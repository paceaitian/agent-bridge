"""收件处理与目标设备 B 的镜像（DESIGN §88.3/§88.4）：按认证来源与单写者规则应用信封。

- A 发来的 attempt 类信封、task_state、report_decision、sync_state：只接受 source 就是任务权威设备；
- B 发来的 report、delivery_status、sync_request：只在本机就是权威时处理，并核对写者就是该 attempt 的目标设备。
低 revision 不能覆盖高 revision；同 revision 不同内容是 idempotency_conflict。B 本机的报告走源端冻结规则。
"""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass, replace
from typing import Any

from ..ids import new_id
from ..store import StoreError
from . import authority, envelopes
from .codec import CodecError, canonical_bytes, is_hex32, sha256_hex
from .fedstore import FederatedStore, FedAttempt, FedTask, dump, load_dict
from .refs import AttemptDefinition, Checkpoint, RemoteEndpointRef, TargetRef, WireActor
from ..model import EndpointRef
from ..reminders import PendingReminder, pending_reminder, reminder_candidate
from .views import model_attempts, model_task

FROM_AUTHORITY = frozenset({"handoff", "review", "notice", "task_state", "report_decision", "sync_state"})
TO_AUTHORITY = frozenset({"report", "delivery_status", "sync_request"})
TERMINAL_REPORT_KINDS = frozenset({"result", "failed", "approve", "changes"})
STALE_MIRROR_MS = 29 * 86400 * 1000  # 比 30 天 TTL 留 24 小时余量
CLOCK_ROLLBACK_MS = 10 * 60 * 1000  # 本机时钟比上次同步早 10 分钟以上视为倒退


@dataclass(frozen=True)
class ReceiveResult:
    """收件结果：applied=可回 L2；rejected=可回运输 reject（证明从未 intent）；duplicate=已处理过，重发 ACK。"""

    status: str
    reason: str | None = None


def _checkpoint_hash(checkpoint: Checkpoint) -> str:
    return sha256_hex(canonical_bytes(checkpoint.to_dict()))


def apply_checkpoint(store: FederatedStore, checkpoint: Checkpoint, *, now: int) -> tuple[FedTask, bool]:
    """B 导入 A 的 checkpoint：只接受更高 revision；返回 (镜像任务, 是否有变化)。调用方须在事务内。"""
    digest = _checkpoint_hash(checkpoint)
    current = store.get_task(checkpoint.authority_device, checkpoint.task_id)
    if current is not None and current.is_authority:
        raise StoreError("authority_conflict")
    if current is not None:
        if checkpoint.revision < current.revision:
            return current, False
        if checkpoint.revision == current.revision:
            if current.state.get("checkpointHash") != digest:
                raise StoreError("idempotency_conflict")
            return current, False
    state: dict[str, Any] = dict(current.state) if current is not None else {"createdAt": now}
    state.update({
        "title": checkpoint.title, "flow": checkpoint.flow, "control": checkpoint.control,
        "verdict": checkpoint.verdict, "acceptedAt": checkpoint.accepted_at, "closedAt": checkpoint.closed_at,
        "closeReason": checkpoint.close_reason, "notifyOrigin": checkpoint.notify_origin,
        "allowShared": checkpoint.allow_shared,
        "originActor": checkpoint.origin.to_dict() if checkpoint.origin else None,
        "members": list(checkpoint.members), "checkpointHash": digest, "checkpoint": checkpoint.to_dict(),
        "updatedAt": now,
    })
    task = FedTask(
        authority_device=checkpoint.authority_device, task_id=checkpoint.task_id, is_authority=False,
        revision=checkpoint.revision, current_work_seq=checkpoint.current_work_seq, max_seq=checkpoint.max_seq,
        state=state, last_sync_at=now,
        local_archived=current.local_archived if current is not None else False,
        # 拿到 A 的当前 checkpoint 才能清 sync_required（§88.4 第 8 条后的说明）
        sync_required=False,
    )
    if current is None:
        store.insert_task(task)
    else:
        store.update_task(task)
    # 已有镜像 attempt 的 A 控制请求跟着 checkpoint 更新（定义本身不可变）
    for definition in checkpoint.attempts:
        attempt = store.attempt_by_msg(definition.msg_id)
        if attempt is None:
            continue
        authority_state = dict(attempt.authority_state)
        authority_state.update({"cancelRequested": definition.cancel_requested, "superseded": definition.superseded,
                                "reportHigh": definition.report_high})
        if authority_state != attempt.authority_state:
            store.update_attempt_columns(attempt.msg_id, authority_state=authority_state)
    return task, True


def _local_target(store: FederatedStore, remote: RemoteEndpointRef) -> TargetRef:
    """B 把信封里的远端目标映射回本机端点；绑定不存在时保留远端形状，由 worker 判定无法投递。"""
    binding = store.binding(remote.endpoint_id)
    if binding is None or binding["provider"] != remote.provider.value or binding["native_id"] != remote.native_id:
        return TargetRef(remote=remote)
    local = EndpointRef.from_json(binding["local_ref_json"])
    if local is None:
        return TargetRef(remote=remote)
    return TargetRef(remote=remote, local=local)


def suppress_reason(task: FedTask, attempt: FedAttempt) -> str | None:
    """B 上未进入 intent 的作业是否应被 A 的最新控制抑制：返回抑制原因或 None（收件、worker 领取与 relay 唤醒共用）。"""
    if task.local_archived:
        return "mirror_archived"
    if attempt.is_closure:
        return None
    if task.finished:
        return "task_finished"
    if attempt.cancel_requested:
        return "task_cancelled"
    if attempt.superseded or (attempt.role != "notice" and task.current_work_seq not in (None, attempt.seq)):
        return "stale_attempt"
    return None


def suppress_pending(store: FederatedStore, ident: authority.Identity, task: FedTask, *, now: int) -> int:
    """按最新 checkpoint 抑制本机尚未 intent 的作业，并把抑制证据回传 A；返回抑制条数。调用方须在事务内。"""
    count = 0
    for attempt in store.attempts(task.authority_device, task.task_id):
        if attempt.target_device != ident.device_id:
            continue
        reason = suppress_reason(task, attempt)
        if reason is None:
            continue
        if suppress_one(store, ident, task, attempt, reason=reason, now=now):
            count += 1
    return count


def suppress_one(store: FederatedStore, ident: authority.Identity, task: FedTask, attempt: FedAttempt, *,
                 reason: str, now: int) -> bool:
    """同事务竞争 native 行：只有 absent/prepared 且从未 intent 才能抑制（§88.5）。"""
    changed = store.connection.execute(
        "UPDATE fed_native_sends SET state='suppressed', result_json=? WHERE msg_id=? AND state='prepared'"
        " AND intent_at IS NULL", (dump({"reason": reason}), attempt.msg_id)).rowcount
    if changed != 1:
        return False
    record_evidence(store, ident, task, attempt, {"state": "cancelled", "reason": reason, "at": now}, now=now)
    # 作业已终结：收件行同事务置 applied，留存回收不再把它当未结收件而永久延期
    store.set_inbox_state(attempt.msg_id, state="applied", expected=("ready",))
    return True


def blocked(store: FederatedStore, ident: authority.Identity, task: FedTask, attempt: FedAttempt, *, now: int) -> bool:
    """暂时不能领取（等待，不抑制）：停用、运行时身份过期、hub 冻结或收件追赶、需同步（含镜像陈旧/时钟倒退）、旧 hub 路由、暂停。

    worker 领取（CAS 锁内）、worker 驻留判定与 relay 唤醒共用这一判定。
    """
    if store.meta("enabled") != "1":
        return True
    if store.meta("hubId") != ident.hub_id or store.meta("deviceId") != ident.device_id:
        return True  # 进程启动时的身份已过期（rebuild 换了 hub/设备）：旧运行时一律不领取，等按新身份重开（§88.11）
    if store.meta("hubStateLost") == "1" or store.meta("ingressCatchup") == "1":
        return True
    if task.sync_required or mirror_needs_sync(task, now):
        return True
    hubs = store.task_hubs(task.authority_device, task.task_id)
    if hubs and ident.hub_id not in hubs:
        return True  # 旧 hub 路由上的任务：灾难换 hub 后冻结，不自动接到新 hub（§88.11）
    return task.paused and not attempt.is_closure


def reminder_candidates(store: FederatedStore, now: int) -> Iterator[tuple[FedTask, PendingReminder, bool]]:
    """A 上等发起方处理的任务各自的下一条提醒：(任务, 提醒, 是否已到期)。

    worker 排提醒与驻留判定、relay 唤醒、本机补拉共用这一判定（Opus r3-P3-1）；B 上没有权威任务，自然为空。
    """
    now_s = now / 1000.0
    for task in store.tasks(authority_only=True, limit=200):
        view = model_task(task)
        if not reminder_candidate(view) or task.origin() is None:
            continue
        reminder = pending_reminder(view, model_attempts(store.attempts(task.authority_device, task.task_id)))
        if reminder is not None:
            yield task, reminder, reminder.due(now_s)


def wake_candidates(store: FederatedStore, ident: authority.Identity, *, now: int) -> set[str]:
    """relay 拉起 worker 的依据：intent（可能要恢复）、现在就能处理的 prepared（含该抑制收尾的），以及 A 上已到期、
    还没排出的发起方提醒（`reminder:<令牌>`；worker 崩溃或重启后也要有人拉起它来排，Opus r3-P3-1）；冻结/暂停的不算。"""
    found: set[str] = set()
    for row in store.natives_in(("prepared", "intent")):
        msg_id = str(row["msg_id"])
        if row["state"] == "intent":
            found.add(msg_id)
            continue
        attempt = store.attempt_by_msg(msg_id)
        task = store.get_task(attempt.authority_device, attempt.task_id) if attempt is not None else None
        if attempt is None or task is None:
            continue
        if suppress_reason(task, attempt) is not None or not blocked(store, ident, task, attempt, now=now):
            found.add(msg_id)
    found |= {f"reminder:{reminder.token}" for _task, reminder, due in reminder_candidates(store, now) if due}
    return found


def mirror_needs_sync(task: FedTask, now: int) -> bool:
    """镜像要先与 A 窄同步才能领取：超过 29 天没同步（比 30 天 TTL 留 24 小时），或本机时钟明显倒退到上次同步之前。

    worker 领取时（CAS 锁内）与 relay 打标共用这一判定：relay 不在线时 worker 也不会外调陈旧镜像的旧作业（§88.4 后备）。
    """
    if task.is_authority or task.finished or task.local_archived:
        return False
    return now - task.last_sync_at >= STALE_MIRROR_MS or task.last_sync_at - now > CLOCK_ROLLBACK_MS


def record_evidence(store: FederatedStore, ident: authority.Identity, task: FedTask, attempt: FedAttempt,
                    evidence: dict[str, Any], *, now: int) -> int:
    """投递设备写一条本机证据并回传 A（A 就是自己时直接导入）；返回 evidenceNo。调用方须在事务内。"""
    current = store.attempt_by_msg(attempt.msg_id) or attempt
    evidence_no = current.evidence_no + 1
    store.add_evidence(attempt.msg_id, evidence_no, delivery_device=ident.device_id, evidence=evidence)
    delivery = dict(current.delivery)
    for key in ("state", "reason", "at", "consumption"):
        if key in evidence:
            delivery[key] = evidence[key]
    store.update_attempt_columns(attempt.msg_id, delivery=delivery, evidence_no=evidence_no)
    if task.authority_device == ident.device_id:
        return evidence_no
    envelope, digest = envelopes.build(
        kind="delivery_status", target_device=task.authority_device, authority_device=task.authority_device,
        task_id=task.task_id, revision=max(task.revision, 1), now=now, attempt=attempt.seq, related=attempt.msg_id,
        data={"msgId": attempt.msg_id, "evidenceNo": evidence_no, "evidence": evidence},
    )
    store.add_operation(source_device=ident.device_id, operation_id=envelope["operationId"], msg_id=envelope["msg_id"],
                        payload_hash=digest, result={"kind": "delivery_status"}, now=now)
    store.add_outbox(msg_id=envelope["msg_id"], operation_id=envelope["operationId"], target_device=task.authority_device,
                     envelope=envelope, payload_hash=digest, expires_at=envelope["expiresAt"], now=now)
    return evidence_no


def receive(store: FederatedStore, ident: authority.Identity, envelope: dict[str, Any], *, source_device: str,
            payload_hash: str, now: int, command: str = "ab") -> ReceiveResult:
    """应用一封已认证来源的信封（附件已齐）；同 (source, operationId) 重复返回 duplicate。"""
    kind = envelope.get("kind")
    if envelope.get("targetDeviceId") != ident.device_id:
        raise CodecError("destination_unknown")
    with store.transaction():
        prior = store.inbox_by_operation(source_device, envelope["operationId"])
        if prior is not None:
            if prior["payload_hash"] != payload_hash or prior["msg_id"] != envelope["msg_id"]:
                raise CodecError("idempotency_conflict")
            if prior["apply_state"] != "receiving":
                return ReceiveResult("duplicate")
            # receiving：metadata 已先落账、附件已齐，现在完成应用（§88.3 L2 前一个事务）
        elif store.inbox_item(envelope["msg_id"]) is not None:
            raise CodecError("idempotency_conflict")
        if kind in FROM_AUTHORITY:
            if source_device != envelope.get("authorityDeviceId"):
                raise CodecError("identity_mismatch", "not_authority")
            result = _from_authority(store, ident, envelope, source_device=source_device, payload_hash=payload_hash,
                                     now=now)
        elif kind in TO_AUTHORITY:
            if envelope.get("authorityDeviceId") != ident.device_id:
                raise CodecError("destination_unknown", "not_authority")
            result = _to_authority(store, ident, envelope, source_device=source_device, payload_hash=payload_hash,
                                   now=now, command=command)
        else:
            raise CodecError("frame_invalid", "kind")
    return result


def _record_inbox(store: FederatedStore, envelope: dict[str, Any], *, source_device: str, payload_hash: str,
                  state: str, now: int, result: dict[str, Any] | None = None) -> None:
    if store.inbox_item(envelope["msg_id"]) is not None:
        store.set_inbox_state(envelope["msg_id"], state=state, expected=("receiving",), result=result)
        return
    store.add_inbox(msg_id=envelope["msg_id"], source_device=source_device, operation_id=envelope["operationId"],
                    payload_hash=payload_hash, envelope=envelope, state=state, now=now, result=result)


def begin_receiving(store: FederatedStore, envelope: dict[str, Any], *, source_device: str, payload_hash: str,
                    now: int) -> str:
    """收到 item 先持久 metadata（inbox=receiving）与附件 manifest；返回已有状态或 receiving。

    同 (source, operationId) 不同 hash/msg_id 拒绝；已 ready/applied/rejected 的只需重 ACK/重拒。
    """
    with store.transaction():
        prior = store.inbox_by_operation(source_device, envelope["operationId"])
        if prior is not None:
            if prior["payload_hash"] != payload_hash or prior["msg_id"] != envelope["msg_id"]:
                raise CodecError("idempotency_conflict")
            return str(prior["apply_state"])
        if store.inbox_item(envelope["msg_id"]) is not None:
            raise CodecError("idempotency_conflict")
        store.add_inbox(msg_id=envelope["msg_id"], source_device=source_device, operation_id=envelope["operationId"],
                        payload_hash=payload_hash, envelope=envelope, state="receiving", now=now)
        refs = list(envelope.get("refs") or [])
        if refs:
            store.add_attachments(msg_id=envelope["msg_id"], authority_device=envelope["authorityDeviceId"],
                                  task_id=envelope["taskId"], refs=refs, blob_state="downloading", now=now,
                                  report_operation_id=envelope["operationId"] if envelope["kind"] == "report" else None)
    return "receiving"


def reject_receiving(store: FederatedStore, msg_id: str, *, reason: str) -> bool:
    """附件硬失败：L2 前把 receiving 收件标 rejected（此时从未建 native 作业，天然 never-intent）。"""
    with store.transaction():
        if store.native(msg_id) is not None:
            return False
        return store.set_inbox_state(msg_id, state="rejected", expected=("receiving",), result={"reason": reason})


def transport_failed(store: FederatedStore, ident: authority.Identity, outbox: dict[str, Any], *, state: str,
                     reason: str | None, now: int) -> None:
    """本机发出的信封被 hub 拒收（refused，确定未 L1）或收件方 never-intent 拒绝（rejected）后的业务收尾。

    - 原生 attempt：这是「已证明未投」，派生 failed（不覆盖收件方已有证据或报告）；
    - 报告：写 rejected 决定以解除源端冻结，原报告事实保留；
    - 其余（控制/证据/决定/同步）只记事件，等下次状态同步。
    """
    envelope = load_dict(outbox.get("envelope_json"))
    kind = envelope.get("kind")
    proven = state in ("refused", "rejected")  # expired/revoked 不证明对方未投，只记事件
    with store.transaction():
        if proven and kind in ("handoff", "review", "notice"):
            attempt = store.attempt_by_msg(envelope.get("msg_id", ""))
            if attempt is not None and attempt.evidence_no == 0 and attempt.delivery.get("receiverReported") is not True:
                delivery = dict(attempt.delivery, state="failed", reason=reason or state, at=now, transport=state)
                store.update_attempt_columns(attempt.msg_id, delivery=delivery)
        elif proven and kind == "report":
            store.add_decision(reporter_device=ident.device_id, report_operation_id=envelope["operationId"],
                               authority_revision=int(envelope.get("authorityRevision", 1)), decision="rejected",
                               reason=reason or state)
        if is_hex32(envelope.get("authorityDeviceId")) and is_hex32(envelope.get("taskId")):
            store.add_event(envelope["authorityDeviceId"], envelope["taskId"], f"transport_{state}", now=now,
                            attempt_seq=envelope.get("attempt"), detail={"kind": kind, "reason": reason})


def _from_authority(store: FederatedStore, ident: authority.Identity, envelope: dict[str, Any], *,
                    source_device: str, payload_hash: str, now: int) -> ReceiveResult:
    kind = envelope["kind"]
    data = envelope.get("data") or {}
    raw_checkpoint = data.get("checkpoint")
    checkpoint = Checkpoint.from_dict(raw_checkpoint) if raw_checkpoint is not None else None
    if checkpoint is not None and (checkpoint.authority_device != source_device
                                   or checkpoint.task_id != envelope["taskId"]):
        raise CodecError("identity_mismatch", "checkpoint_owner")
    if kind in ("handoff", "review", "notice"):
        assert checkpoint is not None  # check_envelope 已要求 attempt 类必须带 checkpoint
        # 先应用信封携带的 A checkpoint，再建作业（§88.3 P2-2）：不依赖 outbox 跨信封 FIFO
        task, _ = apply_checkpoint(store, checkpoint, now=now)
        return _receive_attempt(store, ident, task, envelope, source_device=source_device,
                                payload_hash=payload_hash, now=now)
    if kind == "task_state":
        assert checkpoint is not None
        task, _ = apply_checkpoint(store, checkpoint, now=now)
        suppress_pending(store, ident, task, now=now)
        _record_inbox(store, envelope, source_device=source_device, payload_hash=payload_hash, state="applied", now=now)
        return ReceiveResult("applied")
    if kind == "report_decision":
        if checkpoint is not None:
            task, _ = apply_checkpoint(store, checkpoint, now=now)
            suppress_pending(store, ident, task, now=now)
        _apply_decision(store, ident, envelope, now=now)
        _record_inbox(store, envelope, source_device=source_device, payload_hash=payload_hash, state="applied", now=now)
        return ReceiveResult("applied")
    if kind == "sync_state":
        if checkpoint is not None:
            task, _ = apply_checkpoint(store, checkpoint, now=now)
            suppress_pending(store, ident, task, now=now)
            store.connection.execute("UPDATE fed_tasks SET sync_required=0, last_sync_at=? WHERE authority_device=?"
                                     " AND task_id=?", (now, task.authority_device, task.task_id))
        for item in data.get("decisions") or []:
            if isinstance(item, dict):
                _apply_decision(store, ident, {**envelope, "data": item}, now=now)
        _record_inbox(store, envelope, source_device=source_device, payload_hash=payload_hash, state="applied", now=now)
        return ReceiveResult("applied")
    raise CodecError("frame_invalid", "kind")


def _receive_attempt(store: FederatedStore, ident: authority.Identity, task: FedTask, envelope: dict[str, Any], *,
                     source_device: str, payload_hash: str, now: int) -> ReceiveResult:
    target = RemoteEndpointRef.from_dict(envelope.get("target"))
    if target.device_id != ident.device_id:
        raise CodecError("destination_unknown", "target_device")
    seq = envelope.get("attempt")
    if not isinstance(seq, int):
        raise CodecError("frame_invalid", "attempt")
    definition = next((item for item in Checkpoint.from_dict(envelope["data"]["checkpoint"]).attempts
                       if item.msg_id == envelope["msg_id"]), None)
    if definition is None or definition.seq != seq or definition.role != envelope["kind"]:
        raise CodecError("frame_invalid", "attempt_definition")
    # 不可变定义取原信封；取消/替代/reportHigh 以本机已保存的最高 checkpoint 为准（先到的取消不能被迟到的旧信封抹掉）
    control = next((item for item in _stored_checkpoint_attempts(task) if item.msg_id == envelope["msg_id"]), definition)
    actor_raw = envelope.get("actor")
    sender = WireActor.from_dict(actor_raw) if actor_raw is not None else None
    options = dict((envelope.get("data") or {}).get("options") or {})
    attempt = FedAttempt(
        authority_device=task.authority_device, task_id=task.task_id, seq=seq, msg_id=envelope["msg_id"],
        role=envelope["kind"], target_device=ident.device_id, target=_local_target(store, target), sender=sender,
        sender_class=str(envelope.get("senderClass") or "unknown"), body=str(envelope.get("body") or ""),
        refs=list(envelope.get("refs") or []), options=options,
        authority_state={"createdAt": envelope.get("createdAt"), "cancelRequested": control.cancel_requested,
                         "superseded": control.superseded, "reportHigh": control.report_high},
        evidence_no=0, delivery={"state": "pending"},
        effective_work={"work": "none" if envelope["kind"] == "notice" else "awaiting_ack"},
    )
    if store.attempt_by_msg(attempt.msg_id) is None:
        store.insert_attempt(attempt)
    store.add_route(task_id=task.task_id, authority_device=task.authority_device, hub_id=ident.hub_id,
                    local_role=attempt.role, local_endpoint_id=target.endpoint_id, first_msg_id=attempt.msg_id)
    _record_inbox(store, envelope, source_device=source_device, payload_hash=payload_hash, state="ready", now=now)
    store.add_native(attempt.msg_id)
    store.add_event(task.authority_device, task.task_id, f"{attempt.role}_received", now=now, attempt_seq=seq)
    # 收件即按 A 的控制抑制：结束/取消/过时的工作不投；结束回执另按 covers 判定
    reason = suppress_reason(task, attempt)
    if reason is not None:
        suppress_one(store, ident, task, attempt, reason=reason, now=now)
    elif attempt.is_closure:
        _settle_closure(store, ident, task, attempt, now=now)
    suppress_pending(store, ident, task, now=now)
    return ReceiveResult("applied")


def _stored_checkpoint_attempts(task: FedTask) -> tuple[AttemptDefinition, ...]:
    """镜像当前保存的 A checkpoint 里的 attempt 定义；坏数据视为没有。"""
    raw = task.state.get("checkpoint")
    if not isinstance(raw, dict):
        return ()
    try:
        return Checkpoint.from_dict(raw).attempts
    except CodecError:
        return ()


def _settle_closure(store: FederatedStore, ident: authority.Identity, task: FedTask, closure: FedAttempt, *,
                    now: int) -> None:
    """B 收到结束回执：covers 里有已交出/不明的工作才投，否则抑制并回传证据（§88.4 P2-1）。"""
    covers = closure.options.get("coversWorkMessageIds")
    if not isinstance(covers, list):
        return  # A 本机路径排的回执，没有 covers：照常投递
    may_have_arrived = False
    latest: FedAttempt | None = None
    for msg_id in covers:
        if not isinstance(msg_id, str) or not is_hex32(msg_id):
            continue
        work = store.attempt_by_msg(msg_id)
        native = store.native(msg_id)
        if work is None or native is None or work.target_device != ident.device_id:
            continue
        if native["state"] in ("intent", "unknown") or (
                native["state"] == "finished" and work.delivery.get("state") not in ("failed", "refused", "denied", "expired")):
            may_have_arrived = True
            if latest is None or work.seq > latest.seq:
                latest = work
    if not may_have_arrived:
        suppress_one(store, ident, task, closure, reason="closure_not_needed", now=now)
        return
    if latest is not None and latest.target.local is not None:
        # 投给最近相关工作实际接收的那个本机端点（实际代际由 worker 按投递记录复核）
        native = store.native(latest.msg_id) or {}
        delivered = EndpointRef.from_json(native.get("local_target_json"))
        local = delivered or latest.target.local
        store.update_attempt_columns(closure.msg_id, target=replace(closure.target, local=local))


def _apply_decision(store: FederatedStore, ident: authority.Identity, envelope: dict[str, Any], *, now: int) -> None:
    data = envelope.get("data") or {}
    operation = data.get("reportOperationId")
    decision = data.get("decision")
    if not isinstance(operation, str) or not is_hex32(operation) or decision not in (
            "accepted", "rejected", "superseded", "not_seen", "pending"):
        return
    report = store.report_by_operation(ident.device_id, operation)
    if report is None:
        return
    # 决定必须来自该报告所属任务的权威设备：只核信封自洽不够，C 不能裁决 B 交给 A 的报告
    attempt = envelope.get("attempt")
    if (report["authority_device"] != envelope.get("authorityDeviceId") or report["task_id"] != envelope.get("taskId")
            or (isinstance(attempt, int) and attempt != report["attempt_seq"])):
        store.add_event(str(envelope.get("authorityDeviceId")), str(envelope.get("taskId")), "decision_misrouted",
                        now=now, detail={"operation": operation})
        return
    if decision in ("not_seen", "pending"):
        store.add_event(envelope["authorityDeviceId"], envelope["taskId"], f"report_{decision}", now=now,
                        detail={"operation": operation})
        outbox = store.connection.execute("SELECT state FROM fed_outbox WHERE operation_id=?", (operation,)).fetchone()
        if decision == "not_seen" and outbox is not None and outbox[0] == "expired" \
                and store.decision(ident.device_id, operation) is None:
            # 运输已终结（过期/上次交付不明后放弃）且 A 明确没见过：解除源端冻结，允许按当前资格重新汇报（§88.4 第 8 条）
            store.add_decision(reporter_device=ident.device_id, report_operation_id=operation,
                               authority_revision=int(envelope.get("authorityRevision", 1)), decision="rejected",
                               reason="report_not_seen")
        return
    store.add_decision(reporter_device=ident.device_id, report_operation_id=operation,
                       authority_revision=int(envelope.get("authorityRevision", 1)), decision=decision,
                       reason=data.get("reason") if isinstance(data.get("reason"), str) else None)
    store.add_event(envelope["authorityDeviceId"], envelope["taskId"], f"report_{decision}", now=now,
                    attempt_seq=report["attempt_seq"], detail={"reason": data.get("reason")})


def _to_authority(store: FederatedStore, ident: authority.Identity, envelope: dict[str, Any], *, source_device: str,
                  payload_hash: str, now: int, command: str) -> ReceiveResult:
    kind = envelope["kind"]
    data = envelope.get("data") or {}
    task = store.get_task(ident.device_id, envelope["taskId"])
    if task is None or not task.is_authority:
        _record_inbox(store, envelope, source_device=source_device, payload_hash=payload_hash, state="rejected",
                      now=now, result={"reason": "authority_mismatch"})
        return ReceiveResult("applied", "authority_mismatch")
    if kind == "report":
        report = dict(data.get("report") or {})
        report.update({"authorityDeviceId": ident.device_id, "taskId": task.task_id,
                       "operationId": envelope["operationId"], "attempt": envelope.get("attempt")})
        report["reporter"] = envelope.get("actor")
        report["reporterClass"] = envelope.get("senderClass")
        authority.apply_report_safely(store, ident, report, reporter_device=source_device, now=now,
                                      command=command)
    elif kind == "delivery_status":
        msg_id = data.get("msgId")
        evidence = data.get("evidence")
        number = data.get("evidenceNo")
        if not is_hex32(msg_id) or not isinstance(evidence, dict) or not isinstance(number, int):
            raise CodecError("frame_invalid", "delivery_status")
        authority.apply_evidence(store, task, str(msg_id), number, dict(evidence),  # pyright: ignore[reportUnknownArgumentType]
                                 delivery_device=source_device, now=now)
    elif kind == "sync_request":
        _answer_sync(store, ident, task, envelope, source_device=source_device, now=now)
    _record_inbox(store, envelope, source_device=source_device, payload_hash=payload_hash, state="applied", now=now)
    return ReceiveResult("applied")


def _answer_sync(store: FederatedStore, ident: authority.Identity, task: FedTask, envelope: dict[str, Any], *,
                 source_device: str, now: int) -> None:
    """A 回答窄同步：只给当前 checkpoint 与最多 16 个指定报告的决定，不重放正文/附件（§88.4 第 7 条）。"""
    attempts = store.attempts(task.authority_device, task.task_id)
    if source_device not in authority.members(task, attempts):
        raise CodecError("identity_mismatch", "not_member")
    decisions: list[dict[str, Any]] = []
    for item in ((envelope.get("data") or {}).get("pending") or [])[:16]:
        if not isinstance(item, dict) or not is_hex32(item.get("operationId")):
            continue
        found = store.decision(source_device, item["operationId"])
        if found is not None:
            decisions.append({"reportOperationId": item["operationId"], "decision": found["decision"],
                              "reason": found["reason"]})
            continue
        attempt = next((a for a in attempts if a.seq == item.get("attempt")), None)
        high = int(attempt.authority_state.get("reportHigh", 0)) if attempt is not None else 0
        number = item.get("reportNo")
        status = "superseded" if isinstance(number, int) and number <= high else "not_seen"
        decisions.append({"reportOperationId": item["operationId"], "decision": status, "reason": None})
    checkpoint = authority.build_checkpoint(task, attempts)
    reply, digest = envelopes.build(
        kind="sync_state", target_device=source_device, authority_device=task.authority_device, task_id=task.task_id,
        revision=task.revision, now=now, related=envelope["msg_id"],
        data=envelopes.checkpoint_data(checkpoint, decisions=decisions),
    )
    store.add_operation(source_device=ident.device_id, operation_id=reply["operationId"], msg_id=reply["msg_id"],
                        payload_hash=digest, result={"kind": "sync_state"}, now=now)
    store.add_outbox(msg_id=reply["msg_id"], operation_id=reply["operationId"], target_device=source_device,
                     envelope=reply, payload_hash=digest, expires_at=reply["expiresAt"], now=now)


# ---- B 本机报告 ----


@dataclass(frozen=True)
class LocalReport:
    """B（或 A 本机参与方）已核验归属的一条报告。"""

    task: FedTask
    attempt: FedAttempt
    kind: str
    note: str
    refs: list[dict[str, Any]]
    commit: dict[str, Any] | None
    reporter: WireActor
    reporter_class: str
    source: str  # agent / manual


@dataclass(frozen=True)
class ReportResult:
    report_no: int
    operation_id: str
    decision: str | None  # A 本机同事务裁决时有值；B 远端报告为 None（等待 A 确认）
    reason: str | None = None


def _report_frozen(store: FederatedStore, ident: authority.Identity, report: LocalReport) -> str | None:
    """源端终态冻结：本 attempt 已有未被拒绝的终态报告时，不接受会覆盖它的新报告（§88.4 第 3 条）。"""
    for prior in store.reports(report.task.authority_device, report.task.task_id, report.attempt.seq):
        if prior["reporter_device"] != ident.device_id:
            continue
        kind = prior["report"].get("kind")
        if kind not in TERMINAL_REPORT_KINDS:
            continue
        decision = store.decision(ident.device_id, prior["operation_id"])
        if decision is None:
            return "report_pending"
        if decision["decision"] == "accepted":
            return "attempt_report_finalized"
    return None


def submit_report(store: FederatedStore, ident: authority.Identity, report: LocalReport, *, now: int,
                  command: str = "ab") -> ReportResult:
    """在目标设备落一条报告：分配 reportNo、写事实与 outbox；A 本机参与方在同一事务里直接裁决。"""
    task, attempt = report.task, report.attempt
    if attempt.target_device != ident.device_id:
        raise StoreError("reporter_mismatch")
    with store.transaction():
        current = store.get_task(task.authority_device, task.task_id) or task
        if current.finished:
            raise StoreError("task_finished")
        if current.local_archived:
            raise StoreError("mirror_archived")
        if current.current_work_seq != attempt.seq:
            raise StoreError("stale_attempt")
        frozen = _report_frozen(store, ident, report)
        if frozen is not None:
            raise StoreError(frozen)
        report_no = store.max_report_no(current.authority_device, current.task_id, attempt.seq, ident.device_id) + 1
        operation_id = new_id()
        body: dict[str, Any] = {"kind": report.kind, "note": report.note, "refs": report.refs, "reportNo": report_no,
                                "source": report.source, "observedRevision": current.revision}
        if report.commit is not None:
            body["commit"] = report.commit
        fact = {**body, "authorityDeviceId": current.authority_device, "taskId": current.task_id,
                "attempt": attempt.seq, "operationId": operation_id, "reporter": report.reporter.to_dict(),
                "reporterClass": report.reporter_class}
        if current.authority_device == ident.device_id:
            decision = authority.apply_report_safely(store, ident, fact, reporter_device=ident.device_id, now=now,
                                                     command=command)
            return ReportResult(report_no, operation_id, decision.decision, decision.reason)
        store.add_report(authority_device=current.authority_device, task_id=current.task_id, attempt_seq=attempt.seq,
                         reporter_device=ident.device_id, report_no=report_no, operation_id=operation_id, report=fact)
        envelope, digest = envelopes.build(
            kind="report", target_device=current.authority_device, authority_device=current.authority_device,
            task_id=current.task_id, revision=max(current.revision, 1), now=now, attempt=attempt.seq,
            related=attempt.msg_id, actor=report.reporter, sender_class=report.reporter_class,
            refs=report.refs, data={"report": body, "note": report.note}, operation_id=operation_id,
        )
        if report.refs:
            store.add_attachments(msg_id=envelope["msg_id"], authority_device=current.authority_device,
                                  task_id=current.task_id, refs=report.refs, blob_state="staged", now=now,
                                  report_operation_id=operation_id)
        store.add_operation(source_device=ident.device_id, operation_id=operation_id, msg_id=envelope["msg_id"],
                            payload_hash=digest, result={"kind": "report", "reportNo": report_no}, now=now)
        store.add_outbox(msg_id=envelope["msg_id"], operation_id=operation_id, target_device=current.authority_device,
                         envelope=envelope, payload_hash=digest, expires_at=envelope["expiresAt"], now=now)
        store.add_event(current.authority_device, current.task_id, f"report_{report.kind}_saved", now=now,
                        attempt_seq=attempt.seq, detail={"reportNo": report_no})
    return ReportResult(report_no, operation_id, None)


# ---- 窄同步请求（B → A） ----


def pending_reports(store: FederatedStore, ident: authority.Identity, task: FedTask) -> list[dict[str, Any]]:
    """本机发给 A、还没有决定的报告描述（最多 16 个，§88.4 第 7 条）。"""
    pending: list[dict[str, Any]] = []
    for row in store.reports(task.authority_device, task.task_id):
        if row["reporter_device"] != ident.device_id or store.decision(ident.device_id, row["operation_id"]) is not None:
            continue
        pending.append({"operationId": row["operation_id"], "attempt": row["attempt_seq"], "reportNo": row["report_no"]})
    return pending[-16:]


def request_sync(store: FederatedStore, ident: authority.Identity, task: FedTask, *, now: int) -> str:
    """排一条 sync_request 给 A：只问当前 checkpoint 与指定报告的决定；返回 msg_id。调用方负责每 task 限频。"""
    with store.transaction():
        envelope, digest = envelopes.build(
            kind="sync_request", target_device=task.authority_device, authority_device=task.authority_device,
            task_id=task.task_id, revision=max(task.revision, 1), now=now,
            data={"knownRevision": task.revision, "pending": pending_reports(store, ident, task)},
        )
        store.add_operation(source_device=ident.device_id, operation_id=envelope["operationId"],
                            msg_id=envelope["msg_id"], payload_hash=digest, result={"kind": "sync_request"}, now=now)
        store.add_outbox(msg_id=envelope["msg_id"], operation_id=envelope["operationId"],
                         target_device=task.authority_device, envelope=envelope, payload_hash=digest,
                         expires_at=envelope["expiresAt"], now=now)
    return envelope["msg_id"]


def mark_sync_required(store: FederatedStore, *, authority_device: str | None) -> int:
    """过期空洞/游标缺口：把该 A（None=全部）的开放镜像标 sync_required；返回标记数。调用方须在事务内。"""
    count = 0
    rows = store.connection.execute(
        "SELECT authority_device,task_id,state_json FROM fed_tasks WHERE is_authority=0 AND local_archived=0"
        " AND sync_required=0" + (" AND authority_device=?" if authority_device is not None else ""),
        (authority_device,) if authority_device is not None else ()).fetchall()
    for row in rows:
        state = load_dict(row[2])
        if state.get("acceptedAt") is not None or state.get("closedAt") is not None:
            continue  # 已终结的镜像不再需要同步
        store.connection.execute("UPDATE fed_tasks SET sync_required=1 WHERE authority_device=? AND task_id=?",
                                 (row[0], row[1]))
        count += 1
    return count
