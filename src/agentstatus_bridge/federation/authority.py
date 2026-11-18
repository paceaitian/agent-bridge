"""发起设备 A 的权威状态推进（DESIGN §88.4）：建任务、分配 attempt、裁决报告、导入投递证据、控制与结束回执。

A 是任务定义、序号、control、accept/close 与报告裁决的唯一写者；投递事实只能从执行投递的设备导入。
所有写入都在联邦库的单个事务里完成，与本机账本无关。阶段折叠、下一步文案与容量上限复用本机纯规则（views）。
"""

from __future__ import annotations

from collections.abc import Callable, Iterable
from dataclasses import dataclass, field, replace
from typing import Any

from ..closure import ACCEPTED, CLOSED, closure_body
from ..ids import new_id, short
from ..labels import next_step, review_capacity_hint
from ..native_names import id_token
from ..model import MAY_HAVE_ARRIVED, Attempt, Delivery, Provider, ReportKind, Role, Task, Verdict, Work
from ..reports import REPORT_LABELS
from ..store import CAPACITY_CODES, MAX_ACTIVE_TASKS, MAX_PENDING_ATTEMPTS, StoreError, attempt_limit
from . import envelopes
from .codec import SENDER_CLASSES
from .fedstore import LOCAL_NOTICE_KIND, FederatedStore, FedAttempt, FedTask, dump, notice_options
from .refs import AttemptDefinition, Checkpoint, RemoteEndpointRef, TargetRef, WireActor
from .views import TERMINAL_REPORTS, fold_report, initial_work, model_attempt, model_attempts, model_task

# A 视角里「投递设备已证明未投」的状态：只来自 B 的证据或 hub 运输拒绝，A 本机的取消请求不算（§88.4 P2-1）
REMOTE_PROVEN_UNDELIVERED = frozenset({"failed", "refused", "denied", "expired", "cancelled"})
# 远端工作尝试的到达证据（§98.1）：投递设备的原生通道已接收。不含 held：它是 Claude 接收端暂存、等对方会话里批准，
# 消息在设备上但还没交给会话，结案后仍可能被批准执行，少提示一句的代价比多一句大；pending/sending/unknown 与将来
# 新增的状态同样不算
REMOTE_ARRIVAL_EVIDENCE = frozenset({"written", "queued", "delivered"})
NOTIFYING_REPORTS = frozenset(TERMINAL_REPORTS | {ReportKind.BLOCKED})
DECISION_REASONS = frozenset(
    {"task_finished", "stale_attempt", "attempt_not_found", "attempt_not_reportable", "report_kind_mismatch",
     "reporter_mismatch", "target_no_inbox", "authority_mismatch", "report_sequence_conflict",
     "result_already_submitted", "verdict_requires_review", "review_requires_verdict"}
)
# 有收件通道的 provider（Grok 只读，§45.34）
INBOX_PROVIDERS = frozenset({Provider.CODEX, Provider.CLAUDE})


@dataclass(frozen=True)
class Identity:
    """本机在联邦里的身份：稳定 deviceId、登记名与当前 hub。"""

    device_id: str
    device_name: str
    hub_id: str


@dataclass
class Decision:
    """一次报告裁决的结果；duplicate 表示同 operation 的重复报告，返回原决定。"""

    decision: str
    reason: str | None
    revision: int
    followups: list[FedAttempt] = field(default_factory=list)
    skipped: dict[str, str] = field(default_factory=dict)
    duplicate: bool = False


def can_notify(target: TargetRef) -> bool:
    """目标有没有收件通道：静态能力，不随在线与否变化。"""
    return target.remote.provider in INBOX_PROVIDERS


def actor_for(target: TargetRef, *, wire_token: str) -> WireActor:
    """由目标引用投影出逻辑发送者（wireToken 由来源设备生成后随事实保存）。"""
    return WireActor(device_id=target.remote.device_id, provider=target.remote.provider,
                     native_id=target.remote.native_id, wire_token=wire_token,
                     endpoint_id=target.remote.endpoint_id)


def _same_session(a: TargetRef, b: TargetRef) -> bool:
    return a.remote.same_endpoint(b.remote)


def members(task: FedTask, attempts: Iterable[FedAttempt]) -> tuple[str, ...]:
    """任务成员设备：A 自己、所有 attempt 的目标设备与复核方设备（去重，A 在前）。"""
    found = [task.authority_device]
    reviewer = task.reviewer()
    candidates = [item.target_device for item in attempts]
    if reviewer is not None:
        candidates.append(reviewer.remote.device_id)
    for device in candidates:
        if device not in found:
            found.append(device)
    return tuple(found)


def build_checkpoint(task: FedTask, attempts: list[FedAttempt]) -> Checkpoint:
    """A 的当前快照：不含正文、报告原文、附件字节与本机 PID/路径。"""
    state = task.state
    reviewer = task.reviewer()
    origin_actor = state.get("originActor")
    definitions = tuple(
        AttemptDefinition(
            seq=item.seq,
            msg_id=item.msg_id,
            role=item.role,
            target=item.target.remote,
            # note 与 fyi 不进 checkpoint 定义（旧读方的闭合枚举会整封拒收）；类别与 forSeq 只经信封 data.options 传（§95.5.5）
            notice_kind=(item.options.get("noticeKind")
                         if item.role == "notice" and not (item.is_note or item.is_fyi) else None),
            cancel_requested=item.cancel_requested,
            superseded=item.superseded,
            report_high=int(item.authority_state.get("reportHigh", 0)),
        )
        for item in attempts
    )
    return Checkpoint(
        authority_device=task.authority_device,
        task_id=task.task_id,
        revision=task.revision,
        title=task.title,
        flow=str(state.get("flow", "handoff")),
        control=str(state.get("control", "active")),
        max_seq=task.max_seq,
        current_work_seq=task.current_work_seq,
        attempts=definitions,
        members=members(task, attempts),
        origin=WireActor.from_dict(origin_actor) if isinstance(origin_actor, dict) else None,
        reviewer=actor_for(reviewer, wire_token=str(state.get("reviewerToken") or "-")) if reviewer else None,
        verdict=state.get("verdict"),
        accepted_at=state.get("acceptedAt"),
        closed_at=state.get("closedAt"),
        close_reason=state.get("closeReason"),
        notify_origin=state.get("notifyOrigin", True) is not False,
        allow_shared=state.get("allowShared") is True,
    )


def _bump(store: FederatedStore, task: FedTask, *, now: int, **state_changes: Any) -> FedTask:
    """A 的可见变化：revision+1，更新 state；调用方须在事务内。"""
    state = dict(task.state)
    state.update(state_changes)
    state["updatedAt"] = now
    updated = replace(task, revision=task.revision + 1, state=state, last_sync_at=now)
    store.update_task(updated)
    return updated


def _check_capacity(store: FederatedStore) -> None:
    # §83：联邦库独立计数，接受与本机库合计最多翻倍（R2）
    if store.pending_authority_attempts() >= MAX_PENDING_ATTEMPTS:
        raise StoreError("capacity_pending")


def _queue(store: FederatedStore, ident: Identity, task: FedTask, attempt: FedAttempt, *, now: int,
           extra_data: dict[str, Any] | None = None) -> None:
    """把一个原生 attempt 交给投递设备：远端目标进 outbox（携带当前 checkpoint），本机目标直接建等价的就绪作业。"""
    if attempt.target_device == ident.device_id:
        # A 本机目标：不经 hub 给自己发 L1/L2；同事务建 ready 收件记录与 prepared 原生作业（§88.4）
        store.add_inbox(msg_id=attempt.msg_id, source_device=ident.device_id, operation_id=new_id(),
                        payload_hash="local", envelope=None, state="ready", now=now)
        store.add_native(attempt.msg_id)
        if attempt.refs:
            # 本机目标也用冻结/交付副本：worker 投递前从 staging 落交付叶（§88.3 本机目标+远端 reviewer）
            store.add_attachments(msg_id=attempt.msg_id, authority_device=task.authority_device, task_id=task.task_id,
                                  refs=attempt.refs, blob_state="staged", now=now)
        return
    checkpoint = build_checkpoint(task, store.attempts(task.authority_device, task.task_id))
    data = envelopes.checkpoint_data(checkpoint, **(extra_data or {}))
    data["options"] = {key: value for key, value in attempt.options.items()
                       if key in ("noticeKind", "closure", "allowShared", "reminderToken", "coversWorkMessageIds",
                                  "forSeq")}
    if isinstance(attempt.options.get(LOCAL_NOTICE_KIND), str):
        data["options"]["noticeKind"] = attempt.options[LOCAL_NOTICE_KIND]  # 本机键映射回线上键（§95.5.5）
    envelope, digest = envelopes.build(
        kind=attempt.role, target_device=attempt.target_device, authority_device=task.authority_device,
        task_id=task.task_id, revision=task.revision, now=now, attempt=attempt.seq, actor=attempt.sender,
        target=attempt.target.remote, sender_class=attempt.sender_class, title=task.title, body=attempt.body,
        refs=attempt.refs, data=data, msg_id=attempt.msg_id,
    )
    if attempt.refs:
        store.add_attachments(msg_id=attempt.msg_id, authority_device=task.authority_device, task_id=task.task_id,
                              refs=attempt.refs, blob_state="staged", now=now)
    store.add_operation(source_device=ident.device_id, operation_id=envelope["operationId"], msg_id=attempt.msg_id,
                        payload_hash=digest, result={"kind": attempt.role}, now=now)
    store.add_outbox(msg_id=attempt.msg_id, operation_id=envelope["operationId"], target_device=attempt.target_device,
                     envelope=envelope, payload_hash=digest, expires_at=envelope["expiresAt"], now=now)


def send_task_state(store: FederatedStore, ident: Identity, task: FedTask, *, now: int,
                    devices: Iterable[str] | None = None) -> int:
    """把当前 checkpoint 发给远端成员（每个成员一个 operation）；返回排队条数。"""
    attempts = store.attempts(task.authority_device, task.task_id)
    checkpoint = build_checkpoint(task, attempts)
    queued = 0
    for device in devices if devices is not None else members(task, attempts):
        if device == ident.device_id:
            continue
        envelope, digest = envelopes.build(
            kind="task_state", target_device=device, authority_device=task.authority_device, task_id=task.task_id,
            revision=task.revision, now=now, data=envelopes.checkpoint_data(checkpoint),
        )
        store.add_operation(source_device=ident.device_id, operation_id=envelope["operationId"],
                            msg_id=envelope["msg_id"], payload_hash=digest, result={"kind": "task_state"}, now=now)
        store.add_outbox(msg_id=envelope["msg_id"], operation_id=envelope["operationId"], target_device=device,
                         envelope=envelope, payload_hash=digest, expires_at=envelope["expiresAt"], now=now)
        queued += 1
    return queued


def _new_attempt(task: FedTask, *, seq: int, role: str, target: TargetRef, body: str, refs: list[dict[str, Any]],
                 sender: WireActor | None, sender_class: str, options: dict[str, Any], now: int) -> FedAttempt:
    return FedAttempt(
        authority_device=task.authority_device, task_id=task.task_id, seq=seq, msg_id=new_id(), role=role,
        target_device=target.remote.device_id, target=target, sender=sender,
        # 闭集外的类别一律按 unknown（接收端会暂存），本机目标不经信封校验也保持同一口径
        sender_class=sender_class if sender_class in SENDER_CLASSES else "unknown",
        body=body, refs=list(refs), options=dict(options),
        authority_state={"createdAt": now, "cancelRequested": False, "superseded": False, "reportHigh": 0},
        evidence_no=0, delivery={"state": "pending"},
        effective_work=initial_work(role),
    )


def create_task(
    store: FederatedStore,
    ident: Identity,
    *,
    title: str,
    flow: str,
    body: str,
    refs: list[dict[str, Any]],
    origin: TargetRef | None,
    origin_actor: WireActor | None,
    origin_class: str,
    target: TargetRef,
    reviewer: TargetRef | None,
    reviewer_token: str | None = None,
    notify_origin: bool = True,
    allow_shared: bool = False,
    now: int,
    follows: str | None = None,
) -> tuple[FedTask, FedAttempt]:
    """A 上建联邦任务与第一次交接（L0）：任务、attempt、路由、operation 与 outbox 同一事务。

    follows（§93.3）只进本机 state_json：build_checkpoint 按字段挑选，不会把它带进 checkpoint 与信封。
    """
    if not can_notify(target):
        raise StoreError("target_no_inbox")
    with store.transaction():
        if store.active_authority_tasks() >= MAX_ACTIVE_TASKS:
            raise StoreError("capacity_active_tasks")
        _check_capacity(store)
        task = FedTask(
            authority_device=ident.device_id, task_id=new_id(), is_authority=True, revision=1,
            current_work_seq=1, max_seq=1, last_sync_at=now,
            state={
                "title": title[:120], "flow": flow, "control": "active", "verdict": None,
                "acceptedAt": None, "closedAt": None, "closeReason": None,
                "origin": origin.to_dict() if origin else None,
                "originActor": origin_actor.to_dict() if origin_actor else None,
                "reviewer": reviewer.to_dict() if reviewer else None,
                "reviewerToken": reviewer_token,
                "notifyOrigin": notify_origin, "allowShared": allow_shared,
                "createdAt": now, "updatedAt": now, "hubId": ident.hub_id,
                **({"follows": follows} if follows is not None else {}),
            },
        )
        store.insert_task(task)
        attempt = _new_attempt(task, seq=1, role="handoff", target=target, body=body, refs=refs,
                               sender=origin_actor, sender_class=origin_class,
                               options={"allowShared": allow_shared}, now=now)
        store.insert_attempt(attempt)
        store.add_route(task_id=task.task_id, authority_device=ident.device_id, hub_id=ident.hub_id,
                        local_role="origin", local_endpoint_id=origin.remote.endpoint_id if origin else "",
                        first_msg_id=attempt.msg_id)
        store.add_event(task.authority_device, task.task_id, "created", now=now, attempt_seq=1, detail={"flow": flow})
        _queue(store, ident, task, attempt, now=now)
    return task, attempt


def create_fyi(
    store: FederatedStore,
    ident: Identity,
    *,
    title: str,
    body: str,
    refs: list[dict[str, Any]],
    origin: TargetRef | None,
    origin_actor: WireActor | None,
    origin_class: str,
    target: TargetRef,
    allow_shared: bool = False,
    now: int,
    follows: str | None = None,
) -> tuple[FedTask, FedAttempt]:
    """A 上建「已关闭」的联邦告知（DESIGN §95.5.7）：任务、唯一一条 seq 1 的 notice、路由与 outbox 同一事务。

    没有工作尝试（currentWorkSeq 为空），不进进行中容量；镜像收到的第一封就是 notice、任务已关闭，
    按 delivers_after_finish 投递。能力门（目标设备目录 features 含 fyi）由调用方在写前核对。
    """
    if not can_notify(target):
        raise StoreError("target_no_inbox")
    with store.transaction():
        _check_capacity(store)
        task = FedTask(
            authority_device=ident.device_id, task_id=new_id(), is_authority=True, revision=1,
            current_work_seq=None, max_seq=1, last_sync_at=now,
            state={
                "title": title[:120], "flow": "handoff", "control": "active", "verdict": None,
                "acceptedAt": None, "closedAt": now, "closeReason": "fyi", "fyi": True,
                "origin": origin.to_dict() if origin else None,
                "originActor": origin_actor.to_dict() if origin_actor else None,
                "reviewer": None, "reviewerToken": None,
                "notifyOrigin": False, "allowShared": allow_shared,
                "createdAt": now, "updatedAt": now, "hubId": ident.hub_id,
                **({"follows": follows} if follows is not None else {}),
            },
        )
        store.insert_task(task)
        attempt = _new_attempt(task, seq=1, role="notice", target=target, body=body, refs=refs,
                               sender=origin_actor, sender_class=origin_class,
                               options={LOCAL_NOTICE_KIND: "fyi", "allowShared": allow_shared}, now=now)
        store.insert_attempt(attempt)
        store.add_route(task_id=task.task_id, authority_device=ident.device_id, hub_id=ident.hub_id,
                        local_role="origin", local_endpoint_id=origin.remote.endpoint_id if origin else "",
                        first_msg_id=attempt.msg_id)
        store.add_event(task.authority_device, task.task_id, "fyi_created", now=now, attempt_seq=1)
        _queue(store, ident, task, attempt, now=now)
    return task, attempt


def add_attempt(
    store: FederatedStore,
    ident: Identity,
    task: FedTask,
    *,
    role: str,
    target: TargetRef,
    body: str,
    refs: list[dict[str, Any]],
    sender: WireActor | None,
    sender_class: str,
    options: dict[str, Any] | None = None,
    now: int,
    event: str | None = None,
) -> tuple[FedTask, FedAttempt]:
    """为已有任务追加一个原生 attempt（复核、通知、返工）；容量按 §83 同一函数判定。"""
    opts = dict(options or {})
    with store.transaction():
        current = store.get_task(task.authority_device, task.task_id)
        if current is None or not current.is_authority:
            raise StoreError("task_not_found")
        seq = current.max_seq + 1
        # 容量按共用口径判定：本机键记的 note 仍按工作类 60，不占 61–64 预留（G4 审计 r1 复核）
        if seq > attempt_limit(Role(role), notice_options(opts)):
            raise StoreError("capacity_attempts")
        _check_capacity(store)
        attempt = _new_attempt(current, seq=seq, role=role, target=target, body=body, refs=refs, sender=sender,
                               sender_class=sender_class, options=opts, now=now)
        store.insert_attempt(attempt)
        work_seq = seq if role != "notice" else current.current_work_seq
        updated = replace(current, max_seq=seq, current_work_seq=work_seq)
        updated = _bump(store, updated, now=now)
        store.add_event(task.authority_device, task.task_id, event or f"{role}_created", now=now, attempt_seq=seq)
        _queue(store, ident, updated, attempt, now=now)
    return updated, attempt


# ---- 任务内补充消息（DESIGN §95.5） ----

# A 视角：当前工作尝试已发出（有投递设备的证据或本机事实，可能已到对方）且尚未终态汇报，才有可补充的对象
_NOTE_SENT = frozenset(MAY_HAVE_ARRIVED | {Delivery.SENDING})
_NOTE_OPEN_WORK = frozenset({Work.AWAITING_ACK, Work.ACKNOWLEDGED, Work.IN_PROGRESS})


def add_note(store: FederatedStore, ident: Identity, task: FedTask, *, body: str, sender: WireActor | None,
             sender_class: str, now: int) -> tuple[FedTask, FedAttempt]:
    """A 上给当前工作尝试补一条 note：资格与写入同一事务；目标与当前工作尝试相同，不改 current_work_seq。"""
    with store.transaction():
        current = store.get_task(task.authority_device, task.task_id)
        if current is None or not current.is_authority:
            raise StoreError("task_not_found")
        if current.finished:
            raise StoreError("note_no_active_attempt")
        if current.paused:
            raise StoreError("note_task_paused")
        work = next((item for item in store.attempts(current.authority_device, current.task_id)
                     if item.role != "notice" and item.seq == current.current_work_seq), None)
        view = model_attempt(work) if work is not None else None
        if work is None or view is None or view.delivery not in _NOTE_SENT or view.work not in _NOTE_OPEN_WORK:
            raise StoreError("note_no_active_attempt")
        return add_attempt(store, ident, current, role="notice", target=work.target, body=body, refs=[],
                           sender=sender, sender_class=sender_class,
                           options={LOCAL_NOTICE_KIND: "note", "forSeq": work.seq,
                                    "allowShared": work.options.get("allowShared") is True},
                           now=now, event="note_created")


# ---- 报告裁决 ----


def _describe_result(result: dict[str, Any]) -> list[str]:
    lines: list[str] = []
    note = result.get("note")
    if isinstance(note, str) and note:
        lines.append(f"结论：{note}")
    for item in result.get("refs", []) if isinstance(result.get("refs"), list) else []:
        if isinstance(item, dict):
            digest = str(item.get("sha256") or "")[:12]
            name = item.get("name")
            lines.append(f"文件：{name}（sha256 {digest}）" if digest else f"文件：{name}（未传输）")
    commit = result.get("commit")
    if isinstance(commit, dict) and isinstance(commit.get("commit"), str):
        lines.append(f"提交：{commit['commit']}")
    return lines


def _reject(store: FederatedStore, ident: Identity, task: FedTask | None, report: dict[str, Any], *,
            reporter_device: str, reason: str, now: int) -> Decision:
    assert reason in DECISION_REASONS, reason
    revision = task.revision if task is not None else 1
    store.add_decision(reporter_device=reporter_device, report_operation_id=report["operationId"],
                       authority_revision=revision, decision="rejected", reason=reason)
    if task is not None:
        store.add_event(task.authority_device, task.task_id, "report_rejected", now=now,
                        attempt_seq=report.get("attempt"), detail={"reason": reason, "kind": report.get("kind")})
        _send_decision(store, ident, task, report, reporter_device=reporter_device, decision="rejected",
                       reason=reason, now=now)
    return Decision("rejected", reason, revision)


def _send_decision(store: FederatedStore, ident: Identity, task: FedTask, report: dict[str, Any], *,
                   reporter_device: str, decision: str, reason: str | None, now: int) -> None:
    if reporter_device == ident.device_id:
        return  # A 本机参与方的报告在同一事务里已经裁决，不经 hub 给自己发决定（§88.4 第 6 条）
    checkpoint = build_checkpoint(task, store.attempts(task.authority_device, task.task_id))
    envelope, digest = envelopes.build(
        kind="report_decision", target_device=reporter_device, authority_device=task.authority_device,
        task_id=task.task_id, revision=task.revision, now=now, attempt=report.get("attempt"),
        data=envelopes.checkpoint_data(checkpoint, reportOperationId=report["operationId"], decision=decision,
                                       reason=reason, reportNo=report.get("reportNo")),
    )
    store.add_operation(source_device=ident.device_id, operation_id=envelope["operationId"], msg_id=envelope["msg_id"],
                        payload_hash=digest, result={"kind": "report_decision"}, now=now)
    store.add_outbox(msg_id=envelope["msg_id"], operation_id=envelope["operationId"], target_device=reporter_device,
                     envelope=envelope, payload_hash=digest, expires_at=envelope["expiresAt"], now=now)


def apply_report(store: FederatedStore, ident: Identity, report: dict[str, Any], *, reporter_device: str,
                 now: int, command: str = "ab") -> Decision:
    """A 裁决一条报告（远端报告与 A 本机参与方报告共用）。

    report 字段：authorityDeviceId/taskId/attempt/reportNo/operationId/kind/note/refs/commit/reporter/reporterClass/source。
    远端报告本身就是收到任务的证据，不套本机 `_UNSENT` 门（§88.4 P2-3）；reportNo 采用高水位，不等缺号。
    """
    with store.transaction():
        existing = store.decision(reporter_device, report["operationId"])
        if existing is not None:
            return Decision(existing["decision"], existing["reason"], int(existing["authority_revision"]), duplicate=True)
        task = store.get_task(report["authorityDeviceId"], report["taskId"])
        if task is None or not task.is_authority or task.authority_device != ident.device_id:
            return _reject(store, ident, None, report, reporter_device=reporter_device, reason="authority_mismatch", now=now)
        seq = report.get("attempt")
        report_no = int(report.get("reportNo", 0))
        prior = store.report_by_operation(reporter_device, report["operationId"])
        if prior is None:
            try:
                store.add_report(authority_device=task.authority_device, task_id=task.task_id,
                                 attempt_seq=int(seq or 0), reporter_device=reporter_device, report_no=report_no,
                                 operation_id=report["operationId"], report=report)
            except StoreError as error:
                if error.code != "record_conflict":
                    raise  # 锁忙/写满等暂时故障：整轮不提交，收件不 ACK，等重推再裁决
                return _reject(store, ident, task, report, reporter_device=reporter_device,
                               reason="report_sequence_conflict", now=now)
        attempts = store.attempts(task.authority_device, task.task_id)
        attempt = next((item for item in attempts if item.seq == seq), None)
        if attempt is None:
            return _reject(store, ident, task, report, reporter_device=reporter_device, reason="attempt_not_found", now=now)
        if attempt.role == "notice":
            return _reject(store, ident, task, report, reporter_device=reporter_device,
                           reason="attempt_not_reportable", now=now)
        reporter = report.get("reporter")
        # 报告者要与 attempt 目标的完整绑定一致：设备、provider、会话 UUID 与 endpointId（不同根的同 UUID 不算）
        if (reporter_device != attempt.target_device or not isinstance(reporter, dict)
                or reporter.get("deviceId") != reporter_device
                or reporter.get("nativeId") != attempt.target.remote.native_id
                or reporter.get("provider") != attempt.target.remote.provider.value
                or reporter.get("endpointId") != attempt.target.remote.endpoint_id):
            return _reject(store, ident, task, report, reporter_device=reporter_device, reason="reporter_mismatch", now=now)
        high = int(attempt.authority_state.get("reportHigh", 0))
        if report_no <= high:
            # 迟到低号只记历史，不覆盖高号、不开新通知（§88.4 第 3 条）；决定照样发回报告方，镜像不用等 relay 的窄同步
            # 就能越过这一号（§97.2 第 4 条 r2）。取值旧 B 已认识，窄同步本来也会给出同样的答案
            store.add_decision(reporter_device=reporter_device, report_operation_id=report["operationId"],
                               authority_revision=task.revision, decision="superseded", reason=None)
            _send_decision(store, ident, task, report, reporter_device=reporter_device, decision="superseded",
                           reason=None, now=now)
            return Decision("superseded", None, task.revision)
        if task.finished:
            return _reject(store, ident, task, report, reporter_device=reporter_device, reason="task_finished", now=now)
        if task.current_work_seq != attempt.seq or attempt.superseded:
            return _reject(store, ident, task, report, reporter_device=reporter_device, reason="stale_attempt", now=now)
        try:
            kind = ReportKind(report.get("kind"))
        except ValueError:
            return _reject(store, ident, task, report, reporter_device=reporter_device,
                           reason="report_kind_mismatch", now=now)
        if kind in (ReportKind.APPROVE, ReportKind.CHANGES) and attempt.role != "review":
            return _reject(store, ident, task, report, reporter_device=reporter_device,
                           reason="verdict_requires_review", now=now)
        if kind is ReportKind.RESULT and attempt.role == "review":
            return _reject(store, ident, task, report, reporter_device=reporter_device,
                           reason="review_requires_verdict", now=now)
        work_now = attempt.effective_work.get("work")
        if work_now in (Work.RESULT.value, Work.FAILED.value):
            return _reject(store, ident, task, report, reporter_device=reporter_device,
                           reason="result_already_submitted", now=now)
        return _accept_report(store, ident, task, attempts, attempt, report, kind, reporter_device=reporter_device,
                              now=now, command=command)


def _accept_report(store: FederatedStore, ident: Identity, task: FedTask, attempts: list[FedAttempt],
                   attempt: FedAttempt, report: dict[str, Any], kind: ReportKind, *, reporter_device: str, now: int,
                   command: str) -> Decision:
    result: dict[str, Any] = {"note": report.get("note") or "", "refs": list(report.get("refs") or []),
                              "source": report.get("source", "agent"), "reportedAt": now}
    if isinstance(report.get("commit"), dict):
        result["commit"] = report["commit"]
    # 与镜像读时推导共用同一个折叠函数（§97.2）：A 的行为不变
    effective = fold_report(attempt.effective_work, kind, result=result, at=now)
    delivery = dict(attempt.delivery)
    delivery["receiverReported"] = True  # 只写 A 侧派生视图，不覆盖 B 的原始证据
    authority_state = dict(attempt.authority_state)
    authority_state["reportHigh"] = int(report.get("reportNo", 0))
    store.update_attempt_columns(attempt.msg_id, effective_work=effective, delivery=delivery,
                                 authority_state=authority_state)
    changes: dict[str, Any] = {}
    if kind is ReportKind.APPROVE:
        changes["verdict"] = "approved"
    elif kind is ReportKind.CHANGES:
        changes["verdict"] = "changes_requested"
    task = _bump(store, task, now=now, **changes)
    store.add_event(task.authority_device, task.task_id, kind.value, now=now, attempt_seq=attempt.seq,
                    detail={"source": result["source"], "reporterDevice": short(reporter_device)})
    store.add_decision(reporter_device=reporter_device, report_operation_id=report["operationId"],
                       authority_revision=task.revision, decision="accepted", reason=None)
    decision = Decision("accepted", None, task.revision)
    attempts = store.attempts(task.authority_device, task.task_id)
    first = next((item for item in attempts if item.role != "notice"), attempt)
    reviewer = task.reviewer()
    reporter_actor = WireActor.from_dict(report["reporter"]) if isinstance(report.get("reporter"), dict) else None
    reporter_class = str(report.get("reporterClass") or "unknown")
    if (kind is ReportKind.RESULT and attempt.role == "handoff" and task.state.get("flow") == "review"
            and reviewer is not None):
        if not can_notify(reviewer):
            # 与本机一致：结果与自动复核一起回滚（§45.34），作为确定业务拒绝写进决定
            raise _Rollback("target_no_inbox")
        try:
            task, review = add_attempt(
                store, ident, task, role="review", target=reviewer, body=_review_body(attempt, result),
                refs=list(report.get("refs") or []), sender=first.sender, sender_class=first.sender_class,
                options={"allowShared": first.options.get("allowShared") is True or task.state.get("allowShared") is True},
                now=now,
            )
            decision.followups.append(review)
        except StoreError as error:
            if error.code not in CAPACITY_CODES:
                raise
            decision.skipped["review"] = error.code
            store.add_event(task.authority_device, task.task_id, "review_skipped_capacity", now=now,
                            attempt_seq=attempt.seq, detail={"reason": error.code})
    origin = task.origin()
    if (not decision.followups and kind in NOTIFYING_REPORTS and origin is not None
            and task.state.get("notifyOrigin", True) is not False and not _same_session(origin, attempt.target)):
        if can_notify(origin):
            view_task = model_task(task)
            view_attempts = model_attempts(store.attempts(task.authority_device, task.task_id))
            step = next_step(view_task, view_attempts, ref=short(task.task_id), command=command, reserved=1)
            next_text = step.text if step else None
            if "review" in decision.skipped:
                next_text = review_capacity_hint(decision.skipped["review"])
            title = f"「{task.title}」" if task.title else ""
            # 执行方标识按结构化身份生成（完整 ID），不照抄对端信封里的 wireToken：W3.9 对端仍发友好名（附注 P3-4）
            label = (id_token(reporter_actor.provider, reporter_actor.native_id) if reporter_actor
                     else id_token(attempt.target.remote.provider, attempt.target.remote.native_id))
            lines = [f"你发起的任务{title}{REPORT_LABELS[kind]}（{label}）。", *_describe_result(result)]
            if next_text:
                lines.append(f"下一步：{next_text}")
            try:
                task, notice = add_attempt(
                    store, ident, task, role="notice", target=origin, body="\n".join(lines),
                    refs=list(report.get("refs") or []), sender=reporter_actor, sender_class=reporter_class,
                    options={"noticeKind": "result"}, now=now,
                )
                decision.followups.append(notice)
            except StoreError as error:
                if error.code not in CAPACITY_CODES:
                    raise
                decision.skipped["result"] = error.code
                store.add_event(task.authority_device, task.task_id, "notification_skipped", now=now,
                                attempt_seq=attempt.seq, detail={"reason": error.code, "route": "result"})
        else:
            store.add_event(task.authority_device, task.task_id, "notification_skipped", now=now,
                            attempt_seq=attempt.seq, detail={"reason": "poll_only", "route": "result"})
    decision.revision = task.revision
    _send_decision(store, ident, task, report, reporter_device=reporter_device, decision="accepted", reason=None, now=now)
    return decision


class _Rollback(Exception):
    """确定业务拒绝：回滚报告的状态推进，但保留报告事实并写拒绝决定。"""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


def apply_report_safely(store: FederatedStore, ident: Identity, report: dict[str, Any], *, reporter_device: str,
                        now: int, command: str = "ab") -> Decision:
    """apply_report 的外层：确定业务拒绝（如复核方无收件通道）回滚推进后，另开事务写报告事实与拒绝决定。"""
    try:
        return apply_report(store, ident, report, reporter_device=reporter_device, now=now, command=command)
    except _Rollback as rollback:
        with store.transaction():
            existing = store.decision(reporter_device, report["operationId"])
            if existing is not None:
                return Decision(existing["decision"], existing["reason"], int(existing["authority_revision"]),
                                duplicate=True)
            task = store.get_task(report["authorityDeviceId"], report["taskId"])
            if store.report_by_operation(reporter_device, report["operationId"]) is None and task is not None:
                store.add_report(authority_device=task.authority_device, task_id=task.task_id,
                                 attempt_seq=int(report.get("attempt") or 0), reporter_device=reporter_device,
                                 report_no=int(report.get("reportNo", 0)), operation_id=report["operationId"],
                                 report=report)
            return _reject(store, ident, task, report, reporter_device=reporter_device, reason=rollback.reason, now=now)


def _review_body(attempt: FedAttempt, result: dict[str, Any]) -> str:
    # 复核请求可能发往另一台设备：执行方写完整 ID，不写 8 位短 ID（附注 P3-1）
    lines = [f"请复核 {id_token(attempt.target.remote.provider, attempt.target.remote.native_id)} 完成的这项工作。", "",
             "【结果】"]
    lines.extend(_describe_result(result) or ["（对方未附说明）"])
    lines.extend(["", "【原始任务要求】", attempt.body.rstrip()])
    text = "\n".join(lines)
    encoded = text.encode("utf-8")
    if len(encoded) > 64 * 1024 - 64:
        text = encoded[: 64 * 1024 - 128].decode("utf-8", errors="ignore") + "\n…（原始任务过长，已截断）"
    return text


# ---- 投递证据 ----


def apply_evidence(store: FederatedStore, task: FedTask, msg_id: str, evidence_no: int, evidence: dict[str, Any], *,
                   delivery_device: str, now: int) -> bool:
    """导入投递设备的证据（高水位）；只有该 attempt 的目标设备能出具，迟到低号只留历史。"""
    with store.transaction():
        attempt = store.attempt_by_msg(msg_id)
        if attempt is None or attempt.task_id != task.task_id or attempt.target_device != delivery_device:
            raise StoreError("evidence_writer_mismatch")
        store.add_evidence(msg_id, evidence_no, delivery_device=delivery_device, evidence=evidence)
        if evidence_no <= attempt.evidence_no:
            return False
        delivery = dict(attempt.delivery)
        for key in ("state", "reason", "at", "consumption"):
            if key in evidence:
                delivery[key] = evidence[key]
        store.update_attempt_columns(msg_id, delivery=delivery, evidence_no=evidence_no)
        store.add_event(task.authority_device, task.task_id, f"delivery_{evidence.get('state')}", now=now,
                        attempt_seq=attempt.seq, detail={"reason": evidence.get("reason")} if evidence.get("reason") else None)
    return True


# ---- 控制 ----


def proven_undelivered(attempt: FedAttempt, ident: Identity) -> bool:
    """A 能否证明该 attempt 未被投递：远端只认投递设备的证据，本机认本机原生事实。"""
    state = attempt.delivery.get("state", "pending")
    if attempt.delivery.get("receiverReported") is True:
        return False
    if attempt.target_device == ident.device_id:
        return state in ("pending", "cancelled", "failed", "refused", "denied", "expired")
    return state in REMOTE_PROVEN_UNDELIVERED


def _has_arrival_evidence(attempt: FedAttempt) -> bool:
    """A 是否握有远端尝试已到达对方的证据：对方已汇报，或投递状态属于 REMOTE_ARRIVAL_EVIDENCE（§98.1）。"""
    return (attempt.delivery.get("receiverReported") is True
            or attempt.delivery.get("state", "pending") in REMOTE_ARRIVAL_EVIDENCE)


def _awaiting_remote_evidence(attempt: FedAttempt) -> bool:
    """远端 attempt 还没有投递设备的任何证据（A 视角仍是 pending）：只有这种还值得发抑制请求。"""
    return attempt.delivery.get("state", "pending") == "pending" and attempt.delivery.get("receiverReported") is not True


def request_cancel(store: FederatedStore, ident: Identity, task: FedTask, *, now: int) -> tuple[FedTask, bool]:
    """cancel：远端只写取消请求并通知成员，本机未领取的作业直接抑制；返回 (任务, 是否有远端待确认)。

    A 本机的取消请求不是「已证明未投」：远端 attempt 的投递状态保持原样，等 B 的抑制证据（§88.4 P2-1）。
    """
    with store.transaction():
        current = store.get_task(task.authority_device, task.task_id) or task
        remote_pending = False
        for attempt in store.attempts(task.authority_device, task.task_id):
            # 补充消息与工作尝试一样取消（§95.5.2）；其余 notice（结果通知、提醒、结束回执）不受 cancel 影响
            if (attempt.role == "notice" and not attempt.is_note) or attempt.delivery.get("receiverReported") is True:
                continue
            if attempt.target_device == ident.device_id:
                _suppress_local(store, current, attempt, reason="cancelled", now=now)
                continue
            if proven_undelivered(attempt, ident) or attempt.cancel_requested:
                continue
            if attempt.is_note and not _awaiting_remote_evidence(attempt):
                # B 已回报交出（queued/delivered 等）的补充消息撤不回：不标取消请求，免得报「对方设备尚未确认」（P3-7）
                continue
            authority_state = dict(attempt.authority_state)
            authority_state["cancelRequested"] = True
            store.update_attempt_columns(attempt.msg_id, authority_state=authority_state)
            remote_pending = True
        current = _bump(store, current, now=now)
        store.add_event(current.authority_device, current.task_id, "cancel_requested", now=now,
                        detail={"remotePending": remote_pending})
        send_task_state(store, ident, current, now=now)
    return current, remote_pending


def _suppress_local(store: FederatedStore, task: FedTask, attempt: FedAttempt, *, reason: str, now: int) -> None:
    native = store.native(attempt.msg_id)
    if native is None or native["state"] != "prepared":
        return
    store.connection.execute("UPDATE fed_native_sends SET state='suppressed', result_json=? WHERE msg_id=?"
                             " AND state='prepared'", (dump({"reason": reason}), attempt.msg_id))
    evidence_no = attempt.evidence_no + 1
    store.add_evidence(attempt.msg_id, evidence_no, delivery_device=attempt.target_device,
                       evidence={"state": "cancelled", "reason": reason, "at": now})
    delivery = dict(attempt.delivery, state="cancelled", reason=reason, at=now)
    store.update_attempt_columns(attempt.msg_id, delivery=delivery, evidence_no=evidence_no)


def set_paused(store: FederatedStore, ident: Identity, task: FedTask, *, paused: bool, now: int) -> FedTask:
    with store.transaction():
        current = store.get_task(task.authority_device, task.task_id) or task
        current = _bump(store, current, now=now, control="paused" if paused else "active")
        store.add_event(current.authority_device, current.task_id, "paused" if paused else "resumed", now=now)
        send_task_state(store, ident, current, now=now)
    return current


@dataclass
class RetryOutcome:
    task: FedTask
    attempt: FedAttempt
    undelivered: bool
    rework: bool


def retry_task(store: FederatedStore, ident: Identity, task: FedTask, *, force: bool, message: str | None,
               new_target: TargetRef | None, rework_body: Callable[[Attempt, Attempt, Task, str | None], str],
               now: int, allow_shared: bool = False) -> RetryOutcome:
    """A 上重发或返工（与本机 `_retry_in_transaction` 同口径）：校验、作废本机待发通知、追加新尝试、清 verdict 同一事务。

    远端「仍在途」（无 B 证据）与本机 PENDING 一样报 still_pending；--force 可越过远端在途（B 收到新 checkpoint 后
    按 current_work_seq 抑制旧作业，已 intent 的照实记），本机 PENDING 不可越过。返工文案复用本机 `_rework_body`。
    """
    with store.transaction():
        current_task = store.get_task(task.authority_device, task.task_id)
        if current_task is None or not current_task.is_authority:
            raise StoreError("task_not_found")
        if current_task.finished:
            raise StoreError("task_finished")
        attempts = store.attempts(task.authority_device, task.task_id)
        work = [item for item in attempts if item.role != "notice"]
        if not work:
            raise StoreError("attempt_not_found")
        first, current = work[0], next((item for item in work if item.seq == current_task.current_work_seq), work[-1])
        view_task, view_first, view_current = model_task(current_task), model_attempt(first), model_attempt(current)
        local_target = current.target_device == ident.device_id
        undelivered = proven_undelivered(current, ident)
        rework = view_current.work in (Work.BLOCKED, Work.FAILED) or (
            view_current.role is Role.REVIEW and view_task.verdict is Verdict.CHANGES
        ) or (view_current.work is Work.RESULT and view_current.role is Role.HANDOFF)
        if view_current.delivery is Delivery.PENDING and not rework and (local_target or not force):
            raise StoreError("still_pending")
        if not (undelivered or rework or force):
            raise StoreError("retry_requires_force")
        role, target = current.role, current.target
        if undelivered and not rework:
            body = current.body if not message else f"{current.body}\n\n补充：{message}"
        else:
            if view_current.role is Role.REVIEW and view_task.verdict is Verdict.CHANGES:
                role = "handoff"
                target = next((item for item in reversed(work) if item.role == "handoff"), first).target
            body = rework_body(view_first, view_current, view_task, message)
        if new_target is not None:
            target = new_target
        if not can_notify(target):
            raise StoreError("target_no_inbox")
        # 先作废本机待发的旧通知（返工意味着旧结果不作数）；远端通知随新 checkpoint 由 B 判定
        for stale in attempts:
            if stale.role == "notice" and stale.target_device == ident.device_id and not stale.is_closure:
                _suppress_local(store, current_task, stale, reason="notice_outdated", now=now)
            elif stale.is_note and _awaiting_remote_evidence(stale) and not stale.superseded:
                # 远端的补充消息补的是旧尝试：只给 B 还没回报任何投递结果的标 superseded，随新 checkpoint 到对方后
                # 按 stale_attempt 抑制（旧读方也认这个标志）；B 已回报交出（queued/delivered 等）或已证明未投的不再标
                # （§95.5.2，G4 审计 r1 P3-7）
                store.update_attempt_columns(stale.msg_id, authority_state=dict(stale.authority_state, superseded=True))
        allow_shared = (allow_shared or current.options.get("allowShared") is True
                        or current_task.state.get("allowShared") is True)
        reset = _bump(store, current_task, now=now, control="active", verdict=None)
        updated, attempt = add_attempt(
            store, ident, reset, role=role, target=target, body=body,
            refs=list(first.refs if role == "handoff" else current.refs), sender=first.sender,
            sender_class=first.sender_class, options={"allowShared": allow_shared}, now=now, event="retry")
        # 新尝试的信封已带最新 checkpoint；其余远端成员另发一次 task_state，让 B 上的旧作业按新序号抑制
        others = [device for device in members(updated, store.attempts(task.authority_device, task.task_id))
                  if device != attempt.target_device]
        send_task_state(store, ident, updated, now=now, devices=others)
    return RetryOutcome(updated, attempt, undelivered, rework)


@dataclass
class FinishOutcome:
    task: FedTask
    closures: list[FedAttempt] = field(default_factory=list)
    skipped: list[str] = field(default_factory=list)
    # 有远端工作尝试还没有到达证据（§98.1）：CLI 据此打印「尚未证明送达」提示，accept/close 的 JSON 同值
    remote_unconfirmed: bool = False


def finish(store: FederatedStore, ident: Identity, task: FedTask, *, state: str, reason: str | None, decider: str,
           sender: WireActor | None, sender_class: str, now: int, command: str = "ab") -> FinishOutcome:
    """accept/close：终态与结束回执同一事务；远端未证明未投的工作由 B 决定投递或抑制结束回执（§88.4 P2-1）。"""
    assert state in (ACCEPTED, CLOSED)
    with store.transaction():
        current = store.get_task(task.authority_device, task.task_id) or task
        if current.state.get("closedAt") is not None or (current.finished and state == ACCEPTED):
            raise StoreError("task_finished")
        if current.finished:
            # 已验收后补记关闭：只记关闭时间，不发第二份结束回执（与本机 cmd_close 同口径）
            current = _bump(store, current, now=now, closedAt=now, closeReason=reason)
            store.add_event(current.authority_device, current.task_id, state, now=now)
            send_task_state(store, ident, current, now=now)
            return FinishOutcome(current)
        changes: dict[str, Any] = {"acceptedAt": now} if state == ACCEPTED else {"closedAt": now, "closeReason": reason}
        current = _bump(store, current, now=now, **changes)
        store.add_event(current.authority_device, current.task_id, state, now=now)
        attempts = store.attempts(current.authority_device, current.task_id)
        outcome = FinishOutcome(current)
        body = closure_body(model_task(current), state, decider=decider, reason=reason, command=command)
        origin = current.origin()
        planned: list[tuple[TargetRef, list[str], bool]] = []
        for role in ("handoff", "review"):
            work = [item for item in attempts if item.role == role]
            if not work:
                continue
            remote_unproven = [item for item in work if item.target_device != ident.device_id
                               and not proven_undelivered(item, ident)]
            if remote_unproven:
                latest = max(remote_unproven, key=lambda item: item.seq)
                covers = [item.msg_id for item in remote_unproven]
                planned.append((latest.target, covers, True))
                # 回执照旧覆盖全部未证明未投的尝试；提示只看到达证据，同一角色任一尝试还没有就提示（§98.1）
                if any(not _has_arrival_evidence(item) for item in remote_unproven):
                    outcome.remote_unconfirmed = True
                continue
            arrived = [item for item in work if item.target_device == ident.device_id
                       and _local_may_have_arrived(item)]
            if arrived:
                latest = max(arrived, key=lambda item: item.seq)
                planned.append((latest.target, [latest.msg_id], False))
        merged: list[tuple[TargetRef, list[str], bool]] = []
        for target, covers, remote in planned:
            if origin is not None and _same_session(origin, target):
                continue
            existing = next((item for item in merged if _same_session(item[0], target)), None)
            if existing is not None:
                existing[1].extend(covers)
                continue
            merged.append((target, list(covers), remote))
        for target, covers, remote in merged:
            if not can_notify(target):
                store.add_event(current.authority_device, current.task_id, "notification_skipped", now=now,
                                detail={"reason": "target_no_inbox", "route": state})
                continue
            options: dict[str, Any] = {"noticeKind": "closure", "closure": state}
            if remote:
                options["coversWorkMessageIds"] = covers
            try:
                current, closure = add_attempt(store, ident, current, role="notice", target=target, body=body, refs=[],
                                               sender=sender, sender_class=sender_class, options=options, now=now,
                                               event="closure_created")
                outcome.closures.append(closure)
            except StoreError as error:
                if error.code not in CAPACITY_CODES:
                    raise
                outcome.skipped.append(error.code.removeprefix("capacity_"))
                store.add_event(current.authority_device, current.task_id, "closure_skipped_capacity", now=now,
                                detail={"capacity": error.code.removeprefix("capacity_")})
        # 本机未领取的旧工作直接抑制；远端由 checkpoint 的终态在 B 上抑制
        for item in attempts:
            if (item.role != "notice" or item.is_note) and item.target_device == ident.device_id:
                _suppress_local(store, current, item, reason="task_finished", now=now)
        outcome.task = current
        send_task_state(store, ident, current, now=now)
    return outcome


def _local_may_have_arrived(attempt: FedAttempt) -> bool:
    if attempt.delivery.get("receiverReported") is True:
        return True
    try:
        return Delivery(attempt.delivery.get("state", "pending")) in MAY_HAVE_ARRIVED
    except ValueError:
        return True


def resolve_remote_target(target: RemoteEndpointRef) -> TargetRef:
    """远端目标包装成 TargetRef（无本机字段）。"""
    return TargetRef(remote=target)
