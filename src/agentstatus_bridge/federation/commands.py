"""联邦 CLI 操作（DESIGN §88.6/§88.7/§88.10/§88.12）：send --device、report --origin-device、控制、状态、启停与 relay。

纯本机命令路径完全不变：只有显式 `--device/--origin-device`、或本机库找不到而联邦库有唯一命中时才进入这里。
所有联邦写入只开 federation.sqlite3；L0（本机已记录）成功即返回 0，后台不可用时返回 6，都不能重跑。
本模块不 import cli：本机返工文案等由 cli 以参数传入，保持 import 图无环。
"""

from __future__ import annotations

import json
import os
import sqlite3
import time
from collections.abc import Callable
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any

from ..closure import ACCEPTED
from ..endpoints import ADAPTERS, Caller, DiscoverySources, Endpoint, discover
from ..ids import short
from ..labels import reason_text
from ..model import PHASE_LABELS, Attempt, EndpointRef, Phase, Provider, ReportKind, Task, TaskView, describe
from ..naming import command_name
from ..native_names import full_id_token
from ..platforms import process as procfs
from ..platforms.factory import get_platform
from ..platforms.types import Capability
from ..reports import (  # pyright: ignore[reportPrivateUsage]
    _UNSENT,
    MAX_NOTE_CHARS,
    ReportError,
    ReportInput,
    _attribute,
    _commit_reference,
    _git_resolve_commit,
)
from ..store import MAX_BODY_BYTES, MAX_FILES, StoreError
from ..worker import ensure_worker
from . import attachments, authority, budget, config as fed_config, directory, mirror
from .attachments import AttachmentError, Frozen
from .authority import Identity
from .codec import is_hex32
from .errors import FedCliError
from .fedstore import FED_DB_NAME, FederatedStore, FedAttempt, FedTask, load_dict, now_ms
from .refs import TargetRef, WireActor
from .relay import STOP_STATES, Relay, RelayPaths, ssh_connector
from .relay_control import RelayDiagnostics, StopController, config_disabled, install_sigterm
from .relay_control import valid_distribution_version
from .views import model_attempt, model_attempts, model_task

RELAY_LOCK = "federation-relay.lock"
# 待传超过 30 分钟叠加「远端离线/传输未恢复」提示（§88.6）；只是提示，不改业务状态
STALLED_MS = 30 * 60 * 1000
RELAY_STATES = frozenset({"starting", "connected", "reconnecting", "offline", "auth_failed", "incompatible",
                          "storage_failed"})


@dataclass
class Runtime:
    """一次联邦命令的上下文：已核对的配置、联邦库、本机身份与路径。"""

    root: Path
    config: fed_config.FederationConfig
    store: FederatedStore
    ident: Identity
    paths: RelayPaths

    def close(self) -> None:
        self.store.close()


def _paths(root: Path) -> RelayPaths:
    appdata = os.environ.get("LOCALAPPDATA")
    return RelayPaths(root, windows=get_platform().name == "windows", local_appdata=Path(appdata) if appdata else None)


def configured(root: Path) -> bool:
    """是否存在联邦配置（未配置的机器完全不碰联邦库）。"""
    return (root / fed_config.CONFIG_NAME).exists()


def open_runtime(root: Path, *, require_enabled: bool = True) -> Runtime:
    """核配置与 expectedStateRoot 后打开联邦库；绝不新建，库缺失报 federation_store_missing。"""
    try:
        config = fed_config.load(root)
    except fed_config.ConfigError as error:
        raise FedCliError(error.code) from error
    if config is None:
        raise FedCliError("federation_not_configured", 9)
    if require_enabled and not config.enabled:
        raise FedCliError("federation_disabled", 9)
    try:
        fed_config.check_state_root(config, root)
    except fed_config.ConfigError as error:
        raise FedCliError(error.code) from error
    if not (root / FED_DB_NAME).exists():
        raise FedCliError("federation_store_missing", 8)
    try:
        store = FederatedStore.open(root)
    except StoreError as error:
        raise FedCliError(error.code, 8) from error
    try:
        device_id, hub_id = store.device_id(), store.meta("hubId")
    except StoreError:
        device_id = hub_id = None
    if device_id != config.device_id:
        store.close()
        raise FedCliError("ledger_instance_mismatch", 8)
    if hub_id != config.hub_id:
        store.close()
        raise FedCliError("federation_rebuild_incomplete", 8)  # 库已换 hub、配置没写完：重跑 rebuild 即可补齐
    return Runtime(root, config, store, Identity(config.device_id, config.device_name, config.hub_id), _paths(root))


def try_runtime(root: Path) -> Runtime | None:
    """查询/回退路径用：未配置或打不开都返回 None（不能让联邦故障打断本机命令）；停用后仍可读历史。"""
    if not configured(root):
        return None
    try:
        return open_runtime(root, require_enabled=False)
    except FedCliError:
        return None


def relay_running(root: Path) -> bool | None:
    """只读瞬时探测 relay 单例锁（DESIGN §90.6）：忙=True，可取=False，根或锁不存在=False，权限/IO 异常=None。

    不新建根或锁、不修 ACL、不打开任何 SQLite；只回答探测当时是否有人持有锁，不证明 hub 已连接。
    """
    try:
        return get_platform().lifecycle.probe_lock(root / RELAY_LOCK)
    except FileNotFoundError:
        return False
    except OSError:
        return None


# ---- 目标 ----


def is_local_device(rt: Runtime, reference: str | None) -> bool:
    return reference is None or reference in (rt.ident.device_name, rt.ident.device_id)


def local_target(rt: Runtime, endpoint: Endpoint) -> TargetRef:
    """本机已核端点 → 带持久 endpointId 的 TargetRef；根核实不了按用户可读错误拒绝。"""
    try:
        return directory.bind_local(rt.store, rt.ident.device_id, endpoint.ref,
                                    verified_name=directory.published_name(endpoint, publish_names=rt.config.publish_names))
    except directory.DirectoryError as error:
        raise FedCliError(error.code, 2) from error


def remote_target(rt: Runtime, device: str, selector: str, *, now: int | None = None,
                  flags: tuple[str, str] = ("--device", "--to")) -> TargetRef:
    """在缓存目录里解析远端目标；本机 slug 不当远端。名字/前缀要求目录新鲜（now 缺省取当前时刻）。

    flags 是这一对参数在命令行上的写法（执行方 `--device/--to`，复核方 `--review-device/--review-by`），
    候选提示按它给出可照抄的写法，免得把复核方抄成执行方（Opus 实现审计 r2 P2-1）。"""
    if is_local_device(rt, device):
        raise FedCliError("target_is_local_device", 2)
    try:
        return directory.resolve_remote(rt.store, device, selector, now=now_ms() if now is None else now)
    except directory.DirectoryError as error:
        raise FedCliError(error.code, 2, hint=_candidate_hint(device, error.candidates, flags)) from error


def _candidate_hint(device: str, candidates: tuple[str, ...], flags: tuple[str, str]) -> str | None:
    """名字未核实/不唯一时把候选给成可照抄的完整写法（§91.2.2「提示 peers --device 及全 ID」）；
    设备引用不唯一时候选是完整 deviceId。参数名取调用方给的那一对，不固定写执行方的。"""
    if not candidates:
        return None
    device_flag, target_flag = flags
    if all("@id:" in item for item in candidates):
        return "可选目标：" + "、".join(f"{device_flag} {device} {target_flag} {item}" for item in candidates)
    return "可选设备：" + "、".join(f"{device_flag} {item}" for item in candidates)


def _actor(rt: Runtime, ref: EndpointRef) -> WireActor:
    try:
        bound = directory.bind_local(rt.store, rt.ident.device_id, ref, verified_name=None)  # actor 一律完整 ID
    except directory.DirectoryError as error:
        raise FedCliError(error.code, 2) from error
    return authority.actor_for(bound, wire_token=full_id_token(ref))


# ---- send ----


@dataclass
class SendOutcome:
    task: FedTask
    attempt: FedAttempt
    target: TargetRef
    blobs: int
    blob_bytes: int
    references: int
    device_name: str


def freeze_refs(rt: Runtime, paths: list[str], cwd: Path) -> list[Frozen]:
    """冻结 --ref/--file 点名的文件；有点名时先按设备内容预算预检（§88.11），不足在写任务/报告前拒绝。"""
    if not paths:
        return []
    left = budget.available(rt.store, rt.paths, rt.config.storage_budget)
    try:
        return attachments.freeze(paths, cwd=cwd, origin_device=rt.ident.device_id, staging=rt.paths.staging,
                                  available=left)
    except AttachmentError as error:
        raise FedCliError(error.code) from error


def send(rt: Runtime, *, target: TargetRef, body: str, title: str, ref_paths: list[str], cwd: Path,
         origin: EndpointRef | None, origin_class: str | None, reviewer: TargetRef | None, allow_shared: bool,
         no_notify: bool) -> SendOutcome:
    """A 上建联邦任务（L0）。至少一方在别的设备（本机目标 + 远端复核也算）；参与设备超过两台写前拒绝（§88.14/T16）。"""
    if len(body.encode("utf-8")) > MAX_BODY_BYTES:
        raise FedCliError("message_too_large")
    local_target_only = target.remote.device_id == rt.ident.device_id
    if local_target_only and (reviewer is None or reviewer.remote.device_id == rt.ident.device_id):
        raise FedCliError("target_is_local_device", 2)  # 全在本机：用本机 send
    if reviewer is not None:
        if len({rt.ident.device_id, target.remote.device_id, reviewer.remote.device_id}) > 2:
            raise FedCliError("federation_review_device_unsupported")
        if reviewer.remote.same_endpoint(target.remote):
            raise FedCliError("reviewer_is_target")
    origin_actor = _actor(rt, origin) if origin is not None else None
    origin_target = (directory.bind_local(rt.store, rt.ident.device_id, origin, verified_name=None)
                     if origin is not None else None)
    frozen = freeze_refs(rt, ref_paths, cwd)
    blobs, blob_bytes, references = attachments.transfer_summary(frozen)
    reviewer_token = full_id_token(reviewer.local) if reviewer is not None and reviewer.local is not None else None
    try:
        task, attempt = authority.create_task(
            rt.store, rt.ident, title=title, flow="review" if reviewer else "handoff", body=body,
            refs=[item.manifest for item in frozen], origin=origin_target, origin_actor=origin_actor,
            origin_class=origin_class or "unknown", target=target, reviewer=reviewer, reviewer_token=reviewer_token,
            notify_origin=not no_notify, allow_shared=allow_shared, now=now_ms())
    except StoreError as error:
        raise FedCliError(error.code) from error
    return SendOutcome(task, attempt, target, blobs, blob_bytes, references, device_name(rt, target.remote.device_id))


# ---- 任务查找 ----


def authority_for(rt: Runtime, origin_device: str) -> str:
    """--origin-device 接受登记 slug 或完整 deviceId；slug→ID 只查本机目录缓存。"""
    if is_local_device(rt, origin_device):
        return rt.ident.device_id
    try:
        return str(directory.device_row(rt.store, origin_device)["device_id"])
    except directory.DirectoryError as error:
        if len(origin_device) == 32 and all(ch in "0123456789abcdef" for ch in origin_device):
            return origin_device
        raise FedCliError(error.code, 2) from error


def find_task(rt: Runtime, reference: str, origin_device: str | None) -> FedTask:
    """按 taskId（前缀）找联邦任务；给了 --origin-device 只在该权威下查。歧义报 task_ambiguous。"""
    authority_id = authority_for(rt, origin_device) if origin_device else None
    found = rt.store.find_tasks(reference, authority_device=authority_id)
    if not found:
        raise FedCliError("task_not_found", 2)
    if len(found) > 1:
        raise FedCliError("task_ambiguous", 2)
    return found[0]


# ---- report ----


def _delivery_detail(rt: Runtime, attempt: FedAttempt) -> dict[str, Any]:
    """本机实际接收代际：取 intent 时记下的活端点（pid/start），没有就按绑定时的引用核。"""
    native = rt.store.native(attempt.msg_id) or {}
    raw = native.get("local_target_json")
    if not isinstance(raw, str):
        return {}
    try:
        delivered = EndpointRef.from_json(raw)
    except (TypeError, ValueError, KeyError):
        return {}
    if delivered is None:
        return {}
    return {"deliveredPid": delivered.pid, "deliveredStart": delivered.start_ticks}


def report(rt: Runtime, *, task: FedTask, kind: ReportKind, attempt_seq: int | None, note: str | None,
           files: list[str], commit: str | None, manual: bool, caller: Caller, caller_class: str | None,
           cwd: Path) -> tuple[FedAttempt, mirror.ReportResult]:
    """目标设备上的联邦报告：核本机真实接收方与当前 attempt，冻结附件，事务分配 reportNo；A 本机参与方立即裁决。"""
    if task.finished:
        raise FedCliError("task_finished")
    mine = [item for item in rt.store.attempts(task.authority_device, task.task_id)
            if item.role != "notice" and item.target_device == rt.ident.device_id]
    current = next((item for item in mine if item.seq == task.current_work_seq), None)
    attempt = current if attempt_seq is None else next((item for item in mine if item.seq == attempt_seq), None)
    if attempt is None:
        raise FedCliError("attempt_not_found")
    if current is None or attempt.seq != current.seq:
        raise FedCliError("stale_attempt")
    if kind in (ReportKind.APPROVE, ReportKind.CHANGES) and attempt.role != "review":
        raise FedCliError("verdict_requires_review")
    if kind is ReportKind.RESULT and attempt.role == "review":
        raise FedCliError("review_requires_verdict")
    if len(files) > MAX_FILES:
        raise FedCliError("too_many_files")
    if attempt.target.local is None:
        raise FedCliError("reporter_mismatch")
    # 只核这一个相关本机 ref 的实际接收代际（§88.7），复用本机 _attribute；不核远端 origin/历史 root
    view = replace(model_attempt(attempt), delivery_detail=_delivery_detail(rt, attempt))
    _windows_root_check(replace(model_task(task), origin=None, reviewer=None), [view])
    try:
        source = _attribute(view, ReportInput(task_ref=task.task_id, kind=kind, manual=manual), caller,
                            procfs.DEFAULT_PROC)
    except ReportError as error:
        raise FedCliError(error.code) from error
    if view.delivery in _UNSENT:
        raise FedCliError("attempt_not_sent")  # 投递设备自己的事实：从未 intent 或已抑制的作业不能汇报
    frozen = freeze_refs(rt, files, cwd)
    commit_ref = None
    if commit:
        try:
            commit_ref = _commit_reference(commit, cwd=cwd, git=_git_resolve_commit)
        except ReportError as error:
            raise FedCliError(error.code) from error
    reporter = authority.actor_for(attempt.target, wire_token=full_id_token(attempt.target.local))
    try:
        result = mirror.submit_report(rt.store, rt.ident, mirror.LocalReport(
            task=task, attempt=attempt, kind=kind.value, note=(note or "").strip()[:MAX_NOTE_CHARS],
            refs=[item.manifest for item in frozen], commit=commit_ref, reporter=reporter,
            reporter_class=caller_class or "unknown", source=source), now=now_ms(), command=command_name())
    except StoreError as error:
        raise FedCliError(error.code) from error
    return attempt, result


# ---- 控制（只在权威设备 A） ----


def may_decide(caller: Caller, task: FedTask) -> bool:
    """与本机 `_may_decide` 同一口径：用户本人或发起会话可以决定；执行方和复核方不能。"""
    if caller.is_user_shell:
        return True
    origin = task.origin()
    return (caller.endpoint is not None and origin is not None and origin.local is not None
            and caller.endpoint.ref.same_session(origin.local))


def _decidable(task: FedTask, caller: Caller) -> FedTask:
    if not task.is_authority:
        raise FedCliError("federation_not_authority")  # B 不能代 A 决定；要 A 处理请 report --blocked
    if not may_decide(caller, task):
        raise FedCliError("accept_not_allowed")
    # 只核本机发起 ref 的 root；远端成员只核认证路由，不交本机 root 检查（§88.7）
    _windows_root_check(replace(model_task(task), reviewer=None), [])
    return task


def _windows_root_check(task: Task, attempts: list[Attempt]) -> None:
    """Windows：对本次相关的本机 ref 复用现行 root/能力核查；远端显示引用不得传入。"""
    if get_platform().name != "windows":
        return
    from ..platforms.windows.commands import check_task  # layout: allow 只核本次相关本机 ref（§88.7）
    check_task(task, attempts)


def set_control(rt: Runtime, task: FedTask, action: str, *, caller: Caller) -> tuple[FedTask, bool]:
    """pause/resume/cancel：A 本机写入并同步 task_state；cancel 远端只写请求，不承诺 L3 撤回。返回 (任务, 远端待确认)。"""
    task = _decidable(task, caller)
    if task.finished:
        raise FedCliError("task_finished")
    if action == "resume" and not task.paused:
        raise FedCliError("not_paused")
    now = now_ms()
    try:
        if action in ("pause", "resume"):
            return authority.set_paused(rt.store, rt.ident, task, paused=action == "pause", now=now), False
        return authority.request_cancel(rt.store, rt.ident, task, now=now)
    except StoreError as error:
        raise FedCliError(error.code) from error


def finish(rt: Runtime, task: FedTask, state: str, *, caller: Caller, caller_class: str | None,
           reason: str | None = None, force: bool = False) -> authority.FinishOutcome:
    """accept/close：终态与结束回执同一事务；结束回执以决定者会话的名义发出（与本机 `_closure_decider` 同口径）。"""
    task = _decidable(task, caller)
    if state == ACCEPTED:
        if task.finished:
            raise FedCliError("task_finished")
        if phase_of(rt, task)[0] is not Phase.AWAITING_ACCEPTANCE and not force:
            raise FedCliError("no_result_to_accept")
    elif task.state.get("closedAt") is not None:
        raise FedCliError("task_finished")
    sender = _actor(rt, caller.endpoint.ref) if caller.endpoint is not None else None
    # 结束回执一份正文、同一事务发给全部参与方（可能跨设备）：decider 一律完整 ID（附注 P3-3）。
    # 不按参与方另渲染：正文随事实固化，本机参与方看到完整 ID 也能复制，代价只是不显示友好名
    decider = full_id_token(caller.endpoint.ref) if caller.endpoint is not None else "用户"
    try:
        return authority.finish(rt.store, rt.ident, task, state=state, reason=reason, decider=decider, sender=sender,
                                sender_class=caller_class or "unknown", now=now_ms(), command=command_name())
    except StoreError as error:
        raise FedCliError(error.code) from error


def retry(rt: Runtime, task: FedTask, *, caller: Caller, message: str | None, force: bool,
          new_target: TargetRef | None, allow_shared: bool,
          rework_body: Callable[[Attempt, Attempt, Task, str | None], str]) -> authority.RetryOutcome:
    """A 上重发/返工：判定与本机 retry 相同（未投/返工/--force），新目标按 send 核。"""
    task = _decidable(task, caller)
    try:
        return authority.retry_task(rt.store, rt.ident, task, force=force, message=message, new_target=new_target,
                                    allow_shared=allow_shared, rework_body=rework_body, now=now_ms())
    except StoreError as error:
        raise FedCliError(error.code) from error


def archive(rt: Runtime, task: FedTask) -> int:
    """B 本机归档镜像：只抑制本机未 intent 作业；不改 A 生命周期、不删 intent/证据/报告。返回抑制条数。"""
    if task.is_authority:
        raise FedCliError("federation_archive_authority")  # A 的权威任务用 close
    now = now_ms()
    with rt.store.transaction() as conn:
        conn.execute("UPDATE fed_tasks SET local_archived=1 WHERE authority_device=? AND task_id=?",
                     (task.authority_device, task.task_id))
        current = rt.store.get_task(task.authority_device, task.task_id)
        if current is None:
            raise FedCliError("task_not_found", 2)
        count = mirror.suppress_pending(rt.store, rt.ident, current, now=now)
        rt.store.add_event(task.authority_device, task.task_id, "mirror_archived", now=now, detail={"suppressed": count})
    return count


# ---- 展示 ----


def device_name(rt: Runtime, device_id: str) -> str:
    if device_id == rt.ident.device_id:
        return rt.ident.device_name
    for row in rt.store.device_states():
        if row["device_id"] == device_id and row["name"]:
            return str(row["name"])
    return device_id  # 这个值会进 --origin-device/--device 等可复制命令：8 位前缀解析不了，用完整 deviceId


def view_of(rt: Runtime, task: FedTask) -> TaskView:
    """联邦任务的本机阶段折叠（复用 describe）；远端目标在视图里是仅供显示的引用。"""
    return describe(model_task(task), model_attempts(rt.store.attempts(task.authority_device, task.task_id)))


def phase_of(rt: Runtime, task: FedTask) -> tuple[Phase, str]:
    view = view_of(rt, task)
    return view.phase, view.reason


def stalled(rt: Runtime, task: FedTask, *, now: int) -> bool:
    """本任务有待传操作超过 30 分钟（远端离线/hub 不可达/relay 未运行）。"""
    row = rt.store.connection.execute(
        "SELECT COUNT(*) FROM fed_outbox WHERE state IN ('ready','submitting')"
        " AND json_extract(envelope_json,'$.authorityDeviceId')=? AND json_extract(envelope_json,'$.taskId')=?"
        " AND json_extract(envelope_json,'$.createdAt')<?",
        (task.authority_device, task.task_id, now - STALLED_MS)).fetchone()
    return int(row[0]) > 0


def _attempt_rows(rt: Runtime, task: FedTask) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for attempt in rt.store.attempts(task.authority_device, task.task_id):
        outbox = rt.store.outbox_item(attempt.msg_id)
        native = rt.store.native(attempt.msg_id)
        files: list[dict[str, Any]] = []
        for item in rt.store.attachments(attempt.msg_id):
            entry: dict[str, Any] = {"name": item["original_name"], "state": item["state"], "size": item["size"],
                                     "sha256": item["sha256"], "transfer": item["transfer"]}
            if item["state"] == "ready" and item["location"] == "delivery" and item["local_relpath"]:
                entry["path"] = str(rt.paths.delivery_base(rt.store.ledger_instance_id()) / str(item["local_relpath"]))
            if item["reason"]:
                entry["reason"] = item["reason"]
            files.append(entry)
        local = attempt.target_device == rt.ident.device_id
        rows.append({
            "seq": attempt.seq, "role": attempt.role, "msgId": attempt.msg_id,
            "targetDevice": attempt.target_device, "targetDeviceName": device_name(rt, attempt.target_device),
            "target": f"{attempt.target.remote.provider.value}@id:{attempt.target.remote.native_id}",
            "network": outbox["state"] if outbox else ("local" if local else None),
            "native": native["state"] if native else None,
            "delivery": attempt.delivery.get("state", "pending"),
            "receiverReported": attempt.delivery.get("receiverReported") is True,
            "work": attempt.effective_work.get("work"), "attachments": files,
        })
    return rows


def _report_rows(rt: Runtime, task: FedTask) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for row in rt.store.reports(task.authority_device, task.task_id):
        decision = rt.store.decision(str(row["reporter_device"]), str(row["operation_id"]))
        rows.append({"attempt": row["attempt_seq"], "reportNo": row["report_no"], "kind": row["report"].get("kind"),
                     "reporterDevice": row["reporter_device"],
                     "decision": decision["decision"] if decision else None,
                     "reason": decision["reason"] if decision else None})
    return rows


def task_document(rt: Runtime, task: FedTask, *, now: int, include_body: bool = False) -> dict[str, Any]:
    """status/tasks --json 的联邦形状：scope=federation，不伪造本机进程字段。"""
    attempts = rt.store.attempts(task.authority_device, task.task_id)
    view = describe(model_task(task), model_attempts(attempts))
    document: dict[str, Any] = {
        "scope": "federation", "id": task.task_id, "authorityDevice": task.authority_device,
        "authorityDeviceName": device_name(rt, task.authority_device), "isAuthority": task.is_authority,
        "title": task.title, "phase": view.phase.value, "reason": view.reason, "revision": task.revision,
        "lastSyncAt": task.last_sync_at, "syncRequired": task.sync_required, "archived": task.local_archived,
        "stalled": stalled(rt, task, now=now), "attempts": _attempt_rows(rt, task), "reports": _report_rows(rt, task),
    }
    if include_body:
        first = next((item for item in attempts if item.role != "notice"), None)
        document["body"] = first.body if first is not None else ""
    return document


_NETWORK_LABELS = {"ready": "待传", "submitting": "提交中", "accepted": "hub 已收", "received": "对端已落账",
                   "refused": "hub 拒收", "rejected": "对端拒收", "expired": "已过期", "revoked": "已撤销",
                   "local": "本机"}


def task_lines(rt: Runtime, task: FedTask, *, now: int, show_body: bool = False) -> list[str]:
    """status 文本：权威/镜像、同步时间、网络 L0–L2、投递 L3、报告与 A 采纳 L4、附件逐项状态。"""
    document = task_document(rt, task, now=now, include_body=show_body)
    view = view_of(rt, task)
    role = "本机发起（权威）" if task.is_authority else f"镜像（发起设备 {document['authorityDeviceName']}）"
    age = max(0, (now - task.last_sync_at) // 1000)
    flags = ("；需同步" if task.sync_required else "") + ("；仅本机已归档" if task.local_archived else "")
    lines = [f"跨设备任务 {short(task.task_id)}  {task.title}",
             f"  {role}；{PHASE_LABELS[view.phase]}（{reason_text(view.reason)}）；最近同步 {age} 秒前{flags}"]
    if document["stalled"]:
        lines.append("  需处理：远端离线/传输未恢复（待传超过 30 分钟；不改变任务状态）")
    for row in document["attempts"]:
        network = _NETWORK_LABELS.get(str(row["network"]), "-")
        reported = "，对方已汇报" if row["receiverReported"] else ""
        lines.append(f"  #{row['seq']} {row['role']} → {row['targetDeviceName']} {row['target']}"
                     f"  网络 {network}  投递 {row['delivery']}{reported}")
        for item in row["attachments"]:
            where = f" {item['path']}" if "path" in item else ""
            state = "已过留存期" if item["state"] == "expired" else item["state"]
            lines.append(f"     附件 {item['name']}：{state}（{item['size']} B）{where}")
    for row in document["reports"]:
        status = row["decision"] or "等待发起设备确认"
        reason = f"（{row['reason']}）" if row["reason"] else ""
        lines.append(f"  报告 #{row['attempt']}.{row['reportNo']} {row['kind']}：{status}{reason}")
    if show_body:
        lines.extend(["", str(document.get("body", ""))])
    cmd = command_name()
    if not task.is_authority and not task.finished:
        # 联邦页脚带 --origin-device：CLI 只据本机索引找发起设备，不读正文里的远端路径（§88.8）
        lines.append(f"汇报：{cmd} report {short(task.task_id)} --origin-device {document['authorityDeviceName']}"
                     " --result（或 --blocked / --failed）")
    return lines


def list_tasks(rt: Runtime, *, include_finished: bool) -> list[FedTask]:
    tasks = rt.store.tasks(include_finished=include_finished)
    return sorted(tasks, key=lambda item: item.last_sync_at, reverse=True)


# ---- 启停 ----


def enable(root: Path, *, hub_host: str, hub_user: str, hub_port: int, hub_id: str, device_id: str, name: str,
           identity_file: str, known_hosts_file: str, ssh_executable: str) -> tuple[fed_config.FederationConfig, bool]:
    """首次启用建库（只允许没有既有配置时）；已启用幂等；停用后再启用接续同一 ID。返回 (配置, 是否新建库)。"""
    try:
        existing = fed_config.load(root)
    except fed_config.ConfigError as error:
        raise FedCliError(error.code) from error
    if existing is not None:
        if existing.device_id != device_id or existing.hub_id != hub_id:
            raise FedCliError("federation_already_configured")  # 换设备/换 hub 走灾难流程，不在这里覆盖
        if not (root / FED_DB_NAME).exists():
            raise FedCliError("federation_store_missing", 8)
        updated = replace(existing, enabled=True)
        with FederatedStore.open(root) as store:
            store.set_meta("enabled", "1")
        fed_config.save(root, updated)
        return updated, False
    if (root / FED_DB_NAME).exists():
        raise FedCliError("federation_store_exists", 8)
    try:
        config = fed_config.parse({
            "schema": fed_config.CONFIG_SCHEMA, "enabled": True, "hubId": hub_id, "deviceId": device_id,
            "deviceName": name, "hub": {"host": hub_host, "port": hub_port, "user": hub_user},
            "sshExecutable": ssh_executable, "identityFile": identity_file, "knownHostsFile": known_hosts_file,
            "expectedStateRoot": str(root.resolve()),
        })
    except fed_config.ConfigError as error:
        raise FedCliError(error.code) from error
    with FederatedStore.create(root) as store:
        for key, value in (("deviceId", device_id), ("hubId", hub_id), ("deviceName", name), ("enabled", "1")):
            store.set_meta(key, value)
    fed_config.save(root, config)
    return config, True


def disable(root: Path) -> None:
    """停用：relay 停止、worker 不再领取联邦作业；数据与附件不删，本机照常。

    先写库（运行中的 worker 在领取锁内只认库里的 enabled），再写配置（relay 认配置）。返回成功就保证 worker 已停领。
    库写不进去时整体失败、配置不动，状态仍是一致的「启用」，重试即可；之后配置保存若失败，同样报错、重试即可
    （两个文件不是一个原子事务）。
    """
    try:
        config = fed_config.load(root)
    except fed_config.ConfigError as error:
        raise FedCliError(error.code) from error
    if config is None:
        raise FedCliError("federation_not_configured", 9)
    if (root / FED_DB_NAME).exists():
        try:
            with FederatedStore.open(root) as store:
                store.set_meta("enabled", "0")
        except StoreError as error:
            raise FedCliError(error.code, 8) from error
    fed_config.save(root, replace(config, enabled=False))


def rebuild(root: Path, *, hub_id: str, device_id: str | None = None) -> dict[str, Any]:
    """灾难换 hub（§88.11）：hub 丢库/恢复旧备份后由运维换新 hubId 并重新登记设备。

    本机联邦库完整：保留 deviceId，只换 hubId 并清 hub 冻结与游标；旧 hub 上未结的发件全部冻结（revoked），
    旧路由任务的未投作业不再领取——不自动转投新 hub，也不当作未投证据。
    本机联邦库丢失：必须换新 deviceId，旧配置改名留档后按首次启用建新库。返回本次处理摘要。

    relay 在跑时拒绝（relay_running）：运行中的 relay 会继续写旧 hub 的游标与冻结标记，覆盖本次重置。
    全程持有 relay 单例锁，换 hub 期间 relay 也起不来；已在运行的 worker 由领取锁内的身份核对挡住、随后按新配置重开。
    """
    if not is_hex32(hub_id) or (device_id is not None and not is_hex32(device_id)):
        raise FedCliError("config_invalid")
    lifecycle = get_platform().lifecycle
    fd = lifecycle.open_lock(root / RELAY_LOCK)
    try:
        try:
            lifecycle.try_lock(fd)
        except BlockingIOError:
            raise FedCliError("relay_running") from None
        try:
            return _rebuild_locked(root, hub_id=hub_id, device_id=device_id)
        finally:
            lifecycle.unlock(fd)
    finally:
        lifecycle.close_lock(fd)


def _rebuild_locked(root: Path, *, hub_id: str, device_id: str | None) -> dict[str, Any]:
    try:
        config = fed_config.load(root)
    except fed_config.ConfigError as error:
        raise FedCliError(error.code) from error
    if config is None:
        raise FedCliError("federation_not_configured", 9)
    if config.hub_id == hub_id:
        raise FedCliError("federation_rebuild_same_hub")
    if not (root / FED_DB_NAME).exists():
        if device_id is None or device_id == config.device_id:
            raise FedCliError("federation_rebuild_needs_new_device")  # 失去本机库必须新 deviceId
        backup = root / f"{fed_config.CONFIG_NAME}.lost-{now_ms()}"
        os.replace(root / fed_config.CONFIG_NAME, backup)
        try:
            enable(root, hub_host=config.host, hub_user=config.user, hub_port=config.port, hub_id=hub_id,
                   device_id=device_id, name=config.device_name, identity_file=config.identity_file,
                   known_hosts_file=config.known_hosts_file, ssh_executable=config.ssh_executable)
        except BaseException:
            os.replace(backup, root / fed_config.CONFIG_NAME)
            raise
        return {"newDevice": True, "frozenOutbox": 0}
    if device_id is not None and device_id != config.device_id:
        raise FedCliError("federation_rebuild_device_mismatch")  # 本机库完整时保留原 deviceId
    try:
        fed_config.check_state_root(config, root)
    except fed_config.ConfigError as error:
        raise FedCliError(error.code) from error
    with FederatedStore.open(root) as store:
        if store.device_id() != config.device_id:
            raise FedCliError("ledger_instance_mismatch", 8)
        with store.transaction() as conn:
            frozen = conn.execute("UPDATE fed_outbox SET state='revoked', hub_receipt_json=?"
                                  " WHERE state IN ('ready','submitting','accepted')",
                                  (json.dumps({"reason": "hub_rebuilt", "at": now_ms()}),)).rowcount
            for key, value in (("hubId", hub_id), ("hubStateLost", ""), ("ingressCatchup", ""), ("inboxCursor", "0"),
                               ("receiptCursor", "0"), ("directoryRevision", "0"), ("directoryDigest", ""),
                               ("directoryLocalDigest", ""), ("relayState", "starting")):
                store.set_meta(key, value)
    fed_config.save(root, replace(config, hub_id=hub_id))
    return {"newDevice": False, "frozenOutbox": int(frozen)}


# ---- relay 入口 ----


def run_relay(root: Path, *, once: bool = False, connector: Callable[[], Any] | None = None,
              watch_anchor: bool = False) -> str:
    """`federation relay`：单例锁、开库前核非提权令牌与 stateRoot，跑重连循环；停用、SIGTERM 或任务结束即退出。

    启动顺序（DESIGN §90.5）：取单例锁 → 开 runtime → Windows 按需绑定 launch anchor → 初始化诊断 →
    主线程接管 SIGTERM、启动停止控制线程 → 连接。重复启动先因锁退出，不扫描祖先、不改诊断。
    """
    lifecycle = get_platform().lifecycle
    fd = lifecycle.open_lock(root / RELAY_LOCK)
    try:
        lifecycle.try_lock(fd)
    except BlockingIOError:
        lifecycle.close_lock(fd)
        return "already_running"
    try:
        _require_unelevated()
        rt = open_runtime(root)
        try:
            controller = StopController(read_disabled=lambda: config_disabled(root),
                                        anchor=_launch_anchor() if watch_anchor and rt.paths.windows else None)
            try:
                diagnostics = RelayDiagnostics(rt.store, controller, windows=rt.paths.windows)
                diagnostics.initialize()  # 先清上一代三键；Windows 随即整组发布本次值
                restore = install_sigterm(controller)
                try:
                    controller.start()  # 线程创建失败也要恢复原 SIGTERM 处理函数
                    relay = Relay(rt.store, rt.ident, rt.config, rt.paths,
                                  connect=connector or ssh_connector(rt.config, root, windows=rt.paths.windows),
                                  directory=directory_source(rt), on_work=worker_starter(root), on_tick=diagnostics.tick)
                    if once:
                        state = relay.connect_and_run(cycles=1, wait=lambda _s: None, should_stop=controller.is_set,
                                                      stopper=controller)
                    else:
                        state = relay.run_forever(should_stop=controller.is_set, stopper=controller)
                finally:
                    restore()
            finally:
                controller.close()
            return "stop_controller_failed" if controller.reason == "stop_controller_failed" else state
        finally:
            rt.close()
    finally:
        lifecycle.unlock(fd)
        lifecycle.close_lock(fd)


def _launch_anchor() -> Any:
    """Windows 任务模板带 --watch-launch-anchor 时绑定 action conhost；定位不到或出错都按 unavailable 继续服务。"""
    from ..platforms.windows import anchor  # layout: allow Windows launch anchor，只在 Windows relay 启动时加载
    api: Any = getattr(get_platform().transport, "api", None)
    if api is None:
        return None
    try:
        return anchor.bind(api, pid=os.getpid(), system_root=os.environ.get("SystemRoot"))
    except Exception:  # 定位失败不是 relay 失败（§90.6）
        return None


def worker_starter(root: Path, *, start: Callable[[Path], bool] = ensure_worker,
                   clock: Callable[[], float] = time.monotonic) -> Callable[[], bool | None]:
    """relay 不投递：有可领取作业时按需拉起 worker；启动失败 10/30/60 秒退避，不形成拉起风暴。

    返回值告诉 relay 这次的结果：
    - True：新起了 worker 进程，relay 记下这批作业、按复查间隔再看；
    - None：worker 已在运行（不是失败、不退避）。它一秒内就会领取；但它也可能正要空闲退出，所以 relay 不记下，
      下个周期再探一次锁（Opus r2-P2-1）；
    - False：拉起失败或还在退避中，relay 下一周期再试。
    """
    state = {"next": 0.0, "delay": 10.0}

    def on_work() -> bool | None:
        if clock() < state["next"]:
            return False
        try:
            started = start(root)
            state["delay"] = 10.0
            return True if started else None
        except (OSError, StoreError):
            state["next"] = clock() + state["delay"]
            state["delay"] = min(60.0, state["delay"] * 3)
            return False

    return on_work


def _require_unelevated() -> None:
    """Windows：真实令牌必须非提权（Limited 配置字段不能替代核验）；High 上下文在开库前拒绝。"""
    if get_platform().name != "windows":
        return
    api: Any = getattr(get_platform().transport, "api", None)
    try:
        if api is None or api.current_token().elevated:  # current_token 在提权令牌上本身就抛 OSError
            raise FedCliError("relay_elevated")
    except OSError as error:
        raise FedCliError("relay_elevated") from error


def directory_source(rt: Runtime) -> Callable[[], dict[str, Any]]:
    """relay 目录采样：Linux 走 discover()，Windows 按 provider 完整性发现；只发最小公开目录。"""

    def collect() -> dict[str, Any]:
        complete: dict[str, bool] = {}
        if get_platform().name == "windows":
            from ..platforms.windows.commands import WorkerDiscovery  # layout: allow Windows 按 provider 完整性发现
            from ..platforms.windows.local_transport import WindowsPlatform  # layout: allow 已选择后端

            backend = get_platform().transport
            if not isinstance(backend, WindowsPlatform):
                return {"endpoints": [], "complete": False, "providers": {}, "reason": "windows_provider_not_enabled"}
            sampler = WorkerDiscovery(backend)
            found = sampler()
            complete = {provider.value: sampler.provider_complete(provider)
                        for provider in (Provider.CODEX, Provider.CLAUDE)}
        else:
            # Linux 按本轮实际采样的完整性：注册目录读不到、预算截断或 /proc 不可列举的 provider 标不完整
            # （消费端据此不按名字在它上面消歧）；平台能力只是前提，不代表这一轮看全了
            sources = DiscoverySources()
            found = discover(sources) if get_platform().discovery is Capability.VERIFIED else []
            complete = {provider.value: get_platform().discovery is Capability.VERIFIED
                        and sources.provider_complete(provider) for provider in ADAPTERS}
        return directory.snapshot(rt.store, rt.ident.device_id, found, publish_names=rt.config.publish_names,
                                  provider_complete=complete)

    return collect


# ---- doctor 投影 ----


_PROBE = object()  # doctor_projection 未给 running 时现场探锁
ANCHOR_WATCH_STATES = frozenset({"active", "unavailable"})


def relay_diagnostics_projection(raw: dict[str, str]) -> dict[str, Any]:
    """Windows 三键 → 投影（§90.6）：必需键 relayAnchorWatch 与 relayPublishedAt 缺一或不合法时整组未知（null）；

    版本可选（Opus r3 P3-3），缺失或不合法只让 relayVersion 为 null。
    """
    anchor, published = raw.get("relayAnchorWatch"), raw.get("relayPublishedAt")
    if (anchor not in ANCHOR_WATCH_STATES or published is None or not published.isascii()
            or not published.isdecimal() or len(published) > 19):
        return {"anchorWatch": None, "relayVersion": None, "relayPublishedAt": None}
    version = raw.get("relayDistributionVersion")
    return {"anchorWatch": anchor, "relayVersion": version if valid_distribution_version(version) else None,
            "relayPublishedAt": int(published)}


def federation_status(root: Path, *, now: int | None = None) -> dict[str, Any]:
    """`federation status --json` 的整体（§90.6）：先取顶层 relayRunning，再做可选联邦投影；投影失败不丢运行事实。"""
    running = relay_running(root)
    return {"relayRunning": running, "federation": doctor_projection(root, now=now, running=running)}


def doctor_projection(root: Path, *, now: int | None = None, running: object = _PROBE) -> dict[str, Any] | None:
    """doctor 的 optional federation 投影（§88.12/§90.6）：不读 key、不连 hub；失败只写进本投影，不覆盖本机账本结论。

    联邦库走只读 SQL（不设 WAL、不修 ACL、不迁移）；running 是本次已探得的锁事实（status 先探再投影），未给则现场探。
    Windows 上 relay 在跑时附带同快照读取的三键诊断；Linux 不发布这组字段，投影里也不出现。
    """
    try:
        config = fed_config.load(root)
    except fed_config.ConfigError:
        return {"enabled": False, "ledgerReadable": False, "transport": "ssh-stdio", "state": "storage_failed",
                "hubAccepted": False, "lastSeen": None, "reason": "config_invalid"}
    if config is None:
        return None  # 未启用：不建库，不出现联邦投影
    result: dict[str, Any] = {"enabled": config.enabled, "ledgerReadable": False, "transport": "ssh-stdio",
                              "state": "storage_failed", "hubAccepted": False, "lastSeen": None}
    try:
        fed_config.check_state_root(config, root)
    except fed_config.ConfigError:
        result["reason"] = "state_root_mismatch"
        return result
    if not (root / FED_DB_NAME).exists():
        result.update(reason="federation_store_missing", storageReason="federation_store_unavailable",
                      storageSubreason="federation_store_missing")
        return result
    try:
        store = FederatedStore.open_readonly(root)
    except StoreError as error:
        result.update(reason="unknown", storageReason="federation_store_unavailable", storageSubreason=error.code)
        return result
    with store:
        try:
            _project_store(result, store, root, config, now=now,
                           running=relay_running(root) if running is _PROBE else running)
        except (StoreError, sqlite3.Error, OSError) as error:
            # 只读查询中途失败（库忙、只读读者补建辅助文件失败等）：投影未知，不回退到可写打开
            code = error.code if isinstance(error, StoreError) else "federation_store_unavailable"
            for key in ("outboxPending", "outboxDeferred", "authorityDecisionsPending", "attachments", "anchorWatch",
                        "relayVersion", "relayPublishedAt"):
                result.pop(key, None)
            result.update(ledgerReadable=False, state="storage_failed", hubAccepted=False, lastSeen=None,
                          reason="unknown", storageReason="federation_store_unavailable", storageSubreason=code)
    return result


def _project_store(result: dict[str, Any], store: FederatedStore, root: Path, config: fed_config.FederationConfig, *,
                   now: int | None, running: object) -> None:
    try:
        mismatch = store.device_id() != config.device_id
    except StoreError:
        mismatch = True
    result["ledgerReadable"] = True
    if mismatch:
        result["reason"] = "ledger_instance_mismatch"
        return
    current = now if now is not None else now_ms()
    conn = store.connection
    pending, deferred = conn.execute(
        "SELECT COALESCE(SUM(next_try_at<=?),0), COALESCE(SUM(next_try_at>?),0) FROM fed_outbox"
        " WHERE state IN ('ready','submitting')", (current, current)).fetchone()
    decisions = conn.execute(
        "SELECT COUNT(*) FROM fed_reports r LEFT JOIN fed_report_decisions d ON d.reporter_device=r.reporter_device"
        " AND d.report_operation_id=r.operation_id WHERE d.decision IS NULL").fetchone()[0]
    result.update(outboxPending=int(pending), outboxDeferred=int(deferred),
                  authorityDecisionsPending=int(decisions),
                  attachments=attachment_usage(store, _paths(root), config.storage_budget))
    relay_state = store.meta("relayState") or "starting"
    seen = store.meta("relayLastSeen")
    result["lastSeen"] = int(seen) if seen and seen.isdigit() else None
    if not config.enabled:
        result.update(state="disabled", reason="unknown")
    elif store.meta("hubStateLost"):
        result.update(state="incompatible", reason="hub_state_lost")
    elif running is None:
        result.update(state="storage_failed", reason="relay_running_unknown")  # 锁文件读不了：不冒称离线或在线
    elif not running:
        result.update(state="offline", reason="relay_not_running")
    elif relay_state in STOP_STATES:
        result.update(state="incompatible", reason=relay_state)
    else:
        result["state"] = relay_state if relay_state in RELAY_STATES else "reconnecting"
        result["reason"] = "unknown" if relay_state == "connected" else "hub_unavailable"
        result["hubAccepted"] = relay_state == "connected"
    if running is True and get_platform().name == "windows":
        # 未运行/运行未知时隐藏磁盘残留；锁忙但字段缺失/不合法时为 null（未知），不假定 active
        result.update(relay_diagnostics_projection(store.relay_diagnostics()))


def attachment_usage(store: FederatedStore, paths: RelayPaths, storage_budget: int) -> dict[str, int | None]:
    """联邦内容占用与设备预算（只计大小，不列名称/路径）：staging 与交付叶（Windows 在 LocalAppData 下）、part、未清理信封。"""
    used = budget.usage(store, paths)
    deferred = store.meta(budget.DEFERRED_META) or ""
    write_failed = store.meta(attachments.WRITE_FAILED_META) or ""
    return {"bytes": used.file_bytes, "files": used.files, "partialBytes": used.partial_bytes,
            "envelopeBytes": used.envelope_bytes, "budgetBytes": storage_budget,
            "incomingDeferredAt": int(deferred) if deferred.isdigit() else None,
            "incomingWriteFailedAt": int(write_failed) if write_failed.isdigit() else None}
