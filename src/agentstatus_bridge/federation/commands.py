"""联邦 CLI 操作（DESIGN §88.6/§88.7/§88.10/§88.12）：send --device、report --origin-device、控制、状态、启停与 relay。

纯本机命令路径完全不变：只有显式 `--device/--origin-device`、或本机库找不到而联邦库有唯一命中时才进入这里。
所有联邦写入只开 federation.sqlite3；L0（本机已记录）成功即返回 0，后台不可用时返回 6，都不能重跑。
本模块不 import cli：本机返工文案等由 cli 以参数传入，保持 import 图无环。
"""

from __future__ import annotations

import json
import os
import re
import sqlite3
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any

from ..closure import ACCEPTED
from ..endpoints import ADAPTERS, Caller, DiscoverySources, Endpoint, discover
from ..endpoints import _ids_complete  # pyright: ignore[reportPrivateUsage]  与本机解析/名字投影同一身份判据（§94.1）
from ..ids import short
from ..labels import (
    DELIVERY_LABELS,
    EVENT_LABELS,
    FEDERATION_EVENT_LABELS,
    FYI_LABEL,
    FYI_STATUS_LABEL,
    NOTE_LABEL,
    REASON_TEXTS,
    TRANSPORT_EVENT_LABELS,
    notification_capacity_hint,
    deferred_due,
    reason_registered,
    reason_text,
    shown_reason,
    reminded_label,
    review_capacity_hint,
    silent_minutes,
)
from ..model import PHASE_LABELS, Attempt, Delivery, EndpointRef, Phase, Provider, ReportKind, Task, TaskView
from ..naming import command_name
from ..native_names import UUID_SHAPE, full_id_token, remote_display, remote_path
from ..platforms import process as procfs
from ..platforms.factory import get_platform
from ..platforms.types import Capability
from ..reports import (  # pyright: ignore[reportPrivateUsage]
    ReportError,
    ReportInput,
    _attribute,
    _commit_reference,
    _git_resolve_commit,
    checked_note,
    refs_over_limit,
)
from ..store import CAPACITY_CODES, MAX_BODY_BYTES, MAX_FILES, StoreError
from ..task_filter import TASK_LIST_LIMIT, Party, TaskFilter
from ..views import deferred_text, timeline_lines
from ..worker import ensure_worker
from . import attachments, authority, budget, config as fed_config, directory, mirror
from .attachments import AttachmentError, Frozen
from .authority import Identity
from .codec import CodecError, is_hex32, is_slug
from .errors import FedCliError
from .fedstore import FED_DB_NAME, FederatedStore, FedAttempt, FedTask, load_dict, now_ms
from .refs import TargetRef, WireActor
from .relay import STOP_STATES, Relay, RelayPaths, ssh_connector
from .relay_control import RelayDiagnostics, StopController, config_disabled, install_sigterm
from .relay_control import valid_distribution_version
from .views import model_attempt, model_task, steer_detail

RELAY_LOCK = "federation-relay.lock"
# 待传超过 30 分钟叠加「远端离线/传输未恢复」提示（§88.6）；只是提示，不改业务状态
STALLED_MS = 30 * 60 * 1000
# 投递原因码来自投递设备（可能是另一台）：只显示形状合规的固定码，不合规显示 unknown（§97.3）
_REASON_SHAPE = re.compile(r"[a-z][a-z0-9_]{0,63}")
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


_PROVIDER_VALUES = frozenset(provider.value for provider in Provider)


def _copyable_full_id(item: str) -> bool:
    """候选 `provider@id:<ID>` 能否照抄：provider 属枚举、ID 是 UUID 形状（与 peers 文字行的 target= 同一判据，§101.1）。"""
    provider, _, native = item.partition("@id:")
    return provider in _PROVIDER_VALUES and UUID_SHAPE.fullmatch(native) is not None


def _candidate_hint(device: str, candidates: tuple[str, ...], flags: tuple[str, str]) -> str | None:
    """名字未核实/不唯一时把候选给成可照抄的完整写法（§91.2.2「提示 peers --device 及全 ID」）；
    设备引用不唯一时候选是完整 deviceId。参数名取调用方给的那一对，不固定写执行方的。

    候选来自远端目录（provider、nativeId）或缓存的 deviceId，与 peers 文字行同一口径（§101.1）：判得过的给照抄写法，
    判不过的（provider 不在枚举、ID 不是 UUID、deviceId 不是 32 位十六进制）经 remote_display 转义、只作展示。"""
    if not candidates:
        return None
    device_flag, target_flag = flags
    if all("@id:" in item for item in candidates):
        return "可选目标：" + "、".join(
            f"{device_flag} {device} {target_flag} {item}" if _copyable_full_id(item)
            else f"{remote_display(item) or ''}（仅展示，不能作目标）" for item in candidates)
    return "可选设备：" + "、".join(f"{device_flag} {item}" if is_hex32(item)
                                 else f"{remote_display(item) or ''}（仅展示）" for item in candidates)


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


def freeze_refs(rt: Runtime, paths: list[str], cwd: Path, *, used: int = 0) -> list[Frozen]:
    """冻结 --ref/--file 点名的文件；有点名时先按设备内容预算预检（§88.11），不足在写任务/报告前拒绝。

    used 是同一条消息已占的 blob 字节（retry 继承的附件），只计入 32 MiB 预算（§104.11 第 5 条）。
    """
    if not paths:
        return []
    left = budget.available(rt.store, rt.paths, rt.config.storage_budget)
    try:
        return attachments.freeze(paths, cwd=cwd, origin_device=rt.ident.device_id, staging=rt.paths.staging,
                                  available=left, used=used)
    except AttachmentError as error:
        raise FedCliError(error.code) from error


def send(rt: Runtime, *, target: TargetRef, body: str, title: str, ref_paths: list[str], cwd: Path,
         origin: EndpointRef | None, origin_class: str | None, reviewer: TargetRef | None, allow_shared: bool,
         no_notify: bool, follows: str | None = None, fyi: bool = False, expect: float | None = None,
         after: float | None = None) -> SendOutcome:
    """A 上建联邦任务（L0）。至少一方在别的设备（本机目标 + 远端复核也算）；参与设备超过两台写前拒绝（§88.14/T16）。

    follows 是 `--follows` 解析出的旧任务完整 ID，只写进本机 state（§93.3），不进 checkpoint 与信封。
    expect（秒）与 after（秒，§104.9 一、二）同样只在 A 本机：沉默阈值进 state，延迟投递进尝试 options 与 outbox 的
    next_try_at，线上不加键。
    """
    if len(body.encode("utf-8")) > MAX_BODY_BYTES:
        raise FedCliError("message_too_large")
    local_target_only = target.remote.device_id == rt.ident.device_id
    if local_target_only and (reviewer is None or reviewer.remote.device_id == rt.ident.device_id):
        raise FedCliError("target_is_local_device", 2)  # 全在本机：用本机 send
    if fyi and "fyi" not in directory.device_features(rt.store, target.remote.device_id):
        # 告知保留能力门（§95.5.7）：旧镜像会按「任务已结束」抑制，不落账、不发
        raise FedCliError("fyi_remote_unsupported", 3)
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
    now = now_ms()
    defer_until = (now / 1000.0 + after) if after is not None else None
    try:
        if fyi:
            task, attempt = authority.create_fyi(
                rt.store, rt.ident, title=title, body=body, refs=[item.manifest for item in frozen],
                origin=origin_target, origin_actor=origin_actor, origin_class=origin_class or "unknown",
                target=target, allow_shared=allow_shared, now=now, follows=follows, defer_until=defer_until)
            return SendOutcome(task, attempt, target, blobs, blob_bytes, references,
                               device_name(rt, target.remote.device_id))
        task, attempt = authority.create_task(
            rt.store, rt.ident, title=title, flow="review" if reviewer else "handoff", body=body,
            refs=[item.manifest for item in frozen], origin=origin_target, origin_actor=origin_actor,
            origin_class=origin_class or "unknown", target=target, reviewer=reviewer, reviewer_token=reviewer_token,
            notify_origin=not no_notify, allow_shared=allow_shared, now=now, follows=follows, expect=expect,
            defer_until=defer_until)
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
           cwd: Path, ask: bool = False) -> tuple[FedAttempt, mirror.ReportResult]:
    """目标设备上的联邦报告：核本机真实接收方与当前 attempt，冻结附件，事务分配 reportNo；A 本机参与方立即裁决。"""
    try:
        note_text = checked_note(note)  # 说明超长在冻结附件（写 staging）之前拒绝，与本机同一口径（§104.4）
    except ReportError as error:
        raise FedCliError(error.code) from error
    if task.finished:
        raise FedCliError("task_finished")
    attempts = rt.store.attempts(task.authority_device, task.task_id)
    if attempt_seq is not None and any(item.seq == attempt_seq and item.role == "notice" for item in attempts):
        raise FedCliError("attempt_not_reportable")  # 补充消息等 notice 不需要汇报，与本机同一原因码（§95.5.3）
    mine = [item for item in attempts if item.role != "notice" and item.target_device == rt.ident.device_id]
    current = mirror.current_local_attempt(rt.store, rt.ident, task)  # 与镜像页脚同一判定（§98.2）
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
    if ask and (kind is not ReportKind.PROGRESS or not (note or "").strip()):
        raise FedCliError("ask_requires_note")  # 与本机同一判据，任何写入与附件冻结之前（§104.9 五）
    local = mirror.local_binding(attempt)
    if local is None:
        raise FedCliError("reporter_mismatch")  # 与镜像页脚同一判定（§98 r1）
    # 只核这一个相关本机 ref 的实际接收代际（§88.7），复用本机 _attribute；不核远端 origin/历史 root
    view = replace(model_attempt(attempt), delivery_detail=_delivery_detail(rt, attempt))
    _windows_root_check(replace(model_task(task), origin=None, reviewer=None), [view])
    try:
        source = _attribute(view, ReportInput(task_ref=task.task_id, kind=kind, manual=manual), caller,
                            procfs.DEFAULT_PROC)
    except ReportError as error:
        raise FedCliError(error.code) from error
    if mirror.attempt_unsent(attempt):
        raise FedCliError("attempt_not_sent")  # 投递设备自己的事实：从未 intent 或已抑制的作业不能汇报
    frozen = freeze_refs(rt, files, cwd)
    commit_ref = None
    if commit:
        try:
            commit_ref = _commit_reference(commit, cwd=cwd, git=_git_resolve_commit)
        except ReportError as error:
            raise FedCliError(error.code) from error
    reporter = authority.actor_for(attempt.target, wire_token=full_id_token(local))
    try:
        result = mirror.submit_report(rt.store, rt.ident, mirror.LocalReport(
            task=task, attempt=attempt, kind=kind.value, note=note_text,
            refs=[item.manifest for item in frozen], commit=commit_ref, reporter=reporter,
            reporter_class=caller_class or "unknown", source=source, ask=ask), now=now_ms(), command=command_name())
    except StoreError as error:
        raise FedCliError(error.code) from error
    return attempt, result


def authority_supports_ask(rt: Runtime, task: FedTask) -> bool:
    """发起设备认不认汇报帧的可选键 ask（§104.9 五）：本机就是权威时恒认；否则看缓存目录里 A 声明的 features。

    旧 A、目录还没缓存，或快照超限丢了 features 都按不认处理（执行方的输出加一句提示，不拒绝）。
    """
    return task.authority_device == rt.ident.device_id or "ask" in directory.device_features(
        rt.store, task.authority_device)


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


def note(rt: Runtime, task: FedTask, *, caller: Caller, caller_class: str | None, body: str,
         ref_paths: list[str] | None = None, cwd: Path | None = None) -> FedAttempt:
    """跨设备任务的 `ab note`（DESIGN §95.5.5）：只在权威设备建尝试，经现有 notice 信封送到目标设备投递。

    不做权限校验（寻址由任务决定）；发送者按调用方会话的结构化身份记（与 send 同口径）。
    """
    if not task.is_authority:
        raise FedCliError("note_not_authority")
    if len(body.encode("utf-8")) > MAX_BODY_BYTES:
        raise FedCliError("message_too_large")
    if not body.strip():
        raise FedCliError("empty_message")
    sender = _actor(rt, caller.endpoint.ref) if caller.endpoint is not None else None
    # note --ref（§104.4）：正文校验之后才冻结（写 staging），与 send 同一预算与 16 项上限
    frozen = freeze_refs(rt, list(ref_paths or []), cwd or Path.cwd())
    try:
        _, attempt = authority.add_note(rt.store, rt.ident, task, body=body, sender=sender,
                                        sender_class=caller_class or "unknown", now=now_ms(),
                                        refs=[item.manifest for item in frozen])
    except StoreError as error:
        raise FedCliError(error.code) from error
    return attempt


def retry(rt: Runtime, task: FedTask, *, caller: Caller, message: str | None, force: bool,
          new_target: TargetRef | None, allow_shared: bool,
          rework_body: Callable[[Attempt, Attempt, Task, str | None, bool], str],
          ref_paths: list[str] | None = None, cwd: Path | None = None) -> authority.RetryOutcome:
    """A 上重发/返工：判定与本机 retry 相同（未投/返工/--force），新目标按 send 核。

    --ref（§104.4）追加在继承的附件之后：
    - 与继承 blob 完全相同的点名先剔掉（同路径、大小与 sha256）；
    - 冻结前按「继承 + 新点名（同路径视为重复）」预判，新增部分让合并结果超过 16 就不复制任何副本；同一路径内容已变的
      会在冻结后的精确合并里再判一次（retry_task 内，按来源路径与 sha256）；
    - 继承 blob 的字节计入 32 MiB 预算，超出的新附件降为仅引用（§104.11 第 5 条）。
    预判之后任务若被并发改动、继承集合变大，信封校验会在 retry_task 的事务里拒绝（整体回滚）：这里兜住 CodecError，
    报闭集码、退出 3，不打出堆栈。
    """
    task = _decidable(task, caller)
    frozen: list[Frozen] = []
    if ref_paths:
        inherited = authority.retry_inherited_refs(task, rt.store.attempts(task.authority_device, task.task_id))
        try:
            named = attachments.drop_inherited(attachments.named_paths(ref_paths, cwd or Path.cwd()), inherited)
        except AttachmentError as error:
            raise FedCliError(error.code) from error
        known = {item.get("originalPath") for item in inherited}
        added = len([path for path in named if path not in known])
        if refs_over_limit(len(inherited), len(inherited) + added, MAX_FILES):
            raise FedCliError("too_many_files")
        frozen = freeze_refs(rt, named, cwd or Path.cwd(), used=attachments.blob_bytes(inherited))
    try:
        return authority.retry_task(rt.store, rt.ident, task, force=force, message=message, new_target=new_target,
                                    allow_shared=allow_shared, rework_body=rework_body, now=now_ms(),
                                    extra_refs=[item.manifest for item in frozen])
    except StoreError as error:
        raise FedCliError(error.code) from error
    except CodecError as error:
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


def device_text(name: object) -> str:
    """人读文字里的设备名（§101.1）：登记名来自远端，与 peers 文字行同一套转义；JSON 字段与 device_row 匹配仍用原值。"""
    return remote_display(name) or ""


def target_text(token: str) -> str:
    """人读文字里由会话 ID 拼成的 `provider@id:<ID>`（§101.1）：远端 ID 只过了 refs 的空白/控制字符校验，RLO、零宽等
    格式字符仍可能带进来，与 peers 文字行同一套转义；正常 UUID 原样不变，JSON 的 target 照给原值。"""
    return remote_display(token) or token


_DELIVERY_VALUES = frozenset(item.value for item in Delivery)
_REPORT_KIND_VALUES = frozenset(item.value for item in ReportKind)


def unknown_text(value: object) -> str:
    """闭集外取值的人读写法（§103.3）：「未知取值（转义原文）」；非字符串按其文字形式转义，入库与 --json 不变。"""
    return f"未知取值（{remote_display(value if isinstance(value, str) else str(value)) or ''}）"


def delivery_text(value: object) -> str:
    """投递状态的人读文字（§103.3）：B 出具的证据 state 入库不校验；合法值照旧写英文码，闭集外写「未知取值」。"""
    return value if isinstance(value, str) and value in _DELIVERY_VALUES else unknown_text(value)


def report_kind_text(value: object) -> str:
    """报告类别的人读文字（§103.3）：A 先存报告、后校验类别，被拒报告的原始 kind 也会显示；闭集外写「未知取值」。"""
    return value if isinstance(value, str) and value in _REPORT_KIND_VALUES else unknown_text(value)


def code_text(value: object) -> str:
    """来自远端的原因码（裁决 reason 等）的人读文字（§103.3）：与 deliveryReason 同一形状判据，不枚举闭集，
    免得读方比写方严；形状不合规写「未知取值」。"""
    return value if isinstance(value, str) and _REASON_SHAPE.fullmatch(value) else unknown_text(value)


def title_text(title: str) -> str:
    """跨设备任务文字行里的标题（§103.3）：镜像标题来自发起设备，codec 只限长度；一律与 peers 文字行同一套转义。"""
    return remote_display(title) or ""


def display_attempts(rt: Runtime, task: FedTask) -> list[FedAttempt]:
    """显示与 `ab wait` 用的尝试：镜像上本机工作尝试的 work 改读读时推导值，权威端原样（§97.2 第 3 条）。"""
    return mirror.display_attempts(rt.store, task, device_id=rt.ident.device_id)


def view_of(rt: Runtime, task: FedTask) -> TaskView:
    """联邦任务的本机阶段折叠（复用 describe；镜像另按 checkpoint 的当前尝试判，§97.2 第 2 条）。"""
    return mirror.describe_view(task, display_attempts(rt, task), device_id=rt.ident.device_id)


def reason_label(rt: Runtime, task: FedTask, view: TaskView, now: float | None = None) -> str:
    """原因的人读文本；当前尝试由别的设备处理时写出是哪台设备（§97.2 第 2 条）。now（秒）只用于定时项是否已到点。"""
    if view.reason == mirror.HANDLED_ON_OTHER_DEVICE:
        definition = mirror.current_definition(task)
        if definition is not None:
            return f"当前由 {device_text(device_name(rt, definition.target.device_id))} 处理，完整状态以发起设备为准"
    if view.phase is Phase.CLOSED and not task.is_authority:
        # 镜像的关闭原因是发起设备 `ab close --reason` 的自由文本（checkpoint 只限 64 字），reason_text 查不到时原样回退，
        # 与其余远端字符串同一套转义（§103.3）；登记过的原因码照旧映射成文案
        return reason_text(view.reason) if view.reason in REASON_TEXTS else (remote_display(view.reason) or "")
    return reason_text(shown_reason(view, now))  # 定时项到点后按等待对方写（§104.11 P3）


def phase_of(rt: Runtime, task: FedTask) -> tuple[Phase, str]:
    view = view_of(rt, task)
    return view.phase, view.reason


def stalled(rt: Runtime, task: FedTask, *, now: int) -> bool:
    """本任务有待传操作超过 30 分钟（远端离线/hub 不可达/relay 未运行）。

    延迟投递（§104.9 二）的信封从到期时刻起算，不从建立时刻：定时项在到点前不算「待传」。
    """
    row = rt.store.connection.execute(
        "SELECT COUNT(*) FROM fed_outbox o LEFT JOIN fed_attempts a ON a.msg_id=o.msg_id"
        " WHERE o.state IN ('ready','submitting')"
        " AND json_extract(o.envelope_json,'$.authorityDeviceId')=? AND json_extract(o.envelope_json,'$.taskId')=?"
        " AND MAX(json_extract(o.envelope_json,'$.createdAt'),"
        " COALESCE(CAST(json_extract(a.options_json,'$.deferUntil') * 1000 AS INTEGER), 0))<?",
        (task.authority_device, task.task_id, now - STALLED_MS)).fetchone()
    return int(row[0]) > 0


def delivery_reason(attempt: FedAttempt) -> str | None:
    """尝试的投递原因码（投递设备随证据回传，§97.3）；没有为 None，形状不合规为 unknown。"""
    raw = attempt.delivery.get("reason")
    if raw is None:
        return None
    return raw if isinstance(raw, str) and _REASON_SHAPE.fullmatch(raw) else "unknown"


def delivery_detail(rt: Runtime, attempt: FedAttempt) -> dict[str, str]:
    """跨设备投递细节闭集（§97.3）：两端都从 fed_evidence 读该尝试高水位那一行的 detail，按闭集过滤。

    高水位行要与显示的投递状态、原因码一致；它没有 detail 时才往低号找，而且只在投递状态与原因码都与高水位行相同
    时找，一旦不同就省略——不把一行的 state/reason 与另一行的 steerPath 拼在一起。A 升级前收到的证据同样可读。
    """
    rows = {int(row["evidenceNo"]): row for row in rt.store.evidence(attempt.msg_id)}
    high = rows.get(attempt.evidence_no)
    if high is None or (high.get("state"), high.get("reason")) != (attempt.delivery.get("state"),
                                                                  attempt.delivery.get("reason")):
        return {}
    for number in sorted((item for item in rows if item <= attempt.evidence_no), reverse=True):
        row = rows[number]
        if (row.get("state"), row.get("reason")) != (high.get("state"), high.get("reason")):
            return {}
        raw = row.get("detail")
        detail = steer_detail(raw) if isinstance(raw, dict) else {}  # pyright: ignore[reportUnknownArgumentType]
        if detail:
            return detail
    return {}


def _attempt_rows(rt: Runtime, attempts: list[FedAttempt]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for attempt in attempts:
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
        # 补充消息另标类别与所补序号（§95.5.6），告知标类别（§95.5.7）
        kind: dict[str, Any] = ({"noticeKind": "note", "forSeq": attempt.options.get("forSeq")} if attempt.is_note
                                else {"noticeKind": "fyi"} if attempt.is_fyi else {})
        detail = delivery_detail(rt, attempt)
        rows.append({
            **kind,
            **({"deliveryDetail": detail} if detail else {}),  # 只含闭集键，没有就省略（§97.3）
            "seq": attempt.seq, "role": attempt.role, "msgId": attempt.msg_id,
            "targetDevice": attempt.target_device, "targetDeviceName": device_name(rt, attempt.target_device),
            "target": f"{attempt.target.remote.provider.value}@id:{attempt.target.remote.native_id}",
            "network": outbox["state"] if outbox else ("local" if local else None),
            "native": native["state"] if native else None,
            "delivery": attempt.delivery.get("state", "pending"), "deliveryReason": delivery_reason(attempt),
            "receiverReported": attempt.delivery.get("receiverReported") is True,
            "work": attempt.effective_work.get("work"), "attachments": files,
            # §104.9 七：与本机同名同单位（epoch 秒）；createdAt 是 A 的钟，远端尝试的 deliveryAt 来自 B 的证据（B 的钟）
            "createdAt": _seconds(attempt.authority_state.get("createdAt")),
            "deliveryAt": _seconds(attempt.delivery.get("at")),
        })
    return rows


def _seconds(value: object) -> float | None:
    """联邦库的毫秒整数换成 epoch 秒（与本机 status --json 同单位）；缺值或形状不对为 None。"""
    if isinstance(value, int) and not isinstance(value, bool):
        return value / 1000.0
    return None


# 时间线条数（与本机一致）：文字 20 条，status --json 50 条
TIMELINE_TEXT_EVENTS = 20
TIMELINE_JSON_EVENTS = 50


def _event_rows(rt: Runtime, task: FedTask, limit: int) -> list[dict[str, Any]]:
    """本设备 fed_events 的记录，at 换成秒；kind/detail 原值（JSON 不转义，文字行另转义）。"""
    rows: list[dict[str, Any]] = []
    for event in rt.store.events(task.authority_device, task.task_id, limit=limit):
        at = _seconds(event["at"])
        if at is not None:
            rows.append({**event, "at": at})
    return rows


def _evidence_rows(rt: Runtime, attempt: FedAttempt) -> list[dict[str, Any]]:
    """A 收到的该尝试全部投递证据（fed_evidence），每条只取闭集的四个键；at 是投递设备的钟（秒）。"""
    return [{"no": row.get("evidenceNo"), "state": row.get("state"), "reason": row.get("reason"),
             "at": _seconds(row.get("at"))} for row in rt.store.evidence(attempt.msg_id)]


def _fed_reason_text(value: object) -> str:
    """时间线附注里的原因码：登记过的写文案，形状合规的原样写码，其余（来自远端的异常取值）写「未知取值」。

    先显式查是否登记（§104.12 第 10 条），命中才展开本地文案；未知取值不进 reason_text，免得被当成模板替换占位。
    """
    if not isinstance(value, str) or not value:
        return ""
    if reason_registered(value):
        return reason_text(value)  # 登记过的码（含 delivery_* 的投递标签）与本机时间线同一文案
    return code_text(value)


def fed_event_text(event: Mapping[str, Any]) -> tuple[str, object]:
    """联邦时间线一行的标签与附注（§104.9 七）。kind 可能嵌着远端取值（delivery_<B 的 state>、B 上
    report_<A 的裁决>），没登记的部分一律按 §103.3 写「未知取值（转义原文）」，不原样输出。"""
    kind = event.get("kind")
    raw_detail = event.get("detail")
    detail: dict[str, Any] = raw_detail if isinstance(raw_detail, dict) else {}  # pyright: ignore[reportUnknownVariableType]
    if not isinstance(kind, str):
        return unknown_text(kind), ""
    label = FEDERATION_EVENT_LABELS.get(kind) or EVENT_LABELS.get(kind)
    if kind == "origin_reminded":
        label = reminded_label(detail) or label
    if label is None:
        if kind.startswith("delivery_"):
            state = kind.removeprefix("delivery_")
            label = DELIVERY_LABELS[Delivery(state)] if state in _DELIVERY_VALUES else f"投递证据：{unknown_text(state)}"
        elif kind.startswith("transport_"):
            state = kind.removeprefix("transport_")
            label = f"传输：{TRANSPORT_EVENT_LABELS.get(state) or unknown_text(state)}"
        elif kind.startswith("report_") and kind.endswith("_saved") and len(kind) > len("report__saved"):
            label = f"已提交汇报（{report_kind_text(kind[len('report_'):-len('_saved')])}），等待发起设备确认"
        elif kind.startswith("report_"):
            label = f"发起设备裁决：{unknown_text(kind.removeprefix('report_'))}"
        else:
            label = unknown_text(kind)
    reason = detail.get("reason")
    extra: object = "" if kind == "origin_reminded" and silent_minutes(detail) is not None else _fed_reason_text(reason)
    if kind == "report_rejected" and "kind" in detail:
        extra = "；".join(part for part in (str(extra), f"类别 {report_kind_text(detail.get('kind'))}") if part)
    if kind == "notification_skipped" and reason in CAPACITY_CODES:
        extra = notification_capacity_hint(str(reason))
    elif kind == "review_skipped_capacity" and reason in CAPACITY_CODES:
        extra = review_capacity_hint(str(reason))
    return label, extra


def _report_rows(rt: Runtime, task: FedTask) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for row in rt.store.reports(task.authority_device, task.task_id):
        decision = rt.store.decision(str(row["reporter_device"]), str(row["operation_id"]))
        rows.append({"attempt": row["attempt_seq"], "reportNo": row["report_no"], "kind": row["report"].get("kind"),
                     "reporterDevice": row["reporter_device"],
                     "decision": decision["decision"] if decision else None,
                     "reason": decision["reason"] if decision else None})
    return rows


def task_document(rt: Runtime, task: FedTask, *, now: int, include_body: bool = False,
                  events: bool = False) -> dict[str, Any]:
    """status/tasks --json 的联邦形状：scope=federation，不伪造本机进程字段。

    events=True 只给 status --json（§104.9 七）：本设备记录的时间线 events（50 条），权威设备另给每次尝试收到的
    投递证据 evidence；tasks、send/retry/note 等复用本函数的输出不带这两项。
    """
    attempts = display_attempts(rt, task)
    view = mirror.describe_view(task, attempts, device_id=rt.ident.device_id)
    document: dict[str, Any] = {
        "scope": "federation", "id": task.task_id, "authorityDevice": task.authority_device,
        "authorityDeviceName": device_name(rt, task.authority_device), "isAuthority": task.is_authority,
        "title": task.title, "phase": view.phase.value, "reason": view.reason, "revision": task.revision,
        "lastSyncAt": task.last_sync_at, "syncRequired": task.sync_required, "archived": task.local_archived,
        "stalled": stalled(rt, task, now=now), "attempts": _attempt_rows(rt, attempts), "reports": _report_rows(rt, task),
    }
    if events:
        document["events"] = _event_rows(rt, task, TIMELINE_JSON_EVENTS)
        if task.is_authority:
            for row, attempt in zip(document["attempts"], attempts):
                row["evidence"] = _evidence_rows(rt, attempt)
    follows = task.state.get("follows")
    if isinstance(follows, str):
        document["follows"] = follows  # 只在发起设备本机有（§93.3）；无关联时不出现该键
    if task.is_fyi:
        document["fyi"] = True  # 一句话告知（§95.5.7）；普通任务不出现该键
    if include_body:
        first = next((item for item in attempts if item.role != "notice"), None)
        document["body"] = first.body if first is not None else ""
    return document


def _fyi_delivery(document: dict[str, Any]) -> str:
    """告知任务唯一那条 notice 的投递状态（联邦 L3 原值）。"""
    rows = document.get("attempts") or []
    return delivery_text(rows[0].get("delivery", "pending")) if rows else "-"


_NETWORK_LABELS = {"ready": "待传", "submitting": "提交中", "accepted": "hub 已收", "received": "对端已落账",
                   "refused": "hub 拒收", "rejected": "对端拒收", "expired": "已过期", "revoked": "已撤销",
                   "local": "本机"}


# 镜像汇报页脚按角色给出的命令（§98.2）：复核尝试不收 --result，交接尝试不收 --approve/--changes
HANDOFF_REPORT_CHOICES = "--result（或 --blocked / --failed）"
REVIEW_REPORT_CHOICES = "--approve 或 --changes（或 --blocked / --failed）"


def task_lines(rt: Runtime, task: FedTask, *, now: int, show_body: bool = False) -> list[str]:
    """status 文本：权威/镜像、同步时间、网络 L0–L2、投递 L3、报告与 A 采纳 L4、附件逐项状态。"""
    document = task_document(rt, task, now=now, include_body=show_body)
    view = view_of(rt, task)
    origin = device_text(document["authorityDeviceName"])
    role = "本机发起（权威）" if task.is_authority else f"镜像（发起设备 {origin}）"
    age = max(0, (now - task.last_sync_at) // 1000)
    flags = ("；需同步" if task.sync_required else "") + ("；仅本机已归档" if task.local_archived else "")
    state = (f"{FYI_STATUS_LABEL}（{_fyi_delivery(document)}）" if task.is_fyi
             else f"{PHASE_LABELS[view.phase]}（{reason_label(rt, task, view, now / 1000.0)}）")
    lines = [f"跨设备任务 {short(task.task_id)}  {title_text(task.title)}",
             f"  {role}；{state}；最近同步 {age} 秒前{flags}"]
    if document["stalled"]:
        lines.append("  需处理：远端离线/传输未恢复（待传超过 30 分钟；不改变任务状态）")
    for row, attempt in zip(document["attempts"], display_attempts(rt, task)):
        network = _NETWORK_LABELS.get(str(row["network"]), "-")
        reported = "，对方已汇报" if row["receiverReported"] else ""
        causes = [str(row["deliveryReason"])] if row["deliveryReason"] else []
        steer = row.get("deliveryDetail") or {}
        if "steerPath" in steer:
            causes.append(f"steer：{steer['steerPath']}")
        if "steerRejected" in steer:
            causes.append(f"steer 拒绝：{steer['steerRejected']}")
        cause = f"（{'；'.join(causes)}）" if causes else ""
        label = (f"{NOTE_LABEL} #{row['seq']}" if row.get("noticeKind") == "note"
                 else f"{FYI_LABEL} #{row['seq']}" if row.get("noticeKind") == "fyi" else f"#{row['seq']} {row['role']}")
        lines.append(f"  {label} → {device_text(row['targetDeviceName'])} {target_text(row['target'])}"
                     f"  网络 {network}  投递 {delivery_text(row['delivery'])}{cause}{reported}")
        for item in row["attachments"]:
            # 落地路径：新落地的叶名已清洗；按旧规则落地的叶名可能带 C1/RLO/零宽等，显示时再转义一次（§103.8 修 2）
            where = f" {remote_path(str(item['path'])) or ''}" if "path" in item else ""
            state = "已过留存期" if item["state"] == "expired" else item["state"]
            # 附件名来自发起方（镜像上即远端）：codec 只拒 0x20 以下控制字符，与其余远端字符串同一套转义（§103.3）
            lines.append(f"     附件 {remote_display(item['name']) or ''}：{state}（{item['size']} B）{where}")
        # 延迟投递（§104.9 二）：与本机同一判据 labels.deferred_due，到点后或在等自动重试时不写（§104.11 P3）
        due = deferred_due(attempt.options, pending=row["delivery"] == "pending", now=now / 1000.0)
        if due is not None:
            lines.append(f"     {deferred_text(due)}")
    for row in document["reports"]:
        status = row["decision"] or "等待发起设备确认"
        reason = f"（{code_text(row['reason'])}）" if row["reason"] else ""
        lines.append(f"  报告 #{row['attempt']}.{row['reportNo']} {report_kind_text(row['kind'])}：{status}{reason}")
    # 时间线（§104.9 七）：本设备 fed_events 的记录，格式同本机；镜像端没有投递证据事件
    lines.extend(timeline_lines(_event_rows(rt, task, TIMELINE_TEXT_EVENTS), describe=fed_event_text,
                                note="本设备记录"))
    if show_body:
        lines.extend(["", str(document.get("body", ""))])
    # 本机联邦停用时 ab report 报 federation_disabled，判据与 cli._fed_lookup(write=True) 相同，不给汇报提示（§98 r1）
    target = mirror.local_report_target(rt.store, rt.ident, task) if rt.config.enabled else None
    if target is not None:
        # 页脚只在本机当前尝试真能汇报时打印，判定与 B 端受理条件共用，命令按角色给（§98.2）；
        # 联邦页脚带 --origin-device：CLI 只据本机索引找发起设备，不读正文里的远端路径（§88.8）
        choices = (REVIEW_REPORT_CHOICES if target.role == "review" else HANDOFF_REPORT_CHOICES)
        # 页脚是可照抄的命令：登记名不是 slug 时改用完整 deviceId（--origin-device 两者都认），与 peers 的 target= 同口径（§101.1）
        name = document["authorityDeviceName"]
        reference = name if is_slug(name) else task.authority_device
        lines.append(f"汇报：{command_name()} report {short(task.task_id)} --origin-device {reference} {choices}")
    return lines


def list_tasks(rt: Runtime, *, include_finished: bool, wanted: TaskFilter | None = None) -> list[FedTask]:
    """tasks 的联邦部分，最近同步在前；有筛选时先取全部候选再筛、留最新的 200 条（DESIGN §93.1）。"""
    if wanted is None or not wanted.active:
        tasks = rt.store.tasks(include_finished=include_finished)
    else:
        candidates = rt.store.tasks(include_finished=include_finished, limit=-1)
        tasks = [item for item in candidates if matches(rt, item, wanted)][:TASK_LIST_LIMIT]
    return sorted(tasks, key=lambda item: item.last_sync_at, reverse=True)


def _actor_party(raw: object) -> Party | None:
    """账本里的 WireActor/RemoteEndpointRef 字典投影成 (provider, 会话 ID)；形状不对视为没有。"""
    if not isinstance(raw, dict):
        return None
    provider, native_id = raw.get("provider"), raw.get("nativeId")  # pyright: ignore[reportUnknownMemberType,reportUnknownVariableType]
    return (provider, native_id) if isinstance(provider, str) and isinstance(native_id, str) else None


def _checkpoint_targets(checkpoint: object) -> list[Party]:
    """checkpoint 里各 handoff/review 尝试的目标（不看 notice）；形状不对的项跳过。"""
    raw = checkpoint.get("attempts") if isinstance(checkpoint, dict) else None  # pyright: ignore[reportUnknownMemberType,reportUnknownVariableType]
    if not isinstance(raw, list):
        return []
    found: list[Party] = []
    for item in raw:  # pyright: ignore[reportUnknownVariableType]
        if isinstance(item, dict) and item.get("role") != "notice":  # pyright: ignore[reportUnknownMemberType]
            party = _actor_party(item.get("target"))  # pyright: ignore[reportUnknownMemberType]
            if party is not None:
                found.append(party)
    return found


def matches(rt: Runtime, task: FedTask, wanted: TaskFilter) -> bool:
    """联邦任务是否符合筛选：会话一律比远端完整 ID；最近活动取 state.updatedAt（毫秒），缺失用 last_sync_at。

    镜像（B）上只有 checkpoint 里的 originActor/reviewer，没有 A 的 origin/reviewer 引用，所以发起方取 originActor、
    复核方先取 A 的 reviewer、没有再取 checkpoint 里的 reviewer。镜像的 fed_attempts 只有发给本机的尝试，
    所以目标另并入 checkpoint 里全部 handoff/review 尝试的目标（含发给其他设备会话的）。
    正文取本机库里 seq 1 的那条，没有就只看标题。
    """
    attempts = rt.store.attempts(task.authority_device, task.task_id)
    state = task.state
    origin = _actor_party(state.get("originActor"))
    if origin is None and (found := task.origin()) is not None:
        origin = (found.remote.provider.value, found.remote.native_id)
    reviewer_ref = task.reviewer()
    checkpoint = state.get("checkpoint")
    reviewer = ((reviewer_ref.remote.provider.value, reviewer_ref.remote.native_id) if reviewer_ref is not None
                else _actor_party(checkpoint.get("reviewer") if isinstance(checkpoint, dict) else None))  # pyright: ignore[reportUnknownMemberType]
    updated = state.get("updatedAt")
    updated_ms = updated if isinstance(updated, int) and not isinstance(updated, bool) else task.last_sync_at
    first = next((item for item in attempts if item.seq == 1), None)
    return wanted.accepts(
        origin=origin, reviewer=reviewer,
        targets=[*((item.target.remote.provider.value, item.target.remote.native_id) for item in attempts
                   if item.role != "notice"), *_checkpoint_targets(checkpoint)],
        updated_at=updated_ms / 1000, title=task.title, body=first.body if first is not None else None)


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
    """relay 目录采样：Linux 走 discover()，Windows 按 provider 完整性发现；只发最小公开目录。

    来源完整与身份完整分开交给 snapshot（§94.1）：某家有认不出的根候选只降它自己的 providers[p]，
    顶层 complete 仍按来源算，别家的名字与前缀不连带失效。
    """

    def collect() -> dict[str, Any]:
        complete: dict[str, bool] = {}
        identities: dict[str, bool] = {}
        if get_platform().name == "windows":
            from ..platforms.windows.commands import WorkerDiscovery  # layout: allow Windows 按 provider 完整性发现
            from ..platforms.windows.local_transport import WindowsPlatform  # layout: allow 已选择后端

            backend = get_platform().transport
            if not isinstance(backend, WindowsPlatform):
                return {"endpoints": [], "complete": False, "providers": {}, "reason": "windows_provider_not_enabled"}
            sampler = WorkerDiscovery(backend)
            found = sampler()
            complete = {provider.value: sampler.source_complete(provider)
                        for provider in (Provider.CODEX, Provider.CLAUDE)}
            identities = {provider.value: sampler.ids_complete(provider)
                          for provider in (Provider.CODEX, Provider.CLAUDE)}
        else:
            # Linux 按本轮实际采样的完整性：注册目录读不到、预算截断或 /proc 不可列举的 provider 标不完整
            # （消费端据此不按名字在它上面消歧）；平台能力只是前提，不代表这一轮看全了
            sources = DiscoverySources()
            found = discover(sources) if get_platform().discovery is Capability.VERIFIED else []
            complete = {provider.value: get_platform().discovery is Capability.VERIFIED
                        and sources.provider_complete(provider) for provider in ADAPTERS}
            # 身份全集与本机 --to 解析、名字投影共用 _ids_complete（selection_complete 的身份部分），不另算一份
            identities = {provider.value: _ids_complete(found, provider) for provider in ADAPTERS}
        return directory.snapshot(rt.store, rt.ident.device_id, found, publish_names=rt.config.publish_names,
                                  provider_complete=complete, ids_complete=identities)

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
