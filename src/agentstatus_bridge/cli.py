"""协作桥命令行：在本机 Codex/Claude 会话之间交接任务、查看进展、复核与验收（DESIGN §45.9）。

终端、SSH 与 agent 会话使用同一套命令，不需要图形界面批准。退出码是桥自己的合同：
0 完成；2 目标不存在/歧义；3 校验或策略拒绝、可证明未送达；4 等待超时；5 对方报告失败或受阻；
6 能力不可用；7 投递结果不明；8 账本/协议错误。
"""

from __future__ import annotations

import argparse
from collections.abc import Sequence
import json
import os
import sqlite3
from pathlib import Path
import sys
import time
from typing import TYPE_CHECKING

from . import __version__, summary
from .platforms import process as procfs
from .codex_metadata import command_scope
from .display import endpoint_text
from .endpoints import (
    Caller,
    DiscoverySources,
    ResolveError,
    discover,
    identify_caller,
    permission_class,
    resolve_target,
)
from .hints import PaneState, stopped_without_report, target_session_missing
from .ids import short
from .labels import (  # 标签表移至 labels 供摘要与 worker 共用；此处保留同名导出
    CONSUMPTION_LABELS,
    DELIVERY_LABELS,
    EVENT_LABELS,
    ISSUE_LABELS,
    ROLE_LABELS,
    RUNTIME_LABELS,
    WORK_LABELS,
    next_step,
    reason_text,
    role_label,
    review_capacity_hint,
    notification_capacity_hint,
)
from .model import (
    HANDED_OVER,
    PHASE_LABELS,
    PROVEN_UNDELIVERED,
    UNRESOLVED_NATIVE_ID,
    Attempt,
    Delivery,
    Endpoint,
    EndpointRef,
    Flow,
    Phase,
    ReportKind,
    Role,
    Task,
    TaskView,
    Verdict,
    Work,
    describe,
    work_attempts,
)
from .naming import command_name
from .observer_dbus import ObserverView
from .platforms.factory import get_platform, using_platform
from .paths import codex_home, codex_sqlite_home, device_name, state_dir
from .reports import ReportError, ReportInput, apply_report, file_reference
from .store import ATTEMPT_WARNING_THRESHOLD, DB_NAME, MAX_BODY_BYTES, Store, StoreError
from .closure import ACCEPTED, CLOSED, ClosureOutcome, queue_closures
from .dispatch import needs_worker, select_generation
from .doctor import collect_checks, federation_text, print_checks
from .views import (
    _no_pane_warning,
    _NO_HINT,
    _TargetHint,
    _age,
    _closure_document,
    _describe_result,
    _print_closure,
    _print_task,
    _task_document,
    _withdrawal_document,
    _withdrawn,
)
from .worker import ensure_worker, run_worker, wait_for_worker, worker_running
from .transports import local_codex
from .transports.codex_queue import cli_version
from .transports.codex_withdraw import QueueDeleteClient
from .notification_policy import can_notify, receipt_options
from .federation.errors import FedCliError

if TYPE_CHECKING:
    from .federation.commands import Runtime as FedRuntime
    from .federation.fedstore import FedTask

EXIT_OK = 0
EXIT_TARGET = 2
EXIT_REJECTED = 3
EXIT_TIMEOUT = 4
EXIT_FAILURE_REPORTED = 5
EXIT_UNAVAILABLE = 6
EXIT_UNKNOWN = 7
EXIT_STORE = 8
EXIT_NOT_ENABLED = 9

SEND_WAIT_SECONDS = 15.0
# 新拉起的 worker 取得单实例锁前的等待上限
WORKER_START_SECONDS = 2.0

_RESULT_PHASES = frozenset({Phase.AWAITING_ACCEPTANCE, Phase.DONE, Phase.CLOSED})
# held 可能随对方批准而变化，继续等；其余需处理的状态立即返回
_KEEP_WAITING = frozenset({"delivery_held"})


class CliError(Exception):
    """命令失败：固定原因码与退出码。"""

    def __init__(self, code: str, exit_code: int = EXIT_REJECTED) -> None:
        super().__init__(code)
        self.code = code
        self.exit_code = exit_code


def _exit_for_store_error(code: str) -> int:
    if code.startswith("store_") or code in {"schema_too_new", "corrupt_record", "withdraw_store_unreadable",
                                             "withdraw_record_conflict", "withdraw_invalid_result"}:
        return EXIT_STORE
    if code in {"withdraw_root_missing", "withdraw_root_mismatch", "withdraw_platform_unsupported"}:
        return EXIT_UNAVAILABLE
    if code in {"task_not_found", "task_ambiguous"}:
        return EXIT_TARGET
    return EXIT_REJECTED


def _open_store() -> Store:
    try:
        return Store.open()
    except StoreError as error:
        raise CliError(error.code, _exit_for_store_error(error.code)) from error
    except PermissionError as error:
        raise CliError("store_unavailable", EXIT_STORE) from error


def _print_json(document: object) -> None:
    print(json.dumps(document, ensure_ascii=False, indent=2, sort_keys=True))


# ---- 目标与调用者 ----


def _selectors(endpoints: list[Endpoint]) -> dict[int, str]:
    """为每个端点给出最短且唯一的 `--to` 写法。"""
    counts: dict[tuple[str, str], int] = {}
    for item in endpoints:
        if item.ref.label:
            key = (item.ref.provider.value, item.ref.label)
            counts[key] = counts.get(key, 0) + 1
    selectors: dict[int, str] = {}
    for item in endpoints:
        label = item.ref.label
        if label and counts[(item.ref.provider.value, label)] == 1:
            # tmux 会话名可含空格；显示成可直接复制的连字符形式（解析时同样归一化）
            candidate = item.ref.token()
        elif item.ref.pane:
            candidate = item.ref.pane
        else:
            # 没有会话名也没有 pane（不经 tmux）：用 provider@<原生 ID 前缀>，与展示名一致且可直接复制
            candidate = item.ref.token()
        # 一律验算一遍：短写法撞上别人的会话名、同前缀会话，或同一 pane 里有多个会话（Grok resume 之后）时，
        # 退回完整原生 ID，保证复制过去解析到的就是这一行
        try:
            selectors[id(item)] = candidate if resolve_target(candidate, endpoints) is item else item.ref.native_id
        except ResolveError:
            selectors[id(item)] = item.ref.native_id
    return selectors


def _receiver_class(endpoint: Endpoint) -> str | None:
    if get_platform().name == 'windows':
        return None  # No trustworthy launch argv; never call the Linux legacy process facade.
    info = procfs.read_process(endpoint.ref.pid)
    if info is None or info.start_ticks != endpoint.ref.start_ticks:
        return None
    return permission_class(Caller(None, info))


def _check_sender(caller: Caller) -> None:
    """发起方必须是认得出的会话或用户本人（DESIGN §45.48 R3/R5）。

    Codex 子代理不能发起；看得见 agent 进程或环境迹象却认不出是哪个会话时拒绝，不把 agent 发起的任务
    落成 `origin=None`（那等于伪装成用户，回执身份也丢了）；`"-"` 不是身份，同样拒绝。
    """
    if caller.rejection == "subagent":
        raise CliError("sender_is_subagent")
    if caller.endpoint is not None and caller.endpoint.ref.native_id == UNRESOLVED_NATIVE_ID:
        raise CliError("caller_unattributed")
    if caller.endpoint is None and not caller.is_user_shell:
        raise CliError("caller_unattributed")


def _check_target(endpoint: Endpoint, *, allow_shared: bool) -> None:
    if not can_notify(endpoint.ref):
        raise CliError('target_no_inbox')
    blocking = endpoint.blocking_issues
    if blocking:
        raise CliError(f"target_{blocking[0]}")
    if "shared_thread" in endpoint.issues and not allow_shared:
        raise CliError("target_shared_thread")


def _resolve(selector: str, endpoints: list[Endpoint]) -> Endpoint:
    if get_platform().name == 'windows':
        from .platforms.windows.commands import resolve  # layout: allow Windows完整loaded名称解析，不改变Linux选择器
        return resolve(selector)
    try:
        return resolve_target(selector, endpoints)
    except ResolveError as error:
        if error.candidates and all("no_inbox" in item.blocking_issues for item in error.candidates):
            # 候选全是只读会话（例如 resume 之后同 pane 两个 Grok 会话）：改哪个候选都投不进去，
            # 报「不唯一」会让人以为换个写法就能发（Opus 复审 N1）
            raise CliError("target_no_inbox") from error
        if error.candidates:
            names = _selectors(list(error.candidates))
            options = "、".join(names[id(item)] for item in error.candidates)
            print(f"{command_name()}: 可选目标：{options}", file=sys.stderr)
        raise CliError(error.code, EXIT_TARGET) from error


def _hold_hint(target: Endpoint, sender_class: str | None) -> str | None:
    if target.ref.provider.value != "claude":
        return None
    if get_platform().name == 'windows':
        return "发送方类别未知：对方若是 bypass 会话需批准，默认 5 分钟过期"
    receiver = _receiver_class(target)
    if receiver == "bypass" and sender_class != "bypass":
        return "对方是 bypass 会话、发送方不是：消息会先等对方会话批准（默认 5 分钟过期）"
    if receiver != "bypass" and sender_class == "bypass":
        return "发送方是 bypass、对方不是：消息会先等对方会话批准（默认 5 分钟过期）"
    return None


# ---- 文档与显示 ----


def _target_hint(
    attempts: list[Attempt], endpoints: list[Endpoint], view: ObserverView, now: float
) -> _TargetHint:
    """当前工作尝试的接收方是否已停下却未汇报，或当前未发现其会话。"""
    working = work_attempts(attempts)
    if not working:
        return _NO_HINT
    current = working[-1]
    live, problem = select_generation(current.target, endpoints)
    if target_session_missing(current, live, problem, discovered=bool(endpoints)):
        return _TargetHint(missing=True)
    pane = _target_state(view, live) if live is not None and live.ref.pane else None
    return _TargetHint(stopped_at=stopped_without_report(current, live, pane, now=now))


def _target_state(view: ObserverView, live: Endpoint) -> PaneState | None:
    """停下提示只认目标自己的行（DESIGN §62 ⑤，候选 C）。

    按活端点算出的 observer 键取行，与摘要的 `endpoint_binding` 同一套键：Codex 按进程代际键；Claude 代际键优先，
    没有代际行时兼容回退到同 pane 的同一逻辑会话行（与 `endpoints._claude_background_row` 同口径，回退不证明
    pid/start 相同）。算不出键或键上没有行就不提示：同 pane 上被保持的旧代际、别的会话，它们的结束时刻都不能替目标作证。
    """
    for item in summary.endpoint_binding(live.ref)["observerKeys"]:
        row = view.row(item["key"])
        if row is None:
            continue
        if item["match"] == "session" and row.pane != live.ref.pane:
            return None
        return row.pane_state()
    return None


def _observations() -> tuple[list[Endpoint], ObserverView]:
    """查询命令用的只读观察：活端点与 AgentStatus 快照，只读一次 ListSessions（DESIGN §55）。

    端点状态与提示证据出自同一份快照（端点忙闲按 pane 与 provider 取行，提示证据按目标的 observer 键取行，
    DESIGN §62 ④⑤）；任一来源不可用时提示自然缺席。
    """
    view = get_platform().runtime.view()
    if get_platform().name == 'windows':
        return [], view
    return discover(DiscoverySources(runtime=lambda: view)), view


# ---- 命令 ----


def cmd_peers(args: argparse.Namespace) -> int:
    if args.device or (args.all_devices and get_platform().name == "windows"):
        return _fed_peers(args)
    endpoints = discover()
    caller = identify_caller(endpoints)
    selectors = _selectors(endpoints)
    # 设备只是路由属性：今天发现到的端点全在本机，所以每行都是同一个值（DESIGN §45.35）
    device = device_name()
    rows: list[dict[str, object]] = []
    for item in endpoints:
        rows.append(
            {
                "target": selectors[id(item)],
                "device": device,
                "provider": item.ref.provider.value,
                "session": item.ref.label,
                "pane": item.ref.pane,
                "nativeId": item.ref.native_id,
                "runtime": item.runtime.value,
                "permissionClass": _receiver_class(item),
                "issues": list(item.issues),
                # 该进程持有的全部 Codex thread（诊断用，只在运行期，不进账本；DESIGN §45.48 R1）
                "threads": list(item.threads),
                # 按身份比较而不是对象相等：R3 可能生成解析后的副本（DESIGN §45.48）
                "self": caller.endpoint is not None and caller.endpoint.ref == item.ref,
            }
        )
    if args.json:
        document: dict[str, object] = {"peers": rows}
        if args.all_devices:
            document["devices"] = _fed_all_devices()
        _print_json(document)
        return EXIT_OK
    if args.all_devices:
        print(f"设备 {device}（本机）：")
    if not rows:
        print("没有发现正在运行的 agent 终端会话（Claude/Codex/Grok）")
        if args.all_devices:
            _fed_all_devices_text()
        return EXIT_OK
    # 列宽按最长的目标写法算：同一 pane 里有多个会话时目标会退回 36 字符的完整会话 ID，固定列宽会把后面挤歪
    width = max(28, *(len(str(row["target"])) for row in rows))
    for row, item in zip(rows, endpoints):
        mark = "  ← 当前会话" if row["self"] else ""
        issues = "，".join(ISSUE_LABELS.get(issue, issue) for issue in item.issues)
        extra = f"  [{issues}]" if issues else ""
        mode = f"  {row['permissionClass']}" if row["permissionClass"] else ""
        print(
            f"{str(row['target']):<{width}} {item.ref.pane or '-':<5} {RUNTIME_LABELS[item.runtime]:<6}"
            f" {item.ref.native_id[:8]}{mode}{extra}{mark}"
        )
    if args.all_devices:
        _fed_all_devices_text()
    return EXIT_OK


def _fed_all_devices() -> list[dict[str, object]]:
    """peers --all-devices 的远端部分；未启用联邦时为空。"""
    from .federation import commands as fed  # layout: allow 联邦按需加载
    from .federation import directory as fed_directory  # layout: allow 联邦按需加载
    rt = fed.try_runtime(state_dir())
    if rt is None:
        return []
    try:
        return list(fed_directory.peer_devices(rt.store, None, now=int(time.time() * 1000)))
    finally:
        rt.close()


def _fed_all_devices_text() -> None:
    from .federation import commands as fed  # layout: allow 联邦按需加载
    from .federation import directory as fed_directory  # layout: allow 联邦按需加载
    rt = fed.try_runtime(state_dir())
    if rt is None:
        return
    try:
        for line in fed_directory.peer_lines(rt.store, None, now=int(time.time() * 1000)):
            print(line)
    finally:
        rt.close()


# 本次命令是否真的新拉起过 worker：main 结束时的补拉据此跳过。新 worker 还没拿到锁时再拉一次会多起一个进程（Opus 审计 F2）。
# 只在确实启动了新进程后置真：启动失败，或当时旧 worker 仍在（随后可能退出），都保留结束时的补拉（Codex 复审 S02 / Opus 复审 P3-1）
_worker_ensured = False


def _ensure_worker() -> bool:
    """拉起后台 worker（已在运行则不动）；新启动了进程才记下，结束时不再补拉。"""
    global _worker_ensured
    started = ensure_worker(state_dir())
    _worker_ensured = _worker_ensured or started
    return started


def _start_worker() -> bool | None:
    """拉起后台 worker；返回是否新启动，启动失败返回 None。"""
    try:
        return _ensure_worker()
    except (OSError, StoreError):
        return None


def _queued_without_worker(started: bool | None) -> bool:
    """结果已记入账本、后续消息排队，但 worker 没能启动：说明情况，返回 True 供命令给出退出码 6（DESIGN §45.29）。"""
    if started is not None:
        return False
    cmd = command_name()
    # 退出码 6 不代表没记上：写明勿重复执行（重复汇报受阻会再排一条通知），并只承诺真的会补拉的入口（Codex F03 / Opus P3-4）
    print(
        f"注意：{reason_text('worker_start_failed')}。上面的操作已记入账本，请勿重复执行；"
        "排队消息、发送恢复与待办提醒要等后台 worker 拉起后才继续。"
        f"本命令结束时会再试一次，之后运行 {cmd} status / {cmd} tasks 等命令（普通 {cmd} summary 除外）也会再试，"
        f"AgentStatus 扩展定时补查摘要时也会按需再试；{cmd} doctor 可检查 worker 状态",
        file=sys.stderr,
    )
    return True


def _worker_up(root: Path) -> bool:
    """worker 是否在运行；锁文件异常（例如被替换成目录）按未运行处理，不打断已提交的命令（Opus 审计 P3-6）。"""
    try:
        return worker_running(root)
    except OSError:
        return False


def _wait_worker_up(root: Path, timeout: float) -> bool:
    """等新拉起的 worker 持锁；锁文件异常时按未运行处理。"""
    try:
        return wait_for_worker(root, timeout=timeout)
    except OSError:
        return False


def _revive_worker(store: Store, now: float) -> None:
    """有待办而 worker 不在（例如异常退出）时重新拉起；查询命令也能让排队恢复流动。

    本机与跨设备作业同口径（§79「CLI 不排除停泊的 PENDING」）：联邦作业停泊后，查询命令与扩展定时补查也会续上。
    """
    try:
        if (needs_worker(store, now) or _federation_needs_worker(now)) and not _worker_up(state_dir()):
            _ensure_worker()
    except (OSError, StoreError):
        pass


def _revive_for_federation() -> None:
    """没有本机账本、或走了不开本机账本的入口时，只按联邦待办补拉 worker：不建本机库，未配置联邦时不导入联邦实现。"""
    try:
        if not _worker_ensured and _federation_needs_worker(time.time()) and not _worker_up(state_dir()):
            _ensure_worker()
    except (OSError, StoreError):
        pass


def _federation_needs_worker(now: float) -> bool:
    """联邦已启用且本机有现在就能处理或待恢复的跨设备作业（与 relay 唤醒同一判定）；未配置时不导入联邦实现。

    只是补拉 worker 的辅助判断：联邦库打不开或任何异常都按「不需要」处理，不影响本机命令（Opus r2-P2-2）。
    """
    root = state_dir()
    if not _fed_configured(root):
        return False
    try:
        from .federation import commands as fed, mirror  # layout: allow 联邦按需加载：未配置的机器不导入联邦实现

        rt = fed.try_runtime(root)
        if rt is None:
            return False
        try:
            now_ms = int(now * 1000)
            # 与本机 needs_worker(reminders=True) 同口径：可处理/待恢复的作业与已到期提醒（wake_candidates），
            # 或 A 上还没到期的发起方提醒（worker 为它驻留，Opus r3-P3-1）
            return rt.config.enabled and (bool(mirror.wake_candidates(rt.store, rt.ident, now=now_ms))
                                          or any(True for _ in mirror.reminder_candidates(rt.store, now_ms)))
        finally:
            rt.close()
    except Exception:  # noqa: BLE001 - 辅助判断不能让本机命令失败
        return False


def _read_body(args: argparse.Namespace) -> str:
    if args.file and args.message is not None:
        raise CliError("message_and_file_conflict")
    if args.file:
        path = Path(args.file).expanduser()
        try:
            data = path.read_bytes() if path.stat().st_size <= MAX_BODY_BYTES else None
        except OSError as error:
            raise CliError("file_unreadable") from error
        if data is None:
            raise CliError("message_too_large")
        if get_platform().name == 'windows':
            return _windows_body(data)
        return data.decode("utf-8", errors="replace")
    if args.message == "-" or (args.message is None and not sys.stdin.isatty()):
        if get_platform().name == 'windows':
            return _windows_body(sys.stdin.buffer.read(MAX_BODY_BYTES + 1))
        return sys.stdin.read(MAX_BODY_BYTES + 1)
    if args.message is None:
        raise CliError("empty_message")
    return args.message


def _windows_body(data: bytes) -> str:
    if len(data) > MAX_BODY_BYTES:
        raise CliError('message_too_large')
    try:
        return data.decode('utf-8', errors='strict')
    except UnicodeDecodeError as error:
        raise CliError('message_invalid_utf8') from error


def _wait_first_delivery(store: Store, task_id: str, timeout: float) -> Attempt | None:
    deadline = time.monotonic() + timeout
    current: Attempt | None = None
    while True:
        attempts = work_attempts(store.attempts(task_id))
        current = attempts[-1] if attempts else None
        if current is None or current.delivery not in (Delivery.PENDING, Delivery.SENDING):
            return current
        if time.monotonic() >= deadline:
            return current
        time.sleep(0.25)


def _delivery_exit(delivery: Delivery) -> int:
    if delivery is Delivery.UNKNOWN:
        return EXIT_UNKNOWN
    if delivery in PROVEN_UNDELIVERED and delivery is not Delivery.PENDING:
        return EXIT_REJECTED
    return EXIT_OK


def cmd_send(args: argparse.Namespace) -> int:
    if args.device or args.review_device:
        return _fed_send(args)
    return _local_send(args)


def _local_send(args: argparse.Namespace, *, body: str | None = None) -> int:
    body = _read_body(args) if body is None else body
    cwd = Path.cwd()
    refs = [file_reference(path, cwd=cwd) for path in args.ref]
    endpoints = discover()
    caller = identify_caller(endpoints)
    _check_sender(caller)
    target = _resolve(args.to, endpoints)
    _check_target(target, allow_shared=args.allow_shared)
    if caller.endpoint is not None and caller.endpoint.ref.same_session(target.ref):
        raise CliError("target_is_self")
    reviewer: Endpoint | None = None
    if args.review_by:
        reviewer = _resolve(args.review_by, endpoints)
        _check_target(reviewer, allow_shared=args.allow_shared)
        if reviewer.ref.same_session(target.ref):
            raise CliError("reviewer_is_target")
    origin = caller.endpoint.ref if caller.endpoint is not None else None
    try:
        receipts = receipt_options(origin, no_notify=args.no_notify)
    except ValueError as error:
        raise CliError(str(error)) from error
    origin_class = permission_class(caller)
    first_line = body.strip().splitlines()[0] if body.strip() else ""
    title = (args.title or first_line)[:60]
    now = time.time()
    with _open_store() as store:
        try:
            task, attempt = store.create_task(
                title=title,
                flow=Flow.REVIEW if reviewer else Flow.HANDOFF,
                origin=origin,
                origin_class=origin_class,
                reviewer=reviewer.ref if reviewer else None,
                target=target.ref,
                body=body,
                refs=refs,
                now=now,
                task_options={"notify": not args.no_notify, "allowShared": bool(args.allow_shared), **receipts},
                attempt_options={"allowShared": bool(args.allow_shared)},
            )
        except StoreError as error:
            raise CliError(error.code, _exit_for_store_error(error.code)) from error
        started = _start_worker()
        current = attempt
        if not args.no_wait:
            current = _wait_first_delivery(store, task.id, SEND_WAIT_SECONDS) or attempt
        worker_up = (
            current.delivery is not Delivery.PENDING
            or _worker_up(state_dir())
            or (bool(started) and _wait_worker_up(state_dir(), WORKER_START_SECONDS))
        )
        hint = _hold_hint(target, origin_class)
        if args.json:
            document = _task_document(store, task)
            document["hint"] = hint
            _print_json(document)
        else:
            print(f"任务 {short(task.id)} 已交给 {endpoint_text(target.ref)}：{DELIVERY_LABELS[current.delivery]}")
            warning = _no_pane_warning([current])
            if warning is not None:
                print(warning)
            if receipts.get('receiptMode') == 'poll_only':
                print('回执方式：poll_only；用 status / wait 读取，不推送通知。')
            if current.delivery is Delivery.PENDING:
                # 不再按忙闲扣留（§45.42）：还是 PENDING 只说明 worker 还没轮到它
                if worker_up:
                    print(f"后台 worker 正在发送；稍后用 {command_name()} status 查看投递结果")
                if not worker_up:
                    code = "worker_start_failed" if started is None else "worker_not_running"
                    print(f"注意：{reason_text(code)}")
            elif current.delivery_reason and current.delivery_reason not in {"codex_queued", "claude_written"}:
                print(reason_text(current.delivery_reason))
            if current.delivery is Delivery.QUEUED:
                print("Codex 会在空闲时按顺序执行队列消息；已入队的消息无法由桥撤回")
            if hint:
                print(f"提示：{hint}")
            cmd = command_name()
            print(f"查看进展：{cmd} status {short(task.id)}；等待结果：{cmd} wait {short(task.id)}")
        if not worker_up:
            return EXIT_UNAVAILABLE
        return _delivery_exit(current.delivery)


def cmd_tasks(args: argparse.Namespace) -> int:
    now = time.time()
    with _open_store() as store:
        # 待办而 worker 不在时的补拉由 main 结束时统一做（DESIGN §45.28.3），这里不重复拉起
        tasks = store.list_tasks(include_finished=args.all)
        federation = _fed_task_list(args.all, now)
        endpoints, observed = _observations() if any(not task.finished for task in tasks) else ([], ObserverView())
        hints = {
            task.id: _target_hint(store.attempts(task.id), endpoints, observed, now)
            for task in tasks
            if not task.finished
        }
        if args.json:
            listing: dict[str, object] = {
                "tasks": [_task_document(store, task, hint=hints.get(task.id, _NO_HINT)) for task in tasks]}
            if federation is not None:
                listing["federation"] = federation[0]
            _print_json(listing)
            return EXIT_OK
        if not tasks:
            print("没有进行中的协作任务" if not args.all else "没有协作任务")
        for task in tasks:
            attempts = store.attempts(task.id)
            view = describe(task, attempts)
            target = endpoint_text(view.current.target) if view.current else "-"
            hint = hints.get(task.id, _NO_HINT)
            withdrawals = _withdrawal_document(store, task)
            withdrawal_note = ""
            if not withdrawals["readable"]:
                withdrawal_note = "，原生撤回附表不可读"
            if _withdrawn(view.current, withdrawals["operations"]):
                hint = _NO_HINT
                withdrawal_note += "，本桥已移除该队列项（不证明未执行）"
            if any(item["ownerStatus"] == "gone" for item in withdrawals["operations"]):
                withdrawal_note += "，执行者已不在，下次 withdraw 恢复"
            elif any(item["ownerStatus"] == "namespace_unverified" for item in withdrawals["operations"]):
                withdrawal_note += "，执行者 PID 命名空间不可核对，不判死"
            flag = "，未发现对方会话" if hint.missing else "，对方已停下未汇报" if hint.stopped_at is not None else ""
            print(
                f"{short(task.id)}  {PHASE_LABELS[view.phase]:<4} {target:<28}"
                f" {task.title[:40]}  （{reason_text(view.reason)}{flag}{withdrawal_note}，{_age(task.updated_at, now)}）"
            )
        for line in federation[1] if federation is not None else []:
            print(line)
    return EXIT_OK


def _task(store: Store, reference: str) -> Task:
    try:
        task = store.resolve_task(reference)
        if get_platform().name == 'windows':
            from .platforms.windows.commands import check_task  # layout: allow 本地读后、业务变更前的Windows能力核对
            check_task(task, store.attempts(task.id))
        return task
    except StoreError as error:
        raise CliError(error.code, _exit_for_store_error(error.code)) from error


def cmd_status(args: argparse.Namespace) -> int:
    found = _fed_lookup(args, write=False)
    if found is not None:
        return _fed_status(args, *found)
    now = time.time()
    with _open_store() as store:
        # 待办而 worker 不在时的补拉由 main 结束时统一做（DESIGN §45.28.3），这里不重复拉起
        task = _task(store, args.task)
        hint = _NO_HINT
        if not task.finished:
            endpoints, observed = _observations()
            hint = _target_hint(store.attempts(task.id), endpoints, observed, now)
        if args.json:
            _print_json(_task_document(store, task, include_body=args.body, events=True, hint=hint))
        else:
            _print_task(store, task, now=now, show_body=args.body, hint=hint)
    return EXIT_OK


_REPORT_KINDS: tuple[tuple[str, ReportKind], ...] = (
    ("ack", ReportKind.ACK),
    ("progress", ReportKind.PROGRESS),
    ("result", ReportKind.RESULT),
    ("blocked", ReportKind.BLOCKED),
    ("failed", ReportKind.FAILED),
    ("approve", ReportKind.APPROVE),
    ("changes", ReportKind.CHANGES),
)


def cmd_report(args: argparse.Namespace) -> int:
    kind = next(value for name, value in _REPORT_KINDS if getattr(args, name))
    found = _fed_lookup(args, write=True)
    if found is not None:
        return _fed_report(args, kind, *found)
    endpoints = discover()
    caller = identify_caller(endpoints)
    with _open_store() as store:
        if get_platform().name == 'windows':
            _task(store, args.task)  # Windows root/capability check before apply_report's transaction
        try:
            outcome = apply_report(
                store,
                ReportInput(
                    task_ref=args.task,
                    kind=kind,
                    attempt_seq=args.attempt,
                    note=args.note,
                    files=tuple(args.file),
                    commit=args.commit,
                    manual=args.manual,
                ),
                caller=caller,
                caller_class=permission_class(caller),
                now=time.time(),
                cwd=Path.cwd(),
            )
        except ReportError as error:
            raise CliError(error.code) from error
        except StoreError as error:
            raise CliError(error.code, _exit_for_store_error(error.code)) from error
        # 汇报已提交：拉起 worker 失败不能以异常堆栈退出，让人误以为没记上（DESIGN §45.29）
        unavailable = _queued_without_worker(_start_worker()) if outcome.followups else False
        exit_code = EXIT_UNAVAILABLE if unavailable else EXIT_OK
        warnings = []
        if 'review' in outcome.skipped:
            warnings.append(review_capacity_hint(outcome.skipped['review'], reporter=True))
        if 'result' in outcome.skipped:
            warnings.append(notification_capacity_hint(outcome.skipped['result'], reporter=True))
        if max(a.seq for a in store.attempts(outcome.task.id)) >= ATTEMPT_WARNING_THRESHOLD:
            warnings.append(reason_text('report_attempts_near_limit'))
        if args.json:
            document = _task_document(store, outcome.task)
            document['reportSkipped'] = outcome.skipped
            document['warnings'] = warnings
            _print_json(document)
            return exit_code
        print(f"已记录：{EVENT_LABELS[kind.value]}（任务 {short(outcome.task.id)} #{outcome.attempt.seq}）")
        for followup in outcome.followups:
            label = "已排队发给复核方" if followup.role is Role.REVIEW else "已排队通知发起方"
            print(f"{label} {endpoint_text(followup.target)}")
        for warning in warnings:
            print(f"提示：{warning}")
    return exit_code


def _wait_outcome(view: TaskView, until: str) -> int | None:
    """wait 是否到达：本机与跨设备任务共用同一判定（联邦视图经 views 投影）。"""
    current = view.current
    reached: int | None = None
    if until == "sent":
        if current is not None and current.delivery in (*HANDED_OVER, Delivery.HELD):
            reached = EXIT_OK
    elif until == "ack":
        if current is not None and current.work in (Work.ACKNOWLEDGED, Work.IN_PROGRESS, Work.RESULT):
            reached = EXIT_OK
    if reached is None:
        if view.phase in _RESULT_PHASES and until in {"result", "ack", "sent"}:
            reached = EXIT_OK
        elif view.phase is Phase.NEEDS_ATTENTION and view.reason not in _KEEP_WAITING:
            if view.reason == "delivery_unknown":
                reached = EXIT_UNKNOWN
            elif view.reason in {
                "blocked_reported",
                "failure_reported",
                "changes_requested",
                "review_verdict_missing",
            }:
                reached = EXIT_FAILURE_REPORTED
            else:
                reached = EXIT_REJECTED
    return reached


def cmd_wait(args: argparse.Namespace) -> int:
    found = _fed_lookup(args, write=False)
    if found is not None:
        return _fed_wait(args, *found)
    deadline = time.monotonic() + args.timeout
    rounds = 0
    opener = _open_store
    if get_platform().name == 'windows':
        from .platforms.windows.local_store import open_store  # layout: allow Windows wait只读，不配置/迁移账本
        opener = open_store
    with opener() as store:
        while True:
            if rounds % 10 == 0 and get_platform().name != 'windows':
                _revive_worker(store, time.time())
            rounds += 1
            task = _task(store, args.task)
            attempts = store.attempts(task.id)
            view = describe(task, attempts)
            reached = _wait_outcome(view, args.until)
            if reached is not None:
                if args.json:
                    _print_json(_task_document(store, task))
                else:
                    _print_task(store, task, now=time.time(), show_body=False)
                return reached
            if time.monotonic() >= deadline:
                if not args.json:
                    print(f"等待超时：{PHASE_LABELS[view.phase]}（{reason_text(view.reason)}）")
                return EXIT_TIMEOUT
            time.sleep(1.0)


def cmd_pause(args: argparse.Namespace) -> int:
    found = _fed_lookup(args, write=True)
    if found is not None:
        return _fed_control(args, "pause", *found)
    caller = identify_caller(discover()) if get_platform().name == 'windows' else None
    with _open_store() as store:
        task = _task(store, args.task)
        if caller is not None and not _may_decide(caller, task):
            raise CliError('accept_not_allowed')
        if task.finished:
            raise CliError("task_finished")
        store.update_task(task.id, now=time.time(), event="paused", control="paused")
        print(f"任务 {short(task.id)} 已暂停发送；已发出的消息不受影响")
    return EXIT_OK


def cmd_resume(args: argparse.Namespace) -> int:
    found = _fed_lookup(args, write=True)
    if found is not None:
        return _fed_control(args, "resume", *found)
    caller = identify_caller(discover()) if get_platform().name == 'windows' else None
    with _open_store() as store:
        task = _task(store, args.task)
        if caller is not None and not _may_decide(caller, task):
            raise CliError('accept_not_allowed')
        if task.finished:
            raise CliError("task_finished")
        if not task.paused:
            raise CliError("not_paused")
        store.update_task(task.id, now=time.time(), event="resumed", control="active")
        started = _start_worker()
        print(f"任务 {short(task.id)} 继续发送")
        # 按全账本的实际后台需求判断（排队、发送恢复、观察窗口、待办提醒；worker 全局只有一个），不只看本任务排队消息（Codex 复审 R01）
        needed = False
        if started is None:
            try:
                needed = needs_worker(store, time.time())
            except (StoreError, sqlite3.Error):  # 读账本出错时按需要处理，不以堆栈退出（Opus 第二轮复审）
                needed = True
    return EXIT_UNAVAILABLE if needed and _queued_without_worker(started) else EXIT_OK


def cmd_cancel(args: argparse.Namespace) -> int:
    found = _fed_lookup(args, write=True)
    if found is not None:
        return _fed_control(args, "cancel", *found)
    caller = identify_caller(discover()) if get_platform().name == 'windows' else None
    now = time.time()
    with _open_store() as store:
        task = _task(store, args.task)
        if caller is not None and not _may_decide(caller, task):
            raise CliError('accept_not_allowed')
        cancelled = 0
        for attempt in store.attempts(task.id):
            if store.transition_delivery(
                attempt.id, expected=(Delivery.PENDING,), new=Delivery.CANCELLED, reason="cancelled", now=now
            ):
                cancelled += 1
        if cancelled == 0:
            raise CliError("nothing_to_cancel")
        print(f"已取消 {cancelled} 条尚未发送的消息（任务 {short(task.id)}）")
    return EXIT_OK


def _may_decide(caller: Caller, task: Task) -> bool:
    """用户本人，或代表用户发起任务的会话，可以验收；执行方和复核方不能。"""
    if caller.is_user_shell:
        return True
    return caller.endpoint is not None and task.origin is not None and caller.endpoint.ref.same_session(task.origin)


def _closure_decider(caller: Caller) -> tuple[EndpointRef | None, str]:
    """结束回执以谁的名义发出：决定者所在会话（用户在终端时为空）与正文里的显示名。"""
    if caller.endpoint is not None:
        from .notification_policy import wire_ref  # layout: allow Windows自动通知不携原生label，Linux原样
        return caller.endpoint.ref, wire_ref(caller.endpoint.ref).display()
    return None, "用户"


def _cancel_ordinary_pending(store: Store, attempts: list[Attempt], *, reason: str, now: float) -> None:
    """取消尚未发出的普通消息；已排队的结束回执照发（DESIGN §45.31.2）。"""
    for attempt in attempts:
        if attempt.is_closure:
            continue
        store.transition_delivery(
            attempt.id, expected=(Delivery.PENDING,), new=Delivery.CANCELLED, reason=reason, now=now
        )


def cmd_accept(args: argparse.Namespace) -> int:
    found = _fed_lookup(args, write=True)
    if found is not None:
        return _fed_finish(args, ACCEPTED, *found)
    endpoints = discover()
    caller = identify_caller(endpoints)
    with _open_store() as store:
        task = _task(store, args.task)
        if task.finished:
            raise CliError("task_finished")
        if not _may_decide(caller, task):
            raise CliError("accept_not_allowed")
        view = describe(task, store.attempts(task.id))
        if view.phase is not Phase.AWAITING_ACCEPTANCE and not args.force:
            raise CliError("no_result_to_accept")
        sender, decider = _closure_decider(caller)
        sender_class = permission_class(caller)
        now = time.time()
        with store.transaction():
            # 事务内重读：并发的另一个 accept/close 已先提交时，这里不再生成第二份结束回执
            current = store.get_task(task.id)
            if current is None or current.finished:
                raise CliError("task_finished")
            attempts = store.attempts(task.id)
            # 验收后不会再发送：尚在桥内排队的消息一并取消，不占用排队容量
            _cancel_ordinary_pending(store, attempts, reason="accepted", now=now)
            outcome = queue_closures(
                store, current, store.attempts(task.id), ACCEPTED,
                now=now, decider=decider, reason=None, sender=sender, sender_class=sender_class,
            )
            store.update_task(task.id, now=now, event="accepted", accepted_at=now)
        if args.json:
            _print_json({"ok": True, "id": task.id, "phase": Phase.DONE.value, "closure": _closure_document(outcome)})
        else:
            print(f"任务 {short(task.id)} 已验收")
            _print_closure(outcome)
    return EXIT_OK


_NATIVE_RISK = frozenset({Delivery.WRITTEN, Delivery.QUEUED, Delivery.HELD, Delivery.UNKNOWN, Delivery.DELIVERED})


def cmd_close(args: argparse.Namespace) -> int:
    found = _fed_lookup(args, write=True)
    if found is not None:
        return _fed_finish(args, CLOSED, *found)
    endpoints = discover()
    caller = identify_caller(endpoints)
    now = time.time()
    with _open_store() as store:
        task = _task(store, args.task)
        if task.closed_at is not None:
            raise CliError("task_finished")
        if not _may_decide(caller, task):
            raise CliError("accept_not_allowed")
        sender, decider = _closure_decider(caller)
        sender_class = permission_class(caller)
        with store.transaction():
            current = store.get_task(task.id)
            if current is None or current.closed_at is not None:
                raise CliError("task_finished")
            attempts = store.attempts(task.id)
            _cancel_ordinary_pending(store, attempts, reason="closed", now=now)
            at_risk = any(
                attempt.delivery in _NATIVE_RISK and attempt.work not in (Work.RESULT, Work.FAILED, Work.NONE)
                for attempt in attempts
            )
            if at_risk:
                store.note_archived_risk()
            # 只在第一次进入终态时生成；已验收后补记关闭不再发第二份
            outcome = (
                ClosureOutcome([], [])
                if current.finished
                else queue_closures(
                    store, current, store.attempts(task.id), CLOSED,
                    now=now, decider=decider, reason=args.reason, sender=sender, sender_class=sender_class,
                )
            )
            store.update_task(
                task.id, now=now, event="closed", closed_at=now, close_reason=args.reason or "closed"
            )
        print(f"任务 {short(task.id)} 已停止追踪")
        if at_risk:
            print("注意：停止追踪不撤回已交接内容；可显式尝试移除仍在 Codex 队列中的项（withdraw），已开始的工作不能撤销")
        _print_closure(outcome)
    return EXIT_OK


def cmd_withdraw(args: argparse.Namespace) -> int:
    found = _fed_lookup(args, write=False)
    if found is not None:
        found[0].close()
        # 写前退出：跨设备任务不触碰任何原生删除（§88.7）
        raise CliError("federation_withdraw_unsupported", EXIT_NOT_ENABLED)
    caller = identify_caller(discover())
    _check_sender(caller)
    now = time.time()
    info = procfs.read_process(os.getpid())
    if info is None:
        raise CliError("withdraw_owner_unknown", EXIT_UNAVAILABLE)
    home, sqlite_home = codex_home(), codex_sqlite_home()
    backend = local_codex.platform()
    if not backend.supported:
        raise CliError("withdraw_platform_unsupported", EXIT_UNAVAILABLE)
    root_identity = backend.root_identity(home, sqlite_home)
    if root_identity is None:
        raise CliError("withdraw_root_missing", EXIT_UNAVAILABLE)
    with _open_store() as store:
        store.recover_withdrawals(now=now)
        with store.transaction():
            task = _task(store, args.task)
            if not _may_decide(caller, task):
                raise CliError("withdraw_not_allowed")
            operation, created = store.prepare_withdrawal(task.id, args.attempt, root_identity=root_identity,
                now=now, pid=info.pid, start=info.start_ticks, again=args.again)
        if created:
            client = QueueDeleteClient(lambda timeout: cli_version(timeout=timeout))
            outcome = client.delete(home, thread=operation["thread_id"], item=operation["item_id"],
                root_identity=root_identity, sqlite_home=sqlite_home,
                before_send=lambda budget: store.begin_withdrawal(operation["id"], now=time.time(), pid=info.pid,
                                                                  start=info.start_ticks, budget=budget))
            try:
                store.finish_withdrawal(operation["id"], thread=operation["thread_id"], item=operation["item_id"],
                    state=outcome.state, reason=outcome.reason, version=outcome.server_version, now=time.time())
            except StoreError as error:
                try:
                    recorded = next((item for item in store.withdrawals(task.id) if item["id"] == operation["id"]), None)
                except Exception:
                    recorded = None
                actual = {"state": outcome.state, "reason": outcome.reason, "serverVersion": outcome.server_version}
                if args.json:
                    _print_json({"version": 1, "taskId": task.id, "ok": False, "code": error.code,
                                 "reasonText": reason_text(error.code), "operation": recorded,
                                 "actualResult": actual, "execution": "not_proven_unexecuted"})
                else:
                    print(f"撤回结果落账失败：{reason_text(error.code)}（{error.code}）；"
                          f"本次实际结果 {outcome.state}（{outcome.reason}），账本未覆盖；不证明未执行")
                return EXIT_STORE
        current = next(item for item in store.withdrawals(operation["task_id"]) if item["id"] == operation["id"])
        if args.json:
            _print_json({"version": 1, "taskId": task.id, "operation": current,
                         "execution": "not_proven_unexecuted"})
        else:
            print(f"任务 {short(task.id)} #{args.attempt} 撤回：{current['state']}（{current['reason']}）")
            print("仅描述原生队列项；不证明从未执行，不能停止已开始的工作；原投递与重发规则不变")
        if current["reason"] in {"boundary_store_busy", "boundary_record_failed"}:
            return EXIT_STORE
        return {"deleted": EXIT_OK, "absent": EXIT_OK, "refused": EXIT_REJECTED,
                "unknown": EXIT_UNKNOWN}.get(current["state"], EXIT_UNAVAILABLE)


def _rework_body(first: Attempt, current: Attempt, task: Task, extra: str | None) -> str:
    lines = ["【返工】"]
    if current.role is Role.REVIEW and task.verdict is Verdict.CHANGES:
        lines.append(f"复核方 {current.target.display()} 要求修改。")
    elif current.work is Work.BLOCKED:
        lines.append("上次处理受阻，情况已处理，请继续。")
    elif current.work is Work.FAILED:
        lines.append("上次未能完成，请按下面的要求重新处理。")
    else:
        lines.append("请按下面的意见继续修改。")
    result = current.result or {}
    note = result.get("note") if isinstance(result, dict) else None
    if isinstance(note, str) and note:
        lines.append(f"意见：{note}")
    for line in _describe_result(result if isinstance(result, dict) else None):
        if not line.startswith("说明："):
            lines.append(line)
    if extra:
        lines.append(f"补充：{extra}")
    lines.extend(["", "【原始任务要求】", first.body.rstrip()])
    text = "\n".join(lines)
    encoded = text.encode("utf-8")
    if len(encoded) > MAX_BODY_BYTES:
        text = encoded[: MAX_BODY_BYTES - 64].decode("utf-8", errors="ignore") + "\n…（已截断）"
    return text


def cmd_retry(args: argparse.Namespace) -> int:
    found = _fed_lookup(args, write=True)
    if found is not None:
        return _fed_retry(args, *found)
    if args.device:
        raise CliError("target_is_local_device", EXIT_TARGET)
    endpoints = discover()
    caller = identify_caller(endpoints)
    now = time.time()
    with _open_store() as store:
        # 校验、作废过时回执、追加返工尝试必须在同一个事务里（Codex 复审 F01）。分成多次提交时，
        # 提交间隙里另一连接可能已经汇报出新一轮结果、或并发 close 排了结束回执，随后的全量扫描
        # 会把它们一起作废；追加成功而作废失败还会留下「返工已落账却返回错误」的半完成命令。
        # 端点发现在事务外做，事务内重做全部校验——世界变了就照常抛原来那些错误。
        try:
            with store.transaction():
                attempt, undelivered, rework = _retry_in_transaction(store, args, endpoints, caller, now)
        except StoreError as error:
            raise CliError(error.code, _exit_for_store_error(error.code)) from error
        started = _start_worker()
        print(f"已排队第 {attempt.seq} 次{ROLE_LABELS[attempt.role]} → {endpoint_text(attempt.target)}（任务 {short(attempt.task_id)}）")
        if attempt.seq >= ATTEMPT_WARNING_THRESHOLD:
            print(f"提示：{reason_text('attempts_near_limit')}")
        if args.force and not undelivered and not rework:
            print("注意：上一条消息可能已送达，对方可能重复执行")
    return EXIT_UNAVAILABLE if _queued_without_worker(started) else EXIT_OK


def _retry_in_transaction(
    store: Store, args: argparse.Namespace, endpoints: list[Endpoint], caller: Caller, now: float
) -> tuple[Attempt, bool, bool]:
    """在调用方开启的事务内完成返工：重新校验 → 作废过时回执 → 追加新尝试 → 更新任务。"""
    task = _task(store, args.task)
    if task.finished:
        raise CliError("task_finished")
    if not _may_decide(caller, task):
        raise CliError("accept_not_allowed")
    attempts = work_attempts(store.attempts(task.id))
    if not attempts:
        raise CliError("attempt_not_found")
    first = attempts[0]
    current = attempts[-1]
    if current.delivery is Delivery.PENDING:
        raise CliError("still_pending")
    undelivered = current.delivery in PROVEN_UNDELIVERED
    rework = current.work in (Work.BLOCKED, Work.FAILED) or (
        current.role is Role.REVIEW and task.verdict is Verdict.CHANGES
    ) or (current.work is Work.RESULT and current.role is Role.HANDOFF)
    if not (undelivered or rework or args.force):
        raise CliError("retry_requires_force")
    role = current.role
    target_ref = current.target
    if undelivered and not rework:
        body = current.body
        if args.message:
            body = f"{body}\n\n补充：{args.message}"
    else:
        if current.role is Role.REVIEW and task.verdict is Verdict.CHANGES:
            role = Role.HANDOFF
            implementer = next((item for item in reversed(attempts) if item.role is Role.HANDOFF), first)
            target_ref = implementer.target
        body = _rework_body(first, current, task, args.message)
    allow_shared = bool(args.allow_shared or current.allow_shared)
    if args.to:
        target = _resolve(args.to, endpoints)
        _check_target(target, allow_shared=allow_shared)
        target_ref = target.ref
    else:
        live, problem = select_generation(target_ref, endpoints)
        if problem is not None:
            raise CliError(f"target_{problem}")
        if live is not None:
            _check_target(live, allow_shared=allow_shared)
            target_ref = live.ref
        elif get_platform().name == 'windows':
            raise CliError('target_not_found', EXIT_TARGET)
    # 先作废再追加：全局尝试槽有上限，别让即将作废的回执占着位置（Codex 复审 F01）。
    # 返工意味着「这个结果不作数」，还没发出的通知随之作废；已经发出去的不追，那是对方已经看到的事实。
    # **不再额外排除结束回执**：结束回执只在 accept/close 的事务里与 accepted_at/closed_at 同写，
    # 而本函数开头的 `task.finished` 检查就在同一个事务内重做过——有结束回执就意味着任务已结束，
    # 那一步已经抛 `task_finished` 了。再加一条 `not is_closure` 只会是永远走不到的死代码
    # （Fable 复审的变异佐证：加上它 96 条用例全绿）。Codex 复审 F01 的并发反例正是由「分多次提交」
    # 造成的，事务边界一合并就不成立。
    for stale in store.attempts(task.id):
        if stale.role is Role.NOTICE and stale.delivery is Delivery.PENDING:
            store.transition_delivery(
                stale.id, expected=(Delivery.PENDING,), new=Delivery.CANCELLED,
                reason="notice_outdated", now=now,
            )
    attempt = store.add_attempt(
        task.id,
        role=role,
        target=target_ref,
        body=body,
        refs=first.refs if role is Role.HANDOFF else current.refs,
        now=now,
        sender=first.sender,
        sender_class=first.sender_class,
        options={"allowShared": allow_shared},
    )
    fields: dict[str, object] = {"control": "active"}
    if task.verdict is not None:
        fields["verdict"] = None
    store.update_task(task.id, now=now, event="retry", **fields)
    return attempt, undelivered, rework


def cmd_worker(args: argparse.Namespace) -> int:
    try:
        return run_worker(once=args.once)
    except OSError as error:
        if get_platform().name != 'windows':
            raise
        raise CliError('worker_identity_unverified', EXIT_STORE) from error


def cmd_doctor(args: argparse.Namespace) -> int:
    checks = collect_checks()
    if args.json:
        _print_json(checks)
        return EXIT_OK
    if get_platform().name == 'windows':
        for key, value in checks.items():
            print(f'{key}: {value}')
    else:
        print_checks(checks)
    return EXIT_OK


def _refresh_summary(*, force: bool = False, revive: bool = False) -> summary.PublishResult | None:
    """账本存在时发布摘要（默认 if-stale）；失败不改变命令结果，交给 worker 补写（DESIGN §45.14）。

    revive：命令结束后若还有待办（含未到期的发起方提醒）而 worker 不在（崩溃、重启），顺手拉起（DESIGN §45.28.3）。
    """
    try:
        root = state_dir()
        if get_platform().name == 'windows':
            get_platform().files.ensure_private_dir(root)
        if not (root / DB_NAME).is_file():
            if revive:
                _revive_for_federation()  # 只承接跨设备任务的设备可以没有本机库：联邦待办照样补拉（Codex r3-P2-02）
            return None  # 没用过协作桥的机器不创建账本
        with Store.open(root) as store:
            try:
                return summary.publish(store, root, force=force)
            finally:
                if revive and not _worker_ensured:
                    _revive_worker(store, time.time())
    except Exception:  # 摘要是可重建投影：任何失败都不能阻止命令或覆盖已提交的结果（3A-F02）
        if revive and not _worker_ensured:  # 异常也不能替 withdraw/manual summary 拉 worker
            _start_worker()
        return None


def _revive_from_summary(store: Store) -> None:
    """扩展定时 `summary --if-stale` 后按需恢复 worker（DESIGN §45.30）：只试一次，任何错误都吞掉。

    这是辅助动作：不能改变摘要输出与退出码，出错也不像其他命令那样兜底再拉一次。
    worker 由 gnome-shell 环境拉起时，worker_environment 会给 PATH 补上 ~/.local/bin，保证找得到 codex。
    """
    if get_platform().name == 'windows':
        return
    try:
        _revive_worker(store, time.time())
    except Exception:  # needs_worker 读账本也可能抛 sqlite3.Error 等 _revive_worker 不接的异常
        pass


def cmd_summary(args: argparse.Namespace) -> int:
    # 只有 --if-stale（扩展的定时与打开菜单补查）在发布后按需拉起 worker：普通 summary 与只带 --refresh 的手动重建不拉起。
    # 早先因 gnome-shell 的 PATH 找不到 codex 而完全不拉起（§45.28.3 实现修订），现由 worker 环境补 PATH 解决（§45.30）
    if get_platform().name == 'windows':
        try:
            root = state_dir()
            get_platform().files.ensure_private_dir(root)
        except OSError as error:
            raise CliError('store_unavailable', EXIT_STORE) from error
    else:
        root = state_dir()
    ledger = (root / DB_NAME).is_file()
    published: summary.PublishResult | None = None
    if args.refresh or args.if_stale:
        if not ledger:
            if args.if_stale and get_platform().name != 'windows':
                _revive_for_federation()  # 扩展定时补查在只有联邦库的设备上也续上跨设备作业；退出码不变
            raise CliError("ledger_absent", EXIT_UNAVAILABLE)
        with _open_store() as store:
            try:
                published = summary.publish(store, root, force=not args.if_stale)
            except summary.SummaryError as error:
                raise CliError(error.code, EXIT_STORE) from error
            finally:
                # 摘要重写、未变化或写入失败都照样补查：新 worker 启动时会强制重建摘要
                if args.if_stale:
                    _revive_from_summary(store)
    if ledger:
        with _open_store() as store:
            state = summary.status(root, store)
    else:
        state = summary.status(root, None)
    if published is not None:
        state["published"] = published.status
    if args.json:
        _print_json(state)
        return EXIT_OK
    print(f"协作摘要：{summary.STATE_LABELS.get(state['state'], state['state'])}")
    if "revision" in state:
        print(f"摘要修订号：{state['revision']}（账本 {state.get('ledgerRevision', '-')}）")
    if published is not None:
        print("已重建" if published.status == "written" else "摘要已是最新，未重写")
    return EXIT_OK


# ---- 跨设备（DESIGN §88）：显式 --device/--origin-device，或本机找不到时的唯一联邦命中 ----


def _local_task_exists(root: Path, reference: str) -> bool:
    """本机账本能否解析该任务；找不到才轮到联邦。歧义或账本错误一律交本机路径原样报错（§88.7 命名空间）。"""
    if not (root / DB_NAME).is_file():
        return False
    try:
        with Store.open(root) as store:
            store.resolve_task(reference)
    except StoreError as error:
        return error.code != "task_not_found"
    except PermissionError:
        return True
    return True


def _fed_configured(root: Path) -> bool:
    """只看配置文件在不在（与摘要同一个文件名）：未配置的机器在这一步就返回，不导入联邦实现（实现决定 D20）。"""
    return (root / summary.FEDERATION_CONFIG).exists()


def _fed_lookup(args: argparse.Namespace, *, write: bool) -> tuple[FedRuntime, FedTask] | None:
    """显式 --origin-device 只查联邦；否则本机精确任务优先，本机找不到才查联邦唯一索引。

    联邦库损坏/停用不能让已命中的本机任务失败；写命令要求联邦已启用（停用后仍可读历史）。
    """
    root = state_dir()
    origin = getattr(args, "origin_device", None)
    if origin is None and not _fed_configured(root):
        return None
    from .federation import commands as fed  # layout: allow 联邦按需加载：未配置的机器不导入联邦实现
    if origin is None:
        if _local_task_exists(root, args.task):
            return None
        rt = fed.try_runtime(root)
        if rt is None:
            return None
        try:
            task = fed.find_task(rt, args.task, None)
        except FedCliError as error:
            rt.close()
            if error.code == "task_ambiguous":
                raise
            return None
    else:
        rt = fed.open_runtime(root, require_enabled=False)
        try:
            task = fed.find_task(rt, args.task, origin)
        except BaseException:
            rt.close()
            raise
    if write and not rt.config.enabled:
        rt.close()
        raise FedCliError("federation_disabled", EXIT_NOT_ENABLED)
    return rt, task


def _fed_relay_missing(rt: FedRuntime) -> bool:
    """已记入联邦账本；relay 未运行时说明并返回 True（命令返回 6，勿重复执行）。"""
    from .federation import commands as fed  # layout: allow 联邦按需加载
    try:
        if fed.relay_running(rt.root):
            return False
    except OSError:
        pass
    print(f"注意：{reason_text('relay_not_running')}。上面的操作已记入本机联邦账本，请勿重复执行；"
          f"relay 启动后自动发出（{command_name()} federation status 查看）", file=sys.stderr)
    return True


def _fed_target_text(rt: FedRuntime, target: object) -> str:
    from .federation import commands as fed  # layout: allow 联邦按需加载
    from .federation.refs import TargetRef  # layout: allow 联邦按需加载
    assert isinstance(target, TargetRef)
    remote = target.remote
    label = remote.display_label or remote.native_id[:8]
    return f"{fed.device_name(rt, remote.device_id)} 上的 {remote.provider.value}@{label}〔{remote.native_id[:8]}〕"


def _fed_peers(args: argparse.Namespace) -> int:
    from .federation import commands as fed  # layout: allow 联邦按需加载
    from .federation import directory as fed_directory  # layout: allow 联邦按需加载
    rt = fed.open_runtime(state_dir(), require_enabled=False)
    try:
        now_ms = int(time.time() * 1000)
        reference = None if args.all_devices else args.device
        try:
            if args.json:
                _print_json({"devices": fed_directory.peer_devices(rt.store, reference, now=now_ms)})
                return EXIT_OK
            lines = fed_directory.peer_lines(rt.store, reference, now=now_ms)
        except fed_directory.DirectoryError as error:
            raise CliError(error.code, EXIT_TARGET) from error
        if not lines:
            print("还没有其他设备的目录（relay 连上 hub 后自动同步）")
        for line in lines:
            print(line)
    finally:
        rt.close()
    return EXIT_OK


def _fed_send(args: argparse.Namespace) -> int:
    """跨设备 send：A 上 L0 记账即返回；目标在 B 的缓存目录解析，复核方缺省在本机。"""
    from .federation import commands as fed  # layout: allow 联邦按需加载
    body = _read_body(args)
    endpoints = discover()
    caller = identify_caller(endpoints)
    _check_sender(caller)
    rt = fed.open_runtime(state_dir())
    try:
        target_local = not args.device or fed.is_local_device(rt, args.device)
        reviewer_local = not args.review_device or fed.is_local_device(rt, args.review_device)
        if target_local and reviewer_local and args.review_device and not args.review_by:
            raise CliError("review_device_requires_reviewer")
    except BaseException:
        rt.close()
        raise
    if target_local and reviewer_local:
        rt.close()
        args.device = args.review_device = None
        return _local_send(args, body=body)  # 两个参与方都在本机：就是本机任务（正文已读，不重读 stdin）
    try:
        if target_local:
            # 本机执行 + 远端复核（T16）：目标按本机资格核验
            live = _resolve(args.to, endpoints)
            _check_target(live, allow_shared=bool(args.allow_shared))
            if caller.endpoint is not None and caller.endpoint.ref.same_session(live.ref):
                raise CliError("target_is_self")
            target = fed.local_target(rt, live)
        else:
            target = fed.remote_target(rt, args.device, args.to)
        reviewer = None
        if args.review_by:
            if fed.is_local_device(rt, args.review_device):
                live = _resolve(args.review_by, endpoints)
                _check_target(live, allow_shared=bool(args.allow_shared))
                reviewer = fed.local_target(rt, live)
            else:
                reviewer = fed.remote_target(rt, args.review_device, args.review_by)
        elif args.review_device:
            raise CliError("review_device_requires_reviewer")
        first_line = body.strip().splitlines()[0] if body.strip() else ""
        outcome = fed.send(
            rt, target=target, body=body, title=(args.title or first_line)[:60], ref_paths=list(args.ref),
            cwd=Path.cwd(), origin=caller.endpoint.ref if caller.endpoint is not None else None,
            origin_class=permission_class(caller), reviewer=reviewer, allow_shared=bool(args.allow_shared),
            no_notify=bool(args.no_notify))
        missing = _fed_relay_missing(rt)
        task_id = outcome.task.task_id
        if args.json:
            _print_json(fed.task_document(rt, outcome.task, now=int(time.time() * 1000)))
        else:
            print(f"跨设备任务 {short(task_id)} 已记录，交给 {_fed_target_text(rt, outcome.target)}：等待 relay 发出")
            if outcome.blobs or outcome.references:
                print(f"附件：{outcome.blobs} 个随消息传输（{outcome.blob_bytes} B），"
                      f"{outcome.references} 个超出大小上限只作引用（对方没有这些文件）")
            cmd = command_name()
            print(f"查看进展：{cmd} status {short(task_id)}；等待结果：{cmd} wait {short(task_id)}")
    finally:
        rt.close()
    return EXIT_UNAVAILABLE if missing else EXIT_OK


def _fed_task_list(include_finished: bool, now: float) -> tuple[list[dict[str, object]], list[str]] | None:
    """tasks 的联邦部分：未配置返回 None（输出不变）；库不可读只注明，不影响本机行。"""
    root = state_dir()
    if not _fed_configured(root):
        return None
    from .federation import commands as fed  # layout: allow 联邦按需加载
    rt = fed.try_runtime(root)
    if rt is None:
        return [], [f"跨设备任务：联邦库不可读（本机任务不受影响；{command_name()} doctor 查看原因）"]
    try:
        now_ms = int(now * 1000)
        documents: list[dict[str, object]] = []
        lines: list[str] = []
        for task in fed.list_tasks(rt, include_finished=include_finished):
            document = fed.task_document(rt, task, now=now_ms)
            documents.append(document)
            view = fed.view_of(rt, task)
            target = "-"
            if view.current is not None:
                row = next((item for item in document["attempts"] if item["seq"] == view.current.seq), None)
                where = f"{row['targetDeviceName']}:" if row is not None else ""
                target = where + endpoint_text(view.current.target)
            role = "本机发起" if task.is_authority else f"发起设备 {document['authorityDeviceName']}"
            flag = "，需处理：远端离线/传输未恢复" if document["stalled"] else ""
            lines.append(f"{short(task.task_id)}  {PHASE_LABELS[view.phase]:<4} {target:<28} {task.title[:40]}"
                         f"  （跨设备·{role}，{reason_text(view.reason)}{flag}，{_age(task.last_sync_at / 1000, now)}）")
        return documents, lines
    finally:
        rt.close()


def _fed_status(args: argparse.Namespace, rt: FedRuntime, task: FedTask) -> int:
    from .federation import commands as fed  # layout: allow 联邦按需加载
    try:
        now_ms = int(time.time() * 1000)
        if args.json:
            _print_json(fed.task_document(rt, task, now=now_ms, include_body=args.body))
        else:
            for line in fed.task_lines(rt, task, now=now_ms, show_body=args.body):
                print(line)
    finally:
        rt.close()
    return EXIT_OK


def _fed_report(args: argparse.Namespace, kind: ReportKind, rt: FedRuntime, task: FedTask) -> int:
    """目标设备上的跨设备汇报：B 上记账后等 A 裁决；A 本机参与方同事务裁决。"""
    from .federation import commands as fed  # layout: allow 联邦按需加载
    try:
        endpoints = discover()
        caller = identify_caller(endpoints)
        attempt, result = fed.report(
            rt, task=task, kind=kind, attempt_seq=args.attempt, note=args.note, files=list(args.file),
            commit=args.commit, manual=args.manual, caller=caller, caller_class=permission_class(caller),
            cwd=Path.cwd())
        started: bool | None = True
        if result.decision == "accepted":
            started = _start_worker()  # A 本机采纳可能排出本机通知/复核
        missing = _fed_relay_missing(rt)
        if result.decision is None:
            status = "已提交，等待发起设备确认"
        elif result.decision == "accepted":
            status = "发起设备已采纳"
        else:
            status = f"未采纳：{reason_text(result.reason or result.decision)}"
        if args.json:
            document = fed.task_document(rt, rt.store.get_task(task.authority_device, task.task_id) or task,
                                         now=int(time.time() * 1000))
            document["report"] = {"reportNo": result.report_no, "operationId": result.operation_id,
                                  "decision": result.decision, "reason": result.reason}
            _print_json(document)
        else:
            print(f"已记录：{EVENT_LABELS[kind.value]}（跨设备任务 {short(task.task_id)} #{attempt.seq}，"
                  f"第 {result.report_no} 号报告）；{status}")
    finally:
        rt.close()
    if result.decision == "rejected":
        return EXIT_REJECTED
    if _queued_without_worker(started) or missing:
        return EXIT_UNAVAILABLE
    return EXIT_OK


def _fed_wait(args: argparse.Namespace, rt: FedRuntime, task: FedTask) -> int:
    from .federation import commands as fed  # layout: allow 联邦按需加载
    deadline = time.monotonic() + args.timeout
    try:
        while True:
            current = rt.store.get_task(task.authority_device, task.task_id) or task
            view = fed.view_of(rt, current)
            reached = _wait_outcome(view, args.until)
            if reached is not None:
                now_ms = int(time.time() * 1000)
                if args.json:
                    _print_json(fed.task_document(rt, current, now=now_ms))
                else:
                    for line in fed.task_lines(rt, current, now=now_ms):
                        print(line)
                return reached
            if time.monotonic() >= deadline:
                if not args.json:
                    print(f"等待超时：{PHASE_LABELS[view.phase]}（{reason_text(view.reason)}）")
                return EXIT_TIMEOUT
            time.sleep(1.0)
    finally:
        rt.close()


def _fed_control(args: argparse.Namespace, action: str, rt: FedRuntime, task: FedTask) -> int:
    """pause/resume/cancel：只在发起设备；cancel 对远端只是抑制请求，不是原生撤回。"""
    from .federation import commands as fed  # layout: allow 联邦按需加载
    try:
        caller = identify_caller(discover())
        _, remote_pending = fed.set_control(rt, task, action, caller=caller)
        text = {"pause": "已暂停发送；已交给对方的消息不受影响", "resume": "继续发送",
                "cancel": "已请求取消尚未发出的消息"}[action]
        print(f"跨设备任务 {short(task.task_id)} {text}")
        if remote_pending:
            print("对方设备尚未确认：它收到最新状态后抑制还没发出的作业；已发出的不能撤回")
        if action == "resume":
            _start_worker()
        missing = _fed_relay_missing(rt)
    finally:
        rt.close()
    return EXIT_UNAVAILABLE if missing else EXIT_OK


def _fed_finish(args: argparse.Namespace, state: str, rt: FedRuntime, task: FedTask) -> int:
    """accept/close：发起设备本机写终态与结束回执；对方离线不阻塞决定。"""
    from .federation import commands as fed  # layout: allow 联邦按需加载
    try:
        caller = identify_caller(discover())
        outcome = fed.finish(rt, task, state, caller=caller, caller_class=permission_class(caller),
                             reason=getattr(args, "reason", None), force=bool(getattr(args, "force", False)))
        if any(item.target_device == rt.ident.device_id for item in outcome.closures):
            _start_worker()
        missing = _fed_relay_missing(rt)
        if getattr(args, "json", False):
            _print_json({"ok": True, "id": task.task_id, "scope": "federation",
                         "phase": fed.phase_of(rt, outcome.task)[0].value,
                         "closure": {"queued": [{"seq": item.seq, "targetDevice": item.target_device}
                                                for item in outcome.closures],
                                     "skipped": list(outcome.skipped),
                                     "remoteUnconfirmed": outcome.remote_unconfirmed}})
        else:
            print(f"跨设备任务 {short(task.task_id)} " + ("已验收" if state == ACCEPTED else "已停止追踪"))
            for closure in outcome.closures:
                print(f"已排队结束回执 → {_fed_target_text(rt, closure.target)}")
            for capacity in outcome.skipped:
                print(f"提示：容量已满（{capacity}），未排结束回执")
            if outcome.remote_unconfirmed:
                print("注意：对方设备尚未证明工作消息是否送达；结束回执由对方按实际情况投递或抑制，已交出的工作不能撤回")
    finally:
        rt.close()
    return EXIT_UNAVAILABLE if missing else EXIT_OK


def _fed_retry(args: argparse.Namespace, rt: FedRuntime, task: FedTask) -> int:
    """重发/返工：发起设备上追加新尝试；改派可指向本机会话或 --device 指定设备上的会话。"""
    from .federation import commands as fed  # layout: allow 联邦按需加载
    try:
        endpoints = discover()
        caller = identify_caller(endpoints)
        new_target = None
        if args.to:
            if not fed.is_local_device(rt, args.device):
                new_target = fed.remote_target(rt, args.device, args.to)
            else:
                live = _resolve(args.to, endpoints)
                _check_target(live, allow_shared=bool(args.allow_shared))
                new_target = fed.local_target(rt, live)
        elif args.device:
            raise CliError("target_explicit_required")
        outcome = fed.retry(rt, task, caller=caller, message=args.message, force=bool(args.force),
                            new_target=new_target, allow_shared=bool(args.allow_shared), rework_body=_rework_body)
        attempt = outcome.attempt
        local = attempt.target_device == rt.ident.device_id
        started = _start_worker() if local else True
        missing = False if local else _fed_relay_missing(rt)
        print(f"已排队第 {attempt.seq} 次{ROLE_LABELS[Role(attempt.role)]} → {_fed_target_text(rt, attempt.target)}"
              f"（跨设备任务 {short(task.task_id)}）")
        if attempt.seq >= ATTEMPT_WARNING_THRESHOLD:
            print(f"提示：{reason_text('attempts_near_limit')}")
        if args.force and not outcome.undelivered and not outcome.rework:
            print("注意：上一条消息可能已送达，对方可能重复执行")
    finally:
        rt.close()
    if _queued_without_worker(started) or missing:
        return EXIT_UNAVAILABLE
    return EXIT_OK


def cmd_federation(args: argparse.Namespace) -> int:
    """`federation enable/disable/status/relay/archive`：本机跨设备协作的启停、诊断与 relay 入口。"""
    from .federation import commands as fed  # layout: allow 联邦按需加载
    from .federation.codec import is_slug  # layout: allow 联邦按需加载
    root = state_dir()
    action = args.federation_action
    if action == "enable":
        name = args.name or device_name()
        if not is_slug(name):
            raise CliError("federation_device_name_invalid")
        config, created = fed.enable(
            root, hub_host=args.hub_host, hub_user=args.hub_user, hub_port=args.hub_port, hub_id=args.hub_id,
            device_id=args.device_id, name=name, identity_file=args.identity_file,
            known_hosts_file=args.known_hosts_file, ssh_executable=args.ssh_executable)
        print(f"跨设备协作已启用：本机登记为 {config.device_name}（{'新建联邦库' if created else '沿用既有联邦库'}）")
        print(f"relay 需要以服务方式运行：{command_name()} federation relay（Linux 用 systemd 用户服务、Windows 用登录计划任务，见 docs/federation-deployment.md §3）")
        return EXIT_OK
    if action == "disable":
        fed.disable(root)
        print("跨设备协作已停用：relay 会在一秒内退出，worker 不再领取跨设备作业；数据与附件保留，本机协作照常")
        return EXIT_OK
    if action == "status":
        projection = fed.doctor_projection(root)
        if args.json:
            _print_json({"federation": projection})
            return EXIT_OK
        if projection is None:
            print(reason_text("federation_not_configured"))
            return EXIT_OK
        print(federation_text(projection))
        return EXIT_OK
    if action == "rebuild":
        outcome = fed.rebuild(root, hub_id=args.hub_id, device_id=args.device_id)
        if outcome["newDevice"]:
            print("已按新设备身份重建本机联邦库（旧配置已改名留档）；旧任务不迁移")
        else:
            print(f"已切换到新 hub：旧 hub 上未结的 {outcome['frozenOutbox']} 条发件已冻结，旧任务的未投作业不再领取；"
                  "旧任务可在发起设备本机 close，确认对方没收到后再 send 新任务")
        return EXIT_OK
    if action == "relay":
        state = fed.run_relay(root, once=args.once)
        if state in ("connected", "stopped", "already_running"):
            return EXIT_OK
        _report_error(args, state)
        return EXIT_STORE if state in fed.STOP_STATES else EXIT_UNAVAILABLE
    found = _fed_lookup(args, write=False)
    if found is None:
        raise CliError("task_not_found", EXIT_TARGET)
    rt, task = found
    try:
        count = fed.archive(rt, task)
    finally:
        rt.close()
    print(f"已在本机归档跨设备任务 {short(task.task_id)} 的镜像（抑制 {count} 条未发出的作业）；不改变发起设备上的任务")
    return EXIT_OK


def _report_error(args: argparse.Namespace, code: str) -> None:
    message = reason_text(code)
    if code == 'caller_unattributed' and get_platform().name == 'windows':
        message += '；Windows 仅支持已认出的 Codex/Claude 会话发起；终端手动发起不提供资格，--manual 不能绕过'
    print(f"{command_name()}: {message} [{code}]", file=sys.stderr)
    if getattr(args, "json_errors", False) and getattr(args, "json", False):
        _print_json({"ok": False, "code": code, "reasonText": message})


def build_parser(*, include_alias: bool = False) -> argparse.ArgumentParser:
    prog = command_name()
    parser = argparse.ArgumentParser(prog=prog, description="AgentStatus 协作桥：在本机 agent 会话之间交接任务")
    parser.add_argument("--version", action="version", version=f"{prog} {__version__}")
    commands = parser.add_subparsers(dest="command", required=True)

    peers = commands.add_parser("peers", help="列出可交接的会话")
    peers.add_argument("--device", help="查看另一台设备的缓存目录（跨设备）")
    peers.add_argument("--all-devices", action="store_true", help="分设备列出本机与其他设备的会话")
    peers.add_argument("--json", action="store_true")
    peers.set_defaults(handler=cmd_peers)

    send = commands.add_parser("send", help="把任务交给另一个会话")
    send.add_argument("--to", required=True, help="目标：codex@会话名 / claude@会话名、pane（%%3）或会话 ID")
    send.add_argument("-m", "--message", help="任务内容；- 表示从标准输入读取")
    send.add_argument("--file", help="从文件读取任务内容")
    send.add_argument("--title", help="任务标题（默认取内容第一行）")
    send.add_argument("--ref", action="append", default=[], help="附带引用文件（记录 sha256）")
    send.add_argument("--review-by", help="完成后自动交给该会话复核")
    send.add_argument("--device", help="目标所在的设备（登记名或完整设备 ID）；不给则是本机会话")
    send.add_argument("--review-device", help="复核方所在设备（缺省本机；只能是本机或目标设备）")
    send.add_argument("--allow-shared", action="store_true", help="允许投递到被多个进程加载的 thread")
    send.add_argument("--no-wait", action="store_true", help="不等待首次投递结果")
    send.add_argument("--no-notify", action="store_true", help="对方交结果后不回推通知发起会话")
    send.add_argument("--json", action="store_true")
    send.set_defaults(handler=cmd_send)

    tasks = commands.add_parser("tasks", help="列出协作任务")
    tasks.add_argument("--all", action="store_true", help="包含已结束的任务")
    tasks.add_argument("--json", action="store_true")
    tasks.set_defaults(handler=cmd_tasks)

    status = commands.add_parser("status", help="查看任务详情")
    status.add_argument("task")
    status.add_argument("--origin-device", help="跨设备任务的发起设备（登记名或完整设备 ID）")
    status.add_argument("--body", action="store_true", help="显示任务正文")
    status.add_argument("--json", action="store_true")
    status.set_defaults(handler=cmd_status)

    report = commands.add_parser(
        "report",
        help="汇报自己承接的任务",
        description=(
            "汇报自己承接的任务。--result/--blocked/--failed/--approve/--changes 会给发起方发结果回执（会叫醒对方；发起时加了 --no-notify 的除外）；"
            "--ack/--progress 只记进账本，不通知、不叫醒发起方。需要发起方或用户处理时用 --blocked。"
        ),
    )
    report.add_argument("task")
    report.add_argument("--origin-device", help="跨设备任务的发起设备（消息页脚里已给出）")
    report.add_argument("--attempt", type=int)
    kinds = report.add_mutually_exclusive_group(required=True)
    kinds.add_argument("--ack", action="store_true", help="开始处理（只记账，不通知发起方）")
    kinds.add_argument("--progress", action="store_true", help="进展（只记账，不通知发起方；需要对方处理请用 --blocked）")
    kinds.add_argument("--result", action="store_true", help="完成并提交结果（通知发起方；复核流程先交给复核方）")
    kinds.add_argument("--blocked", action="store_true", help="受阻，需要发起方或用户处理（通知发起方）")
    kinds.add_argument("--failed", action="store_true", help="无法完成（通知发起方）")
    kinds.add_argument("--approve", action="store_true", help="复核通过（通知发起方）")
    kinds.add_argument("--changes", action="store_true", help="复核要求修改（通知发起方）")
    report.add_argument("--note", help="一句话说明")
    report.add_argument("--file", action="append", default=[], help="结果文件（记录 sha256）")
    report.add_argument("--commit", help="结果提交")
    report.add_argument("--manual", action="store_true", help="用户在终端里代为补记")
    report.add_argument("--json", action="store_true")
    report.set_defaults(handler=cmd_report)

    wait = commands.add_parser("wait", help="等待任务到达某个阶段")
    wait.add_argument("task")
    wait.add_argument("--origin-device", help="跨设备任务的发起设备")
    wait.add_argument("--until", choices=("sent", "ack", "result"), default="result")
    wait.add_argument("--timeout", type=float, default=3600.0)
    wait.add_argument("--json", action="store_true")
    wait.set_defaults(handler=cmd_wait)

    for name, handler, text in (
        ("pause", cmd_pause, "暂停发送桥内排队的消息"),
        ("resume", cmd_resume, "继续发送"),
        ("cancel", cmd_cancel, "取消尚未发送的消息"),
    ):
        command = commands.add_parser(name, help=text)
        command.add_argument("task")
        command.add_argument("--origin-device", help="跨设备任务的发起设备")
        command.set_defaults(handler=handler)

    accept = commands.add_parser("accept", help="验收结果")
    accept.add_argument("task")
    accept.add_argument("--origin-device", help="跨设备任务的发起设备")
    accept.add_argument("--force", action="store_true", help="没有待验收结果时也标记验收")
    accept.add_argument("--json", action="store_true", help="成功与失败都输出结构化结果（供界面调用）")
    accept.set_defaults(handler=cmd_accept, json_errors=True)

    close = commands.add_parser("close", help="停止追踪任务")
    close.add_argument("task")
    close.add_argument("--origin-device", help="跨设备任务的发起设备")
    close.add_argument("--reason")
    close.set_defaults(handler=cmd_close)

    withdraw = commands.add_parser("withdraw", help="显式移除指定 Codex 原生队列项（不证明未执行）")
    withdraw.add_argument("task")
    withdraw.add_argument("--attempt", type=int, required=True, help="明确指定原投递尝试序号")
    withdraw.add_argument("--again", action="store_true", help="未知/未尝试/拒绝后另建一次显式操作，不自动重试")
    withdraw.add_argument("--json", action="store_true")
    withdraw.set_defaults(handler=cmd_withdraw, json_errors=True)

    retry = commands.add_parser("retry", help="重发未送达的消息，或把意见交回返工")
    retry.add_argument("task")
    retry.add_argument("--origin-device", help="跨设备任务的发起设备")
    retry.add_argument("--to", help="改派到其他会话")
    retry.add_argument("--device", help="改派目标所在设备（跨设备任务；与 --to 一起用）")
    retry.add_argument("-m", "--message", help="补充说明")
    retry.add_argument("--force", action="store_true", help="上一条可能已送达时仍重发")
    retry.add_argument("--allow-shared", action="store_true")
    retry.set_defaults(handler=cmd_retry)

    worker = commands.add_parser("worker", help=f"运行后台 worker（通常由 {prog} 自动拉起）")
    worker.add_argument("--once", action="store_true")
    worker.set_defaults(handler=cmd_worker)

    summary_parser = commands.add_parser("summary", help="查看或重建给 AgentStatus 界面用的协作摘要")
    summary_parser.add_argument("--refresh", action="store_true", help="重建摘要")
    summary_parser.add_argument("--if-stale", action="store_true", help="仅在摘要缺失、损坏或落后于账本时重建")
    summary_parser.add_argument("--json", action="store_true")
    summary_parser.set_defaults(handler=cmd_summary)

    federation = commands.add_parser("federation", help="跨设备协作：启用、停用、状态与 relay")
    federation_actions = federation.add_subparsers(dest="federation_action", required=True)
    enable = federation_actions.add_parser("enable", help="首次启用（建联邦库）或停用后重新启用")
    enable.add_argument("--hub-host", required=True, help="hub 主机名")
    enable.add_argument("--hub-user", required=True, help="hub 上的受限 relay 用户")
    enable.add_argument("--hub-port", type=int, default=22)
    enable.add_argument("--hub-id", required=True, help="hub init 打印的 hubId")
    enable.add_argument("--device-id", required=True, help="hub add-device 打印的 deviceId")
    enable.add_argument("--name", help="本机登记名（默认取设备名；须与 hub 登记一致）")
    enable.add_argument("--identity-file", required=True, help="relay 专用私钥路径（不复用管理 key）")
    enable.add_argument("--known-hosts-file", required=True, help="relay 专用 known_hosts 路径")
    enable.add_argument("--ssh-executable", default="ssh")
    federation_actions.add_parser("disable", help="停用（数据保留，本机协作照常）")
    fed_status = federation_actions.add_parser("status", help="relay 与联邦库状态（不连 hub、不读 key）")
    fed_status.add_argument("--json", action="store_true")
    relay = federation_actions.add_parser("relay", help="运行 relay（通常由用户服务/计划任务拉起）")
    relay.add_argument("--once", action="store_true", help="只连一次、跑一轮")
    rebuild = federation_actions.add_parser("rebuild", help="灾难换 hub：hub 换新 hubId 并重新登记本机后使用")
    rebuild.add_argument("--hub-id", required=True, help="新 hub 的 hubId")
    rebuild.add_argument("--device-id", help="本机联邦库丢失时 hub 新登记的 deviceId（库完整时保留原 ID，不用给）")
    archive = federation_actions.add_parser("archive", help="在本机归档跨设备任务的镜像")
    archive.add_argument("task")
    archive.add_argument("--origin-device", help="跨设备任务的发起设备")
    federation.set_defaults(handler=cmd_federation)

    doctor = commands.add_parser("doctor", help="检查协作桥运行环境")
    doctor.add_argument("--json", action="store_true")
    doctor.set_defaults(handler=cmd_doctor)
    try:
        include_alias = include_alias or get_platform().name == 'windows'
    except ValueError:
        pass  # main maps platform_unsupported, including help-free invocations
    if not include_alias:
        return parser  # Linux legacy help/errors remain byte-for-byte unchanged
    aliases = commands.add_parser('alias', help='Windows 本地目标别名（不开放投递）')
    actions = aliases.add_subparsers(dest='alias_action', required=True)
    for action in ('set', 'list', 'rm'):
        sub = actions.add_parser(action)
        if action != 'list':
            sub.add_argument('name')
        if action == 'set':
            sub.add_argument('target')
        sub.add_argument('--json', action='store_true')
        sub.set_defaults(json_errors=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    raw = list(sys.argv[1:] if argv is None else argv)
    if raw[:1] == ['hub']:
        # hub 管理与 forced command 入口：不碰本机账本、平台发现与 provider（§88.1）
        from .federation.hub_cli import main as hub_main  # layout: allow hub 只用标准库与联邦存储
        return hub_main(raw[1:])
    try:
        windows = get_platform().name == 'windows'
    except ValueError:
        windows = False
    if windows:
        from .platforms.windows.stdio import output_scope  # layout: allow Windows入口编码；Linux输出字节原样
        with output_scope():
            return _main(argv)
    return _main(argv)


def _main(argv: Sequence[str] | None = None) -> int:
    """命令入口；错误以固定原因码和可读说明输出到 stderr。"""
    global _worker_ensured
    _worker_ensured = False
    raw = list(sys.argv[1:] if argv is None else argv)
    args = build_parser(include_alias=bool(raw and raw[0] == 'alias')).parse_args(raw)
    try:
        platform = get_platform()
    except ValueError as error:
        if str(error) != 'platform_unsupported':
            raise
        _report_error(args, 'platform_unsupported')
        return EXIT_REJECTED
    with using_platform(platform):
        if platform.name == 'windows' and args.command != 'alias':
            from .platforms.windows.commands import scope  # layout: allow 命令级资格先于任何账本写入
            from .transports.codex_native import NativeFailure  # layout: allow 固定原因投影，不透传原始错误
            try:
                with scope(args):
                    return _run_command(args)
            except NativeFailure as error:
                _report_error(args, error.reason)
                if error.reason in {'target_ambiguous','target_changed','target_names_unverified','target_not_found',
                                    'discovery_incomplete','claude_discovery_incomplete','alias_target_unavailable'}:
                    print('目标未发送；请刷新 peers，可加 claude@ / codex@ 前缀明确指定 provider，或用已核实的完整 UUID 消歧。', file=sys.stderr)
                if error.reason == 'windows_provider_not_enabled':
                    return EXIT_NOT_ENABLED
                return EXIT_TARGET if error.reason.startswith(('target_', 'alias_')) else EXIT_REJECTED
        return _run_command(args)


def _run_command(args: argparse.Namespace) -> int:
    if args.command == 'alias':
        if get_platform().name != 'windows':
            _report_error(args, 'alias_platform_unsupported')
            return EXIT_REJECTED
        from .platforms.windows.alias_command import run, AliasError  # layout: allow Windows本地别名，不开账本
        try:
            return run(args)
        except AliasError as error:
            _report_error(args, error.code)
            return error.exit_code
    if get_platform().name == 'windows':
        # main's Windows scope has already checked capability and attribution.
        if args.command == 'peers' and not (args.device or args.all_devices):
            from .platforms.windows import codex_discovery  # layout: allow Windows只读候选，Linux路径与构造不加载
            from .platforms.windows.local_transport import WindowsPlatform  # layout: allow 已选择后端的窄能力
            backend = get_platform().transport
            result = codex_discovery.discover(backend) if isinstance(backend, WindowsPlatform) else codex_discovery.Discovery()
            from .platforms.windows.commands import claude_evidence  # layout: allow W3 read-only registry candidates
            peers = claude_evidence()
            if args.json:
                document = result.document()
                existing = document.get('peers')
                document['peers'] = (existing if isinstance(existing, list) else []) + peers.document()
                document['claudeDiscovery'] = {'complete': peers.complete, 'reason': peers.reason}
                _print_json(document)
            else:
                codex_discovery.print_peers(result)
                print('Windows Claude 原生 peer：' + ('发现完整' if peers.complete else reason_text(peers.reason)))
                for endpoint in (*peers.endpoints, *peers.duplicates):
                    # 原生名称只在 Endpoint.name 中；保留原 JSON 字符串转义，仅投影到本机文字。
                    label = json.dumps(endpoint.name, ensure_ascii=False)[1:-1] if endpoint.name else None
                    issues = '；'.join(reason_text('target_' + issue) for issue in endpoint.issues)
                    print(endpoint_text(endpoint.ref, label=label) + '  target=claude@id:' + endpoint.ref.native_id
                          + '  [root] 状态未知' + ('  ' + issues if issues else ''))
            _revive_for_federation()  # 这个入口不开本机账本、不走通用补查：只按联邦待办补拉（Codex r3-P2-02）
            return EXIT_OK
    # 任一调用前后补查摘要：提交后未发布（进程被杀、锁超时）的窗口由下一次调用收敛；worker 与 summary 自行处理
    refresh = args.command not in {"worker", "summary"} and not (get_platform().name == 'windows' and args.command == 'wait')
    if refresh:
        _refresh_summary()
    try:
        with command_scope():
            return int(args.handler(args))
    except CliError as error:
        _report_error(args, error.code)
        return error.exit_code
    except ReportError as error:
        _report_error(args, error.code)
        return EXIT_REJECTED
    except StoreError as error:
        _report_error(args, error.code)
        return _exit_for_store_error(error.code)
    except FedCliError as error:
        _report_error(args, error.code)
        return error.exit_code
    except KeyboardInterrupt:
        return 130
    finally:
        if refresh:
            _refresh_summary(revive=args.command != "withdraw")
