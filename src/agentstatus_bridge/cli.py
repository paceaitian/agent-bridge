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

from . import __version__, summary
from .platforms import process as procfs
from .codex_metadata import command_scope
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
from .store import DB_NAME, MAX_BODY_BYTES, Store, StoreError
from .closure import ACCEPTED, CLOSED, ClosureOutcome, queue_closures
from .dispatch import needs_worker, select_generation
from .doctor import collect_checks, print_checks
from .views import (
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
    blocking = endpoint.blocking_issues
    if blocking:
        raise CliError(f"target_{blocking[0]}")
    if "shared_thread" in endpoint.issues and not allow_shared:
        raise CliError("target_shared_thread")


def _resolve(selector: str, endpoints: list[Endpoint]) -> Endpoint:
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
        _print_json({"peers": rows})
        return EXIT_OK
    if not rows:
        print("没有发现正在运行的 agent 终端会话（Claude/Codex/Grok）")
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
    return EXIT_OK


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
    """有待办而 worker 不在（例如异常退出）时重新拉起；查询命令也能让排队恢复流动。"""
    try:
        if needs_worker(store, now) and not _worker_up(state_dir()):
            _ensure_worker()
    except (OSError, StoreError):
        pass


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
        return data.decode("utf-8", errors="replace")
    if args.message == "-" or (args.message is None and not sys.stdin.isatty()):
        return sys.stdin.read(MAX_BODY_BYTES + 1)
    if args.message is None:
        raise CliError("empty_message")
    return args.message


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
    body = _read_body(args)
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
                task_options={"notify": not args.no_notify, "allowShared": bool(args.allow_shared)},
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
            print(f"任务 {short(task.id)} 已交给 {target.ref.display()}：{DELIVERY_LABELS[current.delivery]}")
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
        endpoints, observed = _observations() if any(not task.finished for task in tasks) else ([], ObserverView())
        hints = {
            task.id: _target_hint(store.attempts(task.id), endpoints, observed, now)
            for task in tasks
            if not task.finished
        }
        if args.json:
            _print_json({"tasks": [_task_document(store, task, hint=hints.get(task.id, _NO_HINT)) for task in tasks]})
            return EXIT_OK
        if not tasks:
            print("没有进行中的协作任务" if not args.all else "没有协作任务")
            return EXIT_OK
        for task in tasks:
            attempts = store.attempts(task.id)
            view = describe(task, attempts)
            target = view.current.target.display() if view.current else "-"
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
    return EXIT_OK


def _task(store: Store, reference: str) -> Task:
    try:
        return store.resolve_task(reference)
    except StoreError as error:
        raise CliError(error.code, _exit_for_store_error(error.code)) from error


def cmd_status(args: argparse.Namespace) -> int:
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
    endpoints = discover()
    caller = identify_caller(endpoints)
    with _open_store() as store:
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
        if args.json:
            _print_json(_task_document(store, outcome.task))
            return exit_code
        print(f"已记录：{EVENT_LABELS[kind.value]}（任务 {short(outcome.task.id)} #{outcome.attempt.seq}）")
        for followup in outcome.followups:
            label = "已排队发给复核方" if followup.role is Role.REVIEW else "已排队通知发起方"
            print(f"{label} {followup.target.display()}")
    return exit_code


def cmd_wait(args: argparse.Namespace) -> int:
    deadline = time.monotonic() + args.timeout
    rounds = 0
    with _open_store() as store:
        while True:
            if rounds % 10 == 0:
                _revive_worker(store, time.time())
            rounds += 1
            task = _task(store, args.task)
            attempts = store.attempts(task.id)
            view = describe(task, attempts)
            current = view.current
            reached: int | None = None
            if args.until == "sent":
                if current is not None and current.delivery in (*HANDED_OVER, Delivery.HELD):
                    reached = EXIT_OK
            elif args.until == "ack":
                if current is not None and current.work in (Work.ACKNOWLEDGED, Work.IN_PROGRESS, Work.RESULT):
                    reached = EXIT_OK
            if reached is None:
                if view.phase in _RESULT_PHASES and args.until in {"result", "ack", "sent"}:
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
    with _open_store() as store:
        task = _task(store, args.task)
        if task.finished:
            raise CliError("task_finished")
        store.update_task(task.id, now=time.time(), event="paused", control="paused")
        print(f"任务 {short(task.id)} 已暂停发送；已发出的消息不受影响")
    return EXIT_OK


def cmd_resume(args: argparse.Namespace) -> int:
    with _open_store() as store:
        task = _task(store, args.task)
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
    now = time.time()
    with _open_store() as store:
        task = _task(store, args.task)
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
        return caller.endpoint.ref, caller.endpoint.ref.display()
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
        print(f"已排队第 {attempt.seq} 次{ROLE_LABELS[attempt.role]} → {attempt.target.display()}（任务 {short(attempt.task_id)}）")
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
    return run_worker(once=args.once)


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
    revive = revive and get_platform().name != 'windows'
    try:
        root = state_dir()
        if get_platform().name == 'windows':
            get_platform().files.ensure_private_dir(root)
        if not (root / DB_NAME).is_file():
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


def _report_error(args: argparse.Namespace, code: str) -> None:
    print(f"{command_name()}: {reason_text(code)} [{code}]", file=sys.stderr)
    if getattr(args, "json_errors", False) and getattr(args, "json", False):
        _print_json({"ok": False, "code": code, "reasonText": reason_text(code)})


def build_parser() -> argparse.ArgumentParser:
    prog = command_name()
    parser = argparse.ArgumentParser(prog=prog, description="AgentStatus 协作桥：在本机 agent 会话之间交接任务")
    parser.add_argument("--version", action="version", version=f"{prog} {__version__}")
    commands = parser.add_subparsers(dest="command", required=True)

    peers = commands.add_parser("peers", help="列出可交接的会话")
    peers.add_argument("--json", action="store_true")
    peers.set_defaults(handler=cmd_peers)

    send = commands.add_parser("send", help="把任务交给另一个会话")
    send.add_argument("--to", required=True, help="目标：codex@会话名、pane（%%3）或会话 ID")
    send.add_argument("-m", "--message", help="任务内容；- 表示从标准输入读取")
    send.add_argument("--file", help="从文件读取任务内容")
    send.add_argument("--title", help="任务标题（默认取内容第一行）")
    send.add_argument("--ref", action="append", default=[], help="附带引用文件（记录 sha256）")
    send.add_argument("--review-by", help="完成后自动交给该会话复核")
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
        command.set_defaults(handler=handler)

    accept = commands.add_parser("accept", help="验收结果")
    accept.add_argument("task")
    accept.add_argument("--force", action="store_true", help="没有待验收结果时也标记验收")
    accept.add_argument("--json", action="store_true", help="成功与失败都输出结构化结果（供界面调用）")
    accept.set_defaults(handler=cmd_accept, json_errors=True)

    close = commands.add_parser("close", help="停止追踪任务")
    close.add_argument("task")
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
    retry.add_argument("--to", help="改派到其他会话")
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

    doctor = commands.add_parser("doctor", help="检查协作桥运行环境")
    doctor.add_argument("--json", action="store_true")
    doctor.set_defaults(handler=cmd_doctor)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """命令入口；错误以固定原因码和可读说明输出到 stderr。"""
    global _worker_ensured
    _worker_ensured = False
    args = build_parser().parse_args(argv)
    try:
        platform = get_platform()
    except ValueError as error:
        if str(error) != 'platform_unsupported':
            raise
        _report_error(args, 'platform_unsupported')
        return EXIT_REJECTED
    with using_platform(platform):
        return _run_command(args)


def _run_command(args: argparse.Namespace) -> int:
    if get_platform().name == 'windows':
        # Before body/ref reads, ledger/summary, caller sampling, or finally/revive.
        if args.command not in {'doctor', 'tasks', 'status', 'summary', 'peers'}:
            _report_error(args, 'windows_provider_not_enabled')
            return EXIT_NOT_ENABLED
        if args.command == 'peers':
            value = {'peers': [], 'discovery': 'unverified', 'providerEnabled': False}
            _print_json(value) if args.json else print('Windows 会话发现未验证；未开放投递。')
            return EXIT_OK
    # 任一调用前后补查摘要：提交后未发布（进程被杀、锁超时）的窗口由下一次调用收敛；worker 与 summary 自行处理
    refresh = args.command not in {"worker", "summary"}
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
    except KeyboardInterrupt:
        return 130
    finally:
        if refresh:
            _refresh_summary(revive=args.command != "withdraw")
