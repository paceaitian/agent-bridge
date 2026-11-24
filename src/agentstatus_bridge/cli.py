"""协作桥命令行：在本机 Codex/Claude 会话之间交接任务、查看进展、复核与验收（DESIGN §45.9）。

终端、SSH 与 agent 会话使用同一套命令，不需要图形界面批准。退出码是桥自己的合同：
0 完成；2 目标不存在/歧义；3 校验或策略拒绝、可证明未送达；4 等待超时；5 对方报告失败或受阻；
6 能力不可用；7 投递结果不明；8 账本/协议错误。
"""

from __future__ import annotations

import argparse
from collections.abc import Callable, Sequence
import json
import os
import sqlite3
from pathlib import Path
import sys
import time
from typing import TYPE_CHECKING, Any

from . import __version__, claude_titles, summary
from .platforms import process as procfs
from .codex_metadata import command_scope
from .native_names import (NO_NAMES, NameBook, SelectorError, parse_selector, remote_display, shown_name, workdir_suffix,
                           workdir_text)
from .endpoints import (
    Caller,
    DiscoverySources,
    ResolveError,
    discover,
    identify_caller,
    permission_class,
    resolve_target,
)
from .hints import stopped_without_report, target_session_missing
from .ids import short
from .labels import (  # 标签表移至 labels 供摘要与 worker 共用；此处保留同名导出
    CONSUMPTION_LABELS,
    DELIVERY_LABELS,
    EVENT_LABELS,
    FYI_LABEL,
    ISSUE_LABELS,
    ROLE_LABELS,
    RUNTIME_LABELS,
    WORK_LABELS,
    clock_text,
    next_step,
    reason_text,
    shown_reason,
    role_label,
    review_capacity_hint,
    notification_capacity_hint,
)
from .model import (
    DEFER_OPTION,
    DEFINITELY_UNDELIVERED,
    EXPECT_OPTION,
    FOR_SEQ_OPTION,
    HANDED_OVER,
    MAX_DEFER_SECONDS,
    MAX_EXPECT_SECONDS,
    MAY_HAVE_ARRIVED,
    MIN_EXPECT_SECONDS,
    NOTE_KIND,
    REMIND_OPTION,
    NOTICE_KIND_OPTION,
    ORIGIN_WATCH_OPTION,
    PHASE_LABELS,
    PROVEN_UNDELIVERED,
    UNRESOLVED_NATIVE_ID,
    Attempt,
    Delivery,
    Endpoint,
    EndpointRef,
    Flow,
    Phase,
    Provider,
    ReportKind,
    Role,
    Task,
    TaskView,
    Verdict,
    Work,
    defer_time,
    describe,
    work_attempts,
)
from .naming import command_name
from .nudges import target_pane_state
from .observer_dbus import ObserverView
from .todo import TodoItem, local_items as todo_items, report_item as todo_report_item, text_line as todo_line
from .platforms.factory import get_platform, using_platform
from .paths import codex_home, codex_sqlite_home, device_name, state_dir
from .reports import (MAX_NOTE_CHARS, ReportError, ReportInput, apply_report, checked_note, file_reference,
                      refs_over_limit, retry_inherits_first, retry_is_rework)
from .store import ATTEMPT_WARNING_THRESHOLD, DB_NAME, MAX_BODY_BYTES, MAX_FILES, Store, StoreError
from .task_filter import (
    TASK_LIST_LIMIT,
    FilterError,
    SessionMatch,
    TaskFilter,
    accepts_local,
    parse_duration,
    parse_since,
)
from .closure import ACCEPTED, CLOSED, ClosureOutcome, delivered_endpoint, queue_closures
from .dispatch import needs_worker, select_generation
from .doctor import collect_checks, federation_text, print_checks, relay_diagnostics_text
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
    from .federation.fedstore import FedAttempt, FederatedStore, FedTask

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
    """每个端点的规范可复制 `--to`（§91.1）：一律 `provider@id:<完整ID>`；认不出 ID 的端点没有可用写法。"""
    return {id(item): (f"{item.ref.provider.value}@id:{item.ref.native_id}"
                       if item.ref.native_id != UNRESOLVED_NATIVE_ID else f"{item.ref.provider.value}（ID未解析）")
            for item in endpoints}


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
    # 只认目标自己的 observer 行（§62 ⑤ 候选 C）；与 worker 催执行方同一份实现（§104.11 P3 去重）
    pane = target_pane_state(view, live) if live is not None and live.ref.pane else None
    return _TargetHint(stopped_at=stopped_without_report(current, live, pane, now=now, attempts=attempts))


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
    # 显式空的 --device 不静默列出本机（§101.2，与 send/retry 同一拒绝）
    _reject_blank_selectors(args, ("device",))
    # Windows 的不带参数与 --all-devices 都在 _run_command 的 Windows 分支里处理（§94.6），到不了这里
    if args.device:
        return _fed_peers(args)
    endpoints = discover()
    caller = identify_caller(endpoints)
    # §91.4.2：名字只取本轮同绑定的 NameView（不回退 tmux 会话名）；可复制 target 一律完整 ID，认不出 ID 的为 null
    book = NameBook.of(endpoints)
    # 设备只是路由属性：今天发现到的端点全在本机，所以每行都是同一个值（DESIGN §45.35）
    device = device_name()
    rows: list[dict[str, object]] = []
    for item in endpoints:
        view = book.view(item.ref)
        rows.append(
            {
                "target": view.target if item.ref.native_id != UNRESOLVED_NATIVE_ID else None,
                "name": view.name,
                "displayName": view.display_name,
                "nameVerified": view.verified,
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
                # 工作目录末段（§95.3）：与 displayName 同样转义、限 120 字符；不知道为 null
                "workdir": workdir_text(item.workdir),
            }
        )
    if args.json:
        # claudeTitles：Claude 名字取自会话记录标题的计数与退回原因码（§99.3，只有计数，不含路径与标题）
        document: dict[str, object] = {"peers": rows, "claudeTitles": claude_titles.counts(endpoints)}
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
    # 与 Windows 同形（§91.4.2、91.7）：人读名字〔全集消歧前缀〕加同行可复制 target；pane 不是输入，不再占一列
    for row, item in zip(rows, endpoints):
        mark = "  ← 当前会话" if row["self"] else ""
        issues = "，".join(ISSUE_LABELS.get(issue, issue) for issue in item.issues)
        extra = f"  [{issues}]" if issues else ""
        mode = f"  {row['permissionClass']}" if row["permissionClass"] else ""
        target = f"  target={row['target']}" if row["target"] is not None else ""
        # 目录放在「← 当前会话」之前：箭头标记一直是行的最后一项（§95.3 的「行尾」按此理解）
        workdir = workdir_suffix(workdir_text(item.workdir), shown_name(book.view(item.ref)))
        print(f"{book.text(item.ref)}{target}  {RUNTIME_LABELS[item.runtime]}{mode}{extra}{workdir}{mark}")
    if args.all_devices:
        _fed_all_devices_text()
    return EXIT_OK


def _windows_local_peers(*, as_json: bool) -> dict[str, object] | None:
    """Windows 本机 peers（§94.6）：Codex 候选与 Claude 原生 peer 两部分，不带参数的 peers 与 --all-devices 共用。

    as_json 为真时只返回文档（与 `ab peers --json` 同形，调用方决定是否再加 devices 后打印）；否则直接打印文字行。
    只读：不开本机账本、不走通用补查。
    """
    from .platforms.windows import codex_discovery  # layout: allow Windows只读候选，Linux路径与构造不加载
    from .platforms.windows.local_transport import WindowsPlatform  # layout: allow 已选择后端的窄能力
    from .platforms.windows.commands import claude_evidence  # layout: allow W3 read-only registry candidates
    backend = get_platform().transport
    # 只有 peers 显示要忙闲：with_status 让可投递根线程多一次有界的 metadata-only thread/read（§96.2）
    result = (codex_discovery.discover(backend, with_status=True) if isinstance(backend, WindowsPlatform)
              else codex_discovery.Discovery())
    peers = claude_evidence()
    if as_json:
        document = result.document()
        existing = document.get('peers')
        document['peers'] = (existing if isinstance(existing, list) else []) + peers.document()
        document['claudeDiscovery'] = {'complete': peers.complete, 'reason': peers.reason}
        document['claudeTitles'] = claude_titles.counts((*peers.endpoints, *peers.duplicates))  # §99.3 只计数
        return document
    codex_discovery.print_peers(result)
    print('Windows Claude 原生 peer：' + ('发现完整' if peers.complete else reason_text(peers.reason)))
    names = NameBook.of((*peers.endpoints, *peers.duplicates))
    for endpoint in (*peers.endpoints, *peers.duplicates):
        # 人读名字走本轮 NameView（未核实只作「名称=…（仅展示）」，转义由投影负责）；target 一律完整 ID
        issues = '；'.join(reason_text('target_' + issue) for issue in endpoint.issues)
        workdir = workdir_suffix(workdir_text(endpoint.workdir), shown_name(names.view(endpoint.ref)))
        print(names.text(endpoint.ref) + '  target=claude@id:' + endpoint.ref.native_id
              + '  [root] ' + RUNTIME_LABELS[endpoint.runtime] + ('  ' + issues if issues else '') + workdir)
    return None


def _windows_peers(args: argparse.Namespace) -> int:
    """Windows `ab peers` 与 `--all-devices`（§94.6）：--all-devices 先列本机一节再列远端，JSON 与 Linux 同构。"""
    if args.json:
        document = _windows_local_peers(as_json=True) or {}
        if args.all_devices:
            document['devices'] = _fed_all_devices()
        _print_json(document)
    else:
        if args.all_devices:
            print(f"设备 {device_name()}（本机）：")
        _windows_local_peers(as_json=False)
        if args.all_devices:
            _fed_all_devices_text()
    _revive_for_federation()  # 这个入口不开本机账本、不走通用补查：只按联邦待办补拉（Codex r3-P2-02）
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


def _read_input(text: str | None, path: str | None, *, conflict: str, too_large: str,
                implicit_stdin: bool) -> str | None:
    """正文/说明的三种来源（DESIGN §104.4）：命令行文本、`-`（标准输入）、文件；都没给时返回 None。

    implicit_stdin 只给必填正文（send/note）用：没给文本且 stdin 不是终端时照旧读 stdin。可选正文（retry 的
    `-m/--file`、report 的 `--note/--note-file`）只在显式 `-` 时读，否则 agent shell 里的 `ab retry`、
    `ab report --ack` 会被非终端 stdin 卡住（§104.9 四）。超长报 too_large，读前即判，不落账。
    """
    if path and text is not None:
        raise CliError(conflict)
    if path:
        source = Path(path).expanduser()
        try:
            data = source.read_bytes() if source.stat().st_size <= MAX_BODY_BYTES else None
        except OSError as error:
            raise CliError("file_unreadable") from error
        if data is None:
            raise CliError(too_large)
        return _strict_body(data, too_large=too_large)
    if text == "-" or (implicit_stdin and text is None and not sys.stdin.isatty()):
        return _strict_body(sys.stdin.buffer.read(MAX_BODY_BYTES + 1), too_large=too_large)
    return text  # 编码不成 UTF-8 的命令行文本已在 _main 的统一参数检查里拒绝（§101.2）


def _read_body(args: argparse.Namespace) -> str:
    """必填正文（send、note，以及 ab remind）：`-m 文本`、`-m -`、`--file 路径`；都没给且 stdin 是终端时报 empty_message。"""
    body = _read_input(args.message, getattr(args, "file", None), conflict="message_and_file_conflict",
                       too_large="message_too_large", implicit_stdin=True)
    if body is None:
        raise CliError("empty_message")
    return body


def _read_optional_body(args: argparse.Namespace) -> str | None:
    """可选正文（retry 的补充或返工要求）：`-m 文本`、`-m -`、`--file 路径`，只在显式 `-` 时读标准输入；没给为 None。"""
    return _read_input(args.message, getattr(args, "file", None), conflict="message_and_file_conflict",
                       too_large="message_too_large", implicit_stdin=False)


def _read_note(args: argparse.Namespace) -> str | None:
    """report 的说明（§104.4）：`--note 文本`、`--note -`、`--note-file 路径`；没给为 None。

    超过 MAX_NOTE_CHARS（strip 后按字符计）或文件超过 64 KiB 报 note_too_large，在任何写入之前（不再静默截断）。
    """
    note = _read_input(args.note, getattr(args, "note_file", None), conflict="note_and_file_conflict",
                       too_large="note_too_large", implicit_stdin=False)
    if note is not None:
        try:
            checked_note(note)
        except ReportError as error:
            raise CliError(error.code) from error
    return note


def _ref_key(raw: str, cwd: Path) -> str:
    """点名路径的去重键：与 file_reference 存的路径同一解析（展开 ~、相对 cwd、跟随链接）；解析不了的用绝对路径，
    留给 file_reference 报 file_unreadable。"""
    candidate = Path(raw).expanduser()
    if not candidate.is_absolute():
        candidate = cwd / candidate
    try:
        return str(candidate.resolve())
    except (OSError, RuntimeError):
        return os.path.abspath(candidate)


def _named_refs(paths: list[str], cwd: Path) -> dict[str, str]:
    """--ref 点名按解析后的路径去重（不读文件内容）：键与 file_reference 存的路径同一解析，值是原样点名，保持点名顺序。"""
    unique: dict[str, str] = {}
    for raw in paths:
        unique.setdefault(_ref_key(raw, cwd), raw)
    return unique


def _local_refs(paths: list[str]) -> list[dict[str, object]]:
    """note 的 --ref（§104.4）：先按解析后的路径去重再计数，超过上限在算 sha256 之前拒绝（note 对自己的附件单独限额）。"""
    cwd = Path.cwd()
    unique = _named_refs(paths, cwd)
    if len(unique) > MAX_FILES:
        raise CliError("too_many_files")
    return _merge_refs([], [file_reference(raw, cwd=cwd) for raw in unique.values()])


def _retry_base_refs(task: Task, work: list[Attempt]) -> list[dict[str, object]]:
    """retry 新尝试继承的附件（§104.11 第 5 条，判据 retry_inherits_first 与跨设备共用）；work 是工作尝试，按序号。"""
    if not work:
        return []
    first, current = work[0], work[-1]
    return list(first.refs if retry_inherits_first(task, current) else current.refs)


def _retry_fresh_refs(store: Store, args: argparse.Namespace, named: dict[str, str],
                      cwd: Path) -> dict[str, dict[str, object]]:
    """retry --ref 在事务外只为真正新增的路径算 sha256（§104.12 第 9 条）。

    先只读看一眼将继承的附件：已在其中的点名不读文件；净增量让合并结果超过上限时，在读任何文件之前拒绝。
    事务内按那时真正的继承集合再判一次（_retry_in_transaction）；这里没算到的新增路径（并发改变了继承集合）
    在事务内补算。
    """
    if not named:
        return {}
    task = _task(store, args.task)
    base = _retry_base_refs(task, work_attempts(store.attempts(task.id)))
    known = {item.get("path") for item in base}
    fresh = [key for key in named if key not in known]
    if refs_over_limit(len(base), len(base) + len(fresh)):
        raise CliError("too_many_files")
    return {key: file_reference(named[key], cwd=cwd) for key in fresh}


def _merge_refs(inherited: list[dict[str, object]], extra: list[dict[str, object]]) -> list[dict[str, object]]:
    """把新附件追加在继承的附件之后，按路径去重；只有新增部分让合并结果超过 MAX_FILES 才报 too_many_files
    （§104.11 第 5 条，与跨设备同一口径）。"""
    merged = list(inherited)
    seen = {item.get("path") for item in merged}
    for item in extra:
        if item.get("path") not in seen:
            seen.add(item.get("path"))
            merged.append(item)
    if refs_over_limit(len(inherited), len(merged)):
        raise CliError("too_many_files")
    return merged


def _utf8_encodable(text: str) -> bool:
    try:
        text.encode('utf-8')
    except UnicodeEncodeError:
        return False
    return True


def _unencodable_argument(args: argparse.Namespace) -> str | None:
    """命令行参数的统一 UTF-8 检查（§101.2）：解析后、任何读写之前，找出编码不成 UTF-8 的 str 参数（Linux argv 里的
    非法字节经 surrogateescape、Windows 命令行的孤立代理），否则它们会在写账本或输出时抛 UnicodeEncodeError。
    正文 -m 报 message_invalid_utf8，其余参数报 argument_invalid_utf8，退出码都是 3；没有返回 None。
    例外：send/note/retry 的 --file 与 report 的 --note-file 只是正文来源路径，只交给文件系统打开、不保存不显示，
    非 UTF-8 文件名照常可用（report 的 --file 是要记录的结果附件，不在此列）。
    """
    values = vars(args)
    for key in ('message', *sorted(name for name in values if name != 'message')):
        value: object = values.get(key)
        if key in ('file', 'note_file') and isinstance(value, str):
            continue
        items: list[object] = list(value) if isinstance(value, list) else [value]  # pyright: ignore[reportUnknownArgumentType]
        if any(isinstance(item, str) and not _utf8_encodable(item) for item in items):
            return 'message_invalid_utf8' if key == 'message' else 'argument_invalid_utf8'
    return None


def _strict_body(data: bytes, *, too_large: str = 'message_too_large') -> str:
    """正文按原始字节严格 UTF-8 解码，两平台同一判定（§77.14、§101.2）：超过 MAX_BODY_BYTES 报 too_large（缺省
    message_too_large，report 说明为 note_too_large），非法 UTF-8 报 message_invalid_utf8，都退出 3、都在落账前；
    不按本机编码猜、不替换字符，BOM 保留为 U+FEFF。"""
    if len(data) > MAX_BODY_BYTES:
        raise CliError(too_large)
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


def _printed_delivery(document: dict[str, object], seq: int, fallback: Delivery) -> Delivery:
    """`--json` 文档里第 seq 号尝试的投递状态（即实际打印给调用方的那个）；文档里找不到时用 fallback。"""
    attempts = document.get("attempts")
    for item in attempts if isinstance(attempts, list) else []:  # pyright: ignore[reportUnknownVariableType]
        if isinstance(item, dict) and item.get("seq") == seq:  # pyright: ignore[reportUnknownMemberType]
            try:
                return Delivery(item.get("delivery"))  # pyright: ignore[reportUnknownMemberType,reportUnknownArgumentType]
            except ValueError:
                return fallback
    return fallback


def _delivery_exit(delivery: Delivery) -> int:
    if delivery is Delivery.UNKNOWN:
        return EXIT_UNKNOWN
    if delivery in PROVEN_UNDELIVERED and delivery is not Delivery.PENDING:
        return EXIT_REJECTED
    return EXIT_OK


def _reject_blank_selectors(args: argparse.Namespace, names: tuple[str, ...]) -> None:
    """显式给出空串或只有空白的目标类参数与 `--to ""` 同一拒绝（§101.2）：报 target_explicit_required/2，不静默当作
    没给（例如 --review-by "" 降为 handoff、--device "" 变成本机任务、retry --to "" 变成不改派）；两平台同码同退出码，
    调用方放在其他参数检查、读正文与任何读写之前。"""
    for name in names:
        value = getattr(args, name, None)
        if isinstance(value, str) and not value.strip():
            raise CliError("target_explicit_required", EXIT_TARGET)


def _duration_arg(raw: str | None, code: str, *, minimum: float, maximum: float) -> float | None:
    """--after/--expect/--in 的时长（§104.9 一、二）：没给为 None；格式或范围不对在任何写入之前报 code。"""
    if raw is None:
        return None
    seconds = parse_duration(raw, minimum=minimum, maximum=maximum)
    if seconds is None:
        raise CliError(code)
    return seconds


def cmd_send(args: argparse.Namespace) -> int:
    # --review-by/--device/--review-device 显式空值不静默忽略（Windows 的 --review-by 由命令作用域先拒、同码同退出码）
    _reject_blank_selectors(args, ("review_by", "device", "review_device"))
    # 延迟投递与沉默阈值（§104.9 一、二）：时长先解析，格式错误不写任何东西
    args.defer_seconds = _duration_arg(getattr(args, "after", None), "after_invalid", minimum=60.0,
                                       maximum=MAX_DEFER_SECONDS)
    args.expect_seconds = _duration_arg(getattr(args, "expect", None), "expect_invalid", minimum=MIN_EXPECT_SECONDS,
                                        maximum=MAX_EXPECT_SECONDS)
    # 一句话告知只建立即关闭的单向消息：只对工作有意义的参数一律互斥，任何写入之前拒绝（§95.5.7）
    if getattr(args, "fyi", False) and (args.review_by or args.review_device or args.no_notify
                                        or args.expect_seconds is not None):
        raise CliError("fyi_conflict", EXIT_TARGET)
    # 关联只是元数据：写任何东西之前先解析，解析不了就不落账（§93.3）
    follows = _resolve_follows(args.follows) if args.follows is not None else None
    if args.device or args.review_device:
        return _fed_send(args, follows=follows)
    return _local_send(args, follows=follows)


def _resolve_follows(reference: str) -> str:
    """`send --follows`：先在本机账本、再在联邦库（本机发起的任务与镜像）里解析旧任务，返回完整任务 ID（§93.3）。

    两边各命中一个或任一边前缀不唯一报 follows_ambiguous，都没有报 follows_not_found（都退出 2，与 task_not_found 同类）。
    只读：本机账本不存在时不建库，联邦未配置时不导入联邦实现；不要求调用方是旧任务的发起方，旧任务可已结束。
    """
    root = state_dir()
    found: list[str] = []
    ambiguous = False
    if (root / DB_NAME).is_file():
        with _open_store() as store:
            try:
                found.append(store.resolve_task(reference).id)
            except StoreError as error:
                if error.code == "task_ambiguous":
                    ambiguous = True
                elif error.code != "task_not_found":
                    raise CliError(error.code, _exit_for_store_error(error.code)) from error
    if _fed_configured(root):
        from .federation import commands as fed  # layout: allow 联邦按需加载
        try:
            rt = fed.try_runtime(root)
        except (StoreError, sqlite3.Error):
            rt = None
        if rt is not None:
            try:
                found.extend(task.task_id for task in rt.store.find_tasks(reference))
            except (StoreError, sqlite3.Error):
                # 能打开却查不了（表或页损坏）：与打不开同口径，跳过联邦库、只按本机解析，不让本机 send 以堆栈退出（§88.7）
                pass
            finally:
                rt.close()
    if ambiguous or len(found) > 1:
        raise CliError("follows_ambiguous", EXIT_TARGET)
    if not found:
        raise CliError("follows_not_found", EXIT_TARGET)
    return found[0]


def _local_send(args: argparse.Namespace, *, body: str | None = None, follows: str | None = None) -> int:
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
    origin_class = permission_class(caller)
    first_line = body.strip().splitlines()[0] if body.strip() else ""
    title = (args.title or first_line)[:60]
    if getattr(args, "fyi", False):
        return _local_fyi(args, body=body, refs=refs, origin=origin, origin_class=origin_class, target=target,
                          title=title, follows=follows, endpoints=endpoints)
    try:
        receipts = receipt_options(origin, no_notify=args.no_notify)
    except ValueError as error:
        raise CliError(str(error)) from error
    now = time.time()
    defer_until = _defer_until(args, now)
    # 定时发出不等首投、不盖章（§104.9 二）：到点前命令早已返回，之后的确定未送达照常立即告知
    wait = not args.no_wait and defer_until is None
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
                task_options={"notify": not args.no_notify, "allowShared": bool(args.allow_shared), **receipts,
                              **({"follows": follows} if follows is not None else {}),
                              **_expect_option(args)},
                # 预先盖章（DESIGN §103.2）：命令会等首次投递结果；打印出确定未送达就留着（= 发起方已见）
                attempt_options={"allowShared": bool(args.allow_shared),
                                 **({ORIGIN_WATCH_OPTION: True} if wait else {}),
                                 **({DEFER_OPTION: defer_until} if defer_until is not None else {})},
            )
        except StoreError as error:
            raise CliError(error.code, _exit_for_store_error(error.code)) from error
        started = _start_worker()
        current = attempt
        if wait:
            current = _wait_first_delivery(store, task.id, SEND_WAIT_SECONDS) or attempt
        worker_up = (
            current.delivery is not Delivery.PENDING
            or _worker_up(state_dir())
            or (bool(started) and _wait_worker_up(state_dir(), WORKER_START_SECONDS))
        )
        hint = _hold_hint(target, origin_class)
        names = NameBook.of(endpoints)
        document: dict[str, object] | None = None
        printed = current.delivery
        if args.json:
            # --json 的文档是此刻重读账本得到的：清不清章按文档里实际打印的状态，与文字模式一致（§103.8 修 5）
            document = _task_document(store, task, names=names)
            document["hint"] = hint
            printed = _printed_delivery(document, attempt.seq, printed)
        if wait and printed not in DEFINITELY_UNDELIVERED:
            # 这次没打印确定未送达：清章，之后落定的失败由 worker 立即告知；清不掉只会退化成 30 分钟提醒
            try:
                store.clear_attempt_option(attempt.id, ORIGIN_WATCH_OPTION)
            except StoreError:
                pass
        if document is not None:
            _print_json(document)
        elif defer_until is not None:
            cmd = command_name()
            print(f"任务 {short(task.id)} 已排定，交给 {names.text(target.ref)}：定时 {clock_text(defer_until)} 发出"
                  f"（到点由后台 worker 发送；不需要了可 {cmd} cancel {short(task.id)}）")
            print(f"查看进展：{cmd} status {short(task.id)}；等待结果：{cmd} wait {short(task.id)}")
        else:
            print(f"任务 {short(task.id)} 已交给 {names.text(target.ref)}：{DELIVERY_LABELS[current.delivery]}")
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


def _defer_until(args: argparse.Namespace, now: float) -> float | None:
    """`send --after` 的到期时刻（epoch 秒）；没给为 None。"""
    seconds = getattr(args, "defer_seconds", None)
    return None if seconds is None else now + seconds


def _expect_option(args: argparse.Namespace) -> dict[str, object]:
    """`send --expect` 写进任务 options 的沉默阈值（秒，§104.9 一）；没给不写，读方按缺省 30 分钟。"""
    seconds = getattr(args, "expect_seconds", None)
    return {} if seconds is None else {EXPECT_OPTION: seconds}


def _local_fyi(args: argparse.Namespace, *, body: str, refs: list[dict[str, Any]], origin: EndpointRef | None,
               origin_class: str | None, target: Endpoint, title: str, follows: str | None,
               endpoints: list[Endpoint]) -> int:
    """`ab send --fyi` 本机部分（DESIGN §95.5.7）：同一写事务建任务并立即关闭，排队后即返回，不等投递结果。

    投递结果用 status 查；投递失败不叫醒发起方（单向消息，与结束回执同口径）。
    """
    with _open_store() as store:
        try:
            now = time.time()
            defer_until = _defer_until(args, now)
            task, attempt = store.create_fyi(
                title=title, origin=origin, origin_class=origin_class, target=target.ref, body=body, refs=refs,
                now=now,
                task_options={"allowShared": bool(args.allow_shared),
                              **({"follows": follows} if follows is not None else {})},
                attempt_options={"allowShared": bool(args.allow_shared),
                                 **({DEFER_OPTION: defer_until} if defer_until is not None else {})},
            )
        except StoreError as error:
            raise CliError(error.code, _exit_for_store_error(error.code)) from error
        started = _start_worker()
        names = NameBook.of(endpoints)
        document: dict[str, object] | None = None
        if args.json:
            document = _task_document(store, task, names=names)
        else:
            cmd = command_name()
            when = f"定时 {clock_text(attempt.defer_until)} 发出" if attempt.defer_until is not None else "已排队"
            print(f"告知 {short(task.id)} {when}，发给 {names.text(attempt.target)}；对方只需读到，不汇报、不验收")
            print(f"查看投递：{cmd} status {short(task.id)}")
    unavailable = _queued_without_worker(started)
    if document is not None:
        document["notes"] = ["worker_not_running"] if unavailable else []
        _print_json(document)
    return EXIT_UNAVAILABLE if unavailable else EXIT_OK


def _session_selector(raw: str, endpoints: Callable[[], list[Endpoint]]) -> SessionMatch:
    """`tasks --to/--from` 的 SEL（§93.1，复用 §91 选择器）：ID 形直接按会话 ID（前缀）匹配，本机与跨设备通用；
    名字形只按本机当前发现解析成一个会话（与不带 --device 的 send 同一套解析与完整性要求），失败照 send 报错，不给空列表。"""
    try:
        wanted = parse_selector(raw)
    except SelectorError as error:
        raise CliError(error.args[0], EXIT_TARGET) from error
    if wanted.kind != "name":
        return SessionMatch(wanted.provider.value if wanted.provider is not None else None, wanted.value,
                            exact=wanted.kind == "id")
    live = _resolve(raw, endpoints())
    return SessionMatch(live.ref.provider.value, live.ref.native_id.lower())


def _task_filter(args: argparse.Namespace, now: float) -> TaskFilter:
    """解析 tasks 的筛选参数；全部在读任务之前完成，格式错误与解析失败都直接报错（§93.1）。"""
    since: float | None = None
    if args.since is not None:
        try:
            since = parse_since(args.since, now)
        except FilterError as error:
            raise CliError(error.code) from error
    if args.grep is not None and not args.grep:
        raise CliError("grep_empty")
    found: list[list[Endpoint]] = []

    def endpoints() -> list[Endpoint]:
        # 只有 --mine 或名字形 SEL 才需要发现，而且一条命令只发现一次；不带这些参数时与原来一样不做发现
        if not found:
            found.append(discover())
        return found[0]

    mine: SessionMatch | None = None
    if args.mine:
        caller = identify_caller(endpoints())
        # 按会话 ID 匹配：用户终端或认不出 ID 的调用方没有可比的会话
        if caller.endpoint is None or caller.endpoint.ref.native_id == UNRESOLVED_NATIVE_ID:
            raise CliError("mine_requires_session")
        mine = SessionMatch(caller.endpoint.ref.provider.value, caller.endpoint.ref.native_id.lower())
    return TaskFilter(
        mine=mine,
        to=_session_selector(args.to, endpoints) if args.to is not None else None,
        origin=_session_selector(args.from_session, endpoints) if args.from_session is not None else None,
        since=since,
        grep=args.grep.casefold() if args.grep is not None else None,
    )


def cmd_tasks(args: argparse.Namespace) -> int:
    now = time.time()
    wanted = _task_filter(args, now)
    with _open_store() as store:
        # 待办而 worker 不在时的补拉由 main 结束时统一做（DESIGN §45.28.3），这里不重复拉起
        # 先取全部候选再筛，留最新的 200 条、按创建时间升序显示（§93.1）；账本已受 30 天保留约束
        tasks = [task for task in store.list_tasks(include_finished=args.all, limit=None)
                 if not wanted.active or accepts_local(wanted, task, store.attempts(task.id))][-TASK_LIST_LIMIT:]
        federation = _fed_task_list(args.all, now, wanted)
        endpoints, observed = _observations() if any(not task.finished for task in tasks) else ([], ObserverView())
        names = NameBook.of(endpoints)
        hints = {
            task.id: _target_hint(store.attempts(task.id), endpoints, observed, now)
            for task in tasks
            if not task.finished
        }
        if args.json:
            listing: dict[str, object] = {
                "tasks": [_task_document(store, task, hint=hints.get(task.id, _NO_HINT),
                                         names=NO_NAMES if task.finished else names) for task in tasks]}
            if federation is not None:
                listing["federation"] = federation[0]
            _print_json(listing)
            return EXIT_OK
        if wanted.active:
            # 有筛选时「没有结果」指本机与跨设备都没有（联邦库不可读那一行不算任务）
            if not tasks and not (federation is not None and federation[0]):
                print("没有符合条件的协作任务")
        elif not tasks:
            print("没有进行中的协作任务" if not args.all else "没有协作任务")
        for task in tasks:
            attempts = store.attempts(task.id)
            view = describe(task, attempts)
            if task.is_fyi:
                # 一句话告知（§95.5.7）只在 --all 里出现：阶段列写「告知」，目标取那条告知，原因写投递状态
                notice = attempts[0] if attempts else None
                target = NO_NAMES.text(notice.target) if notice else "-"
                state = DELIVERY_LABELS[notice.delivery] if notice else "-"
                print(f"{short(task.id)}  {FYI_LABEL:<4} {target:<28} {task.title[:40]}  （{state}，{_age(task.updated_at, now)}）")
                continue
            # 已结束的行与 status 一致：不借本轮发现的名字，完整 ID（§91.4.2）
            target = (NO_NAMES if task.finished else names).text(view.current.target) if view.current else "-"
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
                f" {task.title[:40]}  （{reason_text(shown_reason(view, now))}{flag}{withdrawal_note}，{_age(task.updated_at, now)}）"
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
        names = NO_NAMES  # 已结束的任务不为排版另做发现：无同绑定名字证据即完整 ID（§91.4.2）
        if not task.finished:
            endpoints, observed = _observations()
            hint = _target_hint(store.attempts(task.id), endpoints, observed, now)
            names = NameBook.of(endpoints)
        follows = task.options.get("follows")
        relations, followed_by = _follow_links(task.id, follows if isinstance(follows, str) else None, store=store)
        if args.json:
            document = _task_document(store, task, include_body=args.body, events=True, hint=hint, names=names)
            if followed_by:
                document["followedBy"] = followed_by
            _print_json(document)
        else:
            _print_task(store, task, now=now, show_body=args.body, hint=hint, names=names, relations=relations)
    return EXIT_OK


def _follow_links(task_id: str, follows: str | None, *, store: Store | None = None,
                  fed_store: FederatedStore | None = None) -> tuple[list[str], list[str]]:
    """status 的任务关联（§93.3）：返回（显示行, 后续任务完整 ID 列表）。

    本机账本与联邦库都查，调用方已开的那一边直接用。另一边按需打开：联邦库先做与 §90.6 投影相同的配置核对
    （配置读不了或 expectedStateRoot 与本根不符就不查联邦库），再用只读连接（mode=ro、query_only，忙时约 50 ms
    即放弃、不写库），本机账本按普通方式打开；未配置联邦时不导入联邦实现。
    关联只是展示：打开或查询任一步出任何故障都只少显示，不让已命中的 status 失败（§88.7）。
    """
    root = state_dir()
    own_store: Store | None = None
    own_fed: FederatedStore | None = None
    try:
        if store is None and (root / DB_NAME).is_file():
            try:
                store = own_store = Store.open(root)
            except (StoreError, OSError, sqlite3.Error):
                store = None
        if fed_store is None and _fed_configured(root):
            from .federation import config as fed_config  # layout: allow 联邦按需加载
            from .federation.fedstore import FederatedStore as FedStore  # layout: allow 联邦按需加载
            try:
                # 状态目录被复制或挪走时配置指向别处：不显示一个与当前配置不符的联邦库里的后续任务（§94.2）
                config = fed_config.load(root)
                if config is not None:
                    fed_config.check_state_root(config, root)
                    fed_store = own_fed = FedStore.open_readonly(root)
            except Exception:  # noqa: BLE001 - 关联只是展示：配置或联邦库任何故障都不能让已命中的本机 status 失败
                fed_store = None
        lines: list[str] = []
        if follows is not None:
            title: str | None = None
            try:
                old = store.get_task(follows) if store is not None else None
                if old is not None:
                    title = old.title
                elif fed_store is not None and (hits := fed_store.find_tasks(follows)):
                    # 联邦库里的旧任务可能是镜像（标题来自发起设备）：与其余远端字符串同一套转义（§103.3）
                    title = remote_display(hits[0].title) or ""
            except Exception:  # noqa: BLE001 - 与打开同口径：查不到就当旧任务已不在
                title = None
            note = "已不在账本" if title is None else title  # 旧任务已过保留期被删除时只剩 ID
            lines.append(f"承接任务 {short(follows)}（{note}）" if note else f"承接任务 {short(follows)}")
        later: list[tuple[float, str]] = []
        for source in (store, fed_store):
            if source is None:
                continue
            try:
                later.extend(source.followers(task_id))
            except Exception:  # noqa: BLE001 - 与打开同口径：这一边查不了就少显示
                continue
        later.sort()
        if later:
            lines.append("后续任务 " + "、".join(short(item) for _, item in later))
        return lines, [item for _, item in later]
    finally:
        if own_store is not None:
            own_store.close()
        if own_fed is not None:
            own_fed.close()


_REPORT_KINDS: tuple[tuple[str, ReportKind], ...] = (
    ("ack", ReportKind.ACK),
    ("progress", ReportKind.PROGRESS),
    ("result", ReportKind.RESULT),
    ("blocked", ReportKind.BLOCKED),
    ("failed", ReportKind.FAILED),
    ("approve", ReportKind.APPROVE),
    ("changes", ReportKind.CHANGES),
    # 提问（DESIGN §104.9 五）：一次 progress 加可选标记 ask，不新增 ReportKind 枚举值
    ("ask", ReportKind.PROGRESS),
)
# 提问回执在本机任务里总能叫醒发起方；跨设备时发起设备版本较旧会只记成进展（§104.9 五）
ASK_OLD_AUTHORITY_HINT = "对方设备版本较旧时可能不会叫醒；急事改用 --blocked"


def cmd_report(args: argparse.Namespace) -> int:
    kind = next(value for name, value in _REPORT_KINDS if getattr(args, name))
    # 说明的三种来源统一读进 args.note（§104.4）：超长、冲突在找任务与任何写入之前拒绝，后面两条路径照旧只读 args.note
    args.note = _read_note(args)
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
                    ask=bool(getattr(args, "ask", False)),
                ),
                caller=caller,
                caller_class=permission_class(caller),
                now=time.time(),
                cwd=Path.cwd(),
                names=NameBook.of(endpoints),
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
        names = NameBook.of(endpoints)
        if args.json:
            document = _task_document(store, outcome.task, names=names)
            document['reportSkipped'] = outcome.skipped
            document['warnings'] = warnings
            _print_json(document)
            return exit_code
        label = "提问（任务仍在进行）" if getattr(args, "ask", False) else EVENT_LABELS[kind.value]
        print(f"已记录：{label}（任务 {short(outcome.task.id)} #{outcome.attempt.seq}）")
        for followup in outcome.followups:
            label = "已排队发给复核方" if followup.role is Role.REVIEW else "已排队通知发起方"
            print(f"{label} {names.text(followup.target)}")
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
                # 执行方提问（§104.9 五）：需要发起方回答，与受阻同一组返回 5
                "question_asked",
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
                    print(f"等待超时：{PHASE_LABELS[view.phase]}（{reason_text(shown_reason(view))}）")
                return EXIT_TIMEOUT
            time.sleep(1.0)


def _decision_document(command: str, scope: str, task_id: str, **fields: object) -> dict[str, object]:
    """决定类命令（pause/resume/cancel/close）`--json` 的成功文档（§93.2）：本机与跨设备同一形状，scope 区分。

    `notes` 是闭集原因码列表，对应文字模式里的「注意」「提示」；`--json` 时这些文字不再打印到 stdout。
    """
    return {"ok": True, "command": command, "scope": scope, "id": task_id, **fields}


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
        if getattr(args, "json", False):
            _print_json(_decision_document("pause", "local", task.id, control="paused", notes=[]))
        else:
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
        as_json = bool(getattr(args, "json", False))
        if not as_json:
            print(f"任务 {short(task.id)} 继续发送")
        # 按全账本的实际后台需求判断（排队、发送恢复、观察窗口、待办提醒；worker 全局只有一个），不只看本任务排队消息（Codex 复审 R01）
        needed = False
        if started is None:
            try:
                needed = needs_worker(store, time.time())
            except (StoreError, sqlite3.Error):  # 读账本出错时按需要处理，不以堆栈退出（Opus 第二轮复审）
                needed = True
    unavailable = needed and _queued_without_worker(started)
    if as_json:
        # 退出码先算出来再打印：stdout 只有这一份文档（§93.2）
        _print_json(_decision_document("resume", "local", task.id, control="active",
                                       notes=["worker_not_running"] if unavailable else []))
    return EXIT_UNAVAILABLE if unavailable else EXIT_OK


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
        if getattr(args, "json", False):
            _print_json(_decision_document("cancel", "local", task.id, control=task.control, cancelled=cancelled,
                                           notes=[]))
        else:
            print(f"已取消 {cancelled} 条尚未发送的消息（任务 {short(task.id)}）")
    return EXIT_OK


def _may_decide(caller: Caller, task: Task) -> bool:
    """用户本人，或代表用户发起任务的会话，可以验收；执行方和复核方不能。"""
    if caller.is_user_shell:
        return True
    return caller.endpoint is not None and task.origin is not None and caller.endpoint.ref.same_session(task.origin)


def _closure_decider(caller: Caller, names: NameBook = NO_NAMES) -> tuple[EndpointRef | None, str]:
    """结束回执以谁的名义发出：决定者所在会话（用户在终端时为空）与正文里的标识（本机已核实主名，否则完整 ID）。"""
    if caller.endpoint is not None:
        return caller.endpoint.ref, names.local_wire(caller.endpoint.ref)
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
        sender, decider = _closure_decider(caller, NameBook.of(endpoints))
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
            _print_json({"ok": True, "id": task.id, "phase": Phase.DONE.value,
                         "closure": _closure_document(outcome, NameBook.of(endpoints))})
        else:
            print(f"任务 {short(task.id)} 已验收")
            _print_closure(outcome, NameBook.of(endpoints))
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
        sender, decider = _closure_decider(caller, NameBook.of(endpoints))
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
        if getattr(args, "json", False):
            closed = store.get_task(task.id) or task
            _print_json(_decision_document(
                "close", "local", task.id, phase=describe(closed, store.attempts(task.id)).phase.value,
                closure=_closure_document(outcome, NameBook.of(endpoints)),
                notes=["native_risk"] if at_risk else []))
            return EXIT_OK
        print(f"任务 {short(task.id)} 已停止追踪")
        if at_risk:
            print("注意：停止追踪不撤回已交接内容；可显式尝试移除仍在 Codex 队列中的项（withdraw），已开始的工作不能撤销")
        _print_closure(outcome, NameBook.of(endpoints))
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


# 返工/重发正文的固定措辞（DESIGN §104.4、§104.9 四）
REWORK_HEADER = "【返工】"
RESEND_HEADER = "【重发】上一条消息可能已经送达；如果你已经在做，按这一条继续，不要重复执行。"
# --force 的另两种首行（§104.11 一并修）：改派到另一个会话时对方没收到过上一条，「可能已送达、不要重复」不成立；
# 复核已通过后再 --force 是请复核方重新复核（retry 会清掉原结论），不是重发
REASSIGN_HEADER = "【改派】这项任务改由你接手，请按下面的内容处理。"
REREVIEW_HEADER = "【重新复核】请重新复核下面的内容；之前的复核结论已作废。"
_FORCE_HEADERS = (RESEND_HEADER, REASSIGN_HEADER, REREVIEW_HEADER)


def _rework_body(first: Attempt, current: Attempt, task: Task, extra: str | None, reassigned: bool = False,
                 names: NameBook = NO_NAMES) -> str:
    """返工或强制重发的新正文；本机 retry 与跨设备 retry_task 共用（后者经回调传入）。

    reassigned：`--to` 改派到另一个会话，新执行方没有给过「上次的结论／说明」，改称「上一位执行方的…」。
    交过结果后的返工把发起方的要求放在最前；--force 而对方还没交结果时不写「意见」，正文接最近一次实际发出的那条
    （不是首条任务正文），首行三选一：改派到另一个会话写「改由你接手」（改派优先），复核已通过后写「请重新复核」，
    其余写【重发】「可能已经送达」。
    超过正文上限时截断末尾并标「…（已截断）」（长要求请改用 --ref，docs/ab.md 写明）。
    """
    result = current.result if isinstance(current.result, dict) else {}
    note = result.get("note")
    note = note if isinstance(note, str) and note else None
    whose = "上一位执行方的" if reassigned else "你上次的"
    files = [line for line in _describe_result(result or None) if not line.startswith("说明：")]
    if current.role is Role.REVIEW and task.verdict is Verdict.CHANGES:
        # 「意见」是复核方的话，标签不变
        lines = [REWORK_HEADER, f"复核方 {names.local_wire(current.target)} 要求修改。"]
        if note:
            lines.append(f"意见：{note}")
        lines.extend(files)
        if extra:
            lines.append(f"补充：{extra}")
    elif current.work is Work.BLOCKED:
        lines = [REWORK_HEADER, "上次处理受阻，情况已处理，请继续。"]  # 措辞照旧（受阻时没有结果记录）
        if note:
            lines.append(f"意见：{note}")
        lines.extend(files)
        if extra:
            lines.append(f"补充：{extra}")
    elif current.work is Work.FAILED:
        lines = [REWORK_HEADER, "上次未能完成，请按下面的要求重新处理。"]
        if note:
            lines.append(f"{whose}说明：{note}")
        lines.extend(files)
        if extra:
            lines.append(f"补充：{extra}")
    elif current.work is Work.RESULT and current.role is Role.HANDOFF:
        # 交过结果后：发起方的要求在最前，执行方自己的结论不再标成「意见」
        if extra:
            lines = [REWORK_HEADER, "发起方看过结果，请按下面的要求继续：", extra.rstrip()]
        else:
            lines = [REWORK_HEADER, "发起方看过结果，请继续处理。"]
        if note:
            lines.append(f"{whose}结论：{note}")
        lines.extend(files)
    else:
        # --force：对方还没交结果（或复核方已给过结论）。正文取最近一次实际发出的那条（§104.9 四补定）：上一轮的返工
        # 要求不会丢，复核尝试收到的是复核请求本身；去掉其中已有的首行以免嵌套
        if reassigned:
            header = REASSIGN_HEADER
        elif current.role is Role.REVIEW and task.verdict is Verdict.APPROVED:
            header = REREVIEW_HEADER
        else:
            header = RESEND_HEADER
        lines = [header]
        if extra:
            lines.append(f"补充：{extra}")
        lines.extend(["", _without_resend_header(current.body).rstrip()])
        return _bounded_body("\n".join(lines))
    lines.extend(["", "【原始任务要求】", first.body.rstrip()])
    return _bounded_body("\n".join(lines))


def _without_resend_header(body: str) -> str:
    """去掉上一次 --force 加的首行（重发、改派、重新复核三种之一；连续 --force 只保留一个首行）；其余内容（含当时的
    「补充：」）原样保留。"""
    head, _, rest = body.partition("\n")
    return rest.lstrip("\n") if head in _FORCE_HEADERS else body


def _bounded_body(text: str) -> str:
    """返工/重发正文的上限：超过 MAX_BODY_BYTES 截断末尾并标「…（已截断）」（长要求请改用 --ref）。"""
    encoded = text.encode("utf-8")
    if len(encoded) > MAX_BODY_BYTES:
        return encoded[: MAX_BODY_BYTES - 64].decode("utf-8", errors="ignore") + "\n…（已截断）"
    return text


def cmd_retry(args: argparse.Namespace) -> int:
    _reject_blank_selectors(args, ("to", "device"))  # retry --to "" 不再静默变成不改派（§101.2）
    # 可选正文：-m 文本、-m -、--file 统一读进 args.message（§104.4）；没给时不碰 stdin，「-」不再被当成字面文本
    args.message = _read_optional_body(args)
    found = _fed_lookup(args, write=True)
    if found is not None:
        return _fed_retry(args, *found)
    if args.device:
        raise CliError("target_is_local_device", EXIT_TARGET)
    cwd = Path.cwd()
    named = _named_refs(args.ref, cwd)  # 只解析、去重路径；读不读文件要看继承集合（§104.12 第 9 条）
    endpoints = discover()
    caller = identify_caller(endpoints)
    now = time.time()
    with _open_store() as store:
        hashed = _retry_fresh_refs(store, args, named, cwd)  # 事务外只为新增路径算 sha256
        # 校验、作废过时回执、追加返工尝试必须在同一个事务里（Codex 复审 F01）。分成多次提交时，
        # 提交间隙里另一连接可能已经汇报出新一轮结果、或并发 close 排了结束回执，随后的全量扫描
        # 会把它们一起作废；追加成功而作废失败还会留下「返工已落账却返回错误」的半完成命令。
        # 端点发现在事务外做，事务内重做全部校验——世界变了就照常抛原来那些错误。
        try:
            with store.transaction():
                attempt, undelivered, rework = _retry_in_transaction(store, args, endpoints, caller, now,
                                                                     named_refs=named, hashed_refs=hashed, cwd=cwd)
        except StoreError as error:
            raise CliError(error.code, _exit_for_store_error(error.code)) from error
        started = _start_worker()
        notes = _retry_notes(attempt.seq, duplicate=bool(args.force) and not undelivered and not rework)
        document: dict[str, object] | None = None
        if getattr(args, "json", False):
            # 与 send --json 同一份任务文档，另标命令与新尝试（§93.2）；scope 与跨设备文档对应
            current = store.get_task(attempt.task_id)
            if current is None:
                raise CliError("task_not_found", EXIT_TARGET)
            document = _task_document(store, current, names=NameBook.of(endpoints))
            document.update(ok=True, scope="local", command="retry",
                            retried={"seq": attempt.seq, "role": attempt.role.value})
        else:
            print(f"已排队第 {attempt.seq} 次{ROLE_LABELS[attempt.role]} → {NameBook.of(endpoints).text(attempt.target)}（任务 {short(attempt.task_id)}）")
            if attempt.seq >= ATTEMPT_WARNING_THRESHOLD:
                print(f"提示：{reason_text('attempts_near_limit')}")
            if args.force and not undelivered and not rework:
                print("注意：上一条消息可能已送达，对方可能重复执行")
    unavailable = _queued_without_worker(started)
    if document is not None:
        document["notes"] = notes + (["worker_not_running"] if unavailable else [])
        _print_json(document)
    return EXIT_UNAVAILABLE if unavailable else EXIT_OK


def _retry_notes(seq: int, *, duplicate: bool) -> list[str]:
    """retry `--json` 的 notes：接近交接上限、上一条可能已送达而强制重发（对应文字模式的「提示」「注意」）。"""
    notes: list[str] = []
    if seq >= ATTEMPT_WARNING_THRESHOLD:
        notes.append("attempts_near_limit")
    if duplicate:
        notes.append("retry_may_duplicate")
    return notes


def _retry_in_transaction(
    store: Store, args: argparse.Namespace, endpoints: list[Endpoint], caller: Caller, now: float,
    *, named_refs: dict[str, str] | None = None, hashed_refs: dict[str, dict[str, object]] | None = None,
    cwd: Path | None = None,
) -> tuple[Attempt, bool, bool]:
    """在调用方开启的事务内完成返工：重新校验 → 作废过时回执 → 追加新尝试 → 更新任务。

    named_refs 是去重后的 --ref 点名（解析后的路径 → 原样点名），hashed_refs 是事务外已为新增路径算好的引用。
    """
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
    rework = retry_is_rework(task, current)
    if not (undelivered or rework or args.force):
        raise CliError("retry_requires_force")
    role = current.role
    target_ref = current.target
    resend = undelivered and not rework
    if not resend and current.role is Role.REVIEW and task.verdict is Verdict.CHANGES:
        role = Role.HANDOFF
        implementer = next((item for item in reversed(attempts) if item.role is Role.HANDOFF), first)
        target_ref = implementer.target
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
    if resend:
        body = current.body
        if args.message:
            body = f"{body}\n\n补充：{args.message}"
    else:
        # 正文在目标解析之后生成：--to 改派到另一个会话时，结论／说明改称「上一位执行方的…」（§104.4）
        body = _rework_body(first, current, task, args.message, reassigned=not target_ref.same_session(current.target),
                            names=NameBook.of(endpoints))
    # retry --ref 追加在继承的附件之后（§104.4）；继承哪一条见 retry_inherits_first（§104.11 第 5 条）。
    # 按此刻真正的继承集合算净增量（§104.12 第 9 条）：已继承的点名不读文件，先判个数再补算事务外没算到的新增路径；
    # 在作废旧回执之前判合并后的上限，超出时事务里还没有任何写入
    base = _retry_base_refs(task, attempts)
    known = {item.get("path") for item in base}
    fresh = {key: raw for key, raw in (named_refs or {}).items() if key not in known}
    if refs_over_limit(len(base), len(base) + len(fresh)):
        raise CliError("too_many_files")
    hashed = hashed_refs or {}
    extra = [hashed[key] if key in hashed else file_reference(raw, cwd=cwd or Path.cwd()) for key, raw in fresh.items()]
    refs = _merge_refs(base, extra)
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
        refs=refs,
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


# ab note（DESIGN §95.5.2）：当前工作尝试已发出（可能已到对方）且尚未终态汇报，才有可补充的对象
_NOTE_SENT = frozenset(MAY_HAVE_ARRIVED | {Delivery.SENDING})
_NOTE_OPEN_WORK = frozenset({Work.AWAITING_ACK, Work.ACKNOWLEDGED, Work.IN_PROGRESS})


def cmd_note(args: argparse.Namespace) -> int:
    """`ab note`：给进行中的执行方补一句话（DESIGN §95.5）。

    新增一条 noticeKind=note 的 notice 尝试，目标是当前工作尝试实际投递的端点；不改变当前工作尝试，
    接收方不汇报这条。不做权限校验（寻址由任务决定）；调用方归属沿用 send 的规则，免得 agent 冒充用户。
    跨设备任务只在发起设备上建尝试（§95.5.5）。
    """
    found = _fed_lookup(args, write=True)
    if found is not None:
        return _fed_note(args, *found)
    body = _read_body(args)
    refs = _local_refs(args.ref)
    endpoints = discover()
    caller = identify_caller(endpoints)
    _check_sender(caller)
    now = time.time()
    with _open_store() as store:
        try:
            with store.transaction():
                note = _note_in_transaction(store, args, body, caller, now, refs=refs)
        except StoreError as error:
            raise CliError(error.code, _exit_for_store_error(error.code)) from error
        started = _start_worker()
        names = NameBook.of(endpoints)
        for_seq = note.note_for_seq
        notes = ["attempts_near_limit"] if note.seq >= ATTEMPT_WARNING_THRESHOLD else []
        document: dict[str, object] | None = None
        if getattr(args, "json", False):
            current = store.get_task(note.task_id)
            if current is None:
                raise CliError("task_not_found", EXIT_TARGET)
            document = _task_document(store, current, names=names)
            document.update(ok=True, scope="local", command="note", noted={"seq": note.seq, "forSeq": for_seq})
        else:
            print(f"已排队补充 #{note.seq} → {names.text(note.target)}（任务 {short(note.task_id)} 第 {for_seq} 次尝试；"
                  f"对方不需要汇报这条）")
            if notes:
                print(f"提示：{reason_text('attempts_near_limit')}")
    unavailable = _queued_without_worker(started)
    if document is not None:
        document["notes"] = notes + (["worker_not_running"] if unavailable else [])
        _print_json(document)
    return EXIT_UNAVAILABLE if unavailable else EXIT_OK


def _note_in_transaction(store: Store, args: argparse.Namespace, body: str, caller: Caller, now: float,
                         *, refs: list[dict[str, object]] | None = None) -> Attempt:
    """在调用方开启的事务内：重新校验可补充的工作尝试并追加 note，校验与写入之间不留窗口（同 retry）。"""
    task = _task(store, args.task)
    if task.finished:
        raise CliError("note_no_active_attempt")
    if task.paused:
        raise CliError("note_task_paused")
    working = work_attempts(store.attempts(task.id))
    current = working[-1] if working else None
    if current is None or current.delivery not in _NOTE_SENT or current.work not in _NOTE_OPEN_WORK:
        raise CliError("note_no_active_attempt")
    return store.add_attempt(
        task.id,
        role=Role.NOTICE,
        # 投给对方实际收到工作尝试的那个端点（与结束回执同口径）；选定代际退出时由 worker 接续同会话
        target=delivered_endpoint(current),
        body=body,
        refs=list(refs or []),  # note --ref（§104.4）：envelope 照常渲染「引用文件：」
        now=now,
        sender=caller.endpoint.ref if caller.endpoint is not None else None,
        sender_class=permission_class(caller),
        options={NOTICE_KIND_OPTION: NOTE_KIND, FOR_SEQ_OPTION: current.seq, "allowShared": current.allow_shared},
        event="note_created",
    )


def _agent_session(caller: Caller, code: str) -> Endpoint:
    """remind/todo 的调用方必须是认得出的 agent 会话（按会话 ID 认）；用户终端、认不出的会话与子代理报 code。"""
    if caller.rejection is not None or caller.endpoint is None or caller.endpoint.ref.native_id == UNRESOLVED_NATIVE_ID:
        raise CliError(code)
    return caller.endpoint


def _remind_body(args: argparse.Namespace) -> str:
    """remind 的提醒内容：-m 文本、-m -（标准输入）或 --file；都没给时报空，不隐式读标准输入（agent shell 里会卡住）。"""
    if args.message is None and not args.file:
        raise CliError("empty_message")
    body = _read_body(args)
    if not body.strip():
        raise CliError("empty_message")
    return body


def cmd_remind(args: argparse.Namespace) -> int:
    """`ab remind`（DESIGN §104.9 二）：给调用会话自己排一条定时提醒，到点作为 role=notice 送回本会话。

    实现是「发给自己的告知」加延迟投递：建即关闭的 fyi 任务，尝试 options {deferUntil, remind:true}；消息由桥代发
    （from=user），叫醒的那一轮不静默。只有这条命令允许目标等于调用方；`--list` 列出本会话未发出的定时提醒，
    取消用 `ab cancel <ID>`。
    """
    if args.list:
        return _remind_list(args)
    seconds = _duration_arg(args.in_, "in_invalid", minimum=60.0, maximum=MAX_DEFER_SECONDS)
    if seconds is None:
        raise CliError("in_invalid")
    body = _remind_body(args)
    endpoints = discover()
    caller = identify_caller(endpoints)
    me = _agent_session(caller, "remind_requires_session")
    # 自己就收不了（只读 provider、没有收件 socket 等）时写前就拒绝；共享 thread 与 send 同一判定（§104.11 P3）：
    # 调用方自己的 thread 被多个进程加载时，提醒可能由另一个进程执行，要显式 --allow-shared
    allow_shared = bool(args.allow_shared)
    _check_target(me, allow_shared=allow_shared)
    now = time.time()
    due = now + seconds
    first_line = body.strip().splitlines()[0]
    with _open_store() as store:
        try:
            task, attempt = store.create_fyi(
                title=(args.title or first_line)[:60], origin=me.ref, origin_class=permission_class(caller),
                target=me.ref, body=body, refs=[], now=now,
                task_options={"allowShared": allow_shared},
                attempt_options={"allowShared": allow_shared, DEFER_OPTION: due, REMIND_OPTION: True},
                bridge_sender=True)
        except StoreError as error:
            raise CliError(error.code, _exit_for_store_error(error.code)) from error
        started = _start_worker()
        document = _task_document(store, task, names=NameBook.of(endpoints)) if args.json else None
    unavailable = _queued_without_worker(started)
    if document is not None:
        document["remindAt"] = due
        document["notes"] = ["worker_not_running"] if unavailable else []
        _print_json(document)
    else:
        cmd = command_name()
        print(f"定时提醒 {short(task.id)} 已排定：{clock_text(due)} 送回本会话（#{attempt.seq}）")
        print(f"取消：{cmd} cancel {short(task.id)}；查看未到期的：{cmd} remind --list")
    return EXIT_UNAVAILABLE if unavailable else EXIT_OK


def _remind_list(args: argparse.Namespace) -> int:
    """本会话还没发出的定时提醒（本机账本里 PENDING 且 remind 的尝试），按到期时刻排序。"""
    caller = identify_caller(discover())
    me = _agent_session(caller, "remind_requires_session")
    rows: list[dict[str, object]] = []
    with _open_store() as store:
        pending = [item for item in store.attempts_in((Delivery.PENDING,))
                   if item.is_remind and item.target.same_session(me.ref)]
        for item in sorted(pending, key=lambda attempt: attempt.defer_until or 0.0):
            task = store.get_task(item.task_id)
            rows.append({"taskId": item.task_id, "short": short(item.task_id), "remindAt": item.defer_until,
                         "title": task.title if task is not None else ""})
    if args.json:
        _print_json({"reminders": rows})
        return EXIT_OK
    if not rows:
        print("没有未发出的定时提醒")
    for row in rows:
        due = row["remindAt"]
        when = clock_text(due) if isinstance(due, float) else "-"
        print(f"{row['short']}  {when}  {str(row['title'])[:60]}")
    return EXIT_OK


def cmd_todo(args: argparse.Namespace) -> int:
    """`ab todo`（DESIGN §104.3、§104.9 六）：只列调用会话要动手的事，每行一项带可照抄的命令；没有就什么都不输出。

    身份与 `ab tasks --mine` 同口径（按会话 ID），认不出的会话报 mine_requires_session。包括本机任务、本机为权威的
    联邦任务，以及发给本会话的镜像尝试（命令带 --origin-device）。联邦库读不了时 stdout 不出联邦行、stderr 注明，退出 0。
    """
    now = time.time()
    caller = identify_caller(discover())
    me = _agent_session(caller, "mine_requires_session").ref
    cmd = command_name()
    items: list[TodoItem] = []
    if (state_dir() / DB_NAME).is_file():
        with _open_store() as store:
            for task in store.list_tasks():
                items.extend(todo_items(task, store.attempts(task.id), me, now=now, command=cmd))
    federated = _fed_todo(me, now, cmd)
    if federated is None:
        print(f"跨设备任务：联邦库不可读，没有列出（{cmd} doctor 查看原因）", file=sys.stderr)
    else:
        items.extend(federated)
    if args.json:
        _print_json([item.to_dict() for item in items])
        return EXIT_OK
    for item in items:
        print(todo_line(item))
    return EXIT_OK


def _fed_todo(me: EndpointRef, now: float, cmd: str) -> list[TodoItem] | None:
    """todo 的联邦部分：未配置为 []；库读不了为 None。A 上的权威任务按本机同一判定，镜像只看发给本会话的汇报项。"""
    root = state_dir()
    if not _fed_configured(root):
        return []
    from .federation import authority as fed_authority, commands as fed, mirror  # layout: allow 联邦按需加载
    from .federation.codec import is_slug  # layout: allow 联邦按需加载
    from .federation.views import model_attempts, model_task  # layout: allow 联邦按需加载
    try:
        rt = fed.try_runtime(root)
    except (StoreError, sqlite3.Error):
        rt = None
    if rt is None:
        return None
    items: list[TodoItem] = []
    try:
        for task in rt.store.tasks():
            if task.is_authority:
                # 标题保留原值：--json 照给，文字行由 todo.text_line 按来源转义（§104.12 第 11 条）
                # 命令用完整 ID 加 --origin-device <本机>（§104.13 第 2 条）：两库同 ID 时也只作用到联邦这一项
                items.extend(todo_items(model_task(task), model_attempts(rt.store.attempts(task.authority_device,
                                                                                         task.task_id)),
                                        me, now=now, command=cmd, scope="federation",
                                        command_ref=fed_authority.command_ref(rt.ident, task.task_id)))
                continue
            work = mirror.local_report_target(rt.store, rt.ident, task) if rt.config.enabled else None
            local = mirror.local_binding(work) if work is not None else None
            if work is None or local is None or not local.same_session(me):
                continue
            view = model_attempts([work])[0]
            if view.delivery not in HANDED_OVER:
                continue  # 待你汇报只列已交出的尝试，与本机同一判据（§104.12 第 2 条）
            name = fed.device_name(rt, task.authority_device)
            # 与镜像页脚同口径：登记名是 slug 就用名，否则完整 deviceId（§101.1）
            reference = name if is_slug(name) else task.authority_device
            items.append(todo_report_item(task.task_id, task.title, view, command=cmd, scope="federation",
                                          origin_device=reference))
    except (StoreError, sqlite3.Error):
        return None
    finally:
        rt.close()
    return items


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


def _local_task_state(root: Path, reference: str) -> tuple[str, str | None]:
    """本机账本对该引用的解析结果与命中的完整 ID：found（恰好命中一项）、absent（没有）、error（本机歧义或账本错误）。

    error 一律交本机路径原样报错（§88.7 命名空间），联邦不再参与；只有 found 才与联邦命中比较是否跨库歧义。
    """
    if not (root / DB_NAME).is_file():
        return "absent", None
    try:
        with Store.open(root) as store:
            found = store.resolve_task(reference)
    except StoreError as error:
        return ("absent" if error.code == "task_not_found" else "error"), None
    except PermissionError:
        return "error", None
    return "found", found.id


def _federation_twin(root: Path, reference: str, local_id: str) -> str | None:
    """本机已命中时，联邦库里有没有也匹配这个引用的任务（§104.13 第 1 条）；有就返回提示文字，没有返回 None。

    只用只读连接（不走可写的联邦运行时、不迁移）。判定与提示分开（§104.14 第 1 条）：
    - 配置读不了、根不符、库打不开、实例身份（deviceId/hubId）与配置不配对（§104.14 第 6 条，与普通运行时同一判据），
      或任务索引本身读不了：按「没有」处理，只看本机；
    - 索引里查到了就一定拒绝；设备名只用于提示，读不了时提示改用这条记录自带的 authorityDeviceId。
    两库完整 ID 相同时提示写明只能用 --origin-device 选联邦，本机那项目前选不了（§104.14 第 7 条）。
    """
    from .federation import config as fed_config  # layout: allow 联邦按需加载
    from .federation.codec import is_slug  # layout: allow 联邦按需加载
    from .federation.fedstore import FederatedStore as FedStore  # layout: allow 联邦按需加载
    try:
        config = fed_config.load(root)
        if config is None:
            return None
        fed_config.check_state_root(config, root)
        fed_store = FedStore.open_readonly(root)
    except Exception:  # noqa: BLE001 - 联邦库读不了时只看本机（§104.13 第 1 条）
        return None
    try:
        try:
            if (fed_store.meta("deviceId"), fed_store.meta("hubId")) != (config.device_id, config.hub_id):
                return None  # 实例身份不配对：这份索引不属于当前联邦实例，不参与查重
            found = fed_store.find_tasks(reference)
        except Exception:  # noqa: BLE001 - 任务索引本身读不了：只看本机
            return None
        if not found:
            return None
        twin = found[0]
        try:
            if twin.authority_device == config.device_id:
                name = config.device_name
            else:
                name = next((str(row["name"]) for row in fed_store.device_states()
                             if row["device_id"] == twin.authority_device and row["name"]), "")
        except Exception:  # noqa: BLE001 - 设备名只影响提示：读不了就用记录里的 authorityDeviceId
            name = ""
    finally:
        fed_store.close()
    device = name if is_slug(name) else twin.authority_device
    routed = f"{twin.task_id} --origin-device {device}"
    if twin.task_id == local_id:
        return (f"本机账本与跨设备账本里有完整 ID 相同的任务：只能用 --origin-device 选跨设备那项，例如 {routed}；"
                "本机那项目前选不了（已知限制）")
    return (f"本机账本与跨设备账本都有匹配「{remote_display(reference) or ''}」的任务：本机那项请写完整任务 ID；"
            f"跨设备那项请加 --origin-device，例如 {routed}")


def _fed_configured(root: Path) -> bool:
    """只看配置文件在不在（与摘要同一个文件名）：未配置的机器在这一步就返回，不导入联邦实现（实现决定 D20）。"""
    return (root / summary.FEDERATION_CONFIG).exists()


def _fed_lookup(args: argparse.Namespace, *, write: bool) -> tuple[FedRuntime, FedTask] | None:
    """显式 --origin-device 只查联邦；否则本机与联邦都查，同时命中报 task_ambiguous（§104.13 第 1 条）。

    以前本机精确命中优先，生成的短号命令会在两库前八位相同时作用到本机那一项；现在一律拒绝并提示写法。
    本机歧义或账本错误交本机路径原样报错；联邦库读不了（打不开、损坏）时只看本机，不挡住本机命中。
    两库完整 ID 相同时只能用 --origin-device 选联邦，本机那项选不了（随机 128 位 ID 不会相撞，已知限制）。
    写命令要求联邦已启用（停用后仍可读历史）。
    """
    root = state_dir()
    origin = getattr(args, "origin_device", None)
    if origin is None and not _fed_configured(root):
        return None
    from .federation import commands as fed  # layout: allow 联邦按需加载：未配置的机器不导入联邦实现
    if origin is None:
        local, local_id = _local_task_state(root, args.task)
        if local == "error":
            return None
        if local == "found" and local_id is not None:
            # 本机命中：只读查联邦有没有同样匹配的，有就拒绝（不再本机优先）；联邦读不了照常走本机
            hint = _federation_twin(root, args.task, local_id)
            if hint is not None:
                raise FedCliError("task_ambiguous", EXIT_TARGET, hint=hint)
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
    from .federation.views import remote_text  # layout: allow 联邦按需加载
    return remote_text(target, fed.device_name(rt, remote.device_id))


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


def _fed_send(args: argparse.Namespace, *, follows: str | None = None) -> int:
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
        return _local_send(args, body=body, follows=follows)  # 两个参与方都在本机：就是本机任务（正文已读，不重读 stdin）
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
                reviewer = fed.remote_target(rt, args.review_device, args.review_by,
                                             flags=("--review-device", "--review-by"))
        elif args.review_device:
            raise CliError("review_device_requires_reviewer")
        first_line = body.strip().splitlines()[0] if body.strip() else ""
        fyi = bool(getattr(args, "fyi", False))
        outcome = fed.send(
            rt, target=target, body=body, title=(args.title or first_line)[:60], ref_paths=list(args.ref),
            cwd=Path.cwd(), origin=caller.endpoint.ref if caller.endpoint is not None else None,
            origin_class=permission_class(caller), reviewer=reviewer, allow_shared=bool(args.allow_shared),
            no_notify=bool(args.no_notify), follows=follows, fyi=fyi,
            expect=getattr(args, "expect_seconds", None), after=getattr(args, "defer_seconds", None))
        missing = _fed_relay_missing(rt)
        task_id = outcome.task.task_id
        if args.json:
            _print_json(fed.task_document(rt, outcome.task, now=int(time.time() * 1000)))
        elif fyi:
            print(f"跨设备告知 {short(task_id)} 已排队，发给 {_fed_target_text(rt, outcome.target)}："
                  f"{_fed_send_when(rt, outcome.attempt)}；对方只需读到，不汇报、不验收")
            print(f"查看投递：{command_name()} status {short(task_id)}")
        else:
            print(f"跨设备任务 {short(task_id)} 已记录，交给 {_fed_target_text(rt, outcome.target)}："
                  f"{_fed_send_when(rt, outcome.attempt)}")
            if outcome.blobs or outcome.references:
                print(f"附件：{outcome.blobs} 个随消息传输（{outcome.blob_bytes} B），"
                      f"{outcome.references} 个超出大小上限只作引用（对方没有这些文件）")
            cmd = command_name()
            print(f"查看进展：{cmd} status {short(task_id)}；等待结果：{cmd} wait {short(task_id)}")
    finally:
        rt.close()
    return EXIT_UNAVAILABLE if missing else EXIT_OK


def _fed_send_when(rt: FedRuntime, attempt: FedAttempt) -> str:
    """跨设备 send/--fyi 的「何时发出」（§104.11 P3）：远端目标由 relay 交给 hub；目标在本机（A 本机执行方）由本机后台
    worker 投递，定时项到点由 relay 拉起 worker。带 --after 时写出定时时刻。"""
    due = defer_time(attempt.options)
    who = "本机后台 worker " if attempt.target_device == rt.ident.device_id else " relay "
    return f"定时 {clock_text(due)} 由{who}发出" if due is not None else f"等待{who}发出"


def _fed_task_list(include_finished: bool, now: float,
                   wanted: TaskFilter | None = None) -> tuple[list[dict[str, object]], list[str]] | None:
    """tasks 的联邦部分：未配置返回 None（输出不变）；库不可读只注明，不影响本机行；筛选与本机同一组条件（§93.1）。"""
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
        for task in fed.list_tasks(rt, include_finished=include_finished, wanted=wanted):
            document = fed.task_document(rt, task, now=now_ms)
            documents.append(document)
            view = fed.view_of(rt, task)
            target = "-"
            if view.current is not None:
                row = next((item for item in document["attempts"] if item["seq"] == view.current.seq), None)
                where = f"{fed.device_text(row['targetDeviceName'])}:" if row is not None else ""
                # 跨设备：设备名 + 完整 ID，不用对端名字（§91.4.2）；ID 可能来自远端，同 peers 文字行转义（§101.1）
                target = where + fed.target_text(NO_NAMES.text(view.current.target))
            role = "本机发起" if task.is_authority else f"发起设备 {fed.device_text(document['authorityDeviceName'])}"
            flag = "，需处理：远端离线/传输未恢复" if document["stalled"] else ""
            phase, reason = PHASE_LABELS[view.phase], fed.reason_label(rt, task, view)
            rows = document["attempts"]
            if task.is_fyi and isinstance(rows, list) and rows:
                # 一句话告知（§95.5.7）：阶段列写「告知」，目标取那条告知，原因写投递状态
                first = rows[0]
                target = f"{fed.device_text(first['targetDeviceName'])}:{fed.target_text(first['target'])}"
                phase, reason = FYI_LABEL, f"投递 {fed.delivery_text(first['delivery'])}"
            # 标题先截后转义：免得把转义序列截成半截（§103.3）
            lines.append(f"{short(task.task_id)}  {phase:<4} {target:<28} {fed.title_text(task.title[:40])}"
                         f"  （跨设备·{role}，{reason}{flag}，{_age(task.last_sync_at / 1000, now)}）")
        return documents, lines
    finally:
        rt.close()


def _fed_status(args: argparse.Namespace, rt: FedRuntime, task: FedTask) -> int:
    from .federation import commands as fed  # layout: allow 联邦按需加载
    try:
        now_ms = int(time.time() * 1000)
        follows = task.state.get("follows")
        relations, followed_by = _follow_links(task.task_id, follows if isinstance(follows, str) else None,
                                               fed_store=rt.store)
        if args.json:
            document = fed.task_document(rt, task, now=now_ms, include_body=args.body, events=True)
            if followed_by:
                document["followedBy"] = followed_by
            _print_json(document)
        else:
            lines = fed.task_lines(rt, task, now=now_ms, show_body=args.body)
            lines[2:2] = [f"  {line}" for line in relations]  # 标题行与角色行之后，缩进与联邦 status 其余行一致（§93.3）
            for line in lines:
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
            cwd=Path.cwd(), ask=bool(getattr(args, "ask", False)))
        started: bool | None = True
        if result.decision == "accepted":
            started = _start_worker()  # A 本机采纳可能排出本机通知/复核
        missing = _fed_relay_missing(rt)
        # 对方设备没声明 ask 能力（旧版或判断不了）时提示改用 --blocked；文字与 --json 都给（§104.11 P3）
        warnings = ([ASK_OLD_AUTHORITY_HINT] if getattr(args, "ask", False) and not fed.authority_supports_ask(rt, task)
                    else [])
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
            document["warnings"] = warnings
            _print_json(document)
        else:
            label = "提问（任务仍在进行）" if getattr(args, "ask", False) else EVENT_LABELS[kind.value]
            print(f"已记录：{label}（跨设备任务 {short(task.task_id)} #{attempt.seq}，"
                  f"第 {result.report_no} 号报告）；{status}")
            for warning in warnings:
                print(f"提示：{warning}")
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
                    print(f"等待超时：{PHASE_LABELS[view.phase]}（{fed.reason_label(rt, current, view)}）")
                return EXIT_TIMEOUT
            time.sleep(1.0)
    finally:
        rt.close()


def _fed_control(args: argparse.Namespace, action: str, rt: FedRuntime, task: FedTask) -> int:
    """pause/resume/cancel：只在发起设备；cancel 对远端只是抑制请求，不是原生撤回。"""
    from .federation import commands as fed  # layout: allow 联邦按需加载
    as_json = bool(getattr(args, "json", False))
    try:
        caller = identify_caller(discover())
        current, remote_pending = fed.set_control(rt, task, action, caller=caller)
        if not as_json:
            text = {"pause": "已暂停发送；已交给对方的消息不受影响", "resume": "继续发送",
                    "cancel": "已请求取消尚未发出的消息"}[action]
            print(f"跨设备任务 {short(task.task_id)} {text}")
            if remote_pending:
                print("对方设备尚未确认：它收到最新状态后抑制还没发出的作业；已发出的不能撤回")
        if action == "resume":
            _start_worker()
        missing = _fed_relay_missing(rt)
        if as_json:
            notes = (["remote_unconfirmed"] if remote_pending else []) + (["relay_not_running"] if missing else [])
            document = _decision_document(action, "federation", task.task_id,
                                          control=str(current.state.get("control", "active")), notes=notes)
            if action == "cancel":
                # 远端只是抑制请求：本机不知道对方实际取消了几条（§88.7）
                document.update(cancelled=None, cancelRequested=True)
            _print_json(document)
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
            document: dict[str, object] = {
                "ok": True, "id": task.task_id, "scope": "federation",
                "phase": fed.phase_of(rt, outcome.task)[0].value,
                "closure": {"queued": [{"seq": item.seq, "targetDevice": item.target_device}
                                       for item in outcome.closures],
                            "skipped": list(outcome.skipped),
                            "remoteUnconfirmed": outcome.remote_unconfirmed}}
            if state == CLOSED:
                # close 补 command 与 notes（§93.2）；accept 的跨设备 JSON 保持原有键
                document.update(command="close", notes=(["remote_unconfirmed"] if outcome.remote_unconfirmed else [])
                                + (["relay_not_running"] if missing else []))
            _print_json(document)
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


def _fed_note(args: argparse.Namespace, rt: FedRuntime, task: FedTask) -> int:
    """跨设备 `ab note`：发起设备上追加 note；本机目标拉起 worker，远端目标经 relay 送达。"""
    from .federation import commands as fed  # layout: allow 联邦按需加载
    try:
        body = _read_body(args)
        endpoints = discover()
        caller = identify_caller(endpoints)
        _check_sender(caller)
        note = fed.note(rt, task, caller=caller, caller_class=permission_class(caller), body=body,
                        ref_paths=list(args.ref), cwd=Path.cwd())
        local = note.target_device == rt.ident.device_id
        started = _start_worker() if local else True
        missing = False if local else _fed_relay_missing(rt)
        for_seq = note.options.get(FOR_SEQ_OPTION)
        notes = ["attempts_near_limit"] if note.seq >= ATTEMPT_WARNING_THRESHOLD else []
        document: dict[str, Any] | None = None
        if getattr(args, "json", False):
            current = rt.store.get_task(task.authority_device, task.task_id) or task
            document = fed.task_document(rt, current, now=int(time.time() * 1000))
            document.update(ok=True, command="note", noted={"seq": note.seq, "forSeq": for_seq})
        else:
            print(f"已排队补充 #{note.seq} → {_fed_target_text(rt, note.target)}（跨设备任务 {short(task.task_id)}"
                  f" 第 {for_seq} 次尝试；对方不需要汇报这条）")
            if notes:
                print(f"提示：{reason_text('attempts_near_limit')}")
    finally:
        rt.close()
    worker_down = _queued_without_worker(started)
    if document is not None:
        document["notes"] = notes + (["worker_not_running"] if worker_down else []) + (
            ["relay_not_running"] if missing else [])
        _print_json(document)
    return EXIT_UNAVAILABLE if worker_down or missing else EXIT_OK


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
                            new_target=new_target, allow_shared=bool(args.allow_shared), rework_body=_rework_body,
                            ref_paths=list(args.ref), cwd=Path.cwd())
        attempt = outcome.attempt
        local = attempt.target_device == rt.ident.device_id
        started = _start_worker() if local else True
        missing = False if local else _fed_relay_missing(rt)
        notes = _retry_notes(attempt.seq, duplicate=bool(args.force) and not outcome.undelivered and not outcome.rework)
        document: dict[str, Any] | None = None
        if getattr(args, "json", False):
            current = rt.store.get_task(task.authority_device, task.task_id) or outcome.task
            document = fed.task_document(rt, current, now=int(time.time() * 1000))
            document.update(ok=True, command="retry", retried={"seq": attempt.seq, "role": attempt.role})
        else:
            print(f"已排队第 {attempt.seq} 次{ROLE_LABELS[Role(attempt.role)]} → {_fed_target_text(rt, attempt.target)}"
                  f"（跨设备任务 {short(task.task_id)}）")
            if attempt.seq >= ATTEMPT_WARNING_THRESHOLD:
                print(f"提示：{reason_text('attempts_near_limit')}")
            if args.force and not outcome.undelivered and not outcome.rework:
                print("注意：上一条消息可能已送达，对方可能重复执行")
    finally:
        rt.close()
    worker_down = _queued_without_worker(started)
    if document is not None:
        document["notes"] = (notes + (["worker_not_running"] if worker_down else [])
                             + (["relay_not_running"] if missing else []))
        _print_json(document)
    if worker_down or missing:
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
        print("跨设备协作已停用：relay 约一秒内察觉，随后中止连接、释放锁后退出（是否已停以 federation status 为准）；"
              "worker 不再领取跨设备作业；数据与附件保留，本机协作照常")
        return EXIT_OK
    if action == "status":
        # 顶层 relayRunning 先于联邦投影取得，所有分支都有（DESIGN §90.6）；维护只解析 JSON，null 绝非 false
        status = fed.federation_status(root)
        if args.json:
            _print_json(status)
            return EXIT_OK
        projection, running = status["federation"], status["relayRunning"]
        print(reason_text("federation_not_configured") if projection is None else federation_text(projection))
        print("relay 进程：" + ("运行中" if running is True else "未运行" if running is False else "未知"))
        for line in relay_diagnostics_text(projection):
            print(line)
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
        state = fed.run_relay(root, once=args.once, watch_anchor=args.watch_launch_anchor)
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
    send.add_argument("--to", required=True,
                      help="目标：provider@原生会话名、provider@id:<至少 8 位前缀或完整 ID>，或完整会话 ID")
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
    send.add_argument("--follows", metavar="TASK",
                      help="承接的旧任务（任务 ID 或唯一前缀）；只在本机记关联，不进消息，接收方需要时请写在正文里")
    send.add_argument("--fyi", action="store_true",
                      help="一句话告知：只需对方读到，不汇报、不验收（任务建立即关闭）；不能与 --review-by/--review-device/--no-notify 同用")
    send.add_argument("--after", metavar="DUR",
                      help="定时发出：1m～24h 后才投递（如 30m、2h）；到点前可 cancel，命令不等首投")
    send.add_argument("--expect", metavar="DUR",
                      help="对方多久没汇报算沉默（5m～24h，缺省 30m）：满了提醒发起方一次；长任务用 --progress 保活")
    send.add_argument("--json", action="store_true")
    send.set_defaults(handler=cmd_send)

    remind = commands.add_parser(
        "remind", help="给本会话排一条定时提醒（到点送回本会话）",
        description="给调用会话自己排一条定时提醒：到点作为 role=notice 送回本会话，取消用 cancel <ID>。")
    remind.add_argument("--in", dest="in_", metavar="DUR", help="多久之后提醒：1m～24h（如 31m、2h）")
    remind.add_argument("-m", "--message", help="提醒内容；- 表示从标准输入读取")
    remind.add_argument("--file", help="从文件读取提醒内容")
    remind.add_argument("--title", help="标题（默认取内容第一行）")
    remind.add_argument("--list", action="store_true", help="列出本会话还没发出的定时提醒")
    remind.add_argument("--allow-shared", action="store_true",
                        help="本会话的 thread 同时被多个进程加载时仍排提醒（与 send 的 --allow-shared 同义）")
    remind.add_argument("--json", action="store_true")
    remind.set_defaults(handler=cmd_remind)

    todo = commands.add_parser("todo", help="只列本会话要动手的事（每行带可照抄的命令）",
                               description="列出调用会话的待办：待你验收、待你处理、待你汇报、待你复核、对方沉默；"
                                           "没有待办时什么都不输出。")
    todo.add_argument("--json", action="store_true")
    todo.set_defaults(handler=cmd_todo)

    tasks = commands.add_parser("tasks", help="列出协作任务")
    tasks.add_argument("--all", action="store_true", help="包含已结束的任务")
    tasks.add_argument("--mine", action="store_true",
                       help="只看调用方会话参与的任务（发起方、复核方或交接/复核目标；按会话 ID 匹配）")
    tasks.add_argument("--to", help="交接/复核目标（含改派过的）匹配：provider@名字、provider@id:<前缀> 或完整 ID")
    tasks.add_argument("--from", dest="from_session", metavar="FROM", help="发起方匹配，写法同 --to")
    tasks.add_argument("--since", help="最近活动不早于：<正整数>m/h/d（相对现在）或 YYYY-MM-DD（本机时区 0 点）")
    tasks.add_argument("--grep", help="标题或任务正文含该文字（不区分大小写的字面子串，不是正则）")
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
            "--ask 提问也会叫醒发起方，但任务不结束（发起方用 note 回答）；"
            "--ack/--progress 只记进账本，不通知、不叫醒发起方（长任务用 --progress 保活）。需要发起方或用户处理时用 --blocked。"
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
    kinds.add_argument("--ask", action="store_true",
                       help="提问：任务不结束，立即通知发起方回答（要用 --note 写问题；发起方用 note 回答）")
    report.add_argument("--note", help=f"一句话说明（上限 {MAX_NOTE_CHARS} 字，超长报错；- 表示从标准输入读取）")
    report.add_argument("--note-file", help="从文件读取说明（与 --note 二选一）；长内容请用 --file 交附件")
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
        command.add_argument("--json", action="store_true", help="成功与失败都输出结构化结果")
        command.set_defaults(handler=handler, json_errors=True)

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
    close.add_argument("--json", action="store_true", help="成功与失败都输出结构化结果")
    close.set_defaults(handler=cmd_close, json_errors=True)

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
    retry.add_argument("-m", "--message", help="补充说明或返工要求；- 表示从标准输入读取（不给 -m 时不读标准输入）")
    retry.add_argument("--file", help="从文件读取补充说明或返工要求（与 -m 二选一）")
    retry.add_argument("--ref", action="append", default=[],
                       help="追加引用文件（记录 sha256；接在原有附件之后，合计上限 16 个）")
    retry.add_argument("--force", action="store_true", help="上一条可能已送达时仍重发")
    retry.add_argument("--allow-shared", action="store_true")
    retry.add_argument("--json", action="store_true", help="成功与失败都输出结构化结果")
    retry.set_defaults(handler=cmd_retry, json_errors=True)

    note = commands.add_parser(
        "note",
        help="给进行中的执行方补一句话（不新开任务、不作废当前尝试）",
        description="给任务当前进行中的那次交接/复核补一句话：对方不需要汇报这条，继续当前尝试并照常汇报。",
    )
    note.add_argument("task")
    note.add_argument("--origin-device", help="跨设备任务的发起设备（只能在发起设备上补充）")
    note.add_argument("-m", "--message", help="补充内容；- 表示从标准输入读取")
    note.add_argument("--file", help="从文件读取补充内容")
    note.add_argument("--ref", action="append", default=[], help="附带引用文件（记录 sha256，上限 16 个）")
    note.add_argument("--json", action="store_true", help="成功与失败都输出结构化结果")
    note.set_defaults(handler=cmd_note, json_errors=True)

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
    relay.add_argument("--watch-launch-anchor", action="store_true",
                       help="Windows 计划任务用：启动它的 conhost 结束时随之停止（DESIGN §90）；其他平台忽略")
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
    invalid = _unencodable_argument(args)
    if invalid is not None:
        # 先于平台解析、Windows 命令作用域、发现与任何读写（§101.2）
        _report_error(args, invalid)
        return EXIT_REJECTED
    origin_device = getattr(args, "origin_device", None)
    if isinstance(origin_device, str) and not origin_device.strip():
        # 显式空白的 --origin-device 与 --device "" 同一拒绝（§104.14 第 2 条、§101.2）：不当作「没指定」去本机或
        # 联邦查任务，也不当作「不限权威」；两个库都不碰
        _report_error(args, "target_explicit_required")
        return EXIT_TARGET
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
                # 「目标未发送」只对会投递的命令成立；tasks 的名字形筛选解析失败时不打（§93.1）
                if args.command in _DELIVERING_COMMANDS and error.reason in {
                        'target_ambiguous','target_changed','target_names_unverified','target_not_found',
                        'target_id_unverified','target_id_invalid','target_provider_required',
                        'discovery_incomplete','claude_discovery_incomplete','alias_target_unavailable'}:
                    print('目标未发送；请刷新 peers，可加 claude@ / codex@ 前缀明确指定 provider，或用已核实的完整 UUID 消歧。', file=sys.stderr)
                if error.reason == 'target_names_unverified' and _alias_hint_applies(args):
                    # 别名只在 Windows 本机、只对 Codex 可用，通用文案不提（§91.2.2）
                    print(f'Windows 本机也可用 {command_name()} alias set <别名> <完整UUID> 登记本机别名（只在本机可用）。',
                          file=sys.stderr)
                if error.reason == 'windows_provider_not_enabled':
                    return EXIT_NOT_ENABLED
                return EXIT_TARGET if error.reason.startswith(('target_', 'alias_')) else EXIT_REJECTED
        return _run_command(args)


# 会把消息投给 --to/--review-by 目标的命令：Windows 目标解析失败时才提示「目标未发送」
_DELIVERING_COMMANDS = frozenset({'send', 'retry'})


def _alias_hint_applies(args: argparse.Namespace) -> bool:
    """Windows 别名只作用于 Codex：给出的目标都写明了别家（例如 claude@）时不提别名（Opus 实现审计 r1 P3-6）。"""
    for raw in (getattr(args, 'to', None), getattr(args, 'review_by', None)):
        if not isinstance(raw, str):
            continue
        try:
            provider = parse_selector(raw).provider
        except SelectorError:
            return True
        if provider in (None, Provider.CODEX):
            return True
    return not any(isinstance(getattr(args, key, None), str) for key in ('to', 'review_by'))


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
        # 只有真的没给 --device 才走本机列表；显式空串交给 cmd_peers 与 send/retry 同一拒绝（§102，原先 `not` 把 "" 当没给）
        if args.command == 'peers' and args.device is None:
            return _windows_peers(args)  # 不带参数与 --all-devices：本机列表共用一个函数（§94.6）
    # 任一调用前后补查摘要：提交后未发布（进程被杀、锁超时）的窗口由下一次调用收敛；worker 与 summary 自行处理。
    # federation status/relay 前后都不补（DESIGN §90.6）：status 是维护判停的只读查询，不连主账本、不写摘要、不拉 worker；
    # relay 启动取锁与退出清理不被主账本争用拖住
    refresh = (args.command not in {"worker", "summary"} and not (get_platform().name == 'windows' and args.command == 'wait')
               and not (args.command == "federation" and args.federation_action in {"status", "relay"}))
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
        if error.hint:
            print(f"{command_name()}: {error.hint}", file=sys.stderr)
        return error.exit_code
    except KeyboardInterrupt:
        return 130
    finally:
        if refresh:
            _refresh_summary(revive=args.command != "withdraw")
