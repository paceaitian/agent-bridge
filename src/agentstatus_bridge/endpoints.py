"""端点发现：本机正在运行的 agent 终端会话、目标解析，以及调用者身份与权限类别。

每个 provider 由一个 `ProviderAdapter` 描述四件事——进程名、怎么发现、怎么按环境变量归属、有没有
收件通道；加一个 agent 就是加一条注册表项加一个发现函数（DESIGN §45.34）。

- Claude：读 `~/.claude/sessions/<pid>.json` 注册表，核对 PID 启动时刻与消息 socket 属主。
- Codex：扫描 `codex` 进程打开的 rollout 文件确定 thread；终端证据优先 tmux pane，没有 pane 时回退到
  控制终端（DESIGN §45.33，控制终端只是候选门槛、不证明是 TUI）；按启动参数排除 app-server、exec 等
  非交互子命令，既无 pane 又无控制终端的进程也排除（它们不是用户能看到的会话）。
- Grok：读 `~/.grok/active_sessions.json`，再用 `comm` 与进程持有的 events 文件核实；只读，
  没有收件通道，只能作为发起方。
- 运行状态：Claude 用注册表 busy/idle；Codex 与 Grok 用 AgentStatus D-Bus（不自动启动）按 pane 读取。
  注册表分不清「前台这一轮在跑」与「只剩后台工作」，observer 能分，所以后者会覆盖前者（DESIGN §45.37）。
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field, replace
import json
import os
from pathlib import Path
import re
import sqlite3
import stat
import subprocess
import tomllib
from typing import Any

from . import procfs
from .hints import PaneState
from .ids import opaque_id
from .model import UNRESOLVED_NATIVE_ID, Endpoint, EndpointRef, Provider, Runtime
from .paths import claude_sessions_dir, codex_home, codex_sqlite_home, grok_home

MAX_REGISTRY_FILES = 256
# 允许 observer 证据比注册表状态时刻早多少：实测正常后台窗口里早约 0.09 秒，漏 hook 时差一整轮（§45.37）
EVIDENCE_SKEW_SECONDS = 5.0
MAX_REGISTRY_BYTES = 64 * 1024
_REGISTRY_NAME = re.compile(r"[0-9]+\.json")
# rollout 文件名：`rollout-<时刻>-<thread>.jsonl`；thread 回退（TUI 回溯编辑）后为 `rollout-<时刻>-<thread>_<rollout>.jsonl`，
# 取 thread 段（DESIGN §45.48 R6）
_UUID = r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
_ROLLOUT = re.compile(rf"/rollout-[^/]*-(?P<uuid>{_UUID})(?:_{_UUID})?\.jsonl$")
# Codex 状态库：`state_<版本>.sqlite`；版本号编进文件名，两个 Codex 版本可能共用一个目录（DESIGN §45.48 R2）
_CODEX_STATE_DB = re.compile(r"state_(?P<version>[0-9]{1,4})\.sqlite")
# 单元变体的 SessionSource 在状态库里存成裸字符串（如 `cli`），对象变体存 JSON 文本
_BARE_SOURCE = re.compile(r"[a-z0-9_-]{1,32}")
CODEX_STATE_TIMEOUT_SECONDS = 0.2
# Grok 的会话事件文件：`~/.grok/sessions/<urlencode 过的 cwd>/<会话 UUID>/events.jsonl`；
# 目录名是编码过的工作目录，不解码，只认结尾的 UUID 段（DESIGN §45.34）
_GROK_EVENTS = re.compile(
    r"/(?P<uuid>[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})/events\.jsonl$"
)
# 这些 Codex 子命令不是交互 TUI，不能作为任务目标（DESIGN §45.33.2、§45.44 二.7）。名单依据：0.156.0 `--help`
# 可见的非交互子命令 + 固定源码（`fe74a774`）中 `hide=true` 的隐藏子命令 `tcp-tunnel`（`--help` 不列隐藏子命令）；
# 另含 `--help` 未列出（已删或隐藏）的历史名。`agents`/`resume`/`fork` 是交互，故意不在内；
# `app` 只在 macOS/Windows 编译，本桥 Linux 范围不收
_CODEX_NON_TUI = frozenset(
    {
        "app-server",
        "apply",
        "a",
        "archive",
        "cloud",
        "cloud-tasks",
        "completion",
        "debug",
        "delete",
        "doctor",
        "exec",
        "e",
        "exec-server",
        "execpolicy",
        "features",
        "help",
        "login",
        "logout",
        "mcp",
        "mcp-server",
        "migrate-rollouts",
        "plugin",
        "proto",
        "queue",
        "remote-control",
        "responses-api-proxy",
        "review",
        "sandbox",
        "stdio-to-uds",
        "tcp-tunnel",
        "unarchive",
        "update",
    }
)
# 取值型全局选项：识别启动模式时要连它的取值一起跳过，否则 `--profile x exec` 会被误判成交互会话
_CODEX_VALUE_OPTIONS = frozenset(
    {
        "-a",
        "--add-dir",
        "--ask-for-approval",
        "-c",
        "-C",
        "--cd",
        "--config",
        "--disable",
        "--enable",
        "-i",
        "--image",
        "--local-provider",
        "-m",
        "--model",
        "-p",
        "--profile",
        "--remote",
        "--remote-auth-token-env",
        "-s",
        "--sandbox",
    }
)
# 多值选项（上游 num_args = 1..）：空格写法后续非选项 token 仍属于它，直到出现下一个选项；
# 所以 `-i a.png exec` 里的 exec 是图片名（仍是交互 TUI）。内联写法 `--image=a.png`/`-i=a.png` 只带一个取值，其后的 exec 仍是子命令。
_CODEX_MULTI_VALUE_OPTIONS = frozenset({"-i", "--image"})
# 交互子命令：扫到它就确定是 TUI，不再看后面的 token
_CODEX_TUI_SUBCOMMANDS = frozenset({"agents", "fork", "resume"})
# AgentStatus observer 的 D-Bus 名称；桥可脱离 AgentStatus 运行，所以自带常量，由对照用例守住不漂移（DESIGN §45.33.7）
AGENTSTATUS_BUS_NAME = "org.paceaitian.AgentStatus1"
AGENTSTATUS_OBJECT_PATH = "/org/paceaitian/AgentStatus1"
AGENTSTATUS_INTERFACE_NAME = AGENTSTATUS_BUS_NAME
_SELECTOR_NORMALIZE = re.compile(r"[\s_]+")
# 会话键只需要满足一件事：不可能和 pane id 相撞（pane 形如 `%12`）。这里只要求含 `:` 且有界——
# 比 observer 自己的键格式更严没有收益，反而会在上游改键形状时静默丢行、让放行永远不发生（审计 P3-4）
_OBSERVER_KEY = re.compile(r"[^%\s][^\s]{0,126}:[^\s]{1,64}")
# Claude 2.1.x 注册表 status：waiting 为对话框打开，shell 为正在执行 shell 命令
_CLAUDE_STATUS = {
    "idle": Runtime.IDLE,
    "busy": Runtime.BUSY,
    "shell": Runtime.BUSY,
    "waiting": Runtime.WAITING,
}


@dataclass(frozen=True)
class PaneInfo:
    pane_id: str
    pane_pid: int
    session_name: str
    server_pid: int | None = None


def tmux_panes() -> dict[int, PaneInfo]:
    """读取默认 tmux server 的 pane（只读 list-panes）；tmux 不可用时返回空。"""
    try:
        completed = subprocess.run(
            # #{pid} 是 tmux server PID：observer 的 Codex 会话键含它，摘要据此复算绑定（DESIGN §45.14）
            ["tmux", "list-panes", "-a", "-F", "#{pane_pid}\t#{pane_id}\t#{pid}\t#{session_name}"],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            errors="replace",
            timeout=3.0,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return {}
    if completed.returncode != 0:
        return {}
    panes: dict[int, PaneInfo] = {}
    for line in completed.stdout.splitlines():
        parts = line.split("\t", 3)
        if (
            len(parts) != 4
            or not parts[0].isdigit()
            or not re.fullmatch(r"%[0-9]+", parts[1])
            or not parts[2].isdigit()
        ):
            continue
        panes[int(parts[0])] = PaneInfo(
            pane_id=parts[1], pane_pid=int(parts[0]), session_name=parts[3][:80], server_pid=int(parts[2])
        )
    return panes


def _positive_count(value: Any) -> bool:
    """observer 的计数字段：正整数才算数。缺字段、非整数、布尔、0 与负数都当作没有，不比写方更严（DESIGN §45.35）。"""
    return isinstance(value, int) and not isinstance(value, bool) and value > 0


def _has_background_work(item: Mapping[str, Any]) -> bool:
    """本轮之外仍在跑的工作：后台任务与可显示的子代理各自独立计数，任一为正即算。

    定时任务（`scheduledWorkCount`）不算——它是「将来会跑」而不是「现在在跑」，不影响对方能否收件。
    """
    return _positive_count(item.get("backgroundWorkCount")) or _positive_count(item.get("activeChildren"))


def _evidence_covers(evidence_at: float | None, status_at_ms: Any) -> bool:
    """observer 的证据要和注册表这次状态变化对得上：同一时刻附近或更新，才准用来放开忙判。

    注册表的 `statusUpdatedAt` 只在状态**翻转**时更新。实测正常的「本轮结束、只剩后台」窗口里，
    observer 的 Stop 事件比注册表改写早约 0.09 秒，所以不能要求严格不旧；而漏掉开轮 hook 时，
    注册表会因新一轮翻转拿到新时刻、observer 却停在上一轮的旧证据上，两者相差一整轮
    （实测同一会话里这个差可达上百秒）。几秒的偏斜既覆盖两条链路的调度抖动，也挡得住后者（审计 F01）。

    注册表没给这个字段时不作判断，维持既有行为——宁可少一道校验，也不因上游少个字段就整体退化。
    """
    if not isinstance(status_at_ms, (int, float)) or isinstance(status_at_ms, bool):
        return True
    return evidence_at is not None and evidence_at >= status_at_ms / 1000.0 - EVIDENCE_SKEW_SECONDS


def _claude_background_row(
    view: ObserverView, session_id: str, pane: PaneInfo | None, pid: int, start: str
) -> ObserverRow | None:
    """能为这个目标放行的 observer 行：优先运行代际，其次同 pane 的会话行；都没有就返回 None。

    与 `summary._observer_binding` 同一套键与优先级（DESIGN §45.27.1）。一条 native session 可以
    同时存在多个运行代际（resume 到另一个进程/pane），只查 base 行会两头出错：新代际被旧代际的
    工作状态盖住，旧代际的后台状态又会把新代际正在跑的前台轮次显示成已结束（Codex 审计 R02）。
    """
    base = opaque_id("claude", session_id)
    if pane is not None:
        generation = view.row(opaque_id("claude-gen", base, pane.pane_id, pid, start))
        if generation is not None:
            # 有更精确的代际行就以它为准，不再回退到 base 行
            return generation if generation.runtime is Runtime.BACKGROUND else None
    row = view.row(base)
    if row is None or row.runtime is not Runtime.BACKGROUND:
        return None
    # 回退用的会话行必须属于同一个 pane（两边都没有 pane 也算同一个），否则它说的是别的代际
    return row if row.pane == (pane.pane_id if pane is not None else None) else None


def _map_agentstatus_runtime(item: Mapping[str, Any]) -> Runtime:
    # 与 observer 公开文档一致：stale/unavailable 的快照不代表当前状态
    if item.get("freshness") in {"stale", "unavailable"}:
        return Runtime.UNKNOWN
    if item.get("attentionState") == "action_required":
        return Runtime.WAITING
    state = item.get("runtimeState")
    if state == "ready":
        # 本轮已结束：还有后台工作在跑时面板仍显示运行中，但对方能收件（DESIGN §45.37）
        return Runtime.BACKGROUND if _has_background_work(item) else Runtime.IDLE
    if state in {"thinking", "working", "starting"}:
        return Runtime.BUSY
    return Runtime.UNKNOWN


def _pane_state(item: Mapping[str, Any]) -> PaneState:
    ended = item.get("lastTurnEndedAt")
    return PaneState(
        runtime=_map_agentstatus_runtime(item),
        last_turn_ended_at=float(ended) if isinstance(ended, (int, float)) and not isinstance(ended, bool) else None,
        fresh=item.get("freshness") not in {"stale", "unavailable"},
    )


@dataclass(frozen=True)
class ObserverRow:
    """observer 对一个对象的观察：运行状态、该状态被确认的时刻、它属于哪个 pane。

    `runtime_at` 取自 observer 的 `runtimeUpdatedAt`——最后一次**真正设置过这条会话 runtime**
    的事件时刻。子代理结束、存活心跳这类不改父会话 runtime 的事件不会刷新它，所以它才有资格
    充当「这条会话的前台轮次已经结束」的证据；`lastEventAt` 只说明「最近有任何动静」（审计 R01）。
    """

    runtime: Runtime
    runtime_at: float | None
    pane: str | None
    fresh: bool = True


@dataclass(frozen=True)
class ObserverView:
    """一次 ListSessions 快照，按两套互不相交的键索引。

    - `%pane`：pane 级观察，供**收紧**判定使用（等待用户、Codex/Grok 的忙闲）；
    - `provider:hex`：observer 的会话键（含运行代际键 `claude-gen:…`），是**放开**原生忙判的唯一
      凭据——pane 会被换会话或别的 provider 复用，会话身份不会（DESIGN §45.37，审计 F02）。

    两套键不可能相撞：pane 形如 `%12`，会话键必含 `:`。`get()` 与原来的 `Mapping[str, Runtime]`
    同形，只收紧不放开的调用方照旧。
    """

    rows: Mapping[str, ObserverRow] = field(default_factory=dict)

    def get(self, key: str) -> Runtime | None:
        row = self.rows.get(key)
        return row.runtime if row is not None else None

    def row(self, key: str) -> ObserverRow | None:
        return self.rows.get(key)

    @property
    def states(self) -> dict[str, Runtime]:
        return {key: row.runtime for key, row in self.rows.items()}


def agentstatus_view() -> ObserverView:
    """经 AgentStatus D-Bus 读取一次快照；daemon 不在或出错时返回空视图，不启动它。"""
    rows: dict[str, ObserverRow] = {}
    for item in _observer_rows():
        seen = item.get("runtimeUpdatedAt")
        pane = item.get("paneId")
        row = ObserverRow(
            runtime=_map_agentstatus_runtime(item),
            runtime_at=float(seen) if isinstance(seen, (int, float)) and not isinstance(seen, bool) else None,
            pane=pane if isinstance(pane, str) else None,
            fresh=item.get("freshness") not in {"stale", "unavailable"},
        )
        key = item.get("key")
        for index in (row.pane, key if isinstance(key, str) and _OBSERVER_KEY.fullmatch(key) else None):
            if index is None:
                continue
            previous = rows.get(index)
            if previous is not None:
                # 同一个 pane 可能有多行（换会话、残留代际）。新鲜的那行说了算，否则一条 stale 行
                # 会按行序把当前状态盖成未知（审计 P3-2）
                if previous.fresh and not row.fresh:
                    continue
                # 两行都新鲜时偏向更保守的一边：pane 索引只用于收紧，等待用户不该被行序覆盖（审计 P3-B）
                if previous.fresh and row.fresh and previous.runtime is Runtime.WAITING:
                    continue
            # 整行替换，不把状态和证据时刻拼在一起
            rows[index] = row
    return ObserverView(rows)


def agentstatus_runtime() -> dict[str, Runtime]:
    """按键索引的运行状态；`doctor` 用它判断 AgentStatus 可读，不需要证据时刻。"""
    return agentstatus_view().states


def agentstatus_panes() -> dict[str, PaneState]:
    """经 AgentStatus D-Bus 读取各 pane 的运行状态与最近一轮结束时刻；不可用时返回空，不启动 daemon。"""
    return {
        str(item["paneId"]): _pane_state(item) for item in _observer_rows() if isinstance(item.get("paneId"), str)
    }


def _observer_rows() -> list[Mapping[str, Any]]:
    """读一次 ListSessions 并返回其中的对象行；不可用、超限或格式不对时返回空。"""
    try:
        import gi

        gi.require_version("Gio", "2.0")
        from gi.repository import Gio  # pyright: ignore[reportAttributeAccessIssue]

        proxy = Gio.DBusProxy.new_for_bus_sync(
            Gio.BusType.SESSION,
            Gio.DBusProxyFlags.DO_NOT_AUTO_START,
            None,
            AGENTSTATUS_BUS_NAME,
            AGENTSTATUS_OBJECT_PATH,
            AGENTSTATUS_INTERFACE_NAME,
            None,
        )
        flags = getattr(Gio.DBusCallFlags, "NO_AUTO_START", Gio.DBusCallFlags.NONE)
        reply = proxy.call_sync("ListSessions", None, flags, 2000, None)
        raw = reply.unpack()[0]
        if not isinstance(raw, str) or len(raw) > 4 * 1024 * 1024:
            return []
        sessions = json.loads(raw)
    except Exception:  # 可选数据源：任何失败都只意味着“状态未知”
        return []
    if not isinstance(sessions, list):
        return []
    return [item for item in sessions if isinstance(item, dict)]


@dataclass
class DiscoverySources:
    """发现所用的数据源；测试可替换为合成目录和假 tmux/D-Bus。"""

    proc_root: Path = procfs.DEFAULT_PROC
    claude_sessions: Path = field(default_factory=claude_sessions_dir)
    codex_home: Path = field(default_factory=codex_home)
    # Codex 状态库所在目录；上游 `CODEX_SQLITE_HOME` 覆盖 codex_home（DESIGN §45.48 R2）
    codex_sqlite_home: Path | None = field(default_factory=codex_sqlite_home)
    grok_home: Path = field(default_factory=grok_home)
    panes: Callable[[], Mapping[int, PaneInfo]] = tmux_panes
    runtime: Callable[[], ObserverView] = agentstatus_view
    uid: int = field(default_factory=os.getuid)


def _codex_non_interactive(tokens: Sequence[str]) -> bool:
    """按有界 argv 判断 Codex 是否以明确的非交互子命令启动（DESIGN §45.33.2、§45.33.6）。

    跟随上游 0.154 的解析（0.156.0 已按源码逐项核对取值型全局选项，2026-09-22）：跳过已知全局选项及其取值（多值选项的空格写法吞掉后续非选项 token，内联写法只带一个），
    `--` 之后是字面参数；**位置参数之后仍可能出现子命令**（`codex hello exec` 实际进入 exec），所以未知 token 不终止扫描，
    继续找第一个落在子命令表里的 token；一个都没有就是交互（裸 `codex`、`codex "初始要求"`）。
    """
    index = 0
    while index < len(tokens):
        token = tokens[index]
        if token == "--":
            return False
        if token.startswith("-"):
            name, inline, _ = token.partition("=")
            if not inline and name in _CODEX_MULTI_VALUE_OPTIONS:
                index += 1
                while index < len(tokens) and not tokens[index].startswith("-"):
                    index += 1
                continue
            index += 2 if not inline and name in _CODEX_VALUE_OPTIONS else 1
            continue
        if token in _CODEX_NON_TUI:
            return True
        if token in _CODEX_TUI_SUBCOMMANDS:
            return False
        index += 1
    return False


def _pane_for(pid: int, panes: Mapping[int, PaneInfo], proc_root: Path) -> PaneInfo | None:
    for info in procfs.ancestry(pid, proc_root):
        pane = panes.get(info.pid)
        if pane is not None:
            return pane
    return None


def _is_owned_socket(path: str, uid: int) -> bool:
    try:
        status = os.lstat(path)
    except OSError:
        return False
    return stat.S_ISSOCK(status.st_mode) and status.st_uid == uid


def _discover_claude(
    sources: DiscoverySources, panes: Mapping[int, PaneInfo], runtime: ObserverView
) -> list[Endpoint]:
    try:
        files = sorted(
            entry for entry in sources.claude_sessions.iterdir() if _REGISTRY_NAME.fullmatch(entry.name)
        )[:MAX_REGISTRY_FILES]
    except OSError:
        return []
    endpoints: list[Endpoint] = []
    for path in files:
        try:
            if path.stat().st_size > MAX_REGISTRY_BYTES:
                continue
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        if not isinstance(data, dict):
            continue
        pid = data.get("pid")
        session_id = data.get("sessionId")
        proc_start = data.get("procStart")
        if (
            not isinstance(pid, int)
            or isinstance(pid, bool)
            or path.stem != str(pid)
            or not isinstance(session_id, str)
            or not session_id
            or not isinstance(proc_start, str)
        ):
            continue
        if data.get("kind") not in (None, "interactive"):
            continue
        info = procfs.read_process(pid, sources.proc_root)
        if info is None or info.start_ticks != proc_start:
            continue  # 已退出或 PID 复用：注册表残留
        issues: list[str] = []
        if data.get("peerProtocol") != 1:
            issues.append("peer_protocol_unsupported")
        socket_path = data.get("messagingSocketPath")
        if not isinstance(socket_path, str) or not _is_owned_socket(socket_path, sources.uid):
            issues.append("socket_unavailable")
            socket_path = None
        pane = _pane_for(pid, panes, sources.proc_root)
        status = data.get("status")
        state = _CLAUDE_STATUS.get(status, Runtime.UNKNOWN) if isinstance(status, str) else Runtime.UNKNOWN
        source = "claude_registry"
        released = _claude_background_row(runtime, session_id, pane, pid, proc_start)
        if pane is not None and runtime.get(pane.pane_id) is Runtime.WAITING:
            state = Runtime.WAITING  # 原生审批/提问对话框打开；只用于显示与提示，§45.42 起不再影响投递
        elif (
            state is not Runtime.WAITING
            and released is not None
            and _evidence_covers(released.runtime_at, data.get("statusUpdatedAt"))
        ):
            # 注册表只有一个 status：后台工作在跑时它报 busy/shell，看不出本轮其实已经结束。observer 分得清，
            # 但放开忙判**只认会话身份**：pane 会被换会话或另一个 provider 复用，那不是本会话的证据；
            # 收紧忙判（等待用户）仍按 pane 取，宁可多扣一条也不误放（DESIGN §45.37，Codex 审计 F02）
            state = Runtime.BACKGROUND
            source = "agentstatus"
        name = data.get("name")
        endpoints.append(
            Endpoint(
                ref=EndpointRef(
                    provider=Provider.CLAUDE,
                    native_id=session_id,
                    pid=pid,
                    start_ticks=proc_start,
                    pane=pane.pane_id if pane else None,
                    label=pane.session_name if pane else None,
                    server_pid=pane.server_pid if pane else None,
                ),
                runtime=state,
                runtime_source=source,
                socket_path=socket_path,
                name=name[:80] if isinstance(name, str) and name else None,
                issues=tuple(issues),
            )
        )
    return endpoints


def _codex_source_kind(value: object) -> str | None:
    """把状态库 `threads.source` 分成 root / subagent；认不出返回 None（DESIGN §45.48 R2）。

    沿用上游 `is_non_root_agent`：对象键 `subagent`、`internal` 是非根，`custom` 是对象形式的根；
    单元变体（`cli`/`exec`/`vscode`/`mcp`/`unknown`）存成裸字符串，都是根。其他形态一律未知——包括上游不会
    写出的 JSON 字符串形态（`"cli"`、`"subagent"`），不按裸串判根，免得把非根判成根（Fable 实现复核 P3-1）。
    只在内存里判定，原文不进日志、peers、账本或错误输出。
    """
    if not isinstance(value, str) or not value:
        return None
    if value[0] == "{":
        try:
            data = json.loads(value)
        except ValueError:
            return None
        if not isinstance(data, dict) or len(data) != 1:
            return None
        key = next(iter(data))
        if key in {"subagent", "internal"}:
            return "subagent"
        return "root" if key == "custom" else None
    return "root" if _BARE_SOURCE.fullmatch(value) else None


def _classify_codex_threads(sources: DiscoverySources, threads: set[str]) -> dict[str, str]:
    """只读 Codex 状态库给 thread 分类：返回认得出的 thread → root/subagent；认不出的不在结果里。

    只选 `id, source` 两列、只按持有的 thread 查询、`mode=ro` 打开、短超时；按版本号降序逐个探测
    `state_<n>.sqlite`，取第一个查询成功且能查到任一持有 thread 的库。任何错误都当作「没有分类证据」，
    调用方据此退回今天的歧义处理，不猜（DESIGN §45.48 R2）。
    """
    if not threads:
        return {}
    root = sources.codex_sqlite_home or sources.codex_home
    try:
        names = [entry.name for entry in os.scandir(root) if entry.is_file(follow_symlinks=False)]
    except OSError:
        return {}
    candidates = sorted(
        (int(match.group("version")), name) for name in names if (match := _CODEX_STATE_DB.fullmatch(name))
    )
    wanted = sorted(threads)
    for _, name in reversed(candidates):
        try:
            connection = sqlite3.connect(
                f"{(root / name).as_uri()}?mode=ro", uri=True, timeout=CODEX_STATE_TIMEOUT_SECONDS
            )
        except (sqlite3.Error, ValueError):
            continue
        try:
            # 缺表、缺列或库忙都会让这条查询抛 sqlite3.Error，跳到下一个库即可，不另外探列（变异反证 Q09：
            # 探列与查询出错走的是同一个结果，是冗余的防御）
            placeholders = ", ".join("?" for _ in wanted)
            rows = connection.execute(
                f"SELECT id, source FROM threads WHERE id IN ({placeholders})", wanted
            ).fetchall()
        except sqlite3.Error:
            continue
        finally:
            connection.close()
        if not rows:
            continue
        kinds: dict[str, str] = {}
        for thread_id, source in rows:
            kind = _codex_source_kind(source)
            if isinstance(thread_id, str) and kind is not None:
                kinds[thread_id.lower()] = kind
        return kinds
    return {}


def _discover_codex(
    sources: DiscoverySources, panes: Mapping[int, PaneInfo], runtime: ObserverView
) -> list[Endpoint]:
    sessions_root = str(sources.codex_home / "sessions") + "/"
    processes: dict[int, tuple[procfs.ProcessInfo, set[str]]] = {}
    for pid in procfs.list_pids(sources.proc_root):
        info = procfs.read_process(pid, sources.proc_root)
        if info is None or info.comm != "codex":
            continue
        threads: set[str] = set()
        for target in procfs.open_file_targets(pid, sources.proc_root):
            if not target.startswith(sessions_root):
                continue
            match = _ROLLOUT.search(target)
            if match is not None:
                # 同一 thread 的普通与回退后两种文件同时打开时自然去重
                threads.add(match.group("uuid"))
        processes[pid] = (info, threads)
    # 同一 thread 被几个进程打开（含非终端进程）：多于一个时消费者不唯一。在过滤非交互进程之前统计，
    # 并随端点按 thread 保留，解析出身份后按该 thread 重算（DESIGN §45.48 R1、Codex F03）
    consumers = Counter(thread for _, threads in processes.values() for thread in threads)
    # 终端分组只用于本次发现（丢掉同一终端里的启动包装进程），不进会话身份；键带类型，pane 与 tty 不互相混组
    by_terminal: dict[tuple[object, ...], list[tuple[procfs.ProcessInfo, set[str], PaneInfo | None]]] = {}
    for pid, (info, threads) in processes.items():
        if _codex_non_interactive(procfs.launch_tokens(pid, sources.proc_root)):
            continue
        pane = _pane_for(pid, panes, sources.proc_root)
        if pane is not None:
            group: tuple[object, ...] = ("pane", pane.server_pid, pane.pane_id)
        elif info.tty_nr:
            group = ("tty", info.tty_nr)  # 不经 tmux 的终端会话：控制终端是候选门槛，不证明是 TUI
        else:
            continue  # 既无 pane 又无控制终端：app-server、SDK、Desktop 等
        by_terminal.setdefault(group, []).append((info, threads, pane))
    for group_key, candidates in list(by_terminal.items()):
        # 同一 pane 里的启动包装进程没有 rollout，只保留真正持有 thread 的进程
        if any(threads for _, threads, _ in candidates):
            by_terminal[group_key] = [candidate for candidate in candidates if candidate[1]]
    # 所有交互进程的持有集合合并成一次查询（包括只有一个 thread 的，Codex §45.48 第二轮 R01）
    kinds = _classify_codex_threads(
        sources, {thread for candidates in by_terminal.values() for _, threads, _ in candidates for thread in threads}
    )
    endpoints: list[Endpoint] = []
    for candidates in by_terminal.values():
        for info, threads, pane in candidates:
            state = runtime.get(pane.pane_id) if pane is not None else None
            base = Endpoint(
                ref=EndpointRef(
                    provider=Provider.CODEX,
                    native_id=UNRESOLVED_NATIVE_ID,
                    pid=info.pid,
                    start_ticks=info.start_ticks,
                    pane=pane.pane_id if pane is not None else None,
                    label=pane.session_name if pane is not None else None,
                    server_pid=pane.server_pid if pane is not None else None,
                ),
                runtime=state if state is not None else Runtime.UNKNOWN,
                runtime_source="agentstatus" if state is not None else "none",
                consumers=0,
                threads=tuple(sorted(threads)),
                thread_consumers=tuple((thread, consumers[thread]) for thread in sorted(threads)),
            )
            endpoints.extend(_codex_endpoints_for(base, threads, kinds))
    return endpoints


def _codex_endpoints_for(base: Endpoint, threads: set[str], kinds: Mapping[str, str]) -> list[Endpoint]:
    """按持有集合与状态库分类生成一个 Codex 进程的端点（DESIGN §45.48 R2）。

    已知子代理从不成为可寻址端点；单 thread 的根或未知保持今天的行为（未知时功能优先，走旧兼容路径）；
    多 thread 只有「恰好一个根、其余都是已知子代理」才定根，多个根每根一个端点，有未知就如实报歧义。
    """
    if not threads:
        return [replace(base, issues=("no_thread_yet",))]
    roots = sorted(thread for thread in threads if kinds.get(thread) == "root")
    subagents = [thread for thread in threads if kinds.get(thread) == "subagent"]
    unknown = len(threads) - len(roots) - len(subagents)
    if len(threads) == 1:
        [thread] = threads
        if thread in subagents:
            return [replace(base, issues=("subagent_only",))]
        return [base.for_thread(thread)]
    if unknown:
        return [replace(base, issues=("ambiguous_thread",))]
    if not roots:
        return [replace(base, issues=("subagent_only",))]
    extra = ("subagent_threads",) if subagents else ()
    if len(roots) == 1:
        resolved = base.for_thread(roots[0])
        return [replace(resolved, issues=resolved.issues + extra)]
    found: list[Endpoint] = []
    for root in roots:
        resolved = base.for_thread(root)
        found.append(replace(resolved, issues=resolved.issues + ("multiple_roots",) + extra))
    return found


def _discover_grok(
    sources: DiscoverySources, panes: Mapping[int, PaneInfo], runtime: ObserverView
) -> list[Endpoint]:
    """Grok 会话：注册表条目、`comm == "grok"`、进程确实持有该会话的 events 文件，三样都要（DESIGN §45.34）。

    注册表没有进程启动时刻，所以 fd 这条同时充当 PID 复用的守卫。同一进程持有多个会话是常态
    （resume 之后旧会话的 fd 不关），不阻断，只给每行记 `shared_process`。
    """
    registry = sources.grok_home / "active_sessions.json"
    try:
        if registry.stat().st_size > MAX_REGISTRY_BYTES:
            return []
        data = json.loads(registry.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return []
    if not isinstance(data, list):
        return []
    listed: dict[int, list[str]] = {}
    for entry in data[-MAX_REGISTRY_FILES:]:  # 追加式文件：留尾部，从头截断会把最新会话切掉
        if not isinstance(entry, dict):
            continue
        pid = entry.get("pid")
        session_id = entry.get("session_id")
        if (
            not isinstance(pid, int)
            or isinstance(pid, bool)
            or pid <= 0
            or not isinstance(session_id, str)
            or not session_id
        ):
            continue
        # 先归一再去重：脏注册表里同一会话同时有大小写两种写法时，否则会各出一行、还误标 shared_process
        # （Codex 复审 N01）
        token = session_id.lower()
        sessions = listed.setdefault(pid, [])
        if token not in sessions:
            sessions.append(token)
    sessions_root = str(sources.grok_home / "sessions") + "/"
    endpoints: list[Endpoint] = []
    for pid, sessions in sorted(listed.items()):
        info = procfs.read_process(pid, sources.proc_root)
        if info is None or info.comm != "grok":
            continue  # 注册表残留，或 PID 已被别的进程复用
        held: set[str] = set()
        for target in procfs.open_file_targets(pid, sources.proc_root):
            if not target.startswith(sessions_root):
                continue
            match = _GROK_EVENTS.search(target)
            if match is not None:
                held.add(match.group("uuid").lower())
        live = [session for session in sessions if session in held]  # 两边都已归一小写
        pane = _pane_for(pid, panes, sources.proc_root)
        state = runtime.get(pane.pane_id) if pane is not None else None
        for session_id in live:
            endpoints.append(
                Endpoint(
                    ref=EndpointRef(
                        provider=Provider.GROK,
                        # 已在读注册表时归一小写：fd 比对本来不分大小写，而 EndpointRef.same_session 分，
                        # 不归一的话注册表换了口径就会让已落库的发起方 ref 对不上重新发现的端点
                        native_id=session_id,
                        pid=pid,
                        start_ticks=info.start_ticks,
                        pane=pane.pane_id if pane is not None else None,
                        label=pane.session_name if pane is not None else None,
                        server_pid=pane.server_pid if pane is not None else None,
                    ),
                    runtime=state if state is not None else Runtime.UNKNOWN,
                    runtime_source="agentstatus" if state is not None else "none",
                    issues=("shared_process",) if len(live) > 1 else (),
                )
            )
    return endpoints


def _claude_caller_env(env: Mapping[str, str], endpoints: list[Endpoint]) -> list[Endpoint]:
    """按 `CLAUDE_CODE_SESSION_ID` 匹配；同一会话有多个进程时再用 `CLAUDE_PID` 收窄。"""
    session = env.get("CLAUDE_CODE_SESSION_ID")
    if not session:
        return []
    matches = [
        item for item in endpoints if item.ref.provider is Provider.CLAUDE and item.ref.native_id == session
    ]
    narrowed = [item for item in matches if str(item.ref.pid) == env.get("CLAUDE_PID", "")]
    return narrowed or matches


def _codex_env_identity(env: Mapping[str, str]) -> tuple[str, str] | None:
    """由 Codex 注入的两个变量判定调用者：("subagent", 自身 thread) 或 ("root", 根 thread)；缺变量返回 None。

    上游保证 `CODEX_SESSION_ID` 是根 thread、`CODEX_THREAD_ID` 是执行这条命令的 thread 自己，所以两者不等
    就是子代理——无状态判定，不依赖这一轮发现看到几个 fd（DESIGN §45.48 R3）。大小写不敏感比较。
    """
    thread = env.get("CODEX_THREAD_ID")
    session = env.get("CODEX_SESSION_ID")
    if not thread or not session:
        return None
    if thread.lower() != session.lower():
        return ("subagent", thread.lower())
    return ("root", thread.lower())


def _codex_caller_env(env: Mapping[str, str], endpoints: list[Endpoint]) -> list[Endpoint]:
    """按 `CODEX_THREAD_ID` 匹配（大小写不敏感比较）；精确端点优先，否则按它解析仍持有它的未定根端点。

    子代理（两个变量不等）不在这里匹配：它由 identify_caller 明确拒绝，不能借根会话的端点（§45.48 R3）。
    """
    thread = env.get("CODEX_THREAD_ID")
    if not thread:
        return []
    identity = _codex_env_identity(env)
    if identity is not None and identity[0] == "subagent":
        return []
    lowered = thread.lower()
    codex = [item for item in endpoints if item.ref.provider is Provider.CODEX]
    exact = [item for item in codex if item.ref.native_id.lower() == lowered]
    if exact:
        return exact
    return [
        item.for_thread(lowered)
        for item in codex
        if item.ref.native_id == UNRESOLVED_NATIVE_ID and item.holds(lowered)
    ]


def _grok_caller_env(env: Mapping[str, str], endpoints: list[Endpoint]) -> list[Endpoint]:
    """按 `GROK_SESSION_ID` 匹配；同一进程里有多个会话时，只有它能定下是哪一个。"""
    session = env.get("GROK_SESSION_ID")
    if not session:
        return []
    return [
        item
        for item in endpoints
        if item.ref.provider is Provider.GROK and item.ref.native_id.lower() == session.lower()
    ]


@dataclass(frozen=True)
class ProviderAdapter:
    """接入一个 agent 所需的四件事；加 provider 只改这张注册表加一个发现函数（DESIGN §45.34）。

    - `comm`：进程名，用于判断某个祖先进程是不是 agent；
    - `discover`：本机该 provider 的活会话；
    - `caller_env`：按 agent 注入给工具子进程的环境变量正向匹配端点（祖先链看不到时的唯一办法）；
    - `env_markers`：只要有一个非空就说明调用者在该 agent 里（不一定认得出是哪个会话）；
    - `inbox`：有没有原生收件通道。没有的 provider 只能做发起方，发现时统一带上 `no_inbox`。
    """

    provider: Provider
    comm: str
    discover: Callable[[DiscoverySources, Mapping[int, PaneInfo], ObserverView], list[Endpoint]]
    caller_env: Callable[[Mapping[str, str], list[Endpoint]], list[Endpoint]]
    env_markers: tuple[str, ...]
    inbox: bool = True


# 顺序即环境变量归属的优先级：祖先链认不出时，先问 Claude 再问 Codex（与历史行为一致），最后 Grok
ADAPTERS: dict[Provider, ProviderAdapter] = {
    Provider.CLAUDE: ProviderAdapter(
        provider=Provider.CLAUDE,
        comm="claude",
        discover=_discover_claude,
        caller_env=_claude_caller_env,
        env_markers=("CLAUDECODE", "CLAUDE_CODE_SESSION_ID"),
    ),
    Provider.CODEX: ProviderAdapter(
        provider=Provider.CODEX,
        comm="codex",
        discover=_discover_codex,
        caller_env=_codex_caller_env,
        # CODEX_SESSION_ID 也算 agent 迹象：PID 命名空间看不到祖先、只剩根变量时不误当用户（§45.48 R3）
        env_markers=("CODEX_THREAD_ID", "CODEX_SESSION_ID"),
    ),
    Provider.GROK: ProviderAdapter(
        provider=Provider.GROK,
        comm="grok",
        discover=_discover_grok,
        caller_env=_grok_caller_env,
        env_markers=("GROK_SESSION_ID",),
        inbox=False,
    ),
}


# 由注册表派生：加一个 provider 不必再改这两处
_AGENT_COMMS = frozenset(adapter.comm for adapter in ADAPTERS.values())
_AGENT_ENV_MARKERS = tuple(marker for adapter in ADAPTERS.values() for marker in adapter.env_markers)


def discover(sources: DiscoverySources | None = None) -> list[Endpoint]:
    """发现当前可交接的端点，按 provider 与 tmux 会话名排序。"""
    config = sources or DiscoverySources()
    panes = dict(config.panes())
    runtime = config.runtime()
    endpoints: list[Endpoint] = []
    for adapter in ADAPTERS.values():
        found = adapter.discover(config, panes, runtime)
        if not adapter.inbox:
            # 只读 provider 的阻断标记统一在这里加：注册表里写 inbox=False 就够，发现函数不必各自记得
            found = [replace(item, issues=("no_inbox",) + item.issues) for item in found]
        endpoints.extend(found)
    endpoints.sort(key=lambda item: (item.ref.provider.value, item.ref.label or "", item.ref.pane or ""))
    return endpoints


class ResolveError(Exception):
    """目标解析失败：not_found 或 ambiguous，附候选便于用户改写。"""

    def __init__(self, code: str, candidates: tuple[Endpoint, ...] = ()) -> None:
        super().__init__(code)
        self.code = code
        self.candidates = candidates


def _normalize(value: str) -> str:
    return _SELECTOR_NORMALIZE.sub("-", value.strip().lower())


def resolve_target(selector: str, endpoints: list[Endpoint]) -> Endpoint:
    """解析 `--to`：pane（%3）、完整会话 ID、provider@tmux会话名、tmux会话名、Claude 会话名或 ID 前缀。

    按以上优先级逐条匹配；某一条命中多个即报歧义，不挑第一个。
    """
    value = selector.strip()
    if not value:
        raise ResolveError("target_not_found")
    provider: Provider | None = None
    label = value
    if "@" in value:
        head, _, tail = value.partition("@")
        try:
            provider = Provider(head.strip().lower())
        except ValueError:
            provider = None
        else:
            label = tail
    normalized = _normalize(label)
    lowered = value.lower()
    rules: list[Callable[[Endpoint], bool]] = [
        lambda item: item.ref.pane == value,
        lambda item: item.ref.native_id.lower() == lowered,
        lambda item: (
            provider is not None
            and item.ref.provider is provider
            and item.ref.label is not None
            and _normalize(item.ref.label) == normalized
        ),
        lambda item: provider is None and item.ref.label is not None and _normalize(item.ref.label) == normalized,
        lambda item: provider is None and item.name is not None and item.name == value,
        lambda item: len(lowered) >= 8 and item.ref.native_id.lower().startswith(lowered),
        # 没有 tmux 会话名时展示名是 provider@<原生 ID 前缀>，允许照抄它作为目标（DESIGN §45.33.3）
        lambda item: (
            provider is not None
            and item.ref.provider is provider
            and len(label) >= 8
            and item.ref.native_id.lower().startswith(label.lower())
        ),
    ]
    for rule in rules:
        matches = tuple(item for item in endpoints if rule(item))
        if len(matches) == 1:
            return matches[0]
        if len(matches) > 1:
            raise ResolveError("target_ambiguous", matches)
    raise ResolveError("target_not_found")


@dataclass(frozen=True)
class Caller:
    """命令调用者：所在的 agent 会话（若能匹配）、可见的 agent 祖先进程，以及是否有 agent 环境迹象。"""

    endpoint: Endpoint | None
    agent_process: procfs.ProcessInfo | None
    via: str | None = None  # ancestry / environment
    agent_env: bool = False
    # 明确认出但不允许以会话身份行事的调用者：目前只有 "subagent"（Codex 子代理，DESIGN §45.48 R3）
    rejection: str | None = None

    @property
    def is_user_shell(self) -> bool:
        """既无 agent 祖先进程也无 agent 环境变量：用户直接在终端/SSH 中运行。"""
        return self.agent_process is None and not self.agent_env


def identify_caller(
    endpoints: list[Endpoint],
    *,
    pid: int | None = None,
    proc_root: Path = procfs.DEFAULT_PROC,
    environ: Mapping[str, str] | None = None,
) -> Caller:
    """找出调用者所在的 agent 会话；用于报告归属，防止串任务。

    先确定**最近可见的 agent 进程**这条边界，再在边界内定会话，任何情况下都不跨越它：

    - 该进程唯一对应一个端点：就是它（`ancestry`）；
    - 对应多个端点（Grok resume 后的旧会话、Codex 同进程多 thread）：只用该进程自己注入的环境变量在
      这几个候选里细分，定不下来就不归属；
    - 一个端点都没有（注册表缺项、这一轮发现失败、被读取上限截掉）：如实返回「看得见这个 agent 进程，
      但认不出是哪个会话」，不借外层会话的身份（Codex 复审 R01）。

    只有完全看不到 agent 祖先进程时（例如沙箱 PID 命名空间）才退回按环境变量正向匹配全部端点；此时多个
    provider 的变量都能匹配则按注册表顺序取第一个，这是启发式而非身份证明，作为既有限制记在 DESIGN §45.34。
    """
    env = os.environ if environ is None else environ
    chain = procfs.ancestry(pid if pid is not None else os.getpid(), proc_root)
    agent_env = any(env.get(name) for name in _AGENT_ENV_MARKERS)
    by_pid: dict[int, list[Endpoint]] = {}
    for item in endpoints:
        by_pid.setdefault(item.ref.pid, []).append(item)
    codex_identity = _codex_env_identity(env)
    for info in chain:
        candidates = [item for item in by_pid.get(info.pid, ()) if item.ref.start_ticks == info.start_ticks]
        if info.comm == "codex" and codex_identity is not None:
            # 在唯一候选快路径之前统一判定 Codex 调用者，不以本轮看到几个 fd 为前提（DESIGN §45.48 R3）
            return _codex_caller(codex_identity, info, candidates, agent_env)
        if len(candidates) == 1:
            return Caller(candidates[0], info, "ancestry", agent_env)
        if candidates:
            picked = _caller_from_env(env, candidates, comm=info.comm)
            return Caller(picked, info, "environment" if picked is not None else None, agent_env)
        if info.comm in _AGENT_COMMS:
            return Caller(None, info, None, agent_env)
    if codex_identity is not None and codex_identity[0] == "subagent":
        # 看不见祖先、只能靠环境变量时同样拦下子代理
        return Caller(None, None, None, agent_env, rejection="subagent")
    found = _caller_from_env(env, endpoints)
    if found is not None:
        info = procfs.read_process(found.ref.pid, proc_root)
        visible = info if info is not None and info.start_ticks == found.ref.start_ticks else None
        return Caller(found, visible, "environment", agent_env)
    return Caller(None, None, None, agent_env)


def _codex_caller(
    identity: tuple[str, str], info: procfs.ProcessInfo, candidates: list[Endpoint], agent_env: bool
) -> Caller:
    """最近的 agent 祖先是 Codex 且带着两个身份变量时的调用者（DESIGN §45.48 R3）。

    子代理明确拒绝；根 thread T 优先选 `native_id == T` 的端点，否则按 T 解析本进程的候选——T 暂时不在
    持有集合里（writer 写入恢复时 fd 会短暂消失）也照样归属。护栏不在归属侧：汇报时 `reports._attribute`
    既有的投递代际核对（`reporter_generation_mismatch`）拦住另一个仍在的实际接收进程（Fable 实现复核 P3-4）。这条正面
    证据不被状态库分类或别的根否决。本进程没有任何候选（不在终端里等）时认不出是哪个会话。
    """
    kind, thread = identity
    if kind == "subagent":
        return Caller(None, info, None, agent_env, rejection="subagent")
    for item in candidates:
        if item.ref.native_id == thread:
            return Caller(item, info, "environment", agent_env)
    if candidates:
        holding = [item for item in candidates if item.holds(thread)]
        return Caller((holding or candidates)[0].for_thread(thread), info, "environment", agent_env)
    return Caller(None, info, None, agent_env)


def _caller_from_env(
    env: Mapping[str, str], pool: Sequence[Endpoint], *, comm: str | None = None
) -> Endpoint | None:
    """按 agent 注入的环境变量在给定端点集合里定位调用者会话；定不下来就返回 None，不猜。

    `comm` 给定时只问该 provider 的适配器：别的 provider 的变量可能是从外层会话继承来的。
    """
    for adapter in ADAPTERS.values():
        if comm is not None and adapter.comm != comm:
            continue
        matches = adapter.caller_env(env, list(pool))
        if len(matches) == 1:
            return matches[0]
        if matches:
            return None  # 同一组里多个候选都匹配：认不出，不挑一个
    return None


def _argv_tokens(pid: int, proc_root: Path) -> list[str]:
    try:
        raw = (proc_root / str(pid) / "cmdline").read_bytes()[: 64 * 1024]
    except OSError:
        return []
    # 只用于识别启动标志，不保存也不输出
    return [part.decode("utf-8", errors="replace") for part in raw.split(b"\0") if part]


def _toml_string(raw: str) -> str:
    text = raw.strip()
    try:
        parsed = tomllib.loads(f"v = {text}").get("v")
    except tomllib.TOMLDecodeError:
        return text.strip("'\"")
    return parsed if isinstance(parsed, str) else text


def _codex_cli_overrides(tokens: list[str]) -> tuple[str | None, str | None, bool, bool]:
    """解析 Codex 启动参数：(审批策略, 沙箱模式, 是否完全绕过, 是否选了 profile)。

    专用参数 `-a/-s` 优先于 `-c` 覆盖，与出现顺序无关；同一类内后出现者生效。
    """
    flag_approval: str | None = None
    flag_sandbox: str | None = None
    kv_approval: str | None = None
    kv_sandbox: str | None = None
    bypass = False
    profile = False
    index = 1
    while index < len(tokens):
        token = tokens[index]
        name, separator, inline = token.partition("=")
        if separator:
            value: str | None = inline
            step = 1
        else:
            value = tokens[index + 1] if index + 1 < len(tokens) else None
            step = 2
        if token in ("--dangerously-bypass-approvals-and-sandbox", "--yolo"):
            bypass = True
            step = 1
        elif name in ("-a", "--ask-for-approval") and value is not None:
            flag_approval = value
        elif name in ("-s", "--sandbox") and value is not None:
            flag_sandbox = value
        elif name in ("-p", "--profile") and value is not None:
            profile = True
        elif name in ("-c", "--config") and value is not None:
            key, equals, raw = value.partition("=")
            if equals:
                key = key.strip()
                if key == "approval_policy":
                    kv_approval = _toml_string(raw)
                elif key == "sandbox_mode":
                    kv_sandbox = _toml_string(raw)
                elif key == "profile":
                    profile = True
        else:
            step = 1
        index += step
    approval = flag_approval if flag_approval is not None else kv_approval
    sandbox = flag_sandbox if flag_sandbox is not None else kv_sandbox
    return approval, sandbox, bypass, profile


def _codex_class(tokens: list[str], config_path: Path) -> str | None:
    """按 Codex 的配置优先级（启动参数 > -c 覆盖 > profile > 用户配置）判断权限类别。"""
    approval, sandbox, bypass, profile = _codex_cli_overrides(tokens)
    if bypass:
        return "bypass"
    try:
        with config_path.open("rb") as handle:
            config = tomllib.load(handle)
    except (OSError, tomllib.TOMLDecodeError):
        config = {}
    if "profile" in config:
        profile = True
    if not profile:
        # 选了 profile 时其取值无法可靠重建，只用启动参数里明确给出的值
        if approval is None and isinstance(config.get("approval_policy"), str):
            approval = config["approval_policy"]
        if sandbox is None and isinstance(config.get("sandbox_mode"), str):
            sandbox = config["sandbox_mode"]
    if approval is None:
        return None
    if approval != "never":
        return "prompting"
    return "bypass" if sandbox == "danger-full-access" else None


def permission_class(
    caller: Caller, *, proc_root: Path = procfs.DEFAULT_PROC, codex_config: Path | None = None
) -> str | None:
    """如实判断发送方权限类别：bypass / prompting / None（不知道）。

    - 用户 shell（无 agent 迹象）：本人不受 agent 权限提示约束，等同 bypass。
    - Claude：只认启动参数中的明确模式；运行中切换无法从外部确认，未声明即未知。
    - Codex：按启动参数、-c 覆盖、profile 与 config.toml 的优先级判断；无法确定即未知。
    - 有 agent 迹象但看不到其进程：未知，不冒称 bypass。
    """
    agent = caller.agent_process
    if agent is None and caller.endpoint is not None:
        info = procfs.read_process(caller.endpoint.ref.pid, proc_root)
        if info is not None and info.start_ticks == caller.endpoint.ref.start_ticks:
            agent = info
    if agent is None:
        return None if caller.agent_env or caller.endpoint is not None else "bypass"
    tokens = _argv_tokens(agent.pid, proc_root)
    if agent.comm == "claude":
        if "--dangerously-skip-permissions" in tokens:
            return "bypass"
        for index, token in enumerate(tokens):
            name, separator, inline = token.partition("=")
            if name != "--permission-mode":
                continue
            mode = inline if separator else (tokens[index + 1] if index + 1 < len(tokens) else "")
            return "bypass" if mode == "bypassPermissions" else "prompting"
        return None
    if agent.comm == "codex":
        return _codex_class(tokens, codex_config or (codex_home() / "config.toml"))
    return None
