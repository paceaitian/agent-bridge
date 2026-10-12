"""端点发现：本机正在运行的 agent 终端会话、目标解析，以及调用者身份与权限类别。

每个 provider 由一个 `ProviderAdapter` 描述四件事——进程名、怎么发现、怎么按环境变量归属、有没有
收件通道；加一个 agent 就是加一条注册表项加一个发现函数（DESIGN §45.34）。

- Claude：读 `~/.claude/sessions/<pid>.json` 注册表，核对 PID 启动时刻与消息 socket 属主。
- Codex：扫描 `codex` 进程打开的 rollout 文件确定 thread；终端证据优先 tmux pane，没有 pane 时回退到
  控制终端（DESIGN §45.33，控制终端只是候选门槛、不证明是 TUI）；按启动参数排除 app-server、exec 等
  非交互子命令，既无 pane 又无控制终端的进程也排除（它们不是用户能看到的会话）。0.157 起托管 daemon
  持有全部 thread、TUI 一个都不持有：这时按 TUI 标题末段的 thread-id 在 daemon 持有集里认领（DESIGN §53）。
- Grok：读 `~/.grok/active_sessions.json`，再用 `comm` 与进程持有的 events 文件核实；只读，
  没有收件通道，只能作为发起方。
- 运行状态：Claude 用注册表 busy/idle；Codex 与 Grok 用 AgentStatus D-Bus（不自动启动）按 pane 读取。
  注册表分不清「前台这一轮在跑」与「只剩后台工作」，observer 能分，所以后者会覆盖前者（DESIGN §45.37）。
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Callable, Collection, Mapping, Sequence
from dataclasses import dataclass, field, replace
import json
import os
from pathlib import Path
import re
import sqlite3
import stat
import tomllib
from typing import Any

from .platforms import process as procfs
from .platforms.process import _argv_tokens
from .platforms.pane import PaneInfo, _with_title
from .platforms.mux import tmux_panes, tmux_pane_titles
from .platforms.factory import get_platform, using_platform
from .platforms.types import BridgePlatform, Capability
from .codex_metadata import MetadataCache, discovery_cache
from .codex_argv import _codex_class, _codex_non_interactive, codex_app_server
from .ids import opaque_id
from .model import UNRESOLVED_NATIVE_ID, Endpoint, EndpointRef, Provider, Runtime
from .observer_dbus import ObserverRow, ObserverView, agentstatus_view
from .paths import claude_sessions_dir, codex_home as default_codex_home, codex_sqlite_home, grok_home

MAX_REGISTRY_FILES = 256
# 允许 observer 证据比注册表状态时刻早多少：实测正常后台窗口里早约 0.09 秒，漏 hook 时差一整轮（§45.37）
EVIDENCE_SKEW_SECONDS = 5.0
MAX_REGISTRY_BYTES = 64 * 1024
_REGISTRY_NAME = re.compile(r"[0-9]+\.json")
# rollout 文件名：`rollout-<时刻>-<thread>.jsonl`；thread 回退（TUI 回溯编辑）后为 `rollout-<时刻>-<thread>_<rollout>.jsonl`，
# 取 thread 段（DESIGN §45.48 R6）
_UUID = r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
_ROLLOUT = re.compile(rf"/rollout-[^/]*-(?P<uuid>{_UUID})(?:_{_UUID})?\.jsonl$")
# writer lock：`<codex_home>/thread-writer-locks/<thread>.lock`；释放即删，别的进程瞬时撞上的显示 ` (deleted)`，全匹配自然排除
_WRITER_LOCK = re.compile(rf"(?P<uuid>{_UUID})\.lock")
# observer 按标题给 hook 定 pane 时前缀的最短长度（与 `agentstatus.adapters.tmux_title._HOOK_PREFIX_MIN` 相同，
# 两边由 test_codex_hook_mode 对齐）：桥按持有集核对唯一，短前缀也能认；observer 没有持有集，短于它就不认
OBSERVER_HOOK_PREFIX_MIN = 29
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
_SELECTOR_NORMALIZE = re.compile(r"[\s_]+")
# Claude 2.1.x 注册表 status：waiting 为对话框打开，shell 为正在执行 shell 命令
_CLAUDE_STATUS = {
    "idle": Runtime.IDLE,
    "busy": Runtime.BUSY,
    "shell": Runtime.BUSY,
    "waiting": Runtime.WAITING,
}


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


@dataclass
class DiscoverySources:
    """发现所用的数据源；测试可替换为合成目录和假 tmux/D-Bus。"""

    proc_root: Path = procfs.DEFAULT_PROC
    claude_sessions: Path = field(default_factory=claude_sessions_dir)
    codex_home: Path = field(default_factory=default_codex_home)
    # Codex 状态库所在目录；上游 `CODEX_SQLITE_HOME` 覆盖 codex_home（DESIGN §45.48 R2）
    codex_sqlite_home: Path | None = field(default_factory=codex_sqlite_home)
    grok_home: Path = field(default_factory=grok_home)
    panes: Callable[[], Mapping[int, PaneInfo]] = tmux_panes
    # pane_id → 原始标题（DESIGN §53.3.2）；测试给原始标题，经生产解析函数抽 thread-id
    titles: Callable[[], Mapping[str, str]] = tmux_pane_titles
    runtime: Callable[[], ObserverView] = agentstatus_view
    uid: int = field(default_factory=lambda: get_platform().files.uid())
    native_metadata: MetadataCache = field(default_factory=discovery_cache, compare=False)
    native_report: dict[str, object] = field(default_factory=dict, compare=False)
    platform: BridgePlatform = field(default_factory=get_platform, compare=False)

    def __post_init__(self) -> None:
        # 保留显式注入的旧接缝；默认采样经组合根，不在类定义时做IO。
        if self.panes is tmux_panes:
            self.panes = self.platform.mux.panes
        if self.titles is tmux_pane_titles:
            self.titles = self.platform.mux.titles
        if self.runtime is agentstatus_view:
            self.runtime = self.platform.runtime.view


def _pane_for(pid: int, panes: Mapping[int, PaneInfo], proc_root: Path) -> PaneInfo | None:
    for info in procfs.ancestry(pid, proc_root):
        if info.comm == "codex" and codex_app_server(procfs.launch_tokens(info.pid, proc_root)):
            # app-server 承载的是各个窗口的 thread，它是第一个 TUI 的子进程：它下面的进程不借那个 TUI 的 pane，
            # 否则 daemon 工具里起的嵌套 agent 会被算进第一个窗口（DESIGN §53.3.3，Opus 第 1 轮 P2-5）
            return None
        pane = panes.get(info.pid)
        if pane is not None:
            return pane
    return None


def _is_owned_socket(path: str, uid: int) -> bool:
    return get_platform().transport.owned_socket(path, uid)


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
        if pane is not None and runtime.pane_runtime(pane.pane_id, Provider.CLAUDE) is Runtime.WAITING:
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


def _codex_source_parent(value: object) -> str | None:
    """thread_spawn 子代理 `source` 里的 `parent_thread_id`（小写）；其他形态返回 None（DESIGN §53.3.6）。"""
    if not isinstance(value, str) or not value.startswith("{"):
        return None
    try:
        data = json.loads(value)
    except ValueError:
        return None
    subagent = data.get("subagent") if isinstance(data, dict) else None
    spawn = subagent.get("thread_spawn") if isinstance(subagent, dict) else None
    parent = spawn.get("parent_thread_id") if isinstance(spawn, dict) else None
    return parent.lower() if isinstance(parent, str) and re.fullmatch(_UUID, parent.lower()) else None


def _codex_source_parent_not_needed(value: object) -> bool:
    """§73.6：已知内部/记忆任务不补父边；不能把 review/compact/Other 的空字段也当证明。"""
    if not isinstance(value, str) or not value.startswith("{"):
        return False
    try:
        data = json.loads(value)
    except ValueError:
        return False
    return (isinstance(data, dict) and len(data) == 1 and
            ((isinstance(data.get("internal"), str) and data["internal"] in _CODEX_INTERNAL_WITHOUT_PARENT)
             or data.get("subagent") == "memory_consolidation"))  # 带字段的将来变体不可哈希，也照常补查


# 0.162.1 的 InternalSessionSource 只有这两个变体（protocol.rs:2929，snake_case）；新变体照常补查（§73.7）
_CODEX_INTERNAL_WITHOUT_PARENT = frozenset({"memory_consolidation", "guardian"})


@dataclass(frozen=True)
class CodexThreadClasses:
    """状态库给出的分类：thread → root/subagent、thread_spawn 子代理 → 父 thread，以及库是否不可用。"""

    kinds: dict[str, str] = field(default_factory=dict)
    parents: dict[str, str] = field(default_factory=dict)
    # 编号最大的库打不开或查询出错，或者一个库都没有（DESIGN §53.3.6）；旧库可读但查不到行不能掩盖它
    unavailable: bool = False
    sql_checked: bool = False
    present: frozenset[str] = frozenset()
    parent_not_needed: frozenset[str] = frozenset()


def _sql_codex_threads(sources: DiscoverySources, threads: set[str]) -> CodexThreadClasses:
    """只读 Codex 状态库给 thread 分类；认不出的不在结果里。

    只选 `id, source` 两列、只按持有的 thread 查询、`mode=ro` 打开、短超时；按版本号降序逐个探测
    `state_<n>.sqlite`。每个 thread 以有它这一行的最新库为准，旧库只补前面的库里没有的 thread，都找到了就停
    （Opus 实现复核 P3-2：两个版本共用目录时，daemon 持有的 thread 在新库、旧版 TUI 的 thread 只在旧库，
    「取第一个有行的库」会把旧版窗口变成未知）。任何错误都当作「没有分类证据」，调用方据此退回今天的歧义处理，
    不猜（DESIGN §45.48 R2）。
    """
    if not threads:
        return CodexThreadClasses()
    root = sources.codex_sqlite_home or sources.codex_home
    try:
        names = [entry.name for entry in os.scandir(root) if entry.is_file(follow_symlinks=False)]
    except OSError:
        return CodexThreadClasses(unavailable=True, sql_checked=True)
    candidates = sorted(
        (int(match.group("version")), name) for name in names if (match := _CODEX_STATE_DB.fullmatch(name))
    )
    if not candidates:
        return CodexThreadClasses(unavailable=True, sql_checked=True)
    remaining = set(threads)
    kinds: dict[str, str] = {}
    parents: dict[str, str] = {}
    parent_not_needed: set[str] = set()
    newest_failed = False
    for position, (_, name) in enumerate(reversed(candidates)):
        if not remaining:
            break
        try:
            connection = sqlite3.connect(
                get_platform().files.sqlite_uri(root / name, escaped=True), uri=True, timeout=CODEX_STATE_TIMEOUT_SECONDS
            )
        except (sqlite3.Error, ValueError):
            newest_failed = newest_failed or position == 0
            continue
        try:
            # 缺表、缺列或库忙都会让这条查询抛 sqlite3.Error，跳到下一个库即可，不另外探列（变异反证 Q09：
            # 探列与查询出错走的是同一个结果，是冗余的防御）
            wanted = sorted(remaining)
            placeholders = ", ".join("?" for _ in wanted)
            rows = connection.execute(
                f"SELECT id, source FROM threads WHERE id IN ({placeholders})", wanted
            ).fetchall()
        except sqlite3.Error:
            newest_failed = newest_failed or position == 0
            continue
        finally:
            connection.close()
        for thread_id, source in rows:
            if not isinstance(thread_id, str):
                continue
            # 有这一行的库就是这个 thread 的依据，source 认不出也不再去旧库找（查询只带还没分到类的 thread）
            remaining.discard(thread_id.lower())
            kind = _codex_source_kind(source)
            if kind is not None:
                kinds[thread_id.lower()] = kind
                if _codex_source_parent_not_needed(source):
                    parent_not_needed.add(thread_id.lower())
                parent = _codex_source_parent(source)
                if parent is not None:
                    parents[thread_id.lower()] = parent
    return CodexThreadClasses(kinds, parents, newest_failed, sql_checked=True, present=frozenset(threads - remaining),
                              parent_not_needed=frozenset(parent_not_needed))


def _classify_codex_threads(
    sources: DiscoverySources, threads: set[str], processes: Mapping[int, CodexProcess] | None = None,
    preferred: Collection[str] = (),
) -> CodexThreadClasses:
    """§73：SQL已能回答kind/parent时不初始化native；只有缺证据才补查当前持有者。"""
    sql = _sql_codex_threads(sources, threads)
    needed = {thread for thread in threads if thread not in sql.kinds or
              sql.kinds[thread] == "subagent" and thread not in sql.parents and thread not in sql.parent_not_needed}
    priority = set(preferred) & threads
    for _ in range(8):
        priority |= {sql.parents[thread] for thread in tuple(priority) if sql.parents.get(thread) in threads}
    holders = {
        thread: tuple(sorted((pid, process.info.start_ticks) for pid, process in (processes or {}).items()
                             if process.app_server and thread in process.holdings))
        for thread in needed
    }
    holders = {key: value for key, value in holders.items() if value}
    batch = sources.native_metadata.read(sources.codex_home, holders, preferred=priority, absent=threads - sql.present)
    kinds: dict[str, str] = {}
    parents: dict[str, str] = {}
    conflicts = 0
    # 初扫不替代网络后的再证明；但每个pid只复验一次，不按记录数重复遍历fd。
    fresh_processes: dict[int, tuple[str, frozenset[str]] | None] = {}
    def fresh_holder(pid: int, start: str, thread: str) -> bool:
        if pid not in fresh_processes:
            info = procfs.read_process(pid, sources.proc_root)
            fresh_processes[pid] = None if info is None else (
                info.start_ticks, frozenset().union(*codex_holdings(pid, sources.proc_root, sources.codex_home)))
        proof = fresh_processes[pid]
        return proof is not None and proof[0] == start and thread in proof[1]
    for thread, value in batch.records.items():
        fresh = bool(holders.get(thread)) and all(
            fresh_holder(pid, start, thread)
            for pid, start in holders.get(thread, ())
        )
        if not fresh:
            continue
        if value.kind == "conflict":
            kinds[thread] = "subagent"  # 无父关系，标题路径阻断，不走单thread未知兼容
            conflicts += 1
        elif value.kind in {"root", "subagent"}:
            kinds[thread] = value.kind
            if value.parent is not None:
                parents[thread] = value.parent
    fallback = (sources.native_metadata.attempted & threads) - kinds.keys()
    sources.native_report = {
        "state": batch.reason, "serverVersion": batch.server_version,
        "confirmed": len(kinds) - conflicts, "conflicts": conflicts,
        "sqlAnswered": len(threads - needed), "sqlFallback": len(fallback),
        "sqlState": "unavailable" if sql.unavailable else "available" if sql.sql_checked else "not_queried",
    }
    return CodexThreadClasses({**sql.kinds, **kinds},
                              {**{key: value for key, value in sql.parents.items() if key not in kinds}, **parents},
                              sql.unavailable, sql.sql_checked, sql.present, sql.parent_not_needed)


@dataclass(frozen=True)
class CodexProcess:
    """一个 codex 进程的持有情况（DESIGN §53.3.4）：只在内存里，不进端点身份与账本。"""

    info: procfs.ProcessInfo
    app_server: bool
    interactive: bool
    rollouts: frozenset[str]
    locks: frozenset[str]

    @property
    def holdings(self) -> frozenset[str]:
        """rollout 或 writer lock 持有的全部 thread。"""
        return self.rollouts | self.locks


def codex_holdings(pid: int, proc_root: Path, home: Path) -> tuple[frozenset[str], frozenset[str]]:
    """某个进程持有的 Codex thread：（rollout 持有集，writer lock 持有集）；fd 读不到时两个都是空集。

    持有判定只有这一份实现，发现、doctor、调用者识别与汇报侧代际核对共用（DESIGN §53.3.4）：rollout 只认
    `<home>/sessions/` 下的 rollout 文件名里的 thread 段；lock 精确比对 `<home>/thread-writer-locks/<thread>.lock`。
    """
    sessions_root = str(home / "sessions") + "/"
    locks_root = str(home / "thread-writer-locks") + "/"
    rollouts: set[str] = set()
    locks: set[str] = set()
    for target in procfs.open_file_targets(pid, proc_root):
        if target.startswith(sessions_root):
            match = _ROLLOUT.search(target)
            if match is not None:
                # 同一 thread 的普通与回退后两种文件同时打开时自然去重
                rollouts.add(match.group("uuid"))
        elif target.startswith(locks_root):
            lock = _WRITER_LOCK.fullmatch(target[len(locks_root):])
            if lock is not None:
                locks.add(lock.group("uuid"))
    return frozenset(rollouts), frozenset(locks)


def scan_codex_holdings(proc_root: Path, home: Path) -> dict[int, CodexProcess]:
    """本机全部 codex 进程的持有情况；发现与 doctor 共用（DESIGN §53.3.4）。"""
    processes: dict[int, CodexProcess] = {}
    for pid in procfs.list_pids(proc_root):
        info = procfs.read_process(pid, proc_root)
        if info is None or info.comm != "codex":
            continue
        tokens = procfs.launch_tokens(pid, proc_root)
        rollouts, locks = codex_holdings(pid, proc_root, home)
        processes[pid] = CodexProcess(info, codex_app_server(tokens), not _codex_non_interactive(tokens), rollouts, locks)
    return processes


def codex_daemon_mode(processes: Mapping[int, CodexProcess]) -> bool:
    """有持有 thread 的 app-server 进程就是 daemon 模式；不看 `--managed-daemon` 参数（DESIGN §53.3.4）。"""
    return any(process.app_server and process.holdings for process in processes.values())


def _discover_codex(
    sources: DiscoverySources, panes: Mapping[int, PaneInfo], runtime: ObserverView
) -> list[Endpoint]:
    processes = scan_codex_holdings(sources.proc_root, sources.codex_home)
    # 同一 thread 被几个进程打开 rollout（含非终端进程）：多于一个时消费者不唯一。在过滤非交互进程之前统计，
    # 并随端点按 thread 保留，解析出身份后按该 thread 重算（DESIGN §45.48 R1、Codex F03）；lock 只认候选、不计消费者
    # （别的进程扫 stale 锁会瞬时打开锁文件，DESIGN §53.3.6）
    consumers = Counter(thread for process in processes.values() for thread in process.rollouts)
    # 终端分组只用于本次发现（丢掉同一终端里的启动包装进程），不进会话身份；键带类型，pane 与 tty 不互相混组
    by_terminal: dict[tuple[object, ...], list[tuple[CodexProcess, PaneInfo | None]]] = {}
    for pid, process in processes.items():
        if not process.interactive:
            continue
        pane = _pane_for(pid, panes, sources.proc_root)
        if pane is not None:
            group: tuple[object, ...] = ("pane", pane.server_pid, pane.pane_id)
        elif process.info.tty_nr:
            group = ("tty", process.info.tty_nr)  # 不经 tmux 的终端会话：控制终端是候选门槛，不证明是 TUI
        else:
            continue  # 既无 pane 又无控制终端：app-server、SDK、Desktop 等
        by_terminal.setdefault(group, []).append((process, pane))
    daemon_mode = codex_daemon_mode(processes)
    legacy: list[list[tuple[CodexProcess, PaneInfo | None]]] = []
    titled: dict[tuple[object, ...], list[tuple[CodexProcess, PaneInfo | None]]] = {}
    for group_key, members in by_terminal.items():
        if any(process.rollouts for process, _ in members):
            # 交互进程自己持有 rollout（`--no-daemon` 或 ≤0.156）：旧路径，只保留真正持有 thread 的进程
            legacy.append([member for member in members if member[0].rollouts])
        elif daemon_mode:
            titled[group_key] = members  # 托管 daemon 承载：按标题认领（DESIGN §53.3.5）
        else:
            legacy.append(members)  # 没有 daemon 持有任何 thread：照旧 no_thread_yet
    legacy_threads = {thread for members in legacy for process, _ in members for thread in process.rollouts}
    bindable_pool: set[str] = set()
    if titled:
        bindable_pool = {
            thread for process in processes.values() if process.app_server for thread in process.holdings
        } | {thread for members in titled.values() for process, _ in members for thread in process.holdings}
    # 所有需要分类的 thread 合并成一次查询（包括只有一个 thread 的，Codex §45.48 第二轮 R01）
    preferred = {thread for thread in bindable_pool for pane in panes.values()
                 if pane.thread_prefix is not None and thread.startswith(pane.thread_prefix)}
    classes = _classify_codex_threads(sources, legacy_threads | bindable_pool, processes, preferred)
    endpoints: list[Endpoint] = []
    for members in legacy:
        for process, pane in members:
            base = _codex_base(process, pane, runtime, process.rollouts, consumers)
            endpoints.extend(_codex_endpoints_for(base, set(process.rollouts), classes.kinds))
    for members in titled.values():
        endpoints.append(
            _codex_titled_endpoint(sources.proc_root, members, processes, classes, consumers, runtime)
        )
    return endpoints


def _codex_base(
    process: CodexProcess,
    pane: PaneInfo | None,
    runtime: ObserverView,
    threads: Collection[str],
    consumers: Mapping[str, int],
) -> Endpoint:
    state = runtime.pane_runtime(pane.pane_id, Provider.CODEX) if pane is not None else None
    return Endpoint(
        ref=EndpointRef(
            provider=Provider.CODEX,
            native_id=UNRESOLVED_NATIVE_ID,
            pid=process.info.pid,
            start_ticks=process.info.start_ticks,
            pane=pane.pane_id if pane is not None else None,
            label=pane.session_name if pane is not None else None,
            server_pid=pane.server_pid if pane is not None else None,
        ),
        runtime=state if state is not None else Runtime.UNKNOWN,
        runtime_source="agentstatus" if state is not None else "none",
        consumers=0,
        threads=tuple(sorted(threads)),
        thread_consumers=tuple((thread, consumers.get(thread, 0)) for thread in sorted(threads)),
    )


def _outermost(
    members: Sequence[tuple[CodexProcess, PaneInfo | None]], proc_root: Path
) -> tuple[CodexProcess, PaneInfo | None] | None:
    """组里「是其余全部进程祖先」的那个进程；没有唯一的就返回 None（与 observer `_find_unique_agent_process` 同规则）。"""
    ancestors = {process.info.pid: {info.pid for info in procfs.ancestry(process.info.pid, proc_root)} for process, _ in members}
    found = [
        member
        for member in members
        if all(member[0].info.pid in ancestors[other.info.pid] for other, _ in members)
    ]
    return found[0] if len(found) == 1 else None


def _codex_title_root(thread: str, bindable: Collection[str], classes: CodexThreadClasses) -> str | None:
    """标题显示的 thread 对应的根：根或未知就是它自己；thread_spawn 子代理沿父 id 上溯，最多 8 层、每层都要可绑定。

    未知按根（DESIGN §53.3.6，与 §45.48 R2 同一个功能优先口径）；父不可绑定、超层、成环或没有父 id 的子代理返回 None。
    """
    current = thread
    seen: set[str] = set()
    for _ in range(9):  # 自身加最多 8 层父
        if classes.kinds.get(current) != "subagent":
            return current
        parent = classes.parents.get(current)
        if parent is None or parent not in bindable or parent in seen or parent == current:
            return None
        seen.add(current)
        current = parent
    return None


def _codex_titled_endpoint(
    proc_root: Path,
    members: Sequence[tuple[CodexProcess, PaneInfo | None]],
    processes: Mapping[int, CodexProcess],
    classes: CodexThreadClasses,
    consumers: Mapping[str, int],
    runtime: ObserverView,
) -> Endpoint:
    """新路径：每组一个最外层端点，按标题 thread-id 在可绑定集合里唯一前缀认领（DESIGN §53.3.6）。

    可绑定集合 =（app-server 持有 ∪ 本组持有）− 别组交互进程持有：残留标题不能把窗口绑到别的窗口的 thread 上。
    未绑定的端点 `threads=()`，不挂可绑定集合，否则任何 thread 都会命中所有未绑定端点（代码地图陷阱 d）。
    """
    outer = _outermost(members, proc_root)
    process, pane = outer if outer is not None else min(members, key=lambda member: member[0].info.pid)
    if outer is None:
        return replace(_codex_base(process, pane, runtime, (), consumers), issues=("pane_process_ambiguous",))
    in_group = {member.info.pid for member, _ in members}
    others = {
        thread
        for pid, other in processes.items()
        if other.interactive and pid not in in_group
        for thread in other.holdings
    }
    bindable = (
        {thread for other in processes.values() if other.app_server for thread in other.holdings}
        | {thread for member, _ in members for thread in member.holdings}
    ) - others
    prefix = pane.thread_prefix if pane is not None else None
    if prefix is None:
        return replace(_codex_base(process, pane, runtime, (), consumers), issues=("title_thread_missing",))
    matches = [thread for thread in bindable if thread.startswith(prefix)]
    if len(matches) != 1:
        return replace(_codex_base(process, pane, runtime, (), consumers), issues=("title_thread_unmatched",))
    root = _codex_title_root(matches[0], bindable, classes)
    if root is None:
        return replace(_codex_base(process, pane, runtime, (), consumers), issues=("title_shows_subagent",))
    return _codex_base(process, pane, runtime, (root,), consumers).for_thread(root)


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
        state = runtime.pane_runtime(pane.pane_id, Provider.GROK) if pane is not None else None
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
    if sources is None and get_platform().discovery is not Capability.VERIFIED:
        return []
    config = sources or DiscoverySources()
    with using_platform(config.platform):
        return _discover_selected(config)


def _discover_selected(config: DiscoverySources) -> list[Endpoint]:
    if config.platform.discovery is not Capability.VERIFIED:
        return []  # Windows W1不扫描provider、不将空持有集当root、不造伪pane。
    titles = config.titles()
    panes = {pid: _with_title(pane, titles.get(pane.pane_id)) for pid, pane in config.panes().items()}
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


def codex_title_report(sources: DiscoverySources | None = None) -> dict[str, object]:
    """doctor 用：daemon 模式与 Codex 窗口标题里会话 id 的三类计数（DESIGN §53.5）。

    只给计数与布尔，不给标题、thread id 或 pane 标签。三类：末段认出 thread-id；认不出但标题里有 UUID 形状
    （没放在末尾，或末段与 spinner 粘连）；都没有。认出的里面另数前缀被尾截短的（observer 不认，hook 结局
    不公开；Opus 实现复核第 2 轮 P3-3）。状态库不可用另报一项；不是 daemon 模式时只报这一点。
    """
    if sources is None and get_platform().discovery is not Capability.VERIFIED:
        return {'state': 'discovery_unverified'}
    config = sources or DiscoverySources()
    with using_platform(config.platform):
        return _title_report_selected(config)


def _title_report_selected(config: DiscoverySources) -> dict[str, object]:
    if config.platform.discovery is not Capability.VERIFIED:
        return {"state": "discovery_unverified"}
    processes = scan_codex_holdings(config.proc_root, config.codex_home)
    if not codex_daemon_mode(processes):
        return {"daemonMode": False}
    titles = config.titles()
    panes = {pid: _with_title(pane, titles.get(pane.pane_id)) for pid, pane in config.panes().items()}
    seen: dict[str, PaneInfo] = {}
    for pid, process in processes.items():
        if process.interactive and (pane := _pane_for(pid, panes, config.proc_root)) is not None:
            seen[pane.pane_id] = pane
    with_id = sum(1 for pane in seen.values() if pane.thread_prefix is not None)
    short = sum(1 for pane in seen.values() if pane.thread_prefix is not None and len(pane.thread_prefix) < OBSERVER_HOOK_PREFIX_MIN)
    not_parsed = sum(1 for pane in seen.values() if pane.thread_prefix is None and pane.title_has_uuid)
    held = {thread for process in processes.values() if process.app_server for thread in process.holdings}
    preferred = {thread for thread in held for pane in seen.values()
                 if pane.thread_prefix is not None and thread.startswith(pane.thread_prefix)}
    classes = _classify_codex_threads(config, held, processes, preferred)
    return {
        "daemonMode": True,
        "withThreadId": with_id,
        "shortThreadId": short,
        "uuidNotParsed": not_parsed,
        "withoutThreadId": len(seen) - with_id - not_parsed,
        "stateDbUnavailable": classes.unavailable if classes.sql_checked else None,
        "nativeMetadata": dict(config.native_report),
    }


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
    # subagent（§45.48 R3）；platform_unverified（Windows W1未开放caller资格）。
    rejection: str | None = None

    @property
    def is_user_shell(self) -> bool:
        """既无 agent 祖先进程也无 agent 环境变量：用户直接在终端/SSH 中运行。"""
        if self.rejection == 'platform_unverified':
            return False
        return self.agent_process is None and not self.agent_env


def identify_caller(
    endpoints: list[Endpoint],
    *,
    pid: int | None = None,
    proc_root: Path = procfs.DEFAULT_PROC,
    environ: Mapping[str, str] | None = None,
    codex_home: Path | None = None,
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

    最近的 codex 祖先是 app-server（Codex 托管 daemon）时另走 `_codex_daemon_caller`（DESIGN §53.4）。
    """
    if get_platform().name == 'windows':
        return Caller(None,None,rejection='platform_unverified')
    env = os.environ if environ is None else environ
    chain = procfs.ancestry(pid if pid is not None else os.getpid(), proc_root)
    agent_env = any(env.get(name) for name in _AGENT_ENV_MARKERS)
    by_pid: dict[int, list[Endpoint]] = {}
    for item in endpoints:
        by_pid.setdefault(item.ref.pid, []).append(item)
    codex_identity = _codex_env_identity(env)
    for index, info in enumerate(chain):
        candidates = [item for item in by_pid.get(info.pid, ()) if item.ref.start_ticks == info.start_ticks]
        if info.comm == "codex" and codex_identity is not None:
            if codex_app_server(procfs.launch_tokens(info.pid, proc_root)):
                # daemon 是第一个 TUI 的子进程：既不在这里按 pid 找候选，也不往上走到那个 TUI（DESIGN §53.4.1）
                return _codex_daemon_caller(
                    codex_identity, info, endpoints, agent_env, proc_root, codex_home or default_codex_home()
                )
            if not candidates and not _codex_non_interactive(procfs.launch_tokens(info.pid, proc_root)):
                candidates = _codex_wrapper_candidates(
                    chain[index + 1 :], by_pid, proc_root, codex_identity[1], codex_home or default_codex_home()
                )
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


def _codex_wrapper_candidates(
    outer: list[procfs.ProcessInfo], by_pid: dict[int, list[Endpoint]], proc_root: Path, thread: str, home: Path
) -> list[Endpoint]:
    """标题路径每组只出最外层端点（包装进程）：内层 TUI 自己执行工具时按它的 pid 找不到候选，沿紧邻的
    连续 codex 祖先补找（Opus 实现复核 P3-1：包装进程 + `--no-daemon` TUI，TUI 暂时没有 rollout 时）。

    不借外层会话的身份（Codex 复审 R01）：
    - 只走同一条包装链，遇到非 codex 进程（shell 等）或 app-server 就停；
    - shell 对单条 `-c` 命令做 exec 优化，旧路径 TUI 用工具起的 `codex exec`、嵌套 codex 会是它的直接子进程，
      所以调用方只限交互进程（`codex exec` 保持认不出），借来的端点还要身份相容：已绑定的必须就是调用者的
      thread `T`；未绑定的（标题路径里没认出 thread）还要证明它是包装层——纯包装进程自己不持有别的 thread，
      真 TUI 至少持有自己 thread 的 lock（Opus 实现复核第 2 轮 P2-1、Codex 第 2 轮 R01）；
    - 每往外走一层都核对：中间隔着一个持有别的 thread 的 codex，那就是另一个会话，不再往外借（Opus 第 3 轮 P3-1）。
    """
    for info in outer:
        if info.comm != "codex" or codex_app_server(procfs.launch_tokens(info.pid, proc_root)):
            return []
        rollouts, locks = codex_holdings(info.pid, proc_root, home)
        wrapper_only = (rollouts | locks) <= {thread}
        found = [item for item in by_pid.get(info.pid, ()) if item.ref.start_ticks == info.start_ticks]
        if found:
            return [
                item
                for item in found
                if item.ref.native_id.lower() == thread
                or (item.ref.native_id == UNRESOLVED_NATIVE_ID and not item.threads and wrapper_only)
            ]
        if not wrapper_only:
            return []
    return []


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


def _codex_daemon_caller(
    identity: tuple[str, str],
    daemon: procfs.ProcessInfo,
    endpoints: list[Endpoint],
    agent_env: bool,
    proc_root: Path,
    home: Path,
) -> Caller:
    """最近的 codex 祖先是 app-server 时的调用者（DESIGN §53.4.1）。

    身份取上游注入的根 thread T，并要求这个 app-server 确实持有 T（直接读它的 fd，lock 或 rollout）：
    T 恰好显示在一个窗口就是那个窗口的端点，进程信息取 TUI；没有窗口或多个窗口显示时，用 app-server
    自身作调用者端点，没有 pane。子代理照旧拒绝。
    """
    kind, thread = identity
    if kind == "subagent":
        return Caller(None, daemon, None, agent_env, rejection="subagent")
    rollouts, locks = codex_holdings(daemon.pid, proc_root, home)
    if thread not in rollouts and thread not in locks:
        return Caller(None, daemon, None, agent_env)
    bound = [
        item for item in endpoints if item.ref.provider is Provider.CODEX and item.ref.native_id.lower() == thread
    ]
    if len(bound) == 1:
        tui = procfs.read_process(bound[0].ref.pid, proc_root)
        visible = tui if tui is not None and tui.start_ticks == bound[0].ref.start_ticks else None
        return Caller(bound[0], visible, "daemon", agent_env)
    own = Endpoint(
        ref=EndpointRef(
            provider=Provider.CODEX, native_id=thread, pid=daemon.pid, start_ticks=daemon.start_ticks, pane=None
        ),
        threads=(thread,),
    )
    return Caller(own, daemon, "daemon", agent_env)


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


# 判权限类别时读命令行的上限；超过就是没读全（DESIGN §58.8）
# Grok 的权限模式（DESIGN §60 ③）。以上游公开源码为准（xai-org/grok-build 1.0.45：`pager/src/app/cli.rs`、
# `xai-grok-shell/src/util/config/permissions.rs`、`xai-grok-agent/src/config.rs`），随装文档与它有出入的地方见 DESIGN 60.1
_GROK_BYPASS_FLAGS = frozenset({"--always-approve", "--yolo", "--dangerously-skip-permissions"})
# `--permission-mode` 的合法取值（clap 校验，其他值启动不了）；只有 bypassPermissions 产生 always-approve
_GROK_PROMPTING_CLI_MODES = frozenset({"default", "acceptEdits", "auto", "dontAsk", "plan"})
# `[ui] permission_mode` 的取值：只有 always-approve 是 bypass（上游别的字符串都按询问处理，这里当认不出）
_GROK_PROMPTING_CONFIG_MODES = frozenset({"default", "ask", "auto"})
# 系统级 managed_config.toml 与 requirements.toml 的位置（`22-permissions-and-safety.md:106`）


def _present(path: Path) -> bool:
    return get_platform().files.present(path)


def _grok_cli_mode(tokens: list[str]) -> str | None:
    """启动参数里的权限请求：`bypass` / `prompting` / None（没写）/ `unknown`（认不出或互相冲突）。`--` 之后的不看。

    上游只要给了 `--permission-mode` 就只看它（`resolve_effective_yolo`），随装文档却说与 always-approve 同时请求时
    取 always-approve（22-permissions-and-safety.md:42）：两者都给、取值又不是 bypassPermissions 时说不准，判未知。
    `grok agent`（ACP 服务）的权限由连上来的客户端决定，写在 `agent` 之前的顶层参数对它不起作用：命令行里有
    `agent` 这个词就判未知（它也可能只是一段提示词，判未知是少报方向）。
    """
    bypass_flag = False
    modes: set[str] = set()
    arguments = tokens[1:]
    index = 0
    while index < len(arguments):
        token = arguments[index]
        if token == "--":
            break
        if token == "agent":
            return "unknown"
        if token in _GROK_BYPASS_FLAGS:
            bypass_flag = True
        else:
            name, separator, inline = token.partition("=")
            if name == "--permission-mode":
                if separator:
                    modes.add(inline)
                elif index + 1 < len(arguments):
                    index += 1
                    modes.add(arguments[index])
                else:
                    return "unknown"
        index += 1
    if len(modes) > 1 or any(mode not in _GROK_PROMPTING_CLI_MODES | {"bypassPermissions"} for mode in modes):
        return "unknown"
    mode = next(iter(modes), None)
    if mode == "bypassPermissions":
        return "bypass"
    if mode is not None:
        return "unknown" if bypass_flag else "prompting"
    return "bypass" if bypass_flag else None


def _grok_config_mode(home: Path) -> str | None:
    """用户 `config.toml` 的 `[ui] permission_mode`：`bypass` / `prompting` / `unset`（没写）/ None（不知道）。只取这一个键。

    项目级 `.grok/config.toml` 不能设 `ui`，`GROK_CONFIG` 覆盖层的白名单里也没有它（05-configuration.md:30、:324）。
    旧键 `approval_mode`、`yolo` 不复刻上游的换算，有就判未知。
    """
    try:
        with (home / "config.toml").open("rb") as handle:
            config: dict[str, Any] = tomllib.load(handle)
    except FileNotFoundError:
        config = {}
    except (OSError, ValueError):
        return None
    ui = config.get("ui", {})
    if not isinstance(ui, dict):
        return None
    if "permission_mode" in ui:
        mode = ui["permission_mode"]
        if not isinstance(mode, str):
            return None
        if mode == "always-approve":
            return "bypass"
        return "prompting" if mode in _GROK_PROMPTING_CONFIG_MODES else None
    return None if "approval_mode" in ui or "yolo" in ui else "unset"


def _grok_class(tokens: list[str], home: Path, system_dir: Path) -> str | None:
    """Grok 发起方的权限类别（DESIGN §60 ③）：启动参数 > 用户配置；只在有正面证据、且没有可能的锁时声明 bypass。

    Claude 兼容的 `defaultMode` 不看：上游 always-approve 与它无关、且优先于 dontAsk（`permission-rules/src/resolution.rs`），
    `bypassPermissions` 在那里只是一条兜底的允许规则，deny/ask 规则仍会拦，不等于 always-approve。用户配置没写时
    账号侧的 remote 设置可能起作用，这里看不到，按会询问处理（少报）；`managed_config.toml` 可能补上这个键，存在就判未知。
    读的是当前文件：能反映最近一次写盘的 TUI 切换（Shift+Tab 等会写回 `config.toml`），但不保证代表当前这个进程或
    会话——另一个进程的切换也会写进来，Plan 与 headless 的 `/yolo` 不写盘、看不到（与 Claude、Codex 同口径）。
    `requirements.toml`（`~/.grok/` 或系统目录）可以禁止 always-approve，这里不解析它：存在就不声明 bypass。
    """
    requested = _grok_cli_mode(tokens)
    if requested == "unknown":
        return None
    if requested is None:
        native = _grok_config_mode(home)
        if native == "unset":
            if any(_present(directory / "managed_config.toml") for directory in (home, system_dir)):
                return None
            native = "prompting"  # 内置默认会询问
        requested = native
    if requested != "bypass":
        return requested
    if any(_present(directory / "requirements.toml") for directory in (home, system_dir)):
        return None
    return "bypass"


# 官方 CLI reference 明确用于 print/非交互的标志；sdk-url 为任务书指定的 SDK 防呆（§73.6）。
_CLAUDE_HEADLESS_FLAGS = frozenset({
    "-p", "--print", "--sdk-url", "--input-format", "--output-format", "--permission-prompt-tool",
    "--permission-prompts", "--include-partial-messages", "--forward-subagent-text", "--include-hook-events",
    "--prompt-suggestions", "--replay-user-messages",
    "--append-subagent-system-prompt", "--append-subagent-system-prompt-file", "--init", "--init-only",
    "--maintenance", "--max-budget-usd", "--max-turns", "--no-session-persistence", "--json-schema",
})


def _claude_headless(tokens: list[str], names: set[str]) -> bool:
    """非交互证据：官方 print 专用标志，或含 p 的布尔短选项合写（`-pc` = `-p -c`，§73.7）；误判只会少声明 bypass。"""
    return bool(names & _CLAUDE_HEADLESS_FLAGS) or any(
        len(token) > 2 and token[0] == "-" and token[1:].isalpha() and "p" in token[1:] for token in tokens)


def _claude_class(tokens: list[str], *, interactive: bool, complete: bool, system_dir: Path) -> str | None:
    # argv 没读全时被截掉的尾部可能有末项模式或 --restricted 改判：与 Codex/Grok 同一规则，不声明（§58.8、§73.7）
    if not complete:
        return None
    # 不看 -- 后的字面参数；模式取最后一次，含 name=value。只比较启动参数，不读配置内容。
    tokens = tokens[:tokens.index("--")] if "--" in tokens else tokens
    mode = None
    names = {token.partition("=")[0] for token in tokens}
    for index, token in enumerate(tokens):
        name, separator, inline = token.partition("=")
        if name == "--permission-mode":
            mode = inline if separator else (tokens[index + 1] if index + 1 < len(tokens) else "")
    danger = "--dangerously-skip-permissions" in names
    if mode == "plan":
        requested = ("bypass" if interactive and not _claude_headless(tokens, names) and
                     (danger or "--allow-dangerously-skip-permissions" in names) else None)
    elif danger and mode not in {None, "bypassPermissions"}:
        requested = None  # 官方未给冲突优先级，不用 danger 提前冒称 bypass
    elif danger or mode == "bypassPermissions":
        requested = "bypass"
    else:
        requested = "prompting" if mode in {"default", "manual", "acceptEdits", "auto", "dontAsk"} else None
    if requested == "bypass" and ("--restricted" in names or any(
            _present(system_dir / name) for name in ("managed-settings.json", "managed-settings.d"))):
        return None
    return requested


def permission_class(
    caller: Caller,
    *,
    proc_root: Path = procfs.DEFAULT_PROC,
    codex_config: Path | None = None,
    grok_dir: Path | None = None,
    claude_system_dir: Path | None = None,
) -> str | None:
    """如实判断发送方权限类别：bypass / prompting / None（不知道）。

    - 用户 shell（无 agent 迹象）：本人不受 agent 权限提示约束，等同 bypass。
    - Claude：只认启动参数中的明确模式；运行中切换无法从外部确认，未声明即未知。
    - Codex：根层与子命令层分开解析、按上游顺序合并启动参数（DESIGN §58），再按 profile 与 config.toml 补缺；
      无法确定即未知；命令行超过读取上限、没读全时也判未知。非交互子命令的结果是近似，今天没有消费方（其调用者在入口被拒）。
    - 有 agent 迹象但看不到其进程：未知，不冒称 bypass。
    - Codex app-server（托管 daemon 等）：固定未知。它的 argv 没有权限参数，按 config.toml 推会在全局 yolo 配置下
      冒称 bypass；thread 的实际权限由当初加载它的一方决定（DESIGN §53.4.4，Opus 第 2 轮 P2-1）。
    - Grok：启动参数，没写时看用户 config.toml 的 `[ui] permission_mode`；有 requirements.toml 时不声明 bypass，
      命令行没读全判未知（DESIGN §60 ③）。
    """
    if get_platform().name == 'windows':
        return None
    agent = caller.agent_process
    if agent is None and caller.endpoint is not None:
        info = procfs.read_process(caller.endpoint.ref.pid, proc_root)
        if info is not None and info.start_ticks == caller.endpoint.ref.start_ticks:
            agent = info
    if agent is None:
        return None if caller.agent_env or caller.endpoint is not None else "bypass"
    tokens, complete = _argv_tokens(agent.pid, proc_root)
    if agent.comm == "claude":
        return _claude_class(tokens, interactive=complete and agent.tty_nr != 0, complete=complete,
                             system_dir=claude_system_dir or get_platform().files.policy_dir("claude"))
    if agent.comm == "codex":
        if codex_app_server(tokens) or not complete:
            # 命令行没读全时被截掉的部分可能有改判的参数（如提示词后的 --approve-for-me），不声明（DESIGN §58.8）
            return None
        return _codex_class(tokens, codex_config or (default_codex_home() / "config.toml"))
    if agent.comm == "grok":
        if not complete:
            return None
        return _grok_class(tokens, grok_dir or grok_home(), get_platform().files.policy_dir("grok"))
    return None
