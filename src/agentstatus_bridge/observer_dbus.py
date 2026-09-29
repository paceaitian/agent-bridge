"""AgentStatus observer 的 D-Bus 可选数据源：读一次 ListSessions，映射成桥的运行状态与 pane 观察。

桥可脱离 AgentStatus 运行：daemon 不在、没有 Gio 或返回格式不对时一律当作「状态未知」，不启动 daemon。
这是桥里唯一与 AgentStatus 专属集成相关的运行期代码（审计 N4，DESIGN §45.33.7、§45.37；§48 R3 从 endpoints 搬出）。
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
import json
import re
from typing import Any

from .hints import PaneState
from .model import Runtime


# AgentStatus observer 的 D-Bus 名称；桥可脱离 AgentStatus 运行，所以自带常量，由对照用例守住不漂移（DESIGN §45.33.7）
AGENTSTATUS_BUS_NAME = "org.paceaitian.AgentStatus1"


AGENTSTATUS_OBJECT_PATH = "/org/paceaitian/AgentStatus1"


AGENTSTATUS_INTERFACE_NAME = AGENTSTATUS_BUS_NAME


# 会话键只需要满足一件事：不可能和 pane id 相撞（pane 形如 `%12`）。这里只要求含 `:` 且有界——
# 比 observer 自己的键格式更严没有收益，反而会在上游改键形状时静默丢行、让放行永远不发生（审计 P3-4）
_OBSERVER_KEY = re.compile(r"[^%\s][^\s]{0,126}:[^\s]{1,64}")


def _positive_count(value: Any) -> bool:
    """observer 的计数字段：正整数才算数。缺字段、非整数、布尔、0 与负数都当作没有，不比写方更严（DESIGN §45.35）。"""
    return isinstance(value, int) and not isinstance(value, bool) and value > 0


def _has_background_work(item: Mapping[str, Any]) -> bool:
    """本轮之外仍在跑的工作：后台任务与可显示的子代理各自独立计数，任一为正即算。

    定时任务（`scheduledWorkCount`）不算——它是「将来会跑」而不是「现在在跑」，不影响对方能否收件。
    """
    return _positive_count(item.get("backgroundWorkCount")) or _positive_count(item.get("activeChildren"))


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
    except Exception:  # 可选数据源：任何失败都只意味着“状态未知”
        return []
    return _parse_observer_reply(raw)


def _parse_observer_reply(raw: object) -> list[Mapping[str, Any]]:
    """ListSessions 的原始回复 → 对象行，保持原顺序（DESIGN §48 R4，§46.4 移交的接缝）。

    不是字符串、或按字符数超过 4 MiB 时返回空；JSON 解析的任何异常都返回空——嵌套过深抛的是
    RecursionError，收窄成 ValueError 会让 `ab` 打出堆栈。结果不是数组返回空，否则只留对象行。
    """
    if not isinstance(raw, str) or len(raw) > 4 * 1024 * 1024:
        return []
    try:
        sessions = json.loads(raw)
    except Exception:
        return []
    if not isinstance(sessions, list):
        return []
    return [item for item in sessions if isinstance(item, dict)]
