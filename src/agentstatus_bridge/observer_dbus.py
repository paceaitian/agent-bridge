"""AgentStatus observer 的 D-Bus 可选数据源：读一次 ListSessions，映射成桥的运行状态与 pane 观察。

pane 状态（含最近一轮结束时刻）也从同一次读取、同一条选行规则派生，不另读（DESIGN §55）。

桥可脱离 AgentStatus 运行：daemon 不在、没有 Gio 或返回格式不对时一律当作「状态未知」，不启动 daemon。
这是桥里唯一与 AgentStatus 专属集成相关的运行期代码（审计 N4，DESIGN §45.33.7、§45.37；§48 R3 从 endpoints 搬出）。
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
import json
import math
import re
from typing import Any

from .hints import PaneState
from .model import Provider, Runtime


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


def _text(value: Any) -> str | None:
    """observer 的枚举字段：只收字符串，数组、对象等其他类型按缺字段处理，免得集合判定抛 TypeError（DESIGN §59）。"""
    return value if isinstance(value, str) else None


def _is_fresh(item: Mapping[str, Any]) -> bool:
    """与 observer 公开文档一致：stale/unavailable 的快照不代表当前状态；缺字段与未知值算新鲜（现行语义）。"""
    return _text(item.get("freshness")) not in {"stale", "unavailable"}


def _map_agentstatus_runtime(item: Mapping[str, Any]) -> Runtime:
    if not _is_fresh(item):
        return Runtime.UNKNOWN
    if item.get("attentionState") == "action_required":
        return Runtime.WAITING
    state = _text(item.get("runtimeState"))
    if state == "ready":
        # 本轮已结束：还有后台工作在跑时面板仍显示运行中，但对方能收件（DESIGN §45.37）
        return Runtime.BACKGROUND if _has_background_work(item) else Runtime.IDLE
    if state in {"thinking", "working", "starting"}:
        return Runtime.BUSY
    return Runtime.UNKNOWN


def _epoch(value: Any) -> float | None:
    """observer 的时刻字段：只收有限数值，布尔、其他类型、NaN、无穷与转不成浮点的超大整数都当作缺失。

    JSON 能解析出 4300 位以内的整数与 NaN/Infinity：前者 float() 抛 OverflowError，后者让「已停下未汇报」
    提示的时刻格式化抛 ValueError——与枚举值同类，不让 `ab` 打出堆栈（DESIGN §59，Opus 第 1 轮 P3-1）。
    """
    if not isinstance(value, (int, float)) or isinstance(value, bool):
        return None
    try:
        number = float(value)
    except OverflowError:
        return None
    return number if math.isfinite(number) else None


@dataclass(frozen=True)
class ObserverRow:
    """observer 对一个对象的观察：运行状态、该状态被确认的时刻、它属于哪个 pane。

    `runtime_at` 取自 observer 的 `runtimeUpdatedAt`——最后一次**真正设置过这条会话 runtime**
    的事件时刻。子代理结束、存活心跳这类不改父会话 runtime 的事件不会刷新它，所以它才有资格
    充当「这条会话的前台轮次已经结束」的证据；`lastEventAt` 只说明「最近有任何动静」（审计 R01）。

    `last_turn_ended_at` 取自 `lastTurnEndedAt`，只供「对方已停下未汇报」提示用（DESIGN §55）。
    `agent` 取自行的 `agent`（`codex`/`claude`/`grok`），按 pane 取行时只认同 provider 的行（DESIGN §62 ④）。
    """

    runtime: Runtime
    runtime_at: float | None
    pane: str | None
    fresh: bool = True
    last_turn_ended_at: float | None = None
    agent: str | None = None

    def pane_state(self) -> PaneState:
        """「对方已停下未汇报」提示要的三个字段，取自这同一行。"""
        return PaneState(runtime=self.runtime, last_turn_ended_at=self.last_turn_ended_at, fresh=self.fresh)


@dataclass(frozen=True)
class ObserverView:
    """一次 ListSessions 快照，按两套互不相交的键索引。

    - `%pane`：pane 级观察，供**收紧**判定使用（等待用户、Codex/Grok 的忙闲）；
    - `provider:hex`：observer 的会话键（含运行代际键 `claude-gen:…`），是**放开**原生忙判的唯一
      凭据——pane 会被换会话或别的 provider 复用，会话身份不会（DESIGN §45.37，审计 F02）。

    两套键不可能相撞：pane 形如 `%12`，会话键必含 `:`。`get()` 与原来的 `Mapping[str, Runtime]`
    同形。

    `rows` 里的 pane 键不分 provider、会借到同 pane 别家的行，只留给 `states`（doctor 判可读）与诊断；
    凡是按 pane 判定（等待用户、Codex/Grok 的忙闲）一律用 `pane_row`，它从按 `(pane, agent)` 分开的
    `panes` 里只取同 provider 的行（DESIGN §62 ④）。「对方已停下未汇报」提示更严，按目标的 observer 键取行
    （`cli._target_state`，§62 ⑤）。
    """

    rows: Mapping[str, ObserverRow] = field(default_factory=dict)
    panes: Mapping[tuple[str, str | None], ObserverRow] = field(default_factory=dict)

    def get(self, key: str) -> Runtime | None:
        row = self.rows.get(key)
        return row.runtime if row is not None else None

    def row(self, key: str) -> ObserverRow | None:
        return self.rows.get(key)

    def pane_row(self, pane: str, provider: Provider) -> ObserverRow | None:
        """这个 pane 上属于该 provider 的那一行（DESIGN §62 ④）。

        同 provider 的行优先；没有时取不带 `agent` 的行（读方不比写方严：不发 `agent` 的写方照旧按 pane
        匹配）；别家的行一律不借。同一组里多行时按 `_view_from_rows` 的选行规则。
        """
        row = self.panes.get((pane, provider.value))
        return row if row is not None else self.panes.get((pane, None))

    def pane_runtime(self, pane: str, provider: Provider) -> Runtime | None:
        row = self.pane_row(pane, provider)
        return row.runtime if row is not None else None

    def pane_state(self, pane: str, provider: Provider) -> PaneState | None:
        """该 pane 上该 provider 的观察：三个字段取自同一行，不从别的行补。"""
        row = self.pane_row(pane, provider)
        return row.pane_state() if row is not None else None

    @property
    def states(self) -> dict[str, Runtime]:
        return {key: row.runtime for key, row in self.rows.items()}


def agentstatus_view() -> ObserverView:
    """经 AgentStatus D-Bus 读取一次快照；daemon 不在或出错时返回空视图，不启动它。"""
    return _view_from_rows(_observer_rows() or [])


def _view_from_rows(items: list[Mapping[str, Any]]) -> ObserverView:
    """对象行 → 两套索引；同一 pane 多行时按下面的选行规则取一行（DESIGN §55）。"""
    rows: dict[str, ObserverRow] = {}
    panes: dict[tuple[str, str | None], ObserverRow] = {}
    for item in items:
        pane = item.get("paneId")
        agent = item.get("agent")
        row = ObserverRow(
            runtime=_map_agentstatus_runtime(item),
            runtime_at=_epoch(item.get("runtimeUpdatedAt")),
            pane=pane if isinstance(pane, str) else None,
            fresh=_is_fresh(item),
            last_turn_ended_at=_epoch(item.get("lastTurnEndedAt")),
            agent=agent if isinstance(agent, str) else None,
        )
        key = item.get("key")
        for index in (row.pane, key if isinstance(key, str) and _OBSERVER_KEY.fullmatch(key) else None):
            if index is not None:
                _place(rows, index, row)
        if row.pane is not None:
            _place(panes, (row.pane, row.agent), row)
    return ObserverView(rows, panes)


def _place(index: dict[Any, ObserverRow], key: object, row: ObserverRow) -> None:
    """同一个键多行时的选行规则（DESIGN §55）：有新鲜 WAITING 取第一条，否则取最后一条新鲜行，全不新鲜取最后一行。"""
    previous = index.get(key)
    if previous is not None:
        # 同一个 pane 可能有多行（换会话、残留代际）。新鲜的那行说了算，否则一条 stale 行
        # 会按行序把当前状态盖成未知（审计 P3-2）
        if previous.fresh and not row.fresh:
            return
        # 两行都新鲜时偏向更保守的一边：pane 索引只用于收紧，等待用户不该被行序覆盖（审计 P3-B）
        if previous.fresh and row.fresh and previous.runtime is Runtime.WAITING:
            return
    # 整行替换，不把状态和证据时刻拼在一起
    index[key] = row


def agentstatus_runtime() -> dict[str, Runtime] | None:
    """按键索引的运行状态；`doctor` 用它判断 AgentStatus 可读，不需要证据时刻。

    读不到（daemon 不在、调用失败、回复格式不对）返回 None；observer 在线但零可见会话时返回空表，
    doctor 才能把「可读」和「有会话」分开（DESIGN §59）。
    """
    rows = _observer_rows()
    if rows is None:
        return None
    return _view_from_rows(rows).states


def _observer_rows() -> list[Mapping[str, Any]] | None:
    from .platforms.linux.observer_io import read_reply  # layout: allow 纯投影模块在Windows可导入而不加载Linux/GI
    return _parse_observer_reply(read_reply(AGENTSTATUS_BUS_NAME, AGENTSTATUS_OBJECT_PATH, AGENTSTATUS_INTERFACE_NAME))


def _parse_observer_reply(raw: object) -> list[Mapping[str, Any]] | None:
    """ListSessions 的原始回复 → 对象行，保持原顺序（DESIGN §48 R4，§46.4 移交的接缝）。

    不是字符串、或按字符数超过 4 MiB 时返回 None；JSON 解析的任何异常都返回 None——嵌套过深抛的是
    RecursionError，收窄成 ValueError 会让 `ab` 打出堆栈。结果不是数组返回 None，否则只留对象行
    （可能为空：observer 在线但零会话，DESIGN §59）。
    """
    if not isinstance(raw, str) or len(raw) > 4 * 1024 * 1024:
        return None
    try:
        sessions = json.loads(raw)
    except Exception:
        return None
    if not isinstance(sessions, list):
        return None
    return [item for item in sessions if isinstance(item, dict)]
