"""催执行方（DESIGN §104.9 一）：本机工作尝试的接收方停下却没汇报时，worker 给它发一条催促，每次尝试最多一次。

判据直接复用 hints.stopped_without_report，宽限 300 秒：
- 轮次结束晚于 max(投递, 最近一次 ack/progress)，所以也覆盖「ack 过、做完忘了交 result」；
- 端点与 pane 都空闲：有后台任务（BACKGROUND）、忙、等用户都不算；
- observer 行新鲜；Codex 队列项已离开队列；
- 不在提问等回答（question_asked）。

只在 Linux 本机做。Windows 读不到轮次结束时刻与后台任务；跨设备时 B 不能往 A 的任务里加尝试。这两条都是已知限制，
见 docs/ab.md。本模块只放纯判定、正文与观察取样，排队在 dispatch（它有 select_generation）。
"""

from __future__ import annotations

from dataclasses import dataclass, replace

from . import summary
from .endpoints import DiscoverySources, discover
from .hints import PaneState
from .ids import short
from .model import HANDED_OVER, Attempt, Consumption, Delivery, Endpoint, Provider, Role, Runtime, Task, Work
from .naming import command_name
from .observer_dbus import ObserverView
from .platforms.factory import get_platform
from .codex_metadata import MetadataCache
from .reminders import REMINDER_OPTION, nudge_token, silence_due
from .store import Store, attempt_limit

# 执行方停下后留给它自己补交汇报的宽限（§104.9 一）；查询提示用 60 秒，催促更保守
NUDGE_GRACE_SECONDS = 300.0
# worker 有候选时多久取一次发现与 observer（§104.9 一：节流 30–60 秒）
NUDGE_CHECK_SECONDS = 30.0
# 催执行方的窗口：候选资格与驻留上限都是从锚点起 24 小时，不随 --expect 变（§104.11 第 3 条：
# 原先取 --expect 时，--expect 5m 的任务在执行方停满 5 分钟宽限之前就出了窗口，永远催不到）
MAX_NUDGE_WATCH_SECONDS = 24 * 3600.0


ProgressBasis = tuple[Work, int | None, frozenset[str]]


def progress_basis(store: Store, attempts: list[Attempt], work: Attempt) -> ProgressBasis:
    """催促写事务复核用的进展基准（§104.12 第 6 条、§104.13 第 5 条）：工作状态、该尝试最近一条 progress 事件的
    单调序号（events.id 自增），加该尝试已交出补充的 ID 集合。

    只判有没有变化、不比先后：两份普通 progress 的工作时刻完全相同、或本机时钟回拨，时刻都分不出新旧，事件序号能。
    有效进展只有两种：每次 progress（含 --ask），以及让工作从等待确认变成已确认的首次 ACK（看工作状态）；重复的 ACK
    也写 ack 事件但不改状态，所以不算。不用事件条数：事件按任务限量裁剪，条数会变小，最大序号不会。
    """
    return (work.work, store.last_event_id(work.task_id, attempt_seq=work.seq, kind="progress"),
            frozenset(item.id for item in attempts if item.note_for_seq == work.seq and item.delivery in HANDED_OVER))


@dataclass(frozen=True)
class NudgeCandidate:
    """一项还没催过、工作仍开放的本机任务：当前工作尝试、沉默锚点与取候选时的进展基准（nudge_candidates 填入）。"""

    task: Task
    attempts: list[Attempt]
    work: Attempt
    anchor: float
    basis: ProgressBasis | None = None


def nudge_candidate(task: Task, attempts: list[Attempt]) -> NudgeCandidate | None:
    """这项任务能不能催：没结束、没暂停，当前工作尝试已交出、工作仍开放、不在提问，还没催过，提醒档还有容量。"""
    found = silence_due(task, attempts)
    if found is None:
        return None
    work, anchor = found
    token = nudge_token(work)
    if any(item.role is Role.NOTICE and item.options.get(REMINDER_OPTION) == token for item in attempts):
        return None  # 每次尝试只催一次
    # 不占提醒档的最后一格（61）：留给发起方的沉默提醒或「交接次数已满」那一条（§104.12 第 3 条）；催促是尽力而为
    if max((item.seq for item in attempts), default=0) >= attempt_limit(Role.NOTICE, {REMINDER_OPTION: token}) - 1:
        return None
    return NudgeCandidate(task, attempts, work, anchor)


def nudge_candidates(store: Store, now: float) -> list[NudgeCandidate]:
    """全部还在盯守窗口内（从锚点起 24 小时）的催促候选；先按任务字段预筛，再读尝试。"""
    found: list[NudgeCandidate] = []
    for task in store.list_tasks():
        if task.finished or task.paused:
            continue
        candidate = nudge_candidate(task, store.attempts(task.id))
        if candidate is not None and now - candidate.anchor <= MAX_NUDGE_WATCH_SECONDS:
            found.append(replace(candidate, basis=progress_basis(store, candidate.attempts, candidate.work)))
    return found


def worth_watching(work: Attempt, live: Endpoint, pane: PaneState, *, anchor: float, now: float,
                   queue_window: float) -> bool:
    """读得到、还不到催的时候，值不值得让 worker 为它驻留（§104.11 第 4 条）：只在执行方确实还会有动静时。

    - 端点或窗格的运行态不是 IDLE（忙、后台任务、等用户）；
    - Codex 队列项还没离队（它还没开始处理这条消息），且入队不满 queue_window（调用方传 reconcile 同一个 30 分钟
      观察窗口）：消费状态冻结在 still_queued 时不能白白驻留 24 小时；
    - 已经停下、轮次结束晚于锚点、宽限还没满：最多再等 NUDGE_GRACE_SECONDS，到点就催或放手。
    空闲、交出后一直没开过新一轮的不驻留：它可能永远不动，不能把 worker 拖住 24 小时。
    """
    if live.runtime is not Runtime.IDLE or pane.runtime is not Runtime.IDLE:
        return True
    if (work.target.provider is Provider.CODEX and work.delivery is Delivery.QUEUED
            and work.consumption is not Consumption.LEFT_QUEUE
            and work.delivery_at is not None and now - work.delivery_at < queue_window):
        return True
    ended = pane.last_turn_ended_at
    return ended is not None and ended > anchor and now - ended < NUDGE_GRACE_SECONDS


def target_pane_state(view: ObserverView, live: Endpoint) -> PaneState | None:
    """停下判定只认目标自己的 observer 行（DESIGN §62 ⑤，候选 C；与 cli 的停下提示同一套键）。

    按活端点算出的 observer 键取行：Codex 按进程代际键；Claude 代际键优先，没有代际行时兼容回退到同 pane 的
    同一逻辑会话行。算不出键或键上没有行就当读不到：同 pane 上旧代际、别的会话的结束时刻都不能替目标作证。
    """
    for item in summary.endpoint_binding(live.ref)["observerKeys"]:
        row = view.row(item["key"])
        if row is None:
            continue
        if item["match"] == "session" and row.pane != live.ref.pane:
            return None
        return row.pane_state()
    return None


def observations(metadata: MetadataCache | None = None) -> tuple[list[Endpoint], ObserverView]:
    """worker 催执行方用的一次观察（只在 Linux 接入）：活端点与 AgentStatus 快照出自同一次 ListSessions。"""
    view = get_platform().runtime.view()
    sources = DiscoverySources(runtime=lambda: view) if metadata is None else DiscoverySources(
        runtime=lambda: view, native_metadata=metadata)
    return discover(sources), view


def nudge_body(task: Task, work: Attempt, *, command: str | None = None) -> str:
    """催促正文：说明还没汇报，按角色给出可照抄的汇报命令（复核给结论两种，交接给完成、受阻、还在做）。"""
    cmd = command or command_name()
    base = f"{cmd} report {task.id} --attempt {work.seq}"
    if work.role is Role.REVIEW:
        lines = [f"你承接的复核任务 {short(task.id)} 还没有汇报：复核完用 --approve 或 --changes，卡住 --blocked，"
                 "还在做 --progress。",
                 f'- 通过：{base} --approve --note "一句话结论"',
                 f'- 需要修改：{base} --changes --note "主要问题"']
    else:
        lines = [f"你承接的任务 {short(task.id)} 还没有汇报：做完 --result，卡住 --blocked，还在做 --progress。",
                 f'- 做完：{base} --result --note "一句话结论"']
    lines.extend([f'- 卡住：{base} --blocked --note "原因"',
                  f'- 还在做：{base} --progress --note "进展"',
                  "（这条由协作桥在你停下 5 分钟仍未汇报时发出，每次尝试只发一次。）"])
    return "\n".join(lines)
