"""派生提示：判断“对方已停下但还没有汇报”（DESIGN §45.9）与“当前未发现对方会话、仍未汇报”（§45.32）。

只在查询时计算，不写账本、不改变投递或工作状态、不推送给发起会话。
轮次结束不等于任务完成：对方可能忘了运行 ab report，也可能在等人回复，这里只提醒去看一眼。
"""

from __future__ import annotations

from dataclasses import dataclass

from .model import Attempt, Consumption, Delivery, Endpoint, Provider, Role, Runtime, Work, ask_pending

# 轮次结束后留给对方补交汇报的时间，避免在它刚结束、汇报命令尚未落账时误提示
STOPPED_GRACE_SECONDS = 60.0
_TRACKED_DELIVERY = frozenset({Delivery.WRITTEN, Delivery.QUEUED, Delivery.DELIVERED})
_OPEN_WORK = frozenset({Work.AWAITING_ACK, Work.ACKNOWLEDGED, Work.IN_PROGRESS})


@dataclass(frozen=True)
class PaneState:
    """AgentStatus 对某个 pane 的观察：运行状态、最近一轮结束时刻（epoch 秒）、数据是否新鲜。"""

    runtime: Runtime
    last_turn_ended_at: float | None
    fresh: bool


def _awaiting_report(attempt: Attempt) -> bool:
    """已到达对方、工作仍未完成的任务尝试；两种提示共用这道门槛。"""
    return attempt.role is not Role.NOTICE and attempt.delivery in _TRACKED_DELIVERY and attempt.work in _OPEN_WORK


def target_session_missing(
    attempt: Attempt | None, live: Endpoint | None, problem: str | None, *, discovered: bool
) -> bool:
    """已送达而未汇报时当前未发现对方会话：发现到了端点，却找不到该目标的任何一代（与 worker 的 target_gone 同一标准）。

    只看 agent 进程，不看 GNOME tab 或 tmux 是否附着；发现结果为空视为发现失败，代际歧义也不算未发现。
    发现非空不代表完整（读到多个 rollout、tmux 采样缺失时对方仍在也会找不到），所以只说“未发现”，不断言已退出。
    """
    if attempt is None or not _awaiting_report(attempt):
        return False
    return discovered and live is None and problem is None


def stopped_without_report(
    attempt: Attempt | None,
    endpoint: Endpoint | None,
    pane: PaneState | None,
    *,
    now: float,
    grace: float = STOPPED_GRACE_SECONDS,
    attempts: list[Attempt] | None = None,
    since: float | None = None,
) -> float | None:
    """对方在送达（或最近一次汇报）之后结束了一轮、现已空闲超过宽限期仍未交结果时，返回该轮结束时刻。

    grace 缺省 60 秒（查询提示）；worker 催执行方传 300（DESIGN §104.9 一）。给了同任务的 attempts 时，
    执行方提问还在等回答（§104.9 五）不算「停下未汇报」：它停下是在等发起方。
    since：调用方另给的起点（worker 传沉默锚点，含已交出补充的投递时刻，§104.11 第 2 条），轮次须结束在它之后；
    缺省 None 时行为不变（ab tasks/status 的提示与扩展 JS 同一判据）。
    """
    if attempt is None or not _awaiting_report(attempt):
        return None
    if attempts is not None and ask_pending(attempt, attempts):
        return None
    if (
        attempt.target.provider is Provider.CODEX
        and attempt.delivery is Delivery.QUEUED
        and attempt.consumption is not Consumption.LEFT_QUEUE
    ):
        # 仍是“已入队”说明对方还没汇报过（汇报会在同一事务里改为已送达）：此时只有确证已离开队列，
        # 才说明它结束的那一轮处理过这条消息；查询失败或尚未观察都不算离队。汇报过则不再看早先的队列样本。
        return None
    if endpoint is None or pane is None or not pane.fresh:
        return None
    if endpoint.runtime is not Runtime.IDLE or pane.runtime is not Runtime.IDLE:
        return None
    ended = pane.last_turn_ended_at
    marks = [value for value in (attempt.delivery_at, attempt.work_at, since) if value is not None]
    if ended is None or not marks or ended <= max(marks):
        return None
    if now - ended < grace:
        return None
    return ended
