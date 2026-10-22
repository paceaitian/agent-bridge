"""结束回执（DESIGN §45.31）：任务第一次被验收或关闭时，单向告诉执行方与复核方协作已结束。

只在 accept/close 的写事务内调用：选接收者、生成正文、按容量逐个排队，排不进的记一条事件，不回滚终态。
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .model import (
    CLOSURE_KIND,
    CLOSURE_STATE_OPTION,
    MAY_HAVE_ARRIVED,
    NOTICE_KIND_OPTION,
    Attempt,
    EndpointRef,
    Role,
    Task,
)
from .naming import command_name
from .store import Store, StoreError
from .store import CAPACITY_CODES as _CAPACITY_CODES
from .notification_policy import can_notify

ACCEPTED = "accepted"
CLOSED = "closed"
# 容量不足时跳过该接收者；与 report 共用两种容量码（§45.31.4、§83）
MAX_REASON_CHARS = 200


@dataclass(frozen=True)
class Recipient:
    """一个结束回执接收者：它最近一次可能收到的工作尝试，以及实际投递到的端点。"""

    source: Attempt
    target: EndpointRef


@dataclass(frozen=True)
class ClosureOutcome:
    """本次排队结果：已排队的尝试，与因容量跳过的接收者（角色、容量类别、显示名）。"""

    queued: list[Attempt]
    skipped: list[tuple[Recipient, str]]


def delivered_endpoint(attempt: Attempt) -> EndpointRef:
    """对方实际收到消息的端点：有投递证据时 PID/start/pane/tmux server 整组取自投递记录，否则整组用选定目标。

    与摘要 `summary.binding` 同一口径，不把两边的字段混在一起。
    """
    target = attempt.target
    detail = attempt.delivery_detail
    pid = detail.get("deliveredPid")
    start = detail.get("deliveredStart")
    if not (isinstance(pid, int) and not isinstance(pid, bool) and isinstance(start, str)):
        return target
    pane = detail.get("deliveredPane")
    server = detail.get("deliveredServerPid")
    return EndpointRef(
        provider=target.provider,
        native_id=target.native_id,
        pid=pid,
        start_ticks=start,
        pane=pane if isinstance(pane, str) else None,
        label=target.label,
        server_pid=server if isinstance(server, int) and not isinstance(server, bool) else None,
        data_root=target.data_root,
    )


def closure_recipients(task: Task, attempts: list[Attempt]) -> list[Recipient]:
    """先过滤可能已到达的交接/复核尝试，再按角色取最新一条；实现方在前，按原生会话去重并排除发起方。"""
    arrived = [item for item in attempts if item.role in (Role.HANDOFF, Role.REVIEW) and item.delivery in MAY_HAVE_ARRIVED]
    recipients: list[Recipient] = []
    for role in (Role.HANDOFF, Role.REVIEW):
        latest = max((item for item in arrived if item.role is role), key=lambda item: item.seq, default=None)
        if latest is None:
            continue
        target = delivered_endpoint(latest)
        if task.origin is not None and target.same_session(task.origin):
            continue
        if any(target.same_session(item.target) for item in recipients):
            continue
        recipients.append(Recipient(latest, target))
    return recipients


def closure_body(task: Task, state: str, *, decider: str, reason: str | None, command: str | None = None) -> str:
    """结束回执正文：说明谁在什么终态结束了任务；只划清协议边界（不汇报、不给发起方发消息），收到后怎么做由接收方自己判断。

    `command` 缺省按本进程入口解析（DESIGN §45.36）：正文里提到的命令必须是对方能直接敲的那个。
    """
    title = f"「{task.title}」" if task.title else ""
    tail = f"不需要 {command or command_name()} report，也不用再给发起方发消息。"
    if state == ACCEPTED:
        return f"状态同步：任务{title}已由 {decider} 验收，协作结束。这不代表已部署或用户实机验收。{tail}"
    note = f"（原因：{reason[:MAX_REASON_CHARS]}）" if reason else ""
    return f"状态同步：任务{title}已由 {decider} 关闭{note}。{tail}"


def queue_closures(
    store: Store,
    task: Task,
    attempts: list[Attempt],
    state: str,
    *,
    now: float,
    decider: str,
    reason: str | None,
    sender: EndpointRef | None,
    sender_class: str | None,
) -> ClosureOutcome:
    """在调用方的写事务内为每个接收者排一条结束回执；容量不足的跳过并记事件，其他账本错误照常抛出。"""
    body = closure_body(task, state, decider=decider, reason=reason)
    queued: list[Attempt] = []
    skipped: list[tuple[Recipient, str]] = []
    for recipient in closure_recipients(task, attempts):
        if not can_notify(recipient.target):
            store.add_event(task.id, 'notification_skipped', now=now, attempt_seq=recipient.source.seq,
                            detail={'reason': 'target_no_inbox', 'route': state})
            continue
        options: dict[str, Any] = {
            NOTICE_KIND_OPTION: CLOSURE_KIND,
            CLOSURE_STATE_OPTION: state,
            "allowShared": recipient.source.allow_shared,
        }
        try:
            queued.append(
                store.add_attempt(
                    task.id,
                    role=Role.NOTICE,
                    target=recipient.target,
                    body=body,
                    refs=[],
                    now=now,
                    sender=sender,
                    sender_class=sender_class,
                    options=options,
                    event="closure_created",
                )
            )
        except StoreError as error:
            if error.code not in _CAPACITY_CODES:
                raise
            capacity = error.code.removeprefix("capacity_")
            store.add_event(
                task.id,
                "closure_skipped_capacity",
                now=now,
                attempt_seq=recipient.source.seq,
                detail={"role": recipient.source.role.value, "capacity": capacity},
            )
            skipped.append((recipient, capacity))
    return ClosureOutcome(queued, skipped)
