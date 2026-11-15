"""发起方待办提醒：结果回来或任务需要处理后，发起方 30 分钟没有处理就再提醒一次（DESIGN §45.28.3）。

判定是只看账本的纯函数；排队提醒由持单实例锁的 worker 在一个事务里完成。「最后一轮」不靠猜：
只有对方显式 `ab report` 把任务推进到待验收或需处理之后才计时，返工、换轮或原因变化都会换一个令牌重新计时。
"""

from __future__ import annotations

from dataclasses import dataclass

from .ids import short
from .labels import next_step, reason_text
from .model import HANDED_OVER, REMINDER_OPTION, Attempt, Delivery, Role, Task, TaskView, describe
from .store import attempt_limit
from .summary import attention_at, attention_token, classify
from .native_names import NO_NAMES, NameBook
from .notification_policy import can_notify

REMIND_AFTER_SECONDS = 30 * 60.0
# 提醒记在 notice 尝试的 options 上：尝试不按条数裁剪，比每任务有上限的事件时间线更适合去重
# REMINDER_OPTION 在 model 定义，供 Store 写入限额与本模块预筛共用；此处兼容导出。
# 回执还在桥内或正在发送：它送达本身就是提醒，不叠加
_NOT_YET_ARRIVED = frozenset({Delivery.PENDING, Delivery.SENDING})
# 回执可能已到发起方：从它交出的时刻起重新计时。HELD 是对方会话里弹出了批准框（批准后改记送达时刻，过期则不算到达）；
# 不让 HELD 无限阻挡，回执丢失时最多再等 30 分钟。QUEUED 只表示进了 Codex 原生队列，不等于已读（已知限制）
_MAY_HAVE_ARRIVED = HANDED_OVER | {Delivery.HELD, Delivery.UNKNOWN}
# 发起方会话里有人拒绝了这次关注的回执，或会话设置为拒收：不再催（Opus 审计 S6）
_DECLINED = frozenset({Delivery.DENIED, Delivery.REFUSED})


@dataclass(frozen=True)
class PendingReminder:
    """除时间外都已满足的提醒：令牌、到期时刻与判定时的任务视图。"""

    token: str
    due_at: float
    view: TaskView

    def due(self, now: float) -> bool:
        """是否已到提醒时刻。"""
        return now >= self.due_at


def reminder_token(task: Task, attempts: list[Attempt]) -> tuple[str, TaskView] | None:
    """当前这一次关注的令牌与视图；任务此刻不需要发起方处理时返回 None。发送排队中的提醒前也用它核对是否过期。"""
    view = describe(task, attempts)
    # no_attempt 的关注时刻取任务 updated_at，而排队提醒本身会改它：令牌随之变化会每 30 分钟重复提醒
    if view.current is None:
        return None
    # 与界面通知同一口径：只有待验收与需处理会 notify，用户自己撤销的未送达消息除外
    if not classify(view)[1]:
        return None
    return attention_token(task, view), view


def attention_declined(task: Task, attempts: list[Attempt], view: TaskView) -> bool:
    """本次关注的回执或提醒是否被发起方会话明确拒绝（DENIED）或拒收（REFUSED）：有过就不再催（Opus 审计 S6）。

    创建提醒前与发送排队中的提醒前共用：拒绝晚于提醒排队到达时，提醒同样作废（Codex 复审 S01）。
    """
    attention = attention_at(task, view)
    # 任务内补充消息发给执行方：执行方拒收它不是发起方拒绝这次关注（DESIGN §95.5.3）
    return any(
        attempt.role is Role.NOTICE and not attempt.is_note and attempt.created_at >= attention
        and attempt.delivery in _DECLINED
        for attempt in attempts
    )


def reminder_candidate(task: Task) -> bool:
    """只看任务字段的预筛：不满足就不必读尝试（worker 每秒都要判定，Opus 审计 F3）。"""
    return (not task.finished and not task.paused and task.origin is not None and task.notify_origin
            and can_notify(task.origin))


def pending_reminder(task: Task, attempts: list[Attempt]) -> PendingReminder | None:
    """这项任务是否有一条待发的发起方提醒；没有（或已提醒过、回执还没到、回执被拒）时返回 None。"""
    origin = task.origin
    if origin is None or not reminder_candidate(task):
        return None
    found = reminder_token(task, attempts)
    if found is None:
        return None
    token, view = found
    if view.current is None or origin.same_session(view.current.target):
        return None  # 发起方就是当前接收方（例如自己复核）时它已经知道
    if max((attempt.seq for attempt in attempts), default=0) >= attempt_limit(Role.NOTICE, {REMINDER_OPTION: token}):
        return None  # 提醒预算已满，留下终态通知和结束回执；不为排不进的提醒驻留
    if attention_declined(task, attempts, view):
        return None
    attention = attention_at(task, view)
    since = attention
    for attempt in attempts:
        # 补充消息不是给发起方的回执：既不挡住、也不重置发起方提醒（DESIGN §95.5.3）
        if attempt.role is not Role.NOTICE or attempt.is_note:
            continue
        if attempt.options.get(REMINDER_OPTION) == token or attempt.delivery in _NOT_YET_ARRIVED:
            return None
        # 筛选锚点固定为关注时刻，不能用不断抬高的 since：否则较早创建、较晚送达的回执会被漏算（Codex 实现审计 R02）
        if attempt.created_at < attention:
            continue  # 之前几次关注的回执与提醒
        if attempt.delivery in _MAY_HAVE_ARRIVED and attempt.delivery_at is not None:
            # 从这次关注的回执实际交到发起方算起：回执晚到（worker 停摆、发现失败）时，不紧跟着再提醒（Codex 设计复审 F03）
            since = max(since, attempt.delivery_at)
    return PendingReminder(token=token, due_at=since + REMIND_AFTER_SECONDS, view=view)


def reminder_sender_class(attempts: list[Attempt]) -> str | None:
    """提醒声明的权限类别：沿用发起方登记任务时如实记下的类别（第一条工作尝试）。

    提醒是桥替发起方的任务发给发起方自己：发起方权限模式没变时类别与接收方一致，Claude 不会因类别不同而 hold；
    同一会话换了权限模式恢复时仍可能 hold（已知限制）。账本里没有记录时不声明（Codex 设计复审 C02）。
    """
    first = next((attempt for attempt in attempts if attempt.role is not Role.NOTICE), None)
    return first.sender_class if first is not None else None


def reminder_body(task: Task, attempts: list[Attempt], view: TaskView, *, command: str | None = None,
                  names: NameBook = NO_NAMES, receiver: str | None = None) -> str:
    """提醒正文：哪一步卡住、接收方是谁，以及下一步命令；标题由 envelope 的「任务：」行给出。

    `command` 由 worker 传它启动时解析好的入口名（DESIGN §45.36）：提醒是发给发起方照抄的。
    """
    # 接收方标识走 NameView：本机已核实主名，否则完整 ID（§91.4.2）；跨设备调用方不传 names，即完整 ID
    # 联邦调用方对远端接收方传 receiver（带设备的人读文本）：显示引用丢了设备，不能只交给本机 formatter（§91.4.2）
    if receiver is None:
        receiver = names.local_wire(view.current.target) if view.current is not None else "对方"
    minutes = int(REMIND_AFTER_SECONDS // 60)
    lines = [f"提醒：这项任务已超过 {minutes} 分钟没有处理——{reason_text(view.reason, command=command)}（{receiver}）。"]
    step = next_step(task, attempts, ref=short(task.id), command=command, reserved=1)
    if step is not None:
        lines.append(f"下一步：{step.text}")
    return "\n".join(lines)
