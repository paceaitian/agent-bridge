"""发起方待办提醒：结果回来或任务需要处理后，发起方 30 分钟没有处理就再提醒一次（DESIGN §45.28.3）。

判定是只看账本的纯函数；排队提醒由持单实例锁的 worker 在一个事务里完成。「最后一轮」不靠猜：
只有对方显式 `ab report` 把任务推进到待验收或需处理之后才计时，返工、换轮或原因变化都会换一个令牌重新计时。

确定未送达（FAILED/REFUSED/DENIED/EXPIRED）的关注到期时刻是「立即」而不是 +30 分钟（DESIGN §103.2）：同一令牌、
同样只发一次；本机 `ab send` 已当场打印过这次失败（尝试带 originWatch 章）时回到 30 分钟。补充消息（note）不改任务
视图，它确定未送达时另走一支：令牌锚在 note 尝试上，同样只告知一次。

对方沉默（DESIGN §104.9 一）是第三支：投递已交出、工作仍开放、从锚点起满 T 分钟没有新汇报时告诉发起方一次。
锚点取 max(投递时刻, 工作时刻, 本机最近一条催促的建立时刻)，令牌 `<尝试 id>:silent:<锚点>`，每个工作尝试最多 3 条。
沉默提醒、note 告知与催执行方都不是这次关注的主回执（side_notice），不挡、不顺延主提醒。
"""

from __future__ import annotations

from dataclasses import dataclass

from .ids import short
from .labels import DELIVERY_LABELS, capacity_close_text, follows_ref, next_step, reason_text
from .model import (
    DEFINITELY_UNDELIVERED,
    FOR_SEQ_OPTION,
    HANDED_OVER,
    SILENT_TOKEN_MARK,
    NOTE_KIND,
    NOTICE_KIND_OPTION,
    ORIGIN_WATCH_OPTION,
    REMINDER_OPTION,
    Attempt,
    Delivery,
    Role,
    Task,
    TaskView,
    Work,
    Phase,
    auto_retry_first,
    describe,
    expect_seconds,
    origin_is_receiver,
    work_attempts,
)
from .naming import command_name
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
# 立即告知的关注原因（DESIGN §103.2）：当前工作尝试确定未送达；UNKNOWN、HELD 仍按 30 分钟
IMMEDIATE_REASONS = frozenset(f"delivery_{delivery.value}" for delivery in DEFINITELY_UNDELIVERED)
# 补充消息未送达那一支的令牌标记：`<note 尝试 id>:note_undelivered:<delivery_at>`
_NOTE_TOKEN = ":note_undelivered:"
# ab note 能补充的对象：当前工作尝试已发出且尚未终态汇报（与 cli._NOTE_SENT/_NOTE_OPEN_WORK 同口径）
_NOTE_SENT = frozenset({*HANDED_OVER, Delivery.HELD, Delivery.UNKNOWN, Delivery.SENDING})
_NOTE_OPEN_WORK = frozenset({Work.AWAITING_ACK, Work.ACKNOWLEDGED, Work.IN_PROGRESS})
# 每个工作尝试最多几条沉默提醒（§104.9 一）：免得长任务逐条挤占 retry 的 60 档容量
MAX_SILENT_PER_ATTEMPT = 3
# 催执行方的令牌后缀：`<尝试 id>:nudge`，每个工作尝试最多一条（§104.9 一）
_NUDGE_TOKEN = ":nudge"


@dataclass(frozen=True)
class PendingReminder:
    """除时间外都已满足的提醒：令牌、到期时刻与判定时的任务视图。

    immediate：确定未送达、立即告知（§103.2）；note：补充消息未送达那一支所指的 note 尝试（主提醒为 None）。
    """

    token: str
    due_at: float
    view: TaskView
    immediate: bool = False
    note: Attempt | None = None
    # main：主提醒（含立即告知）；note：补充未送达；silent：对方沉默（§104.9 一）
    kind: str = "main"
    # 沉默提醒的锚点（epoch 秒）：正文按排队时刻算「已 N 分钟没有汇报」
    anchor: float | None = None

    def due(self, now: float) -> bool:
        """是否已到提醒时刻；立即告知恒为真——跨设备时 due_at 取自对方设备证据的时钟，对方时钟快也不能拖晚告知。"""
        return self.immediate or now >= self.due_at


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
    # 「补充消息未送达」的告知与沉默提醒都不是这次关注的回执：发起方拒收它们不挡主提醒
    # （§103.2「不挡也不顺延」，§103.8 修 1；§104.9 一）
    return _declined_since(attempts, attention_at(task, view), side_notices=False)


def _declined_since(attempts: list[Attempt], attention: float, *, side_notices: bool = True) -> bool:
    """关注时刻之后有没有被发起方拒绝或拒收的 notice；side_notices=False 时不算 note 告知与沉默提醒（只主提醒一侧）。"""
    # 任务内补充消息与催执行方都发给执行方：执行方拒收它们不是发起方拒绝这次关注（DESIGN §95.5.3、§104.9 一）
    return any(
        attempt.role is Role.NOTICE and not attempt.is_note and not attempt.is_nudge
        and attempt.created_at >= attention and attempt.delivery in _DECLINED
        and (side_notices or not side_notice(attempt))
        for attempt in attempts
    )


def is_note_notice(attempt: Attempt) -> bool:
    """这条 notice 是不是「补充消息未送达」的告知（§103.2）：它不是主提醒的回执，不挡、不重置主提醒。"""
    token = attempt.options.get(REMINDER_OPTION)
    return attempt.role is Role.NOTICE and isinstance(token, str) and _NOTE_TOKEN in token


def side_notice(attempt: Attempt) -> bool:
    """不是「这次关注的主回执」的 notice（§104.9 一）：note 未送达告知、沉默提醒与催执行方。

    主提醒的排队与拒绝判定都跳过它们：它们既不挡住、也不顺延主提醒。
    """
    return is_note_notice(attempt) or attempt.is_silent_reminder or attempt.is_nudge


def nudge_token(attempt: Attempt) -> str:
    """催执行方的令牌（§104.9 一）：锚在工作尝试上，每次尝试只催一次。"""
    return f"{attempt.id}{_NUDGE_TOKEN}"


def _silent_count(attempts: list[Attempt], work: Attempt) -> int:
    """这个工作尝试已占用的沉默提醒名额（上限 3）：因 reminder_outdated 作废、从未交出的不算（§104.12 第 4 条）。

    发起方离线期间锚点每动一次就会作废一条排队中的提醒；把它们也算进去，名额会在发起方一条都没收到时被耗光。
    只放这一种：同令牌去重（任何状态都挡）、结果不明（UNKNOWN 照算）与任务总容量上限都不变。
    """
    prefix = f"{work.id}{SILENT_TOKEN_MARK}"
    return sum(1 for item in attempts if item.is_silent_reminder and not _outdated_before_send(item)
               and str(item.options.get(REMINDER_OPTION)).startswith(prefix))


def _outdated_before_send(attempt: Attempt) -> bool:
    """发送前因令牌过期被作废（PENDING → CANCELLED，原因 reminder_outdated）：从没交出过。"""
    return attempt.delivery is Delivery.CANCELLED and attempt.delivery_reason == "reminder_outdated"


def silence_anchor(attempts: list[Attempt], work: Attempt) -> float | None:
    """沉默的锚点（§104.9 一、§104.11 第 2 条）：max(投递时刻, 工作时刻, 本机该尝试最近一条催促的建立时刻,
    该尝试已交出补充的投递时刻)；工作尝试的投递时刻与工作时刻都缺失时为 None。

    第二次起的 --ack 不改任何时刻，所以不换锚点；联邦里投递时刻是投递设备的钟、工作时刻是权威设备的钟（已知限制）。
    催促只在本机账本里有：执行方忙过 T 之后停下不汇报时先被催，催后满 T 仍无汇报再告诉发起方。
    补充（回答提问、发起方催问）交到对方手里之后对方才有新的事要做，所以从交出那一刻重新计时；补充在桥内排队
    再久也按交出时刻算，投递时刻缺失时退回建立时刻。
    工作尝试本身已证明交出、却没有投递时刻（联邦 A 已采纳 B 的进展，但 B 的投递证据还没到）时，以已采纳报告的时刻
    （work_at）为起点（§104.12 第 7 条）；两者都没有才是 None。
    """
    base = work.delivery_at if work.delivery_at is not None else work.work_at
    if base is None:
        return None
    marks = [base, *([work.work_at] if work.work_at is not None else [])]
    token = nudge_token(work)
    marks.extend(item.created_at for item in attempts if item.is_nudge and item.options.get(REMINDER_OPTION) == token)
    # 取 max(建立, 交出)：联邦里 delivery_at 是投递设备（B）的钟，B 的钟偏慢时只用它会把锚点提前
    marks.extend(max(item.created_at, item.delivery_at) if item.delivery_at is not None else item.created_at
                 for item in attempts if item.note_for_seq == work.seq and item.delivery in HANDED_OVER)
    return max(marks)


def silence_due(task: Task, attempts: list[Attempt]) -> tuple[Attempt, float] | None:
    """满足沉默条件时返回 (当前工作尝试, 锚点)，不看时间是否已到：ab todo 与提醒共用（§104.9 一、六）。

    条件：任务没结束、没暂停；当前工作尝试已交出（written/queued/delivered）、工作仍开放、不在提问等回答
    （阶段为进行中，question_asked 是需处理）。held/unknown 各有提醒路径，不在此列。
    """
    if task.finished or task.paused:
        return None
    view = describe(task, attempts)
    current = view.current
    if view.phase is not Phase.RUNNING or current is None or current.delivery not in HANDED_OVER \
            or current.work not in _NOTE_OPEN_WORK:
        return None
    anchor = silence_anchor(attempts, current)
    return None if anchor is None else (current, anchor)


def silent_counterparty(task: Task, attempts: list[Attempt]) -> tuple[Attempt, float] | None:
    """发起方眼里「对方沉默」的资格（§104.12 第 12 条）：沉默条件成立，且当前接收方不是发起方自己（例如发起方兼任
    复核方时，自己的复核不算对方沉默）。发起方提醒与 ab todo 共用；通知渠道（--no-notify、能否送达、3 条上限、
    令牌去重）只属于提醒，不在这里。「是不是自己」带设备比较：别的设备上的同号会话是对方（§104.13 第 4 条）。"""
    found = silence_due(task, attempts)
    if task.origin is None or found is None or origin_is_receiver(task, found[0]):
        return None
    return found


def silent_now(task: Task, attempts: list[Attempt], now: float) -> bool:
    """此刻对方是否已沉默满 T（ab todo「对方沉默」一类）：资格成立且 now ≥ 锚点 + T；与提醒发没发过无关。"""
    found = silent_counterparty(task, attempts)
    return found is not None and now >= found[1] + expect_seconds(task.options)


def _silent_token(work: Attempt, anchor: float) -> str:
    return f"{work.id}{SILENT_TOKEN_MARK}{anchor:.6f}"


def _silent_reminder(task: Task, attempts: list[Attempt]) -> PendingReminder | None:
    """对方沉默那一支（§104.9 一）：每个锚点一条、每个工作尝试最多 3 条，发起方就是接收方时不发（资格判断与 ab todo
    共用 silent_counterparty）。"""
    found = silent_counterparty(task, attempts)
    if found is None:
        return None
    current, anchor = found
    if _silent_count(attempts, current) >= MAX_SILENT_PER_ATTEMPT:
        return None
    token = _silent_token(current, anchor)
    if any(item.role is Role.NOTICE and item.options.get(REMINDER_OPTION) == token for item in attempts):
        return None  # 同一令牌只发一次
    if max((item.seq for item in attempts), default=0) >= attempt_limit(Role.NOTICE, {REMINDER_OPTION: token}):
        return None  # 提醒预算已满：不为排不进的提醒驻留
    if _declined_since(attempts, anchor):
        return None  # 锚点之后发起方拒绝或拒收过给它的 notice（含沉默提醒本身）
    return PendingReminder(token=token, due_at=anchor + expect_seconds(task.options), view=describe(task, attempts),
                           kind="silent", anchor=anchor)


def note_token(note: Attempt) -> str:
    """补充消息未送达那一支的令牌：锚在 note 尝试与它落定未送达的时刻上。"""
    return f"{note.id}{_NOTE_TOKEN}{(note.delivery_at or 0.0):.6f}"


def reminder_current(task: Task, attempts: list[Attempt], token: object) -> bool:
    """已排的提醒/告知发送前复核：令牌仍是当前这次关注且未被发起方拒绝才照发（主提醒与 note 支共用入口）。"""
    if not isinstance(token, str):
        return False
    if _NOTE_TOKEN in token:
        return any(note_token(note) == token for note in _undelivered_notes(task, attempts))
    if SILENT_TOKEN_MARK in token:
        # 工作尝试 id 不变、条件仍成立、重算锚点相等；发起方在锚点之后拒绝过也作废
        found = silence_due(task, attempts)
        if (found is not None and reminder_candidate(task) and _silent_token(*found) == token
                and not _declined_since(attempts, found[1])):
            return True
        return _last_slot_silent_current(task, attempts, token)
    if token.endswith(_NUDGE_TOKEN):
        # 催执行方：尝试还是当前工作尝试、已交出、工作仍开放、不在提问等回答；已汇报（终态）或换了尝试就作废。
        # 排队后又有新进展或新交出的补充（锚点晚于这条催促自己的建立时刻）也作废（§104.12 第 6 条）；
        # 催促自己会把锚点推到它的建立时刻，那不算新进展。这里按时刻比：排队到领取之间若恰逢同一时刻或时钟回拨，
        # 会多发一条催促（已知限制；写事务那一步比进展基准，不受时钟影响）
        found = silence_due(task, attempts)
        if found is None or nudge_token(found[0]) != token:
            return False
        created = [item.created_at for item in attempts if item.is_nudge and item.options.get(REMINDER_OPTION) == token]
        return not created or found[1] <= max(created)
    current = reminder_token(task, attempts)
    return current is not None and current[0] == token and not attention_declined(task, attempts, current[1])


def _last_slot_silent_current(task: Task, attempts: list[Attempt], token: str) -> bool:
    """排在最后一个提醒序号上的沉默提醒（§104.13 第 3 条）：锚点变了也照发，工作落定或任务结束才作废。

    它的正文是「交接次数已达上限，close 后 send 新任务」，不依赖锚点；它一作废，任务里再也排不进任何提醒，发起方
    就永远收不到了。所以只要任务没结束、它盯的工作尝试仍是当前尝试且工作仍开放（未交结果、未受阻、未失败），
    发起方不是接收方、锚点之后也没拒绝过，就照常投递。最后一格按提醒档容量算，不写死 61。
    """
    queued = next((item for item in attempts if item.is_silent_reminder and item.options.get(REMINDER_OPTION) == token),
                  None)
    if queued is None or queued.seq < attempt_limit(Role.NOTICE, {REMINDER_OPTION: token}):
        return False
    if not reminder_candidate(task):
        return False
    working = work_attempts(attempts)
    current = working[-1] if working else None
    if (current is None or not token.startswith(f"{current.id}{SILENT_TOKEN_MARK}")
            or current.work not in _NOTE_OPEN_WORK or origin_is_receiver(task, current)):
        return False
    try:
        anchor = float(token.rsplit(SILENT_TOKEN_MARK, 1)[1])
    except ValueError:
        anchor = queued.created_at
    return not _declined_since(attempts, anchor)


def _undelivered_notes(task: Task, attempts: list[Attempt]) -> list[Attempt]:
    """仍值得告知的未送达补充消息：确定未送达、所补的工作尝试仍是当前尝试、发起方不是 note 的接收方、未被拒绝。"""
    origin = task.origin
    if origin is None or not reminder_candidate(task):
        return []
    working = work_attempts(attempts)
    current = working[-1] if working else None
    return [
        note for note in attempts
        if note.is_note and note.delivery in DEFINITELY_UNDELIVERED and note.delivery_at is not None
        and current is not None and note.note_for_seq == current.seq
        and not origin_is_receiver(task, note)
        and not _declined_since(attempts, note.delivery_at)
    ]


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
    if view.current is None or origin_is_receiver(task, view.current):
        return None  # 发起方就是当前接收方（例如自己复核）时它已经知道；别的设备上的同号会话不算（§104.13 第 4 条）
    if max((attempt.seq for attempt in attempts), default=0) >= attempt_limit(Role.NOTICE, {REMINDER_OPTION: token}):
        return None  # 提醒预算已满，留下终态通知和结束回执；不为排不进的提醒驻留
    if attention_declined(task, attempts, view):
        return None
    attention = attention_at(task, view)
    since = attention
    for attempt in attempts:
        # 补充消息、note 未送达告知、沉默提醒与催执行方都不是给发起方的回执：既不挡住、也不重置发起方提醒
        # （DESIGN §95.5.3、§103.2、§104.9 一）
        if attempt.role is not Role.NOTICE or attempt.is_note or side_notice(attempt):
            continue
        if attempt.options.get(REMINDER_OPTION) == token or attempt.delivery in _NOT_YET_ARRIVED:
            return None
        # 筛选锚点固定为关注时刻，不能用不断抬高的 since：否则较早创建、较晚送达的回执会被漏算（Codex 实现审计 R02）
        if attempt.created_at < attention:
            continue  # 之前几次关注的回执与提醒
        if attempt.delivery in _MAY_HAVE_ARRIVED and attempt.delivery_at is not None:
            # 从这次关注的回执实际交到发起方算起：回执晚到（worker 停摆、发现失败）时，不紧跟着再提醒（Codex 设计复审 F03）
            since = max(since, attempt.delivery_at)
    # 确定未送达立即告知；本机 `ab send` 已当场打印过这次失败（originWatch 章还在）时回到 30 分钟（§103.2）
    immediate = view.reason in IMMEDIATE_REASONS and view.current.options.get(ORIGIN_WATCH_OPTION) is not True
    return PendingReminder(token=token, due_at=since if immediate else since + REMIND_AFTER_SECONDS, view=view,
                           immediate=immediate)


def pending_notices(task: Task, attempts: list[Attempt]) -> list[PendingReminder]:
    """这项任务全部待发的提醒与告知：主提醒（至多一条）加每条确定未送达、还没告知过的补充消息（§103.2）。"""
    found: list[PendingReminder] = []
    main = pending_reminder(task, attempts)
    if main is not None:
        found.append(main)
    if reminder_candidate(task):
        silent = _silent_reminder(task, attempts)
        if silent is not None:
            found.append(silent)
    notes = _undelivered_notes(task, attempts)
    if not notes:
        return found
    view = describe(task, attempts)
    last = max((attempt.seq for attempt in attempts), default=0)
    queued = {attempt.options.get(REMINDER_OPTION) for attempt in attempts if attempt.role is Role.NOTICE}
    for note in notes:
        token = note_token(note)
        if token in queued or last >= attempt_limit(Role.NOTICE, {REMINDER_OPTION: token}):
            continue  # 同一令牌只告知一次；容量满不为它驻留
        assert note.delivery_at is not None
        found.append(PendingReminder(token=token, due_at=note.delivery_at, view=view, immediate=True, note=note,
                                     kind="note"))
    return found


def silent_minutes(reminder: PendingReminder, now: float | None) -> int:
    """沉默提醒里的「已 N 分钟没有汇报」：按排队时刻算（worker 停摆后补发时会比 T 长）；没有时刻时用 T。"""
    if reminder.anchor is None:
        return 0
    elapsed = (now if now is not None else reminder.due_at) - reminder.anchor
    return max(0, int(elapsed // 60))


def reminder_event_detail(reminder: PendingReminder, now: float | None = None) -> dict[str, object]:
    """「已提醒发起方」事件的 detail：原因码，立即告知另带 immediate=true（标签按它分支，不新增事件取值），
    补充消息那一支另带 noteSeq。只放闭集码与序号，内容无关。"""
    if reminder.note is not None:
        return {"reason": f"delivery_{reminder.note.delivery.value}", "immediate": True, "noteSeq": reminder.note.seq}
    if reminder.kind == "silent":
        return {"reason": "silent", "minutes": silent_minutes(reminder, now)}
    detail: dict[str, object] = {"reason": reminder.view.reason}
    if reminder.immediate:
        detail["immediate"] = True
    return detail


def reminder_sender_class(attempts: list[Attempt]) -> str | None:
    """提醒声明的权限类别：沿用发起方登记任务时如实记下的类别（第一条工作尝试）。

    提醒是桥替发起方的任务发给发起方自己：发起方权限模式没变时类别与接收方一致，Claude 不会因类别不同而 hold；
    同一会话换了权限模式恢复时仍可能 hold（已知限制）。账本里没有记录时不声明（Codex 设计复审 C02）。
    """
    first = next((attempt for attempt in attempts if attempt.role is not Role.NOTICE), None)
    return first.sender_class if first is not None else None


def reminder_body(task: Task, attempts: list[Attempt], view: TaskView, *, command: str | None = None,
                  names: NameBook = NO_NAMES, receiver: str | None = None, immediate: bool = False,
                  note: Attempt | None = None, silent: PendingReminder | None = None, state: str = "未知",
                  now: float | None = None, ref: str | None = None) -> str:
    """提醒正文：哪一步卡住、接收方是谁，以及下一步命令；标题由 envelope 的「任务：」行给出。

    `command` 由 worker 传它启动时解析好的入口名（DESIGN §45.36）：提醒是发给发起方照抄的。
    immediate/note 为确定未送达的立即告知（§103.2）：首行「投递未成功：#N 尝试 …」或「投递未成功：补充 #N …」。
    """
    # ref 是正文命令里的任务引用：本机缺省短 ID；联邦调用方传「完整 ID --origin-device <本机设备>」（§104.13 第 2 条），
    # 两库前八位相同时短号会命中别的任务。正文里展示用的仍是短号
    ref = ref or short(task.id)
    anchor = note if note is not None else view.current
    # 接收方标识走 NameView：本机已核实主名，否则完整 ID（§91.4.2）；跨设备调用方不传 names，即完整 ID
    # 联邦调用方对远端接收方传 receiver（带设备的人读文本）：显示引用丢了设备，不能只交给本机 formatter（§91.4.2）
    if receiver is None:
        receiver = names.local_wire(anchor.target) if anchor is not None else "对方"
    if (immediate or note is not None) and anchor is not None:
        return "\n".join(_undelivered_lines(task, attempts, anchor, receiver=receiver, command=command,
                                             note=note is not None, ref=ref))
    if silent is not None:
        return "\n".join(_silent_lines(task, attempts, receiver=receiver, state=state, command=command,
                                        minutes=silent_minutes(silent, now), ref=ref))
    minutes = int(REMIND_AFTER_SECONDS // 60)
    lines = [f"提醒：这项任务已超过 {minutes} 分钟没有处理——{reason_text(view.reason, command=command)}（{receiver}）。"]
    step = next_step(task, attempts, ref=ref, command=command, reserved=1)
    if step is not None:
        lines.append(f"下一步：{step.text}")
    return "\n".join(lines)


def _silent_lines(task: Task, attempts: list[Attempt], *, receiver: str, state: str, command: str | None,
                  minutes: int, ref: str | None = None) -> list[str]:
    """沉默提醒正文（§104.1 A、§104.9 一）：几分钟没汇报、对方是谁与此刻状态，下一步给催问、查看、改派、关闭。

    这条提醒自己先占一个序号；补充与改派都按工作类 60 档算，容量满时只给查看与关闭。
    """
    cmd = command or command_name()
    shown = short(task.id)
    ref = ref or shown  # 命令里的任务引用（联邦带路由），展示仍用短号
    lines = [f"任务 {shown} 已 {minutes} 分钟没有汇报（{receiver}；对方：{state}）。",
             "对方可能忘了汇报、会话已停，或还在做长任务；长任务按时 --progress 就不会再收到这条。"]
    last = max((attempt.seq for attempt in attempts), default=0)
    room = last + 1 < attempt_limit(Role.HANDOFF)
    if room:
        # 占位写成带引号的中文，不用尖括号：照抄进 shell 时 <…> 是重定向（§104.11 第 1 条）
        lines.append(f'下一步：催问 {cmd} note {ref} -m "问题"；查看 {cmd} status {ref}；'
                     f'改派 {cmd} retry {ref} --force --to "目标会话"；不需要了 {cmd} close {ref}')
    else:
        lines.append(f"下一步：查看 {cmd} status {ref}；交接次数已达上限，{cmd} close {ref} 后 {cmd} send 新任务"
                     f"（可加 --follows {follows_ref(ref)} 关联）")
    return lines


def _undelivered_text(attempt: Attempt, code: str | None, *, command: str | None) -> str:
    """未送达原因的可读文字：没有登记的原因码退回投递状态的标签，不把原码直接给人看。"""
    text = reason_text(code, command=command)
    return DELIVERY_LABELS[attempt.delivery] if not code or text == code else text


def _undelivered_lines(task: Task, attempts: list[Attempt], anchor: Attempt, *, receiver: str,
                       command: str | None, note: bool, ref: str | None = None) -> list[str]:
    """确定未送达的立即告知（§103.2）。「已自动重试」只在本机尝试写：远端尝试的 options 没有这个标记（A 拿不到）。"""
    reason = _undelivered_text(anchor, anchor.delivery_reason, command=command)
    what = f"补充 #{anchor.seq}" if note else f"#{anchor.seq} 尝试"
    lines = [f"投递未成功：{what} {reason}（{receiver}）。"]
    first = auto_retry_first(anchor.options)
    if first is not None:
        lines.append(f"已自动重试 1 次（首次：{_undelivered_text(anchor, first, command=command)}）。")
    if note:
        # 还能重新补充时才说「可以安全重新补充」；容量满或已没有可补充的工作尝试时只陈述事实（§104.11 P3）
        lines.append("对方会话确定没有收到这条补充，可以安全重新补充。" if _can_renote(attempts)
                     else "对方会话确定没有收到这条补充。")
        step = _note_step(task, attempts, command=command, ref=ref)
    else:
        lines.append("对方会话确定没有收到这条消息，可以安全重试。")
        found = next_step(task, attempts, ref=ref or short(task.id), command=command, reserved=1)
        step = found.text if found is not None else None
    if step is not None:
        lines.append(f"下一步：{step}")
    return lines


def _note_room(attempts: list[Attempt]) -> bool:
    """这条告知自己先占一个序号（last + 1），重新补充的 note 还要再占一个：与 next_step 的 reserved=1 同口径。"""
    last = max((attempt.seq for attempt in attempts), default=0)
    return last + 1 < attempt_limit(Role.NOTICE, {NOTICE_KIND_OPTION: NOTE_KIND, FOR_SEQ_OPTION: 0})


def _can_renote(attempts: list[Attempt]) -> bool:
    """还能重新补充：有名额，且当前工作尝试已交出、工作仍开放。"""
    working = work_attempts(attempts)
    current = working[-1] if working else None
    return (_note_room(attempts) and current is not None and current.delivery in _NOTE_SENT
            and current.work in _NOTE_OPEN_WORK)


def _note_step(task: Task, attempts: list[Attempt], *, command: str | None, ref: str | None = None) -> str | None:
    """补充未送达时的下一步：还能补就建议重新 ab note；容量满时给统一的容量写法（含「交接次数已达上限」，第二行据此
    写容量措辞，§104.11 P3）；已没有可补充的工作尝试时退回任务的下一步。"""
    cmd = command or command_name()
    ref = ref or short(task.id)
    if _can_renote(attempts):
        return f'可重新 {cmd} note {ref} -m "补充内容"'
    if not _note_room(attempts):
        return capacity_close_text(cmd, ref)
    found = next_step(task, attempts, ref=ref, command=command, reserved=1)
    return found.text if found is not None else None
