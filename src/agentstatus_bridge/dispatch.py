"""分发引擎：把账本中排队的尝试交给原生通道，处理回执、回复、消费证据与恢复。

规则（DESIGN §45.3）：
- 先持久化 sending 再外调；外调结果不明记 unknown，从不自动重发。
- 不按忙闲扣留：消息一律外调，对方读它的时机交给原生优先级（回执 next、交接 later，§45.42）；
  显式 `ab pause` 与仍在 PENDING 的 `ab cancel` 照旧可用。
- 投递到用户选定的进程代际；它已退出时才接续唯一存活的同会话进程，多个时不猜。
- 目标会话持续不在：可证明未发送，标 failed 并给出原因，交用户重发或改派。
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
import os
from pathlib import Path
import re
import time
import uuid

from . import envelope
from .platforms import process as procfs
from .platforms.factory import get_platform
from .endpoints import ADAPTERS
from .ids import short
from .naming import command_name
from .paths import device_name
from .model import (
    Attempt,
    Consumption,
    Delivery,
    Endpoint,
    EndpointRef,
    UNRESOLVED_NATIVE_ID,
    Provider,
    Role,
    TERMINAL_WORK,
    Task,
    note_may_steer,
)
from .reminders import (
    REMINDER_OPTION,
    PendingReminder,
    attention_declined,
    pending_reminder,
    reminder_body,
    reminder_candidate,
    reminder_sender_class,
    reminder_token,
)
from .store import Store, StoreError
from .transports import DeliveryContext, DeliveryOutcome, Transport
from .platforms.transport_codec import Receipt, parse_receipt, parse_reply
from .platforms.transport_codec import encode_address, same_address
from .native_names import NameBook
from .notification_policy import can_notify
from .transports.codex_queue import queue_item_state

# 原生调度提示按消息种类选（DESIGN §45.42）。取消忙时扣留之后，「对方什么时候读它」不再由
# 桥自己排队决定，而是交给上游为此设计的优先级：
# - 回执类（结果通知、结束回执、提醒）讲的是**已经做完**的事，被对方当前轮吸收反而更早知道结果；
# - 交接类（新任务、复核）要对方**开始做**新事，`later` 会被原生 max-next 过滤掉，等主轮可 drain。
_ROLE_PRIORITY: dict[Role, str] = {
    Role.NOTICE: "next",
    Role.HANDOFF: "later",
    Role.REVIEW: "later",
}


def native_priority(attempt: Attempt, *, note_work: Attempt | None = None) -> str:
    """这条消息希望对方什么时候读它。

    结束回执与提醒都是 `Role.NOTICE`（`is_closure` 按定义就要求 role 是 NOTICE），
    所以不需要单独分支——单独写一条只会是永远改变不了结果的死代码。

    补充消息（note）与 Codex 的 steer 同一判据 `note_may_steer`（G4 审计 r1 复核）：所补的工作尝试
    `note_work` 还没确认开始时用交接那一档 `later`，靠原生队列先进先出排在交接后面，不被对方当前那一轮
    先吸收；已确认开始再用 `next`。Claude 投递不进 Codex 队列、不会有「已离开队列」，对它就是只按 ack 判。
    查不到工作尝试按未确认处理。告知（fyi）不受影响，仍是 `next`。

    直接下标而不是 `.get(默认值)`：`Role` 是闭合枚举，漏配就该是 KeyError，
    由 `test_every_role_has_a_native_priority` 在测试期变红，而不是被静默打成某个默认值
    （与 `labels.py` 的 RUNTIME_LABELS 同一口径）。
    """
    if attempt.is_note and not note_may_steer(note_work):
        return _ROLE_PRIORITY[Role.HANDOFF]
    return _ROLE_PRIORITY[attempt.role]


# 发现结果缓存，避免 worker 每一轮都扫描 /proc 与调用 tmux
DISCOVERY_MIN_INTERVAL_SECONDS = 2.0
# 目标连续缺席这么久才判定不在，容忍短暂的发现失败
TARGET_GONE_GRACE_SECONDS = 15.0
# 不可判定的空发现只限制本 worker 驻留；消息仍 PENDING，后续 CLI 可再拉起（§79）。
DISCOVERY_PARK_SECONDS = 600.0
# Claude 直接接收不发回执，只有 hold/拒收会很快回执：写入后短暂驻留即可
WRITTEN_WATCH_SECONDS = 60.0
# held 等对方会话批准：默认 dialogExpiry 5 分钟加余量
HELD_WATCH_SECONDS = 11 * 60.0
# 已入 Codex 队列后继续观察消费证据的时长
CONSUMPTION_WATCH_SECONDS = 30 * 60.0
# 待重放的回执/回复上限：只在账本持续写入失败时累积
MAX_REPLAY_ITEMS = 256
# 发起方提醒排队失败（账本忙、排队容量满）后的重试间隔：不每秒重试刷日志
REMINDER_RETRY_SECONDS = 60.0
# 提醒扫描连续出错这么多次后不再为提醒驻留：持续故障时让 worker 能空闲退出，下次 ab 命令拉起的新进程重试
REMINDER_MAX_SCAN_ERRORS = 10

_RECEIPT_SOURCES: dict[Delivery, tuple[Delivery, ...]] = {
    Delivery.DELIVERED: (Delivery.WRITTEN, Delivery.HELD, Delivery.UNKNOWN),
    Delivery.HELD: (Delivery.WRITTEN, Delivery.UNKNOWN),
    Delivery.DENIED: (Delivery.WRITTEN, Delivery.HELD, Delivery.UNKNOWN),
    Delivery.EXPIRED: (Delivery.WRITTEN, Delivery.HELD, Delivery.UNKNOWN),
    Delivery.REFUSED: (Delivery.WRITTEN, Delivery.HELD, Delivery.UNKNOWN),
    Delivery.FAILED: (Delivery.WRITTEN, Delivery.HELD, Delivery.UNKNOWN),
}
_REPLY_CANDIDATES = (Delivery.WRITTEN, Delivery.QUEUED, Delivery.DELIVERED, Delivery.HELD, Delivery.UNKNOWN)
_UPGRADE_ON_EXACT = (Delivery.WRITTEN, Delivery.HELD, Delivery.UNKNOWN)
_UPGRADE_ON_ONLY_CANDIDATE = (Delivery.WRITTEN, Delivery.UNKNOWN)
# 前后不能紧邻十六进制字符：40 位提交号里的 32 位片段不算 ID
_HEX_ID = re.compile(r"(?<![0-9a-f])[0-9a-f]{32}(?![0-9a-f])")
_UUID_TEXT = re.compile(r"(?<![0-9a-f-])[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}(?![0-9a-f-])")
_ATTEMPT_SEQ = re.compile(r"\battempt=(\d{1,4})\b")
# 只剥掉外层开标签；引号里的 > 不是标签末尾，所有发送方属性均不参与 ID 关联。
_REPLY_OPEN = re.compile(r'''\A\s*<cross-session-message(?=[\s>])(?:[^<>"']|"[^"]*"|'[^']*')*>''')
_REPLY_CLOSE = re.compile(r"</cross-session-message>\s*\Z")

LogFn = Callable[[str, Mapping[str, object]], None]


def _no_log(_event: str, _fields: Mapping[str, object]) -> None:
    return None


def message_uuid(message_id: str) -> str:
    """把 32 位十六进制消息 ID 转成原生协议使用的 UUID 文本。"""
    return str(uuid.UUID(hex=message_id))


def select_generation(target: EndpointRef, endpoints: list[Endpoint]) -> tuple[Endpoint | None, str | None]:
    """找出应投递的活端点：优先选定的进程代际；已退出时接续唯一存活的同会话进程。

    返回 (端点, None)；没有同会话端点时 (None, None)；多个同会话端点且选定代际已不在时
    (None, "generation_ambiguous")，不猜选哪一个。
    """
    same = (
        _codex_generation_candidates(target, endpoints)
        if target.provider is Provider.CODEX
        else [item for item in endpoints if item.ref.same_session(target)]
    )
    for item in same:
        if item.ref.pid == target.pid and item.ref.start_ticks == target.start_ticks:
            return item, None
    if len(same) == 1:
        return same[0], None
    if len(same) > 1:
        return None, "generation_ambiguous"
    return None, None


def _codex_generation_candidates(target: EndpointRef, endpoints: list[Endpoint]) -> list[Endpoint]:
    """Codex 目标在每个进程代际里的候选，每个代际最多一项（DESIGN §45.48 R4）。

    同一代际内优先 `native_id` 等于目标的端点；没有时再用仍持有目标 thread 的未定根端点，并按目标 thread
    解析（身份取目标、按该 thread 重算消费者与 `shared_thread`）。只看已定根时同进程多根的端点都带着全部
    持有集合，所以不能对所有端点按「持有」匹配；也不在跨代际比较之前全局丢掉未定根端点，否则会否决仍
    持有目标的原代际、掩盖多代际歧义（Codex §45.48 第二轮 R02）。账本里旧的 `"-"` 目标匹配不到任何端点。
    """
    thread = target.native_id.lower()
    if thread == UNRESOLVED_NATIVE_ID:
        return []
    chosen: dict[tuple[int, str], Endpoint] = {}
    for item in endpoints:
        if item.ref.provider is not Provider.CODEX:
            continue
        key = (item.ref.pid, item.ref.start_ticks)
        if item.ref.native_id.lower() == thread:
            chosen[key] = item
        elif (
            key not in chosen
            and item.ref.native_id == UNRESOLVED_NATIVE_ID
            and "subagent_only" not in item.issues
            and item.holds(thread)
        ):
            chosen[key] = item.for_thread(thread)
    return list(chosen.values())


def needs_worker(store: Store, now: float, *, reminders: bool = True) -> bool:
    """是否还有需要 worker 驻留的事情：排队待发、发送中、等待回执、观察消费或等发起方提醒到期。

    reminders=False 时不扫描提醒：worker 自己用按修订号缓存的结果代替。
    CLI 不排除停泊的 PENDING；停泊仅在 Dispatcher 的进程内有效（§79）。
    """
    return _needs_worker(store, now, reminders=reminders)


def _needs_worker(
    store: Store, now: float, *, reminders: bool,
    pending_required: Callable[[Attempt], bool] | None = None,
) -> bool:
    """共享扫描；只有 worker 传入驻留过滤器，SENDING 和观察窗口从不被过滤。"""
    for attempt in store.attempts_in((Delivery.PENDING, Delivery.SENDING)):
        if attempt.delivery is Delivery.SENDING:
            return True
        task = store.get_task(attempt.task_id)
        # 结束回执在任务结束（或结束前已暂停）后才排队、告知的任务建立即关闭，照样要发（DESIGN §45.31.5、§95.5.7）
        if task is not None and (attempt.delivers_after_finish or (not task.finished and not task.paused)):
            if pending_required is None or pending_required(attempt):
                return True
    # 观察窗口判断在 SQL 里做：没人汇报的 Claude 回执会一直停在 WRITTEN，不能每秒把这些历史行连正文读一遍（DESIGN §45.29）
    if store.has_recent_delivery(Delivery.WRITTEN, after=now - WRITTEN_WATCH_SECONDS):
        return True
    if store.has_recent_delivery(Delivery.HELD, after=now - HELD_WATCH_SECONDS):
        return True
    if store.has_recent_delivery(Delivery.QUEUED, after=now - CONSUMPTION_WATCH_SECONDS, unconsumed=True):
        return True
    # 还没到提醒时刻也要驻留，到点由 run_once 排队（DESIGN §45.28.3）；先按任务字段预筛，再读尝试
    return reminders and any(
        reminder_candidate(task) and pending_reminder(task, store.attempts(task.id)) is not None
        for task in store.list_tasks()
    )


@dataclass(frozen=True)
class ResolvedReply:
    """到达时即确定的回复关联：重放只重试写入，不重新判断归属，也不依赖发送方仍然在线。"""

    attempt: Attempt
    text: str
    received_at: float
    upgrade_from: tuple[Delivery, ...]
    association: str


@dataclass
class DispatchSummary:
    sent: int = 0
    waiting: int = 0
    failed: int = 0
    recovered: int = 0


@dataclass
class Dispatcher:
    """单进程分发器；worker 循环调用 `run_once` 与 `handle_frame`。"""

    store: Store
    discover: Callable[[], list[Endpoint]]
    transports: Mapping[Provider, Transport]
    reply_address: str | None = None
    clock: Callable[[], float] = time.time
    proc_root: Path = procfs.DEFAULT_PROC
    queue_state: Callable[[str], Consumption] = queue_item_state
    attempt_queue_state: Callable[[Attempt], Consumption] | None = None
    empty_discovery_complete: Callable[[], bool] | None = None
    provider_discovery_complete: Callable[[Provider], bool] | None = None
    pending_ready: Callable[[set[str]], bool] | None = None
    pending_observe: Callable[[int], None] | None = None
    # 对外命令名：与 device 同理要 lambda 晚绑定，否则类定义时就固化，测试补丁替换不掉（DESIGN §45.36）
    command: str = field(default_factory=lambda: command_name())
    # 发送方所在设备：本机投递一律填本机名，进消息头 `device=`（DESIGN §45.35）。
    # 这里要 lambda 而不是直接 `default_factory=device_name`：后者在类定义时就捕获函数对象，
    # 测试补丁替换不掉，于是「字段确实由 device_name 求值」这条接线没有守卫（独立审计 F-E）
    device: str = field(default_factory=lambda: device_name())
    log: LogFn = _no_log
    monotonic: Callable[[], float] = field(default_factory=lambda: time.monotonic)
    _discovery_wait_since: dict[str, float] = field(default_factory=dict)
    _parked_pending: set[str] = field(default_factory=set)
    _missing_since: dict[str, float] = field(default_factory=dict)
    # 原生通道已有结果、本地记账失败的尝试：只重试记账，绝不重新外调
    _unrecorded: dict[str, tuple[DeliveryOutcome, dict[str, object]]] = field(default_factory=dict)
    # 记账暂缓期间到达的回执：账本仍是 sending 会拒收，先暂存，补记成功后按到达顺序重放
    _deferred_receipts: dict[str, list[Receipt]] = field(default_factory=dict)
    # 待重放的回执与回复：写账本遇临时失败时按到达顺序保留，后续循环逐条重试，成功后才移除
    _replay_receipts: list[Receipt] = field(default_factory=list)
    _replay_replies: list[ResolvedReply] = field(default_factory=list)
    _endpoints: list[Endpoint] = field(default_factory=list)
    _endpoints_at: float | None = None
    # 排队失败的提醒令牌 → 下次重试时刻（只在本进程内有效，每轮清掉已到期的条目）
    _reminder_retry_at: dict[str, float] = field(default_factory=dict)
    # 提醒扫描或排队出错后暂停到这个时刻，不每秒刷日志；连续出错次数在 queue_reminders 整轮（扫描加排队）成功后清零
    _reminder_pause_until: float = 0.0
    _reminder_scan_errors: int = 0
    # (账本标识, 修订号) → 待提醒列表：判定不依赖时间，账本没变就不重读全部尝试（Opus 审计 F3）
    _reminder_cache: tuple[tuple[str, int], list[tuple[str, PendingReminder]]] | None = None

    def endpoints(self, *, fresh: bool = False) -> list[Endpoint]:
        now = self.clock()
        if (
            fresh
            or self._endpoints_at is None
            or now - self._endpoints_at >= DISCOVERY_MIN_INTERVAL_SECONDS
        ):
            self._endpoints = self.discover()
            self._endpoints_at = now
        return self._endpoints

    def run_once(self) -> DispatchSummary:
        summary = DispatchSummary()
        self._flush_unrecorded()
        self._drain_replays()
        summary.recovered = self.store.recover_interrupted(now=self.clock(), proc_root=self.proc_root)
        if summary.recovered:
            self.log("recovered_interrupted_sends", {"count": summary.recovered})
        # 先排提醒再取排队消息：新提醒在同一轮就能发出。提醒是附属功能，任何异常都不能拖住既有投递（Codex 设计复审 F05）
        if self.clock() >= self._reminder_pause_until:
            try:
                self.queue_reminders()
            except Exception as error:
                self._reminder_scan_failed(error)
        pending = self.store.attempts_in((Delivery.PENDING,))
        pending_ids = {attempt.id for attempt in pending}
        for attempt_id in tuple(self._discovery_wait_since):
            if attempt_id not in pending_ids:
                self._clear_discovery_wait(attempt_id)
        ready = self.pending_ready is None or self.pending_ready({a.id for a in pending})
        if pending and ready:
            try:
                endpoints = self.endpoints(fresh=self.pending_ready is not None)
                for attempt in pending:
                    outcome = self.dispatch(attempt, endpoints)
                    if outcome == "sent":
                        summary.sent += 1
                    elif outcome == "waiting":
                        summary.waiting += 1
                    elif outcome == "failed":
                        summary.failed += 1
            finally:
                if self.pending_observe is not None:
                    self.pending_observe(summary.sent)
        self.reconcile_consumption()
        return summary

    def pending_reminders(self) -> list[tuple[str, PendingReminder]]:
        """全部待提醒任务（未到期的也算），按账本修订号缓存。

        先读修订号再读任务：读取期间有新写入时，缓存键偏旧，下一轮一定重算。
        """
        mark = self.store.ledger_revision()
        if self._reminder_cache is None or self._reminder_cache[0] != mark:
            found: list[tuple[str, PendingReminder]] = []
            for task in self.store.list_tasks():
                if not reminder_candidate(task):
                    continue
                reminder = pending_reminder(task, self.store.attempts(task.id))
                if reminder is not None:
                    found.append((task.id, reminder))
            self._reminder_cache = (mark, found)
        return self._reminder_cache[1]

    def _reminder_scan_failed(self, error: Exception) -> None:
        """提醒扫描或排队出错：暂停 60 秒、丢弃缓存、记原因码；run_once 与 has_live_work 共用（Opus 复审 P3-2）。"""
        self._reminder_scan_errors += 1
        self._reminder_pause_until = self.clock() + REMINDER_RETRY_SECONDS
        self._reminder_cache = None
        self.log(
            "reminder_error",
            {
                "error": type(error).__name__,
                "code": getattr(error, "code", None),
                "consecutive": self._reminder_scan_errors,
            },
        )

    def queue_reminders(self) -> int:
        """给到期仍未处理的发起方各排队一条提醒（DESIGN §45.28.3），返回排队条数；单个任务写入失败只记日志，不拖住分发。"""
        now = self.clock()
        # 退避条目到期即清：任务结束或令牌换了的旧条目不会一直留着（Codex 实现审计 R03）
        self._reminder_retry_at = {token: at for token, at in self._reminder_retry_at.items() if at > now}
        queued = 0
        for task_id, reminder in self.pending_reminders():
            if not reminder.due(now) or reminder.token in self._reminder_retry_at:
                continue
            try:
                if self._queue_reminder(task_id, reminder.token, now):
                    queued += 1
            except StoreError as error:
                self._reminder_retry_at[reminder.token] = now + REMINDER_RETRY_SECONDS
                self.log("reminder_failed", {"task": short(task_id), "code": error.code})
        # 整轮（扫描加排队）完成才清零：只看扫描成功会让排队阶段的持续异常每轮先清零再加一，永远到不了上限（Opus 复审 P3-A）
        self._reminder_scan_errors = 0
        return queued

    def _queue_reminder(self, task_id: str, token: str, now: float) -> bool:
        # 事务内重新判定：检查与写入之间用户可能已经 accept/retry，令牌变了就不再提醒
        with self.store.transaction():
            task = self.store.get_task(task_id)
            if task is None or task.origin is None:
                return False
            if not can_notify(task.origin):
                return False
            attempts = self.store.attempts(task_id)
            reminder = pending_reminder(task, attempts)
            if reminder is None or reminder.token != token or not reminder.due(now):
                return False
            notice = self.store.add_attempt(
                task_id,
                role=Role.NOTICE,
                target=task.origin,
                body=reminder_body(task, attempts, reminder.view, command=self.command,
                                   names=NameBook.of(self._endpoints)),
                refs=[],
                now=now,
                # 提醒由桥自己生成，不冒充接收方；消息头照常显示 from=user
                sender=None,
                sender_class=reminder_sender_class(attempts),
                options={REMINDER_OPTION: token},
            )
            self.store.add_event(
                task_id, "origin_reminded", now=now, attempt_seq=notice.seq, detail={"reason": reminder.view.reason}
            )
        self.log("reminder_queued", {"task": short(task_id), "attempt": notice.seq, "reason": reminder.view.reason})
        return True

    def _claim(self, attempt: Attempt, *, now: float, pid: int, start_ticks: str, provider_ref: str | None) -> bool:
        """领取排队消息（pending→sending）。提醒在同一写事务里最后核对一次令牌，核对与领取之间不留窗口（Codex 实现审计 R01）。

        领取之后任务再变化属于「已在发送、不撤回」的边界。
        """
        with self.store.transaction():
            if REMINDER_OPTION in attempt.options:
                task = self.store.get_task(attempt.task_id)
                if task is None or self._reminder_outdated(task, attempt, now):
                    return False
            return self.store.begin_send(
                attempt.id, now=now, pid=pid, start_ticks=start_ticks, provider_ref=provider_ref
            )

    def _reminder_outdated(self, task: Task, attempt: Attempt, now: float) -> bool:
        """排队中的提醒在发送前核对令牌：返工、对方又汇报或原因变化后，取消这条尚未外调的提醒（Codex 设计复审 F02）。

        已经交给原生通道的提醒不撤回（已知限制）。
        """
        token = attempt.options.get(REMINDER_OPTION)
        if token is None:
            return False
        attempts = self.store.attempts(task.id)
        current = reminder_token(task, attempts)
        # 令牌没变且本次关注没被拒绝才照发：拒绝晚于提醒排队到达时同样作废（Codex 复审 S01）
        if current is not None and current[0] == token and not attention_declined(task, attempts, current[1]):
            return False
        if self.store.transition_delivery(
            attempt.id, expected=(Delivery.PENDING,), new=Delivery.CANCELLED, reason="reminder_outdated", now=now
        ):
            self.log("reminder_cancelled", {"task": short(task.id), "attempt": attempt.seq})
        return True

    def _note_work(self, attempt: Attempt) -> Attempt | None:
        """补充消息所补的那次工作尝试（forSeq）；不是 note 或查不到时为 None。"""
        for_seq = attempt.note_for_seq
        if for_seq is None:
            return None
        return next((item for item in self.store.attempts(attempt.task_id) if item.seq == for_seq), None)

    def _note_outdated(self, attempt: Attempt, now: float) -> bool:
        """补充消息在发送前核对所补的那次尝试：已终态汇报（结果、受阻、失败）就取消这条尚未外调的补充。

        否则对方会读到「继续当前尝试、完成后照常汇报」的页脚（G4 审计 r1 P3-4/F-3）。已交给原生通道的不追回。
        """
        if not attempt.is_note:
            return False
        work = self._note_work(attempt)
        if work is None or work.work not in TERMINAL_WORK:
            return False
        if self.store.transition_delivery(
            attempt.id, expected=(Delivery.PENDING,), new=Delivery.CANCELLED, reason="note_outdated", now=now
        ):
            self.log("note_cancelled", {"task": short(attempt.task_id), "attempt": attempt.seq})
        return True

    @staticmethod
    def _may_steer(attempt: Attempt, note_work: Attempt | None) -> bool:
        """这条消息给不给 steer 信号：告知照给；补充消息要等所补的工作尝试离开队列或已确认（G4 审计 r1 P3-1）。"""
        if not attempt.steers:
            return False
        return not attempt.is_note or note_may_steer(note_work)

    def _flush_unrecorded(self) -> None:
        for attempt_id, (outcome, detail) in list(self._unrecorded.items()):
            try:
                self.store.finish_send(
                    attempt_id,
                    delivery=outcome.delivery,
                    reason=outcome.reason,
                    provider_ref=outcome.provider_ref,
                    detail=detail,
                    now=self.clock(),
                    native_root=outcome.native_root,
                )
            except StoreError as error:
                self.log("delivery_record_retry_failed", {"code": error.code})
                continue
            del self._unrecorded[attempt_id]
            self.log("delivery_record_completed", {"delivery": outcome.delivery.value, "reason": outcome.reason})
            # 转入重放队列，由 _drain_replays 逐条应用；不在这里一次性取出后直接应用
            self._queue_replay(self._deferred_receipts.pop(attempt_id, []))

    def _queue_replay(self, receipts: list[Receipt]) -> None:
        self._replay_receipts.extend(receipts)
        overflow = len(self._replay_receipts) - MAX_REPLAY_ITEMS
        if overflow > 0:
            del self._replay_receipts[:overflow]
            self.log("receipt_replay_dropped", {"count": overflow})

    def _drain_replays(self) -> None:
        """逐条重放暂存的回执与回复；遇临时写入失败保留当前及其后各条，下一轮继续，从不重新外调。"""
        while self._replay_receipts:
            try:
                # 返回 False 表示状态已前进无需迁移（或再次暂存）：同样可以移除
                self.apply_receipt(self._replay_receipts[0])
            except StoreError as error:
                self.log("receipt_replay_retry", {"code": error.code, "pending": len(self._replay_receipts)})
                return
            self._replay_receipts.pop(0)
        while self._replay_replies:
            try:
                self._record_reply(self._replay_replies[0])
            except StoreError as error:
                self.log("reply_replay_retry", {"code": error.code, "pending": len(self._replay_replies)})
                return
            self._replay_replies.pop(0)

    def _fail(self, attempt: Attempt, reason: str, now: float) -> str:
        self._clear_discovery_wait(attempt.id)
        if self.store.transition_delivery(
            attempt.id, expected=(Delivery.PENDING,), new=Delivery.FAILED, reason=reason, now=now
        ):
            self.log("delivery_failed", {"task": short(attempt.task_id), "attempt": attempt.seq, "reason": reason})
        return "failed"

    def _clear_discovery_wait(self, attempt_id: str) -> None:
        self._discovery_wait_since.pop(attempt_id, None)
        self._parked_pending.discard(attempt_id)

    def _pending_requires_worker(self, attempt: Attempt) -> bool:
        first = self._discovery_wait_since.get(attempt.id)
        if first is None:
            return True  # 新 PENDING 或其他等待原因，不继承旧尝试的停泊。
        elapsed = self.monotonic() - first
        if elapsed < DISCOVERY_PARK_SECONDS:
            return True
        if attempt.id not in self._parked_pending:
            self._parked_pending.add(attempt.id)
            self.log("pending_parked", {
                "task": short(attempt.task_id), "attempt": attempt.seq,
                "waitSeconds": int(elapsed),
            })
        return False

    def dispatch(self, attempt: Attempt, endpoints: list[Endpoint]) -> str:
        """尝试发送一条排队消息，返回 sent / waiting / failed / skipped。"""
        task = self.store.get_task(attempt.task_id)
        # 只有结束回执不受任务结束/暂停限制；其余发送条件（目标消失、权限）完全照旧（DESIGN §45.31.5）
        if task is None or ((task.finished or task.paused) and not attempt.delivers_after_finish):
            self._clear_discovery_wait(attempt.id)
            return "skipped"
        now = self.clock()
        if get_platform().name == 'windows' and attempt.target.provider not in (Provider.CODEX, Provider.CLAUDE):
            return self._fail(attempt, 'windows_provider_not_enabled', now)
        if self._reminder_outdated(task, attempt, now) or self._note_outdated(attempt, now):
            self._clear_discovery_wait(attempt.id)
            return "skipped"
        # ADAPTERS 覆盖全部 Provider（守卫见 test_bridge_endpoints），漏成员就该是 KeyError 而不是静默放行
        if not ADAPTERS[attempt.target.provider].inbox:
            # 有没有收件通道是注册表里的静态能力：发现不到、发现整体为空、对方离线都不会让它变得能收，
            # 所以不能等 liveness 与 15 秒宽限走完才判——否则这条通知永远 PENDING、worker 一直驻留（Codex 审计 F02）
            return self._fail(attempt, "target_no_inbox", now)
        live, problem = select_generation(attempt.target, endpoints)
        if problem is not None:
            return self._fail(attempt, f"target_{problem}", now)
        if live is None:
            if self.provider_discovery_complete and not self.provider_discovery_complete(attempt.target.provider):
                self._discovery_wait_since.setdefault(attempt.id, self.monotonic())
                return "waiting"
            if (self.provider_discovery_complete is None and not endpoints
                    and not (self.empty_discovery_complete and self.empty_discovery_complete())):
                self._discovery_wait_since.setdefault(attempt.id, self.monotonic())
                return "waiting"  # 整体发现失败（tmux/proc 不可用），不据此判定目标不在
            self._clear_discovery_wait(attempt.id)
            first = self._missing_since.setdefault(attempt.id, now)
            if now - first < TARGET_GONE_GRACE_SECONDS:
                return "waiting"
            self._missing_since.pop(attempt.id, None)
            return self._fail(attempt, "target_gone", now)
        self._missing_since.pop(attempt.id, None)
        if get_platform().name == 'windows' and (
                not attempt.target.data_root or live.ref.data_root != attempt.target.data_root):
            return self._fail(attempt, 'target_root_changed', now)
        blocking = live.blocking_issues
        if blocking:
            return self._fail(attempt, f"target_{blocking[0]}", now)
        if "shared_thread" in live.issues and not attempt.allow_shared:
            # 发送前已看到多个消费者，而用户没有放行共享 thread
            return self._fail(attempt, "target_shared_thread", now)
        # 不再按忙闲扣留（DESIGN §45.42）：扣留换来的撤回窗口 7 天 0 次使用，而代价是回执中位延迟
        # 6 分钟、最大 58 分钟。上游接收路径本就没有「对方忙就不入队」的条件；忙时消息进原生队列，
        # 对方读它的时机由上面的优先级分档表达。忙闲仍用于显示与查询提示，不再充当输入调度器。
        provider = live.ref.provider
        transport = self.transports.get(provider)
        ready = getattr(transport, 'ready', None) if get_platform().name == 'windows' else None
        if provider is Provider.CLAUDE and (self.reply_address is None
                or callable(ready) and not ready(self.reply_address)):
            if get_platform().name == 'windows':
                self._discovery_wait_since.setdefault(attempt.id, self.monotonic())
            return "waiting"  # Claude 回执只能由持有收件箱的 worker 接收
        self._clear_discovery_wait(attempt.id)
        if transport is None:
            return "waiting"
        if get_platform().name == 'windows':
            record = get_platform().process.read(os.getpid()).record
            identity = (record.identity.pid, record.identity.stored_generation()) if record is not None else None
        else:
            me = procfs.read_process(os.getpid())
            identity = (me.pid, me.start_ticks) if me is not None else None
        native_message = message_uuid(attempt.message_id)
        if identity is None or not self._claim(
            attempt,
            now=now,
            pid=identity[0],
            start_ticks=identity[1],
            provider_ref=native_message if provider is Provider.CLAUDE else None,
        ):
            return "skipped"
        sender = attempt.sender
        # 消息头 from 与 Claude 帧 from-name 同走 NameView（§91.4.2）：本轮同绑定已核实的原生主名，否则完整 ID；
        # 本地 worker 只投给本机端点，发送方也是本机会话，所以设备上下文是 LOCAL/LOCAL
        sender_token = NameBook.of(endpoints).local_wire(sender) if sender is not None else None
        try:
            text = envelope.render(
                task, attempt, sender=sender_token or "user", device=self.device, command=self.command
            )
            note_work = self._note_work(attempt)  # 不是补充消息时为 None；优先级与 steer 共用
            context = DeliveryContext(
                message_uuid=native_message,
                sender_name=sender_token
                if sender_token
                else "AgentStatus 协作桥（提醒）"
                if REMINDER_OPTION in attempt.options
                else "AgentStatus 协作桥（结束回执）"
                if attempt.is_closure
                else "AgentStatus 协作桥（告知）"
                if attempt.is_fyi
                else "AgentStatus 协作桥（用户）",
                sender_session=sender.native_id if sender and sender.provider is Provider.CLAUDE else None,
                sender_class=attempt.sender_class,
                reply_to=self.reply_address if provider is Provider.CLAUDE else None,
                priority=native_priority(attempt, note_work=note_work),
                before_send=(lambda: self._windows_boundary(attempt)) if get_platform().name == 'windows' else None,
                steer=self._may_steer(attempt, note_work),
            )
        except Exception as error:
            # 尚未外调：可证明未发送，不能让记录停在发送中
            self.store.transition_delivery(
                attempt.id, expected=(Delivery.SENDING,), new=Delivery.FAILED, reason="render_failed", now=self.clock()
            )
            self.log("delivery_failed", {"task": short(attempt.task_id), "attempt": attempt.seq, "error": type(error).__name__})
            return "failed"
        try:
            outcome = transport.deliver(live, text, context)
        except Exception as error:  # 通道实现异常：外调可能已发生，只能记为不明
            outcome = DeliveryOutcome(
                Delivery.UNKNOWN, "transport_exception", detail={"exception": type(error).__name__}
            )
        detail = {
            **outcome.detail,
            "deliveredPid": live.ref.pid,
            "deliveredStart": live.ref.start_ticks,
            "deliveredPane": live.ref.pane,
            # 与 PID/start/pane 同取自实际投递端点，摘要复算绑定时整组使用（F03）
            "deliveredServerPid": live.ref.server_pid,
        }
        try:
            self.store.finish_send(
                attempt.id,
                delivery=outcome.delivery,
                reason=outcome.reason,
                provider_ref=outcome.provider_ref,
                detail=detail,
                now=self.clock(),
                native_root=outcome.native_root,
            )
        except StoreError as error:
            self._unrecorded[attempt.id] = (outcome, detail)
            self.log(
                "delivery_record_deferred",
                {"task": short(attempt.task_id), "attempt": attempt.seq, "code": error.code},
            )
            return "sent"
        self.log(
            "delivery_result",
            {
                "task": short(attempt.task_id),
                "attempt": attempt.seq,
                "provider": provider.value,
                "delivery": outcome.delivery.value,
                "reason": outcome.reason,
            },
        )
        return "failed" if outcome.delivery is Delivery.FAILED else "sent"

    def _windows_boundary(self, attempt: Attempt) -> None:
        with self.store.transaction():
            current = self.store.get_attempt(attempt.id)
            if current is None or current.delivery is not Delivery.SENDING:
                raise StoreError('boundary_record_failed')
            self.store.add_event(attempt.task_id, 'native_send_boundary', now=self.clock(),
                                 attempt_seq=attempt.seq, detail={'provider': attempt.target.provider.value})

    # ---- 回执与回复 ----

    def handle_frame(self, frame: object) -> str | None:
        """处理收件箱收到的一帧，返回处理类别（receipt/reply）或 None。"""
        receipt = parse_receipt(frame)
        if receipt is not None:
            if self._replay_receipts:
                # 前面还有待重放的回执：排在其后，保持到达顺序
                self._queue_replay([receipt])
                return None
            try:
                return "receipt" if self.apply_receipt(receipt) else None
            except StoreError as error:
                self._queue_replay([receipt])
                self.log("receipt_replay_queued", {"code": error.code})
                return None
        reply = parse_reply(frame)
        if reply is not None and reply.reply_address:
            resolved = self.resolve_reply(reply.reply_address, reply.text)
            if resolved is None:
                return None
            if self._replay_replies:
                # 前面还有待写入的回复：排在其后，保持到达顺序
                self._queue_reply(resolved)
                return None
            try:
                self._record_reply(resolved)
            except StoreError as error:
                self._queue_reply(resolved)
                self.log("reply_replay_queued", {"code": error.code})
                return None
            return "reply"
        return None

    def _queue_reply(self, resolved: ResolvedReply) -> None:
        if len(self._replay_replies) < MAX_REPLAY_ITEMS:
            self._replay_replies.append(resolved)
        else:
            self.log("reply_replay_dropped", {"task": short(resolved.attempt.task_id)})

    def apply_receipt(self, receipt: Receipt) -> bool:
        attempt = self.store.find_attempt_by_provider_ref(
            receipt.message_uuid
        ) or self.store.find_attempt_by_message_uuid(receipt.message_uuid)
        if attempt is None:
            self.log("receipt_unmatched", {"status": receipt.delivery.value})
            return False
        if attempt.id in self._unrecorded:
            pending = self._deferred_receipts.setdefault(attempt.id, [])
            if len(pending) < 8:
                pending.append(receipt)
            self.log("receipt_deferred", {"task": short(attempt.task_id), "attempt": attempt.seq, "status": receipt.delivery.value})
            return False
        sources = _RECEIPT_SOURCES.get(receipt.delivery)
        if sources is None:
            return False
        applied = self.store.transition_delivery(
            attempt.id,
            expected=sources,
            new=receipt.delivery,
            reason=receipt.reason,
            now=self.clock(),
            provider_ref=receipt.message_uuid,
        )
        self.log(
            "receipt",
            {
                "task": short(attempt.task_id),
                "attempt": attempt.seq,
                "status": receipt.delivery.value,
                "applied": applied,
            },
        )
        return applied

    def resolve_reply(self, reply_address: str, text: str) -> ResolvedReply | None:
        """在回复到达时确定它的关联；对不上任何消息时返回 None。

        关联顺序：消息 ID → 任务 ID 加 attempt 序号 → 任务 ID（该任务只有一条尝试）。回复明确提到
        ID 却对不上在途消息（例如已结束或已清理的任务）时，不退回“唯一候选”。没有任何 ID 时，
        该会话只有一条在途消息才记入它且不放行 held；多条无法区分只记录“未关联回复”。
        """
        sender = next(
            (
                item
                for item in self.endpoints(fresh=True)
                if item.socket_path and same_address(encode_address(item.socket_path), reply_address)
            ),
            None,
        )
        if sender is None:
            return None
        related = [
            attempt
            for attempt in self.store.attempts_in(tuple(Delivery))
            if attempt.target.same_session(sender.ref)
        ]
        if not related:
            return None
        body = text
        wrapper = _REPLY_OPEN.match(body)
        if wrapper is not None:
            # parse_reply 可能已截断长回复的尾部，不能依赖闭标签仍然存在。
            body = _REPLY_CLOSE.sub("", body[wrapper.end():], count=1)
        lowered = body.lower()
        mentioned = set(_HEX_ID.findall(lowered)) | {
            item.replace("-", "") for item in _UUID_TEXT.findall(lowered)
        }
        now = self.clock()

        def resolved(attempt: Attempt, upgrade_from: tuple[Delivery, ...], association: str) -> ResolvedReply:
            return ResolvedReply(attempt, text, now, upgrade_from, association)

        by_message = [item for item in related if item.message_id in mentioned]
        if len(by_message) == 1:
            return resolved(by_message[0], _UPGRADE_ON_EXACT, "message_id")
        by_task = [item for item in related if item.task_id in mentioned and item.role is not Role.NOTICE]
        if by_task:
            if len({item.task_id for item in by_task}) == 1:
                seq = _ATTEMPT_SEQ.search(lowered)
                narrowed = [item for item in by_task if seq is not None and item.seq == int(seq.group(1))]
                if len(narrowed) == 1:
                    return resolved(narrowed[0], _UPGRADE_ON_EXACT, "task_attempt")
                if len(by_task) == 1:
                    return resolved(by_task[0], _UPGRADE_ON_EXACT, "task_id")
            return resolved(by_task[-1], (), "ambiguous")
        if mentioned:
            self.log("reply_unmatched", {"mentionedIds": len(mentioned)})
            return None
        open_candidates: list[Attempt] = []
        for attempt in related:
            # 补充消息不改变执行方在做的那次工作尝试：不带 ID 的回复仍只归给工作尝试（DESIGN §95.5.3）
            if attempt.delivery not in _REPLY_CANDIDATES or attempt.is_note:
                continue
            task = self.store.get_task(attempt.task_id)
            if task is not None and not task.finished:
                open_candidates.append(attempt)
        if not open_candidates:
            return None
        if len(open_candidates) == 1:
            return resolved(open_candidates[0], _UPGRADE_ON_ONLY_CANDIDATE, "only_candidate")
        return resolved(open_candidates[-1], (), "ambiguous")

    def _record_reply(self, reply: ResolvedReply) -> None:
        """写入已确定关联的回复：事件与投递迁移同一事务，时间取到达时刻；任务已结束只记事件。"""
        attempt = reply.attempt
        detail: dict[str, object] = {"text": reply.text}
        if reply.association == "ambiguous":
            detail["ambiguous"] = True
        with self.store.transaction():
            self.store.add_event(
                attempt.task_id, "peer_reply", now=reply.received_at, attempt_seq=attempt.seq, detail=detail
            )
            task = self.store.get_task(attempt.task_id)
            if reply.upgrade_from and task is not None and not task.finished:
                self.store.transition_delivery(
                    attempt.id,
                    expected=reply.upgrade_from,
                    new=Delivery.DELIVERED,
                    reason="receiver_replied",
                    now=reply.received_at,
                )
        self.log("reply", {"task": short(attempt.task_id), "attempt": attempt.seq, "association": reply.association})

    # ---- 消费证据与存活 ----

    def reconcile_consumption(self) -> None:
        """只读查询 Codex 队列项是否已离开队列（开始执行或被删除）。"""
        now = self.clock()
        # 只取观察窗口内（或没有时间）的入队记录
        for attempt in self.store.attempts_in((Delivery.QUEUED,), delivered_since=now - CONSUMPTION_WATCH_SECONDS):
            if attempt.provider_ref is None or attempt.consumption is Consumption.LEFT_QUEUE:
                continue
            state = self.attempt_queue_state(attempt) if self.attempt_queue_state is not None else self.queue_state(attempt.provider_ref)
            if state is not Consumption.UNKNOWN and self.store.set_consumption(attempt.id, state, now=now):
                self.log(
                    "consumption",
                    {"task": short(attempt.task_id), "attempt": attempt.seq, "state": state.value},
                )

    def has_live_work(self) -> bool:
        """worker 是否需要继续驻留。"""
        pending_local = self._unrecorded or self._replay_receipts or self._replay_replies
        if pending_local or _needs_worker(
            self.store, self.clock(), reminders=False, pending_required=self._pending_requires_worker,
        ):
            return True
        if self._reminder_scan_errors >= REMINDER_MAX_SCAN_ERRORS:
            return False  # 提醒扫描持续出错：不再为提醒驻留
        if self.clock() < self._reminder_pause_until:
            return True  # 提醒扫描出错后的退避期间继续驻留，到时重试
        try:
            return bool(self.pending_reminders())
        except Exception as error:
            self._reminder_scan_failed(error)
            return self._reminder_scan_errors < REMINDER_MAX_SCAN_ERRORS
