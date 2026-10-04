"""协作桥数据模型：端点身份、任务与投递尝试，以及面向用户的简化阶段。

内部把投递（delivery）、工作进展（work）、复核结论与用户验收分开保存；对外只呈现
排队/进行中/待验收/需处理/已完成/已结束（DESIGN §45.4）。
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from enum import StrEnum
import json
import re
from typing import Any


class Provider(StrEnum):
    CODEX = "codex"
    CLAUDE = "claude"
    # 只读接入：能发起、能被看见，但没有收件通道（DESIGN §45.34）
    GROK = "grok"


class Runtime(StrEnum):
    """投递前参考的对方运行状态；只影响何时发送，不是任务证据。"""

    IDLE = "idle"
    # 本轮已结束、但还有后台工作（后台任务或子代理）在跑：可以投递，但不是「停下未汇报」（DESIGN §45.37）
    BACKGROUND = "background"
    BUSY = "busy"
    WAITING = "waiting"
    UNKNOWN = "unknown"


class Delivery(StrEnum):
    PENDING = "pending"  # 桥内排队，确定尚未外调
    SENDING = "sending"  # 已持久化发送意图，外调进行中
    WRITTEN = "written"  # Claude socket 已写入，尚无接收端回执
    QUEUED = "queued"  # Codex 原生 thread 队列已接收
    DELIVERED = "delivered"  # Claude 接收端确认已交给会话
    HELD = "held"  # Claude 接收端暂存，等对方会话里批准
    REFUSED = "refused"
    DENIED = "denied"
    EXPIRED = "expired"
    FAILED = "failed"  # 原生通道明确未接收（可读原因码）
    UNKNOWN = "unknown"  # 外调结果不明：不自动重发
    CANCELLED = "cancelled"  # 桥内未发送即取消


# 可证明对方没有收到的状态：只有这些状态下重新发送不会造成重复执行
PROVEN_UNDELIVERED = frozenset(
    {
        Delivery.PENDING,
        Delivery.CANCELLED,
        Delivery.FAILED,
        Delivery.REFUSED,
        Delivery.DENIED,
        Delivery.EXPIRED,
    }
)
HANDED_OVER = frozenset({Delivery.WRITTEN, Delivery.QUEUED, Delivery.DELIVERED})
# 可能已经到达对方的状态：交出、对方暂存（held）与结果不明（unknown）
MAY_HAVE_ARRIVED = frozenset(HANDED_OVER | {Delivery.HELD, Delivery.UNKNOWN})
# 结束回执（DESIGN §45.31）：notice 尝试的 options 里 noticeKind=closure，closure 记 accepted/closed
NOTICE_KIND_OPTION = "noticeKind"
CLOSURE_KIND = "closure"
CLOSURE_STATE_OPTION = "closure"
DELIVERY_NEEDS_ATTENTION = frozenset(
    {
        Delivery.HELD,
        Delivery.REFUSED,
        Delivery.DENIED,
        Delivery.EXPIRED,
        Delivery.FAILED,
        Delivery.UNKNOWN,
    }
)


class Consumption(StrEnum):
    """原生队列消费证据（目前仅 Codex）：看不到不等于没消费。"""

    NOT_OBSERVED = "not_observed"
    STILL_QUEUED = "still_queued"
    LEFT_QUEUE = "left_queue"  # 队列项已不在：已开始执行或被删除
    UNKNOWN = "unknown"


class Work(StrEnum):
    NONE = "none"  # 通知类消息不跟踪工作
    AWAITING_ACK = "awaiting_ack"
    ACKNOWLEDGED = "acknowledged"
    IN_PROGRESS = "in_progress"
    BLOCKED = "blocked"
    RESULT = "result_submitted"
    FAILED = "failure_reported"


class Role(StrEnum):
    HANDOFF = "handoff"  # 交给对方完成的工作
    REVIEW = "review"  # 固定复核流程中的复核
    NOTICE = "notice"  # 回告发起方的结果通知，不需要回执


class Flow(StrEnum):
    HANDOFF = "handoff"
    REVIEW = "review"  # 实现 → 复核 固定流程


class Verdict(StrEnum):
    APPROVED = "approved"
    CHANGES = "changes_requested"


class ReportKind(StrEnum):
    ACK = "ack"
    PROGRESS = "progress"
    RESULT = "result"
    BLOCKED = "blocked"
    FAILED = "failed"
    APPROVE = "approve"
    CHANGES = "changes"


class Phase(StrEnum):
    QUEUED = "queued"
    RUNNING = "running"
    AWAITING_ACCEPTANCE = "awaiting_acceptance"
    NEEDS_ATTENTION = "needs_attention"
    DONE = "done"
    CLOSED = "closed"


PHASE_LABELS: dict[Phase, str] = {
    Phase.QUEUED: "排队",
    Phase.RUNNING: "进行中",
    Phase.AWAITING_ACCEPTANCE: "待验收",
    Phase.NEEDS_ATTENTION: "需处理",
    Phase.DONE: "已完成",
    Phase.CLOSED: "已结束",
}

# 只去空白：空格已经分隔消息头的字段，键里不含 `=`，读方按**第一个** `=` 切分即可，
# 值里的 `=` 无歧义。曾一度连 `=` 一起替换，但那会让读方比旧写方更严（Codex 审计 F01）
_TOKEN_UNSAFE = re.compile(r"\s+")


@dataclass(frozen=True)
class EndpointRef:
    """持久化的端点身份：原生会话/thread 加进程代际；标签只作显示，不参与身份判断。"""

    provider: Provider
    native_id: str
    pid: int
    start_ticks: str
    pane: str | None = None
    label: str | None = None
    # 所在 tmux server 的 PID：observer 的 Codex 会话键含它（DESIGN §45.14）；旧记录没有
    server_pid: int | None = None

    def to_dict(self) -> dict[str, object]:
        """序列化为账本字段。"""
        data: dict[str, object] = {
            "provider": self.provider.value,
            "nativeId": self.native_id,
            "pid": self.pid,
            "startTicks": self.start_ticks,
            "pane": self.pane,
            "label": self.label,
        }
        if self.server_pid is not None:
            data["tmuxServerPid"] = self.server_pid
        return data

    def to_json(self) -> str:
        """序列化为紧凑 JSON。"""
        return json.dumps(self.to_dict(), ensure_ascii=False, sort_keys=True, separators=(",", ":"))

    @classmethod
    def from_dict(cls, data: object) -> EndpointRef | None:
        """从账本字段恢复；字段不全时返回 None，不猜测。"""
        if not isinstance(data, dict):
            return None
        try:
            provider = Provider(data.get("provider"))
        except ValueError:
            return None
        native_id = data.get("nativeId")
        pid = data.get("pid")
        start_ticks = data.get("startTicks")
        if (
            not isinstance(native_id, str)
            or not native_id
            or not isinstance(pid, int)
            or isinstance(pid, bool)
            or not isinstance(start_ticks, str)
        ):
            return None
        pane = data.get("pane")
        label = data.get("label")
        server = data.get("tmuxServerPid")
        return cls(
            provider=provider,
            native_id=native_id,
            pid=pid,
            start_ticks=start_ticks,
            pane=pane if isinstance(pane, str) else None,
            label=label if isinstance(label, str) else None,
            server_pid=server if isinstance(server, int) and not isinstance(server, bool) and server > 0 else None,
        )

    @classmethod
    def from_json(cls, raw: object) -> EndpointRef | None:
        """从 JSON 文本恢复。"""
        if not isinstance(raw, str) or not raw:
            return None
        try:
            data = json.loads(raw)
        except ValueError:
            return None
        return cls.from_dict(data)

    def display(self) -> str:
        """人读名称，例如 `codex@agentstatus`。"""
        where = self.label or self.pane or self.native_id[:8]
        return f"{self.provider.value}@{where}"

    def token(self) -> str:
        """消息头里使用的无空白名称。"""
        return _TOKEN_UNSAFE.sub("-", self.display())[:64]

    def same_session(self, other: EndpointRef) -> bool:
        """同一原生会话/thread（进程可以不同）。

        `"-"` 表示「还认不出是哪个 thread」，不是身份：两个 `"-"` 不是同一会话，否则一个认不出身份的
        Codex 会话能对另一个认不出身份的会话的任务做决定（DESIGN §45.48 R5）。
        """
        return (
            self.provider is other.provider
            and self.native_id == other.native_id
            and self.native_id != UNRESOLVED_NATIVE_ID
        )


# 这些问题使端点不能作为投递目标；shared_thread 可由调用方显式放行。
# subagent_only：进程可见的 thread 全是 Codex 子代理，不可作收件人（DESIGN §45.48 R2）
# title_*：Codex 托管 daemon 下按标题 thread-id 认领失败；pane_process_ambiguous：同一终端组里有多个互不包含的 codex（DESIGN §53.3.8）
BLOCKING_ISSUES = frozenset(
    {"no_thread_yet", "ambiguous_thread", "subagent_only", "socket_unavailable", "peer_protocol_unsupported",
     "no_inbox", "title_thread_missing", "title_thread_unmatched", "title_shows_subagent", "pane_process_ambiguous"}
)
# 认不出是哪个 thread 时的占位 native_id（不是身份，见 EndpointRef.same_session）
UNRESOLVED_NATIVE_ID = "-"
# 端点身份未定的问题：按某个 thread 解析出身份后，这些问题对该身份不再成立
# pane_process_ambiguous 说的是进程不是身份，不在此列（DESIGN §53.3.8）
_IDENTITY_ISSUES = frozenset(
    {"no_thread_yet", "ambiguous_thread", "subagent_only", "multiple_roots",
     "title_thread_missing", "title_thread_unmatched", "title_shows_subagent"}
)


@dataclass(frozen=True)
class Endpoint:
    """一次发现得到的活端点。"""

    ref: EndpointRef
    runtime: Runtime = Runtime.UNKNOWN
    runtime_source: str = "none"
    socket_path: str | None = None
    name: str | None = None
    consumers: int = 1
    issues: tuple[str, ...] = ()
    # 该进程持有的全部 rollout thread 与各自的消费者数（同一次完整发现里统计，含不作为端点展示的非交互进程）。
    # 仅 Codex、仅运行期：不进 EndpointRef、不落账本（DESIGN §45.48 R1）
    threads: tuple[str, ...] = ()
    thread_consumers: tuple[tuple[str, int], ...] = ()

    @property
    def blocking_issues(self) -> tuple[str, ...]:
        """阻止投递的问题。"""
        return tuple(issue for issue in self.issues if issue in BLOCKING_ISSUES)

    def holds(self, thread: str) -> bool:
        """这个进程是否持有该 thread（大小写不敏感）。"""
        lowered = thread.lower()
        return any(item == lowered for item in self.threads)

    def for_thread(self, thread: str) -> Endpoint:
        """按该进程持有的某个根 thread 解析出的端点：身份取这个 thread，消费者数与 `shared_thread` 按它重算。

        R2/R3/R4 共用这一个入口（DESIGN §45.48 R4、Codex F03）：只消去已解决的身份问题，不沿用 `"-"` 或
        另一个根的能力字段；`--allow-shared` 的合同因此对解析后的身份照常生效。
        """
        lowered = thread.lower()
        counts = dict(self.thread_consumers)
        consumers = counts.get(lowered, 1)
        issues = tuple(issue for issue in self.issues if issue not in _IDENTITY_ISSUES and issue != "shared_thread")
        if consumers > 1:
            issues = ("shared_thread",) + issues
        return replace(self, ref=replace(self.ref, native_id=lowered), consumers=consumers, issues=issues)


@dataclass(frozen=True)
class Task:
    id: str
    created_at: float
    updated_at: float
    title: str
    flow: Flow
    origin: EndpointRef | None  # None 表示用户直接从终端/SSH/窗口发起
    reviewer: EndpointRef | None
    control: str = "active"
    verdict: Verdict | None = None
    accepted_at: float | None = None
    viewed_at: float | None = None
    closed_at: float | None = None
    close_reason: str | None = None
    # notify=False：结果不回推发起会话
    options: dict[str, Any] = field(default_factory=dict)

    @property
    def notify_origin(self) -> bool:
        return self.options.get("notify", True) is not False

    @property
    def paused(self) -> bool:
        return self.control == "paused"

    @property
    def finished(self) -> bool:
        return self.closed_at is not None or self.accepted_at is not None


@dataclass(frozen=True)
class Attempt:
    id: str
    task_id: str
    seq: int
    role: Role
    target: EndpointRef
    message_id: str
    created_at: float
    body: str
    refs: list[dict[str, Any]] = field(default_factory=list)
    delivery: Delivery = Delivery.PENDING
    delivery_reason: str | None = None
    delivery_at: float | None = None
    provider_ref: str | None = None
    delivery_detail: dict[str, Any] = field(default_factory=dict)
    consumption: Consumption = Consumption.NOT_OBSERVED
    work: Work = Work.AWAITING_ACK
    work_at: float | None = None
    result: dict[str, Any] | None = None
    # 这条消息以谁的名义发出（None 为用户）及其如实的权限类别（bypass/prompting/未知）
    sender: EndpointRef | None = None
    sender_class: str | None = None
    # allowShared=True：用户已显式允许投递到被多个进程加载的 Codex thread
    options: dict[str, Any] = field(default_factory=dict)

    @property
    def allow_shared(self) -> bool:
        return self.options.get("allowShared") is True

    @property
    def is_closure(self) -> bool:
        """验收或关闭后发给参与方的结束回执：任务结束或暂停时仍可发送（DESIGN §45.31.5）。"""
        return self.role is Role.NOTICE and self.options.get(NOTICE_KIND_OPTION) == CLOSURE_KIND


@dataclass(frozen=True)
class TaskView:
    """对外阶段、固定原因码与当前工作尝试。"""

    phase: Phase
    reason: str
    current: Attempt | None


def work_attempts(attempts: list[Attempt]) -> list[Attempt]:
    """去掉结果通知，只保留承载工作的尝试。"""
    return [attempt for attempt in attempts if attempt.role is not Role.NOTICE]


def describe(task: Task, attempts: list[Attempt]) -> TaskView:
    """把内部各维度折叠为用户可读的阶段；不从轮次结束或空闲推断任务完成。"""
    working = work_attempts(attempts)
    current = working[-1] if working else None
    if task.closed_at is not None:
        return TaskView(Phase.CLOSED, task.close_reason or "closed", current)
    if task.accepted_at is not None:
        return TaskView(Phase.DONE, "accepted", current)
    if current is None:
        return TaskView(Phase.NEEDS_ATTENTION, "no_attempt", None)
    delivery = current.delivery
    if delivery is Delivery.PENDING:
        return TaskView(Phase.QUEUED, "paused" if task.paused else "waiting_for_target", current)
    if delivery is Delivery.CANCELLED:
        return TaskView(Phase.NEEDS_ATTENTION, "cancelled_undelivered", current)
    if delivery is Delivery.SENDING:
        return TaskView(Phase.RUNNING, "sending", current)
    if delivery in DELIVERY_NEEDS_ATTENTION:
        return TaskView(Phase.NEEDS_ATTENTION, f"delivery_{delivery.value}", current)
    work = current.work
    if work is Work.BLOCKED:
        return TaskView(Phase.NEEDS_ATTENTION, "blocked_reported", current)
    if work is Work.FAILED:
        return TaskView(Phase.NEEDS_ATTENTION, "failure_reported", current)
    if work is Work.RESULT:
        if current.role is Role.REVIEW:
            if task.verdict is Verdict.CHANGES:
                return TaskView(Phase.NEEDS_ATTENTION, "changes_requested", current)
            if task.verdict is Verdict.APPROVED:
                return TaskView(Phase.AWAITING_ACCEPTANCE, "review_approved", current)
            # 缺少明确结论时绝不默认为通过
            return TaskView(Phase.NEEDS_ATTENTION, "review_verdict_missing", current)
        if task.flow is Flow.REVIEW:
            return TaskView(Phase.NEEDS_ATTENTION, "review_not_dispatched", current)
        return TaskView(Phase.AWAITING_ACCEPTANCE, "result_ready", current)
    return TaskView(Phase.RUNNING, work.value, current)
