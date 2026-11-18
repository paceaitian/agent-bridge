"""协作桥数据模型：端点身份、任务与投递尝试，以及面向用户的简化阶段。

内部把投递（delivery）、工作进展（work）、复核结论与用户验收分开保存；对外只呈现
排队/进行中/待验收/需处理/已完成/已结束（DESIGN §45.4）。
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from enum import StrEnum
import json
import re
from typing import Any, Literal


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


# Claude Code 会话注册信息 `sessions/<pid>.json` 的 `status` → 忙闲（Claude 2.1.x：waiting 为对话框打开，shell 为正在
# 执行 shell 命令）。Linux 与 Windows 发现共用这一张表（DESIGN §96.2），放在两平台都 import 的模型模块里，Windows 不因此
# 加载 Linux 发现。Linux 另借 observer 把「只剩后台」放宽成「后台」；Windows 没有 observer，照表显示。
CLAUDE_REGISTRY_STATUS: dict[str, Runtime] = {
    "idle": Runtime.IDLE,
    "busy": Runtime.BUSY,
    "shell": Runtime.BUSY,
    "waiting": Runtime.WAITING,
}


def claude_registry_runtime(status: object) -> Runtime:
    """注册信息 `status` 的忙闲：表里的取值照表，缺字段、非字符串或未知取值一律 UNKNOWN。"""
    return CLAUDE_REGISTRY_STATUS.get(status, Runtime.UNKNOWN) if isinstance(status, str) else Runtime.UNKNOWN


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
# 提醒令牌的 options 字段；供 Store 限额判定和提醒去重共用。
REMINDER_OPTION = "reminderToken"
CLOSURE_KIND = "closure"
CLOSURE_STATE_OPTION = "closure"
# 任务内补充消息（DESIGN §95.5）：notice 尝试的 options 里 noticeKind=note，forSeq 是发出时的当前工作尝试序号
NOTE_KIND = "note"
FOR_SEQ_OPTION = "forSeq"
# 一句话告知（DESIGN §95.5.7）：建立即关闭的任务，任务 options 里 fyi=true，唯一一条 notice 尝试的 noticeKind=fyi
FYI_KIND = "fyi"
FYI_OPTION = "fyi"
# 摘要投递项要标出的 notice 类别：扩展据此静默它们触发的那一轮（结束回执 §45.31.7，补充消息与告知 §95.5.3）；
# 与 extension/collabModel.js 的 COLLAB_QUIET_NOTICE_KINDS 是同一份（test_contract_collab 核对）
QUIET_NOTICE_KINDS = frozenset({CLOSURE_KIND, NOTE_KIND, FYI_KIND})
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
    NOTICE = "notice"  # 通知类消息（结果通知、提醒、结束回执、任务内补充），不需要回执


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
    # Windows only: bound CODEX_HOME/SQL file identity, never a label or path.
    data_root: str | None = None

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
        if self.data_root is not None:
            data['dataRoot'] = self.data_root
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
            data_root=data.get('dataRoot') if isinstance(data.get('dataRoot'), str)
            and re.fullmatch(r'[0-9a-f]{64}', data['dataRoot']) else None,
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
            and self.data_root == other.data_root
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
class NameSource:
    """一个绑定的原生主名采样（DESIGN §91.3）：named 带原文；unnamed 是已确认无名；unknown 是元数据没读到（不等于无名）。"""
    state: Literal['named', 'unnamed', 'unknown']
    raw: str | None = None
    truncated: bool = False  # 原文超过显示上限被截断；恰好等于上限不算


@dataclass(frozen=True)
class NameView:
    """本轮一个绑定的名字投影（DESIGN §91.3）：可复制原生主名（name）、转义后的展示名、verified 与消歧 ID 前缀。

    由 native_names.project 计算；放在这里是为了让 Endpoint 能携带它而不形成导入环。
    """
    provider: Provider
    native_id: str
    name: str | None
    display_name: str | None
    verified: bool
    id_prefix: str

    @property
    def target(self) -> str:
        """规范可复制 target 一律完整 ID。"""
        return f'{self.provider.value}@id:{self.native_id}'


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
    # 原生主名采样（DESIGN §91.3）：截断前原文与截断事实；仅运行期，不进 EndpointRef、不落账本。None = 平台未提供
    name_source: NameSource | None = None
    # 本轮发现结束时算好的名字投影（§91.4.2：formatter 只查表、不做 I/O）；派生值，不参与相等比较、不落账本
    name_view: NameView | None = field(default=None, compare=False)
    # 本轮发现没看全的 provider（DiscoverySources.incomplete 的快照，§91.2.2）。随每个端点带出、解析时取并集：
    # 某家一个端点都没露出时，别家的端点也能把它带到。派生值，不参与相等比较、不落账本
    round_incomplete: frozenset[str] = field(default=frozenset(), compare=False)
    # 工作目录末段原文（§95.3，未转义）：只作人读旁注与快照的可选键；完整路径发现时即丢弃，不进 EndpointRef、
    # 不落账本，不参与相等比较
    workdir: str | None = field(default=None, compare=False)
    # Claude 名字的来源闭集码（§99.3）：found_custom/found_ai 或退回注册名的原因；只作诊断计数，不进目录行与账本
    name_origin: str | None = field(default=None, compare=False)

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

    @property
    def is_fyi(self) -> bool:
        """一句话告知（DESIGN §95.5.7）：建立时即关闭，没有工作尝试、提醒、结束回执与验收。"""
        return self.options.get(FYI_OPTION) is True


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

    @property
    def is_note(self) -> bool:
        """发给执行方的任务内补充消息（DESIGN §95.5）：不是工作尝试、不可汇报，也不是给发起方的回执。"""
        return self.role is Role.NOTICE and self.options.get(NOTICE_KIND_OPTION) == NOTE_KIND

    @property
    def is_fyi(self) -> bool:
        """一句话告知的那条 notice（DESIGN §95.5.7）：只需对方读到，不汇报、不回复。"""
        return self.role is Role.NOTICE and self.options.get(NOTICE_KIND_OPTION) == FYI_KIND

    @property
    def delivers_after_finish(self) -> bool:
        """任务结束（或暂停）后仍要投递：结束回执本来就在结束后才生成，告知的任务建立即关闭（§45.31.5、§95.5.7）。

        只放宽投递；is_closure 的其他含义（closure_not_needed 过滤、coversWorkMessageIds）不作用到告知。
        """
        return self.is_closure or self.is_fyi

    @property
    def steers(self) -> bool:
        """Codex 有活跃轮时走 turn/steer 的消息：补充消息与告知（§95.5.4、§95.5.7）；其余照旧走队列。"""
        return self.is_note or self.is_fyi

    @property
    def note_for_seq(self) -> int | None:
        """补充消息所补的工作尝试序号；不是 note 或记录不全时为 None。"""
        value = self.options.get(FOR_SEQ_OPTION)
        if not self.is_note or not isinstance(value, int) or isinstance(value, bool) or value <= 0:
            return None
        return value


@dataclass(frozen=True)
class TaskView:
    """对外阶段、固定原因码与当前工作尝试。"""

    phase: Phase
    reason: str
    current: Attempt | None


# 工作尝试已终态汇报：对方交了结果、受阻或失败（复核结论也记为 RESULT）
TERMINAL_WORK = frozenset({Work.BLOCKED, Work.RESULT, Work.FAILED})
# 所补的工作尝试已被执行方取走：对方已确认开始，或之后的任何汇报（§95.5.4，G4 审计 r1 P3-1）
WORK_STARTED = frozenset({Work.ACKNOWLEDGED, Work.IN_PROGRESS, Work.BLOCKED, Work.RESULT, Work.FAILED})


def note_may_steer(work: Attempt | None) -> bool:
    """补充消息能不能插进对方当前一轮（turn/steer）：所补的工作尝试已离开 Codex 队列或对方已确认开始才行。

    交接还排在 Codex 原生队列里时，对方正在跑的是别的轮：steer 会让那一轮先读到「继续当前尝试」的补充、
    之后才读到任务本身；走队列则按先进先出排在交接后面。查不到工作尝试时按不能 steer 处理。
    """
    return work is not None and (work.consumption is Consumption.LEFT_QUEUE or work.work in WORK_STARTED)


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
