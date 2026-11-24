"""联邦任务的只读视图适配（DESIGN §88.4/§88.17）：把 FedTask/FedAttempt 投影成本机模型对象，复用纯规则。

用途只限纯函数：阶段折叠（describe）、下一步文案（next_step）、提醒判定（pending_reminder）、容量提示。
这些视图里的远端目标是**仅供显示**的 EndpointRef（pid=-1、startTicks=`remote:<endpointId>`），
绝不能交给发现、投递、归属核验等会访问本机进程的接口——投递一律只用 TargetRef.local（见 delivery 模块）。
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Any

from ..store import StoreError
from ..transports.codex_rpc import STEER_PATHS, STEER_REJECTED_CODES
from ..native_names import UUID_SHAPE, remote_display
from ..model import (
    ASK_OPTION,
    EXPECT_OPTION,
    Attempt,
    Consumption,
    Delivery,
    EndpointRef,
    Flow,
    ReportKind,
    Role,
    Task,
    Verdict,
    Work,
)
from .codec import CodecError, is_slug
from .fedstore import FedAttempt, FederatedStore, FedTask, notice_options
from .refs import TargetRef, verified_label

# 显示用远端引用的固定标记：真实进程 PID 恒为正，-1 不可能撞上本机进程
DISPLAY_ONLY_PID = -1
DISPLAY_PREFIX = "remote:"


def display_ref(target: TargetRef, *, label: str | None = None) -> EndpointRef:
    """本机目标原样返回；远端目标投影成仅供显示的引用（provider/nativeId 保留，标签可换成 wireToken）。"""
    if target.local is not None:
        return target.local
    remote = target.remote
    return EndpointRef(
        provider=remote.provider,
        native_id=remote.native_id,
        pid=DISPLAY_ONLY_PID,
        start_ticks=DISPLAY_PREFIX + remote.endpoint_id,
        label=label or remote.display_label,
    )


def remote_text(target: TargetRef, device: str) -> str:
    """跨设备目标的人读文本（§91.4.2）：`<设备> 上的 provider@id:<完整ID>`；有对端已核实主名时写成
    `<设备> 上的 provider@名字 target=--device <设备> --to provider@id:<完整ID>`——名字只作旁注，可复制的是全限定 target。

    `device` 是 commands.device_name 的值（登记 slug，没有就是完整 deviceId）。不用 8 位短 ID：这里没有对端完整候选全集。
    设备名、会话 ID 与对端主名都来自远端，与 peers 文字行同一套处理（§101.1）：设备名与 `provider@id:<ID>` 经
    remote_display 转义；target 只在 ID 是 UUID 形状时给出，--device 不是 slug 时改用完整 deviceId；主名过不了 copyable
    （含会被改动的字符等）就不作旁注，只写完整 ID。
    """
    remote = target.remote
    token = f"{remote.provider.value}@id:{remote.native_id}"
    full = remote_display(token) or token
    shown = remote_display(device) or remote.device_id
    label = verified_label(remote.display_label, True)  # display_label 只在已核实时才存；判据与 peers、resolve_remote 共用
    if label and UUID_SHAPE.fullmatch(remote.native_id):
        reference = device if is_slug(device) else remote.device_id
        return f"{shown} 上的 {remote.provider.value}@{label} target=--device {reference} --to {full}"
    return f"{shown} 上的 {full}"


@dataclass(frozen=True)
class RemoteEndpoint:
    """远端端点在摘要里的人读形状（§103.7）：label 是已转义的面板短标签（限长由摘要做），device 是已转义的设备显示名。"""

    label: str
    device: str


@dataclass(frozen=True)
class FederatedItem:
    """一条要并入摘要的联邦权威任务（§103.7）：模型视图与其中远端端点（按 display_ref 造出的引用查）的显示信息。"""

    task: Task
    attempts: list[Attempt]
    remote: Mapping[EndpointRef, RemoteEndpoint]


def remote_endpoint(target: TargetRef, device: str) -> RemoteEndpoint:
    """远端端点在面板里的短标签与设备显示名（§103.7）：「<设备> 上的 provider@id:<完整ID>」，名字过共用判据
    verified_label 时写「<设备> 上的 provider@名字」；不带 target=（面板不是复制入口）。设备名、会话 ID 与名字都来自远端，
    与 remote_text 同一套转义。`device` 是登记名，没有就是完整 deviceId。"""
    remote = target.remote
    shown = remote_display(device) or remote.device_id
    name = verified_label(remote.display_label, True)
    token = f"{remote.provider.value}@id:{remote.native_id}"
    where = f"{remote.provider.value}@{name}" if name else (remote_display(token) or token)
    return RemoteEndpoint(f"{shown} 上的 {where}", shown)


# 一条坏联邦任务在转换成模型时可能抛的错：枚举值（Flow/Role）、时间溢出、记录损坏（corrupt_record）等
_ITEM_ERRORS = (ValueError, OverflowError, TypeError, KeyError, StoreError, CodecError)


def summary_items(store: FederatedStore, *, limit: int = 200) -> tuple[list[FederatedItem], int]:
    """并入摘要的联邦权威任务（§103.7）：本机是权威、未结束的任务转成与发起方提醒相同的模型视图
    （model_task/model_attempts，与 mirror.reminder_candidates 同一查询），并标出其中的远端端点（各尝试的目标与复核方；
    发起方在权威端恒为本机，同样判一次作防御）。关注类别由调用方按 _task_entry 判。坏任务逐条跳过，返回跳过条数。

    调用方须在联邦库的读快照里调用：修订号、任务、尝试与设备登记名取自同一时刻。
    """
    names = {str(row["device_id"]): str(row["name"]) for row in store.device_states() if row["name"]}
    items: list[FederatedItem] = []
    skipped = 0
    for task in store.tasks(authority_only=True, limit=limit):
        try:
            fed_attempts = store.attempts(task.authority_device, task.task_id)
            view_task = model_task(task)
            view_attempts = model_attempts(fed_attempts)
            remote: dict[EndpointRef, RemoteEndpoint] = {}
            for target in [item.target for item in fed_attempts] + [task.origin(), task.reviewer()]:
                if target is not None and target.local is None:
                    device = names.get(target.remote.device_id) or target.remote.device_id
                    remote[display_ref(target)] = remote_endpoint(target, device)
        except _ITEM_ERRORS:
            skipped += 1
            continue
        items.append(FederatedItem(view_task, view_attempts, remote))
    return items, skipped


def is_display_only(ref: EndpointRef) -> bool:
    """是否是 display_ref 造出的远端显示引用。"""
    return ref.pid == DISPLAY_ONLY_PID and ref.start_ticks.startswith(DISPLAY_PREFIX)


def _seconds(value: object) -> float | None:
    if isinstance(value, int) and not isinstance(value, bool):
        return value / 1000.0
    return None


def _delivery(attempt: FedAttempt) -> Delivery:
    """A 视角的投递状态：只取投递设备的证据；本机「取消请求」不算已证明未投（§88.4 P2-1）。"""
    data = attempt.delivery
    if data.get("receiverReported") is True:
        return Delivery.DELIVERED
    raw = data.get("state", "pending")
    try:
        return Delivery(raw)
    except ValueError:
        return Delivery.UNKNOWN


def model_task(task: FedTask) -> Task:
    """FedTask → 本机 Task 视图。"""
    state = task.state
    origin = task.origin()
    reviewer = task.reviewer()
    verdict = state.get("verdict")
    created = _seconds(state.get("createdAt")) or 0.0
    return Task(
        id=task.task_id,
        created_at=created,
        updated_at=_seconds(state.get("updatedAt")) or created,
        title=task.title,
        flow=Flow(state.get("flow", "handoff")),
        origin=display_ref(origin) if origin is not None else None,
        reviewer=display_ref(reviewer) if reviewer is not None else None,
        control=str(state.get("control", "active")),
        verdict=Verdict(verdict) if verdict in ("approved", "changes_requested") else None,
        accepted_at=_seconds(state.get("acceptedAt")),
        viewed_at=_seconds(state.get("viewedAt")),
        closed_at=_seconds(state.get("closedAt")),
        close_reason=state.get("closeReason") if isinstance(state.get("closeReason"), str) else None,
        options={"notify": state.get("notifyOrigin", True) is not False,
                 "allowShared": state.get("allowShared") is True,
                 # 沉默阈值 T（§104.9 一）：只在 A 的 state_json，不进 checkpoint；缺键按缺省 30 分钟
                 **({EXPECT_OPTION: state[EXPECT_OPTION]} if EXPECT_OPTION in state else {})},
        # 带上设备：发起方是不是接收方、待办里接收方是不是本机，都要比设备，不能只比投影后的会话（§104.13 第 4 条）
        device=task.authority_device,
    )


def model_attempt(attempt: FedAttempt) -> Attempt:
    """FedAttempt → 本机 Attempt 视图（id 用 msg_id，保证令牌稳定）。"""
    work_raw = attempt.effective_work.get("work")
    default_work = Work.NONE if attempt.role == "notice" else Work.AWAITING_ACK
    try:
        work = Work(work_raw) if isinstance(work_raw, str) else default_work
    except ValueError:
        work = default_work
    consumption_raw = attempt.delivery.get("consumption", "not_observed")
    try:
        consumption = Consumption(consumption_raw)
    except ValueError:
        consumption = Consumption.UNKNOWN
    result = attempt.effective_work.get("result")
    sender = None
    if attempt.sender is not None:
        sender = EndpointRef(provider=attempt.sender.provider, native_id=attempt.sender.native_id,
                             pid=DISPLAY_ONLY_PID, start_ticks=DISPLAY_PREFIX + (attempt.sender.endpoint_id or ""),
                             label=None)  # 显示走 NameBook；不把存下的 wireToken 当名字
    created = _seconds(attempt.authority_state.get("createdAt")) or 0.0
    options = notice_options(attempt.options)
    question = _ask_view(attempt.effective_work.get(ASK_OPTION))
    if question is not None:
        options[ASK_OPTION] = question  # 权威端提问（§104.9 五）：与本机同一 options 形状，describe 共用
    return Attempt(
        id=attempt.msg_id,
        task_id=attempt.task_id,
        seq=attempt.seq,
        role=Role(attempt.role),
        target=display_ref(attempt.target),
        message_id=attempt.msg_id,
        created_at=created,
        body=attempt.body,
        refs=list(attempt.refs),
        delivery=_delivery(attempt),
        delivery_reason=attempt.delivery.get("reason") if isinstance(attempt.delivery.get("reason"), str) else None,
        delivery_at=_seconds(attempt.delivery.get("at")),
        consumption=consumption,
        work=work,
        work_at=_seconds(attempt.effective_work.get("at")),
        result=result if isinstance(result, dict) else None,  # pyright: ignore[reportUnknownArgumentType]
        sender=sender,
        sender_class=attempt.sender_class if attempt.sender_class != "unknown" else None,
        # 权威端本机键 localNoticeKind 映射回 noticeKind：页脚、steer 与显示按同一口径认类别
        options=options,
        target_device=attempt.target_device,
    )


def _ask_view(raw: object) -> dict[str, Any] | None:
    """effective_work.ask（毫秒）→ 本机 options.ask 形状（秒）；形状不对视为没有提问。"""
    if not isinstance(raw, dict):
        return None
    at = _seconds(raw.get("at"))  # pyright: ignore[reportUnknownMemberType]
    note = raw.get("note")  # pyright: ignore[reportUnknownMemberType,reportUnknownVariableType]
    return None if at is None else {"at": at, "note": note if isinstance(note, str) else ""}


def model_attempts(attempts: list[FedAttempt]) -> list[Attempt]:
    return [model_attempt(item) for item in attempts]


# 已采纳报告对有效 work 的推进（§97.2）：A 采纳报告与镜像读时推导共用同一张表与同一条 ACK 规则，两端不会各算各的
_REPORT_WORK: dict[ReportKind, Work] = {ReportKind.ACK: Work.ACKNOWLEDGED, ReportKind.PROGRESS: Work.IN_PROGRESS,
                                        ReportKind.BLOCKED: Work.BLOCKED, ReportKind.FAILED: Work.FAILED}
TERMINAL_REPORTS = frozenset({ReportKind.RESULT, ReportKind.FAILED, ReportKind.APPROVE, ReportKind.CHANGES})


def fold_report(effective: Mapping[str, Any], kind: ReportKind, *, result: dict[str, Any],
                at: int | None, ask: bool = False) -> dict[str, Any]:
    """一条已采纳报告推进后的有效 work（A 的 `_accept_report` 与镜像读时推导共用，§97.2）。

    ACK 只把 awaiting_ack 推进到 acknowledged，之后再到的 ACK 不改 work；其余报告按表推进（复核结论记为
    result_submitted）。终态报告另记 result。at 为 None 时不写时间：镜像不知道 A 的采纳时刻。

    提问（§104.9 五）：只在 A 采纳时（at 非空）写 ask={"at","note"}；任何改了 work 的后续报告折叠时清掉。
    被忽略的重复 ACK 不清（与本机「第二次起的 ack 不改时刻」同口径）。镜像推导（at=None）从不写，镜像不显示需处理。
    """
    folded = dict(effective)
    if not (kind is ReportKind.ACK and folded.get("work") != Work.AWAITING_ACK.value):
        folded["work"] = _REPORT_WORK.get(kind, Work.RESULT).value
        folded.pop(ASK_OPTION, None)
        if at is not None:
            folded["at"] = at
            if ask and kind is ReportKind.PROGRESS:
                folded[ASK_OPTION] = {"at": at, "note": str(result.get("note") or "")}
    if kind in TERMINAL_REPORTS:
        folded["result"] = result
    return folded


def initial_work(role: str) -> dict[str, Any]:
    """尝试建立时的有效 work：通知类不跟踪，其余等待对方确认（A 建尝试与镜像推导的起点相同）。"""
    return {"work": (Work.NONE if role == "notice" else Work.AWAITING_ACK).value}


def derive_work(role: str, reports: Iterable[tuple[int, Mapping[str, Any], str | None]], *,
                report_high: int) -> dict[str, Any]:
    """镜像读时推导本机尝试的有效 work（§97.2 第 1 条），不写回账本。

    reports 是本设备为这个尝试交过的报告：(reportNo, 报告事实, A 的决定或 None)。按 reportNo 升序只折叠**连续
    前缀**（r1）：accepted 的计入；rejected/superseded 已知未采纳，跳过继续；还没有决定行、号码又恰好等于 A 的
    reportHigh 的那一条按已采纳处理（A 只在采纳时抬高 reportHigh），已知被拒的绝不提升；遇到第一条决定未知的报告
    就停下，后面的即使已有 accepted 决定也暂不计入；不认识的报告类别同样停下（r2）。这样推导值总是 A 某个时刻真实
    有过的状态（只会落后，不会出现 A 没有过的状态）；窄同步补回决定后自然收敛。
    """
    effective = initial_work(role)
    if role == "notice":
        return effective
    for number, fact, decision in sorted(reports, key=lambda item: item[0]):
        if decision in ("rejected", "superseded"):
            continue  # 已知未采纳：不计入，但前缀仍然连续
        if not (decision == "accepted" or (decision is None and report_high > 0 and number == report_high)):
            break  # 第一条决定未知的报告：后面的暂不计入，否则可能拼出 A 从来没有过的状态
        try:
            kind = ReportKind(fact.get("kind"))
        except ValueError:
            break  # 不认识的类别不知道 A 怎么折叠：与决定未知同样停下，宁可落后（r2）
        result: dict[str, Any] = {"note": fact.get("note") or "", "refs": list(fact.get("refs") or []),
                                  "source": fact.get("source", "agent")}
        if isinstance(fact.get("commit"), dict):
            result["commit"] = fact["commit"]
        effective = fold_report(effective, kind, result=result, at=None)
    return effective


def steer_detail(detail: Mapping[str, object]) -> dict[str, str]:
    """投递明细里可以跨设备同步的部分（§97.3）：只留 steerPath 与 steerRejected 两键，值不在闭集内就不放。

    执行端写证据与两端读证据共用这一投影：版本号、pid、filetime、登录细节与队列诊断键一律不出本机；
    旧权威端会把收到的证据原样存下，所以闭集必须由写方守住，读方再过滤一遍。
    """
    shown: dict[str, str] = {}
    path, rejected = detail.get("steerPath"), detail.get("steerRejected")
    if isinstance(path, str) and path in STEER_PATHS:
        shown["steerPath"] = path
    if isinstance(rejected, str) and rejected in STEER_REJECTED_CODES:
        shown["steerRejected"] = rejected
    return shown
