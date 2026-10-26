"""联邦任务的只读视图适配（DESIGN §88.4/§88.17）：把 FedTask/FedAttempt 投影成本机模型对象，复用纯规则。

用途只限纯函数：阶段折叠（describe）、下一步文案（next_step）、提醒判定（pending_reminder）、容量提示。
这些视图里的远端目标是**仅供显示**的 EndpointRef（pid=-1、startTicks=`remote:<endpointId>`），
绝不能交给发现、投递、归属核验等会访问本机进程的接口——投递一律只用 TargetRef.local（见 delivery 模块）。
"""

from __future__ import annotations

from ..model import (
    Attempt,
    Consumption,
    Delivery,
    EndpointRef,
    Flow,
    Role,
    Task,
    Verdict,
    Work,
)
from .fedstore import FedAttempt, FedTask
from .refs import TargetRef

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
                 "allowShared": state.get("allowShared") is True},
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
                             label=attempt.sender.wire_token)
    created = _seconds(attempt.authority_state.get("createdAt")) or 0.0
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
        options=dict(attempt.options),
    )


def model_attempts(attempts: list[FedAttempt]) -> list[Attempt]:
    return [model_attempt(item) for item in attempts]
