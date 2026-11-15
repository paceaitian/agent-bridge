"""原生投递通道的共同接口。"""

from __future__ import annotations

from dataclasses import dataclass, field
from collections.abc import Callable
from typing import Any, Protocol

from ..model import Delivery, Endpoint, Provider


@dataclass(frozen=True)
class DeliveryOutcome:
    """一次外调的结果：状态、固定原因码、原生引用与无正文诊断。"""

    delivery: Delivery
    reason: str
    provider_ref: str | None = None
    detail: dict[str, Any] = field(default_factory=dict)
    # §70 业务证据，不属于deliveryDetail：成功交接的数据根身份摘要。
    native_root: str | None = None


@dataclass(frozen=True)
class DeliveryContext:
    """投递所需的发送方信息；权限类别只如实声明，不知道就为 None。"""

    message_uuid: str
    sender_name: str
    sender_session: str | None = None
    sender_class: str | None = None
    reply_to: str | None = None
    # 原生调度提示：由消息种类决定「让对方什么时候读它」（DESIGN §45.42）。
    # 回执类用 next（被对方当前轮吸收反而更早知道结果），交接类用 later（不插进一轮无关的推理）。
    # 通道不认识的取值一律回落到通道自己的默认，不让上层写错把消息打成中断。
    priority: str | None = None
    before_send: Callable[[], None] | None = field(default=None, repr=False, compare=False)
    # 只有任务内补充消息（note）置 True：Codex 通道在对方有进行中的一轮时先 turn/steer，否则照常排队（DESIGN §95.5.4）。
    # 不从 priority 推断：结果通知、提醒、结束回执同样是 next，但本轮不走 steer
    steer: bool = False


class Transport(Protocol):
    """投递通道；实现不得在结果不明时返回 FAILED（FAILED 表示可证明未接收）。"""

    provider: Provider

    def deliver(self, endpoint: Endpoint, text: str, context: DeliveryContext) -> DeliveryOutcome: ...
