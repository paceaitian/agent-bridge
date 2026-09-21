"""原生投递通道的共同接口。"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol

from ..model import Delivery, Endpoint, Provider


@dataclass(frozen=True)
class DeliveryOutcome:
    """一次外调的结果：状态、固定原因码、原生引用与无正文诊断。"""

    delivery: Delivery
    reason: str
    provider_ref: str | None = None
    detail: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class DeliveryContext:
    """投递所需的发送方信息；权限类别只如实声明，不知道就为 None。"""

    message_uuid: str
    sender_name: str
    sender_session: str | None = None
    sender_class: str | None = None
    reply_to: str | None = None


class Transport(Protocol):
    """投递通道；实现不得在结果不明时返回 FAILED（FAILED 表示可证明未接收）。"""

    provider: Provider

    def deliver(self, endpoint: Endpoint, text: str, context: DeliveryContext) -> DeliveryOutcome: ...
