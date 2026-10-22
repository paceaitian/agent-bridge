"""Claude UDS 地址的纯编码，与Linux listener和peer帧共用。"""
import re
from dataclasses import dataclass
from urllib.parse import unquote
from ..model import Delivery

MAX_INBOX_BUFFER = 2 * 1024 * 1024

_ADDRESS_UNSAFE = re.compile(r"[^A-Za-z0-9:_/.\-]")

def encode_address(path: str) -> str:
    """回复地址：`uds:` + 路径，非安全字符按 %XX 编码。"""
    encoded = _ADDRESS_UNSAFE.sub(lambda match: "".join(f"%{byte:02X}" for byte in match.group(0).encode("utf-8")), path)
    return f"uds:{encoded}"


def same_address(left: str | None, right: str | None) -> bool:
    """Native peers may use raw or percent-encoded from addresses; decode once."""
    return isinstance(left, str) and isinstance(right, str) and unquote(left) == unquote(right)


_STATUS_MAP: dict[str, Delivery] = {
    "delivered": Delivery.DELIVERED,
    "held": Delivery.HELD,
    "denied": Delivery.DENIED,
    "expired": Delivery.EXPIRED,
    "refused": Delivery.REFUSED,
    "dropped": Delivery.FAILED,
}


@dataclass(frozen=True)
class Receipt:
    """接收端回执：原消息 ID 与映射后的投递状态。"""

    message_uuid: str
    delivery: Delivery
    reason: str


def parse_receipt(frame: object) -> Receipt | None:
    """解析 `peer_message_status` control 帧；其他帧返回 None。"""
    if not isinstance(frame, dict):
        return None
    if frame.get("type") != "control" or frame.get("action") != "peer_message_status":
        return None
    message_uuid = frame.get("orig_msg_id")
    status = frame.get("status")
    if not isinstance(message_uuid, str) or not isinstance(status, str):
        return None
    delivery = _STATUS_MAP.get(status)
    if delivery is None:
        return None
    if status == "expired" and frame.get("status_detail") == "refused":
        delivery = Delivery.REFUSED
    return Receipt(message_uuid=message_uuid.lower(), delivery=delivery, reason=f"claude_{status}")


@dataclass(frozen=True)
class PeerReply:
    """对方用原生 SendMessage 回复到收件箱的文本（有界截断，作为任务数据保存）。"""

    reply_address: str | None
    text: str


_REPLY_FROM = re.compile(r'<cross-session-message\b[^>]*\bfrom="(?P<from>[^"]*)"')


def parse_reply(frame: object, *, limit: int = 4000) -> PeerReply | None:
    """解析对方发来的 `type=user` 回复帧。"""
    if not isinstance(frame, dict) or frame.get("type") != "user":
        return None
    message = frame.get("message")
    content = message.get("content") if isinstance(message, dict) else None
    if isinstance(content, list):
        content = "".join(item["text"] for item in content
                          if isinstance(item, dict) and item.get("type") == "text" and isinstance(item.get("text"), str))
        if not content:
            return None
    if not isinstance(content, str):
        return None
    match = _REPLY_FROM.search(content)
    address = frame.get("from") if isinstance(frame.get("from"), str) else None
    if match is not None:
        address = match.group("from")
    return PeerReply(reply_address=address, text=content[:limit])
