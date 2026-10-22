"""Claude 会话消息 socket（peerProtocol 1）投递、回执收件箱与帧解析。

依据 Claude Code 2.1.268 的本地协议（DESIGN §45.5 记录实测结论）：
- Unix stream socket，每行一个 JSON（单行上限约 1 MiB）；Linux 上认证行可省，接收端按
  SO_PEERCRED 校验同一用户。
- 消息帧 `type=user`，正文包在 `<cross-session-message>` 标签中，`from-mode` 如实声明发送方
  权限类别；不知道就不声明（接收端据此决定直接投递还是 hold）。
- held/delivered/denied/expired/refused 回执以 control 帧异步发往帧里的 `from` 回复地址，
  因此回执收件箱由常驻 worker 持有。
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any
import unicodedata

from ..platforms import process as procfs
from ..platforms.factory import get_platform
from ..platforms.transport_types import ByteStream
from ..platforms.transport_codec import MAX_INBOX_BUFFER, Receipt, parse_receipt
from ..model import Delivery, Endpoint, Provider
from . import DeliveryContext, DeliveryOutcome

MAX_LINE_CHARS = 1_000_000
CONNECT_TIMEOUT_SECONDS = 5.0
INLINE_RECEIPT_SECONDS = 2.0
TAG = "cross-session-message"
PRIORITY_ENV = "AB_CLAUDE_PRIORITY"
_PRIORITIES = frozenset({"next", "later", "now"})



MAX_SENDER_NAME_CODEPOINTS = 64
_NAME_DROP_CATEGORIES = frozenset({"Cc", "Cf", "Cs", "Zl", "Zp"})


def normalize_sender_name(name: str) -> str:
    """按接收端规则预先规范发送方名称（去控制/格式字符、去首尾空白、≤64 码点），保证信封往返一致。"""
    cleaned = "".join(ch for ch in name if unicodedata.category(ch) not in _NAME_DROP_CATEGORIES).strip()
    return cleaned[:MAX_SENDER_NAME_CODEPOINTS].strip() or "agentstatus-bridge"


def _attribute(value: str) -> str:
    return (
        value.replace("&", "&amp;").replace('"', "&quot;").replace("<", "&lt;").replace(">", "&gt;")
    )


def build_frame(text: str, context: DeliveryContext, *, priority: str = "next") -> str:
    """构造一行消息帧（含换行）；超过接收端单行上限时抛 ValueError。"""
    attributes: list[str] = []
    if context.reply_to:
        attributes.append(f'from="{_attribute(context.reply_to)}"')
    if context.sender_session:
        attributes.append(f'from-session="{_attribute(context.sender_session)}"')
    attributes.append(f'from-name="{_attribute(normalize_sender_name(context.sender_name))}"')
    if context.sender_class in {"bypass", "prompting"}:
        attributes.append(f'from-mode="{context.sender_class}"')
    # 正文里出现的闭合标签不能提前结束包装
    body = text.replace(f"</{TAG}", f"<\\/{TAG}")
    content = f"<{TAG} {' '.join(attributes)}>\n{body}\n</{TAG}>"
    frame: dict[str, Any] = {
        "msgV": 1,
        "msg_id": context.message_uuid,
        "type": "user",
        "message": {"role": "user", "content": content},
        "priority": priority,
    }
    if context.reply_to:
        frame["from"] = context.reply_to
    line = json.dumps(frame, ensure_ascii=False, separators=(",", ":"))
    if len(line) + 1 > MAX_LINE_CHARS:
        raise ValueError("frame exceeds receiver line limit")
    return line + "\n"




class ClaudePeerTransport:
    """向 Claude 会话 socket 写入一条消息；回执由收件箱异步送达。"""

    provider = Provider.CLAUDE

    def __init__(self, *, proc_root: Path = procfs.DEFAULT_PROC, priority: str | None = None) -> None:
        self._proc_root = proc_root
        # 显式构造参数与环境变量是**运维覆盖**：设了就对所有消息生效，压过按消息种类的选择。
        # 没设时由每条消息的 `DeliveryContext.priority` 决定，再兜底 next（DESIGN §45.42）。
        configured = priority or os.environ.get(PRIORITY_ENV)
        self._override = configured if configured in _PRIORITIES else None

    def _priority_for(self, context: DeliveryContext) -> str:
        if self._override is not None:
            return self._override
        chosen = context.priority
        if chosen is not None and chosen in _PRIORITIES:
            return chosen
        # 兜底可达：其他 transport 复用 DeliveryContext 时可以不填 priority（Codex 侧就不填）
        return "next"

    def deliver(self, endpoint: Endpoint, text: str, context: DeliveryContext) -> DeliveryOutcome:
        path = endpoint.socket_path
        if not path:
            return DeliveryOutcome(Delivery.FAILED, "claude_socket_unavailable")
        priority = self._priority_for(context)
        try:
            frame = build_frame(text, context, priority=priority).encode("utf-8")
        except ValueError:
            return DeliveryOutcome(Delivery.FAILED, "provider_payload_too_large")
        backend = get_platform().transport
        connection = backend.new_stream()
        connection.settimeout(CONNECT_TIMEOUT_SECONDS)
        try:
            try:
                backend.connect_claude(connection, path)
            except OSError:
                # 连接未建立，没有写出任何字节
                return DeliveryOutcome(Delivery.FAILED, "claude_socket_connect_failed")
            pid, uid, _gid = backend.peer_credentials(connection)
            if (
                uid != get_platform().files.uid()
                or pid != endpoint.ref.pid
                or not procfs.is_same_generation(pid, endpoint.ref.start_ticks, self._proc_root)
            ):
                return DeliveryOutcome(Delivery.FAILED, "claude_peer_mismatch")
            try:
                connection.sendall(frame)
                backend.shutdown_write(connection)
            except OSError:
                return DeliveryOutcome(Delivery.UNKNOWN, "claude_socket_write_failed")
            detail: dict[str, Any] = {
                "priority": priority,
                "senderClass": context.sender_class or "unknown",
            }
            # 接收端可能在同一连接上立即回执；读不到就等收件箱的异步回执
            receipt = _read_inline_receipt(connection, context.message_uuid)
            if receipt is not None:
                return DeliveryOutcome(
                    receipt.delivery,
                    receipt.reason,
                    provider_ref=context.message_uuid,
                    detail={**detail, "receipt": "inline"},
                )
            return DeliveryOutcome(
                Delivery.WRITTEN, "claude_written", provider_ref=context.message_uuid, detail=detail
            )
        finally:
            connection.close()


def _read_inline_receipt(connection: ByteStream, message_uuid: str) -> Receipt | None:
    """在写完后短暂读取同一连接，寻找针对本消息的回执帧。"""
    connection.settimeout(INLINE_RECEIPT_SECONDS)
    buffer = bytearray()
    try:
        while len(buffer) < MAX_INBOX_BUFFER:
            chunk = connection.recv(65536)
            if not chunk:
                break
            buffer.extend(chunk)
            if b"\n" in chunk:
                receipt = _find_receipt(buffer, message_uuid)
                if receipt is not None:
                    return receipt
    except OSError:
        pass
    return _find_receipt(buffer, message_uuid)


def _find_receipt(buffer: bytearray, message_uuid: str) -> Receipt | None:
    for line in bytes(buffer).split(b"\n"):
        if not line.strip():
            continue
        try:
            receipt = parse_receipt(json.loads(line.decode("utf-8")))
        except (UnicodeDecodeError, ValueError):
            continue
        if receipt is not None and receipt.message_uuid == message_uuid.lower():
            return receipt
    return None


def inbox_directory() -> Path:
    return get_platform().transport.inbox_directory()


class ClaudeInbox:
    """业务层仅持有平台listener，不拥有select/socket/文件清理。"""
    def __init__(self, directory: Path | None = None, *, name: str | None = None) -> None:
        self._backend = get_platform().transport.inbox(directory, name=name)

    @property
    def backend(self) -> object:
        return self._backend

    @property
    def path(self) -> Path:
        return self._backend.path

    @property
    def address(self) -> str:
        return self._backend.address

    def open(self) -> None:
        self._backend.open()

    def healthy(self) -> bool:
        return self._backend.healthy()

    def poll(self, timeout: float) -> list[object]:
        return self._backend.poll(timeout)

    def close(self) -> None:
        self._backend.close()
