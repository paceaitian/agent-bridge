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

from dataclasses import dataclass
import json
import os
from pathlib import Path
import re
import selectors
import socket
import struct
from typing import Any
import unicodedata

from .. import procfs
from ..model import Delivery, Endpoint, Provider
from . import DeliveryContext, DeliveryOutcome

MAX_LINE_CHARS = 1_000_000
CONNECT_TIMEOUT_SECONDS = 5.0
INLINE_RECEIPT_SECONDS = 2.0
MAX_INBOX_CLIENTS = 32
MAX_INBOX_BUFFER = 2 * 1024 * 1024
TAG = "cross-session-message"
PRIORITY_ENV = "AB_CLAUDE_PRIORITY"
_ADDRESS_UNSAFE = re.compile(r"[^A-Za-z0-9:_/.\-]")
_PEERCRED = struct.Struct("3i")

_STATUS_MAP: dict[str, Delivery] = {
    "delivered": Delivery.DELIVERED,
    "held": Delivery.HELD,
    "denied": Delivery.DENIED,
    "expired": Delivery.EXPIRED,
    "refused": Delivery.REFUSED,
    "dropped": Delivery.FAILED,
}


def encode_address(path: str) -> str:
    """回复地址：`uds:` + 路径，非安全字符按 %XX 编码。"""
    encoded = _ADDRESS_UNSAFE.sub(lambda match: "".join(f"%{byte:02X}" for byte in match.group(0).encode("utf-8")), path)
    return f"uds:{encoded}"


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
    if not isinstance(content, str):
        return None
    match = _REPLY_FROM.search(content)
    address = frame.get("from") if isinstance(frame.get("from"), str) else None
    if match is not None:
        address = match.group("from")
    return PeerReply(reply_address=address, text=content[:limit])


class ClaudePeerTransport:
    """向 Claude 会话 socket 写入一条消息；回执由收件箱异步送达。"""

    provider = Provider.CLAUDE

    def __init__(self, *, proc_root: Path = procfs.DEFAULT_PROC, priority: str | None = None) -> None:
        self._proc_root = proc_root
        configured = priority or os.environ.get(PRIORITY_ENV) or "next"
        self._priority = configured if configured in {"next", "later", "now"} else "next"

    def deliver(self, endpoint: Endpoint, text: str, context: DeliveryContext) -> DeliveryOutcome:
        path = endpoint.socket_path
        if not path:
            return DeliveryOutcome(Delivery.FAILED, "claude_socket_unavailable")
        try:
            frame = build_frame(text, context, priority=self._priority).encode("utf-8")
        except ValueError:
            return DeliveryOutcome(Delivery.FAILED, "provider_payload_too_large")
        connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        connection.settimeout(CONNECT_TIMEOUT_SECONDS)
        try:
            try:
                connection.connect(path)
            except OSError:
                # 连接未建立，没有写出任何字节
                return DeliveryOutcome(Delivery.FAILED, "claude_socket_connect_failed")
            pid, uid, _gid = _PEERCRED.unpack(
                connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, _PEERCRED.size)
            )
            if (
                uid != os.getuid()
                or pid != endpoint.ref.pid
                or not procfs.is_same_generation(pid, endpoint.ref.start_ticks, self._proc_root)
            ):
                return DeliveryOutcome(Delivery.FAILED, "claude_peer_mismatch")
            try:
                connection.sendall(frame)
                connection.shutdown(socket.SHUT_WR)
            except OSError:
                return DeliveryOutcome(Delivery.UNKNOWN, "claude_socket_write_failed")
            detail: dict[str, Any] = {
                "priority": self._priority,
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


def _read_inline_receipt(connection: socket.socket, message_uuid: str) -> Receipt | None:
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
    """回执收件箱放在 Claude 认可的默认 socket 目录中，否则接收端不会回发回执。"""
    runtime = os.environ.get("XDG_RUNTIME_DIR")
    if runtime:
        return Path(runtime) / "cc-socks"
    return Path(f"/tmp/cc-socks-{os.getuid()}")


class ClaudeInbox:
    """worker 持有的回执收件箱：非阻塞 Unix socket，每行一个 JSON 帧。"""

    def __init__(self, directory: Path | None = None, *, name: str | None = None) -> None:
        self._directory = directory or inbox_directory()
        self.path = self._directory / (name or f"{os.getpid()}.sock")
        self._selector = selectors.DefaultSelector()
        self._listener: socket.socket | None = None
        self._buffers: dict[socket.socket, bytearray] = {}

    @property
    def address(self) -> str:
        return encode_address(str(self.path))

    def open(self) -> None:
        """绑定收件箱；只清理本进程自己的同名残留。"""
        if not self._directory.exists():
            self._directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        try:
            if stat_is_socket(self.path):
                self.path.unlink()
        except OSError:
            pass
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        listener.bind(str(self.path))
        os.chmod(self.path, 0o600)
        listener.listen(16)
        listener.setblocking(False)
        self._listener = listener
        self._selector.register(listener, selectors.EVENT_READ)

    def healthy(self) -> bool:
        """收件箱文件仍在（可能被外部清理）。"""
        return self._listener is not None and stat_is_socket(self.path)

    def poll(self, timeout: float) -> list[object]:
        """等待至多 timeout 秒，返回收到的完整帧。"""
        frames: list[object] = []
        if self._listener is None:
            return frames
        for key, _mask in self._selector.select(timeout):
            sock = key.fileobj
            if not isinstance(sock, socket.socket):
                continue
            if sock is self._listener:
                self._accept()
                continue
            frames.extend(self._read(sock))
        return frames

    def _accept(self) -> None:
        assert self._listener is not None
        try:
            client, _ = self._listener.accept()
        except OSError:
            return
        if len(self._buffers) >= MAX_INBOX_CLIENTS:
            client.close()
            return
        client.setblocking(False)
        self._buffers[client] = bytearray()
        self._selector.register(client, selectors.EVENT_READ)

    def _read(self, client: socket.socket) -> list[object]:
        buffer = self._buffers.get(client)
        if buffer is None:
            return []
        try:
            chunk = client.recv(65536)
        except BlockingIOError:
            return []
        except OSError:
            chunk = b""
        frames: list[object] = []
        if chunk:
            buffer.extend(chunk)
        while b"\n" in buffer:
            line, _, rest = bytes(buffer).partition(b"\n")
            buffer[:] = rest
            try:
                frames.append(json.loads(line.decode("utf-8")))
            except (UnicodeDecodeError, ValueError):
                continue
        if not chunk or len(buffer) > MAX_INBOX_BUFFER:
            if chunk == b"" and buffer:
                try:
                    frames.append(json.loads(bytes(buffer).decode("utf-8")))
                except (UnicodeDecodeError, ValueError):
                    pass
            self._drop(client)
        return frames

    def _drop(self, client: socket.socket) -> None:
        try:
            self._selector.unregister(client)
        except (KeyError, ValueError):
            pass
        self._buffers.pop(client, None)
        client.close()

    def close(self) -> None:
        for client in list(self._buffers):
            self._drop(client)
        if self._listener is not None:
            try:
                self._selector.unregister(self._listener)
            except (KeyError, ValueError):
                pass
            self._listener.close()
            self._listener = None
            try:
                if stat_is_socket(self.path):
                    self.path.unlink()
            except OSError:
                pass
        self._selector.close()


def stat_is_socket(path: Path) -> bool:
    """路径是否为本用户拥有的 socket（不跟随符号链接）。"""
    try:
        status = os.lstat(path)
    except OSError:
        return False
    import stat as stat_module

    return stat_module.S_ISSOCK(status.st_mode) and status.st_uid == os.getuid()
