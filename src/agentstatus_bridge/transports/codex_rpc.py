"""Codex 托管 daemon 的一次性 JSON-RPC 客户端：经 UDS 上的 WebSocket 发一条 `thread/queue/add`（DESIGN §61）。

只用标准库（桥不能 import observer 那份 WebSocket 客户端，且它不合用：拒符号链接、不声明 experimental）。
initialize 的身份与今天的 `codex queue` 完全相同（`codex-tui` + 本机 CLI 版本、`experimentalApi`），所以
daemon 看到的全局身份副作用与今天每次 `codex queue` 一样。

边界只有一条：**add 帧开始发送之前**的任何失败都能证明未入队，返回 `RpcFallback`，由调用方原样回退 CLI 通道；
之后的任何问题只能记 UNKNOWN，绝不换通道重投。本模块内的异常（`Exception`）一律就地接住、按这条边界归类，不冒泡给
dispatch（dispatch 会把冒泡的异常记成 UNKNOWN，把一次本可回退的失败变成「是否入队不明」）；`BaseException`
（用户中断、测试守卫）照常冒出。

`clientUserMessageId` 不是去重键：服务端每次插入都新生成队列项 id，同一个值发两次就是两条。响应会原样回显
全文，读完即弃，不进日志与账本。
"""

from __future__ import annotations

import base64
from collections.abc import Callable
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import socket
import stat
import struct
import time
from typing import Final

from ..model import Delivery

# 截止时间（DESIGN §61.2 第 3 条）：initialize 与上游客户端相同；最坏总时长与 CLI 通道的 60 秒相同
CONNECT_SECONDS: Final = 5.0
INITIALIZE_SECONDS: Final = 10.0
ADD_SECONDS: Final = 45.0
# 单条消息上限：响应回显全文，桥正文上限 64 KiB，JSON 转义最坏约 6 倍
MAX_MESSAGE_BYTES: Final = 1024 * 1024
_MAX_HANDSHAKE_BYTES: Final = 16_384
_WEBSOCKET_GUID: Final = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
_MAX_UNFRAGMENTED_HEADER: Final = "x-codex-websocket-max-unfragmented-message-bytes"
# RFC 6455 已定义的操作码（续帧、文本、二进制、Close、Ping、Pong）；其余保留值按协议必须断开（§5.2）
_DEFINED_OPCODES: Final = frozenset({0x0, 0x1, 0x2, 0x8, 0x9, 0xA})

CLIENT_NAME: Final = "codex-tui"
QUEUE_ADD_METHOD: Final = "thread/queue/add"
_INITIALIZE_ID: Final = 1
_ADD_ID: Final = 2

# 回退原因（`rpcFallback` 证据键的取值；version_unavailable 由调用方给出）
FALLBACK_SOCKET_MISSING: Final = "socket_missing"
FALLBACK_SOCKET_REJECTED: Final = "socket_rejected"
FALLBACK_CONNECT_FAILED: Final = "connect_failed"
FALLBACK_HANDSHAKE_FAILED: Final = "handshake_failed"
FALLBACK_INITIALIZE_FAILED: Final = "initialize_failed"
# initialize 成功之后、add 帧发出之前（组装或校验请求时）的意外失败
FALLBACK_REQUEST_FAILED: Final = "request_failed"

OUTPUT_RECOGNIZED: Final = "recognized"
OUTPUT_UNRECOGNIZED: Final = "unrecognized"
UNKNOWN_VERSION: Final = "unknown"

# 版本号形状：与 `codex --version` 里的版本同一套（`codex_queue.parse_version` 由它拼出整行形状）
VERSION_PATTERN: Final = r"\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?"
_VERSION: Final = re.compile(VERSION_PATTERN)
_MAX_VERSION_LENGTH: Final = 64
_UUID: Final = re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")

_UNRECOGNIZED_ERROR: Final = "codex_queue_unrecognized_error"

# (JSON-RPC code, message 子串, 状态, 原因码)：「已知优先」，按表序第一条命中为准（DESIGN §61.2 第 6 条；
# 依据见取证清单 §3.3）。写前的都是 FAILED；`queued submission operation failed` 写前写后都可能，UNKNOWN
_KNOWN_ERRORS: Final[tuple[tuple[int, str, Delivery, str], ...]] = (
    (-32001, "Server overloaded", Delivery.FAILED, "codex_server_overloaded"),
    (-32601, "", Delivery.FAILED, "codex_version_unsupported"),
    (-32600, "requires experimentalApi capability", Delivery.FAILED, "codex_version_unsupported"),
    (-32600, "Invalid request: unknown variant", Delivery.FAILED, "codex_version_unsupported"),
    (-32600, "Not initialized", Delivery.FAILED, "codex_rpc_protocol_error"),
    (-32600, "thread not found:", Delivery.FAILED, "codex_thread_not_found"),
    (-32600, "is archived. Run `codex unarchive", Delivery.FAILED, "codex_thread_archived"),
    (-32600, "ephemeral thread does not support queued submissions", Delivery.FAILED, "codex_thread_ephemeral"),
    (-32600, "not allowed for unloaded spawned sub-agents", Delivery.FAILED, "codex_subagent_unloaded"),
    (-32600, "direct app-server input is not allowed for multi-agent v2 sub-agents", Delivery.FAILED,
     "codex_subagent_unsupported"),
    (-32600, "invalid thread id", Delivery.FAILED, "codex_thread_invalid"),
    (-32600, "user message queue is unavailable", Delivery.FAILED, "codex_queue_unavailable"),
    (-32600, "queue cannot contain more than 100 submissions", Delivery.FAILED, "provider_queue_full"),
    # 这两条只会因桥自己的请求写错而出现：请求在反序列化或校验时被拒，未写
    (-32600, "only user input can be added to the user-message queue", Delivery.FAILED, "codex_rpc_protocol_error"),
    (-32600, "Invalid request:", Delivery.FAILED, "codex_rpc_protocol_error"),
    (-32602, "Input exceeds the maximum length", Delivery.FAILED, "provider_payload_too_large"),
    (-32603, "failed to read thread:", Delivery.FAILED, "codex_thread_unreadable"),
    (-32603, "queued submission operation failed", Delivery.UNKNOWN, "codex_queue_storage_error"),
)


@dataclass(frozen=True)
class RpcFallback:
    """add 帧发送之前就失败了：可证明未入队，调用方应原样回退 CLI 通道。"""

    reason: str


@dataclass(frozen=True)
class RpcResult:
    """add 帧已开始发送（或在发送前可证明不能发）之后的最终结果；不得换通道重投。"""

    delivery: Delivery
    reason: str
    # 服务端版本（initialize 响应的 userAgent），解析不出为 unknown
    server_version: str
    provider_ref: str | None = None
    # 结果是否落在已知接口之内；传输问题（超时、断线）为 None，不评输出
    output: str | None = None


class _Closed(Exception):
    """连接已断、帧或 JSON 有错：在哪个阶段出现决定是回退还是 UNKNOWN。"""


class _Timeout(Exception):
    """截止时间到。"""


def control_socket_path(codex_home: Path) -> Path:
    """托管 daemon 的会合点：`<CODEX_HOME>/app-server-control/app-server-control.sock`（通常是符号链接）。"""
    return codex_home / "app-server-control" / "app-server-control.sock"


def resolve_socket(link: Path) -> Path | RpcFallback:
    """解析会合点并做早失败校验；返回物理 socket 路径或回退原因。

    权威检查是连上之后的 `SO_PEERCRED`；这里只为早失败、给出可读原因：目标是 socket、属主是当前 uid、
    不给组和其他人任何权限，父目录属主是当前 uid、权限 0700（上游 daemon 目录就是 0700，socket 0600）。
    """
    if not os.path.lexists(link):
        return RpcFallback(FALLBACK_SOCKET_MISSING)
    try:
        # daemon 退出后物理 socket 被删、链接悬空：与「不存在」同义
        target = Path(os.path.realpath(link, strict=True))
    except OSError:
        return RpcFallback(FALLBACK_SOCKET_MISSING)
    uid = os.getuid()
    try:
        value = os.stat(target)
        parent = os.stat(target.parent)
    except OSError:
        return RpcFallback(FALLBACK_SOCKET_MISSING)
    if (not stat.S_ISSOCK(value.st_mode) or value.st_uid != uid or value.st_mode & 0o077
            or parent.st_uid != uid or stat.S_IMODE(parent.st_mode) != 0o700):
        return RpcFallback(FALLBACK_SOCKET_REJECTED)
    return target


def parse_server_version(user_agent: object) -> str:
    """服务端版本：与上游 daemon 客户端同法（在第一个 `/` 处切开、取其后第一个空白分隔的词），再严格验形。"""
    if not isinstance(user_agent, str):
        return UNKNOWN_VERSION
    _, separator, rest = user_agent.partition("/")
    words = rest.split()
    if not separator or not words:
        return UNKNOWN_VERSION
    version = words[0]
    if len(version) > _MAX_VERSION_LENGTH or not _VERSION.fullmatch(version):
        return UNKNOWN_VERSION
    return version


def classify_error(error: object) -> tuple[Delivery, str, str]:
    """把 add 的 JSON-RPC error 映射为 (状态, 原因码, 输出证据)；未识别即 UNKNOWN。"""
    if not isinstance(error, dict):
        return Delivery.UNKNOWN, _UNRECOGNIZED_ERROR, OUTPUT_UNRECOGNIZED
    code = error.get("code")
    message = error.get("message")
    if not isinstance(code, int) or isinstance(code, bool) or not isinstance(message, str):
        return Delivery.UNKNOWN, _UNRECOGNIZED_ERROR, OUTPUT_UNRECOGNIZED
    data = error.get("data")
    if code == -32602 and isinstance(data, dict) and data.get("input_error_code") == "input_too_large":
        return Delivery.FAILED, "provider_payload_too_large", OUTPUT_RECOGNIZED
    for known_code, needle, delivery, reason in _KNOWN_ERRORS:
        if code == known_code and needle in message:
            return delivery, reason, OUTPUT_RECOGNIZED
    return Delivery.UNKNOWN, _UNRECOGNIZED_ERROR, OUTPUT_UNRECOGNIZED


def interpret_success(result: object, client_message_id: str) -> tuple[Delivery, str, str | None, str]:
    """成功响应：队列项 id 是 UUID 形状、`clientUserMessageId` 回显等于发出的值才算入队。

    返回 (状态, 原因码, 队列项 id, 输出证据)。形状不认得为 unrecognized；形状认得、回显不符为 recognized
    （与 CLI 通道「thread 不符」同口径）。回显的 `input` 不读。
    """
    submission = result.get("queuedSubmission") if isinstance(result, dict) else None
    if not isinstance(submission, dict):
        return Delivery.UNKNOWN, "codex_queue_unparsed_output", None, OUTPUT_UNRECOGNIZED
    item = submission.get("id")
    echo = submission.get("clientUserMessageId")
    if not isinstance(item, str) or not _UUID.fullmatch(item) or not isinstance(echo, str):
        return Delivery.UNKNOWN, "codex_queue_unparsed_output", None, OUTPUT_UNRECOGNIZED
    if echo != client_message_id:
        return Delivery.UNKNOWN, "codex_queue_unparsed_output", None, OUTPUT_RECOGNIZED
    return Delivery.QUEUED, "codex_queued", item.lower(), OUTPUT_RECOGNIZED


def queue_add(
    link: Path,
    *,
    thread_id: str,
    text: str,
    client_message_id: str,
    client_version: str,
    clock: Callable[[], float] | None = None,
) -> RpcFallback | RpcResult:
    """经 daemon 发一条 `thread/queue/add`；见模块说明里的边界。"""
    now = clock or time.monotonic
    try:
        target = resolve_socket(link)
    except Exception:
        return RpcFallback(FALLBACK_SOCKET_REJECTED)
    if isinstance(target, RpcFallback):
        return target
    try:
        connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    except Exception:  # 还没外调：与 resolve_socket 同样按写前归类（不接 BaseException，不吞用户中断）
        return RpcFallback(FALLBACK_CONNECT_FAILED)
    client = _Client(connection, now)
    try:
        return client.run(target, thread_id=thread_id, text=text, client_message_id=client_message_id,
                          client_version=client_version)
    except Exception:
        # 意外异常（实现缺陷）：按 add 帧是否已开始发送归类，不冒泡给 dispatch
        if client.add_started:
            return RpcResult(Delivery.UNKNOWN, "codex_transport_error", client.server_version)
        return RpcFallback(client.stage)
    finally:
        client.close()



class _Client:
    """一条连接上的一次投递；状态只活在这一次调用里。"""

    def __init__(self, connection: socket.socket, clock: Callable[[], float]) -> None:
        self._socket = connection
        self._clock = clock
        self._buffer = bytearray()
        self._max_unfragmented: int | None = None
        # 进度：意外异常时按它归类（add 帧开始发送之后只能记 UNKNOWN）
        self.stage = FALLBACK_CONNECT_FAILED
        self.add_started = False
        self.server_version = UNKNOWN_VERSION
        # 握手成功之后才有 WebSocket 关闭握手可做
        self._upgraded = False

    def _now(self) -> float:
        return self._clock()

    def run(self, target: Path, *, thread_id: str, text: str, client_message_id: str,
            client_version: str) -> RpcFallback | RpcResult:
        deadline = self._now() + CONNECT_SECONDS
        try:
            self._socket.settimeout(max(deadline - self._now(), 0.001))
            self._socket.connect(str(target))
        except OSError:
            return RpcFallback(FALLBACK_CONNECT_FAILED)
        if not self._peer_is_me():
            return RpcFallback(FALLBACK_SOCKET_REJECTED)
        self.stage = FALLBACK_HANDSHAKE_FAILED
        try:
            self._handshake(deadline)
        except (_Closed, _Timeout, OSError, ValueError):
            return RpcFallback(FALLBACK_HANDSHAKE_FAILED)
        self._upgraded = True
        self.stage = FALLBACK_INITIALIZE_FAILED
        deadline = self._now() + INITIALIZE_SECONDS
        try:
            self._send_json({
                "id": _INITIALIZE_ID,
                "method": "initialize",
                "params": {
                    "clientInfo": {"name": CLIENT_NAME, "title": None, "version": client_version},
                    "capabilities": {"experimentalApi": True},
                },
            }, deadline)
            response = self._await_response(_INITIALIZE_ID, deadline)
            result = response.get("result")
            if not isinstance(result, dict):
                return RpcFallback(FALLBACK_INITIALIZE_FAILED)
            server_version = self.server_version = parse_server_version(result.get("userAgent"))
            self._send_json({"method": "initialized"}, deadline)
        except (_Closed, _Timeout, OSError, ValueError):
            return RpcFallback(FALLBACK_INITIALIZE_FAILED)
        self.stage = FALLBACK_REQUEST_FAILED
        request = self._encode({
            "id": _ADD_ID,
            "method": QUEUE_ADD_METHOD,
            "params": {
                "threadId": thread_id,
                # 字段名是 snake_case：枚举上的 rename_all 只改变体名（v2/turn.rs:421-431、生成的 UserInput.ts）
                "input": [{"type": "text", "text": text, "text_elements": []}],
                "clientUserMessageId": client_message_id,
            },
        })
        if (len(request) > MAX_MESSAGE_BYTES
                or (self._max_unfragmented is not None and len(request) > self._max_unfragmented)):
            # 还没发：可证明未写；CLI 连的是同一个服务端，回退无益
            return RpcResult(Delivery.FAILED, "provider_payload_too_large", server_version)
        # 从这里起，add 帧可能已部分或全部到达服务端：任何问题都只能记 UNKNOWN
        deadline = self._now() + ADD_SECONDS
        self.add_started = True
        try:
            self._send_frame(0x1, request, deadline)
            response = self._await_response(_ADD_ID, deadline)
        except _Timeout:
            return RpcResult(Delivery.UNKNOWN, "codex_queue_timeout", server_version)
        except (_Closed, OSError, ValueError):
            return RpcResult(Delivery.UNKNOWN, "codex_transport_error", server_version)
        if "error" in response:
            delivery, reason, output = classify_error(response.get("error"))
            return RpcResult(delivery, reason, server_version, output=output)
        delivery, reason, item, output = interpret_success(response.get("result"), client_message_id)
        return RpcResult(delivery, reason, server_version, provider_ref=item, output=output)

    def close(self) -> None:
        """结束连接：握手成功过就先 best-effort 发 Close（1000）再关 socket。

        正常结束时这是 RFC 6455 §7.1.2 的关闭握手；服务端先发过 Close 时，它就是 §5.5.1 要求的回应——
        `_read_message` 收到 Close 即按断开处理，调用随即结束、走到这里，所以只回一次。发不出去（对端已断、超时）
        一律忽略：归类早已定下，服务端读到 EOF 一样丢弃尚未开始的请求。
        """
        if self._upgraded:
            try:
                self._send_frame(0x8, b"\x03\xe8", self._now() + 0.2)
            except Exception:  # 收尾不改结果、不冒泡
                pass
        try:
            self._socket.close()
        except Exception:
            pass

    def _peer_is_me(self) -> bool:
        """`SO_PEERCRED` 核对对端 uid（权威检查）；拿不到凭据就不信任。"""
        if not hasattr(socket, "SO_PEERCRED"):
            return False
        try:
            credentials = self._socket.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
        except OSError:
            return False
        uid = struct.unpack("3i", credentials)[1]
        return uid == os.getuid()

    def _handshake(self, deadline: float) -> None:
        key = base64.b64encode(os.urandom(16)).decode("ascii")
        request = (
            "GET /rpc HTTP/1.1\r\n"
            "Host: localhost\r\n"
            "Upgrade: websocket\r\n"
            "Connection: Upgrade\r\n"
            f"Sec-WebSocket-Key: {key}\r\n"
            "Sec-WebSocket-Version: 13\r\n"
            "\r\n"
        ).encode("ascii")
        self._sendall(request, deadline)
        response = bytearray()
        while b"\r\n\r\n" not in response:
            response.extend(self._recv(4096, deadline))
            if len(response) > _MAX_HANDSHAKE_BYTES:
                raise _Closed("handshake too large")
        head, remainder = bytes(response).split(b"\r\n\r\n", 1)
        self._buffer.extend(remainder)
        lines = head.decode("ascii").split("\r\n")
        if not lines[0].startswith("HTTP/1.1 101 "):
            raise _Closed("upgrade rejected")
        headers: dict[str, str] = {}
        for line in lines[1:]:
            name, separator, value = line.partition(":")
            if not separator:
                raise _Closed("malformed header")
            headers[name.strip().casefold()] = value.strip()
        expected = base64.b64encode(hashlib.sha1(f"{key}{_WEBSOCKET_GUID}".encode("ascii")).digest()).decode("ascii")
        if headers.get("sec-websocket-accept") != expected or headers.get("upgrade", "").casefold() != "websocket":
            raise _Closed("upgrade mismatch")
        if "upgrade" not in {token.strip().casefold() for token in headers.get("connection", "").split(",")}:
            raise _Closed("connection header missing")
        advertised = headers.get(_MAX_UNFRAGMENTED_HEADER)
        if advertised is not None and advertised.isdigit():
            self._max_unfragmented = int(advertised)

    def _encode(self, message: dict[str, object]) -> bytes:
        return json.dumps(message, ensure_ascii=False, separators=(",", ":")).encode("utf-8")

    def _send_json(self, message: dict[str, object], deadline: float) -> None:
        self._send_frame(0x1, self._encode(message), deadline)

    def _send_frame(self, opcode: int, payload: bytes, deadline: float) -> None:
        mask = os.urandom(4)
        header = bytearray([0x80 | opcode])
        length = len(payload)
        if length < 126:
            header.append(0x80 | length)
        elif length <= 0xFFFF:
            header.append(0x80 | 126)
            header.extend(length.to_bytes(2, "big"))
        else:
            header.append(0x80 | 127)
            header.extend(length.to_bytes(8, "big"))
        # 按整数一次异或（1 MiB 以内足够快）；掩码按 4 字节循环、截到载荷长度
        repeated = (mask * (length // 4 + 1))[:length]
        masked = (int.from_bytes(payload, "big") ^ int.from_bytes(repeated, "big")).to_bytes(length, "big")
        self._sendall(bytes(header) + mask + masked, deadline)

    def _sendall(self, data: bytes, deadline: float) -> None:
        self._socket.settimeout(self._remaining(deadline))
        try:
            self._socket.sendall(data)
        except socket.timeout as error:
            raise _Timeout("send") from error

    def _remaining(self, deadline: float) -> float:
        remaining = deadline - self._now()
        if remaining <= 0:
            raise _Timeout("deadline")
        return remaining

    def _recv(self, size: int, deadline: float) -> bytes:
        self._socket.settimeout(self._remaining(deadline))
        try:
            chunk = self._socket.recv(size)
        except socket.timeout as error:
            raise _Timeout("recv") from error
        if not chunk:
            raise _Closed("connection closed")
        return chunk

    def _recv_exact(self, length: int, deadline: float) -> bytes:
        value = bytearray()
        if self._buffer:
            count = min(length, len(self._buffer))
            value.extend(self._buffer[:count])
            del self._buffer[:count]
        while len(value) < length:
            value.extend(self._recv(length - len(value), deadline))
        return bytes(value)

    def _discard(self, length: int, deadline: float) -> None:
        """读掉 `length` 字节、不保存（超限消息按截止时间分块读完）。"""
        if self._buffer:
            count = min(length, len(self._buffer))
            del self._buffer[:count]
            length -= count
        while length > 0:
            length -= len(self._recv(min(length, 65_536), deadline))

    def _read_message(self, deadline: float) -> tuple[int, bytes]:
        """读一条完整消息（拼好分片）；ping 回 pong，pong 忽略，close 视为断开，超限的消息读完丢弃。"""
        opcode: int | None = None
        parts = bytearray()
        oversize = False
        while True:
            first, second = self._recv_exact(2, deadline)
            final = bool(first & 0x80)
            frame_opcode = first & 0x0F
            if first & 0x70 or second & 0x80:
                raise _Closed("RSV bits or masked server frame")
            if frame_opcode not in _DEFINED_OPCODES:
                raise _Closed("reserved opcode")
            length = second & 0x7F
            if length == 126:
                length = int.from_bytes(self._recv_exact(2, deadline), "big")
            elif length == 127:
                length = int.from_bytes(self._recv_exact(8, deadline), "big")
            if frame_opcode >= 0x8:
                if not final or length > 125:
                    raise _Closed("invalid control frame")
                payload = self._recv_exact(length, deadline)
                if frame_opcode == 0x8:
                    # 按断开处理；回应的 Close 由 close() 发
                    raise _Closed("server closed")
                if frame_opcode == 0x9:
                    self._send_frame(0xA, payload, deadline)
                continue
            if frame_opcode == 0x0:
                if opcode is None:
                    raise _Closed("unexpected continuation")
            elif opcode is not None:
                raise _Closed("interleaved data frame")
            else:
                opcode = frame_opcode
            if oversize or len(parts) + length > MAX_MESSAGE_BYTES:
                # 已核对版本的正常成功响应不比请求大，而请求发送前已限 1 MiB：超限的多半是服务端推给这条连接的
                # 无关事件。按截止时间读完丢弃、不断开，免得把一次已入队的投递拖成 UNKNOWN（§61 第 1 轮 Opus P3-2）；
                # 异常大的响应同样被丢弃，结局是超时 UNKNOWN 或 initialize 阶段回退，方向安全
                oversize = True
                parts.clear()
                self._discard(length, deadline)
            else:
                parts.extend(self._recv_exact(length, deadline))
            if final:
                if oversize:
                    opcode, oversize = None, False
                    continue
                return opcode, bytes(parts)

    def _await_response(self, request_id: int, deadline: float) -> dict[str, object]:
        """等这个 id 的响应；其间的通知、服务端请求、二进制消息一律忽略、不回应。"""
        while True:
            opcode, payload = self._read_message(deadline)
            if opcode != 0x1:
                continue
            message = json.loads(payload.decode("utf-8"))
            if (isinstance(message, dict) and message.get("id") == request_id
                    and "method" not in message and ("result" in message or "error" in message)):
                return message
