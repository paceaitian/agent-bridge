"""无业务依赖的 WS-over-local-stream 编解码；§61 add 与 §69/70 复用。"""
from __future__ import annotations

import base64
from collections.abc import Callable
import hashlib
import json
import os
import socket

from ..platforms.transport_types import ByteStream, LocalPlatform
from . import local_codex

MAX_MESSAGE_BYTES = 1024 * 1024
_MAX_HANDSHAKE_BYTES = 16_384
_WEBSOCKET_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
_MAX_UNFRAGMENTED_HEADER = "x-codex-websocket-max-unfragmented-message-bytes"
_DEFINED_OPCODES = frozenset({0x0, 0x1, 0x2, 0x8, 0x9, 0xA})


class _Closed(Exception):
    """连接/协议不再可用；不得输出收到的原文。"""


class _Timeout(Exception):
    """本地绝对 deadline 到。"""


class WebSocket:
    def __init__(self, connection: ByteStream, clock: Callable[[], float],
                 platform: LocalPlatform | None = None) -> None:
        self._socket = connection
        self._clock = clock
        self._platform = platform or local_codex.platform()
        self._buffer = bytearray()
        self._max_unfragmented: int | None = None
        self._upgraded = False
        self.peer_pid: int | None = None
        self.close_deadline: float | None = None
        self.receive_budget: int | None = None
        self.strict_size = False
        self.on_write_start: Callable[[], None] | None = None
        # 当前这条消息已读走的字节数：读在消息中途中断时不为 0，流已失步（§95.5.4 读步骤超时后的复用判断）
        self._inflight = 0

    @property
    def desynced(self) -> bool:
        """上一次读在一条消息中途中断（超时或断开）：流已失步，这条连接不能再用。"""
        return self._inflight > 0

    def _now(self) -> float:
        return self._clock()

    def close(self) -> None:
        """结束连接：握手成功过就先 best-effort 发 Close（1000）再关 socket。

        正常结束时这是 RFC 6455 §7.1.2 的关闭握手；服务端先发过 Close 时，它就是 §5.5.1 要求的回应——
        `_read_message` 收到 Close 即按断开处理，调用随即结束、走到这里，所以只回一次。发不出去（对端已断、超时）
        一律忽略：归类早已定下，服务端读到 EOF 一样丢弃尚未开始的请求。
        """
        if self._upgraded:
            try:
                self._send_frame(0x8, b"\x03\xe8", min(self._now() + 0.2, self.close_deadline) if self.close_deadline is not None else self._now() + 0.2)
            except Exception:  # 收尾不改结果、不冒泡
                pass
        try:
            self._socket.close()
        except Exception:
            pass

    def _peer_is_me(self) -> bool:
        self.peer_pid = self._platform.peer_pid(self._socket)
        return self.peer_pid is not None

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
            if self.on_write_start is not None:
                self.on_write_start()
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
        if self.receive_budget is not None:
            self.receive_budget -= len(chunk)
            if self.receive_budget < 0:
                raise _Closed("receive budget")
        if not chunk:
            raise _Closed("connection closed")
        self._inflight += len(chunk)
        return chunk

    def _recv_exact(self, length: int, deadline: float) -> bytes:
        value = bytearray()
        if self._buffer:
            count = min(length, len(self._buffer))
            value.extend(self._buffer[:count])
            del self._buffer[:count]
            self._inflight += count
        while len(value) < length:
            value.extend(self._recv(length - len(value), deadline))
        return bytes(value)

    def _discard(self, length: int, deadline: float) -> None:
        """读掉 `length` 字节、不保存（超限消息按截止时间分块读完）。"""
        if self._buffer:
            count = min(length, len(self._buffer))
            del self._buffer[:count]
            self._inflight += count
            length -= count
        while length > 0:
            length -= len(self._recv(min(length, 65_536), deadline))

    def _read_message(self, deadline: float) -> tuple[int, bytes]:
        """读一条完整消息（拼好分片）；ping 回 pong，pong 忽略，close 视为断开，超限的消息读完丢弃。"""
        opcode: int | None = None
        parts = bytearray()
        oversize = False
        self._inflight = 0
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
                if opcode is None:
                    self._inflight = 0  # 控制帧读完、又不在一条数据消息中间：流仍在消息边界上
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
                if self.strict_size:
                    raise _Closed("message too large")
                oversize = True
                parts.clear()
                self._discard(length, deadline)
            else:
                parts.extend(self._recv_exact(length, deadline))
            if final:
                if oversize:
                    opcode, oversize = None, False
                    self._inflight = 0  # 超限消息已整条读完丢弃，回到消息边界
                    continue
                self._inflight = 0
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

