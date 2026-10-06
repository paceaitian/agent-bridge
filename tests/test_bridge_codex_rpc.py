"""协作桥 Codex RPC 通道（DESIGN §61）：UDS 上的 WebSocket JSON-RPC 一次性客户端与它在 Codex 投递里的接线。

假 daemon 在临时目录里：会合点符号链接 → 0700 目录里的 0600 socket，与托管 daemon 的真实布局相同；一次只接一个
连接，按用例脚本应答握手、initialize 与 add。连生产 daemon 由 `bridge_support` 的守卫拦下。
"""

from __future__ import annotations

import ast
import base64
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
import hashlib
import json
import os
from pathlib import Path
import socket
import struct
import subprocess
import sys
from tempfile import TemporaryDirectory
import threading
import time
from typing import Any
import unittest
from unittest.mock import patch

from agentstatus_bridge.doctor import rpc_evidence_text
from agentstatus_bridge.model import Delivery
from agentstatus_bridge.transports import DeliveryContext, codex_rpc
from agentstatus_bridge.transports.codex_queue import (
    CHANNEL_KEY,
    FALLBACK_KEY,
    OUTPUT_KEY,
    VERSION_KEY,
    CodexQueueTransport,
    RunResult,
    summarize_queue_evidence,
    summarize_rpc_evidence,
)
from agentstatus_bridge.transports.codex_rpc import (
    RpcFallback,
    RpcResult,
    classify_error,
    control_socket_path,
    parse_server_version,
    queue_add,
)
from bridge_support import ProductionSocketUse, endpoint, ref

THREAD = "019a0000-1111-7222-8333-444455556666"
ITEM = "019A9999-AAAA-7BBB-8CCC-DDDDEEEEFFFF"
MESSAGE = "0f3c2b1a-0000-4000-8000-00000000abcd"
USER_AGENT = "codex-tui/0.160.0 (Ubuntu 24.4.0; x86_64) xterm (codex-tui; 0.160.0)"
_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"


def ok_response(*, item: str = ITEM, echo: str = MESSAGE, text: str = "hello") -> dict[str, Any]:
    return {"result": {"queuedSubmission": {
        "id": item, "input": [{"type": "text", "text": text, "text_elements": []}], "clientUserMessageId": echo,
    }}}


def error_response(code: int, message: str, data: object = None) -> dict[str, Any]:
    error: dict[str, Any] = {"code": code, "message": message}
    if data is not None:
        error["data"] = data
    return {"error": error}


@dataclass
class Script:
    """假 daemon 每一步怎么应答。"""

    status: str = "HTTP/1.1 101 Switching Protocols"
    accept: str | None = None  # None = 正确的 Sec-WebSocket-Accept
    headers: dict[str, str] = field(default_factory=dict[str, str])
    initialize: str = "ok"  # ok / error / silent / close / no_result
    user_agent: object = USER_AGENT
    # add 之前先发的帧：("ping", b"..") / ("text", dict) / ("raw", 文本帧原始字节) / ("binary", b"..")
    # / ("opcode", (操作码, 载荷)) / ("big", (总字节数, 分片数))：超过 1 MiB 的无关通知
    before: list[tuple[str, Any]] = field(default_factory=list[tuple[str, Any]])
    # 与 101 响应同一次写出的帧：(总字节数, 分片数) 的超限无关通知，客户端会先在握手余量里读到它的开头
    pushed_with_upgrade: tuple[int, int] | None = None
    # dict / silent / close / huge / server_close（服务端先发 Close，再等客户端回 Close）
    add: dict[str, Any] | str = field(default_factory=ok_response)
    fragment: bool = False


class FakeDaemon:
    def __init__(self, root: Path, script: Script | None = None, *, listen: bool = True) -> None:
        self.script = script or Script()
        self.home = root / "codex"
        (self.home / "app-server-control").mkdir(parents=True)
        self.directory = root / "daemon"
        self.directory.mkdir()
        os.chmod(self.directory, 0o700)
        self.socket_path = self.directory / "s.sock"
        self.link = control_socket_path(self.home)
        self.link.symlink_to(self.socket_path)
        self.received: list[dict[str, Any]] = []
        self.pongs: list[bytes] = []
        self.request_line: str | None = None  # 没收到握手时保持 None，断言以 FAIL 报出
        self.rejected: str | None = None  # 握手请求缺了真实 daemon 要求的头时记下缺哪个
        self.closes: list[bytes] = []  # 客户端发来的 Close 帧载荷
        self.ended_at: float | None = None  # 等客户端断开时读到 EOF 的时刻（monotonic）
        self.connections = 0
        self.listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.listener.bind(str(self.socket_path))
        os.chmod(self.socket_path, 0o600)
        self.thread: threading.Thread | None = None
        if listen:
            self.listener.listen(1)
            self.thread = threading.Thread(target=self._serve, daemon=True)
            self.thread.start()

    def close(self) -> None:
        self.listener.close()
        if self.thread is not None:
            self.thread.join(timeout=5)

    def methods(self) -> list[str | None]:
        return [message.get("method") for message in self.received]

    # 服务端一侧的最小 WebSocket
    def _serve(self) -> None:
        try:
            connection, _ = self.listener.accept()
        except OSError:
            return
        self.connections += 1
        with connection:
            connection.settimeout(5)
            try:
                self._session(connection)
            except (OSError, ConnectionError, ValueError):
                pass

    def _session(self, connection: socket.socket) -> None:
        script = self.script
        request = bytearray()
        while b"\r\n\r\n" not in request:
            chunk = connection.recv(4096)
            if not chunk:
                return
            request.extend(chunk)
        head = bytes(request).split(b"\r\n\r\n", 1)[0].decode("ascii")
        self.request_line = head.split("\r\n")[0]
        headers = {name.strip().casefold(): value.strip() for name, _, value in
                   (line.partition(":") for line in head.split("\r\n")[1:])}
        # 与真实 daemon 的升级校验同口径：缺任何一项都是 400，不升级
        required: dict[str, Callable[[str], bool]] = {
            "host": bool,
            "upgrade": lambda value: value.casefold() == "websocket",
            "connection": lambda value: "upgrade" in {token.strip().casefold() for token in value.split(",")},
            "sec-websocket-version": lambda value: value == "13",
            "sec-websocket-key": bool,
        }
        for name, valid in required.items():
            if not valid(headers.get(name, "")):
                self.rejected = name
                connection.sendall(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n")
                return
        key = headers["sec-websocket-key"]
        accept = script.accept or base64.b64encode(hashlib.sha1(f"{key}{_GUID}".encode()).digest()).decode()
        lines = [script.status, "Upgrade: websocket", "Connection: Upgrade", f"Sec-WebSocket-Accept: {accept}"]
        lines += [f"{name}: {value}" for name, value in script.headers.items()]
        pushed = self._big_frames(*script.pushed_with_upgrade) if script.pushed_with_upgrade else b""
        connection.sendall(("\r\n".join(lines) + "\r\n\r\n").encode("ascii") + pushed)
        if " 101 " not in script.status:
            return
        initialize = self._read_json(connection)
        if initialize is None:
            return
        if script.initialize == "close":
            return
        if script.initialize == "silent":
            self._drain(connection)
            return
        if script.initialize == "error":
            self._send_json(connection, {"id": initialize["id"], **error_response(-32600, "bad init")})
        elif script.initialize == "no_result":
            self._send_json(connection, {"id": initialize["id"], "result": None})
        else:
            self._send_json(connection, {"id": initialize["id"], "result": {
                "userAgent": script.user_agent, "codexHome": "/synthetic", "platformFamily": "unix", "platformOs": "linux",
            }})
        if self._read_json(connection) is None:  # initialized
            return
        add = self._read_json(connection)
        if add is None:
            return
        for kind, value in script.before:
            if kind == "ping":
                self._send_frame(connection, 0x9, value)
                opcode, payload = self._read_frame(connection)
                if opcode == 0xA:
                    self.pongs.append(payload)
            elif kind == "text":
                self._send_json(connection, value)
            elif kind == "raw":
                self._send_frame(connection, 0x1, value)
            elif kind == "opcode":
                self._send_frame(connection, *value)
            elif kind == "big":
                connection.sendall(self._big_frames(*value))
            else:
                self._send_frame(connection, 0x2, value)
        if script.add == "close":
            return
        if script.add == "silent":
            self._drain(connection)
            return
        if script.add == "server_close":
            self._send_frame(connection, 0x8, b"\x03\xe9")  # 1001 going away
            self._drain(connection)
            return
        if script.add == "huge":
            connection.sendall(bytes([0x81, 127]) + (2 * 1024 * 1024).to_bytes(8, "big") + b"{")
            self._drain(connection)
            return
        assert isinstance(script.add, dict)
        payload = json.dumps({"jsonrpc": "2.0", "id": add["id"], **script.add}).encode()
        if script.fragment:
            third = len(payload) // 3
            self._send_frame(connection, 0x1, payload[:third], final=False)
            self._send_frame(connection, 0x9, b"mid")  # 控制帧可以夹在分片之间
            opcode, pong = self._read_frame(connection)
            if opcode == 0xA:
                self.pongs.append(pong)
            self._send_frame(connection, 0x0, payload[third:2 * third], final=False)
            self._send_frame(connection, 0x0, payload[2 * third:], final=True)
        else:
            self._send_frame(connection, 0x1, payload)
        self._drain(connection)

    def _drain(self, connection: socket.socket) -> None:
        # 等客户端自己断开，免得服务端先关造成竞态；其间记下客户端发来的 Close 帧
        try:
            while True:
                opcode, payload = self._read_frame(connection)
                if opcode == 0x8:
                    self.closes.append(payload)
        except (OSError, ConnectionError, ValueError):
            pass
        self.ended_at = time.monotonic()

    @staticmethod
    def _recv_exact(connection: socket.socket, length: int) -> bytes:
        data = bytearray()
        while len(data) < length:
            chunk = connection.recv(length - len(data))
            if not chunk:
                raise ConnectionError("closed")
            data.extend(chunk)
        return bytes(data)

    def _read_frame(self, connection: socket.socket) -> tuple[int, bytes]:
        first, second = self._recv_exact(connection, 2)
        if not second & 0x80:
            raise ValueError("client frames must be masked")
        length = second & 0x7F
        if length == 126:
            length = int.from_bytes(self._recv_exact(connection, 2), "big")
        elif length == 127:
            length = int.from_bytes(self._recv_exact(connection, 8), "big")
        mask = self._recv_exact(connection, 4)
        payload = bytes(value ^ mask[index % 4] for index, value in enumerate(self._recv_exact(connection, length)))
        return first & 0x0F, payload

    def _read_json(self, connection: socket.socket) -> dict[str, Any] | None:
        try:
            opcode, payload = self._read_frame(connection)
        except ConnectionError:
            return None
        if opcode != 0x1:
            return None
        message = json.loads(payload)
        self.received.append(message)
        return message

    @classmethod
    def _big_frames(cls, total: int, pieces: int) -> bytes:
        """一条约 `total` 字节的无关通知，分 `pieces` 片编码好的帧字节。"""
        body = b'{"method":"item/completed","params":{"x":"' + b"a" * (total - 48) + b'"}}'
        size = -(-len(body) // pieces)
        return b"".join(cls._frame(0x1 if index == 0 else 0x0, body[index * size:(index + 1) * size],
                                   final=index == pieces - 1) for index in range(pieces))

    @classmethod
    def _send_frame(cls, connection: socket.socket, opcode: int, payload: bytes, *, final: bool = True) -> None:
        connection.sendall(cls._frame(opcode, payload, final=final))

    @staticmethod
    def _frame(opcode: int, payload: bytes, *, final: bool = True) -> bytes:
        header = bytearray([(0x80 if final else 0) | opcode])
        if len(payload) < 126:
            header.append(len(payload))
        elif len(payload) <= 0xFFFF:
            header.append(126)
            header.extend(len(payload).to_bytes(2, "big"))
        else:
            header.append(127)
            header.extend(len(payload).to_bytes(8, "big"))
        return bytes(header) + payload

    def _send_json(self, connection: socket.socket, message: dict[str, Any]) -> None:
        self._send_frame(connection, 0x1, json.dumps(message).encode())


class RpcCase(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = TemporaryDirectory(dir="/var/tmp" if os.path.isdir("/var/tmp") else None)
        self.addCleanup(self._tmp.cleanup)
        self.root = Path(self._tmp.name)

    def daemon(self, script: Script | None = None, *, listen: bool = True) -> FakeDaemon:
        daemon = FakeDaemon(self.root, script, listen=listen)
        self.addCleanup(daemon.close)
        return daemon

    def add(self, daemon: FakeDaemon, text: str = "hello") -> RpcFallback | RpcResult:
        return queue_add(daemon.link, thread_id=THREAD, text=text, client_message_id=MESSAGE, client_version="0.160.0")


class SocketChecksTests(RpcCase):
    """回退点之一：socket 校验与连接，全部发生在 add 之前（DESIGN §61.2 第 2 条）。"""

    def test_missing_or_dangling_rendezvous_falls_back(self) -> None:
        missing = control_socket_path(self.root / "nowhere")
        self.assertEqual(queue_add(missing, thread_id=THREAD, text="x", client_message_id=MESSAGE,
                                   client_version="0.160.0"), RpcFallback("socket_missing"))
        daemon = self.daemon(listen=False)
        daemon.listener.close()
        daemon.socket_path.unlink()  # daemon 退出后物理 socket 被删、链接悬空
        self.assertEqual(self.add(daemon), RpcFallback("socket_missing"))

    def test_target_that_is_not_a_private_socket_is_rejected(self) -> None:
        cases: dict[str, Callable[[FakeDaemon], None]] = {
            "普通文件": lambda d: (d.socket_path.unlink(), d.socket_path.write_text("")),  # type: ignore[func-returns-value]
            "组可读写": lambda d: os.chmod(d.socket_path, 0o660),
            "目录 0755": lambda d: os.chmod(d.directory, 0o755),
        }
        for name, spoil in cases.items():
            with self.subTest(case=name):
                root = self.root / name
                root.mkdir()
                daemon = FakeDaemon(root, listen=False)
                self.addCleanup(daemon.close)
                spoil(daemon)
                self.assertEqual(self.add(daemon), RpcFallback("socket_rejected"))

    def test_peer_credentials_are_checked_after_connecting(self) -> None:
        daemon = self.daemon()
        real_unpack = struct.unpack

        def other_uid(fmt: str, data: bytes) -> tuple[Any, ...]:
            values = real_unpack(fmt, data)
            return (values[0], values[1] + 1, values[2]) if fmt == "3i" else values

        with patch.object(codex_rpc.struct, "unpack", side_effect=other_uid):
            self.assertEqual(self.add(daemon), RpcFallback("socket_rejected"))
        daemon.close()
        self.assertEqual(daemon.connections, 1)  # 是连上之后被拒的，不是路径校验
        self.assertEqual(daemon.received, [])

    def test_refused_connection_falls_back(self) -> None:
        daemon = self.daemon(listen=False)  # 绑定了但没在听
        self.assertEqual(self.add(daemon), RpcFallback("connect_failed"))


class HandshakeAndInitializeTests(RpcCase):
    def test_bad_upgrade_falls_back(self) -> None:
        for name, script in {"非 101": Script(status="HTTP/1.1 403 Forbidden"), "Accept 不符": Script(accept="AAAA")}.items():
            with self.subTest(case=name):
                (self.root / name).mkdir()
                daemon = FakeDaemon(self.root / name, script)
                self.addCleanup(daemon.close)
                self.assertEqual(self.add(daemon), RpcFallback("handshake_failed"))
                daemon.close()
                self.assertEqual(daemon.received, [])

    def test_initialize_failures_fall_back_before_any_add(self) -> None:
        for mode in ("error", "close", "no_result", "silent"):
            with self.subTest(initialize=mode):
                (self.root / mode).mkdir()
                daemon = FakeDaemon(self.root / mode, Script(initialize=mode))
                self.addCleanup(daemon.close)
                with patch.object(codex_rpc, "INITIALIZE_SECONDS", 0.3):
                    self.assertEqual(self.add(daemon), RpcFallback("initialize_failed"))
                daemon.close()
                self.assertEqual(daemon.methods(), ["initialize"])

    def test_identity_and_request_match_the_cli_exactly(self) -> None:
        daemon = self.daemon()
        result = self.add(daemon, "你好\n\x01")
        daemon.close()
        self.assertEqual(daemon.request_line, "GET /rpc HTTP/1.1")
        self.assertIsNone(daemon.rejected)  # 真实 daemon 要求的升级头都在
        self.assertEqual(daemon.methods(), ["initialize", "initialized", "thread/queue/add"])
        initialize, initialized, add = daemon.received
        self.assertEqual(initialize["method"], "initialize")
        self.assertEqual(initialize["params"], {
            "clientInfo": {"name": "codex-tui", "title": None, "version": "0.160.0"},
            "capabilities": {"experimentalApi": True},
        })
        self.assertEqual(initialized, {"method": "initialized"})
        self.assertEqual(add["method"], "thread/queue/add")
        self.assertEqual(add["params"], {
            "threadId": THREAD,
            "input": [{"type": "text", "text": "你好\n\x01", "text_elements": []}],  # 与上游 UserInput 的线上字段名相同
            "clientUserMessageId": MESSAGE,
        })
        self.assertIsInstance(result, RpcResult)

    def test_the_connection_ends_with_a_close_frame(self) -> None:
        # 一次性连接结束时按 RFC 6455 发 Close（1000）；服务端先发 Close 时回一帧、只回一次（§61 第 1 轮 Fable P3-2）
        daemon = self.daemon()
        self.assertIsInstance(self.add(daemon), RpcResult)
        daemon.close()
        self.assertEqual(daemon.closes, [b"\x03\xe8"])
        (self.root / "server").mkdir()
        daemon = FakeDaemon(self.root / "server", Script(add="server_close"))
        self.addCleanup(daemon.close)
        result = self.add(daemon)
        assert isinstance(result, RpcResult)
        self.assertEqual((result.delivery, result.reason), (Delivery.UNKNOWN, "codex_transport_error"))
        daemon.close()
        self.assertEqual(daemon.closes, [b"\x03\xe8"])

    def test_reserved_opcodes_fail_the_connection(self) -> None:
        # RFC 6455 §5.2：收到未定义的操作码必须断开，不能当成可忽略的帧（§61 第 1 轮 Codex N02）；add 之后只能 UNKNOWN
        for name, frame in {"保留控制帧 0xB": (0xB, b""), "保留数据帧 0x3": (0x3, b"x")}.items():
            with self.subTest(case=name):
                (self.root / name).mkdir()
                daemon = FakeDaemon(self.root / name, Script(before=[("opcode", frame)]))
                self.addCleanup(daemon.close)
                result = self.add(daemon)
                assert isinstance(result, RpcResult)
                self.assertEqual((result.delivery, result.reason), (Delivery.UNKNOWN, "codex_transport_error"))

    def test_rejected_upgrade_sends_no_close_frame(self) -> None:
        # 没升级成 WebSocket 就没有 WebSocket 关闭握手可做，直接断开
        daemon = self.daemon(Script(status="HTTP/1.1 403 Forbidden"))
        sent: list[bytes] = []
        real_send_frame = codex_rpc._Client._send_frame  # pyright: ignore[reportPrivateUsage]

        def record(client: Any, opcode: int, payload: bytes, deadline: float) -> None:
            sent.append(bytes([opcode]))
            real_send_frame(client, opcode, payload, deadline)

        with patch.object(codex_rpc._Client, "_send_frame", record):  # pyright: ignore[reportPrivateUsage]
            self.assertEqual(self.add(daemon), RpcFallback("handshake_failed"))
        self.assertEqual(sent, [])


class AddResultTests(RpcCase):
    def run_add(self, script: Script) -> RpcResult:
        daemon = self.daemon(script)
        result = self.add(daemon)
        self.assertIsInstance(result, RpcResult, result)
        assert isinstance(result, RpcResult)
        return result

    def test_success_needs_a_uuid_item_and_our_echo(self) -> None:
        result = self.run_add(Script())
        self.assertEqual((result.delivery, result.reason, result.provider_ref, result.output),
                         (Delivery.QUEUED, "codex_queued", ITEM.lower(), "recognized"))
        self.assertEqual(result.server_version, "0.160.0")
        cases = {
            "回显不符": (ok_response(echo="0f3c2b1a-0000-4000-8000-0000000000ff"), "recognized"),
            "id 不是 UUID": (ok_response(item="42"), "unrecognized"),
            "没有 queuedSubmission": ({"result": {}}, "unrecognized"),
            "result 不是对象": ({"result": []}, "unrecognized"),
        }
        for name, (response, output) in cases.items():
            with self.subTest(case=name):
                (self.root / name).mkdir()
                daemon = FakeDaemon(self.root / name, Script(add=response))
                self.addCleanup(daemon.close)
                result = self.add(daemon)
                assert isinstance(result, RpcResult)
                self.assertEqual((result.delivery, result.reason, result.provider_ref, result.output),
                                 (Delivery.UNKNOWN, "codex_queue_unparsed_output", None, output))

    def test_error_table(self) -> None:
        not_found = f"thread not found: {THREAD}"
        cases: list[tuple[int, str, object, Delivery, str]] = [
            (-32001, "Server overloaded; retry later.", None, Delivery.FAILED, "codex_server_overloaded"),
            (-32601, "Method not found", None, Delivery.FAILED, "codex_version_unsupported"),
            (-32600, "thread/queue/add requires experimentalApi capability", None, Delivery.FAILED, "codex_version_unsupported"),
            (-32600, "Invalid request: unknown variant `thread/queue/add`, expected one of", None, Delivery.FAILED,
             "codex_version_unsupported"),
            (-32600, "Not initialized", None, Delivery.FAILED, "codex_rpc_protocol_error"),
            (-32600, not_found, None, Delivery.FAILED, "codex_thread_not_found"),
            (-32600, f"session {THREAD} is archived. Run `codex unarchive {THREAD}` to restore it.", None,
             Delivery.FAILED, "codex_thread_archived"),
            (-32600, f"ephemeral thread does not support queued submissions: {THREAD}", None, Delivery.FAILED,
             "codex_thread_ephemeral"),
            (-32600, "direct app-server input is not allowed for unloaded spawned sub-agents", None, Delivery.FAILED,
             "codex_subagent_unloaded"),
            (-32600, "direct app-server input is not allowed for multi-agent v2 sub-agents", None, Delivery.FAILED,
             "codex_subagent_unsupported"),
            (-32600, "invalid thread id: x", None, Delivery.FAILED, "codex_thread_invalid"),
            (-32600, "user message queue is unavailable", None, Delivery.FAILED, "codex_queue_unavailable"),
            (-32600, "queue cannot contain more than 100 submissions", None, Delivery.FAILED, "provider_queue_full"),
            (-32600, "only user input can be added to the user-message queue", None, Delivery.FAILED,
             "codex_rpc_protocol_error"),
            (-32600, "Invalid request: missing field `threadId`", None, Delivery.FAILED, "codex_rpc_protocol_error"),
            (-32602, "Input exceeds the maximum length of 1048576 characters.", None, Delivery.FAILED,
             "provider_payload_too_large"),
            (-32602, "anything", {"input_error_code": "input_too_large"}, Delivery.FAILED, "provider_payload_too_large"),
            (-32603, f"failed to read thread: {THREAD}: io", None, Delivery.FAILED, "codex_thread_unreadable"),
            (-32603, "queued submission operation failed: queue storage failed: locked", None, Delivery.UNKNOWN,
             "codex_queue_storage_error"),
            (-32603, "queued submission operation failed: queued submission payload is invalid", None, Delivery.UNKNOWN,
             "codex_queue_storage_error"),
            (-32603, "queued submission does not contain user input", None, Delivery.UNKNOWN,
             "codex_queue_unrecognized_error"),
            # 写前的文案配上别的 code 不算命中：按 (code, message) 一起认
            (-32603, not_found, None, Delivery.UNKNOWN, "codex_queue_unrecognized_error"),
            (-32602, "something else", None, Delivery.UNKNOWN, "codex_queue_unrecognized_error"),
            (-32000, "something new", None, Delivery.UNKNOWN, "codex_queue_unrecognized_error"),
        ]
        for code, message, data, delivery, reason in cases:
            with self.subTest(code=code, message=message[:32]):
                expected_output = "unrecognized" if reason == "codex_queue_unrecognized_error" else "recognized"
                self.assertEqual(classify_error(error_response(code, message, data)["error"]),
                                 (delivery, reason, expected_output))
        for malformed in (None, "x", {"code": "1", "message": "m"}, {"code": True, "message": "Not initialized"},
                          {"code": -32600}):
            with self.subTest(malformed=malformed):
                self.assertEqual(classify_error(malformed),
                                 (Delivery.UNKNOWN, "codex_queue_unrecognized_error", "unrecognized"))
        # 经真实连接走一遍：错误响应如实落到结果里
        result = self.run_add(Script(add=error_response(-32600, not_found)))
        self.assertEqual((result.delivery, result.reason, result.output), (Delivery.FAILED, "codex_thread_not_found", "recognized"))

    def test_problems_after_the_add_are_unknown_and_never_retried(self) -> None:
        cases: dict[str, tuple[Script, str]] = {
            "超时": (Script(add="silent"), "codex_queue_timeout"),
            "断开": (Script(add="close"), "codex_transport_error"),
            "超限消息没发完": (Script(add="huge"), "codex_queue_timeout"),  # 读完丢弃要等到截止
            "JSON 坏": (Script(before=[("raw", b"{bad")]), "codex_transport_error"),
            "result 为空": (Script(before=[("binary", b"x")], add={"result": None}), "codex_queue_unparsed_output"),
        }
        for name, (script, reason) in cases.items():
            with self.subTest(case=name):
                (self.root / name).mkdir()
                daemon = FakeDaemon(self.root / name, script)
                self.addCleanup(daemon.close)
                with patch.object(codex_rpc, "ADD_SECONDS", 0.3):
                    result = self.add(daemon)
                assert isinstance(result, RpcResult)
                self.assertEqual((result.delivery, result.reason), (Delivery.UNKNOWN, reason))
                if reason != "codex_queue_unparsed_output":
                    self.assertIsNone(result.output)  # 传输问题不评输出
                daemon.close()
                self.assertEqual(daemon.methods(), ["initialize", "initialized", "thread/queue/add"])

    def test_add_timeout_disconnects_at_the_deadline(self) -> None:
        # add 之后超时要按时断开（让服务端丢弃尚未开始的请求），不能一直挂着（§61 第 1 轮 Opus P3-6，原 61.3 的 M17）
        daemon = self.daemon(Script(add="silent"))
        started = time.monotonic()
        with patch.object(codex_rpc, "ADD_SECONDS", 0.3):
            result = self.add(daemon)
        daemon.close()
        assert isinstance(result, RpcResult)
        self.assertEqual(result.reason, "codex_queue_timeout")
        self.assertIsNotNone(daemon.ended_at)
        assert daemon.ended_at is not None
        self.assertLess(daemon.ended_at - started, 0.3 + 1.5)

    def test_oversized_unrelated_messages_are_skipped(self) -> None:
        # 初始化之后服务端会把新建 thread 的事件推给这条连接；超限的无关消息读完丢弃，不把成功拖成 UNKNOWN
        cases = {"单帧 1.5 MiB": (3 * 512 * 1024, 1), "四片共 1.6 MiB，第三片才超限": (1600 * 1024, 4)}
        for name, big in cases.items():
            with self.subTest(case=name):
                (self.root / name).mkdir()
                daemon = FakeDaemon(self.root / name, Script(before=[("big", big)]))
                self.addCleanup(daemon.close)
                result = self.add(daemon)
                assert isinstance(result, RpcResult)
                self.assertEqual((result.delivery, result.reason), (Delivery.QUEUED, "codex_queued"))

    def test_oversized_message_already_in_the_handshake_buffer_is_skipped(self) -> None:
        # 超限消息的开头与 101 响应同一次到达、落在握手余量里：丢弃要先吃掉缓冲区里的那部分，否则帧失步
        # （§61 第 2 轮 Opus P3-1，探针 D 的原形）
        daemon = self.daemon(Script(pushed_with_upgrade=(3 * 512 * 1024, 1)))
        with patch.object(codex_rpc, "INITIALIZE_SECONDS", 2.0):
            result = self.add(daemon)
        assert isinstance(result, RpcResult), result
        self.assertEqual((result.delivery, result.reason), (Delivery.QUEUED, "codex_queued"))

    def test_frames_the_server_interleaves_are_handled(self) -> None:
        script = Script(before=[
            ("ping", b"p1"),
            ("text", {"method": "thread/started", "params": {}}),  # 通知
            ("text", {"id": 99, "method": "item/tool/requestUserInput", "params": {}}),  # 服务端请求：不回应
            ("text", {"id": 7, "result": {}}),  # 别的 id 的响应
            ("binary", b"\x00\x01"),
        ], fragment=True)
        daemon = self.daemon(script)
        result = self.add(daemon)
        daemon.close()
        assert isinstance(result, RpcResult)
        self.assertEqual((result.delivery, result.provider_ref), (Delivery.QUEUED, ITEM.lower()))
        self.assertEqual(daemon.pongs, [b"p1", b"mid"])
        self.assertEqual(daemon.methods(), ["initialize", "initialized", "thread/queue/add"])

    def test_advertised_frame_cap_is_honoured_before_sending(self) -> None:
        daemon = self.daemon(Script(headers={"x-codex-websocket-max-unfragmented-message-bytes": "100"}))
        result = self.add(daemon, "x" * 200)
        daemon.close()
        assert isinstance(result, RpcResult)
        self.assertEqual((result.delivery, result.reason), (Delivery.FAILED, "provider_payload_too_large"))
        self.assertEqual(daemon.methods(), ["initialize", "initialized"])  # add 从没发出

    def test_server_version_comes_from_the_user_agent(self) -> None:
        cases: dict[object, str] = {
            USER_AGENT: "0.160.0",
            "codex_app_server_daemon/1.2.3 (Linux 6.8.0; x86_64) codex_cli_rs/1.2.3": "1.2.3",
            "codex-tui/0.161.0-alpha.2 (x)": "0.161.0-alpha.2",
            "codex-tui": "unknown",
            "codex-tui/": "unknown",
            "codex-tui/not-a-version (x)": "unknown",
            "codex-tui/1.2.3" + "4" * 70: "unknown",
            None: "unknown",
            42: "unknown",
        }
        for user_agent, version in cases.items():
            with self.subTest(user_agent=str(user_agent)[:32]):
                self.assertEqual(parse_server_version(user_agent), version)
        result = self.run_add(Script(user_agent="weird"))
        self.assertEqual((result.delivery, result.server_version), (Delivery.QUEUED, "unknown"))

    def guarded_add(self, daemon: FakeDaemon) -> RpcFallback | RpcResult:
        # 冒泡本身就是缺陷：以 FAIL 报出，而不是让异常把用例变成 ERROR
        try:
            return self.add(daemon)
        except Exception as error:  # noqa: BLE001
            self.fail(f"queue_add 让意外异常冒泡：{error!r}")

    def test_unexpected_exceptions_follow_the_add_boundary(self) -> None:
        daemon = self.daemon()
        with patch.object(codex_rpc._Client, "_handshake", side_effect=RuntimeError("SYNTHETIC")):  # pyright: ignore[reportPrivateUsage]
            self.assertEqual(self.guarded_add(daemon), RpcFallback("handshake_failed"))
        # initialize 成功之后、add 帧开始发送之前（组装请求）：仍是写前，原因码单独一个（§61 第 1 轮 Fable P3-4）
        (self.root / "request").mkdir()
        daemon = FakeDaemon(self.root / "request")
        self.addCleanup(daemon.close)
        real_encode = codex_rpc._Client._encode  # pyright: ignore[reportPrivateUsage]

        def fail_on_add(client: Any, message: dict[str, object]) -> bytes:
            if message.get("method") == "thread/queue/add":
                raise RuntimeError("SYNTHETIC")
            return real_encode(client, message)

        with patch.object(codex_rpc._Client, "_encode", fail_on_add):  # pyright: ignore[reportPrivateUsage]
            self.assertEqual(self.guarded_add(daemon), RpcFallback("request_failed"))
        daemon.close()
        self.assertEqual(daemon.methods(), ["initialize", "initialized"])
        (self.root / "after").mkdir()
        daemon = FakeDaemon(self.root / "after")
        self.addCleanup(daemon.close)
        with patch.object(codex_rpc, "interpret_success", side_effect=RuntimeError("SYNTHETIC")):
            result = self.guarded_add(daemon)
        assert isinstance(result, RpcResult)
        self.assertEqual((result.delivery, result.reason, result.server_version),
                         (Delivery.UNKNOWN, "codex_transport_error", "0.160.0"))

    def test_unexpected_failure_creating_the_socket_falls_back(self) -> None:
        # 还没外调：任何 Exception 都按写前归类，不冒泡给 dispatch 变成 UNKNOWN（§61 第 1 轮 Codex N04）
        daemon = self.daemon(listen=False)
        with patch.object(codex_rpc.socket, "socket", side_effect=RuntimeError("audit hook")):
            self.assertEqual(self.guarded_add(daemon), RpcFallback("connect_failed"))


class TransportChannelTests(RpcCase):
    """`CodexQueueTransport` 的两个通道：RPC 优先，add 之前失败回退 CLI，之后绝不重投（DESIGN §61.2 第 1 条）。"""

    def setUp(self) -> None:
        super().setUp()
        self.calls: list[list[str]] = []
        self.queue_result = RunResult(0, f"Queued message {ITEM} for thread {THREAD}.\n", "")

    def runner(self, argv: Sequence[str], _timeout: float) -> RunResult:
        self.calls.append(list(argv))
        if argv[1] == "--version":
            return RunResult(0, "codex-cli 0.160.0\n", "")
        return self.queue_result

    def deliver(self, daemon: FakeDaemon, text: str = "hello") -> Any:
        binary = self.root / "codex-bin"
        if not binary.exists():
            binary.write_text("#!/bin/sh\n")
        transport = CodexQueueTransport(executable=str(binary), runner=self.runner)
        with patch.dict(os.environ, {"CODEX_HOME": str(daemon.home)}):
            return transport.deliver(endpoint(ref(native=THREAD)), text,
                                     DeliveryContext(message_uuid=MESSAGE, sender_name="user"))

    def queue_calls(self) -> list[list[str]]:
        return [argv for argv in self.calls if argv[1] == "queue"]

    def test_rpc_success_never_runs_the_cli_queue(self) -> None:
        daemon = self.daemon()
        outcome = self.deliver(daemon)
        self.assertEqual((outcome.delivery, outcome.reason, outcome.provider_ref),
                         (Delivery.QUEUED, "codex_queued", ITEM.lower()))
        self.assertEqual(outcome.detail, {CHANNEL_KEY: "rpc", VERSION_KEY: "0.160.0", OUTPUT_KEY: "recognized"})
        self.assertEqual(self.queue_calls(), [])

    def test_failures_before_the_add_fall_back_to_the_cli_once(self) -> None:
        cases: dict[str, Script | None] = {
            "handshake_failed": Script(status="HTTP/1.1 500 Internal"),
            "initialize_failed": Script(initialize="error"),
            "socket_missing": None,
        }
        for reason, script in cases.items():
            with self.subTest(fallback=reason):
                self.calls.clear()
                (self.root / reason).mkdir()
                daemon = FakeDaemon(self.root / reason, script or Script(), listen=script is not None)
                self.addCleanup(daemon.close)
                if script is None:
                    daemon.link.unlink()
                outcome = self.deliver(daemon)
                self.assertEqual(outcome.delivery, Delivery.QUEUED)
                self.assertEqual(len(self.queue_calls()), 1)
                self.assertEqual((outcome.detail[CHANNEL_KEY], outcome.detail[FALLBACK_KEY]), ("cli", reason))
                self.assertEqual(outcome.detail[VERSION_KEY], "0.160.0")

    def test_failures_after_the_add_are_never_retried_over_the_cli(self) -> None:
        for name, script in {"断开": Script(add="close"), "已知拒收": Script(add=error_response(-32600, "invalid thread id: x"))}.items():
            with self.subTest(case=name):
                self.calls.clear()
                (self.root / name).mkdir()
                daemon = FakeDaemon(self.root / name, script)
                self.addCleanup(daemon.close)
                outcome = self.deliver(daemon)
                self.assertEqual(self.queue_calls(), [])
                self.assertEqual(outcome.detail[CHANNEL_KEY], "rpc")
                self.assertNotIn(FALLBACK_KEY, outcome.detail)

    def test_without_a_cli_version_the_socket_is_never_touched(self) -> None:
        daemon = self.daemon()

        def no_version(argv: Sequence[str], timeout: float) -> RunResult:
            if argv[1] == "--version":
                self.calls.append(list(argv))
                return RunResult(1, "", "boom")
            return self.runner(argv, timeout)

        binary = self.root / "codex-bin"
        binary.write_text("#!/bin/sh\n")
        transport = CodexQueueTransport(executable=str(binary), runner=no_version)
        with patch.dict(os.environ, {"CODEX_HOME": str(daemon.home)}):
            outcome = transport.deliver(endpoint(ref(native=THREAD)), "hello",
                                        DeliveryContext(message_uuid=MESSAGE, sender_name="user"))
        daemon.close()
        self.assertEqual(daemon.connections, 0)
        self.assertEqual(outcome.detail[FALLBACK_KEY], "version_unavailable")
        self.assertEqual(len(self.queue_calls()), 1)

    def test_message_text_never_reaches_the_outcome(self) -> None:
        marker = "SYNTHETIC_PRIVATE_MARKER"
        for name, script in {
            "成功": Script(add=ok_response(text=marker)),
            "错误": Script(add=error_response(-32603, f"queued submission operation failed: {marker}")),
        }.items():
            with self.subTest(case=name):
                (self.root / name).mkdir()
                daemon = FakeDaemon(self.root / name, script)
                self.addCleanup(daemon.close)
                outcome = self.deliver(daemon, marker)
                self.assertNotIn(marker, json.dumps(outcome.detail) + repr(outcome))


class RpcEvidenceTests(unittest.TestCase):
    """doctor 按通道分开统计（DESIGN §61.2 第 7 条）：RPC 样本对服务端版本，CLI 样本对 CLI 版本，旧样本算 CLI。"""

    def test_channels_are_counted_separately(self) -> None:
        rpc = {CHANNEL_KEY: "rpc", OUTPUT_KEY: "recognized"}
        cli = {CHANNEL_KEY: "cli", OUTPUT_KEY: "recognized", VERSION_KEY: "0.160.0"}
        details: list[dict[str, object]] = [
            {**rpc, VERSION_KEY: "unknown"},  # 最新一条，但没解析出版本：参照跳过它（§61 第 1 轮 Codex N03）
            {**rpc, VERSION_KEY: "0.161.0"},  # 最近一条能解析版本的：参照版本
            {**rpc, VERSION_KEY: "0.161.0", OUTPUT_KEY: "unrecognized"},
            {**rpc, VERSION_KEY: "0.160.0"},  # 升级前
            {CHANNEL_KEY: "rpc", VERSION_KEY: "0.161.0"},  # 传输问题：不评输出，不算样本
            {**cli, FALLBACK_KEY: "socket_missing"},
            {**cli, FALLBACK_KEY: "socket_missing"},
            {**cli, FALLBACK_KEY: "initialize_failed"},
            {OUTPUT_KEY: "unrecognized", VERSION_KEY: "0.160.0"},  # 旧样本没有通道：算 CLI
        ]
        rpc_summary = summarize_rpc_evidence(details)
        self.assertEqual(
            {key: rpc_summary.get(key) for key in ("state", "version", "recognized", "unrecognized", "otherVersion",
                                                   "unknownVersion", "fallbacks", "topFallback")},
            {"state": "ok", "version": "0.161.0", "recognized": 1, "unrecognized": 1, "otherVersion": 1,
             "unknownVersion": 1, "fallbacks": 3, "topFallback": "socket_missing"},
        )
        cli_summary = summarize_queue_evidence(details, "0.160.0")
        self.assertEqual((cli_summary["recognized"], cli_summary["unrecognized"], cli_summary["otherVersion"]), (3, 1, 0))
        text = rpc_evidence_text(rpc_summary)
        self.assertIn("服务端 0.161.0", text)
        self.assertIn("回退 CLI 3 次（最常见：socket_missing）", text)

    def test_no_samples_and_unreadable_ledger(self) -> None:
        self.assertEqual(summarize_rpc_evidence(None)["state"], "ledger_unreadable")
        self.assertEqual(rpc_evidence_text(summarize_rpc_evidence(None)), "Codex RPC 证据：账本读取失败，无法统计")
        empty = summarize_rpc_evidence([{OUTPUT_KEY: "recognized", VERSION_KEY: "0.160.0"}])
        self.assertEqual((empty["state"], empty["version"], empty["fallbacks"]), ("no_samples", None, 0))
        self.assertNotIn("topFallback", empty)
        self.assertIn("没有可分类的 RPC 响应样本（传输失败的尝试不计入此项）", rpc_evidence_text(empty))
        # add 之后断线、超时的尝试：经过 RPC、没有可分类的响应，不算样本（§61 第 2 轮 Codex C01）
        transport_only = summarize_rpc_evidence([{CHANNEL_KEY: "rpc", VERSION_KEY: "0.160.0"}])
        self.assertEqual(transport_only["state"], "no_samples")
        self.assertIn("没有可分类的 RPC 响应样本（传输失败的尝试不计入此项）", rpc_evidence_text(transport_only))
        # 有样本、只是都没解析出服务端版本：不能说「没有样本」（§61 第 1 轮 Codex N03）
        unversioned = summarize_rpc_evidence([{CHANNEL_KEY: "rpc", OUTPUT_KEY: "recognized", VERSION_KEY: "unknown"}] * 2)
        self.assertEqual((unversioned["state"], unversioned["version"], unversioned["unknownVersion"]),
                         ("no_samples", None, 2))
        self.assertEqual(rpc_evidence_text(unversioned),
                         "Codex RPC 证据（最近最多 200 条 Codex 尝试）：经 daemon 得到的 2 条可分类响应样本都未能解析服务端版本，无法按版本关联")


class SocketCreationInventoryTests(unittest.TestCase):
    """桥里**所有**创建套接字的地方都列在这张清单上（DESIGN §61.2 第 9 条，仿子进程清单 §45.36.1）。

    新增连接点时**故意**要来改这张表：那是该确认「测试会不会连到生产 socket」的时刻。代码结构回归门禁，
    不是对间接调用的全程序证明；按点号全名匹配。
    """

    CALLS = frozenset({"socket.socket", "socket.create_connection", "socket.socketpair", "socket.fromfd"})
    EXPECTED = [
        ("transports/claude_peer.py", ("deliver",), "socket.socket"),   # Claude 对端投递
        ("transports/claude_peer.py", ("open",), "socket.socket"),      # Claude 回执收件箱
        ("transports/codex_rpc.py", ("queue_add",), "socket.socket"),   # Codex daemon（DESIGN §61）
    ]

    def test_every_socket_creation_site_is_accounted_for(self) -> None:
        package = Path(__file__).resolve().parents[1] / "src" / "agentstatus_bridge"
        sites: list[tuple[str, tuple[str, ...], str]] = []
        for path in sorted(package.rglob("*.py")):
            tree = ast.parse(path.read_text(encoding="utf-8"))
            for call in (node for node in ast.walk(tree) if isinstance(node, ast.Call)):
                func = call.func
                name = (f"{func.value.id}.{func.attr}"
                        if isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name) else "")
                if name not in self.CALLS:
                    continue
                owners = tuple(sorted(
                    node.name for node in ast.walk(tree)
                    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and call in ast.walk(node)
                ))
                sites.append((path.relative_to(package).as_posix(), owners, name))
        self.assertEqual(sorted(sites), sorted(self.EXPECTED),
                         "桥里新增了创建套接字的地方：先确认测试连不到生产 socket，再更新这张清单")


class ProductionSocketGuardTests(unittest.TestCase):
    """守卫自己的回归（DESIGN §61.2 第 9 条）：探测的是生产目录下**不存在**的路径，守卫失效时也只会得到 ENOENT。"""

    def test_connecting_under_the_production_codex_home_fails_the_test(self) -> None:
        import pwd
        probe = Path(pwd.getpwuid(os.getuid()).pw_dir) / ".codex" / "agentstatus-guard-probe-does-not-exist.sock"
        self.assertFalse(probe.exists())
        connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.addCleanup(connection.close)
        with self.assertRaises(ProductionSocketUse):
            connection.connect(str(probe))
        with self.assertRaises(ProductionSocketUse):
            connection.connect_ex(f"/tmp/codex-daemon-{os.getuid()}/agentstatus-guard-probe")
        # 会合点本身就是符号链接：守卫要按解析后的路径判，临时目录里指向生产目录的链接同样被拦
        with TemporaryDirectory(dir="/var/tmp" if os.path.isdir("/var/tmp") else None) as tmp:
            link = Path(tmp) / "rendezvous.sock"
            link.symlink_to(f"/tmp/codex-daemon-{os.getuid()}/agentstatus-guard-probe-does-not-exist")
            try:
                connection.connect(str(link))
            except ProductionSocketUse:
                pass
            except OSError as error:  # 守卫没拦下：目标不存在，只会得到 ENOENT
                self.fail(f"守卫没拦下经符号链接的连接：{error!r}")
            else:
                self.fail("守卫没拦下经符号链接的连接")

    def test_the_transport_does_not_swallow_the_guard(self) -> None:
        # queue_add 为了不冒泡接住所有 Exception：守卫若是 Exception 子类，会被当成「连接失败」静默回退 CLI、
        # 用例照样通过（§61 第 1 轮 Fable P2-1）。经完整投递路径确认它冒出来，且 CLI 一次都没跑
        target = Path(f"/tmp/codex-daemon-{os.getuid()}/agentstatus-guard-probe-does-not-exist")
        calls: list[list[str]] = []

        def runner(argv: Sequence[str], _timeout: float) -> RunResult:
            calls.append(list(argv))
            return RunResult(0, "codex-cli 0.160.0\n", "")

        with TemporaryDirectory(dir="/var/tmp" if os.path.isdir("/var/tmp") else None) as tmp:
            binary = Path(tmp) / "codex-bin"
            binary.write_text("#!/bin/sh\n")
            transport = CodexQueueTransport(executable=str(binary), runner=runner)
            with (patch.object(codex_rpc, "resolve_socket", return_value=target),
                  patch.dict(os.environ, {"CODEX_HOME": tmp}),
                  self.assertRaises(ProductionSocketUse)):
                transport.deliver(endpoint(ref(native=THREAD)), "hello",
                                  DeliveryContext(message_uuid=MESSAGE, sender_name="user"))
        self.assertEqual([argv for argv in calls if argv[1] == "queue"], [])

    def test_subprocess_runs_of_this_module_are_isolated_too(self) -> None:
        # 守卫在 import bridge_support 时安装：单独跑本模块也生效
        completed = subprocess.run(
            [sys.executable, "-c", "import bridge_support, socket; print(getattr(socket.socket, '_agentstatus_guarded', False))"],
            cwd=Path(__file__).parent, env={**os.environ, "PYTHONPATH": os.pathsep.join(
                [str(Path(__file__).resolve().parents[1] / "src"), str(Path(__file__).parent)])},
            capture_output=True, text=True, timeout=30, check=False,
        )
        self.assertEqual(completed.stdout.strip(), "True", completed.stderr[-500:])


if __name__ == "__main__":
    unittest.main()
