"""补充消息的 Codex `turn/steer` 通道（DESIGN §95.5.4）：分类表、Linux 与 Windows 两份客户端的通道选择与写入闩锁。

假服务端只用于用例：Linux 是临时目录里的 UDS 假 daemon（与 §61 用例同一套握手），Windows 是假 Win32 内核；
不连真实 daemon（`bridge_support` 守卫）。按 0.163/0.169 源码造的假服务端不算真实证据（§95.5.4）。

本模块在 `bridge-windows` CI 选择集里：分类表与 Windows 假内核用例两种系统都跑；Linux UDS 假 daemon 类在 Windows 上
按选择器放行的 `POSIX-only:` 前缀跳过。
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
from pathlib import Path
import socket
from tempfile import TemporaryDirectory
import time
from types import SimpleNamespace
import unittest
from collections.abc import Callable, Sequence
from typing import Any
from unittest.mock import patch

import bridge_support  # noqa: F401  导入即隔离宿主会话环境

from agentstatus_bridge.model import Delivery
from agentstatus_bridge.transports import DeliveryContext, codex_rpc
from agentstatus_bridge.transports.codex_rpc import (
    STEER_PATH_NO_ACTIVE_TURN,
    STEER_PATH_REJECTED,
    STEER_PATH_STEERED,
    STEER_PATH_THREAD_NOT_ACTIVE,
    STEER_PATH_THREAD_UNREADABLE,
    STEER_PATH_TURNS_UNREADABLE,
    STEER_PATH_UNKNOWN,
    RpcFallback,
    RpcResult,
    classify_steer_error,
    in_progress_turn,
    interpret_steer_success,
    steer_error_reason,
    thread_active,
)
from agentstatus_bridge.transports.websocket import _Timeout

LINUX_FIXTURE_REASON = "POSIX-only: UDS 假 daemon 与 Linux 本机通道（Windows 缺省平台是真实 Win32）"
linux_fixture = unittest.skipUnless(os.name == "posix", LINUX_FIXTURE_REASON)

THREAD = "019a0000-1111-7222-8333-444455556666"
MESSAGE = "0f3c2b1a-0000-4000-8000-00000000abcd"
TURN = "019b0000-2222-7333-8444-555566667777"
ITEM = "019A9999-AAAA-7BBB-8CCC-DDDDEEEEFFFF"
USER_AGENT = "codex-tui/0.169.0 (Ubuntu 24.4.0; x86_64) xterm (codex-tui; 0.169.0)"
_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

# 0.169 源码里确定未送入的拒绝（turn_processor.rs:1129-1251、load_thread、thread_input.rs、transport/mod.rs、
# message_processor.rs、error_code.rs），每条一个真实形状的样本 → 期望原因码
KNOWN_REJECTIONS: tuple[tuple[int, str, str], ...] = (
    (-32601, "method not found", "codex_steer_unsupported"),
    (-32600, "Invalid request: unknown variant `turn/steer`, expected one of `initialize`", "codex_steer_request_rejected"),
    (-32600, "Invalid request: missing field `expectedTurnId`", "codex_steer_request_rejected"),
    (-32001, "Server overloaded; retry later.", "codex_server_overloaded"),
    (-32600, f"invalid thread id: invalid character in {THREAD}", "codex_thread_invalid"),
    (-32600, f"thread not found: {THREAD}", "codex_thread_not_found"),
    (-32600, "direct app-server input is not allowed for multi-agent v2 sub-agents", "codex_subagent_unsupported"),
    (-32600, "expectedTurnId must not be empty", "codex_rpc_protocol_error"),
    (-32602, "Input exceeds the maximum length of 1048576 characters.", "provider_payload_too_large"),
    (-32600, "no active turn to steer", "codex_steer_no_active_turn"),
    (-32600, f"expected active turn id `{TURN}` but found `019c0000-0000-7000-8000-000000000000`",
     "codex_steer_turn_changed"),
    (-32600, "cannot steer a review turn", "codex_steer_review_turn"),
    (-32600, "cannot steer a compact turn", "codex_steer_compact_turn"),
    (-32600, "input must not be empty", "codex_rpc_protocol_error"),
    (-32600, "active turn uses a different output schema", "codex_steer_schema_mismatch"),
    (-32600, "Server is draining; retry after reconnecting", "codex_server_draining"),
)
# 不明：服务端明说 steer 失败、core 原样透出的 InvalidRequest、配置错误，以及已知文案的变体（只认全等/前缀）
UNKNOWN_ERRORS: tuple[tuple[int, str, str], ...] = (
    (-32603, "failed to steer turn: channel closed", "codex_steer_failed"),
    (-32600, "environment network policy rejected", "codex_steer_unrecognized_error"),
    (-32600, "failed to load configuration: bad toml", "codex_steer_unrecognized_error"),
    (-32600, "no active turn to steer (draining)", "codex_steer_unrecognized_error"),
    (-32600, f"core: thread not found: {THREAD}", "codex_steer_unrecognized_error"),
    (-32600, "expected active turn id `a` but found `b` and more", "codex_steer_unrecognized_error"),
    (-32603, "no active turn to steer", "codex_steer_unrecognized_error"),
    (-32000, "Server overloaded; retry later.", "codex_steer_unrecognized_error"),
)


def active_thread(kind: str = "active") -> dict[str, Any]:
    status: dict[str, Any] = {"type": kind}
    if kind == "active":
        status["activeFlags"] = []
    return {"result": {"thread": {"id": THREAD, "source": "cli", "status": status}}}


def turns(status: str = "inProgress", turn_id: str = TURN) -> dict[str, Any]:
    return {"result": {"data": [{"id": turn_id, "items": [], "itemsView": "notLoaded", "status": status,
                                 "error": None}], "nextCursor": None, "backwardsCursor": None}}


def steered(turn_id: str = TURN) -> dict[str, Any]:
    return {"result": {"turnId": turn_id}}


def rpc_error(code: int, message: str) -> dict[str, Any]:
    return {"error": {"code": code, "message": message}}


class SteerClassificationTests(unittest.TestCase):
    """分类表与只读结果解析（纯函数，两种系统都跑）。"""

    def test_every_known_rejection_is_definitely_not_submitted(self) -> None:
        for code, message, reason in KNOWN_REJECTIONS:
            with self.subTest(message=message):
                self.assertEqual(classify_steer_error({"code": code, "message": message}), reason)

    def test_unknown_errors_and_variants_are_not_classified(self) -> None:
        for code, message, reason in UNKNOWN_ERRORS:
            with self.subTest(message=message):
                error = {"code": code, "message": message}
                self.assertIsNone(classify_steer_error(error))
                self.assertEqual(steer_error_reason(error), reason)
        for bad in (None, "x", {"code": "-32600", "message": "no active turn to steer"}, {"code": True, "message": ""},
                    {"code": -32601}):
            with self.subTest(bad=bad):
                self.assertIsNone(classify_steer_error(bad))

    def test_thread_status_projection(self) -> None:
        self.assertIs(thread_active(active_thread()["result"]), True)
        for kind in ("idle", "notLoaded", "systemError"):
            self.assertIs(thread_active(active_thread(kind)["result"]), False)
        for bad in (None, {}, {"thread": {}}, {"thread": {"status": "active"}}, {"thread": {"status": {"type": "x"}}}):
            with self.subTest(bad=bad):
                self.assertIsNone(thread_active(bad))

    def test_turns_projection_reads_only_id_and_status(self) -> None:
        self.assertEqual(in_progress_turn(turns()["result"]), (True, TURN))
        for status in ("completed", "interrupted", "failed"):
            self.assertEqual(in_progress_turn(turns(status)["result"]), (True, None))
        self.assertEqual(in_progress_turn({"data": []}), (True, None))
        for bad in (None, {}, {"data": {}}, {"data": [1]}, {"data": [{"id": TURN}]},
                    turns(turn_id="")["result"], turns(turn_id="a b")["result"], turns(turn_id="x" * 129)["result"]):
            with self.subTest(bad=bad):
                self.assertEqual(in_progress_turn(bad), (False, None))

    def test_steer_success_shape(self) -> None:
        self.assertTrue(interpret_steer_success(steered()["result"]))
        for bad in (None, {}, {"turnId": ""}, {"turnId": 5}, {"turn": TURN}):
            self.assertFalse(interpret_steer_success(bad))


def _make_daemon(root: Path, replies: dict[str, Any]) -> Any:
    """按 0.169 线上形状应答的假 daemon：thread/read、thread/turns/list、turn/steer、thread/queue/add 依次脚本化。

    应答取值：dict（JSON-RPC 结果或错误体）、"silent"（不回，继续读下一条）、("late", dict)（不回，等下一条请求到来
    时先补发这条迟到应答）、"partial"（只发半条消息就停）、"close"（断开）；可调用对象按收到的请求生成。
    """
    import test_bridge_codex_rpc as rpc_tests

    class SteerDaemon(rpc_tests.FakeDaemon):
        def _session(self, connection: socket.socket) -> None:
            request = bytearray()
            while b"\r\n\r\n" not in request:
                chunk = connection.recv(4096)
                if not chunk:
                    return
                request.extend(chunk)
            head = bytes(request).split(b"\r\n\r\n", 1)[0].decode("ascii")
            headers = {name.strip().casefold(): value.strip() for name, _, value in
                       (line.partition(":") for line in head.split("\r\n")[1:])}
            key = headers["sec-websocket-key"]
            accept = base64.b64encode(hashlib.sha1(f"{key}{_GUID}".encode()).digest()).decode()
            connection.sendall(("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
                                f"Sec-WebSocket-Accept: {accept}\r\n\r\n").encode("ascii"))
            initialize = self._read_json(connection)
            if initialize is None:
                return
            self._send_json(connection, {"id": initialize["id"], "result": {
                "userAgent": USER_AGENT, "codexHome": "/synthetic", "platformFamily": "unix", "platformOs": "linux"}})
            if self._read_json(connection) is None:
                return
            late: list[dict[str, Any]] = []
            while True:
                message = self._read_json(connection)
                if message is None:
                    return
                for item in late:
                    self._send_json(connection, item)
                late.clear()
                spec = replies.get(str(message.get("method")))
                if spec is None and message.get("method") == "thread/queue/add":
                    params = message["params"]
                    spec = {"result": {"queuedSubmission": {"id": ITEM, "input": params["input"],
                                                            "clientUserMessageId": params["clientUserMessageId"]}}}
                if callable(spec):
                    spec = spec(message)
                if spec == "close":
                    return
                if spec == "silent" or spec is None:
                    continue
                if isinstance(spec, tuple) and spec[0] == "late":
                    late.append({"jsonrpc": "2.0", "id": message["id"], **spec[1]})
                    continue
                body = json.dumps({"jsonrpc": "2.0", "id": message["id"], **spec}).encode()
                if spec.get("partial") is True:
                    connection.sendall(self._frame(0x1, body)[:5])  # 半条消息就停：客户端读到一半超时
                    self._drain(connection)
                    return
                self._send_frame(connection, 0x1, body)

    return SteerDaemon(root)


@linux_fixture
class LinuxSteerTests(unittest.TestCase):
    """Linux `codex_rpc` 与 `CodexQueueTransport` 的 steer 通道。"""

    def setUp(self) -> None:
        self._tmp = TemporaryDirectory(dir="/var/tmp" if os.path.isdir("/var/tmp") else None)
        self.addCleanup(self._tmp.cleanup)
        self.root = Path(self._tmp.name)
        self.cli_calls: list[list[str]] = []
        # 截止时间压短：超时用例只等零点几秒
        for patcher in (patch.object(codex_rpc, "THREAD_READ_SECONDS", 0.4),
                        patch.object(codex_rpc, "TURNS_LIST_SECONDS", 0.4),
                        patch.object(codex_rpc, "STEER_SECONDS", 0.4),
                        patch.object(codex_rpc, "ADD_SECONDS", 0.4)):
            patcher.start()
            self.addCleanup(patcher.stop)

    def daemon(self, replies: dict[str, Any]) -> Any:
        root = self.root / f"d{len(list(self.root.iterdir()))}"
        root.mkdir()
        daemon = _make_daemon(root, replies)
        self.addCleanup(daemon.close)
        return daemon

    def steer(self, daemon: Any, *, steer: bool = True, text: str = "补充 Y") -> RpcFallback | RpcResult:
        result = codex_rpc.queue_add(daemon.link, thread_id=THREAD, text=text, client_message_id=MESSAGE,
                                     client_version="0.169.0", steer=steer)
        daemon.close()
        return result

    def methods(self, daemon: Any) -> list[str]:
        return [str(item.get("method")) for item in daemon.received]

    def test_steer_success_records_delivered_without_queue_or_turn_id(self) -> None:
        daemon = self.daemon({"thread/read": active_thread(), "thread/turns/list": turns(), "turn/steer": steered()})
        result = self.steer(daemon)
        assert isinstance(result, RpcResult)
        self.assertEqual((result.delivery, result.reason, result.provider_ref, result.steer_path),
                         (Delivery.DELIVERED, "codex_steered", None, STEER_PATH_STEERED))
        self.assertEqual(result.server_version, "0.169.0")
        self.assertEqual(self.methods(daemon), ["initialize", "initialized", "thread/read", "thread/turns/list",
                                                "turn/steer"])
        read, listing, steer = daemon.received[2:]
        self.assertEqual(read["params"], {"threadId": THREAD, "includeTurns": False})
        self.assertEqual(listing["params"], {"threadId": THREAD, "limit": 1, "sortDirection": "desc",
                                             "itemsView": "notLoaded"})
        self.assertEqual(steer["params"], {"threadId": THREAD, "expectedTurnId": TURN, "clientUserMessageId": MESSAGE,
                                           "input": [{"type": "text", "text": "补充 Y", "text_elements": []}]})
        self.assertNotIn(TURN, repr(result))

    def test_without_steer_flag_the_request_sequence_is_unchanged(self) -> None:
        daemon = self.daemon({"thread/read": active_thread(), "thread/turns/list": turns(), "turn/steer": steered()})
        result = self.steer(daemon, steer=False)
        assert isinstance(result, RpcResult)
        self.assertEqual((result.delivery, result.steer_path), (Delivery.QUEUED, None))
        self.assertEqual(self.methods(daemon), ["initialize", "initialized", "thread/queue/add"])

    def test_no_active_turn_paths_go_to_the_queue_on_the_same_connection(self) -> None:
        cases: dict[str, tuple[dict[str, Any], str, list[str]]] = {
            "idle": ({"thread/read": active_thread("idle")}, STEER_PATH_THREAD_NOT_ACTIVE, ["thread/read"]),
            "notLoaded": ({"thread/read": active_thread("notLoaded")}, STEER_PATH_THREAD_NOT_ACTIVE, ["thread/read"]),
            "read_error": ({"thread/read": rpc_error(-32600, "x")}, STEER_PATH_THREAD_UNREADABLE, ["thread/read"]),
            "read_shape": ({"thread/read": {"result": {"thread": {"status": "active"}}}}, STEER_PATH_THREAD_UNREADABLE,
                           ["thread/read"]),
            "read_timeout": ({"thread/read": "silent"}, STEER_PATH_THREAD_UNREADABLE, ["thread/read"]),
            "completed": ({"thread/read": active_thread(), "thread/turns/list": turns("completed")},
                          STEER_PATH_NO_ACTIVE_TURN, ["thread/read", "thread/turns/list"]),
            "empty": ({"thread/read": active_thread(), "thread/turns/list": {"result": {"data": []}}},
                      STEER_PATH_NO_ACTIVE_TURN, ["thread/read", "thread/turns/list"]),
            "turns_error": ({"thread/read": active_thread(), "thread/turns/list": rpc_error(-32603, "failed")},
                            STEER_PATH_TURNS_UNREADABLE, ["thread/read", "thread/turns/list"]),
            "turns_shape": ({"thread/read": active_thread(), "thread/turns/list": {"result": {"data": [{"id": TURN}]}}},
                            STEER_PATH_TURNS_UNREADABLE, ["thread/read", "thread/turns/list"]),
            "turns_timeout": ({"thread/read": active_thread(), "thread/turns/list": "silent"},
                              STEER_PATH_TURNS_UNREADABLE, ["thread/read", "thread/turns/list"]),
            # 超时后迟到的 turns/list 应答在等 add 时按 id 丢弃，不当成 add 的结果
            "turns_late": ({"thread/read": active_thread(), "thread/turns/list": ("late", turns())},
                           STEER_PATH_TURNS_UNREADABLE, ["thread/read", "thread/turns/list"]),
        }
        for name, (replies, path, reads) in cases.items():
            with self.subTest(case=name):
                daemon = self.daemon(replies)
                result = self.steer(daemon)
                assert isinstance(result, RpcResult), result
                self.assertEqual((result.delivery, result.reason, result.provider_ref, result.steer_path),
                                 (Delivery.QUEUED, "codex_queued", ITEM.lower(), path))
                self.assertEqual(self.methods(daemon), ["initialize", "initialized", *reads, "thread/queue/add"])

    def test_known_rejections_fall_back_to_queue_in_the_same_delivery(self) -> None:
        for code, message, reason in KNOWN_REJECTIONS:
            with self.subTest(message=message):
                daemon = self.daemon({"thread/read": active_thread(), "thread/turns/list": turns(),
                                      "turn/steer": rpc_error(code, message)})
                result = self.steer(daemon)
                assert isinstance(result, RpcResult), result
                self.assertEqual((result.delivery, result.steer_path, result.steer_rejected),
                                 (Delivery.QUEUED, STEER_PATH_REJECTED, reason))
                self.assertEqual(self.methods(daemon)[-2:], ["turn/steer", "thread/queue/add"])

    def test_unknown_errors_and_post_send_problems_are_unknown_without_queue(self) -> None:
        cases: dict[str, tuple[Any, str]] = {
            **{message: (rpc_error(code, message), reason) for code, message, reason in UNKNOWN_ERRORS},
            "timeout": ("silent", "codex_steer_timeout"),
            "close": ("close", "codex_transport_error"),
            "shape": ({"result": {"turn": TURN}}, "codex_steer_unparsed_output"),
        }
        for name, (reply, reason) in cases.items():
            with self.subTest(case=name):
                daemon = self.daemon({"thread/read": active_thread(), "thread/turns/list": turns(), "turn/steer": reply})
                result = self.steer(daemon)
                assert isinstance(result, RpcResult), result
                self.assertEqual((result.delivery, result.reason, result.steer_path),
                                 (Delivery.UNKNOWN, reason, STEER_PATH_UNKNOWN))
                self.assertNotIn("thread/queue/add", self.methods(daemon))

    def test_half_read_turns_list_desyncs_and_falls_back_before_any_write(self) -> None:
        for method in ("thread/read", "thread/turns/list"):
            with self.subTest(method=method):
                replies: dict[str, Any] = {"thread/read": active_thread(), "thread/turns/list": turns()}
                replies[method] = {**replies[method], "partial": True}
                daemon = self.daemon(replies)
                self.assertEqual(self.steer(daemon), RpcFallback("steer_read_failed"))
                self.assertNotIn("turn/steer", self.methods(daemon))
                self.assertNotIn("thread/queue/add", self.methods(daemon))

    def test_write_latch_is_reset_after_a_rejection_and_set_by_the_steer_frame(self) -> None:
        # 复位：steer 被确定拒绝后、add 帧发出前的意外异常仍是写前失败（回退），不是 UNKNOWN
        daemon = self.daemon({"thread/read": active_thread(), "thread/turns/list": turns(),
                              "turn/steer": rpc_error(-32600, "no active turn to steer")})
        with patch.object(codex_rpc._Client, "_add", side_effect=RuntimeError("fixture")):  # pyright: ignore[reportPrivateUsage]
            result = self.steer(daemon)
        self.assertIsInstance(result, RpcFallback)
        # 置位：steer 帧开始发送后的意外异常是 UNKNOWN，不回退、不排队
        daemon = self.daemon({"thread/read": active_thread(), "thread/turns/list": turns(), "turn/steer": steered()})
        real_send = codex_rpc._Client._send_frame  # pyright: ignore[reportPrivateUsage]

        def explode_on_steer(client: Any, opcode: int, payload: bytes, deadline: float) -> None:
            real_send(client, opcode, payload, deadline)
            if b'"turn/steer"' in payload:
                raise RuntimeError("fixture")

        with patch.object(codex_rpc._Client, "_send_frame", explode_on_steer):  # pyright: ignore[reportPrivateUsage]
            result = self.steer(daemon)
        assert isinstance(result, RpcResult), result
        self.assertEqual((result.delivery, result.reason, result.steer_path),
                         (Delivery.UNKNOWN, "codex_transport_error", STEER_PATH_UNKNOWN))
        self.assertNotIn("thread/queue/add", self.methods(daemon))

    # ---- CodexQueueTransport：证据键与 CLI 回退 ----

    def runner(self, argv: Sequence[str], _timeout: float) -> Any:
        from agentstatus_bridge.transports.codex_queue import RunResult
        self.cli_calls.append(list(argv))
        if argv[1] == "--version":
            return RunResult(0, "codex-cli 0.169.0\n", "")
        return RunResult(0, f"Queued message {ITEM} for thread {THREAD}.\n", "")

    def deliver(self, daemon: Any, *, steer: bool = True) -> Any:
        from bridge_support import endpoint, ref
        from agentstatus_bridge.transports.codex_queue import CodexQueueTransport
        binary = self.root / "codex-bin"
        if not binary.exists():
            binary.write_text("#!/bin/sh\n")
        transport = CodexQueueTransport(executable=str(binary), runner=self.runner)
        with patch.dict(os.environ, {"CODEX_HOME": str(daemon.home)}):
            outcome = transport.deliver(endpoint(ref(native=THREAD)), "补充 Y",
                                        DeliveryContext(message_uuid=MESSAGE, sender_name="user", steer=steer))
        daemon.close()
        return outcome

    def test_transport_evidence_keeps_steered_out_of_queue_samples(self) -> None:
        from agentstatus_bridge.transports.codex_queue import summarize_queue_evidence, summarize_rpc_evidence
        daemon = self.daemon({"thread/read": active_thread(), "thread/turns/list": turns(), "turn/steer": steered()})
        outcome = self.deliver(daemon)
        self.assertEqual((outcome.delivery, outcome.reason, outcome.provider_ref, outcome.native_root),
                         (Delivery.DELIVERED, "codex_steered", None, None))
        self.assertEqual(outcome.detail, {"codexVersion": "0.169.0", "steerPath": STEER_PATH_STEERED})
        self.assertEqual(summarize_rpc_evidence([outcome.detail])["state"], "no_samples")
        self.assertEqual(summarize_queue_evidence([outcome.detail], "0.169.0")["state"], "no_samples")
        # 退回队列：照旧是 RPC 队列样本，另附通道选择路径与拒绝原因
        daemon = self.daemon({"thread/read": active_thread(), "thread/turns/list": turns(),
                              "turn/steer": rpc_error(-32600, "cannot steer a review turn")})
        outcome = self.deliver(daemon)
        self.assertEqual(outcome.delivery, Delivery.QUEUED)
        self.assertEqual(outcome.detail, {"queueChannel": "rpc", "codexVersion": "0.169.0", "queueOutput": "recognized",
                                          "steerPath": STEER_PATH_REJECTED, "steerRejected": "codex_steer_review_turn"})
        self.assertEqual(summarize_rpc_evidence([outcome.detail])["recognized"], 1)
        self.assertEqual([argv for argv in self.cli_calls if argv[1] == "queue"], [])

    def test_desynced_read_falls_back_to_the_cli_queue(self) -> None:
        daemon = self.daemon({"thread/read": active_thread(), "thread/turns/list": {**turns(), "partial": True}})
        outcome = self.deliver(daemon)
        self.assertEqual(outcome.delivery, Delivery.QUEUED)
        self.assertEqual((outcome.detail["queueChannel"], outcome.detail["rpcFallback"]), ("cli", "steer_read_failed"))
        self.assertEqual(len([argv for argv in self.cli_calls if argv[1] == "queue"]), 1)

    def test_ordinary_delivery_does_not_pass_the_steer_argument(self) -> None:
        from agentstatus_bridge.transports.codex_queue import CodexQueueTransport
        from bridge_support import endpoint, ref
        seen: list[dict[str, Any]] = []

        def rpc(_link: Path, **kwargs: Any) -> RpcFallback:
            seen.append(kwargs)
            return RpcFallback("socket_missing")

        binary = self.root / "codex-bin"
        binary.write_text("#!/bin/sh\n")
        transport = CodexQueueTransport(executable=str(binary), runner=self.runner, rpc=rpc)
        with patch.dict(os.environ, {"CODEX_HOME": str(self.root)}):
            for steer in (False, True):
                transport.deliver(endpoint(ref(native=THREAD)), "x",
                                  DeliveryContext(message_uuid=MESSAGE, sender_name="user", steer=steer))
        self.assertNotIn("steer", seen[0])
        self.assertIs(seen[1]["steer"], True)


class WindowsSteerTests(unittest.TestCase):
    """Windows `codex_delivery` 的 steer 通道（假 Win32 内核，两种系统都跑）。"""

    def setUp(self) -> None:
        import test_bridge_windows_delivery as delivery_tests
        self.fixture = delivery_tests
        self.base = delivery_tests.DeliveryTests
        self.base.setUp(self)  # type: ignore[arg-type]
        self.rebuild()

    def scope(self, **kwargs: Any) -> Any:
        return self.base.scope(self, **kwargs)  # type: ignore[arg-type]

    def target(self) -> Any:
        return self.base.target(self)  # type: ignore[arg-type]

    def rebuild(self) -> None:
        from agentstatus_bridge.platforms.factory import make_platform
        fixture = self.fixture

        class SteerKernel(fixture.QueueKernel):  # type: ignore[name-defined,misc]
            """在 add 假 daemon 之上补 thread/turns/list 与 turn/steer；应答为 None 时不回（连接随即读到 EOF）。"""

            def __init__(self, root: Path, home: Path) -> None:
                super().__init__(root, home)
                self.turns_reply: Callable[[dict[str, Any]], dict[str, Any] | None] | None = None
                self.steer_reply: Callable[[dict[str, Any]], dict[str, Any] | None] | None = None

            def send(self, handle: Any, buf: Any, size: int, flags: int) -> int:
                before = len(self.messages)
                count = super().send(handle, buf, size, flags)
                for message in self.messages[before:]:
                    reply = {"thread/turns/list": self.turns_reply, "turn/steer": self.steer_reply}.get(message["method"])
                    if reply is None:
                        continue
                    body = reply(message)
                    if body is not None:
                        self.socket_in.extend(self.frame({"id": message["id"], **body}))
                return count

        self.k = SteerKernel(self.root, self.home)  # type: ignore[attr-defined]
        self.k.files[str(self.home)] = {"private": False, "protected": False}  # type: ignore[attr-defined]
        self.k.files[str(self.socket)] = {"reparse": True, "tag": 0x80000023}  # type: ignore[attr-defined]
        self.k.processes[200] = (0, 134362090000012230, self.k.sid, False, "codex.exe")
        self.k.peer = 200
        self.p = make_platform("windows", win_api=self.k.api)
        self.k.metadata[THREAD_W()] = {"id": THREAD_W(), "source": "cli", "parentThreadId": None,
                                       "status": {"type": "active", "activeFlags": []}}
        self.k.turns_reply = lambda _m: turns(turn_id=TURN)
        self.k.steer_reply = lambda _m: steered()

    def deliver(self, target: Any, boundaries: list[str] | None = None, *, steer: bool = True,
                boundary: Callable[[], None] | None = None) -> Any:
        from agentstatus_bridge.platforms.windows import codex_delivery as T
        calls = boundaries if boundaries is not None else []
        return T.CodexTransport().deliver(target, "补充 Y", DeliveryContext(
            THREAD_W(700), "fixture", steer=steer, before_send=boundary or (lambda: calls.append("boundary"))))

    def methods(self) -> list[str]:
        return [m["method"] for m in self.k.messages if m["method"] not in ("initialize", "initialized",
                                                                             "thread/loaded/list")]

    def test_steer_success_one_boundary_and_no_add(self) -> None:
        with self.scope():
            target = self.target()
            self.k.messages.clear()
            boundaries: list[str] = []
            result = self.deliver(target, boundaries)
        self.assertEqual((result.delivery, result.reason, result.provider_ref, result.native_root),
                         (Delivery.DELIVERED, "codex_steered", None, None))
        self.assertEqual(result.detail, {"steerPath": STEER_PATH_STEERED, "codexVersion": "0.162.1",
                                         "serverVersion": "0.162.1"})
        self.assertEqual(boundaries, ["boundary"])
        self.assertEqual(self.methods(), ["thread/read", "thread/turns/list", "turn/steer"])
        steer = [m for m in self.k.messages if m["method"] == "turn/steer"][0]
        self.assertEqual(steer["params"], {"threadId": THREAD_W(), "expectedTurnId": TURN,
                                           "clientUserMessageId": THREAD_W(700),
                                           "input": [{"type": "text", "text": "补充 Y", "text_elements": []}]})
        listing = [m for m in self.k.messages if m["method"] == "thread/turns/list"][0]
        self.assertEqual(listing["params"], {"threadId": THREAD_W(), "limit": 1, "sortDirection": "desc",
                                             "itemsView": "notLoaded"})

    def test_sql_classified_target_still_reads_status_once(self) -> None:
        # SQL 已答分类时分类步骤不发 thread/read；补充消息自己补一次 metadata-only 读取
        self.base.sql(self, [(THREAD_W(), "cli")])  # type: ignore[arg-type]
        for kind, expected in (("active", Delivery.DELIVERED), ("idle", Delivery.QUEUED)):
            with self.subTest(kind=kind):
                self.k.metadata[THREAD_W()]["status"] = {"type": kind, **({"activeFlags": []} if kind == "active" else {})}
                with self.scope():
                    target = self.target()
                    self.k.messages.clear()
                    result = self.deliver(target)
                self.assertIs(result.delivery, expected)
                reads = [m for m in self.k.messages if m["method"] == "thread/read"]
                self.assertEqual([m["params"] for m in reads], [{"threadId": THREAD_W(), "includeTurns": False}])

    def test_not_active_and_no_turn_go_to_queue(self) -> None:
        for case in ("idle", "completed", "turns_error"):
            with self.subTest(case=case):
                self.rebuild()
                if case == "idle":
                    self.k.metadata[THREAD_W()]["status"] = {"type": "idle"}
                if case == "completed":
                    self.k.turns_reply = lambda _m: turns("completed")
                if case == "turns_error":
                    self.k.turns_reply = lambda _m: rpc_error(-32603, "failed to read thread: x")
                with self.scope():
                    target = self.target()
                    self.k.messages.clear()
                    boundaries: list[str] = []
                    result = self.deliver(target, boundaries)
                self.assertIs(result.delivery, Delivery.QUEUED)
                self.assertEqual(boundaries, ["boundary"])
                expected = {"idle": STEER_PATH_THREAD_NOT_ACTIVE, "completed": STEER_PATH_NO_ACTIVE_TURN,
                            "turns_error": STEER_PATH_TURNS_UNREADABLE}[case]
                self.assertEqual(result.detail["steerPath"], expected)
                self.assertNotIn("turn/steer", self.methods())
                self.assertEqual(self.methods()[-1], "thread/queue/add")

    def test_rejection_resets_the_latch_and_queues_with_a_second_boundary(self) -> None:
        self.k.steer_reply = lambda _m: rpc_error(-32600, "no active turn to steer")
        with self.scope():
            target = self.target()
            self.k.messages.clear()
            boundaries: list[str] = []
            result = self.deliver(target, boundaries)
        self.assertIs(result.delivery, Delivery.QUEUED)
        self.assertEqual(boundaries, ["boundary", "boundary"])
        self.assertEqual((result.detail["steerPath"], result.detail["steerRejected"]),
                         (STEER_PATH_REJECTED, "codex_steer_no_active_turn"))
        self.assertEqual(self.methods()[-2:], ["turn/steer", "thread/queue/add"])
        # 复位方向：拒绝之后、add 帧之前的写前失败仍是 FAILED（可证明未送入），不是 UNKNOWN
        self.rebuild()
        self.k.steer_reply = lambda _m: rpc_error(-32600, "cannot steer a compact turn")
        from agentstatus_bridge.store import StoreError
        count = [0]

        def second_boundary_fails() -> None:
            count[0] += 1
            if count[0] == 2:
                raise StoreError("store_error")

        with self.scope():
            target = self.target()
            result = self.deliver(target, boundary=second_boundary_fails)
        self.assertEqual((result.delivery, result.reason), (Delivery.FAILED, "boundary_record_failed"))

    def test_unknown_after_the_steer_frame_never_queues(self) -> None:
        cases: dict[str, tuple[Callable[[dict[str, Any]], dict[str, Any] | None], str]] = {
            "failed": (lambda _m: rpc_error(-32603, "failed to steer turn: x"), "codex_steer_failed"),
            "unrecognized": (lambda _m: rpc_error(-32600, "core rejected input"), "codex_steer_unrecognized_error"),
            "shape": (lambda _m: {"result": {}}, "codex_steer_unparsed_output"),
            "eof": (lambda _m: None, "codex_transport_error"),
        }
        for name, (reply, reason) in cases.items():
            with self.subTest(case=name):
                self.rebuild()
                self.k.steer_reply = reply
                with self.scope():
                    target = self.target()
                    self.k.messages.clear()
                    result = self.deliver(target)
                self.assertEqual((result.delivery, result.reason, result.detail["steerPath"]),
                                 (Delivery.UNKNOWN, reason, STEER_PATH_UNKNOWN))
                self.assertNotIn("queueChannel", result.detail)
                self.assertNotIn("thread/queue/add", self.methods())

    def test_timeout_after_the_steer_frame_is_unknown(self) -> None:
        from agentstatus_bridge.transports.codex_native import BoundedConnection
        real = BoundedConnection.response
        kernel = self.k

        def response(client: Any, expected: int, deadline: float, *, stale: Sequence[int] = ()) -> Any:
            if kernel.messages and kernel.messages[-1]["method"] == "turn/steer":
                raise _Timeout("fixture")
            return real(client, expected, deadline, stale=stale)

        with self.scope(), patch.object(BoundedConnection, "response", response):
            target = self.target()
            self.k.messages.clear()
            result = self.deliver(target)
        self.assertEqual((result.delivery, result.reason, result.detail["steerPath"]),
                         (Delivery.UNKNOWN, "codex_steer_timeout", STEER_PATH_UNKNOWN))
        self.assertNotIn("thread/queue/add", self.methods())

    def _timeout_on_turns(self, *, desync: bool) -> Callable[..., Any]:
        from agentstatus_bridge.transports.codex_native import BoundedConnection
        real = BoundedConnection.response
        fired = [False]
        kernel = self.k

        def response(client: Any, expected: int, deadline: float, *, stale: Sequence[int] = ()) -> Any:
            last = kernel.messages[-1]["method"] if kernel.messages else None
            if last == "thread/turns/list" and not fired[0]:
                fired[0] = True
                if desync:
                    client._inflight = 3  # 读走了半条消息
                raise _Timeout("fixture")  # 应答帧还留在流里：迟到
            return real(client, expected, deadline, stale=stale)

        return response

    def test_clean_read_timeout_skips_the_late_reply_but_desync_queues_on_a_fresh_connection(self) -> None:
        from agentstatus_bridge.transports.codex_native import BoundedConnection
        with self.scope(), patch.object(BoundedConnection, "response", self._timeout_on_turns(desync=False)):
            target = self.target()
            self.k.messages.clear()
            result = self.deliver(target)
        self.assertIs(result.delivery, Delivery.QUEUED)
        self.assertEqual(result.detail["steerPath"], STEER_PATH_TURNS_UNREADABLE)
        self.assertNotIn("steerReadFailed", result.detail)
        self.assertNotIn("turn/steer", self.methods())
        self.rebuild()
        # 读到一半失步：还没写过投递帧，新开一条连接走队列，不记 FAILED（G4 审计 r1 P3-3/F-6）
        with self.scope(), patch.object(BoundedConnection, "response", self._timeout_on_turns(desync=True)):
            target = self.target()
            self.k.messages.clear()
            boundaries: list[str] = []
            result = self.deliver(target, boundaries)
        self.assertIs(result.delivery, Delivery.QUEUED)
        self.assertEqual((result.detail["steerPath"], result.detail["steerReadFailed"]),
                         (STEER_PATH_TURNS_UNREADABLE, "codex_steer_read_desync"))
        # 新连接照常先做根会话分类（metadata-only thread/read），再直接 add，不再读轮次、不 steer
        self.assertEqual(self.methods(), ["thread/read", "thread/turns/list", "thread/read", "thread/queue/add"])
        self.assertEqual(sum(1 for m in self.k.messages if m["method"] == "initialize"), 2)  # 两条连接
        self.assertEqual(boundaries, ["boundary"])  # 只有 add 前那一次

    def test_non_timeout_read_failures_queue_on_a_fresh_connection(self) -> None:
        # 只读步骤收到服务端请求或应答 id 不符：同样是写前失败，新开连接走队列
        from agentstatus_bridge.transports.codex_native import BoundedConnection, NativeFailure
        # SQL 已答分类：分类步骤不发 thread/read，失败点落在补充消息自己的只读步骤上（库文件跨 rebuild 保留）
        self.base.sql(self, [(THREAD_W(), "cli")])  # type: ignore[arg-type]
        for reason, step, path in (("server_request_seen", "thread/read", STEER_PATH_THREAD_UNREADABLE),
                                   ("response_id_mismatch", "thread/turns/list", STEER_PATH_TURNS_UNREADABLE)):
            with self.subTest(reason=reason):
                self.rebuild()
                real = BoundedConnection.response
                fired = [False]
                kernel = self.k

                def response(client: Any, expected: int, deadline: float, *, stale: Sequence[int] = (),
                             _step: str = step, _reason: str = reason) -> Any:
                    last = kernel.messages[-1]["method"] if kernel.messages else None
                    if last == _step and not fired[0]:
                        fired[0] = True
                        raise NativeFailure(_reason)
                    return real(client, expected, deadline, stale=stale)

                with self.scope(), patch.object(BoundedConnection, "response", response):
                    target = self.target()
                    self.k.messages.clear()
                    result = self.deliver(target)
                self.assertIs(result.delivery, Delivery.QUEUED, result)
                self.assertEqual((result.detail["steerPath"], result.detail["steerReadFailed"]), (path, reason))
                self.assertNotIn("turn/steer", self.methods())
                self.assertEqual(self.methods()[-1], "thread/queue/add")

    def test_an_os_error_in_a_read_step_queues_on_a_fresh_connection(self) -> None:
        # 只读步骤等应答时遇到 OSError：连接不可用但还没写过投递帧，新开连接走队列（Fable R14）
        from agentstatus_bridge.transports.codex_native import BoundedConnection
        real = BoundedConnection.response
        kernel = self.k
        fired = [False]

        def response(client: Any, expected: int, deadline: float, *, stale: Sequence[int] = ()) -> Any:
            if kernel.messages and kernel.messages[-1]["method"] == "thread/turns/list" and not fired[0]:
                fired[0] = True
                raise OSError("fixture")
            return real(client, expected, deadline, stale=stale)

        with self.scope(), patch.object(BoundedConnection, "response", response):
            target = self.target()
            self.k.messages.clear()
            result = self.deliver(target)
        self.assertIs(result.delivery, Delivery.QUEUED, result)
        self.assertEqual((result.detail["steerPath"], result.detail["steerReadFailed"]),
                         (STEER_PATH_TURNS_UNREADABLE, "codex_transport_error"))
        self.assertEqual(self.methods()[-1], "thread/queue/add")
        self.assertNotIn("turn/steer", self.methods())
        self.assertEqual(sum(1 for m in self.k.messages if m["method"] == "initialize"), 2)

    def test_a_half_written_read_request_queues_on_a_fresh_connection(self) -> None:
        # 请求帧只写出一半就发送超时（没到总截止）：流已不在消息边界上，不能在这条连接上接着写 add——
        # 换新连接走队列，结果仍是可证明的入队（G4 r1 复核 Opus P3-1，复现脚本 audit-opus/xver/win_send_timeout.py）
        from agentstatus_bridge.transports.codex_native import BoundedConnection
        real = BoundedConnection._send_json

        def half_then_timeout(client: Any, message: Any, deadline: float) -> None:
            if isinstance(message, dict) and message.get("method") == "thread/turns/list":
                payload = client._encode(message)
                mask = os.urandom(4)
                header = (bytearray([0x81, 0x80 | 126]) + len(payload).to_bytes(2, "big") if len(payload) >= 126
                          else bytearray([0x81, 0x80 | len(payload)]))
                repeated = (mask * (len(payload) // 4 + 1))[:len(payload)]
                frame = bytes(header) + mask + bytes(a ^ b for a, b in zip(payload, repeated))
                client._sendall(frame[: len(frame) // 2], deadline)
                raise _Timeout("fixture")
            real(client, message, deadline)

        with self.scope(), patch.object(BoundedConnection, "_send_json", half_then_timeout):
            target = self.target()
            self.k.messages.clear()
            boundaries: list[str] = []
            result = self.deliver(target, boundaries)
        self.assertIs(result.delivery, Delivery.QUEUED, result)
        self.assertEqual((result.detail["steerPath"], result.detail["steerReadFailed"]),
                         (STEER_PATH_TURNS_UNREADABLE, "codex_steer_read_desync"))
        self.assertEqual(self.methods()[-1], "thread/queue/add")
        self.assertNotIn("turn/steer", self.methods())
        self.assertEqual(sum(1 for m in self.k.messages if m["method"] == "initialize"), 2)  # 两条连接
        self.assertEqual(boundaries, ["boundary"])

    def test_running_out_of_the_total_budget_in_a_read_step_still_fails(self) -> None:
        # 总预算用完不是「只读失败」：照旧按写前超时记 FAILED，不再开新连接
        from agentstatus_bridge.platforms.windows import codex_delivery as T
        from agentstatus_bridge.transports.codex_native import BoundedConnection
        real = BoundedConnection.response
        kernel = self.k

        # 只换投递模块自己的时钟（真实时钟加偏移），不改进程全局的 time.monotonic：
        # 偏移前与传输层同一时基，偏移后只有投递模块看到总预算用完
        offset = [0.0]

        def response(client: Any, expected: int, deadline: float, *, stale: Sequence[int] = ()) -> Any:
            if kernel.messages and kernel.messages[-1]["method"] == "thread/turns/list":
                offset[0] = 10_000.0  # 等这一步的应答时总预算用完
                raise _Timeout("fixture")
            return real(client, expected, deadline, stale=stale)

        clock = SimpleNamespace(monotonic=lambda: time.monotonic() + offset[0])
        with self.scope(), patch.object(BoundedConnection, "response", response), \
                patch.object(T, "time", clock):
            target = self.target()
            self.k.messages.clear()
            result = self.deliver(target)
        self.assertIs(result.delivery, Delivery.FAILED)
        self.assertEqual(result.reason, "codex_deadline_before_send")
        self.assertNotIn("steerReadFailed", result.detail)  # 没有当成只读失败去新开连接
        self.assertNotIn("thread/queue/add", self.methods())

    def test_without_steer_flag_no_reads_are_added(self) -> None:
        with self.scope():
            target = self.target()
            self.k.messages.clear()
            result = self.deliver(target, steer=False)
        self.assertIs(result.delivery, Delivery.QUEUED)
        self.assertNotIn("steerPath", result.detail)
        self.assertNotIn("thread/turns/list", self.methods())
        self.assertNotIn("turn/steer", self.methods())


def THREAD_W(index: int = 1) -> str:  # noqa: N802 - 与 Windows 夹具的 uuid() 同值
    from test_bridge_windows_discovery import uuid
    return uuid(index)


if __name__ == "__main__":
    unittest.main()
