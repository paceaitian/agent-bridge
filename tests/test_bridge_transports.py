"""协作桥原生通道：Codex queue 结果分类、Claude 帧/回执与真实 Unix socket 投递。"""

from __future__ import annotations

from collections.abc import Sequence
import json
import os
from pathlib import Path
import socket
import sqlite3
import subprocess
from tempfile import TemporaryDirectory
import threading
import unittest
from unittest.mock import patch

from agentstatus_bridge import procfs
from agentstatus_bridge.naming import DEFAULT_COMMAND as CMD
from agentstatus_bridge.envelope import parse_header, render
from agentstatus_bridge.model import Attempt, Consumption, Delivery, EndpointRef, Flow, Provider, Role, Task
from agentstatus_bridge.transports import DeliveryContext
from agentstatus_bridge.transports import claude_peer
from agentstatus_bridge.transports.claude_peer import (
    ClaudeInbox,
    ClaudePeerTransport,
    build_frame,
    encode_address,
    normalize_sender_name,
    parse_receipt,
)
from agentstatus_bridge.transports.codex_queue import (
    MAX_ARGV_MESSAGE_BYTES,
    CodexQueueTransport,
    RunResult,
    classify_failure,
    queue_item_state,
)
from bridge_support import endpoint, ref

THREAD = "019a0000-1111-7222-8333-444455556666"
ITEM = "019A9999-AAAA-7BBB-8CCC-DDDDEEEEFFFF"


class CodexQueueTests(unittest.TestCase):
    def _transport(self, result: RunResult | Exception) -> tuple[CodexQueueTransport, list[Sequence[str]]]:
        calls: list[Sequence[str]] = []

        def runner(argv: Sequence[str], _timeout: float) -> RunResult:
            calls.append(argv)
            if isinstance(result, Exception):
                raise result
            return result

        return CodexQueueTransport(executable="/usr/bin/codex", runner=runner), calls

    def _deliver(self, transport: CodexQueueTransport, text: str = "hello"):
        context = DeliveryContext(message_uuid="u", sender_name="user")
        return transport.deliver(endpoint(ref(native=THREAD)), text, context)

    def test_success_records_queue_item(self) -> None:
        transport, calls = self._transport(RunResult(0, f"Queued message {ITEM} for thread {THREAD}.\n", ""))
        outcome = self._deliver(transport)
        self.assertEqual((outcome.delivery, outcome.provider_ref), (Delivery.QUEUED, ITEM.lower()))
        self.assertEqual(list(calls[0]), ["/usr/bin/codex", "queue", "--thread", THREAD, "--message", "hello"])

    def test_success_for_other_thread_is_unknown(self) -> None:
        other = "019a0000-0000-7000-8000-000000000000"
        transport, _ = self._transport(RunResult(0, f"Queued message {ITEM} for thread {other}.", ""))
        outcome = self._deliver(transport)
        self.assertEqual((outcome.delivery, outcome.reason), (Delivery.UNKNOWN, "codex_queue_unparsed_output"))

    def test_known_rejections_are_proven_undelivered(self) -> None:
        cases = {
            f"Error: failed to queue session message: thread/queue/add failed: thread not found: {THREAD} (code -32600)": "codex_thread_not_found",
            "Error: thread/queue/add failed: thread x is archived. Run `codex unarchive x` (code -32600)": "codex_thread_archived",
            "Error: thread/queue/add failed: queue cannot contain more than 100 submissions (code -32600)": "provider_queue_full",
            "Error: cannot queue through an embedded app server while a local app-server daemon is running": "codex_daemon_conflict",
            "Error: remote app server does not support thread/queue/add; update or restart the server": "codex_version_unsupported",
        }
        for stderr, reason in cases.items():
            with self.subTest(reason=reason):
                transport, _ = self._transport(RunResult(1, "", stderr))
                outcome = self._deliver(transport)
                self.assertEqual((outcome.delivery, outcome.reason), (Delivery.FAILED, reason))

    def test_storage_transport_and_unrecognized_errors_are_unknown(self) -> None:
        self.assertEqual(
            classify_failure("Error: queued submission operation failed: queue storage failed: locked"),
            (Delivery.UNKNOWN, "codex_queue_storage_error"),
        )
        self.assertEqual(
            classify_failure("Error: thread/queue/add transport error: broken pipe"),
            (Delivery.UNKNOWN, "codex_transport_error"),
        )
        self.assertEqual(classify_failure("Error: something new"), (Delivery.UNKNOWN, "codex_queue_unrecognized_error"))

    def test_usage_error_and_other_pre_insert_rejections(self) -> None:
        transport, _ = self._transport(RunResult(2, "", "error: unexpected argument '--bogus' found"))
        outcome = self._deliver(transport)
        self.assertEqual((outcome.delivery, outcome.reason), (Delivery.FAILED, "codex_cli_usage_error"))
        self.assertEqual(
            classify_failure(
                "Error: failed to queue session message: thread/queue/add failed: invalid thread id: x (code -32600)"
            ),
            (Delivery.FAILED, "codex_thread_invalid"),
        )
        transport, _ = self._transport(RunResult(101, "", "thread 'main' panicked"))
        self.assertEqual(self._deliver(transport).delivery, Delivery.UNKNOWN)

    def test_timeout_is_unknown_and_oversized_message_is_not_attempted(self) -> None:
        transport, _ = self._transport(subprocess.TimeoutExpired(["codex"], 60))
        self.assertEqual(self._deliver(transport).reason, "codex_queue_timeout")
        transport, calls = self._transport(RunResult(0, "", ""))
        outcome = self._deliver(transport, "x" * (MAX_ARGV_MESSAGE_BYTES + 1))
        self.assertEqual((outcome.delivery, outcome.reason), (Delivery.FAILED, "message_too_large_for_argv"))
        self.assertEqual(calls, [])

    def test_missing_cli(self) -> None:
        with patch("agentstatus_bridge.transports.codex_queue.shutil.which", return_value=None):
            outcome = CodexQueueTransport().deliver(
                endpoint(ref(native=THREAD)), "x", DeliveryContext(message_uuid="u", sender_name="user")
            )
        self.assertEqual((outcome.delivery, outcome.reason), (Delivery.FAILED, "codex_cli_missing"))

    def test_queue_item_state_reads_ids_only(self) -> None:
        with TemporaryDirectory() as tmp:
            database = Path(tmp) / "queue_1.sqlite"
            self.assertEqual(queue_item_state("a", database=database), Consumption.UNKNOWN)
            with sqlite3.connect(database) as connection:
                connection.execute("CREATE TABLE other (id TEXT)")
            self.assertEqual(queue_item_state("a", database=database), Consumption.UNKNOWN)
            with sqlite3.connect(database) as connection:
                connection.execute(
                    "CREATE TABLE queued_items (id TEXT PRIMARY KEY, thread_id TEXT, payload_json TEXT,"
                    " queue_order INTEGER, created_at_ms INTEGER, updated_at_ms INTEGER)"
                )
                connection.execute("INSERT INTO queued_items VALUES ('a', 't', '{}', 1, 0, 0)")
            self.assertEqual(queue_item_state("a", database=database), Consumption.STILL_QUEUED)
            self.assertEqual(queue_item_state("b", database=database), Consumption.LEFT_QUEUE)


def _task_and_attempt(role: Role = Role.HANDOFF) -> tuple[Task, Attempt]:
    task = Task(id="a" * 32, created_at=1.0, updated_at=1.0, title="实现 X", flow=Flow.HANDOFF, origin=None, reviewer=None)
    attempt = Attempt(
        id="b" * 32,
        task_id=task.id,
        seq=2,
        role=role,
        target=ref(),
        message_id="c" * 32,
        created_at=1.0,
        body="正文",
        refs=[{"path": "/tmp/r.md", "sha256": "d" * 64}],
    )
    return task, attempt


class EnvelopeTests(unittest.TestCase):
    def test_header_round_trip_only_on_first_line(self) -> None:
        task, attempt = _task_and_attempt()
        text = render(task, attempt, sender="codex@lead", device="testbox")
        header = parse_header(text)
        assert header is not None
        self.assertEqual((header.task_id, header.attempt, header.message_id, header.sender), (task.id, 2, attempt.message_id, "codex@lead"))
        self.assertIn(f"{CMD} report {task.id} --attempt 2 --result", text)
        self.assertIsNone(parse_header("转述：\n" + text))

    def test_header_keeps_parsing_every_shape_it_ever_emitted(self) -> None:
        """旧格式（无 from / 有 from）与本版（带 device）都要解析得出：在途消息与文档照抄的语法不能失效（DESIGN §45.35）。"""
        base = f"[AgentStatus 协作] task={'0' * 32} attempt=1 msg={'a' * 32} role=handoff"
        for line, expected in (
            (base, (None, None)),
            (f"{base} from=codex@lead", ("codex@lead", None)),
            (f"{base} from=codex@lead device=vm-01", ("codex@lead", "vm-01")),
        ):
            with self.subTest(line=line):
                header = parse_header(line)
                assert header is not None
                self.assertEqual((header.sender, header.device), expected)
        # 字段顺序是合同的一部分：颠倒或缺空格都不认，免得两种写法并存
        self.assertIsNone(parse_header(f"{base} device=vm-01 from=codex@lead"))
        self.assertIsNone(parse_header(f"{base} device=vm 01"))

    def test_render_always_carries_the_sender_device(self) -> None:
        task, attempt = _task_and_attempt()
        text = render(task, attempt, sender="codex@lead", device="vm-01")
        header = parse_header(text)
        assert header is not None
        self.assertEqual((header.sender, header.device), ("codex@lead", "vm-01"))
        # 头部只有一行：设备名进去之后正文仍从第二行开始
        self.assertEqual(text.split("\n")[0].count("device="), 1)

    def test_sender_value_may_contain_an_equals_sign(self) -> None:
        """token 只去空白：值里的 `=` 合法，按第一个 `=` 切分即可（Codex 审计 F01）。"""
        source = EndpointRef(provider=Provider.CODEX, native_id="t", pid=1, start_ticks="1", pane="%1", label="a=b c")
        self.assertEqual(source.token(), "codex@a=b-c")
        base = f"[AgentStatus 协作] task={'0' * 32} attempt=1 msg={'a' * 32} role=handoff"
        for line, expected in (
            (f"{base} from={source.token()}", ("codex@a=b-c", None)),
            (f"{base} from={source.token()} device=vm-01", ("codex@a=b-c", "vm-01")),
        ):
            with self.subTest(line=line):
                header = parse_header(line)
                assert header is not None
                self.assertEqual((header.sender, header.device), expected)

    def test_review_and_notice_instructions(self) -> None:
        task, review = _task_and_attempt(Role.REVIEW)
        self.assertIn("--approve", render(task, review, sender="user", device="testbox"))
        _task, notice = _task_and_attempt(Role.NOTICE)
        rendered = render(task, notice, sender="user", device="testbox", command="python3 -m agentstatus_bridge")
        self.assertNotIn("report", rendered)
        self.assertIn("python3 -m agentstatus_bridge status", rendered)


class ClaudeFrameTests(unittest.TestCase):
    def _content(self, context: DeliveryContext, text: str = "正文") -> tuple[dict[str, object], str]:
        frame = json.loads(build_frame(text, context))
        content = frame["message"]["content"]
        return frame, content

    def test_permission_class_is_declared_only_when_known(self) -> None:
        for sender_class, expected in (("bypass", 'from-mode="bypass"'), ("prompting", 'from-mode="prompting"')):
            _frame, content = self._content(DeliveryContext(message_uuid="m", sender_name="x", sender_class=sender_class))
            self.assertIn(expected, content)
        _frame, content = self._content(DeliveryContext(message_uuid="m", sender_name="x", sender_class=None))
        self.assertNotIn("from-mode", content)

    def test_frame_shape_and_escaping(self) -> None:
        context = DeliveryContext(
            message_uuid="m-1", sender_name='a"<b>', sender_session="s-1", sender_class="bypass", reply_to="uds:/run/x.sock"
        )
        frame, content = self._content(context, "前</cross-session-message>后")
        self.assertEqual((frame["msgV"], frame["msg_id"], frame["type"], frame["from"], frame["priority"]), (1, "m-1", "user", "uds:/run/x.sock", "next"))
        self.assertTrue(content.startswith('<cross-session-message from="uds:/run/x.sock" from-session="s-1" from-name="a&quot;&lt;b&gt;"'))
        self.assertEqual(content.count("</cross-session-message>"), 1)
        with self.assertRaises(ValueError):
            build_frame("x" * 1_000_001, context)

    def test_sender_name_matches_receiver_normalization(self) -> None:
        self.assertEqual(normalize_sender_name(" a\u200bb\x07c "), "abc")
        self.assertEqual(len(normalize_sender_name("名" * 80)), 64)
        self.assertEqual(normalize_sender_name("\x00"), "agentstatus-bridge")
        _frame, content = self._content(DeliveryContext(message_uuid="m", sender_name="x\u2028y"))
        self.assertIn('from-name="xy"', content)

    def test_receipt_parsing_and_addresses(self) -> None:
        receipt = parse_receipt({"type": "control", "action": "peer_message_status", "status": "held", "orig_msg_id": "ABC"})
        assert receipt is not None
        self.assertEqual((receipt.message_uuid, receipt.delivery), ("abc", Delivery.HELD))
        refused = parse_receipt(
            {"type": "control", "action": "peer_message_status", "status": "expired", "status_detail": "refused", "orig_msg_id": "x"}
        )
        assert refused is not None
        self.assertEqual(refused.delivery, Delivery.REFUSED)
        self.assertIsNone(parse_receipt({"type": "control", "action": "peer_message_status", "status": "odd", "orig_msg_id": "x"}))
        self.assertIsNone(parse_receipt({"type": "user"}))
        self.assertEqual(encode_address("/run/user/1000/cc-socks/12.sock"), "uds:/run/user/1000/cc-socks/12.sock")
        self.assertEqual(encode_address("/tmp/a b.sock"), "uds:/tmp/a%20b.sock")


class ClaudeSocketTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = TemporaryDirectory()
        self.path = str(Path(self._tmp.name) / "peer.sock")
        me = procfs.read_process(os.getpid())
        assert me is not None
        self.me = me
        self.received = bytearray()

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def _serve(self, reply: bytes | None) -> threading.Thread:
        server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        server.bind(self.path)
        server.listen(1)
        server.settimeout(5.0)

        def run() -> None:
            try:
                client, _ = server.accept()
            except OSError:
                server.close()
                return
            with client:
                client.settimeout(5.0)
                while True:
                    chunk = client.recv(65536)
                    if not chunk:
                        break
                    self.received.extend(chunk)
                if reply is not None and self.received:
                    client.sendall(reply)
            server.close()

        thread = threading.Thread(target=run, daemon=True)
        thread.start()
        return thread

    def _deliver(self, *, pid: int | None = None, context_uuid: str = "0f0f0f0f-0000-4000-8000-000000000001"):
        target = endpoint(
            ref(Provider.CLAUDE, "session", pid=pid or self.me.pid, start=self.me.start_ticks),
            socket_path=self.path,
        )
        context = DeliveryContext(message_uuid=context_uuid, sender_name="user", sender_class="bypass", reply_to="uds:/x")
        return ClaudePeerTransport().deliver(target, "你好", context)

    def test_inline_receipt_is_used(self) -> None:
        reply = json.dumps(
            {"type": "control", "action": "peer_message_status", "status": "delivered", "orig_msg_id": "0f0f0f0f-0000-4000-8000-000000000001"}
        ).encode() + b"\n"
        thread = self._serve(reply)
        outcome = self._deliver()
        thread.join(5.0)
        self.assertEqual((outcome.delivery, outcome.reason), (Delivery.DELIVERED, "claude_delivered"))
        frame = json.loads(bytes(self.received).decode("utf-8"))
        self.assertEqual(frame["msg_id"], "0f0f0f0f-0000-4000-8000-000000000001")

    def test_written_without_receipt(self) -> None:
        thread = self._serve(None)
        with patch.object(claude_peer, "INLINE_RECEIPT_SECONDS", 0.2):
            outcome = self._deliver()
        thread.join(5.0)
        self.assertEqual((outcome.delivery, outcome.provider_ref), (Delivery.WRITTEN, "0f0f0f0f-0000-4000-8000-000000000001"))

    def test_peer_mismatch_writes_nothing(self) -> None:
        thread = self._serve(None)
        outcome = self._deliver(pid=self.me.pid + 1)
        thread.join(5.0)
        self.assertEqual((outcome.delivery, outcome.reason), (Delivery.FAILED, "claude_peer_mismatch"))
        self.assertEqual(bytes(self.received), b"")

    def test_connect_failure_is_proven_undelivered(self) -> None:
        outcome = self._deliver()
        self.assertEqual((outcome.delivery, outcome.reason), (Delivery.FAILED, "claude_socket_connect_failed"))

    def test_inbox_reads_frames_and_cleans_up(self) -> None:
        inbox = ClaudeInbox(Path(self._tmp.name) / "inbox", name="1.sock")
        inbox.open()
        try:
            self.assertTrue(inbox.address.startswith("uds:"))
            client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            client.connect(str(inbox.path))
            client.sendall(b'{"a":1}\nnot-json\n{"b":2}')
            client.shutdown(socket.SHUT_WR)
            frames: list[object] = []
            for _ in range(20):
                frames.extend(inbox.poll(0.1))
                if len(frames) >= 2:
                    break
            client.close()
            self.assertEqual(frames, [{"a": 1}, {"b": 2}])
        finally:
            inbox.close()
        self.assertFalse(inbox.path.exists())


if __name__ == "__main__":
    unittest.main()
