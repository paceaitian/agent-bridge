"""§69 的边界测试；只用临时假 daemon，内容金丝雀不接触真实会话。"""
from __future__ import annotations

import base64
import contextlib
from dataclasses import asdict, replace
import hashlib
import io
import json
import os
from pathlib import Path
import socket
import sqlite3
from tempfile import TemporaryDirectory
import time
import unittest
from unittest.mock import patch

from bridge_support import FakeProc, ProductionSocketUse
from test_bridge_codex_rpc import FakeDaemon, THREAD, ITEM
from agentstatus_bridge import cli, codex_metadata, endpoints, procfs
from agentstatus_bridge.codex_metadata import MetadataCache, MAX_CACHED
from agentstatus_bridge.transports import codex_native, local_codex
from agentstatus_bridge.transports.codex_native import NativeBatch, ReadBatchClient, ThreadMetadata, project_thread

CANARY = "SYNTHETIC-PRIVATE-CONTENT-69"


class NativeDaemon(FakeDaemon):
    def __init__(self, root: Path, replies=None, *, version="0.162.1", before=(), init=None):
        self.replies = replies or (lambda request: {"result": {"thread": {
            "id": request["params"]["threadId"], "source": "cli", "preview": CANARY,
            "name": CANARY, "cwd": CANARY, "items": [CANARY],
        }}})
        self.version, self.before, self.init = version, before, init
        super().__init__(root)

    def _read_json(self, connection):
        try:
            opcode, payload = self._read_frame(connection)
        except ConnectionError:
            return None
        if opcode == 8:
            self.closes.append(payload)
            return None
        if opcode != 1:
            return None
        message = json.loads(payload)
        self.received.append(message)
        return message

    def _session(self, connection):
        data = bytearray()
        while b"\r\n\r\n" not in data:
            data.extend(connection.recv(4096))
        headers = dict(line.split(": ", 1) for line in data.decode().split("\r\n")[1:] if ": " in line)
        key = headers["Sec-WebSocket-Key"]
        accept = base64.b64encode(hashlib.sha1((key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode()).digest()).decode()
        connection.sendall(("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n"
                            "Connection: Upgrade\r\nSec-WebSocket-Accept: " + accept + "\r\n\r\n").encode())
        initialize = self._read_json(connection)
        if initialize is None:
            return
        self._send_json(connection, {"id": 1, "result": self.init or {
            "userAgent": f"codex-tui/{self.version} (fixture)", "codexHome": str(self.home), "extra": CANARY,
        }})
        if self._read_json(connection) is None:
            return
        while (request := self._read_json(connection)) is not None:
            for notice in self.before:
                self._send_json(connection, notice)
            response = self.replies(request)
            if response is None:
                self._drain(connection)
                return
            self._send_json(connection, {"id": request["id"], **response})
        self._drain(connection)


class NativeTests(unittest.TestCase):
    def setUp(self):
        self.temp = TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def daemon(self, **options):
        daemon = NativeDaemon(self.root, **options)
        self.addCleanup(daemon.close)
        return daemon

    def read(self, daemon, ids=(THREAD,), *, peers=None, version="0.162.1"):
        output = io.StringIO()
        with contextlib.redirect_stdout(output), contextlib.redirect_stderr(output):
            result = ReadBatchClient(lambda _: version).read(
                daemon.home, ids, peers or {item: {os.getpid()} for item in ids})
        self.assertNotIn(CANARY, output.getvalue())
        return result

    def test_read_whitelist_initialize_order_and_projection(self):
        daemon = self.daemon(before=({"method": "new/unknown", "params": {"text": CANARY}},))
        result = self.read(daemon)
        self.assertEqual(result.records, {THREAD: ThreadMetadata("root")})
        self.assertEqual(daemon.methods(), ["initialize", "initialized", "thread/read"])
        self.assertEqual(daemon.received[2]["params"], {"threadId": THREAD, "includeTurns": False})
        self.assertFalse(daemon.received[0]["params"]["capabilities"]["experimentalApi"])
        self.assertEqual(daemon.received[0]["params"]["clientInfo"]["name"], "codex-tui")
        self.assertNotIn(CANARY, json.dumps(asdict(result)))
        daemon.thread.join(1)
        self.assertEqual(daemon.closes, [b"\x03\xe8"])

    def test_server_request_discards_batch_and_does_not_answer(self):
        daemon = self.daemon(before=({"id": 88, "method": "item/permissions/requestApproval", "params": CANARY},))
        result = self.read(daemon)
        self.assertEqual(result.reason, "server_request_seen")
        self.assertEqual(result.records, {})
        daemon.thread.join(1)
        self.assertEqual(daemon.methods(), ["initialize", "initialized", "thread/read"])
        self.assertNotIn(CANARY, repr(result))

    def test_server_version_not_cli_version_is_gate(self):
        daemon = self.daemon(version="0.163.0")
        result = self.read(daemon)
        self.assertEqual(result.reason, "version_unverified")
        self.assertEqual(daemon.methods(), ["initialize"])

    def test_each_requested_id_must_belong_to_socket_peer(self):
        daemon = self.daemon()
        result = self.read(daemon, (THREAD, ITEM.lower()), peers={THREAD: {os.getpid()}, ITEM.lower(): {987654}})
        self.assertEqual(set(result.records), {THREAD})
        self.assertEqual(len(daemon.received), 3)

    def test_home_and_response_identity_fail_closed(self):
        for response in ({"id": True, "result": {}}, {"id": 99, "result": {}},
                         {"result": {}, "error": {"message": CANARY}},
                         {"result": {"thread": {"id": ITEM, "source": "cli"}}}):
            with self.subTest(response=response), TemporaryDirectory() as tmp:
                daemon = NativeDaemon(Path(tmp), replies=lambda _: response)
                try:
                    result = self.read(daemon)
                    self.assertNotEqual(result.reason, "ok")
                    self.assertEqual(result.records, {})
                    self.assertNotIn(CANARY, repr(result))
                finally:
                    daemon.close()
        daemon = self.daemon(init={"userAgent": "codex-tui/0.162.1", "codexHome": str(self.root / "other")})
        self.assertEqual(self.read(daemon).reason, "home_mismatch")

    def test_deadline_disconnect_and_large_message(self):
        daemon = self.daemon(replies=lambda _: None)
        started = time.monotonic()
        with patch.object(codex_native, "READ_SECONDS", 0.15):
            result = self.read(daemon)
        daemon.thread.join(1)
        self.assertEqual(result.reason, "deadline")
        self.assertLess(time.monotonic() - started, 0.8)
        self.assertIsNotNone(daemon.ended_at)

    def test_33_requests_have_a_32_id_ceiling(self):
        daemon = self.daemon()
        ids = [f"00000000-0000-4000-8000-{number:012x}" for number in range(33)]
        result = self.read(daemon, ids)
        self.assertEqual(len(result.records), 32)
        self.assertEqual(len(daemon.received), 34)

    def test_empty_batch_does_not_touch_socket_or_version(self):
        with patch.object(local_codex.LinuxPlatform, "resolve", side_effect=AssertionError("no candidate")):
            self.assertEqual(ReadBatchClient(lambda _: self.fail("version queried")).read(self.root, [], {}), NativeBatch())
            self.assertEqual(MetadataCache().read(self.root, {}), NativeBatch())

    def test_cli_discoveries_share_one_batch_even_after_expiry(self):
        now = [0.0]
        holders = {THREAD: ((os.getpid(), "1"),)}
        calls = []
        def reader(home, ids, peers):
            calls.append(tuple(ids))
            return NativeBatch({THREAD: ThreadMetadata("root")}, "ok")
        def command(_args):
            one, two = endpoints.DiscoverySources(), endpoints.DiscoverySources()
            self.assertIs(one.native_metadata, two.native_metadata)
            one.native_metadata.clock = lambda: now[0]
            self.assertEqual(one.native_metadata.read(self.root, holders).records[THREAD].kind, "root")
            now[0] += 7
            self.assertEqual(two.native_metadata.read(self.root, holders).records, {})
            return 0
        with (patch.object(ReadBatchClient, "read", side_effect=reader), patch.object(cli, "cmd_peers", side_effect=command),
              patch.object(cli, "_refresh_summary")):
            self.assertEqual(cli.main(["peers"]), 0)
            self.assertEqual(len(calls), 1)
            self.assertEqual(cli.main(["peers"]), 0)
            self.assertEqual(len(calls), 2)
        self.assertIsNone(codex_metadata._COMMAND_CACHE.get())

    def test_receive_budget_and_frame_bound(self):
        for notices in (({"method": "new/event", "params": CANARY * 50_000},),
                        tuple({"method": "new/event", "params": "x" * 500_000} for _ in range(10))):
            with self.subTest(size=len(notices)), TemporaryDirectory() as tmp:
                daemon = NativeDaemon(Path(tmp), before=notices)
                try:
                    result = self.read(daemon)
                    self.assertEqual(result.reason, "transport_error")
                    self.assertEqual(result.records, {})
                finally:
                    daemon.close()

    def test_daemon_epoch_change_drops_the_batch(self):
        daemon = self.daemon()
        def replace_link(_):
            daemon.link.unlink()
            daemon.link.symlink_to(self.root / "absent.sock")
            return {"result": {"thread": {"id": THREAD, "source": "cli"}}}
        daemon.replies = replace_link
        self.assertEqual(self.read(daemon).reason, "daemon_changed")

    def test_production_guard_escapes_new_reader(self):
        target = Path(f"/tmp/codex-daemon-{os.getuid()}/agentstatus-guard-probe-does-not-exist")
        with patch.object(local_codex.LinuxPlatform, "resolve", return_value=target), self.assertRaises(ProductionSocketUse):
            self.read(type("Fixture", (), {"home": self.root})())

    def test_source_truth_table_and_conflicts(self):
        vectors = [
            ("cli", "root"), ("appServer", "root"), ({"custom": CANARY}, "root"),
            ("unknown", "unknown"), ({"internal": "guardian"}, "unknown"),
            ({"subagent": "review"}, "unknown"), ({"custom": 3}, "unknown"),
            ({"subAgent": "review"}, "subagent"), ({"subAgent": {"other": CANARY}}, "subagent"),
            ({"subAgent": {"thread_spawn": {"parent_thread_id": ITEM, "depth": 1}}}, "subagent"),
            ({"subAgent": {"thread_spawn": {"parent_thread_id": THREAD, "depth": 1}}}, "conflict"),
        ]
        for source, kind in vectors:
            with self.subTest(source=source):
                value = project_thread({"id": THREAD, "source": source, "sessionId": ITEM}, THREAD)
                self.assertEqual(value.kind, kind)
                self.assertNotIn(CANARY, repr(value))
        self.assertEqual(project_thread({"id": THREAD, "source": "cli", "parentThreadId": ITEM}, THREAD).kind, "conflict")
        value = {"id": THREAD, "source": {"subAgent": {"thread_spawn": {"parent_thread_id": ITEM, "depth": 1}}},
                 "parentThreadId": "00000000-0000-4000-8000-000000000000"}
        self.assertEqual(project_thread(value, THREAD).kind, "conflict")

    def test_cache_expiry_rotation_holdings_and_size(self):
        now = [0.0]
        calls = []
        def read(home, ids, peers):
            calls.append(set(ids))
            return NativeBatch({key: ThreadMetadata("root") for key in ids}, "ok", "0.162.1")
        reader = ReadBatchClient(lambda _: "0.162.1")
        with patch.object(reader, "read", side_effect=read):
            cache = MetadataCache(reader, clock=lambda: now[0])
            holders = {f"00000000-0000-4000-8000-{number:012x}": ((1, "1"),) for number in range(257)}
            for _ in range(12):
                self.assertLessEqual(len(cache.read(self.root, holders).records), MAX_CACHED)
            self.assertEqual(len(set().union(*calls)), 257)
            one = {THREAD: ((1, "1"),)}
            cache.read(self.root, one)
            count = len(calls)
            cache.read(self.root, one)
            self.assertEqual(len(calls), count)
            now[0] = 6.0
            cache.read(self.root, one)
            self.assertEqual(len(calls), count + 1)
            self.assertEqual(cache.read(self.root, {}).records, {})

    def test_native_sql_partial_and_lost_holder(self):
        home = self.root / "codex"
        home.mkdir()
        proc = FakeProc(self.root / "proc")
        proc.add(20, comm="codex", argv=("codex", "app-server"), fds=(
            str(home / "thread-writer-locks" / f"{THREAD}.lock"),
            str(home / "thread-writer-locks" / f"{ITEM.lower()}.lock"),
        ))
        sources = endpoints.DiscoverySources(proc_root=proc.root, codex_home=home, codex_sqlite_home=home)
        with sqlite3.connect(home / "state_1.sqlite") as db:
            db.execute("CREATE TABLE threads(id TEXT, source TEXT)")
            db.executemany("INSERT INTO threads VALUES (?, ?)", ((THREAD, "cli"), (ITEM.lower(), "unknown")))
        processes = endpoints.scan_codex_holdings(proc.root, home)
        reader = sources.native_metadata.reader
        with patch.object(reader, "read", return_value=NativeBatch({THREAD: ThreadMetadata("subagent", ITEM.lower())}, "ok")):
            result = endpoints._classify_codex_threads(sources, {THREAD, ITEM.lower()}, processes)
            partial = endpoints._classify_codex_threads(replace(sources, codex_sqlite_home=self.root / "missing"),
                                                        {THREAD, ITEM.lower()}, processes)
            self.assertTrue(partial.unavailable)  # native部分成功不能洗掉SQL不可用
        self.assertEqual(result.kinds, {THREAD: "subagent", ITEM.lower(): "root"})
        self.assertEqual(sources.native_report["sqlFallback"], 1)
        with patch.object(procfs, "read_process", return_value=None):
            lost = endpoints._classify_codex_threads(sources, {THREAD}, processes)
        self.assertEqual(lost.kinds[THREAD], "root")  # 丢失持有的native子代理证据未被复用

    def test_conflict_does_not_fallback_and_sql_not_queried_is_explicit(self):
        home = self.root / "codex"
        proc = FakeProc(self.root / "proc")
        proc.add(20, comm="codex", argv=("codex", "app-server"), fds=(str(home / "thread-writer-locks" / f"{THREAD}.lock"),))
        sources = endpoints.DiscoverySources(proc_root=proc.root, codex_home=home, codex_sqlite_home=home)
        with patch.object(sources.native_metadata.reader, "read", return_value=NativeBatch({THREAD: ThreadMetadata("conflict")}, "ok")):
            result = endpoints._classify_codex_threads(sources, {THREAD}, endpoints.scan_codex_holdings(proc.root, home))
        self.assertEqual(result.kinds, {THREAD: "subagent"})
        self.assertIsNone(endpoints._codex_title_root(THREAD, {THREAD}, result))
        self.assertEqual(sources.native_report["sqlState"], "not_queried")


if __name__ == "__main__":
    unittest.main()
