"""§69 的边界测试；只用临时假 daemon，内容金丝雀不接触真实会话。"""
from __future__ import annotations
from agentstatus_bridge.platforms.linux import local_transport as linux_transport

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
from agentstatus_bridge import cli, codex_metadata, doctor, endpoints
from agentstatus_bridge.platforms.linux import process as procfs
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
        self._send_json(connection, {"id": 1, "result": self.init if self.init is not None else {
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

    def test_server_version_is_recorded_without_membership_gate(self):
        for version in ("0.162.1", "0.163.0", "99.99.99", "not-a-version"):
            with self.subTest(version=version), TemporaryDirectory() as tmp:
                daemon = NativeDaemon(Path(tmp), version=version)
                try:
                    result = self.read(daemon)
                    expected = version if version != "not-a-version" else "unknown"
                    self.assertEqual(result, NativeBatch({THREAD: ThreadMetadata("root")}, "ok", expected))
                    self.assertEqual(daemon.methods(), ["initialize", "initialized", "thread/read"])
                    self.assertEqual(daemon.received[0]["params"]["clientInfo"]["version"], "0.162.1")
                    self.assertEqual(daemon.received[2]["params"], {"threadId": THREAD, "includeTurns": False})
                finally:
                    daemon.close()

    def test_missing_server_version_is_unknown_but_initialize_shape_is_required(self):
        for init, reason in (({"codexHome": str(self.root / "codex")}, "ok"),
                             (["invalid"], "initialize_failed"), (False, "initialize_failed"),
                             ({}, "home_mismatch")):
            with self.subTest(init=init), TemporaryDirectory() as tmp:
                if reason == "ok":
                    init = {"codexHome": str(Path(tmp) / "codex")}
                daemon = NativeDaemon(Path(tmp), init=init)
                try:
                    result = self.read(daemon)
                    self.assertEqual(result.reason, reason)
                    self.assertEqual(result.server_version, "unknown")
                    self.assertEqual(result.records, {THREAD: ThreadMetadata("root")} if reason == "ok" else {})
                    self.assertEqual(daemon.methods(), ["initialize", "initialized", "thread/read"]
                                     if reason == "ok" else ["initialize"])
                finally:
                    daemon.close()

    def test_cli_version_unknown_initializes_and_reads(self):
        daemon = self.daemon()
        self.assertEqual(self.read(daemon, version=None),
                         NativeBatch({THREAD: ThreadMetadata("root")}, "ok", "0.162.1"))
        self.assertEqual(daemon.received[0]["params"]["clientInfo"]["version"], "unknown")
        self.assertEqual(daemon.methods(), ["initialize", "initialized", "thread/read"])

    def test_new_server_native_report_and_doctor_are_ok(self):
        daemon = self.daemon(version="0.163.0")
        proc = FakeProc(self.root / "proc")
        proc.add(os.getpid(), comm="codex", argv=("codex", "app-server"),
                 fds=(str(daemon.home / "thread-writer-locks" / f"{THREAD}.lock"),))
        sources = endpoints.DiscoverySources(proc_root=proc.root, codex_home=daemon.home,
            codex_sqlite_home=daemon.home, panes=lambda: {}, titles=lambda: {},
            native_metadata=MetadataCache(ReadBatchClient(lambda _: "0.162.1")))
        report = endpoints.codex_title_report(sources)
        self.assertEqual(report["nativeMetadata"], sources.native_report)
        self.assertEqual(sources.native_report["state"], "ok")
        self.assertEqual(sources.native_report["serverVersion"], "0.163.0")
        self.assertEqual(sources.native_report["confirmed"], 1)
        self.assertEqual(sources.native_report["sqlFallback"], 0)
        self.assertEqual(sources.native_report["sqlState"], "unavailable")
        lines = doctor.thread_title_lines(report)
        self.assertTrue(any(line.startswith("Codex 原生元数据：ok；确认 1") for line in lines))
        self.assertNotIn("version_unverified", repr(report) + repr(lines))
        self.assertNotIn(CANARY, repr(report) + repr(lines))

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
        with patch.object(linux_transport.LinuxPlatform, "resolve", side_effect=AssertionError("no candidate")):
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
        with patch.object(linux_transport.LinuxPlatform, "resolve", return_value=target), self.assertRaises(ProductionSocketUse):
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
        self.assertEqual(result.kinds, {THREAD: "root", ITEM.lower(): "root"})
        self.assertEqual(sources.native_report["state"], "no_candidates")
        self.assertEqual((sources.native_report["sqlAnswered"], sources.native_report["sqlFallback"]), (2, 0))
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
        self.assertEqual(sources.native_report["sqlState"], "unavailable")  # §73 先查SQL，失败不能被native洗掉

    def test_sql_complete_does_not_initialize_native(self):
        home = self.root / "codex"
        home.mkdir()
        parent = ITEM.lower()
        with sqlite3.connect(home / "state_1.sqlite") as db:
            db.execute("CREATE TABLE threads(id TEXT, source TEXT)")
            db.executemany("INSERT INTO threads VALUES (?, ?)", ((parent, "cli"),
                (THREAD, json.dumps({"subagent": {"thread_spawn": {"parent_thread_id": parent}}}))))
        proc = FakeProc(self.root / "proc")
        proc.add(20, comm="codex", argv=("codex", "app-server"), fds=tuple(
            str(home / "thread-writer-locks" / f"{thread}.lock") for thread in (THREAD, parent)))
        sources = endpoints.DiscoverySources(proc_root=proc.root, codex_home=home)
        with patch.object(sources.native_metadata.reader, "read") as read:
            classes = endpoints._classify_codex_threads(sources, {THREAD, parent}, endpoints.scan_codex_holdings(proc.root, home))
        read.assert_not_called()
        self.assertEqual(classes.kinds, {THREAD: "subagent", parent: "root"})
        self.assertEqual(endpoints._codex_title_root(THREAD, {THREAD, parent}, classes), parent)
        self.assertEqual(sources.native_report["sqlState"], "available")

    def test_missing_row_and_review_parent_are_supplemented_and_holdings_memoized(self):
        home = self.root / "codex"
        home.mkdir()
        child = "019affff-0000-7000-8000-000000000001"
        parent = ITEM.lower()
        with sqlite3.connect(home / "state_1.sqlite") as db:
            db.execute("CREATE TABLE threads(id TEXT, source TEXT)")
            db.executemany("INSERT INTO threads VALUES (?, ?)", ((parent, "cli"), (THREAD, '{"subagent":"review"}')))
        proc = FakeProc(self.root / "proc")
        ids = {THREAD, child, parent}
        proc.add(20, comm="codex", argv=("codex", "app-server"), fds=tuple(
            str(home / "thread-writer-locks" / f"{thread}.lock") for thread in ids))
        sources = endpoints.DiscoverySources(proc_root=proc.root, codex_home=home)
        processes = endpoints.scan_codex_holdings(proc.root, home)
        batch = NativeBatch({THREAD: ThreadMetadata("subagent", parent), child: ThreadMetadata("subagent", parent)}, "ok")
        with patch.object(sources.native_metadata.reader, "read", return_value=batch) as read, \
                patch.object(endpoints, "codex_holdings", wraps=endpoints.codex_holdings) as holdings:
            classes = endpoints._classify_codex_threads(sources, ids, processes, {THREAD})
        self.assertEqual(read.call_args.args[1], [THREAD, child])
        self.assertEqual(holdings.call_count, 1, "网络后每pid一次，而不是每记录一次")
        for thread in (THREAD, child):
            self.assertEqual(endpoints._codex_title_root(thread, ids, classes), parent)

    def test_internal_and_memory_sources_never_initialize(self):
        home = self.root / "codex"
        home.mkdir()
        variants = [{"internal": "guardian"}, {"internal": "memory_consolidation"},
                    {"subagent": "memory_consolidation"}]
        ids = [f"019a0000-0000-7000-8000-{i:012x}" for i in range(1, 4)]
        with sqlite3.connect(home / "state_1.sqlite") as db:
            db.execute("CREATE TABLE threads(id TEXT, source TEXT)")
            db.executemany("INSERT INTO threads VALUES (?, ?)", [(key, json.dumps(source)) for key, source in zip(ids, variants)])
        proc = FakeProc(self.root / "proc")
        proc.add(20, comm="codex", argv=("codex", "app-server"), fds=tuple(
            str(home / "thread-writer-locks" / f"{key}.lock") for key in ids))
        for _ in range(2):  # 两条独立命令不能每次重连
            sources = endpoints.DiscoverySources(proc_root=proc.root, codex_home=home)
            with patch.object(sources.native_metadata.reader, "read") as read:
                classes = endpoints._classify_codex_threads(sources, set(ids), endpoints.scan_codex_holdings(proc.root, home))
            read.assert_not_called()
            self.assertEqual(classes.kinds, {key: "subagent" for key in ids})
            self.assertEqual(classes.parents, {})
            self.assertEqual(classes.parent_not_needed, frozenset(ids))
            self.assertEqual(sources.native_report["sqlAnswered"], 3)
            self.assertEqual(sources.native_report["sqlFallback"], 0)

    def test_unknown_internal_variant_remains_a_native_candidate(self):
        """§73.7：只有 0.162.1 已知的两个 Internal 变体免补查；将来的新变体（含带字段、不可哈希的形态）照常交给 native、不抛异常。"""
        variants = ['{"internal":"future_variant"}', json.dumps({"internal": {"guardian": {"parent_thread_id": ITEM.lower()}}}),
                    '{"internal":["guardian"]}']
        for index, source in enumerate(variants):
            with self.subTest(source=source):
                home = self.root / f"codex-{index}"
                home.mkdir()
                with sqlite3.connect(home / "state_1.sqlite") as db:
                    db.execute("CREATE TABLE threads(id TEXT, source TEXT)")
                    db.execute("INSERT INTO threads VALUES (?, ?)", (THREAD, source))
                proc = FakeProc(self.root / f"proc-{index}")
                proc.add(20, comm="codex", argv=("codex", "app-server"), fds=(str(home / "thread-writer-locks" / f"{THREAD}.lock"),))
                sources = endpoints.DiscoverySources(proc_root=proc.root, codex_home=home)
                with patch.object(sources.native_metadata.reader, "read", return_value=NativeBatch(reason="deadline")) as read:
                    try:
                        classes = endpoints._classify_codex_threads(sources, {THREAD}, endpoints.scan_codex_holdings(proc.root, home))
                    except TypeError as error:  # 复审 P2-1：曾让整个 discover 崩溃
                        self.fail(f"带字段的 internal 变体不能让分类抛异常：{error}")
                read.assert_called_once()
                self.assertEqual(read.call_args.args[1], [THREAD])
                self.assertNotIn(THREAD, classes.parent_not_needed)

    def test_compact_parent_and_missing_child_remain_native_candidates(self):
        home = self.root / "codex"
        home.mkdir()
        parent = ITEM.lower()
        with sqlite3.connect(home / "state_1.sqlite") as db:
            db.execute("CREATE TABLE threads(id TEXT, source TEXT)")
            db.executemany("INSERT INTO threads VALUES (?, ?)", [(parent, "cli"), (THREAD, '{"subagent":"compact"}')])
        proc = FakeProc(self.root / "proc")
        proc.add(20, comm="codex", argv=("codex", "app-server"), fds=(str(home / "thread-writer-locks" / f"{THREAD}.lock"),))
        sources = endpoints.DiscoverySources(proc_root=proc.root, codex_home=home)
        with patch.object(sources.native_metadata.reader, "read", return_value=NativeBatch({THREAD: ThreadMetadata("subagent", parent)}, "ok")) as read:
            classes = endpoints._classify_codex_threads(sources, {THREAD, parent}, endpoints.scan_codex_holdings(proc.root, home))
        read.assert_called_once()
        self.assertEqual(read.call_args.args[1], [THREAD])
        self.assertEqual(classes.parents[THREAD], parent)
        self.assertEqual(sources.native_report["sqlAnswered"], 1)
        self.assertEqual(sources.native_report["sqlFallback"], 0)

    def test_sql_fallback_counts_only_selected_or_cached_unconfirmed_ids(self):
        home = self.root / "codex"
        proc = FakeProc(self.root / "proc")
        ids = {f"019a0000-0000-7000-8000-{i:012x}" for i in range(40)}
        proc.add(20, comm="codex", argv=("codex", "app-server"), fds=tuple(
            str(home / "thread-writer-locks" / f"{key}.lock") for key in ids))
        clock = [0.0]
        cache = MetadataCache(clock=lambda: clock[0], single_batch=True)
        sources = endpoints.DiscoverySources(proc_root=proc.root, codex_home=home, native_metadata=cache)
        selected = sorted(ids, reverse=True)[:32]
        batch = NativeBatch({key: ThreadMetadata("unknown") for key in selected}, "ok")
        with patch.object(cache.reader, "read", return_value=batch) as read:
            processes = endpoints.scan_codex_holdings(proc.root, home)
            for expected_calls in (1, 1):
                endpoints._classify_codex_threads(sources, ids, processes)
                self.assertEqual(read.call_count, expected_calls)
                self.assertEqual(sources.native_report["sqlAnswered"], 0)
                self.assertEqual(sources.native_report["sqlFallback"], 32, "未查的8项不算回退")
            clock[0] = 6.0
            endpoints._classify_codex_threads(sources, ids, processes)
            self.assertEqual(sources.native_report["sqlFallback"], 0, "过期缓存/命令批次耗尽不是本轮native尝试")
            endpoints._classify_codex_threads(sources, ids, {})
            self.assertEqual(sources.native_report["sqlFallback"], 0)

    def test_attempted_resets_when_no_holders_follow_an_attempt(self):
        """§73.7（复审 D4）：无 holder 的提前返回也清掉上一轮尝试集，sqlFallback 不沿用旧轮。"""
        key = "019a0000-0000-7000-8000-000000000001"
        cache = MetadataCache(clock=lambda: 0.0)
        with patch.object(cache.reader, "read", return_value=NativeBatch(reason="deadline")):
            cache.read(self.root, {key: ((1, "1"),)})
        self.assertEqual(cache.attempted, frozenset({key}))
        cache.read(self.root, {})
        self.assertEqual(cache.attempted, frozenset())

    def test_cli_priority_and_reader_preserves_selected_order(self):
        ids = [f"019a0000-0000-7000-8000-{i:012x}" for i in range(40)]
        selected = [ids[0], ids[1], *reversed(ids[2:])][:32]
        reader = ReadBatchClient(lambda _: "0.162.1")
        with patch.object(reader, "read", return_value=NativeBatch(reason="deadline")) as read:
            cache = MetadataCache(reader, single_batch=True)
            cache.read(self.root, {key: ((1, "1"),) for key in ids}, preferred=[ids[0]], absent=[ids[1]])
        self.assertEqual(read.call_args.args[1], selected)
        daemon = self.daemon()
        result = self.read(daemon, ids=selected + ids)
        self.assertEqual(result.reason, "ok")
        self.assertEqual([m["params"]["threadId"] for m in daemon.received if m.get("method") == "thread/read"], selected)

    def test_peer_not_holder_preserves_positive_cache_and_negative_expires(self):
        reader = ReadBatchClient(lambda _: "0.162.1")
        now = [0.0]
        cache = MetadataCache(reader, clock=lambda: now[0])
        first, second = THREAD, ITEM.lower()
        with patch.object(reader, "read", side_effect=[
            NativeBatch({first: ThreadMetadata("root")}, "ok"),
            NativeBatch(reason="peer_not_holder", not_held=(second,)),
            NativeBatch({second: ThreadMetadata("root")}, "ok"),
        ]) as read:
            cache.read(self.root, {first: ((1, "1"),)})
            holders = {first: ((1, "1"),), second: ((2, "1"),)}
            result = cache.read(self.root, holders)
            self.assertEqual(result.records, {first: ThreadMetadata("root")})
            cache.read(self.root, holders)
            self.assertEqual(read.call_count, 2)
            now[0] = 6.1
            cache.read(self.root, holders)
            self.assertEqual(read.call_count, 3)

    def test_reader_reports_non_peer_ids_in_mixed_batch(self):
        daemon = self.daemon()
        result = self.read(daemon, ids=[THREAD, ITEM.lower()], peers={THREAD: {os.getpid()}, ITEM.lower(): {-1}})
        self.assertEqual(result.not_held, (ITEM.lower(),))
        self.assertEqual(result.records, {THREAD: ThreadMetadata("root")})
        self.assertEqual(daemon.methods(), ["initialize", "initialized", "thread/read"])

    def test_real_batch_failure_invalidates_cached_positive_evidence(self):
        reader = ReadBatchClient(lambda _: "0.162.1")
        cache = MetadataCache(reader)
        with patch.object(reader, "read", side_effect=[NativeBatch({THREAD: ThreadMetadata("root")}, "ok"),
                                                      NativeBatch(reason="server_request_seen")]):
            cache.read(self.root, {THREAD: ((1, "1"),)})
            result = cache.read(self.root, {THREAD: ((1, "1"),), ITEM.lower(): ((1, "1"),)})
        self.assertEqual(result.records, {})
        self.assertEqual(result.reason, "server_request_seen")


if __name__ == "__main__":
    unittest.main()
