"""DESIGN §90：relay 运行事实（只读锁探测、顶层 relayRunning、status/relay 不补摘要）与 Windows 诊断三键。

只读合同从 `cli.main` 整条调用验证：缺根/锁不创建，主账本连接 0、摘要写入 0、不修 ACL；主库被另一进程持写锁时
status 仍在 1 秒内返回。Windows 分支用 SDK Fake 内核：只读打开既有锁、拒绝访问=未知、不调用任何 ACL 修复。
"""

from __future__ import annotations

import importlib.metadata
import json
import os
import signal
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from contextlib import redirect_stderr, redirect_stdout
from dataclasses import replace
from io import StringIO
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import patch

import bridge_support  # noqa: F401  导入即隔离宿主会话环境
from bridge_winapi import Kernel

from agentstatus_bridge import cli
from agentstatus_bridge.federation import commands as fed_commands
from agentstatus_bridge.federation import config as fed_config
from agentstatus_bridge.federation import mirror, relay_control, retention
from agentstatus_bridge.federation.codec import REQUIRED_CAPABILITIES, encode_frame
from agentstatus_bridge.federation.fedstore import FED_DB_NAME, RELAY_DIAGNOSTIC_KEYS, FederatedStore
from agentstatus_bridge.federation.relay import HubConnection, Relay, RelayPaths, RelayStop, SubprocessTransport
from agentstatus_bridge.federation.relay_control import (RelayDiagnostics, StopController, config_disabled,
                                                          install_sigterm)
from agentstatus_bridge.platforms.factory import get_platform, make_platform, using_platform
from agentstatus_bridge.platforms.windows import anchor as windows_anchor
from agentstatus_bridge.store import DB_NAME, Store, StoreError

HUB = "c" * 32
DEV = "a" * 32
ADMIN = bytes.fromhex("01020000000000052000000020020000")


def enable(root: Path) -> None:
    fed_commands.enable(root, hub_host="hub.example", hub_user="ab-relay", hub_port=22, hub_id=HUB, device_id=DEV,
                        name="vm", identity_file="/nonexistent/relay_key", known_hosts_file="/nonexistent/known_hosts",
                        ssh_executable="ssh")


def tree(root: Path) -> dict[str, tuple[int, int]]:
    """目录清单：相对路径 → (大小, mtime_ns)；用来断言只读命令没有新建或改写文件。"""
    if not root.exists():
        return {}
    return {str(path.relative_to(root)): (path.stat().st_size, path.stat().st_mtime_ns)
            for path in sorted(root.rglob("*"))}


class HeldLock:
    """测试内持有 relay 单例锁（排他），模拟一个正在运行的 relay。"""

    def __init__(self, root: Path) -> None:
        self.lifecycle = get_platform().lifecycle
        self.fd = self.lifecycle.open_lock(root / fed_commands.RELAY_LOCK)
        self.lifecycle.try_lock(self.fd)

    def release(self) -> None:
        self.lifecycle.unlock(self.fd)
        self.lifecycle.close_lock(self.fd)


class LinuxProbeTests(unittest.TestCase):
    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.base = Path(tmp.name)

    def open_fds(self) -> int:
        return len(os.listdir("/proc/self/fd"))

    def test_missing_root_or_lock_is_false_and_nothing_is_created(self) -> None:
        absent = self.base / "absent"
        self.assertIs(fed_commands.relay_running(absent), False)
        self.assertFalse(absent.exists())
        root = self.base / "state"
        root.mkdir()
        self.assertIs(fed_commands.relay_running(root), False)
        self.assertEqual(list(root.iterdir()), [])

    def test_busy_free_and_handle_closed(self) -> None:
        before = self.open_fds()
        held = HeldLock(self.base)
        try:
            self.assertIs(fed_commands.relay_running(self.base), True)
        finally:
            held.release()
        self.assertIs(fed_commands.relay_running(self.base), False)
        self.assertEqual(self.open_fds(), before)

    def test_probe_opens_read_only(self) -> None:
        lock = self.base / fed_commands.RELAY_LOCK
        lock.touch()
        lock.chmod(0o400)  # 只读文件：可写打开会失败，只读打开照常探测
        if os.geteuid() == 0:
            self.skipTest("root 不受文件权限限制")
        self.assertIs(fed_commands.relay_running(self.base), False)
        self.assertEqual(lock.stat().st_mode & 0o777, 0o400)

    def test_non_regular_lock_is_unknown_and_never_blocks(self) -> None:
        # Codex AS90-I-C-P3-01：目录也能 flock（会被误判 false），没有写方的 FIFO 会让只读 open 阻塞
        lock = self.base / fed_commands.RELAY_LOCK
        lock.mkdir()
        self.assertIsNone(fed_commands.relay_running(self.base))
        lock.rmdir()
        os.mkfifo(lock, 0o600)
        results: list[Any] = []
        prober = threading.Thread(target=lambda: results.append(fed_commands.relay_running(self.base)), daemon=True)
        prober.start()
        prober.join(2.0)
        if prober.is_alive():  # 失败时放开阻塞的读方，免得线程挂到进程结束
            os.close(os.open(lock, os.O_WRONLY | os.O_NONBLOCK))
        self.assertFalse(prober.is_alive(), "探锁阻塞在 FIFO 上")
        self.assertEqual(results, [None])
        lock.unlink()
        lock.touch()
        os.link(lock, self.base / "second-name")
        self.assertIsNone(fed_commands.relay_running(self.base))  # 多链接的锁文件不可信

    def test_access_denied_or_bad_root_is_unknown(self) -> None:
        if os.geteuid() == 0:
            self.skipTest("root 不受文件权限限制")
        lock = self.base / fed_commands.RELAY_LOCK
        lock.touch()
        lock.chmod(0)
        self.addCleanup(lock.chmod, 0o600)
        self.assertIsNone(fed_commands.relay_running(self.base))
        not_dir = self.base / "file"
        not_dir.write_text("x")
        self.assertIsNone(fed_commands.relay_running(not_dir))


class WindowsProbeTests(unittest.TestCase):
    """Fake 内核：只读打开既有锁（OPEN_EXISTING、无写/WRITE_DAC/WRITE_OWNER）、不建目录、不修 ACL。"""

    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.state = self.root / "state"
        self.state.mkdir()
        self.k = Kernel(self.root)
        self.p = make_platform("windows", win_api=self.k.api)
        self.enterContext(using_platform(self.p))
        self.addCleanup(lambda: self.assertEqual(self.k.handles, {}))

    def probe(self, root: Path) -> bool | None:
        start = len(self.k.calls)
        result = fed_commands.relay_running(root)
        calls = self.k.calls[start:]
        names = {name for name, _ in calls}
        self.assertFalse(names & {"CreateDirectoryW", "SetSecurityInfo", "SetNamedSecurityInfoW", "SetFileSecurityW",
                                  "DeleteFileW", "MoveFileExW"}, names)
        for name, args in calls:
            if name == "CreateFileW":
                access, disposition = args[1], args[4]
                self.assertEqual(disposition, 3)  # OPEN_EXISTING
                self.assertEqual(access & (0x40000000 | 0x40000 | 0x80000 | 0x2 | 0x10000), 0, hex(access))
        return result

    def test_missing_lock_or_root_is_false(self) -> None:
        self.assertIs(self.probe(self.state), False)
        self.assertIs(self.probe(self.root / "absent"), False)
        self.assertFalse((self.root / "absent").exists())
        self.assertEqual(list(self.state.iterdir()), [])

    def test_busy_free_and_foreign_owner_not_repaired(self) -> None:
        held = HeldLock(self.state)
        try:
            self.assertIs(self.probe(self.state), True)
        finally:
            held.release()
        lock = str(self.state / fed_commands.RELAY_LOCK)
        self.k.files[lock] = {"owner": ADMIN}
        self.assertIs(self.probe(self.state), False)
        self.assertEqual(self.k.files[lock]["owner"], ADMIN)  # status 只观察，不修属主

    def test_access_denied_is_unknown(self) -> None:
        (self.state / fed_commands.RELAY_LOCK).touch()
        self.k.faults["CreateFileW"] = 5
        try:
            self.assertIsNone(self.probe(self.state))
        finally:
            del self.k.faults["CreateFileW"]
        self.k.faults["LockFileEx"] = 6
        try:
            self.assertIsNone(self.probe(self.state))
        finally:
            del self.k.faults["LockFileEx"]


class StatusCliTests(unittest.TestCase):
    """`ab federation status` 经 cli.main：顶层 relayRunning 各分支、只读、不补摘要、主库争用不拖住。"""

    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.base = Path(tmp.name)
        self.state = self.base / "state"
        self.state.mkdir(mode=0o700)
        self.enterContext(patch.dict(os.environ, {"AB_STATE_DIR": str(self.state)}))

    def run_cli(self, *argv: str, state: Path | None = None) -> tuple[int, str, str]:
        out, err = StringIO(), StringIO()
        with patch.dict(os.environ, {"AB_STATE_DIR": str(state or self.state)}), \
                redirect_stdout(out), redirect_stderr(err):
            code = cli.main(list(argv))
        return code, out.getvalue(), err.getvalue()

    def status(self, state: Path | None = None) -> dict[str, Any]:
        code, out, err = self.run_cli("federation", "status", "--json", state=state)
        self.assertEqual(code, 0, err)
        return json.loads(out)

    def test_unconfigured_absent_root_is_false_and_untouched(self) -> None:
        absent = self.base / "absent"
        before = tree(self.base)
        self.assertEqual(self.status(absent), {"relayRunning": False, "federation": None})
        self.assertFalse(absent.exists())
        self.assertEqual(tree(self.base), before)

    def test_every_branch_carries_relay_running(self) -> None:
        self.assertEqual(self.status()["relayRunning"], False)  # 未配置
        (self.state / "federation.json").write_text("{bad", encoding="utf-8")
        held = HeldLock(self.state)
        try:
            document = self.status()
            self.assertEqual((document["relayRunning"], document["federation"]["reason"]), (True, "config_invalid"))
        finally:
            held.release()
        (self.state / "federation.json").unlink()
        enable(self.state)
        self.assertEqual(self.status()["federation"]["state"], "offline")
        (self.state / FED_DB_NAME).write_bytes(b"not a database" * 100)
        held = HeldLock(self.state)
        try:
            document = self.status()
        finally:
            held.release()
        self.assertIs(document["relayRunning"], True)  # 联邦库读不了也保留锁事实
        self.assertFalse(document["federation"]["ledgerReadable"])
        self.assertEqual(document["federation"]["storageSubreason"], "federation_store_corrupt")  # 与可写打开同口径

    def test_status_never_touches_main_ledger_summary_or_worker(self) -> None:
        with Store.open():
            pass
        enable(self.state)
        connected: list[str] = []
        real_connect = sqlite3.connect

        def recording(database: Any, *args: Any, **kwargs: Any) -> sqlite3.Connection:
            connected.append(str(database))
            return real_connect(database, *args, **kwargs)

        before = tree(self.state)
        with patch.object(sqlite3, "connect", side_effect=recording), \
                patch.object(cli, "_refresh_summary", side_effect=AssertionError("summary refresh")), \
                patch.object(cli, "ensure_worker", side_effect=AssertionError("worker spawn")):
            self.status()
            code, out, err = self.run_cli("federation", "status")
        self.assertEqual(code, 0, err)
        self.assertFalse([item for item in connected if DB_NAME in item], connected)
        self.assertTrue(connected and all("mode=ro" in item for item in connected), connected)
        sidecars = {FED_DB_NAME + "-wal", FED_DB_NAME + "-shm"}  # 只读读者可按 SQLite 协调补建（§90.13）
        self.assertEqual({k: v for k, v in tree(self.state).items() if k not in sidecars},
                         {k: v for k, v in before.items() if k not in sidecars})  # 其余文件（含主库）一字不变
        self.assertIn("relay 进程：未运行", out)
        for prefix in ("relay 锚点监视", "relay 版本", "relay 诊断发布于", "relay 发布观察"):
            self.assertNotIn(prefix, out)  # Linux 不发布 Windows 诊断，也不输出「未知」行（Opus P3-2：M46）

    def test_status_reads_wal_and_touches_only_standard_sidecars(self) -> None:
        # §90.13（owner 2026-10-27）：只读读者按 SQLite 协调，最多补建标准 -wal/-shm，主库与其他文件不变
        enable(self.state)
        sidecars = {FED_DB_NAME + "-wal", FED_DB_NAME + "-shm"}
        wal, shm = (self.state / name for name in sorted(sidecars))
        before = tree(self.state)
        document = self.status()
        after = tree(self.state)
        self.assertLessEqual(set(after) - set(before), sidecars)
        self.assertEqual(after[FED_DB_NAME], before[FED_DB_NAME])  # 读者从不写主库
        self.assertEqual((document["federation"]["ledgerReadable"], document["federation"]["state"]),
                         (True, "offline"))
        with FederatedStore.open(self.state) as live:  # 有连接在用 WAL
            live.set_meta("relayState", "connected")  # 只在 WAL 里，主库还没并入
            held = HeldLock(self.state)
            try:
                document = self.status()
            finally:
                held.release()
        self.assertEqual(document["federation"]["state"], "connected")  # 读到 WAL 里的最新值，没有忽略正在使用的 WAL
        for present in (wal, shm):  # 只剩一个辅助文件：照常按读者打开，不判未知
            with self.subTest(present=present.name):
                for item in (wal, shm):
                    item.unlink(missing_ok=True)
                present.write_bytes(b"")
                document = self.status()
                self.assertTrue(document["federation"]["ledgerReadable"])

    def test_readonly_select_keeps_one_snapshot_across_a_checkpoint(self) -> None:
        # Codex r2 AS90-I-r2-C-P2-01：读到一半时另一连接提交并 checkpoint，一条 SELECT 不得混出新旧两种值
        enable(self.state)
        prefix = "maxHubCommitCounter:"
        with FederatedStore.open(self.state) as seed, seed.transaction():
            for number in range(1200):
                seed.set_meta(prefix + f"{number:032x}", "1")
        with FederatedStore.open_readonly(self.state) as reader:
            cursor = reader.connection.execute(
                "SELECT value FROM fed_meta WHERE key LIKE ? ORDER BY rowid", (prefix + "%",))
            first = cursor.fetchone()
            with FederatedStore.open(self.state) as writer:
                with writer.transaction() as conn:
                    conn.execute("UPDATE fed_meta SET value='2' WHERE key LIKE ?", (prefix + "%",))
                writer.connection.execute("PRAGMA wal_checkpoint(PASSIVE)").fetchone()
                values = {str(first[0]), *(str(row[0]) for row in cursor.fetchall())}
        self.assertEqual(values, {"1"})

    def test_status_returns_within_a_second_while_main_ledger_is_write_locked(self) -> None:
        with Store.open():
            pass
        enable(self.state)
        holder = subprocess.Popen(
            [sys.executable, "-c",
             "import sqlite3,sys,time\n"
             "c=sqlite3.connect(sys.argv[1],isolation_level=None);c.execute('BEGIN EXCLUSIVE')\n"
             "print('ready',flush=True);time.sleep(30)", str(self.state / DB_NAME)],
            stdout=subprocess.PIPE, text=True)
        assert holder.stdout is not None
        self.addCleanup(holder.stdout.close)
        self.addCleanup(holder.wait)
        self.addCleanup(holder.kill)
        self.assertEqual(holder.stdout.readline().strip(), "ready")
        started = time.monotonic()
        document = self.status()
        self.assertLess(time.monotonic() - started, 1.0)
        self.assertIs(document["relayRunning"], False)

    def test_other_commands_still_refresh_and_relay_does_not(self) -> None:
        calls: list[dict[str, Any]] = []
        with patch.object(cli, "_refresh_summary", side_effect=lambda **kw: calls.append(kw)):
            self.run_cli("tasks")
            self.assertEqual(len(calls), 2)
            with patch.object(fed_commands, "run_relay", return_value="stopped"):
                code, _, err = self.run_cli("federation", "relay")
            self.assertEqual(code, 0, err)
            self.assertEqual(len(calls), 2)
            enable(self.state)
            self.run_cli("federation", "disable")
            self.assertEqual(len(calls), 4)

    def test_unknown_lock_is_reported_not_offline(self) -> None:
        enable(self.state)
        with patch.object(fed_commands, "relay_running", return_value=None):
            document = self.status()
            code, out, _ = self.run_cli("federation", "status")
        self.assertIsNone(document["relayRunning"])
        self.assertEqual((document["federation"]["state"], document["federation"]["reason"]),
                         ("storage_failed", "relay_running_unknown"))
        self.assertIn("relay 进程：未知", out)


class DiagnosticsTripleTests(unittest.TestCase):
    """三键整组替换、单条 SELECT 同快照读取、必需键与可选版本、只在 Windows 且 relay 在跑时投影。"""

    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.state = Path(tmp.name)
        self.enterContext(patch.dict(os.environ, {"AB_STATE_DIR": str(self.state)}))
        enable(self.state)

    def keys(self) -> dict[str, str]:
        with FederatedStore.open(self.state) as store:
            return store.relay_diagnostics()

    def test_publish_replaces_the_whole_group_and_clear_removes_it(self) -> None:
        with FederatedStore.open(self.state) as store:
            store.publish_relay_diagnostics(anchor_watch="active", version="0.1.0.dev71+gabc", published_at=1000)
        self.assertEqual(self.keys(), {"relayAnchorWatch": "active", "relayDistributionVersion": "0.1.0.dev71+gabc",
                                       "relayPublishedAt": "1000"})
        with FederatedStore.open(self.state) as store:
            store.publish_relay_diagnostics(anchor_watch="unavailable", version=None, published_at=2000)
        self.assertEqual(self.keys(), {"relayAnchorWatch": "unavailable", "relayPublishedAt": "2000"})
        with FederatedStore.open(self.state) as store:
            store.clear_relay_diagnostics()
        self.assertEqual(self.keys(), {})

    def test_publish_is_atomic_for_a_concurrent_reader(self) -> None:
        # Codex AS90-I-C-P3-02：发布执行到一半时，另一条连接只能看到完整的旧组
        old = {"relayAnchorWatch": "active", "relayDistributionVersion": "old", "relayPublishedAt": "1"}
        seen: list[dict[str, str]] = []
        with FederatedStore.open(self.state) as store:
            store.publish_relay_diagnostics(anchor_watch="active", version="old", published_at=1)
            reader = sqlite3.connect(self.state / FED_DB_NAME, isolation_level=None)
            self.addCleanup(reader.close)

            def observe(statement: str) -> None:
                if statement.lstrip().upper().startswith("INSERT INTO FED_META"):
                    rows = reader.execute("SELECT key, value FROM fed_meta WHERE key IN (?,?,?)",
                                          RELAY_DIAGNOSTIC_KEYS).fetchall()
                    seen.append(dict(rows))

            store.connection.set_trace_callback(observe)
            store.publish_relay_diagnostics(anchor_watch="unavailable", version=None, published_at=2)
            store.connection.set_trace_callback(None)
        self.assertEqual(seen, [old, old])  # 两次 INSERT 之间都只见旧组，不见空组或半组
        self.assertEqual(self.keys(), {"relayAnchorWatch": "unavailable", "relayPublishedAt": "2"})

    def test_read_is_one_select(self) -> None:
        statements: list[str] = []
        with FederatedStore.open(self.state) as store:
            store.publish_relay_diagnostics(anchor_watch="active", version="v", published_at=1)
            store.connection.set_trace_callback(statements.append)
            store.relay_diagnostics()
        self.assertEqual(len([s for s in statements if s.lstrip().upper().startswith("SELECT")]), 1, statements)

    def test_projection_rules(self) -> None:
        full = {"relayAnchorWatch": "active", "relayDistributionVersion": "1.0", "relayPublishedAt": "5"}
        unknown = {"anchorWatch": None, "relayVersion": None, "relayPublishedAt": None}
        project = fed_commands.relay_diagnostics_projection
        self.assertEqual(project(full), {"anchorWatch": "active", "relayVersion": "1.0", "relayPublishedAt": 5})
        for key in ("relayAnchorWatch", "relayPublishedAt"):  # 必需键（Opus r3 P3-3）
            self.assertEqual(project({k: v for k, v in full.items() if k != key}), unknown)
        no_version = project({k: v for k, v in full.items() if k != "relayDistributionVersion"})
        self.assertEqual(no_version, {"anchorWatch": "active", "relayVersion": None, "relayPublishedAt": 5})
        for bad in ("", "-1", "1.5", "+3", "１", "9" * 20):
            self.assertEqual(project(full | {"relayPublishedAt": bad}), unknown, bad)
        self.assertEqual(project(full | {"relayAnchorWatch": "dead"}), unknown)
        for bad in ("", "x" * 129, "1.0\n", "版本"):
            self.assertIsNone(project(full | {"relayDistributionVersion": bad})["relayVersion"], bad)

    def test_projection_only_on_windows_while_running(self) -> None:
        with FederatedStore.open(self.state) as store:
            store.publish_relay_diagnostics(anchor_watch="active", version="1.0", published_at=7)
            store.set_meta("relayState", "connected")
        windows = SimpleNamespace(name="windows")
        fields = ("anchorWatch", "relayVersion", "relayPublishedAt")
        with patch.object(fed_commands, "get_platform", return_value=windows):
            running = fed_commands.doctor_projection(self.state, running=True)
            assert running is not None
            self.assertEqual({k: running[k] for k in fields},
                             {"anchorWatch": "active", "relayVersion": "1.0", "relayPublishedAt": 7})
            for value in (False, None):  # 未运行/运行未知：隐藏磁盘残留
                projection = fed_commands.doctor_projection(self.state, running=value)
                assert projection is not None
                self.assertFalse(set(fields) & set(projection), value)
        linux = fed_commands.doctor_projection(self.state, running=True)
        assert linux is not None
        self.assertFalse(set(fields) & set(linux))

    def test_meta_keys_are_registered(self) -> None:
        with FederatedStore.open(self.state) as store:
            for key in RELAY_DIAGNOSTIC_KEYS:
                store.set_meta(key, "x")  # 未登记的键会抛 ValueError



# ---- §90.5 停止控制 ----


class FakeTransport:
    def __init__(self) -> None:
        self.aborts: list[str] = []

    def abort(self) -> None:
        self.aborts.append(threading.current_thread().name)


class FakeAnchor:
    """可编排的 launch anchor：states 依次返回，用完后一直 alive；记录等待与关闭发生在哪个线程。"""

    def __init__(self, *states: str, error: BaseException | None = None) -> None:
        self.states = list(states)
        self.error = error
        self.waits: list[str] = []
        self.closes: list[str] = []

    def wait(self, milliseconds: int) -> str:
        self.waits.append(threading.current_thread().name)
        if self.error is not None:
            raise self.error
        return self.states.pop(0) if self.states else "alive"

    def close(self) -> None:
        self.closes.append(threading.current_thread().name)


def controller(**kwargs: Any) -> StopController:
    kwargs.setdefault("read_disabled", lambda: False)
    return StopController(poll=0.01, config_every=0.02, **kwargs)


def threading_with(thread_class: type[threading.Thread]) -> SimpleNamespace:
    """relay_control 用的 threading 替身：只换 Thread 类，其余照用真实实现。"""
    return SimpleNamespace(Thread=thread_class, Event=threading.Event, Lock=threading.Lock,
                           current_thread=threading.current_thread, main_thread=threading.main_thread)


def wait_until(predicate: Any, seconds: float = 5.0) -> bool:
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(0.005)
    return bool(predicate())


class StopControllerTests(unittest.TestCase):
    STOP_THREAD = "federation-relay-stop"

    def run_controller(self, item: StopController) -> None:
        item.start()
        self.addCleanup(item.close)

    def test_signal_handler_only_assigns_and_thread_turns_it_into_stop(self) -> None:
        item = controller()
        transport = FakeTransport()
        item.bind(transport)
        item.on_signal(15, None)
        self.assertFalse(item.is_set())  # 处理函数不碰 Event
        self.assertEqual(item.signal_requested, "signal")
        self.run_controller(item)
        self.assertTrue(wait_until(item.is_set))
        self.assertEqual(item.reason, "signal")
        self.assertTrue(wait_until(lambda: transport.aborts == [self.STOP_THREAD]))

    def test_disabled_is_read_by_the_control_thread_only(self) -> None:
        readers: list[str] = []

        def read() -> bool:
            readers.append(threading.current_thread().name)
            return len(readers) >= 3

        item = controller(read_disabled=read)
        self.run_controller(item)
        self.assertTrue(wait_until(item.is_set))
        self.assertEqual(item.reason, "disabled")
        self.assertEqual(set(readers), {self.STOP_THREAD})

    def test_round_failure_sleeps_and_keeps_consuming(self) -> None:
        calls: list[int] = []

        def read() -> bool:
            calls.append(1)
            raise RuntimeError("unexpected")

        item = controller(read_disabled=read)
        self.run_controller(item)
        self.assertTrue(wait_until(lambda: len(calls) >= 3))
        self.assertFalse(item.is_set())  # 一轮失败不停 relay
        item.on_signal(15, None)
        self.assertTrue(wait_until(item.is_set))
        self.assertEqual(item.reason, "signal")

    def test_thread_death_is_a_closed_reason_not_silent(self) -> None:
        class Boom(BaseException):
            pass

        def read() -> bool:
            raise Boom()

        item = controller(read_disabled=read)
        transport = FakeTransport()
        item.bind(transport)
        item.start()
        self.assertTrue(wait_until(item.is_set))
        self.assertEqual(item.reason, "stop_controller_failed")
        self.assertEqual(transport.aborts, [self.STOP_THREAD])
        self.assertTrue(item.close())

    def test_anchor_exit_stops_and_handle_is_closed_by_the_control_thread(self) -> None:
        anchor = FakeAnchor("alive", "alive", "exited")
        item = controller(anchor=anchor)
        transport = FakeTransport()
        item.bind(transport)
        self.run_controller(item)
        self.assertTrue(wait_until(item.is_set))
        self.assertEqual(item.reason, "anchor_exited")
        self.assertTrue(item.close())
        self.assertEqual(anchor.closes, [self.STOP_THREAD])
        self.assertEqual(set(anchor.waits), {self.STOP_THREAD})
        self.assertEqual(transport.aborts, [self.STOP_THREAD])

    def test_wait_failed_closes_once_downgrades_and_still_consumes_signal(self) -> None:
        for anchor in (FakeAnchor("alive", "failed"), FakeAnchor(error=OSError("wait"))):
            with self.subTest(error=anchor.error is not None):
                slept: list[float] = []
                item = StopController(read_disabled=lambda: False, anchor=anchor, poll=0.01, config_every=0.02,
                                      sleep=lambda s: (slept.append(s), time.sleep(s)))
                self.assertEqual(item.anchor_watch, "active")
                item.start()
                self.assertTrue(wait_until(lambda: item.anchor_watch == "unavailable"))
                waits = len(anchor.waits)
                self.assertTrue(wait_until(lambda: len(slept) >= waits + 5))  # 之后有 sleep，不空转
                self.assertEqual(len(anchor.waits), waits)  # 失效句柄不再等待
                self.assertEqual(anchor.closes, [self.STOP_THREAD])  # 只关一次，且在控制线程
                self.assertFalse(item.is_set())  # WAIT_FAILED 不是死亡
                item.on_signal(15, None)
                self.assertTrue(wait_until(item.is_set))
                self.assertEqual(item.reason, "signal")
                self.assertTrue(item.close())
                self.assertEqual(anchor.closes, [self.STOP_THREAD])

    def test_request_bind_interleaving_never_loses_the_abort(self) -> None:
        # Codex AS90-I-C-P2-01：request 释放引用锁之后、bind 之前插入调度屏障；新连接仍必须被中止
        released = threading.Event()
        resume = threading.Event()
        native = threading.Lock()

        class ScheduledLock:
            def __enter__(self) -> None:
                native.acquire()

            def __exit__(self, *_exc: object) -> None:
                native.release()
                if threading.current_thread().name == "requester":
                    released.set()
                    resume.wait(5)

        item = controller()
        item._lock = ScheduledLock()  # type: ignore[assignment]  # pyright: ignore[reportPrivateUsage]
        requester = threading.Thread(target=item.request, args=("disabled",), name="requester", daemon=True)
        requester.start()
        self.assertTrue(released.wait(5))
        transport = FakeTransport()
        item.bind(transport)
        resume.set()
        requester.join(5)
        self.assertTrue(item.is_set())
        self.assertEqual(len(transport.aborts), 1)

    def test_bind_after_stop_aborts_at_once_and_first_reason_wins(self) -> None:
        item = controller()
        item.request("disabled")
        item.request("signal")
        self.assertEqual(item.reason, "disabled")
        transport = FakeTransport()
        item.bind(transport)
        self.assertEqual(len(transport.aborts), 1)
        item.unbind()
        item.request("anchor_exited")
        self.assertEqual(len(transport.aborts), 1)

    def test_unstarted_controller_closes_the_handle_on_the_main_thread(self) -> None:
        anchor = FakeAnchor()
        item = controller(anchor=anchor)
        self.assertTrue(item.close())
        self.assertEqual(anchor.closes, [threading.current_thread().name])

    def test_started_but_unclaimed_thread_leaves_the_handle_to_the_main_thread(self) -> None:
        # Codex AS90-I-r3-C-P3-01：线程已启动、还没跑到认领时主线程收尾——句柄归主线程，
        # 迟到的线程不等待、不关句柄，也不报 stop_controller_failed
        gate = threading.Event()

        class GatedThread(threading.Thread):
            def run(self) -> None:
                gate.wait(5)
                super().run()

        anchor = FakeAnchor()
        with patch.object(relay_control, "threading", threading_with(GatedThread)):
            item = controller(anchor=anchor)
            item.start()
        release = threading.Timer(0.2, gate.set)
        release.start()
        self.addCleanup(release.join)
        self.assertTrue(item.close())  # 先在锁内定归属，再等迟到的线程自行退出
        thread = item._thread  # pyright: ignore[reportPrivateUsage]
        self.assertIsNotNone(thread)
        assert thread is not None
        self.assertFalse(thread.is_alive())  # close 确实等到了迟到的线程（Opus P3-r3c-2）
        self.assertEqual(anchor.closes, [threading.current_thread().name])
        self.assertEqual(anchor.waits, [])
        self.assertIsNone(item.reason)

    def test_close_wins_the_claim_even_if_the_late_thread_runs_before_the_swap(self) -> None:
        # Codex AS90-I-r3c-C-P3-01：close 在锁内定案「未认领」后、取出句柄前暂停，放行迟到的线程跑完；
        # 迟到线程必须看到 _closing 直接退出，句柄仍由主线程关（去掉认领前的检查时会由迟到线程关）
        run_gate, child_done = threading.Event(), threading.Event()
        native = threading.Lock()
        pause_next_main_release = [False]
        main = threading.current_thread()

        class DelayedThread(threading.Thread):
            def run(self) -> None:
                try:
                    if run_gate.wait(5):
                        super().run()
                finally:
                    child_done.set()

        class ScheduledLock:
            def __enter__(self) -> None:
                native.acquire()

            def __exit__(self, *_exc: object) -> None:
                native.release()
                if threading.current_thread() is main and pause_next_main_release[0]:
                    pause_next_main_release[0] = False  # 只暂停 close 的仲裁块，之后的取出照常
                    run_gate.set()
                    child_done.wait(5)

        anchor = FakeAnchor()
        with patch.object(relay_control, "threading", threading_with(DelayedThread)):
            item = controller(anchor=anchor)
            item._lock = ScheduledLock()  # type: ignore[assignment]  # pyright: ignore[reportPrivateUsage]
            item.start()
        self.addCleanup(run_gate.set)
        pause_next_main_release[0] = True
        self.assertTrue(item.close())
        self.assertTrue(child_done.is_set())  # 迟到的线程确实在取出句柄之前跑完了
        self.assertEqual(anchor.closes, [main.name])
        self.assertEqual(anchor.waits, [])
        self.assertIsNone(item.reason)

    def test_join_timeout_never_steals_a_claimed_handle(self) -> None:
        # 已认领的句柄只由控制线程关：join 超时返回 False，主线程不抢关；放行后控制线程关一次
        release = threading.Event()

        class BlockingAnchor(FakeAnchor):
            def wait(self, milliseconds: int) -> str:
                self.waits.append(threading.current_thread().name)
                release.wait(5)
                return "alive"

        anchor = BlockingAnchor()
        item = controller(anchor=anchor)
        item.start()
        self.addCleanup(release.set)
        self.assertTrue(wait_until(lambda: bool(anchor.waits)))
        self.assertFalse(item.close(timeout=0.1))
        self.assertEqual(anchor.closes, [])
        release.set()
        self.assertTrue(item.close())
        self.assertEqual(anchor.closes, [self.STOP_THREAD])

    def test_config_disabled_reader(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            enable(root)
            self.assertFalse(config_disabled(root))
            path = root / "federation.json"
            good = path.read_bytes()
            path.write_text("{bad", encoding="utf-8")
            self.assertFalse(config_disabled(root))  # 解析失败只算这一轮没读到
            path.write_bytes(good)
            path.chmod(0)
            try:
                if os.geteuid() != 0:
                    self.assertFalse(config_disabled(root))  # 读失败（含 Windows winerror 5）同样跳过
            finally:
                path.chmod(0o600)
            config = fed_config.load(root)
            assert config is not None
            fed_config.save(root, replace(config, enabled=False))
            self.assertTrue(config_disabled(root))
            path.unlink()
            self.assertTrue(config_disabled(root))  # 配置确实不存在：按停用（Opus r3 P3-1）

    def test_sigterm_install_is_main_thread_only_and_restored(self) -> None:
        original_term, original_int = signal.getsignal(signal.SIGTERM), signal.getsignal(signal.SIGINT)
        item = controller()
        restore = install_sigterm(item)
        try:
            self.assertEqual(signal.getsignal(signal.SIGTERM), item.on_signal)
            self.assertEqual(signal.getsignal(signal.SIGINT), original_int)  # SIGINT 保留 KeyboardInterrupt 语义
        finally:
            restore()
        self.assertEqual(signal.getsignal(signal.SIGTERM), original_term)
        results: list[Any] = []
        worker = threading.Thread(target=lambda: results.append(install_sigterm(item)))
        worker.start()
        worker.join()
        results[0]()
        self.assertEqual(signal.getsignal(signal.SIGTERM), original_term)  # 非主线程不偷偷注册


class RelayStopPriorityTests(unittest.TestCase):
    """连接层：停止优先于断线/协议错误/库忙；停止后不发请求、不跑留存、不拉 worker。"""

    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        enable(self.root)
        self.rt = fed_commands.open_runtime(self.root)
        self.addCleanup(self.rt.close)

    def relay(self, transport: Any, **kwargs: Any) -> Relay:
        return Relay(self.rt.store, self.rt.ident, self.rt.config, self.rt.paths, connect=lambda: transport, **kwargs)

    def hello(self) -> dict[str, Any]:
        return {"type": "hello", "protocol": {"major": 1, "minor": 0}, "capabilities": sorted(REQUIRED_CAPABILITIES),
                "deviceId": DEV, "hubId": HUB, "commitCounter": 0}

    def test_handshake_write_failure_is_stopped_when_stop_was_requested(self) -> None:
        for stopping, expected in ((True, "stopped"), (False, "hub_unavailable")):
            with self.subTest(stopping=stopping):
                flag = {"stop": False}

                class Broken:
                    closed = False

                    def read_frame(inner, timeout: float | None = None) -> Any:
                        return self.hello()

                    def write_frame(inner, frame: Any) -> None:
                        flag["stop"] = stopping  # 停止在阻塞写期间到来，中止 ssh 让写失败
                        raise BrokenPipeError()

                    def close(inner) -> None:
                        inner.closed = True

                transport = Broken()
                state = self.relay(transport).connect_and_run(should_stop=lambda: flag["stop"])
                self.assertEqual(state, expected)
                self.assertEqual(self.rt.store.meta("relayState"), "offline" if stopping else "reconnecting")
                self.assertTrue(transport.closed)

    def test_no_request_retention_or_worker_after_stop(self) -> None:
        stop = {"value": True}
        sent: list[Any] = []
        # 假通道能完整走一轮（连接级错误帧让请求以 RelayStop 结束）：若停止检查缺失，帧会被写出，由下面的断言抓到
        transport = SimpleNamespace(write_frame=sent.append, read_frame=lambda timeout=None: {
            "type": "error", "requestId": None, "code": "hub_unavailable"})
        conn = HubConnection(transport, on_counter=lambda _c: None, should_stop=lambda: stop["value"])
        with self.assertRaises(RelayStop):
            conn.call("heartbeat")
        self.assertEqual(sent, [])
        woke: list[int] = []
        relay = self.relay(None, on_work=lambda: woke.append(1) or True)
        relay._should_stop = lambda: True  # pyright: ignore[reportPrivateUsage]
        with patch.object(retention, "sweep") as sweep:
            relay._retention_tick(10**13)  # pyright: ignore[reportPrivateUsage]
        sweep.assert_not_called()
        with patch.object(mirror, "wake_candidates", return_value={"m" * 32}):
            relay._wake_if_needed()  # pyright: ignore[reportPrivateUsage]
        self.assertEqual(woke, [])

    def test_stopped_before_connect_never_connects(self) -> None:
        connects: list[int] = []
        relay = Relay(self.rt.store, self.rt.ident, self.rt.config, self.rt.paths,
                      connect=lambda: connects.append(1))  # type: ignore[arg-type, return-value]
        self.assertEqual(relay.connect_and_run(should_stop=lambda: True), "stopped")
        self.assertEqual(relay.run_forever(should_stop=lambda: True), "stopped")
        self.assertEqual(connects, [])


class RelayDiagnosticsTests(unittest.TestCase):
    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        enable(self.root)
        self.store = FederatedStore.open(self.root)
        self.addCleanup(self.store.close)
        self.store.publish_relay_diagnostics(anchor_watch="active", version="old", published_at=1)

    def test_linux_clears_and_never_reads_version_or_publishes(self) -> None:
        item = controller()
        diagnostics = RelayDiagnostics(self.store, item, windows=False,
                                       version=lambda: self.fail("Linux 不读分发版本"))  # type: ignore[arg-type,return-value]
        diagnostics.initialize()
        diagnostics.tick()
        self.assertEqual(self.store.relay_diagnostics(), {})

    def test_windows_publishes_group_and_republishes_on_change_or_after_failure(self) -> None:
        item = controller(anchor=FakeAnchor())
        clock = iter(range(100, 200))
        diagnostics = RelayDiagnostics(self.store, item, windows=True, version=lambda: "1.2", clock=lambda: next(clock))
        diagnostics.initialize()
        self.assertEqual(self.store.relay_diagnostics(), {"relayAnchorWatch": "active",
                                                         "relayDistributionVersion": "1.2", "relayPublishedAt": "100"})
        diagnostics.tick()
        self.assertEqual(self.store.relay_diagnostics()["relayPublishedAt"], "100")  # 未变不重写
        item.anchor_watch = "unavailable"
        with patch.object(self.store, "publish_relay_diagnostics", side_effect=StoreError("store_busy")):
            diagnostics.tick()
        self.assertEqual(self.store.relay_diagnostics()["relayAnchorWatch"], "active")
        diagnostics.tick()  # 上次失败：下一次 tick 重发
        self.assertEqual(self.store.relay_diagnostics(), {"relayAnchorWatch": "unavailable",
                                                         "relayDistributionVersion": "1.2", "relayPublishedAt": "102"})

    def test_clear_failure_still_leaves_no_stale_version(self) -> None:
        diagnostics = RelayDiagnostics(self.store, controller(), windows=True, version=lambda: None, clock=lambda: 9)
        with patch.object(self.store, "clear_relay_diagnostics", side_effect=StoreError("store_busy")):
            diagnostics.initialize()
        self.assertEqual(self.store.relay_diagnostics(), {"relayAnchorWatch": "unavailable", "relayPublishedAt": "9"})

    def test_distribution_version_reader(self) -> None:
        for raised in (importlib.metadata.PackageNotFoundError("agent-bridge"), ValueError("bad metadata")):
            with self.subTest(raised=type(raised).__name__), \
                    patch.object(relay_control.importlib.metadata, "version", side_effect=raised):
                self.assertIsNone(relay_control.distribution_version())
        with patch.object(relay_control.importlib.metadata, "version", return_value="0.1.0.dev71+gabc") as read:
            self.assertEqual(relay_control.distribution_version(), "0.1.0.dev71+gabc")
        read.assert_called_once_with("agent-bridge")
        with patch.object(relay_control.importlib.metadata, "version", return_value="x" * 129):
            self.assertIsNone(relay_control.distribution_version())


SILENT = "import time; time.sleep(120)"


class RunRelayStopTests(unittest.TestCase):
    """run_relay 整条路径（Linux 真实子进程）：停用/锚点/SIGTERM 都在 15 秒内停净，ssh 回收、锁释放、worker 存活。"""

    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        enable(self.root)

    def silent_connector(self, children: list[subprocess.Popen[bytes]]) -> Any:
        def connect() -> SubprocessTransport:
            process = subprocess.Popen([sys.executable, "-I", "-c", SILENT], stdin=subprocess.PIPE,
                                       stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
            children.append(process)
            return SubprocessTransport(process)

        return connect

    def reap(self, children: list[subprocess.Popen[bytes]]) -> None:
        for child in children:
            if child.poll() is None:
                child.kill()
            child.wait()

    def set_enabled(self, value: Any, *, delay: float) -> threading.Timer:
        config = fed_config.load(self.root)  # 先取好合法配置：坏配置写入后计时器仍能写回合法的停用配置
        assert config is not None

        def flip() -> None:
            if value == "corrupt":
                (self.root / "federation.json").write_text("{bad", encoding="utf-8")
                return
            fed_config.save(self.root, replace(config, enabled=value))

        timer = threading.Timer(delay, flip)
        timer.start()
        self.addCleanup(timer.join)  # 清理临时目录前等计时器写完
        self.addCleanup(timer.cancel)
        return timer

    def test_disable_stops_a_relay_blocked_in_handshake(self) -> None:
        children: list[subprocess.Popen[bytes]] = []
        self.addCleanup(self.reap, children)
        original = signal.getsignal(signal.SIGTERM)
        self.set_enabled(False, delay=0.3)
        readers: list[str] = []

        def recording(root: Path) -> bool:
            readers.append(threading.current_thread().name)
            return config_disabled(root)

        started = time.monotonic()
        with patch.object(fed_commands, "config_disabled", recording):
            state = fed_commands.run_relay(self.root, connector=self.silent_connector(children))
        self.assertEqual(state, "stopped")
        self.assertEqual(set(readers), {"federation-relay-stop"})  # 停用判定只有控制线程一个读者
        self.assertLess(time.monotonic() - started, 5.0)  # 不等 60 秒读超时
        self.assertEqual(len(children), 1)
        self.assertIsNotNone(children[0].returncode)  # 本连接的 ssh 已回收
        self.assertIs(fed_commands.relay_running(self.root), False)
        self.assertEqual(signal.getsignal(signal.SIGTERM), original)
        with FederatedStore.open(self.root) as store:
            self.assertEqual(store.meta("relayState"), "offline")
            self.assertEqual(store.relay_diagnostics(), {})  # Linux 不发布

    def test_corrupt_config_is_skipped_until_a_valid_disable(self) -> None:
        children: list[subprocess.Popen[bytes]] = []
        self.addCleanup(self.reap, children)
        self.set_enabled("corrupt", delay=0.2)
        self.set_enabled(False, delay=1.5)
        started = time.monotonic()
        self.assertEqual(fed_commands.run_relay(self.root, connector=self.silent_connector(children)), "stopped")
        self.assertGreater(time.monotonic() - started, 1.4)  # 坏配置那一轮没有停
        self.assertEqual(len(children), 1)

    def test_anchor_exit_stops_relay_and_publishes_windows_diagnostics(self) -> None:
        children: list[subprocess.Popen[bytes]] = []
        self.addCleanup(self.reap, children)
        anchor = FakeAnchor("alive", "alive", "alive", "exited")
        windows_paths = RelayPaths(self.root, windows=True, local_appdata=self.root / "LocalAppData")
        published: list[dict[str, str]] = []
        real_connector = self.silent_connector(children)

        def connect() -> SubprocessTransport:
            with FederatedStore.open(self.root) as store:
                published.append(store.relay_diagnostics())  # 连接前诊断已发布
            return real_connector()

        with patch.object(fed_commands, "_paths", return_value=windows_paths), \
                patch.object(fed_commands, "_launch_anchor", return_value=anchor) as bind, \
                patch.object(relay_control, "distribution_version", return_value=None):
            state = fed_commands.run_relay(self.root, connector=connect, watch_anchor=True)
        self.assertEqual(state, "stopped")
        bind.assert_called_once_with()
        self.assertEqual(anchor.closes, ["federation-relay-stop"])
        self.assertEqual(published[0]["relayAnchorWatch"], "active")
        self.assertTrue(published[0]["relayPublishedAt"].isdecimal())
        self.assertNotIn("relayDistributionVersion", published[0])
        self.assertIsNotNone(children[0].returncode)

    def test_anchor_is_not_bound_without_flag_or_off_windows(self) -> None:
        children: list[subprocess.Popen[bytes]] = []
        self.addCleanup(self.reap, children)
        config = fed_config.load(self.root)
        assert config is not None
        for watch in (False, True):
            with self.subTest(watch=watch), patch.object(fed_commands, "_launch_anchor") as bind:
                fed_config.save(self.root, config)
                timer = self.set_enabled(False, delay=0.3)  # relay 先起来、连上，再停用
                self.assertEqual(fed_commands.run_relay(self.root, connector=self.silent_connector(children),
                                                        watch_anchor=watch), "stopped")
                timer.join()
                bind.assert_not_called()  # Linux：--watch-launch-anchor 被忽略

    def test_offline_write_is_bounded_and_failure_does_not_block_stop(self) -> None:
        # Opus P3-2：M33 offline 最多 1 秒、库忙就跳过；M34 写失败照样返回 stopped、关连接
        rt = fed_commands.open_runtime(self.root)
        self.addCleanup(rt.close)
        relay = Relay(rt.store, rt.ident, rt.config, rt.paths, connect=lambda: None)  # type: ignore[arg-type,return-value]
        holder = subprocess.Popen(
            [sys.executable, "-c",
             "import sqlite3,sys,time\n"
             "c=sqlite3.connect(sys.argv[1],isolation_level=None);c.execute('BEGIN IMMEDIATE')\n"
             "print('ready',flush=True);time.sleep(30)", str(self.root / FED_DB_NAME)],
            stdout=subprocess.PIPE, text=True)
        assert holder.stdout is not None
        self.addCleanup(holder.stdout.close)
        self.addCleanup(holder.wait)
        self.addCleanup(holder.kill)
        self.assertEqual(holder.stdout.readline().strip(), "ready")
        started = time.monotonic()
        self.assertEqual(relay._stopped(), "stopped")  # pyright: ignore[reportPrivateUsage]
        self.assertLess(time.monotonic() - started, 2.5)  # 默认 busy 5 秒；停止只给 1 秒
        holder.kill()

        flag = {"stop": False, "closed": False}

        class Closing:
            def read_frame(self, timeout: float | None = None) -> Any:
                flag["stop"] = True  # 停止在握手读期间到来，中止让读方按 EOF 返回
                return None

            def close(self) -> None:
                flag["closed"] = True

        broken = Relay(rt.store, rt.ident, rt.config, rt.paths, connect=Closing)  # type: ignore[arg-type]
        with patch.object(broken, "_set_state", side_effect=StoreError("store_write_failed")):
            self.assertEqual(broken.connect_and_run(should_stop=lambda: flag["stop"]), "stopped")
        self.assertTrue(flag["closed"])  # 诊断写失败不挡关闭连接

    def test_second_start_exits_on_the_lock_before_touching_anchor_or_diagnostics(self) -> None:
        # Opus P3-2：M44b 先锁后锚点——重复启动不扫描祖先、不改诊断
        with FederatedStore.open(self.root) as store:
            store.publish_relay_diagnostics(anchor_watch="active", version="held", published_at=5)
        held = HeldLock(self.root)
        try:
            with patch.object(fed_commands, "_paths",
                              return_value=RelayPaths(self.root, windows=True, local_appdata=self.root)), \
                    patch.object(fed_commands, "_launch_anchor") as bind:
                self.assertEqual(fed_commands.run_relay(self.root, connector=lambda: self.fail("不应连接"),
                                                        watch_anchor=True), "already_running")
            bind.assert_not_called()
        finally:
            held.release()
        with FederatedStore.open(self.root) as store:
            self.assertEqual(store.relay_diagnostics()["relayDistributionVersion"], "held")

    def test_controller_death_is_returned_and_exits_6(self) -> None:
        # Opus P3-2：M45 控制线程意外退出时 run_relay 返回 stop_controller_failed，CLI 退出 6
        class Boom(BaseException):
            pass

        def explode(_root: Path) -> bool:
            raise Boom()

        children: list[subprocess.Popen[bytes]] = []
        self.addCleanup(self.reap, children)
        with patch.object(fed_commands, "config_disabled", explode), \
                patch.object(threading, "excepthook", lambda _args: None):
            state = fed_commands.run_relay(self.root, connector=self.silent_connector(children))
        self.assertEqual(state, "stop_controller_failed")
        self.assertTrue(all(child.returncode is not None for child in children))  # 若已连上，ssh 也已回收
        self.assertIs(fed_commands.relay_running(self.root), False)
        with patch.dict(os.environ, {"AB_STATE_DIR": str(self.root)}), \
                patch.object(fed_commands, "run_relay", return_value="stop_controller_failed"), \
                redirect_stdout(StringIO()), redirect_stderr(StringIO()) as err:
            self.assertEqual(cli.main(["federation", "relay"]), 6)
        self.assertIn("停止控制线程意外退出", err.getvalue())
        self.assertIn("[stop_controller_failed]", err.getvalue())

    def test_thread_start_failure_keeps_the_error_restores_sigterm_and_closes_anchor(self) -> None:
        # Opus P3-r2-3：线程起不来时原异常不被「join 未启动线程」的 RuntimeError 盖住，
        # SIGTERM 恢复原处理函数，锚点句柄由主线程关闭，锁释放
        class NoThreads(Exception):
            pass

        class FailingThread(threading.Thread):
            def start(self) -> None:
                raise NoThreads("can't start new thread")

        fake_threading = threading_with(FailingThread)
        anchor = FakeAnchor()
        windows_paths = RelayPaths(self.root, windows=True, local_appdata=self.root / "LocalAppData")
        original = signal.getsignal(signal.SIGTERM)
        with patch.object(fed_commands, "_paths", return_value=windows_paths), \
                patch.object(fed_commands, "_launch_anchor", return_value=anchor), \
                patch.object(relay_control, "distribution_version", return_value=None), \
                patch.object(relay_control, "threading", fake_threading):
            with self.assertRaises(Exception) as caught:
                fed_commands.run_relay(self.root, connector=lambda: self.fail("不应连接"), watch_anchor=True)
        self.assertIsInstance(caught.exception, NoThreads)
        self.assertEqual(signal.getsignal(signal.SIGTERM), original)
        self.assertEqual(anchor.closes, [threading.current_thread().name])
        self.assertIs(fed_commands.relay_running(self.root), False)

    def test_interrupt_after_the_thread_claimed_keeps_the_handle_with_the_control_thread(self) -> None:
        # Codex AS90-I-r3-C-P3-01：线程已启动并认领后、start 返回前被中断（真实里是 SIGINT 转成的 KeyboardInterrupt），
        # 原异常照常抛出，SIGTERM 恢复，句柄仍由控制线程关、主线程不抢关
        class Interrupted(Exception):
            pass

        anchor = FakeAnchor()

        class InterruptedAfterClaim(threading.Thread):
            def start(self) -> None:
                super().start()
                if not wait_until(lambda: bool(anchor.waits)):  # 控制线程已认领并开始等锚点
                    raise AssertionError("控制线程 5 秒内没有认领")
                raise Interrupted()

        windows_paths = RelayPaths(self.root, windows=True, local_appdata=self.root / "LocalAppData")
        original = signal.getsignal(signal.SIGTERM)
        with patch.object(fed_commands, "_paths", return_value=windows_paths), \
                patch.object(fed_commands, "_launch_anchor", return_value=anchor), \
                patch.object(relay_control, "distribution_version", return_value=None), \
                patch.object(relay_control, "threading", threading_with(InterruptedAfterClaim)):
            with self.assertRaises(Exception) as caught:
                fed_commands.run_relay(self.root, connector=lambda: self.fail("不应连接"), watch_anchor=True)
        self.assertIsInstance(caught.exception, Interrupted)
        self.assertTrue(anchor.waits)
        self.assertEqual(anchor.closes, ["federation-relay-stop"])
        self.assertEqual(signal.getsignal(signal.SIGTERM), original)
        self.assertIs(fed_commands.relay_running(self.root), False)

    def test_cli_passes_the_watch_flag(self) -> None:
        seen: dict[str, Any] = {}

        def fake(root: Path, **kwargs: Any) -> str:
            seen.update(kwargs)
            return "stopped"

        with patch.dict(os.environ, {"AB_STATE_DIR": str(self.root)}), patch.object(fed_commands, "run_relay", fake), \
                redirect_stdout(StringIO()), redirect_stderr(StringIO()):
            self.assertEqual(cli.main(["federation", "relay", "--watch-launch-anchor"]), 0)
            self.assertEqual(seen, {"once": False, "watch_anchor": True})
            self.assertEqual(cli.main(["federation", "relay"]), 0)
            self.assertEqual(seen, {"once": False, "watch_anchor": False})


SIGNAL_SCRIPT = r"""
import json, signal, subprocess, sys
# 父进程从非交互 shell 后台启动时 SIGINT 被继承为忽略，Python 就不装 KeyboardInterrupt；先复位成解释器默认（Opus P3-3）
signal.signal(signal.SIGINT, signal.default_int_handler)
from pathlib import Path
from agentstatus_bridge.federation import commands as fed
from agentstatus_bridge.federation.relay import SubprocessTransport

root, mode, hello = Path(sys.argv[1]), sys.argv[2], sys.argv[3]
worker = subprocess.Popen([sys.executable, "-I", "-c", "import time; time.sleep(120)"], start_new_session=True,
                          stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
(root / "worker.pid").write_text(str(worker.pid))


class Flood(SubprocessTransport):
    def write_frame(self, frame):
        for _ in range(64):  # 对端从不读：阻塞在写 flush 上
            super().write_frame(dict(frame, pad="x" * 512 * 1024))


def connect():
    if mode == "write":
        code = "import sys, time; sys.stdout.buffer.write(open(sys.argv[1], 'rb').read()); sys.stdout.flush(); time.sleep(120)"
    else:
        code = "import time; time.sleep(120)"
    process = subprocess.Popen([sys.executable, "-I", "-c", code, hello], stdin=subprocess.PIPE,
                               stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    (root / "ssh.pid").write_text(str(process.pid))
    return (Flood if mode == "write" else SubprocessTransport)(process)


try:
    state = fed.run_relay(root, connector=connect)
except KeyboardInterrupt:
    state = "interrupted"
print(json.dumps({"state": state}), flush=True)
"""


@unittest.skipUnless(os.name == "posix", "POSIX 信号：Windows 由 launch anchor 停止")
class SignalEndToEndTests(unittest.TestCase):
    """真实 SIGTERM/SIGINT 打到 relay 进程：主线程分别阻塞在 queue.get 与写 flush 上。"""

    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        enable(self.root)
        hello = {"type": "hello", "protocol": {"major": 1, "minor": 0}, "capabilities": sorted(REQUIRED_CAPABILITIES),
                 "deviceId": DEV, "hubId": HUB, "commitCounter": 0}
        self.hello = self.root / "hello.frame"
        self.hello.write_bytes(encode_frame(hello))

    def alive(self, pid: int) -> bool:
        try:
            state = Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()[0]
        except OSError:
            return False
        return state != "Z"

    def run_case(self, mode: str, signum: int) -> dict[str, Any]:
        src = str(Path(cli.__file__).resolve().parents[1])
        env = dict(os.environ, PYTHONPATH=src)
        relay = subprocess.Popen([sys.executable, "-c", SIGNAL_SCRIPT, str(self.root), mode, str(self.hello)],
                                 env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        self.addCleanup(lambda: relay.poll() is None and relay.kill())
        self.assertTrue(wait_until(lambda: (self.root / "ssh.pid").exists(), 30.0), "relay 没有建立连接")
        worker = int((self.root / "worker.pid").read_text())
        self.addCleanup(lambda: self.alive(worker) and os.kill(worker, signal.SIGKILL))
        ssh = int((self.root / "ssh.pid").read_text())
        time.sleep(0.5)  # 让主线程进入阻塞（握手读或写 flush）
        self.assertTrue(fed_commands.relay_running(self.root))
        started = time.monotonic()
        relay.send_signal(signum)
        out, err = relay.communicate(timeout=20)
        elapsed = time.monotonic() - started
        self.assertLess(elapsed, 15.0, err)
        self.assertFalse(self.alive(ssh), "ssh 没有被回收")
        self.assertTrue(self.alive(worker), "relay 停止不能牵连 worker")
        self.assertIs(fed_commands.relay_running(self.root), False)
        return {"state": json.loads(out.strip().splitlines()[-1])["state"], "code": relay.returncode, "err": err}

    def test_sigterm_while_blocked_reading(self) -> None:
        result = self.run_case("read", signal.SIGTERM)
        self.assertEqual((result["state"], result["code"]), ("stopped", 0), result["err"])

    def test_sigterm_while_blocked_writing(self) -> None:
        result = self.run_case("write", signal.SIGTERM)
        self.assertEqual((result["state"], result["code"]), ("stopped", 0), result["err"])

    def test_sigint_keeps_keyboard_interrupt_and_still_cleans_up(self) -> None:
        result = self.run_case("read", signal.SIGINT)
        self.assertEqual(result["state"], "interrupted", result["err"])


# ---- §90.6 Windows launch anchor（SDK Fake 内核） ----

SID = bytes.fromhex("01010000000000052a000000")
OTHER_SID = bytes.fromhex("010100000000000563000000")


class WindowsAnchorTests(unittest.TestCase):
    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.k = Kernel(Path(tmp.name))
        self.addCleanup(lambda: self.assertEqual(self.k.handles, {}))
        # relay(100) ← venv 重定向器(200) ← cmd(300) ← action conhost(400) ← taskhostw(500)
        self.k.processes = {100: (200, 5000, SID, False, "python.exe"), 200: (300, 4000, SID, False, "python.exe"),
                            300: (400, 3000, SID, False, "cmd.exe"), 400: (500, 2000, SID, False, "conhost.exe"),
                            500: (0, 1000, SID, False, "taskhostw.exe")}
        self.k.images = {100: r"C:\py\python.exe", 200: r"C:\venv\Scripts\python.exe",
                         300: r"C:\WINDOWS\system32\cmd.exe", 400: r"C:\WINDOWS\system32\conhost.exe",
                         500: r"C:\WINDOWS\system32\taskhostw.exe"}

    def bind(self, **kwargs: Any) -> Any:
        kwargs.setdefault("system_root", r"C:\Windows")
        return windows_anchor.bind(self.k.api, pid=100, **kwargs)

    def test_binds_the_nearest_system_conhost_and_reports_exit(self) -> None:
        anchor = self.bind()
        assert anchor is not None
        try:
            self.assertEqual((anchor.pid, anchor.birth), (400, 2000))
            self.assertEqual(anchor.wait(0), "alive")
            self.k.exited.add(400)
            self.assertEqual(anchor.wait(0), "exited")
        finally:
            anchor.close()
        anchor.close()  # 幂等
        self.assertEqual(anchor.wait(0), "failed")

    def test_wait_failed_is_failed_not_exit(self) -> None:
        anchor = self.bind()
        assert anchor is not None
        try:
            with patch.object(self.k, "WaitForSingleObject", return_value=0xFFFFFFFF):
                self.assertEqual(anchor.wait(0), "failed")
        finally:
            anchor.close()

    def test_unavailable_cases_return_none(self) -> None:
        self.assertIsNone(self.bind(system_root=None))
        self.assertIsNone(self.bind(system_root=r"D:\Other"))  # 映像不在 System32\conhost.exe：一路到根仍找不到
        cases = {
            "parent reused": lambda: self.k.processes.__setitem__(300, (400, 9000, SID, False, "cmd.exe")),
            "foreign user": lambda: self.k.processes.__setitem__(300, (400, 3000, OTHER_SID, False, "cmd.exe")),
            "parent exited": lambda: self.k.exited.add(300),
        }
        for label, mutate in cases.items():
            with self.subTest(label):
                saved, exited = dict(self.k.processes), set(self.k.exited)
                mutate()
                self.assertIsNone(self.bind())
                self.k.processes, self.k.exited = saved, exited

    def test_depth_is_bounded_at_twelve(self) -> None:
        # relay 自己是第 0 层；第 12 层的 conhost 能绑定，第 13 层的不再找（Opus 实现审计 P3-2：M41/M42）
        for level, expected in ((12, 100 + 12), (13, None)):
            with self.subTest(level=level):
                chain = {100 + i: (101 + i, 10000 - i, SID, False, "python.exe") for i in range(level)}
                chain[100 + level] = (0, 1, SID, False, "conhost.exe")
                self.k.processes = chain
                self.k.images = ({pid: r"C:\py\python.exe" for pid in chain}
                                 | {100 + level: r"C:\Windows\System32\conhost.exe"})
                anchor = self.bind()
                self.assertEqual(None if anchor is None else anchor.pid, expected)
                if anchor is not None:
                    anchor.close()

    def test_handle_generation_is_checked_when_opening(self) -> None:
        with self.assertRaises(OSError):
            self.k.api.open_wait_handle(400, 1999)


if __name__ == "__main__":
    unittest.main()
