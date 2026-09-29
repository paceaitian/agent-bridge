"""协作桥账本：单次领取、崩溃恢复、schema 拒绝、保留与上限。"""

from __future__ import annotations

import os
from typing import Any
from pathlib import Path
import sqlite3
import stat
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

import uuid

from agentstatus_bridge.model import Consumption, Delivery, Flow, Phase, Work, describe
from agentstatus_bridge.store import (
    DB_NAME,
    FINISHED_RETENTION_SECONDS,
    MAX_BODY_BYTES,
    MAX_EVENTS_PER_TASK,
    Store,
    StoreError,
)
from bridge_support import FakeProc, ref


class BridgeStoreTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = TemporaryDirectory()
        self.root = Path(self._tmp.name) / "bridge"
        self.store = Store.open(self.root)

    def tearDown(self) -> None:
        self.store.close()
        self._tmp.cleanup()

    def _create(self, **overrides: object):
        values: dict[str, object] = {
            "title": "实现",
            "flow": Flow.HANDOFF,
            "origin": None,
            "origin_class": "bypass",
            "reviewer": None,
            "target": ref(),
            "body": "请实现 X",
            "refs": [],
            "now": 1000.0,
        }
        values.update(overrides)
        return self.store.create_task(**values)  # type: ignore[arg-type]

    def _delivered(self, delivery: Delivery, at: float) -> str:
        _task, attempt = self._create(now=at)
        self.assertTrue(self.store.begin_send(attempt.id, now=at, pid=1, start_ticks="1"))
        self.store.finish_send(attempt.id, delivery=delivery, reason="test", provider_ref=None, detail={}, now=at)
        return attempt.id

    def test_window_index_is_added_to_existing_ledgers_without_rewrites(self) -> None:
        # 纯增量辅助索引：老账本打开时补建，已存在时打开不写账本（DESIGN §45.29）
        def has_index() -> bool:
            with sqlite3.connect(self.root / DB_NAME) as conn:
                return conn.execute(
                    "SELECT 1 FROM sqlite_master WHERE type = 'index' AND name = 'attempts_by_delivery_at'"
                ).fetchone() is not None

        self.assertTrue(has_index())
        self.store.close()
        with sqlite3.connect(self.root / DB_NAME) as conn:
            conn.execute("DROP INDEX attempts_by_delivery_at")
        self.assertFalse(has_index())
        self.store = Store.open(self.root)
        self.assertTrue(has_index())
        revision = self.store.ledger_revision()
        self.store.close()
        self.store = Store.open(self.root)
        self.assertEqual(self.store._conn.total_changes, 0)  # pyright: ignore[reportPrivateUsage]
        self.assertEqual(self.store.ledger_revision(), revision)

    def test_index_that_cannot_be_built_does_not_block_opening(self) -> None:
        # 账本只读或磁盘满时补建失败：照常打开、照常读，能写之后再补（Opus 审计 P3-1）
        task, _attempt = self._create()
        self.store.close()
        with sqlite3.connect(self.root / DB_NAME) as conn:
            conn.execute("DROP INDEX attempts_by_delivery_at")
        original = Store.__dict__["_transaction"]  # 打补丁之前取原方法
        calls = {"n": 0}

        def failing(store: Store):  # type: ignore[no-untyped-def]
            calls["n"] += 1
            if calls["n"] == 2:  # 第 1 次是 _migrate，第 2 次是补建索引
                raise StoreError("store_write_failed")
            return original(store)

        with patch.object(Store, "_transaction", autospec=True, side_effect=failing):
            self.store = Store.open(self.root)
        self.assertEqual(calls["n"], 2)
        self.assertEqual([item.id for item in self.store.list_tasks()], [task.id])
        with sqlite3.connect(self.root / DB_NAME) as conn:
            self.assertIsNone(
                conn.execute("SELECT 1 FROM sqlite_master WHERE name = 'attempts_by_delivery_at'").fetchone()
            )
        self.store.close()
        self.store = Store.open(self.root)
        with sqlite3.connect(self.root / DB_NAME) as conn:
            self.assertIsNotNone(
                conn.execute("SELECT 1 FROM sqlite_master WHERE name = 'attempts_by_delivery_at'").fetchone()
            )

    def _open_with_authorizer(self, deny: set[int]) -> Store:
        real_connect = sqlite3.connect

        def connect(*args: object, **kwargs: object) -> sqlite3.Connection:
            conn = real_connect(*args, **kwargs)  # type: ignore[arg-type]
            conn.set_authorizer(lambda action, *_rest: sqlite3.SQLITE_DENY if action in deny else sqlite3.SQLITE_OK)
            return conn

        with patch("agentstatus_bridge.store.sqlite3.connect", side_effect=connect):
            return Store.open(self.root)

    def test_index_build_failure_in_a_real_transaction_leaves_a_clean_connection(self) -> None:
        # 让 CREATE INDEX 在真实事务里失败：连接要回到空闲，后续写入仍是原子事务（Opus 复审 P3-a）
        self.store.close()
        with sqlite3.connect(self.root / DB_NAME) as conn:
            conn.execute("DROP INDEX attempts_by_delivery_at")
        self.store = self._open_with_authorizer({sqlite3.SQLITE_CREATE_INDEX})
        conn = self.store._conn  # pyright: ignore[reportPrivateUsage]
        self.assertEqual((self.store._depth, conn.in_transaction), (0, False))  # pyright: ignore[reportPrivateUsage]
        task, _attempt = self._create()
        self.assertEqual([item.id for item in self.store.list_tasks()], [task.id])
        conn.set_authorizer(None)

    def test_index_build_failure_with_failed_rollback_refuses_the_connection(self) -> None:
        # 补建失败且回滚也失败：不能把仍占着事务的连接交出去（Codex 复审 R02）
        self.store.close()
        with sqlite3.connect(self.root / DB_NAME) as conn:
            conn.execute("DROP INDEX attempts_by_delivery_at")
        real_connect = sqlite3.connect
        opened: list[sqlite3.Connection] = []

        def connect(*args: object, **kwargs: object) -> sqlite3.Connection:
            conn = real_connect(*args, **kwargs)  # type: ignore[arg-type]
            state = {"index": False}

            def authorize(action: int, arg1: object, *_rest: object) -> int:
                if action == sqlite3.SQLITE_CREATE_INDEX:
                    state["index"] = True
                    return sqlite3.SQLITE_DENY
                if action == sqlite3.SQLITE_TRANSACTION and arg1 == "ROLLBACK" and state["index"]:
                    return sqlite3.SQLITE_DENY
                return sqlite3.SQLITE_OK

            conn.set_authorizer(authorize)
            opened.append(conn)
            return conn

        with patch("agentstatus_bridge.store.sqlite3.connect", side_effect=connect):
            with self.assertRaises(StoreError):
                Store.open(self.root)
        with self.assertRaises(sqlite3.ProgrammingError):
            opened[0].execute("SELECT 1")  # 已被 Store.open 关闭
        self.store = Store.open(self.root)

    def test_readonly_failure_at_commit_is_classified_and_rolled_back(self) -> None:
        # COMMIT 阶段报只读：原因码为 store_readonly，连接退出事务、之后仍可写（Codex 复审 C01 / Opus 第二轮复审）
        real = self.store._conn  # pyright: ignore[reportPrivateUsage]

        class CommitFails:
            def __init__(self) -> None:
                self.armed = True

            def execute(self, sql: str, *args: Any) -> sqlite3.Cursor:
                if sql == "COMMIT" and self.armed:
                    self.armed = False
                    error = sqlite3.OperationalError("attempt to write a readonly database")
                    # 用扩展码：只认基础码 SQLITE_READONLY 的改法也要被发现（Opus 末轮复审）
                    error.sqlite_errorname = "SQLITE_READONLY_DBMOVED"  # type: ignore[attr-defined]
                    raise error
                return real.execute(sql, *args)

            def __getattr__(self, name: str) -> object:
                return getattr(real, name)

        self.store._conn = CommitFails()  # type: ignore[assignment]  # pyright: ignore[reportPrivateUsage]
        try:
            with self.assertRaises(StoreError) as caught:
                self._create()
            self.assertEqual(caught.exception.code, "store_readonly")
            self.assertEqual((self.store._depth, real.in_transaction), (0, False))  # pyright: ignore[reportPrivateUsage]
            self.assertEqual(self.store.list_tasks(), [], "回滚后没有半截写入")
            task, _attempt = self._create()
            self.assertEqual([item.id for item in self.store.list_tasks()], [task.id])
        finally:
            self.store._conn = real  # pyright: ignore[reportPrivateUsage]

    def test_readonly_ledger_reports_readonly_instead_of_busy(self) -> None:
        # 只读打开后建出的 -wal/-shm 也是只读：主文件改回可写后仍写不进，要报「不可写」而不是「正忙」（Opus 复审 P3-d）
        self._create()
        self.store.close()
        db = self.root / DB_NAME
        os.chmod(db, 0o400)
        try:
            self.store = Store.open(self.root)
            with self.assertRaises(StoreError) as caught:
                self._create()
            self.assertEqual(caught.exception.code, "store_readonly")
            os.chmod(db, 0o600)
            with self.assertRaises(StoreError) as reopened:
                Store.open(self.root)
            self.assertEqual(reopened.exception.code, "store_readonly")
        finally:
            for item in self.root.iterdir():
                if item.is_file():
                    os.chmod(item, 0o600)

    def test_recent_delivery_check_filters_in_sql_and_uses_the_index(self) -> None:
        old = self._delivered(Delivery.WRITTEN, 100.0)
        self._delivered(Delivery.WRITTEN, 1000.0)
        queued = self._delivered(Delivery.QUEUED, 1000.0)
        self.assertTrue(self.store.has_recent_delivery(Delivery.WRITTEN, after=999.0))
        self.assertFalse(self.store.has_recent_delivery(Delivery.WRITTEN, after=1000.0), "delivery_at 必须晚于 after")
        self.assertFalse(self.store.has_recent_delivery(Delivery.HELD, after=0.0))
        self.assertTrue(self.store.has_recent_delivery(Delivery.QUEUED, after=999.0, unconsumed=True))
        self.store.set_consumption(queued, Consumption.LEFT_QUEUE, now=1001.0)
        self.assertFalse(self.store.has_recent_delivery(Delivery.QUEUED, after=999.0, unconsumed=True))
        self.assertTrue(self.store.has_recent_delivery(Delivery.QUEUED, after=999.0))
        self.assertEqual(
            [item.id for item in self.store.attempts_in((Delivery.WRITTEN,), delivered_since=100.0)][0], old,
            "窗口下界包含等于",
        )
        self.assertEqual(len(self.store.attempts_in((Delivery.WRITTEN,), delivered_since=100.5)), 1)
        # 没有投递时间的记录保留，与原先 Python 侧判断一致（Codex 审计 F01）
        with sqlite3.connect(self.root / DB_NAME) as conn:
            conn.execute("UPDATE attempts SET delivery_at = NULL WHERE id = ?", (old,))
        self.assertIn(old, [item.id for item in self.store.attempts_in((Delivery.WRITTEN,), delivered_since=500.0)])
        self.assertEqual(len(self.store.attempts_in((Delivery.WRITTEN,))), 2)
        # 抓取方法实际执行的 SQL，确认走 (delivery, delivery_at) 覆盖索引而不是读行
        statements: list[str] = []
        conn = self.store._conn  # pyright: ignore[reportPrivateUsage]
        conn.set_trace_callback(statements.append)
        try:
            self.store.has_recent_delivery(Delivery.WRITTEN, after=999.0)
        finally:
            conn.set_trace_callback(None)
        [sql] = [item for item in statements if "EXISTS" in item]
        plan = " ".join(str(row[-1]) for row in conn.execute(f"EXPLAIN QUERY PLAN {sql}"))
        self.assertIn("COVERING INDEX attempts_by_delivery_at", plan)

    def test_created_task_is_queued_and_private(self) -> None:
        task, attempt = self._create()
        self.assertEqual(attempt.delivery, Delivery.PENDING)
        self.assertEqual(attempt.sender_class, "bypass")
        self.assertEqual(describe(task, self.store.attempts(task.id)).phase, Phase.QUEUED)
        self.assertEqual(stat.S_IMODE(self.root.stat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE((self.root / DB_NAME).stat().st_mode), 0o600)
        self.assertEqual([item.id for item in self.store.list_tasks()], [task.id])

    def test_symlinked_state_directory_is_refused(self) -> None:
        link = Path(self._tmp.name) / "link"
        os.symlink(self.root, link)
        with self.assertRaises(StoreError) as caught:
            Store.open(link)
        self.assertEqual(caught.exception.code, "store_unavailable")

    def test_send_claim_is_exclusive_across_connections(self) -> None:
        _task, attempt = self._create()
        with Store.open(self.root) as other:
            self.assertTrue(self.store.begin_send(attempt.id, now=1.0, pid=os.getpid(), start_ticks="1"))
            self.assertFalse(other.begin_send(attempt.id, now=1.0, pid=os.getpid(), start_ticks="1"))

    def test_paused_or_finished_task_is_not_claimed(self) -> None:
        task, attempt = self._create()
        self.store.update_task(task.id, now=2.0, event="paused", control="paused")
        self.assertFalse(self.store.begin_send(attempt.id, now=3.0, pid=1, start_ticks="1"))
        self.store.update_task(task.id, now=4.0, event="closed", control="active", closed_at=4.0)
        self.assertFalse(self.store.begin_send(attempt.id, now=5.0, pid=1, start_ticks="1"))

    def test_interrupted_send_becomes_unknown_but_live_sender_is_untouched(self) -> None:
        proc = FakeProc(Path(self._tmp.name) / "proc")
        proc.add(4242, comm="python3", start="7")
        _task, dead = self._create()
        _task2, live = self._create()
        self.store.begin_send(dead.id, now=1.0, pid=5151, start_ticks="9")
        self.store.begin_send(live.id, now=1.0, pid=4242, start_ticks="7")
        recovered = self.store.recover_interrupted(now=2.0, proc_root=proc.root)
        self.assertEqual(recovered, 1)
        dead_after = self.store.get_attempt(dead.id)
        live_after = self.store.get_attempt(live.id)
        assert dead_after is not None and live_after is not None
        self.assertEqual(dead_after.delivery, Delivery.UNKNOWN)
        self.assertEqual(dead_after.delivery_reason, "interrupted_during_send")
        self.assertEqual(live_after.delivery, Delivery.SENDING)

    def test_finish_send_only_applies_to_sending(self) -> None:
        _task, attempt = self._create()
        self.assertFalse(
            self.store.finish_send(
                attempt.id, delivery=Delivery.QUEUED, reason="codex_queued", provider_ref="x", detail={}, now=1.0
            )
        )
        self.store.begin_send(attempt.id, now=1.0, pid=1, start_ticks="1")
        self.assertTrue(
            self.store.finish_send(
                attempt.id, delivery=Delivery.QUEUED, reason="codex_queued", provider_ref="x", detail={}, now=2.0
            )
        )
        found = self.store.find_attempt_by_provider_ref("x")
        assert found is not None
        self.assertEqual(found.id, attempt.id)
        self.assertEqual(found.delivery, Delivery.QUEUED)

    def test_newer_schema_is_refused_without_changes(self) -> None:
        self.store.close()
        path = self.root / DB_NAME
        with sqlite3.connect(path) as connection:
            connection.execute("PRAGMA user_version=99")
        before = path.read_bytes()
        with self.assertRaises(StoreError) as caught:
            Store.open(self.root)
        self.assertEqual(caught.exception.code, "schema_too_new")
        self.assertEqual(path.read_bytes(), before)
        self.store = Store.open(Path(self._tmp.name) / "fresh")

    def test_prune_removes_only_old_finished_tasks(self) -> None:
        old, _ = self._create()
        open_task, _ = self._create()
        self.store.update_task(old.id, now=1.0, event="closed", closed_at=1.0)
        removed = self.store.prune(now=1.0 + FINISHED_RETENTION_SECONDS + 10)
        self.assertEqual(removed, 1)
        self.assertIsNone(self.store.get_task(old.id))
        self.assertIsNotNone(self.store.get_task(open_task.id))

    def test_message_limits(self) -> None:
        with self.assertRaises(StoreError) as empty:
            self._create(body="   ")
        self.assertEqual(empty.exception.code, "empty_message")
        with self.assertRaises(StoreError) as large:
            self._create(body="x" * (MAX_BODY_BYTES + 1))
        self.assertEqual(large.exception.code, "message_too_large")

    def test_task_prefix_resolution_reports_ambiguity(self) -> None:
        ids = iter(["aaaa1111" + "0" * 24, "1" * 32, "2" * 32, "aaaa2222" + "0" * 24, "3" * 32, "4" * 32])
        with patch("agentstatus_bridge.store.new_id", side_effect=lambda: next(ids)):
            first, _ = self._create()
            self._create()
        with self.assertRaises(StoreError) as ambiguous:
            self.store.resolve_task("aaaa")
        self.assertEqual(ambiguous.exception.code, "task_ambiguous")
        self.assertEqual(self.store.resolve_task("aaaa1111").id, first.id)
        with self.assertRaises(StoreError) as short_prefix:
            self.store.resolve_task("aaa")
        self.assertEqual(short_prefix.exception.code, "task_not_found")

    def test_timeline_is_bounded(self) -> None:
        task, _ = self._create()
        for index in range(MAX_EVENTS_PER_TASK + 20):
            self.store.add_event(task.id, "progress", now=float(index))
        self.assertEqual(len(self.store.events(task.id, limit=1000)), MAX_EVENTS_PER_TASK)

    def test_v1_ledger_is_migrated_in_place(self) -> None:
        task, attempt = self._create()
        self.store.close()
        with sqlite3.connect(self.root / DB_NAME) as connection:
            connection.execute("ALTER TABLE tasks DROP COLUMN options")
            connection.execute("ALTER TABLE attempts DROP COLUMN options")
            connection.execute("PRAGMA user_version=1")
        self.store = Store.open(self.root)
        self.assertEqual(self.store._conn.execute("PRAGMA user_version").fetchone()[0], 2)  # pyright: ignore[reportPrivateUsage]
        migrated = self.store.get_task(task.id)
        migrated_attempt = self.store.get_attempt(attempt.id)
        assert migrated is not None and migrated_attempt is not None
        self.assertEqual((migrated.options, migrated_attempt.options), ({}, {}))
        self.assertTrue(migrated.notify_origin)
        self.assertFalse(migrated_attempt.allow_shared)

    def test_transaction_rolls_back_every_nested_write(self) -> None:
        task, attempt = self._create()
        with self.assertRaises(RuntimeError):
            with self.store.transaction():
                self.store.set_work(attempt.id, work=Work.RESULT, result={"note": "x"}, now=2.0, event="result")
                self.store.update_task(task.id, now=2.0, event="verdict_changes", verdict="changes_requested")
                raise RuntimeError("interrupted")
        unchanged = self.store.get_attempt(attempt.id)
        assert unchanged is not None
        self.assertEqual(unchanged.work, Work.AWAITING_ACK)
        self.assertIsNone(self.store.get_task(task.id).verdict)  # type: ignore[union-attr]
        self.assertNotIn("result", [event["kind"] for event in self.store.events(task.id)])
        # 回滚后连接仍可继续使用
        self.store.add_event(task.id, "progress", now=3.0)

    def test_known_message_reference_is_recorded_before_the_call(self) -> None:
        _task, attempt = self._create()
        native = str(uuid.UUID(hex=attempt.message_id))
        self.assertTrue(self.store.begin_send(attempt.id, now=1.0, pid=1, start_ticks="1", provider_ref=native))
        self.store.finish_send(
            attempt.id, delivery=Delivery.UNKNOWN, reason="claude_socket_write_failed", provider_ref=None, detail={}, now=2.0
        )
        found = self.store.find_attempt_by_provider_ref(native)
        assert found is not None
        self.assertEqual((found.id, found.provider_ref), (attempt.id, native))
        by_message = self.store.find_attempt_by_message_uuid(native.upper())
        assert by_message is not None
        self.assertEqual(by_message.id, attempt.id)
        self.assertIsNone(self.store.find_attempt_by_message_uuid("not-a-uuid"))

    def test_archived_risk_counter(self) -> None:
        self.assertEqual(self.store.archived_risk_count(), 0)
        self.store.note_archived_risk()
        self.store.note_archived_risk()
        self.assertEqual(self.store.archived_risk_count(), 2)


if __name__ == "__main__":
    unittest.main()
