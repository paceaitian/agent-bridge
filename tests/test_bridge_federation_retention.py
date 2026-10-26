"""P5 设备侧留存回收（DESIGN §88.3/§88.4，T15 的设备部分）：两台设备 + 真实 hub 会话，结束 30 天后清内容留墓碑。

覆盖：结束且最后引用满 30 天才清正文/报告正文/附件路径与文件，去重与决定墓碑保留、迟到重放仍是重复且不再 native；
未满 30 天、最后引用晚于终态、未结发件/待裁决报告都延期；活任务附件永不回收；同 SHA 仍被活任务引用的冻结副本保留；
文件删除失败下轮重试（两步）；刚被重新冻结复用的副本保留；孤儿 part 24 小时；relay 每小时跑一轮。
"""

from __future__ import annotations

import json
import os
import time
import unittest
from pathlib import Path
from typing import Any
from unittest.mock import patch

import bridge_support  # noqa: F401  导入即隔离宿主会话环境

from agentstatus_bridge.closure import ACCEPTED, CLOSED
from agentstatus_bridge.federation import authority, mirror, relay as relay_module, retention
from agentstatus_bridge.federation.fedstore import FedTask

from test_bridge_federation_relay import Device, RelayTestCase

DAY = 86_400_000
WALL_DAY = 86_400


def finish_natives(device: Device) -> None:
    """本测试不跑 worker：照 worker 结果事务把作业记成已投、收件记成已应用（只为让任务没有未结引用）。"""
    with device.store.transaction() as conn:
        conn.execute("UPDATE fed_inbox SET apply_state='applied' WHERE apply_state='ready' AND msg_id IN"
                     " (SELECT msg_id FROM fed_native_sends WHERE state='prepared')")
        conn.execute("UPDATE fed_native_sends SET state='finished' WHERE state='prepared'")


class RetentionCase(RelayTestCase):
    def setUp(self) -> None:
        super().setUp()
        for device in (self.a, self.b):
            # 只在测试临时根下删除：先钉住回收会碰的三个位置
            for path in (device.paths.staging, device.paths.parts, device.paths.delivery_base("x")):
                self.assertTrue(str(path).startswith(str(self.root)), path)

    @staticmethod
    def wall_after(days: float) -> int:
        """真实时间轴（只用来比文件 mtime）：文件现在才写，过 days 天后的墙钟毫秒。"""
        return int((time.time() + days * WALL_DAY) * 1000)

    def round_trip(self) -> None:
        for _ in range(2):
            self.tick()
            self.a.cycle()
            self.tick()
            self.b.cycle()
        self.tick()
        self.a.cycle()

    def finished_task(self, content: bytes = b"# spec\n") -> tuple[FedTask, str]:
        """A→B 带附件交接、B 带附件交结果、A 验收并送达结束回执；两边作业都已投、发件都已落账。"""
        refs = self.freeze(self.a, ("任务书.md", content))
        task, first = self.create(refs)
        self.round_trip()
        finish_natives(self.b)
        self.b_report(task.task_id, "result", self.freeze(self.b, ("结果.txt", b"result:" + content)))
        self.round_trip()
        finish_natives(self.a)
        current = self.a.store.get_task(self.a.device_id, task.task_id)
        assert current is not None
        authority.finish(self.a.store, self.a.ident, current, state=ACCEPTED, reason=None, decider="owner",
                         sender=authority.actor_for(self.origin, wire_token="claude@vm"), sender_class="bypass",
                         now=self.clock.now)
        self.round_trip()
        finish_natives(self.a)
        finish_natives(self.b)
        self.round_trip()
        return task, first.msg_id

    def sweep(self, device: Device, *, days: float, wall_days: float = 2) -> retention.SweepResult:
        return retention.sweep(device.store, device.paths, now=self.clock.now + int(days * DAY),
                               wall_ms=self.wall_after(wall_days))

    def table_counts(self, device: Device) -> dict[str, int]:
        conn = device.store.connection
        return {table: int(conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0])
                for table in ("fed_operations", "fed_outbox", "fed_inbox", "fed_reports", "fed_report_decisions",
                              "fed_native_sends", "fed_attempts", "fed_attachments")}

    def files(self, device: Device) -> list[Path]:
        found: list[Path] = []
        for base in (device.paths.staging, device.paths.delivery_base(device.store.ledger_instance_id())):
            if base.exists():
                found.extend(path for path in base.rglob("*") if path.is_file())
        return found


class CompactionTests(RetentionCase):
    def test_finished_task_compacts_after_30_days_and_keeps_tombstones(self) -> None:
        task, first_msg = self.finished_task()
        replay = self.a.store.outbox_item(first_msg)
        assert replay is not None
        envelope, digest = json.loads(replay["envelope_json"]), str(replay["payload_hash"])
        before = {device.name: self.table_counts(device) for device in (self.a, self.b)}
        self.assertTrue(self.files(self.a) and self.files(self.b))
        for device in (self.a, self.b):
            result = self.sweep(device, days=31)
            self.assertEqual((result.compacted, result.deferred), (1, 0), device.name)
            self.assertEqual(self.files(device), [], device.name)  # 冻结副本与交付叶都已删
            self.assertEqual(self.table_counts(device), before[device.name])  # 去重/决定墓碑一行不少
            stored = device.store.get_task(self.a.device_id, task.task_id)
            assert stored is not None
            self.assertIsNotNone(stored.state.get("contentExpiredAt"))
            for attempt in device.store.attempts(self.a.device_id, task.task_id):
                self.assertEqual(attempt.body, "")
                self.assertNotIn("note", attempt.effective_work.get("result") or {})
            for row in device.store.reports(self.a.device_id, task.task_id):
                self.assertNotIn("note", row["report"])
                self.assertEqual(row["report"]["kind"], "result")
            rows = [row for attempt in device.store.attempts(self.a.device_id, task.task_id)
                    for row in device.store.attachments(attempt.msg_id)]
            self.assertTrue(rows)
            for row in rows:
                self.assertEqual((row["state"], row["original_path"], row["local_relpath"]), ("expired", "", None))
                self.assertIsNotNone(row["sha256"])  # 紧凑 manifest 保留 hash/size/transfer
        # 迟到重放：去重墓碑还在，按重复处理，不新建 native
        natives = self.table_counts(self.b)["fed_native_sends"]
        again = mirror.receive(self.b.store, self.b.ident, envelope, source_device=self.a.device_id,
                               payload_hash=digest, now=self.clock.now + 32 * DAY)
        self.assertEqual(again.status, "duplicate")
        self.assertEqual(self.table_counts(self.b)["fed_native_sends"], natives)
        # 已清过的任务不再处理
        self.assertEqual(self.sweep(self.a, days=40).compacted, 0)

    def test_not_due_late_reference_and_unresolved_outbox_defer(self) -> None:
        task, _ = self.finished_task()
        self.assertEqual(self.sweep(self.a, days=29).compacted, 0)
        # 终态后 20 天又有引用（迟到报告被拒等事件）：从最后引用起算
        self.a.store.add_event(self.a.device_id, task.task_id, "report_rejected", now=self.clock.now + 20 * DAY)
        self.assertEqual(self.sweep(self.a, days=31).compacted, 0)
        self.assertEqual(self.sweep(self.a, days=51).compacted, 1)
        # B 在终态后还有一条没发出去的发件：整个任务延期，正文与文件都不动
        with self.b.store.transaction() as conn:
            conn.execute("UPDATE fed_outbox SET state='ready' WHERE msg_id=(SELECT msg_id FROM fed_outbox LIMIT 1)")
        kept = self.files(self.b)
        result = self.sweep(self.b, days=31)
        self.assertEqual((result.compacted, result.deferred), (0, 1))
        self.assertEqual(self.files(self.b), kept)
        stored = self.b.store.get_task(self.a.device_id, task.task_id)
        assert stored is not None
        self.assertIsNone(stored.state.get("contentExpiredAt"))

    def test_pending_report_decision_defers(self) -> None:
        task, first = self.create()
        self.round_trip()
        finish_natives(self.b)
        self.b_report(task.task_id, "result")  # 还没交给 A：没有决定
        with self.b.store.transaction() as conn:  # 只为构造：镜像先收到终态（报告仍待裁决）
            row = conn.execute("SELECT state_json FROM fed_tasks").fetchone()
            state = json.loads(row[0])
            state["closedAt"] = self.clock.now
            conn.execute("UPDATE fed_tasks SET state_json=?", (json.dumps(state),))
            conn.execute("UPDATE fed_outbox SET state='received'")
        result = self.sweep(self.b, days=31)
        self.assertEqual((result.compacted, result.deferred), (0, 1))
        self.assertIsNotNone(self.b.store.attempt_by_msg(first.msg_id))

    def test_active_task_attachments_are_never_reclaimed(self) -> None:
        refs = self.freeze(self.a, ("a.md", b"active"))
        self.create(refs)
        self.round_trip()
        finish_natives(self.b)
        kept = (self.files(self.a), self.files(self.b))
        for device in (self.a, self.b):
            result = self.sweep(device, days=400, wall_days=400)
            self.assertEqual((result.compacted, result.files), (0, 0))
        self.assertEqual((self.files(self.a), self.files(self.b)), kept)


class SuppressedWorkTests(RetentionCase):
    """B 上被抑制的作业收件行同事务置 applied（Opus 审计 P2-2）：取消/关闭/免投的结束回执都不让任务永久延期。"""

    def test_cancelled_then_closed_work_compacts_on_b(self) -> None:
        task, first = self.create()
        self.a.cycle()
        self.tick()
        self.b.cycle()  # B 上 prepared，尚未投递
        current = self.a.store.get_task(self.a.device_id, task.task_id)
        assert current is not None
        authority.request_cancel(self.a.store, self.a.ident, current, now=self.clock.now)
        self.round_trip()
        current = self.a.store.get_task(self.a.device_id, task.task_id)
        assert current is not None
        authority.finish(self.a.store, self.a.ident, current, state=CLOSED, reason=None, decider="owner",
                         sender=None, sender_class="unknown", now=self.clock.now)
        self.round_trip()
        natives = {row["msg_id"]: row["state"] for row in self.b.store.natives_in(("suppressed", "prepared"))}
        self.assertEqual(natives.get(first.msg_id), "suppressed")
        self.assertNotIn("prepared", natives.values())  # 结束回执在全部工作未投时免投（closure_not_needed）
        ready = self.b.store.connection.execute("SELECT COUNT(*) FROM fed_inbox WHERE apply_state='ready'").fetchone()[0]
        self.assertEqual(ready, 0)  # 被抑制作业的收件行已 applied，不是永远 ready
        result = self.sweep(self.b, days=40)
        self.assertEqual((result.compacted, result.deferred), (1, 0))

    def test_deferred_tasks_do_not_starve_later_due_ones(self) -> None:
        created = [self.create()[0] for _ in range(4)]
        for task in created:
            current = self.a.store.get_task(self.a.device_id, task.task_id)
            assert current is not None
            authority.finish(self.a.store, self.a.ident, current, state=CLOSED, reason=None, decider="owner",
                             sender=None, sender_class="unknown", now=self.clock.now)
        due = max(created, key=lambda item: item.task_id)  # 排在最后：没有轮转就永远轮不到
        with self.a.store.transaction() as conn:  # 只让它没有未结引用；其余三个的发件仍待发 → 延期
            conn.execute("UPDATE fed_outbox SET state='received' WHERE json_extract(envelope_json,'$.taskId')=?",
                         (due.task_id,))
            conn.execute("UPDATE fed_native_sends SET state='finished' WHERE msg_id IN"
                         " (SELECT msg_id FROM fed_attempts WHERE task_id=?)", (due.task_id,))
        with patch.object(retention, "SWEEP_TASKS", 2):
            compacted = sum(self.sweep(self.a, days=31).compacted for _ in range(2))
        self.assertEqual(compacted, 1)
        state = self.a.store.get_task(self.a.device_id, due.task_id)
        assert state is not None
        self.assertIsNotNone(state.state.get("contentExpiredAt"))


class FileReclaimTests(RetentionCase):
    def test_shared_blob_kept_while_another_task_references_it(self) -> None:
        self.finished_task(b"same bytes")
        refs = self.freeze(self.a, ("again.md", b"same bytes"))  # 同内容：同一个 staging 副本
        self.create(refs)
        self.sweep(self.a, days=31)
        sha = refs[0]["sha256"]
        self.assertTrue((self.a.paths.staging / f"{sha}.blob").exists())  # 活任务还要上传/重传

    def test_unlink_failure_is_retried_next_sweep(self) -> None:
        self.finished_task()
        real_unlink = os.unlink
        calls: list[str] = []

        def failing(path: Any, *args: Any, **kwargs: Any) -> None:
            if str(path).startswith(str(self.a.root)):
                calls.append(str(path))
                raise PermissionError(13, "denied")
            real_unlink(path, *args, **kwargs)

        kept = self.files(self.a)
        self.assertTrue(any(path.suffix == ".blob" for path in kept) and any(path.suffix != ".blob" for path in kept))
        with patch.object(retention.os, "unlink", side_effect=failing):
            self.assertEqual(self.sweep(self.a, days=31).compacted, 1)
        self.assertEqual(len(calls), len(kept))
        self.assertEqual(sorted(self.files(self.a)), sorted(kept))
        self.sweep(self.a, days=32)  # 交付叶的行还在待删清单里，冻结副本每轮按目录重查
        self.assertEqual(self.files(self.a), [])

    def test_recently_refrozen_copy_is_kept(self) -> None:
        self.finished_task(b"reused")
        stale = time.time() - 3 * WALL_DAY
        for path in self.a.paths.staging.iterdir():
            os.utime(path, (stale, stale))
        refs = self.freeze(self.a, ("again.md", b"reused"))  # 冻结复用刷新 mtime，但还没建任务
        result = self.sweep(self.a, days=31, wall_days=0)
        self.assertEqual(result.compacted, 1)
        self.assertTrue((self.a.paths.staging / f"{refs[0]['sha256']}.blob").exists())


class StagingOrphanTests(RetentionCase):
    def test_unreferenced_frozen_copy_is_removed_after_24_hours(self) -> None:
        orphan = self.freeze(self.a, ("lost.md", b"never written to the ledger"))  # 冻结后崩溃：库里没有行
        live = self.freeze(self.a, ("live.md", b"active task"))
        self.create(live)
        fresh = self.freeze(self.a, ("fresh.md", b"just frozen"))
        stale = time.time() - 2 * WALL_DAY
        for refs in (orphan, live):
            path = self.a.paths.staging / f"{refs[0]['sha256']}.blob"
            os.utime(path, (stale, stale))
        result = self.sweep(self.a, days=0, wall_days=0)
        self.assertEqual(result.files, 1)
        exists = {name: (self.a.paths.staging / f"{refs[0]['sha256']}.blob").exists()
                  for name, refs in (("orphan", orphan), ("live", live), ("fresh", fresh))}
        self.assertEqual(exists, {"orphan": False, "live": True, "fresh": True})


class PathSafetyTests(RetentionCase):
    """回收只进自有根下的真实目录：任何一级被换成链接都不进去删（受害文件也在本测试临时根下）。"""

    def outside_victim(self, name: str) -> tuple[Path, Path]:
        outside = self.root / f"outside-{name}"
        outside.mkdir()
        victim = outside / name
        victim.write_bytes(b"not owned by ab")
        stale = time.time() - 3 * WALL_DAY
        os.utime(victim, (stale, stale))
        return outside, victim

    def test_part_directory_symlink_is_not_followed(self) -> None:
        outside, victim = self.outside_victim("keep.part")
        self.b.paths.parts.symlink_to(outside, target_is_directory=True)
        self.sweep(self.b, days=0, wall_days=0)
        self.assertTrue(victim.exists())

    def test_staging_directory_symlink_is_not_followed(self) -> None:
        outside, victim = self.outside_victim("a" * 64 + ".blob")
        self.b.paths.staging.symlink_to(outside, target_is_directory=True)
        self.sweep(self.b, days=0, wall_days=0)
        self.assertTrue(victim.exists())

    def test_delivery_parent_replaced_by_symlink_is_not_followed(self) -> None:
        self.finished_task()
        base = self.b.paths.delivery_base(self.b.store.ledger_instance_id())
        [leaf] = [path for path in base.rglob("*") if path.is_file()]
        moved = self.root / "moved-task-dir"
        leaf.parent.rename(moved)
        leaf.parent.symlink_to(moved, target_is_directory=True)  # 中间一级换成指向别处的链接
        result = self.sweep(self.b, days=31)
        self.assertEqual(result.compacted, 1)
        self.assertTrue((moved / leaf.name).exists())

    def test_replaced_delivery_leaf_is_kept(self) -> None:
        self.finished_task()
        base = self.b.paths.delivery_base(self.b.store.ledger_instance_id())
        [leaf] = [path for path in base.rglob("*") if path.is_file()]
        leaf.unlink()
        leaf.write_bytes(b"user put a different file here")  # 同名但不是落地时那个文件（ext4 可能复用同一 inode）
        self.sweep(self.b, days=31)
        self.assertTrue(leaf.exists())

    def test_edited_delivery_leaf_is_kept(self) -> None:
        self.finished_task()
        base = self.b.paths.delivery_base(self.b.store.ledger_instance_id())
        [leaf] = [path for path in base.rglob("*") if path.is_file()]
        with open(leaf, "ab") as handle:
            handle.write(b"edited by the agent")
        self.sweep(self.b, days=31)
        self.assertTrue(leaf.exists())


class OrphanPartTests(RetentionCase):
    def test_only_old_regular_part_files_in_owned_dirs(self) -> None:
        parts = self.b.paths.parts
        parts.mkdir(parents=True, exist_ok=True)
        self.b.paths.staging.mkdir(parents=True, exist_ok=True)
        old = parts / "m-0.part"
        fresh = parts / "m-1.part"
        frozen = self.b.paths.staging / "freeze-x.part"
        other = parts / "notes.txt"
        target = self.root / "outside.part"
        for path in (old, fresh, frozen, other, target):
            path.write_bytes(b"x")
        link = parts / "link.part"
        link.symlink_to(target)
        stale = time.time() - 2 * WALL_DAY
        for path in (old, frozen, other, target):
            os.utime(path, (stale, stale))
        os.utime(link, (stale, stale), follow_symlinks=False)
        result = self.sweep(self.b, days=0, wall_days=0)
        self.assertEqual(result.parts, 2)
        self.assertEqual(sorted(path.name for path in (old, frozen) if path.exists()), [])
        self.assertTrue(fresh.exists() and other.exists() and link.is_symlink() and target.exists())


class RelayScheduleTests(RetentionCase):
    def test_relay_runs_a_sweep_hourly(self) -> None:
        with patch.object(relay_module.retention, "sweep", return_value=retention.SweepResult()) as swept:
            self.a.cycle()
            self.tick(60_000)
            self.a.cycle()
            self.assertEqual(swept.call_count, 1)
            self.tick(relay_module.RETENTION_INTERVAL_MS)
            self.a.cycle()
            self.assertEqual(swept.call_count, 2)
        with patch.object(relay_module.retention, "sweep", side_effect=OSError(28, "full")):
            self.tick(relay_module.RETENTION_INTERVAL_MS)
            try:
                state = self.a.cycle()
            except OSError as error:
                self.fail(f"回收失败不能打断 relay 收发，实际抛出 {error!r}")
            self.assertEqual(state, "connected")


if __name__ == "__main__":
    unittest.main()
