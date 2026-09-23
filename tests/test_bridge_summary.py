"""协作桥摘要（DESIGN §45.14）：修订号触发器、一致读取、发布语义、映射与 token、接收方绑定与内容边界。"""

from __future__ import annotations

import copy
from dataclasses import replace
import fcntl
from collections.abc import Iterator
from itertools import count, product
import json
import os
from pathlib import Path
import signal
import stat
import subprocess
from tempfile import TemporaryDirectory
from typing import Any
import unittest
from unittest.mock import patch

from agentstatus_bridge import cli, summary
from agentstatus_bridge.naming import DEFAULT_COMMAND as CMD
from agentstatus_bridge.endpoints import PaneInfo, tmux_panes
from agentstatus_bridge.ids import opaque_id
from agentstatus_bridge.model import (
    CLOSURE_KIND,
    NOTICE_KIND_OPTION,
    Attempt,
    Consumption,
    Delivery,
    EndpointRef,
    Flow,
    Provider,
    Role,
    Task,
    Verdict,
    Work,
    describe,
)
from agentstatus_bridge.store import DB_NAME, Store
from agentstatus_bridge.worker import run_worker
from bridge_support import RecordingTransport, ref
import test_bridge_cli as cli_tests
import test_bridge_labels as label_tests
import test_bridge_worker as worker_tests


def new_task(store: Store, **changes: Any) -> tuple[Task, Attempt]:
    options: dict[str, Any] = {
        "title": "实现 X",
        "flow": Flow.HANDOFF,
        "origin": None,
        "origin_class": None,
        "reviewer": None,
        "target": ref(),
        "body": "正文哨兵 BODY-SENTINEL",
        "refs": [],
        "now": 100.0,
    }
    options.update(changes)
    return store.create_task(**options)


class LedgerCase(unittest.TestCase):
    def setUp(self) -> None:
        temporary = TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name) / "bridge"
        self.store = Store.open(self.root)
        self.addCleanup(lambda: self.store.close())

    def create(self, **changes: Any) -> tuple[Task, Attempt]:
        return new_task(self.store, **changes)

    def deliver(self, attempt: Attempt, delivery: Delivery, *, now: float = 110.0, detail: dict[str, Any] | None = None) -> None:
        self.assertTrue(self.store.begin_send(attempt.id, now=now - 1, pid=os.getpid(), start_ticks="1"))
        self.assertTrue(
            self.store.finish_send(
                attempt.id, delivery=delivery, reason="synthetic", provider_ref=None, detail=detail or {}, now=now
            )
        )

    def publish(self, **options: Any) -> summary.PublishResult:
        return summary.publish(self.store, self.root, **options)

    def document(self) -> dict[str, Any]:
        return json.loads((self.root / summary.SUMMARY_NAME).read_text(encoding="utf-8"))

    def entry(self, task_id: str) -> dict[str, Any]:
        return next(item for item in self.document()["tasks"] if item["id"] == task_id)

    def current(self, attempt: Attempt) -> Attempt:
        loaded = self.store.get_attempt(attempt.id)
        assert loaded is not None
        return loaded


class RevisionTests(LedgerCase):
    def test_each_of_the_nine_triggers_increments_the_revision(self) -> None:
        task, attempt = self.create()
        conn = self.store._conn
        names = {row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type = 'trigger'")}
        self.assertEqual(len({name for name in names if name.startswith("ab_revision_")}), 9)
        other_task, _ = self.create(now=101.0)
        extra = self.store.add_attempt(
            task.id, role=Role.NOTICE, target=ref(Provider.CLAUDE, "origin"), body="notice", refs=[], now=102.0,
            sender=None, sender_class=None,
        )
        statements = [
            ("tasks UPDATE", "UPDATE tasks SET title = title WHERE id = ?", (task.id,)),
            ("attempts UPDATE", "UPDATE attempts SET body = body WHERE id = ?", (attempt.id,)),
            ("events INSERT", "INSERT INTO events (task_id, attempt_seq, at, kind, detail) VALUES (?, NULL, 1, 'x', '{}')", (task.id,)),
            ("events UPDATE", "UPDATE events SET kind = kind WHERE kind = 'x'", ()),
            ("events DELETE", "DELETE FROM events WHERE kind = 'x'", ()),
            ("attempts DELETE", "DELETE FROM attempts WHERE id = ?", (extra.id,)),
            ("tasks DELETE", "DELETE FROM tasks WHERE id = ?", (other_task.id,)),
        ]
        for name, statement, params in statements:
            with self.subTest(operation=name):
                before = self.store.ledger_revision()[1]
                conn.execute(statement, params)
                self.assertGreater(self.store.ledger_revision()[1], before)
        # INSERT tasks / attempts 由 create_task、add_attempt 覆盖
        before = self.store.ledger_revision()[1]
        self.create(now=103.0)
        self.assertGreater(self.store.ledger_revision()[1], before)

    def test_revision_rolls_back_with_the_business_transaction(self) -> None:
        task, _ = self.create()
        before = self.store.ledger_revision()[1]
        with self.assertRaises(RuntimeError):
            with self.store.transaction():
                self.store.update_task(task.id, now=102.0, event="paused", control="paused")
                raise RuntimeError("rollback")
        self.assertEqual(self.store.ledger_revision()[1], before)

    def test_install_is_idempotent_and_old_code_keeps_writing(self) -> None:
        self.create()
        identity = self.store.ledger_revision()
        self.store.close()
        with Store.open(self.root) as reopened:
            self.assertEqual(reopened.ledger_revision(), identity)
            self.assertEqual(reopened._conn.execute("PRAGMA user_version").fetchone()[0], 2)
        # 旧版程序（没有安装步骤）打开已安装触发器的账本：照常读写，修订号随其写入递增
        with patch.object(Store, "_ensure_revision_objects", lambda _self: None):
            with Store.open(self.root) as old:
                task, _ = new_task(old, now=200.0)
                self.assertIsNotNone(old.get_task(task.id))
                self.assertGreater(old.ledger_revision()[1], identity[1])
        self.store = Store.open(self.root)

    def test_existing_v2_ledger_gains_triggers_without_rewriting_rows(self) -> None:
        legacy_root = self.root.parent / "legacy"
        with patch.object(Store, "_ensure_revision_objects", lambda _self: None):
            with Store.open(legacy_root) as legacy:
                new_task(legacy)
                self.assertEqual(legacy.ledger_revision(), ("", 0))
        with Store.open(legacy_root) as upgraded:
            ledger_id, revision = upgraded.ledger_revision()
            self.assertEqual((len(ledger_id), revision), (32, 0))
            (task,) = upgraded.list_tasks()
            upgraded.update_task(task.id, now=300.0, event="paused", control="paused")
            self.assertGreater(upgraded.ledger_revision()[1], 0)

    def test_read_snapshot_is_consistent_while_another_connection_commits(self) -> None:
        task, _ = self.create()
        other = Store.open(self.root)
        self.addCleanup(other.close)
        with self.store.read_snapshot():
            revision = self.store.ledger_revision()[1]
            self.assertEqual(len(self.store.list_tasks()), 1)
            other.update_task(task.id, now=200.0, event="closed", closed_at=200.0)
            self.assertEqual(self.store.ledger_revision()[1], revision)
            self.assertEqual(len(self.store.list_tasks()), 1)
        self.assertGreater(self.store.ledger_revision()[1], revision)
        self.assertEqual(self.store.list_tasks(), [])


class PublishTests(LedgerCase):
    def test_file_is_private_bounded_and_content_free(self) -> None:
        target = ref(Provider.CODEX, "native-thread-SECRET", pane="%7", label="proj\tname")
        task, attempt = self.create(title="标题\x07带控制符‮" + "长" * 120, target=target)
        self.deliver(attempt, Delivery.DELIVERED)
        self.store.set_work(
            attempt.id,
            work=Work.RESULT,
            result={"note": "NOTE-SENTINEL", "files": [{"path": "/secret/RESULT-PATH.md"}], "commit": "c0ffee" * 6},
            now=120.0,
            event="result",
            detail={"note": "NOTE-SENTINEL"},
        )
        self.assertEqual(self.publish().status, "written")
        path = self.root / summary.SUMMARY_NAME
        self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
        raw = path.read_text(encoding="utf-8")
        for secret in ("BODY-SENTINEL", "NOTE-SENTINEL", "RESULT-PATH", "native-thread-SECRET", "c0ffee"):
            self.assertNotIn(secret, raw)
        item = self.entry(task.id)
        self.assertEqual(len(item["title"]), summary.TITLE_CODEPOINTS)
        self.assertFalse({"\x07", "‮"} & set(item["title"]))
        self.assertEqual(item["target"]["label"], "codex@proj name")
        self.assertEqual((item["attention"]["kind"], item["next"]["command"]), ("result", f"{CMD} accept {task.id}"))
        self.assertEqual(self.document()["counts"], {"active": 1, "attention": 1, "result": 1, "decision": 0, "failure": 0})

    def test_if_stale_skips_only_a_valid_current_file(self) -> None:
        self.create()
        self.assertEqual(self.publish().status, "written")
        before = (self.root / summary.SUMMARY_NAME).read_bytes()
        self.assertEqual(self.publish().status, "fresh")
        self.assertEqual((self.root / summary.SUMMARY_NAME).read_bytes(), before)
        self.create(now=130.0)
        self.assertEqual(self.publish().status, "written")
        self.assertEqual(self.document()["counts"]["active"], 2)

    def test_same_revision_but_broken_or_foreign_file_is_rebuilt(self) -> None:
        self.create()
        self.publish()
        good = self.document()
        path = self.root / summary.SUMMARY_NAME
        variants: dict[str, object] = {
            "tasks_not_list": {**good, "tasks": "oops"},
            "counts_null": {**good, "counts": None},
            "future_schema": {**good, "schema": 2},
            "other_ledger": {**good, "ledgerId": "0" * 32},
        }
        for name, variant in variants.items():
            with self.subTest(variant=name):
                path.write_text(json.dumps(variant), encoding="utf-8")
                self.assertEqual(self.publish().status, "written")
                self.assertEqual(self.document()["ledgerRevision"], good["ledgerRevision"])
                self.assertTrue(summary.is_valid(self.document()))
        path.write_bytes(b"{not json")
        self.assertEqual(self.publish().status, "written")
        self.assertEqual(self.publish().status, "fresh")
        self.assertEqual(self.publish(force=True).status, "written")

    def test_replaced_ledger_with_lower_revision_is_rebuilt(self) -> None:
        for number in range(3):
            self.create(now=100.0 + number)
        self.publish()
        self.store.close()
        for suffix in ("", "-wal", "-shm"):
            (self.root / f"{DB_NAME}{suffix}").unlink(missing_ok=True)
        self.store = Store.open(self.root)
        self.assertEqual(self.publish().status, "written")
        self.assertEqual(self.document()["counts"]["active"], 0)

    def test_deliveries_publish_message_ids_of_everything_that_may_have_arrived(self) -> None:
        """只发布消息 id 与角色：明确没送到的不发布，结果不明与对方暂存的照常发布（DESIGN §45.26）。"""
        _, delivered = self.create(target=ref(Provider.CODEX, pane="%1"))
        self.deliver(delivered, Delivery.QUEUED, now=110.0)
        # 后续升级到 delivered 不改变发布内容：判定只看 id，不看任何时刻
        self.assertTrue(self.store.transition_delivery(
            delivered.id, expected=(Delivery.QUEUED,), new=Delivery.DELIVERED, reason="receiver_reported", now=190.0))
        _, unknown = self.create(target=ref(Provider.CLAUDE, "thread-unknown", pane="%2"), now=100.0)
        self.deliver(unknown, Delivery.UNKNOWN, now=120.0)
        _, held = self.create(target=ref(Provider.CLAUDE, "thread-held", pane="%3"), now=100.0)
        self.deliver(held, Delivery.HELD, now=130.0)
        _, cancelled = self.create(target=ref(Provider.CLAUDE, "thread-cancel", pane="%4"), now=100.0)
        self.assertTrue(self.store.transition_delivery(
            cancelled.id, expected=(Delivery.PENDING,), new=Delivery.CANCELLED, reason="synthetic", now=150.0))
        _, failed = self.create(target=ref(Provider.CLAUDE, "thread-fail", pane="%5"), now=100.0)
        self.deliver(failed, Delivery.FAILED, now=160.0)
        self.publish(now=200.0)
        published = {item["messageId"]: (item["role"], item["pane"], item["provider"])
                     for item in self.document()["deliveries"]}
        self.assertEqual(
            published,
            {delivered.message_id: ("handoff", "%1", "codex"),
             unknown.message_id: ("handoff", "%2", "claude"),
             held.message_id: ("handoff", "%3", "claude")},
        )
        self.assertTrue(summary.is_valid(self.document()))

    def test_deliveries_are_bounded_and_validated(self) -> None:
        """条数与逐项校验；老摘要没有这个字段仍然有效（DESIGN §45.26）。"""
        _, attempt = self.create(target=ref(Provider.CODEX, pane="%1"))
        self.deliver(attempt, Delivery.DELIVERED, now=110.0)
        self.publish(now=200.0)
        document = self.document()
        self.assertEqual(
            document["deliveries"],
            [{"messageId": attempt.message_id, "role": "handoff", "pane": "%1", "provider": "codex"}],
        )
        without = {key: value for key, value in document.items() if key != "deliveries"}
        self.assertTrue(summary.is_valid(without))
        good = document["deliveries"][0]
        for broken in (
            [{key: value for key, value in good.items() if key != "messageId"}],
            [{key: value for key, value in good.items() if key != "role"}],
            [{**good, "messageId": "not-a-message-id"}],
            [{**good, "messageId": good["messageId"].upper()}],
            [{**good, "role": "other"}],
            [{key: value for key, value in good.items() if key != "pane"}],
            [{**good, "provider": 1}],
            [good] * (summary.DELIVERY_LIMIT + 1),
        ):
            self.assertFalse(summary.is_valid({**document, "deliveries": broken}))

    def test_publish_reads_the_ledger_inside_the_lock_and_never_regresses(self) -> None:
        task, _ = self.create()
        other = Store.open(self.root)
        self.addCleanup(other.close)
        original = summary.read_ledger

        def snapshot_then_concurrent_commit(store: Store) -> summary.LedgerSnapshot:
            snapshot = original(store)
            other.update_task(task.id, now=300.0, event="paused", control="paused")
            return snapshot

        with patch.object(summary, "read_ledger", side_effect=snapshot_then_concurrent_commit):
            first = self.publish()
        self.assertLess(first.revision, other.ledger_revision()[1])
        self.assertEqual(summary.publish(other, self.root).status, "written")
        self.assertEqual(self.document()["ledgerRevision"], other.ledger_revision()[1])
        self.assertEqual(self.entry(task.id)["reason"], "paused")

    def test_lock_timeout_is_reported_without_writing(self) -> None:
        self.create()
        descriptor = os.open(self.root / summary.LOCK_NAME, os.O_RDWR | os.O_CREAT, 0o600)
        self.addCleanup(os.close, descriptor)
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        with patch.object(summary, "LOCK_WAIT_SECONDS", 0.05):
            with self.assertRaises(summary.SummaryError) as caught:
                self.publish()
        self.assertEqual(caught.exception.code, "summary_lock_timeout")
        self.assertFalse((self.root / summary.SUMMARY_NAME).exists())

    def test_hundred_longest_tasks_fit_and_overflow_keeps_the_attention_index(self) -> None:
        for number in range(100):
            _, attempt = self.create(
                title="长" * 200,
                target=ref(Provider.CLAUDE, f"s-{number}", pid=5000 + number, pane=f"%{number}", label="会" * 200),
                now=100.0 + number,
            )
            self.deliver(attempt, Delivery.HELD if number % 2 else Delivery.DELIVERED, now=300.0 + number)
        self.publish()
        self.assertLessEqual((self.root / summary.SUMMARY_NAME).stat().st_size, summary.MAX_BYTES)
        self.assertFalse(self.document()["overflow"])
        with patch.object(summary, "MAX_BYTES", 40_000):
            self.publish(force=True)
        document = self.document()
        self.assertTrue(document["overflow"])
        self.assertLess(len(document["tasks"]), 100)
        self.assertEqual(document["counts"], {"active": 100, "attention": 50, "result": 0, "decision": 50, "failure": 0})
        self.assertEqual(len(document["attentionIndex"]), 50)


class MappingTests(unittest.TestCase):
    def test_every_describe_reason_has_a_fixed_attention_class(self) -> None:
        seen: dict[str, tuple[str, bool]] = {}
        for delivery, work, role, flow, verdict, control in product(
            Delivery, Work, (Role.HANDOFF, Role.REVIEW), Flow, (None, *Verdict), ("active", "paused")
        ):
            item = label_tests.task(flow=flow, verdict=verdict, control=control)
            view = describe(item, [label_tests.attempt(delivery=delivery, work=work, role=role)])
            seen[view.reason] = summary.classify(view)
        seen["no_attempt"] = summary.classify(describe(label_tests.task(), []))
        running = {"paused", "waiting_for_target", "sending", *(work.value for work in Work)}
        for reason, classified in seen.items():
            with self.subTest(reason=reason):
                if reason in {"result_ready", "review_approved"}:
                    self.assertEqual(classified, ("result", True))
                elif reason in {"blocked_reported", "failure_reported"}:
                    self.assertEqual(classified, ("failure", True))
                elif reason == "cancelled_undelivered":
                    self.assertEqual(classified, ("decision", False))
                elif reason.startswith("delivery_") or reason in {
                    "changes_requested", "review_verdict_missing", "review_not_dispatched", "no_attempt"
                }:
                    self.assertEqual(classified, ("decision", True))
                else:
                    self.assertIn(reason, running)
                    self.assertEqual(classified, ("none", False))
        self.assertEqual(seen["delivery_held"], ("decision", True))


class TokenTests(LedgerCase):
    def attention(self, task_id: str) -> dict[str, Any]:
        self.publish()
        return self.entry(task_id)["attention"]

    def test_unrelated_events_keep_the_token_and_a_new_event_changes_it(self) -> None:
        task, attempt = self.create()
        self.deliver(attempt, Delivery.QUEUED)
        self.store.set_work(attempt.id, work=Work.BLOCKED, result=None, now=130.0, event="blocked")
        first = self.attention(task.id)
        self.assertEqual((first["kind"], first["at"]), ("failure", 130.0))
        self.store.set_consumption(attempt.id, Consumption.LEFT_QUEUE, now=131.0)
        self.store.add_attempt(
            task.id, role=Role.NOTICE, target=ref(Provider.CLAUDE, "origin"), body="notice", refs=[], now=132.0,
            sender=None, sender_class=None,
        )
        self.assertEqual(self.attention(task.id), first)
        self.store.set_work(attempt.id, work=Work.IN_PROGRESS, result=None, now=140.0, event="progress")
        self.assertEqual(self.attention(task.id), {"kind": "none"})
        self.store.set_work(attempt.id, work=Work.BLOCKED, result=None, now=150.0, event="blocked")
        second = self.attention(task.id)
        self.assertEqual(second["kind"], "failure")
        self.assertNotEqual(second["token"], first["token"])

    def test_held_is_a_decision_until_the_receiver_approves(self) -> None:
        task, attempt = self.create(target=ref(Provider.CLAUDE, "receiver", pane="%4"))
        self.deliver(attempt, Delivery.HELD)
        held = self.attention(task.id)
        self.assertEqual((held["kind"], held["notify"]), ("decision", True))
        self.assertEqual(self.entry(task.id)["next"]["action"], "approve_at_target")
        self.assertTrue(
            self.store.transition_delivery(
                attempt.id, expected=(Delivery.HELD,), new=Delivery.DELIVERED, reason="claude_delivered", now=140.0
            )
        )
        self.assertEqual(self.attention(task.id), {"kind": "none"})
        self.assertEqual(self.document()["attentionIndex"], [])

    def test_user_cancelled_message_is_listed_but_not_notified(self) -> None:
        task, attempt = self.create()
        self.assertTrue(
            self.store.transition_delivery(
                attempt.id, expected=(Delivery.PENDING,), new=Delivery.CANCELLED, reason="cancelled", now=120.0
            )
        )
        attention = self.attention(task.id)
        self.assertEqual((attention["kind"], attention["notify"]), ("decision", False))
        self.assertEqual(self.document()["attentionIndex"][0]["notify"], False)


class BindingTests(LedgerCase):
    def keys(self, attempt: Attempt) -> list[dict[str, str]]:
        return summary.binding(self.current(attempt))["observerKeys"]

    def test_delivered_generation_is_taken_as_one_tuple(self) -> None:
        selected = replace(ref(Provider.CODEX, "thread-a", pid=111, start="100", pane="%91"), server_pid=333)
        _, attempt = self.create(target=selected)
        self.deliver(
            attempt,
            Delivery.QUEUED,
            detail={"deliveredPid": 222, "deliveredStart": "200", "deliveredPane": "%92", "deliveredServerPid": 444},
        )
        bound = summary.binding(self.current(attempt))
        self.assertEqual((bound["source"], bound["pane"]), ("delivered", "%92"))
        self.assertEqual(bound["observerKeys"], [{"key": opaque_id("codex", 444, "%92", 222, "200"), "match": "generation"}])
        mixed = {opaque_id("codex", 333, "%91", 222, "200"), opaque_id("codex", 444, "%91", 222, "200")}
        self.assertFalse(mixed & {item["key"] for item in bound["observerKeys"]})

    def test_origin_and_reviewer_carry_bindings_from_their_ledger_endpoints(self) -> None:
        # 协作组要把发起方/复核方也对上会话行：键推导与接收方同一口径，来源固定为 selected（DESIGN §45.27.1）
        origin = replace(ref(Provider.CODEX, "thread-origin", pid=301, start="31", pane="%7"), server_pid=555)
        reviewer = ref(Provider.CLAUDE, "session-review", pid=401, start="41", pane="%8")
        task, _ = self.create(flow=Flow.REVIEW, origin=origin, origin_class="bypass", reviewer=reviewer)
        self.publish()
        entry = self.entry(task.id)
        self.assertEqual(
            entry["origin"]["binding"],
            {"source": "selected", "pane": "%7",
             "observerKeys": [{"key": opaque_id("codex", 555, "%7", 301, "31"), "match": "generation"}]},
        )
        base = opaque_id("claude", "session-review")
        self.assertEqual(
            entry["reviewer"]["binding"],
            {"source": "selected", "pane": "%8", "observerKeys": [
                {"key": opaque_id("claude-gen", base, "%8", 401, "41"), "match": "generation"},
                {"key": base, "match": "session"},
            ]},
        )
        self.assertTrue(summary.is_valid(self.document()))

    def test_user_origin_and_old_endpoint_records_stay_valid(self) -> None:
        # 用户直接发起：origin 为 null；旧记录没有 server_pid 的 Codex 发起方只是没有键，不报错
        user_task, _ = self.create()
        old_origin = ref(Provider.CODEX, "thread-old", pane="%9")
        old_task, _ = self.create(origin=old_origin, origin_class="bypass", now=101.0)
        self.publish()
        self.assertIsNone(self.entry(user_task.id)["origin"])
        self.assertEqual(self.entry(old_task.id)["origin"]["binding"]["observerKeys"], [])
        self.assertTrue(summary.is_valid(self.document()))

    def test_endpoint_binding_is_optional_but_checked_when_present(self) -> None:
        origin = ref(Provider.CLAUDE, "session-origin", pane="%3")
        self.create(origin=origin, origin_class="bypass")
        self.publish()
        good = self.document()
        legacy = copy.deepcopy(good)
        del legacy["tasks"][0]["origin"]["binding"]
        self.assertTrue(summary.is_valid(legacy))
        for name, change in {
            "not_object": lambda d: d["tasks"][0]["origin"].__setitem__("binding", []),
            "bad_source": lambda d: d["tasks"][0]["origin"]["binding"].__setitem__("source", "guessed"),
            "bad_match": lambda d: d["tasks"][0]["origin"]["binding"]["observerKeys"].append({"key": "k", "match": "pane"}),
        }.items():
            with self.subTest(damage=name):
                damaged = copy.deepcopy(good)
                change(damaged)
                self.assertFalse(summary.is_valid(damaged))

    def test_if_stale_upgrades_same_revision_summary_without_endpoint_bindings(self) -> None:
        # 升级收敛（Codex 设计复审 D02）：旧发布器写出的同修订号摘要缺 binding，if-stale 也要重建
        origin = ref(Provider.CLAUDE, "session-origin", pane="%3")
        self.create(origin=origin, origin_class="bypass")
        self.assertEqual(self.publish().status, "written")
        path = self.root / summary.SUMMARY_NAME
        legacy = self.document()
        del legacy["tasks"][0]["origin"]["binding"]
        path.write_text(json.dumps(legacy, ensure_ascii=False), encoding="utf-8")
        self.assertIsNotNone(summary.load(self.root))
        self.assertEqual(self.publish().status, "written")
        self.assertIn("binding", self.document()["tasks"][0]["origin"])
        self.assertEqual(self.document()["ledgerRevision"], legacy["ledgerRevision"])
        self.assertEqual(self.publish().status, "fresh")

    def test_if_stale_does_not_rewrite_user_started_tasks(self) -> None:
        # 用户直接发起（origin 为 null）没有可补的字段：不应每次都重写
        self.create()
        self.assertEqual(self.publish().status, "written")
        self.assertEqual(self.publish().status, "fresh")

    def test_undelivered_attempt_uses_the_whole_selected_target(self) -> None:
        target = replace(ref(Provider.CODEX, "thread-b", pid=111, start="100", pane="%91"), server_pid=333)
        _, attempt = self.create(target=target)
        bound = summary.binding(attempt)
        self.assertEqual((bound["source"], bound["pane"]), ("selected", "%91"))
        self.assertEqual(bound["observerKeys"], [{"key": opaque_id("codex", 333, "%91", 111, "100"), "match": "generation"}])

    def test_missing_server_pid_disables_codex_but_not_claude(self) -> None:
        _, codex = self.create(target=ref(Provider.CODEX, "thread-c", pane="%5"))
        self.deliver(codex, Delivery.QUEUED, detail={"deliveredPid": 1000, "deliveredStart": "100", "deliveredPane": "%5"})
        self.assertEqual(self.keys(codex), [])
        _, claude = self.create(target=ref(Provider.CLAUDE, "session-d", pid=2000, start="300", pane="%6"), now=101.0)
        self.deliver(claude, Delivery.DELIVERED, detail={"deliveredPid": 2000, "deliveredStart": "300", "deliveredPane": "%6"})
        base = opaque_id("claude", "session-d")
        self.assertEqual(
            self.keys(claude),
            [
                {"key": opaque_id("claude-gen", base, "%6", 2000, "300"), "match": "generation"},
                {"key": base, "match": "session"},
            ],
        )

    def test_endpoint_ref_round_trips_server_pid_and_accepts_old_records(self) -> None:
        with_server = replace(ref(), server_pid=777)
        self.assertEqual(EndpointRef.from_dict(with_server.to_dict()), with_server)
        old = ref().to_dict()
        self.assertNotIn("tmuxServerPid", old)
        restored = EndpointRef.from_dict(old)
        assert restored is not None
        self.assertIsNone(restored.server_pid)
        bogus = EndpointRef.from_dict({**old, "tmuxServerPid": True})
        assert bogus is not None
        self.assertIsNone(bogus.server_pid)

    def test_tmux_panes_reads_the_server_pid(self) -> None:
        output = "4001\t%7\t900\tproj\tname\nbad line\n4002\t%8\tx\tother\n"
        completed = subprocess.CompletedProcess([], 0, output, "")
        with patch("agentstatus_bridge.endpoints.subprocess.run", return_value=completed):
            panes = tmux_panes()
        self.assertEqual(panes, {4001: PaneInfo("%7", 4001, "proj\tname", 900)})


class SummaryCliTests(unittest.TestCase):
    state: Path
    caller: Any
    setUp = cli_tests.CliTests.setUp
    run_cli = cli_tests.CliTests.run_cli
    send = cli_tests.CliTests.send
    store = cli_tests.CliTests.store
    mark_sent = cli_tests.CliTests.mark_sent

    def summary_document(self) -> dict[str, Any]:
        return json.loads((self.state / summary.SUMMARY_NAME).read_text(encoding="utf-8"))

    def test_any_later_command_repairs_a_commit_that_was_not_published(self) -> None:
        task_id = self.send()
        self.assertEqual(self.summary_document()["tasks"][0]["id"], task_id)
        with self.store() as store:  # 提交后、发布前进程被杀
            store.update_task(task_id, now=500.0, event="paused", control="paused")
            revision = store.ledger_revision()[1]
        self.assertNotEqual(self.summary_document()["ledgerRevision"], revision)
        code, _, err = self.run_cli("tasks")
        self.assertEqual(code, cli.EXIT_OK, err)
        self.assertEqual(self.summary_document()["ledgerRevision"], revision)

    def test_summary_failure_never_changes_the_command_result(self) -> None:
        with patch.object(summary, "publish", side_effect=summary.SummaryError("summary_write_failed")):
            with patch.object(cli, "_start_worker") as start:
                code, out, err = self.run_cli("send", "--to", "codex@impl", "-m", "x", "--no-wait", "--json")
        self.assertEqual(code, cli.EXIT_OK, err)
        self.assertTrue(json.loads(out)["id"])
        start.assert_called()

    def test_summary_command_reports_and_rebuilds(self) -> None:
        code, out, _ = self.run_cli("summary", "--json")
        self.assertEqual((code, json.loads(out)["state"]), (cli.EXIT_OK, "absent"))
        code, _, err = self.run_cli("summary", "--if-stale")
        self.assertEqual((code, "ledger_absent" in err), (cli.EXIT_UNAVAILABLE, True))
        self.assertFalse((self.state / DB_NAME).exists())
        self.send()
        (self.state / summary.SUMMARY_NAME).write_text("{}", encoding="utf-8")
        self.assertEqual(json.loads(self.run_cli("summary", "--json")[1])["state"], "invalid")
        repaired = json.loads(self.run_cli("summary", "--if-stale", "--json")[1])
        self.assertEqual((repaired["published"], repaired["state"]), ("written", "ok"))
        self.assertEqual(json.loads(self.run_cli("summary", "--if-stale", "--json")[1])["published"], "fresh")
        self.assertEqual(json.loads(self.run_cli("summary", "--refresh", "--json")[1])["published"], "written")

    def test_peers_does_not_create_a_ledger(self) -> None:
        code, _, err = self.run_cli("peers", "--json")
        self.assertEqual(code, cli.EXIT_OK, err)
        self.assertFalse((self.state / DB_NAME).exists())

    def test_accept_json_reports_success_and_failure(self) -> None:
        task_id = self.send()
        self.mark_sent(task_id)
        code, out, err = self.run_cli("accept", task_id, "--json")
        self.assertEqual(code, cli.EXIT_REJECTED)
        self.assertEqual(
            json.loads(out),
            {"ok": False, "code": "no_result_to_accept", "reasonText": cli.reason_text("no_result_to_accept")},
        )
        self.assertIn("no_result_to_accept", err)
        self.caller = cli_tests.as_agent(cli_tests.IMPL)
        self.assertEqual(self.run_cli("report", task_id, "--result", "--note", "完成")[0], cli.EXIT_OK)
        self.caller = cli_tests.USER
        code, out, err = self.run_cli("accept", task_id, "--json")
        self.assertEqual(code, cli.EXIT_OK, err)
        # 原有字段不变，另附结束回执排队结果（DESIGN §45.31.6）
        self.assertEqual(
            json.loads(out),
            {
                "ok": True,
                "id": task_id,
                "phase": "done",
                "closure": {"queued": [{"seq": 2, "target": "codex@impl"}], "skipped": []},
            },
        )
        self.assertEqual(self.summary_document()["counts"]["active"], 0)

    def test_doctor_shows_summary_state(self) -> None:
        self.send()
        with (
            patch.object(cli, "cli_version", return_value="0.154.0"),
            patch("agentstatus_bridge.endpoints.agentstatus_runtime", return_value={}),
        ):
            code, out, err = self.run_cli("doctor", "--json")
        self.assertEqual(code, cli.EXIT_OK, err)
        self.assertEqual(json.loads(out)["summaryState"], summary.STATE_LABELS["ok"])


class SummaryWorkerTests(unittest.TestCase):
    root: Path
    inbox_dir: Path
    setUp = worker_tests.WorkerTests.setUp
    _pending_task = worker_tests.WorkerTests._pending_task
    _run_once = worker_tests.WorkerTests._run_once

    def events(self) -> list[dict[str, Any]]:
        text = (self.root / "worker.log").read_text(encoding="utf-8")
        return [json.loads(line) for line in text.splitlines()]

    def test_start_rebuilds_a_broken_summary_and_loop_follows_changes(self) -> None:
        task_id = self._pending_task()
        path = self.root / summary.SUMMARY_NAME
        path.write_text('{"schema": 1}', encoding="utf-8")
        self.assertEqual(self._run_once(RecordingTransport(Provider.CODEX)), 0)
        document = json.loads(path.read_text(encoding="utf-8"))
        self.assertTrue(summary.is_valid(document))
        self.assertIn(task_id, [item["id"] for item in document["tasks"]])
        with Store.open(self.root) as store:
            self.assertEqual(document["ledgerRevision"], store.ledger_revision()[1])
        self.assertIn("summary_published", [record["event"] for record in self.events()])

    def test_failed_summary_keeps_the_worker_retrying_within_a_bound(self) -> None:
        calls: list[object] = []

        def failing(*_args: object, **kwargs: object) -> summary.PublishResult:
            calls.append(kwargs.get("force"))
            if len(calls) > 10:
                # 回归时 worker 会无限重试：借用它安装的 SIGTERM 处理函数收尾，让测试以调用序列不符失败而不是挂住
                stop = signal.getsignal(signal.SIGTERM)
                assert callable(stop)
                stop(signal.SIGTERM, None)
            raise summary.SummaryError("summary_lock_timeout")

        with (
            patch.object(summary, "publish", side_effect=failing),
            patch("agentstatus_bridge.worker.MAX_CONSECUTIVE_FAILURES", 3),
            patch("agentstatus_bridge.worker.IDLE_EXIT_SECONDS", 0.05),
        ):
            code = run_worker(
                root=self.root,
                inbox_directory=self.inbox_dir,
                discover_fn=lambda: [],
                transports={Provider.CODEX: RecordingTransport(Provider.CODEX)},
                loop_seconds=0.01,
            )
        self.assertEqual((code, calls), (0, [True, False, False]))
        failures = [record for record in self.events() if record["event"] == "summary_write_failed"]
        self.assertEqual([record["code"] for record in failures], ["summary_lock_timeout"] * 3)


DEEP_JSON = b"[" * 20000 + b"0" + b"]" * 20000


class SummaryRobustnessTests(LedgerCase):
    """3a 审计 bfbeff29：嵌套损坏、非有限数值与过深 JSON 都判为损坏并重建（3A-F01/F02）。"""

    def published_result(self) -> dict[str, Any]:
        _, attempt = self.create()
        self.deliver(attempt, Delivery.DELIVERED)
        self.store.set_work(attempt.id, work=Work.RESULT, result=None, now=120.0, event="result")
        self.publish()
        return self.document()

    def test_same_revision_nested_damage_is_rebuilt(self) -> None:
        good = self.published_result()
        path = self.root / summary.SUMMARY_NAME

        def damaged(change: Any) -> dict[str, Any]:
            document = copy.deepcopy(good)
            change(document)
            return document

        variants = {
            "attention_empty": damaged(lambda d: d["tasks"][0].__setitem__("attention", {})),
            "current_not_object": damaged(lambda d: d["tasks"][0].__setitem__("current", "not an object")),
            "binding_not_object": damaged(lambda d: d["tasks"][0]["target"].__setitem__("binding", [])),
            "observer_key_bad_match": damaged(
                lambda d: d["tasks"][0]["target"]["binding"]["observerKeys"].append({"key": "x", "match": "pane"})
            ),
            "index_unknown_kind": damaged(lambda d: d["attentionIndex"][0].__setitem__("kind", "unrecognized-kind")),
            "index_count_mismatch": damaged(lambda d: d["attentionIndex"].clear()),
            "phase_unknown": damaged(lambda d: d["tasks"][0].__setitem__("phase", "somewhere")),
            "next_command_number": damaged(lambda d: d["tasks"][0]["next"].__setitem__("command", 7)),
        }
        for name, document in variants.items():
            with self.subTest(damage=name):
                path.write_text(json.dumps(document, ensure_ascii=False), encoding="utf-8")
                self.assertEqual(self.publish().status, "written")
                self.assertEqual(self.document(), {**good, "generatedAt": self.document()["generatedAt"]})
        raw_variants = {
            "nan": json.dumps({**good, "generatedAt": float("nan")}).encode("utf-8"),
            # 可选字段里的 NaN 同样使整份文件不是严格 JSON（界面端 JSON.parse 会拒绝）
            "nan_in_optional_field": json.dumps({**good, "futureOptional": float("nan")}).encode("utf-8"),
            "deep": DEEP_JSON,
        }
        for name, raw in raw_variants.items():
            with self.subTest(damage=name):
                path.write_bytes(raw)
                self.assertIsNone(summary.load(self.root))
                self.assertEqual(self.publish().status, "written")
        self.assertEqual(self.publish().status, "fresh")

    def test_valid_documents_may_add_optional_fields_and_have_no_attempt(self) -> None:
        good = self.published_result()
        extended = copy.deepcopy(good)
        extended["futureOptional"] = {"a": 1}
        extended["tasks"][0]["futureOptional"] = [1, 2]
        self.assertTrue(summary.is_valid(extended))
        no_attempt = copy.deepcopy(good)
        no_attempt["tasks"][0].update(
            current=None, target=None, reason="no_attempt",
            attention={"kind": "decision", "token": "t:no_attempt:1.000000", "at": 1.0, "notify": True},
        )
        no_attempt["attentionIndex"][0]["kind"] = "decision"
        no_attempt["counts"].update(result=0, decision=1)
        self.assertTrue(summary.is_valid(no_attempt))
        half = copy.deepcopy(good)
        half["tasks"][0]["target"] = None
        self.assertFalse(summary.is_valid(half))

    def test_wrong_types_are_invalid_without_raising_and_are_rebuilt(self) -> None:
        good = self.published_result()
        path = self.root / summary.SUMMARY_NAME
        variants: dict[str, Any] = {
            "schema_true": lambda d: d.__setitem__("schema", True),
            "phase_list": lambda d: d["tasks"][0].__setitem__("phase", []),
            "attention_kind_object": lambda d: d["tasks"][0]["attention"].__setitem__("kind", {}),
            "index_kind_list": lambda d: d["attentionIndex"][0].__setitem__("kind", []),
            "binding_source_list": lambda d: d["tasks"][0]["target"]["binding"].__setitem__("source", []),
            "match_object": lambda d: d["tasks"][0]["target"]["binding"]["observerKeys"].append({"key": "k", "match": {}}),
            "generated_at_huge_int": lambda d: d.__setitem__("generatedAt", 10**400),
            "delivery_at_huge_int": lambda d: d["tasks"][0]["current"].__setitem__("deliveryAt", 10**400),
        }
        for name, change in variants.items():
            with self.subTest(variant=name):
                document = copy.deepcopy(good)
                change(document)
                self.assertFalse(summary.is_valid(document))
                path.write_text(json.dumps(document), encoding="utf-8")
                self.assertIsNone(summary.load(self.root))
                self.assertEqual(self.publish().status, "written")
        self.assertTrue(summary.is_valid({**good, "schema": 1}))

    def test_unexpected_validator_error_counts_as_damage(self) -> None:
        self.published_result()
        with patch.object(summary, "is_valid", side_effect=TypeError("synthetic")):
            self.assertIsNone(summary.load(self.root))
            self.assertEqual(self.publish().status, "written")

    def test_non_finite_values_are_never_published(self) -> None:
        self.published_result()
        before = (self.root / summary.SUMMARY_NAME).read_bytes()
        with patch.object(summary, "attention_at", return_value=float("nan")):
            with self.assertRaises(summary.SummaryError) as caught:
                self.publish(force=True)
        self.assertEqual(caught.exception.code, "summary_invalid_value")
        self.assertEqual((self.root / summary.SUMMARY_NAME).read_bytes(), before)


class SummaryRobustCliTests(unittest.TestCase):
    state: Path
    caller: Any
    setUp = cli_tests.CliTests.setUp
    run_cli = cli_tests.CliTests.run_cli
    send = cli_tests.CliTests.send
    store = cli_tests.CliTests.store
    mark_sent = cli_tests.CliTests.mark_sent

    def test_deep_summary_does_not_stop_an_unrelated_command(self) -> None:
        self.send()
        path = self.state / summary.SUMMARY_NAME
        path.write_bytes(DEEP_JSON)
        code, out, err = self.run_cli("peers", "--json")
        self.assertEqual(code, cli.EXIT_OK, err)
        self.assertIn("peers", json.loads(out))
        self.assertTrue(summary.is_valid(json.loads(path.read_text(encoding="utf-8"))))

    def test_any_summary_exception_is_contained_before_and_after_the_command(self) -> None:
        task_id = self.send()
        with (
            patch.object(summary, "publish", side_effect=RecursionError("synthetic")),
            patch.object(cli, "_start_worker") as start,
        ):
            code, out, err = self.run_cli("status", task_id, "--json")
        self.assertEqual(code, cli.EXIT_OK, err)
        self.assertEqual(json.loads(out)["id"], task_id)
        self.assertEqual(start.call_count, 2)

    def test_damage_after_a_committed_accept_keeps_its_success(self) -> None:
        task_id = self.send()
        self.mark_sent(task_id)
        self.caller = cli_tests.as_agent(cli_tests.IMPL)
        self.assertEqual(self.run_cli("report", task_id, "--result", "--note", "完成")[0], cli.EXIT_OK)
        self.caller = cli_tests.USER
        original = cli.cmd_accept

        def accept_then_damage(args: Any) -> int:
            result = original(args)
            (self.state / summary.SUMMARY_NAME).write_bytes(DEEP_JSON)
            return result

        with patch.object(cli, "cmd_accept", side_effect=accept_then_damage):
            code, out, err = self.run_cli("accept", task_id, "--json")
        self.assertEqual((code, json.loads(out)["ok"]), (cli.EXIT_OK, True), err)
        with self.store() as store:
            task = store.get_task(task_id)
            assert task is not None
            self.assertIsNotNone(task.accepted_at)

    def test_summary_if_stale_recovers_wrong_types(self) -> None:
        self.send()
        path = self.state / summary.SUMMARY_NAME
        document = json.loads(path.read_text(encoding="utf-8"))
        document["tasks"][0]["phase"] = []
        path.write_text(json.dumps(document), encoding="utf-8")
        code, out, err = self.run_cli("summary", "--if-stale", "--json")
        self.assertEqual(code, cli.EXIT_OK, err)
        state = json.loads(out)
        self.assertEqual((state["published"], state["state"]), ("written", "ok"))

    def test_summary_if_stale_recovers_deep_json(self) -> None:
        self.send()
        (self.state / summary.SUMMARY_NAME).write_bytes(DEEP_JSON)
        code, out, err = self.run_cli("summary", "--if-stale", "--json")
        self.assertEqual(code, cli.EXIT_OK, err)
        document = json.loads(out)
        self.assertEqual((document["published"], document["state"]), ("written", "ok"))


class SummaryStartupRaceTests(unittest.TestCase):
    root: Path
    inbox_dir: Path
    setUp = worker_tests.WorkerTests.setUp

    def test_startup_tracks_the_published_revision_not_a_later_commit(self) -> None:
        with Store.open(self.root) as writer:
            _, attempt = new_task(writer)
            writer.transition_delivery(
                attempt.id, expected=(Delivery.PENDING,), new=Delivery.DELIVERED, reason="synthetic", now=110.0
            )
            writer.set_work(attempt.id, work=Work.IN_PROGRESS, result=None, now=120.0, event="progress")
            original = summary._atomic_write
            written: list[int] = []

            def write_then_commit(directory: Path, payload: bytes) -> None:
                original(directory, payload)
                written.append(json.loads(payload)["ledgerRevision"])
                if len(written) == 1:
                    # 发布之后、worker 读水位之前另一连接提交（旧版写者或提交后被杀的 CLI）
                    writer.set_work(attempt.id, work=Work.RESULT, result=None, now=130.0, event="result")

            transport = RecordingTransport(Provider.CODEX)
            with (
                patch.object(summary, "_atomic_write", side_effect=write_then_commit),
                patch("agentstatus_bridge.worker.IDLE_EXIT_SECONDS", 0.05),
            ):
                code = run_worker(
                    root=self.root, inbox_directory=self.inbox_dir, discover_fn=lambda: [],
                    transports={Provider.CODEX: transport}, loop_seconds=0.01,
                )
            document = json.loads((self.root / summary.SUMMARY_NAME).read_text(encoding="utf-8"))
            self.assertEqual((code, len(transport.calls)), (0, 0))
            self.assertEqual(len(written), 2)
            self.assertEqual(document["ledgerRevision"], writer.ledger_revision()[1])
            self.assertEqual(document["tasks"][0]["current"]["work"], Work.RESULT.value)


# ---------------------------------------------------------------------------
# summary.json v1 合同（DESIGN §45.35 / docs/summary-contract.md）
# ---------------------------------------------------------------------------

GOLDEN_PATH = Path(__file__).resolve().parent / "fixtures" / "summary-v1.json"
# 这两个值在 golden 里固定注入：abVersion 随发布漂移、device 随机器不同，都不属于冻结的形状
GOLDEN_VERSION = "0.0.0-contract"
GOLDEN_DEVICE = "contract-box"
GOLDEN_NOW = 1_700_000_000.5
# 合成账本跑完这些迁移后的修订号；变了就是账本写入的事件变了（见 frozen_payload 的断言）
GOLDEN_REVISION = 57
# 账本 id 由 Store 在 open 时用 uuid4 生成，任务/尝试/消息 id 来自 store.new_id：
# 造账本前注入确定生成器、账本 id 在快照层替换，摘要就不必做全文替换（Codex 审计 C02）
GOLDEN_LEDGER_ID = "f" * 32
GOLDEN_TOP_LEVEL = (
    "abVersion", "attentionIndex", "counts", "deliveries", "device",
    "generatedAt", "ledgerId", "ledgerRevision", "overflow", "schema", "tasks",
)


class SummaryContractTests(LedgerCase):
    """v1 合同的可执行门禁：字段形状与编码方式一起冻结（docs/summary-contract.md）。

    golden 用真实 Store 造合法状态（造之前注入确定的 id 生成器），不手拼 dataclass——
    否则可能冻结出一个 describe() 永远不会产生的组合。产出就是 golden 的原始字节，不做任何事后替换。
    """

    @staticmethod
    def fixed_ids() -> Iterator[str]:
        """确定的 32 位十六进制 id：`0101…`、`0202…`……前 8 位各不相同，golden 里 `short` 也就可读。"""
        return (f"{index:02x}" * 16 for index in count(1))

    def build_ledger(self) -> None:
        """四项任务覆盖 result/none/failure/decision 四种关注、两种绑定命名空间、review 流程与结束回执投递。

        标题与标签故意写超长：`TITLE_CODEPOINTS`/`INDEX_TITLE_CODEPOINTS`/`LABEL_CODEPOINTS`
        这三个上限写进了合同，golden 必须真的走到截断，改坏了才会红（独立审计 F-C）。
        """
        with patch("agentstatus_bridge.store.new_id", side_effect=self.fixed_ids()):
            lead = EndpointRef(
                provider=Provider.CLAUDE, native_id="claude-session-0001", pid=900, start_ticks="77", pane="%3", label="lead"
            )
            work = EndpointRef(
                provider=Provider.CODEX, native_id="codex-thread-0001", pid=1000, start_ticks="100",
                pane="%7", label="工" * 70, server_pid=800,
            )
            probe = EndpointRef(
                provider=Provider.GROK, native_id="grok-session-0001", pid=1100, start_ticks="120", pane="%9", label="probe"
            )
            # 1 已交结果待验收：投递证据齐全（binding.source=delivered），Claude 发起、Codex 接收
            task_a, attempt_a = self.create(title="交接：实现 X" + "长" * 100, origin=lead, target=work, now=1000.0)
            self.deliver(attempt_a, Delivery.DELIVERED, now=1010.0, detail={
                "deliveredPid": 1000, "deliveredStart": "100", "deliveredPane": "%7", "deliveredServerPid": 800,
            })
            self.store.set_work(attempt_a.id, work=Work.RESULT, result={"note": "结果摘要"}, now=1020.0, event="result")
            # 结束回执：deliveries 里带 kind=closure（旧摘要没有这个字段，合同里是可选）
            closure = self.store.add_attempt(
                task_a.id, role=Role.NOTICE, target=lead, body="结束回执", refs=[], now=1030.0,
                sender=None, sender_class=None, options={NOTICE_KIND_OPTION: CLOSURE_KIND},
            )
            self.deliver(closure, Delivery.WRITTEN, now=1040.0, detail={})
            # 2 用户发起、还没投出：attention=none、originIsUser=true；Claude 目标给出 generation+session 两个绑定键
            self.create(title="交接：整理文档", origin=None, target=lead, now=1100.0)
            # 3 对方报受阻：attention=failure；Grok 发起（只读 provider，没有面板绑定键）
            _task_c, attempt_c = self.create(title="交接：排查失败", origin=probe, target=work, now=1200.0)
            self.deliver(attempt_c, Delivery.QUEUED, now=1210.0, detail={})
            self.store.set_work(attempt_c.id, work=Work.BLOCKED, result=None, now=1220.0, event="blocked")
            # 4 复核流程：结果已交、复核消息被对方暂存 → attention=decision，deliveries 里出现 role=review（独立审计 F-D）
            task_d, attempt_d = self.create(title="复核：审计方案", flow=Flow.REVIEW, origin=lead, target=work, now=1300.0)
            self.deliver(attempt_d, Delivery.DELIVERED, now=1310.0, detail={})
            self.store.set_work(attempt_d.id, work=Work.RESULT, result=None, now=1320.0, event="result")
            review = self.store.add_attempt(
                task_d.id, role=Role.REVIEW, target=lead, body="请复核", refs=[], now=1330.0,
                sender=None, sender_class=None,
            )
            self.deliver(review, Delivery.HELD, now=1340.0, detail={})

    def frozen_payload(self) -> bytes:
        """按合同生成这份账本的摘要：版本、时刻、设备与全部 id 都固定，产出即 golden 的原始字节。"""
        snapshot = replace(summary.read_ledger(self.store), ledger_id=GOLDEN_LEDGER_ID)
        # 修订号由这份合成账本的迁移条数决定：它变了说明账本写入的事件变了，属于合同变化，先确认是有意的再重生成 golden
        self.assertEqual(snapshot.revision, GOLDEN_REVISION, "账本修订数变了：先确认这是有意的合同变化，再重生成 golden")
        with patch.object(summary, "__version__", GOLDEN_VERSION):
            return summary.encode(summary.build_document(snapshot, now=GOLDEN_NOW, device=GOLDEN_DEVICE))

    def test_golden_summary_is_frozen_byte_for_byte(self) -> None:
        self.build_ledger()
        payload = self.frozen_payload()
        if os.environ.get("AB_WRITE_GOLDEN") == "1":
            GOLDEN_PATH.write_bytes(payload)
            self.skipTest(f"已按当前实现重写 golden：{GOLDEN_PATH}")
        self.assertMultiLineEqual(payload.decode("utf-8"), GOLDEN_PATH.read_text(encoding="utf-8"))
        self.assertEqual(payload, GOLDEN_PATH.read_bytes())

    def test_golden_top_level_shape_is_the_contract(self) -> None:
        document = json.loads(GOLDEN_PATH.read_text(encoding="utf-8"))
        self.assertEqual(tuple(sorted(document)), GOLDEN_TOP_LEVEL)
        self.assertTrue(summary.is_valid(document))
        self.assertEqual(
            (document["schema"], document["abVersion"], document["device"]),
            (summary.SCHEMA, GOLDEN_VERSION, GOLDEN_DEVICE),
        )
        kinds = {item["attention"]["kind"] for item in document["tasks"]}
        self.assertEqual(kinds, {"result", "none", "failure", "decision"})
        # 三个截断上限真的被走到：改坏常量时 golden 才会红（独立审计 F-C）
        self.assertEqual(
            max(len(item["title"]) for item in document["tasks"]), summary.TITLE_CODEPOINTS
        )
        self.assertEqual(
            max(len(item["title"]) for item in document["attentionIndex"]), summary.INDEX_TITLE_CODEPOINTS
        )
        labels = [item["target"]["label"] for item in document["tasks"] if item["target"]]
        self.assertEqual(max(len(label) for label in labels), summary.LABEL_CODEPOINTS)
        # 投递角色覆盖 handoff/review/notice（review 只在复核流程里出现，独立审计 F-D）
        self.assertEqual({item["role"] for item in document["deliveries"]}, {"handoff", "review", "notice"})
        sources = {item["target"]["binding"]["source"] for item in document["tasks"] if item["target"]}
        self.assertEqual(sources, {"delivered", "selected"})
        self.assertIn("closure", {item.get("kind") for item in document["deliveries"]})

    def test_readers_tolerate_a_missing_device_and_unknown_fields(self) -> None:
        document = json.loads(GOLDEN_PATH.read_text(encoding="utf-8"))
        # 旧摘要没有 device：照常有效，不触发重建
        self.assertTrue(summary.is_valid({key: value for key, value in document.items() if key != "device"}))
        # 显式 null 与缺失同等对待（Codex 审计 C01：文档要把发布器输出域与读方宽容域分开写清楚）
        self.assertTrue(summary.is_valid(dict(document, device=None)))
        # v1 允许加可选字段：未知键一律忽略（加字段不 bump schema 的前提）
        self.assertTrue(summary.is_valid(dict(document, unknownFuture={"a": 1})))
        # 有则必须是字符串
        self.assertFalse(summary.is_valid(dict(document, device=7)))

    def test_published_summary_carries_the_local_device(self) -> None:
        self.create()
        with patch.object(summary, "device_name", return_value="publish-box"):
            self.assertEqual(self.publish().status, "written")
        self.assertEqual(self.document()["device"], "publish-box")


if __name__ == "__main__":
    unittest.main()
