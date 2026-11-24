"""执行方提问不结束尝试（DESIGN §104.9 五）：本机与联邦的 ask 标记、question_asked 判定、提问回执与读方。"""

from __future__ import annotations

import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

import bridge_support  # noqa: F401  导入即隔离宿主会话环境
from agentstatus_bridge.cli import (  # pyright: ignore[reportPrivateUsage]
    ASK_OLD_AUTHORITY_HINT,
    EXIT_FAILURE_REPORTED,
    _wait_outcome,  # pyright: ignore[reportPrivateUsage]
)
from agentstatus_bridge.endpoints import Caller
from agentstatus_bridge.federation import commands, mirror
from agentstatus_bridge.federation.codec import check_envelope
from agentstatus_bridge.federation.mirror import LocalReport
from agentstatus_bridge.federation.views import derive_work, fold_report, model_attempts, model_task
from agentstatus_bridge.hints import PaneState, stopped_without_report
from agentstatus_bridge.labels import next_step, reason_text
from agentstatus_bridge.model import (
    ASK_OPTION,
    Delivery,
    EndpointRef,
    Flow,
    Phase,
    Provider,
    ReportKind,
    Role,
    Runtime,
    Work,
    ask_pending,
    describe,
)
from agentstatus_bridge.platforms.linux.process import ProcessInfo
from agentstatus_bridge.reports import ReportError, ReportInput, apply_report
from agentstatus_bridge.store import Store
from agentstatus_bridge.summary import attention_at, classify
from bridge_support import endpoint, ref

from test_bridge_federation_cli import WORKER, FedCliCase, as_agent
from test_bridge_federation_mirror_work import runtime
from test_bridge_federation_rules import DEV_A, DEV_B, T0, FederationTestCase, deliver, pump

IMPL = ref(Provider.CODEX, "019a0000-1111-7111-8111-111111111111", pid=1000, pane="%1", label="impl")
LEAD = ref(Provider.CLAUDE, "lead-session", pid=3000, pane="%3", label="lead")


def agent(reference: EndpointRef) -> Caller:
    return Caller(endpoint(reference), ProcessInfo(reference.pid, 1, reference.provider.value, reference.start_ticks))


class LocalAskTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = TemporaryDirectory()
        self.root = Path(self._tmp.name)
        self.store = Store.open(self.root / "bridge")
        self.now = 1000.0

    def tearDown(self) -> None:
        self.store.close()
        self._tmp.cleanup()

    def _task(self, *, notify: bool = True):
        task, attempt = self.store.create_task(
            title="实现 X", flow=Flow.HANDOFF, origin=LEAD, origin_class="bypass", reviewer=None, target=IMPL,
            body="原始要求", refs=[], now=self.now, task_options={"notify": notify})
        self.assertTrue(self.store.begin_send(attempt.id, now=self.now, pid=1, start_ticks="1"))
        self.store.finish_send(attempt.id, delivery=Delivery.QUEUED, reason="codex_queued", provider_ref=None,
                               detail={}, now=self.now)
        return task, attempt

    def _report(self, task_id: str, kind: ReportKind, **extra: object):
        self.now += 10
        return apply_report(self.store, ReportInput(task_ref=task_id, kind=kind, **extra),  # type: ignore[arg-type]
                            caller=agent(IMPL), caller_class="bypass", now=self.now, cwd=self.root)

    def _view(self, task_id: str):
        task = self.store.get_task(task_id)
        assert task is not None
        return task, self.store.attempts(task_id), describe(task, self.store.attempts(task_id))

    def test_ask_requires_progress_and_a_note_before_any_write(self) -> None:
        task, attempt = self._task()
        before = self.store.ledger_revision()
        for extra in ({"ask": True}, {"ask": True, "note": "   "}):
            with self.subTest(extra=extra), self.assertRaises(ReportError) as caught:
                self._report(task.id, ReportKind.PROGRESS, **extra)
            self.assertEqual(caught.exception.code, "ask_requires_note")
        with self.assertRaises(ReportError) as caught:
            self._report(task.id, ReportKind.RESULT, ask=True, note="问题")
        self.assertEqual(caught.exception.code, "ask_requires_note")
        self.assertEqual(self.store.ledger_revision(), before)
        self.assertNotIn(ASK_OPTION, (self.store.get_attempt(attempt.id) or attempt).options)

    def test_ask_marks_question_and_notifies_origin_immediately(self) -> None:
        task, attempt = self._task()
        outcome = self._report(task.id, ReportKind.PROGRESS, ask=True, note="用方案 A 还是 B？")
        _, attempts, view = self._view(task.id)
        self.assertEqual((view.phase, view.reason), (Phase.NEEDS_ATTENTION, "question_asked"))
        self.assertEqual(view.current.work if view.current else None, Work.IN_PROGRESS)
        self.assertEqual(classify(view), ("decision", True))
        refreshed = self.store.get_task(task.id)
        assert refreshed is not None and view.current is not None
        self.assertEqual(attention_at(refreshed, view), view.current.work_at)
        # 与 --blocked 同一路径：汇报事务里同步排一条结果回执，receiptOf=ask
        [notice] = outcome.followups
        self.assertEqual((notice.role, notice.target, notice.receipt_of), (Role.NOTICE, LEAD, "ask"))
        self.assertTrue(notice.body.startswith("对方在等你回答（任务仍在进行）：用方案 A 还是 B？"))
        self.assertNotIn("结论：", notice.body)
        self.assertIn(f'note {task.id[:8]} -m "回答"', notice.body)
        step = next_step(refreshed, attempts, ref="T")
        assert step is not None
        self.assertEqual(step.action, "answer")
        self.assertEqual(reason_text("question_asked"), "对方在等你回答（任务仍在进行）")
        events = [item for item in self.store.events(task.id) if item["kind"] == "progress"]
        self.assertEqual(events[-1]["detail"].get("ask"), True)

    def test_unanswered_question_gets_the_usual_thirty_minute_reminder(self) -> None:
        from agentstatus_bridge.reminders import REMIND_AFTER_SECONDS, pending_reminder
        task, _attempt = self._task()
        outcome = self._report(task.id, ReportKind.PROGRESS, ask=True, note="问题")
        [receipt] = outcome.followups
        refreshed, attempts, _ = self._view(task.id)
        self.assertIsNone(pending_reminder(refreshed, attempts))  # 回执还没交到：不提醒
        self.assertTrue(self.store.begin_send(receipt.id, now=self.now + 1, pid=1, start_ticks="1"))
        self.store.finish_send(receipt.id, delivery=Delivery.DELIVERED, reason="t", provider_ref=None, detail={},
                               now=self.now + 1)
        refreshed, attempts, _ = self._view(task.id)
        reminder = pending_reminder(refreshed, attempts)
        assert reminder is not None
        self.assertEqual(reminder.due_at, self.now + 1 + REMIND_AFTER_SECONDS)
        self.assertEqual(reminder.view.reason, "question_asked")

    def test_delivered_note_answers_but_pending_or_failed_does_not(self) -> None:
        task, attempt = self._task()
        self._report(task.id, ReportKind.PROGRESS, ask=True, note="问题")
        self.now += 5
        note = self.store.add_attempt(task.id, role=Role.NOTICE, target=IMPL, body="回答", refs=[], now=self.now,
                                      sender=LEAD, sender_class="bypass",
                                      options={"noticeKind": "note", "forSeq": attempt.seq})
        self.assertEqual(self._view(task.id)[2].reason, "question_asked")  # 还在桥内排队
        self.assertTrue(self.store.begin_send(note.id, now=self.now, pid=1, start_ticks="1"))
        self.store.finish_send(note.id, delivery=Delivery.FAILED, reason="target_gone", provider_ref=None,
                               detail={}, now=self.now)
        self.assertEqual(self._view(task.id)[2].reason, "question_asked")  # 确定未送达：仍在等
        again = self.store.add_attempt(task.id, role=Role.NOTICE, target=IMPL, body="回答", refs=[], now=self.now,
                                       sender=LEAD, sender_class="bypass",
                                       options={"noticeKind": "note", "forSeq": attempt.seq})
        self.assertTrue(self.store.begin_send(again.id, now=self.now, pid=1, start_ticks="1"))
        self.store.finish_send(again.id, delivery=Delivery.QUEUED, reason="codex_queued", provider_ref=None,
                               detail={}, now=self.now)
        self.assertEqual(self._view(task.id)[2].reason, "in_progress")

    def test_a_note_created_before_the_question_does_not_answer_it(self) -> None:
        task, attempt = self._task()
        self._report(task.id, ReportKind.ACK)
        early = self.store.add_attempt(task.id, role=Role.NOTICE, target=IMPL, body="先补一句", refs=[],
                                       now=self.now + 1, sender=LEAD, sender_class="bypass",
                                       options={"noticeKind": "note", "forSeq": attempt.seq})
        self.assertTrue(self.store.begin_send(early.id, now=self.now + 1, pid=1, start_ticks="1"))
        self.store.finish_send(early.id, delivery=Delivery.QUEUED, reason="codex_queued", provider_ref=None,
                               detail={}, now=self.now + 1)
        self._report(task.id, ReportKind.PROGRESS, ask=True, note="问题")
        self.assertEqual(self._view(task.id)[2].reason, "question_asked")

    def test_a_note_created_before_but_handed_over_after_the_question_does_not_answer_it(self) -> None:
        # 判断已回答用 created_at（§104.11 第 7 条）：补充先建立、再提问、再交出，仍在等回答
        task, attempt = self._task()
        self._report(task.id, ReportKind.ACK)
        early = self.store.add_attempt(task.id, role=Role.NOTICE, target=IMPL, body="先补一句", refs=[],
                                       now=self.now + 1, sender=LEAD, sender_class="bypass",
                                       options={"noticeKind": "note", "forSeq": attempt.seq})
        self._report(task.id, ReportKind.PROGRESS, ask=True, note="问题")
        self.assertTrue(self.store.begin_send(early.id, now=self.now + 5, pid=1, start_ticks="1"))
        self.store.finish_send(early.id, delivery=Delivery.QUEUED, reason="codex_queued", provider_ref=None,
                               detail={}, now=self.now + 5)
        self.assertEqual(self._view(task.id)[2].reason, "question_asked")

    def test_plain_progress_clears_the_question_even_at_the_same_time_or_after_a_clock_step_back(self) -> None:
        # Codex P2-03（§104.12 第 8 条）：普通 progress 在同一事务里清掉提问，不靠比较时刻；重复 ACK 照旧保留
        for step in (0.0, -20.0):
            with self.subTest(step=step):
                task, attempt = self._task()
                self._report(task.id, ReportKind.PROGRESS, ask=True, note="问题")
                self.now -= 10  # 抵消 _report 自己加的 10 秒：下一条与提问同一时刻
                self.now += step
                self._report(task.id, ReportKind.ACK)  # 重复 ACK：不清
                self.assertEqual(self._view(task.id)[2].reason, "question_asked")
                self.now -= 10
                self._report(task.id, ReportKind.PROGRESS, note="已解决")
                self.assertEqual(self._view(task.id)[2].reason, "in_progress")
                refreshed = self.store.get_attempt(attempt.id)
                assert refreshed is not None
                self.assertNotIn(ASK_OPTION, refreshed.options)

    def test_later_progress_clears_but_a_repeated_ack_does_not(self) -> None:
        task, _ = self._task()
        self._report(task.id, ReportKind.ACK)
        self._report(task.id, ReportKind.PROGRESS, ask=True, note="问题")
        self._report(task.id, ReportKind.ACK)  # 第二次起的 ack 不改时刻
        self.assertEqual(self._view(task.id)[2].reason, "question_asked")
        self._report(task.id, ReportKind.PROGRESS, note="自己想通了")
        self.assertEqual(self._view(task.id)[2].reason, "in_progress")

    def test_no_notify_keeps_the_panel_attention_without_a_receipt(self) -> None:
        task, _ = self._task(notify=False)
        outcome = self._report(task.id, ReportKind.PROGRESS, ask=True, note="问题")
        self.assertEqual(outcome.followups, [])
        self.assertEqual(classify(self._view(task.id)[2]), ("decision", True))

    def test_receipts_record_their_kind(self) -> None:
        for kind in (ReportKind.RESULT, ReportKind.BLOCKED, ReportKind.FAILED):
            with self.subTest(kind=kind):
                task, _ = self._task()
                [notice] = self._report(task.id, kind, note="x").followups
                self.assertEqual(notice.receipt_of, kind.value)

    def test_wait_returns_failure_reported_and_stopped_hint_is_suppressed(self) -> None:
        task, _ = self._task()
        self._report(task.id, ReportKind.PROGRESS, ask=True, note="问题")
        _, attempts, view = self._view(task.id)
        self.assertEqual(_wait_outcome(view, "result"), EXIT_FAILURE_REPORTED)  # 与受阻同组：要发起方处理
        current = view.current
        assert current is not None
        live = endpoint(IMPL, runtime=Runtime.IDLE)
        pane = PaneState(runtime=Runtime.IDLE, last_turn_ended_at=self.now + 1, fresh=True)
        self.assertIsNotNone(stopped_without_report(current, live, pane, now=self.now + 999))
        self.assertIsNone(stopped_without_report(current, live, pane, now=self.now + 999, attempts=attempts))
        self.assertTrue(ask_pending(current, attempts))


class FoldAskTests(unittest.TestCase):
    def test_ask_is_written_only_on_adoption_and_cleared_by_the_next_report(self) -> None:
        acked = fold_report({"work": "awaiting_ack"}, ReportKind.ACK, result={}, at=5)
        asked = fold_report(acked, ReportKind.PROGRESS, result={"note": "问题"}, at=6, ask=True)
        self.assertEqual(asked[ASK_OPTION], {"at": 6, "note": "问题"})
        self.assertEqual(fold_report(asked, ReportKind.ACK, result={}, at=7), asked)  # 被忽略的重复 ack 不清
        self.assertNotIn(ASK_OPTION, fold_report(asked, ReportKind.PROGRESS, result={"note": "x"}, at=8))
        self.assertNotIn(ASK_OPTION, fold_report(acked, ReportKind.PROGRESS, result={"note": "q"}, at=None, ask=True))
        self.assertNotIn(ASK_OPTION, fold_report(acked, ReportKind.BLOCKED, result={"note": "q"}, at=9, ask=True))

    def test_mirror_derivation_never_shows_a_question(self) -> None:
        rows = [(1, {"kind": "progress", "note": "问题", "ask": True, "refs": [], "source": "agent"}, "accepted")]
        self.assertEqual(derive_work("handoff", rows, report_high=1), {"work": "in_progress"})


class FederatedAskTests(FederationTestCase):
    def _asked(self, *, ask: bool = True):
        task, first = self.create()
        pump(self.a, self.b, now=T0 + 1)
        deliver(self.b, first.msg_id, "queued", now=T0 + 2)
        pump(self.b, self.a, now=T0 + 3)
        b_task = self.b.store.get_task(DEV_A, task.task_id)
        attempt = self.b.store.attempt_by_msg(first.msg_id)
        assert b_task is not None and attempt is not None
        result = mirror.submit_report(self.b.store, self.b.ident, LocalReport(
            task=b_task, attempt=attempt, kind="progress", note="A 还是 B？", refs=[], commit=None,
            reporter=self.worker_actor(), reporter_class="bypass", source="agent", ask=ask), now=T0 + 4)
        return task, first, result

    def test_report_frame_carries_the_optional_key_and_passes_the_codec(self) -> None:
        self._asked()
        [item] = [row for row in self.b.store.outbox() if '"kind":"report"' in row["envelope_json"]]
        envelope = json.loads(item["envelope_json"])
        check_envelope(envelope)  # codec 与 hub 不限制 data 的键集
        self.assertIs(envelope["data"]["report"]["ask"], True)
        self.assertEqual(envelope["data"]["report"]["kind"], "progress")

    def test_new_authority_marks_the_question_and_queues_a_result_receipt(self) -> None:
        task, first, _ = self._asked()
        pump(self.b, self.a, now=T0 + 5)
        current = self.a.store.get_task(DEV_A, task.task_id)
        assert current is not None
        attempts = model_attempts(self.a.store.attempts(DEV_A, task.task_id))
        view = describe(model_task(current), attempts)
        self.assertEqual((view.phase, view.reason), (Phase.NEEDS_ATTENTION, "question_asked"))
        receipt = [item for item in self.a.store.attempts(DEV_A, task.task_id) if item.role == "notice"]
        self.assertEqual(len(receipt), 1)
        self.assertEqual(receipt[0].options.get("noticeKind"), "result")  # 线上已有类别，不新增取值
        self.assertEqual(receipt[0].options.get("receiptOf"), "ask")
        self.assertTrue(receipt[0].body.startswith("对方在等你回答（任务仍在进行）：A 还是 B？"))
        # 镜像（B）不因提问显示需处理
        b_task = self.b.store.get_task(DEV_A, task.task_id)
        assert b_task is not None
        pump(self.a, self.b, now=T0 + 6)
        b_view = mirror.describe_view(b_task, self.b.store.attempts(DEV_A, task.task_id), device_id=DEV_B)
        self.assertNotEqual(b_view.reason, "question_asked")

    def test_authority_ignores_ask_on_a_non_progress_report_without_rejecting_the_frame(self) -> None:
        # 读方不比写方严（§104.11）：别的设备在 result 帧上也带了 ask，A 照常采纳为 result、不判提问、不拒帧
        task, first = self.create()
        pump(self.a, self.b, now=T0 + 1)
        deliver(self.b, first.msg_id, "queued", now=T0 + 2)
        pump(self.b, self.a, now=T0 + 3)
        b_task = self.b.store.get_task(DEV_A, task.task_id)
        attempt = self.b.store.attempt_by_msg(first.msg_id)
        assert b_task is not None and attempt is not None
        mirror.submit_report(self.b.store, self.b.ident, LocalReport(
            task=b_task, attempt=attempt, kind="result", note="做完了", refs=[], commit=None,
            reporter=self.worker_actor(), reporter_class="bypass", source="agent", ask=True), now=T0 + 4)
        [item] = [row for row in self.b.store.outbox() if '"kind":"report"' in row["envelope_json"]]
        self.assertIs(json.loads(item["envelope_json"])["data"]["report"]["ask"], True)  # 帧里确实带着
        pump(self.b, self.a, now=T0 + 5)
        current = self.a.store.get_task(DEV_A, task.task_id)
        assert current is not None
        attempts = self.a.store.attempts(DEV_A, task.task_id)
        [work] = [item for item in attempts if item.role == "handoff"]
        self.assertNotIn(ASK_OPTION, work.effective_work)
        view = describe(model_task(current), model_attempts(attempts))
        self.assertEqual((view.phase, view.reason), (Phase.AWAITING_ACCEPTANCE, "result_ready"))
        [receipt] = [item for item in attempts if item.role == "notice"]
        self.assertEqual(receipt.options.get("receiptOf"), "result")
        self.assertFalse(receipt.body.startswith("对方在等你回答"))  # work 已是 RESULT：帧被采纳，没有拒帧

    def test_progress_without_ask_still_does_not_notify(self) -> None:
        task, _, _ = self._asked(ask=False)
        # 不提问的汇报帧与旧版逐字节同形：不带 ask 键（线上只为提问加这一个可选键）
        [item] = [row for row in self.b.store.outbox() if '"kind":"report"' in row["envelope_json"]]
        self.assertNotIn("ask", json.loads(item["envelope_json"])["data"]["report"])
        pump(self.b, self.a, now=T0 + 5)
        self.assertEqual([item for item in self.a.store.attempts(DEV_A, task.task_id) if item.role == "notice"], [])

    def test_version_hint_follows_the_authority_features(self) -> None:
        task, _, _ = self._asked()
        b_task = self.b.store.get_task(DEV_A, task.task_id)
        assert b_task is not None
        rt = runtime(self.b, self.root)
        self.assertFalse(commands.authority_supports_ask(rt, b_task))  # 目录没缓存：按不认处理
        self.b.store.put_device_state(device_id=DEV_A, name="vm", revision=1, snapshot={"features": ["fyi"]},
                                      last_seen=T0, state="online")
        self.assertFalse(commands.authority_supports_ask(rt, b_task))
        self.b.store.put_device_state(device_id=DEV_A, name="vm", revision=2, snapshot={"features": ["fyi", "ask"]},
                                      last_seen=T0, state="online")
        self.assertTrue(commands.authority_supports_ask(rt, b_task))
        a_task = self.a.store.get_task(DEV_A, task.task_id)
        assert a_task is not None
        self.assertTrue(commands.authority_supports_ask(runtime(self.a, self.root), a_task))  # 本机就是权威


class FederatedAskCliTests(FedCliCase):
    """跨设备 `report --ask` 经真实 CLI：旧版本提示在文字与 --json 都给（§104.11 P3）。"""

    def test_old_authority_hint_reaches_text_and_json(self) -> None:
        task_id = self.delivered_task()
        code, out, err = self.run_on("win", "report", task_id, "--ask", "--note", "A 还是 B？", caller=as_agent(WORKER))
        self.assertEqual(code, 0, err)
        self.assertIn(f"提示：{ASK_OLD_AUTHORITY_HINT}", out)  # 目录没缓存发起设备的能力：按不认处理
        code, out, err = self.run_on("win", "report", task_id, "--ask", "--note", "再问一句", "--json",
                                     caller=as_agent(WORKER))
        self.assertEqual(code, 0, err)
        self.assertEqual(json.loads(out)["warnings"], [ASK_OLD_AUTHORITY_HINT])
        with self.store("win") as store:
            store.put_device_state(device_id=DEV_A, name="vm", revision=1, snapshot={"features": ["fyi", "ask"]},
                                   last_seen=T0, state="online")
        code, out, err = self.run_on("win", "report", task_id, "--ask", "--note", "第三问", "--json",
                                     caller=as_agent(WORKER))
        self.assertEqual(code, 0, err)
        self.assertEqual(json.loads(out)["warnings"], [])
        code, out, err = self.run_on("win", "report", task_id, "--progress", "--note", "进展", "--json",
                                     caller=as_agent(WORKER))
        self.assertEqual(json.loads(out)["warnings"], [])


if __name__ == "__main__":
    unittest.main()
