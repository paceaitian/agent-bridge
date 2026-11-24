"""发送前瞬时失败自动重试一次（DESIGN §103.1）：闭集、只一次、同一消息 ID、中间失败对读方不可见、到期驱动与补记路径。"""

from __future__ import annotations

from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

import bridge_support  # noqa: F401  导入即隔离宿主会话环境
from agentstatus_bridge import summary, views
from agentstatus_bridge.dispatch import Dispatcher, needs_worker
from agentstatus_bridge.model import (
    AUTO_RETRY_DELAY_SECONDS,
    AUTO_RETRY_OPTION,
    AUTO_RETRY_REASONS,
    Consumption,
    Delivery,
    Flow,
    Phase,
    Provider,
    Role,
    auto_retry_pending,
    describe,
)
from agentstatus_bridge.reminders import pending_reminder
from agentstatus_bridge.store import Store, StoreError
from agentstatus_bridge.transports import DeliveryOutcome
from bridge_support import RecordingTransport, endpoint, ref

LEAD = ref(Provider.CLAUDE, "lead-session", pid=3000, pane="%3", label="lead")
IMPL = ref(Provider.CODEX, "impl-thread", pid=1000, pane="%1", label="impl")
DEADLINE = DeliveryOutcome(Delivery.FAILED, "codex_deadline_before_send",
                           detail={"queueChannel": "rpc", "preSendStage": "loaded", "preSendError": "_Timeout",
                                   "preSendCause": "TimeoutError", "preSendWinerror": 258})
OVERLOADED = DeliveryOutcome(Delivery.FAILED, "codex_server_overloaded", detail={"queueChannel": "rpc"})
QUEUED = DeliveryOutcome(Delivery.QUEUED, "codex_queued", provider_ref="item-1", detail={"queueChannel": "rpc"})


class AutoRetryTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = TemporaryDirectory()
        self.store = Store.open(Path(self._tmp.name) / "bridge")
        self.now = 1000.0
        self.outcomes: list[DeliveryOutcome] = []
        self.discoveries = 0
        self.codex = RecordingTransport(Provider.CODEX, lambda _e, _t, _c: self.outcomes.pop(0))
        self.records: list[tuple[str, dict[str, object]]] = []
        self.dispatcher = self._dispatcher()

    def tearDown(self) -> None:
        self.store.close()
        self._tmp.cleanup()

    def _dispatcher(self) -> Dispatcher:
        return Dispatcher(
            store=self.store,
            discover=self._discover,
            transports={Provider.CODEX: self.codex},
            clock=lambda: self.now,
            queue_state=lambda _item: Consumption.UNKNOWN,
            log=lambda event, fields: self.records.append((event, dict(fields))),
        )

    def _discover(self):
        self.discoveries += 1
        lead = endpoint(LEAD, socket_path="/run/test/lead.sock")
        return [lead] if getattr(self, "impl_gone", False) else [endpoint(IMPL), lead]

    def _task(self) -> str:
        task, _attempt = self.store.create_task(
            title="实现 X", flow=Flow.HANDOFF, origin=LEAD, origin_class="bypass", reviewer=None,
            target=IMPL, body="请实现 X", refs=[], now=self.now,
        )
        return task.id

    def _run(self) -> None:
        self.dispatcher._endpoints_at = None  # pyright: ignore[reportPrivateUsage]
        self.dispatcher.run_once()

    def _attempt(self, task_id: str):
        return [item for item in self.store.attempts(task_id) if item.role is not Role.NOTICE][-1]

    def test_closed_set_is_exactly_the_documented_codes(self) -> None:
        # DESIGN §103.1 第 0 步结论：两个基础码，加上经假内核用例证明重新发现后能成功的 Windows daemon 重启三码；
        # socket_missing（实际落成 codex_preflight_failed）与 Linux codex_daemon_conflict 不在内
        self.assertEqual(AUTO_RETRY_REASONS, {"codex_deadline_before_send", "codex_server_overloaded",
                                              "target_generation_changed", "daemon_changed", "boundary_store_busy"})
        self.assertEqual(AUTO_RETRY_DELAY_SECONDS, 60.0)

    def test_first_failure_is_invisible_and_retried_once_with_the_same_message(self) -> None:
        task_id = self._task()
        self.outcomes = [DEADLINE, QUEUED]
        self._run()
        attempt = self._attempt(task_id)
        # 中间那次失败：回到首发前的形状，对 status/摘要/提醒都只是「排队」
        self.assertIs(attempt.delivery, Delivery.PENDING)
        self.assertIsNone(attempt.delivery_reason)
        self.assertIsNone(attempt.delivery_at)
        self.assertIsNone(attempt.provider_ref)
        self.assertEqual(attempt.delivery_detail, {})
        self.assertEqual(attempt.options[AUTO_RETRY_OPTION],
                         {"due": 1000.0 + AUTO_RETRY_DELAY_SECONDS, "first": "codex_deadline_before_send",
                          "detail": {"preSendStage": "loaded", "preSendError": "_Timeout",
                                     "preSendCause": "TimeoutError", "preSendWinerror": 258}})
        kinds = [event["kind"] for event in self.store.events(task_id)]
        self.assertNotIn("delivery_failed", kinds)
        self.assertNotIn("delivery_pending", kinds)
        task = self.store.get_task(task_id)
        assert task is not None
        attempts = self.store.attempts(task_id)
        view = describe(task, attempts)
        self.assertEqual((view.phase, view.reason), (Phase.QUEUED, "waiting_for_target"))
        self.assertEqual(summary.classify(view), ("none", False))
        self.assertIsNone(pending_reminder(task, attempts))
        document = views._task_document(self.store, task, events=True)  # pyright: ignore[reportPrivateUsage]
        shown = document["attempts"][0]  # type: ignore[index]
        self.assertEqual((shown["delivery"], shown["deliveryReason"], shown["deliveryDetail"]), ("pending", None, {}))
        self.assertNotIn("codex_deadline_before_send", repr(document))
        self.assertIn(("delivery_retry_scheduled", {"task": task_id[:8], "attempt": 1,
                                                    "reason": "codex_deadline_before_send", "preSendStage": "loaded",
                                                    "preSendError": "_Timeout", "preSendCause": "TimeoutError",
                                                    "preSendWinerror": 258}), self.records)

        # 到期之前：不外调、不做发现，worker 仍要驻留（PENDING）
        self.now += AUTO_RETRY_DELAY_SECONDS - 1
        before = self.discoveries
        self._run()
        self.assertEqual(len(self.codex.calls), 1)
        self.assertEqual(self.discoveries, before)
        self.assertTrue(needs_worker(self.store, self.now))
        self.assertTrue(self.dispatcher.has_live_work())

        # 到期：同一尝试、同一消息 ID 再发一次；最终 detail 记是否重试过与首次原因码
        self.now += 1
        self._run()
        self.assertEqual(len(self.codex.calls), 2)
        self.assertEqual(self.codex.calls[0][2].message_uuid, self.codex.calls[1][2].message_uuid)
        final = self._attempt(task_id)
        self.assertEqual(final.id, attempt.id)
        self.assertIs(final.delivery, Delivery.QUEUED)
        self.assertEqual((final.delivery_detail["autoRetried"], final.delivery_detail["firstReason"]),
                         (True, "codex_deadline_before_send"))
        # 首投卡在哪一步：重试成功时只能从这里看到（DESIGN §103.1 诊断）
        self.assertEqual({key: value for key, value in final.delivery_detail.items() if key.startswith("firstPreSend")},
                         {"firstPreSendStage": "loaded", "firstPreSendError": "_Timeout",
                          "firstPreSendCause": "TimeoutError", "firstPreSendWinerror": 258})
        self.assertNotIn("preSendStage", final.delivery_detail)
        self.assertEqual(len(self.store.attempts(task_id)), 1)  # 不新增尝试、不占 §83 名额

    def test_second_transient_failure_is_final(self) -> None:
        task_id = self._task()
        self.outcomes = [DEADLINE, OVERLOADED]
        self._run()
        self.now += AUTO_RETRY_DELAY_SECONDS
        self._run()
        final = self._attempt(task_id)
        self.assertIs(final.delivery, Delivery.FAILED)
        self.assertEqual(final.delivery_reason, "codex_server_overloaded")
        self.assertEqual(final.delivery_detail["firstReason"], "codex_deadline_before_send")
        self.now += 10 * AUTO_RETRY_DELAY_SECONDS
        self._run()
        self.assertEqual(len(self.codex.calls), 2)  # 最多一次
        self.assertIn("delivery_failed", [event["kind"] for event in self.store.events(task_id)])

    def test_overloaded_is_retried_too(self) -> None:
        task_id = self._task()
        self.outcomes = [OVERLOADED, QUEUED]
        self._run()
        self.assertIs(self._attempt(task_id).delivery, Delivery.PENDING)
        self.now += AUTO_RETRY_DELAY_SECONDS
        self._run()
        self.assertIs(self._attempt(task_id).delivery, Delivery.QUEUED)

    def test_unknown_and_other_failures_are_not_retried(self) -> None:
        cases = [
            DeliveryOutcome(Delivery.UNKNOWN, "codex_queue_timeout"),
            DeliveryOutcome(Delivery.UNKNOWN, "codex_deadline_before_send"),  # 原因码对、状态不明：仍不重发
            DeliveryOutcome(Delivery.FAILED, "codex_preflight_failed"),
            DeliveryOutcome(Delivery.UNKNOWN, "daemon_changed"),
            DeliveryOutcome(Delivery.FAILED, "socket_missing"),
            DeliveryOutcome(Delivery.FAILED, "target_gone"),
            DeliveryOutcome(Delivery.FAILED, "boundary_record_failed"),
            DeliveryOutcome(Delivery.FAILED, "codex_daemon_conflict"),
            DeliveryOutcome(Delivery.FAILED, "claude_socket_connect_failed"),
        ]
        for outcome in cases:
            with self.subTest(reason=outcome.reason, delivery=outcome.delivery):
                task_id = self._task()
                self.outcomes = [outcome]
                calls = len(self.codex.calls)
                self._run()
                final = self._attempt(task_id)
                self.assertIs(final.delivery, outcome.delivery)
                self.assertNotIn(AUTO_RETRY_OPTION, final.options)
                self.now += AUTO_RETRY_DELAY_SECONDS
                self._run()
                self.assertEqual(len(self.codex.calls), calls + 1)

    def test_worker_restart_keeps_the_due_time_and_retries_once(self) -> None:
        task_id = self._task()
        self.outcomes = [DEADLINE, QUEUED]
        self._run()
        # 新 worker（新 Dispatcher）接手：到期时刻在账本里，不丢、不提前、不重复
        self.dispatcher = self._dispatcher()
        self.now += 30
        self._run()
        self.assertEqual(len(self.codex.calls), 1)
        self.now += 30
        self._run()
        self.assertEqual(len(self.codex.calls), 2)
        self.assertIs(self._attempt(task_id).delivery, Delivery.QUEUED)

    def test_deferred_record_still_goes_through_the_retry_decision(self) -> None:
        task_id = self._task()
        self.outcomes = [DEADLINE, QUEUED]
        original = self.store.requeue_for_retry
        failures = [StoreError("store_busy")]

        def flaky(*args, **kwargs):
            if failures:
                raise failures.pop()
            return original(*args, **kwargs)

        with patch.object(self.store, "requeue_for_retry", side_effect=flaky):
            self._run()
            self.assertIs(self._attempt(task_id).delivery, Delivery.SENDING)
            self._run()  # 补记：仍按重试判定改回 PENDING，不落成 FAILED
        attempt = self._attempt(task_id)
        self.assertIs(attempt.delivery, Delivery.PENDING)
        self.assertIn(AUTO_RETRY_OPTION, attempt.options)
        self.assertNotIn("delivery_failed", [event["kind"] for event in self.store.events(task_id)])

    def test_notices_are_retried_like_work(self) -> None:
        task_id = self._task()
        self.outcomes = [QUEUED]
        self._run()
        notice = self.store.add_attempt(task_id, role=Role.NOTICE, target=IMPL, body="通知", refs=[], now=self.now,
                                        sender=None, sender_class=None)
        self.outcomes = [DEADLINE, QUEUED]
        self._run()
        self.assertIs(self.store.get_attempt(notice.id).delivery, Delivery.PENDING)  # type: ignore[union-attr]
        self.now += AUTO_RETRY_DELAY_SECONDS
        self._run()
        self.assertIs(self.store.get_attempt(notice.id).delivery, Delivery.QUEUED)  # type: ignore[union-attr]

    def test_cancel_during_the_wait_stops_the_retry(self) -> None:
        task_id = self._task()
        self.outcomes = [DEADLINE]
        self._run()
        attempt = self._attempt(task_id)
        self.assertTrue(self.store.transition_delivery(attempt.id, expected=(Delivery.PENDING,),
                                                       new=Delivery.CANCELLED, reason="cancelled", now=self.now))
        self.now += AUTO_RETRY_DELAY_SECONDS
        self._run()
        self.assertEqual(len(self.codex.calls), 1)

    def test_due_time_is_bounded_against_clock_rollback(self) -> None:
        options = {AUTO_RETRY_OPTION: {"due": 1060.0, "first": "codex_deadline_before_send"}}
        self.assertTrue(auto_retry_pending(options, 1000.0))
        self.assertFalse(auto_retry_pending(options, 1060.0))
        # 本机时钟回拨：到期时刻离现在超过一个 D，按已到期处理，不卡住
        self.assertFalse(auto_retry_pending(options, 900.0))
        self.assertFalse(auto_retry_pending({AUTO_RETRY_OPTION: {"due": True}}, 1000.0))
        self.assertFalse(auto_retry_pending({}, 1000.0))

    def test_requeue_happens_at_most_once_in_the_store(self) -> None:
        task_id = self._task()
        attempt = self._attempt(task_id)
        self.assertTrue(self.store.begin_send(attempt.id, now=self.now, pid=1, start_ticks="1"))
        self.assertTrue(self.store.requeue_for_retry(attempt.id, due=self.now + 60, first="codex_deadline_before_send"))
        self.assertFalse(self.store.requeue_for_retry(attempt.id, due=self.now + 60, first="x"))  # 已不是 sending
        self.assertTrue(self.store.begin_send(attempt.id, now=self.now, pid=1, start_ticks="1"))
        self.assertFalse(self.store.requeue_for_retry(attempt.id, due=self.now + 60, first="x"))  # 已重试过

    def test_requeue_only_flips_a_sending_attempt(self) -> None:
        # §103.8 修 3（MX.4）：迟到的闭集 FAILED 不得把已落定 UNKNOWN 的尝试翻回 PENDING；返回 False、行原样不动
        task_id = self._task()
        attempt = self._attempt(task_id)
        self.assertTrue(self.store.begin_send(attempt.id, now=self.now, pid=1, start_ticks="1"))
        self.assertTrue(self.store.finish_send(attempt.id, delivery=Delivery.UNKNOWN, reason="codex_queue_timeout",
                                               provider_ref=None, detail={"queueChannel": "rpc"}, now=self.now))
        before = self.store.get_attempt(attempt.id)
        self.assertFalse(self.store.requeue_for_retry(attempt.id, due=self.now + 60, first="codex_deadline_before_send"))
        self.assertEqual(self.store.get_attempt(attempt.id), before)
        assert before is not None
        self.assertNotIn(AUTO_RETRY_OPTION, before.options)

    def test_task_finished_during_the_outbound_call_ends_failed_not_pending(self) -> None:
        # §103.8 修 6：外调期间任务被关闭或验收——不重排（begin_send 同一谓词），照常落 FAILED，不永久停在 PENDING；
        # 被暂停的照常重排，resume 后到期即发（暂停本来不会造成永久 PENDING，功能优先）
        changes = {
            "closed": {"closed_at": 1.0, "close_reason": "closed"},
            "accepted": {"accepted_at": 1.0},
            "paused": {"control": "paused"},
        }
        for event, fields in changes.items():
            with self.subTest(event=event):
                task_id = self._task()
                calls = len(self.codex.calls)

                def finish_then_fail(_endpoint: object, _text: str, _context: object) -> DeliveryOutcome:
                    self.store.update_task(task_id, now=self.now, event=event, **fields)
                    return DEADLINE

                self.codex._outcome = finish_then_fail  # pyright: ignore[reportPrivateUsage]
                try:
                    self._run()
                finally:
                    self.codex._outcome = lambda _e, _t, _c: self.outcomes.pop(0)  # pyright: ignore[reportPrivateUsage]
                attempt = self._attempt(task_id)
                if event == "paused":
                    self.assertIs(attempt.delivery, Delivery.PENDING)
                    self.assertIn(AUTO_RETRY_OPTION, attempt.options)
                    self.now += AUTO_RETRY_DELAY_SECONDS
                    self._run()  # 到期但仍暂停：不发
                    self.assertEqual(len(self.codex.calls), calls + 1)
                    self.store.update_task(task_id, now=self.now, event="resumed", control="active")
                    self.outcomes = [QUEUED]
                    self._run()
                    self.assertEqual(len(self.codex.calls), calls + 2)
                    self.assertIs(self._attempt(task_id).delivery, Delivery.QUEUED)
                    continue
                self.assertEqual((attempt.delivery, attempt.delivery_reason),
                                 (Delivery.FAILED, "codex_deadline_before_send"))
                self.assertNotIn(AUTO_RETRY_OPTION, attempt.options)
                self.now += AUTO_RETRY_DELAY_SECONDS
                self._run()
                self.assertEqual(len(self.codex.calls), calls + 1)

    def test_target_gone_at_the_retry_still_records_the_auto_retry(self) -> None:
        # §103.8 修 7：到期重试时在发送前就失败（目标已不在，_fail 落 target_gone），传输只调用过 1 次；
        # 最终 detail 仍带 autoRetried/firstReason/firstPreSend*，与立即告知正文「已自动重试 1 次」一致
        from agentstatus_bridge.dispatch import TARGET_GONE_GRACE_SECONDS

        task_id = self._task()
        self.outcomes = [DEADLINE]
        self._run()
        self.impl_gone = True
        self.now += AUTO_RETRY_DELAY_SECONDS
        self._run()
        self.now += TARGET_GONE_GRACE_SECONDS
        self._run()
        attempt = self._attempt(task_id)
        self.assertEqual((attempt.delivery, attempt.delivery_reason), (Delivery.FAILED, "target_gone"))
        self.assertEqual(len(self.codex.calls), 1)
        self.assertEqual({key: attempt.delivery_detail.get(key) for key in
                          ("autoRetried", "firstReason", "firstPreSendStage", "firstPreSendError")},
                         {"autoRetried": True, "firstReason": "codex_deadline_before_send",
                          "firstPreSendStage": "loaded", "firstPreSendError": "_Timeout"})
        self._run()  # 下一轮排出立即告知
        [notice] = [item for item in self.store.attempts(task_id) if item.role is Role.NOTICE]
        self.assertIn("已自动重试 1 次（首次：", notice.body)

    def test_render_failure_at_the_retry_still_records_the_auto_retry(self) -> None:
        # 修 7 同口径：到期重试时渲染失败（render_failed，同样不经 finish_send）也补 autoRetried/firstReason
        from agentstatus_bridge import dispatch as D

        task_id = self._task()
        self.outcomes = [DEADLINE]
        self._run()
        self.now += AUTO_RETRY_DELAY_SECONDS
        with patch.object(D.envelope, "render", side_effect=RuntimeError("fixture")):
            self._run()
        attempt = self._attempt(task_id)
        self.assertEqual((attempt.delivery, attempt.delivery_reason), (Delivery.FAILED, "render_failed"))
        self.assertEqual((attempt.delivery_detail.get("autoRetried"), attempt.delivery_detail.get("firstReason")),
                         (True, "codex_deadline_before_send"))
        self.assertEqual(len(self.codex.calls), 1)

    def test_closure_receipt_is_still_retried_after_the_task_finished(self) -> None:
        # 修 6 的豁免与 begin_send 一致：任务结束后才生成的结束回执，照样可以自动重试一次
        from agentstatus_bridge.model import CLOSURE_KIND, NOTICE_KIND_OPTION

        task_id = self._task()
        self.outcomes = [QUEUED]
        self._run()
        self.store.update_task(task_id, now=self.now, event="closed", closed_at=self.now, close_reason="closed")
        receipt = self.store.add_attempt(task_id, role=Role.NOTICE, target=IMPL, body="结束", refs=[], now=self.now,
                                         sender=None, sender_class=None, options={NOTICE_KIND_OPTION: CLOSURE_KIND})
        self.outcomes = [DEADLINE, QUEUED]
        self._run()
        self.assertIs(self.store.get_attempt(receipt.id).delivery, Delivery.PENDING)  # type: ignore[union-attr]
        self.now += AUTO_RETRY_DELAY_SECONDS
        self._run()
        self.assertIs(self.store.get_attempt(receipt.id).delivery, Delivery.QUEUED)  # type: ignore[union-attr]

    def _note(self, task_id: str, work_seq: int):
        from agentstatus_bridge.model import FOR_SEQ_OPTION, NOTE_KIND, NOTICE_KIND_OPTION

        return self.store.add_attempt(task_id, role=Role.NOTICE, target=IMPL, body="补一句", refs=[], now=self.now,
                                      sender=LEAD, sender_class="bypass",
                                      options={NOTICE_KIND_OPTION: NOTE_KIND, FOR_SEQ_OPTION: work_seq})

    def test_note_waits_behind_its_work_attempt_awaiting_retry(self) -> None:
        # §103.8 修 4，复现审计实验的顺序：首投发送前失败 → 发起方补 note → 工作消息重试。
        # 修复前 note 立即送出、排在工作消息前面；修复后工作消息先、note 后，等待期间也不做发现
        task_id = self._task()
        work = self._attempt(task_id)
        notes = []

        def outcome(_endpoint: object, _text: str, _context: object) -> DeliveryOutcome:
            if not notes:  # 外调期间发起方补 note（ab note 认 SENDING 的工作尝试），随后这次外调发送前失败
                notes.append(self._note(task_id, work.seq))
                return DEADLINE
            return self.outcomes.pop(0)

        self.codex._outcome = outcome  # pyright: ignore[reportPrivateUsage]
        self._run()
        [note] = notes
        self.outcomes = [QUEUED, QUEUED]
        discoveries = self.discoveries
        self._run()
        self.assertEqual(len(self.codex.calls), 1)
        self.assertIs(self.store.get_attempt(note.id).delivery, Delivery.PENDING)  # type: ignore[union-attr]
        self.assertEqual(self.discoveries, discoveries)
        self.assertTrue(needs_worker(self.store, self.now))
        self.now += AUTO_RETRY_DELAY_SECONDS
        self._run()
        sent = [call[2].message_uuid for call in self.codex.calls]
        self.assertEqual(len(sent), 3)
        self.assertEqual(sent[1], sent[0])  # 工作消息重试在前（同一消息 ID）
        self.assertNotEqual(sent[2], sent[0])  # note 在后
        self.assertIs(self.store.get_attempt(note.id).delivery, Delivery.QUEUED)  # type: ignore[union-attr]

    def test_note_is_released_when_its_work_attempt_finally_fails(self) -> None:
        # 只在 PENDING/SENDING 时等：工作消息重试后仍确定失败，note 照常派发，不永久等待
        task_id = self._task()
        self.outcomes = [DEADLINE]
        self._run()
        work = self._attempt(task_id)
        note = self._note(task_id, work.seq)
        self.now += AUTO_RETRY_DELAY_SECONDS
        self.outcomes = [DEADLINE, QUEUED]
        self._run()
        self.assertIs(self.store.get_attempt(work.id).delivery, Delivery.FAILED)  # type: ignore[union-attr]
        self.assertIs(self.store.get_attempt(note.id).delivery, Delivery.QUEUED)  # type: ignore[union-attr]

    def test_note_waits_while_its_work_attempt_is_being_sent(self) -> None:
        # SENDING（别的 worker 正在外调）同样等：dispatch 返回 waiting，不判目标缺席
        task_id = self._task()
        work = self._attempt(task_id)
        self.assertTrue(self.store.begin_send(work.id, now=self.now, pid=1, start_ticks="1"))
        note = self._note(task_id, work.seq)
        self.assertEqual(self.dispatcher.dispatch(note, [endpoint(IMPL)]), "waiting")
        self.assertEqual(self.dispatcher.dispatch(note, []), "waiting")
        self.assertEqual(self.dispatcher._missing_since, {})  # pyright: ignore[reportPrivateUsage]
        self.assertEqual(self.codex.calls, [])


if __name__ == "__main__":
    unittest.main()
