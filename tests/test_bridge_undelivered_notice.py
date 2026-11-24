"""确定未送达立即告知发起方（DESIGN §103.2）：四种终态立即、HELD/UNKNOWN 照旧 30 分钟、只告知一次、
originWatch 章回到 30 分钟、正文措辞、事件标签、补充消息（note）单独一支。"""

from __future__ import annotations

import json
import unittest

import bridge_support  # noqa: F401  导入即隔离宿主会话环境
import test_bridge_reminders as R
from agentstatus_bridge import views
from agentstatus_bridge.labels import ORIGIN_NOTIFIED_UNDELIVERED_LABEL
from agentstatus_bridge.model import (
    AUTO_RETRY_OPTION,
    Attempt,
    Delivery,
    FOR_SEQ_OPTION,
    NOTE_KIND,
    NOTICE_KIND_OPTION,
    ORIGIN_WATCH_OPTION,
    Role,
    work_attempts,
)
from agentstatus_bridge.reminders import REMIND_AFTER_SECONDS, REMINDER_OPTION, is_note_notice, pending_notices


class UndeliveredNoticeTests(unittest.TestCase):
    # 复用提醒用例的夹具（Dispatcher、假发现与假通道），不重跑那里的用例
    setUp = R.ReminderTests.setUp
    tearDown = R.ReminderTests.tearDown
    _discover = R.ReminderTests._discover
    _task = R.ReminderTests._task
    _run = R.ReminderTests._run
    _deliver = R.ReminderTests._deliver
    _pending = R.ReminderTests._pending
    _reminders = R.ReminderTests._reminders

    def _settle(self, task_id: str, delivery: Delivery, reason: str, *, options: dict[str, object] | None = None) -> None:
        """把当前工作尝试落定为指定投递状态（经 sending，与 worker 写法相同）。"""
        attempt = work_attempts(self.store.attempts(task_id))[-1]
        if options:
            with self.store.transaction() as conn:
                conn.execute("UPDATE attempts SET options=? WHERE id=?",
                             (json.dumps({**attempt.options, **options}), attempt.id))
        self.assertTrue(self.store.begin_send(attempt.id, now=self.now, pid=1, start_ticks="1"))
        self.assertTrue(self.store.finish_send(attempt.id, delivery=delivery, reason=reason, provider_ref=None,
                                               detail={}, now=self.now))

    def test_four_definite_states_are_notified_at_once_others_wait_thirty_minutes(self) -> None:
        cases = [
            (Delivery.FAILED, "codex_thread_not_found", True),
            (Delivery.REFUSED, "claude_refused", True),
            (Delivery.DENIED, "claude_denied", True),
            (Delivery.EXPIRED, "claude_expired", True),
            (Delivery.HELD, "claude_held", False),
            (Delivery.UNKNOWN, "codex_queue_timeout", False),
        ]
        for delivery, reason, immediate in cases:
            with self.subTest(delivery=delivery):
                task_id = self._task()
                self._settle(task_id, delivery, reason)
                pending = self._pending(task_id)
                assert pending is not None
                self.assertEqual(pending.immediate, immediate)
                self.assertEqual(pending.due_at, self.now if immediate else self.now + REMIND_AFTER_SECONDS)
                self._run()
                self.assertEqual(len(self._reminders(task_id)), 1 if immediate else 0)

    def test_body_wording_event_label_and_only_once(self) -> None:
        task_id = self._task()
        self._settle(task_id, Delivery.FAILED, "codex_thread_not_found")
        self._run()
        [notice] = self._reminders(task_id)
        lines = notice.body.splitlines()
        self.assertEqual(lines[0], "投递未成功：#1 尝试 Codex 找不到这个会话（可能已换新会话）（codex@id:impl-thread）。")
        self.assertIn("对方会话确定没有收到这条消息，可以安全重试。", lines)
        self.assertTrue(lines[-1].startswith("下一步："))
        self.assertIn("retry", lines[-1])
        self.assertNotIn("已自动重试", notice.body)
        self.assertNotIn("超过 30 分钟", notice.body)
        events = [event for event in self.store.events(task_id) if event["kind"] == "origin_reminded"]
        self.assertEqual([event["detail"] for event in events], [{"reason": "delivery_failed", "immediate": True}])
        task = self.store.get_task(task_id)
        assert task is not None
        timeline = "\n".join(views._timeline_lines(self.store.events(task_id)))  # pyright: ignore[reportPrivateUsage]
        self.assertIn(ORIGIN_NOTIFIED_UNDELIVERED_LABEL, timeline)
        # 同一次关注只告知一次：30 分钟、1 小时后都不再有第二条
        for _ in range(2):
            self.now += REMIND_AFTER_SECONDS
            self._run()
        self.assertEqual(len(self._reminders(task_id)), 1)

    def test_origin_watch_stamp_falls_back_to_thirty_minutes(self) -> None:
        task_id = self._task()
        self._settle(task_id, Delivery.FAILED, "codex_thread_not_found", options={ORIGIN_WATCH_OPTION: True})
        pending = self._pending(task_id)
        assert pending is not None
        self.assertEqual((pending.immediate, pending.due_at), (False, self.now + REMIND_AFTER_SECONDS))
        self._run()
        self.assertEqual(self._reminders(task_id), [])
        self.now += REMIND_AFTER_SECONDS
        self._run()
        [notice] = self._reminders(task_id)
        self.assertIn("超过 30 分钟", notice.body)  # 回到普通提醒

    def test_auto_retried_local_attempt_says_so(self) -> None:
        task_id = self._task()
        self._settle(task_id, Delivery.FAILED, "codex_server_overloaded",
                     options={AUTO_RETRY_OPTION: {"due": self.now, "first": "codex_deadline_before_send"}})
        self._run()
        [notice] = self._reminders(task_id)
        self.assertIn("已自动重试 1 次（首次：发送前等待 Codex 超时，消息确定没有送出）。", notice.body)

    def test_capacity_full_next_step_does_not_suggest_retry(self) -> None:
        task_id = self._task()
        for _ in range(58):  # 工作尝试到 #59；再插一条告知就到 60 的工作上限
            current = work_attempts(self.store.attempts(task_id))[-1]
            self.store.transition_delivery(current.id, expected=(Delivery.PENDING,), new=Delivery.CANCELLED,
                                           reason="cancelled", now=self.now)
            self.store.add_attempt(task_id, role=Role.HANDOFF, target=R.IMPL, body="x", refs=[], now=self.now,
                                   sender=None, sender_class=None)
        self._settle(task_id, Delivery.FAILED, "codex_thread_not_found")
        self._run()
        [notice] = self._reminders(task_id)
        step = notice.body.splitlines()[-1]
        self.assertIn("上限", step)
        self.assertNotIn(" retry ", step)

    def test_no_notice_without_origin_with_no_notify_or_when_origin_is_the_target(self) -> None:
        for kwargs in ({"origin": None}, {"options": {"notify": False}}):
            with self.subTest(**{key: repr(value) for key, value in kwargs.items()}):
                task_id = self._task(**kwargs)  # type: ignore[arg-type]
                self._settle(task_id, Delivery.FAILED, "codex_thread_not_found")
                self._run()
                self.assertEqual(self._reminders(task_id), [])

    def test_failed_note_gets_its_own_single_notice(self) -> None:
        task_id = self._task()
        work = work_attempts(self.store.attempts(task_id))[-1]
        self._deliver(work.id)
        note = self.store.add_attempt(task_id, role=Role.NOTICE, target=R.IMPL, body="补一句", refs=[], now=self.now,
                                      sender=R.LEAD, sender_class="bypass",
                                      options={NOTICE_KIND_OPTION: NOTE_KIND, FOR_SEQ_OPTION: work.seq})
        self.assertTrue(self.store.begin_send(note.id, now=self.now, pid=1, start_ticks="1"))
        self.store.finish_send(note.id, delivery=Delivery.FAILED, reason="codex_thread_not_found", provider_ref=None,
                               detail={}, now=self.now)
        task = self.store.get_task(task_id)
        assert task is not None
        # 工作尝试仍在进行：另有一条未到期的沉默提醒（§104.9 一），这里只看 note 支
        [pending] = [item for item in pending_notices(task, self.store.attempts(task_id)) if item.kind != "silent"]
        self.assertEqual((pending.immediate, pending.note.id if pending.note else None), (True, note.id))
        self._run()
        [notice] = self._reminders(task_id)
        self.assertTrue(is_note_notice(notice))
        lines = notice.body.splitlines()
        self.assertTrue(lines[0].startswith(f"投递未成功：补充 #{note.seq} "), lines[0])
        self.assertIn("对方会话确定没有收到这条补充，可以安全重新补充。", lines)
        self.assertIn(f"note {task_id[:8]}", lines[-1])
        event = [item for item in self.store.events(task_id) if item["kind"] == "origin_reminded"][-1]
        self.assertEqual(event["detail"], {"reason": "delivery_failed", "immediate": True, "noteSeq": note.seq})
        # 只一次；也不挡、不重置主提醒（主提醒此时没有：工作尝试仍在进行）。满 30 分钟另有一条沉默提醒（§104.9 一），
        # 它不是 note 支，这里不计
        self.now += REMIND_AFTER_SECONDS
        self._run()
        self.assertEqual(len([item for item in self._reminders(task_id) if not item.is_silent_reminder]), 1)

    def test_note_notice_neither_blocks_nor_resets_the_main_reminder(self) -> None:
        task_id = self._task()
        work = work_attempts(self.store.attempts(task_id))[-1]
        self._deliver(work.id)
        R.ReminderTests._report(self, task_id)  # type: ignore[arg-type]  交结果：主提醒从此刻计 30 分钟
        self._run()  # 结果回执交给发起方
        attention = self.now
        self.now += 600
        note = self.store.add_attempt(task_id, role=Role.NOTICE, target=R.IMPL, body="补一句", refs=[], now=self.now,
                                      sender=R.LEAD, sender_class="bypass",
                                      options={NOTICE_KIND_OPTION: NOTE_KIND, FOR_SEQ_OPTION: work.seq})
        self.store.begin_send(note.id, now=self.now, pid=1, start_ticks="1")
        self.store.finish_send(note.id, delivery=Delivery.FAILED, reason="codex_thread_not_found", provider_ref=None,
                               detail={}, now=self.now)
        self._run()  # note 告知排出并交给发起方
        self.assertEqual(len([item for item in self._reminders(task_id) if is_note_notice(item)]), 1)
        main = self._pending(task_id)
        assert main is not None
        self.assertEqual(main.due_at, attention + REMIND_AFTER_SECONDS)  # 不被 note 告知顺延

    def test_note_step_counts_the_notice_itself_against_capacity(self) -> None:
        # 告知自己占一个序号、重新补充再占一个：总序号 58 时还能补（告知 #59、新 note #60），59 时不再建议
        from agentstatus_bridge.reminders import reminder_body

        for last, suggests in ((58, True), (59, False)):
            with self.subTest(last=last):
                task_id = self._task()
                work = work_attempts(self.store.attempts(task_id))[-1]
                self._deliver(work.id)
                note = None
                for _ in range(last - 1):
                    note = self.store.add_attempt(task_id, role=Role.NOTICE, target=R.IMPL, body="补", refs=[],
                                                  now=self.now, sender=R.LEAD, sender_class="bypass",
                                                  options={NOTICE_KIND_OPTION: NOTE_KIND, FOR_SEQ_OPTION: work.seq})
                    self.store.transition_delivery(note.id, expected=(Delivery.PENDING,), new=Delivery.FAILED,
                                                   reason="codex_thread_not_found", now=self.now)
                assert note is not None and note.seq == last
                task = self.store.get_task(task_id)
                assert task is not None
                attempts = self.store.attempts(task_id)
                pending = [item for item in pending_notices(task, attempts) if item.note is not None
                           and item.note.id == note.id]
                self.assertEqual(len(pending), 1)
                body = reminder_body(task, attempts, pending[0].view, command="ab", note=pending[0].note)
                self.assertEqual(f"ab note {task_id[:8]}" in body.splitlines()[-1], suggests, body)

    def test_queued_note_notice_is_cancelled_when_the_work_attempt_changes(self) -> None:
        task_id = self._task()
        work = work_attempts(self.store.attempts(task_id))[-1]
        self._deliver(work.id)
        note = self.store.add_attempt(task_id, role=Role.NOTICE, target=R.IMPL, body="补一句", refs=[], now=self.now,
                                      sender=R.LEAD, sender_class="bypass",
                                      options={NOTICE_KIND_OPTION: NOTE_KIND, FOR_SEQ_OPTION: work.seq})
        self.store.begin_send(note.id, now=self.now, pid=1, start_ticks="1")
        self.store.finish_send(note.id, delivery=Delivery.FAILED, reason="codex_thread_not_found", provider_ref=None,
                               detail={}, now=self.now)
        self.lead_online = False  # 告知排进来但发不出去（发起方暂时不在）
        self.dispatcher.queue_reminders()
        [queued] = self._reminders(task_id)
        self.assertIs(queued.delivery, Delivery.PENDING)
        # 发起方 retry 出新的工作尝试：那条补充所补的已不是当前尝试，排着的告知发送前作废
        self.store.add_attempt(task_id, role=Role.HANDOFF, target=R.IMPL, body="重做", refs=[], now=self.now,
                               sender=None, sender_class=None)
        self.lead_online = True
        self._run()
        self.assertIs(self.store.get_attempt(queued.id).delivery, Delivery.CANCELLED)  # type: ignore[union-attr]
        self.assertTrue(REMINDER_OPTION in queued.options)

    def _failed_note(self, task_id: str, work_seq: int, *, target: object = R.IMPL) -> Attempt:
        """补一条 note 并落定为确定未送达（经 sending，与 worker 写法相同）。"""
        note = self.store.add_attempt(task_id, role=Role.NOTICE, target=target, body="补一句", refs=[],  # type: ignore[arg-type]
                                      now=self.now, sender=R.LEAD, sender_class="bypass",
                                      options={NOTICE_KIND_OPTION: NOTE_KIND, FOR_SEQ_OPTION: work_seq})
        self.assertTrue(self.store.begin_send(note.id, now=self.now, pid=1, start_ticks="1"))
        self.assertTrue(self.store.finish_send(note.id, delivery=Delivery.FAILED, reason="codex_thread_not_found",
                                               provider_ref=None, detail={}, now=self.now))
        return note

    def test_declined_note_notice_does_not_block_the_main_reminder(self) -> None:
        # §103.8 修 1：发起方拒收「补充未送达」的告知，不等于拒绝这次关注；主提醒照常 30 分钟后发出
        for declined in (Delivery.DENIED, Delivery.REFUSED):
            with self.subTest(declined=declined):
                task_id = self._task()
                work = work_attempts(self.store.attempts(task_id))[-1]
                self._deliver(work.id)
                R.ReminderTests._report(self, task_id)  # type: ignore[arg-type]  交结果：主提醒从此刻计 30 分钟
                self._run()
                attention = self.now
                self.now += 600
                self._failed_note(task_id, work.seq)
                self._run()
                [note_notice] = [item for item in self._reminders(task_id) if is_note_notice(item)]
                self.assertTrue(self.store.transition_delivery(
                    note_notice.id, expected=(Delivery.WRITTEN,), new=declined, reason="claude_denied", now=self.now))
                main = self._pending(task_id)
                assert main is not None, "被拒的 note 告知挡住了主提醒"
                self.assertEqual(main.due_at, attention + REMIND_AFTER_SECONDS)
                self.now = attention + REMIND_AFTER_SECONDS
                self._run()
                self.assertEqual(len([item for item in self._reminders(task_id) if not is_note_notice(item)]), 1)

    def test_declined_main_receipt_still_cancels_the_note_notice(self) -> None:
        # 另一个方向（§103.8 修 1/修 3）：note 支自己的拒绝判据不变——note 落定之后发起方拒绝了主回执，
        # 排着的 note 告知发送前作废
        task_id = self._task()
        work = work_attempts(self.store.attempts(task_id))[-1]
        self._deliver(work.id)
        self._failed_note(task_id, work.seq)
        self.lead_online = False  # 告知排进来但发不出去
        self.dispatcher.queue_reminders()
        [queued] = self._reminders(task_id)
        self.assertTrue(is_note_notice(queued))
        self.now += 10
        R.ReminderTests._report(self, task_id)  # type: ignore[arg-type]
        receipt = [item for item in self.store.attempts(task_id)
                   if item.role is Role.NOTICE and not item.is_note and REMINDER_OPTION not in item.options][-1]
        self.assertTrue(self.store.begin_send(receipt.id, now=self.now, pid=1, start_ticks="1"))
        self.store.finish_send(receipt.id, delivery=Delivery.WRITTEN, reason="claude_written", provider_ref=None,
                               detail={}, now=self.now)
        self.store.transition_delivery(receipt.id, expected=(Delivery.WRITTEN,), new=Delivery.DENIED,
                                       reason="claude_denied", now=self.now)
        self.lead_online = True
        sent = len(self.claude.calls)
        self._run()
        cancelled = self.store.get_attempt(queued.id)
        assert cancelled is not None
        self.assertEqual((cancelled.delivery, cancelled.delivery_reason), (Delivery.CANCELLED, "reminder_outdated"))
        self.assertEqual(len(self.claude.calls), sent)

    def test_declined_note_notice_still_cancels_a_later_note_notice(self) -> None:
        # note 支自己的拒绝判据不变（§103.8 修 1 只改主提醒一侧）：发起方拒收了一条 note 告知，
        # 同一批里另一条还没发出的 note 告知同样作废
        task_id = self._task()
        work = work_attempts(self.store.attempts(task_id))[-1]
        self._deliver(work.id)
        self._failed_note(task_id, work.seq)
        self.now += 1
        self._failed_note(task_id, work.seq)
        self.lead_online = False
        self.dispatcher.queue_reminders()
        first, second = self._reminders(task_id)
        self.assertTrue(is_note_notice(first) and is_note_notice(second))
        self.assertTrue(self.store.begin_send(first.id, now=self.now, pid=1, start_ticks="1"))
        self.store.finish_send(first.id, delivery=Delivery.WRITTEN, reason="claude_written", provider_ref=None,
                               detail={}, now=self.now)
        self.store.transition_delivery(first.id, expected=(Delivery.WRITTEN,), new=Delivery.DENIED,
                                       reason="claude_denied", now=self.now)
        self.lead_online = True
        self._run()
        cancelled = self.store.get_attempt(second.id)
        assert cancelled is not None
        self.assertEqual((cancelled.delivery, cancelled.delivery_reason), (Delivery.CANCELLED, "reminder_outdated"))

    def test_cli_needs_worker_for_a_lone_pending_note_notice(self) -> None:
        # §103.8 修 3（MX.9）：CLI 侧的 needs_worker 也要为待发的 note 告知拉起 worker——此时没有排队消息、
        # 没有观察窗口、也没有主提醒，只剩这一支
        from agentstatus_bridge.dispatch import CONSUMPTION_WATCH_SECONDS, needs_worker

        task_id = self._task()
        work = work_attempts(self.store.attempts(task_id))[-1]
        self._deliver(work.id)
        self.now += CONSUMPTION_WATCH_SECONDS + 1
        note = self.store.add_attempt(task_id, role=Role.NOTICE, target=R.IMPL, body="补一句", refs=[], now=self.now,
                                      sender=R.LEAD, sender_class="bypass",
                                      options={NOTICE_KIND_OPTION: NOTE_KIND, FOR_SEQ_OPTION: work.seq})
        self.assertTrue(self.store.transition_delivery(note.id, expected=(Delivery.PENDING,), new=Delivery.FAILED,
                                                       reason="codex_thread_not_found", now=self.now))
        self.assertIsNone(self._pending(task_id))
        self.assertTrue(needs_worker(self.store, self.now))
        self._run()  # 告知交出去之后就不再需要
        self.assertFalse(needs_worker(self.store, self.now + 3600))

    def test_note_to_the_origin_itself_gets_no_notice(self) -> None:
        # §103.8 修 3：note 的接收方就是发起方时，它自己已经知道没收到，不再告知
        task_id = self._task(origin=R.IMPL)
        work = work_attempts(self.store.attempts(task_id))[-1]
        self._deliver(work.id)
        self._failed_note(task_id, work.seq, target=R.IMPL)
        task = self.store.get_task(task_id)
        assert task is not None
        self.assertEqual(pending_notices(task, self.store.attempts(task_id)), [])
        self._run()
        self.assertEqual(self._reminders(task_id), [])

    def test_note_notice_is_offered_when_origin_differs(self) -> None:
        # 上一条的对照：同样的 note、发起方不是 note 接收方时照常告知（确认上一条不是因别的条件为空）
        task_id = self._task()
        work = work_attempts(self.store.attempts(task_id))[-1]
        self._deliver(work.id)
        self._failed_note(task_id, work.seq, target=R.IMPL)
        task = self.store.get_task(task_id)
        assert task is not None
        self.assertEqual(len([item for item in pending_notices(task, self.store.attempts(task_id))
                              if item.kind == "note"]), 1)


if __name__ == "__main__":
    unittest.main()
