"""§83：真实 SQLite 容量边界；发现、传输只用离线夹具，不连接真实服务。"""

from pathlib import Path
from tempfile import TemporaryDirectory
import sqlite3
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from agentstatus_bridge import reports, summary
from agentstatus_bridge.closure import CLOSED, queue_closures
from agentstatus_bridge.dispatch import Dispatcher, needs_worker
from agentstatus_bridge.endpoints import Caller
from agentstatus_bridge.model import Consumption, Delivery, Flow, Provider, ReportKind, Role, Verdict, Work
from agentstatus_bridge.naming import DEFAULT_COMMAND
from agentstatus_bridge.reminders import REMINDER_OPTION, pending_reminder
from agentstatus_bridge.reports import ReportError, ReportInput, apply_report
from agentstatus_bridge.store import Store, StoreError
from bridge_support import RecordingTransport, endpoint, ref

IMPL = ref(Provider.CLAUDE, 'capacity-impl', pid=41001, label='impl')
REVIEW = ref(Provider.CLAUDE, 'capacity-review', pid=41002, label='review')
LEAD = ref(Provider.CODEX, 'capacity-lead', pid=41003, label='lead')


class CapacityTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.store = Store.open(self.root / 'ledger')
        self.addCleanup(self.store.close)
        self.now = 1000.0

    def task(self, *, review=False, notify=True):
        task, attempt = self.store.create_task(
            title='capacity fixture', flow=Flow.REVIEW if review else Flow.HANDOFF,
            origin=LEAD, origin_class='bypass', reviewer=REVIEW if review else None,
            target=IMPL, body='offline fixture', refs=[], now=self.now,
            task_options={'notify': notify},
        )
        self.sent(attempt)
        return task, attempt

    def sent(self, attempt):
        self.assertTrue(self.store.begin_send(attempt.id, now=self.now, pid=1, start_ticks='1'))
        self.store.finish_send(attempt.id, delivery=Delivery.DELIVERED, reason='test',
                               provider_ref=None, detail={}, now=self.now)

    def add(self, task, role=Role.NOTICE, *, options=None):
        target = LEAD if role is Role.NOTICE else REVIEW if role is Role.REVIEW else IMPL
        return self.store.add_attempt(task.id, role=role, target=target, body='fixture',
                                      refs=[], now=self.now, sender=LEAD, sender_class='bypass', options=options)

    def fill(self, task, total):
        while len(self.store.attempts(task.id)) < total:
            self.sent(self.add(task))

    def report(self, task, attempt, kind=ReportKind.RESULT):
        try:
            return apply_report(self.store, ReportInput(task.id, kind, attempt_seq=attempt.seq, note='pinned result'),
                                caller=Caller(endpoint(attempt.target), None), caller_class='bypass', now=self.now,
                                cwd=self.root)
        except StoreError as error:
            if error.code in ('capacity_attempts', 'capacity_pending'):
                self.fail(f'终态汇报被容量回滚：{error.code}')
            raise

    def dispatcher(self):
        transport = RecordingTransport(Provider.CODEX)
        dispatcher = Dispatcher(store=self.store, discover=lambda: [endpoint(LEAD)],
                                transports={Provider.CODEX: transport}, clock=lambda: self.now,
                                queue_state=lambda _: Consumption.UNKNOWN, device='fixture', command='ab')
        return dispatcher, transport

    def fill_global_pending(self):
        """真实填满 256 个 PENDING，返回条目以便在用例内模拟队列腾空。"""
        queued = []
        # 填充任务不通知发起方：它们的工作尝试一直开放，否则满 30 分钟会各自排沉默提醒（§104.9 一），干扰本用例的计数
        for _ in range(4):
            other, _ = self.task(notify=False)
            queued.extend(self.add(other) for _ in range(63))
        extra, _ = self.task(notify=False)
        queued.extend(self.add(extra) for _ in range(4))
        return queued

    def test_capacity_attempts_raise_before_any_write_in_outer_transaction(self):
        task, _ = self.task()
        self.fill(task, 64)
        with self.store.transaction() as conn:
            before = (conn.total_changes, self.store.ledger_revision())
            with self.assertRaises(StoreError) as caught:
                self.add(task)
            self.assertEqual(caught.exception.code, 'capacity_attempts')
            self.assertEqual((conn.total_changes, self.store.ledger_revision()), before)

    def test_capacity_pending_raise_before_any_write_in_outer_transaction(self):
        task, _ = self.task()
        self.fill_global_pending()
        with self.store.transaction() as conn:
            before = (conn.total_changes, self.store.ledger_revision())
            with self.assertRaises(StoreError) as caught:
                self.add(task)
            self.assertEqual(caught.exception.code, 'capacity_pending')
            self.assertEqual((conn.total_changes, self.store.ledger_revision()), before)

    def test_successful_review_with_poll_only_origin_has_no_skipped_event(self):
        task, work = self.task(review=True)
        with patch.object(reports, 'can_notify', side_effect=lambda target: not target.same_session(LEAD)):
            outcome = self.report(task, work)
        self.assertEqual([a.role for a in outcome.followups], [Role.REVIEW])
        self.assertEqual(outcome.skipped, {})
        self.assertNotIn('notification_skipped', [e['kind'] for e in self.store.events(task.id)])

    def test_pending_capacity_recovers_via_reminder_only_when_attempt_budget_allows(self):
        for total in (59, 60, 61):
            with self.subTest(total=total):
                self.store = self.enterContext(Store.open(self.root / f'reminder-{total}'))
                self.now = 1000.0
                task, work = self.task()
                self.fill(task, total)
                queued = self.fill_global_pending()
                outcome = self.report(task, work, ReportKind.BLOCKED)
                self.assertEqual(outcome.skipped, {'result': 'capacity_pending'})
                self.assertEqual(outcome.attempt.work, Work.BLOCKED)
                for item in queued:
                    self.sent(item)
                dispatcher, transport = self.dispatcher()
                self.now += 1799
                dispatcher.run_once()
                self.assertEqual(transport.calls, [])
                self.now += 1
                dispatcher.run_once()
                if total <= 60:
                    self.assertEqual(len(transport.calls), 1)
                    reminder = self.store.attempts(task.id)[-1]
                    self.assertEqual(reminder.seq, total + 1)
                    self.assertIn(REMINDER_OPTION, reminder.options)
                    self.assertNotIn('retry', reminder.body)
                    self.assertIn('close', reminder.body)
                    self.assertTrue(transport.calls[0][0].ref.same_session(LEAD))
                    entry = summary._task_entry(self.store.get_task(task.id), self.store.attempts(task.id))
                    self.assertEqual(entry['next']['action'], 'rework_or_close')
                    self.assertNotIn('retry', entry['next']['text'])
                    self.assertNotIn('retry', entry['next']['command'])
                else:
                    self.assertEqual(transport.calls, [])
                    self.assertEqual(len(self.store.attempts(task.id)), 61)
                    self.assertIsNone(pending_reminder(self.store.get_task(task.id), self.store.attempts(task.id)))

    def test_held_unknown_at_capacity_preserve_conditions_in_worker_reminder_and_summary(self):
        for delivery in (Delivery.HELD, Delivery.UNKNOWN):
            with self.subTest(delivery=delivery):
                self.store = self.enterContext(Store.open(self.root / f'conditional-{delivery.value}'))
                self.now = 1000.0
                task, _ = self.task()
                self.fill(task, 59)
                work = self.add(task, Role.HANDOFF)
                self.assertEqual(work.seq, 60)
                self.assertTrue(self.store.begin_send(work.id, now=self.now, pid=1, start_ticks='1'))
                self.store.finish_send(work.id, delivery=delivery, reason='fixture',
                                       provider_ref=None, detail={}, now=self.now)
                dispatcher, transport = self.dispatcher()
                self.now += 1900
                dispatcher.run_once()
                self.assertEqual(len(transport.calls), 1)
                reminder = self.store.attempts(task.id)[-1]
                self.assertEqual(reminder.seq, 61)
                self.assertIn(REMINDER_OPTION, reminder.options)
                self.assertIn(reminder.body, transport.calls[0][1])
                entry = summary._task_entry(self.store.get_task(task.id), self.store.attempts(task.id))
                step = entry['next']
                if delivery is Delivery.HELD:
                    self.assertEqual(step['action'], 'approve_at_target')
                    self.assertIsNone(step['command'])
                    for text in (reminder.body, step['text']):
                        self.assertIn('批准这条消息；若已过期，', text)
                else:
                    self.assertEqual(step['action'], 'confirm_then_force_retry')
                    self.assertEqual(step['command'], f'{DEFAULT_COMMAND} close {task.id}')
                    for text in (reminder.body, step['text']):
                        self.assertIn('不会自动重发', text)
                        self.assertIn('先确认对方没收到（也不会再汇报），再', text)
                self.assertFalse(self.store.get_task(task.id).finished)
                self.assertEqual(self.store.get_attempt(work.id).delivery, delivery)

    def test_alternating_work_and_notices_reserve_last_result_and_wake_origin(self):
        task, work = self.task()
        for _ in range(29):
            notice = self.report(task, work, ReportKind.BLOCKED).followups[0]
            self.sent(notice)
            work = self.add(task, Role.HANDOFF)
            self.sent(work)
        self.assertEqual(work.seq, 59)
        notice = self.report(task, work, ReportKind.BLOCKED).followups[0]
        self.assertEqual(notice.seq, 60)
        self.sent(notice)
        # 第 61 个名额可给提醒，但不能再开一轮工作。
        for role in (Role.HANDOFF, Role.REVIEW):
            with self.assertRaises(StoreError) as caught:
                self.add(task, role)
            self.assertEqual(caught.exception.code, 'capacity_attempts')
        dispatcher, transport = self.dispatcher()
        self.now += 1900
        dispatcher.run_once()
        reminder = self.store.attempts(task.id)[-1]
        self.assertEqual(reminder.seq, 61)
        self.assertIn(REMINDER_OPTION, reminder.options)
        self.assertEqual(len(transport.calls), 1)
        outcome = self.report(task, work)
        self.assertEqual((outcome.attempt.work, outcome.followups[0].seq), (Work.RESULT, 62))
        self.assertEqual(outcome.attempt.result['note'], 'pinned result')
        dispatcher.run_once()
        self.assertEqual(len(transport.calls), 2)
        self.assertTrue(transport.calls[-1][0].ref.same_session(LEAD))
        self.assertIn('pinned result', transport.calls[-1][1])
        self.assertEqual(self.store.get_attempt(outcome.followups[0].id).delivery, Delivery.QUEUED)

    def test_reminder_cannot_take_final_notice_or_two_closure_slots(self):
        task, _ = self.task(review=True)
        reviewer = self.add(task, Role.REVIEW)
        self.sent(reviewer)
        self.fill(task, 60)
        self.report(task, reviewer, ReportKind.BLOCKED)  # notice 61
        self.sent(self.store.attempts(task.id)[-1])
        self.assertIsNone(pending_reminder(self.store.get_task(task.id), self.store.attempts(task.id)))
        for _ in range(2):
            with self.assertRaises(StoreError) as caught:
                self.add(task, options={REMINDER_OPTION: 'new-token'})
            self.assertEqual(caught.exception.code, 'capacity_attempts')
        dispatcher, _ = self.dispatcher()
        self.now += 2000
        self.assertFalse(needs_worker(self.store, self.now))
        self.assertFalse(dispatcher.has_live_work())
        self.assertEqual(self.report(task, reviewer, ReportKind.APPROVE).followups[0].seq, 62)
        with self.store.transaction():
            closures = queue_closures(self.store, self.store.get_task(task.id), self.store.attempts(task.id), CLOSED,
                                      now=self.now, decider='fixture', reason=None, sender=LEAD, sender_class='bypass')
            self.store.update_task(task.id, now=self.now, event='closed', closed_at=self.now)
        self.assertEqual([a.seq for a in closures.queued], [63, 64])
        self.assertEqual(closures.skipped, [])
        with self.assertRaises(StoreError) as caught:
            self.add(task)
        self.assertEqual(caught.exception.code, 'capacity_attempts')

    def test_work_sequence_60_is_allowed_but_61_is_not(self):
        for role in (Role.HANDOFF, Role.REVIEW):
            with self.subTest(role=role):
                task, _ = self.task()
                self.fill(task, 59)
                self.assertEqual(self.add(task, role).seq, 60)
                with self.assertRaises(StoreError) as caught:
                    self.add(task, role)
                self.assertEqual(caught.exception.code, 'capacity_attempts')
                self.assertEqual(len(self.store.attempts(task.id)), 60)

    def test_all_terminal_reports_commit_at_64_and_pending_256(self):
        for capacity in ('attempts', 'pending'):
            for kind in (ReportKind.RESULT, ReportKind.BLOCKED, ReportKind.FAILED,
                         ReportKind.APPROVE, ReportKind.CHANGES):
                with self.subTest(capacity=capacity, kind=kind):
                    # 每个反例独立账本：变异导致断言失败时，不把满队列带入下一个子用例。
                    case_root = self.root / f'{capacity}-{kind.value}'
                    self.store = self.enterContext(Store.open(case_root))
                    task, work = self.task()
                    if kind in (ReportKind.APPROVE, ReportKind.CHANGES):
                        work = self.add(task, Role.REVIEW)
                        self.sent(work)
                    if capacity == 'attempts':
                        self.fill(task, 64)
                    else:
                        # 四组 63 加 4，真实达到全局 256 个 PENDING，不改容量常量。
                        for _ in range(4):
                            other, _ = self.task()  # 首条已送达
                            for _ in range(63):
                                self.add(other)
                        extra, _ = self.task()
                        for _ in range(4):
                            self.add(extra)
                    count = len(self.store.attempts(task.id))
                    outcome = self.report(task, work, kind)
                    expected = Work.BLOCKED if kind is ReportKind.BLOCKED else Work.FAILED if kind is ReportKind.FAILED else Work.RESULT
                    self.assertEqual(outcome.attempt.work, expected)
                    if kind is not ReportKind.BLOCKED:
                        self.assertEqual(outcome.attempt.result['note'], 'pinned result')
                    if kind in (ReportKind.APPROVE, ReportKind.CHANGES):
                        self.assertEqual(outcome.task.verdict, Verdict.APPROVED if kind is ReportKind.APPROVE else Verdict.CHANGES)
                    self.assertEqual(outcome.followups, [])
                    self.assertEqual(outcome.skipped, {'result': f'capacity_{capacity}'})
                    self.assertEqual(len(self.store.attempts(task.id)), count)
                    events = self.store.events(task.id)
                    self.assertTrue(any(e['kind'] == kind.value for e in events))
                    self.assertEqual(events[-1]['kind'], 'notification_skipped')
                    self.assertEqual(events[-1]['detail'], {'reason': f'capacity_{capacity}', 'route': 'result'})
                    # 用独立只读连接确认提交可见，而不是仅同连接的未提交状态。
                    connection = sqlite3.connect(f'{(case_root / "bridge.sqlite3").as_uri()}?mode=ro', uri=True)
                    try:
                        row = connection.execute('SELECT work FROM attempts WHERE id=?', (work.id,)).fetchone()
                        self.assertEqual(row[0], expected.value)
                    finally:
                        connection.close()

    def test_review_capacity_falls_back_to_origin_with_result_and_instructions(self):
        task, work = self.task(review=True)
        self.fill(task, 60)
        outcome = self.report(task, work)
        self.assertEqual(outcome.attempt.work, Work.RESULT)
        self.assertEqual(outcome.skipped, {'review': 'capacity_attempts'})
        self.assertEqual([a.role for a in outcome.followups], [Role.NOTICE])
        notice = outcome.followups[0]
        self.assertEqual(notice.seq, 61)
        self.assertIn('复核未能排入（交接次数已达上限）', notice.body)
        self.assertIn('close 后新开任务复核', notice.body)
        self.assertIn('pinned result', notice.body)
        self.assertFalse(any(a.role is Role.REVIEW for a in self.store.attempts(task.id)))
        dispatcher, transport = self.dispatcher()
        dispatcher.run_once()
        self.assertEqual(len(transport.calls), 1)

    def test_review_and_fallback_notice_both_full_still_commit(self):
        for reason in ('capacity_attempts', 'capacity_pending'):
            task, work = self.task(review=True)
            with patch.object(self.store, 'add_attempt', side_effect=StoreError(reason)) as add:
                outcome = self.report(task, work)
            self.assertEqual(add.call_count, 2)
            self.assertEqual(outcome.attempt.work, Work.RESULT)
            self.assertEqual(outcome.skipped, {'review': reason, 'result': reason})
            self.assertEqual(outcome.followups, [])
            self.assertEqual([e['kind'] for e in self.store.events(task.id)][-2:],
                             ['review_skipped_capacity', 'notification_skipped'])

    def test_no_notify_still_does_not_queue_origin_after_skipped_review(self):
        task, work = self.task(review=True, notify=False)
        self.fill(task, 60)
        outcome = self.report(task, work)
        self.assertEqual(outcome.skipped, {'review': 'capacity_attempts'})
        self.assertEqual(outcome.followups, [])

    def test_review_no_inbox_and_noncapacity_errors_still_roll_back(self):
        task, work = self.task(review=True)
        with patch.object(reports, 'can_notify', return_value=False):
            with self.assertRaises(ReportError) as caught:
                self.report(task, work)
        self.assertEqual(caught.exception.code, 'target_no_inbox')
        self.assertEqual(self.store.get_attempt(work.id).work, Work.AWAITING_ACK)
        for review in (False, True):
            task, work = self.task(review=review)
            with patch.object(self.store, 'add_attempt', side_effect=StoreError('store_write_failed')):
                with self.assertRaises(StoreError):
                    self.report(task, work)
            self.assertEqual(self.store.get_attempt(work.id).work, Work.AWAITING_ACK)
            self.assertEqual(len(self.store.attempts(task.id)), 1)

    def test_review_only_noncapacity_error_rolls_back_without_origin_fallback(self):
        for reason in ('store_write_failed', 'message_too_large'):
            with self.subTest(reason=reason):
                task, work = self.task(review=True)
                original = self.store.add_attempt
                before_events = self.store.events(task.id)
                before_revision = self.store.ledger_revision()
                def add(*args, **kwargs):
                    if kwargs['role'] is Role.REVIEW:
                        raise StoreError(reason)
                    return original(*args, **kwargs)  # NOTICE would succeed; it cannot mask the review bug.
                with patch.object(self.store, 'add_attempt', side_effect=add) as calls:
                    with self.assertRaises(StoreError) as caught:
                        self.report(task, work)
                self.assertEqual(caught.exception.code, reason)
                self.assertEqual([call.kwargs['role'] for call in calls.call_args_list], [Role.REVIEW])
                self.assertEqual(self.store.get_attempt(work.id).work, Work.AWAITING_ACK)
                self.assertEqual(len(self.store.attempts(task.id)), 1)
                self.assertEqual(self.store.events(task.id), before_events)
                self.assertEqual(self.store.ledger_revision(), before_revision)

    def test_skip_event_failure_also_rolls_back(self):
        task, work = self.task()
        self.fill(task, 64)
        with patch.object(self.store, 'add_event', side_effect=StoreError('store_write_failed')):
            with self.assertRaises(StoreError):
                self.report(task, work)
        self.assertEqual(self.store.get_attempt(work.id).work, Work.AWAITING_ACK)

    def test_successful_review_keeps_origin_suppression(self):
        task, work = self.task(review=True)
        outcome = self.report(task, work)
        self.assertEqual([a.role for a in outcome.followups], [Role.REVIEW])
        self.assertEqual(outcome.skipped, {})

    def test_exhausted_legacy_task_can_report_blocked_then_result_without_progress_workaround(self):
        task, work = self.task(review=True)
        self.fill(task, 64)
        blocked = self.report(task, work, ReportKind.BLOCKED)
        self.assertEqual(blocked.attempt.work, Work.BLOCKED)
        result = self.report(task, work)
        self.assertEqual(result.attempt.work, Work.RESULT)
        self.assertEqual(result.skipped, {'review': 'capacity_attempts', 'result': 'capacity_attempts'})
        self.assertEqual(len(self.store.attempts(task.id)), 64)
        self.assertEqual(result.attempt.result['note'], 'pinned result')

    def test_windows_report_branch_uses_same_capacity_commit_and_fallback(self):
        # 只切归属分支；endpoint/SQLite 均为离线夹具，无真实 Windows API/pipe/key。
        task, work = self.task(review=True)
        self.fill(task, 60)
        with patch.object(reports, 'get_platform', return_value=SimpleNamespace(name='windows')):
            outcome = self.report(task, work)
        self.assertEqual(outcome.attempt.work, Work.RESULT)
        self.assertEqual(outcome.skipped, {'review': 'capacity_attempts'})
        self.assertEqual([a.seq for a in outcome.followups], [61])
        task, work = self.task()
        self.fill(task, 64)
        with patch.object(reports, 'get_platform', return_value=SimpleNamespace(name='windows')):
            outcome = self.report(task, work)
        self.assertEqual(outcome.attempt.work, Work.RESULT)
        self.assertEqual(outcome.skipped, {'result': 'capacity_attempts'})

    def test_fallback_notice_io_failure_rolls_back_result_and_skip_event(self):
        task, work = self.task(review=True)
        with patch.object(self.store, 'add_attempt', side_effect=[StoreError('capacity_attempts'),
                                                                StoreError('store_write_failed')]):
            with self.assertRaises(StoreError):
                self.report(task, work)
        self.assertEqual(self.store.get_attempt(work.id).work, Work.AWAITING_ACK)
        self.assertNotIn('review_skipped_capacity', [e['kind'] for e in self.store.events(task.id)])


if __name__ == '__main__':
    unittest.main()
