"""§79：虚拟时钟、私有账本和 Fake 传输；不连接真实 daemon/socket。"""
from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
import json
import os
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from agentstatus_bridge import cli, dispatch, observer_dbus, worker
from agentstatus_bridge.dispatch import Dispatcher, DISCOVERY_PARK_SECONDS, needs_worker
from agentstatus_bridge.endpoints import Caller
from agentstatus_bridge.ids import short
from agentstatus_bridge.model import Consumption, Delivery, Flow, Provider, Role
from agentstatus_bridge.reminders import REMIND_AFTER_SECONDS, REMINDER_OPTION
from agentstatus_bridge.store import Store
from agentstatus_bridge.transports import DeliveryOutcome
from bridge_support import RecordingTransport, endpoint, ref


class DiscoveryParkTests(unittest.TestCase):
    def setUp(self):
        self.tmp = TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name) / 'bridge'
        self.store = Store.open(self.root)
        self.addCleanup(self.store.close)
        self.wall, self.mono = 1000.0, 0.0
        self.found = []
        self.complete = False
        self.transport = RecordingTransport(Provider.CODEX)
        self.logs = []
        self.dispatcher = self.make_dispatcher()

    def make_dispatcher(self, *, complete=None):
        return Dispatcher(
            self.store, lambda: list(self.found), {Provider.CODEX: self.transport},
            clock=lambda: self.wall, monotonic=lambda: self.mono,
            empty_discovery_complete=complete,
            queue_state=lambda _item: Consumption.LEFT_QUEUE,
            log=lambda event, fields: self.logs.append((event, dict(fields))),
        )

    def task(self, *, target=None, origin=None):
        return self.store.create_task(
            title='synthetic', flow=Flow.HANDOFF, origin=origin, origin_class='bypass',
            reviewer=None, target=target or ref(), body='synthetic', refs=[], now=self.wall,
        )

    def run_once(self, engine=None):
        engine = engine or self.dispatcher
        engine._endpoints_at = None
        return engine.run_once()

    def advance(self, seconds):
        self.mono += seconds
        self.wall += seconds

    def parked(self):
        return [fields for event, fields in self.logs if event == 'pending_parked']

    def test_linux_empty_discovery_parks_at_600_without_ledger_write(self):
        task, attempt = self.task()
        mark = self.store.ledger_revision()
        self.run_once()
        self.advance(599.999)
        self.assertTrue(self.dispatcher.has_live_work())
        self.assertEqual(self.parked(), [])
        self.advance(.001)
        self.assertFalse(self.dispatcher.has_live_work())
        self.assertEqual(self.store.ledger_revision(), mark)
        self.assertEqual(self.store.get_attempt(attempt.id).delivery, Delivery.PENDING)
        self.assertEqual(self.parked(), [{'task': short(task.id), 'attempt': 1, 'waitSeconds': 600}])
        self.assertTrue(needs_worker(self.store, self.wall))
        self.assertEqual(self.transport.calls, [])

    def test_windows_equivalent_incomplete_empty_parks_not_fails(self):
        self.dispatcher = self.make_dispatcher(complete=lambda: False)
        _, attempt = self.task()
        self.run_once()
        self.advance(DISCOVERY_PARK_SECONDS)
        self.run_once()
        self.assertFalse(self.dispatcher.has_live_work())
        self.assertEqual(self.store.get_attempt(attempt.id).delivery, Delivery.PENDING)

    def test_complete_empty_uses_exact_15_second_grace_not_parking(self):
        self.dispatcher = self.make_dispatcher(complete=lambda: True)
        _, attempt = self.task()
        self.run_once()
        self.advance(14.999)
        self.run_once()
        self.assertEqual(self.store.get_attempt(attempt.id).delivery, Delivery.PENDING)
        self.advance(.001)
        self.run_once()
        result = self.store.get_attempt(attempt.id)
        self.assertEqual((result.delivery, result.delivery_reason), (Delivery.FAILED, 'target_gone'))
        self.assertEqual(self.parked(), [])

    def test_nonempty_missing_target_keeps_existing_grace(self):
        self.found = [endpoint(ref(native='other'))]
        self._assert_missing_grace()

    def _assert_missing_grace(self):
        # Also a positive complete-empty witness; no fabricated endpoint identity.
        if not self.found:
            self.dispatcher = self.make_dispatcher(complete=lambda: True)
        _, attempt = self.task()
        self.run_once()
        self.advance(15)
        self.run_once()
        self.assertEqual(self.store.get_attempt(attempt.id).delivery_reason, 'target_gone')
        self.assertEqual(self.parked(), [])

    def test_unknown_gap_preserves_existing_missing_grace(self):
        self.dispatcher = self.make_dispatcher(complete=lambda: self.complete)
        _, attempt = self.task()
        self.complete = True
        self.run_once()
        self.advance(14)
        self.complete = False
        self.run_once()
        self.advance(600)
        self.run_once()
        # 空轮自身仍不能判 gone，但不能抹掉此前可判定缺席的起点。
        self.assertEqual(self.store.get_attempt(attempt.id).delivery, Delivery.PENDING)
        self.assertFalse(self.dispatcher.has_live_work())
        self.complete = True
        self.run_once()
        self.assertEqual(self.store.get_attempt(attempt.id).delivery_reason, 'target_gone')
        self.assertFalse(self.dispatcher.has_live_work())

    def test_alternating_empty_and_missing_target_keeps_15_second_grace(self):
        for complete in (None, lambda: False):
            with self.subTest(completeness='linux_none' if complete is None else 'incomplete_false'):
                self.dispatcher = self.make_dispatcher(complete=complete)
                _, attempt = self.task()
                start = self.mono
                for index in range(9):
                    self.found = [endpoint(ref(native='other'))] if index % 2 == 0 else []
                    self.run_once()
                    result = self.store.get_attempt(attempt.id)
                    if index < 8:
                        self.assertEqual(result.delivery, Delivery.PENDING)
                        self.assertTrue(self.dispatcher.has_live_work())
                        self.advance(2)
                    else:
                        # 每两秒一次采样：首次缺席的15秒宽限在第16秒被下一次非空轮核实。
                        self.assertEqual(self.mono - start, 16)
                        self.assertEqual((result.delivery, result.delivery_reason),
                                         (Delivery.FAILED, 'target_gone'))
                        self.assertFalse(self.dispatcher.has_live_work())
                self.assertEqual(self.transport.calls, [])

    def test_parked_pending_does_not_suppress_another_tasks_future_reminder(self):
        _, parked = self.task()
        self.run_once()
        self.advance(600)
        self.assertFalse(self.dispatcher.has_live_work())
        other, work = self.task(origin=ref(native='other-origin'), target=ref(native='other-target'))
        self.store.begin_send(work.id, now=self.wall, pid=123, start_ticks='1')
        self.store.finish_send(work.id, delivery=Delivery.UNKNOWN, reason='synthetic',
                               provider_ref=None, detail={}, now=self.wall)
        self.run_once()
        reminders = self.dispatcher.pending_reminders()
        self.assertEqual([task_id for task_id, _ in reminders], [other.id])
        self.assertEqual(reminders[0][1].due_at, self.wall + REMIND_AFTER_SECONDS)
        self.assertEqual(self.dispatcher._parked_pending, {parked.id})
        self.assertEqual([a.id for a in self.store.attempts_in((Delivery.PENDING,))], [parked.id])
        self.assertTrue(self.dispatcher.has_live_work(), 'future reminder independently keeps worker live')
        self.advance(REMIND_AFTER_SECONDS - 1)
        self.run_once()
        self.assertTrue(self.dispatcher.has_live_work())
        self.assertEqual(len(self.store.attempts(other.id)), 1, 'not due: no reminder has been queued')
        # 去掉唯一的提醒驻留理由，停泊的旧 PENDING 本身不能留住 worker。
        self.store.update_task(other.id, control='paused', event='paused', now=self.wall)
        self.run_once()
        self.assertFalse(self.dispatcher.has_live_work())
        self.assertEqual(self.store.get_attempt(parked.id).delivery, Delivery.PENDING)
        self.assertEqual(self.transport.calls, [])

    def test_recovery_clears_clock_even_if_target_is_still_missing(self):
        self.task()
        self.run_once()
        self.advance(600)
        self.assertFalse(self.dispatcher.has_live_work())
        self.found = [endpoint(ref(native='different'))]
        self.run_once()
        self.assertTrue(self.dispatcher.has_live_work())
        self.found = []
        self.advance(1)
        self.run_once()
        self.advance(599)
        self.assertTrue(self.dispatcher.has_live_work())
        self.advance(1)
        self.assertFalse(self.dispatcher.has_live_work())
        self.assertEqual(len(self.parked()), 2)

    def test_live_target_with_no_transport_is_not_discovery_wait(self):
        self.task()
        self.run_once()
        self.advance(600)
        self.assertFalse(self.dispatcher.has_live_work())
        self.found = [endpoint(ref())]
        self.dispatcher.transports = {}
        self.run_once()
        self.advance(1000)
        self.assertTrue(self.dispatcher.has_live_work())
        self.assertEqual(self.dispatcher._discovery_wait_since, {})

    def test_new_dispatcher_starts_fresh_and_recovery_delivers_once(self):
        _, attempt = self.task()
        self.run_once()
        self.advance(600)
        self.assertFalse(self.dispatcher.has_live_work())
        new = self.make_dispatcher()
        self.assertTrue(new.has_live_work())
        self.run_once(new)
        self.advance(599)
        self.assertTrue(new.has_live_work())
        self.found = [endpoint(ref())]
        self.run_once(new)
        self.assertEqual(self.store.get_attempt(attempt.id).delivery, Delivery.QUEUED)
        self.assertEqual(len(self.transport.calls), 1)
        self.assertEqual(new._discovery_wait_since, {})
        self.run_once(new)
        self.assertEqual(len(self.transport.calls), 1)

    def test_same_worker_recovers_and_new_pending_still_delivers(self):
        _, old = self.task()
        self.run_once()
        self.advance(600)
        self.assertFalse(self.dispatcher.has_live_work())
        target = ref(native='new-target')
        _, new = self.task(target=target)
        self.assertTrue(self.dispatcher.has_live_work(), 'new ID must not inherit old parking')
        self.found = [endpoint(ref()), endpoint(target)]
        self.run_once()
        self.assertEqual([self.store.get_attempt(a.id).delivery for a in (old, new)], [Delivery.QUEUED] * 2)
        self.assertEqual(len(self.transport.calls), 2)
        self.assertEqual(self.dispatcher._discovery_wait_since, {})

    def test_restarted_worker_runs_real_dispatch_path_after_discovery_recovers(self):
        _, attempt = self.task()
        self.run_once()
        self.advance(600)
        self.assertFalse(self.dispatcher.has_live_work())
        # run_worker 自己创建新 Dispatcher、重开同一个私有账本；只替换 I/O 边界。
        with patch.object(worker, '_open_inbox', return_value=None):
            self.assertEqual(worker.run_worker(
                root=self.root, discover_fn=lambda: [endpoint(ref())],
                transports={Provider.CODEX: self.transport}, once=True, loop_seconds=0,
            ), 0)
        self.assertEqual(self.store.get_attempt(attempt.id).delivery, Delivery.QUEUED)
        self.assertEqual(len(self.transport.calls), 1)

    def test_nonempty_target_does_not_need_complete_empty_certificate(self):
        def never():
            self.fail('empty-only proof must not override a live target')
        self.dispatcher = self.make_dispatcher(complete=never)
        _, attempt = self.task()
        self.found = [endpoint(ref())]
        self.run_once()
        self.assertEqual(self.store.get_attempt(attempt.id).delivery, Delivery.QUEUED)
        self.assertEqual(len(self.transport.calls), 1)

    def test_cli_status_revives_despite_worker_local_parking(self):
        task, attempt = self.task()
        self.run_once()
        self.advance(600)
        self.assertFalse(self.dispatcher.has_live_work())
        self.assertTrue(needs_worker(self.store, self.wall))
        with (
            patch.dict(os.environ, {'AB_STATE_DIR': str(self.root)}),
            patch.object(cli, 'discover', return_value=[]),
            patch.object(cli, 'identify_caller', return_value=Caller(None, None)),
            patch.object(observer_dbus, '_observer_rows', return_value=[]),
            patch.object(cli, 'worker_running', return_value=False),
            patch.object(cli, 'ensure_worker', return_value=True) as ensure,
            redirect_stdout(StringIO()), redirect_stderr(StringIO()),
        ):
            self.assertEqual(cli.main(['status', task.id, '--json']), 0)
        ensure.assert_called_once_with(self.root)
        self.assertEqual(self.store.get_attempt(attempt.id).delivery, Delivery.PENDING)

    def test_sending_and_local_replay_are_never_parked(self):
        _, attempt = self.task()
        self.run_once()
        self.advance(600)
        self.assertFalse(self.dispatcher.has_live_work())
        self.store.begin_send(attempt.id, now=self.wall, pid=123, start_ticks='1')
        self.assertTrue(self.dispatcher.has_live_work())
        self.store.finish_send(attempt.id, delivery=Delivery.UNKNOWN, reason='synthetic', provider_ref=None, detail={}, now=self.wall)
        self.dispatcher._unrecorded[attempt.id] = (DeliveryOutcome(Delivery.UNKNOWN, 'synthetic'), {})
        self.assertTrue(self.dispatcher.has_live_work())

    def test_observation_window_still_keeps_worker_live(self):
        self.task()
        self.run_once()
        self.advance(600)
        self.assertFalse(self.dispatcher.has_live_work())
        _, observed = self.task(target=ref(native='observed'))
        self.store.begin_send(observed.id, now=self.wall, pid=123, start_ticks='1')
        self.store.finish_send(observed.id, delivery=Delivery.QUEUED, reason='synthetic', provider_ref='item1', detail={}, now=self.wall)
        self.assertTrue(self.dispatcher.has_live_work())
        self.advance(dispatch.CONSUMPTION_WATCH_SECONDS)
        self.assertFalse(self.dispatcher.has_live_work())

    def test_paused_and_terminal_attempts_forget_parked_state(self):
        task, attempt = self.task()
        self.run_once()
        self.advance(600)
        self.assertFalse(self.dispatcher.has_live_work())
        self.store.update_task(task.id, control='paused', event='paused', now=self.wall)
        self.run_once()
        self.assertEqual(self.dispatcher._discovery_wait_since, {})
        self.assertEqual(self.dispatcher._parked_pending, set())
        self.store.update_task(task.id, control='active', event='resumed', now=self.wall)
        self.run_once()
        self.assertTrue(self.dispatcher.has_live_work())
        self.store.transition_delivery(attempt.id, expected=(Delivery.PENDING,), new=Delivery.CANCELLED, reason='cancelled', now=self.wall)
        self.run_once()
        self.assertEqual(self.dispatcher._discovery_wait_since, {})

    def test_unknown_result_is_not_requeued_by_parking(self):
        _, attempt = self.task()
        self.run_once()
        self.advance(600)
        self.assertFalse(self.dispatcher.has_live_work())
        self.found = [endpoint(ref())]
        self.transport.error = RuntimeError('synthetic private marker')
        self.run_once()
        self.assertEqual(self.store.get_attempt(attempt.id).delivery, Delivery.UNKNOWN)
        self.assertEqual(self.dispatcher._discovery_wait_since, {})
        self.advance(600)
        self.run_once()
        self.assertEqual(len(self.transport.calls), 1)

    def test_clock_uses_monotonic_not_wall_and_log_is_once(self):
        task, attempt = self.task()
        self.run_once()
        self.wall += 86400
        self.assertTrue(self.dispatcher.has_live_work())
        self.wall = 500  # 倒退，但不造出 Unix 纪元之前的提醒退避时钟。
        self.mono = 600
        for _ in range(3):
            self.run_once()
            self.assertFalse(self.dispatcher.has_live_work())
        self.assertEqual(self.parked(), [{'task': short(task.id), 'attempt': attempt.seq, 'waitSeconds': 600}])
        self.assertEqual(set(self.parked()[0]), {'task', 'attempt', 'waitSeconds'})

    def test_fault_reminder_pending_parks_without_losing_message(self):
        origin = ref(native='origin')
        task, work = self.task(origin=origin)
        self.store.begin_send(work.id, now=self.wall, pid=123, start_ticks='1')
        self.store.finish_send(work.id, delivery=Delivery.UNKNOWN, reason='codex_transport_error', provider_ref=None, detail={}, now=self.wall)
        self.advance(REMIND_AFTER_SECONDS)
        self.run_once()
        reminders = [a for a in self.store.attempts(task.id) if REMINDER_OPTION in a.options]
        self.assertEqual(len(reminders), 1)
        reminder = reminders[0]
        self.assertEqual((reminder.role, reminder.delivery), (Role.NOTICE, Delivery.PENDING))
        self.advance(600)
        self.run_once()
        self.assertFalse(self.dispatcher.has_live_work())
        self.assertTrue(needs_worker(self.store, self.wall))
        self.assertEqual(self.store.get_attempt(work.id).delivery, Delivery.UNKNOWN)
        self.assertEqual(self.store.get_attempt(reminder.id).delivery, Delivery.PENDING)
        self.assertEqual(len(self.store.attempts(task.id)), 2)
        fresh = self.make_dispatcher()
        self.found = [endpoint(origin)]
        self.run_once(fresh)
        self.assertEqual(self.store.get_attempt(reminder.id).delivery, Delivery.QUEUED)
        self.assertEqual(len(self.transport.calls), 1)

    def test_real_worker_loop_exits_after_park_plus_idle(self):
        for complete in (None, lambda: False):
            with self.subTest(completeness='linux_none' if complete is None else 'incomplete_false'):
                self.mono = 0
                _, attempt = self.task()

                def create(**kwargs):
                    return Dispatcher(**kwargs, clock=lambda: self.wall,
                                      monotonic=lambda: self.mono, empty_discovery_complete=complete)

                def sleep(seconds):
                    self.advance(seconds)
                    self.assertLessEqual(self.mono, 840, 'worker failed to become idle')

                with (
                    patch.object(worker, 'Dispatcher', side_effect=create),
                    patch.object(worker, '_open_inbox', return_value=None),
                    patch.object(worker.time, 'sleep', side_effect=sleep),
                    patch.object(worker.time, 'monotonic', side_effect=lambda: self.mono),
                ):
                    self.assertEqual(worker.run_worker(root=self.root, discover_fn=lambda: [],
                                                     transports={Provider.CODEX: self.transport}, loop_seconds=60), 0)
                self.assertEqual(self.mono, DISCOVERY_PARK_SECONDS + worker.IDLE_EXIT_SECONDS)
                self.assertEqual(self.store.get_attempt(attempt.id).delivery, Delivery.PENDING)
                self.assertTrue(needs_worker(self.store, self.wall))
                records = [json.loads(line) for line in (self.root / worker.LOG_NAME).read_text().splitlines()]
                self.assertEqual(records[-1]['event'], 'stop')
                self.assertEqual(records[-1]['consecutiveFailures'], 0)
                self.assertNotIn('loop_error', [r['event'] for r in records])
                self.assertEqual(self.transport.calls, [])


if __name__ == '__main__':
    unittest.main()
