"""对方沉默时提醒发起方、催执行方（DESIGN §104.9 一）：锚点、每锚点一次、上限 3、不挡主提醒、过期复核、
催促的判据与驻留、联邦 A 侧沉默提醒。"""

from __future__ import annotations

from dataclasses import replace
import unittest

import bridge_support  # noqa: F401  导入即隔离宿主会话环境
import test_bridge_reminders as R
from agentstatus_bridge import summary
from agentstatus_bridge.dispatch import CONSUMPTION_WATCH_SECONDS, needs_worker
from agentstatus_bridge.federation import mirror
from agentstatus_bridge.federation.delivery import FederationDispatcher
from agentstatus_bridge.federation.relay import RelayPaths
from agentstatus_bridge.federation.views import model_attempts, model_task
from agentstatus_bridge.model import (
    Consumption,
    Delivery,
    EndpointRef,
    Flow,
    Provider,
    ReportKind,
    Role,
    Runtime,
    Work,
    work_attempts,
)
from agentstatus_bridge.hints import PaneState
from agentstatus_bridge.nudges import MAX_NUDGE_WATCH_SECONDS, NUDGE_GRACE_SECONDS, nudge_candidate, worth_watching
from agentstatus_bridge.observer_dbus import ObserverRow, ObserverView
from agentstatus_bridge.reminders import (
    MAX_SILENT_PER_ATTEMPT,
    REMINDER_OPTION,
    nudge_token,
    pending_notices,
    pending_reminder,
    side_notice,
    silence_anchor,
)
from bridge_support import endpoint, ref, with_name_views

from test_bridge_federation_rules import DEV_A, DEV_B, T0, FederationTestCase, deliver, pump

T = 1800.0
WORKER = ref(Provider.CLAUDE, "worker-session", pid=5000, pane="%5", label="worker")


class SilenceTests(unittest.TestCase):
    setUp = R.ReminderTests.setUp
    tearDown = R.ReminderTests.tearDown
    _discover = R.ReminderTests._discover
    _task = R.ReminderTests._task
    _run = R.ReminderTests._run
    _deliver = R.ReminderTests._deliver
    _report = R.ReminderTests._report
    _reminders = R.ReminderTests._reminders

    def _sent_task(self, **kwargs: object) -> tuple[str, str]:
        task_id = self._task(**kwargs)  # type: ignore[arg-type]
        work = work_attempts(self.store.attempts(task_id))[-1]
        self._deliver(work.id)
        return task_id, work.id

    def _silent(self, task_id: str) -> list:
        return [item for item in self.store.attempts(task_id) if item.is_silent_reminder]

    def _progress(self, task_id: str, work: Work = Work.IN_PROGRESS) -> None:
        current = work_attempts(self.store.attempts(task_id))[-1]
        self.store.set_work(current.id, work=work, result=None, now=self.now, event="progress")

    def test_origin_is_told_once_per_anchor_after_t(self) -> None:
        task_id, work_id = self._sent_task()
        self.assertTrue(needs_worker(self.store, self.now))  # 未到期也驻留
        self.now += T - 1
        self._run()
        self.assertEqual(self._silent(task_id), [])
        self.now += 1
        self._run()
        [notice] = self._silent(task_id)
        self.assertEqual(notice.target, R.LEAD)
        self.assertEqual(notice.options[REMINDER_OPTION], f"{work_id}:silent:{1000.0:.6f}")
        first = notice.body.splitlines()[0]
        self.assertTrue(first.startswith(f"任务 {task_id[:8]} 已 30 分钟没有汇报（codex@impl；对方："), first)
        self.assertIn("对方：空闲", first)  # 发现到 IMPL、空闲
        self.assertIn(f"note {task_id[:8]}", notice.body)
        self.assertIn("--force --to", notice.body)
        event = [item for item in self.store.events(task_id) if item["kind"] == "origin_reminded"][-1]
        self.assertEqual(event["detail"], {"reason": "silent", "minutes": 30})
        self.now += T * 3
        self._run()
        self.assertEqual(len(self._silent(task_id)), 1)  # 同一锚点只发一次

    def test_progress_moves_the_anchor_but_a_repeated_ack_does_not(self) -> None:
        task_id, _ = self._sent_task()
        self.now += 600
        self._progress(task_id)  # 新锚点 = 1600
        self.now += T - 1
        self._run()
        self.assertEqual(self._silent(task_id), [])
        self.now += 1
        self._run()
        self.assertEqual(len(self._silent(task_id)), 1)
        current = work_attempts(self.store.attempts(task_id))[-1]
        self.store.add_event(task_id, "ack", now=self.now + 10, attempt_seq=current.seq)  # 重复 ack 只记事件
        self.now += T * 2
        self._run()
        self.assertEqual(len(self._silent(task_id)), 1)

    def test_expect_sets_t_and_invalid_values_fall_back(self) -> None:
        task_id, _ = self._sent_task(options={"expect": 600})
        self.now += 600
        self._run()
        self.assertEqual(len(self._silent(task_id)), 1)
        for bad in (60, 10 ** 9, True, "600"):
            with self.subTest(bad=bad):
                other, _ = self._sent_task(options={"expect": bad})
                task = self.store.get_task(other)
                assert task is not None
                [silent] = [item for item in pending_notices(task, self.store.attempts(other)) if item.kind == "silent"]
                self.assertEqual(silent.due_at - (silent.anchor or 0), T)

    def test_not_sent_without_origin_notify_or_when_origin_is_the_receiver(self) -> None:
        cases = [self._sent_task(origin=None)[0], self._sent_task(options={"notify": False})[0],
                 self._sent_task(origin=R.IMPL)[0]]
        self.now += T * 2
        self._run()
        for task_id in cases:
            self.assertEqual(self._silent(task_id), [])

    def test_at_most_three_per_attempt(self) -> None:
        self.assertEqual(MAX_SILENT_PER_ATTEMPT, 3)  # §104.9 一定的上限；下面用字面值，别让改坏的常量自证
        task_id, _ = self._sent_task()
        for _ in range(5):
            self.now += T
            self._run()
            self.now += 1
            self._progress(task_id)
        self.assertEqual(len(self._silent(task_id)), 3)

    def test_not_for_held_unknown_paused_or_finished_work(self) -> None:
        held = self._task()
        work = work_attempts(self.store.attempts(held))[-1]
        self.store.begin_send(work.id, now=self.now, pid=1, start_ticks="1")
        self.store.finish_send(work.id, delivery=Delivery.HELD, reason="claude_held", provider_ref=None,
                               detail={}, now=self.now)
        paused, _ = self._sent_task()
        self.store.update_task(paused, now=self.now, event="paused", control="paused")
        blocked, _ = self._sent_task()
        self._progress(blocked, Work.BLOCKED)
        self.now += T * 2
        self._run()
        for task_id in (held, paused, blocked):
            self.assertEqual(self._silent(task_id), [])

    def test_silent_notice_neither_blocks_nor_resets_the_main_reminder(self) -> None:
        task_id, _ = self._sent_task()
        self.now += T
        self.lead_online = False  # 沉默通知留在 PENDING
        self._run()
        [silent] = self._silent(task_id)
        self.assertEqual(silent.delivery, Delivery.PENDING)
        self.assertTrue(side_notice(silent))
        self.now += 5
        self._report(task_id, notice=False)  # 对方交了结果：主关注开始
        task = self.store.get_task(task_id)
        assert task is not None
        main = pending_reminder(task, self.store.attempts(task_id))
        self.assertIsNotNone(main)  # PENDING 的沉默通知不挡主提醒
        assert main is not None
        self.assertEqual(main.due_at, self.now + R.REMIND_AFTER_SECONDS)
        # 沉默通知在领取时按令牌作废
        self.lead_online = True
        self._run()
        refreshed = self.store.get_attempt(silent.id)
        assert refreshed is not None
        self.assertEqual((refreshed.delivery, refreshed.delivery_reason), (Delivery.CANCELLED, "reminder_outdated"))

    def test_refused_silent_notice_only_blocks_later_note_undelivered_notices(self) -> None:
        # 发起方拒收沉默提醒（§104.11）：只挡住「补充落定未送达、告知还没排上」的 §103.2 告知（拒收晚于补充失败）；
        # 新锚点的沉默提醒与主提醒都不受影响
        task_id, work_id = self._sent_task()
        self._note(task_id, created=self.now + T - 10, delivered=self.now + T - 10, delivery=Delivery.FAILED)
        task = self.store.get_task(task_id)
        assert task is not None
        self.assertEqual(len([p for p in pending_notices(task, self.store.attempts(task_id)) if p.kind == "note"]), 1)
        self.now += T
        silent = self.store.add_attempt(task_id, role=Role.NOTICE, target=R.LEAD, body="沉默", refs=[], now=self.now,
                                        sender=None, sender_class="bypass",
                                        options={"noticeKind": "reminder",
                                                 REMINDER_OPTION: f"{work_id}:silent:{1000.0:.6f}"})
        self.store.begin_send(silent.id, now=self.now, pid=1, start_ticks="1")
        self.store.finish_send(silent.id, delivery=Delivery.REFUSED, reason="claude_refused", provider_ref=None,
                               detail={}, now=self.now)
        task = self.store.get_task(task_id)
        assert task is not None
        self.assertEqual([p for p in pending_notices(task, self.store.attempts(task_id)) if p.kind == "note"], [])
        self.now += 1
        self._progress(task_id)  # 新锚点晚于拒收：照常再算
        task = self.store.get_task(task_id)
        assert task is not None
        self.assertEqual(len([p for p in pending_notices(task, self.store.attempts(task_id)) if p.kind == "silent"]), 1)
        self._report(task_id, notice=False)
        task = self.store.get_task(task_id)
        assert task is not None
        self.assertIsNotNone(pending_reminder(task, self.store.attempts(task_id)))

    def _note(self, task_id: str, *, created: float, delivered: float | None = None,
              delivery: Delivery = Delivery.QUEUED, body: str = "回答"):
        """给当前工作尝试补一条补充；delivered 给出时按那个时刻落定投递（不经 worker，时刻可控）。"""
        work = work_attempts(self.store.attempts(task_id))[-1]
        note = self.store.add_attempt(task_id, role=Role.NOTICE, target=work.target, body=body, refs=[], now=created,
                                      sender=R.LEAD, sender_class="bypass",
                                      options={"noticeKind": "note", "forSeq": work.seq})
        if delivered is not None:
            self.store.begin_send(note.id, now=delivered, pid=1, start_ticks="1")
            self.store.finish_send(note.id, delivery=delivery, reason="t", provider_ref=None, detail={},
                                   now=delivered)
        return self.store.get_attempt(note.id)

    def test_answer_handed_over_after_t_restarts_the_count_from_its_delivery(self) -> None:
        # 提问后过了 T 才回答（补充排队 10 分钟才交出）：从交出时刻起 T−1 不发、满 T 才发（§104.11 第 2 条）
        task_id, work_id = self._sent_task()
        self.now += 60
        self.store.set_attempt_option(work_id, "ask", {"at": self.now, "note": "问题"})
        self.store.set_work(work_id, work=Work.IN_PROGRESS, result=None, now=self.now, event="progress")
        self.now += T + 100
        self._run()
        self.assertEqual(self._silent(task_id), [])  # 在等回答：不算沉默
        created = self.now
        handed = created + 600
        note = self._note(task_id, created=created)  # 先排队，不交出
        self.assertEqual(silence_anchor(self.store.attempts(task_id), work_attempts(self.store.attempts(task_id))[-1]),
                         self.now - T - 100)  # 排队中的补充不动锚点（仍是提问时刻）
        assert note is not None
        self.store.begin_send(note.id, now=handed, pid=1, start_ticks="1")
        self.store.finish_send(note.id, delivery=Delivery.QUEUED, reason="t", provider_ref=None, detail={}, now=handed)
        work = work_attempts(self.store.attempts(task_id))[-1]
        self.assertEqual(silence_anchor(self.store.attempts(task_id), work), handed)
        self.now = handed + T - 1
        self._run()
        self.assertEqual(self._silent(task_id), [])
        self.now = handed + T
        self._run()
        [silent] = self._silent(task_id)
        self.assertEqual(silent.options[REMINDER_OPTION], f"{work_id}:silent:{handed:.6f}")

    def test_origin_follow_up_note_moves_the_anchor(self) -> None:
        task_id, work_id = self._sent_task()  # 交出于 1000
        self._note(task_id, created=1600.0, delivered=1600.0)  # 发起方催问
        self.now = 1000.0 + T
        self._run()
        self.assertEqual(self._silent(task_id), [])
        self.now = 1600.0 + T
        self._run()
        [silent] = self._silent(task_id)
        self.assertEqual(silent.options[REMINDER_OPTION], f"{work_id}:silent:{1600.0:.6f}")

    def test_only_handed_over_notes_count_and_a_missing_delivery_time_falls_back_to_creation(self) -> None:
        task_id, work_id = self._sent_task()
        pending = self._note(task_id, created=1500.0)
        failed = self._note(task_id, created=1600.0, delivered=1700.0, delivery=Delivery.FAILED)
        held = self._note(task_id, created=1650.0, delivered=1750.0, delivery=Delivery.HELD)
        attempts = self.store.attempts(task_id)
        work = work_attempts(attempts)[-1]
        self.assertEqual(silence_anchor(attempts, work), 1000.0)  # 排队、确定未送达、等批准都不动锚点
        assert pending is not None and failed is not None and held is not None
        written = self._note(task_id, created=1800.0, delivered=1900.0, delivery=Delivery.WRITTEN)
        assert written is not None
        attempts = self.store.attempts(task_id)
        self.assertEqual(silence_anchor(attempts, work), 1900.0)
        # 交出但没记投递时刻（形状上可能的旧行）：退回建立时刻
        attempts = [replace(item, delivery_at=None) if item.id == written.id else item for item in attempts]
        self.assertEqual(silence_anchor(attempts, work), 1800.0)
        # 补别的尝试的不算
        other = replace(written, options={**written.options, "forSeq": work.seq + 5})
        self.assertEqual(silence_anchor([*self.store.attempts(task_id)[:-1], other], work), 1000.0)

    def test_cancelled_silent_reminders_do_not_use_up_the_three_slots(self) -> None:
        # §104.11 P3：发起方离线期间锚点一动，排队中的提醒就作废（reminder_outdated）；作废的不占「最多 3 条」名额
        task_id, _ = self._sent_task()
        self.lead_online = False  # 沉默提醒都留在 PENDING
        for _ in range(4):
            self.now += T
            self._run()  # 排一条
            self.now += 1
            self._progress(task_id)  # 锚点变了
            self._run()  # 领取时作废上一条
        cancelled = [item for item in self._silent(task_id) if item.delivery is Delivery.CANCELLED]
        self.assertEqual(len(cancelled), 4)
        self.assertTrue(all(item.delivery_reason == "reminder_outdated" for item in cancelled))
        self.lead_online = True
        self.now += T
        self._run()
        sent = [item for item in self._silent(task_id) if item.delivery is not Delivery.CANCELLED]
        self.assertEqual(len(sent), 1)  # 作废了 4 条，名额仍在

    def test_only_outdated_unsent_reminders_are_released(self) -> None:
        # §104.12 第 4 条：只有发送前因 reminder_outdated 作废的不占名额；别的原因作废的、结果不明的照算
        task_id, work_id = self._sent_task()
        work = self.store.get_attempt(work_id)
        assert work is not None

        def silent(anchor: float, delivery: Delivery, reason: str) -> None:
            notice = self.store.add_attempt(task_id, role=Role.NOTICE, target=R.LEAD, body="沉默", refs=[],
                                            now=self.now, sender=None, sender_class="bypass",
                                            options={"noticeKind": "reminder",
                                                     REMINDER_OPTION: f"{work_id}:silent:{anchor:.6f}"})
            self.store.begin_send(notice.id, now=self.now, pid=1, start_ticks="1")
            if delivery is Delivery.CANCELLED:
                self.store.finish_send(notice.id, delivery=Delivery.FAILED, reason="t", provider_ref=None, detail={},
                                       now=self.now)  # 先落一个终态，再改成作废（只为造出原因不同的 CANCELLED 行）
                self.store._conn.execute(  # pyright: ignore[reportPrivateUsage]
                    "UPDATE attempts SET delivery='cancelled', delivery_reason=? WHERE id=?", (reason, notice.id))
                self.store._conn.commit()  # pyright: ignore[reportPrivateUsage]
            else:
                self.store.finish_send(notice.id, delivery=delivery, reason=reason, provider_ref=None, detail={},
                                       now=self.now)

        silent(1.0, Delivery.CANCELLED, "reminder_outdated")
        silent(2.0, Delivery.CANCELLED, "reminder_outdated")
        silent(3.0, Delivery.CANCELLED, "notice_outdated")
        silent(4.0, Delivery.UNKNOWN, "claude_unknown")
        task = self.store.get_task(task_id)
        assert task is not None
        self.assertEqual(len([p for p in pending_notices(task, self.store.attempts(task_id)) if p.kind == "silent"]), 1)
        silent(5.0, Delivery.WRITTEN, "claude_written")  # 第 3 条真正占名额的：满额
        self.assertEqual([p for p in pending_notices(task, self.store.attempts(task_id)) if p.kind == "silent"], [])

    def test_note_anchor_uses_the_later_of_creation_and_delivery(self) -> None:
        # 联邦里 delivery_at 是投递设备（B）的钟：B 偏慢时交出时刻早于建立时刻，锚点取较晚的那个（§104.11 P3）
        task_id, _ = self._sent_task()
        self._note(task_id, created=1600.0, delivered=1550.0)  # 交出时刻（B 的钟）早于建立时刻
        work = work_attempts(self.store.attempts(task_id))[-1]
        self.assertEqual(silence_anchor(self.store.attempts(task_id), work), 1600.0)
        self._note(task_id, created=1700.0, delivered=1750.0)
        self.assertEqual(silence_anchor(self.store.attempts(task_id), work), 1750.0)

    def test_silent_reminder_fits_the_61_slot_but_not_beyond(self) -> None:
        # 提醒档上限 61（§83）：最后一条序号 60 时还能排（占 61），到 61 就不排（审计 1f）
        for last, expected in ((60, 1), (61, 0)):
            with self.subTest(last=last):
                task_id, _ = self._sent_task()
                while max(item.seq for item in self.store.attempts(task_id)) < last:
                    self.store.add_attempt(task_id, role=Role.NOTICE, target=R.LEAD, body="容量夹具", refs=[],
                                           now=self.now, sender=None, sender_class="bypass")
                task = self.store.get_task(task_id)
                assert task is not None
                found = [p for p in pending_notices(task, self.store.attempts(task_id)) if p.kind == "silent"]
                self.assertEqual(len(found), expected)

    def test_pending_nudge_does_not_block_the_main_reminder(self) -> None:
        # 审计 1d：排队中的催促（发给执行方）不是发起方回执，不挡主提醒
        task_id, work_id = self._sent_task()
        work = self.store.get_attempt(work_id)
        assert work is not None
        self.store.add_attempt(task_id, role=Role.NOTICE, target=R.IMPL, body="催", refs=[], now=self.now + 5,
                               sender=None, sender_class="bypass",
                               options={"noticeKind": "nudge", REMINDER_OPTION: nudge_token(work)})
        self.now += 10
        self._report(task_id, notice=False)  # 交结果：主关注开始
        task = self.store.get_task(task_id)
        assert task is not None
        main = pending_reminder(task, self.store.attempts(task_id))
        assert main is not None
        self.assertEqual(main.due_at, self.now + R.REMIND_AFTER_SECONDS)

    def test_queued_silent_reminder_is_cancelled_when_progress_arrives_before_it_goes_out(self) -> None:
        task_id, _ = self._sent_task()
        self.now += T
        self.lead_online = False  # 沉默提醒留在 PENDING
        self._run()
        [silent] = self._silent(task_id)
        self.assertEqual(silent.delivery, Delivery.PENDING)
        self.now += 5
        self._progress(task_id)  # 锚点变了：领取时按令牌作废
        self.lead_online = True
        self._run()
        refreshed = self.store.get_attempt(silent.id)
        assert refreshed is not None
        self.assertEqual((refreshed.delivery, refreshed.delivery_reason), (Delivery.CANCELLED, "reminder_outdated"))
        self.assertEqual(self.claude.calls, [])

    def test_refused_nudge_still_lets_the_silent_reminder_through_after_t(self) -> None:
        task_id, work_id = self._sent_task()
        work = self.store.get_attempt(work_id)
        assert work is not None
        self.now += 900
        nudge = self.store.add_attempt(task_id, role=Role.NOTICE, target=R.IMPL, body="催", refs=[], now=self.now,
                                       sender=None, sender_class="bypass",
                                       options={"noticeKind": "nudge", REMINDER_OPTION: nudge_token(work)})
        self.store.begin_send(nudge.id, now=self.now, pid=1, start_ticks="1")
        self.store.finish_send(nudge.id, delivery=Delivery.REFUSED, reason="codex_refused", provider_ref=None,
                               detail={}, now=self.now)
        nudged = self.now
        self.now = nudged + T - 1
        self._run()
        self.assertEqual(self._silent(task_id), [])
        self.now = nudged + T
        self._run()
        [silent] = self._silent(task_id)  # 执行方拒收催促不是发起方拒绝
        self.assertEqual(silent.options[REMINDER_OPTION], f"{work_id}:silent:{nudged:.6f}")

    def test_question_pending_is_not_silence(self) -> None:
        task_id, work_id = self._sent_task()
        self.store.set_attempt_option(work_id, "ask", {"at": self.now, "note": "问题"})
        self.store.set_work(work_id, work=Work.IN_PROGRESS, result=None, now=self.now, event="progress")
        self.now += T * 2
        self._run()
        self.assertEqual(self._silent(task_id), [])

    def test_nudge_creation_time_moves_the_anchor(self) -> None:
        task_id, work_id = self._sent_task()
        work = self.store.get_attempt(work_id)
        assert work is not None
        self.now += 900
        self.store.add_attempt(task_id, role=Role.NOTICE, target=R.IMPL, body="催", refs=[], now=self.now,
                               sender=None, sender_class="bypass",
                               options={"noticeKind": "nudge", REMINDER_OPTION: nudge_token(work)})
        attempts = self.store.attempts(task_id)
        self.assertEqual(silence_anchor(attempts, work), self.now)
        self.now += T - 1
        self._run()
        self.assertEqual(self._silent(task_id), [])
        self.now += 1
        self._run()
        self.assertEqual(len(self._silent(task_id)), 1)


class NudgeTests(unittest.TestCase):
    setUp = R.ReminderTests.setUp
    tearDown = R.ReminderTests.tearDown
    _run = R.ReminderTests._run

    def _discover(self):
        return with_name_views([endpoint(WORKER, runtime=self.runtime), endpoint(R.LEAD, socket_path=R.LEAD_SOCKET)])

    def _observe(self):
        rows = {}
        if self.readable:
            for item in summary.endpoint_binding(WORKER)["observerKeys"]:
                rows[item["key"]] = ObserverRow(runtime=self.pane_runtime, runtime_at=self.ended, pane=WORKER.pane,
                                                fresh=self.fresh, last_turn_ended_at=self.ended, agent="claude")
        return self._discover(), ObserverView(rows)

    def _prepare(self, *, target: EndpointRef = WORKER, origin: EndpointRef | None = R.LEAD,
                 options: dict[str, object] | None = None) -> tuple[str, str]:
        self.runtime = Runtime.IDLE
        self.pane_runtime = Runtime.IDLE
        self.readable = True
        self.fresh = True
        self.dispatcher.discover = self._discover
        self.dispatcher.observe = self._observe
        task, work = self.store.create_task(title="长任务", flow=Flow.HANDOFF, origin=origin, origin_class="bypass",
                                            reviewer=None, target=target, body="做 X", refs=[], now=self.now,
                                            task_options=options)
        self.store.begin_send(work.id, now=self.now, pid=1, start_ticks="1")
        self.store.finish_send(work.id, delivery=Delivery.WRITTEN, reason="claude_written", provider_ref=None,
                               detail={}, now=self.now)
        self.ended = self.now + 60  # 交出之后那一轮结束
        return task.id, work.id

    def _nudges(self, task_id: str) -> list:
        return [item for item in self.store.attempts(task_id) if item.is_nudge]

    def _check(self) -> None:
        self.dispatcher._nudge_next_check = 0.0  # pyright: ignore[reportPrivateUsage]
        self._run()

    def test_idle_after_grace_is_nudged_once_with_copyable_commands(self) -> None:
        self.assertEqual(NUDGE_GRACE_SECONDS, 300.0)  # §104.9 一定的 G；下面用字面值，别让改坏的常量自证
        task_id, work_id = self._prepare()
        self.now = self.ended + 299
        self._check()
        self.assertEqual(self._nudges(task_id), [])
        self.assertTrue(self.dispatcher.has_live_work())  # 读得到、宽限未满：驻留盯着
        self.now += 1
        self._check()
        [nudge] = self._nudges(task_id)
        self.assertEqual((nudge.target, nudge.options[REMINDER_OPTION]), (WORKER, f"{work_id}:nudge"))
        self.assertIn(f"report {task_id} --attempt 1 --result", nudge.body)
        self.assertIn("--blocked", nudge.body)
        self.assertIn("--progress", nudge.body)
        self.assertEqual([e for e in self.store.events(task_id) if e["kind"] == "nudge_created"][0]["attemptSeq"], 2)
        self.now += 3600
        self._check()
        self.assertEqual(len(self._nudges(task_id)), 1)  # 每次尝试只一次

    def test_delivered_nudge_has_a_notice_header_and_no_origin_footer(self) -> None:
        task_id, _ = self._prepare()
        self.now = self.ended + NUDGE_GRACE_SECONDS
        before = len(self.claude.calls) + len(self.codex.calls)
        self._check()  # 同一轮排队后照常投递：走真实的信封渲染与传输调用
        [nudge] = self._nudges(task_id)
        sent = [text for _ep, text, _ctx in self.claude.calls + self.codex.calls][before:]
        self.assertEqual(len(sent), 1, sent)
        text = sent[0]
        first = text.splitlines()[0]
        self.assertIn(f"task={task_id} attempt={nudge.seq}", first)
        self.assertIn("role=notice", first)
        self.assertIn(f"report {task_id} --attempt 1 --result", text)
        footer = text.rstrip().splitlines()[-1]
        self.assertIn("AgentStatus 协作桥通知", footer)
        for word in (" accept ", " retry ", " close "):  # 没有发起方那一侧的收尾命令
            self.assertNotIn(word, text)

    def test_busy_background_or_unreadable_executors_are_not_nudged(self) -> None:
        for case in ("busy", "background", "unreadable", "stale"):
            with self.subTest(case=case):
                task_id, _ = self._prepare()
                if case == "busy":
                    self.runtime = self.pane_runtime = Runtime.BUSY
                elif case == "background":
                    self.runtime = self.pane_runtime = Runtime.BACKGROUND
                elif case == "unreadable":
                    self.readable = False
                else:
                    self.fresh = False
                self.now = self.ended + NUDGE_GRACE_SECONDS * 3
                self._check()
                self.assertEqual(self._nudges(task_id), [])
                # 读得到、正在忙（含后台）才驻留；读不到就跳过、不驻留
                self.assertEqual(self.dispatcher._nudge_watching,  # pyright: ignore[reportPrivateUsage]
                                 case in ("busy", "background"))
                task = self.store.get_task(task_id)
                assert task is not None
                self.store.update_task(task_id, now=self.now, event="closed", closed_at=self.now)

    def test_watching_a_busy_executor_keeps_the_worker_resident_until_the_24h_cap(self) -> None:
        # 无发起方（不发沉默提醒）、WRITTEN 观察窗口早已过：驻留只能来自盯守执行方
        task_id, _ = self._prepare(origin=None, options={"expect": 1800})  # --expect 不收窄窗口（§104.11 第 3 条）
        anchor = self.ended - 60
        self.runtime = self.pane_runtime = Runtime.BUSY
        self.now = self.ended + 600
        self._check()
        self.assertTrue(self.dispatcher.has_live_work())
        self.readable = False  # 读不到：跳过、不驻留
        self._check()
        self.assertFalse(self.dispatcher.has_live_work())
        self.readable = True
        self.assertEqual(MAX_NUDGE_WATCH_SECONDS, 24 * 3600.0)
        self.now = anchor + 24 * 3600.0  # 上限按字面值：从锚点起 24 小时
        self._check()
        self.assertTrue(self.dispatcher.has_live_work())
        self.now += 2
        self._check()
        self.assertFalse(self.dispatcher.has_live_work())
        self.runtime = self.pane_runtime = Runtime.IDLE  # 过了窗口不再盯、也不再催
        self.now += NUDGE_GRACE_SECONDS
        self._check()
        self.assertEqual(self._nudges(task_id), [])

    def test_short_expect_still_gets_a_nudge(self) -> None:
        # --expect 5m：执行方忙到第 10 分钟才停，停满宽限照样催（原写法下窗口只有 5 分钟，永远催不到）
        task_id, _ = self._prepare(options={"expect": 300})
        self.ended = self.now + 600
        self.now = self.ended + 299
        self._check()
        self.assertEqual(self._nudges(task_id), [])
        self.now = self.ended + 300
        self._check()
        self.assertEqual(len(self._nudges(task_id)), 1)

    def test_idle_without_a_turn_after_delivery_is_not_watched(self) -> None:
        # 空闲、交出后没开过新一轮：不为它驻留（§104.11 第 4 条）
        task_id, _ = self._prepare(origin=None)
        self.ended = self.now - 10  # 最近一轮结束早于交出
        self.now += 120  # WRITTEN 观察窗口（60 秒）已过
        self._check()
        self.assertEqual(self._nudges(task_id), [])
        self.assertFalse(self.dispatcher._nudge_watching)  # pyright: ignore[reportPrivateUsage]
        self.assertFalse(self.dispatcher.has_live_work())
        for runtime in (Runtime.BUSY, Runtime.BACKGROUND, Runtime.WAITING):  # 运行态不是 IDLE 才驻留
            with self.subTest(runtime=runtime):
                self.pane_runtime = runtime
                self._check()
                self.assertTrue(self.dispatcher.has_live_work())
        self.pane_runtime = Runtime.IDLE
        self.runtime = Runtime.BUSY  # 端点一侧忙也算
        self._check()
        self.assertTrue(self.dispatcher.has_live_work())

    def test_stopped_within_grace_is_watched_until_the_nudge(self) -> None:
        task_id, _ = self._prepare(origin=None)
        self.now = self.ended + 100  # 刚停下、宽限未满：驻留到点（最多 300 秒）
        self._check()
        self.assertTrue(self.dispatcher.has_live_work())
        self.now = self.ended + NUDGE_GRACE_SECONDS
        self._check()
        self.assertEqual(len(self._nudges(task_id)), 1)
        self.assertFalse(self.dispatcher._nudge_watching)  # pyright: ignore[reportPrivateUsage]

    def test_after_the_silent_reminder_a_late_stop_is_watched_through_grace_and_nudged(self) -> None:
        # §104.11 第 4 条（dfcdb7e 补定）：沉默提醒已发出、执行方忙到 T 之后才停；worker 只靠盯守驻留到宽限期满并发出催促
        task_id, _ = self._prepare()  # 发起方可通知：T 时发沉默提醒
        anchor = self.now
        self.runtime = self.pane_runtime = Runtime.BUSY
        self.now = anchor + T
        self._check()
        self.assertEqual(len([item for item in self.store.attempts(task_id) if item.is_silent_reminder]), 1)
        self.assertTrue(self.dispatcher._nudge_watching)  # pyright: ignore[reportPrivateUsage]
        self.ended = anchor + T + 600  # 忙到 T 之后 10 分钟才停
        self.runtime = self.pane_runtime = Runtime.IDLE
        self.now = self.ended + 100
        self._check()
        task = self.store.get_task(task_id)
        assert task is not None
        self.assertEqual([item for item in pending_notices(task, self.store.attempts(task_id))
                          if item.kind == "silent"], [])  # 没有待发的沉默提醒替它驻留
        self.assertFalse(needs_worker(self.store, self.now))  # 投递观察窗口也已过：只剩盯守
        self.assertTrue(self.dispatcher._nudge_watching)  # pyright: ignore[reportPrivateUsage]
        self.assertTrue(self.dispatcher.has_live_work())
        self.assertEqual(self._nudges(task_id), [])
        self.now = self.ended + NUDGE_GRACE_SECONDS
        self._check()
        self.assertEqual(len(self._nudges(task_id)), 1)
        self.assertFalse(self.dispatcher._nudge_watching)  # pyright: ignore[reportPrivateUsage]

    def _fill_notes(self, task_id: str, last: int) -> None:
        while max(item.seq for item in self.store.attempts(task_id)) < last:
            note = self.store.add_attempt(task_id, role=Role.NOTICE, target=WORKER, body="补充", refs=[], now=self.now,
                                          sender=R.LEAD, sender_class="bypass",
                                          options={"noticeKind": "note", "forSeq": 1})
            self.store.begin_send(note.id, now=self.now, pid=1, start_ticks="1")
            self.store.finish_send(note.id, delivery=Delivery.WRITTEN, reason="t", provider_ref=None, detail={},
                                   now=self.now)

    def _origin_silent(self, task_id: str) -> list:
        return [item for item in self.store.attempts(task_id)
                if item.is_silent_reminder and item.delivery in (Delivery.WRITTEN, Delivery.QUEUED, Delivery.DELIVERED)]

    def test_at_60_the_nudge_yields_the_last_slot_and_the_origin_gets_the_close_instruction(self) -> None:
        # Codex P1-03（test_last_origin_slot）：序号已到 60 时不催；满 T 后 61 给发起方，正文是容量写法（close 后重开）
        task_id, _ = self._prepare()
        self._fill_notes(task_id, 60)
        self.now = self.ended + NUDGE_GRACE_SECONDS
        self._run()
        self.assertEqual(self._nudges(task_id), [])
        self.now += 48 * 3600
        self._run()
        [silent] = self._origin_silent(task_id)
        self.assertEqual(silent.seq, 61)
        self.assertIn("交接次数已达上限", silent.body)

    def test_nudge_first_then_the_origin_still_gets_its_slot_after_t(self) -> None:
        # 真实队列「先催、随后满 T」：最后一条序号 59 时催促占 60，催后满 T 仍没动静，61 给发起方
        task_id, _ = self._prepare()
        self._fill_notes(task_id, 59)
        self.now = self.ended + NUDGE_GRACE_SECONDS
        self._run()
        [nudge] = self._nudges(task_id)
        self.assertEqual(nudge.seq, 60)
        self.now = nudge.created_at + T
        self._run()
        [silent] = self._origin_silent(task_id)
        self.assertEqual(silent.seq, 61)
        self.assertIn("交接次数已达上限", silent.body)

    def test_progress_between_candidate_and_write_cancels_the_nudge(self) -> None:
        # Codex P2-01（test_nudge_rechecks_intervening_progress）：取候选之后、写入之前有新进展，这次观察不能作证
        task_id, work_id = self._prepare()
        self.now = self.ended + NUDGE_GRACE_SECONDS
        observe = self.dispatcher.observe
        assert observe is not None

        def observe_then_progress():  # noqa: ANN202
            state = observe()
            self.store.set_work(work_id, work=Work.IN_PROGRESS, result=None, now=self.now, event="progress")
            return state

        self.dispatcher.observe = observe_then_progress
        self._check()
        self.assertEqual(self._nudges(task_id), [])

    def _intervene(self, change) -> str:  # noqa: ANN001
        """取候选之后、写入之前调 change(task_id, work_id, anchor)；返回任务 ID。anchor 是此刻的沉默锚点（交出时刻）。"""
        task_id, work_id = self._prepare()
        work = self.store.get_attempt(work_id)
        assert work is not None and work.delivery_at is not None and work.work_at is None
        anchor = work.delivery_at
        self.now = self.ended + NUDGE_GRACE_SECONDS
        observe = self.dispatcher.observe
        assert observe is not None

        def observe_then_change():  # noqa: ANN202
            state = observe()
            change(task_id, work_id, anchor)
            return state

        self.dispatcher.observe = observe_then_change
        self._check()
        return task_id

    def test_progress_at_the_anchor_time_between_candidate_and_write_still_cancels_the_nudge(self) -> None:
        # §104.12 第 6 条：写事务比进展基准、不比锚点时刻；新进展与原锚点同一时刻时锚点不变，照样不催
        task_id = self._intervene(lambda _task, work_id, anchor: self.store.set_work(
            work_id, work=Work.IN_PROGRESS, result=None, now=anchor, event="progress"))
        self.assertEqual(self._nudges(task_id), [])

    def test_progress_after_a_clock_step_back_between_candidate_and_write_still_cancels_the_nudge(self) -> None:
        # 本机时钟回拨 20 秒后的新进展：工作时刻早于原锚点，锚点不变，但进展基准变了
        task_id = self._intervene(lambda _task, work_id, anchor: self.store.set_work(
            work_id, work=Work.IN_PROGRESS, result=None, now=anchor - 20, event="progress"))
        self.assertEqual(self._nudges(task_id), [])

    def test_note_handed_over_after_a_clock_step_back_between_candidate_and_write_still_cancels_the_nudge(self) -> None:
        # 同上，换成新交出的补充（建立与交出都在回拨后的时刻）：已交出补充的 ID 集合变了
        def hand_over_note(task_id: str, _work: str, anchor: float) -> None:
            note = self.store.add_attempt(task_id, role=Role.NOTICE, target=WORKER, body="回答", refs=[],
                                          now=anchor - 20, sender=R.LEAD, sender_class="bypass",
                                          options={"noticeKind": "note", "forSeq": 1})
            self.store.begin_send(note.id, now=anchor - 20, pid=1, start_ticks="1")
            self.store.finish_send(note.id, delivery=Delivery.QUEUED, reason="t", provider_ref=None, detail={},
                                   now=anchor - 20)

        task_id = self._intervene(hand_over_note)
        self.assertEqual(self._nudges(task_id), [])

    def test_note_still_queued_in_the_bridge_between_candidate_and_write_does_not_cancel_the_nudge(self) -> None:
        # 只认已交出的补充（与锚点同口径）：还在桥内排队的补充对方没读到，这次停下仍可作证
        task_id = self._intervene(lambda task_id, _work, anchor: self.store.add_attempt(
            task_id, role=Role.NOTICE, target=WORKER, body="回答", refs=[], now=anchor + 1, sender=R.LEAD,
            sender_class="bypass", options={"noticeKind": "note", "forSeq": 1}))
        self.assertEqual(len(self._nudges(task_id)), 1)

    def _report_between_candidate_and_write(self, kind: ReportKind, *, at_anchor: bool = False,
                                            first: ReportKind | None = None) -> str:
        """经真实汇报入口：先（可选）交一份 first，取候选之后、写入之前再交 kind；两份用同一工作时刻
        （at_anchor 时就是交出时刻，即原锚点）。"""
        from pathlib import Path
        from agentstatus_bridge.reports import ReportInput, apply_report
        from test_bridge_ask import agent
        task_id, _ = self._prepare()
        stamp = self.now if at_anchor else self.now + 1

        def report(which: ReportKind, note: str) -> None:
            apply_report(self.store, ReportInput(task_ref=task_id, attempt_seq=1, kind=which, note=note),
                         caller=agent(WORKER), caller_class="bypass", now=stamp, cwd=Path(self._tmp.name),
                         proc_root=Path(self._tmp.name) / "private-proc")

        if first is not None:
            report(first, "第一份")
        self.now = self.ended + NUDGE_GRACE_SECONDS
        observe = self.dispatcher.observe
        assert observe is not None

        def observe_then_report():  # noqa: ANN202
            state = observe()
            report(kind, "第二份")
            return state

        self.dispatcher.observe = observe_then_report
        self._check()
        return task_id

    def test_second_progress_with_the_same_work_time_between_candidate_and_write_cancels_the_nudge(self) -> None:
        # §104.13 第 5 条（Codex r2 P2-01）：两份普通 progress 工作时刻完全相同，靠 progress 事件序号分辨出新进展
        task_id = self._report_between_candidate_and_write(ReportKind.PROGRESS, first=ReportKind.PROGRESS)
        self.assertEqual(len([e for e in self.store.events(task_id) if e["kind"] == "progress"]), 2)
        self.assertEqual(self._nudges(task_id), [])

    def test_first_ack_at_the_anchor_time_between_candidate_and_write_cancels_the_nudge(self) -> None:
        # 首次 ACK 让工作从等待确认变成已确认：同一时刻也算新进展（看工作状态）
        task_id = self._report_between_candidate_and_write(ReportKind.ACK, at_anchor=True)
        self.assertEqual(self._nudges(task_id), [])

    def test_repeated_ack_between_candidate_and_write_does_not_cancel_the_nudge(self) -> None:
        # 重复 ACK 也写 ack 事件，但不改工作状态与工作时刻，不是新进展：这次停下仍可作证，照常催
        task_id = self._report_between_candidate_and_write(ReportKind.ACK, first=ReportKind.ACK)
        self.assertEqual(len([e for e in self.store.events(task_id) if e["kind"] == "ack"]), 2)
        self.assertEqual(len(self._nudges(task_id)), 1)

    def _queue_origin_silent_at(self, last: int):  # noqa: ANN202
        """把序号填到 last，满 T 后排出发起方的沉默提醒（排在 last+1，还没领取）。"""
        task_id, work_id = self._prepare()
        self._fill_notes(task_id, last)
        self.now += T + 1
        self.assertEqual(self.dispatcher.queue_reminders(), 1)
        slot = self.store.attempts(task_id)[-1]
        self.assertEqual((slot.seq, slot.is_silent_reminder, slot.delivery), (last + 1, True, Delivery.PENDING))
        return task_id, work_id, slot

    def test_last_slot_silent_reminder_is_still_delivered_after_new_progress(self) -> None:
        # §104.13 第 3 条（Codex r2 P1-03）：#61 排出后、领取前对方交了进展，锚点变了；它的正文是「交接次数已达上限，
        # close 后 send 新任务」，不依赖锚点，照常交给发起方。推进 48 小时也只这一条
        task_id, work_id, slot = self._queue_origin_silent_at(60)
        self.now += 1
        self.store.set_work(work_id, work=Work.IN_PROGRESS, result=None, now=self.now, event="progress")
        self._run()
        self.now += 48 * 3600
        self._run()
        delivered = self.store.get_attempt(slot.id)
        assert delivered is not None
        self.assertIn(delivered.delivery, (Delivery.WRITTEN, Delivery.QUEUED, Delivery.DELIVERED))
        self.assertEqual([item.id for item in self._origin_silent(task_id)], [slot.id])
        self.assertIn("交接次数已达上限", delivered.body)

    def test_silent_reminder_below_the_last_slot_is_still_dropped_after_new_progress(self) -> None:
        # 只有最后一格不随锚点作废：#60 上的沉默提醒照旧作废（之后还有 #61 可排）
        task_id, work_id, slot = self._queue_origin_silent_at(59)
        self.now += 1
        self.store.set_work(work_id, work=Work.IN_PROGRESS, result=None, now=self.now, event="progress")
        self._run()
        dropped = self.store.get_attempt(slot.id)
        assert dropped is not None
        self.assertEqual((dropped.delivery, dropped.delivery_reason), (Delivery.CANCELLED, "reminder_outdated"))

    def test_last_slot_silent_reminder_is_dropped_once_the_work_settles(self) -> None:
        # 工作落定（交结果、受阻、无法完成）后，这条已不对：作废
        for work, result in ((Work.RESULT, {"note": "好了"}), (Work.BLOCKED, None), (Work.FAILED, {"note": "不行"})):
            with self.subTest(work=work):
                _task_id, work_id, slot = self._queue_origin_silent_at(60)
                self.now += 1
                self.store.set_work(work_id, work=work, result=result, now=self.now, event=work.value)
                self._run()
                dropped = self.store.get_attempt(slot.id)
                assert dropped is not None
                self.assertEqual((dropped.delivery, dropped.delivery_reason),
                                 (Delivery.CANCELLED, "reminder_outdated"))

    def test_last_slot_rule_checks_task_work_receiver_and_declines(self) -> None:
        # 最后一格的复核逐条：任务结束或暂停、工作落定、换了工作尝试、发起方就是接收方、锚点后发起方拒收过、
        # 不在最后一格——任一成立都不发
        from agentstatus_bridge.reminders import reminder_current
        task_id, work_id, slot = self._queue_origin_silent_at(60)
        self.now += 1
        self.store.set_work(work_id, work=Work.IN_PROGRESS, result=None, now=self.now, event="progress")
        task = self.store.get_task(task_id)
        assert task is not None
        attempts = self.store.attempts(task_id)
        token = slot.options[REMINDER_OPTION]
        self.assertTrue(reminder_current(task, attempts, token))
        work = next(item for item in attempts if item.id == work_id)

        def swap(old, new):  # noqa: ANN001, ANN202
            return [new if item.id == old.id else item for item in attempts]

        cases = {
            "closed": (replace(task, closed_at=self.now), attempts),
            "paused": (replace(task, control="paused"), attempts),
            "result": (task, swap(work, replace(work, work=Work.RESULT))),
            "other work": (task, swap(work, replace(work, id="another-work-attempt"))),
            "origin receives": (replace(task, origin=work.target), attempts),
            "declined": (task, [*attempts, replace(slot, id="refused", seq=62, delivery=Delivery.REFUSED,
                                                   options={"noticeKind": "result"})]),
            "not last": (task, swap(slot, replace(slot, seq=60))),
        }
        for name, (case_task, case_attempts) in cases.items():
            with self.subTest(case=name):
                self.assertFalse(reminder_current(case_task, case_attempts, token))

    def test_queued_nudge_is_dropped_on_claim_after_new_progress_but_not_by_its_own_anchor(self) -> None:
        # 领取时复核：排队后有新进展就作废；催促自己把锚点推到它的建立时刻，那不算（§104.12 第 6 条）
        task_id, work_id = self._prepare()
        work = self.store.get_attempt(work_id)
        assert work is not None
        self.runtime = self.pane_runtime = Runtime.BUSY  # 不再起新的催促候选
        for progress in (False, True):
            with self.subTest(progress=progress):
                nudge = self.store.add_attempt(task_id, role=Role.NOTICE, target=WORKER, body="催", refs=[],
                                               now=self.now + 10, sender=None, sender_class="bypass",
                                               options={"noticeKind": "nudge", REMINDER_OPTION: nudge_token(work)})
                if progress:
                    self.store.set_work(work_id, work=Work.IN_PROGRESS, result=None, now=self.now + 20,
                                        event="progress")
                self._run()
                claimed = self.store.get_attempt(nudge.id)
                assert claimed is not None
                if progress:
                    self.assertEqual((claimed.delivery, claimed.delivery_reason), (Delivery.CANCELLED,
                                                                                   "reminder_outdated"))
                else:
                    self.assertIn(claimed.delivery, (Delivery.WRITTEN, Delivery.QUEUED, Delivery.DELIVERED))

    def test_stale_observation_is_not_watched_even_if_busy(self) -> None:
        # 审计 1i：观察不新鲜时不能作证，运行态写着 BUSY 也不驻留
        task_id, _ = self._prepare(origin=None)
        self.runtime = self.pane_runtime = Runtime.BUSY
        self.fresh = False
        self.now += 120
        self._check()
        self.assertFalse(self.dispatcher._nudge_watching)  # pyright: ignore[reportPrivateUsage]
        self.assertFalse(self.dispatcher.has_live_work())
        self.fresh = True
        self._check()
        self.assertTrue(self.dispatcher.has_live_work())
        self.assertEqual(self._nudges(task_id), [])

    def test_nudge_leaves_the_last_reminder_slot_to_the_origin(self) -> None:
        # 审计 1j 与 Codex P1-03（§104.12 第 3 条）：提醒档上限 61，最后一格留给发起方；最后一条序号 59 时能催（占 60），
        # 已到 60 时不催
        for last, expected in ((59, True), (60, False), (61, False)):
            with self.subTest(last=last):
                task_id, _ = self._prepare()
                while max(item.seq for item in self.store.attempts(task_id)) < last:
                    self.store.add_attempt(task_id, role=Role.NOTICE, target=R.LEAD, body="容量夹具", refs=[],
                                           now=self.now, sender=None, sender_class="bypass")
                task = self.store.get_task(task_id)
                assert task is not None
                self.assertEqual(nudge_candidate(task, self.store.attempts(task_id)) is not None, expected)

    def test_codex_item_still_in_queue_is_watched(self) -> None:
        codex = ref(Provider.CODEX, "019a0000-2222-7222-8222-222222222222", pid=6000, pane="%6", label="cx")
        task, work = self.store.create_task(title="排队", flow=Flow.HANDOFF, origin=None, origin_class="bypass",
                                            reviewer=None, target=codex, body="做 X", refs=[], now=self.now)
        self.store.begin_send(work.id, now=self.now, pid=1, start_ticks="1")
        self.store.finish_send(work.id, delivery=Delivery.QUEUED, reason="codex_queued", provider_ref="item-1",
                               detail={}, now=self.now)
        queued = self.store.get_attempt(work.id)
        assert queued is not None
        idle = PaneState(runtime=Runtime.IDLE, last_turn_ended_at=self.now - 10, fresh=True)
        live = endpoint(codex)
        window = CONSUMPTION_WATCH_SECONDS
        self.assertEqual(window, 30 * 60.0)  # 与 reconcile 的观察窗口同口径
        self.assertTrue(worth_watching(queued, live, idle, anchor=self.now, now=self.now + 600, queue_window=window))
        left = replace(queued, consumption=Consumption.LEFT_QUEUE)
        self.assertFalse(worth_watching(left, live, idle, anchor=self.now, now=self.now + 600, queue_window=window))
        # 消费状态冻结在 still_queued：入队满 30 分钟后不再为它驻留（§104.11 P3）
        self.assertTrue(worth_watching(queued, live, idle, anchor=self.now, now=self.now + 1799, queue_window=window))
        self.assertFalse(worth_watching(queued, live, idle, anchor=self.now, now=self.now + 1800, queue_window=window))
        self.assertEqual(task.id, queued.task_id)

    def test_answer_needs_a_new_turn_after_its_delivery_before_a_nudge(self) -> None:
        # 提问后停下（等回答）不催；回答交出之后，交出前结束的那一轮不算，得再结束一轮、停满宽限才催（§104.11 第 2 条）
        task_id, work_id = self._prepare()
        self.store.set_attempt_option(work_id, "ask", {"at": self.now + 30, "note": "问题"})
        self.store.set_work(work_id, work=Work.IN_PROGRESS, result=None, now=self.now + 30, event="progress")
        answer_at = self.now + 2000
        work = work_attempts(self.store.attempts(task_id))[-1]
        note = self.store.add_attempt(task_id, role=Role.NOTICE, target=WORKER, body="回答", refs=[], now=answer_at,
                                      sender=R.LEAD, sender_class="bypass",
                                      options={"noticeKind": "note", "forSeq": work.seq})
        self.store.begin_send(note.id, now=answer_at, pid=1, start_ticks="1")
        self.store.finish_send(note.id, delivery=Delivery.WRITTEN, reason="claude_written", provider_ref=None,
                               detail={}, now=answer_at)
        self.now = answer_at + NUDGE_GRACE_SECONDS * 2
        self._check()
        self.assertEqual(self._nudges(task_id), [])  # 最近一轮结束（交出后 60 秒）早于回答
        self.ended = answer_at + 100  # 回答之后又结束了一轮
        self.now = self.ended + NUDGE_GRACE_SECONDS - 1
        self._check()
        self.assertEqual(self._nudges(task_id), [])
        self.now = self.ended + NUDGE_GRACE_SECONDS
        self._check()
        self.assertEqual(len(self._nudges(task_id)), 1)

    def test_question_pending_or_reported_attempts_are_not_nudged(self) -> None:
        task_id, work_id = self._prepare()
        self.store.set_attempt_option(work_id, "ask", {"at": self.now + 30, "note": "问题"})
        self.store.set_work(work_id, work=Work.IN_PROGRESS, result=None, now=self.now + 30, event="progress")
        self.now = self.ended + NUDGE_GRACE_SECONDS * 2
        self._check()
        self.assertEqual(self._nudges(task_id), [])
        other, other_work = self._prepare()
        self.store.set_work(other_work, work=Work.RESULT, result={"note": "x"}, now=self.now, event="result")
        self.now = self.ended + NUDGE_GRACE_SECONDS * 2
        self._check()
        self.assertEqual(self._nudges(other), [])

    def test_ack_then_stopped_without_result_is_nudged(self) -> None:
        task_id, work_id = self._prepare()
        self.store.set_work(work_id, work=Work.ACKNOWLEDGED, result=None, now=self.now + 10, event="ack")
        self.now = self.ended + NUDGE_GRACE_SECONDS
        self._check()
        self.assertEqual(len(self._nudges(task_id)), 1)

    def test_nudge_is_cancelled_when_the_executor_reports_before_it_goes_out(self) -> None:
        task_id, work_id = self._prepare()
        self.now = self.ended + NUDGE_GRACE_SECONDS
        online = self.dispatcher.discover
        self.dispatcher.discover = lambda: []  # 催促排上但这轮发不出
        self._check()
        [nudge] = self._nudges(task_id)
        self.store.set_work(work_id, work=Work.RESULT, result={"note": "x"}, now=self.now, event="result")
        self.dispatcher.discover = online
        self._run()
        refreshed = self.store.get_attempt(nudge.id)
        assert refreshed is not None
        self.assertEqual((refreshed.delivery, refreshed.delivery_reason), (Delivery.CANCELLED, "reminder_outdated"))

    def test_checks_are_throttled_and_absent_without_observe(self) -> None:
        task_id, _ = self._prepare()
        calls: list[int] = []
        base = self._observe

        def counting():
            calls.append(1)
            return base()
        self.dispatcher.observe = counting
        self._check()
        self._run()
        self._run()
        self.assertEqual(len(calls), 1)  # 30 秒节流
        self.dispatcher.observe = None
        self.now = self.ended + NUDGE_GRACE_SECONDS * 2
        self._check()
        self.assertEqual(self._nudges(task_id), [])

    def test_no_candidates_means_no_observation(self) -> None:
        self._prepare()
        self.dispatcher.observe = lambda: (_ for _ in ()).throw(AssertionError("不该取观察"))
        for task in self.store.list_tasks():
            self.store.update_task(task.id, now=self.now, event="closed", closed_at=self.now)
        self._check()
        self.assertFalse(self.dispatcher._nudge_watching)  # pyright: ignore[reportPrivateUsage]

    def test_candidate_requires_room_and_no_prior_nudge(self) -> None:
        task_id, work_id = self._prepare()
        task = self.store.get_task(task_id)
        work = self.store.get_attempt(work_id)
        assert task is not None and work is not None
        self.assertIsNotNone(nudge_candidate(task, self.store.attempts(task_id)))
        self.store.add_attempt(task_id, role=Role.NOTICE, target=WORKER, body="催", refs=[], now=self.now,
                               sender=None, sender_class="bypass",
                               options={"noticeKind": "nudge", REMINDER_OPTION: nudge_token(work)})
        self.assertIsNone(nudge_candidate(task, self.store.attempts(task_id)))


class FederatedSilenceTests(FederationTestCase):
    def test_authority_tells_the_origin_with_cross_device_unknown_state(self) -> None:
        task, first = self.create()
        state = dict(task.state, expect=600)
        with self.a.store.transaction() as conn:
            import json
            conn.execute("UPDATE fed_tasks SET state_json=? WHERE authority_device=? AND task_id=?",
                         (json.dumps(state), DEV_A, task.task_id))
        pump(self.a, self.b, now=T0 + 1)
        deliver(self.b, first.msg_id, "queued", now=T0 + 2)
        pump(self.b, self.a, now=T0 + 3)
        dispatcher = FederationDispatcher(self.a.store, self.a.ident, RelayPaths(self.root), discover=lambda: [],
                                          transports={}, clock=lambda: T0 + 2 + 600_000)
        current = self.a.store.get_task(DEV_A, task.task_id)
        assert current is not None
        self.assertEqual(model_task(current).options.get("expect"), 600)
        candidates = list(mirror.reminder_candidates(self.a.store, T0 + 2 + 600_000))
        self.assertEqual([(item[1].kind, item[2]) for item in candidates], [("silent", True)])
        self.assertIn(f"reminder:{candidates[0][1].token}",
                      mirror.wake_candidates(self.a.store, self.a.ident, now=T0 + 2 + 600_000))
        self.assertEqual(dispatcher.queue_reminders(), 1)
        [notice] = [item for item in self.a.store.attempts(DEV_A, task.task_id) if item.role == "notice"]
        self.assertEqual(notice.options.get("noticeKind"), "reminder")  # 线上已有类别
        self.assertIn("对方：跨设备未知", notice.body)
        self.assertTrue(model_attempts([notice])[0].is_silent_reminder)
        self.assertEqual(list(mirror.reminder_candidates(self.a.store, T0 + 3_000_000)), [])


    def test_accepted_progress_without_delivery_evidence_still_anchors(self) -> None:
        # Codex P2-02（§104.12 第 7 条）：B 的进展先到、投递证据后到；A 已采纳进展时以采纳时刻为锚点，满 T 照常提醒
        import json
        task, first = self.create()
        pump(self.a, self.b, now=T0 + 10)
        deliver(self.b, first.msg_id, "queued", now=T0 + 20)
        self.b_report(task.task_id, 1, "progress", now=T0 + 30)
        row = next(item for item in self.b.store.outbox() if json.loads(item["envelope_json"])["kind"] == "report")
        mirror.receive(self.a.store, self.a.ident, json.loads(row["envelope_json"]), source_device=DEV_B,
                       payload_hash=row["payload_hash"], now=T0 + 40)
        [attempt] = model_attempts(self.a.store.attempts(DEV_A, task.task_id))
        self.assertEqual((attempt.delivery.value, attempt.work.value, attempt.delivery_at),
                         ("delivered", "in_progress", None))
        self.assertEqual(silence_anchor([attempt], attempt), attempt.work_at)
        now = T0 + 3_600_000
        due = [item for _task, item, ready in mirror.reminder_candidates(self.a.store, now)
               if ready and item.kind == "silent"]
        self.assertEqual(len(due), 1)

    def _same_session_id_on_b(self):  # noqa: ANN202
        """B 上绑定一个与 A 的发起方同 provider、同会话号的端点（同一会话拷到两台机器），A 把任务交给它并已交出。"""
        from agentstatus_bridge.federation.refs import TargetRef
        twin = self.b.bind(self.origin.remote.provider, self.origin.remote.native_id)
        self.assertFalse(self.origin.remote.same_endpoint(twin.remote))
        self.worker = twin
        self.worker_remote = TargetRef(remote=twin.remote)
        task, first = self.create()
        pump(self.a, self.b, now=T0 + 1)
        deliver(self.b, first.msg_id, "written", now=T0 + 2)
        pump(self.b, self.a, now=T0 + 3)
        return task, first

    def _due_kinds(self, task_id: str, now: int) -> list[str]:
        return [item.kind for task, item, ready in mirror.reminder_candidates(self.a.store, now)
                if ready and task.task_id == task_id]

    def test_same_session_id_on_another_device_is_the_silent_counterparty(self) -> None:
        # §104.13 第 4 条（Codex r2 P1-04）：「是不是自己」带设备比较。A 的发起方照常收到沉默提醒、待办列「对方沉默」，
        # 不被列为接收方去代对方汇报
        from agentstatus_bridge.todo import local_items
        task, _ = self._same_session_id_on_b()
        now = T0 + 3_600_000
        self.assertEqual(self._due_kinds(task.task_id, now), ["silent"])
        current = self.a.store.get_task(DEV_A, task.task_id)
        assert current is not None
        attempts = model_attempts(self.a.store.attempts(DEV_A, task.task_id))
        self.assertEqual(attempts[0].target_device, DEV_B)
        items = local_items(model_task(current), attempts, self.origin.local, now=now / 1000, command="ab",
                            scope="federation")
        self.assertEqual([item.category for item in items], ["silent"])

    def test_same_session_id_on_another_device_still_gets_the_main_reminder(self) -> None:
        # §103 主提醒同一判据：对方受阻后发起方没处理，满 30 分钟照常提醒（不因「发起方就是接收方」而跳过）
        task, _ = self._same_session_id_on_b()
        self.b_report(task.task_id, 1, "blocked", note="卡住", now=T0 + 10)
        pump(self.b, self.a, now=T0 + 11)
        [notice] = [item for item in self.a.store.attempts(DEV_A, task.task_id) if item.role == "notice"]
        deliver(self.a, notice.msg_id, "written", now=T0 + 12)  # 受阻回执已交给 A 的发起方
        self.assertIn("main", self._due_kinds(task.task_id, T0 + 12 + 31 * 60 * 1000))

    def test_same_session_id_on_another_device_still_gets_the_note_undelivered_notice(self) -> None:
        # §103.2 补充未送达告知同一判据：发给 B 上同号会话的补充确定没送到，立即告诉 A 的发起方
        from agentstatus_bridge.federation import authority
        task, _ = self._same_session_id_on_b()
        current = self.a.store.get_task(DEV_A, task.task_id)
        assert current is not None
        _, note = authority.add_note(self.a.store, self.a.ident, current, body="补充", sender=self.origin_actor(),
                                     sender_class="bypass", now=T0 + 100)
        pump(self.a, self.b, now=T0 + 101)
        deliver(self.b, note.msg_id, "failed", now=T0 + 102)
        pump(self.b, self.a, now=T0 + 103)
        self.assertIn("note", self._due_kinds(task.task_id, T0 + 104))

    def test_origin_reviewing_on_its_own_device_is_still_itself(self) -> None:
        # 反向（§104.13 第 4 条）：发起方在 A 上兼任复核方，复核尝试的接收方就在 A，仍是自己——不给自己发沉默提醒，
        # todo 列「待你复核」而不是「对方沉默」
        from agentstatus_bridge.todo import local_items
        task, first = self.create(flow="review", reviewer=self.origin)
        pump(self.a, self.b, now=T0 + 1)
        deliver(self.b, first.msg_id, "queued", now=T0 + 2)
        pump(self.b, self.a, now=T0 + 3)
        self.b_report(task.task_id, 1, "result", note="已修复", now=T0 + 4)
        pump(self.b, self.a, now=T0 + 5)
        review = next(item for item in self.a.store.attempts(DEV_A, task.task_id) if item.seq == 2)
        self.assertEqual((review.role, review.target_device), ("review", DEV_A))
        deliver(self.a, review.msg_id, "written", now=T0 + 6)
        now = T0 + 6 + 3_600_000
        self.assertEqual(self._due_kinds(task.task_id, now), [])
        current = self.a.store.get_task(DEV_A, task.task_id)
        assert current is not None
        items = local_items(model_task(current), model_attempts(self.a.store.attempts(DEV_A, task.task_id)),
                            self.origin.local, now=now / 1000, command="ab", scope="federation")
        self.assertEqual([item.category for item in items], ["review"])

    def test_a_handed_over_note_moves_the_authority_anchor(self) -> None:
        # 联邦同一判据（§104.11 第 2 条）：A 补给远端执行方的补充经 B 交出后，从交出时刻重新计时
        from agentstatus_bridge.federation import authority
        task, first = self.create()
        pump(self.a, self.b, now=T0 + 1)
        deliver(self.b, first.msg_id, "queued", now=T0 + 2)
        pump(self.b, self.a, now=T0 + 3)
        current = self.a.store.get_task(DEV_A, task.task_id)
        assert current is not None
        _, note = authority.add_note(self.a.store, self.a.ident, current, body="催问", sender=self.origin_actor(),
                                     sender_class="bypass", now=T0 + 600_000)
        pump(self.a, self.b, now=T0 + 600_001)
        deliver(self.b, note.msg_id, "queued", now=T0 + 600_002)
        pump(self.b, self.a, now=T0 + 600_003)

        def silent(now: int) -> list[tuple[float | None, bool]]:
            return [(item[1].anchor, item[2]) for item in mirror.reminder_candidates(self.a.store, now)
                    if item[1].kind == "silent"]

        handed = (T0 + 600_002) / 1000.0
        self.assertEqual(silent(T0 + 2 + 1_800_000), [(handed, False)])  # 旧锚点（交出于 T0+2）满 T 也不到期
        self.assertEqual(silent(T0 + 600_002 + 1_800_000), [(handed, True)])


if __name__ == "__main__":
    unittest.main()
