"""发起方待办提醒（DESIGN §45.28.3）：判定矩阵、30 分钟边界、只提醒一次、返工重新计时与失败隔离。"""

from __future__ import annotations

from dataclasses import replace
import os
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from agentstatus_bridge import procfs, summary
from agentstatus_bridge.naming import DEFAULT_COMMAND as CMD
from agentstatus_bridge.dispatch import (
    REMINDER_MAX_SCAN_ERRORS,
    REMINDER_RETRY_SECONDS,
    TARGET_GONE_GRACE_SECONDS,
    Dispatcher,
    needs_worker,
)
from agentstatus_bridge.envelope import parse_header
from agentstatus_bridge.ids import short
from agentstatus_bridge.model import (
    Consumption,
    Delivery,
    EndpointRef,
    Flow,
    Phase,
    Provider,
    Role,
    Runtime,
    Verdict,
    Work,
    describe,
    work_attempts,
)
from agentstatus_bridge.reminders import REMIND_AFTER_SECONDS, REMINDER_OPTION, pending_reminder, reminder_token
from agentstatus_bridge.store import MAX_ATTEMPTS_PER_TASK, Store, StoreError
from agentstatus_bridge.transports import DeliveryOutcome
from bridge_support import RecordingTransport, endpoint, ref

LEAD = ref(Provider.CLAUDE, "lead-session", pid=3000, pane="%3", label="lead")
IMPL = ref(Provider.CODEX, "impl-thread", pid=1000, pane="%1", label="impl")
LEAD_SOCKET = "/run/test/lead.sock"
CODEX_LEAD = ref(Provider.CODEX, "lead-thread", pid=3100, pane="%4", label="codex-lead")
# 只读发起方：Grok 没有收件通道，发现时就带 no_inbox（DESIGN §45.34）
GROK_LEAD = ref(Provider.GROK, "019a0000-cccc-7ccc-8ccc-cccccccccccc", pid=3200, pane="%9", label="grok-lead")


class ReminderTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = TemporaryDirectory()
        self.store = Store.open(Path(self._tmp.name) / "bridge")
        self.now = 1000.0
        self.lead_online = True
        self.grok_online = False
        self.lead_busy = False
        self.codex_lead_busy = False
        self.queue_state = Consumption.UNKNOWN
        self.codex = RecordingTransport(Provider.CODEX)
        self.claude = RecordingTransport(
            Provider.CLAUDE,
            lambda _endpoint, _text, context: DeliveryOutcome(
                Delivery.WRITTEN, "claude_written", provider_ref=context.message_uuid
            ),
        )
        self.records: list[tuple[str, dict[str, object]]] = []
        self.dispatcher = Dispatcher(
            store=self.store,
            discover=self._discover,
            transports={Provider.CODEX: self.codex, Provider.CLAUDE: self.claude},
            reply_address="uds:/run/test/inbox.sock",
            clock=lambda: self.now,
            # 显式注入：不去读本机真实的 Codex 队列（Codex 实现审计旁注）
            queue_state=lambda _item: self.queue_state,
            log=lambda event, fields: self.records.append((event, dict(fields))),
        )

    def tearDown(self) -> None:
        self.store.close()
        self._tmp.cleanup()

    def _discover(self):
        if getattr(self, "endpoints_empty", False):
            return []
        found = [endpoint(IMPL), endpoint(CODEX_LEAD, runtime=Runtime.BUSY if self.codex_lead_busy else Runtime.IDLE)]
        if self.lead_online:
            runtime = Runtime.BUSY if self.lead_busy else Runtime.IDLE
            found.append(endpoint(LEAD, runtime=runtime, socket_path=LEAD_SOCKET))
        if self.grok_online:
            found.append(endpoint(GROK_LEAD, issues=("no_inbox",)))
        return found

    def _task(
        self,
        *,
        origin: EndpointRef | None = LEAD,
        flow: Flow = Flow.HANDOFF,
        reviewer: EndpointRef | None = None,
        options: dict[str, object] | None = None,
    ) -> str:
        task, _attempt = self.store.create_task(
            title="实现 X",
            flow=flow,
            origin=origin,
            origin_class="bypass",
            reviewer=reviewer,
            target=IMPL,
            body="请实现 X",
            refs=[],
            now=self.now,
            task_options=options,
        )
        return task.id

    def _run(self) -> None:
        self.dispatcher._endpoints_at = None  # pyright: ignore[reportPrivateUsage]
        self.dispatcher.run_once()

    def _deliver(self, attempt_id: str) -> None:
        self.store.begin_send(attempt_id, now=self.now, pid=1, start_ticks="1")
        self.store.finish_send(
            attempt_id, delivery=Delivery.QUEUED, reason="codex_queued", provider_ref=None, detail={}, now=self.now
        )

    def _report(self, task_id: str, work: Work = Work.RESULT, *, notice: bool = True) -> None:
        """模拟接收方汇报：工作状态与回告发起方的 notice 同一时刻写入（与 reports.apply_report 一致）。"""
        current = work_attempts(self.store.attempts(task_id))[-1]
        with self.store.transaction():
            result = {"note": "完成"} if work in (Work.RESULT, Work.FAILED) else None
            self.store.set_work(current.id, work=work, result=result, now=self.now, event="result")
            task = self.store.get_task(task_id)
            if notice and task is not None and task.origin is not None:
                self.store.add_attempt(
                    task_id, role=Role.NOTICE, target=task.origin, body="你发起的任务已完成", refs=[],
                    # 与发起方登记的 bypass 故意不同：「类别沿用」不能靠两者碰巧相等通过（Opus 审计 F4）
                    now=self.now, sender=IMPL, sender_class="prompting",
                )

    def _pending(self, task_id: str):
        task = self.store.get_task(task_id)
        assert task is not None
        return pending_reminder(task, self.store.attempts(task_id))

    def _reminders(self, task_id: str):
        return [item for item in self.store.attempts(task_id) if REMINDER_OPTION in item.options]

    def _view(self, task_id: str):
        task = self.store.get_task(task_id)
        assert task is not None
        return describe(task, self.store.attempts(task_id))

    def _summary_token(self, task_id: str) -> str:
        document = summary.build_document(summary.read_ledger(self.store), now=self.now, device="testbox")
        return next(item for item in document["tasks"] if item["id"] == task_id)["attention"]["token"]

    # ---- 端到端：worker 一轮轮推进 ----

    def test_read_only_target_fails_even_when_discovery_is_empty(self) -> None:
        """发现整体为空（例如刚重启、还没有任何会话）也要立刻终态失败：能力是静态的（Codex 审计 F02）。"""
        self.grok_online = True
        task_id = self._task(origin=GROK_LEAD)
        work = work_attempts(self.store.attempts(task_id))[-1]
        self._deliver(work.id)
        self._report(task_id)
        self.lead_online = False
        self.grok_online = False
        self.endpoints_empty = True  # discover 返回空：普通 provider 据此不判目标不在，只读 provider 照样终态失败
        self.now += 1
        self._run()
        notices = [item for item in self.store.attempts(task_id) if item.role is Role.NOTICE]
        self.assertEqual([(item.delivery, item.delivery_reason) for item in notices], [(Delivery.FAILED, "target_no_inbox")])
        self.now += REMIND_AFTER_SECONDS + 60
        self._run()
        self.assertFalse(needs_worker(self.store, self.now))

    def test_read_only_origin_gets_no_receipt_and_no_resident_worker(self) -> None:
        """Grok 只能发起：回执与提醒都投不进去，必须终态失败，不能让 worker 一直醒着（DESIGN §45.34）。"""
        self.grok_online = True
        task_id = self._task(origin=GROK_LEAD)
        work = work_attempts(self.store.attempts(task_id))[-1]
        self._deliver(work.id)
        self._report(task_id)  # 接收方交结果，桥照常给发起方排结果回执
        self.now += 1
        self._run()
        notices = [item for item in self.store.attempts(task_id) if item.role is Role.NOTICE]
        self.assertEqual([(item.delivery, item.delivery_reason) for item in notices], [(Delivery.FAILED, "target_no_inbox")])
        # 回执不是工作尝试：任务照常停在待验收，不会因为投不出去变成「需处理」
        self.assertEqual(self._view(task_id).phase, Phase.AWAITING_ACCEPTANCE)
        # 过了 30 分钟提醒时刻再跑：提醒要么不排、要么同样终态失败，两种情况下 worker 都不为它驻留
        self.now += REMIND_AFTER_SECONDS + 60
        self._run()
        self.assertTrue(
            all(item.delivery is Delivery.FAILED for item in self.store.attempts(task_id) if item.role is Role.NOTICE)
        )
        self.assertFalse(needs_worker(self.store, self.now))
        # 再跑一轮也不会把失败的通知翻出来重排（否则每轮失败一次，worker 永远醒着）
        before = len(self.store.attempts(task_id))
        self._run()
        self.assertEqual(len(self.store.attempts(task_id)), before)

    def test_result_is_reminded_once_after_thirty_minutes(self) -> None:
        task_id = self._task()
        self.queue_state = Consumption.LEFT_QUEUE  # 交接已被消费：驻留只可能来自等提醒
        self._run()  # 交接进入 Codex 队列
        self._report(task_id)
        self._run()  # 结果回执写入发起方会话
        start = self.now
        token = self._summary_token(task_id)
        self.now = start + REMIND_AFTER_SECONDS - 0.001
        self._run()
        self.assertEqual(self._reminders(task_id), [])
        self.assertTrue(needs_worker(self.store, self.now + 3600), "等提醒到期期间 worker 必须驻留")
        self.assertTrue(self.dispatcher.has_live_work(), "worker 自己的驻留判定同样要算上待提醒")
        self.now = start + REMIND_AFTER_SECONDS
        self._run()
        [reminder] = self._reminders(task_id)
        self.assertEqual((reminder.role, reminder.target, reminder.sender), (Role.NOTICE, LEAD, None))
        self.assertEqual(reminder.options[REMINDER_OPTION], token)
        self.assertEqual(
            reminder.body.splitlines()[0], "提醒：这项任务已超过 30 分钟没有处理——对方已交结果，待验收（codex@impl）。"
        )
        self.assertIn(f"下一步：{CMD} accept {short(task_id)} 验收", reminder.body)
        # 同一轮里就发出去了；消息头是桥发出的 notice
        self.assertEqual(self.store.get_attempt(reminder.id).delivery, Delivery.WRITTEN)  # type: ignore[union-attr]
        _endpoint, text, context = self.claude.calls[-1]
        header = parse_header(text)
        assert header is not None
        self.assertEqual((header.role, header.sender), (Role.NOTICE, "user"))
        # 沿用发起方登记时的权限类别：与接收方（发起方自己）一致，Claude 不因类别不同而 hold
        self.assertEqual((reminder.sender_class, context.sender_class), ("bypass", "bypass"))
        self.assertEqual((context.sender_name, context.sender_session), ("AgentStatus 协作桥（提醒）", None))
        self.assertIn("origin_reminded", [event["kind"] for event in self.store.events(task_id)])
        # 提醒不改变任务阶段与关注令牌：界面不会因此再弹一次
        self.assertEqual(self._view(task_id).phase, Phase.AWAITING_ACCEPTANCE)
        self.assertEqual(self._summary_token(task_id), token)
        self.now += REMIND_AFTER_SECONDS * 4
        self._run()
        self.assertEqual(len(self._reminders(task_id)), 1, "同一次关注只提醒一次")
        self.assertFalse(needs_worker(self.store, self.now))
        self.assertTrue(any(event == "reminder_queued" for event, _fields in self.records))
        self.assertNotIn("完成", repr(self.records))

    def test_rework_starts_a_new_token_and_a_new_clock(self) -> None:
        task_id = self._task()
        self._run()
        self._report(task_id)
        self._run()
        self.now += REMIND_AFTER_SECONDS
        self._run()
        [first] = self._reminders(task_id)
        # 发起方 ab retry 返工：新的交接进行中不提醒
        self.store.add_attempt(
            task_id, role=Role.HANDOFF, target=IMPL, body="返工", refs=[], now=self.now, sender=LEAD, sender_class="bypass"
        )
        self._run()
        self.assertIsNone(self._pending(task_id))
        self.now += 600
        self._report(task_id)
        self._run()
        pending = self._pending(task_id)
        assert pending is not None
        self.assertEqual(pending.due_at, self.now + REMIND_AFTER_SECONDS)
        self.assertNotEqual(pending.token, first.options[REMINDER_OPTION])
        self.now += REMIND_AFTER_SECONDS
        self._run()
        self.assertEqual(len(self._reminders(task_id)), 2)

    def test_busy_origin_is_timed_from_when_the_result_notice_arrives(self) -> None:
        task_id = self._task()
        self._run()
        self.lead_busy = True
        self._report(task_id)
        reported = self.now
        self.now += 40 * 60
        self._run()
        self.assertEqual(self._reminders(task_id), [], "回执还在排队时不叠加提醒")
        self.lead_busy = False
        self._run()  # 发起方空闲，回执送达
        arrived = self.now
        self._run()
        self.assertEqual(self._reminders(task_id), [], "回执刚送达不紧跟着再提醒")
        pending = self._pending(task_id)
        assert pending is not None
        self.assertEqual(pending.due_at, arrived + REMIND_AFTER_SECONDS)
        self.assertGreater(pending.due_at, reported + REMIND_AFTER_SECONDS)
        self.now = pending.due_at
        self._run()
        self.assertEqual(len(self._reminders(task_id)), 1)

    def test_queued_reminder_is_cancelled_when_the_task_moves_on(self) -> None:
        task_id = self._task()
        self._run()
        self._report(task_id)
        self._run()
        self.lead_busy = True
        self.now += REMIND_AFTER_SECONDS
        self._run()
        [reminder] = self._reminders(task_id)
        self.assertEqual(self.store.get_attempt(reminder.id).delivery, Delivery.PENDING)  # type: ignore[union-attr]
        sent = len(self.claude.calls)
        # 提醒排队期间发起方返工：旧的「请验收」不能再发出去
        self.store.add_attempt(
            task_id, role=Role.HANDOFF, target=IMPL, body="返工", refs=[], now=self.now, sender=LEAD, sender_class="bypass"
        )
        self._run()
        cancelled = self.store.get_attempt(reminder.id)
        assert cancelled is not None
        self.assertEqual((cancelled.delivery, cancelled.delivery_reason), (Delivery.CANCELLED, "reminder_outdated"))
        self.lead_busy = False
        self._run()
        self.assertEqual(len(self.claude.calls), sent, "取消的提醒不外调")
        # 新结果照常计时提醒，被取消的旧提醒不挡路
        self._report(task_id)
        self._run()
        self.now += REMIND_AFTER_SECONDS
        self._run()
        self.assertEqual(len(self._reminders(task_id)), 2)
        self.assertEqual(self.store.get_attempt(self._reminders(task_id)[-1].id).delivery, Delivery.WRITTEN)  # type: ignore[union-attr]

    def test_held_result_notice_is_timed_from_the_prompt_and_expiry_reminds(self) -> None:
        task_id = self._task()
        self._run()
        self.lead_busy = True
        self._report(task_id)
        reported = self.now
        notice = self.store.attempts(task_id)[-1]
        self.now += 10 * 60
        self.store.begin_send(notice.id, now=self.now, pid=1, start_ticks="1")
        self.store.finish_send(notice.id, delivery=Delivery.HELD, reason="claude_held", provider_ref=None, detail={}, now=self.now)
        held_at = self.now
        pending = self._pending(task_id)
        assert pending is not None
        # 批准框弹出即算交到发起方面前：从那时起再等 30 分钟；回执丢失也不会无限挡住提醒
        self.assertEqual(pending.due_at, held_at + REMIND_AFTER_SECONDS)
        self.now = reported + REMIND_AFTER_SECONDS + 60
        self.assertFalse(pending.due(self.now))
        self.store.transition_delivery(
            notice.id, expected=(Delivery.HELD,), new=Delivery.EXPIRED, reason="claude_expired", now=self.now
        )
        expired = self._pending(task_id)
        assert expired is not None
        self.assertTrue(expired.due(self.now), "批准框过期没人看到：按结果时刻计，已到期就提醒")

    def test_reminder_crash_does_not_stop_other_deliveries_and_backs_off(self) -> None:
        self._task()  # 有发起方：会进入提醒判定
        self.queue_state = Consumption.LEFT_QUEUE  # 交接一发出就被消费：驻留只可能来自提醒退避（Opus 复审 P3-3）
        with patch("agentstatus_bridge.dispatch.pending_reminder", side_effect=RuntimeError("boom")):
            self._run()
            self.assertEqual(len(self.codex.calls), 1, "提醒判定出错，排队的交接照常发出")
            errors = [event for event, _fields in self.records if event == "reminder_error"]
            self.assertEqual(errors, ["reminder_error"])
            self.assertIn(("reminder_error", {"error": "RuntimeError", "code": None, "consecutive": 1}), self.records)
            self.assertTrue(self.dispatcher.has_live_work(), "退避期间继续驻留，到时重试")
            self._run()
            self.assertEqual(len([event for event, _ in self.records if event == "reminder_error"]), 1, "退避期内不每秒重试")
            self.now += REMINDER_RETRY_SECONDS
            self._run()
            self.assertEqual(len([event for event, _ in self.records if event == "reminder_error"]), 2)

    def test_liveness_check_survives_scan_errors_and_gives_up_after_repeated_failures(self) -> None:
        task_id = self._task()
        self.queue_state = Consumption.LEFT_QUEUE
        self._run()
        self._report(task_id)
        self._run()
        self.now += 120  # 回执写入后的观察窗口已过：驻留只可能来自等提醒
        with patch("agentstatus_bridge.dispatch.pending_reminder", side_effect=RuntimeError("boom")):
            self.assertEqual(REMINDER_MAX_SCAN_ERRORS, 10)
            for round_ in range(1, 11):
                if round_ > 1:
                    self.now += REMINDER_RETRY_SECONDS
                alive = self.dispatcher.has_live_work()  # 暂停到期那一轮直接扫描：不能抛出（Opus 复审 P3-2）
                self.assertEqual(alive, round_ < 10, f"第 {round_} 次")
                if round_ == 1:
                    # 出错后进入暂停：同一时刻再问不重扫、不再记日志，照常驻留（Opus 复审 P3-B）
                    logged = len([event for event, _ in self.records if event == "reminder_error"])
                    self.assertTrue(self.dispatcher.has_live_work())
                    self.assertEqual(len([event for event, _ in self.records if event == "reminder_error"]), logged)
            self.assertFalse(self.dispatcher.has_live_work(), "持续出错后即使在暂停期内也不再为提醒驻留，worker 可以空闲退出")
            self.now += REMINDER_RETRY_SECONDS
            self.assertFalse(self.dispatcher.has_live_work())
        self._run()  # 驻留期间 run_once 仍每 60 秒重试扫描；整轮成功后清零
        self.assertTrue(self.dispatcher.has_live_work(), "扫描恢复正常后照常驻留")
        self.assertEqual(self.dispatcher._reminder_scan_errors, 0)  # pyright: ignore[reportPrivateUsage]

    def test_persistent_queueing_bug_still_reaches_the_error_cap(self) -> None:
        task_id = self._task()
        self.queue_state = Consumption.LEFT_QUEUE
        self._run()
        self._report(task_id)
        self._run()
        self.now += REMIND_AFTER_SECONDS
        # 扫描正常、排队阶段持续抛出非账本错误（例如正文生成的代码缺陷）：计数不能每轮被扫描成功清零（Opus 复审 P3-A）
        with patch("agentstatus_bridge.dispatch.reminder_body", side_effect=RuntimeError("bug")):
            for _ in range(REMINDER_MAX_SCAN_ERRORS):
                self._run()
                self.now += REMINDER_RETRY_SECONDS
                # 真实 worker 每轮在 run_once 之后问一次是否驻留，暂停常在这里到期并先由它扫描：
                # 它扫描成功也不能清零，否则计数又回到 1（Opus 末轮 P3）
                self.dispatcher.has_live_work()
            self.assertEqual(self.dispatcher._reminder_scan_errors, REMINDER_MAX_SCAN_ERRORS)  # pyright: ignore[reportPrivateUsage]
            self.assertFalse(self.dispatcher.has_live_work(), "持续失败时 worker 可以空闲退出")
        self._run()
        self.assertEqual(len(self._reminders(task_id)), 1, "缺陷消失后下一轮照常提醒并清零")
        self.assertEqual(self.dispatcher._reminder_scan_errors, 0)  # pyright: ignore[reportPrivateUsage]

    def test_decline_arriving_after_the_reminder_is_queued_cancels_it(self) -> None:
        for declined in (Delivery.DENIED, Delivery.REFUSED):
            with self.subTest(declined=declined):
                task_id = self._task()
                self._run()
                self._report(task_id)
                self._run()
                notice = [item for item in self.store.attempts(task_id) if item.role is Role.NOTICE][0]
                self.lead_busy = True
                self.now += REMIND_AFTER_SECONDS
                self._run()
                [reminder] = self._reminders(task_id)
                # 提醒还在桥内排队时，原回执迟到的拒绝回执到了（Codex 复审 S01）
                self.store.transition_delivery(
                    notice.id, expected=(Delivery.WRITTEN,), new=declined, reason="claude_denied", now=self.now
                )
                self.lead_busy = False
                sent = len(self.claude.calls)
                self._run()
                cancelled = self.store.get_attempt(reminder.id)
                assert cancelled is not None
                self.assertEqual((cancelled.delivery, cancelled.delivery_reason), (Delivery.CANCELLED, "reminder_outdated"))
                self.assertEqual(len(self.claude.calls), sent)

    def test_claim_check_and_begin_send_hold_one_write_lock(self) -> None:
        task_id = self._task()
        self._run()
        self._report(task_id)
        self._run()
        self.lead_busy = True
        self.now += REMIND_AFTER_SECONDS
        self._run()
        [reminder] = self._reminders(task_id)
        self.lead_busy = False
        other = Store.open(Path(self._tmp.name) / "bridge")
        self.addCleanup(other.close)
        other._conn.execute("PRAGMA busy_timeout=100")  # pyright: ignore[reportPrivateUsage]
        real_check = Dispatcher._reminder_outdated  # pyright: ignore[reportPrivateUsage]
        seen: list[str] = []

        def check_then_race(dispatcher: Dispatcher, task, attempt, now):  # type: ignore[no-untyped-def]
            outdated = real_check(dispatcher, task, attempt, now)
            seen.append("check")
            if len(seen) == 2:  # 第 1 次是 dispatch 开头的早期核对，第 2 次在领取事务里
                try:
                    other.add_attempt(
                        task_id, role=Role.HANDOFF, target=IMPL, body="返工", refs=[], now=now,
                        sender=LEAD, sender_class="bypass",
                    )
                    seen.append("other_wrote")
                except StoreError as error:
                    seen.append(error.code)
            return outdated

        with patch.object(Dispatcher, "_reminder_outdated", autospec=True, side_effect=check_then_race):
            self._run()
        self.assertEqual(seen, ["check", "check", "store_busy"], "领取核对之后到 begin_send 之前，别的连接写不进来（Opus 复审 P3-3）")
        self.assertEqual(self.store.get_attempt(reminder.id).delivery, Delivery.WRITTEN)  # type: ignore[union-attr]

    def test_change_between_early_check_and_claim_cancels_the_reminder(self) -> None:
        task_id = self._task()
        self._run()
        self._report(task_id)
        self._run()
        self.lead_busy = True
        self.now += REMIND_AFTER_SECONDS
        self._run()
        [reminder] = self._reminders(task_id)
        self.lead_busy = False
        sent = len(self.claude.calls)
        real = procfs.read_process
        raced = False

        def racing(pid: int, *args: object, **kwargs: object):
            nonlocal raced
            if pid == os.getpid() and not raced:
                raced = True
                # 发送前的早期核对已通过、尚未领取：此刻另一进程提交了返工（Codex 实现审计 R01）
                self.store.add_attempt(
                    task_id, role=Role.HANDOFF, target=IMPL, body="返工", refs=[], now=self.now,
                    sender=LEAD, sender_class="bypass",
                )
            return real(pid, *args, **kwargs)  # type: ignore[arg-type]

        with patch("agentstatus_bridge.dispatch.procfs.read_process", side_effect=racing):
            self._run()
        self.assertTrue(raced)
        cancelled = self.store.get_attempt(reminder.id)
        assert cancelled is not None
        self.assertEqual((cancelled.delivery, cancelled.delivery_reason), (Delivery.CANCELLED, "reminder_outdated"))
        self.assertEqual(len(self.claude.calls), sent, "令牌已变的提醒不能被领取外调")

    def test_codex_origin_queued_notice_restarts_the_clock(self) -> None:
        task_id = self._task(origin=CODEX_LEAD)
        self._run()
        self.codex_lead_busy = True
        self._report(task_id)
        self.now += 40 * 60
        self._run()
        self.assertEqual(self._reminders(task_id), [])
        self.codex_lead_busy = False
        self._run()  # 回执进入发起方 Codex 队列
        notice = [item for item in self.store.attempts(task_id) if item.role is Role.NOTICE][0]
        self.assertEqual(notice.delivery, Delivery.QUEUED)
        arrived = self.now
        self._run()
        self.assertEqual(self._reminders(task_id), [], "Codex 回执刚入队不紧跟提醒")
        self.now = arrived + REMIND_AFTER_SECONDS
        self._run()
        [reminder] = self._reminders(task_id)
        self.assertEqual(reminder.target, CODEX_LEAD)

    def test_deadline_by_result_notice_state(self) -> None:
        task_id = self._task()
        self._deliver(work_attempts(self.store.attempts(task_id))[-1].id)
        self._report(task_id)
        task = self.store.get_task(task_id)
        assert task is not None
        attempts = self.store.attempts(task_id)
        notice = attempts[-1]
        attention = notice.created_at
        arrived = attention + 600
        base = [item for item in attempts if item.id != notice.id]
        cases: dict[Delivery, float | None] = {
            Delivery.WRITTEN: arrived,
            Delivery.QUEUED: arrived,
            Delivery.DELIVERED: arrived,
            Delivery.HELD: arrived,
            Delivery.UNKNOWN: arrived,
            Delivery.EXPIRED: attention,
            Delivery.FAILED: attention,
            Delivery.CANCELLED: attention,
            Delivery.DENIED: None,  # 发起方会话里有人拒绝了回执：不再催
            Delivery.REFUSED: None,
            Delivery.PENDING: None,
            Delivery.SENDING: None,
        }
        for delivery, start in cases.items():
            with self.subTest(delivery=delivery):
                pending = pending_reminder(task, [*base, replace(notice, delivery=delivery, delivery_at=arrived)])
                if start is None:
                    self.assertIsNone(pending)
                else:
                    assert pending is not None
                    self.assertEqual(pending.due_at, start + REMIND_AFTER_SECONDS)

    def test_decline_of_an_earlier_attention_does_not_silence_a_new_result(self) -> None:
        task_id = self._task()
        self._deliver(work_attempts(self.store.attempts(task_id))[-1].id)
        self._report(task_id)
        task = self.store.get_task(task_id)
        assert task is not None
        attempts = self.store.attempts(task_id)
        notice = attempts[-1]
        attention = notice.created_at
        # 上一次关注的回执被拒；返工后这一次关注照常提醒（Opus 复审 P3-3）
        earlier = replace(notice, id="c" * 32, seq=0, created_at=attention - 10, delivery=Delivery.DENIED, delivery_at=attention - 5)
        pending = pending_reminder(task, [earlier, *attempts[:-1], replace(notice, delivery=Delivery.DELIVERED, delivery_at=attention)])
        assert pending is not None
        self.assertEqual(pending.due_at, attention + REMIND_AFTER_SECONDS)

    def test_every_notice_of_this_attention_counts_toward_the_deadline(self) -> None:
        task_id = self._task()
        self._deliver(work_attempts(self.store.attempts(task_id))[-1].id)
        self._report(task_id)
        task = self.store.get_task(task_id)
        assert task is not None
        attempts = self.store.attempts(task_id)
        first = attempts[-1]
        attention = first.created_at
        # 两条回执：先创建的先送达，后创建的（创建早于前一条送达）更晚送达（Codex 实现审计 R02）
        early = replace(first, delivery=Delivery.DELIVERED, delivery_at=attention + 1000)
        late = replace(
            first, id="e" * 32, seq=first.seq + 1, created_at=attention + 600,
            delivery=Delivery.DELIVERED, delivery_at=attention + 1500,
        )
        older = replace(first, id="d" * 32, seq=0, created_at=attention - 5, delivery=Delivery.DELIVERED, delivery_at=attention + 9000)
        pending = pending_reminder(task, [older, *attempts[:-1], early, late])
        assert pending is not None
        self.assertEqual(pending.due_at, attention + 1500 + REMIND_AFTER_SECONDS)

    def test_retry_backoff_entries_are_dropped_once_expired(self) -> None:
        task_id = self._task()
        self._run()
        self._report(task_id)
        self._run()
        self.now += REMIND_AFTER_SECONDS
        with patch.object(self.store, "add_attempt", side_effect=StoreError("capacity_pending")):
            self._run()
        retry = self.dispatcher._reminder_retry_at  # pyright: ignore[reportPrivateUsage]
        self.assertEqual(len(retry), 1)
        self.store.update_task(task_id, now=self.now, event="closed", closed_at=self.now, close_reason="closed")
        self.now += REMINDER_RETRY_SECONDS
        self._run()
        self.assertEqual(self.dispatcher._reminder_retry_at, {}, "任务结束后旧令牌的退避条目不再留着")  # pyright: ignore[reportPrivateUsage]

    def test_unchanged_ledger_is_not_rescanned_every_second(self) -> None:
        task_id = self._task()
        self._run()
        self._report(task_id)
        self._run()
        self._run()  # 上一轮投递回执改了账本：这一轮按新修订号重算一次缓存
        with patch("agentstatus_bridge.dispatch.pending_reminder", wraps=pending_reminder) as spy:
            self._run()
            self._run()
            self.assertEqual(len(self.dispatcher.pending_reminders()), 1)
            self.assertEqual(spy.call_count, 0, "账本没变时用缓存，不重读全部尝试（Opus 审计 F3）")
            self.store.add_event(task_id, "peer_reply", now=self.now)
            self.assertEqual(len(self.dispatcher.pending_reminders()), 1)
            self.assertEqual(spy.call_count, 1, "账本一变就重算")

    def test_reminder_that_cannot_be_delivered_changes_nothing_else(self) -> None:
        task_id = self._task()
        self._run()
        self._report(task_id)
        self._run()
        token = self._summary_token(task_id)
        self.lead_online = False
        self.now += REMIND_AFTER_SECONDS
        self._run()
        self.now += TARGET_GONE_GRACE_SECONDS + 1
        self._run()
        [reminder] = self._reminders(task_id)
        self.assertEqual(self.store.get_attempt(reminder.id).delivery, Delivery.FAILED)  # type: ignore[union-attr]
        self.assertEqual(self._view(task_id).phase, Phase.AWAITING_ACCEPTANCE)
        self.assertEqual(self._summary_token(task_id), token)
        self.now += REMIND_AFTER_SECONDS * 4
        self._run()
        self.assertEqual(len(self._reminders(task_id)), 1)
        self.assertFalse(needs_worker(self.store, self.now))

    def test_store_failure_is_isolated_and_retried_later(self) -> None:
        task_id = self._task()
        self._run()
        self._report(task_id)
        self._run()
        self.now += REMIND_AFTER_SECONDS
        with patch.object(self.store, "add_attempt", side_effect=StoreError("capacity_pending")):
            self._run()  # 不能抛出：分发循环照常
        self.assertEqual(self._reminders(task_id), [])
        self.assertIn(("reminder_failed", {"task": short(task_id), "code": "capacity_pending"}), self.records)
        self.now += REMINDER_RETRY_SECONDS - 1
        self._run()
        self.assertEqual(self._reminders(task_id), [], "失败后不每秒重试")
        self.now += 1
        self._run()
        self.assertEqual(len(self._reminders(task_id)), 1)

    def test_queueing_rechecks_inside_the_transaction(self) -> None:
        task_id = self._task()
        self._run()
        self._report(task_id)
        self._run()
        self.now += REMIND_AFTER_SECONDS
        pending = self._pending(task_id)
        assert pending is not None
        queue = self.dispatcher._queue_reminder  # pyright: ignore[reportPrivateUsage]
        self.assertFalse(queue(task_id, "stale-token", self.now))
        # 判定与写入之间发起方已验收
        self.store.update_task(task_id, now=self.now, event="accepted", accepted_at=self.now)
        self.assertFalse(queue(task_id, pending.token, self.now))
        self.assertEqual(self._reminders(task_id), [])

    # ---- 判定矩阵 ----

    def test_needs_attention_reasons_are_reminded(self) -> None:
        for work, text, step in (
            (Work.BLOCKED, "对方报告受阻", f"{CMD} retry"),
            (Work.FAILED, "对方报告无法完成", f"{CMD} retry"),
        ):
            with self.subTest(work=work):
                task_id = self._task()
                self._deliver(work_attempts(self.store.attempts(task_id))[-1].id)
                self._report(task_id, work)
                self._run()
                self.now += REMIND_AFTER_SECONDS
                self._run()
                [reminder] = self._reminders(task_id)
                self.assertIn(text, reminder.body)
                self.assertIn(step, reminder.body)

    def test_delivery_failure_is_reminded_from_the_failure_time(self) -> None:
        task_id = self._task()
        attempt = work_attempts(self.store.attempts(task_id))[-1]
        self.store.transition_delivery(
            attempt.id, expected=(Delivery.PENDING,), new=Delivery.FAILED, reason="target_gone", now=self.now
        )
        pending = self._pending(task_id)
        assert pending is not None
        self.assertEqual(pending.due_at, self.now + REMIND_AFTER_SECONDS)
        self.now += REMIND_AFTER_SECONDS
        self._run()
        [reminder] = self._reminders(task_id)
        self.assertIn("未送达", reminder.body)

    def test_review_changes_are_reminded_but_self_review_is_not(self) -> None:
        reviewer = ref(Provider.CLAUDE, "review-session", pid=2000, pane="%2", label="review")
        for who, verdict, expected in (
            (reviewer, Verdict.CHANGES, "复核要求修改"),
            (LEAD, Verdict.APPROVED, None),
        ):
            with self.subTest(reviewer=who.label, verdict=verdict):
                task_id = self._task(flow=Flow.REVIEW, reviewer=who)
                self._deliver(work_attempts(self.store.attempts(task_id))[-1].id)
                self._report(task_id, notice=False)
                review = self.store.add_attempt(
                    task_id, role=Role.REVIEW, target=who, body="请复核", refs=[], now=self.now,
                    sender=LEAD, sender_class="bypass",
                )
                self._deliver(review.id)
                self.store.set_work(review.id, work=Work.RESULT, result={"note": "结论"}, now=self.now, event="approve")
                self.store.update_task(task_id, now=self.now, event="verdict", verdict=verdict.value)
                pending = self._pending(task_id)
                if expected is None:
                    self.assertIsNone(pending, "发起方自己复核通过时已经知道")
                    continue
                assert pending is not None
                self.now = pending.due_at
                self._run()
                [reminder] = self._reminders(task_id)
                self.assertIn(expected, reminder.body)
                self.assertIn(f"{CMD} retry {short(task_id)}", reminder.body)

    def test_states_that_are_never_reminded(self) -> None:
        running = self._task()
        self._deliver(work_attempts(self.store.attempts(running))[-1].id)
        self._report(running, Work.ACKNOWLEDGED, notice=False)
        queued = self._task()
        cancelled = self._task()
        attempt = work_attempts(self.store.attempts(cancelled))[-1]
        self.store.transition_delivery(
            attempt.id, expected=(Delivery.PENDING,), new=Delivery.CANCELLED, reason="cancelled", now=self.now
        )
        cases: dict[str, str] = {"running": running, "queued": queued, "user_cancelled": cancelled}
        for name, kwargs in (
            ("user_origin", {"origin": None}),
            ("no_notify", {"options": {"notify": False}}),
            ("accepted", {}),
            ("closed", {}),
            ("paused", {}),
        ):
            task_id = self._task(**kwargs)  # type: ignore[arg-type]
            self._deliver(work_attempts(self.store.attempts(task_id))[-1].id)
            # 不排回执：排队中的回执本身就会挡住提醒，会掩盖这里要验证的条件
            self._report(task_id, notice=False)
            if name == "accepted":
                self.store.update_task(task_id, now=self.now, event="accepted", accepted_at=self.now)
            elif name == "closed":
                self.store.update_task(task_id, now=self.now, event="closed", closed_at=self.now, close_reason="closed")
            elif name == "paused":
                self.store.update_task(task_id, now=self.now, event="paused", control="paused")
            cases[name] = task_id
        control = self._task()
        self._deliver(work_attempts(self.store.attempts(control))[-1].id)
        self._report(control, notice=False)
        self.assertIsNotNone(self._pending(control), "对照：同样写法、没有排除条件时应当待提醒")
        for name, task_id in cases.items():
            with self.subTest(case=name):
                task = self.store.get_task(task_id)
                assert task is not None
                self.assertIsNone(pending_reminder(task, self.store.attempts(task_id)))

    def test_task_without_work_attempt_has_no_reminder_token(self) -> None:
        # no_attempt 的关注时刻取任务 updated_at，排队提醒会改它：不能给它令牌，否则每 30 分钟重复提醒或误判排队提醒过期
        task_id = self._task()
        task = self.store.get_task(task_id)
        assert task is not None
        self.assertEqual(describe(task, []).reason, "no_attempt")
        self.assertIsNone(reminder_token(task, []))
        self.assertIsNone(pending_reminder(task, []))

    def test_task_at_attempt_capacity_is_not_reminded(self) -> None:
        task_id = self._task()
        self._deliver(work_attempts(self.store.attempts(task_id))[-1].id)
        self._report(task_id, notice=False)
        task = self.store.get_task(task_id)
        assert task is not None
        attempts = self.store.attempts(task_id)
        self.assertIsNotNone(pending_reminder(task, attempts))
        filler = replace(
            attempts[0], id="f" * 32, seq=MAX_ATTEMPTS_PER_TASK, role=Role.NOTICE, target=LEAD,
            delivery=Delivery.FAILED, created_at=0.0,
        )
        self.assertIsNone(pending_reminder(task, [*attempts, filler]), "排不进提醒时不能让 worker 一直驻留")


if __name__ == "__main__":
    unittest.main()
