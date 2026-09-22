"""协作桥派生提示：“对方已停下但还没有汇报”“当前未发现对方会话”的判定条件与各类不提示的情形。"""

from __future__ import annotations

from dataclasses import replace
import unittest

from agentstatus_bridge.hints import STOPPED_GRACE_SECONDS, PaneState, stopped_without_report, target_session_missing
from agentstatus_bridge.model import Attempt, Consumption, Delivery, Provider, Role, Runtime, Work
from bridge_support import endpoint, ref


def attempt(**changes: object) -> Attempt:
    base = Attempt(
        id="a" * 32,
        task_id="b" * 32,
        seq=1,
        role=Role.HANDOFF,
        target=ref(Provider.CLAUDE, "claude-session"),
        message_id="c" * 32,
        created_at=90.0,
        body="x",
        delivery=Delivery.DELIVERED,
        delivery_at=100.0,
        work=Work.ACKNOWLEDGED,
        work_at=150.0,
    )
    return replace(base, **changes)  # type: ignore[arg-type]


class StoppedWithoutReportTests(unittest.TestCase):
    def test_turn_ended_after_last_report_and_grace_elapsed(self) -> None:
        now = 200.0 + STOPPED_GRACE_SECONDS + 1
        live = endpoint(ref(Provider.CLAUDE, "claude-session"))
        self.assertEqual(stopped_without_report(attempt(), live, PaneState(Runtime.IDLE, 200.0, True), now=now), 200.0)
        codex = attempt(target=ref(), delivery=Delivery.QUEUED, consumption=Consumption.LEFT_QUEUE, work=Work.AWAITING_ACK, work_at=None)
        self.assertEqual(stopped_without_report(codex, endpoint(ref()), PaneState(Runtime.IDLE, 200.0, True), now=now), 200.0)

    def test_acknowledged_codex_is_not_hidden_by_old_queue_sample(self) -> None:
        now = 200.0 + STOPPED_GRACE_SECONDS + 1
        acknowledged = attempt(
            target=ref(),
            delivery=Delivery.DELIVERED,
            consumption=Consumption.STILL_QUEUED,
            work=Work.ACKNOWLEDGED,
            work_at=120.0,
        )
        self.assertEqual(
            stopped_without_report(acknowledged, endpoint(ref()), PaneState(Runtime.IDLE, 200.0, True), now=now), 200.0
        )

    def test_cases_that_must_not_be_flagged(self) -> None:
        now = 200.0 + STOPPED_GRACE_SECONDS + 1
        live = endpoint(ref(Provider.CLAUDE, "claude-session"))
        idle = PaneState(Runtime.IDLE, 200.0, True)
        cases = {
            "grace_not_elapsed": (attempt(), live, idle, 230.0),
            "turn_ended_before_last_report": (attempt(), live, PaneState(Runtime.IDLE, 140.0, True), now),
            "target_busy_again": (attempt(), endpoint(ref(Provider.CLAUDE, "claude-session"), runtime=Runtime.BUSY), idle, now),
            "pane_asking_user": (attempt(), live, PaneState(Runtime.WAITING, 200.0, True), now),
            # 本轮结束后后台工作还在跑：对方能收件，但不能说它「已停下」（DESIGN §45.37）
            "target_in_background": (
                attempt(),
                endpoint(ref(Provider.CLAUDE, "claude-session"), runtime=Runtime.BACKGROUND),
                idle,
                now,
            ),
            "pane_in_background": (attempt(), live, PaneState(Runtime.BACKGROUND, 200.0, True), now),
            "stale_snapshot": (attempt(), live, PaneState(Runtime.IDLE, 200.0, False), now),
            "no_turn_end_seen": (attempt(), live, PaneState(Runtime.IDLE, None, True), now),
            "no_pane": (attempt(), live, None, now),
            "target_not_found": (attempt(), None, idle, now),
            "result_submitted": (attempt(work=Work.RESULT), live, idle, now),
            "blocked_reported": (attempt(work=Work.BLOCKED), live, idle, now),
            "held_not_delivered": (attempt(delivery=Delivery.HELD), live, idle, now),
            "codex_still_queued": (
                attempt(target=ref(), delivery=Delivery.QUEUED, consumption=Consumption.STILL_QUEUED, work=Work.AWAITING_ACK, work_at=None),
                endpoint(ref()),
                idle,
                now,
            ),
            "codex_queue_state_not_observed": (
                attempt(target=ref(), delivery=Delivery.QUEUED, consumption=Consumption.NOT_OBSERVED, work=Work.AWAITING_ACK, work_at=None),
                endpoint(ref()),
                idle,
                now,
            ),
            "codex_queue_state_unknown": (
                attempt(target=ref(), delivery=Delivery.QUEUED, consumption=Consumption.UNKNOWN, work=Work.AWAITING_ACK, work_at=None),
                endpoint(ref()),
                idle,
                now,
            ),
            "notice": (attempt(role=Role.NOTICE, work=Work.NONE), live, idle, now),
        }
        for name, (item, target, pane, when) in cases.items():
            with self.subTest(case=name):
                self.assertIsNone(stopped_without_report(item, target, pane, now=when))


class TargetSessionMissingTests(unittest.TestCase):
    """与 worker 的 target_gone 同一标准：发现到端点却找不到对方任何一代（DESIGN §45.32）。"""

    def test_delivered_open_work_with_no_generation_is_missing(self) -> None:
        self.assertTrue(target_session_missing(attempt(), None, None, discovered=True))
        queued = attempt(target=ref(), delivery=Delivery.QUEUED, work=Work.AWAITING_ACK, work_at=None)
        self.assertTrue(target_session_missing(queued, None, None, discovered=True))
        self.assertTrue(target_session_missing(attempt(delivery=Delivery.WRITTEN, work=Work.IN_PROGRESS), None, None, discovered=True))

    def test_cases_that_must_not_be_flagged(self) -> None:
        live = endpoint(ref(Provider.CLAUDE, "claude-session"))
        cases = {
            "target_still_running": (attempt(), live, None, True),
            "discovery_empty": (attempt(), None, None, False),
            "generation_ambiguous": (attempt(), None, "generation_ambiguous", True),
            "no_attempt": (None, None, None, True),
            "notice": (attempt(role=Role.NOTICE, work=Work.NONE), None, None, True),
            "result_submitted": (attempt(work=Work.RESULT), None, None, True),
            "failed_reported": (attempt(work=Work.FAILED), None, None, True),
            "held_for_approval": (attempt(delivery=Delivery.HELD), None, None, True),
            "not_sent_yet": (attempt(delivery=Delivery.PENDING, delivery_at=None), None, None, True),
        }
        for name, (item, target, problem, discovered) in cases.items():
            with self.subTest(case=name):
                self.assertFalse(target_session_missing(item, target, problem, discovered=discovered))


if __name__ == "__main__":
    unittest.main()
