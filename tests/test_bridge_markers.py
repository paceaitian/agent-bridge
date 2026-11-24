"""§104 判别键（DESIGN §104.9 三）：沉默提醒、催促、定时提醒、回执种类与延迟投递时刻的只读属性。"""

from __future__ import annotations

import unittest

import bridge_support  # noqa: F401  导入即隔离宿主会话环境
from agentstatus_bridge.model import (
    ASK_OPTION,
    DEFER_OPTION,
    MAX_DEFER_SECONDS,
    NUDGE_KIND,
    RECEIPT_KINDS,
    RECEIPT_OF_OPTION,
    REMIND_OPTION,
    REMINDER_OPTION,
    Attempt,
    Role,
    defer_pending,
    defer_time,
)
from bridge_support import ref


def _attempt(role: Role = Role.NOTICE, **options: object) -> Attempt:
    return Attempt(id="a" * 32, task_id="t" * 32, seq=2, role=role, target=ref(), message_id="m" * 32,
                   created_at=1.0, body="正文", options=dict(options))


class MarkerTests(unittest.TestCase):
    def test_names_are_the_agreed_wire_free_keys(self) -> None:
        self.assertEqual((NUDGE_KIND, REMIND_OPTION, DEFER_OPTION, RECEIPT_OF_OPTION, ASK_OPTION),
                         ("nudge", "remind", "deferUntil", "receiptOf", "ask"))
        self.assertEqual(RECEIPT_KINDS, {"result", "approve", "changes", "blocked", "failed", "ask"})

    def test_silent_reminder_is_a_notice_whose_token_has_the_silent_mark(self) -> None:
        self.assertTrue(_attempt(**{REMINDER_OPTION: "x:silent:12.000000"}).is_silent_reminder)
        self.assertFalse(_attempt(**{REMINDER_OPTION: "x:result_ready:12.000000"}).is_silent_reminder)
        self.assertFalse(_attempt(**{REMINDER_OPTION: 3}).is_silent_reminder)
        self.assertFalse(_attempt(Role.HANDOFF, **{REMINDER_OPTION: "x:silent:1"}).is_silent_reminder)

    def test_nudge_and_remind(self) -> None:
        self.assertTrue(_attempt(noticeKind="nudge").is_nudge)
        self.assertFalse(_attempt(Role.HANDOFF, noticeKind="nudge").is_nudge)
        self.assertTrue(_attempt(noticeKind="fyi", remind=True).is_remind)
        self.assertFalse(_attempt(noticeKind="fyi").is_remind)
        self.assertFalse(_attempt(noticeKind="fyi", remind="true").is_remind)
        self.assertFalse(_attempt(noticeKind="note", remind=True).is_remind)

    def test_receipt_of_only_returns_closed_set_values(self) -> None:
        for kind in RECEIPT_KINDS:
            self.assertEqual(_attempt(receiptOf=kind).receipt_of, kind)
        for value in ("progress", "", None, 1, True):
            self.assertIsNone(_attempt(receiptOf=value).receipt_of)
        self.assertIsNone(_attempt().receipt_of)
        self.assertIsNone(_attempt(Role.HANDOFF, receiptOf="result").receipt_of)

    def test_defer_until_shapes(self) -> None:
        self.assertEqual(_attempt(deferUntil=100).defer_until, 100.0)
        self.assertEqual(_attempt(deferUntil=100.5).defer_until, 100.5)
        for value in (True, "100", float("nan"), float("inf"), None):
            self.assertIsNone(_attempt(deferUntil=value).defer_until)
        self.assertIsNone(defer_time({}))

    def test_defer_pending_is_bounded_by_the_24_hour_limit_not_the_retry_delay(self) -> None:
        now = 1_000_000.0
        self.assertTrue(defer_pending({DEFER_OPTION: now + 3600}, now))
        self.assertTrue(defer_pending({DEFER_OPTION: now + MAX_DEFER_SECONDS}, now))
        self.assertFalse(defer_pending({DEFER_OPTION: now}, now))
        self.assertFalse(defer_pending({DEFER_OPTION: now - 1}, now))
        # 本机时钟回拨：到期时刻远超上限按已到期，不会永久扣住
        self.assertFalse(defer_pending({DEFER_OPTION: now + MAX_DEFER_SECONDS + 3600}, now))
        self.assertFalse(defer_pending({}, now))


if __name__ == "__main__":
    unittest.main()
