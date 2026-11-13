"""协作桥标签与下一步：结构化动作穷举覆盖 describe() 全部分支，CLI 文案保持不变。"""

from __future__ import annotations

from dataclasses import replace
from itertools import product
import unittest
from unittest.mock import patch

from agentstatus_bridge import cli, labels, views, store as store_module
from agentstatus_bridge.naming import DEFAULT_COMMAND as CMD
from agentstatus_bridge.ids import short
from agentstatus_bridge.labels import next_step
from agentstatus_bridge.model import (
    DELIVERY_NEEDS_ATTENTION,
    Attempt,
    Delivery,
    Flow,
    Phase,
    ReportKind,
    Role,
    Runtime,
    Task,
    Verdict,
    Work,
    describe,
)
from bridge_support import ref

ACTIONS = frozenset({
    "resume", "wait", "approve_at_target", "confirm_then_force_retry", "retry_or_close",
    "rework_or_close", "ask_reviewer_or_retry", "rework", "status_or_close", "accept",
})


def task(**changes: object) -> Task:
    base = Task(id="a" * 32, created_at=1.0, updated_at=2.0, title="x", flow=Flow.HANDOFF, origin=None, reviewer=None)
    return replace(base, **changes)  # type: ignore[arg-type]


def attempt(**changes: object) -> Attempt:
    base = Attempt(
        id="b" * 32, task_id="a" * 32, seq=1, role=Role.HANDOFF, target=ref(), message_id="c" * 32,
        created_at=1.0, body="x", delivery=Delivery.DELIVERED, delivery_at=3.0, work=Work.AWAITING_ACK,
    )
    return replace(base, **changes)  # type: ignore[arg-type]


class NextStepTests(unittest.TestCase):
    def test_every_open_state_has_a_known_action(self) -> None:
        # 穷举投递 × 工作 × 角色/流程 × 复核结论 × 暂停：未结束的任务一定有下一步，且动作码在已知集合内
        for delivery, work, role, flow, verdict, control in product(
            Delivery, Work, (Role.HANDOFF, Role.REVIEW), Flow, (None, *Verdict), ("active", "paused")
        ):
            item = task(flow=flow, verdict=verdict, control=control)
            attempts = [attempt(delivery=delivery, work=work, role=role)]
            view = describe(item, attempts)
            with self.subTest(delivery=delivery, work=work, role=role, flow=flow, verdict=verdict, control=control):
                step = next_step(item, attempts, ref=item.id)
                self.assertIsNotNone(step, view.reason)
                assert step is not None
                self.assertIn(step.action, ACTIONS)
                if step.command is not None:
                    self.assertTrue(step.command.startswith(f"{CMD} ") and item.id in step.command, step.command)
        for finished in (task(accepted_at=5.0), task(closed_at=5.0, close_reason="closed")):
            self.assertIn(describe(finished, [attempt()]).phase, {Phase.DONE, Phase.CLOSED})
            self.assertIsNone(next_step(finished, [attempt()], ref=finished.id))

    def test_reason_to_action_mapping(self) -> None:
        cases = {
            "paused": (task(control="paused"), [attempt(delivery=Delivery.PENDING)], "resume"),
            "waiting_for_target": (task(), [attempt(delivery=Delivery.PENDING)], "wait"),
            "cancelled_undelivered": (task(), [attempt(delivery=Delivery.CANCELLED)], "retry_or_close"),
            "sending": (task(), [attempt(delivery=Delivery.SENDING)], "wait"),
            "blocked_reported": (task(), [attempt(work=Work.BLOCKED)], "rework_or_close"),
            "failure_reported": (task(), [attempt(work=Work.FAILED)], "rework_or_close"),
            "result_ready": (task(), [attempt(work=Work.RESULT)], "accept"),
            "review_not_dispatched": (task(flow=Flow.REVIEW), [attempt(work=Work.RESULT)], "status_or_close"),
            "changes_requested": (
                task(flow=Flow.REVIEW, verdict=Verdict.CHANGES), [attempt(role=Role.REVIEW, work=Work.RESULT)], "rework"
            ),
            "review_approved": (
                task(flow=Flow.REVIEW, verdict=Verdict.APPROVED), [attempt(role=Role.REVIEW, work=Work.RESULT)], "accept"
            ),
            "review_verdict_missing": (
                task(flow=Flow.REVIEW), [attempt(role=Role.REVIEW, work=Work.RESULT)], "ask_reviewer_or_retry"
            ),
            "no_attempt": (task(), [], "status_or_close"),
        }
        for delivery in DELIVERY_NEEDS_ATTENTION:
            expected = {Delivery.HELD: "approve_at_target", Delivery.UNKNOWN: "confirm_then_force_retry"}.get(
                delivery, "retry_or_close"
            )
            cases[f"delivery_{delivery.value}"] = (task(), [attempt(delivery=delivery)], expected)
        for reason, (item, attempts, action) in cases.items():
            with self.subTest(reason=reason):
                self.assertEqual(describe(item, attempts).reason, reason)
                step = next_step(item, attempts, ref=item.id)
                assert step is not None
                self.assertEqual(step.action, action)
        held = next_step(task(), [attempt(delivery=Delivery.HELD)], ref="a" * 32)
        assert held is not None
        self.assertIsNone(held.command, "等待批准时不给出重发命令")
        accept = next_step(task(), [attempt(work=Work.RESULT)], ref="a" * 32)
        assert accept is not None
        self.assertEqual(accept.command, f"{CMD} accept {'a' * 32}")

    def test_cli_text_is_unchanged_by_refactor(self) -> None:
        # 拆分前 cli._next_step（§48 R6 起在 views）的原文逐字冻结（短 ID）
        tid = short("a" * 32)
        cases = [
            (task(control="paused"), [attempt(delivery=Delivery.PENDING)], f"{CMD} resume {tid} 继续发送"),
            (task(), [attempt(delivery=Delivery.PENDING)], f"等后台 worker 发送；不需要了可 {CMD} cancel {tid}"),
            (task(), [attempt(delivery=Delivery.HELD)], f"去对方会话里批准这条消息；过期后可 {CMD} retry"),
            (task(), [attempt(delivery=Delivery.UNKNOWN)], f"不会自动重发。确认对方没收到后可 {CMD} retry {tid} --force"),
            (task(), [attempt(delivery=Delivery.REFUSED)], f"未送达：{CMD} retry {tid}（可加 --to 改派）或 {CMD} close {tid}"),
            (task(), [attempt(work=Work.BLOCKED)], f"处理对方的问题后 {CMD} retry {tid} 返工，或 {CMD} close {tid}"),
            (task(flow=Flow.REVIEW), [attempt(role=Role.REVIEW, work=Work.RESULT)], f"让复核方补交结论，或 {CMD} retry {tid} 重新复核"),
            (
                task(flow=Flow.REVIEW, verdict=Verdict.CHANGES),
                [attempt(role=Role.REVIEW, work=Work.RESULT)],
                f"{CMD} retry {tid} 把复核意见交回实现方返工，或 {CMD} accept {tid} --force",
            ),
            (task(), [attempt(work=Work.RESULT)], f"{CMD} accept {tid} 验收；需要返工用 {CMD} retry {tid}"),
            # 复核通过后普通 retry 会被拒（需 --force 且只是重新复核），不再建议（Codex 设计复审 F04）
            (
                task(flow=Flow.REVIEW, verdict=Verdict.APPROVED),
                [attempt(role=Role.REVIEW, work=Work.RESULT)],
                f"{CMD} accept {tid} 验收；复核结论见 {CMD} status {tid}",
            ),
            (task(), [attempt(delivery=Delivery.WRITTEN)], f"已写入对方会话，等待对方汇报；{CMD} wait {tid} 可以一直等到结果"),
            (task(), [attempt()], f"等待对方汇报；{CMD} wait {tid} 可以一直等到结果"),
            (task(accepted_at=5.0), [attempt()], None),
        ]
        for item, attempts, expected in cases:
            with self.subTest(expected=expected):
                self.assertEqual(views._next_step(item, attempts), expected)

    def test_every_runtime_has_a_label(self) -> None:
        # 打印路径是直接下标（cli.peers / cli.send），漏一个成员就是 KeyError 而不是难看的文案
        self.assertEqual(set(labels.RUNTIME_LABELS), set(Runtime))

    def test_capacity_next_step_keeps_actions_but_removes_unavailable_retry(self) -> None:
        cases = [
            (task(), attempt(delivery=Delivery.HELD), 'approve_at_target'),
            (task(), attempt(delivery=Delivery.UNKNOWN), 'confirm_then_force_retry'),
            (task(), attempt(delivery=Delivery.FAILED), 'retry_or_close'),
            (task(), attempt(delivery=Delivery.CANCELLED), 'retry_or_close'),
            (task(), attempt(work=Work.BLOCKED), 'rework_or_close'),
            (task(), attempt(work=Work.FAILED), 'rework_or_close'),
            (task(flow=Flow.REVIEW), attempt(role=Role.REVIEW, work=Work.RESULT), 'ask_reviewer_or_retry'),
            (task(flow=Flow.REVIEW, verdict=Verdict.CHANGES), attempt(role=Role.REVIEW, work=Work.RESULT), 'rework'),
            (task(), attempt(work=Work.RESULT), 'accept'),
        ]
        for item, work, action in cases:
            for seq, reserved, limited in ((58, 1, False), (59, 0, False), (59, 1, True),
                                           (60, 0, True), (60, 1, True), (64, 0, True)):
                with self.subTest(action=action, seq=seq, reserved=reserved):
                    step = next_step(item, [replace(work, seq=seq)], ref='TASK', command='trial', reserved=reserved)
                    self.assertIsNotNone(step)
                    self.assertEqual(step.action, action)
                    if limited:
                        self.assertNotIn('retry', step.text)
                        self.assertNotIn('retry', step.command or '')
                        self.assertIn('trial close TASK 后 trial send 新任务', step.text)
                        expected = {'accept': 'trial accept TASK', 'approve_at_target': None}
                        self.assertEqual(step.command, expected.get(action, 'trial close TASK'))
                        if action == 'approve_at_target':
                            self.assertIn('批准这条消息；若已过期，', step.text)
                        elif action == 'confirm_then_force_retry':
                            self.assertIn('先确认对方没收到（也不会再汇报），再', step.text)
                        elif action == 'ask_reviewer_or_retry':
                            self.assertIn('让复核方补交结论，或 ', step.text)
                    else:
                        self.assertIn('retry', step.text)

    def test_review_capacity_hint_distinguishes_capacity_and_audience(self) -> None:
        for reporter in (False, True):
            pending = labels.review_capacity_hint('capacity_pending', reporter=reporter)
            attempts = labels.review_capacity_hint('capacity_attempts', reporter=reporter)
            self.assertIn('全局待投递容量已满', pending)
            self.assertNotIn('交接次数已达上限', pending)
            self.assertIn('交接次数已达上限', attempts)
            if reporter:
                self.assertIn('后续由发起方决定', pending)
                self.assertNotIn(f'请 {CMD} close', pending)
            else:
                self.assertIn(f'请 {CMD} close 后新开任务复核', pending)

    def test_notification_capacity_text_has_distinct_audience_without_retry_contradiction(self) -> None:
        for code in ('capacity_pending', 'capacity_attempts'):
            report = labels.notification_capacity_hint(code, reporter=True)
            status = labels.notification_capacity_hint(code)
            self.assertIn('不要重复汇报', report)
            self.assertIn('发起方需', report)
            self.assertNotIn('不要重复汇报', status)
            self.assertIn('对方汇报已提交', status)
            for text in (report, status):
                self.assertNotIn('稍后再试', text)
                if code == 'capacity_pending':
                    self.assertIn('全局待投递容量已满', text)
                    self.assertIn('队列腾空后', text)
                    self.assertIn('若本任务还有提醒名额', text)
                    self.assertIn('仍符合提醒条件', text)
                    self.assertNotRegex(text, r'\d')
                else:
                    self.assertIn('交接次数已达上限', text)
                    self.assertNotIn('30分钟', text)

    def test_reminder_limit_is_derived_from_notice_reserve(self) -> None:
        with patch.object(store_module, 'NOTICE_RESERVE', 5):
            self.assertEqual(store_module.attempt_limit(Role.HANDOFF), 59)
            self.assertEqual(store_module.attempt_limit(Role.NOTICE, {'reminderToken': 'fixture'}), 60)
            self.assertEqual(store_module.attempt_limit(Role.NOTICE), 64)

    def test_every_report_kind_has_an_event_label(self) -> None:
        # cmd_report 的打印路径也是直接下标：ReportKind 是闭合枚举，漏一个成员就该是 KeyError
        # （EVENT_LABELS 还含账本里的其他事件名，所以是包含关系而不是相等）
        self.assertLessEqual({kind.value for kind in ReportKind}, set(labels.EVENT_LABELS))

    def test_cli_keeps_label_exports(self) -> None:
        # 既有测试与审计脚本经 cli 引用这些名称
        for name in ("CONSUMPTION_LABELS", "DELIVERY_LABELS", "WORK_LABELS", "EVENT_LABELS", "reason_text"):
            self.assertIs(getattr(cli, name), getattr(labels, name))


class NativeTargetTextTests(unittest.TestCase):
    """§91 新增与改写的目标文案：三个新码有中文文案；通用文案不推荐别名、不推荐 pane。"""

    def test_new_codes_have_texts_and_no_alias_or_pane_advice(self) -> None:
        for code in ("target_provider_required", "target_id_invalid", "target_id_unverified"):
            with self.subTest(code=code):
                self.assertNotEqual(labels.reason_text(code), code)
        for code in ("target_names_unverified", "target_ambiguous", "target_generation_ambiguous"):
            with self.subTest(code=code):
                text = labels.reason_text(code, command="ab")
                self.assertNotIn("别名", text)
                self.assertNotIn("pane", text)
        self.assertIn("provider@id:<完整ID>", labels.reason_text("target_names_unverified"))
        self.assertIn("ab peers", labels.reason_text("target_id_unverified", command="ab"))


class ReasonTextCommandTests(unittest.TestCase):
    """原因文案里的 `{command}` 占位必须被换成实际入口名（DESIGN §45.36）。

    之前这一步零覆盖：把 `reason_text` 的替换整句删掉，全量 983 仍然全绿，而用户会看到
    字面量 `{command} peers`（独立 Opus 审计 P2-1）。
    """

    def test_placeholder_is_replaced_with_the_resolved_command(self) -> None:
        text = labels.reason_text("target_not_found", command="testcmd")
        self.assertIn("testcmd peers", text)
        self.assertNotIn(labels.PLACEHOLDER, text)

    def test_no_reason_text_ever_leaks_the_placeholder(self) -> None:
        carriers = [code for code, text in labels.REASON_TEXTS.items() if labels.PLACEHOLDER in text]
        # 清理范围是 6 条，不是 3 条：DESIGN 与提交信息原来都记错了（独立 Opus 审计 P2-1）；
        # §53.3.8 加了 3 条（标题缺 id 的目标文案、汇报与发起的未归属文案都指向 doctor）
        # §83 及审计 r1 按读者/原因分开的容量文案同样使用当前入口名。
        # §91 的 target_id_unverified 提示用当前入口名刷新 peers。
        # §93.1 的 mine_requires_session 提示改用当前入口名的不带 --mine 的 tasks。
        self.assertEqual(len(carriers), 17, carriers)
        for code in labels.REASON_TEXTS:
            with self.subTest(code=code):
                self.assertNotIn(labels.PLACEHOLDER, labels.reason_text(code, command="testcmd"))
                self.assertNotIn(labels.PLACEHOLDER, labels.reason_text(code))


if __name__ == "__main__":
    unittest.main()
