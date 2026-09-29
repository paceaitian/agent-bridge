"""协作桥标签与下一步：结构化动作穷举覆盖 describe() 全部分支，CLI 文案保持不变。"""

from __future__ import annotations

from dataclasses import replace
from itertools import product
import unittest

from agentstatus_bridge import cli, labels, views
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

    def test_every_report_kind_has_an_event_label(self) -> None:
        # cmd_report 的打印路径也是直接下标：ReportKind 是闭合枚举，漏一个成员就该是 KeyError
        # （EVENT_LABELS 还含账本里的其他事件名，所以是包含关系而不是相等）
        self.assertLessEqual({kind.value for kind in ReportKind}, set(labels.EVENT_LABELS))

    def test_cli_keeps_label_exports(self) -> None:
        # 既有测试与审计脚本经 cli 引用这些名称
        for name in ("CONSUMPTION_LABELS", "DELIVERY_LABELS", "WORK_LABELS", "EVENT_LABELS", "reason_text"):
            self.assertIs(getattr(cli, name), getattr(labels, name))


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
        # 清理范围是 6 条，不是 3 条：DESIGN 与提交信息原来都记错了（独立 Opus 审计 P2-1）
        self.assertEqual(len(carriers), 6, carriers)
        for code in labels.REASON_TEXTS:
            with self.subTest(code=code):
                self.assertNotIn(labels.PLACEHOLDER, labels.reason_text(code, command="testcmd"))
                self.assertNotIn(labels.PLACEHOLDER, labels.reason_text(code))


if __name__ == "__main__":
    unittest.main()
