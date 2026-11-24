"""§104.2 / §104.9 三：第二行随真实投递送出——本机 worker 与跨设备 B 侧（POSIX 夹具）。

逐类判别、括号、页脚等纯函数断言在可移植模块 test_bridge_action_line_portable（Windows CI 选择集也跑）。
"""

from __future__ import annotations

import unittest

import bridge_support  # noqa: F401  导入即隔离宿主会话环境
import test_bridge_dispatch as dispatch_base  # 只借夹具方法，不把 DispatchTests 导入本模块命名空间
import test_bridge_federation_cli as fed_base

from agentstatus_bridge import envelope
from agentstatus_bridge.labels import next_step
from agentstatus_bridge.model import (
    ASK_OPTION,
    REMINDER_OPTION,
    Attempt,
    Delivery,
    EndpointRef,
    Flow,
    Provider,
    Role,
    Task,
    Work,
    describe,
)
from agentstatus_bridge.reminders import PendingReminder, reminder_body
from agentstatus_bridge.store import attempt_limit


class LocalDeliveryCarriesTheSecondLine(unittest.TestCase):
    setUp = dispatch_base.DispatchTests.setUp
    tearDown = dispatch_base.DispatchTests.tearDown
    _task = dispatch_base.DispatchTests._task
    _run = dispatch_base.DispatchTests._run

    def test_worker_delivers_header_then_second_line(self) -> None:
        target = bridge_support.ref(Provider.CODEX, "019a0000-2222-7222-8222-222222222222", pid=2100, label="impl")
        self.endpoints = [bridge_support.endpoint(target)]
        task, first = self._task(target)
        self._run()
        _target, text, _context = self.codex.calls[-1]
        lines = text.split("\n")
        self.assertTrue(lines[0].startswith(f"[AgentStatus 协作] task={task.id} attempt=1 msg={first.message_id}"))
        self.assertEqual(lines[1], envelope.ACTION_HANDOFF)
        self.assertEqual(lines[2], "任务：实现")


class CapacityWordingContract(unittest.TestCase):
    """§104.11 一并修：第二行按正文最后一条下一步里的 envelope.CAPACITY_REACHED 判容量满；这里钉住写方真的写出这个措辞。

    写方是 reminders 的沉默提醒正文、labels.next_step（回执、30 分钟提醒、告知都用它）与 review_capacity_hint；
    措辞改了这里会先红。
    """

    TARGET = EndpointRef(provider=Provider.CODEX, native_id="impl-thread", pid=1, start_ticks="1")
    TASK = Task(id="1" * 32, created_at=1.0, updated_at=1.0, title="T", flow=Flow.HANDOFF,
                origin=EndpointRef(provider=Provider.CLAUDE, native_id="lead", pid=2, start_ticks="2"), reviewer=None)

    def attempts(self, last_seq: int, *, ask: bool) -> list[Attempt]:
        work = Attempt(id="a" * 32, task_id=self.TASK.id, seq=1, role=Role.HANDOFF, target=self.TARGET,
                       message_id="b" * 32, created_at=1.0, body="实现", delivery=Delivery.QUEUED, delivery_at=2.0,
                       work=Work.IN_PROGRESS, work_at=3.0, options={ASK_OPTION: {"at": 3.0, "note": "问题"}} if ask else {})
        filler = [Attempt(id=f"{seq:032x}", task_id=self.TASK.id, seq=seq, role=Role.NOTICE, target=self.TARGET,
                          message_id=f"{seq + 100:032x}", created_at=1.0, body="x", delivery=Delivery.QUEUED)
                  for seq in range(2, last_seq + 1)]
        return [work, *filler]

    def notice(self, body: str, **options: object) -> Attempt:
        return Attempt(id="c" * 32, task_id=self.TASK.id, seq=60, role=Role.NOTICE, target=self.TARGET,
                       message_id="d" * 32, created_at=1.0, body=body, options=dict(options))

    def test_silent_reminder_body_and_second_line_agree_at_capacity(self) -> None:
        token = f"{'a' * 32}:silent:3.000000"
        for last, expected in ((attempt_limit(Role.HANDOFF) - 1, envelope.ACTION_CAPACITY),
                               (10, envelope.ACTION_SILENT + envelope.NEXT_STEP_SUFFIX)):
            with self.subTest(last=last):
                attempts = self.attempts(last, ask=False)
                view = describe(self.TASK, attempts)
                silent = PendingReminder(token=token, due_at=1903.0, view=view, kind="silent", anchor=3.0)
                body = reminder_body(self.TASK, attempts, view, command="ab", silent=silent, state="空闲", now=1903.0)
                self.assertEqual(envelope.CAPACITY_REACHED in body.splitlines()[-1], expected == envelope.ACTION_CAPACITY)
                item = self.notice(body, **{REMINDER_OPTION: token})
                self.assertEqual(envelope.action_line(item), expected)

    def test_question_next_step_and_second_line_agree_at_capacity(self) -> None:
        token = f"{'a' * 32}:question_asked:3.000000"
        for last, expected in ((attempt_limit(Role.HANDOFF) - 1, envelope.ACTION_CAPACITY),
                               (10, envelope.ACTION_QUESTION + envelope.NEXT_STEP_SUFFIX)):
            with self.subTest(last=last):
                attempts = self.attempts(last, ask=True)
                self.assertEqual(describe(self.TASK, attempts).reason, "question_asked")
                step = next_step(self.TASK, attempts, ref="11111111", command="ab", reserved=1)
                assert step is not None
                self.assertEqual(envelope.CAPACITY_REACHED in step.text, expected == envelope.ACTION_CAPACITY)
                # 提问回执（receiptOf=ask）与提问的 30 分钟提醒都在正文末尾写这条下一步
                receipt = self.notice(f"对方在等你回答（任务仍在进行）：问题\n下一步：{step.text}", receiptOf="ask")
                self.assertEqual(envelope.action_line(receipt), expected)
                body = reminder_body(self.TASK, attempts, describe(self.TASK, attempts), command="ab")
                self.assertEqual(envelope.action_line(self.notice(body, **{REMINDER_OPTION: token})), expected)

    def test_every_next_step_branch_at_capacity_carries_the_phrase(self) -> None:
        """B' 统一：任务处在哪个阶段，容量满时 next_step 都写出 CAPACITY_REACHED（复核降级提示同样）。"""
        from dataclasses import replace
        from agentstatus_bridge.labels import review_capacity_hint
        from agentstatus_bridge.model import Verdict
        last = attempt_limit(Role.HANDOFF) - 1
        base = self.attempts(last, ask=False)
        work = base[0]
        reviewed = replace(self.TASK, flow=Flow.REVIEW, verdict=Verdict.CHANGES)
        cases = {
            "result_submitted": (self.TASK, replace(work, work=Work.RESULT)),
            "blocked_reported": (self.TASK, replace(work, work=Work.BLOCKED)),
            "failure_reported": (self.TASK, replace(work, work=Work.FAILED)),
            "delivery_failed": (self.TASK, replace(work, delivery=Delivery.FAILED, work=Work.AWAITING_ACK)),
            "changes_requested": (reviewed, replace(work, role=Role.REVIEW, work=Work.RESULT)),
        }
        for name, (task, current) in cases.items():
            with self.subTest(stage=name):
                attempts = [current, *base[1:]]
                step = next_step(task, attempts, ref="11111111", command="ab", reserved=1)
                assert step is not None
                self.assertIn(envelope.CAPACITY_REACHED, step.text)
                item = self.notice(f"首行\n下一步：{step.text}", receiptOf="result")
                self.assertEqual(envelope.action_line(item), envelope.ACTION_CAPACITY)
        self.assertIn(envelope.CAPACITY_REACHED, review_capacity_hint("capacity_attempts"))
        self.assertNotIn(envelope.CAPACITY_REACHED, review_capacity_hint("capacity_pending"))


class FederatedDeliveryCarriesTheSecondLine(fed_base.FedCliCase):
    def test_b_renders_second_line_for_handoff_and_note(self) -> None:
        task_id = self.delivered_task()
        self.pump("win", "vm")  # A 收到投递证据后当前尝试才可补充
        code, _, err = self.run_on("vm", "note", task_id, "-m", "补一句", caller=fed_base.as_agent(fed_base.ORIGIN))
        self.assertEqual(code, 0, err)
        self.pump("vm", "win")
        calls = self.deliver_on_b().calls
        self.assertEqual(len(calls), 1)
        lines = calls[0][1].split("\n")
        self.assertTrue(lines[0].startswith(f"[AgentStatus 协作] task={task_id} attempt="))
        self.assertEqual(lines[1], envelope.ACTION_NOTE)

    def test_first_handoff_on_b_has_second_line(self) -> None:
        task_id = self.send()
        self.pump("vm", "win")
        [call] = self.deliver_on_b().calls
        lines = call[1].split("\n")
        self.assertTrue(lines[0].startswith(f"[AgentStatus 协作] task={task_id} attempt=1"))
        self.assertEqual(lines[1], envelope.ACTION_HANDOFF)
        self.assertIn("--ask --note", call[1])


if __name__ == "__main__":
    unittest.main()
