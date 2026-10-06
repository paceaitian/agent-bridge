"""结束回执（DESIGN §45.31）：一次性生成、接收者选择、容量、发送放行、失败隔离与摘要标记。"""

from __future__ import annotations

from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
import json
import os
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any
import unittest
from unittest.mock import patch

from agentstatus_bridge import cli, observer_dbus, summary
from agentstatus_bridge import store as store_module
from agentstatus_bridge.naming import DEFAULT_COMMAND as CMD
from agentstatus_bridge.closure import (
    ACCEPTED,
    CLOSED,
    MAX_REASON_CHARS,
    closure_body,
    closure_recipients,
    delivered_endpoint,
    queue_closures,
)
from agentstatus_bridge.dispatch import TARGET_GONE_GRACE_SECONDS, Dispatcher, needs_worker
from agentstatus_bridge.envelope import parse_header
from agentstatus_bridge.model import Attempt, Consumption, Delivery, EndpointRef, Flow, Provider, Role, Runtime, Task, Work
from agentstatus_bridge.store import Store, StoreError
from agentstatus_bridge.transports import DeliveryOutcome, codex_queue
from bridge_support import FakeProc, RecordingTransport, discovering, endpoint, ref
from test_bridge_cli import IMPL, LEAD, REVIEW, USER, as_agent

DAY = 86400.0


class ClosureCliTests(unittest.TestCase):
    """accept/close 命令：何时生成、发给谁、容量与事务。"""

    def setUp(self) -> None:
        self._tmp = TemporaryDirectory()
        self.state = Path(self._tmp.name) / "bridge"
        self.caller = USER
        self.worker_up = True
        patches = [
            # AgentStatus 快照在最底层替换为空（DESIGN §55.4）：查询命令照真实代码读一次、什么也读不到
            patch.object(observer_dbus, "_observer_rows", return_value=[]),
            patch.dict(os.environ, {"AB_STATE_DIR": str(self.state)}),
            patch.object(cli, "discover", side_effect=discovering(lambda: [IMPL, REVIEW, LEAD])),
            patch.object(cli, "identify_caller", side_effect=lambda _endpoints: self.caller),
            patch.object(cli, "ensure_worker", return_value=False),
            patch.object(cli, "worker_running", side_effect=lambda _root: self.worker_up),
            patch.object(cli, "_receiver_class", return_value="bypass"),
            # 决定者的权限类别如实沿用 permission_class 的结果：agent 会话记 prompting，终端用户记 bypass
            patch.object(cli, "permission_class", side_effect=lambda caller: "prompting" if caller.endpoint else "bypass"),
        ]
        for item in patches:
            item.start()
            self.addCleanup(item.stop)
        self.addCleanup(self._tmp.cleanup)

    # ---- 辅助 ----

    def run_cli(self, *argv: str) -> tuple[int, str, str]:
        out, err = StringIO(), StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            code = cli.main(list(argv))
        return code, out.getvalue(), err.getvalue()

    def send(self, *extra: str, to: str = "codex@impl") -> str:
        code, out, err = self.run_cli("send", "--to", to, "-m", "实现 X\n细节", "--no-wait", "--json", *extra)
        self.assertEqual(code, cli.EXIT_OK, err)
        return json.loads(out)["id"]

    def store(self) -> Store:
        return Store.open(self.state)

    def deliver(self, task_id: str, delivery: Delivery = Delivery.QUEUED, detail: dict[str, Any] | None = None) -> None:
        """把本任务最新一条排队消息标为已发出。"""
        with self.store() as store:
            attempt = [item for item in store.attempts(task_id) if item.delivery is Delivery.PENDING][-1]
            self.assertTrue(store.begin_send(attempt.id, now=1.0, pid=1, start_ticks="1"))
            store.finish_send(attempt.id, delivery=delivery, reason="test", provider_ref=None, detail=detail or {}, now=2.0)

    def attempts(self, task_id: str) -> list[Attempt]:
        with self.store() as store:
            return store.attempts(task_id)

    def closures(self, task_id: str) -> list[Attempt]:
        return [item for item in self.attempts(task_id) if item.is_closure]

    def task(self, task_id: str) -> Task:
        with self.store() as store:
            task = store.get_task(task_id)
        assert task is not None
        return task

    def events(self, task_id: str) -> list[dict[str, Any]]:
        with self.store() as store:
            return store.events(task_id, limit=100)

    def review_flow(self) -> str:
        """lead 发起、impl 实现、review 复核通过，等 lead 验收；lead 的结果回执仍在排队。"""
        self.caller = as_agent(LEAD)
        task_id = self.send("--review-by", "claude@review")
        self.deliver(task_id)
        self.caller = as_agent(IMPL)
        self.assertEqual(self.run_cli("report", task_id, "--result", "--note", "v1")[0], cli.EXIT_OK)
        self.deliver(task_id, Delivery.DELIVERED)
        self.caller = as_agent(REVIEW)
        self.assertEqual(self.run_cli("report", task_id, "--approve", "--note", "通过")[0], cli.EXIT_OK)
        self.caller = as_agent(LEAD)
        return task_id

    # ---- 一次性 ----

    def test_accept_notifies_implementer_and_reviewer_once_and_close_keeps_the_pending_receipts(self) -> None:
        task_id = self.review_flow()
        code, out, err = self.run_cli("accept", task_id)
        self.assertEqual(code, cli.EXIT_OK, err)
        # 括号里的说明也钉住：§45.42 取消忙时扣留后不能再写「对方空闲后发送」（Codex 复审 F02）
        self.assertIn("已排队结束回执 → codex@impl、claude@review（进对方原生队列，不需要汇报）", out)
        closures = self.closures(task_id)
        self.assertEqual(len(closures), 2)
        self.assertTrue(closures[0].target.same_session(IMPL.ref) and closures[1].target.same_session(REVIEW.ref))
        for item in closures:
            self.assertEqual((item.role, item.work, item.delivery), (Role.NOTICE, Work.NONE, Delivery.PENDING))
            self.assertEqual(item.options, {"noticeKind": "closure", "closure": "accepted", "allowShared": False})
            self.assertTrue(item.sender is not None and item.sender.same_session(LEAD.ref))
            self.assertEqual(item.sender_class, "prompting")
            self.assertEqual(
                item.body,
                "状态同步：任务「实现 X」已由 codex@lead 验收，协作结束。这不代表已部署或用户实机验收。"
                f"不需要 {CMD} report，也不用再给发起方发消息。",
            )
        # 发给发起方的普通结果回执还没发出：先被取消，不占容量
        notices = [item for item in self.attempts(task_id) if item.role is Role.NOTICE and not item.is_closure]
        self.assertEqual([(item.delivery, item.delivery_reason) for item in notices], [(Delivery.CANCELLED, "accepted")])
        created = [event for event in self.events(task_id) if event["kind"] == "closure_created"]
        self.assertEqual([event["attemptSeq"] for event in created], [item.seq for item in closures])

        code, _, err = self.run_cli("accept", task_id, "--force")
        self.assertEqual((code, "task_finished" in err), (cli.EXIT_REJECTED, True))
        # 已验收后补记关闭：不再生成第二份，也不取消还没发出的结束回执
        code, out, err = self.run_cli("close", task_id, "--reason", "收尾")
        self.assertEqual(code, cli.EXIT_OK, err)
        self.assertNotIn("结束回执", out)
        self.assertEqual([item.delivery for item in self.closures(task_id)], [Delivery.PENDING, Delivery.PENDING])
        self.assertEqual(len(self.attempts(task_id)), len(closures) + 3)
        self.assertEqual(self.task(task_id).close_reason, "收尾")
        code, _, err = self.run_cli("close", task_id)
        self.assertEqual((code, "task_finished" in err), (cli.EXIT_REJECTED, True))
        self.assertEqual(len(self.closures(task_id)), 2)

    def test_user_close_notifies_agent_participant_once_with_reason(self) -> None:
        task_id = self.send()
        self.deliver(task_id)
        code, out, err = self.run_cli("close", task_id, "--reason", "需求取消")
        self.assertEqual(code, cli.EXIT_OK, err)
        self.assertIn("已排队结束回执 → codex@impl", out)
        (closure,) = self.closures(task_id)
        self.assertEqual(closure.options["closure"], "closed")
        self.assertIsNone(closure.sender)
        self.assertEqual(closure.sender_class, "bypass")
        self.assertEqual(closure.body, f"状态同步：任务「实现 X」已由 用户 关闭（原因：需求取消）。不需要 {CMD} report，也不用再给发起方发消息。")
        for command in (("close", task_id), ("accept", task_id, "--force")):
            code, _, err = self.run_cli(*command)
            self.assertEqual((code, "task_finished" in err), (cli.EXIT_REJECTED, True))
        self.assertEqual(len(self.closures(task_id)), 1)

    def test_nobody_to_notify_when_nothing_may_have_arrived(self) -> None:
        pending = self.send()
        code, out, err = self.run_cli("accept", pending, "--force", "--json")
        self.assertEqual(code, cli.EXIT_OK, err)
        self.assertEqual(json.loads(out)["closure"], {"queued": [], "skipped": []})
        self.assertEqual([item.delivery for item in self.attempts(pending)], [Delivery.CANCELLED])
        for state in (Delivery.FAILED, Delivery.DENIED, Delivery.EXPIRED, Delivery.REFUSED):
            with self.subTest(state=state):
                task_id = self.send()
                self.deliver(task_id, state)
                code, out, err = self.run_cli("close", task_id)
                self.assertEqual(code, cli.EXIT_OK, err)
                self.assertNotIn("结束回执", out)
                self.assertEqual(self.closures(task_id), [])

    def test_only_the_latest_handoff_that_may_have_arrived_is_notified(self) -> None:
        # A（impl）已送达，改派给 B（lead）仍在排队：只通知 A，B 的那条随关闭取消
        task_id = self.send()
        self.deliver(task_id)
        self.assertEqual(self.run_cli("retry", task_id, "--to", "codex@lead", "--force")[0], cli.EXIT_OK)
        self.assertEqual(self.run_cli("close", task_id)[0], cli.EXIT_OK)
        (closure,) = self.closures(task_id)
        self.assertTrue(closure.target.same_session(IMPL.ref))
        self.assertEqual(self.attempts(task_id)[1].delivery, Delivery.CANCELLED)
        # 改派已送达：只通知最新的接收方，不广播更早的历史
        second = self.send()
        self.deliver(second)
        self.assertEqual(self.run_cli("retry", second, "--to", "codex@lead", "--force")[0], cli.EXIT_OK)
        self.deliver(second, Delivery.HELD)
        self.assertEqual(self.run_cli("close", second)[0], cli.EXIT_OK)
        (closure,) = self.closures(second)
        self.assertTrue(closure.target.same_session(LEAD.ref))

    def test_status_shows_closure_receipts(self) -> None:
        task_id = self.send()
        self.deliver(task_id)
        self.assertEqual(self.run_cli("close", task_id)[0], cli.EXIT_OK)
        code, out, _ = self.run_cli("status", task_id)
        self.assertEqual(code, cli.EXIT_OK)
        self.assertIn("#2 结束回执 → codex@impl：桥内排队", out)
        self.assertIn("排队结束回执", out)
        self.assertNotIn("通知发起方", out)
        code, out, _ = self.run_cli("status", task_id, "--json")
        attempts = json.loads(out)["attempts"]
        self.assertEqual([(item.get("kind"), item.get("closure")) for item in attempts], [(None, None), ("closure", "closed")])

    # ---- 容量与事务 ----

    def test_capacity_skips_reviewer_first_and_never_rolls_back_the_decision(self) -> None:
        cases = {"attempts": None, "pending": None, "none_left": None}
        for case in cases:
            with self.subTest(case=case):
                task_id = self.review_flow()
                top = max(item.seq for item in self.attempts(task_id))
                self.caller = USER
                others = self.send(to="codex@lead")  # 另一项任务占着一个全局排队名额
                self.caller = as_agent(LEAD)
                if case == "attempts":
                    limit = patch.object(store_module, "MAX_ATTEMPTS_PER_TASK", top + 1)
                else:
                    # 结果回执先被取消；全局只剩别的任务那一条排队：pending 留 1 个名额，none_left 一个不留
                    limit = patch.object(store_module, "MAX_PENDING_ATTEMPTS", 2 if case == "pending" else 1)
                with limit:
                    code, out, err = self.run_cli("accept", task_id, "--json")
                self.assertEqual(code, cli.EXIT_OK, err)
                document = json.loads(out)
                capacity = "attempts" if case == "attempts" else "pending"
                if case == "none_left":
                    self.assertEqual(document["closure"]["queued"], [])
                    skipped = [("handoff", "codex@impl", capacity), ("review", "claude@review", capacity)]
                else:
                    self.assertEqual([item["target"] for item in document["closure"]["queued"]], ["codex@impl"])
                    skipped = [("review", "claude@review", capacity)]
                self.assertEqual(
                    [(item["role"], item["target"], item["capacity"]) for item in document["closure"]["skipped"]], skipped
                )
                self.assertIsNotNone(self.task(task_id).accepted_at)
                events = [event["detail"] for event in self.events(task_id) if event["kind"] == "closure_skipped_capacity"]
                self.assertEqual([(item["role"], item["capacity"]) for item in events], [(role, cap) for role, _, cap in skipped])
                # 清掉本轮留下的排队消息（cancel 对已结束任务同样有效），下一轮从同样的全局排队数开始
                self.caller = USER
                for leftover in (others, task_id):
                    self.run_cli("cancel", leftover)

    def test_capacity_skip_is_reported_in_text_output(self) -> None:
        task_id = self.review_flow()
        with patch.object(store_module, "MAX_PENDING_ATTEMPTS", 1):
            code, out, err = self.run_cli("close", task_id)
        self.assertEqual(code, cli.EXIT_OK, err)
        self.assertIn("已排队结束回执 → codex@impl", out)
        self.assertIn("排队容量已满，未给 claude@review 排结束回执", out)

    def test_other_ledger_errors_roll_back_the_whole_decision(self) -> None:
        for command in (("accept", ), ("close", )):
            with self.subTest(command=command[0]):
                task_id = self.review_flow()
                before = [(item.id, item.delivery) for item in self.attempts(task_id)]
                with patch.object(Store, "add_attempt", side_effect=StoreError("store_write_failed")):
                    code, _, err = self.run_cli(command[0], task_id)
                self.assertEqual((code, "store_write_failed" in err), (cli.EXIT_STORE, True))
                task = self.task(task_id)
                self.assertEqual((task.accepted_at, task.closed_at), (None, None))
                # 已取消的结果回执随事务一起回滚
                self.assertEqual([(item.id, item.delivery) for item in self.attempts(task_id)], before)
                kinds = {event["kind"] for event in self.events(task_id)}
                self.assertFalse(kinds & {"accepted", "closed", "closure_created", "closure_skipped_capacity"})

    def test_a_racing_decision_committed_first_leaves_a_single_set_of_receipts(self) -> None:
        for command, racer in (("accept", "close"), ("close", "accept"), ("accept", "accept"), ("close", "close")):
            with self.subTest(command=command, racer=racer):
                task_id = self.review_flow()

                def race(caller: object) -> str:
                    # 预检查之后、写事务之前，另一个决定已经提交（含它自己的结束回执）
                    with self.store() as other:
                        current = other.get_task(task_id)
                        assert current is not None
                        with other.transaction():
                            queue_closures(
                                other, current, other.attempts(task_id), ACCEPTED if racer == "accept" else CLOSED,
                                now=5.0, decider="用户", reason=None, sender=None, sender_class="bypass",
                            )
                            fields: dict[str, object] = (
                                {"accepted_at": 5.0} if racer == "accept" else {"closed_at": 5.0, "close_reason": "closed"}
                            )
                            other.update_task(task_id, now=5.0, event=racer, **fields)
                    return "bypass"

                with patch.object(cli, "permission_class", side_effect=race):
                    code, _, err = self.run_cli(command, task_id)
                if command == "close" and racer == "accept":
                    # 已验收后补记关闭仍然允许，但不再生成
                    self.assertEqual(code, cli.EXIT_OK, err)
                else:
                    self.assertEqual((code, "task_finished" in err), (cli.EXIT_REJECTED, True))
                self.assertEqual(len(self.closures(task_id)), 2)

    # ---- worker ----

    def test_decision_revives_a_missing_worker_and_worker_errors_do_not_fail_it(self) -> None:
        task_id = self.send()
        self.deliver(task_id)
        self.worker_up = False
        cli.ensure_worker.reset_mock()  # type: ignore[attr-defined]
        self.assertEqual(self.run_cli("close", task_id)[0], cli.EXIT_OK)
        cli.ensure_worker.assert_called_once()  # type: ignore[attr-defined]
        self.worker_up = True
        second = self.send()
        self.deliver(second)
        self.worker_up = False
        with patch.object(cli, "ensure_worker", side_effect=OSError("spawn failed")):
            code, out, err = self.run_cli("close", second)
        self.assertEqual((code, err), (cli.EXIT_OK, ""))
        self.assertIn("已排队结束回执", out)
        self.assertEqual([item.delivery for item in self.closures(second)], [Delivery.PENDING])


class RecipientTests(unittest.TestCase):
    """接收者选择：先过滤可能已到达，再按角色取最新；实际投递端点整组绑定；去重与排除发起方。"""

    def setUp(self) -> None:
        self._tmp = TemporaryDirectory()
        self.store = Store.open(Path(self._tmp.name) / "bridge")
        self.addCleanup(self._tmp.cleanup)
        self.addCleanup(self.store.close)

    def task(self, target: EndpointRef, *, origin: EndpointRef | None = None) -> tuple[Task, Attempt]:
        return self.store.create_task(
            title="实现", flow=Flow.HANDOFF, origin=origin, origin_class=None, reviewer=None,
            target=target, body="请实现 X", refs=[], now=1.0,
        )

    def add(self, task: Task, role: Role, target: EndpointRef) -> Attempt:
        return self.store.add_attempt(
            task.id, role=role, target=target, body="x", refs=[], now=2.0, sender=None, sender_class=None
        )

    def mark(self, attempt: Attempt, delivery: Delivery, detail: dict[str, Any] | None = None) -> None:
        self.assertTrue(self.store.begin_send(attempt.id, now=3.0, pid=1, start_ticks="1"))
        self.store.finish_send(attempt.id, delivery=delivery, reason="test", provider_ref=None, detail=detail or {}, now=4.0)

    def recipients(self, task: Task) -> list[tuple[str, int]]:
        current = self.store.get_task(task.id)
        assert current is not None
        return [(item.target.native_id, item.source.seq) for item in closure_recipients(current, self.store.attempts(task.id))]

    def test_states_that_may_have_arrived(self) -> None:
        arrived = {Delivery.WRITTEN, Delivery.QUEUED, Delivery.DELIVERED, Delivery.HELD, Delivery.UNKNOWN}
        for state in (*arrived, Delivery.FAILED, Delivery.DENIED, Delivery.EXPIRED, Delivery.REFUSED):
            with self.subTest(state=state):
                task, attempt = self.task(ref(native=f"t-{state.value}"))
                self.mark(attempt, state)
                self.assertEqual(self.recipients(task), [(f"t-{state.value}", 1)] if state in arrived else [])
        task, _attempt = self.task(ref(native="pending"))
        self.assertEqual(self.recipients(task), [])

    def test_filter_before_taking_the_latest_per_role(self) -> None:
        task, first = self.task(ref(native="a"))
        self.mark(first, Delivery.QUEUED)
        self.add(task, Role.HANDOFF, ref(native="b"))  # 最新交接还在排队
        review_old = self.add(task, Role.REVIEW, ref(Provider.CLAUDE, "r-old"))
        self.mark(review_old, Delivery.DELIVERED)
        review_new = self.add(task, Role.REVIEW, ref(Provider.CLAUDE, "r-new"))
        self.mark(review_new, Delivery.FAILED)
        notice = self.add(task, Role.NOTICE, ref(native="origin-notice"))
        self.mark(notice, Delivery.DELIVERED)
        # 交接取 a（b 未发出）；复核取 r-old（r-new 明确未送达）；notice 不算参与方
        self.assertEqual(self.recipients(task), [("a", 1), ("r-old", 3)])

    def test_same_session_is_notified_once_and_origin_is_excluded(self) -> None:
        task, handoff = self.task(ref(native="same", pid=10))
        self.mark(handoff, Delivery.QUEUED)
        review = self.add(task, Role.REVIEW, ref(native="same", pid=11, pane="%5"))
        self.mark(review, Delivery.QUEUED)
        self.assertEqual(self.recipients(task), [("same", 1)])
        origin = ref(native="lead", pid=20, pane="%3")
        led, attempt = self.task(ref(native="lead", pid=21, pane="%4"), origin=origin)
        self.mark(attempt, Delivery.QUEUED)
        other = self.add(led, Role.REVIEW, ref(Provider.CLAUDE, "reviewer"))
        self.mark(other, Delivery.HELD)
        self.assertEqual(self.recipients(led), [("reviewer", 2)])

    def test_delivered_endpoint_is_bound_as_a_whole(self) -> None:
        target = EndpointRef(Provider.CODEX, "t", pid=10, start_ticks="1", pane="%1", label="work", server_pid=700)
        task, attempt = self.task(target)
        self.mark(attempt, Delivery.QUEUED, {"deliveredPid": 42, "deliveredStart": "77", "deliveredPane": "%7",
                                             "deliveredServerPid": 900})
        (recipient,) = closure_recipients(task, self.store.attempts(task.id))
        self.assertEqual(recipient.target, EndpointRef(Provider.CODEX, "t", pid=42, start_ticks="77", pane="%7",
                                                       label="work", server_pid=900))
        base = Attempt(id="x", task_id=task.id, seq=1, role=Role.HANDOFF, target=target, message_id="m", created_at=1.0, body="")
        cases: dict[str, tuple[dict[str, Any], EndpointRef]] = {
            # 缺 start 就整组回退到选定目标，不拿投递 pane 去拼选定 PID
            "no_start": ({"deliveredPid": 42, "deliveredPane": "%7"}, target),
            "bool_pid": ({"deliveredPid": True, "deliveredStart": "77"}, target),
            "no_detail": ({}, target),
            # 有投递证据但 pane/server 缺失或类型不对：为空，不回退到选定目标的 pane/server
            "bad_pane_server": (
                {"deliveredPid": 42, "deliveredStart": "77", "deliveredPane": 5, "deliveredServerPid": "900"},
                EndpointRef(Provider.CODEX, "t", pid=42, start_ticks="77", pane=None, label="work", server_pid=None),
            ),
        }
        for name, (detail, expected) in cases.items():
            with self.subTest(case=name):
                self.assertEqual(delivered_endpoint(Attempt(**{**base.__dict__, "delivery_detail": detail})), expected)

    def test_body_variants(self) -> None:
        task = Task(id="0" * 32, created_at=1.0, updated_at=1.0, title="", flow=Flow.HANDOFF, origin=None, reviewer=None)
        # 没有标题、没写原因：省略书名号与括注
        self.assertTrue(
            closure_body(task, CLOSED, decider="用户", reason=None).startswith(
                f"状态同步：任务已由 用户 关闭。不需要 {CMD} report，也不用再给发起方发消息。"
            )
        )
        long_reason = closure_body(task, CLOSED, decider="用户", reason="很" * 1000)
        self.assertIn("（原因：" + "很" * MAX_REASON_CHARS + "）。", long_reason)
        self.assertNotIn("很" * (MAX_REASON_CHARS + 1), long_reason)


class ClosureDispatchTests(unittest.TestCase):
    """发送：只对结束/暂停放行结束回执，其余条件照旧；失败不改终态。"""

    def setUp(self) -> None:
        self._tmp = TemporaryDirectory()
        self.root = Path(self._tmp.name) / "bridge"
        self.store = Store.open(self.root)
        self.now = 1000.0
        self.endpoints: list[Any] = []
        self.codex = RecordingTransport(Provider.CODEX)
        self.claude = RecordingTransport(
            Provider.CLAUDE,
            lambda _endpoint, _text, context: DeliveryOutcome(Delivery.WRITTEN, "claude_written", provider_ref=context.message_uuid),
        )
        self.proc = FakeProc(Path(self._tmp.name) / "proc")
        self.queue_states: dict[str, Consumption] = {}
        self.queue_queries: list[str] = []
        # 守卫：Dispatcher 的 queue_state 默认绑定生产读取器（dataclass 默认值，事后改模块名拦不住），
        # 夹具必须注入假查询；生产队列库路径一被解析就失败（Codex 审计 F01）
        guard = patch.object(
            codex_queue, "queue_database_path", side_effect=AssertionError("测试不得解析生产 Codex 队列库路径")
        )
        self.queue_path_lookup = guard.start()
        self.addCleanup(guard.stop)
        self.addCleanup(lambda: self.assertEqual(self.queue_path_lookup.call_count, 0))
        self.dispatcher = self.make_dispatcher(self.store)
        self.addCleanup(self._tmp.cleanup)
        self.addCleanup(lambda: self.store.close())

    def fake_queue_state(self, item: str) -> Consumption:
        self.queue_queries.append(item)
        return self.queue_states.get(item, Consumption.UNKNOWN)

    def make_dispatcher(self, store: Store) -> Dispatcher:
        """所有 dispatcher（含重启后重新构造的）都注入假发现、假通道与假队列查询。"""
        return Dispatcher(
            store=store,
            discover=lambda: list(self.endpoints),
            transports={Provider.CODEX: self.codex, Provider.CLAUDE: self.claude},
            reply_address="uds:/run/test/inbox.sock",
            clock=lambda: self.now,
            proc_root=self.proc.root,
            queue_state=self.fake_queue_state,
        )

    def run_once(self, dispatcher: Dispatcher | None = None) -> None:
        worker = dispatcher or self.dispatcher
        worker._endpoints_at = None  # pyright: ignore[reportPrivateUsage]
        worker.run_once()

    def get(self, attempt: Attempt) -> Attempt:
        current = self.store.get_attempt(attempt.id)
        assert current is not None
        return current

    def finish(self, target: EndpointRef, state: str = CLOSED, *, paused: bool = False) -> tuple[Task, Attempt]:
        """交接已送达、按命令同一顺序进入终态并排好结束回执。"""
        task, attempt = self.store.create_task(
            title="实现", flow=Flow.HANDOFF, origin=None, origin_class=None, reviewer=None,
            target=target, body="请实现 X", refs=[], now=self.now,
        )
        self.assertTrue(self.store.begin_send(attempt.id, now=self.now, pid=1, start_ticks="1"))
        self.store.finish_send(attempt.id, delivery=Delivery.QUEUED, reason="codex_queued", provider_ref=None, detail={}, now=self.now)
        if paused:
            self.store.update_task(task.id, now=self.now, event="paused", control="paused")
        with self.store.transaction():
            current = self.store.get_task(task.id)
            assert current is not None
            outcome = queue_closures(
                self.store, current, self.store.attempts(task.id), state,
                now=self.now, decider="用户", reason=None, sender=None, sender_class="bypass",
            )
            fields: dict[str, object] = {"accepted_at": self.now} if state == ACCEPTED else {"closed_at": self.now, "close_reason": "closed"}
            self.store.update_task(task.id, now=self.now, event=state, **fields)
        (closure,) = outcome.queued
        return task, closure

    def test_closure_is_sent_once_after_the_task_finished(self) -> None:
        target = ref()
        self.endpoints = [endpoint(target)]
        task, closure = self.finish(target, ACCEPTED)
        self.assertTrue(needs_worker(self.store, self.now + DAY))
        self.run_once()
        self.run_once()
        self.assertEqual(len(self.codex.calls), 1)
        _endpoint, text, context = self.codex.calls[0]
        header = parse_header(text)
        assert header is not None
        self.assertEqual((header.task_id, header.message_id, header.role, header.sender), (task.id, closure.message_id, Role.NOTICE, "user"))
        self.assertEqual(text.splitlines()[-1], f"（AgentStatus 协作桥结束回执：不需要 {CMD} report；详情 {CMD} status {task.id[:8]}）")
        # 只给查看命令：不附任何汇报命令
        self.assertNotIn(f"report {task.id}", text)
        self.assertNotIn("--attempt", text)
        self.assertEqual((context.sender_name, context.sender_class), ("AgentStatus 协作桥（结束回执）", "bypass"))
        self.assertEqual(self.get(closure).delivery, Delivery.QUEUED)
        finished = self.store.get_task(task.id)
        assert finished is not None
        self.assertTrue(finished.accepted_at is not None and finished.closed_at is None)

    def test_paused_then_closed_sends_only_the_closure_and_stays_paused(self) -> None:
        target = ref(native="closed-paused")
        other_target = ref(native="still-paused", pid=2000, pane="%2")
        self.endpoints = [endpoint(target), endpoint(other_target)]
        task, closure = self.finish(target, paused=True)
        # 另一项仍暂停中的任务的普通消息，和已结束任务里一条普通 notice，都不能借道发出
        paused_task, paused_attempt = self.store.create_task(
            title="暂停", flow=Flow.HANDOFF, origin=None, origin_class=None, reviewer=None,
            target=other_target, body="x", refs=[], now=self.now,
        )
        self.store.update_task(paused_task.id, now=self.now, event="paused", control="paused")
        ordinary = self.store.add_attempt(
            task.id, role=Role.NOTICE, target=target, body="普通通知", refs=[], now=self.now, sender=None, sender_class=None
        )
        self.run_once()
        self.assertEqual([call[1].splitlines()[0].split(" msg=")[1].split(" ")[0] for call in self.codex.calls], [closure.message_id])
        self.assertEqual((self.get(paused_attempt).delivery, self.get(ordinary).delivery), (Delivery.PENDING, Delivery.PENDING))
        self.assertFalse(self.store.begin_send(ordinary.id, now=self.now, pid=1, start_ticks="1"))
        current = self.store.get_task(task.id)
        assert current is not None
        self.assertEqual((current.control, current.closed_at is not None), ("paused", True))
        # 只剩普通排队消息（任务暂停或已结束）时 worker 不为它驻留
        self.assertFalse(needs_worker(self.store, self.now + DAY))

    def test_busy_or_waiting_target_receives_the_closure(self) -> None:
        """结束回执同样不再按忙闲扣留（DESIGN §45.42）。"""
        for runtime in (Runtime.BUSY, Runtime.WAITING):
            with self.subTest(runtime=runtime):
                target = ref()
                _task, closure = self.finish(target)
                self.endpoints = [endpoint(target, runtime=runtime)]
                before = len(self.codex.calls)
                self.run_once()
                self.assertEqual(self.get(closure).delivery, Delivery.QUEUED)
                self.assertEqual(len(self.codex.calls), before + 1)

    def test_unsent_closure_survives_a_worker_restart(self) -> None:
        target = ref()
        _task, closure = self.finish(target)
        self.store.close()
        self.store = Store.open(self.root)
        self.endpoints = [endpoint(target)]
        self.assertTrue(needs_worker(self.store, self.now + DAY))
        restarted = self.make_dispatcher(self.store)
        self.run_once(restarted)
        self.assertEqual((len(self.codex.calls), self.get(closure).delivery), (1, Delivery.QUEUED))
        # 重启后重新构造的 dispatcher 同样只用注入的假队列查询
        self.queue_states["item-1"] = Consumption.LEFT_QUEUE
        self.run_once(restarted)
        self.assertEqual(self.get(closure).consumption, Consumption.LEFT_QUEUE)
        self.assertIn("item-1", self.queue_queries)

    def test_fixture_never_reaches_the_production_queue_reader(self) -> None:
        """发送后的消费观察走注入的假查询；守卫本身确实拦得住生产读取器（Codex 审计 F01）。"""
        target = ref()
        self.endpoints = [endpoint(target)]
        _task, closure = self.finish(target)
        self.queue_states["item-1"] = Consumption.STILL_QUEUED
        self.run_once()
        self.assertEqual(self.get(closure).consumption, Consumption.STILL_QUEUED)
        self.assertEqual(self.queue_queries, ["item-1"])
        self.assertEqual(self.queue_path_lookup.call_count, 0)
        with self.assertRaises(AssertionError):
            codex_queue.queue_item_state("item-1")
        self.queue_path_lookup.reset_mock()

    def test_interrupted_send_is_unknown_and_never_resent(self) -> None:
        target = ref()
        self.endpoints = [endpoint(target)]
        _task, closure = self.finish(target)
        self.assertTrue(self.store.begin_send(closure.id, now=self.now, pid=5151, start_ticks="9"))
        self.run_once()
        self.run_once()
        self.assertEqual((self.get(closure).delivery, self.get(closure).delivery_reason), (Delivery.UNKNOWN, "interrupted_during_send"))
        self.assertEqual(self.codex.calls, [])

    def test_delivery_failures_do_not_touch_the_finished_task(self) -> None:
        target = ref()
        task, closure = self.finish(target)
        other = ref(native="unrelated", pid=3000, pane="%3")
        self.endpoints = [endpoint(other)]
        self.run_once()
        self.now += TARGET_GONE_GRACE_SECONDS + 1
        self.run_once()
        self.assertEqual((self.get(closure).delivery, self.get(closure).delivery_reason), (Delivery.FAILED, "target_gone"))
        # 通道异常：结果不明，不重发
        second_target = ref(native="boom", pid=4000, pane="%4")
        self.endpoints = [endpoint(second_target)]
        second_task, second = self.finish(second_target)
        self.codex.error = RuntimeError("boom")
        self.run_once()
        self.run_once()
        self.assertEqual((self.get(second).delivery, len(self.codex.calls)), (Delivery.UNKNOWN, 1))
        for finished in (task, second_task):
            current = self.store.get_task(finished.id)
            assert current is not None
            self.assertTrue(current.finished)
        summary.publish(self.store, self.root, now=self.now)
        document = json.loads((self.root / summary.SUMMARY_NAME).read_text(encoding="utf-8"))
        self.assertEqual((document["tasks"], document["attentionIndex"], document["counts"]["attention"]), ([], [], 0))
        self.assertEqual(self.dispatcher.pending_reminders(), [])
        self.assertFalse(needs_worker(self.store, self.now + DAY))

    def test_claude_hold_and_its_outcomes_are_recorded_normally(self) -> None:
        target = ref(Provider.CLAUDE, "claude-session")
        self.endpoints = [endpoint(target, socket_path="/run/test/peer.sock")]
        for final in ("delivered", "denied", "expired"):
            with self.subTest(final=final):
                _task, closure = self.finish(target)
                self.run_once()
                written = self.get(closure)
                self.assertEqual(written.delivery, Delivery.WRITTEN)
                receipt = {"type": "control", "action": "peer_message_status", "orig_msg_id": str(written.provider_ref)}
                self.assertEqual(self.dispatcher.handle_frame({**receipt, "status": "held"}), "receipt")
                self.assertEqual(self.get(closure).delivery, Delivery.HELD)
                self.dispatcher.handle_frame({**receipt, "status": final})
                self.assertEqual(self.get(closure).delivery, Delivery(final))

    def test_summary_marks_only_closure_deliveries(self) -> None:
        target = ref(pane="%1")
        self.endpoints = [endpoint(target)]
        task, closure = self.finish(target)
        ordinary_task, ordinary = self.store.create_task(
            title="普通", flow=Flow.HANDOFF, origin=None, origin_class=None, reviewer=None,
            target=ref(native="other", pid=2000, pane="%2"), body="x", refs=[], now=self.now,
        )
        notice = self.store.add_attempt(
            ordinary_task.id, role=Role.NOTICE, target=ref(native="lead", pid=3000, pane="%3"), body="结果",
            refs=[], now=self.now, sender=None, sender_class=None,
        )
        for attempt in (ordinary, notice):
            self.assertTrue(self.store.begin_send(attempt.id, now=self.now, pid=1, start_ticks="1"))
            self.store.finish_send(attempt.id, delivery=Delivery.DELIVERED, reason="t", provider_ref=None, detail={}, now=self.now)
        self.run_once()
        summary.publish(self.store, self.root, now=self.now)
        document = json.loads((self.root / summary.SUMMARY_NAME).read_text(encoding="utf-8"))
        by_id = {item["messageId"]: item for item in document["deliveries"]}
        self.assertEqual(by_id[closure.message_id], {"messageId": closure.message_id, "role": "notice", "kind": "closure",
                                                     "pane": "%1", "provider": "codex"})
        self.assertNotIn("kind", by_id[notice.message_id])
        self.assertNotIn("kind", by_id[ordinary.message_id])
        self.assertTrue(summary.is_valid(document))
        del task
        # 兼容：旧摘要（没有 kind）、新旧混合都有效；kind 不是字符串才无效
        old = [{key: value for key, value in item.items() if key != "kind"} for item in document["deliveries"]]
        self.assertTrue(summary.is_valid({**document, "deliveries": old}))
        self.assertTrue(summary.is_valid({**document, "deliveries": [*old[:1], by_id[closure.message_id]]}))
        self.assertFalse(summary.is_valid({**document, "deliveries": [{**by_id[closure.message_id], "kind": 1}]}))


if __name__ == "__main__":
    unittest.main()
