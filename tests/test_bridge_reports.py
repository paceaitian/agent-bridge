"""协作桥汇报：归属核验、陈旧/重复汇报拒绝、固定复核流程与发起方通知。"""

from __future__ import annotations

from pathlib import Path
from tempfile import TemporaryDirectory
import threading
import unittest
from unittest.mock import patch

from agentstatus_bridge.naming import DEFAULT_COMMAND as CMD
from agentstatus_bridge.endpoints import Caller
from agentstatus_bridge.model import (
    Delivery,
    EndpointRef,
    Flow,
    Phase,
    Provider,
    ReportKind,
    Role,
    Verdict,
    Work,
    describe,
)
from agentstatus_bridge.procfs import ProcessInfo
from agentstatus_bridge.reports import ReportError, ReportInput, apply_report
from agentstatus_bridge.store import Store, StoreError
from bridge_support import FakeProc, endpoint, ref

IMPLEMENTER = ref(Provider.CODEX, "impl-thread", pid=1000, pane="%1", label="impl")
REVIEWER = ref(Provider.CLAUDE, "review-session", pid=2000, pane="%2", label="review")
ORIGIN = ref(Provider.CLAUDE, "origin-session", pid=3000, pane="%3", label="lead")


def agent_caller(reference: EndpointRef) -> Caller:
    return Caller(endpoint(reference), ProcessInfo(reference.pid, 1, reference.provider.value, reference.start_ticks))


class ReportTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = TemporaryDirectory()
        self.root = Path(self._tmp.name)
        self.store = Store.open(self.root / "bridge")
        self.now = 1000.0

    def tearDown(self) -> None:
        self.store.close()
        self._tmp.cleanup()

    def _task(self, *, flow: Flow = Flow.REVIEW, origin: EndpointRef | None = ORIGIN):
        task, attempt = self.store.create_task(
            title="实现 X",
            flow=flow,
            origin=origin,
            origin_class="bypass",
            reviewer=REVIEWER if flow is Flow.REVIEW else None,
            target=IMPLEMENTER,
            body="原始要求：实现 X",
            refs=[],
            now=self.now,
        )
        self._mark_sent(attempt.id, Delivery.QUEUED)
        return task, attempt

    def _mark_sent(self, attempt_id: str, delivery: Delivery) -> None:
        self.assertTrue(self.store.begin_send(attempt_id, now=self.now, pid=1, start_ticks="1"))
        self.store.finish_send(
            attempt_id, delivery=delivery, reason="test", provider_ref=None, detail={}, now=self.now
        )

    def _report(self, task_id: str, kind: ReportKind, caller: Caller, **extra: object):
        return apply_report(
            self.store,
            ReportInput(task_ref=task_id, kind=kind, **extra),  # type: ignore[arg-type]
            caller=caller,
            caller_class="bypass",
            now=self.now,
            cwd=self.root,
            git=lambda _cwd, value: "a" * 40 if value.startswith("abc") else None,
        )

    def _code(self, task_id: str, kind: ReportKind, caller: Caller, **extra: object) -> str:
        with self.assertRaises(ReportError) as caught:
            self._report(task_id, kind, caller, **extra)
        return caught.exception.code

    def test_implementer_result_queues_review_with_pinned_result(self) -> None:
        task, attempt = self._task()
        result_file = self.root / "report.md"
        result_file.write_text("结果", encoding="utf-8")
        outcome = self._report(
            task.id, ReportKind.RESULT, agent_caller(IMPLEMENTER), note="已完成", files=(str(result_file),), commit="abc1234"
        )
        implemented = self.store.get_attempt(attempt.id)
        assert implemented is not None
        self.assertEqual((implemented.delivery, implemented.work), (Delivery.DELIVERED, Work.RESULT))
        self.assertEqual(implemented.result["commit"], {"commit": "a" * 40, "verified": True})  # type: ignore[index]
        self.assertEqual(len(outcome.followups), 1)
        review = outcome.followups[0]
        self.assertEqual((review.role, review.delivery), (Role.REVIEW, Delivery.PENDING))
        self.assertTrue(review.target.same_session(REVIEWER))
        self.assertIn("【结果】", review.body)
        self.assertIn("原始要求：实现 X", review.body)
        self.assertEqual(review.refs[0]["sha256"], implemented.result["files"][0]["sha256"])  # type: ignore[index]
        self.assertEqual(review.sender_class, "bypass")

    def test_only_the_receiving_session_may_report(self) -> None:
        task, _ = self._task()
        self.assertEqual(self._code(task.id, ReportKind.ACK, agent_caller(REVIEWER)), "reporter_mismatch")
        stray_agent = Caller(None, ProcessInfo(4000, 1, "codex", "5"))
        self.assertEqual(self._code(task.id, ReportKind.ACK, stray_agent), "reporter_unattributed")
        user = Caller(None, None)
        self.assertEqual(self._code(task.id, ReportKind.ACK, user), "manual_flag_required")
        outcome = self._report(task.id, ReportKind.ACK, user, manual=True)
        self.assertEqual(outcome.attempt.work, Work.ACKNOWLEDGED)

    def test_stale_attempt_and_duplicate_results_are_rejected(self) -> None:
        task, _ = self._task()
        self._report(task.id, ReportKind.RESULT, agent_caller(IMPLEMENTER))
        self.assertEqual(
            self._code(task.id, ReportKind.RESULT, agent_caller(IMPLEMENTER), attempt_seq=1), "stale_attempt"
        )
        handoff, _ = self._task(flow=Flow.HANDOFF)
        self._report(handoff.id, ReportKind.RESULT, agent_caller(IMPLEMENTER))
        self.assertEqual(
            self._code(handoff.id, ReportKind.RESULT, agent_caller(IMPLEMENTER)), "result_already_submitted"
        )

    def test_unsent_attempt_cannot_be_reported(self) -> None:
        task, _ = self.store.create_task(
            title="t",
            flow=Flow.HANDOFF,
            origin=None,
            origin_class=None,
            reviewer=None,
            target=IMPLEMENTER,
            body="x",
            refs=[],
            now=self.now,
        )
        self.assertEqual(self._code(task.id, ReportKind.ACK, agent_caller(IMPLEMENTER)), "attempt_not_sent")

    def test_verdict_flags_are_role_specific(self) -> None:
        task, _ = self._task()
        self.assertEqual(
            self._code(task.id, ReportKind.APPROVE, agent_caller(IMPLEMENTER)), "verdict_requires_review"
        )
        outcome = self._report(task.id, ReportKind.RESULT, agent_caller(IMPLEMENTER))
        self._mark_sent(outcome.followups[0].id, Delivery.DELIVERED)
        self.assertEqual(self._code(task.id, ReportKind.RESULT, agent_caller(REVIEWER)), "review_requires_verdict")

    def test_review_approval_awaits_acceptance_and_notifies_origin(self) -> None:
        task, _ = self._task()
        outcome = self._report(task.id, ReportKind.RESULT, agent_caller(IMPLEMENTER))
        self._mark_sent(outcome.followups[0].id, Delivery.DELIVERED)
        approved = self._report(task.id, ReportKind.APPROVE, agent_caller(REVIEWER), note="没问题")
        self.assertEqual(approved.task.verdict, Verdict.APPROVED)
        view = describe(approved.task, self.store.attempts(task.id))
        self.assertEqual((view.phase, view.reason), (Phase.AWAITING_ACCEPTANCE, "review_approved"))
        self.assertEqual([item.role for item in approved.followups], [Role.NOTICE])
        notice = approved.followups[0]
        self.assertTrue(notice.target.same_session(ORIGIN))
        self.assertTrue(notice.sender is not None and notice.sender.same_session(REVIEWER))
        self.assertIn("复核通过", notice.body)

    def test_review_changes_needs_attention(self) -> None:
        task, _ = self._task()
        outcome = self._report(task.id, ReportKind.RESULT, agent_caller(IMPLEMENTER))
        self._mark_sent(outcome.followups[0].id, Delivery.DELIVERED)
        changed = self._report(task.id, ReportKind.CHANGES, agent_caller(REVIEWER), note="缺测试")
        view = describe(changed.task, self.store.attempts(task.id))
        self.assertEqual((view.phase, view.reason), (Phase.NEEDS_ATTENTION, "changes_requested"))

    def test_handoff_result_notifies_agent_origin_but_not_user_origin(self) -> None:
        task, _ = self._task(flow=Flow.HANDOFF)
        outcome = self._report(task.id, ReportKind.RESULT, agent_caller(IMPLEMENTER), note="好了")
        self.assertEqual([item.role for item in outcome.followups], [Role.NOTICE])
        self.assertEqual(outcome.followups[0].work, Work.NONE)
        user_task, _ = self._task(flow=Flow.HANDOFF, origin=None)
        self.assertEqual(self._report(user_task.id, ReportKind.RESULT, agent_caller(IMPLEMENTER)).followups, [])

    def test_origin_notice_spells_out_the_next_step(self) -> None:
        # DESIGN §45.28.2：回执末尾按写入后的阶段写明下一步，发起方不必再去查 ab status
        handoff, _ = self._task(flow=Flow.HANDOFF)
        ref = handoff.id[:8]
        result = self._report(handoff.id, ReportKind.RESULT, agent_caller(IMPLEMENTER), note="好了").followups[0]
        self.assertTrue(result.body.endswith(f"下一步：{CMD} accept {ref} 验收；需要返工用 {CMD} retry {ref}"))
        blocked_task, _ = self._task(flow=Flow.HANDOFF)
        blocked_ref = blocked_task.id[:8]
        blocked = self._report(blocked_task.id, ReportKind.BLOCKED, agent_caller(IMPLEMENTER), note="缺权限").followups[0]
        self.assertIn(f"下一步：处理对方的问题后 {CMD} retry {blocked_ref} 返工，或 {CMD} close {blocked_ref}", blocked.body)
        failed_task, _ = self._task(flow=Flow.HANDOFF)
        failed_ref = failed_task.id[:8]
        failed = self._report(failed_task.id, ReportKind.FAILED, agent_caller(IMPLEMENTER), note="做不了").followups[0]
        self.assertTrue(failed.body.endswith(f"下一步：处理对方的问题后 {CMD} retry {failed_ref} 返工，或 {CMD} close {failed_ref}"))
        review_task, _ = self._task()
        review_ref = review_task.id[:8]
        implemented = self._report(review_task.id, ReportKind.RESULT, agent_caller(IMPLEMENTER))
        self.assertNotIn("下一步", implemented.followups[0].body)  # 复核请求不是回执，不加
        self._mark_sent(implemented.followups[0].id, Delivery.DELIVERED)
        changes = self._report(review_task.id, ReportKind.CHANGES, agent_caller(REVIEWER), note="缺测试").followups[0]
        self.assertIn(f"下一步：{CMD} retry {review_ref} 把复核意见交回实现方返工", changes.body)
        approved_task, _ = self._task()
        approved_ref = approved_task.id[:8]
        request = self._report(approved_task.id, ReportKind.RESULT, agent_caller(IMPLEMENTER)).followups[0]
        self._mark_sent(request.id, Delivery.DELIVERED)
        approved = self._report(approved_task.id, ReportKind.APPROVE, agent_caller(REVIEWER), note="可以").followups[0]
        self.assertTrue(approved.body.endswith(f"下一步：{CMD} accept {approved_ref} 验收；复核结论见 {CMD} status {approved_ref}"))
        self.assertNotIn(f"{CMD} retry", approved.body)

    def test_notice_attempts_are_not_reportable(self) -> None:
        task, _ = self._task(flow=Flow.HANDOFF)
        outcome = self._report(task.id, ReportKind.BLOCKED, agent_caller(IMPLEMENTER), note="缺权限")
        notice = outcome.followups[0]
        self.assertEqual(
            self._code(task.id, ReportKind.ACK, agent_caller(ORIGIN), attempt_seq=notice.seq),
            "attempt_not_reportable",
        )
        view = describe(outcome.task, self.store.attempts(task.id))
        self.assertEqual(view.reason, "blocked_reported")

    def test_interrupted_report_rolls_back_result_and_followup_together(self) -> None:
        task, attempt = self._task()
        with patch.object(self.store, "add_attempt", side_effect=StoreError("store_write_failed")):
            with self.assertRaises(StoreError):
                self._report(task.id, ReportKind.RESULT, agent_caller(IMPLEMENTER), note="v1")
        unchanged = self.store.get_attempt(attempt.id)
        assert unchanged is not None
        self.assertEqual((unchanged.work, unchanged.delivery), (Work.AWAITING_ACK, Delivery.QUEUED))
        self.assertEqual([item.role for item in self.store.attempts(task.id)], [Role.HANDOFF])
        replay = self._report(task.id, ReportKind.RESULT, agent_caller(IMPLEMENTER), note="v1")
        self.assertEqual([item.role for item in replay.followups], [Role.REVIEW])

    def test_interrupted_changes_verdict_never_appears_approved(self) -> None:
        task, _ = self._task()
        review = self._report(task.id, ReportKind.RESULT, agent_caller(IMPLEMENTER)).followups[0]
        self._mark_sent(review.id, Delivery.DELIVERED)
        with patch.object(self.store, "update_task", side_effect=StoreError("store_write_failed")):
            with self.assertRaises(StoreError):
                self._report(task.id, ReportKind.CHANGES, agent_caller(REVIEWER), note="缺测试")
        view = describe(self.store.get_task(task.id), self.store.attempts(task.id))  # type: ignore[arg-type]
        self.assertNotEqual(view.reason, "review_approved")
        # 即使结论字段丢失，已交的复核结果也不会被当作通过
        self.store.set_work(review.id, work=Work.RESULT, result={}, now=self.now, event="result")
        view = describe(self.store.get_task(task.id), self.store.attempts(task.id))  # type: ignore[arg-type]
        self.assertEqual((view.phase, view.reason), (Phase.NEEDS_ATTENTION, "review_verdict_missing"))

    def test_concurrent_final_reports_create_one_review(self) -> None:
        task, _ = self._task()
        barrier = threading.Barrier(2)
        outcomes: list[str] = []

        def report() -> None:
            with Store.open(self.root / "bridge") as connection:
                def pin(_cwd: Path, _commit: str) -> str:
                    barrier.wait(10)
                    return "a" * 40

                try:
                    apply_report(
                        connection,
                        ReportInput(task_ref=task.id, kind=ReportKind.RESULT, attempt_seq=1, commit="abcdef0"),
                        caller=agent_caller(IMPLEMENTER),
                        caller_class="bypass",
                        now=self.now,
                        cwd=self.root,
                        git=pin,
                    )
                    outcomes.append("ok")
                except (ReportError, StoreError) as error:
                    outcomes.append(error.code)

        threads = [threading.Thread(target=report) for _ in range(2)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(15)
        reviews = [item for item in self.store.attempts(task.id) if item.role is Role.REVIEW]
        self.assertEqual(len(reviews), 1)
        self.assertEqual(sorted(outcomes)[0], "ok")
        self.assertEqual(len(outcomes), 2)

    def test_other_live_generation_of_same_session_cannot_report(self) -> None:
        proc = FakeProc(self.root / "proc")
        proc.add(1500, comm="codex", start="55")
        task, attempt = self._task(flow=Flow.HANDOFF)
        self.store.transition_delivery(
            attempt.id,
            expected=(Delivery.QUEUED,),
            new=Delivery.QUEUED,
            reason="test",
            now=self.now,
            detail={"deliveredPid": 1500, "deliveredStart": "55"},
        )

        def report(caller: Caller) -> str:
            try:
                apply_report(
                    self.store,
                    ReportInput(task_ref=task.id, kind=ReportKind.ACK),
                    caller=caller,
                    caller_class="bypass",
                    now=self.now,
                    cwd=self.root,
                    proc_root=proc.root,
                )
            except ReportError as error:
                return error.code
            return "ok"

        self.assertEqual(report(agent_caller(IMPLEMENTER)), "reporter_generation_mismatch")
        delivered = ref(Provider.CODEX, IMPLEMENTER.native_id, pid=1500, start="55")
        self.assertEqual(report(agent_caller(delivered)), "ok")
        # 实际收到消息的进程退出后，同会话的新进程可以继续汇报
        gone_task, gone = self._task(flow=Flow.HANDOFF)
        self.store.transition_delivery(
            gone.id,
            expected=(Delivery.QUEUED,),
            new=Delivery.QUEUED,
            reason="test",
            now=self.now,
            detail={"deliveredPid": 1600, "deliveredStart": "66"},
        )
        outcome = apply_report(
            self.store,
            ReportInput(task_ref=gone_task.id, kind=ReportKind.ACK),
            caller=agent_caller(IMPLEMENTER),
            caller_class="bypass",
            now=self.now,
            cwd=self.root,
            proc_root=proc.root,
        )
        self.assertEqual(outcome.attempt.work, Work.ACKNOWLEDGED)

    def test_review_request_inherits_shared_thread_opt_in(self) -> None:
        task, attempt = self.store.create_task(
            title="t",
            flow=Flow.REVIEW,
            origin=None,
            origin_class="bypass",
            reviewer=REVIEWER,
            target=IMPLEMENTER,
            body="x",
            refs=[],
            now=self.now,
            task_options={"allowShared": True},
            attempt_options={"allowShared": True},
        )
        self._mark_sent(attempt.id, Delivery.QUEUED)
        review = self._report(task.id, ReportKind.RESULT, agent_caller(IMPLEMENTER)).followups[0]
        self.assertTrue(review.allow_shared)
        plain, plain_attempt = self._task()
        self.assertFalse(self._report(plain.id, ReportKind.RESULT, agent_caller(IMPLEMENTER)).followups[0].allow_shared)
        del plain_attempt

    def test_report_without_attempt_is_pinned_while_hashing(self) -> None:
        task, _attempt = self._task(flow=Flow.HANDOFF)

        def retry_during_git(_cwd: Path, _commit: str) -> str:
            newer = self.store.add_attempt(
                task.id, role=Role.HANDOFF, target=IMPLEMENTER, body="新要求", refs=[], now=self.now, sender=None, sender_class=None
            )
            self._mark_sent(newer.id, Delivery.QUEUED)
            return "a" * 40

        with self.assertRaises(ReportError) as caught:
            apply_report(
                self.store,
                ReportInput(task_ref=task.id, kind=ReportKind.RESULT, commit="abcdef0", note="第一次的结果"),
                caller=agent_caller(IMPLEMENTER),
                caller_class="bypass",
                now=self.now,
                cwd=self.root,
                git=retry_during_git,
            )
        self.assertEqual(caught.exception.code, "stale_attempt")
        newest = self.store.attempts(task.id)[-1]
        self.assertEqual((newest.seq, newest.work, newest.result), (2, Work.AWAITING_ACK, None))

    def test_agent_environment_without_endpoint_is_not_the_user(self) -> None:
        task, _ = self._task()
        hidden_agent = Caller(None, None, None, True)
        self.assertFalse(hidden_agent.is_user_shell)
        self.assertEqual(self._code(task.id, ReportKind.ACK, hidden_agent, manual=True), "reporter_unattributed")

    def test_no_notify_task_does_not_push_to_origin(self) -> None:
        task, attempt = self.store.create_task(
            title="t",
            flow=Flow.HANDOFF,
            origin=ORIGIN,
            origin_class="bypass",
            reviewer=None,
            target=IMPLEMENTER,
            body="x",
            refs=[],
            now=self.now,
            task_options={"notify": False},
        )
        self._mark_sent(attempt.id, Delivery.QUEUED)
        self.assertEqual(self._report(task.id, ReportKind.RESULT, agent_caller(IMPLEMENTER)).followups, [])

    def test_invalid_commit_and_missing_file(self) -> None:
        task, _ = self._task(flow=Flow.HANDOFF)
        self.assertEqual(
            self._code(task.id, ReportKind.RESULT, agent_caller(IMPLEMENTER), commit="zz"), "commit_invalid"
        )
        self.assertEqual(
            self._code(task.id, ReportKind.RESULT, agent_caller(IMPLEMENTER), files=("missing.md",)),
            "file_unreadable",
        )
        unverified = self._report(task.id, ReportKind.RESULT, agent_caller(IMPLEMENTER), commit="def5678")
        self.assertEqual(unverified.attempt.result["commit"], {"commit": "def5678", "verified": False})  # type: ignore[index]


if __name__ == "__main__":
    unittest.main()
