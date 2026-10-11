"""§70 delete 的协议、三段事务、权限/崩溃和旧状态机隔离。"""
from __future__ import annotations

from dataclasses import asdict
import json
import contextlib
import io
import os
from pathlib import Path
from tempfile import TemporaryDirectory
import time
import unittest
from unittest.mock import patch

from bridge_support import ProductionSocketUse, LedgerCase, RecordingTransport, ref, endpoint
from test_bridge_codex_native import CANARY, NativeDaemon
from test_bridge_codex_rpc import THREAD, ITEM
from agentstatus_bridge.transports import codex_withdraw, local_codex
from agentstatus_bridge.transports.codex_withdraw import DeleteResult, QueueDeleteClient
from agentstatus_bridge import cli, procfs, views
from agentstatus_bridge.endpoints import Caller
from agentstatus_bridge.model import Delivery, Role, Work, Provider
from agentstatus_bridge.store import Store, StoreError
from agentstatus_bridge.dispatch import Dispatcher
from agentstatus_bridge.transports import DeliveryOutcome
from agentstatus_bridge.transports.codex_queue import CodexQueueTransport
from agentstatus_bridge.transports.codex_rpc import RpcResult


class DeleteProtocolTests(unittest.TestCase):
    def setUp(self):
        self.tmp = TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.boundaries = []

    def run_delete(self, response, *, version="0.162.1", before=(), hook=None):
        daemon = NativeDaemon(self.root, replies=lambda _: response, version=version, before=before)
        self.addCleanup(daemon.close)
        stamp = local_codex.platform().root_identity(daemon.home)
        result = QueueDeleteClient(lambda _: "0.162.1").delete(
            daemon.home, thread=THREAD, item=ITEM.lower(), root_identity=stamp,
            before_send=hook or (lambda: self.boundaries.append("sending")),
        )
        return result, daemon

    def test_exact_pair_true_false_and_no_other_method(self):
        result, daemon = self.run_delete({"result": {"deleted": True, "extra": CANARY}})
        self.assertEqual(result, DeleteResult("deleted", "deleted", "0.162.1"))
        self.assertEqual(self.boundaries, ["sending"])
        self.assertEqual(daemon.methods(), ["initialize", "initialized", "thread/queue/delete"])
        self.assertEqual(daemon.received[2]["params"], {"threadId": THREAD, "queuedSubmissionId": ITEM.lower()})
        self.assertTrue(daemon.received[0]["params"]["capabilities"]["experimentalApi"])
        self.assertNotIn(CANARY, json.dumps(asdict(result)))

    def test_deleted_is_strict_bool_and_response_id_is_strict(self):
        for value, state in ((False, "absent"), ("false", "unknown"), (0, "unknown"), (1, "unknown"), (None, "unknown")):
            with self.subTest(value=value), TemporaryDirectory() as tmp:
                daemon = NativeDaemon(Path(tmp), replies=lambda _, value=value: {"result": {"deleted": value}})
                try:
                    result = QueueDeleteClient(lambda _: "0.162.1").delete(daemon.home, thread=THREAD, item=ITEM.lower(),
                        root_identity=local_codex.platform().root_identity(daemon.home), before_send=lambda: None)
                    self.assertEqual(result.state, state)
                finally:
                    daemon.close()
        result, _ = self.run_delete({"id": 7, "result": {"deleted": True}})
        self.assertEqual(result.state, "unknown")

    def test_version_gate_never_enters_send_boundary(self):
        result, daemon = self.run_delete({"result": {"deleted": True}}, version="0.160.0")
        self.assertEqual((result.state, result.reason), ("not_attempted", "version_unverified"))
        self.assertEqual(self.boundaries, [])
        self.assertEqual(daemon.methods(), ["initialize"])

    def test_errors_do_not_claim_original_undelivered(self):
        rows = ((-32601, "missing", "refused"), (-32600, "thread not found: fixture", "refused"),
                (-32603, "failed to read thread: fixture", "refused"),
                (-32603, "queued submission operation failed " + CANARY, "unknown"),
                (-999, CANARY, "unknown"))
        for code, message, state in rows:
            with self.subTest(code=code, state=state):
                self.assertEqual(codex_withdraw.delete_error({"code": code, "message": message})[0], state)
        result, _ = self.run_delete({"error": {"code": -999, "message": CANARY}})
        self.assertEqual(result.state, "unknown")
        self.assertNotIn(CANARY, repr(result))

    def test_silent_after_write_is_unknown_and_no_retry(self):
        started = time.monotonic()
        with patch.object(codex_withdraw, "DELETE_SECONDS", 0.15):
            result, daemon = self.run_delete(None)
        self.assertEqual((result.state, result.reason), ("unknown", "deadline"))
        self.assertEqual(daemon.methods().count("thread/queue/delete"), 1)
        self.assertLess(time.monotonic() - started, 0.8)

    def test_approval_request_is_not_answered(self):
        result, daemon = self.run_delete({"result": {"deleted": True}}, before=(
            {"id": 222, "method": "item/commandExecution/requestApproval", "params": CANARY},))
        self.assertEqual((result.state, result.reason), ("unknown", "server_request_seen"))
        daemon.thread.join(1)
        self.assertEqual(len(daemon.received), 3)

    def test_callback_failure_does_not_send(self):
        def failing():
            raise RuntimeError(CANARY)
        result, daemon = self.run_delete({"result": {"deleted": True}}, hook=failing)
        daemon.thread.join(1)
        self.assertEqual(result.state, "not_attempted")
        self.assertEqual(daemon.methods(), ["initialize", "initialized"])
        self.assertNotIn(CANARY, repr(result))

    def test_wrong_root_is_rejected_without_connecting(self):
        self.assertEqual(QueueDeleteClient(lambda _: "0.162.1").delete(
            self.root, thread=THREAD, item=ITEM.lower(), root_identity="different",
            before_send=lambda: self.fail("boundary called")), DeleteResult("not_attempted", "root_mismatch"))

    def test_production_guard_escapes_delete(self):
        target = Path(f"/tmp/codex-daemon-{os.getuid()}/agentstatus-guard-probe-does-not-exist")
        with patch.object(local_codex.LinuxPlatform, "resolve", return_value=target), self.assertRaises(ProductionSocketUse):
            QueueDeleteClient(lambda _: "0.162.1").delete(self.root, thread=THREAD, item=ITEM.lower(),
                root_identity=local_codex.platform().root_identity(self.root), before_send=lambda: self.fail("boundary"))


class WithdrawalLedgerTests(LedgerCase):
    def setUp(self):
        super().setUp()
        self.home = self.root.parent / "home"
        self.home.mkdir()
        self.stamp = local_codex.platform().root_identity(self.home)
        self.info = procfs.read_process(os.getpid())
        self.task, self.attempt = self.create(target=ref(native=THREAD), origin=ref(native="origin"))
        self.store.begin_send(self.attempt.id, now=100, pid=os.getpid(), start_ticks=self.info.start_ticks)
        self.store.finish_send(self.attempt.id, delivery=Delivery.QUEUED, reason="codex_queued", provider_ref=ITEM.lower(),
                               detail={}, native_root=self.stamp, now=101)

    def prepare(self, **kwargs):
        return self.store.prepare_withdrawal(self.task.id, self.attempt.seq, root_identity=self.stamp,
            now=110, pid=self.info.pid, start=self.info.start_ticks, **kwargs)

    def finish(self, operation, state="deleted"):
        self.store.finish_withdrawal(operation["id"], thread=THREAD, item=ITEM.lower(), state=state,
                                    reason=state, version="0.162.1", now=120)

    def test_root_is_business_evidence_and_revision_changes(self):
        before = self.store.ledger_revision()[1]
        attempt = self.current(self.attempt)
        self.assertEqual(attempt.options.get("codexDataRoot"), self.stamp)
        self.assertNotIn("codexDataRoot", attempt.delivery_detail)
        operation, created = self.prepare()
        self.assertTrue(created)
        self.assertGreater(self.store.ledger_revision()[1], before)
        before = self.store.ledger_revision()[1]
        self.store.begin_withdrawal(operation["id"], now=115, pid=self.info.pid, start=self.info.start_ticks)
        self.assertGreater(self.store.ledger_revision()[1], before)
        before = self.store.ledger_revision()[1]
        self.finish(operation)
        self.assertGreater(self.store.ledger_revision()[1], before)
        self.assertEqual(self.current(self.attempt).delivery, Delivery.QUEUED)
        public = views._task_document(self.store, self.task)["nativeWithdrawals"]
        self.assertEqual(public["version"], 1)
        self.assertNotIn(self.stamp, json.dumps(public))

    def test_transport_root_proof_flows_through_dispatch_and_deferred_record(self):
        transport = CodexQueueTransport(rpc=lambda *a, **kw: RpcResult(Delivery.QUEUED, "codex_queued", "0.162.1", ITEM.lower()))
        with (patch.dict(os.environ, {"CODEX_HOME": str(self.home), "CODEX_SQLITE_HOME": str(self.home)}),
              patch.object(transport, "_resolve_executable", return_value="/synthetic/codex"),
              patch.object(transport, "_release_version", return_value="0.162.1")):
            task, attempt = self.create(target=ref(native=THREAD))
            dispatcher = Dispatcher(self.store, lambda: [endpoint(attempt.target)], {Provider.CODEX: transport}, clock=lambda: 140)
            self.assertEqual(dispatcher.dispatch(attempt, [endpoint(attempt.target)]), "sent")
        self.assertEqual(self.current(attempt).options.get("codexDataRoot"), self.stamp)
        other, pending = self.create(target=ref(native=THREAD))
        output = DeliveryOutcome(Delivery.QUEUED, "codex_queued", ITEM.lower(), native_root=self.stamp)
        recording = RecordingTransport(Provider.CODEX, output)
        dispatcher = Dispatcher(self.store, lambda: [endpoint(pending.target)], {Provider.CODEX: recording}, clock=lambda: 150)
        with patch.object(self.store, "finish_send", side_effect=StoreError("store_busy")):
            self.assertEqual(dispatcher.dispatch(pending, [endpoint(pending.target)]), "sent")
        dispatcher._flush_unrecorded()
        self.assertEqual(self.current(pending).options.get("codexDataRoot"), self.stamp)
        self.assertEqual(len(recording.calls), 1)

    def test_concurrent_duplicate_has_only_one_intent(self):
        operation, _ = self.prepare()
        with Store.open(self.root) as other:
            same, created = other.prepare_withdrawal(self.task.id, self.attempt.seq, root_identity=self.stamp,
                now=111, pid=987654, start="1", again=True)
        self.assertFalse(created)
        self.assertEqual(same["id"], operation["id"])
        self.assertEqual(len(self.store.withdrawals(self.task.id)), 1)

    def test_withdrawal_delete_advances_revision(self):
        operation, _ = self.prepare()
        before = self.store.ledger_revision()[1]
        with self.store.transaction() as conn:
            conn.execute("DELETE FROM native_withdrawals WHERE id=?", (operation["id"],))
        self.assertEqual(self.store.ledger_revision()[1], before + 1)

    def test_recovery_never_resends_and_again_keeps_history(self):
        operation, _ = self.prepare()
        with patch.object(procfs, "read_process", return_value=None):
            self.store.recover_withdrawals(now=130)
        self.assertEqual(self.store.withdrawals(self.task.id)[0]["state"], "not_attempted")
        self.assertFalse(self.prepare()[1])
        second, created = self.prepare(again=True)
        self.assertTrue(created)
        self.store.begin_withdrawal(second["id"], now=115, pid=self.info.pid, start=self.info.start_ticks)
        with patch.object(procfs, "read_process", return_value=None):
            self.store.recover_withdrawals(now=130)
        self.assertEqual([r["state"] for r in self.store.withdrawals(self.task.id)], ["not_attempted", "unknown"])
        self.assertFalse(self.prepare()[1])

    def test_concurrent_result_close_and_new_attempt_are_not_overwritten(self):
        operation, _ = self.prepare()
        self.store.begin_withdrawal(operation["id"], now=111, pid=self.info.pid, start=self.info.start_ticks)
        with Store.open(self.root) as other:
            next_attempt = other.add_attempt(self.task.id, role=Role.HANDOFF, target=ref(native=ITEM.lower()),
                body="synthetic next attempt", refs=[], now=111.5, sender=None, sender_class=None)
            other.update_task(self.task.id, now=112, event="closed", closed_at=112)
            # 模拟独立report的精确列更新；若finish用旧Attempt回写，后面的原值断言会红。
            with other.transaction() as conn:
                conn.execute("UPDATE attempts SET work=?,result=? WHERE id=?", (Work.RESULT.value, '{"note":"synthetic result"}', self.attempt.id))
        self.finish(operation)
        self.assertEqual(self.current(self.attempt).work, Work.RESULT)
        self.assertEqual(self.current(self.attempt).result, {"note": "synthetic result"})
        self.assertEqual(self.store.get_task(self.task.id).closed_at, 112)
        self.assertEqual(self.current(next_attempt).delivery, Delivery.PENDING)
        self.assertEqual(self.current(next_attempt).target.native_id, ITEM.lower())

    def test_exact_attempt_and_ineligible_are_rejected(self):
        for changes in ({"delivery": Delivery.UNKNOWN.value}, {"role": Role.NOTICE.value}, {"provider_ref": None},
                        {"options": "{}"}, {"provider_ref": "wrong"}):
            with self.subTest(changes=changes), self.store.transaction() as conn:
                old = conn.execute("SELECT * FROM attempts WHERE id=?", (self.attempt.id,)).fetchone()
                for key, value in changes.items():
                    conn.execute(f"UPDATE attempts SET {key}=? WHERE id=?", (value, self.attempt.id))
                with self.assertRaises(StoreError):
                    self.prepare()
                for key in changes:
                    conn.execute(f"UPDATE attempts SET {key}=? WHERE id=?", (old[key], self.attempt.id))
        with self.assertRaisesRegex(StoreError, "withdraw_attempt_missing"):
            self.store.prepare_withdrawal(self.task.id, 999, root_identity=self.stamp, now=1, pid=1, start="1")
        self.assertEqual(self.store.withdrawals(self.task.id), [])

    def test_missing_root_different_provider_and_closed_task(self):
        old = self.current(self.attempt)
        with self.store.transaction() as conn:
            target = old.target.to_dict()
            target["provider"] = Provider.CLAUDE.value
            conn.execute("UPDATE attempts SET target=? WHERE id=?", (json.dumps(target), old.id))
        with self.assertRaisesRegex(StoreError, "withdraw_ineligible"):
            self.prepare()
        with self.store.transaction() as conn:
            conn.execute("UPDATE attempts SET target=? WHERE id=?", (json.dumps(old.target.to_dict()), old.id))
        self.store.update_task(self.task.id, now=108, event="closed", closed_at=108)
        self.assertTrue(self.prepare()[1])

    def test_old_attempt_not_replaced_by_latest_and_uncertain_history_survives_prune(self):
        # 新尝试并不改变旧UUID对；准备仍只读用户指定的旧attempt。
        with self.store.transaction() as conn:
            conn.execute("UPDATE attempts SET seq=2 WHERE id=?", (self.attempt.id,))
        with self.assertRaisesRegex(StoreError, "withdraw_attempt_missing"):
            self.prepare()
        with self.store.transaction() as conn:
            conn.execute("UPDATE attempts SET seq=1 WHERE id=?", (self.attempt.id,))
        operation, _ = self.prepare()
        self.store.begin_withdrawal(operation["id"], now=112, pid=self.info.pid, start=self.info.start_ticks)
        self.finish(operation, "unknown")
        self.store.update_task(self.task.id, now=113, event="closed", closed_at=113)
        self.store.prune(now=113 + 40 * 86400)
        self.assertEqual(len(self.store.withdrawals(self.task.id)), 1)
        self.assertEqual(self.store.withdrawals(self.task.id)[0]["state"], "unknown")

    def test_result_write_failure_keeps_sending_without_retry(self):
        operation, _ = self.prepare()
        self.store.begin_withdrawal(operation["id"], now=112, pid=self.info.pid, start=self.info.start_ticks)
        with self.assertRaises(StoreError):
            self.store.finish_withdrawal(operation["id"], thread=ITEM.lower(), item=ITEM.lower(),
                state="deleted", reason="deleted", version="0.162.1", now=120)
        self.assertEqual(self.store.withdrawals(self.task.id)[0]["state"], "sending")
        self.assertFalse(self.prepare(again=True)[1])

    def run_cli(self, arguments, *, caller=None, delete=None):
        output = io.StringIO()
        manager = patch.object(QueueDeleteClient, "delete", side_effect=delete) if delete else contextlib.nullcontext()
        with (patch.dict(os.environ, {"AB_STATE_DIR": str(self.root), "CODEX_HOME": str(self.home), "CODEX_SQLITE_HOME": str(self.home)}),
              patch.object(cli, "discover", return_value=[]), patch.object(cli, "identify_caller", return_value=caller or Caller(None, None)),
              patch.object(cli, "_start_worker", return_value=True),
              patch.object(cli, "_refresh_summary") as refresh, manager,
              contextlib.redirect_stdout(output), contextlib.redirect_stderr(output)):
            code = cli.main(arguments)
        return code, output.getvalue(), refresh

    def test_command_permissions_are_checked_before_any_delete(self):
        for caller in (Caller(endpoint(ref(native=THREAD)), self.info), Caller(None, None, agent_env=True, rejection="subagent")):
            code, _, _ = self.run_cli(["withdraw", self.task.id, "--attempt", "1"], caller=caller,
                                      delete=lambda *a, **kw: self.fail("unauthorized delete"))
            self.assertEqual(code, 3)
        self.assertEqual(self.store.withdrawals(self.task.id), [])

    def test_command_persists_boundary_no_long_transaction_and_does_not_wake_worker(self):
        calls = []
        def delete(home, **kwargs):
            self.assertEqual((kwargs["thread"], kwargs["item"]), (THREAD, ITEM.lower()))
            with Store.open(self.root) as other:
                self.assertEqual(other.withdrawals(self.task.id)[0]["state"], "prepared")
            kwargs["before_send"]()
            with Store.open(self.root) as other:
                self.assertEqual(other.withdrawals(self.task.id)[0]["state"], "sending")
                other.update_task(self.task.id, now=117, event="synthetic", control="paused")
            calls.append(1)
            return DeleteResult("deleted", "deleted", "0.162.1")
        args = ["withdraw", self.task.id, "--attempt", "1", "--json"]
        code, output, refresh = self.run_cli(args, delete=delete)
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(output)["operation"]["state"], "deleted")
        self.assertEqual(refresh.call_args.kwargs, {"revive": False})
        self.assertEqual(self.run_cli(args, delete=delete)[0], 0)
        self.assertEqual(calls, [1])
        self.assertEqual(self.store.get_task(self.task.id).control, "paused")

    def test_deleted_after_execution_still_requires_force(self):
        operation, _ = self.prepare()
        self.finish(operation)
        code, output, _ = self.run_cli(["retry", self.task.id])
        self.assertEqual(code, 3)
        self.assertIn("--force", output)
        self.assertEqual(len(self.store.attempts(self.task.id)), 1)
        self.assertEqual(self.current(self.attempt).delivery, Delivery.QUEUED)

    def test_close_and_cancel_never_delete_or_claim_native_recall(self):
        for command in ("cancel", "close", "retry"):
            with self.subTest(command=command):
                code, output, _ = self.run_cli([command, self.task.id],
                    delete=lambda *a, **kw: self.fail("implicit native delete"))
                self.assertIn(code, (0, 3))
        self.assertEqual(self.store.withdrawals(self.task.id), [])


if __name__ == "__main__":
    unittest.main()
