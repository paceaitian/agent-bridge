"""§70 delete 的协议、三段事务、权限/崩溃和旧状态机隔离。"""
from __future__ import annotations
from agentstatus_bridge.platforms.null_transport import UnsupportedPlatform
from agentstatus_bridge.platforms.linux import local_transport as linux_transport

from dataclasses import asdict
import json
import contextlib
import io
import os
import sqlite3
import threading
from concurrent.futures import ThreadPoolExecutor
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
from agentstatus_bridge import cli, views
from agentstatus_bridge.platforms.linux import process as procfs
from agentstatus_bridge.endpoints import Caller
from agentstatus_bridge.model import Consumption, Delivery, Role, Work, Provider
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
            before_send=hook or (lambda budget: self.boundaries.append("sending")),
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
                        root_identity=local_codex.platform().root_identity(daemon.home), before_send=lambda budget: None)
                    self.assertEqual(result.state, state)
                finally:
                    daemon.close()
        result, _ = self.run_delete({"id": 7, "result": {"deleted": True}})
        self.assertEqual(result.state, "unknown")

    def test_server_version_is_recorded_without_blocking_delete(self):
        for version in ("0.160.0", "0.163.0", "99.99.99", "not-a-version"):
            for deleted in (True, False):
                with self.subTest(version=version, deleted=deleted), TemporaryDirectory() as tmp:
                    daemon = NativeDaemon(Path(tmp), version=version,
                        replies=lambda _, deleted=deleted: {"result": {"deleted": deleted}})
                    boundaries = []
                    try:
                        result = QueueDeleteClient(lambda _: "0.162.1").delete(daemon.home,
                            thread=THREAD, item=ITEM.lower(), root_identity=local_codex.platform().root_identity(daemon.home),
                            before_send=lambda budget: boundaries.append("sending"))
                        state = "deleted" if deleted else "absent"
                        expected = version if version != "not-a-version" else "unknown"
                        self.assertEqual(result, DeleteResult(state, state, expected))
                        self.assertEqual(boundaries, ["sending"])
                        self.assertEqual(daemon.methods(), ["initialize", "initialized", "thread/queue/delete"])
                        self.assertEqual(daemon.received[0]["params"]["clientInfo"]["version"], "0.162.1")
                        self.assertTrue(daemon.received[0]["params"]["capabilities"]["experimentalApi"])
                        self.assertEqual(daemon.received[2]["params"], {"threadId": THREAD, "queuedSubmissionId": ITEM.lower()})
                    finally:
                        daemon.close()

    def test_invalid_initialize_still_never_enters_send_boundary(self):
        for init, reason in ((["invalid"], "initialize_failed"),
                             ({"userAgent": "codex-tui/0.163.0", "codexHome": 42}, "home_mismatch"),
                             ({"userAgent": "codex-tui/0.163.0", "codexHome": str(self.root / "other")}, "home_mismatch")):
            with self.subTest(reason=reason, init=init), TemporaryDirectory() as tmp:
                daemon = NativeDaemon(Path(tmp), init=init)
                boundaries = []
                try:
                    result = QueueDeleteClient(lambda _: "0.162.1").delete(daemon.home,
                        thread=THREAD, item=ITEM.lower(), root_identity=local_codex.platform().root_identity(daemon.home),
                        before_send=lambda budget: boundaries.append("sending"))
                    self.assertEqual((result.state, result.reason), ("not_attempted", reason))
                    self.assertEqual(boundaries, [])
                    self.assertEqual(daemon.methods(), ["initialize"])
                finally:
                    daemon.close()

    def test_cli_version_unknown_initializes_and_deletes(self):
        daemon = NativeDaemon(self.root, replies=lambda _: {"result": {"deleted": True}})
        self.addCleanup(daemon.close)
        result = QueueDeleteClient(lambda _: None).delete(daemon.home,
            thread=THREAD, item=ITEM.lower(), root_identity=local_codex.platform().root_identity(daemon.home),
            before_send=lambda budget: self.boundaries.append("sending"))
        self.assertEqual(result, DeleteResult("deleted", "deleted", "0.162.1"))
        self.assertEqual(daemon.received[0]["params"]["clientInfo"]["version"], "unknown")
        self.assertEqual(self.boundaries, ["sending"])
        self.assertEqual(daemon.methods(), ["initialize", "initialized", "thread/queue/delete"])

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
        def failing(budget):
            raise RuntimeError(CANARY)
        result, daemon = self.run_delete({"result": {"deleted": True}}, hook=failing)
        daemon.thread.join(1)
        self.assertEqual(result.state, "not_attempted")
        self.assertEqual(daemon.methods(), ["initialize", "initialized"])
        self.assertNotIn(CANARY, repr(result))

    def test_wrong_root_is_rejected_without_connecting(self):
        self.assertEqual(QueueDeleteClient(lambda _: "0.162.1").delete(
            self.root, thread=THREAD, item=ITEM.lower(), root_identity="different",
            before_send=lambda budget: self.fail("boundary called")), DeleteResult("not_attempted", "root_mismatch"))

    def test_production_guard_escapes_delete(self):
        target = Path(f"/tmp/codex-daemon-{os.getuid()}/agentstatus-guard-probe-does-not-exist")
        with patch.object(linux_transport.LinuxPlatform, "resolve", return_value=target), self.assertRaises(ProductionSocketUse):
            QueueDeleteClient(lambda _: "0.162.1").delete(self.root, thread=THREAD, item=ITEM.lower(),
                root_identity=local_codex.platform().root_identity(self.root), before_send=lambda budget: self.fail("boundary"))

    def test_boundary_budget_and_store_failures_never_become_unknown(self):
        for failure, reason in ((StoreError("store_busy"), "boundary_store_busy"),
                                (StoreError("store_write_failed"), "boundary_record_failed")):
            with self.subTest(reason=reason), TemporaryDirectory() as tmp:
                daemon = NativeDaemon(Path(tmp))
                try:
                    def boundary(budget):
                        self.assertGreater(budget, 0)
                        self.assertLessEqual(budget, 10)
                        raise failure
                    result = QueueDeleteClient(lambda _: "0.162.1").delete(daemon.home,
                        thread=THREAD, item=ITEM.lower(), root_identity=local_codex.platform().root_identity(daemon.home),
                        before_send=boundary)
                    daemon.thread.join(1)
                    self.assertEqual((result.state, result.reason), ("not_attempted", reason))
                    self.assertEqual(daemon.methods(), ["initialize", "initialized"])
                finally:
                    daemon.close()

    def test_deadline_checked_both_sides_of_boundary(self):
        for expire_before in (False, True):
            with self.subTest(expire_before=expire_before), TemporaryDirectory() as tmp:
                daemon = NativeDaemon(Path(tmp))
                now, calls = [0.0], []
                original_encode = codex_withdraw.BoundedConnection._encode
                def encode(client, value):
                    if expire_before and value.get("method") == "thread/queue/delete":
                        now[0] = 11.0
                    return original_encode(client, value)
                def boundary(budget):
                    calls.append(budget)
                    now[0] = 11.0
                try:
                    with patch.object(codex_withdraw.BoundedConnection, "_encode", encode):
                        result = QueueDeleteClient(lambda _: "0.162.1", clock=lambda: now[0]).delete(
                            daemon.home, thread=THREAD, item=ITEM.lower(),
                            root_identity=local_codex.platform().root_identity(daemon.home), before_send=boundary)
                    daemon.thread.join(1)
                    self.assertEqual((result.state, result.reason), ("not_attempted", "deadline"))
                    self.assertEqual(len(calls), 0 if expire_before else 1)
                    self.assertEqual(daemon.methods(), ["initialize", "initialized"])
                finally:
                    daemon.close()

    def test_deadline_before_actual_sendall_is_still_not_attempted(self):
        now = [0.0]
        daemon = NativeDaemon(self.root)
        self.addCleanup(daemon.close)
        send_frame = codex_withdraw.BoundedConnection._send_frame
        def expire(client, opcode, payload, deadline):
            if b'thread/queue/delete' in payload:
                now[0] = 11.0
            return send_frame(client, opcode, payload, deadline)
        with patch.object(codex_withdraw.BoundedConnection, "_send_frame", expire):
            result = QueueDeleteClient(lambda _: "0.162.1", clock=lambda: now[0]).delete(
                daemon.home, thread=THREAD, item=ITEM.lower(), root_identity=local_codex.platform().root_identity(daemon.home),
                before_send=lambda budget: None)
        daemon.thread.join(1)
        self.assertEqual((result.state, result.reason), ("not_attempted", "deadline"))
        self.assertEqual(daemon.methods(), ["initialize", "initialized"])


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
        for caller, reason in ((Caller(endpoint(ref(native=THREAD)), self.info), "withdraw_not_allowed"),
                               (Caller(None, None, agent_env=True, rejection="subagent"), "sender_is_subagent")):
            code, output, _ = self.run_cli(["withdraw", self.task.id, "--attempt", "1", "--json"], caller=caller,
                                      delete=lambda *a, **kw: self.fail("unauthorized delete"))
            self.assertEqual(code, 3)
            self.assertEqual(json.loads(output[output.index("{"):])["code"], reason)
        self.assertEqual(self.store.withdrawals(self.task.id), [])

    def test_command_persists_boundary_no_long_transaction_and_does_not_wake_worker(self):
        calls = []
        def delete(home, **kwargs):
            self.assertEqual((kwargs["thread"], kwargs["item"]), (THREAD, ITEM.lower()))
            with Store.open(self.root) as other:
                self.assertEqual(other.withdrawals(self.task.id)[0]["state"], "prepared")
            kwargs["before_send"](1.0)
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

    def test_first_open_interleaving_reads_version_in_write_transaction(self):
        # 同时首次安装附表；断言读版本也在锁内，不只靠 OR IGNORE 掩盖读后写。
        barrier = threading.Barrier(2)
        initial_reads = threading.Barrier(2)
        transactional_reads = []
        class Connection(sqlite3.Connection):
            def execute(connection, sql, *args):
                if sql.startswith("SELECT value FROM meta WHERE key='native_withdrawals_version'"):
                    if not connection.execute("SELECT name FROM sqlite_master WHERE name='native_withdrawals'").fetchone():
                        transactional_reads.append(connection.in_transaction)
                    if not connection.in_transaction and not getattr(connection, "read_initial_version", False):
                        connection.read_initial_version = True
                        value = super().execute(sql, *args).fetchone()
                        initial_reads.wait(3)  # 两方均先看到无版本，再开始竞争写事务
                        return type("Fetched", (), {"fetchone": lambda _: value})()
                return super().execute(sql, *args)
        class ConcurrentStore(Store):
            def _ensure_withdrawals(store):
                barrier.wait(3)
                super()._ensure_withdrawals()
        root = self.root.parent / "race"
        # 只准备旧主 schema，两个 opener 才会真正同时首次安装附表。
        root.mkdir(mode=0o700)
        with sqlite3.connect(root / "bridge.sqlite3", isolation_level=None) as connection:
            old = Store(connection)
            old._configure()
            old._migrate()
        connect = sqlite3.connect
        def open_one():
            try:
                with ConcurrentStore.open(root) as store:
                    return store.withdrawals_readable
            except StoreError as error:
                return error.code  # 两方都成功是被测判据，安装异常应以断言FAIL呈现
        with patch("agentstatus_bridge.store.sqlite3.connect", side_effect=lambda *a, **kw: connect(*a, **kw, factory=Connection)):
            with ThreadPoolExecutor(max_workers=2) as pool:
                self.assertEqual(list(pool.map(lambda _: open_one(), range(2))), [True, True])
        self.assertTrue(transactional_reads)
        self.assertIn(True, transactional_reads, "需要安装附表时，必须在写事务中重读版本")

    def test_unknown_table_version_only_disables_withdrawals(self):
        with self.store.transaction() as conn:
            conn.execute("UPDATE meta SET value='2' WHERE key='native_withdrawals_version'")
        try:
            opened = Store.open(self.root)
        except StoreError as error:
            self.fail(f"附表不可读阻断了主账本：{error.code}")
        with opened as other:
            self.assertFalse(other.withdrawals_readable)
            doc = views._task_document(other, self.task)["nativeWithdrawals"]
            self.assertEqual(doc, {"version": 1, "readable": False, "reason": "withdraw_store_unreadable", "operations": []})
            other.update_task(self.task.id, now=200, event="test", control="paused")
            self.assertEqual(other.get_task(self.task.id).control, "paused")
            with self.assertRaisesRegex(StoreError, "withdraw_store_unreadable"):
                other.prepare_withdrawal(self.task.id, 1, root_identity=self.stamp, now=210, pid=1, start="1")
            other.prune(now=220)
        code, output, _ = self.run_cli(["withdraw", self.task.id, "--attempt", "1", "--json"])
        self.assertEqual(code, 8)
        self.assertIn("withdraw_store_unreadable", output)

    def test_cold_open_wal_busy_is_bounded_and_both_stores_succeed(self):
        root = self.root.parent / "cold"
        connect = sqlite3.connect
        busy = sqlite3.OperationalError("synthetic busy")
        busy.sqlite_errorcode = sqlite3.SQLITE_BUSY
        wal_calls = []
        class ColdConnection(sqlite3.Connection):
            def execute(connection, sql, *args):
                if sql == "PRAGMA journal_mode=WAL":
                    wal_calls.append(sql)
                    if len(wal_calls) == 1:
                        # A配置时B抢先完整首开空账本；A遇到的是WAL切换的瞬时BUSY。
                        with patch("agentstatus_bridge.store.sqlite3.connect", connect):
                            with Store.open(root) as other:
                                if not other.withdrawals_readable:
                                    raise AssertionError("second opener failed")
                        raise busy
                return super().execute(sql, *args)
        with patch("agentstatus_bridge.store.sqlite3.connect", side_effect=lambda *a, **kw: connect(*a, **kw, factory=ColdConnection)):
            try:
                opened = Store.open(root)
            except StoreError as error:
                self.fail(f"first opener failed: {error.code}")
            with opened:
                self.assertTrue(opened.withdrawals_readable)
        self.assertEqual(len(wal_calls), 2)
        with patch.object(Store, "_configure", Store._configure):
            class AlwaysBusy:
                def execute(self, *args):
                    raise busy
            with patch("agentstatus_bridge.store.time.monotonic", side_effect=[0.0, 6.0]):
                with self.assertRaisesRegex(StoreError, "store_busy"):
                    Store._configure(type("BoundedFixture", (), {"_conn": AlwaysBusy()})())

    def test_owner_liveness_read_only_and_namespace_guard(self):
        operation, _ = self.prepare()
        revision = self.store.ledger_revision()
        with patch.object(procfs, "read_process", return_value=None):
            rows = self.store.withdrawals(self.task.id)
            self.assertEqual(rows[0]["ownerStatus"], "gone")
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                views._print_task(self.store, self.task, now=150, show_body=False)
            self.assertIn("执行者已不在，下次 withdraw 恢复", output.getvalue())
            self.assertEqual(self.store.ledger_revision(), revision)
            self.assertEqual(rows[0]["state"], "prepared")
            with patch.object(cli, "_observations", return_value=([], cli.ObserverView())):
                code, compact, _ = self.run_cli(["tasks"])
            self.assertEqual(code, 0)
            self.assertIn("执行者已不在，下次 withdraw 恢复", compact)
            self.assertEqual(self.store.ledger_revision(), revision)
            with patch.object(procfs, "pid_namespace", return_value="pid:[different]"):
                self.store.recover_withdrawals(now=151)
                self.assertEqual(self.store.withdrawals(self.task.id)[0]["ownerStatus"], "namespace_unverified")
                self.assertEqual(self.store.withdrawals(self.task.id)[0]["state"], "prepared")
        with self.store.transaction() as conn:
            conn.execute("UPDATE native_withdrawals SET owner_pid_namespace=NULL WHERE id=?", (operation["id"],))
        with patch.object(procfs, "read_process", return_value=None):
            self.store.recover_withdrawals(now=152)
        self.assertEqual(self.store.withdrawals(self.task.id)[0]["state"], "not_attempted")

    def test_finish_conflict_returns_actual_result_without_overwriting_unknown(self):
        def delete(home, **kwargs):
            kwargs["before_send"](1.0)
            with Store.open(self.root) as other, patch.object(procfs, "read_process", return_value=None):
                other.recover_withdrawals(now=130)
            return DeleteResult("deleted", "deleted", "0.162.1")
        code, output, _ = self.run_cli(["withdraw", self.task.id, "--attempt", "1", "--json"], delete=delete)
        self.assertEqual(code, 8)
        doc = json.loads(output)
        self.assertEqual(doc["code"], "withdraw_record_conflict")
        self.assertIn("actualResult", doc)
        self.assertEqual(doc["actualResult"], {"state": "deleted", "reason": "deleted", "serverVersion": "0.162.1"})
        self.assertEqual(doc["operation"]["state"], "unknown")
        self.assertEqual(self.store.withdrawals(self.task.id)[0]["state"], "unknown")
        code, output, _ = self.run_cli(["withdraw", self.task.id, "--attempt", "1", "--again"], delete=delete)
        self.assertEqual(code, 8)
        self.assertIn("本次实际结果 deleted", output)
        self.assertIn("账本未覆盖", output)

    def test_summary_failure_respects_withdraw_revive_false(self):
        output = io.StringIO()
        with (patch.dict(os.environ, {"AB_STATE_DIR": str(self.root), "CODEX_HOME": str(self.home), "CODEX_SQLITE_HOME": str(self.home)}),
              patch.object(cli, "discover", return_value=[]), patch.object(cli, "identify_caller", return_value=Caller(None, None)),
              patch.object(cli.summary, "publish", side_effect=RuntimeError("synthetic")),
              patch.object(cli, "_start_worker") as start,
              patch.object(QueueDeleteClient, "delete", return_value=DeleteResult("not_attempted", "boundary_store_busy")),
              contextlib.redirect_stdout(output), contextlib.redirect_stderr(output)):
            self.assertEqual(cli.main(["withdraw", self.task.id, "--attempt", "1"]), 8)
            start.assert_not_called()

    def test_root_reasons_and_public_keys(self):
        with self.assertRaisesRegex(StoreError, "^withdraw_root_missing$"):
            self.store.prepare_withdrawal(self.task.id, 1, root_identity="", now=110, pid=1, start="1")
        with self.store.transaction() as conn:
            conn.execute("UPDATE attempts SET options='{}' WHERE id=?", (self.attempt.id,))
            with self.assertRaisesRegex(StoreError, "^withdraw_root_missing$"):
                self.store.prepare_withdrawal(self.task.id, 1, root_identity=self.stamp, now=110, pid=1, start="1")
            conn.execute("UPDATE attempts SET options=? WHERE id=?", (json.dumps({"codexDataRoot": self.stamp}), self.attempt.id))
        with self.assertRaisesRegex(StoreError, "withdraw_root_mismatch"):
            self.store.prepare_withdrawal(self.task.id, 1, root_identity="0" * 64, now=110, pid=1, start="1")
        for code in ("withdraw_root_missing", "withdraw_root_mismatch", "withdraw_platform_unsupported"):
            self.assertEqual(cli._exit_for_store_error(code), 6)
            self.assertNotEqual(cli.reason_text(code), code)
        self.assertNotEqual(cli.reason_text("withdraw_invalid_result"), "withdraw_invalid_result")
        with patch.object(local_codex, "platform", return_value=UnsupportedPlatform()):
            code, output, _ = self.run_cli(["withdraw", self.task.id, "--attempt", "1", "--json"])
            self.assertEqual(code, 6)
            self.assertIn("withdraw_platform_unsupported", output)
        operation, _ = self.prepare()
        self.finish(operation)
        keys = set(self.store.withdrawals(self.task.id)[0])
        self.assertEqual(keys, {"id", "attemptSeq", "state", "reason", "serverVersion", "createdAt", "sendingAt", "finishedAt", "ownerStatus"})

    def test_deleted_item_does_not_suggest_forgotten_report_or_retry(self):
        operation, _ = self.prepare()
        self.finish(operation)
        with self.store.transaction() as conn:
            conn.execute("UPDATE attempts SET consumption=? WHERE id=?", (Consumption.LEFT_QUEUE.value, self.attempt.id))
        hint = views._TargetHint(stopped_at=130, missing=True)
        doc = views._task_document(self.store, self.task, hint=hint)
        self.assertFalse(doc["targetStoppedWithoutReport"])
        self.assertFalse(doc["targetSessionMissing"])
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            views._print_task(self.store, self.task, now=200, show_body=False, hint=hint)
        self.assertIn("本桥已移除", output.getvalue())
        self.assertNotIn("可能忘了", output.getvalue())
        self.assertNotIn("retry", output.getvalue())
        self.assertEqual(self.current(self.attempt).consumption, Consumption.LEFT_QUEUE)
        with patch.object(cli, "_observations", return_value=([], cli.ObserverView())), \
                patch.object(cli, "_target_hint", return_value=hint):
            code, compact, _ = self.run_cli(["tasks"])
            self.assertEqual(code, 0)
            self.assertIn("本桥已移除", compact)
            self.assertNotIn("对方已停下未汇报", compact)
            self.assertNotIn("未发现对方会话", compact)
            next_attempt = self.store.add_attempt(self.task.id, role=Role.HANDOFF, target=ref(native=ITEM.lower()),
                body="synthetic next", refs=[], now=210, sender=None, sender_class=None)
            self.store.begin_send(next_attempt.id, now=211, pid=self.info.pid, start_ticks=self.info.start_ticks)
            self.store.finish_send(next_attempt.id, delivery=Delivery.QUEUED, reason="codex_queued", provider_ref=THREAD,
                                   detail={}, native_root=self.stamp, now=212)
            _, next_output, _ = self.run_cli(["tasks"])
            self.assertIn("未发现对方会话", next_output, "旧attempt撤回不能抑制新attempt提示")
            next_doc = views._task_document(self.store, self.task, hint=hint)
            self.assertTrue(next_doc["targetSessionMissing"])

    def test_unknown_withdraw_version_prune_keeps_attached_rows_n22(self):
        operation, _ = self.prepare()
        self.finish(operation)
        self.store.update_task(self.task.id, now=200, event="closed", closed_at=200)
        before = tuple(self.store._conn.execute("SELECT * FROM native_withdrawals WHERE id=?", (operation["id"],)).fetchone())
        with self.store.transaction() as conn:
            conn.execute("UPDATE meta SET value='future-version' WHERE key='native_withdrawals_version'")
        with Store.open(self.root) as other:
            self.assertFalse(other.withdrawals_readable)
            self.assertEqual(other.prune(now=200 + 40 * 86400), 1)
            remaining = [tuple(row) for row in other._conn.execute("SELECT * FROM native_withdrawals")]
            self.assertEqual(remaining, [before], "未知版本不能删除已经失去主任务的附表行")

    def test_withdraw_timeout_recovers_both_states_but_not_before_boundary(self):
        for state in ("prepared", "sending"):
            for owner in ("alive", "other-namespace", "namespace-unreadable"):
                with self.subTest(state=state, owner=owner):
                    operation, created = self.prepare(again=True)
                    self.assertTrue(created)
                    if state == "sending":
                        self.store.begin_withdrawal(operation["id"], now=115, pid=self.info.pid, start=self.info.start_ticks)
                    context = (contextlib.nullcontext() if owner == "alive" else
                               patch.object(procfs, "pid_namespace", return_value="pid:[other]" if owner == "other-namespace" else None))
                    with context:
                        revision = self.store.ledger_revision()
                        for now in (110 - 601, 100, 709.999, 710):  # created_at=110；回拨（含超过门槛的回拨）、门槛前、恰门槛均不动
                            self.store.recover_withdrawals(now=now)
                            current = next(row for row in self.store.withdrawals(self.task.id) if row["id"] == operation["id"])
                            self.assertEqual(current["state"], state)
                            self.assertEqual(self.store.ledger_revision(), revision)
                        self.store.recover_withdrawals(now=710.001)
                    current = next(row for row in self.store.withdrawals(self.task.id) if row["id"] == operation["id"])
                    self.assertEqual(current["state"], "not_attempted" if state == "prepared" else "unknown")
                    self.assertEqual(current["reason"], "owner_timeout")
                    with self.assertRaisesRegex(StoreError, "withdraw_record_conflict"):
                        self.finish(operation)
                    self.assertEqual(next(row for row in self.store.withdrawals(self.task.id) if row["id"] == operation["id"]), current)

    def test_timeout_late_result_cli_reports_actual_without_overwrite(self):
        def delete(home, **kwargs):
            kwargs["before_send"](1.0)
            with Store.open(self.root) as other, patch.object(procfs, "pid_namespace", return_value="pid:[other]"):
                created = other.withdrawals(self.task.id)[-1]["createdAt"]
                other.recover_withdrawals(now=created + 601)
            return DeleteResult("deleted", "deleted", "0.162.1")
        code, output, _ = self.run_cli(["withdraw", self.task.id, "--attempt", "1", "--json"], delete=delete)
        doc = json.loads(output)
        self.assertEqual(code, 8)
        self.assertEqual(doc["code"], "withdraw_record_conflict")
        self.assertEqual(doc["actualResult"]["state"], "deleted")
        self.assertEqual((doc["operation"]["state"], doc["operation"]["reason"]), ("unknown", "owner_timeout"))

    def test_live_owner_is_not_recovered_m1(self):
        operation, _ = self.prepare()
        self.store.recover_withdrawals(now=120)
        self.assertEqual(self.store.withdrawals(self.task.id)[0]["state"], "prepared")
        self.store.begin_withdrawal(operation["id"], now=121, pid=self.info.pid, start=self.info.start_ticks)
        self.store.recover_withdrawals(now=122)
        self.assertEqual(self.store.withdrawals(self.task.id)[0]["state"], "sending")

    def test_begin_requires_exact_owner_pid_and_start_m13(self):
        operation, _ = self.prepare()
        for pid, start in ((self.info.pid + 1, self.info.start_ticks), (self.info.pid, "reused")):
            with self.subTest(pid=pid, start=start), self.assertRaisesRegex(StoreError, "withdraw_conflict"):
                self.store.begin_withdrawal(operation["id"], now=121, pid=pid, start=start)
            self.assertEqual(self.store.withdrawals(self.task.id)[0]["state"], "prepared")

    def test_boundary_limits_sqlite_busy_wait_and_restores_timeout(self):
        operation, _ = self.prepare()
        seen = []
        with Store.open(self.root) as other, other.transaction():
            self.store._conn.set_trace_callback(seen.append)
            with self.assertRaisesRegex(StoreError, "store_busy"):
                self.store.begin_withdrawal(operation["id"], now=120, pid=self.info.pid, start=self.info.start_ticks, budget=0.01)
            self.store._conn.set_trace_callback(None)
        self.assertIn("PRAGMA busy_timeout=10", seen)
        self.assertEqual(self.store._conn.execute("PRAGMA busy_timeout").fetchone()[0], 5000)

    def test_deleted_and_absent_are_not_repeated_with_again_m14(self):
        operation, _ = self.prepare()
        for state in ("deleted", "absent"):
            with self.subTest(state=state):
                with self.store.transaction() as conn:
                    conn.execute("UPDATE native_withdrawals SET state=? WHERE id=?", (state, operation["id"]))
                same, created = self.prepare(again=True)
                self.assertFalse(created)
                self.assertEqual(same["id"], operation["id"])
                self.assertEqual(len(self.store.withdrawals(self.task.id)), 1)

    def test_seventeenth_explicit_operation_is_rejected_m16(self):
        for _ in range(16):
            operation, created = self.prepare(again=True)
            self.assertTrue(created)
            self.finish(operation, "unknown")
        with self.assertRaisesRegex(StoreError, "withdraw_limit"):
            self.prepare(again=True)
        self.assertEqual(len(self.store.withdrawals(self.task.id)), 16)

    def test_add_home_symlink_switch_does_not_save_root_m21(self):
        with TemporaryDirectory() as tmp:
            base = Path(tmp)
            daemon = NativeDaemon(base)
            self.addCleanup(daemon.close)
            other = base / "other"
            other.mkdir()
            home = base / "home-link"
            home.symlink_to(daemon.home, target_is_directory=True)
            def response(request):
                home.unlink()
                home.symlink_to(other, target_is_directory=True)
                return {"result": {"queuedSubmission": {"id": ITEM.lower(),
                    "clientUserMessageId": request["params"]["clientUserMessageId"]}}}
            daemon.replies = response
            transport = CodexQueueTransport()
            with (patch.dict(os.environ, {"CODEX_HOME": str(home), "CODEX_SQLITE_HOME": str(home)}),
                  patch.object(transport, "_resolve_executable", return_value="/synthetic/codex"),
                  patch.object(transport, "_release_version", return_value="0.162.1")):
                task, attempt = self.create(target=ref(native=THREAD))
                dispatcher = Dispatcher(self.store, lambda: [endpoint(attempt.target)], {Provider.CODEX: transport}, clock=lambda: 140)
                self.assertEqual(dispatcher.dispatch(attempt, [endpoint(attempt.target)]), "sent")
            self.assertEqual(self.current(attempt).delivery, Delivery.QUEUED)
            self.assertNotIn("codexDataRoot", self.current(attempt).options)
            self.assertEqual(daemon.methods(), ["initialize", "initialized", "thread/queue/add"])

    def test_delete_home_switch_after_initialize_never_sends_m22(self):
        with TemporaryDirectory() as tmp:
            base = Path(tmp)
            daemon = NativeDaemon(base)
            self.addCleanup(daemon.close)
            other = base / "other"
            other.mkdir()
            # 会合点前后保持相同socket，单靠daemon epoch检测不能兜住数据根漂移。
            (other / "app-server-control").mkdir()
            (other / "app-server-control/app-server-control.sock").symlink_to(daemon.socket_path)
            home = base / "home-link"
            home.symlink_to(daemon.home, target_is_directory=True)
            root = local_codex.platform().root_identity(home)
            initialize = codex_withdraw.BoundedConnection.initialize
            def switch(client, *args, **kwargs):
                initialize(client, *args, **kwargs)
                home.unlink()
                home.symlink_to(other, target_is_directory=True)
            boundary = []
            with patch.object(codex_withdraw.BoundedConnection, "initialize", switch):
                result = QueueDeleteClient(lambda _: "0.162.1").delete(home, thread=THREAD, item=ITEM.lower(),
                    root_identity=root, before_send=lambda budget: boundary.append(budget))
            daemon.thread.join(1)
            self.assertEqual((result.state, result.reason), ("not_attempted", "root_mismatch"))
            self.assertEqual(boundary, [])
            self.assertEqual(daemon.methods(), ["initialize", "initialized"])


if __name__ == "__main__":
    unittest.main()
