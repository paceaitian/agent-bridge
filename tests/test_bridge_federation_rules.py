"""P5 联邦账本与业务规则（DESIGN §88.4，T03–T07/T13）：两台设备各一个联邦库，用内存泵代替 hub 搬运信封。

覆盖：建库/打开的三种拒绝、fedRevision、证据与裁决幂等；交接→投递证据→ack/result→自动复核；报告先于证据；
迟到低号、过时、写者不符、已结束；A 的取消只写请求、由 B 抑制并回证据；结束回执按 covers 投或抑制；
checkpoint 高 revision 规则；收件重复/冲突；非权威来源；窄同步。
"""

from __future__ import annotations

import json
import sqlite3
import tempfile
import unittest
from unittest.mock import patch
from pathlib import Path
from typing import Any

import bridge_support  # noqa: F401  导入即隔离宿主会话环境

from agentstatus_bridge.closure import ACCEPTED, CLOSED
from agentstatus_bridge.federation import authority, envelopes, mirror
from agentstatus_bridge.federation.authority import Identity
from agentstatus_bridge.federation.codec import CodecError
from agentstatus_bridge.federation.fedstore import FED_DB_NAME, FederatedStore
from agentstatus_bridge.federation.mirror import LocalReport
from agentstatus_bridge.federation.refs import RemoteEndpointRef, TargetRef, WireActor
from agentstatus_bridge.model import EndpointRef, Provider
from agentstatus_bridge.store import StoreError

DEV_A = "a" * 32
DEV_B = "b" * 32
DEV_C = "c" * 32
HUB = "f" * 32
T0 = 1_800_000_000_000
CODEX_B = "019a0000-0000-7000-8000-00000000000b"
CLAUDE_A = "0000000a-1111-4222-8333-444444444444"
CLAUDE_A2 = "0000000a-1111-4222-8333-555555555555"


class Device:
    """一台设备：联邦库、身份与本机端点绑定。"""

    def __init__(self, root: Path, device_id: str, name: str) -> None:
        self.store = FederatedStore.create(root / name, now=T0)
        self.store.set_meta("deviceId", device_id)
        self.store.set_meta("hubId", HUB)
        self.store.set_meta("enabled", "1")  # 夹具代表已启用联邦的设备
        self.ident = Identity(device_id=device_id, device_name=name, hub_id=HUB)

    def bind(self, provider: Provider, native_id: str, *, pid: int = 4242) -> TargetRef:
        local = EndpointRef(provider=provider, native_id=native_id, pid=pid, start_ticks="777", label=native_id[:8])
        endpoint_id, revision = self.store.bind_endpoint(provider=provider.value, native_id=native_id,
                                                         root_binding="root", local_ref=local.to_dict())
        remote = RemoteEndpointRef(device_id=self.ident.device_id, provider=provider, native_id=native_id,
                                   endpoint_id=endpoint_id, endpoint_revision=revision, display_label=native_id[:8])
        return TargetRef(remote=remote, local=local)


def pump(src: Device, dst: Device, *, now: int) -> list[mirror.ReceiveResult]:
    """把 src 发给 dst 的 ready 信封按 outbox 顺序交给 dst（代替 hub + relay）。"""
    results: list[mirror.ReceiveResult] = []
    for item in src.store.outbox():
        envelope = json.loads(item["envelope_json"])
        if envelope["targetDeviceId"] != dst.ident.device_id:
            continue
        results.append(mirror.receive(dst.store, dst.ident, envelope, source_device=src.ident.device_id,
                                      payload_hash=item["payload_hash"], now=now))
        src.store.set_outbox_state(item["msg_id"], state="received")
    return results


def mark_intent(device: Device, msg_id: str, *, now: int) -> None:
    """模拟 worker 在投递前提交 intent（§88.5 P1-1）。"""
    with device.store.transaction() as conn:
        conn.execute("UPDATE fed_native_sends SET state='intent', intent_at=? WHERE msg_id=? AND state='prepared'",
                     (now, msg_id))


def deliver(device: Device, msg_id: str, state: str, *, now: int) -> None:
    """模拟投递完成：intent → finished，并写本机证据回传权威。"""
    mark_intent(device, msg_id, now=now)
    with device.store.transaction() as conn:
        conn.execute("UPDATE fed_native_sends SET state='finished' WHERE msg_id=?", (msg_id,))
        attempt = device.store.attempt_by_msg(msg_id)
        assert attempt is not None
        task = device.store.get_task(attempt.authority_device, attempt.task_id)
        assert task is not None
        mirror.record_evidence(device.store, device.ident, task, attempt, {"state": state, "at": now}, now=now)


class FederationTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        self.a = Device(self.root, DEV_A, "vm")
        self.b = Device(self.root, DEV_B, "win")
        self.origin = self.a.bind(Provider.CLAUDE, CLAUDE_A)
        self.worker = self.b.bind(Provider.CODEX, CODEX_B)
        self.worker_remote = TargetRef(remote=self.worker.remote)  # A 只知道远端形状

    def tearDown(self) -> None:
        self.a.store.close()
        self.b.store.close()
        self._tmp.cleanup()

    def origin_actor(self) -> WireActor:
        return authority.actor_for(self.origin, wire_token="claude@vm")

    def worker_actor(self) -> WireActor:
        return authority.actor_for(self.worker, wire_token="codex@win")

    def create(self, *, flow: str = "handoff", reviewer: TargetRef | None = None, now: int = T0):
        return authority.create_task(
            self.a.store, self.a.ident, title="跨设备任务", flow=flow, body="请修复 X", refs=[],
            origin=self.origin, origin_actor=self.origin_actor(), origin_class="bypass", target=self.worker_remote,
            reviewer=reviewer, now=now,
        )

    def b_report(self, task_id: str, seq: int, kind: str, *, note: str = "", now: int):
        task = self.b.store.get_task(DEV_A, task_id)
        assert task is not None
        attempt = next(item for item in self.b.store.attempts(DEV_A, task_id) if item.seq == seq)
        return mirror.submit_report(self.b.store, self.b.ident, LocalReport(
            task=task, attempt=attempt, kind=kind, note=note, refs=[], commit=None, reporter=self.worker_actor(),
            reporter_class="bypass", source="agent"), now=now)


class StoreTests(FederationTestCase):
    def test_active_tasks_listed_however_many_finished_tombstones_exist(self) -> None:
        # 墓碑永久保留：已结束任务再多也不能挤掉进行中的任务（ab tasks、A 的提醒都靠它，Opus 审计 P2-3）
        old, _ = self.create(now=T0)
        authority.finish(self.a.store, self.a.ident, old, state=CLOSED, reason=None, decider="owner", sender=None,
                         sender_class="unknown", now=T0 + 1)
        with self.a.store.transaction() as conn:
            for index in range(800):
                conn.execute("INSERT INTO fed_tasks(authority_device,task_id,is_authority,revision,current_work_seq,"
                             "max_seq,state_json,last_sync_at,local_archived,sync_required) SELECT authority_device,?,"
                             "is_authority,revision,current_work_seq,max_seq,state_json,?,local_archived,sync_required"
                             " FROM fed_tasks WHERE task_id=?", (f"{index:032x}", T0 + 2 + index, old.task_id))
        active, _ = self.create(now=T0 + 10)
        with self.a.store.transaction() as conn:
            conn.execute("UPDATE fed_tasks SET last_sync_at=? WHERE task_id=?", (T0 - 1, active.task_id))  # 活动最早
        self.assertEqual([task.task_id for task in self.a.store.tasks(authority_only=True, limit=200)],
                         [active.task_id])
        self.assertEqual(len(self.a.store.tasks(include_finished=True, limit=5)), 5)

    def test_open_missing_exists_and_too_new(self) -> None:
        with self.assertRaises(StoreError) as missing:
            FederatedStore.open(self.root / "nowhere")
        self.assertEqual(missing.exception.code, "federation_store_missing")
        self.assertFalse((self.root / "nowhere" / FED_DB_NAME).exists())  # 打开绝不自动建库
        with self.assertRaises(StoreError) as exists:
            FederatedStore.create(self.root / "vm")
        self.assertEqual(exists.exception.code, "federation_store_exists")
        path = self.root / "vm" / FED_DB_NAME
        self.a.store.close()
        with sqlite3.connect(path) as conn:
            conn.execute("PRAGMA user_version=2")
        with self.assertRaises(StoreError) as newer:
            FederatedStore.open(self.root / "vm")
        self.assertEqual(newer.exception.code, "federation_schema_too_new")
        with sqlite3.connect(path) as conn:
            conn.execute("PRAGMA user_version=1")
        self.a.store = FederatedStore.open(self.root / "vm")
        self.assertEqual(self.a.store.device_id(), DEV_A)

    def test_revision_and_idempotent_facts(self) -> None:
        ledger, before = self.a.store.revision()
        task, attempt = self.create()
        ledger2, after = self.a.store.revision()
        self.assertEqual(ledger, ledger2)
        self.assertGreater(after, before)
        self.assertTrue(self.a.store.add_evidence(attempt.msg_id, 1, delivery_device=DEV_B, evidence={"state": "queued"}))
        self.assertFalse(self.a.store.add_evidence(attempt.msg_id, 1, delivery_device=DEV_B, evidence={"state": "queued"}))
        with self.assertRaises(StoreError) as conflict:
            self.a.store.add_evidence(attempt.msg_id, 1, delivery_device=DEV_B, evidence={"state": "failed"})
        self.assertEqual(conflict.exception.code, "idempotency_conflict")
        op = "9" * 32
        self.assertTrue(self.a.store.add_decision(reporter_device=DEV_B, report_operation_id=op, authority_revision=2,
                                                  decision="accepted", reason=None))
        self.assertFalse(self.a.store.add_decision(reporter_device=DEV_B, report_operation_id=op,
                                                   authority_revision=3, decision="rejected", reason="x"))
        self.assertEqual(self.a.store.decision(DEV_B, op)["decision"], "accepted")  # type: ignore[index]
        self.assertEqual(task.revision, 1)

    def test_bind_endpoint_keeps_id_across_recovery(self) -> None:
        first = self.b.store.bind_endpoint(provider="codex", native_id=CODEX_B, root_binding="root",
                                           local_ref={"pid": 1})
        again = self.b.store.bind_endpoint(provider="codex", native_id=CODEX_B, root_binding="root",
                                           local_ref={"pid": 1})
        moved = self.b.store.bind_endpoint(provider="codex", native_id=CODEX_B, root_binding="root",
                                           local_ref={"pid": 2})
        other_root = self.b.store.bind_endpoint(provider="codex", native_id=CODEX_B, root_binding="root2",
                                                local_ref={"pid": 2})
        self.assertEqual(first[0], again[0])
        self.assertEqual((moved[0], moved[1]), (first[0], first[1] + 1))
        self.assertNotEqual(other_root[0], first[0])


class HandoffFlowTests(FederationTestCase):
    def test_handoff_evidence_ack_result_and_auto_review(self) -> None:
        reviewer = self.a.bind(Provider.CLAUDE, CLAUDE_A2)
        task, first = self.create(flow="review", reviewer=reviewer)
        self.assertEqual(len(self.a.store.outbox()), 1)
        self.assertIsNone(self.a.store.native(first.msg_id))  # 远端目标不在 A 建原生作业
        self.assertEqual([r.status for r in pump(self.a, self.b, now=T0 + 1)], ["applied"])
        mirrored = self.b.store.get_task(DEV_A, task.task_id)
        assert mirrored is not None
        self.assertFalse(mirrored.is_authority)
        b_attempt = self.b.store.attempt_by_msg(first.msg_id)
        assert b_attempt is not None
        self.assertIsNotNone(b_attempt.target.local)  # B 用绑定把远端目标映射回本机端点
        self.assertEqual(self.b.store.native(first.msg_id)["state"], "prepared")  # type: ignore[index]
        self.assertEqual(self.b.store.inbox_item(first.msg_id)["apply_state"], "ready")  # type: ignore[index]

        deliver(self.b, first.msg_id, "queued", now=T0 + 2)
        pump(self.b, self.a, now=T0 + 3)
        a_attempt = self.a.store.attempt_by_msg(first.msg_id)
        assert a_attempt is not None
        self.assertEqual(a_attempt.delivery["state"], "queued")
        self.assertEqual(a_attempt.evidence_no, 1)

        ack = self.b_report(task.task_id, 1, "ack", now=T0 + 4)
        self.assertIsNone(ack.decision)  # B 远端报告等 A 裁决
        pump(self.b, self.a, now=T0 + 5)
        self.assertEqual(self.a.store.decision(DEV_B, ack.operation_id)["decision"], "accepted")  # type: ignore[index]
        pump(self.a, self.b, now=T0 + 6)
        self.assertEqual(self.b.store.decision(DEV_B, ack.operation_id)["decision"], "accepted")  # type: ignore[index]

        result = self.b_report(task.task_id, 1, "result", note="已修复", now=T0 + 7)
        self.assertEqual(result.report_no, 2)
        pump(self.b, self.a, now=T0 + 8)
        current = self.a.store.get_task(DEV_A, task.task_id)
        assert current is not None
        self.assertEqual(current.current_work_seq, 2)
        review = next(item for item in self.a.store.attempts(DEV_A, task.task_id) if item.seq == 2)
        self.assertEqual(review.role, "review")
        self.assertIn("已修复", review.body)
        self.assertEqual(self.a.store.native(review.msg_id)["state"], "prepared")  # type: ignore[index]  A 本机复核方
        # B 收到决定与新 checkpoint 后不能再对旧 attempt 报告
        pump(self.a, self.b, now=T0 + 9)
        with self.assertRaises(StoreError) as stale:
            self.b_report(task.task_id, 1, "progress", now=T0 + 10)
        self.assertEqual(stale.exception.code, "stale_attempt")

    def test_report_before_evidence_is_accepted(self) -> None:
        task, first = self.create()
        pump(self.a, self.b, now=T0 + 1)
        mark_intent(self.b, first.msg_id, now=T0 + 2)  # 投递已外调，证据尚未写
        result = self.b_report(task.task_id, 1, "result", note="完成", now=T0 + 3)
        pump(self.b, self.a, now=T0 + 4)
        self.assertEqual(self.a.store.decision(DEV_B, result.operation_id)["decision"], "accepted")  # type: ignore[index]
        a_attempt = self.a.store.attempt_by_msg(first.msg_id)
        assert a_attempt is not None
        self.assertTrue(a_attempt.delivery["receiverReported"])
        self.assertEqual(a_attempt.effective_work["work"], "result_submitted")
        # 发起方在 A 本机：结果通知直接成为本机作业，正文带下一步
        notice = next(item for item in self.a.store.attempts(DEV_A, task.task_id) if item.role == "notice")
        self.assertIn("下一步", notice.body)
        self.assertEqual(notice.target.local, self.origin.local)

    def _remote_report(self, task_id: str, seq: int, kind: str, report_no: int, *, device: str = DEV_B,
                       native: str = CODEX_B, op: str | None = None, provider: Provider = Provider.CODEX,
                       endpoint: str | None = None) -> dict[str, Any]:
        actor = WireActor(device_id=device, provider=provider, native_id=native, wire_token="codex@x",
                          endpoint_id=endpoint or self.worker.remote.endpoint_id)
        return {"authorityDeviceId": DEV_A, "taskId": task_id, "attempt": seq, "reportNo": report_no,
                "operationId": op or (str(report_no) * 32)[:32], "kind": kind, "note": "", "refs": [],
                "reporter": actor.to_dict(), "reporterClass": "bypass", "source": "agent"}

    def test_report_number_conflict_is_a_decision_but_transient_errors_are_not(self) -> None:
        task, _ = self.create()
        apply = authority.apply_report_safely
        first = apply(self.a.store, self.a.ident, self._remote_report(task.task_id, 1, "progress", 5, op="a" * 32),
                      reporter_device=DEV_B, now=T0 + 1)
        self.assertEqual(first.decision, "accepted")
        try:
            with self.a.store.transaction():  # 与真实收件事务同样嵌套：约束冲突要变成确定拒绝（Opus 审计 P3-6）
                clash = apply(self.a.store, self.a.ident,
                              self._remote_report(task.task_id, 1, "progress", 5, op="b" * 32),
                              reporter_device=DEV_B, now=T0 + 2)
        except StoreError as error:  # D11
            self.fail(f"序号冲突没成为确定拒绝：{error.code}")
        self.assertEqual((clash.decision, clash.reason), ("rejected", "report_sequence_conflict"))
        busy = self._remote_report(task.task_id, 1, "progress", 6, op="c" * 32)
        with patch.object(self.a.store, "add_report", side_effect=StoreError("store_busy")):
            try:
                outcome = apply(self.a.store, self.a.ident, busy, reporter_device=DEV_B, now=T0 + 3)
            except StoreError as error:
                self.assertEqual(error.code, "store_busy")  # 暂时故障整轮不提交，等重推再裁决
            else:
                self.fail(f"锁忙被当成业务裁决：{outcome}")
        self.assertIsNone(self.a.store.decision(DEV_B, "c" * 32))

    def test_second_result_after_accepted_result_is_rejected(self) -> None:
        task, _ = self.create()
        apply = authority.apply_report_safely
        self.assertEqual(apply(self.a.store, self.a.ident, self._remote_report(task.task_id, 1, "result", 1),
                               reporter_device=DEV_B, now=T0 + 1).decision, "accepted")
        again = apply(self.a.store, self.a.ident, self._remote_report(task.task_id, 1, "result", 2),
                      reporter_device=DEV_B, now=T0 + 2)
        self.assertEqual((again.decision, again.reason), ("rejected", "result_already_submitted"))

    def test_late_low_number_stale_mismatch_and_finished(self) -> None:
        task, _ = self.create()
        apply = authority.apply_report_safely
        high = apply(self.a.store, self.a.ident, self._remote_report(task.task_id, 1, "progress", 3),
                     reporter_device=DEV_B, now=T0 + 1)
        self.assertEqual(high.decision, "accepted")
        late = apply(self.a.store, self.a.ident, self._remote_report(task.task_id, 1, "result", 2),
                     reporter_device=DEV_B, now=T0 + 2)
        self.assertEqual(late.decision, "superseded")  # 迟到低号只留历史，不覆盖
        a_attempt = next(iter(self.a.store.attempts(DEV_A, task.task_id)))
        self.assertEqual(a_attempt.effective_work["work"], "in_progress")
        wrong = apply(self.a.store, self.a.ident, self._remote_report(task.task_id, 1, "result", 4, device=DEV_C),
                      reporter_device=DEV_C, now=T0 + 3)
        self.assertEqual((wrong.decision, wrong.reason), ("rejected", "reporter_mismatch"))
        self.assertEqual(len(self.a.store.attempts(DEV_A, task.task_id)), 1)  # 拒绝决定不分配 native 通知
        missing = apply(self.a.store, self.a.ident, self._remote_report(task.task_id, 5, "result", 5),
                        reporter_device=DEV_B, now=T0 + 4)
        self.assertEqual(missing.reason, "attempt_not_found")
        again = apply(self.a.store, self.a.ident, self._remote_report(task.task_id, 1, "progress", 3),
                      reporter_device=DEV_B, now=T0 + 5)
        self.assertTrue(again.duplicate)
        self.assertEqual(again.decision, "accepted")
        authority.finish(self.a.store, self.a.ident, task, state=CLOSED, reason="不做了", decider="owner",
                         sender=self.origin_actor(), sender_class="bypass", now=T0 + 6)
        after = apply(self.a.store, self.a.ident, self._remote_report(task.task_id, 1, "result", 6),
                      reporter_device=DEV_B, now=T0 + 7)
        self.assertEqual(after.reason, "task_finished")

    def test_reporter_must_match_every_part_of_the_target_binding(self) -> None:
        task, _ = self.create()
        variants = {
            "device": dict(device=DEV_C), "provider": dict(provider=Provider.CLAUDE),
            "native": dict(native=CODEX_B.replace("b", "c")), "endpoint": dict(endpoint="9" * 32),
        }
        for index, (name, changes) in enumerate(variants.items(), start=1):
            report = self._remote_report(task.task_id, 1, "result", index, op=f"{index:x}" * 32, **changes)  # type: ignore[arg-type]
            decision = authority.apply_report_safely(self.a.store, self.a.ident, report, reporter_device=DEV_B,
                                                     now=T0 + index)
            self.assertEqual((decision.decision, decision.reason), ("rejected", "reporter_mismatch"), name)
        a_attempt = next(iter(self.a.store.attempts(DEV_A, task.task_id)))
        self.assertEqual(a_attempt.effective_work["work"], "awaiting_ack")

    def test_review_rejection_under_real_ingress_rolls_back_result(self) -> None:
        # 真实收件事务包着裁决：内层确定拒绝必须撤回推进（SAVEPOINT），不能把外层提交成 accepted
        grok = RemoteEndpointRef(device_id=DEV_A, provider=Provider.GROK, native_id="grok-1", endpoint_id="e" * 32)
        task, first = self.create(flow="review", reviewer=TargetRef(remote=grok))
        pump(self.a, self.b, now=T0 + 1)
        result = self.b_report(task.task_id, 1, "result", now=T0 + 2)
        pump(self.b, self.a, now=T0 + 3)
        decision = self.a.store.decision(DEV_B, result.operation_id)
        assert decision is not None
        self.assertEqual((decision["decision"], decision["reason"]), ("rejected", "target_no_inbox"))
        attempt = self.a.store.attempt_by_msg(first.msg_id)
        assert attempt is not None
        self.assertEqual(attempt.effective_work["work"], "awaiting_ack")

    def test_review_capacity_missing_inbox_rolls_back(self) -> None:
        grok = RemoteEndpointRef(device_id=DEV_C, provider=Provider.GROK, native_id="grok-1", endpoint_id="e" * 32)
        task, _ = self.create(flow="review", reviewer=TargetRef(remote=grok))
        decision = authority.apply_report_safely(self.a.store, self.a.ident,
                                                 self._remote_report(task.task_id, 1, "result", 1),
                                                 reporter_device=DEV_B, now=T0 + 1)
        self.assertEqual((decision.decision, decision.reason), ("rejected", "target_no_inbox"))
        a_attempt = next(iter(self.a.store.attempts(DEV_A, task.task_id)))
        self.assertEqual(a_attempt.effective_work["work"], "awaiting_ack")  # 推进已回滚
        self.assertEqual(len(self.a.store.reports(DEV_A, task.task_id)), 1)  # 报告事实保留


class CancelAndClosureTests(FederationTestCase):
    def test_cancel_request_is_not_proof_until_b_suppresses(self) -> None:
        task, first = self.create()
        pump(self.a, self.b, now=T0 + 1)
        current, remote_pending = authority.request_cancel(self.a.store, self.a.ident, task, now=T0 + 2)
        self.assertTrue(remote_pending)
        a_attempt = self.a.store.attempt_by_msg(first.msg_id)
        assert a_attempt is not None
        self.assertTrue(a_attempt.cancel_requested)
        self.assertEqual(a_attempt.delivery["state"], "pending")  # 取消请求不等于已证明未投
        self.assertGreater(current.revision, task.revision)
        pump(self.a, self.b, now=T0 + 3)
        self.assertEqual(self.b.store.native(first.msg_id)["state"], "suppressed")  # type: ignore[index]
        pump(self.b, self.a, now=T0 + 4)
        a_attempt = self.a.store.attempt_by_msg(first.msg_id)
        assert a_attempt is not None
        self.assertEqual(a_attempt.delivery["state"], "cancelled")
        self.assertTrue(authority.proven_undelivered(a_attempt, self.a.ident))

    def test_closure_counts_work_that_is_mid_delivery(self) -> None:
        # T09：工作正在外调（intent）时 A 关闭：工作可能已到，结束回执必须投，不能按「未投」免掉（Opus 审计 C3）
        task, first = self.create()
        pump(self.a, self.b, now=T0 + 1)
        mark_intent(self.b, first.msg_id, now=T0 + 2)
        current = self.a.store.get_task(DEV_A, task.task_id)
        assert current is not None
        authority.finish(self.a.store, self.a.ident, current, state=CLOSED, reason=None, decider="owner",
                         sender=None, sender_class="unknown", now=T0 + 3)
        pump(self.a, self.b, now=T0 + 4)
        closures = [item for item in self.b.store.attempts(DEV_A, task.task_id) if item.is_closure]
        self.assertEqual(len(closures), 1)
        native = self.b.store.native(closures[0].msg_id) or {}
        self.assertEqual(native.get("state"), "prepared")

    def test_cancel_after_intent_cannot_suppress(self) -> None:
        task, first = self.create()
        pump(self.a, self.b, now=T0 + 1)
        mark_intent(self.b, first.msg_id, now=T0 + 2)
        authority.request_cancel(self.a.store, self.a.ident, task, now=T0 + 3)
        pump(self.a, self.b, now=T0 + 4)
        self.assertEqual(self.b.store.native(first.msg_id)["state"], "intent")  # type: ignore[index]
        self.assertEqual(self.b.store.outbox(), [])  # 没有伪造的取消证据

    def _accept_and_pump(self, task_id: str, *, now: int) -> authority.FinishOutcome:
        task = self.a.store.get_task(DEV_A, task_id)
        assert task is not None
        outcome = authority.finish(self.a.store, self.a.ident, task, state=ACCEPTED, reason=None, decider="owner",
                                   sender=self.origin_actor(), sender_class="bypass", now=now)
        pump(self.a, self.b, now=now + 1)
        return outcome

    def test_closure_delivered_when_covered_work_was_sent(self) -> None:
        task, first = self.create()
        pump(self.a, self.b, now=T0 + 1)
        deliver(self.b, first.msg_id, "queued", now=T0 + 2)
        outcome = self._accept_and_pump(task.task_id, now=T0 + 10)
        self.assertTrue(outcome.remote_unconfirmed)
        (closure,) = outcome.closures
        self.assertEqual(closure.options["coversWorkMessageIds"], [first.msg_id])
        self.assertEqual(self.b.store.native(closure.msg_id)["state"], "prepared")  # type: ignore[index]
        b_closure = self.b.store.attempt_by_msg(closure.msg_id)
        assert b_closure is not None
        self.assertEqual(b_closure.target.local, self.worker.local)

    def test_closure_suppressed_when_work_never_sent(self) -> None:
        task, first = self.create()
        pump(self.a, self.b, now=T0 + 1)  # B 收到但从未 intent
        outcome = self._accept_and_pump(task.task_id, now=T0 + 10)
        (closure,) = outcome.closures
        self.assertEqual(self.b.store.native(closure.msg_id)["state"], "suppressed")  # type: ignore[index]
        self.assertEqual(self.b.store.native(first.msg_id)["state"], "suppressed")  # type: ignore[index]
        pump(self.b, self.a, now=T0 + 20)
        self.assertEqual(self.a.store.attempt_by_msg(first.msg_id).delivery["state"], "cancelled")  # type: ignore[union-attr]

    def test_closure_alone_applies_its_checkpoint_before_settling(self) -> None:
        task, first = self.create()
        pump(self.a, self.b, now=T0 + 1)  # B 已有任务与未 intent 的工作
        current = self.a.store.get_task(DEV_A, task.task_id)
        assert current is not None
        outcome = authority.finish(self.a.store, self.a.ident, current, state=ACCEPTED, reason=None, decider="owner",
                                   sender=self.origin_actor(), sender_class="bypass", now=T0 + 10)
        (closure,) = outcome.closures
        # 只送结束回执本身（task_state 延迟/丢失）：它携带的 checkpoint 必须先于建作业应用，旧工作随之抑制
        for item in self.a.store.outbox():
            envelope = json.loads(item["envelope_json"])
            if envelope["msg_id"] == closure.msg_id:
                mirror.receive(self.b.store, self.b.ident, envelope, source_device=DEV_A,
                               payload_hash=item["payload_hash"], now=T0 + 11)
        self.assertEqual(self.b.store.native(first.msg_id)["state"], "suppressed")  # type: ignore[index]

    def test_closure_arriving_before_work_suppresses_both(self) -> None:
        task, first = self.create()
        handoff = self.a.store.outbox()[0]
        self.a.store.set_outbox_state(handoff["msg_id"], state="submitting")  # 交接信封还在路上
        outcome = self._accept_and_pump(task.task_id, now=T0 + 10)
        (closure,) = outcome.closures
        self.assertEqual(self.b.store.native(closure.msg_id)["state"], "suppressed")  # type: ignore[index]
        envelope = json.loads(handoff["envelope_json"])
        mirror.receive(self.b.store, self.b.ident, envelope, source_device=DEV_A, payload_hash=handoff["payload_hash"],
                       now=T0 + 20)
        self.assertEqual(self.b.store.native(first.msg_id)["state"], "suppressed")  # type: ignore[index]

    def test_local_target_closure_and_suppression(self) -> None:
        # 目标在 A 本机：不经 hub，取消直接抑制本机未领取的作业
        local_worker = self.a.bind(Provider.CODEX, CODEX_B)
        task, first = authority.create_task(
            self.a.store, self.a.ident, title="本机", flow="handoff", body="b", refs=[], origin=self.origin,
            origin_actor=self.origin_actor(), origin_class="bypass", target=local_worker, reviewer=None, now=T0)
        self.assertEqual(self.a.store.outbox(), [])
        self.assertEqual(self.a.store.native(first.msg_id)["state"], "prepared")  # type: ignore[index]
        _, remote_pending = authority.request_cancel(self.a.store, self.a.ident, task, now=T0 + 1)
        self.assertFalse(remote_pending)
        self.assertEqual(self.a.store.native(first.msg_id)["state"], "suppressed")  # type: ignore[index]
        self.assertEqual(self.a.store.attempt_by_msg(first.msg_id).delivery["state"], "cancelled")  # type: ignore[union-attr]


class CapacityTests(FederationTestCase):
    """T08：联邦库按 §83 同一函数计 60/61/64；容量满只跳后续通知，不回滚已采纳的报告。"""

    def add(self, task_id: str, role: str, *, options: dict[str, Any] | None = None, now: int = T0):
        task = self.a.store.get_task(DEV_A, task_id)
        assert task is not None
        return authority.add_attempt(self.a.store, self.a.ident, task, role=role, target=self.worker_remote,
                                     body="b", refs=[], sender=self.origin_actor(), sender_class="bypass",
                                     options=options, now=now)

    def test_work_reminder_notice_limits(self) -> None:
        task, _ = self.create()
        for _ in range(59):
            self.add(task.task_id, "handoff")
        with self.assertRaises(StoreError) as work:
            self.add(task.task_id, "handoff")
        self.assertEqual(work.exception.code, "capacity_attempts")  # 工作最高 60
        _, reminder = self.add(task.task_id, "notice", options={"noticeKind": "reminder", "reminderToken": "r"})
        self.assertEqual(reminder.seq, 61)
        with self.assertRaises(StoreError):
            self.add(task.task_id, "notice", options={"noticeKind": "reminder", "reminderToken": "r2"})
        for seq in (62, 63, 64):
            _, notice = self.add(task.task_id, "notice", options={"noticeKind": "result"})
            self.assertEqual(notice.seq, seq)  # 62–64 留给终态通知与结束回执
        with self.assertRaises(StoreError):
            self.add(task.task_id, "notice", options={"noticeKind": "result"})

    def test_full_task_still_accepts_report_and_skips_notice(self) -> None:
        task, _ = self.create()
        for _ in range(59):
            self.add(task.task_id, "handoff")
        for _ in range(4):
            self.add(task.task_id, "notice", options={"noticeKind": "result"})
        report = {"authorityDeviceId": DEV_A, "taskId": task.task_id, "attempt": 60, "reportNo": 1,
                  "operationId": "7" * 32, "kind": "result", "note": "", "refs": [],
                  "reporter": self.worker_actor().to_dict(), "reporterClass": "bypass", "source": "agent"}
        try:
            decision = authority.apply_report_safely(self.a.store, self.a.ident, report, reporter_device=DEV_B,
                                                     now=T0 + 1)
        except StoreError as error:
            self.fail(f"容量满只跳过通知，报告本身必须采纳，实际抛出 {error.code}")
        self.assertEqual(decision.decision, "accepted")
        self.assertEqual(decision.skipped, {"result": "capacity_attempts"})
        self.assertEqual(len(self.a.store.reports(DEV_A, task.task_id, 60)), 1)  # 报告事实已持久
        self.assertEqual(len(self.a.store.attempts(DEV_A, task.task_id)), 64)
        rejected = authority.apply_report_safely(self.a.store, self.a.ident, dict(report, operationId="8" * 32,
                                                                                  attempt=1, reportNo=2),
                                                 reporter_device=DEV_B, now=T0 + 2)
        self.assertEqual((rejected.decision, rejected.reason), ("rejected", "stale_attempt"))
        self.assertEqual(len(self.a.store.attempts(DEV_A, task.task_id)), 64)  # 拒绝决定不分配 native 通知

    def test_active_and_pending_caps(self) -> None:
        for index in range(100):
            self.create(now=T0 + index)
        with self.assertRaises(StoreError) as active:
            self.create(now=T0 + 200)
        self.assertEqual(active.exception.code, "capacity_active_tasks")
        tasks = self.a.store.tasks(authority_only=True, limit=200)
        added = 100
        for task in tasks[:4]:
            for _ in range(39):
                self.add(task.task_id, "handoff")
                added += 1
        self.assertEqual(added, 256)
        with self.assertRaises(StoreError) as pending:
            self.add(tasks[5].task_id, "handoff")
        self.assertEqual(pending.exception.code, "capacity_pending")


    def test_finished_tasks_release_pending_slots(self) -> None:
        tasks = [self.create(now=T0 + index)[0] for index in range(64)]
        for task in tasks:
            for _ in range(3):
                self.add(task.task_id, "handoff")  # 64 个任务各 4 个远端未回证据的 attempt = 256
        with self.assertRaises(StoreError) as full:
            self.create(now=T0 + 500)
        self.assertEqual(full.exception.code, "capacity_pending")
        current = self.a.store.get_task(DEV_A, tasks[0].task_id)
        assert current is not None
        authority.finish(self.a.store, self.a.ident, current, state=CLOSED, reason=None, decider="owner",
                         sender=None, sender_class="unknown", now=T0 + 600)  # 对方离线/换 hub：关闭旧任务释放名额
        try:
            self.create(now=T0 + 700)
        except StoreError as error:  # D11
            self.fail(f"关闭的任务仍占 pending 名额：{error.code}")


class MirrorRuleTests(FederationTestCase):
    def test_checkpoint_revision_rules(self) -> None:
        task, _ = self.create()
        pump(self.a, self.b, now=T0 + 1)
        checkpoint = authority.build_checkpoint(*self._authority_view(task.task_id))
        with self.b.store.transaction():
            _, changed = mirror.apply_checkpoint(self.b.store, checkpoint, now=T0 + 2)
        self.assertFalse(changed)  # 同 revision 同内容：幂等
        tampered = type(checkpoint)(**{**checkpoint.__dict__, "title": "被改"})
        with self.assertRaises(StoreError) as conflict, self.b.store.transaction():
            mirror.apply_checkpoint(self.b.store, tampered, now=T0 + 3)
        self.assertEqual(conflict.exception.code, "idempotency_conflict")
        authority.set_paused(self.a.store, self.a.ident, task, paused=True, now=T0 + 4)
        pump(self.a, self.b, now=T0 + 5)
        mirrored = self.b.store.get_task(DEV_A, task.task_id)
        assert mirrored is not None
        self.assertTrue(mirrored.paused)
        with self.b.store.transaction():
            _, changed = mirror.apply_checkpoint(self.b.store, checkpoint, now=T0 + 6)
        self.assertFalse(changed)  # 低 revision 不覆盖
        self.assertTrue(self.b.store.get_task(DEV_A, task.task_id).paused)  # type: ignore[union-attr]

    def _authority_view(self, task_id: str):
        task = self.a.store.get_task(DEV_A, task_id)
        assert task is not None
        return task, self.a.store.attempts(DEV_A, task_id)

    def test_cancel_checkpoint_before_handoff_keeps_handoff_suppressed(self) -> None:
        task, first = self.create()
        authority.request_cancel(self.a.store, self.a.ident, task, now=T0 + 1)
        items = self.a.store.outbox()
        state = next(item for item in items if json.loads(item["envelope_json"])["kind"] == "task_state")
        handoff = next(item for item in items if item["msg_id"] == first.msg_id)
        for item in (state, handoff):  # 取消的 checkpoint 先到、原 handoff 后到
            mirror.receive(self.b.store, self.b.ident, json.loads(item["envelope_json"]), source_device=DEV_A,
                           payload_hash=item["payload_hash"], now=T0 + 2)
        self.assertEqual(self.b.store.native(first.msg_id)["state"], "suppressed")  # type: ignore[index]

    def test_decision_from_another_authority_cannot_settle_a_report(self) -> None:
        task, _ = self.create()
        pump(self.a, self.b, now=T0 + 1)
        report = self.b_report(task.task_id, 1, "result", now=T0 + 2)
        message, digest = envelopes.build(kind="report_decision", target_device=DEV_B, authority_device=DEV_C,
                                          task_id=task.task_id, revision=1, now=T0 + 3, attempt=1,
                                          data={"reportOperationId": report.operation_id, "decision": "accepted"})
        try:
            mirror.receive(self.b.store, self.b.ident, message, source_device=DEV_C, payload_hash=digest, now=T0 + 4)
        except (CodecError, StoreError):
            pass
        self.assertIsNone(self.b.store.decision(DEV_B, report.operation_id))  # C 不能裁决 B 交给 A 的报告
        pump(self.b, self.a, now=T0 + 5)
        pump(self.a, self.b, now=T0 + 6)
        decision = self.b.store.decision(DEV_B, report.operation_id)
        self.assertEqual((decision or {}).get("decision"), "accepted")  # A 的真实决定照常落账

    def test_duplicate_and_conflicting_operation(self) -> None:
        self.create()
        item = self.a.store.outbox()[0]
        envelope = json.loads(item["envelope_json"])
        first = mirror.receive(self.b.store, self.b.ident, envelope, source_device=DEV_A,
                               payload_hash=item["payload_hash"], now=T0 + 1)
        try:
            again = mirror.receive(self.b.store, self.b.ident, envelope, source_device=DEV_A,
                                   payload_hash=item["payload_hash"], now=T0 + 2)
        except Exception as error:  # noqa: BLE001 - 合同就是「重放幂等返回 duplicate」，抛错同样不合格
            self.fail(f"重复信封必须幂等返回 duplicate 以便重发 L2，实际抛出 {error!r}")
        self.assertEqual((first.status, again.status), ("applied", "duplicate"))
        with self.assertRaises(CodecError) as conflict:
            mirror.receive(self.b.store, self.b.ident, envelope, source_device=DEV_A, payload_hash="0" * 64,
                           now=T0 + 3)
        self.assertEqual(conflict.exception.code, "idempotency_conflict")

    def test_non_authority_source_and_wrong_destination(self) -> None:
        task, _ = self.create()
        item = self.a.store.outbox()[0]
        envelope = json.loads(item["envelope_json"])
        with self.assertRaises(CodecError) as forged:
            mirror.receive(self.b.store, self.b.ident, envelope, source_device=DEV_C,
                           payload_hash=item["payload_hash"], now=T0 + 1)
        self.assertEqual(forged.exception.code, "identity_mismatch")
        self.assertIsNone(self.b.store.get_task(DEV_A, task.task_id))  # 拒绝不留半截镜像
        with self.assertRaises(CodecError) as wrong:
            mirror.receive(self.a.store, self.a.ident, envelope, source_device=DEV_A,
                           payload_hash=item["payload_hash"], now=T0 + 2)
        self.assertEqual(wrong.exception.code, "destination_unknown")

    def test_forged_decision_without_checkpoint_rejected(self) -> None:
        # 不带 checkpoint 的决定只能靠来源核验挡住：C 冒充 A 给 B 的报告下「已采纳」
        task, _ = self.create()
        pump(self.a, self.b, now=T0 + 1)
        result = self.b_report(task.task_id, 1, "result", now=T0 + 2)
        forged, digest = envelopes.build(
            kind="report_decision", target_device=DEV_B, authority_device=DEV_A, task_id=task.task_id, revision=9,
            now=T0 + 3, data={"reportOperationId": result.operation_id, "decision": "accepted", "reason": None})
        with self.assertRaises(CodecError) as caught:
            mirror.receive(self.b.store, self.b.ident, forged, source_device=DEV_C, payload_hash=digest, now=T0 + 4)
        self.assertEqual(caught.exception.code, "identity_mismatch")
        self.assertIsNone(self.b.store.decision(DEV_B, result.operation_id))

    def test_frozen_terminal_report_and_narrow_sync(self) -> None:
        task, _ = self.create()
        pump(self.a, self.b, now=T0 + 1)
        result = self.b_report(task.task_id, 1, "result", note="x", now=T0 + 2)
        with self.assertRaises(StoreError) as pending:
            self.b_report(task.task_id, 1, "failed", now=T0 + 3)
        self.assertEqual(pending.exception.code, "report_pending")  # 终态报告未裁决前冻结
        # 报告信封丢了：B 发窄同步，A 回 not_seen；补发后再同步拿到 accepted
        report_item = self.b.store.outbox()[0]
        self.b.store.set_outbox_state(report_item["msg_id"], state="submitting")
        b_task = self.b.store.get_task(DEV_A, task.task_id)
        assert b_task is not None
        sync, digest = envelopes.build(
            kind="sync_request", target_device=DEV_A, authority_device=DEV_A, task_id=task.task_id,
            revision=b_task.revision, now=T0 + 4,
            data={"pending": [{"operationId": result.operation_id, "attempt": 1, "reportNo": result.report_no}]})
        mirror.receive(self.a.store, self.a.ident, sync, source_device=DEV_B, payload_hash=digest, now=T0 + 5)
        pump(self.a, self.b, now=T0 + 6)
        events = [item["kind"] for item in self.b.store.events(DEV_A, task.task_id)]
        self.assertIn("report_not_seen", events)
        envelope = json.loads(report_item["envelope_json"])
        mirror.receive(self.a.store, self.a.ident, envelope, source_device=DEV_B,
                       payload_hash=report_item["payload_hash"], now=T0 + 7)
        pump(self.a, self.b, now=T0 + 8)
        self.assertEqual(self.b.store.decision(DEV_B, result.operation_id)["decision"], "accepted")  # type: ignore[index]
        with self.assertRaises(StoreError) as finalized:
            self.b_report(task.task_id, 1, "failed", now=T0 + 9)
        self.assertEqual(finalized.exception.code, "attempt_report_finalized")


if __name__ == "__main__":
    unittest.main()
