"""§97 镜像读时推导 work、镜像阶段规则与跨设备投递细节（DESIGN §97）。

两台设备各一个联邦库，内存泵代替 hub（夹具来自 test_bridge_federation_rules）。差分预言机用随机报告序列同时
驱动真实的 A 裁决（_accept_report）与镜像推导，逐步比对并断言 §97.2 第 1 条的不变量。
"""

from __future__ import annotations

import json
import random
import sqlite3
import unittest
from pathlib import Path
from typing import Any

import bridge_support  # noqa: F401  导入即隔离宿主会话环境

from agentstatus_bridge import cli
from agentstatus_bridge.cli import EXIT_OK, _wait_outcome  # pyright: ignore[reportPrivateUsage]
from agentstatus_bridge.federation import authority, commands, mirror
from agentstatus_bridge.federation.delivery import FederationDispatcher
from agentstatus_bridge.federation.config import FederationConfig
from agentstatus_bridge.federation.errors import FedCliError
from agentstatus_bridge.federation.fedstore import now_ms
from agentstatus_bridge.federation.mirror import LocalReport
from agentstatus_bridge.federation.refs import TargetRef
from agentstatus_bridge.federation.relay import RelayPaths
from agentstatus_bridge.federation.views import derive_work, fold_report, steer_detail
from agentstatus_bridge.model import Delivery, Provider, ReportKind
from agentstatus_bridge.store import StoreError
from agentstatus_bridge.transports import DeliveryOutcome, codex_rpc
from bridge_support import RecordingTransport

from test_bridge_federation_cli import LOCAL_REVIEW, ORIGIN, THREAD_B, WORKER, FedCliCase, as_agent
from test_bridge_federation_delivery import DeliveryTestCase
from test_bridge_federation_relay import RelayTestCase
from test_bridge_federation_rules import CLAUDE_A2, DEV_A, DEV_B, T0, FederationTestCase, deliver, pump


def runtime(device: Any, root: Path, *, enabled: bool = True) -> commands.Runtime:
    """status 文档用到 store/ident/paths；config 只用到 enabled（停用时不打汇报页脚，§98 r1）。"""
    config = FederationConfig(enabled=enabled, hub_id=device.ident.hub_id, device_id=device.ident.device_id,
                              device_name=device.ident.device_name, host="hub.example", user="ab-relay",
                              expected_state_root=str(root))
    return commands.Runtime(root=root, config=config, store=device.store, ident=device.ident, paths=RelayPaths(root))


def document(device: Any, root: Path, task_id: str, now: int) -> dict[str, Any]:
    task = device.store.get_task(DEV_A, task_id)
    assert task is not None
    return commands.task_document(runtime(device, root), task, now=now)


def lines(device: Any, root: Path, task_id: str, now: int) -> str:
    task = device.store.get_task(DEV_A, task_id)
    assert task is not None
    return "\n".join(commands.task_lines(runtime(device, root), task, now=now))


def raw_work(device: Any, msg_id: str) -> str:
    """账本原始列（另开连接读已提交值）：§97.2 第 3 条要求它保持不变。"""
    with sqlite3.connect(device.store.path) as conn:
        text = conn.execute("SELECT effective_work_json FROM fed_attempts WHERE msg_id=?", (msg_id,)).fetchone()[0]
    return json.loads(text)["work"]


def raw_delivery(device: Any, msg_id: str) -> dict[str, Any]:
    """投递列的账本原值：显示副本置的 receiverReported 不得写回（§97.2 第 4 条 r2）。"""
    with sqlite3.connect(device.store.path) as conn:
        text = conn.execute("SELECT delivery_json FROM fed_attempts WHERE msg_id=?", (msg_id,)).fetchone()[0]
    return json.loads(text)


def fact(kind: str, note: str = "") -> dict[str, Any]:
    return {"kind": kind, "note": note, "refs": [], "source": "agent"}


class FoldTests(unittest.TestCase):
    """共用折叠函数与推导函数本身（纯函数）。"""

    def test_ack_only_advances_from_awaiting_ack(self) -> None:
        start = {"work": "awaiting_ack"}
        acked = fold_report(start, ReportKind.ACK, result={}, at=5)
        self.assertEqual(acked, {"work": "acknowledged", "at": 5})
        progressed = fold_report(acked, ReportKind.PROGRESS, result={}, at=6)
        self.assertEqual(fold_report(progressed, ReportKind.ACK, result={}, at=7), progressed)  # 迟到的 ack 不倒退
        blocked = fold_report(start, ReportKind.BLOCKED, result={}, at=8)
        self.assertEqual(fold_report(blocked, ReportKind.ACK, result={}, at=9)["work"], "blocked")

    def test_terminal_reports_carry_result_and_no_time_without_at(self) -> None:
        folded = fold_report({"work": "acknowledged"}, ReportKind.APPROVE, result={"note": "通过"}, at=None)
        self.assertEqual(folded, {"work": "result_submitted", "result": {"note": "通过"}})
        self.assertEqual(fold_report({"work": "in_progress"}, ReportKind.FAILED, result={"note": "x"}, at=None),
                         {"work": "failure_reported", "result": {"note": "x"}})

    def test_known_rejected_report_is_never_promoted_by_report_high(self) -> None:
        rows = [(1, fact("ack"), "accepted"), (2, fact("result", "完成"), "rejected")]
        self.assertEqual(derive_work("handoff", rows, report_high=2), {"work": "acknowledged"})

    def test_report_high_counts_only_the_undecided_report_with_that_number(self) -> None:
        rows = [(1, fact("ack"), "accepted"), (2, fact("progress"), None), (3, fact("result", "完成"), None)]
        self.assertEqual(derive_work("handoff", rows, report_high=2)["work"], "in_progress")
        self.assertEqual(derive_work("handoff", rows, report_high=0)["work"], "acknowledged")
        self.assertEqual(derive_work("handoff", rows, report_high=4)["work"], "acknowledged")  # 本机没有 #4

    def test_folding_stops_at_the_first_undecided_report(self) -> None:
        # r1：只折叠连续前缀。#1 决定未知时，后面已采纳的 #2 也暂不计入（否则会拼出 A 从没有过的 acknowledged）
        for first in ("progress", "blocked"):
            with self.subTest(first=first):
                rows = [(1, fact(first), None), (2, fact("ack"), "accepted")]
                self.assertEqual(derive_work("handoff", rows, report_high=0), {"work": "awaiting_ack"})
                self.assertEqual(derive_work("handoff", rows, report_high=2), {"work": "awaiting_ack"})  # 兜底也要前缀
                self.assertEqual(derive_work("handoff", rows, report_high=1)["work"],
                                 "in_progress" if first == "progress" else "blocked")
        rows = [(1, fact("ack"), "accepted"), (2, fact("result"), "rejected"), (3, fact("progress"), "accepted")]
        self.assertEqual(derive_work("handoff", rows, report_high=0)["work"], "in_progress")  # 已知被拒不打断前缀

    def test_superseded_report_does_not_stop_the_prefix(self) -> None:
        # 乱序到达：#2 先被采纳，迟到的 #1 判 superseded；镜像越过 #1 继续计入 #2（两方 r0 审计 N4/O2）
        rows = [(1, fact("progress"), "superseded"), (2, fact("result", "完成"), "accepted")]
        self.assertEqual(derive_work("handoff", rows, report_high=0),
                         {"work": "result_submitted", "result": {"note": "完成", "refs": [], "source": "agent"}})

    def test_unknown_kind_or_decision_stops_the_prefix(self) -> None:
        rows = [(2, fact("blocked"), "superseded"), (1, fact("ack"), "accepted"), (3, fact("future"), "accepted"),
                (4, fact("progress"), "pending")]
        self.assertEqual(derive_work("handoff", rows, report_high=0), {"work": "acknowledged"})
        # r2：不认识的报告类别不知道 A 怎么折叠，停下而不是跳过；不认识的决定取值同样停下
        self.assertEqual(derive_work("handoff", [(1, fact("future"), "accepted"), (2, fact("ack"), "accepted")],
                                     report_high=0), {"work": "awaiting_ack"})
        self.assertEqual(derive_work("handoff", [(1, fact("ack"), "pending"), (2, fact("progress"), "accepted")],
                                     report_high=0), {"work": "awaiting_ack"})

    def test_reports_fold_in_report_number_order(self) -> None:
        rows = [(3, fact("result", "完成"), "accepted"), (1, fact("ack"), "accepted"), (2, fact("progress"), "accepted")]
        derived = derive_work("handoff", rows, report_high=0)
        self.assertEqual((derived["work"], derived["result"]["note"]), ("result_submitted", "完成"))

    def test_notice_never_tracks_work(self) -> None:
        self.assertEqual(derive_work("notice", [(1, fact("result"), "accepted")], report_high=1), {"work": "none"})


class _MirrorCase(FederationTestCase):
    """镜像用例共用的步骤：建任务、B 投递、B 汇报并往返一次。"""

    def delivered(self, **kw: Any) -> tuple[Any, Any]:
        task, first = self.create(**kw)
        pump(self.a, self.b, now=T0 + 1)
        deliver(self.b, first.msg_id, "queued", now=T0 + 2)
        pump(self.b, self.a, now=T0 + 3)
        return task, first

    def round_trip(self, task_id: str, kind: str, now: int, *, note: str = "") -> None:
        self.b_report(task_id, 1, kind, note=note, now=now)
        pump(self.b, self.a, now=now + 1)
        pump(self.a, self.b, now=now + 2)

    def view(self, device: Any, task_id: str) -> Any:
        task = device.store.get_task(DEV_A, task_id)
        assert task is not None
        return commands.view_of(runtime(device, self.root), task)


class MirrorStatusTests(_MirrorCase):
    """调研探针 a1/a2/a4 反转：镜像上的 status、tasks 与 wait 改读推导值，A 侧与原始列不变。"""

    def test_ack_accepted_shows_acknowledged_on_the_mirror(self) -> None:
        task, first = self.delivered()
        before = self.view(self.b, task.task_id)
        self.assertIsNone(_wait_outcome(before, "ack"))  # 采纳之前镜像上照旧等
        self.round_trip(task.task_id, "ack", T0 + 4)
        b_doc = document(self.b, self.root, task.task_id, T0 + 7)
        self.assertEqual((b_doc["phase"], b_doc["reason"], b_doc["attempts"][0]["work"]),
                         ("running", "acknowledged", "acknowledged"))
        self.assertEqual([(row["kind"], row["decision"]) for row in b_doc["reports"]], [("ack", "accepted")])
        self.assertIn("对方已开始处理", lines(self.b, self.root, task.task_id, T0 + 7))
        self.assertEqual(raw_work(self.b, first.msg_id), "awaiting_ack")  # 原始列不改
        a_doc = document(self.a, self.root, task.task_id, T0 + 7)
        self.assertEqual((a_doc["phase"], a_doc["reason"], a_doc["attempts"][0]["work"]),
                         ("running", "acknowledged", "acknowledged"))
        self.assertEqual(_wait_outcome(self.view(self.b, task.task_id), "ack"), EXIT_OK)

    def test_blocked_then_result_follow_the_authority(self) -> None:
        task, first = self.delivered()
        self.round_trip(task.task_id, "blocked", T0 + 4, note="缺权限")
        b_doc = document(self.b, self.root, task.task_id, T0 + 7)
        self.assertEqual((b_doc["phase"], b_doc["reason"]), ("needs_attention", "blocked_reported"))
        self.round_trip(task.task_id, "result", T0 + 8, note="已修复")
        a_doc, b_doc = (document(self.a, self.root, task.task_id, T0 + 11),
                        document(self.b, self.root, task.task_id, T0 + 11))
        self.assertEqual((b_doc["phase"], b_doc["reason"], b_doc["attempts"][0]["work"]),
                         (a_doc["phase"], a_doc["reason"], a_doc["attempts"][0]["work"]))
        self.assertEqual(b_doc["reason"], "result_ready")
        self.assertEqual(_wait_outcome(self.view(self.b, task.task_id), "result"), EXIT_OK)
        b_attempt = commands.display_attempts(runtime(self.b, self.root), self.b.store.get_task(DEV_A, task.task_id))[0]  # type: ignore[arg-type]
        self.assertEqual(b_attempt.effective_work["result"]["note"], "已修复")
        self.assertEqual(raw_work(self.b, first.msg_id), "awaiting_ack")

    def test_row_work_after_accept_is_the_last_accepted_report(self) -> None:
        task, _ = self.delivered()
        self.round_trip(task.task_id, "result", T0 + 4, note="完成")
        current = self.a.store.get_task(DEV_A, task.task_id)
        assert current is not None
        authority.finish(self.a.store, self.a.ident, current, state="accepted", reason=None, decider="origin",
                         sender=self.origin_actor(), sender_class="bypass", now=T0 + 8)
        pump(self.a, self.b, now=T0 + 9)
        b_doc = document(self.b, self.root, task.task_id, T0 + 10)
        self.assertEqual((b_doc["phase"], b_doc["reason"], b_doc["attempts"][0]["work"]),
                         ("done", "accepted", "result_submitted"))

    def test_lost_decision_is_recovered_by_report_high(self) -> None:
        task, first = self.delivered()
        self.round_trip(task.task_id, "ack", T0 + 4)
        self.b_report(task.task_id, 1, "progress", now=T0 + 10)
        pump(self.b, self.a, now=T0 + 11)
        for item in self.a.store.outbox():  # 决定信封丢失：只到了一封 task_state（带新的 reportHigh）
            if json.loads(item["envelope_json"])["kind"] == "report_decision":
                self.a.store.set_outbox_state(item["msg_id"], state="expired")
        current = self.a.store.get_task(DEV_A, task.task_id)
        assert current is not None
        with self.a.store.transaction():
            authority.send_task_state(self.a.store, self.a.ident, current, now=T0 + 12)
        pump(self.a, self.b, now=T0 + 13)
        rows = self.b.store.reports(DEV_A, task.task_id, 1)
        self.assertIsNone(self.b.store.decision(DEV_B, rows[-1]["operation_id"]))
        self.assertEqual(self.a.store.attempt_by_msg(first.msg_id).effective_work["work"], "in_progress")  # type: ignore[union-attr]
        self.assertEqual(document(self.b, self.root, task.task_id, T0 + 14)["attempts"][0]["work"], "in_progress")

    def test_receiver_reported_follows_the_authority_on_the_display_copy(self) -> None:
        # r2：本机投递 unknown/failed 时，A 采纳报告会在派生视图里写 receiverReported，阶段改按 work 判；镜像的显示副本
        # 同口径。还没有被采纳的报告时照旧显示投递异常，账本原值不写入这个键
        for state in ("unknown", "failed"):
            with self.subTest(state=state):
                self.tearDown()
                self.setUp()
                task, first = self.create()
                pump(self.a, self.b, now=T0 + 1)
                deliver(self.b, first.msg_id, state, now=T0 + 2)
                pump(self.b, self.a, now=T0 + 3)
                b_doc = document(self.b, self.root, task.task_id, T0 + 3)
                self.assertEqual((b_doc["phase"], b_doc["reason"], b_doc["attempts"][0]["receiverReported"]),
                                 ("needs_attention", f"delivery_{state}", False))
                self.b_report(task.task_id, 1, "ack", now=T0 + 3)  # 交了但还没送到 A：本机交过报告不等于被采纳
                b_doc = document(self.b, self.root, task.task_id, T0 + 3)
                self.assertEqual((b_doc["phase"], b_doc["reason"], b_doc["attempts"][0]["receiverReported"]),
                                 ("needs_attention", f"delivery_{state}", False))
                for kind, expected in (("ack", ("running", "acknowledged")),
                                       ("result", ("awaiting_acceptance", "result_ready"))):
                    self.round_trip(task.task_id, kind, T0 + 4 + 10 * (kind == "result"))
                    a_doc = document(self.a, self.root, task.task_id, T0 + 20)
                    b_doc = document(self.b, self.root, task.task_id, T0 + 20)
                    self.assertEqual((a_doc["phase"], a_doc["reason"]), expected, kind)
                    self.assertEqual((b_doc["phase"], b_doc["reason"]), expected, kind)
                    self.assertEqual((b_doc["attempts"][0]["delivery"], b_doc["attempts"][0]["receiverReported"]),
                                     (state, True), kind)
                    self.assertIn("对方已汇报", lines(self.b, self.root, task.task_id, T0 + 20))
                    self.assertNotIn("receiverReported", raw_delivery(self.b, first.msg_id))

    def test_receiver_reported_stays_off_while_the_prefix_is_stopped(self) -> None:
        # Opus r2 复核 P3-r2-1：本机投递 unknown；progress 被采纳但决定丢失，之后 ack 被采纳且决定送达。前缀停在 #1 之前、
        # 推导仍是 awaiting_ack，A 从没有过「awaiting_ack 且已汇报」，所以不能只因有 accepted 决定就置 receiverReported
        task, first = self.create()
        pump(self.a, self.b, now=T0 + 1)
        deliver(self.b, first.msg_id, "unknown", now=T0 + 2)
        pump(self.b, self.a, now=T0 + 3)
        self.b_report(task.task_id, 1, "progress", now=T0 + 4)
        pump(self.b, self.a, now=T0 + 5)
        for item in self.a.store.outbox():
            if json.loads(item["envelope_json"])["kind"] == "report_decision":
                self.a.store.set_outbox_state(item["msg_id"], state="expired")
        self.round_trip(task.task_id, "ack", T0 + 6)
        b_doc = document(self.b, self.root, task.task_id, T0 + 9)
        row = b_doc["attempts"][0]
        self.assertEqual([(item["kind"], item["decision"]) for item in b_doc["reports"]],
                         [("progress", None), ("ack", "accepted")])
        self.assertEqual((row["work"], b_doc["phase"], b_doc["reason"], row["receiverReported"]),
                         ("awaiting_ack", "needs_attention", "delivery_unknown", False))

    def test_o2_out_of_order_superseded_converges(self) -> None:
        # Opus 审计 O2：B 的 #1 progress 与 #2 ack 乱序到 A（#2 先到被采纳、#1 判 superseded）。#1 的决定没送到时镜像停在
        # #1 之前（awaiting_ack）；窄同步补回 superseded 后越过 #1，与 A 一致（superseded 不能打断前缀）
        task, first = self.delivered()
        self.b_report(task.task_id, 1, "progress", now=T0 + 4)
        self.b_report(task.task_id, 1, "ack", now=T0 + 5)
        items = [item for item in self.b.store.outbox() if json.loads(item["envelope_json"])["kind"] == "report"]
        for item in reversed(items):  # #2 先到 A
            mirror.receive(self.a.store, self.a.ident, json.loads(item["envelope_json"]), source_device=DEV_B,
                           payload_hash=item["payload_hash"], now=T0 + 6)
            self.b.store.set_outbox_state(item["msg_id"], state="received")
        self.assertEqual(self.a.store.attempt_by_msg(first.msg_id).effective_work["work"], "acknowledged")  # type: ignore[union-attr]
        for item in self.a.store.outbox():  # 只送到 #2 的 accepted 决定（若 A 也推送了 #1 的决定，这里让它丢失）
            data = json.loads(item["envelope_json"])
            if data["kind"] == "report_decision" and data["data"]["decision"] != "accepted":
                self.a.store.set_outbox_state(item["msg_id"], state="expired")
        pump(self.a, self.b, now=T0 + 7)
        self.assertEqual(document(self.b, self.root, task.task_id, T0 + 8)["attempts"][0]["work"], "awaiting_ack")
        mirrored = self.b.store.get_task(DEV_A, task.task_id)
        assert mirrored is not None
        mirror.request_sync(self.b.store, self.b.ident, mirrored, now=T0 + 9)
        pump(self.b, self.a, now=T0 + 10)
        pump(self.a, self.b, now=T0 + 11)
        b_doc = document(self.b, self.root, task.task_id, T0 + 12)
        self.assertEqual([(row["kind"], row["decision"]) for row in b_doc["reports"]],
                         [("progress", "superseded"), ("ack", "accepted")])
        self.assertEqual(b_doc["attempts"][0]["work"], "acknowledged")

    def test_out_of_order_superseded_decision_reaches_the_mirror_without_sync(self) -> None:
        # §97.2 第 4 条 r2：A 判 superseded 时也发回决定，镜像只凭决定信封就越过迟到的 #1；随后到的窄同步回答再给出
        # 同一取值无害（决定表先写者赢）
        task, first = self.delivered()
        self.b_report(task.task_id, 1, "progress", now=T0 + 4)
        self.b_report(task.task_id, 1, "ack", now=T0 + 5)
        items = [item for item in self.b.store.outbox() if json.loads(item["envelope_json"])["kind"] == "report"]
        for item in reversed(items):  # #2 先到 A
            mirror.receive(self.a.store, self.a.ident, json.loads(item["envelope_json"]), source_device=DEV_B,
                           payload_hash=item["payload_hash"], now=T0 + 6)
            self.b.store.set_outbox_state(item["msg_id"], state="received")
        mirrored = self.b.store.get_task(DEV_A, task.task_id)
        assert mirrored is not None
        mirror.request_sync(self.b.store, self.b.ident, mirrored, now=T0 + 7)  # B 此时还不知道两条的决定
        pump(self.b, self.a, now=T0 + 8)
        outgoing = [(json.loads(item["envelope_json"]), item) for item in self.a.store.outbox()]
        self.assertEqual(sorted(envelope["kind"] for envelope, _ in outgoing),
                         ["report_decision", "report_decision", "sync_state"])
        rows: list[Any] = []
        for kind in ("report_decision", "sync_state"):  # 先只送决定信封，再送窄同步回答
            for envelope, item in outgoing:
                if envelope["kind"] == kind:
                    mirror.receive(self.b.store, self.b.ident, envelope, source_device=DEV_A,
                                   payload_hash=item["payload_hash"], now=T0 + 9)
                    self.a.store.set_outbox_state(item["msg_id"], state="received")
            rows.append(self.b.store.decision(DEV_B, json.loads(items[0]["envelope_json"])["operationId"]))
            self.assertEqual((rows[-1] or {}).get("decision"), "superseded", kind)
            self.assertEqual(document(self.b, self.root, task.task_id, T0 + 10)["attempts"][0]["work"], "acknowledged",
                             kind)
        self.assertEqual(rows[0], rows[1])  # 窄同步回答没有改写已有的决定行
        self.assertEqual(self.a.store.attempt_by_msg(first.msg_id).effective_work["work"], "acknowledged")  # type: ignore[union-attr]

    def test_mirror_stops_at_the_first_report_without_a_decision(self) -> None:
        # r1（§97.2 第 1 条）：只折叠连续前缀。先交的 progress/blocked 被 A 采纳但决定丢失、后交的 ack 被采纳并送达时，
        # A 因 ACK 规则停在 in_progress/blocked；镜像停在 #1 之前，显示 awaiting_ack（A 真实有过的状态），不得显示
        # 「对方已开始处理」，wait --until ack 也不得返回 0；窄同步补回后与 A 一致
        for first_kind, final in (("progress", "in_progress"), ("blocked", "blocked")):
            with self.subTest(first=first_kind):
                self.tearDown()
                self.setUp()
                task, first = self.delivered()
                self.b_report(task.task_id, 1, first_kind, now=T0 + 4)
                pump(self.b, self.a, now=T0 + 5)
                for item in self.a.store.outbox():
                    if json.loads(item["envelope_json"])["kind"] == "report_decision":
                        self.a.store.set_outbox_state(item["msg_id"], state="expired")
                self.round_trip(task.task_id, "ack", T0 + 6)
                self.assertEqual(self.a.store.attempt_by_msg(first.msg_id).effective_work["work"], final)  # type: ignore[union-attr]
                b_doc = document(self.b, self.root, task.task_id, T0 + 9)
                self.assertEqual((b_doc["attempts"][0]["work"], b_doc["reason"]), ("awaiting_ack", "awaiting_ack"))
                self.assertEqual([(row["kind"], row["decision"]) for row in b_doc["reports"]],
                                 [(first_kind, None), ("ack", "accepted")])
                self.assertNotIn("对方已开始处理", lines(self.b, self.root, task.task_id, T0 + 9))
                self.assertIsNone(_wait_outcome(self.view(self.b, task.task_id), "ack"))
                mirrored = self.b.store.get_task(DEV_A, task.task_id)
                assert mirrored is not None
                mirror.request_sync(self.b.store, self.b.ident, mirrored, now=T0 + 10)
                pump(self.b, self.a, now=T0 + 11)
                pump(self.a, self.b, now=T0 + 12)
                self.assertEqual(document(self.b, self.root, task.task_id, T0 + 13)["attempts"][0]["work"], final)

    def test_report_high_counts_per_attempt(self) -> None:
        # 按尝试计（§97.2 第 1 条）：返工派回 B 的新尝试从 awaiting_ack 起算，reportHigh 兜底只看本尝试
        task, first = self.delivered()
        self.round_trip(task.task_id, "blocked", T0 + 4, note="缺权限")
        current = self.a.store.get_task(DEV_A, task.task_id)
        assert current is not None
        outcome = authority.retry_task(self.a.store, self.a.ident, current, force=False, message=None,
                                       new_target=None, rework_body=lambda *args: "返工", now=T0 + 8)
        pump(self.a, self.b, now=T0 + 9)
        deliver(self.b, outcome.attempt.msg_id, "queued", now=T0 + 10)
        pump(self.b, self.a, now=T0 + 11)
        rows = [row for row in document(self.b, self.root, task.task_id, T0 + 12)["attempts"] if row["role"] != "notice"]
        self.assertEqual([(row["seq"], row["work"]) for row in rows], [(1, "blocked"), (3, "awaiting_ack")])
        self.b_report(task.task_id, 3, "ack", now=T0 + 13)  # 新尝试的第 1 号报告；决定丢失，只到了 task_state
        pump(self.b, self.a, now=T0 + 14)
        for item in self.a.store.outbox():
            if json.loads(item["envelope_json"])["kind"] == "report_decision":
                self.a.store.set_outbox_state(item["msg_id"], state="expired")
        updated = self.a.store.get_task(DEV_A, task.task_id)
        assert updated is not None
        with self.a.store.transaction():
            authority.send_task_state(self.a.store, self.a.ident, updated, now=T0 + 15)
        pump(self.a, self.b, now=T0 + 16)
        rows = [row for row in document(self.b, self.root, task.task_id, T0 + 17)["attempts"] if row["role"] != "notice"]
        self.assertEqual([(row["seq"], row["work"]) for row in rows], [(1, "blocked"), (3, "acknowledged")])

    def test_authority_keeps_its_ack_rule(self) -> None:
        # 共用折叠函数改动后 A 的行为不变：progress 之后再到的 ack 不把 work 倒回 acknowledged
        task, first = self.delivered()
        self.round_trip(task.task_id, "progress", T0 + 4)
        self.round_trip(task.task_id, "ack", T0 + 8)
        self.assertEqual(self.a.store.attempt_by_msg(first.msg_id).effective_work["work"], "in_progress")  # type: ignore[union-attr]
        self.assertEqual(document(self.b, self.root, task.task_id, T0 + 12)["attempts"][0]["work"], "in_progress")


class MirrorPhaseTests(_MirrorCase):
    """镜像阶段规则（§97.2 第 2 条）：当前工作尝试不在本机时不拿旧尝试当当前（调研探针 a3/a6/a7 反转）。"""

    def review_elsewhere(self) -> Any:
        self.b.store.remember_device_name(DEV_A, "vm")  # relay 会从 hub 盖章的 sourceDeviceName 记下登记名
        reviewer = self.a.bind(Provider.CLAUDE, CLAUDE_A2)
        task, _ = self.delivered(flow="review", reviewer=reviewer)
        self.round_trip(task.task_id, "result", T0 + 4, note="已修复")
        return task

    def test_review_on_the_authority_is_not_review_not_dispatched(self) -> None:
        task = self.review_elsewhere()
        b_doc = document(self.b, self.root, task.task_id, T0 + 10)
        self.assertEqual(b_doc["attempts"][0]["work"], "result_submitted")  # 本机尝试的推导值照常
        self.assertEqual((b_doc["phase"], b_doc["reason"]), ("running", "handled_on_other_device"))
        self.assertIn("当前由 vm 处理，完整状态以发起设备为准", lines(self.b, self.root, task.task_id, T0 + 10))
        view = self.view(self.b, task.task_id)
        self.assertIsNone(view.current)
        for until in ("sent", "ack", "result"):
            self.assertIsNone(_wait_outcome(view, until), until)  # 继续等，不以 EXIT_REJECTED 提前返回
        a_doc = document(self.a, self.root, task.task_id, T0 + 10)
        self.assertEqual(a_doc["attempts"][-1]["role"], "review")  # A 侧照旧按自己的尝试判

    def test_hostile_origin_device_name_is_escaped_in_status_text(self) -> None:
        # §101.1：登记名来自远端（hub 盖章或目录帧，relay 入库不校验）；status 文字里的发起设备名与「当前由 … 处理」
        # 与 peers 文字行同一套转义，伪造不出新行；JSON 照给原值
        task = self.review_elsewhere()
        honest = lines(self.b, self.root, task.task_id, T0 + 10).splitlines()
        hostile = "v\n设备 forged〔ffffffff〕：在线\x1b[2K\u202e\u200bm"
        self.b.store.put_device_state(device_id=DEV_A, name=hostile, revision=0, snapshot={}, last_seen=None,
                                      state="unknown")
        text = lines(self.b, self.root, task.task_id, T0 + 10)
        self.assertEqual(len(text.splitlines()), len(honest), text)
        self.assertFalse(any(char in text for char in "\x1b\u202e\u200b"), text)
        escaped = "v\\u000a设备 forged〔ffffffff〕：在线\\u001b[2K\\u202e\\u200bm"
        self.assertIn(f"镜像（发起设备 {escaped}）", text)
        self.assertIn(f"当前由 {escaped} 处理，完整状态以发起设备为准", text)
        self.assertEqual(document(self.b, self.root, task.task_id, T0 + 10)["authorityDeviceName"], hostile)

    def test_p1_review_on_a_then_accepted_shows_done_on_mirror(self) -> None:
        # Opus 审计 P1：已结束的任务不套镜像规则。复核方在 A、A 验收后镜像显示 done/accepted，wait 返回 0
        task = self.review_elsewhere()
        current = self.a.store.get_task(DEV_A, task.task_id)
        assert current is not None
        authority.finish(self.a.store, self.a.ident, current, state="accepted", reason=None, decider="origin",
                         sender=self.origin_actor(), sender_class="bypass", now=T0 + 30)
        pump(self.a, self.b, now=T0 + 31)
        b_doc = document(self.b, self.root, task.task_id, T0 + 32)
        self.assertEqual((b_doc["phase"], b_doc["reason"]), ("done", "accepted"))
        self.assertEqual(_wait_outcome(self.view(self.b, task.task_id), "result"), EXIT_OK)

    def test_review_on_the_authority_then_closed_shows_closed_on_mirror(self) -> None:
        task = self.review_elsewhere()
        current = self.a.store.get_task(DEV_A, task.task_id)
        assert current is not None
        authority.finish(self.a.store, self.a.ident, current, state="closed", reason=None, decider="origin",
                         sender=self.origin_actor(), sender_class="bypass", now=T0 + 30)
        pump(self.a, self.b, now=T0 + 31)
        a_doc = document(self.a, self.root, task.task_id, T0 + 32)
        b_doc = document(self.b, self.root, task.task_id, T0 + 32)
        self.assertEqual(b_doc["phase"], "closed")
        self.assertEqual((b_doc["phase"], b_doc["reason"]), (a_doc["phase"], a_doc["reason"]))

    def test_p2_paused_with_local_attempt_in_flight(self) -> None:
        # Opus 审计 P2：返工派回本机、新尝试的信封还在路上时 A 暂停任务：镜像显示「已暂停」而不是「等待发送」
        task, _ = self.delivered()
        self.round_trip(task.task_id, "blocked", T0 + 4, note="缺权限")
        current = self.a.store.get_task(DEV_A, task.task_id)
        assert current is not None
        authority.retry_task(self.a.store, self.a.ident, current, force=False, message=None, new_target=None,
                             rework_body=lambda *args: "返工", now=T0 + 8)
        updated = self.a.store.get_task(DEV_A, task.task_id)
        assert updated is not None
        paused = authority.set_paused(self.a.store, self.a.ident, updated, paused=True, now=T0 + 9)
        state = next(item for item in self.a.store.outbox() if json.loads(item["envelope_json"])["kind"] == "task_state"
                     and json.loads(item["envelope_json"])["authorityRevision"] == paused.revision)
        mirror.receive(self.b.store, self.b.ident, json.loads(state["envelope_json"]), source_device=DEV_A,
                       payload_hash=state["payload_hash"], now=T0 + 10)
        b_doc = document(self.b, self.root, task.task_id, T0 + 11)
        self.assertEqual((b_doc["phase"], b_doc["reason"]), ("queued", "paused"))

    def test_no_report_footer_while_handled_on_other_device(self) -> None:
        # r2：当前工作在别的设备上时照页脚汇报会被本机以 attempt_not_found 拒绝，所以不打印；普通镜像照常打印
        self.b.store.remember_device_name(DEV_A, "vm")
        task, _ = self.delivered()
        text = lines(self.b, self.root, task.task_id, T0 + 4)
        self.assertIn("汇报：", text)
        self.assertIn(f" report {task.task_id[:8]} --origin-device vm --result", text)
        task = self.review_elsewhere()
        self.assertEqual(document(self.b, self.root, task.task_id, T0 + 10)["reason"], "handled_on_other_device")
        self.assertNotIn("汇报：", lines(self.b, self.root, task.task_id, T0 + 10))

    def test_review_verdict_from_the_checkpoint_uses_existing_mapping(self) -> None:
        for verdict, expected in (("approve", ("awaiting_acceptance", "review_approved")),
                                  ("changes", ("needs_attention", "changes_requested"))):
            with self.subTest(verdict=verdict):
                self.tearDown()
                self.setUp()
                task = self.review_elsewhere()
                current = self.a.store.get_task(DEV_A, task.task_id)
                assert current is not None
                review = next(item for item in self.a.store.attempts(DEV_A, task.task_id) if item.role == "review")
                reviewer = review.target
                mirror.submit_report(self.a.store, self.a.ident, LocalReport(
                    task=current, attempt=review, kind=verdict, note="结论", refs=[], commit=None,
                    reporter=authority.actor_for(reviewer, wire_token="claude@vm2"), reporter_class="bypass",
                    source="agent"), now=T0 + 20)
                updated = self.a.store.get_task(DEV_A, task.task_id)
                assert updated is not None
                with self.a.store.transaction():
                    authority.send_task_state(self.a.store, self.a.ident, updated, now=T0 + 21)
                pump(self.a, self.b, now=T0 + 22)
                b_doc = document(self.b, self.root, task.task_id, T0 + 23)
                self.assertEqual((b_doc["phase"], b_doc["reason"]), expected)

    def test_retry_elsewhere_does_not_keep_the_old_attempt_current(self) -> None:
        task, _ = self.delivered()
        self.round_trip(task.task_id, "blocked", T0 + 4, note="缺权限")
        current = self.a.store.get_task(DEV_A, task.task_id)
        assert current is not None
        local = self.a.bind(Provider.CLAUDE, CLAUDE_A2)
        authority.retry_task(self.a.store, self.a.ident, current, force=False, message=None, new_target=local,
                             rework_body=lambda *args: "返工", now=T0 + 8)
        pump(self.a, self.b, now=T0 + 9)
        b_doc = document(self.b, self.root, task.task_id, T0 + 10)
        self.assertEqual([row["seq"] for row in b_doc["attempts"]], [1])
        self.assertEqual((b_doc["phase"], b_doc["reason"]), ("running", "handled_on_other_device"))

    def test_current_attempt_for_this_device_still_in_flight_waits_for_target(self) -> None:
        task, _ = self.delivered()
        self.round_trip(task.task_id, "blocked", T0 + 4, note="缺权限")
        current = self.a.store.get_task(DEV_A, task.task_id)
        assert current is not None
        authority.retry_task(self.a.store, self.a.ident, current, force=False, message=None, new_target=None,
                             rework_body=lambda *args: "返工", now=T0 + 8)
        updated = self.a.store.get_task(DEV_A, task.task_id)
        assert updated is not None
        # 新尝试的信封还在路上，先到的是一封 task_state（带 currentWorkSeq 指向它）
        with self.a.store.transaction():
            authority.send_task_state(self.a.store, self.a.ident, updated, now=T0 + 9)
        task_state = next(item for item in self.a.store.outbox() if json.loads(item["envelope_json"])["kind"] == "task_state")
        mirror.receive(self.b.store, self.b.ident, json.loads(task_state["envelope_json"]), source_device=DEV_A,
                       payload_hash=task_state["payload_hash"], now=T0 + 10)
        b_doc = document(self.b, self.root, task.task_id, T0 + 11)
        self.assertEqual((b_doc["phase"], b_doc["reason"]), ("queued", "waiting_for_target"))
        pump(self.a, self.b, now=T0 + 12)  # 新尝试到达后照常按本机尝试判
        b_doc = document(self.b, self.root, task.task_id, T0 + 13)
        self.assertEqual(([row["seq"] for row in b_doc["attempts"] if row["role"] != "notice"], b_doc["reason"]),
                         ([1, 3], "waiting_for_target"))

    def test_tasks_list_names_the_device(self) -> None:
        task = self.review_elsewhere()
        rt = runtime(self.b, self.root)
        current = self.b.store.get_task(DEV_A, task.task_id)
        assert current is not None
        self.assertEqual(commands.reason_label(rt, current, commands.view_of(rt, current)),
                         "当前由 vm 处理，完整状态以发起设备为准")


class DeliveryReasonTests(DeliveryTestCase):
    """B-1a（§97.3）：联邦尝试行显示投递原因码；值来自投递设备，按形状把关（调研探针 b1 反转）。"""

    STEER = {"steerPath": "steered", "codexVersion": "0.169.0", "serverVersion": "0.169.0"}

    def run_delivery(self, outcome: DeliveryOutcome) -> tuple[Any, Any]:
        task, first = self.create()
        pump(self.a, self.b, now=self.clock.now)
        transport = RecordingTransport(Provider.CODEX, outcome)
        self.assertEqual(self.dispatcher(self.b, self.b_paths, transport, [self.live(self.worker)]).run_once()["sent"], 1)
        pump(self.b, self.a, now=self.clock.now + 1)
        return task, first

    def row(self, device: Any, task_id: str) -> dict[str, Any]:
        return document(device, self.root, task_id, self.clock.now + 2)["attempts"][0]

    def test_reason_is_shown_on_both_sides(self) -> None:
        task, _ = self.run_delivery(DeliveryOutcome(Delivery.DELIVERED, "codex_steered", detail=self.STEER))
        for device in (self.a, self.b):
            with self.subTest(device=device.ident.device_name):
                row = self.row(device, task.task_id)
                self.assertEqual((row["delivery"], row["deliveryReason"]), ("delivered", "codex_steered"))
                # 带 steer 细节时括号里另有「；steer：…」（B-1b），这里只核原因码
                self.assertIn("投递 delivered（codex_steered", lines(device, self.root, task.task_id, self.clock.now + 2))

    def test_reason_absent_before_any_evidence(self) -> None:
        task, _ = self.create()
        row = self.row(self.a, task.task_id)
        self.assertEqual((row["delivery"], row["deliveryReason"]), ("pending", None))
        self.assertIn("投递 pending\n", lines(self.a, self.root, task.task_id, self.clock.now) + "\n")

    def test_reason_from_another_device_is_shape_checked(self) -> None:
        for raw, shown in (("codex_queued", "codex_queued"), ("Bad Reason!", "unknown"), ("x" * 65, "unknown"),
                           ("9starts_with_digit", "unknown"), (7, "unknown")):
            with self.subTest(raw=raw):
                self.tearDown()
                self.setUp()
                task, first = self.create()
                pump(self.a, self.b, now=self.clock.now)
                with self.b.store.transaction():
                    attempt = self.b.store.attempt_by_msg(first.msg_id)
                    current = self.b.store.get_task(DEV_A, task.task_id)
                    assert attempt is not None and current is not None
                    mirror.record_evidence(self.b.store, self.b.ident, current, attempt,
                                           {"state": "queued", "reason": raw, "at": self.clock.now}, now=self.clock.now)
                pump(self.b, self.a, now=self.clock.now + 1)
                self.assertEqual(self.row(self.a, task.task_id)["deliveryReason"], shown)


class SteerDetailTests(DeliveryTestCase):
    """B-1b（§97.3）：执行端证据只带闭集 detail，两端从 fed_evidence 读出显示。"""

    def delivered_with(self, detail: dict[str, Any], reason: str = "codex_queued",
                       state: Delivery = Delivery.QUEUED) -> tuple[Any, Any]:
        task, first = self.create()
        pump(self.a, self.b, now=self.clock.now)
        transport = RecordingTransport(Provider.CODEX, DeliveryOutcome(state, reason, detail=detail))
        self.assertEqual(self.dispatcher(self.b, self.b_paths, transport, [self.live(self.worker)]).run_once()["sent"], 1)
        return task, first

    def sent_evidence(self) -> list[dict[str, Any]]:
        return [json.loads(item["envelope_json"])["data"]["evidence"] for item in self.b.store.outbox()
                if json.loads(item["envelope_json"])["kind"] == "delivery_status"]

    def test_writer_keeps_only_the_closed_keys(self) -> None:
        detail = {"steerPath": "steer_rejected", "steerRejected": "codex_steer_review_turn", "queueChannel": "rpc",
                  "codexVersion": "0.169.0", "serverVersion": "0.169.0", "queueOutput": "recognized",
                  "steerReadFailed": "codex_transport_error", "deliveredPid": 4242, "logonType": "interactive"}
        task, first = self.delivered_with(detail)
        closed = {"steerPath": "steer_rejected", "steerRejected": "codex_steer_review_turn"}
        self.assertEqual([item.get("detail") for item in self.sent_evidence()], [closed])
        self.assertEqual([item.get("detail") for item in self.b.store.evidence(first.msg_id)], [closed])
        self.assertNotIn("detail", self.b.store.attempt_by_msg(first.msg_id).delivery)  # type: ignore[union-attr]
        pump(self.b, self.a, now=self.clock.now + 1)
        self.assertNotIn("detail", self.a.store.attempt_by_msg(first.msg_id).delivery)  # type: ignore[union-attr]
        for device in (self.a, self.b):
            with self.subTest(device=device.ident.device_name):
                row = document(device, self.root, task.task_id, self.clock.now + 2)["attempts"][0]
                self.assertEqual(row["deliveryDetail"], closed)
                self.assertIn("投递 queued（codex_queued；steer：steer_rejected；steer 拒绝：codex_steer_review_turn）",
                              lines(device, self.root, task.task_id, self.clock.now + 2))

    def test_writer_drops_values_outside_the_closed_sets(self) -> None:
        task, first = self.delivered_with({"steerPath": "weird", "steerRejected": "free text", "codexVersion": "1"})
        self.assertEqual([sorted(item) for item in self.sent_evidence()], [["at", "reason", "state"]])
        pump(self.b, self.a, now=self.clock.now + 1)
        row = document(self.a, self.root, task.task_id, self.clock.now + 2)["attempts"][0]
        self.assertNotIn("deliveryDetail", row)
        self.assertEqual(row["deliveryReason"], "codex_queued")

    def test_steered_note_shows_its_channel(self) -> None:
        task, _ = self.delivered_with({"steerPath": "steered", "codexVersion": "0.169.0"}, reason="codex_steered",
                                      state=Delivery.DELIVERED)
        pump(self.b, self.a, now=self.clock.now + 1)
        self.assertIn("投递 delivered（codex_steered；steer：steered）",
                      lines(self.a, self.root, task.task_id, self.clock.now + 2))

    def evidence_on_a(self, *items: dict[str, Any]) -> tuple[Any, str]:
        """直接按 A 的 ingest（apply_evidence，高水位）导入几条证据，造往回找的边界。"""
        task, first = self.create()
        current = self.a.store.get_task(DEV_A, task.task_id)
        assert current is not None
        for number, item in enumerate(items, start=1):
            authority.apply_evidence(self.a.store, current, first.msg_id, number, item, delivery_device=DEV_B,
                                     now=self.clock.now)
        return task, first.msg_id

    def detail_on_a(self, task_id: str) -> Any:
        return document(self.a, self.root, task_id, self.clock.now)["attempts"][0].get("deliveryDetail")

    def test_old_executor_evidence_without_detail(self) -> None:
        task, _ = self.evidence_on_a({"state": "queued", "reason": "codex_queued", "at": 1})
        self.assertIsNone(self.detail_on_a(task.task_id))

    def test_back_search_only_across_rows_with_the_same_state_and_reason(self) -> None:
        steered = {"steerPath": "thread_not_active"}
        cases = (
            ("同状态同原因、高水位无 detail：取低号的", [{"state": "queued", "reason": "codex_queued", "detail": steered},
                                                     {"state": "queued", "reason": "codex_queued"}], steered),
            ("原因不同：省略", [{"state": "queued", "reason": "codex_queued", "detail": steered},
                                {"state": "queued", "reason": "codex_queue_retry"}], None),
            ("状态不同：省略", [{"state": "queued", "reason": "codex_queued", "detail": steered},
                                {"state": "delivered", "reason": "codex_queued"}], None),
            ("高水位 detail 不合规：往回找", [{"state": "queued", "reason": "codex_queued", "detail": steered},
                                             {"state": "queued", "reason": "codex_queued", "detail": {"steerPath": "x"}}],
             steered),
            ("中间隔着不同的一行：在那里停", [{"state": "queued", "reason": "codex_queued", "detail": steered},
                                             {"state": "written", "reason": "codex_queued"},
                                             {"state": "queued", "reason": "codex_queued"}], None),
            ("高水位自己的优先", [{"state": "queued", "reason": "codex_queued", "detail": steered},
                                  {"state": "queued", "reason": "codex_queued", "detail": {"steerPath": "steered"}}],
             {"steerPath": "steered"}),
        )
        for label, items, expected in cases:
            with self.subTest(label):
                self.tearDown()
                self.setUp()
                task, _ = self.evidence_on_a(*items)
                self.assertEqual(self.detail_on_a(task.task_id), expected)

    def test_high_row_must_match_the_shown_delivery(self) -> None:
        task, msg_id = self.evidence_on_a({"state": "queued", "reason": "codex_queued", "detail": {"steerPath": "steered"}})
        attempt = self.a.store.attempt_by_msg(msg_id)
        assert attempt is not None
        with self.a.store.transaction():  # 例如 hub 拒收收据改写了显示的投递状态，却没有新的证据行
            self.a.store.update_attempt_columns(msg_id, delivery=dict(attempt.delivery, state="failed",
                                                                       reason="attachment_hash_mismatch"))
        self.assertIsNone(self.detail_on_a(task.task_id))


class OldAuthorityToleranceTests(RelayTestCase):
    """旧 A 容忍新键（§97.4 hub 轴）：带 detail 与未知键的 delivery_status 走真实的 hub 提交、relay 拉取、
    payloadHash 复核、begin_receiving 与 receive→apply_evidence；A 的 ingest 代码本轮未改，就是现役「旧 A」。"""

    def test_detail_and_unknown_keys_pass_the_real_ingest_path(self) -> None:
        task, first = self.create()
        self.a.cycle()
        self.tick()
        self.b.cycle()
        evidence = {"state": "delivered", "reason": "codex_steered", "at": self.clock.now,
                    "detail": {"steerPath": "steered", "futureKey": "x"}, "futureTop": {"nested": 1}}
        with self.b.store.transaction():
            attempt = self.b.store.attempt_by_msg(first.msg_id)
            current = self.b.store.get_task(self.a.device_id, task.task_id)
            assert attempt is not None and current is not None
            mirror.record_evidence(self.b.store, self.b.ident, current, attempt, evidence, now=self.clock.now)
        self.tick()
        self.assertEqual(self.b.cycle(), "connected")
        self.tick()
        self.assertEqual(self.a.cycle(), "connected")
        a_attempt = self.a.store.attempt_by_msg(first.msg_id)
        assert a_attempt is not None
        self.assertEqual((a_attempt.evidence_no, sorted(a_attempt.delivery)), (1, ["at", "reason", "state"]))
        (stored,) = self.a.store.evidence(first.msg_id)
        self.assertEqual((stored["detail"], stored["futureTop"]), (evidence["detail"], {"nested": 1}))
        rt = commands.Runtime(root=self.a.root, config=self.a.config, store=self.a.store, ident=self.a.ident,
                              paths=self.a.paths)
        current = self.a.store.get_task(self.a.device_id, task.task_id)
        assert current is not None
        row = commands.task_document(rt, current, now=self.clock.now)["attempts"][0]
        # 升级后的读方：只显示闭集键（升级前收到的这一行同样可读）
        self.assertEqual((row["deliveryReason"], row["deliveryDetail"]), ("codex_steered", {"steerPath": "steered"}))


class SteerDetailProjectionTests(unittest.TestCase):
    def test_projection_is_closed(self) -> None:
        self.assertEqual(steer_detail({"steerPath": "no_active_turn", "steerRejected": "codex_server_draining",
                                       "queueChannel": "rpc"}),
                         {"steerPath": "no_active_turn", "steerRejected": "codex_server_draining"})
        self.assertEqual(steer_detail({"steerPath": 1, "steerRejected": None}), {})
        self.assertEqual(steer_detail({}), {})

    def test_closed_sets_cover_every_named_value(self) -> None:
        # 两方 r0 审计 N25：闭集漏一个成员时，执行端会把这个通道静默丢掉；与模块里的 STEER_PATH_* 常量逐一核对
        named = {value for name, value in vars(codex_rpc).items() if name.startswith("STEER_PATH_")}
        self.assertEqual(codex_rpc.STEER_PATHS, named)
        self.assertEqual(named, {"steered", "thread_not_active", "thread_unreadable", "no_active_turn",
                                 "turns_unreadable", "steer_rejected", "steer_unknown"})
        for path in sorted(named):
            self.assertEqual(steer_detail({"steerPath": path}), {"steerPath": path})
        for code in sorted(codex_rpc.STEER_REJECTED_CODES):
            self.assertEqual(steer_detail({"steerRejected": code}), {"steerRejected": code})


class EvidenceColumnTests(FedCliCase):
    """§97.2 第 4 条 r2（两方 r0 审计 P2-1/P3-1）：证据正文里与列同名的键（evidenceNo、deliveryDevice）不得覆盖列值。
    两端的 status（文本与 --json）、tasks、wait 都不抛异常，detail 挂在正确的那一行上。"""

    def test_body_keys_cannot_override_the_row_columns(self) -> None:
        for extra in ({"evidenceNo": "x"}, {"evidenceNo": None}, {"evidenceNo": 7}, {"deliveryDevice": 1}):
            with self.subTest(extra=extra):
                self.doCleanups()
                self.setUp()
                task_id = self.send()
                self.pump("vm", "win")
                with self.store("win") as store:
                    task = store.get_task(self.ids["vm"], task_id)
                    assert task is not None
                    attempt = store.attempts(self.ids["vm"], task_id)[0]
                    evidence = {"state": "queued", "reason": "codex_queued", "at": 1,
                                "detail": {"steerPath": "steered"}, **extra}
                    with store.transaction():
                        mirror.record_evidence(store, self.ident("win"), task, attempt, evidence, now=2)
                self.pump("win", "vm")
                for device, caller in (("vm", self.endpoints["vm"][0]), ("win", WORKER)):
                    with self.store(device) as store:
                        rows = store.evidence(store.attempts(self.ids["vm"], task_id)[0].msg_id)
                    self.assertEqual([(row["evidenceNo"], row["deliveryDevice"]) for row in rows],
                                     [(1, self.ids["win"])], device)
                    code, out, err = self.run_on(device, "status", task_id, "--json", caller=as_agent(caller))
                    self.assertEqual((code, json.loads(out)["attempts"][0].get("deliveryDetail")),
                                     (0, {"steerPath": "steered"}), err)
                    code, out, err = self.run_on(device, "status", task_id, caller=as_agent(caller))
                    self.assertEqual(code, 0, err)
                    self.assertIn("投递 queued（codex_queued；steer：steered）", out)
                    self.assertEqual(self.run_on(device, "tasks", caller=as_agent(caller))[0], 0, device)
                    code, _, err = self.run_on(device, "wait", task_id, "--until", "sent", "--timeout", "0",
                                               caller=as_agent(caller))
                    self.assertEqual(code, cli.EXIT_OK, err)


class MirrorCliTests(FedCliCase):
    """镜像上真实 CLI 的 ab wait 退出码与 ab tasks 行（§97.5）：经 cli.main，不只测 _wait_outcome。"""

    def test_wait_on_the_mirror_returns_once_ack_and_result_are_accepted(self) -> None:
        task_id = self.delivered_task()
        code, _, _ = self.run_on("win", "wait", task_id, "--until", "ack", "--timeout", "0", caller=as_agent(WORKER))
        self.assertEqual(code, cli.EXIT_TIMEOUT)  # A 还没采纳：照旧等
        for kind, until in (("--ack", "ack"), ("--result", "result")):
            with self.subTest(until=until):
                self.assertEqual(self.run_on("win", "report", task_id, kind, caller=as_agent(WORKER))[0], 0)
                self.pump("win", "vm")
                self.pump("vm", "win")
                code, out, err = self.run_on("win", "wait", task_id, "--until", until, "--timeout", "0",
                                             caller=as_agent(WORKER))
                self.assertEqual(code, cli.EXIT_OK, out + err)

    def test_wait_ack_does_not_return_when_an_earlier_blocked_decision_is_missing(self) -> None:
        # r1：blocked 被 A 采纳但决定丢失、随后的 ack 被采纳送达。镜像停在前缀 awaiting_ack：不显示「对方已开始处理」，
        # wait --until ack 继续等（A 侧此时是受阻，不会以 0 返回）
        task_id = self.delivered_task()
        self.assertEqual(self.run_on("win", "report", task_id, "--blocked", caller=as_agent(WORKER))[0], 0)
        self.pump("win", "vm")
        with self.store("vm") as store:
            for item in store.outbox():
                if json.loads(item["envelope_json"])["kind"] == "report_decision":
                    store.set_outbox_state(item["msg_id"], state="expired")
        self.assertEqual(self.run_on("win", "report", task_id, "--ack", caller=as_agent(WORKER))[0], 0)
        self.pump("win", "vm")
        self.pump("vm", "win")
        code, out, err = self.run_on("win", "wait", task_id, "--until", "ack", "--timeout", "0", caller=as_agent(WORKER))
        self.assertEqual(code, cli.EXIT_TIMEOUT, out + err)
        code, out, _ = self.run_on("win", "status", task_id, caller=as_agent(WORKER))
        self.assertNotIn("对方已开始处理", out)

    def test_wait_on_the_mirror_keeps_waiting_while_the_review_is_on_the_authority(self) -> None:
        task_id = self.local_review_requested()
        self.pump("vm", "win")
        code, out, err = self.run_on("win", "wait", task_id, "--until", "result", "--timeout", "0",
                                     caller=as_agent(WORKER))
        self.assertEqual(code, cli.EXIT_TIMEOUT, out + err)  # 不以 EXIT_REJECTED（review_not_dispatched）提前返回
        self.assertIn("等待超时：进行中（当前由 vm 处理，完整状态以发起设备为准）", out)
        code, out, err = self.run_on("win", "tasks", caller=as_agent(WORKER))
        self.assertEqual(code, 0, err)
        self.assertIn("当前由 vm 处理，完整状态以发起设备为准", out)
        code, out, _ = self.run_on("win", "status", task_id, "--json", caller=as_agent(WORKER))
        self.assertEqual((json.loads(out)["phase"], json.loads(out)["reason"]), ("running", "handled_on_other_device"))


class SubmitReportRereadTests(_MirrorCase):
    """§98.2 共用的「当前尝试」在 submit_report 事务内按重读的任务判（两方 r0 审计 Opus P2-2 的 M11/M13、Fable B5）。"""

    def test_submit_report_judges_the_task_reread_inside_its_transaction(self) -> None:
        # 调用方手里的任务已过时：返工派回 B、新尝试已物化。用旧任务与旧尝试直接调 submit_report 得 stale_attempt
        task, first = self.delivered()
        stale_task = self.b.store.get_task(DEV_A, task.task_id)
        old_attempt = self.b.store.attempt_by_msg(first.msg_id)
        assert stale_task is not None and old_attempt is not None
        self.round_trip(task.task_id, "blocked", T0 + 4, note="缺权限")
        current = self.a.store.get_task(DEV_A, task.task_id)
        assert current is not None
        retried = authority.retry_task(self.a.store, self.a.ident, current, force=False, message=None,
                                       new_target=None, rework_body=lambda *args: "返工", now=T0 + 8)
        pump(self.a, self.b, now=T0 + 9)
        moved = self.b.store.get_task(DEV_A, task.task_id)
        assert moved is not None
        self.assertEqual(moved.current_work_seq, retried.attempt.seq)
        self.assertIsNotNone(self.b.store.attempt_by_msg(retried.attempt.msg_id))
        with self.assertRaises(StoreError) as raised:
            mirror.submit_report(self.b.store, self.b.ident, LocalReport(
                task=stale_task, attempt=old_attempt, kind="result", note="", refs=[], commit=None,
                reporter=self.worker_actor(), reporter_class="bypass", source="agent"), now=T0 + 10)
        self.assertEqual(raised.exception.code, "stale_attempt")


class ReportFooterTests(FedCliCase):
    """§98.2：镜像汇报页脚只在本机当前尝试真能汇报时打印，命令按角色给出；每种会被拒的状态都在同一夹具上直接调用
    commands.report，证明页脚与受理条件一致（同一组判定）。"""

    HANDOFF = "--result（或 --blocked / --failed）"
    REVIEW = "--approve 或 --changes（或 --blocked / --failed）"

    def footer(self, device: str, task_id: str) -> list[str]:
        runtime = commands.open_runtime(self.states[device])
        try:
            [task] = runtime.store.find_tasks(task_id)
            return [line for line in commands.task_lines(runtime, task, now=now_ms()) if line.startswith("汇报：")]
        finally:
            runtime.close()

    def one_footer(self, device: str, task_id: str) -> str:
        """恰好一行页脚；先断言条数，判据改坏时以断言失败而不是解包异常暴露。"""
        lines = self.footer(device, task_id)
        self.assertEqual(len(lines), 1, lines)
        return lines[0]

    def report_code(self, device: str, task_id: str, kind: ReportKind, who: Any = WORKER) -> str | None:
        """直接调用 commands.report：被拒时返回错误码，受理时返回 None（会真的记一条报告）。"""
        runtime = commands.open_runtime(self.states[device])
        try:
            [task] = runtime.store.find_tasks(task_id)
            commands.report(runtime, task=task, kind=kind, attempt_seq=None, note=None, files=[], commit=None,
                            manual=False, caller=as_agent(who), caller_class="bypass", cwd=self.root)
        except FedCliError as error:
            return error.code
        finally:
            runtime.close()
        return None

    def reason(self, device: str, task_id: str, who: Any) -> str:
        code, out, err = self.run_on(device, "status", task_id, "--json", caller=as_agent(who))
        self.assertEqual(code, 0, err)
        return str(json.loads(out)["reason"])

    def pump_kind(self, src: str, dst: str, kind: str) -> int:
        """只把某一类信封交给 dst（其余留在发件箱，模拟还在路上）。"""
        moved = 0
        with self.store(src) as source, self.store(dst) as target:
            for item in source.outbox():
                envelope = json.loads(item["envelope_json"])
                if envelope["targetDeviceId"] != self.ids[dst] or envelope["kind"] != kind:
                    continue
                mirror.receive(target, self.ident(dst), envelope, source_device=self.ids[src],
                               payload_hash=item["payload_hash"], now=now_ms())
                source.set_outbox_state(item["msg_id"], state="received")
                moved += 1
        return moved

    def send_task_state(self, task_id: str) -> None:
        with self.store("vm") as store:
            [task] = store.find_tasks(task_id)
            with store.transaction():
                authority.send_task_state(store, self.ident("vm"), task, now=now_ms())

    def test_handoff_footer_and_still_printed_after_blocked(self) -> None:
        task_id = self.delivered_task()
        line = self.one_footer("win", task_id)
        self.assertTrue(line.endswith(f"report {task_id[:8]} --origin-device vm {self.HANDOFF}"), line)
        self.assertEqual(self.run_on("win", "report", task_id, "--blocked", caller=as_agent(WORKER))[0], 0)
        self.pump("win", "vm")
        self.pump("vm", "win")
        self.assertEqual(self.reason("win", task_id, WORKER), "blocked_reported")
        self.assertEqual(len(self.footer("win", task_id)), 1)  # blocked 不是终态，之后仍可交结果

    def test_no_footer_while_the_current_attempt_has_not_arrived(self) -> None:
        for paused in (False, True):
            with self.subTest(paused=paused):
                self.doCleanups()
                self.setUp()
                task_id = self.delivered_task()
                self.assertEqual(self.run_on("win", "report", task_id, "--blocked", caller=as_agent(WORKER))[0], 0)
                self.pump("win", "vm")
                self.assertEqual(self.run_on("vm", "retry", task_id, caller=as_agent(ORIGIN))[0], 0)  # 返工派回 B
                if paused:
                    self.assertEqual(self.run_on("vm", "pause", task_id, caller=as_agent(ORIGIN))[0], 0)
                else:
                    self.send_task_state(task_id)
                self.assertGreaterEqual(self.pump_kind("vm", "win", "task_state"), 1)  # 新尝试的信封还在路上
                self.assertEqual(self.reason("win", task_id, WORKER), "paused" if paused else "waiting_for_target")
                self.assertEqual(self.footer("win", task_id), [])
                self.assertEqual(self.report_code("win", task_id, ReportKind.RESULT), "attempt_not_found")

    def test_no_footer_once_a_review_verdict_is_mapped_from_the_checkpoint(self) -> None:
        for flag, reason in (("--approve", "review_approved"), ("--changes", "changes_requested")):
            with self.subTest(verdict=flag):
                self.doCleanups()
                self.setUp()
                task_id = self.local_review_requested()
                self.assertEqual(self.run_on("vm", "report", task_id, flag, caller=as_agent(LOCAL_REVIEW))[0], 0)
                self.pump("vm", "win")
                self.send_task_state(task_id)  # 复核结论要等 A 下一次发 checkpoint 才到镜像
                self.pump("vm", "win")
                self.assertEqual(self.reason("win", task_id, WORKER), reason)
                self.assertEqual(self.footer("win", task_id), [])
                self.assertEqual(self.report_code("win", task_id, ReportKind.RESULT), "attempt_not_found")

    def test_no_footer_while_the_local_job_is_not_sent(self) -> None:
        for cancelled in (False, True):
            with self.subTest(cancelled=cancelled):
                self.doCleanups()
                self.setUp()
                task_id = self.send()
                self.pump("vm", "win")  # B 已物化，worker 还没交出（pending）
                if cancelled:
                    self.assertEqual(self.run_on("vm", "cancel", task_id, caller=as_agent(ORIGIN))[0], 0)
                    self.pump("vm", "win")  # B 抑制未领取的作业：投递 cancelled
                self.assertEqual(self.footer("win", task_id), [])
                self.assertEqual(self.report_code("win", task_id, ReportKind.ACK), "attempt_not_sent")

    def test_no_footer_on_an_archived_mirror(self) -> None:
        task_id = self.delivered_task()
        runtime = commands.open_runtime(self.states["win"])
        try:
            [task] = runtime.store.find_tasks(task_id)
            commands.archive(runtime, task)
        finally:
            runtime.close()
        self.assertEqual(self.footer("win", task_id), [])
        self.assertEqual(self.report_code("win", task_id, ReportKind.ACK), "mirror_archived")

    def test_no_footer_while_a_terminal_report_is_pending_or_accepted(self) -> None:
        task_id = self.delivered_task()
        self.assertEqual(self.run_on("win", "report", task_id, "--result", caller=as_agent(WORKER))[0], 0)
        self.assertEqual(self.footer("win", task_id), [])  # 待发起设备裁决
        self.assertEqual(self.report_code("win", task_id, ReportKind.FAILED), "report_pending")
        self.pump("win", "vm")
        self.pump("vm", "win")
        self.assertEqual(self.reason("win", task_id, WORKER), "result_ready")
        self.assertEqual(self.footer("win", task_id), [])  # 已被采纳
        self.assertEqual(self.report_code("win", task_id, ReportKind.FAILED), "attempt_report_finalized")

    def review_on_this_device(self) -> str:
        """本机实现、复核在 win：A 的实现方交了结果，复核请求已投到 win 的会话。"""
        code, out, err = self.run_on("vm", "send", "--to", "codex@review", "--review-device", "win", "--review-by",
                                     f"codex@id:{THREAD_B}", "-m", "本机实现、远端复核", "--json",
                                     caller=as_agent(ORIGIN))
        self.assertEqual(code, 0, err)
        task_id = json.loads(out)["id"]
        with self.store("vm") as store:
            FederationDispatcher(store, self.ident("vm"), RelayPaths(self.states["vm"]),
                                 discover=lambda: [LOCAL_REVIEW], transports={Provider.CODEX: RecordingTransport(
                                     Provider.CODEX)}, reply_address=None, command="ab").run_once()
        self.assertEqual(self.run_on("vm", "report", task_id, "--result", caller=as_agent(LOCAL_REVIEW))[0], 0)
        self.pump("vm", "win")
        self.assertEqual(len(self.deliver_on_b().calls), 1)
        return task_id

    def test_review_on_this_device_prints_the_verdict_footer(self) -> None:
        # 页脚给出的两种结论照做都被本机受理（两方 r0 审计 Opus P3-5），--result 被拒
        for flag in ("--approve", "--changes"):
            with self.subTest(verdict=flag):
                self.doCleanups()
                self.setUp()
                task_id = self.review_on_this_device()
                line = self.one_footer("win", task_id)
                self.assertTrue(line.endswith(f"--origin-device vm {self.REVIEW}"), line)
                self.assertNotIn("--result", line)
                self.assertEqual(self.report_code("win", task_id, ReportKind.RESULT), "review_requires_verdict")
                code, _, err = self.run_on("win", "report", task_id, "--origin-device", "vm", flag,
                                           caller=as_agent(WORKER))
                self.assertEqual(code, 0, err)

    def test_handoff_attempt_of_a_review_flow_prints_the_handoff_footer(self) -> None:
        # 页脚按尝试的角色给命令，不按任务流程（两方 r0 审计 Fable C1）：复核流程里镜像上的当前尝试是交接，给 --result
        code, out, err = self.run_on("vm", "send", "--device", "win", "--to", "codex@impl", "--review-by",
                                     "codex@review", "-m", "实现 Y", "--json", caller=as_agent(ORIGIN))
        self.assertEqual(code, 0, err)
        task_id = json.loads(out)["id"]
        self.pump("vm", "win")
        self.assertEqual(len(self.deliver_on_b().calls), 1)
        line = self.one_footer("win", task_id)
        self.assertTrue(line.endswith(f"--origin-device vm {self.HANDOFF}"), line)
        code, _, err = self.run_on("win", "report", task_id, "--origin-device", "vm", "--result",
                                   caller=as_agent(WORKER))
        self.assertEqual(code, 0, err)

    def test_no_footer_on_a_finished_mirror_without_a_terminal_report(self) -> None:
        # 两方 r0 审计 Opus M1、Fable B2：镜像收到关闭后，即使本机没交过终态报告也不打页脚
        task_id = self.delivered_task()
        self.assertEqual(self.run_on("vm", "close", task_id, caller=as_agent(ORIGIN))[0], 0)
        self.pump("vm", "win")
        self.assertEqual(self.footer("win", task_id), [])
        self.assertEqual(self.report_code("win", task_id, ReportKind.RESULT), "task_finished")

    def test_footer_returns_after_a_rejected_terminal_report(self) -> None:
        # 终态汇报被拒即解除冻结（两方 r0 审计 Opus M9）：页脚重新出现，照做被本机受理
        task_id = self.delivered_task()
        code, out, err = self.run_on("win", "report", task_id, "--result", "--json", caller=as_agent(WORKER))
        self.assertEqual(code, 0, err)
        operation = json.loads(out)["report"]["operationId"]
        self.assertEqual(self.footer("win", task_id), [])
        with self.store("win") as store:  # 例如 hub 确定拒收后 B 本机记下 rejected
            store.add_decision(reporter_device=DEV_B, report_operation_id=operation, authority_revision=1,
                               decision="rejected", reason="test_rejected")
        line = self.one_footer("win", task_id)
        argv = line[len("汇报："):].split("（")[0].split()[1:]  # 去掉命令名与括号里的备选
        self.assertEqual(argv, ["report", task_id[:8], "--origin-device", "vm", "--result"])
        code, _, err = self.run_on("win", *argv, caller=as_agent(WORKER))
        self.assertEqual(code, 0, err)

    def test_no_footer_while_the_local_job_is_mid_send(self) -> None:
        # 「未交出」含 sending（两方 r0 审计 Fable B12）：B 已 intent、外调结果还没落账
        task_id = self.send()
        self.pump("vm", "win")
        with self.store("win") as store:
            [attempt] = [item for item in store.attempts(self.ids["vm"], task_id) if item.role != "notice"]
            with store.transaction() as conn:
                changed = conn.execute("UPDATE fed_native_sends SET state='intent', intent_at=? WHERE msg_id=?"
                                       " AND state='prepared'", (now_ms(), attempt.msg_id)).rowcount
                store.update_attempt_columns(attempt.msg_id, delivery=dict(attempt.delivery, state="sending"))
        self.assertEqual(changed, 1)
        self.assertEqual(self.footer("win", task_id), [])
        self.assertEqual(self.report_code("win", task_id, ReportKind.ACK), "attempt_not_sent")

    def test_attribution_is_checked_before_attempt_not_sent(self) -> None:
        # 错误码先后顺序不变（两方 r0 审计 Fable C2）：不是收件会话的调用方先得 reporter_mismatch，再轮到「未交出」
        task_id = self.send()
        self.pump("vm", "win")
        self.assertEqual(self.report_code("win", task_id, ReportKind.ACK, who=LOCAL_REVIEW), "reporter_mismatch")
        self.assertEqual(self.report_code("win", task_id, ReportKind.ACK), "attempt_not_sent")

    def test_authority_session_cannot_report_on_a_remote_current_attempt(self) -> None:
        # 「当前尝试」只认发给本设备的（两方 r0 审计 Fable B3）：当前尝试在远端时，A 本机会话汇报得 attempt_not_found
        task_id = self.delivered_task()
        self.assertEqual(self.report_code("vm", task_id, ReportKind.RESULT, who=LOCAL_REVIEW), "attempt_not_found")

    def test_no_footer_without_a_local_binding(self) -> None:
        # §98 r1：B 收信时没有该端点的绑定，worker 记 failed（target_not_found），没有会话收到工作：不打页脚，
        # 照做在 commands.report 报 reporter_mismatch（同一判定）
        with self.store("win") as store:
            with store.transaction() as conn:
                self.assertGreater(conn.execute("DELETE FROM fed_bindings").rowcount, 0)
        task_id = self.send()
        self.pump("vm", "win")
        self.deliver_on_b()
        with self.store("win") as store:
            [attempt] = [item for item in store.attempts(self.ids["vm"], task_id) if item.role != "notice"]
        self.assertEqual((attempt.target.local, attempt.delivery.get("state")), (None, "failed"))
        self.assertEqual(self.footer("win", task_id), [])
        self.assertEqual(self.report_code("win", task_id, ReportKind.RESULT), "reporter_mismatch")

    def test_no_footer_once_federation_is_disabled(self) -> None:
        # §98 r1：本机联邦停用后 ab status 仍可读，但 ab report 报 federation_disabled，所以不打页脚
        task_id = self.delivered_task()
        self.assertEqual(len(self.footer("win", task_id)), 1)
        self.assertEqual(self.run_on("win", "federation", "disable")[0], 0)
        code, out, err = self.run_on("win", "status", task_id, caller=as_agent(WORKER))
        self.assertEqual(code, 0, err)
        self.assertIn("镜像（发起设备 vm）", out)
        self.assertNotIn("汇报：", out)
        code, _, err = self.run_on("win", "report", task_id, "--result", caller=as_agent(WORKER))
        self.assertEqual(code, cli.EXIT_NOT_ENABLED)
        self.assertIn("federation_disabled", err)

    def test_authority_side_reviewer_still_reports_through_commands_report(self) -> None:
        # 共用判定的「非权威」条件只用于页脚，不进汇报路径：A 本机复核方照常经 commands.report 汇报并当场采纳
        task_id = self.local_review_requested()
        self.assertEqual(self.footer("vm", task_id), [])  # 权威端不打镜像页脚
        runtime = commands.open_runtime(self.states["vm"])
        try:
            [task] = runtime.store.find_tasks(task_id)
            attempt, result = commands.report(runtime, task=task, kind=ReportKind.APPROVE, attempt_seq=None, note=None,
                                              files=[], commit=None, manual=False, caller=as_agent(LOCAL_REVIEW),
                                              caller_class="bypass", cwd=self.root)
        finally:
            runtime.close()
        self.assertEqual((attempt.role, result.decision), ("review", "accepted"))


# 每个场景里 B 可能交的报告：交接场景下 approve/changes 会被 A 以 verdict_requires_review 拒绝；复核场景下 result 被拒
_HANDOFF_KINDS = ("ack", "progress", "blocked", "result", "failed", "approve", "changes")
_REVIEW_KINDS = ("ack", "progress", "blocked", "approve", "changes", "result", "failed")

# 预言机的独立参考（两方 r0 审计 P3-2）：按 DESIGN §97.2 第 1 条的文字另写一份折叠表，不借用被测的 fold_report
_REF_WORK = {"progress": "in_progress", "blocked": "blocked", "failed": "failure_reported",
             "result": "result_submitted", "approve": "result_submitted", "changes": "result_submitted"}
_REF_TERMINAL = frozenset({"result", "failed", "approve", "changes"})


def _ref_fold(effective: dict[str, Any], report: dict[str, Any]) -> dict[str, Any]:
    """参考折叠：ACK 只把 awaiting_ack 推进到 acknowledged；终态报告带结果说明（不含时间）。"""
    kind = report["kind"]
    folded = dict(effective)
    if kind != "ack":
        folded["work"] = _REF_WORK[kind]
    elif folded["work"] == "awaiting_ack":
        folded["work"] = "acknowledged"
    if kind in _REF_TERMINAL:
        result: dict[str, Any] = {"note": report.get("note") or "", "refs": list(report.get("refs") or []),
                                  "source": report.get("source", "agent")}
        if isinstance(report.get("commit"), dict):
            result["commit"] = report["commit"]
        folded["result"] = result
    return folded


def _timeless(effective: dict[str, Any]) -> dict[str, Any]:
    """去掉时间戳后的整份 effective：A 写采纳时刻 at 与 result.reportedAt，镜像推导不知道这两个值。"""
    shown = {key: value for key, value in effective.items() if key != "at"}
    result = shown.get("result")
    if isinstance(result, dict):
        shown["result"] = {key: value for key, value in result.items() if key != "reportedAt"}  # pyright: ignore[reportUnknownVariableType]
    return shown


class DifferentialOracleTests(FederationTestCase):
    """差分预言机（§97.5）：随机报告序列同时驱动真实 A 裁决与镜像推导，逐步比对。

    序列包含：被拒（类别不符、结果已交）、superseded（B 的报告乱序到 A）、决定丢失（A→B 信封随机丢弃）、
    决定乱序、task_state（只带 reportHigh）与窄同步。每一步断言（effective 一律去掉时间戳后整份比较）：
    0. A 的 effective_work 就是「A 已采纳报告」按 reportNo 用独立参考表折叠的结果（镜像推导依赖的前提）；
    1. 镜像推导值总等于 A 折叠某个已采纳前缀后的状态，即 A 某个时刻真实有过的状态（r1 只折叠连续前缀，见
       MirrorStatusTests.test_mirror_stops_at_the_first_report_without_a_decision）；另断言镜像计入的每条报告在 A 上
       都是 accepted；
    2. 决定齐全时（A 已裁决的报告 B 都有同样决定，且不超过 A 的 reportHigh 的报告 B 都已有决定），推导值等于 A；
    3. 精确口径（Opus 审计）：B 已有的决定与 A 一致（或 B 经窄同步得知 superseded 而 A 还没收到这条报告）；取 B 上第一条
       「没有决定、号码也不等于 B 所存 reportHigh」的报告号 k，A 已采纳且号码小于 k 的报告按参考表折叠，就是推导值。
    序列末尾无损送达并窄同步到静止：B 的每条报告都有决定，推导值等于 A，当前尝试在 B 时阶段与原因也与 A 相同（收敛）。
    定向模式（test_directed_sequences_track_the_authority）专门构造随机生成很少命中的三类窄序列。
    """

    SEEDS = 160
    DIRECTED_SEEDS = 48

    def setUp(self) -> None:
        super().setUp()
        self.coverage = {"rejected": 0, "superseded": 0, "lost": 0, "fallback": 0, "complete_equal": 0, "lagging": 0,
                         "cut": 0, "converged": 0, "converged_view": 0}
        self.directed = {"ack_after_lost": 0, "reverse": 0, "lost_no_sync": 0}

    def test_mirror_derivation_tracks_the_authority(self) -> None:
        totals = dict.fromkeys(self.coverage, 0)
        for seed in range(self.SEEDS):
            with self.subTest(seed=seed):
                self.tearDown()
                self.setUp()
                self.run_sequence(random.Random(seed))
                for key, value in self.coverage.items():
                    totals[key] += value
        # 生成器必须真的覆盖到这些情形，否则预言机会静默退化
        for key, value in totals.items():
            with self.subTest(coverage=key):
                self.assertGreater(value, 0, totals)

    def test_directed_sequences_track_the_authority(self) -> None:
        """定向生成（两方 r0 审计 P3-2）：progress/blocked 的决定丢失后再交 ack、B→A 倒序交付、丢失决定后不插窄同步。

        与随机模式共用每步断言与末尾的收敛后置条件；种子独立，不改随机模式的序列。
        """
        totals = dict.fromkeys(self.directed, 0)
        for seed in range(self.DIRECTED_SEEDS):
            with self.subTest(seed=seed):
                self.tearDown()
                self.setUp()
                self.run_directed(random.Random(seed))
                for key, value in self.directed.items():
                    totals[key] += value
        for key, value in totals.items():
            with self.subTest(coverage=key):
                self.assertGreater(value, 0, totals)

    def start(self, rng: random.Random) -> tuple[str, str, int, tuple[str, ...]]:
        """建任务并让 B 的工作尝试投递完成；返回 (taskId, B 尝试 msgId, 序号, 可交的报告类别)。"""
        if rng.random() < 0.6:
            task, first = self.create()
            pump(self.a, self.b, now=T0 + 1)
            deliver(self.b, first.msg_id, "queued", now=T0 + 2)
            pump(self.b, self.a, now=T0 + 3)
            return task.task_id, first.msg_id, 1, _HANDOFF_KINDS
        local = self.a.bind(Provider.CLAUDE, CLAUDE_A2)
        task, first = authority.create_task(
            self.a.store, self.a.ident, title="复核在 B", flow="review", body="实现 X", refs=[], origin=self.origin,
            origin_actor=self.origin_actor(), origin_class="bypass", target=local,
            reviewer=self.worker_remote, now=T0)
        a_task = self.a.store.get_task(DEV_A, task.task_id)
        assert a_task is not None
        mirror.submit_report(self.a.store, self.a.ident, LocalReport(
            task=a_task, attempt=first, kind="result", note="实现完成", refs=[], commit=None,
            reporter=authority.actor_for(local, wire_token="claude@vm2"), reporter_class="bypass", source="agent"),
            now=T0 + 1)
        pump(self.a, self.b, now=T0 + 2)
        review = next(item for item in self.b.store.attempts(DEV_A, task.task_id) if item.role == "review")
        deliver(self.b, review.msg_id, "queued", now=T0 + 3)
        pump(self.b, self.a, now=T0 + 4)
        return task.task_id, review.msg_id, review.seq, _REVIEW_KINDS

    def ship(self, rng: random.Random, src: Any, dst: Any, now: int, *, lose: float) -> None:
        """把 src 发给 dst 的待发信封按随机顺序交付一部分；lose>0 时按概率丢弃（运输终结，不再重发）。"""
        items = [item for item in src.store.outbox()
                 if json.loads(item["envelope_json"])["targetDeviceId"] == dst.ident.device_id]
        rng.shuffle(items)
        for item in items:
            roll = rng.random()
            if roll < lose:
                src.store.set_outbox_state(item["msg_id"], state="expired")
                if json.loads(item["envelope_json"])["kind"] == "report_decision":
                    self.coverage["lost"] += 1
            elif roll < lose + 0.65:
                mirror.receive(dst.store, dst.ident, json.loads(item["envelope_json"]),
                               source_device=src.ident.device_id, payload_hash=item["payload_hash"], now=now)
                src.store.set_outbox_state(item["msg_id"], state="received")

    def run_sequence(self, rng: random.Random) -> None:
        task_id, msg_id, seq, kinds = self.start(rng)
        now = T0 + 10
        log: list[str] = []
        for _ in range(rng.randint(5, 16)):
            now += 10
            action = rng.choices(("report", "to_a", "to_b", "task_state", "sync"), weights=(4, 3, 3, 1, 1))[0]
            log.append(action)
            if action == "report":
                try:
                    self.b_report(task_id, seq, rng.choice(kinds), note=f"n{now}", now=now)
                except StoreError:
                    pass  # 源端冻结、已结束或过时：真实 CLI 也会拒绝
            elif action == "to_a":
                self.ship(rng, self.b, self.a, now, lose=0.0)
            elif action == "to_b":
                self.ship(rng, self.a, self.b, now, lose=0.2)
            elif action == "task_state":
                self.send_task_state(task_id, now)
            else:
                self.sync(task_id, now)
            self.check(task_id, msg_id, seq, log)
        self.converge(task_id, msg_id, seq, log, now)

    # ---- 定向模式：每个宏动作构造一类窄序列，逐步检查 ----

    def run_directed(self, rng: random.Random) -> None:
        task_id, msg_id, seq, kinds = self.start(rng)
        now = T0 + 10
        log: list[str] = ["directed"]
        for _ in range(rng.randint(1, 3)):
            macro = rng.choice(("ack_after_lost", "reverse", "lost_no_sync"))
            log.append(macro)
            now += 100
            if macro == "ack_after_lost":
                self.ack_after_lost(rng, task_id, msg_id, seq, now, log)
            elif macro == "reverse":
                self.reverse(rng, task_id, msg_id, seq, kinds, now, log)
            else:
                self.lost_no_sync(rng, task_id, msg_id, seq, kinds, now, log)
        self.converge(task_id, msg_id, seq, log, now + 100)

    def submit(self, task_id: str, seq: int, kinds: list[str], now: int, log: list[str]) -> list[str]:
        """B 依次交报告；被源端冻结等拒绝的跳过。返回交出的 operationId。"""
        operations: list[str] = []
        for offset, kind in enumerate(kinds):
            try:
                operations.append(self.b_report(task_id, seq, kind, note=f"d{now + offset}", now=now + offset).operation_id)
                log.append(f"report:{kind}")
            except StoreError as error:
                log.append(f"report:{kind}!{error.code}")
        return operations

    def decision_items(self, operations: list[str]) -> list[dict[str, Any]]:
        return [item for item in self.a.store.outbox()
                if json.loads(item["envelope_json"])["kind"] == "report_decision"
                and json.loads(item["envelope_json"])["data"]["reportOperationId"] in operations]

    def ack_after_lost(self, rng: random.Random, task_id: str, msg_id: str, seq: int, now: int,
                       log: list[str]) -> None:
        """progress/blocked 被采纳但决定丢失，随后的 ack 被采纳并送达（M10 的情形：镜像必须停在前一条之前）。"""
        first = self.submit(task_id, seq, [rng.choice(("progress", "blocked"))], now, log)
        pump(self.b, self.a, now=now + 2)
        for item in self.decision_items(first):
            self.a.store.set_outbox_state(item["msg_id"], state="expired")
        second = self.submit(task_id, seq, ["ack"], now + 3, log)
        pump(self.b, self.a, now=now + 5)
        pump(self.a, self.b, now=now + 6)
        self.check(task_id, msg_id, seq, log)
        accepted = [self.a.store.decision(DEV_B, item) for item in first + second]
        if len(accepted) == 2 and all(item is not None and item["decision"] == "accepted" for item in accepted) \
                and self.b.store.decision(DEV_B, first[0]) is None:
            self.directed["ack_after_lost"] += 1
        if rng.random() < 0.5:
            self.sync(task_id, now + 7)
            self.check(task_id, msg_id, seq, log)

    def reverse(self, rng: random.Random, task_id: str, msg_id: str, seq: int, kinds: tuple[str, ...], now: int,
                log: list[str]) -> None:
        """B 的几条报告倒序交到 A：低号判 superseded（O2/O3b 的情形：superseded 跳过，不打断也不计入）。

        多数情形固定成 progress/blocked 之后交 ack：低号若被错当成已采纳，ACK 规则会让结果与 A 不同。
        """
        planned = ([rng.choice(("progress", "blocked")), "ack"] if rng.random() < 0.6
                   else [rng.choice(kinds) for _ in range(rng.randint(2, 3))])
        operations = self.submit(task_id, seq, planned, now, log)
        items = [item for item in self.b.store.outbox() if json.loads(item["envelope_json"])["kind"] == "report"
                 and json.loads(item["envelope_json"])["operationId"] in operations]
        for item in reversed(items):
            mirror.receive(self.a.store, self.a.ident, json.loads(item["envelope_json"]), source_device=DEV_B,
                           payload_hash=item["payload_hash"], now=now + 5)
            self.b.store.set_outbox_state(item["msg_id"], state="received")
        self.check(task_id, msg_id, seq, log)
        decided = [self.a.store.decision(DEV_B, item) for item in operations]
        if any(item is not None and item["decision"] == "superseded" for item in decided):
            self.directed["reverse"] += 1
        self.ship(rng, self.a, self.b, now + 6, lose=0.3)
        self.check(task_id, msg_id, seq, log)
        if rng.random() < 0.5:
            self.sync(task_id, now + 7)
            self.check(task_id, msg_id, seq, log)

    def lost_no_sync(self, rng: random.Random, task_id: str, msg_id: str, seq: int, kinds: tuple[str, ...], now: int,
                     log: list[str]) -> None:
        """报告送到 A，决定全部丢失、不插窄同步；一半情形另到一封只带 reportHigh 的 task_state。"""
        operations = self.submit(task_id, seq, [rng.choice(kinds) for _ in range(rng.randint(1, 2))], now, log)
        pump(self.b, self.a, now=now + 3)
        for item in self.decision_items(operations):
            self.a.store.set_outbox_state(item["msg_id"], state="expired")
        if rng.random() < 0.5:
            self.send_task_state(task_id, now + 4)
            log.append("task_state")
        pump(self.a, self.b, now=now + 5)
        if self.check(task_id, msg_id, seq, log):
            self.directed["lost_no_sync"] += 1

    # ---- 公共步骤与断言 ----

    def send_task_state(self, task_id: str, now: int) -> None:
        current = self.a.store.get_task(DEV_A, task_id)
        assert current is not None
        with self.a.store.transaction():
            authority.send_task_state(self.a.store, self.a.ident, current, now=now)

    def sync(self, task_id: str, now: int) -> None:
        mirrored = self.b.store.get_task(DEV_A, task_id)
        assert mirrored is not None
        mirror.request_sync(self.b.store, self.b.ident, mirrored, now=now)

    def converge(self, task_id: str, msg_id: str, seq: int, log: list[str], now: int) -> None:
        """收敛后置条件（两方 r0 审计 P2-3）：无损送达并窄同步到静止后，推导值与 A 相同。"""
        log.append("converge")
        for _ in range(3):
            now += 100
            pump(self.b, self.a, now=now)
            pump(self.a, self.b, now=now + 1)
            self.sync(task_id, now + 2)
            pump(self.b, self.a, now=now + 3)
            pump(self.a, self.b, now=now + 4)
            self.check(task_id, msg_id, seq, log)
        rows = [row for row in self.b.store.reports(DEV_A, task_id, seq) if row["reporter_device"] == DEV_B]
        for row in rows:  # 先确认真的静止了，否则下面的相等是空断言
            self.assertIsNotNone(self.b.store.decision(DEV_B, row["operation_id"]), log)
        a_attempt = self.a.store.attempt_by_msg(msg_id)
        b_task = self.b.store.get_task(DEV_A, task_id)
        b_attempt = self.b.store.attempt_by_msg(msg_id)
        a_task = self.a.store.get_task(DEV_A, task_id)
        assert a_attempt is not None and b_task is not None and b_attempt is not None and a_task is not None
        derived = mirror.derived_attempt(self.b.store, b_task, b_attempt, device_id=DEV_B)
        self.assertEqual(_timeless(derived.effective_work), _timeless(a_attempt.effective_work), log)
        self.coverage["converged"] += 1
        if a_task.current_work_seq == seq:
            b_view = commands.view_of(runtime(self.b, self.root), b_task)
            a_view = commands.view_of(runtime(self.a, self.root), a_task)
            self.assertEqual((b_view.phase, b_view.reason), (a_view.phase, a_view.reason), log)
            self.coverage["converged_view"] += 1

    def check(self, task_id: str, msg_id: str, seq: int, log: list[str]) -> bool:
        """逐步断言四条不变量；返回这一步镜像是否落后于 A。"""
        a_attempt = self.a.store.attempt_by_msg(msg_id)
        b_task = self.b.store.get_task(DEV_A, task_id)
        b_attempt = self.b.store.attempt_by_msg(msg_id)
        assert a_attempt is not None and b_task is not None and b_attempt is not None
        a_work = _timeless(a_attempt.effective_work)
        a_rows = [row for row in self.a.store.reports(DEV_A, task_id, seq) if row["reporter_device"] == DEV_B]
        b_rows = [row for row in self.b.store.reports(DEV_A, task_id, seq) if row["reporter_device"] == DEV_B]
        on_a = {row["operation_id"]: (self.a.store.decision(DEV_B, row["operation_id"]) or {}).get("decision")
                for row in a_rows}
        on_b = {row["operation_id"]: (self.b.store.decision(DEV_B, row["operation_id"]) or {}).get("decision")
                for row in b_rows}
        state: dict[str, Any] = {"work": "awaiting_ack"}
        prefixes = [dict(state)]  # A 已采纳报告各前缀的折叠值：A 真实有过的状态
        for row in a_rows:  # A 已采纳报告按 reportNo 升序折叠
            if on_a[row["operation_id"]] == "accepted":
                state = _ref_fold(state, row["report"])
                prefixes.append(state)
        self.assertEqual(state, a_work, log)  # 不变量 0
        derived = _timeless(mirror.derived_attempt(self.b.store, b_task, b_attempt, device_id=DEV_B).effective_work)
        self.assertIn(derived, prefixes, log)  # 不变量 1：只会落后，不会出现 A 没有过的状态
        raw_high = b_attempt.authority_state.get("reportHigh", 0)
        high = raw_high if isinstance(raw_high, int) and not isinstance(raw_high, bool) and raw_high > 0 else 0
        cut: int | None = None
        for row in b_rows:
            number, decided = int(row["report_no"]), on_b[row["operation_id"]]
            counted = decided == "accepted" or (decided is None and high > 0 and number == high)
            if counted:  # 不变量 1：镜像计入的报告在 A 上都已采纳
                self.assertEqual(on_a.get(row["operation_id"]), "accepted", log)
            if decided is not None:  # 不变量 3 的前提：B 的决定来自 A
                self.assertIn((on_a.get(row["operation_id"]), decided), {(decided, decided), (None, "superseded")}, log)
            elif not counted and cut is None:
                cut = number
        expected: dict[str, Any] = {"work": "awaiting_ack"}
        for row in a_rows:
            if on_a[row["operation_id"]] == "accepted" and (cut is None or int(row["report_no"]) < cut):
                expected = _ref_fold(expected, row["report"])
        self.coverage["cut"] += cut is not None
        self.assertEqual(derived, expected, log)  # 不变量 3：精确口径
        # 决定齐全：A 已裁决的报告 B 都有同样的决定，且号码不超过 A 的 reportHigh 的报告 B 都已有决定（A 还没见过的
        # 低号报告会把镜像的连续前缀挡在它前面，A 却可能已采纳了更高号的）
        a_high = int(a_attempt.authority_state.get("reportHigh", 0))
        complete = True
        for row in b_rows:
            decided_a, decided_b = on_a.get(row["operation_id"]), on_b[row["operation_id"]]
            if decided_a is not None:
                self.coverage["rejected"] += decided_a == "rejected"
                self.coverage["superseded"] += decided_a == "superseded"
                if decided_b != decided_a:
                    complete = False
            elif int(row["report_no"]) <= a_high:
                complete = False
        rows = [(int(row["report_no"]), row["report"], on_b[row["operation_id"]]) for row in b_rows]
        if derive_work(b_attempt.role, rows, report_high=0) != derive_work(b_attempt.role, rows, report_high=high):
            self.coverage["fallback"] += 1
        if complete:
            self.coverage["complete_equal"] += 1
            self.assertEqual(derived, a_work, log)  # 不变量 2：决定齐全时整份相等
        lagging = derived != a_work
        self.coverage["lagging"] += lagging
        return lagging

if __name__ == "__main__":
    unittest.main()
