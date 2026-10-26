"""P5 摘要读方（DESIGN §88.8）：本设备实际执行的联邦投递并入 summary.deliveries，组合新鲜度键，真实 JS 消费者静默。

覆盖：B 上 handoff/closure 投递进摘要（实际 pane/provider/messageId/kind）；A 的远端 attempt 不进 A 的摘要、
A 本机结果通知照常（普通 notice 不静默；真实 collabModel.js 消费见 test_contract_federation_summary）；
组合 ledgerId/修订号与 status/if-stale/worker 水位同口径；联邦库不可读时保持上一份摘要并标落后；
无联邦实例时水位与旧版逐字相同；合并排序/去重/冲突/上限。
"""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from typing import Any

import bridge_support  # noqa: F401  导入即隔离宿主会话环境

from agentstatus_bridge import summary
from agentstatus_bridge.closure import ACCEPTED
from agentstatus_bridge.federation import authority, mirror
from agentstatus_bridge.federation.delivery import FederationDispatcher
from agentstatus_bridge.federation.refs import TargetRef
from agentstatus_bridge.federation.relay import RelayPaths
from agentstatus_bridge.model import Delivery, Provider
from agentstatus_bridge.store import Store
from agentstatus_bridge.transports import DeliveryOutcome
from bridge_support import RecordingTransport, endpoint

from test_bridge_federation_delivery import bind
from test_bridge_federation_rules import DEV_A, DEV_B, T0, Device, pump

THREAD = "019a0000-1111-7222-8333-44445555cccc"
CLAUDE_A = "0000000a-1111-4222-8333-444444444444"


class FedSummaryCase(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.root = Path(self._tmp.name)
        sessions = patch.dict(os.environ, {"AB_CLAUDE_SESSIONS_DIR": str(self.root / "claude-sessions")})
        sessions.start()
        self.addCleanup(sessions.stop)
        self.a = Device(self.root, DEV_A, "vm")
        self.b = Device(self.root, DEV_B, "win")
        self.addCleanup(self.a.store.close)
        self.addCleanup(self.b.store.close)
        self.a.store.remember_device_name(DEV_B, "win")
        self.b.store.remember_device_name(DEV_A, "vm")
        self.origin = bind(self.a, Provider.CLAUDE, CLAUDE_A, pane="%1")
        self.worker = bind(self.b, Provider.CODEX, THREAD, pane="%3")
        self.local_a = Store.open(self.root / "vm")
        self.local_b = Store.open(self.root / "win")
        self.addCleanup(self.local_a.close)
        self.addCleanup(self.local_b.close)
        self.now = T0 + 10

    def clock(self) -> int:
        return self.now

    def dispatch(self, device: Device, transport: RecordingTransport, live: Any, *, reply: str | None = None) -> None:
        FederationDispatcher(device.store, device.ident, RelayPaths(self.root / device.ident.device_name),
                             discover=lambda: [live], transports={transport.provider: transport},
                             reply_address=reply, clock=self.clock, command="ab").run_once()

    def round_trip(self) -> tuple[str, str, str]:
        """A→B 交接投递、B 汇报结果、A 本机结果通知投递、A 验收、B 投递结束回执。返回 (任务, 交接 msg, 回执 msg)。"""
        task, first = authority.create_task(
            self.a.store, self.a.ident, title="跨设备", flow="handoff", body="请处理", refs=[], origin=self.origin,
            origin_actor=authority.actor_for(self.origin, wire_token="claude@vm"), origin_class="bypass",
            target=TargetRef(remote=self.worker.remote), reviewer=None, now=self.now)
        pump(self.a, self.b, now=self.now)
        assert self.worker.local is not None
        self.dispatch(self.b, RecordingTransport(Provider.CODEX), endpoint(self.worker.local))
        self.now += 1000
        [mirrored] = self.b.store.find_tasks(task.task_id)
        attempt = self.b.store.attempts(DEV_A, task.task_id)[0]
        mirror.submit_report(self.b.store, self.b.ident, mirror.LocalReport(
            task=mirrored, attempt=attempt, kind="result", note="完成", refs=[], commit=None,
            reporter=authority.actor_for(self.worker, wire_token="codex@win"), reporter_class="bypass",
            source="agent"), now=self.now)
        pump(self.b, self.a, now=self.now)
        assert self.origin.local is not None
        self.dispatch(self.a, RecordingTransport(Provider.CLAUDE, DeliveryOutcome(Delivery.DELIVERED, "claude_delivered")),
                      endpoint(self.origin.local), reply="uds:/x")
        self.now += 1000
        current = self.a.store.get_task(DEV_A, task.task_id)
        assert current is not None
        outcome = authority.finish(self.a.store, self.a.ident, current, state=ACCEPTED, reason=None, decider="用户",
                                   sender=None, sender_class="unknown", now=self.now)
        [closure] = outcome.closures
        pump(self.a, self.b, now=self.now)
        self.dispatch(self.b, RecordingTransport(Provider.CODEX), endpoint(self.worker.local))
        return task.task_id, first.msg_id, closure.msg_id

    def publish(self, device: str, store: Store) -> dict[str, Any]:
        summary.publish(store, self.root / device, force=True, now=1.0)
        document = summary.load(self.root / device)
        assert document is not None
        return document


class DeliveryMergeTests(FedSummaryCase):
    def test_b_publishes_its_real_federation_deliveries_and_a_does_not_copy_remote_attempts(self) -> None:
        task_id, handoff, closure = self.round_trip()
        b_doc = self.publish("win", self.local_b)
        self.assertEqual(b_doc["deliveries"], [
            {"messageId": closure, "role": "notice", "pane": "%3", "provider": "codex", "kind": "closure"},
            {"messageId": handoff, "role": "handoff", "pane": "%3", "provider": "codex"},
        ])
        a_doc = self.publish("vm", self.local_a)
        messages = {item["messageId"] for item in a_doc["deliveries"]}
        self.assertNotIn(handoff, messages)  # A 的远端投递副本不进 A 的摘要
        [notice] = a_doc["deliveries"]
        self.assertEqual((notice["role"], notice["pane"], notice["provider"], "kind" in notice),
                         ("notice", "%1", "claude", False))
        self.assertTrue(summary.is_valid(a_doc) and summary.is_valid(b_doc))
        self.assertNotIn(task_id, json.dumps(b_doc["deliveries"]))  # 时间与任务 ID 不出投递项

    def test_delivery_without_a_real_pane_is_not_published(self) -> None:
        paneless = bind(self.b, Provider.CODEX, THREAD.replace("c", "d"), pane=None)
        authority.create_task(
            self.a.store, self.a.ident, title="无 pane", flow="handoff", body="X", refs=[], origin=None,
            origin_actor=None, origin_class="unknown", target=TargetRef(remote=paneless.remote), reviewer=None,
            now=self.now)
        pump(self.a, self.b, now=self.now)
        assert paneless.local is not None
        transport = RecordingTransport(Provider.CODEX)
        self.dispatch(self.b, transport, endpoint(paneless.local))
        self.assertEqual(len(transport.calls), 1)
        self.assertEqual(self.b.store.recent_deliveries(), [])  # 没有真实 pane 不伪造

    def test_merge_orders_dedupes_drops_conflicts_and_caps(self) -> None:
        item = {"messageId": "1" * 32, "role": "handoff", "pane": "%1", "provider": "codex"}
        clash = {"messageId": "2" * 32, "role": "handoff", "pane": "%2", "provider": "codex"}
        wrong = dict(clash, pane="%9")
        many = [(float(index), {"messageId": f"{index:032x}", "role": "notice", "pane": "%5", "provider": "claude"})
                for index in range(100, 200)]
        merged = summary.merge_deliveries([(5.0, item), (3.0, clash)], [(5.0, dict(item)), (4.0, wrong)])
        self.assertEqual(merged, [item])  # 同内容去重；同 id 不同端点两条都不发布
        capped = summary.merge_deliveries(many[:60], many[60:])
        self.assertEqual(len(capped), summary.DELIVERY_LIMIT)
        self.assertEqual(capped[0]["messageId"], f"{199:032x}")  # 按内部时刻倒序


class FreshnessTests(FedSummaryCase):
    def test_without_federation_instance_mark_is_unchanged(self) -> None:
        bare = self.root / "bare"
        bare.mkdir(mode=0o700)
        with Store.open(bare) as store:
            self.assertEqual(summary.ledger_mark(store, bare), store.ledger_revision())
            summary.publish(store, bare, force=True, now=1.0)
            document = summary.load(bare)
            assert document is not None
            self.assertEqual((document["ledgerId"], document["ledgerRevision"]), store.ledger_revision())

    def test_composite_mark_drives_publish_status_and_if_stale(self) -> None:
        directory = self.root / "win"
        document = self.publish("win", self.local_b)
        local_id, local_revision = self.local_b.ledger_revision()
        instance, fed_revision = self.b.store.revision()
        # 独立预言：按设计公式重算，不复用被测函数
        expected = hashlib.sha256(json.dumps(["summary-fed-v1", local_id, instance], ensure_ascii=False,
                                             separators=(",", ":")).encode("utf-8")).hexdigest()
        self.assertEqual((document["ledgerId"], document["ledgerRevision"]), (expected, local_revision + fed_revision))
        self.assertEqual(summary.ledger_mark(self.local_b, directory), (document["ledgerId"], document["ledgerRevision"]))
        self.assertEqual(summary.status(directory, self.local_b)["state"], "ok")
        self.b.store.add_event(DEV_A, "f" * 32, "probe", now=self.now)  # 只有联邦库变化
        self.assertEqual(summary.status(directory, self.local_b)["state"], "stale")
        self.assertEqual(summary.publish(self.local_b, directory).status, "written")
        self.assertEqual(summary.publish(self.local_b, directory).status, "fresh")
        self.assertEqual(summary.status(directory, self.local_b)["state"], "ok")

    def test_worker_mark_reuses_its_open_federation_store(self) -> None:
        # worker 每秒一轮：传入已打开的联邦库就不再重开（Windows 上每次重开要做私有目录核验，Opus 审计 P3-9）
        directory = self.root / "win"
        expected = summary.ledger_mark(self.local_b, directory)
        with patch.object(summary, "open_federation", side_effect=AssertionError("不该重开联邦库")):
            self.assertEqual(summary.ledger_mark(self.local_b, directory, federation=self.b.store), expected)
        self.b.store.revision()  # 传入的库没有被关掉

    def test_unreadable_federation_keeps_previous_summary_and_marks_stale(self) -> None:
        directory = self.root / "win"
        self.publish("win", self.local_b)
        before = (directory / summary.SUMMARY_NAME).read_bytes()
        self.b.store.close()
        (directory / summary.FEDERATION_DB).rename(directory / "moved.sqlite3")
        (directory / summary.FEDERATION_CONFIG).write_text("{}", encoding="utf-8")  # 配置在而库缺失
        with self.assertRaises(summary.SummaryError) as caught:
            summary.publish(self.local_b, directory, force=True)
        self.assertEqual(caught.exception.code, "summary_federation_unavailable")
        self.assertEqual((directory / summary.SUMMARY_NAME).read_bytes(), before)
        state = summary.status(directory, self.local_b)
        self.assertEqual((state["state"], state["reason"]), ("stale", "summary_federation_unavailable"))


if __name__ == "__main__":
    unittest.main()
