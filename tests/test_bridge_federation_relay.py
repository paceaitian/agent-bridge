"""P5 relay 端到端（DESIGN §88.2/§88.3/§88.10，T03/T04/T13/T17/T18 的网络部分）：两台设备 + 真实 hub 会话（管道）。

覆盖：交接带附件 A→hub→B（上传、下载、重算 SHA、落地、镜像、L2、收据）；B 结果报告带附件回 A 裁决并生成本机通知；
hub 上附件一字节损坏 → B 运输拒绝、零 native 作业、A 派生 failed；hub 拒收报告 → 源端冻结解除；
commitCounter 回退与 hubId 变化 → hub_state_lost 冻结；ledgerInstance 不符；过期空洞 → sync_required → 窄同步收敛；
catchup 标志；Windows 式交付目录；SSH argv/专用配置；重连间隔。
"""

from __future__ import annotations

import errno
import json
import os
import sqlite3
import tempfile
import threading
import unittest
from dataclasses import replace
from pathlib import Path
from typing import Any
from unittest import mock

import bridge_support  # noqa: F401  导入即隔离宿主会话环境

from agentstatus_bridge.federation import attachments, authority, budget, mirror, retention
from agentstatus_bridge.closure import CLOSED
from agentstatus_bridge.federation.authority import Identity
from agentstatus_bridge.federation.codec import CodecError
from agentstatus_bridge.federation.config import (
    ConfigError,
    FederationConfig,
    check_state_root,
    load,
    save,
    ssh_argv,
    ssh_config_text,
)
from agentstatus_bridge.federation.fedstore import FederatedStore
from agentstatus_bridge.federation.hub import HubSession
from agentstatus_bridge.federation.hubstore import DAY_MS, HubStore, auth_fingerprint
from agentstatus_bridge.federation.mirror import LocalReport
from agentstatus_bridge.federation.refs import RemoteEndpointRef, TargetRef
from agentstatus_bridge.federation.relay import HubConnection, Relay, RelayPaths, RelayStop, reconnect_delay
from agentstatus_bridge.federation.transport import StreamTransport
from agentstatus_bridge.model import EndpointRef, Provider
from agentstatus_bridge.store import StoreError

from test_bridge_federation_hub import fingerprint, synthetic_key

T0 = 1_800_000_000_000
CODEX_B = "019a0000-0000-7000-8000-00000000000b"
CLAUDE_A = "0000000a-1111-4222-8333-444444444444"


class Clock:
    def __init__(self) -> None:
        self.now = T0

    def __call__(self) -> int:
        return self.now


class Device:
    def __init__(self, test: RelayTestCase, name: str, key: str, *, windows: bool = False) -> None:
        self.name = name
        self.key = key
        self.root = test.root / name
        self.root.mkdir(mode=0o700)
        self.device_id = test.hub.add_device(name=name, fingerprint=fingerprint(key))
        self.store = FederatedStore.create(self.root, now=T0)
        self.store.set_meta("deviceId", self.device_id)
        self.store.set_meta("hubId", test.hub.hub_id())
        self.store.set_meta("enabled", "1")  # 夹具代表已启用联邦的设备
        self.ident = Identity(device_id=self.device_id, device_name=name, hub_id=test.hub.hub_id())
        self.config = FederationConfig(enabled=True, hub_id=test.hub.hub_id(), device_id=self.device_id,
                                       device_name=name, host="hub.example", user="ab-relay",
                                       expected_state_root=str(self.root))
        appdata = test.root / f"{name}-LocalAppData" if windows else None
        if appdata is not None:
            appdata.mkdir()
        self.paths = RelayPaths(self.root, windows=windows, local_appdata=appdata)
        self.work = 0
        self.relay = self.make_relay(test)

    def make_relay(self, test: RelayTestCase) -> Relay:
        return Relay(self.store, self.ident, self.config, self.paths, connect=test.connector(self.name, self.key),
                     on_work=self._work, clock=test.clock)

    def _work(self) -> bool:
        self.work += 1
        return True  # 夹具代表「新起了 worker」；「已在运行」（None）的语义另有用例

    def bind(self, provider: Provider, native_id: str) -> TargetRef:
        local = EndpointRef(provider=provider, native_id=native_id, pid=4242, start_ticks="777", label=native_id[:8])
        endpoint_id, revision = self.store.bind_endpoint(provider=provider.value, native_id=native_id,
                                                         root_binding="root", local_ref=local.to_dict())
        remote = RemoteEndpointRef(device_id=self.device_id, provider=provider, native_id=native_id,
                                   endpoint_id=endpoint_id, endpoint_revision=revision)
        return TargetRef(remote=remote, local=local)

    def cycle(self, n: int = 1) -> str:
        return self.relay.connect_and_run(cycles=n, wait=lambda _s: None)


class RelayTestCase(unittest.TestCase):
    windows_b = False

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        self.clock = Clock()
        self.hub, _ = HubStore.init(self.root / "hub", now=T0)
        self.threads: list[threading.Thread] = []
        self.a = Device(self, "vm", synthetic_key(11))
        self.b = Device(self, "win", synthetic_key(12), windows=self.windows_b)
        self.origin = self.a.bind(Provider.CLAUDE, CLAUDE_A)
        self.worker = self.b.bind(Provider.CODEX, CODEX_B)

    def tearDown(self) -> None:
        for thread in self.threads:
            thread.join(timeout=5)
        self.a.store.close()
        self.b.store.close()
        self.hub.close()
        self._tmp.cleanup()

    def connector(self, name: str, key: str):
        auth = self.root / f"auth-{name}"
        auth.write_text(f"publickey {key}\n", encoding="utf-8")

        def connect() -> StreamTransport:
            r1, w1 = os.pipe()
            r2, w2 = os.pipe()
            server = StreamTransport(os.fdopen(r1, "rb"), os.fdopen(w2, "wb"))
            client = StreamTransport(os.fdopen(r2, "rb"), os.fdopen(w1, "wb"))

            def serve() -> None:
                store = HubStore.open(self.root / "hub")
                try:
                    HubSession(store, server, device_name=name, auth=lambda: auth_fingerprint(str(auth)),
                               clock=self.clock, tick_seconds=0.05).run()
                finally:
                    store.close()

            thread = threading.Thread(target=serve, daemon=True)
            thread.start()
            self.threads.append(thread)
            return client

        return connect

    def freeze(self, device: Device, *files: tuple[str, bytes]) -> list[dict[str, Any]]:
        src = device.root / "src"
        src.mkdir(exist_ok=True)
        names = []
        for name, data in files:
            (src / name).write_bytes(data)
            names.append(name)
        frozen = attachments.freeze(names, cwd=src, origin_device=device.device_id, staging=device.paths.staging)
        return [item.manifest for item in frozen]

    def create(self, refs: list[dict[str, Any]] | None = None):
        return authority.create_task(
            self.a.store, self.a.ident, title="跨设备", flow="handoff", body="请处理", refs=refs or [],
            origin=self.origin, origin_actor=authority.actor_for(self.origin, wire_token="claude@vm"),
            origin_class="bypass", target=TargetRef(remote=self.worker.remote), reviewer=None, now=self.clock.now)

    def b_report(self, task_id: str, kind: str, refs: list[dict[str, Any]] | None = None):
        task = self.b.store.get_task(self.a.device_id, task_id)
        assert task is not None
        attempt = self.b.store.attempts(self.a.device_id, task_id)[0]
        return mirror.submit_report(self.b.store, self.b.ident, LocalReport(
            task=task, attempt=attempt, kind=kind, note="完成", refs=refs or [], commit=None,
            reporter=authority.actor_for(self.worker, wire_token="codex@win"), reporter_class="bypass",
            source="agent"), now=self.clock.now)

    def tick(self, ms: int = 1000) -> None:
        self.clock.now += ms


class RoundTripTests(RelayTestCase):
    def test_handoff_and_report_with_attachments(self) -> None:
        refs = self.freeze(self.a, ("任务书.md", "# 任务\n细节".encode()))
        task, first = self.create(refs)
        self.assertEqual(self.a.cycle(), "connected")
        self.assertEqual(self.a.store.outbox_item(first.msg_id)["state"], "accepted")  # type: ignore[index]
        self.tick()
        self.assertEqual(self.b.cycle(), "connected")
        self.assertEqual(self.b.store.native(first.msg_id)["state"], "prepared")  # type: ignore[index]
        self.assertEqual(self.b.store.inbox_item(first.msg_id)["apply_state"], "ready")  # type: ignore[index]
        self.assertEqual(self.b.work, 1)
        (manifest,) = self.b.store.attachments(first.msg_id)
        self.assertEqual((manifest["state"], manifest["location"]), ("ready", "delivery"))
        landed = self.b.paths.delivery_base(self.b.store.ledger_instance_id()) / manifest["local_relpath"]
        self.assertEqual(landed.read_bytes(), "# 任务\n细节".encode())
        self.assertEqual(self.b.store.meta("ingressCatchup"), "0")
        self.tick()
        self.a.cycle()
        self.assertEqual(self.a.store.outbox_item(first.msg_id)["state"], "received")  # type: ignore[index]

        report_refs = self.freeze(self.b, ("结果.txt", b"result bytes"))
        result = self.b_report(task.task_id, "result", report_refs)
        self.tick()
        self.b.cycle()
        self.tick()
        self.a.cycle()
        self.assertEqual(self.a.store.decision(self.b.device_id, result.operation_id)["decision"], "accepted")  # type: ignore[index]
        notice = next(item for item in self.a.store.attempts(self.a.device_id, task.task_id) if item.role == "notice")
        self.assertEqual(self.a.store.native(notice.msg_id)["state"], "prepared")  # type: ignore[index]
        report_msg = self.a.store.inbox_by_operation(self.b.device_id, result.operation_id)
        assert report_msg is not None
        (received,) = self.a.store.attachments(report_msg["msg_id"])
        self.assertEqual((received["state"], received["report_operation_id"]), ("ready", result.operation_id))
        self.tick()
        self.b.cycle()
        self.assertEqual(self.b.store.decision(self.b.device_id, result.operation_id)["decision"], "accepted")  # type: ignore[index]

    def test_corrupted_blob_rejected_without_native(self) -> None:
        refs = self.freeze(self.a, ("a.bin", b"0123456789" * 100))
        _, first = self.create(refs)
        self.a.cycle()
        with sqlite3.connect(self.root / "hub" / "hub.sqlite3") as conn:
            conn.execute("UPDATE hub_blobs SET data=?", ((b"X" + b"0123456789" * 100)[:1000],))  # 一字节损坏
        self.tick()
        self.b.cycle()
        self.assertIsNone(self.b.store.native(first.msg_id))  # 附件损坏绝不建 native 作业
        self.assertEqual(self.b.store.inbox_item(first.msg_id)["apply_state"], "rejected")  # type: ignore[index]
        self.assertEqual(list(self.b.paths.parts.iterdir()), [])  # 坏 part 已清
        self.tick()
        self.a.cycle()
        self.assertEqual(self.a.store.outbox_item(first.msg_id)["state"], "rejected")  # type: ignore[index]
        attempt = self.a.store.attempt_by_msg(first.msg_id)
        assert attempt is not None
        self.assertEqual((attempt.delivery["state"], attempt.delivery["reason"]), ("failed", "attachment_hash_mismatch"))
        self.assertTrue(authority.proven_undelivered(attempt, self.a.ident))

    def test_hub_refused_report_releases_freeze(self) -> None:
        task, _ = self.create()
        self.a.cycle()
        self.tick()
        self.b.cycle()
        result = self.b_report(task.task_id, "result")
        self.hub.remove_device("vm", now=self.clock.now)  # A 被撤销：hub 拒收发给它的新信封（确定未 L1）
        self.tick()
        self.b.cycle()
        report = self.b.store.inbox_by_operation(self.b.device_id, result.operation_id)
        self.assertIsNone(report)
        outbox = [row for row in self.b.store.outbox(states=("refused",)) if row["operation_id"] == result.operation_id]
        self.assertEqual(len(outbox), 1)
        decision = self.b.store.decision(self.b.device_id, result.operation_id)
        self.assertEqual((decision or {}).get("decision"), "rejected")  # 冻结解除：可修订重报
        again = self.b_report(task.task_id, "result")
        self.assertEqual(again.report_no, result.report_no + 1)


class UncertainSubmitTests(RelayTestCase):
    """上次 submit 结果不明（submitting）时：先查收据；查不到又重交不了也不能当「确定未投」（审计 P1-01）。"""

    def delivered_after_lost_ack(self) -> tuple[Any, str, Path]:
        refs = self.freeze(self.a, ("synthetic.txt", b"one task"))
        task, first = self.create(refs)
        self.a.cycle()
        self.a.store.set_outbox_state(first.msg_id, state="submitting")  # hub 已 L1，A 记 accepted 前崩溃
        self.tick()
        self.b.cycle()
        self.assertEqual(self.b.store.native(first.msg_id)["state"], "prepared")  # type: ignore[index]  B 已收
        blob = self.a.paths.staging / f"{refs[0]['sha256']}.blob"
        return task, first.msg_id, blob

    def test_receipt_settles_uncertain_submit_without_reupload(self) -> None:
        _, msg_id, blob = self.delivered_after_lost_ack()
        self.tick(31 * DAY_MS)  # A 离线一个月：hub 已按 L2+30 天清掉内容与 blob，收据仍在
        for _ in range(2):
            self.hub.gc(now=self.clock.now, owner="test")
        blob.unlink()  # 源副本也丢了：不需要重传，按收据推进
        self.a.cycle()
        self.assertEqual(self.a.store.outbox_item(msg_id)["state"], "received")  # type: ignore[index]

    def test_missing_source_after_receipts_aged_out_is_not_proof(self) -> None:
        _, msg_id, blob = self.delivered_after_lost_ack()
        self.tick(61 * DAY_MS)
        self.hub.gc(now=self.clock.now, owner="test")  # hub 的收据与去重行也过了留存期
        blob.unlink()
        self.a.cycle()
        row = self.a.store.outbox_item(msg_id)
        assert row is not None
        attempt = self.a.store.attempt_by_msg(msg_id)
        assert attempt is not None
        self.assertEqual(row["state"], "expired")  # 放弃重交，但不是 refused
        self.assertFalse(authority.proven_undelivered(attempt, self.a.ident))

    def test_refusal_and_business_side_effect_commit_together(self) -> None:
        task, _ = self.create()
        self.a.cycle()
        self.tick()
        self.b.cycle()
        report = self.b_report(task.task_id, "result")
        item = next(row for row in self.b.store.outbox() if row["operation_id"] == report.operation_id)
        with mock.patch.object(mirror, "transport_failed", side_effect=StoreError("store_unavailable")):
            with self.assertRaises(StoreError):
                self.b.relay._refuse(item, "destination_unknown")  # pyright: ignore[reportPrivateUsage]
        current = self.b.store.outbox_item(item["msg_id"])
        assert current is not None
        self.assertEqual(current["state"], "ready")  # 业务收尾失败：传输终态一起回滚，下轮重来

    def test_receipt_state_and_business_side_effect_commit_together(self) -> None:
        # 合同 2：回执推进传输终态与业务收尾同一事务（Opus r2-P3-2 N10）
        task, _ = self.create()
        self.a.cycle()
        self.tick()
        self.b.cycle()
        report = self.b_report(task.task_id, "result")
        item = next(row for row in self.b.store.outbox() if row["operation_id"] == report.operation_id)
        receipt = {"state": "expired", "msgId": item["msg_id"], "at": self.clock.now, "reason": None}
        with mock.patch.object(mirror, "transport_failed", side_effect=StoreError("store_unavailable")):
            with self.assertRaises(StoreError):
                self.b.relay._apply_receipts([receipt])  # pyright: ignore[reportPrivateUsage]
        current = self.b.store.outbox_item(item["msg_id"])
        assert current is not None
        self.assertEqual(current["state"], item["state"])  # 业务收尾失败：终态一起回滚，下轮按同一回执重来

    def test_transient_store_error_keeps_report_retryable_until_applied(self) -> None:
        for code in ("store_busy", "federation_store_unavailable"):
            with self.subTest(code):
                task, _ = self.create()
                self.a.cycle()
                self.tick()
                self.b.cycle()
                report = self.b_report(task.task_id, "result")
                self.tick()
                self.b.cycle()
                with mock.patch.object(authority, "apply_report_safely", side_effect=StoreError(code)):
                    self.tick()
                    self.a.cycle()
                receipt = self.a.store.inbox_by_operation(self.b.device_id, report.operation_id)
                self.assertEqual((receipt or {}).get("apply_state"), "receiving")  # 不是永久拒收，也没 L2
                self.tick(31_000)  # hub 30 秒后重推同一操作
                self.a.cycle()
                decision = self.a.store.decision(self.b.device_id, report.operation_id)
                self.assertEqual((decision or {}).get("decision"), "accepted")
        self.tick()
        self.a.cycle()
        self.tick()
        self.b.cycle()
        mine = self.b.store.decision(self.b.device_id, report.operation_id)
        self.assertEqual((mine or {}).get("decision"), "accepted")  # B 也看到了决定

    def test_unseen_report_after_transport_ended_can_be_resubmitted(self) -> None:
        task, _ = self.create()
        self.a.cycle()
        self.tick()
        self.b.cycle()
        report = self.b_report(task.task_id, "result")
        item = next(row for row in self.b.store.outbox() if row["operation_id"] == report.operation_id)
        self.b.store.set_outbox_state(item["msg_id"], state="expired",
                                      receipt={"state": "expired", "at": self.clock.now - 120_000})
        for _ in range(2):  # B 发窄同步 → A 回「没见过」→ B 解除冻结
            self.tick(61_000)
            self.b.cycle()
            self.tick()
            self.a.cycle()
        self.tick()
        self.b.cycle()
        decision = self.b.store.decision(self.b.device_id, report.operation_id)
        self.assertEqual(((decision or {}).get("decision"), (decision or {}).get("reason")),
                         ("rejected", "report_not_seen"))
        again = self.b_report(task.task_id, "result")
        self.assertEqual(again.report_no, report.report_no + 1)


class WakeTests(RelayTestCase):
    def test_failed_worker_start_is_retried_without_new_messages(self) -> None:
        from agentstatus_bridge.federation import commands as fed_commands  # layout: allow 只在本用例用到命令层

        outcomes = iter([OSError("spawn failed")])

        def spawn(_root: Path) -> bool:
            failure = next(outcomes, None)
            if failure is not None:
                raise failure
            return False  # 之后：worker 已在运行

        start = mock.Mock(side_effect=spawn)
        self.b.relay._on_work = fed_commands.worker_starter(  # pyright: ignore[reportPrivateUsage]
            self.b.root, start=start, clock=lambda: self.clock.now / 1000)
        self.create()
        self.a.cycle()
        self.tick()
        self.b.cycle()
        self.assertEqual(start.call_count, 1)  # 新作业到达时拉起，失败
        for _ in range(2):  # 之后没有任何新消息
            self.tick(61_000)
            self.b.cycle()
        self.assertGreaterEqual(start.call_count, 2)


    def test_same_work_is_not_rewoken_every_period(self) -> None:
        # 停泊的作业（worker 等不到目标、空闲退出）不被 relay 每 15 秒拉回来常驻（Opus 审计 P2-1）
        self.create()
        self.a.cycle()
        self.tick()
        self.b.cycle()
        self.assertEqual(self.b.work, 1)
        for _ in range(3):
            self.tick(61_000)
            self.b.cycle()
        self.assertEqual(self.b.work, 1)
        self.create()  # 新作业到达：再拉起一次
        self.tick()
        self.a.cycle()
        self.tick()
        self.b.cycle()
        self.assertEqual(self.b.work, 2)

    def test_dead_worker_intent_is_rewoken_until_recovered(self) -> None:
        # worker 提交 intent 后死掉：同一作业已拉起过，也要再拉起 worker 把它恢复为 UNKNOWN（Codex r2-P2-02）
        _, first = self.create()
        self.a.cycle()
        self.tick()
        self.b.cycle()
        self.assertEqual(self.b.work, 1)
        with self.b.store.transaction() as conn:
            conn.execute("UPDATE fed_native_sends SET state='intent', intent_at=?, worker_generation=? WHERE msg_id=?",
                         (self.clock.now, json.dumps({"pid": 2**22 + 7, "start": "1"}), first.msg_id))
        self.tick(16_000)
        self.b.cycle()
        self.tick(16_000)
        self.b.cycle()
        self.assertEqual(self.b.work, 3)  # 收敛之前每个周期都确认 worker 在跑（已在跑时 ensure_worker 只探锁）
        with self.b.store.transaction() as conn:
            conn.execute("UPDATE fed_native_sends SET state='unknown' WHERE msg_id=?", (first.msg_id,))
        self.tick(16_000)
        self.b.cycle()
        self.assertEqual(self.b.work, 3)  # 恢复收敛后不再拉起

    def test_woken_work_is_rechecked_with_doubling_interval(self) -> None:
        # 拉起过仍在的作业：12 分钟后复查一次，之后间隔翻倍——worker 启动即退出、目标回来了都迟早接上，
        # 等不到目标时 worker 也基本不驻留（Codex r2-P2-02 与 §4 的停泊取舍）
        self.create()
        self.a.cycle()
        self.tick()
        self.b.cycle()
        self.assertEqual(self.b.work, 1)
        self.tick(11 * 60_000)
        self.b.cycle()
        self.assertEqual(self.b.work, 1)
        self.tick(61_000)
        self.b.cycle()
        self.assertEqual(self.b.work, 2)
        self.tick(23 * 60_000)
        self.b.cycle()
        self.assertEqual(self.b.work, 2)  # 第二次间隔是 24 分钟
        self.tick(61_000)
        self.b.cycle()
        self.assertEqual(self.b.work, 3)

    def test_running_worker_does_not_absorb_the_wake(self) -> None:
        # worker 已在跑（可能正要空闲退出）：relay 不记下、下个周期再探；真正新起了 worker 才记下（Opus r2-P2-1）
        from agentstatus_bridge.federation import commands as fed_commands  # layout: allow 只在本用例用到命令层

        results = iter([False, False])  # 前两次：已在运行；之后新起

        start = mock.Mock(side_effect=lambda _root: next(results, True))
        self.b.relay._on_work = fed_commands.worker_starter(  # pyright: ignore[reportPrivateUsage]
            self.b.root, start=start, clock=lambda: self.clock.now / 1000)
        self.create()
        self.a.cycle()
        self.tick()
        self.b.cycle()
        self.assertEqual(start.call_count, 1)
        for _ in range(4):
            self.tick(16_000)
            self.b.cycle()
        self.assertEqual(start.call_count, 3)  # 两次「已在跑」都没记下；第三次新起后记下，不再每周期拉起

    def test_local_session_change_rechecks_woken_work_at_once(self) -> None:
        # 本机会话出现或消失（目录 digest 变化）：停泊作业等的目标可能回来了，立即复查（Opus r2-P2-2）
        from agentstatus_bridge.federation import directory as fed_directory  # layout: allow 只在本用例用到目录层

        complete = {"codex": True, "claude": True}

        def sample() -> dict[str, Any]:
            return fed_directory.snapshot(self.b.store, self.b.device_id, [], publish_names=True,
                                          provider_complete=dict(complete))

        self.b.relay._directory = sample  # pyright: ignore[reportPrivateUsage]
        self.create()
        self.a.cycle()
        self.tick()
        self.b.cycle()
        self.assertEqual(self.b.work, 1)
        self.tick(31_000)
        self.b.cycle()
        self.assertEqual(self.b.work, 1)  # 目录没变：不复查
        complete["codex"] = False
        self.tick(31_000)
        self.b.cycle()
        self.assertEqual(self.b.work, 2)

    def test_name_only_change_republishes_the_directory(self) -> None:
        # §91.6：目录 digest 覆盖整帧（含 name/namesVerified）；只改原生主名也要重发，远端才不会一直按旧名字寻址。
        # 采样周期 30 秒（DIRECTORY_SAMPLE_MS），每步拨 31 秒
        item: dict[str, Any] = {"provider": "codex", "nativeId": CODEX_B, "endpointId": "e" * 32, "endpointRevision": 1,
                                "inbox": True, "eligible": True, "namesVerified": True, "name": "alpha"}
        self.b.relay._directory = lambda: {  # pyright: ignore[reportPrivateUsage]
            "endpoints": [dict(item)], "complete": True, "providers": {"codex": True}, "namePolicy": "agent-native-v1"}
        self.b.cycle()
        first = int(self.b.store.meta("directoryRevision") or "0")
        self.assertGreaterEqual(first, 1)
        self.tick(31_000)
        self.b.cycle()
        self.assertEqual(int(self.b.store.meta("directoryRevision") or "0"), first)  # 没变：不重发
        item["name"] = "beta"
        self.tick(31_000)
        self.b.cycle()
        self.assertEqual(int(self.b.store.meta("directoryRevision") or "0"), first + 1)
        item["namesVerified"] = False  # 只改核实状态同样要重发
        self.tick(31_000)
        self.b.cycle()
        self.assertEqual(int(self.b.store.meta("directoryRevision") or "0"), first + 2)

    def test_work_paused_after_wake_is_rewoken_on_resume(self) -> None:
        # 拉起之后才暂停：作业离开候选、记录随之清掉；恢复后算新作业，立即拉起（Opus r2-P3-2 N02）
        task, _ = self.create()
        self.a.cycle()
        self.tick()
        self.b.cycle()
        self.assertEqual(self.b.work, 1)
        current = self.a.store.get_task(self.a.device_id, task.task_id)
        assert current is not None
        paused = authority.set_paused(self.a.store, self.a.ident, current, paused=True, now=self.clock.now)
        self.tick()
        self.a.cycle()
        self.tick(16_000)
        self.b.cycle()
        authority.set_paused(self.a.store, self.a.ident, paused, paused=False, now=self.clock.now)
        self.tick()
        self.a.cycle()
        self.tick(16_000)
        self.b.cycle()
        self.assertEqual(self.b.work, 2)

    def test_recheck_interval_is_capped_at_six_hours(self) -> None:
        # 翻倍到 6 小时封顶：长期等不到目标的作业，最迟 6 小时也会被复查一次
        from agentstatus_bridge.federation import relay as relay_module  # layout: allow 只在本用例读间隔常量

        self.create()
        self.a.cycle()
        self.tick()
        self.b.cycle()
        interval = relay_module.REWAKE_MIN_MS
        while interval < relay_module.REWAKE_MAX_MS:
            self.tick(interval + 16_000)
            self.b.cycle()
            interval *= 2
        woken = self.b.work
        for _ in range(2):
            self.tick(relay_module.REWAKE_MAX_MS - 60_000)
            self.b.cycle()
            self.assertEqual(self.b.work, woken)
            self.tick(76_000)
            self.b.cycle()
            woken += 1
            self.assertEqual(self.b.work, woken)  # 之后每次都是 6 小时，不再翻倍

    def test_due_origin_reminder_wakes_worker_on_authority(self) -> None:
        # A 上发起方提醒到期而 worker 不在（崩溃或重启）：relay 拉起 worker 来排（Opus r3-P3-1）
        from agentstatus_bridge.federation.delivery import FederationDispatcher  # layout: allow 只在本用例投通知
        from agentstatus_bridge.model import Delivery  # layout: allow 只在本用例构造投递结果
        from agentstatus_bridge.transports import DeliveryOutcome  # layout: allow 同上
        from bridge_support import RecordingTransport, endpoint  # layout: allow 同上

        task, _ = self.create()
        self.a.cycle()
        self.tick()
        self.b.cycle()
        self.b_report(task.task_id, "result")
        self.tick()
        self.b.cycle()
        self.tick()
        self.a.cycle()
        origin_ref = self.origin.local
        assert origin_ref is not None
        claude = RecordingTransport(Provider.CLAUDE, DeliveryOutcome(Delivery.DELIVERED, "claude_delivered"))
        # 夹具绑定的根是占位值 "root"；根核对不是本用例的对象
        with mock.patch("agentstatus_bridge.federation.delivery.root_binding", return_value="root"):
            FederationDispatcher(self.a.store, self.a.ident, self.a.paths, discover=lambda: [endpoint(origin_ref)],
                                 transports={Provider.CLAUDE: claude}, reply_address="uds:/x", clock=self.clock,
                                 command="ab").run_once()
        self.assertEqual(len(claude.calls), 1)  # 结果通知已交给发起方
        woken = self.a.work
        self.tick(10 * 60_000)
        self.a.cycle()
        self.assertEqual(self.a.work, woken)  # 提醒还没到期：不拉起
        self.tick(21 * 60_000)
        self.a.cycle()
        self.assertEqual(self.a.work, woken + 1)

    def test_paused_work_wakes_only_after_resume(self) -> None:
        task, _ = self.create()
        self.a.cycle()
        current = self.a.store.get_task(self.a.device_id, task.task_id)
        assert current is not None
        paused = authority.set_paused(self.a.store, self.a.ident, current, paused=True, now=self.clock.now)
        self.tick()
        self.a.cycle()
        self.tick()
        self.b.cycle()
        self.tick(61_000)
        self.b.cycle()
        self.assertEqual(self.b.work, 0)  # 暂停的作业现在处理不了：不拉起 worker
        authority.set_paused(self.a.store, self.a.ident, paused, paused=False, now=self.clock.now)
        self.tick()
        self.a.cycle()
        self.tick()
        self.b.cycle()
        self.tick(16_000)
        self.b.cycle()
        self.assertEqual(self.b.work, 1)


class LocalStoreBusyTests(RelayTestCase):
    """收件分类之外的本机写遇到库忙：结束这条连接、按退避重连，不让 relay 进程崩出（Opus r2-P3-3）。"""

    def test_storage_failure_outside_receive_reconnects(self) -> None:
        self.create()
        self.a.cycle()
        self.tick()
        with mock.patch.object(self.b.store, "remember_device_name", side_effect=StoreError("store_busy")):
            try:
                state = self.b.relay.connect_and_run(cycles=1, wait=lambda _s: None)
            except StoreError as error:
                self.fail(f"本机库忙让 relay 崩出：{error.code}")
        self.assertEqual(state, "reconnecting")
        self.tick(31_000)
        self.b.cycle()
        self.assertEqual(len(self.b.store.natives_in(("prepared",))), 1)  # 重推后照常接上

    def test_other_store_errors_still_surface(self) -> None:
        self.create()
        self.a.cycle()
        self.tick()
        with mock.patch.object(self.b.store, "remember_device_name", side_effect=StoreError("record_conflict")):
            with self.assertRaises(StoreError):
                self.b.relay.connect_and_run(cycles=1, wait=lambda _s: None)


class StopTests(RelayTestCase):
    def test_should_stop_ends_an_open_connection(self) -> None:
        calls = {"n": 0}

        def stop() -> bool:
            calls["n"] += 1
            return calls["n"] > 2

        # 停用后不必等连接断开：每轮前检查一次，第三轮前退出（cycles 给上限，缺检查时以 connected 结束而非挂起）
        self.assertEqual(self.a.relay.connect_and_run(cycles=5, wait=lambda _s: None, should_stop=stop), "stopped")
        self.assertEqual(self.a.store.meta("relayState"), "offline")


class LossDetectionTests(RelayTestCase):
    def test_counter_rollback_freezes(self) -> None:
        self.a.cycle()
        key = f"maxHubCommitCounter:{self.hub.hub_id()}"
        seen = int(self.a.store.meta(key) or "0")
        self.assertGreater(seen, 0)
        self.a.store.set_meta(key, str(seen + 1000))  # 等价于 hub 回到了一个更旧的备份
        self.assertEqual(self.a.cycle(), "hub_state_lost")
        self.assertEqual(self.a.store.meta("hubStateLost"), "1")
        self.assertEqual(self.a.store.meta("relayState"), "hub_state_lost")
        self.a.store.set_meta(key, str(seen))
        self.assertEqual(self.a.cycle(), "hub_state_lost")  # 已冻结：不因计数恢复而自动解冻

    def test_hub_id_change_freezes(self) -> None:
        self.a.config = FederationConfig(**{**self.a.config.__dict__, "hub_id": "9" * 32})
        self.a.relay = self.a.make_relay(self)
        self.assertEqual(self.a.cycle(), "hub_state_lost")

    def test_ledger_instance_mismatch(self) -> None:
        self.b.cycle()
        self.b.store.close()
        os.unlink(self.b.root / "federation.sqlite3")
        self.b.store = FederatedStore.create(self.b.root, now=T0)  # 丢库后新建：新 ledgerInstanceId
        self.b.store.set_meta("deviceId", self.b.device_id)
        self.b.relay = self.b.make_relay(self)
        self.assertEqual(self.b.cycle(), "ledger_instance_mismatch")

    def test_out_of_order_counter_does_not_freeze(self) -> None:
        self.a.cycle()
        key = f"maxHubCommitCounter:{self.hub.hub_id()}"
        seen = self.a.store.meta(key)
        self.a.relay._observe_counter(1)  # pyright: ignore[reportPrivateUsage]  旧回复晚到：只取 max
        self.assertEqual(self.a.store.meta(key), seen)  # 持久最大值不倒退
        self.assertEqual(self.a.cycle(), "connected")

    def test_catchup_set_until_first_fetch_end(self) -> None:
        transport = self.a.relay._connect()  # pyright: ignore[reportPrivateUsage]
        try:
            self.a.store.set_meta("ingressCatchup", "0")
            self.a.relay.handshake(transport)
            self.assertEqual(self.a.store.meta("ingressCatchup"), "1")  # 重连后先持久 catchup，worker 不领取
            self.a.relay.cycle()
            self.assertEqual(self.a.store.meta("ingressCatchup"), "0")
        finally:
            transport.close()


def shorten(device: Device, msg_id: str, ms: int) -> None:
    """把尚未提交的 outbox 信封有效期改短（重算发件哈希），用来制造 TTL 内的过期。"""
    from agentstatus_bridge.federation.codec import payload_hash
    from agentstatus_bridge.federation.fedstore import dump, load_dict

    row = device.store.outbox_item(msg_id)
    assert row is not None
    envelope = load_dict(row["envelope_json"])
    envelope["expiresAt"] = envelope["createdAt"] + ms
    with device.store.transaction() as conn:
        conn.execute("UPDATE fed_outbox SET envelope_json=?, payload_hash=?, expires_at=? WHERE msg_id=?",
                     (dump(envelope), payload_hash(envelope), envelope["expiresAt"], msg_id))


class SyncTests(RelayTestCase):
    def test_expired_gap_without_staleness(self) -> None:
        task, _ = self.create()
        self.a.cycle()
        self.tick()
        self.b.cycle()
        current = self.a.store.get_task(self.a.device_id, task.task_id)
        assert current is not None
        authority.set_paused(self.a.store, self.a.ident, current, paused=True, now=self.clock.now)
        (state_msg,) = [row["msg_id"] for row in self.a.store.outbox()]
        shorten(self.a, state_msg, DAY_MS)
        self.a.cycle()
        self.clock.now += 2 * DAY_MS  # 远小于 29 天：只有过期空洞能触发同步
        self.hub.gc(now=self.clock.now, owner="t")
        self.b.cycle()
        mirrored = self.b.store.get_task(self.a.device_id, task.task_id)
        assert mirrored is not None
        self.assertTrue(mirrored.sync_required)

    def test_expired_attempt_is_not_proof(self) -> None:
        _, first = self.create()
        shorten(self.a, first.msg_id, DAY_MS)
        self.a.cycle()
        self.clock.now += 2 * DAY_MS
        self.hub.gc(now=self.clock.now, owner="t")
        self.a.cycle()
        self.assertEqual(self.a.store.outbox_item(first.msg_id)["state"], "expired")  # type: ignore[index]
        attempt = self.a.store.attempt_by_msg(first.msg_id)
        assert attempt is not None
        self.assertEqual(attempt.delivery["state"], "pending")
        self.assertFalse(authority.proven_undelivered(attempt, self.a.ident))  # 过期不等于对方没收到

    def test_expired_gap_marks_sync_and_converges(self) -> None:
        task, _ = self.create()
        self.a.cycle()
        self.tick()
        self.b.cycle()
        current = self.a.store.get_task(self.a.device_id, task.task_id)
        assert current is not None
        authority.set_paused(self.a.store, self.a.ident, current, paused=True, now=self.clock.now)
        self.a.cycle()  # task_state 进 hub，B 一直不在线
        self.clock.now += 31 * DAY_MS
        self.hub.gc(now=self.clock.now, owner="t")
        self.b.cycle()
        mirrored = self.b.store.get_task(self.a.device_id, task.task_id)
        assert mirrored is not None
        self.assertTrue(mirrored.sync_required)  # 来自 A 的过期空洞
        self.assertFalse(mirrored.paused)
        self.tick()
        self.b.cycle()  # 窄 sync_request 发出
        self.tick()
        self.a.cycle()  # A 回 sync_state
        self.tick()
        self.b.cycle()
        mirrored = self.b.store.get_task(self.a.device_id, task.task_id)
        assert mirrored is not None
        self.assertFalse(mirrored.sync_required)
        self.assertTrue(mirrored.paused)


    def test_relay_marks_stale_or_clock_rolled_back_mirror_for_sync(self) -> None:
        # worker 只挡住领取；脱困靠 relay 打 sync_required 发窄同步（Opus r2-P3-2 N43/N15）
        for label, shift in (("stale", -30 * DAY_MS), ("rollback", 15 * 60_000)):
            with self.subTest(label):
                task, _ = self.create()
                self.a.cycle()
                self.tick()
                self.b.cycle()
                with self.b.store.transaction() as conn:
                    conn.execute("UPDATE fed_tasks SET last_sync_at=? WHERE authority_device=? AND task_id=?",
                                 (self.clock.now + shift, self.a.device_id, task.task_id))
                self.tick(61_000)
                self.b.cycle()
                mirrored = self.b.store.get_task(self.a.device_id, task.task_id)
                assert mirrored is not None
                self.assertTrue(mirrored.sync_required)

    def test_one_open_sync_request_per_task_while_a_is_offline(self) -> None:
        task, _ = self.create()
        self.a.cycle()
        self.tick()
        self.b.cycle()
        with self.b.store.transaction() as conn:
            conn.execute("UPDATE fed_tasks SET sync_required=1 WHERE task_id=?", (task.task_id,))
        for _ in range(10):  # A 一直不在线：十分钟里 B 每分钟一轮
            self.tick(61_000)
            self.b.cycle()
        open_requests = self.b.store.connection.execute(
            "SELECT COUNT(*) FROM fed_outbox WHERE state IN ('ready','submitting','accepted')"
            " AND json_extract(envelope_json,'$.kind')='sync_request'").fetchone()[0]
        self.assertEqual(open_requests, 1)  # §88.4 第 7 条：每 task 最多一个未结查询（Opus 审计 P3-3）
        self.tick()
        self.a.cycle()
        self.tick()
        self.b.cycle()
        mirrored = self.b.store.get_task(self.a.device_id, task.task_id)
        assert mirrored is not None
        self.assertFalse(mirrored.sync_required)  # A 回来后照常收敛

    def test_expired_gap_is_marked_before_items_and_catchup_clears_after(self) -> None:
        task, _ = self.create()
        self.a.cycle()
        self.tick()
        self.b.cycle()
        current = self.a.store.get_task(self.a.device_id, task.task_id)
        assert current is not None
        paused = authority.set_paused(self.a.store, self.a.ident, current, paused=True, now=self.clock.now)
        (state_msg,) = [row["msg_id"] for row in self.a.store.outbox()]
        shorten(self.a, state_msg, DAY_MS)
        self.a.cycle()
        self.clock.now += 2 * DAY_MS
        self.hub.gc(now=self.clock.now, owner="t")
        authority.set_paused(self.a.store, self.a.ident, paused, paused=False, now=self.clock.now)
        self.a.cycle()  # 空洞之后又有一封新信封：同一批 fetch 里既有过期来源又有 item
        seen: list[tuple[str | None, bool]] = []
        real = self.b.relay._process_item  # pyright: ignore[reportPrivateUsage]

        def spy(item: dict[str, Any]) -> bool:
            mirrored = self.b.store.get_task(self.a.device_id, task.task_id)
            seen.append((self.b.store.meta("ingressCatchup"), bool(mirrored and mirrored.sync_required)))
            return real(item)

        self.b.relay._process_item = spy  # type: ignore[method-assign]
        self.tick()
        self.b.cycle()
        self.assertTrue(seen)
        self.assertEqual(seen[0], ("1", True))  # §88.2：先按空洞打标再应用 item，追赶标记最后才清
        self.assertEqual(self.b.store.meta("ingressCatchup"), "0")

    def test_lost_decision_recovered_by_narrow_sync(self) -> None:
        task, _ = self.create()
        self.a.cycle()
        self.tick()
        self.b.cycle()
        result = self.b_report(task.task_id, "result")
        self.tick()
        self.b.cycle()  # 报告交给 hub
        self.tick()
        # A 裁决后决定信封丢失（例如过期被回收）：只删 A 的决定 outbox，不动报告事实
        relay_order = self.a.relay
        self.a.relay = self.a.make_relay(self)
        self.a.relay._submit_outbox = lambda: None  # pyright: ignore[reportPrivateUsage]  本轮不发出
        self.a.cycle()
        self.a.relay = relay_order
        with self.a.store.transaction() as conn:
            conn.execute("DELETE FROM fed_outbox WHERE envelope_json LIKE '%report_decision%'")
        self.tick()
        self.b.cycle()  # 收到 L2 收据
        self.assertIsNone(self.b.store.decision(self.b.device_id, result.operation_id))
        self.clock.now += 61_000
        self.b.cycle()  # 决定超过 60 秒未到：排 sync_request
        self.tick()
        self.b.cycle()
        self.tick()
        self.a.cycle()
        self.tick()
        self.b.cycle()
        self.assertEqual((self.b.store.decision(self.b.device_id, result.operation_id) or {}).get("decision"),
                         "accepted")


class BudgetTests(RelayTestCase):
    """设备内容预算（§88.11/T15）：收端新附件超出预算或磁盘写满就延后、不发 L2；腾出空间后接上；没有附件的事实照常。"""

    def set_budget(self, device: Device, value: int) -> None:
        device.config = replace(device.config, storage_budget=value)
        device.relay.config = device.config

    def outbox_state(self, msg_id: str) -> str:
        item = self.a.store.outbox_item(msg_id)
        assert item is not None
        return str(item["state"])

    def test_incoming_attachment_over_budget_defers_then_resumes_at_exact_fit(self) -> None:
        refs = self.freeze(self.a, ("a.bin", b"x" * 1000))
        _, first = self.create(refs)
        self.a.cycle()
        self.set_budget(self.b, 1)
        self.tick()
        self.b.cycle()
        self.assertIsNone(self.b.store.native(first.msg_id))  # 没下载就不建 native
        self.assertEqual(self.b.store.inbox_item(first.msg_id)["apply_state"], "receiving")  # type: ignore[index]
        self.assertTrue(self.b.store.meta(budget.DEFERRED_META))
        self.assertIsNone(self.b.store.meta(attachments.WRITE_FAILED_META))  # 预算延后不是落地写失败，两个时刻不混用
        self.assertGreater(budget.usage(self.b.store, self.b.paths).envelope_bytes, 0)  # 已收信封计入占用
        self.assertFalse(self.b.paths.parts.exists() and any(self.b.paths.parts.iterdir()))
        self.tick()
        self.a.cycle()
        self.assertEqual(self.outbox_state(first.msg_id), "accepted")  # 没有假 L2
        # 剩余比需要少 1 字节：仍延后；正好够：接上
        self.set_budget(self.b, budget.usage(self.b.store, self.b.paths).total + 999)
        self.tick(31_000)
        self.b.cycle()
        self.assertIsNone(self.b.store.native(first.msg_id))
        self.set_budget(self.b, budget.usage(self.b.store, self.b.paths).total + 1000)
        self.tick(31_000)
        self.b.cycle()
        self.assertEqual((self.b.store.native(first.msg_id) or {}).get("state"), "prepared")
        self.assertEqual(self.b.store.meta(budget.DEFERRED_META), "")  # 预检通过后清掉延后标记
        self.tick()
        self.a.cycle()
        self.assertEqual(self.outbox_state(first.msg_id), "received")

    def test_messages_without_attachments_ignore_budget(self) -> None:
        self.set_budget(self.a, 1)
        self.set_budget(self.b, 1)
        task, first = self.create()
        self.a.cycle()
        self.tick()
        self.b.cycle()
        self.assertEqual((self.b.store.native(first.msg_id) or {}).get("state"), "prepared")
        result = self.b_report(task.task_id, "result")
        self.tick()
        self.b.cycle()
        self.tick()
        self.a.cycle()
        decision = self.a.store.decision(self.b.device_id, result.operation_id)
        self.assertEqual((decision or {}).get("decision"), "accepted")  # 报告事实不因预算受阻

    def test_disk_full_while_landing_defers_instead_of_rejecting(self) -> None:
        refs = self.freeze(self.a, ("a.bin", b"payload"))
        _, first = self.create(refs)
        self.a.cycle()
        self.tick()
        with mock.patch("agentstatus_bridge.federation.attachments.os.link",
                        side_effect=OSError(errno.ENOSPC, "synthetic disk full")):
            self.assertEqual(self.b.cycle(), "connected")
        self.assertEqual(self.b.store.inbox_item(first.msg_id)["apply_state"], "receiving")  # type: ignore[index]
        self.tick()
        self.a.cycle()
        self.assertEqual(self.outbox_state(first.msg_id), "accepted")  # 不是永久拒收
        self.tick(31_000)
        self.b.cycle()
        self.assertEqual((self.b.store.native(first.msg_id) or {}).get("state"), "prepared")

    def test_disk_full_while_creating_delivery_directory_defers(self) -> None:
        # 建交付目录时写满也是暂时的：留在 receiving、不拒收，腾出空间后同一操作接上（Codex r2-P2-03）
        refs = self.freeze(self.a, ("a.bin", b"x" * 10))
        _, first = self.create(refs)
        self.a.cycle()
        self.tick()
        base = os.path.realpath(self.b.paths.delivery_base(self.b.store.ledger_instance_id()))
        real_mkdir = os.mkdir

        def mkdir(path: Any, *args: Any, **kwargs: Any) -> None:
            if os.path.realpath(path) == base:
                raise OSError(errno.ENOSPC, "synthetic disk full")
            real_mkdir(path, *args, **kwargs)

        with mock.patch("agentstatus_bridge.federation.attachments.os.mkdir", side_effect=mkdir) as patched:
            self.b.cycle()
        self.assertTrue(any(os.path.realpath(call.args[0]) == base for call in patched.call_args_list))
        self.assertEqual(self.b.store.inbox_item(first.msg_id)["apply_state"], "receiving")  # type: ignore[index]
        self.tick()
        self.a.cycle()
        self.assertEqual(self.outbox_state(first.msg_id), "accepted")  # 不是永久拒收
        self.tick(31_000)
        self.b.cycle()
        self.assertEqual((self.b.store.native(first.msg_id) or {}).get("state"), "prepared")

    def test_recorded_but_missing_pending_leaf_still_needs_budget(self) -> None:
        # 半成品叶只在记录里、文件已不在：要重新下载，照样核预算（Codex r2-P2-04）
        refs = self.freeze(self.a, ("a.bin", b"x" * 1000))
        _, first = self.create(refs)
        self.a.cycle()
        self.set_budget(self.b, 1)
        self.tick()
        self.b.cycle()
        self.b.store.update_attachment(first.msg_id, 0, file_identity_json=json.dumps(
            {"pendingLeaf": "lost/file.bin", "dev": 0, "ino": 0, "size": 0, "mtimeNs": 0}))
        self.tick(31_000)
        self.b.cycle()
        self.assertIsNone(self.b.store.native(first.msg_id))
        self.assertEqual(self.b.store.inbox_item(first.msg_id)["apply_state"], "receiving")  # type: ignore[index]
        self.set_budget(self.b, budget.usage(self.b.store, self.b.paths).total + 1000)
        self.tick(31_000)
        self.b.cycle()
        self.assertEqual((self.b.store.native(first.msg_id) or {}).get("state"), "prepared")

    def test_verified_pending_leaf_is_adopted_without_budget(self) -> None:
        # 崩溃留下、核实完整的半成品叶直接采用，不再下载，也就不需要预算
        data = b"x" * 1000
        refs = self.freeze(self.a, ("a.bin", data))
        _, first = self.create(refs)
        self.a.cycle()
        self.set_budget(self.b, 1)
        self.tick()
        self.b.cycle()
        base = self.b.paths.delivery_base(self.b.store.ledger_instance_id())
        leaf = base / "crashed" / "a.bin"
        leaf.parent.mkdir(parents=True)
        leaf.write_bytes(data)
        info = os.lstat(leaf)
        self.b.store.update_attachment(first.msg_id, 0, file_identity_json=json.dumps(
            {"pendingLeaf": "crashed/a.bin", "dev": info.st_dev, "ino": info.st_ino, "size": info.st_size,
             "mtimeNs": info.st_mtime_ns}))
        self.set_budget(self.b, budget.usage(self.b.store, self.b.paths).total)  # 剩余 0：再下载一字节都不够
        with mock.patch.object(Relay, "_download", side_effect=AssertionError("核实完整的叶不应重新下载")):
            self.tick(31_000)
            self.b.cycle()
        self.assertEqual((self.b.store.native(first.msg_id) or {}).get("state"), "prepared")
        row = self.b.store.attachments(first.msg_id)[0]
        self.assertEqual((row["state"], row["local_relpath"]), ("ready", "crashed/a.bin"))

    def test_local_write_error_while_landing_defers_instead_of_rejecting(self) -> None:
        # Windows 杀软占用、共享冲突这类本机写错误是暂时的：不拒收；路径本身不成立才确定失败（Opus r2-P3-1）
        for errno_value, expected in ((errno.EACCES, "receiving"), (errno.ENAMETOOLONG, "rejected")):
            with self.subTest(errno.errorcode[errno_value]):
                refs = self.freeze(self.a, ("a.bin", b"payload"))
                _, first = self.create(refs)
                self.a.cycle()
                self.tick()
                with mock.patch("agentstatus_bridge.federation.attachments.os.link",
                                side_effect=OSError(errno_value, "synthetic")):
                    self.b.cycle()
                self.assertEqual(self.b.store.inbox_item(first.msg_id)["apply_state"], expected)  # type: ignore[index]

    def test_persistent_landing_failure_reuses_downloaded_part(self) -> None:
        # 落地持续暂时失败：已完整下载的私有 part 直接复用，不每 30 秒重下整份；doctor 看得到失败时刻，恢复后清掉（Opus r3-P3-2）
        refs = self.freeze(self.a, ("a.bin", b"payload" * 64))
        _, first = self.create(refs)
        self.a.cycle()
        self.tick()
        fetched: list[int] = []
        call = HubConnection.call

        def counting(conn: HubConnection, method: str, **params: Any) -> dict[str, Any]:
            if method == "blob_get":
                fetched.append(int(params["offset"]))
            return call(conn, method, **params)

        with mock.patch.object(HubConnection, "call", counting), \
                mock.patch("agentstatus_bridge.federation.attachments.os.link",
                           side_effect=OSError(errno.EACCES, "synthetic")):
            self.b.cycle()
            failed_at = self.b.store.meta(attachments.WRITE_FAILED_META)
            self.assertEqual(failed_at, str(self.clock.now))
            downloads = len(fetched)
            self.assertGreaterEqual(downloads, 1)
            self.tick(31_000)
            self.b.cycle()
            self.assertEqual(len(fetched), downloads, "完整的 part 被重新下载")
        self.assertEqual(self.b.store.inbox_item(first.msg_id)["apply_state"], "receiving")  # type: ignore[index]
        with mock.patch.object(HubConnection, "call", counting):
            self.tick(31_000)
            self.b.cycle()
        self.assertEqual(len(fetched), downloads)
        self.assertEqual((self.b.store.native(first.msg_id) or {}).get("state"), "prepared")
        self.assertEqual(self.b.store.meta(attachments.WRITE_FAILED_META), "")

    def test_disk_full_while_landing_is_visible_in_doctor(self) -> None:
        # 预算内的实际写满（建交付目录 ENOSPC）：照常延后，也要在 doctor 上看得到；预算预检的延后另记，不混用（Opus r4-P3-1）
        refs = self.freeze(self.a, ("a.bin", b"payload"))
        _, first = self.create(refs)
        self.a.cycle()
        self.tick()
        mkdir = os.mkdir
        base = str(self.b.root)

        def full(path: Any, *args: Any, **kwargs: Any) -> None:
            if str(path).startswith(base) and "attachments" in str(path):
                raise OSError(errno.ENOSPC, "synthetic")
            mkdir(path, *args, **kwargs)

        with mock.patch("agentstatus_bridge.federation.attachments.os.mkdir", side_effect=full):
            self.b.cycle()
        self.assertEqual(self.b.store.inbox_item(first.msg_id)["apply_state"], "receiving")  # type: ignore[index]
        self.assertEqual((self.b.store.meta(attachments.WRITE_FAILED_META), self.b.store.meta(budget.DEFERRED_META)),
                         (str(self.clock.now), None))

    def test_other_success_does_not_hide_a_persistent_landing_failure(self) -> None:
        # 一条持续落地失败时，另一条完整落地不清标记；失败的那条也落地、没有别的收件再等重推时才清（Opus r4-P3-1）
        bad_refs = self.freeze(self.a, ("bad.bin", b"bad" * 100))
        _, bad = self.create(bad_refs)
        _, good = self.create(self.freeze(self.a, ("good.bin", b"good" * 100)))
        self.a.cycle()
        self.tick()
        link = os.link
        bad_prefix = str(bad_refs[0]["sha256"])[:16]

        def denied(src: Any, dst: Any, *args: Any, **kwargs: Any) -> None:
            if Path(dst).name.startswith(bad_prefix):
                raise OSError(errno.EACCES, "synthetic")
            link(src, dst, *args, **kwargs)

        with mock.patch("agentstatus_bridge.federation.attachments.os.link", side_effect=denied):
            self.b.cycle()
        states = {name: self.b.store.inbox_item(item.msg_id)["apply_state"]  # type: ignore[index]
                  for name, item in (("bad", bad), ("good", good))}
        self.assertEqual(states, {"bad": "receiving", "good": "ready"})
        self.assertEqual(self.b.store.meta(attachments.WRITE_FAILED_META), str(self.clock.now))
        self.tick(31_000)
        self.b.cycle()  # 写抖动过去，hub 重推后 bad 也落地
        self.assertNotEqual(self.b.store.inbox_item(bad.msg_id)["apply_state"], "receiving")  # type: ignore[index]
        self.assertEqual(self.b.store.meta(attachments.WRITE_FAILED_META), "")

    def test_damaged_part_is_downloaded_again(self) -> None:
        # 复用只限完整副本：留下的 part 内容不对（截断、被改）照常重下
        refs = self.freeze(self.a, ("a.bin", b"payload"))
        _, first = self.create(refs)
        self.a.cycle()
        self.tick()
        part = self.b.paths.parts / f"{first.msg_id}-0.part"
        part.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        part.write_bytes(b"paylXad")
        self.b.cycle()
        self.assertEqual((self.b.store.native(first.msg_id) or {}).get("state"), "prepared")
        row = self.b.store.attachments(first.msg_id)[0]
        base = self.b.paths.delivery_base(self.b.store.ledger_instance_id())
        self.assertEqual((base / str(row["local_relpath"])).read_bytes(), b"payload")

    def test_local_file_error_while_receiving_keeps_relay_running(self) -> None:
        refs = self.freeze(self.a, ("a.bin", b"payload"))
        _, first = self.create(refs)
        self.a.cycle()
        self.tick()
        with mock.patch.object(Relay, "_download", side_effect=PermissionError(errno.EACCES, "synthetic")):
            try:
                state = self.b.cycle()
            except OSError as error:
                self.fail(f"本机文件错误让 relay 崩出：{error!r}")
        self.assertEqual(state, "connected")
        self.assertEqual(self.b.store.inbox_item(first.msg_id)["apply_state"], "receiving")  # type: ignore[index]
        self.assertEqual(self.b.store.meta(attachments.WRITE_FAILED_META), str(self.clock.now))  # 写 part 失败同样给 doctor 看
        self.tick(31_000)
        self.b.cycle()
        self.assertEqual((self.b.store.native(first.msg_id) or {}).get("state"), "prepared")


class TransportFailureTests(RelayTestCase):
    def dead(self) -> StreamTransport:
        """读端立即 EOF、写端对面已关的连接：模拟 SSH 刚连上就退出。"""
        r1, w1 = os.pipe()
        os.close(w1)
        r2, w2 = os.pipe()
        os.close(r2)
        return StreamTransport(os.fdopen(r1, "rb"), os.fdopen(w2, "wb"))

    def test_broken_pipe_on_write_is_reconnect_not_crash(self) -> None:
        transport = self.dead()
        self.addCleanup(transport.close)
        conn = HubConnection(transport, on_counter=lambda _c: None, timeout=1)
        try:
            conn.call("heartbeat")
        except RelayStop as stop:
            self.assertEqual(stop.state, "hub_unavailable")
        except OSError as error:  # D11：产品异常记为断言失败
            self.fail(f"管道断开以 OSError 逃出，relay 进程会崩：{error!r}")
        else:
            self.fail("死连接上的请求居然成功")

    def test_retention_runs_while_hub_unreachable(self) -> None:
        relay = Relay(self.b.store, self.b.ident, self.b.config, self.b.paths, connect=self.dead,
                      clock=self.clock)
        waits: list[float] = []

        with mock.patch.object(retention, "sweep") as sweep:
            try:
                # 第一次断线后进入退避、等过一段即停：留存回收在退避开始前跑一轮（不靠数 should_stop 的调用次数）
                relay.run_forever(wait=waits.append, should_stop=lambda: bool(waits))
            except OSError as error:  # D11
                self.fail(f"连不上 hub 时 relay 崩出：{error!r}")
        self.assertEqual(sweep.call_count, 1)  # 断线退避期间也回收过期内容


class ErrorFrameTests(RelayTestCase):
    def test_unhandled_error_frame_reconnects_instead_of_crashing(self) -> None:
        with mock.patch.object(Relay, "_periodic", side_effect=CodecError("hub_busy")):
            try:
                state = self.b.cycle()
            except CodecError as error:  # D11
                self.fail(f"错误帧让 relay 进程崩出：{error!r}")
        self.assertEqual(state, "hub_unavailable")
        self.assertEqual(self.b.store.meta("relayState"), "reconnecting")


class BusyStoreTests(RelayTestCase):
    def test_close_hitting_a_busy_store_is_retried_not_lost(self) -> None:
        # 真实锁竞争（Opus 审计 P1-1）：A 的关闭撞上 B 库锁忙超过 5 秒 → 不 ACK、留在 receiving，重推后照常应用
        task, first = self.create()
        self.a.cycle()
        self.tick()
        self.b.cycle()  # 交接已在 B（prepared）
        current = self.a.store.get_task(self.a.device_id, task.task_id)
        assert current is not None
        authority.finish(self.a.store, self.a.ident, current, state=CLOSED, reason=None, decider="owner",
                         sender=None, sender_class="unknown", now=self.clock.now)
        self.tick()
        self.a.cycle()
        real = mirror.receive
        held: list[int] = []

        def busy_receive(*args: Any, **kwargs: Any) -> Any:
            if not held:
                held.append(1)
                ready = threading.Event()

                def hold_lock() -> None:
                    conn = sqlite3.connect(self.b.store.path, timeout=0, isolation_level=None)
                    conn.execute("BEGIN IMMEDIATE")
                    ready.set()
                    threading.Event().wait(5.6)
                    conn.execute("COMMIT")
                    conn.close()

                holder = threading.Thread(target=hold_lock, daemon=True)
                holder.start()
                self.threads.append(holder)
                ready.wait(5)
            return real(*args, **kwargs)

        self.tick()
        with mock.patch.object(mirror, "receive", side_effect=busy_receive):
            self.b.cycle()
        receiving = [str(row[0]) for row in self.b.store.connection.execute(
            "SELECT msg_id FROM fed_inbox WHERE apply_state='receiving'").fetchall()]
        rejected = self.b.store.connection.execute(
            "SELECT COUNT(*) FROM fed_inbox WHERE apply_state='rejected'").fetchone()[0]
        self.assertEqual((len(receiving), rejected), (1, 0))  # 撞上锁忙的那封留在 receiving，没有假拒收
        self.tick()
        self.a.cycle()
        busy = self.a.store.outbox_item(receiving[0])
        assert busy is not None
        self.assertEqual(busy["state"], "accepted")  # 没有 L2：A 不会看到「对端已落账」的假象
        self.tick(31_000)
        self.b.cycle()  # hub 重推：这次库空闲，照常应用
        mirrored = self.b.store.get_task(self.a.device_id, task.task_id)
        assert mirrored is not None
        self.assertTrue(mirrored.finished)
        self.assertEqual((self.b.store.native(first.msg_id) or {}).get("state"), "suppressed")


class WindowsDeliveryTests(RelayTestCase):
    windows_b = True

    def test_windows_style_delivery_root(self) -> None:
        refs = self.freeze(self.a, ("CON .txt", b"payload"))
        _, first = self.create(refs)
        self.a.cycle()
        self.tick()
        self.b.cycle()
        (manifest,) = self.b.store.attachments(first.msg_id)
        base = self.b.paths.delivery_base(self.b.store.ledger_instance_id())
        assert self.b.paths.local_appdata is not None
        self.assertEqual(base.parent.parent, self.b.paths.local_appdata.resolve())
        landed = base / manifest["local_relpath"]
        self.assertTrue(landed.name.endswith("-file-CON .txt"))
        self.assertEqual(landed.read_bytes(), b"payload")


    def test_crash_during_copy_recovers_only_own_leaf(self) -> None:
        refs = self.freeze(self.a, ("r.md", b"payload-bytes"))
        _, first = self.create(refs)
        self.a.cycle()
        real = attachments._copy_new_leaf  # pyright: ignore[reportPrivateUsage]

        def crashing(part: Path, dest: Path, sha: str, size: int, on_create: Any = None) -> None:
            fd = os.open(dest, os.O_WRONLY | os.O_CREAT | os.O_EXCL)
            info = os.fstat(fd)
            on_create(dest, {"dev": info.st_dev, "ino": info.st_ino})
            os.write(fd, b"pay")
            os.close(fd)
            raise RuntimeError("simulated crash")  # 进程被杀：except 清理来不及运行

        attachments._copy_new_leaf = crashing  # pyright: ignore[reportPrivateUsage]
        try:
            with self.assertRaises(RuntimeError):
                self.b.cycle()
        finally:
            attachments._copy_new_leaf = real  # pyright: ignore[reportPrivateUsage]
        self.assertIsNone(self.b.store.native(first.msg_id))
        self.tick(31_000)
        self.b.cycle()
        (manifest,) = self.b.store.attachments(first.msg_id)
        base = self.b.paths.delivery_base(self.b.store.ledger_instance_id())
        directory = (base / manifest["local_relpath"]).parent
        self.assertEqual([p.read_bytes() for p in directory.iterdir()], [b"payload-bytes"])  # 半成品已回收
        self.assertEqual(self.b.store.native(first.msg_id)["state"], "prepared")  # type: ignore[index]


class ConfigTests(unittest.TestCase):
    def test_roundtrip_and_ssh_material(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config = FederationConfig(enabled=True, hub_id="1" * 32, device_id="2" * 32, device_name="vm",
                                      host="hub.example", user="ab-relay", expected_state_root=str(root),
                                      identity_file="/k/relay", known_hosts_file="/k/known_hosts",
                                      extra={"future": 1})
            self.assertIsNone(load(root))
            save(root, config)
            self.assertEqual(oct((root / "federation.json").stat().st_mode & 0o777), "0o600")
            self.assertEqual(load(root), config)
            check_state_root(config, root)
            with self.assertRaises(ConfigError) as caught:
                check_state_root(config, root / "other")
            self.assertEqual(caught.exception.code, "state_root_mismatch")
            (root / "federation.json").write_text('{"schema":1,"enabled":true,"reconnectMin":5}')
            with self.assertRaises(ConfigError):
                load(root)
        text = ssh_config_text(config)
        for line in ("StrictHostKeyChecking yes", "BatchMode yes", "ControlMaster no", "ControlPath none",
                     "ForwardAgent no", "PermitLocalCommand no", "ClearAllForwardings yes", "UpdateHostKeys no",
                     "IdentitiesOnly yes", "IdentityAgent none", 'UserKnownHostsFile "/k/known_hosts"', "ServerAliveInterval 30",
                     "ServerAliveCountMax 3", "ConnectTimeout 15", "ConnectionAttempts 1"):
            self.assertIn(line, text)
        self.assertNotIn("Include", text)
        argv = ssh_argv(config, Path("/s/federation-ssh.conf"))
        self.assertEqual(argv[:4], ["ssh", "-F", "/s/federation-ssh.conf", "-T"])
        self.assertEqual(argv[-1], "agent-bridge-hub")

    def test_reconnect_delay_bounds(self) -> None:
        self.assertEqual(reconnect_delay(0, jitter=0), 30)
        self.assertEqual(reconnect_delay(1, jitter=0), 60)
        self.assertEqual(reconnect_delay(9, jitter=0), 300)
        self.assertEqual(reconnect_delay(4, jitter=15), 315)
        for attempt in range(8):
            self.assertGreaterEqual(reconnect_delay(attempt), 30)


if __name__ == "__main__":
    unittest.main()
