"""§103.7 本机发起的跨设备任务并入摘要「需处理」（DESIGN §103.7 与第 0 步结论）：Python 侧。

并入范围（本机权威、未结束、关注类别不为 none）、远端端点的专门绑定与短标签、面板令牌等于发起方提醒令牌、
钟差钳制、坏任务逐条跳过与重复 ID 本机优先、溢出截断后 attentionIndex 仍完整。真实 collabModel.js（现役冻结副本
与新版）判有效见 test_contract_federation_panel（镜像仓不带 extension/）。
"""

from __future__ import annotations

from dataclasses import replace
import json
import unittest
from typing import Any
from unittest.mock import patch

import bridge_support  # noqa: F401  导入即隔离宿主会话环境

from agentstatus_bridge import summary, worker
from agentstatus_bridge.federation import authority, mirror
from agentstatus_bridge.federation.refs import TargetRef
from agentstatus_bridge.federation.views import display_ref, model_attempts, model_task, summary_items
from agentstatus_bridge.model import Delivery, Provider
from agentstatus_bridge.reminders import reminder_token
from agentstatus_bridge.transports import DeliveryOutcome
from bridge_support import RecordingTransport, endpoint

from test_bridge_federation_delivery import bind
from test_bridge_federation_rules import DEV_A, DEV_B, deliver, pump
from test_bridge_federation_summary import FedSummaryCase

CLAUDE_B = "0000000b-1111-4222-8333-444444444444"
CLAUDE_REVIEW = "0000000b-1111-4222-8333-555555555555"
REMOTE_BINDING = {"source": "selected", "pane": None, "observerKeys": []}


class PanelCase(FedSummaryCase):
    """A（vm）发起、B（win）上的 Claude 会话执行；A 本机另有一个同原生 ID 的 Claude 会话行（同名反例）。"""

    def setUp(self) -> None:
        super().setUp()
        self.claude_b = bind(self.b, Provider.CLAUDE, CLAUDE_B, pane="%7")
        self.same_id_on_a = bind(self.a, Provider.CLAUDE, CLAUDE_B, pid=5151, pane="%9")

    def create(self, *, target: TargetRef | None = None, reviewer: TargetRef | None = None, flow: str = "handoff",
               title: str = "跨设备") -> tuple[str, str]:
        task, first = authority.create_task(
            self.a.store, self.a.ident, title=title, flow=flow, body="请处理", refs=[], origin=self.origin,
            origin_actor=authority.actor_for(self.origin, wire_token="claude@vm"), origin_class="bypass",
            target=target or TargetRef(remote=self.claude_b.remote), reviewer=reviewer, now=self.now)
        return task.task_id, first.msg_id

    def fail_on_b(self, msg_id: str, *, at: int | None = None, state: str = "failed") -> None:
        pump(self.a, self.b, now=self.now)
        deliver(self.b, msg_id, state, now=self.now if at is None else at)
        pump(self.b, self.a, now=self.now)

    def publish_a(self, *, now: float | None = None) -> tuple[summary.PublishResult, dict[str, Any]]:
        result = summary.publish(self.local_a, self.root / "vm", force=True, now=self.now / 1000 + 60 if now is None else now)
        document = summary.load(self.root / "vm")
        assert document is not None
        return result, document

    def entry(self, document: dict[str, Any], task_id: str) -> dict[str, Any]:
        [found] = [item for item in document["tasks"] if item["id"] == task_id]
        return found


class InclusionTests(PanelCase):
    def test_remote_failure_enters_as_a_notifying_decision_with_a_remote_binding(self) -> None:
        task_id, msg_id = self.create()
        self.fail_on_b(msg_id)
        result, document = self.publish_a()
        self.assertTrue(summary.is_valid(document))
        entry = self.entry(document, task_id)
        self.assertEqual((entry["phase"], entry["reason"], entry["attention"]["kind"], entry["attention"]["notify"]),
                         ("needs_attention", "delivery_failed", "decision", True))
        self.assertEqual(entry["target"], {"provider": "claude", "label": f"win 上的 claude@id:{CLAUDE_B}", "pane": None,
                                           "role": "handoff", "binding": REMOTE_BINDING, "device": "win"})
        # 发起方在权威端是本机会话：照旧走 endpoint_binding，能对上本机会话行（导航取 (B) 的依据）
        assert self.origin.local is not None
        self.assertEqual(entry["origin"]["binding"], summary.endpoint_binding(self.origin.local))
        self.assertNotIn("device", entry["origin"])
        self.assertEqual(document["counts"], {"active": 1, "attention": 1, "result": 0, "decision": 1, "failure": 0})
        [index] = document["attentionIndex"]
        self.assertEqual((index["id"], index["kind"], index["token"], index["notify"]),
                         (task_id, "decision", entry["attention"]["token"], True))
        self.assertEqual((result.skipped, result.duplicates), (0, 0))

    def test_next_command_routes_to_this_device(self) -> None:
        # §104.13 第 2 条：联邦权威项的 next.command 用完整 ID 加 --origin-device <本机>（authority.command_ref），
        # 两库同 ID 时照抄也只作用到联邦这一项；v1 合同里 next.command 是开放字符串，形状变化不影响旧读方
        import shlex
        from agentstatus_bridge import cli
        task_id, msg_id = self.create()
        self.fail_on_b(msg_id)
        # 联邦库 meta 里没有登记名时退回完整 deviceId（authority_for 同样接受）；启用时会写入登记名，命令里用 slug
        for name, device in ((None, DEV_A), ("vm", "vm")):
            with self.subTest(name=name):
                if name is not None:
                    self.a.store.set_meta("deviceName", name)
                command = self.entry(self.publish_a()[1], task_id)["next"]["command"]
                self.assertIn(f" {task_id} --origin-device {device}", command)
                args = cli.build_parser().parse_args(shlex.split(command)[1:])
                self.assertEqual((args.task, args.origin_device), (task_id, device))

    def test_same_native_id_on_this_device_is_never_bound(self) -> None:
        # 反例：A 本机有同 provider 同原生 ID 的 Claude 会话；endpoint_binding 会给出它的 session 键，远端目标绝不能用
        task_id, msg_id = self.create()
        self.fail_on_b(msg_id)
        entry = self.entry(self.publish_a()[1], task_id)
        leaked = summary.endpoint_binding(display_ref(TargetRef(remote=self.claude_b.remote)))
        assert self.same_id_on_a.local is not None
        local_keys = {item["key"] for item in summary.endpoint_binding(self.same_id_on_a.local)["observerKeys"]}
        self.assertTrue({item["key"] for item in leaked["observerKeys"]} & local_keys)  # 改回 endpoint_binding 就会绑上
        self.assertEqual(entry["target"]["binding"]["observerKeys"], [])
        self.assertIsNone(entry["target"]["pane"])
        self.assertIsNone(entry["target"]["binding"]["pane"])

    def test_panel_token_equals_the_origin_reminder_token(self) -> None:
        task_id, msg_id = self.create()
        self.fail_on_b(msg_id)
        entry = self.entry(self.publish_a()[1], task_id)
        fed_task = self.a.store.get_task(DEV_A, task_id)
        assert fed_task is not None
        found = reminder_token(model_task(fed_task), model_attempts(self.a.store.attempts(DEV_A, task_id)))
        assert found is not None
        [(_, pending, _)] = list(mirror.reminder_candidates(self.a.store, self.now))
        self.assertEqual(entry["attention"]["token"], found[0])
        self.assertEqual(entry["attention"]["token"], pending.token)

    def test_held_and_unknown_also_enter_like_local_tasks(self) -> None:
        for state in ("held", "unknown", "refused", "denied", "expired"):
            with self.subTest(state=state):
                task_id, msg_id = self.create()
                self.fail_on_b(msg_id, state=state)
                entry = self.entry(self.publish_a()[1], task_id)
                self.assertEqual((entry["reason"], entry["attention"]["kind"], entry["attention"]["notify"]),
                                 (f"delivery_{state}", "decision", True))

    def test_running_remote_task_without_attention_is_not_included(self) -> None:
        _, msg_id = self.create()
        self.fail_on_b(msg_id, state="queued")
        _, document = self.publish_a()
        self.assertEqual((document["tasks"], document["attentionIndex"], document["counts"]["active"]), ([], [], 0))

    def test_mirror_tasks_are_not_included_on_the_executing_device(self) -> None:
        _, msg_id = self.create()
        self.fail_on_b(msg_id)
        summary.publish(self.local_b, self.root / "win", force=True, now=self.now / 1000 + 60)
        document = summary.load(self.root / "win")
        assert document is not None
        self.assertEqual((document["tasks"], document["counts"]["active"]), ([], 0))

    def test_finished_tasks_are_not_included(self) -> None:
        task_id, msg_id = self.create()
        self.fail_on_b(msg_id)
        current = self.a.store.get_task(DEV_A, task_id)
        assert current is not None
        authority.finish(self.a.store, self.a.ident, current, state="closed", reason=None, decider="用户", sender=None,
                         sender_class="unknown", now=self.now + 1)
        self.assertEqual(self.publish_a()[1]["tasks"], [])

    def test_without_a_federation_instance_the_document_is_unchanged(self) -> None:
        # 无联邦实例：read_ledger 不导入联邦实现，条目与诊断字段都是默认值
        snapshot = summary.read_ledger(self.local_b)
        self.assertEqual((snapshot.remote_entries, snapshot.skipped, snapshot.duplicates), ([], 0, 0))


class FederatedMarkerTests(PanelCase):
    """顶层标记 federatedTasks（§103.7 第 0 步结论之后，协调方定选项二）：旧 worker 跨部署按同一水位写出的
    无标记摘要被新代码重建一次；新文档在旧发布器眼里仍是 fresh，同一修订内不来回抢写。"""

    def old_build(self, snapshot: summary.LedgerSnapshot, *, now: float, device: str) -> dict[str, Any]:
        # 旧发布器的输出：不并入联邦任务、不写标记（其余逐字相同）
        return self.real_build(replace(snapshot, remote_entries=[], federated=False), now=now, device=device)

    def setUp(self) -> None:
        super().setUp()
        self.real_build = summary.build_document
        self.directory = self.root / "vm"
        self.summary_path = self.directory / summary.SUMMARY_NAME

    def test_marker_only_with_a_federation_instance(self) -> None:
        _, document = self.publish_a()
        self.assertEqual(document[summary.FEDERATED_TASKS_KEY], summary.FEDERATED_TASKS)
        # 无联邦实例：read_ledger 不读联邦库，文档没有这个键（与旧版逐字相同）
        plain = summary.build_document(summary.read_ledger(self.local_a), now=1.0, device="vm")
        self.assertNotIn(summary.FEDERATED_TASKS_KEY, plain)
        self.assertTrue(summary.is_valid(document))

    def test_old_publisher_document_is_rebuilt_once(self) -> None:
        task_id, msg_id = self.create()
        self.fail_on_b(msg_id)
        with patch.object(summary, "build_document", self.old_build):
            self.assertEqual(summary.publish(self.local_a, self.directory, force=True).status, "written")
        stale = summary.load(self.directory)
        assert stale is not None
        self.assertNotIn(summary.FEDERATED_TASKS_KEY, stale)
        self.assertEqual(stale["tasks"], [])  # 旧 worker 写的：同一水位、没有远端条目
        # 新代码的 if-stale（扩展定时补查、任一 ab 命令前后）：水位相同也重建一次
        self.assertEqual(summary.publish(self.local_a, self.directory).status, "written")
        rebuilt = summary.load(self.directory)
        assert rebuilt is not None
        self.assertEqual((rebuilt["ledgerId"], rebuilt["ledgerRevision"]), (stale["ledgerId"], stale["ledgerRevision"]))
        self.assertEqual([item["id"] for item in rebuilt["tasks"]], [task_id])
        self.assertEqual(summary.publish(self.local_a, self.directory).status, "fresh")  # 只重建一次

    def test_new_document_is_fresh_for_the_old_publisher(self) -> None:
        _, msg_id = self.create()
        self.fail_on_b(msg_id)
        self.assertEqual(summary.publish(self.local_a, self.directory).status, "written")
        before = self.summary_path.read_bytes()
        # 旧发布器的 fresh 判定只有水位与 binding 两条：把新加的那条去掉、输出换成旧版，就是旧 worker 的行为
        with patch.object(summary, "_lacks_federated_tasks", return_value=False), \
                patch.object(summary, "build_document", self.old_build):
            self.assertEqual(summary.publish(self.local_a, self.directory).status, "fresh")
        self.assertEqual(self.summary_path.read_bytes(), before)  # 没有抢写

    def test_newer_marker_versions_are_not_rewritten(self) -> None:
        self.assertEqual(summary.publish(self.local_a, self.directory).status, "written")
        document = summary.load(self.directory)
        assert document is not None
        for value, status in ((summary.FEDERATED_TASKS + 1, "fresh"), (0, "written"), (True, "written"),
                              ("1", "written")):
            with self.subTest(value=value):
                self.summary_path.write_text(json.dumps({**document, summary.FEDERATED_TASKS_KEY: value}),
                                             encoding="utf-8")
                self.assertEqual(summary.publish(self.local_a, self.directory).status, status)


class EndpointTests(PanelCase):
    def test_remote_reviewer_takes_the_remote_path_and_local_reviewer_does_not(self) -> None:
        reviewer_b = bind(self.b, Provider.CLAUDE, CLAUDE_REVIEW, pane="%8")
        task_id, msg_id = self.create(flow="review", reviewer=TargetRef(remote=reviewer_b.remote))
        self.fail_on_b(msg_id)
        entry = self.entry(self.publish_a()[1], task_id)
        self.assertEqual(entry["reviewer"], {"provider": "claude", "label": f"win 上的 claude@id:{CLAUDE_REVIEW}",
                                             "pane": None, "binding": REMOTE_BINDING, "device": "win"})
        local_reviewer = bind(self.a, Provider.CODEX, "019a0000-1111-7222-8333-44445555dddd", pane="%4")
        task_id, msg_id = self.create(flow="review", reviewer=local_reviewer)
        self.fail_on_b(msg_id)
        entry = self.entry(self.publish_a()[1], task_id)
        assert local_reviewer.local is not None
        self.assertEqual(entry["reviewer"]["binding"], summary.endpoint_binding(local_reviewer.local))
        self.assertNotIn("device", entry["reviewer"])

    def test_attempt_to_this_device_keeps_the_local_binding(self) -> None:
        # 跨设备任务里投给本机的尝试（例如本机复核方）：按本机处理，不带 device，绑定照旧
        local_worker = bind(self.a, Provider.CODEX, "019a0000-1111-7222-8333-44445555eeee", pane="%5")
        task_id, _ = self.create(target=local_worker)
        assert local_worker.local is not None
        self.dispatch(self.a, RecordingTransport(Provider.CODEX, DeliveryOutcome(Delivery.FAILED, "codex_preflight_failed")),
                      endpoint(local_worker.local))
        entry = self.entry(self.publish_a()[1], task_id)
        self.assertEqual(entry["reason"], "delivery_failed")
        self.assertNotIn("device", entry["target"])
        self.assertEqual(entry["target"]["binding"], summary.endpoint_binding(local_worker.local))
        self.assertEqual(entry["target"]["pane"], "%5")

    def test_verified_name_label_and_long_device_label_limit(self) -> None:
        named = TargetRef(remote=replace(self.claude_b.remote, display_label="impl"))
        task_id, msg_id = self.create(target=named)
        self.fail_on_b(msg_id)
        self.assertEqual(self.entry(self.publish_a()[1], task_id)["target"]["label"], "win 上的 claude@impl")
        # 32 字 slug：完整 ID 形式约 81 字，旧 64 字上限会截成半截 ID；远端上限 120
        slug = "w" * 32
        self.a.store.put_device_state(device_id=DEV_B, name=slug, revision=1, snapshot={}, last_seen=None,
                                      state="unknown")
        task_id, msg_id = self.create()
        self.fail_on_b(msg_id)
        target = self.entry(self.publish_a()[1], task_id)["target"]
        self.assertEqual((target["label"], target["device"]), (f"{slug} 上的 claude@id:{CLAUDE_B}", slug))

    def test_hostile_remote_strings_are_escaped(self) -> None:
        forged = "w\n设备 forged\x1b[2K\u202e\u200b"
        escaped = "w\\u000a设备 forged\\u001b[2K\\u202e\\u200b"
        self.a.store.put_device_state(device_id=DEV_B, name=forged, revision=1, snapshot={}, last_seen=None,
                                      state="unknown")
        hostile = TargetRef(remote=replace(self.claude_b.remote, native_id=CLAUDE_B + "\u202e\u200b\x7f",
                                           display_label="im\u200bpl"))
        task_id, _ = self.create(target=hostile)
        with self.a.store.transaction() as conn:  # 投递证据由 B 出具：直接写 A 的投递列代替往返（目标 ID 已不是 B 真有的会话）
            conn.execute("UPDATE fed_attempts SET delivery_json=? WHERE task_id=?",
                         ('{"state":"failed","at":%d}' % self.now, task_id))
        result, document = self.publish_a()
        target = self.entry(document, task_id)["target"]
        self.assertEqual(target["device"], escaped)
        self.assertEqual(target["label"], f"{escaped} 上的 claude@id:{CLAUDE_B}\\u202e\\u200b\\u007f")
        for value in (target["label"], target["device"]):
            self.assertFalse(any(char in value for char in "\n\x1b\u202e\u200b\x7f"), value)
        self.assertTrue(summary.is_valid(document))
        self.assertEqual(result.skipped, 0)


class ClockAndIsolationTests(PanelCase):
    def test_attention_at_is_clamped_to_generated_at_and_token_is_unchanged(self) -> None:
        task_id, msg_id = self.create()
        future = self.now + 10 * 3600 * 1000  # B 的时钟快了 10 小时
        self.fail_on_b(msg_id, at=future)
        generated = self.now / 1000 + 60
        _, document = self.publish_a(now=generated)
        entry = self.entry(document, task_id)
        self.assertEqual(entry["attention"]["at"], generated)
        self.assertEqual(document["attentionIndex"][0]["at"], generated)
        self.assertTrue(entry["attention"]["token"].endswith(f":{future / 1000:.6f}"))  # token 仍按原关注时刻
        fed_task = self.a.store.get_task(DEV_A, task_id)
        assert fed_task is not None
        found = reminder_token(model_task(fed_task), model_attempts(self.a.store.attempts(DEV_A, task_id)))
        assert found is not None
        self.assertEqual(entry["attention"]["token"], found[0])
        # 关注时刻不晚于生成时刻的条目不动
        _, later = self.publish_a(now=future / 1000 + 1)
        self.assertEqual(self.entry(later, task_id)["attention"]["at"], future / 1000)

    def test_bad_federated_task_is_skipped_and_counted(self) -> None:
        bad_id, bad_msg = self.create(title="坏")
        self.fail_on_b(bad_msg)
        good_id, good_msg = self.create(title="好")
        self.fail_on_b(good_msg)
        with self.a.store.transaction() as conn:
            conn.execute("UPDATE fed_tasks SET state_json=json_set(state_json,'$.flow','bogus') WHERE task_id=?", (bad_id,))
        result, document = self.publish_a()
        self.assertEqual([item["id"] for item in document["tasks"]], [good_id])
        self.assertEqual((result.skipped, result.duplicates), (1, 0))
        events: list[tuple[str, dict[str, object]]] = []
        worker._publish_summary(self.local_a, self.root / "vm", lambda event, fields: events.append((event, dict(fields))),  # pyright: ignore[reportPrivateUsage]
                                force=True)
        self.assertIn(("summary_federation_items", {"skipped": 1, "duplicates": 0}), events)

    def test_corrupt_attempt_record_is_skipped_and_counted(self) -> None:
        # 尝试记录损坏：store.attempts 回读时抛 StoreError("corrupt_record")（DESIGN 第 0 步结论点名的一类）
        bad_id, bad_msg = self.create(title="坏")
        self.fail_on_b(bad_msg)
        good_id, good_msg = self.create(title="好")
        self.fail_on_b(good_msg)
        with self.a.store.transaction() as conn:
            conn.execute("UPDATE fed_attempts SET target_json=json_set(target_json,'$.remote.nativeId','x y')"
                         " WHERE task_id=?", (bad_id,))
        result, document = self.publish_a()
        self.assertEqual([item["id"] for item in document["tasks"]], [good_id])
        self.assertEqual((result.skipped, result.duplicates), (1, 0))

    def test_entry_level_errors_are_also_skipped(self) -> None:
        good_id, good_msg = self.create()
        self.fail_on_b(good_msg)
        items, skipped = summary_items(self.a.store)
        self.assertEqual(skipped, 0)
        broken = replace(items[0], task=replace(items[0].task, id="x"))
        with patch.object(summary, "next_step", side_effect=[ValueError("bad"), None]):
            entries, failed, duplicates = summary.federated_entries([broken, items[0]], set())
        self.assertEqual(([item["id"] for item in entries], failed, duplicates), ([good_id], 1, 0))

    def test_duplicate_id_keeps_the_local_entry(self) -> None:
        task_id, msg_id = self.create()
        self.fail_on_b(msg_id)
        items, _ = summary_items(self.a.store)
        entries, failed, duplicates = summary.federated_entries(items, {task_id})
        self.assertEqual((entries, failed, duplicates), ([], 0, 1))

    def test_overflow_trims_tasks_but_keeps_every_remote_attention(self) -> None:
        ids = []
        for index in range(3):
            task_id, msg_id = self.create(title=f"任务{index}")
            self.fail_on_b(msg_id)
            ids.append(task_id)
        snapshot = summary.read_ledger(self.local_a, self.a.store)
        document = summary.build_document(snapshot, now=self.now / 1000 + 60, device="vm")
        whole = len(summary.encode(document))
        with patch.object(summary, "MAX_BYTES", whole - 1):
            trimmed = summary.encode(document)
        parsed = json.loads(trimmed)
        self.assertTrue(parsed["overflow"])
        self.assertEqual(sorted(item["id"] for item in parsed["attentionIndex"]), sorted(ids))
        self.assertEqual(parsed["counts"]["active"], 3)
        self.assertLess(len(parsed["tasks"]), 3)
        with patch.object(summary, "MAX_BYTES", whole - 1):
            self.assertTrue(summary.is_valid(parsed))


if __name__ == "__main__":
    unittest.main()
