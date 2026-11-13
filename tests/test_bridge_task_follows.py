"""DESIGN §93.3：`ab send --follows <旧任务>` 的解析、存储与显示，以及上限文案里的关联提示。

经真实 `cli.main` 解析 argv；本机与跨设备夹具复用 `test_bridge_task_filters`/`test_bridge_federation_cli`（只取不含用例的基类）。
跨设备的关联只写发起设备本机的 state：用例核对它不出现在 checkpoint、出站信封与对方镜像里。
"""

from __future__ import annotations

import json
import secrets
import sqlite3
from unittest.mock import patch
import unittest

from agentstatus_bridge import cli, labels, store as store_module
from agentstatus_bridge.federation import authority
from agentstatus_bridge.federation.authority import build_checkpoint
from agentstatus_bridge.ids import short
from agentstatus_bridge.model import Delivery, Flow, Role
from agentstatus_bridge.federation.fedstore import FED_DB_NAME
from agentstatus_bridge.store import DB_NAME, Store
from test_bridge_federation_cli import DEV_A, ORIGIN, THREAD_B, FedCliCase
from test_bridge_federation_cli import as_agent as fed_agent
from test_bridge_task_filters import IMPL, LEAD, OTHER, USER, LocalCliCase, as_agent


def prefixed(prefix: str) -> str:
    """固定前缀的 32 位十六进制 ID：用来制造前缀歧义。"""
    return prefix + secrets.token_hex(16)[len(prefix):]


class LocalFollowsTests(LocalCliCase):
    def old_task(self, title: str = "旧任务标题") -> str:
        task_id = self.send("--title", title)
        self.caller = USER
        self.assertEqual(self.run_cli("close", task_id)[0], 0)  # 旧任务已结束也能被关联
        return task_id

    def test_follows_is_stored_and_shown_on_both_sides(self) -> None:
        old = self.old_task()
        new = self.send("--follows", old[:6], caller=as_agent(OTHER))  # 不要求是旧任务的发起方
        with self.store() as store:
            task = store.get_task(new)
            assert task is not None
            self.assertEqual(task.options["follows"], old)
        code, out, err = self.run_cli("status", new)
        self.assertEqual(code, 0, err)
        self.assertIn(f"承接任务 {short(old)}（旧任务标题）", out)
        code, out, err = self.run_cli("status", new, "--json")
        document = json.loads(out)
        self.assertEqual(document["follows"], old)
        self.assertNotIn("followedBy", document)
        code, out, err = self.run_cli("status", old)
        self.assertIn(f"后续任务 {short(new)}", out)
        document = json.loads(self.run_cli("status", old, "--json")[1])
        self.assertEqual(document["followedBy"], [new])
        self.assertNotIn("follows", document)
        listing = {item["id"]: item for item in json.loads(self.run_cli("tasks", "--all", "--json")[1])["tasks"]}
        self.assertEqual(listing[new]["follows"], old)
        self.assertNotIn("follows", listing[old])
        text = self.run_cli("tasks", "--all")[1]
        self.assertNotIn("承接", text)  # tasks 文字行不变

    def test_followers_are_listed_in_creation_order(self) -> None:
        old = self.old_task()
        first = self.send("--follows", old)
        second = self.send("--follows", old)
        document = json.loads(self.run_cli("status", old, "--json")[1])
        self.assertEqual(document["followedBy"], [first, second])
        self.assertIn(f"后续任务 {short(first)}、{short(second)}", self.run_cli("status", old)[1])

    def test_unknown_reference_is_rejected_before_writing(self) -> None:
        self.send()
        with self.store() as store:
            before = [item.id for item in store.list_tasks(include_finished=True)]
        for extra in ((), ("--json",)):
            code, out, err = self.run_cli("send", "--to", "codex@impl", "-m", "x", "--no-wait",
                                          "--follows", "ffffffff", *extra)
            self.assertEqual((code, out), (cli.EXIT_TARGET, ""), err)
            self.assertIn("[follows_not_found]", err)
        with self.store() as store:
            self.assertEqual([item.id for item in store.list_tasks(include_finished=True)], before)

    def test_missing_ledger_is_not_created_by_follows(self) -> None:
        code, _, err = self.run_cli("send", "--to", "codex@impl", "-m", "x", "--follows", "abcd1234")
        self.assertEqual(code, cli.EXIT_TARGET)
        self.assertIn("[follows_not_found]", err)
        self.assertFalse((self.state / DB_NAME).exists())

    def test_ambiguous_prefix_is_rejected(self) -> None:
        with self.store() as store, patch.object(store_module, "new_id", side_effect=lambda: prefixed("abcd")):
            for _ in range(2):
                store.create_task(title="同前缀", flow=Flow.HANDOFF, origin=LEAD.ref, origin_class="bypass",
                                  reviewer=None, target=IMPL.ref, body="x", refs=[], now=1.0)
        code, out, err = self.run_cli("send", "--to", "codex@impl", "-m", "x", "--follows", "abcd")
        self.assertEqual((code, out), (cli.EXIT_TARGET, ""))
        self.assertIn("[follows_ambiguous]", err)

    def test_pruned_old_task_shows_as_gone(self) -> None:
        old = self.old_task()
        new = self.send("--follows", old)
        with self.store() as store:
            self.assertGreaterEqual(store.prune(now=10 ** 12), 1)  # 超过保留期被删除
            self.assertIsNone(store.get_task(old))
        code, out, err = self.run_cli("status", new)
        self.assertEqual(code, 0, err)
        self.assertIn(f"承接任务 {short(old)}（已不在账本）", out)
        self.assertEqual(json.loads(self.run_cli("status", new, "--json")[1])["follows"], old)


class FederatedFollowsTests(FedCliCase):
    def local_task(self, *extra: str) -> str:
        with patch.object(cli, "worker_running", return_value=True):
            code, out, err = self.run_on("vm", "send", "--to", "codex@review", "-m", "本机旧任务", "--no-wait", "--json",
                                         *extra, caller=fed_agent(ORIGIN))
        self.assertEqual(code, 0, err)
        return str(json.loads(out)["id"])

    def test_federated_follows_stays_in_local_state_only(self) -> None:
        old = self.local_task()
        new = self.send("--follows", old)
        with self.store("vm") as store:
            [task] = store.find_tasks(new)
            self.assertEqual(task.state["follows"], old)
            checkpoint = build_checkpoint(task, store.attempts(DEV_A, new)).to_dict()
            envelopes = [item["envelope_json"] for item in store.outbox()]
        self.assertNotIn(old, json.dumps(checkpoint))
        self.assertTrue(envelopes)
        for raw in envelopes:
            self.assertNotIn(old, raw)
            self.assertNotIn("follows", raw)
        self.pump("vm", "win")
        with self.store("win") as store:
            [mirrored] = store.find_tasks(new)
            self.assertNotIn("follows", mirrored.state)
            self.assertNotIn(old, json.dumps(mirrored.state))
        # 发起设备上的可见变化（bump）不丢关联
        self.assertEqual(self.run_on("vm", "pause", new, caller=fed_agent(ORIGIN))[0], 0)
        self.pump("vm", "win")
        with self.store("vm") as store:
            [task] = store.find_tasks(new)
            self.assertEqual(task.state["follows"], old)
        with self.store("win") as store:
            [mirrored] = store.find_tasks(new)
            self.assertNotIn("follows", mirrored.state)
        code, out, err = self.run_on("vm", "status", new)
        self.assertEqual(code, 0, err)
        self.assertIn(f"  承接任务 {short(old)}（本机旧任务）", out.splitlines())  # 与联邦 status 其余行同缩进
        self.assertEqual(json.loads(self.run_on("vm", "status", new, "--json")[1])["follows"], old)
        code, out, err = self.run_on("vm", "status", old)
        self.assertIn(f"后续任务 {short(new)}", out)
        self.assertEqual(json.loads(self.run_on("vm", "status", old, "--json")[1])["followedBy"], [new])
        listing = json.loads(self.run_on("vm", "tasks", "--json")[1])
        self.assertEqual(next(item for item in listing["federation"] if item["id"] == new)["follows"], old)
        code, out, err = self.run_on("win", "status", new, "--json")
        self.assertEqual(code, 0, err)
        self.assertNotIn("follows", json.loads(out))  # 目标设备不知道关联

    def test_local_send_can_follow_a_federated_task(self) -> None:
        old = self.send()
        new = self.local_task("--follows", old[:10])
        code, out, err = self.run_on("vm", "status", new)
        self.assertEqual(code, 0, err)
        self.assertIn(f"承接任务 {short(old)}（请处理 X）", out)
        code, out, err = self.run_on("vm", "status", old, "--json")
        self.assertEqual(json.loads(out)["followedBy"], [new], err)
        self.assertIn(f"  后续任务 {short(new)}", self.run_on("vm", "status", old)[1].splitlines())

    def test_prefix_hitting_both_stores_is_ambiguous(self) -> None:
        with patch.object(store_module, "new_id", side_effect=lambda: prefixed("abcd")):
            local = self.local_task()
        with patch.object(authority, "new_id", side_effect=lambda: prefixed("abcd")):
            remote = self.send()
        self.assertTrue(local.startswith("abcd") and remote.startswith("abcd"))
        code, out, err = self.run_on("vm", "send", "--device", "win", "--to", f"codex@id:{THREAD_B}", "-m", "x",
                                     "--follows", "abcd", caller=fed_agent(ORIGIN))
        self.assertEqual((code, out), (cli.EXIT_TARGET, ""))
        self.assertIn("[follows_ambiguous]", err)
        with self.store("vm") as store:
            self.assertEqual(len(store.tasks()), 1)  # 没有落账
        new = self.send("--follows", remote)  # 完整 ID 不歧义
        with self.store("vm") as store:
            [task] = store.find_tasks(new)
            self.assertEqual(task.state["follows"], remote)
        code, _, err = self.run_on("vm", "send", "--device", "win", "--to", f"codex@id:{THREAD_B}", "-m", "x",
                                   "--follows", "eeeeeeee", caller=fed_agent(ORIGIN))
        self.assertEqual(code, cli.EXIT_TARGET)
        self.assertIn("[follows_not_found]", err)


class BrokenFederationFollowsTests(FedCliCase):
    def test_send_follows_skips_a_structurally_broken_federation_store(self) -> None:
        # 联邦库能打开却查不了（表被删）：--follows 只按本机解析，不以堆栈退出（审计 r1 P2-2）
        with patch.object(cli, "worker_running", return_value=True):
            code, out, err = self.run_on("vm", "send", "--to", "codex@review", "-m", "本机旧任务", "--no-wait", "--json",
                                         caller=fed_agent(ORIGIN))
        self.assertEqual(code, 0, err)
        old = json.loads(out)["id"]
        connection = sqlite3.connect(self.states["vm"] / FED_DB_NAME, isolation_level=None)
        try:
            connection.execute("DROP TABLE fed_tasks")  # 不开外键：真实的结构损坏，不经产品代码
        finally:
            connection.close()
        with patch.object(cli, "worker_running", return_value=True):
            code, out, err = self.run_on("vm", "send", "--to", "codex@review", "-m", "后续", "--no-wait", "--json",
                                         "--follows", old[:8], caller=fed_agent(ORIGIN))
            self.assertEqual(code, 0, err)
            new = json.loads(out)["id"]
            code, out, err = self.run_on("vm", "send", "--to", "codex@review", "-m", "x", "--follows", "ffffffff",
                                         caller=fed_agent(ORIGIN))
        self.assertEqual((code, out), (cli.EXIT_TARGET, ""))
        self.assertIn("[follows_not_found]", err)
        with Store.open(self.states["vm"]) as store:
            task = store.get_task(new)
            assert task is not None
            self.assertEqual(task.options["follows"], old)
            self.assertEqual(len(store.list_tasks()), 2)  # 失败的那次没有落账
        code, out, err = self.run_on("vm", "status", old)
        self.assertEqual(code, 0, err)
        self.assertIn(f"后续任务 {short(new)}", out)  # 本机一侧照常显示


class LimitTextTests(LocalCliCase):
    def test_limit_texts_mention_follows(self) -> None:
        for code in ("attempts_near_limit", "report_attempts_near_limit", "capacity_attempts"):
            with self.subTest(code=code):
                self.assertIn("（可加 --follows <旧ID> 关联）", labels.reason_text(code))
        task_id = self.send()
        self.mark_sent(task_id, Delivery.FAILED)
        with self.store() as store:
            while max(item.seq for item in store.attempts(task_id)) < 60:
                store.add_attempt(task_id, role=Role.NOTICE, target=LEAD.ref, body="容量夹具", refs=[], now=3.0,
                                  sender=IMPL.ref, sender_class="bypass")
            task = store.get_task(task_id)
            assert task is not None
            step = labels.next_step(task, store.attempts(task_id), ref="TASK", command="ab")
            assert step is not None
            self.assertIn("ab close TASK 后 ab send 新任务（可加 --follows <旧ID> 关联）", step.text)
        code, _, err = self.run_cli("retry", task_id)
        self.assertEqual(code, cli.EXIT_REJECTED)
        self.assertIn("--follows <旧ID>", err)


if __name__ == "__main__":
    unittest.main()
