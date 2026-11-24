"""§104.13 第 1、2 条：跨库歧义一律拒绝；联邦权威端生成的可执行命令用完整 ID 并带 --origin-device。

回归都真的执行命令，并断言本机库与联邦库各自的最终状态（Codex P1-01、P1-02 的形状）。
"""

from __future__ import annotations

import re
import shlex
import unittest
from unittest.mock import patch
from uuid import uuid4

import bridge_support  # noqa: F401  导入即隔离宿主会话环境
import test_bridge_federation_cli as fed_base

from agentstatus_bridge import cli
from agentstatus_bridge import store as store_module
from agentstatus_bridge.federation import authority
from agentstatus_bridge.federation.delivery import FederationDispatcher
from agentstatus_bridge.federation.fedstore import now_ms
from agentstatus_bridge.federation.relay import RelayPaths
from agentstatus_bridge.labels import capacity_close_text, follows_ref
from agentstatus_bridge import reminders
from agentstatus_bridge.model import Attempt, Delivery, EndpointRef, Flow, Provider, Role, Task, Work, describe
from agentstatus_bridge.reminders import PendingReminder, reminder_body
from agentstatus_bridge.store import Store, attempt_limit

ORIGIN = fed_base.ORIGIN
DEV_A = fed_base.DEV_A


def commands_in(text: str, verb: str) -> list[list[str]]:
    """正文里每条 `ab <verb> …` 命令（到中文标点或行尾为止），按 shlex 切成参数。"""
    found = re.findall(rf"\bab {verb} [0-9a-f]+(?: --origin-device [a-z0-9-]+)?", text)
    return [shlex.split(item)[1:] for item in found]


class CrossStoreAmbiguityTests(fed_base.FedCliCase):
    def twin(self, fid: str, *, result: bool = True) -> str:
        """本机建一项与联邦任务前八位相同、其余不同的任务（发起方同一会话），返回完整 ID。"""
        lid = fid[:8] + ("0" * 24 if fid[8:] != "0" * 24 else "1" * 24)
        with Store.open(self.states["vm"]) as local:
            with patch.object(store_module, "new_id", side_effect=[lid, uuid4().hex, uuid4().hex]):
                _, attempt = local.create_task(title="本机", flow=Flow.HANDOFF, origin=ORIGIN.ref, origin_class="bypass",
                                               reviewer=None, target=fed_base.LOCAL_REVIEW.ref, body="另一项", refs=[],
                                               now=1)
            if result:
                local.begin_send(attempt.id, now=2, pid=1, start_ticks="1")
                local.finish_send(attempt.id, delivery=Delivery.DELIVERED, reason="t", provider_ref=None, detail={},
                                  now=2)
                local.set_work(attempt.id, work=Work.RESULT, result={"note": "ok"}, now=3, event="result")
        return lid

    def finished(self, lid: str, fid: str) -> tuple[bool, bool]:
        with Store.open(self.states["vm"]) as local, self.store("vm") as fed:
            local_task, fed_task = local.get_task(lid), fed.get_task(DEV_A, fid)
            assert local_task is not None and fed_task is not None
            return local_task.finished, fed_task.finished

    def result_task(self) -> str:
        fid = self.delivered_task()
        self.assertEqual(self.run_on("win", "report", fid, "--result", "--note", "完成",
                                     caller=fed_base.as_agent(fed_base.WORKER))[0], 0)
        self.pump("win", "vm")
        return fid

    def test_prefix_twin_is_ambiguous_full_ids_resolve_each_store(self) -> None:
        fid = self.result_task()
        lid = self.twin(fid)
        origin = fed_base.as_agent(ORIGIN)
        for verb in ("status", "accept", "close"):
            with self.subTest(verb=verb):
                code, out, err = self.run_on("vm", verb, fid[:8], caller=origin)
                self.assertEqual((code, "[task_ambiguous]" in err), (cli.EXIT_TARGET, True), err)
                self.assertIn(f"{fid} --origin-device vm", err)
        self.assertEqual(self.finished(lid, fid), (False, False))
        # 完整 ID 各自只命中一个库：本机完整 ID 走本机，联邦完整 ID 不带路由也唯一
        code, out, err = self.run_on("vm", "status", lid, caller=origin)
        self.assertEqual(code, 0, err)
        self.assertNotIn("跨设备任务", out)
        code, out, err = self.run_on("vm", "status", fid, caller=origin)
        self.assertEqual(code, 0, err)
        self.assertIn("跨设备任务", out)

    def test_federation_store_unreadable_keeps_the_local_hit(self) -> None:
        fid = self.result_task()
        lid = self.twin(fid)
        with patch("agentstatus_bridge.federation.fedstore.FederatedStore.open_readonly",
                   side_effect=store_module.StoreError("federation_store_unavailable")):
            code, out, err = self.run_on("vm", "status", fid[:8], caller=fed_base.as_agent(ORIGIN))
        self.assertEqual(code, 0, err)
        self.assertIn(lid[:8], out)
        self.assertNotIn("跨设备任务", out)

    def test_blank_origin_device_is_refused_before_touching_either_store(self) -> None:
        # §104.14 第 2 条：显式空白的 --origin-device 与 --device "" 同一拒绝，不当作「没指定」也不当作「不限权威」
        fid = self.result_task()
        lid = self.twin(fid)
        origin = fed_base.as_agent(ORIGIN)
        with patch.object(Store, "open", side_effect=AssertionError("local store opened")), \
                patch("agentstatus_bridge.federation.fedstore.FederatedStore.open",
                      side_effect=AssertionError("federation store opened")), \
                patch("agentstatus_bridge.federation.fedstore.FederatedStore.open_readonly",
                      side_effect=AssertionError("federation store opened read-only")):
            for value in ("", " ", "\t"):
                for argv in (("accept", fid[:8]), ("close", fid), ("status", fid[:8]),
                             ("report", fid, "--result")):
                    with self.subTest(value=value, argv=argv):
                        code, out, err = self.run_on("vm", *argv, "--origin-device", value, caller=origin)
                        self.assertEqual((code, out), (cli.EXIT_TARGET, ""))
                        self.assertIn("[target_explicit_required]", err)
        self.assertEqual(self.finished(lid, fid), (False, False))

    def test_device_name_failure_still_refuses_with_the_records_authority_id(self) -> None:
        # §104.14 第 1 条：B 上镜像与本机任务撞号；只读设备名那一步失败，仍按已查到的命中拒绝，提示用记录里的 authorityDeviceId
        import sqlite3
        from agentstatus_bridge.federation.fedstore import FederatedStore
        fid = self.delivered_task()
        lid = fid[:8] + ("0" * 24 if fid[8:] != "0" * 24 else "1" * 24)
        with Store.open(self.states["win"]) as local:
            with patch.object(store_module, "new_id", side_effect=[lid, uuid4().hex, uuid4().hex]):
                local.create_task(title="本机", flow=Flow.HANDOFF, origin=fed_base.WORKER.ref, origin_class="bypass",
                                  reviewer=None, target=fed_base.LOCAL_REVIEW.ref, body="另一项", refs=[], now=1)
        with patch.object(FederatedStore, "device_states", side_effect=sqlite3.OperationalError("busy")):
            code, out, err = self.run_on("win", "close", fid[:8], caller=fed_base.as_agent(fed_base.WORKER))
        self.assertEqual((code, "[task_ambiguous]" in err), (cli.EXIT_TARGET, True), err)
        self.assertIn(f"{fid} --origin-device {DEV_A}", err)
        with Store.open(self.states["win"]) as local, self.store("win") as fed:
            local_task, mirror_task = local.get_task(lid), fed.get_task(DEV_A, fid)
            assert local_task is not None and mirror_task is not None
            self.assertEqual((local_task.finished, mirror_task.finished), (False, False))

    def test_unreadable_task_index_or_foreign_instance_falls_back_to_the_local_hit(self) -> None:
        # 只有任务索引本身读不了，或联邦库实例身份与配置不配对（§104.14 第 6 条）时，才只看本机
        import sqlite3
        from agentstatus_bridge.federation.fedstore import FederatedStore
        fid = self.result_task()
        origin = fed_base.as_agent(ORIGIN)
        lid = self.twin(fid)
        with patch.object(FederatedStore, "find_tasks", side_effect=sqlite3.DatabaseError("broken index")):
            code, out, err = self.run_on("vm", "status", fid[:8], caller=origin)
        self.assertEqual(code, 0, err)
        self.assertNotIn("跨设备任务", out)
        for key, value in (("hubId", "e" * 32), ("deviceId", "f" * 32)):
            with self.subTest(key=key):
                with self.store("vm") as fed:
                    original = fed.meta(key)
                    fed.set_meta(key, value)
                try:
                    code, out, err = self.run_on("vm", "status", fid[:8], caller=origin)
                    self.assertEqual(code, 0, err)
                    self.assertNotIn("跨设备任务", out)
                finally:
                    with self.store("vm") as fed:
                        assert original is not None
                        fed.set_meta(key, original)
        # 身份配对时照常拒绝（反证上面的放行确实来自身份核对）
        code, _, err = self.run_on("vm", "status", fid[:8], caller=origin)
        self.assertEqual((code, "[task_ambiguous]" in err), (cli.EXIT_TARGET, True), err)
        self.assertEqual(self.finished(lid, fid), (False, False))

    def test_receipt_next_step_command_routes_to_the_federation_row(self) -> None:
        fid = self.result_task()
        lid = self.twin(fid)
        with self.store("vm") as fed:
            [receipt] = [item for item in fed.attempts(DEV_A, fid) if item.role == "notice"]
        accepts = commands_in(receipt.body, "accept")
        self.assertEqual(accepts[0], ["accept", fid, "--origin-device", "vm"])
        self.assertNotIn(f"ab accept {fid[:8]} ", receipt.body)
        self.assertEqual(self.run_on("vm", *accepts[0], caller=fed_base.as_agent(ORIGIN))[0], 0)
        self.assertEqual(self.finished(lid, fid), (False, True))

    def test_reminder_commands_route_to_the_federation_row(self) -> None:
        fid = self.result_task()
        lid = self.twin(fid)
        start = now_ms()
        with self.store("vm") as fed:
            # 先把回执交给发起会话（待发通知在时不排 30 分钟提醒），再到 31 分钟后排提醒
            for clock in (start, start + 31 * 60 * 1000):
                FederationDispatcher(fed, self.ident("vm"), RelayPaths(self.states["vm"]), discover=lambda: [ORIGIN],
                                     transports={Provider.CLAUDE: bridge_support.RecordingTransport(Provider.CLAUDE)},
                                     clock=lambda clock=clock: clock,
                                     reply_address="uds:" + str(self.root / "fixture-reply.sock"), command="ab").run_once()
            reminder = fed.attempts(DEV_A, fid)[-1]
        self.assertIn("提醒", reminder.body)
        accepts = commands_in(reminder.body, "accept")
        self.assertEqual(accepts[0], ["accept", fid, "--origin-device", "vm"])
        self.assertEqual(self.run_on("vm", *accepts[0], caller=fed_base.as_agent(ORIGIN))[0], 0)
        self.assertEqual(self.finished(lid, fid), (False, True))


    def test_authority_side_review_row_routes_to_the_federation_row(self) -> None:
        # A 本机复核方的「待你复核」行：权威端的接收方一侧同样带路由，照抄后改的是联邦那一项
        fid = self.local_review_requested()
        lid = self.twin(fid, result=False)
        code, out, err = self.run_on("vm", "todo", "--json", caller=fed_base.as_agent(fed_base.LOCAL_REVIEW))
        self.assertEqual(code, 0, err)
        import json
        [row] = [item for item in json.loads(out) if item["taskId"] == fid and item["category"] == "review"]
        approve = shlex.split(row["commands"][0])[1:]
        self.assertEqual(approve[:4], ["report", fid, "--origin-device", "vm"])
        self.assertEqual(self.run_on("vm", *approve, caller=fed_base.as_agent(fed_base.LOCAL_REVIEW))[0], 0)
        with self.store("vm") as fed:
            task = fed.get_task(DEV_A, fid)
            assert task is not None
            self.assertEqual(task.state.get("verdict"), "approved")
        with Store.open(self.states["vm"]) as local:
            self.assertEqual([item.work for item in local.attempts(lid)], [Work.AWAITING_ACK])


class ReminderCommandShapeTests(unittest.TestCase):
    """提醒正文里的命令：联邦传入的 ref 进命令、展示仍是短号；--follows 只取任务 ID；每条都能被真实解析器接受。"""

    TARGET = EndpointRef(provider=Provider.CODEX, native_id="impl-thread", pid=1, start_ticks="1")
    TASK = Task(id="ab" * 16, created_at=1.0, updated_at=1.0, title="T", flow=Flow.HANDOFF,
                origin=EndpointRef(provider=Provider.CLAUDE, native_id="lead", pid=2, start_ticks="2"), reviewer=None)
    REF = f"{'ab' * 16} --origin-device vm"

    def attempts(self, last: int) -> list[Attempt]:
        work = Attempt(id="a" * 32, task_id=self.TASK.id, seq=1, role=Role.HANDOFF, target=self.TARGET,
                       message_id="b" * 32, created_at=1.0, body="实现", delivery=Delivery.QUEUED, delivery_at=2.0,
                       work=Work.IN_PROGRESS, work_at=3.0)
        return [work, *[Attempt(id=f"{seq:032x}", task_id=self.TASK.id, seq=seq, role=Role.NOTICE, target=self.TARGET,
                                message_id=f"{seq + 100:032x}", created_at=1.0, body="x", delivery=Delivery.QUEUED)
                        for seq in range(2, last + 1)]]

    def body(self, last: int, *, ref: str | None) -> str:
        attempts = self.attempts(last)
        view = describe(self.TASK, attempts)
        silent = PendingReminder(token=f"{'a' * 32}:silent:3.000000", due_at=1903.0, view=view, kind="silent",
                                 anchor=3.0)
        return reminder_body(self.TASK, attempts, view, command="ab", silent=silent, state="空闲", now=1903.0, ref=ref)

    def test_routed_ref_reaches_every_command_and_follows_takes_only_the_task(self) -> None:
        parser = cli.build_parser()
        for last in (10, attempt_limit(Role.HANDOFF) - 1):
            with self.subTest(last=last):
                text = self.body(last, ref=self.REF)
                self.assertIn(f"任务 {self.TASK.id[:8]} 已", text)  # 展示用短号
                for verb in ("note", "status", "retry", "close"):
                    for argv in commands_in(text, verb):
                        self.assertEqual(argv[1:], [self.TASK.id, "--origin-device", "vm"], text)
                    for argv in commands_in(text, verb):
                        parser.parse_args(argv + (["-m", "x"] if verb == "note" else []))  # 真实解析器接受
                if last > 10:
                    self.assertIn(f"--follows {self.TASK.id} 关联", text)
                    self.assertNotIn("--follows " + self.REF, text)
        # 本机缺省仍是短号
        local = self.body(10, ref=None)
        self.assertIn(f"ab status {self.TASK.id[:8]}", local)
        self.assertNotIn("--origin-device", local)

    def test_capacity_and_note_and_undelivered_steps_carry_the_routed_ref(self) -> None:
        text = capacity_close_text("ab", self.REF)
        self.assertIn(f"ab close {self.REF} 后", text)
        self.assertIn(f"--follows {self.TASK.id} 关联", text)
        # 补充还能重新补：命令带路由
        attempts = self.attempts(10)
        step = reminders._note_step(self.TASK, attempts, command="ab", ref=self.REF)  # pyright: ignore[reportPrivateUsage]
        self.assertEqual(step, f'可重新 ab note {self.REF} -m "补充内容"')
        # 确定未送达的立即告知：下一步的 retry/close 带路由
        from dataclasses import replace
        failed = [replace(attempts[0], delivery=Delivery.FAILED, work=Work.AWAITING_ACK, delivery_reason="t")]
        body = reminder_body(self.TASK, failed, describe(self.TASK, failed), command="ab", immediate=True, ref=self.REF)
        self.assertIn(f"ab retry {self.REF}", body)
        self.assertIsNone(re.search(rf"ab retry {self.TASK.id[:8]}(?![0-9a-f])", body), body)  # 不出现裸短号

    def test_follows_ref_keeps_only_the_task_reference(self) -> None:
        self.assertEqual(follows_ref(self.REF), self.TASK.id)
        self.assertEqual(follows_ref("12345678"), "12345678")
        argv = ["send", "--to", "codex@impl", "-m", "x", "--follows", follows_ref(self.REF)]
        self.assertEqual(cli.build_parser().parse_args(argv).follows, self.TASK.id)

    def test_command_ref_uses_slug_or_full_device_id(self) -> None:
        self.assertEqual(authority.command_ref(authority.Identity("d" * 32, "vm", "h"), "1" * 32),
                         f"{'1' * 32} --origin-device vm")
        self.assertEqual(authority.command_ref(authority.Identity("d" * 32, "Not A Slug", "h"), "1" * 32),
                         f"{'1' * 32} --origin-device {'d' * 32}")


if __name__ == "__main__":
    unittest.main()
