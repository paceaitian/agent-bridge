"""`ab todo`（DESIGN §104.3、§104.9 六）：五类判定、身份口径、联邦权威任务与镜像、空输出与退出码。"""

from __future__ import annotations

import json
import os
import shlex
import unittest
from unittest.mock import patch

import bridge_support  # noqa: F401  导入即隔离宿主会话环境
from agentstatus_bridge import cli
from agentstatus_bridge.model import Delivery, Flow, Role, Task, Work
from agentstatus_bridge.store import Store
from agentstatus_bridge.todo import local_items

from test_bridge_federation_cli import FedCliCase
from test_bridge_federation_mirror_work import runtime
from test_bridge_federation_rules import DEV_A, T0, FederationTestCase, deliver, pump

LINUX_FIXTURE_REASON = "POSIX-only: 替身 Linux 发现与调用方、Linux 私有状态目录（Windows 缺省平台是真实 Win32）"
linux_fixture = unittest.skipUnless(os.name == "posix", LINUX_FIXTURE_REASON)


@linux_fixture
class TodoCliTests(unittest.TestCase):
    def setUp(self) -> None:
        import test_bridge_cli as cli_tests
        self.cli_tests = cli_tests
        self.IMPL, self.LEAD, self.REVIEW = cli_tests.IMPL, cli_tests.LEAD, cli_tests.REVIEW
        cli_tests.CliTests.setUp(self)  # type: ignore[arg-type]
        from agentstatus_bridge import cli
        self.cli = cli
        self.caller = cli_tests.as_agent(self.LEAD)
        self.now = __import__("time").time()

    def run_cli(self, *argv: str) -> tuple[int, str, str]:
        return self.cli_tests.CliTests.run_cli(self, *argv)  # type: ignore[arg-type]

    def store(self):  # noqa: ANN201
        return self.cli_tests.CliTests.store(self)  # type: ignore[arg-type]

    def _task(self, *, target=None, origin=None, delivery: Delivery = Delivery.QUEUED, work: Work | None = None,
              flow: Flow = Flow.HANDOFF, at: float | None = None, options: dict[str, object] | None = None) -> Task:
        target = target or self.IMPL.ref
        origin = origin if origin is not None else self.LEAD.ref
        at = self.now if at is None else at
        with self.store() as store:
            task, attempt = store.create_task(title="任务标题", flow=flow, origin=origin, origin_class="bypass",
                                              reviewer=None, target=target, body="做 X", refs=[], now=at,
                                              task_options=options)
            if delivery is not Delivery.PENDING:
                store.begin_send(attempt.id, now=at, pid=1, start_ticks="1")
                store.finish_send(attempt.id, delivery=delivery, reason="test", provider_ref=None, detail={}, now=at)
            if work is not None:
                store.set_work(attempt.id, work=work, result={"note": "x"} if work is Work.RESULT else None, now=at,
                               event="t")
        return task

    def todo(self) -> list[dict[str, object]]:
        code, out, err = self.run_cli("todo", "--json")
        self.assertEqual(code, 0, err)
        return json.loads(out)

    def test_empty_prints_nothing_and_exits_zero(self) -> None:
        code, out, err = self.run_cli("todo")
        self.assertEqual((code, out, err), (0, "", ""))
        self.assertEqual(self.todo(), [])

    def test_five_categories(self) -> None:
        accept = self._task(work=Work.RESULT)
        handle = self._task(work=Work.BLOCKED)
        silent = self._task(at=self.now - 3600)
        quiet = self._task()  # 还没满 30 分钟：不列
        report = self._task(target=self.LEAD.ref, origin=self.IMPL.ref)
        found = {(item["category"], item["taskId"]) for item in self.todo()}
        self.assertEqual(found, {("accept", accept.id), ("handle", handle.id), ("silent", silent.id),
                                 ("report", report.id)})
        self.assertNotIn(quiet.id, {item["taskId"] for item in self.todo()})
        by_id = {item["taskId"]: item for item in self.todo()}
        from agentstatus_bridge.naming import command_name
        ab = command_name()  # 夹具里的入口名（与真实安装的 ab 不同）
        self.assertNotIn("command", by_id[accept.id])  # 未部署过：只有 commands 列表，没有拼接串（§104.11 第 1 条）
        # 命令一律写完整任务 ID（§104.12 第 1 条）；短 ID 只在文字行的展示列
        self.assertEqual(by_id[accept.id]["commands"],
                         [f"{ab} accept {accept.id}", f'{ab} retry {accept.id} -m "返工要求"'])
        self.assertEqual(by_id[handle.id]["commands"], [f"{ab} retry {handle.id}"])
        self.assertEqual(by_id[silent.id]["commands"],
                         [f'{ab} note {silent.id} -m "问题"', f"{ab} status {silent.id}"])
        self.assertEqual(by_id[accept.id]["short"], accept.id[:8])
        base = f"{ab} report {report.id} --attempt 1"
        self.assertEqual(by_id[report.id]["commands"],
                         [f'{base} --result --note "一句话结论"', f'{base} --blocked --note "原因"',
                          f'{base} --progress --note "进展"'])
        code, out, _ = self.run_cli("todo")
        self.assertEqual(len(out.splitlines()), 4)
        self.assertNotIn("|", out)
        self.assertIn(f'{base} --result --note "一句话结论" ｜ {base} --blocked --note "原因"', out)
        self.assertIn("待你验收", out)
        self.assertIn("对方沉默", out)

    def test_review_unsent_and_question_pending_receiver_side(self) -> None:
        review = self._task(target=self.LEAD.ref, origin=self.IMPL.ref, flow=Flow.REVIEW)
        with self.store() as store:
            first = store.attempts(review.id)[0]
            store.set_work(first.id, work=Work.RESULT, result={"note": "x"}, now=self.now, event="result")
            attempt = store.add_attempt(review.id, role=Role.REVIEW, target=self.LEAD.ref, body="请复核", refs=[],
                                        now=self.now, sender=None, sender_class="bypass")
            store.begin_send(attempt.id, now=self.now, pid=1, start_ticks="1")
            store.finish_send(attempt.id, delivery=Delivery.QUEUED, reason="t", provider_ref=None, detail={},
                              now=self.now)
        unsent = self._task(target=self.LEAD.ref, origin=self.IMPL.ref, delivery=Delivery.PENDING)
        asked = self._task(target=self.LEAD.ref, origin=self.IMPL.ref)
        with self.store() as store:
            work = store.attempts(asked.id)[0]
            store.set_attempt_option(work.id, "ask", {"at": self.now + 1, "note": "问题"})
            store.set_work(work.id, work=Work.IN_PROGRESS, result=None, now=self.now + 1, event="progress")
        found = {(item["category"], item["taskId"]) for item in self.todo()}
        self.assertEqual(found, {("review", review.id)})
        self.assertNotIn(unsent.id, {item["taskId"] for item in self.todo()})
        # 提问方的对面（发起方）看到「待你处理」
        self.caller = self.cli_tests.as_agent(self.IMPL)
        found = {(item["category"], item["taskId"]) for item in self.todo()}
        self.assertIn(("handle", asked.id), found)

    def test_receiver_items_require_a_handed_over_attempt(self) -> None:
        # Codex P1-02（§104.12 第 2 条）：交接与复核都只在已交出时列「待你汇报/复核」；确定未送达、拒收的不列，
        # 否则照抄第一条命令就会对没交到手的交接交出终态结果
        found: dict[tuple[str, str], bool] = {}
        for flow in (Flow.HANDOFF, Flow.REVIEW):
            for delivery in (Delivery.FAILED, Delivery.REFUSED, Delivery.QUEUED, Delivery.WRITTEN):
                if flow is Flow.HANDOFF:
                    task = self._task(target=self.LEAD.ref, origin=self.IMPL.ref, delivery=delivery)
                else:
                    task = self._task(target=self.REVIEW.ref, origin=self.IMPL.ref, flow=Flow.REVIEW,
                                      work=Work.RESULT)
                    with self.store() as store:
                        review = store.add_attempt(task.id, role=Role.REVIEW, target=self.LEAD.ref, body="请复核",
                                                   refs=[], now=self.now, sender=None, sender_class="bypass")
                        store.begin_send(review.id, now=self.now, pid=1, start_ticks="1")
                        store.finish_send(review.id, delivery=delivery, reason="t", provider_ref=None, detail={},
                                          now=self.now)
                found[(flow.value, delivery.value)] = task.id in {item["taskId"] for item in self.todo()}
        self.assertEqual(found, {("handoff", "failed"): False, ("handoff", "refused"): False,
                                 ("handoff", "queued"): True, ("handoff", "written"): True,
                                 ("review", "failed"): False, ("review", "refused"): False,
                                 ("review", "queued"): True, ("review", "written"): True})

    def test_origin_who_reviews_is_not_its_own_silent_counterparty(self) -> None:
        # Codex P2-07（§104.12 第 12 条）：发起方兼任复核方时，自己的复核只列「待你复核」，不列「对方沉默」
        from unittest.mock import patch
        helper = self.cli_tests.CliTests
        task_id = helper.send(self, "--review-by", "codex@lead")
        helper.mark_sent(self, task_id)
        self.caller = self.cli_tests.as_agent(self.IMPL)
        code, _, err = self.run_cli("report", task_id, "--result", "--note", "ready")
        self.assertEqual(code, 0, err)
        self.caller = self.cli_tests.as_agent(self.LEAD)
        with self.store() as store:
            review = next(item for item in store.attempts(task_id) if item.role is Role.REVIEW)
            store.begin_send(review.id, now=self.now + 2, pid=1, start_ticks="1")
            store.finish_send(review.id, delivery=Delivery.QUEUED, reason="t", provider_ref=None, detail={},
                              now=self.now + 2)
        with patch.object(self.cli.time, "time", return_value=self.now + 4000):
            categories = [item["category"] for item in self.todo() if item["taskId"] == task_id]
        self.assertEqual(categories, ["review"])

    def test_unrecognized_sessions_are_rejected(self) -> None:
        self.caller = self.cli_tests.USER
        code, _out, err = self.run_cli("todo")
        self.assertNotEqual(code, 0)
        self.assertIn("--mine 按会话 ID 匹配", err)

    def test_unreadable_federation_store_goes_to_stderr_and_exits_zero(self) -> None:
        self._task(work=Work.RESULT)
        (self.state / "federation.json").write_text("{}", encoding="utf-8")
        code, out, err = self.run_cli("todo")
        self.assertEqual(code, 0, err)
        self.assertEqual(len(out.splitlines()), 1)
        self.assertIn("联邦库不可读", err)


class TodoFederationTests(FederationTestCase):
    def test_authority_origin_and_mirror_receiver(self) -> None:
        task, first = self.create()
        pump(self.a, self.b, now=T0 + 1)
        deliver(self.b, first.msg_id, "queued", now=T0 + 2)
        pump(self.b, self.a, now=T0 + 3)
        # B：镜像尝试发给本机执行方，命令带 --origin-device（登记名是 slug 就用名）
        b_task = self.b.store.get_task(DEV_A, task.task_id)
        assert b_task is not None
        from agentstatus_bridge.federation import mirror
        work = mirror.local_report_target(self.b.store, self.b.ident, b_task)
        assert work is not None and work.target.local is not None
        rt = runtime(self.b, self.root)
        from agentstatus_bridge.federation import commands
        self.assertEqual(commands.device_name(rt, DEV_A), DEV_A)  # 目录没缓存登记名：退回完整 deviceId
        # A：发起方沉默满 T 时列「对方沉默」
        current = self.a.store.get_task(DEV_A, task.task_id)
        assert current is not None
        from agentstatus_bridge.federation.views import model_attempts, model_task
        origin_ref = self.origin.local
        assert origin_ref is not None
        items = local_items(model_task(current), model_attempts(self.a.store.attempts(DEV_A, task.task_id)),
                            origin_ref, now=(T0 + 3) / 1000.0 + 1800, command="ab", scope="federation")
        self.assertEqual([(item.category, item.scope) for item in items], [("silent", "federation")])
        self.assertEqual(local_items(model_task(current), model_attempts(self.a.store.attempts(DEV_A, task.task_id)),
                                     origin_ref, now=(T0 + 3) / 1000.0 + 1799, command="ab"), [])

    def test_cli_federation_part_lists_the_mirror_report_with_origin_device(self) -> None:
        from unittest.mock import patch
        from agentstatus_bridge import cli
        from agentstatus_bridge.federation import commands
        task, first = self.create()
        pump(self.a, self.b, now=T0 + 1)
        deliver(self.b, first.msg_id, "queued", now=T0 + 2)
        self.b.store.put_device_state(device_id=DEV_A, name="vm", revision=1, snapshot={}, last_seen=T0,
                                      state="online")
        worker = self.worker.local
        assert worker is not None
        rt = runtime(self.b, self.root)
        with patch.object(cli, "_fed_configured", return_value=True), \
                patch.object(commands, "try_runtime", return_value=rt), patch.object(rt, "close"):
            [item] = cli._fed_todo(worker, T0 / 1000.0, "ab")  # pyright: ignore[reportPrivateUsage]
            self.assertEqual((item.category, item.scope, item.task_id), ("report", "federation", task.task_id))
            self.assertTrue(all(f"report {task.task_id} --origin-device vm --attempt 1 --" in line
                                for line in item.commands), item.commands)
            self.assertEqual(len(item.commands), 3)
            # 别的会话没有这一项
            other = self.origin.local
            assert other is not None
            self.assertEqual(cli._fed_todo(other, T0 / 1000.0, "ab"), [])  # pyright: ignore[reportPrivateUsage]
        with patch.object(cli, "_fed_configured", return_value=True), \
                patch.object(commands, "try_runtime", return_value=None):
            self.assertIsNone(cli._fed_todo(worker, T0 / 1000.0, "ab"))  # pyright: ignore[reportPrivateUsage]

    def test_mirror_attempt_that_failed_to_deliver_is_not_listed(self) -> None:
        # §104.12 第 2 条在镜像上同一判据：本机确定投递失败的尝试不列「待你汇报」
        from agentstatus_bridge import cli
        from agentstatus_bridge.federation import commands
        task, first = self.create()
        pump(self.a, self.b, now=T0 + 1)
        deliver(self.b, first.msg_id, "failed", now=T0 + 2)
        worker = self.worker.local
        assert worker is not None
        rt = runtime(self.b, self.root)
        with patch.object(cli, "_fed_configured", return_value=True), \
                patch.object(commands, "try_runtime", return_value=rt), patch.object(rt, "close"):
            self.assertEqual(cli._fed_todo(worker, T0 / 1000.0, "ab"), [])  # pyright: ignore[reportPrivateUsage]
        self.assertTrue(task.task_id)


class TodoFederationCliTests(FedCliCase):
    """跨设备 todo 经真实 CLI（§104.12 第 1、11 条）。"""

    def test_same_codex_thread_on_another_device_is_the_counterparty_not_me(self) -> None:
        # §104.13 第 4 条（Codex r2 P1-04）：A 上的发起会话与 B 上的执行方是同一个 Codex thread 号（拷到两台机器）。
        # A 照常排出沉默提醒、todo 只列「对方沉默」不列「待你汇报」；B 照常汇报，A 采纳
        from agentstatus_bridge import cli
        from agentstatus_bridge.federation.delivery import FederationDispatcher
        from agentstatus_bridge.federation.relay import RelayPaths
        from agentstatus_bridge.model import Provider
        from agentstatus_bridge.reminders import REMINDER_OPTION
        from bridge_support import endpoint, ref
        from test_bridge_federation_cli import DEV_A as FED_A, THREAD_B, WORKER, as_agent
        here = endpoint(ref(Provider.CODEX, THREAD_B, pid=31005, start="88", pane="%9", label="here"), name="here")
        self.endpoints["vm"].append(here)
        me = as_agent(here)
        code, out, err = self.run_on("vm", "send", "--device", "win", "--to", f"codex@id:{THREAD_B}", "--expect", "5m",
                                     "-m", "做 X", "--json", caller=me)
        self.assertEqual(code, 0, err)
        task_id = json.loads(out)["id"]
        self.pump("vm", "win")
        self.assertEqual(len(self.deliver_on_b().calls), 1)
        self.pump("win", "vm")
        with self.store("vm") as store:
            due = store.attempts(FED_A, task_id)[0].delivery["at"] + 600_000
        with patch.object(cli.time, "time", return_value=due / 1000):
            code, out, err = self.run_on("vm", "todo", "--json", caller=me)
        self.assertEqual(code, 0, err)
        self.assertEqual([row["category"] for row in json.loads(out) if row["taskId"] == task_id], ["silent"])
        with self.store("vm") as store:
            dispatcher = FederationDispatcher(store, self.ident("vm"), RelayPaths(self.states["vm"]),
                                              discover=lambda: [], transports={}, clock=lambda: due, command="ab")
            self.assertEqual(dispatcher.queue_reminders(), 1)
            notice = store.attempts(FED_A, task_id)[-1]
            self.assertEqual(notice.role, "notice")
            self.assertIn(":silent:", str(notice.options.get(REMINDER_OPTION)))
        code, _, err = self.run_on("win", "report", task_id, "--origin-device", "vm", "--attempt", "1", "--progress",
                                   "--note", "在做", caller=as_agent(WORKER))
        self.assertEqual(code, 0, err)
        self.pump("win", "vm")
        with self.store("vm") as store:
            self.assertEqual(store.attempts(FED_A, task_id)[0].effective_work["work"], "in_progress")

    def test_copied_accept_command_hits_the_listed_federation_task_not_a_local_prefix_twin(self) -> None:
        # Codex P1-01：本机与联邦两库各有一项待验收、前八位相同；照抄联邦行的命令，改的是联邦那一项、本机那一项不动
        from uuid import uuid4
        from agentstatus_bridge import store as store_module
        from test_bridge_federation_cli import LOCAL_REVIEW, ORIGIN, WORKER, as_agent
        fid = self.delivered_task()
        self.assertEqual(self.run_on("win", "report", fid, "--result", caller=as_agent(WORKER))[0], 0)
        self.pump("win", "vm")
        lid = fid[:8] + ("0" * 24 if fid[8:] != "0" * 24 else "1" * 24)
        with Store.open(self.states["vm"]) as local:
            with patch.object(store_module, "new_id", side_effect=[lid, uuid4().hex, uuid4().hex]):
                _, attempt = local.create_task(title="本机", flow=Flow.HANDOFF, origin=ORIGIN.ref, origin_class="bypass",
                                               reviewer=None, target=LOCAL_REVIEW.ref, body="另一项", refs=[], now=1)
            local.begin_send(attempt.id, now=2, pid=1, start_ticks="1")
            local.finish_send(attempt.id, delivery=Delivery.DELIVERED, reason="t", provider_ref=None, detail={}, now=2)
            local.set_work(attempt.id, work=Work.RESULT, result={"note": "ok"}, now=3, event="result")
        code, out, err = self.run_on("vm", "todo", "--json", caller=as_agent(ORIGIN))
        self.assertEqual(code, 0, err)
        rows = {row["taskId"]: row for row in json.loads(out)}
        self.assertEqual(rows[fid]["short"], rows[lid]["short"])  # 两项前八位相同
        # 联邦权威行的命令带路由（§104.13 第 2 条）：完整 ID 加 --origin-device <本机>，本机行只写完整 ID
        command = shlex.split(rows[fid]["commands"][0])[1:]
        self.assertEqual(command, ["accept", fid, "--origin-device", "vm"])
        self.assertEqual(shlex.split(rows[lid]["commands"][0])[1:], ["accept", lid])
        # 手输短号两库都命中：拒绝，两项都不动（§104.13 第 1 条）
        code, _, err = self.run_on("vm", "accept", fid[:8], caller=as_agent(ORIGIN))
        self.assertEqual((code, "[task_ambiguous]" in err), (cli.EXIT_TARGET, True), err)
        code, _, err = self.run_on("vm", *command, caller=as_agent(ORIGIN))
        self.assertEqual(code, 0, err)
        with Store.open(self.states["vm"]) as local, self.store("vm") as fed:
            local_task, fed_task = local.get_task(lid), fed.get_task(DEV_A, fid)
            assert local_task is not None and fed_task is not None
            self.assertEqual((local_task.finished, fed_task.finished), (False, True))
        # 本机行的命令同样照抄执行，只改本机那一项
        code, _, err = self.run_on("vm", *shlex.split(rows[lid]["commands"][0])[1:], caller=as_agent(ORIGIN))
        self.assertEqual(code, 0, err)
        with Store.open(self.states["vm"]) as local:
            local_task = local.get_task(lid)
            assert local_task is not None
            self.assertTrue(local_task.finished)

    def test_json_keeps_the_remote_title_and_text_escapes_it_on_one_line(self) -> None:
        # Codex P2-06：行模型保留原标题；--json 解码后与镜像库里的原字符一致，文字行按远端字符串转义、一项一行
        from test_bridge_federation_cli import WORKER, as_agent
        title = "sample\ntitle"
        task_id = self.send("--title", title)
        self.pump("vm", "win")
        self.deliver_on_b()
        code, out, err = self.run_on("win", "todo", "--json", caller=as_agent(WORKER))
        self.assertEqual(code, 0, err)
        [row] = [item for item in json.loads(out) if item["taskId"] == task_id]
        self.assertEqual(row["title"], title)
        code, out, err = self.run_on("win", "todo", caller=as_agent(WORKER))
        self.assertEqual(code, 0, err)
        self.assertEqual(len(out.splitlines()), 1)
        self.assertIn("sample\\u000atitle", out)
        # 权威端（发起设备）的待你验收行同一口径
        from test_bridge_federation_cli import ORIGIN
        self.assertEqual(self.run_on("win", "report", task_id, "--result", caller=as_agent(WORKER))[0], 0)
        self.pump("win", "vm")
        code, out, err = self.run_on("vm", "todo", "--json", caller=as_agent(ORIGIN))
        self.assertEqual(code, 0, err)
        [row] = [item for item in json.loads(out) if item["taskId"] == task_id]
        self.assertEqual((row["category"], row["title"]), ("accept", title))
        code, out, err = self.run_on("vm", "todo", caller=as_agent(ORIGIN))
        self.assertEqual(code, 0, err)
        self.assertEqual(len(out.splitlines()), 1)
        self.assertIn("sample\\u000atitle", out)


if __name__ == "__main__":
    unittest.main()
