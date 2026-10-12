"""`ab` 命令行：退出码合同、验收/重发/返工规则与不需要图形界面的完整流程。"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from contextlib import redirect_stderr, redirect_stdout
from dataclasses import replace
import fcntl
import threading
import time
from io import StringIO
import json
import os
import sqlite3
from pathlib import Path
import subprocess
import sys
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from agentstatus_bridge import cli, doctor, naming, observer_dbus, paths, summary, views
from agentstatus_bridge.naming import DEFAULT_COMMAND as CMD
from agentstatus_bridge.endpoints import Caller, DiscoverySources
from agentstatus_bridge.observer_dbus import ObserverView
from agentstatus_bridge.model import Consumption, Delivery, Endpoint, EndpointRef, Flow, Provider, Role, Runtime, Verdict, Work
from agentstatus_bridge.procfs import ProcessInfo
from agentstatus_bridge.store import Store, StoreError
from bridge_support import discovering, endpoint, ref

IMPL = endpoint(ref(Provider.CODEX, "impl-thread", pid=1000, pane="%1", label="impl", server=100))
REVIEW = endpoint(ref(Provider.CLAUDE, "review-session", pid=2000, pane="%2", label="review"))
LEAD = endpoint(ref(Provider.CODEX, "lead-thread", pid=3000, pane="%3", label="lead", server=100))


def own_row(live: Endpoint, match: str = "generation", **fields: object) -> dict[str, object]:
    """目标自己的 observer 行，`match` 选代际键或（Claude）会话键：键与摘要的 `endpoint_binding` 同算法（该算法另由 observer 对照用例锁定）。"""
    [key] = [item["key"] for item in summary.endpoint_binding(live.ref)["observerKeys"] if item["match"] == match]
    return {"key": key, "paneId": live.ref.pane, "agent": live.ref.provider.value, **fields}
# 只读 provider：发现阶段就带 no_inbox，所有投递入口都要拒（DESIGN §45.34）
GROK = endpoint(ref(Provider.GROK, "019a0000-cccc-7ccc-8ccc-cccccccccccc", pid=4000, pane="%9", label="grok"))


def as_agent(item: Endpoint) -> Caller:
    return Caller(item, ProcessInfo(item.ref.pid, 1, item.ref.provider.value, item.ref.start_ticks))


USER = Caller(None, None)


class CliTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = TemporaryDirectory()
        self.state = Path(self._tmp.name) / "bridge"
        self.endpoints: list[Endpoint] = [IMPL, REVIEW, LEAD]
        self.caller = USER
        self.worker_up = True
        # AgentStatus 快照在最底层替换：给原始 ListSessions 行并计数，选行与解析都走真实代码（DESIGN §55.4）。
        # rows 是每次读取都给的行；replies 非空时按读取次序逐份给（读多了就重复最后一份，不抛 StopIteration）
        self.rows: list[dict[str, object]] = []
        self.replies: list[list[dict[str, object]]] = []
        self.observer_reads = 0
        self.discovered: list[tuple[DiscoverySources | None, ObserverView]] = []

        def read_rows() -> list[dict[str, object]]:
            self.observer_reads += 1
            if self.replies:
                return [dict(item) for item in self.replies[min(self.observer_reads, len(self.replies)) - 1]]
            return [dict(item) for item in self.rows]

        patches = [
            patch.object(observer_dbus, "_observer_rows", side_effect=read_rows),
            # doctor 会 `shutil.which("codex")` 并**真的执行**它（strace 实证：还会在真实 ~/.codex 下
            # 建目录与锁），也会探测真实 `~/.claude/sessions`。测试不该碰 PATH 上任意同名程序与真实
            # agent 目录，两处都在这里注入（独立 Fable 审计 P3-4）
            patch.dict(
                os.environ,
                {
                    "AB_STATE_DIR": str(self.state),
                    "AB_CLAUDE_SESSIONS_DIR": str(Path(self._tmp.name) / "claude-sessions"),
                },
            ),
            patch.object(doctor, "cli_version", return_value=None),
            # doctor 的 agentstatus_runtime 读的是真实 session bus：8 个 doctor 用例原来都连到本机 daemon（§48.1 第 3 条）
            patch.object(doctor, "agentstatus_runtime", return_value={}),
            # doctor 的标题检查会扫真实 /proc 与 tmux（DESIGN §53.5）
            patch.object(doctor, "codex_title_report", return_value={"daemonMode": False}),
            patch.object(cli, "discover", side_effect=discovering(lambda: list(self.endpoints), self.discovered)),
            patch.object(cli, "identify_caller", side_effect=lambda _endpoints: self.caller),
            patch.object(cli, "ensure_worker", return_value=False),
            patch.object(cli, "worker_running", side_effect=lambda _root: self.worker_up),
            # cli 的 _worker_up 与 doctor 各读一份（§48 R7 起 doctor 在自己的模块里 import）
            patch.object(doctor, "worker_running", side_effect=lambda _root: self.worker_up),
            patch.object(cli, "_receiver_class", return_value="bypass"),
        ]
        for item in patches:
            item.start()
            self.addCleanup(item.stop)
        self.addCleanup(self._tmp.cleanup)

    def run_cli(self, *argv: str) -> tuple[int, str, str]:
        out, err = StringIO(), StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            code = cli.main(list(argv))
        return code, out.getvalue(), err.getvalue()

    def send(self, *extra: str) -> str:
        code, out, err = self.run_cli("send", "--to", "codex@impl", "-m", "实现 X\n细节", "--no-wait", "--json", *extra)
        self.assertEqual(code, cli.EXIT_OK, err)
        return json.loads(out)["id"]

    def store(self) -> Store:
        return Store.open(self.state)

    def mark_sent(self, task_id: str, delivery: Delivery = Delivery.QUEUED) -> None:
        with self.store() as store:
            attempt = store.attempts(task_id)[-1]
            store.begin_send(attempt.id, now=1.0, pid=1, start_ticks="1")
            store.finish_send(attempt.id, delivery=delivery, reason="test", provider_ref=None, detail={}, now=2.0)

    def test_peers_json_lists_the_threads_a_codex_process_holds(self) -> None:
        """诊断用：多 thread 的 Codex 进程在 peers --json 里列出持有集合（DESIGN §45.48 R1，Codex 实现复核 C02）。"""
        root, child = "019a0000-aaaa-7aaa-8aaa-aaaaaaaaaaaa", "019a0000-cccc-7ccc-8ccc-cccccccccccc"
        holder = Endpoint(ref=ref(Provider.CODEX, root, pid=5000, pane="%8", label="holder"),
                          issues=("subagent_threads",), threads=(root, child), thread_consumers=((root, 1), (child, 1)))
        self.endpoints = [IMPL, holder]
        code, out, err = self.run_cli("peers", "--json")
        self.assertEqual(code, cli.EXIT_OK, err)
        rows = {row["nativeId"]: row for row in json.loads(out)["peers"]}
        self.assertEqual(rows[root]["threads"], [root, child])
        self.assertEqual(rows[root]["issues"], ["subagent_threads"])
        self.assertEqual(rows["impl-thread"]["threads"], [])

    def test_peers_and_doctor_show_the_local_device(self) -> None:
        """设备名要有人看得见：peers 每行一列、doctor 一行（DESIGN §45.35）。"""
        with patch.object(cli, "device_name", return_value="test-box"), patch.object(doctor, "device_name", return_value="test-box"):
            code, out, err = self.run_cli("peers", "--json")
            self.assertEqual(code, cli.EXIT_OK, err)
            rows = json.loads(out)["peers"]
            # 今天发现到的端点全在本机，所以每行都是同一个值；这一列是给以后跨设备留的显示位
            self.assertEqual({row["device"] for row in rows}, {"test-box"})
            code, out, err = self.run_cli("doctor", "--json")
            self.assertEqual(code, cli.EXIT_OK, err)
            self.assertEqual(json.loads(out)["device"], "test-box")
        code, out, _err = self.run_cli("doctor")
        self.assertIn("本机设备名", out)

    def test_doctor_shows_the_loaded_package_path(self) -> None:
        """doctor 的 JSON 多一个键、文字多一行「包路径」（DESIGN §48 R9）。"""
        code, out, err = self.run_cli("doctor", "--json")
        self.assertEqual(code, cli.EXIT_OK, err)
        value = json.loads(out)["packagePath"]
        self.assertTrue(value.startswith(("/", "~")), value)
        self.assertTrue(value.endswith("/agentstatus_bridge"), value)
        code, out, _err = self.run_cli("doctor")
        self.assertIn(f"包路径：{value}\n", out)

    def test_doctor_counts_a_readable_observer_with_zero_sessions_as_readable(self) -> None:
        """「忙闲状态可读」只看 observer 能不能读，零可见会话也算可读（DESIGN §59）。

        换回真实的 `agentstatus_runtime`，在最底层的 `_observer_rows` 上给三种回复。
        """
        row: dict[str, object] = {"key": "claude:abc", "paneId": "%5", "freshness": "fresh", "runtimeState": "ready"}
        cases: list[tuple[list[dict[str, object]] | None, bool]] = [([], True), ([row], True), (None, False)]
        for reply, expected in cases:
            with self.subTest(reply=reply), \
                    patch.object(doctor, "agentstatus_runtime", observer_dbus.agentstatus_runtime), \
                    patch.object(observer_dbus, "_observer_rows", return_value=reply):
                code, out, err = self.run_cli("doctor", "--json")
                self.assertEqual(code, cli.EXIT_OK, err)
                self.assertIs(json.loads(out)["agentstatusRuntimeAvailable"], expected)

    def test_peers_works_when_the_observer_cannot_be_read(self) -> None:
        """observer 不在线（读不到）是最常见的情形：`ab peers` 照常退出 0（Opus P3-5）。"""
        with patch.object(observer_dbus, "_observer_rows", return_value=None):
            try:
                code, _out, err = self.run_cli("peers")
            except TypeError as error:
                self.fail(f"observer 读不到时 ab peers 抛出 {error!r}")
        self.assertEqual(code, cli.EXIT_OK, err)
        self.assertNotIn("Traceback", err)

    def test_peers_survives_observer_rows_whose_enums_are_not_strings(self) -> None:
        """observer 行的 `freshness`、`runtimeState` 是数组或对象时，`ab peers` 不打出堆栈（DESIGN §59）。"""
        self.rows = [
            {"key": "claude:aaa", "paneId": "%1", "freshness": [], "runtimeState": "ready"},
            {"key": "codex:bbb", "paneId": "%2", "freshness": "fresh", "runtimeState": {}},
        ]
        try:
            code, _out, err = self.run_cli("peers")
        except TypeError as error:  # 让缺陷以 FAIL 出现，而不是 ERROR
            self.fail(f"ab peers 抛出 {error!r}")
        self.assertEqual(code, cli.EXIT_OK, err)
        self.assertNotIn("Traceback", err)
        self.assertGreater(self.observer_reads, 0)  # 前提：这些行真的被读过

    def test_read_only_target_is_refused_at_every_entry(self) -> None:
        self.endpoints = [IMPL, REVIEW, LEAD, endpoint(GROK.ref, issues=("no_inbox",))]
        task_id = self.send()
        self.mark_sent(task_id, Delivery.FAILED)
        cases = [
            ("send", "--to", GROK.ref.native_id, "-m", "x", "--no-wait"),
            ("send", "--to", "grok@grok", "-m", "x", "--no-wait"),
            ("send", "--to", "codex@impl", "--review-by", "grok@grok", "-m", "x", "--no-wait"),
            ("retry", task_id[:8], "--to", "grok@grok", "-m", "x"),
        ]
        for argv in cases:
            with self.subTest(command=argv[0] + ("+review" if "--review-by" in argv else "")):
                code, _out, err = self.run_cli(*argv)
                self.assertEqual(code, cli.EXIT_REJECTED, err)
                self.assertIn("target_no_inbox", err)
                self.assertIn("没有收件通道", err)
        # 只读端点照常出现在 peers 里，并标明原因
        code, out, _err = self.run_cli("peers")
        self.assertEqual(code, cli.EXIT_OK)
        self.assertIn("只读", out)

    def test_ambiguous_read_only_candidates_report_the_real_reason(self) -> None:
        # 同一进程 resume 出两个会话：pane 与 provider@会话名都命中两行，但换哪个候选都投不进去
        second = endpoint(
            ref(Provider.GROK, "019a0000-dddd-7ddd-8ddd-dddddddddddd", pid=4000, pane="%9", label="grok"),
            issues=("no_inbox", "shared_process"),
        )
        self.endpoints = [IMPL, REVIEW, LEAD, endpoint(GROK.ref, issues=("no_inbox", "shared_process")), second]
        for selector in ("grok@grok", "%9"):
            with self.subTest(selector=selector):
                code, _out, err = self.run_cli("send", "--to", selector, "-m", "x", "--no-wait")
                self.assertEqual(code, cli.EXIT_REJECTED, err)
                self.assertIn("target_no_inbox", err)
                self.assertNotIn("可选目标", err)
        # 候选里混有能收件的会话时（同一 pane 里既有 Grok 又有 Codex），仍然是「目标不唯一」，让用户去选
        self.endpoints = [
            IMPL,
            endpoint(GROK.ref, issues=("no_inbox",)),
            endpoint(ref(Provider.CODEX, "other-thread", pid=1001, pane="%9", label="other")),
        ]
        code, _out, err = self.run_cli("send", "--to", "%9", "-m", "x", "--no-wait")
        self.assertEqual(code, cli.EXIT_TARGET, err)
        self.assertIn("target_ambiguous", err)

    def test_send_from_terminal_creates_queued_task(self) -> None:
        task_id = self.send()
        code, out, _ = self.run_cli("status", task_id[:8], "--json")
        self.assertEqual(code, 0)
        document = json.loads(out)
        self.assertEqual((document["phase"], document["title"], document["origin"]), ("queued", "实现 X", None))
        self.assertEqual(document["attempts"][0]["senderClass"], "bypass")
        self.assertNotIn("body", document["attempts"][0])
        code, out, _ = self.run_cli("status", task_id[:8], "--body", "--json")
        self.assertEqual(json.loads(out)["attempts"][0]["body"], "实现 X\n细节")

    def test_no_wait_send_to_idle_target_explains_background_sending(self) -> None:
        code, out, _ = self.run_cli("send", "--to", "codex@impl", "-m", "x", "--no-wait")
        self.assertEqual(code, cli.EXIT_OK)
        self.assertIn("后台 worker 正在发送", out)

    def test_send_rejects_the_daemon_title_codes(self) -> None:
        # Codex 托管 daemon 下按标题认领失败的四个码都阻断投递（DESIGN §53.3.8）
        for issue in ("title_thread_missing", "title_thread_unmatched", "title_shows_subagent", "pane_process_ambiguous"):
            with self.subTest(issue=issue):
                self.endpoints = [endpoint(IMPL.ref, issues=(issue,))]
                code, _, err = self.run_cli("send", "--to", "%1", "-m", "x", "--no-wait")
                self.assertEqual((code, f"target_{issue}" in err), (cli.EXIT_REJECTED, True))
                self.assertNotIn("{command}", err)

    def test_a_daemon_caller_cannot_send_to_the_window_showing_its_own_thread(self) -> None:
        # daemon 调用者端点（pid 是 daemon、没有 pane）与显示同一 thread 的窗口是同一会话（DESIGN §53.4.3）
        daemon_ref = EndpointRef(Provider.CODEX, IMPL.ref.native_id, pid=900, start_ticks="100", pane=None)
        self.caller = Caller(Endpoint(ref=daemon_ref), ProcessInfo(900, 1000, "codex", "100"), "daemon")
        code, _, err = self.run_cli("send", "--to", "%1", "-m", "x", "--no-wait")
        self.assertEqual((code, "target_is_self" in err), (cli.EXIT_REJECTED, True))
        # 发给别的窗口可以：发起方就是这个没有 pane 的端点
        code, _, err = self.run_cli("send", "--to", "%2", "-m", "x", "--no-wait")
        self.assertEqual(code, cli.EXIT_OK, err)
        with Store.open(self.state) as store:
            [task] = store.list_tasks()
        assert task.origin is not None
        self.assertEqual((task.origin.pid, task.origin.pane), (900, None))
        self.assertEqual(task.origin.display(), f"codex@{IMPL.ref.native_id[:8]}")

    def test_send_exit_codes(self) -> None:
        code, _, err = self.run_cli("send", "--to", "nope", "-m", "x", "--no-wait")
        self.assertEqual((code, "target_not_found" in err), (cli.EXIT_TARGET, True))
        self.caller = as_agent(IMPL)
        code, _, err = self.run_cli("send", "--to", "%1", "-m", "x", "--no-wait")
        self.assertEqual((code, "target_is_self" in err), (cli.EXIT_REJECTED, True))
        self.caller = USER
        self.endpoints = [endpoint(IMPL.ref, issues=("no_thread_yet",))]
        code, _, err = self.run_cli("send", "--to", "%1", "-m", "x", "--no-wait")
        self.assertEqual((code, "target_no_thread_yet" in err), (cli.EXIT_REJECTED, True))
        # 对方忙不再影响投递（§45.42）：排队与否只取决于 worker 在不在
        self.endpoints = [endpoint(IMPL.ref, runtime=Runtime.BUSY)]
        self.worker_up = False
        code, out, _ = self.run_cli("send", "--to", "%1", "-m", "x", "--no-wait")
        self.assertEqual(code, cli.EXIT_UNAVAILABLE)
        self.assertIn("后台 worker 未运行", out)
        self.assertNotIn("对方忙", out)

    def test_agent_origin_is_recorded(self) -> None:
        self.caller = as_agent(LEAD)
        task_id = self.send("--review-by", "claude@review")
        with self.store() as store:
            task = store.get_task(task_id)
        assert task is not None
        self.assertTrue(task.origin is not None and task.origin.same_session(LEAD.ref))
        self.assertTrue(task.reviewer is not None and task.reviewer.same_session(REVIEW.ref))

    def test_retry_needs_force_when_delivery_is_unknown(self) -> None:
        task_id = self.send()
        code, _, err = self.run_cli("retry", task_id)
        self.assertEqual((code, "still_pending" in err), (cli.EXIT_REJECTED, True))
        self.mark_sent(task_id, Delivery.UNKNOWN)
        code, _, err = self.run_cli("retry", task_id)
        self.assertEqual((code, "retry_requires_force" in err), (cli.EXIT_REJECTED, True))
        code, out, _ = self.run_cli("retry", task_id, "--force")
        self.assertEqual(code, 0)
        self.assertIn("可能重复执行", out)
        with self.store() as store:
            attempts = store.attempts(task_id)
        self.assertEqual([(item.seq, item.delivery) for item in attempts], [(1, Delivery.UNKNOWN), (2, Delivery.PENDING)])

    def test_retry_cancels_a_result_notice_that_has_not_been_sent(self) -> None:
        """返工意味着这个结果不作数：还没发出的结果回执随之作废（DESIGN §45.42）。

        不作废的话它会在新一轮派出之后才送达发起方——实测发生过 2 例。
        """
        self.caller = as_agent(LEAD)  # 有发起方才会产生结果回执
        task_id = self.send()
        self.mark_sent(task_id)
        self.caller = as_agent(IMPL)
        self.assertEqual(self.run_cli("report", task_id, "--result", "--note", "完成")[0], 0)
        self.caller = as_agent(LEAD)
        with self.store() as store:
            notice = [item for item in store.attempts(task_id) if item.role is Role.NOTICE][-1]
        self.assertEqual(notice.delivery, Delivery.PENDING)
        code, _out, err = self.run_cli("retry", task_id, "--message", "还差测试")
        self.assertEqual(code, 0, err)
        with self.store() as store:
            stale = store.get_attempt(notice.id)
            latest = store.attempts(task_id)[-1]
        assert stale is not None
        self.assertEqual((stale.delivery, stale.delivery_reason), (Delivery.CANCELLED, "notice_outdated"))
        # 新一轮照常排队；已送达的回执不会被追回（这里只有未发出的那条被作废）
        self.assertEqual((latest.role, latest.delivery), (Role.HANDOFF, Delivery.PENDING))

    def test_delivery_detail_projection_omits_whole_values_and_flags_it(self) -> None:
        """不合规的键值整体省略并打标记，不截断、不放占位串（DESIGN §45.43 2.3，Codex 复核 R02）。

        截断后的 64 个 `a` 与真实的 64 个 `a` 无从分辨；占位串 `"<omitted>"` 本身也是合法字符串。
        所以合规值原样展示（包括恰好 64 字符、包括字面量 `"<omitted>"`），不合规的只能靠标记告诉读方。
        """
        ok = {"priority": "later", "senderPid": 12, "receipt": None, "flag": True,
              "exact": "a" * 64, "literal": "<omitted>"}
        self.assertEqual(views.project_delivery_detail(ok), (ok, False))
        for bad in ({"long": "a" * 65}, {"nested": {"text": "x"}}, {"items": [1]}, {"ratio": 0.5},
                    {"bad key": "x"}, {"9lead": "x"}, {"k" * 33: "x"}):
            with self.subTest(bad=bad):
                shown, redacted = views.project_delivery_detail({"priority": "next", **bad})
                self.assertEqual(shown, {"priority": "next"})
                self.assertTrue(redacted)
        # 坏项在前、合法项在后：省略标记不能被后面的合法项复位（Codex 实现复核 C01）
        self.assertEqual(views.project_delivery_detail({"bad key": "x", "priority": "later"}), ({"priority": "later"}, True))
        self.assertEqual(views.project_delivery_detail({"priority\n": "later", "good": None}), ({"good": None}, True))

    def test_json_views_carry_the_delivery_detail_diagnostic(self) -> None:
        """五个带 --json 的命令共用 `_task_document`，都要带上投递明细与省略标记（DESIGN §45.43 2.1）。"""
        self.caller = as_agent(LEAD)
        code, out, err = self.run_cli("send", "--to", "codex@impl", "-m", "实现 X", "--no-wait", "--json")
        self.assertEqual(code, cli.EXIT_OK, err)
        views = {"send": json.loads(out)}
        task_id = views["send"]["id"]
        self.mark_sent(task_id)
        views["status"] = json.loads(self.run_cli("status", task_id, "--json")[1])
        views["tasks"] = json.loads(self.run_cli("tasks", "--json")[1])["tasks"][0]
        views["wait"] = json.loads(self.run_cli("wait", task_id, "--until", "sent", "--timeout", "0", "--json")[1])
        self.caller = as_agent(IMPL)
        views["report"] = json.loads(self.run_cli("report", task_id, "--ack", "--json")[1])
        for name, document in views.items():
            with self.subTest(command=name):
                self.assertTrue(document["attempts"])
                for attempt in document["attempts"]:
                    self.assertIsInstance(attempt["deliveryDetail"], dict)
                    self.assertIs(attempt["deliveryDetailRedacted"], False)
        # 还没发出时明细是空对象；发出后 begin_send 记下的发送方进程出现在里面
        self.assertEqual(views["send"]["attempts"][0]["deliveryDetail"], {})
        self.assertEqual(views["status"]["attempts"][0]["deliveryDetail"], {"senderPid": 1, "senderStart": "1"})

    def record_attempts(self, rows: Sequence[tuple[float, EndpointRef, Mapping[str, object]]]) -> None:
        """经 store 落若干条已发出的尝试，created_at 与 delivery_detail 可控（每个任务最多 60 条，受单任务上限约束）。"""
        with self.store() as store:
            task_id: str | None = None
            count = 0
            for created, target, detail in rows:
                if task_id is None or count >= 60:
                    task, attempt = store.create_task(
                        title="证据", flow=Flow.HANDOFF, origin=None, origin_class=None, reviewer=None,
                        target=target, body="x", refs=[], now=created,
                    )
                    task_id, count = task.id, 1
                else:
                    attempt = store.add_attempt(
                        task_id, role=Role.HANDOFF, target=target, body="x", refs=[], now=created,
                        sender=None, sender_class=None,
                    )
                    count += 1
                store.begin_send(attempt.id, now=created, pid=1, start_ticks="1")
                store.finish_send(
                    attempt.id, delivery=Delivery.QUEUED, reason="codex_queued", provider_ref=None, detail=dict(detail), now=created
                )

    def doctor(self, version: str | None = "0.156.0") -> tuple[dict[str, object], str]:
        with patch.object(doctor, "cli_version", return_value=version):
            code, out, err = self.run_cli("doctor", "--json")
            self.assertEqual(code, cli.EXIT_OK, err)
            text_code, text, text_err = self.run_cli("doctor")
            self.assertEqual(text_code, cli.EXIT_OK, text_err)
        document = json.loads(out)
        self.assertNotIn("codexVersionVerified", document)
        evidence = document["codexQueueEvidence"]
        assert isinstance(evidence, dict)
        line = next(item for item in text.splitlines() if item.startswith("Codex CLI 输出证据"))
        return evidence, line

    SAMPLE = {"codexVersion": "0.156.0", "queueOutput": "recognized"}

    def test_doctor_codex_evidence_texts(self) -> None:
        """四种文字各一例（DESIGN §45.44 二.6）；写死版本前缀的 codexVersionVerified 已删。"""
        evidence, line = self.doctor(None)
        self.assertEqual((evidence["state"], line), ("version_unavailable", "Codex CLI 输出证据：当前 codex 版本不可用，无法关联样本"))
        evidence, line = self.doctor()
        self.assertEqual(evidence["state"], "no_samples")
        self.assertIn("0.156.0 在本次查询窗口内没有可用样本（旧记录可能未记这两个字段）", line)
        self.record_attempts([(1.0, IMPL.ref, dict(self.SAMPLE)), (2.0, IMPL.ref, {"codexVersion": "unknown", "queueOutput": "recognized"})])
        evidence, line = self.doctor()
        self.assertEqual((evidence["recognized"], evidence["unrecognized"], evidence["unknownVersion"]), (1, 0, 1))
        self.assertIn("（最近最多 200 条 Codex 尝试）：0.156.0 命中已知分支 1 次，未识别 0 次", line)
        self.assertIn("此统计不代表投递成功、执行完成或所有错误分支都已验证", line)
        self.assertIn("另有 1 次未能确定执行投递的版本", line)
        with patch.object(Store, "recent_codex_details", side_effect=sqlite3.OperationalError("synthetic")):
            evidence, line = self.doctor()
        # 读失败不能显示成零样本
        self.assertEqual((evidence["state"], line), ("ledger_unreadable", "Codex CLI 输出证据：账本读取失败，无法统计"))

    def test_doctor_window_follows_creation_time_not_insertion_order(self) -> None:
        # 先插入、但创建时间最新的那条仍在窗口里：排序按 created_at，不按 rowid
        self.record_attempts([(10_000.0, IMPL.ref, dict(self.SAMPLE))] + [(float(i), IMPL.ref, {}) for i in range(1, 201)])
        evidence, _ = self.doctor()
        self.assertEqual((evidence["state"], evidence["recognized"]), ("ok", 1))

    def test_doctor_sample_older_than_the_window_is_reported_as_no_samples(self) -> None:
        # 第 201 条（最旧）有样本、最近 200 条没有：说「窗口内无可用样本」，不说「没有投递」
        self.record_attempts([(1000.0 + i, IMPL.ref, {}) for i in range(200)] + [(1.0, IMPL.ref, dict(self.SAMPLE))])
        evidence, line = self.doctor()
        self.assertEqual(evidence["state"], "no_samples")
        self.assertIn("在本次查询窗口内没有可用样本", line)

    def test_doctor_window_only_counts_codex_targets(self) -> None:
        # 200 条更新的 Claude 尝试即使带着同名键也不占窗口、不计数
        self.record_attempts([(1.0, IMPL.ref, dict(self.SAMPLE))] + [(float(i), REVIEW.ref, dict(self.SAMPLE)) for i in range(2, 202)])
        evidence, _ = self.doctor()
        self.assertEqual((evidence["recognized"], evidence["unrecognized"]), (1, 0))

    def test_doctor_after_an_upgrade_says_the_samples_belong_to_another_version(self) -> None:
        """自动升级后的常态：窗口里全是旧版本样本，不能说成「旧记录可能未记字段」了事（Fable 实现复核 P3-1）。"""
        self.record_attempts([(1.0, IMPL.ref, dict(self.SAMPLE)), (2.0, IMPL.ref, dict(self.SAMPLE))])
        evidence, line = self.doctor("0.157.0")
        self.assertEqual((evidence["state"], evidence["otherVersion"]), ("no_samples", 2))
        self.assertIn("另有 2 次记于其他版本（多半是升级前的投递）", line)
        # 只有「版本未能确定」的样本时，无样本那句后面也要带上这一条
        self.record_attempts([(3.0, IMPL.ref, {"codexVersion": "unknown", "queueOutput": "recognized"})])
        _, line = self.doctor("0.157.0")
        self.assertIn("另有 1 次未能确定执行投递的版本", line)

    def test_doctor_window_breaks_creation_ties_by_id_descending(self) -> None:
        self.record_attempts([(123.0, IMPL.ref, dict(self.SAMPLE)), (123.0, IMPL.ref, {})])
        with self.store() as store:
            newest = store._conn.execute(  # pyright: ignore[reportPrivateUsage]
                "SELECT delivery_detail FROM attempts ORDER BY id DESC LIMIT 1"
            ).fetchone()
            self.assertEqual(store.recent_codex_details(limit=1), [json.loads(newest["delivery_detail"])])

    def test_doctor_window_never_reads_message_bodies_or_results(self) -> None:
        # 只投影必要列：用 SQLite authorizer 直接禁读正文与结果列，SELECT * 会在这里报错（Codex 实现复核 C01）
        self.record_attempts([(123.0, IMPL.ref, dict(self.SAMPLE))])

        def authorize(action: int, table: str | None, column: str | None, *_: object) -> int:
            if action == sqlite3.SQLITE_READ and table == "attempts" and column in ("body", "result"):
                return sqlite3.SQLITE_DENY
            return sqlite3.SQLITE_OK

        with self.store() as store:
            store._conn.set_authorizer(authorize)  # pyright: ignore[reportPrivateUsage]
            [detail] = store.recent_codex_details(limit=200)
        self.assertEqual({key: detail[key] for key in self.SAMPLE}, self.SAMPLE)

    def test_doctor_does_not_call_an_unrecognized_but_acknowledged_attempt_undelivered(self) -> None:
        """Codex 用临时账本走过：finish_send(UNKNOWN, unrecognized) 后再 ACK，结局是 DELIVERED、detail 仍在。"""
        task_id = self.send()
        with self.store() as store:
            attempt = store.attempts(task_id)[-1]
            store.begin_send(attempt.id, now=1.0, pid=1, start_ticks="1")
            store.finish_send(attempt.id, delivery=Delivery.UNKNOWN, reason="codex_queue_unparsed_output", provider_ref=None,
                              detail={"codexVersion": "0.156.0", "queueOutput": "unrecognized"}, now=2.0)
        self.caller = as_agent(IMPL)
        code, _out, err = self.run_cli("report", task_id, "--ack", "--json")
        self.assertEqual(code, cli.EXIT_OK, err)
        status = json.loads(self.run_cli("status", task_id, "--json")[1])["attempts"][0]
        self.assertEqual((status["delivery"], status["deliveryDetail"]["queueOutput"]), ("delivered", "unrecognized"))
        evidence, line = self.doctor()
        self.assertEqual(evidence["unrecognized"], 1)
        self.assertIn(f"以 `{CMD} status` 为准，可能已由接收方汇报确证", line)
        self.assertNotIn("是否送达不明", line)

    def test_retry_is_atomic_when_the_new_attempt_cannot_be_written(self) -> None:
        """作废旧通知与追加返工必须同进同退（Codex 复审 F01）。

        分多次提交时，提交间隙里另一连接可能汇报出新一轮结果或排了结束回执，随后的全量扫描
        会把它们一起作废；追加失败而作废已提交，还会留下「旧通知没了、返工没落账」的半完成命令。
        """
        self.caller = as_agent(LEAD)
        task_id = self.send()
        self.mark_sent(task_id)
        self.caller = as_agent(IMPL)
        self.assertEqual(self.run_cli("report", task_id, "--result", "--note", "完成")[0], 0)
        self.caller = as_agent(LEAD)
        with self.store() as store:
            notice = [item for item in store.attempts(task_id) if item.role is Role.NOTICE][-1]
            before = len(store.attempts(task_id))
        with patch.object(Store, "add_attempt", side_effect=StoreError("store_busy")):
            code, _out, _err = self.run_cli("retry", task_id, "--message", "还差测试")
        self.assertEqual(code, cli.EXIT_STORE)
        with self.store() as store:
            rolled_back = store.get_attempt(notice.id)
            after = store.attempts(task_id)
        assert rolled_back is not None
        self.assertEqual(rolled_back.delivery, Delivery.PENDING, "追加失败时旧通知不能已经被作废")
        self.assertEqual(len(after), before, "失败的返工不得留下半条记录")

    def test_failed_delivery_can_be_redirected_without_force(self) -> None:
        task_id = self.send()
        self.mark_sent(task_id, Delivery.FAILED)
        code, _, err = self.run_cli("retry", task_id, "--to", "codex@lead")
        self.assertEqual(code, 0, err)
        with self.store() as store:
            latest = store.attempts(task_id)[-1]
        self.assertTrue(latest.target.same_session(LEAD.ref))
        self.assertEqual(latest.body, "实现 X\n细节")

    def test_acceptance_rules(self) -> None:
        self.caller = as_agent(LEAD)
        task_id = self.send()
        self.mark_sent(task_id)
        self.caller = as_agent(IMPL)
        code, _, err = self.run_cli("accept", task_id, "--force")
        self.assertEqual((code, "accept_not_allowed" in err), (cli.EXIT_REJECTED, True))
        self.caller = USER
        code, _, err = self.run_cli("accept", task_id)
        self.assertEqual((code, "no_result_to_accept" in err), (cli.EXIT_REJECTED, True))
        self.caller = as_agent(IMPL)
        code, out, err = self.run_cli("report", task_id, "--result", "--note", "完成")
        self.assertEqual(code, 0, err)
        self.assertIn("已排队通知发起方", out)
        self.caller = as_agent(LEAD)
        code, _, err = self.run_cli("accept", task_id)
        self.assertEqual(code, 0, err)
        code, out, _ = self.run_cli("status", task_id, "--json")
        self.assertEqual(json.loads(out)["phase"], "done")

    def test_review_changes_go_back_to_implementer(self) -> None:
        task_id = self.send("--review-by", "claude@review")
        self.mark_sent(task_id)
        self.caller = as_agent(IMPL)
        self.assertEqual(self.run_cli("report", task_id, "--result", "--note", "v1")[0], 0)
        self.mark_sent(task_id, Delivery.DELIVERED)
        self.caller = as_agent(REVIEW)
        self.assertEqual(self.run_cli("report", task_id, "--changes", "--note", "缺测试")[0], 0)
        code, _, _ = self.run_cli("wait", task_id, "--timeout", "0")
        self.assertEqual(code, cli.EXIT_FAILURE_REPORTED)
        self.caller = USER
        code, _, err = self.run_cli("retry", task_id)
        self.assertEqual(code, 0, err)
        with self.store() as store:
            task = store.get_task(task_id)
            latest = store.attempts(task_id)[-1]
        assert task is not None
        self.assertIsNone(task.verdict)
        self.assertEqual((latest.role, latest.work), (Role.HANDOFF, Work.AWAITING_ACK))
        self.assertTrue(latest.target.same_session(IMPL.ref))
        self.assertIn("缺测试", latest.body)
        self.assertIn("实现 X", latest.body)
        self.assertNotEqual(task.verdict, Verdict.CHANGES)

    def test_cancel_wait_and_close(self) -> None:
        task_id = self.send()
        code, _, _ = self.run_cli("wait", task_id, "--timeout", "0")
        self.assertEqual(code, cli.EXIT_TIMEOUT)
        self.assertEqual(self.run_cli("cancel", task_id)[0], 0)
        code, _, err = self.run_cli("cancel", task_id)
        self.assertEqual((code, "nothing_to_cancel" in err), (cli.EXIT_REJECTED, True))
        second = self.send()
        self.mark_sent(second)
        code, out, _ = self.run_cli("close", second)
        self.assertEqual(code, 0)
        self.assertIn("停止追踪不撤回", out)
        with self.store() as store:
            self.assertEqual(store.archived_risk_count(), 1)
        code, out, _ = self.run_cli("tasks", "--json")
        self.assertEqual([item["id"] for item in json.loads(out)["tasks"]], [task_id])

    def test_wait_returns_unknown_delivery_immediately(self) -> None:
        task_id = self.send()
        self.mark_sent(task_id, Delivery.UNKNOWN)
        started = time.monotonic()
        code, out, _ = self.run_cli("wait", task_id, "--timeout", "30")
        self.assertEqual(code, cli.EXIT_UNKNOWN)
        self.assertLess(time.monotonic() - started, 5.0)
        self.assertIn("retry", out)

    def test_wait_until_ack_stops_on_blocked_report(self) -> None:
        task_id = self.send()
        self.mark_sent(task_id)
        self.caller = as_agent(IMPL)
        self.assertEqual(self.run_cli("report", task_id, "--blocked", "--note", "缺权限")[0], 0)
        code, _, _ = self.run_cli("wait", task_id, "--until", "ack", "--timeout", "0")
        self.assertEqual(code, cli.EXIT_FAILURE_REPORTED)

    def test_forced_acceptance_cancels_queued_messages(self) -> None:
        task_id = self.send()
        code, _, err = self.run_cli("accept", task_id, "--force")
        self.assertEqual(code, 0, err)
        with self.store() as store:
            self.assertEqual([item.delivery for item in store.attempts(task_id)], [Delivery.CANCELLED])

    def test_shared_thread_opt_in_is_required_and_kept_for_retry(self) -> None:
        self.endpoints = [endpoint(IMPL.ref, issues=("shared_thread",)), REVIEW, LEAD]
        code, _, err = self.run_cli("send", "--to", "%1", "-m", "x", "--no-wait")
        self.assertEqual((code, "target_shared_thread" in err), (cli.EXIT_REJECTED, True))
        task_id = self.send("--allow-shared")
        self.mark_sent(task_id, Delivery.FAILED)
        code, _, err = self.run_cli("retry", task_id)
        self.assertEqual(code, 0, err)
        with self.store() as store:
            self.assertTrue(store.attempts(task_id)[-1].allow_shared)

    def test_no_notify_skips_origin_notice(self) -> None:
        self.caller = as_agent(LEAD)
        task_id = self.send("--no-notify")
        self.mark_sent(task_id)
        self.caller = as_agent(IMPL)
        code, out, err = self.run_cli("report", task_id, "--result", "--note", "完成")
        self.assertEqual(code, 0, err)
        self.assertNotIn("通知发起方", out)
        with self.store() as store:
            self.assertEqual(len(store.attempts(task_id)), 1)

    def test_status_revives_missing_worker_for_queued_messages(self) -> None:
        task_id = self.send()
        self.worker_up = False
        cli.ensure_worker.reset_mock()  # type: ignore[attr-defined]
        self.assertEqual(self.run_cli("status", task_id)[0], 0)
        cli.ensure_worker.assert_called_once()  # type: ignore[attr-defined]

    def test_commands_and_if_stale_summary_revive_worker_for_a_pending_origin_reminder(self) -> None:
        self.caller = as_agent(LEAD)
        task_id = self.send()
        self.mark_sent(task_id)
        self.caller = as_agent(IMPL)
        self.assertEqual(self.run_cli("report", task_id, "--result", "--note", "完成")[0], 0)
        self.mark_sent(task_id)  # 回执已交到发起方：此时只剩「等提醒到期」这一件待办
        self.caller = USER
        self.worker_up = False
        cli.ensure_worker.reset_mock()  # type: ignore[attr-defined]
        # 扩展定时 summary --if-stale 也能恢复：worker 环境会补上 ~/.local/bin（DESIGN §45.30，取代 §45.28.3 的「summary 不拉起」）
        self.assertEqual(self.run_cli("summary", "--if-stale")[0], 0)
        cli.ensure_worker.assert_called_once()  # type: ignore[attr-defined]
        cli.ensure_worker.reset_mock()  # type: ignore[attr-defined]
        self.assertEqual(self.run_cli("tasks")[0], 0)
        cli.ensure_worker.assert_called_once()  # type: ignore[attr-defined]
        self.assertEqual(self.run_cli("accept", task_id)[0], 0)
        # 验收给执行方排了结束回执（DESIGN §45.31），它发出之前仍需要 worker
        cli.ensure_worker.reset_mock()  # type: ignore[attr-defined]
        self.assertEqual(self.run_cli("summary", "--if-stale")[0], 0)
        cli.ensure_worker.assert_called_once()  # type: ignore[attr-defined]
        self.mark_sent(task_id)
        cli.ensure_worker.reset_mock()  # type: ignore[attr-defined]
        self.assertEqual(self.run_cli("tasks")[0], 0)
        self.assertEqual(self.run_cli("summary", "--if-stale")[0], 0)
        cli.ensure_worker.assert_not_called()  # type: ignore[attr-defined]

    def summary_json(self, *extra: str) -> tuple[int, dict[str, object], str]:
        code, out, err = self.run_cli("summary", *extra, "--json")
        return code, json.loads(out) if out else {}, err

    def test_only_if_stale_summary_revives_and_only_when_needed(self) -> None:
        # 还没有账本：if-stale 仍报 ledger_absent（退出码 6、未落账），不拉起、不建账本
        code, _out, err = self.run_cli("summary", "--if-stale")
        self.assertEqual(code, cli.EXIT_UNAVAILABLE)
        self.assertIn("ledger_absent", err)
        self.assertFalse((self.state / "bridge.sqlite3").exists())
        cli.ensure_worker.assert_not_called()  # type: ignore[attr-defined]
        self.send()  # 用户发起、排队待发：需要 worker
        self.worker_up = False
        # 普通 summary 与只带 --refresh 的手动重建不新增拉起
        for extra in ((), ("--refresh",)):
            with self.subTest(extra=extra):
                cli.ensure_worker.reset_mock()  # type: ignore[attr-defined]
                code, document, err = self.summary_json(*extra)
                self.assertEqual((code, err), (cli.EXIT_OK, ""))
                self.assertEqual(document["state"], "ok")
                cli.ensure_worker.assert_not_called()  # type: ignore[attr-defined]
        # if-stale 的「未变化」分支：按需拉起一次，JSON 与退出码不变
        cli.ensure_worker.reset_mock()  # type: ignore[attr-defined]
        code, document, err = self.summary_json("--if-stale")
        self.assertEqual((code, document["published"], err), (cli.EXIT_OK, "fresh", ""))
        cli.ensure_worker.assert_called_once()  # type: ignore[attr-defined]
        # 「重写」分支：账本有变化而摘要未发布
        (self.state / "summary.json").unlink()
        cli.ensure_worker.reset_mock()  # type: ignore[attr-defined]
        code, document, err = self.summary_json("--if-stale")
        self.assertEqual((code, document["published"], err), (cli.EXIT_OK, "written", ""))
        cli.ensure_worker.assert_called_once()  # type: ignore[attr-defined]
        # worker 已在运行：不新增进程
        self.worker_up = True
        cli.ensure_worker.reset_mock()  # type: ignore[attr-defined]
        self.assertEqual(self.summary_json("--if-stale")[0], cli.EXIT_OK)
        cli.ensure_worker.assert_not_called()  # type: ignore[attr-defined]
        self.worker_up = False
        # 没有后台需求：不拉起
        with patch.object(cli, "needs_worker", return_value=False):
            cli.ensure_worker.reset_mock()  # type: ignore[attr-defined]
            self.assertEqual(self.summary_json("--if-stale")[0], cli.EXIT_OK)
            cli.ensure_worker.assert_not_called()  # type: ignore[attr-defined]

    def test_if_stale_revive_errors_never_change_summary_output_or_exit_code(self) -> None:
        self.send()
        self.worker_up = False
        expected = self.summary_json("--if-stale")[1]
        # 需求检查读账本出错：吞掉，不兜底再拉
        with patch.object(cli, "needs_worker", side_effect=sqlite3.OperationalError("disk I/O error")):
            cli.ensure_worker.reset_mock()  # type: ignore[attr-defined]
            self.assertEqual(self.summary_json("--if-stale"), (cli.EXIT_OK, expected, ""))
            cli.ensure_worker.assert_not_called()  # type: ignore[attr-defined]
        # 锁文件异常按未运行处理；拉起本身抛错：只试一次，输出不变
        for failure in (OSError("spawn"), RuntimeError("unexpected")):
            with self.subTest(failure=type(failure).__name__):
                cli.ensure_worker.reset_mock()  # type: ignore[attr-defined]
                cli.ensure_worker.side_effect = failure  # type: ignore[attr-defined]
                try:
                    self.assertEqual(self.summary_json("--if-stale"), (cli.EXIT_OK, expected, ""))
                finally:
                    cli.ensure_worker.side_effect = None  # type: ignore[attr-defined]
                cli.ensure_worker.assert_called_once()  # type: ignore[attr-defined]
        with patch.object(cli, "worker_running", side_effect=IsADirectoryError("worker.lock")):
            cli.ensure_worker.reset_mock()  # type: ignore[attr-defined]
            self.assertEqual(self.summary_json("--if-stale"), (cli.EXIT_OK, expected, ""))
            cli.ensure_worker.assert_called_once()  # type: ignore[attr-defined]
        # 摘要写入失败：既有退出码 8 不变，补查照样只试一次（新 worker 启动时会重建摘要）
        with patch.object(cli.summary, "publish", side_effect=cli.summary.SummaryError("summary_write_failed")):
            cli.ensure_worker.reset_mock()  # type: ignore[attr-defined]
            code, out, err = self.run_cli("summary", "--if-stale", "--json")
            self.assertEqual((code, out), (cli.EXIT_STORE, ""))
            self.assertIn("summary_write_failed", err)
            self.assertNotIn("Traceback", err)
            cli.ensure_worker.assert_called_once()  # type: ignore[attr-defined]

    def test_if_stale_summary_follows_every_background_need(self) -> None:
        # summary 用的是同一个 needs_worker：排队、发送中、观察窗口与待办提醒（见上）都拉起，窗口外的旧投递不拉起
        now = time.time()
        cases: list[tuple[str, Delivery | None, float, bool]] = [
            ("pending", None, now, True),
            ("sending", Delivery.SENDING, now, True),
            ("written_recent", Delivery.WRITTEN, now, True),
            ("held_recent", Delivery.HELD, now, True),
            ("queued_unconsumed", Delivery.QUEUED, now, True),
            ("written_old", Delivery.WRITTEN, now - 2 * 3600, False),
            ("queued_old", Delivery.QUEUED, now - 2 * 3600, False),
        ]
        for name, delivery, at, needed in cases:
            with self.subTest(case=name), TemporaryDirectory() as other:
                state = Path(other) / "bridge"
                with patch.dict(os.environ, {"AB_STATE_DIR": str(state)}):
                    self.worker_up = True
                    task_id = self.send()
                    self.worker_up = False
                    if delivery is not None:
                        with Store.open(state) as store:
                            attempt = store.attempts(task_id)[-1]
                            store.begin_send(attempt.id, now=at, pid=1, start_ticks="1")
                            if delivery is not Delivery.SENDING:
                                store.finish_send(
                                    attempt.id, delivery=delivery, reason="test", provider_ref=None, detail={}, now=at
                                )
                    cli.ensure_worker.reset_mock()  # type: ignore[attr-defined]
                    self.assertEqual(self.run_cli("summary", "--if-stale")[0], cli.EXIT_OK)
                    self.assertEqual(cli.ensure_worker.call_count, 1 if needed else 0)  # type: ignore[attr-defined]

    def test_command_that_already_started_worker_is_not_revived_again(self) -> None:
        # report/retry/resume 自己拉起过 worker：main 结束时不再补拉，新 worker 还没持锁时会多起一个进程（Opus 审计 F2）
        self.caller = as_agent(LEAD)
        task_id = self.send()
        self.mark_sent(task_id)
        self.worker_up = False
        self.caller = as_agent(IMPL)
        cli.ensure_worker.reset_mock()  # type: ignore[attr-defined]
        cli.ensure_worker.return_value = True  # type: ignore[attr-defined]  # 真的新拉起了进程（它还没拿到锁）
        self.assertEqual(self.run_cli("report", task_id, "--blocked", "--note", "缺权限")[0], 0)
        cli.ensure_worker.assert_called_once()  # type: ignore[attr-defined]
        self.mark_sent(task_id)
        self.caller = as_agent(LEAD)
        cli.ensure_worker.reset_mock()  # type: ignore[attr-defined]
        self.assertEqual(self.run_cli("retry", task_id)[0], 0)
        cli.ensure_worker.assert_called_once()  # type: ignore[attr-defined]
        # 结束补查失败的兜底分支也不能再拉一次（Codex 复审 S03）
        self.mark_sent(task_id)
        self.caller = as_agent(IMPL)
        real_publish = cli.summary.publish
        calls = {"n": 0}

        def failing_after_first(*args: object, **kwargs: object):
            calls["n"] += 1
            if calls["n"] >= 2:
                raise cli.summary.SummaryError("summary_write_failed")
            return real_publish(*args, **kwargs)  # type: ignore[arg-type]

        cli.ensure_worker.reset_mock()  # type: ignore[attr-defined]
        with patch.object(cli.summary, "publish", side_effect=failing_after_first):
            self.assertEqual(self.run_cli("report", task_id, "--blocked", "--note", "还是缺")[0], 0)
        cli.ensure_worker.assert_called_once()  # type: ignore[attr-defined]

    def test_worker_start_failure_after_commit_explains_instead_of_crashing(self) -> None:
        # report/retry/resume 已写入账本后拉起 worker 失败：说明已记录并返回 6，不以异常堆栈退出（DESIGN §45.29）
        self.caller = as_agent(LEAD)
        task_id = self.send()
        self.mark_sent(task_id)
        self.worker_up = False
        cli.ensure_worker.side_effect = OSError("spawn")  # type: ignore[attr-defined]
        try:
            self.caller = as_agent(IMPL)
            code, out, err = self.run_cli("report", task_id, "--blocked", "--note", "缺权限")
            self.assertEqual(code, cli.EXIT_UNAVAILABLE)
            self.assertIn("已记录", out)
            self.assertIn("无法启动后台 worker", err)
            self.assertIn("已记入账本", err)
            with self.store() as store:
                self.assertEqual(store.attempts(task_id)[0].work, Work.BLOCKED)
                self.assertEqual(store.attempts(task_id)[-1].role, Role.NOTICE)
            self.caller = as_agent(LEAD)
            code, out, err = self.run_cli("retry", task_id)
            self.assertEqual(code, cli.EXIT_UNAVAILABLE)
            self.assertIn("已排队第", out)
            self.assertIn("无法启动后台 worker", err)
            self.assertIn("请勿重复执行", err)
            self.assertIn("summary 除外", err)
            self.assertEqual(self.run_cli("pause", task_id)[0], 0)
            code, out, err = self.run_cli("resume", task_id)
            self.assertEqual(code, cli.EXIT_UNAVAILABLE)
            self.assertIn("继续发送", out)
            self.assertIn("无法启动后台 worker", err)
            # --json 同样返回 6，stdout 仍是合法 JSON，说明只写 stderr（Codex F02 / Opus P3-3）
            self.mark_sent(task_id)
            self.caller = as_agent(IMPL)
            code, out, err = self.run_cli("report", task_id, "--result", "--note", "好了", "--json")
            self.assertEqual(code, cli.EXIT_UNAVAILABLE)
            self.assertEqual(json.loads(out)["phase"], "awaiting_acceptance")
            self.assertIn("已记入账本", err)
            # 没有排队消息、但结果待验收还等着提醒：仍需要 worker，照样报 6（Codex 复审 R01）
            self.caller = as_agent(LEAD)
            with self.store() as store:
                for attempt in store.attempts(task_id):
                    store.transition_delivery(
                        attempt.id, expected=(Delivery.PENDING,), new=Delivery.CANCELLED, reason="test", now=3.0
                    )
            self.assertEqual(self.run_cli("pause", task_id)[0], 0)
            code, _out, err = self.run_cli("resume", task_id)
            self.assertEqual(code, cli.EXIT_UNAVAILABLE)
            self.assertIn("可检查 worker 状态", err)
            # 读账本判断需求时出错：按需要处理、返回 6，不打堆栈（Opus 第二轮复审）
            self.assertEqual(self.run_cli("pause", task_id)[0], 0)
            with patch.object(cli, "needs_worker", side_effect=sqlite3.OperationalError("disk I/O error")):
                code, _out, err = self.run_cli("resume", task_id)
            self.assertEqual(code, cli.EXIT_UNAVAILABLE)
            self.assertNotIn("Traceback", err)
            # 没有任何后台工作的任务恢复：不需要 worker，不报（Opus 审计 P3-5）
            with self.store() as store:
                store.update_task(task_id, now=4.0, event="accepted", accepted_at=4.0)
            self.caller = USER
            code, out, _err = self.run_cli("send", "--to", "codex@impl", "-m", "只读", "--no-wait", "--json")
            self.assertEqual(code, cli.EXIT_UNAVAILABLE, "新任务排队、拉起失败：send 报 6")
            idle = json.loads(out)["id"]
            self.mark_sent(idle)
            self.caller = as_agent(IMPL)
            # 没有后续消息的汇报不需要 worker：拉起失败也不报（Opus 复审 P3-c）
            code, _out, err = self.run_cli("report", idle, "--progress", "--note", "进行中")
            self.assertEqual((code, err), (cli.EXIT_OK, ""))
            code, _out, err = self.run_cli("report", idle, "--result", "--note", "好了")
            self.assertEqual((code, err), (cli.EXIT_OK, ""), "用户发起的任务没有回执与提醒")
            self.caller = USER
            self.assertEqual(self.run_cli("pause", idle)[0], 0)
            code, _out, err = self.run_cli("resume", idle)
            self.assertEqual((code, err), (cli.EXIT_OK, ""))
            # 另一个仍在暂停的任务上有发送中断待恢复的记录（SENDING）：恢复空闲任务时也需要 worker。
            # SENDING 所在任务保持暂停，才测得到「暂停中的发送也要恢复」这条专属判断（Opus 末轮复审）
            with self.store() as store:
                store.update_task(task_id, now=5.0, event="reopen", accepted_at=None)
                retried = store.add_attempt(
                    task_id, role=Role.HANDOFF, target=IMPL.ref, body="再来", refs=[], now=5.0, sender=None, sender_class=None
                )
                store.begin_send(retried.id, now=5.0, pid=1, start_ticks="1")
                store.update_task(task_id, now=5.0, event="paused", control="paused")
            self.assertEqual(self.run_cli("pause", idle)[0], 0)
            code, _out, _err = self.run_cli("resume", idle)
            self.assertEqual(code, cli.EXIT_UNAVAILABLE)
        finally:
            cli.ensure_worker.side_effect = None  # type: ignore[attr-defined]
        # 能拉起时照常返回 0
        self.assertEqual(self.run_cli("pause", idle)[0], 0)
        self.assertEqual(self.run_cli("resume", idle)[0], 0)

    def test_broken_worker_lock_does_not_crash_send_or_doctor(self) -> None:
        # 锁文件异常（例如被替换成目录）：已写入账本的 send 与用来排查的 doctor 都不能打堆栈（Opus 审计 P3-6）
        with patch.object(cli, "worker_running", side_effect=IsADirectoryError("worker.lock")), \
                patch.object(doctor, "worker_running", side_effect=IsADirectoryError("worker.lock")):
            code, out, err = self.run_cli("send", "--to", "codex@impl", "-m", "x", "--no-wait")
            self.assertEqual(code, cli.EXIT_UNAVAILABLE)
            self.assertIn("已交给", out)
            self.assertNotIn("Traceback", err)
            code, out, _err = self.run_cli("doctor", "--json")
            self.assertEqual(code, cli.EXIT_OK)
            self.assertFalse(json.loads(out)["workerRunning"])
            self.assertIn("IsADirectoryError", json.loads(out)["workerLockError"], "doctor 要能看到原因（Opus 复审 P3-b）")

    def test_failed_or_noop_start_keeps_the_final_revive(self) -> None:
        # 启动失败、或当时旧 worker 还在（随后退出），都不能消费命令结束时的补拉（Codex 复审 S02 / Opus 复审 P3-1）
        self.caller = as_agent(LEAD)  # 有发起方：结果回执排队，需要 worker
        task_id = self.send()
        self.worker_up = False
        real_publish = cli.summary.publish
        calls = {"n": 0}

        def failing_first(*args: object, **kwargs: object):
            calls["n"] += 1
            if calls["n"] == 1:
                raise cli.summary.SummaryError("summary_lock_timeout")
            return real_publish(*args, **kwargs)  # type: ignore[arg-type]

        cli.ensure_worker.reset_mock()  # type: ignore[attr-defined]
        cli.ensure_worker.side_effect = [True]  # type: ignore[attr-defined]
        try:
            with patch.object(cli.summary, "publish", side_effect=failing_first):
                self.assertEqual(self.run_cli("tasks")[0], 0)
        finally:
            cli.ensure_worker.side_effect = None  # type: ignore[attr-defined]
        # §73：入口刷新 revive=False，异常也不拉起；末尾补拉仍必须发生。
        self.assertEqual(cli.ensure_worker.call_count, 1)  # type: ignore[attr-defined]
        self.mark_sent(task_id)
        self.caller = as_agent(IMPL)
        cli.ensure_worker.reset_mock()  # type: ignore[attr-defined]
        cli.ensure_worker.return_value = False  # type: ignore[attr-defined]  # report 时旧 worker 仍持锁，结束前退出
        self.assertEqual(self.run_cli("report", task_id, "--blocked", "--note", "缺权限")[0], 0)
        self.assertEqual(cli.ensure_worker.call_count, 2)  # type: ignore[attr-defined]

    def test_status_flags_target_that_stopped_without_reporting(self) -> None:
        task_id = self.send()
        self.mark_sent(task_id)
        # worker 已观察到 Codex 队列项离开队列；未观察到时不应提示（DESIGN §45.12）
        with self.store() as store:
            store.set_consumption(store.attempts(task_id)[0].id, Consumption.LEFT_QUEUE, now=3.0)
        self.rows = [own_row(IMPL, runtimeState="ready", freshness="fresh", lastTurnEndedAt=time.time() - 120)]
        code, out, _ = self.run_cli("status", task_id)
        self.assertEqual(code, 0)
        self.assertIn("还没有汇报", out)
        self.assertIn(f"{CMD} retry {task_id[:8]} --force", out)
        self.assertNotIn(f"{CMD} retry {task_id[:8]} /", out)
        document = json.loads(self.run_cli("status", task_id, "--json")[1])
        self.assertTrue(document["targetStoppedWithoutReport"])
        listed = json.loads(self.run_cli("tasks", "--json")[1])["tasks"][0]
        self.assertTrue(listed["targetStoppedWithoutReport"])
        self.assertIn("对方已停下未汇报", self.run_cli("tasks")[1])
        # 只是查询时的提示：不改变任务状态
        self.assertEqual(document["phase"], "running")
        self.caller = as_agent(IMPL)
        self.assertEqual(self.run_cli("report", task_id, "--result", "--note", "完成")[0], 0)
        self.caller = USER
        self.assertFalse(json.loads(self.run_cli("status", task_id, "--json")[1])["targetStoppedWithoutReport"])

    def test_stopped_hint_takes_the_fresh_row_when_the_pane_also_has_a_stale_one(self) -> None:
        """S1：同一 pane 上新鲜的 ready 行后面还有一条 stale 行时，按新鲜那行提示，与面板一致（DESIGN §55.1、§55.4 用例 5）。"""
        code, out, err = self.run_cli("send", "--to", "claude@review", "-m", "复核 X", "--no-wait", "--json")
        self.assertEqual(code, cli.EXIT_OK, err)
        task_id = json.loads(out)["id"]
        self.mark_sent(task_id, Delivery.DELIVERED)
        ended = time.time() - 120
        claude = own_row(REVIEW, "session", runtimeState="ready", freshness="fresh", lastTurnEndedAt=ended)
        codex = {"key": "codex:" + "b" * 24, "paneId": "%2", "runtimeState": "ready", "freshness": "stale", "lastTurnEndedAt": ended + 30}
        # observer 的真实行序就是这样（新鲜的 Claude 行在前）：旧实现取末行，提示被 stale 行压住
        self.rows = [claude, codex]
        document = json.loads(self.run_cli("status", task_id, "--json")[1])
        self.assertTrue(document["targetStoppedWithoutReport"])
        self.assertEqual(document["targetTurnEndedAt"], ended)
        self.assertIn("对方已停下未汇报", self.run_cli("tasks")[1])
        # 对照：pane 上只有那条 stale 行时不提示
        self.rows = [codex]
        self.assertFalse(json.loads(self.run_cli("status", task_id, "--json")[1])["targetStoppedWithoutReport"])

    def test_stopped_hint_does_not_borrow_another_providers_row(self) -> None:
        """Codex 目标的 pane 上只有别家的行时不提示；同 provider 的行照常提示（DESIGN §62 ④）。"""
        task_id = self.send()
        self.mark_sent(task_id)
        with self.store() as store:
            store.set_consumption(store.attempts(task_id)[0].id, Consumption.LEFT_QUEUE, now=3.0)
        ended = time.time() - 120
        self.rows = [{"paneId": "%1", "agent": "claude", "runtimeState": "ready", "freshness": "fresh", "lastTurnEndedAt": ended}]
        self.assertFalse(json.loads(self.run_cli("status", task_id, "--json")[1])["targetStoppedWithoutReport"])
        self.rows = [own_row(IMPL, runtimeState="ready", freshness="fresh", lastTurnEndedAt=ended)]
        self.assertTrue(json.loads(self.run_cli("status", task_id, "--json")[1])["targetStoppedWithoutReport"])

    def test_stopped_hint_only_trusts_the_targets_own_generation(self) -> None:
        """Codex 目标的停下提示按它的进程代际键取行（DESIGN §62 ⑤，Codex 第 1 轮 F03）。

        legacy Codex：任务交给 B 时它在别的 pane；A 在 %1 结束一轮后挂起，B 在 %1 恢复。%1 有两个根进程、解析失败，
        observer 只保持着 A 的行（宽限内 aging），B 不可见——A 的结束时刻不能替 B 作证。
        """
        task_id = self.send()
        self.mark_sent(task_id)
        with self.store() as store:
            store.set_consumption(store.attempts(task_id)[0].id, Consumption.LEFT_QUEUE, now=3.0)
        older = endpoint(ref(Provider.CODEX, "other-thread", pid=990, start="90", pane="%1", label="impl", server=100))
        ended = time.time() - 120
        self.rows = [own_row(older, runtimeState="ready", freshness="aging", lastTurnEndedAt=ended)]
        self.assertFalse(json.loads(self.run_cli("status", task_id, "--json")[1])["targetStoppedWithoutReport"])
        # 对照：B 自己的行
        self.rows = [own_row(IMPL, runtimeState="ready", freshness="aging", lastTurnEndedAt=ended)]
        self.assertTrue(json.loads(self.run_cli("status", task_id, "--json")[1])["targetStoppedWithoutReport"])
        # 算不出代际键（端点没有 tmux server）：不替目标作证
        self.endpoints = [endpoint(replace(IMPL.ref, server_pid=None)), REVIEW, LEAD]
        self.assertFalse(json.loads(self.run_cli("status", task_id, "--json")[1])["targetStoppedWithoutReport"])

    def test_stopped_hint_for_claude_takes_the_generation_row_then_the_session_row_on_the_pane(self) -> None:
        """Claude 目标：代际行优先；没有代际行时会话行必须在活端点的 pane 上（DESIGN §62 ⑤）。"""
        code, out, err = self.run_cli("send", "--to", "claude@review", "-m", "复核 X", "--no-wait", "--json")
        self.assertEqual(code, cli.EXIT_OK, err)
        task_id = json.loads(out)["id"]
        self.mark_sent(task_id, Delivery.DELIVERED)
        ended = time.time() - 120
        session = own_row(REVIEW, "session", runtimeState="ready", freshness="fresh", lastTurnEndedAt=ended)
        self.rows = [session]
        self.assertTrue(json.loads(self.run_cli("status", task_id, "--json")[1])["targetStoppedWithoutReport"])
        # 会话行在别的 pane（这条会话的另一代）：不提示
        self.rows = [{**session, "paneId": "%9"}]
        self.assertFalse(json.loads(self.run_cli("status", task_id, "--json")[1])["targetStoppedWithoutReport"])
        # 代际行说了算：它还在忙时，同 pane 会话行里旧的结束时刻不算
        generation = own_row(REVIEW, runtimeState="working", freshness="fresh", lastTurnEndedAt=ended)
        self.rows = [session, generation]
        self.assertFalse(json.loads(self.run_cli("status", task_id, "--json")[1])["targetStoppedWithoutReport"])
        self.rows = [session, {**generation, "runtimeState": "ready"}]
        self.assertTrue(json.loads(self.run_cli("status", task_id, "--json")[1])["targetStoppedWithoutReport"])

    def test_query_commands_read_the_observer_snapshot_once(self) -> None:
        """有未结束任务时 tasks/status 只读一次 ListSessions，发现与提示用同一份快照（DESIGN §55.4 用例 4）。"""
        # 没有任务：tasks 不读
        self.observer_reads = 0
        self.assertEqual(self.run_cli("tasks")[0], 0)
        self.assertEqual(self.observer_reads, 0)
        task_id = self.send()
        self.mark_sent(task_id)
        with self.store() as store:
            store.set_consumption(store.attempts(task_id)[0].id, Consumption.LEFT_QUEUE, now=3.0)
        # _observations 本身：读一次，discover 收到的 runtime 就是返回的那份快照
        self.observer_reads = 0
        self.discovered.clear()
        _, observed = cli._observations()  # pyright: ignore[reportPrivateUsage]
        self.assertEqual(self.observer_reads, 1)
        [(sources, served)] = self.discovered
        assert sources is not None
        self.assertIs(served, observed)
        # 只换 runtime：其他发现来源仍是默认值（Opus 实现复核 P3-1）
        self.assertEqual(replace(sources, runtime=DiscoverySources().runtime), DiscoverySources())
        # 两次读取会读到不同内容时，提示按唯一那次读取判（旧实现的第二次读取会读到 working、不提示）
        ended = time.time() - 120
        self.replies = [
            [own_row(IMPL, runtimeState="ready", freshness="fresh", lastTurnEndedAt=ended)],
            [own_row(IMPL, runtimeState="working", freshness="fresh", lastTurnEndedAt=ended)],
        ]
        for command in (("status", task_id, "--json"), ("tasks", "--json")):
            with self.subTest(command=command[0]):
                self.observer_reads = 0
                code, out, _ = self.run_cli(*command)
                self.assertEqual(code, 0)
                self.assertEqual(self.observer_reads, 1)
                document = json.loads(out)
                item = document if command[0] == "status" else document["tasks"][0]
                self.assertTrue(item["targetStoppedWithoutReport"])
        # 任务结束后：status 与 tasks 都不再读
        self.replies = []
        self.caller = as_agent(IMPL)
        self.assertEqual(self.run_cli("report", task_id, "--result", "--note", "完成")[0], 0)
        self.caller = USER
        self.assertEqual(self.run_cli("accept", task_id)[0], 0)
        # `tasks --all` 列出的全是已结束任务：列表非空也不读（Codex 实现复核 N01）
        for command in (("status", task_id), ("tasks",), ("tasks", "--all")):
            with self.subTest(finished=" ".join(command[:2])):
                self.observer_reads = 0
                self.assertEqual(self.run_cli(*command)[0], 0)
                self.assertEqual(self.observer_reads, 0)

    def test_tasks_reads_once_for_many_open_tasks(self) -> None:
        """多个未结束任务共用一份快照，不按任务各读一次（Opus 实现复核 P3-2）。"""
        for _ in range(3):
            self.mark_sent(self.send())
        self.observer_reads = 0
        code, out, _ = self.run_cli("tasks", "--json")
        self.assertEqual(code, 0)
        self.assertEqual(len(json.loads(out)["tasks"]), 3)
        self.assertEqual(self.observer_reads, 1)

    def test_stopped_hint_follows_the_live_generation_pane(self) -> None:
        """对方在另一个 pane 恢复了同一 thread：按活端点当前的 pane 取行，不按账本里送达时的 pane（Fable 实现复核 P3-1）。"""
        task_id = self.send()
        self.mark_sent(task_id)
        with self.store() as store:
            store.set_consumption(store.attempts(task_id)[0].id, Consumption.LEFT_QUEUE, now=3.0)
        resumed = endpoint(ref(Provider.CODEX, "impl-thread", pid=1007, pane="%7", label="impl", server=100))
        self.endpoints = [resumed, REVIEW, LEAD]
        ended = time.time() - 120
        self.rows = [own_row(resumed, runtimeState="ready", freshness="fresh", lastTurnEndedAt=ended)]
        document = json.loads(self.run_cli("status", task_id, "--json")[1])
        self.assertTrue(document["targetStoppedWithoutReport"])
        self.assertEqual(document["targetTurnEndedAt"], ended)
        # 对照：账本里的旧 pane %1 上的行不算数
        self.rows = [own_row(IMPL, runtimeState="ready", freshness="fresh", lastTurnEndedAt=ended)]
        self.assertFalse(json.loads(self.run_cli("status", task_id, "--json")[1])["targetStoppedWithoutReport"])

    def test_status_flags_target_session_that_is_not_found(self) -> None:
        task_id = self.send()
        self.mark_sent(task_id)
        # 发现里还有别的会话，却没有 impl 的任何一代：可能已退出，也可能暂时无法识别（DESIGN §45.32）
        self.endpoints = [REVIEW, LEAD]
        code, out, _ = self.run_cli("status", task_id)
        self.assertEqual(code, 0)
        self.assertIn("当前未发现 codex@impl 的会话（可能已退出", out)
        self.assertNotIn("已不在", out)
        self.assertIn(f"{CMD} retry {task_id[:8]} --force", out)
        document = json.loads(self.run_cli("status", task_id, "--json")[1])
        self.assertTrue(document["targetSessionMissing"])
        self.assertFalse(document["targetStoppedWithoutReport"])
        self.assertEqual(document["phase"], "running")
        self.assertTrue(json.loads(self.run_cli("tasks", "--json")[1])["tasks"][0]["targetSessionMissing"])
        self.assertIn("未发现对方会话", self.run_cli("tasks")[1])
        # 未确证离开 Codex 队列的各种观察都只说“若仍在”，重发与改派都提示可能重复；确证离队后不再提
        with self.store() as store:
            attempt_id = store.attempts(task_id)[0].id
        for consumption in (Consumption.NOT_OBSERVED, Consumption.UNKNOWN, Consumption.STILL_QUEUED, Consumption.LEFT_QUEUE):
            with self.subTest(consumption=consumption):
                with self.store() as store:
                    store.set_consumption(attempt_id, consumption, now=3.0)
                out = self.run_cli("status", task_id)[1]
                self.assertIn("当前未发现", out)
                maybe_queued = consumption is not Consumption.LEFT_QUEUE
                self.assertEqual("尚未确认离开 Codex 队列" in out, maybe_queued)
                self.assertEqual("都可能重复执行" in out, maybe_queued)
        # 发现结果为空视为发现失败，不提示；对方恢复后提示消失
        self.endpoints = []
        self.assertFalse(json.loads(self.run_cli("status", task_id, "--json")[1])["targetSessionMissing"])
        self.endpoints = [IMPL, REVIEW, LEAD]
        self.assertFalse(json.loads(self.run_cli("status", task_id, "--json")[1])["targetSessionMissing"])
        self.assertNotIn("未发现对方会话", self.run_cli("tasks")[1])

    def test_left_queue_wording_does_not_claim_execution(self) -> None:
        self.assertNotIn("已开始", cli.CONSUMPTION_LABELS[Consumption.LEFT_QUEUE])

    def test_pause_resume(self) -> None:
        task_id = self.send()
        self.assertEqual(self.run_cli("pause", task_id)[0], 0)
        code, out, _ = self.run_cli("status", task_id)
        self.assertIn(f"{CMD} resume", out)
        self.assertEqual(self.run_cli("resume", task_id)[0], 0)
        code, _, err = self.run_cli("resume", task_id)
        self.assertEqual((code, "not_paused" in err), (cli.EXIT_REJECTED, True))


class DeviceNameTests(unittest.TestCase):
    """本机设备名：固定值、形状受控，且 peers/doctor 都把它显示出来（DESIGN §45.35）。"""

    def resolve(self, hostname: str, override: str | None = None) -> str:
        environment = {"AB_DEVICE": override} if override is not None else {}
        with (
            patch.object(paths.socket, "gethostname", return_value=hostname),
            patch.dict(os.environ, environment, clear=False),
        ):
            if override is None:
                os.environ.pop("AB_DEVICE", None)
            return paths.device_name()

    def test_value_is_bounded_and_safe_for_a_header_field(self) -> None:
        cases = {
            # 只取主机名第一段：没有理由把内网域名一起发进跨会话消息
            ("devbox.lan", None): "devbox",
            # 空白与 `=` 都会毁掉「消息头只有一行、按 k=v 切分」这条
            ("my box=1", None): "my-box-1",
            ("...", None): "local",
            ("", None): "local",
            # 覆盖优先：跨设备时主机名可能重名，要能显式命名
            ("devbox", "arm-hub"): "arm-hub",
            ("devbox", "  "): "devbox",
            ("x" * 80, None): "x" * paths.DEVICE_CHARS,
        }
        for (hostname, override), expected in cases.items():
            with self.subTest(hostname=hostname, override=override):
                value = self.resolve(hostname, override)
                self.assertEqual(value, expected)
                self.assertRegex(value, r"^[A-Za-z0-9._-]{1,32}$")


class PackagePathTests(unittest.TestCase):
    """doctor 的 `packagePath`：包目录解开符号链接，与解析后的 home 比较再缩写（DESIGN §48 R9）。"""

    def setUp(self) -> None:
        self.package = Path(doctor.__file__).resolve().parent
        temporary = TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.temporary = Path(temporary.name).resolve()

    def value(self, home: Path | str) -> str:
        with patch.dict(os.environ, {"HOME": os.fspath(home)}):
            return doctor.package_path()

    def test_package_under_home_is_abbreviated(self) -> None:
        self.assertEqual(self.value(self.package.parent), f"~/{self.package.name}")

    def test_symlinked_home_is_resolved_before_comparing(self) -> None:
        # 拿未解析的 HOME 去比会缩写不上，完整路径照样带出用户名
        link = self.temporary / "home-link"
        link.symlink_to(self.package.parent, target_is_directory=True)
        self.assertEqual(self.value(link), f"~/{self.package.name}")

    def test_unrelated_or_root_home_gives_the_full_path(self) -> None:
        self.assertEqual(self.value(self.temporary), str(self.package))
        self.assertEqual(self.value("/"), str(self.package))

    def test_relative_or_empty_home_gives_the_full_path(self) -> None:
        # 当前目录恰好是包的上级：相对 HOME 若先 resolve，会把它当成 home 误缩写（Fable 实现复核 P3-2）
        original = os.getcwd()
        os.chdir(self.package.parent)
        self.addCleanup(os.chdir, original)
        self.assertEqual(self.value("."), str(self.package))
        self.assertEqual(self.value(""), str(self.package))

    def test_unavailable_home_gives_the_full_path(self) -> None:
        # 没有 HOME、pwd 也查不到时 Path.home() 抛 RuntimeError（Opus 实现复核 P3-3）
        with patch.object(doctor.Path, "home", side_effect=RuntimeError("no home")):
            self.assertEqual(doctor.package_path(), str(self.package))

    def test_package_loaded_through_a_symlink_shows_the_real_directory(self) -> None:
        link = self.temporary / "src-link"
        link.symlink_to(self.package.parent, target_is_directory=True)
        environment = {
            "PATH": "/usr/bin:/bin", "HOME": os.fspath(self.temporary), "LANG": "C.UTF-8",
            "PYTHONPATH": os.fspath(link), "PYTHONDONTWRITEBYTECODE": "1",
        }
        result = subprocess.run(
            [sys.executable, "-c", "from agentstatus_bridge.doctor import package_path; print(package_path())"],
            env=environment, capture_output=True, text=True, timeout=30, check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), str(self.package))


class CommandNameTests(unittest.TestCase):
    """对外命令名：env > argv0（限认得的入口名）> 独立版默认名（DESIGN §45.36）。"""

    def resolve(self, argv0: str, override: str | None = None) -> str:
        environment = {naming.COMMAND_ENV: override} if override is not None else {}
        with patch.object(naming.sys, "argv", [argv0]), patch.dict(os.environ, environment, clear=False):
            if override is None:
                os.environ.pop(naming.COMMAND_ENV, None)
            return naming.command_name()

    def test_resolution_order(self) -> None:
        cases = {
            # 装出来的命令与 opt-in 别名：用户敲哪个，生成给对方的命令就写哪个
            ("/home/x/.local/bin/ab", None): "ab",
            ("agent-bridge", None): "agent-bridge",
            ("/opt/venv/bin/agent-bridge", None): "agent-bridge",
            # 不是命令行入口（worker 是 `python -m` 起的）：猜不出来就用默认名，由拉起方显式传
            ("/usr/bin/python3", None): naming.DEFAULT_COMMAND,
            ("/x/agentstatus_bridge/__main__.py", None): naming.DEFAULT_COMMAND,
            ("", None): naming.DEFAULT_COMMAND,
            # env 显式覆盖一切：集成版的入口脚本就是这么绑的
            ("/usr/bin/python3", "ab"): "ab",
            ("agent-bridge", "ab"): "ab",
            ("ab", "  "): "ab",
        }
        for (argv0, override), expected in cases.items():
            with self.subTest(argv0=argv0, override=override):
                self.assertEqual(self.resolve(argv0, override), expected)

    def test_argv_may_be_empty(self) -> None:
        with patch.object(naming.sys, "argv", []), patch.dict(os.environ, {}, clear=False):
            os.environ.pop(naming.COMMAND_ENV, None)
            self.assertEqual(naming.command_name(), naming.DEFAULT_COMMAND)

    def test_help_and_version_follow_the_entry_name(self) -> None:
        with patch.dict(os.environ, {naming.COMMAND_ENV: "ab"}, clear=False):
            parser = cli.build_parser()
        self.assertEqual(parser.prog, "ab")
        self.assertIn("ab 自动拉起", parser.format_help())


class StateRootTests(unittest.TestCase):
    """状态根：默认是独立版的目录，集成版由入口脚本绑回现役根，来源要能看出来（DESIGN §45.36）。"""

    def resolve(self, environment: dict[str, str]) -> tuple[str, str]:
        keys = ("AB_STATE_DIR", "AB_BINDING", "XDG_STATE_HOME")
        with patch.dict(os.environ, environment, clear=False):
            for key in keys:
                if key not in environment:
                    os.environ.pop(key, None)
            return str(paths.state_dir()), paths.state_dir_source()

    def test_default_is_the_standalone_directory(self) -> None:
        root, source = self.resolve({})
        self.assertEqual(root, str(Path.home() / ".local/state" / paths.STATE_DIR_NAME))
        self.assertEqual(source, "default")
        # 拆仓前的现役根不再是默认值：集成版必须显式绑，不能靠默认值碰巧相同
        self.assertNotEqual(root, str(Path.home() / ".local/state/agentstatus/bridge"))

    def test_xdg_state_home_is_respected(self) -> None:
        root, source = self.resolve({"XDG_STATE_HOME": "/tmp/xdg"})
        self.assertEqual(root, f"/tmp/xdg/{paths.STATE_DIR_NAME}")
        self.assertEqual(source, "default")

    def test_source_separates_an_explicit_value_from_the_integration_binding(self) -> None:
        self.assertEqual(self.resolve({"AB_STATE_DIR": "/tmp/mine"}), ("/tmp/mine", "env"))
        self.assertEqual(
            self.resolve({"AB_STATE_DIR": "/tmp/bound", "AB_BINDING": "agentstatus:/tmp/bound"}),
            ("/tmp/bound", "integration"),
        )

    def test_stale_or_rootless_binding_never_claims_integration(self) -> None:
        # 旧的裸标记没有绑定根证据；继承标记后改根也不能沿用 integration。
        for marker in ("agentstatus", "agentstatus:", "agentstatus:/tmp/old"):
            with self.subTest(marker=marker):
                self.assertEqual(
                    self.resolve({"AB_STATE_DIR": "/tmp/new", "AB_BINDING": marker}),
                    ("/tmp/new", "env"),
                )
        self.assertEqual(self.resolve({"AB_BINDING": "agentstatus:/tmp/old"})[1], "default")

    def test_prefix_collision_is_not_a_match(self) -> None:
        # 比对必须是**相等**而不是前缀：`/tmp/bound` 的标记不能认下 `/tmp/bound-2`。
        # 没有这条时，把 `==` 换成 `startswith` 的弱化会全绿通过（复核实测）。
        self.assertEqual(
            self.resolve({"AB_STATE_DIR": "/tmp/bound-2", "AB_BINDING": "agentstatus:/tmp/bound"}),
            ("/tmp/bound-2", "env"),
        )

    def test_binding_root_may_itself_contain_a_colon(self) -> None:
        root = "/tmp/fixture:bridge"
        self.assertEqual(
            self.resolve({"AB_STATE_DIR": root, "AB_BINDING": f"agentstatus:{root}"}),
            (root, "integration"),
        )


class PeerSelectorTests(unittest.TestCase):
    """ab peers 给出的目标必须能解析回这一行（DESIGN §45.33.6）。"""

    def test_short_id_is_used_only_when_it_resolves_back(self) -> None:
        plain = endpoint(ref(Provider.CODEX, "019a0000-1111-7111-8111-111111111111", pid=5001, pane=None, label=None))
        named = endpoint(ref(Provider.CODEX, "019a9999-3333-7333-8333-333333333333", pid=5003, pane="%3", label="tmuxed"))
        # 唯一时用展示名
        selectors = cli._selectors([plain, named])
        self.assertEqual(selectors[id(plain)], "codex@019a0000")
        self.assertEqual(selectors[id(named)], "codex@tmuxed")
        # 同前缀的第二条无 pane 会话出现后，两条都退回完整原生 ID
        twin = endpoint(ref(Provider.CODEX, "019a0000-2222-7222-8222-222222222222", pid=5002, pane=None, label=None))
        selectors = cli._selectors([plain, twin])
        self.assertEqual(selectors[id(plain)], plain.ref.native_id)
        self.assertEqual(selectors[id(twin)], twin.ref.native_id)
        # 前缀撞上别人的 tmux 会话名时也退回完整原生 ID
        clash = endpoint(ref(Provider.CODEX, "019a8888-4444-7444-8444-444444444444", pid=5004, pane="%4", label="019a0000"))
        selectors = cli._selectors([plain, clash])
        self.assertEqual(selectors[id(plain)], plain.ref.native_id)
        self.assertEqual(selectors[id(clash)], "codex@019a0000")


class WorkerStartupTests(unittest.TestCase):
    """不替换 worker_running：新拉起的 worker 稍后才持锁时，--no-wait 不能误报不可用。"""

    def setUp(self) -> None:
        self._tmp = TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.state = Path(self._tmp.name) / "bridge"
        self._lock_fd: int | None = None
        self._thread: threading.Thread | None = None
        for item in (
            patch.dict(os.environ, {"AB_STATE_DIR": str(self.state)}),
            patch.object(cli, "discover", return_value=[IMPL]),
            patch.object(cli, "identify_caller", return_value=USER),
            patch.object(cli, "_receiver_class", return_value=None),
            patch.object(cli, "WORKER_START_SECONDS", 1.0),
        ):
            item.start()
            self.addCleanup(item.stop)
        self.addCleanup(self._release)

    def _late_worker(self, root: Path) -> bool:
        def hold() -> None:
            time.sleep(0.3)
            fd = os.open(root / "worker.lock", os.O_RDWR | os.O_CREAT, 0o600)
            fcntl.flock(fd, fcntl.LOCK_EX)
            self._lock_fd = fd

        self._thread = threading.Thread(target=hold, daemon=True)
        self._thread.start()
        return True

    def _release(self) -> None:
        if self._thread is not None:
            self._thread.join(2.0)
        if self._lock_fd is not None:
            fcntl.flock(self._lock_fd, fcntl.LOCK_UN)
            os.close(self._lock_fd)

    def _send(self) -> tuple[int, str, str]:
        out, err = StringIO(), StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            code = cli.main(["send", "--to", "%1", "-m", "x", "--no-wait"])
        return code, out.getvalue(), err.getvalue()

    def test_starting_worker_is_not_reported_missing(self) -> None:
        with patch.object(cli, "ensure_worker", side_effect=self._late_worker):
            code, out, err = self._send()
        self.assertEqual(code, cli.EXIT_OK, err)
        self.assertNotIn("未运行", out)

    def test_worker_that_never_takes_the_lock_is_reported(self) -> None:
        with patch.object(cli, "ensure_worker", return_value=True):
            code, out, _ = self._send()
        self.assertEqual(code, cli.EXIT_UNAVAILABLE)
        self.assertIn("未运行", out)


if __name__ == "__main__":
    unittest.main()
