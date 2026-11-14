"""P5 CLI 接入（DESIGN §88.6/§88.7/§88.10/§88.12）：两台设备经真实 `cli.main` 跑通 send→投递→report→裁决→accept。

hub/relay 由测试内的 pump 代替（网络部分另有 relay 用例）；B 的投递用真实 FederationDispatcher + 记录型 transport。
覆盖：本机优先/联邦回退的命名空间、--origin-device、B 不能代 A 决定、withdraw 写前退出 9、relay 未运行退出 6、
停用后写拒绝读照常、第三设备复核写前拒绝、peers --device/--all-devices、tasks 合并与联邦库不可读、启用幂等与冲突、
返工与取消、镜像归档、federation status/doctor 投影、relay 停用退出与 worker 拉起退避、Windows 提权拒绝。
"""

from __future__ import annotations

import json
import os
import re
import sqlite3
import subprocess
import sys
import tempfile
import time
import unittest
from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import Mock, patch

import bridge_support  # noqa: F401  导入即隔离宿主会话环境

from agentstatus_bridge import cli, doctor
from agentstatus_bridge.endpoints import Caller, ResolveError, resolve_target
from agentstatus_bridge.envelope import parse_header
from agentstatus_bridge.federation import commands as fed_commands
from agentstatus_bridge.federation import directory, mirror, retention
from agentstatus_bridge.federation.authority import Identity
from agentstatus_bridge.federation.config import FederationConfig
from agentstatus_bridge.federation.delivery import FederationDispatcher
from agentstatus_bridge.federation.errors import FedCliError
from agentstatus_bridge.federation.fedstore import FED_DB_NAME, FederatedStore, now_ms
from agentstatus_bridge.federation.relay import Relay, RelayPaths
from agentstatus_bridge.model import Delivery, Endpoint, Provider, ReportKind
from agentstatus_bridge.platforms.linux.process import ProcessInfo
from agentstatus_bridge.store import DB_NAME, Store
from agentstatus_bridge.transports import DeliveryOutcome
from bridge_support import RecordingTransport, endpoint, ref, register_claude_session, with_name_views

HUB = "c" * 32
DEV_A = "a" * 32
DEV_B = "b" * 32
DEV_C = "d" * 32
CLAUDE_A = "0000000a-1111-4222-8333-444444444444"
THREAD_B = "019a0000-1111-7222-8333-44445555bbbb"
ORIGIN = endpoint(ref(Provider.CLAUDE, CLAUDE_A, pid=31001, start="501", pane="%1", label="lead"), name="lead")
WORKER = endpoint(ref(Provider.CODEX, THREAD_B, pid=32002, start="777", pane="%3", label="impl"), name="impl")
LOCAL_REVIEW = endpoint(ref(Provider.CODEX, "019a0000-1111-7222-8333-44445555aaaa", pid=31003, start="503",
                            pane="%2", label="review"), name="review")


def as_agent(item: Endpoint) -> Caller:
    return Caller(item, ProcessInfo(item.ref.pid, 1, item.ref.provider.value, item.ref.start_ticks))


USER = Caller(None, None)


# §94.3：引用本夹具的 tasks 用例模块进了 Windows CI 选择集；这里用联邦库与替身 Linux 发现，原因按选择器放行的前缀写
# （test_bridge_federation_windows 导入常量核对前缀）
FED_FIXTURE_REASON = "POSIX-only: 联邦库与替身 Linux 发现（提权的 Windows CI 不建联邦库，§88.18）"


@unittest.skipUnless(os.name == "posix", FED_FIXTURE_REASON)
class FedCliCase(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.root = Path(self._tmp.name)
        self.states = {"vm": self.root / "vm", "win": self.root / "win"}
        for path in self.states.values():
            path.mkdir(mode=0o700)
        self.ids = {"vm": DEV_A, "win": DEV_B}
        self.hub = HUB
        self.endpoints: dict[str, list[Endpoint]] = {"vm": [ORIGIN, LOCAL_REVIEW], "win": [WORKER]}
        self.device = "vm"
        self.caller: Caller = as_agent(ORIGIN)
        self.relay_up = True
        patches = [
            patch.dict(os.environ, {"AB_CLAUDE_SESSIONS_DIR": str(self.root / "claude-sessions")}),
            patch.object(cli, "discover", side_effect=lambda *_a, **_k: list(self.endpoints[self.device])),
            patch.object(cli, "identify_caller", side_effect=lambda _endpoints: self.caller),
            patch.object(cli, "permission_class", return_value="bypass"),
            patch.object(cli, "ensure_worker", return_value=False),
            patch.object(cli, "worker_running", return_value=False),
            patch.object(fed_commands, "relay_running", side_effect=lambda _root: self.relay_up),
            patch.object(doctor, "cli_version", return_value=None),
            patch.object(doctor, "_runtime_available", return_value=True),
            patch.object(doctor, "codex_title_report", return_value={"daemonMode": False}),
            patch.object(doctor, "caller_diagnostic", return_value={"attributed": False}),
            patch.object(doctor, "worker_running", return_value=False),
        ]
        for item in patches:
            item.start()
            self.addCleanup(item.stop)
        register_claude_session(ORIGIN.ref)  # 发起会话的注册记录：联邦根绑定按它核实
        for name in ("vm", "win"):
            code, _, err = self.run_on(name, "federation", "enable", "--hub-host", "hub.example", "--hub-user",
                                       "ab-relay", "--hub-id", HUB, "--device-id", self.ids[name], "--name", name,
                                       "--identity-file", "/nonexistent/relay_key",
                                       "--known-hosts-file", "/nonexistent/known_hosts")
            self.assertEqual(code, 0, err)
        # relay 会从目录与 hub 盖章记下对方：这里直接写入 B 的整帧目录与 A 的登记名
        with self.store("win") as store:
            # 目录只发布端点携带的已核实 NameView（§91.4.3），照真实发现的最后一步附上
            snapshot = directory.snapshot(store, DEV_B, with_name_views([WORKER]), provider_complete={"codex": True})
            store.remember_device_name(DEV_A, "vm")
        with self.store("vm") as store:
            store.put_device_state(device_id=DEV_B, name="win", revision=1, snapshot=snapshot, last_seen=now_ms(),
                                   state="online")

    # ---- 工具 ----

    def run_on(self, device: str, *argv: str, caller: Caller | None = None) -> tuple[int, str, str]:
        self.device = device
        if caller is not None:
            self.caller = caller
        out, err = StringIO(), StringIO()
        with patch.dict(os.environ, {"AB_STATE_DIR": str(self.states[device])}), \
                redirect_stdout(out), redirect_stderr(err):
            code = cli.main(list(argv))
        return code, out.getvalue(), err.getvalue()

    def store(self, device: str) -> FederatedStore:
        return FederatedStore.open(self.states[device])

    def ident(self, device: str) -> Identity:
        return Identity(self.ids[device], device, self.hub)

    def pump(self, src: str, dst: str) -> int:
        """代替 hub + relay：把 src 发给 dst 的 ready 信封按顺序交给 dst。"""
        moved = 0
        with self.store(src) as source, self.store(dst) as target:
            for item in source.outbox():
                envelope = json.loads(item["envelope_json"])
                if envelope["targetDeviceId"] != self.ids[dst]:
                    continue
                mirror.receive(target, self.ident(dst), envelope, source_device=self.ids[src],
                               payload_hash=item["payload_hash"], now=now_ms())
                source.set_outbox_state(item["msg_id"], state="received")
                moved += 1
        return moved

    def deliver_on_b(self) -> RecordingTransport:
        transport = RecordingTransport(Provider.CODEX)
        with self.store("win") as store:
            FederationDispatcher(store, self.ident("win"), RelayPaths(self.states["win"]),
                                 discover=lambda: [WORKER], transports={Provider.CODEX: transport},
                                 reply_address=None, command="ab").run_once()
        return transport

    def send(self, *extra: str) -> str:
        code, out, err = self.run_on("vm", "send", "--device", "win", "--to", f"codex@id:{THREAD_B}", "-m",
                                     "请处理 X\n细节", "--json", *extra, caller=as_agent(ORIGIN))
        self.assertEqual(code, cli.EXIT_OK, err)
        return json.loads(out)["id"]

    def local_review_requested(self) -> str:
        """远端执行、A 本机复核：B 交结果后，A 的 worker 已把复核请求投给本机复核方。"""
        code, out, err = self.run_on("vm", "send", "--device", "win", "--to", "codex@impl", "--review-by",
                                     "codex@review", "-m", "实现 Y", "--json", caller=as_agent(ORIGIN))
        self.assertEqual(code, 0, err)
        task_id = json.loads(out)["id"]
        self.pump("vm", "win")
        self.deliver_on_b()
        self.assertEqual(self.run_on("win", "report", task_id, "--result", caller=as_agent(WORKER))[0], 0)
        self.pump("win", "vm")
        # A 本机复核方：先由 A 的 worker 投递复核请求，再在 A 本机同事务裁决
        transport = RecordingTransport(Provider.CODEX)
        with self.store("vm") as store:
            FederationDispatcher(store, self.ident("vm"), RelayPaths(self.states["vm"]),
                                 discover=lambda: [LOCAL_REVIEW], transports={Provider.CODEX: transport},
                                 reply_address=None, command="ab").run_once()
        self.assertEqual(len(transport.calls), 1)
        self.review_calls = transport.calls
        return task_id

    def delivered_task(self) -> str:
        task_id = self.send()
        self.assertGreaterEqual(self.pump("vm", "win"), 1)
        self.assertEqual(len(self.deliver_on_b().calls), 1)
        return task_id


class EndToEndTests(FedCliCase):
    def test_send_deliver_report_accept_round_trip(self) -> None:
        task_id = self.delivered_task()
        # B 本机库没有这个任务：status 无参数时回退到联邦唯一命中，并给出带 --origin-device 的汇报页脚
        code, out, err = self.run_on("win", "status", task_id[:12], caller=as_agent(WORKER))
        self.assertEqual(code, 0, err)
        self.assertIn("镜像（发起设备 vm）", out)
        self.assertIn(f"report {task_id[:8]} --origin-device vm", out)
        code, out, err = self.run_on("win", "report", task_id, "--origin-device", "vm", "--result", "--note", "完成",
                                     caller=as_agent(WORKER))
        self.assertEqual(code, 0, err)
        self.assertIn("等待发起设备确认", out)
        self.assertGreaterEqual(self.pump("win", "vm"), 1)
        code, out, err = self.run_on("vm", "status", task_id, "--json")
        self.assertEqual(code, 0, err)
        document = json.loads(out)
        self.assertEqual((document["scope"], document["isAuthority"], document["phase"]),
                         ("federation", True, "awaiting_acceptance"))
        self.assertEqual(document["reports"][0]["decision"], "accepted")
        self.assertEqual(self.run_on("vm", "wait", task_id, "--timeout", "1")[0], cli.EXIT_OK)
        # B 不能代 A 决定
        code, _, err = self.run_on("win", "accept", task_id, caller=as_agent(WORKER))
        self.assertEqual(code, cli.EXIT_REJECTED)
        self.assertIn("federation_not_authority", err)
        code, out, err = self.run_on("vm", "accept", task_id, caller=as_agent(ORIGIN))
        self.assertEqual(code, 0, err)
        self.assertIn("已验收", out)
        self.assertIn("已排队结束回执 → win 上的 codex@", out)
        self.pump("vm", "win")
        code, out, err = self.run_on("win", "status", task_id, "--json", caller=as_agent(WORKER))
        self.assertEqual(json.loads(out)["phase"], "done", err)

    def test_actor_tokens_and_closure_decider_use_full_id(self) -> None:
        """§91.4.2/冻结附注 P3-3：联邦 wireToken（发起方 actor、汇报方 reporter）随事实保存并可转发到别的设备，
        一律 provider@id:<完整ID>；参与方跨设备时结束回执的 decider 也写完整 ID。本机名字 lead/impl 不进这些标识。"""
        origin_id, worker_id = f"claude@id:{CLAUDE_A}", f"codex@id:{THREAD_B}"
        # 夹具同真实发现（_discover_selected）一样附本轮 NameView：lead/impl 都已核实，名字才有机会漏进跨设备标识
        self.endpoints = {"vm": with_name_views([ORIGIN, LOCAL_REVIEW]), "win": with_name_views([WORKER])}
        origin, worker = self.endpoints["vm"][0], self.endpoints["win"][0]
        assert origin.name_view is not None and worker.name_view is not None
        self.assertEqual((origin.name_view.verified, worker.name_view.verified), (True, True))
        code, out, err = self.run_on("vm", "send", "--device", "win", "--to", worker_id, "-m", "请处理 X", "--json",
                                     caller=as_agent(origin))
        self.assertEqual(code, cli.EXIT_OK, err)
        task_id = json.loads(out)["id"]
        self.assertGreaterEqual(self.pump("vm", "win"), 1)
        [(_endpoint, text, _context)] = self.deliver_on_b().calls
        self.assertIn(f" from={origin_id} device=", text.splitlines()[0])
        self.assertNotIn("claude@lead", text)
        with self.store("win") as store:
            [handoff] = [item for item in store.attempts(DEV_A, task_id) if item.role == "handoff"]
        self.assertIsNotNone(handoff.sender)
        assert handoff.sender is not None
        self.assertEqual(handoff.sender.wire_token, origin_id)
        code, _, err = self.run_on("win", "report", task_id, "--origin-device", "vm", "--result", "--note", "完成",
                                   caller=as_agent(worker))
        self.assertEqual(code, 0, err)
        self.assertGreaterEqual(self.pump("win", "vm"), 1)
        with self.store("vm") as store:
            [notice] = [item for item in store.attempts(DEV_A, task_id) if item.role == "notice"]
        assert notice.sender is not None
        self.assertEqual(notice.sender.wire_token, worker_id)
        self.assertIn(f"（{worker_id}）", notice.body)
        self.assertNotIn("codex@impl", notice.body)
        code, _, err = self.run_on("vm", "accept", task_id, caller=as_agent(origin))
        self.assertEqual(code, 0, err)
        with self.store("vm") as store:
            closures = [item for item in store.attempts(DEV_A, task_id) if item.is_closure]
        self.assertTrue(closures)
        for item in closures:
            self.assertIn(f"已由 {origin_id} 验收", item.body)
            self.assertNotIn("claude@lead", item.body)
            assert item.sender is not None
            self.assertEqual(item.sender.wire_token, origin_id)

    def test_reviewer_token_uses_full_id(self) -> None:
        """§91.4.2：远端执行、本机复核时随任务保存的 reviewer_token 同样是完整 ID，不是本机名字 review。"""
        self.endpoints["vm"] = with_name_views(self.endpoints["vm"])  # 复核方带已核实 NameView（displayLabel=review）
        review = self.endpoints["vm"][1]
        assert review.name_view is not None
        self.assertEqual((review.name_view.name, review.name_view.verified), ("review", True))
        task_id = self.local_review_requested()
        with self.store("vm") as store:
            task = store.get_task(DEV_A, task_id)
        assert task is not None
        self.assertEqual(task.state.get("reviewerToken"), f"codex@id:{LOCAL_REVIEW.ref.native_id}")
        # 复核请求正文写执行方的完整 ID，不写对端主名或 8 位短 ID（§91.4.2，附注 P3-1）
        (_, text, _) = self.review_calls[0]
        self.assertIn(f"请复核 codex@id:{THREAD_B} 完成的这项工作。", text)

    def test_executor_cannot_accept_on_authority_and_user_shell_can(self) -> None:
        task_id = self.delivered_task()
        code, _, err = self.run_on("vm", "pause", task_id, caller=as_agent(LOCAL_REVIEW))
        self.assertEqual(code, cli.EXIT_REJECTED)
        self.assertIn("accept_not_allowed", err)
        code, out, err = self.run_on("vm", "pause", task_id, caller=USER)
        self.assertEqual(code, 0, err)
        self.assertIn("已暂停发送", out)
        self.assertEqual(self.run_on("vm", "resume", task_id, caller=USER)[0], 0)
        self.assertIn("not_paused", self.run_on("vm", "resume", task_id, caller=USER)[2])

    def test_rework_after_blocked_report_queues_new_attempt_with_original_body(self) -> None:
        task_id = self.delivered_task()
        self.assertEqual(self.run_on("win", "report", task_id, "--blocked", "--note", "缺权限",
                                     caller=as_agent(WORKER))[0], 0)
        self.pump("win", "vm")
        code, out, err = self.run_on("vm", "retry", task_id, "-m", "已授权", caller=as_agent(ORIGIN))
        self.assertEqual(code, 0, err)
        # #2 是发给发起方的受阻通知；对端主名只作旁注，后面跟可复制的全限定 target（§91.4.2）
        self.assertIn(f"已排队第 3 次交接 → win 上的 codex@impl target=--device win --to codex@id:{THREAD_B}", out)
        with self.store("vm") as store:
            [task] = store.find_tasks(task_id)
            second = store.attempts(DEV_A, task_id)[-1]
            self.assertEqual((task.current_work_seq, second.role, second.target_device), (second.seq, "handoff", DEV_B))
            self.assertIn("【返工】", second.body)
            self.assertIn("补充：已授权", second.body)
            self.assertIn("请处理 X", second.body)
        self.pump("vm", "win")
        with self.store("win") as store:
            [mirrored] = store.find_tasks(task_id)
            self.assertEqual(mirrored.current_work_seq, second.seq)
        # 旧 attempt 已过时：B 不能再对它汇报
        code, _, err = self.run_on("win", "report", task_id, "--attempt", "1", "--result", caller=as_agent(WORKER))
        self.assertEqual(code, cli.EXIT_REJECTED)
        self.assertIn("stale_attempt", err)

    def test_local_reviewer_changes_then_rework_clears_verdict(self) -> None:
        task_id = self.local_review_requested()
        code, out, err = self.run_on("vm", "report", task_id, "--changes", "--note", "补测试",
                                     caller=as_agent(LOCAL_REVIEW))
        self.assertEqual(code, 0, err)
        self.assertIn("发起设备已采纳", out)
        with self.store("vm") as store:
            [task] = store.find_tasks(task_id)
            self.assertEqual(task.state["verdict"], "changes_requested")
        code, out, err = self.run_on("vm", "retry", task_id, caller=as_agent(ORIGIN))
        self.assertEqual(code, 0, err)
        self.assertIn("次交接 → win 上的 codex@impl", out)
        with self.store("vm") as store:
            [task] = store.find_tasks(task_id)
            latest = store.attempts(DEV_A, task_id)[-1]
            self.assertIsNone(task.state["verdict"])  # 返工清掉上一轮 verdict
            self.assertIn("复核方", latest.body)
            self.assertIn("意见：补测试", latest.body)

    def test_retry_without_evidence_needs_force_and_pending_remote_needs_cancel_or_force(self) -> None:
        task_id = self.send()
        code, _, err = self.run_on("vm", "retry", task_id, caller=as_agent(ORIGIN))
        self.assertEqual(code, cli.EXIT_REJECTED)
        self.assertIn("still_pending", err)
        code, out, err = self.run_on("vm", "retry", task_id, "--force", caller=as_agent(ORIGIN))
        self.assertEqual(code, 0, err)
        self.assertIn("对方可能重复执行", out)

    def test_cancel_is_remote_request_and_b_suppresses_unsent_job(self) -> None:
        task_id = self.send()
        self.pump("vm", "win")
        code, out, err = self.run_on("vm", "cancel", task_id, caller=as_agent(ORIGIN))
        self.assertEqual(code, 0, err)
        self.assertIn("对方设备尚未确认", out)
        self.pump("vm", "win")
        self.assertEqual(self.deliver_on_b().calls, [])  # B 收到最新状态后不再投递
        self.pump("win", "vm")
        code, out, _ = self.run_on("vm", "status", task_id, "--json")
        self.assertEqual(json.loads(out)["attempts"][0]["delivery"], "cancelled")

    def test_mirror_archive_suppresses_unsent_job_without_touching_authority(self) -> None:
        task_id = self.send()
        self.pump("vm", "win")
        code, _, err = self.run_on("vm", "federation", "archive", task_id)
        self.assertEqual(code, cli.EXIT_REJECTED)
        self.assertIn("federation_archive_authority", err)
        code, out, err = self.run_on("win", "federation", "archive", task_id, "--origin-device", "vm")
        self.assertEqual(code, 0, err)
        self.assertIn("抑制 1 条", out)
        self.assertEqual(self.deliver_on_b().calls, [])
        with self.store("vm") as store:
            [task] = store.find_tasks(task_id)
            self.assertFalse(task.finished)


class BoundaryTests(FedCliCase):
    def test_withdraw_on_federation_task_exits_9_before_any_write(self) -> None:
        task_id = self.send()
        with patch.object(cli, "_check_sender") as local_flow:
            code, _, err = self.run_on("vm", "withdraw", task_id, "--attempt", "1")
        self.assertEqual(code, cli.EXIT_NOT_ENABLED)
        self.assertIn("federation_withdraw_unsupported", err)
        self.assertEqual(local_flow.call_count, 0)  # 写前退出：不进入本机撤回流程

    def test_local_task_wins_the_namespace_and_origin_device_selects_federation(self) -> None:
        fed_id = self.send()
        self.run_on("vm", "send", "--to", "codex@review", "-m", "本机任务", "--no-wait", caller=as_agent(ORIGIN))
        with cli.Store.open(self.states["vm"]) as local:
            [local_task] = local.list_tasks()
        # 让联邦任务与本机任务同 ID：无参数时只能指向本机，联邦必须带 --origin-device（§88.7）
        conn = sqlite3.connect(self.states["vm"] / FED_DB_NAME)
        with conn:
            for table in ("fed_tasks", "fed_attempts", "fed_routes", "fed_events"):
                conn.execute(f"UPDATE {table} SET task_id=? WHERE task_id=?", (local_task.id, fed_id))
        conn.close()
        code, out, err = self.run_on("vm", "status", local_task.id)
        self.assertEqual(code, 0, err)
        self.assertNotIn("跨设备任务", out)
        code, out, err = self.run_on("vm", "status", local_task.id, "--origin-device", "vm")
        self.assertEqual(code, 0, err)
        self.assertIn("跨设备任务", out)

    def test_local_hit_never_resolves_through_the_federation_store(self) -> None:
        # §93.3 起本机 status 会用只读连接打开联邦库查「后续任务」（设计要求本机账本与联邦库都查），所以不再断言零打开；
        # 本机命中时仍不经联邦库解析任务、不走可写的联邦运行时，联邦库真实损坏也不影响本机 status（§88.7）
        self.run_on("vm", "send", "--to", "codex@review", "-m", "本机任务", "--no-wait", caller=as_agent(ORIGIN))
        with cli.Store.open(self.states["vm"]) as local:
            [local_task] = local.list_tasks()
        with patch.object(fed_commands, "find_task", wraps=fed_commands.find_task) as resolved, \
                patch.object(fed_commands, "try_runtime", wraps=fed_commands.try_runtime) as probe, \
                patch.object(fed_commands, "open_runtime", wraps=fed_commands.open_runtime) as opened, \
                patch.object(FederatedStore, "open_readonly", wraps=FederatedStore.open_readonly) as readonly:
            code, out, err = self.run_on("vm", "status", local_task.id)
        self.assertEqual(code, 0, err)
        self.assertEqual((resolved.call_count, probe.call_count, opened.call_count), (0, 0, 0))
        self.assertEqual(readonly.call_count, 1)

        def steady(text: str) -> str:
            return re.sub(r"[0-9]+ 秒前", "N 秒前", text)  # 两次运行之间可能跨过一秒

        path = self.states["vm"] / FED_DB_NAME
        faults = [
            ("版本过新", lambda: self._raw_sql(path, "PRAGMA user_version=999")),
            ("表缺失", lambda: self._raw_sql(path, "PRAGMA user_version=1", "DROP TABLE fed_tasks")),
            ("垃圾文件", lambda: self._garbage(path)),
        ]
        for name, damage in faults:
            damage()
            with self.subTest(fault=name):
                broken = self.run_on("vm", "status", local_task.id)
                self.assertEqual((broken[0], steady(broken[1])), (0, steady(out)), broken[2])
                self.assertNotIn("Traceback", broken[2])

    @staticmethod
    def _raw_sql(path: Path, *statements: str) -> None:
        """不经产品代码直接改联邦库文件（制造真实结构故障）；不开外键，DROP 不会被子表拦下。"""
        connection = sqlite3.connect(path, isolation_level=None)
        try:
            for statement in statements:
                connection.execute(statement)
            connection.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        finally:
            connection.close()

    @staticmethod
    def _garbage(path: Path) -> None:
        for suffix in ("-wal", "-shm"):
            Path(f"{path}{suffix}").unlink(missing_ok=True)
        path.write_bytes(b"not a sqlite database" * 64)

    def test_windows_federation_report_checks_only_the_relevant_local_ref(self) -> None:
        task_id = self.delivered_task()
        seen: list[tuple[Any, list[Any]]] = []
        windows = type("Windows", (), {"name": "windows"})()
        runtime = fed_commands.open_runtime(self.states["win"])
        try:
            [task] = runtime.store.find_tasks(task_id)
            with patch.object(fed_commands, "get_platform", return_value=windows), \
                    patch("agentstatus_bridge.platforms.windows.commands.check_task",
                          side_effect=lambda view, attempts: seen.append((view, list(attempts)))):
                fed_commands.report(runtime, task=task, kind=ReportKind.ACK, attempt_seq=None, note=None, files=[],
                                    commit=None, manual=False, caller=as_agent(WORKER), caller_class="bypass",
                                    cwd=self.root)
        finally:
            runtime.close()
        [(view, attempts)] = seen
        # 远端发起方/复核方与其他 attempt 不交给本机 root 检查（§88.7）
        self.assertEqual((view.origin, view.reviewer), (None, None))
        self.assertEqual([item.target for item in attempts], [WORKER.ref])

    def test_windows_authority_side_report_checks_only_the_reviewer_ref(self) -> None:
        task_id = self.local_review_requested()
        seen: list[tuple[Any, list[Any]]] = []
        windows = type("Windows", (), {"name": "windows"})()
        runtime = fed_commands.open_runtime(self.states["vm"])
        try:
            [task] = runtime.store.find_tasks(task_id)
            with patch.object(fed_commands, "get_platform", return_value=windows), \
                    patch("agentstatus_bridge.platforms.windows.commands.check_task",
                          side_effect=lambda view, attempts: seen.append((view, list(attempts)))):
                fed_commands.report(runtime, task=task, kind=ReportKind.APPROVE, attempt_seq=None, note=None,
                                    files=[], commit=None, manual=False, caller=as_agent(LOCAL_REVIEW),
                                    caller_class="bypass", cwd=self.root)
        finally:
            runtime.close()
        [(view, attempts)] = seen
        # A 上发起方与复核方都是本机端点，远端工作 attempt 也在历史里：都不属于这次汇报的相关 ref
        self.assertEqual((view.origin, view.reviewer), (None, None))
        self.assertEqual([item.target for item in attempts], [LOCAL_REVIEW.ref])

    def test_pure_local_windows_task_keeps_the_full_ref_check(self) -> None:
        self.run_on("vm", "send", "--to", "codex@review", "-m", "本机任务", "--no-wait", caller=as_agent(ORIGIN))
        seen: list[tuple[Any, list[Any]]] = []
        windows = type("Windows", (), {"name": "windows"})()
        with cli.Store.open(self.states["vm"]) as local, \
                patch.object(cli, "get_platform", return_value=windows), \
                patch("agentstatus_bridge.platforms.windows.commands.check_task",
                      side_effect=lambda task, attempts: seen.append((task, list(attempts)))):
            [task] = local.list_tasks()
            cli._task(local, task.id)  # pyright: ignore[reportPrivateUsage]
            expected = local.attempts(task.id)
        [(checked, attempts)] = seen
        # 纯本机 Windows 写命令照旧核发起方/复核方与全部 attempt，不套联邦的缩小检查（§88.7）
        self.assertEqual(checked.origin, task.origin)
        self.assertIsNotNone(checked.origin)
        self.assertEqual(len(attempts), len(expected))

    def test_report_before_native_delivery_is_refused(self) -> None:
        task_id = self.send()
        self.pump("vm", "win")
        code, _, err = self.run_on("win", "report", task_id, "--result", caller=as_agent(WORKER))
        self.assertEqual(code, cli.EXIT_REJECTED)
        self.assertIn("attempt_not_sent", err)

    def test_close_after_accept_records_close_without_second_closure(self) -> None:
        task_id = self.delivered_task()
        self.run_on("win", "report", task_id, "--result", caller=as_agent(WORKER))
        self.pump("win", "vm")
        self.assertEqual(self.run_on("vm", "accept", task_id, caller=as_agent(ORIGIN))[0], 0)
        with self.store("vm") as store:
            before = len(store.attempts(DEV_A, task_id))
        code, out, err = self.run_on("vm", "close", task_id, "--reason", "收尾", caller=as_agent(ORIGIN))
        self.assertEqual(code, 0, err)
        self.assertIn("已停止追踪", out)
        self.assertNotIn("结束回执", out)
        with self.store("vm") as store:
            [task] = store.find_tasks(task_id)
            self.assertEqual((len(store.attempts(DEV_A, task_id)), task.state["closeReason"]), (before, "收尾"))
        self.assertIn("task_finished", self.run_on("vm", "close", task_id, caller=as_agent(ORIGIN))[2])

    def test_stalled_hint_only_after_thirty_minutes(self) -> None:
        task_id = self.send()
        runtime = fed_commands.open_runtime(self.states["vm"])
        try:
            [task] = runtime.store.find_tasks(task_id)
            created = runtime.store.attempts(DEV_A, task_id)[0].authority_state["createdAt"]
            self.assertFalse(fed_commands.stalled(runtime, task, now=created + 29 * 60 * 1000))
            self.assertTrue(fed_commands.stalled(runtime, task, now=created + 31 * 60 * 1000))
            lines = fed_commands.task_lines(runtime, task, now=created + 31 * 60 * 1000)
            self.assertIn("需处理：远端离线/传输未恢复", "\n".join(lines))
        finally:
            runtime.close()

    def test_relay_not_running_returns_6_after_l0_and_says_do_not_repeat(self) -> None:
        self.relay_up = False
        code, out, err = self.run_on("vm", "send", "--device", "win", "--to", "codex@impl", "-m", "X",
                                     caller=as_agent(ORIGIN))
        self.assertEqual(code, cli.EXIT_UNAVAILABLE)
        self.assertIn("请勿重复执行", err)
        self.assertIn("已记录", out)
        with self.store("vm") as store:
            self.assertEqual(len(store.tasks()), 1)

    def test_disabled_rejects_writes_but_keeps_reads(self) -> None:
        task_id = self.delivered_task()
        self.assertEqual(self.run_on("win", "federation", "disable")[0], 0)
        code, _, err = self.run_on("win", "report", task_id, "--result", caller=as_agent(WORKER))
        self.assertEqual(code, cli.EXIT_NOT_ENABLED)
        self.assertIn("federation_disabled", err)
        self.assertEqual(self.run_on("win", "status", task_id)[0], 0)
        code, _, err = self.run_on("win", "send", "--device", "vm", "--to", f"claude@id:{CLAUDE_A}", "-m", "X",
                                   caller=as_agent(WORKER))
        self.assertEqual(code, cli.EXIT_NOT_ENABLED)
        self.assertIn("federation_disabled", err)
        # 再启用接续同一 ID 与同一库
        code, out, err = self.run_on("win", "federation", "enable", "--hub-host", "hub.example", "--hub-user", "u",
                                     "--hub-id", HUB, "--device-id", DEV_B, "--name", "win", "--identity-file", "/k",
                                     "--known-hosts-file", "/kh")
        self.assertEqual(code, 0, err)
        self.assertIn("沿用既有联邦库", out)

    def test_enable_refuses_a_different_identity_and_bad_names(self) -> None:
        code, _, err = self.run_on("vm", "federation", "enable", "--hub-host", "h", "--hub-user", "u", "--hub-id", HUB,
                                   "--device-id", DEV_C, "--name", "vm", "--identity-file", "/k",
                                   "--known-hosts-file", "/kh")
        self.assertEqual(code, cli.EXIT_REJECTED)
        self.assertIn("federation_already_configured", err)
        fresh = self.root / "fresh"
        fresh.mkdir(mode=0o700)
        self.states["fresh"] = fresh
        code, _, err = self.run_on("fresh", "federation", "enable", "--hub-host", "h", "--hub-user", "u", "--hub-id",
                                   HUB, "--device-id", DEV_C, "--name", "bad name", "--identity-file", "/k",
                                   "--known-hosts-file", "/kh")
        self.assertEqual(code, cli.EXIT_REJECTED)
        self.assertIn("federation_device_name_invalid", err)
        self.assertFalse((fresh / FED_DB_NAME).exists())

    def test_targets_resolve_only_from_the_cached_directory(self) -> None:
        code, _, err = self.run_on("vm", "send", "--device", "win", "--to", "codex@id:019a0000-9999-7999-8999-999999999999",
                                   "-m", "X", caller=as_agent(ORIGIN))
        self.assertEqual(code, cli.EXIT_TARGET)
        self.assertIn("remote_endpoint_unresolved", err)
        code, _, err = self.run_on("vm", "send", "--device", "nowhere", "--to", "codex@impl", "-m", "X",
                                   caller=as_agent(ORIGIN))
        self.assertEqual(code, cli.EXIT_TARGET)
        self.assertIn("device_unknown", err)
        # --device 指本机：两个参与方都在本机，就是本机任务（按本机目录解析，不进联邦库）
        code, _, err = self.run_on("vm", "send", "--device", "vm", "--to", "codex@impl", "-m", "X",
                                   caller=as_agent(ORIGIN))
        self.assertEqual(code, cli.EXIT_TARGET)
        self.assertIn("target_not_found", err)
        code, _, err = self.run_on("vm", "send", "--device", "vm", "--to", "codex@review", "-m", "X", "--no-wait",
                                   caller=as_agent(ORIGIN))
        self.assertIn(code, (0, cli.EXIT_UNAVAILABLE), err)  # 本机 send：worker 不在时照常返回 6
        with cli.Store.open(self.states["vm"]) as local, self.store("vm") as store:
            self.assertEqual((len(local.list_tasks()), len(store.tasks())), (1, 0))

    def test_unverified_or_ambiguous_remote_names_print_copyable_candidates(self) -> None:
        # §91.2.2「提示 peers --device 及全 ID」：候选给成可直接照抄的完整写法（带 --device），不只留在异常里
        first, second = "019a0000-1111-7222-8333-44445555cccc", "019a0000-1111-7222-8333-44445555dddd"
        rows = [{"provider": "codex", "nativeId": native, "endpointId": native[-8:].ljust(32, "0"), "endpointRevision": 1,
                 "inbox": True, "eligible": True, "namesVerified": False, "name": "dup"} for native in (first, second)]
        with self.store("vm") as store:
            store.put_device_state(device_id=DEV_C, name="wsl", revision=1, snapshot={
                "endpoints": rows, "complete": True, "providers": {"codex": True}, "namePolicy": "agent-native-v1"},
                last_seen=now_ms(), state="online")
        code, _, err = self.run_on("vm", "send", "--device", "wsl", "--to", "codex@dup", "-m", "X", caller=as_agent(ORIGIN))
        self.assertEqual(code, cli.EXIT_TARGET, err)
        self.assertIn("target_names_unverified", err)
        self.assertIn(f"可选目标：--device wsl --to codex@id:{first}、--device wsl --to codex@id:{second}", err)
        code, _, err = self.run_on("vm", "send", "--device", "wsl", "--to", "codex@id:019a0000", "-m", "X",
                                   caller=as_agent(ORIGIN))
        self.assertEqual(code, cli.EXIT_TARGET, err)
        self.assertIn("target_ambiguous", err)
        self.assertIn(f"--device wsl --to codex@id:{first}", err)
        # 复核方路径按复核方的参数名给（不能把复核方抄成执行方）
        code, _, err = self.run_on("vm", "send", "--to", "codex@review", "--review-device", "wsl", "--review-by", "codex@dup",
                                   "-m", "X", caller=as_agent(ORIGIN))
        self.assertEqual(code, cli.EXIT_TARGET, err)
        self.assertIn(f"可选目标：--review-device wsl --review-by codex@id:{first}、--review-device wsl --review-by "
                      f"codex@id:{second}", err)
        self.assertNotIn("--device wsl --to", err)
        # 设备引用不唯一时候选是完整 deviceId（两台设备登记成同一个名字）
        with self.store("vm") as store:
            store.put_device_state(device_id="e" * 32, name="wsl", revision=1, snapshot={
                "endpoints": [], "complete": True, "providers": {"codex": True}, "namePolicy": "agent-native-v1"},
                last_seen=now_ms(), state="online")
        code, _, err = self.run_on("vm", "send", "--device", "wsl", "--to", "codex@dup", "-m", "X", caller=as_agent(ORIGIN))
        self.assertEqual(code, cli.EXIT_TARGET, err)
        self.assertIn(f"可选设备：--device {DEV_C}、--device {'e' * 32}", err)
        # 复核方路径上设备引用不唯一：设备候选也按复核方的参数名给（两方 r3 P3）
        code, _, err = self.run_on("vm", "send", "--to", "codex@review", "--review-device", "wsl", "--review-by", "codex@dup",
                                   "-m", "X", caller=as_agent(ORIGIN))
        self.assertEqual(code, cli.EXIT_TARGET, err)
        self.assertIn(f"可选设备：--review-device {DEV_C}、--review-device {'e' * 32}", err)

    def test_reviewer_defaults_to_origin_device_and_third_device_is_refused_before_write(self) -> None:
        code, out, err = self.run_on("vm", "send", "--device", "win", "--to", "codex@impl", "--review-by",
                                     "codex@review", "-m", "X", "--json", caller=as_agent(ORIGIN))
        self.assertEqual(code, 0, err)
        with self.store("vm") as store:
            [task] = store.find_tasks(json.loads(out)["id"])
            reviewer = task.reviewer()
            assert reviewer is not None
            self.assertEqual((reviewer.remote.device_id, task.state["flow"]), (DEV_A, "review"))
            store.put_device_state(device_id=DEV_C, name="wsl", revision=1, snapshot={
                "endpoints": [{"provider": "codex", "nativeId": THREAD_B.replace("b", "c"), "endpointId": "e" * 32,
                               "endpointRevision": 1, "inbox": True, "eligible": True, "namesVerified": True,
                               "name": "other"}], "complete": True, "providers": {"codex": True}},
                last_seen=now_ms(), state="online")  # 名字解析要求目录完整且新鲜（§91.6），这里只测三设备拒绝
            before = len(store.tasks())
        code, _, err = self.run_on("vm", "send", "--device", "win", "--to", "codex@impl", "--review-by",
                                   "codex@other", "--review-device", "wsl", "-m", "X", caller=as_agent(ORIGIN))
        self.assertEqual(code, cli.EXIT_REJECTED)
        self.assertIn("federation_review_device_unsupported", err)
        with self.store("vm") as store:
            self.assertEqual(len(store.tasks()), before)
        code, _, err = self.run_on("vm", "send", "--to", "codex@review", "--review-device", "win", "-m", "X",
                                   caller=as_agent(ORIGIN))
        self.assertEqual(code, cli.EXIT_REJECTED)
        self.assertIn("review_device_requires_reviewer", err)

    def test_local_target_with_remote_reviewer_round_trip(self) -> None:
        note = self.root / "spec.md"
        note.write_text("规格", encoding="utf-8")
        code, out, err = self.run_on("vm", "send", "--to", "codex@review", "--review-device", "win", "--review-by",
                                     f"codex@id:{THREAD_B}", "-m", "本机实现、远端复核", "--ref", str(note), "--json",
                                     caller=as_agent(ORIGIN))
        self.assertEqual(code, 0, err)
        task_id = json.loads(out)["id"]
        transport = RecordingTransport(Provider.CODEX)
        with self.store("vm") as store:  # A 的 worker 把工作投给本机目标，附件从冻结副本落本机交付叶
            FederationDispatcher(store, self.ident("vm"), RelayPaths(self.states["vm"]),
                                 discover=lambda: [LOCAL_REVIEW], transports={Provider.CODEX: transport},
                                 reply_address=None, command="ab").run_once()
        self.assertEqual(len(transport.calls), 1)
        self.assertIn("spec.md", transport.calls[0][1])
        code, out, err = self.run_on("vm", "report", task_id, "--result", "--note", "完成",
                                     caller=as_agent(LOCAL_REVIEW))
        self.assertEqual(code, 0, err)
        self.assertGreaterEqual(self.pump("vm", "win"), 1)  # 复核请求交给 B
        self.assertEqual(len(self.deliver_on_b().calls), 1)
        code, _, err = self.run_on("win", "report", task_id, "--origin-device", "vm", "--approve",
                                   caller=as_agent(WORKER))
        self.assertEqual(code, 0, err)
        self.pump("win", "vm")
        code, out, err = self.run_on("vm", "status", task_id, "--json")
        self.assertEqual(json.loads(out)["phase"], "awaiting_acceptance", err)

    def test_copied_cross_device_identifiers_never_hit_a_same_named_local_session(self) -> None:
        """T7（§91.4.2）：B 本机也有叫 lead 的 Claude、A 本机也有叫 impl 的 Codex；照抄跨设备消息头、帧发送方名与
        自动正文里的标识却漏了 --device，只会找不到，不会命中本机同名的另一个会话。"""
        lead_b = endpoint(ref(Provider.CLAUDE, "0000000b-1111-4222-8333-444444444444", pid=32010, start="790",
                              label="lead"), name="lead")
        impl_a = endpoint(ref(Provider.CODEX, "019a0000-1111-7222-8333-44445555dddd", pid=31010, start="510",
                              label="impl"), name="impl")
        on_b, on_a = with_name_views([WORKER, lead_b]), with_name_views([ORIGIN, LOCAL_REVIEW, impl_a])
        self.assertIs(resolve_target("claude@lead", on_b), on_b[1])  # 同名风险是真的：裸名会选中 B 本机的 lead
        task_id = self.delivered_task()
        with self.store("win") as store:
            [attempt] = [item for item in store.attempts(DEV_A, task_id) if item.role == "handoff"]
        # 帧与消息头里的发送方：按 B 的投递渲染取出（与真实投递同一个函数）
        recorder = RecordingTransport(Provider.CODEX)
        with self.store("win") as store:
            dispatcher = FederationDispatcher(store, self.ident("win"), RelayPaths(self.states["win"]),
                                              discover=lambda: [WORKER], transports={Provider.CODEX: recorder},
                                              reply_address=None, command="ab")
            text, context = dispatcher._render(  # pyright: ignore[reportPrivateUsage]
                store.get_task(DEV_A, task_id), attempt, None, Provider.CODEX)  # type: ignore[arg-type]
        parsed = parse_header(text)
        assert parsed is not None and parsed.sender is not None
        copied = [parsed.sender, context.sender_name.split("（", 1)[0]]
        self.assertEqual(copied, [f"claude@id:{CLAUDE_A}"] * 2)
        for token in copied:
            with self.assertRaises(ResolveError) as caught:
                resolve_target(token, on_b)
            self.assertEqual(caught.exception.code, "target_not_found")
        # A 上的结果通知：执行方标识照抄到 A 本机也不会命中 A 本机的 impl
        self.assertEqual(self.run_on("win", "report", task_id, "--origin-device", "vm", "--result",
                                     caller=as_agent(WORKER))[0], 0)
        self.pump("win", "vm")
        with self.store("vm") as store:
            notice = store.attempts(DEV_A, task_id)[-1]
        self.assertIn(f"（codex@id:{THREAD_B}）", notice.body)
        with self.assertRaises(ResolveError):
            resolve_target(f"codex@id:{THREAD_B}", on_a)
        self.assertIs(resolve_target("codex@impl", on_a), on_a[2])

    def test_unnamed_remote_target_and_unknown_device_print_full_ids(self) -> None:
        unnamed = endpoint(ref(Provider.CODEX, THREAD_B.replace("b", "e"), pid=32003, start="778"), native_name=None)
        with self.store("win") as store:
            snapshot = directory.snapshot(store, DEV_B, with_name_views([WORKER, unnamed]),
                                          provider_complete={"codex": True})
        with self.store("vm") as store:
            store.put_device_state(device_id=DEV_B, name="win", revision=2, snapshot=snapshot, last_seen=now_ms(),
                                   state="online")
            runtime = SimpleNamespace(ident=SimpleNamespace(device_id=DEV_A, device_name="vm"), store=store)
            self.assertEqual(fed_commands.device_name(runtime, DEV_C), DEV_C)  # type: ignore[arg-type]  未登记用完整 ID
        code, out, err = self.run_on("vm", "send", "--device", "win", "--to", f"codex@id:{unnamed.ref.native_id}",
                                     "-m", "X", caller=as_agent(ORIGIN))
        self.assertEqual(code, cli.EXIT_OK, err)
        self.assertIn(f"交给 win 上的 codex@id:{unnamed.ref.native_id}：", out)  # 没有已核实主名：完整 ID，不截 8 位

    def test_publish_names_off_keeps_the_local_target_label_off_the_network(self) -> None:
        self.endpoints["vm"] = with_name_views([ORIGIN, LOCAL_REVIEW])
        labels: list[str | None] = []
        for publish in (True, False):
            config = self.states["vm"] / "federation.json"
            data = json.loads(config.read_text(encoding="utf-8"))
            data["directory"]["publishNames"] = publish
            config.write_text(json.dumps(data), encoding="utf-8")
            code, out, err = self.run_on("vm", "send", "--to", "codex@review", "--review-device", "win",
                                         "--review-by", f"codex@id:{THREAD_B}", "-m", "X", "--json",
                                         caller=as_agent(ORIGIN))
            self.assertEqual(code, 0, err)
            with self.store("vm") as store:
                [first, *_] = store.attempts(DEV_A, json.loads(out)["id"])
                labels.append(first.target.remote.display_label)
        self.assertEqual(labels, ["review", None])

    def test_attachments_are_frozen_at_send_and_listed_per_item(self) -> None:
        note = self.root / "spec.md"
        note.write_text("规格", encoding="utf-8")
        code, out, err = self.run_on("vm", "send", "--device", "win", "--to", "codex@impl", "-m", "X",
                                     "--ref", str(note), caller=as_agent(ORIGIN))
        self.assertEqual(code, 0, err)
        self.assertIn("附件：1 个随消息传输", out)
        with self.store("vm") as store:
            [task] = store.tasks()
        code, out, _ = self.run_on("vm", "status", task.task_id, "--json")
        [item] = json.loads(out)["attempts"][0]["attachments"]
        self.assertEqual((item["name"], item["state"], item["transfer"]), ("spec.md", "staged", "blob"))


class BudgetCliTests(FedCliCase):
    def test_send_with_attachment_over_budget_is_refused_before_writing(self) -> None:
        note = self.root / "spec.md"
        note.write_text("规格内容", encoding="utf-8")
        with patch.object(fed_commands.budget, "available", return_value=note.stat().st_size - 1):
            code, _, err = self.run_on("vm", "send", "--device", "win", "--to", "codex@impl", "-m", "X",
                                       "--ref", str(note), caller=as_agent(ORIGIN))
        self.assertNotEqual(code, 0)
        self.assertIn("[device_storage_full]", err)
        with self.store("vm") as store:
            self.assertEqual(store.tasks(), [])  # 写前拒绝：没有半建的任务
        code, _, err = self.run_on("vm", "send", "--device", "win", "--to", "codex@impl", "-m", "X",
                                   caller=as_agent(ORIGIN))
        self.assertEqual(code, 0, err)  # 不带附件不受预算影响


class RetentionDisplayTests(FedCliCase):
    def test_status_says_attachment_is_past_retention(self) -> None:
        note = self.root / "spec.md"
        note.write_text("规格", encoding="utf-8")
        code, out, err = self.run_on("vm", "send", "--device", "win", "--to", "codex@impl", "-m", "X", "--ref",
                                     str(note), "--json", caller=as_agent(ORIGIN))
        self.assertEqual(code, 0, err)
        task_id = json.loads(out)["id"]
        self.assertEqual(self.run_on("vm", "close", task_id, "--reason", "收尾", caller=as_agent(ORIGIN))[0], 0)
        with self.store("vm") as store:
            with store.transaction() as conn:  # 只为构造：发件都已落账、本机作业都已结束
                conn.execute("UPDATE fed_outbox SET state='received'")
                conn.execute("UPDATE fed_native_sends SET state='finished' WHERE state='prepared'")
            day = 86_400_000
            result = retention.sweep(store, RelayPaths(self.states["vm"]), now=now_ms() + 31 * day,
                                     wall_ms=now_ms() + 2 * day)
            self.assertEqual(result.compacted, 1)
        code, out, err = self.run_on("vm", "status", task_id)
        self.assertEqual(code, 0, err)
        self.assertIn("附件 spec.md：已过留存期", out)
        code, out, _ = self.run_on("vm", "status", task_id, "--json")
        [item] = json.loads(out)["attempts"][0]["attachments"]
        self.assertEqual(item["state"], "expired")  # JSON 保留机器可读状态


class ParkedRevivalTests(FedCliCase):
    """停泊的跨设备作业：查询命令与扩展定时补查也会补拉 worker，与本机 §79 同口径（Opus r2-P2-2）。"""

    def queued_on_b(self) -> str:
        code, out, err = self.run_on("vm", "send", "--device", "win", "--to", f"codex@id:{THREAD_B}", "-m", "请处理",
                                     caller=as_agent(ORIGIN))
        self.assertEqual(code, 0, err)
        self.pump("vm", "win")
        Store.open(self.states["win"]).close()  # B 也用过本机 ab：有本机账本
        return out.split()[1]

    def test_query_commands_revive_worker_for_federated_work(self) -> None:
        task = self.queued_on_b()
        starter = cli.ensure_worker
        assert isinstance(starter, Mock)
        for argv in (("tasks",), ("status", task), ("summary", "--if-stale")):
            starter.reset_mock()
            code, _, err = self.run_on("win", *argv, caller=as_agent(ORIGIN))
            self.assertEqual(code, 0, (argv, err))
            self.assertGreaterEqual(starter.call_count, 1, argv)

    def test_federation_only_device_revives_without_creating_local_ledger(self) -> None:
        # 只承接跨设备任务的 B 可以没有本机库：查询照样补拉，也不顺手建本机库（Codex r3-P2-02）
        code, out, err = self.run_on("vm", "send", "--device", "win", "--to", f"codex@id:{THREAD_B}", "-m", "请处理",
                                     caller=as_agent(ORIGIN))
        self.assertEqual(code, 0, err)
        self.pump("vm", "win")
        self.assertFalse((self.states["win"] / DB_NAME).exists())
        starter = cli.ensure_worker
        assert isinstance(starter, Mock)
        for argv in (("status", out.split()[1]), ("summary", "--if-stale")):
            starter.reset_mock()
            self.run_on("win", *argv, caller=as_agent(ORIGIN))
            self.assertGreaterEqual(starter.call_count, 1, argv)
        self.assertFalse((self.states["win"] / DB_NAME).exists())

    def test_windows_default_peers_revives(self) -> None:
        # Windows 默认 peers 不开本机账本、不走通用补查：只按联邦待办补拉（只测控制流，不进 Win32）
        self.queued_on_b()
        platform = SimpleNamespace(name="windows", transport=object())
        evidence = SimpleNamespace(endpoints=(), duplicates=(), complete=True, reason="complete")
        starter = cli.ensure_worker
        assert isinstance(starter, Mock)
        starter.reset_mock()
        with patch.dict(os.environ, {"AB_STATE_DIR": str(self.states["win"])}), \
                patch.object(cli, "get_platform", return_value=platform), \
                patch("agentstatus_bridge.platforms.windows.commands.claude_evidence", return_value=evidence), \
                redirect_stdout(StringIO()):
            code = cli._run_command(cli.build_parser().parse_args(["peers"]))  # pyright: ignore[reportPrivateUsage]
        self.assertEqual((code, starter.call_count), (0, 1))

    def test_pending_origin_reminder_revives_worker_on_authority(self) -> None:
        # A 上结果通知已交给发起方、还有一条提醒未排：没有可领的投递作业，也要补拉 worker 来排提醒，
        # 与本机 §45.28 驻留同口径；worker 崩溃后不至于漏掉这条提醒（Opus r3-P3-1）
        task_id = self.delivered_task()
        code, _, err = self.run_on("win", "report", task_id, "--origin-device", "vm", "--result",
                                   caller=as_agent(WORKER))
        self.assertEqual(code, 0, err)
        self.pump("win", "vm")
        claude = RecordingTransport(Provider.CLAUDE, DeliveryOutcome(Delivery.DELIVERED, "claude_delivered"))
        with self.store("vm") as store:
            FederationDispatcher(store, self.ident("vm"), RelayPaths(self.states["vm"]), discover=lambda: [ORIGIN],
                                 transports={Provider.CLAUDE: claude}, reply_address="uds:/x",
                                 command="ab").run_once()
            self.assertEqual(mirror.wake_candidates(store, self.ident("vm"), now=now_ms()), set())
        self.assertEqual(len(claude.calls), 1)
        with patch.dict(os.environ, {"AB_STATE_DIR": str(self.states["vm"])}):
            self.assertTrue(cli._federation_needs_worker(time.time()))  # pyright: ignore[reportPrivateUsage]
        self.assertEqual(self.run_on("vm", "accept", task_id, caller=as_agent(ORIGIN))[0], 0)
        with patch.dict(os.environ, {"AB_STATE_DIR": str(self.states["vm"])}):
            self.assertFalse(cli._federation_needs_worker(time.time()))  # pyright: ignore[reportPrivateUsage]

    def test_no_revive_without_workable_federated_work(self) -> None:
        self.queued_on_b()
        with self.store("win") as store:
            store.set_meta("enabled", "0")  # 停用：作业现在处理不了
        starter = cli.ensure_worker
        assert isinstance(starter, Mock)
        starter.reset_mock()
        code, _, err = self.run_on("win", "tasks", caller=as_agent(ORIGIN))
        self.assertEqual(code, 0, err)
        self.assertEqual(starter.call_count, 0)


class RebuildTests(FedCliCase):
    def test_rebuild_freezes_old_hub_routes_and_new_tasks_flow(self) -> None:
        old_task = self.send()
        self.pump("vm", "win")
        self.assertEqual(self.run_on("vm", "pause", old_task, caller=as_agent(ORIGIN))[0], 0)
        with self.store("vm") as store:
            [pending] = store.outbox()
            store.set_outbox_state(pending["msg_id"], state="accepted")  # 旧 hub 已收、等收据
            store.set_meta("hubStateLost", "1")  # relay 握手发现 hubId 变化
        new_hub = "e" * 32
        code, out, err = self.run_on("vm", "federation", "rebuild", "--hub-id", new_hub)
        self.assertEqual(code, 0, err)
        self.assertIn("已切换到新 hub", out)
        self.assertEqual(self.run_on("win", "federation", "rebuild", "--hub-id", new_hub)[0], 0)
        self.hub = new_hub
        with self.store("vm") as store:
            self.assertEqual((store.meta("hubId"), store.meta("hubStateLost")), (new_hub, ""))
            frozen = store.outbox_item(pending["msg_id"])
            assert frozen is not None
            self.assertEqual(frozen["state"], "revoked")  # 不再向新 hub 查旧收据
        self.assertEqual(json.loads((self.states["vm"] / "federation.json").read_text())["hubId"], new_hub)
        # 旧 hub 路由上的未投作业冻结：不自动接到新 hub
        self.assertEqual(self.deliver_on_b().calls, [])
        # A 本机 close 旧任务：后续发件在提交时冻结（不转投新 hub、不当作未投证据）
        self.assertEqual(self.run_on("vm", "close", old_task, caller=as_agent(ORIGIN))[0], 0)
        calls: list[str] = []

        class Conn:
            def call(self, name: str, **_kwargs: Any) -> dict[str, Any]:
                calls.append(name)
                return {}

        with self.store("vm") as store:
            relay = Relay(store, self.ident("vm"), FederationConfig(
                enabled=True, hub_id=new_hub, device_id=DEV_A, device_name="vm", host="h", user="u",
                expected_state_root=str(self.states["vm"])), RelayPaths(self.states["vm"]), connect=lambda: None)  # type: ignore[arg-type,return-value]
            relay.conn = Conn()  # type: ignore[assignment]
            relay._submit_outbox()  # pyright: ignore[reportPrivateUsage]
            states = {item["state"] for item in store.outbox(states=("ready", "submitting", "revoked"), limit=64)}
            attempt = store.attempts(DEV_A, old_task)[0]
        self.assertEqual((calls, states), ([], {"revoked"}))
        self.assertEqual(attempt.delivery.get("state", "pending"), "pending")  # 不是已证明未投
        # 新 hub 上的新任务照常流动
        self.send()
        self.assertEqual(self.pump("vm", "win"), 1)
        self.assertEqual(len(self.deliver_on_b().calls), 1)

    def test_rebuild_identity_rules(self) -> None:
        code, _, err = self.run_on("vm", "federation", "rebuild", "--hub-id", HUB)
        self.assertEqual(code, cli.EXIT_REJECTED)
        self.assertIn("federation_rebuild_same_hub", err)
        code, _, err = self.run_on("vm", "federation", "rebuild", "--hub-id", "e" * 32, "--device-id", DEV_C)
        self.assertIn("federation_rebuild_device_mismatch", err)
        (self.states["win"] / FED_DB_NAME).unlink()  # 本机联邦库丢失
        code, _, err = self.run_on("win", "federation", "rebuild", "--hub-id", "e" * 32)
        self.assertIn("federation_rebuild_needs_new_device", err)
        code, out, err = self.run_on("win", "federation", "rebuild", "--hub-id", "e" * 32, "--device-id", DEV_C)
        self.assertEqual(code, 0, err)
        self.assertIn("新设备身份", out)
        self.assertTrue(any(path.name.startswith("federation.json.lost-") for path in self.states["win"].iterdir()))
        with self.store("win") as store:
            self.assertEqual((store.device_id(), store.meta("hubId")), (DEV_C, "e" * 32))


class ListingTests(FedCliCase):
    def test_peers_device_and_all_devices(self) -> None:
        code, out, err = self.run_on("vm", "peers", "--device", "win")
        self.assertEqual(code, 0, err)
        self.assertIn(f"target=--device win --to codex@id:{THREAD_B}", out)
        code, out, _ = self.run_on("vm", "peers", "--device", "win", "--json")
        [device] = json.loads(out)["devices"]
        self.assertEqual((device["device"], device["peers"][0]["scope"]), ("win", "remote"))
        self.assertNotIn("pid", device["peers"][0]["remoteRef"])
        code, out, err = self.run_on("vm", "peers", "--all-devices")
        self.assertEqual(code, 0, err)
        self.assertIn("（本机）", out)
        self.assertIn("设备 win", out)

    def test_linux_all_devices_is_the_local_list_then_remote_lines(self) -> None:
        # §94.6 回归：Linux 输出不变——本机标题、与不带参数 peers 逐字节相同的本机列表、远端设备行；
        # JSON 是不带参数 peers --json 的文档再加 devices（Windows 按这个形状补齐）
        with patch.dict(os.environ, {"AB_DEVICE": "vmbox"}):
            plain = self.run_on("vm", "peers")[1]
            text = self.run_on("vm", "peers", "--all-devices")[1]
            plain_document = json.loads(self.run_on("vm", "peers", "--json")[1])
            document = json.loads(self.run_on("vm", "peers", "--all-devices", "--json")[1])
        with self.store("vm") as store:
            remote = directory.peer_lines(store, None, now=now_ms())
            devices = directory.peer_devices(store, None, now=now_ms())
        self.assertTrue(plain_document["peers"] and remote)
        self.assertEqual(text, "设备 vmbox（本机）：\n" + plain + "".join(line + "\n" for line in remote))
        self.assertEqual(document, {**plain_document, "devices": json.loads(json.dumps(devices))})

    def test_tasks_merges_federation_and_survives_unreadable_federation_store(self) -> None:
        task_id = self.send()
        code, out, err = self.run_on("vm", "tasks")
        self.assertEqual(code, 0, err)
        self.assertIn(task_id[:8], out)
        self.assertIn("跨设备·本机发起", out)
        code, out, _ = self.run_on("vm", "tasks", "--json")
        self.assertEqual(json.loads(out)["federation"][0]["id"], task_id)
        (self.states["vm"] / FED_DB_NAME).rename(self.states["vm"] / "moved.sqlite3")
        code, out, err = self.run_on("vm", "tasks")
        self.assertEqual(code, 0, err)
        self.assertIn("联邦库不可读", out)

    def test_unconfigured_machine_output_is_unchanged(self) -> None:
        bare = self.root / "bare"
        bare.mkdir(mode=0o700)
        self.states["bare"] = bare
        self.endpoints["bare"] = []
        code, out, _ = self.run_on("bare", "tasks", "--json")
        self.assertEqual(json.loads(out), {"tasks": []})
        code, out, _ = self.run_on("bare", "doctor", "--json")
        self.assertNotIn("federation", json.loads(out))
        self.assertFalse((bare / FED_DB_NAME).exists())

    def test_federation_status_and_doctor_projection(self) -> None:
        self.send()
        self.relay_up = False
        code, out, err = self.run_on("vm", "federation", "status", "--json")
        self.assertEqual(code, 0, err)
        projection = json.loads(out)["federation"]
        self.assertEqual((projection["state"], projection["reason"], projection["outboxPending"]),
                         ("offline", "relay_not_running", 1))
        self.assertTrue(projection["ledgerReadable"])
        code, out, _ = self.run_on("vm", "doctor", "--json")
        checks = json.loads(out)
        self.assertEqual(checks["federation"]["state"], "offline")
        self.assertIn("ledgerOk", checks)  # 本机账本结论独立
        (self.states["vm"] / FED_DB_NAME).rename(self.states["vm"] / "moved.sqlite3")
        projection = fed_commands.doctor_projection(self.states["vm"])
        assert projection is not None
        self.assertEqual((projection["ledgerReadable"], projection["storageReason"]),
                         (False, "federation_store_unavailable"))


class UnconfiguredMachineTests(unittest.TestCase):
    def test_local_commands_do_not_load_federation_implementation(self) -> None:
        # 实现决定 D20：没有 federation.json 的机器不导入联邦实现（Opus 审计 P3-9）；
        # 只允许包本身与 cli 顶层要捕获的 FedCliError 所在的 errors 模块
        script = (
            "import contextlib, io, json, sys\n"
            "from agentstatus_bridge import cli\n"
            "with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):\n"
            "    for argv in (['status', 'abcd1234'], ['tasks']):\n"
            "        cli.main(argv)\n"
            "print(json.dumps(sorted(m for m in sys.modules if m.startswith('agentstatus_bridge.federation'))))\n")
        src = Path(__file__).resolve().parents[1] / "src"
        with tempfile.TemporaryDirectory() as home:
            state = Path(home) / "state"
            env = {"HOME": home, "AB_STATE_DIR": str(state), "PATH": "/usr/bin:/bin", "LANG": "C.UTF-8",
                   "PYTHONPATH": str(src), "XDG_RUNTIME_DIR": str(Path(home) / "run")}
            result = subprocess.run([sys.executable, "-c", script], env=env, capture_output=True, text=True,
                                    timeout=120)
            self.assertEqual(result.returncode, 0, result.stderr)
            loaded = json.loads(result.stdout.strip().splitlines()[-1])
            self.assertFalse((state / "federation.sqlite3").exists())
        self.assertLessEqual(set(loaded), {"agentstatus_bridge.federation", "agentstatus_bridge.federation.errors"},
                             loaded)


class RelayRuntimeTests(unittest.TestCase):
    def test_should_stop_ends_an_open_connection_and_backoff_wait(self) -> None:
        connects: list[int] = []

        class Stop(Exception):
            pass

        relay = Relay.__new__(Relay)
        relay.config = FederationConfig(enabled=True, hub_id=HUB, device_id=DEV_A, device_name="vm", host="h",
                                        user="u", expected_state_root="/x")
        flags = {"stop": False}
        waits: list[float] = []

        def connect_and_run(**kwargs: Any) -> str:
            connects.append(1)
            self.assertIn("should_stop", kwargs)
            return "hub_unavailable"

        relay.connect_and_run = connect_and_run  # type: ignore[method-assign]
        relay._clock = lambda: 0  # pyright: ignore[reportPrivateUsage]  半构造对象：退避期间的留存回收不在本例范围
        relay._retention_tick = lambda _now: None  # type: ignore[method-assign]  # pyright: ignore[reportPrivateUsage]
        relay._on_tick = lambda: None  # pyright: ignore[reportPrivateUsage]  诊断发布点（§90.6）不在本例范围
        relay.store = Mock()  # 停止时尽力写 offline（§90.5）

        def wait(seconds: float) -> None:
            waits.append(seconds)
            if len(waits) == 3:
                flags["stop"] = True

        self.assertEqual(relay.run_forever(wait=wait, should_stop=lambda: flags["stop"]), "stopped")
        self.assertEqual(connects, [1])
        self.assertEqual(waits, [1.0, 1.0, 1.0])  # 退避分段等待，停用后一秒内退出

    def test_worker_starter_backs_off_after_failures(self) -> None:
        now = [0.0]
        calls: list[Path] = []

        def start(root: Path) -> bool:
            calls.append(root)
            raise OSError("spawn failed")

        on_work = fed_commands.worker_starter(Path("/state"), start=start, clock=lambda: now[0])
        on_work()
        on_work()  # 退避期内不再尝试
        now[0] = 10.0
        on_work()
        now[0] = 39.0
        on_work()  # 第二次失败后退避 30 秒
        now[0] = 40.0
        on_work()
        self.assertEqual(len(calls), 3)

    def test_worker_started_by_relay_follows_the_service_env_contract(self) -> None:
        from agentstatus_bridge import worker
        from agentstatus_bridge.platforms.linux.lifecycle import LinuxLifecycle

        spawned: dict[str, Any] = {}

        class Lifecycle:
            """真实环境整理 + 记录型拉起：绝不起真实子进程（get_platform() 每次新建平台对象，不能只 patch 实例）。"""

            worker_environment = staticmethod(LinuxLifecycle.worker_environment)

            @staticmethod
            def spawn_worker(directory: Path, env: dict[str, str]) -> None:
                spawned.update(directory=directory, env=dict(env))

        platform = type("Platform", (), {"name": "linux", "lifecycle": Lifecycle})()
        service_env = {"HOME": "/home/u", "PATH": "/usr/bin:/bin", "XDG_RUNTIME_DIR": "/run/user/1000",
                       "AB_COMMAND": "ab", "CODEX_HOME": "/x/codex", "AB_CLAUDE_SESSIONS_DIR": "/x/claude",
                       "CLAUDE_CODE_SESSION_ID": "inherited-session"}
        with tempfile.TemporaryDirectory() as tmp, \
                patch.dict(os.environ, service_env, clear=True), \
                patch.object(worker, "worker_running", return_value=False), \
                patch.object(worker, "get_platform", return_value=platform):
            fed_commands.worker_starter(Path(tmp))()
            env = spawned["env"]
            self.assertEqual((env["AB_STATE_DIR"], env["AB_COMMAND"]), (tmp, "ab"))
        # 显式 provider 根覆盖保留；会话归属变量不传给 worker；PATH 补 ~/.local/bin
        self.assertEqual((env["CODEX_HOME"], env["AB_CLAUDE_SESSIONS_DIR"]), ("/x/codex", "/x/claude"))
        self.assertNotIn("CLAUDE_CODE_SESSION_ID", env)
        self.assertTrue(env["PATH"].startswith("/usr/bin:/bin") and env["PATH"].endswith("/home/u/.local/bin"))

    def test_windows_elevated_token_is_refused_before_opening_store(self) -> None:
        class Api:
            def current_token(self) -> Any:
                raise OSError("windows_elevated_unsupported")

        class Platform:
            name = "windows"
            transport = type("T", (), {"api": Api()})()

        with patch.object(fed_commands, "get_platform", return_value=Platform()):
            with self.assertRaises(FedCliError) as caught:
                fed_commands._require_unelevated()  # pyright: ignore[reportPrivateUsage]
        self.assertEqual(caught.exception.code, "relay_elevated")

    def test_relay_passes_platform_windows_flag_to_ssh_connector(self) -> None:
        """§89：relay 命令按运行时平台给 ssh 连接工厂传 windows，Windows 上 ssh 才会带 CREATE_NO_WINDOW。"""
        for windows in (True, False):
            seen: dict[str, Any] = {}

            def connector(config: Any, root: Path, *, windows: bool = False) -> Any:
                seen["windows"] = windows
                return lambda: None

            class FakeRelay:
                def __init__(self, *args: Any, connect: Any, **kwargs: Any) -> None:
                    seen["connect"] = connect

                def connect_and_run(self, **kwargs: Any) -> str:
                    return "ok"

            rt = SimpleNamespace(store=Mock(), ident=None, config=None, close=lambda: None,
                                 paths=RelayPaths(Path("/nonexistent"), windows=windows))
            with self.subTest(windows=windows), tempfile.TemporaryDirectory() as tmp, \
                    patch.object(fed_commands, "_require_unelevated"), \
                    patch.object(fed_commands, "open_runtime", return_value=rt), \
                    patch.object(fed_commands, "directory_source", return_value=lambda: {}), \
                    patch.object(fed_commands, "worker_starter", return_value=lambda: None), \
                    patch.object(fed_commands, "ssh_connector", side_effect=connector), \
                    patch.object(fed_commands, "Relay", FakeRelay):
                self.assertEqual(fed_commands.run_relay(Path(tmp), once=True), "ok")
                self.assertIs(seen["windows"], windows)

    def test_ssh_connector_hides_the_ssh_window_only_on_windows(self) -> None:
        """§89：Windows 上 ssh 子进程用 CREATE_NO_WINDOW（0x08000000）；其他平台创建标志为 0。"""
        from agentstatus_bridge.federation import relay as relay_module

        config = FederationConfig(enabled=True, hub_id=HUB, device_id=DEV_A, device_name="vm", host="h",
                                  user="ab-relay", expected_state_root="/x", identity_file="/k",
                                  known_hosts_file="/kh")
        for windows, flags in ((True, 0x08000000), (False, 0)):
            calls: list[dict[str, Any]] = []

            def popen(argv: Any, **kwargs: Any) -> Any:
                calls.append(kwargs)
                return Mock(stdin=Mock(), stdout=Mock())

            with self.subTest(windows=windows), tempfile.TemporaryDirectory() as tmp, \
                    patch.object(relay_module.subprocess, "Popen", side_effect=popen):
                relay_module.ssh_connector(config, Path(tmp), windows=windows)()
                self.assertEqual([call["creationflags"] for call in calls], [flags])
                self.assertEqual((calls[0]["stdin"], calls[0]["stdout"], calls[0]["stderr"]),
                                 (subprocess.PIPE, subprocess.PIPE, subprocess.DEVNULL))

    def test_relay_single_instance_lock(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            from agentstatus_bridge.platforms.factory import get_platform

            lifecycle = get_platform().lifecycle
            fd = lifecycle.open_lock(root / fed_commands.RELAY_LOCK)
            lifecycle.try_lock(fd)
            try:
                self.assertEqual(fed_commands.run_relay(root, once=True), "already_running")
                self.assertTrue(fed_commands.relay_running(root))
            finally:
                lifecycle.unlock(fd)
                lifecycle.close_lock(fd)
            self.assertFalse(fed_commands.relay_running(root))


if __name__ == "__main__":
    unittest.main()
