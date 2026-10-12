"""协作桥端点发现：注册表代际、Codex thread 归属、目标解析、调用者与权限类别。"""

from __future__ import annotations
from agentstatus_bridge.platforms.linux import files as linux_files

from collections.abc import Callable
from dataclasses import replace
from pathlib import Path
import json
import os
import shutil
import socket
from tempfile import TemporaryDirectory
import unittest
import unittest.mock

from agentstatus_bridge import endpoints as endpoints_module, observer_dbus
from agentstatus_bridge.endpoints import (
    ADAPTERS,
    DiscoverySources,
    MAX_REGISTRY_FILES,
    PaneInfo,
    ResolveError,
    discover,
    identify_caller,
    permission_class,
    resolve_target,
)
from agentstatus_bridge.observer_dbus import (
    ObserverRow,
    ObserverView,
    _map_agentstatus_runtime,  # pyright: ignore[reportPrivateUsage]
    agentstatus_view,
)
from agentstatus_bridge.ids import opaque_id
from agentstatus_bridge.model import Provider, Runtime
from agentstatus_bridge.platforms.linux import process as procfs
from agentstatus_bridge.codex_argv import _codex_non_interactive  # pyright: ignore[reportPrivateUsage]
from agentstatus_bridge.transports import DeliveryContext
from agentstatus_bridge.transports.claude_peer import build_frame
from bridge_support import FakeProc, endpoint, ref

UUID_A = "019a0000-aaaa-7aaa-8aaa-aaaaaaaaaaaa"
UUID_B = "019a0000-bbbb-7bbb-8bbb-bbbbbbbbbbbb"
UUID_C = "019a0000-cccc-7ccc-8ccc-cccccccccccc"


class DiscoveryTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = TemporaryDirectory()
        self.root = Path(self._tmp.name)
        self.proc = FakeProc(self.root / "proc")
        self.sessions = self.root / "claude-sessions"
        self.sessions.mkdir()
        self.codex_home = self.root / "codex"
        self.grok_home = self.root / "grok"
        self.panes: dict[int, PaneInfo] = {}
        # pane_id → 原始标题；给定才有，默认不读真实 tmux（DESIGN §53.3.2）
        self.titles: dict[str, str] = {}
        self.runtime: dict[str, Runtime] = {}
        self.evidence: dict[str, float] = {}
        self.observer_pane: dict[str, str | None] = {}
        self._sockets: list[socket.socket] = []

    def tearDown(self) -> None:
        for item in self._sockets:
            item.close()
        self._tmp.cleanup()

    def _sources(self) -> DiscoverySources:
        return DiscoverySources(
            proc_root=self.proc.root,
            claude_sessions=self.sessions,
            codex_home=self.codex_home,
            # 显式不继承外部 CODEX_SQLITE_HOME：状态库只在合成的 codex_home 里找（Codex §45.48 实现复核 C01）
            codex_sqlite_home=None,
            grok_home=self.grok_home,
            panes=lambda: self.panes,
            titles=lambda: self.titles,
            runtime=lambda: self._view(),
        )

    def _view(self) -> ObserverView:
        """把测试里写的「键 → 状态」摊成 observer 行；pane 键默认属于自己，会话键默认没有 pane。

        pane 键的行不带 `agent`，按 pane 匹配任意 provider（与不发 `agent` 的写方同口径，DESIGN §62 ④）。
        """
        rows = {
            key: ObserverRow(
                state,
                self.evidence.get(key),
                self.observer_pane.get(key, key if key.startswith("%") else None),
            )
            for key, state in self.runtime.items()
        }
        return ObserverView(rows, {(key, None): row for key, row in rows.items() if key.startswith("%")})

    def _socket(self, name: str) -> str:
        path = str(self.root / name)
        server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        server.bind(path)
        self._sockets.append(server)
        return path

    def _claude(self, pid: int, *, start: str = "77", registry_start: str | None = None, sock: bool = True, **extra: object) -> None:
        self.proc.add(pid - 100, comm="zsh")
        self.proc.add(pid, comm="claude", ppid=pid - 100, start=start, argv=["claude"])
        self.panes[pid - 100] = PaneInfo(f"%{pid}", pid - 100, "proj")
        document: dict[str, object] = {
            "pid": pid,
            "sessionId": f"session-{pid}",
            "procStart": registry_start or start,
            "peerProtocol": 1,
            "status": "idle",
            "kind": "interactive",
            "messagingSocketPath": self._socket(f"{pid}.sock") if sock else str(self.root / "missing.sock"),
        }
        document.update(extra)
        (self.sessions / f"{pid}.json").write_text(json.dumps(document), encoding="utf-8")

    def _rollout(self, uuid: str) -> str:
        return str(self.codex_home / "sessions/2026/09/15" / f"rollout-2026-09-15T00-00-00-{uuid}.jsonl")

    def _grok(
        self,
        pid: int,
        sessions: list[str],
        *,
        comm: str = "grok",
        start: str = "88",
        held: list[str] | None = None,
        pane: str | None = "%9",
        ppid: int | None = None,
        extra_fds: list[str] = [],
    ) -> None:
        """写一条（或几条）Grok 注册表条目，并按需让进程持有对应的 events 文件。"""
        holding = sessions if held is None else held
        fds = [str(self.grok_home / "sessions/%2Fhome%2Fuser" / item / "events.jsonl") for item in holding]
        fds.extend(extra_fds)
        parent = pid - 1 if ppid is None else ppid  # 父进程 pid 显式可给：别的夹具用同号段时不会互相覆盖
        self.proc.add(parent, comm="zsh")
        self.proc.add(pid, comm=comm, ppid=parent, start=start, argv=["grok"], fds=fds)
        if pane is not None:
            self.panes[parent] = PaneInfo(pane, parent, "grok-proj")
        registry = self.grok_home / "active_sessions.json"
        registry.parent.mkdir(parents=True, exist_ok=True)
        entries = json.loads(registry.read_text(encoding="utf-8")) if registry.exists() else []
        entries.extend(
            {"session_id": item, "pid": pid, "cwd": "/home/user", "opened_at": "2026-09-17T00:00:00Z"}
            for item in sessions
        )
        registry.write_text(json.dumps(entries), encoding="utf-8")

    def test_grok_session_is_discovered_read_only(self) -> None:
        self._grok(900, [UUID_A])
        self.runtime["%9"] = Runtime.IDLE
        [found] = [item for item in discover(self._sources()) if item.ref.provider is Provider.GROK]
        self.assertEqual(
            (found.ref.native_id, found.ref.pid, found.ref.start_ticks, found.ref.pane, found.ref.label, found.runtime),
            (UUID_A, 900, "88", "%9", "grok-proj", Runtime.IDLE),
        )
        # 只读：发现阶段就带上阻断标记，任何投递路径都据此拒绝（DESIGN §45.34）
        self.assertEqual((found.issues, found.blocking_issues), (("no_inbox",), ("no_inbox",)))

    def test_grok_events_path_must_be_exact_and_inside_grok_home(self) -> None:
        # 只认 grok 数据根下、以 /<uuid>/events.jsonl 结尾的路径：改名、删除留痕、同名 UUID 放在别处都不算持有
        outside = str(Path("/tmp/evil/sessions") / UUID_A / "events.jsonl")
        renamed = str(self.grok_home / "sessions/%2Fhome%2Fuser" / UUID_A / "events.jsonl (deleted)")
        backup = str(self.grok_home / "sessions/%2Fhome%2Fuser" / UUID_A / "events.jsonl.bak")
        self._grok(900, [UUID_A], held=[], extra_fds=[outside, renamed, backup])
        self.assertEqual([item for item in discover(self._sources()) if item.ref.provider is Provider.GROK], [])

    def test_grok_native_id_is_normalized_and_registry_keeps_newest(self) -> None:
        # 注册表写大写也要能对上小写的 fd 路径，且落库归一（否则重新发现时 same_session 对不上）
        self._grok(900, [UUID_A.upper()], held=[UUID_A])
        [found] = [item for item in discover(self._sources()) if item.ref.provider is Provider.GROK]
        self.assertEqual(found.ref.native_id, UUID_A)
        # 注册表是追加式的：条目超过上限时要留最新的（在尾部），不是从头截断
        registry = self.grok_home / "active_sessions.json"
        stale = [
            {"session_id": f"019a0000-0000-7000-8000-{index:012d}", "pid": 900, "cwd": "/x"}
            for index in range(MAX_REGISTRY_FILES + 5)
        ]
        registry.write_text(json.dumps(stale + json.loads(registry.read_text(encoding="utf-8"))), encoding="utf-8")
        found = [item for item in discover(self._sources()) if item.ref.provider is Provider.GROK]
        self.assertEqual([item.ref.native_id for item in found], [UUID_A])

    def test_case_mixed_duplicate_registry_entries_make_one_endpoint(self) -> None:
        # 脏注册表：同一会话同时有小写与大写两条，去重要在归一之后（Codex 复审 N01）
        self._grok(900, [UUID_A, UUID_A.upper()], held=[UUID_A])
        found = [item for item in discover(self._sources()) if item.ref.provider is Provider.GROK]
        self.assertEqual([item.ref.native_id for item in found], [UUID_A])
        self.assertEqual(found[0].issues, ("no_inbox",))  # 不是两行，也不该标 shared_process

    def test_grok_registry_entry_without_open_events_file_is_ignored(self) -> None:
        # 注册表列了会话，但进程没有持有它的 events 文件：残留条目，不是活会话
        self._grok(900, [UUID_A], held=[])
        self.assertEqual([item for item in discover(self._sources()) if item.ref.provider is Provider.GROK], [])

    def test_grok_entry_on_reused_pid_is_ignored(self) -> None:
        # PID 已被别的程序复用：注册表没有进程代际，只能靠 comm 与 fd 挡住
        self._grok(900, [UUID_B], comm="bash")
        self.assertEqual([item for item in discover(self._sources()) if item.ref.provider is Provider.GROK], [])

    def test_grok_same_process_holds_two_sessions(self) -> None:
        # resume 之后旧会话的 fd 不关：两条都是活的，不阻断，只标同进程（DESIGN §45.34）
        self._grok(900, [UUID_A, UUID_B])
        found = {item.ref.native_id: item for item in discover(self._sources()) if item.ref.provider is Provider.GROK}
        self.assertEqual(set(found), {UUID_A, UUID_B})
        for item in found.values():
            self.assertEqual(item.issues, ("no_inbox", "shared_process"))
            self.assertEqual(item.blocking_issues, ("no_inbox",))

    def test_grok_without_pane_has_unknown_runtime(self) -> None:
        self._grok(900, [UUID_A], pane=None)
        [found] = [item for item in discover(self._sources()) if item.ref.provider is Provider.GROK]
        self.assertEqual((found.ref.pane, found.runtime, found.runtime_source), (None, Runtime.UNKNOWN, "none"))

    def test_claude_registry_with_live_generation(self) -> None:
        self._claude(500)
        [found] = discover(self._sources())
        self.assertEqual(
            (found.ref.provider, found.ref.native_id, found.ref.pane, found.ref.label, found.runtime, found.issues),
            (Provider.CLAUDE, "session-500", "%500", "proj", Runtime.IDLE, ()),
        )

    def test_stale_registry_and_missing_socket(self) -> None:
        self._claude(500, registry_start="1")
        self._claude(600, sock=False, status="busy")
        [found] = discover(self._sources())
        self.assertEqual(found.ref.native_id, "session-600")
        self.assertEqual((found.runtime, found.issues), (Runtime.BUSY, ("socket_unavailable",)))

    def test_registry_waiting_and_shell_status(self) -> None:
        self._claude(500, status="waiting")
        self._claude(700, status="shell")
        found = {item.ref.pid: item.runtime for item in discover(self._sources())}
        self.assertEqual(found, {500: Runtime.WAITING, 700: Runtime.BUSY})

    def test_open_native_dialog_marks_claude_waiting(self) -> None:
        self._claude(500)
        self.runtime["%500"] = Runtime.WAITING
        [found] = discover(self._sources())
        self.assertEqual(found.runtime, Runtime.WAITING)

    def test_observer_corrects_the_registry_when_only_background_work_is_left(self) -> None:
        """注册表的 busy/shell 分不清前台轮次与后台工作，observer 能分，以 observer 为准（DESIGN §45.37）。"""
        self._claude(500, status="shell")  # 后台 shell 在跑时注册表报 shell
        self._claude(700, status="busy")  # 子代理在跑时注册表报 busy
        for pid in (500, 700):
            key = opaque_id("claude", f"session-{pid}")
            self.runtime[key] = Runtime.BACKGROUND
            self.observer_pane[key] = f"%{pid}"
        found = {item.ref.pid: (item.runtime, item.runtime_source) for item in discover(self._sources())}
        self.assertEqual(
            found,
            {500: (Runtime.BACKGROUND, "agentstatus"), 700: (Runtime.BACKGROUND, "agentstatus")},
        )

    def test_only_this_session_identity_can_release_the_native_busy(self) -> None:
        """放开忙判只认会话身份：pane 会被换会话或别的 provider 复用，那不是本会话的证据（Codex 审计 F02）。"""
        self._claude(500, status="busy")
        cases = {
            # pane 级观察：同一 pane 上换了会话、或行本来就属于另一个 provider，都可能是这个值
            "pane_row": "%500",
            "other_claude_session": opaque_id("claude", "session-999"),
            "other_provider": opaque_id("codex", "777", "%500", 400, "77"),
        }
        for name, key in cases.items():
            with self.subTest(name):
                self.runtime.clear()
                self.runtime[key] = Runtime.BACKGROUND
                [found] = discover(self._sources())
                self.assertEqual((found.runtime, found.runtime_source), (Runtime.BUSY, "claude_registry"))

    def test_release_needs_observer_evidence_from_this_state_change(self) -> None:
        """observer 的证据要和注册表这次状态变化对得上：停在上一轮的旧证据不能放开当前的忙（审计 F01）。

        实测正常窗口里 observer 的 Stop 事件比注册表改写早约 0.09 秒，所以判据是「不早于 5 秒」，
        不是「不早于」；漏开轮 hook 时两者相差一整轮，这条就挡得住。
        """
        key = opaque_id("claude", "session-500")
        self.runtime[key] = Runtime.BACKGROUND
        self.observer_pane[key] = "%500"
        cases = {
            # 注册表在 1000.0 翻转；observer 的证据分别是：同一次变化前 0.09 秒 / 恰好在容差边缘 / 上一轮
            "same_transition": (1000.0, 999.91, Runtime.BACKGROUND),
            "within_skew": (1000.0, 995.0, Runtime.BACKGROUND),
            "just_outside_skew": (1000.0, 994.99, Runtime.BUSY),
            "previous_turn": (1000.0, 40.0, Runtime.BUSY),
            "no_evidence_at_all": (1000.0, None, Runtime.BUSY),
        }
        self._claude(500, status="busy")
        registry = self.sessions / "500.json"
        for name, (status_at, evidence_at, expected) in cases.items():
            with self.subTest(name):
                self.evidence.clear()
                if evidence_at is not None:
                    self.evidence[key] = evidence_at
                document = json.loads(registry.read_text(encoding="utf-8"))
                document["statusUpdatedAt"] = int(status_at * 1000)
                registry.write_text(json.dumps(document), encoding="utf-8")
                [found] = discover(self._sources())
                self.assertIs(found.runtime, expected)

    def test_registry_without_a_status_timestamp_keeps_the_old_behaviour(self) -> None:
        """上游少给 statusUpdatedAt 时不作时效判断：少一道校验，而不是整体退回保守（审计 F01）。"""
        self._claude(500, status="busy")
        self.assertNotIn("statusUpdatedAt", json.loads((self.sessions / "500.json").read_text(encoding="utf-8")))
        key = opaque_id("claude", "session-500")
        self.runtime[key] = Runtime.BACKGROUND
        self.observer_pane[key] = "%500"
        [found] = discover(self._sources())
        self.assertIs(found.runtime, Runtime.BACKGROUND)

    def test_generation_row_decides_when_a_session_has_more_than_one(self) -> None:
        """同一 native session resume 到别的进程/pane 时会有多个代际行：只认自己那一代（审计 R02）。"""
        self._claude(500, status="busy")
        base = opaque_id("claude", "session-500")
        mine = opaque_id("claude-gen", base, "%500", 500, "77")
        other = opaque_id("claude-gen", base, "%900", 900, "77")
        # 1. 自己那一代说「本轮已结束、只剩后台」→ 放行
        self.runtime[mine] = Runtime.BACKGROUND
        self.observer_pane[mine] = "%500"
        self.assertIs(discover(self._sources())[0].runtime, Runtime.BACKGROUND)
        # 2. 自己那一代说在跑前台 → 不放行，哪怕 base 行说后台（旧代际留下的）
        self.runtime[mine] = Runtime.BUSY
        self.runtime[base] = Runtime.BACKGROUND
        self.observer_pane[base] = "%500"
        self.assertIs(discover(self._sources())[0].runtime, Runtime.BUSY)
        # 3. 只有别的代际说后台 → 不放行
        self.runtime.pop(mine)
        self.runtime.pop(base)
        self.runtime[other] = Runtime.BACKGROUND
        self.observer_pane[other] = "%900"
        self.assertIs(discover(self._sources())[0].runtime, Runtime.BUSY)
        # 4. 没有代际行时才回退到会话行，且它必须属于同一个 pane
        self.runtime.pop(other)
        self.runtime[base] = Runtime.BACKGROUND
        self.observer_pane[base] = "%900"
        self.assertIs(discover(self._sources())[0].runtime, Runtime.BUSY)
        self.observer_pane[base] = "%500"
        self.assertIs(discover(self._sources())[0].runtime, Runtime.BACKGROUND)

    def test_generation_key_matches_the_summary_binding(self) -> None:
        """桥自己算的代际键必须与摘要给面板的那套逐字节相同，否则永远查不到自己的行。"""
        from agentstatus_bridge.summary import endpoint_binding

        self._claude(500)
        [found] = discover(self._sources())
        keys = [entry["key"] for entry in endpoint_binding(found.ref)["observerKeys"]]
        base = opaque_id("claude", "session-500")
        self.assertEqual(keys, [opaque_id("claude-gen", base, "%500", 500, "77"), base])

    def test_waiting_for_the_user_outranks_background_work(self) -> None:
        """两个来源里只要有一个说在等用户就不投递：注册表说等待、或 observer 看到原生对话框。"""
        self._claude(500, status="waiting")
        self._claude(700, status="busy")
        self.runtime["%700"] = Runtime.WAITING
        for pid in (500, 700):
            key = opaque_id("claude", f"session-{pid}")
            self.runtime[key] = Runtime.BACKGROUND
            self.observer_pane[key] = f"%{pid}"
        found = {item.ref.pid: item.runtime for item in discover(self._sources())}
        self.assertEqual(found, {500: Runtime.WAITING, 700: Runtime.WAITING})

    def test_without_an_observer_reading_the_registry_still_decides(self) -> None:
        """observer 不在线（runtime 映射为空）时维持现行行为：注册表说忙就是忙，桥不因此失效。"""
        self._claude(500, status="busy")
        self.assertEqual(self.runtime, {})
        [found] = discover(self._sources())
        self.assertEqual(found.runtime, Runtime.BUSY)

    def test_codex_thread_from_open_rollout_and_shared_consumer(self) -> None:
        self.proc.add(401, comm="zsh")
        self.proc.add(600, comm="codex", ppid=401, argv=["codex"], fds=[self._rollout(UUID_A), str(self.codex_home / "queue_1.sqlite")])
        self.proc.add(700, comm="codex", ppid=1, argv=["codex", "app-server"], fds=[self._rollout(UUID_A)])
        self.panes[401] = PaneInfo("%4", 401, "proj")
        self.runtime["%4"] = Runtime.BUSY
        [found] = discover(self._sources())
        self.assertEqual((found.ref.native_id, found.ref.pid, found.runtime), (UUID_A, 600, Runtime.BUSY))
        self.assertEqual((found.issues, found.consumers), (("shared_thread",), 2))
        self.assertEqual(found.blocking_issues, ())

    def test_discover_consumes_the_injected_snapshot_once(self) -> None:
        """注入的快照恰好被读一次、不另读 D-Bus；Codex、Grok 端点状态就是该 pane 选中的那一行（DESIGN §55.4 用例 3）。"""
        self.proc.add(401, comm="zsh")
        self.proc.add(600, comm="codex", ppid=401, argv=["codex"], fds=[self._rollout(UUID_A)])
        self.panes[401] = PaneInfo("%4", 401, "proj")
        self._grok(900, [UUID_B])
        # 两个 pane 各有冲突的两行：按行序取末行会得到 UNKNOWN 与 IDLE，按 view 的规则是 BUSY 与 WAITING
        rows: list[dict[str, object]] = [
            {"paneId": "%4", "runtimeState": "working", "freshness": "fresh", "lastTurnEndedAt": 41.0},
            {"paneId": "%4", "runtimeState": "ready", "freshness": "stale", "lastTurnEndedAt": 42.0},
            {"paneId": "%9", "runtimeState": "working", "attentionState": "action_required", "freshness": "aging", "lastTurnEndedAt": 91.0},
            {"paneId": "%9", "runtimeState": "ready", "freshness": "fresh", "lastTurnEndedAt": 92.0},
        ]
        with unittest.mock.patch.object(observer_dbus, "_observer_rows", return_value=rows):
            view = agentstatus_view()
        served: list[ObserverView] = []

        def runtime() -> ObserverView:
            served.append(view)
            return view

        with unittest.mock.patch.object(observer_dbus, "_observer_rows", return_value=[]) as reads:
            found = {item.ref.provider: item for item in discover(replace(self._sources(), runtime=runtime))}
        self.assertEqual(len(served), 1)
        reads.assert_not_called()
        # 只断言对象相同不能证明被消费：逐个核对端点状态取自该 pane 选中的那一行
        for provider, pane, expected in ((Provider.CODEX, "%4", Runtime.BUSY), (Provider.GROK, "%9", Runtime.WAITING)):
            with self.subTest(provider=provider.value):
                state = view.pane_state(pane, provider)
                self.assertIsNotNone(state)
                assert state is not None
                self.assertEqual((found[provider].runtime, state.runtime), (expected, expected))

    def test_rows_of_another_provider_on_the_pane_are_not_borrowed(self) -> None:
        """pane 上只有别家的行时不借（DESIGN §62 ④）：Codex、Grok 端点状态未知，Claude 不被别家的等待覆盖。"""
        self.proc.add(401, comm="zsh")
        self.proc.add(600, comm="codex", ppid=401, argv=["codex"], fds=[self._rollout(UUID_A)])
        self.panes[401] = PaneInfo("%4", 401, "proj")
        self._grok(900, [UUID_B])
        self._claude(500)
        borrowed: list[dict[str, object]] = [
            {"paneId": "%4", "agent": "claude", "runtimeState": "working", "freshness": "fresh"},
            {"paneId": "%9", "agent": "codex", "runtimeState": "ready", "freshness": "fresh"},
            {"paneId": "%500", "agent": "codex", "runtimeState": "working", "attentionState": "action_required",
             "freshness": "fresh"},
        ]
        own: list[dict[str, object]] = [
            {"paneId": "%4", "agent": "codex", "runtimeState": "working", "freshness": "fresh"},
            {"paneId": "%9", "agent": "grok", "runtimeState": "working", "attentionState": "action_required",
             "freshness": "fresh"},
            {"paneId": "%500", "agent": "claude", "runtimeState": "working", "attentionState": "action_required",
             "freshness": "fresh"},
        ]
        expected = {
            "别家的行": {Provider.CODEX: Runtime.UNKNOWN, Provider.GROK: Runtime.UNKNOWN, Provider.CLAUDE: Runtime.IDLE},
            "自己的行": {Provider.CODEX: Runtime.BUSY, Provider.GROK: Runtime.WAITING, Provider.CLAUDE: Runtime.WAITING},
        }
        for name, rows in (("别家的行", borrowed), ("自己的行", own)):
            with self.subTest(rows=name):
                with unittest.mock.patch.object(observer_dbus, "_observer_rows", return_value=rows):
                    view = agentstatus_view()
                found = {item.ref.provider: item.runtime for item in discover(replace(self._sources(), runtime=lambda: view))}
                self.assertEqual(found, expected[name])

    def test_codex_ambiguity_missing_thread_wrapper_and_non_tui(self) -> None:
        self.proc.add(401, comm="zsh")
        self.proc.add(600, comm="codex", ppid=401, fds=[self._rollout(UUID_A), self._rollout(UUID_B)])
        self.panes[401] = PaneInfo("%4", 401, "two")
        self.proc.add(402, comm="zsh")
        self.proc.add(601, comm="codex", ppid=402)
        self.panes[402] = PaneInfo("%5", 402, "fresh")
        self.proc.add(403, comm="zsh")
        self.proc.add(602, comm="codex", ppid=403, argv=["codex"])
        self.proc.add(603, comm="codex", ppid=602, argv=["codex"], fds=[self._rollout(UUID_B)])
        self.panes[403] = PaneInfo("%6", 403, "wrapped")
        self.proc.add(404, comm="zsh")
        self.proc.add(604, comm="codex", ppid=404, argv=["codex", "exec"], fds=[self._rollout(UUID_A)])
        self.panes[404] = PaneInfo("%7", 404, "exec")
        found = {item.ref.pane: item for item in discover(self._sources())}
        self.assertEqual(set(found), {"%4", "%5", "%6"})
        self.assertEqual(found["%4"].blocking_issues, ("ambiguous_thread",))
        self.assertEqual((found["%5"].ref.native_id, found["%5"].blocking_issues), ("-", ("no_thread_yet",)))
        self.assertEqual((found["%6"].ref.pid, found["%6"].ref.native_id), (603, UUID_B))


    def test_codex_without_tmux_uses_controlling_terminal(self) -> None:
        # GNOME 终端里直起的 Codex：没有 pane，但有控制终端（DESIGN §45.33.2）
        self.proc.add(500, comm="zsh", tty=34816)
        self.proc.add(601, comm="codex", ppid=500, argv=["codex"], fds=[self._rollout(UUID_A)], tty=34816)
        # 同一终端里的启动包装进程没有 rollout，应被丢掉
        self.proc.add(602, comm="codex", ppid=601, argv=["codex"], tty=34816)
        # 另一个终端的 resume 会话照常发现
        self.proc.add(700, comm="codex", ppid=1, argv=["codex", "resume", "--last"], fds=[self._rollout(UUID_B)], tty=34817)
        # 既无 pane 又无控制终端：app-server 之类，不发现
        self.proc.add(800, comm="codex", ppid=1, argv=["codex"], fds=[self._rollout(UUID_A)])
        found = {item.ref.pid: item for item in discover(self._sources())}
        self.assertEqual(set(found), {601, 700})
        self.assertEqual(
            (found[601].ref.native_id, found[601].ref.pane, found[601].ref.label, found[601].ref.server_pid),
            (UUID_A, None, None, None),
        )
        self.assertEqual(found[601].runtime, Runtime.UNKNOWN)
        self.assertEqual(found[601].ref.display(), f"codex@{UUID_A[:8]}")
        self.assertEqual(found[700].ref.native_id, UUID_B)

    def test_launch_mode_ignores_global_options_and_unknown_tokens(self) -> None:
        cases = {
            "bare": (["codex"], True),
            "prompt": (["codex", "帮我看看 exec 这个子命令"], True),
            "resume": (["codex", "resume", "--last"], True),
            "fork": (["codex", "fork"], True),
            "value_option_then_tui": (["codex", "--profile", "work", "resume"], True),
            "inline_value_then_tui": (["codex", "--config=k=v", "--search"], True),
            "exec": (["codex", "exec", "做点事"], False),
            "profile_then_exec": (["codex", "--profile", "work", "exec"], False),
            "config_then_app_server": (["codex", "-c", "k=v", "app-server"], False),
            # 以下预期全部以本机 Codex 0.154 的 `--help` 解析为准（DESIGN §45.33.6）
            # --image 空格写法是多值：后续非选项 token 仍是图片名
            "image_then_exec_is_still_tui": (["codex", "-i", "a.png", "exec"], True),
            "image_named_exec": (["codex", "-i", "exec", "--search"], True),
            "image_then_option_then_exec": (["codex", "-i", "a.png", "b.png", "--search", "exec"], False),
            # 内联写法只带一个取值，其后的 exec 仍是子命令
            "image_inline_then_exec": (["codex", "--image=a.png", "exec"], False),
            "image_short_inline_then_exec": (["codex", "-i=a.png", "exec"], False),
            "image_attached_then_exec": (["codex", "-ia.png", "exec"], False),
            "image_attached_then_positional_then_exec": (["codex", "-ia.png", "b.png", "exec"], False),
            "image_inline_then_positional_then_exec": (["codex", "--image=a.png", "b.png", "exec"], False),
            "inline_profile_then_exec": (["codex", "--profile=work", "exec"], False),
            # 位置参数之后仍可能出现子命令：上游 `codex hello exec` 实际进入 exec
            "positional_then_exec": (["codex", "hello", "exec"], False),
            "quoted_prompt_mentioning_exec": (["codex", "帮我看看 exec 这个子命令"], True),
            "positional_then_resume": (["codex", "hello", "resume"], True),
            "resume_then_exec": (["codex", "resume", "exec"], True),
            "double_dash_then_exec": (["codex", "--", "exec"], True),
            "flag_then_review": (["codex", "--search", "review"], False),
            "help_exec": (["codex", "help", "exec"], False),
            # 0.154 的 agents 是交互 TUI（上游 run_interactive_tui），不能当非交互排除
            "agents_is_tui": (["codex", "agents"], True),
            "execpolicy": (["codex", "execpolicy", "check"], False),
            # 0.156.0 的隐藏子命令（clap hide=true，`--help` 不列）：直接执行 TCP tunnel helper，不是 TUI
            "tcp_tunnel_hidden": (["codex", "tcp-tunnel"], False),
            "cloud_tasks_alias": (["codex", "cloud-tasks"], False),
            # 长选项串不能把子命令挤出有界窗口，否则 exec 会被当成可投递目标
            "many_config_then_exec": (["codex", *sum(([f"-c", f"k{i}=v"] for i in range(20)), []), "exec"], False),
            "many_config_then_tui": (["codex", *sum(([f"-c", f"k{i}=v"] for i in range(20)), []), "resume"], True),
        }
        for name, (argv, discovered) in cases.items():
            with self.subTest(case=name):
                self.proc.add(900, comm="codex", ppid=1, argv=argv, fds=[self._rollout(UUID_A)], tty=34820)
                self.assertEqual([item.ref.pid for item in discover(self._sources())], [900] if discovered else [])
                shutil.rmtree(self.proc.root / "900")

    def test_launch_tokens_are_bounded(self) -> None:
        # cmdline 可以很长：读取与返回都要有上限，且不因此把子命令挤掉判断（DESIGN §45.33.6）
        long_argv = ["codex", *[f"--config=k{index}=v" for index in range(200)], "exec"]
        self.proc.add(910, comm="codex", ppid=1, argv=long_argv, fds=[self._rollout(UUID_A)], tty=34850)
        tokens = procfs.launch_tokens(910, self.proc.root)
        self.assertLessEqual(len(tokens), 64)
        self.assertTrue(all(len(item) <= 256 for item in tokens))
        # 超出窗口时按交互处理（不把「窗口用尽」当非交互，避免误伤带很多 -c 的真 TUI）
        self.assertEqual([item.ref.pid for item in discover(self._sources())], [910])

    def test_terminal_groups_do_not_mix_and_keep_both_real_sessions(self) -> None:
        # 同一控制终端上两个各自持有 thread 的进程都保留
        self.proc.add(610, comm="codex", ppid=1, argv=["codex"], fds=[self._rollout(UUID_A)], tty=34830)
        self.proc.add(611, comm="codex", ppid=1, argv=["codex"], fds=[self._rollout(UUID_B)], tty=34830)
        # pane 组与 tty 组互不相干：pane 里的包装进程不能把 tty 组的会话挤掉
        self.proc.add(402, comm="zsh")
        self.proc.add(620, comm="codex", ppid=402, argv=["codex"], tty=34830)
        self.panes[402] = PaneInfo("%9", 402, "paned")
        found = {item.ref.pid: item.ref.native_id for item in discover(self._sources())}
        self.assertEqual(found, {610: UUID_A, 611: UUID_B, 620: "-"})


class AdapterRegistryTests(unittest.TestCase):
    """注册表合同：加 provider 时这里先红，避免漏掉投递通道或漏登记（DESIGN §45.34）。"""

    def test_registry_covers_every_provider(self) -> None:
        self.assertEqual(set(ADAPTERS), set(Provider))
        for provider, adapter in ADAPTERS.items():
            self.assertEqual(adapter.provider, provider)

    def test_providers_with_inbox_have_a_transport(self) -> None:
        # 声明有收件通道却没给通道，会让消息永远 PENDING、worker 一直驻留（dispatch 的 transport is None 分支）
        from agentstatus_bridge.worker import default_transports

        declared = {provider for provider, adapter in ADAPTERS.items() if adapter.inbox}
        transports = default_transports()
        self.assertEqual(declared, set(transports))
        for provider, transport in transports.items():
            self.assertEqual(transport.provider, provider)


class AgentStatusMappingTests(unittest.TestCase):
    def test_runtime_view_indexes_panes_and_session_identities(self) -> None:
        """一次快照建两套键：pane 供收紧判定，会话键供放开判定；键不合法的行只进 pane（Codex 审计 F02）。"""
        rows: list[dict[str, object]] = [
            {"paneId": "%1", "key": f"claude:{'a' * 24}", "runtimeState": "ready", "freshness": "fresh", "activeChildren": 1, "runtimeUpdatedAt": 1000.5},
            {"paneId": "%2", "key": f"codex:{'b' * 24}", "runtimeState": "working", "freshness": "fresh", "runtimeUpdatedAt": True},
            # 没有 pane 的会话（不在 tmux 里）仍然要有身份条目，否则它永远拿不到放行
            {"key": f"claude:{'c' * 24}", "runtimeState": "ready", "freshness": "fresh", "backgroundWorkCount": 2, "runtimeUpdatedAt": 7},
            {"paneId": "%3", "key": "not-an-opaque-id", "runtimeState": "ready", "freshness": "fresh"},
            # 运行代际键也要收：放开判定优先查它（审计 R02）
            {"paneId": "%4", "key": f"claude-gen:{'d' * 24}", "runtimeState": "ready", "freshness": "fresh", "activeChildren": 1},
        ]
        with unittest.mock.patch.object(observer_dbus, "_observer_rows", return_value=rows):
            snapshot = agentstatus_view()
        # 证据时刻取自 runtimeUpdatedAt（不是 lastEventAt）；不是数（True 也不是）或缺字段的行没有证据
        self.assertEqual(
            {key: row.runtime_at for key, row in snapshot.rows.items() if row.runtime_at is not None},
            {"%1": 1000.5, f"claude:{'a' * 24}": 1000.5, f"claude:{'c' * 24}": 7.0},
        )
        # 每行都记住自己属于哪个 pane：会话行回退时要用它核对代际
        self.assertEqual(snapshot.rows[f"claude:{'a' * 24}"].pane, "%1")
        self.assertIsNone(snapshot.rows[f"claude:{'c' * 24}"].pane)
        self.assertEqual(
            snapshot.states,
            {
                "%1": Runtime.BACKGROUND,
                f"claude:{'a' * 24}": Runtime.BACKGROUND,
                "%2": Runtime.BUSY,
                f"codex:{'b' * 24}": Runtime.BUSY,
                f"claude:{'c' * 24}": Runtime.BACKGROUND,
                "%3": Runtime.IDLE,
                "%4": Runtime.BACKGROUND,
                f"claude-gen:{'d' * 24}": Runtime.BACKGROUND,
            },
        )

    def test_fresh_row_wins_over_a_stale_one_on_the_same_pane(self) -> None:
        """同一个 pane 上有多行时新鲜的说了算：否则一条残留的 stale 行会按行序把当前状态盖成未知（审计 P3-2）。"""
        fresh = {"paneId": "%1", "runtimeState": "working", "freshness": "fresh"}
        stale = {"paneId": "%1", "runtimeState": "ready", "freshness": "stale"}
        for order in ([fresh, stale], [stale, fresh]):
            with self.subTest(order=[row["freshness"] for row in order]):
                with unittest.mock.patch.object(observer_dbus, "_observer_rows", return_value=order):
                    self.assertEqual(agentstatus_view().states, {"%1": Runtime.BUSY})
        # 两行都不新鲜时保持「最后一行胜出」，不引入新的偏好
        older = {"paneId": "%1", "runtimeState": "working", "freshness": "unavailable"}
        with unittest.mock.patch.object(observer_dbus, "_observer_rows", return_value=[older, stale]):
            self.assertEqual(agentstatus_view().states, {"%1": Runtime.UNKNOWN})
        # 两行都新鲜时偏保守：等待用户不被行序覆盖（审计 P3-B）
        asking = {"paneId": "%1", "runtimeState": "working", "attentionState": "action_required", "freshness": "fresh"}
        for order in ([asking, fresh], [fresh, asking]):
            with self.subTest(order=[row.get("attentionState") for row in order]):
                with unittest.mock.patch.object(observer_dbus, "_observer_rows", return_value=order):
                    self.assertEqual(agentstatus_view().states, {"%1": Runtime.WAITING})

    def test_session_keys_are_taken_as_the_observer_writes_them(self) -> None:
        """键只需不与 pane 相撞：比 observer 更严会在上游改键形状时静默丢行、让放行永不发生（审计 P3-4）。"""
        rows: list[dict[str, object]] = [
            {"key": "claude:" + "a" * 24, "runtimeState": "ready", "freshness": "fresh", "activeChildren": 1},
            {"key": "claude-gen:" + "b" * 40, "runtimeState": "ready", "freshness": "fresh", "activeChildren": 1},
            {"key": "future.provider:XYZ-99", "runtimeState": "ready", "freshness": "fresh", "activeChildren": 1},
            {"key": "%12", "runtimeState": "ready", "freshness": "fresh"},  # 长得像 pane：不收
            {"key": "no-colon", "runtimeState": "ready", "freshness": "fresh"},
            {"key": "has space:" + "c" * 24, "runtimeState": "ready", "freshness": "fresh"},
        ]
        with unittest.mock.patch.object(observer_dbus, "_observer_rows", return_value=rows):
            keys = set(agentstatus_view().rows)
        self.assertEqual(keys, {"claude:" + "a" * 24, "claude-gen:" + "b" * 40, "future.provider:XYZ-99"})

    def test_turn_ended_with_background_work_is_not_idle(self) -> None:
        """本轮已结束、后台工作仍在跑：可投递但不是空闲；判据是两个计数，任一为正即算（DESIGN §45.37）。"""
        ended = {"runtimeState": "ready", "freshness": "fresh"}
        for name, counts in {
            "background_task": {"backgroundWorkCount": 1},
            "subagent": {"activeChildren": 1},
            "both": {"backgroundWorkCount": 2, "activeChildren": 3},
        }.items():
            with self.subTest(name):
                self.assertIs(_map_agentstatus_runtime(ended | counts), Runtime.BACKGROUND)
        for name, counts in {
            "absent": {},
            "zero": {"backgroundWorkCount": 0, "activeChildren": 0},
            "negative": {"backgroundWorkCount": -1},
            "true_is_not_a_count": {"activeChildren": True},
            "string": {"activeChildren": "1"},
            "float": {"backgroundWorkCount": 1.5},
            # 定时任务是「将来会跑」，不影响对方现在能否收件
            "scheduled_only": {"scheduledWorkCount": 4},
        }.items():
            with self.subTest(name):
                self.assertIs(_map_agentstatus_runtime(ended | counts), Runtime.IDLE)
        # 计数不改变另外三种判定：前台轮次在跑、快照不新鲜、正在要求用户注意
        running = {"runtimeState": "working", "freshness": "fresh", "activeChildren": 1}
        self.assertIs(_map_agentstatus_runtime(running), Runtime.BUSY)
        self.assertIs(_map_agentstatus_runtime(ended | {"freshness": "stale", "activeChildren": 1}), Runtime.UNKNOWN)
        asking = ended | {"attentionState": "action_required", "activeChildren": 1}
        self.assertIs(_map_agentstatus_runtime(asking), Runtime.WAITING)


class ResolveTests(unittest.TestCase):
    def setUp(self) -> None:
        self.codex = endpoint(ref(Provider.CODEX, UUID_A, pane="%1", label="vm"))
        self.claude = endpoint(ref(Provider.CLAUDE, "4e24a95f-1111-2222-3333-444444444444", pid=2, pane="%2", label="vm claude"), name="审计")
        self.other = endpoint(ref(Provider.CLAUDE, "5f000000-1111-2222-3333-444444444444", pid=3, pane="%3", label="vm"))
        self.endpoints = [self.codex, self.claude, self.other]

    def test_selectors(self) -> None:
        self.assertIs(resolve_target("%2", self.endpoints), self.claude)
        self.assertIs(resolve_target("codex@vm", self.endpoints), self.codex)
        self.assertIs(resolve_target("claude@vm-claude", self.endpoints), self.claude)
        self.assertIs(resolve_target("claude@vm claude", self.endpoints), self.claude)
        self.assertIs(resolve_target("审计", self.endpoints), self.claude)
        self.assertIs(resolve_target(UUID_A.upper(), self.endpoints), self.codex)
        self.assertIs(resolve_target("5f000000", self.endpoints), self.other)
        # 无 tmux 会话名时展示名是 provider@<原生 ID 前缀>，照抄也要能解析（DESIGN §45.33.3）
        self.assertIs(resolve_target(f"codex@{UUID_A[:8]}", self.endpoints), self.codex)
        # 无会话名无 pane 时 ab peers 给的目标就是这个形式（cli._selectors 用 token()）
        self.assertEqual(ref(Provider.CODEX, UUID_A, pane=None, label=None).token(), f"codex@{UUID_A[:8]}")
        self.assertIs(resolve_target(f"codex@{UUID_A[:8].upper()}", self.endpoints), self.codex)
        with self.assertRaises(ResolveError) as short:
            resolve_target(f"codex@{UUID_A[:7]}", self.endpoints)
        self.assertEqual(short.exception.code, "target_not_found")

    def test_ambiguous_and_missing(self) -> None:
        with self.assertRaises(ResolveError) as ambiguous:
            resolve_target("vm", self.endpoints)
        self.assertEqual(ambiguous.exception.code, "target_ambiguous")
        self.assertEqual(set(ambiguous.exception.candidates), {self.codex, self.other})
        with self.assertRaises(ResolveError) as missing:
            resolve_target("codex@nope", self.endpoints)
        self.assertEqual(missing.exception.code, "target_not_found")


class CallerTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = TemporaryDirectory()
        self.root = Path(self._tmp.name)
        self.proc = FakeProc(self.root / "proc")

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_caller_inside_registered_session(self) -> None:
        self.proc.add(600, comm="codex", start="9", argv=["codex"])
        self.proc.add(800, comm="bash", ppid=600)
        self.proc.add(900, comm="python3", ppid=800)
        session = endpoint(ref(Provider.CODEX, UUID_A, pid=600, start="9"))
        caller = identify_caller([session], pid=900, proc_root=self.proc.root, environ={})
        self.assertIs(caller.endpoint, session)
        stale = endpoint(ref(Provider.CODEX, UUID_A, pid=600, start="8"))
        unmatched = identify_caller([stale], pid=900, proc_root=self.proc.root, environ={})
        self.assertIsNone(unmatched.endpoint)
        self.assertFalse(unmatched.is_user_shell)

    def test_caller_inside_session_without_pane(self) -> None:
        # 不经 tmux 的会话没有 pane，归属仍走进程祖先链（DESIGN §45.33）
        self.proc.add(601, comm="codex", start="11", argv=["codex"], tty=34840)
        self.proc.add(801, comm="zsh", ppid=601)
        session = endpoint(ref(Provider.CODEX, UUID_A, pid=601, start="11", pane=None, label=None))
        caller = identify_caller([session], pid=801, proc_root=self.proc.root, environ={})
        self.assertIs(caller.endpoint, session)
        self.assertEqual(caller.via, "ancestry")

    def test_user_shell(self) -> None:
        self.proc.add(800, comm="bash")
        self.proc.add(900, comm="python3", ppid=800)
        caller = identify_caller([], pid=900, proc_root=self.proc.root, environ={})
        self.assertTrue(caller.is_user_shell)
        self.assertEqual(permission_class(caller, proc_root=self.proc.root), "bypass")

    def test_permission_classes(self) -> None:
        config = self.root / "config.toml"
        cases = [
            ("claude", ["claude", "--dangerously-skip-permissions", "--resume"], None, "bypass"),
            ("claude", ["claude", "--permission-mode", "acceptEdits"], None, "prompting"),
            ("claude", ["claude", "--permission-mode=bypassPermissions"], None, "bypass"),
            ("claude", ["claude"], None, None),
            ("codex", ["codex", "--yolo"], None, "bypass"),
            ("codex", ["codex"], 'approval_policy = "never"\nsandbox_mode = "danger-full-access"\n', "bypass"),
            ("codex", ["codex"], 'approval_policy = "on-request"\n', "prompting"),
            ("codex", ["codex"], None, None),
        ]
        for index, (comm, argv, toml, expected) in enumerate(cases):
            with self.subTest(argv=argv, toml=toml):
                if toml is None:
                    config.unlink(missing_ok=True)
                else:
                    config.write_text(toml, encoding="utf-8")
                pid = 600 + index
                self.proc.add(pid, comm=comm, argv=argv)
                self.proc.add(pid + 100, comm="python3", ppid=pid)
                caller = identify_caller([], pid=pid + 100, proc_root=self.proc.root, environ={})
                self.assertEqual(permission_class(caller, proc_root=self.proc.root, codex_config=config), expected)

    def test_environment_attribution_when_ancestry_is_hidden(self) -> None:
        # 沙箱 PID 命名空间里看不到 agent 祖先进程
        self.proc.add(900, comm="python3", ppid=1)
        first = endpoint(ref(Provider.CLAUDE, "s-1", pid=700, start="7"))
        second = endpoint(ref(Provider.CLAUDE, "s-1", pid=701, start="8"))
        caller = identify_caller(
            [first, second],
            pid=900,
            proc_root=self.proc.root,
            environ={"CLAUDECODE": "1", "CLAUDE_CODE_SESSION_ID": "s-1", "CLAUDE_PID": "701"},
        )
        self.assertIs(caller.endpoint, second)
        self.assertEqual(caller.via, "environment")
        codex = endpoint(ref(Provider.CODEX, UUID_A, pid=600))
        matched = identify_caller([codex], pid=900, proc_root=self.proc.root, environ={"CODEX_THREAD_ID": UUID_A.upper()})
        self.assertIs(matched.endpoint, codex)
        stray = identify_caller([codex], pid=900, proc_root=self.proc.root, environ={"CODEX_THREAD_ID": UUID_B})
        self.assertIsNone(stray.endpoint)
        self.assertFalse(stray.is_user_shell)
        self.assertIsNone(permission_class(stray, proc_root=self.proc.root))

    def test_missing_inner_endpoint_does_not_fall_through_to_outer_session(self) -> None:
        """内层 agent 可见但这一轮没被发现时，不能穿过它归到外层会话（Codex 复审 R01 反例 A）。"""
        self.proc.add(500, comm="claude", start="55", argv=["claude"])
        self.proc.add(900, comm="grok", ppid=500, start="88", argv=["grok"])
        self.proc.add(950, comm="bash", ppid=900)
        outer = endpoint(ref(Provider.CLAUDE, "outer-session", pid=500, start="55", pane="%1", label="outer"))
        caller = identify_caller(
            [outer],  # Grok 注册表这一轮不可读／条目缺失
            pid=950,
            proc_root=self.proc.root,
            environ={"CLAUDECODE": "1", "CLAUDE_CODE_SESSION_ID": "outer-session", "GROK_SESSION_ID": UUID_A},
        )
        self.assertIsNone(caller.endpoint)
        self.assertEqual(caller.agent_process.comm if caller.agent_process else None, "grok")
        self.assertFalse(caller.is_user_shell)

    def test_visible_process_group_is_not_overridden_by_same_provider_env(self) -> None:
        """同 provider 的继承值也不能越过可见的进程代际组（Codex 复审 R01 反例 B）。"""
        self.proc.add(500, comm="grok", start="55", argv=["grok"])
        self.proc.add(900, comm="grok", ppid=500, start="88", argv=["grok"])
        self.proc.add(950, comm="bash", ppid=900)
        outer = endpoint(ref(Provider.GROK, UUID_C, pid=500, start="55", pane="%1", label="outer"))
        first = endpoint(ref(Provider.GROK, UUID_A, pid=900, start="88", pane="%9", label="grok-proj"))
        second = endpoint(ref(Provider.GROK, UUID_B, pid=900, start="88", pane="%9", label="grok-proj"))
        stray = identify_caller(
            [outer, first, second], pid=950, proc_root=self.proc.root, environ={"GROK_SESSION_ID": UUID_C}
        )
        self.assertIsNone(stray.endpoint)  # 环境值指向组外的外层会话：不归属
        self.assertEqual(stray.agent_process.pid if stray.agent_process else None, 900)
        # 正向对照：指向组内的会话（含大写写法）照常归属
        picked = identify_caller(
            [outer, first, second], pid=950, proc_root=self.proc.root, environ={"GROK_SESSION_ID": UUID_B.upper()}
        )
        self.assertIs(picked.endpoint, second)
        self.assertEqual(picked.via, "environment")

    def test_visible_inner_agent_wins_over_inherited_outer_env(self) -> None:
        """外层 agent 会话里起的内层会话会继承外层的环境变量，不能让外层抢走归属（Codex 审计 F01）。"""
        self.proc.add(500, comm="claude", start="5", argv=["claude"])
        self.proc.add(900, comm="grok", ppid=500, start="88", argv=["grok"])
        self.proc.add(950, comm="bash", ppid=900)
        outer = endpoint(ref(Provider.CLAUDE, "outer-session", pid=500, start="5", pane="%1", label="outer"))
        first = endpoint(ref(Provider.GROK, UUID_A, pid=900, start="88", pane="%9", label="grok-proj"))
        second = endpoint(ref(Provider.GROK, UUID_B, pid=900, start="88", pane="%9", label="grok-proj"))
        caller = identify_caller(
            [outer, first, second],
            pid=950,
            proc_root=self.proc.root,
            environ={"CLAUDECODE": "1", "CLAUDE_CODE_SESSION_ID": "outer-session", "GROK_SESSION_ID": UUID_B},
        )
        self.assertIs(caller.endpoint, second)
        self.assertEqual(caller.agent_process.comm if caller.agent_process else None, "grok")

    def test_visible_agent_without_endpoint_is_not_attributed_to_another_provider(self) -> None:
        """可见的内层 Claude 没匹配到端点时，不能用继承来的 CODEX_THREAD_ID 归到外层 Codex（Codex 审计 F01）。"""
        # 祖先链只到可见的 Claude；CODEX_THREAD_ID 是从已退出的外层继承来的，那个 codex 会话不在链上
        self.proc.add(700, comm="claude", ppid=1, start="7", argv=["claude"])
        self.proc.add(950, comm="bash", ppid=700)
        codex_elsewhere = endpoint(ref(Provider.CODEX, UUID_A, pid=600, start="6", pane="%1", label="other"))
        caller = identify_caller(
            [codex_elsewhere],  # 内层 Claude 这一轮没被发现（注册表缺项等）
            pid=950,
            proc_root=self.proc.root,
            environ={"CLAUDE_CODE_SESSION_ID": "inner-session", "CODEX_THREAD_ID": UUID_A},
        )
        self.assertIsNone(caller.endpoint)
        self.assertEqual(caller.agent_process.comm if caller.agent_process else None, "claude")
        self.assertFalse(caller.is_user_shell)

    def test_grok_caller_needs_env_when_process_holds_two_sessions(self) -> None:
        # 同一个 grok 进程里有两个会话：祖先链只能定到进程，必须由 GROK_SESSION_ID 决定是哪一个
        self.proc.add(900, comm="grok", start="88", argv=["grok"])
        self.proc.add(950, comm="bash", ppid=900)
        first = endpoint(ref(Provider.GROK, UUID_A, pid=900, start="88", pane="%9", label="grok-proj"))
        second = endpoint(ref(Provider.GROK, UUID_B, pid=900, start="88", pane="%9", label="grok-proj"))
        blind = identify_caller([first, second], pid=950, proc_root=self.proc.root, environ={})
        self.assertIsNone(blind.endpoint)
        self.assertFalse(blind.is_user_shell)  # 看得见 grok 祖先进程，不能当成用户本人
        self.assertEqual(blind.agent_process.comm if blind.agent_process else None, "grok")
        picked = identify_caller(
            [first, second], pid=950, proc_root=self.proc.root, environ={"GROK_SESSION_ID": UUID_B.upper()}
        )
        self.assertIs(picked.endpoint, second)
        self.assertEqual(picked.via, "environment")
        # 只有一个会话时祖先链照旧够用
        alone = identify_caller([first], pid=950, proc_root=self.proc.root, environ={})
        self.assertEqual((alone.endpoint, alone.via), (first, "ancestry"))

    def test_claude_plan_requires_bypass_availability(self) -> None:
        vectors = [
            (["--permission-mode", "plan"], None), (["--permission-mode=plan"], None),
            (["--permission-mode", "plan", "--allow-dangerously-skip-permissions"], "bypass"),
            (["--permission-mode=plan", "--dangerously-skip-permissions"], "bypass"),
            (["--allow-dangerously-skip-permissions"], None),
            (["--permission-mode", "not-a-mode"], None),
            (["--permission-mode=bypassPermissions"], "bypass"),
            *[(["--permission-mode", mode], "prompting") for mode in ("default", "acceptEdits", "auto", "dontAsk")],
        ]
        for index, (argv, expected) in enumerate(vectors):
            pid = 8000 + index
            with self.subTest(argv=argv):
                self.proc.add(pid, comm="claude", argv=["claude", *argv], tty=34816)
                caller = endpoints_module.Caller(None, procfs.read_process(pid, self.proc.root))
                self.assertEqual(permission_class(caller, proc_root=self.proc.root), expected)

    def test_claude_plan_requires_interactive_terminal(self) -> None:
        # 独立固定向量，不从生产集合生成；无头标志即使有tty也不能冒称交互。
        vectors = [
            ["-p", "synthetic"], ["--print"], ["--input-format", "stream-json"],
            ["--output-format=stream-json"], ["--sdk-url", "ws://synthetic.invalid"],
            ["--permission-prompt-tool", "synthetic"], ["--permission-prompts=none"],
            ["--include-partial-messages"], ["--forward-subagent-text"], ["--include-hook-events"],
            ["--prompt-suggestions"], ["--replay-user-messages"],
            ["--append-subagent-system-prompt", "synthetic"], ["--append-subagent-system-prompt-file", "synthetic"],
            ["--init"], ["--init-only"], ["--maintenance"], ["--max-budget-usd", "1"],
            ["--max-turns", "1"], ["--no-session-persistence"], ["--json-schema", "{}"],
            ["--output-format=json"], ["--input-format=text"],
        ]
        for danger in ("--allow-dangerously-skip-permissions", "--dangerously-skip-permissions"):
            for extra, tty in [([], 0), *[(args, 34816) for args in vectors]]:
                with self.subTest(extra=extra, tty=tty, danger=danger):
                    self.proc.add(8000, comm="claude", argv=["claude", "--permission-mode=plan", danger, *extra], tty=tty)
                    caller = endpoints_module.Caller(None, procfs.read_process(8000, self.proc.root))
                    self.assertIsNone(permission_class(caller, proc_root=self.proc.root, claude_system_dir=self.root / "managed"))
        for extra in ([], ["--bare"]):
            self.proc.add(8000, comm="claude", argv=["claude", "--permission-mode=plan", danger, *extra], tty=34816)
            caller = endpoints_module.Caller(None, procfs.read_process(8000, self.proc.root))
            self.assertEqual(permission_class(caller, proc_root=self.proc.root, claude_system_dir=self.root / "managed"), "bypass")
        self.proc.add(8000, comm="claude", argv=["claude", "--permission-mode=plan", danger, "x" * 70000], tty=34816)
        caller = endpoints_module.Caller(None, procfs.read_process(8000, self.proc.root))
        self.assertIsNone(permission_class(caller, proc_root=self.proc.root, claude_system_dir=self.root / "managed"))

    def test_claude_last_mode_conflicts_and_managed_settings(self) -> None:
        vectors = [
            (["--permission-mode=bypassPermissions", "--permission-mode", "acceptEdits"], "prompting"),
            (["--permission-mode", "acceptEdits", "--permission-mode=bypassPermissions"], "bypass"),
            (["--permission-mode=bypassPermissions", "--permission-mode=plan"], None),
            (["--permission-mode=plan", "--permission-mode=default", "--allow-dangerously-skip-permissions"], "prompting"),
            (["--permission-mode=bypassPermissions", "--permission-mode"], None),
            (["--permission-mode=manual"], "prompting"),
            *[(["--dangerously-skip-permissions", "--permission-mode=" + mode], None)
              for mode in ("default", "manual", "acceptEdits", "auto", "dontAsk", "unknown")],
            (["--dangerously-skip-permissions", "--permission-mode=bypassPermissions"], "bypass"),
            (["--dangerously-skip-permissions", "--restricted"], None),
            (["--permission-mode=plan", "--allow-dangerously-skip-permissions", "--restricted"], None),
        ]
        system_dir = self.root / "managed"
        for argv, expected in vectors:
            with self.subTest(argv=argv):
                self.proc.add(8000, comm="claude", argv=["claude", *argv], tty=34816)
                caller = endpoints_module.Caller(None, procfs.read_process(8000, self.proc.root))
                self.assertEqual(permission_class(caller, proc_root=self.proc.root, claude_system_dir=system_dir), expected)
        for name in ("managed-settings.json", "managed-settings.d"):
            for argv in (["--dangerously-skip-permissions"], ["--permission-mode=bypassPermissions"],
                         ["--permission-mode=plan", "--allow-dangerously-skip-permissions"]):
                with self.subTest(name=name, argv=argv):
                    system_dir.mkdir(exist_ok=True)
                    item = system_dir / name
                    if name.endswith(".d"):
                        item.mkdir()
                    else:
                        item.write_text("not-json-must-not-be-parsed")
                    self.proc.add(8000, comm="claude", argv=["claude", *argv], tty=34816)
                    caller = endpoints_module.Caller(None, procfs.read_process(8000, self.proc.root))
                    try:
                        self.assertIsNone(permission_class(caller, proc_root=self.proc.root, claude_system_dir=system_dir))
                    finally:
                        item.rmdir() if item.is_dir() else item.unlink()
        with unittest.mock.patch.object(Path, "lstat", autospec=True, side_effect=self._lstat_denied_under(system_dir)):
            self.assertIsNone(permission_class(caller, proc_root=self.proc.root, claude_system_dir=system_dir))

    def test_claude_plan_interactivity_is_preserved_in_the_frame(self) -> None:
        for tty, extra, bypass in ((34816, [], True), (0, [], False), (34816, ["-p", "synthetic"], False)):
            self.proc.add(8000, comm="claude", argv=["claude", "--permission-mode=plan", "--dangerously-skip-permissions", *extra], tty=tty)
            caller = endpoints_module.Caller(None, procfs.read_process(8000, self.proc.root))
            sender_class = permission_class(caller, proc_root=self.proc.root, claude_system_dir=self.root / "managed")
            frame = json.loads(build_frame("synthetic", DeliveryContext(message_uuid="m", sender_name="x", sender_class=sender_class)))
            self.assertEqual('from-mode="bypass"' in frame["message"]["content"], bypass)

    def test_claude_truncation_combined_short_flags_and_separator(self) -> None:
        """§73.7：argv 没读全不声明 bypass；含 p 的短选项合写算 print；`--` 之后不计；托管存在不改 prompting。"""
        managed = self.root / "managed"
        long_prompt = "x" * (70 * 1024)
        vectors = [
            (["--permission-mode=bypassPermissions", long_prompt, "--permission-mode=default"], None),
            (["--dangerously-skip-permissions", long_prompt, "--restricted"], None),
            (["--dangerously-skip-permissions", long_prompt], None),
            (["--dangerously-skip-permissions", "x" * 1024], "bypass"),
            (["-pc", "--permission-mode", "plan", "--allow-dangerously-skip-permissions"], None),
            (["-cp", "--permission-mode=plan", "--dangerously-skip-permissions"], None),
            (["-c", "--permission-mode=plan", "--dangerously-skip-permissions"], "bypass"),
            (["-cv", "--permission-mode=plan", "--dangerously-skip-permissions"], "bypass"),  # 合写但不含 p
            (["--", "--dangerously-skip-permissions"], None),
            (["--permission-mode=default", "--", "--permission-mode=bypassPermissions"], "prompting"),
        ]
        for argv, expected in vectors:
            with self.subTest(argv=[token[:40] for token in argv]):
                self.proc.add(8000, comm="claude", argv=["claude", *argv], tty=34816)
                caller = endpoints_module.Caller(None, procfs.read_process(8000, self.proc.root))
                self.assertEqual(permission_class(caller, proc_root=self.proc.root, claude_system_dir=managed), expected)
        managed.mkdir()
        (managed / "managed-settings.json").write_text("not-json-must-not-be-parsed")
        self.proc.add(8000, comm="claude", argv=["claude", "--permission-mode=default"], tty=34816)
        caller = endpoints_module.Caller(None, procfs.read_process(8000, self.proc.root))
        self.assertEqual(permission_class(caller, proc_root=self.proc.root, claude_system_dir=managed), "prompting")

    def test_host_policy_dirs_are_isolated_in_tests(self) -> None:
        """bridge_support 把默认系统策略目录改指不存在的临时路径，core 不随宿主是否受管变红（§73.7）。"""
        for path, host in ((linux_files.CLAUDE_SYSTEM_DIR, "/etc/claude-code"), (linux_files.GROK_SYSTEM_DIR, "/etc/grok")):
            self.assertNotEqual(str(path), host)
            self.assertFalse(path.exists())
        self.proc.add(8000, comm="claude", argv=["claude", "--dangerously-skip-permissions"], tty=34816)
        caller = endpoints_module.Caller(None, procfs.read_process(8000, self.proc.root))
        self.assertEqual(permission_class(caller, proc_root=self.proc.root), "bypass")

    def _codex_class_for(self, argv: list[str], toml: str | None, pid: int) -> str | None:
        """在合成 /proc 上按给定 argv 与 config.toml 走真实的 identify_caller → permission_class。"""
        config = self.root / "codex-layers.toml"
        if toml is None:
            config.unlink(missing_ok=True)
        else:
            config.write_text(toml, encoding="utf-8")
        self.proc.add(pid, comm="codex", argv=argv)
        self.proc.add(pid + 1000, comm="python3", ppid=pid)
        caller = identify_caller([], pid=pid + 1000, proc_root=self.proc.root, environ={})
        return permission_class(caller, proc_root=self.proc.root, codex_config=config)

    def test_codex_permission_layers_follow_upstream_merge(self) -> None:
        """DESIGN §58：根层与子命令层分开解析后按上游 0.160.0 的顺序合并，不冒称 bypass。

        YOLO 是本机全局配置的形态；ALT 用来区分「根层 -c 是否被整组替换」；None 为没有 config.toml。
        """
        yolo = 'approval_policy = "never"\nsandbox_mode = "danger-full-access"\n'
        alt = 'approval_policy = "on-request"\nsandbox_mode = "workspace-write"\n'
        never_dfa = ["-c", 'approval_policy="never"', "-c", "sandbox_mode=danger-full-access"]
        cases: list[tuple[str, list[str], str | None, str | None]] = [
            # 1 单层
            ("1a", ["--approve-for-me"], yolo, "prompting"),
            ("1b", ["--not-so-yolo"], yolo, "prompting"),
            ("1c", ["--approve-for-me"], None, "prompting"),
            # 2 单层与 -c：覆盖追加在全部 -c 之后
            ("2a", [*never_dfa, "--approve-for-me"], yolo, "prompting"),
            ("2b", ["--approve-for-me", *never_dfa], yolo, "prompting"),
            ("2c", ["resume", "-c", 'approval_policy="never"', "--approve-for-me"], yolo, "prompting"),
            # 3 profile：任一层选了就不采用 config.toml
            ("3a", ["-p", "work", "--approve-for-me"], yolo, "prompting"),
            ("3b", ["resume", "-p", "work"], yolo, None),
            # 4 子命令层
            ("4a", ["resume", "--approve-for-me"], yolo, "prompting"),
            ("4b", ["fork", "--not-so-yolo"], yolo, "prompting"),
            # 5 跨层：子命令层选了沙箱组就整组替换根层，resume/fork 层的 --approve-for-me 清根层 -a
            ("5a", ["--yolo", "resume", "--approve-for-me"], yolo, "prompting"),
            ("5b", ["--dangerously-bypass-approvals-and-sandbox", "fork", "--not-so-yolo"], yolo, "prompting"),
            ("5c", ["-a", "never", "-s", "danger-full-access", "resume", "--approve-for-me"], yolo, "prompting"),
            ("5d", ["-a", "never", "resume", "--approve-for-me"], yolo, "prompting"),
            # 6 反向跨层
            ("6a", ["--approve-for-me", "resume", "-a", "never"], yolo, None),
            ("6b", ["--approve-for-me", "resume", "--yolo"], yolo, "bypass"),
            ("6c", ["--approve-for-me", "resume", *never_dfa], yolo, "prompting"),
            ("6d", ["--approve-for-me", "fork", *never_dfa], yolo, "prompting"),
            # 7 既有的跨层缺口
            ("7a", ["--yolo", "resume", "-s", "workspace-write"], yolo, None),
            ("7b", ["--yolo", "resume", "-a", "on-request"], yolo, "bypass"),
            ("7c", ["-a", "never", "resume", "-a", "on-request"], yolo, "prompting"),
            ("7d", ["-s", "danger-full-access", "resume", "-s", "workspace-write"], yolo, None),
            # 8 -c 是 clap 全局参数：子命令层出现任何键的 -c 就整组替换根层
            ("8a", [*never_dfa, "resume", "-c", 'model="x"'], None, None),
            ("8b", [*never_dfa, "resume", "-c", "tui.fullscreen_transcript=true"], alt, "prompting"),
            ("8c", ["-c", "approval_policy=on-request", "resume", *never_dfa], yolo, "bypass"),
            # 9 -- 之后是字面参数
            ("9a", ["--", "--approve-for-me"], yolo, "bypass"),
            ("9b", ["--", "--not-so-yolo"], yolo, "bypass"),
            ("9c", ["--", "--yolo"], None, None),
            ("9d", ["resume", "--", "--yolo"], None, None),
            ("9e", ["--approve-for-me", "--", "文本"], yolo, "prompting"),
            # 10 非交互子命令：只固定与上游一致的结果
            ("10b", ["exec", "--yolo", "x"], yolo, "bypass"),
            ("10c", ["--yolo", "exec", "--approve-for-me", "x"], yolo, "prompting"),
            ("10d", ["exec", "x"], yolo, "bypass"),
            # 12 第 3 轮补充：位置参数在前、根层覆盖不随组替换消失、内联与粘连写法
            ("12a", ["写个脚本", "--approve-for-me"], yolo, "prompting"),
            ("12b", ["resume", "0199aaaa-uuid", "--approve-for-me"], yolo, "prompting"),
            ("12c", ["--approve-for-me", "resume", "-s", "danger-full-access"], yolo, "prompting"),
            ("12d", ["--not-so-yolo", "fork", "--sandbox=danger-full-access"], yolo, "prompting"),
            ("12e", ["--yolo", "resume", "--sandbox=workspace-write"], yolo, None),
            ("12f", [*never_dfa, "resume", '--config=model="x"'], None, None),
            ("12g", ["--yolo", "resume", "-sworkspace-write"], yolo, None),
            ("12h", ["-a", "never", "resume", "-aon-request"], yolo, "prompting"),
            ("12i", [*never_dfa, "resume", "-cmodel=x"], None, None),
            ("12j", ["-capproval_policy=never", "-csandbox_mode=danger-full-access"], None, "bypass"),
            # 13 实现复核补充：profile 的两种写法、--enable/--disable 不算 -c、fork 层也清根层 -a、粘连写法的边界
            ("13a", ["-c", 'profile="work"'], yolo, None),
            ("13b", ["resume", "-c", "profile=work"], yolo, None),
            ("13c", ["resume", '--config=profile="work"'], yolo, None),
            ("13d", ["-pwork"], yolo, None),
            ("13e", ["resume", "-pwork"], yolo, None),
            ("13f", ["fork", "-p=work"], yolo, None),
            ("13g", ["-c", "approval_policy=on-request", "resume", "--enable=shell_snapshot"], yolo, "prompting"),
            ("13h", ["-c", "approval_policy=on-request", "fork", "--disable", "shell_snapshot"], yolo, "prompting"),
            ("13i", ["-a", "never", "fork", "--approve-for-me"], yolo, "prompting"),
            ("13j", ["resume", "-cmodel=x", "--approve-for-me"], yolo, "prompting"),
            ("13k", ["-c", "sandbox_mode=danger-full-access", "resume", "-c=sandbox_mode=workspace-write"], yolo, None),
        ]
        for index, (label, arguments, toml, expected) in enumerate(cases):
            with self.subTest(label=label, argv=arguments):
                self.assertEqual(self._codex_class_for(["codex", *arguments], toml, 3000 + index * 2), expected)
        # 11 对照：去掉这个参数、其余相同，结果回到原来（锁住「是这个参数改变了结果」）
        for index, (arguments, expected) in enumerate(((["resume"], "bypass"), (["--yolo", "resume"], "bypass"), ([], "bypass"))):
            with self.subTest(control=arguments):
                self.assertEqual(self._codex_class_for(["codex", *arguments], yolo, 3200 + index * 2), expected)

    def test_a_truncated_codex_command_line_declares_nothing(self) -> None:
        """命令行超过读取上限时，被截掉的尾部可能有改判的参数：不声明类别（DESIGN §58.8，Opus 实现复核 P3-2）。"""
        yolo = 'approval_policy = "never"\nsandbox_mode = "danger-full-access"\n'
        long_prompt = "x" * (70 * 1024)
        self.assertIsNone(self._codex_class_for(["codex", long_prompt, "--approve-for-me"], yolo, 3500))
        self.assertIsNone(self._codex_class_for(["codex", "--yolo", long_prompt], yolo, 3502))
        # 远在上限内（约 1 KiB 提示词）的照常判类
        self.assertEqual(self._codex_class_for(["codex", "x" * 1024, "--approve-for-me"], yolo, 3504), "prompting")
        # 按字节而不是解码后的字符数判断：25000 个汉字约 75 KB，字符数在上限内、字节数超过
        self.assertIsNone(self._codex_class_for(["codex", "中" * 25000, "--approve-for-me"], yolo, 3516))
        # 总字节数恰好等于上限算读全、多一个字节算没读全：cmdline 是 "\0" 连接的 argv 再加结尾 "\0"，三项共 24 字节加提示词长度
        self.assertEqual(self._codex_class_for(["codex", "x" * (65536 - 24), "--approve-for-me"], yolo, 3506), "prompting")
        self.assertIsNone(self._codex_class_for(["codex", "x" * (65537 - 24), "--approve-for-me"], yolo, 3508))
        # 读不到也不声明：空 cmdline 与读失败（进程正在退出）
        self.assertIsNone(self._codex_class_for([], yolo, 3510))
        self.assertIsNone(self._codex_class_after_cmdline_vanishes(yolo, 3512))
        # §73.7 起 Claude 同样不在截断时声明：末项模式与 --restricted 让被截掉的尾部也能改判（复审 P3-1）
        self.proc.add(3514, comm="claude", argv=["claude", "--dangerously-skip-permissions", long_prompt])
        self.proc.add(4514, comm="python3", ppid=3514)
        caller = identify_caller([], pid=4514, proc_root=self.proc.root, environ={})
        self.assertIsNone(permission_class(caller, proc_root=self.proc.root))
        self.proc.add(3518, comm="claude", argv=["claude", "--permission-mode=default", long_prompt])
        self.proc.add(4518, comm="python3", ppid=3518)
        caller = identify_caller([], pid=4518, proc_root=self.proc.root, environ={})
        self.assertIsNone(permission_class(caller, proc_root=self.proc.root))

    def _codex_class_after_cmdline_vanishes(self, toml: str, pid: int) -> str | None:
        """先按正常 argv 建进程、认出调用者，再删掉 cmdline，模拟判类时读失败。"""
        config = self.root / "codex-layers.toml"
        config.write_text(toml, encoding="utf-8")
        self.proc.add(pid, comm="codex", argv=["codex", "--yolo"])
        self.proc.add(pid + 1000, comm="python3", ppid=pid)
        caller = identify_caller([], pid=pid + 1000, proc_root=self.proc.root, environ={})
        (self.proc.root / str(pid) / "cmdline").unlink()
        return permission_class(caller, proc_root=self.proc.root, codex_config=config)

    def test_a_codex_argument_after_the_subcommand_is_still_recognised(self) -> None:
        # --approve-for-me 是无值布尔，不能吞掉后面的子命令（DESIGN §58.2 第 1 条）
        self.assertTrue(_codex_non_interactive(["--approve-for-me", "exec", "x"]))
        self.assertFalse(_codex_non_interactive(["--approve-for-me", "resume"]))

    def _grok_class_for(
        self,
        argv: list[str],
        config: str | None,
        pid: int,
        *,
        requirements: tuple[str, ...] = (),
        managed: tuple[str, ...] = (),
    ) -> str | None:
        """在合成 /proc 与临时 grok 目录上走真实的 identify_caller → permission_class（DESIGN §60 ③）。

        `requirements`/`managed` 列出放这两种文件的位置：`home` 是 `~/.grok`，`system` 是系统目录（补丁指到临时目录）。
        """
        home = self.root / f"grok-home-{pid}"
        system = self.root / f"grok-system-{pid}"
        home.mkdir()
        system.mkdir()
        if config is not None:
            (home / "config.toml").write_text(config, encoding="utf-8")
        for name, places in (("requirements.toml", requirements), ("managed_config.toml", managed)):
            for place in places:
                ((home if place == "home" else system) / name).write_text("", encoding="utf-8")
        self.proc.add(pid, comm="grok", argv=argv)
        self.proc.add(pid + 1000, comm="python3", ppid=pid)
        caller = identify_caller([], pid=pid + 1000, proc_root=self.proc.root, environ={})
        with unittest.mock.patch.object(linux_files, "GROK_SYSTEM_DIR", system):
            try:
                return permission_class(caller, proc_root=self.proc.root, grok_dir=home)
            except TypeError as error:  # 让缺陷以 FAIL 出现，而不是 ERROR
                self.fail(f"配置取值的类型让判定抛出 {error!r}")

    def test_grok_permission_class_follows_flags_then_user_config(self) -> None:
        """DESIGN §60 ③：启动参数 > 用户 config.toml 的 [ui] permission_mode；只在有正面证据时声明 bypass。

        期望值按上游公开源码（xai-org/grok-build 1.0.45 `util/config/permissions.rs`、`pager/src/app/cli.rs`），
        与随装文档有出入的组合判未知（第 3 版，Codex F01、Opus P1-2）。
        """
        approve = '[ui]\npermission_mode = "always-approve"\n'
        ask = '[ui]\npermission_mode = "ask"\n'
        cases: list[tuple[str, list[str], str | None, str | None]] = [
            # 启动参数
            ("flag-always", ["grok", "--always-approve"], None, "bypass"),
            ("flag-yolo", ["grok", "--yolo"], None, "bypass"),
            ("flag-skip", ["grok", "--dangerously-skip-permissions"], None, "bypass"),
            ("mode-bypass", ["grok", "--permission-mode", "bypassPermissions"], None, "bypass"),
            ("mode-inline", ["grok", "--permission-mode=bypassPermissions"], None, "bypass"),
            *((f"mode-{mode}", ["grok", "--permission-mode", mode], None, "prompting")
              for mode in ("default", "auto", "acceptEdits", "dontAsk", "plan")),
            # 上游 clap 不收的取值（产品名也不是合法的启动参数值）：认不出
            ("mode-product-name", ["grok", "--permission-mode", "always-approve"], None, None),
            ("mode-ask", ["grok", "--permission-mode", "ask"], None, None),
            ("mode-unknown", ["grok", "--permission-mode", "weird"], approve, None),
            ("mode-missing-value", ["grok", "--permission-mode"], approve, None),
            # 上游只看 --permission-mode，随装文档说 always-approve 优先：说不准
            ("yolo-with-auto", ["grok", "--yolo", "--permission-mode", "auto"], None, None),
            ("yolo-with-default", ["grok", "--yolo", "--permission-mode", "default"], None, None),
            ("yolo-with-bypass", ["grok", "--yolo", "--permission-mode", "bypassPermissions"], None, "bypass"),
            ("two-modes", ["grok", "--permission-mode", "auto", "--permission-mode", "default"], None, None),
            ("after-dashdash", ["grok", "--", "--yolo"], None, "prompting"),
            # grok agent（ACP 服务）的权限由客户端决定，顶层参数对它不起作用
            ("agent-subcommand", ["grok", "agent", "--yolo"], approve, None),
            ("agent-after-top-flag", ["grok", "--yolo", "agent"], None, None),
            ("agent-plain", ["grok", "agent"], approve, None),
            ("flag-over-config", ["grok", "--permission-mode", "default"], approve, "prompting"),
            ("yolo-over-config", ["grok", "--yolo"], ask, "bypass"),
            # 用户配置
            ("owner-shape", ["grok", "继续"], approve, "bypass"),
            # 原生配置只认 always-approve；bypassPermissions 上游按询问处理，这里当认不出
            ("config-bypass-name", ["grok"], '[ui]\npermission_mode = "bypassPermissions"\n', None),
            *((f"config-{mode}", ["grok"], f'[ui]\npermission_mode = "{mode}"\n', "prompting")
              for mode in ("default", "ask", "auto")),
            ("config-unknown", ["grok"], '[ui]\npermission_mode = "weird"\n', None),
            ("config-not-string", ["grok"], "[ui]\npermission_mode = 1\n", None),
            ("config-list", ["grok"], '[ui]\npermission_mode = ["always-approve"]\n', None),
            ("ui-not-table", ["grok"], "ui = 3\n", None),
            ("no-config", ["grok"], None, "prompting"),
            ("no-ui", ["grok"], 'theme = "dark"\n', "prompting"),
            ("deprecated-key", ["grok"], '[ui]\napproval_mode = "yolo"\n', None),
            ("legacy-yolo-key", ["grok"], "[ui]\nyolo = true\n", None),
            ("bad-toml", ["grok"], "[ui\n", None),
        ]
        for index, (name, argv, config, expected) in enumerate(cases):
            with self.subTest(case=name):
                self.assertEqual(expected, self._grok_class_for(argv, config, 4000 + index * 2))

    def test_grok_bypass_needs_no_possible_lock_and_managed_config_only_fills_a_missing_key(self) -> None:
        approve = '[ui]\npermission_mode = "always-approve"\n'
        ask = '[ui]\npermission_mode = "ask"\n'
        self.assertEqual("bypass", self._grok_class_for(["grok"], approve, 4200))
        for place in ("home", "system"):
            with self.subTest(lock=place):
                self.assertIsNone(self._grok_class_for(["grok"], approve, 4202 + (place == "system") * 2,
                                                       requirements=(place,)))
                self.assertIsNone(self._grok_class_for(["grok", "--yolo"], None, 4206 + (place == "system") * 2,
                                                       requirements=(place,)))
                # 锁只挡 bypass：本来就会询问的仍如实声明
                self.assertEqual("prompting", self._grok_class_for(["grok"], ask, 4210 + (place == "system") * 2,
                                                                   requirements=(place,)))
            with self.subTest(managed=place):
                self.assertIsNone(self._grok_class_for(["grok"], None, 4214 + (place == "system") * 2,
                                                       managed=(place,)))
                # 用户配置写了这个键时 managed 在它之下，不起作用
                self.assertEqual("bypass", self._grok_class_for(["grok"], approve, 4218 + (place == "system") * 2,
                                                                managed=(place,)))

    def test_a_lock_location_that_cannot_be_checked_counts_as_locked(self) -> None:
        # 系统目录拿不准（没有执行权限、lstat 失败）时按有锁处理，不声明 bypass（Opus 第 1 轮 Y3）
        approve = '[ui]\npermission_mode = "always-approve"\n'
        system = self.root / "grok-system-4250"
        with unittest.mock.patch.object(Path, "lstat", autospec=True, side_effect=self._lstat_denied_under(system)):
            self.assertIsNone(self._grok_class_for(["grok"], approve, 4250))
        self.assertEqual("bypass", self._grok_class_for(["grok"], approve, 4252))

    @staticmethod
    def _lstat_denied_under(directory: Path) -> Callable[[Path], os.stat_result]:
        real = os.lstat

        def fake(path: Path) -> os.stat_result:
            if Path(path).parent == directory:
                raise PermissionError(13, "Permission denied", str(path))
            return real(path)

        return fake

    def test_a_truncated_grok_command_line_declares_nothing(self) -> None:
        approve = '[ui]\npermission_mode = "always-approve"\n'
        self.assertIsNone(self._grok_class_for(["grok", "x" * (70 * 1024), "--permission-mode", "default"], approve, 4300))
        self.assertEqual("bypass", self._grok_class_for(["grok", "x" * 1024], approve, 4302))

    def test_grok_permission_class_reaches_the_frame(self) -> None:
        """Grok 发起方的类别原样进 Claude 消息帧的 from-mode：owner 的形状不再是「未知」（DESIGN §60 ③）。"""
        sender_class = self._grok_class_for(["grok"], '[ui]\npermission_mode = "always-approve"\n', 4400)
        content = json.loads(build_frame("正文", DeliveryContext(message_uuid="m", sender_name="x", sender_class=sender_class)))
        self.assertIn('from-mode="bypass"', content["message"]["content"])

    def test_codex_permission_class_reaches_the_frame(self) -> None:
        """分类结果原样进 Claude 消息帧的 from-mode：跨层的 --approve-for-me 不再写出 bypass（DESIGN §58.4 接线断言）。"""
        yolo = 'approval_policy = "never"\nsandbox_mode = "danger-full-access"\n'
        sender_class = self._codex_class_for(["codex", "--yolo", "resume", "--approve-for-me"], yolo, 3400)
        content = json.loads(build_frame("正文", DeliveryContext(message_uuid="m", sender_name="x", sender_class=sender_class)))
        self.assertIn('from-mode="prompting"', content["message"]["content"])
        # app-server 仍固定未知，不按全局 yolo 配置推（DESIGN §53.4.4）
        self.assertIsNone(self._codex_class_for(["codex", "app-server", "--approve-for-me"], yolo, 3402))

    def test_codex_command_line_overrides_take_precedence(self) -> None:
        config = self.root / "codex.toml"
        bypass_config = 'approval_policy = "never"\nsandbox_mode = "danger-full-access"\n'
        cases = [
            (bypass_config, ["codex", "--ask-for-approval", "on-request", "--sandbox", "workspace-write"], "prompting"),
            (bypass_config, ["codex", "-a", "never", "--sandbox=workspace-write"], None),
            (bypass_config, ["codex", "-p", "work"], None),
            (bypass_config, ["codex", "resume", "--last"], "bypass"),
            ('profile = "work"\n' + bypass_config, ["codex"], None),
            (None, ["codex", "-c", 'approval_policy="never"', "-c", "sandbox_mode=danger-full-access"], "bypass"),
            (None, ["codex", "--config=approval_policy=on-request"], "prompting"),
            (
                None,
                ["codex", "-a", "on-request", "-s", "workspace-write", "-c", 'approval_policy="never"', "-c", "sandbox_mode=danger-full-access"],
                "prompting",
            ),
            (
                None,
                ["codex", "-c", 'approval_policy="never"', "-c", "sandbox_mode=danger-full-access", "-a", "on-request", "-s", "workspace-write"],
                "prompting",
            ),
            (None, ["codex", "-a", "on-request", "-a", "never", "-s", "danger-full-access"], "bypass"),
        ]
        for index, (toml, argv, expected) in enumerate(cases):
            with self.subTest(argv=argv, toml=toml):
                if toml is None:
                    config.unlink(missing_ok=True)
                else:
                    config.write_text(toml, encoding="utf-8")
                pid = 1200 + index
                self.proc.add(pid, comm="codex", argv=argv)
                self.proc.add(pid + 100, comm="python3", ppid=pid)
                caller = identify_caller([], pid=pid + 100, proc_root=self.proc.root, environ={})
                self.assertEqual(permission_class(caller, proc_root=self.proc.root, codex_config=config), expected)


if __name__ == "__main__":
    unittest.main()
