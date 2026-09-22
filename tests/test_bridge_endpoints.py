"""协作桥端点发现：注册表代际、Codex thread 归属、目标解析、调用者与权限类别。"""

from __future__ import annotations

from pathlib import Path
import json
import shutil
import socket
from tempfile import TemporaryDirectory
import unittest
import unittest.mock

from agentstatus_bridge import endpoints as endpoints_module
from agentstatus_bridge.endpoints import (
    ADAPTERS,
    DiscoverySources,
    MAX_REGISTRY_FILES,
    _map_agentstatus_runtime,  # pyright: ignore[reportPrivateUsage]
    ObserverRow,
    ObserverView,
    agentstatus_view,
    _pane_state,  # pyright: ignore[reportPrivateUsage]
    PaneInfo,
    ResolveError,
    discover,
    identify_caller,
    permission_class,
    resolve_target,
)
from agentstatus_bridge.hints import PaneState
from agentstatus_bridge.ids import opaque_id
from agentstatus_bridge.model import Provider, Runtime
from agentstatus_bridge import procfs
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
            grok_home=self.grok_home,
            panes=lambda: self.panes,
            runtime=lambda: self._view(),
        )

    def _view(self) -> ObserverView:
        """把测试里写的「键 → 状态」摊成 observer 行；pane 键默认属于自己，会话键默认没有 pane。"""
        return ObserverView(
            {
                key: ObserverRow(
                    state,
                    self.evidence.get(key),
                    self.observer_pane.get(key, key if key.startswith("%") else None),
                )
                for key, state in self.runtime.items()
            }
        )

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
    def test_pane_state_from_public_snapshot(self) -> None:
        fresh = _pane_state({"runtimeState": "ready", "freshness": "fresh", "lastTurnEndedAt": 1700000000.5})
        self.assertEqual(fresh, PaneState(Runtime.IDLE, 1700000000.5, True))
        stale = _pane_state({"runtimeState": "ready", "freshness": "stale", "lastTurnEndedAt": True})
        self.assertEqual(stale, PaneState(Runtime.UNKNOWN, None, False))
        asking = _pane_state({"runtimeState": "working", "attentionState": "action_required", "freshness": "aging"})
        self.assertEqual(asking, PaneState(Runtime.WAITING, None, True))
        background = _pane_state(
            {"runtimeState": "ready", "freshness": "fresh", "activeChildren": 1, "lastTurnEndedAt": 1700000000.5}
        )
        self.assertEqual(background, PaneState(Runtime.BACKGROUND, 1700000000.5, True))

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
        with unittest.mock.patch.object(endpoints_module, "_observer_rows", return_value=rows):
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
                with unittest.mock.patch.object(endpoints_module, "_observer_rows", return_value=order):
                    self.assertEqual(agentstatus_view().states, {"%1": Runtime.BUSY})
        # 两行都不新鲜时保持「最后一行胜出」，不引入新的偏好
        older = {"paneId": "%1", "runtimeState": "working", "freshness": "unavailable"}
        with unittest.mock.patch.object(endpoints_module, "_observer_rows", return_value=[older, stale]):
            self.assertEqual(agentstatus_view().states, {"%1": Runtime.UNKNOWN})
        # 两行都新鲜时偏保守：等待用户不被行序覆盖（审计 P3-B）
        asking = {"paneId": "%1", "runtimeState": "working", "attentionState": "action_required", "freshness": "fresh"}
        for order in ([asking, fresh], [fresh, asking]):
            with self.subTest(order=[row.get("attentionState") for row in order]):
                with unittest.mock.patch.object(endpoints_module, "_observer_rows", return_value=order):
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
        with unittest.mock.patch.object(endpoints_module, "_observer_rows", return_value=rows):
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
