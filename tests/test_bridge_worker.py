"""协作桥 worker：会话私有环境隔离、单实例锁、一次循环分发与失败时不留收件箱。"""

from __future__ import annotations

import ast
import fcntl
import json
import os
from pathlib import Path
import shutil
import sqlite3
import subprocess
import sys
from tempfile import TemporaryDirectory
import threading
import time
import unittest
from unittest.mock import patch
from unittest.mock import Mock
from dataclasses import replace

from agentstatus_bridge.model import Delivery, Flow, Provider
from agentstatus_bridge.store import DB_NAME, Store, StoreError
from agentstatus_bridge.endpoints import ADAPTERS
from agentstatus_bridge.platforms.linux.lifecycle import LOCK_RETRY_ATTEMPTS, worker_environment, worker_path
from agentstatus_bridge.worker import (
    LOCK_NAME,
    ensure_worker,
    run_worker,
    wait_for_worker,
    worker_running,
)
from bridge_support import RecordingTransport, endpoint, ref


class WorkerTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        base = Path(self._tmp.name)
        self.root = base / "bridge"
        self.inbox_dir = base / "socks"
        # 消费证据查询指向不存在的库，测试不读取真实 Codex 数据
        env = patch.dict(os.environ, {"CODEX_SQLITE_HOME": str(base / "codex")})
        env.start()
        self.addCleanup(env.stop)

    def _run_once(self, transport: RecordingTransport) -> int:
        return run_worker(
            root=self.root,
            once=True,
            inbox_directory=self.inbox_dir,
            discover_fn=lambda: [endpoint(ref())],
            transports={Provider.CODEX: transport},
            loop_seconds=0.05,
        )

    def test_spawn_passes_the_resolved_command_name(self) -> None:
        # worker 是 `python -m` 起的，argv0 认不出命令名：拉起方必须显式传，
        # 否则页脚会退回默认名而不是用户实际敲的那个（DESIGN §45.36）
        with (
            patch("agentstatus_bridge.platforms.linux.lifecycle.subprocess.Popen") as popen,
            patch("agentstatus_bridge.worker.command_name", return_value="testcmd"),
            patch.dict(os.environ, {"AB_STATE_DIR": str(self.root / "inherited")}, clear=False),
        ):
            os.environ.pop("AB_COMMAND", None)
            self.assertTrue(ensure_worker(self.root))
        env = popen.call_args.kwargs["env"]
        popen.assert_called_once()
        self.assertEqual(popen.call_args.args[0], [sys.executable, "-m", "agentstatus_bridge", "worker"])
        self.assertEqual(env["AB_COMMAND"], "testcmd")
        # 显式 root 优先于继承环境；删掉这次赋值不能靠父进程碰巧有同值蒙混过关。
        self.assertEqual(env["AB_STATE_DIR"], str(self.root))
        self.assertEqual(popen.call_args.kwargs.get('cwd'),str(self.root))

    def test_worker_loop_renders_the_footer_with_the_resolved_command(self) -> None:
        # `run_worker` 那行 `command=command_name()` 此前零守卫：改成字面量时六个模块 200 个用例全绿，
        # 而生产页脚正是 worker 生成的——用户照抄错名字会跑到 ApacheBench（独立 Fable 审计 P3-1）
        self._pending_task()
        transport = RecordingTransport(Provider.CODEX)
        with patch.dict(os.environ, {"AB_COMMAND": "testcmd"}, clear=False):
            self.assertEqual(self._run_once(transport), 0)
        text = transport.calls[0][1]
        self.assertIn("testcmd report", text)
        self.assertNotIn("agent-bridge", text)

    def test_run_worker_keeps_the_lifecycle_that_opened_its_lock(self):
        from agentstatus_bridge.platforms.factory import make_platform
        base=make_platform('linux')
        owner,other=Mock(),Mock()
        owner.open_lock.return_value=4242
        owner.acquire_worker_lock.return_value=True
        owner.install_stop.return_value={}
        first=replace(base,lifecycle=owner);later=replace(base,lifecycle=other)
        count=0
        def fresh():
            nonlocal count
            count+=1
            return first if count==1 else later
        with patch('agentstatus_bridge.worker.get_platform',side_effect=fresh):
            self.assertEqual(self._run_once(RecordingTransport(Provider.CODEX)),0)
        owner.open_lock.assert_called_once()
        owner.acquire_worker_lock.assert_called_once_with(4242)
        owner.restore_stop.assert_called_once_with({})
        owner.unlock.assert_called_once_with(4242)
        owner.close_lock.assert_called_once_with(4242)
        self.assertEqual(other.mock_calls,[])

    def test_environment_preserves_bridge_configuration_values(self) -> None:
        bridge = {
            "AB_STATE_DIR": str(self.root),
            "AB_BINDING": f"agentstatus:{self.root}",
            "AB_COMMAND": "ab",
            "AB_DEVICE": "fixture-device",
            "AB_CLAUDE_SESSIONS_DIR": str(self.inbox_dir),
        }
        env = worker_environment({"PATH": "/bin", **bridge})
        self.assertEqual({key: env.get(key) for key in bridge}, bridge)

    def test_spawn_environment_keeps_binding_in_a_fresh_interpreter(self) -> None:
        # 不运行 worker、不发现真实会话；仅把实际 Popen 接线交给新解释器读三个纯配置值。
        from agentstatus_bridge import paths

        inherited = {
            "AB_STATE_DIR": str(self.root),
            "AB_BINDING": f"agentstatus:{self.root}",
            "AB_COMMAND": "ab",
        }
        with (
            patch("agentstatus_bridge.platforms.linux.lifecycle.subprocess.Popen") as popen,
            patch.dict(os.environ, inherited),
        ):
            self.assertEqual(paths.state_dir_source(), "integration")
            self.assertTrue(ensure_worker())
        completed = subprocess.run(
            [
                sys.executable, "-c",
                "import json; from agentstatus_bridge.paths import state_dir, state_dir_source; "
                "from agentstatus_bridge.naming import command_name; "
                "print(json.dumps([str(state_dir()), state_dir_source(), command_name()]))",
            ],
            env=popen.call_args.kwargs["env"],
            cwd=self._tmp.name,
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(json.loads(completed.stdout), [str(self.root), "integration", "ab"])

    def test_environment_drops_calling_session_variables(self) -> None:
        env = worker_environment(
            {
                "PATH": "/bin",
                "CODEX_HOME": "/c",
                "AB_COMMAND": "ab",
                "CLAUDECODE": "1",
                "CLAUDE_CODE_MESSAGING_TOKEN": "t",
                "CODEX_SANDBOX": "seatbelt",
                "CODEX_THREAD_ID": "x",
                "PYTHONPATH": "/extra",
                "CODEX_SQLITE_HOME": "/s",
                "CODEX_COMPANION_SESSION_ID": "c",
                "CODEX_PERMISSION_PROFILE": "p",
                "CLAUDE_PID": "1",
                "GROK_SESSION_ID": "g",
                "GROK_AGENT": "a",
                "GROK_HOME": "/g",
            }
        )
        # 数据根（*_HOME）要留下：剥掉它 worker 会去看另一个目录；会话身份变量必须剥掉
        self.assertEqual(
            set(env), {"PATH", "CODEX_HOME", "CODEX_SQLITE_HOME", "GROK_HOME", "AB_COMMAND", "PYTHONPATH"}
        )
        self.assertTrue(env["PYTHONPATH"].endswith(os.pathsep + "/extra"))
        self.assertTrue(Path(env["PYTHONPATH"].split(os.pathsep)[0], "agentstatus_bridge").is_dir())

    def test_environment_covers_every_provider_env_marker(self) -> None:
        """注册表里声明的会话变量都必须被滤掉：加 provider 时这条会先红（Opus 复审 N2）。"""
        markers = {marker for adapter in ADAPTERS.values() for marker in adapter.env_markers}
        self.assertIn("GROK_SESSION_ID", markers)  # 注册表真的声明了它，不是空集合让断言空转
        env = worker_environment({"PATH": "/bin", **{marker: "x" for marker in markers}})
        self.assertEqual(sorted(marker for marker in markers if marker in env), [])

    def _events(self) -> list[str]:
        try:
            lines = (self.root / "worker.log").read_text().splitlines()
        except FileNotFoundError:
            return []
        return [json.loads(line)["event"] for line in lines]

    def test_worker_path_appends_local_bin_only_when_missing(self) -> None:
        # 扩展从 gnome-shell 拉起 worker 时 PATH 没有 ~/.local/bin（codex 在那里）：只在缺失时补到末尾（DESIGN §45.30）
        home = Path(self._tmp.name) / "home"
        local = str(home / ".local" / "bin")
        cases: list[tuple[str, str | None, str]] = [
            ("missing", "/opt/tool/bin:/usr/bin:/bin", f"/opt/tool/bin:/usr/bin:/bin:{local}"),
            ("present_first", f"{local}:/usr/bin", f"{local}:/usr/bin"),
            ("present_later", f"/usr/bin:{local}", f"/usr/bin:{local}"),
            ("present_trailing_slash", f"/usr/bin:{local}/", f"/usr/bin:{local}/"),
            ("empty", "", f"{os.defpath}:{local}"),
            ("only_separators", "::", f"{os.defpath}:{local}"),
            ("unset", None, f"{os.defpath}:{local}"),
            ("keeps_caller_string", "/usr/bin::/bin", f"/usr/bin::/bin:{local}"),
        ]
        with patch.dict(os.environ, {"HOME": str(home)}):
            for name, given, expected in cases:
                with self.subTest(case=name):
                    result = worker_path(given)
                    self.assertEqual(result, expected)
                    self.assertEqual(worker_path(result), result, "重复构造不重复追加")
            # 调用方已有的同名命令仍优先：系统路径在前，~/.local/bin 只追加
            self.assertTrue(set(os.defpath.split(os.pathsep)) <= set(worker_path(None).split(os.pathsep)))
            base = {"PATH": "/usr/local/bin:/usr/bin", "HOME": str(home)}
            once = worker_environment(base)
            self.assertEqual(once["PATH"], f"/usr/local/bin:/usr/bin:{local}")
            self.assertEqual(worker_environment(once)["PATH"], once["PATH"])
            self.assertEqual(worker_environment({"HOME": str(home)})["PATH"], f"{os.defpath}:{local}")

    def test_racing_starts_leave_a_single_working_instance(self) -> None:
        # 扩展的 summary --if-stale 与终端 ab 同时发现 worker 不在：两边都可能 Popen，只有拿到 flock 的那个工作，
        # 另一个不碰账本立即退出；已有 worker 持锁时 ensure_worker 不再 Popen（DESIGN §45.30）
        release = [threading.Event(), threading.Event()]
        results: dict[int, int] = {}
        threads: list[threading.Thread] = []
        transport = RecordingTransport(Provider.CODEX)

        def fake_popen(_argv: object, **_kwargs: object) -> object:
            index = len(threads)

            def body() -> None:
                release[index].wait(10)
                results[index] = run_worker(
                    root=self.root,
                    inbox_directory=self.inbox_dir,
                    discover_fn=lambda: [],
                    transports={Provider.CODEX: transport},
                    loop_seconds=0.02,
                )

            thread = threading.Thread(target=body, daemon=True)
            threads.append(thread)
            thread.start()
            return object()

        with (
            patch("agentstatus_bridge.platforms.linux.lifecycle.subprocess.Popen", side_effect=fake_popen) as popen,
            patch("agentstatus_bridge.platforms.linux.lifecycle.signal.signal", return_value=None),  # 线程里不能装信号处理器
            patch("agentstatus_bridge.worker.IDLE_EXIT_SECONDS", 2.0),
        ):
            self.assertTrue(ensure_worker(self.root))  # 扩展补查
            self.assertTrue(ensure_worker(self.root))  # 终端 ab：新 worker 还没持锁，同样拉起
            release[0].set()
            # 等 worker 自己记下 start 再探测，让本用例只测两次拉起的竞争；探测与取锁相撞另有专门用例（§45.30.6）
            deadline = time.monotonic() + 5.0
            while "start" not in self._events() and time.monotonic() < deadline:
                time.sleep(0.02)
            self.assertIn("start", self._events())
            self.assertFalse(ensure_worker(self.root), "已有 worker 持锁：不再拉起")
            self.assertEqual(popen.call_count, 2)
            release[1].set()
            threads[1].join(5)
            self.assertEqual(results.get(1), 0)
            self.assertTrue(worker_running(self.root), "第二个进程退出时第一个仍在工作")
            threads[0].join(10)
        self.assertEqual(results, {0: 0, 1: 0})
        events = self._events()
        self.assertEqual(events.count("start"), 1)
        self.assertEqual(events.count("stop"), 1)

    def test_second_worker_exits_without_touching_ledger(self) -> None:
        self.assertFalse(worker_running(self.root))
        fd = os.open(self.root / LOCK_NAME, os.O_RDWR | os.O_CREAT, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
            self.assertTrue(worker_running(self.root))
            self.assertTrue(wait_for_worker(self.root, timeout=0.1))
            transport = RecordingTransport(Provider.CODEX)
            self.assertEqual(self._run_once(transport), 0)
            self.assertFalse((self.root / DB_NAME).exists())
            self.assertFalse(self.inbox_dir.exists())
        finally:
            fcntl.flock(fd, fcntl.LOCK_UN)
            os.close(fd)
        self.assertFalse(wait_for_worker(self.root, timeout=0.1))

    def _hold_lock(self, operation: int) -> int:
        self.root.mkdir(mode=0o700, parents=True, exist_ok=True)
        fd = os.open(self.root / LOCK_NAME, os.O_RDWR | os.O_CREAT, 0o600)
        fcntl.flock(fd, operation)
        return fd

    def _release_lock(self, fd: int) -> None:
        fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)

    def test_concurrent_probes_do_not_look_like_a_worker(self) -> None:
        # 两个 ab 同时探测：探测只持共享锁，彼此不冲突；旧实现用排他锁探测，会把对方误判成 worker 而不拉起（DESIGN §45.30.6）
        probe = self._hold_lock(fcntl.LOCK_SH)
        try:
            self.assertFalse(worker_running(self.root))
            self.assertFalse(wait_for_worker(self.root, timeout=0.05))
        finally:
            self._release_lock(probe)
        holder = self._hold_lock(fcntl.LOCK_EX)
        try:
            self.assertTrue(worker_running(self.root), "worker 持排他锁时共享锁拿不到")
        finally:
            self._release_lock(holder)

    def test_new_worker_survives_a_probe_holding_the_lock_at_start(self) -> None:
        # 新 worker 取锁的那一刻另一个进程正在探测（瞬时持共享锁）：重试后照常启动，不能以为已有实例而退出
        probe = self._hold_lock(fcntl.LOCK_SH)
        releaser = threading.Timer(0.02, self._release_lock, args=(probe,))
        with patch("agentstatus_bridge.platforms.linux.lifecycle.LOCK_RETRY_SECONDS", 0.1):  # 重试预算 0.4 秒，远长于探测持锁的 0.02 秒
            releaser.start()
            try:
                self.assertEqual(self._run_once(RecordingTransport(Provider.CODEX)), 0)
            finally:
                releaser.join()
        self.assertEqual(self._events().count("start"), 1)
        # 一直拿不到（另一个 worker 真在持有）：重试用完才退出，不碰账本
        shutil.rmtree(self.root)
        holder = self._hold_lock(fcntl.LOCK_EX)
        try:
            with patch("agentstatus_bridge.worker.time.sleep") as sleep:
                self.assertEqual(self._run_once(RecordingTransport(Provider.CODEX)), 0)
            self.assertEqual(sleep.call_count, LOCK_RETRY_ATTEMPTS - 1)
            self.assertFalse((self.root / DB_NAME).exists())
        finally:
            self._release_lock(holder)

    def test_repeated_starts_under_polling_probes_always_leave_a_worker(self) -> None:
        # 压力对照：另一线程不停探测，同时连续启动 worker，每次都必须真正启动。
        # 旧实现（排他锁探测、取锁不重试）跑本用例 5 次全部失败（40 次启动只成功 24–38 次）；确定性反例见上面两个用例
        stop = threading.Event()

        def poll() -> None:
            while not stop.is_set():
                worker_running(self.root)

        prober = threading.Thread(target=poll, daemon=True)
        prober.start()
        try:
            for _ in range(40):
                self._run_once(RecordingTransport(Provider.CODEX))
        finally:
            stop.set()
            prober.join(5)
        self.assertEqual(self._events().count("start"), 40)

    def test_one_loop_dispatches_and_cleans_up(self) -> None:
        with Store.open(self.root) as store:
            _task, attempt = store.create_task(
                title="t",
                flow=Flow.HANDOFF,
                origin=None,
                origin_class="bypass",
                reviewer=None,
                target=ref(),
                body="x",
                refs=[],
                now=1.0,
            )
        transport = RecordingTransport(Provider.CODEX)
        self.assertEqual(self._run_once(transport), 0)
        self.assertEqual(len(transport.calls), 1)
        with Store.open(self.root) as store:
            sent = store.get_attempt(attempt.id)
        assert sent is not None
        self.assertEqual(sent.delivery, Delivery.QUEUED)
        self.assertFalse(worker_running(self.root))
        self.assertTrue(self.inbox_dir.is_dir(), 'Linux worker must open its inbox')
        self.assertEqual(list(self.inbox_dir.iterdir()), [])

    def _pending_task(self, *, body: str = "x", now: float = 1.0) -> str:
        with Store.open(self.root) as store:
            task, _attempt = store.create_task(
                title="t",
                flow=Flow.HANDOFF,
                origin=None,
                origin_class="bypass",
                reviewer=None,
                target=ref(),
                body=body,
                refs=[],
                now=now,
            )
        return task.id

    def test_loop_errors_are_logged_and_retried_before_giving_up(self) -> None:
        self._pending_task()
        calls: list[int] = []

        def broken() -> list:
            calls.append(1)
            raise RuntimeError("synthetic secret detail")

        with patch("agentstatus_bridge.worker.MAX_CONSECUTIVE_FAILURES", 3):
            code = run_worker(
                root=self.root,
                inbox_directory=self.inbox_dir,
                discover_fn=broken,
                transports={Provider.CODEX: RecordingTransport(Provider.CODEX)},
                loop_seconds=0.01,
            )
        self.assertEqual((code, len(calls)), (0, 3))
        text = (self.root / "worker.log").read_text(encoding="utf-8")
        records = [json.loads(line) for line in text.splitlines()]
        events = [record["event"] for record in records]
        self.assertEqual((events[0], events[-1], events.count("loop_error")), ("start", "stop", 3))
        self.assertEqual(next(record for record in records if record["event"] == "loop_error")["error"], "RuntimeError")
        self.assertNotIn("synthetic secret detail", text)
        self.assertFalse(worker_running(self.root))

    def test_start_prunes_old_finished_tasks_and_log_has_no_content(self) -> None:
        old = self._pending_task(body="正文哨兵 A")
        live = self._pending_task(body="正文哨兵 B")
        with Store.open(self.root) as store:
            store.update_task(old, now=1.0, event="closed", closed_at=1.0)
        self.assertEqual(self._run_once(RecordingTransport(Provider.CODEX)), 0)
        with Store.open(self.root) as store:
            self.assertIsNone(store.get_task(old))
            self.assertIsNotNone(store.get_task(live))
        text = (self.root / "worker.log").read_text(encoding="utf-8")
        self.assertIn('"pruned": 1', text)
        self.assertIn('"delivery": "queued"', text)
        self.assertNotIn("正文哨兵", text)

    def test_unopenable_ledger_leaves_no_inbox_and_releases_lock(self) -> None:
        Store.open(self.root).close()
        with sqlite3.connect(self.root / DB_NAME) as connection:
            connection.execute("PRAGMA user_version=99")
        with self.assertRaises(StoreError):
            self._run_once(RecordingTransport(Provider.CODEX))
        self.assertFalse(self.inbox_dir.exists())
        self.assertFalse(worker_running(self.root))


class WorkerSpawnInventoryTests(unittest.TestCase):
    """桥里**所有**创建子进程的地方都必须列在这张清单上（DESIGN §45.36.1）。

    守的是「新起的进程有没有拿到对的状态根与命令名」。初版只认五个后台名字，于是一句
    `subprocess.run([sys.executable, "-m", "agentstatus_bridge", ...])` 能静默绕过去（复核实测）。
    按**点号全名**匹配而不是属性名，否则 `foo.run()` 这类无关调用会被误扫进来。
    新增子进程调用时**故意**要来改这张表——那正是该复核环境传递的时刻。
    这是代码结构回归门禁，不是对间接/动态调用的全程序证明。
    """

    SPAWN_CALLS = frozenset({
        "subprocess.run", "subprocess.call", "subprocess.check_call", "subprocess.check_output",
        "subprocess.Popen", "asyncio.create_subprocess_exec", "asyncio.create_subprocess_shell",
        "os.system", "os.popen", "os.fork", "os.forkpty", "os.posix_spawn", "os.posix_spawnp",
        "os.execv", "os.execve", "os.execvp", "os.spawnv", "os.spawnvp",
    })
    PLATFORM_CALLS = frozenset({'run_capture', 'spawn_worker', '_spawn'})
    # 后台（长命）子进程：只有它会带着整份环境活下去，所以单独再钉一次
    BACKGROUND_CALLS = frozenset({
        "subprocess.Popen", "asyncio.create_subprocess_exec", "asyncio.create_subprocess_shell",
        "os.fork", "os.forkpty", "os.posix_spawn", "os.posix_spawnp",
    })
    EXPECTED = [
        ('reports.py', ('_git_resolve_commit',), '.run_capture'),
        ('transports/codex_queue.py', ('_default_runner',), '.run_capture'),
        ('worker.py', ('ensure_worker',), '.spawn_worker'),
        ('platforms/windows/codex_version.py', ('read_cli_version',), 'subprocess.run'), # W2-1 only --version, UTF-8, no shell
        ('platforms/windows/lifecycle.py', ('_spawn', 'create'), 'subprocess.Popen'), # §77.17 shared breakaway/fallback
        ('platforms/windows/lifecycle.py', ('spawn_worker',), '._spawn'),
        ('platforms/windows/lifecycle.py', ('spawn_fixture',), '._spawn'),
        ('platforms/windows/lifecycle.py', ('run_capture',), 'subprocess.run'), # W2-4 only git read-only commit validation
        ("platforms/linux/mux.py", ("tmux_pane_titles",), "subprocess.run"),    # W1-1下沉，原argv不改
        ("platforms/linux/mux.py", ("tmux_panes",), "subprocess.run"),          # tmux 只读发现
        ("platforms/linux/lifecycle.py", ("run_capture",), "subprocess.run"), # 原git分支，不带errors参数
        ("platforms/linux/lifecycle.py", ("run_capture",), "subprocess.run"), # 原codex分支，errors=replace
        ("platforms/linux/lifecycle.py", ("spawn_worker",), "subprocess.Popen"),                  # 唯一的后台自调用
        # §88.10 relay 的 SSH 子进程：连 hub 而非自调用，不需要 AB_STATE_DIR/AB_COMMAND；-F 专用配置、IdentityAgent none
        ("federation/relay.py", ("connect", "ssh_connector"), "subprocess.Popen"),
    ]

    @staticmethod
    def _dotted(node: ast.AST) -> str:
        parts: list[str] = []
        while isinstance(node, ast.Attribute):
            parts.append(node.attr)
            node = node.value
        return ".".join(reversed(parts + [node.id])) if isinstance(node, ast.Name) else ""

    def inventory(self) -> list[tuple[str, tuple[str, ...], str]]:
        package = Path(__file__).resolve().parents[1] / "src" / "agentstatus_bridge"
        sites: list[tuple[str, tuple[str, ...], str]] = []
        for path in sorted(package.rglob("*.py")):
            tree = ast.parse(path.read_text(encoding="utf-8"))
            for call in (node for node in ast.walk(tree) if isinstance(node, ast.Call)):
                name = self._dotted(call.func)
                if isinstance(call.func, ast.Attribute) and call.func.attr in self.PLATFORM_CALLS:
                    name = '.' + call.func.attr
                if name not in self.SPAWN_CALLS and name not in {'.'+n for n in self.PLATFORM_CALLS}:
                    continue
                owners = tuple(sorted(
                    node.name for node in ast.walk(tree)
                    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and call in ast.walk(node)
                ))
                sites.append((path.relative_to(package).as_posix(), owners, name))
        return sorted(sites)

    def test_every_process_creation_site_is_accounted_for(self) -> None:
        self.assertEqual(
            self.inventory(),
            sorted(self.EXPECTED),
            "桥里新增了创建子进程的地方：先确认它要不要 AB_STATE_DIR/AB_COMMAND，再更新这张清单",
        )

    def test_background_spawn_is_owned_by_ensure_worker(self) -> None:
        background = [site for site in self.inventory() if site[2] in self.BACKGROUND_CALLS]
        self.assertEqual(background, [("federation/relay.py", ("connect", "ssh_connector"), "subprocess.Popen"),
                                      ("platforms/linux/lifecycle.py", ("spawn_worker",), "subprocess.Popen"),
                                      ("platforms/windows/lifecycle.py", ("_spawn", "create"), "subprocess.Popen")])
        self.assertEqual([site for site in self.inventory() if site[2]=='.spawn_worker'],
                         [('worker.py', ('ensure_worker',), '.spawn_worker')])

    def test_no_aliased_or_from_import_can_hide_a_spawn(self) -> None:
        # `_dotted` 只认字面模块名，所以 `import subprocess as _sp` 或 `from subprocess import Popen`
        # 之后的新增调用会整条绕过上面的清单——**而别名是静态可查的**，不能用「不做全程序证明」搪塞
        # （独立 Fable 审计 P3-2；当前包内零此类 import，加这条不需要改任何生产代码）
        package = Path(__file__).resolve().parents[1] / "src" / "agentstatus_bridge"
        risky = {"subprocess", "os", "asyncio"}
        offenders: list[tuple[str, int, str]] = []
        for path in sorted(package.rglob("*.py")):
            tree = ast.parse(path.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    offenders += [
                        (path.name, node.lineno, alias.name)
                        for alias in node.names
                        if alias.name.split(".")[0] in risky and alias.asname
                    ]
                elif isinstance(node, ast.ImportFrom) and (node.module or "").split(".")[0] in risky:
                    offenders.append((path.name, node.lineno, node.module or ""))
        self.assertEqual(offenders, [], "别名或 from 导入会让子进程清单漏检；请改回 `import subprocess` 这种写法")

    def test_matching_keeps_the_module_prefix(self) -> None:
        # 只取属性名的实现会把 `foo.run` 也认成 `run`：那样无关调用会被误扫，这里必须变红
        tree = ast.parse("subprocess.run(x)\nfoo.run(y)\nos.fork()\n")
        names = sorted(self._dotted(node.func) for node in ast.walk(tree) if isinstance(node, ast.Call))
        self.assertEqual(names, ["foo.run", "os.fork", "subprocess.run"])


if __name__ == "__main__":
    unittest.main()
