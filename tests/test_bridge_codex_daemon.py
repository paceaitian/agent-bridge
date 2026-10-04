"""协作桥在 Codex 托管 daemon 模式下认回会话（DESIGN §53 批 1：发现、归组、调用者、权限类别、doctor）。

0.157 起交互 TUI 不再持有 rollout 与 writer lock，全由共享的 app-server daemon 持有；桥按 TUI 标题末段的
thread-id 在 daemon 的持有集里唯一前缀认领。夹具全部合成：假 /proc、临时 codex_home 与状态库、给定的原始标题。
"""

from __future__ import annotations

import dataclasses
import json
from pathlib import Path
import shutil
import sqlite3
import subprocess
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import Mock, patch

from agentstatus_bridge import doctor
from agentstatus_bridge import endpoints as endpoints_module
from agentstatus_bridge.codex_argv import codex_app_server
from agentstatus_bridge.dispatch import select_generation
from agentstatus_bridge.endpoints import (
    Caller,
    DiscoverySources,
    PaneInfo,
    ResolveError,
    codex_holdings,
    codex_title_report,
    discover,
    identify_caller,
    permission_class,
    resolve_target,
    title_thread_prefix,
    tmux_pane_titles,
)
from agentstatus_bridge.model import Endpoint, EndpointRef, Provider
from agentstatus_bridge.observer_dbus import ObserverView
from agentstatus_bridge.reports import ReportError, _attribute  # pyright: ignore[reportPrivateUsage]
from bridge_support import FakeProc

T1 = "019b0001-1111-7111-8111-111111111111"
T2 = "019b0002-2222-7222-8222-222222222222"
T3 = "019b0003-3333-7333-8333-333333333333"
T4 = "019b0004-4444-7444-8444-444444444444"
T5 = "019b0005-5555-7555-8555-555555555555"
T6 = "019b0006-6666-7666-8666-666666666666"
# 与 T1 共用前 23 个字符：只给到 8-4-4-4 的标题会同时命中两个
T1_TWIN = "019b0001-1111-7111-8111-999999999999"
DAEMON_ARGV = ("codex", "app-server", "--listen", "unix://", "--managed-daemon")
VECTORS = Path(__file__).resolve().parent / "fixtures" / "codex_title_vectors.json"


def spawn(parent: str) -> str:
    return json.dumps({"subagent": {"thread_spawn": {"parent_thread_id": parent, "depth": 1}}})


def title(thread: str, name: str = "proj") -> str:
    """上游 thread-id 项：29 位前缀加 `...`，放在标题末段。"""
    return f"Ready | {name} | {thread[:29]}..."


class DaemonBase(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.root = Path(self._tmp.name)
        self.proc = FakeProc(self.root / "proc")
        self.codex_home = self.root / "codex"
        self.codex_home.mkdir()
        self.panes: dict[int, PaneInfo] = {}
        self.titles: dict[str, str] = {}

    def sources(self) -> DiscoverySources:
        return DiscoverySources(
            proc_root=self.proc.root,
            claude_sessions=self.root / "none",
            codex_home=self.codex_home,
            codex_sqlite_home=None,
            grok_home=self.root / "none",
            panes=lambda: self.panes,
            titles=lambda: self.titles,
            runtime=lambda: ObserverView({}),
        )

    def rollout(self, thread: str) -> str:
        return str(self.codex_home / "sessions/2026/10/03" / f"rollout-2026-10-03T08-00-00-{thread}.jsonl")

    def lock(self, thread: str) -> str:
        return str(self.codex_home / "thread-writer-locks" / f"{thread}.lock")

    def tui(self, pid: int, pane: str | None, *, shows: str | None = None, raw_title: str | None = None,
            argv: tuple[str, ...] = ("codex",), fds: tuple[str, ...] = (), ppid: int | None = None,
            tty: int = 0) -> None:
        """一个交互 TUI：默认挂在自己的 shell（pid-1）下，shell 是 pane 的 pane_pid。"""
        shell = pid - 1
        if ppid is None:
            self.proc.add(shell, comm="zsh")
            if pane is not None:
                self.panes[shell] = PaneInfo(pane, shell, f"label{pane}")
        self.proc.add(pid, comm="codex", ppid=ppid if ppid is not None else shell, argv=argv, fds=fds, tty=tty)
        if pane is not None and (shows is not None or raw_title is not None):
            self.titles[pane] = raw_title if raw_title is not None else title(shows or "")

    def daemon(self, *fds: str, pid: int = 900, ppid: int = 1000, argv: tuple[str, ...] = DAEMON_ARGV) -> None:
        self.proc.add(pid, comm="codex", ppid=ppid, argv=argv, fds=fds)

    def state_db(self, rows: dict[str, str], *, name: str = "state_5.sqlite", columns: tuple[str, ...] = ("id", "source")) -> None:
        connection = sqlite3.connect(self.codex_home / name)
        connection.execute(f"CREATE TABLE threads ({', '.join(f'{column} TEXT' for column in columns)})")
        for thread, source in rows.items():
            values = {"id": thread, "source": source}
            connection.execute(
                f"INSERT INTO threads ({', '.join(columns)}) VALUES ({', '.join('?' for _ in columns)})",
                [values[column] for column in columns],
            )
        connection.commit()
        connection.close()

    def found(self) -> list[Endpoint]:
        return [item for item in discover(self.sources()) if item.ref.provider is Provider.CODEX]

    def by_pane(self) -> dict[str | None, Endpoint]:
        return {item.ref.pane: item for item in self.found()}


class AppServerPredicateTests(unittest.TestCase):
    """53.3.0：只认子命令 app-server；`_codex_non_interactive` 分不开 daemon 与 exec。"""

    def test_only_the_app_server_subcommand_counts(self) -> None:
        yes = {
            "托管 daemon": ["codex", "app-server", "--listen", "unix://", "--managed-daemon"],
            "不带 --managed-daemon": ["codex", "app-server", "--listen", "unix://"],
            "选项在子命令前": ["codex", "-c", "a=1", "app-server", "--listen", "stdio://"],
            "pid 更新辅助进程": ["codex", "app-server", "daemon", "pid-update-loop"],
        }
        no = {
            "exec": ["codex", "exec", "--full-auto", "hi"],
            "exec-server": ["codex", "exec-server"],
            "mcp-server": ["codex", "mcp-server"],
            "review": ["codex", "review"],
            "sandbox": ["codex", "sandbox", "linux", "--", "codex"],
            "交互": ["codex", "-a", "on-request"],
            "resume": ["codex", "resume", "--last"],
        }
        for label, tokens in yes.items():
            with self.subTest(case=label):
                self.assertTrue(codex_app_server(tokens))
        for label, tokens in no.items():
            with self.subTest(case=label):
                self.assertFalse(codex_app_server(tokens))


class TitleVectorTests(unittest.TestCase):
    """53.3.1：桥用生产解析函数跑共用固定向量（observer 侧跑同一份）。"""

    def test_fixed_vectors(self) -> None:
        vectors = json.loads(VECTORS.read_text(encoding="utf-8"))["vectors"]
        self.assertGreaterEqual(len(vectors), 20)
        for vector in vectors:
            with self.subTest(case=vector["case"]):
                self.assertEqual(title_thread_prefix(vector["title"]), vector["prefix"])
                pane = endpoints_module._with_title(PaneInfo("%1", 1, "s"), vector["title"])  # pyright: ignore[reportPrivateUsage]
                self.assertEqual((pane.thread_prefix, pane.title_has_uuid), (vector["prefix"], vector["uuidShape"]))

    def test_tmux_titles_are_read_by_pane_id_and_raw_titles_stay_out_of_pane_info(self) -> None:
        output = f"%1\t{title(T1)}\n%2\tbad\twith tab\nnot-a-pane\tx\n%3\n"
        completed = subprocess.CompletedProcess([], 0, output, "")
        with patch.object(endpoints_module.subprocess, "run", return_value=completed) as run:
            titles = tmux_pane_titles()
        self.assertEqual(titles, {"%1": title(T1), "%2": "bad\twith tab"})
        # -u：不随调用方的 locale 把 spinner 换成 `_`（Opus 实现复核 P3-3）
        self.assertEqual(run.call_args.args[0][:4], ["tmux", "-u", "list-panes", "-a"])
        self.assertEqual(
            [item.name for item in dataclasses.fields(PaneInfo)],
            ["pane_id", "pane_pid", "session_name", "server_pid", "thread_prefix", "title_has_uuid"],
        )

    def test_tmux_unavailable_gives_no_titles(self) -> None:
        with patch.object(endpoints_module.subprocess, "run", side_effect=OSError):
            self.assertEqual(tmux_pane_titles(), {})


class DaemonDiscoveryTests(DaemonBase):
    """53.3.4–53.3.7：新路径的绑定、原因码、分类、消费者与归组。"""

    def test_each_pane_binds_the_thread_its_title_shows(self) -> None:
        self.daemon(self.lock(T1), self.lock(T2), self.rollout(T1))
        self.tui(1000, "%1", shows=T1)
        self.tui(2000, "%4", shows=T2)
        found = self.by_pane()
        self.assertEqual((found["%1"].ref.native_id, found["%1"].threads, found["%1"].ref.pid), (T1, (T1,), 1000))
        self.assertEqual((found["%4"].ref.native_id, found["%4"].threads), (T2, (T2,)))
        self.assertEqual((found["%1"].blocking_issues, found["%4"].blocking_issues), ((), ()))
        self.assertEqual(resolve_target("%4", self.found()).ref.native_id, T2)

    def test_lock_only_and_rollout_only_are_candidates_and_a_deleted_lock_is_not(self) -> None:
        self.daemon(self.lock(T1), self.rollout(T2), self.lock(T3) + " (deleted)")
        self.tui(1000, "%1", shows=T1)
        self.tui(2000, "%4", shows=T2)
        self.tui(3000, "%5", shows=T3)
        found = self.by_pane()
        self.assertEqual((found["%1"].ref.native_id, found["%4"].ref.native_id), (T1, T2))
        self.assertEqual(found["%5"].issues, ("title_thread_unmatched",))

    def test_title_failures_give_the_three_codes(self) -> None:
        self.daemon(self.lock(T1), self.lock(T1_TWIN))
        self.tui(1000, "%1")  # 没有标题
        self.tui(2000, "%4", shows=T3)  # 对不上
        self.tui(3000, "%5", raw_title=f"Ready | proj | {T1[:23]}")  # 前缀同时命中两个
        found = self.by_pane()
        self.assertEqual(found["%1"].issues, ("title_thread_missing",))
        self.assertEqual(found["%4"].issues, ("title_thread_unmatched",))
        self.assertEqual(found["%5"].issues, ("title_thread_unmatched",))
        for item in found.values():
            self.assertEqual(item.threads, ())

    def test_a_shown_spawned_subagent_climbs_to_its_root(self) -> None:
        self.state_db({T1: "cli", T2: spawn(T1), T3: spawn(T2)})
        self.daemon(self.lock(T1), self.lock(T2), self.lock(T3))
        self.tui(1000, "%1", shows=T3)
        item = self.by_pane()["%1"]
        # 端点挂的是根，不是标题显示的子代理（Opus 实现复核 P3-5）
        self.assertEqual((item.ref.native_id, item.threads), (T1, (T1,)))

    def test_subagents_that_cannot_climb_are_reported(self) -> None:
        review = json.dumps({"subagent": "review"})
        cases = {
            "父不可绑定": ({T2: spawn(T5)}, (T2,)),
            "成环": ({T2: spawn(T3), T3: spawn(T2)}, (T2, T3)),
            "review 子代理": ({T2: review}, (T2,)),
        }
        for label, (rows, held) in cases.items():
            with self.subTest(case=label):
                self.setUp()
                self.state_db({T1: "cli", **rows})
                self.daemon(*(self.lock(thread) for thread in held))
                self.tui(1000, "%1", shows=T2)
                self.assertEqual(self.by_pane()["%1"].issues, ("title_shows_subagent",))

    def test_the_parent_chain_is_bounded_to_eight_levels(self) -> None:
        def chain(levels: int) -> list[str]:
            return [f"019b00{index:02d}-0000-7000-8000-{index:012d}" for index in range(levels + 1)]

        for levels, expected in ((8, "bound"), (9, "title_shows_subagent")):
            with self.subTest(levels=levels):
                self.setUp()
                threads = chain(levels)
                rows = {threads[0]: "cli"} | {child: spawn(parent) for parent, child in zip(threads, threads[1:])}
                self.state_db(rows)
                self.daemon(*(self.lock(thread) for thread in threads))
                self.tui(1000, "%1", shows=threads[-1])
                item = self.by_pane()["%1"]
                if expected == "bound":
                    self.assertEqual(item.ref.native_id, threads[0])
                else:
                    self.assertEqual(item.issues, (expected,))

    def test_unknown_classification_binds_as_root(self) -> None:
        cases = {
            "库里没有这一行": lambda: self.state_db({T2: "cli"}),
            "没有库": lambda: None,
            "查询出错": lambda: self.state_db({T1: "cli"}, columns=("id",)),
        }
        for label, prepare in cases.items():
            with self.subTest(case=label):
                self.setUp()
                prepare()
                self.daemon(self.lock(T1))
                self.tui(1000, "%1", shows=T1)
                self.assertEqual(self.by_pane()["%1"].ref.native_id, T1)

    def test_state_db_unavailable_is_judged_by_the_newest_database(self) -> None:
        classify = endpoints_module._classify_codex_threads  # pyright: ignore[reportPrivateUsage]
        missing = dataclasses.replace(self.sources(), codex_sqlite_home=self.root / "missing")
        self.assertTrue(classify(missing, {T1}).unavailable)  # 目录读不到（Fable 实现复核 P3-3）
        self.assertTrue(classify(self.sources(), {T1}).unavailable)  # 一个库都没有
        self.state_db({T2: "cli"})
        self.assertFalse(classify(self.sources(), {T1}).unavailable)  # 可读、没有行
        self.state_db({T1: "cli"}, name="state_6.sqlite", columns=("id",))
        self.assertTrue(classify(self.sources(), {T1}).unavailable)  # 最新的库出错，旧库可读也不能掩盖
        self.assertEqual(classify(self.sources(), set()).unavailable, False)  # 不查库

    def test_each_thread_is_classified_by_the_newest_database_that_has_it(self) -> None:
        # 两个版本共用目录：daemon 的 T1 只在新库，旧版 TUI 的根 T5 与子代理 T6 只在旧库（Opus 实现复核 P3-2）
        self.state_db({T1: "cli"}, name="state_5.sqlite")
        self.state_db({T5: "cli", T6: spawn(T5)}, name="state_4.sqlite")
        self.daemon(self.lock(T1))
        self.tui(1000, "%1", shows=T1)
        self.tui(3000, "%6", fds=(self.rollout(T5), self.rollout(T6)))
        found = self.by_pane()
        self.assertEqual(found["%1"].ref.native_id, T1)
        # 与基线一致：绑定根、带不阻断的子代理提示，可投递
        self.assertEqual((found["%6"].ref.native_id, found["%6"].issues, found["%6"].blocking_issues), (T5, ("subagent_threads",), ()))
        classify = endpoints_module._classify_codex_threads  # pyright: ignore[reportPrivateUsage]
        classes = classify(self.sources(), {T1, T5, T6})
        self.assertEqual((classes.kinds, classes.parents), ({T1: "root", T5: "root", T6: "subagent"}, {T6: T5}))

    def test_the_newest_database_that_has_a_row_decides(self) -> None:
        # 新库有这一行就以新库为准：分类不同取新库；source 认不出也不再去旧库找
        classify = endpoints_module._classify_codex_threads  # pyright: ignore[reportPrivateUsage]
        self.state_db({T5: spawn(T1), T6: "{"}, name="state_5.sqlite")
        self.state_db({T5: "cli", T6: "cli"}, name="state_4.sqlite")
        classes = classify(self.sources(), {T5, T6})
        self.assertEqual((classes.kinds, classes.parents), ({T5: "subagent"}, {T5: T1}))

    def test_a_parent_chain_spread_over_three_databases_still_climbs(self) -> None:
        # 子→父→根分在三个库里：按 thread 合并时父关系也要跨库累积（Codex 实现复核第 2 轮 N03，变异 M02）
        self.state_db({T3: spawn(T2)}, name="state_6.sqlite")
        self.state_db({T2: spawn(T1)}, name="state_5.sqlite")
        self.state_db({T1: "cli"}, name="state_4.sqlite")
        self.daemon(self.lock(T1), self.lock(T2), self.lock(T3))
        self.tui(1000, "%1", shows=T3)
        self.assertEqual(self.by_pane()["%1"].ref.native_id, T1)

    def test_an_older_database_never_overrides_or_fails_the_newest(self) -> None:
        # 合并以后旧库真会被探到（daemon 下新建、只有 lock 的 thread 常不在新库里）：旧库出错不算「不可用」，
        # 也不覆盖新库已有的分类（Opus 实现复核第 2 轮 P3-2，变异 Q2、Q4）
        classify = endpoints_module._classify_codex_threads  # pyright: ignore[reportPrivateUsage]
        self.state_db({T1: "cli"}, name="state_5.sqlite")
        self.state_db({T2: "cli"}, name="state_4.sqlite", columns=("id",))
        classes = classify(self.sources(), {T1, T2})
        self.assertEqual((classes.kinds, classes.unavailable), ({T1: "root"}, False))
        self.setUp()
        self.state_db({T5: spawn(T1)}, name="state_5.sqlite")
        self.state_db({T5: "cli", T4: "cli"}, name="state_4.sqlite")
        classes = classify(self.sources(), {T4, T5})
        self.assertEqual((classes.kinds, classes.parents), ({T5: "subagent", T4: "root"}, {T5: T1}))

    def test_prefixes_are_compared_beyond_the_first_eight_hex_digits(self) -> None:
        # 同一分钟内建的 thread 前 8 位常相同（53.1）：标题前缀要整段比（Opus 实现复核 P3-4）
        twin = T1[:8] + "-9999-7999-8999-999999999999"
        unheld = T1[:8] + "-8888-7888-8888-888888888888"
        with self.subTest(case="两个持有的 thread 前 8 位相同"):
            self.daemon(self.lock(T1), self.lock(twin))
            self.tui(1000, "%1", shows=T1)
            self.assertEqual(self.by_pane()["%1"].ref.native_id, T1)
        with self.subTest(case="标题显示一个没被持有、前 8 位相同的 thread"):
            self.setUp()
            self.daemon(self.lock(T1))
            self.tui(1000, "%1", shows=unheld)
            self.assertEqual(self.by_pane()["%1"].issues, ("title_thread_unmatched",))

    def test_a_tui_outside_tmux_reports_a_missing_title_in_daemon_mode(self) -> None:
        # 不在 tmux 里的 TUI（按 tty 归组）没有标题可读：daemon 模式下报缺段，不报「先发一句话」（53.8.2，Fable 实现复核 P3-2）
        self.daemon(self.lock(T1))
        self.tui(3000, None, tty=34817)
        [item] = [item for item in self.found() if item.ref.pid == 3000]
        self.assertEqual((item.ref.pane, item.issues), (None, ("title_thread_missing",)))

    def test_wrapper_and_tui_in_one_pane_give_one_outermost_endpoint(self) -> None:
        self.daemon(self.lock(T1))
        self.tui(1000, "%1", shows=T1)
        self.proc.add(1002, comm="codex", ppid=1000, argv=("codex",))  # 包装进程下的真正 TUI
        [item] = self.found()
        self.assertEqual((item.ref.pid, item.ref.native_id), (1000, T1))

    def test_two_unrelated_codex_in_one_pane_are_ambiguous(self) -> None:
        self.daemon(self.lock(T1))
        self.tui(1000, "%1", shows=T1)
        self.proc.add(1005, comm="codex", ppid=999, argv=("codex",))
        [item] = self.found()
        self.assertEqual((item.issues, item.blocking_issues), (("pane_process_ambiguous",), ("pane_process_ambiguous",)))

    def test_a_no_daemon_tui_holding_only_a_lock_is_not_its_own_holder(self) -> None:
        # daemon 模式下：只持有 lock 不算「自己持有」，不走旧路径；标题缺段就报缺段（误走旧路径会直接绑定）
        self.daemon(self.lock(T1))
        self.tui(1000, "%1", shows=T1)
        self.tui(3000, "%5", argv=("codex", "--no-daemon"), fds=(self.lock(T5),))
        self.assertEqual(self.by_pane()["%5"].issues, ("title_thread_missing",))
        # 标题显示自己的 thread：本组持有可绑定，消费者按 rollout 算是 0
        self.titles["%5"] = title(T5)
        item = self.by_pane()["%5"]
        self.assertEqual((item.ref.native_id, item.consumers, item.issues), (T5, 0, ()))

    def test_without_a_daemon_holding_threads_unowned_groups_stay_no_thread_yet(self) -> None:
        self.tui(3000, "%5", argv=("codex", "--no-daemon"), fds=(self.lock(T5),), shows=T5)
        self.assertEqual(self.by_pane()["%5"].issues, ("no_thread_yet",))

    def test_daemon_mode_needs_an_app_server_holding_threads(self) -> None:
        cases = {
            "daemon 空转": lambda: self.daemon(),
            "只有 codex exec 持有": lambda: self.proc.add(3100, comm="codex", argv=("codex", "exec", "x"), fds=(self.lock(T1),)),
        }
        for label, prepare in cases.items():
            with self.subTest(case=label):
                self.setUp()
                prepare()
                self.tui(1000, "%1", shows=T1)
                self.assertEqual(self.by_pane()["%1"].issues, ("no_thread_yet",))
        with self.subTest(case="不带 --managed-daemon 的 daemon"):
            self.setUp()
            self.daemon(self.lock(T1), argv=("codex", "app-server", "--listen", "unix://"))
            self.tui(1000, "%1", shows=T1)
            self.assertEqual(self.by_pane()["%1"].ref.native_id, T1)

    def test_consumers_count_rollouts_only(self) -> None:
        self.daemon(self.lock(T1), self.rollout(T1), self.lock(T2))
        self.tui(1000, "%1", shows=T1)
        self.tui(2000, "%4", shows=T2)
        # 另一个非交互进程只读打开 T1 的 rollout、瞬时打开 T2 的锁文件
        self.proc.add(3100, comm="codex", argv=("codex", "exec", "x"), fds=(self.rollout(T1), self.lock(T2)))
        found = self.by_pane()
        self.assertEqual((found["%1"].consumers, found["%1"].issues), (2, ("shared_thread",)))
        self.assertEqual((found["%4"].consumers, found["%4"].issues), (0, ()))

    def test_unbound_endpoints_hold_nothing(self) -> None:
        self.daemon(self.lock(T1), self.lock(T2))
        self.tui(1000, "%1", shows=T1)
        self.tui(2000, "%4")
        found = self.found()
        unbound = [item for item in found if item.issues]
        self.assertEqual([item.threads for item in unbound], [()])
        caller_env = endpoints_module._codex_caller_env  # pyright: ignore[reportPrivateUsage]
        self.assertEqual(caller_env({"CODEX_THREAD_ID": T2, "CODEX_SESSION_ID": T2}, found), [])
        origin = EndpointRef(Provider.CODEX, T2, pid=4242, start_ticks="1")
        self.assertEqual(select_generation(origin, found), (None, None))

    def test_the_same_thread_in_two_panes(self) -> None:
        self.daemon(self.lock(T1))
        self.tui(1000, "%1", shows=T1)
        self.tui(2000, "%4", shows=T1)
        found = self.found()
        self.assertEqual(sorted(item.ref.native_id for item in found), [T1, T1])
        self.assertEqual(resolve_target("%4", found).ref.pid, 2000)
        with self.assertRaises(ResolveError) as caught:
            resolve_target(T1, found)
        self.assertEqual(caught.exception.code, "target_ambiguous")

    def test_a_residual_title_cannot_bind_another_windows_thread(self) -> None:
        # 只有 app-server 与别组交互进程同时持有一个 thread 时，排除才起作用：这里 daemon 加载了 T5，
        # 旧版 TUI（%5，没有 lock）也开着它的 rollout；%1 的残留标题指向 T5，不能绑上去
        self.daemon(self.lock(T1), self.lock(T5))
        self.tui(3000, "%5", argv=("codex", "--no-daemon"), fds=(self.rollout(T5),))
        self.tui(1000, "%1", shows=T5)
        found = self.by_pane()
        self.assertEqual(found["%1"].issues, ("title_thread_unmatched",))
        self.assertEqual(found["%5"].ref.native_id, T5)

    def test_processes_under_the_daemon_do_not_borrow_the_first_pane(self) -> None:
        # 嵌套：daemon 工具里用 PTY 起的、自己持有 rollout 的交互 codex 不进 %1 的组（Opus 第 1 轮 nested_probe）
        self.daemon(self.lock(T1))
        self.tui(1000, "%1", shows=T1)
        self.proc.add(950, comm="sh", ppid=900)
        self.proc.add(960, comm="codex", ppid=950, argv=("codex", "--no-daemon"), fds=(self.rollout(T6),), tty=34817)
        found = self.found()
        self.assertEqual(resolve_target("%1", found).ref.native_id, T1)
        nested = [item for item in found if item.ref.pid == 960]
        self.assertEqual([(item.ref.pane, item.ref.native_id) for item in nested], [(None, T6)])
        # 同样不借给 Claude：daemon 工具里的 Claude 找不到 pane
        self.proc.add(970, comm="claude", ppid=950)
        pane_for = endpoints_module._pane_for  # pyright: ignore[reportPrivateUsage]
        self.assertIsNone(pane_for(970, self.panes, self.proc.root))

    def test_other_codex_ancestors_still_lend_their_pane(self) -> None:
        # 反向：交互 codex 下的嵌套交互 codex、`codex sandbox -- codex` 里的交互 codex 照旧借 pane
        self.tui(1000, "%1")
        self.proc.add(1010, comm="codex", ppid=1000, argv=("codex",), fds=(self.rollout(T1),))
        self.tui(1020, "%6", argv=("codex", "sandbox", "linux", "--", "codex"))
        self.proc.add(1021, comm="codex", ppid=1020, argv=("codex",), fds=(self.rollout(T2),))
        found = self.by_pane()
        # 先断言两个 pane 都有端点：`_pane_for` 停错地方时以断言失败变红而不是 KeyError（Opus 实现复核 P3-6）
        self.assertLessEqual({"%1", "%6"}, found.keys())
        self.assertEqual((found["%1"].ref.pid, found["%1"].ref.native_id), (1010, T1))
        self.assertEqual((found["%6"].ref.pid, found["%6"].ref.native_id), (1021, T2))

    def test_holdings_are_read_by_one_function(self) -> None:
        self.proc.add(
            1500,
            comm="codex",
            fds=(self.rollout(T1), self.lock(T2), self.lock(T3) + " (deleted)",
                 str(self.root / "elsewhere" / "thread-writer-locks" / f"{T4}.lock")),
        )
        self.assertEqual(codex_holdings(1500, self.proc.root, self.codex_home), (frozenset({T1}), frozenset({T2})))
        self.assertEqual(codex_holdings(4444, self.proc.root, self.codex_home), (frozenset(), frozenset()))


class DaemonCallerTests(DaemonBase):
    """53.4：调用者的 daemon 分支、代际核对与权限类别。"""

    def setUp(self) -> None:
        super().setUp()
        # %1 的 TUI（1000）拉起 daemon（900）；T3 已加载但没有窗口显示
        self.daemon(self.lock(T1), self.lock(T2), self.lock(T3))
        self.tui(1000, "%1", shows=T1, argv=("codex", "-a", "on-request"))
        self.tui(2000, "%4", shows=T2)
        self.proc.add(950, comm="sh", ppid=900)
        self.proc.add(951, comm="python3", ppid=950)
        self.yolo = self.root / "config.toml"
        self.yolo.write_text('approval_policy = "never"\nsandbox_mode = "danger-full-access"\n', encoding="utf-8")

    def caller(self, thread: str, session: str | None = None, *, pid: int = 951, found: list[Endpoint] | None = None) -> Caller:
        environ = {"CODEX_THREAD_ID": thread, "CODEX_SESSION_ID": session or thread}
        return identify_caller(
            self.found() if found is None else found,
            pid=pid,
            proc_root=self.proc.root,
            environ=environ,
            codex_home=self.codex_home,
        )

    def test_a_displayed_thread_resolves_to_its_window(self) -> None:
        caller = self.caller(T1)
        assert caller.endpoint is not None and caller.agent_process is not None
        self.assertEqual((caller.endpoint.ref.pid, caller.endpoint.ref.native_id, caller.via), (1000, T1, "daemon"))
        self.assertEqual(caller.agent_process.pid, 1000)
        # 权限类别取那个 TUI 的 argv，不按 daemon 推
        self.assertEqual(permission_class(caller, proc_root=self.proc.root, codex_config=self.yolo), "prompting")
        # 不会因为 daemon 是 %1 的子进程就归到 %1
        other = self.caller(T2)
        assert other.endpoint is not None
        self.assertEqual(other.endpoint.ref.pid, 2000)

    def test_a_thread_the_daemon_does_not_hold_is_unattributed(self) -> None:
        caller = self.caller(T5)
        self.assertEqual((caller.endpoint, caller.agent_process and caller.agent_process.pid), (None, 900))
        # 即使有一个端点自称 T5，daemon 不持有也不认（E 分支同样查 T ∈ D）
        fake = Endpoint(ref=EndpointRef(Provider.CODEX, T5, pid=2000, start_ticks="100", pane="%4"))
        self.assertIsNone(self.caller(T5, found=[fake]).endpoint)
        attempt = Mock(target=EndpointRef(Provider.CODEX, T5, pid=2000, start_ticks="100"), delivery_detail={})
        with self.assertRaises(ReportError) as caught:
            _attribute(attempt, Mock(manual=False), caller, self.proc.root, codex_home=self.codex_home)
        self.assertEqual(caught.exception.code, "reporter_unattributed")

    def test_an_undisplayed_thread_gets_the_daemon_as_its_endpoint(self) -> None:
        caller = self.caller(T3)
        assert caller.endpoint is not None
        ref = caller.endpoint.ref
        self.assertEqual((ref.pid, ref.pane, ref.native_id, caller.via), (900, None, T3, "daemon"))
        attempt = Mock(
            target=EndpointRef(Provider.CODEX, T3, pid=1000, start_ticks="100"),
            delivery_detail={"deliveredPid": 1000, "deliveredStart": "100"},
        )
        # 投递记下的 TUI（1000）还活着，但它只是视图、不持有 T3：照样接受
        self.assertEqual(_attribute(attempt, Mock(manual=False), caller, self.proc.root, codex_home=self.codex_home), "agent")

    def test_a_thread_in_two_windows_gets_the_daemon_as_its_endpoint(self) -> None:
        self.titles["%4"] = title(T1)
        caller = self.caller(T1)
        assert caller.endpoint is not None
        self.assertEqual((caller.endpoint.ref.pid, caller.endpoint.ref.pane), (900, None))

    def test_an_exec_ancestor_stays_unattributed(self) -> None:
        # exec 持有自己 thread 的 fd：只有这样才分得开「D 用 app-server 判」与「D 用非交互判」
        self.proc.add(3000, comm="codex", argv=("codex", "exec", "x"), fds=(self.lock(T4),))
        self.proc.add(3001, comm="python3", ppid=3000)
        caller = self.caller(T4, pid=3001)
        assert caller.agent_process is not None
        self.assertEqual((caller.endpoint, caller.agent_process.pid), (None, 3000))
        # 它的权限类别仍按配置推，只有 app-server 固定未知
        self.assertEqual(permission_class(Caller(None, caller.agent_process), proc_root=self.proc.root, codex_config=self.yolo), "bypass")

    def test_an_adopted_daemon_works_the_same(self) -> None:
        shutil.rmtree(self.proc.root / "900")
        self.daemon(self.lock(T1), self.lock(T2), self.lock(T3), ppid=1)
        caller = self.caller(T2)
        assert caller.endpoint is not None
        self.assertEqual(caller.endpoint.ref.pid, 2000)

    def test_a_subagent_is_rejected(self) -> None:
        self.assertEqual(self.caller(T2, T1).rejection, "subagent")

    def test_a_no_daemon_tui_in_the_new_path_resolves_by_identity(self) -> None:
        # 新路径下的非 daemon TUI（只持 lock、标题缺段）里的工具：身份码被 for_thread 剥掉
        self.tui(3000, "%5", argv=("codex", "--no-daemon"), fds=(self.lock(T5),))
        self.proc.add(3050, comm="python3", ppid=3000)
        caller = self.caller(T5, pid=3050)
        assert caller.endpoint is not None
        self.assertEqual((caller.endpoint.ref.native_id, caller.endpoint.issues), (T5, ()))

    def test_a_tool_of_a_wrapped_no_daemon_tui_resolves_to_its_group(self) -> None:
        # 包装进程 3000 下的 --no-daemon TUI 3002 只持 lock（第一句话之前或 F02 缺席）：组端点是最外层的 3000，
        # TUI 自己的工具沿紧邻的 codex 祖先找到它（Opus 实现复核 P3-1；基线按 3002 自己的端点能认）
        self.tui(3000, "%5", shows=T5)
        self.proc.add(3002, comm="codex", ppid=3000, argv=("codex", "--no-daemon"), fds=(self.lock(T5),))
        self.proc.add(3050, comm="python3", ppid=3002)
        caller = self.caller(T5, pid=3050)
        assert caller.endpoint is not None and caller.agent_process is not None
        self.assertEqual((caller.endpoint.ref.pid, caller.endpoint.ref.native_id, caller.agent_process.pid), (3000, T5, 3002))
        attempt = Mock(target=caller.endpoint.ref, delivery_detail={})
        self.assertEqual(_attribute(attempt, Mock(manual=False), caller, self.proc.root, codex_home=self.codex_home), "agent")
        # 任务是在 TUI 自己持有 rollout 时投给它的（旧路径，端点就是 3002）；汇报时恰逢 F02、端点换成包装进程：
        # 汇报的正是投递进程本身，接受（Opus 实现复核第 2 轮 P3-1）
        delivered = Mock(
            target=EndpointRef(Provider.CODEX, T5, pid=3002, start_ticks="100"),
            delivery_detail={"deliveredPid": 3002, "deliveredStart": "100"},
        )
        try:
            outcome = _attribute(delivered, Mock(manual=False), caller, self.proc.root, codex_home=self.codex_home)
        except ReportError as error:  # 以断言失败变红，不以异常变红（变异 P31）
            outcome = error.code
        self.assertEqual(outcome, "agent")
        # 发现与调用之间包装进程换了代（pid 复用）：不借（Codex 实现复核第 2 轮 N03，变异 M04）
        stale = [
            dataclasses.replace(item, ref=dataclasses.replace(item.ref, start_ticks="1")) if item.ref.pid == 3000 else item
            for item in self.found()
        ]
        self.assertIsNone(self.caller(T5, pid=3050, found=stale).endpoint)
        # 隔着 shell 的嵌套 codex 不借外层组的端点（Codex 复审 R01）
        self.proc.add(3060, comm="zsh", ppid=3002)
        self.proc.add(3061, comm="codex", ppid=3060, argv=("codex",))
        self.proc.add(3062, comm="python3", ppid=3061)
        nested = self.caller(T5, pid=3062)
        assert nested.agent_process is not None
        self.assertEqual((nested.endpoint, nested.agent_process.pid), (None, 3061))

    def test_an_unbound_or_two_level_wrapper_still_resolves_by_identity(self) -> None:
        # 包装进程标题缺段（未绑定）：TUI 的工具照样按身份解析（变异 W5）；两层包装照样补找到最外层（变异 W6）
        self.tui(3000, "%5")
        self.proc.add(3001, comm="codex", ppid=3000, argv=("codex",))
        self.proc.add(3002, comm="codex", ppid=3001, argv=("codex", "--no-daemon"), fds=(self.lock(T5),))
        self.proc.add(3050, comm="python3", ppid=3002)
        caller = self.caller(T5, pid=3050)
        assert caller.endpoint is not None and caller.agent_process is not None
        self.assertEqual((caller.endpoint.ref.pid, caller.endpoint.ref.native_id, caller.agent_process.pid), (3000, T5, 3002))

    def test_an_exec_or_nested_codex_directly_under_a_legacy_tui_does_not_borrow_it(self) -> None:
        # shell 对单条 -c 命令做 exec 优化：旧路径 TUI（%6，自己持有 T6）用工具起的 codex exec 与嵌套 codex
        # 是它的直接子进程。它们的工具不能被认成 %6 的窗口（R01、53.4.1；Opus 实现复核第 2 轮 P2-1）
        self.tui(4000, "%6", argv=("codex", "-a", "on-request"), fds=(self.rollout(T6),))
        self.proc.add(4100, comm="codex", ppid=4000, argv=("codex", "exec", "x"), fds=(self.lock(T4),))
        self.proc.add(4150, comm="python3", ppid=4100)
        self.proc.add(4200, comm="codex", ppid=4000, argv=("codex",), fds=(self.lock(T5),))  # 嵌套会话处在 F02
        self.proc.add(4250, comm="python3", ppid=4200)
        for pid, thread, agent in ((4150, T4, 4100), (4250, T5, 4200)):
            with self.subTest(agent=agent):
                caller = self.caller(thread, pid=pid)
                assert caller.agent_process is not None
                self.assertEqual((caller.endpoint, caller.agent_process.pid), (None, agent))

    def test_unbound_outer_endpoints_lend_only_to_wrapped_tuis(self) -> None:
        # 外层端点未绑定（标题缺段）时，只借给包装链里的交互 TUI（Codex 实现复核第 2 轮 R01、Opus P2-1）：
        # - 挂在纯包装进程下的 codex exec 不借（变异 W1：补找方不限交互进程）；
        # - 外层其实是自己持有 thread 的真 TUI（%7，持有 T6 的 lock），它直接起的嵌套 codex 不借（外层不是包装层）
        self.tui(3000, "%5")
        self.proc.add(3100, comm="codex", ppid=3000, argv=("codex", "exec", "x"), fds=(self.lock(T4),))
        self.proc.add(3150, comm="python3", ppid=3100)
        self.tui(5000, "%7", argv=("codex", "--no-daemon"), fds=(self.lock(T6),))
        self.proc.add(5200, comm="codex", ppid=5000, argv=("codex",), fds=(self.lock(T5),))
        self.proc.add(5250, comm="python3", ppid=5200)
        for pid, thread, agent in ((3150, T4, 3100), (5250, T5, 5200)):
            with self.subTest(agent=agent):
                caller = self.caller(thread, pid=pid)
                assert caller.agent_process is not None
                self.assertEqual((caller.endpoint, caller.agent_process.pid), (None, agent))

    def test_a_wrapper_holding_the_callers_own_thread_still_lends(self) -> None:
        # 包装进程自己也开着 T 的 lock（持有 ⊆ {T}）仍算包装层（Opus 实现复核第 3 轮 P3-2，变异 X3）
        self.tui(3000, "%5", fds=(self.lock(T5),))
        self.proc.add(3002, comm="codex", ppid=3000, argv=("codex", "--no-daemon"), fds=(self.lock(T5),))
        self.proc.add(3050, comm="python3", ppid=3002)
        caller = self.caller(T5, pid=3050)
        assert caller.endpoint is not None
        self.assertEqual((caller.endpoint.ref.pid, caller.endpoint.ref.native_id), (3000, T5))

    def test_a_real_tui_in_the_middle_of_the_chain_stops_the_lookup(self) -> None:
        # 包装进程 → 持有 T6 的真 TUI → 它直接起的嵌套 codex（持有 T5）：标题缺段、两层都在 F02 时，嵌套 codex 的
        # 工具不能越过中间的真 TUI 借外层窗口（Opus 实现复核第 3 轮 P3-1，探针 B1）
        # 中间是 codex exec（持有 T6 的 lock 与 rollout）同样截断：exec 不成为发现端点，rollout 正常打开也会被跳过
        #（Codex 实现复核第 3 轮 R01 残余的第二个反例）
        for middle_argv, with_rollout in ((("codex", "--no-daemon"), False), (("codex", "exec", "x"), True)):
            with self.subTest(middle=middle_argv[1]):
                self.setUp()  # 换了临时 codex_home：fd 路径要在 setUp 之后再算，持有判定按 home 锚定
                middle_fds = (self.lock(T6), self.rollout(T6)) if with_rollout else (self.lock(T6),)
                self.tui(3000, "%5")
                self.proc.add(3001, comm="codex", ppid=3000, argv=middle_argv, fds=middle_fds)
                self.proc.add(3002, comm="codex", ppid=3001, argv=("codex",), fds=(self.lock(T5),))
                self.proc.add(3050, comm="python3", ppid=3002)
                caller = self.caller(T5, pid=3050)
                assert caller.agent_process is not None
                self.assertEqual((caller.endpoint, caller.agent_process.pid), (None, 3002))

    def test_the_wrapper_chain_stops_at_the_daemon(self) -> None:
        # daemon 是 %1 的 TUI 的子进程：从 daemon 下的进程往上补找时，到 app-server 就停，不借 %1 的端点
        wrapper_candidates = endpoints_module._codex_wrapper_candidates  # pyright: ignore[reportPrivateUsage]
        by_pid: dict[int, list[Endpoint]] = {}
        for item in self.found():
            by_pid.setdefault(item.ref.pid, []).append(item)
        self.assertIn(1000, by_pid)
        outer = [info for pid in (900, 1000) if (info := endpoints_module.procfs.read_process(pid, self.proc.root))]
        home = self.codex_home
        self.assertEqual(wrapper_candidates(outer, by_pid, self.proc.root, T1, home), [])
        # daemon 只持有 T1 时「持有 ⊆ {T}」挡不住，靠的是在 app-server 处停（变异 R1b）
        shutil.rmtree(self.proc.root / "900")
        self.daemon(self.lock(T1))
        outer = [info for pid in (900, 1000) if (info := endpoints_module.procfs.read_process(pid, self.proc.root))]
        self.assertEqual(wrapper_candidates(outer, by_pid, self.proc.root, T1, home), [])
        self.assertEqual(wrapper_candidates(outer[1:], by_pid, self.proc.root, T1, home), by_pid[1000])
        # 借来的端点身份不相容（已绑定到别的 thread）也不借（Opus 实现复核第 2 轮 P2-1）
        self.assertEqual(wrapper_candidates(outer[1:], by_pid, self.proc.root, T2, home), [])

    def test_a_window_whose_tui_changed_generation_does_not_lend_its_argv(self) -> None:
        # 发现与调用之间 %1 的 TUI 换了代（pid 复用）：不把新进程当 agent 进程，权限类别未知（Fable P3-4、Opus P3-5）
        stale = [
            dataclasses.replace(item, ref=dataclasses.replace(item.ref, start_ticks="1")) if item.ref.pid == 1000 else item
            for item in self.found()
        ]
        caller = self.caller(T1, found=stale)
        assert caller.endpoint is not None
        self.assertEqual((caller.endpoint.ref.pid, caller.agent_process), (1000, None))
        self.assertIsNone(permission_class(caller, proc_root=self.proc.root, codex_config=self.yolo))

    def test_the_daemon_endpoint_has_no_permission_class(self) -> None:
        caller = self.caller(T3)
        self.assertIsNone(permission_class(caller, proc_root=self.proc.root, codex_config=self.yolo))
        assert caller.endpoint is not None
        # 作为接收方（没有 agent 进程，只看端点 pid）也是未知
        self.assertIsNone(permission_class(Caller(caller.endpoint, None), proc_root=self.proc.root, codex_config=self.yolo))

    def test_receipts_to_a_daemon_origin_follow_where_the_thread_is_shown(self) -> None:
        origin = EndpointRef(Provider.CODEX, T3, pid=900, start_ticks="100")
        self.assertEqual(select_generation(origin, self.found()), (None, None))  # 没有窗口显示
        self.titles["%4"] = title(T3)
        chosen, problem = select_generation(origin, self.found())
        self.assertEqual((chosen and chosen.ref.pid, problem), (2000, None))  # 恰好一个窗口
        self.titles["%1"] = title(T3)
        self.assertEqual(select_generation(origin, self.found()), (None, "generation_ambiguous"))


class DoctorTitleTests(DaemonBase):
    """53.5：doctor 只报计数与提示。"""

    def test_without_a_daemon_only_the_mode_is_reported(self) -> None:
        self.tui(1000, "%1", shows=T1)
        report = codex_title_report(self.sources())
        self.assertEqual(report, {"daemonMode": False})
        self.assertIn("未检测到 daemon 持有的会话", doctor.thread_title_lines(report)[0])

    def test_three_title_kinds_and_the_state_db(self) -> None:
        self.daemon(self.lock(T1), self.lock(T2))
        self.tui(1000, "%1", shows=T1)
        self.tui(2000, "%4", raw_title=f"Working ⠙ {T2[:29]}...")  # 紧挨 activity，粘在一起
        self.tui(3000, "%5", raw_title="Ready | proj")
        report = codex_title_report(self.sources())
        self.assertEqual(
            report,
            {"daemonMode": True, "withThreadId": 1, "shortThreadId": 0, "uuidNotParsed": 1, "withoutThreadId": 1,
             "stateDbUnavailable": True},
        )
        lines = "\n".join(doctor.thread_title_lines(report))
        self.assertIn("不紧挨 activity", lines)
        self.assertIn("停在选择器", lines)
        self.assertIn("状态库读不到", lines)
        # 不输出标题原文与 thread id
        for secret in ("proj", T1[:8], T2[:8], "Working"):
            self.assertNotIn(secret, lines)
        self.state_db({T1: "cli"})
        self.assertFalse(codex_title_report(self.sources())["stateDbUnavailable"])

    def test_truncated_ids_are_counted_apart(self) -> None:
        # 标题尾截只剩 23 字符：桥在持有集里唯一仍认，observer 不认、hook 结局不公开，doctor 要单独说出来
        #（Opus 实现复核第 2 轮 P3-3）
        self.daemon(self.lock(T1), self.lock(T2))
        self.tui(1000, "%1", shows=T1)
        self.tui(2000, "%4", raw_title=f"Ready | proj | {T2[:23]}")
        report = codex_title_report(self.sources())
        self.assertEqual((report["withThreadId"], report["shortThreadId"]), (2, 1))
        lines = "\n".join(doctor.thread_title_lines(report))
        self.assertIn("1 个的会话 id 被截短", lines)
        # 措辞限定在走托管 daemon 的窗口：legacy/--no-daemon 窗口按进程关系定位，不受门槛影响（Codex 第 3 轮 N04）
        self.assertIn("按进程关系定位的旧版或 --no-daemon 窗口不受影响", lines)
        self.assertNotIn(T2[:8], lines)
        self.assertEqual(self.by_pane()["%4"].ref.native_id, T2)
        self.assertEqual(endpoints_module.OBSERVER_HOOK_PREFIX_MIN, len(T1[:29]))


if __name__ == "__main__":
    unittest.main()
