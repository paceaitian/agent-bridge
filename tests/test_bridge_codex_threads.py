"""协作桥认出同进程的 Codex 根会话（DESIGN §45.48 R1–R6）。

Codex 派出的子代理与根会话在同一进程里各持一个 rollout；桥用 Codex 状态库 `threads(id, source)` 给持有的 thread
正面分类，用调用方的 `CODEX_THREAD_ID`/`CODEX_SESSION_ID` 认出汇报者与发起者，用「每个代际至多一个候选」接续
已登记的投递。夹具全部合成：假 /proc、临时 sqlite、临时账本；状态库里特意放一列内容列，确认只读两列。
"""

from __future__ import annotations

import json
from pathlib import Path
import sqlite3
from tempfile import TemporaryDirectory
from typing import Any
import unittest
import unittest.mock

from agentstatus_bridge import cli
from agentstatus_bridge import endpoints as endpoints_module
from agentstatus_bridge.dispatch import select_generation
from agentstatus_bridge.endpoints import (
    DiscoverySources,
    PaneInfo,
    ResolveError,
    discover,
    identify_caller,
    resolve_target,
)
from agentstatus_bridge.observer_dbus import ObserverView
from agentstatus_bridge.model import Endpoint, Provider
from agentstatus_bridge.platforms.linux.process import ProcessInfo
from agentstatus_bridge.reports import ReportError, _attribute  # pyright: ignore[reportPrivateUsage]
from bridge_support import FakeProc, endpoint, ref

ROOT_A = "019a0000-aaaa-7aaa-8aaa-aaaaaaaaaaaa"
ROOT_B = "019a0000-bbbb-7bbb-8bbb-bbbbbbbbbbbb"
CHILD_C = "019a0000-cccc-7ccc-8ccc-cccccccccccc"
REVERT_R = "019a0000-dddd-7ddd-8ddd-dddddddddddd"
SPAWN = json.dumps({"subagent": {"thread_spawn": {"parent_thread_id": ROOT_A, "depth": 1}}})
REVIEW = json.dumps({"subagent": "review"})


class CodexThreadsBase(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.root = Path(self._tmp.name)
        self.proc = FakeProc(self.root / "proc")
        self.codex_home = self.root / "codex"
        self.codex_home.mkdir()
        self.sqlite_home: Path | None = None
        self.panes: dict[int, PaneInfo] = {}
        # pane_id → 原始标题；给定才有，默认不读真实 tmux（DESIGN §53.3.2）
        self.titles: dict[str, str] = {}

    def sources(self) -> DiscoverySources:
        return DiscoverySources(
            proc_root=self.proc.root,
            claude_sessions=self.root / "none",
            codex_home=self.codex_home,
            codex_sqlite_home=self.sqlite_home,
            grok_home=self.root / "none",
            panes=lambda: self.panes,
            titles=lambda: self.titles,
            runtime=lambda: ObserverView({}),
        )

    def rollout(self, thread: str, suffix: str = "") -> str:
        return str(self.codex_home / "sessions/2026/09/23" / f"rollout-2026-09-23T08-05-25-{thread}{suffix}.jsonl")

    def state_db(self, rows: dict[str, str], *, name: str = "state_5.sqlite", where: Path | None = None,
                 columns: tuple[str, ...] = ("id", "source", "title")) -> None:
        """真实存储词法：单元变体存裸字符串（`cli`），对象变体存 JSON 文本；title 是不该被读的内容列。"""
        folder = where or self.codex_home
        folder.mkdir(parents=True, exist_ok=True)
        connection = sqlite3.connect(folder / name)
        connection.execute(f"CREATE TABLE threads ({', '.join(f'{column} TEXT' for column in columns)})")
        for thread, source in rows.items():
            values = {"id": thread, "source": source, "title": "不该被读的标题"}
            connection.execute(
                f"INSERT INTO threads ({', '.join(columns)}) VALUES ({', '.join('?' for _ in columns)})",
                [values[column] for column in columns],
            )
        connection.commit()
        connection.close()

    def codex(self, pid: int, threads: list[str], *, pane: str | None = "%4", label: str = "work",
              start: str = "100", tty: int = 0, argv: tuple[str, ...] = ("codex",)) -> None:
        shell = pid - 1
        self.proc.add(shell, comm="zsh")
        self.proc.add(pid, comm="codex", ppid=shell, start=start, argv=argv, fds=threads, tty=tty)
        if pane is not None:
            self.panes[shell] = PaneInfo(pane, shell, label)

    def found(self) -> list[Endpoint]:
        return [item for item in discover(self.sources()) if item.ref.provider is Provider.CODEX]


class RootClassificationTests(CodexThreadsBase):
    """R2：状态库正面分类定根；认不出就如实报歧义。"""

    def test_one_root_with_a_lingering_subagent_resolves_the_root(self) -> None:
        self.state_db({ROOT_A: "cli", CHILD_C: SPAWN})
        self.codex(601, [self.rollout(ROOT_A), self.rollout(CHILD_C)])
        [item] = self.found()
        self.assertEqual((item.ref.native_id, item.blocking_issues), (ROOT_A, ()))
        self.assertIn("subagent_threads", item.issues)
        self.assertEqual(resolve_target("%4", self.found()).ref.native_id, ROOT_A)

    def test_review_subagent_without_a_spawn_edge_also_counts_as_subagent(self) -> None:
        self.state_db({ROOT_A: "vscode", CHILD_C: REVIEW})
        self.codex(601, [self.rollout(ROOT_A), self.rollout(CHILD_C)])
        self.assertEqual(self.found()[0].ref.native_id, ROOT_A)

    def test_two_roots_give_one_endpoint_each_and_names_are_ambiguous(self) -> None:
        self.state_db({ROOT_A: "cli", ROOT_B: "cli", CHILD_C: SPAWN})
        self.codex(601, [self.rollout(ROOT_A), self.rollout(ROOT_B), self.rollout(CHILD_C)])
        found = self.found()
        self.assertEqual(sorted(item.ref.native_id for item in found), [ROOT_A, ROOT_B])
        for item in found:
            self.assertIn("multiple_roots", item.issues)
            self.assertEqual(item.blocking_issues, ())
        with self.assertRaises(ResolveError) as caught:
            resolve_target("%4", found)
        self.assertEqual(caught.exception.code, "target_ambiguous")
        self.assertEqual(resolve_target(ROOT_B, found).ref.native_id, ROOT_B)

    def test_any_unknown_thread_keeps_the_process_ambiguous(self) -> None:
        cases = {
            "missing_row": lambda: self.state_db({ROOT_A: "cli"}),
            "unparseable": lambda: self.state_db({ROOT_A: "cli", CHILD_C: "{broken"}),
            "unknown_object": lambda: self.state_db({ROOT_A: "cli", CHILD_C: json.dumps({"future": 1})}),
            "no_database": lambda: None,
            "missing_column": lambda: self.state_db({ROOT_A: "cli"}, columns=("id", "title")),
        }
        for label, prepare in cases.items():
            with self.subTest(case=label):
                for leftover in self.codex_home.glob("state_*.sqlite"):
                    leftover.unlink()
                prepare()
                self.proc = FakeProc(self.root / f"proc-{label}")
                self.codex(601, [self.rollout(ROOT_A), self.rollout(CHILD_C)])
                [item] = self.found()
                self.assertEqual((item.ref.native_id, item.blocking_issues), ("-", ("ambiguous_thread",)))

    def test_a_single_known_subagent_is_never_an_addressable_target(self) -> None:
        # 根的 fd 在写入恢复窗口暂缺，唯一可见的是子代理（Codex §45.48 第二轮 R01）
        self.state_db({CHILD_C: SPAWN})
        self.codex(601, [self.rollout(CHILD_C)])
        [item] = self.found()
        self.assertEqual((item.ref.native_id, item.blocking_issues), ("-", ("subagent_only",)))
        with self.assertRaises(ResolveError):
            resolve_target(CHILD_C, self.found())
        with self.assertRaises(cli.CliError) as caught:
            cli._check_target(resolve_target("%4", self.found()), allow_shared=True)  # noqa: SLF001
        self.assertEqual(str(caught.exception), "target_subagent_only")

    def test_all_subagents_and_no_root_only_leave_a_diagnostic_endpoint(self) -> None:
        other = "019a0000-eeee-7eee-8eee-eeeeeeeeeeee"
        self.state_db({CHILD_C: SPAWN, other: json.dumps({"internal": "memory_consolidation"})})
        self.codex(601, [self.rollout(CHILD_C), self.rollout(other)])
        [item] = self.found()
        self.assertEqual((item.ref.native_id, item.blocking_issues), ("-", ("subagent_only",)))

    def test_single_root_or_unknown_thread_keeps_todays_behavior(self) -> None:
        for label, rows in (("known_root", {ROOT_A: "cli"}), ("no_row", {})):
            with self.subTest(case=label):
                for leftover in self.codex_home.glob("state_*.sqlite"):
                    leftover.unlink()
                self.state_db(rows)
                self.proc = FakeProc(self.root / f"proc-{label}")
                self.codex(601, [self.rollout(ROOT_A)])
                [item] = self.found()
                self.assertEqual((item.ref.native_id, item.issues), (ROOT_A, ()))

    def test_tty_only_processes_are_classified_the_same_way(self) -> None:
        self.state_db({ROOT_A: "cli", CHILD_C: SPAWN})
        self.codex(601, [self.rollout(ROOT_A), self.rollout(CHILD_C)], pane=None, tty=34840)
        [item] = self.found()
        self.assertEqual(item.ref.native_id, ROOT_A)


class StateDatabaseTests(CodexThreadsBase):
    """R2 的读库边界：按版本降序探测、尊重 CODEX_SQLITE_HOME、只读、只选两列。"""

    def test_newest_database_that_knows_the_held_threads_wins(self) -> None:
        self.state_db({ROOT_A: "cli", CHILD_C: SPAWN}, name="state_4.sqlite")
        self.state_db({"019a0000-ffff-7fff-8fff-ffffffffffff": "cli"}, name="state_5.sqlite")
        self.state_db({ROOT_A: "cli"}, name="state_6.sqlite", columns=("id", "title"))
        self.codex(601, [self.rollout(ROOT_A), self.rollout(CHILD_C)])
        self.assertEqual(self.found()[0].ref.native_id, ROOT_A)

    def test_codex_sqlite_home_overrides_codex_home(self) -> None:
        self.state_db({ROOT_A: "cli", CHILD_C: SPAWN}, where=self.root / "sqlite-home")
        self.codex(601, [self.rollout(ROOT_A), self.rollout(CHILD_C)])
        self.assertEqual(self.found()[0].ref.native_id, "-")
        self.sqlite_home = self.root / "sqlite-home"
        self.assertEqual(self.found()[0].ref.native_id, ROOT_A)

    def test_explicit_none_sqlite_home_ignores_the_environment(self) -> None:
        # 夹具隔离守卫（Codex 实现复核 C01）：环境里的 CODEX_SQLITE_HOME 指向别处时，显式 None 仍只看 codex_home
        elsewhere = self.root / "elsewhere"
        self.state_db({ROOT_A: "cli", CHILD_C: SPAWN}, where=elsewhere)
        self.codex(601, [self.rollout(ROOT_A), self.rollout(CHILD_C)])
        with unittest.mock.patch.dict("os.environ", {"CODEX_SQLITE_HOME": str(elsewhere)}):
            self.assertEqual(self.found()[0].ref.native_id, "-")

    def test_database_is_opened_read_only_and_only_two_columns_are_selected(self) -> None:
        self.state_db({ROOT_A: "cli", CHILD_C: SPAWN})
        self.codex(601, [self.rollout(ROOT_A), self.rollout(CHILD_C)])
        seen: list[str] = []
        real_connect = sqlite3.connect

        class Recording:
            def __init__(self, inner: sqlite3.Connection) -> None:
                self.inner = inner

            def execute(self, sql: str, *args: Any) -> sqlite3.Cursor:
                seen.append(sql)
                return self.inner.execute(sql, *args)

            def close(self) -> None:
                self.inner.close()

        def connect(database: str, **kwargs: object) -> Recording:
            seen.append(f"connect {database}")
            return Recording(real_connect(database, **kwargs))  # type: ignore[arg-type]

        with unittest.mock.patch.object(endpoints_module.sqlite3, "connect", side_effect=connect):
            self.assertEqual(self.found()[0].ref.native_id, ROOT_A)
        [opened] = [item for item in seen if item.startswith("connect ")]
        self.assertTrue(opened.endswith("?mode=ro"), opened)
        selects = [item for item in seen if item.lstrip().upper().startswith("SELECT")]
        self.assertEqual(selects, ["SELECT id, source FROM threads WHERE id IN (?, ?)"])

    def test_source_classification_follows_upstream_storage_and_is_non_root_agent(self) -> None:
        kind = endpoints_module._codex_source_kind  # noqa: SLF001
        # 符合有界词法的未知裸 unit（如将来新增的单元变体）按根：上游非根只有 Internal/SubAgent 两种对象变体（C04）
        for value in ("cli", "exec", "vscode", "mcp", "unknown", "future_unit", json.dumps({"custom": "sdk"})):
            with self.subTest(value=value):
                self.assertEqual(kind(value), "root")
        for value in (SPAWN, REVIEW, json.dumps({"subagent": {"other": "x"}}),
                      json.dumps({"internal": "memory_consolidation"})):
            with self.subTest(value=value):
                self.assertEqual(kind(value), "subagent")
        # JSON 字符串形态上游不会写出，不按裸串判根（Fable 实现复核 P3-1）
        for value in ("", "{broken", json.dumps({"future": 1}), json.dumps({"a": 1, "b": 2}), json.dumps([1]),
                      None, "has space", '"cli"', '"subagent"'):
            with self.subTest(value=value):
                self.assertIsNone(kind(value))


class RolloutNameTests(CodexThreadsBase):
    """R6：回退后的 `_<rollout>` 文件名取 thread 段；两种文件同时打开去重；非法后缀不认。"""

    def test_reverted_file_name_is_the_same_thread(self) -> None:
        self.codex(601, [self.rollout(ROOT_A, f"_{REVERT_R}")])
        self.assertEqual(self.found()[0].ref.native_id, ROOT_A)

    def test_both_file_forms_of_one_thread_are_deduplicated(self) -> None:
        self.codex(601, [self.rollout(ROOT_A), self.rollout(ROOT_A, f"_{REVERT_R}")])
        [item] = self.found()
        self.assertEqual((item.ref.native_id, item.threads), (ROOT_A, (ROOT_A,)))

    def test_invalid_suffix_is_not_a_rollout(self) -> None:
        self.codex(601, [self.rollout(ROOT_A, "_notauuid")])
        self.assertEqual(self.found()[0].issues, ("no_thread_yet",))


class ConsumerTests(CodexThreadsBase):
    """R1/R4：按 thread 保留消费者数（含不展示的非交互进程），解析出身份后照常执行 --allow-shared 合同。"""

    def test_hidden_second_consumer_of_the_root_still_needs_allow_shared(self) -> None:
        self.state_db({ROOT_A: "cli", CHILD_C: SPAWN})
        self.codex(601, [self.rollout(ROOT_A), self.rollout(CHILD_C)])
        self.proc.add(700, comm="codex", argv=("codex", "app-server"), fds=[self.rollout(ROOT_A)])
        [item] = self.found()
        self.assertEqual((item.ref.native_id, item.consumers), (ROOT_A, 2))
        self.assertIn("shared_thread", item.issues)
        with self.assertRaises(cli.CliError) as caught:
            cli._check_target(item, allow_shared=False)  # noqa: SLF001
        self.assertEqual(str(caught.exception), "target_shared_thread")
        cli._check_target(item, allow_shared=True)  # noqa: SLF001


class CallerTests(CodexThreadsBase):
    """R3：两个身份变量先于唯一候选快路径判定调用者。"""

    def caller_under(self, pid: int) -> int:
        self.proc.add(900, comm="bash", ppid=pid)
        return 900

    def env(self, thread: str, session: str | None = None) -> dict[str, str]:
        values = {"CODEX_THREAD_ID": thread}
        if session is not None:
            values["CODEX_SESSION_ID"] = session
        return values

    def test_subagent_is_rejected_on_single_multi_and_fallback_paths(self) -> None:
        for label, threads in (("single_unknown", [self.rollout(CHILD_C)]),
                               ("multi", [self.rollout(ROOT_A), self.rollout(CHILD_C)])):
            with self.subTest(path=label):
                self.proc = FakeProc(self.root / f"proc-{label}")
                self.codex(601, threads)
                pid = self.caller_under(601)
                caller = identify_caller(self.found(), pid=pid, proc_root=self.proc.root,
                                         environ=self.env(CHILD_C.upper(), ROOT_A))
                self.assertEqual((caller.endpoint, caller.rejection), (None, "subagent"))
        # 看不见任何 agent 祖先（PID 命名空间）时只能靠环境变量，同样拦下
        self.proc = FakeProc(self.root / "proc-fallback")
        self.proc.add(900, comm="bash")
        caller = identify_caller([], pid=900, proc_root=self.proc.root, environ=self.env(CHILD_C, ROOT_A))
        self.assertEqual(caller.rejection, "subagent")
        self.assertFalse(caller.is_user_shell)

    def test_root_caller_is_resolved_even_when_the_process_is_ambiguous(self) -> None:
        self.codex(601, [self.rollout(ROOT_A), self.rollout(CHILD_C)])
        [item] = self.found()
        self.assertEqual(item.ref.native_id, "-")
        pid = self.caller_under(601)
        caller = identify_caller(self.found(), pid=pid, proc_root=self.proc.root, environ=self.env(ROOT_A, ROOT_A))
        assert caller.endpoint is not None
        self.assertEqual((caller.endpoint.ref.native_id, caller.via), (ROOT_A, "environment"))
        self.assertEqual(caller.endpoint.blocking_issues, ())

    def test_root_caller_whose_fd_is_missing_is_not_taken_for_the_visible_subagent(self) -> None:
        # 写入恢复窗口：进程只露出子代理 C（无分类证据时它按旧兼容成了端点），根 A 的环境证据照样归属 A
        self.codex(601, [self.rollout(CHILD_C)])
        self.assertEqual(self.found()[0].ref.native_id, CHILD_C)
        pid = self.caller_under(601)
        caller = identify_caller(self.found(), pid=pid, proc_root=self.proc.root, environ=self.env(ROOT_A, ROOT_A))
        assert caller.endpoint is not None
        self.assertEqual((caller.endpoint.ref.native_id, caller.endpoint.ref.pid), (ROOT_A, 601))

    def test_root_variables_resolve_a_process_that_has_no_rollout_yet(self) -> None:
        # 比设计字面更宽、有意保留（Codex 实现复核 C03）：两个一致的身份变量是上游注入的正面根证据，进程还没有
        # rollout fd（no_thread_yet）时也按它归属、可以发起；回执要等 rollout 物化后才能按持有集合投到
        self.codex(601, [])
        [bare] = self.found()
        self.assertEqual(bare.issues, ("no_thread_yet",))
        pid = self.caller_under(601)
        caller = identify_caller(self.found(), pid=pid, proc_root=self.proc.root, environ=self.env(ROOT_A, ROOT_A))
        assert caller.endpoint is not None
        self.assertEqual((caller.endpoint.ref.native_id, caller.endpoint.blocking_issues), (ROOT_A, ()))
        cli._check_sender(caller)  # noqa: SLF001
        without = identify_caller(self.found(), pid=pid, proc_root=self.proc.root, environ={})
        with self.assertRaises(cli.CliError) as caught:
            cli._check_sender(without)  # noqa: SLF001 - 没有身份变量的 no_thread_yet 调用方照旧拒绝
        self.assertEqual(str(caught.exception), "caller_unattributed")

    def test_each_root_of_a_multi_root_process_is_its_own_caller(self) -> None:
        self.state_db({ROOT_A: "cli", ROOT_B: "cli"})
        self.codex(601, [self.rollout(ROOT_A), self.rollout(ROOT_B)])
        pid = self.caller_under(601)
        for root in (ROOT_A, ROOT_B):
            with self.subTest(root=root):
                caller = identify_caller(self.found(), pid=pid, proc_root=self.proc.root, environ=self.env(root, root))
                assert caller.endpoint is not None
                self.assertEqual(caller.endpoint.ref.native_id, root)

    def test_identity_variables_compare_case_insensitively(self) -> None:
        # 同一个根 id 只是大小写不同：是根，不是子代理
        self.codex(601, [self.rollout(ROOT_A)])
        pid = self.caller_under(601)
        caller = identify_caller(self.found(), pid=pid, proc_root=self.proc.root,
                                 environ=self.env(ROOT_A.upper(), ROOT_A))
        self.assertIsNone(caller.rejection)
        assert caller.endpoint is not None
        self.assertEqual(caller.endpoint.ref.native_id, ROOT_A)

    def test_session_variable_alone_is_an_agent_sign(self) -> None:
        self.proc.add(900, comm="bash")
        caller = identify_caller([], pid=900, proc_root=self.proc.root, environ={"CODEX_SESSION_ID": ROOT_A})
        self.assertFalse(caller.is_user_shell)
        self.assertIsNone(caller.endpoint)

    def test_old_codex_without_the_variables_keeps_the_ancestry_fast_path(self) -> None:
        self.codex(601, [self.rollout(ROOT_A)])
        pid = self.caller_under(601)
        caller = identify_caller(self.found(), pid=pid, proc_root=self.proc.root, environ={})
        assert caller.endpoint is not None
        self.assertEqual((caller.endpoint.ref.native_id, caller.via), (ROOT_A, "ancestry"))


class GenerationTests(unittest.TestCase):
    """R4：每个代际至多一个候选，再在代际之间优先原代际（Codex §45.48 第二轮 R02）。"""

    def unresolved(self, pid: int, start: str, threads: tuple[str, ...], *issues: str) -> Endpoint:
        base = endpoint(ref(Provider.CODEX, "-", pid=pid, start=start), issues=issues or ("ambiguous_thread",))
        return Endpoint(ref=base.ref, runtime=base.runtime, runtime_source=base.runtime_source, consumers=0,
                        issues=base.issues, threads=threads, thread_consumers=tuple((t, 1) for t in threads))

    def test_original_unresolved_generation_is_not_displaced_by_another_exact_one(self) -> None:
        target = ref(Provider.CODEX, ROOT_A, pid=601, start="100")
        original = self.unresolved(601, "100", (ROOT_A, CHILD_C))
        other = endpoint(ref(Provider.CODEX, ROOT_A, pid=602, start="200"))
        live, problem = select_generation(target, [other, original])
        assert live is not None
        self.assertEqual((live.ref.pid, live.ref.native_id, problem), (601, ROOT_A, None))
        self.assertEqual(live.blocking_issues, ())

    def test_two_other_generations_holding_the_target_are_ambiguous(self) -> None:
        target = ref(Provider.CODEX, ROOT_A, pid=600, start="50")
        live, problem = select_generation(target, [
            self.unresolved(601, "100", (ROOT_A, CHILD_C)), endpoint(ref(Provider.CODEX, ROOT_A, pid=602, start="200")),
        ])
        self.assertEqual((live, problem), (None, "generation_ambiguous"))

    def test_multi_root_generation_matches_only_the_target_root(self) -> None:
        target = ref(Provider.CODEX, ROOT_A, pid=601, start="100")
        roots = [
            Endpoint(ref=ref(Provider.CODEX, root, pid=601, start="100"), issues=("multiple_roots",),
                     threads=(ROOT_A, ROOT_B), thread_consumers=((ROOT_A, 1), (ROOT_B, 1)))
            for root in (ROOT_A, ROOT_B)
        ]
        live, problem = select_generation(target, roots)
        assert live is not None
        self.assertEqual((live.ref.native_id, problem), (ROOT_A, None))

    def test_subagent_only_endpoint_and_legacy_dash_target_never_match(self) -> None:
        target = ref(Provider.CODEX, ROOT_A, pid=601, start="100")
        only = self.unresolved(601, "100", (ROOT_A,), "subagent_only")
        self.assertEqual(select_generation(target, [only]), (None, None))
        legacy = ref(Provider.CODEX, "-", pid=601, start="100")
        self.assertEqual(select_generation(legacy, [self.unresolved(601, "100", (ROOT_A,))]), (None, None))


class IdentityRuleTests(unittest.TestCase):
    """R5 与 R3 的拒绝出口。"""

    def test_dash_is_never_the_same_session(self) -> None:
        self.assertFalse(ref(Provider.CODEX, "-", pid=1).same_session(ref(Provider.CODEX, "-", pid=2)))
        self.assertTrue(ref(Provider.CODEX, ROOT_A, pid=1).same_session(ref(Provider.CODEX, ROOT_A, pid=2)))

    def test_sender_rules(self) -> None:
        codex = ProcessInfo(601, 1, "codex", "100")
        rejected = {
            "sender_is_subagent": endpoints_module.Caller(None, codex, None, True, rejection="subagent"),
            "caller_unattributed": endpoints_module.Caller(None, codex, None, True),
        }
        for code, caller in rejected.items():
            with self.subTest(code=code), self.assertRaises(cli.CliError) as caught:
                cli._check_sender(caller)  # noqa: SLF001
            self.assertEqual(str(caught.exception), code)
        dash = endpoints_module.Caller(endpoint(ref(Provider.CODEX, "-", pid=601)), codex)
        with self.assertRaises(cli.CliError) as caught:
            cli._check_sender(dash)  # noqa: SLF001
        self.assertEqual(str(caught.exception), "caller_unattributed")
        cli._check_sender(endpoints_module.Caller(None, None))  # noqa: SLF001 - 真实用户终端仍可发起
        cli._check_sender(endpoints_module.Caller(endpoint(ref(Provider.CODEX, ROOT_A, pid=601)), codex))  # noqa: SLF001

    def test_report_rules(self) -> None:
        from agentstatus_bridge.reports import ReportInput
        from agentstatus_bridge.model import ReportKind
        attempt = unittest.mock.Mock(target=ref(Provider.CODEX, ROOT_A, pid=601), delivery_detail={})
        report = ReportInput(task_ref="t", kind=ReportKind.ACK)
        codex = ProcessInfo(601, 1, "codex", "100")
        cases = {
            "reporter_is_subagent": endpoints_module.Caller(None, codex, None, True, rejection="subagent"),
            "reporter_unattributed": endpoints_module.Caller(endpoint(ref(Provider.CODEX, "-", pid=601)), codex),
        }
        for code, caller in cases.items():
            with self.subTest(code=code), self.assertRaises(ReportError) as caught:
                _attribute(attempt, report, caller, Path("/nonexistent"))
            self.assertEqual(caught.exception.code, code)


if __name__ == "__main__":
    unittest.main()
