"""DESIGN §93.1/§93.2：`ab tasks` 的筛选与取最新 200 条，以及决定类命令（pause/resume/cancel/close/retry）的 `--json`。

全部经真实 `cli.main`（即真实 `build_parser`）解析 argv；账本、状态根与发现都在临时目录与替身里，不连真实 HOME、
Codex daemon 或现役账本。本机用例的夹具 `LocalCliCase` 也供 §93.3 的关联用例复用（反向不依赖）。

本模块在 `bridge-windows` CI 选择集里（§94.3）：纯函数与假 Win32 内核用例两种系统都跑；替身 Linux 发现与联邦库的
夹具类在 Windows 上按选择器放行的 `POSIX-only:` 前缀跳过（缺省平台是真实 Win32，Linux 平台要导入 fcntl，
提权的 Windows CI 不建联邦库）。
"""

from __future__ import annotations

from contextlib import closing, nullcontext, redirect_stderr, redirect_stdout
from dataclasses import replace
import datetime
from io import StringIO
import json
import os
from pathlib import Path
import sqlite3
from tempfile import TemporaryDirectory
import time
import unittest
from unittest.mock import patch

from bridge_support import discovering, endpoint, ref, with_name_views
from bridge_winapi import Kernel
import test_bridge_windows_callers as windows_callers
import test_bridge_windows_claude as windows_claude
import test_bridge_windows_discovery as windows_discovery
from test_bridge_windows_discovery import uuid

from agentstatus_bridge import cli, observer_dbus, summary
from agentstatus_bridge.endpoints import Caller
from agentstatus_bridge.model import Delivery, Endpoint, EndpointRef, Flow, Provider, Role
from agentstatus_bridge.platforms.factory import make_platform, using_platform
from agentstatus_bridge.platforms.linux.process import ProcessInfo
from agentstatus_bridge.platforms.windows import commands as windows_commands
from agentstatus_bridge.store import Store
from agentstatus_bridge.task_filter import FilterError, SessionMatch, TaskFilter, parse_since
from agentstatus_bridge.transports.codex_native import NativeFailure
from agentstatus_bridge.federation import commands as fed_commands, directory
from agentstatus_bridge.ids import new_id
from agentstatus_bridge.federation.fedstore import FederatedStore, now_ms
from test_bridge_federation_cli import CLAUDE_A, DEV_A, DEV_B, LOCAL_REVIEW, ORIGIN, THREAD_B, WORKER, FedCliCase
from test_bridge_federation_cli import USER as FED_USER
from test_bridge_federation_cli import as_agent as fed_agent

IMPL_ID = "019a0000-aaaa-7aaa-8aaa-aaaaaaaaaaaa"
LEAD_ID = "019a0000-bbbb-7bbb-8bbb-bbbbbbbbbbbb"
REVIEW_ID = "0000000c-cccc-4ccc-8ccc-cccccccccccc"
OTHER_ID = "019a0000-dddd-7ddd-8ddd-dddddddddddd"
IMPL = endpoint(ref(Provider.CODEX, IMPL_ID, pid=1000, pane="%1", label="impl", server=100))
LEAD = endpoint(ref(Provider.CODEX, LEAD_ID, pid=3000, pane="%3", label="lead", server=100))
REVIEW = endpoint(ref(Provider.CLAUDE, REVIEW_ID, pid=2000, pane="%2", label="review"))
OTHER = endpoint(ref(Provider.CODEX, OTHER_ID, pid=4000, pane="%4", label="other", server=100))
USER = Caller(None, None)
# 跨设备用例里 win 上的另外两个会话：复核方与旁观者
HELPER_ID = "019a0000-eeee-7eee-8eee-eeeeeeeeeeee"
HELPER = endpoint(ref(Provider.CODEX, HELPER_ID, pid=7100, pane="%9", label="helper", server=100))
OTHER_WIN = endpoint(ref(Provider.CODEX, "019a0000-ffff-7fff-8fff-ffffffffffff", pid=7200, pane="%8", label="bystander",
                         server=100))


# Windows CI 上的跳过原因（§94.3）：必须以选择器放行的 POSIX-only: 开头，否则整份选择判失败；
# test_bridge_federation_windows 导入这两个常量核对前缀。跨设备夹具 FedCliCase 在它自己的模块里同样用常量
LINUX_FIXTURE_REASON = "POSIX-only: 替身 Linux 发现与调用方、Linux 私有状态目录（Windows 缺省平台是真实 Win32，Linux 平台要导入 fcntl）"
TZSET_REASON = "POSIX-only: 需要 time.tzset 固定时区"
linux_fixture = unittest.skipUnless(os.name == "posix", LINUX_FIXTURE_REASON)


def as_agent(item: Endpoint) -> Caller:
    return Caller(item, ProcessInfo(item.ref.pid, 1, item.ref.provider.value, item.ref.start_ticks))


def dumped(document: object) -> str:
    """`_print_json` 的输出格式（独立写出，不经被测代码）：用于逐字节比对。"""
    return json.dumps(document, ensure_ascii=False, indent=2, sort_keys=True) + "\n"


@linux_fixture
class LocalCliCase(unittest.TestCase):
    """本机命令的公共夹具：临时状态根、替身发现与调用者、worker 不真起；不含用例。"""

    def setUp(self) -> None:
        temporary = TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.state = Path(temporary.name) / "bridge"
        self.endpoints: list[Endpoint] = [IMPL, LEAD, REVIEW, OTHER]
        self.caller: Caller = USER
        self.worker_up = True
        self.discover_calls = 0

        def endpoints() -> list[Endpoint]:
            self.discover_calls += 1
            return list(self.endpoints)

        patches = [
            patch.object(observer_dbus, "_observer_rows", return_value=[]),
            patch.dict(os.environ, {"AB_STATE_DIR": str(self.state),
                                    "AB_CLAUDE_SESSIONS_DIR": str(Path(temporary.name) / "claude-sessions")}),
            patch.object(cli, "discover", side_effect=discovering(endpoints)),
            patch.object(cli, "identify_caller", side_effect=lambda _endpoints: self.caller),
            patch.object(cli, "ensure_worker", return_value=False),
            patch.object(cli, "worker_running", side_effect=lambda _root: self.worker_up),
            patch.object(cli, "_receiver_class", return_value="bypass"),
        ]
        for item in patches:
            item.start()
            self.addCleanup(item.stop)

    def run_cli(self, *argv: str) -> tuple[int, str, str]:
        out, err = StringIO(), StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            code = cli.main(list(argv))
        return code, out.getvalue(), err.getvalue()

    def store(self) -> Store:
        return Store.open(self.state)

    def send(self, *extra: str, to: str = "codex@impl", message: str = "实现 X\n细节", caller: Caller | None = None) -> str:
        self.caller = caller or as_agent(LEAD)
        code, out, err = self.run_cli("send", "--to", to, "-m", message, "--no-wait", "--json", *extra)
        self.assertEqual(code, cli.EXIT_OK, err)
        return str(json.loads(out)["id"])

    def mark_sent(self, task_id: str, delivery: Delivery = Delivery.QUEUED) -> None:
        with self.store() as store:
            attempt = store.attempts(task_id)[-1]
            store.begin_send(attempt.id, now=1.0, pid=1, start_ticks="1")
            store.finish_send(attempt.id, delivery=delivery, reason="test", provider_ref=None, detail={}, now=2.0)

    def listed(self, *argv: str) -> list[str]:
        code, out, err = self.run_cli("tasks", "--json", *argv)
        self.assertEqual(code, cli.EXIT_OK, err)
        return [item["id"] for item in json.loads(out)["tasks"]]


class SinceAndMatchTests(unittest.TestCase):
    def test_relative_and_date_forms(self) -> None:
        now = 1_000_000.0
        self.assertEqual(parse_since("30m", now), now - 1800)
        self.assertEqual(parse_since("2h", now), now - 7200)
        self.assertEqual(parse_since("7d", now), now - 7 * 86400)
        # 日期取本机时区当天 0 点（与 datetime 本地解释同口径）
        self.assertEqual(parse_since("2026-11-13", now), datetime.datetime(2026, 11, 13).timestamp())

    @unittest.skipUnless(hasattr(time, "tzset"), TZSET_REASON)
    def test_date_form_is_local_midnight_even_when_the_runner_is_utc(self) -> None:
        # 显式设成 UTC+8（POSIX 写法，不依赖 tzdata）：CI 跑在 UTC 时也能抓住「按 UTC 解释日期」的错误
        try:
            with patch.dict(os.environ, {"TZ": "UTC-08"}):
                time.tzset()
                # 2026-11-13 00:00 +08:00 = 2026-11-12T16:00:00Z
                self.assertEqual(parse_since("2026-11-13", 0.0), 1794499200.0)
        finally:
            time.tzset()

    def test_invalid_forms_are_rejected(self) -> None:
        for raw in ("", "0m", "05m", "1w", "1.5h", "-1h", "2h ", "H", "2026-13-01", "2026-02-30", "2026-1-01",
                    "20261113", "9" * 400 + "d"):
            with self.subTest(raw=raw), self.assertRaises(FilterError) as caught:
                parse_since(raw, 0.0)
            self.assertEqual(caught.exception.code, "since_invalid")

    def test_session_match_exact_prefix_provider_and_unresolved(self) -> None:
        exact = SessionMatch("codex", IMPL_ID)
        self.assertTrue(exact.matches(("codex", IMPL_ID.upper())))
        self.assertFalse(exact.matches(("claude", IMPL_ID)))
        self.assertFalse(SessionMatch("codex", IMPL_ID[:8]).matches(("codex", IMPL_ID)))
        prefix = SessionMatch(None, IMPL_ID[:8], exact=False)
        self.assertTrue(prefix.matches(("claude", IMPL_ID)))
        self.assertFalse(prefix.matches(("codex", "-")))
        self.assertFalse(prefix.matches(None))

    def test_filters_are_conjunctive_and_grep_is_literal_casefold(self) -> None:
        both = TaskFilter(to=SessionMatch(None, IMPL_ID), grep="a.c")
        common = {"origin": None, "reviewer": None, "updated_at": 5.0, "body": None}
        self.assertTrue(both.accepts(targets=[("codex", IMPL_ID)], title="xA.Cx", **common))
        self.assertFalse(both.accepts(targets=[("codex", IMPL_ID)], title="abc", **common))  # 不是正则
        self.assertFalse(both.accepts(targets=[("codex", OTHER_ID)], title="a.c", **common))
        self.assertTrue(TaskFilter(grep="straße".casefold()).accepts(targets=[], title="STRASSE", **common))
        self.assertFalse(TaskFilter(since=6.0).accepts(targets=[], title="", **common))
        self.assertTrue(TaskFilter(since=5.0).accepts(targets=[], title="", **common))
        self.assertFalse(TaskFilter().active)


class TaskFilterCliTests(LocalCliCase):
    def test_mine_covers_origin_reviewer_and_work_targets_but_not_notices(self) -> None:
        lead_task = self.send()
        review_task = self.send("--review-by", "claude@review", to="codex@other")
        notice_only = self.send(to="codex@other")
        with self.store() as store:
            # 只当通知的接收方不算参与（§93.1：不看 notice）
            store.add_attempt(notice_only, role=Role.NOTICE, target=IMPL.ref, body="通知", refs=[], now=3.0,
                              sender=LEAD.ref, sender_class="bypass")
        self.caller = as_agent(IMPL)
        self.assertEqual(self.listed("--mine"), [lead_task])
        self.caller = as_agent(REVIEW)
        self.assertEqual(self.listed("--mine"), [review_task])
        self.caller = as_agent(LEAD)
        self.assertEqual(self.listed("--mine"), [lead_task, review_task, notice_only])

    def test_mine_without_session_is_rejected(self) -> None:
        self.send()
        unattributed = Caller(None, ProcessInfo(5000, 1, "codex", "9"))
        unresolved = as_agent(endpoint(ref(Provider.CODEX, "-", pid=6000, pane="%6", label="x")))
        for caller in (USER, unattributed, unresolved):
            self.caller = caller
            for extra in ((), ("--json",)):
                code, out, err = self.run_cli("tasks", "--mine", *extra)
                self.assertEqual((code, out), (cli.EXIT_REJECTED, ""), err)
                self.assertIn("[mine_requires_session]", err)

    def test_to_matches_any_work_target_including_reassigned(self) -> None:
        first = self.send()
        moved = self.send()
        other = self.send(to="codex@other")
        self.mark_sent(moved, Delivery.FAILED)
        self.caller = as_agent(LEAD)
        self.assertEqual(self.run_cli("retry", moved, "--to", "codex@other")[0], cli.EXIT_OK)
        self.assertEqual(self.listed("--to", "codex@impl"), [first, moved])  # 改派前的目标也算
        self.assertEqual(self.listed("--to", "codex@other"), [moved, other])
        self.assertEqual(self.listed("--to", f"codex@id:{IMPL_ID[:13]}"), [first, moved])
        self.assertEqual(self.listed("--to", f"codex@id:{IMPL_ID[:8]}"), [first, moved, other])  # 前缀照字面匹配
        self.assertEqual(self.listed("--to", IMPL_ID), [first, moved])
        self.assertEqual(self.listed("--to", f"claude@id:{IMPL_ID}"), [])  # provider 不同不算

    def test_from_matches_origin_and_user_tasks_never_match(self) -> None:
        mine = self.send(caller=as_agent(LEAD))
        theirs = self.send(caller=as_agent(OTHER))
        users = self.send(caller=USER)
        self.assertEqual(self.listed("--from", "codex@lead"), [mine])
        self.assertEqual(self.listed("--from", f"codex@id:{OTHER_ID}"), [theirs])
        self.assertEqual(self.listed("--from", f"codex@id:{OTHER_ID[:8]}"), [mine, theirs])  # 用户发起的不命中
        self.assertNotIn(users, self.listed("--from", f"codex@id:{OTHER_ID[:13]}"))
        self.assertEqual(len(self.listed()), 3)

    def test_name_selector_failures_report_like_send_even_on_empty_ledger(self) -> None:
        twin = endpoint(ref(Provider.CODEX, "019a0000-eeee-7eee-8eee-eeeeeeeeeeee", pid=7000, pane="%7",
                            label="impl", server=100))
        cases = [
            (("--to", "codex@nobody"), cli.EXIT_TARGET, "target_not_found"),
            (("--from", "codex@nobody"), cli.EXIT_TARGET, "target_not_found"),
            (("--to", "codex@id:xyz"), cli.EXIT_TARGET, "target_id_invalid"),
            (("--from", ""), cli.EXIT_TARGET, "target_explicit_required"),
        ]
        for argv, exit_code, code in cases:
            with self.subTest(argv=argv):
                result, out, err = self.run_cli("tasks", *argv)
                self.assertEqual((result, out), (exit_code, ""), err)
                self.assertIn(f"[{code}]", err)
        self.endpoints.append(twin)
        result, out, err = self.run_cli("tasks", "--to", "codex@impl")
        self.assertEqual((result, out), (cli.EXIT_TARGET, ""))
        # 与 send 同一套解析：同名不算已核实，原因码、退出码与候选提示都与 send 一致
        self.assertIn("[target_names_unverified]", err)
        self.assertIn("可选目标", err)
        self.caller = as_agent(LEAD)
        sent = self.run_cli("send", "--to", "codex@impl", "-m", "x", "--no-wait")
        self.assertEqual((sent[0], sent[2]), (result, err))

    def test_since_compares_updated_at(self) -> None:
        old = self.send()
        fresh = self.send()
        now = time.time()
        with self.store() as store:
            store.update_task(old, now=now - 3 * 3600, event="test")
        self.assertEqual(self.listed("--since", "2h"), [fresh])
        self.assertEqual(self.listed("--since", "4h"), [old, fresh])
        today = datetime.date.fromtimestamp(now).isoformat()
        self.assertIn(fresh, self.listed("--since", today))
        code, out, err = self.run_cli("tasks", "--since", "yesterday")
        self.assertEqual((code, out), (cli.EXIT_REJECTED, ""))
        self.assertIn("[since_invalid]", err)

    def test_grep_matches_title_or_first_body_only(self) -> None:
        titled = self.send("--title", "Fix STRASSE parser")
        bodied = self.send(message="标题行\n正文里有 needle 一词")
        later = self.send(message="别的事")
        self.mark_sent(later, Delivery.FAILED)
        self.caller = as_agent(LEAD)
        self.assertEqual(self.run_cli("retry", later, "-m", "needle 只在补充里")[0], cli.EXIT_OK)
        self.assertEqual(self.listed("--grep", "straße"), [titled])
        self.assertEqual(self.listed("--grep", "NEEDLE"), [bodied])  # seq>1 的正文不算
        self.assertEqual(self.listed("--grep", "s.r"), [])
        code, out, err = self.run_cli("tasks", "--grep", "")
        self.assertEqual((code, out), (cli.EXIT_REJECTED, ""))
        self.assertIn("[grep_empty]", err)

    def test_filters_do_not_change_all_semantics_and_combine(self) -> None:
        done = self.send(message="needle 已验收")
        open_ = self.send(message="needle 进行中")
        other = self.send(to="codex@other", message="needle 别人")
        with self.store() as store:
            store.update_task(done, now=time.time(), event="accepted", accepted_at=time.time())
        self.assertEqual(self.listed("--grep", "needle"), [open_, other])
        self.assertEqual(self.listed("--grep", "needle", "--all"), [done, open_, other])
        self.assertEqual(self.listed("--grep", "needle", "--to", "codex@impl"), [open_])
        code, out, err = self.run_cli("tasks", "--grep", "没有这个词")
        self.assertEqual((code, out), (cli.EXIT_OK, "没有符合条件的协作任务\n"), err)
        code, out, _ = self.run_cli("tasks", "--grep", "没有这个词", "--json")
        self.assertEqual(json.loads(out), {"tasks": []})

    def test_all_keeps_the_newest_200_in_creation_order(self) -> None:
        with self.store() as store:
            created: list[str] = []
            for index in range(205):
                task, _attempt = store.create_task(
                    title=f"任务 {index}", flow=cli.Flow.HANDOFF, origin=LEAD.ref, origin_class="bypass",
                    reviewer=None, target=IMPL.ref, body=f"正文 {index}" + (" needle" if index % 2 else ""),
                    refs=[], now=1000.0 + index)
                store.update_task(task.id, now=1000.0 + index, event="accepted", accepted_at=1000.0 + index)
                created.append(task.id)
        self.assertEqual(self.listed("--all"), created[5:])
        # 有筛选时也是先筛再留最新的 200 条
        self.assertEqual(self.listed("--all", "--grep", "needle"), [item for i, item in enumerate(created) if i % 2])
        # 筛选命中超过 200 条时同样截到最新的 200 条（筛选路径自己的截断）
        self.assertEqual(self.listed("--all", "--grep", "正文"), created[5:])
        self.assertEqual(self.listed("--all", "--from", f"codex@id:{LEAD_ID}"), created[5:])
        self.assertEqual(self.listed(), [])

    def test_unfiltered_listing_is_unchanged_and_does_no_extra_discovery(self) -> None:
        tasks = [self.send(), self.send(to="codex@other")]
        with self.store() as store:
            expected = [item.id for item in store.list_tasks()]  # 旧取法：默认 200 条升序
        before = self.discover_calls
        code, out, err = self.run_cli("tasks", "--json")
        self.assertEqual(code, 0, err)
        self.assertEqual([item["id"] for item in json.loads(out)["tasks"]], expected)
        self.assertEqual(expected, tasks)
        self.assertEqual(self.discover_calls - before, 1)  # 只有原来那次观察
        with self.store() as store:
            for task_id in tasks:
                store.update_task(task_id, now=time.time(), event="accepted", accepted_at=time.time())
        before = self.discover_calls
        self.assertEqual(self.run_cli("tasks"), (0, "没有进行中的协作任务\n", ""))
        self.assertEqual(self.discover_calls, before)
        self.assertEqual(self.run_cli("tasks", "--since", "1h")[0], 0)
        self.assertEqual(self.discover_calls, before)  # ID 形与时间筛选不做发现


class DecisionJsonTests(LocalCliCase):
    def assert_single_json(self, argv: tuple[str, ...], expected_exit: int) -> dict[str, object]:
        code, out, err = self.run_cli(*argv, "--json")
        self.assertEqual(code, expected_exit, err)
        document = json.loads(out)  # 整个 stdout 恰好一份 JSON 文档
        self.assertIsInstance(document, dict)
        return document

    def test_pause_resume_cancel_success_documents(self) -> None:
        task_id = self.send()
        self.caller = USER
        self.assertEqual(self.assert_single_json(("pause", task_id[:8]), 0),
                         {"ok": True, "command": "pause", "scope": "local", "id": task_id, "control": "paused",
                          "notes": []})
        self.assertEqual(self.assert_single_json(("resume", task_id), 0),
                         {"ok": True, "command": "resume", "scope": "local", "id": task_id, "control": "active",
                          "notes": []})
        self.assertEqual(self.assert_single_json(("cancel", task_id), 0),
                         {"ok": True, "command": "cancel", "scope": "local", "id": task_id, "control": "active",
                          "cancelled": 1, "notes": []})

    def test_errors_print_one_json_document_and_keep_exit_codes_and_stderr(self) -> None:
        task_id = self.send()
        self.caller = USER
        cases = [
            (("resume", task_id), cli.EXIT_REJECTED, "not_paused"),
            (("retry", task_id), cli.EXIT_REJECTED, "still_pending"),
            (("close", "ffffffff"), cli.EXIT_TARGET, "task_not_found"),
            (("pause", "ffffffff"), cli.EXIT_TARGET, "task_not_found"),
        ]
        for argv, exit_code, code in cases:
            with self.subTest(argv=argv):
                plain = self.run_cli(*argv)
                document = self.assert_single_json(argv, exit_code)
                self.assertEqual(plain[0], exit_code)
                self.assertEqual(document, {"ok": False, "code": code, "reasonText": cli.reason_text(code)})
                self.assertEqual(self.run_cli(*argv, "--json")[2], plain[2])  # stderr 文字不变
        self.assertEqual(self.run_cli("cancel", task_id)[0], 0)
        document = self.assert_single_json(("cancel", task_id), cli.EXIT_REJECTED)
        self.assertEqual(document["code"], "nothing_to_cancel")

    def test_close_document_carries_phase_closure_and_native_risk(self) -> None:
        task_id = self.send()
        self.mark_sent(task_id)
        self.caller = as_agent(LEAD)
        document = self.assert_single_json(("close", task_id, "--reason", "不需要了"), 0)
        self.assertEqual(set(document), {"ok", "command", "scope", "id", "phase", "closure", "notes"})
        self.assertEqual((document["command"], document["scope"], document["id"], document["phase"]),
                         ("close", "local", task_id, "closed"))
        self.assertEqual(document["notes"], ["native_risk"])
        closure = document["closure"]
        assert isinstance(closure, dict)
        self.assertEqual(len(closure["queued"]), 1)
        quiet = self.send()
        self.mark_sent(quiet, Delivery.FAILED)
        self.caller = as_agent(LEAD)
        document = self.assert_single_json(("close", quiet), 0)
        self.assertEqual(document["notes"], [])

    def test_retry_document_is_the_task_document_with_command_and_notes(self) -> None:
        task_id = self.send()
        self.mark_sent(task_id)
        self.caller = as_agent(LEAD)
        document = self.assert_single_json(("retry", task_id, "--force"), 0)
        self.assertEqual((document["ok"], document["id"], document["scope"], document["command"]),
                         (True, task_id, "local", "retry"))
        self.assertEqual(document["retried"], {"seq": 2, "role": "handoff"})
        self.assertEqual(document["notes"], ["retry_may_duplicate"])
        attempts = document["attempts"]
        assert isinstance(attempts, list)
        self.assertEqual(len(attempts), 2)
        # 接近上限：与文字模式的「提示」同一阈值
        with self.store() as store:
            while max(item.seq for item in store.attempts(task_id)) < 47:
                store.add_attempt(task_id, role=Role.NOTICE, target=LEAD.ref, body="容量夹具", refs=[], now=3.0,
                                  sender=IMPL.ref, sender_class="bypass")
        self.mark_sent(task_id, Delivery.FAILED)
        with self.store() as store:
            store.transition_delivery(store.attempts(task_id)[1].id, expected=(Delivery.PENDING,),
                                      new=Delivery.FAILED, reason="test", now=4.0)
        document = self.assert_single_json(("retry", task_id), 0)
        self.assertEqual(document["notes"], ["attempts_near_limit"])

    def test_exit_6_keeps_the_code_and_moves_the_note_into_json(self) -> None:
        task_id = self.send()
        self.mark_sent(task_id, Delivery.FAILED)
        self.worker_up = False
        cli.ensure_worker.side_effect = OSError("spawn")  # type: ignore[attr-defined]
        self.caller = as_agent(LEAD)
        plain_retry = self.run_cli("retry", task_id)
        self.assertEqual(plain_retry[0], cli.EXIT_UNAVAILABLE)
        self.mark_sent(task_id, Delivery.FAILED)
        document = self.assert_single_json(("retry", task_id), cli.EXIT_UNAVAILABLE)
        self.assertEqual(document["notes"], ["worker_not_running"])
        self.assertEqual(self.run_cli("pause", task_id)[0], 0)
        plain = self.run_cli("resume", task_id)
        self.assertEqual(plain[0], cli.EXIT_UNAVAILABLE)
        self.assertEqual(self.run_cli("pause", task_id)[0], 0)
        code, out, err = self.run_cli("resume", task_id, "--json")
        self.assertEqual(code, cli.EXIT_UNAVAILABLE)
        self.assertEqual(json.loads(out)["notes"], ["worker_not_running"])
        self.assertIn("请勿重复执行", err)  # stderr 说明照旧

    def test_accept_json_bytes_are_unchanged(self) -> None:
        task_id = self.send()
        self.mark_sent(task_id)
        with self.store() as store:
            first = store.attempts(task_id)[0]
            store.set_work(first.id, work=cli.Work.RESULT, result={"note": "好了"}, now=5.0, event="result")
        self.caller = as_agent(LEAD)
        code, out, err = self.run_cli("accept", task_id, "--json")
        self.assertEqual(code, 0, err)
        expected = {"ok": True, "id": task_id, "phase": "done",
                    "closure": {"queued": [{"seq": 2, "target": f"codex@id:{IMPL_ID}"}], "skipped": []}}
        self.assertEqual(out, dumped(expected))
        code, out, err = self.run_cli("accept", task_id, "--json")
        self.assertEqual((code, out), (cli.EXIT_REJECTED, dumped(
            {"ok": False, "code": "task_finished", "reasonText": "任务已结束"})))



class FederatedFilterTests(FedCliCase):
    def federation_ids(self, device: str, *argv: str) -> tuple[list[str], list[str]]:
        code, out, err = self.run_on(device, "tasks", "--json", *argv)
        self.assertEqual(code, cli.EXIT_OK, err)
        document = json.loads(out)
        return [item["id"] for item in document["tasks"]], [item["id"] for item in document.get("federation", [])]

    def test_authority_side_filters_cover_federated_tasks(self) -> None:
        remote = self.send()
        with patch.object(cli, "worker_running", return_value=True):  # 本机任务的 worker 视为在跑，退出 0
            code, out, err = self.run_on("vm", "send", "--to", "codex@review", "-m", "本机复核 needle", "--no-wait", "--json",
                                         caller=fed_agent(ORIGIN))
        self.assertEqual(code, 0, err)
        local = json.loads(out)["id"]
        self.assertEqual(self.federation_ids("vm", "--to", f"codex@id:{THREAD_B}"), ([], [remote]))
        self.assertEqual(self.federation_ids("vm", "--to", "codex@review"), ([local], []))
        self.assertEqual(self.federation_ids("vm", "--from", "claude@lead"), ([local], [remote]))
        self.assertEqual(self.federation_ids("vm", "--from", f"claude@id:{CLAUDE_A}"), ([local], [remote]))
        self.caller = fed_agent(ORIGIN)
        self.assertEqual(self.federation_ids("vm", "--mine"), ([local], [remote]))
        self.assertEqual(self.federation_ids("vm", "--grep", "细节"), ([], [remote]))  # seq 1 的正文
        self.assertEqual(self.federation_ids("vm", "--grep", "NEEDLE"), ([local], []))
        self.assertEqual(self.federation_ids("vm", "--since", "1h"), ([local], [remote]))
        with self.store("vm") as store:
            [task] = store.find_tasks(remote)
            store.update_task(replace(task, state={**task.state, "updatedAt": now_ms() - 3 * 3600 * 1000}))
        self.assertEqual(self.federation_ids("vm", "--since", "1h"), ([local], []))
        code, out, err = self.run_on("vm", "tasks", "--grep", "没有这个词")
        self.assertEqual((code, out), (0, "没有符合条件的协作任务\n"), err)
        code, out, err = self.run_on("vm", "tasks", "--to", f"codex@id:{THREAD_B}")
        self.assertEqual(code, 0, err)
        self.assertNotIn("没有符合条件", out)
        self.assertIn("跨设备·本机发起", out)

    def test_mirror_side_uses_origin_actor_and_attempt_targets(self) -> None:
        task_id = self.send()
        self.pump("vm", "win")
        self.caller = fed_agent(WORKER)
        self.assertEqual(self.federation_ids("win", "--from", f"claude@id:{CLAUDE_A}"), ([], [task_id]))
        self.assertEqual(self.federation_ids("win", "--mine"), ([], [task_id]))
        self.assertEqual(self.federation_ids("win", "--to", "codex@impl"), ([], [task_id]))  # 名字形按本机发现解析
        self.assertEqual(self.federation_ids("win", "--to", f"codex@id:{CLAUDE_A}"), ([], []))
        with self.store("win") as store:
            [mirrored] = store.find_tasks(task_id)
            self.assertNotIn("origin", mirrored.state)  # 镜像只有 originActor 与 checkpoint

    def test_mirror_reviewer_comes_from_the_checkpoint_in_a_real_flow(self) -> None:
        # 目标与复核方同在 win 的两个会话：复核请求到达前，镜像上的复核方只在 checkpoint.reviewer 里
        self.endpoints["win"] = [WORKER, HELPER]
        with self.store("win") as store:
            snapshot = directory.snapshot(store, DEV_B, with_name_views([WORKER, HELPER]),
                                          provider_complete={"codex": True})
        with self.store("vm") as store:
            store.put_device_state(device_id=DEV_B, name="win", revision=2, snapshot=snapshot, last_seen=now_ms(),
                                   state="online")
        code, out, err = self.run_on("vm", "send", "--device", "win", "--to", f"codex@id:{THREAD_B}",
                                     "--review-device", "win", "--review-by", f"codex@id:{HELPER_ID}",
                                     "-m", "远端执行远端复核", "--json", caller=fed_agent(ORIGIN))
        self.assertEqual(code, 0, err)
        task_id = json.loads(out)["id"]
        self.pump("vm", "win")
        with self.store("win") as store:
            [mirrored] = store.find_tasks(task_id)
            self.assertEqual([item.seq for item in store.attempts(mirrored.authority_device, task_id)], [1])
            self.assertIsNone(mirrored.state.get("reviewer"))
        self.caller = fed_agent(HELPER)
        self.assertEqual(self.federation_ids("win", "--mine"), ([], [task_id]))
        self.caller = fed_agent(WORKER)
        self.assertEqual(self.federation_ids("win", "--mine"), ([], [task_id]))
        self.caller = fed_agent(OTHER_WIN)
        self.endpoints["win"] = [WORKER, HELPER, OTHER_WIN]
        self.assertEqual(self.federation_ids("win", "--mine"), ([], []))

    def test_mirror_to_covers_attempts_sent_to_other_devices(self) -> None:
        # B 执行、A 本机复核：镜像库里只有发给 B 的尝试，复核尝试只在 checkpoint 里（审计 r1 P2-1）
        task_id = self.local_review_requested()
        self.pump("vm", "win")
        review_id = LOCAL_REVIEW.ref.native_id
        for device in ("vm", "win"):
            with self.subTest(device=device):
                self.assertEqual(self.federation_ids(device, "--to", f"codex@id:{review_id}"), ([], [task_id]))
                self.assertEqual(self.federation_ids(device, "--to", f"claude@id:{review_id}"), ([], []))

    def test_notice_targets_never_count_as_work_targets(self) -> None:
        task_id = self.delivered_task()
        self.assertEqual(self.run_on("win", "report", task_id, "--result", caller=fed_agent(WORKER))[0], 0)
        self.pump("win", "vm")
        with self.store("vm") as store:
            roles = [(item.role, item.target.remote.native_id) for item in store.attempts(DEV_A, task_id)]
        self.assertIn(("notice", CLAUDE_A), roles)  # 发起方只收到结果通知
        self.pump("vm", "win")
        for device in ("vm", "win"):
            with self.subTest(device=device):
                self.assertEqual(self.federation_ids(device, "--to", f"claude@id:{CLAUDE_A}"), ([], []))
                self.assertEqual(self.federation_ids(device, "--from", f"claude@id:{CLAUDE_A}"), ([], [task_id]))

    def clone_tasks(self, count: int, *, title: str, base: int) -> list[str]:
        """在 vm 联邦库里按一条真实任务克隆 count 条（新 ID、更晚的最近同步时间），返回按同步时间升序的 ID。"""
        source = self.send()
        created: list[str] = []
        with self.store("vm") as store:
            [task] = store.find_tasks(source)
            for index in range(count):
                clone = replace(task, task_id=new_id(), state={**task.state, "title": f"{title} {index}"},
                                last_sync_at=base + index)
                store.insert_task(clone)
                created.append(clone.task_id)
        return created

    def test_filtering_reads_all_candidates_then_keeps_the_newest_200(self) -> None:
        oldest = self.send("--title", "最旧的唯一一条")
        with self.store("vm") as store:
            [task] = store.find_tasks(oldest)
            store.update_task(replace(task, last_sync_at=1))
        later = self.clone_tasks(205, title="批量", base=now_ms())
        # 先取全部再筛：最旧的一条排在第 207 位也能筛出来
        self.assertEqual(self.federation_ids("vm", "--grep", "最旧的唯一")[1], [oldest])
        # 筛完再截 200 条，留最近同步的那些
        self.assertEqual(self.federation_ids("vm", "--grep", "批量")[1], list(reversed(later))[:200])
        self.assertEqual(len(self.federation_ids("vm")[1]), 200)  # 无筛选照旧取最近 200 条

    def test_since_falls_back_to_last_sync_when_updated_at_is_missing(self) -> None:
        task_id = self.send()
        with self.store("vm") as store:
            [task] = store.find_tasks(task_id)
            state = {key: value for key, value in task.state.items() if key != "updatedAt"}
            store.update_task(replace(task, state=state, last_sync_at=now_ms()))
        self.assertEqual(self.federation_ids("vm", "--since", "1h")[1], [task_id])
        with self.store("vm") as store:
            [task] = store.find_tasks(task_id)
            store.update_task(replace(task, last_sync_at=now_ms() - 3 * 3600 * 1000))
        self.assertEqual(self.federation_ids("vm", "--since", "1h")[1], [])

    def test_grep_reads_only_the_first_body(self) -> None:
        task_id = self.send()
        code, _, err = self.run_on("vm", "retry", task_id, "--force", "-m", "补充里的独有词", caller=fed_agent(ORIGIN))
        self.assertEqual(code, 0, err)
        with self.store("vm") as store:
            self.assertIn("补充里的独有词", store.attempts(DEV_A, task_id)[-1].body)
        self.assertEqual(self.federation_ids("vm", "--grep", "补充里的独有词")[1], [])
        self.assertEqual(self.federation_ids("vm", "--grep", "细节")[1], [task_id])


class FederatedDecisionJsonTests(FedCliCase):
    def decide(self, *argv: str, exit_code: int = 0) -> dict[str, object]:
        code, out, err = self.run_on("vm", *argv, "--json", caller=fed_agent(ORIGIN))
        self.assertEqual(code, exit_code, err)
        document = json.loads(out)
        self.assertIsInstance(document, dict)
        return document

    def test_control_documents_and_exit_6(self) -> None:
        task_id = self.send()
        self.assertEqual(self.decide("pause", task_id),
                         {"ok": True, "command": "pause", "scope": "federation", "id": task_id,
                          "control": "paused", "notes": []})
        self.assertEqual(self.decide("resume", task_id)["control"], "active")
        self.pump("vm", "win")
        self.assertEqual(self.decide("cancel", task_id),
                         {"ok": True, "command": "cancel", "scope": "federation", "id": task_id, "control": "active",
                          "cancelled": None, "cancelRequested": True, "notes": ["remote_unconfirmed"]})
        self.relay_up = False
        plain = self.run_on("vm", "pause", task_id, caller=fed_agent(ORIGIN))
        self.assertEqual(plain[0], cli.EXIT_UNAVAILABLE)
        self.assertEqual(self.run_on("vm", "resume", task_id, caller=fed_agent(ORIGIN))[0], cli.EXIT_UNAVAILABLE)
        document = self.decide("pause", task_id, exit_code=cli.EXIT_UNAVAILABLE)
        self.assertEqual(document["notes"], ["relay_not_running"])
        code, out, err = self.run_on("vm", "resume", task_id, "--json", caller=FED_USER)
        self.assertEqual(code, cli.EXIT_UNAVAILABLE)
        self.assertEqual(json.loads(out)["notes"], ["relay_not_running"])
        self.assertIn("请勿重复执行", err)

    def test_retry_and_close_documents(self) -> None:
        task_id = self.send()
        document = self.decide("retry", task_id, "--force")
        self.assertEqual((document["ok"], document["scope"], document["id"], document["command"]),
                         (True, "federation", task_id, "retry"))
        self.assertEqual(document["retried"], {"seq": 2, "role": "handoff"})
        self.assertEqual(document["notes"], ["retry_may_duplicate"])
        document = self.decide("close", task_id, "--reason", "收尾")
        self.assertEqual(set(document), {"ok", "id", "scope", "phase", "closure", "command", "notes"})
        self.assertEqual((document["command"], document["phase"]), ("close", "closed"))
        self.assertEqual(document["notes"], ["remote_unconfirmed"])
        errors = self.decide("close", task_id, exit_code=cli.EXIT_REJECTED)
        self.assertEqual(errors, {"ok": False, "code": "task_finished", "reasonText": "任务已结束"})

    def test_close_and_retry_keep_exit_6_when_relay_is_down(self) -> None:
        task_id = self.send()
        self.relay_up = False
        plain = self.run_on("vm", "retry", task_id, "--force", caller=fed_agent(ORIGIN))
        self.assertEqual(plain[0], cli.EXIT_UNAVAILABLE)
        document = self.decide("retry", task_id, "--force", exit_code=cli.EXIT_UNAVAILABLE)
        self.assertEqual(document["notes"], ["retry_may_duplicate", "relay_not_running"])
        document = self.decide("close", task_id, exit_code=cli.EXIT_UNAVAILABLE)
        self.assertEqual(document["notes"], ["remote_unconfirmed", "relay_not_running"])
        self.relay_up = True
        other = self.send()
        self.relay_up = False
        self.assertEqual(self.run_on("vm", "close", other, caller=fed_agent(ORIGIN))[0], cli.EXIT_UNAVAILABLE)  # 文字模式同码

    def test_federated_accept_json_bytes_are_unchanged(self) -> None:
        task_id = self.delivered_task()
        self.assertEqual(self.run_on("win", "report", task_id, "--result", caller=fed_agent(WORKER))[0], 0)
        self.pump("win", "vm")
        code, out, err = self.run_on("vm", "accept", task_id, "--json", caller=fed_agent(ORIGIN))
        self.assertEqual(code, 0, err)
        with self.store("vm") as store:
            [closure] = [item for item in store.attempts(DEV_A, task_id) if item.is_closure]
        expected = {"ok": True, "id": task_id, "scope": "federation", "phase": "done",
                    "closure": {"queued": [{"seq": closure.seq, "targetDevice": DEV_B}], "skipped": [],
                                "remoteUnconfirmed": True}}
        self.assertEqual(out, dumped(expected))



class LocalHitDecisionTests(FedCliCase):
    def test_local_task_decisions_never_open_the_federation_store(self) -> None:
        # §88.7/§94.2：本机任务命中时，决定类命令（含 --json）本身不经联邦库；命令后补拉 worker 的联邦判断与
        # 命令结束时的摘要刷新（§45.14 的可重建投影，会开联邦库）都不算命令本身，守卫期间置空
        with patch.object(cli, "worker_running", return_value=True):
            code, out, err = self.run_on("vm", "send", "--to", "codex@review", "-m", "本机任务", "--no-wait", "--json",
                                         caller=fed_agent(ORIGIN))
        self.assertEqual(code, 0, err)
        task_id = json.loads(out)["id"]
        # 对照：摘要刷新照常时，开联邦库的是它（所以守卫要把它置空，而不是按次数相减）
        with patch.object(cli, "_federation_needs_worker", return_value=False), \
                patch.object(FederatedStore, "open", wraps=FederatedStore.open) as fed_open, \
                patch.object(summary, "open_federation", wraps=summary.open_federation) as projected:
            self.assertEqual(self.run_on("vm", "pause", task_id, caller=FED_USER)[0], 0)
            self.assertEqual(self.run_on("vm", "resume", task_id, caller=FED_USER)[0], 0)
        self.assertTrue(projected.call_count)
        self.assertEqual(fed_open.call_count, projected.call_count)
        steps = [("pause", task_id), ("resume", task_id), ("cancel", task_id), ("retry", task_id),
                 ("accept", task_id, "--force"), ("close", task_id)]
        with patch.object(cli, "_federation_needs_worker", return_value=False), \
                patch.object(cli, "_refresh_summary", return_value=None), \
                patch.object(fed_commands, "try_runtime", wraps=fed_commands.try_runtime) as probe, \
                patch.object(fed_commands, "open_runtime", wraps=fed_commands.open_runtime) as opened, \
                patch.object(fed_commands, "find_task", wraps=fed_commands.find_task) as resolved, \
                patch.object(FederatedStore, "open", wraps=FederatedStore.open) as fed_open, \
                patch.object(FederatedStore, "open_readonly", wraps=FederatedStore.open_readonly) as fed_readonly:
            for step in steps:
                for extra in ((), ("--json",)) if step[0] == "pause" else ((),):
                    with self.subTest(step=step, extra=extra):
                        code, _, err = self.run_on("vm", *step, *extra, caller=FED_USER)
                        self.assertEqual(code, 0, err)
                if step[0] == "pause":
                    self.assertEqual(self.run_on("vm", "resume", task_id, caller=FED_USER)[0], 0)
                    self.assertEqual(self.run_on("vm", "pause", task_id, caller=FED_USER)[0], 0)
        # 命令本身开联邦库的全部入口严格 0 次（r1 两方 P3-1：不能用「等于摘要刷新次数」，命令内经摘要入口开库会被抵消）
        self.assertEqual((probe.call_count, opened.call_count, resolved.call_count, fed_open.call_count,
                          fed_readonly.call_count), (0, 0, 0, 0, 0))


class WindowsTaskFilterTests(unittest.TestCase):
    """Windows 走同一套 CLI：新参数的格式校验与退出码不随平台分叉（假 Win32 内核，不碰真实系统）。"""

    def setUp(self) -> None:
        temporary = TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.kernel = Kernel(self.root)
        self.platform = make_platform("windows", win_api=self.kernel.api)
        version = patch("agentstatus_bridge.platforms.windows.codex_version.read_cli_version", return_value=None)
        version.start()
        self.addCleanup(version.stop)
        self.addCleanup(lambda: self.assertEqual(self.kernel.handles, {}))

    def test_filter_validation_matches_linux(self) -> None:
        cases = [(("--since", "bad"), cli.EXIT_REJECTED, "since_invalid"),
                 (("--grep", ""), cli.EXIT_REJECTED, "grep_empty"),
                 (("--to", "codex@id:xyz"), cli.EXIT_TARGET, "target_id_invalid")]
        with using_platform(self.platform), patch.dict(os.environ, {"AB_STATE_DIR": str(self.root / "state"),
                                                                   "CODEX_HOME": str(self.root / "absent-home")}), \
                patch.object(cli, "discover", side_effect=AssertionError("ID 形与格式错误不做发现")):
            for argv, exit_code, code in cases:
                with self.subTest(argv=argv):
                    out, err = StringIO(), StringIO()
                    with redirect_stdout(out), redirect_stderr(err):
                        self.assertEqual(cli.main(["tasks", *argv]), exit_code)
                    self.assertEqual(out.getvalue(), "")
                    self.assertIn(f"[{code}]", err.getvalue())
            out = StringIO()
            with redirect_stdout(out):
                self.assertEqual(cli.main(["tasks", "--since", "1h", "--to", f"codex@id:{IMPL_ID}", "--json"]), 0)
            self.assertEqual(json.loads(out.getvalue()), {"tasks": []})

    def test_only_delivering_commands_say_the_target_was_not_sent(self) -> None:
        # 「目标未发送」是投递命令的提示：tasks 的名字形筛选解析失败时不打（两方审计 r1 P3-5）
        with using_platform(self.platform), patch.dict(os.environ, {"AB_STATE_DIR": str(self.root / "state"),
                                                                   "CODEX_HOME": str(self.root / "absent-home")}):
            err = StringIO()
            with redirect_stdout(StringIO()), redirect_stderr(err):
                self.assertEqual(cli.main(["tasks", "--to", "codex@nobody"]), cli.EXIT_TARGET)
            self.assertIn("[target_", err.getvalue())
            self.assertNotIn("目标未发送", err.getvalue())
            # 投递命令照旧提示：越过命令资格（假内核里认不出调用方），只看 _main 的提示分支
            with patch("agentstatus_bridge.platforms.windows.commands.scope", side_effect=lambda _args: nullcontext()), \
                    patch.object(cli, "_run_command", side_effect=NativeFailure("target_not_found")):
                for argv, hinted in ((["send", "--to", "codex@nobody", "-m", "x"], True),
                                     (["retry", "abcd1234", "--to", "codex@nobody"], True),
                                     (["tasks", "--to", "codex@nobody"], False)):
                    err = StringIO()
                    with self.subTest(argv=argv), redirect_stdout(StringIO()), redirect_stderr(err):
                        self.assertEqual(cli.main(argv), cli.EXIT_TARGET)
                    self.assertEqual("目标未发送" in err.getvalue(), hinted, err.getvalue())


def _windows_cli(*argv: str) -> tuple[int, str, str]:
    """在调用方已设好的假 Windows 平台上跑真实 cli.main；worker 一律不真起（不派生进程、不连 daemon）。"""
    out, err = StringIO(), StringIO()
    with patch("os.getpid", return_value=100), patch.object(cli, "_start_worker", return_value=False), \
            patch.object(cli, "_ensure_worker", return_value=False), patch.object(cli, "_worker_up", return_value=False), \
            redirect_stdout(out), redirect_stderr(err):
        code = cli.main(list(argv))
    return code, out.getvalue(), err.getvalue()


def _create(store: Store, title: str, *, target: EndpointRef, origin: EndpointRef | None = None,
            reviewer: EndpointRef | None = None) -> str:
    task, _ = store.create_task(title=title, flow=Flow.REVIEW if reviewer else Flow.HANDOFF, origin=origin,
                                origin_class=None, reviewer=reviewer, target=target, body="fixture", refs=[], now=1000.0)
    return task.id


class WindowsCodexCallerFilterTests(unittest.TestCase):
    """§94.3 第 1 条：Windows 上认得出的 Codex 调用方跑 tasks --mine；名字形 --to 经 Windows 发现解析成功与失败。

    夹具借用 Windows 发现与调用方用例（假 Win32 内核 + 合成 daemon 与 SQL），不派生进程、不连真实 daemon。
    """

    setUp = windows_discovery.DiscoveryTests.setUp
    rebuild = windows_discovery.DiscoveryTests.rebuild
    scope = windows_discovery.DiscoveryTests.scope
    sql = windows_discovery.DiscoveryTests.sql
    chain = windows_callers.CallerTests.chain

    def ledger(self) -> dict[str, str]:
        """三条任务：本会话发起、本会话是执行目标、与本会话无关（别的 Codex 会话发给 Claude）。"""
        me = EndpointRef(Provider.CODEX, uuid(1), 200, "win-filetime:134362090000012230")
        peer = EndpointRef(Provider.CODEX, uuid(2), 200, "win-filetime:134362090000012230")
        claude = EndpointRef(Provider.CLAUDE, REVIEW_ID, 300, "win-filetime:1")
        with self.scope(), Store.open(self.state) as store:
            return {"origin": _create(store, "本会话发起", origin=me, target=peer),
                    "target": _create(store, "交给本会话", target=me),
                    "other": _create(store, "无关", origin=peer, target=claude)}

    def run_cli(self, *argv: str, environ: dict[str, str] | None = None) -> tuple[int, str, str]:
        with self.scope(), patch.dict(os.environ, environ or {}):
            return _windows_cli(*argv)

    def test_recognized_codex_caller_mine_lists_only_its_own_tasks(self) -> None:
        tasks = self.ledger()
        code, out, err = self.run_cli("tasks", "--mine", "--json", environ=self.chain())
        self.assertEqual(code, 0, err)
        self.assertEqual(sorted(item["id"] for item in json.loads(out)["tasks"]), sorted([tasks["origin"], tasks["target"]]))
        # 同一条进程链但没有 Codex 会话变量：认不出会话，--mine 拒绝而不是返回全部或空列表
        code, out, err = self.run_cli("tasks", "--mine")
        self.assertEqual((code, out), (cli.EXIT_REJECTED, ""))
        self.assertIn("[mine_requires_session]", err)

    def test_name_form_to_resolves_through_windows_discovery(self) -> None:
        tasks = self.ledger()
        path = self.sql([(uuid(1), "cli")])
        with closing(sqlite3.connect(path)) as db, db:
            db.execute("UPDATE threads SET name=? WHERE id=?", ("impl", uuid(1)))
        code, out, err = self.run_cli("tasks", "--to", "codex@impl", "--json")
        self.assertEqual(code, 0, err)
        self.assertEqual([item["id"] for item in json.loads(out)["tasks"]], [tasks["target"]])
        # 解析失败照 send 报错与退出码，不能当成「没有符合条件的任务」
        code, out, err = self.run_cli("tasks", "--to", "codex@nobody")
        self.assertEqual((code, out), (cli.EXIT_TARGET, ""))
        self.assertIn("[target_not_found]", err)


class WindowsClaudeCallerFilterTests(unittest.TestCase):
    """§94.3 第 1 条：Windows 上认得出的 Claude 调用方跑 tasks --mine（假 Win32 内核 + 私有注册表，不读 key、不连管道）。"""

    setUp = windows_claude.NativeTests.setUp
    write = windows_claude.NativeTests.write

    def test_recognized_claude_caller_mine_lists_only_its_own_tasks(self) -> None:
        me = EndpointRef(Provider.CLAUDE, windows_claude.UUID, 200, "win-filetime:" + windows_claude.BIRTH)
        codex = EndpointRef(Provider.CODEX, uuid(1), 400, "win-filetime:1")
        other = EndpointRef(Provider.CODEX, uuid(2), 400, "win-filetime:1")
        state = self.root / "state"
        with patch.dict(os.environ, {"AB_STATE_DIR": str(state)}), \
                patch.object(windows_commands, "sample", return_value=windows_commands.Discovery()):
            with Store.open(state) as store:
                tasks = {"origin": _create(store, "本会话发起", origin=me, target=codex),
                         "review": _create(store, "本会话复核", origin=codex, reviewer=me, target=other),
                         "target": _create(store, "交给本会话", origin=codex, target=me),
                         "other": _create(store, "无关", origin=codex, target=other)}
            code, out, err = _windows_cli("tasks", "--mine", "--json")
            self.assertEqual(code, 0, err)
            self.assertEqual(sorted(item["id"] for item in json.loads(out)["tasks"]),
                             sorted([tasks["origin"], tasks["review"], tasks["target"]]))
            code, out, err = _windows_cli("tasks", "--to", "claude@fixture-peer", "--json")  # 注册表原生名
            self.assertEqual(code, 0, err)
            self.assertEqual([item["id"] for item in json.loads(out)["tasks"]], [tasks["target"]])


if __name__ == "__main__":
    unittest.main()
