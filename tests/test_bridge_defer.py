"""延迟投递与定时提醒（DESIGN §104.9 二）：本机 --after/--expect、ab remind、跨设备 A1（outbox next_try_at）。

本模块的 CLI 用例借用 test_bridge_cli 的替身发现与隔离状态目录（POSIX-only）；纯函数与联邦夹具两种系统都跑。
"""

from __future__ import annotations

from dataclasses import replace
import json
import os
import unittest

import bridge_support  # noqa: F401  导入即隔离宿主会话环境
import test_bridge_reminders as R
from agentstatus_bridge.dispatch import DISCOVERY_PARK_SECONDS, needs_worker
from agentstatus_bridge.federation import authority, commands, mirror
from agentstatus_bridge.federation.delivery import FederationDispatcher
from agentstatus_bridge.federation.relay import RelayPaths
from agentstatus_bridge.federation.views import model_attempts, model_task
from agentstatus_bridge.labels import REASON_TEXTS, deferred_due, next_step, shown_reason
from agentstatus_bridge.model import (
    AUTO_RETRY_OPTION,
    DEFER_OPTION,
    MAX_DEFER_SECONDS,
    ORIGIN_WATCH_OPTION,
    REMIND_OPTION,
    Delivery,
    Phase,
    Provider,
    Role,
    describe,
    work_attempts,
)
from agentstatus_bridge.task_filter import parse_duration
from agentstatus_bridge.views import defer_line, deferred_text

from test_bridge_federation_cli import ORIGIN, THREAD_B, FedCliCase, as_agent
from test_bridge_federation_mirror_work import runtime
from test_bridge_federation_rules import CLAUDE_A2, DEV_A, T0, FederationTestCase, pump

LINUX_FIXTURE_REASON = "POSIX-only: 替身 Linux 发现与调用方、Linux 私有状态目录（Windows 缺省平台是真实 Win32）"
linux_fixture = unittest.skipUnless(os.name == "posix", LINUX_FIXTURE_REASON)


class DurationTests(unittest.TestCase):
    def test_minutes_and_hours_within_range(self) -> None:
        self.assertEqual(parse_duration("30m", minimum=60, maximum=MAX_DEFER_SECONDS), 1800.0)
        self.assertEqual(parse_duration(" 2h ", minimum=60, maximum=MAX_DEFER_SECONDS), 7200.0)
        self.assertEqual(parse_duration("24h", minimum=60, maximum=MAX_DEFER_SECONDS), MAX_DEFER_SECONDS)
        for bad in ("0m", "25h", "1441m", "30", "30s", "1h30m", "-5m", "m", "", "05m"):
            with self.subTest(bad=bad):
                self.assertIsNone(parse_duration(bad, minimum=60, maximum=MAX_DEFER_SECONDS))
        self.assertIsNone(parse_duration("4m", minimum=300, maximum=MAX_DEFER_SECONDS))


class LocalDeferTests(unittest.TestCase):
    setUp = R.ReminderTests.setUp
    tearDown = R.ReminderTests.tearDown
    _discover = R.ReminderTests._discover
    _run = R.ReminderTests._run

    def _deferred(self, delay: float = 3600.0) -> str:
        task, _ = self.store.create_task(title="定时", flow=R.Flow.HANDOFF, origin=R.LEAD, origin_class="bypass",
                                         reviewer=None, target=R.IMPL, body="到点再做", refs=[], now=self.now,
                                         attempt_options={DEFER_OPTION: self.now + delay})
        return task.id

    def test_not_sent_or_discovered_before_due_then_sent(self) -> None:
        task_id = self._deferred()
        calls: list[int] = []
        original = self.dispatcher.discover

        def counting():
            calls.append(1)
            return original()
        self.dispatcher.discover = counting
        self.now += 3599
        self._run()
        [work] = work_attempts(self.store.attempts(task_id))
        self.assertEqual(work.delivery, Delivery.PENDING)
        self.assertEqual((calls, self.codex.calls), ([], []))  # 到期前不发现、不外调
        self.assertTrue(needs_worker(self.store, self.now))  # worker 为未到期项驻留
        task = self.store.get_task(task_id)
        assert task is not None
        view = describe(task, self.store.attempts(task_id))
        self.assertEqual((view.phase, view.reason), (Phase.QUEUED, "deferred"))
        step = next_step(task, self.store.attempts(task_id), ref="x", now=self.now)
        assert step is not None
        self.assertTrue(step.text.startswith("定时 "))
        self.assertIn("cancel x", step.text)
        self.now += 1
        self._run()
        [work] = work_attempts(self.store.attempts(task_id))
        self.assertEqual(work.delivery, Delivery.QUEUED)

    def test_worker_stays_resident_past_the_parking_bound_for_deferred_and_remind_items(self) -> None:
        # 未到期的定时项不做发现、不进 §79 停泊计时：worker 一直驻留到点（含建即关闭的 remind 告知）
        mono = [0.0]
        self.dispatcher.monotonic = lambda: mono[0]
        task_id = self._deferred(delay=1860.0)
        remind, _ = self.store.create_fyi(title="提醒", origin=R.LEAD, origin_class="bypass", target=R.LEAD,
                                          body="复查", refs=[], now=self.now, bridge_sender=True,
                                          attempt_options={DEFER_OPTION: self.now + 1860.0, REMIND_OPTION: True})
        for step in range(1, 31):  # 30 分钟里每分钟跑一轮，单调钟同步走过停泊上限
            self.now += 60
            mono[0] += 60
            self._run()
            self.assertTrue(self.dispatcher.has_live_work(), step)
        self.assertGreater(mono[0], DISCOVERY_PARK_SECONDS)
        self.assertEqual([e for e, _ in self.records if e == "pending_parked"], [])
        self.now += 60
        mono[0] += 60
        self._run()
        [work] = work_attempts(self.store.attempts(task_id))
        [notice] = self.store.attempts(remind.id)
        self.assertEqual((work.delivery, notice.delivery), (Delivery.QUEUED, Delivery.WRITTEN))

    def test_past_due_and_auto_retry_fall_back_to_the_waiting_text(self) -> None:
        # 显示层判据（§104.11 P3）：到点后目标一直不在线、或首发失败在等自动重试时，不再印「定时 <时刻> 发出」
        self.lead_online = False
        task, _ = self.store.create_task(title="定时", flow=R.Flow.HANDOFF, origin=R.IMPL, origin_class="bypass",
                                         reviewer=None, target=R.LEAD, body="到点再做", refs=[], now=self.now,
                                         attempt_options={DEFER_OPTION: self.now + 600})
        due = self.now + 600
        attempts = self.store.attempts(task.id)
        [work] = work_attempts(attempts)
        self.assertEqual(deferred_due(work.options, pending=True, now=due - 1), due)
        self.assertIsNone(deferred_due(work.options, pending=True, now=due))
        self.assertIsNone(deferred_due(work.options, pending=False, now=due - 1))
        self.assertEqual(defer_line(work, due - 1), deferred_text(due))
        self.now += 3600  # 到点后一小时，目标一直不在线
        self._run()
        current = self.store.get_task(task.id)
        assert current is not None
        attempts = self.store.attempts(task.id)
        [work] = work_attempts(attempts)
        view = describe(current, attempts)
        self.assertEqual((work.delivery, view.reason), (Delivery.PENDING, "deferred"))  # describe 不看时钟、不改
        self.assertEqual(shown_reason(view, self.now), "waiting_for_target")
        step = next_step(current, attempts, ref="x", now=self.now)
        assert step is not None
        self.assertTrue(step.text.startswith("等后台 worker 发送"), step.text)
        self.assertIsNone(defer_line(work, self.now))
        # 定时与自动重试并存：describe 已写 waiting_for_target，「定时发出」行也不印
        retrying = replace(work, options={**work.options, AUTO_RETRY_OPTION: {"first": "t"}})
        self.assertEqual(describe(current, [retrying]).reason, "waiting_for_target")
        self.assertIsNone(defer_line(retrying, due - 1))
        self.assertIsNone(deferred_due(retrying.options, pending=True, now=due - 1))

    def test_force_publish_that_waited_for_the_lock_across_the_due_time_does_not_roll_the_summary_back(self) -> None:
        # §104.13 第 6 条（Codex r2 P2-02）：强制发布在等锁期间，另一发布者已按到期后的时刻写好；它进锁后才取时，
        # 用同一时刻判过期、渲染与写入，不会把摘要覆盖回「定时发出」
        from contextlib import contextmanager
        from pathlib import Path
        from unittest.mock import patch
        from agentstatus_bridge import summary as summary_module
        directory = Path(self._tmp.name) / "summary"
        directory.mkdir()
        task_id = self._deferred(delay=600)
        due = self.now + 600
        summary_module.publish(self.store, directory, now=self.now)
        clock = [due - 0.1]  # 强制发布调用时（还没拿锁）尚未到期
        real_lock = summary_module._lock  # pyright: ignore[reportPrivateUsage]

        @contextmanager
        def another_writer_goes_first(path: Path):  # noqa: ANN202
            clock[0] = due + 0.1  # 等锁期间到期，另一发布者先写
            with patch.object(summary_module, "_lock", real_lock):
                self.assertEqual(summary_module.publish(self.store, path).status, "written")
            with real_lock(path):
                yield

        with patch.object(summary_module.time, "time", side_effect=lambda: clock[0]), \
                patch.object(summary_module, "_lock", another_writer_goes_first):
            summary_module.publish(self.store, directory, force=True)
        document = summary_module.load(directory)
        assert document is not None
        self.assertEqual(document["generatedAt"], due + 0.1)
        [entry] = [item for item in document["tasks"] if item["id"] == task_id]
        self.assertEqual(entry["reasonText"], REASON_TEXTS["waiting_for_target"])

    def test_summary_is_republished_once_a_deferred_item_falls_due(self) -> None:
        # §104.11 P3：摘要文字随到期改变而账本修订不变；发布判断「上次生成之后有没有定时项到期」并给出下一个到期时刻
        from pathlib import Path
        from agentstatus_bridge import summary as summary_module
        directory = Path(self._tmp.name) / "summary"
        directory.mkdir()
        task_id = self._deferred(delay=600)
        due = self.now + 600
        first = summary_module.publish(self.store, directory, now=self.now)
        self.assertEqual((first.status, first.refresh_at), ("written", due))
        document = summary_module.load(directory)
        assert document is not None
        [entry] = [item for item in document["tasks"] if item["id"] == task_id]
        # 条目按摘要自己的生成时刻判断（不是读文件那一刻的系统时钟）：生成时还没到期
        self.assertEqual(entry["reasonText"], REASON_TEXTS["deferred"])
        self.assertTrue(entry["next"]["text"].startswith("定时 "))
        again = summary_module.publish(self.store, directory, now=due - 1)
        self.assertEqual((again.status, again.refresh_at), ("fresh", due))
        later = summary_module.publish(self.store, directory, now=due)
        self.assertEqual((later.status, later.refresh_at), ("written", None))
        document = summary_module.load(directory)
        assert document is not None
        [entry] = [item for item in document["tasks"] if item["id"] == task_id]
        self.assertEqual((entry["reason"], entry["reasonText"]), ("deferred", REASON_TEXTS["waiting_for_target"]))
        self.assertEqual(summary_module.publish(self.store, directory, now=due + 5).status, "fresh")
        # 自动重试并存的不算定时项，不触发刷新
        retrying, _ = self.store.create_task(title="重试", flow=R.Flow.HANDOFF, origin=R.LEAD, origin_class="bypass",
                                             reviewer=None, target=R.IMPL, body="x", refs=[], now=self.now,
                                             attempt_options={DEFER_OPTION: due + 900, AUTO_RETRY_OPTION: {"first": "t"}})
        self.assertIsNone(summary_module.publish(self.store, directory, now=due + 10).refresh_at)
        self.assertTrue(retrying.id)

    def test_clock_rollback_does_not_hold_forever(self) -> None:
        task_id = self._deferred(delay=MAX_DEFER_SECONDS + 3600)  # 到期时刻远超上限：按已到期
        self._run()
        self.assertEqual(work_attempts(self.store.attempts(task_id))[0].delivery, Delivery.QUEUED)

    def test_cancel_before_due(self) -> None:
        task_id = self._deferred()
        [work] = work_attempts(self.store.attempts(task_id))
        self.assertTrue(self.store.transition_delivery(work.id, expected=(Delivery.PENDING,), new=Delivery.CANCELLED,
                                                       reason="cancelled", now=self.now))
        self.now += 7200
        self._run()
        self.assertEqual(self.codex.calls, [])


@linux_fixture
class DeferCliTests(unittest.TestCase):
    def setUp(self) -> None:
        import test_bridge_cli as cli_tests
        self.cli_tests = cli_tests
        self.IMPL, self.LEAD = cli_tests.IMPL, cli_tests.LEAD
        cli_tests.CliTests.setUp(self)  # type: ignore[arg-type]
        from agentstatus_bridge import cli
        self.cli = cli
        self.caller = cli_tests.as_agent(self.LEAD)

    def run_cli(self, *argv: str) -> tuple[int, str, str]:
        return self.cli_tests.CliTests.run_cli(self, *argv)  # type: ignore[arg-type]

    def store(self):  # noqa: ANN201
        return self.cli_tests.CliTests.store(self)  # type: ignore[arg-type]

    def _only_task(self):  # noqa: ANN202
        with self.store() as store:
            [task] = store.list_tasks(include_finished=True)
            return task, store.attempts(task.id)

    def test_after_defers_without_waiting_or_stamping(self) -> None:
        code, out, err = self.run_cli("send", "--to", "codex@impl", "-m", "到点再做", "--after", "30m", "--expect", "2h")
        self.assertEqual(code, 0, err)
        self.assertIn("定时 ", out)
        self.assertIn("cancel ", out)
        task, [work] = self._only_task()
        self.assertEqual(task.options.get("expect"), 7200.0)
        self.assertNotIn(ORIGIN_WATCH_OPTION, work.options)
        self.assertAlmostEqual(work.options[DEFER_OPTION] - work.created_at, 1800.0, delta=1.0)
        self.assertEqual(work.delivery, Delivery.PENDING)

    def _deferred_task(self, due: float) -> str:
        with self.store() as store:
            task, _ = store.create_task(title="定时任务", flow=R.Flow.HANDOFF, origin=self.LEAD.ref, origin_class="bypass",
                                        reviewer=None, target=self.IMPL.ref, body="到点再做", refs=[], now=due - 3600,
                                        attempt_options={DEFER_OPTION: due})
        return task.id

    def test_past_due_display_uses_the_waiting_wording_everywhere(self) -> None:
        # 显示层端到端（§104.11 P3）：定时项已过期、仍是 PENDING（目标不在线、worker 没轮到）。status 首行与下一步、tasks 行、
        # wait 超时行、status --json 的 reasonText、summary 的 reasonText 与 next.text 都用等待写法；JSON 的 reason 仍是 deferred
        import time as clock
        from agentstatus_bridge import summary as summary_module
        waiting, deferred = REASON_TEXTS["waiting_for_target"], REASON_TEXTS["deferred"]
        past = self._deferred_task(clock.time() - 60)
        future = self._deferred_task(clock.time() + 3600)
        code, out, err = self.run_cli("status", past)
        self.assertEqual(code, 0, err)
        self.assertIn(f"排队：{waiting}", out.splitlines()[0])
        self.assertNotIn(deferred, out)
        self.assertNotIn("定时发出：", out)
        self.assertIn("等后台 worker 发送", out)
        code, out, _ = self.run_cli("status", past, "--json")
        document = json.loads(out)
        self.assertEqual((document["reason"], document["reasonText"]), ("deferred", waiting))
        code, out, _ = self.run_cli("tasks")
        [row] = [line for line in out.splitlines() if line.startswith(past[:8])]
        self.assertIn(waiting, row)
        self.assertNotIn(deferred, row)
        code, out, _ = self.run_cli("wait", past, "--timeout", "0")
        self.assertIn(f"等待超时：排队（{waiting}）", out)
        with self.store() as store:
            summary_module.publish(store, self.state)
        published = summary_module.load(self.state)
        assert published is not None
        entries = {item["id"]: item for item in published["tasks"]}
        self.assertEqual((entries[past]["reason"], entries[past]["reasonText"]), ("deferred", waiting))
        self.assertTrue(entries[past]["next"]["text"].startswith("等后台 worker 发送"), entries[past]["next"])
        # 对照：还没到点的照旧写定时
        self.assertEqual(entries[future]["reasonText"], deferred)
        self.assertTrue(entries[future]["next"]["text"].startswith("定时 "))
        code, out, _ = self.run_cli("status", future)
        self.assertIn(f"排队：{deferred}", out.splitlines()[0])
        self.assertIn("定时发出：", out)
        code, out, _ = self.run_cli("status", future, "--json")
        self.assertEqual(json.loads(out)["reasonText"], deferred)

    def test_send_after_does_not_wait_for_the_first_delivery(self) -> None:
        # 审计 3f/3h：定时项到点前不外调，send 不进首投等待（本机 send 与 --fyi 都一样）
        from unittest.mock import patch
        with patch.object(self.cli, "_wait_first_delivery", side_effect=AssertionError("不该等首投")):
            code, out, err = self.run_cli("send", "--to", "codex@impl", "-m", "到点再做", "--after", "30m")
            self.assertEqual(code, 0, err)
            code, out, err = self.run_cli("send", "--to", "codex@impl", "-m", "到点再看", "--fyi", "--after", "30m")
            self.assertEqual(code, 0, err)
        with self.store() as store:
            attempts = [item for task in store.list_tasks(include_finished=True) for item in store.attempts(task.id)]
        self.assertEqual(len(attempts), 2)
        self.assertTrue(all(DEFER_OPTION in item.options and item.delivery is Delivery.PENDING for item in attempts))

    def test_local_fyi_after_is_deferred_too(self) -> None:
        code, out, err = self.run_cli("send", "--to", "codex@impl", "-m", "到点再看", "--fyi", "--after", "30m")
        self.assertEqual(code, 0, err)
        self.assertIn("定时 ", out)
        task, [notice] = self._only_task()
        self.assertTrue(task.finished and task.is_fyi)
        self.assertFalse(notice.is_remind)
        self.assertEqual(notice.delivery, Delivery.PENDING)
        self.assertAlmostEqual(notice.options[DEFER_OPTION] - notice.created_at, 1800.0, delta=1.0)

    def test_invalid_durations_and_fyi_expect_conflict_write_nothing(self) -> None:
        cases = [(("--after", "30s"), "after_invalid"), (("--after", "25h"), "after_invalid"),
                 (("--expect", "4m"), "expect_invalid"), (("--fyi", "--expect", "1h"), "fyi_conflict")]
        for extra, code_name in cases:
            with self.subTest(extra=extra):
                code, _out, err = self.run_cli("send", "--to", "codex@impl", "-m", "x", *extra)
                self.assertNotEqual(code, 0)
                self.assertIn(REASON_TEXTS[code_name], err)
        with self.store() as store:
            self.assertEqual(store.list_tasks(include_finished=True), [])

    def test_remind_schedules_a_bridge_sent_fyi_to_the_caller_itself(self) -> None:
        code, out, err = self.run_cli("remind", "--in", "31m", "-m", "复查 db0d0b7f 没有第二条")
        self.assertEqual(code, 0, err)
        self.assertIn("定时提醒 ", out)
        task, [notice] = self._only_task()
        self.assertTrue(task.finished and task.is_fyi)
        self.assertTrue(notice.is_remind)
        self.assertEqual((notice.target, notice.sender, task.origin), (self.LEAD.ref, None, self.LEAD.ref))
        self.assertEqual(notice.options[REMIND_OPTION], True)
        self.assertAlmostEqual(notice.options[DEFER_OPTION] - notice.created_at, 1860.0, delta=1.0)
        code, out, err = self.run_cli("remind", "--list", "--json")
        self.assertEqual(code, 0, err)
        [row] = json.loads(out)["reminders"]
        self.assertEqual(row["taskId"], task.id)
        code, out, _ = self.run_cli("remind", "--list")
        self.assertIn(task.id[:8], out)
        # 别的会话看不到这条
        self.caller = self.cli_tests.as_agent(self.IMPL)
        code, out, _ = self.run_cli("remind", "--list")
        self.assertIn("没有未发出的定时提醒", out)
        # 取消照现有 cancel
        self.caller = self.cli_tests.as_agent(self.LEAD)
        code, _out, err = self.run_cli("cancel", task.id)
        self.assertEqual(code, 0, err)
        _, [notice] = self._only_task()
        self.assertEqual(notice.delivery, Delivery.CANCELLED)

    def test_remind_follows_the_shared_thread_rule_instead_of_always_allowing_it(self) -> None:
        # §104.11 P3：remind 不再无条件 allowShared；调用方自己的 thread 被多个进程加载时与 send 同一判定
        code, _out, err = self.run_cli("remind", "--in", "5m", "-m", "普通")
        self.assertEqual(code, 0, err)
        _task, [notice] = self._only_task()
        self.assertFalse(notice.allow_shared)
        from bridge_support import endpoint
        shared = endpoint(self.LEAD.ref, issues=("shared_thread",))
        self.endpoints = [self.IMPL, shared]
        self.caller = self.cli_tests.as_agent(shared)
        code, _out, err = self.run_cli("remind", "--in", "5m", "-m", "共享")
        self.assertEqual(code, self.cli.EXIT_REJECTED)
        self.assertIn(REASON_TEXTS["target_shared_thread"], err)
        with self.store() as store:
            self.assertEqual(len(store.list_tasks(include_finished=True)), 1)  # 写前拒绝
        code, _out, err = self.run_cli("remind", "--in", "5m", "-m", "共享", "--allow-shared")
        self.assertEqual(code, 0, err)
        with self.store() as store:
            newest = max(store.list_tasks(include_finished=True), key=lambda item: item.created_at)
            [notice] = store.attempts(newest.id)
        self.assertTrue(notice.allow_shared)

    def test_remind_reads_the_body_from_a_file(self) -> None:
        body = self.state.parent / "remind-body.txt"
        body.write_text("文件里的提醒内容", encoding="utf-8")
        code, _out, err = self.run_cli("remind", "--in", "5m", "--file", str(body))
        self.assertEqual(code, 0, err)
        _task, [notice] = self._only_task()
        self.assertEqual(notice.body, "文件里的提醒内容")
        code, _out, err = self.run_cli("remind", "--in", "5m")
        self.assertNotEqual(code, 0)
        self.assertIn(REASON_TEXTS["empty_message"], err)

    def test_remind_turn_is_not_quiet_in_the_summary(self) -> None:
        self.run_cli("remind", "--in", "1m", "-m", "看一眼")
        task, [notice] = self._only_task()
        with self.store() as store:
            self.assertTrue(store.begin_send(notice.id, now=notice.created_at + 61, pid=1, start_ticks="1"))
            store.finish_send(notice.id, delivery=Delivery.QUEUED, reason="codex_queued", provider_ref=None,
                              detail={}, now=notice.created_at + 61)
            [(_, item)] = store.recent_delivery_rows(limit=8)
        self.assertEqual(item["role"], "notice")
        self.assertNotIn("kind", item)  # 不标 fyi：扩展照常通知叫醒的那一轮

    def test_remind_requires_an_agent_session_and_input(self) -> None:
        self.caller = self.cli_tests.USER
        code, _out, err = self.run_cli("remind", "--in", "5m", "-m", "x")
        self.assertNotEqual(code, 0)
        self.assertIn("remind 只给认得出的 agent 会话用", err)
        self.caller = self.cli_tests.as_agent(self.LEAD)
        for argv in (("remind", "--in", "5m"), ("remind", "-m", "x"), ("remind", "--in", "30s", "-m", "x")):
            with self.subTest(argv=argv):
                code, _out, _err = self.run_cli(*argv)
                self.assertNotEqual(code, 0)
        with self.store() as store:
            self.assertEqual(store.list_tasks(include_finished=True), [])


class FederatedDeferTests(FederationTestCase):
    def _deferred_remote(self, delay_ms: int = 3_600_000):
        return authority.create_task(
            self.a.store, self.a.ident, title="跨设备定时", flow="handoff", body="到点再做", refs=[], origin=self.origin,
            origin_actor=self.origin_actor(), origin_class="bypass", target=self.worker_remote, reviewer=None, now=T0,
            defer_until=(T0 + delay_ms) / 1000.0, expect=900.0)

    def test_status_line_shows_the_scheduled_time_only_before_it_is_due(self) -> None:
        task, _ = self._deferred_remote()
        current = self.a.store.get_task(DEV_A, task.task_id)
        assert current is not None
        rt = runtime(self.a, self.root)
        due = (T0 + 3_600_000) / 1000.0
        before = "\n".join(commands.task_lines(rt, current, now=T0 + 3_599_000))
        self.assertIn(deferred_text(due), before)
        after = "\n".join(commands.task_lines(rt, current, now=T0 + 3_600_000))
        self.assertNotIn("定时发出：", after)  # 到点后（relay 还没交出）不印过去的时刻（§104.11 P3）
        self.assertIn(REASON_TEXTS["deferred"], before)
        self.assertNotIn(REASON_TEXTS["deferred"], after)
        self.assertIn(REASON_TEXTS["waiting_for_target"], after)

    def test_remote_target_waits_in_the_outbox_until_due(self) -> None:
        task, first = self._deferred_remote()
        [row] = self.a.store.outbox()
        self.assertEqual(int(row["next_try_at"]), T0 + 3_600_000)
        envelope = json.loads(row["envelope_json"])
        self.assertNotIn(DEFER_OPTION, envelope["data"]["options"])  # 线上不加键
        self.assertNotIn("expect", json.dumps(envelope["data"]["checkpoint"]))
        current = self.a.store.get_task(DEV_A, task.task_id)
        assert current is not None
        view = describe(model_task(current), model_attempts(self.a.store.attempts(DEV_A, task.task_id)))
        self.assertEqual(view.reason, "deferred")
        self.assertEqual(model_task(current).options.get("expect"), 900.0)
        rt = runtime(self.a, self.root)
        # 到点前不算「待传超过 30 分钟」；到点 30 分钟后仍没提交才算
        self.assertFalse(commands.stalled(rt, current, now=T0 + 3_000_000))
        self.assertFalse(commands.stalled(rt, current, now=T0 + 3_600_000 + 1_700_000))
        self.assertTrue(commands.stalled(rt, current, now=T0 + 3_600_000 + 1_900_000))
        self.assertIsNotNone(first)

    def test_cancel_before_due_is_suppressed_by_the_mirror(self) -> None:
        task, first = self._deferred_remote()
        current = self.a.store.get_task(DEV_A, task.task_id)
        assert current is not None
        authority.request_cancel(self.a.store, self.a.ident, current, now=T0 + 10)
        pump(self.a, self.b, now=T0 + 3_600_001)  # task_state（取消）先到，定时交接随后到
        self.assertEqual(self.b.store.native(first.msg_id)["state"], "suppressed")  # type: ignore[index]

    def test_local_target_is_held_by_the_dispatcher_and_not_woken_early(self) -> None:
        local = self.a.bind(Provider.CLAUDE, CLAUDE_A2)
        task, first = authority.create_task(
            self.a.store, self.a.ident, title="本机目标+远端复核", flow="review", body="x", refs=[], origin=self.origin,
            origin_actor=self.origin_actor(), origin_class="bypass", target=local, reviewer=self.worker_remote,
            now=T0, defer_until=(T0 + 600_000) / 1000.0)
        self.assertEqual(self.a.store.native(first.msg_id)["state"], "prepared")  # type: ignore[index]
        self.assertNotIn(first.msg_id, mirror.wake_candidates(self.a.store, self.a.ident, now=T0 + 599_000))
        self.assertIn(first.msg_id, mirror.wake_candidates(self.a.store, self.a.ident, now=T0 + 600_000))
        seen: list[int] = []
        clock = [T0 + 599_000]
        dispatcher = FederationDispatcher(self.a.store, self.a.ident, RelayPaths(self.root),
                                          discover=lambda: seen.append(1) or [], transports={},
                                          clock=lambda: clock[0])
        counts = dispatcher.run_once()
        self.assertEqual((counts["waiting"], seen), (1, []))  # 不发现
        self.assertFalse(dispatcher.has_live_work())  # 不为它驻留：到点由 relay 唤醒
        clock[0] = T0 + 600_000
        dispatcher.run_once()
        self.assertEqual(seen, [1])  # 到点才做发现
        self.assertIsNotNone(task)

    def test_fyi_can_be_deferred_too(self) -> None:
        task, notice = authority.create_fyi(
            self.a.store, self.a.ident, title="告知", body="x", refs=[], origin=self.origin,
            origin_actor=self.origin_actor(), origin_class="bypass", target=self.worker_remote, now=T0,
            defer_until=(T0 + 120_000) / 1000.0)
        [row] = self.a.store.outbox()
        self.assertEqual(int(row["next_try_at"]), T0 + 120_000)
        self.assertEqual(model_attempts([notice])[0].defer_until, (T0 + 120_000) / 1000.0)
        self.assertEqual(model_attempts([notice])[0].role, Role.NOTICE)
        self.assertIsNotNone(task)


class FederatedDeferCliTests(FedCliCase):
    """跨设备 send 的「何时发出」措辞（§104.11 P3）：远端由 relay，本机目标由本机 worker；--fyi --after 写定时时刻。"""

    def test_remote_and_local_targets_say_who_sends_and_when(self) -> None:
        code, out, err = self.run_on("vm", "send", "--device", "win", "--to", f"codex@id:{THREAD_B}", "-m", "x",
                                     "--after", "30m", caller=as_agent(ORIGIN))
        self.assertEqual(code, 0, err)
        self.assertRegex(out, r"定时 \S+ \S+ UTC[+-]\d\d:\d\d 由 relay 发出")
        code, out, err = self.run_on("vm", "send", "--device", "win", "--to", f"codex@id:{THREAD_B}", "-m", "告知",
                                     "--fyi", "--after", "30m", caller=as_agent(ORIGIN))
        self.assertEqual(code, 0, err)
        self.assertIn("由 relay 发出；对方只需读到", out)
        self.assertIn("定时 ", out)
        code, out, err = self.run_on("vm", "send", "--device", "win", "--to", f"codex@id:{THREAD_B}", "-m", "y",
                                     caller=as_agent(ORIGIN))
        self.assertEqual(code, 0, err)
        self.assertIn("等待 relay 发出", out)
        # A 本机执行方、远端复核方：仍是跨设备任务，第一封在本机由后台 worker 投递
        code, out, err = self.run_on("vm", "send", "--to", "codex@review", "--review-device", "win", "--review-by",
                                     f"codex@id:{THREAD_B}", "-m", "本机", "--after", "30m", caller=as_agent(ORIGIN))
        self.assertIn(code, (0, 6), out + err)  # 6：夹具里没有真实 worker 可拉起
        first = out.splitlines()[0]
        self.assertTrue(first.startswith("跨设备任务 "), out)
        self.assertIn("由本机后台 worker 发出", first)
        self.assertNotIn("relay", first)


class DeferSummaryWorkerTests(unittest.TestCase):
    """worker 在账本修订不变时，也会在定时项到期后再发布一次摘要（§104.11 P3）。"""

    def setUp(self) -> None:
        from pathlib import Path
        from tempfile import TemporaryDirectory
        from unittest.mock import patch
        tmp = TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        base = Path(tmp.name)
        self.root = base / "bridge"
        self.inbox_dir = base / "socks"
        env = patch.dict(os.environ, {"CODEX_SQLITE_HOME": str(base / "codex")})  # 不读真实 Codex 数据
        env.start()
        self.addCleanup(env.stop)

    @linux_fixture
    def test_worker_republishes_when_a_deferred_item_falls_due(self) -> None:
        import time as clock
        from unittest.mock import patch
        from agentstatus_bridge import summary as summary_module, worker
        from agentstatus_bridge.store import Store
        from bridge_support import RecordingTransport, endpoint, ref
        real = clock.time
        start = real()
        with Store.open(self.root) as store:
            task, _ = store.create_task(title="定时", flow=R.Flow.HANDOFF, origin=None, origin_class="bypass",
                                        reviewer=None, target=ref(), body="到点再做", refs=[], now=start,
                                        attempt_options={DEFER_OPTION: start + 3600})
        shift = [0.0]
        calls: list[tuple[bool, str | None]] = []
        publish, mark = worker._publish_summary, summary_module.ledger_mark  # pyright: ignore[reportPrivateUsage]

        def spy(store, directory, log, *, force):  # noqa: ANN001, ANN202
            result = publish(store, directory, log, force=force)
            calls.append((force, None if result is None else result.status))
            return result

        def jump(*args, **kwargs):  # noqa: ANN002, ANN003, ANN202
            shift[0] = 7200.0  # 本轮投递之后、摘要判断之前时钟走过到期时刻；账本没有任何变化
            return mark(*args, **kwargs)

        with patch("time.time", side_effect=lambda: real() + shift[0]), \
                patch.object(worker, "_publish_summary", side_effect=spy), \
                patch.object(summary_module, "ledger_mark", side_effect=jump):
            code = worker.run_worker(root=self.root, once=True, inbox_directory=self.inbox_dir,
                                     discover_fn=lambda: [endpoint(ref())],
                                     transports={Provider.CODEX: RecordingTransport(Provider.CODEX)}, loop_seconds=0.05)
        self.assertEqual(code, 0)
        self.assertEqual(calls, [(True, "written"), (False, "written")])
        document = summary_module.load(self.root)
        assert document is not None
        [entry] = [item for item in document["tasks"] if item["id"] == task.id]
        self.assertEqual(entry["reasonText"], REASON_TEXTS["waiting_for_target"])


    @linux_fixture
    def test_worker_does_not_republish_every_round_after_the_refresh(self) -> None:
        # 刷新发布之后，刷新时刻随结果更新（没有更晚的定时项就清空）：之后几轮账本不变时不再每轮读快照、调发布（常驻开销）
        import time as clock
        from unittest.mock import patch
        from agentstatus_bridge import summary as summary_module, worker
        from agentstatus_bridge.platforms.factory import make_platform
        from agentstatus_bridge.store import Store
        from bridge_support import RecordingTransport, ref
        real = clock.time
        start = real()
        with Store.open(self.root) as store:
            store.create_task(title="定时", flow=R.Flow.HANDOFF, origin=None, origin_class="bypass", reviewer=None,
                              target=ref(), body="到点再做", refs=[], now=start,
                              attempt_options={DEFER_OPTION: start + 3600})
        base = make_platform("linux")
        handlers: list = []

        class Lifecycle:  # 只换掉信号安装：拿到 worker 的停止回调，第 3 轮结束时请它停
            def __getattr__(self, name: str):  # noqa: ANN204
                return getattr(base.lifecycle, name)

            def install_stop(self, handler):  # noqa: ANN001, ANN201
                handlers.append(handler)
                return {}

            def restore_stop(self, previous):  # noqa: ANN001, ANN201
                return None

        shift = [0.0]
        rounds = [0]
        calls: list[tuple[bool, str | None]] = []
        publish, mark = worker._publish_summary, summary_module.ledger_mark  # pyright: ignore[reportPrivateUsage]

        def spy(store, directory, log, *, force):  # noqa: ANN001, ANN202
            result = publish(store, directory, log, force=force)
            calls.append((force, None if result is None else result.status))
            return result

        def tick(*args, **kwargs):  # noqa: ANN002, ANN003, ANN202
            rounds[0] += 1
            shift[0] = 7200.0  # 第 1 轮起时钟已过到期时刻；目标发现不到，定时项留在 PENDING，账本不变
            if rounds[0] >= 3:
                handlers[0](15, None)
            return mark(*args, **kwargs)

        with patch("time.time", side_effect=lambda: real() + shift[0]), \
                patch.object(worker, "get_platform", return_value=replace(base, lifecycle=Lifecycle())), \
                patch.object(worker, "_publish_summary", side_effect=spy), \
                patch.object(summary_module, "ledger_mark", side_effect=tick):
            code = worker.run_worker(root=self.root, once=False, inbox_directory=self.inbox_dir,
                                     discover_fn=lambda: [],
                                     transports={Provider.CODEX: RecordingTransport(Provider.CODEX)}, loop_seconds=0.05)
        self.assertEqual(code, 0)
        self.assertEqual(rounds[0], 3)
        self.assertEqual(calls, [(True, "written"), (False, "written")])  # 第 2、3 轮没有再调发布


if __name__ == "__main__":
    unittest.main()
