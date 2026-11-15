"""`ab note`：给进行中的执行方补一句话（DESIGN §95.5）——账本、页脚、取消、容量、显示与读方核对（§95.5.3）。

本模块在 `bridge-windows` CI 选择集里（§95.6）：纯函数用例两种系统都跑；替身 Linux 发现与本机账本的夹具类在
Windows 上按选择器放行的 `POSIX-only:` 前缀跳过（与 §94.3 同一做法）。
"""

from __future__ import annotations

from dataclasses import replace
import json
import os
import unittest
from unittest.mock import patch

import bridge_support  # noqa: F401  导入即隔离宿主会话环境
import test_bridge_federation_cli as federation_cli  # 联邦夹具类自带 POSIX-only 跳过（§94.3 已在选择集里导入）

from agentstatus_bridge import envelope
from agentstatus_bridge.dispatch import native_priority
from agentstatus_bridge.labels import NOTE_LABEL, REASON_TEXTS, EVENT_LABELS, reason_text, role_label
from agentstatus_bridge.model import (
    FOR_SEQ_OPTION,
    NOTE_KIND,
    NOTICE_KIND_OPTION,
    Attempt,
    Delivery,
    Flow,
    Phase,
    Provider,
    Role,
    Task,
    Work,
    describe,
)
from agentstatus_bridge.reminders import REMIND_AFTER_SECONDS, attention_declined, pending_reminder
from agentstatus_bridge.store import MAX_ATTEMPTS_PER_TASK, NOTICE_RESERVE, attempt_limit
from bridge_support import ref

# Windows CI 上的跳过原因（§94.3、§95.6）：必须以选择器放行的 POSIX-only: 开头
LINUX_FIXTURE_REASON = "POSIX-only: 替身 Linux 发现与调用方、Linux 私有状态目录（Windows 缺省平台是真实 Win32）"
linux_fixture = unittest.skipUnless(os.name == "posix", LINUX_FIXTURE_REASON)

TASK_ID = "1" * 32
LEAD_REF = ref(Provider.CLAUDE, "lead-session", pid=3000, pane="%3", label="lead")
IMPL_REF = ref(Provider.CODEX, "impl-thread", pid=1000, pane="%1", label="impl")
NOTE_OPTIONS = {NOTICE_KIND_OPTION: NOTE_KIND, FOR_SEQ_OPTION: 1}


def make_task(**changes: object) -> Task:
    fields: dict[str, object] = dict(id=TASK_ID, created_at=10.0, updated_at=10.0, title="实现 X", flow=Flow.HANDOFF,
                                     origin=LEAD_REF, reviewer=None)
    fields.update(changes)
    return Task(**fields)  # type: ignore[arg-type]


def make_attempt(seq: int, role: Role = Role.HANDOFF, **changes: object) -> Attempt:
    fields: dict[str, object] = dict(
        id=f"{seq:032x}", task_id=TASK_ID, seq=seq, role=role, target=IMPL_REF, message_id=f"{seq + 100:032x}",
        created_at=float(seq), body="正文", work=Work.NONE if role is Role.NOTICE else Work.AWAITING_ACK)
    fields.update(changes)
    return Attempt(**fields)  # type: ignore[arg-type]


class NoteModelTests(unittest.TestCase):
    """纯函数：类别判定、页脚、容量、原生优先级、标签与提醒判定（两种系统都跑）。"""

    def test_is_note_and_for_seq_only_for_note_notices(self) -> None:
        note = make_attempt(2, Role.NOTICE, options=dict(NOTE_OPTIONS))
        self.assertTrue(note.is_note)
        self.assertEqual(note.note_for_seq, 1)
        self.assertFalse(note.is_closure)
        # 别的 notice、带同样 options 的工作尝试、坏 forSeq 都不是可用的 note
        self.assertFalse(make_attempt(2, Role.NOTICE).is_note)
        self.assertFalse(make_attempt(2, Role.HANDOFF, options=dict(NOTE_OPTIONS)).is_note)
        for bad in (0, -1, True, "1", None):
            with self.subTest(bad=bad):
                broken = make_attempt(2, Role.NOTICE, options={NOTICE_KIND_OPTION: NOTE_KIND, FOR_SEQ_OPTION: bad})
                self.assertTrue(broken.is_note)
                self.assertIsNone(broken.note_for_seq)

    def test_note_does_not_change_the_current_work_attempt(self) -> None:
        work = make_attempt(1, delivery=Delivery.QUEUED, delivery_at=5.0, work=Work.IN_PROGRESS)
        note = make_attempt(2, Role.NOTICE, options=dict(NOTE_OPTIONS))
        view = describe(make_task(), [work, note])
        self.assertIs(view.current, work)
        self.assertEqual((view.phase, view.reason), (Phase.RUNNING, "in_progress"))

    def test_footer_points_report_at_the_supplemented_attempt(self) -> None:
        task = make_task()
        note = make_attempt(3, Role.NOTICE, body="还要顺便测 Y", options={NOTICE_KIND_OPTION: NOTE_KIND, FOR_SEQ_OPTION: 2})
        text = envelope.render(task, note, sender="claude@lead", device="vm", command="ab")
        lines = text.splitlines()
        self.assertEqual(lines[0], f"[AgentStatus 协作] task={TASK_ID} attempt=3 msg={note.message_id} role=notice"
                                   " from=claude@lead device=vm")
        self.assertEqual(lines[-1], f"（AgentStatus 协作桥补充消息：这是任务 {TASK_ID} 第 2 次尝试的补充，不需要 ab report"
                                    f" 这条消息；继续当前尝试，完成后仍按 `ab report {TASK_ID} --attempt 2 …` 汇报。）")
        self.assertIn("还要顺便测 Y", text)
        # 不是通用 notice 页脚，也没有工作类的汇报命令清单
        self.assertNotIn("协作桥通知；查看详情", text)
        self.assertNotIn("--ack", text)
        header = envelope.parse_header(text)
        assert header is not None
        self.assertEqual((header.role, header.attempt), (Role.NOTICE, 3))
        # 联邦：汇报命令带 --origin-device
        remote = envelope.render(task, note, sender="claude@lead", device="vm", command="ab", origin_device="vm")
        self.assertIn(f"`ab report {TASK_ID} --origin-device vm --attempt 2 …`", remote)

    def test_note_without_for_seq_falls_back_to_generic_notice_footer(self) -> None:
        broken = make_attempt(2, Role.NOTICE, options={NOTICE_KIND_OPTION: NOTE_KIND})
        text = envelope.render(make_task(), broken, sender="user", device="vm", command="ab")
        self.assertIn("协作桥通知；查看详情", text)

    def test_note_capacity_is_work_class(self) -> None:
        work_limit = MAX_ATTEMPTS_PER_TASK - NOTICE_RESERVE
        self.assertEqual(attempt_limit(Role.NOTICE, dict(NOTE_OPTIONS)), work_limit)
        self.assertEqual(attempt_limit(Role.HANDOFF), work_limit)
        # 其他 notice 的预留不变
        self.assertEqual(attempt_limit(Role.NOTICE), MAX_ATTEMPTS_PER_TASK)
        self.assertEqual(attempt_limit(Role.NOTICE, {"noticeKind": "closure"}), MAX_ATTEMPTS_PER_TASK)

    def test_note_priority_follows_the_ack_and_its_own_label(self) -> None:
        # 与 Codex steer 同一判据（G4 审计 r1 复核）：所补的工作尝试未确认开始时用交接那一档 later，已确认后 next
        from agentstatus_bridge.model import WORK_STARTED
        note = make_attempt(2, Role.NOTICE, options=dict(NOTE_OPTIONS))
        self.assertEqual(native_priority(note), "later")  # 查不到工作尝试按未确认
        for work in Work:
            with self.subTest(work=work):
                expected = "next" if work in WORK_STARTED else "later"
                self.assertEqual(native_priority(note, note_work=make_attempt(1, work=work)), expected)
        # 告知、其他通知与交接不看所补尝试
        acknowledged, waiting = make_attempt(1, work=Work.ACKNOWLEDGED), make_attempt(1, work=Work.AWAITING_ACK)
        fyi = make_attempt(1, Role.NOTICE, options={NOTICE_KIND_OPTION: "fyi"})
        for attempt, expected in ((fyi, "next"), (make_attempt(3, Role.NOTICE), "next"), (make_attempt(1), "later")):
            for work in (None, acknowledged, waiting):
                with self.subTest(attempt=attempt.seq, role=attempt.role, work=work and work.work):
                    self.assertEqual(native_priority(attempt, note_work=work), expected)
        self.assertEqual(role_label(note), NOTE_LABEL)
        self.assertEqual(role_label(make_attempt(2, Role.NOTICE)), "通知发起方")
        self.assertIn("note_created", EVENT_LABELS)
        for code in ("note_no_active_attempt", "note_task_paused", "note_not_authority", "codex_steered"):
            with self.subTest(code=code):
                self.assertIn(code, REASON_TEXTS)
                self.assertNotIn("{command}", reason_text(code, command="ab"))

    def _unknown_work(self) -> Attempt:
        # 工作尝试结果不明：需处理（delivery_unknown），关注时刻是投递时刻；这时仍可以补充
        return make_attempt(1, delivery=Delivery.UNKNOWN, delivery_at=100.0)

    def test_pending_note_does_not_block_origin_reminder(self) -> None:
        note = make_attempt(2, Role.NOTICE, created_at=200.0, options=dict(NOTE_OPTIONS))
        for delivery in (Delivery.PENDING, Delivery.SENDING):
            with self.subTest(delivery=delivery):
                reminder = pending_reminder(make_task(), [self._unknown_work(), replace(note, delivery=delivery)])
                assert reminder is not None
                self.assertEqual(reminder.due_at, 100.0 + REMIND_AFTER_SECONDS)

    def test_delivered_note_does_not_reset_origin_reminder(self) -> None:
        note = make_attempt(2, Role.NOTICE, created_at=200.0, delivery=Delivery.QUEUED, delivery_at=900.0,
                            options=dict(NOTE_OPTIONS))
        reminder = pending_reminder(make_task(), [self._unknown_work(), note])
        assert reminder is not None
        self.assertEqual(reminder.due_at, 100.0 + REMIND_AFTER_SECONDS)

    def test_note_at_seq_60_leaves_the_reminder_slot(self) -> None:
        # note 按工作类算，最多占到 60；提醒限额判断（max seq >= 61 才不再提醒）不受影响（§95.5.3）
        note = make_attempt(60, Role.NOTICE, created_at=200.0, delivery=Delivery.QUEUED, delivery_at=300.0,
                            options={NOTICE_KIND_OPTION: NOTE_KIND, FOR_SEQ_OPTION: 1})
        self.assertIsNotNone(pending_reminder(make_task(), [self._unknown_work(), note]))
        receipt = make_attempt(61, Role.NOTICE, created_at=50.0, delivery=Delivery.QUEUED, delivery_at=60.0)
        self.assertIsNone(pending_reminder(make_task(), [self._unknown_work(), note, receipt]))

    def test_target_refusing_a_note_is_not_origin_declining(self) -> None:
        task = make_task()
        for delivery in (Delivery.DENIED, Delivery.REFUSED):
            with self.subTest(delivery=delivery):
                note = make_attempt(2, Role.NOTICE, created_at=200.0, delivery=delivery, delivery_at=300.0,
                                    options=dict(NOTE_OPTIONS))
                attempts = [self._unknown_work(), note]
                self.assertFalse(attention_declined(task, attempts, describe(task, attempts)))
                self.assertIsNotNone(pending_reminder(task, attempts))
                # 对照：同样状态的普通 notice（发给发起方的回执）仍算发起方拒绝
                receipt = replace(note, options={})
                self.assertTrue(attention_declined(task, [self._unknown_work(), receipt],
                                                   describe(task, [self._unknown_work(), receipt])))


@linux_fixture
class NoteCliTests(unittest.TestCase):
    """本机 CLI：资格、账本、取消、容量、显示（借用 CliTests 的替身发现与隔离状态目录）。"""

    def _borrow(self) -> None:
        import test_bridge_cli as cli_tests
        self.cli_tests = cli_tests
        self.IMPL, self.LEAD, self.REVIEW = cli_tests.IMPL, cli_tests.LEAD, cli_tests.REVIEW
        self.as_agent, self.USER = cli_tests.as_agent, cli_tests.USER

    def setUp(self) -> None:
        self._borrow()
        self.cli_tests.CliTests.setUp(self)  # type: ignore[arg-type]
        from agentstatus_bridge import cli
        self.cli = cli

    def run_cli(self, *argv: str) -> tuple[int, str, str]:
        return self.cli_tests.CliTests.run_cli(self, *argv)  # type: ignore[arg-type]

    def send(self, *extra: str) -> str:
        return self.cli_tests.CliTests.send(self, *extra)  # type: ignore[arg-type]

    def store(self):  # noqa: ANN201
        return self.cli_tests.CliTests.store(self)  # type: ignore[arg-type]

    def mark_sent(self, task_id: str, delivery: Delivery = Delivery.QUEUED, detail: dict[str, object] | None = None) -> None:
        with self.store() as store:
            attempt = [item for item in store.attempts(task_id) if item.role is not Role.NOTICE][-1]
            store.begin_send(attempt.id, now=1.0, pid=1, start_ticks="1")
            if delivery is not Delivery.SENDING:
                store.finish_send(attempt.id, delivery=delivery, reason="test", provider_ref=None,
                                  detail=dict(detail or {}), now=2.0)

    def started(self) -> str:
        self.caller = self.as_agent(self.LEAD)
        task_id = self.send()
        self.mark_sent(task_id)
        return task_id

    def notes(self, task_id: str) -> list[Attempt]:
        with self.store() as store:
            return [item for item in store.attempts(task_id) if item.is_note]

    def test_note_adds_a_notice_for_the_current_attempt_target(self) -> None:
        task_id = self.started()
        code, out, err = self.run_cli("note", task_id, "-m", "还要顺便测 Y")
        self.assertEqual(code, self.cli.EXIT_OK, err)
        self.assertIn(f"已排队补充 #2 → codex@id:impl-thread（任务 {task_id[:8]} 第 1 次尝试；对方不需要汇报这条）", out)
        [note] = self.notes(task_id)
        self.assertEqual((note.seq, note.role, note.delivery, note.work), (2, Role.NOTICE, Delivery.PENDING, Work.NONE))
        self.assertEqual(note.options, {NOTICE_KIND_OPTION: NOTE_KIND, FOR_SEQ_OPTION: 1, "allowShared": False})
        self.assertEqual(note.body, "还要顺便测 Y")
        self.assertEqual(note.target, self.IMPL.ref)
        self.assertEqual(note.sender, self.LEAD.ref)
        with self.store() as store:
            view = describe(store.get_task(task_id), store.attempts(task_id))  # type: ignore[arg-type]
            events = [event["kind"] for event in store.events(task_id)]
        self.assertEqual(view.current.seq if view.current else None, 1)
        self.assertIn("note_created", events)
        self.assertNotIn("notice_created", events)

    def test_note_goes_to_the_generation_that_received_the_work(self) -> None:
        self.caller = self.as_agent(self.LEAD)
        task_id = self.send()
        self.mark_sent(task_id, detail={"deliveredPid": 4321, "deliveredStart": "999", "deliveredPane": "%7"})
        self.assertEqual(self.run_cli("note", task_id, "-m", "补充")[0], 0)
        [note] = self.notes(task_id)
        self.assertEqual((note.target.pid, note.target.start_ticks, note.target.pane), (4321, "999", "%7"))
        self.assertTrue(note.target.same_session(self.IMPL.ref))

    def test_user_note_and_file_and_stdin_bodies(self) -> None:
        task_id = self.started()
        self.caller = self.USER
        path = os.path.join(self._tmp.name, "note.txt")  # type: ignore[attr-defined]
        with open(path, "w", encoding="utf-8") as handle:
            handle.write("来自文件的补充")
        self.assertEqual(self.run_cli("note", task_id, "--file", path)[0], 0)
        code, _out, err = self.run_cli("note", task_id, "--file", path, "-m", "x")
        self.assertEqual(code, 3, err)
        self.assertIn("message_and_file_conflict", err)
        code, _out, err = self.run_cli("note", task_id, "-m", "  ")
        self.assertEqual(code, 3, err)
        self.assertIn("empty_message", err)
        [note] = self.notes(task_id)
        self.assertEqual((note.body, note.sender), ("来自文件的补充", None))

    def test_unattributed_agent_caller_is_rejected_like_send(self) -> None:
        task_id = self.started()
        from agentstatus_bridge.endpoints import Caller
        from agentstatus_bridge.platforms.linux.process import ProcessInfo
        self.caller = Caller(None, ProcessInfo(5000, 1, "codex", "5"))
        code, _out, err = self.run_cli("note", task_id, "-m", "补充")
        self.assertEqual(code, 3, err)
        self.assertIn("caller_unattributed", err)
        self.assertEqual(self.notes(task_id), [])

    def test_note_is_allowed_while_the_attempt_may_be_with_the_target(self) -> None:
        for delivery in (Delivery.SENDING, Delivery.WRITTEN, Delivery.QUEUED, Delivery.DELIVERED, Delivery.HELD,
                         Delivery.UNKNOWN):
            with self.subTest(delivery=delivery):
                self.caller = self.as_agent(self.LEAD)
                task_id = self.send()
                self.mark_sent(task_id, delivery)
                code, _out, err = self.run_cli("note", task_id, "-m", "补充")
                self.assertEqual(code, 0, err)
        # ack / progress 之后仍可补充
        for kind in ("--ack", "--progress"):
            with self.subTest(kind=kind):
                task_id = self.started()
                self.caller = self.as_agent(self.IMPL)
                self.assertEqual(self.run_cli("report", task_id, kind)[0], 0)
                self.caller = self.as_agent(self.LEAD)
                self.assertEqual(self.run_cli("note", task_id, "-m", "补充")[0], 0)

    def assert_rejected(self, task_id: str, code_name: str, *, exit_code: int = 3) -> None:
        before = len(self.notes(task_id))
        code, out, err = self.run_cli("note", task_id, "-m", "补充", "--json")
        self.assertEqual(code, exit_code, err)
        self.assertIn(f"[{code_name}]", err)
        document = json.loads(out)
        self.assertEqual((document["ok"], document["code"]), (False, code_name))
        self.assertEqual(len(self.notes(task_id)), before)

    def test_rejections_write_nothing(self) -> None:
        # 还在桥内排队（未发出）
        self.caller = self.as_agent(self.LEAD)
        self.assert_rejected(self.send(), "note_no_active_attempt")
        # 可证明未送达
        for delivery in (Delivery.FAILED, Delivery.REFUSED, Delivery.DENIED, Delivery.EXPIRED, Delivery.CANCELLED):
            with self.subTest(delivery=delivery):
                self.caller = self.as_agent(self.LEAD)
                task_id = self.send()
                if delivery is Delivery.CANCELLED:
                    self.assertEqual(self.run_cli("cancel", task_id)[0], 0)
                else:
                    self.mark_sent(task_id, delivery)
                self.assert_rejected(task_id, "note_no_active_attempt")
        # 已终态汇报
        for kind in ("--result", "--blocked", "--failed"):
            with self.subTest(kind=kind):
                task_id = self.started()
                self.caller = self.as_agent(self.IMPL)
                self.assertEqual(self.run_cli("report", task_id, kind, "--note", "x")[0], 0)
                self.caller = self.as_agent(self.LEAD)
                self.assert_rejected(task_id, "note_no_active_attempt")
        # 复核结论
        for kind in ("--approve", "--changes"):
            with self.subTest(kind=kind):
                self.caller = self.as_agent(self.LEAD)
                task_id = self.send("--review-by", "claude@review")
                self.mark_sent(task_id)
                self.caller = self.as_agent(self.IMPL)
                self.assertEqual(self.run_cli("report", task_id, "--result")[0], 0)
                self.mark_sent(task_id)
                self.caller = self.as_agent(self.REVIEW)
                self.assertEqual(self.run_cli("report", task_id, kind, "--note", "x")[0], 0)
                self.caller = self.as_agent(self.LEAD)
                self.assert_rejected(task_id, "note_no_active_attempt")
        # 已结束
        task_id = self.started()
        self.assertEqual(self.run_cli("close", task_id)[0], 0)
        self.assert_rejected(task_id, "note_no_active_attempt")
        # 暂停
        task_id = self.started()
        self.assertEqual(self.run_cli("pause", task_id)[0], 0)
        self.assert_rejected(task_id, "note_task_paused")
        # 找不到任务
        code, _out, err = self.run_cli("note", "f" * 32, "-m", "补充")
        self.assertEqual(code, 2, err)

    def test_capacity_is_work_class_and_keeps_the_notice_reserve(self) -> None:
        task_id = self.started()
        with self.store() as store:
            while len(store.attempts(task_id)) < 59:
                store.add_attempt(task_id, role=Role.NOTICE, target=self.LEAD.ref, body="容量夹具", refs=[], now=3.0,
                                  sender=None, sender_class=None)
        code, out, err = self.run_cli("note", task_id, "-m", "第 60 条", "--json")
        self.assertEqual(code, 0, err)
        document = json.loads(out)
        self.assertEqual((document["noted"], document["notes"]), ({"seq": 60, "forSeq": 1}, ["attempts_near_limit"]))
        code, _out, err = self.run_cli("note", task_id, "-m", "第 61 条")
        self.assertEqual(code, 3, err)
        self.assertIn("capacity_attempts", err)
        self.assertIn("close 旧任务", err)
        # 61–64 仍留给结果通知与结束回执
        self.caller = self.as_agent(self.IMPL)
        self.assertEqual(self.run_cli("report", task_id, "--result", "--note", "完成")[0], 0)
        with self.store() as store:
            notice = store.attempts(task_id)[-1]
        self.assertEqual((notice.seq, notice.role, notice.is_note), (61, Role.NOTICE, False))

    def test_near_limit_hint_in_text(self) -> None:
        task_id = self.started()
        with self.store() as store:
            while len(store.attempts(task_id)) < 47:
                store.add_attempt(task_id, role=Role.NOTICE, target=self.LEAD.ref, body="容量夹具", refs=[], now=3.0,
                                  sender=None, sender_class=None)
        code, out, _err = self.run_cli("note", task_id, "-m", "第 48 条")
        self.assertEqual(code, 0)
        self.assertIn("提示：接近交接上限", out)

    def test_note_seq_is_not_reportable_but_the_work_attempt_is(self) -> None:
        task_id = self.started()
        self.assertEqual(self.run_cli("note", task_id, "-m", "补充")[0], 0)
        self.caller = self.as_agent(self.IMPL)
        code, _out, err = self.run_cli("report", task_id, "--attempt", "2", "--ack")
        self.assertEqual(code, 3, err)
        self.assertIn("attempt_not_reportable", err)
        self.assertEqual(self.run_cli("report", task_id, "--ack")[0], 0)
        self.assertEqual(self.run_cli("report", task_id, "--attempt", "1", "--result", "--note", "完成")[0], 0)
        with self.store() as store:
            work = store.attempts(task_id)[0]
        self.assertEqual(work.work, Work.RESULT)

    def test_pending_note_is_cancelled_by_retry_accept_close_and_cancel(self) -> None:
        def with_pending_note() -> str:
            task_id = self.started()
            self.assertEqual(self.run_cli("note", task_id, "-m", "补充")[0], 0)
            return task_id

        task_id = with_pending_note()
        self.assertEqual(self.run_cli("retry", task_id, "--force")[0], 0)
        [note] = self.notes(task_id)
        self.assertEqual((note.delivery, note.delivery_reason), (Delivery.CANCELLED, "notice_outdated"))
        for command, reason in ((("accept", "--force"), "accepted"), (("close",), "closed"), (("cancel",), "cancelled")):
            with self.subTest(command=command):
                task_id = with_pending_note()
                self.assertEqual(self.run_cli(command[0], task_id, *command[1:])[0], 0)
                [note] = self.notes(task_id)
                self.assertEqual((note.delivery, note.delivery_reason), (Delivery.CANCELLED, reason))

    def test_closure_receipt_covers_only_work_attempts(self) -> None:
        task_id = self.started()
        self.assertEqual(self.run_cli("note", task_id, "-m", "补充")[0], 0)
        with self.store() as store:
            [note] = [item for item in store.attempts(task_id) if item.is_note]
            store.begin_send(note.id, now=3.0, pid=1, start_ticks="1")
            store.finish_send(note.id, delivery=Delivery.QUEUED, reason="codex_queued", provider_ref=None, detail={},
                              now=4.0)
        self.assertEqual(self.run_cli("accept", task_id, "--force")[0], 0)
        with self.store() as store:
            closures = [item for item in store.attempts(task_id) if item.is_closure]
        self.assertEqual(len(closures), 1)
        self.assertEqual(closures[0].target, self.IMPL.ref)

    def test_status_text_and_json_show_the_note(self) -> None:
        task_id = self.started()
        code, out, err = self.run_cli("note", task_id, "-m", "补充", "--json")
        self.assertEqual(code, 0, err)
        document = json.loads(out)
        self.assertEqual((document["ok"], document["scope"], document["command"], document["notes"]),
                         (True, "local", "note", []))
        self.assertEqual(document["id"], task_id)
        text = self.run_cli("status", task_id)[1]
        self.assertIn("  补充 #2 → codex@id:impl-thread（桥内排队）", text)
        self.assertIn("#1 交接 → codex@id:impl-thread", text)
        self.assertIn("排队补充消息", text)
        status = json.loads(self.run_cli("status", task_id, "--json")[1])
        note = status["attempts"][1]
        self.assertEqual((note["role"], note["noticeKind"], note["forSeq"]), ("notice", "note", 1))
        self.assertNotIn("noticeKind", status["attempts"][0])
        self.assertEqual(status["phase"], "running")

    def test_tasks_filter_by_target_is_unchanged(self) -> None:
        task_id = self.started()
        self.assertEqual(self.run_cli("note", task_id, "-m", "补充")[0], 0)
        # 执行方 --mine 按参与会话匹配（交接目标）；note 的目标就是工作目标，不多出、不少掉
        self.caller = self.as_agent(self.IMPL)
        code, out, err = self.run_cli("tasks", "--mine", "--json")
        self.assertEqual(code, 0, err)
        listed = json.loads(out)
        rows = listed["tasks"] if isinstance(listed, dict) else listed
        self.assertEqual([row["id"] for row in rows], [task_id])

    def test_summary_keys_and_next_are_unchanged_and_delivery_is_marked_note(self) -> None:
        from agentstatus_bridge import summary
        task_id = self.started()

        def document() -> dict[str, object]:
            return json.loads((self.state / summary.SUMMARY_NAME).read_text(encoding="utf-8"))  # type: ignore[attr-defined]

        self.run_cli("tasks")  # 先按当前账本刷新一次摘要（mark_sent 直接写库，不经命令）
        before = document()
        [entry_before] = [item for item in before["tasks"] if item["id"] == task_id]  # type: ignore[union-attr,index]
        self.assertEqual(self.run_cli("note", task_id, "-m", "补充")[0], 0)
        with self.store() as store:
            [note] = [item for item in store.attempts(task_id) if item.is_note]
            store.begin_send(note.id, now=3.0, pid=1, start_ticks="1")
            store.finish_send(note.id, delivery=Delivery.DELIVERED, reason="codex_steered", provider_ref=None,
                              detail={"deliveredPid": 1000, "deliveredStart": "100", "deliveredPane": "%1",
                                      "steerPath": "steered"}, now=4.0)
        self.run_cli("tasks")  # 任一命令前后补发摘要
        after = document()
        self.assertEqual(sorted(after), sorted(before))
        [entry_after] = [item for item in after["tasks"] if item["id"] == task_id]  # type: ignore[union-attr,index]
        self.assertEqual(sorted(entry_after), sorted(entry_before))
        for key in ("phase", "reason", "next", "current", "attention"):
            if key in entry_before:
                self.assertEqual(entry_after[key], entry_before[key], key)
        [delivery] = [item for item in after["deliveries"] if item["messageId"] == note.message_id]  # type: ignore[union-attr,index]
        # 补充消息标 kind=note：扩展据此静默它触发的那一轮（DESIGN §95.5.3）；kind 是可选开放字段，摘要仍合法
        self.assertEqual(delivery, {"messageId": note.message_id, "role": "notice", "pane": "%1", "provider": "codex",
                                    "kind": "note"})
        self.assertTrue(summary.is_valid(after))

    def test_worker_not_running_returns_6_after_recording(self) -> None:
        task_id = self.started()
        with patch.object(self.cli, "ensure_worker", side_effect=OSError("fixture startup failed")):
            code, out, _err = self.run_cli("note", task_id, "-m", "补充", "--json")
        self.assertEqual(code, self.cli.EXIT_UNAVAILABLE)
        self.assertEqual(json.loads(out)["notes"], ["worker_not_running"])
        self.assertEqual(len(self.notes(task_id)), 1)


@linux_fixture
class NoteDispatchTests(unittest.TestCase):
    """worker 投递：优先级、页脚、暂停/结束不发、回复关联（借用 DispatchTests 的账本与假通道）。"""

    def setUp(self) -> None:
        import test_bridge_dispatch as dispatch_tests
        self.base = dispatch_tests.DispatchTests
        self.base.setUp(self)  # type: ignore[arg-type]

    def tearDown(self) -> None:
        self.base.tearDown(self)  # type: ignore[arg-type]

    def _task(self, target, **kwargs):  # noqa: ANN001,ANN003,ANN202
        return self.base._task(self, target, **kwargs)  # type: ignore[arg-type]

    def _run(self) -> None:
        self.base._run(self)  # type: ignore[arg-type]

    def _attempt(self, attempt_id: str) -> Attempt:
        return self.base._attempt(self, attempt_id)  # type: ignore[arg-type]

    def _reply(self, text: str) -> dict[str, object]:
        return self.base._reply(self, text)  # type: ignore[arg-type]

    def add_note(self, task_id: str, target, for_seq: int = 1) -> Attempt:  # noqa: ANN001
        return self.store.add_attempt(task_id, role=Role.NOTICE, target=target, body="补充 Y", refs=[], now=self.now,
                                      sender=None, sender_class=None,
                                      options={NOTICE_KIND_OPTION: NOTE_KIND, FOR_SEQ_OPTION: for_seq},
                                      event="note_created")

    def test_claude_note_priority_follows_the_ack_and_note_footer(self) -> None:
        # 对方还没 --ack：note 与交接同为 later，原生队列先进先出排在交接后面；ack 之后的 note 用 next（G4 审计 r1 复核）
        from bridge_support import endpoint
        from agentstatus_bridge.model import Work
        target = ref(Provider.CLAUDE, "claude-session")
        self.endpoints = [endpoint(target, socket_path="/run/test/peer.sock")]
        task, work = self._task(target)
        self._run()
        note = self.add_note(task.id, target)
        self._run()
        self.store.set_work(work.id, work=Work.ACKNOWLEDGED, result=None, now=self.now, event="acknowledged")
        self.add_note(task.id, target)
        self._run()
        self.assertEqual([context.priority for _endpoint, _text, context in self.claude.calls], ["later", "later", "next"])
        _endpoint, text, context = self.claude.calls[1]
        self.assertEqual(context.sender_name, "AgentStatus 协作桥（用户）")
        self.assertIn(f"这是任务 {task.id} 第 1 次尝试的补充，不需要 testcmd report", text)
        self.assertEqual(self._attempt(note.id).delivery, Delivery.WRITTEN)

    def test_only_notes_carry_the_steer_signal(self) -> None:
        # turn/steer 只给补充消息：交接与其他 notice（结果通知、提醒、结束回执）本轮不改通道（§95.5.4）
        from bridge_support import endpoint
        from agentstatus_bridge.model import Consumption
        target = ref()
        self.endpoints = [endpoint(target)]
        self.queue_states["item-1"] = Consumption.LEFT_QUEUE  # 交接已离开 Codex 队列（同一轮末尾对账记下）
        task, _work = self._task(target)
        self._run()
        self.add_note(task.id, target)
        self.store.add_attempt(task.id, role=Role.NOTICE, target=target, body="结果通知", refs=[], now=self.now,
                               sender=None, sender_class=None)
        self._run()
        signals = [(context.priority, context.steer) for _endpoint, _text, context in self.codex.calls]
        self.assertEqual(signals, [("later", False), ("next", True), ("next", False)])

    def test_note_for_a_handoff_still_in_the_codex_queue_is_not_steered(self) -> None:
        # G4 审计 r1 P3-1：交接还排在队列里时 note 走队列（先进先出排在交接后），已确认开始或离开队列后才 steer
        from bridge_support import endpoint
        from agentstatus_bridge.model import Consumption, Work
        target = ref()
        self.endpoints = [endpoint(target)]
        self.queue_states["item-1"] = Consumption.STILL_QUEUED
        task, work = self._task(target)
        self._run()
        self.assertIs(self._attempt(work.id).consumption, Consumption.STILL_QUEUED)
        self.add_note(task.id, target)
        self._run()
        self.store.set_work(work.id, work=Work.ACKNOWLEDGED, result=None, now=self.now, event="acknowledged")
        self.add_note(task.id, target)
        self._run()
        signals = [(context.priority, context.steer) for _endpoint, _text, context in self.codex.calls]
        self.assertEqual(signals, [("later", False), ("later", False), ("next", True)])

    def test_note_work_is_found_by_for_seq_after_a_retry(self) -> None:
        # retry 之后 note 补的是第 3 次尝试、第 1 次已终态：_note_work 按 forSeq 取第 3 次，note 照发不被当成过期
        # （Fable R1-4）；优先级与 steer 也按第 3 次（未确认）判
        from bridge_support import endpoint
        from agentstatus_bridge.model import Work
        target = ref()
        self.endpoints = [endpoint(target)]
        task, work = self._task(target)
        self._run()
        self.store.set_work(work.id, work=Work.FAILED, result=None, now=self.now, event="failed")
        self.store.add_attempt(task.id, role=Role.NOTICE, target=target, body="结果通知", refs=[], now=self.now,
                               sender=None, sender_class=None)
        retried = self.store.add_attempt(task.id, role=Role.HANDOFF, target=target, body="返工", refs=[],
                                         now=self.now, sender=None, sender_class=None)
        self.assertEqual(retried.seq, 3)
        note = self.add_note(task.id, target, for_seq=3)
        self._run()
        self.assertIs(self._attempt(note.id).delivery, Delivery.QUEUED)
        [(_endpoint, _text, context)] = [call for call in self.codex.calls if "补充 Y" in call[1]]
        self.assertEqual((context.priority, context.steer), ("later", False))

    def test_steered_note_is_not_withdrawable_watched_or_resident(self) -> None:
        # (b)#1/#3/#5：steered note 记 DELIVERED、无队列项：不进撤回、不进消费对账、worker 不为它驻留
        from bridge_support import endpoint
        from agentstatus_bridge.dispatch import needs_worker
        from agentstatus_bridge.model import Consumption
        from agentstatus_bridge.store import StoreError
        from agentstatus_bridge.transports import DeliveryOutcome
        target = ref(Provider.CODEX, "019a0000-1111-7222-8333-444455556666")
        self.endpoints = [endpoint(target)]

        def outcome(_endpoint, _text, context):  # noqa: ANN001,ANN202
            if context.steer:
                return DeliveryOutcome(Delivery.DELIVERED, "codex_steered", None, {"steerPath": "steered"})
            return DeliveryOutcome(Delivery.QUEUED, "codex_queued", provider_ref="019a9999-aaaa-7bbb-8ccc-ddddeeeeffff")

        self.codex._outcome = outcome
        queried: list[str] = []
        self.dispatcher.queue_state = lambda item: (queried.append(item), Consumption.LEFT_QUEUE)[1]
        task, work = self._task(target)
        self._run()
        note = self.add_note(task.id, target)
        self._run()
        recorded = self._attempt(note.id)
        self.assertEqual((recorded.delivery, recorded.delivery_reason, recorded.provider_ref),
                         (Delivery.DELIVERED, "codex_steered", None))
        self.assertEqual(recorded.delivery_detail["steerPath"], "steered")
        self.assertEqual(queried, ["019a9999-aaaa-7bbb-8ccc-ddddeeeeffff"])  # 只问工作尝试的队列项
        self.assertEqual(self._attempt(work.id).consumption, Consumption.LEFT_QUEUE)
        self.assertFalse(needs_worker(self.store, self.now))
        self.assertFalse(self.dispatcher.has_live_work())
        for seq in (note.seq,):
            with self.assertRaises(StoreError) as caught:
                self.store.prepare_withdrawal(task.id, seq, root_identity="a" * 64, now=self.now, pid=1, start="1")
            self.assertEqual(caught.exception.code, "withdraw_ineligible")

    def test_queued_note_is_not_withdrawable(self) -> None:
        from bridge_support import endpoint
        from agentstatus_bridge.store import StoreError
        target = ref(Provider.CODEX, "019a0000-1111-7222-8333-444455556666")
        self.endpoints = [endpoint(target)]
        task, _work = self._task(target)
        self._run()
        note = self.add_note(task.id, target)
        self.store.begin_send(note.id, now=self.now, pid=1, start_ticks="1")
        self.store.finish_send(note.id, delivery=Delivery.QUEUED, reason="codex_queued",
                               provider_ref="019a9999-aaaa-7bbb-8ccc-ddddeeeeffff", detail={}, now=self.now,
                               native_root="a" * 64)
        with self.assertRaises(StoreError) as caught:
            self.store.prepare_withdrawal(task.id, note.seq, root_identity="a" * 64, now=self.now, pid=1, start="1")
        self.assertEqual(caught.exception.code, "withdraw_ineligible")

    def test_pending_note_after_a_terminal_report_is_cancelled_as_outdated(self) -> None:
        # G4 审计 r1 P3-4/F-3：所补的那次尝试已交结果/受阻/失败，尚未发出的 note 不再发，记 note_outdated
        from bridge_support import endpoint
        from agentstatus_bridge.labels import reason_text
        from agentstatus_bridge.model import Work
        target = ref()
        self.endpoints = [endpoint(target)]
        for terminal in (Work.RESULT, Work.BLOCKED, Work.FAILED):
            with self.subTest(work=terminal):
                task, work = self._task(target)
                self._run()
                note = self.add_note(task.id, target)
                self.store.set_work(work.id, work=terminal, result=None, now=self.now, event="reported")
                calls = len(self.codex.calls)
                self._run()
                self.assertEqual(len(self.codex.calls), calls)
                recorded = self._attempt(note.id)
                self.assertEqual((recorded.delivery, recorded.delivery_reason), (Delivery.CANCELLED, "note_outdated"))
        self.assertNotEqual(reason_text("note_outdated"), "note_outdated")
        # 反例：只确认开始（未终态）照常发
        task, work = self._task(target)
        self._run()
        self.store.set_work(work.id, work=Work.IN_PROGRESS, result=None, now=self.now, event="progress")
        note = self.add_note(task.id, target)
        self._run()
        self.assertIsNot(self._attempt(note.id).delivery, Delivery.CANCELLED)

    def test_note_is_not_sent_when_task_is_paused_or_finished(self) -> None:
        from bridge_support import endpoint
        target = ref()
        self.endpoints = [endpoint(target)]
        for change in ({"control": "paused"}, {"closed_at": 5.0}):
            with self.subTest(change=change):
                task, _work = self._task(target)
                self._run()
                note = self.add_note(task.id, target)
                self.store.update_task(task.id, now=self.now, event="test", **change)
                calls = len(self.codex.calls)
                self._run()
                self.assertEqual(len(self.codex.calls), calls)
                self.assertEqual(self._attempt(note.id).delivery, Delivery.PENDING)

    def test_reply_without_ids_still_goes_to_the_work_attempt(self) -> None:
        from bridge_support import endpoint
        target = ref(Provider.CLAUDE, "claude-session")
        self.endpoints = [endpoint(target, socket_path="/run/test/peer.sock")]
        task, work = self._task(target)
        self._run()
        self.add_note(task.id, target)
        self._run()  # note 也写入（WRITTEN），两条都在途
        resolved = self.dispatcher.resolve_reply("uds:/run/test/peer.sock", "收到")
        assert resolved is not None
        self.assertEqual((resolved.association, resolved.attempt.id), ("only_candidate", work.id))
        self.assertEqual(self.dispatcher.handle_frame(self._reply("收到")), "reply")
        self.assertEqual(self._attempt(work.id).delivery, Delivery.DELIVERED)


class NoteCheckpointTests(unittest.TestCase):
    """跨设备线格式（两种系统都跑）：新读方认得 note 定义；写方不把 note 写进定义（旧读方闭合枚举）。"""

    def test_new_reader_accepts_a_note_definition(self) -> None:
        from agentstatus_bridge.federation.refs import AttemptDefinition
        target = {"deviceId": "b" * 32, "provider": "codex", "nativeId": "019a0000-1111-7222-8333-44445555bbbb",
                  "endpointId": "e" * 32, "endpointRevision": 1}
        definition = AttemptDefinition.from_dict({"seq": 2, "msgId": "1" * 32, "role": "notice", "target": target,
                                                  "noticeKind": "note"})
        self.assertEqual(definition.notice_kind, "note")



class NoteFederationTests(federation_cli.FedCliCase):
    """跨设备 note（§95.5.5）：权威端建尝试，notice 信封送到目标设备投递；取消、返工与结束随 checkpoint 抑制。"""

    def evidence_back(self, task_id: str) -> None:
        self.pump("win", "vm")
        code, out, err = self.run_on("vm", "status", task_id, "--json")
        self.assertEqual(code, 0, err)
        self.assertEqual(json.loads(out)["attempts"][0]["delivery"], "queued")

    def noted(self) -> str:
        task_id = self.delivered_task()
        self.evidence_back(task_id)
        code, out, err = self.run_on("vm", "note", task_id, "-m", "补充：顺便检查 Y",
                                     caller=federation_cli.as_agent(federation_cli.ORIGIN))
        self.assertEqual(code, 0, err)
        self.assertIn(f"已排队补充 #2 → win 上的 codex@impl target=--device win --to codex@id:{federation_cli.THREAD_B}"
                      f"（跨设备任务 {task_id[:8]} 第 1 次尝试；对方不需要汇报这条）", out)
        return task_id

    def note_envelopes(self) -> list[dict[str, object]]:
        with self.store("vm") as store:
            return [json.loads(item["envelope_json"]) for item in store.outbox()
                    if json.loads(item["envelope_json"])["kind"] == "notice"]

    def test_round_trip_footer_steer_signal_and_wire_shape(self) -> None:
        task_id = self.noted()
        [envelope] = self.note_envelopes()
        data = envelope["data"]
        assert isinstance(data, dict)
        self.assertEqual(data["options"], {"noticeKind": "note", "forSeq": 1, "allowShared": False})
        definitions = data["checkpoint"]["attempts"]
        # 旧读方（9a2ac62）的闭合枚举不认 note：定义里不写 noticeKind
        self.assertEqual([item.get("noticeKind") for item in definitions], [None, None])
        self.assertEqual([item["role"] for item in definitions], ["handoff", "notice"])
        self.assertEqual(envelope["attempt"], 2)
        self.pump("vm", "win")
        calls = self.deliver_on_b().calls
        self.assertEqual(len(calls), 1)
        _endpoint, text, context = calls[0]
        # 执行方还没确认开始：联邦作业不追踪队列消费，按交接可能还排在队列里处理，走队列（G4 审计 r1 P3-1）；
        # 优先级同一判据，用交接那一档 later
        self.assertFalse(context.steer)
        self.assertEqual(context.priority, "later")
        self.assertIn("补充：顺便检查 Y", text)
        self.assertIn(f"`ab report {task_id} --origin-device vm --attempt 1 …`", text)
        self.pump("win", "vm")
        code, out, err = self.run_on("vm", "status", task_id, "--json")
        self.assertEqual(code, 0, err)
        row = json.loads(out)["attempts"][1]
        self.assertEqual((row["role"], row["noticeKind"], row["forSeq"], row["delivery"]), ("notice", "note", 1, "queued"))
        text = self.run_on("vm", "status", task_id)[1]
        self.assertIn("补充 #2 → win codex@id:", text)
        # 汇报：note 序号不可汇报，工作尝试照常
        code, _out, err = self.run_on("win", "report", task_id, "--origin-device", "vm", "--attempt", "2", "--ack",
                                      caller=federation_cli.as_agent(federation_cli.WORKER))
        self.assertEqual(code, 3, err)
        self.assertIn("attempt_not_reportable", err)
        code, _out, err = self.run_on("win", "report", task_id, "--origin-device", "vm", "--ack",
                                      caller=federation_cli.as_agent(federation_cli.WORKER))
        self.assertEqual(code, 0, err)

    def test_authority_ledger_keeps_the_kind_where_an_old_build_checkpoint_does_not_look(self) -> None:
        # G4 审计 r1 P3-2 回滚加固：A 本机账本把 note 类别记在 localNoticeKind；旧代码的 build_checkpoint 只读
        # options.noticeKind，回滚后写出的定义与新代码逐字相同；线上信封照旧带 noticeKind
        from agentstatus_bridge.federation import authority
        task_id = self.noted()
        with self.store("vm") as store:
            [task] = store.find_tasks(task_id)
            attempts = store.attempts(federation_cli.DEV_A, task_id)
        [note] = [item for item in attempts if item.is_note]
        self.assertNotIn("noticeKind", note.options)
        self.assertEqual((note.options["localNoticeKind"], note.notice_kind), ("note", "note"))
        old_style = [item.options.get("noticeKind") if item.role == "notice" else None for item in attempts]
        new = [item.notice_kind for item in authority.build_checkpoint(task, attempts).attempts]
        self.assertEqual(old_style, new)
        self.assertEqual(new, [None, None])
        [envelope] = self.note_envelopes()
        self.assertEqual(envelope["data"]["options"]["noticeKind"], "note")  # type: ignore[index]
        self.assertNotIn("localNoticeKind", envelope["data"]["options"])  # type: ignore[operator]
        # 纵深防御：账本里即使是加固前的形状（options.noticeKind=note），build_checkpoint 也不写进定义
        from dataclasses import replace
        legacy = [replace(item, options={**{k: v for k, v in item.options.items() if k != "localNoticeKind"},
                                         "noticeKind": "note"}) if item.is_note else item for item in attempts]
        self.assertEqual([item.notice_kind for item in authority.build_checkpoint(task, legacy).attempts], [None, None])

    def test_federated_note_capacity_is_work_class(self) -> None:
        # 回滚加固后类别记在 localNoticeKind，容量仍按工作类 60（不占 61–64 预留）；结束回执照样排得进
        from dataclasses import replace
        from agentstatus_bridge.federation import authority
        from agentstatus_bridge.store import StoreError
        task_id = self.noted()
        with self.store("vm") as store:
            [task] = store.find_tasks(task_id)
            store.update_task(replace(task, max_seq=59))
        code, _out, err = self.run_on("vm", "note", task_id, "-m", "第 60 条",
                                      caller=federation_cli.as_agent(federation_cli.ORIGIN))
        self.assertEqual(code, 0, err)
        code, _out, err = self.run_on("vm", "note", task_id, "-m", "第 61 条",
                                      caller=federation_cli.as_agent(federation_cli.ORIGIN))
        self.assertNotEqual(code, 0, err)
        self.assertIn("capacity_attempts", err)
        with self.store("vm") as store:
            [task] = store.find_tasks(task_id)
            self.assertEqual(task.max_seq, 60)
            with self.assertRaises(StoreError) as caught:
                authority.add_note(store, self.ident("vm"), task, body="x", sender=None, sender_class="bypass",
                                   now=task.last_sync_at + 1)
            self.assertEqual(caught.exception.code, "capacity_attempts")
        code, _out, err = self.run_on("vm", "close", task_id, caller=federation_cli.as_agent(federation_cli.ORIGIN))
        self.assertEqual(code, 0, err)
        with self.store("vm") as store:
            closures = [item for item in store.attempts(federation_cli.DEV_A, task_id) if item.is_closure]
        self.assertEqual([item.seq for item in closures], [61])

    def test_authority_views_map_the_local_kind_key(self) -> None:
        # 权威端账本把类别记在 localNoticeKind：视图映射回 noticeKind，发起方提醒按 note 口径（不挡、不重置）
        from dataclasses import replace
        from agentstatus_bridge.federation.views import model_attempts
        task_id = self.noted()
        with self.store("vm") as store:
            [task] = store.find_tasks(task_id)
            stored = store.attempts(task.authority_device, task.task_id)
        [raw] = [item for item in stored if item.seq == 2]
        self.assertNotIn("noticeKind", raw.options)
        [note] = [item for item in model_attempts(stored) if item.seq == 2]
        self.assertTrue(note.is_note)
        self.assertEqual(note.note_for_seq, 1)
        reminder = pending_reminder(make_task(), [make_attempt(1, delivery=Delivery.UNKNOWN, delivery_at=100.0),
                                                  replace(note, created_at=200.0)])
        assert reminder is not None
        self.assertEqual(reminder.due_at, 100.0 + REMIND_AFTER_SECONDS)

    def test_steered_evidence_reaches_the_authority_and_closure_covers_only_work(self) -> None:
        from agentstatus_bridge.federation.delivery import FederationDispatcher
        from agentstatus_bridge.federation.relay import RelayPaths
        from agentstatus_bridge.transports import DeliveryOutcome
        from bridge_support import RecordingTransport
        task_id = self.noted()
        self.pump("vm", "win")
        # 镜像上执行方先确认开始：本设备自己交过的汇报即可（还没回到 A 也算），note 才给 steer 信号
        code, _out, err = self.run_on("win", "report", task_id, "--origin-device", "vm", "--ack",
                                      caller=federation_cli.as_agent(federation_cli.WORKER))
        self.assertEqual(code, 0, err)
        transport = RecordingTransport(Provider.CODEX, lambda _e, _t, context: DeliveryOutcome(
            Delivery.DELIVERED, "codex_steered", None, {"steerPath": "steered"}) if context.steer else
            DeliveryOutcome(Delivery.QUEUED, "codex_queued", provider_ref="i"))
        with self.store("win") as store:
            FederationDispatcher(store, self.ident("win"), RelayPaths(self.states["win"]),
                                 discover=lambda: [federation_cli.WORKER], transports={Provider.CODEX: transport},
                                 reply_address=None, command="ab").run_once()
            deliveries = [item for _at, item in store.recent_deliveries()]
        self.assertEqual(len(transport.calls), 1)
        self.assertEqual([(context.priority, context.steer) for _e, _t, context in transport.calls], [("next", True)])
        # B 的摘要投递项给补充消息标 kind=note（与本机同口径，DESIGN §95.5.3）
        [published] = [item for item in deliveries if item["role"] == "notice"]
        self.assertEqual(published.get("kind"), "note")
        self.pump("win", "vm")
        code, out, err = self.run_on("vm", "status", task_id, "--json")
        self.assertEqual(code, 0, err)
        rows = json.loads(out)["attempts"]
        self.assertEqual((rows[1]["noticeKind"], rows[1]["delivery"]), ("note", "delivered"))
        self.assertEqual(rows[0]["delivery"], "queued")
        # 结束回执的 coversWorkMessageIds 只含工作尝试，不含 note
        code, _out, err = self.run_on("vm", "close", task_id, caller=federation_cli.as_agent(federation_cli.ORIGIN))
        self.assertEqual(code, 0, err)
        with self.store("vm") as store:
            attempts = store.attempts(federation_cli.DEV_A, task_id)
        work = attempts[0]
        [closure] = [item for item in attempts if item.is_closure]
        self.assertEqual(closure.options.get("coversWorkMessageIds"), [work.msg_id])

    def test_summary_kind_reads_the_authority_local_key(self) -> None:
        # 联邦任务的 note/fyi 目标在 A 本机时（如 retry --to 本机会话），A 账本里类别记在 localNoticeKind：
        # 联邦摘要的投递项照样标 kind（Opus N9 / Fable R10）。用 B 上真实投递出的一行改写成 A 账本形状来核对读方
        from agentstatus_bridge.federation.delivery import FederationDispatcher
        from agentstatus_bridge.federation.relay import RelayPaths
        from agentstatus_bridge.transports import DeliveryOutcome
        from bridge_support import RecordingTransport
        task_id = self.noted()
        self.pump("vm", "win")
        transport = RecordingTransport(Provider.CODEX, lambda _e, _t, _c: DeliveryOutcome(
            Delivery.QUEUED, "codex_queued", provider_ref="i"))
        with self.store("win") as store:
            FederationDispatcher(store, self.ident("win"), RelayPaths(self.states["win"]),
                                 discover=lambda: [federation_cli.WORKER], transports={Provider.CODEX: transport},
                                 reply_address=None, command="ab").run_once()
            [note] = [item for item in store.attempts(federation_cli.DEV_A, task_id) if item.is_note]
            self.assertEqual(note.options.get("noticeKind"), "note")  # 镜像上是线上键
            for options in ({"localNoticeKind": "note", "forSeq": 1, "allowShared": False},
                            {"localNoticeKind": "fyi", "allowShared": False}):
                with self.subTest(kind=options["localNoticeKind"]):
                    with store.transaction() as conn:
                        conn.execute("UPDATE fed_attempts SET options_json=? WHERE msg_id=?",
                                     (json.dumps(options), note.msg_id))
                    [published] = [item for _at, item in store.recent_deliveries() if item["messageId"] == note.msg_id]
                    self.assertEqual(published.get("kind"), options["localNoticeKind"])

    def test_note_on_the_mirror_after_a_terminal_report_is_outdated(self) -> None:
        # 镜像侧同等判据（G4 审计 r1 P3-4/F-3）：执行方在镜像上交了 --result（还没回到 A 也算），未发出的 note 抑制
        task_id = self.noted()
        self.pump("vm", "win")
        code, _out, err = self.run_on("win", "report", task_id, "--origin-device", "vm", "--result",
                                      caller=federation_cli.as_agent(federation_cli.WORKER))
        self.assertEqual(code, 0, err)
        self.assertEqual(self.deliver_on_b().calls, [])
        with self.store("win") as store:
            [note] = [item for item in store.attempts(federation_cli.DEV_A, task_id) if item.is_note]
        self.assertEqual((note.delivery.get("state"), note.delivery.get("reason")), ("cancelled", "note_outdated"))
        self.pump("win", "vm")
        code, out, err = self.run_on("vm", "status", task_id, "--json")
        self.assertEqual(code, 0, err)
        self.assertEqual(json.loads(out)["attempts"][1]["delivery"], "cancelled")

    def test_rejections_before_evidence_paused_and_on_the_mirror(self) -> None:
        origin = federation_cli.as_agent(federation_cli.ORIGIN)
        task_id = self.send()
        code, _out, err = self.run_on("vm", "note", task_id, "-m", "x", caller=origin)
        self.assertEqual(code, 3, err)
        self.assertIn("note_no_active_attempt", err)  # A 还没收到投递证据：不算已发出
        self.pump("vm", "win")
        self.deliver_on_b()
        self.evidence_back(task_id)
        code, _out, err = self.run_on("win", "note", task_id, "--origin-device", "vm", "-m", "x",
                                      caller=federation_cli.as_agent(federation_cli.WORKER))
        self.assertEqual(code, 3, err)
        self.assertIn("note_not_authority", err)
        self.assertEqual(self.run_on("vm", "pause", task_id, caller=origin)[0], 0)
        code, _out, err = self.run_on("vm", "note", task_id, "-m", "x", caller=origin)
        self.assertEqual(code, 3, err)
        self.assertIn("note_task_paused", err)
        self.assertEqual(self.note_envelopes(), [])

    def test_cancel_suppresses_a_remote_pending_note(self) -> None:
        task_id = self.noted()
        self.pump("vm", "win")  # note 已到 B，尚未投递
        code, out, err = self.run_on("vm", "cancel", task_id, caller=federation_cli.as_agent(federation_cli.ORIGIN))
        self.assertEqual(code, 0, err)
        self.assertIn("对方设备尚未确认", out)
        self.pump("vm", "win")
        self.assertEqual(self.deliver_on_b().calls, [])
        self.pump("win", "vm")
        code, out, _err = self.run_on("vm", "status", task_id, "--json")
        self.assertEqual(json.loads(out)["attempts"][1]["delivery"], "cancelled")

    # ---- G4 审计 r1 P3-5：变异存活暴露的用例缺口 ----

    def local_noted(self) -> str:
        """联邦任务、执行方在 A 本机（远端复核）：A 的分发器投递交接后补一条 note，note 目标也在 A 本机。"""
        from agentstatus_bridge.federation.delivery import FederationDispatcher
        from agentstatus_bridge.federation.relay import RelayPaths
        from bridge_support import RecordingTransport
        code, out, err = self.run_on("vm", "send", "--to", "codex@review", "--review-by",
                                     f"codex@id:{federation_cli.THREAD_B}", "--review-device", "win", "-m", "实现 Z",
                                     "--json", caller=federation_cli.as_agent(federation_cli.ORIGIN))
        self.assertEqual(code, 0, err)
        task_id = json.loads(out)["id"]
        self.local_transport = RecordingTransport(Provider.CODEX)
        self.run_local_dispatcher()
        headers = [federation_cli.parse_header(text) for _e, text, _c in self.local_transport.calls]
        self.assertIn((task_id, "handoff"), [(h.task_id, h.role.value) for h in headers if h is not None])
        code, _out, err = self.run_on("vm", "note", task_id, "-m", "补一句",
                                      caller=federation_cli.as_agent(federation_cli.ORIGIN))
        self.assertEqual(code, 0, err)
        return task_id

    def run_local_dispatcher(self) -> None:
        from agentstatus_bridge.federation.delivery import FederationDispatcher
        from agentstatus_bridge.federation.relay import RelayPaths
        with self.store("vm") as store:
            FederationDispatcher(store, self.ident("vm"), RelayPaths(self.states["vm"]),
                                 discover=lambda: [federation_cli.LOCAL_REVIEW],
                                 transports={Provider.CODEX: self.local_transport},
                                 reply_address=None, command="ab").run_once()

    def local_note(self, task_id: str):  # noqa: ANN201
        with self.store("vm") as store:
            [note] = [item for item in store.attempts(federation_cli.DEV_A, task_id) if item.is_note]
            native = store.native(note.msg_id)
        return note, native

    def test_retry_suppresses_a_local_target_note_on_the_authority(self) -> None:
        # Fable M17：本机目标的 PENDING note 由 retry 的 _suppress_local 抑制；notice 不受 current_work_seq 约束、
        # 也没有 superseded，缺了这一步旧 note 会照投
        task_id = self.local_noted()
        note, native = self.local_note(task_id)
        self.assertEqual((note.target_device, native["state"]), (federation_cli.DEV_A, "prepared"))
        code, _out, err = self.run_on("vm", "retry", task_id, "--force",
                                      caller=federation_cli.as_agent(federation_cli.ORIGIN))
        self.assertEqual(code, 0, err)
        note, native = self.local_note(task_id)
        self.assertEqual((native["state"], note.delivery.get("state")), ("suppressed", "cancelled"))
        self.run_local_dispatcher()
        headers = [federation_cli.parse_header(text) for _e, text, _c in self.local_transport.calls]
        self.assertEqual([(h.attempt, h.role.value) for h in headers if h is not None], [(1, "handoff"), (3, "handoff")])

    def test_close_suppresses_a_local_target_note_before_the_dispatcher_runs(self) -> None:
        # Fable M16 / Opus O13：close/finish 当场抑制本机目标 note（不靠分发器领取时按 task_finished 的第二道防线）
        for decision in ("close", "accept"):
            with self.subTest(decision=decision):
                task_id = self.local_noted()
                extra = ("--force",) if decision == "accept" else ()
                code, _out, err = self.run_on("vm", decision, task_id, *extra,
                                              caller=federation_cli.as_agent(federation_cli.ORIGIN))
                self.assertEqual(code, 0, err)
                note, native = self.local_note(task_id)
                self.assertEqual((native["state"], note.delivery.get("state")), ("suppressed", "cancelled"))

    def test_note_on_the_authority_requires_an_open_work_state(self) -> None:
        # Fable M23：联邦 add_note 也看工作状态，执行方已交结果（回到 A）时报 note_no_active_attempt
        task_id = self.delivered_task()
        self.evidence_back(task_id)
        code, _out, err = self.run_on("win", "report", task_id, "--origin-device", "vm", "--result",
                                      caller=federation_cli.as_agent(federation_cli.WORKER))
        self.assertEqual(code, 0, err)
        self.pump("win", "vm")
        code, _out, err = self.run_on("vm", "note", task_id, "-m", "x",
                                      caller=federation_cli.as_agent(federation_cli.ORIGIN))
        self.assertEqual(code, 3, err)
        self.assertIn("note_no_active_attempt", err)
        self.assertEqual(self.note_envelopes(), [])

    def test_delivered_remote_note_is_not_marked_by_cancel_or_retry(self) -> None:
        # G4 审计 r1 P3-7：B 已回报交出的远端 note 撤不回，cancel 不标 cancelRequested、retry 不标 superseded
        task_id = self.noted()
        self.pump("vm", "win")
        self.assertEqual(len(self.deliver_on_b().calls), 1)  # note 交出（队列）
        self.pump("win", "vm")
        with self.store("vm") as store:
            [note] = [item for item in store.attempts(federation_cli.DEV_A, task_id) if item.is_note]
        self.assertEqual(note.delivery.get("state"), "queued")
        code, _out, err = self.run_on("vm", "cancel", task_id, caller=federation_cli.as_agent(federation_cli.ORIGIN))
        self.assertEqual(code, 0, err)
        code, _out, err = self.run_on("vm", "retry", task_id, "--force",
                                      caller=federation_cli.as_agent(federation_cli.ORIGIN))
        self.assertEqual(code, 0, err)
        with self.store("vm") as store:
            [note] = [item for item in store.attempts(federation_cli.DEV_A, task_id) if item.is_note]
            handoff = store.attempts(federation_cli.DEV_A, task_id)[0]
        self.assertEqual((note.cancel_requested, note.superseded), (False, False))
        self.assertTrue(handoff.cancel_requested)  # 工作尝试照旧发抑制请求（行为不变）

    def test_retry_supersedes_a_remote_pending_note(self) -> None:
        task_id = self.noted()
        self.pump("vm", "win")
        code, _out, err = self.run_on("vm", "retry", task_id, "--force",
                                      caller=federation_cli.as_agent(federation_cli.ORIGIN))
        self.assertEqual(code, 0, err)
        self.pump("vm", "win")
        calls = self.deliver_on_b().calls
        self.assertEqual(len(calls), 1)
        header = federation_cli.parse_header(calls[0][1])
        assert header is not None
        self.assertEqual((header.attempt, header.role.value), (3, "handoff"))
        with self.store("win") as store:
            [note] = [item for item in store.attempts(federation_cli.DEV_A, task_id) if item.is_note]
            self.assertTrue(note.superseded)
            self.assertEqual(store.native(note.msg_id)["state"], "suppressed")

    def test_close_suppresses_a_remote_pending_note(self) -> None:
        task_id = self.noted()
        self.pump("vm", "win")
        code, _out, err = self.run_on("vm", "close", task_id, caller=federation_cli.as_agent(federation_cli.ORIGIN))
        self.assertEqual(code, 0, err)
        self.pump("vm", "win")
        calls = self.deliver_on_b().calls
        self.assertFalse(any("补充消息" in text for _endpoint, text, _context in calls))
        with self.store("win") as store:
            [note] = [item for item in store.attempts(federation_cli.DEV_A, task_id) if item.is_note]
            self.assertEqual(store.native(note.msg_id)["state"], "suppressed")


class WindowsNoteCliTests(unittest.TestCase):
    """Windows 整条 CLI 路径（假 Win32 内核）：轻量调用方证明、落账、不初始化 daemon（两种系统都跑）。"""

    import test_bridge_windows_delivery as _wd  # 模块属性，不让加载器把对方的用例类重复收集
    setUp = _wd.DeliveryTests.setUp
    rebuild = _wd.DeliveryTests.rebuild
    scope = _wd.DeliveryTests.scope
    sql = _wd.DeliveryTests.sql
    run_cli = _wd.DeliveryTests.run_cli
    chain = _wd.DeliveryTests.chain
    del _wd

    def test_note_records_with_light_proof_and_no_initialize(self) -> None:
        from agentstatus_bridge import cli
        from agentstatus_bridge.dispatch import Dispatcher
        from agentstatus_bridge.platforms.windows import codex_consumption, codex_delivery, codex_discovery
        from agentstatus_bridge.store import Store
        from test_bridge_windows_discovery import uuid
        env = self.chain()  # type: ignore[attr-defined]
        self.k.loaded = [uuid(1), uuid(2)]  # type: ignore[attr-defined]
        with (self.scope(), patch.dict(os.environ, env),  # type: ignore[attr-defined]
              patch("agentstatus_bridge.platforms.windows.caller.os.getpid", return_value=100),
              patch.object(cli, "_start_worker", return_value=False), patch.object(cli, "_worker_up", return_value=False),
              patch.object(cli, "_revive_worker")):
            code, out, err = self.run_cli("send", "--to", uuid(2), "-m", "任务", "--no-wait", "--json")  # type: ignore[attr-defined]
            self.assertEqual(code, 6, (out, err))
            with Store.open(self.state) as store:  # type: ignore[attr-defined]
                [task] = store.list_tasks()
                result = codex_discovery.discover(self.p.transport)  # type: ignore[attr-defined]
                target = result.endpoint(result.select(uuid(2)))
                Dispatcher(store, lambda: [target], {Provider.CODEX: codex_delivery.CodexTransport()},
                           attempt_queue_state=codex_consumption.state).run_once()
            self.k.messages.clear()  # type: ignore[attr-defined]
            code, out, err = self.run_cli("note", task.id, "-m", "补充", "--json")  # type: ignore[attr-defined]
            self.assertEqual(code, 0, (out, err))  # _start_worker 返回 False=已有 worker，不算启动失败
            document = json.loads(out)
            self.assertEqual((document["noted"], document["notes"]), ({"seq": 2, "forSeq": 1}, []))
            self.assertFalse(any(m["method"] == "initialize" for m in self.k.messages))  # type: ignore[attr-defined]
            with Store.open(self.state) as store:  # type: ignore[attr-defined]
                [note] = [item for item in store.attempts(task.id) if item.is_note]
            self.assertEqual(note.target, target.ref)
            self.assertEqual(note.sender.native_id if note.sender else None, uuid(1))
            self.assertIs(note.delivery, Delivery.PENDING)
            # Windows 投递端同一判据（G4 审计 r1 P3-1）：交接未离开队列、对方未确认时不给 steer 信号；确认后才给
            from agentstatus_bridge.model import Consumption, Work
            transport = codex_delivery.CodexTransport()
            seen: list[bool] = []
            real = transport.deliver

            def deliver(endpoint, text, context):  # noqa: ANN001,ANN202
                seen.append(context.steer)
                return real(endpoint, text, context)

            transport.deliver = deliver  # type: ignore[method-assign]
            with Store.open(self.state) as store:  # type: ignore[attr-defined]
                Dispatcher(store, lambda: [target], {Provider.CODEX: transport},
                           attempt_queue_state=codex_consumption.state).run_once()
                [work] = [item for item in store.attempts(task.id) if item.seq == 1]
                self.assertIsNot(work.consumption, Consumption.LEFT_QUEUE)
                store.set_work(work.id, work=Work.ACKNOWLEDGED, result=None, now=2000, event="acknowledged")
            code, out, err = self.run_cli("note", task.id, "-m", "再补", "--json")  # type: ignore[attr-defined]
            self.assertEqual(code, 0, (out, err))
            with Store.open(self.state) as store:  # type: ignore[attr-defined]
                Dispatcher(store, lambda: [target], {Provider.CODEX: transport},
                           attempt_queue_state=codex_consumption.state).run_once()
            self.assertEqual(seen, [False, True])


if __name__ == "__main__":
    unittest.main()
