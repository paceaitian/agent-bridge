"""桥生成的可照抄命令不含 shell 元字符（DESIGN §104.11 第 1 条）。

覆盖 next_step（各阶段、容量满两种）、提醒正文（主提醒、沉默提醒、补充未送达）、催促正文与 `ab todo`：
- 每条命令不含 shell 元字符（引号除外：占位写成带引号的中文），经 shlex.split 后能被真实解析器接受；
- 全部文字里不出现 ASCII 的 `|`、`<`、`>`（管道与重定向，照抄会真的执行或吞掉内容）；
- `ab todo` 一项有几条命令时，整行照抄（全角「｜」成了多余参数）会被解析器拒绝，不会落账。
"""

from __future__ import annotations

import contextlib
import io
from pathlib import Path
import re
import shlex
from tempfile import TemporaryDirectory
import unittest

import bridge_support  # noqa: F401  导入即隔离宿主会话环境
from agentstatus_bridge.cli import build_parser
from agentstatus_bridge.ids import short
from agentstatus_bridge import envelope
from agentstatus_bridge.labels import REASON_TEXTS, next_step, reason_text
from agentstatus_bridge.model import (
    ASK_OPTION,
    DEFER_OPTION,
    FOR_SEQ_OPTION,
    NOTE_KIND,
    NOTICE_KIND_OPTION,
    Delivery,
    Flow,
    Provider,
    Role,
    Verdict,
    Work,
    describe,
    work_attempts,
)
from agentstatus_bridge.nudges import nudge_body
from agentstatus_bridge.reminders import pending_notices, reminder_body
from agentstatus_bridge.store import Store
from agentstatus_bridge.todo import COMMAND_SEPARATOR, local_items, report_item, text_line
from bridge_support import ref

CMD = "ab"
IMPL = ref(Provider.CODEX, "019a0000-1111-7111-8111-111111111111", pid=1000, pane="%1", label="impl")
LEAD = ref(Provider.CLAUDE, "lead-session", pid=3000, pane="%3", label="lead")
# shell 元字符（引号不在内：占位写成 "问题" 这类带引号的中文）
META = frozenset("|&;<>()$`\\*?[]{}!#~\n")
# 文字里嵌着的命令：ab 子命令后接 ASCII 词或带引号的占位；遇到中文、全角标点就停
COMMAND_RE = re.compile(r'(?<![\w-])ab [a-z]+(?: (?:"[^"\n]*"|[A-Za-z0-9_.@:%/=+-]+))*')
# 文字里只点名子命令、不是完整命令的用法：「close 后 ab send 新任务」「过期后可 ab retry」。照抄只会被解析器拒绝
#（缺任务或目标），不会执行任何东西；后者补上任务标识要改 summary 合同 golden，不在本轮
MENTIONS = frozenset({"ab send", "ab retry"})


class CopyableCommandTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = TemporaryDirectory()
        self.store = Store.open(Path(self._tmp.name) / "bridge")
        self.now = 1000.0
        self.parser = build_parser()
        self.checked = 0

    def tearDown(self) -> None:
        self.store.close()
        self._tmp.cleanup()

    # ---- 判定 ----
    def parses(self, line: str) -> bool:
        argv = shlex.split(line)
        self.assertEqual(argv[0], CMD, line)
        with contextlib.redirect_stderr(io.StringIO()), contextlib.redirect_stdout(io.StringIO()):
            try:
                self.parser.parse_args(argv[1:])
            except SystemExit:
                return False
        return True

    def assert_command(self, line: str) -> None:
        self.assertFalse(META & set(line), f"含 shell 元字符：{line}")
        self.assertTrue(self.parses(line), f"解析器不接受：{line}")
        self.checked += 1

    def assert_text(self, text: str) -> None:
        self.assertNotRegex(text, r"[|<>]", text)
        for line in COMMAND_RE.findall(text):
            if line not in MENTIONS:
                self.assert_command(line)

    # ---- 夹具 ----
    def _task(self, *, flow: Flow = Flow.HANDOFF, delivery: Delivery | None = Delivery.QUEUED,
              work: Work | None = None, options: dict[str, object] | None = None):
        task, attempt = self.store.create_task(
            title="任务", flow=flow, origin=LEAD, origin_class="bypass",
            reviewer=LEAD if flow is Flow.REVIEW else None, target=IMPL, body="做 X", refs=[], now=self.now,
            attempt_options=options)
        if delivery is not None:
            self.store.begin_send(attempt.id, now=self.now, pid=1, start_ticks="1")
            self.store.finish_send(attempt.id, delivery=delivery, reason="t", provider_ref=None, detail={},
                                   now=self.now)
        if work is not None:
            self.store.set_work(attempt.id, work=work, result={"note": "x"} if work is Work.RESULT else None,
                                now=self.now, event="t")
        return task.id, attempt

    def _review(self, verdict: str | None) -> str:
        task_id, first = self._task(flow=Flow.REVIEW, work=Work.RESULT)
        review = self.store.add_attempt(task_id, role=Role.REVIEW, target=LEAD, body="请复核", refs=[], now=self.now,
                                        sender=None, sender_class="bypass")
        self.store.begin_send(review.id, now=self.now, pid=1, start_ticks="1")
        self.store.finish_send(review.id, delivery=Delivery.WRITTEN, reason="t", provider_ref=None, detail={},
                               now=self.now)
        self.store.set_work(review.id, work=Work.RESULT, result={"note": "x"}, now=self.now, event="t")
        if verdict is not None:
            self.store.update_task(task_id, now=self.now, event="t", verdict=verdict)
        return task_id

    def _states(self) -> dict[str, str]:
        found: dict[str, str] = {}
        task_id, _ = self._task(delivery=None)
        self.store.update_task(task_id, now=self.now, event="t", control="paused")
        found["paused"] = task_id
        found["waiting"] = self._task(delivery=None)[0]
        found["deferred"] = self._task(delivery=None, options={DEFER_OPTION: self.now + 600})[0]
        for delivery in (Delivery.HELD, Delivery.UNKNOWN, Delivery.FAILED, Delivery.REFUSED):
            found[delivery.value] = self._task(delivery=delivery)[0]
        task_id, attempt = self._task(delivery=None)
        self.store.transition_delivery(attempt.id, expected=(Delivery.PENDING,), new=Delivery.CANCELLED,
                                       reason="cancelled", now=self.now)
        found["cancelled"] = task_id
        found["blocked"] = self._task(work=Work.BLOCKED)[0]
        found["failure"] = self._task(work=Work.FAILED)[0]
        task_id, attempt = self._task(work=Work.IN_PROGRESS)
        self.store.set_attempt_option(attempt.id, ASK_OPTION, {"at": self.now, "note": "问题"})
        found["question"] = task_id
        found["result"] = self._task(work=Work.RESULT)[0]
        found["written"] = self._task(delivery=Delivery.WRITTEN)[0]
        found["queued"] = self._task()[0]
        found["review_missing"] = self._review(None)
        found["changes"] = self._review(Verdict.CHANGES.value)
        found["approved"] = self._review(Verdict.APPROVED.value)
        return found

    # ---- 用例 ----
    def test_next_step_and_reminder_bodies_in_every_phase(self) -> None:
        states = self._states()
        reasons = set()
        for name, task_id in states.items():
            task = self.store.get_task(task_id)
            assert task is not None
            attempts = self.store.attempts(task_id)
            view = describe(task, attempts)
            reasons.add(view.reason)
            for reserved in (0, 60):  # 60：交接次数已满，走容量文案
                with self.subTest(state=name, reserved=reserved):
                    step = next_step(task, attempts, ref=short(task_id), command=CMD, reserved=reserved)
                    if step is None:
                        continue
                    if step.command is not None:
                        self.assert_command(step.command)
                    self.assert_text(step.text)
            with self.subTest(state=name, body="reminder"):
                self.assert_text(reminder_body(task, attempts, view, command=CMD))
        # 各阶段都确实走到了（夹具没退化成同一个原因）
        self.assertTrue({"paused", "waiting_for_target", "deferred", "delivery_held", "delivery_unknown",
                         "delivery_failed", "cancelled_undelivered", "blocked_reported", "failure_reported",
                         "question_asked", "result_ready", "review_verdict_missing", "changes_requested",
                         "review_approved"} <= reasons, reasons)
        self.assertGreater(self.checked, 30)

    def test_silent_and_note_undelivered_bodies_with_and_without_room(self) -> None:
        for fill in (False, True):
            with self.subTest(fill=fill):
                task_id, work = self._task(delivery=Delivery.WRITTEN)
                if fill:  # 序号用到 59：沉默提醒自己占第 60 个，只给查看与关闭
                    while max(item.seq for item in self.store.attempts(task_id)) < 59:
                        self.store.add_attempt(task_id, role=Role.NOTICE, target=LEAD, body="容量夹具", refs=[],
                                               now=self.now, sender=None, sender_class="bypass")
                task = self.store.get_task(task_id)
                assert task is not None
                attempts = self.store.attempts(task_id)
                [silent] = [item for item in pending_notices(task, attempts) if item.kind == "silent"]
                text = reminder_body(task, attempts, silent.view, command=CMD, silent=silent, state="空闲",
                                     now=silent.due_at)
                self.assertIn("下一步：", text)
                self.assert_text(text)
                self.assertIn(f"{CMD} status {short(task_id)}", COMMAND_RE.findall(text))
        task_id, work = self._task(delivery=Delivery.WRITTEN)
        note = self.store.add_attempt(task_id, role=Role.NOTICE, target=IMPL, body="补充", refs=[], now=self.now,
                                      sender=LEAD, sender_class="bypass",
                                      options={NOTICE_KIND_OPTION: NOTE_KIND, FOR_SEQ_OPTION: work.seq})
        self.store.begin_send(note.id, now=self.now, pid=1, start_ticks="1")
        self.store.finish_send(note.id, delivery=Delivery.FAILED, reason="target_gone", provider_ref=None, detail={},
                               now=self.now)
        task = self.store.get_task(task_id)
        assert task is not None
        attempts = self.store.attempts(task_id)
        [undelivered] = [item for item in pending_notices(task, attempts) if item.kind == "note"]
        text = reminder_body(task, attempts, undelivered.view, command=CMD, immediate=undelivered.immediate,
                             note=undelivered.note)
        self.assert_text(text)
        self.assertIn(f'{CMD} note {short(task_id)} -m "补充内容"', COMMAND_RE.findall(text))

    def test_nudge_bodies(self) -> None:
        task_id, work = self._task(delivery=Delivery.WRITTEN)
        task = self.store.get_task(task_id)
        assert task is not None
        handoff = nudge_body(task, work, command=CMD)
        review_id = self._review(None)
        review_task = self.store.get_task(review_id)
        assert review_task is not None
        review = work_attempts(self.store.attempts(review_id))[-1]
        for text in (handoff, nudge_body(review_task, review, command=CMD)):
            self.assert_text(text)
        self.assertEqual(len(COMMAND_RE.findall(handoff)), 3)

    def test_todo_commands_parse_one_by_one_and_the_whole_line_is_rejected(self) -> None:
        states = self._states()
        items = []
        for task_id in states.values():
            task = self.store.get_task(task_id)
            assert task is not None
            items.extend(local_items(task, self.store.attempts(task_id), LEAD, now=self.now + 3600, command=CMD))
        # 接收方一侧（待你汇报 / 待你复核），含镜像上带 --origin-device 的写法
        task_id, work = self._task()
        task = self.store.get_task(task_id)
        assert task is not None
        items.extend(local_items(task, self.store.attempts(task_id), IMPL, now=self.now, command=CMD))
        items.append(report_item(task_id, "标题", work, command=CMD, scope="federation", origin_device="vm"))
        review_id = self._review(None)
        review = work_attempts(self.store.attempts(review_id))[-1]
        items.append(report_item(review_id, "标题", review, command=CMD, scope="local"))
        categories = {item.category for item in items}
        self.assertTrue({"accept", "handle", "report", "review", "silent"} <= categories, categories)
        multi = 0
        for item in items:
            with self.subTest(category=item.category, task=short(item.task_id)):
                for line in item.commands:
                    self.assert_command(line)
                line = text_line(item)
                self.assertNotRegex(line, r"[|<>]")
                joined = line.split("→ ", 1)[1]
                self.assertEqual(joined.split(COMMAND_SEPARATOR), list(item.commands))
                if len(item.commands) > 1:
                    multi += 1
                    self.assertFalse(self.parses(joined), f"整行照抄竟被接受：{joined}")
                    self.assertFalse(self.parses(COMMAND_SEPARATOR.strip().join(item.commands)))
        self.assertGreaterEqual(multi, 4)

    def test_reason_texts_have_no_flag_placeholders_and_their_commands_parse(self) -> None:
        # §104.11 P3：错误说明里的 `--flag <占位>` 照抄是重定向（`--follows <旧ID>`、`--hub-id <新hubId>`）；占位写成带引号的
        # 中文。`provider@id:<完整ID>` 这类不跟在选项后面的地址格式说明按协调方决定本轮不动（open-items 可选项）
        for code in REASON_TEXTS:
            with self.subTest(code=code):
                text = reason_text(code, command=CMD)
                self.assertNotIn("|", text)
                self.assertNotRegex(text, r"--[a-z][a-z-]* <", text)
                # 错误说明是通用文案、没有任务标识或设备名（「请 ab close 旧任务」「用 ab peers --device 核对」）：
                # 照抄只会被解析器拒绝；这里只要求嵌着的命令不含 shell 元字符
                for line in COMMAND_RE.findall(text):
                    self.assertFalse(META & set(line), line)
                    self.checked += 1
        rebuild = COMMAND_RE.findall(reason_text("federation_rebuild_incomplete", command=CMD))
        self.assertEqual(rebuild, ['ab federation rebuild --hub-id "新hubId"'])
        self.assertTrue(self.parses(rebuild[0]))

    def test_footers_of_handoff_review_and_mirror_messages(self) -> None:
        # 页脚（§104.11 P3）：可选参数的方括号放行——整行照抄只会被解析器拒绝；去掉方括号部分后每条都能解析；其余元字符照旧禁止
        task_id, work = self._task(delivery=None)
        review_id = self._review(None)
        review = work_attempts(self.store.attempts(review_id))[-1]
        texts = []
        for tid, attempt in ((task_id, work), (review_id, review)):
            task = self.store.get_task(tid)
            assert task is not None
            texts.append(envelope.render(task, attempt, sender="claude@lead", device="vm", command=CMD))
            texts.append(envelope.render(task, attempt, sender="claude@lead", device="vm", command=CMD,
                                         origin_device="vm"))
        checked = 0
        for text in texts:
            for line in text.splitlines():
                if not line.startswith("- ") or f"：{CMD} " not in line:
                    continue
                command = line.split("：", 1)[1]
                self.assertFalse((META - set("[]")) & set(command), command)
                bare = re.sub(r" \[[^\]]*\]", "", command)
                self.assertFalse(META & set(bare), bare)
                self.assertTrue(self.parses(bare), bare)
                if bare != command:
                    self.assertFalse(self.parses(command), f"带方括号的整行竟被接受：{command}")
                checked += 1
        self.assertGreaterEqual(checked, 16)  # 交接 5 条、复核 3 条，本机与镜像各一份
        self.assertTrue(any("--origin-device vm" in text for text in texts))

    def test_note_undelivered_at_capacity_uses_the_shared_capacity_wording(self) -> None:
        # §104.11 P3：补充未送达时容量满（重新补充排不进）→ 下一步给统一的 close 写法，第二行据此写容量措辞；
        # 第 2 行不再说「可以安全重新补充」
        task_id, work = self._task(delivery=Delivery.WRITTEN)
        while max(item.seq for item in self.store.attempts(task_id)) < 58:
            self.store.add_attempt(task_id, role=Role.NOTICE, target=LEAD, body="容量夹具", refs=[], now=self.now,
                                   sender=None, sender_class="bypass")
        note = self.store.add_attempt(task_id, role=Role.NOTICE, target=IMPL, body="补充", refs=[], now=self.now,
                                      sender=LEAD, sender_class="bypass",
                                      options={NOTICE_KIND_OPTION: NOTE_KIND, FOR_SEQ_OPTION: work.seq})
        self.store.begin_send(note.id, now=self.now, pid=1, start_ticks="1")
        self.store.finish_send(note.id, delivery=Delivery.FAILED, reason="target_gone", provider_ref=None, detail={},
                               now=self.now)
        task = self.store.get_task(task_id)
        assert task is not None
        attempts = self.store.attempts(task_id)
        self.assertEqual(max(item.seq for item in attempts), 59)  # 告知占 60，重新补充已排不进
        [undelivered] = [item for item in pending_notices(task, attempts) if item.kind == "note"]
        text = reminder_body(task, attempts, undelivered.view, command=CMD, immediate=undelivered.immediate,
                             note=undelivered.note)
        lines = text.splitlines()
        self.assertEqual(lines[1], "对方会话确定没有收到这条补充。")
        self.assertNotIn("可以安全重新补充", text)
        step = [line for line in lines if line.startswith("下一步：")][-1]
        self.assertIn("交接次数已达上限", step)
        self.assertIn(f"{CMD} close {short(task_id)}", step)
        self.assertTrue(envelope._at_capacity(text))  # pyright: ignore[reportPrivateUsage]
        self.assert_text(text)
        # 还有空位时照旧建议重新补充
        task_id, work = self._task(delivery=Delivery.WRITTEN)
        note = self.store.add_attempt(task_id, role=Role.NOTICE, target=IMPL, body="补充", refs=[], now=self.now,
                                      sender=LEAD, sender_class="bypass",
                                      options={NOTICE_KIND_OPTION: NOTE_KIND, FOR_SEQ_OPTION: work.seq})
        self.store.begin_send(note.id, now=self.now, pid=1, start_ticks="1")
        self.store.finish_send(note.id, delivery=Delivery.FAILED, reason="target_gone", provider_ref=None, detail={},
                               now=self.now)
        task = self.store.get_task(task_id)
        assert task is not None
        attempts = self.store.attempts(task_id)
        [undelivered] = [item for item in pending_notices(task, attempts) if item.kind == "note"]
        text = reminder_body(task, attempts, undelivered.view, command=CMD, immediate=undelivered.immediate,
                             note=undelivered.note)
        self.assertEqual(text.splitlines()[1], "对方会话确定没有收到这条补充，可以安全重新补充。")
        self.assertFalse(envelope._at_capacity(text))  # pyright: ignore[reportPrivateUsage]


if __name__ == "__main__":
    unittest.main()
