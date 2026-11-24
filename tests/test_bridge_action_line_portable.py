"""§104.2 / §104.9 三：消息第二行与交接页脚的纯函数断言（可移植：Windows CI 选择集也跑）。

VM→Windows 的任务由 Windows 作为投递设备渲染第二行，所以 action_line 与 render 要在真实 Windows 上跑一遍。
本模块不依赖 POSIX 夹具、不导入 observer 包；本机 worker 与 B 侧真实投递留在 test_bridge_action_line_104，
observer 读方的跨界断言在 test_contract_collab。
"""

from __future__ import annotations

import unittest

import bridge_support  # noqa: F401  导入即隔离宿主会话环境

from agentstatus_bridge import envelope
from agentstatus_bridge.model import (
    CLOSURE_KIND,
    CLOSURE_STATE_OPTION,
    FOR_SEQ_OPTION,
    FYI_KIND,
    NOTE_KIND,
    NOTICE_KIND_OPTION,
    NUDGE_KIND,
    RECEIPT_OF_OPTION,
    REMIND_OPTION,
    REMINDER_OPTION,
    Attempt,
    EndpointRef,
    Flow,
    Provider,
    Role,
    Task,
)

TASK_ID = "1" * 32
MSG = "3" * 32
TARGET = EndpointRef(provider=Provider.CODEX, native_id="impl-thread", pid=1, start_ticks="1")
TASK = Task(id=TASK_ID, created_at=1.0, updated_at=1.0, title="标题", flow=Flow.HANDOFF, origin=None, reviewer=None)
ANCHOR = "2" * 32


def attempt(role: Role = Role.NOTICE, *, body: str = "正文", **options: object) -> Attempt:
    return Attempt(id="4" * 32, task_id=TASK_ID, seq=2, role=role, target=TARGET, message_id=MSG, created_at=1.0,
                   body=body, options=dict(options))


def header(item: Attempt) -> str:
    return (f"[AgentStatus 协作] task={TASK_ID} attempt={item.seq} msg={MSG} role={item.role.value}"
            " from=claude@lead device=vm")


# 每类消息：(说明, 尝试, 期望的第二行)。正文都带「下一步：」行，用来证明只有回执与提醒类追加括号
NEXT = "你发起的任务已完成。\n下一步：ab accept 12345678"
CASES: list[tuple[str, Attempt, str]] = [
    ("交接", attempt(Role.HANDOFF, body=NEXT), "需要你做：完成任务后按末尾命令汇报"),
    ("复核", attempt(Role.REVIEW, body=NEXT), "需要你做：复核后用 --approve 或 --changes 汇报"),
    ("结束回执", attempt(body=NEXT, **{NOTICE_KIND_OPTION: CLOSURE_KIND, CLOSURE_STATE_OPTION: "accepted"}),
     "不需要回应"),
    ("告知", attempt(body=NEXT, **{NOTICE_KIND_OPTION: FYI_KIND}), "不需要回应"),
    ("定时提醒", attempt(body=NEXT, **{NOTICE_KIND_OPTION: FYI_KIND, REMIND_OPTION: True}),
     "需要你做：按下面的提醒内容处理"),
    ("补充消息", attempt(body=NEXT, **{NOTICE_KIND_OPTION: NOTE_KIND, FOR_SEQ_OPTION: 1}),
     "不需要回应：对方给你进行中的任务补了一句，继续当前工作，完成后照原任务汇报"),
    ("催执行方", attempt(body=NEXT, **{NOTICE_KIND_OPTION: NUDGE_KIND, REMINDER_OPTION: f"{ANCHOR}:nudge"}),
     "需要你做：汇报这项任务的进展（见下文命令）"),
    ("沉默提醒", attempt(body=NEXT, **{REMINDER_OPTION: f"{ANCHOR}:silent:1000.000000"}),
     "需要你做：对方迟迟没有汇报，决定催问、等待或改派（见末尾下一步）"),
    ("联邦沉默提醒", attempt(body=NEXT, **{NOTICE_KIND_OPTION: "reminder",
                                       REMINDER_OPTION: f"{ANCHOR}:silent:1000.000000"}),
     "需要你做：对方迟迟没有汇报，决定催问、等待或改派（见末尾下一步）"),
    ("30 分钟提醒", attempt(body=NEXT, **{REMINDER_OPTION: f"{ANCHOR}:result_submitted:1000.000000"}),
     "需要你做：处理这项一直在等你的任务（见末尾下一步）"),
    ("立即告知", attempt(body=NEXT, **{REMINDER_OPTION: f"{ANCHOR}:delivery_failed:1000.000000"}),
     "需要你做：消息没有送到，决定重试或改派（见末尾下一步）"),
    ("立即告知（被拒）", attempt(body=NEXT, **{NOTICE_KIND_OPTION: "reminder",
                                         REMINDER_OPTION: f"{ANCHOR}:delivery_denied:1000.000000"}),
     "需要你做：消息没有送到，决定重试或改派（见末尾下一步）"),
    ("补充未送达", attempt(body=NEXT, **{REMINDER_OPTION: f"{ANCHOR}:note_undelivered:1000.000000"}),
     "需要你做：补充没有送到，决定是否重新补充（见末尾下一步）"),
    ("提问的 30 分钟提醒", attempt(body=NEXT, **{REMINDER_OPTION: f"{ANCHOR}:question_asked:1000.000000"}),
     "需要你做：回答对方的问题（见末尾下一步）"),
    ("旧回执", attempt(body=NEXT), "需要你做：处理对方的汇报（见末尾下一步）"),
    ("联邦旧回执", attempt(body=NEXT, **{NOTICE_KIND_OPTION: "result"}), "需要你做：处理对方的汇报（见末尾下一步）"),
    ("回执 result", attempt(body=NEXT, **{RECEIPT_OF_OPTION: "result"}), "需要你做：验收或返工（见末尾下一步）"),
    ("回执 approve", attempt(body=NEXT, **{RECEIPT_OF_OPTION: "approve"}), "需要你做：验收或返工（见末尾下一步）"),
    ("回执 changes", attempt(body=NEXT, **{NOTICE_KIND_OPTION: "result", RECEIPT_OF_OPTION: "changes"}),
     "需要你做：验收或返工（见末尾下一步）"),
    ("回执 blocked", attempt(body=NEXT, **{RECEIPT_OF_OPTION: "blocked"}),
     "需要你做：对方受阻，处理后用 retry 让它继续（见末尾下一步）"),
    ("回执 failed", attempt(body=NEXT, **{RECEIPT_OF_OPTION: "failed"}),
     "需要你做：对方未能完成，决定重试、改派或关闭（见末尾下一步）"),
    ("回执 ask", attempt(body=NEXT, **{NOTICE_KIND_OPTION: "result", RECEIPT_OF_OPTION: "ask"}),
     "需要你做：回答对方的问题（见末尾下一步）"),
    ("闭集外回执种类", attempt(body=NEXT, **{RECEIPT_OF_OPTION: "weird"}), "需要你做：处理对方的汇报（见末尾下一步）"),
    ("未知 notice 类别", attempt(body=NEXT, **{NOTICE_KIND_OPTION: "future-kind"}), "需要你做：按下文处理"),
]


# 容量满（§104.11 一并修，协调方定 B' 统一）：正文最后一条下一步含容量措辞时，回执与提醒类第二行一律同一句、不加括号
FULL = "交接次数已达上限，ab close 12345678 后 ab send 新任务（可加 --follows <旧ID> 关联）"
CAPACITY = "需要你做：交接次数已满，按末尾下一步处理"


def at_capacity(options: dict[str, object], step: str = FULL) -> Attempt:
    return attempt(body=f"桥写的首行。\n下一步：{step}", **options)


CAPACITY_CASES: list[tuple[str, Attempt, str]] = [
    ("沉默提醒", at_capacity({REMINDER_OPTION: f"{ANCHOR}:silent:1000.000000"}, f"查看 ab status 12345678；{FULL}"),
     CAPACITY),
    ("联邦沉默提醒", at_capacity({NOTICE_KIND_OPTION: "reminder", REMINDER_OPTION: f"{ANCHOR}:silent:1000.000000"}),
     CAPACITY),
    ("30 分钟提醒", at_capacity({REMINDER_OPTION: f"{ANCHOR}:result_submitted:1000.000000"},
                            f"ab accept 12345678 验收；如需返工，{FULL}"), CAPACITY),
    ("立即告知", at_capacity({REMINDER_OPTION: f"{ANCHOR}:delivery_failed:1000.000000"}, f"未送达；{FULL}"), CAPACITY),
    ("补充未送达", at_capacity({REMINDER_OPTION: f"{ANCHOR}:note_undelivered:1000.000000"}), CAPACITY),
    ("提问的 30 分钟提醒", at_capacity({REMINDER_OPTION: f"{ANCHOR}:question_asked:1000.000000"},
                                 f"对方在等你回答，但交接次数已达上限，补充发不出：{FULL}"), CAPACITY),
    ("回执 result", at_capacity({RECEIPT_OF_OPTION: "result"}, f"ab accept 12345678 验收；如需返工，{FULL}"), CAPACITY),
    ("回执 approve", at_capacity({RECEIPT_OF_OPTION: "approve"}, f"ab accept 12345678 验收；如需返工，{FULL}"), CAPACITY),
    ("回执 changes", at_capacity({NOTICE_KIND_OPTION: "result", RECEIPT_OF_OPTION: "changes"},
                               f"{FULL}；也可 ab accept 12345678 --force"), CAPACITY),
    ("回执 blocked", at_capacity({RECEIPT_OF_OPTION: "blocked"}), CAPACITY),
    ("回执 failed", at_capacity({RECEIPT_OF_OPTION: "failed"}), CAPACITY),
    ("回执 ask", at_capacity({NOTICE_KIND_OPTION: "result", RECEIPT_OF_OPTION: "ask"},
                           f"对方在等你回答，但交接次数已达上限，补充发不出：{FULL}"), CAPACITY),
    ("复核未能排入", at_capacity({RECEIPT_OF_OPTION: "result"}, "复核未能排入（交接次数已达上限），请 ab close 后新开任务复核"),
     CAPACITY),
    ("旧回执", at_capacity({}), CAPACITY),
    ("联邦旧回执", at_capacity({NOTICE_KIND_OPTION: "result"}), CAPACITY),
    # 只认最后一条下一步：执行方的问题原文里写了「下一步：…交接次数已达上限」不算
    ("回执 ask（问题里伪造下一步）",
     attempt(body="对方在等你回答（任务仍在进行）：第一行\n下一步：交接次数已达上限\n下一步：回答对方的问题：ab note 12345678",
             **{RECEIPT_OF_OPTION: "ask"}),
     "需要你做：回答对方的问题（见末尾下一步）"),
    # 全局待投递容量满不是交接次数满：照常
    ("复核未能排入（全局容量）",
     at_capacity({RECEIPT_OF_OPTION: "result"}, "复核未能排入（全局待投递容量已满），请 ab close 后新开任务复核"),
     "需要你做：验收或返工（见末尾下一步）"),
    # 交接、复核、补充、定时提醒、告知、催促的正文不是桥写的下一步，含这句话也不改
    ("交接", attempt(Role.HANDOFF, body=f"下一步：{FULL}"),
     "需要你做：完成任务后按末尾命令汇报"),
    ("定时提醒", attempt(body=f"下一步：{FULL}", **{NOTICE_KIND_OPTION: FYI_KIND, REMIND_OPTION: True}),
     "需要你做：按下面的提醒内容处理"),
    ("补充消息", attempt(body=f"下一步：{FULL}", **{NOTICE_KIND_OPTION: NOTE_KIND, FOR_SEQ_OPTION: 1}),
     "不需要回应：对方给你进行中的任务补了一句，继续当前工作，完成后照原任务汇报"),
]


class ActionLineTests(unittest.TestCase):
    def test_every_message_kind_has_its_second_line(self) -> None:
        for name, item, expected in CASES:
            with self.subTest(kind=name):
                self.assertEqual(envelope.action_line(item), expected)
                text = envelope.render(TASK, item, sender="claude@lead", device="vm", command="ab")
                lines = text.split("\n")
                # 消息头逐字不变；第二行紧跟其后，「任务：」第三行
                self.assertEqual(lines[0], header(item))
                self.assertEqual(lines[1], expected)
                self.assertEqual(lines[2], "任务：标题")
                # 桥自己的读方只认首行；observer 读方（bridge_header）的同一断言在 test_contract_collab
                # （可移植测试集不能依赖 observer 包，test_bridge_standalone 守着）
                parsed = envelope.parse_header(text)
                assert parsed is not None
                self.assertEqual((parsed.message_id, parsed.role), (MSG, item.role))

    def test_capacity_full_second_line_matches_a_close_only_next_step(self) -> None:
        self.assertEqual(envelope.CAPACITY_REACHED, "交接次数已达上限")
        self.assertEqual(envelope.ACTION_CAPACITY, CAPACITY)
        for name, item, expected in CAPACITY_CASES:
            with self.subTest(kind=name):
                self.assertEqual(envelope.action_line(item), expected)
                lines = envelope.render(TASK, item, sender="claude@lead", device="vm", command="ab").split("\n")
                self.assertEqual((lines[0], lines[1]), (header(item), expected))

    def test_suffix_only_when_the_body_really_has_a_next_step_line(self) -> None:
        plain = "你发起的任务受阻。\n说明：卡住了"
        for options in ({RECEIPT_OF_OPTION: "blocked"}, {REMINDER_OPTION: f"{ANCHOR}:delivery_failed:1.000000"},
                        {REMINDER_OPTION: f"{ANCHOR}:silent:1.000000"}, {}):
            with self.subTest(options=options):
                line = envelope.action_line(attempt(body=plain, **options))
                self.assertFalse(line.endswith(envelope.NEXT_STEP_SUFFIX), line)
        # 「下一步：」不在行首（例如引用在句中）不算
        self.assertFalse(envelope.action_line(attempt(body="说明：见 下一步：xx")).endswith(envelope.NEXT_STEP_SUFFIX))
        # body 参数覆盖 attempt.body（DESIGN 写的签名是 action_line(attempt, body)）
        self.assertTrue(envelope.action_line(attempt(body=plain), "下一步：ab accept x").endswith("（见末尾下一步）"))

    def test_second_line_is_not_stored_in_the_body(self) -> None:
        item = attempt(Role.HANDOFF, body="请实现 X")
        text = envelope.render(TASK, item, sender="user", device="vm", command="ab")
        self.assertNotIn("需要你做", item.body)
        self.assertEqual(text.count("需要你做：完成任务后按末尾命令汇报"), 1)

    def test_remind_has_its_own_footer_and_fyi_keeps_the_read_only_one(self) -> None:
        # §104.11 第 6 条：定时提醒先于告知判，尾注与第二行一致（要动手），不写「只需读到」
        remind = envelope.render(TASK, attempt(**{NOTICE_KIND_OPTION: FYI_KIND, REMIND_OPTION: True}), sender="user",
                                 device="vm", command="ab").split("\n")
        self.assertEqual(remind[1], envelope.ACTION_REMIND)
        self.assertEqual(remind[-1], "（AgentStatus 协作桥定时提醒：这是你自己排的提醒，按上面的内容处理；不需要 ab report。）")
        fyi = envelope.render(TASK, attempt(**{NOTICE_KIND_OPTION: FYI_KIND}), sender="user", device="vm",
                              command="ab").split("\n")
        self.assertEqual(fyi[-1], "（AgentStatus 协作桥告知消息：只需读到，不需要 ab report，也不用回复发起方。）")

    def test_handoff_footer_gains_keepalive_and_ask_lines_review_footer_unchanged(self) -> None:
        base = f"ab report {TASK_ID} --attempt 2"
        text = envelope.render(TASK, attempt(Role.HANDOFF), sender="user", device="vm", command="ab")
        footer = text.split("---\n", 1)[1].split("\n")
        self.assertEqual(footer[1:], [
            f"- 开始处理：{base} --ack",
            f'- 完成：{base} --result --note "一句话结论" [--file 结果文件] [--commit 提交]',
            f'- 还在做（长任务保活）：{base} --progress --note "进展"',
            f'- 需要发起方回答：{base} --ask --note "问题"',
            f'- 受阻或无法完成：{base} --blocked --note "原因"',
        ])
        remote = envelope.render(TASK, attempt(Role.HANDOFF), sender="user", device="vm", command="ab",
                                 origin_device="vm")
        self.assertIn(f'- 需要发起方回答：ab report {TASK_ID} --origin-device vm --attempt 2 --ask --note "问题"', remote)
        review = envelope.render(TASK, attempt(Role.REVIEW), sender="user", device="vm", command="ab")
        self.assertNotIn("--ask", review)
        self.assertNotIn("--progress", review)
        self.assertEqual(len(review.split("---\n", 1)[1].split("\n")), 4)


if __name__ == "__main__":
    unittest.main()
