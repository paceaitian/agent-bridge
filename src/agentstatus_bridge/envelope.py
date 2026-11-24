"""投递给接收会话的消息格式：一行机器可读头、第二行写明要不要动手、正文，以及教对方如何用 ab 汇报的说明。"""

from __future__ import annotations

from dataclasses import dataclass
import re

from .model import (
    DEFINITELY_UNDELIVERED,
    NOTICE_KIND_OPTION,
    REMINDER_OPTION,
    Attempt,
    Role,
    Task,
)
from .naming import command_name

HEADER_TAG = "[AgentStatus 协作]"
# 字段顺序固定 `task attempt msg role from device`；`from=`/`device=` 都可选，旧格式必须继续解析得出来
# （在途消息、docs/ab.md 与独立仓 README 照抄的是这份语法）。值只要求不含空白：空格已经分隔字段、键里不含 `=`，
# 按第一个 `=` 切分就没有歧义。**读方不得比任何发过的写方更严**——旧写方的 token 只去空白，
# 会发出 `from=codex@a=b`，而安装不停 worker，升级后那个旧 worker 还会发一段时间（Codex 审计 F01）。
_HEADER = re.compile(
    r"^\[AgentStatus 协作\] task=(?P<task>[0-9a-f]{32}) attempt=(?P<attempt>[0-9]{1,4})"
    r" msg=(?P<message>[0-9a-f]{32}) role=(?P<role>handoff|review|notice)"
    r"(?: from=(?P<sender>\S{1,64}))?(?: device=(?P<device>\S{1,64}))?$"
)


# 第二行（DESIGN §104.2、§104.9 三）：每条消息头下面写明要不要对方动手；只在渲染时生成，不存进正文
ACTION_HANDOFF = "需要你做：完成任务后按末尾命令汇报"
ACTION_REVIEW = "需要你做：复核后用 --approve 或 --changes 汇报"
ACTION_NONE = "不需要回应"
ACTION_NOTE = "不需要回应：对方给你进行中的任务补了一句，继续当前工作，完成后照原任务汇报"
ACTION_REMIND = "需要你做：按下面的提醒内容处理"
ACTION_NUDGE = "需要你做：汇报这项任务的进展（见下文命令）"
ACTION_SILENT = "需要你做：对方迟迟没有汇报，决定催问、等待或改派"
ACTION_REMINDER = "需要你做：处理这项一直在等你的任务"
ACTION_UNDELIVERED = "需要你做：消息没有送到，决定重试或改派"
ACTION_NOTE_UNDELIVERED = "需要你做：补充没有送到，决定是否重新补充"
ACTION_QUESTION = "需要你做：回答对方的问题"
ACTION_RECEIPT = "需要你做：处理对方的汇报"  # 没有 receiptOf 的旧回执
ACTION_FALLBACK = "需要你做：按下文处理"  # 认不出的 notice 类别（例如更新版本的发起设备将来新增的）
RECEIPT_ACTIONS = {
    "result": "需要你做：验收或返工",
    "approve": "需要你做：验收或返工",
    "changes": "需要你做：验收或返工",
    "blocked": "需要你做：对方受阻，处理后用 retry 让它继续",
    "failed": "需要你做：对方未能完成，决定重试、改派或关闭",
    "ask": ACTION_QUESTION,
}
NEXT_STEP_SUFFIX = "（见末尾下一步）"
# 容量满（§104.11 一并修，协调方定 B' 统一）：正文的下一步含容量措辞时，回执与提醒类的第二行一律写这一句，
# 不再叫人催问、改派、返工或补充回答；「按末尾下一步处理」对只剩 close 与仍可 accept 两种情况都成立。
# CAPACITY_REACHED 是写方（labels.next_step、reminders 的沉默提醒正文、review_capacity_hint）下一步里的固定措辞，
# 契约测试钉住两边一致
CAPACITY_REACHED = "交接次数已达上限"
ACTION_CAPACITY = "需要你做：交接次数已满，按末尾下一步处理"
_IMMEDIATE_REASONS = frozenset(f"delivery_{delivery.value}" for delivery in DEFINITELY_UNDELIVERED)


def _reminder_action(token: str) -> str:
    """提醒令牌 `<锚点>:<原因>:<时刻>` 的原因段决定措辞：确定未送达（立即告知）、补充未送达、提问，其余是 30 分钟提醒。

    与 reminders.IMMEDIATE_REASONS 同一闭集（由 DEFINITELY_UNDELIVERED 导出，不反向导入 reminders）；本机 `ab send`
    当场打印过失败、退回 30 分钟的那条，原因仍是 delivery_*，措辞同样是「消息没有送到」。
    """
    parts = token.split(":")
    reason = parts[1] if len(parts) == 3 else ""
    if reason == "note_undelivered":
        return ACTION_NOTE_UNDELIVERED
    if reason in _IMMEDIATE_REASONS:
        return ACTION_UNDELIVERED
    if reason == "question_asked":
        return ACTION_QUESTION
    return ACTION_REMINDER


def _has_next_step(body: str) -> bool:
    """正文里确有以「下一步：」开头的行（这些 notice 的正文都是桥生成的，判断可靠，§104.9 三）。"""
    return any(line.startswith("下一步：") for line in body.splitlines())


def _at_capacity(body: str) -> bool:
    """正文最后一条「下一步：」行含容量措辞（§104.11 一并修）。

    只看最后一条：桥把下一步写在正文末尾，提问回执的首行是执行方的原文，里面即使写了「下一步：…」也不算。
    """
    steps = [line for line in body.splitlines() if line.startswith("下一步：")]
    return bool(steps) and CAPACITY_REACHED in steps[-1]


def action_line(attempt: Attempt, body: str | None = None) -> str:
    """消息头下面那一行：要不要你动手、做什么（DESIGN §104.9 三）。纯函数，按 role、noticeKind 与提醒令牌判别。

    结果回执与提醒类正文里有「下一步：」行时追加「（见末尾下一步）」；交接、复核、定时提醒的正文是发起方内容，不追加。
    回执与提醒类在正文下一步含容量措辞时一律写 ACTION_CAPACITY（§104.11）。
    """
    text = attempt.body if body is None else body
    if attempt.role is Role.HANDOFF:
        return ACTION_HANDOFF
    if attempt.role is Role.REVIEW:
        return ACTION_REVIEW
    if attempt.is_closure:
        return ACTION_NONE
    if attempt.is_remind:  # 定时提醒也是 fyi：先于告知判
        return ACTION_REMIND
    if attempt.is_fyi:
        return ACTION_NONE
    if attempt.is_note:
        return ACTION_NOTE
    if attempt.is_nudge:
        return ACTION_NUDGE
    token = attempt.options.get(REMINDER_OPTION)
    kind = attempt.options.get(NOTICE_KIND_OPTION)
    if attempt.is_silent_reminder:
        line = ACTION_SILENT
    elif isinstance(token, str):
        line = _reminder_action(token)
    elif kind is None or kind == "result":
        # 结果回执：本机没有 noticeKind，联邦记 noticeKind=result；种类读 receiptOf，缺或闭集外走兜底
        receipt = attempt.receipt_of
        line = RECEIPT_ACTIONS[receipt] if receipt is not None else ACTION_RECEIPT
    else:
        return ACTION_FALLBACK
    if _at_capacity(text):
        return ACTION_CAPACITY  # 已写明「按末尾下一步」，不再追加括号
    return line + NEXT_STEP_SUFFIX if _has_next_step(text) else line


@dataclass(frozen=True)
class Header:
    """解析出的消息头；只用于关联，不作为权限凭据。"""

    task_id: str
    attempt: int
    message_id: str
    role: Role
    sender: str | None
    # 发送方所在设备：本机投递一律是本机名，旧格式的消息没有这个字段（DESIGN §45.35）
    device: str | None = None


def render(task: Task, attempt: Attempt, *, sender: str, device: str, command: str | None = None,
           origin_device: str | None = None, attachment_lines: list[str] | None = None) -> str:
    """生成发给对方的完整文本；`device` 是发送方所在设备（本机投递即本机名，由调用方注入以便测试固定）。

    结构：消息头 → 第二行（action_line）→「任务：」→ 空行 → 正文 → 附件 → 尾注。第二行不进账本正文，返工不会嵌套。

    `command` 缺省按本进程入口解析：页脚里的命令必须是对方能直接敲的那个名字（DESIGN §45.36）。
    联邦任务（DESIGN §88.8）另给 `origin_device`（发起设备 slug，页脚 report/status 都带 `--origin-device`）与
    `attachment_lines`（接收侧 manifest 渲染的附件段，取代本机「引用文件」段）；两者都缺省时输出与本机逐字相同。
    """
    command = command or command_name()
    route = f" --origin-device {origin_device}" if origin_device else ""
    lines = [
        f"{HEADER_TAG} task={task.id} attempt={attempt.seq} msg={attempt.message_id}"
        f" role={attempt.role.value} from={sender} device={device}",
        action_line(attempt),  # 第二行：消息头逐字不变，两个读方只认首行（§104.2）
    ]
    if task.title:
        lines.append(f"任务：{task.title}")
    lines.append("")
    lines.append(attempt.body.rstrip())
    if attachment_lines is not None:
        if attachment_lines:
            lines.append("")
            lines.append("附件：")
            lines.extend(attachment_lines)
    elif attempt.refs:
        lines.append("")
        lines.append("引用文件：")
        for ref in attempt.refs:
            digest = str(ref.get("sha256", ""))[:12]
            lines.append(f"- {ref.get('path')}（sha256 {digest}）")
    if attempt.is_closure:
        # 单向同步：只给查看命令，不附汇报命令，避免形成来回（DESIGN §45.31.6）
        lines.append("")
        lines.append(f"（AgentStatus 协作桥结束回执：不需要 {command} report；详情 {command} status {task.id[:8]}{route}）")
        return "\n".join(lines)
    if attempt.is_remind:
        # 定时提醒（§104.11 第 6 条）：也是 fyi，先于告知判。告知尾注写「只需读到」，与第二行「按下面的提醒内容处理」
        # 矛盾，而 G-9 按尾注识别告知，所以给专属尾注；仍不附汇报命令
        lines.append("")
        lines.append(f"（AgentStatus 协作桥定时提醒：这是你自己排的提醒，按上面的内容处理；不需要 {command} report。）")
        return "\n".join(lines)
    if attempt.is_fyi:
        # 一句话告知（DESIGN §95.5.7）：单向，只需读到，不附汇报或查看命令
        lines.append("")
        lines.append(f"（AgentStatus 协作桥告知消息：只需读到，不需要 {command} report，也不用回复发起方。）")
        return "\n".join(lines)
    for_seq = attempt.note_for_seq
    if for_seq is not None:
        # 任务内补充消息（DESIGN §95.5.2）：不汇报这条，继续当前尝试，汇报命令仍指向所补的那次工作尝试
        lines.append("")
        lines.append(
            f"（AgentStatus 协作桥补充消息：这是任务 {task.id} 第 {for_seq} 次尝试的补充，不需要 {command} report"
            f" 这条消息；继续当前尝试，完成后仍按 `{command} report {task.id}{route} --attempt {for_seq} …` 汇报。）"
        )
        return "\n".join(lines)
    if attempt.role is Role.NOTICE:
        lines.append("")
        lines.append(f"（AgentStatus 协作桥通知；查看详情：{command} status {task.id[:8]}{route}）")
        return "\n".join(lines)
    base = f"{command} report {task.id}{route} --attempt {attempt.seq}"
    lines.append("")
    lines.append("---")
    if attempt.role is Role.REVIEW:
        lines.extend(
            [
                f"请复核上面的结果，并用 {command} 给出结论（本段由 AgentStatus 协作桥附加）：",
                f"- 开始复核：{base} --ack",
                f'- 通过：{base} --approve --note "一句话结论" [--file 审查报告]',
                f'- 需要修改：{base} --changes --note "主要问题" [--file 审查报告]',
            ]
        )
    else:
        lines.extend(
            [
                f"处理这项任务时请用 {command} 汇报，便于发起方和用户跟踪（本段由 AgentStatus 协作桥附加）：",
                f"- 开始处理：{base} --ack",
                f'- 完成：{base} --result --note "一句话结论" [--file 结果文件] [--commit 提交]',
                # §104.9 三：长任务保活（沉默提醒的锚点随 --progress 移动）与不结束尝试的提问
                f'- 还在做（长任务保活）：{base} --progress --note "进展"',
                f'- 需要发起方回答：{base} --ask --note "问题"',
                f'- 受阻或无法完成：{base} --blocked --note "原因"',
            ]
        )
    return "\n".join(lines)


def parse_header(text: str) -> Header | None:
    """解析首行消息头；引用或转述中的头不在首行时不匹配。"""
    first = text.split("\n", 1)[0].rstrip("\r")
    match = _HEADER.fullmatch(first)
    if match is None:
        return None
    return Header(
        task_id=match.group("task"),
        attempt=int(match.group("attempt")),
        message_id=match.group("message"),
        role=Role(match.group("role")),
        sender=match.group("sender"),
        device=match.group("device"),
    )
