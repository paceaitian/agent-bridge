"""投递给接收会话的消息格式：一行机器可读头、正文，以及教对方如何用 ab 汇报的说明。"""

from __future__ import annotations

from dataclasses import dataclass
import re

from .model import Attempt, Role, Task
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

    `command` 缺省按本进程入口解析：页脚里的命令必须是对方能直接敲的那个名字（DESIGN §45.36）。
    联邦任务（DESIGN §88.8）另给 `origin_device`（发起设备 slug，页脚 report/status 都带 `--origin-device`）与
    `attachment_lines`（接收侧 manifest 渲染的附件段，取代本机「引用文件」段）；两者都缺省时输出与本机逐字相同。
    """
    command = command or command_name()
    route = f" --origin-device {origin_device}" if origin_device else ""
    lines = [
        f"{HEADER_TAG} task={task.id} attempt={attempt.seq} msg={attempt.message_id}"
        f" role={attempt.role.value} from={sender} device={device}"
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
