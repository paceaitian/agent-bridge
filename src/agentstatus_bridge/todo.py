"""`ab todo`（DESIGN §104.3、§104.9 六）：只列需要调用方会话动手的事，每项带可照抄的命令。

五类（身份与 `ab tasks --mine` 同口径，按会话 ID）：
- 待你验收：你发起、已交结果；
- 待你处理：你发起、需处理（受阻、失败、确定未送达、对方提问等）；
- 待你汇报：你是当前交接的接收方、已交出、还没交结果，且不在提问等回答；
- 待你复核：同上，复核尝试；
- 对方沉默：你发起、满足沉默条件且已满 T。

本模块只做纯判定：本机任务与联邦权威任务（经 model_task/model_attempts 投影）共用 local_items；镜像上的汇报项由
CLI 用 mirror.local_report_target 判定后调用 report_item。

可照抄的命令（DESIGN §104.11 第 1 条）：每个选项一条完整命令，不含任何 shell 元字符；占位写成带引号的中文
（如 `--note "结论"`），文字模式用全角「｜」分隔。整行照抄时「｜」会成为多余的参数，命令被解析器拒绝、不落账。
命令里一律写完整任务 ID（§104.12 第 1 条）：本机与联邦两个库里前八位相同的任务，短 ID 会命中本机那一项；短 ID
只用于展示。标题在行模型里保留原值（--json 照给），只在文字渲染时按来源转义（§104.12 第 11 条）。
"""

from __future__ import annotations

from dataclasses import dataclass

from .ids import short
from .labels import next_step
from .model import (
    HANDED_OVER,
    Attempt,
    EndpointRef,
    Phase,
    Role,
    Task,
    Work,
    ask_pending,
    describe,
    on_task_device,
)
from .native_names import remote_display
from .reminders import silent_now
from .store import attempt_limit

CATEGORY_LABELS: dict[str, str] = {
    "accept": "待你验收",
    "handle": "待你处理",
    "report": "待你汇报",
    "review": "待你复核",
    "silent": "对方沉默",
}
# 文字模式里同一项几条命令之间的分隔：全角竖线，整行照抄进 shell 不会被当成管道（§104.11 第 1 条）
COMMAND_SEPARATOR = " ｜ "
_OPEN_WORK = frozenset({Work.AWAITING_ACK, Work.ACKNOWLEDGED, Work.IN_PROGRESS})


@dataclass(frozen=True)
class TodoItem:
    """一项待办：类别闭集码、范围（local/federation）、任务、相关尝试序号与可照抄的命令（每个选项一条）。"""

    category: str
    scope: str
    task_id: str
    title: str
    attempt: int | None
    commands: tuple[str, ...]

    def to_dict(self) -> dict[str, object]:
        """`--json` 的一项（§104.9 六、§104.11 第 1 条）：commands 是列表，每条都能单独照抄执行。"""
        return {"category": self.category, "scope": self.scope, "taskId": self.task_id, "short": short(self.task_id),
                "title": self.title, "attempt": self.attempt, "commands": list(self.commands)}


def report_item(task_id: str, title: str, work: Attempt, *, command: str, scope: str,
                origin_device: str | None = None, ref: str | None = None) -> TodoItem:
    """待你汇报／待你复核：按角色给出各结论一条完整命令（完整任务 ID）；镜像上的命令带 --origin-device。

    ref 是调用方已拼好的任务引用（联邦权威端的「完整 ID --origin-device <本机>」，§104.13 第 2 条），给了就用它。
    """
    route = f" --origin-device {origin_device}" if origin_device else ""
    base = f"{command} report {ref or task_id + route} --attempt {work.seq}"
    if work.role is Role.REVIEW:
        return TodoItem("review", scope, task_id, title, work.seq,
                        (f'{base} --approve --note "一句话结论"', f'{base} --changes --note "主要问题"'))
    return TodoItem("report", scope, task_id, title, work.seq,
                    (f'{base} --result --note "一句话结论"', f'{base} --blocked --note "原因"',
                     f'{base} --progress --note "进展"'))


def _accept_commands(task: Task, attempts: list[Attempt], view_reason: str, *, command: str,
                     ref: str) -> tuple[str, ...]:
    accept = f"{command} accept {ref}"
    room = max((item.seq for item in attempts), default=0) < attempt_limit(Role.HANDOFF)
    # 复核通过时普通 retry 是重新复核且要 --force，不建议（与 next_step 同口径）
    if view_reason == "result_ready" and room:
        return (accept, f'{command} retry {ref} -m "返工要求"')
    return (accept,)


def local_items(task: Task, attempts: list[Attempt], me: EndpointRef, *, now: float, command: str,
                scope: str = "local", command_ref: str | None = None) -> list[TodoItem]:
    """一项任务里调用方 me 要动手的事（可能有发起方一侧与接收方一侧各一项）。

    me 在任务所在的设备上：本机账本，或联邦任务的权威端（镜像行另走 report_item）。接收方一侧还要求工作目标就在
    这台设备上——别的设备上的同号会话不是 me（§104.13 第 4 条）。

    command_ref 是命令里的任务引用：本机缺省完整 ID；联邦权威任务由调用方传「完整 ID --origin-device <本机>」
    （§104.13 第 2 条），两库完整 ID 相同时也只作用到这一项。
    """
    if task.finished:
        return []
    view = describe(task, attempts)
    ref = command_ref or task.id  # 命令用完整 ID：短 ID 跨库可能命中别的任务（§104.12 第 1 条）
    items: list[TodoItem] = []
    current = view.current
    if task.origin is not None and task.origin.same_session(me):
        if view.phase is Phase.AWAITING_ACCEPTANCE:
            items.append(TodoItem("accept", scope, task.id, task.title, current.seq if current else None,
                                  _accept_commands(task, attempts, view.reason, command=command, ref=ref)))
        elif view.phase is Phase.NEEDS_ATTENTION:
            # 只取下一步的命令字段：文字说明是给人读的句子，不能当命令照抄；没有命令时给查看
            step = next_step(task, attempts, ref=ref, command=command, now=now)
            found = step.command if step is not None and step.command else f"{command} status {ref}"
            items.append(TodoItem("handle", scope, task.id, task.title, current.seq if current else None, (found,)))
        elif silent_now(task, attempts, now) and current is not None:
            items.append(TodoItem("silent", scope, task.id, task.title, current.seq,
                                  (f'{command} note {ref} -m "问题"', f"{command} status {ref}")))
    # 待你汇报/复核只列已交出的尝试（§104.12 第 2 条）：确定未送达、拒收、等批准、结果不明的都不列，
    # 免得对没交到手的交接直接交终态结果；接收方汇报兼作送达证明的兼容规则留在汇报入口
    if (current is not None and current.role is not Role.NOTICE and current.target.same_session(me)
            and on_task_device(task, current) and not task.paused and current.delivery in HANDED_OVER and current.work in _OPEN_WORK
            and not ask_pending(current, attempts)):
        items.append(report_item(task.id, task.title, current, command=command, scope=scope, ref=ref))
    return items


def text_line(item: TodoItem) -> str:
    """文字模式的一行：类别、短 ID、标题（截 40 字）与命令；几条命令之间用全角「｜」分隔，每条可单独照抄。

    跨设备任务的标题来自另一台设备：在这里按远端字符串转义（换行、控制字符写成 \\uXXXX），保证一项一行；
    行模型与 --json 保留原标题（§104.12 第 11 条）。"""
    title = (remote_display(item.title) or "") if item.scope == "federation" else item.title
    return (f"{CATEGORY_LABELS[item.category]}  {short(item.task_id)}  {title[:40]}  → "
            f"{COMMAND_SEPARATOR.join(item.commands)}")
