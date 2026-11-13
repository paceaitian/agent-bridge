"""协作桥命令的展示层：把账本里的任务与尝试投影成 `--json` 文档或终端文字（DESIGN §48 R6，审计 H1）。

只读 Store、只写 stdout，不做发现、不拉起 worker、不改账本；命令编排留在 `cli`。
投递明细的诊断视图规则（DESIGN §45.43 2.3/2.4）也在这里，summary 与 worker 不经过本模块。
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
import re
import time
from typing import Any

from .closure import ClosureOutcome
from .native_names import NO_NAMES, NameBook
from .ids import short
from .labels import (
    CONSUMPTION_LABELS,
    DELIVERY_LABELS,
    EVENT_LABELS,
    WORK_LABELS,
    next_step,
    reason_text,
    role_label,
    review_capacity_hint,
    notification_capacity_hint,
)
from .model import (
    CLOSURE_KIND,
    CLOSURE_STATE_OPTION,
    PHASE_LABELS,
    Attempt,
    Consumption,
    Delivery,
    EndpointRef,
    Flow,
    Provider,
    Role,
    Task,
    describe,
)
from .naming import command_name
from .store import CAPACITY_CODES, Store
from .platforms.factory import get_platform


def _no_pane_warning(attempts: list[Attempt]) -> str | None:
    if get_platform().name == 'windows' and any(
            a.target.provider is Provider.CODEX and a.target.pane is None for a in attempts):
        from .platforms.windows.codex_discovery import NO_PANE_WARNING  # layout: allow Windows展示独立告警，无发现IO
        return NO_PANE_WARNING
    return None


def _age(timestamp: float | None, now: float) -> str:
    if timestamp is None:
        return ""
    seconds = max(0, int(now - timestamp))
    if seconds < 60:
        return f"{seconds} 秒前"
    if seconds < 3600:
        return f"{seconds // 60} 分钟前"
    if seconds < 86400:
        return f"{seconds // 3600} 小时前"
    return f"{seconds // 86400} 天前"


def _clock(timestamp: float) -> str:
    return time.strftime("%m-%d %H:%M:%S", time.localtime(timestamp))


def _ref_document(ref: EndpointRef | None, names: NameBook = NO_NAMES) -> dict[str, object] | None:
    if ref is None:
        return None
    return {
        "provider": ref.provider.value,
        # 本机可复制标识（§91.4.2）：同绑定已核实的原生主名，否则完整 ID；不回退 ref.label/pane
        "name": names.local_wire(ref),
        "pane": ref.pane,
        "nativeId": ref.native_id,
    }


# 投递明细的诊断视图（DESIGN §45.43 2.3/2.4）。键集随 provider 变化、不承诺稳定，不能拿来做调度、
# 终态或身份判定——判断请用 delivery/deliveryReason 这些合同字段。不合规的键值整体省略并打标记，
# 不截断、不放占位串：截断后的值与真实值、占位串与真实字符串都无从分辨（Codex 复核 R02）。
# 这道规则只约束形状与体积，不保证无正文；写入方不放正文、路径、凭据仍是硬要求。
_DETAIL_KEY = re.compile(r"[A-Za-z][A-Za-z0-9_]{0,31}")


_DETAIL_STRING_LIMIT = 64


def project_delivery_detail(detail: Mapping[str, object]) -> tuple[dict[str, object], bool]:
    """按诊断视图规则投影账本里的 `delivery_detail`，返回（可展示的键值, 是否省略过）。"""
    shown: dict[str, object] = {}
    redacted = False
    for key, value in detail.items():
        if isinstance(key, str) and _DETAIL_KEY.fullmatch(key) and _is_short_scalar(value):
            shown[key] = value
        else:
            redacted = True
    return shown, redacted


def _is_short_scalar(value: object) -> bool:
    if value is None or isinstance(value, bool | int):
        return True
    return isinstance(value, str) and len(value) <= _DETAIL_STRING_LIMIT


def _attempt_document(attempt: Attempt, *, include_body: bool, names: NameBook = NO_NAMES) -> dict[str, object]:
    detail, redacted = project_delivery_detail(attempt.delivery_detail)
    document: dict[str, object] = {
        "seq": attempt.seq,
        "role": attempt.role.value,
        "target": _ref_document(attempt.target, names),
        "sender": _ref_document(attempt.sender, names),
        "senderClass": attempt.sender_class,
        "messageId": attempt.message_id,
        "createdAt": attempt.created_at,
        "delivery": attempt.delivery.value,
        "deliveryReason": attempt.delivery_reason,
        "deliveryAt": attempt.delivery_at,
        "deliveryDetail": detail,
        # 为 true 时展示的不是账本原值的全集，不得与账本做字节级比对
        "deliveryDetailRedacted": redacted,
        "providerRef": attempt.provider_ref,
        "consumption": attempt.consumption.value,
        "work": attempt.work.value,
        "workAt": attempt.work_at,
        "result": attempt.result,
        "refs": attempt.refs,
        "bodyBytes": len(attempt.body.encode("utf-8")),
    }
    if attempt.is_closure:
        # 结束回执（DESIGN §45.31）：role 仍是 notice，另标类别与终态
        document["kind"] = CLOSURE_KIND
        document["closure"] = attempt.options.get(CLOSURE_STATE_OPTION)
    if include_body:
        document["body"] = attempt.body
    return document


@dataclass(frozen=True)
class _TargetHint:
    """查询时派生的对方提示：停下未汇报的轮次结束时刻（§45.9），或当前未发现对方会话（§45.32）；两者互斥。"""

    stopped_at: float | None = None
    missing: bool = False


_NO_HINT = _TargetHint()


def _withdrawal_document(store: Store, task: Task) -> dict[str, Any]:
    readable = store.withdrawals_readable
    return {"version": 1, "readable": readable,
            "reason": None if readable else "withdraw_store_unreadable",
            "operations": store.withdrawals(task.id) if readable else []}


def _withdrawn(attempt: Attempt | None, operations: list[dict[str, Any]]) -> bool:
    return attempt is not None and attempt.delivery is Delivery.QUEUED and any(
        item["attemptSeq"] == attempt.seq and item["state"] == "deleted" for item in operations)


def _task_document(
    store: Store,
    task: Task,
    *,
    include_body: bool = False,
    events: bool = False,
    hint: _TargetHint = _NO_HINT,
    names: NameBook = NO_NAMES,
) -> dict[str, object]:
    attempts = store.attempts(task.id)
    view = describe(task, attempts)
    withdrawals = _withdrawal_document(store, task)
    if _withdrawn(view.current, withdrawals["operations"]):
        hint = _NO_HINT
    document: dict[str, object] = {
        "id": task.id,
        "title": task.title,
        "flow": task.flow.value,
        "phase": view.phase.value,
        "phaseLabel": PHASE_LABELS[view.phase],
        "reason": view.reason,
        "reasonText": reason_text(view.reason),
        "origin": _ref_document(task.origin, names),
        "reviewer": _ref_document(task.reviewer, names),
        "control": task.control,
        "verdict": task.verdict.value if task.verdict else None,
        "createdAt": task.created_at,
        "updatedAt": task.updated_at,
        "acceptedAt": task.accepted_at,
        "closedAt": task.closed_at,
        "targetStoppedWithoutReport": hint.stopped_at is not None,
        "targetTurnEndedAt": hint.stopped_at,
        "targetSessionMissing": hint.missing,
        "attempts": [_attempt_document(item, include_body=include_body, names=names) for item in attempts],
        "nativeWithdrawals": withdrawals,
    }
    if events:
        document["events"] = store.events(task.id)
    warning = _no_pane_warning(attempts)
    if warning is not None:
        document['targetWindowWarning'] = warning
    if get_platform().name == 'windows' and task.options.get('receiptMode') == 'poll_only':
        document['receiptMode'] = 'poll_only'
    follows = task.options.get("follows")
    if isinstance(follows, str):
        document["follows"] = follows  # send --follows 记下的旧任务（§93.3）；无关联时不出现该键
    return document


def _next_step(task: Task, attempts: list[Attempt]) -> str | None:
    step = next_step(task, attempts, ref=short(task.id), reserved=0)
    return step.text if step is not None else None


def _describe_result(result: dict[str, Any] | None) -> list[str]:
    if not result:
        return []
    lines: list[str] = []
    note = result.get("note")
    if isinstance(note, str) and note:
        lines.append(f"说明：{note}")
    files = result.get("files")
    if isinstance(files, list):
        for item in files:
            if isinstance(item, dict):
                lines.append(f"文件：{item.get('path')}（sha256 {str(item.get('sha256', ''))[:12]}）")
    commit = result.get("commit")
    if isinstance(commit, dict):
        mark = "" if commit.get("verified") else "（本机未找到该提交）"
        lines.append(f"提交：{commit.get('commit')}{mark}")
    return lines


def _print_task(
    store: Store, task: Task, *, now: float, show_body: bool, hint: _TargetHint = _NO_HINT, names: NameBook = NO_NAMES,
    relations: Sequence[str] = (),
) -> None:
    attempts = store.attempts(task.id)
    view = describe(task, attempts)
    withdrawals = _withdrawal_document(store, task)
    if _withdrawn(view.current, withdrawals["operations"]):
        hint = _NO_HINT
    cmd = command_name()
    title = f"「{task.title}」" if task.title else ""
    print(f"任务 {short(task.id)} {title} {PHASE_LABELS[view.phase]}：{reason_text(view.reason)}")
    flow = "交接" if task.flow is Flow.HANDOFF else f"实现 → 复核（{names.text(task.reviewer) if task.reviewer else '?'}）"
    origin = names.text(task.origin) if task.origin else "用户"
    print(f"流程：{flow}；发起：{origin}；创建于 {_age(task.created_at, now)}")
    for line in relations:  # 承接/后续任务（§93.3），由 cli 跨本机账本与联邦库查好
        print(line)
    if get_platform().name == 'windows' and task.options.get('receiptMode') == 'poll_only':
        print('回执方式：poll_only；用 status / wait 读取，不推送通知。')
    warning = _no_pane_warning(attempts)
    if warning is not None:
        print(warning)
    for attempt in attempts:
        delivery = DELIVERY_LABELS[attempt.delivery]
        if attempt.delivery_reason and attempt.delivery is not Delivery.PENDING:
            text = reason_text(attempt.delivery_reason)
            if text and text != delivery:
                delivery = f"{delivery}（{text}）"
        consumption = CONSUMPTION_LABELS[attempt.consumption]
        if _withdrawn(attempt, withdrawals["operations"]):
            consumption = "本桥已移除该队列项；不证明未执行，不能停止已开始的工作"
        if consumption:
            delivery = f"{delivery}，{consumption}"
        work = "" if attempt.role is Role.NOTICE else f"；工作：{WORK_LABELS[attempt.work]}"
        print(f"  #{attempt.seq} {role_label(attempt)} → {names.text(attempt.target)}：{delivery}{work}")
        for line in _describe_result(attempt.result):
            print(f"      {line}")
        if show_body:
            for line in attempt.body.splitlines():
                print(f"      | {line}")
    if hint.stopped_at is not None and view.current is not None:
        print(
            f"提示：{names.text(view.current.target)} 这一轮已在 {_clock(hint.stopped_at)} 结束，但还没有汇报"
            f"（可能忘了运行 {cmd} report，或在等人回复）；可去对方会话查看或请它补报；确需重发用 "
            f"{cmd} retry {short(task.id)} --force（对方可能已在执行），不再需要可 {cmd} close {short(task.id)}"
        )
    if hint.missing and view.current is not None:
        current = view.current
        ref = short(task.id)
        # 未确证离开 Codex 队列时消息可能还在原生队列里，恢复同一 thread 后会继续执行（docs/ab.md §7）
        maybe_queued = (
            current.target.provider is Provider.CODEX
            and current.delivery is Delivery.QUEUED
            and current.consumption is not Consumption.LEFT_QUEUE
        )
        if maybe_queued:
            action = (
                f"消息尚未确认离开 Codex 队列，若仍在，恢复同一 thread 后可能继续执行，勿直接重发；"
                f"确需 {cmd} retry {ref} --force 重发或加 --to 改派，都可能重复执行"
            )
        else:
            action = f"确已退出可恢复该会话后 {cmd} retry {ref} --force 重发（对方可能已处理过），或加 --to 改派"
        print(
            f"提示：当前未发现 {names.text(current.target)} 的会话（可能已退出，也可能暂时无法识别），还没有汇报，"
            f"先去确认；{action}；不再需要可 {cmd} close {ref}"
        )
    step = _next_step(task, attempts)
    if not withdrawals["readable"]:
        print(f"  原生撤回：{reason_text('withdraw_store_unreadable')}")
    for operation in withdrawals["operations"]:
        print(f"  原生撤回 #{operation['attemptSeq']}：{operation['state']}（{operation['reason']}），"
              f"{_clock(operation['finishedAt'] or operation['createdAt'])}；不证明未执行")
        if operation["ownerStatus"] == "gone":
            print("    执行者已不在，下次 withdraw 恢复；当前仅显示，不改账本")
        elif operation["ownerStatus"] == "namespace_unverified":
            print("    执行者 PID 命名空间不可核对，不判死、不恢复")
    if step:
        print(f"下一步：{step}")
    events = store.events(task.id, limit=20)
    if events:
        print("时间线：")
        for event in events:
            kind = str(event["kind"])
            label = EVENT_LABELS.get(kind)
            if label is None and kind.startswith("delivery_"):
                label = reason_text(kind)
            if label is None and kind.startswith("consumption_"):
                try:
                    label = CONSUMPTION_LABELS[Consumption(kind.removeprefix("consumption_"))] or kind
                except ValueError:
                    label = kind
            detail = event["detail"] if isinstance(event["detail"], dict) else {}
            extra = detail.get("note") or detail.get("text") or reason_text(detail.get("reason"))
            if kind == 'notification_skipped' and detail.get('reason') in CAPACITY_CODES:
                extra = notification_capacity_hint(detail['reason'])
            elif kind == 'review_skipped_capacity' and detail.get('reason') in CAPACITY_CODES:
                extra = review_capacity_hint(detail['reason'])
            suffix = f"：{str(extra)[:160]}" if extra else ""
            seq = f" #{event['attemptSeq']}" if event["attemptSeq"] else ""
            print(f"  {_clock(float(event['at']))}{seq} {label or kind}{suffix}")


def _closure_document(outcome: ClosureOutcome, names: NameBook = NO_NAMES) -> dict[str, object]:
    return {
        "queued": [
            {"seq": item.seq, "target": names.local_wire(item.target)} for item in outcome.queued
        ],
        "skipped": [
            {"role": recipient.source.role.value, "target": names.local_wire(recipient.target), "capacity": capacity}
            for recipient, capacity in outcome.skipped
        ],
    }


def _print_closure(outcome: ClosureOutcome, names: NameBook = NO_NAMES) -> None:
    if outcome.queued:
        queued = "、".join(names.text(item.target) for item in outcome.queued)
        print(f"已排队结束回执 → {queued}（进对方原生队列，不需要汇报）")
    for recipient, _capacity in outcome.skipped:
        print(f"排队容量已满，未给 {names.text(recipient.target)} 排结束回执")
