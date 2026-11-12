"""agent 汇报处理：归属核验、状态推进，以及复核流程与发起方通知的后续消息。

归属规则（DESIGN §45.5）：调用者所在的 agent 会话必须就是该尝试的接收会话，同一会话有多个
存活进程时还须是实际投递到的那个进程；有 agent 迹象却对不上任何端点的一律拒绝；用户终端需
显式 `--manual` 代为补记。只推进当前尝试，陈旧尝试、已交结果后的重复结果都拒绝。

原子性：文件 hash 与提交校验在事务外完成；随后在一个事务内重新校验并写入汇报、复核结论与
后续请求。中断或并发重复时整体回滚或被拒；仅容量不足时跳过后续请求并记事件，
不丢失已交结果。自动复核排不进时改通知发起方（DESIGN §83）。
"""

from __future__ import annotations
from .platforms.factory import get_platform
from .platforms.types import Presence

from collections.abc import Callable
from dataclasses import dataclass, field, replace
import hashlib
from pathlib import Path
import re
import subprocess

from .platforms import process as procfs
from .ids import short
from .endpoints import Caller, codex_holdings
from .model import (
    UNRESOLVED_NATIVE_ID,
    Attempt,
    Delivery,
    EndpointRef,
    Flow,
    Provider,
    ReportKind,
    Role,
    Task,
    Verdict,
    Work,
    work_attempts,
)
from .labels import next_step, review_capacity_hint
from .paths import codex_home as default_codex_home
from .store import CAPACITY_CODES, MAX_BODY_BYTES, MAX_FILES, Store, StoreError
from .native_names import NO_NAMES, NameBook
from .notification_policy import can_notify

MAX_NOTE_CHARS = 4000
MAX_HASH_BYTES = 256 * 1024 * 1024
_COMMIT = re.compile(r"[0-9a-fA-F]{7,64}")
_UNSENT = (Delivery.PENDING, Delivery.SENDING, Delivery.CANCELLED)

REPORT_LABELS: dict[ReportKind, str] = {
    ReportKind.ACK: "已开始处理",
    ReportKind.PROGRESS: "进展",
    ReportKind.RESULT: "已完成",
    ReportKind.BLOCKED: "受阻",
    ReportKind.FAILED: "无法完成",
    ReportKind.APPROVE: "复核通过",
    ReportKind.CHANGES: "复核要求修改",
}


class ReportError(Exception):
    """汇报被拒绝，带固定原因码。"""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


@dataclass(frozen=True)
class ReportInput:
    task_ref: str
    kind: ReportKind
    attempt_seq: int | None = None
    note: str | None = None
    files: tuple[str, ...] = ()
    commit: str | None = None
    manual: bool = False


@dataclass
class ReportOutcome:
    task: Task
    attempt: Attempt
    followups: list[Attempt] = field(default_factory=list)
    # 容量降级路线（review/result）到原因码；只影响展示，不用它恢复或重发。
    skipped: dict[str, str] = field(default_factory=dict)


GitRunner = Callable[[Path, str], str | None]


def _git_resolve_commit(cwd: Path, value: str) -> str | None:
    try:
        completed = get_platform().lifecycle.run_capture(
            ["git", "-C", str(cwd), "rev-parse", "--verify", "--quiet", f"{value}^{{commit}}"],
            timeout=5.0,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    resolved = completed.stdout.strip()
    return resolved if completed.returncode == 0 and _COMMIT.fullmatch(resolved) else None


def file_reference(path: str, *, cwd: Path) -> dict[str, object]:
    """固定一个结果文件：绝对路径、大小与 sha256（流式计算，不读入内存）。"""
    candidate = Path(path).expanduser()
    if not candidate.is_absolute():
        candidate = cwd / candidate
    try:
        resolved = candidate.resolve(strict=True)
        if not resolved.is_file():
            raise ReportError("file_unreadable")
        size = resolved.stat().st_size
        if size > MAX_HASH_BYTES:
            raise ReportError("file_too_large")
        digest = hashlib.sha256()
        with resolved.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
    except OSError as error:
        raise ReportError("file_unreadable") from error
    return {"path": str(resolved), "size": size, "sha256": digest.hexdigest()}


def _commit_reference(value: str, *, cwd: Path, git: GitRunner) -> dict[str, object]:
    text = value.strip()
    if not _COMMIT.fullmatch(text):
        raise ReportError("commit_invalid")
    resolved = git(cwd, text)
    return {"commit": (resolved or text).lower(), "verified": resolved is not None}


def _describe_result(result: dict[str, object]) -> list[str]:
    lines: list[str] = []
    note = result.get("note")
    if isinstance(note, str) and note:
        lines.append(f"结论：{note}")
    files = result.get("files")
    if isinstance(files, list):
        for item in files:
            if isinstance(item, dict):
                digest = str(item.get("sha256", ""))[:12]
                lines.append(f"文件：{item.get('path')}（sha256 {digest}）")
    commit = result.get("commit")
    if isinstance(commit, dict) and isinstance(commit.get("commit"), str):
        lines.append(f"提交：{commit['commit']}")
    return lines


def _fit_body(lines: list[str], tail: str) -> str:
    head = "\n".join(lines)
    budget = MAX_BODY_BYTES - len(head.encode("utf-8")) - 64
    encoded = tail.encode("utf-8")
    if len(encoded) > budget:
        tail = encoded[: max(budget, 0)].decode("utf-8", errors="ignore") + "\n…（原始任务过长，已截断）"
    return f"{head}\n{tail}" if tail else head


def review_request_body(implement: Attempt, result: dict[str, object], names: NameBook = NO_NAMES) -> str:
    """复核请求：固定结果在前，原始任务要求在后；执行方标识走 NameView（本机已核实主名，否则完整 ID）。"""
    lines = [f"请复核 {names.local_wire(implement.target)} 完成的这项工作。", "", "【结果】"]
    lines.extend(_describe_result(result) or ["（对方未附说明）"])
    lines.extend(["", "【原始任务要求】"])
    return _fit_body(lines, implement.body.rstrip())


def notice_body(
    task: Task, attempt: Attempt, kind: ReportKind, result: dict[str, object], *, next_text: str | None = None,
    names: NameBook = NO_NAMES,
) -> str:
    """回告发起方的结果通知；next_text 是写入后任务阶段对应的下一步（DESIGN §45.28.2）。"""
    title = f"「{task.title}」" if task.title else ""
    lines = [f"你发起的任务{title}{REPORT_LABELS[kind]}（{names.local_wire(attempt.target)}）。"]
    lines.extend(_describe_result(result))
    if next_text:
        lines.append(f"下一步：{next_text}")
    return "\n".join(lines)


def _select_attempt(task: Task, attempts: list[Attempt], report: ReportInput) -> Attempt:
    if task.finished:
        raise ReportError("task_finished")
    working = work_attempts(attempts)
    if not working:
        raise ReportError("attempt_not_found")
    current = working[-1]
    if report.attempt_seq is None:
        return current
    found = next((item for item in attempts if item.seq == report.attempt_seq), None)
    if found is None:
        raise ReportError("attempt_not_found")
    if found.role is Role.NOTICE:
        raise ReportError("attempt_not_reportable")
    if found.seq != current.seq:
        raise ReportError("stale_attempt")
    return found


def _still_receiving(target: EndpointRef, pid: int, proc_root: Path, home: Path | None) -> bool:
    """投递时记下的进程此刻是不是仍是实际接收方（它仍是同一代之后再问这一句）。

    Codex：仍持有目标 thread（rollout 或 writer lock）才算——托管 daemon 下投递时记下的 TUI 只是视图，从不持有；
    fd 读不到按不持有算（身份是上游注入的正面证据，DESIGN §53.4.2）。Claude 等：活着就算，规则不变——「持有」
    只对 Codex 有定义，套用会让 §45.5 的护栏对 Claude 静默失效（§53 第 3 轮两方 P2）。
    """
    if target.provider is not Provider.CODEX:
        return True
    rollouts, locks = codex_holdings(pid, proc_root, home or default_codex_home())
    thread = target.native_id.lower()
    return thread in rollouts or thread in locks


def _attribute(
    attempt: Attempt, report: ReportInput, caller: Caller, proc_root: Path, *, codex_home: Path | None = None
) -> str:
    """核验汇报来源，返回 agent 或 manual。"""
    if caller.rejection == "subagent":
        # Codex 子代理不能代替根会话汇报：与根会话自己的汇报撞 result_already_submitted（DESIGN §45.48 R3）
        raise ReportError("reporter_is_subagent")
    if get_platform().name == 'windows':
        if caller.rejection is not None or (caller.endpoint is None and not caller.is_user_shell):
            raise ReportError('caller_unattributed')
        if caller.endpoint is not None:
            if not caller.endpoint.ref.same_session(attempt.target):
                raise ReportError('reporter_mismatch')
            if attempt.target.provider is Provider.CLAUDE:
                expected_pid = attempt.delivery_detail.get('deliveredPid', attempt.target.pid)
                expected_start = attempt.delivery_detail.get('deliveredStart', attempt.target.start_ticks)
                ref = caller.endpoint.ref
                if (ref.pid, ref.start_ticks) != (expected_pid, expected_start):
                    if type(expected_pid) is not int or not isinstance(expected_start, str):
                        raise ReportError('reporter_unattributed')
                    from .platforms.windows.commands import receiver_presence  # layout: allow native prior-peer generation proof
                    current = receiver_presence(expected_pid, expected_start)
                    if current is Presence.CURRENT:
                        raise ReportError('reporter_generation_mismatch')
                    if current is not Presence.EXITED:
                        raise ReportError('reporter_unattributed')
            # Current authenticated loaded-root attribution already proves the
            # caller's daemon generation. Historical daemon death is not revocation.
            return 'agent'
    if caller.endpoint is not None and caller.endpoint.ref.native_id == UNRESOLVED_NATIVE_ID:
        # 认不出是哪个 thread 不是身份（§45.48 R5）：按未归属报，不说成「不是收件会话」
        raise ReportError("reporter_unattributed")
    if caller.endpoint is not None:
        ref = caller.endpoint.ref
        if not ref.same_session(attempt.target):
            raise ReportError("reporter_mismatch")
        detail = attempt.delivery_detail
        expected_pid = detail.get("deliveredPid", attempt.target.pid)
        expected_start = detail.get("deliveredStart", attempt.target.start_ticks)
        if (
            isinstance(expected_pid, int)
            and isinstance(expected_start, str)
            and (ref.pid, ref.start_ticks) != (expected_pid, expected_start)
            # 汇报方的 agent 进程就是投递进程本身：包装进程下的 TUI 在 F02 时组落到标题路径、端点换成包装进程，
            # 但汇报的仍是收件人（Opus 实现复核第 2 轮 P3-1）
            and not (
                caller.agent_process is not None
                and (caller.agent_process.pid, caller.agent_process.start_ticks) == (expected_pid, expected_start)
            )
            and procfs.is_same_generation(expected_pid, expected_start, proc_root)
            and _still_receiving(attempt.target, expected_pid, proc_root, codex_home)
        ):
            # 实际收到消息的进程仍在，另一个同会话进程不能替它汇报
            raise ReportError("reporter_generation_mismatch")
        return "agent"
    if caller.agent_process is not None or caller.agent_env:
        raise ReportError("reporter_unattributed")
    if report.manual:
        return "manual"
    raise ReportError("manual_flag_required")


def _check_kind(attempt: Attempt, report: ReportInput) -> None:
    kind = report.kind
    if kind in (ReportKind.APPROVE, ReportKind.CHANGES) and attempt.role is not Role.REVIEW:
        raise ReportError("verdict_requires_review")
    if kind is ReportKind.RESULT and attempt.role is Role.REVIEW:
        raise ReportError("review_requires_verdict")
    if attempt.delivery in _UNSENT:
        raise ReportError("attempt_not_sent")
    if attempt.work in (Work.RESULT, Work.FAILED):
        raise ReportError("result_already_submitted")
    if len(report.files) > MAX_FILES:
        raise ReportError("too_many_files")


def apply_report(
    store: Store,
    report: ReportInput,
    *,
    caller: Caller,
    caller_class: str | None,
    now: float,
    cwd: Path,
    git: GitRunner = _git_resolve_commit,
    proc_root: Path = procfs.DEFAULT_PROC,
    codex_home: Path | None = None,
    names: NameBook = NO_NAMES,
) -> ReportOutcome:
    """核验并原子记录一条汇报；必要时一并排队复核请求或发起方通知（由 worker 发送）。"""
    task = store.resolve_task(report.task_ref)
    # 事务外先做一次校验：尽早给出可读错误，避免无谓的文件 hash
    preview = _select_attempt(task, store.attempts(task.id), report)
    _attribute(preview, report, caller, proc_root, codex_home=codex_home)
    _check_kind(preview, report)
    # 固定首次选定的尝试：hash/提交校验期间若出现新尝试，事务内按 stale_attempt 拒绝，不会改投
    report = replace(report, attempt_seq=preview.seq)

    files = [file_reference(path, cwd=cwd) for path in report.files]
    note = (report.note or "").strip()[:MAX_NOTE_CHARS]
    commit = _commit_reference(report.commit, cwd=cwd, git=git) if report.commit else None

    followups: list[Attempt] = []
    skipped: dict[str, str] = {}
    with store.transaction():
        # 事务内重新读取并校验：并发的重复汇报在这里被拒绝
        current_task = store.get_task(task.id)
        if current_task is None:
            raise ReportError("task_not_found")
        attempts = store.attempts(task.id)
        attempt = _select_attempt(current_task, attempts, report)
        source = _attribute(attempt, report, caller, proc_root, codex_home=codex_home)
        _check_kind(attempt, report)
        kind = report.kind
        detail: dict[str, object] = {"source": source}
        if note:
            detail["note"] = note

        # 接收方汇报本身就证明消息已送达
        if attempt.delivery is not Delivery.DELIVERED:
            store.transition_delivery(
                attempt.id,
                expected=tuple(state for state in Delivery if state not in (*_UNSENT, Delivery.DELIVERED)),
                new=Delivery.DELIVERED,
                reason="receiver_reported",
                now=now,
            )

        result: dict[str, object] = {"note": note, "files": files, "source": source, "reportedAt": now}
        if commit is not None:
            result["commit"] = commit
        if kind is ReportKind.ACK:
            if attempt.work is Work.AWAITING_ACK:
                store.set_work(attempt.id, work=Work.ACKNOWLEDGED, result=None, now=now, event="ack", detail=detail)
            else:
                store.add_event(task.id, "ack", now=now, attempt_seq=attempt.seq, detail=detail)
        elif kind is ReportKind.PROGRESS:
            store.set_work(attempt.id, work=Work.IN_PROGRESS, result=None, now=now, event="progress", detail=detail)
        elif kind is ReportKind.BLOCKED:
            store.set_work(attempt.id, work=Work.BLOCKED, result=None, now=now, event="blocked", detail=detail)
        elif kind is ReportKind.FAILED:
            store.set_work(attempt.id, work=Work.FAILED, result=result, now=now, event="failed", detail=detail)
        else:
            store.set_work(attempt.id, work=Work.RESULT, result=result, now=now, event=kind.value, detail=detail)
            if kind is ReportKind.APPROVE:
                store.update_task(task.id, now=now, event="verdict_approved", verdict=Verdict.APPROVED.value)
            elif kind is ReportKind.CHANGES:
                store.update_task(task.id, now=now, event="verdict_changes", verdict=Verdict.CHANGES.value)

        first = work_attempts(attempts)[0]
        if (
            kind is ReportKind.RESULT
            and attempt.role is Role.HANDOFF
            and current_task.flow is Flow.REVIEW
            and current_task.reviewer is not None
        ):
            if not can_notify(current_task.reviewer):
                raise ReportError('target_no_inbox')  # rolls back result and auto-review together
            try:
                followups.append(store.add_attempt(
                    task.id,
                    role=Role.REVIEW,
                    target=current_task.reviewer,
                    body=review_request_body(attempt, result, names),
                    refs=files,
                    now=now,
                    sender=first.sender,
                    sender_class=first.sender_class,
                    # 登记工作流时对共享 thread 的放行同样适用于复核目标
                    options={"allowShared": first.allow_shared or current_task.options.get("allowShared") is True},
                ))
            except StoreError as error:
                if error.code not in CAPACITY_CODES:
                    raise
                skipped['review'] = error.code
                store.add_event(task.id, 'review_skipped_capacity', now=now, attempt_seq=attempt.seq,
                                detail={'reason': error.code})
        if (
            not followups
            and kind in (ReportKind.RESULT, ReportKind.BLOCKED, ReportKind.FAILED, ReportKind.APPROVE, ReportKind.CHANGES)
            and current_task.origin is not None
            and current_task.notify_origin
            and can_notify(current_task.origin)
            and not current_task.origin.same_session(attempt.target)
        ):
            # 发起方最容易忘的是收尾：按本次写入后的阶段写明下一步（验收/返工/关闭），事务内读得到刚写入的状态
            written_task = store.get_task(task.id) or current_task
            step = next_step(written_task, store.attempts(task.id), ref=short(task.id), reserved=1)
            next_text = step.text if step else None
            if 'review' in skipped:
                next_text = review_capacity_hint(skipped['review'])
            try:
                followups.append(store.add_attempt(
                    task.id,
                    role=Role.NOTICE,
                    target=current_task.origin,
                    body=notice_body(current_task, attempt, kind, result, next_text=next_text, names=names),
                    refs=files,
                    now=now,
                    sender=caller.endpoint.ref if caller.endpoint else None,
                    sender_class=caller_class,
                ))
            except StoreError as error:
                if error.code not in CAPACITY_CODES:
                    raise
                skipped['result'] = error.code
                store.add_event(task.id, 'notification_skipped', now=now, attempt_seq=attempt.seq,
                                detail={'reason': error.code, 'route': 'result'})
        elif (not followups and current_task.origin is not None and not can_notify(current_task.origin)
              and kind in (ReportKind.RESULT, ReportKind.BLOCKED, ReportKind.FAILED, ReportKind.APPROVE, ReportKind.CHANGES)):
            store.add_event(task.id, 'notification_skipped', now=now, attempt_seq=attempt.seq,
                            detail={'reason': 'poll_only', 'route': 'result'})
    refreshed = store.get_task(task.id)
    updated = store.get_attempt(attempt.id)
    if refreshed is None or updated is None:
        raise StoreError("corrupt_record")
    return ReportOutcome(task=refreshed, attempt=updated, followups=followups, skipped=skipped)
