"""协作桥的中文标签表与原因文案：CLI、摘要发布与 worker 共用（摘要不能导入 cli，cli 会导入 worker）。"""

from __future__ import annotations

from dataclasses import dataclass

from .model import Attempt, Consumption, Delivery, Phase, Role, Runtime, Task, Work, describe
from .naming import command_name
from .store import MAX_BODY_BYTES, MAX_FILES
from .transports.codex_queue import READABLE_REASONS

# 原因文案里的命令名占位：文案是模块级常量，只能在 `reason_text` 里按本次进程的入口名替换
PLACEHOLDER = "{command}"

DELIVERY_LABELS: dict[Delivery, str] = {
    Delivery.PENDING: "桥内排队",
    Delivery.SENDING: "发送中",
    Delivery.WRITTEN: "已写入对方会话（未拒收即已接收）",
    Delivery.QUEUED: "已进入 Codex 队列",
    Delivery.DELIVERED: "已送达",
    Delivery.HELD: "等对方会话批准",
    Delivery.REFUSED: "对方拒收",
    Delivery.DENIED: "对方拒绝",
    Delivery.EXPIRED: "对方未批准，已过期",
    Delivery.FAILED: "未送达",
    Delivery.UNKNOWN: "是否送达不明",
    Delivery.CANCELLED: "已取消（未发送）",
}
WORK_LABELS: dict[Work, str] = {
    Work.NONE: "—",
    Work.AWAITING_ACK: "等待对方确认",
    Work.ACKNOWLEDGED: "已开始处理",
    Work.IN_PROGRESS: "处理中",
    Work.BLOCKED: "受阻",
    Work.RESULT: "已交结果",
    Work.FAILED: "无法完成",
}
CONSUMPTION_LABELS: dict[Consumption, str] = {
    Consumption.NOT_OBSERVED: "",
    Consumption.STILL_QUEUED: "仍在队列中",
    Consumption.LEFT_QUEUE: "已离开队列（开始执行或被删除，以对方汇报为准）",
    Consumption.UNKNOWN: "",
}
ROLE_LABELS: dict[Role, str] = {Role.HANDOFF: "交接", Role.REVIEW: "复核", Role.NOTICE: "通知发起方"}
CLOSURE_LABEL = "结束回执"
RUNTIME_LABELS: dict[Runtime, str] = {
    Runtime.IDLE: "空闲",
    Runtime.BACKGROUND: "后台",
    Runtime.BUSY: "忙",
    Runtime.WAITING: "等待用户",
    Runtime.UNKNOWN: "状态未知",
}
ISSUE_LABELS: dict[str, str] = {
    "no_thread_yet": "还没有会话 thread",
    "ambiguous_thread": "进程打开了多个 thread",
    "shared_thread": "thread 被多个进程加载",
    "socket_unavailable": "消息 socket 不可用",
    "peer_protocol_unsupported": "Claude 消息协议版本不支持",
    "no_inbox": "只读：没有收件通道，只能由它发起",
    "shared_process": "同一进程里还有别的会话",
    # Codex 子代理与同进程多根（DESIGN §45.48 R2）
    "subagent_only": "进程里只看得到 Codex 子代理 thread，不能作为目标",
    "subagent_threads": "进程里还挂着子代理 thread",
    "multiple_roots": "同一进程里有多个根会话（按会话 ID 选择）",
    # Codex 托管 daemon 下按标题认领（DESIGN §53.3.8）
    "title_thread_missing": "Codex 标题里没有会话 id",
    "title_thread_unmatched": "Codex 标题里的会话 id 对不上已加载的会话",
    "title_shows_subagent": "Codex 窗口正在显示子代理",
    "pane_process_ambiguous": "同一窗口里有多个互不包含的 Codex 进程",
}
REASON_TEXTS: dict[str, str] = {
    **READABLE_REASONS,
    "waiting_for_target": "已排队，还没发出",
    "paused": "已暂停发送",
    "sending": "正在发送",
    "awaiting_ack": "等待对方确认开始处理",
    "acknowledged": "对方已开始处理",
    "in_progress": "对方处理中",
    "no_attempt": "任务没有可用的交接记录",
    "cancelled_undelivered": "消息已取消，未发送",
    "blocked_reported": "对方报告受阻",
    "failure_reported": "对方报告无法完成",
    "result_ready": "对方已交结果，待验收",
    "review_approved": "复核通过，待验收",
    "changes_requested": "复核要求修改",
    "review_not_dispatched": "结果已交，但复核消息未生成",
    "accepted": "已验收",
    "closed": "已停止追踪",
    "target_not_found": "找不到目标会话（用 {command} peers 查看可用目标）",
    "target_ambiguous": "目标不唯一，请换成完整会话 ID（{command} peers 里显示的就是）或 pane（如 %3）",
    "target_is_self": "不能把任务交给自己所在的会话",
    "target_gone": "目标会话已不在（可能已退出或换了新会话）",
    "target_no_thread_yet": "目标 Codex 还没有会话 thread（先在里面发一句话）",
    "target_ambiguous_thread": "目标 Codex 进程打开了多个 thread，无法确定投递位置",
    "target_title_thread_missing": "目标 Codex 的标题里没有会话 id（停在选择器、标题过长，或 terminal_title 末尾没加 thread-id；见 {command} doctor）",
    "target_title_thread_unmatched": "目标 Codex 标题里的会话 id 对不上已加载的会话",
    "target_title_shows_subagent": "目标 Codex 窗口正在显示子代理，切回主会话后才能投递",
    "target_pane_process_ambiguous": "目标窗口里有多个互不包含的 Codex 进程，无法确定投递位置",
    "target_subagent_only": "目标只看得到 Codex 子代理 thread（子代理只经根会话收件），不能作为目标",
    "target_shared_thread": "目标 thread 同时被多个进程加载，可能由另一个进程执行；确认后加 --allow-shared",
    "target_socket_unavailable": "目标 Claude 的消息 socket 不可用",
    "target_peer_protocol_unsupported": "目标 Claude 版本的消息协议不受支持",
    "target_no_inbox": "该 agent 会话没有收件通道，不能作为目标；它只能自己发起，结果自己用 {command} status 查",
    "reviewer_is_target": "复核方不能是实现方",
    "reporter_mismatch": "只有收到这项任务的会话才能汇报",
    "reporter_unattributed": "无法确认汇报来自哪个会话（需要在 tmux 里的 agent 会话中运行；Codex 托管 daemon 下见 {command} doctor）",
    "reporter_is_subagent": "子代理不能代替根会话汇报，请由根会话汇报",
    "sender_is_subagent": "子代理不能发起协作任务，请由根会话发起",
    "caller_unattributed": "看得见 agent 进程，但认不出是哪个会话（例如 Codex 进程开着多个 thread 且定不下根；Codex 托管 daemon 下见 {command} doctor），不能以会话身份发起",
    "manual_flag_required": "在终端里代为汇报需要加 --manual",
    "stale_attempt": "这是旧的一次交接，任务已有更新的尝试",
    "attempt_not_found": "找不到这次交接",
    "attempt_not_reportable": "通知消息不需要汇报",
    "attempt_not_sent": "消息还没发出，不能汇报",
    "result_already_submitted": "这次交接已经交过结果",
    "verdict_requires_review": "通过/要求修改只用于复核",
    "review_requires_verdict": "复核请用 --approve 或 --changes 给出结论",
    "task_finished": "任务已结束",
    "task_not_found": "找不到任务",
    "task_ambiguous": "任务 ID 前缀不唯一，请多写几位",
    "file_unreadable": "文件不存在或不可读",
    "file_too_large": "文件过大（上限 256 MiB）",
    "too_many_files": f"文件过多（上限 {MAX_FILES} 个）",
    "commit_invalid": "提交号格式不对",
    "empty_message": "任务内容为空",
    "message_and_file_conflict": "-m 与 --file 只能二选一",
    "message_too_large": f"任务内容过长（上限 {MAX_BODY_BYTES // 1024} KiB），请改用 --ref 引用文件",
    "capacity_active_tasks": "进行中的任务过多（上限 100），请先验收或关闭一些",
    "capacity_pending": "排队中的消息过多，请稍后再试",
    "capacity_attempts": "这项任务的交接次数已达上限",
    "store_unavailable": "任务账本无法打开",
    "store_corrupt": "任务账本已损坏",
    "store_busy": "任务账本正忙，请重试",
    "store_readonly": "任务账本不可写（检查 bridge.sqlite3 及同目录 -wal/-shm 文件的权限）",
    "store_write_failed": "任务账本写入失败",
    "schema_too_new": "任务账本版本比当前程序新，请使用更新的 {command}",
    "corrupt_record": "任务记录损坏",
    "nothing_to_cancel": "没有尚未发送的消息可取消；Codex 已排队项可显式 withdraw，但不证明未执行",
    "withdraw_attempt_missing": "没有指定的投递尝试",
    "withdraw_ineligible": "只能撤回有完整原生项 id 的 Codex QUEUED 交接或复核消息",
    "withdraw_root_missing": "缺少原投递或当前数据根证据，不能猜删",
    "withdraw_root_mismatch": "当前数据根与原投递存证不一致，未发撤回请求",
    "withdraw_platform_unsupported": "本平台尚不支持原生撤回，未发撤回请求",
    "windows_provider_not_enabled": "Windows W1 尚未开放会话投递，尚未写入任务",
    "platform_unsupported": "当前平台未受支持，尚未执行操作",
    "withdraw_not_allowed": "只有用户或发起任务的会话可以撤回原生队列项",
    "withdraw_store_unreadable": "撤回附表版本不可读；主账本仍可使用，撤回功能已停用",
    "withdraw_record_conflict": "撤回结果未落账：操作已被恢复或处理，请区分本次实际结果与账本记录",
    "withdraw_invalid_result": "撤回结果无效，未写入账本",
    "withdraw_owner_unknown": "无法确认当前操作进程代际，未发撤回请求",
    "owner_timeout": "撤回操作超过10分钟，已恢复为未尝试或结果未知；未自动重试",
    "withdraw_limit": "此投递的显式撤回次数已到上限16次",
    "withdraw_conflict": "撤回操作已被另一次调用处理，请查看现有结果",
    "still_pending": "上一条消息还在桥内排队，不需要重发",
    "retry_requires_force": "上一条消息可能已送达或正在执行，重发可能重复执行；确认后加 --force",
    "accept_not_allowed": "只有用户或发起任务的会话可以验收",
    "no_result_to_accept": "还没有可验收的结果；确需验收加 --force",
    "not_paused": "任务未暂停",
    "worker_not_running": "后台 worker 未运行（可运行 {command} worker 查看原因）",
    "interrupted_during_send": "发送过程中断，是否送达不明",
    "transport_exception": "投递通道出错，是否送达不明",
    "receiver_reported": "对方已汇报",
    "receiver_replied": "对方已回复",
    "codex_queued": "已进入 Codex 队列",
    "claude_written": "已写入对方会话；未收到拒收或 hold 回执即视为已接收",
    "target_generation_ambiguous": "同一会话有多个进程且原先选定的进程已退出，请用 --to 指定 pane 重发",
    "reporter_generation_mismatch": "该会话实际收到消息的进程仍在运行，只能由它汇报",
    "review_verdict_missing": "复核已交但缺少明确结论（通过或要求修改）",
    "worker_start_failed": "无法启动后台 worker",
    "ledger_absent": "还没有任务账本（尚未使用 {command}）",
    "summary_write_failed": "协作摘要写入失败",
    "summary_lock_timeout": "协作摘要正被其他进程写入，请稍后重试",
    "summary_too_large": "协作摘要超过大小上限",
    "summary_invalid_value": "协作摘要含无效数值，未写入",
    "claude_delivered": "对方会话已接收",
    "claude_held": "对方会话需要批准这条消息（默认 5 分钟过期）",
    "claude_denied": "对方会话拒绝了这条消息",
    "claude_expired": "对方会话未批准，消息已过期",
    "claude_refused": "对方会话设置为拒收",
    "claude_dropped": "对方会话丢弃了这条消息（队列满或速率限制）",
    "claude_peer_mismatch": "socket 对端进程与目标会话不符，未发送",
    "claude_socket_connect_failed": "连接对方会话失败，未发送",
    "claude_socket_write_failed": "写入对方会话中断，是否送达不明",
    "claude_socket_unavailable": "对方会话没有可用的消息 socket",
    "reminder_outdated": "提醒排队期间任务已有变化或回执被拒，这条提醒不再发送",
    "notice_outdated": "发起方已返工，这条还没发出的通知不再发送",
}
EVENT_LABELS: dict[str, str] = {
    "created": "创建任务",
    "sending": "发送中",
    "ack": "对方已开始处理",
    "progress": "进展",
    "blocked": "对方受阻",
    "failed": "对方无法完成",
    "result": "对方已交结果",
    "approve": "复核通过",
    "changes": "复核要求修改",
    "verdict_approved": "记录复核结论：通过",
    "verdict_changes": "记录复核结论：要求修改",
    "handoff_created": "排队新的交接",
    "review_created": "排队发给复核方",
    "notice_created": "排队通知发起方",
    "peer_reply": "对方回复",
    "paused": "暂停发送",
    "resumed": "继续发送",
    "cancelled": "取消未发送的消息",
    "accepted": "验收",
    "closed": "停止追踪",
    "retry": "重发/返工",
    "origin_reminded": "超时未处理，提醒发起方",
    "closure_created": "排队结束回执",
    "closure_skipped_capacity": "容量已满，未排结束回执",
}


def reason_text(code: str | None, *, command: str | None = None) -> str:
    """原因码的可读说明；没有登记的原因码原样显示。

    文案里的 `{command}` 占位替换成实际入口名（DESIGN §45.36）。用 `replace` 而不是 `str.format`：
    这些是中文自由文本，不能因为某条文案以后出现花括号就抛异常。
    """
    if not code:
        return ""
    if code.startswith("delivery_"):
        try:
            return DELIVERY_LABELS[Delivery(code.removeprefix("delivery_"))]
        except ValueError:
            return code
    text = REASON_TEXTS.get(code, code)
    return text.replace(PLACEHOLDER, command or command_name()) if PLACEHOLDER in text else text


def role_label(attempt: Attempt) -> str:
    """尝试的角色名；结束回执虽是 notice，但不是发给发起方的（DESIGN §45.31.6）。"""
    return CLOSURE_LABEL if attempt.is_closure else ROLE_LABELS[attempt.role]


@dataclass(frozen=True)
class NextStep:
    """下一步：固定动作码供摘要与界面判断，文案与命令供人阅读或复制。"""

    action: str
    text: str
    command: str | None = None


def next_step(task: Task, attempts: list[Attempt], *, ref: str, command: str | None = None) -> NextStep | None:
    """按任务当前阶段给出下一步；ref 是命令里的任务标识（CLI 用短 ID，摘要用完整 ID）。

    命令名缺省按本进程入口解析：这些文案会进摘要的 `next.command`，也会被用户直接照抄（DESIGN §45.36）。
    """
    cmd = command or command_name()
    view = describe(task, attempts)
    reason = view.reason
    if view.phase is Phase.DONE or view.phase is Phase.CLOSED:
        return None
    if reason == "paused":
        return NextStep("resume", f"{cmd} resume {ref} 继续发送", f"{cmd} resume {ref}")
    if reason == "waiting_for_target":
        return NextStep("wait", f"等后台 worker 发送；不需要了可 {cmd} cancel {ref}")
    if reason == "delivery_held":
        # 等接收方批准时重发没有帮助，只提示去对方会话处理
        return NextStep("approve_at_target", f"去对方会话里批准这条消息；过期后可 {cmd} retry")
    if reason == "delivery_unknown":
        return NextStep(
            "confirm_then_force_retry",
            f"不会自动重发。确认对方没收到后可 {cmd} retry {ref} --force",
            f"{cmd} retry {ref} --force",
        )
    if reason.startswith("delivery_") or reason == "cancelled_undelivered":
        return NextStep("retry_or_close", f"未送达：{cmd} retry {ref}（可加 --to 改派）或 {cmd} close {ref}", f"{cmd} retry {ref}")
    if reason in {"blocked_reported", "failure_reported"}:
        return NextStep("rework_or_close", f"处理对方的问题后 {cmd} retry {ref} 返工，或 {cmd} close {ref}", f"{cmd} retry {ref}")
    if reason == "review_verdict_missing":
        return NextStep("ask_reviewer_or_retry", f"让复核方补交结论，或 {cmd} retry {ref} 重新复核", f"{cmd} retry {ref}")
    if reason == "changes_requested":
        return NextStep(
            "rework", f"{cmd} retry {ref} 把复核意见交回实现方返工，或 {cmd} accept {ref} --force", f"{cmd} retry {ref}"
        )
    if reason in {"no_attempt", "review_not_dispatched"}:
        return NextStep("status_or_close", f"{reason_text(reason, command=cmd)}：{cmd} status {ref} 查看，或 {cmd} close {ref}", f"{cmd} status {ref}")
    if reason == "review_approved":
        # 复核已通过时普通 retry 会被要求 --force，且那是重新复核而不是返工：不建议（Codex 设计复审 F04）
        return NextStep("accept", f"{cmd} accept {ref} 验收；复核结论见 {cmd} status {ref}", f"{cmd} accept {ref}")
    if view.phase is Phase.AWAITING_ACCEPTANCE:
        return NextStep("accept", f"{cmd} accept {ref} 验收；需要返工用 {cmd} retry {ref}", f"{cmd} accept {ref}")
    if view.phase is Phase.RUNNING and view.current is not None:
        if view.current.delivery is Delivery.WRITTEN:
            return NextStep("wait", f"已写入对方会话，等待对方汇报；{cmd} wait {ref} 可以一直等到结果", f"{cmd} wait {ref}")
        return NextStep("wait", f"等待对方汇报；{cmd} wait {ref} 可以一直等到结果", f"{cmd} wait {ref}")
    return None
