"""协作桥的中文标签表与原因文案：CLI、摘要发布与 worker 共用（摘要不能导入 cli，cli 会导入 worker）。"""

from __future__ import annotations

import calendar
from dataclasses import dataclass
import math
import time

from collections.abc import Mapping
from typing import Any

from .model import (
    AUTO_RETRY_OPTION,
    Attempt,
    Consumption,
    Delivery,
    Phase,
    Role,
    Runtime,
    Task,
    TaskView,
    Work,
    defer_time,
    describe,
)
from .naming import command_name
from .store import MAX_BODY_BYTES, MAX_FILES, attempt_limit
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
# 任务内补充消息（DESIGN §95.5.6）：role 仍是 notice，但发给执行方
NOTE_LABEL = "补充"
# 一句话告知（DESIGN §95.5.7）：role 是 notice，任务建立即关闭；状态行写「已告知（关闭）」
FYI_LABEL = "告知"
FYI_STATUS_LABEL = "已告知（关闭）"
# 催执行方与定时提醒（DESIGN §104.9 一、二）：role 都是 notice，催促发给执行方，定时提醒发给调用方自己
NUDGE_LABEL = "催促"
REMIND_LABEL = "定时提醒"
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
    # 镜像上当前工作尝试在别的设备（§97.2 第 2 条）；联邦 status 另写出设备名
    "handled_on_other_device": "当前由其他设备处理，完整状态以发起设备为准",
    "accepted": "已验收",
    "closed": "已停止追踪",
    "target_not_found": "找不到目标会话（用 {command} peers 查看可用目标）",
    # §91.2.3：区分「不同 ID」与「同一 ID 多实例」，不再推荐 pane，也不假称完整 ID 万能
    "target_ambiguous": "目标不唯一：不同会话请改用 provider@id:<完整ID>（{command} peers 里显示的就是）；"
                        "同一会话 ID 有多个实例时完整 ID 也区分不了，先只保留一个实例",
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
    "reporter_unattributed": "无法确认汇报来自哪个会话；请在已认出的 agent 会话中运行，见 {command} doctor",
    "reporter_is_subagent": "子代理不能代替根会话汇报，请由根会话汇报",
    "sender_is_subagent": "子代理不能发起协作任务，请由根会话发起",
    "caller_unattributed": "看得见 agent 进程，但认不出是哪个会话；不能以会话身份发起，请用 {command} doctor 核对归属",
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
    "message_invalid_utf8": "正文必须是合法 UTF-8；尚未写入账本",
    # 正文以外的命令行参数（--title、--note、--to、--ref 等）含编码不成 UTF-8 的字符（§101.2）
    "argument_invalid_utf8": "命令行参数必须是合法 UTF-8（终端或脚本传入了非法字节）；未执行任何操作",
    "file_too_large": "文件过大（上限 256 MiB）",
    "too_many_files": f"文件过多（上限 {MAX_FILES} 个）",
    # 跨设备 retry 继承的附件与新附件合计超过单条消息 32 MiB（§104.11 第 5 条；信封校验的闭集码）
    "attachment_too_large": "附件合计过大（单条消息上限 32 MiB），请减少 --ref 后重试",
    "commit_invalid": "提交号格式不对",
    "empty_message": "任务内容为空",
    "message_and_file_conflict": "-m 与 --file 只能二选一",
    "message_too_large": f"任务内容过长（上限 {MAX_BODY_BYTES // 1024} KiB），请改用 --ref 引用文件",
    "capacity_active_tasks": "进行中的任务过多（上限 100），请先验收或关闭一些",
    "capacity_pending": "排队中的消息过多，请稍后再试",
    # 占位写成带引号的中文（§104.11 P3）：<旧ID> 照抄进 shell 是重定向
    "capacity_attempts": "这项任务的交接次数已达上限；请 {command} close 旧任务，再 {command} send 新任务（可加 --follows \"旧任务ID\" 关联）",
    "attempts_near_limit": "接近交接上限，长迭代建议 {command} close 旧任务、{command} send 新任务（可加 --follows \"旧任务ID\" 关联）",
    "report_attempts_near_limit": "接近交接上限，后续由发起方决定 {command} close 本任务、{command} send 新任务（可加 --follows \"旧任务ID\" 关联）",
    "notification_attempts_report": "汇报已提交，通知未能排队（交接次数已达上限），发起方需 {command} status 查看；不要重复汇报",
    "notification_pending_report": "汇报已提交，通知未能排队（全局待投递容量已满），发起方需 {command} status 查看；不要重复汇报。队列腾空后，若本任务还有提醒名额且仍符合提醒条件，提醒会照常叫醒发起方",
    "notification_attempts_status": "对方汇报已提交，通知因交接次数已达上限未排队；请查看本任务结果并决定 {command} close 后新开任务",
    "notification_pending_status": "对方汇报已提交，通知因全局待投递容量已满未排队；请查看本任务结果。队列腾空后，若本任务还有提醒名额且仍符合提醒条件，提醒会照常叫醒发起方",
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
    "windows_provider_not_enabled": "此 Windows 命令或 provider 能力尚未开放，尚未写入任务",
    "platform_unsupported": "当前平台未受支持，尚未执行操作",
    "alias_platform_unsupported": "本地别名命令目前只支持 Windows；Linux 请用现有目标选择器",
    "alias_name_invalid": "别名须以字母起始，仅用字母数字、点、短横线或下划线，不能伪装 UUID",
    "alias_name_conflict": "别名与另一个根的当前会话名或目录标签冲突，请换一个名字",
    "alias_uuid_required": "登记时请指定完整 UUID 或唯一 UUID 前缀，不使用另一个别名",
    "alias_target_unavailable": "别名目标当前不可用；请核对 peers，不会自动换绑",
    # §91.2.2：通用提示不推荐别名（别名只在 Windows 本机可用，CLI 在 Windows 上另附一行）
    "target_names_unverified": "名称唯一性未核实：改用已核实的 provider@名字，或 provider@id:<完整ID>",
    "target_provider_required": "按名字寻址须带 provider：provider@名字，或 provider@id:<完整ID>",
    "target_id_invalid": "id: 后须是至少 8 位的 UUID 前缀或完整 ID；不会改按名字查找",
    "target_id_unverified": "ID 前缀唯一性未核实（会话全集未读全或设备目录过期）：{command} peers 刷新后重试，或改用完整 ID",
    "target_explicit_required": "请明确指定非空的目标或复核方；不会自动选择会话",
    "target_changed": "选择期间目标更名、重名或代际改变；未改投，请刷新 peers 或用 codex@id:<UUID> / claude@id:<UUID> 消歧",
    "target_root_changed": "Codex 数据根与原任务不一致，未投递",
    "target_not_loaded": "目标已离开 loaded 集，未投递",
    "target_generation_changed": "Codex daemon 代际已改变，未投递",
    "daemon_changed": "Codex daemon 在连接期间换了（可能正在重启），消息确定没有送出",
    "boundary_store_busy": "本机账本正忙，发送前停下，消息确定没有送出",
    "codex_deadline_before_send": "发送前等待 Codex 超时，消息确定没有送出",
    "codex_preflight_failed": "Windows Codex 写前核验失败，未发送 add 帧",
    "alias_store_unverified": "本地别名库无法安全读取，未改写",
    "alias_store_busy": "本地别名库正忙，请重试",
    "alias_invalid": "别名格式、有效期或限额不符，未改写",
    "receipt_poll_only_required": "此发起方没有收件通道；必须显式 --no-notify，并用 status / wait 读取结果",
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
    # ab note（DESIGN §95.5.2）
    "note_no_active_attempt": "这项任务没有可以补充的进行中尝试（尚未发出、已汇报或任务已结束）；"
                              "对方已汇报请用 {command} retry，任务已结束请用 {command} send 新任务",
    "note_task_paused": "任务已暂停，补充消息不会发出；先 {command} resume 再补充",
    "note_not_authority": "跨设备任务只能在发起设备上补充（本机是镜像）",
    # ab send --fyi（DESIGN §95.5.7）
    "fyi": "一句话告知，建立即关闭；只需对方读到，不汇报、不验收",
    "fyi_conflict": "--fyi 只发一句话告知，不能与 --review-by、--review-device、--no-notify、--expect 同用",
    "fyi_remote_unsupported": "对方设备的协作桥版本还不支持跨设备告知（--fyi）；请对方升级后再发，或改用普通任务",
    # tasks 筛选（DESIGN §93.1）
    "mine_requires_session": "--mine 按会话 ID 匹配，需要在认得出的 agent 会话里运行；用户终端或 /clear 后的新会话请用不带 --mine 的 {command} tasks",
    "since_invalid": "--since 格式不对：写 <正整数>m/h/d（如 30m、2h、7d）或 YYYY-MM-DD",
    "grep_empty": "--grep 的文字不能为空",
    # 决定类命令 --json 的 notes（DESIGN §93.2）；worker_not_running、relay_not_running 沿用已有说明
    "native_risk": "停止追踪不撤回已交接内容；可显式尝试移除仍在 Codex 队列中的项（withdraw），已开始的工作不能撤销",
    "remote_unconfirmed": "对方设备尚未确认最新状态：还没发出的由对方按最新状态投递或抑制，已交出的消息与工作不能撤回",
    "retry_may_duplicate": "上一条消息可能已送达，对方可能重复执行",
    # send --follows（DESIGN §93.3）：与 task_not_found 同类，退出 2
    # 联邦库读不了时没查成，不把「读不了」说成「没有」（§101.3）
    "follows_not_found": "找不到 --follows 指定的旧任务：本机账本没有；联邦库里也没有，或联邦库读不了"
                         "（读不了时只查了本机账本，可用 {command} federation status 查看）",
    "follows_ambiguous": "--follows 指定的旧任务不唯一（本机账本与联邦库里命中不止一个），请多写几位或用完整 ID",
    "worker_not_running": "后台 worker 未运行（可运行 {command} worker 查看原因）",
    "interrupted_during_send": "发送过程中断，是否送达不明",
    "transport_exception": "投递通道出错，是否送达不明",
    "receiver_reported": "对方已汇报",
    "receiver_replied": "对方已回复",
    "codex_queued": "已进入 Codex 队列",
    "codex_steered": "已插入 Codex 进行中的一轮（turn/steer），在它下一次请求模型前读入",
    "claude_written": "已写入对方会话；未收到拒收或 hold 回执即视为已接收",
    "claude_discovery_incomplete": "Claude 会话发现不完整，请用已核实的完整会话 ID 或稍后再试",
    "discovery_incomplete": "Codex 会话发现不完整，请用已核实的完整会话 ID 或稍后再试",
    "claude_session_ambiguous": "同一 Claude 会话有多个存活进程，暂不能唯一选定",
    "claude_inbox_unavailable": "本机 Claude 回信收件箱暂不可用",
    "claude_peer_unverified": "未能核实 Claude 原生端点或其认证登记，尚未发送",
    "claude_target_changed": "Claude 目标身份或管道已变化，尚未发送",
    "target_generation_ambiguous": "同一会话有多个进程且原先选定的进程已退出：完整 ID 也区分不了，先只保留一个进程再重发",
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
    "note_outdated": "所补的那次尝试已交结果、受阻或失败，这条还没发出的补充不再发送",
    # 跨设备协作（DESIGN §88）；不含入口名占位，联邦文案与本机文案互不影响
    "federation_not_configured": "本机未启用跨设备协作（没有 federation.json）",
    "federation_disabled": "跨设备协作已停用；重新启用后才能写入联邦任务",
    "federation_store_missing": "联邦库缺失：配置还在而 federation.sqlite3 不在，不自动新建，按灾难恢复流程处理",
    "federation_store_exists": "联邦库已存在：只有首次启用才新建，不覆盖既有联邦库",
    "federation_store_corrupt": "联邦库损坏或缺少必要元数据",
    "federation_store_unavailable": "联邦库不可读",
    "federation_schema_too_new": "联邦库来自更新的版本，当前版本不能打开",
    "federation_already_configured": "本机已登记为另一个设备或另一个 hub；换设备、换 hub 不在启用命令里覆盖",
    "federation_device_name_invalid": "设备名须为 1～32 位 ASCII，字母或数字开头，只含字母、数字、点、下划线和连字符；请用 --name 指定",
    "ledger_instance_mismatch": "联邦库身份与配置不符（设备 ID 或账本实例不同），已停止，不联网",
    "state_root_mismatch": "状态根与配置的 expectedStateRoot 不符，已在开库、联网前停止",
    "config_invalid": "federation.json 无效",
    "target_is_local_device": "目标设备就是本机；本机会话不用 --device",
    "federation_review_device_unsupported": "复核方只能在发起设备或目标设备上（第三台设备复核另期支持）",
    "review_device_requires_reviewer": "--review-device 要和 --review-by 一起用",
    "review_device_requires_device": "--review-device 只用于跨设备任务，要和 --device 一起用",
    "federation_not_authority": "只有发起设备能决定这个跨设备任务；需要对方处理请用 report --blocked",
    "federation_archive_authority": "发起设备上的任务用 close 结束；archive 只归档本机镜像",
    "federation_withdraw_unsupported": "跨设备任务不支持 withdraw（不触碰对方设备的原生队列）",
    "relay_not_running": "联邦 relay 未运行",
    "relay_running_unknown": "无法确认联邦 relay 是否在运行（relay 锁文件无法读取）",
    "stop_controller_failed": "relay 的停止控制线程意外退出，relay 已停止；服务管理器会重新拉起",
    "relay_elevated": "relay 不能在管理员（提权）令牌下运行",
    "remote_endpoint_unresolved": "对方设备的目录里没有这个会话；先用 peers --device 查看，再用 provider@id:<完整ID> 指定",
    "target_remote_invalid": "对方目录里这个会话的记录不合法（ID 含空白或控制字符、过长，或 provider 未知等），不能作目标；"
                             "用 {command} peers --device 核对，或等对方设备刷新目录后重试",
    "device_unknown": "未知设备：本机目录里没有这个设备名或设备 ID",
    "mirror_archived": "本机镜像已归档，不再投递或汇报",
    "task_cancelled": "发起设备已请求取消",
    "hub_unavailable": "hub 不可达",
    "hub_state_lost": "hub 状态回退（提交计数变小），已冻结联邦投递，等运维处理",
    "device_offline": "对方设备离线",
    "authority_sync_required": "需要先与发起设备同步",
    "authority_mismatch": "报告指向的发起设备不符",
    "report_sequence_conflict": "报告序号冲突",
    "record_conflict": "联邦账本里已有冲突的记录（同一序号或 ID 内容不同）",
    "report_not_seen": "发起设备没收到这份汇报、传输已终结：可按当前资格重新汇报",
    "report_pending": "上一份终态汇报仍在本机等发起设备确认：确认或判定未收到之前不能再交终态汇报（--progress 照常可用）",
    "attempt_report_finalized": "这一轮的终态汇报已被发起设备采纳，不能再交",
    "target_root_unverified": "核实不了这个会话所在的 provider 根（注册记录与进程代际不符），不能作为跨设备端点",
    "remote_directory_incomplete": "对方目录不完整，按名字或 ID 前缀可能选错：请用 provider@id:<完整ID>",
    "report_kind_mismatch": "报告类型无效",
    "idempotency_conflict": "同一操作 ID 的内容前后不一致，已拒绝",
    "attachment_unreadable": "附件不可读",
    "attachment_not_regular": "附件不是普通文件",
    "attachment_path_unavailable": "附件路径不可用",
    "attachment_write_failed": "本机写附件暂时失败（磁盘或权限抖动），稍后自动重试",
    "attachment_source_changed": "附件在读取期间被修改",
    "attachment_hash_mismatch": "附件内容校验不符",
    "device_storage_full": "本机联邦内容已到预算上限（storageBudgetBytes）：等过期内容回收或调高预算后再试",
    "federation_rebuild_same_hub": "新 hubId 与当前相同；灾难换 hub 必须使用新的 hubId",
    "federation_rebuild_needs_new_device": "本机联邦库已丢失：必须用 hub 新登记的设备 ID（--device-id）",
    "federation_rebuild_incomplete": "联邦库与配置的 hubId 不一致（上次换 hub 没有完成）：重新运行 ab federation rebuild --hub-id \"新hubId\"",
    "relay_running": "relay 正在运行：先停止 relay 再换 hub，完成后重新启动",
    "federation_rebuild_device_mismatch": "本机联邦库完整时保留原设备 ID；hub 重新登记时请用 --device-id 保留原 ID",
    "hub_rebuilt": "hub 已换新：旧 hub 上的发件冻结，不转投新 hub",
    "summary_federation_unavailable": "联邦库不可读：协作摘要保持上一份，标为落后于账本",
    # §104 甲：延迟投递、执行方提问、定时提醒、沉默提醒与 todo（DESIGN §104.9 一、二、五、六）
    "deferred": "定时发出，到点前不外调",
    "question_asked": "对方在等你回答（任务仍在进行）",
    "ask_requires_note": "--ask 要用 --note 写明问题",
    "after_invalid": "--after 格式不对：写 1m～24h 之间的时长（如 30m、2h），单位 m 或 h",
    "expect_invalid": "--expect 格式不对：写 5m～24h 之间的时长（如 45m、2h），单位 m 或 h",
    "in_invalid": "--in 格式不对：写 1m～24h 之间的时长（如 31m、2h），单位 m 或 h",
    "silent": "从锚点起满设定时长没有新的汇报",
    "remind_requires_session": "{command} remind 只给认得出的 agent 会话用：提醒会送回调用会话本身；用户终端与认不出的会话不能排提醒",
    # 正文输入统一（DESIGN §104.4）：report 说明超长不再静默截断，与 --note-file 互斥
    "note_too_large": "说明过长（上限 4000 字），长内容请写成文件用 --file 交附件",
    "note_and_file_conflict": "--note 与 --note-file 只能二选一",
}
# origin_reminded 事件 detail 带 immediate=true 时（确定未送达立即告知，DESIGN §103.2）用这个标签；不新增事件取值
ORIGIN_NOTIFIED_UNDELIVERED_LABEL = "投递未成功，已告知发起方"
# origin_reminded 事件 detail.reason=silent 时（对方沉默提醒，DESIGN §104.9 一）用这个标签；同样不新增事件取值
ORIGIN_NOTIFIED_SILENT_LABEL = "对方迟迟没有汇报，已提醒发起方"


def silent_minutes(detail: object) -> int | None:
    """沉默提醒事件 detail 里的分钟数（§104.9 一：{"reason":"silent","minutes":N}）；不是沉默提醒或没有合法分钟数为 None。"""
    if not isinstance(detail, dict) or detail.get("reason") != "silent":  # pyright: ignore[reportUnknownMemberType]
        return None
    minutes = detail.get("minutes")  # pyright: ignore[reportUnknownMemberType, reportUnknownVariableType]
    return minutes if isinstance(minutes, int) and not isinstance(minutes, bool) and minutes > 0 else None


def reminded_label(detail: object) -> str | None:
    """origin_reminded 事件按 detail 分支的标签（不新增事件取值）：立即告知（§103.2）与沉默提醒（§104.9 一）各有专用文字，
    其余返回 None 用默认标签。沉默提醒带分钟数时写「对方 N 分钟没有汇报，已提醒发起方」，时间线不再加附注（见
    silent_minutes）；缺分钟数时退回固定文字，附注照常写原因。本机与跨设备时间线共用这一份。"""
    if not isinstance(detail, dict):
        return None
    if detail.get("reason") == "silent":  # pyright: ignore[reportUnknownMemberType]
        minutes = silent_minutes(detail)  # pyright: ignore[reportUnknownArgumentType]
        return f"对方 {minutes} 分钟没有汇报，已提醒发起方" if minutes is not None else ORIGIN_NOTIFIED_SILENT_LABEL
    if detail.get("immediate") is True:  # pyright: ignore[reportUnknownMemberType]
        return ORIGIN_NOTIFIED_UNDELIVERED_LABEL
    return None
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
    "note_created": "排队补充消息",
    "fyi_created": "排队告知（任务建立即关闭）",
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
    "notification_skipped": "未排通知",
    "review_skipped_capacity": "容量已满，未排复核请求",
    # §104.9 一：执行方停下 5 分钟仍未汇报时排的催促（只在本机）
    "nudge_created": "排队催促执行方汇报",
}
# 联邦库专有的事件（§104.9 七，跨设备时间线）：每台设备显示本设备 fed_events 的记录；这些 kind 本机账本不写
FEDERATION_EVENT_LABELS: dict[str, str] = {
    "native_send_boundary": "外调走到发送边界",
    "cancel_requested": "请求取消未发送的消息",
    "mirror_archived": "本机已归档这项镜像",
    "handoff_received": "收到交接",
    "review_received": "收到复核请求",
    "notice_received": "收到通知",
    "report_rejected": "汇报未被发起设备采纳",
    "report_accepted": "发起设备已采纳汇报",
    "report_superseded": "汇报已被更新的汇报取代",
    "report_not_seen": "发起设备没收到这份汇报",
    "report_pending": "汇报仍在等发起设备确认",
    "decision_misrouted": "收到指向别的任务的裁决（已忽略）",
    "content_expired": "附件内容已过留存期",
}
# transport_<state> 事件（hub 拒收/对端拒收/过期/撤销，mirror.transport_failed）
TRANSPORT_EVENT_LABELS: dict[str, str] = {
    "refused": "hub 拒收",
    "rejected": "对端拒收",
    "expired": "传输已过期",
    "revoked": "传输已撤销",
}


def clock_time(timestamp: float) -> str:
    """本机时区（含 TZ 环境变量）下的时刻，不带偏移；单独出现时用 clock_text。"""
    return time.strftime("%m-%d %H:%M:%S", time.localtime(timestamp))


def utc_offset(timestamp: float) -> str:
    """该时刻在本机时区下的 UTC 偏移（如 UTC+08:00），按该时刻自身算，夏令时前后各自正确（§100.2）。

    直接由 localtime 的各字段反推（timegm(本地字段) − 时刻），与 clock_time 显示的时刻必然一致——Windows 上 TZ 被
    C 运行库按它自己的规则解释时也照实标出，不另外绕开 TZ。
    """
    seconds = calendar.timegm(time.localtime(timestamp)) - math.floor(timestamp)
    hours, rest = divmod(abs(seconds), 3600)
    minutes, extra = divmod(rest, 60)
    text = f"UTC{'-' if seconds < 0 else '+'}{hours:02d}:{minutes:02d}"
    return f"{text}:{extra:02d}" if extra else text


def clock_text(timestamp: float) -> str:
    """单独出现的时刻：本机时区（含 TZ）加该时刻自身的 UTC 偏移（§100.2）。时刻格式只有这一份实现，views 的
    时间线、「定时发出」与 cli 的定时提示都委托到这里（§104 合并时收拢）。"""
    return f"{clock_time(timestamp)} {utc_offset(timestamp)}"


def review_capacity_hint(code: str, *, reporter: bool = False) -> str:
    """两种容量拒绝的复核降级提示；汇报方只获知决定归发起方，不被要求自行 close。"""
    reason = "交接次数已达上限" if code == "capacity_attempts" else "全局待投递容量已满"
    cmd = command_name()
    if reporter:
        return f"复核未能排入（{reason}）；结果已提交，后续由发起方决定 {cmd} close 本任务、{cmd} send 新任务复核"
    return f"复核未能排入（{reason}），请 {cmd} close 后新开任务复核"


def notification_capacity_hint(code: str, *, reporter: bool = False) -> str:
    """容量跳过通知的完整文案：按原因与读者选择，不能拼上通用的“稍后再试”。"""
    capacity = 'attempts' if code == 'capacity_attempts' else 'pending'
    audience = 'report' if reporter else 'status'
    return reason_text(f'notification_{capacity}_{audience}')


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
    text = REASON_TEXTS.get(code)
    if text is None:
        return code  # 没登记的原样返回，不当本地模板展开（§104.12 第 10 条：未知码里的 {command} 不替换）
    return text.replace(PLACEHOLDER, command or command_name()) if PLACEHOLDER in text else text


def reason_registered(code: object) -> bool:
    """原因码有没有本地文案：登记在 REASON_TEXTS，或是合法投递枚举的 `delivery_*`（§104.12 第 10 条）。

    来自远端的取值只有命中才按本地文案展开；其余由调用方当闭集外取值转义，不靠「翻译后有没有变化」去猜。
    """
    if not isinstance(code, str) or not code:
        return False
    if code.startswith("delivery_"):
        return code.removeprefix("delivery_") in {item.value for item in Delivery}
    return code in REASON_TEXTS


def role_label(attempt: Attempt) -> str:
    """尝试的角色名；结束回执、补充消息与告知虽是 notice，但不是发给发起方的（DESIGN §45.31.6、§95.5.6、§95.5.7）。"""
    if attempt.is_closure:
        return CLOSURE_LABEL
    if attempt.is_remind:
        return REMIND_LABEL
    if attempt.is_fyi:
        return FYI_LABEL
    if attempt.is_nudge:
        return NUDGE_LABEL
    return NOTE_LABEL if attempt.is_note else ROLE_LABELS[attempt.role]


@dataclass(frozen=True)
class NextStep:
    """下一步：固定动作码供摘要与界面判断，文案与命令供人阅读或复制。"""

    action: str
    text: str
    command: str | None = None


def capacity_close_text(cmd: str, ref: str) -> str:
    """交接次数满时的统一下一步：close 本任务后 send 新任务（§83）。含 envelope.CAPACITY_REACHED 的固定措辞，第二行据此
    写容量写法；后续任务直接写本任务标识，不用 <旧ID> 占位（照抄进 shell 时尖括号是重定向，§104.11 第 1 条）。"""
    return f"交接次数已达上限，{cmd} close {ref} 后 {cmd} send 新任务（可加 --follows {follows_ref(ref)} 关联）"


def follows_ref(ref: str) -> str:
    """命令引用里的任务那一段：联邦命令的 ref 带路由（`<完整ID> --origin-device <设备>`，§104.13 第 2 条），
    `send --follows` 只接任务引用、不接 --origin-device，取第一段。"""
    return ref.split(" ", 1)[0]


def deferred_due(options: Mapping[str, Any], *, pending: bool, now: float) -> float | None:
    """显示层的「定时发出」判据（§104.11 P3）：还没发出、带 deferUntil、不在等自动重试、到期时刻还没过时返回该时刻。

    describe 不看时钟（到点后 worker 还没轮到、或目标一直不在线时仍判 deferred）；写「定时 <时刻> 发出」的地方
    都先过这一道，到点后改按等待对方的写法，不再印一个已经过去的时刻。本机与联邦 status 共用。
    """
    due = defer_time(dict(options))
    if not pending or due is None or AUTO_RETRY_OPTION in options or due <= now:
        return None
    return due


def shown_reason(view: TaskView, now: float | None = None) -> str:
    """显示用的原因码：describe 的 deferred 到点后（或已在等自动重试）按 waiting_for_target 显示（§104.11 P3）。

    只用于人读文字（状态行、任务列表、下一步）；JSON 的 reason 仍是 describe 的原值。
    """
    current = view.current
    if view.reason == "deferred" and (current is None or deferred_due(
            current.options, pending=current.delivery is Delivery.PENDING,
            now=time.time() if now is None else now) is None):
        return "waiting_for_target"
    return view.reason


def next_step(
    task: Task, attempts: list[Attempt], *, ref: str, command: str | None = None, reserved: int = 0,
    now: float | None = None,
) -> NextStep | None:
    """按任务当前阶段给出下一步；ref 是命令里的任务标识（CLI 用短 ID，摘要用完整 ID）。

    命令名缺省按本进程入口解析：这些文案会进摘要的 `next.command`，也会被用户直接照抄（DESIGN §45.36）。
    reserved 是正文写成后还要插入的通知数；达到工作上限时只改文案/命令，不改摘要 action 枚举。
    now 只用于「定时发出」是否已过（缺省取当前时刻）：到点后按等待对方写，不印过去的时刻（§104.11 P3）。
    """
    cmd = command or command_name()
    view = describe(task, attempts)
    reason = shown_reason(view, now)
    at_capacity = max((item.seq for item in attempts), default=0) + reserved >= attempt_limit(Role.HANDOFF)
    close_command = f"{cmd} close {ref}"
    close_text = capacity_close_text(cmd, ref)
    if view.phase is Phase.DONE or view.phase is Phase.CLOSED:
        return None
    if reason == "paused":
        return NextStep("resume", f"{cmd} resume {ref} 继续发送", f"{cmd} resume {ref}")
    if reason == "waiting_for_target":
        return NextStep("wait", f"等后台 worker 发送；不需要了可 {cmd} cancel {ref}")
    if reason == "deferred" and view.current is not None and view.current.defer_until is not None:
        # 延迟投递（§104.9 二）：到点由后台 worker 发出（跨设备远端目标由 relay 交给 hub）；shown_reason 已排除到点后
        when = clock_text(view.current.defer_until)
        return NextStep("wait", f"定时 {when} 发出；不需要了可 {cmd} cancel {ref}")
    if reason == "delivery_held":
        # 等接收方批准时重发没有帮助，只提示去对方会话处理
        if at_capacity:
            return NextStep("approve_at_target", f"去对方会话里批准这条消息；若已过期，{close_text}")
        return NextStep("approve_at_target", f"去对方会话里批准这条消息；过期后可 {cmd} retry")
    if reason == "delivery_unknown":
        if at_capacity:
            return NextStep("confirm_then_force_retry", f"不会自动重发。交接次数已达上限；先确认对方没收到（也不会再汇报），再 {close_command} 后 {cmd} send 新任务（可加 --follows {follows_ref(ref)} 关联）", close_command)
        return NextStep(
            "confirm_then_force_retry",
            f"不会自动重发。确认对方没收到后可 {cmd} retry {ref} --force",
            f"{cmd} retry {ref} --force",
        )
    if reason.startswith("delivery_") or reason == "cancelled_undelivered":
        if at_capacity:
            return NextStep("retry_or_close", f"未送达；{close_text}", close_command)
        return NextStep("retry_or_close", f"未送达：{cmd} retry {ref}（可加 --to 改派）或 {cmd} close {ref}", f"{cmd} retry {ref}")
    if reason in {"blocked_reported", "failure_reported"}:
        if at_capacity:
            return NextStep("rework_or_close", close_text, close_command)
        return NextStep("rework_or_close", f"处理对方的问题后 {cmd} retry {ref} 返工，或 {cmd} close {ref}", f"{cmd} retry {ref}")
    if reason == "question_asked":
        # 执行方提问、尝试仍在进行（§104.9 五）：用补充消息回答，送达后回到进行中；补充也占工作类名额（60）
        if at_capacity:
            return NextStep("answer", f"对方在等你回答，但交接次数已达上限，补充发不出：{close_text}", close_command)
        answer = f'{cmd} note {ref} -m "回答"'
        return NextStep("answer", f"回答对方的问题：{answer}", answer)
    if reason == "review_verdict_missing":
        if at_capacity:
            return NextStep("ask_reviewer_or_retry", f"让复核方补交结论，或 {close_text}", close_command)
        return NextStep("ask_reviewer_or_retry", f"让复核方补交结论，或 {cmd} retry {ref} 重新复核", f"{cmd} retry {ref}")
    if reason == "changes_requested":
        if at_capacity:
            return NextStep("rework", f"{close_text}；也可 {cmd} accept {ref} --force", close_command)
        return NextStep(
            "rework", f"{cmd} retry {ref} 把复核意见交回实现方返工，或 {cmd} accept {ref} --force", f"{cmd} retry {ref}"
        )
    if reason in {"no_attempt", "review_not_dispatched"}:
        return NextStep("status_or_close", f"{reason_text(reason, command=cmd)}：{cmd} status {ref} 查看，或 {cmd} close {ref}", f"{cmd} status {ref}")
    if reason == "review_approved":
        # 复核已通过时普通 retry 会被要求 --force，且那是重新复核而不是返工：不建议（Codex 设计复审 F04）
        return NextStep("accept", f"{cmd} accept {ref} 验收；复核结论见 {cmd} status {ref}", f"{cmd} accept {ref}")
    if view.phase is Phase.AWAITING_ACCEPTANCE:
        if at_capacity:
            return NextStep("accept", f"{cmd} accept {ref} 验收；如需返工，{close_text}", f"{cmd} accept {ref}")
        return NextStep("accept", f"{cmd} accept {ref} 验收；需要返工用 {cmd} retry {ref}", f"{cmd} accept {ref}")
    if view.phase is Phase.RUNNING and view.current is not None:
        if view.current.delivery is Delivery.WRITTEN:
            return NextStep("wait", f"已写入对方会话，等待对方汇报；{cmd} wait {ref} 可以一直等到结果", f"{cmd} wait {ref}")
        return NextStep("wait", f"等待对方汇报；{cmd} wait {ref} 可以一直等到结果", f"{cmd} wait {ref}")
    return None
