"""协作桥的中文标签表与原因文案：CLI、摘要发布与 worker 共用（摘要不能导入 cli，cli 会导入 worker）。"""

from __future__ import annotations

from dataclasses import dataclass

from .model import Attempt, Consumption, Delivery, Phase, Role, Runtime, Task, Work, describe
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
    "file_too_large": "文件过大（上限 256 MiB）",
    "too_many_files": f"文件过多（上限 {MAX_FILES} 个）",
    "commit_invalid": "提交号格式不对",
    "empty_message": "任务内容为空",
    "message_and_file_conflict": "-m 与 --file 只能二选一",
    "message_too_large": f"任务内容过长（上限 {MAX_BODY_BYTES // 1024} KiB），请改用 --ref 引用文件",
    "capacity_active_tasks": "进行中的任务过多（上限 100），请先验收或关闭一些",
    "capacity_pending": "排队中的消息过多，请稍后再试",
    "capacity_attempts": "这项任务的交接次数已达上限；请 {command} close 旧任务，再 {command} send 新任务（可加 --follows <旧ID> 关联）",
    "attempts_near_limit": "接近交接上限，长迭代建议 {command} close 旧任务、{command} send 新任务（可加 --follows <旧ID> 关联）",
    "report_attempts_near_limit": "接近交接上限，后续由发起方决定 {command} close 本任务、{command} send 新任务（可加 --follows <旧ID> 关联）",
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
    "codex_deadline_before_send": "投递预算已用尽，尚未发送 add 帧",
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
    "fyi_conflict": "--fyi 只发一句话告知，不能与 --review-by、--review-device、--no-notify 同用",
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
    "follows_not_found": "找不到 --follows 指定的旧任务：本机账本没有，联邦库里也没有"
                         "（联邦库读不了时只查了本机账本，可用 {command} federation status 查看）",
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
    "federation_rebuild_incomplete": "联邦库与配置的 hubId 不一致（上次换 hub 没有完成）：重新运行 ab federation rebuild --hub-id <新hubId>",
    "relay_running": "relay 正在运行：先停止 relay 再换 hub，完成后重新启动",
    "federation_rebuild_device_mismatch": "本机联邦库完整时保留原设备 ID；hub 重新登记时请用 --device-id 保留原 ID",
    "hub_rebuilt": "hub 已换新：旧 hub 上的发件冻结，不转投新 hub",
    "summary_federation_unavailable": "联邦库不可读：协作摘要保持上一份，标为落后于账本",
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
}


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
    text = REASON_TEXTS.get(code, code)
    return text.replace(PLACEHOLDER, command or command_name()) if PLACEHOLDER in text else text


def role_label(attempt: Attempt) -> str:
    """尝试的角色名；结束回执、补充消息与告知虽是 notice，但不是发给发起方的（DESIGN §45.31.6、§95.5.6、§95.5.7）。"""
    if attempt.is_closure:
        return CLOSURE_LABEL
    if attempt.is_fyi:
        return FYI_LABEL
    return NOTE_LABEL if attempt.is_note else ROLE_LABELS[attempt.role]


@dataclass(frozen=True)
class NextStep:
    """下一步：固定动作码供摘要与界面判断，文案与命令供人阅读或复制。"""

    action: str
    text: str
    command: str | None = None


def next_step(
    task: Task, attempts: list[Attempt], *, ref: str, command: str | None = None, reserved: int = 0
) -> NextStep | None:
    """按任务当前阶段给出下一步；ref 是命令里的任务标识（CLI 用短 ID，摘要用完整 ID）。

    命令名缺省按本进程入口解析：这些文案会进摘要的 `next.command`，也会被用户直接照抄（DESIGN §45.36）。
    reserved 是正文写成后还要插入的通知数；达到工作上限时只改文案/命令，不改摘要 action 枚举。
    """
    cmd = command or command_name()
    view = describe(task, attempts)
    reason = view.reason
    at_capacity = max((item.seq for item in attempts), default=0) + reserved >= attempt_limit(Role.HANDOFF)
    close_command = f"{cmd} close {ref}"
    close_text = f"交接次数已达上限，{close_command} 后 {cmd} send 新任务（可加 --follows <旧ID> 关联）"
    if view.phase is Phase.DONE or view.phase is Phase.CLOSED:
        return None
    if reason == "paused":
        return NextStep("resume", f"{cmd} resume {ref} 继续发送", f"{cmd} resume {ref}")
    if reason == "waiting_for_target":
        return NextStep("wait", f"等后台 worker 发送；不需要了可 {cmd} cancel {ref}")
    if reason == "delivery_held":
        # 等接收方批准时重发没有帮助，只提示去对方会话处理
        if at_capacity:
            return NextStep("approve_at_target", f"去对方会话里批准这条消息；若已过期，{close_text}")
        return NextStep("approve_at_target", f"去对方会话里批准这条消息；过期后可 {cmd} retry")
    if reason == "delivery_unknown":
        if at_capacity:
            return NextStep("confirm_then_force_retry", f"不会自动重发。交接次数已达上限；先确认对方没收到（也不会再汇报），再 {close_command} 后 {cmd} send 新任务（可加 --follows <旧ID> 关联）", close_command)
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
