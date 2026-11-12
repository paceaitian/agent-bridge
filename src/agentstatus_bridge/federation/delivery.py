"""联邦本机投递（DESIGN §88.5/§88.7/§88.8）：worker 领取 fed_native_sends=prepared 的作业，经本机原生通道投递。

关键次序：事务外完成本机目标/代际/附件核验与渲染 → **在调用 transport.deliver 之前**的一个 IMMEDIATE 事务里
CAS prepared→intent（同时复读 inbox、控制、工作序号、附件版本、catchup/sync/hub 冻结）并 FULL 提交 → 外调 →
结果事务写 native 事实与证据（回传 A）。两平台相同：Linux 通道从不调用 before_send 也已持久 intent。
intent 之后崩溃一律恢复为 UNKNOWN，绝不自动重投；CAS 失败零 native 字节。
"""

from __future__ import annotations

import json
import os
import shutil
import tempfile
import time
from collections.abc import Callable, Mapping
from dataclasses import replace
from pathlib import Path
from typing import Any

from .. import envelope
from ..dispatch import TARGET_GONE_GRACE_SECONDS, message_uuid, native_priority, select_generation
from ..endpoints import ADAPTERS, Endpoint
from ..ids import short
from ..model import REMINDER_OPTION, Delivery, Provider
from ..native_names import id_token, sender_display
from ..naming import command_name
from ..platforms import process as procfs
from ..platforms.factory import get_platform
from ..platforms.transport_codec import Receipt, parse_receipt
from ..reminders import attention_declined, reminder_body, reminder_sender_class, reminder_token
from ..store import StoreError, WINDOWS_SENDING_RECOVERY_SECONDS
from ..transports import DeliveryContext, DeliveryOutcome, Transport
from . import attachments, authority, mirror
from .directory import root_binding
from .attachments import REFERENCE_NOTICE, AttachmentError
from .fedstore import FederatedStore, FedAttempt, FedTask, dump, load_dict
from .relay import RelayPaths, local_blob
from .views import model_attempt, model_attempts, model_task, remote_text

LogFn = Callable[[str, Mapping[str, object]], None]
REMINDER_RETRY_MS = 60_000
DISCOVERY_PARK_MS = 600_000  # 与本机 DISCOVERY_PARK_SECONDS 同口径：等目标超过 10 分钟就不再为它驻留
_REASON_TEXT = {"single_file_limit": "单文件超过 8 MiB", "message_total_limit": "本条消息附件合计超过 32 MiB"}
# Claude 接收端回执可推进的来源状态，与本机 _RECEIPT_SOURCES 同口径
_RECEIPT_SOURCES: dict[str, tuple[str, ...]] = {
    "delivered": ("written", "held", "unknown"),
    "held": ("written", "unknown"),
    "denied": ("written", "held", "unknown"),
    "expired": ("written", "held", "unknown"),
    "refused": ("written", "held", "unknown"),
    "failed": ("written", "held", "unknown"),
}


def _no_log(_event: str, _fields: Mapping[str, object]) -> None:
    return None


def now_ms() -> int:
    return time.time_ns() // 1_000_000


class FederationDispatcher:
    """worker 内的联邦作业分发器；与本机 Dispatcher 并列，各开各的库、各自捕获存储错误。"""

    def __init__(self, store: FederatedStore, ident: authority.Identity, paths: RelayPaths, *,
                 discover: Callable[[], list[Endpoint]], transports: Mapping[Provider, Transport],
                 reply_address: str | None = None, clock: Callable[[], int] = now_ms,
                 proc_root: Path = procfs.DEFAULT_PROC, command: str | None = None, log: LogFn = _no_log,
                 empty_discovery_complete: Callable[[], bool] | None = None,
                 provider_discovery_complete: Callable[[Provider], bool] | None = None) -> None:
        self.store = store
        self.ident = ident
        self.paths = paths
        self.discover = discover
        self.transports = transports
        self.reply_address = reply_address
        self.clock = clock
        self.proc_root = proc_root
        self.command = command or command_name()
        self.log = log
        self.empty_discovery_complete = empty_discovery_complete
        self.provider_discovery_complete = provider_discovery_complete
        self._missing_since: dict[str, int] = {}
        self._reminder_retry: dict[str, int] = {}
        # 结果事务失败的外调：保留结果下轮重写（不再调 adapter），写成之前 worker 驻留（与本机 _unrecorded 同口径）
        self._unrecorded: dict[str, tuple[FedAttempt, Endpoint, DeliveryOutcome]] = {}
        self._waiting_since: dict[str, int] = {}  # 本 worker 内每条作业开始等待（目标/通道）的时刻，用于停泊
        self._parked: set[str] = set()
        # 持久身份已不是本运行时的身份（rebuild 换了 hub/设备、库文件已不在）：worker 据此关掉并按新配置重开
        self.stale = False

    # ---- 主循环 ----

    def enabled(self) -> bool:
        """联邦当前是否启用：每轮从库里读（disable 写 enabled=0），运行中的 worker 也立刻停止领取。"""
        return self.store.meta("enabled") == "1"

    def identity_current(self) -> bool:
        """库里的 hub/设备身份仍是本运行时启动时的身份，且库文件还在原处。"""
        return (self.store.meta("hubId") == self.ident.hub_id and self.store.meta("deviceId") == self.ident.device_id
                and os.path.exists(self.store.path))

    def run_once(self) -> dict[str, int]:
        self._retry_unrecorded()  # 已经发生的外调照常落账，与身份是否过期无关
        counts = {"recovered": 0, "reminders": 0, "sent": 0, "waiting": 0, "failed": 0}
        if not self.identity_current():
            if not self.stale:
                self.log("federation_runtime_stale", {})
            self.stale = True
            return counts  # 旧身份下不恢复、不提醒、不领取（领取 CAS 里 blocked 也会挡）：交给 worker 按新配置重开
        counts["recovered"] = self.recover_interrupted()
        if not self.enabled():
            return counts  # 停用：只把中断的 intent 收尾成 UNKNOWN，不排提醒、不领取
        try:
            counts["reminders"] = self.queue_reminders()
        except StoreError as error:
            self.log("federation_reminder_error", {"code": error.code})
        prepared = self.store.natives_in(("prepared",))
        current = {str(row["msg_id"]) for row in prepared}
        for msg_id in set(self._waiting_since) - current:
            self._waiting_since.pop(msg_id, None)
            self._parked.discard(msg_id)
        endpoints: list[Endpoint] | None = None
        now = self.clock()
        for row in prepared:
            msg_id = str(row["msg_id"])
            attempt, task = self._load(msg_id)
            if attempt is None or task is None:
                continue
            if self._suppress_reason(task, attempt) is None:
                if self._blocked(task, attempt):
                    counts["waiting"] += 1  # 冻结/暂停/需同步：不发现、不计停泊，解除后由 relay 重新唤醒
                    continue
                if endpoints is None:
                    endpoints = self.discover()  # 只有真要领取时才做整体发现
            outcome = self.dispatch(msg_id, endpoints or [])
            if outcome == "waiting":
                self._waiting_since.setdefault(msg_id, now)
            else:
                self._waiting_since.pop(msg_id, None)
                self._parked.discard(msg_id)
            if outcome in counts:
                counts[outcome] += 1
        return counts

    def has_live_work(self) -> bool:
        """worker 是否为联邦驻留：结果待重写、外调中（intent）、现在就能处理的作业，或 A 上有未到期提醒。

        冻结、暂停、需同步的作业不驻留（解除后 relay 会再拉起）；等目标/通道超过 10 分钟的停泊，不再驻留（与本机同口径）。
        停用时只为中断的 intent 驻留。
        """
        if self._unrecorded:
            return True
        if self.stale:
            return False  # 身份过期：只等结果重写完，随后由 worker 关掉重开
        if self.store.natives_in(("intent",)):
            return True
        if not self.enabled():
            return False
        now = self.clock()
        for row in self.store.natives_in(("prepared",)):
            msg_id = str(row["msg_id"])
            attempt, task = self._load(msg_id)
            if attempt is None or task is None:
                continue
            if self._suppress_reason(task, attempt) is not None:
                return True  # 下一轮就会收尾
            if self._blocked(task, attempt):
                continue
            since = self._waiting_since.get(msg_id)
            if since is None or now - since < DISCOVERY_PARK_MS:
                return True
            if msg_id not in self._parked:
                self._parked.add(msg_id)
                self.log("federation_pending_parked", {"task": short(attempt.task_id), "attempt": attempt.seq,
                                                       "waitSeconds": (now - since) // 1000})
        return any(True for _ in self._reminder_candidates())

    def _retry_unrecorded(self) -> None:
        for msg_id, (attempt, live, outcome) in tuple(self._unrecorded.items()):
            self._unrecorded.pop(msg_id, None)
            self._record_outcome(attempt, live, outcome)  # 再失败会重新放回

    # ---- 恢复 ----

    def recover_interrupted(self) -> int:
        """intent 的执行者已不在：恢复为 UNKNOWN 并回传证据；不重投、不倒退成 prepared。"""
        recovered = 0
        now = self.clock()
        try:
            mine = self._identity()
        except OSError:
            mine = None  # 读不到本进程代际：只按执行者是否还在判断
        for row in self.store.natives_in(("intent",)):
            generation = load_dict(row["worker_generation"])
            pid, start = generation.get("pid"), generation.get("start")
            if mine is not None and {"pid": pid, "start": start} == mine:
                if str(row["msg_id"]) in self._unrecorded:
                    continue  # 本 worker 外调完、结果还没写成：由 _retry_unrecorded 重写
                # 本进程的代际却不在本分发器手里（结果已丢）：外调可能发生过，与执行者退出同样收敛为 UNKNOWN
            elif get_platform().name == "windows":
                presence = (procfs.windows_presence(pid, start)
                            if isinstance(pid, int) and isinstance(start, str) else procfs.Presence.UNKNOWN)
                if presence is not procfs.Presence.EXITED and now - int(row["intent_at"] or now) <= \
                        WINDOWS_SENDING_RECOVERY_SECONDS * 1000:
                    continue
            elif isinstance(pid, int) and isinstance(start, str) and procfs.is_same_generation(pid, start,
                                                                                                self.proc_root):
                continue
            with self.store.transaction() as conn:
                changed = conn.execute(
                    "UPDATE fed_native_sends SET state='unknown', result_json=? WHERE msg_id=? AND state='intent'",
                    (dump({"reason": "interrupted_during_send"}), row["msg_id"])).rowcount
                if changed != 1:
                    continue
                attempt, task = self._load(str(row["msg_id"]))
                if attempt is not None and task is not None:
                    mirror.record_evidence(self.store, self.ident, task, attempt,
                                           {"state": "unknown", "reason": "interrupted_during_send", "at": now},
                                           now=now)
                    self.store.set_inbox_state(attempt.msg_id, state="applied", expected=("ready",))
            recovered += 1
        if recovered:
            self.log("federation_recovered_interrupted", {"count": recovered})
        return recovered

    # ---- 分发 ----

    def _load(self, msg_id: str) -> tuple[FedAttempt | None, FedTask | None]:
        attempt = self.store.attempt_by_msg(msg_id)
        if attempt is None:
            return None, None
        return attempt, self.store.get_task(attempt.authority_device, attempt.task_id)

    @staticmethod
    def _suppress_reason(task: FedTask, attempt: FedAttempt) -> str | None:
        """这条作业按最新控制应被抑制的原因（结束回执不受结束/暂停限制，但受本机归档限制）；与收件时同一判定。"""
        return mirror.suppress_reason(task, attempt)

    def _blocked(self, task: FedTask, attempt: FedAttempt) -> bool:
        """暂时不能领取（等待，不抑制）。领取 CAS 锁内会再判一次。"""
        return mirror.blocked(self.store, self.ident, task, attempt, now=self.clock())

    def _finish_pre_intent(self, attempt: FedAttempt, task: FedTask, reason: str, *, state: str = "failed") -> str:
        """intent 之前确定失败/抑制：同事务写 native 终态与证据；这类失败可证明从未外调。"""
        now = self.clock()
        with self.store.transaction() as conn:
            target_state = "suppressed" if state == "cancelled" else "finished"
            changed = conn.execute(
                "UPDATE fed_native_sends SET state=?, result_json=? WHERE msg_id=? AND state='prepared'"
                " AND intent_at IS NULL", (target_state, dump({"reason": reason}), attempt.msg_id)).rowcount
            if changed != 1:
                return "skipped"
            mirror.record_evidence(self.store, self.ident, task, attempt, {"state": state, "reason": reason, "at": now},
                                   now=now)
            self.store.set_inbox_state(attempt.msg_id, state="applied", expected=("ready",))
        self._missing_since.pop(attempt.msg_id, None)
        self.log("federation_delivery_failed" if state == "failed" else "federation_suppressed",
                 {"task": short(attempt.task_id), "attempt": attempt.seq, "reason": reason})
        return "failed" if state == "failed" else "skipped"

    def dispatch(self, msg_id: str, endpoints: list[Endpoint]) -> str:
        """尝试投递一条联邦本机作业，返回 sent / waiting / failed / skipped。"""
        attempt, task = self._load(msg_id)
        if attempt is None or task is None:
            return "skipped"
        reason = self._suppress_reason(task, attempt)
        if reason is not None:
            return self._finish_pre_intent(attempt, task, reason, state="cancelled")
        if self._blocked(task, attempt):
            return "waiting"
        local = attempt.target.local
        if local is None:
            return self._finish_pre_intent(attempt, task, "target_not_found")
        if not ADAPTERS[local.provider].inbox:
            return self._finish_pre_intent(attempt, task, "target_no_inbox")
        live, problem = select_generation(local, endpoints)
        if problem is not None:
            return self._finish_pre_intent(attempt, task, f"target_{problem}")
        now = self.clock()
        if live is None:
            # 与本机 Dispatcher 同口径：该 provider 发现不完整才等待；完整的空结果（对方已退出）照常进 15 秒宽限
            if self.provider_discovery_complete is not None and not self.provider_discovery_complete(local.provider):
                return "waiting"
            if (self.provider_discovery_complete is None and not endpoints
                    and not (self.empty_discovery_complete is not None and self.empty_discovery_complete())):
                return "waiting"  # 没有完整性信号时，整体为空按发现失败处理，不据此判定目标不在
            first = self._missing_since.setdefault(msg_id, now)
            if now - first < TARGET_GONE_GRACE_SECONDS * 1000:
                return "waiting"
            return self._finish_pre_intent(attempt, task, "target_gone")
        self._missing_since.pop(msg_id, None)
        binding = self.store.binding(attempt.target.remote.endpoint_id)
        if get_platform().name == "windows":
            if not local.data_root or live.ref.data_root != local.data_root:
                return self._finish_pre_intent(attempt, task, "target_root_changed")
        elif binding is None or root_binding(live.ref) != binding["root_binding"]:
            # 选中的活端点必须仍在绑定时的 provider 根上：换根不能借同 UUID 恢复（§88.6）
            return self._finish_pre_intent(attempt, task, "target_root_changed")
        if live.blocking_issues:
            return self._finish_pre_intent(attempt, task, f"target_{live.blocking_issues[0]}")
        if "shared_thread" in live.issues and attempt.options.get("allowShared") is not True:
            return self._finish_pre_intent(attempt, task, "target_shared_thread")
        provider = live.ref.provider
        transport = self.transports.get(provider)
        if transport is None or (provider is Provider.CLAUDE and self.reply_address is None):
            return "waiting"  # Claude 回执只能由持有收件箱的 worker 接收
        try:
            lines, versions = self._prepare_attachments(task, attempt)
        except AttachmentError as error:
            if error.code in attachments.TRANSIENT_CODES:
                return "waiting"  # 本机落地时写满/写抖动：暂时的，等下一轮，不记失败（Opus r2-P3-1）
            return self._finish_pre_intent(attempt, task, error.code)  # 附件损坏绝不 native 投递
        except OSError:
            return "waiting"  # 复制到私有 part 时的本机文件错误：同样暂时
        text, context = self._render(task, attempt, lines, provider)
        identity = self._identity()
        revision = int(binding["revision"]) if binding is not None else None
        if identity is None or not self._claim(attempt, live, versions, identity, now, binding_revision=revision):
            return "skipped"
        try:
            outcome = transport.deliver(live, text, context)
        except Exception as error:  # 外调可能已发生：只能记为不明
            outcome = DeliveryOutcome(Delivery.UNKNOWN, "transport_exception",
                                      detail={"exception": type(error).__name__})
        self._record_outcome(attempt, live, outcome)
        return "failed" if outcome.delivery is Delivery.FAILED else "sent"

    # ---- 附件 ----

    def _delivery_path(self, row: Mapping[str, Any]) -> Path:
        return self.paths.delivery_base(self.store.ledger_instance_id()) / str(row["local_relpath"])

    def _prepare_attachments(self, task: FedTask, attempt: FedAttempt) -> tuple[list[str] | None, dict[int, str]]:
        """intent 前核每个 blob 的交付文件身份/大小/SHA；本机目标的冻结副本此时落交付叶。返回 (附件段, 版本)。"""
        rows = self.store.attachments(attempt.msg_id)
        if not rows:
            return None, {}
        lines: list[str] = []
        versions: dict[int, str] = {}
        for row in rows:
            name = str(row["original_name"])
            source = f"{self._device_name(str(row['origin_device']))}:{row['original_path']}"
            if row["transfer"] == "reference":
                reason = _REASON_TEXT.get(str(row["reason"]), str(row["reason"]))
                lines.append(f"- {name}：{REFERENCE_NOTICE}（{reason}；来源 {source}，{row['size']} B）")
                versions[int(row["ref_index"])] = "reference"
                continue
            if row["state"] == "staged":
                row = self._land_staged(task, attempt, row)
            if row["state"] != "ready" or row["location"] != "delivery":
                raise AttachmentError("attachment_unavailable")
            path = self._delivery_path(row)
            recorded = load_dict(row["file_identity_json"])
            try:
                current = attachments.identity(path)
                intact = attachments.file_digest(path) == (row["sha256"], int(row["size"]))
            except (OSError, AttachmentError):
                intact, current = False, {}
            if not intact or any(current.get(key) != recorded.get(key) for key in ("dev", "ino", "size")):
                raise AttachmentError("attachment_unavailable")  # DB ready 但文件丢失/被改：不投
            versions[int(row["ref_index"])] = str(row["file_identity_json"])
            lines.append(f"- {name}：{path}（{row['size']} B，sha256 {str(row['sha256'])[:12]}；来源 {source}）")
        return lines, versions

    def _land_staged(self, task: FedTask, attempt: FedAttempt, row: dict[str, Any]) -> dict[str, Any]:
        """本机目标：从冻结副本（或已校验的接收副本）复制到私有 part，再落交付叶；不把远端 local_path 抄过来。"""
        source = local_blob(self.store, self.paths, str(row["sha256"]))
        if source is None:
            raise AttachmentError("attachment_unavailable")
        self.paths.parts.mkdir(mode=0o700, parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=self.paths.parts, prefix="local-", suffix=".part")
        os.close(fd)
        part = Path(tmp)
        try:
            shutil.copyfile(source, part)
            if attachments.file_digest(part) != (row["sha256"], int(row["size"])):
                raise AttachmentError("attachment_hash_mismatch")
            directory = attachments.delivery_dir(
                state_root=self.paths.state_root, windows=self.paths.windows,
                instance_id=self.store.ledger_instance_id(), local_appdata=self.paths.local_appdata,
                task_id=task.task_id, authority_device=task.authority_device)
            landed = attachments.land(part, directory, name=str(row["original_name"]), sha=str(row["sha256"]),
                                      size=int(row["size"]), copy_new_leaf=self.paths.windows)
        finally:
            if part.exists():
                part.unlink()
        relpath = landed.relative_to(self.paths.delivery_base(self.store.ledger_instance_id())).as_posix()
        identity = json.dumps(attachments.identity(landed), sort_keys=True)
        self.store.update_attachment(attempt.msg_id, int(row["ref_index"]), state="ready", location="delivery",
                                     local_relpath=relpath, file_identity_json=identity, verified_at=self.clock())
        return {**row, "state": "ready", "location": "delivery", "local_relpath": relpath,
                "file_identity_json": identity}

    # ---- 渲染 ----

    def _device_name(self, device_id: str) -> str:
        if device_id == self.ident.device_id:
            return self.ident.device_name
        for row in self.store.device_states():
            if row["device_id"] == device_id and row["name"]:
                return str(row["name"])
        return device_id  # 进消息头 device= 与页脚 --origin-device：用完整 deviceId，8 位前缀解析不了

    def _render(self, task: FedTask, attempt: FedAttempt, lines: list[str] | None,
                provider: Provider) -> tuple[str, DeliveryContext]:
        view_task = model_task(task)
        view_attempt = replace(model_attempt(attempt), refs=[])
        sender = attempt.sender
        sender_device = self._device_name(sender.device_id) if sender is not None else self.ident.device_name
        # 头 from 与帧 from-name 按 actor 的结构化身份生成完整 ID，不照抄存下的 wireToken：旧账本与 W3.9 对端的
        # actor 带的是友好名，跨设备照抄会让漏 --device 时命中本机同名会话（§91.4.2）
        token = id_token(sender.provider, sender.native_id) if sender is not None else "user"
        text = envelope.render(view_task, view_attempt, sender=token,
                               device=sender_device, command=self.command,
                               origin_device=self._device_name(task.authority_device), attachment_lines=lines)
        if sender is not None:
            name = sender_display(token, sender_device)
        elif REMINDER_OPTION in attempt.options:
            name = "AgentStatus 协作桥（提醒）"
        elif attempt.is_closure:
            name = "AgentStatus 协作桥（结束回执）"
        else:
            name = "AgentStatus 协作桥（用户）"
        context = DeliveryContext(
            message_uuid=message_uuid(attempt.msg_id),
            sender_name=name,
            sender_session=sender.native_id if sender is not None and sender.provider is Provider.CLAUDE else None,
            # 已认证设备转述的真实类别；unknown 照 unknown，不升级（§88.9）
            sender_class=attempt.sender_class if attempt.sender_class in ("bypass", "prompting") else None,
            reply_to=self.reply_address if provider is Provider.CLAUDE else None,
            priority=native_priority(view_attempt),
            before_send=(lambda: self._windows_boundary(attempt)) if get_platform().name == "windows" else None,
        )
        return text, context

    def _windows_boundary(self, attempt: FedAttempt) -> None:
        with self.store.transaction():
            native = self.store.native(attempt.msg_id)
            if native is None or native["state"] != "intent":
                raise StoreError("boundary_record_failed")
            self.store.add_event(attempt.authority_device, attempt.task_id, "native_send_boundary", now=self.clock(),
                                 attempt_seq=attempt.seq)

    # ---- intent CAS ----

    @staticmethod
    def _identity() -> dict[str, Any] | None:
        if get_platform().name == "windows":
            record = get_platform().process.read(os.getpid()).record
            if record is None:
                return None
            return {"pid": record.identity.pid, "start": record.identity.stored_generation()}
        me = procfs.read_process(os.getpid())
        return {"pid": me.pid, "start": me.start_ticks} if me is not None else None

    def _claim(self, attempt: FedAttempt, live: Endpoint, versions: dict[int, str], identity: dict[str, Any],
               now: int, *, binding_revision: int | None) -> bool:
        """在外调之前的一个 IMMEDIATE 事务里 CAS prepared→intent；锁内复读全部领取条件（§88.5 ①–⑦）。"""
        with self.store.transaction() as conn:
            native = self.store.native(attempt.msg_id)
            if native is None or native["state"] != "prepared" or native["intent_at"] is not None:
                return False
            inbox = self.store.inbox_item(attempt.msg_id)
            if inbox is None or inbox["apply_state"] != "ready":
                return False
            current, task = self._load(attempt.msg_id)
            if current is None or task is None:
                return False
            reason = self._suppress_reason(task, current)
            if reason is not None:
                mirror.suppress_one(self.store, self.ident, task, current, reason=reason, now=now)
                self.store.set_inbox_state(current.msg_id, state="applied", expected=("ready",))
                return False
            if self._blocked(task, current):
                return False
            for row in self.store.attachments(current.msg_id):
                expected = versions.get(int(row["ref_index"]))
                actual = "reference" if row["transfer"] == "reference" else str(row["file_identity_json"])
                if row["transfer"] == "blob" and row["state"] != "ready" or expected != actual:
                    return False  # 附件状态在核验与领取之间变了：下一轮重新核验
            binding = self.store.binding(current.target.remote.endpoint_id)
            if (int(binding["revision"]) if binding is not None else None) != binding_revision:
                return False  # 本机端点绑定在核验与领取之间换了代际/根：下一轮按新绑定重新核验
            if REMINDER_OPTION in current.options and not self._reminder_current(task, current):
                mirror.suppress_one(self.store, self.ident, task, current, reason="reminder_outdated", now=now)
                self.store.set_inbox_state(current.msg_id, state="applied", expected=("ready",))
                return False
            changed = conn.execute(
                "UPDATE fed_native_sends SET state='intent', intent_at=?, worker_generation=?, local_target_json=?"
                " WHERE msg_id=? AND state='prepared' AND intent_at IS NULL",
                (now, dump(identity), live.ref.to_json(), current.msg_id)).rowcount
            if changed != 1:
                return False
            # 投递设备上 delivery=pending 的含义是「从未 intent」：与 intent 同事务改成 sending（实现决定 D3）
            self.store.update_attempt_columns(current.msg_id, delivery=dict(current.delivery, state="sending", at=now))
        return True

    # ---- 结果 ----

    def _record_outcome(self, attempt: FedAttempt, live: Endpoint, outcome: DeliveryOutcome) -> None:
        now = self.clock()
        evidence: dict[str, Any] = {"state": outcome.delivery.value, "reason": outcome.reason, "at": now}
        result = {"delivery": outcome.delivery.value, "reason": outcome.reason, "providerRef": outcome.provider_ref,
                  "deliveredPane": live.ref.pane, "deliveredPid": live.ref.pid}
        final = "unknown" if outcome.delivery is Delivery.UNKNOWN else "finished"
        try:
            with self.store.transaction() as conn:
                conn.execute("UPDATE fed_native_sends SET state=?, result_json=? WHERE msg_id=? AND state='intent'",
                             (final, dump(result), attempt.msg_id))
                current, task = self._load(attempt.msg_id)
                if current is not None and task is not None:
                    mirror.record_evidence(self.store, self.ident, task, current, evidence, now=now)
                self.store.set_inbox_state(attempt.msg_id, state="applied", expected=("ready",))
        except StoreError as error:
            # 结果落账失败：不再调用 adapter；保留结果下轮重写，期间 worker 驻留；worker 退出后由恢复收敛为 UNKNOWN
            self._unrecorded[attempt.msg_id] = (attempt, live, outcome)
            self.log("federation_record_deferred", {"task": short(attempt.task_id), "code": error.code})
            return
        self.log("federation_delivery_result", {"task": short(attempt.task_id), "attempt": attempt.seq,
                                                "delivery": outcome.delivery.value, "reason": outcome.reason})

    # ---- Claude 回执 ----

    def handle_frame(self, frame: object) -> str | None:
        """处理收件箱的回执帧：只认联邦作业的 message uuid（本机库的由本机 Dispatcher 处理）。"""
        receipt = parse_receipt(frame)
        if receipt is None:
            return None
        return "receipt" if self.apply_receipt(receipt) else None

    def apply_receipt(self, receipt: Receipt) -> bool:
        msg_id = receipt.message_uuid.replace("-", "")
        native = self.store.native(msg_id) if len(msg_id) == 32 else None
        if native is None:
            return False
        sources = _RECEIPT_SOURCES.get(receipt.delivery.value)
        attempt, task = self._load(msg_id)
        if sources is None or attempt is None or task is None:
            return False
        if attempt.delivery.get("state") not in sources:
            return False
        now = self.clock()
        with self.store.transaction():
            mirror.record_evidence(self.store, self.ident, task, attempt,
                                   {"state": receipt.delivery.value, "reason": receipt.reason, "at": now}, now=now)
        return True

    # ---- A 侧 30 分钟提醒 ----

    def _reminder_candidates(self):  # noqa: ANN202 - 内部生成器
        return mirror.reminder_candidates(self.store, self.clock())

    def _reminder_current(self, task: FedTask, attempt: FedAttempt) -> bool:
        """已排的提醒发送前核对：本次关注的令牌没变、也没被发起方拒绝才照发，与本机 dispatch._reminder_outdated 同判据。

        不能再问 pending_reminder：它回答「还缺不缺一条提醒」，已排的这条本身就让它返回 None，有效提醒会把自己作废
        （Codex r4-P2-02）。
        """
        view = model_task(task)
        attempts = model_attempts(self.store.attempts(task.authority_device, task.task_id))
        current = reminder_token(view, attempts)
        return (current is not None and current[0] == attempt.options.get(REMINDER_OPTION)
                and not attention_declined(view, attempts, current[1]))

    def queue_reminders(self) -> int:
        """只在权威设备 A 上算提醒（B 不催）；到期仍未处理的发起方各排一条（§88.4）。"""
        now = self.clock()
        self._reminder_retry = {key: at for key, at in self._reminder_retry.items() if at > now}
        queued = 0
        for task, reminder, due in list(self._reminder_candidates()):
            if not due or reminder.token in self._reminder_retry:
                continue
            origin = task.origin()
            assert origin is not None
            if not authority.can_notify(origin):
                continue
            attempts = self.store.attempts(task.authority_device, task.task_id)
            view_task, view_attempts = model_task(task), model_attempts(attempts)
            current = reminder.view.current
            stuck = next((item for item in attempts if current is not None and item.seq == current.seq), None)
            receiver = (remote_text(stuck.target, self._device_name(stuck.target_device))
                        if stuck is not None and stuck.target_device != self.ident.device_id else None)
            try:
                _, notice = authority.add_attempt(
                    self.store, self.ident, task, role="notice", target=origin,
                    body=reminder_body(view_task, view_attempts, reminder.view, command=self.command,
                                       receiver=receiver), refs=[],
                    sender=None, sender_class=reminder_sender_class(view_attempts) or "unknown",
                    options={"noticeKind": "reminder", REMINDER_OPTION: reminder.token}, now=now,
                    event="origin_reminded")
            except StoreError as error:
                self._reminder_retry[reminder.token] = now + REMINDER_RETRY_MS
                self.log("federation_reminder_failed", {"task": short(task.task_id), "code": error.code})
                continue
            queued += 1
            self.log("federation_reminder_queued", {"task": short(task.task_id), "attempt": notice.seq})
        return queued
