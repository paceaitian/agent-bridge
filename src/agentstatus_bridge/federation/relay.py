"""relay（DESIGN §88.1/§88.2/§88.10）：每设备一个，普通用户出站连 hub，搬运 outbox/inbox、附件、收据与目录。

relay 不调用 provider send、不启动/恢复 agent、不裁决业务：收到的信封交给 mirror.receive（A 侧报告由同一 reducer 裁决），
原生投递由 worker 做。握手核 hubId、deviceId、持久最大 commitCounter（回退即 hub_state_lost）与 ledgerInstanceId；
重连/缺口恢复期间先置 ingressCatchup，处理完首轮 fetch_end（过期空洞 → sync_required）才清，防止 worker 抢先领取。
"""

from __future__ import annotations

import base64
import json
import os
import random
import sqlite3
import subprocess
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ..ids import new_id
from ..model import DELIVERY_NEEDS_ATTENTION
from ..store import StoreError
from . import attachments, budget, mirror, retention
from .attachments import AttachmentError
from .authority import Identity
from .codec import (
    BLOB_CHUNK_BYTES,
    ERROR_CODES,
    PROTOCOL_MAJOR,
    PROTOCOL_MINOR,
    REQUIRED_CAPABILITIES,
    RETRYABLE_ERRORS,
    CodecError,
    canonical_bytes,
    payload_hash,
    sha256_hex,
)
from .config import SSH_CONFIG_NAME, FederationConfig, ssh_argv, ssh_config_text
from .fedstore import FederatedStore, load_dict
from .hubstore import REJECT_REASONS
from .transport import FederationTransport, StreamTransport

HEARTBEAT_MS = 30_000
DIRECTORY_SAMPLE_MS = 30_000
DIRECTORY_MIN_GAP_MS = 5_000
SYNC_INTERVAL_MS = 60_000
WORK_WAKE_MS = 15_000  # 每 15 秒看一次有没有新的可处理作业要拉起 worker（首次拉起失败也靠它重试）
REWAKE_MIN_MS = 12 * 60_000  # 已拉起过的作业仍在：停泊（10 分钟）加空闲退出（2 分钟）之后再拉起复查一次
REWAKE_MAX_MS = 6 * 3_600_000  # 复查间隔逐次翻倍到 6 小时：目标长期不在时 worker 基本不驻留，回来后迟早续投
RETENTION_INTERVAL_MS = 3_600_000  # 本机留存回收每小时一轮（§88.3/§88.4）
REQUEST_TIMEOUT_S = 60.0
HEALTHY_RESET_S = 120.0
AUTH_RETRY_S = 300.0
FETCH_BATCHES_PER_CYCLE = 8
SUBMIT_PER_CYCLE = 16
# submit 遇到这些码：同 ID 稍后重试（attachment_missing 多为上传与 GC 交错）
RETRY_LATER = RETRYABLE_ERRORS | {"attachment_missing"}
# 握手/连接级失败后不自动重连、等运维处理的状态
STOP_STATES = frozenset({"hub_state_lost", "ledger_instance_mismatch", "incompatible", "identity_mismatch",
                         "device_revoked", "device_unregistered", "state_root_mismatch", "federation_store_missing"})
_RECEIPT_TARGETS = {
    "accepted": ("accepted", ("ready", "submitting")),
    "l2": ("received", ("ready", "submitting", "accepted")),
    "rejected": ("rejected", ("ready", "submitting", "accepted")),
    "expired": ("expired", ("ready", "submitting", "accepted")),
    "revoked": ("revoked", ("ready", "submitting", "accepted")),
}


def _storage_failure(error: StoreError) -> bool:
    """本机库忙/只读/写失败/库不可用等基础设施错误（可恢复），区别于来源/冲突/容量这类确定业务拒绝。"""
    return error.code.startswith(("store_", "federation_store_"))


class RelayStop(Exception):
    """本次连接结束；state 进 fed_meta.relayState，供 doctor/status 展示。"""

    def __init__(self, state: str) -> None:
        super().__init__(state)
        self.state = state


def now_ms() -> int:
    return time.time_ns() // 1_000_000


def reconnect_delay(attempt: int, *, low: int = 30, high: int = 300, jitter: float | None = None) -> float:
    """`min(high, low*2^min(n,4)) + Uniform(0,15)` 秒；永不短于 low（30 秒）。"""
    base = min(high, low * 2 ** min(attempt, 4))
    return max(float(low), base + (random.uniform(0, 15) if jitter is None else jitter))


class HubConnection:
    """协议客户端（单线程）：写请求，按 requestId 收集响应帧，跟踪认证回复里的 commitCounter。"""

    def __init__(self, transport: FederationTransport, *, on_counter: Callable[[int], None],
                 timeout: float = REQUEST_TIMEOUT_S, should_stop: Callable[[], bool] = lambda: False) -> None:
        self.transport = transport
        self._on_counter = on_counter
        self._timeout = timeout
        self._should_stop = should_stop

    def _read(self) -> dict[str, Any]:
        try:
            frame = self.transport.read_frame(timeout=self._timeout)
        except TimeoutError as error:
            raise RelayStop("hub_unavailable") from error
        except CodecError as error:
            raise RelayStop("incompatible") from error
        if frame is None:
            raise RelayStop("hub_unavailable")
        counter = frame.get("commitCounter")
        if isinstance(counter, int) and not isinstance(counter, bool):
            self._on_counter(counter)
        return frame

    def request(self, kind: str, **fields: Any) -> list[dict[str, Any]]:
        """发一个请求，返回属于它的全部帧（item/directory_snapshot 收齐后连同终结帧）；错误帧抛 CodecError。"""
        if self._should_stop():
            raise RelayStop("stopped")  # 停止已请求：不再发新请求（含附件 chunk），由 connect_and_run 收尾（§90.5）
        request_id = new_id()
        try:
            self.transport.write_frame({"type": kind, "requestId": request_id, **fields})
        except OSError as error:
            raise RelayStop("hub_unavailable") from error  # 管道断了（SSH 退出）：按断线重连，不当本机文件错误
        frames: list[dict[str, Any]] = []
        while True:
            frame = self._read()
            if frame.get("type") == "error" and frame.get("requestId") is None:
                raise RelayStop(str(frame.get("code") or "hub_unavailable"))  # 连接级错误（被取代/撤销）
            if frame.get("requestId") != request_id:
                continue  # 迟到的旧请求响应
            if frame["type"] == "error":
                raise CodecError(str(frame.get("code")) if frame.get("code") in ERROR_CODES else "hub_unavailable")
            frames.append(frame)
            if frame["type"] == "item":
                continue
            if frame["type"] == "directory_snapshot":
                if int(frame.get("total", 0)) > int(frame.get("index", 0)) + 1:
                    continue
            return frames

    def call(self, kind: str, **fields: Any) -> dict[str, Any]:
        return self.request(kind, **fields)[-1]


class SubprocessTransport(StreamTransport):
    """SSH 子进程上的帧通道；关闭时结束子进程（不读 stderr，日志不含 SSH 错误文本）。"""

    TERMINATE_GRACE_S = 5.0

    def __init__(self, process: subprocess.Popen[bytes]) -> None:
        assert process.stdout is not None and process.stdin is not None
        super().__init__(process.stdout, process.stdin)
        self.process = process
        self._reap_lock = threading.Lock()  # 同一 Popen 的 terminate/kill/wait 串行：abort 与 close 不争 waitpid/信号

    def abort(self) -> None:
        """停止控制线程调用（DESIGN §90.5），幂等：唤醒读方，再结束并回收本连接的 ssh；不关 Python 流、不碰 worker。

        ssh 退出后管道断开，阻塞在写 flush 上的主线程得到 BrokenPipe/OSError 返回。
        """
        self.wake()
        with self._reap_lock:
            self._reap()

    def close(self) -> None:
        # 先终止并回收子进程，再关流：后台读线程可能正阻塞在 readline 上、持有读端的锁，先关读端会一直等下去，
        # terminate 永远轮不到；写端 flush 也可能因对端不读而阻塞（Codex AS89-C-P2-04）。子进程退出后管道断开，
        # 读线程读到 EOF 释放锁；远端按异常断开处理（hub 的 CAS 与重推本就覆盖断连）。
        # 控制线程正在 abort 时，这里在同一把锁上等它回收完，再关流（§90.5）
        with self._reap_lock:
            self._reap()
        super().close()

    def _reap(self) -> None:
        if self.process.poll() is not None:
            return
        try:
            self.process.terminate()
            self.process.wait(timeout=self.TERMINATE_GRACE_S)
        except subprocess.TimeoutExpired:
            self.process.kill()
            try:
                self.process.wait(timeout=self.TERMINATE_GRACE_S)
            except subprocess.TimeoutExpired:
                pass  # kill 之后仍未回收只可能是系统异常；不在关闭路径上无限等
        except OSError:
            pass  # 进程已在别处退出（ESRCH/拒绝访问）：交给 poll/wait 的结果，不在停止路径上抛


def ssh_connector(config: FederationConfig, state_root: Path, *,
                  windows: bool = False) -> Callable[[], FederationTransport]:
    """生成 SSH 连接工厂：专用 -F 配置写在私有 state 下（0600），argv 不经 shell。

    Windows 上 ssh 用 CREATE_NO_WINDOW：relay 无论由 headless 控制台还是无控制台的父进程拉起，
    ssh 都不会另开可见窗口（DESIGN §89）。
    """

    def connect() -> FederationTransport:
        path = state_root / SSH_CONFIG_NAME
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(ssh_config_text(config))
        process = subprocess.Popen(ssh_argv(config, path), stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                   stderr=subprocess.DEVNULL, creationflags=0x08000000 if windows else 0)
        return SubprocessTransport(process)

    return connect


@dataclass
class RelayPaths:
    """relay 用到的本机路径：冻结副本 staging、私有下载 part、交付根。"""

    state_root: Path
    windows: bool = False
    local_appdata: Path | None = None

    @property
    def staging(self) -> Path:
        return self.state_root / "fed-staging"

    @property
    def parts(self) -> Path:
        return self.state_root / "fed-parts"

    @property
    def delivery_owner(self) -> Path:
        """交付目录所在的自有根：Linux 是状态根，Windows 是 LocalAppData（其下各级不得是链接）。"""
        if self.windows:
            if self.local_appdata is None:
                raise AttachmentError("attachment_path_unavailable")  # 没有 LocalAppData 就没有交付位置
            return self.local_appdata.resolve()
        return self.state_root.resolve()

    def delivery_base(self, instance_id: str) -> Path:
        if self.windows:
            return self.delivery_owner / "agent-bridge-inbox" / instance_id
        return self.state_root.resolve() / "attachments"


def local_blob(store: FederatedStore, paths: RelayPaths, sha: str) -> Path | None:
    """本机持有该 SHA 的已冻结/已校验副本：staging 优先，其次已落地的交付或私有副本；不重读源路径。"""
    candidate = paths.staging / f"{sha}.blob"
    if candidate.is_file():
        return candidate
    for row in store.blob_sources(sha):
        base = paths.delivery_base(store.ledger_instance_id()) if row["location"] == "delivery" else paths.staging
        path = base / str(row["local_relpath"])
        if path.is_file():
            return path
    return None


@dataclass
class _Timers:
    heartbeat: int = 0
    directory_sample: int = 0
    directory_put: int = 0
    sync: int = 0
    retention: int = 0
    wake: int = 0
    sync_sent: dict[str, int] = field(default_factory=dict)


# 需要发起方处理的投递状态（与 model.DELIVERY_NEEDS_ATTENTION 同一组）：B 回传这些证据时 A 立即叫醒 worker
_ATTENTION_STATES = frozenset(delivery.value for delivery in DELIVERY_NEEDS_ATTENTION)


def _needs_attention(envelope: dict[str, Any]) -> bool:
    """delivery_status 信封里的证据状态是否属于需处理集合；形状不对一律 False（只决定叫不叫醒，不影响应用）。"""
    data = envelope.get("data")
    evidence = data.get("evidence") if isinstance(data, dict) else None
    state = evidence.get("state") if isinstance(evidence, dict) else None
    return isinstance(state, str) and state in _ATTENTION_STATES


class Relay:
    """一个设备的 relay；`connect_and_run` 跑一条连接直到断开或停止。"""

    def __init__(self, store: FederatedStore, ident: Identity, config: FederationConfig, paths: RelayPaths, *,
                 connect: Callable[[], FederationTransport],
                 directory: Callable[[], dict[str, Any]] | None = None,
                 on_work: Callable[[], bool | None] | None = None,
                 on_tick: Callable[[], None] | None = None,
                 clock: Callable[[], int] = now_ms) -> None:
        self.store = store
        self.ident = ident
        self.config = config
        self.paths = paths
        self._connect = connect
        self._directory = directory
        self._on_work = on_work or (lambda: None)
        self._on_tick = on_tick or (lambda: None)  # 主线程的诊断发布点（§90.6）：每轮循环与每段退避各调一次
        self._should_stop: Callable[[], bool] = lambda: False
        self._clock = clock
        self._timers = _Timers()
        self._max_counter = 0
        # 已成功拉起过 worker 的 prepared 作业 → (下次复查时刻, 当前间隔)；停泊的不每 15 秒拉回来
        self._woken: dict[str, tuple[int, int]] = {}
        self.conn: HubConnection | None = None

    # ---- 状态 ----

    def _set_state(self, state: str) -> None:
        self.store.set_meta("relayState", state)

    def _counter_key(self) -> str:
        return f"maxHubCommitCounter:{self.config.hub_id}"

    def _observe_counter(self, value: int) -> None:
        """认证回复只取 max 持久保存：普通回复可能乱序，旧值不误冻结。"""
        if value > self._max_counter:
            self._max_counter = value
            self.store.set_meta(self._counter_key(), str(value))

    # ---- 握手 ----

    def handshake(self, transport: FederationTransport) -> HubConnection:
        if self.store.meta("hubStateLost") == "1":
            raise RelayStop("hub_state_lost")
        try:
            hello = transport.read_frame(timeout=REQUEST_TIMEOUT_S)
        except (TimeoutError, CodecError) as error:
            raise RelayStop("hub_unavailable") from error
        if hello is None:
            raise RelayStop("hub_unavailable")
        if hello.get("type") == "error":
            code = str(hello.get("code"))
            raise RelayStop("auth_failed" if code == "auth_evidence_unavailable" else code)
        if hello.get("type") != "hello" or (hello.get("protocol") or {}).get("major") != PROTOCOL_MAJOR:
            raise RelayStop("incompatible")
        capabilities = set(hello.get("capabilities") or [])
        if not REQUIRED_CAPABILITIES <= capabilities:
            raise RelayStop("incompatible")
        if hello.get("deviceId") != self.config.device_id:
            raise RelayStop("identity_mismatch")
        if hello.get("hubId") != self.config.hub_id:
            self.store.set_meta("hubStateLost", "1")  # hubId 变化：旧路线冻结，不自动接到新 hub
            raise RelayStop("hub_state_lost")
        persisted = int(self.store.meta(self._counter_key()) or "0")
        counter = hello.get("commitCounter")
        if not isinstance(counter, int) or counter < persisted:
            self.store.set_meta("hubStateLost", "1")  # 新连接计数低于见过的最大值：hub 回退
            raise RelayStop("hub_state_lost")
        self._max_counter = persisted
        try:
            transport.write_frame({"type": "hello_ack", "protocol": {"major": PROTOCOL_MAJOR, "minor": PROTOCOL_MINOR},
                                   "capabilities": sorted(capabilities & REQUIRED_CAPABILITIES),
                                   "ledgerInstanceId": self.store.ledger_instance_id()})
        except OSError as error:
            raise RelayStop("hub_unavailable") from error  # 管道已断（ssh 退出或被停止中止）：不当认证失败
        try:
            ready = transport.read_frame(timeout=REQUEST_TIMEOUT_S)
        except (TimeoutError, CodecError) as error:
            raise RelayStop("hub_unavailable") from error
        if ready is None:
            raise RelayStop("hub_unavailable")
        if ready.get("type") == "error":
            raise RelayStop(str(ready.get("code")))
        if ready.get("type") != "ready":
            raise RelayStop("incompatible")
        self._observe_counter(int(ready.get("commitCounter") or 0))
        # 先持久 catchup：首轮 fetch_end 处理完之前 worker 不领取联邦 prepared
        self.store.set_meta("ingressCatchup", "1")
        self._set_state("connected")
        self.store.set_meta("relayLastSeen", str(self._clock()))  # 本机最后认证活动（doctor lastSeen）
        self.conn = HubConnection(transport, on_counter=self._observe_counter, should_stop=self._should_stop)
        return self.conn

    # ---- 一轮 ----

    def cycle(self) -> None:
        """一轮：收件、发 outbox、收收据、周期任务（心跳/目录/窄同步）。

        先收件再发：收件应用产生的决定/同步回复在同一轮发出，不多等一秒。
        """
        assert self.conn is not None
        self._fetch_inbox()
        self._submit_outbox()
        self._poll_receipts()
        self._periodic()

    def connect_and_run(self, *, cycles: int | None = None, wait: Callable[[float], None] = time.sleep,
                        should_stop: Callable[[], bool] = lambda: False, stopper: Any = None) -> str:
        """建立一条连接并循环；cycles=None 时一直跑到断开或 should_stop。返回结束状态。

        stopper（StopController）登记本条连接，停止时由它的控制线程中止 ssh（§90.5）。停止优先：
        已请求停止时，读断、写断、协议错误与库忙都归 stopped，不重连、不当认证失败。
        """
        self._should_stop = should_stop
        if should_stop():
            return self._stopped()  # 停止后不再新建连接
        transport = self._connect()
        if stopper is not None:
            stopper.bind(transport)  # 停止先于绑定时，bind 立即中止这条新连接
        try:
            self.handshake(transport)
            done = 0
            while cycles is None or done < cycles:
                self._on_tick()
                if should_stop():
                    return self._stopped()
                self.cycle()
                done += 1
                if cycles is None or done < cycles:
                    wait(1.0)
            return "connected"
        except RelayStop as stop:
            if should_stop():
                return self._stopped()
            self._set_state(stop.state if stop.state in STOP_STATES or stop.state == "auth_failed"
                            else "reconnecting")
            return stop.state
        except CodecError:
            if should_stop():
                return self._stopped()
            # 某个请求收到 hub 的错误帧而调用处没有专门处理：结束这条连接、按退避重连，不让 relay 进程崩出
            self._set_state("reconnecting")
            return "hub_unavailable"
        except StoreError as error:
            if not _storage_failure(error):
                raise
            if should_stop():
                return self._stopped()
            # 收件分类之外的本机写遇到库忙/暂不可用：同样结束这条连接、按退避重连，不靠进程崩溃后的服务重启
            # （状态都已持久、hub 会重推；重连也不清空唤醒记录，Opus r2-P3-3）
            try:
                self._set_state("reconnecting")
            except StoreError:
                pass
            return "reconnecting"
        finally:
            self.conn = None
            if stopper is not None:
                stopper.unbind()
            transport.close()  # SubprocessTransport：控制线程正在 abort 时在同一把锁上等它回收完 ssh

    def _stopped(self) -> str:
        """停止收尾：尽力写 offline 诊断，最多 1 秒、库忙就跳过；失败不挡连接关闭与释放单例锁（§90.5）。"""
        try:
            self.store.connection.execute("PRAGMA busy_timeout=1000")
            self._set_state("offline")
        except (StoreError, sqlite3.Error):
            pass
        return "stopped"

    def run_forever(self, *, wait: Callable[[float], None] = time.sleep,
                    should_stop: Callable[[], bool] = lambda: False, stopper: Any = None) -> str:
        """重连循环：退避 30s 起、健康 120 秒清零；停止类状态直接返回等运维处理。"""
        self._should_stop = should_stop
        attempt = 0
        while not should_stop():
            started = time.monotonic()
            state = self.connect_and_run(wait=wait, should_stop=should_stop, stopper=stopper)
            if state in STOP_STATES or state == "stopped":
                return state
            if time.monotonic() - started >= HEALTHY_RESET_S:
                attempt = 0
            delay = AUTH_RETRY_S if state == "auth_failed" else reconnect_delay(
                attempt, low=self.config.reconnect_min, high=self.config.reconnect_max)
            attempt += 1
            self._retention_tick(self._clock())  # 长时间连不上 hub 也照常清过期内容（停止后不开始，见 _retention_tick）
            # 退避分段等待：停止后最多一秒内结束等待，不必等满重连间隔
            while delay > 0 and not should_stop():
                self._on_tick()
                step = min(1.0, delay)
                wait(step)
                delay -= step
        return self._stopped()

    # ---- outbox ----

    def _local_blob(self, sha: str) -> Path | None:
        return local_blob(self.store, self.paths, sha)

    def _upload(self, ref: dict[str, Any]) -> None:
        assert self.conn is not None
        sha, size = str(ref["sha256"]), int(ref["size"])
        ready = self.conn.call("blob_begin", sha256=sha, size=size)
        if ready.get("exists"):
            return
        path = self._local_blob(sha)
        if path is None:
            raise AttachmentError("attachment_unavailable")
        offset = 0
        with open(path, "rb") as handle:
            while True:
                chunk = handle.read(BLOB_CHUNK_BYTES)
                if not chunk:
                    break
                ack = self.conn.call("blob_chunk", uploadId=ready["uploadId"], offset=offset,
                                     data=base64.b64encode(chunk).decode("ascii"))
                offset = int(ack["nextOffset"])
        self.conn.call("blob_finish", uploadId=ready["uploadId"])

    def _refuse(self, item: dict[str, Any], reason: str) -> None:
        """不再发送这条发件，并把业务收尾放进同一事务（崩溃不会只留下传输终态而丢了解冻/未投事实）。

        只有本轮之前从未 submit 过的（载入时仍是 ready）才是「确定未 L1」的 refused、可作已证明未投；
        之前已经 submit 过（submitting：可能已被 hub 接纳并投到）的一律记 expired，只记事件，不当未投证据。
        """
        now = self._clock()
        uncertain = item["state"] == "submitting"
        state = "expired" if uncertain else "refused"
        derived = False
        with self.store.transaction():
            if self.store.set_outbox_state(item["msg_id"], state=state, expected=("ready", "submitting"),
                                           receipt={"error": reason, "at": now, "uncertain": uncertain}):
                derived = mirror.transport_failed(self.store, self.ident, item, state=state, reason=reason, now=now)
        if derived:
            self._wake_for_attention()

    def _settled_by_receipt(self, item: dict[str, Any], now: int) -> bool:
        """上次 submit 结果不明（submitting）：先按 msg_id 查 hub 收据，查到就照收据推进，不再重传附件或重交。"""
        assert self.conn is not None
        try:
            page = self.conn.call("receipts_get", msgIds=[item["msg_id"]])
        except CodecError as error:
            if error.code in RETRY_LATER:
                self._backoff(item, now)
                return True
            raise RelayStop("hub_unavailable") from error
        receipts = page["byMessage"][0]["receipts"] if page.get("byMessage") else []
        if not receipts:
            return False
        self._apply_receipts(receipts)
        return True

    def _submit_outbox(self) -> None:
        assert self.conn is not None
        now = self._clock()
        for item in self.store.outbox(states=("ready", "submitting"), limit=SUBMIT_PER_CYCLE):
            if int(item["next_try_at"]) > now:
                continue
            envelope = load_dict(item["envelope_json"])
            hubs = self.store.task_hubs(str(envelope.get("authorityDeviceId")), str(envelope.get("taskId")))
            if hubs and self.ident.hub_id not in hubs:
                # 旧 hub 路由上的任务（灾难换 hub 后 A 本机 close 等）：冻结，不转投新 hub，也不当作未投证据
                self.store.set_outbox_state(item["msg_id"], state="revoked", expected=("ready", "submitting"),
                                            receipt={"reason": "hub_rebuilt", "at": now})
                continue
            if item["state"] == "submitting" and self._settled_by_receipt(item, now):
                continue
            try:
                for ref in envelope.get("refs") or []:
                    if ref.get("transfer") == "blob":
                        self._upload(ref)
            except AttachmentError as error:
                self._refuse(item, error.code)  # DB 已引用的 blob 丢了：不改成 reference 后发同一操作
                continue
            except CodecError as error:
                if error.code in RETRY_LATER:
                    self._backoff(item, now)
                else:
                    self._refuse(item, error.code)
                continue
            # 网络 submit 前先持久 submitting：之后只见 L0/L1 或超时都不能证明对方未投
            self.store.set_outbox_state(item["msg_id"], state="submitting", expected=("ready", "submitting"))
            try:
                result = self.conn.call("submit", envelope=envelope, payloadHash=item["payload_hash"])
            except CodecError as error:
                if error.code in RETRY_LATER:
                    self._backoff(item, now)
                elif error.code == "idempotency_conflict":
                    self._resolve_conflict(item, now)
                else:
                    self._refuse(item, error.code)
                continue
            self.store.set_outbox_state(item["msg_id"], state="accepted", expected=("submitting",),
                                        receipt={"acceptedAt": result.get("acceptedAt"),
                                                 "expiresAt": result.get("expiresAt")})

    def _backoff(self, item: dict[str, Any], now: int) -> None:
        current = self.store.outbox_item(item["msg_id"])
        if current is not None:
            self.store.set_outbox_state(item["msg_id"], state=str(current["state"]), next_try_at=now + 30_000)

    def _resolve_conflict(self, item: dict[str, Any], now: int) -> None:
        """同 ID 冲突涉及旧操作：先查原收据，不能用本次拒绝抹掉原投递风险。"""
        assert self.conn is not None
        page = self.conn.call("receipts_get", msgIds=[item["msg_id"]])
        receipts = page["byMessage"][0]["receipts"] if page.get("byMessage") else []
        if receipts:
            self._apply_receipts(receipts)
            return
        self.store.set_outbox_state(item["msg_id"], state="submitting", next_try_at=now + 300_000,
                                    receipt={"error": "idempotency_conflict", "at": now})

    # ---- 收据 ----

    def _apply_receipts(self, receipts: list[dict[str, Any]]) -> None:
        now = self._clock()
        derived = False
        for receipt in receipts:
            target = _RECEIPT_TARGETS.get(str(receipt.get("state")))
            row = self.store.outbox_item(str(receipt.get("msgId")))
            if target is None or row is None:
                continue
            state, allowed = target
            with self.store.transaction():  # 传输终态与业务收尾同一事务，崩溃不留半步
                changed = self.store.set_outbox_state(row["msg_id"], state=state, expected=allowed,
                                                      receipt={"state": receipt.get("state"), "at": receipt.get("at"),
                                                               "reason": receipt.get("reason")})
                if changed and state in ("rejected", "expired", "revoked"):
                    # 只有收件方持久 never-intent 拒绝是已证明未投；expired/revoked 只记事件（mirror 内区分）
                    derived = mirror.transport_failed(
                        self.store, self.ident, row, state=state,
                        reason=str(receipt["reason"]) if receipt.get("reason") else None, now=now) or derived
        if derived:
            self._wake_for_attention()

    def _poll_receipts(self) -> None:
        assert self.conn is not None
        cursor = int(self.store.meta("receiptCursor") or "0")
        for _ in range(FETCH_BATCHES_PER_CYCLE):
            try:
                page = self.conn.call("receipts_get", after=cursor)
            except CodecError as error:
                if error.code != "cursor_gap":
                    raise RelayStop("hub_unavailable") from error
                self._receipt_gap()
                page = self.conn.call("receipts_get", after=cursor, fromFloor=True)
            self._apply_receipts(page.get("items") or [])
            cursor = max(cursor, int(page.get("next") or cursor))
            self.store.set_meta("receiptCursor", str(cursor))
            if not page.get("more"):
                break
        if cursor:
            self.conn.call("receipt_seen", through=cursor)

    def _receipt_gap(self) -> None:
        """收据游标落后保留底线：按本机未结 msg_id 查收据（每次 ≤128），未识别的过期项保持原状等提示。"""
        assert self.conn is not None
        open_items = [row["msg_id"] for row in self.store.outbox(states=("submitting", "accepted"), limit=4096)]
        for start in range(0, len(open_items), 128):
            page = self.conn.call("receipts_get", msgIds=open_items[start:start + 128])
            for entry in page.get("byMessage") or []:
                self._apply_receipts(entry.get("receipts") or [])

    # ---- 收件 ----

    def _fetch_inbox(self) -> None:
        assert self.conn is not None
        for _ in range(FETCH_BATCHES_PER_CYCLE):
            cursor = int(self.store.meta("inboxCursor") or "0")
            frames = self.conn.request("fetch", after=cursor)
            end = frames[-1]
            items = [frame for frame in frames if frame["type"] == "item"]
            # 先处理过期空洞（sync_required 与游标同事务），再应用本批 item：防先到的作业抢在空洞检查前开轮
            with self.store.transaction():
                for source in end.get("expiredSources") or []:
                    mirror.mark_sync_required(self.store, authority_device=str(source))
                if end.get("gap"):
                    mirror.mark_sync_required(self.store, authority_device=None)
            work = False
            for item in items:
                work = self._process_item(item) or work
            with self.store.transaction():
                scanned = int(end.get("scannedThrough") or cursor)
                self.store.set_meta("inboxCursor", str(max(cursor, scanned)))
                if not end.get("more"):
                    self.store.set_meta("ingressCatchup", "0")
            if work:
                self._wake_if_needed()
            if not end.get("more"):
                return

    def _process_item(self, item: dict[str, Any]) -> bool:
        """处理一个收件 item；返回是否产生了可领取的本机作业。附件齐后才应用并 ACK（L2）。"""
        assert self.conn is not None
        envelope: dict[str, Any] = dict(item["envelope"])
        digest = str(item["payloadHash"])
        if payload_hash(envelope) != digest:
            return False  # hub 交来的内容与其哈希不符：不 ACK、不应用，等重推或过期
        source = str(item["sourceDeviceId"])
        msg_id = str(item["msgId"])
        now = self._clock()
        name = envelope.get("sourceDeviceName")
        if isinstance(name, str) and name:
            self.store.remember_device_name(source, name)  # 页脚 --origin-device 与消息头 device= 用登记名
        try:
            state = mirror.begin_receiving(self.store, envelope, source_device=source, payload_hash=digest, now=now)
        except CodecError:
            self.conn.call("ack", msgId=msg_id, payloadHash=digest)  # 同 ID 异内容：已有记录为准，不再重推
            return False
        except StoreError as error:
            if _storage_failure(error):
                return False  # 本机库暂时写不进：不 ACK，hub 30 秒后重推
            raise
        if state == "rejected":
            reason = load_dict(self.store.inbox_item(msg_id)["result_json"]).get("reason")  # type: ignore[index]
            self._hub_reject_or_ack(msg_id, digest, reason)
            return False
        if state in ("ready", "applied"):
            self.conn.call("ack", msgId=msg_id, payloadHash=digest)
            return False
        try:
            self._receive_blobs(msg_id, envelope)
        except AttachmentError as error:
            if error.code in attachments.TRANSIENT_CODES:
                return False  # 预算不足/磁盘写满/本机写抖动：留在 receiving、不 ACK，hub 30 秒后重推，恢复后自然接上
            if mirror.reject_receiving(self.store, msg_id, reason=error.code):
                self._hub_reject_or_ack(msg_id, digest, error.code)
            return False
        except OSError:
            self.store.set_meta(attachments.WRITE_FAILED_META, str(now))
            return False  # 本机写 part/交付叶失败（磁盘、权限抖动）：不发 L2，等重推，不让 relay 进程崩掉
        except CodecError as error:
            if error.code == "message_expired":
                self.store.set_inbox_state(msg_id, state="rejected", expected=("receiving",),
                                           result={"reason": "transport_expired"})
                return False
            if error.code in ("attachment_missing", "identity_mismatch"):
                if mirror.reject_receiving(self.store, msg_id, reason="attachment_unavailable"):
                    self._hub_reject_or_ack(msg_id, digest, "attachment_unavailable")
                return False
            raise RelayStop("hub_unavailable") from error
        try:
            mirror.receive(self.store, self.ident, envelope, source_device=source, payload_hash=digest, now=now)
        except (CodecError, StoreError) as error:
            if isinstance(error, StoreError) and _storage_failure(error):
                # 存储/事务失败不是业务拒绝：保持 receiving、不发 L2，等 hub 重推后再应用同一操作
                return False
            # 业务上不能接受（来源/形状/冲突）：持久记拒绝后 ACK，L2 只表示已完整落账，不代表采纳
            code = error.code
            self.store.set_inbox_state(msg_id, state="rejected", expected=("receiving",), result={"reason": code})
            self.conn.call("ack", msgId=msg_id, payloadHash=digest)
            return False
        self.conn.call("ack", msgId=msg_id, payloadHash=digest)
        if envelope.get("kind") == "delivery_status" and _needs_attention(envelope):
            self._wake_for_attention()
        return self.store.native(msg_id) is not None or envelope.get("kind") == "report"

    def _hub_reject_or_ack(self, msg_id: str, digest: str, reason: object) -> None:
        assert self.conn is not None
        if reason in REJECT_REASONS:
            try:
                self.conn.call("reject", msgId=msg_id, payloadHash=digest, reason=reason)
                return
            except CodecError:
                pass  # 已 L2/过期：hub 不再接受运输拒绝，按本机记录为准
        try:
            self.conn.call("ack", msgId=msg_id, payloadHash=digest)
        except CodecError:
            pass

    def _receive_blobs(self, msg_id: str, envelope: dict[str, Any]) -> None:
        """下载每个 blob 到私有 part、重算 SHA/size，落到交付位置并写 manifest ready。"""
        assert self.conn is not None
        instance = self.store.ledger_instance_id()
        todo = [row for row in self.store.attachments(msg_id) if row["transfer"] == "blob"
                and not (row["state"] == "ready" and self._ready_intact(row, instance))]
        if not todo:
            return
        base = self.paths.delivery_base(instance)
        # 先核实崩溃留下的半成品叶能否直接采用；只有核实可用的才不计预算，记录里有名字不等于已占有完整副本
        recovered = {int(row["ref_index"]): landed for row in todo
                     if (landed := self._recover_pending(row, base)) is not None}
        self._check_budget([row for row in todo if int(row["ref_index"]) not in recovered])
        directory: Path | None = None
        for row in todo:
            if directory is None:
                directory = self._landing(lambda: attachments.delivery_dir(
                    state_root=self.paths.state_root, windows=self.paths.windows, instance_id=instance,
                    local_appdata=self.paths.local_appdata, task_id=str(envelope["taskId"]),
                    authority_device=str(envelope["authorityDeviceId"])))
            index, sha, size = int(row["ref_index"]), str(row["sha256"]), int(row["size"])
            landed = recovered.get(index)
            if landed is None:
                part = self._kept_part(msg_id, index, sha, size) or self._download(msg_id, index, sha, size)

                def remember(dest: Path, ident: dict[str, int], *, _index: int = index) -> None:
                    # 先持久本次新叶的身份，崩溃后只核验/回收这一个文件
                    self.store.update_attachment(msg_id, _index, file_identity_json=json.dumps(
                        {"pendingLeaf": dest.relative_to(base).as_posix(), **ident}, sort_keys=True))

                into = directory  # 已收窄为 Path，闭包里用它
                landed = self._landing(lambda: attachments.land(
                    part, into, name=str(row["original_name"]), sha=sha, size=size,
                    copy_new_leaf=self.paths.windows, on_create=remember))
            relpath = landed.relative_to(base).as_posix()
            self.store.update_attachment(msg_id, int(row["ref_index"]), state="ready", location="delivery",
                                         local_relpath=relpath,
                                         file_identity_json=json.dumps(attachments.identity(landed), sort_keys=True),
                                         verified_at=self._clock())
        if self.store.meta(attachments.WRITE_FAILED_META) and not self.store.inbox_receiving_others(msg_id):
            # 这条完整落地、也没有别的收件还在等重推：清掉暂时失败标记；别的收件仍在持续失败时保留（Opus r4-P3-1）
            self.store.set_meta(attachments.WRITE_FAILED_META, "")

    def _landing(self, step: Callable[[], Path]) -> Path:
        """建交付目录或落交付叶；暂时失败（实际写满、本机写抖动）记下最近一次的时刻给 doctor 看，再照常抛出等重推。

        预算预检不足另记 budgetDeferredAt，不经这里（Opus r4-P3-1）。
        """
        try:
            return step()
        except AttachmentError as error:
            if error.code in attachments.TRANSIENT_CODES:
                self.store.set_meta(attachments.WRITE_FAILED_META, str(self._clock()))
            raise

    def _check_budget(self, rows: list[dict[str, Any]]) -> None:
        """下载新附件前的设备内容预算预检（§88.11）：要新写的字节超出剩余就延后，并记下时间给 doctor 看。"""
        needed = sum(int(row["size"]) for row in rows)
        if not needed:
            return
        if budget.available(self.store, self.paths, self.config.storage_budget) < needed:
            self.store.set_meta(budget.DEFERRED_META, str(self._clock()))
            raise AttachmentError(budget.STORAGE_FULL)
        if self.store.meta(budget.DEFERRED_META):
            self.store.set_meta(budget.DEFERRED_META, "")

    @staticmethod
    def _recover_pending(row: dict[str, Any], base: Path) -> Path | None:
        recorded = load_dict(row.get("file_identity_json"))
        pending = recorded.get("pendingLeaf")
        if row["state"] == "ready" or not isinstance(pending, str):
            return None
        return attachments.recover_pending(base / pending, recorded, sha=str(row["sha256"]), size=int(row["size"]))

    def _ready_intact(self, row: dict[str, Any], instance: str) -> bool:
        path = self.paths.delivery_base(instance) / str(row["local_relpath"])
        try:
            return attachments.file_digest(path) == (row["sha256"], int(row["size"]))
        except (OSError, AttachmentError):
            return False

    def _part_path(self, msg_id: str, ref_index: int) -> Path:
        return self.paths.parts / f"{msg_id}-{ref_index}.part"

    def _kept_part(self, msg_id: str, ref_index: int, sha: str, size: int) -> Path | None:
        """上次已完整下载、只是落地失败时留下的私有 part（落地失败时 part 留在原处）。

        完整就直接复用：持续落地失败时不每 30 秒重下整份（Opus r3-P3-2）。
        """
        part = self._part_path(msg_id, ref_index)
        return part if attachments.intact_copy(part, sha, size) else None

    def _download(self, msg_id: str, ref_index: int, sha: str, size: int) -> Path:
        assert self.conn is not None
        self.paths.parts.mkdir(mode=0o700, parents=True, exist_ok=True)
        part = self._part_path(msg_id, ref_index)
        fd = os.open(part, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_BINARY", 0), 0o600)
        offset = 0
        try:
            with os.fdopen(fd, "wb") as out:
                while True:
                    chunk = self.conn.call("blob_get", msgId=msg_id, refIndex=ref_index, offset=offset)
                    data = base64.b64decode(str(chunk.get("data") or ""), validate=True)
                    if int(chunk.get("offset", -1)) != offset or offset + len(data) > size:
                        raise AttachmentError("attachment_hash_mismatch")
                    out.write(data)
                    offset += len(data)
                    if chunk.get("eof"):
                        break
                    if not data:
                        raise AttachmentError("attachment_hash_mismatch")
                out.flush()
                os.fsync(out.fileno())
            if attachments.file_digest(part) != (sha, size):
                raise AttachmentError("attachment_hash_mismatch")
        except BaseException:
            if part.exists():
                part.unlink()
            raise
        return part

    # ---- 周期任务 ----

    def _periodic(self) -> None:
        assert self.conn is not None
        now = self._clock()
        if now - self._timers.heartbeat >= HEARTBEAT_MS:
            self._timers.heartbeat = now
            beat = self.conn.call("heartbeat")
            self.store.set_meta("relayLastSeen", str(now))
            if self._directory is not None and beat.get("directoryDigest") != self.store.meta("directoryDigest"):
                # hub 上的目录缺失/不同（例如 hub 重建）：下次采样强制重发整帧
                self._timers.directory_put = 0
                self._timers.directory_sample = 0
                self.store.set_meta("directoryLocalDigest", "")
            self._refresh_remote_directory(now)
        if self._directory is not None and now - self._timers.directory_sample >= DIRECTORY_SAMPLE_MS:
            self._timers.directory_sample = now
            self._publish_directory(now)
        if now - self._timers.sync >= SYNC_INTERVAL_MS:
            self._timers.sync = now
            self._sync_mirrors(now)
        if now - self._timers.wake >= WORK_WAKE_MS:
            self._wake_if_needed()  # 不只在新消息到达时：解除暂停/冻结后的作业、首次拉起失败的作业也能接上
        self._retention_tick(now)

    def _retention_tick(self, now: int) -> None:
        """每小时一轮留存回收；连着 hub 时在周期任务里跑，断线退避期间也跑（回收只碰本机库与自有目录）。

        停止已请求时不开始新一轮（§90.5）。
        """
        if now - self._timers.retention < RETENTION_INTERVAL_MS or self._should_stop():
            return
        self._timers.retention = now
        try:
            retention.sweep(self.store, self.paths, now=now)
        except (StoreError, OSError, AttachmentError):
            pass  # 回收失败只是晚点再删，不影响收发；下一小时重试

    def _wake_for_attention(self) -> None:
        """投递证据落在需处理集合、或 A 侧派生了 failed：立即叫醒 worker（DESIGN §103.2 立即告知、§103.7 面板刷新），
        不等 15 秒的作业轮询；worker 启动时强制发布摘要。拉起失败或退避中由 on_work 自己处理，下个周期照常复查。"""
        if not self._should_stop():
            self._on_work()

    def _wake_if_needed(self) -> None:
        """有现在就能处理的作业时拉起 worker（拉起与退避由 on_work 负责，worker 已在跑时只探一下锁）。

        - intent（外调中或执行者已退出、待恢复为 UNKNOWN）：每个周期都确认 worker 在跑，直到恢复收敛；
        - prepared：新出现的立即拉起；拉起过的按 12 分钟起、逐次翻倍到 6 小时的间隔再复查，等不到目标的作业不让
          worker 常驻，worker 启动即退出或目标回来了也迟早接上。新作业、relay 重启或会拉起 worker 的本机 ab 命令立即复查。
        冻结/暂停的作业不算（解除后才算新）。拉起失败下一周期重试。
        """
        now = self._clock()
        self._timers.wake = now
        candidates = mirror.wake_candidates(self.store, self.ident, now=now)
        intents = {str(row["msg_id"]) for row in self.store.natives_in(("intent",))}
        self._woken = {msg_id: due for msg_id, due in self._woken.items() if msg_id in candidates}
        due = {msg_id for msg_id in candidates
               if msg_id in intents or msg_id not in self._woken or self._woken[msg_id][0] <= now}
        if not due or self._should_stop() or self._on_work() is not True:
            return  # 拉起失败/退避中/停止已请求，或 worker 已在跑（可能正要空闲退出）：都不记下，下个周期再看
        for msg_id in due - intents:
            previous = self._woken.get(msg_id)
            interval = REWAKE_MIN_MS if previous is None else min(previous[1] * 2, REWAKE_MAX_MS)
            self._woken[msg_id] = (now + interval, interval)

    def _publish_directory(self, now: int) -> None:
        """整帧目录：规范化内容 digest 变化才发，且不快于 5 秒；无变化只靠心跳。"""
        assert self.conn is not None and self._directory is not None
        snapshot = self._directory()
        local = sha256_hex(canonical_bytes(snapshot))
        previous = self.store.meta("directoryLocalDigest")
        if local == previous:
            return  # 无变化：只靠心跳延续，不递增 revision、不反复写 snapshot
        if previous:
            # 本机会话出现或消失：停泊作业等的目标可能回来了，全部候选下个周期立即复查（Opus r2-P2-2）。
            # 首次发布与 hub 要求整帧重发（previous 为空）不算会话变化
            self._woken.clear()
        if now - self._timers.directory_put < DIRECTORY_MIN_GAP_MS:
            return
        revision = int(self.store.meta("directoryRevision") or "0") + 1
        ack = self.conn.call("directory_put", revision=revision, snapshot=snapshot)
        self._timers.directory_put = now
        with self.store.transaction():
            self.store.set_meta("directoryRevision", str(revision))
            self.store.set_meta("directoryDigest", str(ack.get("digest") or ""))  # hub 侧摘要，心跳据此比对
            self.store.set_meta("directoryLocalDigest", local)

    def _refresh_remote_directory(self, now: int) -> None:
        assert self.conn is not None
        for frame in self.conn.request("directory_get"):
            device = frame.get("deviceId")
            if not device or device == self.ident.device_id:
                continue
            state = "online" if frame.get("online") else ("revoked" if frame.get("status") != "active" else "offline")
            self.store.put_device_state(device_id=str(device), name=str(frame.get("deviceName") or ""),
                                        revision=int(frame.get("revision") or 0), snapshot=frame.get("snapshot") or {},
                                        last_seen=frame.get("lastSeen"), state=state)

    def _decision_overdue(self, task: Any, now: int) -> bool:
        """有报告已交到 A（L2）或已过期却超过 60 秒没有决定：决定可能丢了，用窄同步查。"""
        for item in mirror.pending_reports(self.store, self.ident, task):
            row = self.store.connection.execute(
                "SELECT state,hub_receipt_json FROM fed_outbox WHERE operation_id=?", (item["operationId"],)).fetchone()
            if row is None or row[0] not in ("received", "expired"):
                continue
            at = load_dict(row[1]).get("at")
            if not isinstance(at, int) or now - at >= SYNC_INTERVAL_MS:
                return True
        return False

    def _sync_mirrors(self, now: int) -> None:
        """需要同步的镜像每 task 一条窄 sync_request，且同一 task 至少隔 60 秒（§88.4 第 7 条）。"""
        with self.store.transaction():
            for row in self.store.connection.execute(
                    "SELECT authority_device,task_id,last_sync_at,state_json FROM fed_tasks WHERE is_authority=0"
                    " AND local_archived=0 AND sync_required=0").fetchall():
                state = load_dict(row[3])
                if state.get("acceptedAt") is None and state.get("closedAt") is None and (
                        now - int(row[2]) >= mirror.STALE_MIRROR_MS or int(row[2]) - now > mirror.CLOCK_ROLLBACK_MS):
                    self.store.connection.execute(
                        "UPDATE fed_tasks SET sync_required=1 WHERE authority_device=? AND task_id=?", (row[0], row[1]))
        # 候选只取需同步的镜像与本机还有未决报告的任务：不随历史任务总数截断（墓碑永久保留）
        candidates = self.store.connection.execute(
            "SELECT authority_device,task_id FROM fed_tasks WHERE is_authority=0 AND local_archived=0 AND sync_required=1"
            " UNION SELECT r.authority_device,r.task_id FROM fed_reports r LEFT JOIN fed_report_decisions d"
            " ON d.reporter_device=r.reporter_device AND d.report_operation_id=r.operation_id"
            " WHERE r.reporter_device=? AND d.decision IS NULL", (self.ident.device_id,)).fetchall()
        for authority_device, task_id in candidates:
            task = self.store.get_task(str(authority_device), str(task_id))
            if task is None or task.is_authority or task.local_archived:
                continue
            if not (task.sync_required or self._decision_overdue(task, now)):
                continue
            key = f"{task.authority_device}:{task.task_id}"
            if now - self._timers.sync_sent.get(key, -SYNC_INTERVAL_MS) < SYNC_INTERVAL_MS:
                continue
            if self._sync_outstanding(task):
                continue  # 每 task 最多一个未结查询：A 离线时不每分钟往 hub 堆一条（§88.4 第 7 条）
            self._timers.sync_sent[key] = now
            mirror.request_sync(self.store, self.ident, task, now=now)

    def _sync_outstanding(self, task: Any) -> bool:
        """这个 task 是否已有一条还没送到 A 的 sync_request（待发、发送中或 hub 已收）。"""
        row = self.store.connection.execute(
            "SELECT 1 FROM fed_outbox WHERE state IN ('ready','submitting','accepted')"
            " AND json_extract(envelope_json,'$.kind')='sync_request'"
            " AND json_extract(envelope_json,'$.authorityDeviceId')=? AND json_extract(envelope_json,'$.taskId')=? LIMIT 1",
            (task.authority_device, task.task_id)).fetchone()
        return row is not None
