"""hub stdio 服务端（DESIGN §88.1/§88.2）：一条 SSH 连接一个进程，按 forced command 绑定的登记设备服务。

身份只来自 forced command 参数映射的登记设备，并用 sshd ExposeAuthInfo 的实际公钥指纹核对；不信客户端 hello 自报。
握手：hello → hello_ack（核协议、必需能力、ledgerInstanceId）→ 事务内取得新 fence → ready。之后每个业务读写核 fence，
主循环每秒复核一次，被新连接取代或设备撤销时停止。stdout 只有帧，错误只给闭集码，不回显异常/SQL/命令。
"""

from __future__ import annotations

import time
from collections.abc import Callable
from typing import Any

from ..ids import new_id
from .codec import (
    BLOB_CHUNK_BYTES,
    MAX_BLOB_BYTES,
    MAX_ENVELOPE_BYTES,
    MAX_FRAME_BYTES,
    MAX_MESSAGE_BLOB_BYTES,
    MAX_REFS,
    PROTOCOL_MAJOR,
    PROTOCOL_MINOR,
    REQUIRED_CAPABILITIES,
    TRANSFER_TTL_MS,
    CodecError,
    error_frame,
    is_hex32,
)
from .hubstore import HubStore
from .transport import FederationTransport

HANDSHAKE_TIMEOUT_S = 30.0
REPUSH_MS = 30_000  # 同项重复推送不早于 30 秒
GC_INTERVAL_MS = 60_000
CAPABILITIES = tuple(sorted(REQUIRED_CAPABILITIES))
LIMITS = {"frameBytes": MAX_FRAME_BYTES, "envelopeBytes": MAX_ENVELOPE_BYTES, "blobBytes": MAX_BLOB_BYTES,
          "messageBlobBytes": MAX_MESSAGE_BLOB_BYTES, "chunkBytes": BLOB_CHUNK_BYTES, "refs": MAX_REFS,
          "ttlMs": TRANSFER_TTL_MS}
# 会话收到这些码后停止：连接身份已不成立
FATAL_CODES = frozenset({"connection_superseded", "device_revoked", "device_unregistered", "frame_too_large"})

EXIT_OK = 0
EXIT_REFUSED = 3


def now_ms() -> int:
    return time.time_ns() // 1_000_000


class HubSession:
    """一条已认证 SSH 连接上的会话；同一线程处理请求与写帧（单 writer）。"""

    def __init__(self, store: HubStore, transport: FederationTransport, *, device_name: str,
                 auth: Callable[[], str], clock: Callable[[], int] = now_ms, tick_seconds: float = 1.0,
                 handshake_timeout: float = HANDSHAKE_TIMEOUT_S) -> None:
        self.store = store
        self.transport = transport
        self.device_name = device_name
        self._auth = auth
        self._clock = clock
        self._tick = tick_seconds
        self._handshake_timeout = handshake_timeout
        self.device_id: str | None = None
        self.connection_id: str | None = None
        self._pushed: dict[str, int] = {}
        self._last_gc = 0
        self._gc_owner = new_id()

    # ---- 写帧 ----

    def _send(self, frame: dict[str, Any]) -> None:
        self.transport.write_frame(frame)

    def _error(self, code: str, request_id: str | None = None) -> None:
        self._send(error_frame(code, request_id=request_id))

    def _reply(self, kind: str, request_id: str | None, **fields: Any) -> None:
        frame: dict[str, Any] = {"type": kind, "commitCounter": self.store.counter, **fields}
        if request_id is not None:
            frame["requestId"] = request_id
        self._send(frame)

    # ---- 握手 ----

    def _handshake(self) -> bool:
        device = self.store.device(self.device_name)
        if device is None or device["name"] != self.device_name:
            self._error("device_unregistered")
            return False
        if device["status"] != "active":
            self._error("device_revoked")
            return False
        try:
            fingerprint = self._auth()
        except CodecError as error:
            self._error(error.code)
            return False
        if fingerprint != device["public_key_fingerprint"]:
            self._error("identity_mismatch")  # authorized_keys 把别的设备公钥绑到了这个 slug
            return False
        self.store.read_counter()
        self._send({"type": "hello", "protocol": {"major": PROTOCOL_MAJOR, "minor": PROTOCOL_MINOR},
                    "hubId": self.store.hub_id(), "deviceId": device["device_id"], "deviceName": device["name"],
                    "serverTime": self._clock(), "commitCounter": self.store.counter, "limits": LIMITS,
                    "capabilities": list(CAPABILITIES)})
        try:
            ack = self.transport.read_frame(timeout=self._handshake_timeout)
        except TimeoutError:
            self._error("handshake_required")
            return False
        except CodecError as error:
            self._error(error.code)
            return False
        if ack is None:
            return False
        if ack.get("type") != "hello_ack":
            self._error("handshake_required", ack.get("requestId"))
            return False
        protocol = ack.get("protocol")
        if not isinstance(protocol, dict) or protocol.get("major") != PROTOCOL_MAJOR:  # pyright: ignore[reportUnknownMemberType]
            self._error("protocol_unsupported")
            return False
        capabilities = ack.get("capabilities")
        if not isinstance(capabilities, list) or not REQUIRED_CAPABILITIES <= set(capabilities):  # pyright: ignore[reportUnknownArgumentType]
            self._error("capability_missing")
            return False
        ledger = ack.get("ledgerInstanceId")
        if not is_hex32(ledger):
            self._error("frame_invalid")
            return False
        try:
            connection_id, generation = self.store.begin_connection(device["device_id"], ledger_instance_id=str(ledger),
                                                                    now=self._clock())
        except CodecError as error:
            self._error(error.code)  # 握手失败不踢掉健康连接
            return False
        self.device_id, self.connection_id = str(device["device_id"]), connection_id
        self._send({"type": "ready", "connectionId": connection_id, "connectionGeneration": generation,
                    "commitCounter": self.store.counter})
        return True

    # ---- 主循环 ----

    def run(self) -> int:
        """跑完整个会话；返回进程退出码。"""
        try:
            if not self._handshake():
                return EXIT_REFUSED
            return self._loop()
        finally:
            if self.device_id is not None and self.connection_id is not None:
                try:
                    self.store.drop_connection_uploads(self.device_id, self.connection_id)
                except CodecError:
                    pass
            self.transport.close()

    def _loop(self) -> int:
        next_tick = time.monotonic() + self._tick
        while True:
            timeout = max(0.0, next_tick - time.monotonic())
            try:
                frame = self.transport.read_frame(timeout=timeout)
            except TimeoutError:
                frame = None
                eof = False
            except CodecError as error:
                self._error(error.code)
                if error.code in FATAL_CODES:
                    return EXIT_REFUSED
                continue
            else:
                eof = frame is None
            if eof:
                return EXIT_OK
            if frame is not None:
                if not self._dispatch(frame):
                    return EXIT_REFUSED
            if time.monotonic() >= next_tick:
                next_tick = time.monotonic() + self._tick
                if not self._periodic():
                    return EXIT_REFUSED

    def _periodic(self) -> bool:
        """每秒：复核 fence（撤销/被取代即停）；每 60 秒竞争租约做一次小批 GC。"""
        assert self.device_id is not None and self.connection_id is not None
        try:
            self.store.check_fence(self.device_id, self.connection_id)
        except CodecError as error:
            self._error(error.code)
            return error.code not in FATAL_CODES
        now = self._clock()
        if now - self._last_gc >= GC_INTERVAL_MS:
            self._last_gc = now
            try:
                self.store.gc(now=now, owner=self._gc_owner)
            except CodecError:
                pass  # GC 失败不影响会话；下一轮再试
        return True

    def _dispatch(self, frame: dict[str, Any]) -> bool:
        assert self.device_id is not None and self.connection_id is not None
        request_id = frame.get("requestId")
        kind = frame.get("type")
        me, conn = self.device_id, self.connection_id
        try:
            if not is_hex32(request_id):
                raise CodecError("frame_invalid", "request_id")
            now = self._clock()
            if kind == "heartbeat":
                self._reply("heartbeat_ack", request_id, **self.store.heartbeat(me, conn, now=now))
            elif kind == "submit":
                envelope = frame.get("envelope")
                if not isinstance(envelope, dict):
                    raise CodecError("frame_invalid", "envelope")
                hint = frame.get("payloadHash")
                result = self.store.submit(me, conn, envelope, now=now,  # pyright: ignore[reportUnknownArgumentType]
                                           payload_hash_hint=hint if isinstance(hint, str) else None)
                self._reply("accepted", request_id, **result)
            elif kind == "fetch":
                self._fetch(str(request_id), frame, now)
            elif kind == "ack":
                self.store.ack(me, conn, frame.get("msgId"), frame.get("payloadHash"), now=now)
                self._pushed.pop(str(frame.get("msgId")), None)
                self._reply("acked", request_id, msgId=frame.get("msgId"))
            elif kind == "reject":
                reason = self.store.reject(me, conn, frame.get("msgId"), frame.get("payloadHash"),
                                           reason=frame.get("reason"), now=now)
                self._pushed.pop(str(frame.get("msgId")), None)
                self._reply("rejected", request_id, msgId=frame.get("msgId"), reason=reason)
            elif kind == "receipts_get":
                ids = frame.get("msgIds")
                if ids is not None and not isinstance(ids, list):
                    raise CodecError("frame_invalid", "msg_ids")
                after = frame.get("after")
                if after is not None and (not isinstance(after, int) or isinstance(after, bool)):
                    raise CodecError("frame_invalid", "after")
                page = self.store.receipts(me, conn, after=after, msg_ids=ids,  # pyright: ignore[reportUnknownArgumentType]
                                           source=frame.get("sourceDeviceId"), from_floor=frame.get("fromFloor") is True)
                self._reply("receipt_page", request_id, **page)
            elif kind == "receipt_seen":
                seen = self.store.receipt_seen(me, conn, frame.get("through"))
                self._reply("receipt_seen_ok", request_id, through=seen)
            elif kind == "directory_put":
                result = self.store.directory_put(me, conn, revision=frame.get("revision"),
                                                  snapshot=frame.get("snapshot"), now=now)
                self._reply("directory_ack", request_id, **result)
            elif kind == "directory_get":
                devices = frame.get("devices")
                if devices is not None and (not isinstance(devices, list)
                                            or not all(is_hex32(item) for item in devices)):  # pyright: ignore[reportUnknownVariableType]
                    raise CodecError("frame_invalid", "devices")
                snapshots = self.store.directory_get(me, conn, devices=devices, now=now)  # pyright: ignore[reportUnknownArgumentType]
                # 每设备一帧，带 index/total 让客户端知道何时收齐；没有设备时回一帧 total=0
                for index, snapshot in enumerate(snapshots):
                    self._reply("directory_snapshot", request_id, index=index, total=len(snapshots), **snapshot)
                if not snapshots:
                    self._reply("directory_snapshot", request_id, index=0, total=0)
            elif kind == "blob_begin":
                self._reply("blob_ready", request_id,
                            **self.store.blob_begin(me, conn, sha256=frame.get("sha256"), size=frame.get("size"),
                                                    now=now))
            elif kind == "blob_chunk":
                next_offset = self.store.blob_chunk(me, conn, upload_id=frame.get("uploadId"),
                                                    offset=frame.get("offset"), data=frame.get("data"))
                self._reply("blob_chunk_ack", request_id, uploadId=frame.get("uploadId"), nextOffset=next_offset)
            elif kind == "blob_finish":
                self._reply("blob_stored", request_id,
                            **self.store.blob_finish(me, conn, upload_id=frame.get("uploadId"), now=now))
            elif kind == "blob_get":
                self._reply("blob_data", request_id,
                            **self.store.blob_get(me, conn, msg_id=frame.get("msgId"), ref_index=frame.get("refIndex"),
                                                  offset=frame.get("offset")))
            elif kind == "hello_ack":
                raise CodecError("frame_invalid", "duplicate_hello")
            else:
                raise CodecError("frame_invalid", "unexpected_type")  # 响应类帧不能当请求
        except CodecError as error:
            self._error(error.code, request_id if is_hex32(request_id) else None)
            return error.code not in FATAL_CODES
        return True

    def _fetch(self, request_id: str, frame: dict[str, Any], now: int) -> None:
        assert self.device_id is not None and self.connection_id is not None
        after = frame.get("after", 0)
        if not isinstance(after, int) or isinstance(after, bool):
            raise CodecError("frame_invalid", "after")
        recent = frozenset(msg for msg, at in self._pushed.items() if now - at < REPUSH_MS)
        items, end = self.store.fetch(self.device_id, self.connection_id, after=after, skip=recent)
        for item in items:
            self._pushed[item["msgId"]] = now
            self._reply("item", request_id, **item)
        self._reply("fetch_end", request_id, **end)
