"""hub 存储（DESIGN §88.1/§88.2/§88.11）：hub.sqlite3 单库里的设备登记、连接 fence、mailbox、收据、目录与 BLOB CAS。

hub 只做存储转发：不导入任务/报告/结束回执状态机，不解释正文。每个修改数据的事务恰好让 commitCounter 加一，
读回复带同一读快照里的值；设备据此检测 hub 回退（hub_state_lost）。只依赖标准库与 codec，不导入 provider/GNOME。
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import os
import shutil
import sqlite3
from collections.abc import Callable, Generator, Mapping
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from ..ids import new_id
from .codec import (
    BLOB_CHUNK_BYTES,
    MAX_BLOB_BYTES,
    MAX_MESSAGE_BLOB_BYTES,
    TRANSFER_TTL_MS,
    CodecError,
    canonical_bytes,
    check_envelope,
    is_hex32,
    is_hex64,
    is_slug,
    loads_strict,
    payload_hash,
    sha256_hex,
)

HUB_DB_NAME = "hub.sqlite3"
HUB_SCHEMA_VERSION = 1
DEFAULT_BUDGET_BYTES = 2 * 1024**3
MIN_FREE_BYTES = 256 * 1024**2
ROW_OVERHEAD_BYTES = 512
DAY_MS = 86400 * 1000
CONTENT_RETENTION_MS = 30 * DAY_MS  # L2/终结后信封与 blob 引用再留 30 天
RECEIPT_RETENTION_MS = 60 * DAY_MS  # 紧凑收据与去重行留 60 天
ORPHAN_MS = DAY_MS  # 异常遗留上传、未被引用的完整 CAS 至少留 24 小时
MAX_CLOCK_SKEW_MS = DAY_MS  # 信封 createdAt 不得领先 hub 时钟超过一天（防晚重放躲过去重行回收）
GC_BATCH = 256
GC_LEASE_MS = 120_000
FETCH_MAX_ITEMS = 16
FETCH_MAX_BYTES = 1024 * 1024
RECEIPT_PAGE = 128
DIRECTORY_MAX_ENDPOINTS = 256
DIRECTORY_MAX_ENDPOINT_BYTES = 2048
DIRECTORY_MAX_BYTES = 768 * 1024
# 收件设备在 L2 前可声明的运输拒绝原因（§88.3 闭集）
REJECT_REASONS = frozenset(
    {"attachment_unreadable", "attachment_not_regular", "attachment_source_changed", "attachment_unavailable",
     "attachment_hash_mismatch", "attachment_path_unavailable", "task_cancelled", "task_finished", "stale_attempt",
     "mirror_archived"}
)
MESSAGE_OUTCOMES = frozenset({"queued", "l2", "rejected", "expired", "revoked"})

_SCHEMA_V1 = (
    "CREATE TABLE hub_meta(key TEXT PRIMARY KEY,value TEXT NOT NULL)",
    """CREATE TABLE hub_devices(device_id TEXT PRIMARY KEY,name TEXT NOT NULL UNIQUE,display_name TEXT NOT NULL,
        public_key_fingerprint TEXT NOT NULL UNIQUE,status TEXT NOT NULL,ledger_instance_id TEXT,
        connection_generation INTEGER NOT NULL DEFAULT 0,connection_id TEXT,last_seen INTEGER,
        next_recipient_seq INTEGER NOT NULL DEFAULT 1)""",
    """CREATE TABLE hub_directory(device_id TEXT PRIMARY KEY REFERENCES hub_devices(device_id),
        revision INTEGER NOT NULL,snapshot_json TEXT NOT NULL,received_at INTEGER NOT NULL)""",
    """CREATE TABLE hub_blobs(sha256 TEXT PRIMARY KEY,size INTEGER NOT NULL,data BLOB NOT NULL,
        verified_at INTEGER NOT NULL,CHECK(size BETWEEN 0 AND 8388608))""",
    """CREATE TABLE hub_uploads(upload_id TEXT PRIMARY KEY,source_device TEXT NOT NULL,connection_id TEXT NOT NULL,
        sha256 TEXT NOT NULL,size INTEGER NOT NULL,received_bytes INTEGER NOT NULL,started_at INTEGER NOT NULL,
        data BLOB NOT NULL,CHECK(size BETWEEN 0 AND 8388608))""",
    """CREATE TABLE hub_messages(msg_id TEXT PRIMARY KEY,source_device TEXT NOT NULL,operation_id TEXT NOT NULL,
        target_device TEXT NOT NULL,recipient_seq INTEGER NOT NULL,payload_hash TEXT NOT NULL,envelope_json TEXT,
        payload_bytes INTEGER NOT NULL,accepted_at INTEGER NOT NULL,expires_at INTEGER NOT NULL,l2_at INTEGER,
        outcome TEXT NOT NULL,UNIQUE(source_device,operation_id),UNIQUE(target_device,recipient_seq))""",
    """CREATE TABLE hub_blob_refs(msg_id TEXT NOT NULL REFERENCES hub_messages(msg_id),ref_index INTEGER NOT NULL,
        sha256 TEXT NOT NULL REFERENCES hub_blobs(sha256),PRIMARY KEY(msg_id,ref_index))""",
    # reason 列是对设计 DDL 的补充：拒绝收据要把闭集原因带给源设备（§88.2 reject）
    """CREATE TABLE hub_receipts(seq INTEGER PRIMARY KEY AUTOINCREMENT,source_device TEXT NOT NULL,
        msg_id TEXT NOT NULL,state TEXT NOT NULL,at INTEGER NOT NULL,reason TEXT,UNIQUE(msg_id,state))""",
    """CREATE TABLE hub_cursors(device_id TEXT PRIMARY KEY,scan_through INTEGER NOT NULL DEFAULT 0,
        receipt_seen INTEGER NOT NULL DEFAULT 0)""",
    "CREATE INDEX hub_target_pending ON hub_messages(target_device,outcome,recipient_seq)",
    "CREATE INDEX hub_expiry ON hub_messages(expires_at,outcome)",
    "CREATE INDEX hub_source_receipts ON hub_receipts(source_device,seq)",
    "CREATE INDEX hub_blob_references ON hub_blob_refs(sha256)",
)


def openssh_fingerprint(key_blob: bytes) -> str:
    """OpenSSH 的 SHA256 指纹形状：`SHA256:` + 无填充 base64。"""
    return "SHA256:" + base64.b64encode(hashlib.sha256(key_blob).digest()).decode("ascii").rstrip("=")


def parse_public_key(line: str) -> tuple[str, bytes]:
    """解析一行 OpenSSH 公钥 `<type> <base64> [comment]`，返回 (类型, 解码后的 key blob)。

    只支持普通公钥：证书（类型含 -cert-）或内嵌类型与声明不符一律拒绝，不猜测身份。
    """
    parts = line.strip().split()
    if len(parts) < 2:
        raise CodecError("auth_evidence_unavailable", "public_key_shape")
    key_type, encoded = parts[0], parts[1]
    if "-cert-" in key_type or not key_type.isascii() or len(key_type) > 64:
        raise CodecError("auth_evidence_unavailable", "public_key_type")
    try:
        blob = base64.b64decode(encoded, validate=True)
    except (binascii.Error, ValueError) as error:
        raise CodecError("auth_evidence_unavailable", "public_key_base64") from error
    # SSH wire 格式：uint32 长度 + 类型名，必须与声明一致
    if len(blob) < 4:
        raise CodecError("auth_evidence_unavailable", "public_key_blob")
    length = int.from_bytes(blob[:4], "big")
    if blob[4:4 + length] != key_type.encode("ascii"):
        raise CodecError("auth_evidence_unavailable", "public_key_blob")
    return key_type, blob


def auth_fingerprint(path: str | None) -> str:
    """读 sshd ExposeAuthInfo 的临时认证记录（§88.15）：恰好一条 publickey 行才给出指纹。

    文件缺失、超过 64 KiB、没有/多于一条 publickey、证书或格式不可识别都报 auth_evidence_unavailable。
    """
    if not path:
        raise CodecError("auth_evidence_unavailable", "missing")
    try:
        with open(path, "rb") as handle:
            raw = handle.read(64 * 1024 + 1)
    except OSError as error:
        raise CodecError("auth_evidence_unavailable", "unreadable") from error
    if len(raw) > 64 * 1024:
        raise CodecError("auth_evidence_unavailable", "too_large")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as error:
        raise CodecError("auth_evidence_unavailable", "encoding") from error
    keys = [line.split(None, 1)[1] for line in text.splitlines() if line.startswith("publickey ") and " " in line]
    if len(keys) != 1:
        raise CodecError("auth_evidence_unavailable", "publickey_count")
    _, blob = parse_public_key(keys[0])
    return openssh_fingerprint(blob)


def _b64decode(value: object) -> bytes:
    if not isinstance(value, str):
        raise CodecError("frame_invalid", "data")
    try:
        return base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError) as error:
        raise CodecError("frame_invalid", "data") from error


def _storage_error(error: sqlite3.Error) -> CodecError:
    """SQLite 错误投影成闭集网络码：锁忙可重试，写满/只读报存储满，其余 hub 不可用。"""
    name = str(getattr(error, "sqlite_errorname", ""))
    if name.startswith("SQLITE_BUSY") or name.startswith("SQLITE_LOCKED"):
        return CodecError("hub_busy")
    if name.startswith("SQLITE_FULL"):
        return CodecError("hub_storage_full")
    return CodecError("hub_unavailable")


class HubStore:
    """hub 账本连接。公开写方法各自一个 IMMEDIATE 事务并让 commitCounter 恰好加一。"""

    def __init__(self, connection: sqlite3.Connection, path: Path, *,
                 free_bytes: Callable[[Path], int] | None = None) -> None:
        self._conn = connection
        self._conn.row_factory = sqlite3.Row
        self.path = path
        self._free_bytes = free_bytes or (lambda where: shutil.disk_usage(where).free)
        self.counter = 0  # 最近一次事务/读快照里的 commitCounter

    # ---- 建库与打开 ----

    @staticmethod
    def _private_dir(directory: Path) -> Path:
        directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        os.chmod(directory, 0o700)
        return directory

    @classmethod
    def _connect(cls, path: Path, **kwargs: Any) -> HubStore:
        try:
            connection = sqlite3.connect(path, timeout=5.0, isolation_level=None)
        except sqlite3.Error as error:
            raise CodecError("hub_unavailable") from error
        store = cls(connection, path, **kwargs)
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("PRAGMA synchronous=FULL")
        connection.execute("PRAGMA foreign_keys=ON")
        return store

    @classmethod
    def init(cls, directory: Path, *, now: int, **kwargs: Any) -> tuple[HubStore, bool]:
        """`hub init`：库不存在就建（随机 hubId）；已存在只核 schema，绝不重置旧库。返回 (store, 是否新建)。"""
        root = cls._private_dir(directory)
        path = root / HUB_DB_NAME
        if path.exists():
            return cls.open(root, **kwargs), False
        fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        os.close(fd)
        store = cls._connect(path, **kwargs)
        with store._tx(bump=False) as conn:
            for statement in _SCHEMA_V1:
                conn.execute(statement)
            conn.executemany("INSERT INTO hub_meta(key,value) VALUES (?,?)", (
                ("hubId", new_id()), ("commitCounter", "1"), ("createdAt", str(now)),
                ("storageBudgetBytes", str(DEFAULT_BUDGET_BYTES)),
            ))
            conn.execute(f"PRAGMA user_version={HUB_SCHEMA_VERSION}")
        store.counter = 1
        return store, True

    @classmethod
    def open(cls, directory: Path, **kwargs: Any) -> HubStore:
        """打开已有 hub 库；不存在或 schema 不符直接报 hub_unavailable，不自动建库。"""
        path = directory / HUB_DB_NAME
        if not path.exists():
            raise CodecError("hub_unavailable", "missing")
        store = cls._connect(path, **kwargs)
        version = int(store._conn.execute("PRAGMA user_version").fetchone()[0])
        if version != HUB_SCHEMA_VERSION:
            store.close()
            raise CodecError("hub_unavailable", "schema")
        return store

    def close(self) -> None:
        self._conn.close()

    # ---- 事务 ----

    @contextmanager
    def _tx(self, *, bump: bool = True) -> Generator[sqlite3.Connection]:
        """写事务：成功提交时 commitCounter 加一（同一提交里），失败整体回滚。"""
        try:
            self._conn.execute("BEGIN IMMEDIATE")
        except sqlite3.Error as error:
            raise _storage_error(error) from error
        try:
            yield self._conn
            if bump:
                self._conn.execute(
                    "UPDATE hub_meta SET value=CAST(value AS INTEGER)+1 WHERE key='commitCounter'")
                self.counter = int(self._conn.execute(
                    "SELECT value FROM hub_meta WHERE key='commitCounter'").fetchone()[0])
            self._conn.execute("COMMIT")
        except BaseException as error:
            self._conn.execute("ROLLBACK")
            if isinstance(error, sqlite3.Error):
                raise _storage_error(error) from error
            raise

    @contextmanager
    def _read(self) -> Generator[sqlite3.Connection]:
        """读快照：数据与 commitCounter 来自同一快照，不递增计数。"""
        try:
            self._conn.execute("BEGIN")
            self.counter = int(self._conn.execute(
                "SELECT value FROM hub_meta WHERE key='commitCounter'").fetchone()[0])
        except sqlite3.Error as error:
            raise _storage_error(error) from error
        try:
            yield self._conn
        except sqlite3.Error as error:
            raise _storage_error(error) from error
        finally:
            self._conn.execute("COMMIT")

    def read_counter(self) -> int:
        """读当前 commitCounter（只读快照，不递增）。"""
        with self._read():
            return self.counter

    def meta(self, key: str) -> str | None:
        row = self._conn.execute("SELECT value FROM hub_meta WHERE key=?", (key,)).fetchone()
        return None if row is None else str(row[0])

    def hub_id(self) -> str:
        value = self.meta("hubId")
        if value is None:
            raise CodecError("hub_unavailable", "meta")
        return value

    @staticmethod
    def _set_meta(conn: sqlite3.Connection, key: str, value: str) -> None:
        conn.execute("INSERT INTO hub_meta(key,value) VALUES (?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                     (key, value))

    # ---- 设备管理（只给 hub 运维用户） ----

    def add_device(self, *, name: str, fingerprint: str, device_id: str | None = None,
                   display_name: str | None = None) -> str:
        """登记设备：slug 与指纹各自唯一；显式 device_id 只用于 hub 重建且本机账本完整的场景。"""
        if not is_slug(name):
            raise ValueError("device_name_invalid")
        if device_id is not None and not is_hex32(device_id):
            raise ValueError("device_id_invalid")
        chosen = device_id or new_id()
        with self._tx() as conn:
            for column, value, code in (("name", name, "device_name_taken"),
                                        ("public_key_fingerprint", fingerprint, "public_key_taken"),
                                        ("device_id", chosen, "device_id_taken")):
                if conn.execute(f"SELECT 1 FROM hub_devices WHERE {column}=?", (value,)).fetchone() is not None:
                    raise ValueError(code)
            conn.execute("INSERT INTO hub_devices(device_id,name,display_name,public_key_fingerprint,status)"
                         " VALUES (?,?,?,?, 'active')", (chosen, name, display_name or name, fingerprint))
            conn.execute("INSERT INTO hub_cursors(device_id) VALUES (?)", (chosen,))
        return chosen

    def device(self, ref: str) -> dict[str, Any] | None:
        """按 slug 或完整 deviceId 找设备。"""
        row = self._conn.execute("SELECT * FROM hub_devices WHERE name=? OR device_id=?", (ref, ref)).fetchone()
        return None if row is None else dict(row)

    def remove_device(self, ref: str, *, now: int) -> str:
        """撤销设备：原子 revoked 并递增连接 generation（旧连接一秒轮询内停止）；发往它的待转交信封标 revoked。"""
        with self._tx() as conn:
            row = conn.execute("SELECT device_id FROM hub_devices WHERE name=? OR device_id=?", (ref, ref)).fetchone()
            if row is None:
                raise ValueError("device_unregistered")
            device_id = str(row[0])
            conn.execute("UPDATE hub_devices SET status='revoked', connection_generation=connection_generation+1,"
                         " connection_id=NULL WHERE device_id=?", (device_id,))
            pending = conn.execute("SELECT msg_id,source_device FROM hub_messages WHERE target_device=?"
                                   " AND outcome='queued'", (device_id,)).fetchall()
            for msg_id, source in pending:
                conn.execute("UPDATE hub_messages SET outcome='revoked' WHERE msg_id=?", (msg_id,))
                self._receipt(conn, source, msg_id, "revoked", now)
            conn.execute("DELETE FROM hub_uploads WHERE source_device=?", (device_id,))
        return device_id

    # ---- 连接与 fence ----

    def begin_connection(self, device_id: str, *, ledger_instance_id: str, now: int) -> tuple[str, int]:
        """握手通过后取得新 fence：首次固定 ledgerInstanceId，此后不符拒绝且不动健康连接（§88.1/§88.2）。"""
        with self._tx() as conn:
            row = conn.execute("SELECT status,ledger_instance_id FROM hub_devices WHERE device_id=?",
                               (device_id,)).fetchone()
            if row is None:
                raise CodecError("device_unregistered")
            if row["status"] != "active":
                raise CodecError("device_revoked")
            pinned = row["ledger_instance_id"]
            if pinned is not None and pinned != ledger_instance_id:
                raise CodecError("ledger_instance_mismatch")
            connection_id = new_id()
            conn.execute("UPDATE hub_devices SET ledger_instance_id=?, connection_generation=connection_generation+1,"
                         " connection_id=?, last_seen=? WHERE device_id=?",
                         (ledger_instance_id, connection_id, now, device_id))
            # 新 fence 后清同设备旧 generation 的未完成上传，避免异常断线累积临时额度
            conn.execute("DELETE FROM hub_uploads WHERE source_device=? AND connection_id<>?", (device_id, connection_id))
            generation = int(conn.execute("SELECT connection_generation FROM hub_devices WHERE device_id=?",
                                          (device_id,)).fetchone()[0])
        return connection_id, generation

    @staticmethod
    def _fence(conn: sqlite3.Connection, device_id: str, connection_id: str) -> sqlite3.Row:
        row = conn.execute("SELECT * FROM hub_devices WHERE device_id=?", (device_id,)).fetchone()
        if row is None:
            raise CodecError("device_unregistered")
        if row["status"] != "active":
            raise CodecError("device_revoked")
        if row["connection_id"] != connection_id:
            raise CodecError("connection_superseded")
        return row

    def check_fence(self, device_id: str, connection_id: str) -> None:
        with self._read() as conn:
            self._fence(conn, device_id, connection_id)

    def heartbeat(self, device_id: str, connection_id: str, *, now: int) -> dict[str, Any]:
        with self._tx() as conn:
            self._fence(conn, device_id, connection_id)
            conn.execute("UPDATE hub_devices SET last_seen=? WHERE device_id=?", (now, device_id))
            directory = conn.execute("SELECT revision,snapshot_json FROM hub_directory WHERE device_id=?",
                                     (device_id,)).fetchone()
        return {"serverTime": now,
                "directoryRevision": int(directory[0]) if directory else None,
                "directoryDigest": self._snapshot_digest(directory[1]) if directory else None}

    def drop_connection_uploads(self, device_id: str, connection_id: str) -> None:
        """断线清本连接未完成的上传（不改 fence）。"""
        with self._tx() as conn:
            conn.execute("DELETE FROM hub_uploads WHERE source_device=? AND connection_id=?", (device_id, connection_id))

    # ---- 计费 ----

    def _usage(self, conn: sqlite3.Connection) -> int:
        """§88.11 保守逻辑占用：完整 blob + 上传预留 + 保留信封/目录字节 + 每行 512 B 元数据。"""
        blobs = conn.execute("SELECT COALESCE(SUM(size),0) FROM hub_blobs").fetchone()[0]
        uploads = conn.execute("SELECT COALESCE(SUM(size),0) FROM hub_uploads").fetchone()[0]
        envelopes = conn.execute(
            "SELECT COALESCE(SUM(payload_bytes),0) FROM hub_messages WHERE envelope_json IS NOT NULL").fetchone()[0]
        directory = conn.execute("SELECT COALESCE(SUM(LENGTH(snapshot_json)),0) FROM hub_directory").fetchone()[0]
        rows = sum(int(conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]) for table in (
            "hub_messages", "hub_receipts", "hub_blob_refs", "hub_devices", "hub_directory", "hub_uploads"))
        return int(blobs) + int(uploads) + int(envelopes) + int(directory) + rows * ROW_OVERHEAD_BYTES

    def _budget(self, conn: sqlite3.Connection) -> int:
        row = conn.execute("SELECT value FROM hub_meta WHERE key='storageBudgetBytes'").fetchone()
        return int(row[0]) if row is not None else DEFAULT_BUDGET_BYTES

    def _reserve(self, conn: sqlite3.Connection, extra: int) -> None:
        """写前核预算与物理余量；不足报 hub_storage_full，绝不假 L1。"""
        try:
            free = self._free_bytes(self.path.parent)
        except OSError:
            free = 0
        if free < MIN_FREE_BYTES or self._usage(conn) + extra > self._budget(conn):
            raise CodecError("hub_storage_full")

    # ---- 收据 ----

    @staticmethod
    def _receipt(conn: sqlite3.Connection, source: str, msg_id: str, state: str, now: int,
                 reason: str | None = None) -> None:
        conn.execute("INSERT OR IGNORE INTO hub_receipts(source_device,msg_id,state,at,reason) VALUES (?,?,?,?,?)",
                     (source, msg_id, state, now, reason))

    # ---- mailbox ----

    def submit(self, device_id: str, connection_id: str, envelope: Mapping[str, Any], *,
               now: int, payload_hash_hint: str | None = None) -> dict[str, Any]:
        """接纳一个信封（L1）：信封、blob 引用与 accepted 收据同一事务；同 (source, operationId) 返回原收据。"""
        check_envelope(envelope)
        digest = payload_hash(envelope)
        if payload_hash_hint is not None and payload_hash_hint != digest:
            raise CodecError("frame_invalid", "payload_hash")
        created, expires = int(envelope["createdAt"]), int(envelope["expiresAt"])
        if created > now + MAX_CLOCK_SKEW_MS or expires - created > TRANSFER_TTL_MS:
            raise CodecError("frame_invalid", "time")
        with self._tx() as conn:
            source = self._fence(conn, device_id, connection_id)
            prior = conn.execute("SELECT * FROM hub_messages WHERE source_device=? AND operation_id=?",
                                 (device_id, envelope["operationId"])).fetchone()
            if prior is not None:
                if prior["payload_hash"] != digest or prior["msg_id"] != envelope["msg_id"]:
                    raise CodecError("idempotency_conflict")
                # 同 ID 同 hash：只回原收据，不延 TTL
                return {"msgId": prior["msg_id"], "operationId": prior["operation_id"],
                        "acceptedAt": prior["accepted_at"], "expiresAt": prior["expires_at"], "duplicate": True}
            if conn.execute("SELECT 1 FROM hub_messages WHERE msg_id=?", (envelope["msg_id"],)).fetchone() is not None:
                raise CodecError("idempotency_conflict")
            if expires <= now:
                raise CodecError("message_expired")
            target_id = envelope["targetDeviceId"]
            target = conn.execute("SELECT status,next_recipient_seq FROM hub_devices WHERE device_id=?",
                                  (target_id,)).fetchone()
            if target is None or target["status"] != "active" or target_id == device_id:
                raise CodecError("destination_unknown")
            refs: list[tuple[int, str]] = []
            blob_total = 0
            for index, ref in enumerate(envelope.get("refs") or []):
                if ref.get("transfer") != "blob":
                    continue  # reference 声明本来就无内容，不参与 blob 门
                row = conn.execute("SELECT size FROM hub_blobs WHERE sha256=?", (ref["sha256"],)).fetchone()
                if row is None or int(row[0]) != int(ref["size"]):
                    raise CodecError("attachment_missing")
                blob_total += int(row[0])
                refs.append((index, str(ref["sha256"])))
            if blob_total > MAX_MESSAGE_BLOB_BYTES:
                raise CodecError("attachment_too_large")
            stamped = dict(envelope)
            seq = int(target["next_recipient_seq"])
            effective_expiry = min(expires, now + TRANSFER_TTL_MS)
            stamped.update({"sourceDeviceId": device_id, "sourceDeviceName": source["name"], "receivedAt": now,
                            "acceptedAt": now, "recipientSeq": seq, "payloadHash": digest,
                            "connectionGeneration": int(source["connection_generation"])})
            text = canonical_bytes(stamped).decode("utf-8")
            self._reserve(conn, len(text.encode("utf-8")) + ROW_OVERHEAD_BYTES * (2 + len(refs)))
            conn.execute(
                "INSERT INTO hub_messages(msg_id,source_device,operation_id,target_device,recipient_seq,payload_hash,"
                "envelope_json,payload_bytes,accepted_at,expires_at,outcome) VALUES (?,?,?,?,?,?,?,?,?,?,'queued')",
                (envelope["msg_id"], device_id, envelope["operationId"], target_id, seq, digest, text,
                 len(text.encode("utf-8")), now, effective_expiry),
            )
            conn.execute("UPDATE hub_devices SET next_recipient_seq=? WHERE device_id=?", (seq + 1, target_id))
            for index, sha in refs:
                conn.execute("INSERT INTO hub_blob_refs(msg_id,ref_index,sha256) VALUES (?,?,?)",
                             (envelope["msg_id"], index, sha))
            self._receipt(conn, device_id, envelope["msg_id"], "accepted", now)
        return {"msgId": envelope["msg_id"], "operationId": envelope["operationId"], "acceptedAt": now,
                "expiresAt": effective_expiry, "duplicate": False}

    def fetch(self, device_id: str, connection_id: str, *, after: int, skip: frozenset[str] = frozenset()
              ) -> tuple[list[dict[str, Any]], dict[str, Any]]:
        """取收件：先旧 unacked 再新 seq（FIFO），每批 ≤16 项/1 MiB；skip 是本连接 30 秒内已推过的项。

        fetch_end 带 scannedThrough、本批范围内过期空洞的真实 source 集合，以及游标早于保留底线时的 gap。
        """
        if not isinstance(after, int) or isinstance(after, bool) or after < 0:
            raise CodecError("frame_invalid", "after")
        with self._read() as conn:
            device = self._fence(conn, device_id, connection_id)
            rows = conn.execute(
                "SELECT msg_id,recipient_seq,source_device,payload_hash,envelope_json FROM hub_messages"
                " WHERE target_device=? AND outcome='queued' ORDER BY recipient_seq", (device_id,)).fetchall()
            items: list[dict[str, Any]] = []
            size = 0
            full = False
            for row in rows:
                if row["msg_id"] in skip:
                    continue
                text = row["envelope_json"]
                if items and (len(items) >= FETCH_MAX_ITEMS or size + len(text) > FETCH_MAX_BYTES):
                    full = True
                    break
                items.append({"msgId": row["msg_id"], "recipientSeq": row["recipient_seq"],
                              "sourceDeviceId": row["source_device"], "payloadHash": row["payload_hash"],
                              "envelope": loads_strict(text.encode("utf-8"))})
                size += len(text)
            newest = int(device["next_recipient_seq"]) - 1
            scanned = int(items[-1]["recipientSeq"]) if full else newest
            scanned = max(scanned, after) if not full else scanned
            expired = sorted({str(row[0]) for row in conn.execute(
                "SELECT DISTINCT source_device FROM hub_messages WHERE target_device=? AND outcome='expired'"
                " AND recipient_seq>? AND recipient_seq<=?", (device_id, after, scanned)).fetchall()})
            floor_raw = conn.execute("SELECT value FROM hub_meta WHERE key=?", (f"seqFloor:{device_id}",)).fetchone()
            floor = int(floor_raw[0]) if floor_raw is not None else 0
        return items, {"scannedThrough": scanned, "expiredSources": expired, "gap": after < floor, "more": full}

    def _own_message(self, conn: sqlite3.Connection, device_id: str, msg_id: object,
                     digest: object) -> sqlite3.Row:
        if not is_hex32(msg_id) or not is_hex64(digest):
            raise CodecError("frame_invalid", "msg")
        row = conn.execute("SELECT * FROM hub_messages WHERE msg_id=?", (msg_id,)).fetchone()
        if row is None or row["target_device"] != device_id:
            raise CodecError("identity_mismatch")
        if row["payload_hash"] != digest:
            raise CodecError("idempotency_conflict")
        return row

    def ack(self, device_id: str, connection_id: str, msg_id: object, digest: object, *, now: int) -> None:
        """L2：B 已完整持久化信封与全部附件。重复 ACK 幂等；过期/拒绝/撤销后不能改回。"""
        with self._tx() as conn:
            self._fence(conn, device_id, connection_id)
            row = self._own_message(conn, device_id, msg_id, digest)
            if row["outcome"] == "l2":
                return
            if row["outcome"] == "expired":
                raise CodecError("message_expired")
            if row["outcome"] != "queued":
                raise CodecError("idempotency_conflict")
            conn.execute("UPDATE hub_messages SET outcome='l2', l2_at=? WHERE msg_id=?", (now, msg_id))
            self._receipt(conn, row["source_device"], row["msg_id"], "l2", now)
            conn.execute("UPDATE hub_cursors SET scan_through=MAX(scan_through,?) WHERE device_id=?",
                         (row["recipient_seq"], device_id))

    def reject(self, device_id: str, connection_id: str, msg_id: object, digest: object, *, reason: object,
               now: int) -> str:
        """运输拒绝（不是 L2）：只接受指定收件设备、尚未 L2 的闭集原因；重复终结返回原原因。"""
        if reason not in REJECT_REASONS:
            raise CodecError("frame_invalid", "reason")
        with self._tx() as conn:
            self._fence(conn, device_id, connection_id)
            row = self._own_message(conn, device_id, msg_id, digest)
            if row["outcome"] == "rejected":
                prior = conn.execute("SELECT reason FROM hub_receipts WHERE msg_id=? AND state='rejected'",
                                     (msg_id,)).fetchone()
                return str(prior[0]) if prior and prior[0] else str(reason)
            if row["outcome"] == "expired":
                raise CodecError("message_expired")
            if row["outcome"] != "queued":
                raise CodecError("idempotency_conflict")  # 已 L2/撤销：拒绝不能抹掉已交出的事实
            conn.execute("UPDATE hub_messages SET outcome='rejected' WHERE msg_id=?", (msg_id,))
            self._receipt(conn, row["source_device"], row["msg_id"], "rejected", now, str(reason))
        return str(reason)

    def receipts(self, device_id: str, connection_id: str, *, after: int | None = None,
                 msg_ids: list[str] | None = None, source: object = None, from_floor: bool = False) -> dict[str, Any]:
        """收据只查认证设备作为 source 的；按 msg_id 查询时别人的消息与不存在同样回 not_found。

        from_floor：cursor_gap 后由客户端显式要求从保留底线重新开始（先按 msg_id 查完未结项再用）。
        """
        if source is not None and source != device_id:
            raise CodecError("identity_mismatch")
        with self._read() as conn:
            self._fence(conn, device_id, connection_id)
            if msg_ids is not None:
                if len(msg_ids) > RECEIPT_PAGE or not all(is_hex32(item) for item in msg_ids):
                    raise CodecError("frame_invalid", "msg_ids")
                found: dict[str, list[dict[str, Any]]] = {item: [] for item in msg_ids}
                marks = ",".join("?" for _ in msg_ids)
                for row in conn.execute(
                        f"SELECT seq,msg_id,state,at,reason FROM hub_receipts WHERE source_device=? AND msg_id IN"
                        f" ({marks}) ORDER BY seq", (device_id, *msg_ids)).fetchall():
                    found[row["msg_id"]].append(self._receipt_dict(row))
                return {"byMessage": [{"msgId": key, "receipts": value, "found": bool(value)}
                                      for key, value in found.items()]}
            cursor = after or 0
            if not isinstance(cursor, int) or cursor < 0:
                raise CodecError("frame_invalid", "after")
            floor_raw = conn.execute("SELECT value FROM hub_meta WHERE key=?",
                                     (f"receiptFloor:{device_id}",)).fetchone()
            floor = int(floor_raw[0]) if floor_raw is not None else 0
            if from_floor:
                cursor = max(cursor, floor)
            elif cursor < floor:
                raise CodecError("cursor_gap")
            rows = conn.execute("SELECT seq,msg_id,state,at,reason FROM hub_receipts WHERE source_device=? AND seq>?"
                                " ORDER BY seq LIMIT ?", (device_id, cursor, RECEIPT_PAGE)).fetchall()
            items = [self._receipt_dict(row) for row in rows]
        return {"items": items, "next": items[-1]["seq"] if items else cursor, "more": len(items) == RECEIPT_PAGE}

    @staticmethod
    def _receipt_dict(row: sqlite3.Row) -> dict[str, Any]:
        item: dict[str, Any] = {"seq": row["seq"], "msgId": row["msg_id"], "state": row["state"], "at": row["at"]}
        if row["reason"]:
            item["reason"] = row["reason"]
        return item

    def receipt_seen(self, device_id: str, connection_id: str, through: object) -> int:
        if not isinstance(through, int) or isinstance(through, bool) or through < 0:
            raise CodecError("frame_invalid", "through")
        with self._tx() as conn:
            self._fence(conn, device_id, connection_id)
            conn.execute("UPDATE hub_cursors SET receipt_seen=MAX(receipt_seen,?) WHERE device_id=?",
                         (through, device_id))
            return int(conn.execute("SELECT receipt_seen FROM hub_cursors WHERE device_id=?",
                                    (device_id,)).fetchone()[0])

    # ---- 目录 ----

    @staticmethod
    def _snapshot_digest(text: str) -> str:
        data = loads_strict(text.encode("utf-8"))
        data.pop("receivedAt", None)
        return sha256_hex(canonical_bytes(data))

    def directory_put(self, device_id: str, connection_id: str, *, revision: object, snapshot: object,
                      now: int) -> dict[str, Any]:
        """整份目录单帧原子替换；hub 覆盖设备身份；超预算的快照必须自己标 complete=false。"""
        if not isinstance(revision, int) or isinstance(revision, bool) or revision < 1:
            raise CodecError("frame_invalid", "revision")
        if not isinstance(snapshot, dict):
            raise CodecError("frame_invalid", "snapshot")
        data: dict[str, Any] = dict(snapshot)  # pyright: ignore[reportUnknownArgumentType]
        endpoints = data.get("endpoints")
        if not isinstance(endpoints, list) or len(endpoints) > DIRECTORY_MAX_ENDPOINTS:  # pyright: ignore[reportUnknownArgumentType]
            raise CodecError("frame_invalid", "endpoints")
        for item in endpoints:  # pyright: ignore[reportUnknownVariableType]
            if not isinstance(item, dict) or len(canonical_bytes(item)) > DIRECTORY_MAX_ENDPOINT_BYTES:  # pyright: ignore[reportUnknownArgumentType]
                raise CodecError("frame_invalid", "endpoint")
        if not isinstance(data.get("complete"), bool):
            raise CodecError("frame_invalid", "complete")
        with self._tx() as conn:
            device = self._fence(conn, device_id, connection_id)
            data.update({"deviceId": device_id, "deviceName": device["name"], "receivedAt": now})
            text = canonical_bytes(data).decode("utf-8")
            if len(text.encode("utf-8")) > DIRECTORY_MAX_BYTES:
                raise CodecError("frame_invalid", "snapshot_too_large")
            prior = conn.execute("SELECT revision FROM hub_directory WHERE device_id=?", (device_id,)).fetchone()
            if prior is not None and revision < int(prior[0]):
                raise CodecError("idempotency_conflict")
            conn.execute("INSERT INTO hub_directory(device_id,revision,snapshot_json,received_at) VALUES (?,?,?,?)"
                         " ON CONFLICT(device_id) DO UPDATE SET revision=excluded.revision,"
                         " snapshot_json=excluded.snapshot_json, received_at=excluded.received_at",
                         (device_id, revision, text, now))
            conn.execute("UPDATE hub_devices SET last_seen=? WHERE device_id=?", (now, device_id))
        return {"revision": revision, "digest": self._snapshot_digest(text)}

    def directory_get(self, device_id: str, connection_id: str, *, devices: list[str] | None,
                      now: int) -> list[dict[str, Any]]:
        """每设备一帧；不分页拼 snapshot。在线=90 秒内有认证活动且有当前连接。"""
        with self._read() as conn:
            self._fence(conn, device_id, connection_id)
            rows = conn.execute("SELECT d.device_id,d.name,d.status,d.last_seen,d.connection_id,y.revision,"
                                "y.snapshot_json,y.received_at FROM hub_devices d LEFT JOIN hub_directory y"
                                " ON y.device_id=d.device_id ORDER BY d.name").fetchall()
        result: list[dict[str, Any]] = []
        for row in rows:
            if devices is not None and row["device_id"] not in devices:
                continue
            online = (row["status"] == "active" and row["connection_id"] is not None and row["last_seen"] is not None
                      and now - int(row["last_seen"]) <= 90_000)
            result.append({
                "deviceId": row["device_id"], "deviceName": row["name"], "status": row["status"], "online": online,
                "lastSeen": row["last_seen"], "revision": row["revision"], "receivedAt": row["received_at"],
                "snapshot": loads_strict(row["snapshot_json"].encode("utf-8")) if row["snapshot_json"] else None,
            })
        return result

    # ---- BLOB CAS ----

    def blob_begin(self, device_id: str, connection_id: str, *, sha256: object, size: object,
                   now: int) -> dict[str, Any]:
        """已完整存在则 exists；否则为本连接分配 uploadId 并按声明 size 预留（每连接同时一个上传）。"""
        if not is_hex64(sha256):
            raise CodecError("frame_invalid", "sha256")
        if not isinstance(size, int) or isinstance(size, bool) or size < 0:
            raise CodecError("frame_invalid", "size")
        if size > MAX_BLOB_BYTES:
            raise CodecError("attachment_too_large")
        with self._tx() as conn:
            self._fence(conn, device_id, connection_id)
            existing = conn.execute("SELECT size FROM hub_blobs WHERE sha256=?", (sha256,)).fetchone()
            if existing is not None:
                if int(existing[0]) != size:
                    raise CodecError("attachment_hash_mismatch")
                return {"exists": True}
            conn.execute("DELETE FROM hub_uploads WHERE source_device=? AND connection_id=?", (device_id, connection_id))
            self._reserve(conn, size + ROW_OVERHEAD_BYTES)
            upload_id = new_id()
            conn.execute("INSERT INTO hub_uploads(upload_id,source_device,connection_id,sha256,size,received_bytes,"
                         "started_at,data) VALUES (?,?,?,?,?,0,?,zeroblob(?))",
                         (upload_id, device_id, connection_id, sha256, size, now, size))
        return {"exists": False, "uploadId": upload_id}

    def _own_upload(self, conn: sqlite3.Connection, device_id: str, connection_id: str,
                    upload_id: object) -> sqlite3.Row:
        if not is_hex32(upload_id):
            raise CodecError("frame_invalid", "upload")
        row = conn.execute("SELECT rowid,* FROM hub_uploads WHERE upload_id=?", (upload_id,)).fetchone()
        if row is None or row["source_device"] != device_id or row["connection_id"] != connection_id:
            raise CodecError("attachment_offset_invalid")  # 重连不继续旧 uploadId
        return row

    def blob_chunk(self, device_id: str, connection_id: str, *, upload_id: object, offset: object,
                   data: object) -> int:
        """只接受下一顺序 offset，每块原始数据 ≤256 KiB；返回 nextOffset。"""
        raw = _b64decode(data)
        if len(raw) > BLOB_CHUNK_BYTES or not raw:
            raise CodecError("frame_invalid", "chunk")
        with self._tx() as conn:
            self._fence(conn, device_id, connection_id)
            row = self._own_upload(conn, device_id, connection_id, upload_id)
            if offset != row["received_bytes"] or int(row["received_bytes"]) + len(raw) > int(row["size"]):
                raise CodecError("attachment_offset_invalid")
            with conn.blobopen("hub_uploads", "data", int(row["rowid"])) as blob:
                blob.seek(int(row["received_bytes"]))
                blob.write(raw)
            next_offset = int(row["received_bytes"]) + len(raw)
            conn.execute("UPDATE hub_uploads SET received_bytes=? WHERE upload_id=?", (next_offset, upload_id))
        return next_offset

    def blob_finish(self, device_id: str, connection_id: str, *, upload_id: object, now: int) -> dict[str, Any]:
        """复核总长与服务端重算的 SHA，原子转成完整 CAS 对象；不符删除残块，不把它当 CAS。"""
        mismatch = False
        with self._tx() as conn:
            self._fence(conn, device_id, connection_id)
            row = self._own_upload(conn, device_id, connection_id, upload_id)
            if int(row["received_bytes"]) != int(row["size"]):
                raise CodecError("attachment_offset_invalid")
            hasher = hashlib.sha256()
            with conn.blobopen("hub_uploads", "data", int(row["rowid"]), readonly=True) as blob:
                while True:
                    piece = blob.read(BLOB_CHUNK_BYTES)
                    if not piece:
                        break
                    hasher.update(piece)
            if hasher.hexdigest() != row["sha256"]:
                mismatch = True
            elif conn.execute("SELECT 1 FROM hub_blobs WHERE sha256=?", (row["sha256"],)).fetchone() is None:
                conn.execute("INSERT INTO hub_blobs(sha256,size,data,verified_at) SELECT sha256,size,data,?"
                             " FROM hub_uploads WHERE upload_id=?", (now, upload_id))
            conn.execute("DELETE FROM hub_uploads WHERE upload_id=?", (upload_id,))
        if mismatch:
            raise CodecError("attachment_hash_mismatch")
        return {"sha256": row["sha256"], "size": int(row["size"])}

    def blob_get(self, device_id: str, connection_id: str, *, msg_id: object, ref_index: object,
                 offset: object) -> dict[str, Any]:
        """按已授权的收件 msg/ref 索引读 ≤256 KiB；不接受任意 hash 或路径。"""
        if not is_hex32(msg_id) or not isinstance(ref_index, int) or not isinstance(offset, int) or offset < 0:
            raise CodecError("frame_invalid", "blob_get")
        with self._read() as conn:
            self._fence(conn, device_id, connection_id)
            message = conn.execute("SELECT target_device,outcome FROM hub_messages WHERE msg_id=?", (msg_id,)).fetchone()
            if message is None or message["target_device"] != device_id:
                raise CodecError("identity_mismatch")
            if message["outcome"] == "expired":
                raise CodecError("message_expired")
            if message["outcome"] not in ("queued", "l2"):
                raise CodecError("attachment_missing")
            ref = conn.execute("SELECT b.rowid,b.size FROM hub_blob_refs r JOIN hub_blobs b ON b.sha256=r.sha256"
                               " WHERE r.msg_id=? AND r.ref_index=?", (msg_id, ref_index)).fetchone()
            if ref is None:
                raise CodecError("attachment_missing")
            size = int(ref["size"])
            if offset > size:
                raise CodecError("attachment_offset_invalid")
            with conn.blobopen("hub_blobs", "data", int(ref["rowid"]), readonly=True) as blob:
                blob.seek(offset)
                piece = blob.read(min(BLOB_CHUNK_BYTES, size - offset))
        return {"msgId": msg_id, "refIndex": ref_index, "offset": offset, "size": size,
                "data": base64.b64encode(piece).decode("ascii"), "eof": offset + len(piece) >= size}

    # ---- GC 与状态 ----

    def gc(self, *, now: int, owner: str) -> dict[str, int] | None:
        """竞争维护租约后小批回收；返回各类计数，租约被他人持有时返回 None。不做任务状态机。"""
        counts = {"expired": 0, "contentCleared": 0, "messagesDeleted": 0, "receiptsDeleted": 0,
                  "uploadsDeleted": 0, "blobsDeleted": 0}
        with self._tx() as conn:
            lease = conn.execute("SELECT value FROM hub_meta WHERE key='gcLease'").fetchone()
            if lease is not None:
                holder, _, until = str(lease[0]).partition(":")
                if holder != owner and until.isdigit() and int(until) > now:
                    return None
            self._set_meta(conn, "gcLease", f"{owner}:{now + GC_LEASE_MS}")
            # 1. 未 L2 到期：先标 expired + 收据，后续再删内容
            for msg_id, source in conn.execute(
                    "SELECT msg_id,source_device FROM hub_messages WHERE outcome='queued' AND expires_at<=?"
                    " ORDER BY expires_at LIMIT ?", (now, GC_BATCH)).fetchall():
                conn.execute("UPDATE hub_messages SET outcome='expired' WHERE msg_id=?", (msg_id,))
                self._receipt(conn, source, msg_id, "expired", now)
                counts["expired"] += 1
            # 2. 终结 30 天后删信封正文与 blob 引用，保留去重行
            terminal_at = ("COALESCE(l2_at,(SELECT MAX(at) FROM hub_receipts r WHERE r.msg_id=hub_messages.msg_id"
                           " AND r.state IN ('rejected','expired','revoked')))")
            for (msg_id,) in conn.execute(
                    f"SELECT msg_id FROM hub_messages WHERE outcome<>'queued' AND envelope_json IS NOT NULL"
                    f" AND {terminal_at}<=? LIMIT ?", (now - CONTENT_RETENTION_MS, GC_BATCH)).fetchall():
                conn.execute("UPDATE hub_messages SET envelope_json=NULL WHERE msg_id=?", (msg_id,))
                conn.execute("DELETE FROM hub_blob_refs WHERE msg_id=?", (msg_id,))
                counts["contentCleared"] += 1
            # 3. 去重行与收据 60 天后删除，记录保留底线（之后的游标请求报 gap/cursor_gap）
            for msg_id, target, seq in conn.execute(
                    f"SELECT msg_id,target_device,recipient_seq FROM hub_messages WHERE outcome<>'queued'"
                    f" AND envelope_json IS NULL AND {terminal_at}<=? LIMIT ?",
                    (now - RECEIPT_RETENTION_MS, GC_BATCH)).fetchall():
                conn.execute("DELETE FROM hub_messages WHERE msg_id=?", (msg_id,))
                self._raise_floor(conn, f"seqFloor:{target}", int(seq))
                counts["messagesDeleted"] += 1
            for seq, source in conn.execute("SELECT seq,source_device FROM hub_receipts WHERE at<=? ORDER BY seq"
                                            " LIMIT ?", (now - RECEIPT_RETENTION_MS, GC_BATCH)).fetchall():
                conn.execute("DELETE FROM hub_receipts WHERE seq=?", (seq,))
                self._raise_floor(conn, f"receiptFloor:{source}", int(seq))
                counts["receiptsDeleted"] += 1
            # 4. 异常遗留上传 24 小时；无引用且已满 24 小时的完整 CAS
            counts["uploadsDeleted"] = conn.execute("DELETE FROM hub_uploads WHERE started_at<=?",
                                                    (now - ORPHAN_MS,)).rowcount
            counts["blobsDeleted"] = conn.execute(
                "DELETE FROM hub_blobs WHERE verified_at<=? AND sha256 NOT IN (SELECT sha256 FROM hub_blob_refs)"
                " AND sha256 NOT IN (SELECT sha256 FROM hub_uploads)", (now - ORPHAN_MS,)).rowcount
        return counts

    def _raise_floor(self, conn: sqlite3.Connection, key: str, value: int) -> None:
        row = conn.execute("SELECT value FROM hub_meta WHERE key=?", (key,)).fetchone()
        if row is None or int(row[0]) < value:
            self._set_meta(conn, key, str(value))

    def status(self, *, now: int) -> dict[str, Any]:
        """`hub status --json`：设备在线、积压、附件字节、TTL、GC 与存储原因；不含正文/附件名/路径/key。"""
        with self._read() as conn:
            devices = []
            for row in conn.execute("SELECT * FROM hub_devices ORDER BY name").fetchall():
                backlog = conn.execute("SELECT COUNT(*),MIN(accepted_at) FROM hub_messages WHERE target_device=?"
                                       " AND outcome='queued'", (row["device_id"],)).fetchone()
                devices.append({
                    "deviceId": row["device_id"], "name": row["name"], "status": row["status"],
                    "online": row["connection_id"] is not None and row["last_seen"] is not None
                              and now - int(row["last_seen"]) <= 90_000,
                    "lastSeen": row["last_seen"], "connectionGeneration": row["connection_generation"],
                    "ledgerPinned": row["ledger_instance_id"] is not None,
                    "backlog": int(backlog[0]), "oldestQueuedAgeMs": now - int(backlog[1]) if backlog[1] else None,
                })
            outcomes = {str(row[0]): int(row[1]) for row in conn.execute(
                "SELECT outcome,COUNT(*) FROM hub_messages GROUP BY outcome").fetchall()}
            blobs = conn.execute("SELECT COUNT(*),COALESCE(SUM(size),0) FROM hub_blobs").fetchone()
            uploads = conn.execute("SELECT COUNT(*),COALESCE(SUM(size),0) FROM hub_uploads").fetchone()
            usage, budget = self._usage(conn), self._budget(conn)
            lease = conn.execute("SELECT value FROM hub_meta WHERE key='gcLease'").fetchone()
            hub_id = conn.execute("SELECT value FROM hub_meta WHERE key='hubId'").fetchone()[0]
        try:
            free = self._free_bytes(self.path.parent)
        except OSError:
            free = 0
        reason = "hub_storage_full" if free < MIN_FREE_BYTES or usage >= budget else None
        db_bytes = sum(p.stat().st_size for p in self.path.parent.glob(HUB_DB_NAME + "*") if p.is_file())
        return {"hubId": hub_id, "commitCounter": self.counter, "devices": devices, "messages": outcomes,
                "blobs": {"count": int(blobs[0]), "bytes": int(blobs[1])},
                "uploads": {"count": int(uploads[0]), "bytes": int(uploads[1])},
                "usageBytes": usage, "budgetBytes": budget, "freeBytes": free, "dbBytes": db_bytes,
                "ttlMs": TRANSFER_TTL_MS, "gcLeaseHeld": lease is not None, "storageReason": reason}
