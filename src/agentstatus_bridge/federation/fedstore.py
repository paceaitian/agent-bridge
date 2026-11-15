"""联邦账本 `federation.sqlite3`（DESIGN §88.4）：独立 schema=1，与本机 `bridge.sqlite3` 不共事务、不 ATTACH。

只放存储原语与一致的读写；谁能写哪个字段由 authority/mirror/delivery 各自按单写者规则决定。
时间一律 UTC epoch 毫秒整数；`fedRevision` 由触发器在可见表变化时单调递增，供摘要判断新鲜度。
"""

from __future__ import annotations

from collections.abc import Iterator, Mapping
from contextlib import AbstractContextManager, ExitStack, contextmanager
from dataclasses import dataclass, field
import json
import re
from pathlib import Path
import sqlite3
import time
from typing import Any

from ..ids import new_id
from ..model import QUIET_NOTICE_KINDS
from ..paths import ensure_private_dir, state_dir
from ..platforms.factory import get_platform
from ..store import StoreError
from .codec import CodecError
from .refs import TargetRef, WireActor

FED_DB_NAME = "federation.sqlite3"
FED_SCHEMA_VERSION = 1
# 与本机账本同一口径：每个任务时间线最多保留 256 条事件；去重墓碑不随事件裁剪
MAX_EVENTS_PER_TASK = 256

_SCHEMA_V1: tuple[str, ...] = (
    "CREATE TABLE fed_meta(key TEXT PRIMARY KEY,value TEXT NOT NULL)",
    """CREATE TABLE fed_device_state(device_id TEXT PRIMARY KEY,name TEXT NOT NULL,
        directory_revision INTEGER NOT NULL,snapshot_json TEXT NOT NULL,last_seen INTEGER,state TEXT NOT NULL)""",
    """CREATE TABLE fed_bindings(endpoint_id TEXT PRIMARY KEY,provider TEXT NOT NULL,native_id TEXT NOT NULL,
        root_binding TEXT NOT NULL,revision INTEGER NOT NULL,local_ref_json TEXT NOT NULL,
        UNIQUE(provider,native_id,root_binding))""",
    """CREATE TABLE fed_tasks(authority_device TEXT NOT NULL,task_id TEXT NOT NULL,is_authority INTEGER NOT NULL,
        revision INTEGER NOT NULL,current_work_seq INTEGER,max_seq INTEGER NOT NULL,state_json TEXT NOT NULL,
        last_sync_at INTEGER NOT NULL,local_archived INTEGER NOT NULL DEFAULT 0,
        sync_required INTEGER NOT NULL DEFAULT 0,PRIMARY KEY(authority_device,task_id),CHECK(is_authority IN(0,1)))""",
    """CREATE TABLE fed_attempts(authority_device TEXT NOT NULL,task_id TEXT NOT NULL,seq INTEGER NOT NULL,
        msg_id TEXT NOT NULL UNIQUE,role TEXT NOT NULL,target_device TEXT NOT NULL,target_json TEXT NOT NULL,
        sender_json TEXT NOT NULL,sender_class TEXT NOT NULL,body TEXT NOT NULL,refs_json TEXT NOT NULL,
        options_json TEXT NOT NULL,authority_state_json TEXT NOT NULL,evidence_no INTEGER NOT NULL DEFAULT 0,
        delivery_json TEXT NOT NULL,effective_work_json TEXT NOT NULL,
        PRIMARY KEY(authority_device,task_id,seq),CHECK(seq BETWEEN 1 AND 64),
        FOREIGN KEY(authority_device,task_id) REFERENCES fed_tasks(authority_device,task_id))""",
    """CREATE TABLE fed_routes(task_id TEXT NOT NULL,authority_device TEXT NOT NULL,hub_id TEXT NOT NULL,
        local_role TEXT NOT NULL,local_endpoint_id TEXT NOT NULL,first_msg_id TEXT NOT NULL,
        PRIMARY KEY(task_id,authority_device,local_role,local_endpoint_id))""",
    """CREATE TABLE fed_operations(source_device TEXT NOT NULL,operation_id TEXT NOT NULL,msg_id TEXT NOT NULL UNIQUE,
        payload_hash TEXT NOT NULL,result_json TEXT NOT NULL,created_at INTEGER NOT NULL,
        PRIMARY KEY(source_device,operation_id))""",
    """CREATE TABLE fed_outbox(msg_id TEXT PRIMARY KEY,operation_id TEXT NOT NULL UNIQUE,target_device TEXT NOT NULL,
        envelope_json TEXT NOT NULL,payload_hash TEXT NOT NULL,state TEXT NOT NULL,expires_at INTEGER NOT NULL,
        next_try_at INTEGER NOT NULL,hub_receipt_json TEXT)""",
    """CREATE TABLE fed_inbox(msg_id TEXT PRIMARY KEY,source_device TEXT NOT NULL,operation_id TEXT NOT NULL,
        payload_hash TEXT NOT NULL,envelope_json TEXT,received_at INTEGER NOT NULL,apply_state TEXT NOT NULL,
        result_json TEXT NOT NULL,UNIQUE(source_device,operation_id))""",
    """CREATE TABLE fed_reports(authority_device TEXT NOT NULL,task_id TEXT NOT NULL,attempt_seq INTEGER NOT NULL,
        reporter_device TEXT NOT NULL,report_no INTEGER NOT NULL,operation_id TEXT NOT NULL,report_json TEXT NOT NULL,
        PRIMARY KEY(authority_device,task_id,attempt_seq,report_no),UNIQUE(reporter_device,operation_id))""",
    """CREATE TABLE fed_report_decisions(reporter_device TEXT NOT NULL,report_operation_id TEXT NOT NULL,
        authority_revision INTEGER NOT NULL,decision TEXT NOT NULL,reason TEXT,
        PRIMARY KEY(reporter_device,report_operation_id))""",
    """CREATE TABLE fed_native_sends(msg_id TEXT PRIMARY KEY,state TEXT NOT NULL,worker_generation TEXT,
        local_target_json TEXT,intent_at INTEGER,result_json TEXT NOT NULL)""",
    """CREATE TABLE fed_evidence(msg_id TEXT NOT NULL,evidence_no INTEGER NOT NULL,delivery_device TEXT NOT NULL,
        evidence_json TEXT NOT NULL,PRIMARY KEY(msg_id,evidence_no))""",
    """CREATE TABLE fed_attachments(msg_id TEXT NOT NULL,ref_index INTEGER NOT NULL,authority_device TEXT NOT NULL,
        task_id TEXT NOT NULL,report_operation_id TEXT,origin_device TEXT NOT NULL,original_path TEXT NOT NULL,
        resolved_path TEXT NOT NULL,original_name TEXT NOT NULL,transfer TEXT NOT NULL,reason TEXT,
        sha256 TEXT,size INTEGER NOT NULL,location TEXT,local_relpath TEXT,file_identity_json TEXT,
        state TEXT NOT NULL,verified_at INTEGER,last_ref_at INTEGER NOT NULL,retain_until INTEGER,
        PRIMARY KEY(msg_id,ref_index),CHECK(size>=0),
        CHECK((transfer='blob' AND size<=8388608 AND sha256 IS NOT NULL)
           OR (transfer='reference' AND sha256 IS NULL AND reason IS NOT NULL
               AND reason IN('single_file_limit','message_total_limit'))))""",
    """CREATE TABLE fed_events(id INTEGER PRIMARY KEY AUTOINCREMENT,authority_device TEXT NOT NULL,
        task_id TEXT NOT NULL,attempt_seq INTEGER,at INTEGER NOT NULL,kind TEXT NOT NULL,detail_json TEXT NOT NULL)""",
    "CREATE INDEX fed_outbox_ready ON fed_outbox(state,next_try_at)",
    "CREATE INDEX fed_inbox_ready ON fed_inbox(apply_state,received_at)",
    "CREATE INDEX fed_attachment_gc ON fed_attachments(state,retain_until)",
    "CREATE INDEX fed_route_lookup ON fed_routes(task_id)",
    "CREATE INDEX fed_native_state ON fed_native_sends(state)",
    "CREATE INDEX fed_events_by_task ON fed_events(authority_device,task_id,id)",
)
# 这些表的任一行变化都让 fedRevision 递增（摘要组合新鲜度用，§88.8）
_REVISION_TABLES = (
    "fed_tasks", "fed_attempts", "fed_native_sends", "fed_evidence", "fed_reports",
    "fed_report_decisions", "fed_attachments", "fed_events",
)
OUTBOX_STATES = frozenset({"ready", "submitting", "accepted", "received", "refused", "rejected", "expired", "revoked"})
INBOX_STATES = frozenset({"receiving", "ready", "applied", "rejected"})
NATIVE_STATES = frozenset({"prepared", "intent", "finished", "unknown", "suppressed"})
ATTACHMENT_STATES = frozenset(
    {"reference_only", "staged", "uploading", "hub_ready", "downloading", "ready", "failed", "expired"}
)
_PANE = re.compile(r"%[0-9]+")
META_KEYS = frozenset(
    {"hubId", "deviceId", "deviceName", "ledgerInstanceId", "fedRevision", "enabled", "relayGeneration",
     "inboxCursor", "receiptCursor", "directoryRevision", "directoryDigest", "ingressCatchup", "hubStateLost",
     "relayState", "relayLastSeen", "directoryLocalDigest", "budgetDeferredAt", "retentionCursor",
     "incomingWriteFailedAt", "relayAnchorWatch", "relayDistributionVersion", "relayPublishedAt"}
)
# relay 运行诊断三键（DESIGN §90.6）：只由 Windows relay 主线程整组发布；任一平台的 relay 启动时先清掉旧值
RELAY_DIAGNOSTIC_KEYS = ("relayAnchorWatch", "relayDistributionVersion", "relayPublishedAt")


def now_ms() -> int:
    """UTC epoch 毫秒。"""
    return int(time.time() * 1000)


def dump(value: object) -> str:
    """账本 JSON 列：紧凑、键排序、保留非 ASCII。"""
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def load_dict(raw: object) -> dict[str, Any]:
    """读 JSON 对象列；坏数据返回空字典（调用方按缺字段处理，不猜测）。"""
    if not isinstance(raw, str):
        return {}
    try:
        value = json.loads(raw)
    except ValueError:
        return {}
    return value if isinstance(value, dict) else {}  # pyright: ignore[reportUnknownVariableType]


def load_list(raw: object) -> list[Any]:
    """读 JSON 数组列。"""
    if not isinstance(raw, str):
        return []
    try:
        value = json.loads(raw)
    except ValueError:
        return []
    return value if isinstance(value, list) else []  # pyright: ignore[reportUnknownVariableType]


# 权威端本机账本里 note/fyi 的类别键（G4 审计 r1 P3-2 回滚加固）：旧代码的 build_checkpoint 只读 noticeKind，
# 所以 A 回滚到旧代码后写出的 checkpoint 定义与新代码逐字相同（都不带新类别），旧读方不拒收、新读方不报
# idempotency_conflict；_queue 写信封时再映射成 data.options.noticeKind，线上形状不变。
LOCAL_NOTICE_KIND = "localNoticeKind"


def notice_options(options: Mapping[str, Any]) -> dict[str, Any]:
    """按共用口径看的 options：本机键 localNoticeKind 映射回 noticeKind（容量判定与本机视图共用，§95.5.2）。"""
    view = dict(options)
    kind = view.pop(LOCAL_NOTICE_KIND, None)
    if isinstance(kind, str):
        view["noticeKind"] = kind
    return view

@dataclass(frozen=True)
class FedTask:
    """fed_tasks 一行：A 上是权威任务，B 上是镜像。"""

    authority_device: str
    task_id: str
    is_authority: bool
    revision: int
    current_work_seq: int | None
    max_seq: int
    state: dict[str, Any]
    last_sync_at: int
    local_archived: bool = False
    sync_required: bool = False

    @property
    def finished(self) -> bool:
        return self.state.get("acceptedAt") is not None or self.state.get("closedAt") is not None

    @property
    def is_fyi(self) -> bool:
        """一句话告知（DESIGN §95.5.7）：权威端本机 state 记 fyi=true；镜像只有 checkpoint，认 closeReason=fyi 且没有工作尝试。

        `ab close --reason` 是自由文本，普通任务也可能以 fyi 为关闭原因；它们一定有工作尝试（currentWorkSeq 非空）。
        """
        if self.state.get("fyi") is True:
            return True
        return self.state.get("closeReason") == "fyi" and self.current_work_seq is None

    @property
    def paused(self) -> bool:
        return self.state.get("control") == "paused"

    @property
    def title(self) -> str:
        value = self.state.get("title")
        return value if isinstance(value, str) else ""

    def origin(self) -> TargetRef | None:
        """发起方（A 上可能是本机端点）；坏数据视为没有。"""
        raw = self.state.get("origin")
        if raw is None:
            return None
        try:
            return TargetRef.from_dict(raw)
        except CodecError:
            return None

    def reviewer(self) -> TargetRef | None:
        raw = self.state.get("reviewer")
        if raw is None:
            return None
        try:
            return TargetRef.from_dict(raw)
        except CodecError:
            return None


@dataclass(frozen=True)
class FedAttempt:
    """fed_attempts 一行：A 分配的不可变定义加各写者的事实缓存（控制请求、投递证据、采纳后的工作状态分列）。"""

    authority_device: str
    task_id: str
    seq: int
    msg_id: str
    role: str
    target_device: str
    target: TargetRef
    sender: WireActor | None
    sender_class: str
    body: str
    refs: list[dict[str, Any]]
    options: dict[str, Any]
    authority_state: dict[str, Any]
    evidence_no: int
    delivery: dict[str, Any]
    effective_work: dict[str, Any] = field(default_factory=dict)

    @property
    def is_closure(self) -> bool:
        return self.role == "notice" and self.options.get("noticeKind") == "closure"

    @property
    def notice_kind(self) -> str | None:
        """notice 的类别：权威端本机记在 localNoticeKind（note/fyi），镜像与其他类别记在 noticeKind。"""
        value = self.options.get(LOCAL_NOTICE_KIND, self.options.get("noticeKind"))
        return value if isinstance(value, str) else None

    @property
    def is_note(self) -> bool:
        """任务内补充消息（DESIGN §95.5）：发给执行方的 notice，不是工作尝试。"""
        return self.role == "notice" and self.notice_kind == "note"

    @property
    def is_fyi(self) -> bool:
        """一句话告知的那条 notice（DESIGN §95.5.7）。"""
        return self.role == "notice" and self.notice_kind == "fyi"

    @property
    def delivers_after_finish(self) -> bool:
        """任务结束或暂停后仍投递：结束回执与告知（与本机 Attempt.delivers_after_finish 同口径）。"""
        return self.is_closure or self.is_fyi

    @property
    def cancel_requested(self) -> bool:
        return self.authority_state.get("cancelRequested") is True

    @property
    def superseded(self) -> bool:
        return self.authority_state.get("superseded") is True


def _task_from_row(row: sqlite3.Row) -> FedTask:
    return FedTask(
        authority_device=row["authority_device"],
        task_id=row["task_id"],
        is_authority=bool(row["is_authority"]),
        revision=int(row["revision"]),
        current_work_seq=row["current_work_seq"],
        max_seq=int(row["max_seq"]),
        state=load_dict(row["state_json"]),
        last_sync_at=int(row["last_sync_at"]),
        local_archived=bool(row["local_archived"]),
        sync_required=bool(row["sync_required"]),
    )


def _attempt_from_row(row: sqlite3.Row) -> FedAttempt:
    sender_raw = load_dict(row["sender_json"])
    try:
        target = TargetRef.from_dict(load_dict(row["target_json"]))
        sender = WireActor.from_dict(sender_raw) if sender_raw else None
    except CodecError as error:
        raise StoreError("corrupt_record") from error
    return FedAttempt(
        authority_device=row["authority_device"],
        task_id=row["task_id"],
        seq=int(row["seq"]),
        msg_id=row["msg_id"],
        role=row["role"],
        target_device=row["target_device"],
        target=target,
        sender=sender,
        sender_class=row["sender_class"],
        body=row["body"],
        refs=[item for item in load_list(row["refs_json"]) if isinstance(item, dict)],
        options=load_dict(row["options_json"]),
        authority_state=load_dict(row["authority_state_json"]),
        evidence_no=int(row["evidence_no"]),
        delivery=load_dict(row["delivery_json"]),
        effective_work=load_dict(row["effective_work_json"]),
    )


def _write_error(error: sqlite3.Error, fallback: str) -> str:
    """sqlite 错误 → 闭集码：约束冲突是业务上的记录冲突（record_conflict，不以 store_ 开头、不当暂时存储故障重试）。"""
    if isinstance(error, sqlite3.IntegrityError):
        return "record_conflict"
    name = getattr(error, "sqlite_errorname", "")
    return "store_readonly" if isinstance(name, str) and name.startswith("SQLITE_READONLY") else fallback


class FederatedStore:
    """联邦账本连接；公开写方法各自一个 IMMEDIATE 事务，嵌套在 `transaction()` 里时并入外层。"""

    def __init__(self, connection: sqlite3.Connection, path: Path) -> None:
        self._conn = connection
        self._conn.row_factory = sqlite3.Row
        self._depth = 0
        self._lease = ExitStack()
        self.path = path

    # ---- 打开与创建 ----

    @classmethod
    def _connect(cls, root: Path, *, create: bool) -> FederatedStore:
        lease = ExitStack()
        files: Any = get_platform().files
        path = root / FED_DB_NAME
        try:
            if get_platform().name == "windows":
                lease.enter_context(files.lease(root))
            if create:
                files.prepare_database(path)
            elif not path.exists():
                lease.close()
                raise StoreError("federation_store_missing")
            connection = sqlite3.connect(path, timeout=5.0, isolation_level=None)
        except StoreError:
            raise
        except (OSError, sqlite3.Error) as error:
            lease.close()
            raise StoreError("federation_store_unavailable") from error
        store = cls(connection, path)
        store._lease = lease
        return store

    @classmethod
    def create(cls, directory: Path | None = None, *, now: int | None = None) -> FederatedStore:
        """首次 `federation enable` 建库：只允许库文件尚不存在；生成随机 ledgerInstanceId。"""
        root = ensure_private_dir(directory or state_dir())
        if (root / FED_DB_NAME).exists():
            raise StoreError("federation_store_exists")
        store = cls._connect(root, create=True)
        try:
            store._configure()
            with store._transaction() as conn:
                if int(conn.execute("PRAGMA user_version").fetchone()[0]) != 0:
                    raise StoreError("federation_store_exists")
                for statement in _SCHEMA_V1:
                    conn.execute(statement)
                for table in _REVISION_TABLES:
                    for operation in ("INSERT", "UPDATE", "DELETE"):
                        conn.execute(
                            f"CREATE TRIGGER fed_rev_{table}_{operation.lower()} AFTER {operation} ON {table} BEGIN"
                            " UPDATE fed_meta SET value = CAST(value AS INTEGER) + 1 WHERE key = 'fedRevision'; END"
                        )
                conn.executemany(
                    "INSERT INTO fed_meta(key,value) VALUES (?,?)",
                    (("ledgerInstanceId", new_id()), ("fedRevision", "0"), ("enabled", "0"),
                     ("inboxCursor", "0"), ("receiptCursor", "0"), ("relayGeneration", "0"),
                     ("createdAt", str(now if now is not None else now_ms()))),
                )
                conn.execute(f"PRAGMA user_version={FED_SCHEMA_VERSION}")
            store._validate_files()
        except StoreError:
            store.close()
            raise
        except (sqlite3.DatabaseError, OSError) as error:
            store.close()
            raise StoreError("federation_store_corrupt") from error
        return store

    @classmethod
    def open(cls, directory: Path | None = None) -> FederatedStore:
        """打开已有联邦库；不存在报 federation_store_missing，绝不自动建空库（§88.2/§88.4，P2-5）。"""
        root = directory or state_dir()
        store = cls._connect(root, create=False)
        try:
            store._configure()
            version = int(store._conn.execute("PRAGMA user_version").fetchone()[0])
            if version > FED_SCHEMA_VERSION:
                raise StoreError("federation_schema_too_new")
            if version != FED_SCHEMA_VERSION:
                raise StoreError("federation_store_corrupt")
            store._validate_files()
        except StoreError:
            store.close()
            raise
        except (sqlite3.DatabaseError, OSError) as error:
            store.close()
            raise StoreError("federation_store_corrupt") from error
        return store

    @classmethod
    def open_readonly(cls, directory: Path) -> FederatedStore:
        """状态投影用的只读连接（DESIGN §90.6）：mode=ro、query_only、50 ms busy；不设 WAL、不修 ACL、不建库、不迁移。

        按普通只读读者参与 WAL 协调，读到的总是一致快照。SQLite 需要时会以调用方本人令牌补建标准 -wal/-shm
        （owner 2026-10-27 决定放宽「不补建」：用 SQLite 做不到严格不补建，immutable 绕法会读到前后不一致的数据，
        见 §90.13）；同用户普通令牌下与任何 ab 命令开库相同，Windows 提权令牌建出的属主由 §86 自愈。
        只读连接关库时不做 checkpoint，补建的空辅助文件会留到下一个写连接关库时才删除（Opus P3-r2-1）。
        不用 immutable，也不回退到可写打开；打不开时报 federation_store_unavailable，调用方把投影判为未知。
        """
        path = directory / FED_DB_NAME
        if not path.exists():
            raise StoreError("federation_store_missing")
        try:
            connection = sqlite3.connect(get_platform().files.sqlite_uri(path.absolute(), escaped=True), uri=True,
                                         timeout=0.05, isolation_level=None)
        except sqlite3.Error as error:
            raise StoreError("federation_store_unavailable") from error
        store = cls(connection, path)
        try:
            connection.execute("PRAGMA query_only=ON")
            version = int(connection.execute("PRAGMA user_version").fetchone()[0])
            if version > FED_SCHEMA_VERSION:
                raise StoreError("federation_schema_too_new")
            if version != FED_SCHEMA_VERSION:
                raise StoreError("federation_store_corrupt")
        except StoreError:
            store.close()
            raise
        except sqlite3.OperationalError as error:
            store.close()
            raise StoreError("federation_store_unavailable") from error  # 忙、锁定、打不开
        except sqlite3.DatabaseError as error:
            store.close()
            raise StoreError("federation_store_corrupt") from error  # 与可写 open() 同口径（Opus 实现审计 P3-5）
        return store

    def _validate_files(self) -> None:
        if get_platform().name == "windows":
            get_platform().files.validate_database(self.path)  # pyright: ignore[reportAttributeAccessIssue]

    def _configure(self) -> None:
        deadline = time.monotonic() + 5.0
        while True:
            try:
                self._conn.execute("PRAGMA journal_mode=WAL")
                break
            except sqlite3.OperationalError as error:
                if getattr(error, "sqlite_errorcode", 0) & 0xFF != sqlite3.SQLITE_BUSY:
                    raise
                if time.monotonic() >= deadline:
                    raise StoreError("store_busy") from error
                time.sleep(0.02)
        # intent 必须在外调前真正落盘
        self._conn.execute("PRAGMA synchronous=FULL")
        self._conn.execute("PRAGMA foreign_keys=ON")

    def close(self) -> None:
        try:
            self._conn.close()
        finally:
            self._lease.close()

    def __enter__(self) -> FederatedStore:
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()

    # ---- 事务 ----

    @contextmanager
    def _transaction(self) -> Iterator[sqlite3.Connection]:
        if self._depth:
            # 嵌套事务用 SAVEPOINT：内层抛错只撤回内层的写入（例如报告推进被确定拒绝），外层照常提交
            name = f"fed_sp_{self._depth}"
            try:
                self._conn.execute(f"SAVEPOINT {name}")
            except sqlite3.Error as error:
                raise StoreError(_write_error(error, "store_write_failed")) from error
            self._depth += 1
            try:
                yield self._conn
            except BaseException as error:
                try:
                    self._conn.execute(f"ROLLBACK TO {name}")
                    self._conn.execute(f"RELEASE {name}")
                except sqlite3.Error:
                    pass
                if isinstance(error, sqlite3.Error):
                    raise StoreError(_write_error(error, "store_write_failed")) from error
                raise
            else:
                try:
                    self._conn.execute(f"RELEASE {name}")
                except sqlite3.Error as error:
                    raise StoreError(_write_error(error, "store_write_failed")) from error
            finally:
                self._depth -= 1
            return
        try:
            self._conn.execute("BEGIN IMMEDIATE")
        except sqlite3.OperationalError as error:
            raise StoreError(_write_error(error, "store_busy")) from error
        self._depth = 1
        try:
            yield self._conn
        except BaseException as error:
            self._depth = 0
            try:
                self._conn.execute("ROLLBACK")
            except sqlite3.Error:
                pass
            if isinstance(error, sqlite3.Error):
                raise StoreError(_write_error(error, "store_write_failed")) from error
            raise
        else:
            self._depth = 0
            try:
                self._conn.execute("COMMIT")
            except sqlite3.Error as error:
                try:
                    self._conn.execute("ROLLBACK")
                except sqlite3.Error:
                    pass
                raise StoreError(_write_error(error, "store_write_failed")) from error

    def transaction(self) -> AbstractContextManager[sqlite3.Connection]:
        """多步写入合并为一个原子事务。"""
        return self._transaction()

    @contextmanager
    def read_snapshot(self) -> Iterator[None]:
        """同一个 WAL 读快照里完成多次查询。"""
        if self._depth:
            yield
            return
        self._conn.execute("BEGIN DEFERRED")
        self._depth = 1
        try:
            yield
        finally:
            self._depth = 0
            try:
                self._conn.execute("COMMIT")
            except sqlite3.Error:
                self._conn.execute("ROLLBACK")

    @property
    def connection(self) -> sqlite3.Connection:
        """供同包模块在事务内执行固定语句；不要在包外使用。"""
        return self._conn

    # ---- meta ----

    def meta(self, key: str) -> str | None:
        row = self._conn.execute("SELECT value FROM fed_meta WHERE key=?", (key,)).fetchone()
        return None if row is None else str(row[0])

    def set_meta(self, key: str, value: str) -> None:
        if key not in META_KEYS and not key.startswith("maxHubCommitCounter:"):
            raise ValueError(f"unknown fed_meta key: {key}")
        with self._transaction() as conn:
            conn.execute(
                "INSERT INTO fed_meta(key,value) VALUES (?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                (key, value),
            )

    def clear_relay_diagnostics(self) -> None:
        """relay 启动初始化：一笔短事务删掉上一代留下的三键（§90.6）。"""
        with self._transaction() as conn:
            conn.execute("DELETE FROM fed_meta WHERE key IN (?,?,?)", RELAY_DIAGNOSTIC_KEYS)

    def publish_relay_diagnostics(self, *, anchor_watch: str, version: str | None, published_at: int) -> None:
        """整组替换（§90.6）：同一事务先删三键再写本次有值的键，不依赖初始化清除成功；没有版本时旧版本随之删除。"""
        values = [("relayAnchorWatch", anchor_watch), ("relayPublishedAt", str(published_at))]
        if version is not None:
            values.append(("relayDistributionVersion", version))
        with self._transaction() as conn:
            conn.execute("DELETE FROM fed_meta WHERE key IN (?,?,?)", RELAY_DIAGNOSTIC_KEYS)
            conn.executemany("INSERT INTO fed_meta(key,value) VALUES (?,?)", values)

    def relay_diagnostics(self) -> dict[str, str]:
        """单条 SELECT 取齐三键并物化：三键来自同一 SQLite 读快照，不会拼出旧版本配新时间（§90.6）。"""
        rows = self._conn.execute("SELECT key, value FROM fed_meta WHERE key IN (?,?,?)",
                                  RELAY_DIAGNOSTIC_KEYS).fetchall()
        return {str(row[0]): str(row[1]) for row in rows}

    def ledger_instance_id(self) -> str:
        value = self.meta("ledgerInstanceId")
        if value is None:
            raise StoreError("federation_store_corrupt")
        return value

    def revision(self) -> tuple[str, int]:
        """(ledgerInstanceId, fedRevision)；摘要组合新鲜度用。"""
        raw = self.meta("fedRevision") or "0"
        return self.ledger_instance_id(), int(raw) if raw.isdigit() else 0

    def device_id(self) -> str:
        value = self.meta("deviceId")
        if value is None:
            raise StoreError("federation_not_configured")
        return value

    # ---- 任务与尝试 ----

    def get_task(self, authority_device: str, task_id: str) -> FedTask | None:
        row = self._conn.execute(
            "SELECT * FROM fed_tasks WHERE authority_device=? AND task_id=?", (authority_device, task_id)
        ).fetchone()
        return None if row is None else _task_from_row(row)

    def tasks(self, *, include_finished: bool = False, authority_only: bool = False, limit: int = 200) -> list[FedTask]:
        """最近活动在前的联邦任务；不含已结束时在 SQL 里先过滤，历史墓碑再多也不会挤掉进行中的任务。"""
        clauses: list[str] = []
        if authority_only:
            clauses.append("is_authority=1")
        if not include_finished:
            clauses.append("json_extract(state_json,'$.acceptedAt') IS NULL"
                           " AND json_extract(state_json,'$.closedAt') IS NULL")
        rows = self._conn.execute(
            "SELECT * FROM fed_tasks" + (" WHERE " + " AND ".join(clauses) if clauses else "")
            + " ORDER BY last_sync_at DESC, task_id LIMIT ?", (limit,),
        ).fetchall()
        return [_task_from_row(row) for row in rows]

    def followers(self, task_id: str) -> list[tuple[float, str]]:
        """以 task_id 为 `follows` 的联邦任务（只有本机发起的才有这个键，DESIGN §93.3）：(创建时间秒, 完整 ID)。"""
        rows = self._conn.execute(
            "SELECT task_id, state_json, last_sync_at FROM fed_tasks WHERE CASE WHEN json_valid(state_json)"
            " THEN json_extract(state_json,'$.follows') END = ?", (task_id,),
        ).fetchall()
        found: list[tuple[float, str]] = []
        for row in rows:
            created = load_dict(row["state_json"]).get("createdAt")
            when = created if isinstance(created, int) and not isinstance(created, bool) else int(row["last_sync_at"])
            found.append((when / 1000, str(row["task_id"])))
        return sorted(found)

    def find_tasks(self, task_ref: str, *, authority_device: str | None = None) -> list[FedTask]:
        """按完整 ID 或前缀查联邦任务；authority_device 给出时只在该权威下找。"""
        value = task_ref.strip().lower()
        if len(value) < 4 or any(ch not in "0123456789abcdef" for ch in value):
            return []
        params: list[object] = [value, value + "g"]
        where = "task_id >= ? AND task_id < ?"
        if authority_device is not None:
            where += " AND authority_device=?"
            params.append(authority_device)
        rows = self._conn.execute(f"SELECT * FROM fed_tasks WHERE {where} ORDER BY task_id LIMIT 8", params).fetchall()
        return [_task_from_row(row) for row in rows]

    def attempts(self, authority_device: str, task_id: str) -> list[FedAttempt]:
        rows = self._conn.execute(
            "SELECT * FROM fed_attempts WHERE authority_device=? AND task_id=? ORDER BY seq", (authority_device, task_id)
        ).fetchall()
        return [_attempt_from_row(row) for row in rows]

    def attempt_by_msg(self, msg_id: str) -> FedAttempt | None:
        row = self._conn.execute("SELECT * FROM fed_attempts WHERE msg_id=?", (msg_id,)).fetchone()
        return None if row is None else _attempt_from_row(row)

    def insert_task(self, task: FedTask) -> None:
        with self._transaction() as conn:
            conn.execute(
                "INSERT INTO fed_tasks(authority_device,task_id,is_authority,revision,current_work_seq,max_seq,"
                "state_json,last_sync_at,local_archived,sync_required) VALUES (?,?,?,?,?,?,?,?,?,?)",
                (task.authority_device, task.task_id, int(task.is_authority), task.revision, task.current_work_seq,
                 task.max_seq, dump(task.state), task.last_sync_at, int(task.local_archived), int(task.sync_required)),
            )

    def update_task(self, task: FedTask) -> None:
        """整行覆盖（调用方已在同一事务里读出并按写者规则改好）。"""
        with self._transaction() as conn:
            changed = conn.execute(
                "UPDATE fed_tasks SET is_authority=?,revision=?,current_work_seq=?,max_seq=?,state_json=?,"
                "last_sync_at=?,local_archived=?,sync_required=? WHERE authority_device=? AND task_id=?",
                (int(task.is_authority), task.revision, task.current_work_seq, task.max_seq, dump(task.state),
                 task.last_sync_at, int(task.local_archived), int(task.sync_required), task.authority_device,
                 task.task_id),
            ).rowcount
            if changed != 1:
                raise StoreError("task_not_found")

    def insert_attempt(self, attempt: FedAttempt) -> None:
        with self._transaction() as conn:
            conn.execute(
                "INSERT INTO fed_attempts(authority_device,task_id,seq,msg_id,role,target_device,target_json,"
                "sender_json,sender_class,body,refs_json,options_json,authority_state_json,evidence_no,"
                "delivery_json,effective_work_json) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (attempt.authority_device, attempt.task_id, attempt.seq, attempt.msg_id, attempt.role,
                 attempt.target_device, dump(attempt.target.to_dict()),
                 dump(attempt.sender.to_dict() if attempt.sender else {}), attempt.sender_class, attempt.body,
                 dump(attempt.refs), dump(attempt.options), dump(attempt.authority_state), attempt.evidence_no,
                 dump(attempt.delivery), dump(attempt.effective_work)),
            )

    def update_attempt_columns(self, msg_id: str, **columns: object) -> None:
        """按白名单列更新一条 attempt；JSON 列传 dict，由这里序列化。"""
        allowed = {"authority_state": "authority_state_json", "delivery": "delivery_json",
                   "effective_work": "effective_work_json", "evidence_no": "evidence_no",
                   "target": "target_json", "body": "body", "refs": "refs_json", "options": "options_json"}
        unknown = set(columns) - set(allowed)
        if unknown:
            raise ValueError(f"unsupported attempt columns: {sorted(unknown)}")
        values: list[object] = []
        sets: list[str] = []
        for name, value in columns.items():
            sets.append(f"{allowed[name]}=?")
            if name == "target":
                assert isinstance(value, TargetRef)
                values.append(dump(value.to_dict()))
            elif isinstance(value, dict | list):
                values.append(dump(value))
            else:
                values.append(value)
        with self._transaction() as conn:
            changed = conn.execute(f"UPDATE fed_attempts SET {', '.join(sets)} WHERE msg_id=?", (*values, msg_id)).rowcount
            if changed != 1:
                raise StoreError("attempt_not_found")

    # ---- 事件 ----

    def add_event(self, authority_device: str, task_id: str, kind: str, *, now: int,
                  attempt_seq: int | None = None, detail: Mapping[str, Any] | None = None) -> None:
        with self._transaction() as conn:
            conn.execute(
                "INSERT INTO fed_events(authority_device,task_id,attempt_seq,at,kind,detail_json) VALUES (?,?,?,?,?,?)",
                (authority_device, task_id, attempt_seq, now, kind, dump(dict(detail or {}))),
            )
            conn.execute(
                "DELETE FROM fed_events WHERE authority_device=? AND task_id=? AND id NOT IN"
                " (SELECT id FROM fed_events WHERE authority_device=? AND task_id=? ORDER BY id DESC LIMIT ?)",
                (authority_device, task_id, authority_device, task_id, MAX_EVENTS_PER_TASK),
            )

    def events(self, authority_device: str, task_id: str, *, limit: int = 50) -> list[dict[str, Any]]:
        rows = self._conn.execute(
            "SELECT attempt_seq,at,kind,detail_json FROM fed_events WHERE authority_device=? AND task_id=?"
            " ORDER BY id DESC LIMIT ?", (authority_device, task_id, limit)
        ).fetchall()
        return [{"attemptSeq": row[0], "at": row[1], "kind": row[2], "detail": load_dict(row[3])} for row in reversed(rows)]

    # ---- 路由 ----

    def add_route(self, *, task_id: str, authority_device: str, hub_id: str, local_role: str,
                  local_endpoint_id: str, first_msg_id: str) -> None:
        with self._transaction() as conn:
            conn.execute(
                "INSERT OR IGNORE INTO fed_routes(task_id,authority_device,hub_id,local_role,local_endpoint_id,"
                "first_msg_id) VALUES (?,?,?,?,?,?)",
                (task_id, authority_device, hub_id, local_role, local_endpoint_id, first_msg_id),
            )

    def routes(self, task_id: str) -> list[dict[str, Any]]:
        rows = self._conn.execute("SELECT * FROM fed_routes WHERE task_id=?", (task_id,)).fetchall()
        return [dict(row) for row in rows]

    def task_hubs(self, authority_device: str, task_id: str) -> set[str]:
        """该任务的路由所属 hub（灾难换 hub 后，旧 hub 路由上的任务冻结，§88.11）。"""
        rows = self._conn.execute("SELECT DISTINCT hub_id FROM fed_routes WHERE authority_device=? AND task_id=?",
                                  (authority_device, task_id)).fetchall()
        return {str(row[0]) for row in rows}

    # ---- 操作、发件箱、收件箱 ----

    def operation(self, source_device: str, operation_id: str) -> dict[str, Any] | None:
        row = self._conn.execute(
            "SELECT * FROM fed_operations WHERE source_device=? AND operation_id=?", (source_device, operation_id)
        ).fetchone()
        return None if row is None else dict(row)

    def add_operation(self, *, source_device: str, operation_id: str, msg_id: str, payload_hash: str,
                      result: Mapping[str, Any], now: int) -> None:
        with self._transaction() as conn:
            conn.execute(
                "INSERT INTO fed_operations(source_device,operation_id,msg_id,payload_hash,result_json,created_at)"
                " VALUES (?,?,?,?,?,?)",
                (source_device, operation_id, msg_id, payload_hash, dump(dict(result)), now),
            )

    def add_outbox(self, *, msg_id: str, operation_id: str, target_device: str, envelope: Mapping[str, Any],
                   payload_hash: str, expires_at: int, now: int) -> None:
        with self._transaction() as conn:
            conn.execute(
                "INSERT INTO fed_outbox(msg_id,operation_id,target_device,envelope_json,payload_hash,state,expires_at,"
                "next_try_at) VALUES (?,?,?,?,?,'ready',?,?)",
                (msg_id, operation_id, target_device, dump(dict(envelope)), payload_hash, expires_at, now),
            )

    def outbox(self, *, states: tuple[str, ...] = ("ready",), limit: int = 64) -> list[dict[str, Any]]:
        marks = ",".join("?" for _ in states)
        rows = self._conn.execute(
            f"SELECT * FROM fed_outbox WHERE state IN ({marks}) ORDER BY next_try_at, rowid LIMIT ?", (*states, limit)
        ).fetchall()
        return [dict(row) for row in rows]

    def outbox_item(self, msg_id: str) -> dict[str, Any] | None:
        row = self._conn.execute("SELECT * FROM fed_outbox WHERE msg_id=?", (msg_id,)).fetchone()
        return None if row is None else dict(row)

    def set_outbox_state(self, msg_id: str, *, state: str, expected: tuple[str, ...] | None = None,
                         receipt: Mapping[str, Any] | None = None, next_try_at: int | None = None) -> bool:
        if state not in OUTBOX_STATES:
            raise ValueError(state)
        with self._transaction() as conn:
            row = conn.execute("SELECT state FROM fed_outbox WHERE msg_id=?", (msg_id,)).fetchone()
            if row is None or (expected is not None and row[0] not in expected):
                return False
            conn.execute(
                "UPDATE fed_outbox SET state=?, hub_receipt_json=COALESCE(?,hub_receipt_json),"
                " next_try_at=COALESCE(?,next_try_at) WHERE msg_id=?",
                (state, dump(dict(receipt)) if receipt is not None else None, next_try_at, msg_id),
            )
        return True

    def inbox_item(self, msg_id: str) -> dict[str, Any] | None:
        row = self._conn.execute("SELECT * FROM fed_inbox WHERE msg_id=?", (msg_id,)).fetchone()
        return None if row is None else dict(row)

    def inbox_receiving_others(self, msg_id: str) -> bool:
        """除 msg_id 外是否还有收件停在 receiving（等 hub 重推）。"""
        row = self._conn.execute("SELECT 1 FROM fed_inbox WHERE apply_state='receiving' AND msg_id<>? LIMIT 1",
                                 (msg_id,)).fetchone()
        return row is not None

    def inbox_by_operation(self, source_device: str, operation_id: str) -> dict[str, Any] | None:
        row = self._conn.execute(
            "SELECT * FROM fed_inbox WHERE source_device=? AND operation_id=?", (source_device, operation_id)
        ).fetchone()
        return None if row is None else dict(row)

    def add_inbox(self, *, msg_id: str, source_device: str, operation_id: str, payload_hash: str,
                  envelope: Mapping[str, Any] | None, state: str, now: int,
                  result: Mapping[str, Any] | None = None) -> None:
        if state not in INBOX_STATES:
            raise ValueError(state)
        with self._transaction() as conn:
            conn.execute(
                "INSERT INTO fed_inbox(msg_id,source_device,operation_id,payload_hash,envelope_json,received_at,"
                "apply_state,result_json) VALUES (?,?,?,?,?,?,?,?)",
                (msg_id, source_device, operation_id, payload_hash,
                 dump(dict(envelope)) if envelope is not None else None, now, state, dump(dict(result or {}))),
            )

    def set_inbox_state(self, msg_id: str, *, state: str, expected: tuple[str, ...] | None = None,
                        result: Mapping[str, Any] | None = None) -> bool:
        if state not in INBOX_STATES:
            raise ValueError(state)
        with self._transaction() as conn:
            row = conn.execute("SELECT apply_state FROM fed_inbox WHERE msg_id=?", (msg_id,)).fetchone()
            if row is None or (expected is not None and row[0] not in expected):
                return False
            conn.execute(
                "UPDATE fed_inbox SET apply_state=?, result_json=COALESCE(?,result_json) WHERE msg_id=?",
                (state, dump(dict(result)) if result is not None else None, msg_id),
            )
        return True

    # ---- 原生发送与证据 ----

    def native(self, msg_id: str) -> dict[str, Any] | None:
        row = self._conn.execute("SELECT * FROM fed_native_sends WHERE msg_id=?", (msg_id,)).fetchone()
        return None if row is None else dict(row)

    def add_native(self, msg_id: str, *, state: str = "prepared") -> None:
        if state not in NATIVE_STATES:
            raise ValueError(state)
        with self._transaction() as conn:
            conn.execute("INSERT INTO fed_native_sends(msg_id,state,result_json) VALUES (?,?,'{}')", (msg_id, state))

    def natives_in(self, states: tuple[str, ...]) -> list[dict[str, Any]]:
        marks = ",".join("?" for _ in states)
        rows = self._conn.execute(
            f"SELECT * FROM fed_native_sends WHERE state IN ({marks}) ORDER BY rowid", states
        ).fetchall()
        return [dict(row) for row in rows]

    def add_evidence(self, msg_id: str, evidence_no: int, *, delivery_device: str, evidence: Mapping[str, Any]) -> bool:
        """导入/写入一条证据；同号同内容幂等返回 False，同号不同内容拒绝。"""
        with self._transaction() as conn:
            row = conn.execute(
                "SELECT evidence_json FROM fed_evidence WHERE msg_id=? AND evidence_no=?", (msg_id, evidence_no)
            ).fetchone()
            text = dump(dict(evidence))
            if row is not None:
                if row[0] != text:
                    raise StoreError("idempotency_conflict")
                return False
            conn.execute(
                "INSERT INTO fed_evidence(msg_id,evidence_no,delivery_device,evidence_json) VALUES (?,?,?,?)",
                (msg_id, evidence_no, delivery_device, text),
            )
        return True

    def evidence(self, msg_id: str) -> list[dict[str, Any]]:
        rows = self._conn.execute(
            "SELECT evidence_no,delivery_device,evidence_json FROM fed_evidence WHERE msg_id=? ORDER BY evidence_no",
            (msg_id,),
        ).fetchall()
        return [{"evidenceNo": row[0], "deliveryDevice": row[1], **load_dict(row[2])} for row in rows]

    # ---- 报告与裁决 ----

    def add_report(self, *, authority_device: str, task_id: str, attempt_seq: int, reporter_device: str,
                   report_no: int, operation_id: str, report: Mapping[str, Any]) -> None:
        with self._transaction() as conn:
            conn.execute(
                "INSERT INTO fed_reports(authority_device,task_id,attempt_seq,reporter_device,report_no,operation_id,"
                "report_json) VALUES (?,?,?,?,?,?,?)",
                (authority_device, task_id, attempt_seq, reporter_device, report_no, operation_id, dump(dict(report))),
            )

    def reports(self, authority_device: str, task_id: str, attempt_seq: int | None = None) -> list[dict[str, Any]]:
        params: list[object] = [authority_device, task_id]
        where = "authority_device=? AND task_id=?"
        if attempt_seq is not None:
            where += " AND attempt_seq=?"
            params.append(attempt_seq)
        rows = self._conn.execute(
            f"SELECT * FROM fed_reports WHERE {where} ORDER BY attempt_seq, report_no", params
        ).fetchall()
        return [{**dict(row), "report": load_dict(row["report_json"])} for row in rows]

    def report_by_operation(self, reporter_device: str, operation_id: str) -> dict[str, Any] | None:
        row = self._conn.execute(
            "SELECT * FROM fed_reports WHERE reporter_device=? AND operation_id=?", (reporter_device, operation_id)
        ).fetchone()
        return None if row is None else {**dict(row), "report": load_dict(row["report_json"])}

    def max_report_no(self, authority_device: str, task_id: str, attempt_seq: int, reporter_device: str) -> int:
        row = self._conn.execute(
            "SELECT COALESCE(MAX(report_no),0) FROM fed_reports WHERE authority_device=? AND task_id=?"
            " AND attempt_seq=? AND reporter_device=?", (authority_device, task_id, attempt_seq, reporter_device)
        ).fetchone()
        return int(row[0])

    def decision(self, reporter_device: str, report_operation_id: str) -> dict[str, Any] | None:
        row = self._conn.execute(
            "SELECT * FROM fed_report_decisions WHERE reporter_device=? AND report_operation_id=?",
            (reporter_device, report_operation_id),
        ).fetchone()
        return None if row is None else dict(row)

    def add_decision(self, *, reporter_device: str, report_operation_id: str, authority_revision: int,
                     decision: str, reason: str | None) -> bool:
        """记录一条裁决；已有则返回 False（同 operation 的重复裁决返回原决定，由调用方读取）。"""
        if decision not in ("accepted", "rejected", "superseded"):
            raise ValueError(decision)
        with self._transaction() as conn:
            if conn.execute(
                "SELECT 1 FROM fed_report_decisions WHERE reporter_device=? AND report_operation_id=?",
                (reporter_device, report_operation_id),
            ).fetchone() is not None:
                return False
            conn.execute(
                "INSERT INTO fed_report_decisions(reporter_device,report_operation_id,authority_revision,decision,reason)"
                " VALUES (?,?,?,?,?)", (reporter_device, report_operation_id, authority_revision, decision, reason),
            )
        return True

    # ---- 端点绑定 ----

    def binding(self, endpoint_id: str) -> dict[str, Any] | None:
        row = self._conn.execute("SELECT * FROM fed_bindings WHERE endpoint_id=?", (endpoint_id,)).fetchone()
        return None if row is None else dict(row)

    def bind_endpoint(self, *, provider: str, native_id: str, root_binding: str, local_ref: Mapping[str, Any]) -> tuple[str, int]:
        """按 (provider, nativeId, 本机根绑定) 分配或复用持久 endpointId；同根恢复更新 revision 不换 ID（§88.6）。"""
        with self._transaction() as conn:
            row = conn.execute(
                "SELECT endpoint_id,revision,local_ref_json FROM fed_bindings WHERE provider=? AND native_id=?"
                " AND root_binding=?", (provider, native_id, root_binding)
            ).fetchone()
            text = dump(dict(local_ref))
            if row is None:
                endpoint_id = new_id()
                conn.execute(
                    "INSERT INTO fed_bindings(endpoint_id,provider,native_id,root_binding,revision,local_ref_json)"
                    " VALUES (?,?,?,?,1,?)", (endpoint_id, provider, native_id, root_binding, text)
                )
                return endpoint_id, 1
            endpoint_id, revision = str(row[0]), int(row[1])
            if row[2] != text:
                revision += 1
                conn.execute("UPDATE fed_bindings SET revision=?,local_ref_json=? WHERE endpoint_id=?",
                             (revision, text, endpoint_id))
            return endpoint_id, revision

    # ---- 远端目录缓存 ----

    def put_device_state(self, *, device_id: str, name: str, revision: int, snapshot: Mapping[str, Any],
                         last_seen: int | None, state: str) -> None:
        with self._transaction() as conn:
            conn.execute(
                "INSERT INTO fed_device_state(device_id,name,directory_revision,snapshot_json,last_seen,state)"
                " VALUES (?,?,?,?,?,?) ON CONFLICT(device_id) DO UPDATE SET name=excluded.name,"
                " directory_revision=excluded.directory_revision, snapshot_json=excluded.snapshot_json,"
                " last_seen=excluded.last_seen, state=excluded.state",
                (device_id, name, revision, dump(dict(snapshot)), last_seen, state),
            )

    def remember_device_name(self, device_id: str, name: str) -> None:
        """记住某设备的登记名（来自 hub 认证盖章的 sourceDeviceName）；已有目录行不覆盖。"""
        with self._transaction() as conn:
            conn.execute("INSERT OR IGNORE INTO fed_device_state(device_id,name,directory_revision,snapshot_json,"
                         "last_seen,state) VALUES (?,?,0,'{}',NULL,'unknown')", (device_id, name))

    def device_states(self) -> list[dict[str, Any]]:
        rows = self._conn.execute("SELECT * FROM fed_device_state ORDER BY name").fetchall()
        return [{**dict(row), "snapshot": load_dict(row["snapshot_json"])} for row in rows]

    # ---- 附件 manifest ----

    def add_attachments(self, *, msg_id: str, authority_device: str, task_id: str, refs: list[dict[str, Any]],
                        blob_state: str, now: int, report_operation_id: str | None = None) -> None:
        """按 wire refs 写 manifest：blob 取给定状态（源端 staged、收件端 downloading），reference 一律 reference_only。

        源端冻结副本按 SHA 放在 staging（`<sha>.blob`），manifest 不记位置；收件端落地后再写 location/relpath。
        """
        if blob_state not in ATTACHMENT_STATES:
            raise ValueError(blob_state)
        with self._transaction() as conn:
            for index, ref in enumerate(refs):
                blob = ref.get("transfer") == "blob"
                conn.execute(
                    "INSERT OR IGNORE INTO fed_attachments(msg_id,ref_index,authority_device,task_id,report_operation_id,"
                    "origin_device,original_path,resolved_path,original_name,transfer,reason,sha256,size,location,"
                    "local_relpath,file_identity_json,state,verified_at,last_ref_at,retain_until)"
                    " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,NULL,?,NULL,?,NULL)",
                    (msg_id, index, authority_device, task_id, report_operation_id, ref["originDeviceId"],
                     ref["originalPath"], ref["resolvedPath"], ref["name"], ref["transfer"], ref.get("reason"),
                     ref.get("sha256"), int(ref["size"]), None, None,
                     blob_state if blob else "reference_only", now),
                )

    def attachments(self, msg_id: str) -> list[dict[str, Any]]:
        rows = self._conn.execute("SELECT * FROM fed_attachments WHERE msg_id=? ORDER BY ref_index", (msg_id,)).fetchall()
        return [dict(row) for row in rows]

    def update_attachment(self, msg_id: str, ref_index: int, **columns: object) -> None:
        allowed = {"state", "location", "local_relpath", "file_identity_json", "verified_at", "last_ref_at",
                   "retain_until"}
        if not columns or set(columns) - allowed:
            raise ValueError("attachment columns")
        if "state" in columns and columns["state"] not in ATTACHMENT_STATES:
            raise ValueError("attachment state")
        assignments = ",".join(f"{name}=?" for name in columns)
        with self._transaction() as conn:
            conn.execute(f"UPDATE fed_attachments SET {assignments} WHERE msg_id=? AND ref_index=?",
                         (*columns.values(), msg_id, ref_index))

    def blob_sources(self, sha256: str) -> list[dict[str, Any]]:
        """本机持有该 SHA 内容的 manifest（冻结副本或已校验的交付/私有副本）：上传与转发只从这里取，不重读源路径。"""
        rows = self._conn.execute(
            "SELECT * FROM fed_attachments WHERE sha256=? AND state IN ('staged','ready','hub_ready','uploading')"
            " AND location IS NOT NULL AND local_relpath IS NOT NULL ORDER BY verified_at DESC", (sha256,)).fetchall()
        return [dict(row) for row in rows]

    # ---- 计数（§83，联邦库独立计） ----

    def recent_deliveries(self, *, limit: int = 64) -> list[tuple[int, dict[str, Any]]]:
        """本设备实际执行过的联邦原生投递（DESIGN §88.8）：(投递时刻毫秒, 摘要投递项)。

        只取本机 native 作业（A 的远端 attempt 在 A 上没有 native 行，天然不入）；按本机证据状态沿
        MAY_HAVE_ARRIVED 筛选；接收端点取实际投递的 pane/provider，没有真实 pane 不发布，不伪造。
        """
        states = ("written", "queued", "delivered", "unknown", "held")
        marks = ",".join("?" for _ in states)
        rows = self._conn.execute(
            "SELECT n.msg_id, n.local_target_json, n.result_json, n.intent_at, a.role, a.options_json, a.delivery_json"
            " FROM fed_native_sends n JOIN fed_attempts a ON a.msg_id=n.msg_id"
            f" WHERE n.state IN ('finished','unknown') AND json_extract(a.delivery_json,'$.state') IN ({marks})"
            " ORDER BY COALESCE(json_extract(a.delivery_json,'$.at'), n.intent_at) DESC LIMIT ?",
            (*states, int(limit)),
        ).fetchall()
        found: list[tuple[int, dict[str, Any]]] = []
        for row in rows:
            target = load_dict(row["local_target_json"])
            result = load_dict(row["result_json"])
            pane = result.get("deliveredPane") if isinstance(result.get("deliveredPane"), str) else target.get("pane")
            provider = target.get("provider")
            if not isinstance(pane, str) or not _PANE.fullmatch(pane) or not isinstance(provider, str):
                continue
            item: dict[str, Any] = {"messageId": row["msg_id"], "role": row["role"], "pane": pane, "provider": provider}
            # 结束回执与补充消息标出 kind，与本机 Store.recent_delivery_rows 同口径（DESIGN §45.31.7、§95.5.3）
            options = load_dict(row["options_json"])
            kind = options.get(LOCAL_NOTICE_KIND, options.get("noticeKind"))
            if row["role"] == "notice" and kind in QUIET_NOTICE_KINDS:
                item["kind"] = kind
            at = load_dict(row["delivery_json"]).get("at")
            found.append((at if isinstance(at, int) else int(row["intent_at"] or 0), item))
        return found

    def active_authority_tasks(self) -> int:
        rows = self._conn.execute("SELECT state_json FROM fed_tasks WHERE is_authority=1").fetchall()
        return sum(1 for row in rows if not (load_dict(row[0]).get("acceptedAt") or load_dict(row[0]).get("closedAt")))

    def pending_authority_attempts(self) -> int:
        """A 作者名下、未结束任务里还没有任何投递结论的 attempt 数（pending 安全阀）。

        已验收/关闭的任务不计：远端没回证据的 attempt（对方离线、换 hub、撤销设备）随任务结束出列，不永久占额。
        """
        rows = self._conn.execute(
            "SELECT a.delivery_json FROM fed_attempts a JOIN fed_tasks t ON t.authority_device=a.authority_device"
            " AND t.task_id=a.task_id WHERE t.is_authority=1"
            " AND json_extract(t.state_json,'$.acceptedAt') IS NULL AND json_extract(t.state_json,'$.closedAt') IS NULL"
        ).fetchall()
        return sum(1 for row in rows if load_dict(row[0]).get("state", "pending") == "pending")
