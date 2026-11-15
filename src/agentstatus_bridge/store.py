"""协作桥任务账本（SQLite）：任务、投递尝试、时间线与崩溃恢复。

账本只属于协作模块，保存用户交给它的任务正文、引用与结构化结果（DESIGN §45.1），
不保存其他会话的 transcript。投递状态一律用条件更新（compare-and-set）迁移，保证同一
消息只由一个进程外调；外调中断的消息恢复时标为 unknown，从不自动重发。多步业务写入
（汇报、复核结论与后续请求）用 `transaction()` 合并为一个事务，中断时整体回滚。
"""

from __future__ import annotations

from .platforms.factory import get_platform
from contextlib import ExitStack
from .platforms.types import Presence

from collections.abc import Collection, Iterator
from contextlib import AbstractContextManager, contextmanager
import json
import math
import os
from pathlib import Path
import re
import sqlite3
import time
from types import TracebackType
from typing import Any
import uuid

from .platforms import process as procfs
from .ids import is_id_prefix, new_id
from .model import (
    CLOSURE_KIND,
    FYI_KIND,
    FYI_OPTION,
    QUIET_NOTICE_KINDS,
    HANDED_OVER,
    NOTE_KIND,
    NOTICE_KIND_OPTION,
    REMINDER_OPTION,
    Attempt,
    Consumption,
    Delivery,
    EndpointRef,
    Flow,
    Provider,
    Role,
    Task,
    Verdict,
    Work,
)
from .paths import ensure_private_dir, state_dir
from .transports.codex_native import native_id

SCHEMA_VERSION = 2
DB_NAME = "bridge.sqlite3"
MAX_ACTIVE_TASKS = 100
MAX_ATTEMPTS_PER_TASK = 64
# 通知预留总额；其中最多一个名额可用于提醒，其余留给终态通知和结束回执。
NOTICE_RESERVE = 4
# 按全部尝试序号计数的提前提示阈值，不是工作轮次数。
ATTEMPT_WARNING_THRESHOLD = 48
# 仅这两种写前容量拒绝允许业务层跳过附带消息，不回滚主状态。
CAPACITY_CODES = frozenset({"capacity_attempts", "capacity_pending"})
MAX_PENDING_ATTEMPTS = 256
# 接收 pane 只接受 tmux 形式，与摘要 binding 同一口径（DESIGN §45.24）
_PANE_RE = re.compile(r"%[0-9]+")
# 消息 id：桥生成的随机 32 位十六进制，与 envelope 头部、观察者回传的 outcomeOrigin 同一口径（DESIGN §45.26）
_MESSAGE_RE = re.compile(r"[0-9a-f]{32}")
# 可能已经到达对方的投递状态：交出、结果不明、对方暂存
_MAY_HAVE_ARRIVED = frozenset(HANDED_OVER | {Delivery.UNKNOWN, Delivery.HELD})
MAX_EVENTS_PER_TASK = 256
MAX_BODY_BYTES = 64 * 1024
MAX_TITLE_CHARS = 120
# 一次报告最多引用的文件数；与其他账本记录上限放在一起，labels 与 reports 都从这里取（DESIGN §48 R2）
MAX_FILES = 16
FINISHED_RETENTION_SECONDS = 30 * 86400
MAX_FINISHED_TASKS = 1000
WITHDRAWAL_RECOVERY_SECONDS = 600  # 远大于10秒受控等待预算，防止异空间/卡住的活动行永久占位（§73.6）
WINDOWS_SENDING_RECOVERY_SECONDS = 600 + 120  # W2 add总预算＋余量；只恢复UNKNOWN，不重发


def attempt_limit(role: Role, options: dict[str, Any] | None = None) -> int:
    """§83：按全部尝试的序号限额，不能只数工作条数；提醒留出终态通知＋两个结束回执。

    任务内补充消息（§95.5.2）按工作类算：与 retry 同为 60，不占留给提醒、结果通知与结束回执的 61–64。
    """
    if role is not Role.NOTICE or (options is not None and options.get(NOTICE_KIND_OPTION) == NOTE_KIND):
        return MAX_ATTEMPTS_PER_TASK - NOTICE_RESERVE
    if options is not None and REMINDER_OPTION in options:
        return MAX_ATTEMPTS_PER_TASK - (NOTICE_RESERVE - 1)
    return MAX_ATTEMPTS_PER_TASK

_SCHEMA_V2: tuple[str, ...] = (
    """CREATE TABLE IF NOT EXISTS meta (
        key TEXT PRIMARY KEY,
        value TEXT NOT NULL
    )""",
    """CREATE TABLE IF NOT EXISTS tasks (
        id TEXT PRIMARY KEY,
        created_at REAL NOT NULL,
        updated_at REAL NOT NULL,
        title TEXT NOT NULL,
        flow TEXT NOT NULL,
        origin TEXT,
        reviewer TEXT,
        control TEXT NOT NULL DEFAULT 'active',
        verdict TEXT,
        accepted_at REAL,
        viewed_at REAL,
        closed_at REAL,
        close_reason TEXT,
        options TEXT NOT NULL DEFAULT '{}'
    )""",
    """CREATE TABLE IF NOT EXISTS attempts (
        id TEXT PRIMARY KEY,
        task_id TEXT NOT NULL REFERENCES tasks(id) ON DELETE CASCADE,
        seq INTEGER NOT NULL,
        role TEXT NOT NULL,
        target TEXT NOT NULL,
        message_id TEXT NOT NULL UNIQUE,
        created_at REAL NOT NULL,
        body TEXT NOT NULL,
        refs TEXT NOT NULL DEFAULT '[]',
        delivery TEXT NOT NULL,
        delivery_reason TEXT,
        delivery_at REAL,
        provider_ref TEXT,
        delivery_detail TEXT NOT NULL DEFAULT '{}',
        consumption TEXT NOT NULL DEFAULT 'not_observed',
        work TEXT NOT NULL,
        work_at REAL,
        result TEXT,
        sender TEXT,
        sender_class TEXT,
        options TEXT NOT NULL DEFAULT '{}',
        UNIQUE (task_id, seq)
    )""",
    """CREATE TABLE IF NOT EXISTS events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        task_id TEXT NOT NULL REFERENCES tasks(id) ON DELETE CASCADE,
        attempt_seq INTEGER,
        at REAL NOT NULL,
        kind TEXT NOT NULL,
        detail TEXT NOT NULL DEFAULT '{}'
    )""",
    "CREATE INDEX IF NOT EXISTS events_by_task ON events (task_id, id)",
    "CREATE INDEX IF NOT EXISTS attempts_by_delivery ON attempts (delivery)",
)
# v1 → v2：任务与尝试增加 options（显式放行共享 thread、是否通知发起方等）
_MIGRATE_V1_TO_V2: tuple[str, ...] = (
    "ALTER TABLE tasks ADD COLUMN options TEXT NOT NULL DEFAULT '{}'",
    "ALTER TABLE attempts ADD COLUMN options TEXT NOT NULL DEFAULT '{}'",
)

_TASK_FIELDS = frozenset(
    {"control", "verdict", "accepted_at", "viewed_at", "closed_at", "close_reason"}
)
_ARCHIVED_RISK_KEY = "archived_with_native_risk"
# 账本修订号：由触发器在 tasks/attempts/events 任一行变化后递增，供摘要判断是否落后（DESIGN §45.14）
# worker 每秒判断是否驻留要查「观察窗口内有没有某状态的投递」：复合索引让它只走索引，不读历史行与正文（DESIGN §45.29）
_WINDOW_INDEX = "attempts_by_delivery_at"
_REVISION_KEY = "ledger_revision"
_LEDGER_ID_KEY = "ledger_id"
_REVISION_TRIGGERS: tuple[tuple[str, str, str], ...] = tuple(
    (f"ab_revision_{table}_{operation.lower()}", table, operation)
    for table in ("tasks", "attempts", "events", "native_withdrawals")
    for operation in ("INSERT", "UPDATE", "DELETE")
)


def _write_error_code(error: sqlite3.Error, fallback: str) -> str:
    """写入类失败的原因码：账本或其 -wal/-shm 不可写时单独报出，不混进「正忙」或「写入失败」（Opus 复审 P3-d）。"""
    name = getattr(error, "sqlite_errorname", "")
    return "store_readonly" if isinstance(name, str) and name.startswith("SQLITE_READONLY") else fallback


class StoreError(Exception):
    """账本错误，带固定原因码。"""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def _dump(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _load_dict(raw: object) -> dict[str, Any]:
    if not isinstance(raw, str):
        return {}
    try:
        value = json.loads(raw)
    except ValueError:
        return {}
    return value if isinstance(value, dict) else {}


def _load_list(raw: object) -> list[dict[str, Any]]:
    if not isinstance(raw, str):
        return []
    try:
        value = json.loads(raw)
    except ValueError:
        return []
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, dict)]


def _task_from_row(row: sqlite3.Row) -> Task:
    verdict = row["verdict"]
    return Task(
        id=row["id"],
        created_at=float(row["created_at"]),
        updated_at=float(row["updated_at"]),
        title=row["title"],
        flow=Flow(row["flow"]),
        origin=EndpointRef.from_json(row["origin"]),
        reviewer=EndpointRef.from_json(row["reviewer"]),
        control=row["control"],
        verdict=Verdict(verdict) if verdict else None,
        accepted_at=row["accepted_at"],
        viewed_at=row["viewed_at"],
        closed_at=row["closed_at"],
        close_reason=row["close_reason"],
        options=_load_dict(row["options"]),
    )


def _attempt_from_row(row: sqlite3.Row) -> Attempt:
    target = EndpointRef.from_json(row["target"])
    if target is None:
        raise ValueError("attempt target is unreadable")
    result = row["result"]
    return Attempt(
        id=row["id"],
        task_id=row["task_id"],
        seq=int(row["seq"]),
        role=Role(row["role"]),
        target=target,
        message_id=row["message_id"],
        created_at=float(row["created_at"]),
        body=row["body"],
        refs=_load_list(row["refs"]),
        delivery=Delivery(row["delivery"]),
        delivery_reason=row["delivery_reason"],
        delivery_at=row["delivery_at"],
        provider_ref=row["provider_ref"],
        delivery_detail=_load_dict(row["delivery_detail"]),
        consumption=Consumption(row["consumption"]),
        work=Work(row["work"]),
        work_at=row["work_at"],
        result=_load_dict(result) if result is not None else None,
        sender=EndpointRef.from_json(row["sender"]),
        sender_class=row["sender_class"],
        options=_load_dict(row["options"]),
    )


def check_body(body: str) -> None:
    """正文大小上限；超出时建议改用文件引用。"""
    if not body.strip():
        raise StoreError("empty_message")
    if len(body.encode("utf-8")) > MAX_BODY_BYTES:
        raise StoreError("message_too_large")


class Store:
    """单个账本连接；公开写方法各自是一个 IMMEDIATE 事务，嵌套在 `transaction()` 内时并入外层。"""

    def __init__(self, connection: sqlite3.Connection) -> None:
        self._conn = connection
        self._conn.row_factory = sqlite3.Row
        self._depth = 0
        self._withdrawals_ready = False
        self._platform_lease = ExitStack()

    @classmethod
    def open(cls, directory: Path | None = None) -> Store:
        """打开（必要时创建）账本；schema 高于本程序时只读拒绝，不迁移不删除。"""
        lease = ExitStack()
        files: Any = get_platform().files
        try:
            root = ensure_private_dir(directory or state_dir())
            path = root / DB_NAME
            if get_platform().name == 'windows':
                lease.enter_context(files.lease(root))
            get_platform().files.prepare_database(path)
            connection = sqlite3.connect(path, timeout=5.0, isolation_level=None)
        except (OSError, sqlite3.Error) as error:
            lease.close()
            raise StoreError("store_unavailable") from error
        store = cls(connection)
        store._platform_lease = lease
        try:
            store._configure()
            store._migrate()
            store._ensure_withdrawals()
            store._ensure_revision_objects()
            store._ensure_indexes()
            if get_platform().name == 'windows':
                files.validate_database(path)
        except StoreError:
            store.close()
            raise
        except (sqlite3.DatabaseError, OSError) as error:
            store.close()
            raise StoreError("store_corrupt") from error
        return store

    def close(self) -> None:
        try:
            self._conn.close()
        finally:
            self._platform_lease.close()

    def __enter__(self) -> Store:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        del exc_type, exc, traceback
        self.close()

    def _configure(self) -> None:
        # 空账本两个首次opener竞争切WAL时，SQLite有的BUSY不走busy_timeout。
        # 仅重试这一只影响连接配置的操作，沿既有5秒预算，不重试任何业务写入。
        deadline = time.monotonic() + 5.0
        while True:
            try:
                self._conn.execute("PRAGMA journal_mode=WAL")
                break
            except sqlite3.OperationalError as error:
                if getattr(error, "sqlite_errorcode", 0) & 0xFF != sqlite3.SQLITE_BUSY:
                    raise
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise StoreError("store_busy") from error
                time.sleep(min(0.02, remaining))
        # 发送意图必须在外调前真正落盘
        self._conn.execute("PRAGMA synchronous=FULL")
        self._conn.execute("PRAGMA foreign_keys=ON")

    def _migrate(self) -> None:
        with self._transaction() as conn:
            version = int(conn.execute("PRAGMA user_version").fetchone()[0])
            if version > SCHEMA_VERSION:
                raise StoreError("schema_too_new")
            if version == SCHEMA_VERSION:
                return
            if version == 0:
                for statement in _SCHEMA_V2:
                    conn.execute(statement)
            elif version == 1:
                for statement in _MIGRATE_V1_TO_V2:
                    conn.execute(statement)
            conn.execute(f"PRAGMA user_version={SCHEMA_VERSION}")

    def _ensure_withdrawals(self) -> None:
        # 已安装的账本保留纯读快路（含只读账本）；需要安装/补列时，锁内必须再读版本。
        version = self._conn.execute("SELECT value FROM meta WHERE key='native_withdrawals_version'").fetchone()
        if version is not None:
            if version[0] != "1":
                return
            if "owner_pid_namespace" in {row[1] for row in self._conn.execute("PRAGMA table_info(native_withdrawals)")}:
                self._withdrawals_ready = True
                return
        with self._transaction() as conn:
            version = conn.execute("SELECT value FROM meta WHERE key='native_withdrawals_version'").fetchone()
            if version is not None and version[0] != "1":
                return  # 附表不可读不能阻断主账本；也不改未来版本的对象。
            conn.execute("""CREATE TABLE IF NOT EXISTS native_withdrawals (
                id TEXT PRIMARY KEY, task_id TEXT NOT NULL, attempt_id TEXT NOT NULL, attempt_seq INTEGER NOT NULL,
                thread_id TEXT NOT NULL, item_id TEXT NOT NULL, root_identity TEXT NOT NULL,
                owner_pid INTEGER NOT NULL, owner_start TEXT NOT NULL, owner_pid_namespace TEXT,
                created_at REAL NOT NULL, sending_at REAL, finished_at REAL,
                state TEXT NOT NULL, reason TEXT NOT NULL, server_version TEXT NOT NULL DEFAULT 'unknown'
            )""")
            columns = {row[1] for row in conn.execute("PRAGMA table_info(native_withdrawals)")}
            if "owner_pid_namespace" not in columns:
                conn.execute("ALTER TABLE native_withdrawals ADD COLUMN owner_pid_namespace TEXT")
            conn.execute("CREATE INDEX IF NOT EXISTS withdrawals_by_task ON native_withdrawals(task_id, created_at)")
            conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS withdrawals_active ON native_withdrawals(root_identity, thread_id, item_id)"
                         " WHERE state IN ('prepared','sending')")
            conn.execute("INSERT OR IGNORE INTO meta(key,value) VALUES ('native_withdrawals_version','1')")
        self._withdrawals_ready = True

    @property
    def withdrawals_readable(self) -> bool:
        version = self._conn.execute("SELECT value FROM meta WHERE key='native_withdrawals_version'").fetchone()
        return self._withdrawals_ready and version is not None and version[0] == "1"

    def _require_withdrawals(self) -> None:
        if not self.withdrawals_readable:
            raise StoreError("withdraw_store_unreadable")

    def _ensure_revision_objects(self) -> None:
        """幂等安装修订号触发器与账本标识：纯增量辅助对象，不提升 user_version，旧版程序照常读写。"""
        present = {row[0] for row in self._conn.execute("SELECT name FROM sqlite_master WHERE type = 'trigger'")}
        keys = {
            row[0]
            for row in self._conn.execute("SELECT key FROM meta WHERE key IN (?, ?)", (_REVISION_KEY, _LEDGER_ID_KEY))
        }
        triggers = tuple(item for item in _REVISION_TRIGGERS if item[1] != "native_withdrawals" or self.withdrawals_readable)
        if {name for name, _, _ in triggers} <= present and keys == {_REVISION_KEY, _LEDGER_ID_KEY}:
            return
        with self._transaction() as conn:
            # 已有值保持不变：重复安装不得重置修订号或更换账本标识
            conn.execute("INSERT OR IGNORE INTO meta (key, value) VALUES (?, '0')", (_REVISION_KEY,))
            conn.execute("INSERT OR IGNORE INTO meta (key, value) VALUES (?, ?)", (_LEDGER_ID_KEY, uuid.uuid4().hex))
            for name, table, operation in triggers:
                conn.execute(
                    f"CREATE TRIGGER IF NOT EXISTS {name} AFTER {operation} ON {table} BEGIN"
                    f" UPDATE meta SET value = CAST(value AS INTEGER) + 1 WHERE key = '{_REVISION_KEY}'; END"
                )

    def _ensure_indexes(self) -> None:
        """幂等补建查询索引：纯增量辅助对象，不提升 user_version，旧版程序照常读写；已存在时不写账本。

        补建失败（账本只读、磁盘满、刚好被别的连接占着写锁）不影响打开：索引只加速查询，下次打开再补（Opus 审计 P3-1）。
        """
        present = self._conn.execute(
            "SELECT 1 FROM sqlite_master WHERE type = 'index' AND name = ?", (_WINDOW_INDEX,)
        ).fetchone()
        if present is not None:
            return
        try:
            with self._transaction() as conn:
                conn.execute(f"CREATE INDEX IF NOT EXISTS {_WINDOW_INDEX} ON attempts (delivery, delivery_at)")
        except StoreError:
            if self._depth or self._conn.in_transaction:
                # 回滚也没成功：不能把仍占着事务的连接交出去，交给 Store.open 关闭并报错（Codex 复审 R02）
                raise
            return

    @contextmanager
    def _transaction(self) -> Iterator[sqlite3.Connection]:
        if self._depth:
            # 已在外层事务中：并入外层，由外层统一提交或回滚
            self._depth += 1
            try:
                yield self._conn
            finally:
                self._depth -= 1
            return
        try:
            self._conn.execute("BEGIN IMMEDIATE")
        except sqlite3.OperationalError as error:
            raise StoreError(_write_error_code(error, "store_busy")) from error
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
                raise StoreError(_write_error_code(error, "store_write_failed")) from error
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
                raise StoreError(_write_error_code(error, "store_write_failed")) from error

    def transaction(self) -> AbstractContextManager[sqlite3.Connection]:
        """把多次读写合并为一个原子事务；块内调用的公开写方法并入该事务。"""
        return self._transaction()

    def ledger_revision(self) -> tuple[str, int]:
        """账本标识与修订号；缺失时视为 (\"\", 0)。"""
        values = {
            row[0]: row[1]
            for row in self._conn.execute("SELECT key, value FROM meta WHERE key IN (?, ?)", (_REVISION_KEY, _LEDGER_ID_KEY))
        }
        raw = str(values.get(_REVISION_KEY, "0"))
        return str(values.get(_LEDGER_ID_KEY, "")), int(raw) if raw.isdigit() else 0

    @contextmanager
    def read_snapshot(self) -> Iterator[None]:
        """在同一个 SQLite 读事务里完成多次查询（WAL 快照，不抢写锁）；已在事务中时并入外层。"""
        if self._depth:
            yield
            return
        try:
            self._conn.execute("BEGIN DEFERRED")
        except sqlite3.OperationalError as error:
            raise StoreError("store_busy") from error
        self._depth = 1
        try:
            yield
        finally:
            self._depth = 0
            try:
                self._conn.execute("COMMIT")
            except sqlite3.Error:
                try:
                    self._conn.execute("ROLLBACK")
                except sqlite3.Error:
                    pass

    # ---- 任务与尝试 ----

    def create_task(
        self,
        *,
        title: str,
        flow: Flow,
        origin: EndpointRef | None,
        origin_class: str | None,
        reviewer: EndpointRef | None,
        target: EndpointRef,
        body: str,
        refs: list[dict[str, Any]],
        now: float,
        task_options: dict[str, Any] | None = None,
        attempt_options: dict[str, Any] | None = None,
    ) -> tuple[Task, Attempt]:
        """创建任务及第一次交接尝试（pending）；容量满时固定拒绝。"""
        check_body(body)
        with self._transaction() as conn:
            active = conn.execute(
                "SELECT COUNT(*) FROM tasks WHERE closed_at IS NULL AND accepted_at IS NULL"
            ).fetchone()[0]
            if active >= MAX_ACTIVE_TASKS:
                raise StoreError("capacity_active_tasks")
            self._check_pending_capacity(conn)
            task_id = new_id()
            conn.execute(
                "INSERT INTO tasks (id, created_at, updated_at, title, flow, origin, reviewer, options)"
                " VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    task_id,
                    now,
                    now,
                    title[:MAX_TITLE_CHARS],
                    flow.value,
                    origin.to_json() if origin else None,
                    reviewer.to_json() if reviewer else None,
                    _dump(task_options or {}),
                ),
            )
            attempt = self._insert_attempt(
                conn,
                task_id=task_id,
                seq=1,
                role=Role.HANDOFF,
                target=target,
                body=body,
                refs=refs,
                now=now,
                sender=origin,
                sender_class=origin_class,
                options=attempt_options or {},
            )
            self._event(conn, task_id, "created", now, attempt_seq=1, detail={"flow": flow.value})
            row = conn.execute("SELECT * FROM tasks WHERE id = ?", (task_id,)).fetchone()
        return _task_from_row(row), attempt

    def create_fyi(
        self,
        *,
        title: str,
        origin: EndpointRef | None,
        origin_class: str | None,
        target: EndpointRef,
        body: str,
        refs: list[dict[str, Any]],
        now: float,
        task_options: dict[str, Any] | None = None,
        attempt_options: dict[str, Any] | None = None,
    ) -> tuple[Task, Attempt]:
        """一句话告知（DESIGN §95.5.7）：同一写事务里建任务并立即关闭，唯一一条 seq 1 的 notice（noticeKind=fyi）。

        已关闭的任务不占进行中任务容量；全局 PENDING 上限照常计入。没有工作尝试，所以没有提醒、结束回执与验收。
        """
        check_body(body)
        with self._transaction() as conn:
            self._check_pending_capacity(conn)
            task_id = new_id()
            conn.execute(
                "INSERT INTO tasks (id, created_at, updated_at, title, flow, origin, reviewer, options,"
                " closed_at, close_reason) VALUES (?, ?, ?, ?, ?, ?, NULL, ?, ?, ?)",
                (
                    task_id,
                    now,
                    now,
                    title[:MAX_TITLE_CHARS],
                    Flow.HANDOFF.value,
                    origin.to_json() if origin else None,
                    _dump({**(task_options or {}), FYI_OPTION: True}),
                    now,
                    FYI_KIND,
                ),
            )
            attempt = self._insert_attempt(
                conn,
                task_id=task_id,
                seq=1,
                role=Role.NOTICE,
                target=target,
                body=body,
                refs=refs,
                now=now,
                sender=origin,
                sender_class=origin_class,
                options={**(attempt_options or {}), NOTICE_KIND_OPTION: FYI_KIND},
            )
            self._event(conn, task_id, "fyi_created", now, attempt_seq=1)
            row = conn.execute("SELECT * FROM tasks WHERE id = ?", (task_id,)).fetchone()
        return _task_from_row(row), attempt

    def add_attempt(
        self,
        task_id: str,
        *,
        role: Role,
        target: EndpointRef,
        body: str,
        refs: list[dict[str, Any]],
        now: float,
        sender: EndpointRef | None,
        sender_class: str | None,
        options: dict[str, Any] | None = None,
        event: str | None = None,
    ) -> Attempt:
        """为已有任务追加一次尝试（复核、结果通知或用户确认的重发）；event 缺省为 `<角色>_created`。"""
        check_body(body)
        with self._transaction() as conn:
            if conn.execute("SELECT 1 FROM tasks WHERE id = ?", (task_id,)).fetchone() is None:
                raise StoreError("task_not_found")
            seq = int(
                conn.execute(
                    "SELECT COALESCE(MAX(seq), 0) FROM attempts WHERE task_id = ?", (task_id,)
                ).fetchone()[0]
            ) + 1
            if seq > attempt_limit(role, options):
                raise StoreError("capacity_attempts")
            self._check_pending_capacity(conn)
            attempt = self._insert_attempt(
                conn,
                task_id=task_id,
                seq=seq,
                role=role,
                target=target,
                body=body,
                refs=refs,
                now=now,
                sender=sender,
                sender_class=sender_class,
                options=options or {},
            )
            self._touch(conn, task_id, now)
            self._event(conn, task_id, event or f"{role.value}_created", now, attempt_seq=seq)
        return attempt

    def _check_pending_capacity(self, conn: sqlite3.Connection) -> None:
        pending = conn.execute("SELECT COUNT(*) FROM attempts WHERE delivery = 'pending'").fetchone()[0]
        if pending >= MAX_PENDING_ATTEMPTS:
            raise StoreError("capacity_pending")

    def _insert_attempt(
        self,
        conn: sqlite3.Connection,
        *,
        task_id: str,
        seq: int,
        role: Role,
        target: EndpointRef,
        body: str,
        refs: list[dict[str, Any]],
        now: float,
        sender: EndpointRef | None,
        sender_class: str | None,
        options: dict[str, Any],
    ) -> Attempt:
        attempt = Attempt(
            id=new_id(),
            task_id=task_id,
            seq=seq,
            role=role,
            target=target,
            message_id=new_id(),
            created_at=now,
            body=body,
            refs=list(refs),
            work=Work.NONE if role is Role.NOTICE else Work.AWAITING_ACK,
            sender=sender,
            sender_class=sender_class,
            options=dict(options),
        )
        conn.execute(
            "INSERT INTO attempts (id, task_id, seq, role, target, message_id, created_at, body, refs,"
            " delivery, work, sender, sender_class, options) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                attempt.id,
                task_id,
                seq,
                role.value,
                target.to_json(),
                attempt.message_id,
                now,
                body,
                _dump(attempt.refs),
                Delivery.PENDING.value,
                attempt.work.value,
                sender.to_json() if sender else None,
                sender_class,
                _dump(attempt.options),
            ),
        )
        return attempt

    def get_task(self, task_id: str) -> Task | None:
        row = self._conn.execute("SELECT * FROM tasks WHERE id = ?", (task_id,)).fetchone()
        if row is None:
            return None
        try:
            return _task_from_row(row)
        except ValueError as error:
            raise StoreError("corrupt_record") from error

    def resolve_task(self, reference: str) -> Task:
        """按完整 ID 或唯一前缀查找任务。"""
        value = reference.strip().lower()
        if not is_id_prefix(value):
            raise StoreError("task_not_found")
        rows = self._conn.execute(
            "SELECT id FROM tasks WHERE id >= ? AND id < ? ORDER BY id LIMIT 2",
            (value, value + "g"),
        ).fetchall()
        if not rows:
            raise StoreError("task_not_found")
        if len(rows) > 1:
            raise StoreError("task_ambiguous")
        task = self.get_task(rows[0]["id"])
        if task is None:
            raise StoreError("task_not_found")
        return task

    def list_tasks(self, *, include_finished: bool = False, limit: int | None = 200) -> list[Task]:
        """列出任务（按创建时间升序）；单条坏记录跳过，不拖垮整个列表。

        limit 为 None 时不限条数：`ab tasks` 先取全部候选再筛选、留最新的若干条（DESIGN §93.1）。
        """
        where = "" if include_finished else " WHERE closed_at IS NULL AND accepted_at IS NULL"
        # SQLite 的 LIMIT -1 即不限
        rows = self._conn.execute(
            f"SELECT * FROM tasks{where} ORDER BY created_at, id LIMIT ?", (-1 if limit is None else limit,)
        ).fetchall()
        tasks: list[Task] = []
        for row in rows:
            try:
                tasks.append(_task_from_row(row))
            except ValueError:
                continue
        return tasks

    def followers(self, task_id: str) -> list[tuple[float, str]]:
        """以 task_id 为 `follows` 的本机任务（DESIGN §93.3）：(创建时间秒, 完整 ID)，按创建时间升序。

        坏 JSON 的 options 不参与比较（CASE 先判 json_valid），单条坏记录不让查询失败。
        """
        rows = self._conn.execute(
            "SELECT id, created_at FROM tasks WHERE CASE WHEN json_valid(options)"
            " THEN json_extract(options, '$.follows') END = ? ORDER BY created_at, id",
            (task_id,),
        ).fetchall()
        return [(float(row["created_at"]), str(row["id"])) for row in rows]

    def attempts(self, task_id: str) -> list[Attempt]:
        rows = self._conn.execute(
            "SELECT * FROM attempts WHERE task_id = ? ORDER BY seq", (task_id,)
        ).fetchall()
        attempts: list[Attempt] = []
        for row in rows:
            try:
                attempts.append(_attempt_from_row(row))
            except ValueError:
                continue
        return attempts

    def recent_deliveries(self, *, limit: int = 64) -> list[dict[str, Any]]:
        """最近可能已经到达对方的投递：消息 id、角色与接收端点（DESIGN §45.26）。

        判定「某一轮是不是 ab 发起的」靠对方开轮时回传的消息 id，不再靠时刻比对，所以这里不发布任何时间。
        取所有可能已经到达对方的状态：交出（written/queued/delivered）、结果不明（unknown）与对方暂存（held）；
        明确没送到的（pending/sending/cancelled/failed/denied/expired/refused）不发布。
        同时发布接收端点，消费者据此确认「这条消息确实是发给这个会话的」（审计 F05）。
        """
        return [item for _, item in self.recent_delivery_rows(limit=limit)]

    def recent_delivery_rows(self, *, limit: int = 64) -> list[tuple[float, dict[str, Any]]]:
        """同 recent_deliveries，另带内部投递时刻（只供与联邦投递合并排序，不进摘要 JSON；DESIGN §88.8）。"""
        states = [delivery.value for delivery in _MAY_HAVE_ARRIVED]
        marks = ",".join("?" for _ in states)
        rows = self._conn.execute(
            f"SELECT message_id, role, target, delivery_detail, options, delivery_at FROM attempts"
            f" WHERE delivery IN ({marks}) AND delivery_at IS NOT NULL ORDER BY delivery_at DESC LIMIT ?",
            (*states, int(limit)),
        ).fetchall()
        deliveries: list[tuple[float, dict[str, Any]]] = []
        for row in rows:
            message_id = row["message_id"]
            if not isinstance(message_id, str) or not _MESSAGE_RE.fullmatch(message_id):
                continue
            ref = EndpointRef.from_json(row["target"])
            if ref is None:
                continue
            # 接收方以实际投递端点为准：选定代际退出后会接续同会话的另一个 pane（§45.14 同一口径）
            delivered = _load_dict(row["delivery_detail"]).get("deliveredPane")
            pane = delivered if isinstance(delivered, str) else ref.pane
            if not isinstance(pane, str) or not _PANE_RE.fullmatch(pane):
                continue
            item: dict[str, Any] = {
                "messageId": message_id,
                "role": str(row["role"]),
                "pane": pane,
                "provider": ref.provider.value,
            }
            # 结束回执与补充消息单独标出 kind：扩展据此静默它们触发的那一轮，普通结果回执与提醒照常通知
            # （DESIGN §45.31.7、§95.5.3；kind 是可选开放字符串，键集与 summary v1 合同不变）
            kind = _load_dict(row["options"]).get(NOTICE_KIND_OPTION)
            if item["role"] == Role.NOTICE.value and kind in QUIET_NOTICE_KINDS:
                item["kind"] = kind
            deliveries.append((float(row["delivery_at"]), item))
        return deliveries

    def get_attempt(self, attempt_id: str) -> Attempt | None:
        row = self._conn.execute("SELECT * FROM attempts WHERE id = ?", (attempt_id,)).fetchone()
        if row is None:
            return None
        try:
            return _attempt_from_row(row)
        except ValueError as error:
            raise StoreError("corrupt_record") from error

    def find_attempt_by_provider_ref(self, provider_ref: str) -> Attempt | None:
        """按原生引用（Codex 队列项 ID、Claude msg_id）查找尝试，用于回执关联。"""
        row = self._conn.execute(
            "SELECT * FROM attempts WHERE provider_ref = ? ORDER BY created_at DESC LIMIT 1",
            (provider_ref,),
        ).fetchone()
        if row is None:
            return None
        try:
            return _attempt_from_row(row)
        except ValueError:
            return None

    def find_attempt_by_message_uuid(self, message_uuid: str) -> Attempt | None:
        """按桥自己生成的消息 ID（UUID 文本形式）查找尝试；外调结果不明时回执仍可关联。"""
        try:
            message_id = uuid.UUID(message_uuid).hex
        except ValueError:
            return None
        row = self._conn.execute("SELECT * FROM attempts WHERE message_id = ?", (message_id,)).fetchone()
        if row is None:
            return None
        try:
            return _attempt_from_row(row)
        except ValueError:
            return None

    def attempts_in(self, deliveries: Collection[Delivery], *, delivered_since: float | None = None) -> list[Attempt]:
        """按投递状态列出尝试（恢复、消费对账与排队分发用）。

        delivered_since：只取 delivery_at 为空或不早于该时刻的，在 SQL 里过滤，不把观察窗口外的历史行连正文读进内存。
        为空的保留，与原先 Python 侧「没有时间就不跳过」的判断一致（Codex 审计 F01）。
        """
        values = [delivery.value for delivery in deliveries]
        if not values:
            return []
        marks = ",".join("?" for _ in values)
        window = "" if delivered_since is None else " AND (delivery_at >= ? OR delivery_at IS NULL)"
        params: list[object] = [*values] if delivered_since is None else [*values, delivered_since]
        rows = self._conn.execute(
            f"SELECT * FROM attempts WHERE delivery IN ({marks}){window} ORDER BY created_at, seq, rowid", params
        ).fetchall()
        attempts: list[Attempt] = []
        for row in rows:
            try:
                attempts.append(_attempt_from_row(row))
            except ValueError:
                continue
        return attempts

    def has_recent_delivery(self, delivery: Delivery, *, after: float, unconsumed: bool = False) -> bool:
        """是否有 delivery_at 晚于 after 的该状态投递；unconsumed 时排除已离开 Codex 队列的。

        worker 每秒调用：走 (delivery, delivery_at) 索引，只判断存在，不构造记录。
        """
        consumed = " AND consumption != ?" if unconsumed else ""
        params: list[object] = [delivery.value, after]
        if unconsumed:
            params.append(Consumption.LEFT_QUEUE.value)
        row = self._conn.execute(
            f"SELECT EXISTS(SELECT 1 FROM attempts WHERE delivery = ? AND delivery_at > ?{consumed})", params
        ).fetchone()
        return bool(row[0])

    # ---- 投递状态 ----

    def begin_send(
        self,
        attempt_id: str,
        *,
        now: float,
        pid: int,
        start_ticks: str,
        provider_ref: str | None = None,
    ) -> bool:
        """pending→sending；任务暂停/结束或已被别的进程领取时返回 False（结束回执不受暂停/结束限制）。

        外调前已知的原生消息 ID（Claude msg_id）在此一并落盘，结果不明时回执仍能关联。
        """
        with self._transaction() as conn:
            row = conn.execute(
                "SELECT a.task_id, a.seq, a.role, a.options, t.control, t.closed_at, t.accepted_at FROM attempts a"
                " JOIN tasks t ON t.id = a.task_id WHERE a.id = ? AND a.delivery = 'pending'",
                (attempt_id,),
            ).fetchone()
            if row is None:
                return False
            # 结束回执本来就是任务结束后才生成的、告知的任务建立即关闭，暂停也不挡它们（DESIGN §45.31.5、§95.5.7）
            after_finish = row["role"] == Role.NOTICE.value and _load_dict(row["options"]).get(NOTICE_KIND_OPTION) in (
                CLOSURE_KIND, FYI_KIND)
            if not after_finish and (
                row["control"] != "active" or row["closed_at"] is not None or row["accepted_at"] is not None
            ):
                return False
            conn.execute(
                "UPDATE attempts SET delivery = 'sending', delivery_reason = NULL,"
                " delivery_detail = ?, delivery_at = ?, provider_ref = ? WHERE id = ?",
                (_dump({"senderPid": pid, "senderStart": start_ticks}), now, provider_ref, attempt_id),
            )
            self._touch(conn, row["task_id"], now)
            self._event(conn, row["task_id"], "sending", now, attempt_seq=row["seq"])
        return True

    def finish_send(
        self,
        attempt_id: str,
        *,
        delivery: Delivery,
        reason: str,
        provider_ref: str | None,
        detail: dict[str, Any],
        now: float,
        native_root: str | None = None,
    ) -> bool:
        """sending→原生结果；只接受仍处于 sending 的记录。"""
        with self._transaction() as conn:
            changed = self.transition_delivery(
                attempt_id, expected=(Delivery.SENDING,), new=delivery, reason=reason,
                now=now, provider_ref=provider_ref, detail=detail,
            )
            if changed and delivery is Delivery.QUEUED and isinstance(native_root, str) and re.fullmatch(r"[0-9a-f]{64}", native_root):
                row = conn.execute("SELECT options FROM attempts WHERE id=?", (attempt_id,)).fetchone()
                options = _load_dict(row[0])
                options["codexDataRoot"] = native_root
                conn.execute("UPDATE attempts SET options=? WHERE id=?", (_dump(options), attempt_id))
            return changed

    def prepare_withdrawal(self, task_id: str, seq: int, *, root_identity: str, now: float,
                           pid: int, start: str, again: bool = False) -> tuple[dict[str, Any], bool]:
        with self._transaction() as conn:
            self._require_withdrawals()
            attempt = next((item for item in self.attempts(task_id) if item.seq == seq), None)
            if attempt is None:
                raise StoreError("withdraw_attempt_missing")
            if (attempt.target.provider is not Provider.CODEX or attempt.role not in {Role.HANDOFF, Role.REVIEW}
                    or attempt.delivery is not Delivery.QUEUED
                    or native_id(attempt.target.native_id) is None or native_id(attempt.provider_ref) is None):
                raise StoreError("withdraw_ineligible")
            assert attempt.provider_ref is not None  # 上面的UUID验证已拒绝None
            if not root_identity or not attempt.options.get("codexDataRoot"):
                raise StoreError("withdraw_root_missing")
            if attempt.options.get("codexDataRoot") != root_identity:
                raise StoreError("withdraw_root_mismatch")
            rows = conn.execute("SELECT * FROM native_withdrawals WHERE attempt_id=? ORDER BY created_at DESC, rowid DESC",
                                (attempt.id,)).fetchall()
            active = conn.execute("SELECT * FROM native_withdrawals WHERE root_identity=? AND thread_id=? AND item_id=?"
                                  " AND state IN ('prepared','sending')",
                                  (root_identity, attempt.target.native_id.lower(), attempt.provider_ref.lower())).fetchone()
            previous = active or (rows[0] if rows else None)
            if previous is not None and (not again or previous["state"] not in {"unknown", "not_attempted", "refused"}):
                return dict(previous), False
            if len(rows) >= 16:
                raise StoreError("withdraw_limit")
            operation = new_id()
            conn.execute("INSERT INTO native_withdrawals(id,task_id,attempt_id,attempt_seq,thread_id,item_id,root_identity,"
                         "owner_pid,owner_start,owner_pid_namespace,created_at,state,reason) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
                         (operation, task_id, attempt.id, seq, attempt.target.native_id.lower(), attempt.provider_ref.lower(),
                          root_identity, pid, start, procfs.pid_namespace(), now, "prepared", "prepared"))
            return dict(conn.execute("SELECT * FROM native_withdrawals WHERE id=?", (operation,)).fetchone()), True

    def begin_withdrawal(self, operation: str, *, now: float, pid: int, start: str,
                         budget: float | None = None) -> None:
        timeout = int(self._conn.execute("PRAGMA busy_timeout").fetchone()[0])
        try:
            if budget is not None:
                self._conn.execute(f"PRAGMA busy_timeout={max(0, min(timeout, int(budget * 1000)))}")
            with self._transaction() as conn:
                self._require_withdrawals()
                changed = conn.execute("UPDATE native_withdrawals SET state='sending',reason='sending',sending_at=?"
                                       " WHERE id=? AND state='prepared' AND owner_pid=? AND owner_start=?",
                                       (now, operation, pid, start)).rowcount
                if changed != 1:
                    raise StoreError("withdraw_conflict")
        finally:
            self._conn.execute(f"PRAGMA busy_timeout={timeout}")

    def finish_withdrawal(self, operation: str, *, thread: str, item: str, state: str, reason: str,
                          version: str, now: float) -> None:
        if state not in {"deleted", "absent", "not_attempted", "refused", "unknown"}:
            raise StoreError("withdraw_invalid_result")
        with self._transaction() as conn:
            self._require_withdrawals()
            changed = conn.execute("UPDATE native_withdrawals SET state=?,reason=?,server_version=?,finished_at=?"
                                   " WHERE id=? AND thread_id=? AND item_id=? AND state IN ('prepared','sending')",
                                   (state, reason, version, now, operation, thread, item)).rowcount
            if changed != 1:
                raise StoreError("withdraw_record_conflict")

    def recover_withdrawals(self, *, now: float, proc_root: Path = procfs.DEFAULT_PROC) -> None:
        self._require_withdrawals()
        rows = self._conn.execute("SELECT id,owner_pid,owner_start,owner_pid_namespace,state,created_at FROM native_withdrawals"
                                  " WHERE state IN ('prepared','sending')").fetchall()
        for row in rows:
            timed_out = now - row["created_at"] > WITHDRAWAL_RECOVERY_SECONDS
            if not timed_out and self._withdrawal_owner_status(row, proc_root) != "gone":
                continue
            state = "unknown" if row["state"] == "sending" else "not_attempted"
            reason = "owner_timeout" if timed_out else "owner_gone"
            with self._transaction() as conn:
                self._require_withdrawals()
                conn.execute("UPDATE native_withdrawals SET state=?,reason=?,finished_at=? WHERE id=? AND state=?",
                             (state, reason, now, row["id"], row["state"]))

    @staticmethod
    def _withdrawal_owner_status(row: sqlite3.Row, proc_root: Path) -> str:
        if row["state"] not in {"prepared", "sending"}:
            return "finished"
        if get_platform().name == 'windows':
            state = procfs.windows_presence(row['owner_pid'], row['owner_start'])
            return {Presence.CURRENT: 'alive', Presence.EXITED: 'gone', Presence.UNKNOWN: 'identity_unverified'}[state]
        namespace = row["owner_pid_namespace"]
        if namespace is not None and namespace != procfs.pid_namespace(proc_root):
            return "namespace_unverified"
        info = procfs.read_process(row["owner_pid"], proc_root)
        return "alive" if info is not None and info.start_ticks == row["owner_start"] else "gone"

    def withdrawals(self, task_id: str, *, proc_root: Path = procfs.DEFAULT_PROC) -> list[dict[str, Any]]:
        # 展示只取安全列，root/进程/原始请求不离开业务层。
        if not self.withdrawals_readable:
            return []
        return [{"id": row["id"], "attemptSeq": row["attempt_seq"], "state": row["state"], "reason": row["reason"],
                 "serverVersion": row["server_version"], "createdAt": row["created_at"],
                 "sendingAt": row["sending_at"], "finishedAt": row["finished_at"],
                 "ownerStatus": self._withdrawal_owner_status(row, proc_root)} for row in self._conn.execute(
            "SELECT id,attempt_seq,state,reason,server_version,created_at,sending_at,finished_at,"
            "owner_pid,owner_start,owner_pid_namespace FROM native_withdrawals"
            " WHERE task_id=? ORDER BY created_at,rowid", (task_id,))]

    def transition_delivery(
        self,
        attempt_id: str,
        *,
        expected: Collection[Delivery],
        new: Delivery,
        reason: str | None,
        now: float,
        provider_ref: str | None = None,
        detail: dict[str, Any] | None = None,
    ) -> bool:
        """条件迁移投递状态；当前状态不在 expected 中时不修改。"""
        values = [delivery.value for delivery in expected]
        marks = ",".join("?" for _ in values)
        with self._transaction() as conn:
            row = conn.execute(
                f"SELECT task_id, seq, provider_ref, delivery_detail FROM attempts"
                f" WHERE id = ? AND delivery IN ({marks})",
                (attempt_id, *values),
            ).fetchone()
            if row is None:
                return False
            merged = _load_dict(row["delivery_detail"])
            if detail:
                merged.update(detail)
            conn.execute(
                "UPDATE attempts SET delivery = ?, delivery_reason = ?, delivery_at = ?,"
                " provider_ref = ?, delivery_detail = ? WHERE id = ?",
                (
                    new.value,
                    reason,
                    now,
                    provider_ref if provider_ref is not None else row["provider_ref"],
                    _dump(merged),
                    attempt_id,
                ),
            )
            self._touch(conn, row["task_id"], now)
            self._event(
                conn,
                row["task_id"],
                f"delivery_{new.value}",
                now,
                attempt_seq=row["seq"],
                detail={"reason": reason} if reason else None,
            )
        return True

    def set_consumption(self, attempt_id: str, consumption: Consumption, *, now: float) -> bool:
        """记录原生队列消费证据；只在值变化时写时间线。"""
        with self._transaction() as conn:
            row = conn.execute(
                "SELECT task_id, seq, consumption, delivery_detail FROM attempts WHERE id = ?", (attempt_id,)
            ).fetchone()
            if row is None or row["consumption"] == consumption.value:
                return False
            conn.execute("UPDATE attempts SET consumption = ? WHERE id = ?", (consumption.value, attempt_id))
            self._touch(conn, row["task_id"], now)
            self._event(conn, row["task_id"], f"consumption_{consumption.value}", now, attempt_seq=row["seq"])
        return True

    def set_work(
        self,
        attempt_id: str,
        *,
        work: Work,
        result: dict[str, Any] | None,
        now: float,
        event: str,
        detail: dict[str, Any] | None = None,
    ) -> None:
        """记录归属已核验的工作进展或结果。"""
        with self._transaction() as conn:
            row = conn.execute("SELECT task_id, seq FROM attempts WHERE id = ?", (attempt_id,)).fetchone()
            if row is None:
                raise StoreError("attempt_not_found")
            if result is None:
                conn.execute(
                    "UPDATE attempts SET work = ?, work_at = ? WHERE id = ?", (work.value, now, attempt_id)
                )
            else:
                conn.execute(
                    "UPDATE attempts SET work = ?, work_at = ?, result = ? WHERE id = ?",
                    (work.value, now, _dump(result), attempt_id),
                )
            self._touch(conn, row["task_id"], now)
            self._event(conn, row["task_id"], event, now, attempt_seq=row["seq"], detail=detail)

    def update_task(self, task_id: str, *, now: float, event: str, **fields: object) -> None:
        """更新任务控制/验收字段（白名单）。"""
        unknown = set(fields) - _TASK_FIELDS
        if unknown:
            raise ValueError(f"unsupported task fields: {sorted(unknown)}")
        with self._transaction() as conn:
            if conn.execute("SELECT 1 FROM tasks WHERE id = ?", (task_id,)).fetchone() is None:
                raise StoreError("task_not_found")
            if fields:
                assignments = ", ".join(f"{name} = ?" for name in fields)
                conn.execute(
                    f"UPDATE tasks SET {assignments}, updated_at = ? WHERE id = ?",
                    (*fields.values(), now, task_id),
                )
            else:
                self._touch(conn, task_id, now)
            self._event(conn, task_id, event, now)

    def add_event(
        self,
        task_id: str,
        kind: str,
        *,
        now: float,
        attempt_seq: int | None = None,
        detail: dict[str, Any] | None = None,
    ) -> None:
        with self._transaction() as conn:
            self._event(conn, task_id, kind, now, attempt_seq=attempt_seq, detail=detail)

    def events(self, task_id: str, *, limit: int = 50) -> list[dict[str, Any]]:
        rows = self._conn.execute(
            "SELECT attempt_seq, at, kind, detail FROM events WHERE task_id = ? ORDER BY id DESC LIMIT ?",
            (task_id, limit),
        ).fetchall()
        return [
            {"attemptSeq": row["attempt_seq"], "at": row["at"], "kind": row["kind"], "detail": _load_dict(row["detail"])}
            for row in reversed(rows)
        ]

    def _touch(self, conn: sqlite3.Connection, task_id: str, now: float) -> None:
        conn.execute("UPDATE tasks SET updated_at = ? WHERE id = ?", (now, task_id))

    def _event(
        self,
        conn: sqlite3.Connection,
        task_id: str,
        kind: str,
        now: float,
        *,
        attempt_seq: int | None = None,
        detail: dict[str, Any] | None = None,
    ) -> None:
        conn.execute(
            "INSERT INTO events (task_id, attempt_seq, at, kind, detail) VALUES (?, ?, ?, ?, ?)",
            (task_id, attempt_seq, now, kind, _dump(detail or {})),
        )
        conn.execute(
            "DELETE FROM events WHERE task_id = ? AND id NOT IN"
            " (SELECT id FROM events WHERE task_id = ? ORDER BY id DESC LIMIT ?)",
            (task_id, task_id, MAX_EVENTS_PER_TASK),
        )

    # ---- 恢复、归档与保留 ----

    def recover_interrupted(self, *, now: float, proc_root: Path = procfs.DEFAULT_PROC) -> int:
        """发送进程已不在的 sending 记录改为 unknown；Windows另有超预算兜底。

        只应由持有单实例锁的 worker 调用：其他进程（例如在 PID 命名空间里）可能看不到 worker。
        """
        recovered = 0
        for attempt in self.attempts_in((Delivery.SENDING,)):
            reason = "interrupted_during_send"
            pid = attempt.delivery_detail.get("senderPid")
            start = attempt.delivery_detail.get("senderStart")
            if get_platform().name == 'windows':
                presence = (procfs.windows_presence(pid, start)
                            if isinstance(pid, int) and isinstance(start, str) else Presence.UNKNOWN)
                if presence is not Presence.EXITED:
                    started = attempt.delivery_at if attempt.delivery_at is not None else attempt.created_at
                    if now - started <= WINDOWS_SENDING_RECOVERY_SECONDS:
                        continue
                    reason = "codex_queue_timeout"
            elif isinstance(pid, int) and isinstance(start, str) and procfs.is_same_generation(pid, start, proc_root):
                continue
            if self.transition_delivery(
                attempt.id,
                expected=(Delivery.SENDING,),
                new=Delivery.UNKNOWN,
                reason=reason,
                now=now,
            ):
                recovered += 1
        return recovered

    def note_archived_risk(self) -> None:
        """归档仍可能在原生侧执行的任务时，累加有界风险计数（不随历史轮转清零）。"""
        with self._transaction() as conn:
            row = conn.execute("SELECT value FROM meta WHERE key = ?", (_ARCHIVED_RISK_KEY,)).fetchone()
            count = int(row["value"]) if row is not None and str(row["value"]).isdigit() else 0
            conn.execute(
                "INSERT INTO meta (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                (_ARCHIVED_RISK_KEY, str(min(count + 1, 9999))),
            )

    def recent_codex_details(self, *, limit: int) -> list[dict[str, Any]]:
        """最近最多 limit 条 **Codex 目标**尝试的 delivery_detail，供 doctor 统计投递证据（DESIGN §45.44 二.6）。

        只投影 target 与 delivery_detail，不读 body/result。按 created_at 倒序、id 为稳定次键；
        `json_extract` 遇到坏 JSON 会让整条查询报错，所以先用 CASE 判 json_valid，Python 侧再按 EndpointRef 复核一次。
        """
        rows = self._conn.execute(
            "SELECT target, delivery_detail FROM attempts"
            " WHERE CASE WHEN json_valid(target) THEN json_extract(target, '$.provider') END = ?"
            " ORDER BY created_at DESC, id DESC LIMIT ?",
            (Provider.CODEX.value, int(limit)),
        ).fetchall()
        details: list[dict[str, Any]] = []
        for row in rows:
            ref = EndpointRef.from_json(row["target"])
            if ref is not None and ref.provider is Provider.CODEX:
                details.append(_load_dict(row["delivery_detail"]))
        return details

    def archived_risk_count(self) -> int:
        row = self._conn.execute("SELECT value FROM meta WHERE key = ?", (_ARCHIVED_RISK_KEY,)).fetchone()
        return int(row["value"]) if row is not None and str(row["value"]).isdigit() else 0

    def prune(self, *, now: float) -> int:
        """删除超过保留期或数量上限的已结束任务；未结束任务从不自动删除。"""
        cutoff = now - FINISHED_RETENTION_SECONDS
        with self._transaction() as conn:
            expired = conn.execute(
                "DELETE FROM tasks WHERE COALESCE(closed_at, accepted_at) IS NOT NULL"
                " AND COALESCE(closed_at, accepted_at) < ?",
                (cutoff,),
            ).rowcount
            overflow = conn.execute(
                "DELETE FROM tasks WHERE id IN (SELECT id FROM tasks"
                " WHERE COALESCE(closed_at, accepted_at) IS NOT NULL"
                " ORDER BY COALESCE(closed_at, accepted_at) DESC LIMIT -1 OFFSET ?)",
                (MAX_FINISHED_TASKS,),
            ).rowcount
            if self.withdrawals_readable:
                conn.execute("DELETE FROM native_withdrawals WHERE state NOT IN ('prepared','sending','unknown')"
                             " AND task_id NOT IN (SELECT id FROM tasks)")
        return int(expired) + int(overflow)
