"""P5 设备侧留存回收（DESIGN §88.3 附件留存、§88.4 内容留存）：任务结束且最后引用满 30 天后清正文与附件。

只删本包自有路径（fed-staging、私有 part 目录、交付根）里的文件；冻结后没写进库的孤儿副本超过 24 小时也清。先在一个事务里把内容改成墓碑、附件行改成
expired（保留 SHA/size/transfer），文件第二步在引用重查后删：崩溃只会留下待删文件、下轮再删，不会出现库里
ready 而文件已删。活任务、未结发件/收件/native、待裁决报告都让整个任务延期；镜像没收到终态就宁可留着。
去重与决定墓碑（operations/inbox/outbox/decisions 的 ID 与 hash）不清，迟到重放仍按重复处理、不再 native。
"""

from __future__ import annotations

import json
import os
import stat
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

from .attachments import is_link_or_reparse
from .fedstore import FederatedStore, load_dict

DAY_MS = 86_400_000
RETENTION_MS = 30 * DAY_MS  # 终态确认且最后引用满 30 天
ORPHAN_PART_MS = DAY_MS  # 崩溃遗留的私有 part 至少留 24 小时（进行中的复制不会这么久）
STAGING_GRACE_MS = DAY_MS  # 刚被重新冻结复用的 staging 副本不删，挡住「冻结后、建任务前」的并发
SWEEP_TASKS = 200  # 一轮最多检查的结束任务数
_UNRESOLVED_OUTBOX = ("ready", "submitting", "accepted")
_UNRESOLVED_INBOX = ("receiving", "ready")
_REPORT_CONTENT_KEYS = ("note", "refs", "commit")


class RetentionPaths(Protocol):
    """回收只需要的自有位置（RelayPaths 满足）：两个自有根，以及其下的 staging、part 与交付目录。"""

    @property
    def state_root(self) -> Path: ...

    @property
    def staging(self) -> Path: ...

    @property
    def parts(self) -> Path: ...

    @property
    def delivery_owner(self) -> Path: ...

    def delivery_base(self, instance_id: str) -> Path: ...


def _plain_dirs(owner: Path, target: Path) -> bool:
    """target 在自有根 owner 之下，且 owner 以下到 target 的每一级都是真实目录（不是链接/重解析点）。

    只信任配置给出的自有根本身；其下任何一级被换成链接（迁移、恢复、junction）都不进去删，避免删到别处的文件。
    """
    try:
        relative = target.relative_to(owner)
    except ValueError:
        return False
    current = owner
    for part in relative.parts:
        if part in (".", ".."):
            return False
        current = current / part
        try:
            info = os.lstat(current)
        except OSError:
            return False
        if is_link_or_reparse(info) or not stat.S_ISDIR(info.st_mode):
            return False
    return True


@dataclass
class SweepResult:
    """一轮回收的计数：parts=孤儿 part、compacted=清成墓碑的任务、deferred=到期但有未结引用、files=删掉的文件。"""

    parts: int = 0
    compacted: int = 0
    deferred: int = 0
    files: int = 0


def sweep(store: FederatedStore, paths: RetentionPaths, *, now: int, wall_ms: int | None = None) -> SweepResult:
    """跑一轮回收。now 是账本时钟（判定任务到期）；wall_ms 是真实时间（只用来比文件 mtime）。"""
    wall = int(time.time() * 1000) if wall_ms is None else wall_ms
    result = SweepResult()
    result.parts = _sweep_parts(paths, wall)
    candidates = _finished_candidates(store)
    for authority_device, task_id in candidates:
        outcome = _compact_task(store, authority_device, task_id, now=now)
        if outcome == "compacted":
            result.compacted += 1
        elif outcome == "deferred":
            result.deferred += 1
    if candidates:
        # 下一轮从这里接着往后检查：长期延期的任务不会一直占住前 SWEEP_TASKS 个位置、饿死后面的到期任务
        store.set_meta("retentionCursor", "\n".join(candidates[-1]))
    result.files = _reclaim_files(store, paths, wall) + _sweep_staging_orphans(store, paths, wall)
    return result


def _sweep_parts(paths: RetentionPaths, wall: int) -> int:
    """只删自有目录里超过 24 小时的普通 `.part` 文件；不跟随链接、不进子目录。"""
    removed = 0
    for directory in (paths.parts, paths.staging):
        if not _plain_dirs(paths.state_root, directory):
            continue
        try:
            entries = list(os.scandir(directory))
        except FileNotFoundError:
            continue
        for entry in entries:
            if not entry.name.endswith(".part"):
                continue
            try:
                info = entry.stat(follow_symlinks=False)
                if not stat.S_ISREG(info.st_mode) or info.st_mtime_ns // 1_000_000 > wall - ORPHAN_PART_MS:
                    continue
                os.unlink(entry.path)
                removed += 1
            except FileNotFoundError:
                continue
    return removed


_CANDIDATE_SQL = (
    "SELECT authority_device, task_id FROM fed_tasks"
    " WHERE json_extract(state_json,'$.contentExpiredAt') IS NULL"
    " AND (json_extract(state_json,'$.acceptedAt') IS NOT NULL"
    "      OR json_extract(state_json,'$.closedAt') IS NOT NULL)")


def _finished_candidates(store: FederatedStore) -> list[tuple[str, str]]:
    """本轮要检查的已结束、未清内容的任务：从上轮的游标之后取，不够再从头补，最多 SWEEP_TASKS 个（轮转）。"""
    cursor = (store.meta("retentionCursor") or "").split("\n")
    after = (cursor[0], cursor[1]) if len(cursor) == 2 else ("", "")
    with store.read_snapshot():
        conn = store.connection
        rows = conn.execute(_CANDIDATE_SQL + " AND (authority_device, task_id) > (?, ?)"
                            " ORDER BY authority_device, task_id LIMIT ?", (*after, SWEEP_TASKS)).fetchall()
        if len(rows) < SWEEP_TASKS:
            rows += conn.execute(_CANDIDATE_SQL + " AND (authority_device, task_id) <= (?, ?)"
                                 " ORDER BY authority_device, task_id LIMIT ?",
                                 (*after, SWEEP_TASKS - len(rows))).fetchall()
    return [(str(row[0]), str(row[1])) for row in rows]


def _last_reference(conn: Any, authority_device: str, task_id: str, state: dict[str, Any]) -> int | None:
    """终态确认与最后一次内容引用中较晚者；终态时间缺失/坏数据返回 None（不回收）。"""
    terminal = [value for value in (state.get("acceptedAt"), state.get("closedAt")) if isinstance(value, int)]
    if not terminal:
        return None
    marks = [max(terminal)]
    if isinstance(state.get("updatedAt"), int):
        marks.append(int(state["updatedAt"]))
    for sql in (
        "SELECT MAX(at) FROM fed_events WHERE authority_device=? AND task_id=?",
        "SELECT MAX(last_ref_at) FROM fed_attachments WHERE authority_device=? AND task_id=?",
        "SELECT MAX(received_at) FROM fed_inbox WHERE json_extract(envelope_json,'$.authorityDeviceId')=?"
        " AND json_extract(envelope_json,'$.taskId')=?",
    ):
        value = conn.execute(sql, (authority_device, task_id)).fetchone()[0]
        if isinstance(value, int):
            marks.append(value)
    return max(marks)


def _unresolved(conn: Any, authority_device: str, task_id: str) -> bool:
    """还有重传/领取/裁决需要的内容：未结发件、未应用收件、prepared/intent、没有决定的报告。"""
    checks: tuple[tuple[str, tuple[object, ...]], ...] = (
        ("SELECT 1 FROM fed_outbox WHERE state IN (?,?,?) AND json_extract(envelope_json,'$.authorityDeviceId')=?"
         " AND json_extract(envelope_json,'$.taskId')=? LIMIT 1", (*_UNRESOLVED_OUTBOX, authority_device, task_id)),
        ("SELECT 1 FROM fed_inbox WHERE apply_state IN (?,?) AND json_extract(envelope_json,'$.authorityDeviceId')=?"
         " AND json_extract(envelope_json,'$.taskId')=? LIMIT 1", (*_UNRESOLVED_INBOX, authority_device, task_id)),
        ("SELECT 1 FROM fed_native_sends n JOIN fed_attempts a ON a.msg_id=n.msg_id"
         " WHERE a.authority_device=? AND a.task_id=? AND n.state IN ('prepared','intent') LIMIT 1",
         (authority_device, task_id)),
        ("SELECT 1 FROM fed_reports r LEFT JOIN fed_report_decisions d"
         " ON d.reporter_device=r.reporter_device AND d.report_operation_id=r.operation_id"
         " WHERE r.authority_device=? AND r.task_id=? AND d.decision IS NULL LIMIT 1", (authority_device, task_id)),
    )
    return any(conn.execute(sql, params).fetchone() is not None for sql, params in checks)


def _compact_task(store: FederatedStore, authority_device: str, task_id: str, *, now: int) -> str:
    """锁内复读到期与延期条件，再一次性把正文/结果/路径清成墓碑。返回 compacted/deferred/not_due。"""
    with store.transaction() as conn:
        row = conn.execute("SELECT state_json FROM fed_tasks WHERE authority_device=? AND task_id=?",
                           (authority_device, task_id)).fetchone()
        if row is None:
            return "not_due"
        state = load_dict(row[0])
        if state.get("contentExpiredAt") is not None:
            return "not_due"
        last = _last_reference(conn, authority_device, task_id, state)
        if last is None or now - last < RETENTION_MS:
            return "not_due"
        if _unresolved(conn, authority_device, task_id):
            return "deferred"
        for msg_id, raw in conn.execute(
                "SELECT msg_id, effective_work_json FROM fed_attempts WHERE authority_device=? AND task_id=?",
                (authority_device, task_id)).fetchall():
            conn.execute("UPDATE fed_attempts SET body='', refs_json='[]', effective_work_json=? WHERE msg_id=?",
                         (json.dumps(_strip_work(load_dict(raw)), ensure_ascii=False), msg_id))
        for operation_id, reporter, raw in conn.execute(
                "SELECT operation_id, reporter_device, report_json FROM fed_reports"
                " WHERE authority_device=? AND task_id=?", (authority_device, task_id)).fetchall():
            report = {key: value for key, value in load_dict(raw).items() if key not in _REPORT_CONTENT_KEYS}
            conn.execute("UPDATE fed_reports SET report_json=? WHERE reporter_device=? AND operation_id=?",
                         (json.dumps({**report, "contentExpired": True}, ensure_ascii=False), reporter, operation_id))
        for msg_id, raw in conn.execute(
                "SELECT msg_id, envelope_json FROM fed_outbox WHERE json_extract(envelope_json,'$.authorityDeviceId')=?"
                " AND json_extract(envelope_json,'$.taskId')=?", (authority_device, task_id)).fetchall():
            conn.execute("UPDATE fed_outbox SET envelope_json=? WHERE msg_id=?",
                         (json.dumps(_envelope_tombstone(load_dict(raw)), ensure_ascii=False), msg_id))
        conn.execute("UPDATE fed_inbox SET envelope_json=NULL WHERE json_extract(envelope_json,'$.authorityDeviceId')=?"
                     " AND json_extract(envelope_json,'$.taskId')=?", (authority_device, task_id))
        # 附件行：先改 expired 并清原始路径；交付叶/冻结副本留给第二步按引用重查后删
        conn.execute("UPDATE fed_attachments SET state='expired', original_path='', resolved_path='', retain_until=NULL"
                     " WHERE authority_device=? AND task_id=? AND state!='expired'", (authority_device, task_id))
        state["contentExpiredAt"] = now
        conn.execute("UPDATE fed_tasks SET state_json=? WHERE authority_device=? AND task_id=?",
                     (json.dumps(state, ensure_ascii=False), authority_device, task_id))
        store.add_event(authority_device, task_id, "content_expired", now=now)
    return "compacted"


def _strip_work(work: dict[str, Any]) -> dict[str, Any]:
    """保留工作状态与时间，结果只剩来源/时间与「已过留存期」标记。"""
    result = work.get("result")
    if isinstance(result, dict):
        kept = {key: result[key] for key in ("reportedAt", "source") if key in result}
        work = {**work, "result": {**kept, "contentExpired": True}}
    return work


def _envelope_tombstone(envelope: dict[str, Any]) -> dict[str, Any]:
    keys = ("msg_id", "operationId", "kind", "authorityDeviceId", "taskId", "targetDeviceId", "createdAt", "expiresAt")
    return {**{key: envelope[key] for key in keys if key in envelope}, "contentExpired": True}


def _reclaim_files(store: FederatedStore, paths: RetentionPaths, wall: int) -> int:
    """第二步：已 expired 行的交付叶逐个重查引用后删，处理完记 retain_until 免得反复扫描；删失败下轮重试。

    冻结副本 `<sha>.blob` 按 SHA 共享，统一由 `_sweep_staging_orphans` 按「没有未过期行引用」回收。
    """
    removed = 0
    with store.read_snapshot():
        rows = store.connection.execute(
            "SELECT msg_id, ref_index, location, local_relpath, file_identity_json FROM fed_attachments"
            " WHERE state='expired' AND transfer='blob' AND retain_until IS NULL LIMIT ?", (SWEEP_TASKS,)).fetchall()
    instance = store.ledger_instance_id()
    for msg_id, ref_index, location, relpath, identity_json in rows:
        with store.transaction() as conn:
            done = True
            if location == "delivery" and relpath:
                shared = conn.execute("SELECT 1 FROM fed_attachments WHERE state!='expired' AND location='delivery'"
                                      " AND local_relpath=? LIMIT 1", (relpath,)).fetchone()
                leaf = paths.delivery_base(instance) / str(relpath)
                if shared is None and _plain_dirs(paths.delivery_owner, leaf.parent):
                    # 只删落地时记下身份的那个叶：被替换/挪动过的同名文件不碰
                    outcome = _unlink_owned(leaf, expected=load_dict(identity_json))
                    removed += outcome == "removed"
                    done = outcome != "error"
            if done:
                conn.execute("UPDATE fed_attachments SET location=NULL, local_relpath=NULL, file_identity_json=NULL,"
                             " retain_until=? WHERE msg_id=? AND ref_index=?", (wall, msg_id, ref_index))
    return removed


def _sweep_staging_orphans(store: FederatedStore, paths: RetentionPaths, wall: int) -> int:
    """`<sha>.blob` 没有任何未过期行引用（任务已过留存期、或冻结后没能写库）且超过 24 小时才删。

    引用重查与删除在同一个写事务里，和建任务写 manifest 互斥；刚冻结/刚复用的副本有 24 小时 mtime 保护。
    """
    removed = 0
    if not _plain_dirs(paths.state_root, paths.staging):
        return 0
    try:
        entries = list(os.scandir(paths.staging))
    except FileNotFoundError:
        return 0
    for entry in entries:
        sha = entry.name[: -len(".blob")] if entry.name.endswith(".blob") else ""
        if len(sha) != 64 or any(char not in "0123456789abcdef" for char in sha):
            continue
        with store.transaction() as conn:
            live = conn.execute("SELECT 1 FROM fed_attachments WHERE state!='expired' AND sha256=? LIMIT 1",
                                (sha,)).fetchone()
            if live is None:
                outcome = _unlink_owned(Path(entry.path), grace_before=wall - STAGING_GRACE_MS)
                removed += outcome == "removed"
    return removed


def _unlink_owned(path: Path, *, grace_before: int | None = None, expected: dict[str, Any] | None = None) -> str:
    """删一个自有普通文件；不存在算已删，链接/目录不碰，太新的 staging 副本留着，身份与落地记录不符的留着。

    返回 removed/absent/kept/error。
    """
    try:
        info = path.lstat()
    except FileNotFoundError:
        return "absent"
    except OSError:
        return "error"
    if is_link_or_reparse(info) or not stat.S_ISREG(info.st_mode):
        return "kept"
    # dev/ino 之外再比 size/mtime：ext4 会立刻复用刚释放的 inode，被改写过的叶也按「已不是落地那份」留着
    if expected and any(expected.get(key) != value for key, value in (
            ("dev", int(info.st_dev)), ("ino", int(info.st_ino)), ("size", int(info.st_size)),
            ("mtimeNs", int(info.st_mtime_ns)))):
        return "kept"
    if grace_before is not None and info.st_mtime_ns // 1_000_000 > grace_before:
        return "kept"
    try:
        os.unlink(path)
    except FileNotFoundError:
        return "absent"
    except OSError:
        return "error"
    return "removed"
