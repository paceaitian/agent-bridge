"""P5 设备联邦内容预算（DESIGN §88.11「设备联邦内容预算」/T15）：新附件操作前的容量预检。

占用 = 冻结副本 staging + 私有 part + 交付叶 + 库里未清理的信封字节。只在「源端冻结新附件」与「收端下载新附件」前核一次：
源端超出写前拒绝（任务/报告都还没写），收端超出不 ACK、留在 receiving 等 hub 重推。没有附件的信封与报告事实
不受预算影响，已落账的结果不因空间回滚。不做跨进程预留：并发写可以短暂越过预检值，实际写失败照常不发 L2。
"""

from __future__ import annotations

import os
import stat
from dataclasses import dataclass
from pathlib import Path

from .attachments import AttachmentError, is_link_or_reparse
from .fedstore import FederatedStore
from .retention import RetentionPaths

STORAGE_FULL = "device_storage_full"  # 与 attachments.freeze 的写前拒绝同一个码
DEFERRED_META = "budgetDeferredAt"  # 收端最近一次因预算延后下载的时刻；预检通过后清空


@dataclass(frozen=True)
class Usage:
    """联邦内容占用（字节）；只计大小，不列名称或路径。"""

    file_bytes: int
    files: int
    partial_bytes: int
    envelope_bytes: int

    @property
    def total(self) -> int:
        return self.file_bytes + self.partial_bytes + self.envelope_bytes


def _tree_bytes(top: Path) -> tuple[int, int]:
    """目录下普通文件的 (字节, 个数)：不跟随链接/重解析点（含 top 本身），读不到的子项跳过。"""
    total = count = 0
    try:
        info = os.lstat(top)
    except OSError:
        return 0, 0
    if is_link_or_reparse(info) or not stat.S_ISDIR(info.st_mode):
        return 0, 0  # staging/part/交付根本身是链接：指向的不是本包内容，不计（与留存回收的自有根口径一致）
    pending = [top]
    while pending:
        folder = pending.pop()
        try:
            entries = list(os.scandir(folder))
        except OSError:
            continue
        for entry in entries:
            try:
                info = entry.stat(follow_symlinks=False)
            except OSError:
                continue
            if is_link_or_reparse(info):
                continue
            if stat.S_ISDIR(info.st_mode):
                pending.append(Path(entry.path))
            elif stat.S_ISREG(info.st_mode):
                total += info.st_size
                count += 1
    return total, count


def usage(store: FederatedStore, paths: RetentionPaths) -> Usage:
    """当前联邦内容占用：staging 与交付叶算文件，part 单列，加上未清理（未成墓碑）的发件/收件信封。"""
    staged, staged_files = _tree_bytes(paths.staging)
    try:
        delivered, delivered_files = _tree_bytes(paths.delivery_base(store.ledger_instance_id()))
    except AttachmentError:
        delivered = delivered_files = 0  # Windows 缺 LocalAppData：没有交付位置，也就没有交付叶
    partial, _ = _tree_bytes(paths.parts)
    row = store.connection.execute(
        "SELECT (SELECT COALESCE(SUM(LENGTH(CAST(envelope_json AS BLOB))),0) FROM fed_outbox),"
        " (SELECT COALESCE(SUM(LENGTH(CAST(envelope_json AS BLOB))),0) FROM fed_inbox)").fetchone()
    return Usage(staged + delivered, staged_files + delivered_files, partial, int(row[0]) + int(row[1]))


def available(store: FederatedStore, paths: RetentionPaths, budget: int) -> int:
    """预算剩余字节（可为负）：新附件操作前与本次要写入的字节数比较。"""
    return budget - usage(store, paths).total
