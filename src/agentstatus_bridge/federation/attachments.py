"""联邦附件（DESIGN §88.3）：源端点名文件的解析/冻结/超限降级、交付文件名清洗与接收端落地。

源端：只读调用方明确点名的文件，允许跟随 symlink/junction/OneDrive 占位，最终必须是普通文件；一次打开、分块复制到
私有 staging 并算 SHA，句柄前后身份/大小/mtime 一致才算冻结。超过 8 MiB 或消息合计 32 MiB 的项按点名顺序降级成
「仅引用」（不读内容、不算 hash），不截断、不让整条命令失败。
接收端：私有 part 校验后落到生成的交付路径；祖先与目标叶不跟随链接；已存在的叶只有内容完全相同才复用，否则换名，
绝不覆盖或删除别人的文件。Linux 同文件系统硬链接后删 part（原子且不覆盖）；Windows 在交付父目录 CREATE_NEW 新叶
（继承目录 ACL）后从 part 复制、flush、重算 hash。
"""

from __future__ import annotations

import errno
import hashlib
import os
import re
import stat
import sys
import tempfile
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ..ids import new_id
from ..native_names import altered_char
from .codec import BLOB_CHUNK_BYTES, MAX_BLOB_BYTES, MAX_MESSAGE_BLOB_BYTES, MAX_REFS

# 源端与接收端的闭集失败原因（§88.3）；too_many_files 沿用本机报告的 16 个文件上限与文案
ATTACHMENT_ERRORS = frozenset(
    {"attachment_unreadable", "attachment_not_regular", "attachment_source_changed", "attachment_unavailable",
     "attachment_hash_mismatch", "attachment_path_unavailable", "too_many_files", "device_storage_full",
     "attachment_write_failed"}
)
# 磁盘/配额写满（Windows 的 ERROR_DISK_FULL 也映射成 ENOSPC）：暂时性的，不当永久拒收
NO_SPACE = frozenset({errno.ENOSPC, getattr(errno, "EDQUOT", errno.ENOSPC)})
# 路径本身不成立（名字过长/非法、中间一级不是目录、链接环）：重试也不会变，确定失败
_PATH_ERRNOS = frozenset({errno.ENAMETOOLONG, errno.ENOTDIR, errno.ELOOP, errno.EINVAL})
# 收端/本机落地时的暂时失败：写满与其他本机写错误（Windows 杀软占用、共享冲突、权限抖动）。
# relay 不 ACK 等重推，worker 按等待处理；确定失败只留哈希不符、链接/重解析点与路径本身不成立（Opus r2-P3-1）
TRANSIENT_CODES = frozenset({"device_storage_full", "attachment_write_failed"})
# 收端最近一次落地交付叶暂时失败的时刻（doctor 显示）；之后一次完整落地清空
WRITE_FAILED_META = "incomingWriteFailedAt"
REFERENCE_NOTICE = "未传输：仅源设备引用，不能按此路径在本机读取"
MAX_NAME_CHARS = 64
MAX_NAME_BYTES = 128
MAX_LEAF_RETRIES = 8
_FORBIDDEN = set('/\\<>:"|?*')
_RESERVED = frozenset(
    {"CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$"}
    | {f"{prefix}{suffix}" for prefix in ("COM", "LPT") for suffix in (*"0123456789", "¹", "²", "³")}
)


class AttachmentError(Exception):
    """附件处理失败，带闭集原因码；不回显路径或系统错误文本。"""

    def __init__(self, code: str) -> None:
        assert code in ATTACHMENT_ERRORS, code
        super().__init__(code)
        self.code = code


@dataclass(frozen=True)
class Frozen:
    """一个点名附件的冻结结果：wire manifest 加本机冻结副本（仅 blob 有）。"""

    manifest: dict[str, Any]
    staging: Path | None


# ---- 名字清洗 ----


def _truncate(text: str) -> str:
    text = text[:MAX_NAME_CHARS]
    while len(text.encode("utf-8")) > MAX_NAME_BYTES:
        text = text[:-1]
    return text


def _reserved(name: str) -> bool:
    stem = name.split(".", 1)[0].rstrip(" .")
    return stem.upper() in _RESERVED


def sanitize_name(raw: str) -> str:
    """交付文件显示名清洗（两平台共用）：basename、去控制符与 Windows 非法字符、去尾点/空格、保留名加 file-。

    C0 与 DEL 照旧去掉；copyable 拒绝集合里的其余字符（C1 控制如 NEL/CSI、格式字符如 RLO/零宽、行/段分隔符、私用与
    未分配码位）换成 `_`（§103.8 修 2）：落地文件名本身就不含会断行或倒排的字符，路径原样进 status 与 agent 正文也安全，
    agent 照抄路径能打开。叶名带内容 SHA，改名只影响新落地的叶：同内容复用仍按 SHA/size 核对，已落地的旧叶不动。
    """
    base = re.split(r"[\\/]", raw)[-1]
    base = "".join("_" if altered_char(ch) else ch
                   for ch in base if ord(ch) >= 32 and ord(ch) != 127 and ch not in _FORBIDDEN)
    for _ in range(3):  # 截短/加前缀后重做空名与保留名检查
        base = _truncate(base.rstrip(" ."))
        base = base.rstrip(" .")
        if base in ("", ".", ".."):
            base = "attachment"
        if not _reserved(base):
            return base
        base = "file-" + base
    return "attachment"


def wire_name(path: str) -> str:
    """manifest 里的原名：basename，控制符与路径分隔符替换成 _（仅作显示，不拼目的路径）。"""
    base = os.path.basename(path.rstrip("/\\")) or "attachment"
    cleaned = "".join("_" if ord(ch) < 32 or ch in "/\\" else ch for ch in base)
    return cleaned[:255] or "attachment"


# ---- 源端 ----


def _named_path(raw: str, cwd: Path) -> str:
    candidate = os.path.expanduser(raw)
    if not os.path.isabs(candidate):
        candidate = os.path.join(str(cwd), candidate)
    path = os.path.abspath(candidate)
    if any(ord(ch) < 32 for ch in path) or len(path) > 4096:
        raise AttachmentError("attachment_unreadable")
    return path


def named_paths(paths: Sequence[str], cwd: Path) -> list[str]:
    """点名附件规范成绝对路径并折叠重复（与 freeze 同一规则）；retry 冻结前预判合并后的个数用（§104.4）。"""
    named: list[str] = []
    for raw in paths:
        path = _named_path(raw, cwd)
        if path not in named:
            named.append(path)
    return named


def merge_refs(inherited: Sequence[dict[str, Any]], extra: Sequence[dict[str, Any]]) -> list[dict[str, Any]]:
    """retry --ref 的附件合并（§104.4）：新附件追加在继承的之后，按（来源路径, sha256）去重。

    只有新增部分让合并结果超过 16 项才报 too_many_files（§104.11 第 5 条，与本机 reports.refs_over_limit 同一口径）。
    """
    merged = list(inherited)
    seen = {(item.get("originalPath"), item.get("sha256")) for item in merged}
    for item in extra:
        key = (item.get("originalPath"), item.get("sha256"))
        if key not in seen:
            seen.add(key)
            merged.append(item)
    if len(merged) > MAX_REFS and len(merged) > len(inherited):
        raise AttachmentError("too_many_files")
    return merged


def blob_bytes(refs: Sequence[dict[str, Any]]) -> int:
    """已冻结 blob 的字节合计（仅引用不算）：retry --ref 冻结新附件前计入 32 MiB 预算（§104.11 第 5 条）。"""
    return sum(int(item.get("size") or 0) for item in refs if item.get("transfer") == "blob")


def drop_inherited(named: Sequence[str], inherited: Sequence[dict[str, Any]]) -> list[str]:
    """retry --ref 冻结前去掉与继承 blob 完全相同的点名（同一来源路径、大小与 sha256，§104.11 第 5 条）。

    它们合并时本来就会被去重，不该再占 32 MiB 预算；预算紧时还会被降成「仅引用」（sha256 为空，去不了重，同一个文件
    会列两次）。只在路径与大小都相同时才读一遍算 sha256；读不了的保留，交给 freeze 报原来的错误。
    """
    blobs = {(item.get("originalPath"), item.get("size"), item.get("sha256"))
             for item in inherited if item.get("transfer") == "blob"}
    sized = {(path, size) for path, size, _ in blobs}
    kept: list[str] = []
    for path in named:
        try:
            size = os.stat(path).st_size
            if (path, size) in sized and (path, size, file_digest(Path(path))[0]) in blobs:
                continue
        except (OSError, AttachmentError):
            pass
        kept.append(path)
    return kept


def _handle_path(fd: int, fallback: str) -> str:
    """源文件的最终路径（只进 manifest 的 resolvedPath 供展示，不作身份保证；身份由 fstat 的 dev/ino 前后核对）。

    Linux 读 /proc/self/fd，得到的就是这个句柄；其他平台按路径 realpath，是另一次解析，不保证与已打开的句柄同一文件。
    """
    if sys.platform.startswith("linux"):
        try:
            return os.readlink(f"/proc/self/fd/{fd}")
        except OSError:
            pass
    return os.path.realpath(fallback)


def _same_identity(a: os.stat_result, b: os.stat_result) -> bool:
    return (a.st_dev, a.st_ino) == (b.st_dev, b.st_ino)


def _freeze_blob(path: str, initial: os.stat_result, staging: Path) -> tuple[str, int, str]:
    """一次打开、分块复制到私有 staging 并算 SHA；返回 (sha256, size, resolvedPath)。"""
    # O_NONBLOCK 只在 POSIX 有：即使检查后被换成 FIFO 也不会卡住；getattr 让 Windows 类型检查也通过
    flags = (os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_BINARY", 0)
             | getattr(os, "O_NONBLOCK", 0))
    try:
        fd = os.open(path, flags)
    except OSError as error:
        raise AttachmentError("attachment_unreadable") from error
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode):
            raise AttachmentError("attachment_not_regular")
        if not _same_identity(before, initial):
            raise AttachmentError("attachment_source_changed")
        resolved = _handle_path(fd, path)
        staging.mkdir(mode=0o700, parents=True, exist_ok=True)
        tmp_fd, tmp_name = tempfile.mkstemp(dir=staging, prefix="freeze-", suffix=".part")
        hasher = hashlib.sha256()
        copied = 0
        try:
            with os.fdopen(tmp_fd, "wb") as out:
                while True:
                    try:
                        chunk = os.read(fd, BLOB_CHUNK_BYTES)
                    except OSError as error:
                        raise AttachmentError("attachment_unreadable") from error
                    if not chunk:
                        break
                    copied += len(chunk)
                    if copied > MAX_BLOB_BYTES:
                        raise AttachmentError("attachment_source_changed")
                    hasher.update(chunk)
                    out.write(chunk)
                out.flush()
                os.fsync(out.fileno())
            after = os.fstat(fd)
            if (copied != before.st_size or after.st_size != before.st_size
                    or after.st_mtime_ns != before.st_mtime_ns or not _same_identity(after, before)):
                raise AttachmentError("attachment_source_changed")
            digest = hasher.hexdigest()
            final = staging / f"{digest}.blob"
            if final.exists():
                os.unlink(tmp_name)  # 相同内容已冻结过：CAS 去重
                os.utime(final)  # 刷新 mtime：留存回收不删刚被复用的副本（STAGING_GRACE_MS）
            else:
                os.replace(tmp_name, final)
            return digest, copied, resolved
        except BaseException:
            if os.path.exists(tmp_name):
                os.unlink(tmp_name)
            raise
    finally:
        os.close(fd)


def freeze(paths: Sequence[str], *, cwd: Path, origin_device: str, staging: Path,
           available: int | None = None, used: int = 0) -> list[Frozen]:
    """冻结点名附件：重复点名折叠；超过 16 项拒绝；单项 8 MiB、合计 32 MiB 按点名顺序贪心，超出的降级为仅引用。

    available 是设备内容预算的剩余字节（§88.11）：要冻结的副本合计超过它就在复制前拒绝 device_storage_full。
    used 是同一条消息里已占用的 blob 字节（retry 继承的附件，§104.11 第 5 条）：只计入 32 MiB，不计入 available
    （那些副本已经在 staging 里，不再复制）。
    """
    named = named_paths(paths, cwd)
    if len(named) > MAX_REFS:
        raise AttachmentError("too_many_files")
    planned: list[tuple[str, os.stat_result, str | None]] = []
    total = used
    for path in named:
        try:
            info = os.stat(path)  # 跟随链接：源端允许 symlink/junction/OneDrive 占位
        except OSError as error:
            raise AttachmentError("attachment_unreadable") from error
        if not stat.S_ISREG(info.st_mode):
            raise AttachmentError("attachment_not_regular")
        reason = None
        if info.st_size > MAX_BLOB_BYTES:
            reason = "single_file_limit"
        elif total + info.st_size > MAX_MESSAGE_BLOB_BYTES:
            reason = "message_total_limit"
        else:
            total += info.st_size
        planned.append((path, info, reason))
    if available is not None and total - used > available:
        raise AttachmentError("device_storage_full")  # 写前拒绝：一个副本都还没复制
    result: list[Frozen] = []
    for path, info, reason in planned:
        manifest: dict[str, Any] = {"originDeviceId": origin_device, "originalPath": path, "name": wire_name(path)}
        if reason is not None:
            # 仅引用：不为算 hash 遍读超限文件，不伪称冻结副本
            manifest.update({"resolvedPath": os.path.realpath(path), "transfer": "reference", "reason": reason,
                             "size": int(info.st_size), "sha256": None, "hashState": "not_computed_size_limit"})
            result.append(Frozen(manifest, None))
            continue
        try:
            digest, size, resolved = _freeze_blob(path, info, staging)
        except OSError as error:
            if error.errno in NO_SPACE:
                raise AttachmentError("device_storage_full") from error  # 实际写满：与预检同一结论，任务/报告都没写
            raise
        if size != info.st_size:
            raise AttachmentError("attachment_source_changed")  # 规划后变了大小：贪心与预算按旧大小算的，不再成立
        manifest.update({"resolvedPath": resolved, "transfer": "blob", "reason": None, "size": size,
                         "sha256": digest, "hashState": "frozen"})
        result.append(Frozen(manifest, staging / f"{digest}.blob"))
    return result


def transfer_summary(frozen: Sequence[Frozen]) -> tuple[int, int, int]:
    """(blob 个数, blob 字节, 仅引用个数)：CLI 写前提示「附件 N 个、X 字节，将上传 hub」用。"""
    blobs = [item for item in frozen if item.manifest["transfer"] == "blob"]
    return len(blobs), sum(int(item.manifest["size"]) for item in blobs), len(frozen) - len(blobs)


# ---- 接收端 ----


def file_digest(path: Path, *, limit: int = MAX_BLOB_BYTES) -> tuple[str, int]:
    """流式算 (sha256, size)；超过 limit 视为不符。"""
    hasher = hashlib.sha256()
    size = 0
    with open(path, "rb") as handle:
        while True:
            chunk = handle.read(BLOB_CHUNK_BYTES)
            if not chunk:
                break
            size += len(chunk)
            if size > limit:
                raise AttachmentError("attachment_hash_mismatch")
            hasher.update(chunk)
    return hasher.hexdigest(), size


def is_link_or_reparse(info: os.stat_result) -> bool:
    """lstat 结果是符号链接，或 Windows 重解析点（junction 等）。"""
    if stat.S_ISLNK(info.st_mode):
        return True
    attributes = getattr(info, "st_file_attributes", 0)
    return bool(attributes & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))


_is_link_or_reparse = is_link_or_reparse


def safe_dirs(root: Path, parts: Sequence[str], *, private: bool) -> Path:
    """在 root 下逐级建目录；root 以下任何一级是链接/reparse 或不是目录都拒绝（目的地不跟随链接）。

    root 本身（state 根或 LocalAppData）按解析后的真实目录信任：用户把 state 根放在链接后面是正常用法。
    """
    current = root.resolve()
    if not current.is_dir():
        raise AttachmentError("attachment_path_unavailable")
    for part in parts:
        current = current / part
        try:
            info = os.lstat(current)
        except FileNotFoundError:
            try:
                os.mkdir(current, 0o700 if private else 0o777)
            except FileExistsError:
                pass
            except OSError as error:
                raise _write_error(error) from error  # 建目录时写满或本机写抖动也是暂时的：收端延后重试
            info = os.lstat(current)
        except OSError as error:
            raise _write_error(error) from error
        if _is_link_or_reparse(info) or not stat.S_ISDIR(info.st_mode):
            raise AttachmentError("attachment_path_unavailable")
    return current


def delivery_dir(*, state_root: Path, windows: bool, instance_id: str, local_appdata: Path | None,
                 task_id: str, authority_device: str) -> Path:
    """交付目录：Linux 在私有 state 下 0700；Windows 在 LocalAppData 下另建、继承用户目录 ACL（§88.3）。"""
    if windows:
        if local_appdata is None:
            raise AttachmentError("attachment_path_unavailable")
        return safe_dirs(local_appdata, ["agent-bridge-inbox", instance_id, task_id, authority_device], private=False)
    return safe_dirs(state_root, ["attachments", task_id, authority_device], private=True)


def identity(path: Path) -> dict[str, int]:
    info = os.lstat(path)
    return {"dev": int(info.st_dev), "ino": int(info.st_ino), "size": int(info.st_size),
            "mtimeNs": int(info.st_mtime_ns)}


def intact_copy(path: Path, sha: str, size: int) -> bool:
    """已存在的副本是普通、非链接、单链接的文件，且完整 SHA/size 相符（可直接复用）。"""
    return _reusable(path, sha, size)


def _reusable(path: Path, sha: str, size: int) -> bool:
    """已存在的叶：普通、非链接、单链接且完整 SHA/size 相符才复用。"""
    try:
        info = os.lstat(path)
    except OSError:
        return False
    if _is_link_or_reparse(info) or not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size != size:
        return False
    try:
        return file_digest(path) == (sha, size)
    except (OSError, AttachmentError):
        return False


def _candidates(sha: str, name: str) -> list[str]:
    clean = sanitize_name(name)
    names = [f"{sha[:16]}-{clean}", f"{sha}-{clean}"]
    names += [f"{sha}-{new_id()}-{clean}" for _ in range(MAX_LEAF_RETRIES)]
    return names


OnCreate = Callable[[Path, dict[str, int]], None]


def land(part: Path, directory: Path, *, name: str, sha: str, size: int, copy_new_leaf: bool,
         on_create: OnCreate | None = None) -> Path:
    """把已校验的私有 part 落成交付叶；返回最终路径。part 成功后被移走/删除。

    copy_new_leaf=True（Windows）：CREATE_NEW 新叶继承父目录 ACL，从 part 复制、flush、重算 hash；
    否则（Linux）硬链接到新名后删除 part，同文件系统原子且不覆盖。
    on_create：新叶刚以 CREATE_NEW 建出、尚未写内容时回调 (路径, {dev, ino})，供调用方先持久「本次的半成品」，
    崩溃后只按这份记录核验/回收，不碰其他文件。
    """
    for leaf in _candidates(sha, name):
        dest = directory / leaf
        if os.path.lexists(dest):
            if _reusable(dest, sha, size):
                os.unlink(part)
                return dest
            continue  # 同名异内容/被编辑过：换名，不覆盖不删除
        try:
            if copy_new_leaf:
                _copy_new_leaf(part, dest, sha, size, on_create)
            else:
                os.link(part, dest)
            os.unlink(part)
            return dest
        except FileExistsError:
            continue  # 并发创建：真实冲突才重取
        except OSError as error:
            if error.errno == errno.ENAMETOOLONG and not leaf.startswith(sha[:16] + "-attachment"):
                # 路径过长：缩 basename（不缩 hash）再试一次
                short = directory / f"{sha[:16]}-attachment"
                if not os.path.lexists(short):
                    return land(part, directory, name="attachment", sha=sha, size=size, copy_new_leaf=copy_new_leaf,
                                on_create=on_create)
            raise _write_error(error) from error  # 磁盘满/本机写抖动是暂时的：收端延后重试，不当永久拒收
    raise AttachmentError("attachment_path_unavailable")


def _write_error(error: OSError) -> AttachmentError:
    """本机建目录/落交付叶的 OSError 分类：写满、路径本身不成立（确定）、其余本机写错误（暂时）。"""
    if error.errno in NO_SPACE:
        return AttachmentError("device_storage_full")
    if error.errno in _PATH_ERRNOS:
        return AttachmentError("attachment_path_unavailable")
    return AttachmentError("attachment_write_failed")


def _copy_new_leaf(part: Path, dest: Path, sha: str, size: int, on_create: OnCreate | None = None) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0) | getattr(os, "O_CLOEXEC", 0)
    fd = os.open(dest, flags)  # 不传安全描述符：继承交付目录 ACL，不调用 ensure_private
    try:
        if on_create is not None:
            info = os.fstat(fd)
            on_create(dest, {"dev": int(info.st_dev), "ino": int(info.st_ino)})
        with os.fdopen(fd, "wb") as out, open(part, "rb") as source:
            while True:
                chunk = source.read(BLOB_CHUNK_BYTES)
                if not chunk:
                    break
                out.write(chunk)
            out.flush()
            os.fsync(out.fileno())
        if file_digest(dest) != (sha, size):
            raise AttachmentError("attachment_hash_mismatch")
    except BaseException:
        try:
            os.unlink(dest)  # 只删本次刚建的新叶
        except OSError:
            pass
        raise


def recover_pending(path: Path, recorded: dict[str, int], *, sha: str, size: int) -> Path | None:
    """崩溃恢复：只处理本次记录的半成品叶。

    身份（dev/ino）与记录一致：内容完整则直接采用，否则删除它；身份不符（已被别人替换）或不存在：不动、返回 None。
    """
    try:
        info = os.lstat(path)
    except OSError:
        return None
    if _is_link_or_reparse(info) or (int(info.st_dev), int(info.st_ino)) != (recorded.get("dev"), recorded.get("ino")):
        return None
    if info.st_size == size and _reusable(path, sha, size):
        return path
    try:
        os.unlink(path)
    except OSError:
        pass
    return None
