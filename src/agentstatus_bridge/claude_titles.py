"""Claude 会话名的有界只读取法（DESIGN §99）：从会话记录尾部找最近一组标题记录，只取标题字段作原生主名。

只解析含三种标题类型字样的单行（ai-title、custom-title、agent-name），其余字节不解析、不保留、不进日志；
结果与原因码都不带记录内容。平台差异（Windows 共享读打开）由调用方注入平台层的 `open_shared_read`。
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Callable, Iterable
from contextlib import AbstractContextManager
from dataclasses import dataclass, replace
import json
import os
from pathlib import Path
import stat
from typing import Any

from .model import Endpoint, Provider
from .native_names import UUID_SHAPE, name_source
from .platforms.types import SharedRead

CHUNK_BYTES = 64 * 1024  # 从文件尾回读的块大小
FILE_BUDGET_BYTES = 1024 * 1024  # 单文件预算：已观测相邻标题记录最大间隔 562 KiB（§99.3）
ROUND_BUDGET_BYTES = 8 * 1024 * 1024  # 一次发现里全部会话合计的读取上限：会话再多也不拖长发现
MAX_PROJECT_DIRS = 4096  # projects/ 一级子目录的扫描上限
MAX_RECORD_BYTES = 16 * 1024  # 标题记录都是几百字节的小行；更长的行即使含字样也当普通记录，不解析
DISPLAY_LIMIT = 80  # 与注册名相同的显示上限（Linux、Windows 都是 80）
MAX_MEMO = 512

FOUND_CUSTOM = "found_custom"
FOUND_AI = "found_ai"
# 取不到标题时的闭集原因码（不带路径、目录名与内容）：诊断只按码计数
FALLBACK_REASONS = frozenset({
    "no_record_file", "multiple_files", "not_regular", "unreadable", "budget_exhausted", "no_title_record",
    "session_mismatch", "bad_value", "bad_session_id", "directory_limit",
})
REASONS = frozenset({FOUND_CUSTOM, FOUND_AI}) | FALLBACK_REASONS

_AI, _CUSTOM, _AGENT = "ai-title", "custom-title", "agent-name"
_MARKERS = {kind: f'"type":"{kind}"'.encode() for kind in (_AI, _CUSTOM, _AGENT)}
_FIELDS = {_AI: "aiTitle", _CUSTOM: "customTitle"}
# 唯一的解析入口：隐私判据「只解析含紧凑字样、不超过 16 KiB 的单行」由用例在这里记录核对
_parse: Callable[[bytes], Any] = json.loads


@dataclass(frozen=True)
class TitleResult:
    """取名结果：title 为 None 时按 reason 退回注册名；reason 属于 REASONS。"""
    title: str | None
    reason: str


def _usable(value: object) -> str | None:
    """标题值能否作名字：只认非空白字符串，否则 None（按值不符退回）。

    截断、首尾空白与会被消费者改动的字符照 §91.3 的 name_source 投影与 §91 展示/可复制规则处理，不另开规则。
    """
    return value if isinstance(value, str) and value.strip() else None


class _Group:
    """从尾往前喂行，认出最近一组相邻的标题类记录（§99.2）。"""

    def __init__(self, session_id: str) -> None:
        self.session_id = session_id
        self.started = False
        self.values: dict[str, object] = {}  # 组内每种类型最近（最先读到）的一条的字段值
        self.mismatch = False

    def feed(self, line: bytes) -> TitleResult | None:
        """喂入一整行；最近一组结束时返回结果，否则 None。"""
        if not any(marker in line for marker in _MARKERS.values()) or len(line) > MAX_RECORD_BYTES:
            return self._end()  # 普通记录：组在这里结束
        try:
            record: Any = _parse(line)
        except (ValueError, RecursionError):
            return None  # 坏行（如写到一半）：跳过，不带内容
        kind = record.get("type") if isinstance(record, dict) else None
        if not isinstance(kind, str) or kind not in _MARKERS:
            return self._end()  # 字样只出现在别的记录内部（嵌套对象）：仍是普通记录
        if record.get("sessionId") != self.session_id:
            self.mismatch = True
            return None  # 不是这个会话的记录：跳过这一行
        self.started = True
        if kind in _FIELDS and kind not in self.values:
            self.values[kind] = record.get(_FIELDS[kind])
        return None

    def _end(self) -> TitleResult | None:
        return self.result() if self.started else None

    def result(self) -> TitleResult:
        """组内有 custom-title 取它，否则取 ai-title；最新的那条值不符时退回，不改取另一种。"""
        if not self.started:
            return TitleResult(None, "session_mismatch" if self.mismatch else "no_title_record")
        for kind, reason in ((_CUSTOM, FOUND_CUSTOM), (_AI, FOUND_AI)):
            if kind in self.values:
                value = _usable(self.values[kind])
                return TitleResult(value, reason) if value is not None else TitleResult(None, "bad_value")
        return TitleResult(None, "no_title_record")


def _read_title(reader: SharedRead, session_id: str, budget: int) -> tuple[TitleResult, int, bool]:
    """从文件尾按块回读（跨块拼行），找最近一组标题记录；返回结果、实际读取的字节数与是否被预算截断。

    截断时组若已开始，返回的是已读到的那一部分组（可能缺了更早的 custom-title）。
    """
    group = _Group(session_id)
    end, carry, consumed = reader.size, b"", 0
    while end > 0:
        if consumed >= budget:
            return (group.result() if group.started else TitleResult(None, "budget_exhausted")), consumed, True
        length = min(CHUNK_BYTES, end, budget - consumed)
        start = end - length
        block = reader.read_at(start, length)
        if len(block) != length:
            raise OSError("short_read")
        consumed += length
        lines = (block + carry).split(b"\n")
        carry = lines[0]  # 块首可能是半行：留到读下一块时拼上
        for line in reversed(lines[1:]):
            found = group.feed(line)
            if found is not None:
                return found, consumed, False
        end = start
    found = group.feed(carry)  # 读到文件开头：块首这一行是完整的第一行
    return (found if found is not None else group.result()), consumed, False


def _project_dirs(config_root: Path) -> tuple[tuple[Path, ...], str | None]:
    """<配置根>/projects/ 的一级子目录：跳过符号链接、junction 与非目录项，不进更深一层。

    projects 本身按路径打开：它是账号根的一部分（兼容布局里可能是指向真实账号根的链接）；
    「不跟随链接」管的是它下面的子目录项与最终的记录文件。
    """
    dirs: list[Path] = []
    try:
        with os.scandir(config_root / "projects") as entries:
            for index, entry in enumerate(entries):
                if index >= MAX_PROJECT_DIRS:
                    return (), "directory_limit"
                if entry.is_symlink() or entry.is_junction() or not entry.is_dir(follow_symlinks=False):
                    continue
                dirs.append(Path(entry.path))
    except (FileNotFoundError, NotADirectoryError):
        return (), "no_record_file"
    except OSError:
        return (), "unreadable"
    return tuple(dirs), None


def _locate(dirs: tuple[Path, ...], session_id: str) -> tuple[Path | None, os.stat_result | None, str | None]:
    """在一级子目录里找文件名恰为 <sessionId>.jsonl 的项：lstat 不跟随链接，多个算无法判定。

    某个子目录查不了（权限等）只跳过它，不连累其他目录；什么都没找到且有目录查不了时记 unreadable。
    """
    name = f"{session_id}.jsonl"
    found: list[tuple[Path, os.stat_result]] = []
    blocked = False
    for folder in dirs:
        candidate = folder / name
        try:
            info = os.lstat(candidate)
        except FileNotFoundError:
            continue
        except OSError:
            blocked = True
            continue
        found.append((candidate, info))
    if not found:
        return None, None, "unreadable" if blocked else "no_record_file"
    if len(found) > 1:
        return None, None, "multiple_files"
    path, info = found[0]
    # 符号链接、目录、FIFO 与 Windows 重解析点（st_file_attributes 的 0x400）都不读
    if not stat.S_ISREG(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
        return None, None, "not_regular"
    return path, info, None


# 进程内记忆：按路径存 (大小, 修改时间, 结果)，两者有一个变了就重读；每个路径只留最新一条，常驻 worker 里
# 活跃会话不断追加也不会堆旧键。不落盘，标题不写进任何本地缓存文件
_MEMO: dict[str, tuple[int, int, TitleResult]] = {}


class TitleReader:
    """一次发现用的取名器：合计读取预算按本轮算；打开文件用平台层注入的共享读打开。"""

    def __init__(self, open_read: Callable[[Path], AbstractContextManager[SharedRead]], *,
                 budget: int | None = None) -> None:
        self.open_read = open_read
        self.remaining = ROUND_BUDGET_BYTES if budget is None else budget  # 构造时读常量：测试可改小
        self._dirs: dict[Path, tuple[tuple[Path, ...], str | None]] = {}  # 每个配置根本轮只扫一次 projects/
        # 本轮按（设备号, inode, 会话 ID）复用读取结果：别名根经链接指向同一个文件时不重读、不重复扣预算。
        # 只复用同一个物理文件、同一会话的结果：不单按 sessionId（不同根下找不到文件不能代表别处也没有），
        # 也不单按 inode（硬链接下另一个会话 ID 的文件名指向同一 inode，结果要按各自的 sessionId 判）
        self._files: dict[tuple[int, int, str], TitleResult] = {}

    def lookup(self, config_root: Path, session_id: str) -> TitleResult:
        """取该会话的标题；任何失败都返回退回原因码，不抛异常、不带内容。"""
        if not UUID_SHAPE.fullmatch(session_id):
            return TitleResult(None, "bad_session_id")  # 会话 ID 拼进文件名：只认 UUID 形状
        if config_root not in self._dirs:
            self._dirs[config_root] = _project_dirs(config_root)
        dirs, reason = self._dirs[config_root]
        if reason is not None:
            return TitleResult(None, reason)
        path, info, reason = _locate(dirs, session_id)
        if path is None or info is None:
            return TitleResult(None, reason or "no_record_file")
        identity = (info.st_dev, info.st_ino, session_id) if info.st_ino else None  # inode 为 0 时不认身份
        if identity is not None and identity in self._files:
            return self._files[identity]
        key, stamp = str(path), (info.st_size, info.st_mtime_ns)
        cached = _MEMO.get(key)
        if cached is not None and cached[:2] == stamp:
            if identity is not None:
                self._files[identity] = cached[2]  # 记忆命中也登记：别名根上的同一文件本轮不再按另一条路径重读
            return cached[2]
        budget = min(FILE_BUDGET_BYTES, self.remaining)
        if budget <= 0:
            return TitleResult(None, "budget_exhausted")
        try:
            with self.open_read(path) as reader:
                result, used, truncated = _read_title(reader, session_id, budget)
        except FileNotFoundError:
            return TitleResult(None, "no_record_file")
        except OSError as error:
            return TitleResult(None, "not_regular" if error.args == ("not_regular",) else "unreadable")
        self.remaining -= used
        if identity is not None:
            self._files[identity] = result
        if truncated and budget < FILE_BUDGET_BYTES:
            # 被本轮剩余预算截断：结果取决于同一轮里别的文件读了多少，不记忆，下一轮重读。
            # 只被单文件 1 MiB 截断的结果照常记忆——它只取决于文件内容与固定上限，文件不变时重读必然相同
            return result
        if key not in _MEMO and len(_MEMO) >= MAX_MEMO:
            _MEMO.clear()
        _MEMO[key] = (*stamp, result)
        return result

    def apply(self, endpoint: Endpoint, *config_roots: Path) -> Endpoint:
        """取到标题就换作该 Claude 端点的原生主名（§99.2，按 §91.3 投影、80 字符显示上限）；取不到保留注册名。

        同一条注册记录经多个配置根看到时按给定顺序逐个试，取到标题即停；都取不到时原因码取第一个不是
        no_record_file 的结果（找到了记录文件的那个根更能说明原因），全是 no_record_file 就记它。
        """
        result = TitleResult(None, "no_record_file")
        for root in config_roots:
            attempt = self.lookup(root, endpoint.ref.native_id)
            if attempt.title is not None or result.reason == "no_record_file":
                result = attempt
            if attempt.title is not None:
                break
        if result.title is None:
            return replace(endpoint, name_origin=result.reason)
        return replace(endpoint, name=result.title[:DISPLAY_LIMIT],
                       name_source=name_source(result.title, limit=DISPLAY_LIMIT), name_origin=result.reason)


def counts(endpoints: Iterable[Endpoint]) -> dict[str, object]:
    """诊断计数（§99.3）：取到标题几个、退回几个及各退回原因码的次数；不含路径、目录名与标题原文。"""
    origins = Counter(item.name_origin for item in endpoints
                      if item.ref.provider is Provider.CLAUDE and item.name_origin in REASONS)
    found = origins.pop(FOUND_CUSTOM, 0) + origins.pop(FOUND_AI, 0)
    return {"found": found, "fallback": dict(sorted((str(key), value) for key, value in origins.items()))}
