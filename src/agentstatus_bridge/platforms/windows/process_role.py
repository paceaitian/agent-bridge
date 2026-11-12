"""Windows Claude 发现的进程角色正证（DESIGN §92）：Electron 辅助进程（T）与其主进程（P）。

只服务完整性判定：已正证的 Desktop 进程不再算「可能漏看的 Claude Code 会话」。读不到、证不出一律
unknown，由调用方保持原来的不完整判定。命令行原文只在本模块内临时存在，不进返回值、异常、日志或账本。
"""
from __future__ import annotations

import ctypes as C
from collections.abc import Callable, Iterable, Iterator
from dataclasses import dataclass, field
from pathlib import PureWindowsPath
import re
import time

from . import abi as A
from .api import ProcessFact, WinApi

HELPER, NOT_PROVEN, UNKNOWN = 'helper', 'not_proven_helper', 'unknown'
NO_TYPE, TYPE_PRESENT = 'no_type', 'type_present'  # 只给验收探针计数用（§92.7 ⑥），不参与产品判定
ROLE_SECONDS = 0.5           # 单进程协作预算，另受调用方截止时刻约束（§92.3）
ARG_UNITS = 256              # 每个参数最多读 256 个 UTF-16 码元（含终止符）
QUERY_INITIAL = 4096
QUERY_LIMIT = C.sizeof(A.UNICODE_STRING) + 65534 + 2   # Win64 为 65552 字节
RETRY_STATUS = frozenset({0xC0000004, 0xC0000023, 0x80000005})
COMMAND_LINE_CLASS = 60      # ProcessCommandLineInformation
QUERY_ACCESS = 0x101000      # QUERY_LIMITED_INFORMATION|SYNCHRONIZE，不申请 VM_READ
TYPE_VALUE = re.compile(r'[A-Za-z0-9_-]+')


Judge = Callable[[Iterable['Arg']], str]


@dataclass(frozen=True)
class Arg:
    """惰性参数视图的一项：最多 ARG_UNITS 个码元的前缀，以及是否读到了终止符；text 为 None 表示指针无效。"""
    text: str | None
    complete: bool


def _scan(args: Iterable[Arg]) -> tuple[bool, int, bool]:
    """扫描前导 `--键=值` 段：返回（是否判定得出、type 键个数、type 值是否全部合法）。

    args 从 argv[1] 起；独立 `--`、非 equals 开关、位置参数结束前导段，之后的参数不再读取。
    无效指针、截断的 type 值、截断后无法判断是否为 equals 结构的开关，都判定不出。
    """
    types, valid = 0, True
    for arg in args:
        if arg.text is None:
            return False, types, valid
        text = arg.text
        if text == '--' and arg.complete:
            break
        if text.startswith('--'):
            key, sep, value = text[2:].partition('=')
            if sep:
                if key == 'type':
                    if not arg.complete:
                        return False, types, valid
                    types += 1
                    # 空值、非法字符（含孤立代理码元）都不是正证；只按码元比较，不会抛异常
                    valid = valid and TYPE_VALUE.fullmatch(value) is not None
                continue  # 已知的非 type 键：前缀里已见 `=`，跳过其余内容，不把值再当开关
            if not arg.complete:
                return False, types, valid
        break
    return True, types, valid


def classify(args: Iterable[Arg]) -> str:
    """前导段内恰好一个完整、合法的 `--type=` 才是辅助进程正证（§92.3 第 5 条）；判定不出为 unknown。"""
    decided, types, valid = _scan(args)
    if not decided:
        return UNKNOWN
    return HELPER if types == 1 and valid else NOT_PROVEN


def type_presence(args: Iterable[Arg]) -> str:
    """验收探针用（§92.7 ⑥）：前导段读全且没有 type 键为 no_type；有 type 键（含重复、空、非法）为
    type_present；判定不出为 unknown。与 classify 共用同一扫描函数（_scan），不另立规则；探针另做一次有界
    读取，两次读取不是同一份样本，第二次判定不出计入 unknown。
    """
    decided, types, _ = _scan(args)
    if not decided:
        return UNKNOWN
    return TYPE_PRESENT if types else NO_TYPE


def _wipe(address: int, size: int) -> None:
    """尽力清零（卫生措施，不参与判定）。"""
    try:
        if address and size > 0:
            C.memset(address, 0, size)
    except Exception:  # noqa: BLE001 - 清零失败不能改变判定，也不能跳过释放
        pass


def _read_arg(pointer: int) -> Arg:
    """逐个宽字符读到 NUL，最多 ARG_UNITS 个码元，不多读第 257 个。"""
    units = C.cast(pointer, C.POINTER(C.c_uint16))
    collected: list[int] = []
    for index in range(ARG_UNITS):
        unit = units[index]
        if unit == 0:
            return Arg(_decode(collected), True)
        collected.append(unit)
    return Arg(_decode(collected), False)


def _decode(units: list[int]) -> str:
    return b''.join(unit.to_bytes(2, 'little') for unit in units).decode('utf-16-le', 'surrogatepass')


def _split(api: WinApi, raw: C.Array, length: int, judge: Judge) -> str:
    """CommandLineToArgvW 分词后惰性分类；argv 块按 argc 划界，用完尽力清零并一定释放。"""
    argc = C.c_int()
    argv = api.dll['shell32'].CommandLineToArgvW(raw, C.byref(argc))
    if not argv:
        return UNKNOWN
    try:
        count = argc.value
        if not 1 <= count <= length // 2 + 1:
            return UNKNOWN
        pointers = C.cast(argv, C.POINTER(C.c_void_p))

        def args() -> Iterator[Arg]:
            for index in range(1, count):
                pointer = pointers[index]
                if not pointer:
                    yield Arg(None, False)
                    return
                yield _read_arg(pointer)

        return judge(args())
    finally:
        try:
            size = int(api.k.LocalSize(argv) or 0)
        except Exception:  # noqa: BLE001 - LocalSize 只用于尽力清零（§92.3 第 6 条）
            size = 0
        _wipe(argv, size)
        api.k.LocalFree(argv)


def read_role(api: WinApi, handle: int, deadline: float, judge: Judge = classify) -> str:
    """T 的读取原语：对已打开、已核实的进程句柄读 class 60 命令行并分类（§92.3 第 2–4 条）。

    不做身份/映像资格检查（由 command_role 负责），所以真实 CI 可以对自己创建的子进程调用它。
    """
    query = api.dll['ntdll'].NtQueryInformationProcess
    buffers: list[C.Array] = []
    try:
        size = QUERY_INITIAL
        for attempt in range(2):
            if time.monotonic() > deadline:
                return UNKNOWN
            buf = C.create_string_buffer(size)
            buffers.append(buf)
            returned = A.DWORD(0)
            status = int(query(handle, COMMAND_LINE_CLASS, buf, size, C.byref(returned))) & 0xFFFFFFFF
            if status == 0:
                return _parse(api, buf, size, returned.value, judge)
            if status in RETRY_STATUS and attempt == 0 and size < returned.value <= QUERY_LIMIT:
                size = returned.value
                continue
            return UNKNOWN
        return UNKNOWN
    finally:
        for buf in buffers:
            _wipe(C.addressof(buf), len(buf))


def _parse(api: WinApi, buf: C.Array, size: int, returned: int, judge: Judge) -> str:
    header = C.sizeof(A.UNICODE_STRING)
    if not header <= returned <= size:
        return UNKNOWN
    value = A.UNICODE_STRING.from_buffer(buf)
    length, maximum, pointer = int(value.length), int(value.maximum), value.buffer
    base = C.addressof(buf)
    if (length == 0 or length % 2 or maximum % 2 or maximum < length or not pointer
            or pointer < base + header or pointer + length > base + returned):
        return UNKNOWN  # Length=0 时分词会返回本进程路径，必须先拦下
    raw = (C.c_char * (length + 2))()  # 自有缓冲，末尾两个零字节作 NUL
    try:
        C.memmove(raw, pointer, length)
        units = (C.c_uint16 * (length // 2)).from_buffer(raw)
        if any(unit == 0 for unit in units):
            return UNKNOWN  # 内嵌 NUL
        return _split(api, raw, length, judge)
    finally:
        _wipe(C.addressof(raw), len(raw))


def witness(parent_birth: int, parent_image: str, child_birth: int, child_role: str, child_image: str) -> bool:
    """P 的纯判定（§92.4）：孩子已正证为 helper、出生严格晚于父、映像完整路径逐字相同。

    出生相等只废这一个见证；PPID、同用户与代际复核由调用方负责。真实 CI 用它检验采到的父子事实。
    """
    return parent_birth < child_birth and child_role == HELPER and child_image == parent_image


def _qualified(api: WinApi, pid: int, birth: str) -> bool:
    """同 SID、双方未提权、映像 basename 为 claude.exe、仍是同一代（§92.3 第 1 条）。"""
    me = api.current_token()
    fact = api.process(pid, expected_birth=birth)
    if fact.token.sid != me.sid or fact.token.elevated:
        return False
    return PureWindowsPath(api.process_image(pid, birth)).name.lower() == 'claude.exe'


def command_role(api: WinApi, pid: int, birth: str, *, deadline: float, judge: Judge = classify) -> str:
    """T：合格的 claude.exe 才读命令行；持同一句柄核出生时刻与令牌，返回前再核代际。"""
    return _command_role(api, pid, birth, deadline=deadline, judge=judge)[0]


def _command_role(api: WinApi, pid: int, birth: str, *, deadline: float,
                  judge: Judge = classify) -> tuple[str, ProcessFact | None]:
    """command_role 的实现，另交回取证时的进程事实（含令牌资格），供缓存复用时整份比对。"""
    limit = min(deadline, time.monotonic() + ROLE_SECONDS)
    try:
        if not _qualified(api, pid, birth):
            return UNKNOWN, None
        before = api.process(pid, expected_birth=birth)
        with api.owned(api.handle(api.k.OpenProcess(QUERY_ACCESS, False, pid))) as handle:
            times = [A.FILETIME() for _ in range(4)]
            api.check(api.k.GetProcessTimes(handle, *(C.byref(t) for t in times)))
            if str(times[0].number()) != birth or api.token(handle) != before.token:
                return UNKNOWN, None
            judge_role = read_role(api, handle, limit, judge)
        # 最后一次同步核验之后再看时钟：核验本身跨过截止也不交出结论（Codex 实现审计 P3-01）
        if api.process(pid, expected_birth=birth) != before or time.monotonic() > limit:
            return UNKNOWN, None
        return judge_role, before
    except OSError:
        return UNKNOWN, None


@dataclass
class Roles:
    """一次 discover 内的角色裁决：按 (pid, birth) 记住闭集结论，不写盘、不跨命令（§92.4）。"""
    api: WinApi
    deadline: float
    allow_parent: bool = True
    _roles: dict[tuple[int, str], tuple[str, ProcessFact | None]] = field(default_factory=dict)
    _children: dict[int, list[tuple[int, str]]] | None = None
    _table_failed: bool = False

    def role(self, pid: int, birth: str) -> str:
        key = (pid, birth)
        if key not in self._roles:
            self._roles[key] = _command_role(self.api, pid, birth, deadline=self.deadline)
        return self._roles[key][0]

    def exempt(self, pid: int, birth: str, protected: frozenset[int]) -> bool:
        """该 PID 的缺口能否免除：同代、无有效登记，且 T 或 P 已正证。"""
        if pid in protected or time.monotonic() > self.deadline:
            return False
        role = self.role(pid, birth)
        if role == HELPER:
            # 复用缓存前的同步复核本身跨过截止也不产生正证（与 _parent 的返回前检查一致，Codex r1 残留 P3-01）
            return self._same(pid, birth) and time.monotonic() <= self.deadline
        if role != NOT_PROVEN or not self.allow_parent:
            return False  # 父自身命令行 unknown 时不靠孩子补证（§92.4 保守选择）
        return self._parent(pid, birth, protected)

    def _same(self, pid: int, birth: str) -> bool:
        """复用缓存前整份比对进程事实：同代、仍存活，且令牌资格（SID、是否提权）与取证时一致（P3-02）。"""
        fact = self._roles.get((pid, birth), (UNKNOWN, None))[1]
        try:
            return fact is not None and self.api.process(pid, expected_birth=birth) == fact
        except OSError:
            return False

    def _table(self) -> dict[int, list[tuple[int, str]]] | None:
        if self._children is None and not self._table_failed:
            try:
                rows = self.api.process_table()  # 只在需要 P 时最多取一次
            except OSError:
                self._table_failed = True
                return None
            children: dict[int, list[tuple[int, str]]] = {}
            for child, parent, name in rows:
                children.setdefault(parent, []).append((child, name))
            self._children = children
        return self._children

    def _parent(self, pid: int, birth: str, protected: frozenset[int]) -> bool:
        """P：存在一个已正证 helper 的直接孩子，映像完整路径逐字相同、出生严格晚于父（§92.4）。"""
        table = self._table()
        if table is None:
            return False
        try:
            parent = self.api.process(pid, expected_birth=birth)
            image = self.api.process_image(pid, birth)
        except OSError:
            return False
        for child, name in table.get(pid, ()):
            if time.monotonic() > self.deadline:
                return False
            if child == pid or child in protected or name.lower() != 'claude.exe':
                continue
            try:
                fact = self.api.process(child)
                # 各条件只在 witness 里判一次（变异逐条可见）；Desktop 孩子不多，多读几次命令行可接受
                role = self.role(child, str(fact.birth))
                if not witness(int(birth), image, fact.birth, role, self.api.process_image(child, str(fact.birth))):
                    continue
                # 返回前复核两代进程事实：任何一方退出、复用或令牌变化都不产生正证
                if (self.api.process(child, expected_birth=str(fact.birth)) != fact
                        or self.api.process(pid, expected_birth=birth) != parent):
                    continue
            except OSError:
                continue
            return time.monotonic() <= self.deadline  # 复核本身跨过截止不产生正证（P3-01）
        return False
