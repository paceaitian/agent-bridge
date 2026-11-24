"""`ab tasks` 的筛选条件（DESIGN §93.1）：会话 ID 匹配、`--since` 解析与本机任务判定。

只做纯计算：不做发现、不读账本、不导入联邦实现（未配置联邦的机器跑 `ab tasks` 不加载 federation）。
本机与跨设备任务共用 `TaskFilter.accepts`，各自把参与方投影成 (provider, 会话 ID) 再交给它判。
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
import datetime
import re

from .model import UNRESOLVED_NATIVE_ID, Attempt, EndpointRef, Role, Task

# `ab tasks` 最多显示的任务条数：筛选后取最新的这么多条，再按创建时间升序显示
TASK_LIST_LIMIT = 200
_RELATIVE = re.compile(r"([1-9][0-9]*)([mhd])")
_DATE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}")
_UNIT_SECONDS = {"m": 60, "h": 3600, "d": 86400}
# --after/--expect/--in 的时长（DESIGN §104.9 一、二）：`<正整数>m` 或 `<正整数>h`
_DURATION = re.compile(r"([1-9][0-9]{0,5})([mh])")

# 参与方投影：(provider 值, 会话 ID)
Party = tuple[str, str]


class FilterError(Exception):
    """筛选参数无效，带固定原因码。"""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def parse_since(raw: str, now: float) -> float:
    """`--since` 的下限（秒）：`<正整数>m/h/d` 相对 now，`YYYY-MM-DD` 为本机时区当天 0 点。

    格式不对、日期不存在或超出可表示范围一律抛 `since_invalid`，不猜测。
    """
    relative = _RELATIVE.fullmatch(raw)
    try:
        if relative is not None:
            return now - float(int(relative[1]) * _UNIT_SECONDS[relative[2]])
        if _DATE.fullmatch(raw):
            # 不带时区的 datetime.timestamp() 按本机时区解释
            return datetime.datetime.strptime(raw, "%Y-%m-%d").timestamp()
    except (ValueError, OverflowError, OSError) as error:
        raise FilterError("since_invalid") from error
    raise FilterError("since_invalid")


def parse_duration(raw: str, *, minimum: float, maximum: float) -> float | None:
    """`30m`、`2h` 这类时长换成秒；格式不对或超出 [minimum, maximum] 返回 None，由调用方报各自的原因码。"""
    found = _DURATION.fullmatch(raw.strip())
    if found is None:
        return None
    seconds = float(int(found[1]) * _UNIT_SECONDS[found[2]])
    return seconds if minimum <= seconds <= maximum else None


@dataclass(frozen=True)
class SessionMatch:
    """按会话 ID 匹配一个参与方：provider 缺省不限；exact 为假时按 ID 前缀匹配（均为小写比较）。"""

    provider: str | None
    value: str
    exact: bool = True

    def matches(self, party: Party | None) -> bool:
        """参与方是否命中；认不出 ID 的参与方（`-`）从不命中。"""
        if party is None:
            return False
        provider, native_id = party
        if native_id == UNRESOLVED_NATIVE_ID or (self.provider is not None and provider != self.provider):
            return False
        lowered = native_id.lower()
        return lowered == self.value if self.exact else lowered.startswith(self.value)


@dataclass(frozen=True)
class TaskFilter:
    """一次 `ab tasks` 的全部筛选条件；多个条件之间是「且」，不决定是否含已结束任务（那由 `--all` 决定）。"""

    mine: SessionMatch | None = None
    to: SessionMatch | None = None
    origin: SessionMatch | None = None
    since: float | None = None
    grep: str | None = None  # 已 casefold 的字面子串

    @property
    def active(self) -> bool:
        """是否给了任何筛选条件。"""
        return any(item is not None for item in (self.mine, self.to, self.origin, self.since, self.grep))

    def accepts(self, *, origin: Party | None, reviewer: Party | None, targets: Iterable[Party],
                updated_at: float, title: str, body: str | None) -> bool:
        """按投影后的参与方与文本判定一条任务；targets 只含 handoff/review 尝试的目标（不看 notice）。"""
        workers = list(targets)
        if self.mine is not None and not (self.mine.matches(origin) or self.mine.matches(reviewer)
                                          or any(self.mine.matches(item) for item in workers)):
            return False
        if self.to is not None and not any(self.to.matches(item) for item in workers):
            return False
        if self.origin is not None and not self.origin.matches(origin):
            return False
        if self.since is not None and updated_at < self.since:
            return False
        if self.grep is not None:
            return self.grep in title.casefold() or (body is not None and self.grep in body.casefold())
        return True


def party(ref: EndpointRef | None) -> Party | None:
    """本机端点引用投影成 (provider, 会话 ID)。"""
    return None if ref is None else (ref.provider.value, ref.native_id)


def accepts_local(wanted: TaskFilter, task: Task, attempts: list[Attempt]) -> bool:
    """本机任务是否符合筛选：正文取 seq 1 那条尝试，最近活动取 `tasks.updated_at`（秒）。"""
    first = next((item for item in attempts if item.seq == 1), None)
    return wanted.accepts(
        origin=party(task.origin),
        reviewer=party(task.reviewer),
        targets=[(item.target.provider.value, item.target.native_id) for item in attempts
                 if item.role is not Role.NOTICE],
        updated_at=task.updated_at,
        title=task.title,
        body=first.body if first is not None else None,
    )
