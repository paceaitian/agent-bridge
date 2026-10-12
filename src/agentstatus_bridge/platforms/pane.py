"""平台无关的 pane 元数据与 §53 Codex 标题投影；原文仅在调用栈中。"""
from dataclasses import dataclass, replace
import re

# Codex 标题末段的 thread-id 项（DESIGN §53.3.1）：至少到第 4 组（20 个 hex，过了 UUIDv7 的时间戳与版本位），
# 可带上游 32 字符截断的 `...` 与自动生成标题期间的 ` <Braille spinner>`
_TITLE_THREAD_ID = re.compile(
    r"(?P<id>[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}(?:-[0-9a-f]{1,12})?)(?:\.\.\.)?(?: [\u2800-\u28ff])?",
    re.IGNORECASE,
)
# 标题任意位置的 UUID 形状：只给 doctor 区分「配了但没放在末尾或与 spinner 粘连」
_TITLE_UUID_SHAPE = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}", re.IGNORECASE)

@dataclass(frozen=True)
class PaneInfo:
    pane_id: str
    pane_pid: int
    session_name: str
    server_pid: int | None = None
    # 标题末段解析出的 thread-id 前缀（小写）；原始标题不进这里（DESIGN §53.3.2）
    thread_prefix: str | None = None
    # 标题任意位置有 UUID 形状（只给 doctor 用）
    title_has_uuid: bool = False


def title_thread_prefix(title: str) -> str | None:
    """取 Codex 标题末段的 thread-id 前缀（小写）；末段不是这个形状就返回 None（DESIGN §53.3.1）。

    只看按 ` | ` 切开后的最后一段：用户的 thread 名可能就像 hex，`thread-title` 回退出的完整 UUID 也不在末段。
    """
    match = _TITLE_THREAD_ID.fullmatch(title.rsplit(" | ", 1)[-1].strip())
    return match.group("id").lower() if match is not None else None


def _with_title(pane: PaneInfo, title: str | None) -> PaneInfo:
    if title is None:
        return pane
    return replace(pane, thread_prefix=title_thread_prefix(title), title_has_uuid=_TITLE_UUID_SHAPE.search(title) is not None)
