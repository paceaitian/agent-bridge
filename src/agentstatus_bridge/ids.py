"""任务、尝试与消息使用的 128-bit 随机标识，以及与 observer 对齐的稳定哈希键。"""

from __future__ import annotations

import hashlib
import re
import secrets

_ID_PREFIX = re.compile(r"[0-9a-f]{4,32}")


def new_id() -> str:
    """生成新的 32 位十六进制标识；标识只由桥生成，调用方不能指定。"""
    return secrets.token_hex(16)


def is_id_prefix(value: str) -> bool:
    """判断是否为可用于查找的标识前缀（至少 4 位）。"""
    return bool(_ID_PREFIX.fullmatch(value))


def short(value: str) -> str:
    """显示用短标识。"""
    return value[:8]


def opaque_id(namespace: str, *parts: object) -> str:
    """稳定哈希键：`<namespace>:<sha256 前 24 位>`，用于和 observer 的会话键对齐。

    算法必须与 observer 的 `agentstatus.adapters.common.opaque_id` 逐字节一致——摘要里的绑定键靠它匹配面板会话行。
    桥要能脱离 AgentStatus 单独运行，所以这里自带一份实现，由固定向量用例与一条对照用例守住不漂移（DESIGN §45.33.7）。
    """
    digest = hashlib.sha256()
    digest.update(namespace.encode("ascii"))
    for part in parts:
        digest.update(b"\x00")
        digest.update(str(part).encode("utf-8", errors="replace"))
    return f"{namespace}:{digest.hexdigest()[:24]}"
