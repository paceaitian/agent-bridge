"""§69 LocalPlatform 注入接缝，最终选择只委托 W1 组合根，不再独立选 OS。"""
from pathlib import Path
from ..platforms.factory import get_platform
from ..platforms.transport_types import LocalPlatform


def platform() -> LocalPlatform:
    return get_platform().transport


def socket_identity(link: Path) -> tuple[str, int, int, int] | None:
    return platform().socket_identity(link)
