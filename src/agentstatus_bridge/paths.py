"""F 组合根入口；既有路径函数是正式公共接口，不再拥有 Linux 系统调用。"""
from pathlib import Path

from .platforms.factory import get_platform


def state_base() -> Path:
    return get_platform().files.state_base()


def state_dir() -> Path:
    return get_platform().files.state_dir()


def state_dir_source() -> str:
    return get_platform().files.state_dir_source()


def device_name() -> str:
    return get_platform().files.device_name()


def codex_home() -> Path:
    return get_platform().files.codex_home()


def codex_sqlite_home() -> Path | None:
    return get_platform().files.codex_sqlite_home()


def grok_home() -> Path:
    return get_platform().files.grok_home()


def claude_sessions_dir() -> Path:
    return get_platform().files.claude_sessions_dir()

def ensure_private_dir(path: Path) -> Path:
    return get_platform().files.ensure_private_dir(path)
