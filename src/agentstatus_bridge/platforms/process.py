"""P 的既有 Linux 投影接口：统一经组合根，保留 None/bool 恢复合同。

不是三态自动转换器：未实现兼容投影的平台必须显性拒绝，不能 UNKNOWN=>False。
"""
from pathlib import Path
from .factory import get_platform
from .process_values import ProcessInfo, DEFAULT_PROC
from .types import Presence, ProcessIdentity


def windows_presence(pid: int, stored: str) -> Presence:
    if not stored.startswith('win-filetime:'):
        return Presence.UNKNOWN
    return get_platform().process.same_generation(ProcessIdentity('windows', pid, 'win-filetime', stored[13:]))


def read_process(pid: int, proc_root: Path = DEFAULT_PROC) -> ProcessInfo | None:
    return get_platform().process.legacy().read_process(pid, proc_root)


def ancestry(pid: int, proc_root: Path = DEFAULT_PROC) -> list[ProcessInfo]:
    return get_platform().process.legacy().ancestry(pid, proc_root)


def list_pids(proc_root: Path = DEFAULT_PROC) -> list[int]:
    return get_platform().process.legacy().list_pids(proc_root)


def open_file_targets(pid: int, proc_root: Path = DEFAULT_PROC) -> list[str]:
    return get_platform().process.legacy().open_file_targets(pid, proc_root)


def open_file_scan(pid: int, proc_root: Path = DEFAULT_PROC) -> tuple[list[str], bool]:
    return get_platform().process.legacy().open_file_scan(pid, proc_root)


def launch_tokens(pid: int, proc_root: Path = DEFAULT_PROC) -> list[str]:
    return get_platform().process.legacy().launch_tokens(pid, proc_root)


def is_same_generation(pid: int, start_ticks: str, proc_root: Path = DEFAULT_PROC) -> bool:
    return get_platform().process.legacy().is_same_generation(pid, start_ticks, proc_root)


def pid_namespace(proc_root: Path = DEFAULT_PROC) -> str | None:
    if get_platform().name == 'windows':
        return get_platform().process.pid_namespace()
    return get_platform().process.legacy().pid_namespace(proc_root)


def _argv_tokens(pid: int, proc_root: Path = DEFAULT_PROC) -> tuple[list[str], bool]:
    return get_platform().process.legacy()._argv_tokens(pid, proc_root)
