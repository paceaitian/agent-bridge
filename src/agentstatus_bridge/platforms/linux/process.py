"""Linux /proc 原语；从 procfs 原样下沉，旧 None/bool/字节窗口合同不改。"""

from __future__ import annotations

from ..process_values import ProcessInfo, DEFAULT_PROC
import os
from pathlib import Path



def pid_namespace(proc_root: Path = DEFAULT_PROC) -> str | None:
    """本进程可比较的 PID 命名空间标识；不读命令/环境，读不到不猜。"""
    try:
        return os.readlink(proc_root / "self/ns/pid")
    except OSError:
        return None


_MAX_ANCESTRY = 64
# 识别启动模式用的有界读取：只比较已知选项与子命令名，不保存也不输出（DESIGN §45.33.2）。
# 窗口要够宽：`codex -c a=1 … -c a=16 exec` 这类长选项串若把子命令挤出窗口，就会把非交互进程当成可投递目标。
_MAX_ARGV_BYTES = 16384
_MAX_ARGV_TOKENS = 64
_MAX_ARGV_TOKEN_BYTES = 256



def read_process(pid: int, proc_root: Path = DEFAULT_PROC) -> ProcessInfo | None:
    """读取进程身份；进程不存在或格式异常时返回 None。"""
    try:
        raw = (proc_root / str(pid) / "stat").read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None
    open_at = raw.find("(")
    close_at = raw.rfind(")")
    if open_at < 0 or close_at < open_at:
        return None
    # comm 可含空格和括号，只能以最后一个右括号切分
    fields = raw[close_at + 2 :].split()
    if len(fields) < 20:
        return None
    try:
        ppid = int(fields[1])
    except ValueError:
        return None
    try:
        tty_nr = int(fields[4])
    except ValueError:
        tty_nr = 0
    return ProcessInfo(
        pid=pid, ppid=ppid, comm=raw[open_at + 1 : close_at], start_ticks=fields[19], tty_nr=tty_nr
    )


def ancestry(pid: int, proc_root: Path = DEFAULT_PROC) -> list[ProcessInfo]:
    """返回从自身到 init 的祖先链（自身在前），有长度上限防环。"""
    chain: list[ProcessInfo] = []
    seen: set[int] = set()
    current = pid
    while current > 0 and current not in seen and len(chain) < _MAX_ANCESTRY:
        seen.add(current)
        info = read_process(current, proc_root)
        if info is None:
            break
        chain.append(info)
        current = info.ppid
    return chain


def list_pids(proc_root: Path = DEFAULT_PROC) -> list[int]:
    """列出当前可见进程 PID。"""
    try:
        names = os.listdir(proc_root)
    except OSError:
        return []
    return sorted(int(name) for name in names if name.isdigit())


def open_file_targets(pid: int, proc_root: Path = DEFAULT_PROC) -> list[str]:
    """列出进程打开的文件路径（只读 fd 链接，不读取文件内容）。"""
    fd_dir = proc_root / str(pid) / "fd"
    try:
        names = os.listdir(fd_dir)
    except OSError:
        return []
    targets: list[str] = []
    for name in names:
        try:
            targets.append(os.readlink(fd_dir / name))
        except OSError:
            continue
    return targets


def launch_tokens(pid: int, proc_root: Path = DEFAULT_PROC) -> list[str]:
    """取 argv[1:] 的前若干个 token 用于识别启动模式；数量与长度都有上限，只在内存里比较。

    其中可能含 prompt 与配置取值，调用方只拿它和已知选项、子命令名比对，不保存也不输出（DESIGN §45.33.2）。
    """
    try:
        # 有界读取：cmdline 可以很长，不整份读进内存再截断
        with (proc_root / str(pid) / "cmdline").open("rb") as stream:
            raw = stream.read(_MAX_ARGV_BYTES)
    except OSError:
        return []
    parts = raw.split(b"\0")[1 : _MAX_ARGV_TOKENS + 1]
    return [item[:_MAX_ARGV_TOKEN_BYTES].decode("utf-8", errors="replace") for item in parts if item]


def is_same_generation(pid: int, start_ticks: str, proc_root: Path = DEFAULT_PROC) -> bool:
    """判断 PID 是否仍是记录时的同一进程。"""
    info = read_process(pid, proc_root)
    return info is not None and info.start_ticks == start_ticks


_PERMISSION_ARGV_BYTES = 64 * 1024


def _argv_tokens(pid: int, proc_root: Path) -> tuple[list[str], bool]:
    """读进程命令行用于识别启动标志：(token 列表, 是否读全)；只在内存里比较，不保存也不输出。

    读失败或为空（进程正在退出等）也算没读全：读不到就不声明（DESIGN §58.8 第 2 轮）。
    """
    try:
        # 有界读取：多读一个字节用来判断是否超过上限，与 procfs.launch_tokens 一致不整份读入
        with (proc_root / str(pid) / "cmdline").open("rb") as stream:
            raw = stream.read(_PERMISSION_ARGV_BYTES + 1)
    except OSError:
        return [], False
    complete = 0 < len(raw) <= _PERMISSION_ARGV_BYTES
    raw = raw[:_PERMISSION_ARGV_BYTES]
    return [part.decode("utf-8", errors="replace") for part in raw.split(b"\0") if part], complete
