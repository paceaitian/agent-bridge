"""既有进程投影的纯值；Linux ticks 语义不变。"""
from dataclasses import dataclass
from pathlib import Path

DEFAULT_PROC = Path("/proc")

@dataclass(frozen=True)
class ProcessInfo:
    """一个进程的最小身份：PID 加启动时刻（clock ticks）才能排除 PID 复用。"""

    pid: int
    ppid: int
    comm: str
    start_ticks: str
    tty_nr: int = 0  # 控制终端设备号，0 表示没有控制终端
