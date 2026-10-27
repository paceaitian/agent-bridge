"""Linux L：文件锁、子进程与退出信号；不包含投递/恢复决策。"""
from __future__ import annotations
from collections.abc import Callable, Mapping, Sequence
import fcntl
import os
from pathlib import Path
import signal
import stat
import subprocess
import sys
import time
from types import FrameType

LOCK_RETRY_ATTEMPTS = 5
LOCK_RETRY_SECONDS = 0.02
# 拉起 worker 的可能是某个 agent 会话里的命令；这些变量属于那个会话，不能带进常驻 worker
# （worker 再调用 codex queue 时也不应带着发起会话的 thread/权限变量）。
# 每加一个 provider，这里要覆盖它在 ADAPTERS 里声明的 env markers——有用例按注册表逐个核对（DESIGN §45.34）
_SESSION_ENV_PREFIXES = ("CLAUDE_CODE_", "CODEX_", "GROK_")
_SESSION_ENV_NAMES = frozenset({"CLAUDECODE", "CLAUDE_PID"})
# 数据根指针不是会话身份：剥掉它们 worker 会去看另一个目录，发现结果与调用方不一致
_KEEP_ENV = frozenset({"CODEX_HOME", "CODEX_SQLITE_HOME", "GROK_HOME"})

def worker_path(path: str | None) -> str:
    """worker 的 PATH：调用方原有顺序不变，缺 ~/.local/bin 时补在末尾（DESIGN §45.30）。

    扩展从 gnome-shell 调用 `ab summary --if-stale` 时 PATH 没有 ~/.local/bin，而 codex 装在那里；
    与 agentstatus.service 给自己的私有 PATH 补同一目录是同一做法。只追加不前置，调用方已有的同名命令仍优先。
    PATH 为空或未设置时先取系统默认路径 os.defpath，与 exec 和 shutil.which 在未设置时的回退一致；其余情况原样保留调用方的字符串。
    """
    local_bin = str(Path.home() / ".local" / "bin")
    current = path if path and any(path.split(os.pathsep)) else os.defpath
    # 末尾带 / 的同一目录也算已有；重复构造不会重复追加
    if any(os.path.normpath(segment) == local_bin for segment in current.split(os.pathsep) if segment):
        return current
    return f"{current}{os.pathsep}{local_bin}"


def worker_environment(base: Mapping[str, str]) -> dict[str, str]:
    """worker 环境：去掉调用方会话私有变量，保证能导入本包、能找到 ~/.local/bin 下的 codex。"""
    env = {
        key: value
        for key, value in base.items()
        if key in _KEEP_ENV or (key not in _SESSION_ENV_NAMES and not key.startswith(_SESSION_ENV_PREFIXES))
    }
    package_parent = str(Path(__file__).resolve().parents[3])
    existing = env.get("PYTHONPATH")
    env["PYTHONPATH"] = package_parent if not existing else f"{package_parent}{os.pathsep}{existing}"
    env["PATH"] = worker_path(env.get("PATH"))
    return env


def _acquire_worker_lock(fd: int) -> bool:
    """取单实例排他锁；被占用时短暂重试，只有一直拿不到（另一个 worker 在持有）才放弃。

    旧实现一次失败就退出：探测恰好瞬时持锁的那一刻，新拉起的 worker 会以为已有实例而退出，结果一个 worker 都没有。
    """
    for attempt in range(LOCK_RETRY_ATTEMPTS):
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            return True
        except BlockingIOError:
            if attempt + 1 < LOCK_RETRY_ATTEMPTS:
                time.sleep(LOCK_RETRY_SECONDS)
    return False


class LinuxLifecycle:
    worker_environment = staticmethod(worker_environment)
    acquire_worker_lock = staticmethod(_acquire_worker_lock)

    @staticmethod
    def run_capture(argv: Sequence[str], timeout: float, *, replace_errors: bool = False) -> subprocess.CompletedProcess[str]:
        if replace_errors:
            return subprocess.run(list(argv), stdin=subprocess.DEVNULL, capture_output=True, text=True,
                                  errors="replace", timeout=timeout, check=False)
        return subprocess.run(list(argv), stdin=subprocess.DEVNULL, capture_output=True, text=True,
                              timeout=timeout, check=False)

    @staticmethod
    def open_lock(path: Path, *, nofollow: bool = False) -> int:
        return os.open(path, os.O_RDWR | os.O_CREAT | (os.O_NOFOLLOW if nofollow else 0), 0o600)

    @staticmethod
    def try_lock(fd: int, *, shared: bool = False) -> None:
        fcntl.flock(fd, (fcntl.LOCK_SH if shared else fcntl.LOCK_EX) | fcntl.LOCK_NB)

    @staticmethod
    def unlock(fd: int) -> None:
        fcntl.flock(fd, fcntl.LOCK_UN)

    @staticmethod
    def close_lock(fd: int) -> None:
        os.close(fd)

    @staticmethod
    def probe_lock(path: Path) -> bool:
        """只读瞬时探测已有锁文件是否被他人持有（DESIGN §90.6）：忙=True、可取=False。

        O_RDONLY、不带 O_CREAT：锁文件或上级目录不存在时抛 FileNotFoundError，绝不新建；共享锁取到即释放。
        O_NONBLOCK 让 FIFO 不在 open 上阻塞；打开后必须是普通文件且只有一个链接，否则抛 OSError 由调用方判未知
        （目录也能 flock，不能把它当成「可取」；Codex AS90-I-C-P3-01）。
        """
        fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NONBLOCK | os.O_NOCTTY)
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                raise OSError("relay_lock_untrusted")
            try:
                fcntl.flock(fd, fcntl.LOCK_SH | fcntl.LOCK_NB)
            except BlockingIOError:
                return True
            fcntl.flock(fd, fcntl.LOCK_UN)
            return False
        finally:
            os.close(fd)

    @staticmethod
    def spawn_worker(directory: Path, env: Mapping[str, str]) -> None:
        subprocess.Popen(
            [sys.executable, "-m", "agentstatus_bridge", "worker"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            close_fds=True,
            start_new_session=True,
            cwd=str(directory),
            env=env,
        )

    @staticmethod
    def install_stop(handler: Callable[[int, FrameType | None], None]) -> dict[int, object]:
        return {number: signal.signal(number, handler) for number in (signal.SIGTERM, signal.SIGINT)}

    @staticmethod
    def restore_stop(previous: Mapping[int, object]) -> None:
        for number, handler in previous.items():
            signal.signal(number, handler)  # type: ignore[arg-type]

