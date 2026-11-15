"""Windows L：LockFileEx、带代际/镜像回执的W2 worker与单独fixture入口。"""
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path
import os
import sys
import time
import secrets
import signal
from types import FrameType
from typing import Any

from ..lock_retry import retry_lock
from .files import WindowsPaths


class WindowsLifecycle:
    def __init__(self, api: Any, files: WindowsPaths) -> None:
        self.api, self.files = api, files
        self._leases: dict[int, Any] = {}

    def open_lock(self, path: Path, *, nofollow: bool = False) -> int:
        lease = self.files.lease(path.parent, create=True)
        lease.__enter__()
        handle: int | None = None
        try:
            handle = self.files.open_private_file(path, create=True, write=True)
            assert handle is not None
            info = self.api.file_info(handle)
            if info.attributes & 0x10 or info.links != 1:
                raise OSError('windows_file_untrusted')
            self.files.ensure_private(handle, path)
            self._leases[handle] = lease
            return handle
        except BaseException:
            if handle is not None:
                self.api.close(handle)
            lease.__exit__(*sys.exc_info())
            raise

    def try_lock(self, fd: int, *, shared: bool = False) -> None:
        self.api.lock(fd, shared=shared)

    def acquire_worker_lock(self, fd: int) -> bool:
        """取单实例排他锁；被占用时按与 Linux 共用的时间预算重试（DESIGN §95.2）。"""
        return retry_lock(lambda: self.try_lock(fd))

    def unlock(self, fd: int) -> None:
        self.api.unlock(fd)

    def close_lock(self, fd: int) -> None:
        try:
            self.api.close(fd)
        finally:
            self._leases.pop(fd).__exit__(None, None, None)

    def probe_lock(self, path: Path) -> bool:
        """只读瞬时探测已有锁文件是否被他人持有（DESIGN §90.6）：忙=True、可取=False。

        OPEN_EXISTING、只读数据访问，不经 lease/open_private_file/ensure_private：不建目录或文件、不修 ACL。
        文件或路径不存在（2/3）抛 FileNotFoundError；其余失败（含拒绝访问）原样上抛，由调用方判未知。
        句柄不进 _leases，本函数自己关闭。
        """
        try:
            handle = self.api.open_file(str(path), read_data=True)
        except OSError as error:
            if getattr(error, 'winerror', None) in (2, 3):
                raise FileNotFoundError(str(path)) from error
            raise
        try:
            info = self.api.file_info(handle)
            if info.attributes & 0x10 or info.links != 1:
                raise OSError('windows_file_untrusted')
            try:
                self.api.lock(handle, shared=True)
            except BlockingIOError:
                return True
            self.api.unlock(handle)
            return False
        finally:
            self.api.close(handle)

    def worker_environment(self, base: Mapping[str, str]) -> dict[str, str]:
        env: dict[str, str] = {}
        for key, value in base.items():
            upper = key.upper()
            if upper in {'CODEX_HOME', 'CODEX_SQLITE_HOME', 'GROK_HOME'} or (
                    upper not in {'CLAUDECODE', 'CLAUDE_PID'} and not upper.startswith(('CLAUDE_CODE_', 'CODEX_', 'GROK_'))):
                env[upper] = value
        env['PYTHONPATH'] = str(Path(__file__).resolve().parents[3])
        return env

    def spawn_worker(self, directory: Path, env: Mapping[str, str]) -> None:
        from . import worker_identity as identity  # layout: allow 真实worker代际和镜像，不复用fixture入口
        with self.files.lease(directory):
            expected_image = identity.image_identity(self.files, identity.executable())
            launch = dict(env)
            launch[identity.TOKEN_ENV] = token = secrets.token_hex(16)
            child = self._spawn([str(identity.executable()), '-m', 'agentstatus_bridge', 'worker'],
                                directory, launch)
            fact = self.api.process(child.pid)
            deadline = time.monotonic()+10.0
            while True:
                try:
                    identity.verify(self.files, directory, pid=child.pid, birth=str(fact.birth), token=token,
                                    expected_image=expected_image)
                    return
                except OSError:
                    if time.monotonic() >= deadline:
                        raise OSError('worker_identity_unverified')
                    time.sleep(0.05)

    def spawn_fixture(self, script: Path, directory: Path, *, popen: Any = None) -> Any:
        self.files.validate_file(script)
        with self.files.lease(directory):
            return self._spawn([sys.executable, str(script)], directory, self.worker_environment(os.environ), popen)

    def _spawn(self, argv: list[str], directory: Path, env: Mapping[str, str], popen: Any = None) -> Any:
        import subprocess  # layout: allow 两条显式spawn入口共用；仍有可登记的字面Popen调用
        from .worker_identity import BREAKAWAY_ENV  # layout: allow 私有启动回执的观察字段
        launch = dict(env)
        launch[BREAKAWAY_ENV] = 'requested'
        def create(flags: int) -> Any:
            if popen is not None:  # explicit fixture injection, never production
                return popen(argv, cwd=str(directory), env=dict(launch), stdin=subprocess.DEVNULL,
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, close_fds=True, creationflags=flags)
            return subprocess.Popen(argv, cwd=str(directory), env=dict(launch), stdin=subprocess.DEVNULL,
                                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, close_fds=True, creationflags=flags)
        # BREAKAWAY|CREATE_NO_WINDOW|NEW_PROCESS_GROUP，不用 DETACHED_PROCESS：没有控制台的进程再拉控制台子进程
        # （worker 投递 Codex 前的 `codex --version`）时，系统会给子进程新开可见控制台，桌面会话里闪出 WT 窗口
        # （DESIGN §89）；无窗口控制台由这些子进程继承，worker 自己的控制台也不受父窗口关闭影响
        try:
            return create(0x09000200)
        except OSError as error:
            if getattr(error, 'winerror', None) != 5:
                raise
            launch[BREAKAWAY_ENV] = 'denied_fallback'
            return create(0x08000200)

    def install_stop(self, handler: Callable[[int, FrameType | None], None]) -> dict[int, object]:
        return {number: signal.signal(number, handler) for number in (signal.SIGINT, signal.SIGTERM)}

    def restore_stop(self, previous: Mapping[int, object]) -> None:
        for number, handler in previous.items():
            signal.signal(number, handler)  # type: ignore[arg-type]

    def run_capture(self, argv: Sequence[str], timeout: float, *, replace_errors: bool = False) -> Any:
        # Only report's read-only commit validation, never codex queue fallback.
        if (len(argv) != 7 or argv[0] != 'git' or argv[1] != '-C'
                or list(argv[3:6]) != ['rev-parse', '--verify', '--quiet'] or not argv[6].endswith('^{commit}')):
            raise OSError('windows_provider_not_enabled')
        import subprocess  # layout: allow 只读提交号核验，显式编码
        return subprocess.run(list(argv), stdin=subprocess.DEVNULL, capture_output=True,
                              text=True, encoding='utf-8', errors='replace', timeout=timeout, check=False)
