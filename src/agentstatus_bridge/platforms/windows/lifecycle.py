"""Windows L：LockFileEx原语；生产spawn仍关闭，fixture显式使用自己的入口。"""
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path
import os
import sys
import time
from types import FrameType
from typing import Any

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
            handle = self.api.open_file(str(path), create=True, write=True)
            assert handle is not None
            self.api.check_private(handle)
            self.api.file_info(handle)
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
        for attempt in range(5):
            try:
                self.try_lock(fd)
                return True
            except BlockingIOError:
                if attempt < 4:
                    time.sleep(0.02)
        return False

    def unlock(self, fd: int) -> None:
        self.api.unlock(fd)

    def close_lock(self, fd: int) -> None:
        try:
            self.api.close(fd)
        finally:
            self._leases.pop(fd).__exit__(None, None, None)

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
        raise OSError('windows_provider_not_enabled')

    def spawn_fixture(self, script: Path, directory: Path, *, popen: Any = None) -> Any:
        import subprocess  # layout: allow 首次fixture spawn才导入，Linux subprocess本身会加载fcntl
        popen = popen or subprocess.Popen
        self.files.validate_file(script)
        with self.files.lease(directory):
            return popen([sys.executable, str(script)], cwd=str(directory),
                         env=self.worker_environment(os.environ), stdin=subprocess.DEVNULL,
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, close_fds=True,
                         creationflags=0x00000008 | 0x00000200)  # DETACHED + NEW_GROUP; never BREAKAWAY

    def install_stop(self, handler: Callable[[int, FrameType | None], None]) -> dict[int, object]:
        raise OSError('windows_provider_not_enabled')

    def restore_stop(self, previous: Mapping[int, object]) -> None:
        if previous:
            raise OSError('windows_provider_not_enabled')

    def run_capture(self, argv: Sequence[str], timeout: float, *, replace_errors: bool = False) -> Any:
        raise OSError('windows_provider_not_enabled')
