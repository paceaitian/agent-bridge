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
        try:
            return create(0x01000208)
        except OSError as error:
            if getattr(error, 'winerror', None) != 5:
                raise
            launch[BREAKAWAY_ENV] = 'denied_fallback'
            return create(0x00000208)

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
