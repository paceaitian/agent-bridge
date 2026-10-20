"""Authenticated read and W2 add scopes. Legacy add/delete clients stay disabled.

No provider JSON here: BoundedConnection owns protocol and budgets. The stream
pins filesystem epochs and authenticates the kernel peer before application IO.
"""
from __future__ import annotations
from contextlib import ExitStack, contextmanager
from contextvars import ContextVar
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
import time
from typing import Any, TYPE_CHECKING

from ..null_transport import UnsupportedPlatform
from ..transport_types import ByteStream, LocalFailure, WINDOWS_READ_SECONDS
from .files import WindowsPaths

if TYPE_CHECKING:
    from .api import ProcessFact


@dataclass(frozen=True)
class IdentityEvidence:
    """Peer/local root proof only; never claims that loaded discovery ran."""
    root_identity: str
    daemon: tuple[int, str]


class WindowsPlatform(UnsupportedPlatform):
    # Legacy provider-write qualification. A doctor read scope does not grant it.
    supported = False

    def __init__(self, api: Any, files: WindowsPaths) -> None:
        self.api, self.files = api, files
        self._read = ContextVar('windows_codex_read', default=False)
        self._budget = ContextVar('windows_codex_budget', default=WINDOWS_READ_SECONDS)

    def codex_cli_version(self) -> str | None:
        try:
            self.api.current_token()  # native platform/identity, no connection
            from .codex_version import read_cli_version  # layout: allow 版本外调才加载subprocess，不影响Windows构造的纯导入门
            return read_cli_version()
        except OSError:
            return None

    @contextmanager
    def codex_read_scope(self, version: str) -> Iterator[None]:
        token = self._read.set(True)
        try:
            yield
        finally:
            self._read.reset(token)

    def resolve(self, link: Path) -> Path | LocalFailure:
        if not self._read.get():
            return LocalFailure('windows_provider_not_enabled')
        if link != self.control_socket_path(self.files.codex_home()):
            return LocalFailure('socket_rejected')
        try:
            self.files.validate_socket(link, external=True)
            return link
        except OSError as error:
            return LocalFailure('socket_missing' if getattr(error, 'winerror', None) in (2, 3)
                                else 'socket_rejected')

    @contextmanager
    def codex_add_scope(self, version: str) -> Iterator[None]:
        """Only the W2 transport uses this scope; legacy add/delete stay disabled."""
        token = self._budget.set(600.0)
        try:
            with self.codex_read_scope(version):
                yield
        finally:
            self._budget.reset(token)

    def new_stream(self) -> ByteStream:
        if not self._read.get():
            raise OSError('windows_provider_not_enabled')
        return DaemonStream(self)

    def connect(self, stream: ByteStream, target: Path) -> None:
        if not self._read.get() or not isinstance(stream, DaemonStream) or stream.platform is not self:
            raise OSError('windows_provider_not_enabled')
        if target != self.control_socket_path(self.files.codex_home()):
            raise OSError('socket_rejected')
        stream.connect(target)

    def peer_pid(self, stream: ByteStream) -> int | None:
        if not isinstance(stream, DaemonStream) or stream.platform is not self:
            return None
        return stream.authenticated_peer().pid

    def root_identity(self, home: Path, sqlite_home: Path | None = None) -> str | None:
        return self.files.root_identity(home, sqlite_home)

    def read_identity(self, stream: ByteStream) -> tuple[int, str]:
        if not isinstance(stream, DaemonStream) or stream.platform is not self:
            raise OSError('peer_rejected')
        fact = stream.verify_peer()  # semantic generation boundary, not per-frame IO
        return fact.pid, str(fact.birth)

    def caller_identity(self) -> IdentityEvidence:
        """Authenticate and close the control socket without application bytes."""
        files = self.files
        home, sql_root = files.codex_home(), files.codex_sqlite_home()
        with self.codex_read_scope('unknown'), files.external_directory(home), files.external_directory(sql_root or home):
            root = files.root_identity(home, sql_root)
            if not root:
                raise OSError('windows_root_unverified')
            stream = self.new_stream()
            try:
                self.connect(stream, self.control_socket_path(home))
                peer = self.read_identity(stream)
                if files.root_identity(home, sql_root) != root:
                    raise OSError('windows_root_changed')
                return IdentityEvidence(root, peer)
            finally:
                stream.close()

    def socket_identity(self, link: Path) -> tuple[str, int, int, int] | None:
        if not self._read.get():
            return None
        return self.files.socket_identity(link, external=True)

    def home_equal(self, reported: str, expected: Path) -> bool:
        return self.files.home_equal(reported, expected)

    def logon_info(self, stream: ByteStream) -> dict[str, object]:
        from .logon import logon_info  # layout: allow 只有已认证连接才加载Win32诊断，构造/help不导入ctypes
        if not isinstance(stream, DaemonStream) or stream.platform is not self:
            return {'logonType': 'UNKNOWN'}
        return logon_info(self.api, stream.authenticated_peer())


class DaemonStream:
    def __init__(self, platform: WindowsPlatform) -> None:
        from .io import WinIO  # layout: allow 只在显式平台scope内构造native流，版本不作资格
        self.platform = platform
        self.io = WinIO(platform.api)
        self.resources = ExitStack()
        self.handle: int | None = None
        self.peer: ProcessFact | None = None
        self.link: Path | None = None
        self.home: Path | None = None
        self.epoch: tuple[str, int, int, int] | None = None
        self.root: str | None = None
        self.deadline = time.monotonic() + platform._budget.get()

    def settimeout(self, value: float) -> None:
        if not 0 < value <= 600:
            raise TimeoutError('windows_io_deadline')
        # A later settimeout never renews the total budget.
        self.deadline = min(self.deadline, time.monotonic() + value)

    def connect(self, target: Path) -> None:
        if self.handle is not None:
            raise OSError('windows_stream_already_connected')
        files = self.platform.files
        try:
            self.link, self.home = target, target.parent.parent
            self.resources.enter_context(files.lease(target.parent, external=True))
            self.epoch = files.socket_identity(target, external=True)
            self.root = files.root_identity(self.home)
            if self.root is None:
                raise OSError('windows_root_unverified')
            self.handle = self.io.socket()
            self.io.connect_unix(self.handle, str(target), self.deadline)
            pid = self.io.peer_pid(self.handle)
            self.peer = self.platform.api.process(pid)
            self.verify()  # includes second FILETIME observation, before any HTTP
        except BaseException:
            self.close()
            raise

    def verify(self) -> ProcessFact:
        fact = self.verify_peer()
        files = self.platform.files
        assert self.home is not None and self.link is not None
        if (files.socket_identity(self.link, external=True) != self.epoch
                or files.root_identity(self.home) != self.root):
            raise OSError('windows_root_changed')
        return fact

    def verify_peer(self) -> ProcessFact:
        if self.handle is None or self.peer is None or self.home is None or self.link is None:
            raise OSError('windows_peer_unverified')
        api = self.platform.api
        pid = self.io.peer_pid(self.handle)
        if pid != self.peer.pid:
            raise OSError('windows_peer_unverified')
        current = api.current_token()
        fact = api.process(pid, expected_birth=str(self.peer.birth))
        if (fact.birth != self.peer.birth or fact.token.sid != current.sid
                or fact.token.elevated or current.elevated):
            raise OSError('windows_peer_unverified')
        return fact

    def sendall(self, data: bytes) -> None:
        assert self.handle is not None
        self.io.socket_write(self.handle, data, self.deadline)

    def recv(self, size: int) -> bytes:
        assert self.handle is not None
        return self.io.socket_read(self.handle, size, self.deadline)

    def authenticated_peer(self) -> ProcessFact:
        # This connected socket cannot be replaced by a new process. Writes
        # retain the independent codex_delivery.unchanged boundary checks.
        if self.handle is None or self.peer is None:
            raise OSError('windows_peer_unverified')
        return self.peer

    def close(self) -> None:
        try:
            if self.handle is not None:
                handle, self.handle = self.handle, None
                self.io.close_socket(handle)
        finally:
            self.resources.close()
