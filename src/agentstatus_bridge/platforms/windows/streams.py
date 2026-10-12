"""Concrete byte streams for explicit W1 fixtures; provider registry stays empty."""
from __future__ import annotations
from contextlib import ExitStack
from pathlib import Path
import time
from typing import Any

from ..types import ProcessIdentity
from .files import WindowsPaths
from .io import WinIO


class PeerStream:
    def __init__(self, api: Any, expected: ProcessIdentity, timeout: float) -> None:
        self.api, self.io, self.expected = api, WinIO(api), expected
        self.timeout = timeout
        self.settimeout(timeout)
        self.handle: int | None = None
        self.resources = ExitStack()

    def settimeout(self, value: float) -> None:
        if not 0 < value <= 600:
            raise ValueError('windows_timeout_invalid')
        self.timeout = value

    def verify_peer(self, *, pipe: bool = False, server: bool = False) -> None:
        if self.handle is None:
            raise OSError('windows_stream_closed')
        pid = self.io.peer_pid(self.handle, pipe=pipe, server=server)
        fact = self.api.process(pid)
        me = self.api.current_token()
        if (self.expected.platform != 'windows' or self.expected.generation_kind != 'win-filetime'
                or pid != self.expected.pid or str(fact.birth) != self.expected.generation_value
                or fact.token.sid != me.sid or fact.token.elevated or me.elevated):
            raise OSError('windows_peer_unverified')


class WinsockStream(PeerStream):
    def __init__(self, api: Any, files: WindowsPaths, address: Path, expected: ProcessIdentity, timeout: float = 1.0) -> None:
        super().__init__(api, expected, timeout)
        try:
            self.resources.enter_context(files.lease(address.parent))
            files.validate_socket(address)
            self.handle = self.io.socket()
            self.io.connect_unix(self.handle, str(address), time.monotonic() + timeout)
            self.verify_peer()
        except BaseException:
            self.close()
            raise

    def sendall(self, data: bytes) -> None:
        self.verify_peer()
        assert self.handle is not None
        self.io.socket_write(self.handle, data, time.monotonic() + self.timeout)

    def recv(self, size: int) -> bytes:
        self.verify_peer()
        if size <= 0:
            return b''
        assert self.handle is not None
        return self.io.socket_read(self.handle, size, time.monotonic() + self.timeout)

    def close(self) -> None:
        try:
            if self.handle is not None:
                handle, self.handle = self.handle, None
                self.io.close_socket(handle)
        finally:
            self.resources.close()


class PipeStream(PeerStream):
    def __init__(self, api: Any, files: WindowsPaths, root: Path, address: str, expected: ProcessIdentity,
                 timeout: float = 1.0, *, server_handle: int | None = None) -> None:
        super().__init__(api, expected, timeout)
        self.server = server_handle is not None
        self.handle = server_handle  # constructor failures must also release an accepted handle
        try:
            self.resources.enter_context(files.lease(root))
            self.handle = server_handle if server_handle is not None else self.io.open_pipe(address)
            self.api.check_private(self.handle)
            self.verify_peer(pipe=True, server=self.server)
        except BaseException:
            self.close()
            raise

    def sendall(self, data: bytes) -> None:
        self.verify_peer(pipe=True, server=self.server)
        assert self.handle is not None
        deadline, offset = time.monotonic() + self.timeout, 0
        try:
            while offset < len(data):
                count = self.io.pipe_io(self.handle, 'write', data[offset:offset+65536], deadline)
                if not isinstance(count, int) or not 0 < count <= min(65536, len(data)-offset):
                    raise OSError('windows_pipe_disconnected')
                offset += count
        except BaseException:
            self.close()
            raise

    def recv(self, size: int) -> bytes:
        self.verify_peer(pipe=True, server=self.server)
        if size <= 0:
            return b''
        assert self.handle is not None
        try:
            data = self.io.pipe_io(self.handle, 'read', min(size,65536), time.monotonic()+self.timeout)
        except BaseException:
            self.close()
            raise
        assert isinstance(data, bytes)
        return data

    def close(self) -> None:
        try:
            if self.handle is not None:
                handle, self.handle = self.handle, None
                if not self.io.close_pipe(handle, self.resources):
                    self.resources = ExitStack()  # ownership transferred to cancellation quarantine
        finally:
            self.resources.close()


class PipeListener:
    """One fixture connection, no worker registration or application authentication."""
    def __init__(self, api: Any, files: WindowsPaths, root: Path, name: str) -> None:
        self.api, self.files, self.root, self.name = api, files, root, name
        self.io, self.resources, self.handle = WinIO(api), ExitStack(), None
        try:
            self.resources.enter_context(files.lease(root))
            self.handle = self.io.create_pipe(name)
            api.check_private(self.handle)
        except BaseException:
            self.close()
            raise

    def accept(self, expected: ProcessIdentity, timeout: float = 1.0) -> PipeStream:
        if self.handle is None:
            raise OSError('windows_listener_closed')
        self.io.pipe_io(self.handle, 'accept', 0, time.monotonic()+timeout)
        handle, self.handle = self.handle, None
        try:
            return PipeStream(self.api,self.files,self.root,self.name,expected,timeout,server_handle=handle)
        finally:
            self.resources.close()

    def close(self) -> None:
        try:
            if self.handle is not None:
                handle, self.handle = self.handle, None
                if not self.io.close_pipe(handle, self.resources):
                    self.resources = ExitStack()
        finally:
            self.resources.close()
