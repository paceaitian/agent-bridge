"""Win32 local byte I/O, no provider protocol, credentials, or discovery.

The audit event is immediately before the two native connection calls. Test
guards abort with BaseException, so RPC cannot turn a forbidden connect into
a fallback. Cancellation holds buffers until completion (including failure).
"""
from __future__ import annotations
import ctypes as C
from dataclasses import dataclass
import math
import sys
import threading
import time
from typing import Any

from . import abi as A
from .api import WinFailure


@dataclass
class Pending:
    api: Any
    handle: int
    overlap: A.OVERLAPPED
    buffer: Any
    count: A.DWORD
    resources: Any = None
    owned: bool = False


# If a driver refuses cancellation, bounded return must not free live buffers.
# No new pipe IO until quarantined operations complete; not an unbounded queue.
_quarantine: list[Pending] = []
_quarantine_lock = threading.RLock()


def reap() -> bool:
    with _quarantine_lock:
        for pending in list(_quarantine):
            api = pending.api
            ok = api.k.GetOverlappedResult(pending.handle, C.byref(pending.overlap), C.byref(pending.count), False)
            if ok or api.last_error() != 996:
                api.close(pending.overlap.event)
                if pending.owned:
                    api.close(pending.handle)
                if pending.resources is not None:
                    pending.resources.close()
                _quarantine.remove(pending)
        return not _quarantine


def remaining_ms(deadline: float) -> int:
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise TimeoutError('windows_io_deadline')
    return min(0xfffffffe, max(1, math.ceil(remaining * 1000)))


def unix_address(address: str) -> A.SOCKADDR_UN:
    try:
        raw = address.encode('utf-8')
    except UnicodeEncodeError as error:
        raise OSError('windows_socket_path_invalid') from error
    if not raw or len(raw) >= 108 or b'\0' in raw:
        raise OSError('windows_socket_path_invalid')
    return A.SOCKADDR_UN(1, raw)


def local_pipe(address: str) -> bool:
    """One local leaf, optionally under Windows' LOCAL namespace; never UNC."""
    if not isinstance(address, str) or not address.startswith('\\\\.\\pipe\\'):
        return False
    leaf = address[9:]
    if leaf[:6].upper() == 'LOCAL\\':
        leaf = leaf[6:]
    return bool(leaf) and not any(c in leaf for c in '\\/\x00:') and leaf not in {'.', '..'}


class WinIO:
    def __init__(self, api: Any) -> None:
        self.api = api

    def socket(self) -> int:
        ws = self.api.ws
        data = C.create_string_buffer(512)  # WSADATA <= 408 bytes on supported Win64
        result = ws.WSAStartup(0x202, data)
        if result:
            raise WinFailure(result)
        handle = ws.socket(1, 1, 0)
        try:
            if handle == A.INVALID:
                raise WinFailure(ws.WSAGetLastError())
            self.api.check(self.api.k.SetHandleInformation(handle, 1, 0))
            mode = A.DWORD(1)
            if ws.ioctlsocket(handle, -2147195266, C.byref(mode)) == -1:  # FIONBIO 0x8004667e
                raise WinFailure(ws.WSAGetLastError())
            return handle
        except BaseException:
            if handle != A.INVALID:
                ws.closesocket(handle)
            ws.WSACleanup()
            raise

    def close_socket(self, handle: int) -> None:
        try:
            if self.api.ws.closesocket(handle) == -1:
                raise WinFailure(self.api.ws.WSAGetLastError())
        finally:
            self.api.ws.WSACleanup()

    def wait_socket(self, handle: int, deadline: float, *, write: bool) -> None:
        ms = remaining_ms(deadline)
        target, errors = A.FD_SET(), A.FD_SET()
        target.count = errors.count = 1
        target.sockets[0] = errors.sockets[0] = handle
        timeout = A.TIMEVAL(ms // 1000, (ms % 1000) * 1000)
        result = self.api.ws.select(0, None if write else C.byref(target), C.byref(target) if write else None,
                                    C.byref(errors), C.byref(timeout))
        if result == -1:
            raise WinFailure(self.api.ws.WSAGetLastError())
        if result == 0:
            raise TimeoutError('windows_io_deadline')
        error, size = A.DWORD(), C.c_int32(4)
        if self.api.ws.getsockopt(handle, 0xffff, 0x1007, C.byref(error), C.byref(size)) == -1:
            raise WinFailure(self.api.ws.WSAGetLastError())
        if error.value:
            raise WinFailure(error.value)

    def connect_unix(self, handle: int, address: str, deadline: float) -> None:
        value = unix_address(address)
        remaining_ms(deadline)
        sys.audit('agent_bridge.windows.connect', 'unix', address)
        result = self.api.ws.connect(handle, C.byref(value), C.sizeof(value))
        if result == -1:
            error = self.api.ws.WSAGetLastError()
            if error not in (10035, 10036):
                raise WinFailure(error)
            self.wait_socket(handle, deadline, write=True)

    def peer_pid(self, handle: int, *, pipe: bool = False, server: bool = False) -> int:
        pid, count = A.DWORD(), A.DWORD()
        if pipe:
            fn = self.api.k.GetNamedPipeClientProcessId if server else self.api.k.GetNamedPipeServerProcessId
            self.api.check(fn(handle, C.byref(pid)))
        else:
            if self.api.ws.WSAIoctl(handle, 0x58000100, None, 0, C.byref(pid), 4,
                                    C.byref(count), None, None) == -1:
                raise WinFailure(self.api.ws.WSAGetLastError())
            if count.value not in (0, 4):
                raise OSError('windows_peer_unverified')
        if pid.value <= 0:
            raise OSError('windows_peer_unverified')
        return int(pid.value)

    def socket_write(self, handle: int, data: bytes, deadline: float) -> None:
        offset = 0
        while offset < len(data):
            remaining_ms(deadline)
            chunk = data[offset:offset + 65536]
            buf = C.create_string_buffer(chunk)
            count = self.api.ws.send(handle, buf, len(chunk), 0)
            if count == -1:
                if self.api.ws.WSAGetLastError() != 10035:
                    raise WinFailure(self.api.ws.WSAGetLastError())
                self.wait_socket(handle, deadline, write=True)
                continue
            if not 0 < count <= len(chunk):
                raise OSError('windows_socket_disconnected')
            offset += count

    def socket_read(self, handle: int, size: int, deadline: float) -> bytes:
        buf = C.create_string_buffer(min(size, 65536))
        while True:
            remaining_ms(deadline)
            count = self.api.ws.recv(handle, buf, len(buf), 0)
            if count >= 0:
                if count > len(buf):
                    raise OSError('windows_io_invalid_count')
                return buf.raw[:count]
            if self.api.ws.WSAGetLastError() != 10035:
                raise WinFailure(self.api.ws.WSAGetLastError())
            self.wait_socket(handle, deadline, write=False)

    def open_pipe(self, address: str) -> int:
        if not local_pipe(address):
            raise OSError('windows_pipe_path_invalid')
        if not reap():
            raise OSError('windows_cancel_pending')
        # SECURITY_IDENTIFICATION: do not grant an untrusted server impersonation.
        sys.audit('agent_bridge.windows.connect', 'pipe', address)
        return self.api.handle(self.api.k.CreateFileW(A.wide(address), 0xc0000000 | 0x20000, 0,
                               None, 3, 0x40000000 | 0x110000, None))

    def create_pipe(self, address: str) -> int:
        if not local_pipe(address):
            raise OSError('windows_pipe_path_invalid')
        if not reap():
            raise OSError('windows_cancel_pending')
        with self.api.private_attributes() as sa:
            # byte mode, reject remote, FIRST_PIPE_INSTANCE, overlapped, non-inherit.
            return self.api.handle(self.api.k.CreateNamedPipeW(A.wide(address), 3 | 0x40000000 | 0x80000,
                                      8, 1, 65536, 65536, 0, C.byref(sa)))

    def pipe_io(self, handle: int, operation: str, data: bytes | int, deadline: float) -> bytes | int:
        remaining_ms(deadline)
        if not reap():
            raise OSError('windows_cancel_pending')
        event = self.api.handle(self.api.k.CreateEventW(None, True, False, None))
        overlap = A.OVERLAPPED()
        overlap.event = event
        count = A.DWORD()
        buf = C.create_string_buffer(data if isinstance(data, bytes) else max(1, data))
        quarantined = False
        pending = False
        cancel_observed = False
        try:
            if operation == 'accept':
                ok = self.api.k.ConnectNamedPipe(handle, C.byref(overlap))
            else:
                fn = self.api.k.ReadFile if operation == 'read' else self.api.k.WriteFile
                length = len(data) if isinstance(data, bytes) else data
                ok = fn(handle, buf, length, C.byref(count), C.byref(overlap))
            if not ok:
                error = self.api.last_error()
                if error in (535, 232) and operation == 'accept':
                    # CPython PipeListener/bpo-14725: a client may have written
                    # and closed already; consume buffered data before disconnect.
                    return 0
                if error in (109, 233) and operation == 'read':
                    return b''
                if error != 997:
                    raise WinFailure(error)
                pending = True
                wait = self.api.k.WaitForSingleObject(event, remaining_ms(deadline))
                if wait != 0:
                    if wait == 258:
                        if operation == 'accept':
                            self.api.k.CancelIoEx(handle, C.byref(overlap))
                            self.api.k.WaitForSingleObject(event, 1000)
                            done = self.api.k.GetOverlappedResult(handle, C.byref(overlap), C.byref(count), False)
                            cancel_observed = True
                            if done:
                                pending = False
                                return 0  # Cancellation lost to a valid connection; do not reaccept.
                            if self.api.last_error() != 996:
                                pending = False
                        raise TimeoutError('windows_io_deadline')
                    raise WinFailure(self.api.last_error())
                ok = self.api.k.GetOverlappedResult(handle, C.byref(overlap), C.byref(count), False)
                if not ok and self.api.last_error() == 996:
                    raise OSError('windows_completion_unverified')
                pending = False
                if not ok:
                    error = self.api.last_error()
                    if error in (109, 233) and operation == 'read':
                        return b''
                    raise WinFailure(error)
            if count.value > len(buf):
                raise OSError('windows_io_invalid_count')
            return buf.raw[:count.value] if operation == 'read' else int(count.value)
        finally:
            if pending:
                if not cancel_observed:
                    self.api.k.CancelIoEx(handle, C.byref(overlap))
                    # Completion observation, not cancellation request, frees buffers.
                    self.api.k.WaitForSingleObject(event, 1000)  # one bounded cleanup grace
                    done = self.api.k.GetOverlappedResult(handle, C.byref(overlap), C.byref(count), False)
                else:
                    done = False  # Already observed IO_INCOMPLETE; retain without a second grace.
                if not done and self.api.last_error() == 996:
                    with _quarantine_lock:
                        _quarantine.append(Pending(self.api, handle, overlap, buf, count))
                    quarantined = True
            if not quarantined:
                self.api.close(event)

    def close_pipe(self, handle: int, resources: Any = None) -> bool:
        with _quarantine_lock:
            for pending in _quarantine:
                if pending.handle == handle and pending.api is self.api:
                    pending.resources = resources
                    pending.owned = True
                    return False
            self.api.close(handle)
            return True
