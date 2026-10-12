"""平台测试的连接边界；可独立导入，不加载 CLI/fcntl/pwd 或任何平台后端。"""
from contextlib import contextmanager
import ntpath
import os
import socket
import sys
from typing import Iterator


class ProductionSocketUse(BaseException):
    """越过 RPC 的 Exception 兜底；不可把测试违规降成可回退的连接失败。"""


def linux_roots() -> tuple[str, ...]:
    import pwd
    uid = os.getuid()
    home = pwd.getpwuid(uid).pw_dir
    return tuple(os.path.realpath(p) + os.sep for p in (
        os.path.join(home, '.codex'), f'/tmp/codex-daemon-{uid}',
        os.path.join(home, '.local/state/agentstatus/bridge'),
        os.path.join(home, '.local/state/agent-bridge'),
    ))


def check_posix(address: object, roots: tuple[str, ...], uid: int) -> None:
    if not isinstance(address, (str, bytes, os.PathLike)):
        return
    path = os.fsdecode(address)
    path = os.path.realpath(path) if path and not path.startswith('\0') else path
    if (any((path + os.sep).startswith(root) for root in roots)
            or path in {f'/run/user/{uid}/bus', '/run/dbus/system_bus_socket'}):
        raise ProductionSocketUse('production_local_endpoint')


_windows_fixtures: set[tuple[str, str]] = set()


def _windows_key(kind: str, address: str) -> tuple[str, str]:
    return kind, ntpath.normcase(ntpath.normpath(address))


def check_windows(kind: str, address: str) -> None:
    """未来 ctypes connect/CreateFile 必须在最底层调用；默认全部拒绝，不能靠 HOME 隔离。"""
    if _windows_key(kind, address) not in _windows_fixtures:
        raise ProductionSocketUse('unregistered_windows_fixture')


@contextmanager
def windows_fixture(kind: str, address: str) -> Iterator[None]:
    key = _windows_key(kind, address)
    existing = key in _windows_fixtures
    _windows_fixtures.add(key)
    try:
        yield
    finally:
        if not existing:
            _windows_fixtures.remove(key)


def install() -> None:
    if getattr(socket.socket, '_agentstatus_guarded', False):
        return
    is_posix = os.name == 'posix'
    roots = linux_roots() if is_posix else ()
    uid = os.getuid() if is_posix else -1
    original_connect, original_connect_ex = socket.socket.connect, socket.socket.connect_ex

    def check(sock: socket.socket, address: object) -> None:
        if sock.family != getattr(socket, 'AF_UNIX', None):
            return
        if is_posix:
            check_posix(address, roots, uid)
        elif isinstance(address, (str, bytes, os.PathLike)):
            check_windows('unix', os.fsdecode(address))

    def connect(self: socket.socket, address: object) -> None:
        check(self, address)
        original_connect(self, address)

    def connect_ex(self: socket.socket, address: object) -> int:
        check(self, address)
        return original_connect_ex(self, address)

    socket.socket.connect = connect
    socket.socket.connect_ex = connect_ex
    socket.socket._agentstatus_guarded = True
    def win32_connect(event: str, args: tuple) -> None:
        if event == 'agent_bridge.windows.connect':
            check_windows(args[0], args[1])
    sys.addaudithook(win32_connect)


install()
