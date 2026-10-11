"""本地 Codex 平台边界：定位、私有对象、连接与内核 peer 校验（§69）。

Windows 保留接口但尚不实现；不回退 TCP、不启动 daemon。此层不依赖桥业务/observer。
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import os
from pathlib import Path
import socket
import stat
import struct
import sys
from typing import Protocol


class ByteStream(Protocol):
    def settimeout(self, value: float, /) -> None: ...
    def sendall(self, data: bytes, /) -> None: ...
    def recv(self, size: int, /) -> bytes: ...
    def close(self) -> None: ...


@dataclass(frozen=True)
class LocalFailure:
    reason: str


class LocalPlatform(Protocol):
    def control_socket_path(self, home: Path) -> Path: ...
    def resolve(self, link: Path) -> Path | LocalFailure: ...
    def new_stream(self) -> ByteStream: ...
    def connect(self, stream: ByteStream, target: Path) -> None: ...
    def peer_pid(self, stream: ByteStream) -> int | None: ...
    def root_identity(self, home: Path, sqlite_home: Path | None = None) -> str | None: ...


class UnsupportedPlatform:
    def control_socket_path(self, home: Path) -> Path:
        return home / "app-server-control" / "app-server-control.sock"

    def resolve(self, link: Path) -> Path | LocalFailure:
        return LocalFailure("platform_unsupported")

    def new_stream(self) -> ByteStream:
        raise OSError("platform_unsupported")

    def connect(self, stream: ByteStream, target: Path) -> None:
        raise OSError("platform_unsupported")

    def peer_pid(self, stream: ByteStream) -> int | None:
        return None

    def root_identity(self, home: Path, sqlite_home: Path | None = None) -> str | None:
        return None


class LinuxPlatform(UnsupportedPlatform):
    def resolve(self, link: Path) -> Path | LocalFailure:
        if not os.path.lexists(link):
            return LocalFailure("socket_missing")
        try:
            target = Path(os.path.realpath(link, strict=True))
            value, parent = target.stat(), target.parent.stat()
        except OSError:
            return LocalFailure("socket_missing")
        uid = os.getuid()
        if (not stat.S_ISSOCK(value.st_mode) or value.st_uid != uid or value.st_mode & 0o077
                or parent.st_uid != uid or stat.S_IMODE(parent.st_mode) != 0o700):
            return LocalFailure("socket_rejected")
        return target

    def new_stream(self) -> socket.socket:
        return socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)

    def connect(self, stream: ByteStream, target: Path) -> None:
        if not isinstance(stream, socket.socket):
            raise OSError("invalid_stream")
        stream.connect(str(target))

    def peer_pid(self, stream: ByteStream) -> int | None:
        if not isinstance(stream, socket.socket) or not hasattr(socket, "SO_PEERCRED"):
            return None
        try:
            value = stream.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
            pid, uid, _ = struct.unpack("3i", value)
        except OSError:
            return None
        # §61的权威条件仍是同uid；pid在当前命名空间不可见(0)时，native持有者集合另会拒绝。
        return pid if uid == os.getuid() else None

    def root_identity(self, home: Path, sqlite_home: Path | None = None) -> str | None:
        # 只持久摘要，不保存绝对路径。ctime/mtime 会随正常写文件改变，不能充当根代际。
        try:
            parts: list[str] = []
            for root in (home, sqlite_home or home):
                resolved = root.resolve(strict=True)
                info = resolved.stat()
                if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid():
                    return None
                parts.extend((str(resolved), str(info.st_uid), str(info.st_dev), str(info.st_ino)))
            return hashlib.sha256("\0".join(parts).encode()).hexdigest()
        except (OSError, ValueError):
            return None


_LINUX = LinuxPlatform()
_UNSUPPORTED = UnsupportedPlatform()


def platform() -> LocalPlatform:
    return _LINUX if sys.platform == "linux" else _UNSUPPORTED


def socket_identity(link: Path) -> tuple[str, int, int, int] | None:
    """只在内存作缓存 epoch；路径/目录换代不能复用旧 native 结果。"""
    try:
        target = platform().resolve(link)
        if isinstance(target, LocalFailure):
            return None
        info = target.stat()
        return str(target), info.st_dev, info.st_ino, info.st_ctime_ns
    except (OSError, ValueError):
        return None
