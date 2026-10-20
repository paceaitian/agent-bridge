"""Linux T：Codex 与 Claude 共用本地流原语，原安全检查分支不合并。"""
from pathlib import Path
import logging
import os
import socket
import stat
import struct
from typing import cast
from ..transport_types import ByteStream, LocalFailure
from ..null_transport import UnsupportedPlatform
from ..types import PathsAndIdentityBackend
from .files import LinuxPaths
from .listener import LinuxInbox, inbox_directory

class LinuxPlatform(UnsupportedPlatform):
    supported = True

    def __init__(self, files: PathsAndIdentityBackend | None = None) -> None:
        self.files = files if files is not None else LinuxPaths()
        self._permission_observations: set[tuple[bool, bool | None, bool | None]] = set()
    def resolve(self, link: Path) -> Path | LocalFailure:
        if not os.path.lexists(link):
            return LocalFailure("socket_missing")
        try:
            target = Path(os.path.realpath(link, strict=True))
            value = target.stat()
        except OSError:
            return LocalFailure("socket_missing")
        uid = os.getuid()
        if not stat.S_ISSOCK(value.st_mode) or value.st_uid != uid:
            return LocalFailure("socket_rejected")
        # Upstream's Unix client does not reject socket/parent permissions.
        # Keep addressing proof; permissions are bounded content-free observations.
        try:
            parent = target.parent.stat()
            parent_owned, parent_private = parent.st_uid == uid, stat.S_IMODE(parent.st_mode) == 0o700
        except OSError:
            parent_owned, parent_private = None, None
        observation = (not bool(value.st_mode & 0o077), parent_owned, parent_private)
        if observation != (True, True, True) and observation not in self._permission_observations:
            logging.getLogger(__name__).debug(
                "codex_socket_permissions_observed socketPrivate=%s parentOwned=%s parentPrivate=%s",
                *observation,
            )
            self._permission_observations.add(observation)
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
        return self.files.root_identity(home, sqlite_home)

    def home_equal(self, reported: str, expected: Path) -> bool:
        return self.files.home_equal(reported, expected)

    def socket_identity(self, link: Path) -> tuple[str, int, int, int] | None:
        try:
            target = self.resolve(link)
            if isinstance(target, LocalFailure):
                return None
            return self.files.socket_identity(target)
        except (OSError, ValueError):
            return None

    def connect_claude(self, stream: ByteStream, path: str) -> None:
        cast(socket.socket, stream).connect(path)

    def peer_credentials(self, stream: ByteStream) -> tuple[int, int, int]:
        return struct.unpack("3i", cast(socket.socket, stream).getsockopt(
            socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i")))

    def shutdown_write(self, stream: ByteStream) -> None:
        cast(socket.socket, stream).shutdown(socket.SHUT_WR)

    def owned_socket(self, path: str, uid: int) -> bool:
        try:
            status = os.lstat(path)
        except OSError:
            return False
        return stat.S_ISSOCK(status.st_mode) and status.st_uid == uid

    def inbox_directory(self) -> Path:
        return inbox_directory()

    def inbox(self, directory: Path | None = None, *, name: str | None = None) -> LinuxInbox:
        return LinuxInbox(directory, name=name)
