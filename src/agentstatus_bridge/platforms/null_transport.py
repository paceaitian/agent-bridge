"""未获资格的T不产生连接或listener。"""
from pathlib import Path
from contextlib import contextmanager
from collections.abc import Iterator
from .transport_types import ByteStream, LocalFailure, Inbox

class UnsupportedPlatform:
    supported = False
    def codex_cli_version(self) -> str | None:
        return None

    @contextmanager
    def codex_read_scope(self, version: str) -> Iterator[None]:
        raise OSError('platform_unsupported')
        yield

    def logon_info(self, stream: ByteStream) -> dict[str, object]:
        return {'logonType': 'UNKNOWN'}

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



    def socket_identity(self, link: Path) -> tuple[str, int, int, int] | None:
        return None

    def home_equal(self, reported: str, expected: Path) -> bool:
        return False

    def connect_claude(self, stream: ByteStream, path: str) -> None:
        raise OSError("platform_unsupported")

    def peer_credentials(self, stream: ByteStream) -> tuple[int, int, int]:
        raise OSError("platform_unsupported")

    def shutdown_write(self, stream: ByteStream) -> None:
        raise OSError("platform_unsupported")

    def owned_socket(self, path: str, uid: int) -> bool:
        return False

    def inbox_directory(self) -> Path:
        raise OSError("platform_unsupported")

    def inbox(self, directory: Path | None = None, *, name: str | None = None) -> Inbox:
        raise OSError("platform_unsupported")
