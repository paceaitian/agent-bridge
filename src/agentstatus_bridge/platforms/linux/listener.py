"""Linux 非阻塞本地 listener 与有界行帧；不参与业务状态机。"""
from __future__ import annotations
import json
import os
from pathlib import Path
import selectors
import socket
from ..transport_codec import encode_address, MAX_INBOX_BUFFER

MAX_INBOX_CLIENTS = 32

def inbox_directory() -> Path:
    """回执收件箱放在 Claude 认可的默认 socket 目录中，否则接收端不会回发回执。"""
    runtime = os.environ.get("XDG_RUNTIME_DIR")
    if runtime:
        return Path(runtime) / "cc-socks"
    return Path(f"/tmp/cc-socks-{os.getuid()}")


class LinuxInbox:
    """worker 持有的回执收件箱：非阻塞 Unix socket，每行一个 JSON 帧。"""

    def __init__(self, directory: Path | None = None, *, name: str | None = None) -> None:
        self._directory = directory or inbox_directory()
        self.path = self._directory / (name or f"{os.getpid()}.sock")
        self._selector = selectors.DefaultSelector()
        self._listener: socket.socket | None = None
        self._buffers: dict[socket.socket, bytearray] = {}

    @property
    def address(self) -> str:
        return encode_address(str(self.path))

    def open(self) -> None:
        """绑定收件箱；只清理本进程自己的同名残留。"""
        if not self._directory.exists():
            self._directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        try:
            if stat_is_socket(self.path):
                self.path.unlink()
        except OSError:
            pass
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        listener.bind(str(self.path))
        os.chmod(self.path, 0o600)
        listener.listen(16)
        listener.setblocking(False)
        self._listener = listener
        self._selector.register(listener, selectors.EVENT_READ)

    def healthy(self) -> bool:
        """收件箱文件仍在（可能被外部清理）。"""
        return self._listener is not None and stat_is_socket(self.path)

    def poll(self, timeout: float) -> list[object]:
        """等待至多 timeout 秒，返回收到的完整帧。"""
        frames: list[object] = []
        if self._listener is None:
            return frames
        for key, _mask in self._selector.select(timeout):
            sock = key.fileobj
            if not isinstance(sock, socket.socket):
                continue
            if sock is self._listener:
                self._accept()
                continue
            frames.extend(self._read(sock))
        return frames

    def _accept(self) -> None:
        assert self._listener is not None
        try:
            client, _ = self._listener.accept()
        except OSError:
            return
        if len(self._buffers) >= MAX_INBOX_CLIENTS:
            client.close()
            return
        client.setblocking(False)
        self._buffers[client] = bytearray()
        self._selector.register(client, selectors.EVENT_READ)

    def _read(self, client: socket.socket) -> list[object]:
        buffer = self._buffers.get(client)
        if buffer is None:
            return []
        try:
            chunk = client.recv(65536)
        except BlockingIOError:
            return []
        except OSError:
            chunk = b""
        frames: list[object] = []
        if chunk:
            buffer.extend(chunk)
        while b"\n" in buffer:
            line, _, rest = bytes(buffer).partition(b"\n")
            buffer[:] = rest
            try:
                frames.append(json.loads(line.decode("utf-8")))
            except (UnicodeDecodeError, ValueError):
                continue
        if not chunk or len(buffer) > MAX_INBOX_BUFFER:
            if chunk == b"" and buffer:
                try:
                    frames.append(json.loads(bytes(buffer).decode("utf-8")))
                except (UnicodeDecodeError, ValueError):
                    pass
            self._drop(client)
        return frames

    def _drop(self, client: socket.socket) -> None:
        try:
            self._selector.unregister(client)
        except (KeyError, ValueError):
            pass
        self._buffers.pop(client, None)
        client.close()

    def close(self) -> None:
        for client in list(self._buffers):
            self._drop(client)
        if self._listener is not None:
            try:
                self._selector.unregister(self._listener)
            except (KeyError, ValueError):
                pass
            self._listener.close()
            self._listener = None
            try:
                if stat_is_socket(self.path):
                    self.path.unlink()
            except OSError:
                pass
        self._selector.close()


def stat_is_socket(path: Path) -> bool:
    """路径是否为本用户拥有的 socket（不跟随符号链接）。"""
    try:
        status = os.lstat(path)
    except OSError:
        return False
    import stat as stat_module

    return stat_module.S_ISSOCK(status.st_mode) and status.st_uid == os.getuid()
