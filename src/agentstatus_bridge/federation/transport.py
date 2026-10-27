"""联邦传输抽象（DESIGN §88.2）：read_frame/write_frame/close 与 codec、业务层解耦。

默认实现是字节流（SSH stdio 子进程的 stdin/stdout，或离线普通管道）；v1.1 可另加 HTTPS 实现。
读端单独线程读帧放进有界队列，主循环单线程写，避免写锁内等待网络。
"""

from __future__ import annotations

import queue
import threading
from typing import IO, Any, Protocol

from .codec import CodecError, read_frame, write_frame

READ_QUEUE_FRAMES = 16


class FederationTransport(Protocol):
    """一条已建立的帧通道。"""

    def read_frame(self, timeout: float | None = None) -> dict[str, Any] | None:
        """读下一帧；EOF 返回 None；超时抛 TimeoutError；坏帧抛 CodecError。"""
        ...

    def write_frame(self, frame: dict[str, Any]) -> None:
        ...

    def close(self) -> None:
        ...


_EOF = object()
_STOP = object()  # 停止唤醒哨兵（DESIGN §90.5）：不是线上帧，只让阻塞在 queue.get 的主线程立即返回


class StreamTransport:
    """基于一对二进制流的传输：后台线程有界读帧（≤16 帧排队），调用方线程写帧。

    帧过大后流停在一行中间，读线程随即停止并在队列里留下错误与 EOF；调用方应回错误后关闭连接。
    """

    def __init__(self, reader: IO[bytes], writer: IO[bytes]) -> None:
        self._reader = reader
        self._writer = writer
        self._queue: queue.Queue[object] = queue.Queue(maxsize=READ_QUEUE_FRAMES)
        self._closed = False
        self._stopping = False
        self._thread = threading.Thread(target=self._pump, name="federation-reader", daemon=True)
        self._thread.start()

    def _pump(self) -> None:
        while True:
            try:
                frame = read_frame(self._reader)
            except CodecError as error:
                self._queue.put(error)
                if error.code == "frame_too_large" or error.detail == "truncated":
                    self._queue.put(_EOF)
                    return
                continue
            except (OSError, ValueError):
                self._queue.put(_EOF)
                return
            if frame is None:
                self._queue.put(_EOF)
                return
            self._queue.put(frame)

    def wake(self) -> None:
        """停止已请求：之后的读一律按 EOF 返回，并投一个哨兵唤醒正阻塞在读上的线程（队列满说明读方没在等）。"""
        self._stopping = True
        try:
            self._queue.put_nowait(_STOP)
        except queue.Full:
            pass

    def read_frame(self, timeout: float | None = None) -> dict[str, Any] | None:
        if self._stopping:
            return None
        try:
            item = self._queue.get(timeout=timeout)
        except queue.Empty as error:
            raise TimeoutError from error
        if item is _STOP or self._stopping:
            return None
        if item is _EOF:
            self._queue.put(_EOF)  # 之后的读也立即得到 EOF
            return None
        if isinstance(item, CodecError):
            raise item
        assert isinstance(item, dict)
        return item  # pyright: ignore[reportUnknownVariableType]

    def write_frame(self, frame: dict[str, Any]) -> None:
        if self._closed:
            raise OSError("transport_closed")
        write_frame(self._writer, frame)

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        for stream in (self._writer, self._reader):
            try:
                stream.close()
            except OSError:
                pass
