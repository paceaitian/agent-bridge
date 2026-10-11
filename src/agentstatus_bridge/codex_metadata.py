"""§69 一次命令/worker内的 native 分类缓存；持有证据由调用方每轮重新证明。"""
from __future__ import annotations

from collections.abc import Callable, Mapping
from contextlib import contextmanager
from contextvars import ContextVar
from pathlib import Path
import time

from .transports import local_codex
from .transports.codex_native import MAX_IDS, NativeBatch, ReadBatchClient, ThreadMetadata
from .transports.codex_queue import cli_version

CACHE_SECONDS = 6.0
MAX_CACHED = 256


class MetadataCache:
    def __init__(self, reader: ReadBatchClient | None = None, *, clock: Callable[[], float] = time.monotonic,
                 single_batch: bool = False) -> None:
        self.clock = clock
        self.single_batch = single_batch
        self._queried = False
        self.reader = reader or ReadBatchClient(lambda timeout: cli_version(timeout=timeout), clock=clock)
        self._epoch: object = None
        self._entries: dict[str, tuple[tuple[tuple[int, str], ...], float, ThreadMetadata]] = {}
        self._cursor = 0
        self.last = NativeBatch()

    def read(self, home: Path, holders: Mapping[str, tuple[tuple[int, str], ...]]) -> NativeBatch:
        if not holders:
            self._entries.clear()
            self.last = NativeBatch()
            return self.last
        now = self.clock()
        epoch = local_codex.socket_identity(local_codex.platform().control_socket_path(home))
        if epoch != self._epoch:
            self._entries.clear()
            self._epoch = epoch
        self._entries = {key: value for key, value in self._entries.items()
                         if holders.get(key) == value[0] and 0 <= now - value[1] < CACHE_SECONDS}
        missing = sorted(set(holders) - self._entries.keys())
        if missing and not (self.single_batch and self._queried):
            self._queried = True
            offset = self._cursor % len(missing)
            wanted = (missing[offset:] + missing[:offset])[:MAX_IDS]
            self._cursor += len(wanted)
            peers = {key: {pid for pid, _ in holders[key]} for key in wanted}
            batch = self.reader.read(home, wanted, peers)
            self.last = batch
            if batch.reason == "ok":
                for key, value in batch.records.items():
                    if key in holders:
                        self._entries[key] = (holders[key], now, value)
                while len(self._entries) > MAX_CACHED:
                    del self._entries[next(iter(self._entries))]
            else:
                # 批次异常清缓存；不让同epoch的旧正面证据掩盖权限/协议失败。
                self._entries.clear()
        elif not holders:
            self.last = NativeBatch()
        return NativeBatch({key: value[2] for key, value in self._entries.items()},
                           self.last.reason, self.last.server_version)


_COMMAND_CACHE: ContextVar[MetadataCache | None] = ContextVar("codex_metadata_command", default=None)


def discovery_cache() -> MetadataCache:
    return _COMMAND_CACHE.get() or MetadataCache()


@contextmanager
def command_scope():
    """包括wait等多次发现的长命令：只准一批，过6秒仍可用SQL但不重连native。"""
    token = _COMMAND_CACHE.set(MetadataCache(single_batch=True))
    try:
        yield
    finally:
        _COMMAND_CACHE.reset(token)
