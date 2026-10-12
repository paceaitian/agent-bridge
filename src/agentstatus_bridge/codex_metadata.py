"""§69 一次命令/worker内的 native 分类缓存；持有证据由调用方每轮重新证明。"""
from __future__ import annotations

from collections.abc import Callable, Collection, Mapping
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
        self._negative: dict[str, tuple[tuple[tuple[int, str], ...], float]] = {}
        self._cursor = 0
        self.last = NativeBatch()
        self.attempted: frozenset[str] = frozenset()  # 诊断：本轮交给读取器或仍有效缓存的 id，不是发帧计数

    def read(self, home: Path, holders: Mapping[str, tuple[tuple[int, str], ...]], *,
             preferred: Collection[str] = (), absent: Collection[str] = ()) -> NativeBatch:
        self.attempted = frozenset()
        if not holders:
            self._entries.clear()
            self._negative.clear()
            self.last = NativeBatch()
            return self.last
        now = self.clock()
        epoch = local_codex.socket_identity(local_codex.platform().control_socket_path(home))
        if epoch != self._epoch:
            self._entries.clear()
            self._negative.clear()
            self._epoch = epoch
        self._entries = {key: value for key, value in self._entries.items()
                         if holders.get(key) == value[0] and 0 <= now - value[1] < CACHE_SECONDS}
        self._negative = {key: value for key, value in self._negative.items()
                          if holders.get(key) == value[0] and 0 <= now - value[1] < CACHE_SECONDS}
        self.attempted = frozenset(self._entries) | frozenset(self._negative)
        missing = set(holders) - self._entries.keys() - self._negative.keys()
        if missing and not (self.single_batch and self._queried):
            self._queried = True
            priority = set(preferred)
            no_row = set(absent)
            ordered: list[str] = []
            for group in (missing & priority, (missing - priority) & no_row, missing - priority - no_row):
                values = sorted(group, reverse=True)
                offset = 0 if self.single_batch or not values else self._cursor % len(values)
                ordered.extend(values[offset:] + values[:offset])
            wanted = ordered[:MAX_IDS]
            self._cursor += len(wanted)
            peers = {key: {pid for pid, _ in holders[key]} for key in wanted}
            self.attempted |= frozenset(wanted)
            batch = self.reader.read(home, wanted, peers)
            self.last = batch
            if batch.reason in {"ok", "peer_not_holder"}:
                for key, value in batch.records.items():
                    if key in wanted:
                        self._entries[key] = (holders[key], now, value)
                for key in batch.not_held:
                    if key in wanted:
                        self._negative[key] = (holders[key], now)
                while len(self._entries) + len(self._negative) > MAX_CACHED:
                    if self._negative:
                        del self._negative[next(iter(self._negative))]
                    else:
                        del self._entries[next(iter(self._entries))]
            else:
                # 批次异常清缓存；不让同epoch的旧正面证据掩盖权限/协议失败。
                self._entries.clear()
                self._negative.clear()
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
