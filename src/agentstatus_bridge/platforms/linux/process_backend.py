"""P接口的Linux适配；legacy消费者继续使用process模块，W1-2迁移其注入。"""
from pathlib import Path
from contextlib import nullcontext

from ..types import (Capability, Presence, ProcessIdentity, ProcessRead, ProcessRecord,
                     ProcessSnapshot, SampleState)
from . import process


def _record(info: process.ProcessInfo) -> ProcessRecord:
    return ProcessRecord(ProcessIdentity('linux', info.pid, 'linux-proc-ticks', info.start_ticks),
                         info.ppid, info.comm, info.tty_nr)


class LinuxProcess:
    capability = Capability.VERIFIED

    @staticmethod
    def generation_scan():
        return nullcontext()

    @staticmethod
    def legacy():
        # 原始模块满足兼容协议；不经三态改写旧 bool/None。
        return process

    def __init__(self, proc_root: Path | None = None) -> None:
        self.root = proc_root if proc_root is not None else process.DEFAULT_PROC

    def read(self, pid: int) -> ProcessRead:
        info = process.read_process(pid, self.root)
        # Linux旧的缺失/不可读/坏结构都投影None；不在抽取时暗改恢复行为。
        return (ProcessRead(Presence.CURRENT, _record(info)) if info is not None
                else ProcessRead(Presence.UNKNOWN, reason='legacy_missing_or_unreadable'))

    def ancestry(self, pid: int, limit: int = 64) -> tuple[ProcessRecord, ...]:
        return tuple(_record(info) for info in process.ancestry(pid, self.root)[:max(0, min(limit, 64))])

    def snapshot(self) -> ProcessSnapshot:
        records = tuple(_record(info) for pid in process.list_pids(self.root)
                        if (info := process.read_process(pid, self.root)) is not None)
        return ProcessSnapshot(SampleState.AVAILABLE if records else SampleState.EMPTY, records)

    def same_generation(self, identity: ProcessIdentity) -> Presence:
        if identity.platform != 'linux' or identity.generation_kind != 'linux-proc-ticks':
            return Presence.UNKNOWN
        info = process.read_process(identity.pid, self.root)
        if info is None:
            return Presence.UNKNOWN
        return Presence.CURRENT if info.start_ticks == identity.generation_value else Presence.EXITED

    def pid_namespace(self) -> str | None:
        return process.pid_namespace(self.root)

    def launch_tokens(self, pid: int) -> list[str]:
        return process.launch_tokens(pid, self.root)

    def permission_tokens(self, pid: int) -> tuple[list[str], bool]:
        return process._argv_tokens(pid, self.root)

    def held_files(self, pid: int) -> list[str]:
        return process.open_file_targets(pid, self.root)
