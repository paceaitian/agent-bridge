"""Windows P：查询权限、同handle代际/token，UNKNOWN不投影成Linux的False。"""
from typing import Any
from dataclasses import dataclass
from collections.abc import Iterator
from contextlib import contextmanager
from ..types import Capability, Presence, ProcessIdentity, ProcessRead, ProcessRecord, ProcessSnapshot, SampleState


@dataclass(frozen=True)
class Ancestry:
    records: tuple[ProcessRecord, ...]
    termination: str


def _name(record: ProcessRecord) -> str:
    return record.comm.lower().removesuffix('.exe')


class WindowsProcess:
    capability = Capability.UNVERIFIED  # implementation fixtures != real Windows qualification

    def __init__(self, api: Any) -> None:
        self.api = api
        self._scanning = False
        self._table: list[tuple[int, int, str]] | None = None

    @contextmanager
    def generation_scan(self) -> Iterator[None]:
        previous = self._scanning, self._table
        self._scanning, self._table = True, None
        try:
            yield
        finally:
            self._scanning, self._table = previous

    def read(self, pid: int) -> ProcessRead:
        return self._read(pid)

    def _read(self, pid: int, expected_birth: str | None = None) -> ProcessRead:
        if type(pid) is not int or not 0 < pid < 2**32:
            return ProcessRead(Presence.UNKNOWN, reason='process_invalid')
        try:
            fact = self.api.process(pid) if expected_birth is None else self.api.process(pid, expected_birth=expected_birth)
            me = self.api.current_token()
            if fact.token.elevated or fact.token.sid != me.sid:
                return ProcessRead(Presence.UNKNOWN, reason='process_identity_unverified')
            if self._scanning:
                if self._table is None:
                    self._table = self.api.process_table()
                table = self._table
                assert table is not None
            else:
                table = self.api.process_table()
            match = [r for r in table if r[0] == pid]
            if len(match) != 1:
                return ProcessRead(Presence.UNKNOWN, reason='process_snapshot_changed')
            # Revalidate after the Toolhelp snapshot, never splice two reused PIDs.
            if self.api.process(pid) != fact:
                return ProcessRead(Presence.UNKNOWN, reason='process_snapshot_changed')
            identity = ProcessIdentity('windows', pid, 'win-filetime', str(fact.birth))
            return ProcessRead(Presence.CURRENT, ProcessRecord(identity, match[0][1], match[0][2], None))
        except OSError as error:
            if getattr(error, 'winerror', None) in (87, 1168):
                return ProcessRead(Presence.EXITED, reason='process_exited')
            return ProcessRead(Presence.UNKNOWN, reason='process_unverified')

    def same_generation(self, identity: ProcessIdentity) -> Presence:
        if (identity.platform != 'windows' or identity.generation_kind != 'win-filetime'
                or not isinstance(identity.generation_value,str)
                or not identity.generation_value.isascii() or not identity.generation_value.isdecimal()):
            return Presence.UNKNOWN
        current = self._read(identity.pid, identity.generation_value)
        if current.record is not None:
            return Presence.CURRENT if current.record.identity == identity else Presence.EXITED
        return current.state

    def ancestry(self, pid: int, limit: int = 64) -> tuple[ProcessRecord, ...]:
        rows: list[ProcessRecord] = []
        seen: set[int] = set()
        while pid > 0 and len(rows) < min(64, max(0, limit)):
            if pid in seen:
                return ()  # incomplete/loop cannot prove caller attribution
            seen.add(pid)
            read = self.read(pid)
            if read.record is None:
                return ()
            if rows and int(read.record.identity.generation_value) > int(rows[-1].identity.generation_value):
                return ()
            rows.append(read.record)
            pid = read.record.parent_pid
        return tuple(rows) if pid == 0 else ()

    def snapshot(self) -> ProcessSnapshot:
        # W1 does not turn a process table into provider discovery.
        return ProcessSnapshot(SampleState.UNVERIFIED)

    def trace(self, pid: int, limit: int = 64) -> Ancestry:
        """Caller-only evidence; preserve the verified prefix, never bridge a gap.

        ancestry() retains W1's complete-chain projection for older consumers.
        Neither a truncated prefix nor an empty chain means a user shell.
        """
        rows: list[ProcessRecord] = []
        seen: set[int] = set()
        with self.generation_scan():
            while pid > 0:
                if pid in seen:
                    return Ancestry(tuple(rows), 'cycle')
                if len(rows) >= min(64, max(0, limit)):
                    return Ancestry(tuple(rows), 'limit')
                seen.add(pid)
                read = self.read(pid)
                if read.state is not Presence.CURRENT or read.record is None:
                    return Ancestry(tuple(rows), read.reason or 'process_unverified')
                row = read.record
                if rows and int(row.identity.generation_value) > int(rows[-1].identity.generation_value):
                    return Ancestry(tuple(rows), 'parent_reused')
                rows.append(row)
                pid = row.parent_pid
        return Ancestry(tuple(rows), 'root')

    def pid_namespace(self) -> None:
        return None

    def legacy(self) -> Any:
        raise OSError('windows_legacy_process_unsupported')
