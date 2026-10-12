"""W1 S: private identity hints, never caller authorization or provider discovery.

Linux disabled. No CLI/worker/ledger dependency, no real hook configuration.
The executable entry can only record an unverified Claude projection; positive
proof requires an independently qualified adapter (W1 supplies only fixtures).
"""
from __future__ import annotations
from collections.abc import Callable, Mapping
from contextlib import contextmanager
from dataclasses import asdict, dataclass
import hashlib
import json
import math
import os
from pathlib import Path
import sys
import threading
import time
from typing import Any, Iterator
import uuid

from .platforms.factory import get_platform
from .platforms.types import BridgePlatform, Presence, ProcessIdentity

LIMIT = 256
MAX_RECORD = 4096
MAX_INPUT = 65536
GRACE = 86400
FIELDS = frozenset({'schema','provider','sessionId','agentProcess','ownerRole','source','sourceVersion',
                    'attribution','reason','candidateCount','sessionKind','observedAt','writer'})


@dataclass(frozen=True)
class Proof:
    """Only an explicit qualified adapter supplies this, never hook JSON."""
    identity: ProcessIdentity
    role: str
    kind: str


@dataclass(frozen=True)
class Candidates:
    records: tuple[dict[str, Any], ...]
    complete: bool
    reason: str | None = None


def identity(value: object) -> ProcessIdentity | None:
    if not isinstance(value, dict) or set(value) != {'platform','pid','generation_kind','generation_value'}:
        return None
    if (value['platform'] != 'windows' or value['generation_kind'] != 'win-filetime'
            or type(value['pid']) is not int or not 0 < value['pid'] < 2**32
            or not isinstance(value['generation_value'],str) or not value['generation_value'].isascii()
            or not value['generation_value'].isdecimal() or not 0 < int(value['generation_value']) < 2**64):
        return None
    return ProcessIdentity(**value)


def session_id(raw: object) -> str | None:
    if not isinstance(raw,str):
        return None
    try:
        parsed = str(uuid.UUID(raw))
        return parsed if parsed == raw.lower() and len(raw) == 36 else None
    except ValueError:
        return None


def key(record: Mapping[str, Any]) -> str:
    value = [record['provider'],record['sessionId'],record['ownerRole'],record['agentProcess']]
    return hashlib.sha256(json.dumps(value,sort_keys=True,separators=(',',':')).encode()).hexdigest()


def valid(record: object) -> bool:
    if not isinstance(record,dict) or set(record) != FIELDS:
        return False
    return (type(record['schema']) is int and record['schema'] == 1 and record['provider'] in ('claude','codex','grok')
            and session_id(record['sessionId']) is not None
            and (record['agentProcess'] is None or identity(record['agentProcess']) is not None)
            and identity(record['writer']) is not None
            and record['ownerRole'] in ('tui','daemon','unknown')
            and record['source'] in ('provider-session-start','qualified-project-hook','controlled-fixture')
            and record['sourceVersion'] == '1' and record['attribution'] in ('bound','ambiguous','unverified')
            and record['reason'] in ('source_unqualified','source_verified','source_ambiguous')
            and type(record['candidateCount']) is int and 0 <= record['candidateCount'] <= LIMIT+1
            and record['sessionKind'] in ('root','subagent','unknown')
            and type(record['observedAt']) in (int,float) and math.isfinite(record['observedAt']) and record['observedAt'] >= 0)


class Registry:
    def __init__(self, root: Path, platform: BridgePlatform | None = None) -> None:
        self.platform = platform or get_platform()
        self.root = root / 'registrations' / 'v1'
        self.files: Any = self.platform.files
        self.enabled = self.platform.name == 'windows'

    @contextmanager
    def lock(self, deadline: float) -> Iterator[None]:
        self.files.ensure_private_dir(self.root)
        fd = self.platform.lifecycle.open_lock(self.root / '.registry.lock')
        locked = False
        try:
            while time.monotonic() < deadline:
                try:
                    self.platform.lifecycle.try_lock(fd)
                    locked = True
                    break
                except BlockingIOError:
                    time.sleep(min(0.01,max(0,deadline-time.monotonic())))
            if not locked:
                raise TimeoutError('registration_deadline')
            yield
        finally:
            if locked:
                self.platform.lifecycle.unlock(fd)
            self.platform.lifecycle.close_lock(fd)

    def _paths(self) -> tuple[list[Path], bool]:
        entries: list[Path] = []
        # Scanning must itself be bounded, not list(glob()) of an unbounded directory.
        with os.scandir(self.root) as iterator:
            for entry in iterator:
                if entry.name != '.registry.lock':
                    entries.append(Path(entry.path))
                    if len(entries) > LIMIT:
                        return sorted(entries), False
        return sorted(entries), True

    def _read(self, path: Path) -> dict[str, Any] | None:
        self.files.validate_file(path)
        with path.open('rb') as stream:
            raw = stream.read(MAX_RECORD+1)
        if len(raw)>MAX_RECORD:
            return None
        try:
            record=json.loads(raw)
            return record if valid(record) and path.stem==key(record) else None
        except (ValueError,TypeError,RecursionError):
            return None

    def write(self, payload: object, *, provider: str, writer: ProcessIdentity, now: float,
              proof: Proof | None = None, fixture: bool = False, deadline: float | None = None) -> str:
        if not self.enabled:
            return 'disabled'
        deadline = deadline if deadline is not None else time.monotonic()+1
        if (not isinstance(payload,dict) or payload.get('hook_event_name') != 'SessionStart'
                or provider not in ('claude','codex','grok') or session_id(payload.get('session_id')) is None):
            return 'invalid_input'
        # Codex shared daemon hook never maps pane/TUI, even if JSON claims one.
        if provider != 'claude':
            proof = None
        if self.platform.process.same_generation(writer) is not Presence.CURRENT:
            return 'writer_unverified'
        if proof is not None:
            chain=self.platform.process.ancestry(writer.pid)
            if (proof.identity not in [r.identity for r in chain] or proof.role not in ('tui','daemon')
                    or proof.kind not in ('root','subagent')):
                return 'source_unqualified'
        record = {'schema':1,'provider':provider,'sessionId':session_id(payload['session_id']),
                  'agentProcess':asdict(proof.identity) if proof else None,'ownerRole':proof.role if proof else 'unknown',
                  'source':'controlled-fixture' if fixture else 'provider-session-start','sourceVersion':'1',
                  'attribution':'bound' if proof else 'unverified','reason':'source_verified' if proof else 'source_unqualified',
                  'candidateCount':1 if proof else 0,'sessionKind':proof.kind if proof else 'unknown',
                  'observedAt':now,'writer':asdict(writer)}
        if not valid(record):
            return 'invalid_projection'
        raw=json.dumps(record,sort_keys=True,separators=(',',':')).encode()
        if len(raw)>MAX_RECORD or time.monotonic()>=deadline:
            return 'registration_deadline'
        with self.lock(deadline):
            self._cleanup_locked(now, deadline)
            paths,complete=self._paths()
            dest=self.root/(key(record)+'.json')
            if not complete or (len(paths)>=LIMIT and dest not in paths):
                return 'registration_full'
            if dest in paths:
                previous=self._read(dest)
                if previous and previous['observedAt']>=now:
                    return 'older_observation'
            if time.monotonic()>=deadline:
                return 'registration_deadline'
            self.files.atomic_write(self.root,raw,name=dest.name,prefix='.registration.')
        return 'recorded'

    def load(self, *, qualify: Callable[[dict[str,Any]],bool] | None = None) -> Candidates:
        if not self.enabled:
            return Candidates((),False,'registration_disabled')
        try:
            return self._load(qualify)
        except OSError as error:
            missing=getattr(error,'winerror',None) in (2,3)
            return Candidates((),missing,None if missing else 'registration_store_unverified')

    def _load(self, qualify: Callable[[dict[str,Any]],bool] | None) -> Candidates:
        with self.files.lease(self.root):
            paths,complete=self._paths()
            rows=[]
            for path in paths[:LIMIT]:
                try:
                    record=self._read(path)
                    if record is None:
                        continue
                    owner=identity(record['agentProcess'])
                    state=self.platform.process.same_generation(owner) if owner else Presence.UNKNOWN
                    if state is Presence.EXITED:
                        continue
                    admitted=(complete and state is Presence.CURRENT and record['provider']=='claude'
                              and qualify is not None and qualify(record))
                    rows.append({**record,'current':state.value,'qualified':bool(admitted)})
                except OSError:
                    complete=False
            if not complete:
                rows=[{**row,'qualified':False} for row in rows]
            conflicts={(r['provider'],r['sessionId']) for r in rows
                       if sum((v['provider'],v['sessionId'])==(r['provider'],r['sessionId']) for v in rows)>1}
            if conflicts:
                rows=[{**row,'qualified':False} if (row['provider'],row['sessionId']) in conflicts else row for row in rows]
            reason='registration_scan_incomplete' if not complete else ('registration_ambiguous' if conflicts else None)
            return Candidates(tuple(rows),complete,reason)

    def _cleanup_locked(self, now: float, deadline: float) -> int:
        with self.platform.process.generation_scan():
            return self._cleanup_scan(now, deadline)

    def _cleanup_scan(self, now: float, deadline: float) -> int:
        paths,_=self._paths()
        removed=0
        for path in paths[:LIMIT]:
            if time.monotonic()>=deadline:
                break
            try:
                before=self.files.validate_file(path)
                stamp=(path.stat().st_mtime_ns,path.stat().st_size)
                record=self._read(path)
                owner=identity(record['agentProcess']) if record else None
                state=self.platform.process.same_generation(owner) if owner else None
                # AccessDenied or long-lived CURRENT are not age garbage.
                dead=state is Presence.EXITED
                old_bad=owner is None and 0 <= path.stat().st_mtime <= now-GRACE
                if (dead or old_bad) and self.files.validate_file(path)==before and (path.stat().st_mtime_ns,path.stat().st_size)==stamp:
                    self.files.api.delete(str(path))
                    removed+=1
            except OSError:
                continue
        return removed

    def cleanup(self, *, now: float) -> int:
        if not self.enabled:
            return 0
        deadline=time.monotonic()+1
        with self.lock(deadline):
            return self._cleanup_locked(now,deadline)

    def retire_exact(self, provider: str, session: str, owner: ProcessIdentity) -> int:
        if not self.enabled:
            return 0
        with self.lock(time.monotonic()+1):
            paths,_=self._paths()
            removed=0
            for path in paths[:LIMIT]:
                record=self._read(path)
                if (record and record['provider']==provider and record['sessionId']==session
                        and identity(record['agentProcess'])==owner):
                    self.files.api.delete(str(path));removed+=1
            return removed


def main() -> int:
    p=get_platform()
    if p.name!='windows':
        return 0  # disabled on Linux, no stdin/directory work
    # Hard fail-open budget, also bounds a blocking stdin/antivirus/WinAPI call.
    # Atomic temp+replace means termination cannot truncate the previous record.
    watchdog=threading.Timer(1.0,lambda: os._exit(0))
    watchdog.daemon=True
    watchdog.start()
    try:
        raw=sys.stdin.buffer.read(MAX_INPUT+1)
        if len(raw)>MAX_INPUT:
            return 0
        payload=json.loads(raw)
        writer=p.process.read(os.getpid())
        if writer.record:
            Registry(p.files.state_dir(),p).write(payload,provider='claude',writer=writer.record.identity,now=time.time())
    except Exception:
        pass  # no stderr or raw exception/payload, no ledger/fallback path
    finally:
        watchdog.cancel()
    return 0


if __name__=='__main__':
    raise SystemExit(main())
