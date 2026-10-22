"""Bounded native Claude registry projection; keys are read only during delivery."""
from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, replace
from pathlib import Path, PureWindowsPath
import re
import time
from typing import Any

from ...model import Endpoint, EndpointRef, Provider, Runtime
from ...transports.codex_native import NativeFailure, native_id
from .claude_auth import PeerFiles, PIPE, generation
from .local_transport import WindowsPlatform
from .api import ProcessFact
from .io import WinIO

MAX_RECORDS, SECONDS = 4096, 5.0
RECORD = re.compile(r'[1-9][0-9]{0,9}\.json')


class Ineligible(OSError):
    """A read record is known not to be a supported live peer, not a missing sample."""


def peer_process(backend: WindowsPlatform, pid: int, *, birth: str | None = None) -> ProcessFact:
    """A peer was/will be same-user and non-elevated; not a general PID liveness API."""
    me = backend.api.current_token()  # Failure to identify ourselves is still unknown.
    try:
        fact = backend.api.process(pid, expected_birth=birth)
    except OSError as error:
        if getattr(error, 'winerror', None) in (5, 87, 1168):
            raise Ineligible('claude_process_ineligible') from None
        raise
    if fact.token.sid != me.sid or fact.token.elevated:
        raise Ineligible('claude_process_ineligible')
    return fact


def project(data: dict[str, Any], pid: int, birth: str, root: str) -> Endpoint:
    session, pipe = data.get('sessionId'), data.get('messagingSocketPath')
    if (type(data.get('pid')) is not int or data['pid'] != pid or native_id(session) != session
            or not isinstance(session, str)):
        raise OSError('claude_registry_unverified')
    if (data.get('kind') not in (None, 'interactive')
            or 'procStartFt' in data and not generation(data['procStartFt'], birth)):
        raise Ineligible('claude_registry_ineligible')
    issues: list[str] = []
    if type(data.get('peerProtocol')) is not int or data['peerProtocol'] != 1:
        issues.append('peer_protocol_unsupported')
    if not isinstance(pipe, str) or not PIPE.fullmatch(pipe):
        issues.append('socket_unavailable')
        pipe = None
    name = data.get('name')
    name = name[:80] if isinstance(name, str) and name.strip() else None
    return Endpoint(EndpointRef(Provider.CLAUDE, session, pid, 'win-filetime:' + birth, data_root=root),
                    runtime=Runtime.UNKNOWN, runtime_source='none', name=name, socket_path=pipe,
                    issues=tuple(issues))


def inspect(backend: WindowsPlatform, pid: int, *, connect: bool = True,
            tolerate_pipe: bool = False) -> tuple[Endpoint, dict[str, Any]]:
    if type(pid) is not int or not 0 < pid < 2**32:
        raise OSError('claude_process_unverified')
    files = PeerFiles(backend.files)
    with files.root() as root:
        fact = peer_process(backend, pid)
        image = backend.api.process_image(pid, str(fact.birth))
        if PureWindowsPath(image).name.lower() != 'claude.exe':
            raise Ineligible('claude_image_unverified')
        data = files.read(f'{pid}.json')
        endpoint = project(data, pid, str(fact.birth), root)
        if endpoint.blocking_issues and not tolerate_pipe:
            raise OSError('claude_peer_unverified')
        if connect and not endpoint.blocking_issues:
            io = WinIO(backend.api)
            try:
                handle = io.open_pipe(endpoint.socket_path or '')
                try:
                    if io.peer_pid(handle, pipe=True) != pid:
                        raise OSError('claude_peer_mismatch')
                finally:
                    io.close_pipe(handle)
            except OSError:
                if not tolerate_pipe:
                    raise
                endpoint = replace(endpoint, issues=('socket_unavailable',))
        if peer_process(backend, pid, birth=str(fact.birth)) != fact:
            raise OSError('claude_process_changed')
        with files.root() as again:
            if again != root:
                raise OSError('claude_root_changed')
        return endpoint, data


@dataclass(frozen=True)
class Discovery:
    endpoints: tuple[Endpoint, ...] = ()
    complete: bool = False
    reason: str = 'claude_discovery_incomplete'
    # Excluded from selection, but retained for worker liveness/ambiguity decisions.
    duplicates: tuple[Endpoint, ...] = ()

    def select(self, reference: str) -> Endpoint:
        key = reference.removeprefix('claude@')
        forced = key.startswith('id:')
        key = key.removeprefix('id:')
        if not key.strip():
            raise NativeFailure('target_explicit_required')
        exact = native_id(key)
        if not self.complete and exact is None:
            raise NativeFailure(self.reason)
        matches = [e for e in (*self.endpoints, *self.duplicates) if (len(key) >= 8 and e.ref.native_id.startswith(key.lower()))
                   or not forced and e.name == key]
        if not matches and not self.complete:
            raise NativeFailure(self.reason)  # An unobserved UUID is not proof of absence.
        if len(matches) != 1:
            raise NativeFailure('target_ambiguous' if matches else 'target_not_found')
        if matches[0].blocking_issues:
            raise NativeFailure('target_' + matches[0].blocking_issues[0])
        return matches[0]

    def document(self) -> list[dict[str, object]]:
        return [{'provider': 'claude', 'target': 'claude@id:' + e.ref.native_id, 'nativeId': e.ref.native_id,
                 'pane': None, 'runtime': 'unknown', 'kind': 'root',
                 'eligible': not e.blocking_issues, 'name': e.name, 'issues': list(e.issues)}
                for e in (*self.endpoints, *self.duplicates)]


def discover(backend: WindowsPlatform, *, connect: bool = True) -> Discovery:
    found: list[Endpoint] = []
    complete, started = True, time.monotonic()
    try:
        files = PeerFiles(backend.files)
        try:
            files.sessions.lstat()
        except FileNotFoundError:
            return Discovery(complete=True, reason='complete')
        with files.root():
            names: list[str] = []
            for index, entry in enumerate(files.sessions.iterdir()):
                if index >= MAX_RECORDS or time.monotonic() - started > SECONDS:
                    raise OSError('claude_registry_limit')
                if RECORD.fullmatch(entry.name):
                    names.append(entry.name)
            for name in sorted(names):
                if time.monotonic() - started > SECONDS:
                    raise OSError('claude_discovery_timeout')
                try:
                    endpoint, _ = inspect(backend, int(Path(name).stem), connect=connect, tolerate_pipe=True)
                    found.append(endpoint)
                except Ineligible:
                    continue
                except OSError:
                    # A missing pipe/key/record does NOT prove the process died.
                    # Only an independent process query may discard a stale PID.
                    try:
                        peer_process(backend, int(Path(name).stem))
                    except Ineligible:
                        continue
                    except OSError:
                        pass
                    complete = False
    except OSError:
        complete = False
    counts = Counter(e.ref.native_id for e in found)
    duplicates = tuple(replace(e, issues=(*e.issues, 'ambiguous_thread'))
                       for e in found if counts[e.ref.native_id] > 1)
    eligible = tuple(e for e in found if counts[e.ref.native_id] == 1)
    return Discovery(eligible, complete, 'complete' if complete else 'claude_discovery_incomplete', duplicates)
