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
from .process_role import Roles

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
    if 'procStartFt' in data and not generation(data['procStartFt'], birth):
        raise Ineligible('claude_registry_ineligible')
    if data.get('kind') not in (None, 'interactive'):
        raise Ineligible('claude_kind_ineligible' if 'procStartFt' in data else 'claude_kind_generation_unknown')
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
            tolerate_pipe: bool = False, sessions: Path | None = None) -> tuple[Endpoint, dict[str, Any]]:
    if type(pid) is not int or not 0 < pid < 2**32:
        raise OSError('claude_process_unverified')
    if sessions is None:
        matches = []
        for path in backend.files.claude_sessions_dirs().roots:
            try:
                matches.append(inspect(backend, pid, connect=connect, tolerate_pipe=tolerate_pipe, sessions=path))
            except OSError:
                continue
        if len(matches) != 1:
            raise OSError('claude_registry_unverified')
        return matches[0]
    files = PeerFiles(backend.files, sessions)
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
    registries: tuple[dict[str, Any], ...] = ()
    root_diagnostics: tuple[tuple[Path, str], ...] = ()
    # §92：本轮当前代际的非交互登记 PID（进程内事实，不进协议/doctor）；与 found 一起构成角色裁决的保护集
    noninteractive: frozenset[int] = frozenset()

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
    registries: list[dict[str, Any]] = []
    count = 0
    budget_hit = False
    try:
        scan = backend.files.claude_sessions_dirs()
    except OSError:
        return Discovery()
    roots = scan.roots
    complete = scan.complete
    unlocated = set(scan.unlocated)
    located_roots = dict(scan.live)
    known_noninteractive: set[int] = set()
    # 逐 PID 的待判缺口：(pid, birth)；birth 为 None 表示拿不到当前事实，不能做角色裁决（§92.5）
    gaps: list[tuple[int, str | None]] = []
    for root in roots:
        files = PeerFiles(backend.files, root)
        diagnostic = {'path': str(root), 'readable': False, 'reason': 'unreadable'}
        registries.append(diagnostic)
        try:
            try:
                files.sessions.lstat()
            except FileNotFoundError:
                diagnostic['reason'] = 'not_found'
                # PEB 已定位的根不存在，表示没有注册记录；不等于环境读取失败。
                continue
            with files.root():
                names: list[str] = []
                for entry in files.sessions.iterdir():
                    count += 1
                    if count > MAX_RECORDS or time.monotonic() - started > SECONDS:
                        budget_hit = True
                        raise OSError('claude_registry_limit')
                    if RECORD.fullmatch(entry.name):
                        names.append(entry.name)
                diagnostic.update(readable=True, reason='readable')
                for name in sorted(names):
                    if time.monotonic() - started > SECONDS:
                        budget_hit = True
                        raise OSError('claude_discovery_timeout')
                    try:
                        endpoint, _ = inspect(backend, int(Path(name).stem), connect=connect,
                                              tolerate_pipe=True, sessions=root)
                        found.append(endpoint)
                    except Ineligible as error:
                        if error.args == ('claude_kind_ineligible',):
                            known_noninteractive.add(int(Path(name).stem))
                        continue
                    except OSError:
                        pid = int(Path(name).stem)
                        if pid in located_roots and located_roots[pid] != root:
                            continue  # 已定位到别处的 PID，不由旧根的损坏残留决定完整性。
                        try:
                            gaps.append((pid, str(peer_process(backend, pid).birth)))
                        except Ineligible:
                            continue
                        except OSError:
                            gaps.append((pid, None))
        except OSError:
            # Speculative accounts are not authority for unrelated live peers.
            # Only an as-yet unlocated owner of this root can affect completeness.
            unlocated.update(pid for pid, path in scan.live if path == root)
            if budget_hit or scan.exclusive:
                complete = False
    for pid in unlocated - known_noninteractive - {endpoint.ref.pid for endpoint in found}:
        try:
            fact = peer_process(backend, pid)
            if PureWindowsPath(backend.api.process_image(pid, str(fact.birth))).name.lower() != 'claude.exe':
                continue
            gaps.append((pid, str(fact.birth)))
        except Ineligible:
            continue
        except OSError:
            gaps.append((pid, None))
    # 全部登记处理完后才裁决角色：有效登记者既不被免除、也不作 P 的见证；只免除同代且已正证的缺口，
    # 全局失败（扫描、预算、显式覆盖）不受影响，已不完整时不必再读命令行。显式覆盖只做 T，不做父子扫描（§92.5）
    if gaps and complete:
        protected = frozenset({endpoint.ref.pid for endpoint in found} | known_noninteractive)
        roles = Roles(backend.api, started + SECONDS, allow_parent=not scan.exclusive)
        if any(birth is None or not roles.exempt(pid, birth, protected) for pid, birth in gaps):
            complete = False
    counts = Counter(e.ref.native_id for e in found)
    duplicates = tuple(replace(e, issues=(*e.issues, 'ambiguous_thread'))
                       for e in found if counts[e.ref.native_id] > 1)
    eligible = tuple(e for e in found if counts[e.ref.native_id] == 1)
    return Discovery(eligible, complete, 'complete' if complete else 'claude_discovery_incomplete', duplicates,
                     tuple(registries), scan.diagnostics, frozenset(known_noninteractive))
