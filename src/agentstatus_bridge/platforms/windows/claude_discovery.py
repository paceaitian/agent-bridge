"""Bounded native Claude registry projection; keys are read only during delivery."""
from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, replace
from pathlib import Path, PureWindowsPath
import re
import time
from typing import Any, cast

from ...claude_titles import TitleReader
from ...model import Endpoint, EndpointRef, Provider, claude_registry_runtime
from ...native_names import (
    TARGET_ID_UNVERIFIED, UNKNOWN_NAME, NameFacts, NameView, Selector, SelectorError, canonical, cwd_tail, name_source,
    parse_selector, project as project_names, workdir_text,
)
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
    raw = data.get('name')
    name = raw[:80] if isinstance(raw, str) and raw.strip() else None
    return Endpoint(EndpointRef(Provider.CLAUDE, session, pid, 'win-filetime:' + birth, data_root=root),
                    # 忙闲取注册信息的 status，与 Linux 同一张表；只读这一个键（§96.2、96.4）
                    runtime=claude_registry_runtime(data.get('status')), runtime_source='claude_registry',
                    name=name, socket_path=pipe,
                    issues=tuple(issues), name_source=name_source(raw, limit=80),  # 截断前保存事实（§91.3）
                    workdir=cwd_tail(data.get('cwd'), windows=True))  # 注册信息的 cwd 只留末段（§95.3）


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


def _binding(endpoint: Endpoint) -> tuple[str, int, str]:
    return (endpoint.ref.native_id, endpoint.ref.pid, endpoint.ref.start_ticks)


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

    def select(self, reference: str | Selector) -> Endpoint:
        """解析 Claude 目标（§91.2）：完整 ID 精确；`id:` 前缀要求发现完整；名字只认已核实的原生主名，互不回退。"""
        try:
            selector = reference if isinstance(reference, Selector) else parse_selector(reference)
        except SelectorError as error:
            raise NativeFailure(error.args[0]) from None
        if selector.provider not in (None, Provider.CLAUDE):
            raise NativeFailure('target_not_found')
        rows = (*self.endpoints, *self.duplicates)
        if selector.kind == 'id':
            matches = [e for e in rows if e.ref.native_id == selector.value]
            if not matches and not self.complete:
                raise NativeFailure(self.reason)  # An unobserved UUID is not proof of absence.
        elif not self.complete:
            raise NativeFailure(TARGET_ID_UNVERIFIED if selector.kind == 'prefix' else self.reason)
        elif selector.kind == 'prefix':
            matches = [e for e in rows if e.ref.native_id.startswith(selector.value)]
        else:
            views = self.name_views()
            matches = [e for e in rows if canonical(e.name_source or UNKNOWN_NAME) == selector.value]
            if any(not views[_binding(e)].verified for e in matches):
                raise NativeFailure('target_names_unverified')
        if len(matches) != 1:
            raise NativeFailure('target_ambiguous' if matches else 'target_not_found')
        if matches[0].blocking_issues:
            raise NativeFailure('target_' + matches[0].blocking_issues[0])
        return matches[0]

    def name_views(self) -> dict[tuple[str, int, str], NameView]:
        """§91.3 的 NameView：按 (会话 ID, PID, 出生代际) 绑定，重复会话的两份登记各算一个绑定。"""
        facts = [NameFacts(_binding(e), Provider.CLAUDE, e.ref.native_id, e.name_source or UNKNOWN_NAME)
                 for e in (*self.endpoints, *self.duplicates)]
        views = project_names(facts, complete={Provider.CLAUDE: self.complete})
        return {cast(tuple[str, int, str], binding): view for binding, view in views.items()}

    def with_views(self) -> Discovery:
        """让端点携带本轮名字投影（§91.4.2：输出侧只查表）；不改身份字段。"""
        views = self.name_views()
        def attach(items: tuple[Endpoint, ...]) -> tuple[Endpoint, ...]:
            return tuple(replace(item, name_view=views[_binding(item)]) for item in items)
        return replace(self, endpoints=attach(self.endpoints), duplicates=attach(self.duplicates))

    def document(self) -> list[dict[str, object]]:
        views = self.name_views()
        return [{'provider': 'claude', 'target': 'claude@id:' + e.ref.native_id, 'nativeId': e.ref.native_id,
                 'pane': None, 'runtime': e.runtime.value, 'kind': 'root',
                 'eligible': not e.blocking_issues, 'name': views[_binding(e)].name,
                 'displayName': views[_binding(e)].display_name, 'nameVerified': views[_binding(e)].verified,
                 'issues': list(e.issues), 'workdir': workdir_text(e.workdir)}
                for e in (*self.endpoints, *self.duplicates)]


def discover(backend: WindowsPlatform, *, connect: bool = True) -> Discovery:
    found: list[Endpoint] = []
    found_roots: list[Path] = []  # 与 found 一一对应的 sessions 目录：取会话记录标题用（§99.3）
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
                        found_roots.append(root)
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
    # 计时与完整性裁决都已结束才取名（§99.2）：标题优先、取不到退回注册名，读多读少都不改变完整性
    titles = TitleReader(backend.files.open_shared_read)
    found = [titles.apply(endpoint, root.parent) for endpoint, root in zip(found, found_roots)]
    counts = Counter(e.ref.native_id for e in found)
    duplicates = tuple(replace(e, issues=(*e.issues, 'ambiguous_thread'))
                       for e in found if counts[e.ref.native_id] > 1)
    eligible = tuple(e for e in found if counts[e.ref.native_id] == 1)
    return Discovery(eligible, complete, 'complete' if complete else 'claude_discovery_incomplete', duplicates,
                     tuple(registries), scan.diagnostics, frozenset(known_noninteractive)).with_views()
