"""W2-2 read-only Windows candidates. No mux, worker, writes or auto-selection."""
from __future__ import annotations

from collections.abc import Callable
from contextlib import ExitStack
from dataclasses import dataclass, field
import re
import time

from ...transports.codex_native import (
    BoundedConnection, MAX_IDS, NativeFailure, WINDOWS_READ_SECONDS, ThreadMetadata,
    native_id, project_thread,
)
from ...transports.websocket import _Closed, _Timeout
from .codex_sql import read_classes, source_class
from .local_transport import WindowsPlatform
from .target_aliases import AliasFile, AliasSet, ALIAS
from .thread_names import names, fields_valid
from ...model import Endpoint, EndpointRef, Provider

PAGE_SIZE, MAX_LOADED = 256, 4096
NO_PANE_WARNING = ('可能没有窗口在显示；若窗口已关闭，可 codex resume 查看；'
                   '需要审批时可能等待无人处理')
PREFIX = re.compile(r'[0-9a-fA-F-]{8,36}')


def display_label(value: object) -> str:
    if not isinstance(value, dict):
        return ''
    name, cwd = names(value)
    return name or cwd


@dataclass(frozen=True)
class Candidate:
    thread: str
    kind: str
    parent: str | None = None
    label: str = field(default='', repr=False)  # local presentation, never identity or wire headers
    metadata_verified: bool = True
    name: str = field(default='', repr=False)
    cwd_label: str = field(default='', repr=False)
    names_verified: bool = False
    metadata_source: str = 'none'
    source_class: str = 'other'
    sql_present: bool = False
    stable: bool = True

    @property
    def eligible(self) -> bool:
        return self.kind == 'root' and self.metadata_verified and self.stable


@dataclass(frozen=True)
class Discovery:
    rows: tuple[Candidate, ...] = ()
    complete: bool = False
    reason: str = 'discovery_incomplete'
    root_identity: str = ''
    daemon: tuple[int, str] | None = None
    aliases: AliasSet = field(default_factory=lambda: AliasSet({}))
    home_identity: str = ''  # aliases bind only CODEX_HOME, not SQLite-home relocation
    hidden_ephemeral: int = 0
    loaded_total: int = 0
    native_reads: int = 0
    native_read_budget_hit: bool = False

    def select(self, reference: str | None) -> Candidate:
        if not self.complete:
            raise NativeFailure('discovery_incomplete')
        if not reference:
            raise NativeFailure('target_explicit_required')
        reference = reference.removeprefix('codex@')
        # id: is an explicit disambiguation escape, including UUID-shaped names.
        forced = reference.startswith('id:')
        if forced:
            reference = reference[3:]
        if not reference.strip():
            raise NativeFailure('target_explicit_required')
        explicit_id = forced or native_id(reference) is not None
        if not explicit_id and reference in self.aliases.unavailable:
            raise NativeFailure('alias_target_unavailable')
        alias = self.aliases.names.get(reference) if ALIAS.fullmatch(reference) and not explicit_id else None
        key = alias or (reference.lower() if PREFIX.fullmatch(reference) else None)
        matches = [row for row in self.rows if key is not None and row.thread.startswith(key)]
        if alias is None and not explicit_id:
            if not self.names_complete:
                raise NativeFailure('target_names_unverified')
            matches = list({r.thread: r for r in (*matches, *self._named(reference))}.values())
        if len(matches) != 1:
            raise NativeFailure('target_ambiguous' if matches else 'target_not_found')
        row = matches[0]
        if not row.stable:
            raise NativeFailure('target_changed')
        if not row.eligible:
            raise NativeFailure('target_metadata_unverified' if row.kind == 'unknown' else 'target_not_root')
        return row

    def _named(self, reference: str) -> list[Candidate]:
        # Independent empty-name guard: unnamed rows are never selectors.
        return [r for r in self.rows if r.kind == 'root' and r.metadata_verified
                and reference and reference in (r.name, r.cwd_label)]

    @property
    def names_complete(self) -> bool:
        return all(r.metadata_verified and (r.kind != 'root' or r.names_verified) for r in self.rows)

    def endpoint(self, row: Candidate) -> Endpoint:
        if not self.complete or self.daemon is None or not row.eligible or not self.root_identity:
            raise NativeFailure('target_metadata_unverified')
        label = self.target_name(row).removeprefix('codex@')
        return Endpoint(EndpointRef(Provider.CODEX, row.thread, self.daemon[0],
                                   'win-filetime:'+self.daemon[1], label=label, data_root=self.root_identity), consumers=0)

    def document(self) -> dict[str, object]:
        return {'discovery': self.reason, 'complete': self.complete, 'providerEnabled': True,
                'namingComplete': self.names_complete,
                'hiddenEphemeral': self.hidden_ephemeral, 'loadedTotal': self.loaded_total,
                'nativeReads': self.native_reads, 'nativeReadBudgetHit': self.native_read_budget_hit,
                'qualification': 'implementation_only_pending_w2_5',
                'aliasState': self.aliases.reason, 'warning': NO_PANE_WARNING,
                'unavailableAliases': [{'alias': a, 'reason': 'alias_target_unavailable',
                                        'message': '别名目标当前不可用'} for a in self.aliases.unavailable],
                'peers': [{'target': self.target_name(r) if r.eligible else None, 'nativeId': r.thread, 'provider': 'codex',
                           'pane': None, 'runtime': 'unknown', 'kind': r.kind, 'eligible': r.eligible, 'stable': r.stable,
                           'label': r.label, 'aliases': [a for a, t in self.aliases.names.items() if t == r.thread],
                           'nameVerified': r.names_verified,
                           'metadataSource': r.metadata_source, 'sourceClass': r.source_class,
                           'sqlPresent': r.sql_present, 'parentPresent': r.parent is not None,
                           'metadata': r.kind if r.metadata_verified else '元数据未核实',
                           'warning': NO_PANE_WARNING} for r in self.rows]}

    def target_name(self, row: Candidate) -> str:
        aliases = sorted(a for a, thread in self.aliases.names.items() if thread == row.thread)
        for name in (*aliases, row.name, row.cwd_label):
            if name:
                try:
                    if self.select('codex@'+name).thread == row.thread:
                        return 'codex@'+name
                except NativeFailure:
                    pass
        length = 8
        while sum(r.thread.startswith(row.thread[:length]) for r in self.rows) > 1 and length < 36:
            length += 1
        short = row.thread[:length]
        try:
            if self.select(short).thread != row.thread:
                short = 'id:'+row.thread
        except NativeFailure:
            short = 'id:'+row.thread
        return 'codex@'+short


class Reader:
    def __init__(self, client: BoundedConnection, deadline: float) -> None:
        self.client, self.deadline, self.request_id = client, deadline, 1

    def request(self, method: str, params: dict[str, object]) -> object:
        if method not in {'thread/loaded/list', 'thread/read'}:
            raise NativeFailure('read_method_rejected')
        self.request_id += 1
        self.client._send_json({'id': self.request_id, 'method': method, 'params': params}, self.deadline)
        return self.client.response(self.request_id, self.deadline).get('result')

    def loaded(self) -> tuple[str, ...]:
        ids: list[str] = []
        cursor: str | None = None
        while True:
            result = self.request('thread/loaded/list', {'cursor': cursor, 'limit': PAGE_SIZE})
            if not isinstance(result, dict) or not {'data', 'nextCursor'} <= result.keys():
                raise NativeFailure('discovery_incomplete')
            raw, next_cursor = result['data'], result['nextCursor']
            if not isinstance(raw, list) or len(raw) > PAGE_SIZE:
                raise NativeFailure('discovery_incomplete')
            page: list[str] = []
            previous = cursor or ''
            for item in raw:
                key = native_id(item)
                if key is None or key <= previous:
                    raise NativeFailure('discovery_incomplete')
                page.append(key)
                previous = key
            ids.extend(page)
            if len(ids) > MAX_LOADED:
                raise NativeFailure('discovery_incomplete')
            if next_cursor is None:
                return tuple(ids)
            if (not page or len(page) != PAGE_SIZE or next_cursor != page[-1]
                    or len(ids) >= MAX_LOADED):
                raise NativeFailure('discovery_incomplete')
            cursor = next_cursor


def discover(backend: WindowsPlatform, *, clock: Callable[[], float] | None = None) -> Discovery:
    clock = clock or time.monotonic
    version = backend.codex_cli_version() or 'unknown'
    client: BoundedConnection | None = None
    try:
        with backend.codex_read_scope(version), ExitStack() as leases:
            files = backend.files
            home, sql_root = files.codex_home(), files.codex_sqlite_home()
            leases.enter_context(files.external_directory(home))
            leases.enter_context(files.external_directory(sql_root or home))
            root_identity = files.root_identity(home, sql_root)
            if root_identity is None:
                raise NativeFailure('root_unverified')
            deadline = clock() + WINDOWS_READ_SECONDS
            client = BoundedConnection(home, deadline, clock)
            client.initialize(version, deadline, experimental=True)
            reader = Reader(client, deadline)
            loaded = reader.loaded()
            labels: dict[str, tuple[str, str]] = {}
            sources: dict[str, str] = {}
            records: dict[str, ThreadMetadata] = {}
            sql_present: set[str] = set()
            metadata_sources: dict[str, str] = {}
            hidden: set[str] = set()
            native_reads = 0
            missing: list[str] = []
            def classify(ids: tuple[str, ...]) -> None:
                nonlocal native_reads
                batch_labels: dict[str, tuple[str, str]] = {}
                batch_sources: dict[str, str] = {}
                sql = read_classes(files, sql_root or home, ids, deadline, clock,
                                   labels=batch_labels, sources=batch_sources)
                labels.update(batch_labels)
                sources.update(batch_sources)
                records.update(sql)
                sql_present.update(sql)
                metadata_sources.update({t: 'sql' for t in sql})
                # SQL-present unknown/conflict cannot be overturned by native.
                wanted = [t for t in reversed(ids) if t not in records or
                          records[t].kind == 'subagent' and records[t].parent is None]
                wanted += [t for t in reversed(ids) if t in records and records[t].kind == 'root' and t not in labels]
                missing.extend(wanted)
                for thread in wanted[:MAX_IDS-native_reads]:
                    native_reads += 1
                    result = reader.request('thread/read', {'threadId': thread, 'includeTurns': False})
                    if not isinstance(result, dict) or not isinstance(result.get('thread'), dict):
                        continue
                    value = result['thread']
                    fact = project_thread(value, thread)
                    if value.get('ephemeral') is True:
                        hidden.add(thread)
                        continue
                    metadata_sources[thread] = 'native'
                    sources[thread] = source_class(value.get('source'))
                    if isinstance(value.get('source'), dict) and 'internal' in value['source']:
                        fact = ThreadMetadata('internal')
                    old = records.get(thread)
                    if old is not None and (old.kind != fact.kind or
                                            old.parent is not None and old.parent != fact.parent):
                        fact = ThreadMetadata('conflict')
                    records[thread] = fact
                    if fields_valid(value):
                        labels[thread] = names(value)
            classify(loaded)
            after = reader.loaded()
            first_set = set(loaded)
            stable = first_set & set(after)
            union = tuple(sorted(first_set | set(after)))
            if len(union) > MAX_LOADED:
                raise NativeFailure('discovery_incomplete')
            added = tuple(t for t in after if t not in first_set)
            if added:
                classify(added)  # same connection and remaining metadata budget
            loaded = union
            client.unchanged()
            if files.root_identity(home, sql_root) != root_identity:
                raise NativeFailure('root_changed')
            home_identity = files.root_identity(home)
            if home_identity is None:
                raise NativeFailure('root_unverified')
            aliases = AliasFile(files, files.state_dir()).load(home_identity)
            client._remaining(deadline)
            daemon = backend.read_identity(client._socket)
            rows = tuple(Candidate(t, fact.kind, fact.parent, (labels.get(t, ('', ''))[0] or labels.get(t, ('', ''))[1]),
                                   fact.kind != 'unknown' and not (fact.kind == 'subagent' and fact.parent is None),
                                   *labels.get(t, ('', '')), t in labels,
                                   metadata_sources.get(t, 'none'), sources.get(t, 'other'), t in sql_present, t in stable)
                         for t in loaded if t not in hidden for fact in (records.get(t, ThreadMetadata('unknown')),))
            aliases = aliases.bind(home_identity, daemon, {r.thread for r in rows if r.eligible})
            return Discovery(rows, True, 'metadata_unverified' if any(not r.metadata_verified for r in rows)
                             else 'complete', root_identity, daemon, aliases, home_identity,
                             len(hidden), len(loaded), native_reads, len(missing) > MAX_IDS)
    except (NativeFailure, OSError, _Closed, _Timeout, ValueError):
        return Discovery()  # no partial root, id, title, error body or fallback connection
    finally:
        if client is not None:
            client.close()


def print_peers(result: Discovery) -> None:
    print('Windows Codex 候选；W2-5 实机与独立审计尚未通过。' + NO_PANE_WARNING)
    if not result.complete:
        print(result.reason)
    for row in result.rows:
        suffix = row.kind if row.metadata_verified else '元数据未核实'
        if row.eligible and not row.names_verified:
            suffix += '/名称未核实'
        target = result.target_name(row) if row.eligible else '不可投递 '+row.thread[:8]
        print(f'{target}  {row.label}  [{suffix}] 状态未知')
    for name in result.aliases.unavailable:
        print(f'别名 {name}  别名目标当前不可用')
    if result.aliases.reason != 'ok':
        print(result.aliases.reason)


class WorkerDiscovery:
    """Retain completeness, not just endpoints; an empty loaded set is evidence."""
    def __init__(self, backend: WindowsPlatform) -> None:
        self.backend, self.result = backend, Discovery()

    def __call__(self) -> list[Endpoint]:
        self.result = discover(self.backend)
        return [self.result.endpoint(r) for r in self.result.rows if r.eligible] if self.result.complete else []

    def complete(self) -> bool:
        # An empty eligible projection with unknown classes is not absence.
        return self.result.complete and all(r.metadata_verified and r.stable for r in self.result.rows)
