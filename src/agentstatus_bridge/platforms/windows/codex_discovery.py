"""W2-2 read-only Windows candidates. No mux, worker, writes or auto-selection."""
from __future__ import annotations

from collections.abc import Callable
from contextlib import ExitStack
from dataclasses import dataclass, field
from functools import cached_property
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
from .thread_names import names, fields_valid, native_source
from ...model import Endpoint, EndpointRef, NameSource, Provider
from ...native_names import (
    NO_NAME, TARGET_ID_UNVERIFIED, UNKNOWN_NAME, NameFacts, NameView, Selector, SelectorError, endpoint_text,
    id_prefixes, parse_selector, project,
)

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
    # §91 原生主名事实（原文、未转义、保留截断标志）；name/cwd_label 是旧的本机名字分支用的转义值
    name_source: NameSource | None = field(default=None, repr=False, compare=False)

    @property
    def eligible(self) -> bool:
        return self.kind == 'root' and self.metadata_verified and self.stable

    @property
    def native_name(self) -> NameSource:
        """§91.3 的 NameFacts 来源：已正证不属收件类别（子代理、internal）不取名；其余行（含元数据未核实、
        冲突）读到名字就用，读不到即来源未知，使 Codex 原生名一律未核实。"""
        if self.metadata_verified and self.kind in ('subagent', 'internal'):
            return NO_NAME
        return self.name_source if self.name_source is not None else UNKNOWN_NAME


def _selector(reference: str | Selector | None) -> Selector:
    if isinstance(reference, Selector):
        return reference
    if reference is None:
        raise NativeFailure('target_explicit_required')
    try:
        return parse_selector(reference)
    except SelectorError as error:
        raise NativeFailure(error.args[0]) from None


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

    def select(self, reference: str | Selector | None) -> Candidate:
        """解析 Codex 目标（§91.2）：先按公用语法分流 ID 与名字，二者互不回退。

        ID 只认完整 ID 或显式 `id:` 前缀；名字走旧的本机名字分支（alias、原生名、次级 cwd，沿原优先级、
        资格与错误语义），不再并入 ID 前缀。
        """
        selector = _selector(reference)
        if not self.complete:
            # 本机前缀缺证用 target_id_unverified（§91.2.2，与 Windows Claude、Linux 同口径）；完整 ID 与名字照旧
            raise NativeFailure(TARGET_ID_UNVERIFIED if selector.kind == 'prefix' else 'discovery_incomplete')
        if selector.provider not in (None, Provider.CODEX):
            raise NativeFailure('target_not_found')
        if selector.kind == 'id':
            matches = [row for row in self.rows if row.thread == selector.value]
        elif selector.kind == 'prefix':
            matches = [row for row in self.rows if row.thread.startswith(selector.value)]
        else:
            matches = [self._by_thread[thread] for thread in self._legacy_threads(selector.value)]
        if len(matches) != 1:
            raise NativeFailure('target_ambiguous' if matches else 'target_not_found')
        row = matches[0]
        if not row.stable:
            raise NativeFailure('target_changed')
        if not row.eligible:
            raise NativeFailure('target_metadata_unverified' if row.kind == 'unknown' else 'target_not_root')
        return row

    def _legacy_threads(self, name: str) -> frozenset[str]:
        """旧的本机名字分支命中的 thread 集合（查表，不扫 rows）；门错误照旧抛出。"""
        if name in self.aliases.unavailable:
            raise NativeFailure('alias_target_unavailable')
        alias = self.aliases.names.get(name) if ALIAS.fullmatch(name) else None
        if alias is not None:
            return frozenset({alias} & self._by_thread.keys())
        if not self.names_complete:
            raise NativeFailure('target_names_unverified')
        return self._legacy_index.get(name, frozenset())

    def _legacy_pick(self, name: str) -> str | None:
        """旧名字分支对 name 的完整结果：唯一命中且可选的 thread，否则 None（等价于 select 名字分支不抛错）。"""
        try:
            threads = self._legacy_threads(name)
        except NativeFailure:
            return None
        if len(threads) != 1:
            return None
        row = self._by_thread[next(iter(threads))]
        return row.thread if row.eligible else None

    @cached_property
    def _by_thread(self) -> dict[str, Candidate]:
        return {row.thread: row for row in self.rows}

    @cached_property
    def _aliases_by_thread(self) -> dict[str, tuple[str, ...]]:
        """active alias 的反查表（按名字排序），一次建好，避免每行扫一遍 alias 表。"""
        found: dict[str, list[str]] = {}
        for alias, thread in sorted(self.aliases.names.items()):
            found.setdefault(thread, []).append(alias)
        return {thread: tuple(names) for thread, names in found.items()}

    @cached_property
    def _legacy_index(self) -> dict[str, frozenset[str]]:
        """一次遍历建旧名字分支的索引：贡献条件沿原 _named（已核实的 root），原生名与次级 cwd 同等。"""
        index: dict[str, set[str]] = {}
        for row in self.rows:
            if row.kind == 'root' and row.metadata_verified:
                for value in {row.name, row.cwd_label} - {''}:
                    index.setdefault(value, set()).add(row.thread)
        return {value: frozenset(threads) for value, threads in index.items()}

    @cached_property
    def names_complete(self) -> bool:
        return all(r.metadata_verified and (r.kind != 'root' or r.names_verified) for r in self.rows)

    @cached_property
    def name_views(self) -> dict[str, NameView]:
        """§91.3 的 NameView：先原生全集唯一，再用本机 alias 与旧名字分支的同轮索引否证（只能 true→false）。

        alias 文件读失败时全部未核实；暂不可用的 alias 与指向别处的 active alias 否证同名原生名；
        最后往返：旧名字分支对该名字的结果不是本行，就未核实（次级 cwd、names_complete 为假都在此体现）。
        """
        facts = [NameFacts(row.thread, Provider.CODEX, row.thread, row.native_name) for row in self.rows]

        def negated(fact: NameFacts, name: str) -> bool:
            return self.aliases.reason != 'ok' or self._legacy_pick(name) != fact.native_id
        views = project(facts, complete={Provider.CODEX: self.complete}, negated=negated)
        return {str(binding): view for binding, view in views.items()}

    @cached_property
    def _prefixes(self) -> dict[str, str]:
        return id_prefixes((row.thread for row in self.rows), complete=True)

    def endpoint(self, row: Candidate) -> Endpoint:
        if not self.complete or self.daemon is None or not row.eligible or not self.root_identity:
            raise NativeFailure('target_metadata_unverified')
        label = self.target_name(row).removeprefix('codex@')
        return Endpoint(EndpointRef(Provider.CODEX, row.thread, self.daemon[0],
                                   'win-filetime:'+self.daemon[1], label=label, data_root=self.root_identity), consumers=0,
                        name_source=row.native_name, name_view=self.name_views[row.thread])

    def document(self) -> dict[str, object]:
        views = self.name_views
        return {'discovery': self.reason, 'complete': self.complete, 'providerEnabled': True,
                'namingComplete': self.names_complete,
                'hiddenEphemeral': self.hidden_ephemeral, 'loadedTotal': self.loaded_total,
                'nativeReads': self.native_reads, 'nativeReadBudgetHit': self.native_read_budget_hit,
                'aliasState': self.aliases.reason, 'warning': NO_PANE_WARNING,
                'unavailableAliases': [{'alias': a, 'reason': 'alias_target_unavailable',
                                        'message': '别名目标当前不可用'} for a in self.aliases.unavailable],
                # peers 的 target 一律完整 ID（§91.4.2）；alias 与 label 只是本机诊断字段
                'peers': [{'target': views[r.thread].target if r.eligible else None, 'nativeId': r.thread, 'provider': 'codex',
                           'pane': None, 'runtime': 'unknown', 'kind': r.kind, 'eligible': r.eligible, 'stable': r.stable,
                           'label': r.label, 'aliases': list(self._aliases_by_thread.get(r.thread, ())),
                           'name': views[r.thread].name, 'displayName': views[r.thread].display_name,
                           'nameVerified': views[r.thread].verified,
                           'metadataSource': r.metadata_source, 'sourceClass': r.source_class,
                           'sqlPresent': r.sql_present, 'parentPresent': r.parent is not None,
                           'metadata': r.kind if r.metadata_verified else '元数据未核实',
                           'warning': NO_PANE_WARNING} for r in self.rows]}

    def target_name(self, row: Candidate) -> str:
        """本机私有 label（§91.6：endpoint() 仍用它生成 EndpointRef.label）：能往返选回本行的 alias、旧名字或
        次级 cwd，否则 `codex@id:<消歧前缀>`。不是规范名字来源，不进网络输出。"""
        for name in (*self._aliases_by_thread.get(row.thread, ()), row.name, row.cwd_label):
            if not name:
                continue
            try:
                selector = parse_selector('codex@' + name)
            except SelectorError:
                continue
            if selector == Selector(Provider.CODEX, 'name', name) and self._legacy_pick(name) == row.thread:
                return 'codex@' + name
        return 'codex@id:' + self._prefixes.get(row.thread, row.thread)


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
    try:
        backend.files.codex_home().lstat()
    except FileNotFoundError:
        return Discovery(complete=True, reason='complete')
    except OSError:
        return Discovery()
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
            name_sources: dict[str, NameSource] = {}
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
                batch_names: dict[str, NameSource] = {}
                batch_sources: dict[str, str] = {}
                sql = read_classes(files, sql_root or home, ids, deadline, clock,
                                   labels=batch_labels, sources=batch_sources, name_sources=batch_names)
                labels.update(batch_labels)
                name_sources.update(batch_names)
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
                    native = native_source(value)
                    if native is not None:
                        name_sources[thread] = native
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
                                   metadata_sources.get(t, 'none'), sources.get(t, 'other'), t in sql_present, t in stable,
                                   name_sources.get(t))
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
    print(NO_PANE_WARNING)
    if not result.complete:
        print(result.reason)
    views = result.name_views
    for row in result.rows:
        suffix = row.kind if row.metadata_verified else '元数据未核实'
        # 人读名字走 NameView（未核实时只作「名称=…（仅展示）」）；可复制 target 一律完整 ID（§91.4.2）
        view = views[row.thread]
        target = view.target if row.eligible else '不可投递'
        # 现役 alias 只作本机旁注（§91.3 本机例外），不是规范 target，也不进 JSON 以外的网络输出
        aliases = result._aliases_by_thread.get(row.thread, ())
        note = f"  本机别名={'、'.join(aliases)}（仅本机可用）" if aliases else ''
        print(f'{endpoint_text(view)}  target={target}  [{suffix}] 状态未知{note}')
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
