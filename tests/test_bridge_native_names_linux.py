"""§91 Linux 适配器：Codex/Claude 原生名字采样、按名/ID 解析的全集与核实门（只用临时库与合成端点）。"""
from dataclasses import replace
import json
from pathlib import Path
import sqlite3
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from bridge_support import FakeProc, endpoint, ref
from agentstatus_bridge import endpoints
from agentstatus_bridge.endpoints import ResolveError, resolve_target
from agentstatus_bridge.model import NameSource, Provider
from agentstatus_bridge.native_names import NO_NAME, UNKNOWN_NAME
from agentstatus_bridge.transports.codex_native import NativeBatch, ThreadMetadata, project_thread

A = '019a0000-0000-7000-8000-00000000000a'
B = '019a0000-0000-7000-8000-00000000000b'
C = '019a1111-0000-7000-8000-00000000000c'
COLUMNS = 'id TEXT, source TEXT, name TEXT, cwd TEXT, history_mode TEXT'


class ProjectionTests(unittest.TestCase):
    def thread(self, **fields):
        return project_thread({'id': A, 'source': 'cli', **fields}, A)

    def test_native_name_fields(self):
        self.assertEqual(self.thread(name='alpha', cwd='/w/x').name_source, NameSource('named', 'alpha'))
        self.assertEqual(self.thread(name='', cwd='/w/proj/').name_source, NameSource('named', 'proj'))
        self.assertEqual(self.thread(name=None, cwd='/w/proj').name_source, NameSource('named', 'proj'))
        self.assertEqual(self.thread(name='  ', cwd='/w/proj').name_source, NameSource('named', '  '))  # 不降到 cwd
        self.assertEqual(self.thread(name=None, cwd=None).name_source, NO_NAME)
        self.assertIsNone(self.thread(cwd='/w/proj').name_source)  # 没有 name 字段：旧服务端，来源未知
        self.assertIsNone(self.thread(name=3, cwd='/w').name_source)
        self.assertEqual(self.thread(name='x'), ThreadMetadata('root'))  # 分类相等性不含名字


class SqlNameTests(unittest.TestCase):
    def setUp(self):
        self.temp = TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.home = Path(self.temp.name)

    def db(self, version, columns, rows):
        with sqlite3.connect(self.home / f'state_{version}.sqlite') as db:
            db.execute(f'CREATE TABLE threads({columns})')
            marks = ', '.join('?' for _ in rows[0])
            db.executemany(f'INSERT INTO threads VALUES ({marks})', rows)

    def classes(self, threads):
        sources = endpoints.DiscoverySources(codex_home=self.home, codex_sqlite_home=self.home)
        return endpoints._sql_codex_threads(sources, set(threads))

    def test_only_paginated_rows_give_names_from_the_row_database(self):
        self.db(1, COLUMNS, [(A, 'cli', 'alpha', '/w/a', 'paginated'), (B, 'cli', 'secret title', '/w/b', 'legacy'),
                             (C, 'cli', None, '/w/c', 'paginated')])
        result = self.classes({A, B, C})
        self.assertEqual(result.kinds, {A: 'root', B: 'root', C: 'root'})
        self.assertEqual(result.names, {A: NameSource('named', 'alpha'), C: NameSource('named', 'c')})

    def test_missing_columns_never_break_classification_or_backfill_old_names(self):
        self.db(1, COLUMNS, [(A, 'cli', 'old-name', '/w/a', 'paginated')])
        self.db(2, 'id TEXT, source TEXT', [(A, 'cli')])  # 最新含行的库没有名字列
        result = self.classes({A})
        self.assertEqual(result.kinds, {A: 'root'})
        self.assertEqual(result.names, {})  # 不倒查旧库的名字


class ClassifyNameTests(unittest.TestCase):
    def setUp(self):
        self.temp = TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.home = self.root / 'codex'; self.home.mkdir()
        with sqlite3.connect(self.home / 'state_1.sqlite') as db:
            db.execute('CREATE TABLE threads(id TEXT, source TEXT)')
            db.executemany('INSERT INTO threads VALUES (?, ?)', [(A, 'cli'), (B, json.dumps({'subagent': 'review'}))])
        proc = FakeProc(self.root / 'proc')
        proc.add(20, comm='codex', argv=('codex', 'app-server'),
                 fds=tuple(str(self.home / 'thread-writer-locks' / f'{key}.lock') for key in (A, B)))
        self.proc = proc

    def test_name_only_reads_are_deferred_and_never_rewrite_sql_kinds(self):
        sources = endpoints.DiscoverySources(proc_root=self.proc.root, codex_home=self.home)
        processes = endpoints.scan_codex_holdings(self.proc.root, self.home)
        named = ThreadMetadata('subagent', B, name_source=NameSource('named', 'alpha'))
        with patch.object(sources.native_metadata, 'read', wraps=sources.native_metadata.read) as cache, \
                patch.object(sources.native_metadata.reader, 'read', return_value=NativeBatch({A: named}, 'ok')) as read:
            classes = endpoints._classify_codex_threads(sources, {A, B}, processes)
        self.assertEqual(cache.call_args.kwargs['deferred'], {A})  # 子代理 B 不为取名而读
        self.assertEqual(read.call_args.args[1], [B, A])  # B 为分类（补父）而读，排在只为取名的 A 之前
        self.assertEqual(classes.kinds, {A: 'root', B: 'subagent'})  # 原生的 subagent 不改写 SQL 的 root
        self.assertEqual(classes.names, {A: NameSource('named', 'alpha')})
        self.assertEqual(sources.native_report['sqlFallback'], 1)  # 只算为分类而读却没得到记录的 B，不算取名的 A

    def test_codex_endpoint_name_sources(self):
        classes = endpoints.CodexThreadClasses(kinds={A: 'root', B: 'subagent'}, names={A: NameSource('named', 'x')})
        def with_name(native, issues=()):
            item = endpoint(ref(Provider.CODEX, native), issues=issues, native_name=None)
            return endpoints._with_codex_name(item, classes).name_source
        self.assertEqual(with_name(A), NameSource('named', 'x'))
        self.assertEqual(with_name(B), NO_NAME)
        self.assertEqual(with_name(C), UNKNOWN_NAME)
        self.assertEqual(with_name('-', ('no_thread_yet',)), NO_NAME)
        self.assertEqual(with_name('-', ('subagent_only',)), NO_NAME)
        self.assertEqual(with_name('-', ('title_thread_missing',)), UNKNOWN_NAME)


class ResolveTests(unittest.TestCase):
    def codex(self, native, name, pid, **kwargs):
        source = name if isinstance(name, NameSource) else NameSource('named', name) if name else NO_NAME
        return endpoint(ref(Provider.CODEX, native, pid=pid, label='tmux-label', pane=f'%{pid}'), native_name=source, **kwargs)

    def claude(self, native, name, pid):
        return endpoint(ref(Provider.CLAUDE, native, pid=pid), name=name)

    def code(self, selector, items):
        with self.assertRaises(ResolveError) as caught:
            resolve_target(selector, items)
        return caught.exception

    def test_names_ids_and_completeness(self):
        items = [self.codex(A, 'alpha', 1), self.codex(B, 'beta', 2), self.claude(C, 'review', 3)]
        self.assertIs(resolve_target('codex@alpha', items), items[0])
        self.assertIs(resolve_target('review', items), items[2])
        self.assertIs(resolve_target('id:019a1111', items), items[2])
        self.assertIs(resolve_target(B.upper(), items), items[1])
        self.assertEqual(self.code('id:019a0000', items).code, 'target_ambiguous')
        for selector in ('tmux-label', 'codex@tmux-label', '%1', 'codex@019a0000', '019a1111'):
            with self.subTest(selector=selector):
                self.assertEqual(self.code(selector, items).code, 'target_not_found')
        self.assertEqual(self.code('codex@id:019a000', items).code, 'target_id_invalid')
        unresolved = items + [self.codex('-', UNKNOWN_NAME, 9, issues=('title_thread_missing',))]
        self.assertEqual(self.code('id:019a1111', unresolved).code, 'target_id_unverified')  # 前缀要求身份全集
        self.assertIs(resolve_target('claude@id:019a1111', unresolved), items[2])  # 只看相关 provider
        self.assertEqual(self.code('review', unresolved).code, 'target_names_unverified')  # 裸名要求名字全集
        self.assertIs(resolve_target('claude@review', unresolved), items[2])
        self.assertIs(resolve_target(C, unresolved), items[2])  # 完整 ID 不受全集门影响

    def test_unverified_hits_report_candidates_and_never_pick_one(self):
        items = [self.codex(A, 'same', 1), self.codex(B, 'same', 2), self.codex(C, ' same', 3)]
        error = self.code('codex@same', items)
        self.assertEqual((error.code, set(error.candidates)), ('target_names_unverified', set(items)))
        lone = [self.codex(A, 'same', 1), self.codex(B, ' same', 2)]  # 不可复制的名字仍否证别人
        self.assertEqual(self.code('codex@same', lone).code, 'target_names_unverified')
        blank = [self.codex(A, '  ', 1)]  # 只含空白的原生名不降到 cwd，也不能按名字找到
        self.assertEqual(self.code('codex@  ', blank).code, 'target_explicit_required')
        twins = [self.codex(A, 'x', 1), self.codex(A, 'x', 2)]  # 同一 ID 两个独立绑定同名（§91.2.3）：名字不能证唯一
        views = endpoints.name_views(twins)
        self.assertEqual([views[id(item)].verified for item in twins], [False, False])

    def test_known_non_root_endpoints_keep_the_identity_set_complete(self):
        # 认不出 ID 的端点只有能排除是根会话时（还没 thread、只持有子代理 thread）才不破坏全集；与取名同口径
        # 结果按值比较（选中的 ID 或错误码），门判错时是断言失败而不是用例异常
        def outcome(selector, items):
            try:
                return resolve_target(selector, items).ref.native_id
            except ResolveError as error:
                return error.code

        root = self.codex(A, 'alpha', 1)
        for issue, source, usable in (('subagent_only', NO_NAME, True), ('no_thread_yet', NO_NAME, True),
                                      ('title_thread_missing', UNKNOWN_NAME, False)):
            items = [root, self.codex('-', source, 2, issues=(issue,))]
            with self.subTest(issue=issue):
                expected = (A, A) if usable else ('target_names_unverified', 'target_id_unverified')
                self.assertEqual((outcome('codex@alpha', items), outcome('codex@id:019a0000', items)), expected)

    def test_unseen_incomplete_provider_still_counts_for_bare_selectors(self):
        # 本轮没看全 Claude、且一个 Claude 端点都没露出：无 provider 的前缀与裸名不能落到 Codex 的唯一命中；
        # 写明 codex@ 的照常可用（M4c 在 Linux 上的同形）
        [item] = [replace(self.codex(A, 'alpha', 1), round_incomplete=frozenset({'claude'}))]
        self.assertEqual(self.code('id:019a0000', [item]).code, 'target_id_unverified')
        self.assertEqual(self.code('alpha', [item]).code, 'target_names_unverified')
        self.assertIs(resolve_target('codex@alpha', [item]), item)
        self.assertIs(resolve_target('codex@id:019a0000', [item]), item)
        self.assertIs(resolve_target(A, [item]), item)
        # Grok 没有原生主名：它没看全挡前缀（ID 可能撞前缀），不挡裸名（藏不了同名会话）。按值比较结果，门判错时是断言失败
        [grok] = [replace(self.codex(A, 'alpha', 1), round_incomplete=frozenset({'grok'}))]
        outcomes = []
        for selector in ('alpha', 'id:019a0000'):
            try:
                outcomes.append(resolve_target(selector, [grok]).ref.native_id)
            except ResolveError as error:
                outcomes.append(error.code)
        self.assertEqual(outcomes, [A, 'target_id_unverified'])

    def test_claude_truncation_keeps_the_raw_name_fact(self):
        self.assertEqual(endpoints.name_source('x' * 81, limit=80), NameSource('named', 'x' * 80, True))
        item = endpoint(ref(Provider.CLAUDE, A, pid=1), native_name=NameSource('named', 'x' * 80, True))
        self.assertEqual(self.code('claude@' + 'x' * 80, [item]).code, 'target_names_unverified')


if __name__ == '__main__':
    unittest.main()
