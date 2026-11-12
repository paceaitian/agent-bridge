"""§91 Windows 适配器：Codex 原生主名的 alias 否证与旧名字分支往返否证、ID/名字分流、一次索引与差分预言机；
Claude 原生名与本机解析分发（只用合成 Candidate/Endpoint，不连接任何 daemon）。"""
from contextlib import redirect_stdout
from dataclasses import replace
import io
import random
import unittest
from unittest.mock import patch

from agentstatus_bridge.model import Endpoint, EndpointRef, NameSource, Provider
from agentstatus_bridge.native_names import NO_NAME, UNKNOWN_NAME, canonical, copyable
from agentstatus_bridge.platforms.windows import claude_discovery as CD, codex_discovery as D, commands as B
from agentstatus_bridge.platforms.windows.target_aliases import ALIAS, AliasSet
from agentstatus_bridge.platforms.windows.thread_names import native_source
from agentstatus_bridge.transports.codex_native import NativeFailure

A = '019a0000-0000-7000-8000-00000000000a'
B_ = '019a0000-0000-7000-8000-00000000000b'
C = '019a1111-0000-7000-8000-00000000000c'


def row(thread, native=None, *, name=None, cwd='', kind='root', verified=True, names_verified=True, stable=True,
        source='auto'):
    """合成候选：native 是原生主名原文；旧分支的 name 默认与原生名相同（生产中二者来自同一字段）。"""
    if source == 'auto':
        source = NameSource('named', native) if native is not None else NO_NAME
    legacy = (native or '').strip() if name is None else name
    return D.Candidate(thread, kind, A if kind == 'subagent' else None, legacy or cwd, verified, legacy, cwd,
                       names_verified, stable=stable, name_source=source)


def discovery(*rows, aliases=None, unavailable=(), reason='ok', complete=True):
    alias_set = AliasSet(dict(aliases or {}), reason, unavailable=tuple(unavailable))
    return D.Discovery(tuple(rows), complete, 'complete', 'a' * 64, (200, '1'), alias_set, 'b' * 64)


def verified(result):
    return {thread: view.verified for thread, view in result.name_views.items()}


class CodexNegationTests(unittest.TestCase):
    def test_unique_native_names_verify_and_collisions_do_not(self):
        result = discovery(row(A, 'alpha'), row(B_, 'beta'))
        self.assertEqual(verified(result), {A: True, B_: True})
        self.assertEqual(result.name_views[A].target, 'codex@id:' + A)
        result = discovery(row(A, 'x'), row(B_, 'x'))
        self.assertEqual(verified(result), {A: False, B_: False})
        result = discovery(row(A, 'x'), row(B_, ' x', name='x '))  # 不可复制的名字仍否证别人
        self.assertFalse(result.name_views[A].verified)
        result = discovery(row(A, 'x'), row(B_, source=None))  # 可能的 root 没有名字证据：全部未核实
        self.assertEqual(verified(result), {A: False, B_: False})
        self.assertEqual(result.name_views[A].name, 'x')  # 名字仍可展示

    def test_active_alias_negates_other_bindings_but_never_promotes(self):
        # M21 反例：本机 alias x→A、另一绑定 B 原生 x：本机仍选 A，B 的原生 x 未核实
        result = discovery(row(A, 'alpha'), row(B_, 'x'), aliases={'x': A})
        self.assertEqual(result.select('codex@x').thread, A)
        self.assertEqual(verified(result), {A: True, B_: False})
        self.assertEqual(result.name_views[A].name, 'alpha')  # alias 不成为主名
        result = discovery(row(A, 'x'), row(B_, 'y'), aliases={'x': A})
        self.assertEqual(verified(result), {A: True, B_: True})  # 同一绑定不否证
        result = discovery(row(A, 'x'), row(B_, 'x'), aliases={'x': A})
        self.assertEqual(verified(result), {A: False, B_: False})  # 两个原生 x 不因 alias 选中一方而变唯一
        result = discovery(row(A, 'x', source=UNKNOWN_NAME), row(B_, 'y'), aliases={'x': A})
        self.assertEqual(verified(result), {A: False, B_: False})  # alias 不把未知来源提升

    def test_unavailable_alias_and_store_failure(self):
        result = discovery(row(A, 'x'), row(B_, 'y'), unavailable=('x',))
        self.assertEqual(verified(result), {A: False, B_: True})
        with self.assertRaisesRegex(NativeFailure, 'alias_target_unavailable'):
            result.select('codex@x')
        result = discovery(row(A, 'x'), row(B_, 'y'), reason='alias_store_unverified')
        self.assertEqual(verified(result), {A: False, B_: False})

    def test_secondary_cwd_and_incomplete_names_negate_by_round_trip(self):
        result = discovery(row(A, 'alpha', cwd='x'), row(B_, 'x'))
        self.assertEqual(verified(result), {A: True, B_: False})  # 次级 cwd 使本机歧义
        with self.assertRaisesRegex(NativeFailure, '^target_ambiguous$'):
            result.select('codex@x')
        result = discovery(row(A, 'alpha'), row(B_, 'beta', names_verified=False))
        self.assertEqual(verified(result), {A: False, B_: False})  # names_complete 为假
        result = discovery(row(A, 'alpha'), row(C, 'gamma', kind='unknown', verified=False))
        self.assertEqual(verified(result), {A: False, C: False})

    def test_non_recipient_rows_carry_no_name_but_unverified_rows_do(self):
        result = discovery(row(A, 'x'), row(B_, 'x', kind='subagent'), row(C, 'z', kind='internal'))
        self.assertTrue(result.name_views[A].verified)  # 已正证的子代理/internal 不参与
        self.assertIsNone(result.name_views[B_].name)
        result = discovery(row(A, 'x'), row(B_, 'x', kind='conflict'))
        self.assertFalse(result.name_views[A].verified)  # 冲突行可能是 root，参与否证

    def test_native_source_truncation_and_old_server(self):
        self.assertEqual(native_source({'name': 'x' * 96, 'cwd': None}), NameSource('named', 'x' * 96))
        self.assertEqual(native_source({'name': 'x' * 97, 'cwd': None}), NameSource('named', 'x' * 96, True))
        self.assertEqual(native_source({'name': None, 'cwd': 'C:\\w\\proj\\'}), NameSource('named', 'proj'))
        self.assertEqual(native_source({'name': '  ', 'cwd': 'C:\\w\\proj'}), NameSource('named', '  '))
        self.assertIsNone(native_source({'cwd': 'C:\\w\\proj'}))  # 没有 name 键：旧服务端，来源未知
        self.assertIsNone(native_source({'name': 3}))
        result = discovery(row(A, 'x' * 96, source=native_source({'name': 'x' * 97})))
        self.assertFalse(result.name_views[A].verified)
        self.assertTrue(result.name_views[A].display_name.endswith('…'))


class CodexSelectTests(unittest.TestCase):
    def test_ids_and_names_never_fall_back_to_each_other(self):
        result = discovery(row(A, 'alpha'), row(B_, A[:8]), row(C, 'gamma'))
        self.assertEqual(result.select(A[:8]).thread, B_)  # 裸短串只按名字
        with self.assertRaisesRegex(NativeFailure, '^target_ambiguous$'):
            result.select('id:' + A[:8])
        self.assertEqual(result.select('codex@id:' + C[:8]).thread, C)
        self.assertEqual(result.select(A.upper()).thread, A)
        for reference, code in (('019a1111', 'target_not_found'), ('id:019a111', 'target_id_invalid'),
                                ('claude@alpha', 'target_not_found'), (None, 'target_explicit_required'),
                                ('codex@', 'target_explicit_required')):
            with self.subTest(reference=reference), self.assertRaisesRegex(NativeFailure, code):
                result.select(reference)
        incomplete = replace(result, complete=False)
        for reference, code in (('id:' + C, 'discovery_incomplete'), ('alpha', 'discovery_incomplete'),
                                ('codex@id:' + C[:8], 'target_id_unverified')):  # 前缀缺证用新码，完整 ID 与名字照旧
            with self.subTest(reference=reference), self.assertRaisesRegex(NativeFailure, f'^{code}$'):
                incomplete.select(reference)

    def test_target_name_is_private_and_round_trips(self):
        result = discovery(row(A, 'alpha'), row(B_, 'two words', cwd='proj'), row(C), aliases={'work': C})
        self.assertEqual(result.target_name(result.rows[0]), 'codex@alpha')
        self.assertEqual(result.target_name(result.rows[2]), 'codex@work')
        bare = discovery(row(A), row(B_))
        self.assertEqual(bare.target_name(bare.rows[0]), 'codex@id:' + A)  # 只差末位：消歧到完整 ID
        mixed = discovery(row(A), row(B_, kind='subagent'))  # 不可投的子代理行同样参与消歧（全集，不是可投子集）
        self.assertEqual(mixed.target_name(mixed.rows[0]), 'codex@id:' + A)
        self.assertEqual(mixed.select(mixed.target_name(mixed.rows[0])).thread, A)
        self.assertEqual(discovery(row(C)).target_name(row(C)), 'codex@id:' + C[:8])
        for item in (*result.rows, *bare.rows):
            owner = result if item in result.rows else bare
            self.assertEqual(owner.select(owner.target_name(item)).thread, item.thread)
        shaped = discovery(row(A, 'id:x'), row(B_, C))  # 保留形状的旧名字不作 label
        self.assertEqual(shaped.target_name(shaped.rows[0]), 'codex@id:' + A)
        self.assertEqual(shaped.target_name(shaped.rows[1]), 'codex@id:' + B_)

    def test_document_targets_are_full_ids_and_aliases_stay_local(self):
        result = discovery(row(A, 'alpha'), row(B_, 'x'), row(C, kind='subagent'), aliases={'x': A, 'work': A})
        peers = {peer['nativeId']: peer for peer in result.document()['peers']}
        self.assertEqual(peers[A]['target'], 'codex@id:' + A)
        self.assertIsNone(peers[C]['target'])
        self.assertEqual((peers[A]['name'], peers[A]['nameVerified']), ('alpha', True))
        self.assertEqual((peers[B_]['name'], peers[B_]['nameVerified']), ('x', False))
        self.assertEqual(peers[A]['aliases'], ['work', 'x'])  # 本机诊断字段保留
        for peer in peers.values():
            self.assertNotIn(peer['name'], ('work',))
            self.assertNotIn('work', str(peer['target']))
        out = io.StringIO()
        with redirect_stdout(out):
            D.print_peers(result)
        line = next(text for text in out.getvalue().splitlines() if text.startswith('codex@alpha'))
        self.assertIn(f'target=codex@id:{A}', line)
        self.assertTrue(line.endswith('本机别名=work、x（仅本机可用）'))  # 现役 alias 只作本机旁注，不作 target
        self.assertNotIn('codex@work', out.getvalue())


def legacy_select(result, name):
    """独立参照：照搬改造前 Discovery.select 的名字分支（逐行线性扫描），返回可选的 thread 或 None。"""
    if name in result.aliases.unavailable:
        return None
    alias = result.aliases.names.get(name) if ALIAS.fullmatch(name) else None
    if alias is not None:
        matches = [r for r in result.rows if r.thread.startswith(alias)]
    else:
        if not all(r.metadata_verified and (r.kind != 'root' or r.names_verified) for r in result.rows):
            return None
        matches = [r for r in result.rows if r.kind == 'root' and r.metadata_verified
                   and name and name in (r.name, r.cwd_label)]
    if len(matches) != 1:
        return None
    found = matches[0]
    return found.thread if found.stable and found.eligible else None


class DifferentialOracleTests(unittest.TestCase):
    """附注 P3-6：一次索引的否证结果与逐行旧名字分支的结果逐项一致（合成随机样本，固定种子）。"""
    NAMES = ('a', 'b', 'work', ' a', 'a ', 'id:a', A, '', 'x' * 3)
    KINDS = ('root', 'root', 'root', 'subagent', 'internal', 'unknown', 'conflict')

    def sample(self, rng):
        threads = rng.sample([A, B_, C] + [f'019a{n:04x}-0000-7000-8000-0000000000{n:02x}' for n in range(9)],
                             rng.randint(1, 8))
        rows = []
        for thread in threads:
            kind = rng.choice(self.KINDS)
            native = rng.choice(self.NAMES + (None,))
            source = rng.choice((NameSource('named', native) if native is not None else NO_NAME, None, UNKNOWN_NAME))
            rows.append(D.Candidate(thread, kind, None if rng.random() < 0.3 else A, '',
                                    kind != 'unknown' and rng.random() < 0.9,
                                    rng.choice(self.NAMES), rng.choice(self.NAMES), rng.random() < 0.85,
                                    stable=rng.random() < 0.9, name_source=source))
        eligible = [r.thread for r in rows if r.eligible]
        aliases = {name: rng.choice(eligible) for name in ('a', 'b', 'work') if eligible and rng.random() < 0.3}
        unavailable = tuple(name for name in ('a', 'b', 'work') if name not in aliases and rng.random() < 0.2)
        reason = 'alias_store_unverified' if rng.random() < 0.1 else 'ok'
        return discovery(*rows, aliases=aliases, unavailable=unavailable, reason=reason,
                         complete=rng.random() < 0.95)

    def expected(self, result, item):
        source = item.native_name
        value = canonical(source)
        if value is None or not copyable(source) or not result.complete:
            return False
        if any(r.native_name.state == 'unknown' for r in result.rows):
            return False
        if sum(canonical(r.native_name) == value for r in result.rows) != 1:
            return False
        return result.aliases.reason == 'ok' and legacy_select(result, value) == item.thread

    def test_index_matches_row_by_row_legacy_select(self):
        rng = random.Random(9101)
        checked = 0
        for _ in range(600):
            result = self.sample(rng)
            views = result.name_views
            for item in result.rows:
                self.assertEqual(views[item.thread].verified, self.expected(result, item), (result, item))
                checked += 1
            for name in (*self.NAMES[:-2], 'none'):
                if not result.complete or not name:
                    continue
                try:
                    picked = result.select(D.Selector(Provider.CODEX, 'name', name)).thread
                except NativeFailure:
                    picked = None
                self.assertEqual(picked, legacy_select(result, name), (result, name))
        self.assertGreater(checked, 1500)

    def test_large_snapshot_builds_one_index_without_per_row_select(self):
        threads = [f'{n:08x}-0000-7000-8000-000000000000' for n in range(4096)]
        rows = CountingRows(row(t, f'n{n}', cwd=f'c{n % 512}') for n, t in enumerate(threads))
        aliases = {f'al{n}': threads[n * 7] for n in range(256)}
        result = discovery(aliases=aliases)
        result = replace(result, rows=rows)
        with patch.object(D.Discovery, 'select', side_effect=AssertionError('per-row select')):
            views = result.name_views
            labels = [result.target_name(item) for item in rows]
            result.document()
        self.assertEqual(len(views), 4096)
        self.assertTrue(all(views[t].verified for t in threads))
        self.assertEqual(labels[7], 'codex@al1')
        self.assertLessEqual(rows.walks, 8)  # 常数次整表遍历，不随行数逐行重扫


class CountingRows(tuple):
    walks = 0

    def __iter__(self):
        type(self).walks += 1
        return super().__iter__()


def claude(native, name, pid, *, issues=(), source='auto'):
    if source == 'auto':
        source = NameSource('named', name) if name is not None else NO_NAME
    return Endpoint(EndpointRef(Provider.CLAUDE, native, pid, f'win-filetime:{pid}', data_root='r'),
                    name=name, issues=issues, name_source=source)


class ClaudeTests(unittest.TestCase):
    def test_names_require_verified_native_and_prefixes_require_complete(self):
        result = CD.Discovery((claude(A, 'review', 1), claude(C, 'other', 2)), True, 'complete')
        self.assertEqual(result.select('claude@review').ref.native_id, A)
        self.assertEqual(result.select('id:' + C[:8]).ref.native_id, C)
        self.assertEqual(result.select(C.upper()).ref.native_id, C)
        with self.assertRaisesRegex(NativeFailure, 'target_not_found'):
            result.select('019a1111')  # 裸短串不按前缀
        incomplete = replace(result, complete=False, reason='claude_discovery_incomplete')
        self.assertEqual(incomplete.select('claude@id:' + A).ref.native_id, A)
        for reference, code in (('claude@id:' + A[:8], 'target_id_unverified'), ('review', 'claude_discovery_incomplete'),
                                ('claude@id:' + B_, 'claude_discovery_incomplete')):
            with self.subTest(reference=reference), self.assertRaisesRegex(NativeFailure, code):
                incomplete.select(reference)

    def test_collisions_duplicates_and_truncation_are_unverified(self):
        same = CD.Discovery((claude(A, 'x', 1), claude(C, 'x', 2)), True, 'complete')
        with self.assertRaisesRegex(NativeFailure, 'target_names_unverified'):
            same.select('x')
        duplicate = CD.Discovery((), True, 'complete', (claude(A, 'x', 1, issues=('ambiguous_thread',)),
                                                        claude(A, 'x', 2, issues=('ambiguous_thread',))))
        with self.assertRaisesRegex(NativeFailure, 'target_names_unverified'):
            duplicate.select('x')  # 同会话两个独立绑定：名字不能证唯一
        with self.assertRaisesRegex(NativeFailure, '^target_ambiguous$'):
            duplicate.select('id:' + A)
        long = CD.Discovery((claude(A, 'x' * 80, 1, source=NameSource('named', 'x' * 80, True)),), True, 'complete')
        with self.assertRaisesRegex(NativeFailure, 'target_names_unverified'):
            long.select('x' * 80)

    def test_registry_projection_keeps_raw_name_fact(self):
        data = {'pid': 7, 'sessionId': A, 'name': 'y' * 81, 'peerProtocol': 1}
        endpoint = CD.project(data, 7, '1', 'root')
        self.assertEqual(endpoint.name, 'y' * 80)
        self.assertEqual(endpoint.name_source, NameSource('named', 'y' * 80, True))
        self.assertEqual(CD.project({**data, 'name': '  '}, 7, '1', 'root').name_source, NO_NAME)


class ResolveTests(unittest.TestCase):
    def resolve(self, reference, codex, claude_result):
        with patch.object(B, 'evidence', return_value=codex), patch.object(B, 'claude_evidence', return_value=claude_result), \
                patch.object(D.Discovery, 'endpoint', lambda self, item: item):
            return B.resolve(reference)

    def test_provider_dispatch_and_no_first_hit(self):
        codex = discovery(row(A, 'x'), row(B_, 'only-codex'))
        claudes = CD.Discovery((claude(C, 'x', 3),), True, 'complete')
        with self.assertRaisesRegex(NativeFailure, '^target_ambiguous$'):
            self.resolve('x', codex, claudes)  # 两家各一个 x：不首命中返回
        self.assertEqual(self.resolve('Codex@x', codex, claudes).thread, A)  # provider 大小写统一
        self.assertEqual(self.resolve('claude@x', codex, claudes).ref.native_id, C)
        self.assertEqual(self.resolve('only-codex', codex, claudes).thread, B_)
        with self.assertRaisesRegex(NativeFailure, 'target_not_found'):
            self.resolve('grok@x', codex, claudes)
        with self.assertRaisesRegex(NativeFailure, 'target_id_invalid'):
            self.resolve('id:', codex, claudes)

    def test_codex_local_alias_does_not_touch_claude_native_name(self):
        # T1：alias 否证只在 Codex 内部（§91.2.1）；Codex 本机别名 x 不让 claude@x 失效，也不让 Claude 的 x 变未核实
        codex = discovery(row(A, 'alpha'), aliases={'x': A})
        claudes = CD.Discovery((claude(C, 'x', 3),), True, 'complete')
        self.assertEqual(self.resolve('claude@x', codex, claudes).ref.native_id, C)
        self.assertEqual(self.resolve('codex@x', codex, claudes).thread, A)
        self.assertTrue(next(iter(claudes.name_views().values())).verified)
        with self.assertRaisesRegex(NativeFailure, '^target_ambiguous$'):
            self.resolve('x', codex, claudes)  # 无 provider 的本机裸名跨两家判唯一，不首命中返回

    def test_other_provider_unverified_errors_are_not_swallowed(self):
        codex = discovery(row(A, 'x'), row(B_, 'x'))
        claudes = CD.Discovery((claude(C, 'solo', 3),), True, 'complete')
        with self.assertRaisesRegex(NativeFailure, '^target_ambiguous$'):
            self.resolve('x', codex, claudes)  # Codex 旧名字分支的歧义照报，不吞
        incomplete = CD.Discovery((), False, 'claude_discovery_incomplete')
        self.assertEqual(self.resolve(A, codex, incomplete).thread, A)  # 完整 ID 容忍另一家不完整
        with self.assertRaisesRegex(NativeFailure, 'target_id_unverified'):
            self.resolve('id:' + C[:8], discovery(row(C, 'c')), incomplete)
        claudes = CD.Discovery((claude(C, 'x', 3),), True, 'complete')
        with self.assertRaises(NativeFailure) as caught:  # Codex 全集未知：前缀在 Claude 里唯一也不算唯一
            self.resolve('id:' + C[:8], D.Discovery(), claudes)
        self.assertEqual(caught.exception.reason, 'target_id_unverified')


if __name__ == '__main__':
    unittest.main()
