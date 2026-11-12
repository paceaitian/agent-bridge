"""§91 纯投影：选择器语法、原生主名证明、ID 消歧、跨设备名字输出与本机人读文本。"""
from dataclasses import replace
import unittest

from agentstatus_bridge.model import Provider
from agentstatus_bridge import native_names as N
from agentstatus_bridge.native_names import NameFacts, NameSource, Selector, SelectorError
from agentstatus_bridge.platforms.windows.thread_names import safe_name
from agentstatus_bridge.transports.claude_peer import normalize_sender_name

A = '019a0000-0000-7000-8000-00000000000a'
B = '019a0000-0000-7000-8000-00000000000b'
C = '019a1111-0000-7000-8000-00000000000c'


def fact(binding, native, raw=None, *, state=None, provider=Provider.CODEX, truncated=False):
    source = NameSource(state or ('named' if raw is not None else 'unnamed'), raw, truncated)
    return NameFacts(binding, provider, native, source)


class SelectorTests(unittest.TestCase):
    def test_id_name_and_provider_forms(self):
        cases = {
            'codex@id:019A0000': Selector(Provider.CODEX, 'prefix', '019a0000'),
            ' Codex @ ID: 019a0000-0000 ': Selector(Provider.CODEX, 'prefix', '019a0000-0000'),
            'id:' + A.upper(): Selector(None, 'id', A),
            A: Selector(None, 'id', A),
            'claude@' + A.upper(): Selector(Provider.CLAUDE, 'id', A),
            'codex@019a0000': Selector(Provider.CODEX, 'name', '019a0000'),  # 裸短串只按名字
            'Review Bot': Selector(None, 'name', 'Review Bot'),
            'codex@ My Thread ': Selector(Provider.CODEX, 'name', 'My Thread'),
            'team@x': Selector(None, 'name', 'team@x'),  # 未知 provider：整体是名字
            '%3': Selector(None, 'name', '%3'),
        }
        for raw, expected in cases.items():
            with self.subTest(raw=raw):
                self.assertEqual(N.parse_selector(raw), expected)

    def test_explicit_id_errors_never_fall_back_to_names(self):
        for raw in ('id:', 'codex@id:', 'id:019a000', 'id:019a0000x', 'id:019a0000_0000', 'id:g-1',
                    'id:019a00000000', 'id:' + A + '0'):
            with self.subTest(raw=raw), self.assertRaises(SelectorError) as caught:
                N.parse_selector(raw)
            self.assertEqual(caught.exception.args, (N.TARGET_ID_INVALID,))
        for raw in ('', '   ', 'codex@', 'claude@  '):
            with self.subTest(raw=raw), self.assertRaises(SelectorError) as caught:
                N.parse_selector(raw)
            self.assertEqual(caught.exception.args, ('target_explicit_required',))


class SourceTests(unittest.TestCase):
    def test_name_source_and_truncation_fact(self):
        self.assertEqual(N.name_source('x' * 80, limit=80), NameSource('named', 'x' * 80))  # 恰等于上限不算截断
        self.assertEqual(N.name_source('x' * 81, limit=80), NameSource('named', 'x' * 80, True))
        self.assertEqual(N.name_source('   '), N.NO_NAME)
        self.assertEqual(N.name_source(None), N.NO_NAME)
        self.assertEqual(N.name_source('x', known=False), N.UNKNOWN_NAME)

    def test_copyable_rejects_every_character_a_name_consumer_would_alter(self):
        # 名字照抄要能原样回到选择器：Claude 帧发送方名会删、Windows safe_name 会转义的字符，copyable 一律为假
        altered, wrong = 0, []
        for code in (*range(0x10000), 0x1F468, 0xE0001, 0xF0000, 0x10FFFD):
            raw = f'a{chr(code)}b'
            if normalize_sender_name(raw) != raw or safe_name(raw) != raw:
                altered += 1
                if N.copyable(NameSource('named', raw)) or chr(code) in (N.display_text(NameSource('named', raw)) or ''):
                    wrong.append(hex(code))  # 不可复制，展示时也只出现转义写法（RLO 不会倒排同行的 target=）
        self.assertEqual(wrong, [])
        self.assertGreater(altered, 4000)  # 前置：确实扫到了大量会被改动的字符（Cc/Cf/Cs/Co/Cn/Zl/Zp）
        self.assertTrue(N.copyable(NameSource('named', 'a\u4e2d\U0001F468b')))  # 中文与 emoji 本身不受影响
        # BMP 之外的转义定长 8 位，与「BMP 字符 + 后面的数字」不会写成同一串
        self.assertEqual(N.display_text(NameSource('named', 'a\U000f0000y')), 'a\\U000f0000y')
        self.assertNotEqual(N.display_text(NameSource('named', 'a\U000f0000y')),
                            N.display_text(NameSource('named', 'a\uf0000y')))

    def test_copyable_and_display(self):
        good = ('alpha', '中文 名字', 'a b', 'x' * 120)
        bad = (' alpha', 'alpha ', 'id:alpha', 'ID:x', A, 'a\tb', 'a\x07', 'a\u2028b', 'x\u200b', 'dev\u200dbox', 'a\u202eb')
        for raw in good:
            with self.subTest(raw=raw):
                self.assertTrue(N.copyable(NameSource('named', raw)))
        for raw in bad:
            with self.subTest(raw=raw):
                self.assertFalse(N.copyable(NameSource('named', raw)))
        self.assertFalse(N.copyable(NameSource('named', 'alpha', True)))
        self.assertEqual(N.display_text(NameSource('named', ' a\x07')), '" a\\u0007"')
        self.assertEqual(N.display_text(NameSource('named', 'abc', True)), 'abc…')
        long = N.display_text(NameSource('named', '\x01' * 100))
        self.assertEqual(len(long), 120); self.assertTrue(long.endswith('…'))
        self.assertIsNone(N.display_text(NameSource('named', '  ')))


class ProjectTests(unittest.TestCase):
    def views(self, facts, complete=True, negated=None):
        return N.project(facts, complete={Provider.CODEX: complete, Provider.CLAUDE: complete}, negated=negated)

    def test_unique_native_name_is_verified(self):
        views = self.views([fact(1, A, 'alpha'), fact(2, B, 'beta'), fact(3, C)])
        self.assertEqual((views[1].name, views[1].verified, views[1].id_prefix), ('alpha', True, A))  # A/B 只差最后一位：唯一前缀即完整 ID
        self.assertEqual(views[3].name, None); self.assertFalse(views[3].verified)
        self.assertEqual(views[3].id_prefix, C[:8])
        self.assertEqual(views[1].target, 'codex@id:' + A)

    def test_collisions_unknown_sources_and_incomplete_sets_never_verify(self):
        views = self.views([fact(1, A, 'x'), fact(2, B, 'x')])
        self.assertFalse(views[1].verified or views[2].verified)
        views = self.views([fact(1, A, 'x'), fact(2, B, ' x ')])  # 不可复制的名字仍以规范值否证别人
        self.assertFalse(views[1].verified); self.assertIsNone(views[2].name)
        views = self.views([fact(1, A, 'x'), fact(2, B, 'X')])  # 区分大小写
        self.assertTrue(views[1].verified and views[2].verified)
        views = self.views([fact(1, A, 'x'), fact(2, C, state='unknown')])
        self.assertFalse(views[1].verified)  # 有绑定名字来源未知：全 provider 未核实
        self.assertEqual(views[1].name, 'x')  # 名字仍可展示
        self.assertEqual(views[1].id_prefix, A[:8])  # 名字缺证不等于身份缺证：消歧前缀照常
        views = self.views([fact(1, A, 'x')], complete=False)
        self.assertFalse(views[1].verified); self.assertEqual(views[1].id_prefix, A)
        views = self.views([fact(1, A, 'x'), fact(2, B, 'x', provider=Provider.CLAUDE)])
        self.assertTrue(views[1].verified and views[2].verified)  # 不同 provider 互不否证

    def test_same_binding_counts_once_and_shared_id_bindings_are_distinct(self):
        views = self.views([fact(1, A, 'x'), fact(1, A, 'x')])
        self.assertTrue(views[1].verified)
        views = self.views([fact((A, 10), A, 'x'), fact((A, 11), A, 'x')])
        self.assertFalse(views[(A, 10)].verified)  # 同 ID 两个独立绑定：名字不能证唯一

    def test_negation_only_lowers(self):
        seen = []
        def negated(row, name):
            seen.append((row.binding, name)); return row.binding == 1
        views = self.views([fact(1, A, 'x'), fact(2, B, 'y'), fact(3, C, ' z')], negated=negated)
        self.assertFalse(views[1].verified); self.assertTrue(views[2].verified)
        self.assertEqual(sorted(seen), [(1, 'x'), (2, 'y')])  # 只对本可核实的行问否证
        views = self.views([fact(1, A, 'x'), fact(2, B, 'x')], negated=lambda row, name: False)
        self.assertFalse(views[1].verified)  # 否证不能把冲突提升为 true


class OutputTests(unittest.TestCase):
    def view(self, name: str | None = 'alpha', verified=True, native=A, provider=Provider.CODEX):
        return N.NameView(provider, native, name, name, verified, native[:8])

    def test_wire_name_only_local_verified_names(self):
        local = dict(endpoint_device=N.LOCAL, render_device=N.LOCAL)
        self.assertEqual(N.wire_name(self.view(), **local), 'codex@alpha')
        full = 'codex@id:' + A
        for kwargs in (dict(endpoint_device=N.LOCAL, render_device='dev-b'),   # A 为 B 预渲染
                       dict(endpoint_device='dev-b', render_device='dev-b'),   # 端点在 B，生成方不在 B
                       dict(endpoint_device=None, render_device=N.LOCAL),      # 设备未知不当本机
                       dict(endpoint_device=N.LOCAL, render_device=None)):
            with self.subTest(**kwargs):
                self.assertEqual(N.wire_name(self.view(), **kwargs), full)
        self.assertEqual(N.wire_name(self.view(verified=False), **local), full)
        self.assertEqual(N.wire_name(self.view(name='two words'), **local), full)
        self.assertEqual(N.wire_name(self.view(name='x' * 58), **local), 'codex@' + 'x' * 58)  # 恰 64 字符
        self.assertEqual(N.wire_name(self.view(name='x' * 59), **local), full)  # 超 64 改全 ID

    def test_overlong_native_id_falls_back_to_display_only_token(self):
        token = N.wire_name(self.view(native='g' * 128, provider=Provider.GROK), endpoint_device=N.LOCAL,
                            render_device='dev-b')
        self.assertLessEqual(len(token), 64); self.assertTrue(token.endswith('…'))
        with self.assertRaises(SelectorError):
            N.parse_selector(token)  # 照抄只会报错，不会误选
        self.assertEqual(N.wire_name(self.view(native=A, provider=Provider.GROK), endpoint_device=None,
                                     render_device=None), 'grok@id:' + A)

    def test_endpoint_text(self):
        self.assertEqual(N.endpoint_text(self.view()), 'codex@alpha〔019a0000〕')
        self.assertEqual(N.endpoint_text(self.view(verified=False)), 'codex@id:019a0000 名称=alpha（仅展示）')
        self.assertEqual(N.endpoint_text(self.view(name=None)), 'codex@id:019a0000')
        self.assertEqual(N.endpoint_text(self.view(native='-')), 'codex（ID未解析）')

    def test_name_book_binding_includes_generation_and_root(self):
        from agentstatus_bridge.model import Endpoint, EndpointRef
        base = EndpointRef(Provider.CODEX, A, 10, '1', data_root='root-a')
        view = N.NameView(Provider.CODEX, A, 'alpha', 'alpha', True, A[:8])
        book = N.NameBook.of([Endpoint(base, name_view=view)])
        self.assertEqual(book.local_wire(base), 'codex@alpha')
        self.assertEqual(book.local_wire(replace(base, native_id=A.upper())), 'codex@alpha')  # ID 大小写不分
        for other in (replace(base, pid=11), replace(base, start_ticks='2'), replace(base, data_root='root-b'),
                      replace(base, data_root=None)):
            with self.subTest(other=other):
                self.assertEqual(book.local_wire(other), 'codex@id:' + other.native_id)  # 不同绑定不借名字
        self.assertEqual(N.binding(base), N.binding(replace(base, label='tmux', pane='%1')))  # 标签/pane 不是身份

    def test_id_token_is_structural_and_sender_display_keeps_the_token_whole(self):
        token = N.id_token(Provider.CLAUDE, A)
        self.assertEqual(token, 'claude@id:' + A)
        self.assertEqual(N.sender_display(token, 'vm'), f'{token}（vm）')
        device = 'd' * 32  # 设备 slug 上限 32
        shown = N.sender_display(token, device)
        self.assertEqual(len(shown), N.SENDER_NAME_LIMIT)
        self.assertTrue(shown.startswith(token + '（') and shown.endswith('…）'))  # 只截设备名，token 完整可复制
        exact = 'e' * (N.SENDER_NAME_LIMIT - len(token) - 2)
        self.assertEqual(N.sender_display(token, exact), f'{token}（{exact}）')  # 恰好 64 不截
        overlong = N.id_token(Provider.GROK, 'g' * 128)  # 超长 ID 回退的仅展示 token 已占满预算
        self.assertEqual(N.sender_display(overlong, 'vm'), overlong)

    def test_id_prefix_grows_to_unique_or_full(self):
        self.assertEqual(N.id_prefix(A, [A, B], complete=True), A)
        self.assertEqual(N.id_prefix(A, [A, C], complete=True), A[:8])
        self.assertEqual(N.id_prefix(A, [A, C], complete=False), A)
        self.assertEqual(N.id_prefix(A, [A, A], complete=True), A[:8])


if __name__ == '__main__':
    unittest.main()
