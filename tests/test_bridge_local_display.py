"""§85 本机显示与协议分开（§91.4.2 起名字统一经 NameView）；只用合成端点，不连接 provider。"""
from contextlib import redirect_stdout
from dataclasses import replace
from io import StringIO
from types import SimpleNamespace
import unittest

import bridge_support
from agentstatus_bridge import cli, envelope, reports, views
from agentstatus_bridge.closure import ClosureOutcome, Recipient, closure_body
from agentstatus_bridge.display import endpoint_text
from agentstatus_bridge.model import Attempt, Endpoint, EndpointRef, Flow, NameSource, Provider, ReportKind, Role, Task, Verdict
from agentstatus_bridge.native_names import NO_NAMES, NameBook
from agentstatus_bridge.platforms.factory import using_platform
from agentstatus_bridge.platforms.windows.codex_discovery import Candidate, Discovery, NO_PANE_WARNING, print_peers

ORIGIN = EndpointRef(Provider.CODEX, '01a15e9f-0000-4000-8000-000000000001', 100, '1', label='回复 W3-ONE')
RECEIVER = EndpointRef(Provider.CLAUDE, '2aa904d4-0000-4000-8000-000000000002', 200, '2', label='vm claude')


def book(*items: EndpointRef | Endpoint) -> NameBook:
    """本轮发现的名字表：按这些端点经 Linux 适配器算 NameView 并随端点携带（真实发现的最后一步）。

    传 EndpointRef 时用 bridge_support.endpoint 的默认采样（label 注入为原生主名）；要让主名与 label 不同就传 Endpoint。
    """
    found = [item if isinstance(item, Endpoint) else bridge_support.endpoint(item) for item in items]
    return NameBook.of(bridge_support.with_name_views(found))


class LocalDisplayTests(unittest.TestCase):
    def test_unusable_id_keeps_legacy_display_without_placeholder_suffix(self):
        # §91.4.2：ID 未解析写 provider（ID未解析）；仍不显示〔-〕，但不再回退 label/pane（旧 ref.display()）
        for native in ('-', '', ' ', '\t', ' - '):
            for label, pane in (('中文 name', None), (None, '%5'), (None, None)):
                with self.subTest(native=native, label=label, pane=pane):
                    ref = replace(ORIGIN, native_id=native, label=label, pane=pane)
                    for names in (NO_NAMES, book(ref)):
                        self.assertEqual(endpoint_text(ref, names), 'codex（ID未解析）')
        # 不透明的历史 ID 仍可用，显示不校验 UUID 语法：有同绑定名字照常「名字〔ID〕」，没有就写完整 ID
        old = replace(ORIGIN, native_id='thread-old')
        self.assertEqual(endpoint_text(old, book(old)), 'codex@回复 W3-ONE〔thread-o〕')
        self.assertEqual(endpoint_text(old), 'codex@id:thread-old')

    def test_short_prefix_uses_eight_chars_or_the_whole_short_id(self):
        # §91.1：消歧 ID 由 NameView 按同 provider 完整候选全集一次算出，从 8 位起增长到唯一；调用方不再传 id_prefix
        short_name = replace(ORIGIN, label='01a1')
        self.assertEqual(endpoint_text(short_name, book(short_name)), 'codex@01a1〔01a15e9f〕')
        # 另一候选与它共享前 11 位：前缀增长到 12 位才唯一
        neighbour = EndpointRef(Provider.CODEX, '01a15e9f-001a-4000-8000-000000000009', 101, '1', label='other')
        self.assertEqual(endpoint_text(short_name, book(short_name, neighbour)), 'codex@01a1〔01a15e9f-000〕')
        small = replace(ORIGIN, native_id='abcd')
        self.assertEqual(endpoint_text(small, book(small)), 'codex@回复 W3-ONE〔abcd〕')
        # 名字与 ID 同形不再被猜成 ID 去重：名字逐字比较，照常附消歧 ID
        same = replace(small, label='abcd')
        self.assertEqual(endpoint_text(same, book(same)), 'codex@abcd〔abcd〕')
        nameless = replace(small, label=None)
        self.assertEqual(endpoint_text(nameless, book(nameless)), 'codex@id:abcd')
        self.assertEqual(endpoint_text(small), 'codex@id:abcd')

    def test_names_ids_panes_and_unicode(self):
        # §91.4.2：名字只来自同绑定 NameView；pane 不是名字来源，ID 形状的名字也不再被猜成 ID
        for ref, expected in (
            (ORIGIN, 'codex@回复 W3-ONE〔01a15e9f〕'),
            (RECEIVER, 'claude@vm claude〔2aa904d4〕'),
            (replace(ORIGIN, label='01a15e9f'), 'codex@01a15e9f〔01a15e9f〕'),
            (replace(ORIGIN, label=None), 'codex@id:01a15e9f'),
            (replace(ORIGIN, label=None, pane='%5'), 'codex@id:01a15e9f'),
            (replace(ORIGIN, label='01a15e9f-000'), 'codex@01a15e9f-000〔01a15e9f〕'),
            # 规范值以 id: 开头不可复制（§91.3）：只作展示名
            (replace(ORIGIN, label='id:'+ORIGIN.native_id), 'codex@id:01a15e9f 名称=id:'+ORIGIN.native_id+'（仅展示）'),
            (replace(ORIGIN, label='0'), 'codex@0〔01a15e9f〕'),
        ):
            with self.subTest(expected=expected):
                self.assertEqual(endpoint_text(ref, book(ref)), expected)
                # 没有本轮名字证据：一律完整 ID，不回退 label/pane
                self.assertEqual(endpoint_text(ref), f'{ref.provider.value}@id:{ref.native_id}')
        # 同 provider 两个绑定原生主名相同：互相否证，只作展示名，不挑其中一个
        twin = EndpointRef(Provider.CODEX, '7f000000-0000-4000-8000-000000000007', 300, '3', label=ORIGIN.label)
        self.assertEqual(endpoint_text(ORIGIN, book(ORIGIN, twin)), 'codex@id:01a15e9f 名称=回复 W3-ONE（仅展示）')

    def test_windows_peers_display_and_copyable_long_target(self):
        # 两行原生主名同为 peertest：互相否证，都只作展示名；消歧 ID 前缀要长过 8 位
        rows = tuple(Candidate('12345678-0000-4000-8000-00000000000'+str(i), 'root',
                               label='peertest', cwd_label='peertest', names_verified=True,
                               name_source=NameSource('named', 'peertest')) for i in (1, 2))
        result = Discovery(rows, complete=True, reason='complete')
        before = result.document()
        # nameVerified 是 NameView.verified（主名已证唯一），不再是「名字已读到」：撞名时保留 name 但为 False
        self.assertEqual([(p['name'], p['displayName'], p['nameVerified']) for p in before['peers']],
                         [('peertest', 'peertest', False)] * 2)
        out = StringIO()
        with redirect_stdout(out):
            print_peers(result)
        text = out.getvalue()
        self.assertEqual(text.splitlines()[0], NO_PANE_WARNING)
        self.assertNotIn('尚未通过', text)
        self.assertNotIn('名称未核实', text)  # §91 去掉了旧后缀，未核实改由「名称=…（仅展示）」表达
        for row in rows:
            # §91.4.2：可复制 target 一律完整 ID；人读部分是 codex@id:<消歧前缀> 加仅展示的原生名
            target = 'codex@id:' + row.thread
            prefix = result.name_views[row.thread].id_prefix
            self.assertGreater(len(prefix), 8)
            self.assertIn(f'codex@id:{prefix} 名称=peertest（仅展示）  target={target}', text)
            self.assertEqual(result.select(target).thread, row.thread)
            # 本机私有 label 仍是能往返选回本行的写法
            self.assertEqual(result.select(result.target_name(row)).thread, row.thread)
        self.assertEqual(result.document(), before)
        self.assertEqual(before['peers'][0]['label'], 'peertest')

    def test_windows_named_and_ineligible_peers(self):
        row = Candidate(ORIGIN.native_id, 'root', label=ORIGIN.label, name=ORIGIN.label, names_verified=True,
                        name_source=NameSource('named', ORIGIN.label))
        bad = Candidate(RECEIVER.native_id, 'unknown', label='不可选', name_source=NameSource('named', '不可选'))
        out = StringIO()
        with redirect_stdout(out):
            print_peers(Discovery((row, bad), complete=True))
        # §91.4.2：已核实原生名照旧显示名字〔消歧ID〕，可复制 target 改为完整 ID；不可投递行不再附 ID，
        # 它的名字不在本机名字分支里，只作展示名
        self.assertIn('codex@回复 W3-ONE〔01a15e9f〕  target=codex@id:'+ORIGIN.native_id, out.getvalue())
        self.assertIn('codex@id:2aa904d4 名称=不可选（仅展示）  target=不可投递  [unknown]', out.getvalue())
        # 有一行名字来源未知（没有 name_source）时，Codex 原生名一律未核实，只作展示名（§91.3）
        out = StringIO()
        with redirect_stdout(out):
            print_peers(Discovery((row, replace(bad, name_source=None)), complete=True))
        self.assertIn('名称=回复 W3-ONE（仅展示）  target=codex@id:'+ORIGIN.native_id, out.getvalue())
        self.assertNotIn('codex@回复 W3-ONE〔', out.getvalue())

    def test_closure_text_changes_but_json_stays_legacy(self):
        # §91.4.2：文本走 NameBook.text（名字〔ID〕）；JSON 走本机可复制标识——已核实且整个 provider@名字 无空白才写
        # 名字，否则完整 ID。没有本轮名字证据两者都写完整 ID；都不回退 ref.display()（label）
        item = Attempt('b'*32, 'a'*32, 1, Role.NOTICE, RECEIVER, 'c'*32, 1, 'fixture')
        outcome = ClosureOutcome([item], [(Recipient(item, ORIGIN), 'attempts')])
        receiver_id, origin_id = 'claude@id:' + RECEIVER.native_id, 'codex@id:' + ORIGIN.native_id
        plain = book(bridge_support.endpoint(ORIGIN, native_name=NameSource('named', 'w3-one')),
                     bridge_support.endpoint(RECEIVER, native_name=NameSource('named', 'vm-claude')))
        for case, names, receiver_text, origin_text, receiver_wire, origin_wire in (
            ('spaced', book(ORIGIN, RECEIVER), 'claude@vm claude〔2aa904d4〕', 'codex@回复 W3-ONE〔01a15e9f〕',
             receiver_id, origin_id),
            ('plain', plain, 'claude@vm-claude〔2aa904d4〕', 'codex@w3-one〔01a15e9f〕', 'claude@vm-claude', 'codex@w3-one'),
            ('none', NO_NAMES, receiver_id, origin_id, receiver_id, origin_id),
        ):
            with self.subTest(case=case):
                out = StringIO()
                with redirect_stdout(out):
                    views._print_closure(outcome, names)
                self.assertIn(f'已排队结束回执 → {receiver_text}（', out.getvalue())
                self.assertIn(f'未给 {origin_text} 排结束回执', out.getvalue())
                self.assertEqual(views._closure_document(outcome, names),
                                 {'queued': [{'seq': 1, 'target': receiver_wire}],
                                  'skipped': [{'role': 'notice', 'target': origin_wire, 'capacity': 'attempts'}]})
                self.assertEqual(views._ref_document(ORIGIN, names), {'provider': 'codex', 'name': origin_wire,
                                                                     'pane': None, 'nativeId': ORIGIN.native_id})

    def test_protocol_header_notice_review_and_closure_goldens(self):
        # §91.4.2 取代 wire_ref 的平台屏障：Linux、Windows 同一规则，名字只来自本轮 NameView，label 不进协议输出。
        # 头 from、结果通知、复核请求、结束回执 decider、返工正文都用本机可复制标识；字段顺序与 \S{1,64} 语法不变
        origin_id, receiver_id = 'codex@id:' + ORIGIN.native_id, 'claude@id:' + RECEIVER.native_id
        # 原生主名与账本 ref 的 label 不同（绑定相同）：出现的名字只能来自 NameView
        named = book(bridge_support.endpoint(ORIGIN, native_name=NameSource('named', 'w3-one')),
                     bridge_support.endpoint(RECEIVER, native_name=NameSource('named', 'vm-claude')))
        # 账本 ref 带无空白的 label（可直接当 token）但本轮没有名字证据：仍写完整 ID
        bare_origin, bare_receiver = replace(ORIGIN, label='w3-one'), replace(RECEIVER, label='vm-claude')
        for platform in ('linux', 'windows'):
            for case, names, refs, origin, receiver in (
                ('named', named, (ORIGIN, RECEIVER), 'codex@w3-one', 'claude@vm-claude'),
                # 名字含空格：不转连字符、不截短 ID，写完整 ID
                ('spaced', book(ORIGIN, RECEIVER), (ORIGIN, RECEIVER), origin_id, receiver_id),
                ('none', NO_NAMES, (ORIGIN, RECEIVER), origin_id, receiver_id),
                ('label-only', NO_NAMES, (bare_origin, bare_receiver), origin_id, receiver_id),
            ):
                task = Task('a'*32, 1, 1, '合成任务', Flow.HANDOFF, refs[0], None)
                item = Attempt('b'*32, task.id, 1, Role.HANDOFF, refs[1], 'c'*32, 1, '合成正文', sender=refs[0])
                with self.subTest(platform=platform, case=case), using_platform(SimpleNamespace(name=platform)):
                    text = envelope.render(task, item, sender=names.local_wire(refs[0]), device='testbox', command='ab')
                    header = text.splitlines()[0]
                    self.assertEqual(header, '[AgentStatus 协作] task='+'a'*32+' attempt=1 msg='+'c'*32
                                     +' role=handoff from='+origin+' device=testbox')
                    self.assertRegex(origin, r'^\S{1,64}$')
                    parsed = envelope.parse_header(text)
                    assert parsed is not None
                    self.assertEqual((parsed.sender, parsed.device), (origin, 'testbox'))
                    notice = reports.notice_body(task, item, ReportKind.RESULT, {'note': 'OK'}, names=names)
                    self.assertEqual(notice, f'你发起的任务「合成任务」已完成（{receiver}）。\n结论：OK')
                    review = reports.review_request_body(item, {'note': 'OK'}, names)
                    self.assertEqual(review,
                                     f'请复核 {receiver} 完成的这项工作。\n\n【结果】\n结论：OK\n\n【原始任务要求】\n合成正文')
                    caller = SimpleNamespace(endpoint=Endpoint(refs[0]))
                    _, decider = cli._closure_decider(caller, names)
                    self.assertEqual(decider, origin)
                    self.assertEqual(closure_body(task, 'accepted', decider=decider, reason=None, command='ab'),
                                     f'状态同步：任务「合成任务」已由 {origin} 验收，协作结束。这不代表已部署或用户实机验收。'
                                     '不需要 ab report，也不用再给发起方发消息。')
                    changed = replace(task, flow=Flow.REVIEW, verdict=Verdict.CHANGES)
                    retry = cli._rework_body(item, replace(item, role=Role.REVIEW), changed, None, names)
                    self.assertEqual(retry, f'【返工】\n复核方 {receiver} 要求修改。\n\n【原始任务要求】\n合成正文')
                    for generated in (header, notice, review, decider, retry):
                        for leaked in ('回复', 'vm claude', '〔', *(('w3-one', 'vm-claude') if case != 'named' else ())):
                            self.assertNotIn(leaked, generated)
        # 过渡期旧头（§85/W3.9 写的 8 位 ID 或 tmux 名 token）仍可被读取（§91.2.1），只读不重写
        for legacy in ('codex@01a15e9f', 'codex@回复-W3-ONE'):
            parsed = envelope.parse_header('[AgentStatus 协作] task='+'a'*32+' attempt=1 msg='+'c'*32
                                           +' role=handoff from='+legacy+' device=testbox\n合成正文')
            assert parsed is not None
            self.assertEqual((parsed.role, parsed.sender, parsed.device), (Role.HANDOFF, legacy, 'testbox'))
        # EndpointRef 的 display/token 不全局改（§91.4.2）；只是新输出不再用它们
        self.assertEqual(ORIGIN.display(), 'codex@回复 W3-ONE')
        self.assertEqual(RECEIVER.token(), 'claude@vm-claude')
