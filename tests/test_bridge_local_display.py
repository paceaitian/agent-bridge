"""§85 本机显示与协议分开；只用合成端点，不连接 provider。"""
from contextlib import redirect_stdout
from dataclasses import replace
from io import StringIO
from types import SimpleNamespace
import unittest

import bridge_support
from agentstatus_bridge import cli, envelope, reports, views
from agentstatus_bridge.closure import ClosureOutcome, Recipient, closure_body
from agentstatus_bridge.display import endpoint_text
from agentstatus_bridge.model import Attempt, Endpoint, EndpointRef, Flow, Provider, ReportKind, Role, Task, Verdict
from agentstatus_bridge.notification_policy import wire_ref
from agentstatus_bridge.platforms.factory import using_platform
from agentstatus_bridge.platforms.windows.codex_discovery import Candidate, Discovery, NO_PANE_WARNING, print_peers

ORIGIN = EndpointRef(Provider.CODEX, '01a15e9f-0000-4000-8000-000000000001', 100, '1', label='回复 W3-ONE')
RECEIVER = EndpointRef(Provider.CLAUDE, '2aa904d4-0000-4000-8000-000000000002', 200, '2', label='vm claude')


class LocalDisplayTests(unittest.TestCase):
    def test_unusable_id_keeps_legacy_display_without_placeholder_suffix(self):
        for native in ('-', '', ' ', '\t', ' - '):
            for label, pane in (('中文 name', None), (None, '%5'), (None, None)):
                with self.subTest(native=native, label=label, pane=pane):
                    ref = replace(ORIGIN, native_id=native, label=label, pane=pane)
                    self.assertEqual(endpoint_text(ref, id_prefix='-'), ref.display())
                    self.assertNotIn('〔', endpoint_text(ref))
        # Opaque historical IDs are still usable; display does not validate UUID syntax.
        self.assertEqual(endpoint_text(replace(ORIGIN, native_id='thread-old')), 'codex@回复 W3-ONE〔thread-o〕')

    def test_short_prefix_uses_eight_chars_or_the_whole_short_id(self):
        short_name = replace(ORIGIN, label='01a1')
        for prefix in ('', '0', '01a1', '01a15e9', 'unrelated'):
            with self.subTest(prefix=prefix):
                self.assertEqual(endpoint_text(short_name, id_prefix=prefix), 'codex@01a1〔01a15e9f〕')
        self.assertEqual(endpoint_text(short_name, id_prefix=ORIGIN.native_id[:12]),
                         'codex@01a1〔01a15e9f-000〕')
        small = replace(ORIGIN, native_id='abcd')
        self.assertEqual(endpoint_text(small, id_prefix='ab'), 'codex@回复 W3-ONE〔abcd〕')
        self.assertEqual(endpoint_text(replace(small, label='abcd'), id_prefix='ab'), 'codex@abcd')
        self.assertEqual(endpoint_text(replace(small, label=None)), 'codex@abcd')

    def test_names_ids_panes_and_unicode(self):
        for ref, expected in (
            (ORIGIN, 'codex@回复 W3-ONE〔01a15e9f〕'),
            (RECEIVER, 'claude@vm claude〔2aa904d4〕'),
            (replace(ORIGIN, label='01a15e9f'), 'codex@01a15e9f'),
            (replace(ORIGIN, label=None), 'codex@01a15e9f'),
            (replace(ORIGIN, label=None, pane='%5'), 'codex@%5〔01a15e9f〕'),
            (replace(ORIGIN, label='01a15e9f-000'), 'codex@01a15e9f-000'),
            (replace(ORIGIN, label='id:'+ORIGIN.native_id), 'codex@'+ORIGIN.native_id),
            (replace(ORIGIN, label='0'), 'codex@0〔01a15e9f〕'),
        ):
            with self.subTest(expected=expected):
                self.assertEqual(endpoint_text(ref), expected)
        self.assertEqual(endpoint_text(ORIGIN, id_prefix='01a15e9f-000'), 'codex@回复 W3-ONE〔01a15e9f-000〕')
        self.assertEqual(endpoint_text(ORIGIN, id_prefix='unrelated'), 'codex@回复 W3-ONE〔01a15e9f〕')

    def test_windows_peers_display_and_copyable_long_target(self):
        rows = tuple(Candidate('12345678-0000-4000-8000-00000000000'+str(i), 'root',
                               label='peertest', cwd_label='peertest', names_verified=True) for i in (1, 2))
        result = Discovery(rows, complete=True, reason='complete')
        before = result.document()
        out = StringIO()
        with redirect_stdout(out):
            print_peers(result)
        text = out.getvalue()
        self.assertEqual(text.splitlines()[0], NO_PANE_WARNING)
        self.assertNotIn('尚未通过', text)
        for row in rows:
            target = result.target_name(row)
            prefix = target.removeprefix('codex@').removeprefix('id:')
            self.assertGreater(len(prefix), 8)
            self.assertIn(f'codex@peertest〔{prefix}〕  target={target}', text)
            self.assertEqual(result.select(target).thread, row.thread)
        self.assertEqual(result.document(), before)
        self.assertEqual(before['peers'][0]['label'], 'peertest')

    def test_windows_named_and_ineligible_peers(self):
        row = Candidate(ORIGIN.native_id, 'root', label=ORIGIN.label, name=ORIGIN.label, names_verified=True)
        bad = Candidate(RECEIVER.native_id, 'unknown', label='不可选')
        out = StringIO()
        with redirect_stdout(out):
            print_peers(Discovery((row, bad), complete=True))
        self.assertIn('codex@回复 W3-ONE〔01a15e9f〕  target=codex@回复 W3-ONE', out.getvalue())
        self.assertIn('codex@不可选〔2aa904d4〕  target=不可投递 2aa904d4', out.getvalue())

    def test_closure_text_changes_but_json_stays_legacy(self):
        item = Attempt('b'*32, 'a'*32, 1, Role.NOTICE, RECEIVER, 'c'*32, 1, 'fixture')
        outcome = ClosureOutcome([item], [(Recipient(item, ORIGIN), 'attempts')])
        before = views._closure_document(outcome)
        out = StringIO()
        with redirect_stdout(out):
            views._print_closure(outcome)
        self.assertIn('claude@vm claude〔2aa904d4〕', out.getvalue())
        self.assertIn('未给 codex@回复 W3-ONE〔01a15e9f〕 排结束回执', out.getvalue())
        self.assertEqual(before, {'queued': [{'seq': 1, 'target': 'claude@vm claude'}],
                                 'skipped': [{'role': 'notice', 'target': 'codex@回复 W3-ONE', 'capacity': 'attempts'}]})
        self.assertEqual(views._ref_document(ORIGIN), {'provider': 'codex', 'name': 'codex@回复 W3-ONE',
                                                     'pane': None, 'nativeId': ORIGIN.native_id})

    def test_protocol_header_notice_review_and_closure_goldens(self):
        task = Task('a'*32, 1, 1, '合成任务', Flow.HANDOFF, ORIGIN, None)
        item = Attempt('b'*32, task.id, 1, Role.HANDOFF, RECEIVER, 'c'*32, 1, '合成正文', sender=ORIGIN)
        for platform, origin, receiver, sender in (
            ('linux', 'codex@回复 W3-ONE', 'claude@vm claude', 'codex@回复-W3-ONE'),
            ('windows', 'codex@01a15e9f', 'claude@2aa904d4', 'codex@01a15e9f'),
        ):
            with self.subTest(platform=platform), using_platform(SimpleNamespace(name=platform)):
                header = envelope.render(task, item, sender=wire_ref(ORIGIN).token(), device='testbox', command='ab').splitlines()[0]
                self.assertEqual(header, '[AgentStatus 协作] task='+'a'*32+' attempt=1 msg='+'c'*32
                                 +' role=handoff from='+sender+' device=testbox')
                self.assertEqual(reports.notice_body(task, item, ReportKind.RESULT, {'note': 'OK'}),
                                 f'你发起的任务「合成任务」已完成（{receiver}）。\n结论：OK')
                self.assertEqual(reports.review_request_body(item, {'note': 'OK'}),
                                 f'请复核 {receiver} 完成的这项工作。\n\n【结果】\n结论：OK\n\n【原始任务要求】\n合成正文')
                caller = SimpleNamespace(endpoint=Endpoint(ORIGIN))
                _, decider = cli._closure_decider(caller)
                self.assertEqual(decider, origin)
                self.assertEqual(closure_body(task, 'accepted', decider=decider, reason=None, command='ab'),
                                 f'状态同步：任务「合成任务」已由 {origin} 验收，协作结束。这不代表已部署或用户实机验收。'
                                 '不需要 ab report，也不用再给发起方发消息。')
                changed = replace(task, flow=Flow.REVIEW, verdict=Verdict.CHANGES)
                retry = cli._rework_body(item, replace(item, role=Role.REVIEW), changed, None)
                self.assertEqual(retry, '【返工】\n复核方 claude@vm claude 要求修改。\n\n【原始任务要求】\n合成正文')
        self.assertEqual(ORIGIN.display(), 'codex@回复 W3-ONE')
        self.assertEqual(RECEIVER.token(), 'claude@vm-claude')
