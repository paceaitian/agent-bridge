"""W3 review regressions: private SDK fixtures, no native provider or key access."""
from dataclasses import replace
from contextlib import redirect_stdout
import io
import json
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

import test_bridge_windows_claude as F
from agentstatus_bridge import cli, worker
from agentstatus_bridge.dispatch import Dispatcher, DISCOVERY_PARK_SECONDS, needs_worker
from agentstatus_bridge.labels import reason_text
from agentstatus_bridge.model import Delivery, NameSource, Provider
from agentstatus_bridge.platforms.transport_codec import encode_address, parse_reply, same_address
from agentstatus_bridge.platforms.windows import claude_discovery as D, claude_peer as P, commands, codex_discovery
from agentstatus_bridge.platforms.windows import worker_identity
from agentstatus_bridge.platforms.windows.io import WinIO
from agentstatus_bridge.store import Store
from agentstatus_bridge.transports import claude_windows as T
from agentstatus_bridge.transports.codex_native import NativeFailure

OTHER = '019b0000-0000-7000-8000-000000000002'


class ReworkTests(unittest.TestCase):
    setUp = F.NativeTests.setUp
    write = F.NativeTests.write
    task = F.NativeTests.task
    inbox = F.NativeTests.inbox
    sending = F.NativeTests.sending

    def another(self, pid=300, **fields):
        self.k.processes[pid] = (0, int(F.BIRTH) + pid, self.k.sid, False, 'claude.exe')
        self.k.images[pid] = r'C:\fixture\claude.exe'
        self.write(str(pid) + '.json', {**self.record, 'pid': pid, 'sessionId': OTHER,
                   'procStartFt': str(int(F.BIRTH) + pid), 'name': 'other', **fields})

    def test_unrelated_known_ineligible_records_do_not_poison_discovery(self):
        for kind in ('generation', 'kind', 'image', 'elevated'):
            with self.subTest(kind=kind):
                self.another(**{'generation': {'procStartFt': '1'}, 'kind': {'kind': 'sdk'}}.get(kind, {}))
                if kind == 'image': self.k.images[300] = r'C:\fixture\other.exe'
                if kind == 'elevated':
                    row = self.k.processes[300]; self.k.processes[300] = (*row[:3], True, row[4])
                result = D.discover(self.p.transport)
                self.assertTrue(result.complete)
                self.assertEqual(result.select('claude@fixture-peer').ref.native_id, F.UUID)
                self.assertEqual(len(result.endpoints), 1)

    def test_unknown_read_failure_keeps_verified_full_uuid_but_not_name_or_prefix(self):
        self.another()
        (self.sessions / '300.json').write_text('{')
        result = D.discover(self.p.transport)
        self.assertFalse(result.complete)
        selected, error = None, None
        try: selected = result.select('claude@id:' + F.UUID)
        except NativeFailure as failure: error = failure.reason
        self.assertIsNone(error)
        self.assertIsNotNone(selected)
        self.assertEqual(selected.ref.native_id, F.UUID)
        # 名字与未观察到的完整 ID 仍报发现不完整；id: 前缀的唯一性无法证明，报 target_id_unverified（§91.2.2）
        for name in ('fixture-peer', 'claude@id:' + OTHER):
            with self.assertRaisesRegex(NativeFailure, 'claude_discovery_incomplete'):
                result.select(name)
        with self.assertRaisesRegex(NativeFailure, 'target_id_unverified'):
            result.select('claude@id:' + F.UUID[:8])

    def test_duplicate_sessions_only_exclude_the_duplicate_group(self):
        self.another(300); self.another(400)
        with patch.object(D.WinIO, 'peer_pid', side_effect=[200, 300, 400]):
            result = D.discover(self.p.transport)
        self.assertTrue(result.complete)
        self.assertEqual([e.ref.native_id for e in result.endpoints], [F.UUID])
        self.assertEqual(len(result.duplicates), 2)
        self.assertEqual(result.select('claude@id:' + F.UUID).ref.native_id, F.UUID)
        with self.assertRaisesRegex(NativeFailure, '^target_ambiguous$'):
            result.select('claude@id:' + OTHER)
        self.assertEqual(sum(row['eligible'] for row in result.document()), 1)

    def test_missing_sessions_is_complete_empty_but_permission_failure_is_unknown(self):
        with patch.object(self.p.files, 'claude_sessions_dir', return_value=self.root / 'absent' / 'sessions'):
            missing = D.discover(self.p.transport)
        self.assertTrue(missing.complete)
        path_type = type(self.sessions)
        with patch.object(path_type, 'lstat', side_effect=PermissionError('synthetic')):
            self.assertFalse(D.discover(self.p.transport).complete)
        from test_bridge_windows_delivery import NamingTests
        codex = NamingTests().result()
        with patch.object(commands, 'evidence', return_value=codex), patch.object(commands, 'claude_evidence', return_value=missing):
            self.assertIs(commands.resolve('原生甲').ref.provider, Provider.CODEX)

    def test_cross_provider_fallback_only_allows_target_not_found(self):
        ep, _ = D.inspect(self.p.transport, 200)
        good = D.Discovery((ep,), True, 'complete')
        for code in ('discovery_incomplete', 'target_names_unverified', 'alias_target_unavailable', 'target_changed'):
            codex = Mock(spec=commands.Discovery)
            codex.select.side_effect = NativeFailure(code)
            with patch.object(commands, 'evidence', return_value=codex), patch.object(commands, 'claude_evidence', return_value=good):
                self.assertEqual(commands.resolve('claude@fixture-peer'), ep)
                with self.assertRaisesRegex(NativeFailure, code): commands.resolve('fixture-peer')
        codex.select.side_effect = NativeFailure('target_not_found')
        with patch.object(commands, 'evidence', return_value=codex), patch.object(commands, 'claude_evidence', return_value=good):
            self.assertEqual(commands.resolve('fixture-peer'), ep)

    def test_actual_worker_sampler_preserves_unknown_claude_completeness(self):
        tick = [1000.]
        with Store.open(self.root / 'ledger') as store:
            _, _, attempt = self.task(store)
            sampler = commands.WorkerDiscovery(self.p.transport)
            with patch.object(commands, 'discover', return_value=commands.Discovery()), patch.object(D, 'discover', return_value=D.Discovery()):
                engine = Dispatcher(store, sampler, {}, clock=lambda: tick[0], monotonic=lambda: tick[0],
                                    provider_discovery_complete=sampler.provider_complete)
                engine.run_once(); tick[0] += DISCOVERY_PARK_SECONDS; engine.run_once()
                self.assertFalse(sampler.provider_complete(Provider.CLAUDE))
                self.assertIs(store.get_attempt(attempt.id).delivery, Delivery.PENDING)
                self.assertFalse(engine.has_live_work())
                self.assertTrue(needs_worker(store, tick[0]))

    def test_exited_target_gets_gone_despite_unrelated_ineligible_record(self):
        tick = [1000.]
        with Store.open(self.root / 'ledger') as store:
            _, _, attempt = self.task(store)
            self.k.processes.pop(200)
            self.another(kind='sdk')
            sampler = commands.WorkerDiscovery(self.p.transport)
            with patch.object(commands, 'discover', return_value=commands.Discovery()):
                engine = Dispatcher(store, sampler, {}, clock=lambda: tick[0], provider_discovery_complete=sampler.provider_complete)
                engine.run_once(); tick[0] += 16; engine.run_once()
            current = store.get_attempt(attempt.id)
            self.assertEqual((current.delivery, current.delivery_reason), (Delivery.FAILED, 'target_gone'))

    def test_buffered_closed_client_232_is_authenticated_before_disconnect(self):
        ep, _ = D.inspect(self.p.transport, 200)
        box = self.inbox(); box.expect(ep, F.UUID)
        handle = box._io.create_pipe(str(box.path)); self.addCleanup(box._io.close_pipe, handle)
        box._handle = handle
        self.k.record(handle)['connect_error'] = 232
        self.k.socket_in.clear()
        def wire(state):
            return (json.dumps({'type': 'auth', 'token': box._token}) + '\n' + json.dumps(F.status(state=state)) + '\n').encode()
        self.k.socket_in.extend(wire('held'))
        disconnected = []
        def disconnect(_):
            disconnected.append(True)
            if len(disconnected) == 1:
                self.k.socket_in.extend(wire('delivered'))
                return 0  # A failed disconnect must not prevent the next valid connection.
            box._stop.set()
            return 1
        with patch.object(self.k, 'DisconnectNamedPipe', side_effect=disconnect): box._serve()
        box._handle = None
        self.assertEqual(box.poll(0), [F.status(), F.status(state='delivered')])
        self.assertFalse(box._failed)

    def test_busy_231_is_not_mistaken_for_a_connection(self):
        io = WinIO(self.k.api)
        handle = io.create_pipe(F.PIPE); self.addCleanup(io.close_pipe, handle)
        self.k.record(handle)['connect_error'] = 231
        with self.assertRaises(OSError) as caught: io.pipe_io(handle, 'accept', 0, __import__('time').monotonic() + 1)
        self.assertEqual(caught.exception.winerror, 231)

    def test_connected_535_is_accepted(self):
        io = WinIO(self.k.api)
        handle = io.create_pipe(F.PIPE); self.addCleanup(io.close_pipe, handle)
        result, error = None, None
        try: result = io.pipe_io(handle, 'accept', 0, __import__('time').monotonic() + 1)
        except OSError as failure: error = str(failure)
        self.assertIsNone(error)
        self.assertEqual(result, 0)

    def test_accept_completion_wins_over_timeout_cancellation(self):
        io = WinIO(self.k.api)
        handle = io.create_pipe(F.PIPE); self.addCleanup(io.close_pipe, handle)
        self.k.io_pending = True
        def done(h, *_):
            self.k.pending.pop(h, None)
            return 1
        with patch.object(self.k, 'GetOverlappedResult', side_effect=done):
            result, error = None, None
            try: result = io.pipe_io(handle, 'accept', 0, __import__('time').monotonic() + 1)
            except OSError as failure: error = str(failure)
            self.assertIsNone(error)
            self.assertEqual(result, 0)
        self.assertFalse(self.k.pending)

    def test_each_authenticated_frame_rechecks_generation(self):
        ep, _ = D.inspect(self.p.transport, 200)
        box = self.inbox(); box.expect(ep, F.UUID)
        frames = [F.status(state='held'), F.status(state='delivered')]
        wire = ('\n'.join(json.dumps(x) for x in [{'type': 'auth', 'token': box._token}, *frames]) + '\n').encode()
        box._io = Mock(peer_pid=Mock(return_value=200), pipe_io=Mock(side_effect=[wire, b'']))
        original = box._accepted
        def accepted(frame, pid, birth):
            result = original(frame, pid, birth)
            row = self.k.processes[200]; self.k.processes[200] = (row[0], row[1] + 1, *row[2:])
            return result
        with patch.object(box, '_accepted', side_effect=accepted), self.assertRaises(OSError): box._connection(1)
        self.assertEqual(box.poll(0), frames[:1])

    def test_expected_callback_expires_after_twelve_minutes(self):
        ep, _ = D.inspect(self.p.transport, 200)
        box = self.inbox()
        with patch.object(P.time, 'monotonic', return_value=1000): box.expect(ep, F.UUID)
        with patch.object(P.time, 'monotonic', return_value=1719.999): self.assertTrue(box._accepted(F.status(), 200, F.BIRTH))
        with patch.object(P.time, 'monotonic', return_value=1720): self.assertFalse(box._accepted(F.status(), 200, F.BIRTH))

    def test_reply_content_lists_and_both_address_encodings(self):
        ep, _ = D.inspect(self.p.transport, 200)
        box = self.inbox(); box.expect(ep, F.UUID)
        for address in ('uds:' + F.PIPE, encode_address(F.PIPE)):
            for content in ('fixture', [{'type': 'text', 'text': 'fix'}, {'type': 'text', 'text': 'ture'}]):
                frame = {'type': 'user', 'from': address, 'message': {'content': content}}
                parsed = parse_reply(frame)
                self.assertIsNotNone(parsed)
                self.assertEqual(parsed.text, 'fixture')
                self.assertTrue(box._accepted(frame, 200, F.BIRTH))
        self.assertFalse(same_address(None, None))
        self.assertFalse(same_address('uds:other', encode_address(F.PIPE)))

    def test_dispatcher_correlates_both_reply_address_encodings(self):
        with Store.open(self.root / 'ledger') as store:
            ep, _, attempt = self.task(store)
            store.begin_send(attempt.id, now=1001, pid=100, start_ticks='win-filetime:'+str(int(F.BIRTH)+1000))
            store.finish_send(attempt.id, delivery=Delivery.WRITTEN, reason='fixture', provider_ref=None,
                              detail={}, now=1001, native_root=ep.ref.data_root)
            engine = Dispatcher(store, lambda: [ep], {}, clock=lambda: 1002)
            for address in ('uds:' + F.PIPE, encode_address(F.PIPE)):
                resolved = engine.resolve_reply(address, attempt.message_id)
                self.assertIsNotNone(resolved)
                self.assertEqual(resolved.attempt.id, attempt.id)

    def peers_output(self, result, *argv):
        output = io.StringIO()
        with (patch.object(commands, 'claude_evidence', return_value=result),
              patch.object(codex_discovery, 'discover', return_value=commands.Discovery(complete=True)),
              patch.object(commands.claude, 'discover', return_value=result), redirect_stdout(output)):
            self.assertEqual(cli.main(['peers', *argv]), 0)
        return output.getvalue()

    def test_windows_peers_text_shows_name_and_readable_discovery_reason(self):
        ep, _ = D.inspect(self.p.transport, 200)
        native = ep.ref.native_id
        # 注册表名字同时进 Endpoint.name（显示用）与 name_source（截断前原文）；真实 discover() 末尾调 with_views()
        named = replace(ep, name='测试名称', name_source=NameSource('named', '测试名称'))
        for complete in (True, False):
            result = D.Discovery((named,), complete, 'complete' if complete else 'claude_discovery_incomplete').with_views()
            output = self.peers_output(result)
            if complete:
                self.assertIn('claude@测试名称〔'+native[:8]+'〕', output)
            else:
                # 发现不完整（§91.3）：名字未核实，只作展示名；消歧前缀没有全集证明，写完整 ID
                self.assertIn('claude@id:'+native+' 名称=测试名称（仅展示）', output)
                self.assertNotIn('claude@测试名称', output)
            self.assertIn('target=claude@id:'+native, output)
            self.assertIsNone(ep.ref.label)
            self.assertIn('发现完整' if complete else '发现不完整', output)
            self.assertNotIn('claude_discovery_incomplete', output)
            # JSON（§91 S4）：name 是可复制主名，另给 displayName 与 nameVerified；target 一律完整 ID
            [row] = [item for item in json.loads(self.peers_output(result, '--json'))['peers']
                     if item['provider'] == 'claude']
            self.assertEqual((row['target'], row['name'], row['displayName'], row['nameVerified']),
                             ('claude@id:'+native, '测试名称', '测试名称', complete))
        # 不可复制的原生名（首尾空白）：JSON name 为 None，只作转义展示名；文本同样只作展示
        edge = replace(ep, name=' 测试名称 ', name_source=NameSource('named', ' 测试名称 '))
        edged = D.Discovery((edge,), True, 'complete').with_views()
        output = self.peers_output(edged)
        self.assertIn('claude@id:'+native[:8]+' 名称=" 测试名称 "（仅展示）', output)
        [row] = [item for item in json.loads(self.peers_output(edged, '--json'))['peers'] if item['provider'] == 'claude']
        self.assertEqual((row['name'], row['displayName'], row['nameVerified']), (None, '" 测试名称 "', False))
        # 反例：端点没带本轮 NameView 时，文本不回退 Endpoint.name 或 label，只写完整 ID
        bare = D.Discovery((named,), True, 'complete')
        output = self.peers_output(bare)
        self.assertNotIn('测试名称', output)
        self.assertIn('claude@id:'+native+'  target=claude@id:'+native, output)
        # 经真实 discover()：端点在发现末尾带上本轮 NameView，peers 文本据此显示已核实的注册表名字
        found = D.discover(self.p.transport)
        self.assertTrue(found.complete)
        self.assertTrue(found.endpoints and all(item.name_view is not None for item in found.endpoints))
        self.assertIn('claude@fixture-peer〔'+native[:8]+'〕  target=claude@id:'+native, self.peers_output(found))

    def test_dead_inbox_with_stale_address_parks_without_claim_or_send(self):
        tick = [1000.]
        with Store.open(self.root / 'ledger') as store:
            ep, _, attempt = self.task(store)
            box = self.inbox(); box._failed = True
            transport = T.Transport(self.p.transport, lambda: box)
            engine = Dispatcher(store, lambda: [ep], {Provider.CLAUDE: transport}, reply_address=box.address,
                                clock=lambda: tick[0], monotonic=lambda: tick[0])
            with patch.object(transport, 'deliver', side_effect=AssertionError('must not send')):
                engine.run_once(); tick[0] += DISCOVERY_PARK_SECONDS; engine.run_once()
            self.assertIs(store.get_attempt(attempt.id).delivery, Delivery.PENDING)
            self.assertFalse(engine.has_live_work())
            self.assertTrue(needs_worker(store, tick[0]))

    def test_payload_limit_and_readable_windows_messages(self):
        with self.sending() as (transport, ep, context, writes, boundary):
            result = transport.deliver(ep, 'x' * (2 * 1024 * 1024), context)
        self.assertEqual(result.reason, 'provider_payload_too_large')
        self.assertEqual(writes, []); boundary.assert_not_called()
        self.assertIn('默认 5 分钟过期', cli._hold_hint(ep, None))
        for code in ('claude_discovery_incomplete', 'claude_session_ambiguous', 'claude_inbox_unavailable',
                     'claude_peer_unverified', 'claude_target_changed'):
            self.assertNotEqual(reason_text(code), code)

    def test_worker_clears_dead_address_and_retries_inbox_every_ten_seconds(self):
        tick, opened, addresses = [0.], [], []
        dead = SimpleNamespace(address='uds:old', healthy=lambda: False, close=Mock())
        def sleep(seconds):
            tick[0] += seconds
            self.assertLess(tick[0], 40, 'worker did not become idle')
        live = SimpleNamespace(address='uds:new', healthy=lambda: True,
                               poll=lambda seconds: sleep(seconds) or [], close=Mock())
        def open_box(_):
            opened.append(tick[0])
            return dead if len(opened) == 1 else live if tick[0] >= 20 else None
        def build(**kwargs):
            engine = Dispatcher(**kwargs)
            original = engine.run_once
            def run_once():
                addresses.append((tick[0], engine.reply_address))
                return original()
            engine.run_once = run_once
            return engine
        with (patch.object(worker_identity, 'register'), patch.object(worker, '_open_inbox', side_effect=open_box),
              patch.object(worker, 'Dispatcher', side_effect=build), patch.object(worker, 'IDLE_EXIT_SECONDS', 23),
              patch.object(worker.time, 'monotonic', side_effect=lambda: tick[0]),
              patch.object(worker.time, 'time', side_effect=lambda: 1000 + tick[0]),
              patch.object(worker.time, 'sleep', side_effect=sleep),
              patch.object(worker, '_publish_summary', return_value=SimpleNamespace(status='written', ledger_id='fixture', revision=0))):
            self.assertEqual(worker.run_worker(root=self.root / 'worker-state', discover_fn=lambda: [], loop_seconds=1), 0)
        self.assertEqual(opened, [0, 10, 20])
        self.assertIsNone(addresses[0][1])
        self.assertEqual(addresses[-1][1], 'uds:new')
        dead.close.assert_called_once(); live.close.assert_called_once()


if __name__ == '__main__': unittest.main()
