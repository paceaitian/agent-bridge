"""W3 contract on independent SDK buffers and private fixtures, never real keys/pipes."""
from contextlib import contextmanager
from dataclasses import replace
import json
import os
from pathlib import Path
import queue
import threading
import time
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import Mock, patch

import bridge_support
from bridge_platform_guard import windows_fixture
from bridge_winapi import Kernel
from agentstatus_bridge.model import Delivery, Endpoint, EndpointRef, Provider
from agentstatus_bridge.transports import DeliveryContext
from agentstatus_bridge.transports import claude_windows as T
from agentstatus_bridge.platforms.factory import make_platform, using_platform
from agentstatus_bridge.platforms.transport_codec import encode_address, MAX_INBOX_BUFFER
from agentstatus_bridge.platforms.windows import claude_auth as A, claude_discovery as D, claude_peer as P, caller, commands
from agentstatus_bridge.platforms.windows.io import local_pipe
from agentstatus_bridge.platforms.windows import io as IO, abi as ABI
from agentstatus_bridge.transports.codex_native import NativeFailure
from agentstatus_bridge.dispatch import Dispatcher, DISCOVERY_PARK_SECONDS, needs_worker
from agentstatus_bridge.store import Store
from agentstatus_bridge.model import Flow
from agentstatus_bridge.platforms.windows.local_transport import IdentityEvidence

PIPE = r'\\.\pipe\LOCAL\cc-msg-0123456789abcdef0123456789abcdef'
UUID = '019a0000-0000-7000-8000-000000000001'
BIRTH = '134362090000012230'
TOKEN = 'a' * 32


def status(message=UUID, state='held'):
    return {'type': 'control', 'action': 'peer_message_status', 'orig_msg_id': message, 'status': state}


class NativeTests(unittest.TestCase):
    def setUp(self):
        self.temp = TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.sessions = self.root / 'config' / 'sessions'
        self.sessions.mkdir(parents=True)
        self.k = Kernel(self.root)
        self.k.processes[100] = (200, int(BIRTH)+1000, self.k.sid, False, 'python.exe')
        self.k.processes[200] = (0, int(BIRTH), self.k.sid, False, 'claude.exe')
        self.k.images[200] = r'C:\fixture\claude.exe'
        self.k.peer = 200
        self.p = make_platform('windows', win_api=self.k.api)
        self.addCleanup(lambda: self.assertEqual(self.k.handles, {}))
        self.record = {'pid': 200, 'sessionId': UUID, 'peerProtocol': 1, 'kind': 'interactive',
                       'messagingSocketPath': PIPE, 'procStartFt': BIRTH, 'name': 'fixture-peer'}
        self.write('200.json', self.record)
        self.write(A.key_name(200, PIPE), {'peerToken': TOKEN, 'childToken': 'b'*32, 'procStartFt': BIRTH})
        self.enterContext(patch.object(self.p.files, 'claude_sessions_dir', return_value=self.sessions))
        self.enterContext(using_platform(self.p))
        self.enterContext(windows_fixture('pipe', PIPE))

    def write(self, name, data):
        (self.sessions / name).write_text(json.dumps(data), encoding='utf-8')

    def test_discovery_binds_registry_process_pipe_and_not_key(self):
        with patch.object(A.PeerFiles, 'token', side_effect=AssertionError('discovery key read')):
            result = D.discover(self.p.transport)
        self.assertTrue(result.complete)
        self.assertEqual(len(result.endpoints), 1)
        ep = result.select('claude@fixture-peer')
        self.assertEqual(ep.ref.provider, Provider.CLAUDE)
        self.assertEqual(ep.ref.start_ticks, 'win-filetime:' + BIRTH)
        self.assertEqual(result.select('claude@id:' + UUID[:8]), ep)
        self.assertEqual(len(ep.ref.data_root), 64)
        self.assertNotIn(TOKEN, json.dumps(result.document()))
        with self.assertRaises(NativeFailure): result.select('claude@id:fixture-peer')

    def test_registry_shape_generation_and_pipe_are_strict(self):
        for update in ({'pid': True}, {'pid': 201}, {'sessionId': 'bad'}):
            with self.subTest(update=update):
                self.write('200.json', {**self.record, **update})
                self.assertFalse(D.discover(self.p.transport).complete)
        for update in ({'kind': 'subagent'}, {'procStartFt': '1'}):
            with self.subTest(update=update):
                self.write('200.json', {**self.record, **update})
                result = D.discover(self.p.transport)
                self.assertTrue(result.complete)
                self.assertEqual(result.endpoints, ())
        for update, reason in (({'peerProtocol': True}, 'peer_protocol_unsupported'),
                               ({'peerProtocol': 2}, 'peer_protocol_unsupported'),
                               ({'messagingSocketPath': r'\\remote\pipe\cc-msg-'+'a'*32}, 'socket_unavailable')):
            with self.subTest(update=update):
                self.write('200.json', {**self.record, **update})
                result = D.discover(self.p.transport)
                self.assertTrue(result.complete)
                self.assertEqual(result.endpoints[0].issues, (reason,))
                with self.assertRaisesRegex(NativeFailure, 'target_' + reason): result.select(UUID)

    def test_dead_pid_is_stale_but_missing_pipe_only_marks_live_endpoint(self):
        self.k.processes.pop(200)
        self.assertTrue(D.discover(self.p.transport).complete)
        self.k.processes[200] = (0, int(BIRTH), self.k.sid, False, 'claude.exe')
        error = OSError('synthetic'); error.winerror = 2
        with patch.object(D.WinIO, 'open_pipe', side_effect=error):
            result = D.discover(self.p.transport)
            self.assertTrue(result.complete)
            self.assertEqual(result.endpoints[0].issues, ('socket_unavailable',))

    def test_registry_enumeration_budget_includes_non_session_names(self):
        with patch.object(D,'MAX_RECORDS',1):
            self.assertFalse(D.discover(self.p.transport).complete)
        with patch.object(D.time,'monotonic',side_effect=[0,6]):
            self.assertFalse(D.discover(self.p.transport).complete)

    def test_discovery_rejects_wrong_server_image_and_ambiguous_session(self):
        self.k.peer = 100
        self.assertEqual(D.discover(self.p.transport).endpoints[0].issues, ('socket_unavailable',))
        self.k.peer = 200
        self.k.images[200] = r'C:\fixture\python.exe'
        self.assertEqual(D.discover(self.p.transport).endpoints, ())
        self.k.images[200] = r'C:\fixture\claude.exe'
        endpoint, _ = D.inspect(self.p.transport, 200)
        result = D.Discovery((endpoint, replace(endpoint, ref=replace(endpoint.ref, pid=300))), True, 'complete')
        with self.assertRaisesRegex(NativeFailure, '^target_ambiguous$'): result.select(UUID)

    def test_key_exact_peer_token_and_optional_generation(self):
        files = A.PeerFiles(self.p.files)
        self.assertEqual(files.token(200, PIPE, BIRTH, self.record), TOKEN)
        for value in ({'childToken': TOKEN}, {'peerToken': 'x'*32}, {'peerToken': TOKEN, 'procStartFt': '1'},
                      {'peerToken': TOKEN, 'procStart': 'old'}):
            self.write(A.key_name(200, PIPE), value)
            with self.assertRaises(OSError): files.token(200, PIPE, BIRTH, {**self.record, 'procStart': 'new'})
        self.write(A.key_name(200, PIPE), {'peerToken': TOKEN})
        self.assertEqual(files.token(200, PIPE, BIRTH, self.record), TOKEN)

    def test_key_bounds_duplicate_fields_and_reparse_refused(self):
        files, name = A.PeerFiles(self.p.files), A.key_name(200, PIPE)
        for raw in ('{"peerToken":"a","peerToken":"b"}', '[]', ' '*(64*1024+1)):
            (self.sessions/name).write_text(raw)
            with self.assertRaises(OSError): files.read(name)
        self.write(name, {'peerToken': TOKEN})
        self.k.files[str(self.sessions/name)] = {'reparse': True}
        with self.assertRaises(OSError): files.read(name)
        with self.assertRaises(OSError): files.read('../200.json')

    def own(self):
        return A.OwnKey(A.PeerFiles(self.p.files), 100, PIPE, str(int(BIRTH)+1000), 'c'*32)

    def test_own_key_create_new_cleanup_and_full_width_identity(self):
        owned = self.own(); owned.publish()
        path = self.sessions / owned.name
        self.assertEqual(set(json.loads(path.read_bytes())), {'peerToken', 'procStartFt'})
        self.assertEqual(owned._identity[0], 2082046436356788024)
        self.assertEqual(len(owned._identity[1]), 32)
        second = self.own()
        with self.assertRaises(OSError): second.publish()
        second.close()
        self.assertTrue(path.exists())
        owned.close(); owned.close()
        self.assertFalse(path.exists())
        self.assertTrue((self.sessions/'200.json').exists())

    def test_own_key_does_not_delete_replacement(self):
        owned = self.own(); owned.publish()
        path = self.sessions / owned.name
        self.k.files[str(path)]['file_id128'] = 2**120 + 1
        with self.assertRaisesRegex(OSError, 'identity_changed'): owned.close()
        self.assertTrue(path.exists())
        self.assertFalse(any(n == 'SetFileInformationByHandle' for n, _ in self.k.calls))

    def test_failed_publish_closes_and_deletes_only_its_created_leaf(self):
        owned = self.own()
        self.k.faults['FlushFileBuffers'] = 5
        with self.assertRaises(OSError): owned.publish()
        owned.close()
        self.assertFalse((self.sessions / owned.name).exists())
        self.assertTrue((self.sessions / A.key_name(200, PIPE)).exists())

    def test_nearest_native_claude_is_caller_without_env_and_ignores_inherited_codex(self):
        for env in ({}, {'CODEX_THREAD_ID': 'old', 'CODEX_SESSION_ID': 'different'}):
            who = caller.identify(pid=100, environ=env)
            self.assertIsNotNone(who.endpoint)
            self.assertEqual(who.endpoint.ref.native_id, UUID)
            self.assertFalse(who.is_user_shell)
        who = caller.identify(pid=100, environ={'CLAUDE_CODE_SESSION_ID': 'other'})
        self.assertIsNone(who.endpoint)
        self.assertFalse(who.is_user_shell)

    def test_environment_and_outer_claude_do_not_override_nearest_other_agent(self):
        self.k.processes[100] = (150, int(BIRTH)+1000, self.k.sid, False, 'python.exe')
        self.k.processes[150] = (200, int(BIRTH)+500, self.k.sid, False, 'grok.exe')
        who = caller.identify(pid=100, environ={'CLAUDE_CODE_SESSION_ID': UUID})
        self.assertIsNone(who.endpoint)
        self.assertFalse(who.is_user_shell)

    def inbox(self):
        box = P.Inbox(self.p.files)
        box._thread = Mock(is_alive=Mock(return_value=True))
        return box

    def test_inbox_registers_actual_writer_process_and_cleans_on_close(self):
        box = P.Inbox(self.p.files)
        thread = Mock(is_alive=Mock(return_value=False))
        with patch.object(P.threading,'Thread',return_value=thread), patch.object(self.k.api.k,'CancelIoEx',return_value=1):
            box.open()
            path=self.sessions / A.key_name(100,str(box.path))
            self.assertEqual(json.loads(path.read_bytes())['procStartFt'],str(int(BIRTH)+1000))
            self.assertEqual(box._key.name.split('.')[0],'100')
            self.assertEqual(thread.start.call_count,1)
            box.close(); box.close()
            self.assertFalse(path.exists())
            self.assertIsNone(box._handle)
            self.assertEqual(box._token,'')

    def test_listener_start_failure_removes_only_own_key_and_closes_pipe(self):
        box=P.Inbox(self.p.files)
        thread=Mock(start=Mock(side_effect=RuntimeError('synthetic thread failure')))
        with patch.object(P.threading,'Thread',return_value=thread):
            with self.assertRaises(RuntimeError): box.open()
        thread.join.assert_not_called()
        self.assertFalse((self.sessions/A.key_name(100,str(box.path))).exists())
        self.assertTrue((self.sessions/A.key_name(200,PIPE)).exists())

    def test_callback_cross_user_and_elevated_peer_are_refused(self):
        endpoint,_=D.inspect(self.p.transport,200)
        box=self.inbox(); box.expect(endpoint,UUID)
        box._io=Mock(peer_pid=Mock(return_value=200), pipe_io=Mock(return_value=b''))
        original=self.k.processes[200]
        foreign=bytes.fromhex('01010000000000052b000000')
        for stage in ('process', 'token', 'queryable'):
            self.k.restricted_process_stage=stage
            for changed in ((original[0],original[1],foreign,False,original[4]),
                            (*original[:3],True,original[4])):
                with self.subTest(stage=stage, elevated=changed[3]):
                    self.k.processes[200]=changed
                    with self.assertRaises(OSError) as caught: box._connection(1)
                    if stage == 'queryable':
                        self.assertEqual(str(caught.exception), 'claude_inbox_peer_mismatch')
        box._io.pipe_io.assert_not_called()

    def test_expected_receipts_require_message_peer_generation_and_address(self):
        endpoint, _ = D.inspect(self.p.transport, 200)
        box = self.inbox(); box.expect(endpoint, UUID)
        for state in ('held', 'delivered', 'denied'):
            self.assertTrue(box._accepted(status(state=state), 200, BIRTH))
        self.assertFalse(box._accepted(status(message='other'), 200, BIRTH))
        self.assertFalse(box._accepted(status(), 100, BIRTH))
        self.assertFalse(box._accepted(status(), 200, '1'))
        frame = {'type': 'user', 'from': encode_address(PIPE), 'message': {'content': 'fixture'}}
        self.assertTrue(box._accepted(frame, 200, BIRTH))
        self.assertFalse(box._accepted({**frame, 'from': 'uds:other'}, 200, BIRTH))
        self.assertFalse(box._accepted(status(state='unknown-new-state'), 200, BIRTH))

    def test_authenticated_callback_checks_kernel_peer_and_never_queues_auth(self):
        endpoint, _ = D.inspect(self.p.transport, 200)
        box = self.inbox(); box.expect(endpoint, UUID)
        wire = (json.dumps({'type': 'auth', 'token': box._token})+'\n'+json.dumps(status())+'\n').encode()
        io = Mock(peer_pid=Mock(return_value=200), pipe_io=Mock(side_effect=[wire, b'']))
        box._io = io
        box._connection(1)
        self.assertEqual(box.poll(0), [status()])
        io.peer_pid.return_value = 100
        with self.assertRaises(OSError): box._connection(1)
        self.assertEqual(box.poll(0), [])

    def test_callback_bad_auth_and_unexpected_message_never_queue(self):
        endpoint, _ = D.inspect(self.p.transport, 200)
        box = self.inbox(); box.expect(endpoint, UUID)
        for token, frame in (('0'*32, status()), (box._token, status(message='other'))):
            wire = (json.dumps({'type': 'auth', 'token': token})+'\n'+json.dumps(frame)+'\n').encode()
            box._io = Mock(peer_pid=Mock(return_value=200), pipe_io=Mock(side_effect=[wire, b'']))
            try: box._connection(1)
            except OSError: pass
            self.assertEqual(box.poll(0), [])

    @contextmanager
    def sending(self, *, failure=None, short=False):
        endpoint, _ = D.inspect(self.p.transport, 200)
        box = self.inbox()
        writes, boundary = [], Mock()
        def write(handle, operation, data, deadline):
            self.assertEqual(operation, 'write')
            writes.append(data)
            if len(writes) == 2:
                if failure: raise OSError('synthetic write failure')
                if short: return 1
            return len(data)
        with patch.object(P.WinIO, 'pipe_io', side_effect=write):
            context = DeliveryContext(UUID, 'fixture', reply_to=box.address, before_send=boundary)
            yield T.Transport(self.p.transport, lambda: box), endpoint, context, writes, boundary

    def test_transport_auth_then_exactly_one_message_and_native_root(self):
        with self.sending() as (transport, endpoint, context, writes, boundary):
            outcome = transport.deliver(endpoint, 'fixture', context)
        self.assertIs(outcome.delivery, Delivery.WRITTEN)
        self.assertEqual(outcome.native_root, endpoint.ref.data_root)
        self.assertEqual(len(writes), 2)
        self.assertEqual(json.loads(writes[0]), {'type': 'auth', 'token': TOKEN})
        self.assertEqual(json.loads(writes[1])['type'], 'user')
        self.assertNotIn(TOKEN, repr(outcome))
        self.assertNotIn('b'*32, b''.join(writes).decode())
        self.assertEqual(outcome.detail['senderClass'], 'unknown')
        boundary.assert_called_once()

    def test_a_status_change_after_discovery_does_not_block_delivery(self):
        # §96.3：忙闲只用于显示。发现时注册信息是 idle，投递前复核时已变成 busy：端点 runtime 不同，消息照常写出
        self.write('200.json', {**self.record, 'status': 'idle'})
        with self.sending() as (transport, endpoint, context, writes, boundary):
            self.assertEqual(endpoint.runtime.value, 'idle')
            self.write('200.json', {**self.record, 'status': 'busy'})
            outcome = transport.deliver(endpoint, 'fixture', context)
        self.assertIs(outcome.delivery, Delivery.WRITTEN)
        self.assertEqual(len(writes), 2)
        boundary.assert_called_once()

    def test_partial_or_failed_message_is_unknown_and_never_resent(self):
        for options in ({'failure': True}, {'short': True}):
            with self.sending(**options) as (transport, endpoint, context, writes, boundary):
                result = transport.deliver(endpoint, 'fixture', context)
            self.assertIs(result.delivery, Delivery.UNKNOWN)
            self.assertEqual(len(writes), 2)
            boundary.assert_called_once()

    def test_prewrite_identity_and_key_failure_never_cross_boundary(self):
        for change in ('key', 'pid', 'root'):
            with self.sending() as (transport, endpoint, context, writes, boundary):
                if change == 'key': self.write(A.key_name(200, PIPE), {'peerToken': 'invalid'})
                if change == 'pid': self.k.peer = 100
                if change == 'root': endpoint = replace(endpoint, ref=replace(endpoint.ref, data_root='wrong'))
                result = transport.deliver(endpoint, 'fixture', context)
            self.assertIs(result.delivery, Delivery.FAILED)
            self.assertEqual(writes, [])
            boundary.assert_not_called()
            self.write(A.key_name(200, PIPE), {'peerToken': TOKEN})
            self.k.peer = 200

    def test_inbox_unavailable_never_reads_keys_or_sends(self):
        with patch.object(A.PeerFiles, 'token', side_effect=AssertionError('no key')):
            endpoint = Endpoint(EndpointRef(Provider.CLAUDE, UUID, 200, 'win-filetime:'+BIRTH))
            result = T.Transport(self.p.transport).deliver(endpoint, 'fixture', DeliveryContext(UUID, 'fixture'))
        self.assertIs(result.delivery, Delivery.FAILED)

    def test_selector_ambiguity_and_provider_completeness_are_separate(self):
        ep, _ = D.inspect(self.p.transport, 200)
        sampling = commands.WorkerDiscovery(self.p.transport)
        sampling.claude = D.Discovery((ep,), True, 'complete')
        self.assertTrue(sampling.provider_complete(Provider.CLAUDE))
        self.assertFalse(sampling.provider_complete(Provider.CODEX))
        codex = Mock(spec=commands.Discovery,complete=True)
        codex.endpoint.return_value = replace(ep, ref=replace(ep.ref, provider=Provider.CODEX))
        with patch.object(commands, 'evidence', return_value=codex), patch.object(commands, 'claude_evidence', return_value=sampling.claude):
            self.assertEqual(commands.resolve('claude@id:' + UUID), ep)
            with self.assertRaisesRegex(NativeFailure,'target_ambiguous'): commands.resolve(UUID)
            self.assertIs(commands.resolve('codex@id:'+UUID).ref.provider,Provider.CODEX)

    def test_cross_provider_task_roots_remain_separate(self):
        ep, _ = D.inspect(self.p.transport, 200)
        codex = replace(ep.ref, provider=Provider.CODEX, data_root='c'*64)
        evidence = Mock(spec=IdentityEvidence, root_identity='c'*64)
        token = commands._current.set(commands.Command('report', evidence))
        self.addCleanup(commands._current.reset, token)
        task = Mock(origin=codex, reviewer=None)
        commands.check_task(task, [Mock(target=ep.ref)])
        with self.assertRaisesRegex(NativeFailure, 'target_root_changed'):
            commands.check_task(task, [Mock(target=replace(ep.ref, data_root='c'*64))])

    def task(self, store):
        ep, _ = D.inspect(self.p.transport, 200)
        task, attempt = store.create_task(title='fixture', flow=Flow.HANDOFF, origin=None, origin_class=None,
            reviewer=None, target=ep.ref, body='fixture', refs=[], now=1000)
        return ep, task, attempt

    def test_complete_empty_provider_not_masked_by_other_provider_failure(self):
        tick=[1000.]
        with Store.open(self.root/'ledger') as store:
            ep, _, attempt = self.task(store)
            engine = Dispatcher(store, lambda: [], {}, clock=lambda: tick[0],
                empty_discovery_complete=lambda: False, provider_discovery_complete=lambda p: p is Provider.CLAUDE)
            engine.run_once(); tick[0]+=16; engine.run_once()
            self.assertIs(store.get_attempt(attempt.id).delivery, Delivery.FAILED)
            self.assertEqual(store.get_attempt(attempt.id).delivery_reason,'target_gone')

    def test_incomplete_provider_does_not_use_other_provider_as_absence_proof(self):
        tick=[1000.]
        with Store.open(self.root/'ledger') as store:
            ep, _, attempt = self.task(store)
            other = replace(ep, ref=replace(ep.ref, provider=Provider.CODEX))
            engine = Dispatcher(store, lambda: [other], {}, clock=lambda: tick[0], monotonic=lambda: tick[0],
                provider_discovery_complete=lambda p: p is Provider.CODEX)
            engine.run_once(); tick[0]+=DISCOVERY_PARK_SECONDS; engine.run_once()
            self.assertFalse(engine.has_live_work())
            self.assertIs(store.get_attempt(attempt.id).delivery, Delivery.PENDING)
            self.assertTrue(needs_worker(store,tick[0]))

    def test_unavailable_inbox_is_bounded_without_changing_pending_or_cli_restart(self):
        tick=[1000.]
        with Store.open(self.root/'ledger') as store:
            ep, _, attempt = self.task(store)
            engine = Dispatcher(store,lambda:[ep],{},clock=lambda:tick[0],monotonic=lambda:tick[0])
            engine.run_once(); tick[0]+=DISCOVERY_PARK_SECONDS; engine.run_once()
            self.assertFalse(engine.has_live_work())
            self.assertTrue(needs_worker(store,tick[0]))
            self.assertIs(store.get_attempt(attempt.id).delivery, Delivery.PENDING)

    def test_authenticated_transport_and_dispatcher_closed_loop_approve_and_deny(self):
        with Store.open(self.root/'ledger') as store:
            for final, expected in (('delivered', Delivery.DELIVERED), ('denied', Delivery.DENIED)):
                ep, _, attempt = self.task(store)
                box = self.inbox()
                engine = Dispatcher(store, lambda:[ep], {Provider.CLAUDE:T.Transport(self.p.transport,lambda:box)},
                    reply_address=box.address,clock=lambda:1001.)
                with patch('agentstatus_bridge.dispatch.os.getpid',return_value=100), patch.object(P.WinIO,'pipe_io',side_effect=lambda h,op,data,d:len(data)):
                    engine.run_once()
                sent=store.get_attempt(attempt.id)
                self.assertIs(sent.delivery,Delivery.WRITTEN)
                for state in ('held', final):
                    frame=status(message=sent.provider_ref,state=state)
                    self.assertTrue(box._accepted(frame,200,BIRTH))
                    engine.handle_frame(frame)
                self.assertIs(store.get_attempt(attempt.id).delivery,expected)
                self.assertIsNone(store.get_task(attempt.task_id).accepted_at)
                with patch.object(T.Transport,'deliver',side_effect=AssertionError('never resend')):
                    engine.run_once()


class CodecTests(unittest.TestCase):
    def test_concurrent_listener_and_writer_reap_each_buffer_once(self):
        api=Mock()
        def complete(*args):
            time.sleep(.03)  # Let both synthetic callers reach the shared quarantine.
            return 1
        api.k.GetOverlappedResult.side_effect=complete
        overlap=ABI.OVERLAPPED(); overlap.event=123
        pending=IO.Pending(api,456,overlap,b'',ABI.DWORD(),owned=True)
        errors=[]
        start=threading.Barrier(3)
        def run():
            try:
                start.wait(timeout=2)
                IO.reap()
            except BaseException as error: errors.append(type(error).__name__)
        with patch.object(IO,'_quarantine',[pending]):
            threads=[threading.Thread(target=run) for _ in range(2)]
            for thread in threads: thread.start()
            start.wait(timeout=2)
            for thread in threads: thread.join(2)
            self.assertFalse(any(thread.is_alive() for thread in threads))
            self.assertEqual(errors,[])
            self.assertEqual(IO._quarantine,[])
            self.assertEqual(api.k.GetOverlappedResult.call_count,1)
            self.assertEqual([c.args[0] for c in api.close.call_args_list],[123,456])

    def test_fragmented_auth_and_control_preserve_order(self):
        wire = ('{"type":"auth","token":"'+TOKEN+'"}\n'+json.dumps(status())+'\n'+json.dumps(status(state='delivered'))).encode()
        decoder, frames = P.Decoder(TOKEN), []
        for byte in wire: frames += decoder.feed(bytes([byte]))
        frames += decoder.feed(b'', eof=True)
        self.assertEqual(frames, [status(), status(state='delivered')])

    def test_auth_required_and_bounded(self):
        for raw in (json.dumps(status()).encode(), b'[]', b'{', b'{"type":"auth","token":"bad"}'):
            with self.assertRaises(OSError): P.Decoder(TOKEN).feed(raw, eof=True)
        with self.assertRaises(OSError): P.Decoder(TOKEN).feed(b' '* (MAX_INBOX_BUFFER+1))

    def test_local_pipe_validation_rejects_remote_and_nested(self):
        self.assertTrue(local_pipe(PIPE))
        for value in (r'\\server\pipe\x', r'\\.\pipe\x\y', r'\\.\pipe\LOCAL\x\y', r'\\.\pipe\..'):
            self.assertFalse(local_pipe(value))


if __name__ == '__main__': unittest.main()
