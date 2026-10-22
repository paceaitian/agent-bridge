"""Second W3 review counterexamples, using only private native SDK fixtures."""
from contextlib import redirect_stderr
from dataclasses import replace
import io
import os
import time
import unittest
from unittest.mock import Mock, patch

import test_bridge_windows_claude as F
import test_bridge_windows_claude_cli as CF
import test_bridge_windows_delivery as WF
from bridge_platform_guard import windows_fixture
from agentstatus_bridge import cli
from agentstatus_bridge.dispatch import Dispatcher
from agentstatus_bridge.labels import reason_text
from agentstatus_bridge.model import Delivery, Flow, Provider
from agentstatus_bridge.platforms.types import Presence
from agentstatus_bridge.platforms.windows import claude_discovery as D, commands, codex_discovery as C
from agentstatus_bridge.platforms.windows.api import WinFailure
from agentstatus_bridge.platforms.windows.io import WinIO
from agentstatus_bridge.store import Store
from agentstatus_bridge.transports import DeliveryOutcome
from agentstatus_bridge.transports.codex_native import NativeFailure

OTHER = '019b0000-0000-7000-8000-000000000003'
FOREIGN = bytes.fromhex('010100000000000512000000')


class DiscoveryTests(unittest.TestCase):
    setUp = F.NativeTests.setUp
    write = F.NativeTests.write
    task = F.NativeTests.task

    def stale(self, stage='process', elevated=False):
        self.k.restricted_process_stage = stage
        self.k.processes[300] = (0, int(F.BIRTH) + 777, self.k.sid if elevated else FOREIGN, elevated, 'svchost.exe')
        self.write('300.json', {**self.record, 'pid': 300, 'sessionId': OTHER, 'procStartFt': '1'})

    def test_denied_stale_pid_keeps_complete_name_and_codex_alias_selection(self):
        codex = WF.NamingTests().result()
        for stage in ('process', 'token', 'queryable'):
            for elevated in (False, True):
                with self.subTest(stage=stage, elevated=elevated):
                    self.stale(stage, elevated)
                    result = D.discover(self.p.transport)
                    self.assertTrue(result.complete)
                    self.assertEqual(result.select('fixture-peer').ref.pid, 200)
                    with patch.object(commands, 'evidence', return_value=codex), patch.object(commands, 'claude_evidence', return_value=result):
                        self.assertIs(commands.resolve('原生甲').ref.provider, Provider.CODEX)
        self.assertEqual(self.k.handles, {})

    def test_fake_process_and_token_access_denial_are_not_only_sid_projection(self):
        for stage in ('process', 'token'):
            for elevated in (False, True):
                self.stale(stage, elevated)
                with self.assertRaises(OSError) as caught: self.k.api.process(300)
                self.assertEqual(caught.exception.winerror, 5)
                self.assertEqual(self.k.handles, {})
        self.stale('queryable')
        self.assertEqual(self.k.api.process(300).token.sid, FOREIGN)

    def test_denied_stale_pid_does_not_hold_an_exited_target_pending(self):
        self.stale()
        tick = [1000.]
        with Store.open(self.root / 'ledger') as store:
            _, _, attempt = self.task(store)
            self.k.processes.pop(200)
            sampler = commands.WorkerDiscovery(self.p.transport)
            with patch.object(commands, 'discover', return_value=C.Discovery()):
                engine = Dispatcher(store, sampler, {}, clock=lambda: tick[0],
                                    provider_discovery_complete=sampler.provider_complete)
                engine.run_once(); tick[0] += 16; engine.run_once()
            current = store.get_attempt(attempt.id)
            self.assertEqual((current.delivery, current.delivery_reason), (Delivery.FAILED, 'target_gone'))

    def test_unknown_registry_read_rechecks_ineligible_pid_but_not_unknown_query(self):
        self.stale()
        original = D.inspect
        def inspect(backend, pid, **kwargs):
            if pid == 300: raise OSError('fixture_registry_read_race')
            return original(backend, pid, **kwargs)
        with patch.object(D, 'inspect', side_effect=inspect):
            self.assertTrue(D.discover(self.p.transport).complete)
            self.k.processes[300] = (0, int(F.BIRTH) + 1, self.k.sid, False, 'claude.exe')
            self.assertFalse(D.discover(self.p.transport).complete)
        # OS file-read denial (not a product ACL gate) is not a process access denial.
        with patch.object(D.PeerFiles, 'read', side_effect=WinFailure(5)):
            self.assertFalse(D.discover(self.p.transport).complete)

    def test_worker_sampling_does_not_connect_a_temporarily_busy_pipe(self):
        with Store.open(self.root / 'ledger') as store:
            _, _, attempt = self.task(store)
            sampler = commands.WorkerDiscovery(self.p.transport)
            transport = Mock(ready=Mock(return_value=True), deliver=Mock(return_value=DeliveryOutcome(Delivery.WRITTEN, 'fixture')))
            with (patch.object(commands, 'discover', return_value=C.Discovery()),
                  patch('os.getpid', return_value=100),
                  patch.object(D.WinIO, 'open_pipe', side_effect=WinFailure(231)) as pipe):
                engine = Dispatcher(store, sampler, {Provider.CLAUDE: transport}, reply_address='fixture',
                                    provider_discovery_complete=sampler.provider_complete)
                engine.run_once()
            pipe.assert_not_called()
            transport.deliver.assert_called_once()
            self.assertIs(store.get_attempt(attempt.id).delivery, Delivery.WRITTEN)

    def test_live_unsupported_peer_keeps_specific_blocking_reason(self):
        for i, (update, reason) in enumerate((({'peerProtocol': 2}, 'peer_protocol_unsupported'),
                                              ({'messagingSocketPath': None}, 'socket_unavailable'))):
            self.write('200.json', self.record)
            with Store.open(self.root / ('ledger-' + str(i))) as store:
                _, _, attempt = self.task(store)
                self.write('200.json', {**self.record, **update})
                result = D.discover(self.p.transport, connect=False)
                self.assertTrue(result.complete)
                self.assertEqual(len(result.endpoints), 1)
                self.assertEqual(result.endpoints[0].issues, (reason,))
                with self.assertRaisesRegex(NativeFailure, 'target_' + reason): result.select(F.UUID)
                with self.assertRaises(OSError): D.inspect(self.p.transport, 200)
                sampler = commands.WorkerDiscovery(self.p.transport)
                with patch.object(commands, 'discover', return_value=C.Discovery()):
                    engine = Dispatcher(store, sampler, {}, provider_discovery_complete=sampler.provider_complete)
                    engine.run_once()
                current = store.get_attempt(attempt.id)
                self.assertEqual((current.delivery, current.delivery_reason), (Delivery.FAILED, 'target_' + reason))

    def test_full_uuid_can_cross_unknown_provider_but_names_cannot(self):
        claude = D.discover(self.p.transport)
        codex = WF.NamingTests().result()
        for left, right, target, provider, name in (
                (C.Discovery(), claude, F.UUID, Provider.CLAUDE, 'fixture-peer'),
                (codex, D.Discovery(), codex.rows[0].thread, Provider.CODEX, '原生甲')):
            with patch.object(commands, 'evidence', return_value=left), patch.object(commands, 'claude_evidence', return_value=right):
                for selector in (target, 'id:' + target):
                    selected = None
                    try: selected = commands.resolve(selector)
                    except NativeFailure as error: self.fail(error.reason)
                    self.assertIs(selected.ref.provider, provider)
                for selector in (name, OTHER):
                    with self.assertRaisesRegex(NativeFailure, 'discovery_incomplete'):
                        commands.resolve(selector)
                with self.assertRaises(NativeFailure): commands.resolve(target[:8])
        # Known collision is still ambiguous, and a blocked exact hit cannot borrow another provider.
        collision = replace(codex, rows=(replace(codex.rows[0], thread=F.UUID),))
        with patch.object(commands, 'evidence', return_value=collision), patch.object(commands, 'claude_evidence', return_value=claude):
            with self.assertRaisesRegex(NativeFailure, 'target_ambiguous'): commands.resolve(F.UUID)
        blocked = replace(claude, endpoints=(replace(claude.endpoints[0], issues=('peer_protocol_unsupported',)),))
        with patch.object(commands, 'evidence', return_value=C.Discovery()), patch.object(commands, 'claude_evidence', return_value=blocked):
            with self.assertRaisesRegex(NativeFailure, 'target_peer_protocol_unsupported'): commands.resolve(F.UUID)

    def test_missing_codex_home_is_complete_empty_without_starting_provider(self):
        absent = self.root / 'absent-codex'
        with (patch.object(self.p.files, 'codex_home', return_value=absent),
              patch.object(self.p.transport, 'codex_cli_version', side_effect=AssertionError('provider touched'))):
            missing = C.discover(self.p.transport)
            self.assertTrue(missing.complete)
            self.assertEqual(missing.rows, ())
            path_type = type(absent)
            with patch.object(path_type, 'lstat', side_effect=PermissionError('fixture')):
                self.assertFalse(C.discover(self.p.transport).complete)
        claude = D.discover(self.p.transport)
        with patch.object(commands, 'evidence', return_value=missing), patch.object(commands, 'claude_evidence', return_value=claude):
            self.assertIs(commands.resolve('fixture-peer').ref.provider, Provider.CLAUDE)

    def test_rejection_text_has_both_provider_prefixes_and_no_tmux_requirement(self):
        for reason in ('reporter_unattributed', 'caller_unattributed'):
            self.assertNotIn('tmux', reason_text(reason))
        # Go through the actual Windows CLI error path, without caller or provider I/O.
        for reason in ('discovery_incomplete', 'claude_discovery_incomplete', 'target_names_unverified', 'alias_target_unavailable'):
            out = io.StringIO()
            with patch.object(commands, 'scope', side_effect=NativeFailure(reason)), redirect_stderr(out):
                expected = cli.EXIT_TARGET if reason.startswith(('target_', 'alias_')) else cli.EXIT_REJECTED
                self.assertEqual(cli.main(['send', '--to', 'fixture', '-m', 'fixture']), expected)
            self.assertIn('claude@', out.getvalue())
            self.assertIn('codex@', out.getvalue())


class ResumeTests(unittest.TestCase):
    setUp = F.NativeTests.setUp
    write = F.NativeTests.write
    command = CF.CliTests.command

    def test_resumed_cli_report_with_original_pid_reused_by_other_identity(self):
        received, _ = D.inspect(self.p.transport, 200)
        pipe = r'\\.\pipe\LOCAL\cc-msg-' + '3' * 32
        self.k.processes[300] = (0, int(F.BIRTH) + 500, self.k.sid, False, 'claude.exe')
        self.k.images[300] = r'C:\fixture\claude.exe'
        self.write('300.json', {**self.record, 'pid': 300, 'messagingSocketPath': pipe, 'procStartFt': str(int(F.BIRTH) + 500)})
        row = self.k.processes[100]; self.k.processes[100] = (300, *row[1:])
        def peer(handle, **kw): return 300 if self.k.record(handle)['path'] == pipe else 200
        with (windows_fixture('pipe', pipe), patch.object(WinIO, 'peer_pid', side_effect=peer), patch('os.getpid', return_value=100),
              patch.object(cli, '_start_worker', return_value=False), patch.object(cli, '_worker_up', return_value=False),
              patch.object(cli, '_ensure_worker', return_value=False)):
            for index, (stage, sid, elevated) in enumerate((stage, sid, elevated)
                    for stage in ('process', 'token', 'queryable')
                    for sid, elevated in ((FOREIGN, False), (self.k.sid, True), (self.k.sid, False))):
                with self.subTest(stage=stage, foreign=sid != self.k.sid, elevated=elevated):
                    state = self.root / ('resume-' + str(index))
                    self.k.restricted_process_stage = stage
                    self.k.processes[200] = (0, int(F.BIRTH) + 1, sid, elevated, 'reused.exe')
                    with patch.dict(os.environ, {'AB_STATE_DIR': str(state)}):
                        with Store.open(state) as store:
                            stamp = time.time()
                            task, attempt = store.create_task(title='fixture', flow=Flow.HANDOFF, origin=None, origin_class=None,
                                reviewer=None, target=received.ref, body='fixture', refs=[], now=stamp)
                            store.begin_send(attempt.id, now=stamp, pid=100, start_ticks='win-filetime:' + str(int(F.BIRTH) + 1000))
                            store.finish_send(attempt.id, delivery=Delivery.DELIVERED, reason='fixture', provider_ref=None,
                                detail={'deliveredPid': 200, 'deliveredStart': received.ref.start_ticks}, now=stamp, native_root=received.ref.data_root)
                        code, out, err = self.command('report', task.id, '--result', '--note', 'fixture', '--json')
                        self.assertEqual(code, 0, (out, err))
                        with Store.open(state) as store:
                            self.assertEqual(store.get_attempt(attempt.id).work.value, 'result_submitted')

    def test_prior_peer_proof_keeps_unknown_errors_and_requires_generation(self):
        birth = 'win-filetime:' + F.BIRTH
        self.assertIs(commands.receiver_presence(200, birth), Presence.CURRENT)
        for invalid in ('', F.BIRTH, 'win-filetime:0', 'win-filetime:-1', 'win-filetime:x'):
            self.assertIs(commands.receiver_presence(200, invalid), Presence.UNKNOWN)
        for stage in ('process', 'token', 'queryable'):
            self.k.restricted_process_stage = stage
            for sid, elevated in ((FOREIGN, False), (self.k.sid, True)):
                # Also proves the explicit identity criterion, not just birth mismatch.
                self.k.processes[200] = (0, int(F.BIRTH), sid, elevated, 'reused.exe')
                self.assertIs(commands.receiver_presence(200, birth), Presence.EXITED)
        self.k.processes[200] = (0, int(F.BIRTH), self.k.sid, False, 'claude.exe')
        for call in ('GetProcessTimes', 'OpenProcessToken'):
            self.k.faults[call] = 6
            self.assertIs(commands.receiver_presence(200, birth), Presence.UNKNOWN)
            self.k.faults.clear()
        with patch.object(self.k, 'WaitForSingleObject', return_value=0xffffffff):
            self.assertIs(commands.receiver_presence(200, birth), Presence.UNKNOWN)
        with patch.object(self.k.api, 'current_token', side_effect=WinFailure(5)):
            self.assertIs(commands.receiver_presence(200, birth), Presence.UNKNOWN)
        self.assertEqual(self.k.handles, {})


if __name__ == '__main__':
    unittest.main()
