"""Caller diagnostics use real attribution with private process/registry fixtures."""
from contextlib import redirect_stdout
import io
import json
import os
import unittest
from unittest.mock import patch

import bridge_support
import test_bridge_windows_claude as claude_fixture
import test_bridge_windows_callers as codex_fixture
from agentstatus_bridge import caller_diagnostic as D, doctor, endpoints
from agentstatus_bridge.caller_values import Caller
from agentstatus_bridge.model import Endpoint, EndpointRef, Provider
from agentstatus_bridge.platforms.factory import make_platform, using_platform
from agentstatus_bridge.platforms.process_values import ProcessInfo
from agentstatus_bridge.platforms.windows import claude_auth

KEYS = {'attributed', 'via', 'rejection', 'termination', 'chainLength', 'nearestAgent'}


class WindowsClaudeTests(unittest.TestCase):
    setUp = claude_fixture.NativeTests.setUp
    write = claude_fixture.NativeTests.write

    def collect(self, env=None):
        with (patch.object(D.os, 'getpid', return_value=100),
              patch.dict(os.environ, {'AB_CLAUDE_SESSIONS_DIR':str(self.sessions), **(env or {})}, clear=True),
              patch.object(claude_auth.PeerFiles, 'token', side_effect=AssertionError('no key read')),
              patch('agentstatus_bridge.store.Store.open', side_effect=AssertionError('no ledger'))):
            result = D.collect()
        self.assertEqual(set(result), KEYS)
        text = json.dumps(result)
        for private in (claude_fixture.UUID, claude_fixture.PIPE, 'fixture-peer', str(self.root)):
            self.assertNotIn(private, text)
        self.assertFalse(any(name == 'WriteFile' for name, _ in self.k.calls))
        return result

    def test_native_claude_positive_without_key_or_ledger(self):
        self.assertEqual(self.collect(), dict(attributed=True, via='windows-claude', rejection=None,
                         termination='root', chainLength=2, nearestAgent='claude'))

    def test_broken_shim_parent_reports_exited_not_nearest_agent(self):
        self.k.processes[200] = (300, int(claude_fixture.BIRTH), self.k.sid, False, 'sh.exe')
        result = self.collect({'CLAUDECODE': '1'})
        self.assertEqual(result, dict(attributed=False, via=None, rejection='platform_unverified',
                         termination='process_exited', chainLength=2, nearestAgent=None))

    def test_visible_claude_with_mismatched_session_rejected(self):
        result = self.collect({'CLAUDE_CODE_SESSION_ID': 'different'})
        self.assertFalse(result['attributed'])
        self.assertEqual(result['nearestAgent'], 'claude')
        self.assertEqual(result['rejection'], 'platform_unverified')

    def test_claude_query_or_registry_failure_is_closed(self):
        for kind in ('registry', 'image', 'elevated', 'foreign'):
            with self.subTest(kind=kind):
                if kind == 'registry': self.write('200.json', {'not': 'valid'})
                if kind == 'image': self.k.images[200] = r'C:\fixture\not-claude.exe'
                if kind == 'elevated':
                    self.k.processes[200] = (0, int(claude_fixture.BIRTH), self.k.sid, True, 'claude.exe')
                if kind == 'foreign':
                    self.k.processes[200] = (0, int(claude_fixture.BIRTH), b'other', False, 'claude.exe')
                self.assertFalse(self.collect()['attributed'])
                self.assertEqual(self.collect()['rejection'], 'platform_unverified')
                self.write('200.json', self.record)
                self.k.images[200] = r'C:\fixture\claude.exe'
                self.k.processes[200] = (0, int(claude_fixture.BIRTH), self.k.sid, False, 'claude.exe')

    def test_cycle_parent_reused_and_empty_chain(self):
        for pid, entry, expected, length in (
            (200, (100, int(claude_fixture.BIRTH), self.k.sid, False, 'sh.exe'), 'cycle', 2),
            (200, (0, int(claude_fixture.BIRTH)+2000, self.k.sid, False, 'sh.exe'), 'parent_reused', 1),
            (100, None, 'process_exited', 0),
        ):
            with self.subTest(expected=expected):
                if entry is None: self.k.processes.pop(pid)
                else: self.k.processes[pid] = entry
                result = self.collect({'CLAUDECODE': '1'})
                self.assertEqual(result['termination'], expected)
                self.assertEqual(result['chainLength'], length)
                self.assertFalse(result['attributed'])

    def test_queryable_identity_denial_and_process_unverified(self):
        self.k.restricted_process_stage = 'queryable'
        self.k.processes[200] = (0, int(claude_fixture.BIRTH), self.k.sid, True, 'claude.exe')
        self.assertEqual(self.collect()['termination'], 'process_identity_unverified')
        with patch.object(self.p.process, 'trace', side_effect=OSError('SECRET path')):
            self.assertEqual(self.collect(), dict(attributed=False, via=None, rejection='platform_unverified',
                             termination='unknown', chainLength=0, nearestAgent=None))

    def test_plain_terminal_is_not_an_attributed_agent(self):
        self.k.processes[200] = (0, int(claude_fixture.BIRTH), self.k.sid, False, 'pwsh.exe')
        with patch('sys.stdin.isatty', return_value=True):
            result = self.collect()
        self.assertFalse(result['attributed'])
        self.assertEqual(result['via'], 'windows-terminal')
        self.assertIsNone(result['rejection'])

    def test_doctor_wires_caller_and_removes_only_stale_fields(self):
        expected = self.collect()
        with (patch.object(doctor, 'caller_diagnostic', return_value=expected),
              patch.object(doctor, 'daemon_diagnostic', return_value={'cliVersion': 'unknown'}),
              patch('agentstatus_bridge.store.Store.open', side_effect=OSError('fixture')),
              patch.object(self.p.files, 'state_dir', return_value=self.root/'state')):
            result = doctor.collect_checks()
        self.assertEqual(result['caller'], expected)
        for key in ('processQualification', 'discovery', 'runtime', 'windowsRealMachineGate', 'registrationAuthority'):
            self.assertNotIn(key, result)
        self.assertNotIn('productAcceptance', result['claudePeer'])
        self.assertEqual(result['claudePeer']['authentication'], 'not_probed')


class WindowsCodexTests(unittest.TestCase):
    setUp = codex_fixture.CallerTests.setUp
    rebuild = codex_fixture.CallerTests.rebuild
    scope = codex_fixture.CallerTests.scope
    sql = codex_fixture.CallerTests.sql
    chain = codex_fixture.CallerTests.chain

    def test_codex_native_success_and_subagent_rejection(self):
        env = self.chain()
        with self.scope(), patch.object(D.os, 'getpid', return_value=100), patch.dict(os.environ, env):
            result = D.collect()
            self.assertTrue(result['attributed'])
            self.assertEqual(result['via'], 'windows-daemon')
            self.assertEqual(result['nearestAgent'], 'codex')
            with patch.dict(os.environ, {'CODEX_SESSION_ID': codex_fixture.uuid(2)}):
                result = D.collect()
            self.assertFalse(result['attributed'])
            self.assertEqual(result['rejection'], 'subagent')
        self.assertFalse(self.state.exists())


class LinuxTests(unittest.TestCase):
    def setUp(self):
        self.enterContext(using_platform(make_platform('linux')))
        self.rows = [ProcessInfo(100, 200, 'python', '2'), ProcessInfo(200, 0, 'claude', '1')]
        self.ep = Endpoint(EndpointRef(Provider.CLAUDE, 'private-id', 200, '1'))
        self.chain = self.enterContext(patch.object(D.procfs, 'ancestry', return_value=self.rows))
        self.found = self.enterContext(patch.object(endpoints, 'discover', return_value=[self.ep]))
        self.enterContext(patch.object(D.os, 'getpid', return_value=100))
        self.enterContext(patch.dict(os.environ, {}, clear=True))

    def test_real_identify_success_and_visible_unattributed(self):
        self.assertEqual(D.collect(), dict(attributed=True, via='ancestry', rejection=None,
                         termination='root', chainLength=2, nearestAgent='claude'))
        self.found.return_value = []
        result = D.collect()
        self.assertFalse(result['attributed'])
        self.assertIsNone(result['rejection'])  # preserve real identify's None, do not invent a cause
        self.assertEqual(result['nearestAgent'], 'claude')

    def test_real_subagent_and_user_shell(self):
        self.chain.return_value = [ProcessInfo(100, 0, 'python', '2')]
        self.found.return_value = []
        with patch.dict(os.environ, {'CODEX_THREAD_ID': 'b'*36, 'CODEX_SESSION_ID': 'a'*36}):
            self.assertEqual(D.collect()['rejection'], 'subagent')
        result = D.collect()
        self.assertFalse(result['attributed'])
        self.assertIsNone(result['nearestAgent'])

    def test_missing_cycle_and_limit_are_not_invented_root(self):
        for rows, reason in (([], 'legacy_missing_or_unreadable'),
                             ([ProcessInfo(100, 100, 'python', '2')], 'cycle'),
                             ([ProcessInfo(i, i+1, 'python', '2') for i in range(100,164)], 'limit')):
            with self.subTest(reason=reason):
                self.chain.return_value = rows
                self.assertEqual(D.collect()['termination'], reason)
                self.assertEqual(D.collect()['chainLength'], len(rows))

    def test_unknown_values_and_errors_never_leak(self):
        with patch.object(endpoints, 'identify_caller', return_value=Caller(None, None, 'SECRET', rejection='SECRET')):
            value = D.collect()
            self.assertEqual(value['via'], 'unknown')
            self.assertEqual(value['rejection'], 'unknown')
            self.assertNotIn('SECRET', json.dumps(value))
        with patch.object(endpoints, 'discover', side_effect=OSError('SECRET')):
            self.assertEqual(D.collect()['rejection'], 'platform_unverified')

    def test_text_and_json_projection_have_same_facts_without_identity(self):
        value = D.collect()
        out = io.StringIO()
        with redirect_stdout(out): doctor.print_checks({'caller': value})
        for fragment in ('agent 已归属=是', 'via=ancestry', 'rejection=None', 'termination=root', '长度=2', '最近 agent=claude'):
            self.assertIn(fragment, out.getvalue())
        self.assertNotIn('private-id', out.getvalue())
        self.assertEqual(set(value), KEYS)


if __name__ == '__main__':
    unittest.main()
