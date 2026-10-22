"""W2-1: real codecs over SDK-marshalled fake Winsock, never a real daemon."""
import base64
import ctypes as C
from contextlib import redirect_stdout, redirect_stderr
from dataclasses import replace
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
from tempfile import TemporaryDirectory
import time
import unittest
from unittest.mock import patch

import bridge_support
from bridge_short_socket import short_root
from bridge_platform_guard import ProductionSocketUse, windows_fixture
from bridge_winapi import Kernel
import bridge_winapi_sdk as S
from agentstatus_bridge import cli, doctor, worker
from agentstatus_bridge.model import Delivery
from agentstatus_bridge.platforms.factory import make_platform, using_platform
from agentstatus_bridge.platforms.windows import abi as A, codex_version, local_transport, logon
from agentstatus_bridge.transports import codex_native, codex_rpc, codex_withdraw


class DaemonKernel(Kernel):
    """Only synthetic bytes; independent WS server oracle, no production codec."""
    def __init__(self, root, home):
        super().__init__(root)
        self.home = home
        self.socket_in.clear()
        self.pending_ws = bytearray()
        self.http = None
        self.messages, self.opcodes = [], []
        self.reply = None
        self.server_home = str(home)
        self.server_version = '0.162.1'

    def frame(self, message):
        raw = json.dumps(message).encode('utf-8')
        return (bytes([0x81, len(raw)]) if len(raw) < 126
                else b'\x81\x7e' + len(raw).to_bytes(2, 'big')) + raw

    def send(self, handle, buf, size, flags):
        count = super().send(handle, buf, size, flags)
        self.pending_ws.extend(C.string_at(buf, count))
        if self.http is None:
            if b'\r\n\r\n' not in self.pending_ws:
                return count
            self.http, rest = self.pending_ws.split(b'\r\n\r\n', 1)
            self.pending_ws = bytearray(rest)
            key = next(line.split(b': ', 1)[1] for line in self.http.split(b'\r\n')
                       if line.startswith(b'Sec-WebSocket-Key: '))
            accept = base64.b64encode(hashlib.sha1(key + b'258EAFA5-E914-47DA-95CA-C5AB0DC85B11').digest())
            self.socket_in.extend(b'HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n'
                                  b'Connection: Upgrade\r\nSec-WebSocket-Accept: ' + accept + b'\r\n\r\n')
        while len(self.pending_ws) >= 2:
            first, second = self.pending_ws[:2]
            assert second & 0x80, 'client must mask'
            length, cursor = second & 127, 2
            if length == 126:
                if len(self.pending_ws) < 4: break
                length, cursor = int.from_bytes(self.pending_ws[2:4], 'big'), 4
            if length == 127:
                if len(self.pending_ws) < 10: break
                length, cursor = int.from_bytes(self.pending_ws[2:10], 'big'), 10
            end = cursor + 4 + length
            if len(self.pending_ws) < end: break
            mask = self.pending_ws[cursor:cursor+4]
            raw = bytes(c ^ mask[i % 4] for i, c in enumerate(self.pending_ws[cursor+4:end]))
            del self.pending_ws[:end]
            self.opcodes.append(first & 15)
            if first & 15 != 1: continue
            message = json.loads(raw)
            self.messages.append(message)
            if message.get('method') == 'initialize':
                response = self.reply if self.reply is not None else {
                    'id': 1, 'result': {'userAgent': 'codex-tui/' + self.server_version,
                                       'codexHome': self.server_home}}
                self.socket_in.extend(self.frame(response))
        return count


class WindowsCodexTests(unittest.TestCase):
    def setUp(self):
        bridge_support.bridge_short_socket_guard.isolate(self)
        S.assert_file_layout(self, A.FILE_INFORMATION)
        self.tmp = short_root()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.home = self.root / 'h'
        self.control = self.home / 'app-server-control'
        self.control.mkdir(parents=True)
        self.socket = self.control / 'app-server-control.sock'
        self.socket.touch()
        self.rebuild()
        self.addCleanup(lambda: self.assertEqual(self.k.handles, {}))
        self.addCleanup(lambda: self.assertEqual(self.k.ws_count, 0))
        self.addCleanup(lambda: self.assertEqual(self.k.lsa_allocations, set()))

    def rebuild(self):
        self.k = DaemonKernel(self.root, self.home)
        self.k.files[str(self.home)] = {'private': False, 'protected': False}
        self.k.files[str(self.socket)] = {'reparse': True, 'tag': 0x80000023}
        self.k.processes[200] = (0, 134362090000012230, self.k.sid, False, 'codex.exe')
        self.k.peer = 200
        self.p = make_platform('windows', win_api=self.k.api)

    def diagnose(self, version='0.162.1'):
        with (using_platform(self.p), patch.dict(os.environ, {'CODEX_HOME': str(self.home)}),
              patch.object(codex_version, 'read_cli_version', return_value=version),
              windows_fixture('unix', str(self.socket))):
            return codex_native.daemon_diagnostic(self.p.files.codex_home)

    def assert_rejected(self, result, *, zero=True, connect=None):
        self.assertFalse(result['reachable'])
        if zero: self.assertEqual(self.k.socket_out, b'')
        if connect is not None:
            self.assertEqual(any(n == 'connect' for n, _ in self.k.calls), connect)
        self.assertEqual(self.k.handles, {})
        self.assertEqual(self.k.ws_count, 0)

    def test_success_real_codec_identity_rpc_path_and_read_only_frames(self):
        self.k.short_write = 7
        result = self.diagnose()
        self.assertTrue(result['reachable'], result)
        self.assertTrue(result['peerVerified'])
        self.assertEqual(result['cliVersion'], '0.162.1')
        self.assertEqual(result['serverVersion'], '0.162.1')
        self.assertEqual(bytes(self.k.http).split(b'\r\n')[0], b'GET /rpc HTTP/1.1')
        self.assertEqual(self.k.messages, [
            {'id': 1, 'method': 'initialize', 'params': {
                'clientInfo': {'name': 'codex-tui', 'title': None, 'version': '0.162.1'},
                'capabilities': {'experimentalApi': True}}}, {'method': 'initialized'}])
        self.assertEqual(self.k.opcodes, [1, 1, 8])
        self.assertNotIn(b'/daemon/shutdown', self.k.socket_out)
        self.assertFalse(result['providerWrites'])
        self.assertEqual(result['rendezvous'], 'af_unix_control')
        self.assertEqual(result['logonType'], 'INTERACTIVE')
        self.assertIn('inferred', result['logoutRisk'])

    def test_fake_socket_root_is_short_even_with_long_tmpdir(self):
        import bridge_short_socket
        long=self.root/('long-fixture-'*8);long.mkdir()
        with (patch.object(bridge_short_socket,'gettempdir',return_value=str(long)),
              patch.object(bridge_short_socket,'_scavenge',wraps=bridge_short_socket._scavenge) as clean):
            with short_root() as root:
                address=Path(root)/'h/app-server-control/app-server-control.sock'
                self.assertLess(len(str(address).encode('utf-8')),108)
                self.assertTrue(Path(root).is_dir())
                self.assertTrue((Path(root)/bridge_short_socket.MARKER).is_file())
                clean.assert_called_once_with(Path(root).parent)
            self.assertFalse(Path(root).exists())

    def test_fixture_prefers_tmpdir_and_cleans_owned_stale_fallback_only(self):
        import bridge_short_socket as S
        base=self.root/'s';base.mkdir(mode=0o700)
        preferred=self.root.parent  # fits by construction, even under deep TMPDIR
        with patch.object(S,'gettempdir',return_value=str(preferred)),patch.object(S,'_fallback_bases') as fallback:
            error=None;root=None
            try:
                with short_root() as root:
                    self.assertEqual(Path(root).parent,preferred)
                    self.assertFalse((Path(root)/S.MARKER).exists())
            except OSError as failure:error=failure
            self.assertIsNone(error)
            self.assertFalse(Path(root).exists())
            fallback.assert_not_called()
        roots=[]
        for i in range(1,7):
            path=base/('w2-'+str(i).zfill(8));path.mkdir(mode=0o700)
            marker=path/S.MARKER;marker.write_text(json.dumps({'pid':i}),encoding='ascii')
            marker.chmod(0o600)
            os.utime(marker,(time.time()-S.MAX_AGE-10,)*2)
            roots.append(path)
        # old/dead/owned, foreign owner, recent, live process, unmarked, link tree
        os.utime(roots[2]/S.MARKER,None)
        (roots[4]/S.MARKER).unlink()
        other=base/'keep';other.mkdir();(other/'safe').touch()
        link=roots[5]/'link';link.touch()
        link_inode=link.stat().st_ino
        plain=S._plain
        from types import SimpleNamespace
        import stat
        self.assertFalse(plain(SimpleNamespace(st_mode=stat.S_IFDIR,st_file_attributes=0x400)))
        self.assertFalse(plain(SimpleNamespace(st_mode=stat.S_IFLNK,st_file_attributes=0)))
        with (patch.object(S,'_alive',side_effect=lambda pid:pid==4),
              patch.object(S,'_plain',side_effect=lambda status:status.st_ino!=link_inode and plain(status)),
              patch.object(S,'_owner_matches',side_effect=lambda p,s:p!=roots[1])):
            S._scavenge(base)
            self.assertFalse(roots[0].exists())
            self.assertTrue(all(p.exists() for p in roots[1:]))
            self.assertTrue((other/'safe').exists())

    def test_real_fixture_pid_and_owner_checks(self):
        import bridge_short_socket as S
        import sys
        self.assertTrue(S._alive(os.getpid()))
        child = subprocess.Popen([sys.executable, '-c', 'pass'])
        child.wait(timeout=10)
        self.assertFalse(S._alive(child.pid))
        if os.name != 'nt':
            owned = self.root/'owner';owned.mkdir(mode=0o700)
            self.assertTrue(S._owner_matches(owned, owned.stat()))
            owned.chmod(0o777)
            self.assertFalse(S._owner_matches(owned, owned.stat()))

    def test_scavenge_guard_rejects_shared_bases_before_enumeration(self):
        import bridge_short_socket as S
        bases = [Path('/var/tmp')]
        if os.environ.get('LOCALAPPDATA'):
            bases.append(Path(os.environ['LOCALAPPDATA']))
        for base in bases:
            with patch.object(Path, 'iterdir', side_effect=AssertionError('enumerated_shared_base')) as scan:
                with self.assertRaisesRegex(AssertionError, 'test_scavenge_shared_directory'):
                    S._scavenge(base)
                scan.assert_not_called()

    def test_socket_suffix_budget_covers_second_home(self):
        import bridge_short_socket as S
        suffix = 'other-home/app-server-control/app-server-control.sock'
        self.assertTrue(S._fits('/'+'a'*42))
        self.assertFalse(S._fits('/'+'a'*42, suffix))
        long = self.root/('long-'*20);long.mkdir()
        with (patch.object(S, 'gettempdir', return_value=str(long)),
              patch.object(S, '_fits', wraps=S._fits) as fits):
            with S.short_root(suffix) as root:
                self.assertLess(len(str(Path(root)/suffix).encode('utf-8')), 108)
            self.assertEqual(fits.call_args_list[0].args,(long,suffix))

    def test_explicit_target_has_chinese_label(self):
        self.assertEqual(cli.reason_text('target_explicit_required'),
                         '请明确指定非空的目标或复核方；不会自动选择会话')

    def test_alias_set_empty_name_or_target_never_creates_local_state(self):
        # Parser accepts strings; the alias command, not an argparse accident,
        # is responsible for rejecting empty name / target spelling.
        from agentstatus_bridge.platforms.windows.alias_command import run, AliasError
        from types import SimpleNamespace
        for name,target,reason in (('', '12345678','alias_name_invalid'),
                                   (' ', '12345678','alias_name_invalid'),
                                   ('work','','alias_uuid_required'),
                                   ('work',' ','alias_uuid_required')):
            with (using_platform(self.p),patch.dict(os.environ,{'CODEX_HOME':str(self.home),'AB_STATE_DIR':str(self.root/'s')}),
                  patch('agentstatus_bridge.platforms.windows.alias_command.discover')):
                with self.assertRaises(AliasError) as caught:
                    run(SimpleNamespace(alias_action='set',name=name,target=target,json=False))
                self.assertEqual(caught.exception.code,reason)
                self.assertFalse((self.root/'s/target-aliases/codex.json').exists())

    def test_versions_are_observations_and_unknown_still_connects(self):
        for value in (None, '', '0.160.0', '0.162.2', '0.162.1-foo'):
            with self.subTest(value=value):
                self.rebuild()
                result = self.diagnose(value)
                self.assertTrue(result['reachable'], result)
                self.assertNotIn('versionQualified', result)
                self.assertEqual(result['cliVersion'], value or 'unknown')
                self.assertEqual(self.k.messages[0]['params']['clientInfo']['version'], value or 'unknown')
        for version in ('0.163.0', 'unparseable'):
            with self.subTest(server=version):
                self.rebuild()
                self.k.server_version = version
                result = self.diagnose('0.163.0')
                self.assertTrue(result['reachable'], result)
                self.assertEqual(result['serverVersion'], version if version == '0.163.0' else 'unknown')
                self.assertEqual(result['cliVersion'], '0.163.0')
                text = io.StringIO()
                with redirect_stdout(text): doctor.print_checks({'codexDaemon': result})
                self.assertIn('版本仅观察', text.getvalue())
                self.assertNotIn('codex-tui/', text.getvalue())
        with self.p.transport.codex_read_scope('0.162.2'):
            self.assertTrue(self.p.transport._read.get())
        self.assertFalse(self.p.transport._read.get())

    def test_cli_version_exact_command_and_explicit_utf8(self):
        executable = self.root / 'fixture-codex'
        executable.touch()
        with patch.object(codex_version.shutil, 'which', return_value=str(executable)):
            for text, code, expected in [('codex-cli 0.162.1\r\n', 0, '0.162.1'),
                                         ('codex-cli 0.162.1', 0, '0.162.1'),
                                         ('codex-cli 0.162.2\n', 0, '0.162.2'),
                                         ('prefix codex-cli 0.162.1\n', 0, None),
                                         ('codex-cli 0.162.1\nextra', 0, None),
                                         ('codex-cli 0.162.1\n', 1, None)]:
                with patch.object(codex_version.subprocess, 'run', return_value=subprocess.CompletedProcess([], code, text)) as run:
                    codex_version._cache.clear()
                    self.assertEqual(codex_version.read_cli_version(), expected)
                    self.assertEqual(run.call_args.args[0], [str(executable.resolve()), '--version'])
                    self.assertEqual(run.call_args.kwargs['encoding'], 'utf-8')
                    self.assertEqual(run.call_args.kwargs['errors'], 'strict')
                    self.assertIs(run.call_args.kwargs['shell'], False)
                    self.assertEqual(run.call_args.kwargs['timeout'], 3.0)
            for error in (OSError('private text'), subprocess.TimeoutExpired('fixture', 3),
                          UnicodeDecodeError('utf-8', b'\xff', 0, 1, 'fixture')):
                with patch.object(codex_version.subprocess, 'run', side_effect=error):
                    codex_version._cache.clear()
                    self.assertIsNone(codex_version.read_cli_version())
        with patch.object(codex_version.shutil, 'which', return_value=None), patch.object(codex_version.subprocess, 'run') as run:
            self.assertIsNone(codex_version.read_cli_version())
            run.assert_not_called()

    def test_peer_failure_matrix_zero_bytes(self):
        cases = ('pid_zero', 'pid_missing', 'pid_wrong', 'pid_query', 'peer_sid', 'peer_elevated',
                 'self_elevated', 'query_denied', 'unknown_identity', 'pid_reused', 'peer_changes')
        for case, stage in ((case, stage) for case in cases for stage in ('process', 'token', 'queryable')):
            with self.subTest(case=case, stage=stage):
                self.rebuild()
                self.k.restricted_process_stage = stage
                if case == 'pid_zero': self.k.peer = 0
                if case == 'pid_missing': self.k.peer = 404
                if case == 'pid_wrong': self.k.peer_bytes = 8
                if case == 'pid_query': self.k.faults['WSAIoctl'] = 5
                if case == 'peer_sid': self.k.processes[200] = (0, 123, b'\x01\x01' + b'\x00'*10, False, 'codex.exe')
                if case == 'peer_elevated': self.k.processes[200] = (0, 123, self.k.sid, True, 'codex.exe')
                if case == 'self_elevated': self.k.processes[100] = (0, 123, self.k.sid, True, 'python.exe')
                if case == 'query_denied': self.k.faults['OpenProcess'] = 5
                if case == 'unknown_identity': self.k.processes[200] = (0, 0, self.k.sid, False, 'codex.exe')
                if case == 'peer_changes':
                    # Two distinct PIDs may share a creation timestamp; FILETIME
                    # mismatch must not accidentally stand in for PID equality.
                    self.k.processes[100] = (0, self.k.processes[200][1], self.k.sid, False, 'python.exe')
                original = self.k.api.process
                def process(pid, **kwargs):
                    value = original(pid, **kwargs)
                    if case == 'pid_reused' and not kwargs:
                        self.k.processes[200] = (0, value.birth+1, self.k.sid, False, 'codex.exe')
                    if case == 'peer_changes' and not kwargs: self.k.peer = 100
                    return value
                with patch.object(self.k.api, 'process', side_effect=process):
                    result = self.diagnose()
                    self.assert_rejected(result)
                    if case == 'self_elevated': self.assertEqual(result['cliVersion'], 'unknown')

    def test_path_and_exact_tag_before_connect(self):
        for path, metadata in [(self.home, {'reparse': True}), (self.control, {'reparse': True}),
                               (self.socket, {'reparse': True, 'tag': 0xA000000C}),
                               (self.socket, {'reparse': False, 'tag': 0}),
                               (self.home, {'fs': 'FAT32'})]:
            with self.subTest(path=path.name, metadata=metadata):
                self.rebuild()
                self.k.files[str(path)] = metadata
                self.assert_rejected(self.diagnose(), connect=False)

    def test_external_acl_owner_and_socket_link_policy_does_not_authorize_peer(self):
        for path, metadata in [(self.control, {'protected': False}), (self.control, {'private': False}),
                               (self.control, {'owner': bytes.fromhex('01020000000000052000000020020000'),
                                               'aces': [(0, 0x10, 0x1f01ff, b'\x01\x01'+b'\0'*10)]}),
                               (self.socket, {'private': False}),
                               (self.socket, {'owner': b'\x01\x01'+b'\0'*10})]:
            with self.subTest(path=path.name, metadata=metadata):
                self.rebuild()
                self.k.files.setdefault(str(path), {}).update(metadata)
                result = self.diagnose()
                self.assertTrue(result['reachable'], result)
                self.assertTrue(result['peerVerified'])
                self.assertFalse(any(n == 'SetSecurityInfo' for n, _ in self.k.calls))
        self.rebuild()
        alias = self.home / 'socket-link'
        os.link(self.socket, alias)
        result = self.diagnose()
        self.assertTrue(result['reachable'], result)
        self.assertEqual(self.socket.stat().st_nlink, 2)

    def test_root_locations_external_lease_and_file_identity(self):
        files = self.p.files
        with patch.dict(os.environ, {}, clear=True), patch.object(Path, 'home', return_value=self.root):
            self.assertEqual(files.codex_home(), self.root / '.codex')
            self.assertIsNone(files.codex_sqlite_home())
        with patch.dict(os.environ, {'CODEX_HOME': str(self.home), 'CODEX_SQLITE_HOME': str(self.control)}):
            self.assertEqual(files.codex_home(), self.home)
            self.assertEqual(files.codex_sqlite_home(), self.control)
        with patch.dict(os.environ, {'CODEX_HOME': '//host/share'}), self.assertRaises(OSError):
            files.codex_home()
        identity = files.root_identity(self.home)
        self.assertIsInstance(identity, str)
        self.assertNotEqual(identity, files.root_identity(self.home, self.control))
        self.assertTrue(files.home_equal(str(self.home), self.home))
        self.assertFalse(files.home_equal(str(self.control), self.home))
        with files.lease(self.home, external=True):
            self.assertTrue(any(h.get('path') == str(self.home) for h in self.k.handles.values()))
            self.assertTrue(all(h.get('sharing', 7) & 4 for h in self.k.handles.values()))
        self.assertTrue(self.diagnose()['reachable'])

    def test_root_and_socket_epoch_changes_zero_bytes_before_handshake(self):
        for method in ('socket_identity', 'root_identity'):
            self.rebuild()
            original = getattr(self.p.files, method)
            def identity(*args, **kwargs):
                answer = original(*args, **kwargs)
                if self.k.peer == 100:
                    return ('changed', 1, 2, 3) if method == 'socket_identity' else 'changed'
                return answer
            original_process = self.k.api.process
            def process(pid, **kwargs):
                answer = original_process(pid, **kwargs)
                # Root changes after initial peer sampling, without changing PID.
                self.k.peer = 100
                return answer
            # Epoch mutation is observed after connect but before HTTP.
            with patch.object(self.p.files, method, side_effect=identity):
                original_connect = self.k.connect
                def connect(*args):
                    result = original_connect(*args)
                    self.k.peer = 100
                    return result
                with patch.object(self.k, 'connect', side_effect=connect):
                    self.assert_rejected(self.diagnose(), connect=True)

    def test_server_request_bad_home_shape_and_oversize_fail_closed(self):
        for case in ('request', 'mixed_request', 'home', 'shape', 'oversize'):
            with self.subTest(case=case):
                self.rebuild()
                if case == 'request': self.k.reply = {'id': 42, 'method': 'request/approval', 'params': {}}
                if case == 'mixed_request': self.k.reply = {'id': 1, 'method': 'request/approval',
                    'result': {'userAgent': 'codex-tui/0.162.1', 'codexHome': str(self.home)}}
                if case == 'home': self.k.server_home = str(self.control)
                if case == 'shape': self.k.reply = {'id': 1, 'result': []}
                if case == 'oversize':
                    def frame(_): return b'\x81\x7f' + (4*1024*1024+1).to_bytes(8, 'big')
                    self.k.frame = frame
                # Protocol-shape oracle, not SDK-marshalling throughput. Keep
                # Close/assertions deterministic; separate deadline tests below.
                with patch('time.monotonic', return_value=1000.0):
                    result = self.diagnose()
                self.assert_rejected(result, zero=False)
                self.assertEqual([m.get('method') for m in self.k.messages], ['initialize'])
                self.assertEqual(self.k.opcodes[-1], 8)
                if case in ('request', 'mixed_request'): self.assertEqual(result['reason'], 'server_request_seen')
                if case == 'home': self.assertEqual(result['reason'], 'home_mismatch')
                if case == 'shape': self.assertEqual(result['reason'], 'initialize_failed')

    def test_absolute_deadline_and_receive_cap(self):
        with patch.object(local_transport.time, 'monotonic', side_effect=[10, 10, 10.7]):
            stream = local_transport.DaemonStream(self.p.transport)
            stream.settimeout(.5)
            stream.settimeout(1)
            self.assertEqual(stream.deadline, 10.5)
        self.assertEqual(codex_native.READ_SECONDS, 1.0)
        self.assertEqual(codex_native.MAX_RECEIVE_BYTES, 4*1024*1024)
        with patch.object(local_transport.DaemonStream, 'settimeout', side_effect=TimeoutError):
            self.assert_rejected(self.diagnose(), connect=False)

    def test_live_connection_budget_and_direct_io_epoch_rechecks(self):
        with (using_platform(self.p), patch.dict(os.environ, {'CODEX_HOME': str(self.home)}),
              self.p.transport.codex_read_scope('0.162.1'), windows_fixture('unix', str(self.socket))):
            client = codex_native.BoundedConnection(self.home, time.monotonic()+1, time.monotonic)
            try:
                self.assertEqual(client.receive_budget + 129, 4*1024*1024)  # fixture HTTP response also consumes budget
                self.assertTrue(client.strict_size)
                self.assertIsNotNone(client.close_deadline)
                self.assertLessEqual(client._socket.deadline, time.monotonic()+1)
                original = self.k.api.process
                def corrupt(pid, **kwargs):
                    return replace(original(pid, **kwargs), birth=1)
                with patch.object(self.k.api, 'process', side_effect=corrupt), self.assertRaises(OSError):
                    client._socket.verify()
                # B1: already connected socket IO no longer probes pathname
                # replacement; semantic unchanged() boundaries still do.
                before = len(self.k.socket_out)
                epoch = self.p.files.socket_identity
                def replaced(path, **kwargs):
                    return epoch(path, **kwargs) if len(self.k.socket_out) == before else ('replaced', 0, 0, 0)
                with patch.object(self.p.files, 'socket_identity', side_effect=replaced):
                    client._socket.sendall(b'\x89\x80abcd')  # complete masked empty Ping
                    self.assertGreater(len(self.k.socket_out), before)
                    with self.assertRaises(OSError): client._socket.verify()
            finally:
                client.close()
        self.assertEqual(self.k.handles, {})

    def test_logon_generation_and_record_consistency(self):
        peer = self.k.api.process(200)
        with self.assertRaises(OSError): logon.logon_info(self.k.api, replace(peer, birth=1))
        query = self.k.LsaGetLogonSessionData
        for field in ('LogonId', 'Session'):
            def altered(luid, out):
                result = query(luid, out)
                pointer = C.cast(out, C.POINTER(S.P)).contents.value
                row = C.cast(pointer, C.POINTER(S.SECURITY_LOGON_SESSION_PREFIX)).contents
                if field == 'Session': row.Session += 1
                else: row.LogonId.LowPart += 1
                return result
            with patch.object(self.k, 'LsaGetLogonSessionData', side_effect=altered), self.assertRaises(OSError):
                logon.logon_info(self.k.api, peer)
            self.assertEqual(self.k.lsa_allocations, set())
        for kind in (2, 10, 5, 99):
            self.k.logons = {200: (123, 1, kind)}
            value = logon.logon_info(self.k.api, peer)
            self.assertEqual(value['logonType'], {2:'INTERACTIVE',10:'REMOTE_INTERACTIVE',5:'SERVICE',99:'OTHER'}[kind])
            self.assertTrue(value['sameLogon'])
            self.assertTrue(value['sameSession'])

    def test_doctor_human_warning_and_redaction(self):
        result = self.diagnose()
        out = io.StringIO()
        with redirect_stdout(out): doctor.print_checks({'codexDaemon': result})
        self.assertIn('桌面注销可能终止共享后端', out.getvalue())
        self.assertIn('推断', out.getvalue())
        self.assertNotIn(str(self.home), out.getvalue())

    def test_production_guard_propagates_and_releases(self):
        with (using_platform(self.p), patch.dict(os.environ, {'CODEX_HOME': str(self.home)}),
              patch.object(codex_version, 'read_cli_version', return_value='0.162.1'),
              self.assertRaises(ProductionSocketUse)):
            codex_native.daemon_diagnostic(self.p.files.codex_home)
        self.assertEqual(self.k.socket_out, b'')
        self.assertFalse(any(n == 'connect' for n, _ in self.k.calls))

    def test_write_clients_disabled_even_inside_read_scope(self):
        thread = '019a0000-0000-7000-8000-000000000001'
        with using_platform(self.p), self.p.transport.codex_read_scope('0.162.1'):
            result = codex_rpc.queue_add(self.socket, thread_id=thread, text='synthetic',
                                        client_message_id=thread, client_version='0.162.1')
            self.assertIsInstance(result, codex_rpc.RpcResult)
            self.assertEqual(result.reason, 'windows_provider_not_enabled')
            self.assertIs(result.delivery, Delivery.FAILED)
            deleted = codex_withdraw.QueueDeleteClient(lambda _: '0.162.1').delete(
                self.home, thread=thread, item=thread, root_identity='synthetic', before_send=lambda _: self.fail('write boundary'))
            self.assertEqual((deleted.state, deleted.reason), ('not_attempted', 'windows_provider_not_enabled'))
            self.assertEqual(set(worker.default_transports()), {worker.Provider.CODEX,worker.Provider.CLAUDE})
        self.assertEqual(self.k.calls, [])
        with self.assertRaises(OSError): self.p.transport.new_stream()

    def test_logon_independent_sdk_layout_and_cross_session_not_denied(self):
        self.assertEqual(C.sizeof(A.TOKEN_STATISTICS), C.sizeof(S.TOKEN_STATISTICS))
        self.assertEqual(A.TOKEN_STATISTICS.authentication.offset, S.TOKEN_STATISTICS.AuthenticationId.offset)
        self.assertEqual(C.sizeof(A.LOGON_PREFIX), C.sizeof(S.SECURITY_LOGON_SESSION_PREFIX))
        self.assertEqual(A.LOGON_PREFIX.kind.offset, S.SECURITY_LOGON_SESSION_PREFIX.LogonType.offset)
        self.assertEqual(A.LOGON_PREFIX.session.offset, S.SECURITY_LOGON_SESSION_PREFIX.Session.offset)
        self.k.logons = {100: (0x100000011, 2, 2), 200: (0x200000011, 0, 5)}
        result = self.diagnose()
        self.assertTrue(result['reachable'])
        self.assertEqual(result['logonType'], 'SERVICE')
        self.assertTrue(result['sessionZero'])
        self.assertFalse(result['sameLogon'])
        self.assertFalse(result['sameSession'])
        raw = json.dumps(result)
        for secret in (str(self.home), 'codex.exe', '0x200000011', 'S-1-5', 'PRIVATE'):
            self.assertNotIn(secret, raw)
        self.assertEqual(self.k.lsa_allocations, set())

    def test_logon_failure_is_unknown_not_auth_failure_and_buffer_freed(self):
        for fault in ('query', 'short', 'generation', 'token_short', 'session_short'):
            self.rebuild()
            get = self.k.LsaGetLogonSessionData
            def query(luid, out):
                if fault == 'query': return -1
                result = get(luid, out)
                if fault == 'short':
                    pointer = C.cast(out, C.POINTER(S.P)).contents.value
                    C.cast(pointer, C.POINTER(S.U32)).contents.value = 4
                return result
            token = self.k.GetTokenInformation
            def token_info(handle, kind, buf, size, needed):
                result = token(handle, kind, buf, size, needed)
                if (fault == 'token_short' and kind == 10) or (fault == 'session_short' and kind == 12):
                    C.cast(needed, C.POINTER(S.U32)).contents.value = 0
                return result
            with patch.object(self.k, 'LsaGetLogonSessionData', side_effect=query), patch.object(self.k, 'GetTokenInformation', side_effect=token_info):
                if fault == 'generation':
                    with patch.object(logon, 'logon_info', side_effect=OSError('private')):
                        result = self.diagnose()
                else: result = self.diagnose()
            self.assertTrue(result['reachable'], fault)
            self.assertEqual(result['logonType'], 'UNKNOWN')
            self.assertEqual(self.k.lsa_allocations, set())
            self.assertEqual(self.k.handles, {})

    def test_doctor_read_scope_does_not_enable_write_cli(self):
        with (using_platform(self.p), patch.dict(os.environ, {'CODEX_HOME': str(self.home), 'AB_STATE_DIR': str(self.root/'state')}),
              patch.object(codex_version, 'read_cli_version', return_value='0.162.1'),
              windows_fixture('unix', str(self.socket))):
            checks = doctor.collect_checks()
            self.assertTrue(checks['codexDaemon']['reachable'])
            self.assertTrue(checks['providerEnabled'])
            self.assertEqual(checks['discovery'], 'unverified')
            self.assertTrue(checks['workerAutomatic'])
            out = io.StringIO()
            with redirect_stdout(out), redirect_stderr(out):
                self.assertEqual(cli.main(['send', '--to', 'synthetic', '-m', 'synthetic', '--json', '--no-wait']), 3)
            self.assertIn('caller_unattributed', out.getvalue())


if __name__ == '__main__':
    unittest.main()
