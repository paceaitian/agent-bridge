"""W1-2/3 组合根的负向接线测试；不触及真实平台对象。"""
from dataclasses import replace
import json
import os
import ast
import stat
import socket
import signal
from types import SimpleNamespace
from dataclasses import asdict
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import Mock, patch

from bridge_support import FakeProc
from agentstatus_bridge import paths, worker, summary, endpoints, doctor
from agentstatus_bridge.platforms.factory import get_platform, make_platform, using_platform
from agentstatus_bridge.platforms import process
from agentstatus_bridge.platforms.linux import files, lifecycle
from agentstatus_bridge.platforms.types import Presence, ProcessIdentity
from agentstatus_bridge.store import Store
from agentstatus_bridge.transports import local_codex, codex_queue
from agentstatus_bridge.transports.claude_peer import ClaudeInbox
from agentstatus_bridge.transports.codex_native import ReadBatchClient
from agentstatus_bridge.platforms.types import SampleState, RuntimeSnapshot
from test_bridge_codex_native import NativeDaemon, THREAD
from test_bridge_platform_baseline import record_linux, GOLDEN


class WiringTests(unittest.TestCase):
    def test_linux_listener_private_modes_close_scope_and_uid(self):
        from agentstatus_bridge.platforms.linux.listener import LinuxInbox
        from agentstatus_bridge.platforms.linux.local_transport import LinuxPlatform
        with TemporaryDirectory() as tmp:
            directory=Path(tmp)/'inbox'
            box=LinuxInbox(directory,name='own.sock')
            old=os.umask(0)
            try:box.open()
            finally:os.umask(old)
            try:
                self.assertEqual(stat.S_IMODE(directory.stat().st_mode),0o700)
                self.assertEqual(stat.S_IMODE(box.path.stat().st_mode),0o600)
                # Replaced with an ordinary file: close must not delete it.
                box.path.unlink();box.path.write_bytes(b'not a socket')
            finally:box.close()
            self.assertTrue(box.path.is_file())
            self.assertEqual(box.path.read_bytes(),b'not a socket')
            for mode,uid,expected in [(stat.S_IFSOCK,17,True),(stat.S_IFSOCK,18,False),(stat.S_IFREG,17,False)]:
                with patch('os.lstat',return_value=SimpleNamespace(st_mode=mode,st_uid=uid)):
                    self.assertIs(LinuxPlatform().owned_socket('/synthetic',17),expected)
            own=LinuxInbox(directory,name='later.sock');own.open();own.close()
            self.assertFalse(own.path.exists())
            foreign=LinuxInbox(directory,name='foreign.sock');foreign.open()
            info=SimpleNamespace(st_mode=stat.S_IFSOCK,st_uid=os.getuid()+1)
            with patch('agentstatus_bridge.platforms.linux.listener.os.lstat',return_value=info):
                foreign.close()
            self.assertTrue(foreign.path.exists())

    def test_linux_listener_client_cap_buffer_and_eof_boundaries(self):
        from agentstatus_bridge.platforms.linux.listener import LinuxInbox
        from agentstatus_bridge.platforms import transport_codec
        from agentstatus_bridge.platforms.linux import listener
        from agentstatus_bridge.transports import claude_peer
        self.assertEqual(transport_codec.MAX_INBOX_BUFFER,2*1024*1024)
        self.assertEqual(listener.MAX_INBOX_BUFFER,transport_codec.MAX_INBOX_BUFFER)
        self.assertEqual(claude_peer.MAX_INBOX_BUFFER,transport_codec.MAX_INBOX_BUFFER)
        package=Path(__file__).parents[1]/'src/agentstatus_bridge'
        definitions=[]
        for path in package.rglob('*.py'):
            for node in ast.walk(ast.parse(path.read_text())):
                if isinstance(node,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='MAX_INBOX_BUFFER' for t in node.targets):
                    definitions.append(path.relative_to(package).as_posix())
        self.assertEqual(definitions,['platforms/transport_codec.py'])
        with TemporaryDirectory() as tmp:
            box=LinuxInbox(Path(tmp),name='limit.sock');box.open()
            clients=[]
            try:
                for _ in range(33):
                    client=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);clients.append(client)
                    client.connect(str(box.path));box._accept()
                self.assertEqual(len(box._buffers),32)
                for client in list(box._buffers):box._drop(client)
                mocked=Mock();mocked.recv.return_value=b'x'
                box._buffers[mocked]=bytearray(b'x'*(2*1024*1024-1))
                self.assertEqual(box._read(mocked),[])
                self.assertIn(mocked,box._buffers)
                self.assertEqual(box._read(mocked),[])
                self.assertNotIn(mocked,box._buffers)
                mocked.close.assert_called_once()
                mocked=Mock();mocked.recv.return_value=b''
                box._buffers[mocked]=bytearray(b'{"tail":1}')
                self.assertEqual(box._read(mocked),[{'tail':1}])
                mocked.close.assert_called_once()
            finally:
                box.close()
                for client in clients:client.close()

    def test_linux_log_rotation_retains_old_inode_and_private_creation(self):
        with TemporaryDirectory() as tmp:
            path=Path(tmp)/'worker.log';old=os.umask(0)
            try:
                files.append_log(path,b'old content',4)
                self.assertEqual(stat.S_IMODE(path.stat().st_mode),0o600)
                inode=path.stat().st_ino
                files.append_log(path,b'new',4)
            finally:os.umask(old)
            rotated=path.with_name('worker.log.1')
            self.assertTrue(rotated.exists())
            if rotated.exists():
                self.assertEqual(rotated.stat().st_ino,inode)
                self.assertEqual(rotated.read_bytes(),b'old content')
            self.assertEqual(path.read_bytes(),b'new')
            self.assertEqual(stat.S_IMODE(path.stat().st_mode),0o600)

    def test_linux_stop_signals_include_sigint_and_restore_exact_handlers(self):
        handler=Mock()
        with patch.object(lifecycle.signal,'signal',side_effect=['old-term','old-int',None,None]) as install:
            previous=lifecycle.LinuxLifecycle.install_stop(handler)
            self.assertEqual(previous,{signal.SIGTERM:'old-term',signal.SIGINT:'old-int'})
            lifecycle.LinuxLifecycle.restore_stop(previous)
        self.assertEqual([c.args for c in install.call_args_list],[(signal.SIGTERM,handler),(signal.SIGINT,handler),
                         (signal.SIGTERM,'old-term'),(signal.SIGINT,'old-int')])

    def test_doctor_uses_selected_runtime_availability_not_row_count(self):
        runtime = Mock()
        for state, expected in ((SampleState.AVAILABLE, True), (SampleState.EMPTY, True),
                                (SampleState.UNAVAILABLE, False), (SampleState.UNVERIFIED, False)):
            with self.subTest(state=state), using_platform(replace(make_platform('linux'), runtime=runtime)):
                runtime.reset_mock()
                runtime.sample.return_value = RuntimeSnapshot(state)
                self.assertIs(doctor._runtime_available(), expected)
                runtime.sample.assert_called_once_with()

    def test_transport_facade_and_file_identity_have_one_owner(self):
        base = make_platform('linux')
        self.assertIs(base.transport.files, base.files)
        t = Mock(wraps=base.transport)
        t.socket_identity.return_value = ('opaque', 1, 2, 3)
        with using_platform(replace(base, transport=t)):
            self.assertIs(local_codex.platform(), t)
            self.assertEqual(local_codex.socket_identity(Path('/not-read')), ('opaque', 1, 2, 3))
            self.assertFalse(endpoints._is_owned_socket('/not-read', 999))
            t.owned_socket.assert_called_once_with('/not-read', 999)
        win = make_platform('windows')
        self.assertFalse(win.transport.supported)
        self.assertIsNone(win.transport.socket_identity(Path('/not-read')))
        with self.assertRaises(OSError):
            win.transport.new_stream()
        # W3 construction is still pure: native IO begins only at open().
        inbox = win.transport.inbox()
        self.assertIs(inbox.files, win.files)
        self.assertFalse(inbox.healthy())

    def test_root_hash_and_epoch_match_fixed_linux_object_vectors(self):
        f = make_platform('linux').files
        def resolve(path, **kwargs):
            return Path('/vector/root-' + path.name)
        info = SimpleNamespace(st_uid=1000, st_dev=11, st_ino=22, st_ctime_ns=987, st_mode=stat.S_IFDIR | 0o700)
        with patch.object(Path, 'resolve', resolve), patch.object(Path, 'stat', return_value=info), \
                patch.object(files.os, 'getuid', return_value=1000):
            self.assertEqual(f.root_identity(Path('a'), Path('b')),
                '26443b6b31abb99df24a318744bc205a7ff17ae15249cd877721ea5784f656c5')
            self.assertEqual(f.socket_identity(Path('/vector/socket')), ('/vector/socket', 11, 22, 987))
            self.assertTrue(f.home_equal('a', Path('a')))
            self.assertFalse(f.home_equal('a', Path('b')))
            info.st_uid = 1001
            self.assertIsNone(f.root_identity(Path('a'), Path('b')))

    def test_claude_send_uses_t_and_f_but_keeps_exact_process_gate(self):
        from agentstatus_bridge.transports.claude_peer import ClaudePeerTransport
        from agentstatus_bridge.transports import DeliveryContext
        from agentstatus_bridge.model import Provider, Delivery
        from bridge_support import endpoint, ref
        base = make_platform('linux')
        t, f, stream = Mock(wraps=base.transport), Mock(wraps=base.files), Mock()
        stream.recv.return_value = b''
        t.new_stream.return_value = stream
        t.connect_claude.return_value = None
        t.shutdown_write.return_value = None
        t.peer_credentials.return_value = (17, 77, 77)
        f.uid.return_value = 77
        with TemporaryDirectory() as tmp, using_platform(replace(base, transport=t, files=f)):
            fake = FakeProc(Path(tmp))
            fake.add(17, comm='claude', start='0007')
            fake.add(18, comm='claude', start='0007')
            transport = ClaudePeerTransport(proc_root=fake.root)
            target = endpoint(ref(Provider.CLAUDE, 'fixture', pid=17, start='0007'), socket_path='/not-connected')
            result = transport.deliver(target, 'fixture', DeliveryContext('uuid', 'fixture'))
            self.assertIs(result.delivery, Delivery.WRITTEN)
            t.connect_claude.assert_called_once_with(stream, '/not-connected')
            t.peer_credentials.assert_called_once_with(stream)
            t.shutdown_write.assert_called_once_with(stream)
            stream.close.assert_called_once()
            stream.sendall.assert_called_once()
            f.uid.assert_called_once()
            t.peer_credentials.return_value = (18, 77, 77)
            result = transport.deliver(target, 'fixture', DeliveryContext('uuid', 'fixture'))
            self.assertIs(result.delivery, Delivery.FAILED)
            self.assertEqual(stream.sendall.call_count, 1)
            t.peer_credentials.return_value = (17, 78, 77)
            result = transport.deliver(target, 'fixture', DeliveryContext('uuid', 'fixture'))
            self.assertIs(result.delivery, Delivery.FAILED)
            self.assertEqual(stream.sendall.call_count, 1)
            t.peer_credentials.return_value = (17, 77, 77)
            wrong_generation = endpoint(ref(Provider.CLAUDE, 'fixture', pid=17, start='7'), socket_path='/not-connected')
            result = transport.deliver(wrong_generation, 'fixture', DeliveryContext('uuid', 'fixture'))
            self.assertIs(result.delivery, Delivery.FAILED)
            self.assertEqual(stream.sendall.call_count, 1)

    def test_native_real_wire_uses_selected_transport_epoch_and_home_check(self):
        base = make_platform('linux')
        t = Mock(wraps=base.transport)
        with TemporaryDirectory() as tmp, using_platform(replace(base, transport=t)):
            daemon = NativeDaemon(Path(tmp))
            try:
                result = ReadBatchClient(lambda _: '0.162.1').read(daemon.home, [THREAD], {THREAD: {os.getpid()}})
                self.assertEqual(result.reason, 'ok')
                self.assertEqual(result.records[THREAD].kind, 'root')
                self.assertEqual(daemon.methods(), ['initialize', 'initialized', 'thread/read'])
                self.assertEqual(t.connect.call_count, 1)
                self.assertEqual(t.new_stream.call_count, 1)
                self.assertEqual(t.peer_pid.call_count, 1)
                self.assertEqual(t.home_equal.call_count, 1)
                self.assertGreaterEqual(t.socket_identity.call_count, 4)
            finally:
                daemon.close()

    def test_claude_listener_uses_selected_transport_and_retains_lifecycle(self):
        backing = Mock()
        backing.path = Path('/synthetic-inbox')
        backing.address = 'uds:/synthetic-inbox'
        backing.poll.return_value = [{'a': 1}]
        backing.healthy.return_value = False
        t = Mock(wraps=make_platform('linux').transport)
        t.inbox.return_value = backing
        with using_platform(replace(make_platform('linux'), transport=t)):
            box = ClaudeInbox(Path('/fixture'), name='a.sock')
            self.assertEqual(box.path, backing.path)
            self.assertEqual(box.address, backing.address)
            box.open()
            self.assertFalse(box.healthy())
            self.assertEqual(box.poll(0.125), [{'a': 1}])
            box.close()
            t.inbox.assert_called_once_with(Path('/fixture'), name='a.sock')
            self.assertEqual([c[0] for c in backing.mock_calls], ['open', 'healthy', 'poll', 'close'])

    def test_run_capture_preserves_both_command_shapes(self):
        from subprocess import CompletedProcess
        with patch.object(lifecycle.subprocess, 'run', return_value=CompletedProcess([], 4, 'O', 'E')) as run:
            runner = make_platform('linux').lifecycle
            value = runner.run_capture(('codex-fixture', '--version'), 3.0, replace_errors=True)
            self.assertEqual((value.returncode, value.stdout, value.stderr), (4, 'O', 'E'))
            self.assertEqual(run.call_args.args, (['codex-fixture', '--version'],))
            self.assertEqual(run.call_args.kwargs, dict(stdin=lifecycle.subprocess.DEVNULL, capture_output=True,
                             text=True, errors='replace', timeout=3.0, check=False))
            runner.run_capture(('git-fixture',), 5.0)
            self.assertEqual(run.call_args.kwargs, dict(stdin=lifecycle.subprocess.DEVNULL, capture_output=True,
                             text=True, timeout=5.0, check=False))
        l = Mock(wraps=make_platform('linux').lifecycle)
        l.run_capture.return_value = CompletedProcess([], 0, 'O'*5000, 'E'*5000)
        with using_platform(replace(make_platform('linux'), lifecycle=l)):
            self.assertEqual(asdict(codex_queue._default_runner(['fixture'], 2)),
                             {'returncode': 0, 'stdout': 'O'*4096, 'stderr': 'E'*4096})
            l.run_capture.assert_called_once_with(['fixture'], 2, replace_errors=True)

    def test_both_sql_uri_encodings_remain_distinct(self):
        path = Path('/synthetic/a #?中.sqlite')
        f = make_platform('linux').files
        self.assertEqual(f.sqlite_uri(path, escaped=False), 'file:/synthetic/a #?中.sqlite?mode=ro')
        self.assertEqual(f.sqlite_uri(path, escaped=True), path.as_uri()+'?mode=ro')

    def test_common_consumers_have_no_linux_os_shortcuts(self):
        package = Path(__file__).parents[1] / 'src/agentstatus_bridge'
        prohibited = {'fcntl', 'signal', 'selectors', 'pwd', 'gi'}
        findings = []
        for name in ('paths.py', 'worker.py', 'summary.py', 'store.py', 'endpoints.py', 'cli.py',
                     'reports.py', 'doctor.py', 'transports/local_codex.py', 'transports/claude_peer.py'):
            tree = ast.parse((package/name).read_text())
            for node in ast.walk(tree):
                if isinstance(node, ast.Import) and any(a.name.split('.')[0] in prohibited for a in node.names):
                    findings.append((name, node.lineno, 'import'))
                if isinstance(node, ast.Attribute) and node.attr in {'AF_UNIX', 'SO_PEERCRED', 'getuid', 'flock'}:
                    findings.append((name, node.lineno, node.attr))
        self.assertEqual(findings, [])

    def test_context_restores_and_f_l_consumers_share_root(self):
        base = make_platform('linux')
        f, l = Mock(wraps=base.files), Mock(wraps=base.lifecycle)
        chosen = replace(base, files=f, lifecycle=l)
        with TemporaryDirectory() as tmp, using_platform(chosen):
            root = Path(tmp) / 'state'
            self.assertIs(get_platform(), chosen)
            with Store.open(root) as store:
                summary.publish(store, root, force=True)
            worker.WorkerLog(root / 'worker.log')('sample', {'count': 1})
            self.assertFalse(worker.worker_running(root))
            f.ensure_private_dir.assert_called()
            f.prepare_database.assert_called_once_with(root / 'bridge.sqlite3')
            f.atomic_write.assert_called_once()
            f.append_log.assert_called_once()
            self.assertEqual(l.open_lock.call_count, 2)
            self.assertEqual([c.kwargs for c in l.try_lock.call_args_list], [{}, {'shared': True}])
            self.assertEqual((l.unlock.call_count, l.close_lock.call_count), (2, 2))
            with self.assertRaises(ValueError), using_platform(make_platform('windows')):
                raise ValueError('fixture')
            self.assertIs(get_platform(), chosen)
        self.assertIsNot(get_platform(), chosen)

    def test_baseline_all_indirect_process_consumers_reach_root(self):
        base = make_platform('linux')
        p = Mock(wraps=base.process)
        f = Mock(wraps=base.files)
        with using_platform(replace(base, process=p, files=f)):
            actual = record_linux()
        self.assertEqual(actual, json.loads(GOLDEN.read_text()))
        self.assertGreater(p.legacy.call_count, 10)
        f.sqlite_uri.assert_called()

    def test_linux_legacy_none_does_not_use_three_state_recovery(self):
        base = make_platform('linux')
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            fake = FakeProc(root)
            fake.add(17, comm='sh', start='0007')
            backend = make_platform('linux', proc_root=root).process
            identity = ProcessIdentity('linux', 18, 'linux-proc-ticks', '7')
            self.assertIs(backend.same_generation(identity), Presence.UNKNOWN)
            with using_platform(base):
                self.assertIsNone(process.read_process(18, root))
                self.assertFalse(process.is_same_generation(18, '7', root))
                self.assertTrue(process.is_same_generation(17, '0007', root))
                self.assertFalse(process.is_same_generation(17, '7', root))
            with using_platform(make_platform('windows')), self.assertRaises(OSError):
                process.is_same_generation(18, '7', root)

    def test_paths_and_policy_use_injected_files(self):
        f = Mock(wraps=make_platform('linux').files)
        f.state_dir.return_value = Path('/synthetic-only')
        f.policy_dir.return_value = Path('/synthetic-policy')
        f.present.return_value = True
        with using_platform(replace(make_platform('linux'), files=f)):
            self.assertEqual(paths.state_dir(), Path('/synthetic-only'))
            self.assertTrue(endpoints._present(Path('/not-read')))
            source = endpoints.DiscoverySources()
            self.assertIs(source.platform.files, f)
            f.uid.assert_called_once()
        self.assertNotEqual(files.CLAUDE_SYSTEM_DIR, Path('/etc/claude-code'))

    def test_summary_open_retains_nofollow_and_private_mode(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            target = root / 'target'
            target.touch()
            (root / summary.LOCK_NAME).symlink_to(target)
            with self.assertRaises(OSError):
                with summary._lock(root):
                    pass
            self.assertEqual(target.read_bytes(), b'')

    def test_worker_spawn_uses_selected_lifecycle(self):
        l = Mock(wraps=make_platform('linux').lifecycle)
        with TemporaryDirectory() as tmp, using_platform(replace(make_platform('linux'), lifecycle=l)), \
                patch.object(lifecycle.subprocess, 'Popen') as spawn:
            self.assertTrue(worker.ensure_worker(Path(tmp)))
            self.assertEqual(l.spawn_worker.call_count, 1)
            spawn.assert_called_once()
            self.assertTrue(spawn.call_args.kwargs['close_fds'])
            self.assertTrue(spawn.call_args.kwargs['start_new_session'])
            self.assertEqual(spawn.call_args.kwargs['env']['AB_STATE_DIR'], tmp)

    def test_file_atomic_failure_keeps_old_bytes_and_cleans_temporary(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            path = root / 'summary.json'
            path.write_bytes(b'old')
            with patch.object(files.os, 'replace', side_effect=OSError('fixture')), self.assertRaises(OSError):
                files.atomic_write(root, b'new', name='summary.json', prefix='.summary.')
            self.assertEqual(path.read_bytes(), b'old')
            self.assertEqual(sorted(p.name for p in root.iterdir()), ['summary.json'])


if __name__ == '__main__':
    unittest.main()
