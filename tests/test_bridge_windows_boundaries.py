"""§77.17: SDK/Fake product paths only; no Windows qualification claim."""
from contextlib import closing, redirect_stdout
from dataclasses import replace
import io
import json
import os
from pathlib import Path
import subprocess
import sqlite3
from types import SimpleNamespace
import unittest
from unittest.mock import patch, Mock

import bridge_support
import test_bridge_windows_delivery as delivery_fixture
from test_bridge_windows_discovery import uuid
from agentstatus_bridge import doctor, cli
from agentstatus_bridge.store import Store, StoreError, DB_NAME, SCHEMA_VERSION
from agentstatus_bridge.model import Delivery
from agentstatus_bridge.platforms.windows import codex_version as V, caller as C
from agentstatus_bridge.platforms.windows import worker_identity as W, codex_discovery as D
from agentstatus_bridge.platforms.windows import local_store as L, lifecycle
from agentstatus_bridge.transports import codex_native
from agentstatus_bridge.platforms.windows.api import WinFailure
from agentstatus_bridge.platforms.windows.files import WindowsPaths
from agentstatus_bridge.platforms.windows.local_transport import DaemonStream
from agentstatus_bridge.platforms.windows.private_file import pinned_file


class BoundaryTests(unittest.TestCase):
    setUp = delivery_fixture.DeliveryTests.setUp
    rebuild = delivery_fixture.DeliveryTests.rebuild
    scope = delivery_fixture.DeliveryTests.scope
    target = delivery_fixture.DeliveryTests.target
    deliver = delivery_fixture.DeliveryTests.deliver
    adds = delivery_fixture.DeliveryTests.adds
    chain = delivery_fixture.DeliveryTests.chain
    run_cli = delivery_fixture.DeliveryTests.run_cli

    def test_external_file_delete_sharing_and_private_file_control(self):
        leaf = self.home / 'metadata.sqlite'
        for external in (False, True):
            for action in ('rename', 'delete'):
                leaf.write_bytes(b'fixture')
                moved = self.home / 'moved.sqlite'
                with self.scope(), self.p.files.external_directory(self.home), pinned_file(self.p.files, leaf, external=external):
                    handles = [h for h in self.k.handles.values() if h.get('path') == str(leaf)]
                    self.assertEqual(handles[0]['sharing'] & 4, 4 if external else 0)
                    error = None
                    try:
                        if action == 'rename': self.k.api.replace(str(leaf), str(moved))
                        else: self.k.api.delete(str(leaf))
                    except OSError as exc: error = exc
                    if external:
                        self.assertIsNone(error)
                    else:
                        self.assertEqual(getattr(error, 'winerror', None), 32)
                        self.assertTrue(leaf.exists())
                # DeleteFileW may defer removal until the last shared handle
                # closes. Do not require POSIX unlink timing inside the lease.
                if external:
                    self.assertFalse(leaf.exists())
                moved.unlink(missing_ok=True)
                leaf.unlink(missing_ok=True)
                self.assertEqual(self.k.handles, {})

    def test_external_socket_share_delete_and_acl_not_queried(self):
        with self.scope(), self.p.transport.codex_read_scope('fixture'):
            # No DACL/owner query for an external control directory/socket.
            with patch.object(self.k.api, 'check_private', side_effect=AssertionError('external ACL queried')):
                self.p.files.socket_identity(self.socket, external=True)
            self.assertFalse(any(n == 'GetSecurityInfo' for n, _ in self.k.calls))
            opens = [a for n,a in self.k.calls if n == 'CreateFileW']
            self.assertTrue(opens)
            self.assertTrue(all(a[2] & 4 for a in opens))
        self.assertEqual(self.k.handles, {})

    def test_windows_read_five_seconds_linux_one_and_add_six_hundred(self):
        self.assertEqual(codex_native.READ_SECONDS, 1.0)
        self.assertEqual(codex_native.WINDOWS_READ_SECONDS, 5.0)
        for mode in ('discover', 'doctor'):
            for elapsed in (2.0, 5.01):
                self.rebuild()
                now = [1000.0]
                connect = self.k.connect
                def delayed(*args):
                    now[0] += elapsed
                    return connect(*args)
                with self.scope(), patch('time.monotonic', side_effect=lambda: now[0]), patch.object(self.k, 'connect', delayed):
                    if mode == 'discover':
                        result = D.discover(self.p.transport)
                        self.assertEqual(result.complete, elapsed < 5)
                    else:
                        result = codex_native.daemon_diagnostic(lambda: self.home)
                        self.assertEqual(result['reachable'], elapsed < 5)
                    if elapsed > 5: self.assertEqual(self.k.socket_out, b'')
                self.assertEqual(self.k.handles, {})
        with self.scope():
            self.assertEqual(DaemonStream(self.p.transport).deadline, 1005.0)
            with self.p.transport.codex_add_scope('fixture'):
                self.assertEqual(DaemonStream(self.p.transport).deadline, 1600.0)
            self.assertEqual(DaemonStream(self.p.transport).deadline, 1005.0)

    def test_log_rotates_whole_old_content_and_keeps_exact_limit(self):
        path = self.state / 'worker.log'; backup = self.state / 'worker.log.1'
        with self.scope():
            self.p.files.append_log(path, b'abcd', 4)
            self.p.files.append_log(path, b'e', 4)
            self.assertEqual(path.read_bytes(), b'abcde')
            self.assertFalse(backup.exists())
            # Old log deliberately much larger than the bounded size probe.
            path.write_bytes(b'x' * 64)
            self.p.files.append_log(path, b'new', 4)
            self.assertTrue(backup.is_file())
            self.assertEqual(backup.read_bytes(), b'x' * 64)
            self.assertEqual(path.read_bytes(), b'new')
            self.p.files.append_log(path, b'!!', 4)
            self.p.files.append_log(path, b'next', 4)
            self.assertEqual(backup.read_bytes(), b'new!!')
            self.assertEqual(path.read_bytes(), b'next')
            self.assertIsNotNone(self.p.files.validate_file(backup))
            self.assertIsNotNone(self.p.files.validate_file(path))
        self.assertEqual(self.k.handles, {})

    def test_log_rotation_failure_preserves_old_bytes(self):
        path = self.state / 'worker.log'; backup = path.with_name('worker.log.1')
        with self.scope():
            self.p.files.append_log(path, b'original', 2)
            for fault in (5, 32):
                self.k.faults['MoveFileExW'] = fault
                error = None
                try: self.p.files.append_log(path, b'wrong', 2)
                except OSError as exc: error = exc
                self.assertEqual(getattr(error, 'winerror', None), fault)
                self.assertEqual(path.read_bytes(), b'original')
                self.assertFalse(backup.exists())
            self.k.faults.clear()
            original = self.k.MoveFileExW
            first = [True]
            def fail_once(*args):
                if first[0]:
                    first[0] = False
                    return self.k.fail(32)
                return original(*args)
            error = None
            with patch.object(self.k, 'MoveFileExW', side_effect=fail_once):
                try: self.p.files.append_log(path, b'wrong', 2)
                except OSError as exc: error = exc
            self.assertIsNone(error)
            self.assertEqual(path.read_bytes(), b'wrong')
            self.assertEqual(backup.read_bytes(), b'original')
            backup.write_bytes(b'preserve')
            self.k.files[str(backup)] = {'reparse': True}
            with self.assertRaises(OSError): self.p.files.append_log(path, b'wrong', 2)
            self.assertEqual(backup.read_bytes(), b'preserve')
            self.assertEqual(path.read_bytes(), b'wrong')
        self.assertEqual(self.k.handles, {})

    def test_wait_legacy_options_readonly_and_future_schema_rejected(self):
        with self.scope(), Store.open(self.state) as store:
            task, attempt = bridge_support.new_task(store)
            store.begin_send(attempt.id, now=10, pid=100, start_ticks='fixture')
            store.finish_send(attempt.id, delivery=Delivery.QUEUED, reason='fixture', provider_ref='id', detail={}, now=11)
        path = self.state / DB_NAME
        with closing(sqlite3.connect(path)) as db, db:
            db.execute('ALTER TABLE tasks DROP COLUMN options')
            db.execute('ALTER TABLE attempts DROP COLUMN options')
            db.execute('DROP TABLE native_withdrawals')
        with self.scope(), patch.object(cli, '_revive_worker', side_effect=AssertionError('wait worker')),\
                patch.object(D, 'discover', side_effect=AssertionError('wait daemon')):
            for version in (0, 1):
                with closing(sqlite3.connect(path)) as db, db: db.execute('PRAGMA user_version='+str(version))
                before = path.read_bytes()
                error = None
                try:
                    with L.open_store() as ro:
                        self.assertEqual(ro.get_task(task.id).options, {})
                        self.assertEqual(ro.get_attempt(attempt.id).options, {})
                        self.assertEqual(ro._conn.execute('PRAGMA user_version').fetchone()[0], version)
                        self.assertEqual(ro._conn.execute('PRAGMA query_only').fetchone()[0], 1)
                        self.assertFalse(ro._withdrawals_ready)
                        row = ro._conn.execute('SELECT 17 AS value').fetchone()
                        self.assertEqual(row[0], 17)
                        self.assertEqual(row['value'], 17)
                        with self.assertRaises(IndexError): row['missing']
                        with self.assertRaises(sqlite3.OperationalError): ro._conn.execute('DELETE FROM tasks')
                except (StoreError, IndexError) as exc: error = exc
                self.assertIsNone(error)
                self.assertEqual(self.run_cli('wait', task.id, '--until', 'sent', '--json')[0], 0)
                self.assertEqual(path.read_bytes(), before)
            with closing(sqlite3.connect(path)) as db, db: db.execute('PRAGMA user_version='+str(SCHEMA_VERSION+1))
            with self.assertRaises(StoreError) as caught:
                with L.open_store(): pass
            self.assertEqual(caught.exception.code, 'schema_too_new')
            self.assertEqual(self.run_cli('wait', task.id, '--timeout', '0')[0], 8)
        self.assertEqual(self.k.handles, {})

    def test_worker_identity_ten_second_window_bounded_fake_clock(self):
        binary = self.root/'python.exe'; binary.touch(); self.state.mkdir()
        with self.scope(), patch.object(W, 'executable', return_value=binary),\
                patch.object(self.p.lifecycle, '_spawn', return_value=Mock(pid=100)):
            for ready in (8.0, None):
                now, attempts = [1000.0], []
                def verify(*args, **kw):
                    attempts.append(now[0])
                    self.assertLessEqual(len(attempts), 203, 'unbounded identity retry')
                    if ready is None or now[0] < 1000.0+ready: raise OSError('not_ready')
                    return {}
                def sleep(seconds):
                    self.assertEqual(seconds, 0.05)
                    now[0] += seconds
                error = None
                with patch.object(lifecycle.time, 'monotonic', side_effect=lambda: now[0]),\
                        patch.object(lifecycle.time, 'sleep', side_effect=sleep), patch.object(W, 'verify', side_effect=verify):
                    try: self.p.lifecycle.spawn_worker(self.state, {})
                    except OSError as exc: error = exc
                if ready is None:
                    self.assertIsInstance(error, OSError)
                    self.assertEqual(error.args, ('worker_identity_unverified',))
                    self.assertGreaterEqual(now[0], 1010.0)
                    self.assertLess(now[0], 1010.051)
                else:
                    self.assertIsNone(error)
                    self.assertGreaterEqual(now[0], 1008.0)
                    self.assertLess(now[0], 1008.051)
        self.assertEqual(self.k.handles, {})

    def test_recovery_only_proved_exit_or_reused_pid_not_unknown(self):
        original = self.k.processes[100]
        for case in ('alive', 'missing', 'reused', 'signalled', 'denied', 'sid', 'elevated', 'wait_failed'):
            self.k.processes[100] = original
            self.k.faults.clear()
            with self.scope(), Store.open(self.state) as store:
                task, attempt = bridge_support.new_task(store)
                self.assertTrue(store.begin_send(attempt.id, now=10, pid=100, start_ticks='win-filetime:'+str(original[1])))
                if case == 'missing': del self.k.processes[100]
                if case == 'reused': self.k.processes[100] = (original[0], original[1]+1, original[2], False, original[4])
                if case == 'denied': self.k.faults['OpenProcess'] = 5
                if case == 'sid': self.k.processes[100] = (*original[:2], b'\x01\x01'+b'\0'*10, False, original[4])
                if case == 'elevated': self.k.processes[100] = (*original[:3], True, original[4])
                wait = self.k.WaitForSingleObject
                with patch.object(self.k, 'WaitForSingleObject', side_effect=(lambda *_: 0) if case == 'signalled' else
                                  (lambda *_: 0xffffffff) if case == 'wait_failed' else wait):
                    expected = case in ('missing', 'reused', 'signalled')
                    # Give current-token queries an independent valid caller.
                    with patch.object(self.k.api, 'current_token', return_value=SimpleNamespace(sid=original[2], elevated=False)):
                        self.assertEqual(store.recover_interrupted(now=20), int(expected), case)
                    self.assertIs(store.get_attempt(attempt.id).delivery, Delivery.UNKNOWN if expected else Delivery.SENDING)
                # Avoid a retained SENDING row affecting the next independent vector.
                self.k.processes[100] = original; self.k.faults.clear()
                store.finish_send(attempt.id, delivery=Delivery.UNKNOWN, reason='fixture_cleanup', provider_ref=None, detail={}, now=21)
        self.assertEqual(self.k.handles, {})

    def test_sending_budget_recovery_unknown_alive_and_late_result(self):
        from agentstatus_bridge.store import WINDOWS_SENDING_RECOVERY_SECONDS
        from agentstatus_bridge.platforms.windows.codex_delivery import TOTAL_SECONDS
        self.assertEqual(WINDOWS_SENDING_RECOVERY_SECONDS,TOTAL_SECONDS+120)
        for denied in (False,True):
            with self.scope(), Store.open(self.state) as store:
                _,attempt=bridge_support.new_task(store)
                self.assertTrue(store.begin_send(attempt.id,now=10,pid=100,
                    start_ticks='win-filetime:'+str(self.k.processes[100][1])))
                if denied:self.k.faults['OpenProcess']=5
                try:
                    self.assertEqual(store.recover_interrupted(now=730),0)
                    self.assertIs(store.get_attempt(attempt.id).delivery,Delivery.SENDING)
                    self.assertEqual(store.recover_interrupted(now=730.001),1)
                    self.assertIs(store.get_attempt(attempt.id).delivery,Delivery.UNKNOWN)
                    self.assertEqual(store.get_attempt(attempt.id).delivery_reason,'codex_queue_timeout')
                    self.assertFalse(store.finish_send(attempt.id,delivery=Delivery.QUEUED,reason='late',
                        provider_ref=uuid(900),detail={},now=731))
                    self.assertFalse(store.begin_send(attempt.id,now=732,pid=100,start_ticks='1'))
                    self.assertEqual(store.recover_interrupted(now=10000),0)
                finally:self.k.faults.clear()

    def test_worker_receipt_reads_shared_delete_handle_not_a_second_open(self):
        import sys
        binary=self.root/'python-base.exe';binary.touch();self.k.images[100]=str(binary)
        with self.scope(),patch.object(sys,'_base_executable',str(binary)):
            W.register(self.p.files,self.state)
            path=self.state/W.RECEIPT
            original=self.k.api.read
            captured=[]
            def read(handle,limit):
                row=self.k.record(handle)
                self.assertEqual(row['path'],str(path))
                self.assertEqual(row['sharing'],7)
                # No nested Python open/replacement: the authenticated handle
                # alone supplies bytes. Writer contention is tested separately.
                captured.append(handle)
                return original(handle,limit)
            with patch.object(self.k.api,'read',side_effect=read):
                self.assertEqual(W.verify(self.p.files,self.state)['pid'],100)
            self.assertEqual(len(captured),1)
            self.assertTrue(any(n=='ReadFile' and args[-1] is None for n,args in self.k.calls))
            valid=path.read_bytes()
            self.assertLess(len(valid),4097)
            path.write_bytes(valid+b' '*(4097-len(valid)))
            with self.assertRaisesRegex(OSError,'worker_identity_unverified'):W.verify(self.p.files,self.state)

    def test_one_connection_verification_for_full_discovery(self):
        with self.scope(), patch.object(DaemonStream, 'verify', autospec=True, side_effect=DaemonStream.verify) as check:
            result = D.discover(self.p.transport)
        self.assertTrue(result.complete)
        self.assertEqual(check.call_count, 1)
        self.assertGreater(len(self.k.messages), 3)
        self.assertEqual(self.k.handles, {})

    def test_peer_rejected_before_http_and_boundary_root_still_checked(self):
        pid = self.k.processes[200]
        self.k.processes[200] = (*pid[:2], b'\x01\x01'+b'\0'*6+b'\x01\0\0\0', False, 'codex.exe')
        with self.scope(): result = D.discover(self.p.transport)
        self.assertFalse(result.complete)
        self.assertEqual(bytes(self.k.socket_out), b'')
        self.k.processes[200] = pid
        with self.scope():
            target = self.target()
            # Root changes after the boundary is recorded but before add bytes.
            with patch.object(self.p.files, 'root_identity', wraps=self.p.files.root_identity) as root:
                def boundary(): root.return_value = 'changed'
                outcome = self.deliver(target, before_send=boundary)
        self.assertIsNot(outcome.delivery, Delivery.QUEUED)
        self.assertEqual(self.adds(), [])

    def test_version_final_file_identity_cache_and_failures(self):
        executable = self.root/'actual.exe'; executable.touch()
        # Inject Windows junction resolution, avoiding native symlink privilege
        # requirements on Windows CI. The cache still uses real final-file stat.
        link, outer = self.root/'junction', self.root/'outer'
        resolve = Path.resolve
        def resolved(path, *, strict=False):
            self.assertTrue(strict)
            return resolve(executable if path in (link/'actual.exe',outer/'actual.exe') else path, strict=True)
        V._cache.clear(); self.addCleanup(V._cache.clear)
        with patch.object(Path, 'resolve', resolved), patch.object(V.shutil, 'which', return_value=str(outer/'actual.exe')) as which, patch.object(
                V.subprocess, 'run', return_value=subprocess.CompletedProcess([],0,'codex-cli 0.163.0\n')) as run:
            self.assertEqual(V.read_cli_version(),'0.163.0')
            self.assertEqual(run.call_args.args[0],[str(executable.resolve(strict=True)),'--version'])
            which.return_value=str(link/'actual.exe')
            self.assertEqual(V.read_cli_version(),'0.163.0'); self.assertEqual(run.call_count,1)
            stat=executable.stat(); os.utime(executable,ns=(stat.st_atime_ns,stat.st_mtime_ns+1000000))
            self.assertEqual(V.read_cli_version(),'0.163.0'); self.assertEqual(run.call_count,2)
            replacement=self.root/'replacement'; replacement.touch()
            os.utime(replacement,ns=(stat.st_atime_ns,executable.stat().st_mtime_ns))
            replacement.replace(executable)
            self.assertEqual(V.read_cli_version(),'0.163.0'); self.assertEqual(run.call_count,3)
            V._cache.clear(); run.return_value=subprocess.CompletedProcess([],1,'')
            self.assertIsNone(V.read_cli_version()); self.assertIsNone(V.read_cli_version())
            self.assertEqual(run.call_count,5); self.assertEqual(V._cache,{})
            run.return_value=subprocess.CompletedProcess([],0,'codex-cli 0.164.0\n')
            self.assertEqual(V.read_cli_version(),'0.164.0'); self.assertEqual(run.call_count,6)
            stat=executable.stat()
            with patch.object(Path,'stat',return_value=SimpleNamespace(st_dev=stat.st_dev+1,st_ino=stat.st_ino,st_mtime_ns=stat.st_mtime_ns)):
                self.assertEqual(V.read_cli_version(),'0.164.0');self.assertEqual(run.call_count,7)
        with patch.object(V.shutil, 'which', return_value=str(self.root/'missing')), patch.object(V.subprocess,'run') as run:
            self.assertIsNone(V.read_cli_version()); run.assert_not_called()

    def test_inherited_agent_environment_does_not_override_nearest_agent(self):
        env={**self.chain(),'CLAUDECODE':'1','CLAUDE_CODE_SESSION_ID':'inherited','GROK_SESSION_ID':'inherited'}
        with self.scope():
            evidence=D.discover(self.p.transport)
            caller=C.identify(pid=100,environ=env,evidence=evidence)
            self.assertIsNotNone(caller.endpoint)
            self.assertEqual(caller.endpoint.ref.native_id,uuid(1))
            self.assertTrue(caller.agent_env)
            self.k.processes[201]=(*self.k.processes[201][:4],'claude.exe')
            refused=C.identify(pid=100,environ=env,evidence=evidence)
            self.assertIsNone(refused.endpoint); self.assertFalse(refused.is_user_shell)
            self.k.processes[201]=(*self.k.processes[201][:4],'pwsh.exe')
            self.k.processes[200]=(*self.k.processes[200][:4],'claude.exe')
            refused=C.identify(pid=100,environ=env,evidence=evidence)
            self.assertIsNone(refused.endpoint); self.assertFalse(refused.is_user_shell)
            self.assertEqual(C.identify(pid=100,environ={**env,'CODEX_SESSION_ID':uuid(2)},evidence=evidence).rejection,'subagent')

    def test_state_directory_repair_is_private_and_persistently_observed(self):
        self.state.mkdir()
        other=bytes.fromhex('010100000000000100000000')
        self.k.files[str(self.state)]={'protected':False,'aces':[(0,0x10,0x1f01ff,other)]}
        with self.scope(), self.assertLogs('agentstatus_bridge.platforms.windows.files',level='WARNING') as log:
            error=None
            try:self.p.files.ensure_private_dir(self.state)
            except OSError as exc:error=exc
            self.assertIsNone(error)
            with self.k.api.owned(self.k.api.open_file(str(self.state),directory=True)) as h:
                error=None
                try:self.k.api.check_private(h,protected=True)
                except OSError as exc:error=exc
                self.assertIsNone(error)
            meta=self.k.files[str(self.state)]
            self.assertEqual(meta['aces'],[(0,3,0x1f01ff,self.k.sid),(0,3,0x1f01ff,bytes.fromhex('010100000000000512000000'))])
            self.assertTrue(meta['protected'])
            self.assertTrue(WindowsPaths(self.k.api).acl_observation())
            checks=doctor.collect_checks()
            self.assertTrue(checks['privateAclRepairObserved'])
            output=io.StringIO()
            with redirect_stdout(output):doctor.print_checks(checks)
            self.assertIn('privateAclRepairObserved',output.getvalue())
        self.assertNotIn(str(self.state),repr(log.output))

    def test_private_read_repairs_but_external_does_not(self):
        self.state.mkdir(); path=self.state/'receipt'; path.write_bytes(b'fixture')
        with self.scope():
            for kind in ('own','external'):
                self.k.files[str(path)]={'private':False}
                before=sum(n=='SetSecurityInfo' for n,_ in self.k.calls)
                error=None
                try:
                    with pinned_file(self.p.files,path,external=kind=='external'):pass
                except OSError as exc:error=exc
                if kind=='own':
                    self.assertIsNone(error)
                    self.assertTrue(self.p.files.acl_observation())
                    self.assertGreater(sum(n=='SetSecurityInfo' for n,_ in self.k.calls),before)
                else:
                    self.assertIsInstance(error,OSError)
                    self.assertEqual(sum(n=='SetSecurityInfo' for n,_ in self.k.calls),before)

    def test_owner_reparse_hardlink_and_repair_failure_never_mutate(self):
        self.state.mkdir(); path=self.state/'receipt'; path.write_bytes(b'old')
        other=bytes.fromhex('01010000000000052b000000')
        with self.scope():
            for case in ('owner','reparse','hardlink'):
                self.k.files[str(path)]={'private':False, **({'owner':other} if case=='owner' else {'reparse':True} if case=='reparse' else {})}
                extra=self.state/'link'
                if case=='hardlink': os.link(path,extra)
                before=sum(n=='SetSecurityInfo' for n,_ in self.k.calls)
                error=None
                try:self.p.files.validate_file(path)
                except OSError as exc:error=exc
                self.assertIsInstance(error,OSError,case)
                if case=='owner':self.assertEqual(error.args,('windows_owner_mismatch',))
                self.assertEqual(sum(n=='SetSecurityInfo' for n,_ in self.k.calls),before)
                self.assertEqual(path.read_bytes(),b'old')
                if extra.exists():extra.unlink()
            self.k.files[str(path)]={'private':False}; self.k.faults['SetSecurityInfo']=5
            with self.assertRaises(OSError) as caught:self.p.files.validate_file(path)
            self.assertEqual(caught.exception.winerror,5)
            self.assertFalse(self.k.files[str(path)]['private'])

    def test_atomic_replace_ignores_old_acl_and_owner_but_not_links(self):
        self.state.mkdir(); path=self.state/'summary.json'; path.write_bytes(b'old')
        with self.scope():
            self.k.files[str(path)]={'private':False}
            before=path.stat().st_ino
            error=None
            try:self.p.files.atomic_write(self.state,b'new',name=path.name,prefix='.test.')
            except OSError as exc:error=exc
            self.assertIsNone(error)
            self.assertEqual(path.read_bytes(),b'new');self.assertNotEqual(path.stat().st_ino,before)
            self.assertTrue(self.k.files[str(path)]['private'])
            self.assertFalse(any(n=='SetSecurityInfo' for n,_ in self.k.calls))
            self.k.files[str(path)]={'owner':bytes.fromhex('01020000000000052000000020020000')}
            error=None
            try:self.p.files.atomic_write(self.state,b'new-owner',name=path.name,prefix='.test.')
            except OSError as exc:error=exc
            self.assertIsNone(error)
            self.assertEqual(path.read_bytes(),b'new-owner')
            self.assertIsNone(self.k.files[str(path)].get('owner'))
            for case in ('reparse','hardlink'):
                self.k.files[str(path)]={'reparse':case=='reparse'}
                extra=self.state/'link'
                if case=='hardlink':os.link(path,extra)
                with self.assertRaises(OSError):self.p.files.atomic_write(self.state,b'wrong',name=path.name,prefix='.test.')
                self.assertEqual(path.read_bytes(),b'new-owner')
                if extra.exists():extra.unlink()

    def test_repair_reopen_identity_race_is_rejected_before_setsecurity(self):
        self.state.mkdir();path=self.state/'receipt';path.touch()
        self.k.files[str(path)]={'private':False}
        original=self.k.api.file_info
        for field in ('links','index_low','attributes'):
            def raced(h,**kwargs):
                result=original(h,**kwargs)
                if self.k.record(h)['access'] & 0x40000:
                    setattr(result,field,getattr(result,field)+1)
                return result
            with self.scope(),patch.object(self.k.api,'file_info',side_effect=raced):
                error=None
                try:self.p.files.validate_file(path)
                except OSError as exc:error=exc
                self.assertIsInstance(error,OSError,field)
                self.assertFalse(any(n=='SetSecurityInfo' for n,_ in self.k.calls))

    def test_directory_repair_propagates_and_keeps_identity_checks(self):
        self.state.mkdir();child=self.state/'hardlink-child';child.touch()
        outside=self.root/'outside';os.link(child,outside)
        meta={'private':False,'protected':False,'aces':[]}
        self.k.files[str(child)]=meta.copy();self.k.files[str(outside)]=meta.copy()
        protected=self.state/'protected';protected.touch()
        self.k.files[str(protected)]={'private':False,'protected':True,'aces':[]}
        with self.scope():
            self.k.files[str(self.state)]={'protected':False}
            self.assertEqual(self.p.files.ensure_private_dir(self.state),self.state)
            inherited=self.k.files[str(child)]['aces']
            self.assertEqual(inherited,[(0,16,0x1f01ff,self.k.sid),
                (0,16,0x1f01ff,bytes.fromhex('010100000000000512000000'))])
            self.assertEqual(self.k.files[str(outside)]['aces'],inherited)
            self.assertEqual(self.k.files[str(protected)]['aces'],[])
            self.assertTrue(any(n=='CreateFileW' and args[1]&0x40000 and args[2]==7 for n,args in self.k.calls))
            original=self.k.api.file_info
            for stage in ('before','after'):
                self.k.files[str(self.state)]={'protected':False}
                count=0;sets=sum(n=='SetSecurityInfo' for n,_ in self.k.calls)
                def race(h,**kwargs):
                    nonlocal count
                    record=self.k.record(h);info=original(h,**kwargs)
                    if record['path']==str(self.state):
                        if record['access']&0x40000:count+=1
                        if ((stage=='before' and record['access']&0x40000)
                                or (stage=='after' and count and not record['access']&0x40000)):info.index_low+=1
                    return info
                with patch.object(self.k.api,'file_info',side_effect=race):
                    error=None
                    try:self.p.files.ensure_private_dir(self.state)
                    except OSError as exc:error=exc
                    self.assertIsInstance(error,OSError,stage)
                self.assertEqual(sum(n=='SetSecurityInfo' for n,_ in self.k.calls)-sets,0 if stage=='before' else 1)
                self.assertEqual(self.k.handles,{})

    def test_external_directory_access_denied_never_self_heals(self):
        self.k.files[str(self.home)]={'private':False,'protected':False,'deny_data':True}
        with self.scope():
            for context in (self.p.files.external_directory(self.home), self.p.files.lease(self.home,external=True)):
                before=sum(n=='SetSecurityInfo' for n,_ in self.k.calls)
                with self.assertRaises(OSError) as caught:
                    with context:pass
                self.assertEqual(caught.exception.winerror,5)
                self.assertEqual(sum(n=='SetSecurityInfo' for n,_ in self.k.calls),before)
                self.assertTrue(self.k.files[str(self.home)]['deny_data'])

    def test_metadata_only_share_zero_is_not_an_exclusive_data_lock(self):
        self.state.mkdir()
        api=self.k.api
        with self.scope(), api.owned(api.open_file(str(self.state),directory=True)):
            error=None
            try:
                with api.owned(api.open_file(str(self.state),directory=True,metadata_only=True,write_dac=True,sharing=0)):
                    with api.owned(api.open_file(str(self.state),directory=True)):pass
            except OSError as exc:error=exc
            self.assertIsNone(error)
        with self.scope(), api.owned(api.open_file(str(self.state),directory=True,sharing=0)):
            with self.assertRaises(OSError) as caught:api.open_file(str(self.state),directory=True)
            self.assertEqual(caught.exception.winerror,32)

    def test_owner_denied_data_rights_can_repair_without_metadata_bypass(self):
        self.state.mkdir()
        with self.scope():
            self.k.files[str(self.state)]={'private':False,'deny_data':True}
            error=None
            try:self.p.files.ensure_private_dir(self.state)
            except OSError as exc:error=exc
            self.assertIsNone(error)
            self.assertFalse(self.k.files[str(self.state)]['deny_data'])
            path=self.state/'private';path.touch()
            for operation in ('read','database','lock'):
                self.k.files[str(path)]={'private':False,'deny_data':True}
                error=None
                try:
                    if operation=='read':
                        with pinned_file(self.p.files,path):pass
                    elif operation=='database':self.p.files.prepare_database(path)
                    else:
                        h=self.p.lifecycle.open_lock(path);self.p.lifecycle.close_lock(h)
                except OSError as exc:error=exc
                self.assertIsNone(error,operation)
                self.assertFalse(self.k.files[str(path)]['deny_data'])
            self.k.files[str(path)]={'private':False,'deny_data':True,'owner':bytes.fromhex('01010000000000052b000000')}
            before=sum(n=='SetSecurityInfo' for n,_ in self.k.calls)
            with self.assertRaisesRegex(OSError,'windows_owner_mismatch'):
                with pinned_file(self.p.files,path):pass
            self.assertEqual(sum(n=='SetSecurityInfo' for n,_ in self.k.calls),before)
            self.assertEqual(self.k.handles,{})
            for code in (6,32):
                with patch.object(self.k.api,'open_file',side_effect=WinFailure(code)) as opened:
                    with self.assertRaises(OSError):self.p.files.open_private_file(path,read_data=True)
                    self.assertEqual(opened.call_count,1)

    def test_both_spawns_request_breakaway_and_fallback_only_once_on_five(self):
        binary=self.root/'python.exe';binary.touch();self.state.mkdir()
        with self.scope(),patch.object(W,'executable',return_value=binary),patch.object(W,'verify',return_value={}):
            for fixture in (False,True):
                for failures in ([],[5],[5,5],[6],[87]):
                    seen=[]
                    def popen(argv,**kw):
                        seen.append((kw['creationflags'],dict(kw['env'])))
                        if len(seen)<=len(failures):raise WinFailure(failures[len(seen)-1])
                        return Mock(pid=100)
                    error=None
                    with patch('subprocess.Popen',side_effect=popen):
                        try:
                            if fixture:self.p.lifecycle.spawn_fixture(binary,self.state)
                            else:self.p.lifecycle.spawn_worker(self.state,{})
                        except OSError as exc:error=exc
                    self.assertEqual([x[0] for x in seen],[0x1000208,0x208] if failures and failures[0]==5 else [0x1000208])
                    self.assertEqual(seen[0][1][W.BREAKAWAY_ENV],'requested')
                    if len(seen)==2:self.assertEqual(seen[1][1][W.BREAKAWAY_ENV],'denied_fallback')
                    self.assertEqual(error is None,failures in ([],[5]))

    def test_worker_receipt_reports_job_observation_not_authorization(self):
        binary=self.root/'python.exe';binary.touch();self.k.images[100]=str(binary)
        with self.scope(),patch.object(W,'executable',return_value=binary):
            for in_job,requested,expected in ((False,'requested','granted'),(True,'requested','requested'),(True,'denied_fallback','denied_fallback')):
                self.k.in_job=in_job
                with patch.dict(os.environ,{W.BREAKAWAY_ENV:requested}):W.register(self.p.files,self.state)
                result=W.verify(self.p.files,self.state)
                self.assertIs(result['inJob'],in_job)
                self.assertEqual(result['breakaway'],expected)
                self.assertEqual(W.diagnostic(self.p.files,self.state)['breakaway'],expected)
                self.assertFalse(result['context']['outlivesJob'])


if __name__=='__main__':unittest.main()
