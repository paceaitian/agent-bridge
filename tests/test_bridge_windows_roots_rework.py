"""§84 审计反例的正式见证；所有 Windows 调用均使用 SDK Fake。"""
from contextlib import contextmanager
from dataclasses import FrozenInstanceError, replace
import json
import os
from pathlib import Path
import unittest
from unittest.mock import Mock, patch

import test_bridge_windows_roots as base
from test_bridge_windows_claude import BIRTH, UUID
from agentstatus_bridge.model import Delivery
from agentstatus_bridge.transports import DeliveryContext
from agentstatus_bridge.transports import claude_windows as T
from agentstatus_bridge.transports.codex_native import NativeFailure
from agentstatus_bridge.platforms.windows import claude_auth as A, claude_discovery as D, claude_peer as P, commands
from agentstatus_bridge.platforms.claude_roots import environment_config, MAX_ENV_BYTES


class ReworkTests(unittest.TestCase):
    setUp = base.MultiRootTests.setUp
    write = base.MultiRootTests.write
    roots = base.MultiRootTests.roots
    second = base.MultiRootTests.second

    def test_r1_other_surrogate_does_not_hide_value_and_lowercase_key_works(self):
        self.roots()
        self.k.environments[200] = ('OTHER=x'.encode('utf-16-le') + b'\x00\xd8\0\0' +
            ('claude_config_dir='+str(self.sessions.parent)+'\0\0').encode('utf-16-le'))
        value = self.k.api.claude_config_dir(200,BIRTH)
        self.assertEqual(value.state,'value'); self.assertEqual(value.value,str(self.sessions.parent))
        found=D.discover(self.p.transport,connect=False)
        self.assertTrue(found.complete); self.assertEqual(len(found.endpoints),1)

    def test_unknown_value_duplicate_and_oversize_are_not_absent(self):
        self.roots()
        for raw in (b'CLAUDE_CONFIG_DIR=\0', b'x'*(MAX_ENV_BYTES+2)):
            self.assertEqual(environment_config(raw,windows=True).state,'unknown')
        for raw in (('CLAUDE_CONFIG_DIR='+str(self.sessions.parent)+'\0') .encode('utf-16-le')*2+b'\0\0',
                    'CLAUDE_CONFIG_DIR='.encode('utf-16-le')+b'\x00\xd8\0\0\0\0'):
            with self.subTest(raw_length=len(raw)):
                self.k.environments[200]=raw
                self.assertEqual(self.k.api.claude_config_dir(200,BIRTH).state,'unknown')
                scan=self.p.files.claude_sessions_dirs()
                self.assertIn(200,scan.unlocated)
                self.assertFalse(D.discover(self.p.transport,connect=False).complete)
        self.assertEqual(environment_config('OTHER=x\0\0'.encode('utf-16-le'),windows=True).state,'absent')

    def test_a01_environment_exception_args_and_str_are_content_free(self):
        self.roots()
        self.k.environments[200]=('PRIVATE-ENV-SENTINEL='+'x'*MAX_ENV_BYTES).encode('utf-16-le')
        with self.assertRaises(OSError) as caught:
            self.k.api.claude_config_dir(200,BIRTH)
        self.assertEqual(caught.exception.args,('claude_environment_limit',))
        self.assertEqual(str(caught.exception),'claude_environment_limit')

    def test_r2_unrelated_unreadable_root_does_not_block_known_peer_name(self):
        self.roots()
        junk=self.root/'.rec/claude/accounts/999/config'; junk.mkdir(parents=True)
        (junk/'sessions').write_text('not a directory')
        found=D.discover(self.p.transport,connect=False)
        self.assertTrue(found.complete)
        self.assertEqual(found.select('claude@fixture-peer').ref.pid,200)
        self.assertIn('unreadable',[r['reason'] for r in found.registries])
        self.k.faults['ReadProcessMemory']=5
        self.assertFalse(D.discover(self.p.transport,connect=False).complete)

    def test_r4_fallback_error_keeps_roots_discovery_and_real_inbox(self):
        self.roots(); accounts=self.root/'.rec/claude/accounts'; accounts.mkdir(parents=True)
        original=self.p.files.external_directory
        @contextmanager
        def guarded(path):
            if path==accounts: raise OSError('windows_reparse_unsupported')
            with original(path) as identity: yield identity
        thread=Mock(is_alive=Mock(return_value=False))
        with patch.object(self.p.files,'external_directory',guarded), \
                patch.object(P.threading,'Thread',return_value=thread), patch.object(self.k.api.k,'CancelIoEx',return_value=1):
            try:
                scan=self.p.files.claude_sessions_dirs()
            except OSError as error:
                self.fail(f'fallback failure escaped root scan: {error}')
            self.assertIn(self.sessions,scan.roots)
            self.assertIn((accounts,'fallback_unavailable'),scan.diagnostics)
            self.assertTrue(D.discover(self.p.transport,connect=False).complete)
            box=P.Inbox(self.p.files); box.open(); box.close()

    def test_a04_a05_fallback_is_fixed_depth_and_entry_bounded(self):
        self.roots(); accounts=self.root/'.rec/claude/accounts'; accounts.mkdir(parents=True)
        deep=accounts/'outer/inner/config/sessions'; deep.mkdir(parents=True)
        self.assertNotIn(deep,self.p.files.claude_sessions_dirs().roots)
        # Non-directory entries cannot evade the enumeration budget.
        for n in range(150): (accounts/f'file-{n:03}').touch()
        original=Path.iterdir; seen=[]
        def entries(path):
            for entry in original(path):
                if path==accounts: seen.append(entry)
                yield entry
        with patch.object(Path,'iterdir',entries): scan=self.p.files.claude_sessions_dirs()
        self.assertLessEqual(len(seen),129)
        self.assertIn((accounts,'fallback_limit'),scan.diagnostics)
        self.assertIn(self.sessions,scan.roots)
        self.assertTrue(D.discover(self.p.transport,connect=False).complete)

    def test_a06_process_snapshot_failure_is_not_complete_and_scan_is_immutable(self):
        self.roots(); os.environ['CLAUDE_CONFIG_DIR']=str(self.sessions.parent)
        with patch.object(self.k.api,'process_table',side_effect=OSError('fixture snapshot')):
            scan=self.p.files.claude_sessions_dirs()
            self.assertFalse(scan.complete)
            with self.assertRaises(FrozenInstanceError): scan.complete=True
            found=D.discover(self.p.transport,connect=False)
            self.assertFalse(found.complete); self.assertEqual(len(found.endpoints),1)
        later=self.p.files.claude_sessions_dirs()
        self.assertTrue(later.complete); self.assertFalse(scan.complete)

    def test_r6_noninteractive_without_generation_does_not_locate_live_pid(self):
        self.roots(); self.k.faults['ReadProcessMemory']=5
        stale=self.root/'.rec/claude/accounts/old/config/sessions'; stale.mkdir(parents=True)
        record={k:v for k,v in self.record.items() if k!='procStartFt'}
        (stale/'200.json').write_text(json.dumps({**record,'kind':'subagent'}))
        found=D.discover(self.p.transport,connect=False)
        self.assertFalse(found.complete); self.assertEqual(found.endpoints,())

    def test_r5_task_checks_scan_once_and_cache_each_root(self):
        self.roots(); self.second()
        refs=[D.inspect(self.p.transport,pid,connect=False)[0].ref for pid in (200,300)]
        command=Mock(action='report',evidence=Mock(root_identity=None))
        original=self.p.files.claude_sessions_dirs
        with patch.object(self.p.files,'claude_sessions_dirs',wraps=original) as scan, \
                patch.object(commands,'_current',Mock(get=Mock(return_value=command))):
            try:
                commands.check_task(Mock(origin=refs[0],reviewer=refs[1]),[Mock(target=refs[n%2]) for n in range(60)])
            except Exception as error:
                self.fail(f'two valid pinned roots must pass: {type(error).__name__}')
        self.assertEqual(scan.call_count,1)

    def test_real_inbox_registration_precedes_connection_and_no_scan_in_frame_window(self):
        self.roots(); second=self.second(); ep=D.inspect(self.p.transport,300,connect=False)[0]
        thread=Mock(is_alive=Mock(return_value=True))
        thread.join.side_effect=lambda seconds:setattr(thread.is_alive,'return_value',False)
        box=P.Inbox(self.p.files); window=False; scans=[]
        original=self.p.files.claude_sessions_dirs
        def scan(*args,**kwargs):
            self.assertFalse(window,'discovery while target pipe is connected')
            scans.append(1); return original(*args,**kwargs)
        def opened(path):
            nonlocal window
            self.assertTrue((second/A.key_name(100,str(box.path))).exists(),'target-root key absent before open')
            window=True; return 9
        def closed(handle):
            nonlocal window
            window=False
        io=Mock(open_pipe=opened,close_pipe=closed,peer_pid=Mock(return_value=300),
                pipe_io=Mock(side_effect=lambda h,op,data,deadline:len(data)))
        with patch.object(P.threading,'Thread',return_value=thread), patch.object(self.k.api.k,'CancelIoEx',return_value=1), \
                patch.object(self.p.files,'claude_sessions_dirs',scan):
            box.open()
            try:
                with patch.object(T,'WinIO',return_value=io):
                    outcome=T.Transport(self.p.transport,lambda:box).deliver(ep,'fixture',DeliveryContext(UUID,'fixture',reply_to=box.address))
                self.assertEqual(outcome.delivery,Delivery.WRITTEN)
                self.assertIn(UUID,box._expected)
            finally: box.close()
        self.assertGreater(len(scans),0)

    def test_a11_close_cleans_other_keys_after_first_cleanup_failure(self):
        self.roots(); second=self.second(); found=D.discover(self.p.transport,connect=False)
        thread=Mock(is_alive=Mock(return_value=False)); box=P.Inbox(self.p.files)
        with patch.object(P.threading,'Thread',return_value=thread), patch.object(self.k.api.k,'CancelIoEx',return_value=1):
            box.open()
            with patch.object(box,'healthy',return_value=True):
                for ep in found.endpoints: box.register(A.PeerFiles.from_root(self.p.files,ep.ref.data_root),ep.ref.data_root)
            keys=list(box._keys.values()); self.assertEqual(len(keys),2)
            with patch.object(keys[0],'close',side_effect=OSError('cleanup_fixture')):
                with self.assertRaisesRegex(OSError,'cleanup_fixture'): box.close()
            self.assertFalse((second/keys[1].name).exists())
            keys[0].close()

    def test_empty_override_is_unset_and_relative_values_cannot_expand_user(self):
        self.roots(); os.environ['AB_CLAUDE_SESSIONS_DIR']=''
        self.assertEqual(len(D.discover(self.p.transport,connect=False).endpoints),1)
        self.k.environments[200]='CLAUDE_CONFIG_DIR=~unknown-user/cfg\0\0'.encode('utf-16-le')
        scan=self.p.files.claude_sessions_dirs()
        self.assertIn(200,scan.unlocated); self.assertNotIn(Path('~unknown-user/cfg/sessions'),scan.roots)

    def test_n1_located_missing_default_or_configured_root_keeps_names_usable(self):
        self.roots()
        for config in (None,self.root/'never-created'):
            with self.subTest(configured=config is not None):
                self.k.processes[400]=(0,int(BIRTH)+400,self.k.sid,False,'claude.exe')
                self.k.images[400]=r'C:\fixture\claude.exe'
                value='OTHER=fixture' if config is None else 'CLAUDE_CONFIG_DIR='+str(config)
                self.k.environments[400]=(value+'\0\0').encode('utf-16-le')
                missing=(config or self.root/'.claude')/'sessions'
                self.assertFalse(missing.exists())
                found=D.discover(self.p.transport,connect=False)
                self.assertTrue(found.complete)
                self.assertEqual(found.select('claude@fixture-peer').ref.pid,200)
                self.assertIn({'path':str(missing),'readable':False,'reason':'not_found'},found.registries)
        original=self.k.api.claude_config_dir
        def read(pid,birth):
            if pid==400: raise OSError('fixture_peb_unreadable')
            return original(pid,birth)
        with patch.object(self.k.api,'claude_config_dir',read):
            found=D.discover(self.p.transport,connect=False)
            self.assertFalse(found.complete)
            with self.assertRaisesRegex(NativeFailure,'claude_discovery_incomplete'):
                found.select('claude@fixture-peer')

    def test_n3_corrupt_or_unreadable_stale_record_uses_other_located_root(self):
        self.roots()
        stale=self.root/'.rec/claude/accounts/old/config/sessions'; stale.mkdir(parents=True)
        (stale/'200.json').write_text('{broken fixture')
        found=D.discover(self.p.transport,connect=False)
        self.assertTrue(found.complete)
        self.assertEqual(found.select('claude@fixture-peer').ref.pid,200)
        original=A.PeerFiles.read
        def read(files,name,**kwargs):
            if files.sessions==stale: raise PermissionError('fixture_record_unreadable')
            return original(files,name,**kwargs)
        with patch.object(A.PeerFiles,'read',read):
            self.assertTrue(D.discover(self.p.transport,connect=False).complete)
        # 当前根中的损坏记录、或 PEB 未定位时的旧记录，仍不能忽略。
        with patch.object(A.PeerFiles,'read',side_effect=OSError('fixture_record_unreadable')):
            self.assertFalse(D.discover(self.p.transport,connect=False).complete)
        self.k.faults['ReadProcessMemory']=5
        self.assertFalse(D.discover(self.p.transport,connect=False).complete)

    def test_n2_check_task_rejects_wrong_root_after_valid_root(self):
        self.roots()
        ref=D.inspect(self.p.transport,200,connect=False)[0].ref
        bad=replace(ref,data_root='0'*64)
        command=Mock(action='report',evidence=Mock(root_identity=None))
        with patch.object(commands,'_current',Mock(get=Mock(return_value=command))):
            with self.assertRaisesRegex(NativeFailure,'target_root_changed'):
                commands.check_task(Mock(origin=ref,reviewer=None),[Mock(target=ref),Mock(target=bad)])
