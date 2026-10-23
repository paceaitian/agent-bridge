"""Multi-root W3 on SDK Fake, including environment privacy and reply registration."""
from dataclasses import replace
import json
import os
from pathlib import Path
import unittest
from unittest.mock import Mock, patch

import test_bridge_windows_claude as fixtures
from test_bridge_windows_claude import PIPE, UUID, BIRTH, TOKEN
from agentstatus_bridge.platforms.windows import claude_auth as A, claude_discovery as D, claude_peer as P
from agentstatus_bridge.platforms.windows import caller, commands
from agentstatus_bridge.transports import claude_windows as T, DeliveryContext
from agentstatus_bridge.model import Delivery
from agentstatus_bridge import doctor


class MultiRootTests(unittest.TestCase):
    setUp=fixtures.NativeTests.setUp
    write=fixtures.NativeTests.write

    def roots(self):
        self.enterContext(patch.dict(os.environ))
        os.environ.pop('AB_CLAUDE_SESSIONS_DIR',None); os.environ.pop('CLAUDE_CONFIG_DIR',None)
        self.enterContext(patch.object(Path,'home',return_value=self.root))
        self.k.environments[200]=('SECRET=NEVER-RETURN\0CLAUDE_CONFIG_DIR='+str(self.sessions.parent)+'\0\0').encode('utf-16-le')

    def second(self):
        path=self.root/'second/sessions'; path.mkdir(parents=True)
        birth=str(int(BIRTH)+9)
        self.k.processes[300]=(0,int(birth),self.k.sid,False,'claude.exe')
        self.k.images[300]=r'C:\fixture\claude.exe'
        self.k.environments[300]=('CLAUDE_CONFIG_DIR='+str(path.parent)+'\0\0').encode('utf-16-le')
        record={**self.record,'pid':300,'procStartFt':birth,'sessionId':UUID[:-1]+'2','messagingSocketPath':PIPE[:-1]+'e'}
        (path/'300.json').write_text(json.dumps(record))
        (path/A.key_name(300,record['messagingSocketPath'])).write_text(json.dumps({'peerToken':TOKEN,'procStartFt':birth}))
        return path

    def test_peb_only_returns_config_and_cross_environment_multi_root_discovery(self):
        self.roots(); second=self.second()
        self.assertEqual(self.k.api.claude_config_dir(200,BIRTH).value,str(self.sessions.parent))
        found=D.discover(self.p.transport,connect=False)
        self.assertTrue(found.complete); self.assertEqual({e.ref.pid for e in found.endpoints},{200,300})
        self.assertEqual(len({e.ref.data_root for e in found.endpoints}),2)
        self.assertEqual(D.inspect(self.p.transport,300,connect=False)[0].ref.pid,300)
        self.assertNotIn('NEVER-RETURN',repr(found))
        self.assertNotIn('SECRET',repr(found))
        projection=doctor.registry_checks(list(found.registries))
        self.assertEqual(projection['claudeRegistryCount'],2)
        for ep in found.endpoints:
            files=A.PeerFiles.from_root(self.p.files,ep.ref.data_root)
            self.assertIn(files.sessions,(self.sessions,second))

    def test_peb_failure_falls_back_to_bounded_reclaude_layout(self):
        self.roots()
        fallback=self.root/'.rec/claude/accounts/123/config/sessions'
        fallback.mkdir(parents=True)
        (fallback/'200.json').write_text(json.dumps(self.record))
        self.k.faults['ReadProcessMemory']=5
        found=D.discover(self.p.transport,connect=False)
        self.assertTrue(found.complete); self.assertEqual(len(found.endpoints),1)
        self.assertEqual(A.PeerFiles.from_root(self.p.files,found.endpoints[0].ref.data_root).sessions,fallback)

    def test_override_omits_peb_and_fallback_even_with_multiple_accounts(self):
        self.roots(); self.second()
        os.environ['AB_CLAUDE_SESSIONS_DIR']=str(self.sessions)
        with patch.object(self.k.api,'process_table',side_effect=AssertionError('host enumeration')):
            found=D.discover(self.p.transport,connect=False)
        self.assertEqual([e.ref.pid for e in found.endpoints],[200])

    def test_unlocated_live_process_is_not_complete_empty_or_target_gone(self):
        self.roots()
        self.k.faults['ReadProcessMemory']=5
        found=D.discover(self.p.transport,connect=False)
        self.assertFalse(found.complete); self.assertEqual(found.endpoints,())
        self.k.processes.pop(200)
        self.assertTrue(D.discover(self.p.transport,connect=False).complete)

    def test_peb_failure_known_noninteractive_is_complete_but_stale_record_is_not(self):
        self.roots()
        fallback=self.root/'.rec/claude/accounts/123/config/sessions'; fallback.mkdir(parents=True)
        record={**self.record,'kind':'subagent'}
        (fallback/'200.json').write_text(json.dumps(record))
        self.k.faults['ReadProcessMemory']=5
        found=D.discover(self.p.transport,connect=False)
        self.assertTrue(found.complete); self.assertEqual(found.endpoints,())
        (fallback/'200.json').write_text(json.dumps({**record,'procStartFt':'1'}))
        self.assertFalse(D.discover(self.p.transport,connect=False).complete)

    def test_environment_change_and_partial_reads_are_not_accepted(self):
        self.roots()
        with patch.object(self.k.api.k,'ReadProcessMemory',return_value=1):
            with self.assertRaisesRegex(OSError,'partial'): self.k.api.claude_config_dir(200,BIRTH)
        self.k.environments[200]=b'x\0'* (1024*1024)
        with self.assertRaisesRegex(OSError,'limit'): self.k.api.claude_config_dir(200,BIRTH)

    def test_changed_root_does_not_select_first_other_account_or_create_external_roots(self):
        self.roots(); self.second()
        before={p for p in self.root.rglob('*')}
        with self.assertRaisesRegex(OSError,'root_changed'): A.PeerFiles.from_root(self.p.files,'wrong-root')
        self.assertEqual(before,{p for p in self.root.rglob('*')})

    def test_duplicate_pid_uses_matching_generation_and_budget_is_shared(self):
        self.roots(); second=self.second()
        (second/'200.json').write_text(json.dumps({**self.record,'procStartFt':'1'}))
        found=D.discover(self.p.transport,connect=False)
        self.assertTrue(found.complete); self.assertEqual(len(found.endpoints),2)
        self.assertEqual(D.inspect(self.p.transport,200,connect=False)[0].ref.pid,200)
        with patch.object(D,'MAX_RECORDS',3):
            self.assertFalse(D.discover(self.p.transport,connect=False).complete)

    def test_wrong_identity_image_or_generation_never_reads_environment(self):
        self.roots()
        for change in ('image','birth','sid'):
            with self.subTest(change=change), patch.dict(self.k.processes), patch.dict(self.k.images):
                if change=='image': self.k.images[200]=r'C:\fixture\other.exe'
                if change=='birth': self.k.processes[200]=(0,1,self.k.sid,False,'claude.exe')
                if change=='sid': self.k.processes[200]=(0,int(BIRTH),b'foreign',False,'claude.exe')
                before=len([c for c in self.k.calls if c[0]=='ReadProcessMemory'])
                with self.assertRaises(OSError): self.k.api.claude_config_dir(200,BIRTH)
                self.assertEqual(before,len([c for c in self.k.calls if c[0]=='ReadProcessMemory']))

    def test_reply_registration_in_each_target_root_and_cleanup_all(self):
        self.roots(); second=self.second()
        found=D.discover(self.p.transport,connect=False)
        box=P.Inbox(self.p.files); thread=Mock(is_alive=Mock(return_value=False))
        with patch.object(P.threading,'Thread',return_value=thread), patch.object(box,'healthy',return_value=True), \
                patch.object(self.k.api.k,'CancelIoEx',return_value=1):
            box.open()
            for ep in found.endpoints:
                box.register(A.PeerFiles.from_root(self.p.files,ep.ref.data_root),ep.ref.data_root)
                box.expect(ep,ep.ref.native_id)
            name=A.key_name(100,str(box.path))
            paths=[self.sessions/name,second/name]
            self.assertTrue(all(p.exists() for p in paths))
            self.assertEqual(paths[0].read_bytes(),paths[1].read_bytes())
            box.close()
            self.assertTrue(all(not p.exists() for p in paths))
        self.assertTrue((second/'300.json').exists())

    def test_inbox_skips_unwritable_legacy_root_without_repair(self):
        self.roots(); second=self.second()
        original=A.OwnKey.publish
        def publish(key):
            if key.files.sessions==self.sessions: raise PermissionError('fixture-root-unwritable')
            return original(key)
        box=P.Inbox(self.p.files); thread=Mock(is_alive=Mock(return_value=False))
        with patch.object(A.OwnKey,'publish',publish), patch.object(P.threading,'Thread',return_value=thread), \
                patch.object(self.k.api.k,'CancelIoEx',return_value=1):
            try:
                box.open()
            except OSError as error:
                if error.args != ('claude_inbox_unavailable',):
                    raise
                self.fail('a second writable root must keep the inbox available')
            name=A.key_name(100,str(box.path))
            self.assertFalse((self.sessions/name).exists())
            self.assertTrue((second/name).exists())
            box.close()
            self.assertFalse((second/name).exists())
        self.assertFalse(any(name=='SetSecurityInfo' for name,_ in self.k.calls))

    def test_transport_and_task_checks_select_pinned_root_not_first_root(self):
        self.roots(); second=self.second()
        ep=D.inspect(self.p.transport,300,connect=False)[0]
        inbox=Mock(spec=P.Inbox,healthy=Mock(return_value=True),address='fixture:reply')
        io=Mock(open_pipe=Mock(return_value=9),peer_pid=Mock(return_value=300),
                pipe_io=Mock(side_effect=lambda h,op,data,deadline:len(data)))
        with patch.object(T,'WinIO',return_value=io):
            outcome=T.Transport(self.p.transport,lambda:inbox).deliver(ep,'fixture',DeliveryContext(UUID,'fixture',reply_to=inbox.address))
        self.assertEqual(outcome.delivery,Delivery.WRITTEN)
        self.assertEqual(outcome.native_root,ep.ref.data_root)
        inbox.expect.assert_called_once_with(ep,UUID)
        command=Mock(action='report',evidence=Mock(root_identity=None))
        task=Mock(origin=D.inspect(self.p.transport,200,connect=False)[0].ref,reviewer=None)
        with patch.object(commands,'_current',Mock(get=Mock(return_value=command))):
            commands.check_task(task,[Mock(target=ep.ref)])
        self.assertTrue((second/'300.json').exists())
