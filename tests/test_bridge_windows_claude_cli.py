"""Real CLI/ledger with native SDK identities; worker spawn and all IPC are fixtures."""
from contextlib import redirect_stdout, redirect_stderr
import io
import json
import os
import time
import unittest
from unittest.mock import patch

import test_bridge_windows_claude as fixture
from bridge_platform_guard import windows_fixture
from agentstatus_bridge import cli
from agentstatus_bridge.model import Delivery, Provider, Role
from agentstatus_bridge.store import Store
from agentstatus_bridge.platforms.windows import commands
from agentstatus_bridge.platforms.windows.io import WinIO


class CliTests(unittest.TestCase):
    setUp = fixture.NativeTests.setUp
    write = fixture.NativeTests.write

    def command(self, *args):
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            code = cli.main(list(args))
        return code, out.getvalue(), err.getvalue()

    def test_native_claude_send_report_accept_exact_cli_path(self):
        other = '019a0000-0000-7000-8000-000000000002'
        pipe = r'\\.\pipe\LOCAL\cc-msg-' + '2'*32
        self.k.processes[300] = (0,int(fixture.BIRTH)+500,self.k.sid,False,'claude.exe')
        self.k.images[300] = r'C:\fixture\claude.exe'
        self.write('300.json',{**self.record,'pid':300,'sessionId':other,'messagingSocketPath':pipe,
                               'procStartFt':str(int(fixture.BIRTH)+500),'name':'other'})
        def peer(handle, **kw):
            return 300 if self.k.record(handle)['path'] == pipe else 200
        state = self.root/'state'
        with (windows_fixture('pipe',pipe), patch.object(WinIO,'peer_pid',side_effect=peer),
              patch.object(commands,'sample',return_value=commands.Discovery()),
              patch('os.getpid',return_value=100), patch.dict(os.environ,{'AB_STATE_DIR':str(state)}),
              patch.object(cli,'_start_worker',return_value=False), patch.object(cli,'_worker_up',return_value=False),
              patch.object(cli,'_ensure_worker',return_value=False)):
            code,out,err=self.command('send','--to','claude@id:'+other,'-m','fixture','--no-wait','--json')
            self.assertEqual(code,6,(out,err))  # persisted, explicitly not a running worker
            with Store.open(state) as store:
                tasks=store.list_tasks(); self.assertEqual(len(tasks),1)
                task=tasks[0]; attempt=store.attempts(task.id)[0]
                self.assertEqual(task.origin.native_id,fixture.UUID)
                self.assertEqual(task.options['receiptMode'],'push')
                self.assertIs(attempt.target.provider,Provider.CLAUDE)
                stamp=time.time()
                self.assertTrue(store.begin_send(attempt.id,now=stamp,pid=100,start_ticks='win-filetime:'+str(int(fixture.BIRTH)+1000)))
                store.finish_send(attempt.id,delivery=Delivery.DELIVERED,reason='fixture',provider_ref=None,
                                  detail={},now=stamp,native_root=attempt.target.data_root)
            current=self.k.processes[100]
            self.k.processes[100]=(300,*current[1:])
            code,out,err=self.command('report',task.id,'--result','--note','fixture','--json')
            self.assertIn(code,(0,6),(out,err))
            with Store.open(state) as store:
                attempts=store.attempts(task.id)
                self.assertEqual(len(attempts),2)
                self.assertIs(attempts[1].role,Role.NOTICE)
                self.assertEqual(attempts[1].target.native_id,fixture.UUID)
            code,_,_=self.command('accept',task.id,'--json')
            self.assertEqual(code,3)  # B is not the originating session.
            self.k.processes[100]=current
            code,out,err=self.command('accept',task.id,'--json')
            self.assertIn(code,(0,6),(out,err))
            with Store.open(state) as store:
                self.assertIsNotNone(store.get_task(task.id).accepted_at)
                self.assertTrue(any(a.is_closure for a in store.attempts(task.id)))

    def test_same_session_reporter_must_wait_for_original_receiver_to_exit(self):
        from agentstatus_bridge.platforms.windows import claude_discovery as D
        received, _ = D.inspect(self.p.transport, 200)
        pipe = r'\\.\pipe\LOCAL\cc-msg-' + '3'*32
        self.k.processes[300] = (0, int(fixture.BIRTH)+500, self.k.sid, False, 'claude.exe')
        self.k.images[300] = r'C:\fixture\claude.exe'
        self.write('300.json', {**self.record, 'pid': 300, 'messagingSocketPath': pipe,
                               'procStartFt': str(int(fixture.BIRTH)+500)})
        row = self.k.processes[100]; self.k.processes[100] = (300, *row[1:])
        def peer(handle, **kw): return 300 if self.k.record(handle)['path'] == pipe else 200
        with (windows_fixture('pipe', pipe), patch.object(WinIO, 'peer_pid', side_effect=peer),
              patch('os.getpid', return_value=100),
              patch.object(cli, '_start_worker', return_value=False), patch.object(cli, '_worker_up', return_value=False),
              patch.object(cli, '_ensure_worker', return_value=False)):
            original_query = self.k.api.process
            for original in ('alive', 'gone', 'reused', 'unknown'):
                state = self.root / original
                self.k.processes[200] = (0, int(fixture.BIRTH), self.k.sid, False, 'claude.exe')
                with patch.dict(os.environ, {'AB_STATE_DIR': str(state)}):
                    from agentstatus_bridge.model import Flow
                    with Store.open(state) as store:
                        stamp = time.time()
                        task, attempt = store.create_task(title='fixture', flow=Flow.HANDOFF, origin=None,
                            origin_class=None, reviewer=None, target=received.ref, body='fixture', refs=[], now=stamp)
                        store.begin_send(attempt.id, now=stamp, pid=100, start_ticks='win-filetime:'+str(int(fixture.BIRTH)+1000))
                        store.finish_send(attempt.id, delivery=Delivery.DELIVERED, reason='fixture', provider_ref=None,
                            detail={'deliveredPid': 200, 'deliveredStart': received.ref.start_ticks}, now=stamp,
                            native_root=received.ref.data_root)
                    if original == 'gone': self.k.processes.pop(200)
                    if original == 'reused': self.k.processes[200] = (0, int(fixture.BIRTH)+1, self.k.sid, False, 'claude.exe')
                    def query(pid, **kwargs):
                        if original == 'unknown' and pid == 200:
                            raise OSError('fixture_unknown')
                        return original_query(pid, **kwargs)
                    with patch.object(self.k.api, 'process', side_effect=query):
                        code, out, err = self.command('report', task.id, '--result', '--note', 'fixture', '--json')
                    if original in ('alive', 'unknown'):
                        self.assertEqual(code, 3, (out, err))
                        self.assertIn('reporter_generation_mismatch' if original == 'alive' else 'reporter_unattributed', out+err)
                    else:
                        self.assertEqual(code, 0, (out, err))
                    with Store.open(state) as store:
                        self.assertEqual(store.get_attempt(attempt.id).work.value == 'result_submitted', original in ('gone', 'reused'))


class MixedCliTests(unittest.TestCase):
    # Real Codex RPC/SQL SDK fixture plus the real Claude registry/caller code.
    from test_bridge_windows_delivery import DeliveryTests as _Fixture
    setUp = _Fixture.setUp
    rebuild = _Fixture.rebuild
    scope = _Fixture.scope
    chain = _Fixture.chain
    command = CliTests.command

    def prepare(self):
        self.sessions = self.root / 'claude' / 'sessions'; self.sessions.mkdir(parents=True)
        self.pipe = r'\\.\pipe\LOCAL\cc-msg-' + '4'*32
        self.k.processes[300] = (0, int(fixture.BIRTH)+10, self.k.sid, False, 'claude.exe')
        self.k.images[300] = r'C:\fixture\claude.exe'
        (self.sessions / '300.json').write_text(json.dumps({'pid': 300, 'sessionId': fixture.UUID,
            'peerProtocol': 1, 'kind': 'interactive', 'messagingSocketPath': self.pipe,
            'procStartFt': str(int(fixture.BIRTH)+10), 'name': 'claude-test'}))
        original = WinIO.peer_pid
        self.enterContext(patch.object(WinIO, 'peer_pid', lambda io, handle, **kw:
                          300 if kw.get('pipe') else original(io, handle, **kw)))
        self.enterContext(patch.object(self.p.files, 'claude_sessions_dir', return_value=self.sessions))
        self.enterContext(windows_fixture('pipe', self.pipe))
        self.enterContext(patch('os.getpid', return_value=100))
        self.enterContext(patch.object(cli, '_start_worker', return_value=False))
        self.enterContext(patch.object(cli, '_worker_up', return_value=False))
        self.enterContext(patch.object(cli, '_ensure_worker', return_value=False))
        self.enterContext(patch.object(cli, '_revive_worker'))
        return self.chain()

    def become(self, provider, thread=None):
        from test_bridge_windows_discovery import uuid
        row = self.k.processes[100]
        self.k.processes[100] = (300 if provider == 'claude' else 201, *row[1:])
        os.environ['CODEX_THREAD_ID'] = os.environ['CODEX_SESSION_ID'] = thread or uuid(1)

    def mark_sent(self, attempt):
        with Store.open(self.state) as store:
            stamp = time.time()
            store.begin_send(attempt.id, now=stamp, pid=100, start_ticks='win-filetime:'+str(self.k.processes[100][1]))
            store.finish_send(attempt.id, delivery=Delivery.DELIVERED, reason='fixture', provider_ref=None,
                detail={}, now=stamp, native_root=attempt.target.data_root)

    def test_codex_claude_bidirectional_cli_result_and_accept(self):
        from test_bridge_windows_discovery import uuid
        with self.scope():
            env = self.prepare()
            with patch.dict(os.environ, env):
                for origin, target in (('codex', 'claude'), ('claude', 'codex')):
                    self.become(origin)
                    selector = 'claude@id:'+fixture.UUID if target == 'claude' else 'codex@id:'+uuid(1)
                    code, out, err = self.command('send', '--to', selector, '-m', 'fixture', '--no-wait', '--json')
                    self.assertEqual(code, 6, (out, err))
                    with Store.open(self.state) as store:
                        task = store.list_tasks()[0]; attempt = store.attempts(task.id)[0]
                        self.assertEqual(task.origin.provider.value, origin)
                        self.assertEqual(attempt.target.provider.value, target)
                    self.mark_sent(attempt); self.become(target)
                    code, out, err = self.command('report', task.id, '--result', '--note', 'fixture', '--json')
                    self.assertIn(code, (0, 6), (out, err))
                    with Store.open(self.state) as store:
                        self.assertEqual(store.attempts(task.id)[-1].target.provider.value, origin)
                    self.become(origin)
                    code, out, err = self.command('accept', task.id, '--json')
                    self.assertIn(code, (0, 6), (out, err))
                    with Store.open(self.state) as store: self.assertIsNotNone(store.get_task(task.id).accepted_at)

    def test_claude_reviewer_changes_retry_and_approve_cli(self):
        from test_bridge_windows_discovery import uuid
        with self.scope():
            env = self.prepare(); self.k.loaded = [uuid(1), uuid(2)]
            with patch.dict(os.environ, env):
                code, out, err = self.command('send', '--to', 'codex@id:'+uuid(2), '--review-by',
                    'claude@id:'+fixture.UUID, '-m', 'fixture', '--no-wait', '--json')
                self.assertEqual(code, 6, (out, err))
                with Store.open(self.state) as store: task = store.list_tasks()[0]
                for verdict in ('changes', 'approve'):
                    with Store.open(self.state) as store:
                        attempt = [a for a in store.attempts(task.id) if a.role is Role.HANDOFF][-1]
                    self.mark_sent(attempt); self.become('codex', uuid(2))
                    code, out, err = self.command('report', task.id, '--result', '--note', 'fixture', '--json')
                    self.assertIn(code, (0, 6), (out, err))
                    with Store.open(self.state) as store:
                        review = [a for a in store.attempts(task.id) if a.role is Role.REVIEW][-1]
                        self.assertIs(review.target.provider, Provider.CLAUDE)
                    self.mark_sent(review); self.become('claude')
                    code, out, err = self.command('report', task.id, '--'+verdict, '--note', 'fixture', '--json')
                    self.assertIn(code, (0, 6), (out, err))
                    self.become('codex', uuid(1))
                    action = ('retry', task.id, '-m', 'fixture') if verdict == 'changes' else ('accept', task.id, '--json')
                    code, out, err = self.command(*action)
                    self.assertIn(code, (0, 6), (out, err))
                with Store.open(self.state) as store:
                    self.assertIsNotNone(store.get_task(task.id).accepted_at)
                    self.assertEqual(sum(a.role is Role.REVIEW for a in store.attempts(task.id)), 2)


if __name__ == '__main__': unittest.main()
