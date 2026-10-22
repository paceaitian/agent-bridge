"""W2-4 SDK/codec/local-SQL evidence only, never a real Windows provider."""
from contextlib import closing, redirect_stdout, redirect_stderr
from dataclasses import replace
import io
import json
import os
from pathlib import Path
import sqlite3
import sys
import subprocess
import random
import statistics
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch, Mock

import bridge_support
import bridge_winapi_sdk as SDK
import ctypes
import test_bridge_windows_discovery as F
import test_bridge_windows_callers as CF
from test_bridge_windows_discovery import uuid
from agentstatus_bridge import cli, worker
from agentstatus_bridge.dispatch import Dispatcher
from agentstatus_bridge.model import Delivery, Consumption, Flow, Provider, EndpointRef
from agentstatus_bridge.store import Store, StoreError
from agentstatus_bridge.transports import DeliveryContext, DeliveryOutcome
from agentstatus_bridge.transports.codex_native import NativeFailure
from agentstatus_bridge.transports.websocket import _Timeout
from agentstatus_bridge.platforms.factory import make_platform, using_platform
from agentstatus_bridge.platforms.windows import codex_discovery as D, codex_delivery as T
from agentstatus_bridge.platforms.windows import codex_consumption as Q, commands as B, stdio
from agentstatus_bridge.platforms.windows import worker_identity as W
from agentstatus_bridge.platforms.windows.target_aliases import AliasFile, AliasSet


class QueueKernel(F.LoadedKernel):
    def __init__(self, root, home):
        super().__init__(root, home)
        self.add_reply = None
        self.after_add = None

    def send(self, handle, buf, size, flags):
        before = len(self.messages)
        count = super().send(handle, buf, size, flags)
        for message in self.messages[before:]:
            if message['method'] != 'thread/queue/add':
                continue
            params = message['params']
            reply = {'id': message['id'], 'result': {'queuedSubmission': {
                'id': uuid(900), 'clientUserMessageId': params['clientUserMessageId'],
                'input': params['input']}}}
            self.socket_in.extend(self.frame(self.add_reply(message, reply) if self.add_reply else reply))
            if self.after_add:
                self.after_add()
        return count


class NamingTests(unittest.TestCase):
    def test_empty_review_scope_no_attribution_or_sampling(self):
        from agentstatus_bridge.platforms.windows import caller
        for value in ('',' ','\t','　'):
            args=SimpleNamespace(command='send',to=uuid(1),review_by=value)
            with patch.object(caller,'identify',side_effect=AssertionError('attributed before rejecting empty reviewer')) as identify,\
                 patch.object(B,'sample',side_effect=AssertionError('sampled before rejecting empty reviewer')) as sample:
                with self.assertRaisesRegex(NativeFailure,'target_explicit_required'):
                    with B.scope(args):pass
                identify.assert_not_called()
                sample.assert_not_called()

    def result(self):
        return D.Discovery((D.Candidate(uuid(1),'root',name='原生甲',cwd_label='project-a',names_verified=True),
                            D.Candidate(uuid(2),'root',name='原生乙',cwd_label='project-b',names_verified=True)),
                           True,'complete','a'*64,(200,'100'))

    def test_names_precedence_roundtrip_ambiguity_and_no_autoselection(self):
        result=self.result()
        self.assertEqual(result.select('codex@原生甲').thread,uuid(1))
        self.assertEqual(result.select('project-b').thread,uuid(2))
        self.assertEqual(result.target_name(result.rows[0]),'codex@原生甲')
        self.assertEqual(result.endpoint(result.rows[0]).ref.label,'原生甲')
        prefixed=replace(result,rows=(replace(result.rows[0],name='codex@named'),result.rows[1]))
        self.assertEqual(prefixed.target_name(prefixed.rows[0]),'codex@codex@named')
        self.assertEqual(prefixed.select('codex@codex@named').thread,uuid(1))
        collision=replace(result,rows=(result.rows[0],replace(result.rows[1],cwd_label='原生甲')))
        with self.assertRaisesRegex(NativeFailure,'target_ambiguous'):collision.select('原生甲')
        result=replace(result,rows=(replace(result.rows[0],name='work'),result.rows[1]),aliases=AliasSet({'work':uuid(2)}))
        error=None;chosen=None
        try:chosen=result.select('work')
        except NativeFailure as failure:error=failure.reason
        self.assertIsNone(error)
        self.assertEqual(chosen.thread,uuid(2))
        self.assertEqual(result.target_name(result.rows[0]),'codex@project-a')
        repeated=replace(self.result(),rows=tuple(replace(r,name='same',cwd_label='same') for r in self.result().rows))
        with self.assertRaisesRegex(NativeFailure,'target_ambiguous'):repeated.select('same')
        for row in repeated.rows:
            self.assertEqual(repeated.select(repeated.target_name(row)).thread,row.thread)
        with self.assertRaisesRegex(NativeFailure,'target_explicit_required'):result.select(None)
        with self.assertRaisesRegex(NativeFailure,'target_ambiguous'):result.select('00000000')
        failure=None;chosen=None
        try:chosen=result.select('id:'+uuid(1))
        except NativeFailure as error:failure=error.reason
        self.assertIsNone(failure)
        self.assertEqual(chosen.thread,uuid(1))

    def test_incomplete_names_nonroots_and_control_collisions(self):
        result=self.result()
        for bad in (D.Candidate(uuid(3),'unknown',metadata_verified=False),
                    D.Candidate(uuid(3),'root',names_verified=False)):
            incomplete=replace(result,rows=result.rows+(bad,))
            with self.assertRaisesRegex(NativeFailure,'target_names_unverified'):incomplete.select('原生甲')
            self.assertEqual(incomplete.select(uuid(1)).thread,uuid(1))
        child=replace(result,rows=(replace(result.rows[0],kind='subagent'),result.rows[1]))
        with self.assertRaisesRegex(NativeFailure,'target_not_found'):child.select('原生甲')
        escaped=D.display_label({'name':'x\x1b\ud800','cwd':'C:\\private\\project'})
        self.assertEqual(escaped,'x\\u001b\\ud800')
        self.assertEqual(D.display_label({'name':'','cwd':'C:\\private\\project'}),'project')
        long='x'*96
        collided=replace(result,rows=tuple(replace(r,name=D.display_label({'name':long+str(i)})) for i,r in enumerate(result.rows)))
        with self.assertRaisesRegex(NativeFailure,'target_ambiguous'):collided.select(long)

    def test_root_participates_in_identity_but_label_never_does(self):
        ref=self.result().endpoint(self.result().rows[0]).ref
        self.assertTrue(ref.same_session(replace(ref,label='changed')))
        self.assertFalse(ref.same_session(replace(ref,data_root='b'*64)))
        self.assertFalse(ref.same_session(replace(ref,data_root=None)))
        self.assertEqual(EndpointRef.from_json(ref.to_json()),ref)
        self.assertNotIn('dataRoot',replace(ref,data_root=None).to_dict())
        self.assertEqual(self.result().endpoint(self.result().rows[0]).consumers,0)

    def test_command_reuses_one_discovery_before_store(self):
        before=self.result()
        with (patch.object(B,'evidence',return_value=before),patch.object(B,'sample',side_effect=AssertionError('resampled')),
              patch.object(B,'claude_evidence',return_value=B.claude.Discovery(complete=True,reason='complete'))):
            selected=B.resolve('原生甲')
            self.assertEqual(selected.ref.native_id,uuid(1))
            self.assertEqual(selected.ref.data_root,before.root_identity)
            self.assertEqual(selected.ref.pid,before.daemon[0])

    def test_output_utf8_surrogates_short_writes_and_closed_pipe(self):
        raw=io.BytesIO()
        legacy=io.TextIOWrapper(raw,encoding='cp1252')
        output=stdio.Output(legacy)
        value='中文😀\ud800\n'
        self.assertEqual(output.write(value),len(value))
        output.flush()
        self.assertEqual(raw.getvalue(),'中文😀\\ud800\n'.encode('utf-8'))
        self.assertFalse(raw.getvalue().startswith(b'\xef\xbb\xbf'))
        class Pipe:
            def write(self,b):raise BrokenPipeError()
            def flush(self):raise BrokenPipeError()
        closed=stdio.Output(SimpleNamespace(buffer=Pipe(),flush=Pipe().flush))
        error=None;written=None
        try:written=closed.write('result committed')
        except OSError as failure:error=failure
        self.assertIsNone(error)
        self.assertEqual(written,16)
        self.assertTrue(closed.failed)
        self.assertEqual(closed.write(value),len(value))
        closed.flush()
        collected=bytearray()
        class Short:
            def write(self,b):collected.extend(b[:1]);return 1
        short=stdio.Output(SimpleNamespace(buffer=Short(),flush=lambda:None))
        short.write('中文')
        self.assertEqual(bytes(collected),'中文'.encode('utf-8'))
        zero=stdio.Output(SimpleNamespace(buffer=SimpleNamespace(write=lambda _:0),flush=lambda:None))
        error=None
        try:zero.write('result')
        except OSError as failure:error=failure
        self.assertIsNone(error)
        self.assertTrue(zero.failed)

    def test_closed_os_pipe_keeps_success_at_interpreter_shutdown(self):
        source='''import os,sys,io
from agentstatus_bridge.platforms.windows.stdio import output_scope
r,w=os.pipe();os.close(r)
sys.stdout=io.TextIOWrapper(os.fdopen(w,'wb'),encoding='cp1252')
with output_scope():
 print('committed 中文😀')
raise SystemExit(0)
'''
        done=subprocess.run([sys.executable,'-c',source],stdout=subprocess.PIPE,stderr=subprocess.PIPE,
                            env=dict(os.environ,PYTHONPATH=str(Path(__file__).resolve().parents[1]/'src')),timeout=10)
        self.assertEqual(done.returncode,0,done.stderr)
        self.assertEqual(done.stdout,b'')

    def test_output_scope_restores_healthy_stream_and_main_installs_it(self):
        p=make_platform('windows',win_api=object())
        raw=io.BytesIO();old=io.TextIOWrapper(raw,encoding='cp1252')
        def handled(_args):
            print(json.dumps({'result':'中文😀\ud800'},ensure_ascii=False))
            return 0
        error=None;code=None
        with using_platform(p),redirect_stdout(old),patch.object(cli,'_run_command',side_effect=handled):
            try:code=cli.main(['alias','list','--json'])
            except UnicodeError as failure:error=failure
            self.assertIs(sys.stdout,old)
        self.assertIsNone(error)
        self.assertEqual(code,0)
        self.assertEqual(json.loads(raw.getvalue().decode('utf-8')),{'result':'中文😀\ud800'})


class DeliveryTests(unittest.TestCase):
    setUp=F.DiscoveryTests.setUp
    scope=F.DiscoveryTests.scope
    sql=F.DiscoveryTests.sql
    discover=F.DiscoveryTests.discover
    run_cli=CF.CallerTests.run_cli
    chain=CF.CallerTests.chain

    def rebuild(self):
        self.k=QueueKernel(self.root,self.home)
        self.k.files[str(self.home)]={'private':False,'protected':False}
        self.k.files[str(self.socket)]={'reparse':True,'tag':0x80000023}
        self.k.processes[200]=(0,134362090000012230,self.k.sid,False,'codex.exe')
        self.k.peer=200
        self.p=make_platform('windows',win_api=self.k.api)

    def target(self):
        result=D.discover(self.p.transport)
        self.assertTrue(result.complete)
        return result.endpoint(result.select(uuid(1)))

    def deliver(self,target,**kw):
        return T.CodexTransport().deliver(target,'中文😀 synthetic',DeliveryContext(uuid(700),'fixture',**kw))

    def adds(self):
        return [m for m in self.k.messages if m['method']=='thread/queue/add']

    def test_add_codec_boundary_evidence_and_no_fallback(self):
        with self.scope():
            target=self.target();calls=[]
            result=self.deliver(target,before_send=lambda:calls.append('boundary'))
            self.assertIs(result.delivery,Delivery.QUEUED)
            self.assertEqual(result.provider_ref,uuid(900))
            self.assertEqual(result.native_root,target.ref.data_root)
            self.assertEqual(result.detail,{'queueChannel':'rpc','codexVersion':'0.162.1',
                                           'serverVersion':'0.162.1','queueOutput':'recognized'})
            self.assertEqual(calls,['boundary'])
            self.assertEqual(self.adds()[0]['params'],{'threadId':uuid(1),
                'input':[{'type':'text','text':'中文😀 synthetic','text_elements':[]}], 'clientUserMessageId':uuid(700)})
            self.assertEqual(bytes(self.k.http).split(b'\r\n')[0],b'GET /rpc HTTP/1.1')
            self.assertNotIn(b'/daemon/shutdown',self.k.socket_out)
            self.assertTrue(all(m['method'] in {'initialize','initialized','thread/loaded/list','thread/read','thread/queue/add'} for m in self.k.messages))
            self.assertNotIn('synthetic',repr(result))

    def test_add_versions_are_observations_without_cli_fallback(self):
        for cli_version, server in (('0.163.0', '0.163.0'), ('0.162.1', 'unparseable'), (None, '0.163.0')):
            with self.subTest(cli=cli_version, server=server):
                self.rebuild()
                self.k.server_version = server
                with self.scope(version=cli_version):
                    target = self.target()
                    boundaries = []
                    result = self.deliver(target, before_send=lambda: boundaries.append('sending'))
                self.assertIs(result.delivery, Delivery.QUEUED)
                self.assertEqual(result.provider_ref, uuid(900))
                self.assertEqual(boundaries, ['sending'])
                self.assertEqual(len(self.adds()), 1)
                self.assertEqual(result.detail['codexVersion'], cli_version or 'unknown')
                self.assertEqual(result.detail['serverVersion'], server if server == '0.163.0' else 'unknown')
                self.assertTrue(all(m['params']['clientInfo']['version'] == (cli_version or 'unknown')
                                    for m in self.k.messages if m['method'] == 'initialize'))

    def test_prewrite_unload_generation_root_subagent_and_boundary_errors(self):
        for mode in ('unload','generation','root','child','boundary','busy','deadline'):
            with self.subTest(mode=mode):
                self.rebuild()
                with self.scope():
                    target=self.target()
                    if mode=='unload':self.k.loaded=[]
                    if mode=='generation':self.k.processes[200]=(0,999,self.k.sid,False,'codex.exe')
                    if mode=='root':target=replace(target,ref=replace(target.ref,data_root='b'*64))
                    if mode=='child':self.k.metadata[uuid(1)]={'id':uuid(1),'source':{'subAgent':'review'}}
                    def boundary():
                        if mode in ('boundary','busy'):raise StoreError('store_busy' if mode=='busy' else 'store_error')
                        if mode=='deadline':raise _Timeout()
                    result=self.deliver(target,before_send=boundary)
                    self.assertIs(result.delivery,Delivery.FAILED,result)
                    self.assertEqual(len(self.adds()),0)
                    self.assertIsNone(result.native_root)
                    if mode=='busy':self.assertEqual(result.reason,'boundary_store_busy')
                    if mode=='boundary':self.assertEqual(result.reason,'boundary_record_failed')
        self.rebuild()
        with self.scope():
            target=self.target();self.k.messages.clear()
            with patch.object(T,'TOTAL_SECONDS',0):result=self.deliver(target)
            self.assertIs(result.delivery,Delivery.FAILED)
            self.assertEqual(result.reason,'codex_deadline_before_send')
            self.assertEqual(self.k.messages,[])

    def test_response_unknown_errors_echo_peer_and_server_request(self):
        for mode in ('echo','id','storage','peer','request','refused'):
            with self.subTest(mode=mode):
                self.rebuild()
                with self.scope():
                    target=self.target()
                    def reply(m,r):
                        if mode=='echo':r['result']['queuedSubmission']['clientUserMessageId']=uuid(701)
                        if mode=='id':r['result']['queuedSubmission']['id']='bad'
                        if mode=='storage':return {'id':m['id'],'error':{'code':-32603,'message':'queued submission operation failed'}}
                        if mode=='request':return {'id':88,'method':'approval'}
                        if mode=='refused':return {'id':m['id'],'error':{'code':-32001,'message':'Server overloaded'}}
                        return r
                    self.k.add_reply=reply
                    if mode=='peer':self.k.after_add=lambda:self.k.processes.update({200:(0,999,self.k.sid,False,'codex.exe')})
                    result=self.deliver(target)
                    self.assertIs(result.delivery,Delivery.FAILED if mode=='refused' else Delivery.UNKNOWN)
                    self.assertEqual(len(self.adds()),1)
                    self.assertFalse(any(m.get('id')==88 for m in self.k.messages))
                    self.assertIsNone(result.native_root)

    def test_budget_after_boundary_and_before_server_requests(self):
        self.assertEqual(T.TOTAL_SECONDS,600.0)
        with self.scope():
            target=self.target();now=[1000.0];calls=[]
            def boundary():calls.append(1);now[0]=1601.0
            with patch.object(T.time,'monotonic',side_effect=lambda:now[0]):
                result=self.deliver(target,before_send=boundary)
            self.assertIs(result.delivery,Delivery.FAILED)
            self.assertEqual(result.reason,'codex_deadline_before_send')
            self.assertEqual(calls,[1])
            self.assertEqual(self.adds(),[])
        self.rebuild()
        with self.scope():
            target=self.target()
            self.k.override=lambda m,r:{'id':88,'method':'approval'}
            result=self.deliver(target)
            self.assertIs(result.delivery,Delivery.FAILED)
            self.assertEqual(self.adds(),[])
            self.assertFalse(any(m.get('id')==88 for m in self.k.messages))

    def test_each_loaded_snapshot_and_payload_limit_block_add(self):
        for mode in ('initial','final','size'):
            self.rebuild()
            with self.scope():
                target=self.target()
                if mode=='initial':self.k.loaded=[]
                def alter(m):
                    if m['method']=='thread/loaded/list':
                        self.k.loaded=[uuid(1)] if mode=='initial' else []
                if mode!='size':self.k.after=alter
                result=(T.CodexTransport().deliver(target,'x'*(1024*1024+1),DeliveryContext(uuid(700),'fixture'))
                        if mode=='size' else self.deliver(target))
                self.assertIs(result.delivery,Delivery.FAILED,result)
                self.assertEqual(self.adds(),[])
                if mode=='size':self.assertEqual(result.reason,'provider_payload_too_large')

    def test_sql_names_alias_across_generation_and_send_one_snapshot(self):
        path=self.sql([(uuid(1),'cli')])
        with closing(sqlite3.connect(path)) as db, db:
            db.execute('UPDATE threads SET name=?,cwd=?',('原生任务',r'C:\private\project'))
        with self.scope():
            result=D.discover(self.p.transport)
            self.assertEqual(result.document()['peers'][0]['target'],'codex@原生任务')
            self.assertEqual(result.select('原生任务').thread,uuid(1))
            self.assertEqual(result.select('project').thread,uuid(1))
            self.assertFalse(any(m['method']=='thread/read' for m in self.k.messages))
            self.assertEqual(self.run_cli('alias','set','work',uuid(1))[0],0)
            row=json.loads((self.state/'target-aliases/codex.json').read_bytes())['aliases'][0]
            self.assertEqual(set(row),{'alias','threadId','rootIdentity'})
            self.k.processes[200]=(0,999,self.k.sid,False,'codex.exe')
            failure=None;selected=None
            try:selected=D.discover(self.p.transport).select('work')
            except NativeFailure as error:failure=error.reason
            self.assertIsNone(failure)
            self.assertEqual(selected.thread,uuid(1))
            old=D.discover(self.p.transport)
            fresh=replace(old,rows=(replace(old.rows[0],name='changed'),))
            with patch.object(B,'evidence',return_value=old),patch.object(B,'sample',return_value=fresh) as sampled:
                self.assertEqual(B.resolve('原生任务').ref.native_id,uuid(1))
                sampled.assert_not_called()
            self.k.loaded=[]
            with self.assertRaisesRegex(NativeFailure,'alias_target_unavailable'):D.discover(self.p.transport).select('work')

    def test_alias_home_identity_independent_of_sqlite_location(self):
        other=self.root/'sql-only';other.mkdir()
        with self.scope():
            self.assertEqual(self.run_cli('alias','set','work',uuid(1))[0],0)
            old=D.discover(self.p.transport)
        with self.scope(sql_root=other):
            new=D.discover(self.p.transport)
            self.assertNotEqual(new.root_identity,old.root_identity)
            self.assertEqual(new.home_identity,old.home_identity)
            failure=None;chosen=None
            try:chosen=new.select('work')
            except NativeFailure as error:failure=error.reason
            self.assertIsNone(failure)
            self.assertEqual(chosen.thread,uuid(1))

    def test_legacy_names_use_native_without_reading_first_message_title(self):
        path=self.sql([(uuid(1),'cli')])
        with closing(sqlite3.connect(path)) as db, db:
            db.execute("UPDATE threads SET history_mode='legacy',name='stale',cwd='private/full/path'")
        self.k.metadata[uuid(1)]={'id':uuid(1),'source':'cli','name':'Native legacy name','cwd':'C:\\private\\leaf'}
        trace=[];connect=sqlite3.connect
        def opened(database,**kw):
            db=connect(database,**kw);db.set_trace_callback(trace.append);return db
        with self.scope(),patch.object(sqlite3,'connect',opened):
            result=D.discover(self.p.transport)
            self.assertEqual(result.document()['peers'][0]['target'],'codex@Native legacy name')
            self.assertTrue(result.names_complete)
            self.assertEqual(sum(m['method']=='thread/read' for m in self.k.messages),1)
            self.assertFalse(any('title' in s.lower() or 'preview' in s.lower() for s in trace))
            self.assertNotIn('private',json.dumps(result.document()))
        with closing(sqlite3.connect(path)) as db, db:db.execute("UPDATE threads SET history_mode='future'")
        with self.scope():
            result=D.discover(self.p.transport)
            self.assertEqual(result.document()['peers'][0]['target'],'codex@Native legacy name')

    def test_incomplete_name_budget_does_not_invent_name_uniqueness(self):
        self.k.loaded=[uuid(1),uuid(2)]
        path=self.sql([(t,'cli') for t in self.k.loaded])
        with closing(sqlite3.connect(path)) as db, db:db.execute("UPDATE threads SET history_mode='legacy',name='untrusted-sql'")
        self.k.metadata[uuid(2)]={'id':uuid(2),'source':'cli','name':'Known name'}
        with self.scope(),patch.object(D,'MAX_IDS',1):
            result=D.discover(self.p.transport)
            self.assertTrue(result.complete)
            self.assertFalse(result.document()['namingComplete'])
            self.assertFalse(result.document()['peers'][0]['nameVerified'])
            with self.assertRaisesRegex(NativeFailure,'target_names_unverified'):result.select('Known name')
            self.assertEqual(result.select(uuid(1)).thread,uuid(1))
            self.assertEqual(sum(m['method']=='thread/read' for m in self.k.messages),1)

    def test_bad_native_name_type_is_unknown_not_proved_absent(self):
        self.k.loaded=[uuid(1),uuid(2)]
        self.k.metadata[uuid(1)]={'id':uuid(1),'source':'cli','name':42}
        self.k.metadata[uuid(2)]={'id':uuid(2),'source':'cli','name':'Known name'}
        with self.scope():
            result=D.discover(self.p.transport)
            self.assertTrue(result.complete)
            self.assertFalse(result.names_complete)
            self.assertFalse(result.rows[0].names_verified)
            with self.assertRaisesRegex(NativeFailure,'target_names_unverified'):result.select('Known name')
            self.assertEqual(result.select(uuid(1)).thread,uuid(1))

    def test_empty_complete_loaded_set_expires_pending_but_failure_does_not(self):
        with self.scope(),Store.open(self.state) as store:
            target=self.target();now=[1000.0]
            task,attempt=store.create_task(title='fixture',flow=Flow.HANDOFF,origin=None,origin_class=None,
                reviewer=None,target=target.ref,body='fixture',refs=[],now=now[0])
            sampler=D.WorkerDiscovery(self.p.transport)
            self.k.loaded=[]
            dispatcher=Dispatcher(store,sampler,{Provider.CODEX:T.CodexTransport()},clock=lambda:now[0],
                                  empty_discovery_complete=sampler.complete)
            dispatcher.run_once()
            self.assertTrue(sampler.complete())
            self.assertIs(store.get_attempt(attempt.id).delivery,Delivery.PENDING)
            now[0]+=16;dispatcher.run_once()
            self.assertIs(store.get_attempt(attempt.id).delivery,Delivery.FAILED)
            self.assertEqual(store.get_attempt(attempt.id).delivery_reason,'target_gone')
            _,attempt2=store.create_task(title='fixture',flow=Flow.HANDOFF,origin=None,origin_class=None,
                reviewer=None,target=target.ref,body='fixture',refs=[],now=now[0])
            self.k.override=lambda m,r:{'id':m['id'],'error':{}}
            now[0]+=16;dispatcher.run_once();now[0]+=16;dispatcher.run_once()
            self.assertFalse(sampler.complete())
            self.assertIs(store.get_attempt(attempt2.id).delivery,Delivery.PENDING)
            self.k.override=None
            self.k.loaded=[uuid(1)]
            self.k.metadata[uuid(1)]={'id':uuid(1),'source':'future-unknown'}
            now[0]+=16;dispatcher.run_once();now[0]+=16;dispatcher.run_once()
            self.assertTrue(sampler.result.complete)
            self.assertFalse(sampler.complete())  # no eligible rows is not proof of absence
            self.assertIs(store.get_attempt(attempt2.id).delivery,Delivery.PENDING)
            self.assertEqual(self.adds(),[])

    def test_consumption_only_count_in_same_pinned_readonly_database(self):
        with self.scope(),Store.open(self.state) as store:
            target=self.target()
            task,attempt=store.create_task(title='fixture',flow=Flow.HANDOFF,origin=None,origin_class=None,
                reviewer=None,target=target.ref,body='fixture',refs=[],now=1000)
            attempt=replace(attempt,provider_ref=uuid(900),options={'codexDataRoot':target.ref.data_root})
            path=self.home/'queue_1.sqlite'
            with closing(sqlite3.connect(path)) as db, db:
                db.executescript('CREATE TABLE queued_items(id TEXT PRIMARY KEY,input TEXT);')
                db.execute('INSERT INTO queued_items VALUES (?,?)',(uuid(900),'DO_NOT_READ'))
            trace=[];original=sqlite3.connect;calls=[]
            def connect(database,**kw):
                calls.append((database,kw));db=original(database,**kw);db.set_trace_callback(trace.append);return db
            with patch.object(Q.sqlite3,'connect',connect):self.assertIs(Q.state(attempt),Consumption.STILL_QUEUED)
            self.assertTrue(calls[0][1]['uri'])
            self.assertTrue(calls[0][0].endswith('queue_1.sqlite?mode=ro'))
            self.assertEqual(len([s for s in trace if s.startswith('SELECT')]),1)
            self.assertTrue(trace[-1].startswith('SELECT COUNT(*) FROM queued_items WHERE id = '))
            self.assertIn('PRAGMA query_only=ON',trace)
            self.assertFalse(any('input' in s for s in trace))
            with closing(sqlite3.connect(path)) as db, db:db.execute('DELETE FROM queued_items')
            self.assertIs(Q.state(attempt),Consumption.LEFT_QUEUE)
            self.assertIs(Q.state(replace(attempt,options={})),Consumption.UNKNOWN)
            self.assertIs(Q.state(replace(attempt,options={'codexDataRoot':'b'*64})),Consumption.UNKNOWN)
            with patch.object(Q.sqlite3,'connect',wraps=sqlite3.connect) as opened:
                self.assertIs(Q.state(replace(attempt,options={'codexDataRoot':'b'*64},target=replace(attempt.target,data_root='b'*64))),Consumption.UNKNOWN)
                self.assertEqual(opened.call_count,0)  # reject a different root before any queue read
            self.assertIs(Q.state(replace(attempt,target=replace(attempt.target,data_root='b'*64))),Consumption.UNKNOWN)
            self.assertIs(Q.state(replace(attempt,provider_ref='bad')),Consumption.UNKNOWN)
            self.k.files[str(path)]={'reparse':True}
            self.assertIs(Q.state(attempt),Consumption.UNKNOWN)
            self.assertFalse(any(m['method']=='thread/queue/list' for m in self.k.messages))

    def test_dispatch_unknown_never_retries_and_boundary_is_persisted(self):
        with self.scope(),patch('agentstatus_bridge.dispatch.os.getpid',return_value=100),Store.open(self.state) as store:
            target=self.target()
            task,attempt=store.create_task(title='fixture',flow=Flow.HANDOFF,origin=None,origin_class=None,
                reviewer=None,target=target.ref,body='fixture',refs=[],now=1000)
            self.k.add_reply=lambda m,r:{'id':m['id'],'error':{'code':-32603,'message':'unknown'}}
            dispatcher=Dispatcher(store,lambda:[target],{Provider.CODEX:T.CodexTransport()},clock=lambda:1001,
                                  attempt_queue_state=Q.state)
            dispatcher.run_once();dispatcher.run_once()
            self.assertEqual(len(self.adds()),1)
            self.assertIs(store.get_attempt(attempt.id).delivery,Delivery.UNKNOWN)
            self.assertEqual(sum(e['kind']=='native_send_boundary' for e in store.events(task.id)),1)
            self.assertEqual(store.get_attempt(attempt.id).delivery_detail['deliveredPid'],200)

    def test_worker_image_pid_birth_and_exact_spawn_flags(self):
        binary=self.root/'base-python.exe';binary.touch()
        self.k.images[100]=str(binary)
        with self.scope(),patch.object(sys,'_base_executable',str(binary)):
            self.assertEqual(W.executable(),binary)
            failure=None
            try:W.register(self.p.files,self.state)
            except OSError as error:failure=error
            self.assertIsNone(failure)
            doc=W.verify(self.p.files,self.state)
            self.assertEqual(doc['pid'],100)
            self.assertEqual(W.diagnostic(self.p.files,self.state)['generationAndImage'],'verified')
            self.assertTrue(W.diagnostic(self.p.files,self.state)['inJob'])
            for kwargs in ({'pid':101},{'birth':'999'},{'token':'bad'},{'expected_image':(9,9,9)}):
                with self.assertRaises(OSError):W.verify(self.p.files,self.state,**kwargs)
            other=self.root/'other-python.exe';other.touch();self.k.images[100]=str(other)
            with self.assertRaises(OSError):W.verify(self.p.files,self.state)
            self.k.images[100]=str(binary)
            def popen(argv,**kw):
                self.assertEqual(argv,[str(binary),'-m','agentstatus_bridge','worker'])
                self.assertEqual(kw['creationflags'],0x1000208)
                self.assertTrue(kw['close_fds'])
                self.assertEqual(kw['cwd'],str(self.state))
                self.k.processes[101]=(100,134362090001812230,self.k.sid,False,'python.exe')
                self.k.images[101]=str(binary);self.k.current=101
                try:
                    with patch.dict(os.environ,kw['env']):W.register(self.p.files,self.state)
                finally:self.k.current=100
                return SimpleNamespace(pid=101)
            with patch('subprocess.Popen',side_effect=popen) as spawn:
                self.p.lifecycle.spawn_worker(self.state,self.p.lifecycle.worker_environment(os.environ))
            self.assertEqual(spawn.call_count,1)
            self.assertEqual(W.verify(self.p.files,self.state)['pid'],101)
            self.assertTrue(any(n=='QueryFullProcessImageNameW' for n,_ in self.k.calls))

    def test_real_cli_send_report_accept_close_and_unsupported_stay_closed(self):
        env=self.chain();self.k.loaded=[uuid(1),uuid(2)]
        self.k.metadata={t:{'id':t,'source':'cli','name':'PRIVATE_NATIVE_NAME_'+str(i)} for i,t in enumerate(self.k.loaded)}
        with (self.scope(),patch.dict(os.environ,env),patch('agentstatus_bridge.platforms.windows.caller.os.getpid',return_value=100),
              patch.object(cli,'_start_worker',return_value=False),patch.object(cli,'_worker_up',return_value=False),
              patch.object(cli,'_revive_worker')):
            code,out,err=self.run_cli('send','--to',uuid(2),'-m','任务中文😀','--no-wait','--json')
            self.assertEqual(code,6,(out,err))
            self.assertIn('可能没有窗口在显示',out)
            self.assertIn('PRIVATE_NATIVE_NAME_1',out)  # local JSON/label snapshot is authorized
            with Store.open(self.state) as store:
                tasks=store.list_tasks();self.assertEqual(len(tasks),1)
                task=tasks[0];attempt=store.attempts(task.id)[0]
                result=D.discover(self.p.transport)
                target=result.endpoint(result.select(uuid(2)))
                dispatcher=Dispatcher(store,lambda:[target],{Provider.CODEX:T.CodexTransport()},attempt_queue_state=Q.state)
                dispatcher.run_once()
                self.assertIs(store.get_attempt(attempt.id).delivery,Delivery.QUEUED)
            # Same daemon, different root UUID: no generation guard may hide K11.
            denied=self.run_cli('report',task.id,'--ack','--json')
            self.assertEqual(denied[0],3)
            self.assertIn('reporter_mismatch',denied[2])
            old=self.k.processes[200]
            self.k.processes[200]=(old[0],old[1]+1,*old[2:])
            with patch.dict(os.environ,{'CODEX_THREAD_ID':uuid(2),'CODEX_SESSION_ID':uuid(2)}):
                self.assertEqual(self.run_cli('report',task.id,'--ack','--json')[0],0)
                self.assertEqual(self.run_cli('report',task.id,'--result','--note','完成😀','--json')[0],0)
                for command in (('accept',task.id,'--json'),('close',task.id)):
                    self.assertEqual(self.run_cli(*command)[0],3)
            self.assertEqual(self.run_cli('accept',task.id,'--json')[0],0)
            self.assertEqual(self.run_cli('close',task.id)[0],0)
            with patch.object(cli,'cmd_withdraw',return_value=0) as unopened:
                for cmd in (('withdraw',task.id,'--attempt','1'),
                            ('send','--to','grok@x','-m','fixture')):
                    self.assertEqual(self.run_cli(*cmd)[0],9)
                unopened.assert_not_called()
            with Store.open(self.state) as store:
                self.assertIsNotNone(store.get_task(task.id).accepted_at)
                self.assertIsNotNone(store.get_task(task.id).closed_at)
                self.assertEqual(len(store.list_tasks(include_finished=True)),1)
                self.assertTrue(all('PRIVATE_NATIVE_NAME' not in a.body for a in store.attempts(task.id)))
            self.assertEqual(len(self.adds()),1)
            self.assertNotIn('PRIVATE_NATIVE_NAME',self.adds()[0]['params']['input'][0]['text'])

    def test_worker_once_uses_native_transports_and_recorded_context(self):
        binary=self.root/'python-base.exe';binary.touch();self.k.images[100]=str(binary)
        with (self.scope(),patch.object(sys,'_base_executable',str(binary)),
              patch.object(worker,'_open_inbox',return_value=None) as inbox,
              patch.object(worker.time,'sleep',return_value=None),
              patch.object(worker,'Dispatcher',wraps=Dispatcher) as built):
            self.assertEqual(worker.run_worker(root=self.state,once=True),0)
            inbox.assert_called_once()
            self.assertEqual(set(worker.default_transports()),{Provider.CODEX,Provider.CLAUDE})
            self.assertIsInstance(worker.default_transports()[Provider.CODEX],T.CodexTransport)
            self.assertIsNotNone(built.call_args.kwargs['empty_discovery_complete'])
            self.assertIs(built.call_args.kwargs['attempt_queue_state'],Q.state)
            self.assertEqual(W.verify(self.p.files,self.state)['context'],
                             {'consoleDetached':True,'inJob':True,'outlivesJob':False})
            self.assertFalse(worker.worker_running(self.state))
            self.assertEqual(self.k.messages,[])

    def test_windows_incomplete_parks_then_cli_restarts_worker(self):
        from agentstatus_bridge.platforms.windows import pending_backoff as pacing
        original_backoff = pacing.PendingBackoff
        binary = self.root/'python-base.exe'
        binary.touch()
        self.k.images[100] = str(binary)
        tick = [0.0]
        samples, engines = [], []
        original_discover = D.discover

        def sampled(*args, **kwargs):
            samples.append(tick[0])
            return original_discover(*args, **kwargs)

        def create(**kwargs):
            engine = Dispatcher(**kwargs, clock=lambda: 1000+tick[0], monotonic=lambda: tick[0])
            engines.append(engine)
            return engine

        def sleep(seconds):
            tick[0] += seconds
            self.assertLessEqual(tick[0], 724, 'Windows worker did not become idle')

        with (self.scope(), patch.object(sys, '_base_executable', str(binary)),
              patch.object(worker.time, 'monotonic', side_effect=lambda: tick[0]),
              patch.object(worker.time, 'time', side_effect=lambda: 1000+tick[0]),
              patch.object(worker.time, 'sleep', side_effect=sleep),
              patch.object(worker, '_open_inbox', return_value=None),
              patch.object(worker, 'Dispatcher', side_effect=create),
              patch.object(pacing, 'PendingBackoff', side_effect=lambda: original_backoff(clock=lambda: tick[0])),
              patch('agentstatus_bridge.dispatch.os.getpid', return_value=100)):
            target = self.target()
            with Store.open(self.state) as store:
                task, attempt = store.create_task(title='fixture', flow=Flow.HANDOFF, origin=None,
                    origin_class=None, reviewer=None, target=target.ref, body='fixture', refs=[], now=1000)
            self.k.override = lambda m, r: {'id': m['id'], 'error': {}}
            with patch('agentstatus_bridge.platforms.windows.commands.discover', side_effect=sampled):
                self.assertEqual(worker.run_worker(root=self.state, loop_seconds=2), 0)
            self.assertEqual(samples[:5], [0, 2, 6, 14, 30])
            self.assertLess(len(samples), 30)
            self.assertEqual(tick[0], 720)
            self.assertEqual(engines[0]._discovery_wait_since, {attempt.id: 0})
            self.assertEqual(engines[0]._parked_pending, {attempt.id})
            with Store.open(self.state) as store:
                self.assertIs(store.get_attempt(attempt.id).delivery, Delivery.PENDING)
            records = [json.loads(line) for line in (self.state/worker.LOG_NAME).read_text().splitlines()]
            self.assertEqual([r['waitSeconds'] for r in records if r['event']=='pending_parked'], [600])
            self.assertNotIn('loop_error', [r['event'] for r in records])
            self.assertEqual(records[-1]['event'], 'stop')
            self.assertFalse(worker.worker_running(self.state))
            self.k.override = None

            def restart():
                return worker.run_worker(root=self.state, once=True)

            with patch.object(cli, '_ensure_worker', side_effect=restart) as start:
                self.assertEqual(self.run_cli('status', task.id, '--json')[0], 0)
                start.assert_called_once()
            self.assertEqual(len(engines), 2)
            self.assertIsNot(engines[0], engines[1])
            self.assertEqual(engines[1]._discovery_wait_since, {})
            with Store.open(self.state) as store:
                self.assertIs(store.get_attempt(attempt.id).delivery, Delivery.QUEUED)
            self.assertEqual(len(self.adds()), 1)

    def test_manual_send_resume_permissions_and_subagent_never_write(self):
        env=self.chain();self.k.loaded=[uuid(1),uuid(2)]
        with (self.scope(),patch.dict(os.environ,env),patch('agentstatus_bridge.platforms.windows.caller.os.getpid',return_value=100),
              patch.object(cli,'_start_worker',return_value=False),patch.object(cli,'_worker_up',return_value=False),
              patch.object(cli,'_revive_worker')):
            with patch.dict(os.environ,{'CODEX_SESSION_ID':uuid(2)}):
                code,out,err=self.run_cli('send','--to',uuid(2),'-m','fixture','--no-wait')
                self.assertEqual(code,3)
                self.assertIn('sender_is_subagent',err)
                self.assertFalse(self.state.exists())
            self.assertEqual(self.run_cli('send','--to',uuid(2),'-m','fixture','--no-wait')[0],6)
            with Store.open(self.state) as store:
                task=store.list_tasks()[0]
            with patch.dict(os.environ,{'CODEX_THREAD_ID':uuid(2),'CODEX_SESSION_ID':uuid(2)}):
                for command in ('pause','cancel'):
                    code,_,err=self.run_cli(command,task.id)
                    self.assertEqual(code,3)
                    self.assertIn('accept_not_allowed',err)
            with Store.open(self.state) as store:
                self.assertFalse(store.get_task(task.id).paused)
                self.assertIs(store.attempts(task.id)[0].delivery,Delivery.PENDING)
            self.assertEqual(self.run_cli('pause',task.id)[0],0)
            with Store.open(self.state) as store:self.assertTrue(store.get_task(task.id).paused)
            old=self.k.processes[200]
            self.k.processes[200]=(old[0],old[1]+1,*old[2:])
            with patch.dict(os.environ,{'CODEX_THREAD_ID':uuid(2),'CODEX_SESSION_ID':uuid(2)}):
                self.assertEqual(self.run_cli('resume',task.id)[0],3)
            with Store.open(self.state) as store:self.assertTrue(store.get_task(task.id).paused)
            self.assertEqual(self.run_cli('resume',task.id)[0],0)
            with Store.open(self.state) as store:self.assertFalse(store.get_task(task.id).paused)
            self.assertEqual(self.run_cli('cancel',task.id)[0],0)
            with Store.open(self.state) as store:
                self.assertIs(store.attempts(task.id)[0].delivery,Delivery.CANCELLED)
            code,_,err=self.run_cli('cancel',task.id)
            self.assertEqual(code,3)
            self.assertIn('nothing_to_cancel',err)
            self.assertEqual(self.adds(),[])

    def test_cancel_preserves_sent_unknown_and_never_deletes_native(self):
        env=self.chain();self.k.loaded=[uuid(1),uuid(2)]
        with (self.scope(),patch.dict(os.environ,env),patch('agentstatus_bridge.platforms.windows.caller.os.getpid',return_value=100),
              patch.object(cli,'_start_worker',return_value=False),patch.object(cli,'_worker_up',return_value=False),
              patch.object(cli,'_revive_worker')):
            self.assertEqual(self.run_cli('send','--to',uuid(2),'-m','fixture','--no-wait')[0],6)
            with Store.open(self.state) as store:
                task=store.list_tasks()[0];attempt=store.attempts(task.id)[0]
                store.transition_delivery(attempt.id,expected=(Delivery.PENDING,),new=Delivery.SENDING,reason='fixture',now=1001)
            for state in (Delivery.SENDING,Delivery.QUEUED,Delivery.UNKNOWN):
                with Store.open(self.state) as store:
                    current=store.get_attempt(attempt.id)
                    store.transition_delivery(attempt.id,expected=(current.delivery,),new=state,reason='fixture',now=1002)
                code,_,err=self.run_cli('cancel',task.id)
                self.assertEqual(code,3)
                self.assertIn('nothing_to_cancel',err)
                with Store.open(self.state) as store:self.assertIs(store.get_attempt(attempt.id).delivery,state)
            self.assertFalse(any(m.get('method','').startswith('thread/queue/') for m in self.k.messages))

    def test_pause_cancel_require_attribution_and_accept_positive_user_fixture(self):
        from agentstatus_bridge.caller_values import Caller
        env=self.chain();self.k.loaded=[uuid(1),uuid(2)]
        with (self.scope(),patch.dict(os.environ,env),patch('agentstatus_bridge.platforms.windows.caller.os.getpid',return_value=100),
              patch.object(cli,'_start_worker',return_value=False),patch.object(cli,'_worker_up',return_value=False),
              patch.object(cli,'_revive_worker')):
            self.assertEqual(self.run_cli('send','--to',uuid(2),'-m','fixture','--no-wait')[0],6)
            with Store.open(self.state) as store:task=store.list_tasks()[0]
            for who,reason in ((Caller(None,None,'unknown',True),'caller_unattributed'),
                               (Caller(None,None,'unknown',False,'subagent'),'sender_is_subagent')):
                with patch('agentstatus_bridge.platforms.windows.caller.identify',return_value=who):
                    for action in ('pause','cancel'):
                        code,_,err=self.run_cli(action,task.id)
                        self.assertEqual(code,3)
                        self.assertIn(reason,err)
            # Positive user is a controlled identity fixture, not a claim that
            # real Windows manual attribution has passed the remaining gate.
            with patch('agentstatus_bridge.platforms.windows.caller.identify',return_value=Caller(None,None,'windows-terminal',False)):
                self.assertEqual(self.run_cli('pause',task.id)[0],0)
                self.assertEqual(self.run_cli('cancel',task.id)[0],0)
            with Store.open(self.state) as store:
                self.assertTrue(store.get_task(task.id).paused)
                self.assertIs(store.attempts(task.id)[0].delivery,Delivery.CANCELLED)
            self.assertEqual(self.adds(),[])

    def test_worker_failure_is_storage_error_not_recorded_six(self):
        with self.scope(),patch.object(cli,'run_worker',side_effect=OSError('unverified fixture')):
            code,out,err=self.run_cli('worker','--once')
            self.assertEqual(code,8)
            self.assertIn('worker_identity_unverified',err)
            self.assertEqual(out,'')
            self.assertFalse(self.state.exists())

    def test_closed_report_json_records_exactly_once(self):
        env=self.chain()
        class Broken:
            def write(self,_):raise BrokenPipeError()
            def flush(self):raise BrokenPipeError()
        with (self.scope(),patch.dict(os.environ,env),patch('agentstatus_bridge.platforms.windows.caller.os.getpid',return_value=100),
              patch.object(cli,'_revive_worker')):
            target=self.target()
            with Store.open(self.state) as store:
                task,attempt=store.create_task(title='fixture',flow=Flow.HANDOFF,origin=None,origin_class=None,
                    reviewer=None,target=target.ref,body='fixture',refs=[],now=1000)
                store.begin_send(attempt.id,now=1001,pid=100,start_ticks='win-filetime:1')
                store.finish_send(attempt.id,delivery=Delivery.QUEUED,reason='fixture',provider_ref=uuid(900),detail={},now=1002)
            with redirect_stdout(Broken()),redirect_stderr(io.StringIO()):
                error=None;code=None
                try:code=cli.main(['report',task.id,'--result','--json','--note','完成😀'])
                except OSError as failure:error=failure
            self.assertIsNone(error)
            self.assertEqual(code,0)
            with Store.open(self.state) as store:
                self.assertEqual(sum(e['kind']=='result' for e in store.events(task.id)),1)
                self.assertEqual(store.get_attempt(attempt.id).result['note'],'完成😀')
                self.assertEqual(len(store.attempts(task.id)),1)

    def test_worker_image_query_brackets_generation_and_width(self):
        binary=self.root/'中文-base.exe';binary.touch();self.k.images[100]=str(binary)
        birth=str(self.k.processes[100][1]);original=self.k.GetProcessTimes;calls=[]
        def changed(handle,created,*rest):
            answer=original(handle,created,*rest);calls.append(1)
            if len(calls)==2:
                value=ctypes.cast(created,ctypes.POINTER(SDK.FILETIME)).contents
                value.dwLowDateTime+=1
            return answer
        with patch.object(self.k,'GetProcessTimes',side_effect=changed):
            with self.assertRaises(OSError):self.k.api.process_image(100,birth)
        self.assertEqual(self.k.handles,{})
        self.assertEqual(self.k.api.process_image(100,birth),str(binary))
        self.k.faults['QueryFullProcessImageNameW']=5
        with self.assertRaises(OSError):self.k.api.process_image(100,birth)
        self.assertEqual(self.k.handles,{})

    def test_task_root_mismatch_before_mutation(self):
        env=self.chain();self.k.loaded=[uuid(1),uuid(2)]
        with (self.scope(),patch.dict(os.environ,env),patch('agentstatus_bridge.platforms.windows.caller.os.getpid',return_value=100),
              patch.object(cli,'_start_worker',return_value=False),patch.object(cli,'_revive_worker')):
            result=D.discover(self.p.transport)
            origin=result.endpoint(result.select(uuid(1))).ref
            target=replace(result.endpoint(result.select(uuid(2))).ref,data_root='b'*64)
            with Store.open(self.state) as store:
                task,_=store.create_task(title='fixture',flow=Flow.HANDOFF,origin=origin,origin_class=None,
                    reviewer=None,target=target,body='fixture',refs=[],now=1000)
                store.update_task(task.id,now=1001,event='paused',control='paused')
            code,out,err=self.run_cli('resume',task.id)
            self.assertEqual(code,2)
            self.assertIn('target_root_changed',err)
            with Store.open(self.state) as store:
                self.assertTrue(store.get_task(task.id).paused)
                self.assertFalse(any(e['kind']=='resumed' for e in store.events(task.id)))


class AuditTests(unittest.TestCase):
    setUp=DeliveryTests.setUp
    rebuild=DeliveryTests.rebuild
    scope=DeliveryTests.scope
    target=DeliveryTests.target
    deliver=DeliveryTests.deliver
    adds=DeliveryTests.adds
    sql=DeliveryTests.sql
    run_cli=DeliveryTests.run_cli
    chain=DeliveryTests.chain

    def test_wide_equivalence_boundaries_and_relative_cpu_guard(self):
        from agentstatus_bridge.platforms.windows import abi as A
        def old(value):
            units=list(value)
            if 0 in units:units=units[:units.index(0)]
            return b''.join(int(u).to_bytes(2,'little') for u in units).decode('utf-16-le','surrogatepass')
        for units in ([],[0],[65,0,66],[0xd83d,0xde00],[0xd800,65],[0xdc00],
                      [65]*32768,[65]*32767+[0]):
            value=(A.WCHAR*len(units))(*units)
            self.assertEqual(A.read_wide(value),old(value))
        value=(A.WCHAR*32768)(65,0,66)
        self.assertEqual(A.read_wide(value,0),'')
        self.assertEqual(A.read_wide(value,1),'A')
        self.assertEqual(A.read_wide(value,3),'A')
        # Upper bound first: deleting validation must be an assertion failure,
        # not string_at(-1)'s SystemError masking the unsafe oversized read.
        for length in (32769,-1):
            with self.assertRaises(ValueError):A.read_wide(value,length)
        # Relative CPU guard over the actual large Win32 return buffer. A frozen
        # budget or a fast host cannot hide reintroduced per-element Python work.
        def cost(fn):
            samples=[]
            for _ in range(5):
                start=time.process_time()
                for _ in range(40):fn()
                samples.append((time.process_time()-start)/40)
            return statistics.median(samples)
        reference=cost(lambda:bytes(value).decode('utf-16-le','surrogatepass').partition('\0')[0])
        actual=cost(lambda:A.read_wide(value))
        self.assertLess(actual,reference*8+0.000025,(actual,reference))

    def test_minimal_discovery_and_send_bounded_sdk_work(self):
        # SDK call work is bounded independent of VM scheduling / wall-clock
        # load. The separate relative CPU guard rejects the old decoder loop.
        # Real Windows READ margin is a W2-5 gate, not this synthetic clock.
        from agentstatus_bridge.platforms.windows.local_transport import DaemonStream
        from agentstatus_bridge.platforms.windows.api import WinApi
        # §77.17: IO fragmentation no longer adds full verifications. Tighten
        # the measured scene table after removing per-frame checks; retaining
        # the old bounds would miss newly redundant filesystem probes.
        depth=len(self.home.parents)
        with (self.scope(),
              patch.object(DaemonStream,'verify',autospec=True,side_effect=DaemonStream.verify) as verify,
              patch.object(WinApi,'check_ntfs',autospec=True,side_effect=WinApi.check_ntfs) as ntfs,
              patch.object(WinApi,'check_private',autospec=True,side_effect=WinApi.check_private) as private):
            before=len(self.k.calls);result=D.discover(self.p.transport)
            self.assertTrue(result.complete,result.reason)
            self.assertLess(len(self.k.calls)-before,6000*(len(self.home.parents)+1))
            for count,bound in zip((verify.call_count,ntfs.call_count,private.call_count),
                                   (1,37+27*depth,0)):
                self.assertLessEqual(count,bound)
            for counter in (verify,ntfs,private):counter.reset_mock()
            before=len(self.k.calls);sent=self.deliver(result.endpoint(result.select(uuid(1))))
            self.assertIs(sent.delivery,Delivery.QUEUED,sent)
            self.assertLess(len(self.k.calls)-before,9000*(len(self.home.parents)+1))
            for count,bound in zip((verify.call_count,ntfs.call_count,private.call_count),
                                   (1,49+34*depth,0)):
                self.assertLessEqual(count,bound)
            self.assertEqual(len(self.adds()),1)

    def test_binary_stdin_and_file_strict_utf8_same_bom_and_errors(self):
        with self.scope():
            for raw in ('中文😀'.encode('utf-8'),b'\xef\xbb\xbfhello',b'',b'\xff'):
                file=self.root/'body.txt';file.write_bytes(raw)
                for source in ('stdin','file'):
                    stream=io.TextIOWrapper(io.BytesIO(raw),encoding='cp1252')
                    args=SimpleNamespace(file=str(file) if source=='file' else None,message=None if source=='file' else '-')
                    with patch.object(sys,'stdin',stream):
                        if raw==b'\xff':
                            with self.assertRaises(cli.CliError) as caught:cli._read_body(args)
                            self.assertEqual((caught.exception.code,caught.exception.exit_code),('message_invalid_utf8',3))
                        else:self.assertEqual(cli._read_body(args),raw.decode('utf-8'))
            env=self.chain()
            for source in ('stdin','file'):
                bad=self.root/'bad.txt';bad.write_bytes(b'\xff')
                with (patch.dict(os.environ,env),patch('agentstatus_bridge.platforms.windows.caller.os.getpid',return_value=100),
                      patch.object(sys,'stdin',io.TextIOWrapper(io.BytesIO(b'\xff'),encoding='cp1252')),
                      patch.object(cli,'_refresh_summary')):
                    code,out,err=self.run_cli('send','--to',uuid(1),'--no-wait',*(['-m','-'] if source=='stdin' else ['--file',str(bad)]))
                self.assertEqual(code,3)
                self.assertIn('message_invalid_utf8',err)
                self.assertFalse((self.state/'bridge.sqlite3').exists())
                self.assertEqual(self.adds(),[])

    def test_unattributed_command_scope_fails_before_sampling_without_wait(self):
        from agentstatus_bridge.caller_values import Caller
        from agentstatus_bridge.platforms.windows import caller
        who=Caller(None,None,agent_env=True,rejection='platform_unverified')
        args=SimpleNamespace(command='send',to=uuid(1),review_by=None)
        with self.scope(),patch.object(caller,'identify',return_value=who),patch.object(B,'sample',return_value=D.Discovery()) as sampled:
            with self.assertRaisesRegex(NativeFailure,'caller_unattributed'):
                with B.scope(args):pass
            sampled.assert_not_called()

    def test_union_selectors_and_random_peers_roundtrip(self):
        a,b=uuid(1),uuid(2)
        rows=(D.Candidate(a,'root',name=b,cwd_label='same',names_verified=True),
              D.Candidate(b,'root',name='same',cwd_label=a[:8],names_verified=True))
        result=D.Discovery(rows,True,'complete','a'*64,(200,'1'))
        error=None;chosen=None
        try:chosen=result.select(b)
        except NativeFailure as failure:error=failure.reason
        self.assertIsNone(error)
        self.assertEqual(chosen.thread,b)
        single=replace(result,rows=(replace(rows[0],name='alpha',cwd_label='project'),))
        with self.assertRaisesRegex(NativeFailure,'target_not_found'):single.select('0')
        for key in ('same',a[:8]):
            with self.assertRaisesRegex(NativeFailure,'target_ambiguous'):result.select(key)
        repeated=replace(result,rows=(replace(rows[0],name='same'),rows[1]))
        with self.assertRaisesRegex(NativeFailure,'target_ambiguous'):repeated.select('same')
        same=replace(result,rows=(replace(rows[0],name='one',cwd_label='one'),rows[1]))
        self.assertEqual(same.select('one').thread,a)
        override=replace(result,aliases=AliasSet({'same':a,b:a}))
        self.assertEqual(override.select('same').thread,a)
        self.assertEqual(override.select(b).thread,b)
        rng=random.Random(77)
        for _ in range(120):
            choices=['work','same','project',a,a[:8],'id:'+b,'codex@work','']
            roots=tuple(D.Candidate(uuid(i),'root',name=rng.choice(choices),cwd_label=rng.choice(choices),
                                    names_verified=True) for i in range(1,7))
            sample=replace(result,rows=roots,aliases=AliasSet({'work':rng.choice(roots).thread}))
            for r in roots:
                self.assertEqual(sample.select(sample.target_name(r)).thread,r.thread)
            self.assertEqual(len(sample.document()['peers']),6)
        nonroot=replace(result,rows=(replace(rows[0],kind='subagent'),rows[1]))
        self.assertIsNone(nonroot.document()['peers'][0]['target'])

    def test_empty_selector_cli_send_and_reviewer_never_records(self):
        from agentstatus_bridge.caller_values import Caller
        for kinds in (('origin',''),('',),('','')):
            self.k.loaded=[uuid(i+1) for i in range(len(kinds))]
            self.k.metadata={uuid(i+1):{'id':uuid(i+1),'source':'cli','name':name,'cwd':'C:\\project-'+str(i)}
                             for i,name in enumerate(kinds)}
            env=self.chain()
            with (self.scope(),patch.dict(os.environ,env),
                  # Selection fixture uses a positively attributed manual owner
                  # so the single-root review case doesn't hit target_is_self
                  # before reaching the reviewer parser. Not Windows qualification.
                  patch('agentstatus_bridge.platforms.windows.caller.identify',return_value=Caller(None,None,'windows-terminal',False)),
                  patch.object(cli,'_start_worker',return_value=False),patch.object(cli,'_worker_up',return_value=False)):
                for reference in ('',' ','　','codex@','codex@id:','id:','codex@ ','codex@id:\t',' \t'):
                    for selectors in (['--to',reference],['--to',uuid(1),'--review-by',reference]):
                        code,out,err=self.run_cli('send',*selectors,'-m','fixture','--no-wait','--json')
                        self.assertEqual(code,2,(kinds,reference,selectors,err))
                        self.assertIn('target_explicit_required',err)
                        self.assertFalse((self.state/'bridge.sqlite3').exists())
                        self.assertEqual(self.adds(),[])

    def test_name_union_independently_rejects_empty_and_peers_roundtrip(self):
        rows=tuple(D.Candidate(uuid(i+1),'root',name=name,cwd_label='',names_verified=True)
                   for i,name in enumerate(('', 'named')))
        result=D.Discovery(rows,True,'complete','a'*64,(200,'1'))
        self.assertEqual(result._named(''),[])
        self.assertEqual(result._named('named'),[rows[1]])
        for row in rows:
            selector=result.target_name(row)
            self.assertNotIn(selector,('codex@','codex@id:','codex@ '))
            self.assertEqual(result.select(selector).thread,row.thread)

    def test_distinct_prefix_cross_layer_and_forced_id(self):
        a,b='12345678-0000-4000-8000-000000000001','abcdefab-0000-4000-8000-000000000002'
        for field in ('name','cwd_label'):
            rows=(D.Candidate(a,'root',name='alpha',names_verified=True),
                  replace(D.Candidate(b,'root',name='beta',names_verified=True),**{field:a[:8]}))
            result=D.Discovery(rows,True,'complete','a'*64,(200,'1'))
            with self.assertRaisesRegex(NativeFailure,'target_ambiguous'):result.select(a[:8])
            for incomplete in (False,True):
                sample=replace(result,rows=tuple(replace(r,names_verified=not incomplete) for r in rows))
                error=None;chosen=None
                try:chosen=sample.select('id:'+a[:8])
                except NativeFailure as failure:error=failure.reason
                self.assertIsNone(error)
                self.assertEqual(chosen.thread,a)

    def test_alias_set_forces_id_warns_missing_names_and_load_rejects_hex(self):
        a,b='12345678-0000-4000-8000-000000000001','abcdefab-0000-4000-8000-000000000002'
        self.k.loaded=sorted([a,b])
        self.k.metadata={a:{'id':a,'source':'cli','name':'first','cwd':'C:\\a'},
                         b:{'id':b,'source':'cli','name':a[:8],'cwd':'C:\\b'}}
        with self.scope():
            for incomplete in (False,True):
                if incomplete:self.k.metadata[b]['name']=123
                for mode in ([],['--json']):
                    code,out,err=self.run_cli('alias','set','chosen',a[:8],*mode)
                    self.assertEqual(code,0,err)
                    self.assertEqual('冲突检查不完整' in out,incomplete)
                    if mode:self.assertEqual('warning' in json.loads(out),incomplete)
                    result=D.discover(self.p.transport)
                    self.assertEqual(result.select('chosen').thread,a)
            for name in ('deadbeef','ABCDEFAB','dead-beef',''):
                path=self.state/'target-aliases/codex.json'
                doc=json.loads(path.read_bytes());doc['aliases'][0]['alias']=name
                path.write_text(json.dumps(doc),encoding='utf-8')
                loaded=AliasFile(self.p.files,self.state).load(self.p.files.root_identity(self.home))
                self.assertEqual(loaded.reason,'alias_store_unverified')
                self.assertEqual(loaded.names,{})

    def test_pending_exception_still_observes_backoff(self):
        from agentstatus_bridge.platforms.windows.pending_backoff import PendingBackoff
        with self.scope(),Store.open(self.state) as store:
            target=self.target()
            store.create_task(title='fixture',flow=Flow.HANDOFF,origin=None,origin_class=None,
                reviewer=None,target=target.ref,body='fixture',refs=[],now=1000)
            backoff=PendingBackoff(clock=lambda:1000.)
            discovery=Mock(side_effect=RuntimeError('fixture'))
            dispatcher=Dispatcher(store,discovery,{},clock=lambda:1000.,
                pending_ready=backoff.ready,pending_observe=backoff.observe)
            with self.assertRaisesRegex(RuntimeError,'fixture'):dispatcher.run_once()
            self.assertEqual((backoff.next,backoff.delay),(1002.,4.))
            dispatcher.run_once()
            discovery.assert_called_once()

    def test_windows_unattributed_hint_does_not_change_linux_text(self):
        args=SimpleNamespace(json=True,json_errors=True)
        for platform in (self.p,SimpleNamespace(name='linux')):
            with using_platform(platform),redirect_stdout(io.StringIO()) as out,redirect_stderr(io.StringIO()) as err:
                cli._report_error(args,'caller_unattributed')
            message=json.loads(out.getvalue())['reasonText']
            if platform.name=='windows':
                self.assertIn('Codex/Claude',message)
                self.assertIn('--manual 不能绕过',message)
            else:self.assertEqual(message,cli.reason_text('caller_unattributed'))
            self.assertIn(message,err.getvalue())

    def test_alias_collision_and_json_errors(self):
        self.k.loaded=[uuid(1),uuid(2)]
        self.k.metadata[uuid(2)]={'id':uuid(2),'source':'cli','name':'work','cwd':'C:\\project'}
        with self.scope():
            for alias in ('work','project','deadbeef'):
                code,out,err=self.run_cli('alias','set',alias,uuid(1),'--json')
                self.assertEqual(code,3)
                self.assertIn('alias_name_',err)
                self.assertIn('alias_name_',out)
                self.assertFalse((self.state/'target-aliases/codex.json').exists())
        with using_platform(SimpleNamespace(name='linux')):
            code,out,err=self.run_cli('alias','list','--json')
            self.assertEqual(code,3)
            self.assertIn('alias_platform_unsupported',out)
            self.assertIn('alias_platform_unsupported',err)
            self.assertIsInstance(json.loads(out),dict)

    def test_retry_same_uuid_across_daemon_generation_and_reject_other_origin(self):
        env=self.chain();self.k.loaded=[uuid(1),uuid(2)]
        with (self.scope(),patch.dict(os.environ,env),patch('agentstatus_bridge.platforms.windows.caller.os.getpid',return_value=100),
              patch.object(cli,'_start_worker',return_value=False),patch.object(cli,'_worker_up',return_value=False),
              patch.object(cli,'_revive_worker')):
            self.assertEqual(self.run_cli('send','--to',uuid(2),'-m','fixture','--no-wait')[0],6)
            with Store.open(self.state) as store:
                task=store.list_tasks()[0];attempt=store.attempts(task.id)[0]
                store.transition_delivery(attempt.id,expected=(Delivery.PENDING,),new=Delivery.FAILED,reason='fixture',now=1001)
            old=self.k.processes[200];self.k.processes[200]=(old[0],old[1]+1,*old[2:])
            with patch.dict(os.environ,{'CODEX_THREAD_ID':uuid(2),'CODEX_SESSION_ID':uuid(2)}):
                self.assertEqual(self.run_cli('retry',task.id)[0],3)
            self.assertEqual(self.run_cli('retry',task.id)[0],0)
            with Store.open(self.state) as store:
                latest=store.attempts(task.id)[-1]
                self.assertEqual(latest.target.native_id,uuid(2))
                self.assertEqual(latest.target.start_ticks,'win-filetime:'+str(self.k.processes[200][1]))
                current=D.discover(self.p.transport)
                target=current.endpoint(current.select(uuid(2)))
                Dispatcher(store,lambda:[target],{Provider.CODEX:T.CodexTransport()},attempt_queue_state=Q.state).run_once()
                self.assertIs(store.get_attempt(latest.id).delivery,Delivery.QUEUED)
                self.assertEqual(store.get_attempt(latest.id).delivery_detail['deliveredStart'],target.ref.start_ticks)
                before=len(store.events(task.id))
            wrong=self.root/'other-home';wrong.mkdir()
            control=wrong/'app-server-control';control.mkdir()
            socket=control/'app-server-control.sock';socket.touch()
            self.k.files[str(socket)]={'reparse':True,'tag':0x80000023}
            for variable in ('CODEX_SQLITE_HOME','CODEX_HOME'):
                self.k.server_home=str(wrong if variable=='CODEX_HOME' else self.home)
                with patch.dict(os.environ,{variable:str(wrong)}),F.windows_fixture('unix',str(socket)):
                    for cmd in (('retry',task.id),('resume',task.id),('accept',task.id),('close',task.id),('report',task.id,'--result')):
                        code,_,err=self.run_cli(*cmd)
                        self.assertEqual(code,2)
                        self.assertIn('target_root_changed',err)
            with Store.open(self.state) as store:self.assertEqual(len(store.events(task.id)),before)

    def test_external_admin_acl_only_not_own_state(self):
        from agentstatus_bridge.platforms.windows.private_file import pinned_file
        # SDK SIDs, not a production allowlist import.
        admin=bytes.fromhex('01020000000000052000000020020000')
        system=bytes.fromhex('010100000000000512000000')
        others=(bytes.fromhex('010100000000000100000000'),
                bytes.fromhex('01020000000000052000000021020000'),
                bytes.fromhex('01010000000000050b000000'),
                bytes.fromhex('010100000000000563000000'))
        own=(0,0,0x1f01ff,self.k.sid)
        aces=[own,(0,0,0x1f01ff,system),(0,0,0x1f01ff,admin)]
        path=self.sql([(uuid(1),'cli')])
        for p in (self.control,self.socket,path):
            self.k.files.setdefault(str(p),{}).update(aces=aces)
        with self.scope():
            result=D.discover(self.p.transport)
            self.assertTrue(result.complete)
            self.assertFalse(any(m['method']=='thread/read' for m in self.k.messages))
            self.assertEqual(self.deliver(result.endpoint(result.select(uuid(1)))).delivery,Delivery.QUEUED)
            queue=self.home/'queue_1.sqlite'
            with closing(sqlite3.connect(queue)) as db, db:
                db.execute('CREATE TABLE queued_items(id TEXT PRIMARY KEY)')
                db.execute('INSERT INTO queued_items VALUES (?)',(uuid(900),))
            self.k.files[str(queue)]={'aces':aces}
            with Store.open(self.state) as store:
                _,attempt=store.create_task(title='fixture',flow=Flow.HANDOFF,origin=None,origin_class=None,
                    reviewer=None,target=result.endpoint(result.select(uuid(1))).ref,body='fixture',refs=[],now=1000)
                attempt=replace(attempt,provider_ref=uuid(900),options={'codexDataRoot':result.root_identity})
                self.assertIs(Q.state(attempt),Consumption.STILL_QUEUED)
            for suffix in ('','-wal','-shm','-journal'):
                leaf=self.home/('queue_1.sqlite'+suffix);leaf.touch()
                self.k.files[str(leaf)]={'aces':aces}
                error=None
                try:
                    with pinned_file(self.p.files,leaf,external=True):pass
                except OSError as failure:error=failure
                self.assertIsNone(error)
                with pinned_file(self.p.files,leaf):pass
                self.assertNotIn(admin,[a[3] for a in self.k.files[str(leaf)]['aces']])
            self.state.mkdir(exist_ok=True);self.k.files[str(self.state)]={'aces':aces}
            self.assertEqual(self.p.files.ensure_private_dir(self.state),self.state)
            self.assertNotIn(admin,[a[3] for a in self.k.files[str(self.state)]['aces']])
            for sid in others:
                self.k.files[str(self.socket)]['aces']=[own,(0,0,0x1f01ff,sid)]
                self.assertIsNotNone(self.p.files.validate_socket(self.socket,external=True))
                self.k.files[str(path)]['aces']=[own,(0,0,0x1f01ff,sid)]
                with self.assertRaises(OSError):
                    with pinned_file(self.p.files,path,external=True):pass

    def test_external_sql_read_aces_and_every_write_bit(self):
        from agentstatus_bridge.platforms.windows.private_file import pinned_file
        path = self.home/'arbitrary-sql-leaf'
        path.touch()
        own = (0, 0, 0x1f01ff, self.k.sid)
        others = (bytes.fromhex('010100000000000100000000'), bytes.fromhex('010100000000000563000000'))
        for sid in others:
            for flags in (0, 0x10, 0x0b):
                for mask in (0, 0x120089, 0x1200a9):
                    with self.subTest(sid=sid, flags=flags, mask=mask):
                        self.k.files[str(path)] = {'aces': [own, (0, flags, mask, sid)]}
                        error = None
                        try:
                            with pinned_file(self.p.files, path, external=True, external_sql_read=True): pass
                        except OSError as failure: error = failure
                        self.assertIsNone(error)
                        self.assertEqual(self.k.handles, {})
        for flags in (0, 0x10, 8):
            for bit in (0x2, 0x4, 0x10, 0x40, 0x100, 0x10000, 0x40000, 0x80000,
                        0x10000000, 0x20000000, 0x40000000, 0x80000000):
                with self.subTest(flags=flags, bit=bit):
                    self.k.files[str(path)] = {'aces': [own, (0, flags, 0x120089 | bit, others[0])]}
                    with self.assertRaisesRegex(OSError, 'windows_acl_untrusted'):
                        with pinned_file(self.p.files, path, external=True, external_sql_read=True): pass
                    self.assertEqual(self.k.handles, {})

    def test_sql_read_mode_keeps_owner_and_default_private_contracts(self):
        from agentstatus_bridge.platforms.windows.private_file import pinned_file
        path = self.home/'private-or-sql'; path.touch()
        other = bytes.fromhex('010100000000000100000000')
        own, read = (0, 0, 0x1f01ff, self.k.sid), (0, 0x10, 0x120089, other)
        for meta in ({'owner': other, 'aces': [own, read]}, {'aces': [(0, 0, 0x120089, self.k.sid), read]},
                     {'aces': [(0, 8, 0x1f01ff, self.k.sid), read]}, {'aces': None},
                     {'aces': [own, (0x11, 0, 1, other)]}, {'aces': [own, (9, 0, 0x120089, other)]}):
            with self.subTest(meta=meta):
                self.k.files[str(path)] = meta
                with self.assertRaisesRegex(OSError, 'windows_acl_untrusted'):
                    with pinned_file(self.p.files, path, external=True, external_sql_read=True): pass
        for options in ({}, {'external': True}, {'external_sql_read': True}):
            self.k.files[str(path)] = {'aces': [own, read]}
            with self.subTest(options=options):
                if options.get('external'):
                    with self.assertRaisesRegex(OSError, 'windows_acl_untrusted'):
                        with pinned_file(self.p.files, path, **options): pass
                else:
                    with pinned_file(self.p.files, path, **options): pass
                    self.assertNotIn(other,[a[3] for a in self.k.files[str(path)]['aces']])
        self.k.files[str(self.socket)]['aces'] = [own, read]
        self.assertIsNotNone(self.p.files.validate_socket(self.socket, external=True))
        self.assertEqual(self.k.files[str(self.socket)]['aces'], [own, read])
        self.state.mkdir(exist_ok=True)
        self.k.files[str(self.state)] = {'aces': [own, read]}
        self.assertEqual(self.p.files.ensure_private_dir(self.state),self.state)
        self.assertNotIn(other,[a[3] for a in self.k.files[str(self.state)]['aces']])
        self.assertEqual(self.k.handles, {})

    def test_sql_read_aces_reach_classification_and_consumption_including_journal(self):
        from agentstatus_bridge.platforms.windows import codex_sql
        other = bytes.fromhex('010100000000000563000000')
        own, read = (0, 0, 0x1f01ff, self.k.sid), (0, 0x10, 0x120089, other)
        state = self.sql([(uuid(1), 'cli')])
        queue = self.home/'queue_1.sqlite'
        with closing(sqlite3.connect(queue)) as db, db:
            db.execute('CREATE TABLE queued_items(id TEXT PRIMARY KEY)')
            db.execute('INSERT INTO queued_items VALUES (?)', (uuid(900),))
        for db_path in (state, queue):
            for suffix in ('', '-wal', '-shm', '-journal'):
                leaf = Path(str(db_path)+suffix)
                leaf.touch()
                self.k.files[str(leaf)] = {'aces': [own, read]}
        with self.scope(), Store.open(self.state) as store:
            rows = codex_sql.read_classes(self.p.files, self.home, [uuid(1)], 1001, lambda: 1000)
            self.assertIn(uuid(1), rows)
            self.assertEqual(rows[uuid(1)].kind, 'root')
            target = self.target()
            _, attempt = store.create_task(title='fixture', flow=Flow.HANDOFF, origin=None, origin_class=None,
                reviewer=None, target=target.ref, body='fixture', refs=[], now=1000)
            attempt = replace(attempt, provider_ref=uuid(900), options={'codexDataRoot':target.ref.data_root})
            self.assertIs(Q.state(attempt), Consumption.STILL_QUEUED)
            with closing(sqlite3.connect(queue)) as db, db: db.execute('DELETE FROM queued_items')
            self.assertIs(Q.state(attempt), Consumption.LEFT_QUEUE)
            self.k.files[str(state)]['aces'] = [own, (0, 8, 0x12008b, other)]
            self.k.files[str(queue)]['aces'] = [own, (0, 8, 0x12008b, other)]
            self.assertEqual(codex_sql.read_classes(self.p.files, self.home, [uuid(1)], 1001, lambda:1000), {})
            self.assertIs(Q.state(attempt), Consumption.UNKNOWN)

    def test_sql_read_option_is_confined_to_two_product_callers(self):
        import ast
        import agentstatus_bridge
        calls = []
        for path in Path(agentstatus_bridge.__file__).parent.rglob('*.py'):
            for node in ast.walk(ast.parse(path.read_text(encoding='utf-8'))):
                if isinstance(node, ast.Call):
                    for keyword in node.keywords:
                        if keyword.arg == 'external_sql_read':
                            self.assertIsInstance(keyword.value, ast.Constant)
                            self.assertIs(keyword.value.value, True)
                            calls.append(path.name)
                        if keyword.arg == 'allow_readers':
                            self.assertEqual(path.name, 'private_file.py')
        self.assertEqual(sorted(calls), ['codex_consumption.py', 'codex_sql.py'])

    def test_sql_root_changed_at_boundary_and_after_response(self):
        other=self.root/'separate-sql';other.mkdir()
        for stage in ('boundary','response'):
            self.rebuild();changed=[False]
            original=self.p.files.root_identity
            def identity(home,sql=None):
                return 'b'*64 if changed[0] and sql==other else original(home,sql)
            with self.scope(sql_root=other),patch.object(self.p.files,'root_identity',side_effect=identity):
                target=self.target()
                if stage=='response':
                    response=T.BoundedConnection.response
                    def completed(client,*args):
                        value=response(client,*args)
                        if self.adds():changed[0]=True
                        return value
                    with patch.object(T.BoundedConnection,'response',completed):result=self.deliver(target)
                else:result=self.deliver(target,before_send=lambda:changed.__setitem__(0,True))
                self.assertIs(result.delivery,Delivery.FAILED if stage=='boundary' else Delivery.UNKNOWN)
                self.assertEqual(len(self.adds()),0 if stage=='boundary' else 1)
                self.assertIsNone(result.native_root)

    def test_dispatch_root_mismatch_refuses_before_transport(self):
        with self.scope(),patch('agentstatus_bridge.dispatch.os.getpid',return_value=100),Store.open(self.state) as store:
            target=self.target()
            _,attempt=store.create_task(title='fixture',flow=Flow.HANDOFF,origin=None,origin_class=None,
                reviewer=None,target=target.ref,body='fixture',refs=[],now=1000)
            fake=Mock();fake.deliver.return_value=DeliveryOutcome(Delivery.QUEUED,'fixture')
            dispatcher=Dispatcher(store,lambda:[],{Provider.CODEX:fake},clock=lambda:1001)
            dispatcher.dispatch(attempt,[replace(target,ref=replace(target.ref,data_root='b'*64))])
            fake.deliver.assert_not_called()
            self.assertIsNot(store.get_attempt(attempt.id).delivery,Delivery.QUEUED)
            self.assertEqual(store.get_attempt(attempt.id).delivery_reason,'target_root_changed')
            _,valid=store.create_task(title='fixture',flow=Flow.HANDOFF,origin=None,origin_class=None,
                reviewer=None,target=target.ref,body='fixture',refs=[],now=1000)
            self.assertEqual(dispatcher.dispatch(valid,[target]),'sent')
            fake.deliver.assert_called_once()

    def test_receipt_source_and_locked_worker_are_both_verified(self):
        binary=self.root/'python.exe';binary.touch();self.k.images[100]=str(binary)
        with self.scope(),patch.object(sys,'_base_executable',str(binary)):
            W.register(self.p.files,self.state)
            path=self.state/W.RECEIPT;doc=json.loads(path.read_bytes());doc['source']='b'*64
            path.write_text(json.dumps(doc),encoding='utf-8')
            with self.assertRaisesRegex(OSError,'worker_identity_unverified'):W.verify(self.p.files,self.state)
            fd=self.p.lifecycle.open_lock(worker._lock_path(self.state))
            self.p.lifecycle.try_lock(fd)
            try:
                with self.assertRaises(OSError):worker.worker_running(self.state)
                W.register(self.p.files,self.state)
                self.assertTrue(worker.worker_running(self.state))
            finally:
                self.p.lifecycle.unlock(fd);self.p.lifecycle.close_lock(fd)

    def test_pending_backoff_connections_new_task_success_and_worker_wiring(self):
        from agentstatus_bridge.platforms.windows.pending_backoff import PendingBackoff
        with self.scope(),Store.open(self.state) as store:
            target=self.target();now=[0.0]
            def task():return store.create_task(title='fixture',flow=Flow.HANDOFF,origin=None,origin_class=None,
                reviewer=None,target=target.ref,body='fixture',refs=[],now=1000+now[0])[1]
            task();sampler=D.WorkerDiscovery(self.p.transport);self.k.override=lambda m,r:{'id':m['id'],'error':{}}
            backoff=PendingBackoff(clock=lambda:now[0]);counts=[]
            dispatcher=Dispatcher(store,sampler,{Provider.CODEX:T.CodexTransport()},clock=lambda:1000+now[0],
                empty_discovery_complete=sampler.complete,pending_ready=backoff.ready,pending_observe=backoff.observe)
            for tick in range(33):
                now[0]=float(tick);before=len(self.k.messages);dispatcher.run_once()
                if len(self.k.messages)>before:counts.append(tick)
            self.assertEqual(counts,[0,2,6,14,30])
            self.assertEqual(backoff.delay,32)
            now[0]=33;task();before=len(self.k.messages);dispatcher.run_once()
            self.assertGreater(len(self.k.messages),before)
            self.assertEqual(backoff.next,35)
            self.k.override=None;now[0]=35
            with patch('agentstatus_bridge.dispatch.os.getpid',return_value=100):sent=dispatcher.run_once()
            self.assertGreater(sent.sent,0)
            self.assertEqual((backoff.delay,backoff.next),(2,37))
        binary=self.root/'python.exe';binary.touch();self.k.images[100]=str(binary)
        with (self.scope(),patch.object(sys,'_base_executable',str(binary)),
              patch.object(worker.time,'sleep'),patch.object(worker,'Dispatcher',wraps=Dispatcher) as built):
            self.assertEqual(worker.run_worker(root=self.state,once=True),0)
            self.assertIsNotNone(built.call_args.kwargs['pending_ready'])
            self.assertIsNotNone(built.call_args.kwargs['pending_observe'])


if __name__=='__main__':unittest.main()
