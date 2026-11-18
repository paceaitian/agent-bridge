"""W2-2 real WS+SQLite on SDK Fake Win32. No real provider or private home."""
from contextlib import ExitStack, closing, contextmanager, redirect_stdout, redirect_stderr
from dataclasses import replace
import io
import json
import os
from pathlib import Path
import sqlite3
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import time
import unittest
from unittest.mock import patch

import bridge_support
from bridge_sqlite_fixture import require_closed_connections
from bridge_short_socket import short_root
from bridge_platform_guard import windows_fixture
from test_bridge_windows_codex import DaemonKernel
from agentstatus_bridge import cli, views
from agentstatus_bridge.model import NameSource, Provider, Flow
from agentstatus_bridge.store import Store
from agentstatus_bridge.platforms.factory import make_platform, using_platform
from agentstatus_bridge.platforms.windows import codex_discovery as D, codex_sql as Q, codex_version
from agentstatus_bridge.platforms.windows.target_aliases import AliasFile, AliasSet, MAX_AGE
from agentstatus_bridge.transports.codex_native import NativeFailure


def uuid(n):
    return f'00000000-0000-7000-8000-{n:012x}'


class LoadedKernel(DaemonKernel):
    def __init__(self, root, home):
        super().__init__(root, home)
        self.loaded = [uuid(1)]
        self.metadata = {}
        self.override = None
        self.after = None

    def connect(self, handle, address, size):
        # A new CLI invocation opens a new connection, not the old WS parser.
        self.http = None
        self.pending_ws.clear()
        self.socket_in.clear()
        return super().connect(handle, address, size)

    def send(self, handle, buf, size, flags):
        before = len(self.messages)
        count = super().send(handle, buf, size, flags)
        for message in self.messages[before:]:
            method, params = message['method'], message.get('params', {})
            if method == 'thread/loaded/list':
                remaining = sorted(t for t in self.loaded if t > (params.get('cursor') or ''))
                page = remaining[:params['limit']]
                result = {'data': page, 'nextCursor': page[-1] if len(remaining)>len(page) else None}
            elif method == 'thread/read':
                t = params['threadId']
                result = {'thread': self.metadata.get(t, {'id': t, 'source': 'cli', 'parentThreadId': None})}
            else:
                continue
            reply = {'id': message['id'], 'result': result}
            if self.override is not None:
                reply = self.override(message, reply)
            self.socket_in.extend(self.frame(reply))
            if self.after is not None:
                self.after(message)
        return count


class DiscoveryTests(unittest.TestCase):
    def setUp(self):
        bridge_support.bridge_short_socket_guard.isolate(self)
        # Includes the second home used by delivery's root-change regression.
        self.tmp = short_root('other-home/app-server-control/app-server-control.sock')
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.home = self.root/'h'
        self.control = self.home/'app-server-control'
        self.control.mkdir(parents=True)
        self.socket = self.control/'app-server-control.sock'
        self.socket.touch()
        self.state = self.root/'state'
        self.rebuild()
        self.addCleanup(lambda: self.assertEqual(self.k.handles, {}))
        self.addCleanup(lambda: self.assertEqual(self.k.ws_count, 0))
        require_closed_connections(self)

    def rebuild(self):
        self.k = LoadedKernel(self.root, self.home)
        self.k.files[str(self.home)] = {'private': False, 'protected': False}
        self.k.files[str(self.socket)] = {'reparse': True, 'tag': 0x80000023}
        self.k.processes[200] = (0, 134362090000012230, self.k.sid, False, 'codex.exe')
        self.k.peer = 200
        self.p = make_platform('windows', win_api=self.k.api)

    @contextmanager
    def scope(self, version='0.162.1', sql_root=None):
        env = dict(os.environ, CODEX_HOME=str(self.home), AB_STATE_DIR=str(self.state))
        env.pop('CODEX_SQLITE_HOME', None)
        if sql_root is not None: env['CODEX_SQLITE_HOME'] = str(sql_root)
        with (using_platform(self.p), patch.dict(os.environ, env, clear=True),
              patch.object(codex_version, 'read_cli_version', return_value=version),
              patch('time.monotonic', return_value=1000.0),
              windows_fixture('unix', str(self.socket))):
            yield

    def discover(self, **kw):
        with self.scope(**kw):
            return D.discover(self.p.transport)

    def sql(self, rows, edges=(), root=None):
        root = root or self.home
        root.mkdir(exist_ok=True)
        path = root/'state_5.sqlite'
        with closing(sqlite3.connect(path)) as db, db:
            db.executescript("CREATE TABLE threads(id TEXT PRIMARY KEY,source TEXT,name TEXT,cwd TEXT,history_mode TEXT DEFAULT 'paginated');"
                             'CREATE TABLE thread_spawn_edges(child_thread_id TEXT PRIMARY KEY,parent_thread_id TEXT);')
            db.executemany('INSERT INTO threads(id,source) VALUES (?,?)', rows)
            db.executemany('INSERT INTO thread_spawn_edges VALUES (?,?)', edges)
        return path

    def alias_row(self, **kw):
        return dict(alias='owner-task', threadId=uuid(1), rootIdentity=self.p.files.root_identity(self.home),
                    expiresAt=time.time()+3600, daemonPid=200, daemonBirth=str(self.k.processes[200][1]), **kw)

    def reject(self, result):
        self.assertFalse(result.complete)
        self.assertEqual(result.reason, 'discovery_incomplete')
        self.assertEqual(result.rows, ())
        with self.assertRaisesRegex(NativeFailure, 'discovery_incomplete'):
            result.select(uuid(1))

    def test_sql_first_codec_selection_no_autoselect_or_writes(self):
        self.sql([(uuid(1), 'cli')])
        result = self.discover()
        self.assertTrue(result.complete)
        self.assertTrue(result.select(uuid(1)).eligible)
        self.assertFalse(replace(result.rows[0],metadata_verified=False).eligible)
        # §91.2.1：短 ID 前缀要显式写 id:；裸 '00000000' 只按名字找，不改找 ID 前缀
        self.assertEqual(result.select('id:00000000').thread, uuid(1))
        with self.assertRaisesRegex(NativeFailure, 'target_not_found'): result.select('00000000')
        self.assertEqual(result.daemon, (200, '134362090000012230'))
        with self.assertRaisesRegex(NativeFailure, 'target_explicit_required'): result.select(None)
        self.assertEqual([m['method'] for m in self.k.messages],
                         ['initialize','initialized','thread/loaded/list','thread/loaded/list'])
        self.assertEqual(self.k.messages[0]['params'], {'clientInfo':{'name':'codex-tui','title':None,'version':'0.162.1'},
                                                      'capabilities':{'experimentalApi':True}})
        self.assertEqual(self.k.messages[2]['params'], {'cursor':None,'limit':256})
        self.assertEqual(bytes(self.k.http).split(b'\r\n')[0], b'GET /rpc HTTP/1.1')
        self.assertNotIn(b'/daemon/shutdown', self.k.socket_out)
        self.assertTrue(result.document()['providerEnabled'])
        self.assertNotIn('qualification', result.document())
        self.assertEqual(result.document()['warning'], D.NO_PANE_WARNING)
        self.assertEqual(result.document()['peers'][0]['warning'], D.NO_PANE_WARNING)
        self.assertEqual(result.document()['peers'][0]['runtime'], 'unknown')
        self.assertIsNone(result.document()['peers'][0]['pane'])
        self.assertFalse(self.state.exists())

    def title_helpers(self):
        roles = {r: uuid(n) for r, n in zip('ABC', (0xa1, 0xb1, 0xc1))}
        helpers = {r: uuid(n) for r, n in zip('ABC', (0xa2, 0xb2, 0xc2))}
        self.k.loaded = sorted([*roles.values(), *helpers.values()])
        path = self.sql([(t, 'vscode') for t in roles.values()])
        with closing(sqlite3.connect(path)) as db, db:
            for role, thread in roles.items():
                db.execute('UPDATE threads SET name=?,cwd=? WHERE id=?',
                           ('title '+role, 'C:\\w25\\projects\\'+role, thread))
        for role, thread in helpers.items():
            self.k.metadata[thread] = dict(id=thread, source='vscode', parentThreadId=None,
                ephemeral=True, threadSource='thread_title', name=None,
                cwd='C:\\w25\\projects\\'+role, preview='NOT_EXPORTED', turns=[])
        return roles, helpers

    def test_ephemeral_title_threads_hidden_and_not_ambiguous(self):
        roles, helpers = self.title_helpers()
        result = self.discover(version='0.163.0')
        self.assertTrue(result.complete)
        self.assertEqual(result.reason, 'complete')
        self.assertEqual({r.thread for r in result.rows}, set(roles.values()))
        self.assertEqual(result.select('codex@A').thread, roles['A'])
        self.assertTrue(all(r.eligible for r in result.rows))
        self.assertTrue(result.names_complete)
        doc = result.document()
        self.assertEqual((doc['hiddenEphemeral'], doc['loadedTotal'], doc['nativeReads']), (3, 6, 3))
        self.assertIs(doc['nativeReadBudgetHit'], False)
        self.assertTrue(all(p['metadataSource']=='sql' and p['sqlPresent'] and p['sourceClass']=='vscode'
                            and not p['parentPresent'] for p in doc['peers']))
        self.assertEqual({m['params']['threadId'] for m in self.k.messages if m['method']=='thread/read'}, set(helpers.values()))
        self.assertEqual(len([m for m in self.k.messages if m['method']=='thread/loaded/list']), 2)
        for t in helpers.values():
            with self.assertRaisesRegex(NativeFailure, 'target_not_found'): result.select(t)
        self.assertNotIn('NOT_EXPORTED', repr(doc))
        # Worker and aliases consume the very same filtered eligibility set.
        with patch.object(D, 'discover', return_value=result):
            self.assertEqual({e.ref.native_id for e in D.WorkerDiscovery(self.p.transport)()}, set(roles.values()))
        aliases = AliasSet({'title-helper': helpers['A']}).bind(result.home_identity, result.daemon,
                                                             {r.thread for r in result.rows if r.eligible})
        self.assertNotIn('title-helper', aliases.names)

    def test_ephemeral_only_exact_true_is_hidden(self):
        for value in (False, None, 0, 1, 'true', {}, [True]):
            with self.subTest(value=value):
                self.rebuild()
                self.k.metadata[uuid(1)] = dict(id=uuid(1), source='vscode', name='A', cwd='C:\\A')
                if value is not None: self.k.metadata[uuid(1)]['ephemeral'] = value
                result = self.discover()
                self.assertEqual(len(result.rows), 1)
                self.assertTrue(result.rows[0].eligible)
                self.assertEqual(result.document()['hiddenEphemeral'], 0)
                self.assertEqual(result.document()['peers'][0]['metadataSource'], 'native')
        self.k.metadata[uuid(1)]['ephemeral'] = True
        self.k.metadata[uuid(1)]['threadSource'] = 'future_feature'
        result = self.discover()
        self.assertEqual(result.rows, ())
        self.assertEqual(result.document()['hiddenEphemeral'], 1)

    def test_ephemeral_still_requires_matching_response_id(self):
        self.k.metadata[uuid(1)] = dict(id=uuid(2), source='vscode', ephemeral=True)
        self.reject(self.discover())

    def test_diagnostic_source_preserves_existing_sql_size_bound(self):
        # sql_source already declines this without parsing. Diagnostics must
        # not turn that bounded unknown into recursion/resource failure.
        source = '['*2500+']'*2500
        self.sql([(uuid(1), source)])
        error = None
        # The C JSON recursion ceiling differs between Python builds. Prove
        # the size boundary directly, not by expecting a RecursionError.
        with patch.object(Q.json, 'loads', wraps=json.loads) as parse:
            try:
                result = self.discover()
            except Exception as caught:
                error = caught
        self.assertEqual(sum(isinstance(c.args[0], str) and c.args[0] == source
                             for c in parse.call_args_list), 0)
        self.assertIsNone(error)
        if error is None:
            self.assertTrue(result.complete)
            self.assertEqual(result.reason, 'metadata_unverified')
            self.assertEqual(result.document()['peers'][0]['sourceClass'], 'other')
            self.assertFalse(result.rows[0].eligible)
            self.assertEqual(result.native_reads, 0)

    def test_pagination_all_before_filter_across_pages(self):
        self.k.loaded = [uuid(i) for i in range(1,258)]
        self.sql([(t, 'cli' if i==0 else '{"subagent":"review"}') for i,t in enumerate(self.k.loaded)],
                 [(t, uuid(9999)) for t in self.k.loaded[1:]])
        result = self.discover()
        self.assertTrue(result.complete, result.reason)
        self.assertEqual(len(result.rows), 257)
        self.assertEqual(sum(r.eligible for r in result.rows), 1)
        # id: 前缀在过滤资格之前按全部 257 行判歧义，不自动选唯一可投的根；裸值只按名字（§91.2.1）
        with self.assertRaisesRegex(NativeFailure, '^target_ambiguous$'): result.select('id:00000000')
        with self.assertRaisesRegex(NativeFailure, 'target_not_found'): result.select('00000000')
        self.assertTrue(result.select(uuid(1)).eligible)
        with self.assertRaisesRegex(NativeFailure, 'target_not_root'): result.select(uuid(257))
        pages = [m['params'] for m in self.k.messages if m['method']=='thread/loaded/list']
        self.assertEqual(pages, [{'cursor':None,'limit':256},{'cursor':uuid(256),'limit':256}]*2)

    def test_pagination_negative_shapes_and_loops(self):
        good = [uuid(i) for i in range(1,257)]
        cases = [None, {}, {'data':[]}, {'data':[], 'nextCursor':uuid(1)},
                 {'data':[uuid(1)],'nextCursor':uuid(1)}, {'data':'bad','nextCursor':None},
                 {'data':[uuid(1),uuid(1)],'nextCursor':None},
                 {'data':[uuid(2),uuid(1)],'nextCursor':None},
                 {'data':['not-uuid'],'nextCursor':None},
                 {'data':good+[uuid(257)],'nextCursor':None},
                 {'data':good,'nextCursor':uuid(255)},
                 {'data':good,'nextCursor':uuid(256)}]  # repeated first page => loop
        for value in cases:
            with self.subTest(value=str(value)[:50]):
                self.rebuild()
                self.k.override = lambda m,r: {**r, 'result':value} if m['method']=='thread/loaded/list' else r
                self.reject(self.discover())
                self.assertFalse(any(m['method']=='thread/read' for m in self.k.messages))

    def test_missing_later_page_and_limits(self):
        self.assertEqual((D.PAGE_SIZE,D.MAX_LOADED), (256,4096))
        self.k.loaded = [uuid(i) for i in range(1,258)]
        self.k.override = lambda m,r: {'id':m['id'],'error':{}} if m['params'].get('cursor') else r
        self.reject(self.discover())
        for count in (4096,4097):
            self.rebuild()
            self.k.loaded = [uuid(i) for i in range(1,count+1)]
            # SQL omitted: no more than32 metadata requests even for4096.
            result = self.discover()
            if count==4096:
                self.assertTrue(result.complete, result.reason)
                self.assertEqual(len(result.rows),4096)
            else:
                self.reject(result)
                self.assertEqual(sum(m['method']=='thread/loaded/list' for m in self.k.messages),16)

    def test_reader_short_middle_wrong_cursor_and_full_budget(self):
        from types import SimpleNamespace
        for first in ({'data':[uuid(1)],'nextCursor':uuid(1)},
                      {'data':[uuid(i) for i in range(1,257)],'nextCursor':uuid(300)}):
            pages=iter([first,{'data':[uuid(301)],'nextCursor':None}])
            reader=D.Reader(None,1)
            reader.request=lambda *args: next(pages)
            with self.assertRaisesRegex(NativeFailure,'discovery_incomplete'): reader.loaded()
        pages=iter([{'data':[uuid(i) for i in range(1,257)],'nextCursor':uuid(256)},
                    {'data':[uuid(257),uuid(258)],'nextCursor':None}])
        reader=D.Reader(None,1);reader.request=lambda *args:next(pages)
        with patch.object(D,'MAX_LOADED',257):
            with self.assertRaisesRegex(NativeFailure,'discovery_incomplete'): reader.loaded()

    def test_metadata_budget_unknown_and_display_privacy(self):
        self.k.loaded = [uuid(i) for i in range(1,35)]
        self.k.metadata[uuid(34)] = {'id':uuid(34),'source':'cli','name':'name\x1b\u202e\ud800',
                                    'cwd':'C:\\SECRET\\project','preview':'PRIVATE','turns':[]}
        self.k.metadata[uuid(33)] = {'id':uuid(33),'source':'cli','name':'', 'cwd':'C:\\SECRET\\project'}
        result = self.discover()
        self.assertTrue(result.complete)
        self.assertEqual(result.reason,'metadata_unverified')
        self.assertEqual([r.thread for r in result.rows if r.kind=='unknown'],[uuid(1),uuid(2)])
        reads = [m['params'] for m in self.k.messages if m['method']=='thread/read']
        self.assertEqual(len(reads),32)
        self.assertTrue(all(p['includeTurns'] is False for p in reads))
        self.assertEqual(result.rows[-1].label,'name\\u001b\\u202e\\ud800')
        self.assertEqual(result.rows[-2].label,'project')
        doc = json.dumps(result.document(),ensure_ascii=False)
        self.assertNotIn('PRIVATE',doc)
        self.assertNotIn('SECRET',doc)
        self.assertIn('元数据未核实',doc)
        self.assertLessEqual(len(D.display_label({'name':'a'*200})),96)
        with self.assertRaisesRegex(NativeFailure,'target_metadata_unverified'): result.select(uuid(1))
        with self.assertRaisesRegex(NativeFailure,'target_names_unverified'): result.select('project')
        with self.assertRaisesRegex(NativeFailure,'target_names_unverified'): result.select('0')

    def test_sql_classification_and_conflict_not_reversed(self):
        sources = ['cli','unknown','future','{"internal":"guardian"}',
                   '{"subagent":"review"}', '{"custom":"mine"}',
                   '{"subagent":{"thread_spawn":{"parent_thread_id":"'+uuid(99)+'","depth":1}}}']
        self.k.loaded=[uuid(i) for i in range(1,len(sources)+1)]
        self.sql(list(zip(self.k.loaded,sources)),[(uuid(6),uuid(99)),(uuid(7),uuid(98))])
        result=self.discover()
        self.assertEqual([r.kind for r in result.rows], ['root','unknown','unknown','internal','conflict','conflict','conflict'])
        self.assertEqual([m['params']['threadId'] for m in self.k.messages if m['method']=='thread/read'],[uuid(5)])
        for t in self.k.loaded[1:]:
            with self.assertRaises(NativeFailure): result.select(t)
        self.assertEqual(Q.sql_source(uuid(1),'"cli"',None).kind,'unknown')
        self.assertEqual(Q.sql_source(uuid(1),'mcp',None).kind,'root')

    def test_subagent_missing_parent_over_budget_is_explicitly_unverified(self):
        self.k.loaded=[uuid(i) for i in range(1,35)]
        self.sql([(t,'{"subagent":"review"}') for t in self.k.loaded])
        self.k.metadata={t:{'id':t,'source':{'subAgent':'review'},'parentThreadId':uuid(99)} for t in self.k.loaded}
        result=self.discover()
        self.assertTrue(result.complete)
        self.assertEqual(result.reason,'metadata_unverified')
        self.assertTrue(all(r.kind=='subagent' and not r.eligible for r in result.rows))
        self.assertEqual([r.thread for r in result.rows if not r.metadata_verified],[uuid(1),uuid(2)])
        self.assertEqual([r['metadata'] for r in result.document()['peers'][:2]],['元数据未核实']*2)
        out=io.StringIO()
        with redirect_stdout(out):D.print_peers(result)
        self.assertEqual(out.getvalue().count('元数据未核实'),2)

    def test_native_nonroots_and_invalid_metadata(self):
        self.k.loaded=[uuid(i) for i in range(1,6)]
        for i,source in enumerate(['unknown',{'internal':'guardian'},{'subAgent':'review'},'cli',{'custom':'ok'}],1):
            self.k.metadata[uuid(i)]={'id':uuid(i),'source':source,'parentThreadId':uuid(9) if i==4 else None}
        result=self.discover()
        self.assertEqual([r.kind for r in result.rows],['unknown','internal','subagent','conflict','root'])
        for t in self.k.loaded[:4]:
            with self.assertRaises(NativeFailure): result.select(t)
        self.rebuild()
        self.k.metadata[uuid(1)]={'id':uuid(2),'source':'cli'}
        self.reject(self.discover())

    def test_unloaded_daemon_root_change_and_deadline(self):
        for mode in ('unload','peer','root','deadline'):
            with self.subTest(mode=mode):
                self.rebuild()
                def change(m):
                    if m['method']!='thread/read': return
                    if mode=='unload': self.k.loaded=[]
                    elif mode=='peer': self.k.processes[200]=(0,999,self.k.sid,False,'codex.exe')
                    elif mode=='root': self.k.files[str(self.home)]={'reparse':True}
                self.k.after=change
                if mode=='deadline':
                    with patch.object(D,'WINDOWS_READ_SECONDS',0): self.reject(self.discover())
                elif mode=='unload':
                    result=self.discover()
                    self.assertTrue(result.complete)
                    with self.assertRaisesRegex(NativeFailure,'target_changed'):result.select(uuid(1))
                    self.assertFalse(any(r.eligible for r in result.rows))
                else: self.reject(self.discover())

    def test_version_observation_and_server_request_is_not_answered(self):
        for cli_version, server in (('0.163.0', '0.163.0'), ('0.162.1', 'unparseable'), (None, '0.163.0')):
            with self.subTest(cli=cli_version, server=server):
                self.rebuild()
                self.k.server_version=server
                result=self.discover(version=cli_version)
                self.assertTrue(result.complete, result)
                self.assertEqual(result.reason,'complete')
                self.assertNotEqual(self.k.socket_out,b'')
                self.assertTrue(any(n=='connect' for n,_ in self.k.calls))
                self.assertEqual(self.k.messages[0]['params']['clientInfo']['version'],cli_version or 'unknown')
        self.rebuild()
        self.k.override=lambda m,r: {'id':77,'method':'approval','params':{}}
        self.reject(self.discover())
        self.assertFalse(any(m.get('id')==77 for m in self.k.messages))
        with self.scope():
            class Client:
                def __init__(self):self.writes=[]
                def _send_json(self,*args):self.writes.append(args)
                def response(self,*args):return {'result':{}}
            client=Client()
            with self.assertRaisesRegex(NativeFailure,'read_method_rejected'):
                D.Reader(client,0).request('thread/queue/add',{})
            self.assertEqual(client.writes,[])

    def test_read_state_is_an_ignored_optional_response_field(self):
        for present, value in ((False, None), (True, None), (True, {'revision': 9, 'private': 'synthetic-read-state'})):
            with self.subTest(present=present, value=value):
                self.rebuild()
                self.k.server_version = '0.163.0'
                def response(message, reply):
                    if present and message['method'] == 'thread/read':
                        reply['result']['readState'] = value
                    return reply
                self.k.override = response
                result = self.discover()
                self.assertTrue(result.complete, result)
                self.assertEqual([(r.thread, r.kind) for r in result.rows], [(uuid(1), 'root')])
                self.assertNotIn('synthetic-read-state', repr(result.document()))
                self.assertTrue(all(m['params']['includeTurns'] is False for m in self.k.messages if m['method'] == 'thread/read'))

    def test_sql_location_readonly_pins_and_invalid_leaf_fallback(self):
        other=self.root/'sql'
        path=self.sql([(uuid(1),'exec')],root=other)
        calls=[]
        original=sqlite3.connect
        def connection(database, **kw):
            calls.append((database,kw))
            db=original(database,**kw)
            self.assertTrue(any(v.get('path')==str(path) for v in self.k.handles.values() if isinstance(v,dict)))
            return db
        with patch.object(Q.sqlite3,'connect',connection): result=self.discover(sql_root=other)
        self.assertTrue(result.select(uuid(1)).eligible)
        self.assertTrue(calls)
        self.assertIn('state_5.sqlite?mode=ro',calls[0][0])
        self.assertTrue(calls[0][1]['uri'])
        self.assertLessEqual(calls[0][1]['timeout'],0.05)
        self.assertFalse(any(m['method']=='thread/read' for m in self.k.messages))
        opened=[args for name,args in self.k.calls if name=='CreateFileW' and args[1] & 1]
        self.assertTrue(opened)
        # Observe leaf lease itself, not a directory's coincidental data access.
        with self.p.files.external_directory(other), Q.pinned_file(self.p.files,path,external=True):
            leaf=[v for v in self.k.handles.values() if v.get('path')==str(path)]
            self.assertTrue(leaf)
            self.assertEqual(leaf[0]['access'] & 1,1)
            self.assertEqual(leaf[0]['sharing'] & 4,4)
        for bad in ({'reparse':True,'tag':0xA000000C},{'private':False}):
            self.rebuild();self.k.files[str(path)]=bad
            result=self.discover(sql_root=other)
            self.assertTrue(result.complete)
            self.assertTrue(any(m['method']=='thread/read' for m in self.k.messages))
        self.rebuild();self.k.files[str(other)]={'reparse':True}
        self.reject(self.discover(sql_root=other))
        self.assertEqual(self.k.socket_out,b'')

    def test_sql_query_only_deadline_hardlink_and_parent_evidence(self):
        path=self.sql([(uuid(1),'cli'),(uuid(2),'{"subagent":"review"}')],[(uuid(2),uuid(1))])
        trace=[];original=sqlite3.connect
        def connect(database, **kw):
            db=original(database,**kw);db.set_trace_callback(trace.append);return db
        with patch.object(Q.sqlite3,'connect',connect):
            rows=Q.read_classes(self.p.files,self.home,[uuid(1),uuid(2)],1001,lambda:1000)
        self.assertEqual(rows[uuid(2)].parent,uuid(1))
        self.assertEqual(rows[uuid(1)].kind,'root')
        self.assertIn('PRAGMA query_only=ON',trace)
        self.assertTrue(any('e.parent_thread_id' in line for line in trace))
        self.assertEqual(Q.read_classes(self.p.files,self.home,[uuid(1)],1000,lambda:1000),{})
        os.link(path,self.root/'hardlink')
        self.assertEqual(Q.read_classes(self.p.files,self.home,[uuid(1)],1001,lambda:1000),{})
        (self.root/'hardlink').unlink()
        wal=Path(str(path)+'-wal');wal.touch();self.k.files[str(wal)]={'reparse':True}
        self.assertEqual(Q.read_classes(self.p.files,self.home,[uuid(1)],1001,lambda:1000),{})

    def test_status_and_shared_result_views_warning_without_discovery(self):
        with self.scope(), Store.open(self.state) as store:
            task,_=store.create_task(title='fixture',flow=Flow.HANDOFF,origin=None,origin_class=None,
                                    reviewer=None,target=replace(bridge_support.ref(),native_id=uuid(1),pane=None),
                                    body='synthetic',refs=[],now=time.time())
            doc=views._task_document(store,task)
            self.assertIn('targetWindowWarning',doc)
            self.assertEqual(doc['targetWindowWarning'],D.NO_PANE_WARNING)
            out=io.StringIO()
            with redirect_stdout(out): views._print_task(store,task,now=time.time(),show_body=False)
            self.assertIn(D.NO_PANE_WARNING,out.getvalue())
            for json_mode in (True,False):
                out=io.StringIO()
                with redirect_stdout(out),patch.object(D,'discover',side_effect=AssertionError('status must stay local')),\
                        patch.object(cli, '_ensure_worker', return_value=False):
                    self.assertEqual(cli.main(['status',task.id]+(['--json'] if json_mode else [])),0)
                self.assertIn('可能没有窗口在显示',out.getvalue())
                self.assertIn('codex resume',out.getvalue())
            attempts=store.attempts(task.id)
            self.assertIsNone(views._no_pane_warning([replace(attempts[0],target=replace(attempts[0].target,pane='%2'))]))
            self.assertIsNone(views._no_pane_warning([replace(attempts[0],target=replace(attempts[0].target,provider=Provider.CLAUDE))]))
            # Shared view policy only: no host-specific Linux backend is needed.
            with using_platform(SimpleNamespace(name='linux')):
                self.assertNotIn('targetWindowWarning',views._task_document(store,task))
            self.assertEqual(self.k.messages,[])

    def test_alias_naming_never_elevates_or_overrides_unique_all(self):
        row=self.alias_row()
        aliases=AliasFile(self.p.files,self.state)
        aliases.replace([row])
        result=self.discover()
        self.assertEqual(result.select('owner-task').thread,uuid(1))
        self.assertEqual(result.document()['peers'][0]['aliases'],['owner-task'])
        for kind in ('unknown','internal','subagent','conflict'):
            with self.assertRaises(NativeFailure):
                replace(result,rows=(replace(result.rows[0],kind=kind),)).select('owner-task')
        with self.assertRaisesRegex(NativeFailure,'target_not_found'):
            replace(result,rows=()).select('owner-task')
        with self.assertRaisesRegex(NativeFailure,'discovery_incomplete'):
            replace(result,complete=False).select('owner-task')
        collision=replace(result,rows=result.rows+(D.Candidate(uuid(2),'subagent'),),aliases=AliasSet({'00000000':uuid(1)}))
        # ID 形状的 alias 键不生效：裸值只按名字，既不经 alias 选中 uuid(1)，也不并入前缀（§91.2.1）；
        # id: 前缀仍按全部行（含子代理）判歧义
        with self.assertRaisesRegex(NativeFailure,'target_not_found'): collision.select('00000000')
        with self.assertRaisesRegex(NativeFailure,'target_ambiguous'): collision.select('id:00000000')

    def test_alias_private_limits_expiry_cleanup_no_read_side_effects(self):
        alias=AliasFile(self.p.files,self.state);row=self.alias_row();now=time.time()
        alias.replace([row,{**row,'alias':'expired','expiresAt':now-1}],now=now)
        path=alias.root/'codex.json';raw=path.read_bytes()
        self.assertNotIn(b'expired',raw)
        self.assertEqual(alias.load(row['rootIdentity'],now).names,{'owner-task':uuid(1)})
        self.assertEqual(alias.load('b'*64,now).names,{})
        self.assertEqual(alias.load(row['rootIdentity'],now+4000).names,{})
        self.assertEqual(path.read_bytes(),raw)
        with self.assertRaises(ValueError): alias.replace([{**row,'expiresAt':now+MAX_AGE+1}],now=now)
        for rows in ([row,row],[{**row,'alias':'../bad'}],[{**row,'threadId':'short'}],[{**row,'expiresAt':float('nan')}],
                     [{**row,'unexpected':'SECRET'}],[{**row,'alias':f'item{i}'} for i in range(257)]):
            with self.assertRaises(ValueError): alias.replace(rows)
        for raw_bad in (b'{',b'x'*65537,json.dumps({'schema':1,'aliases':[row]}).encode()+b' '*65537,
                        json.dumps({'schema':2,'aliases':[row]}).encode(),
                        json.dumps({'schema':True,'aliases':[row]}).encode(),
                        json.dumps({'schema':1,'aliases':[row,row]}).encode()):
            self.p.files.atomic_write(alias.root,raw_bad,name='codex.json',prefix='.test.')
            self.assertEqual(alias.load(row['rootIdentity']).reason,'alias_store_unverified')
        alias.replace([row]);self.k.files[str(path)]={'private':False}
        self.assertEqual(alias.load(row['rootIdentity']).reason,'ok')
        self.assertTrue(self.k.files[str(path)]['private'])
        self.k.files[str(path)]={};alias.replace([])
        self.assertEqual(alias.load(row['rootIdentity']).names,{})

    def workdir_fixture(self):
        """§95.3：SQL 行（paginated）给 uuid(1)/uuid(3)，uuid(2) 没有 SQL 行、走 thread/read。"""
        self.k.loaded = [uuid(1), uuid(2), uuid(3)]
        path = self.sql([(uuid(1), 'cli'), (uuid(3), 'cli')])
        with closing(sqlite3.connect(path)) as db, db:
            db.execute('UPDATE threads SET name=?,cwd=? WHERE id=?', (None, 'C:\\w\\proj-a', uuid(1)))
            db.execute('UPDATE threads SET name=?,cwd=? WHERE id=?', ('root dir', 'C:\\', uuid(3)))
        self.k.metadata[uuid(2)] = dict(id=uuid(2), source='cli', parentThreadId=None, name='Fix bug',
                                        cwd='D:/w/a\u202eb/', preview='NOT_EXPORTED', turns=[])

    def test_workdir_tail_from_sql_and_native_reads(self):
        self.workdir_fixture()
        result = self.discover()
        # 原文末段：Windows 同时认 \\ 与 /；根目录视为无；不拿已转义的 cwd_label
        self.assertEqual({r.thread: r.workdir for r in result.rows},
                         {uuid(1): 'proj-a', uuid(2): 'a\u202eb', uuid(3): None})
        self.assertEqual(result.endpoint(result.rows[1]).workdir, 'a\u202eb')
        self.assertEqual([row['workdir'] for row in result.document()['peers']], ['proj-a', 'a\\u202eb', None])
        doc = json.dumps(result.document(), ensure_ascii=False)
        self.assertNotIn('D:/w', doc)
        self.assertNotIn('NOT_EXPORTED', doc)

    def test_workdir_suffix_in_the_codex_peer_lines(self):
        self.workdir_fixture()
        out = io.StringIO()
        result = self.discover()
        with redirect_stdout(out):
            D.print_peers(result)
        lines = {uuid(n): next(line for line in out.getvalue().splitlines() if 'target=codex@id:' + uuid(n) in line)
                 for n in (1, 2, 3)}
        self.assertNotIn('目录', lines[uuid(1)])  # 无名时主名就是 cwd 末段：与显示的名字相同不重复
        self.assertTrue(lines[uuid(2)].endswith('  目录 a\\u202eb'), lines[uuid(2)])
        self.assertNotIn('目录', lines[uuid(3)])

    def test_invalid_native_fields_give_no_directory(self):
        # 审计 r1 Fable Y13：thread/read 的 name/cwd 类型无效时不取名字，也不取目录
        self.k.loaded = [uuid(1)]
        self.k.metadata[uuid(1)] = dict(id=uuid(1), source='cli', parentThreadId=None, name=3, cwd='C:\\w\\proj-a')
        self.assertIsNone(self.discover().rows[0].workdir)

    def test_a_name_taken_from_a_long_directory_is_not_repeated(self):
        # 审计 r1 Opus P3-7：无名线程的主名取自 cwd 末段（按 96 字符截断），目录 100 字符时也不再写一次「目录」；
        # 按名字来源判断：同一目录下有名字的线程照常显示目录
        long_dir = 'd' * 100
        self.k.loaded = [uuid(1), uuid(2), uuid(3)]
        path = self.sql([(uuid(1), 'cli'), (uuid(2), 'cli')])
        with closing(sqlite3.connect(path)) as db, db:
            db.execute('UPDATE threads SET name=?,cwd=? WHERE id=?', (None, 'C:\\w\\' + long_dir, uuid(1)))
            db.execute('UPDATE threads SET name=?,cwd=? WHERE id=?', ('Fix bug', 'C:\\w\\' + long_dir, uuid(2)))
        self.k.metadata[uuid(3)] = dict(id=uuid(3), source='cli', parentThreadId=None, name='',
                                        cwd='D:/w/' + long_dir + '/')  # 原生读：空名同样取自 cwd
        result = self.discover()
        self.assertEqual([r.workdir for r in result.rows], [long_dir] * 3)
        out = io.StringIO()
        with redirect_stdout(out):
            D.print_peers(result)
        lines = {n: next(line for line in out.getvalue().splitlines() if 'target=codex@id:' + uuid(n) in line)
                 for n in (1, 2, 3)}
        self.assertNotIn('目录', lines[1])
        self.assertNotIn('目录', lines[3])
        self.assertTrue(lines[2].endswith('  目录 ' + long_dir), lines[2])
        self.assertEqual([row['workdir'] for row in result.document()['peers']], [long_dir] * 3)  # JSON 照给
        # 发布侧（Discovery.endpoint 进快照）：名字就是目录名的行不带 workdir，有名行照常
        self.assertEqual([result.endpoint(r).workdir for r in result.rows], [None, long_dir, None])

    def test_sql_failure_clears_collected_workdirs(self):
        self.sql([(uuid(1), 'cli')])
        with closing(sqlite3.connect(self.home/'state_5.sqlite')) as db, db:
            db.execute('UPDATE threads SET cwd=? WHERE id=?', ('C:\\w\\proj-a', uuid(1)))
        workdirs: dict[str, str] = {}
        cwd_named: set[str] = set()
        with self.scope():
            Q.read_classes(self.p.files, self.home, [uuid(1)], 1001, lambda: 1000, labels={}, workdirs=workdirs,
                           cwd_named=cwd_named)
        self.assertEqual((workdirs, cwd_named), ({uuid(1): 'proj-a'}, {uuid(1)}))  # 名字为空：主名取自 cwd
        with self.scope(), patch.object(Q, 'sql_source', side_effect=ValueError('synthetic')):
            self.assertEqual(Q.read_classes(self.p.files, self.home, [uuid(1)], 1001, lambda: 1000, labels={},
                                            workdirs=workdirs, cwd_named=cwd_named), {})
        # 出错时与 labels 一起清空，不留半批（审计 r1 Fable N9：名字来源标记同样清空）
        self.assertEqual((workdirs, cwd_named), ({}, set()))

    def test_name_source_marker_needs_the_name_key(self):
        # 审计 r1 Fable N10：响应没有 name 键是旧服务端、名字来源未知，不算取自 cwd；空名与 null 才算
        from agentstatus_bridge.platforms.windows.thread_names import name_from_cwd
        cwd = 'C:\\w\\proj-a'
        self.assertFalse(name_from_cwd({'cwd': cwd}))
        self.assertTrue(name_from_cwd({'name': None, 'cwd': cwd}))
        self.assertTrue(name_from_cwd({'name': '', 'cwd': cwd}))
        self.assertFalse(name_from_cwd({'name': 'Foo', 'cwd': cwd}))
        self.assertFalse(name_from_cwd({'name': None, 'cwd': 7}))
        self.assertFalse(name_from_cwd({'name': None, 'cwd': '  '}))

    def test_a_verified_subagent_row_still_shows_its_directory(self):
        # 审计 r1 Opus MR4：已核实的子代理行不显示名字（codex@id:…），即使 SQL 名为空、主名来源是 cwd，
        # 本机文字也照常写「目录」——只有显示的是原生主名时才因名字就是目录名而省略
        self.k.loaded = [uuid(1), uuid(2)]
        spawn = '{"subagent":{"thread_spawn":{"parent_thread_id":"' + uuid(1) + '","depth":1}}}'
        path = self.sql([(uuid(1), 'cli'), (uuid(2), spawn)], [(uuid(2), uuid(1))])
        with closing(sqlite3.connect(path)) as db, db:
            db.execute('UPDATE threads SET name=?,cwd=? WHERE id=?', ('Lead', 'C:\\w\\lead', uuid(1)))
            db.execute('UPDATE threads SET name=?,cwd=? WHERE id=?', (None, 'C:\\w\\sub-x', uuid(2)))
        result = self.discover()
        child = next(r for r in result.rows if r.thread == uuid(2))
        self.assertEqual((child.kind, child.metadata_verified, child.name_from_cwd), ('subagent', True, True))
        self.assertFalse(child.name_is_workdir)
        out = io.StringIO()
        with redirect_stdout(out):
            D.print_peers(result)
        line = next(line for line in out.getvalue().splitlines() if '[subagent]' in line)  # 子代理行不可投，没有 target ID
        self.assertTrue(line.endswith('  目录 sub-x'), line)

    def test_a_native_name_clears_the_sql_directory_name_marker(self):
        # 审计 r1 Fable N8 / Opus MR5：SQL 子代理行没有父线程、名字为空（记下「主名取自 cwd」），随后补读的原生
        # 响应给出 name='Foo'：主名换成 Foo，旧标记必须撤销，否则会把这一行的目录藏掉
        self.k.loaded = [uuid(1)]
        path = self.sql([(uuid(1), '{"subagent":"review"}')])
        with closing(sqlite3.connect(path)) as db, db:
            db.execute('UPDATE threads SET name=?,cwd=? WHERE id=?', (None, 'C:\\w\\proj-x', uuid(1)))
        self.k.metadata[uuid(1)] = dict(id=uuid(1), source='cli', parentThreadId=None, name='Foo',
                                        cwd='C:\\w\\proj-x')
        result = self.discover()
        self.assertIn(uuid(1), [m['params']['threadId'] for m in self.k.messages if m['method'] == 'thread/read'])
        [row] = result.rows
        self.assertEqual(row.native_name, NameSource('named', 'Foo'))
        self.assertFalse(row.name_from_cwd)
        self.assertFalse(row.name_is_workdir)

    def test_peers_cli_real_entry_readonly_text_json_and_send_gate(self):
        for json_mode in (False,True):
            self.rebuild()
            with self.scope(),patch.object(cli,'_refresh_summary',side_effect=AssertionError('no state writes')):
                out=io.StringIO()
                with redirect_stdout(out): code=cli.main(['peers']+(['--json'] if json_mode else []))
                self.assertEqual(code,0)
                text=out.getvalue();self.assertIn('可能没有窗口在显示',text)
                self.assertIn('codex resume',text)
                self.assertIn('审批',text)
                if json_mode:
                    doc=json.loads(text);self.assertEqual(len(doc['peers']),1)
                    self.assertTrue(doc['providerEnabled'])
                with redirect_stderr(io.StringIO()):
                    self.assertEqual(cli.main(['send','--to',uuid(1),'--file','does-not-exist','--title','fixture','--no-wait']),3)
                self.assertFalse(self.state.exists())


class AllDevicesPeersTests(unittest.TestCase):
    """§94.6：Windows `ab peers --all-devices` 先列本机一节（与不带参数的 peers 同一份列表）再列远端，JSON 与 Linux 同构。

    假 Win32 内核 + 合成 daemon/SQL 的真实 Codex 发现；Claude 原生 peer 用合成的发现结果；远端部分替换成固定输出，
    未启用联邦的情形走真实 _fed_all_devices(_text)。argv 经真实解析器。
    """
    setUp = DiscoveryTests.setUp
    rebuild = DiscoveryTests.rebuild
    scope = DiscoveryTests.scope
    sql = DiscoveryTests.sql
    CLAUDE = '0000000c-cccc-4ccc-8ccc-00000000000c'
    REMOTE_LINE = '设备 win2〔bbbbbbbb〕：在线，目录完整'

    def claude(self):
        from agentstatus_bridge.model import Endpoint, EndpointRef, NameView
        from agentstatus_bridge.native_names import name_source
        from agentstatus_bridge.platforms.windows import claude_discovery
        lead = Endpoint(EndpointRef(Provider.CLAUDE, self.CLAUDE, 300, 'win-filetime:1', label='lead', data_root='c'*64),
                        name='lead', name_source=name_source('lead'),
                        name_view=NameView(Provider.CLAUDE, self.CLAUDE, 'lead', 'lead', True, self.CLAUDE[:8]))
        return claude_discovery.Discovery((lead,), True, 'complete')

    def run_peers(self, *argv, remote=True):
        from agentstatus_bridge.platforms.windows import commands
        out = io.StringIO()
        patches = [patch.object(commands, 'claude_evidence', return_value=self.claude()),
                   patch.object(cli, '_refresh_summary', side_effect=AssertionError('no state writes')),
                   patch.object(cli, '_revive_for_federation')]
        if remote:
            patches += [patch.object(cli, '_fed_all_devices_text', side_effect=lambda: print(self.REMOTE_LINE)),
                        patch.object(cli, '_fed_all_devices', return_value=[{'device': 'win2', 'peers': []}])]
        with self.scope(), patch.dict(os.environ, {'AB_DEVICE': 'winbox'}), ExitStack() as stack, redirect_stdout(out):
            mocks = [stack.enter_context(item) for item in patches]
            self.assertEqual(cli.main(['peers', *argv]), 0)
        self.assertEqual(mocks[2].call_count, 1)  # 本机列表之后照旧按联邦待办补拉
        self.assertFalse(self.state.exists())  # 只读：不建本机账本
        return out.getvalue()

    def legacy_text(self):
        """§94.6 之前 Windows peers 分支的文字输出，逐行照抄作对照：不带参数的输出必须与它逐字节相同。"""
        from agentstatus_bridge.native_names import NameBook
        from agentstatus_bridge.labels import reason_text
        out = io.StringIO()
        with self.scope(), redirect_stdout(out):
            result, peers = D.discover(self.p.transport), self.claude()
            D.print_peers(result)
            print('Windows Claude 原生 peer：' + ('发现完整' if peers.complete else reason_text(peers.reason)))
            names = NameBook.of((*peers.endpoints, *peers.duplicates))
            for endpoint in (*peers.endpoints, *peers.duplicates):
                issues = '；'.join(reason_text('target_' + issue) for issue in endpoint.issues)
                print(names.text(endpoint.ref) + '  target=claude@id:' + endpoint.ref.native_id
                      + '  [root] 状态未知' + ('  ' + issues if issues else ''))
        return out.getvalue()

    def legacy_document(self):
        with self.scope():
            document = D.discover(self.p.transport).document()
        peers = self.claude()
        document['peers'] = list(document['peers']) + peers.document()
        document['claudeDiscovery'] = {'complete': peers.complete, 'reason': peers.reason}
        # §99.3 只加的可选键：合成的 Claude 结果没有取名来源码，所以计数全为零
        document['claudeTitles'] = {'found': 0, 'fallback': {}}
        return json.loads(json.dumps(document))

    def test_plain_peers_output_is_byte_for_byte_unchanged(self):
        self.assertEqual(self.run_peers(), self.legacy_text())
        # JSON 也比原始字节：旧分支经 _print_json 打印（排序、两格缩进、不转义中文、结尾换行），不只比结构
        self.assertEqual(self.run_peers('--json'),
                         json.dumps(self.legacy_document(), ensure_ascii=False, indent=2, sort_keys=True) + '\n')

    def test_all_devices_text_lists_the_local_section_before_remote_devices(self):
        local = self.run_peers()
        text = self.run_peers('--all-devices')
        self.assertEqual(text, '设备 winbox（本机）：\n' + local + self.REMOTE_LINE + '\n')
        self.assertIn('target=codex@id:' + uuid(1), local)  # 本机 Codex 候选
        self.assertIn('claude@lead〔' + self.CLAUDE[:8] + '〕  target=claude@id:' + self.CLAUDE, local)  # 本机 Claude peer
        self.assertLess(text.index('（本机）'), text.index('claude@id:' + self.CLAUDE))
        self.assertLess(text.index('claude@id:' + self.CLAUDE), text.index(self.REMOTE_LINE))

    def test_all_devices_json_is_the_local_document_plus_devices(self):
        document = json.loads(self.run_peers('--all-devices', '--json'))
        self.assertEqual(document, {**json.loads(self.run_peers('--json')), 'devices': [{'device': 'win2', 'peers': []}]})
        self.assertEqual({row['provider'] for row in document['peers']}, {'codex', 'claude'})

    def test_device_flag_still_lists_only_that_remote_device(self):
        # §94.6「--device B 不变（只看 B）」：Windows 上照旧经 _fed_peers，不出本机标题与本机行（Fable 946 P2-1）
        from agentstatus_bridge.platforms.windows import commands
        out = io.StringIO()
        with self.scope(), patch.dict(os.environ, {'AB_DEVICE': 'winbox'}), \
                patch.object(commands, 'claude_evidence', return_value=self.claude()), \
                patch.object(cli, '_refresh_summary', return_value=None), \
                patch.object(cli, '_fed_peers', side_effect=lambda _args: print(self.REMOTE_LINE) or 0) as remote, \
                redirect_stdout(out):
            self.assertEqual(cli.main(['peers', '--device', 'win2']), 0)
        self.assertEqual(remote.call_count, 1)
        self.assertEqual(remote.call_args.args[0].device, 'win2')
        self.assertEqual(out.getvalue(), self.REMOTE_LINE + '\n')
        self.assertNotIn('（本机）', out.getvalue())
        self.assertNotIn(uuid(1), out.getvalue())
        self.assertNotIn(self.CLAUDE, out.getvalue())

    def test_local_rows_show_the_workdir_tail_unless_it_equals_the_name(self):
        # §95.3：Codex 与 Claude 两部分都在行尾加「目录 <末段>」；与显示的名字相同（区分大小写）时不加
        from agentstatus_bridge.platforms.windows import claude_discovery
        self.sql([(uuid(1), 'cli')])
        with closing(sqlite3.connect(self.home/'state_5.sqlite')) as db, db:
            db.execute('UPDATE threads SET name=?,cwd=? WHERE id=?', ('Fix bug', 'C:\\w\\proj-a\\', uuid(1)))
        lead = self.claude().endpoints[0]
        twin = replace(lead, ref=replace(lead.ref, native_id=self.CLAUDE.replace('c', 'd'), pid=301))
        peers = claude_discovery.Discovery((replace(lead, workdir='Lead'), replace(twin, workdir='lead')), True, 'complete')
        with patch.object(self, 'claude', return_value=peers):
            text = self.run_peers(remote=False)
            rows = json.loads(self.run_peers('--json', remote=False))['peers']
        codex = next(line for line in text.splitlines() if 'target=codex@id:' in line)
        self.assertTrue(codex.endswith('  目录 proj-a'), codex)
        claude = [line for line in text.splitlines() if 'target=claude@id:' in line]
        self.assertTrue(claude[0].endswith('  目录 Lead'), claude[0])
        self.assertEqual([row['workdir'] for row in rows], ['proj-a', 'Lead', 'lead'])
        self.assertTrue(claude[1].endswith('状态未知'), claude[1])  # 第二行未核实也照规则比较显示名

    def test_claude_rows_escape_the_directory_in_text_and_json(self):
        # 审计 r1 Fable P2-1（Y10）与 Opus P3-1（MN3）：注册信息 cwd 末段带 RLO，文字行尾与 document() 都是转义文本
        from agentstatus_bridge.platforms.windows import claude_discovery
        data = {'pid': 300, 'sessionId': self.CLAUDE, 'name': 'lead', 'cwd': 'C:\\w\\a\u202eb'}
        found = claude_discovery.project(data, 300, '1', 'c' * 64)
        peers = claude_discovery.Discovery((found,), True, 'complete')
        self.assertEqual(peers.document()[0]['workdir'], 'a\\u202eb')
        with patch.object(self, 'claude', return_value=peers):
            text = self.run_peers(remote=False)
        claude = next(line for line in text.splitlines() if 'target=claude@id:' in line)
        self.assertTrue(claude.endswith('  目录 a\\u202eb'), claude)
        self.assertNotIn('\u202e', text)

    def test_claude_registry_projection_keeps_only_the_tail(self):
        from agentstatus_bridge.platforms.windows import claude_discovery
        data = {'pid': 300, 'sessionId': self.CLAUDE, 'name': 'lead', 'cwd': 'C:\\Users\\x\\proj\\'}
        self.assertEqual(claude_discovery.project(data, 300, '1', 'c' * 64).workdir, 'proj')
        for cwd in ('C:\\', None, 7, ''):
            self.assertIsNone(claude_discovery.project({**data, 'cwd': cwd}, 300, '1', 'c' * 64).workdir)

    def status_fixture(self, *, statuses=True):
        """§96 完整输出夹具：Codex 两个根线程（active、idle），Claude 两个会话（注册信息 busy、idle）；
        statuses 为假时去掉两边的状态字段，作对照。"""
        from agentstatus_bridge.platforms.windows import claude_discovery
        self.k.loaded = [uuid(1), uuid(2)]
        path = self.home/'state_5.sqlite'
        if not path.exists():  # 同一用例里重建夹具时沿用已有的库，只改行，不在用例中途删库
            path = self.sql([(uuid(1), 'cli'), (uuid(2), 'cli')])
        with closing(sqlite3.connect(path)) as db, db:
            db.execute('UPDATE threads SET name=?,cwd=? WHERE id=?', ('impl', 'C:\\w\\proj-a', uuid(1)))
            db.execute('UPDATE threads SET name=?,cwd=? WHERE id=?', ('review', 'C:\\w\\proj-b', uuid(2)))
        self.k.metadata[uuid(1)] = dict(id=uuid(1), source='cli', parentThreadId=None, name='impl',
                                        cwd='C:\\w\\proj-a', status=thread_status('active'))
        self.k.metadata[uuid(2)] = dict(id=uuid(2), source='cli', parentThreadId=None, name='review',
                                        cwd='C:\\w\\proj-b', status=thread_status('idle'))
        if not statuses:
            for n in (1, 2):
                del self.k.metadata[uuid(n)]['status']
        second = self.CLAUDE.replace('c', 'd')
        rows = []
        for pid, session, name, status in ((300, self.CLAUDE, 'lead', 'busy'), (301, second, 'helper', 'idle')):
            data = {'pid': pid, 'sessionId': session, 'peerProtocol': 1, 'messagingSocketPath': pipe(pid),
                    'name': name, 'cwd': 'C:\\w\\proj-c', 'status': status, 'statusUpdatedAt': 1}
            if not statuses:
                del data['status'], data['statusUpdatedAt']
            rows.append(claude_discovery.project(data, pid, '1', 'c' * 64))
        return claude_discovery.Discovery(tuple(rows), True, 'complete').with_views()  # 与真实发现一样带名字投影

    def test_full_peers_output_with_busy_and_idle_sessions(self):
        # §96.5 假内核：Windows `ab peers` 文字与 --json 在 Claude busy/idle、Codex active/idle 下的完整输出
        with patch.object(self, 'claude', return_value=self.status_fixture()):
            text = self.run_peers(remote=False)
            document = json.loads(self.run_peers('--json', remote=False))
        second = self.CLAUDE.replace('c', 'd')
        self.assertEqual(text, '\n'.join([
            D.NO_PANE_WARNING,
            f'codex@impl〔{uuid(1)}〕  target=codex@id:{uuid(1)}  [root] 忙  目录 proj-a',
            f'codex@review〔{uuid(2)}〕  target=codex@id:{uuid(2)}  [root] 空闲  目录 proj-b',
            'Windows Claude 原生 peer：发现完整',
            f'claude@lead〔{self.CLAUDE[:8]}〕  target=claude@id:{self.CLAUDE}  [root] 忙  目录 proj-c',
            f'claude@helper〔{second[:8]}〕  target=claude@id:{second}  [root] 空闲  目录 proj-c',
        ]) + '\n')
        self.assertEqual([(row['provider'], row['nativeId'], row['runtime']) for row in document['peers']],
                         [('codex', uuid(1), 'busy'), ('codex', uuid(2), 'idle'),
                          ('claude', self.CLAUDE, 'busy'), ('claude', second, 'idle')])
        self.assertFalse(any('runtimeSource' in row for row in document['peers']))
        # 同一夹具去掉状态字段：JSON 除各行 runtime 外逐键相同（形状、nativeReads 等诊断键都不变）
        self.rebuild()
        with patch.object(self, 'claude', return_value=self.status_fixture(statuses=False)):
            plain = json.loads(self.run_peers('--json', remote=False))
        self.assertEqual([row['runtime'] for row in plain['peers']], ['unknown'] * 4)
        strip = lambda doc: {**doc, 'peers': [{k: v for k, v in row.items() if k != 'runtime'} for row in doc['peers']]}
        self.assertEqual(strip(document), strip(plain))

    def test_duplicate_claude_rows_show_their_status(self):
        # 审计 r1 Fable P3-5 第二项：同一会话起了两个进程（duplicates，不可选但照样列出）的行也显示各自的忙闲
        from agentstatus_bridge.platforms.windows import claude_discovery
        twin = self.CLAUDE.replace('c', 'e')
        rows = []
        for pid, status in ((310, 'busy'), (311, 'waiting')):
            data = {'pid': pid, 'sessionId': twin, 'peerProtocol': 1, 'messagingSocketPath': pipe(pid),
                    'name': 'twin', 'status': status}
            rows.append(claude_discovery.project(data, pid, '1', 'c' * 64))
        peers = claude_discovery.Discovery((), True, 'complete', duplicates=tuple(rows)).with_views()
        with patch.object(self, 'claude', return_value=peers):
            text = self.run_peers(remote=False)
        lines = [line for line in text.splitlines() if f'target=claude@id:{twin}' in line]
        self.assertEqual(len(lines), 2)
        self.assertIn('  [root] 忙', lines[0])
        self.assertIn('  [root] 等待用户', lines[1])

    def test_without_federation_only_the_local_section_is_listed(self):
        local = self.run_peers(remote=False)
        self.assertEqual(self.run_peers('--all-devices', remote=False), '设备 winbox（本机）：\n' + local)
        document = json.loads(self.run_peers('--all-devices', '--json', remote=False))
        self.assertEqual(document, {**json.loads(self.run_peers('--json', remote=False)), 'devices': []})


def thread_status(kind, *flags):
    """上游 ThreadStatus 的 serde 形状（0.169 v2/thread.rs:1749）：tag=type，active 带 activeFlags 字符串列表。"""
    return {'type': kind, 'activeFlags': list(flags)} if kind == 'active' else {'type': kind}


def pipe(n):
    return '\\\\.\\pipe\\cc-msg-' + f'{n:032x}'


class RuntimeMappingTests(unittest.TestCase):
    """§96.2 两张映射：Claude 注册信息 status（与 Linux 共用）与 Codex thread.status；纯函数，两种系统都跑。"""

    def test_claude_registry_status_table(self):
        from agentstatus_bridge.model import CLAUDE_REGISTRY_STATUS, Runtime, claude_registry_runtime
        cases = {'idle': Runtime.IDLE, 'busy': Runtime.BUSY, 'shell': Runtime.BUSY, 'waiting': Runtime.WAITING}
        self.assertEqual(CLAUDE_REGISTRY_STATUS, cases)
        for value, expected in cases.items():
            self.assertIs(claude_registry_runtime(value), expected, value)
        for value in (None, 1, ['busy'], 'Busy', 'future', ''):
            self.assertIs(claude_registry_runtime(value), Runtime.UNKNOWN, value)

    def test_windows_claude_registry_projection_reads_status(self):
        from agentstatus_bridge.model import Runtime
        from agentstatus_bridge.platforms.windows import claude_discovery
        session = '0000000c-cccc-4ccc-8ccc-00000000000c'
        data = {'pid': 300, 'sessionId': session, 'peerProtocol': 1, 'messagingSocketPath': pipe(1), 'name': 'lead'}
        cases = {'idle': Runtime.IDLE, 'busy': Runtime.BUSY, 'shell': Runtime.BUSY, 'waiting': Runtime.WAITING,
                 'future': Runtime.UNKNOWN, 7: Runtime.UNKNOWN}
        for value, expected in cases.items():
            found = claude_discovery.project({**data, 'status': value}, 300, '1', 'c' * 64)
            self.assertEqual((found.runtime, found.runtime_source), (expected, 'claude_registry'), value)
        missing = claude_discovery.project(data, 300, '1', 'c' * 64)
        self.assertEqual((missing.runtime, missing.runtime_source), (Runtime.UNKNOWN, 'claude_registry'))

    def test_codex_thread_status_table(self):
        from agentstatus_bridge.model import Runtime
        from agentstatus_bridge.transports.codex_rpc import thread_runtime
        def read(status):
            return {'thread': {'id': uuid(1), 'status': status}}
        cases = [(thread_status('idle'), Runtime.IDLE), (thread_status('active'), Runtime.BUSY),
                 (thread_status('active', 'waitingOnApproval'), Runtime.WAITING),
                 (thread_status('active', 'waitingOnUserInput'), Runtime.WAITING),
                 (thread_status('active', 'futureFlag', {'x': 1}, 3), Runtime.BUSY),  # 不认识的旗标当作没有
                 (thread_status('active', 'futureFlag', 'waitingOnApproval'), Runtime.WAITING),
                 (thread_status('notLoaded'), Runtime.UNKNOWN), (thread_status('systemError'), Runtime.UNKNOWN),
                 # type 认得是 active、旗标认不出：按「其他 active」为忙（与 thread_active 同样看作 active）
                 ({'type': 'active'}, Runtime.BUSY), ({'type': 'active', 'activeFlags': 'waitingOnApproval'}, Runtime.BUSY),
                 ({'type': 'active', 'activeFlags': {'waitingOnApproval': True}}, Runtime.BUSY),
                 ({'type': 'future'}, Runtime.UNKNOWN), ('idle', Runtime.UNKNOWN), (None, Runtime.UNKNOWN)]
        for status, expected in cases:
            self.assertIs(thread_runtime(read(status)), expected, status)
        for bad in (None, {}, {'thread': None}, {'thread': {}}, []):
            self.assertIs(thread_runtime(bad), Runtime.UNKNOWN, bad)

    def test_steer_judgement_is_unchanged(self):
        # thread_active 仍只看 type：active 不论旗标形状都为真（steer 的通道选择不受忙闲显示影响）
        from agentstatus_bridge.transports.codex_rpc import thread_active
        self.assertIs(thread_active({'thread': {'status': {'type': 'active'}}}), True)
        self.assertIs(thread_active({'thread': {'status': thread_status('active', 'waitingOnApproval')}}), True)
        self.assertIs(thread_active({'thread': {'status': thread_status('notLoaded')}}), False)
        self.assertIsNone(thread_active({'thread': {'status': {'type': 'future'}}}))


class RuntimeDiscoveryTests(unittest.TestCase):
    """§96.2 Windows Codex 忙闲：只有 discover(with_status=True)（peers 显示）才给可投递根线程取 thread.status。

    假 Win32 内核 + 合成 daemon/SQL；thread/read 只返回元数据形状，不带 turns。
    """
    setUp = DiscoveryTests.setUp
    rebuild = DiscoveryTests.rebuild
    scope = DiscoveryTests.scope
    sql = DiscoveryTests.sql

    def roots(self, statuses, *, sql=True):
        """loaded 线程 uuid(n)；sql 为真时每行都有 paginated 名字（发现过程不必读 thread/read），状态放进 thread/read。"""
        self.k.loaded = sorted(uuid(n) for n in statuses)
        if sql and not (self.home/'state_5.sqlite').exists():  # 同一用例重建内核时沿用已有的库
            path = self.sql([(uuid(n), 'cli') for n in statuses])
            with closing(sqlite3.connect(path)) as db, db:
                for n in statuses:
                    db.execute('UPDATE threads SET name=?,cwd=? WHERE id=?', (f'n{n}', 'C:\\w\\p', uuid(n)))
        for n, status in statuses.items():
            self.k.metadata[uuid(n)] = dict(id=uuid(n), source='cli', parentThreadId=None, name=f'n{n}',
                                            cwd='C:\\w\\p', status=status, preview='NOT_EXPORTED', turns=[])

    def run_discover(self, **kw):
        with self.scope():
            return D.discover(self.p.transport, **kw)

    def reads(self):
        return [m['params']['threadId'] for m in self.k.messages if m['method'] == 'thread/read']

    def runtimes(self, result):
        return {row.thread: row.runtime.value for row in result.rows}

    def test_eligible_roots_get_their_thread_status(self):
        statuses = {1: thread_status('idle'), 2: thread_status('active'), 3: thread_status('active', 'waitingOnApproval'),
                    4: thread_status('active', 'waitingOnUserInput'), 5: thread_status('notLoaded'),
                    6: thread_status('systemError'), 7: {'type': 'future'}, 8: thread_status('active', 'futureFlag')}
        self.roots(statuses)
        result = self.run_discover(with_status=True)
        self.assertEqual((result.complete, result.reason), (True, 'complete'))
        self.assertEqual(self.runtimes(result), {uuid(1): 'idle', uuid(2): 'busy', uuid(3): 'waiting', uuid(4): 'waiting',
                                                 uuid(5): 'unknown', uuid(6): 'unknown', uuid(7): 'unknown',
                                                 uuid(8): 'busy'})
        self.assertEqual(sorted(self.reads()), sorted(uuid(n) for n in statuses))  # 每个可投递根线程一次补读
        reads = [m['params'] for m in self.k.messages if m['method'] == 'thread/read']
        self.assertTrue(all(params['includeTurns'] is False for params in reads))
        self.assertEqual(result.native_reads, 0)  # 补读不计入分类补证次数（JSON nativeReads 口径不变）
        self.assertNotIn('NOT_EXPORTED', json.dumps(result.document(), ensure_ascii=False))

    def test_plain_discovery_reads_no_status(self):
        # worker、send、status 用的发现不取忙闲：不多发 thread/read，行都是 UNKNOWN
        self.roots({1: thread_status('active'), 2: thread_status('idle')})
        result = self.run_discover()
        self.assertEqual(self.reads(), [])
        self.assertEqual(set(self.runtimes(result).values()), {'unknown'})
        self.assertEqual(result.endpoint(result.rows[0]).runtime_source, 'none')

    def test_plain_discovery_never_maps_thread_status(self):
        # 审计 r1 Opus P3-2：不带 with_status 的发现（worker、send、status、caller）即使做了分类补证，也不执行
        # thread_runtime；忙闲映射将来出错也拖不垮投递路径的发现
        self.roots({2: thread_status('active')})
        self.k.loaded = [uuid(1), uuid(2)]
        self.k.metadata[uuid(1)] = dict(id=uuid(1), source='cli', parentThreadId=None, name='n1', cwd='C:\\w\\p',
                                        status=thread_status('idle'))
        with patch.object(D, 'thread_runtime', wraps=D.thread_runtime) as mapped:
            result = self.run_discover()
            self.assertEqual(self.reads(), [uuid(1)])  # 有一次分类补证
            self.assertEqual(mapped.call_count, 0)
            self.rebuild()
            self.roots({2: thread_status('active')})
            self.k.loaded = [uuid(1), uuid(2)]
            self.k.metadata[uuid(1)] = dict(id=uuid(1), source='cli', parentThreadId=None, name='n1', cwd='C:\\w\\p',
                                            status=thread_status('idle'))
            self.run_discover(with_status=True)
            self.assertEqual(mapped.call_count, 2)  # peers：分类读到的一次 + 补读一次
        self.assertTrue(result.complete)

    def test_statuses_read_during_classification_are_reused(self):
        # uuid(1) 没有 SQL 行，分类时已读过 thread/read：直接复用它的 status，不再读第二次；uuid(2) 补读
        self.roots({2: thread_status('active')})
        self.k.loaded = [uuid(1), uuid(2)]
        self.k.metadata[uuid(1)] = dict(id=uuid(1), source='cli', parentThreadId=None, name='n1', cwd='C:\\w\\p',
                                        status=thread_status('idle'))
        result = self.run_discover(with_status=True)
        self.assertEqual(self.reads(), [uuid(1), uuid(2)])
        self.assertEqual(self.runtimes(result), {uuid(1): 'idle', uuid(2): 'busy'})
        self.assertEqual(result.native_reads, 1)

    def test_an_exhausted_read_budget_leaves_the_rest_unknown(self):
        # 32 个没有 SQL 行的线程用完 MAX_IDS 次分类补证；有 SQL 行的 uuid(1) 不再补读，保持 UNKNOWN
        self.roots({1: thread_status('active')})
        self.k.loaded = [uuid(n) for n in range(1, 34)]
        for n in range(2, 34):
            self.k.metadata[uuid(n)] = dict(id=uuid(n), source='cli', parentThreadId=None, name=f'n{n}', cwd='C:\\w\\p',
                                            status=thread_status('idle'))
        result = self.run_discover(with_status=True)
        self.assertEqual(result.native_reads, 32)
        self.assertEqual(len(self.reads()), 32)
        self.assertNotIn(uuid(1), self.reads())
        runtimes = self.runtimes(result)
        self.assertEqual(runtimes.pop(uuid(1)), 'unknown')
        self.assertEqual(set(runtimes.values()), {'idle'})  # 分类时读到的照样复用

    def test_a_timed_out_status_read_keeps_the_discovery_complete(self):
        # 补读新线程优先（uuid(3) → uuid(2) → uuid(1)）：第二个补读超时，它与之后的行都是 UNKNOWN，已读到的保留；
        # 完整性与 eligible 不变
        self.roots({1: thread_status('idle'), 2: thread_status('active'), 3: thread_status('active')})
        clock = {'now': 1000.0}
        def after(message):
            if message['method'] == 'thread/read' and message['params']['threadId'] == uuid(2):
                clock['now'] = 5000.0  # 应答写进去了，但读应答前已过截止时刻
        self.k.after = after
        result = self.run_discover(with_status=True, clock=lambda: clock['now'])
        self.assertEqual((result.complete, result.reason), (True, 'complete'))
        self.assertTrue(all(row.eligible for row in result.rows))
        self.assertEqual(self.runtimes(result), {uuid(1): 'unknown', uuid(2): 'unknown', uuid(3): 'busy'})
        self.assertEqual(self.reads(), [uuid(3), uuid(2)])  # 连接已不可信：不再补读 uuid(1)

    def test_a_protocol_failure_stops_further_status_reads(self):
        # 第二个补读的应答 id 对不上（流已失步，连接不可信）：停止补读，后面的行不再发请求，保持 UNKNOWN；
        # 与超时不同，这时连接本身还能写，换成「继续读」就会再发一条请求
        self.roots({1: thread_status('idle'), 2: thread_status('active'), 3: thread_status('active')})
        self.k.override = lambda m, r: ({**r, 'id': m['id'] + 100}
                                        if m['method'] == 'thread/read' and m['params']['threadId'] == uuid(2) else r)
        result = self.run_discover(with_status=True)
        self.assertEqual((result.complete, result.reason), (True, 'complete'))
        self.assertEqual(self.runtimes(result), {uuid(1): 'unknown', uuid(2): 'unknown', uuid(3): 'busy'})
        self.assertEqual(self.reads(), [uuid(3), uuid(2)])

    def test_each_transport_failure_of_a_status_read_is_contained(self):
        # _statuses 的捕获集合逐项：补读抛 _Closed、OSError、ValueError（以及 NativeFailure、_Timeout）都只让该行与之后的行
        # UNKNOWN，不让整次发现失败
        from agentstatus_bridge.transports.websocket import _Closed, _Timeout
        real = D.Reader.request
        for error in (_Closed('closed'), OSError('reset'), ValueError('bad json'), NativeFailure('response_id_mismatch'),
                      _Timeout('deadline')):
            with self.subTest(error=type(error).__name__):
                self.rebuild()
                self.roots({1: thread_status('idle'), 2: thread_status('active')})
                def request(reader, method, params, error=error):
                    if method == 'thread/read' and params['threadId'] == uuid(1):  # 新线程优先：uuid(1) 是第二个补读
                        raise error
                    return real(reader, method, params)
                with patch.object(D.Reader, 'request', request):
                    result = self.run_discover(with_status=True)
                self.assertEqual((result.complete, result.reason), (True, 'complete'))
                self.assertEqual(self.runtimes(result), {uuid(1): 'unknown', uuid(2): 'busy'})

    def test_unstable_roots_get_no_status(self):
        # 两次 loaded 只出现一次的根线程不可投递：不补读，也不复用分类时读到的 status
        self.roots({1: thread_status('idle'), 2: thread_status('active')})
        self.k.loaded = [uuid(1), uuid(2), uuid(3)]
        self.k.metadata[uuid(3)] = dict(id=uuid(3), source='cli', parentThreadId=None, name='n3', cwd='C:\\w\\p',
                                        status=thread_status('active'))
        def after(message):
            if message['method'] == 'thread/loaded/list':
                self.k.loaded = [uuid(1)]  # 第二次 loaded 里 uuid(2)、uuid(3) 已不在
        self.k.after = after
        result = self.run_discover(with_status=True)
        self.assertEqual([(r.thread, r.kind, r.stable, r.eligible) for r in result.rows],
                         [(uuid(1), 'root', True, True), (uuid(2), 'root', False, False), (uuid(3), 'root', False, False)])
        self.assertEqual(self.runtimes(result), {uuid(1): 'idle', uuid(2): 'unknown', uuid(3): 'unknown'})
        self.assertEqual(self.reads(), [uuid(3), uuid(1)])  # uuid(3) 是分类补证，uuid(1) 是补读；uuid(2) 不读

    def test_status_reads_share_the_discovery_deadline(self):
        # 审计 r1 Opus P2-1（p1）：补读与分类共用同一个 5 秒截止时刻。分类结束时已到 1004.5（截止 1005），
        # 第一个补读 uuid(2) 来得及；第二个补读 uuid(1) 发出后时钟到 1006，按共用截止它必须 UNKNOWN（另起截止就会读到）
        self.roots({1: thread_status('idle'), 2: thread_status('active')})
        clock = {'now': 1000.0, 'loaded': 0}
        def after(message):
            if message['method'] == 'thread/loaded/list':
                clock['loaded'] += 1
                if clock['loaded'] == 2:
                    clock['now'] = 1004.5
            if message['method'] == 'thread/read' and message['params']['threadId'] == uuid(1):
                clock['now'] = 1006.0
        self.k.after = after
        result = self.run_discover(with_status=True, clock=lambda: clock['now'])
        self.assertEqual((result.complete, result.reason), (True, 'complete'))
        self.assertEqual(self.runtimes(result), {uuid(1): 'unknown', uuid(2): 'busy'})

    def test_the_read_budget_counts_failed_classification_reads(self):
        # 审计 r1 Opus P2-1（p2）：额度按分类补证的请求次数扣，错误应答也算。32 个无 SQL 行的线程用完 32 次（其中
        # uuid(33) 是错误应答），有 SQL 行的 uuid(1) 不再补读，总读取不超过 MAX_IDS
        self.roots({1: thread_status('active')})
        self.k.loaded = [uuid(n) for n in range(1, 34)]
        for n in range(2, 34):
            self.k.metadata[uuid(n)] = dict(id=uuid(n), source='cli', parentThreadId=None, name=f'n{n}', cwd='C:\\w\\p',
                                            status=thread_status('idle'))
        self.k.override = lambda m, r: ({'id': m['id'], 'error': {'code': -1}}
                                        if m['method'] == 'thread/read' and m['params']['threadId'] == uuid(33) else r)
        result = self.run_discover(with_status=True)
        self.assertEqual(result.native_reads, 32)
        self.assertEqual(len(self.reads()), 32)
        self.assertNotIn(uuid(1), self.reads())
        self.assertEqual(self.runtimes(result)[uuid(1)], 'unknown')

    def test_a_response_for_another_thread_stops_status_reads(self):
        # 审计 r1 Opus P3-1（p3）：补读应答的 thread.id 不是所请求的线程：不采用它的 status，与协议失步同口径停止补读。
        # id 缺失、非字符串、不是 UUID 都算不符（与分类路径 _project_kind 同一比较），且不抛异常
        missing = object()
        for label, value in (('other', uuid(9)), ('absent', missing), ('none', None), ('int', 5), ('garbage', 'x')):
            with self.subTest(id=label):
                self.rebuild()
                self.roots({1: thread_status('idle'), 2: thread_status('idle'), 3: thread_status('idle')})
                thread = dict(source='cli', status=thread_status('active'))
                if value is not missing:
                    thread['id'] = value
                def swap(m, r, thread=thread):
                    if m['method'] == 'thread/read' and m['params']['threadId'] == uuid(2):
                        return {**r, 'result': {'thread': thread}}
                    return r
                self.k.override = swap
                result = self.run_discover(with_status=True)
                self.assertEqual((result.complete, result.reason), (True, 'complete'))
                self.assertEqual(self.runtimes(result), {uuid(1): 'unknown', uuid(2): 'unknown', uuid(3): 'idle'})
                self.assertEqual(self.reads(), [uuid(3), uuid(2)])

    def test_a_response_id_in_upper_case_is_the_same_thread(self):
        # 正例：id 只差大小写时与分类路径同样按同一线程处理（native_id 归一为小写），照常采用 status、继续补读。
        # 用 10–12（尾段是十六进制字母 a–c）：uuid(1..9) 全是数字，upper() 不改变它，正例会是空的
        self.assertNotEqual(uuid(11).upper(), uuid(11))
        self.roots({10: thread_status('idle'), 11: thread_status('idle'), 12: thread_status('idle')})
        def upper(m, r):
            if m['method'] == 'thread/read' and m['params']['threadId'] == uuid(11):
                return {**r, 'result': {'thread': dict(id=uuid(11).upper(), source='cli', status=thread_status('active'))}}
            return r
        self.k.override = upper
        result = self.run_discover(with_status=True)
        self.assertEqual(self.runtimes(result), {uuid(10): 'idle', uuid(11): 'busy', uuid(12): 'idle'})
        self.assertEqual(self.reads(), [uuid(12), uuid(11), uuid(10)])

    def test_newest_threads_get_their_status_first(self):
        # 审计 r1 Fable P3-3：40 个可投递根只够补读 32 个，新线程优先（线程 ID 是 UUID v7，升序即创建时间升序），
        # 拿不到忙闲的是最旧的 8 个。nativeReadBudgetHit 只反映分类补证，这里仍为假（JSON 不另加提示键）
        self.roots({n: thread_status('active') for n in range(1, 41)})
        result = self.run_discover(with_status=True)
        runtimes = self.runtimes(result)
        self.assertEqual(self.reads(), [uuid(n) for n in range(40, 8, -1)])
        self.assertEqual([n for n in range(1, 41) if runtimes[uuid(n)] == 'unknown'], list(range(1, 9)))
        self.assertFalse(result.native_read_budget_hit)

    def test_a_partial_budget_reads_only_what_is_left(self):
        # 审计 r1 Fable P3-2：30 个无 SQL 行的线程用掉 30 次分类补证，5 个有 SQL 行的根只剩 2 次补读：最新的两个拿到
        self.roots({n: thread_status('active') for n in range(1, 6)})
        self.k.loaded = [uuid(n) for n in range(1, 36)]
        for n in range(6, 36):
            self.k.metadata[uuid(n)] = dict(id=uuid(n), source='cli', parentThreadId=None, name=f'n{n}', cwd='C:\\w\\p',
                                            status=thread_status('idle'))
        result = self.run_discover(with_status=True)
        self.assertEqual((result.native_reads, len(self.reads()), result.complete), (30, 32, True))
        runtimes = self.runtimes(result)
        self.assertEqual([runtimes[uuid(n)] for n in range(1, 6)], ['unknown', 'unknown', 'unknown', 'busy', 'busy'])
        self.assertEqual({runtimes[uuid(n)] for n in range(6, 36)}, {'idle'})

    def test_a_daemon_change_while_reading_status_is_contained(self):
        # 审计 r1 Fable P3-5：补读期间控制 socket 身份变了（response() 里 unchanged() 抛 daemon_changed）：停止补读，
        # 发现仍完整
        from agentstatus_bridge.transports import codex_native
        self.roots({1: thread_status('idle'), 2: thread_status('active'), 3: thread_status('active')})
        real = codex_native.BoundedConnection.unchanged
        state = {'reads': 0}
        def after(message):
            if message['method'] == 'thread/read':
                state['reads'] += 1
        self.k.after = after
        def unchanged(conn):
            if state['reads'] >= 2:
                raise NativeFailure('daemon_changed')
            return real(conn)
        with patch.object(codex_native.BoundedConnection, 'unchanged', unchanged):
            result = self.run_discover(with_status=True)
        self.assertEqual((result.complete, result.reason), (True, 'complete'))
        self.assertEqual(self.runtimes(result), {uuid(1): 'unknown', uuid(2): 'unknown', uuid(3): 'busy'})

    def test_other_call_sites_read_no_status(self):
        # 审计 r1 Fable P3-1：worker（两处）与命令作用域的发现不取忙闲：全部根都有 SQL 行时不出现任何 thread/read
        from agentstatus_bridge.platforms.windows import commands
        self.roots({1: thread_status('active'), 2: thread_status('idle')})
        with self.scope():
            endpoints = D.WorkerDiscovery(self.p.transport)()
        self.assertEqual(self.reads(), [])
        self.assertEqual({(e.runtime.value, e.runtime_source) for e in endpoints}, {('unknown', 'none')})
        self.rebuild()
        self.roots({1: thread_status('active'), 2: thread_status('idle')})
        with self.scope():
            sampled = commands.sample()
        self.assertEqual(self.reads(), [])
        self.assertEqual(set(self.runtimes(sampled).values()), {'unknown'})
        self.rebuild()
        self.roots({1: thread_status('active'), 2: thread_status('idle')})
        with self.scope(), patch.object(commands.claude, 'discover',
                                        return_value=commands.claude.Discovery((), True, 'complete')):
            found = commands.WorkerDiscovery(self.p.transport)()
        self.assertEqual(self.reads(), [])
        self.assertEqual({(e.runtime.value, e.runtime_source) for e in found}, {('unknown', 'none')})

    def test_only_peers_asks_for_status(self):
        # 审计 r1 Fable P3-1 的静态一侧：全部 Codex 发现调用点里，只有 cli._windows_local_peers 传 with_status。
        # 上面的行为用例覆盖 worker 与命令作用域；caller 与 alias 的调用点要真实进程链/别名文件，这里按源码钉住
        import ast
        root = Path(D.__file__).resolve().parents[2]  # agentstatus_bridge 包目录
        calls: dict[tuple[str, str], bool] = {}
        for path in sorted(root.rglob('*.py')):
            tree = ast.parse(path.read_text(encoding='utf-8'))
            for func in [node for node in ast.walk(tree) if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))]:
                for call in [node for node in ast.walk(func) if isinstance(node, ast.Call)]:
                    name = call.func.attr if isinstance(call.func, ast.Attribute) else getattr(call.func, 'id', None)
                    owner = call.func.value.id if isinstance(call.func, ast.Attribute) and isinstance(call.func.value, ast.Name) else None
                    if name != 'discover' or owner in ('claude', 'claude_discovery'):
                        continue
                    asked = any(k.arg == 'with_status' and not (isinstance(k.value, ast.Constant) and not k.value.value)
                                for k in call.keywords)
                    key = (path.relative_to(root).as_posix(), func.name)
                    calls[key] = calls.get(key, False) or asked
        asking = {key for key, asked in calls.items() if asked}
        self.assertEqual(asking, {('cli.py', '_windows_local_peers')})
        for site in (('platforms/windows/commands.py', 'sample'), ('platforms/windows/commands.py', '__call__'),
                     ('platforms/windows/codex_discovery.py', '__call__'), ('platforms/windows/caller.py', '_identify'),
                     ('platforms/windows/alias_command.py', 'run')):
            self.assertIn(site, calls)
            self.assertFalse(calls[site], site)

    def test_an_error_response_only_leaves_that_row_unknown(self):
        # 错误应答放在中间一行（新线程优先：读序 3、2、1）：只让 uuid(2) UNKNOWN，之后的 uuid(1) 照常补读（审计 r1 回归）
        self.roots({1: thread_status('idle'), 2: thread_status('active'), 3: thread_status('active')})
        self.k.override = lambda m, r: ({'id': m['id'], 'error': {'code': -1}}
                                        if m['method'] == 'thread/read' and m['params']['threadId'] == uuid(2) else r)
        result = self.run_discover(with_status=True)
        self.assertEqual(self.runtimes(result), {uuid(1): 'idle', uuid(2): 'unknown', uuid(3): 'busy'})
        self.assertEqual(self.reads(), [uuid(3), uuid(2), uuid(1)])
        self.assertTrue(result.complete)

    def test_non_recipient_rows_stay_unknown(self):
        # 子代理、internal、元数据未核实的行即使 thread/read 报 active 也不显示忙闲，也不为它们补读
        self.k.loaded = [uuid(n) for n in range(1, 5)]
        spawn = '{"subagent":{"thread_spawn":{"parent_thread_id":"' + uuid(1) + '","depth":1}}}'
        self.sql([(uuid(1), 'cli'), (uuid(2), spawn), (uuid(3), '{"internal":"guardian"}'), (uuid(4), 'future')],
                 [(uuid(2), uuid(1))])
        with closing(sqlite3.connect(self.home/'state_5.sqlite')) as db, db:
            db.execute('UPDATE threads SET name=?,cwd=? WHERE id=?', ('lead', 'C:\\w\\p', uuid(1)))
        for n in range(1, 5):
            self.k.metadata[uuid(n)] = dict(id=uuid(n), source='cli', parentThreadId=None, status=thread_status('active'))
        result = self.run_discover(with_status=True)
        self.assertEqual([(r.kind, r.eligible) for r in result.rows],
                         [('root', True), ('subagent', False), ('internal', False), ('unknown', False)])
        self.assertEqual(self.runtimes(result), {uuid(1): 'busy', uuid(2): 'unknown', uuid(3): 'unknown',
                                                 uuid(4): 'unknown'})
        self.assertEqual(self.reads(), [uuid(1)])

    def test_statuses_read_for_non_recipient_rows_are_not_reused(self):
        # 分类时读过 thread/read、但最终不可投递的行（原生判为 internal、无父子代理）不复用它的 status
        self.roots({1: thread_status('idle')})
        self.k.loaded = [uuid(1), uuid(2), uuid(3)]
        self.k.metadata[uuid(2)] = dict(id=uuid(2), source={'internal': 'guardian'}, parentThreadId=None,
                                        status=thread_status('active'))
        self.k.metadata[uuid(3)] = dict(id=uuid(3), source={'subAgent': 'review'}, parentThreadId=None,
                                        status=thread_status('active'))
        result = self.run_discover(with_status=True)
        self.assertEqual([(r.kind, r.eligible) for r in result.rows],
                         [('root', True), ('internal', False), ('subagent', False)])
        self.assertEqual(self.runtimes(result), {uuid(1): 'idle', uuid(2): 'unknown', uuid(3): 'unknown'})

    def test_text_json_and_endpoint_agree(self):
        self.roots({1: thread_status('idle'), 2: thread_status('active'), 3: thread_status('active', 'waitingOnApproval'),
                    4: thread_status('notLoaded')})
        result = self.run_discover(with_status=True)
        out = io.StringIO()
        with redirect_stdout(out):
            D.print_peers(result)
        lines = {n: next(line for line in out.getvalue().splitlines() if f'target=codex@id:{uuid(n)}' in line)
                 for n in range(1, 5)}
        labels = {1: '空闲', 2: '忙', 3: '等待用户', 4: '状态未知'}
        for n, label in labels.items():
            self.assertIn(f'  [root] {label}', lines[n])
        self.assertEqual([row['runtime'] for row in result.document()['peers']], ['idle', 'busy', 'waiting', 'unknown'])
        endpoints = [result.endpoint(row) for row in result.rows]
        self.assertEqual([(e.runtime.value, e.runtime_source) for e in endpoints],
                         [('idle', 'codex_thread_status'), ('busy', 'codex_thread_status'),
                          ('waiting', 'codex_thread_status'), ('unknown', 'none')])
        self.assertNotIn('runtimeSource', json.dumps(result.document()))  # JSON 形状不变


class WindowsClaudeRegistryStatusTests(unittest.TestCase):
    """§96 r1：注册文件 → claude_discovery.discover（inspect、project）→ 端点 runtime 这条未打桩的路径。

    放在 bridge-windows 选择集已有的模块里，真实 Windows CI 也跑；夹具同 test_bridge_windows_claude.NativeTests
    （假 Win32 内核、临时注册目录、假管道），不碰真实注册目录。
    """
    PIPE = r'\\.\pipe\LOCAL\cc-msg-0123456789abcdef0123456789abcdef'
    SESSION = '019a0000-0000-7000-8000-000000000001'
    BIRTH = '134362090000012230'

    def setUp(self):
        from bridge_winapi import Kernel
        temporary = TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.sessions = self.root / 'config' / 'sessions'
        self.sessions.mkdir(parents=True)
        self.k = Kernel(self.root)
        self.k.processes[200] = (0, int(self.BIRTH), self.k.sid, False, 'claude.exe')
        self.k.images[200] = r'C:\fixture\claude.exe'
        self.k.peer = 200
        self.p = make_platform('windows', win_api=self.k.api)
        self.addCleanup(lambda: self.assertEqual(self.k.handles, {}))
        self.enterContext(patch.object(self.p.files, 'claude_sessions_dir', return_value=self.sessions))
        self.enterContext(using_platform(self.p))
        self.enterContext(windows_fixture('pipe', self.PIPE))

    def test_registry_status_reaches_the_discovered_endpoint(self):
        from agentstatus_bridge.platforms.windows import claude_discovery
        record = {'pid': 200, 'sessionId': self.SESSION, 'peerProtocol': 1, 'kind': 'interactive',
                  'messagingSocketPath': self.PIPE, 'procStartFt': self.BIRTH, 'name': 'fixture-peer'}
        for status, expected in (('idle', 'idle'), ('busy', 'busy'), ('shell', 'busy'), ('waiting', 'waiting'),
                                 ('future', 'unknown'), (None, 'unknown')):
            with self.subTest(status=status):
                (self.sessions / '200.json').write_text(
                    json.dumps(record if status is None else {**record, 'status': status}), encoding='utf-8')
                result = claude_discovery.discover(self.p.transport)
                self.assertTrue(result.complete)
                [endpoint] = result.endpoints
                self.assertEqual((endpoint.runtime.value, endpoint.runtime_source), (expected, 'claude_registry'))
                self.assertEqual(result.document()[0]['runtime'], expected)



class WindowsClaudeTitleTests(unittest.TestCase):
    """§99 Windows：注册文件 → claude_discovery.discover → 会话记录标题作主名；共享读打开（READ|WRITE|DELETE）、
    读完即关；打不开或是重解析点时退回注册名，发现完整性不变。夹具同 WindowsClaudeRegistryStatusTests（假内核、临时目录）。
    """
    PIPE = WindowsClaudeRegistryStatusTests.PIPE
    SESSION = WindowsClaudeRegistryStatusTests.SESSION
    BIRTH = WindowsClaudeRegistryStatusTests.BIRTH
    setUp = WindowsClaudeRegistryStatusTests.setUp

    def tearDown(self):
        from agentstatus_bridge import claude_titles
        claude_titles._MEMO.clear()

    def registry(self, name='fixture-peer'):
        (self.sessions / '200.json').write_text(json.dumps(
            {'pid': 200, 'sessionId': self.SESSION, 'peerProtocol': 1, 'kind': 'interactive', 'status': 'idle',
             'messagingSocketPath': self.PIPE, 'procStartFt': self.BIRTH, 'name': name}), encoding='utf-8')

    def transcript(self, title='win-title'):
        path = self.root / 'config' / 'projects' / 'C--work-repo' / f'{self.SESSION}.jsonl'
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps({'type': 'user', 'sessionId': self.SESSION}) + '\n'
                        + json.dumps({'type': 'ai-title', 'aiTitle': title, 'sessionId': self.SESSION},
                                     separators=(',', ':')) + '\n', encoding='utf-8')
        return path

    def discovered(self):
        from agentstatus_bridge.platforms.windows import claude_discovery
        result = claude_discovery.discover(self.p.transport)
        self.assertTrue(result.complete)
        self.assertEqual(self.k.handles, {})  # 会话记录句柄读完即关
        [endpoint] = result.endpoints
        return result, endpoint

    def test_discovery_uses_the_transcript_title(self):
        from agentstatus_bridge.native_names import NameBook
        self.registry()
        self.transcript()
        result, endpoint = self.discovered()
        self.assertEqual((endpoint.name, endpoint.name_source, endpoint.name_origin),
                         ('win-title', NameSource('named', 'win-title'), 'found_ai'))
        self.assertEqual((endpoint.name_view.name, endpoint.name_view.verified), ('win-title', True))
        self.assertEqual(NameBook.of(result.endpoints).local_wire(endpoint.ref), 'claude@win-title')
        self.assertEqual(result.document()[0]['name'], 'win-title')

    def test_the_title_is_addressable_through_windows_resolve(self):
        from agentstatus_bridge.platforms.windows import commands
        from agentstatus_bridge.transports.codex_native import NativeFailure as Failure
        self.registry()
        self.transcript()
        self.assertEqual(commands.resolve('claude@win-title').ref.native_id, self.SESSION)
        with self.assertRaises(Failure) as caught:
            commands.resolve('claude@fixture-peer')
        self.assertEqual(caught.exception.reason, 'target_not_found')
        self.assertEqual(self.k.handles, {})

    def test_the_shared_read_open_lets_claude_append_and_delete(self):
        import ctypes as C
        from agentstatus_bridge.platforms.windows import abi as A
        path = self.transcript()
        with self.p.files.open_shared_read(path) as reader:
            [record] = [item for item in self.k.handles.values() if item.get('path') == str(path)]
            self.assertEqual((record['sharing'], record['access'] & 0x40000001), (7, 0x1))  # 只读数据、三种共享
            self.assertEqual(reader.read_at(reader.size - 3, 3)[-1:], b'\n')
            with self.k.api.owned(self.k.api.open_file(str(path), write=True, sharing=7)):
                pass  # Claude 追加写入
            with self.k.api.private_attributes() as sa:
                deleting = self.k.api.handle(self.k.CreateFileW(A.wide(str(path)), 0x10000, 7, C.byref(sa), 3,
                                                                0x00200000 | 0x80, None))
            self.k.api.close(deleting)  # 带 DELETE 访问的打开（替换、删除）不被拒绝
        self.assertEqual(self.k.handles, {})

    def test_an_unopenable_transcript_falls_back_and_discovery_stays_complete(self):
        self.registry()
        for reason, meta in (('unreadable', {'deny_data': True}), ('not_regular', {'reparse': True})):
            with self.subTest(reason=reason):
                from agentstatus_bridge import claude_titles
                claude_titles._MEMO.clear()
                path = self.transcript()
                self.k.files[str(path)] = meta
                _, endpoint = self.discovered()
                self.assertEqual((endpoint.name, endpoint.name_source, endpoint.name_origin),
                                 ('fixture-peer', NameSource('named', 'fixture-peer'), reason))
                self.assertEqual((endpoint.name_view.name, endpoint.name_view.verified), ('fixture-peer', True))
                del self.k.files[str(path)]

    def test_the_shared_read_open_refuses_directories(self):
        # 审计 Opus O11 / Fable W3：句柄属性带 FILE_ATTRIBUTE_DIRECTORY 时报 not_regular，句柄照样关闭
        path = self.transcript()
        info = SimpleNamespace(attributes=0x10, size_high=0, size_low=1)
        with patch.object(self.k.api, 'file_info', return_value=info), self.assertRaises(OSError) as caught:
            with self.p.files.open_shared_read(path):
                pass
        self.assertEqual(caught.exception.args, ('not_regular',))
        self.assertEqual(self.k.handles, {})

    def test_peers_json_counts_duplicate_sessions_too(self):
        # 审计 Fable C1：计数包括按重复会话剔除出选择的端点
        from agentstatus_bridge.model import Endpoint, EndpointRef
        from agentstatus_bridge.platforms.windows import claude_discovery, commands
        def duplicate(pid):
            return Endpoint(EndpointRef(Provider.CLAUDE, self.SESSION, pid, 'win-filetime:1', data_root='c' * 64),
                            name='t', name_origin='found_ai')
        evidence = claude_discovery.Discovery((), True, 'complete', (duplicate(300), duplicate(301)))
        out = io.StringIO()
        with patch.object(D, 'discover', return_value=D.Discovery()), patch.dict(os.environ, {'AB_DEVICE': 'winbox'}), \
                patch.object(commands, 'claude_evidence', return_value=evidence), \
                patch.object(cli, '_refresh_summary', side_effect=AssertionError('no state writes')), \
                patch.object(cli, '_revive_for_federation'), redirect_stdout(out):
            self.assertEqual(cli.main(['peers', '--json']), 0)
        self.assertEqual(json.loads(out.getvalue())['claudeTitles'], {'found': 2, 'fallback': {}})

    def test_peers_json_counts_title_sources_only(self):
        self.registry()
        self.transcript()
        out = io.StringIO()
        with patch.object(D, 'discover', return_value=D.Discovery()), patch.dict(os.environ, {'AB_DEVICE': 'winbox'}), \
                patch.object(cli, '_refresh_summary', side_effect=AssertionError('no state writes')), \
                patch.object(cli, '_revive_for_federation'), redirect_stdout(out):
            self.assertEqual(cli.main(['peers', '--json']), 0)
        document = json.loads(out.getvalue())
        self.assertEqual(document['claudeTitles'], {'found': 1, 'fallback': {}})
        self.assertNotIn(str(self.root), json.dumps(document['claudeTitles']))


if __name__=='__main__': unittest.main()
