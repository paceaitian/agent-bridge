"""W2-2 real WS+SQLite on SDK Fake Win32. No real provider or private home."""
from contextlib import closing, contextmanager, redirect_stdout, redirect_stderr
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
from agentstatus_bridge.model import Provider, Flow
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
        self.assertEqual(result.select('00000000').thread, uuid(1))
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
        self.assertEqual(result.document()['qualification'],'implementation_only_pending_w2_5')
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
        with self.assertRaisesRegex(NativeFailure, 'target_ambiguous'): result.select('00000000')
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
        with self.assertRaisesRegex(NativeFailure,'target_ambiguous'): collision.select('00000000')

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


if __name__=='__main__': unittest.main()
