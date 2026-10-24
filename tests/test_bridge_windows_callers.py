"""W2-3 injected SDK, readonly daemon, local ledger. No real Windows qualification."""
from contextlib import redirect_stdout, redirect_stderr
from dataclasses import replace
import io
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import time
import unittest
from unittest.mock import patch, Mock

import bridge_support
import test_bridge_windows_discovery as fixture
from test_bridge_windows_discovery import uuid
from agentstatus_bridge import cli, endpoints, reports, closure, reminders, views
from agentstatus_bridge.dispatch import Dispatcher
from agentstatus_bridge.model import Endpoint, EndpointRef, Provider, Flow, Delivery, ReportKind, Role, Work, describe
from agentstatus_bridge.store import Store, DB_NAME
from agentstatus_bridge.notification_policy import can_notify, receipt_options
from agentstatus_bridge.platforms.factory import using_platform, make_platform
from agentstatus_bridge.platforms.types import Presence
from agentstatus_bridge.platforms.windows import caller as C, codex_discovery as D, alias_command as A, local_store as L
from agentstatus_bridge.platforms.windows.target_aliases import AliasFile


class HostEnvironmentTests(unittest.TestCase):
    def test_inherited_session_variables_do_not_poison_claude_caller_modules(self):
        tree = Path(__file__).resolve().parents[1]
        env = dict(os.environ, CLAUDE_CODE_SESSION_ID='ffffffff-ffff-4fff-8fff-ffffffffffff',
                   CODEX_THREAD_ID='eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee',
                   CODEX_SESSION_ID='dddddddd-dddd-4ddd-8ddd-dddddddddddd')
        env['PYTHONPATH'] = os.pathsep.join((str(tree / 'src'), str(tree / 'tests')))
        command = [sys.executable, '-B'] + (['-O'] if sys.flags.optimize else [])
        command += ['-m', 'unittest', 'test_bridge_windows_claude_cli', 'test_bridge_windows_claude_r2', '-v']
        run = subprocess.run(command, cwd=tree, env=env, capture_output=True, text=True, timeout=120)
        self.assertEqual(run.returncode, 0, run.stdout + run.stderr)
        self.assertIn('Ran 15 tests', run.stderr)
        self.assertIn('\nOK\n', run.stderr)

    def test_session_guard_drops_routing_but_keeps_runner_and_ci_controls(self):
        tree = Path(__file__).resolve().parents[1]
        removed = ('CLAUDECODE', 'CLAUDE_PID', 'CLAUDE_SESSION_ID', 'CLAUDE_CONFIG_DIR',
                   'CLAUDE_CODE_SESSION_ID', 'CLAUDE_CODE_MESSAGING_TOKEN', 'CODEX_THREAD_ID',
                   'CODEX_SESSION_ID', 'CODEX_COMPANION_SESSION_ID', 'CODEX_HOME', 'CODEX_SQLITE_HOME',
                   'GROK_SESSION_ID', 'GROK_HOME', 'GROK_HOOK_EVENT', 'TMUX', 'TMUX_PANE',
                   'AB_STATE_DIR', 'AB_BINDING', 'AB_DEVICE', 'AB_COMMAND', 'AB_CLAUDE_PRIORITY',
                   'AB_WORKER_START_TOKEN', 'AB_WORKER_BREAKAWAY', 'AB_FUTURE_ROUTING')
        preserved = ('PATH', 'PYTHONPATH', 'HOME', 'TMPDIR', 'TEMP', 'TMP', 'USERPROFILE', 'SYSTEMROOT',
                     'XDG_RUNTIME_DIR', 'DBUS_SESSION_BUS_ADDRESS', 'TMUX_TMPDIR', 'CI', 'GITHUB_ACTIONS',
                     'AGENTSTATUS_UI_CANARY', 'AGENTSTATUS_WRITE_GOLDEN', 'AB_WRITE_GOLDEN')
        script = '''import json, os, sys
sys.path[:0] = sys.argv[1:3]
removed, preserved = json.loads(sys.argv[3]), json.loads(sys.argv[4])
before = {key: os.environ.get(key) for key in preserved}
old_root = os.environ.get('AB_CLAUDE_SESSIONS_DIR')
import bridge_support
print(json.dumps({'removed': all(key not in os.environ for key in removed),
                  'preserved': before == {key: os.environ.get(key) for key in preserved},
                  'privateRegistry': bool(os.environ.get('AB_CLAUDE_SESSIONS_DIR')) and
                      os.environ['AB_CLAUDE_SESSIONS_DIR'] != old_root}))
'''
        with TemporaryDirectory() as tmp:
            env = dict(os.environ)
            env.update({key: str(Path(tmp) / key) for key in removed})
            env.update(AB_CLAUDE_SESSIONS_DIR=str(Path(tmp) / 'host-registry'), TMUX_TMPDIR=tmp,
                       CI='fixture', GITHUB_ACTIONS='fixture', AGENTSTATUS_UI_CANARY='fixture',
                       AGENTSTATUS_WRITE_GOLDEN='fixture', AB_WRITE_GOLDEN='fixture')
            command = [sys.executable, '-B', '-I'] + (['-O'] if sys.flags.optimize else [])
            command += ['-c', script, str(tree / 'src'), str(tree / 'tests'), json.dumps(removed), json.dumps(preserved)]
            run = subprocess.run(command, env=env, capture_output=True, text=True, timeout=30)
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertEqual(json.loads(run.stdout), {'removed': True, 'preserved': True, 'privateRegistry': True})


class CallerTests(unittest.TestCase):
    # Share only fixture setup, not duplicate inherited tests.
    setUp = fixture.DiscoveryTests.setUp
    rebuild = fixture.DiscoveryTests.rebuild
    scope = fixture.DiscoveryTests.scope
    sql = fixture.DiscoveryTests.sql
    discover = fixture.DiscoveryTests.discover
    alias_row = fixture.DiscoveryTests.alias_row

    def test_report_keeps_local_name_and_wire_id_visible_together(self):
        from agentstatus_bridge import envelope
        from agentstatus_bridge.notification_policy import wire_ref
        origin = EndpointRef(Provider.CODEX, '01a15e9f-0000-4000-8000-000000000001',
                             201, 'win-filetime:1', label='回复 W3-ONE')
        with self.scope(), Store.open(self.state) as store:
            task, attempt = self.task(store, origin=origin)
            text = envelope.render(task, attempt, sender=wire_ref(origin).token(), device='testbox')
            self.assertIn(' from=codex@01a15e9f device=', text.splitlines()[0])
            args = cli.build_parser().parse_args(['report', task.id, '--attempt', '1', '--result', '--note', 'OK'])
            with (patch.object(cli, 'discover', return_value=[]),
                  patch.object(cli, 'identify_caller', return_value=endpoints.Caller(Endpoint(attempt.target), None, agent_env=True)),
                  patch.object(cli, 'permission_class', return_value=None),
                  patch.object(cli, '_start_worker', return_value=False), redirect_stdout(io.StringIO()) as out):
                code = cli.cmd_report(args)
            self.assertEqual(code, 0)
            self.assertIn('已排队通知发起方 codex@回复 W3-ONE〔01a15e9f〕', out.getvalue())
            followup = store.attempts(task.id)[-1]
            self.assertEqual(followup.target.label, '回复 W3-ONE')
            self.assertEqual(views._ref_document(followup.target)['name'], 'codex@回复 W3-ONE')

    def chain(self):
        self.k.processes[100] = (201,134362090001712230,self.k.sid,False,'python.exe')
        self.k.processes[201] = (200,134362090001612230,self.k.sid,False,'pwsh.exe')
        self.k.processes[200] = (4,134362090000012230,self.k.sid,False,'codex.exe')
        self.k.processes[4] = (0,100,bytes.fromhex('010100000000000512000000'),False,'System')
        return {'CODEX_THREAD_ID':uuid(1),'CODEX_SESSION_ID':uuid(1)}

    def reject(self, caller, code='caller_unattributed'):
        self.assertIsNone(caller.endpoint)
        self.assertFalse(caller.is_user_shell)
        with self.assertRaises(cli.CliError) as caught: cli._check_sender(caller)
        self.assertEqual(caught.exception.code,code)

    def test_alias_set_accepts_forced_codex_uuid_and_prefix_only(self):
        with self.scope():
            for name,value in (('full','codex@id:'+uuid(1)),('prefix','codex@id:'+uuid(1)[:8])):
                code,out,err=self.run_cli('alias','set',name,value,'--json')
                self.assertEqual(code,0,(out,err))
            path=self.state/'target-aliases/codex.json'
            rows=json.loads(path.read_bytes())['aliases']
            self.assertEqual({(r['alias'],r['threadId']) for r in rows},{('full',uuid(1)),('prefix',uuid(1))})
            before=path.read_bytes()
            for value in ('codex@id:full','codex@id:','codex@'+uuid(1)):
                code,out,err=self.run_cli('alias','set','bad',value,'--json')
                self.assertEqual(code,3,(out,err))
                self.assertIn('alias_uuid_required',out+err)
            self.assertEqual(path.read_bytes(),before)
            self.k.loaded=[uuid(1),uuid(2)]
            code,out,err=self.run_cli('alias','set','ambiguous','codex@id:00000000','--json')
            self.assertEqual(code,2,(out,err))
            self.assertIn('target_ambiguous',out+err)

    def test_codex_root_real_discovery_no_mux_no_registration(self):
        env=self.chain()
        with self.scope(),patch.object(type(self.p.mux),'sample',side_effect=AssertionError('no mux')):  # layout: allow 组合根NullMux类型，禁止采样
            caller=endpoints.identify_caller([],pid=100,environ=env)
            self.assertIsNotNone(caller.endpoint)
            self.assertEqual(caller.endpoint.ref.native_id,uuid(1))
            self.assertEqual(caller.endpoint.ref.pid,200)
            self.assertEqual(caller.endpoint.ref.start_ticks,'win-filetime:134362090000012230')
            self.assertIsNone(caller.endpoint.ref.pane)
            self.assertFalse(caller.is_user_shell)
            self.assertIsNone(endpoints.permission_class(caller))
            cli._check_sender(caller)
            self.assertEqual([m['method'] for m in self.k.messages],
                             ['initialize','initialized','thread/loaded/list','thread/read','thread/loaded/list'])
            self.assertFalse(self.state.exists())

    def test_missing_mismatched_conflicting_variables_and_manual(self):
        env=self.chain()
        with self.scope(),patch.object(C,'discover',side_effect=AssertionError('precheck IO')):
            for change in ({'CODEX_THREAD_ID':''},{'CODEX_SESSION_ID':''},
                           {'CODEX_THREAD_ID':'bad','CODEX_SESSION_ID':'bad'}):
                self.reject(C.identify(pid=100,environ={**env,**change}))
            sub=C.identify(pid=100,environ={**env,'CODEX_THREAD_ID':uuid(2)})
            self.reject(sub,'sender_is_subagent')
            attempt=Mock(target=EndpointRef(Provider.CODEX,uuid(1),200,'s'),delivery_detail={})
            for caller,reason in ((sub,'reporter_is_subagent'),(C.identify(pid=100,environ={}), 'caller_unattributed')):
                with self.assertRaises(reports.ReportError) as caught:
                    reports._attribute(attempt,reports.ReportInput('t',ReportKind.RESULT,manual=True),caller,Path('/absent'))
                self.assertEqual(caught.exception.code,reason)

    def test_daemon_nearest_agent_generation_root_and_completeness(self):
        env=self.chain()
        with self.scope():
            evidence=D.discover(self.p.transport)
            negatives=[replace(evidence,complete=False),replace(evidence,root_identity=''),
                       replace(evidence,daemon=None),replace(evidence,daemon=(200,'999')),
                       replace(evidence,daemon=(300,evidence.daemon[1])),replace(evidence,rows=()),
                       replace(evidence,root_identity='a'*64)]
            negatives += [replace(evidence,rows=(replace(evidence.rows[0],kind=k),)) for k in ('unknown','subagent','internal','conflict')]
            negatives.append(replace(evidence,rows=(replace(evidence.rows[0],metadata_verified=False),)))
            for value in negatives: self.reject(C.identify(pid=100,environ=env,evidence=value))
            saved=self.k.processes[200]
            self.k.processes[200]=(*saved[:4],'claude.exe')
            self.reject(C.identify(pid=100,environ=env,evidence=evidence))
            self.k.processes[200]=saved
            for name in ('claude.exe','grok.exe','codex.exe'):
                self.k.processes[201]=(200,134362090001612230,self.k.sid,False,name)
                self.reject(C.identify(pid=100,environ=env,evidence=evidence))
            self.k.processes[201]=(200,134362090001612230,self.k.sid,False,'pwsh.exe')
            with patch.object(self.p.process,'same_generation',return_value=Presence.EXITED):
                self.reject(C.identify(pid=100,environ=env,evidence=evidence))
            # A reused ancestor OUTSIDE the proved daemon segment cannot erase it.
            self.k.processes[4]=(0,134362090001812230,self.k.sid,False,'pwsh.exe')
            proved=C.identify(pid=100,environ=env,evidence=evidence)
            self.assertIsNotNone(proved.endpoint)
            self.assertEqual(proved.endpoint.ref.native_id,uuid(1))

    def test_trace_preserves_prefix_and_identifies_each_boundary(self):
        self.chain();p=self.p.process
        for stage, reason in (('process', 'process_unverified'), ('token', 'process_unverified'),
                              ('queryable', 'process_identity_unverified')):
            self.k.restricted_process_stage = stage
            trace=p.trace(100)
            self.assertEqual([r.identity.pid for r in trace.records],[100,201,200])
            self.assertEqual(trace.termination,reason)
        self.k.restricted_process_stage = 'process'
        self.k.processes.pop(4)
        self.assertEqual(p.trace(100).termination,'process_exited')
        self.k.processes[4]=(0,134362090001912230,self.k.sid,False,'pwsh.exe')
        self.assertEqual(p.trace(100).termination,'parent_reused')
        self.assertEqual(len(p.trace(100).records),3)
        self.k.processes[200]=(100,134362090000012230,self.k.sid,False,'codex.exe')
        self.assertEqual(p.trace(100).termination,'cycle')
        self.assertEqual(p.trace(100,1).termination,'limit')
        self.assertEqual(len(p.trace(100,1).records),1)
        self.assertEqual(p.trace(999).records,())
        self.assertEqual(p.trace(999).termination,'process_exited')

    def test_manual_requires_positive_terminal_shell_and_revalidated_chain(self):
        self.chain();self.k.processes[200]=(0,134362090000012230,self.k.sid,False,'WindowsTerminal.exe')
        with self.scope(),patch.object(C,'discover',side_effect=AssertionError('manual no daemon')):
            caller=C.identify(pid=100,environ={},terminal=True)
            self.assertTrue(caller.is_user_shell)
            self.assertIsNone(caller.endpoint)
            self.assertIsNone(endpoints.permission_class(caller))
            for env in ({'CLAUDECODE':'1'},{'GROK_SESSION_ID':'x'},{'CODEX_THREAD_ID':uuid(1)}):
                self.reject(C.identify(pid=100,environ=env,terminal=True))
            self.reject(C.identify(pid=100,environ={},terminal=False))
            self.reject(C.identify(pid=999,environ={},terminal=True))
            self.k.processes[200]=(4,134362090000012230,self.k.sid,False,'WindowsTerminal.exe')
            self.assertTrue(C.identify(pid=100,environ={},terminal=True).is_user_shell)
            self.k.processes[200]=(4,134362090000012230,self.k.sid,False,'python.exe')
            self.reject(C.identify(pid=100,environ={},terminal=True))
            self.k.processes[200]=(0,134362090000012230,self.k.sid,False,'python.exe')
            self.k.processes[201]=(200,134362090001612230,self.k.sid,False,'python.exe')
            self.reject(C.identify(pid=100,environ={},terminal=True))
            self.k.processes[201]=(200,134362090001612230,self.k.sid,False,'pwsh.exe')
            with patch.object(self.p.process,'same_generation',return_value=Presence.UNKNOWN):
                self.reject(C.identify(pid=100,environ={},terminal=True))

    def run_cli(self,*args):
        out,err=io.StringIO(),io.StringIO()
        with redirect_stdout(out),redirect_stderr(err): code=cli.main(list(args))
        return code,out.getvalue(),err.getvalue()

    def test_alias_commands_real_entry_local_only_and_generation_bound(self):
        with (self.scope(),patch.object(cli,'_open_store',side_effect=AssertionError('alias ledger')),
              patch.object(cli,'_refresh_summary',side_effect=AssertionError('alias summary'))):
            code,out,err=self.run_cli('alias','set','work',uuid(1),'--json')
            self.assertEqual((code,err),(0,''))
            self.assertTrue(json.loads(out)['localOnly'])
            self.assertFalse((self.state/DB_NAME).exists())
            raw=json.loads((self.state/'target-aliases/codex.json').read_bytes())
            self.assertEqual(len(raw['aliases']),1)
            row=raw['aliases'][0]
            self.assertEqual(row['threadId'],uuid(1))
            self.assertEqual(set(row),{'alias','threadId','rootIdentity'})
            self.assertNotIn('expiresAt',row)
            result=D.discover(self.p.transport)
            self.assertEqual(result.select('codex@work').thread,uuid(1))
            self.assertEqual(result.document()['peers'][0]['target'],'codex@work')
            out=io.StringIO()
            with redirect_stdout(out):D.print_peers(result)
            self.assertIn('codex@work',out.getvalue())
            with patch.object(A,'discover',side_effect=AssertionError('local list/rm')):
                code,out,err=self.run_cli('alias','list','--json')
                self.assertEqual(code,0)
                self.assertEqual(json.loads(out)['aliases'][0]['eligibility'],'not_checked')
                self.assertEqual(self.run_cli('alias','rm','work')[0],0)
            self.assertEqual(json.loads((self.state/'target-aliases/codex.json').read_bytes())['aliases'],[])
            self.assertTrue(all(m['method'] in {'initialize','initialized','thread/loaded/list','thread/read'} for m in self.k.messages))

    def test_alias_stale_targets_not_hidden_or_rebound(self):
        with self.scope():
            aliases=AliasFile(self.p.files,self.state)
            good=self.alias_row();aliases.replace([good])
            for change in ({'rootIdentity':'b'*64},
                           {'threadId':uuid(9)},{'expiresAt':time.time()-1}):
                raw={'schema':1,'aliases':[{**good,**change}]}
                self.p.files.atomic_write(aliases.root,json.dumps(raw).encode(),name='codex.json',prefix='.test.')
                result=D.discover(self.p.transport)
                self.assertEqual(result.aliases.names,{})
                self.assertEqual(result.aliases.unavailable,('owner-task',))
                with self.assertRaisesRegex(D.NativeFailure,'alias_target_unavailable'):result.select('owner-task')
                self.assertEqual(result.document()['unavailableAliases'][0]['message'],'别名目标当前不可用')
                out=io.StringIO()
                with redirect_stdout(out):D.print_peers(result)
                self.assertIn('别名目标当前不可用',out.getvalue())
                self.assertEqual(json.loads((aliases.root/'codex.json').read_bytes()),raw)
            for key in ('daemonPid','daemonBirth'):good.pop(key)
            aliases.replace([good])
            self.assertEqual(D.discover(self.p.transport).aliases.unavailable,())
            for change in ({'daemonBirth':'999','daemonPid':200},{'daemonPid':300,'daemonBirth':'999'}):
                aliases.replace([{**good,**change}])
                self.assertEqual(D.discover(self.p.transport).select('owner-task').thread,uuid(1))

    def test_alias_selection_failures_never_write_and_lock_is_enforced(self):
        with self.scope():
            for name,target in (('../bad',uuid(1)),('deadbeef',uuid(1)),('valid','owner-task')):
                self.assertEqual(self.run_cli('alias','set',name,target)[0],3)
            self.assertFalse(self.state.exists())
            self.k.loaded=[uuid(1),uuid(2)]
            self.assertEqual(self.run_cli('alias','set','work','00000000')[0],2)
            self.k.metadata[uuid(1)]={'id':uuid(1),'source':{'subAgent':'review'}}
            self.assertEqual(self.run_cli('alias','set','work',uuid(1))[0],2)
            self.assertFalse(self.state.exists())
            self.k.loaded=[uuid(1)];self.k.metadata.clear()
            with patch.object(self.p.lifecycle,'try_lock',side_effect=BlockingIOError()):
                code,_,err=self.run_cli('alias','set','work',uuid(1))
                self.assertEqual(code,8)
                self.assertIn('alias_store_busy',err)
            self.assertFalse((self.state/'target-aliases/codex.json').exists())
            self.assertEqual(self.p.lifecycle._leases,{})
            path=self.state/'target-aliases/codex.json'
            self.p.files.atomic_write(path.parent,b'bad-json',name=path.name,prefix='.bad.')
            self.assertEqual(self.run_cli('alias','set','work',uuid(1))[0],8)
            self.assertEqual(path.read_bytes(),b'bad-json')
            self.assertEqual(self.run_cli('alias','rm','work')[0],8)
            self.assertEqual(path.read_bytes(),b'bad-json')

    def test_alias_linux_rejection_no_old_help_changes(self):
        # This rejection precedes backend I/O, including on a Windows test host.
        with using_platform(SimpleNamespace(name='linux')),patch.object(cli,'_refresh_summary',side_effect=AssertionError('no Linux alias IO')):
            for command in (('list',),('set','work',uuid(1)),('rm','work')):
                code,out,err=self.run_cli('alias',*command)
                self.assertEqual((code,out),(3,''))
                self.assertIn('alias_platform_unsupported',err)
            self.assertNotIn('alias',cli.build_parser().format_help())

    def test_alias_invalid_state_root_is_fixed_error_before_discovery(self):
        with self.scope(),patch.dict(os.environ,{'AB_STATE_DIR':r'\\host\share'}):
            for args in (('list',),('set','work',uuid(1)),('rm','work')):
                code,out,err=self.run_cli('alias',*args)
                self.assertEqual((code,out),(8,''))
                self.assertIn('alias_store_unverified',err)
            self.assertEqual(self.k.messages,[])
            self.assertFalse(self.state.exists())

    def task(self,store,*,origin=None,reviewer=None,target=None,options=None):
        target=target or EndpointRef(Provider.CODEX,uuid(1),200,'win-filetime:134362090000012230')
        task,attempt=store.create_task(title='synthetic',flow=Flow.REVIEW if reviewer else Flow.HANDOFF,
                                       origin=origin,origin_class=None,reviewer=reviewer,target=target,
                                       body='fixture',refs=[],now=1000,task_options=options or {})
        self.assertTrue(store.begin_send(attempt.id,now=1001,pid=100,start_ticks='win-filetime:134362090001712230'))
        store.finish_send(attempt.id,delivery=Delivery.QUEUED,reason='fixture',provider_ref=None,detail={},now=1002)
        return task,store.get_attempt(attempt.id)

    def report(self,store,task,attempt,kind):
        return reports.apply_report(store,reports.ReportInput(task.id,kind),
                                    caller=endpoints.Caller(Endpoint(attempt.target),None,agent_env=True),
                                    caller_class=None,now=1003,cwd=self.root)

    def test_poll_only_and_review_target_contracts_both_platforms(self):
        claude=EndpointRef(Provider.GROK,uuid(2),300,'win-filetime:1')  # W3 migrates the unsupported-provider guard to Grok.
        with self.scope():
            self.assertFalse(can_notify(claude))
            self.assertTrue(can_notify(replace(claude,provider=Provider.CODEX)))
            with self.assertRaisesRegex(ValueError,'receipt_poll_only_required'):
                receipt_options(claude,no_notify=False)
            self.assertEqual(receipt_options(claude,no_notify=True),{'receiptMode':'poll_only'})
            with self.assertRaisesRegex(cli.CliError,'target_no_inbox'):
                cli._check_target(Endpoint(claude),allow_shared=True)
            # A bare registered name or Claude env never proves its root.
            self.chain();self.k.processes[200]=(0,134362090000012230,self.k.sid,False,'claude.exe')
            self.reject(C.identify(pid=100,environ={'CLAUDE_SESSION_ID':uuid(2)},terminal=True))
        with using_platform(SimpleNamespace(name='linux')):
            self.assertTrue(can_notify(claude))
            self.assertEqual(receipt_options(claude,no_notify=True),{})
            self.assertEqual(receipt_options(claude,no_notify=False),{})

    def test_all_result_routes_and_poll_output_never_queue_unsupported_grok(self):
        origin=EndpointRef(Provider.GROK,uuid(2),300,'win-filetime:1')
        with self.scope(),Store.open(self.state) as store:
            for kind in (ReportKind.RESULT,ReportKind.BLOCKED,ReportKind.FAILED,ReportKind.APPROVE,ReportKind.CHANGES):
                task,attempt=self.task(store,origin=origin,options={'notify':True,'receiptMode':'poll_only'})
                if kind in (ReportKind.APPROVE,ReportKind.CHANGES):
                    attempt=store.add_attempt(task.id,role=Role.REVIEW,target=attempt.target,body='fixture',refs=[],now=1002,
                                              sender=None,sender_class=None)
                    store.begin_send(attempt.id,now=1002,pid=100,start_ticks='s')
                    store.finish_send(attempt.id,delivery=Delivery.QUEUED,reason='fixture',provider_ref=None,detail={},now=1002)
                before=len(store.attempts(task.id))
                outcome=self.report(store,task,attempt,kind)
                self.assertEqual(outcome.followups,[])
                self.assertEqual(len(store.attempts(task.id)),before)
                self.assertTrue(any(e['kind']=='notification_skipped' for e in store.events(task.id)))
                self.assertEqual(views._task_document(store,task)['receiptMode'],'poll_only')
                out=io.StringIO()
                with redirect_stdout(out):views._print_task(store,task,now=1004,show_body=False)
                self.assertIn('回执方式：poll_only',out.getvalue())

    def test_auto_review_rejected_atomically_and_codex_still_queues(self):
        claude=EndpointRef(Provider.GROK,uuid(2),300,'win-filetime:1')
        with self.scope(),Store.open(self.state) as store:
            task,attempt=self.task(store,reviewer=claude)
            with self.assertRaisesRegex(reports.ReportError,'target_no_inbox'):
                self.report(store,task,attempt,ReportKind.RESULT)
            self.assertEqual(len(store.attempts(task.id)),1)
            self.assertIs(store.get_attempt(attempt.id).work,Work.AWAITING_ACK)
            task,attempt=self.task(store,reviewer=replace(claude,provider=Provider.CODEX))
            outcome=self.report(store,task,attempt,ReportKind.RESULT)
            self.assertEqual(len(outcome.followups),1)
            self.assertIs(outcome.followups[0].role,Role.REVIEW)

    def test_accept_close_each_recipient_and_reminder_constructor(self):
        claude=EndpointRef(Provider.GROK,uuid(2),300,'win-filetime:1')
        with self.scope(),Store.open(self.state) as store:
            for state in (closure.ACCEPTED,closure.CLOSED):
                task,attempt=self.task(store,target=claude)
                outcome=closure.queue_closures(store,task,store.attempts(task.id),state,now=1003,
                    decider='fixture',reason=None,sender=None,sender_class=None)
                self.assertEqual(outcome.queued,[])
                self.assertTrue(any(e['kind']=='notification_skipped' for e in store.events(task.id)))
                task,attempt=self.task(store)
                self.assertEqual(len(closure.queue_closures(store,task,store.attempts(task.id),state,now=1003,
                    decider='fixture',reason=None,sender=None,sender_class=None).queued),1)
            task,attempt=self.task(store,origin=claude)
            self.report(store,task,attempt,ReportKind.RESULT)
            self.assertFalse(reminders.reminder_candidate(task))
            dispatcher=Dispatcher(store,lambda:[],{},clock=lambda:5000)
            self.assertEqual(dispatcher.queue_reminders(),0)
            fake=Mock(token='token',view=describe(task,store.attempts(task.id)));fake.due.return_value=True
            with patch('agentstatus_bridge.dispatch.pending_reminder',return_value=fake):
                self.assertFalse(dispatcher._queue_reminder(task.id,'token',5000))
            self.assertEqual(len(store.attempts(task.id)),1)

    def test_wait_readonly_timeout_no_revival_and_generation_reporting(self):
        with self.scope(),Store.open(self.state) as store:
            task,attempt=self.task(store)
            caller=endpoints.Caller(Endpoint(replace(attempt.target,start_ticks='win-filetime:9')),None,agent_env=True)
            error=None;attributed=None
            try:attributed=reports._attribute(attempt,reports.ReportInput(task.id,ReportKind.RESULT),caller,Path('/absent'))
            except reports.ReportError as failure:error=failure.code
            self.assertIsNone(error)
            self.assertEqual(attributed,'agent')
        with (self.scope(),patch.object(cli,'_revive_worker',side_effect=AssertionError('wait revive')),
              patch.object(cli,'_refresh_summary',side_effect=AssertionError('wait summary')),
              patch.object(D,'discover',side_effect=AssertionError('wait daemon'))):
            before={p.name:p.read_bytes() for p in self.state.iterdir() if p.is_file()}
            self.assertEqual(self.run_cli('wait',task.id,'--timeout','0')[0],4)
            self.assertEqual(self.run_cli('wait',task.id,'--until','sent','--json')[0],0)
            with patch.object(L.sqlite3,'connect',wraps=sqlite3.connect) as connect, L.open_store() as ro:
                self.assertIn('mode=ro',connect.call_args.args[0])
                self.assertIs(connect.call_args.kwargs['uri'],True)
                self.assertEqual(ro._conn.execute('PRAGMA query_only').fetchone()[0],1)
                with self.assertRaises(sqlite3.OperationalError):ro._conn.execute('DELETE FROM tasks')
            after={p.name:p.read_bytes() for p in self.state.iterdir() if p.is_file() and not p.name.endswith(('-wal','-shm'))}
            self.assertEqual({k:v for k,v in before.items() if not k.endswith(('-wal','-shm'))},after)
            self.assertEqual(self.k.messages,[])

    def test_w3_claude_result_review_closure_and_reminder_use_native_routes(self):
        native=EndpointRef(Provider.CLAUDE,uuid(2),300,'win-filetime:1')
        with self.scope(),Store.open(self.state) as store:
            self.assertTrue(can_notify(native))
            self.assertEqual(receipt_options(native,no_notify=False),{'receiptMode':'push'})
            self.assertEqual(receipt_options(native,no_notify=True),{'receiptMode':'poll_only'})
            for kind in (ReportKind.RESULT,ReportKind.BLOCKED,ReportKind.FAILED,ReportKind.APPROVE,ReportKind.CHANGES):
                task,attempt=self.task(store,origin=native,options={'notify':True,'receiptMode':'push'})
                if kind in (ReportKind.APPROVE,ReportKind.CHANGES):
                    attempt=store.add_attempt(task.id,role=Role.REVIEW,target=attempt.target,body='fixture',refs=[],now=1002,
                                             sender=None,sender_class=None)
                    store.begin_send(attempt.id,now=1002,pid=100,start_ticks='s')
                    store.finish_send(attempt.id,delivery=Delivery.QUEUED,reason='fixture',provider_ref=None,detail={},now=1002)
                outcome=self.report(store,task,attempt,kind)
                self.assertEqual(len(outcome.followups),1)
                self.assertEqual(outcome.followups[0].target,native)
                self.assertIs(outcome.followups[0].role,Role.NOTICE)
                self.assertTrue(reminders.reminder_candidate(task))
            task,attempt=self.task(store,reviewer=native)
            outcome=self.report(store,task,attempt,ReportKind.RESULT)
            self.assertEqual(len(outcome.followups),1)
            self.assertIs(outcome.followups[0].role,Role.REVIEW)
            for state in (closure.ACCEPTED,closure.CLOSED):
                task,_=self.task(store,target=native)
                outcome=closure.queue_closures(store,task,store.attempts(task.id),state,now=1003,
                    decider='fixture',reason=None,sender=None,sender_class=None)
                self.assertEqual(len(outcome.queued),1)

    def test_wait_absent_no_directory_created_and_write_gate_stays_nine(self):
        with self.scope():
            self.assertEqual(self.run_cli('wait','no-task','--timeout','0')[0],8)
            self.assertFalse(self.state.exists())
            for cmd in (['send','--to',uuid(1),'--file','missing'],['report','t','--manual','--result'],['accept','t']):
                self.assertEqual(self.run_cli(*cmd)[0],3)  # enabled command, unattributed caller still refuses before writes
            self.assertFalse(self.state.exists())
            self.assertFalse(any(m['method']=='thread/queue/add' for m in self.k.messages))

    def test_send_preflight_poll_is_explicit_and_persisted_without_opening_gate(self):
        origin=EndpointRef(Provider.GROK,uuid(2),300,'win-filetime:1')
        target=Endpoint(EndpointRef(Provider.CODEX,uuid(1),200,'win-filetime:2'))
        caller=endpoints.Caller(Endpoint(origin),None,agent_env=True,via='controlled-fixture')
        with (self.scope(),patch.object(cli,'discover',return_value=[target]),
              patch.object(cli,'identify_caller',return_value=caller),
              patch.object(cli,'_start_worker',return_value=False),patch.object(cli,'_worker_up',return_value=False)):
            args=cli.build_parser().parse_args(['send','--to',uuid(1),'-m','fixture','--no-wait'])
            with self.assertRaisesRegex(cli.CliError,'receipt_poll_only_required'): cli.cmd_send(args)
            self.assertFalse(self.state.exists())
            args.no_notify=True
            for mode in (False,True):
                args.json=mode;out=io.StringIO()
                with redirect_stdout(out):code=cli.cmd_send(args)  # below the still-closed outer gate, fixture only
                self.assertEqual(code,6)
                self.assertIn('poll_only',out.getvalue())
                self.assertIn('可能没有窗口在显示',out.getvalue())
                self.assertIn('审批',out.getvalue())
            with Store.open(self.state) as store:
                self.assertEqual(len(store.list_tasks()),2)
                self.assertTrue(all(t.options['receiptMode']=='poll_only' and t.options['notify'] is False for t in store.list_tasks()))
            self.assertEqual(self.run_cli('send','--to',uuid(1),'-m','fixture','--no-notify','--no-wait')[0],3)
            self.assertFalse(any(m['method']=='thread/queue/add' for m in self.k.messages))

    def test_caller_os_failure_and_manual_report_are_explicit(self):
        self.chain();self.k.processes[200]=(0,134362090000012230,self.k.sid,False,'WindowsTerminal.exe')
        with self.scope():
            with patch.object(self.p.process,'trace',side_effect=OSError('synthetic')):
                self.reject(C.identify(pid=100,environ={},terminal=True))
            caller=C.identify(pid=100,environ={},terminal=True)
            self.assertTrue(caller.is_user_shell)
            attempt=Mock(target=EndpointRef(Provider.CODEX,uuid(1),200,'s'),delivery_detail={})
            self.assertEqual(reports._attribute(attempt,reports.ReportInput('t',ReportKind.RESULT,manual=True),caller,Path('/absent')),'manual')
            with self.assertRaisesRegex(reports.ReportError,'manual_flag_required'):
                reports._attribute(attempt,reports.ReportInput('t',ReportKind.RESULT),caller,Path('/absent'))


if __name__=='__main__':unittest.main()

