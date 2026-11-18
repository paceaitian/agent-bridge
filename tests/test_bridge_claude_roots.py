"""§84 synthetic Linux process environments; never discover host sessions."""
import io
import json
import os
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch
from contextlib import redirect_stdout
from dataclasses import replace
from types import SimpleNamespace

import bridge_support
from bridge_support import FakeProc
from agentstatus_bridge import claude_titles, endpoints, doctor
from agentstatus_bridge.observer_dbus import ObserverView
from agentstatus_bridge.platforms.linux import files as F
from agentstatus_bridge.platforms.claude_roots import environment_config, MAX_ENV_BYTES


@unittest.skipIf(os.name == 'nt', 'Linux /proc fixture')
class ConfigRootsTests(unittest.TestCase):
    def setUp(self):
        self.temp = TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name); self.proc = self.root / 'proc'
        self.fake = FakeProc(self.proc)
        self.enterContext(patch.dict(os.environ))
        os.environ.pop('AB_CLAUDE_SESSIONS_DIR', None)
        os.environ.pop('CLAUDE_CONFIG_DIR', None)
        self.enterContext(patch.object(Path, 'home', return_value=self.root))

    def account(self, pid, config, *, start='42', comm='claude', env=True):
        self.fake.add(pid, comm=comm, start=start)
        value = b'UNRELATED_SECRET=DO-NOT-PROJECT\0'
        if env: value += ('CLAUDE_CONFIG_DIR='+str(config)).encode()+b'\0'
        (self.proc/str(pid)/'environ').write_bytes(value)
        sessions = config/'sessions'; sessions.mkdir(parents=True, exist_ok=True)
        (sessions/f'{pid}.json').write_text(json.dumps({'pid':pid,'procStart':start,'sessionId':f'session-{pid}',
            'kind':'interactive','peerProtocol':1,'messagingSocketPath':'fixture.sock'}))
        return sessions

    def discover(self):
        source=endpoints.DiscoverySources(proc_root=self.proc)
        with patch.object(endpoints, '_is_owned_socket', return_value=True):
            return endpoints._discover_claude(source, {}, ObserverView())

    def test_cross_environment_many_accounts_and_stale_duplicate_pid(self):
        a=self.account(200,self.root/'account-a')
        b=self.account(300,self.root/'account-b')
        self.account(200,self.root/'.claude',start='old')
        self.fake.add(200,comm='claude',start='42')
        (self.proc/'200/environ').write_bytes(('CLAUDE_CONFIG_DIR='+str(a.parent)+'\0').encode())
        self.assertEqual(set(F.claude_sessions_dirs(self.proc)),{self.root/'.claude/sessions',a,b})
        found=self.discover()
        self.assertEqual({item.ref.pid for item in found},{200,300})
        self.assertTrue(all(item.ref.start_ticks=='42' for item in found))
        self.assertNotIn('DO-NOT-PROJECT',repr(found))
        caller=endpoints.identify_caller(found,pid=200,proc_root=self.proc,environ={})
        self.assertIsNotNone(caller.endpoint)

    def test_explicit_override_never_enumerates_processes_or_real_roots(self):
        real=self.account(200,self.root/'real')
        isolated=self.root/'isolated'; isolated.mkdir()
        os.environ['AB_CLAUDE_SESSIONS_DIR']=str(isolated)
        os.environ['CLAUDE_CONFIG_DIR']=str(real.parent)
        with patch.object(F, 'list_pids', side_effect=AssertionError('real process enumeration')):
            self.assertEqual(F.claude_sessions_dirs(self.proc),(isolated,))
            self.assertEqual(self.discover(),[])

    def test_missing_unreadable_non_claude_and_exited_environments_skip(self):
        self.account(200,self.root/'none',env=False)
        self.account(300,self.root/'not-agent',comm='python')
        self.account(400,self.root/'gone'); (self.proc/'400/environ').unlink()
        self.assertEqual(F.claude_sessions_dirs(self.proc),(self.root/'.claude/sessions',))
        original=Path.open
        def opened(path,*args,**kwargs):
            if path.name=='environ': raise PermissionError('private-exception')
            return original(path,*args,**kwargs)
        with patch.object(Path,'open',opened):
            self.assertEqual(F.claude_sessions_dirs(self.proc),(self.root/'.claude/sessions',))

    def test_environment_projection_exact_key_size_and_duplicates(self):
        self.assertEqual(environment_config(b'SECRET=hidden\0CLAUDE_CONFIG_DIR=/fixture\0').value,'/fixture')
        for raw in (b'OTHER_CLAUDE_CONFIG_DIR=/bad\0', b'CLAUDE_CONFIG_DIR=x\0CLAUDE_CONFIG_DIR=y\0',
                    b'x'*(MAX_ENV_BYTES+1), b'CLAUDE_CONFIG_DIR=\xff\0'):
            self.assertIsNone(environment_config(raw).value)

    def test_own_environment_union_and_doctor_share_actual_roots(self):
        a=self.account(200,self.root/'other-account')
        os.environ['CLAUDE_CONFIG_DIR']=str(self.root/'own-account')
        self.assertIn(self.root/'own-account/sessions', F.claude_sessions_dirs(self.proc))
        with patch.object(doctor,'claude_sessions_dirs',return_value=F.claude_sessions_dirs(self.proc)):
            checks=doctor.registry_checks(doctor.linux_registries())
        self.assertTrue(checks['claudeRegistryReadable']); self.assertEqual(checks['claudeRegistryCount'],1)
        out=io.StringIO()
        with redirect_stdout(out): doctor.print_checks(checks)
        self.assertIn(str(a),out.getvalue()); self.assertNotIn('DO-NOT-PROJECT',out.getvalue())

    def test_directory_budget_is_global_not_per_account(self):
        self.account(200,self.root/'a'); self.account(300,self.root/'b')
        with patch.object(endpoints,'MAX_REGISTRY_FILES',1):
            self.assertEqual(len(self.discover()),1)

    def test_l1_only_target_value_is_decoded(self):
        sessions=self.account(200,self.root/'actual')
        (self.proc/'200/environ').write_bytes(b'OTHER=\xff\0CLAUDE_CONFIG_DIR='+bytes(sessions.parent)+b'\0')
        self.assertIn(sessions,F.claude_sessions_dirs(self.proc))
        self.assertEqual(len(self.discover()),1)
        self.assertEqual(environment_config(b'OTHER=\xff\0').state,'absent')
        for raw in (b'CLAUDE_CONFIG_DIR=\xff\0',b'CLAUDE_CONFIG_DIR=x\0CLAUDE_CONFIG_DIR=y\0',
                    b'x'*(MAX_ENV_BYTES+1)):
            self.assertEqual(environment_config(raw).state,'unknown')

    def test_l2_empty_override_uses_live_roots_and_default_primary(self):
        sessions=self.account(200,self.root/'actual')
        os.environ['AB_CLAUDE_SESSIONS_DIR']=''
        self.assertIn(sessions,F.claude_sessions_dirs(self.proc))
        self.assertEqual(F.claude_sessions_dir(),self.root/'.claude/sessions')
        self.assertEqual(len(self.discover()),1)

    def test_l3_foreign_relative_values_and_per_pid_exceptions_skip(self):
        a=self.account(200,self.root/'a'); b=self.account(300,self.root/'b')
        for value in ('~absent-account/cfg','relative/cfg'):
            (self.proc/'200/environ').write_bytes(('CLAUDE_CONFIG_DIR='+value+'\0').encode())
            self.assertNotIn(a,F.claude_sessions_dirs(self.proc))
            self.assertIn(b,F.claude_sessions_dirs(self.proc))
        original=Path.open
        for failure in (RuntimeError,ValueError):
            def opened(path,*args,**kwargs):
                if path==self.proc/'200/environ': raise failure('fixture')
                return original(path,*args,**kwargs)
            with patch.object(Path,'open',opened):
                self.assertIn(b,F.claude_sessions_dirs(self.proc))

    def test_a02_environment_generation_is_rechecked(self):
        sessions=self.account(200,self.root/'actual')
        before=F.read_process(200,self.proc); self.assertIsNotNone(before)
        with patch.object(F,'read_process',side_effect=[before,replace(before,start_ticks='43')]):
            self.assertNotIn(sessions,F.claude_sessions_dirs(self.proc))

    def test_a07_foreign_uid_is_excluded_before_environment_read(self):
        sessions=self.account(200,self.root/'actual'); original=Path.stat
        def info(path,*args,**kwargs):
            if path==self.proc/'200': return SimpleNamespace(st_uid=os.getuid()+1)
            return original(path,*args,**kwargs)
        with patch.object(Path,'stat',info):
            self.assertNotIn(sessions,F.claude_sessions_dirs(self.proc))

    def test_a09_same_pid_conflicts_are_unselectable(self):
        a=self.account(200,self.root/'a'); b=self.root/'.claude/sessions'; b.mkdir(parents=True)
        data=json.loads((a/'200.json').read_text()); data['sessionId']='different-session'
        (b/'200.json').write_text(json.dumps(data))
        found=self.discover()
        self.assertEqual(len(found),2)
        self.assertTrue(all('ambiguous_thread' in ep.issues for ep in found))

    def test_a10_same_pid_identical_records_are_deduplicated(self):
        a=self.account(200,self.root/'a'); b=self.root/'.claude/sessions'; b.mkdir(parents=True)
        (b/'200.json').write_bytes((a/'200.json').read_bytes())
        found=self.discover()
        self.assertEqual(len(found),1); self.assertEqual(found[0].issues,())

    # §99 r1（两方审计 P1）：同一条注册记录经别名根与账号根都被看到时，先按注册事实折叠再取名，
    # 每条记录按根的顺序取一次名；取名结果因根而异也不能把同一会话拆成两条 ambiguous_thread
    TITLED = '0000000c-cccc-4ccc-8ccc-00000000000c'

    def aliased(self, *, link_projects):
        """账号根 account + 别名根 ~/.claude（sessions 必链；projects 按参数链），返回会话记录路径。"""
        self.addCleanup(claude_titles._MEMO.clear)
        account = self.root / 'account'
        sessions = account / 'sessions'; sessions.mkdir(parents=True)
        self.fake.add(200, comm='claude', start='42')
        (self.proc / '200' / 'environ').write_bytes(('CLAUDE_CONFIG_DIR=' + str(account) + '\0').encode())
        (sessions / '200.json').write_text(json.dumps({'pid': 200, 'procStart': '42', 'sessionId': self.TITLED,
            'kind': 'interactive', 'peerProtocol': 1, 'messagingSocketPath': 'fixture.sock', 'name': 'account-12'}))
        alias = self.root / '.claude'; alias.mkdir()
        os.symlink(sessions, alias / 'sessions')
        if link_projects:
            os.symlink(account / 'projects', alias / 'projects')
        record = account / 'projects' / '-w-repo' / f'{self.TITLED}.jsonl'
        record.parent.mkdir(parents=True)
        self.assertEqual(set(F.claude_sessions_dirs(self.proc)), {alias / 'sessions', sessions})
        return record

    @staticmethod
    def transcript(title, *, filler=0):
        rows = [{'type': 'user', 'sessionId': 'x'}, {'type': 'ai-title', 'aiTitle': title, 'sessionId': ConfigRootsTests.TITLED}]
        text = ''.join(json.dumps(row, separators=(',', ':')) + '\n' for row in rows)
        line = json.dumps({'type': 'user', 'message': 'x' * 1000}, separators=(',', ':')) + '\n'
        return (text + line * (filler // len(line) + 1 if filler else 0)).encode()

    def test_a10b_round_budget_running_out_between_roots_keeps_one_endpoint(self):
        self.aliased(link_projects=True).write_bytes(self.transcript('titled', filler=600 * 1024))
        with patch.object(claude_titles, 'ROUND_BUDGET_BYTES', claude_titles.FILE_BUDGET_BYTES):
            found = self.discover()
        self.assertEqual(len(found), 1)
        [item] = found
        self.assertEqual((item.issues, item.name, item.name_origin), ((), 'titled', 'found_ai'))
        self.assertIs(endpoints.resolve_target('claude@id:' + self.TITLED, found), item)

    def test_a10c_alias_root_without_projects_still_gets_the_title(self):
        self.aliased(link_projects=False).write_bytes(self.transcript('titled'))
        found = self.discover()
        self.assertEqual([(item.issues, item.name, item.name_origin) for item in found], [((), 'titled', 'found_ai')])
        self.assertIs(endpoints.resolve_target('claude@titled', found), found[0])

    def test_a10d_the_session_itself_is_identified_as_caller_under_two_roots(self):
        self.aliased(link_projects=False).write_bytes(self.transcript('titled'))
        found = self.discover()
        for environ in ({}, {'CLAUDE_CODE_SESSION_ID': self.TITLED}):
            with self.subTest(environ=sorted(environ)):
                caller = endpoints.identify_caller(found, pid=200, proc_root=self.proc, environ=environ)
                self.assertIsNotNone(caller.endpoint)
                self.assertEqual((caller.endpoint.ref.native_id, caller.endpoint.name), (self.TITLED, 'titled'))

    def test_a10e_one_untitled_file_behind_two_roots_is_read_once(self):
        self.aliased(link_projects=True).write_bytes(self.transcript('far', filler=claude_titles.FILE_BUDGET_BYTES + 4096))
        used = []
        real = claude_titles._read_title

        def recorder(reader, session_id, budget):
            outcome = real(reader, session_id, budget)
            used.append(outcome[1])
            return outcome
        with patch.object(claude_titles, '_read_title', side_effect=recorder):
            found = self.discover()
        self.assertEqual([(item.issues, item.name, item.name_origin) for item in found],
                         [((), 'account-12', 'budget_exhausted')])
        self.assertEqual(used, [claude_titles.FILE_BUDGET_BYTES])

    def test_a10f_the_first_root_in_registry_path_order_wins(self):
        # 审计 Opus N8：两个根各有一份不同标题的记录 → 取注册路径排序后第一个根（~/.claude 在 account 之前）的标题即停
        self.aliased(link_projects=False).write_bytes(self.transcript('account-title'))
        alias_record = self.root / '.claude' / 'projects' / '-w-repo' / f'{self.TITLED}.jsonl'
        alias_record.parent.mkdir(parents=True)
        alias_record.write_bytes(self.transcript('alias-title'))
        found = self.discover()
        self.assertEqual([(item.issues, item.name) for item in found], [((), 'alias-title')])

    def test_a10g_same_ref_with_different_registry_facts_stays_two_ambiguous_rows(self):
        # 审计 Opus N3：§84.1 只折叠相同的注册事实；同 ref（pid、代际、sessionId 相同）而事实不同 → 仍是两条 ambiguous_thread
        account = self.root / 'account'
        sessions = account / 'sessions'; sessions.mkdir(parents=True)
        self.fake.add(200, comm='claude', start='42')
        (self.proc / '200' / 'environ').write_bytes(('CLAUDE_CONFIG_DIR=' + str(account) + '\0').encode())
        record = {'pid': 200, 'procStart': '42', 'sessionId': self.TITLED, 'kind': 'interactive', 'peerProtocol': 1,
                  'messagingSocketPath': 'fixture.sock', 'name': 'account-12'}
        (sessions / '200.json').write_text(json.dumps(record))
        alias = self.root / '.claude' / 'sessions'; alias.mkdir(parents=True)
        (alias / '200.json').write_text(json.dumps({**record, 'name': 'renamed-elsewhere'}))
        found = self.discover()
        self.assertEqual(len(found), 2)
        self.assertEqual(len({item.ref for item in found}), 1)
        self.assertTrue(all('ambiguous_thread' in item.issues for item in found))
        self.assertEqual(sorted(item.name for item in found), ['account-12', 'renamed-elsewhere'])

    def test_a14_stale_first_root_cannot_starve_live_second_root(self):
        old=self.root/'old/sessions'; old.mkdir(parents=True)
        for pid in range(400,410): (old/f'{pid}.json').write_text('{}')
        live=self.account(200,self.root/'actual')
        with patch.object(endpoints,'claude_sessions_dirs',return_value=(old,live)), \
                patch.object(endpoints,'MAX_REGISTRY_FILES',4):
            self.assertEqual([ep.ref.pid for ep in self.discover()],[200])


class TestIsolation(unittest.TestCase):
    def test_default_registry_guard_is_exclusive_before_real_proc(self):
        self.assertIn('isolated-sessions',os.environ['AB_CLAUDE_SESSIONS_DIR'])
        with patch.object(F,'list_pids',side_effect=AssertionError('host proc')):
            roots=F.claude_sessions_dirs()
        self.assertEqual(roots,(Path(os.environ['AB_CLAUDE_SESSIONS_DIR']),))
        self.assertFalse(roots[0].exists())
