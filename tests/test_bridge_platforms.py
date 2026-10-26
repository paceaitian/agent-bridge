"""W1-1：类型、平台选择与P/M/R合同。Windows仅空后端，不作实机能力声明。"""
from dataclasses import replace
import errno
import json
import importlib
import os
from pathlib import Path
import subprocess
import sys
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from bridge_support import FakeProc
from agentstatus_bridge import endpoints, observer_dbus
from agentstatus_bridge.model import Provider, Runtime
from agentstatus_bridge.platforms.factory import make_platform
from agentstatus_bridge.platforms.linux import process, mux
from agentstatus_bridge.platforms.pane import PaneInfo, title_thread_prefix
from agentstatus_bridge.platforms.policy import CLAUDE_SYSTEM_DIRS, GROK_SYSTEM_DIRS
from agentstatus_bridge.platforms.types import Capability, Presence, ProcessIdentity, SampleState


class PlatformTests(unittest.TestCase):
    def test_live_windows_process_stays_unqualified_when_api_cannot_read(self):
        from unittest.mock import Mock
        api=Mock()
        api.process.side_effect=OSError('access denied')
        p=make_platform('windows',win_api=api).process
        self.assertIs(p.read(123).state,Presence.UNKNOWN)
        self.assertIs(p.same_generation(ProcessIdentity('windows',123,'win-filetime','1')),Presence.UNKNOWN)
        self.assertIs(p.snapshot().state,SampleState.UNVERIFIED)

    def test_namespace_adapter_forwards_injected_proc_root(self):
        from agentstatus_bridge.platforms import process as adapter
        root=Path('/synthetic-proc-root')
        with patch.object(process,'pid_namespace',return_value='synthetic-ns') as query:
            self.assertEqual(adapter.pid_namespace(root),'synthetic-ns')
            query.assert_called_once_with(root)

    def test_windows_modules_have_active_test_cases_on_linux(self):
        for name,clsname in [('test_bridge_windows','WindowsTests'),('test_bridge_windows_streams','StreamTests'),('test_bridge_registration','RegistrationTests')]:
            cls=getattr(importlib.import_module(name),clsname)
            self.assertFalse(getattr(cls,'__unittest_skip__',False))
            names=unittest.defaultTestLoader.getTestCaseNames(cls)
            self.assertGreaterEqual(len(names),7)
            self.assertFalse(any(getattr(getattr(cls,n),'__unittest_skip__',False) for n in names))

    def test_explicit_and_host_selection_and_unknown_rejection(self):
        self.assertEqual(make_platform().name, 'linux')
        self.assertEqual(make_platform('linux').name, 'linux')
        for name in ('win32', 'windows'):
            win = make_platform(name)
            self.assertEqual(win.name, 'windows')
            self.assertIs(win.discovery, Capability.UNVERIFIED)
        for name in ('darwin', 'plan9', '', 'Linux'):
            with self.subTest(name=name), self.assertRaisesRegex(ValueError, '^platform_unsupported$'):
                make_platform(name)

    def test_windows_factory_imports_no_linux_or_winapi_and_does_no_io(self):
        program = '''
import builtins, sys
import os
def no_uid():
    raise AssertionError('Windows UID read')
os.getuid = no_uid
original = builtins.__import__
def guarded(name, *a, **kw):
    if name.split('.')[0] in {'fcntl','pwd','gi','ctypes'}:
        raise AssertionError('platform import: '+name)
    return original(name, *a, **kw)
builtins.__import__ = guarded
from agentstatus_bridge.platforms.factory import make_platform
# Load selected Python modules under import guard; constructor IO guard below
# excludes importlib's own source reads, not any backend operation.
from agentstatus_bridge.platforms.windows import lazy, process, files, lifecycle, local_transport
def audit(event, args):
    if event in {'socket.connect','subprocess.Popen','os.listdir','os.scandir'} or event == 'open':
        raise AssertionError('factory IO: '+event)
sys.addaudithook(audit)
p = make_platform('win32')
assert p.name == 'windows'
assert not any(n.startswith('agentstatus_bridge.platforms.linux') for n in sys.modules)
assert not p.mux.sample().panes
assert not p.runtime.view().rows
assert not p.process.snapshot().records
print('ok')
'''
        done = subprocess.run([sys.executable, '-c', program], text=True, capture_output=True, timeout=20)
        self.assertEqual((done.returncode, done.stdout.strip()), (0, 'ok'), done.stderr)

    def test_nulls_never_claim_death_panes_idle_or_readable_empty(self):
        win = make_platform('windows')
        identity = ProcessIdentity('windows', 123, 'win-filetime', '134362090001712231')
        self.assertIs(win.process.read(123).state, Presence.UNKNOWN)
        self.assertIsNone(win.process.read(123).record)
        self.assertIs(win.process.same_generation(identity), Presence.UNKNOWN)
        self.assertEqual(win.process.ancestry(123), ())
        self.assertIsNone(win.process.pid_namespace())
        self.assertIs(win.process.snapshot().state, SampleState.UNVERIFIED)
        self.assertIs(win.mux.sample().state, SampleState.UNVERIFIED)
        self.assertEqual((win.mux.panes(), win.mux.titles()), ({}, {}))
        self.assertIs(win.runtime.sample().state, SampleState.UNAVAILABLE)
        self.assertEqual(win.runtime.view().states, {})
        self.assertIsNone(win.runtime.view().pane_state('%1', Provider.CODEX))
        self.assertIsNone(win.runtime.view().get('%1'))

    def test_unqualified_discovery_cannot_reach_legacy_provider_io(self):
        def forbidden(*args, **kw):
            self.fail('Windows capability gate leaked to Linux/provider sampling')
        source = endpoints.DiscoverySources(platform=make_platform('windows'),
                                            panes=forbidden, titles=forbidden, runtime=forbidden)
        with patch.object(process, 'list_pids', side_effect=forbidden):
            self.assertEqual(endpoints.discover(source), [])
            try:report=endpoints.codex_title_report(source)
            except Exception as error:report=error
            self.assertEqual(report, {'state': 'discovery_unverified'})

    def test_identity_encoding_keeps_exact_ticks_and_filetime(self):
        self.assertEqual(ProcessIdentity('linux', 1, 'linux-proc-ticks', '001234').stored_generation(), '001234')
        values = ('134362090001712230', '134362090001712231')
        encoded = [ProcessIdentity('windows', 1, 'win-filetime', v).stored_generation() for v in values]
        self.assertEqual(encoded, ['win-filetime:'+v for v in values])
        self.assertNotEqual(*encoded)
        for platform, kind, value in [('windows','linux-proc-ticks','1'), ('linux','win-filetime','1'),
                                      ('windows','win-filetime','1.0'), ('windows','win-filetime','１')]:
            with self.subTest(platform=platform, kind=kind, value=value), self.assertRaises(ValueError):
                ProcessIdentity(platform, 1, kind, value).stored_generation()

    def test_linux_process_projection_and_unknown_are_explicit(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            f = FakeProc(root)
            f.add(10, comm='parent (with ) bracket)', ppid=0, start='0001', tty=42)
            f.add(11, comm='codex', ppid=10, start='9007199254740993', tty=42,
                  argv=['codex', '--approve-for-me'], fds=['/synthetic/lock'])
            f.add(12, comm='cycle', ppid=12, start='3')
            (root/'self/ns').mkdir(parents=True)
            (root/'self/ns/pid').symlink_to('pid:[fake]')
            p = make_platform('linux', proc_root=root).process
            read = p.read(11)
            self.assertIs(read.state, Presence.CURRENT)
            self.assertIsNotNone(read.record)
            assert read.record is not None
            self.assertEqual(read.record.identity, ProcessIdentity('linux',11,'linux-proc-ticks','9007199254740993'))
            self.assertEqual((read.record.parent_pid,read.record.comm,read.record.tty_nr), (10,'codex',42))
            self.assertEqual([r.identity.pid for r in p.ancestry(11)], [11,10])
            self.assertEqual([r.identity.pid for r in p.ancestry(11,1)], [11])
            self.assertEqual(p.ancestry(11,0), ())
            self.assertEqual([r.identity.pid for r in p.ancestry(12)], [12])
            self.assertEqual([r.identity.pid for r in p.snapshot().records], [10,11,12])
            self.assertEqual(p.pid_namespace(),'pid:[fake]')
            self.assertIs(p.same_generation(read.record.identity), Presence.CURRENT)
            self.assertIs(p.same_generation(replace(read.record.identity,generation_value='9007199254740992')), Presence.EXITED)
            self.assertIs(p.same_generation(replace(read.record.identity,platform='windows')), Presence.UNKNOWN)
            self.assertIs(p.same_generation(replace(read.record.identity,generation_kind='win-filetime')), Presence.UNKNOWN)
            self.assertIs(p.read(999).state, Presence.UNKNOWN)
            self.assertIs(p.same_generation(replace(read.record.identity,pid=999)), Presence.UNKNOWN)
            # 旧的布尔恢复合同不变：None仍映射False，不能被三态“顺便修好”。
            self.assertFalse(process.is_same_generation(999,'1',root))

    def test_linux_mux_sample_matches_original_order_and_projects_title_once(self):
        thread = '019a0000-aaaa-7aaa-8aaa-aaaaaaaaaaaa'
        replies = [subprocess.CompletedProcess([],0,'%1\ttitle | '+thread+'\n',''),
                   subprocess.CompletedProcess([],0,'10\t%1\t90\tlabel\n','')]
        with patch.object(mux.subprocess,'run',side_effect=replies) as run:
            sample = make_platform('linux').mux.sample()
        self.assertIs(sample.state,SampleState.AVAILABLE)
        self.assertEqual(sample.panes,{10:PaneInfo('%1',10,'label',90,thread,True)})
        self.assertEqual([c.args[0] for c in run.call_args_list], [
            ['tmux','-u','list-panes','-a','-F','#{pane_id}\t#{pane_title}'],
            ['tmux','list-panes','-a','-F','#{pane_pid}\t#{pane_id}\t#{pid}\t#{session_name}']])
        self.assertEqual([c.kwargs['timeout'] for c in run.call_args_list],[3.0,3.0])
        with patch.object(mux.subprocess,'run',side_effect=OSError):
            sample = make_platform('linux').mux.sample()
        self.assertEqual(sample.panes,{})
        self.assertIs(sample.state,SampleState.EMPTY)
        self.assertEqual(title_thread_prefix('prefix | '+thread), thread)

    def test_runtime_availability_and_entire_selected_row_share_one_read(self):
        p = make_platform('linux').runtime
        for reply, state in [(None,SampleState.UNAVAILABLE),([],SampleState.AVAILABLE)]:
            with self.subTest(reply=reply), patch.object(observer_dbus,'_observer_rows',return_value=reply) as read:
                result=p.sample()
                self.assertIs(result.state,state)
                self.assertEqual(result.view.rows,{})
                self.assertEqual(read.call_count,1)
        rows=[{'key':'codex:one','paneId':'%1','agent':'codex','runtimeState':'ready',
               'attentionState':'action_required','runtimeUpdatedAt':1,'lastTurnEndedAt':2},
              {'key':'codex:two','paneId':'%1','agent':'codex','runtimeState':'working',
               'runtimeUpdatedAt':3,'lastTurnEndedAt':4}]
        with patch.object(observer_dbus,'_observer_rows',return_value=rows) as read:
            result=p.sample()
            self.assertEqual(read.call_count,1)
        row=result.view.pane_row('%1',Provider.CODEX)
        assert row is not None
        self.assertEqual((row.runtime,row.runtime_at,row.last_turn_ended_at),(Runtime.WAITING,1,2))
        self.assertEqual(result.view.pane_state('%1',Provider.CODEX),row.pane_state())

    def test_policy_directories_are_platform_data_not_linux_fallback(self):
        self.assertEqual(str(CLAUDE_SYSTEM_DIRS['linux']),'/etc/claude-code')
        self.assertEqual(str(CLAUDE_SYSTEM_DIRS['darwin']),'/Library/Application Support/ClaudeCode')
        self.assertEqual(str(CLAUDE_SYSTEM_DIRS['windows']),r'C:\Program Files\ClaudeCode')
        self.assertEqual(str(GROK_SYSTEM_DIRS['linux']),'/etc/grok')
        self.assertIsNone(GROK_SYSTEM_DIRS['windows'])

    def test_default_sources_use_selected_m_and_r_without_extra_sampling(self):
        source=endpoints.DiscoverySources()
        self.assertEqual(source.panes,source.platform.mux.panes)
        self.assertEqual(source.titles,source.platform.mux.titles)
        self.assertEqual(source.runtime,source.platform.runtime.view)
        with patch.object(mux.subprocess,'run',return_value=subprocess.CompletedProcess([],0,'','')) as run, \
                patch.object(observer_dbus,'_observer_rows',return_value=[]) as read:
            source.titles(); source.panes(); source.runtime()
            self.assertEqual((run.call_count,read.call_count),(2,1))


@unittest.skipIf(os.name == 'nt', 'Linux /proc 的 fd 链接')
class OpenFileScanTests(unittest.TestCase):
    """fd 扫描的完整性取自同一次扫描（Codex r4-P2-01）：退出与 fd 关闭算看全，读不到算没看全。"""

    def setUp(self):
        self._tmp = TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.proc = FakeProc(Path(self._tmp.name) / 'proc')
        self.proc.add(42, comm='codex', fds=('/x/a', '/x/b'))
        self.fd_dir = self.proc.root / '42' / 'fd'

    def scan(self):
        return process.open_file_scan(42, self.proc.root)

    def test_readable_scan_is_complete(self):
        targets, complete = self.scan()
        self.assertEqual((sorted(targets), complete), (['/x/a', '/x/b'], True))  # listdir 不保证顺序
        self.assertEqual(sorted(process.open_file_targets(42, self.proc.root)), ['/x/a', '/x/b'])

    def test_exited_process_is_complete_and_empty(self):
        self.assertEqual(process.open_file_scan(4343, self.proc.root), ([], True))

    def test_unlistable_fd_directory_is_incomplete(self):
        listdir = os.listdir
        def listing(path):
            if Path(path) == self.fd_dir:
                raise PermissionError(errno.EACCES, 'synthetic')
            return listdir(path)
        with patch.object(process.os, 'listdir', listing):
            self.assertEqual(self.scan(), ([], False))

    def test_one_unreadable_link_makes_the_scan_incomplete(self):
        readlink = os.readlink
        def read_link(path, *args, **kwargs):
            if Path(path) == self.fd_dir / '3':
                raise PermissionError(errno.EACCES, 'synthetic')
            return readlink(path, *args, **kwargs)
        with patch.object(process.os, 'readlink', read_link):
            self.assertEqual(self.scan(), (['/x/b'], False))

    def test_fd_closed_after_listing_is_still_complete(self):
        readlink = os.readlink
        def read_link(path, *args, **kwargs):
            if Path(path) == self.fd_dir / '3':
                raise FileNotFoundError(errno.ENOENT, 'closed')
            return readlink(path, *args, **kwargs)
        with patch.object(process.os, 'readlink', read_link):
            self.assertEqual(self.scan(), (['/x/b'], True))
