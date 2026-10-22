"""W1-0 冻结的 Linux 行为记录器；仅合成目录、原始行与假命令，业务层照常运行。

同一文件可在旧 src 上运行 --record，避免“旧路径”其实调用了新实现。
golden不是SQLite页字节：比较逻辑账本、公开字节、文件/锁系统调用顺序与最终文件权限。
"""
from contextlib import ExitStack, redirect_stdout, redirect_stderr
from dataclasses import asdict
import fcntl
import io
import json
import os
from pathlib import Path
import re
import secrets
import sqlite3
import subprocess
import sys
from tempfile import TemporaryDirectory
import time
import unittest
from unittest.mock import patch
import uuid

from bridge_support import FakeProc
from agentstatus_bridge import cli, doctor, endpoints, observer_dbus, summary, worker
from agentstatus_bridge.platforms.linux import process as procfs

GOLDEN = Path(__file__).with_name('fixtures') / 'bridge-linux-w1-golden.json'
THREAD = '019a0000-aaaa-7aaa-8aaa-aaaaaaaaaaaa'


def record_linux():
    with TemporaryDirectory(prefix='bridge-w1-') as tmp, ExitStack() as stack:
        root = Path(tmp)
        proc = root / 'proc'
        fake = FakeProc(proc)
        fake.add(99, comm='sh', ppid=0, start='9', tty=42)
        fake.add(100, comm='sh', ppid=99, start='10', tty=42)
        home = root / 'codex'
        home.mkdir()
        fake.add(200, comm='codex', ppid=100, start='001234', tty=42,
                 argv=['codex', '--ask-for-approval', 'on-request'],
                 fds=[str(home / 'thread-writer-locks' / (THREAD + '.lock'))])
        fake.add(300, comm='claude', ppid=100, start='9007199254740993', tty=42,
                 argv=['claude', '--permission-mode', 'plan', '--allow-dangerously-skip-permissions'])
        fake.add(250, comm='codex', ppid=200, start='1235', argv=['codex', 'app-server'],
                 fds=[str(home / 'thread-writer-locks' / (THREAD + '.lock'))])
        fake.add(400, comm='name (nested)', ppid=400, start='88')
        (proc / 'self/ns').mkdir(parents=True)
        (proc / 'self/ns/pid').symlink_to('pid:[fixture]')
        sessions = root / 'sessions'
        sessions.mkdir()
        with sqlite3.connect(home / 'state_5.sqlite') as db:
            db.execute('CREATE TABLE threads(id TEXT, source TEXT)')
            db.execute('INSERT INTO threads VALUES (?,?)', (THREAD, 'cli'))
        source = endpoints.DiscoverySources(proc_root=proc, claude_sessions=sessions,
                    codex_home=home, codex_sqlite_home=None, grok_home=root / 'grok',
                    uid=os.getuid())
        rows = [{'key': 'codex:fixture', 'paneId': '%1', 'agent': 'codex', 'runtimeState': 'ready',
                 'runtimeUpdatedAt': 80.0, 'lastTurnEndedAt': 79.0},
                {'key': 'codex:stale', 'paneId': '%1', 'agent': 'codex', 'runtimeState': 'working',
                 'freshness': 'stale', 'runtimeUpdatedAt': 90.0}]
        commands, effects = [], []
        fds = {}

        def norm(value):
            text = str(value).replace(tmp, '<fixture>')
            text = re.sub(r'\.summary\.[^/]+\.tmp', '.summary.<random>.tmp', text)
            return text

        def run(argv, **options):
            commands.append([list(argv), {key: value for key, value in options.items()}])
            text = ('%1\t工作 | ' + THREAD[:29] + '... ⠋\n' if '#{pane_title}' in argv[-1]
                    else '100\t%1\t90\tfixture\tlabel\ninvalid\n')
            return subprocess.CompletedProcess(argv, 0, stdout=text, stderr='')

        original_open, original_flock = os.open, fcntl.flock
        def opened(path, flags, mode=0o777, **kw):
            fd = original_open(path, flags, mode, **kw)
            if str(path).startswith(tmp):
                fds[fd] = norm(path)
                effects.append(['open', norm(path), flags, mode])
            return fd
        def flock(fd, operation):
            effects.append(['flock', fds.get(fd, '<external>'), operation])
            return original_flock(fd, operation)
        def wrap(name):
            original = getattr(os, name)
            def called(*args, **kw):
                first = fds.get(args[0], '<external>') if isinstance(args[0], int) else norm(args[0])
                if first.startswith('<fixture>'):
                    effects.append([name, first, *[norm(x) if isinstance(x, (str, Path)) else x for x in args[1:]]])
                return original(*args, **kw)
            return called

        counter = iter(range(1, 1000))
        env = {'AB_STATE_DIR': str(root/'bridge'), 'AB_DEVICE': 'fixture-device',
               'AB_COMMAND': 'agent-bridge', 'AB_BINDING': '',
               'AB_CLAUDE_SESSIONS_DIR': str(sessions), 'TZ': 'UTC'}
        old_tz = os.environ.get('TZ')
        stack.enter_context(patch.dict(os.environ, env))
        time.tzset()
        def restore_tz():
            if old_tz is None: os.environ.pop('TZ', None)
            else: os.environ['TZ'] = old_tz
            time.tzset()
        stack.callback(restore_tz)
        stack.enter_context(patch.object(time, 'time', return_value=1000.0))
        stack.enter_context(patch.object(uuid, 'uuid4', side_effect=lambda: uuid.UUID(int=next(counter))))
        stack.enter_context(patch.object(secrets, 'token_hex', side_effect=lambda _n: f'{next(counter):032x}'))
        stack.enter_context(patch.object(subprocess, 'run', side_effect=run))
        stack.enter_context(patch.object(observer_dbus, '_observer_rows', return_value=rows))
        stack.enter_context(patch.object(endpoints, 'DiscoverySources', return_value=source))
        stack.enter_context(patch.object(cli, 'DiscoverySources', side_effect=lambda **kw: type(source)(
            **{**source.__dict__, **kw})))
        stack.enter_context(patch.object(cli, 'identify_caller', side_effect=lambda eps:
            endpoints.identify_caller(eps, pid=99, proc_root=proc, environ={}, codex_home=home)))
        stack.enter_context(patch.object(cli, '_receiver_class', side_effect=lambda ep:
            endpoints.permission_class(endpoints.Caller(ep, None), proc_root=proc, codex_config=home/'config.toml')))
        stack.enter_context(patch.object(cli, 'ensure_worker', return_value=False))
        stack.enter_context(patch.object(doctor, 'cli_version', return_value=None))
        stack.enter_context(patch.object(doctor, 'inbox_directory', return_value=root/'inbox'))
        stack.enter_context(patch.object(doctor, 'package_path', return_value='<package>/agentstatus_bridge'))
        # W3.2 adds caller diagnostics only. Keep the frozen pre-W1 contract intact;
        # real attribution is covered separately by test_bridge_caller_diagnostic.
        caller = {'attributed': False, 'via': None, 'rejection': None,
                  'termination': 'root', 'chainLength': 1, 'nearestAgent': None}
        has_caller = hasattr(doctor, 'caller_diagnostic')  # recorder still runs on frozen old src
        if has_caller:
            stack.enter_context(patch.object(doctor, 'caller_diagnostic', return_value=caller))
        for name in ('chmod', 'fchmod', 'fsync', 'replace', 'mkdir'):
            stack.enter_context(patch.object(os, name, side_effect=wrap(name)))  # layout: allow 固定五个OS调用的副作用轨迹；下方golden逐项比较
        stack.enter_context(patch.object(os, 'open', side_effect=opened))
        stack.enter_context(patch.object(fcntl, 'flock', side_effect=flock))

        outputs = []
        def command(*args):
            out, err = io.StringIO(), io.StringIO()
            with redirect_stdout(out), redirect_stderr(err):
                code = cli.main(list(args))
            shown = out.getvalue()
            if args[0] == 'doctor' and has_caller:
                if '--json' in args:
                    data = json.loads(shown)
                    if data.pop('caller') != caller:
                        raise AssertionError('caller projection changed')
                    shown = json.dumps(data, ensure_ascii=False, indent=2, sort_keys=True) + '\n'
                else:
                    line = '调用者：agent 已归属=否；via=None；rejection=None；祖先链 termination=root，长度=1；最近 agent=None\n'
                    if shown.count(line) != 1:
                        raise AssertionError('caller text missing or changed')
                    shown = shown.replace(line, '')
            outputs.append([list(args), code, norm(shown), norm(err.getvalue())])
            if code not in (0, 6):
                raise AssertionError(outputs)
            return out.getvalue()

        command('peers'); command('peers', '--json')
        sent = json.loads(command('send', '--to', '%1', '--no-wait', '--json', '-m', 'synthetic'))
        task_id = sent['id']
        command('tasks'); command('tasks', '--json')
        command('status', task_id); command('status', task_id, '--json')
        command('summary', '--refresh', '--json')
        command('doctor'); command('doctor', '--json')
        with cli.Store.open(root/'bridge') as store:
            logical = {table: [dict(row) for row in store._conn.execute('SELECT * FROM '+table+' ORDER BY rowid')]
                       for table in ('tasks', 'attempts', 'meta', 'native_withdrawals')}
        process = {'rows': [asdict(p) for pid in procfs.list_pids(proc) if (p:=procfs.read_process(pid, proc))],
                   'chain': [asdict(p) for p in procfs.ancestry(200, proc)],
                   'cycle': [asdict(p) for p in procfs.ancestry(400, proc)],
                   'namespace': procfs.pid_namespace(proc),
                   'argv': procfs.launch_tokens(200, proc), 'same': procfs.is_same_generation(200, '001234', proc),
                   'different': procfs.is_same_generation(200, '1234', proc)}
        files = [[p.name, oct(p.stat().st_mode & 0o777)] for p in sorted((root/'bridge').iterdir())]
        return {'outputs': outputs, 'commands': commands, 'effects': effects, 'files': files,
                'summary': (root/'bridge'/'summary.json').read_text(), 'logical': logical, 'process': process}


class LinuxBaselineTests(unittest.TestCase):
    def test_linux_wire_files_locks_and_sampling_match_frozen_baseline(self):
        self.assertEqual(record_linux(), json.loads(GOLDEN.read_text()))

    def test_fixture_does_not_inherit_integrated_command_name(self):
        with patch.dict(os.environ, {'AB_COMMAND':'ab','AB_BINDING':'agentstatus:old-root'}):
            self.assertEqual(record_linux(), json.loads(GOLDEN.read_text()))


if __name__ == '__main__' and sys.argv[1:] == ['--record']:
    print(json.dumps(record_linux(), ensure_ascii=False, indent=2))
elif __name__ == '__main__':
    unittest.main()
