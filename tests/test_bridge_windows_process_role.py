"""§92 Desktop 进程角色正证：纯判定、读取原语、父证与 discover 接入（SDK Fake；Win32 事实见 native 用例）。"""
import ctypes as C
import json
import os
from pathlib import Path
import subprocess
import sys
from tempfile import TemporaryDirectory
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from bridge_winapi import Kernel, split_command_line
import test_bridge_windows_claude as fixtures
import test_bridge_windows_roots as roots_base
from test_bridge_windows_claude import BIRTH, UUID, PIPE
from agentstatus_bridge.platforms.windows import claude_discovery as D, process_role as R
from agentstatus_bridge.platforms.windows.process_role import Arg, HELPER, NOT_PROVEN, UNKNOWN

DESK = r'C:\Users\fixture\AppData\Local\AnthropicClaude\app-1.0.0\claude.exe'
TYPES = ('renderer', 'gpu-process', 'utility', 'renderer', 'utility', 'crashpad-handler')
SECRET = 'ARGV-SECRET-NEVER-RETURN'
ROLES = {HELPER, NOT_PROVEN, UNKNOWN}
# Fake 分词模型与真实 CommandLineToArgvW 的比对语料（native 用例逐项核对；本文件只核模型自身形状）
SPLIT_CORPUS = (
    r'"C:\Program Files\claude.exe" --type=renderer --x="a b"',
    r'claude.exe a\\\"b c\\\\"d e" f\\g',
    'claude.exe   ',
    'claude.exe "" x',
    'claude.exe "a"""b',
    'claude.exe "a""b" c',
    r'"C:\x y\claude.exe"--type=gpu -p "--type=renderer"',
    'claude.exe\t--type=utility\t\t--lang=en-US',
    'claude.exe --type=' + 'a' * 248,
    'claude.exe --foo=' + 'b' * 400 + ' --type=gpu',
)


def roles(*argv):
    return R.classify([Arg(a, True) for a in argv])


def kind60(k):
    """本 Kernel 上发生过的 class 60 查询所对应的 pid（句柄已关，按调用参数里的句柄记录回推）。"""
    return [pid for name, args in k.calls if name == 'NtQueryInformationProcess' and args[1] == 60
            for pid in [k.opened.get(args[0])]]


def track_opens(k):
    """记录句柄 → pid，句柄关闭后仍能断言「对哪个 pid 读过命令行」。"""
    k.opened = {}
    original = k.alloc

    def alloc(kind, **values):
        handle = original(kind, **values)
        if kind == 'process':
            k.opened[handle] = values['pid']
        return handle
    k.alloc = alloc


class ClassifyTests(unittest.TestCase):
    def test_leading_equals_segment_corpus(self):
        cases = {
            ('--type=renderer',): HELPER,
            ('--user-data-dir=C:\\x', '--type=gpu-process', '--lang=en-US'): HELPER,
            ('--type=crashpad-handler', '/prefetch:4', '--type=renderer'): HELPER,  # 停止项后的 type 不计数
            ('--type=utility', '--utility-sub-type=network.mojom.NetworkService'): HELPER,
            (): NOT_PROVEN,
            ('--type=renderer', '--type=gpu-process'): NOT_PROVEN,
            ('--type=renderer', '--lang=en', '--type=renderer'): NOT_PROVEN,
            ('--type=',): NOT_PROVEN,
            ('--type=ren derer',): NOT_PROVEN,
            ('--type=rend/er',): NOT_PROVEN,
            ('--type=rendérer',): NOT_PROVEN,
            ('--type=renderer\ud800',): NOT_PROVEN,  # 孤立代理码元：不是合法字符，也不抛异常
            ('--', '--type=renderer'): NOT_PROVEN,
            ('--enable-logging', '--type=renderer'): NOT_PROVEN,
            ('--type', 'renderer'): NOT_PROVEN,
            ('-p', '--type=renderer'): NOT_PROVEN,
            ('--foo=--type=renderer',): NOT_PROVEN,
            ('x--type=renderer',): NOT_PROVEN,
            ('resume', '--type=renderer'): NOT_PROVEN,
            ('--Type=renderer',): NOT_PROVEN,
            ('--TYPE=renderer',): NOT_PROVEN,
            ('--types=renderer',): NOT_PROVEN,
            ('--\ud800=x', '--type=gpu'): HELPER,
        }
        for argv, expected in cases.items():
            with self.subTest(argv=argv):
                self.assertEqual(roles(*argv), expected)

    def test_truncated_items_and_invalid_pointers(self):
        long = 'a' * 300
        cases = [
            ([Arg('--type=' + long[:249], False)], UNKNOWN),               # 截断的 type 值
            ([Arg('--foo=' + long[:250], False), Arg('--type=gpu', True)], HELPER),  # 已见 = 的非 type 长值可跳过
            ([Arg('--' + long[:254], False), Arg('--type=gpu', True)], UNKNOWN),     # 证不出 equals 结构
            ([Arg('y' * 256, False), Arg('--type=gpu', True)], NOT_PROVEN),          # 位置参数结束前导段
            ([Arg(None, False)], UNKNOWN),
            ([Arg('--type=gpu', True), Arg(None, False)], UNKNOWN),
            ([Arg('pos', True), Arg(None, False)], NOT_PROVEN),
            ([Arg('--type=gpu', True), Arg('--', True), Arg(None, False)], HELPER),
        ]
        for argv, expected in cases:
            with self.subTest(argv=[(a.text and a.text[:12], a.complete) for a in argv]):
                self.assertEqual(R.classify(argv), expected)

    def test_reading_stops_at_the_stop_item(self):
        def lazy():
            yield Arg('--type=renderer', True)
            yield Arg('positional', True)
            raise AssertionError('argument after stop item was read')
        self.assertEqual(R.classify(lazy()), HELPER)

    def test_witness_truth_table(self):
        b = 1000
        self.assertTrue(R.witness(b, DESK, b + 1, HELPER, DESK))
        for name, args in {
            'equal_birth': (b, DESK, b, HELPER, DESK),
            'child_earlier': (b, DESK, b - 1, HELPER, DESK),
            'not_helper': (b, DESK, b + 1, NOT_PROVEN, DESK),
            'unknown_child': (b, DESK, b + 1, UNKNOWN, DESK),
            'other_image_same_basename': (b, DESK, b + 1, HELPER, r'C:\Other\claude.exe'),
            'case_differs': (b, DESK, b + 1, HELPER, DESK.lower()),
        }.items():
            with self.subTest(name):
                self.assertFalse(R.witness(*args))


class FakeSplitTests(unittest.TestCase):
    def test_fixture_model_shape(self):
        # 只校验 Fake 自身；它与真实 API 的一致性由 test_bridge_windows_native 对 SPLIT_CORPUS 逐项核对
        self.assertEqual(split_command_line(r'"C:\Program Files\claude.exe" --type=renderer --x="a b"'),
                         [r'C:\Program Files\claude.exe', '--type=renderer', '--x=a b'])
        self.assertEqual(split_command_line(r'claude.exe a\\\"b c\\\\"d e" f\\g'), ['claude.exe', 'a\\"b', 'c\\\\d e', 'f\\\\g'])
        self.assertEqual(split_command_line('claude.exe   '), ['claude.exe'])
        self.assertEqual(split_command_line('claude.exe "" x'), ['claude.exe', '', 'x'])
        self.assertEqual(split_command_line('claude.exe "a"""b'), ['claude.exe', 'a"b'])  # 连续第三个引号是字面量
        for line in SPLIT_CORPUS:
            self.assertGreaterEqual(len(split_command_line(line)), 1)


class ReadTests(unittest.TestCase):
    def setUp(self):
        self.temp = TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.k = Kernel(self.temp.name)
        self.addCleanup(lambda: self.assertEqual(self.k.handles, {}))
        self.addCleanup(lambda: self.assertEqual(self.k.argv_blocks, {}))  # 每块 argv 都已释放

    def read(self, line=None, hook=None, deadline=None):
        if line is not None:
            self.k.command_lines[300] = line
        if hook is not None:
            self.k.command_line_hooks[300] = hook
        handle = self.k.alloc('process', pid=300, access=0x101000)
        try:
            return R.read_role(self.k.api, handle, time.monotonic() + 5 if deadline is None else deadline)
        except Exception as error:  # 读取原语只返回闭集结论；任何外抛都是缺陷，记为断言失败
            self.fail(f'read_role raised {type(error).__name__}')
        finally:
            self.k.CloseHandle(handle)

    def queries(self):
        return sum(1 for name, args in self.k.calls if name == 'NtQueryInformationProcess' and args[1] == 60)

    def splits(self):
        return sum(1 for name, _ in self.k.calls if name == 'CommandLineToArgvW')

    def header(self, raw, *, length=None, maximum=None, offset=16, returned=None, status=0):
        """按调用方缓冲写任意 UNICODE_STRING 头；offset 是 Buffer 相对缓冲起点的偏移（None=NULL）。"""
        def hook(out, size):
            length_ = len(raw) if length is None else length
            maximum_ = len(raw) + 2 if maximum is None else maximum
            pointer = 0 if offset is None else out + offset
            C.memmove(out, (C.c_uint16 * 2)(length_, maximum_), 4)
            C.memmove(out + 4, (C.c_uint32 * 1)(0), 4)
            C.memmove(out + 8, (C.c_uint64 * 1)(pointer), 8)
            data = raw + b'\0\0'
            C.memmove(out + 16, data, min(len(data), size - 16))
            return status, 16 + len(data) if returned is None else returned
        return hook

    def test_fake_models_query_access_as_permission_failure(self):
        self.assertEqual(self.k.api.k.OpenProcess(0x100000, False, 100), None)
        self.assertEqual(self.k.error, 5)

    def test_quoted_corpus_through_fake_split(self):
        cases = {
            f'"{DESK}" --type=renderer --user-data-dir="C:\\Users\\x\\AppData\\Roaming\\Claude" --lang=en-US': HELPER,
            f'"{DESK}" "--type=gpu-process" --field-trial-handle=1,2': HELPER,
            f'"{DESK}"': NOT_PROVEN,
            f'"{DESK}" -p "--type=renderer"': NOT_PROVEN,
            f'"{DESK}" --enable-features=X --type=utility --type=utility': NOT_PROVEN,
            f'"{DESK}" positional --type=renderer': NOT_PROVEN,
        }
        for line, expected in cases.items():
            with self.subTest(line=line[-30:]):
                self.assertEqual(self.read(line), expected)
        self.assertEqual(len(self.k.argv_freed), len(cases))

    def test_insufficient_buffer_retries_once_up_to_the_limit(self):
        line = f'"{DESK}" --type=renderer ' + ' '.join(f'--k{i}=' + 'v' * 40 for i in range(60))
        self.assertGreater(len(line) * 2, R.QUERY_INITIAL)
        self.assertEqual(self.read(line), HELPER)
        self.assertEqual(self.queries(), 2)
        for code in (-1073741789, -2147483643):  # 0xC0000023 / 0x80000005 与 0xC0000004 同样按 ReturnLength 扩容
            with self.subTest(code=hex(code & 0xFFFFFFFF)):
                self.k.calls.clear()

                def once(out, size, code=code):
                    del self.k.command_line_hooks[300]
                    return code, 8192
                self.assertEqual(self.read(f'"{DESK}" --type=gpu', hook=once), HELPER)
                self.assertEqual(self.queries(), 2)

    def test_retry_refusals(self):
        cases = {
            'access_denied': (-1073741790, 8192),
            'length_not_growing': (-1073741820, R.QUERY_INITIAL),
            'over_limit': (-1073741820, R.QUERY_LIMIT + 2),
        }
        for name, (status, length) in cases.items():
            with self.subTest(name):
                self.k.calls.clear()
                self.assertEqual(self.read(hook=lambda out, size: (status, length)), UNKNOWN)
                self.assertEqual(self.queries(), 1)
        self.k.calls.clear()
        self.assertEqual(self.read(hook=lambda out, size: (-1073741820, R.QUERY_LIMIT)), UNKNOWN)
        self.assertEqual(self.queries(), 2)  # 恰在上限内可扩容一次，第二次仍不足即 unknown

    def test_header_shape_refusals_never_reach_the_splitter(self):
        raw = f'"{DESK}" --type=renderer'.encode('utf-16-le')
        self.assertEqual(self.read(hook=self.header(raw)), HELPER)  # 正向对照：钩子写出的合法头可用
        cases = {
            'zero_length': dict(length=0),
            'odd_length': dict(length=len(raw) - 1),
            'odd_maximum': dict(maximum=len(raw) + 1),
            'maximum_below_length': dict(maximum=len(raw) - 2),
            'null_buffer': dict(offset=None),
            'buffer_inside_header': dict(offset=8),
            # 指针落在头内且读到的码元非 NUL（MaximumLength 字段）：只能靠「Buffer 不早于头尾」拦下（Opus N10）
            'buffer_inside_header_without_nul': dict(offset=2, length=2),
            'buffer_past_returned': dict(returned=16 + len(raw) - 2),
            'returned_below_header': dict(returned=12),
            'returned_above_size': dict(returned=R.QUERY_INITIAL + 2),
        }
        for name, shape in cases.items():
            with self.subTest(name):
                self.k.calls.clear()
                self.assertEqual(self.read(hook=self.header(raw, **shape)), UNKNOWN)
                self.assertEqual(self.splits(), 0)
        self.k.calls.clear()
        nul = f'"{DESK}" --type=renderer\0 --x=y'.encode('utf-16-le')
        self.assertEqual(self.read(hook=self.header(nul)), UNKNOWN)
        self.assertEqual(self.splits(), 0)

    def test_argv_shape_refusals_and_lazy_pointer_reads(self):
        line = f'"{DESK}" --type=renderer positional --x=y'
        self.k.faults['CommandLineToArgvW'] = 8
        self.assertEqual(self.read(line), UNKNOWN)
        del self.k.faults['CommandLineToArgvW']
        for argc in (0, len(line) + 2):
            with self.subTest(argc=argc):
                self.k.argv_argc = argc
                self.assertEqual(self.read(line), UNKNOWN)
        self.k.argv_argc = None
        self.k.argv_null = frozenset({1})
        self.assertEqual(self.read(line), UNKNOWN)
        self.k.argv_null = frozenset({3})  # 停止项之后的空指针不被访问
        self.assertEqual(self.read(line), HELPER)
        self.assertEqual(len(self.k.argv_freed), 4)

    def test_only_the_leading_segment_is_read(self):
        with patch.object(R, '_read_arg', wraps=R._read_arg) as read:
            self.assertEqual(self.read(f'"{DESK}" --type=renderer positional --x=y --z=w'), HELPER)
        self.assertEqual(read.call_count, 2)  # argv[1]、停止项；之后的参数不转换

    def test_lone_surrogates_through_the_read_path(self):
        try:
            self.assertEqual(self.read(f'"{DESK}" --type=gpu\ud800'), NOT_PROVEN)
            # 截断恰好落在代理对中间：长的非 type 值照常跳过
            self.assertEqual(self.read(f'"{DESK}" --foo={"a" * 249}\U0001F600 --type=gpu'), HELPER)
            self.assertEqual(self.read(f'"{DESK}" --{"a" * 253}\U0001F600=x --type=gpu'), UNKNOWN)
        except UnicodeError as error:  # 孤立代理码元不得抛异常（Opus 最终确认 P3-2）
            self.fail(f'decode raised {type(error).__name__}')

    def test_256_unit_boundary(self):
        self.assertEqual(self.read(f'x --type={"a" * 248}'), HELPER)    # 255 个码元 + NUL：完整
        self.assertEqual(self.read(f'x --type={"a" * 249}'), UNKNOWN)   # 256 个都非 NUL：截断
        self.assertEqual(self.read(f'x --foo={"b" * 400} --type=gpu'), HELPER)
        self.assertEqual(self.read(f'x --{"c" * 300} --type=gpu'), UNKNOWN)

    @unittest.skipUnless(sys.platform.startswith('linux'), 'POSIX-only: guard page via libc mprotect')
    def test_read_arg_never_touches_the_257th_unit(self):
        probe = (
            'import ctypes as C, mmap, sys\n'
            'from agentstatus_bridge.platforms.windows import process_role as R\n'
            'libc = C.CDLL(None, use_errno=True)\n'
            'libc.mmap.restype = C.c_void_p\n'
            'libc.mmap.argtypes = [C.c_void_p, C.c_size_t, C.c_int, C.c_int, C.c_int, C.c_long]\n'
            'libc.mprotect.argtypes = [C.c_void_p, C.c_size_t, C.c_int]\n'
            'page = mmap.PAGESIZE\n'
            'base = libc.mmap(None, 2 * page, 3, 0x22, -1, 0)\n'
            'assert base not in (None, C.c_void_p(-1).value) and libc.mprotect(base + page, page, 0) == 0\n'
            'start = base + page - 512\n'
            'C.memmove(start, ("x" * 256).encode("utf-16-le"), 512)\n'
            'arg = R._read_arg(start)\n'
            'C.memmove(start, ("y" * 255 + "\\0").encode("utf-16-le"), 512)\n'
            'full = R._read_arg(start)\n'
            'print(arg.complete, len(arg.text), full.complete, len(full.text))\n')
        src = Path(R.__file__).resolve().parents[3]
        done = subprocess.run([sys.executable, '-I', '-c', f'import sys; sys.path.insert(0, {str(src)!r})\n' + probe],
                              capture_output=True, text=True, timeout=60)
        self.assertEqual((done.returncode, done.stdout.split()), (0, ['False', '256', 'True', '255']), done.stderr[-300:])

    def test_cleanup_failures_do_not_change_roles_and_still_free(self):
        lines = {f'"{DESK}" --type=renderer': HELPER, f'"{DESK}" --enable-logging': NOT_PROVEN}
        def raising(_pointer): raise RuntimeError('fixture LocalSize')
        for name in ('localsize_zero', 'localsize_raises', 'memset_raises'):
            for line, expected in lines.items():
                with self.subTest(name, expected=expected):
                    freed = len(self.k.argv_freed)
                    if name == 'localsize_zero':
                        self.k.faults['LocalSize'] = 6
                        role = self.read(line)
                        del self.k.faults['LocalSize']
                    elif name == 'localsize_raises':
                        with patch.object(self.k, 'LocalSize', raising):
                            role = self.read(line)
                    else:
                        with patch.object(R.C, 'memset', side_effect=RuntimeError('fixture memset')):
                            role = self.read(line)
                    self.assertEqual(role, expected)
                    self.assertEqual(len(self.k.argv_freed), freed + 1)


class CommandRoleTests(unittest.TestCase):
    def setUp(self):
        self.temp = TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.k = Kernel(self.temp.name)
        self.addCleanup(lambda: self.assertEqual(self.k.handles, {}))
        self.birth = int(BIRTH) + 300
        self.k.processes[300] = (0, self.birth, self.k.sid, False, 'claude.exe')
        self.k.images[300] = DESK
        self.k.command_lines[300] = f'"{DESK}" --type=renderer --{SECRET}=1'

    def role(self, birth=None, deadline=None):
        role = R.command_role(self.k.api, 300, str(self.birth if birth is None else birth),
                              deadline=time.monotonic() + 5 if deadline is None else deadline)
        self.assertIn(role, ROLES)
        return role

    def queried(self):
        return any(name == 'NtQueryInformationProcess' and args[1] == 60 for name, args in self.k.calls)

    def test_qualified_helper_and_exact_closed_result(self):
        self.assertEqual(self.role(), HELPER)
        self.k.command_lines[300] = f'"{DESK}" --{SECRET}'
        self.assertEqual(self.role(), NOT_PROVEN)

    def test_qualification_refusals_do_not_read_the_command_line(self):
        self.k.restricted_process_stage = 'queryable'  # 让下游检查真正执行，而不是被 OpenProcess 挡掉
        other = bytes.fromhex('010100000000000515000000')
        cases = {
            'image_not_claude': lambda: self.k.images.__setitem__(300, r'C:\x\claude.exe.bak'),
            'other_sid': lambda: self.k.processes.__setitem__(300, (0, self.birth, other, False, 'claude.exe')),
            'target_elevated': lambda: self.k.processes.__setitem__(300, (0, self.birth, self.k.sid, True, 'claude.exe')),
            'self_elevated': lambda: self.k.processes.__setitem__(100, (0, self.k.processes[100][1], self.k.sid, True, 'python.exe')),
            'image_unreadable': lambda: self.k.images.pop(300),
        }
        for name, change in cases.items():
            with self.subTest(name):
                saved = (dict(self.k.processes), dict(self.k.images))
                try:  # 断言失败也要还原 Fake，免得后续子用例在改过的状态上连锁报错
                    change(); self.k.calls.clear()
                    self.assertEqual(self.role(), UNKNOWN)
                    self.assertFalse(self.queried())
                finally:
                    self.k.processes, self.k.images = map(dict, saved)

    def test_generation_liveness_budget_and_denial(self):
        self.assertEqual(self.role(birth=self.birth + 1), UNKNOWN)
        self.k.calls.clear()
        self.assertEqual(self.role(deadline=time.monotonic() - 1), UNKNOWN)
        self.assertFalse(self.queried())
        line = self.k.command_lines.pop(300)
        self.assertEqual(self.role(), UNKNOWN)  # 命令行读不到：unknown，不当作退出或非候选
        self.k.command_lines[300] = line

        def exits(out, size):
            del self.k.command_line_hooks[300]
            self.k.exited.add(300)  # 读完命令行后才退出
        self.k.command_line_hooks[300] = exits
        self.assertEqual(self.role(), UNKNOWN)  # 读取期间退出：返回前复核不通过
        self.k.exited.clear()
        clock = [time.monotonic()]

        def slow(out, size):
            del self.k.command_line_hooks[300]
            clock[0] += 10
        self.k.command_line_hooks[300] = slow
        with patch.object(R, 'time', SimpleNamespace(monotonic=lambda: clock[0])):
            self.assertEqual(R.command_role(self.k.api, 300, str(self.birth), deadline=clock[0] + 5), UNKNOWN)

    def test_final_generation_recheck_crossing_the_limit_is_not_proof(self):
        # 只让最后一次代际复核本身跨过截止：先数出调用次数，再只在最后一次拨钟（R1f：先看时钟后核验会放行）
        original = self.k.api.process
        calls = []
        with patch.object(self.k.api, 'process', side_effect=lambda *a, **kw: (calls.append(1), original(*a, **kw))[1]):
            self.assertEqual(self.role(), HELPER)
        total, clock, seen = len(calls), [100.0], []

        def slow(*args, **kwargs):
            seen.append(1)
            fact = original(*args, **kwargs)
            if len(seen) == total:
                clock[0] += 0.6
            return fact
        with patch.object(self.k.api, 'process', side_effect=slow), \
                patch.object(R, 'time', SimpleNamespace(monotonic=lambda: clock[0])):
            self.assertEqual(R.command_role(self.k.api, 300, str(self.birth), deadline=200.0), UNKNOWN)
        self.assertEqual(len(seen), total)


class RolesTests(unittest.TestCase):
    """P 的真值表与本轮缓存；只用 Fake 进程表，不接真实桌面。"""
    def setUp(self):
        self.temp = TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.k = Kernel(self.temp.name)
        self.addCleanup(lambda: self.assertEqual(self.k.handles, {}))
        self.base = int(BIRTH)
        self.proc(500, 0, 500, '')
        for i, kind in enumerate(TYPES):
            self.proc(501 + i, 500, 501 + i, f'--type={kind}')

    def proc(self, pid, ppid, birth, args, image=DESK):
        self.k.processes[pid] = (ppid, self.base + birth, self.k.sid, False, 'claude.exe')
        self.k.images[pid] = image
        self.k.command_lines[pid] = f'"{image}" {args}'.rstrip()

    def roles(self, deadline=None, allow_parent=True):
        return R.Roles(self.k.api, time.monotonic() + 5 if deadline is None else deadline, allow_parent=allow_parent)

    def exempt(self, pid, protected=frozenset(), **kwargs):
        return self.roles(**kwargs).exempt(pid, str(self.k.processes[pid][1]), protected)

    def only_children(self, *keep):
        for pid in range(501, 501 + len(TYPES)):
            if pid not in keep:
                del self.k.processes[pid]

    def test_helper_and_parent_are_exempt(self):
        self.assertTrue(self.exempt(501))
        self.assertTrue(self.exempt(500))
        # helper 路径同样受调用方截止约束，不只靠 P 路径的返回前检查（Opus r1 P3-r1-1，变异 RB）
        self.k.calls.clear()
        self.assertFalse(self.exempt(501, deadline=time.monotonic() - 1))
        # 进来时已过截止：入口即拒，不打开任何进程（入口检查自己的作用，变异 R2b）
        self.assertFalse(any(name == 'OpenProcess' for name, _ in self.k.calls))

    def test_cached_helper_recheck_crossing_the_deadline_is_not_exempt(self):
        # 角色已缓存为 helper；只让 _same 的那次同步复核跨过截止（Codex r1 残留 P3-01，变异 R2a）
        clock = [100.0]
        with patch.object(R, 'time', SimpleNamespace(monotonic=lambda: clock[0])):
            roles = R.Roles(self.k.api, 105.0)
            birth = str(self.k.processes[501][1])
            self.assertEqual(roles.role(501, birth), HELPER)
            original = self.k.api.process
            def slow(*args, **kwargs):
                fact = original(*args, **kwargs)
                clock[0] = 106.0
                return fact
            with patch.object(self.k.api, 'process', side_effect=slow):
                self.assertFalse(roles.exempt(501, birth, frozenset()))
            clock[0] = 100.0
            self.assertTrue(roles.exempt(501, birth, frozenset()))  # 对照：复核不跨截止仍免除

    def test_parent_truth_table(self):
        cases = {
            'later_helper': (lambda: self.only_children(501), True),
            'equal_birth_only': (lambda: (self.only_children(501), self.proc(501, 500, 500, '--type=crashpad-handler')), False),
            'equal_then_later': (lambda: (self.only_children(501, 502), self.proc(501, 500, 500, '--type=crashpad-handler')), True),
            'child_earlier': (lambda: (self.only_children(501), self.proc(501, 500, 499, '--type=renderer')), False),
            'other_image': (lambda: (self.only_children(501), self.proc(501, 500, 501, '--type=renderer', r'C:\Other\claude.exe')), False),
            'child_not_helper': (lambda: (self.only_children(501), self.proc(501, 500, 501, '--enable-logging')), False),
            'child_unknown': (lambda: (self.only_children(501), self.k.command_lines.pop(501)), False),
            'child_not_claude': (lambda: (self.only_children(501), self.k.processes.__setitem__(
                501, (500, self.base + 501, self.k.sid, False, 'node.exe'))), False),
            'parent_unknown': (lambda: self.k.command_lines.pop(500), False),
            'no_children': (lambda: self.only_children(), False),
        }
        for name, (change, expected) in cases.items():
            with self.subTest(name):
                saved = (dict(self.k.processes), dict(self.k.images), dict(self.k.command_lines))
                try:
                    change()
                    self.assertIs(self.exempt(500), expected)
                finally:
                    self.k.processes, self.k.images, self.k.command_lines = map(dict, saved)

    def test_protected_budget_override_and_table_failure(self):
        self.only_children(501)
        self.assertFalse(self.exempt(500, protected=frozenset({501})))  # 有效登记者不作见证
        self.assertFalse(self.exempt(500, protected=frozenset({500})))
        self.assertFalse(self.exempt(501, protected=frozenset({501})))
        self.assertFalse(self.exempt(500, allow_parent=False))
        self.assertTrue(self.exempt(501, allow_parent=False))  # 显式覆盖仍做 T
        self.assertFalse(self.exempt(500, deadline=time.monotonic() - 1))
        self.k.faults['CreateToolhelp32Snapshot'] = 5
        self.assertFalse(self.exempt(500))

    def test_no_recursive_exclusion_below_or_beside_the_family(self):
        self.proc(600, 501, 600, '')            # helper 的无 type 孩子
        self.proc(601, 500, 601, '--resume')    # Desktop 主进程启动的 CLI 形态
        self.proc(602, 0, 602, '', image=DESK)  # 同映像但无 helper 孩子
        for pid in (600, 601, 602):
            with self.subTest(pid=pid):
                self.assertFalse(self.exempt(pid))
        self.assertTrue(self.exempt(500))

    def test_generation_bound_cache_and_exit(self):
        roles = self.roles()
        old = str(self.k.processes[501][1])
        self.assertEqual(roles.role(501, old), HELPER)
        self.proc(501, 500, 9000, '--resume')   # 同 PID 换代
        new = str(self.k.processes[501][1])
        self.assertEqual(roles.role(501, new), NOT_PROVEN)
        self.assertFalse(roles.exempt(501, old, frozenset()))  # 旧代际缓存不能免除新代
        self.k.exited.add(502)
        self.assertFalse(self.exempt(502))       # 已退出/读失败不当作「没有缺口」
        self.k.exited.clear()
        self.only_children(503)

        def exits(out, size):
            del self.k.command_line_hooks[503]
            self.k.exited.add(503)
        self.k.command_line_hooks[503] = exits
        self.assertFalse(self.exempt(500))       # 见证读命令行期间退出：在它自己的 command_role 返回前复核即被拦下
        # （P 返回前的两代复核另由 test_parent_proof_rechecks_both_generations_before_returning 覆盖）


class DesktopDiscoveryTests(unittest.TestCase):
    """owner 现场形态：Desktop 落在不可读的默认根（junction），CLI 200 在可读根登记。"""
    setUp = fixtures.NativeTests.setUp
    write = fixtures.NativeTests.write
    roots = roots_base.MultiRootTests.roots

    def desktop(self, *, env=True, main_env=None, lines=True, types=TYPES, image=DESK):
        default = self.root / '.claude'
        if not default.exists():
            default.mkdir()
            (default / 'sessions').write_text('junction fixture')  # 产品读不了的默认根
        self.family = [500, *range(501, 501 + len(types))]
        for pid, args in zip(self.family, ('', *(f'--type={t} --lang=en-US --{SECRET}=1' for t in types))):
            self.k.processes[pid] = (0 if pid == 500 else 500, int(BIRTH) + pid, self.k.sid, False, 'claude.exe')
            self.k.images[pid] = image
            if lines:
                self.k.command_lines[pid] = f'"{image}" {args}'.rstrip()
            located = env if pid != 500 or main_env is None else main_env
            if located:
                self.k.environments[pid] = ('SystemRoot=C:\\Windows\0\0').encode('utf-16-le')
            else:
                self.k.environments.pop(pid, None)

    def discover(self):
        found = D.discover(self.p.transport, connect=False)
        self.assertNotIn(SECRET, repr(found))
        self.assertNotIn(SECRET, json.dumps(found.document()))
        self.assertNotIn(SECRET, json.dumps(found.registries))
        return found

    def scan(self):
        return self.p.files.claude_sessions_dirs()

    def assert_cli_only(self, found):
        self.assertTrue(found.complete)
        self.assertEqual({e.ref.pid for e in found.endpoints}, {200})
        self.assertEqual(found.select('claude@fixture-peer').ref.pid, 200)

    def test_desktop_family_on_unreadable_default_root(self):
        self.roots(); self.desktop(lines=False)
        self.assertTrue(set(self.family) <= self.scan().unlocated | {p for p, _ in self.scan().live})
        self.assertFalse(self.discover().complete)  # 修复前的现场：读不到角色就不完整
        self.desktop()
        track_opens(self.k)
        found = self.discover()
        self.assert_cli_only(found)
        self.assertIn('unreadable', [r['reason'] for r in found.registries])  # 诊断仍如实
        self.assertNotIn(200, kind60(self.k))

    def test_renderer_and_main_without_environment(self):
        self.roots(); self.desktop(env=False)
        self.assertTrue(set(self.family) <= self.scan().unlocated)
        self.assert_cli_only(self.discover())
        self.desktop(env=True, main_env=False)  # 只有主进程读不到环境：靠 P
        self.assertIn(500, self.scan().unlocated)
        self.assert_cli_only(self.discover())

    def test_desktop_without_cli(self):
        self.roots(); self.desktop()
        del self.k.processes[200]; (self.sessions / '200.json').unlink()
        self.k.processes[100] = (0, *self.k.processes[100][1:])
        found = self.discover()
        self.assertTrue(found.complete); self.assertEqual(found.endpoints, ())

    def test_unknown_cli_and_desktop_launched_cli_stay_incomplete(self):
        self.roots(); self.desktop()
        cases = {
            'unreadable_cli': (0, r'C:\fixture\claude.exe', None),
            'cli_without_helpers': (0, r'C:\fixture\claude.exe', '--resume'),
            'same_image_no_type': (0, DESK, ''),
            'child_of_desktop_main': (500, DESK, '--print'),
            'child_of_helper': (501, DESK, ''),
        }
        for name, (ppid, image, args) in cases.items():
            with self.subTest(name):
                self.k.processes[600] = (ppid, int(BIRTH) + 600, self.k.sid, False, 'claude.exe')
                self.k.images[600] = image
                self.k.command_lines.pop(600, None)
                if args is not None:
                    self.k.command_lines[600] = f'"{image}" {args}'.rstrip()
                self.assertFalse(self.discover().complete)
        del self.k.processes[600]
        self.assert_cli_only(self.discover())

    def test_parent_command_line_unknown_keeps_gap(self):
        self.roots(); self.desktop()
        del self.k.command_lines[500]
        self.assertFalse(self.discover().complete)

    def test_witness_may_live_in_a_readable_root(self):
        self.roots(); self.desktop(env=True, main_env=False)
        readable = 'CLAUDE_CONFIG_DIR=' + str(self.sessions.parent) + '\0\0'
        for pid in self.family[1:]:
            self.k.environments[pid] = readable.encode('utf-16-le')  # 已定位到可读根、无登记：不是缺口
        scan = self.scan()
        self.assertEqual(scan.unlocated & set(self.family), {500})
        self.assertTrue({(pid, self.sessions) for pid in self.family[1:]} <= set(scan.live))
        self.assert_cli_only(self.discover())

    def registration(self, pid, root):
        birth = str(int(BIRTH) + pid)
        record = {**self.record, 'pid': pid, 'procStartFt': birth, 'sessionId': UUID[:-3] + f'{pid:03d}',
                  'messagingSocketPath': PIPE[:-3] + f'{pid:03d}', 'name': f'registered-{pid}'}
        (root / f'{pid}.json').write_text(json.dumps(record), encoding='utf-8')

    def test_registered_helper_is_kept_and_never_a_witness(self):
        self.roots(); self.desktop(types=('renderer',))
        self.registration(501, self.sessions)
        found = self.discover()
        self.assertFalse(found.complete)  # 唯一的孩子有有效登记：不作父证
        self.assertIn(501, {e.ref.pid for e in found.endpoints})
        self.desktop(types=('renderer', 'gpu-process'))
        found = self.discover()
        self.assertTrue(found.complete)
        self.assertEqual({e.ref.pid for e in found.endpoints}, {200, 501})  # 登记的 helper 仍可见、不被藏

    def test_record_branch_gap_in_its_own_root(self):
        self.roots(); self.desktop(types=('renderer',))
        own = self.root / 'desk2/sessions'; own.mkdir(parents=True)
        self.k.environments[501] = ('CLAUDE_CONFIG_DIR=' + str(own.parent) + '\0\0').encode('utf-16-le')
        (own / '501.json').write_text('{broken fixture')
        self.assertIn((501, own), self.scan().live)  # 前置：坏记录就在 501 自己映射的根，不被跨根检查挡掉
        track_opens(self.k)
        self.assertTrue(self.discover().complete)
        self.assertIn(501, kind60(self.k))  # 记录分支确实交给了角色判定
        self.k.command_lines.pop(501)
        self.assertFalse(self.discover().complete)  # 证不出：记录分支的缺口仍生效
        # 对照：映射到别处的坏旧记录照旧跳过，不需要角色判定
        self.k.command_lines[501] = f'"{DESK}" --type=renderer'
        stale = self.root / '.rec/claude/accounts/old/config/sessions'; stale.mkdir(parents=True)
        (stale / '501.json').write_text('{broken fixture')
        (own / '501.json').unlink()
        self.k.environments[500] = self.k.environments[501]  # 主进程也定位到可读根：本轮没有任何缺口
        self.k.calls.clear()
        self.assertTrue(self.discover().complete)
        self.assertEqual(kind60(self.k), [])

    def test_registration_priority_does_not_depend_on_root_order(self):
        self.roots(); self.desktop(types=('renderer', 'gpu-process'))
        first, second = self.root / 'a/sessions', self.root / 'b/sessions'
        for path in (first, second):
            path.mkdir(parents=True)
        self.k.environments[501] = ('CLAUDE_CONFIG_DIR=' + str(first.parent) + '\0\0').encode('utf-16-le')
        self.k.environments[502] = ('CLAUDE_CONFIG_DIR=' + str(second.parent) + '\0\0').encode('utf-16-le')
        (first / '501.json').write_text('{broken fixture')   # 501 自己根里的坏记录（逐 PID 缺口）
        self.registration(501, second)                        # 另一根里 501 的有效登记
        for order in ((501, 502), (502, 501)):
            with self.subTest(order=order):
                rows = {pid: self.k.processes.pop(pid) for pid in order}
                self.k.processes.update((pid, rows[pid]) for pid in order)
                found = self.discover()
                self.assertFalse(found.complete)  # 记录错误缺口不被另一处的有效登记顺手扣掉
                self.assertIn(501, {e.ref.pid for e in found.endpoints})

    def test_global_failures_and_budget_are_not_reset(self):
        self.roots(); self.desktop(types=('renderer',))
        own = self.root / '.claude-ok/sessions'; own.mkdir(parents=True)
        os.environ['CLAUDE_CONFIG_DIR'] = str(own.parent)
        (own / '501.json').write_text('{broken fixture')      # 可由 T 免除的记录分支缺口
        self.k.faults['CreateToolhelp32Snapshot'] = 5
        self.assertFalse(self.scan().complete)
        self.assertFalse(self.discover().complete)
        del self.k.faults['CreateToolhelp32Snapshot']
        expired = lambda api, deadline, **kw: R.Roles(api, time.monotonic() - 1, **kw)
        with patch.object(D, 'Roles', expired):
            self.assertFalse(self.discover().complete)
        self.assert_cli_only(self.discover())

    def probe(self):
        import importlib.util, io
        from contextlib import redirect_stdout
        path = Path(__file__).resolve().parents[1] / 'scripts/windows/accept-92.py'
        spec = importlib.util.spec_from_file_location('accept_92', path)
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
        out = io.StringIO()
        with redirect_stdout(out):
            self.assertEqual(module.main(), 0)
        text = out.getvalue()
        for secret in (SECRET, DESK, str(self.root), 'fixture-peer', UUID):
            self.assertNotIn(secret, text)  # 只出闭集/布尔/计数/pid
        return json.loads(text)

    def test_acceptance_probe_reports_closed_reasons_without_content(self):
        self.roots(); self.desktop(env=True, main_env=False)
        self.k.processes[600] = (500, int(BIRTH) + 600, self.k.sid, False, 'claude.exe')  # 主进程下未定位的无 type 孩子
        self.k.images[600] = DESK; self.k.command_lines[600] = f'"{DESK}" --print'
        self.k.processes[601] = (500, int(BIRTH) + 601, self.k.sid, False, 'claude.exe')  # 读不到命令行的孩子
        self.k.images[601] = DESK
        report = self.probe()
        rows = {row['pid']: row for row in report['rows']}
        self.assertFalse(report['complete'])  # 600/601 是真缺口：探针不替产品放宽
        self.assertEqual((rows[500]['pProven'], rows[500]['pReason'], rows[500]['consistent']), (True, 'proven', True))
        self.assertEqual((rows[200].get('pProven'), rows[200].get('pReason')), (False, 'registered'))  # CLI 负例保留
        self.assertEqual(rows[200]['configKey'], 'value'); self.assertEqual(rows[500]['configKey'], 'unknown')
        self.assertEqual({rows[p]['role'] for p in self.family[1:]}, {HELPER})
        self.assertTrue(all('pReason' not in rows[p] for p in self.family[1:]))
        self.assertEqual(rows[600]['pReason'], 'no_witness'); self.assertEqual(rows[601]['pReason'], 'parent_role_unknown')
        self.assertEqual((report['noTypeUnlocatedChildren'], report['unknownUnlocatedChildren'], report['typeRegistered']), (1, 1, 0))
        self.assertTrue(set(rows[r]['pReason'] for r in rows if 'pReason' in rows[r]) <= set(
            ('proven', 'registered', 'parent_role_unknown', 'parent_is_helper', 'no_witness', 'witness_unverified', 'budget_exhausted')))
        del self.k.processes[600], self.k.processes[601]
        report = self.probe()
        self.assertTrue(report['complete'])
        self.assertEqual((report['noTypeUnlocatedChildren'], report['unknownUnlocatedChildren']), (0, 0))
        self.k.command_lines.pop(503)
        rows = {row['pid']: row for row in self.probe()['rows']}
        self.assertEqual(rows[503]['role'], UNKNOWN)
        self.assertEqual(rows[503]['pReason'], 'parent_role_unknown')
        self.assertEqual(rows[500]['pReason'], 'proven')  # 其余合格见证仍成立

    def test_override_runs_type_only_without_process_table(self):
        self.desktop()
        self.enterContext(patch.dict(os.environ, {'AB_CLAUDE_SESSIONS_DIR': str(self.sessions)}))
        (self.sessions / '501.json').write_text('{broken fixture')
        self.k.calls.clear()
        found = self.discover()
        self.assertTrue(found.complete)
        self.assertEqual([n for n, _ in self.k.calls if n == 'CreateToolhelp32Snapshot'], [])
        (self.sessions / '500.json').write_text('{broken fixture')
        self.k.calls.clear()
        self.assertFalse(self.discover().complete)  # 主进程只能靠 P，而显式覆盖不跑父子扫描
        self.assertEqual([n for n, _ in self.k.calls if n == 'CreateToolhelp32Snapshot'], [])



class ImplAuditR1Tests(unittest.TestCase):
    """§92 实现审计 r1（Codex P2-01/P2-02/P3-01..P3-03）的回归。"""
    setUp = fixtures.NativeTests.setUp
    write = fixtures.NativeTests.write
    roots = roots_base.MultiRootTests.roots
    desktop = DesktopDiscoveryTests.desktop
    probe = DesktopDiscoveryTests.probe

    def noninteractive(self, pid):
        birth = str(int(BIRTH) + pid)
        record = {**self.record, 'pid': pid, 'procStartFt': birth, 'kind': 'subagent',
                  'sessionId': UUID[:-3] + f'{pid:03d}', 'messagingSocketPath': PIPE[:-3] + f'{pid:03d}'}
        (self.sessions / f'{pid}.json').write_text(json.dumps(record), encoding='utf-8')

    def test_probe_uses_the_products_noninteractive_protection(self):
        self.roots(); self.desktop(types=('renderer',))
        self.noninteractive(501)  # 唯一的孩子有当前代际的非交互登记：不能作父证
        found = D.discover(self.p.transport, connect=False)
        self.assertIn(501, found.noninteractive); self.assertFalse(found.complete)
        rows = {row['pid']: row for row in self.probe()['rows']}
        self.assertEqual((rows[500]['pProven'], rows[500]['productExempt'], rows[500]['consistent']), (False, False, True))
        self.assertTrue(rows[501]['registered'])

    def test_no_type_count_excludes_present_but_invalid_types(self):
        self.roots(); self.desktop()
        # 603：停止项之后才出现的 type 不算（只看前导段，Opus r1 P3-r1-2，变异 RV）
        for pid, args in ((600, '--type=renderer --type=gpu-process'), (601, '--type= --x=y'), (602, '--print'),
                          (603, '-p --type=renderer')):
            self.k.processes[pid] = (500, int(BIRTH) + pid, self.k.sid, False, 'claude.exe')
            self.k.images[pid] = DESK; self.k.command_lines[pid] = f'"{DESK}" {args}'
        report = self.probe()
        rows = {row['pid']: row for row in report['rows']}
        self.assertEqual({rows[p]['role'] for p in (600, 601, 602, 603)}, {NOT_PROVEN})
        self.assertEqual(rows[500]['pReason'], 'proven')
        self.assertEqual(tuple(rows[p]['typeKeys'] for p in (600, 601, 602, 603)),
                         (R.TYPE_PRESENT, R.TYPE_PRESENT, R.NO_TYPE, R.NO_TYPE))
        self.assertEqual(report['noTypeUnlocatedChildren'], 2)

    def test_type_keys_read_failure_counts_as_unknown(self):
        # 角色读到 not_proven、第二次读 type 键失败（退出或预算）：计入 unknown，不当作 0（Opus r1 P3-r1-3，变异 RC）
        self.roots(); self.desktop()
        self.k.processes[602] = (500, int(BIRTH) + 602, self.k.sid, False, 'claude.exe')
        self.k.images[602] = DESK; self.k.command_lines[602] = f'"{DESK}" --print'
        before = self.probe()
        real = R.command_role
        def failing(*args, judge=R.classify, **kwargs):
            return R.UNKNOWN if judge is R.type_presence else real(*args, judge=judge, **kwargs)
        with patch.object(R, 'command_role', failing):
            after = self.probe()
        rows = {row['pid']: row for row in after['rows']}
        self.assertEqual((rows[602]['role'], rows[602]['typeKeys']), (NOT_PROVEN, R.UNKNOWN))
        self.assertEqual((after['noTypeUnlocatedChildren'], after['unknownUnlocatedChildren']),
                         (before['noTypeUnlocatedChildren'] - 1, before['unknownUnlocatedChildren'] + 1))

    def test_witness_recheck_crossing_the_deadline_is_not_proof(self):
        self.k.processes[500] = (0, int(BIRTH) + 500, self.k.sid, False, 'claude.exe')
        self.k.processes[501] = (500, int(BIRTH) + 501, self.k.sid, False, 'claude.exe')
        for pid, args in ((500, ''), (501, '--type=renderer')):
            self.k.images[pid] = DESK; self.k.command_lines[pid] = f'"{DESK}" {args}'.rstrip()
        clock = [100.0]
        real = R.witness
        def slow(*args):
            clock[0] += 6  # 见证判定之后、返回之前跨过截止
            return real(*args)
        with patch.object(R, 'time', SimpleNamespace(monotonic=lambda: clock[0])), patch.object(R, 'witness', slow):
            roles = R.Roles(self.k.api, 105.0)
            self.assertFalse(roles.exempt(500, str(int(BIRTH) + 500), frozenset()))
        with patch.object(R, 'time', SimpleNamespace(monotonic=lambda: clock[0])):
            self.assertTrue(R.Roles(self.k.api, clock[0] + 5).exempt(500, str(int(BIRTH) + 500), frozenset()))

    def test_probe_reason_prefers_budget_on_every_exit(self):
        import importlib.util
        path = Path(__file__).resolve().parents[1] / 'scripts/windows/accept-92.py'
        spec = importlib.util.spec_from_file_location('accept_92_r1', path)
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
        self.k.processes[500] = (0, int(BIRTH) + 500, self.k.sid, False, 'claude.exe')
        self.k.images[500] = DESK  # 无命令行：父角色读取得 unknown
        clock = [100.0]
        def late(out, size):
            clock[0] += 10  # 父角色读取期间跨过截止
            return -1073741790, 0
        self.k.command_line_hooks[500] = late
        with patch.object(R, 'time', SimpleNamespace(monotonic=lambda: clock[0])), \
                patch.object(module, 'time', SimpleNamespace(monotonic=lambda: clock[0])):
            roles = R.Roles(self.k.api, 105.0)
            reason = module.parent_reason(self.k.api, roles, 500, str(int(BIRTH) + 500), [], frozenset())
        self.assertEqual(reason, 'budget_exhausted')

    def test_cached_helper_rechecks_token_qualification(self):
        self.k.processes[501] = (0, int(BIRTH) + 501, self.k.sid, False, 'claude.exe')
        self.k.images[501] = DESK; self.k.command_lines[501] = f'"{DESK}" --type=renderer'
        birth = str(int(BIRTH) + 501)
        roles = R.Roles(self.k.api, time.monotonic() + 5)
        self.assertTrue(roles.exempt(501, birth, frozenset()))
        self.k.restricted_process_stage = 'queryable'
        self.k.processes[501] = (0, int(BIRTH) + 501, self.k.sid, True, 'claude.exe')  # 同代原地提权
        self.assertFalse(roles.exempt(501, birth, frozenset()))

    def test_fake_models_query_and_wait_access_separately(self):
        self.k.command_lines[200] = f'"{DESK}" --type=gpu-process'
        handle = self.k.api.handle(self.k.api.k.OpenProcess(0x1000, False, 200))  # 只有 QUERY_LIMITED
        try:
            self.assertEqual(R.read_role(self.k.api, handle, time.monotonic() + 5), HELPER)  # class 60 只要 QUERY
            self.assertEqual(self.k.api.k.WaitForSingleObject(handle, 0), 0xFFFFFFFF)  # 等待要 SYNCHRONIZE
            self.assertEqual(self.k.error, 5)
        finally:
            self.k.api.close(handle)



class ImplAuditOpusTests(unittest.TestCase):
    """§92 实现审计 r1（Opus P2-1、P3 N1/N2/N3/N5/N11/N12）的回归。"""
    setUp = fixtures.NativeTests.setUp
    write = fixtures.NativeTests.write
    roots = roots_base.MultiRootTests.roots
    desktop = DesktopDiscoveryTests.desktop
    probe = DesktopDiscoveryTests.probe

    def wait_failed(self, pid):
        """让该 PID 的进程事实读不到（WAIT_FAILED，普通 OSError 而不是 Ineligible）。"""
        original = self.k.WaitForSingleObject
        def wait(handle, timeout):
            record = self.k.handles.get(handle)
            if record is not None and record.get('kind') == 'process' and record['pid'] == pid:
                self.k.error = 6
                return 0xFFFFFFFF
            return original(handle, timeout)
        self.k.WaitForSingleObject = wait

    def test_fact_unknown_gaps_keep_discovery_incomplete(self):
        self.roots(); self.desktop()
        self.assert_complete = lambda: self.assertTrue(D.discover(self.p.transport, connect=False).complete)
        self.assert_complete()
        # 未定位分支：一个未知的 claude.exe，进程事实读不到（不是不合格）
        self.k.processes[600] = (0, int(BIRTH) + 600, self.k.sid, False, 'claude.exe')
        self.k.images[600] = r'C:\fixture\claude.exe'
        self.wait_failed(600)
        self.assertIn(600, self.p.files.claude_sessions_dirs().unlocated)
        self.assertFalse(D.discover(self.p.transport, connect=False).complete)
        del self.k.processes[600]; del self.k.WaitForSingleObject
        self.assert_complete()
        # 记录分支：坏记录就在本 PID 自己映射的根；扫描定位之后才让事实读不到
        own = self.root / 'desk3/sessions'; own.mkdir(parents=True)
        self.k.environments[502] = ('CLAUDE_CONFIG_DIR=' + str(own.parent) + '\0\0').encode('utf-16-le')
        (own / '502.json').write_text('{broken fixture')
        self.assertIn((502, own), self.p.files.claude_sessions_dirs().live)
        scan = self.p.files.claude_sessions_dirs()
        with patch.object(self.p.files, 'claude_sessions_dirs', return_value=scan):
            self.wait_failed(502)
            self.assertFalse(D.discover(self.p.transport, connect=False).complete)

    def test_class60_handle_never_asks_for_vm_read(self):
        self.k.processes[501] = (0, int(BIRTH) + 501, self.k.sid, False, 'claude.exe')
        self.k.images[501] = DESK; self.k.command_lines[501] = f'"{DESK}" --type=renderer'
        self.k.calls.clear()
        self.assertEqual(R.command_role(self.k.api, 501, str(int(BIRTH) + 501), deadline=time.monotonic() + 5), HELPER)
        opens = {args[0] for name, args in self.k.calls if name == 'OpenProcess'}
        self.assertEqual(opens, {0x101000})  # 只申请 QUERY_LIMITED|SYNCHRONIZE，不要 VM_READ
        self.assertEqual(R.QUERY_ACCESS, 0x101000)
        if C.sizeof(C.c_void_p) == 8:
            self.assertEqual(R.QUERY_LIMIT, 65552)  # Win64：头 16 + 65534 + 2

    def family(self):
        self.k.processes[500] = (0, int(BIRTH) + 500, self.k.sid, False, 'claude.exe')
        self.k.processes[501] = (500, int(BIRTH) + 501, self.k.sid, False, 'claude.exe')
        for pid, args in ((500, ''), (501, '--type=renderer')):
            self.k.images[pid] = DESK; self.k.command_lines[pid] = f'"{DESK}" {args}'.rstrip()

    def test_parent_proof_rechecks_both_generations_before_returning(self):
        self.family()
        real = R.witness
        for leaving in (500, 501):
            with self.subTest(leaving=leaving):
                def exits(*args, leaving=leaving):
                    result = real(*args)
                    self.k.exited.add(leaving)  # 见证判定之后、两代复核之前退出
                    return result
                try:
                    with patch.object(R, 'witness', exits):
                        self.assertFalse(R.Roles(self.k.api, time.monotonic() + 5)._parent(
                            500, str(int(BIRTH) + 500), frozenset()))
                finally:
                    self.k.exited.clear()
        self.assertTrue(R.Roles(self.k.api, time.monotonic() + 5)._parent(500, str(int(BIRTH) + 500), frozenset()))

    def test_single_process_budget_is_half_a_second(self):
        self.family()
        clock = [100.0]
        def slow(out, size):
            del self.k.command_line_hooks[501]
            clock[0] += 0.6  # 超过单进程 0.5 秒，但远在调用方截止之前
        self.k.command_line_hooks[501] = slow
        with patch.object(R, 'time', SimpleNamespace(monotonic=lambda: clock[0])):
            self.assertEqual(R.command_role(self.k.api, 501, str(int(BIRTH) + 501), deadline=200.0), UNKNOWN)
        self.assertEqual(R.ROLE_SECONDS, 0.5)

    def test_probe_reports_witness_unverified(self):
        self.roots(); self.desktop(types=('renderer',))
        self.k.command_lines.pop(501)  # 唯一的孩子读不到命令行
        rows = {row['pid']: row for row in self.probe()['rows']}
        self.assertEqual((rows[500]['pProven'], rows[500]['pReason']), (False, 'witness_unverified'))


class NativeCallSignatureTests(unittest.TestCase):
    """native 用例只在真实 Windows 上运行；Linux 上也把其中对 process_role 的引用核一遍，改原语时本地即可发现
    （r1 给 _split 加参数时漏改，CI 才暴露，Opus r1 跟进建议）。覆盖：R.x 引用存在；R.f(...) 按现签名绑定；
    R.Cls(...).m(...) 链式调用按类方法签名绑定（Fable r2 P3-2）。"""

    def bind(self, node, target, *, method=False):
        import ast, inspect
        self.assertFalse(any(isinstance(arg, ast.Starred) for arg in node.args)
                         or any(keyword.arg is None for keyword in node.keywords))
        args = ([None] if method else []) + list(node.args)
        try:
            inspect.signature(target).bind(*args, **{k.arg: k.value for k in node.keywords if k.arg})
        except TypeError as error:
            self.fail(f'native 用例第 {node.lineno} 行与 {getattr(target, "__qualname__", target)} 现签名不符：{error}')

    def test_native_references_match_current_process_role(self):
        import ast
        source = Path(__file__).with_name('test_bridge_windows_native.py').read_text(encoding='utf-8')
        tree = ast.parse(source)
        def is_r(node):
            return isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name) and node.value.id == 'R'
        refs = [node for node in ast.walk(tree) if is_r(node)]
        calls = [node for node in ast.walk(tree) if isinstance(node, ast.Call) and is_r(node.func)]
        chained = [node for node in ast.walk(tree) if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                   and isinstance(node.func.value, ast.Call) and is_r(node.func.value.func)]
        self.assertGreaterEqual(len(calls), 9)  # 防止扫描落空而恒真
        self.assertGreaterEqual(len(chained), 1)
        for node in refs:
            with self.subTest(line=node.lineno, name=node.attr):
                self.assertTrue(hasattr(R, node.attr), f'native 用例第 {node.lineno} 行引用的 R.{node.attr} 不存在')
        for node in calls:
            with self.subTest(line=node.lineno, call=node.func.attr):
                self.bind(node, getattr(R, node.func.attr))
        for node in chained:
            owner = getattr(R, node.func.value.func.attr)
            with self.subTest(line=node.lineno, call=f'{node.func.value.func.attr}().{node.func.attr}'):
                self.assertTrue(isinstance(owner, type) and hasattr(owner, node.func.attr))
                self.bind(node, getattr(owner, node.func.attr), method=True)

if __name__ == '__main__':
    unittest.main()
