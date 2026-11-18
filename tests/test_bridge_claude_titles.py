"""§99 Claude 会话名取自会话记录的标题记录：取名规则、有界回读、定位、进程内记忆、诊断计数与测试守卫（全部临时夹具）。"""
from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import replace
import json
import os
from pathlib import Path
import stat
from tempfile import TemporaryDirectory
import threading
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from bridge_support import endpoint, ref
from bridge_transcript_guard import ROOTS, RealTranscriptAccess, check
from agentstatus_bridge import claude_titles as T
from agentstatus_bridge.model import Provider
from agentstatus_bridge.native_names import copyable, display_text, name_source

SID = '11111111-2222-4333-8444-555555555555'
OTHER = '99999999-2222-4333-8444-555555555555'
POSIX = os.name == 'posix'
POSIX_ONLY = 'POSIX-only: 符号链接、FIFO 与 Linux 只读打开夹具'
FIELDS = {'ai-title': 'aiTitle', 'custom-title': 'customTitle', 'agent-name': 'agentName'}


def title(kind: str, value: object, sid: str | None = SID) -> bytes:
    """一行标题类记录；与真实记录一样是紧凑 JSON（字样 "type":"ai-title" 中间没有空格）。"""
    record: dict[str, object] = {'type': kind, FIELDS[kind]: value}
    if sid is not None:
        record['sessionId'] = sid
    return json.dumps(record, ensure_ascii=False, separators=(',', ':')).encode()


def ordinary(text: str = 'hello', size: int = 0) -> bytes:
    """一行普通记录（夹具内容，非真实会话）。"""
    record = {'type': 'user', 'message': {'content': text + 'x' * size}, 'sessionId': SID}
    return json.dumps(record, separators=(',', ':')).encode()


def lines(*items: bytes) -> bytes:
    return b'\n'.join(items) + b'\n'


def filler(total: int) -> list[bytes]:
    """合计 total 到 total+1 KiB 字节（含换行）的普通记录行，每行约 1 KiB。"""
    line = ordinary(size=1000)
    return [line] * (total // (len(line) + 1) + 1)


class BytesRead:
    """内存里的 SharedRead：记下每次读的偏移与长度，用来断言预算与回读方向。"""

    def __init__(self, data: bytes, *, short: bool = False) -> None:
        self.data, self.size, self.short = data, len(data), short
        self.reads: list[tuple[int, int]] = []

    def read_at(self, offset: int, length: int) -> bytes:
        self.reads.append((offset, length))
        return self.data[offset:offset + length - (1 if self.short else 0)]

    @property
    def consumed(self) -> int:
        return sum(length for _, length in self.reads)


def read(data: bytes, budget: int = T.FILE_BUDGET_BYTES) -> tuple[T.TitleResult, int, BytesRead]:
    reader = BytesRead(data)
    result, used, _truncated = T._read_title(reader, SID, budget)
    return result, used, reader


class RuleTests(unittest.TestCase):
    """§99.2：最近一组相邻标题类记录里 custom-title 优先，否则 ai-title；sessionId 必须相等。"""

    def test_only_an_ai_title_is_used(self):
        self.assertEqual(read(lines(ordinary(), title('ai-title', '修复登录'), ordinary('next')))[0],
                         T.TitleResult('修复登录', 'found_ai'))

    def test_a_renamed_session_uses_the_custom_title(self):
        data = lines(title('ai-title', 'auto'), ordinary(), title('custom-title', 'lead'), title('agent-name', 'lead'))
        self.assertEqual(read(data)[0], T.TitleResult('lead', 'found_custom'))

    def test_custom_wins_inside_one_group_in_either_order(self):
        orders = {'custom-first': (title('custom-title', 'mine'), title('agent-name', 'mine'), title('ai-title', 'auto')),
                  'ai-first': (title('ai-title', 'auto'), title('custom-title', 'mine'), title('agent-name', 'mine'))}
        for name, group in orders.items():
            with self.subTest(order=name):
                self.assertEqual(read(lines(ordinary(), *group))[0], T.TitleResult('mine', 'found_custom'))

    def test_the_newest_group_wins_over_an_older_custom_title(self):
        data = lines(title('custom-title', 'old'), title('agent-name', 'old'), ordinary(), title('ai-title', '新标题'))
        self.assertEqual(read(data)[0], T.TitleResult('新标题', 'found_ai'))

    def test_the_latest_record_of_a_kind_inside_the_group_wins(self):
        data = lines(ordinary(), title('ai-title', 'first'), title('ai-title', 'second'))
        self.assertEqual(read(data)[0], T.TitleResult('second', 'found_ai'))

    def test_other_sessions_lines_are_skipped(self):
        self.assertEqual(read(lines(title('ai-title', 'mine'), title('ai-title', 'theirs', OTHER)))[0],
                         T.TitleResult('mine', 'found_ai'))
        for sid in (OTHER, None):
            with self.subTest(sid=sid):
                self.assertEqual(read(lines(ordinary(), title('ai-title', 'theirs', sid)))[0],
                                 T.TitleResult(None, 'session_mismatch'))

    def test_bad_lines_are_skipped(self):
        half = b'{"type":"ai-title","aiTitle":"trunc'  # 正在追加、还没写完的最后一行
        self.assertEqual(read(lines(ordinary(), title('ai-title', 'good')) + half)[0], T.TitleResult('good', 'found_ai'))
        broken = lines(ordinary(), title('ai-title', 'good'), b'{"type":"ai-title","aiTitle":"\xff\xfe"}',
                       b'{"type":"custom-title",')
        self.assertEqual(read(broken)[0], T.TitleResult('good', 'found_ai'))

    def test_a_marker_inside_another_record_ends_the_group(self):
        nested = json.dumps({'type': 'assistant', 'message': {'content': [
            {'type': 'custom-title', 'customTitle': 'nested', 'sessionId': SID}]}}, separators=(',', ':')).encode()
        listed = json.dumps([{'type': 'custom-title', 'customTitle': 'listed', 'sessionId': SID}],
                            separators=(',', ':')).encode()
        oversized = title('custom-title', 'x' * T.MAX_RECORD_BYTES)
        odd_type = json.dumps({'type': ['custom-title'], 'x': {'type': 'custom-title'}}, separators=(',', ':')).encode()
        for name, middle in (('nested', nested), ('list', listed), ('oversized', oversized), ('odd-type', odd_type)):
            with self.subTest(middle=name):
                data = lines(title('custom-title', 'older'), middle, title('ai-title', 'newer'))
                self.assertEqual(read(data)[0], T.TitleResult('newer', 'found_ai'))
                self.assertEqual(read(lines(ordinary(), middle))[0], T.TitleResult(None, 'no_title_record'))

    def test_non_string_or_blank_titles_fall_back_without_switching_kind(self):
        for value in (123, None, '   ', ''):
            with self.subTest(value=value):
                self.assertEqual(read(lines(ordinary(), title('ai-title', value)))[0], T.TitleResult(None, 'bad_value'))
        data = lines(ordinary(), title('ai-title', 'auto'), title('custom-title', '  '), title('agent-name', 'x'))
        self.assertEqual(read(data)[0], T.TitleResult(None, 'bad_value'))

    def test_other_sessions_lines_inside_a_group_are_skipped_without_ending_it(self):
        # 审计 Opus O1 / Fable F4：组内夹别的会话的标题行只跳过，组照样往前延伸到 custom-title
        data = lines(ordinary(), title('custom-title', 'mine'), title('ai-title', 'theirs', OTHER), title('ai-title', 'auto'))
        self.assertEqual(read(data)[0], T.TitleResult('mine', 'found_custom'))

    def test_bad_lines_inside_a_group_are_skipped_without_ending_it(self):
        # 审计 Opus O2 / Fable F3：组内夹坏行只跳过
        data = lines(ordinary(), title('custom-title', 'mine'), b'{"type":"ai-title","aiTitle":', title('ai-title', 'auto'))
        self.assertEqual(read(data)[0], T.TitleResult('mine', 'found_custom'))

    def test_an_agent_name_only_group_falls_back_without_searching_further(self):
        # 审计 Opus O3：最近一组只有 agent-name 时这一组就是答案（退回注册名），不再往前找更早的 ai-title
        data = lines(title('ai-title', 'older'), ordinary(), title('agent-name', 'x'))
        self.assertEqual(read(data)[0], T.TitleResult(None, 'no_title_record'))

    def test_json_is_parsed_only_for_short_lines_with_a_compact_marker(self):
        # 审计 Fable P2-1：隐私核心判据——只有含紧凑字样、不超过 16 KiB 的单行才进解析入口
        nested = json.dumps({'type': 'assistant', 'x': {'type': 'ai-title', 'aiTitle': 'n', 'sessionId': SID}},
                            separators=(',', ':')).encode()
        spaced = json.dumps({'type': 'ai-title', 'aiTitle': 'spaced', 'sessionId': SID}).encode()  # 冒号后带空格
        oversized = title('custom-title', 'x' * T.MAX_RECORD_BYTES)
        good = title('ai-title', 'good')
        data = lines(good, ordinary(), spaced, nested, oversized, b'{"type":"user","note":"plain"}', ordinary('tail'))
        seen: list[bytes] = []
        real = T._parse

        def recorder(line: bytes) -> object:
            seen.append(line)
            return real(line)
        with patch.object(T, '_parse', side_effect=recorder):
            result = read(data)[0]
        self.assertEqual(result, T.TitleResult('good', 'found_ai'))
        self.assertEqual(seen, [nested, good])  # 从尾往前：嵌套字样的普通记录也会解析后丢弃，其余一概不解析
        self.assertTrue(all(len(line) <= T.MAX_RECORD_BYTES and any(marker in line for marker in T._MARKERS.values())
                            for line in seen))

    def test_a_spaced_title_record_is_not_a_title(self):
        # 不含紧凑字样的行即使解析后顶层 type 是 ai-title 也不算标题（只认真实写法；上游改写法时退回注册名）
        spaced = json.dumps({'type': 'ai-title', 'aiTitle': 'spaced', 'sessionId': SID}).encode()
        self.assertEqual(read(lines(ordinary(), spaced))[0], T.TitleResult(None, 'no_title_record'))
        self.assertEqual(read(lines(title('ai-title', 'real'), spaced))[0], T.TitleResult('real', 'found_ai'))

    def test_files_without_title_records(self):
        for data in (b'', lines(ordinary(), ordinary()), lines(title('agent-name', 'only'))):
            with self.subTest(size=len(data)):
                self.assertEqual(read(data)[0], T.TitleResult(None, 'no_title_record'))


class ChunkTests(unittest.TestCase):
    """§99.3：从尾部按 64 KiB 回读、单文件 1 MiB 预算、跨块拼行。"""

    def straddling(self, record: bytes, before_boundary: int) -> bytes:
        """把 record 放到离文件尾第一个 64 KiB 边界处：边界前留 before_boundary 字节在上一块。"""
        after = T.CHUNK_BYTES - (len(record) - before_boundary)  # 边界之后、record 之后的字节数（含换行）
        base = len(ordinary())
        suffix = ordinary(size=after - 2 - base) + b'\n'
        data = ordinary('first') + b'\n' + record + b'\n' + suffix
        self.assertEqual(len(record) + 1 + len(suffix) - before_boundary, T.CHUNK_BYTES)
        return data

    def test_a_title_line_straddling_a_chunk_boundary_is_joined(self):
        record = title('ai-title', '跨块标题')
        for name, before in (('middle', len(record) // 2), ('one-byte', 1), ('line-start', 0)):
            with self.subTest(split=name):
                result, _, reader = read(self.straddling(record, before))
                self.assertEqual(result, T.TitleResult('跨块标题', 'found_ai'))
                self.assertEqual(len(reader.reads), 2)

    def test_a_group_split_across_chunks_stays_one_group(self):
        record = title('custom-title', 'split-name')
        data = self.straddling(record, len(record) // 2)
        data = data.replace(b'\n' + record + b'\n', b'\n' + record + b'\n' + title('ai-title', 'auto') + b'\n', 1)
        self.assertEqual(read(data)[0], T.TitleResult('split-name', 'found_custom'))

    def test_reads_go_backwards_from_the_end_in_chunks(self):
        data = lines(title('ai-title', 'far'), *filler(3 * T.CHUNK_BYTES))
        result, used, reader = read(data)
        self.assertEqual(result, T.TitleResult('far', 'found_ai'))
        self.assertEqual(sum(reader.reads[0]), len(data))  # 第一块贴着文件尾
        self.assertEqual([offset + length for offset, length in reader.reads[1:]], [o for o, _ in reader.reads[:-1]])
        self.assertTrue(all(length <= T.CHUNK_BYTES for _, length in reader.reads))
        self.assertEqual(used, reader.consumed)

    def test_a_title_beyond_the_file_budget_is_not_found(self):
        data = lines(title('ai-title', 'far'), *filler(T.FILE_BUDGET_BYTES + 4096))
        result, used, reader = read(data)
        self.assertEqual(result, T.TitleResult(None, 'budget_exhausted'))
        self.assertEqual((used, reader.consumed), (T.FILE_BUDGET_BYTES, T.FILE_BUDGET_BYTES))

    def test_a_title_inside_the_budget_is_found(self):
        data = lines(ordinary(), title('ai-title', 'near-edge'), *filler(T.FILE_BUDGET_BYTES - 4096))
        self.assertEqual(read(data)[0], T.TitleResult('near-edge', 'found_ai'))

    def test_truncation_is_reported_only_when_a_budget_stops_the_read(self):
        far = lines(title('ai-title', 'far'), *filler(T.FILE_BUDGET_BYTES + 4096))
        self.assertTrue(T._read_title(BytesRead(far), SID, T.FILE_BUDGET_BYTES)[2])
        self.assertTrue(T._read_title(BytesRead(far), SID, T.CHUNK_BYTES)[2])
        near = lines(ordinary(), title('ai-title', 'near'))
        self.assertFalse(T._read_title(BytesRead(near), SID, T.FILE_BUDGET_BYTES)[2])
        self.assertFalse(T._read_title(BytesRead(lines(title('ai-title', 'whole'))), SID, T.FILE_BUDGET_BYTES)[2])

    def test_a_group_reached_when_the_budget_runs_out_still_counts(self):
        # 标题行整行在预算内，组前的那行只读到一半：预算用完时已开始的组照样算数
        record = title('ai-title', 'edge')
        suffix = ordinary(size=T.CHUNK_BYTES - 10 - len(record) - 1 - 1 - len(ordinary())) + b'\n'
        data = ordinary('before') + b'\n' + record + b'\n' + suffix
        self.assertEqual(len(record) + 1 + len(suffix), T.CHUNK_BYTES - 10)
        self.assertEqual(read(data, budget=T.CHUNK_BYTES)[0], T.TitleResult('edge', 'found_ai'))


@contextmanager
def plain_open(path: Path) -> Iterator[BytesRead]:
    """测试用打开：只读一遍夹具文件（两平台通用），不走平台层。"""
    with open(path, 'rb') as handle:
        data = handle.read()
    yield BytesRead(data)


class _Fixture:
    """临时配置根与记录打开情况；LocateTests 与 MemoTests 共用（混入类，自身不是用例）。"""

    def setUp(self):
        T._MEMO.clear()
        self.addCleanup(T._MEMO.clear)
        temporary = TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name)
        self.root = self.base / 'config'
        self.projects = self.root / 'projects'
        self.projects.mkdir(parents=True)
        self.opened: list[Path] = []
        self.readers: list[BytesRead] = []

    @contextmanager
    def opener(self, path: Path) -> Iterator[BytesRead]:
        self.opened.append(path)
        with plain_open(path) as reader:
            self.readers.append(reader)
            yield reader

    def write(self, folder: str, data: bytes, sid: str = SID) -> Path:
        path = self.projects / folder / f'{sid}.jsonl'
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        return path

    def lookup(self, sid: str = SID, root: Path | None = None, budget: int = T.ROUND_BUDGET_BYTES) -> T.TitleResult:
        return T.TitleReader(self.opener, budget=budget).lookup(root or self.root, sid)


class LocateTests(_Fixture, unittest.TestCase):
    """§99.3 定位：<配置根>/projects/ 一级子目录里恰为 <sessionId>.jsonl 的普通文件；不跟随链接、不读子目录、多个退回。"""

    def test_a_record_in_a_first_level_project_dir_is_found(self):
        self.write('-home-u-repo', lines(ordinary(), title('ai-title', '标题')))
        self.assertEqual(self.lookup(), T.TitleResult('标题', 'found_ai'))
        self.assertEqual(self.opened, [self.projects / '-home-u-repo' / f'{SID}.jsonl'])

    def test_missing_records_and_missing_projects_dir(self):
        self.write('a', lines(title('ai-title', 'other')), sid=OTHER)
        self.assertEqual(self.lookup(), T.TitleResult(None, 'no_record_file'))
        self.assertEqual(self.lookup(root=self.base / 'absent'), T.TitleResult(None, 'no_record_file'))
        self.assertEqual(self.opened, [])

    def test_two_copies_cannot_be_decided(self):
        self.write('a', lines(title('ai-title', 'one')))
        self.write('b', lines(title('ai-title', 'two')))
        self.assertEqual(self.lookup(), T.TitleResult(None, 'multiple_files'))
        self.assertEqual(self.opened, [])

    def test_records_in_deeper_dirs_are_not_read(self):
        self.write('a/subagents', lines(title('ai-title', 'sub')))
        self.assertEqual(self.lookup(), T.TitleResult(None, 'no_record_file'))

    def test_a_directory_named_like_the_record_is_not_read(self):
        (self.projects / 'a' / f'{SID}.jsonl').mkdir(parents=True)
        self.assertEqual(self.lookup(), T.TitleResult(None, 'not_regular'))
        self.assertEqual(self.opened, [])

    @unittest.skipUnless(POSIX, POSIX_ONLY)
    def test_a_symlinked_record_file_is_not_followed(self):
        target = self.base / 'elsewhere.jsonl'
        target.write_bytes(lines(title('ai-title', 'leak')))
        (self.projects / 'a').mkdir()
        os.symlink(target, self.projects / 'a' / f'{SID}.jsonl')
        self.assertEqual(self.lookup(), T.TitleResult(None, 'not_regular'))
        self.assertEqual(self.opened, [])

    @unittest.skipUnless(POSIX, POSIX_ONLY)
    def test_a_symlinked_project_dir_is_skipped(self):
        outside = self.base / 'outside'
        outside.mkdir()
        (outside / f'{SID}.jsonl').write_bytes(lines(title('ai-title', 'leak')))
        os.symlink(outside, self.projects / 'linked')
        self.assertEqual(self.lookup(), T.TitleResult(None, 'no_record_file'))
        self.assertEqual(self.opened, [])

    @unittest.skipUnless(POSIX, POSIX_ONLY)
    def test_a_fifo_is_not_opened(self):
        (self.projects / 'a').mkdir()
        os.mkfifo(self.projects / 'a' / f'{SID}.jsonl')
        self.assertEqual(self.lookup(), T.TitleResult(None, 'not_regular'))
        self.assertEqual(self.opened, [])

    @unittest.skipUnless(POSIX, POSIX_ONLY)
    def test_projects_itself_may_be_a_link_to_the_account_root(self):
        # 兼容布局：<配置根>/projects 是指向真实账号根 projects 的链接；「不跟随链接」管的是它下面的项
        real = self.base / 'account' / 'projects'
        (real / 'a').mkdir(parents=True)
        (real / 'a' / f'{SID}.jsonl').write_bytes(lines(title('ai-title', 'via-link')))
        self.projects.rmdir()
        os.symlink(real, self.projects)
        self.assertEqual(self.lookup(), T.TitleResult('via-link', 'found_ai'))

    def test_session_ids_that_are_not_uuids_are_refused(self):
        self.write('a', lines(title('ai-title', 'x')))
        for bad in ('../x', SID + '/..', 'abc', '', SID + 'x', '*'):
            with self.subTest(sid=bad):
                self.assertEqual(self.lookup(bad), T.TitleResult(None, 'bad_session_id'))
        self.assertEqual(self.opened, [])

    def test_the_project_dir_scan_is_capped(self):
        for name in ('a', 'b', 'c'):
            (self.projects / name).mkdir()
        with patch.object(T, 'MAX_PROJECT_DIRS', 2):
            self.assertEqual(self.lookup(), T.TitleResult(None, 'directory_limit'))

    def test_an_unreadable_project_dir_does_not_hide_the_others(self):
        # 审计 Fable P3-2：一个子目录 lstat 报权限错误只跳过它
        self.write('a', lines(title('ai-title', 'hidden')))
        self.write('b', lines(title('ai-title', 'visible')))
        real = os.lstat

        def lstat(path, *args, **kwargs):
            if Path(path).parent.name == 'a':
                raise PermissionError(13, 'denied')
            return real(path, *args, **kwargs)
        with patch.object(T.os, 'lstat', side_effect=lstat):
            self.assertEqual(self.lookup(), T.TitleResult('visible', 'found_ai'))
            (self.projects / 'b' / f'{SID}.jsonl').unlink()
            T._MEMO.clear()
            self.assertEqual(self.lookup(), T.TitleResult(None, 'unreadable'))  # 什么都没找到且有目录查不了

    def test_junction_project_dirs_are_skipped(self):
        # 审计 Opus O11 / Fable F12：Windows junction 子目录不进（Linux 上用包装的目录项模拟）
        self.write('j', lines(title('ai-title', 'via-junction')))
        real = os.scandir

        class Entry:
            def __init__(self, entry: os.DirEntry[str]) -> None:
                self.entry, self.path, self.name = entry, entry.path, entry.name
            def is_symlink(self) -> bool:
                return False
            def is_junction(self) -> bool:
                return self.name == 'j'
            def is_dir(self, *, follow_symlinks: bool = True) -> bool:
                return self.entry.is_dir(follow_symlinks=follow_symlinks)

        @contextmanager
        def scandir(path):
            with real(path) as entries:
                yield [Entry(entry) for entry in entries]
        with patch.object(T.os, 'scandir', side_effect=scandir):
            self.assertEqual(self.lookup(), T.TitleResult(None, 'no_record_file'))
        self.assertEqual(self.opened, [])

    def test_reparse_point_records_are_not_read(self):
        # 审计 Opus O12 / Fable F13：lstat 带 FILE_ATTRIBUTE_REPARSE_POINT（0x400）的记录不读
        path = self.write('a', lines(title('ai-title', 'reparse')))
        real = os.lstat
        info = real(path)
        flagged = SimpleNamespace(st_mode=stat.S_IFREG | 0o600, st_size=info.st_size, st_mtime_ns=info.st_mtime_ns,
                                  st_dev=info.st_dev, st_ino=info.st_ino, st_file_attributes=0x400)
        with patch.object(T.os, 'lstat', side_effect=lambda value, *a, **k: flagged if Path(value) == path else real(value, *a, **k)):
            self.assertEqual(self.lookup(), T.TitleResult(None, 'not_regular'))
        self.assertEqual(self.opened, [])

    def test_apply_tries_each_root_in_order_until_a_title(self):
        other = self.base / 'alias'
        other.mkdir()
        self.write('a', lines(ordinary()))
        item = endpoint(ref(Provider.CLAUDE, SID), name='repo-1')
        reader = T.TitleReader(self.opener)
        self.assertEqual(reader.apply(item, other, self.root).name_origin, 'no_title_record')  # 第一个找到文件的根
        self.assertEqual(reader.apply(item, self.root, other).name_origin, 'no_title_record')  # 不是取最后一个根
        self.assertEqual(reader.apply(item, other, other).name_origin, 'no_record_file')
        (self.projects / 'a' / f'{SID}.jsonl').write_bytes(lines(title('ai-title', 'found')))
        named = T.TitleReader(self.opener).apply(item, other, self.root)
        self.assertEqual((named.name, named.name_origin), ('found', 'found_ai'))

    @unittest.skipUnless(POSIX, POSIX_ONLY)
    def test_one_file_seen_through_two_roots_is_read_once_per_round(self):
        # 审计 P1：别名根的 projects 链接到同一个账号根时，没有标题的大文件本轮只读一遍、只扣一次预算
        alias = self.base / 'alias'
        alias.mkdir()
        os.symlink(self.projects, alias / 'projects')
        self.write('a', lines(title('ai-title', 'far'), *filler(T.FILE_BUDGET_BYTES + 4096)))
        named = T.TitleReader(self.opener).apply(endpoint(ref(Provider.CLAUDE, SID), name='repo-1'), alias, self.root)
        self.assertEqual(named.name_origin, 'budget_exhausted')
        self.assertEqual(len(self.opened), 1)
        self.assertEqual(sum(item.consumed for item in self.readers), T.FILE_BUDGET_BYTES)

    def test_hard_linked_files_of_two_sessions_keep_their_own_results(self):
        # §99 r1c（两方 P3）：本轮复用键含会话 ID；硬链接让另一个会话 ID 的文件名指向同一 inode 时，
        # 两个会话各按自己的 sessionId 判（B 读到的是 A 的记录 → session_mismatch 退回），先后顺序无关
        mine = self.write('a', lines(ordinary(), title('ai-title', 'a-title')))
        linked = self.projects / 'a' / f'{OTHER}.jsonl'
        os.link(mine, linked)
        self.assertEqual(os.lstat(mine).st_ino, os.lstat(linked).st_ino)
        for order in ((SID, OTHER), (OTHER, SID)):
            with self.subTest(order=order):
                T._MEMO.clear()
                reader = T.TitleReader(self.opener)
                results = {sid: reader.lookup(self.root, sid) for sid in order}
                self.assertEqual(results, {SID: T.TitleResult('a-title', 'found_ai'),
                                           OTHER: T.TitleResult(None, 'session_mismatch')})

    def test_files_without_an_inode_number_are_not_reused(self):
        # 审计 Opus N6：inode 为 0 的文件系统上不认身份——两个根各自的同名记录不能互相顶替
        other = self.base / 'other'
        first = self.write('a', lines(ordinary()))
        second = other / 'projects' / 'b' / f'{SID}.jsonl'
        second.parent.mkdir(parents=True)
        second.write_bytes(lines(title('ai-title', 'second-root')))
        real = os.lstat

        def lstat(value, *args, **kwargs):
            info = real(value, *args, **kwargs)
            if Path(value) in (first, second):
                return SimpleNamespace(st_mode=stat.S_IFREG | 0o600, st_size=info.st_size, st_mtime_ns=info.st_mtime_ns,
                                       st_dev=1, st_ino=0)
            return info
        with patch.object(T.os, 'lstat', side_effect=lstat):
            named = T.TitleReader(self.opener).apply(endpoint(ref(Provider.CLAUDE, SID), name='repo-1'), self.root, other)
        self.assertEqual((named.name, named.name_origin), ('second-root', 'found_ai'))
        self.assertEqual(len(self.opened), 2)

    def test_a_memo_hit_also_registers_the_file_for_the_round(self):
        # 审计 Fable P3-2：两根经硬链接看到同一个不变的无标题大文件，第二轮起两根合计打开 0 次
        other = self.base / 'other'
        first = self.write('a', lines(title('ai-title', 'far'), *filler(T.FILE_BUDGET_BYTES + 4096)))
        second = other / 'projects' / 'b' / f'{SID}.jsonl'
        second.parent.mkdir(parents=True)
        os.link(first, second)
        item = endpoint(ref(Provider.CLAUDE, SID), name='repo-1')
        for round_ in (1, 2, 3):
            with self.subTest(round=round_):
                named = T.TitleReader(self.opener).apply(item, self.root, other)
                self.assertEqual(named.name_origin, 'budget_exhausted')
                self.assertEqual(len(self.opened), 1)

    def test_open_and_read_failures_fall_back_without_raising(self):
        self.write('a', lines(title('ai-title', 'x')))
        failures = ((PermissionError(13, 'denied'), 'unreadable'), (FileNotFoundError(2, 'gone'), 'no_record_file'),
                    (OSError('not_regular'), 'not_regular'), (OSError(5, 'io'), 'unreadable'))
        for error, reason in failures:
            with self.subTest(reason=reason, error=type(error).__name__):
                T._MEMO.clear()
                def broken(_path: Path, error: OSError = error) -> BytesRead:
                    raise error
                self.assertEqual(T.TitleReader(broken).lookup(self.root, SID), T.TitleResult(None, reason))

        @contextmanager
        def short(path: Path) -> Iterator[BytesRead]:
            yield BytesRead(path.read_bytes(), short=True)
        T._MEMO.clear()
        self.assertEqual(T.TitleReader(short).lookup(self.root, SID), T.TitleResult(None, 'unreadable'))

    def test_lookup_stops_at_the_file_budget(self):
        self.write('a', lines(title('ai-title', 'far'), *filler(T.FILE_BUDGET_BYTES + 4096)))
        self.assertEqual(self.lookup(), T.TitleResult(None, 'budget_exhausted'))
        self.assertEqual(self.readers[0].consumed, T.FILE_BUDGET_BYTES)


class MemoTests(_Fixture, unittest.TestCase):
    """§99.3 开销：同一进程按 (路径, 大小, 修改时间) 记忆；本轮合计预算不够时不记忆。"""

    def test_results_are_remembered_by_path_size_and_mtime(self):
        path = self.write('a', lines(ordinary(), title('ai-title', 'one')))
        self.assertEqual(self.lookup().title, 'one')
        self.assertEqual(self.lookup().title, 'one')  # 新的取名器、同一进程：命中记忆
        self.assertEqual(len(self.opened), 1)
        with open(path, 'ab') as handle:
            handle.write(title('ai-title', 'two') + b'\n')
        self.assertEqual(self.lookup().title, 'two')  # 大小变了
        self.assertEqual(len(self.opened), 2)
        stamp = path.stat().st_mtime_ns
        path.write_bytes(path.read_bytes().replace(b'"two"', b'"owt"'))
        os.utime(path, ns=(stamp, stamp))
        self.assertEqual(self.lookup().title, 'two')  # 大小与修改时间都没变：照旧用记忆（已接受的限制）
        os.utime(path, ns=(stamp + 10**9, stamp + 10**9))
        self.assertEqual(self.lookup().title, 'owt')  # 修改时间变了
        self.assertEqual(len(self.opened), 3)

    def test_the_memo_key_includes_the_size(self):
        # 审计 Fable F15：修改时间不变、大小变了也要重读
        path = self.write('a', lines(ordinary(), title('ai-title', 'one')))
        self.assertEqual(self.lookup().title, 'one')
        stamp = path.stat().st_mtime_ns
        with open(path, 'ab') as handle:
            handle.write(title('ai-title', 'two') + b'\n')
        os.utime(path, ns=(stamp, stamp))
        self.assertEqual(self.lookup().title, 'two')

    def test_the_memo_is_bounded(self):
        # 审计 Fable F18：满了整体清空，条数不超过上限
        with patch.object(T, 'MAX_MEMO', 2):
            for index in range(3):
                sid = f'{index:08d}-2222-4333-8444-555555555555'
                self.write('a', lines(title('ai-title', f't{index}', sid)), sid=sid)
                self.assertEqual(self.lookup(sid).title, f't{index}')
                self.assertLessEqual(len(T._MEMO), 2)

    def test_a_group_cut_by_the_round_budget_is_not_remembered(self):
        # 审计 Fable P3-1 / r1b：本轮剩余预算切在 custom-title 与 agent-name 之间 → 只读到半组，不记忆，
        # 下一轮预算充足时取到完整结果
        tail = b'\n' + title('agent-name', 'mine') + b'\n' + ordinary('tail') + b'\n'
        self.write('a', ordinary() + b'\n' + title('custom-title', 'mine') + tail)
        cut = T.TitleReader(self.opener, budget=len(tail) + 4).lookup(self.root, SID)
        self.assertEqual(cut, T.TitleResult(None, 'no_title_record'))
        self.assertEqual(self.lookup(), T.TitleResult('mine', 'found_custom'))

    def test_results_cut_by_the_file_budget_are_remembered(self):
        # §99 r1b：只被单文件 1 MiB 截断的结果只取决于文件内容与固定上限，文件不变时第二轮不重读。
        # 两种都记：1 MiB 切在组中间（取到组内较旧那类，已接受限制）与 1 MiB 内找不到标题（budget_exhausted）
        agent = title('agent-name', 'mine')
        suffix_length = T.FILE_BUDGET_BYTES - 3 - (1 + len(agent) + 1) - 1
        suffix = ordinary(size=suffix_length - len(ordinary())) + b'\n'
        self.write('a', ordinary() + b'\n' + title('custom-title', 'mine') + b'\n' + agent + b'\n' + suffix)
        for _round in (1, 2):
            self.assertEqual(self.lookup(), T.TitleResult(None, 'no_title_record'))
            self.assertEqual(len(self.opened), 1)
        self.assertEqual(sum(item.consumed for item in self.readers), T.FILE_BUDGET_BYTES)
        self.write('a', lines(title('ai-title', 'far'), *filler(T.FILE_BUDGET_BYTES + 4096)))
        for _round in (1, 2):
            self.assertEqual(self.lookup(), T.TitleResult(None, 'budget_exhausted'))
            self.assertEqual(len(self.opened), 2)
        self.assertEqual(sum(item.consumed for item in self.readers), 2 * T.FILE_BUDGET_BYTES)

    def test_the_round_budget_is_shared_and_exhaustion_is_not_remembered(self):
        second = '22222222-2222-4333-8444-555555555555'
        self.write('a', lines(ordinary(), title('ai-title', 'first'), *filler(600 * 1024)))
        self.write('a', lines(ordinary(), title('ai-title', 'second', second), *filler(600 * 1024)), sid=second)
        reader = T.TitleReader(self.opener, budget=T.FILE_BUDGET_BYTES)
        self.assertEqual(reader.lookup(self.root, SID).title, 'first')
        self.assertEqual(reader.lookup(self.root, second), T.TitleResult(None, 'budget_exhausted'))
        self.assertLessEqual(sum(item.consumed for item in self.readers), T.FILE_BUDGET_BYTES)
        self.assertEqual(T.TitleReader(self.opener).lookup(self.root, second).title, 'second')  # 下一轮重读


class ApplyAndCountTests(unittest.TestCase):
    """接入端点：取到标题按 §91.3 投影作主名；退回保留注册名；诊断只出闭集码与数字。"""

    def setUp(self):
        T._MEMO.clear()
        self.addCleanup(T._MEMO.clear)
        temporary = TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        (self.root / 'projects' / 'p').mkdir(parents=True)

    def applied(self, data: bytes | None, *, registry: str = 'repo-32'):
        if data is not None:
            (self.root / 'projects' / 'p' / f'{SID}.jsonl').write_bytes(data)
        T._MEMO.clear()
        item = endpoint(ref(Provider.CLAUDE, SID), name=registry)
        return T.TitleReader(plain_open).apply(item, self.root)

    def test_a_title_replaces_the_registry_name(self):
        item = self.applied(lines(title('ai-title', 'Fix login bug')))
        self.assertEqual((item.name, item.name_source, item.name_origin),
                         ('Fix login bug', name_source('Fix login bug'), 'found_ai'))

    def test_a_fallback_keeps_the_registry_name_as_a_known_source(self):
        item = self.applied(None)
        self.assertEqual((item.name, item.name_source, item.name_origin),
                         ('repo-32', name_source('repo-32'), 'no_record_file'))
        self.assertEqual(item.name_source.state, 'named')

    def test_long_titles_follow_the_91_truncation(self):
        long = '长' * 100
        item = self.applied(lines(title('custom-title', long)))
        self.assertEqual((item.name, item.name_source), (long[:80], name_source(long, limit=80)))
        self.assertTrue(item.name_source.truncated)
        self.assertFalse(copyable(item.name_source))

    def test_titles_with_characters_a_consumer_alters_are_kept_but_escaped(self):
        for value in ('a\u202eb', 'zero\u200bwidth', 'tab\there'):
            with self.subTest(value=value):
                item = self.applied(lines(title('ai-title', value)))
                self.assertEqual(item.name_source, name_source(value))
                self.assertFalse(copyable(item.name_source))
                shown = display_text(item.name_source)
                self.assertIsNotNone(shown)
                self.assertTrue(all(ord(char) >= 0x20 and char not in '\u202e\u200b' for char in shown or ''))

    def test_counts_hold_only_closed_codes_and_numbers(self):
        def claude(index: int, origin: str | None):
            return replace(endpoint(ref(Provider.CLAUDE, f'{index:08d}-2222-4333-8444-555555555555'), name='n'),
                             name_origin=origin)
        items = [claude(1, 'found_ai'), claude(2, 'found_custom'), claude(3, 'no_record_file'),
                 claude(4, 'no_record_file'), claude(5, 'bad_value'), claude(6, None), claude(7, '/home/u/secret'),
                 replace(endpoint(ref(Provider.CODEX, 'thread')), name_origin='found_ai')]
        counts = T.counts(items)
        self.assertEqual(counts, {'found': 2, 'fallback': {'bad_value': 1, 'no_record_file': 2}})
        self.assertEqual(T.counts([]), {'found': 0, 'fallback': {}})

    def test_reason_codes_are_a_closed_set(self):
        self.assertEqual(T.REASONS, frozenset({
            'found_custom', 'found_ai', 'no_record_file', 'multiple_files', 'not_regular', 'unreadable',
            'budget_exhausted', 'no_title_record', 'session_mismatch', 'bad_value', 'bad_session_id',
            'directory_limit'}))
        self.assertTrue(all(code.isascii() and code.replace('_', '').isalpha() for code in T.REASONS))


@unittest.skipUnless(POSIX, POSIX_ONLY)
class LinuxSharedReadTests(unittest.TestCase):
    """Linux 平台层只读打开：O_NOFOLLOW、O_NONBLOCK，非普通文件报 not_regular，按偏移读不受文件位置影响。"""

    def setUp(self):
        from agentstatus_bridge.platforms.linux.files import open_shared_read
        self.open = open_shared_read
        temporary = TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)

    def test_reads_at_offsets_and_reports_the_size(self):
        path = self.root / 'r.jsonl'
        path.write_bytes(b'0123456789')
        with self.open(path) as reader:
            self.assertEqual((reader.size, reader.read_at(6, 4), reader.read_at(0, 3), reader.read_at(8, 10)),
                             (10, b'6789', b'012', b'89'))

    def test_opening_a_fifo_never_blocks(self):
        # 审计 Fable L3：去掉 O_NONBLOCK 时这里以断言失败结束而不是挂起
        fifo = self.root / 'fifo'
        os.mkfifo(fifo)
        outcome: list[object] = []

        def attempt() -> None:
            try:
                with self.open(fifo):
                    outcome.append('opened')
            except OSError as error:
                outcome.append(error.args)
        worker = threading.Thread(target=attempt, daemon=True)
        worker.start()
        worker.join(2)
        if worker.is_alive():
            os.close(os.open(fifo, os.O_WRONLY | os.O_NONBLOCK))  # 放开阻塞中的读端，再判失败
            worker.join(2)
            self.fail('opening a FIFO blocked')
        self.assertEqual(outcome, [('not_regular',)])

    def test_links_fifos_and_directories_are_refused(self):
        target = self.root / 'target'
        target.write_bytes(b'x')
        os.symlink(target, self.root / 'link')
        with self.assertRaises(OSError):
            with self.open(self.root / 'link'):
                pass
        # FIFO 由 test_opening_a_fifo_never_blocks 覆盖（带超时）；这里不再直接打开，免得去掉 O_NONBLOCK 时整模块挂起
        with self.assertRaises(OSError) as caught:
            with self.open(self.root):
                pass
        self.assertEqual(caught.exception.args, ('not_regular',))


class TranscriptGuardTests(unittest.TestCase):
    """测试守卫：任何用例都不能打开或列出真实 ~/.claude、~/.rec 下 projects 里的会话记录。"""

    def test_the_guard_covers_both_account_roots(self):
        home = os.path.normcase(os.path.abspath(os.path.expanduser('~')))
        self.assertIn(os.path.join(home, '.claude'), ROOTS)
        self.assertIn(os.path.join(home, '.rec'), ROOTS)
        check(os.path.join(home, '.claude', 'sessions', '1.json'), ROOTS)  # 不是 projects：不拦
        check('/var/tmp/x/projects/a.jsonl', ROOTS)
        with self.assertRaises(RealTranscriptAccess):
            check(os.path.join(home, '.rec', 'claude', 'accounts', '1', 'config', 'projects', 'a', 'b.jsonl'), ROOTS)

    def test_the_guard_fires_before_the_product_fallback(self):
        # 用不存在的账号目录：守卫若失效，最多得到 FileNotFoundError，不会读到真实记录
        absent = Path(os.path.expanduser('~')) / '.rec' / 'claude' / 'accounts' / 'agentstatus-test-absent' / 'config'
        with self.assertRaises(RealTranscriptAccess):
            T.TitleReader(plain_open).lookup(absent, SID)
        projects = Path(os.path.expanduser('~')) / '.claude' / 'projects' / 'agentstatus-test-absent'
        for name, call in (('open', lambda: open(projects / 'x.jsonl', 'rb')), ('os.listdir', lambda: os.listdir(projects))):
            with self.subTest(event=name):
                try:
                    call()
                except RealTranscriptAccess:
                    continue
                except OSError:
                    self.fail(f'guard did not intercept {name}')
                self.fail(f'guard did not intercept {name}')


if __name__ == '__main__':
    unittest.main()
