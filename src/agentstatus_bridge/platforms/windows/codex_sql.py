"""W2 read-only SQL evidence; no rollout/queue body, no unpinned external path."""
from __future__ import annotations

from collections.abc import Callable, Sequence
from contextlib import ExitStack
import json
from pathlib import Path
import sqlite3

from ...model import NameSource
from ...transports.codex_native import native_id, project_thread, ThreadMetadata
from .files import WindowsPaths
from .private_file import pinned_file
from .thread_names import names, fields_valid, native_source

STATE_NAME = 'state_5.sqlite'  # rust-v0.162.1 state/src/sqlite.rs:38
SQL_TIMEOUT = 0.05


def source_class(value: object, *, sql: bool = False) -> str:
    """Closed diagnostic only; never retain custom labels or source payloads."""
    if isinstance(value, str) and len(value) > 4096:
        return 'other'
    if sql and isinstance(value, str) and value not in {'cli', 'vscode', 'exec', 'mcp'}:
        try:
            value = json.loads(value)
        except ValueError:
            return 'other'
    if isinstance(value, str) and value in {'cli', 'vscode', 'exec', 'mcp', 'appServer'}:
        return value
    if isinstance(value, dict) and len(value) == 1:
        if 'internal' in value:
            return 'internal'
        if 'custom' in value:
            return 'custom'
        sub = value.get('subagent' if sql else 'subAgent')
        if isinstance(sub, str) and sub in {'review', 'compact', 'memory_consolidation'}:
            return 'subAgent.' + sub
        if isinstance(sub, dict) and len(sub) == 1:
            return 'subAgent.thread_spawn' if 'thread_spawn' in sub else 'subAgent.other'
    return 'other'


def sql_source(thread: str, source: object, parent: object) -> ThreadMetadata:
    """Storage snake_case differs from API camelCase; unknown never means root."""
    if not isinstance(source, str) or len(source) > 4096:
        return ThreadMetadata('unknown')
    if source in {'cli', 'vscode', 'exec', 'mcp'}:
        value: object = 'appServer' if source == 'mcp' else source
    else:
        try:
            value = json.loads(source)
        except ValueError:
            return ThreadMetadata('unknown')
        if not isinstance(value, dict) or len(value) != 1:
            return ThreadMetadata('unknown')
        if 'internal' in value:
            return ThreadMetadata('internal')
        if 'subagent' in value:
            value = {'subAgent': value['subagent']}
    return project_thread({'id': thread, 'source': value, 'parentThreadId': parent}, thread)


def read_classes(files: WindowsPaths, root: Path, threads: Sequence[str],
                 deadline: float, clock: Callable[[], float], *,
                 labels: dict[str, tuple[str, str]] | None = None,
                 sources: dict[str, str] | None = None,
                 name_sources: dict[str, NameSource] | None = None) -> dict[str, ThreadMetadata]:
    if not threads:
        return {}
    records: dict[str, ThreadMetadata] = {}
    try:
        with files.external_directory(root), ExitStack() as stack:
            path = root / STATE_NAME
            for suffix in ('', '-wal', '-shm', '-journal'):
                try:
                    stack.enter_context(pinned_file(files, Path(str(path) + suffix), external=True, external_sql_read=True))
                except OSError as error:
                    if suffix and getattr(error, 'winerror', None) in (2, 3):
                        continue
                    raise
            if clock() >= deadline:
                return {}
            db = sqlite3.connect(files.sqlite_uri(path, escaped=True), uri=True,
                                 timeout=min(SQL_TIMEOUT, max(0.0, deadline-clock())))
            stack.callback(db.close)
            db.execute('PRAGMA query_only=ON')
            db.set_progress_handler(lambda: int(clock() >= deadline), 100)
            columns = {r[1] for r in db.execute('PRAGMA table_info(threads)')} if labels is not None else set()
            for offset in range(0, len(threads), 256):
                if clock() >= deadline:
                    return {}
                wanted = threads[offset:offset+256]
                marks = ','.join('?' for _ in wanted)
                rows = db.execute('SELECT t.id, t.source, e.parent_thread_id FROM threads AS t '
                                  'LEFT JOIN thread_spawn_edges AS e ON e.child_thread_id=t.id '
                                  f'WHERE t.id IN ({marks})', tuple(wanted)).fetchall()
                if labels is not None and {'name', 'cwd', 'history_mode'} <= columns:
                    for key, name, cwd, mode in db.execute(f'SELECT id,name,cwd,history_mode FROM threads WHERE id IN ({marks})', tuple(wanted)):
                        # Legacy names use title/index upstream; reading title
                        # here would expose first-message content. Ask native.
                        if key in wanted and mode == 'paginated' and fields_valid({'name': name, 'cwd': cwd}):
                            labels[key] = names({'name': name, 'cwd': cwd})
                            fact = native_source({'name': name, 'cwd': cwd})
                            if name_sources is not None and fact is not None:
                                name_sources[key] = fact  # 与 labels 同行同库，原文另存（§91.3）
                for thread, source, parent in rows:
                    key = native_id(thread)
                    if key is None or key not in wanted:
                        raise ValueError('unexpected_sql_id')
                    if key in records:
                        records[key] = ThreadMetadata('conflict')
                    else:
                        records[key] = sql_source(key, source, parent)
                    if sources is not None:
                        sources[key] = source_class(source, sql=True)
    except (OSError, sqlite3.Error, ValueError):
        if labels is not None:
            labels.clear()
        if sources is not None:
            sources.clear()
        if name_sources is not None:
            name_sources.clear()
        return {}  # Native may supply evidence; SQL failure cannot establish a root.
    return records
