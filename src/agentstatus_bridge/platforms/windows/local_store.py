"""Pure local wait: mode=ro, no Store migrations, summary or worker revival."""
from contextlib import contextmanager, ExitStack
from collections.abc import Iterator
from pathlib import Path
import sqlite3
from typing import Any

from ...store import Store, StoreError, DB_NAME, SCHEMA_VERSION
from ..factory import get_platform
from .files import WindowsPaths
from .codex_sql import pinned_file


class _LegacyRow(sqlite3.Row):
    """v1 had no options columns; project their original empty-options meaning.

    No ALTER, temp view or database write; all other missing fields still fail.
    """
    def __getitem__(self, key: Any) -> Any:
        if key == 'options' and key not in self.keys():
            return '{}'
        return super().__getitem__(key)


@contextmanager
def open_store() -> Iterator[Store]:
    files = get_platform().files
    if not isinstance(files, WindowsPaths):
        raise StoreError('store_unavailable')
    try:
        with ExitStack() as stack:
            root = files.state_dir()
            stack.enter_context(files.lease(root))
            path = root / DB_NAME
            for suffix in ('', '-wal', '-shm', '-journal'):
                try:
                    stack.enter_context(pinned_file(files, Path(str(path)+suffix)))
                except OSError as error:
                    if suffix and getattr(error, 'winerror', None) in (2, 3):
                        continue
                    raise
            connection = sqlite3.connect(files.sqlite_uri(path, escaped=True), uri=True,
                                         timeout=0.05, isolation_level=None)
            stack.callback(connection.close)
            connection.execute('PRAGMA query_only=ON')
            version = connection.execute('PRAGMA user_version').fetchone()[0]
            if version > SCHEMA_VERSION:
                raise StoreError('schema_too_new')
            store = Store(connection)
            if version < 2:
                connection.row_factory = _LegacyRow
            columns = {r[1] for r in connection.execute('PRAGMA table_info(native_withdrawals)')}
            store._withdrawals_ready = {'owner_pid_namespace', 'state', 'reason'} <= columns
            yield store
    except (OSError, sqlite3.Error) as error:
        raise StoreError('store_unavailable') from error
