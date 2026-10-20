"""Exact queue existence in the successful delivery's trusted SQL root."""
from contextlib import ExitStack
from pathlib import Path
import sqlite3
import time

from ...model import Attempt, Consumption
from ...transports.codex_native import native_id
from ..factory import get_platform
from .files import WindowsPaths
from .codex_sql import pinned_file


def state(attempt: Attempt) -> Consumption:
    files = get_platform().files
    item = attempt.provider_ref
    expected = attempt.options.get('codexDataRoot')
    if not isinstance(files, WindowsPaths) or native_id(item) != item or item is None or not expected:
        return Consumption.UNKNOWN
    try:
        home, sql_root = files.codex_home(), files.codex_sqlite_home()
        with ExitStack() as stack:
            stack.enter_context(files.external_directory(home))
            stack.enter_context(files.external_directory(sql_root or home))
            if files.root_identity(home, sql_root) != expected or attempt.target.data_root != expected:
                return Consumption.UNKNOWN
            path = (sql_root or home)/'queue_1.sqlite'
            for suffix in ('', '-wal', '-shm', '-journal'):
                try:
                    stack.enter_context(pinned_file(files, Path(str(path)+suffix), external=True, external_sql_read=True))
                except OSError as error:
                    if suffix and getattr(error, 'winerror', None) in (2, 3):
                        continue
                    raise
            db = sqlite3.connect(files.sqlite_uri(path, escaped=True), uri=True, timeout=0.05)
            stack.callback(db.close)
            db.execute('PRAGMA query_only=ON')
            deadline = time.monotonic()+1.0
            db.set_progress_handler(lambda:int(time.monotonic() >= deadline),100)
            row = db.execute('SELECT COUNT(*) FROM queued_items WHERE id = ?', (item,)).fetchone()
            if files.root_identity(home, sql_root) != expected:
                return Consumption.UNKNOWN
            if row is None or type(row[0]) is not int or row[0] not in (0, 1):
                return Consumption.UNKNOWN
            return Consumption.STILL_QUEUED if row[0] else Consumption.LEFT_QUEUE
    except (OSError, sqlite3.Error, ValueError):
        return Consumption.UNKNOWN
