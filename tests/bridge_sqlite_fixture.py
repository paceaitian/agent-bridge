"""Keep connections alive until teardown to prove explicit close, never GC."""
import sqlite3
from unittest.mock import patch


def require_closed_connections(case):
    original = sqlite3.connect
    connections = []

    def connect(*args, **kwargs):
        db = original(*args, **kwargs)
        connections.append(db)
        return db

    def check():
        unclosed = 0
        for db in connections:
            try:
                db.execute('SELECT 1')
            except sqlite3.ProgrammingError as error:
                case.assertIn('closed', str(error))
            else:
                unclosed += 1
            finally:
                db.close()  # failed witnesses must still clean their own fixture
        case.assertEqual(unclosed, 0, 'SQLite connections require explicit close, not transaction exit')

    replacement = patch.object(sqlite3, 'connect', side_effect=connect)
    replacement.start()
    case.addCleanup(replacement.stop)
    case.addCleanup(check)
