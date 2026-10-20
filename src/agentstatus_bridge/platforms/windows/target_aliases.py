"""Owner-authored names, not discovery, caller authority or persistent labels."""
from __future__ import annotations

from dataclasses import dataclass, field
import json
import math
from pathlib import Path
import re
import time
from typing import Any

from ...transports.codex_native import native_id
from .codex_sql import pinned_file
from .files import WindowsPaths

LIMIT, MAX_BYTES, MAX_AGE = 256, 65536, 30 * 86400
ALIAS = re.compile(r'[A-Za-z][A-Za-z0-9._-]{0,63}')
ID_SHAPED = re.compile(r'[0-9a-fA-F-]{8,36}')
ROOT = re.compile(r'[0-9a-f]{64}')


@dataclass(frozen=True)
class AliasSet:
    names: dict[str, str]
    reason: str = 'ok'
    rows: tuple[dict[str, Any], ...] = field(default=(), repr=False)
    unavailable: tuple[str, ...] = ()

    def bind(self, root_identity: str, daemon: tuple[int, str], eligible: set[str]) -> AliasSet:
        names = {r['alias']: r['threadId'] for r in self.rows
                 if r['alias'] in self.names and r['rootIdentity'] == root_identity
                 and r['threadId'] in eligible}
        return AliasSet(names, self.reason, self.rows, tuple(r['alias'] for r in self.rows if r['alias'] not in names))


def valid(row: object) -> bool:
    base = {'alias', 'threadId', 'rootIdentity'}
    if not isinstance(row, dict) or set(row) not in (base, base | {'expiresAt'}, base | {'expiresAt', 'daemonPid', 'daemonBirth'}):
        return False
    if 'daemonPid' in row and (type(row['daemonPid']) is not int or not 0 < row['daemonPid'] < 2**32
            or not isinstance(row['daemonBirth'], str) or not row['daemonBirth'].isascii()
            or not row['daemonBirth'].isdecimal() or not 0 < int(row['daemonBirth']) < 2**64):
        return False
    return (isinstance(row['alias'], str) and ALIAS.fullmatch(row['alias']) is not None
            and ID_SHAPED.fullmatch(row['alias']) is None
            and native_id(row['threadId']) == row['threadId']
            and row['threadId'] is not None
            and isinstance(row['rootIdentity'], str) and ROOT.fullmatch(row['rootIdentity']) is not None
            and ('expiresAt' not in row or type(row['expiresAt']) in (int, float)
                 and 0 < row['expiresAt'] <= 253402300799 and math.isfinite(row['expiresAt'])))


class AliasFile:
    def __init__(self, files: WindowsPaths, root: Path) -> None:
        self.files, self.root = files, root / 'target-aliases'

    def load(self, root_identity: str, now: float | None = None) -> AliasSet:
        now = time.time() if now is None else now
        try:
            with self.files.lease(self.root), pinned_file(self.files, self.root / 'codex.json'):
                with (self.root / 'codex.json').open('rb') as stream:
                    raw = stream.read(MAX_BYTES + 1)
                if len(raw) > MAX_BYTES:
                    raise ValueError('alias_limit')
                doc = json.loads(raw)
                rows = self._rows(doc)
                return AliasSet({r['alias']: r['threadId'] for r in rows
                                 if r['rootIdentity'] == root_identity
                                 and ('expiresAt' not in r or now < r['expiresAt'] <= now+MAX_AGE)},
                                rows=tuple(rows))
        except OSError as error:
            if getattr(error, 'winerror', None) in (2, 3):
                return AliasSet({})
            return AliasSet({}, 'alias_store_unverified')
        except (ValueError, TypeError):
            return AliasSet({}, 'alias_store_unverified')

    @staticmethod
    def _rows(doc: object) -> list[dict[str, Any]]:
        if (not isinstance(doc, dict) or set(doc) != {'schema', 'aliases'}
                or type(doc['schema']) is not int or doc['schema'] != 1
                or not isinstance(doc['aliases'], list) or len(doc['aliases']) > LIMIT
                or any(not valid(row) for row in doc['aliases'])):
            raise ValueError('alias_invalid')
        rows = doc['aliases']
        if len({r['alias'] for r in rows}) != len(rows):
            raise ValueError('alias_duplicate')
        return rows

    def replace(self, rows: list[dict[str, Any]], *, now: float | None = None) -> None:
        """Explicit whole-file owner update; CLI read/modify/write holds its lock.

        Last explicit replacement wins; no read-modify-write race or auto-renewal.
        Expired entries are collected only here. Empty rows clears all aliases.
        """
        now = time.time() if now is None else now
        checked = self._rows({'schema': 1, 'aliases': rows})
        if any(r.get('expiresAt', now) > now + MAX_AGE for r in checked):
            raise ValueError('alias_expiry_invalid')
        doc = {'schema': 1, 'aliases': [r for r in checked if 'expiresAt' not in r or r['expiresAt'] > now]}
        raw = json.dumps(doc, ensure_ascii=True, separators=(',', ':')).encode('utf-8')
        if len(raw) > MAX_BYTES:
            raise ValueError('alias_limit')
        self.files.atomic_write(self.root, raw, name='codex.json', prefix='.alias.')
