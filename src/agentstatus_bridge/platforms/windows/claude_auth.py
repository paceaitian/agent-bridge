"""W3 IPC-only authentication files. No login credentials, fallback, or key logs."""
from __future__ import annotations

from contextlib import contextmanager
import ctypes as C
import hashlib
import json
from pathlib import Path
import re
from collections.abc import Iterator
from typing import Any

from . import abi as A
from .files import WindowsPaths

PIPE = re.compile(r'\\\\\.\\pipe\\(?:LOCAL\\)?cc-msg-[0-9a-f]{32}', re.IGNORECASE)
TOKEN = re.compile(r'[0-9a-f]{32}')
MAX_JSON = 64 * 1024


def key_name(pid: int, pipe: str) -> str:
    if type(pid) is not int or not 0 < pid < 2**32 or not PIPE.fullmatch(pipe):
        raise OSError('claude_key_identity_invalid')
    return f'{pid}.{hashlib.sha256(pipe.lower().encode()).hexdigest()}.key'


def generation(value: object, birth: str) -> bool:
    return type(value) in (str, int) and str(value) == birth


def _object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('duplicate_key')
        result[key] = value
    return result


class PeerFiles:
    """External roots are never created/repaired; only our CREATE_NEW leaf is writable."""
    def __init__(self, files: WindowsPaths, sessions: Path | None = None) -> None:
        self.files, self.api = files, files.api
        self.sessions = sessions if sessions is not None else files.claude_sessions_dir()

    @classmethod
    def from_root(cls, files: WindowsPaths, identity: str | None,
                  *, sessions: tuple[Path, ...] | None = None) -> PeerFiles:
        """Find the existing pinned root; never substitute a different root."""
        for path in sessions if sessions is not None else files.claude_sessions_dirs().roots:
            candidate = cls(files, path)
            try:
                with candidate.root() as root:
                    if root == identity:
                        return candidate
            except OSError:
                continue
        raise OSError('claude_root_changed')

    @contextmanager
    def root(self) -> Iterator[str]:
        with self.files.external_directory(self.sessions.parent) as config, self.files.external_directory(self.sessions) as directory:
            raw = self.api.current_token().sid + repr((config, directory)).encode('ascii')
            yield hashlib.sha256(b'W3:claude-root:v1\0' + raw).hexdigest()

    def identity(self, handle: int) -> tuple[int, str]:
        info = self.api.file_info(handle)
        if info.attributes & 0x10 or info.links != 1:
            raise OSError('claude_file_untrusted')
        identity = A.FILE_ID_INFO()
        self.api.check(self.api.k.GetFileInformationByHandleEx(handle, 18, C.byref(identity), C.sizeof(identity)))
        return int(identity.volume), bytes(identity.file_id).hex()

    def read(self, name: str) -> dict[str, Any]:
        if not re.fullmatch(r'[1-9][0-9]{0,9}(?:\.[0-9a-f]{64}\.key|\.json)', name):
            raise OSError('claude_file_name_invalid')
        with self.root(), self.api.owned(self.api.open_file(
                str(self.sessions / name), read_data=True, sharing=7)) as handle:
            first = self.identity(handle)
            raw = self.api.read(handle, MAX_JSON + 1)
            if len(raw) > MAX_JSON or self.identity(handle) != first:
                raise OSError('claude_file_changed')
            try:
                value = json.loads(raw, object_pairs_hook=_object)
            except (ValueError, UnicodeError):
                raise OSError('claude_file_invalid') from None
            if not isinstance(value, dict):
                raise OSError('claude_file_invalid')
            return value

    def token(self, pid: int, pipe: str, birth: str, record: dict[str, Any]) -> str:
        value = self.read(key_name(pid, pipe))
        token = value.get('peerToken')
        if (not isinstance(token, str) or not TOKEN.fullmatch(token)
                or 'procStartFt' in value and not generation(value['procStartFt'], birth)
                or 'procStart' in value and 'procStart' in record and value['procStart'] != record['procStart']):
            raise OSError('claude_peer_key_unverified')
        return token

    def open_own(self, name: str, *, create: bool) -> int:
        with self.api.private_attributes(inherit=False) as attributes:
            # DELETE | READ_CONTROL | READ_ATTRIBUTES; GENERIC_WRITE only for CREATE_NEW.
            return self.api.handle(self.api.k.CreateFileW(A.wide(str(self.sessions / name)),
                0x30080 | (0x40000000 if create else 0), 0 if create else 7,
                C.byref(attributes), 1 if create else 3, 0x00200080, None))

    def delete(self, handle: int) -> None:
        flag = C.c_ubyte(1)  # FILE_DISPOSITION_INFO BOOLEAN, not a four-byte BOOL.
        self.api.check(self.api.k.SetFileInformationByHandle(handle, 4, C.byref(flag), 1))


class OwnKey:
    """Own registration only; cleanup never reads a credential or deletes a replacement."""
    def __init__(self, files: PeerFiles, pid: int, pipe: str, birth: str, token: str) -> None:
        if not TOKEN.fullmatch(token) or not re.fullmatch(r'[1-9][0-9]{0,19}', birth):
            raise OSError('claude_key_fields_invalid')
        self.files, self.name = files, key_name(pid, pipe)
        self._payload = (json.dumps({'peerToken': token, 'procStartFt': birth}, separators=(',', ':')) + '\n').encode()
        self._identity: tuple[int, str] | None = None
        self._root: str | None = None
        self._handle: int | None = None
        self._created, self._cleaned = False, False

    def publish(self) -> None:
        if self._created or self._cleaned:
            raise OSError('claude_key_already_used')
        with self.files.root() as root:
            self._root = root
            self._handle = self.files.open_own(self.name, create=True)
            self._created = True
            self._identity = self.files.identity(self._handle)
            self.files.api.check_private(self._handle, protected=True)
            self.files.api.write(self._handle, self._payload)
            self.files.api.flush(self._handle)
            self.files.api.close(self._handle)
            self._handle, self._payload = None, b''

    def close(self) -> None:
        if self._cleaned:
            return
        self._cleaned, self._payload = True, b''
        if not self._created:
            return
        handle, self._handle = self._handle, None
        try:
            if handle is None:
                with self.files.root() as root:
                    if root != self._root:
                        raise OSError('claude_key_root_changed')
                    try:
                        handle = self.files.open_own(self.name, create=False)
                    except OSError as error:
                        if getattr(error, 'winerror', None) in (2, 3):
                            return
                        raise
                    if self.files.identity(handle) != self._identity:
                        raise OSError('claude_key_identity_changed')
                    self.files.delete(handle)
            else:
                self.files.delete(handle)  # Still the handle returned by our own CREATE_NEW.
        finally:
            if handle is not None:
                self.files.api.close(handle)
