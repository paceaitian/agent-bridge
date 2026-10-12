"""Windows F：本地NTFS、创建即DACL、根和祖先句柄租约；无chmod退路。"""
from __future__ import annotations
from contextlib import contextmanager, ExitStack
from collections.abc import Iterator
import hashlib
import ntpath
import os
from pathlib import Path
import socket
import shutil
from typing import Any
import uuid

from ..path_values import STATE_DIR_ENV, BINDING_ENV, DEVICE_ENV, DEVICE_UNSAFE, DEVICE_CHARS
from ..policy import CLAUDE_SYSTEM_DIRS


def local_path(path: Path) -> Path:
    raw = str(path)
    drive, tail = ntpath.splitdrive(raw)
    reserved={'CON','PRN','AUX','NUL','CONIN$','CONOUT$'} | {prefix+n for prefix in ('COM','LPT') for n in '123456789¹²³'}
    if (not path.is_absolute() or raw.startswith(('\\\\', '//')) or '\0' in raw
            or ':' in tail or '..' in path.parts or any(p.endswith(('.', ' ')) for p in path.parts if p not in {'.', '/', drive+'\\'})
            or any(p.split('.',1)[0].upper() in reserved for p in path.parts)
            or (drive and (len(drive) != 2 or drive[1] != ':'))):
        raise OSError('windows_path_unsupported')
    return path


class WindowsPaths:
    def __init__(self, api: Any) -> None:
        self.api = api

    def state_base(self) -> Path:
        return Path(self.api.local_app_data())

    def state_dir(self) -> Path:
        return local_path(Path(os.environ[STATE_DIR_ENV]) if STATE_DIR_ENV in os.environ
                          else self.state_base() / 'agent-bridge')

    def state_dir_source(self) -> str:
        return 'integration' if os.environ.get(BINDING_ENV) else ('env' if STATE_DIR_ENV in os.environ else 'default')

    def device_name(self) -> str:
        # Avoid platform.uname()/WMI's process-wide COM/RPC initialization.
        name = os.environ.get(DEVICE_ENV, '').strip() or socket.gethostname().split('.', 1)[0]
        cleaned = DEVICE_UNSAFE.sub('-', name).strip('-')[:DEVICE_CHARS].strip('-')
        return cleaned or 'local'

    def uid(self) -> int:
        raise OSError('windows_uid_not_applicable')

    def codex_home(self) -> Path:
        raise OSError('windows_provider_not_enabled')
    grok_home = claude_sessions_dir = codex_home

    def codex_sqlite_home(self) -> None:
        return None

    @contextmanager
    def lease(self, path: Path, *, create: bool = False) -> Iterator[None]:
        path = local_path(path)
        # Every path component is pinned without delete sharing; no reparse shortcuts.
        with ExitStack() as stack:
            for component in (*reversed(path.parents), path):
                try:
                    handle = self.api.open_file(str(component), directory=True)
                except OSError as error:
                    if not create or getattr(error, 'winerror', None) not in (2, 3):
                        raise
                    self.api.create_directory(str(component))
                    handle = self.api.open_file(str(component), directory=True)
                stack.callback(self.api.close, handle)
                info = self.api.file_info(handle)
                if not info.attributes & 0x10:
                    raise OSError('windows_directory_required')
                self.api.check_ntfs(handle)
                if component == path:
                    self.api.check_private(handle, protected=True)
            yield

    def ensure_private_dir(self, path: Path) -> Path:
        with self.lease(path, create=True):
            return path

    def validate_file(self, path: Path) -> tuple[int, int, int]:
        return self._validate_file(path, af_unix=False)

    def validate_socket(self, path: Path) -> tuple[int, int, int]:
        return self._validate_file(path, af_unix=True)

    def _validate_file(self, path: Path, *, af_unix: bool) -> tuple[int, int, int]:
        with self.lease(path.parent), self.api.owned(self.api.open_file(str(local_path(path)))) as handle:
            self.api.check_private(handle)
            info = self.api.file_info(handle, af_unix=af_unix)
            if info.attributes & 0x10 or info.links != 1:
                raise OSError('windows_file_untrusted')
            return int(info.volume), int(info.index_high), int(info.index_low)

    def prepare_database(self, path: Path) -> None:
        with self.lease(path.parent, create=True):
            with self.api.owned(self.api.open_file(str(path), create=True, write=True)) as handle:
                self.api.check_private(handle)
                self.api.file_info(handle)
            self.validate_database(path)

    def validate_database(self, path: Path) -> None:
        for suffix in ('', '-wal', '-shm', '-journal'):
            try:
                self.validate_file(Path(str(path) + suffix))
            except OSError as error:
                if suffix and getattr(error, 'winerror', None) in (2, 3):
                    continue
                raise

    def append_log(self, path: Path, payload: bytes, limit: int) -> None:
        with self.lease(path.parent, create=True):
            old = b''
            try:
                self.validate_file(path)
                with path.open('rb') as stream:
                    old = stream.read(limit + 1)
            except FileNotFoundError:
                pass
            except OSError as error:
                if getattr(error, 'winerror', None) not in (2, 3):
                    raise
            self.atomic_write(path.parent, (old if len(old) <= limit else b'') + payload, name=path.name, prefix='.log.')

    def atomic_write(self, directory: Path, payload: bytes, *, name: str, prefix: str) -> None:
        if Path(name).name != name or ntpath.basename(name) != name or any(c in name+prefix for c in ':\\/\0'):
            raise OSError('windows_path_invalid')
        with self.lease(directory, create=True):
            target = directory / name
            try:
                self.validate_file(target)
            except OSError as error:
                if getattr(error, 'winerror', None) not in (2, 3):
                    raise
            tmp = directory / (prefix + uuid.uuid4().hex)
            created = False
            try:
                with self.api.owned(self.api.open_file(str(tmp), write=True, exclusive_create=True)) as handle:
                    created = True
                    self.api.check_private(handle)
                    self.api.file_info(handle)
                    self.api.write(handle, payload)
                    self.api.flush(handle)
                self.api.replace(str(tmp), str(target))  # no unlink of old target
                created = False
                self.validate_file(target)
            finally:
                if created:
                    self.api.delete(str(tmp))

    def present(self, path: Path) -> bool:
        try:
            path.lstat()
            return True
        except FileNotFoundError:
            return False
        except OSError:
            return True

    def policy_dir(self, provider: str) -> Path:
        if provider != 'claude':
            raise OSError('windows_policy_unverified')
        return Path(str(CLAUDE_SYSTEM_DIRS['windows']))

    def sqlite_uri(self, path: Path, *, escaped: bool) -> str:
        return path.absolute().as_uri() + '?mode=ro'

    def root_identity(self, home: Path, sqlite_home: Path | None = None) -> str | None:
        # OS identity primitive only; not §69 qualification or provider root proof.
        try:
            values = []
            for path in (home, sqlite_home or home):
                with self.lease(path), self.api.owned(self.api.open_file(str(path), directory=True)) as handle:
                    info = self.api.file_info(handle)
                    values.append(f'{info.volume}:{info.index_high}:{info.index_low}')
            return hashlib.sha256(b'W1:windows:v1\0' + self.api.current_token().sid + b'\0' + '\0'.join(values).encode()).hexdigest()
        except OSError:
            return None

    def home_equal(self, reported: str, expected: Path) -> bool:
        return False  # W2 must choose provider data-root contract

    def socket_identity(self, target: Path) -> tuple[str, int, int, int]:
        volume, high, low = self.validate_socket(target)
        return 'windows-file-id', volume, high, low

    def which(self, name: str) -> str | None:
        return shutil.which(name)

    def realpath(self, path: str) -> str:
        return str(local_path(Path(path)))

    def mtime_ns(self, path: str) -> int:
        self.validate_file(Path(path))
        return Path(path).stat().st_mtime_ns
