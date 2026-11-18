"""Windows F：本地NTFS、创建即DACL、根租约及本人自有对象权限恢复。"""
from __future__ import annotations
from contextlib import contextmanager, ExitStack
from collections.abc import Iterator
import hashlib
import json
import logging
import ntpath
import os
from pathlib import Path
import socket
import shutil
from typing import Any
import uuid
import time
from ..claude_roots import OVERRIDE, configured, unique, MAX_ROOTS, RootScan

from ..path_values import STATE_DIR_ENV, BINDING_ENV, DEVICE_ENV, DEVICE_UNSAFE, DEVICE_CHARS
from ..policy import CLAUDE_SYSTEM_DIRS

ACL_OBSERVATION = 'acl-repair.json'


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


class _HandleRead:
    """共享读打开的句柄：打开时的大小，按偏移读。"""

    def __init__(self, api: Any, handle: int, size: int) -> None:
        self._api, self._handle = api, handle
        self.size = size

    def read_at(self, offset: int, length: int) -> bytes:
        return self._api.read_at(self._handle, offset, length)


class WindowsPaths:
    def __init__(self, api: Any) -> None:
        self.api = api
        self.acl_repaired = False
        self._recording_repair = False
        self.repair_reasons: set[str] = set()
        self._logged_repairs: set[str] = set()

    def _owner_repair(self, handle: int, path: Path) -> str | None:
        owner = self.api.owner_kind(handle)
        if owner == 'self':
            return None
        # Only this application's state root and descendants; external reads
        # and other private fixtures keep the original owner requirement.
        if owner not in {'administrators', 'system'} or not local_path(path).is_relative_to(self.state_dir()):
            raise OSError('windows_owner_mismatch')
        return owner

    def ensure_private(self, handle: int, path: Path, *, protected: bool = False) -> None:
        """Only owned state, never external Codex/SQL/pipe permissions."""
        try:
            self.api.check_private(handle, protected=protected)
            return
        except OSError as error:
            if error.args != ('windows_acl_untrusted',):
                raise
        before = self.api.file_info(handle)  # rejects reparse before mutation
        if before.attributes & 0x10 or before.links != 1:
            raise OSError('windows_file_untrusted')
        self.api.check_ntfs(handle)
        owner = self._owner_repair(handle, path)
        with self.api.owned(self.api.open_file(str(path), metadata_only=True, write_dac=True,
                                             write_owner=owner is not None)) as repair:
            after = self.api.file_info(repair)
            if ((after.volume, after.index_high, after.index_low, after.links, after.attributes)
                    != (before.volume, before.index_high, before.index_low, 1, before.attributes)):
                raise OSError('windows_file_untrusted')
            self.api.check_ntfs(repair)
            if owner is not None:
                self.api.restore_owner(repair, owner)
                self._observe_repair('owner_' + owner)
            self.api.repair_private(repair)
        self._record_repair(path, reason='owner_' + owner if owner is not None else 'dacl')

    def _private_directory(self, handle: int, path: Path) -> int:
        """Takes ownership of handle, returning the verified replacement lease.

        Inheritable ACEs may propagate into existing unprotected children.
        Metadata-only access is not an exclusive sharing barrier (MS-FSA).
        Reacquire normal data access after repair; check FileId at both reopens.
        """
        current: int | None = handle
        try:
            try:
                self.api.check_private(handle, protected=True)
                return handle
            except OSError as error:
                if error.args != ('windows_acl_untrusted',):
                    raise
            def identity(h: int) -> tuple[int, int, int]:
                info = self.api.file_info(h)
                if not info.attributes & 0x10 or info.links != 1:
                    raise OSError('windows_directory_required')
                self.api.check_ntfs(h)
                return int(info.volume), int(info.index_high), int(info.index_low)
            before = identity(handle)
            owner = self._owner_repair(handle, path)
            self.api.close(handle)
            current = None
            with self.api.owned(self.api.open_file(str(path), directory=True, write_dac=True, sharing=7,
                                                  metadata_only=True, write_owner=owner is not None)) as repair:
                if identity(repair) != before:
                    raise OSError('windows_file_untrusted')
                if owner is not None:
                    self.api.restore_owner(repair, owner)
                    self._observe_repair('owner_' + owner)
                self.api.repair_private(repair, inherit=True)
            current = self.api.open_file(str(path), directory=True)
            assert current is not None
            if identity(current) != before:
                raise OSError('windows_file_untrusted')
            self.api.check_private(current, protected=True)
            self._record_repair(path, reason='owner_' + owner if owner is not None else 'dacl')
            return current
        except BaseException:
            if current is not None:
                self.api.close(current)
            raise

    def _observe_repair(self, reason: str) -> None:
        self.acl_repaired = True
        self.repair_reasons.add(reason)

    def _record_repair(self, path: Path, *, reason: str = 'dacl') -> None:
        self._observe_repair(reason)
        # Owner restoration alone is observable, but is not a completed DACL repair.
        if reason not in self._logged_repairs:
            logging.getLogger(__name__).warning('windows_private_acl_repaired reason=%s', reason)
            self._logged_repairs.add(reason)
        # Content-free, persistent observation; never asserts the old bytes were
        # trustworthy. Non-state fixture paths only set the process observation.
        if (not self._recording_repair and path.is_relative_to(self.state_dir())
                and path != self.state_dir() / ACL_OBSERVATION):
            self._recording_repair = True
            try:
                payload = json.dumps({'previousAclUntrusted': True, 'reasons': sorted(self.repair_reasons)}).encode() + b'\n'
                self.atomic_write(self.state_dir(), payload,
                                  name=ACL_OBSERVATION, prefix='.acl.')
            finally:
                self._recording_repair = False

    def acl_observation(self) -> bool:
        if self.acl_repaired:
            return True
        try:
            self.validate_file(self.state_dir() / ACL_OBSERVATION)
            return True  # observation marker, never an authorization source
        except OSError:
            return False

    def state_base(self) -> Path:
        return Path(self.api.local_app_data())

    @contextmanager
    def open_shared_read(self, path: Path) -> Iterator[_HandleRead]:
        """共享读打开外部普通文件（§99.3）：READ|WRITE|DELETE 共享，不妨碍属主追加、替换或删除；不跟随重解析点。

        目录与重解析点报 OSError('not_regular')；读完即关。只读，不修 ACL、不建任何东西。
        """
        with self.api.owned(self.api.open_file(str(local_path(path)), read_data=True, sharing=7)) as handle:
            try:
                info = self.api.file_info(handle)
            except OSError as error:
                if error.args == ('windows_reparse_unsupported',):
                    raise OSError('not_regular') from None
                raise
            if info.attributes & 0x10:
                raise OSError('not_regular')
            yield _HandleRead(self.api, handle, (int(info.size_high) << 32) | int(info.size_low))

    def open_private_file(self, path: Path, **options: Any) -> int:
        """Owner has metadata rights even if the old ACL denies data IO."""
        try:
            return self.api.open_file(str(path), **options)
        except OSError as error:
            if getattr(error, 'winerror', None) != 5:
                raise
        with self.api.owned(self.api.open_file(str(path), metadata_only=True)) as metadata:
            self.ensure_private(metadata, path)
        # Always reacquire normal data access, never use metadata as a data pin.
        return self.api.open_file(str(path), **options)

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
        value = os.environ.get('CODEX_HOME')
        return local_path(Path(value) if value is not None else Path.home() / '.codex')

    def grok_home(self) -> Path:
        raise OSError('windows_provider_not_enabled')

    def claude_sessions_dir(self) -> Path:
        if os.environ.get(OVERRIDE):
            return local_path(Path(os.environ[OVERRIDE]).expanduser())
        value = os.environ.get('CLAUDE_CONFIG_DIR')
        return local_path(Path(value) if value is not None else Path.home() / '.claude') / 'sessions'

    def claude_sessions_dirs(self, proc_root: Path = Path('/proc')) -> RootScan:
        if os.environ.get(OVERRIDE):
            return RootScan((self.claude_sessions_dir(),), exclusive=True)
        roots = [root / 'sessions' for root in configured(Path.home(), os.environ)]
        complete, unlocated, live, diagnostics = True, set(), [], []
        deadline = time.monotonic() + 3
        try:
            for pid, _, name in self.api.process_table():
                if time.monotonic() > deadline:
                    complete = False
                    break
                if name.lower() != 'claude.exe':
                    continue
                try:
                    fact = self.api.process(pid)
                    value = self.api.claude_config_dir(pid, str(fact.birth))
                    if value.state == 'unknown':
                        unlocated.add(pid)
                        continue
                    path = Path(value.value) if value.value is not None else Path.home() / '.claude'
                    if not path.is_absolute():
                        unlocated.add(pid)
                        continue
                    sessions = local_path(path) / 'sessions'
                    roots.append(sessions)
                    live.append((pid, sessions))
                except (OSError, RuntimeError, ValueError):
                    unlocated.add(pid)
                    continue
        except (OSError, RuntimeError, ValueError):
            complete = False
        if len(set(roots)) > MAX_ROOTS:
            complete = False
        roots = list(unique(roots))
        unlocated.update(pid for pid, path in live if path not in roots)
        # PEB is internal/permission-sensitive. Fixed-depth reclaude fallback,
        # never arbitrary recursion, persistence, root creation or key enumeration.
        accounts = Path.home() / '.rec/claude/accounts'
        try:
            with self.external_directory(accounts):
                for index, account in enumerate(accounts.iterdir()):
                    if index >= MAX_ROOTS:
                        diagnostics.append((accounts, 'fallback_limit'))
                        break
                    if account.is_dir():
                        path = account / 'config/sessions'
                        if path not in roots:
                            if len(roots) >= MAX_ROOTS:
                                diagnostics.append((accounts, 'fallback_limit'))
                                break
                            roots.append(path)
        except FileNotFoundError:
            pass
        except (OSError, RuntimeError, ValueError) as error:
            if getattr(error, 'winerror', None) not in (2, 3):
                diagnostics.append((accounts, 'fallback_unavailable'))
        return RootScan(unique(roots), complete, frozenset(unlocated), tuple(live), tuple(diagnostics))

    def codex_sqlite_home(self) -> Path | None:
        value = os.environ.get('CODEX_SQLITE_HOME')
        return local_path(Path(value)) if value is not None else None

    @contextmanager
    def external_directory(self, path: Path) -> Iterator[tuple[int, int, int]]:
        """Retain an existing external chain's identities without blocking rename.

        Never create, follow a reparse component, or repair external permissions.
        AB_STATE_DIR continues to use the separate private lease contract.
        """
        path = local_path(path)
        with ExitStack() as stack:
            identity = (0, 0, 0)
            for component in (*reversed(path.parents), path):
                handle = self.api.open_file(str(component), directory=True)
                stack.callback(self.api.close, handle)
                info = self.api.file_info(handle)
                if not info.attributes & 0x10:
                    raise OSError('windows_directory_required')
                self.api.check_ntfs(handle)
                identity = int(info.volume), int(info.index_high), int(info.index_low)
            yield identity

    @contextmanager
    def lease(self, path: Path, *, create: bool = False, external: bool = False) -> Iterator[None]:
        if external and create:
            raise OSError('external_creation_forbidden')
        path = local_path(path)
        # Keep handle ownership/identity checks; share deletion, no reparse shortcuts.
        with ExitStack() as stack:
            for component in (*reversed(path.parents), path):
                try:
                    handle = self.api.open_file(str(component), directory=True)
                except OSError as error:
                    code = getattr(error, 'winerror', None)
                    if code == 5 and component == path and not external:
                        metadata = self.api.open_file(str(path), directory=True, metadata_only=True)
                        healed = self._private_directory(metadata, path)  # takes ownership
                        self.api.close(healed)
                    elif create and code in (2, 3):
                        self.api.create_directory(str(component))
                    else:
                        raise
                    handle = self.api.open_file(str(component), directory=True)
                try:
                    info = self.api.file_info(handle)
                    if not info.attributes & 0x10:
                        raise OSError('windows_directory_required')
                    self.api.check_ntfs(handle)
                except BaseException:
                    self.api.close(handle)
                    raise
                if component == path and not external:
                    handle = self._private_directory(handle, path)
                stack.callback(self.api.close, handle)
            yield

    def ensure_private_dir(self, path: Path) -> Path:
        with self.lease(path, create=True):
            return path

    def validate_file(self, path: Path) -> tuple[int, int, int]:
        return self._validate_file(path, af_unix=False)

    def validate_socket(self, path: Path, *, external: bool = False) -> tuple[int, int, int]:
        return self._validate_file(path, af_unix=True, external=external)

    def _validate_file(self, path: Path, *, af_unix: bool, external: bool = False) -> tuple[int, int, int]:
        with self.lease(path.parent, external=external), self.api.owned(
                self.api.open_file(str(local_path(path)), sharing=7 if external else 3)) as handle:
            info = self.api.file_info(handle, af_unix=af_unix)
            # Codex rendezvous files are authenticated by their exact tag and
            # kernel peer, not by Codex's evolving file ACL/owner/link policy.
            if info.attributes & 0x10 or (not external and info.links != 1):
                raise OSError('windows_file_untrusted')
            if external:
                pass
            elif af_unix:
                self.api.check_private(handle)
            else:
                self.ensure_private(handle, path)
            return int(info.volume), int(info.index_high), int(info.index_low)

    def prepare_database(self, path: Path) -> None:
        with self.lease(path.parent, create=True):
            with self.api.owned(self.open_private_file(path, create=True, write=True)) as handle:
                info = self.api.file_info(handle)
                if info.attributes & 0x10 or info.links != 1:
                    raise OSError('windows_file_untrusted')
                self.ensure_private(handle, path)
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
            if len(old) > limit:
                rotated = path.with_name(path.name + '.1')
                try:
                    self.validate_file(rotated)
                except OSError as error:
                    if getattr(error, 'winerror', None) not in (2, 3):
                        raise
                # Rename retains the entire old log, not the bounded read above.
                # If rotation fails the original is intact; never truncate it.
                self.api.replace(str(path), str(rotated))
                old = b''
            self.atomic_write(path.parent, old + payload, name=path.name, prefix='.log.')

    def atomic_write(self, directory: Path, payload: bytes, *, name: str, prefix: str) -> None:
        if Path(name).name != name or ntpath.basename(name) != name or any(c in name+prefix for c in ':\\/\0'):
            raise OSError('windows_path_invalid')
        with self.lease(directory, create=True):
            target = directory / name
            try:
                # Replacement never consumes old bytes or writes through links.
                # The private parent authorizes replacement; retain type/link
                # guards, not the owner or ACL of the bytes being replaced.
                with self.api.owned(self.api.open_file(str(target))) as old:
                    info = self.api.file_info(old)
                    if info.attributes & 0x10 or info.links != 1:
                        raise OSError('windows_file_untrusted')
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
                with self.external_directory(path) as identity:
                    values.append(':'.join(str(part) for part in identity))
            return hashlib.sha256(b'W1:windows:v1\0' + self.api.current_token().sid + b'\0' + '\0'.join(values).encode()).hexdigest()
        except OSError:
            return None

    def home_equal(self, reported: str, expected: Path) -> bool:
        try:
            with self.external_directory(Path(reported)) as actual, self.external_directory(expected) as wanted:
                return actual == wanted
        except OSError:
            return False

    def socket_identity(self, target: Path, *, external: bool = False) -> tuple[str, int, int, int]:
        volume, high, low = self.validate_socket(target, external=external)
        return 'windows-file-id', volume, high, low

    def which(self, name: str) -> str | None:
        return shutil.which(name)

    def realpath(self, path: str) -> str:
        return str(local_path(Path(path)))

    def mtime_ns(self, path: str) -> int:
        self.validate_file(Path(path))
        return Path(path).stat().st_mtime_ns
