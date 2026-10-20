"""Prefer isolated TMPDIR; bounded short fallback for synthetic AF_UNIX paths.

Never widen the production 108-byte limit. Fallback scavenging only touches
our marked, owned, aged, non-reparse roots whose creating process is gone.
"""
import json
import os
from pathlib import Path
import re
import shutil
import stat
from tempfile import TemporaryDirectory, gettempdir
import time

SOCKET_SUFFIX = 'h/app-server-control/app-server-control.sock'
MARKER = '.w2-owner'
MAX_AGE = 24 * 3600


def _fits(base, socket_suffix=SOCKET_SUFFIX):
    return len(str(Path(base) / 'w2-xxxxxxxx' / socket_suffix).encode('utf-8')) < 108


def _fallback_bases():
    if os.name != 'nt':
        return [Path('/var/tmp')]
    # Stay within the user's own directories, never create at a volume root.
    return [Path(p) for p in (os.environ.get('LOCALAPPDATA'), str(Path.home())) if p]


def _plain(status):
    return not stat.S_ISLNK(status.st_mode) and not getattr(status, 'st_file_attributes', 0) & 0x400


def _owner_matches(path, status):
    if os.name != 'nt':
        return status.st_uid == os.getuid() and not status.st_mode & 0o022
    from agentstatus_bridge.platforms.windows.api import WinApi
    api = WinApi()
    try:
        with api.owned(api.open_file(str(path), directory=stat.S_ISDIR(status.st_mode))) as handle:
            api.file_info(handle)
            api.check_private(handle, allow_administrators=True)
        return True
    except OSError:
        return False


def _alive(pid):
    if os.name == 'nt':
        from agentstatus_bridge.platforms.windows.api import WinApi
        try:
            WinApi().process(pid)
            return True
        except OSError as error:
            return getattr(error, 'winerror', None) not in (87, 1168)
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False
    except OSError:
        return True


def _tree_plain(root):
    for child in root.iterdir():
        status = child.lstat()
        if not _plain(status):
            return False
        if stat.S_ISDIR(status.st_mode) and not _tree_plain(child):
            return False
    return True


def _scavenge(base):
    now = time.time()
    for path in base.iterdir():
        if not re.fullmatch(r'w2-[a-z0-9_]{8}', path.name):
            continue
        try:
            before = path.lstat()
            if not stat.S_ISDIR(before.st_mode) or not _plain(before) or not _owner_matches(path, before):
                continue
            marker = path / MARKER
            info = marker.lstat()
            if (not stat.S_ISREG(info.st_mode) or not _plain(info) or info.st_size > 128
                    or not _owner_matches(marker, info) or now - info.st_mtime <= MAX_AGE):
                continue
            value = json.loads(marker.read_text(encoding='ascii'))
            if (not isinstance(value, dict) or set(value) != {'pid'} or type(value['pid']) is not int
                    or not 0 < value['pid'] < 2**32 or _alive(value['pid'])):
                continue
            # A stale fixture containing links is preserved for manual review.
            if not _tree_plain(path):
                continue
            after = path.lstat()
            if (before.st_dev, before.st_ino, before.st_mtime_ns) != (after.st_dev, after.st_ino, after.st_mtime_ns):
                continue
            shutil.rmtree(path)
        except (OSError, ValueError):
            continue  # uncertain provenance/cleanup must not delete other work


def short_root(socket_suffix=SOCKET_SUFFIX):
    """Reserve the longest socket suffix the caller will actually construct."""
    preferred = Path(gettempdir())
    if _fits(preferred, socket_suffix):
        return TemporaryDirectory(prefix='w2-', dir=preferred)
    for base in _fallback_bases():
        if base == Path(base.anchor) or not base.is_dir() or not _fits(base, socket_suffix):
            continue
        _scavenge(base)
        root = TemporaryDirectory(prefix='w2-', dir=base)
        try:
            marker = Path(root.name) / MARKER
            marker.write_text(json.dumps({'pid': os.getpid()}), encoding='ascii')
            if os.name != 'nt':
                marker.chmod(0o600)
            return root
        except BaseException:
            root.cleanup()
            raise
    raise OSError('no_private_short_fixture_root')
