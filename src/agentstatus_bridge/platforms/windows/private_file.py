"""Private ordinary leaf pin, shared by SQL and worker receipts without RPC."""
from contextlib import contextmanager
from collections.abc import Iterator
from pathlib import Path
from .files import WindowsPaths, local_path


@contextmanager
def pinned_file(files: WindowsPaths, path: Path, *, external: bool = False,
                external_sql_read: bool = False, share_delete: bool = False) -> Iterator[int]:
    """Caller owns the directory-chain lease; external owners may rename leaves."""
    path = local_path(path)
    opened = (files.api.open_file(str(path), read_data=True, sharing=7) if external
              else files.open_private_file(path, read_data=True, sharing=7 if share_delete else 3))
    with files.api.owned(opened) as handle:
        info = files.api.file_info(handle)
        if info.attributes & 0x10 or info.links != 1:
            raise OSError('windows_file_untrusted')
        files.api.check_ntfs(handle)
        if external:
            files.api.check_private(handle, allow_administrators=True, allow_readers=external_sql_read)
        else:
            files.ensure_private(handle, path)
        yield handle
