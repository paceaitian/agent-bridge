"""Fixture-only cooperative stop bound to exact process generation; no public stop command."""
from dataclasses import asdict
import hashlib
import json
from pathlib import Path
from .files import WindowsPaths
from ..types import ProcessIdentity


def stop_name(identity: ProcessIdentity) -> str:
    value=json.dumps(asdict(identity),sort_keys=True,separators=(',',':')).encode()
    return 'stop-'+hashlib.sha256(value).hexdigest()+'.json'


def request_stop(files: WindowsPaths, root: Path, identity: ProcessIdentity) -> None:
    files.atomic_write(root,json.dumps({'version':1,'identity':asdict(identity)},sort_keys=True).encode(),
                       name=stop_name(identity),prefix='.stop.')


def stop_requested(files: WindowsPaths, root: Path, identity: ProcessIdentity) -> bool:
    path=root/stop_name(identity)
    try:
        with files.lease(root):
            files.validate_file(path)
            with path.open('rb') as stream:
                raw=stream.read(4097)
            if len(raw)>4096:
                return False
            return json.loads(raw)=={'version':1,'identity':asdict(identity)}
    except (OSError,ValueError):
        return False
