"""Scavenger test isolation, independent of the helper under mutation."""
import os
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

import bridge_short_socket as S

_scavenge = S._scavenge
_shared = {Path('/var/tmp').resolve()}
if os.environ.get('LOCALAPPDATA'):
    _shared.add(Path(os.environ['LOCALAPPDATA']).resolve())


def guarded_scavenge(base):
    if Path(base).resolve() in _shared:
        raise AssertionError('test_scavenge_shared_directory')
    return _scavenge(base)


patch.object(S, '_scavenge', guarded_scavenge).start()


def isolate(case):
    # Create a new owned directory, never enumerate or remove the shared base.
    candidates = [Path('/var/tmp')] if os.name != 'nt' else S._fallback_bases()
    longest='other-home/app-server-control/app-server-control.sock'
    base = next((p for p in candidates if p.is_dir() and p != Path(p.anchor)
                 and S._fits(p/'s-xxxxxxxx',longest)), None)
    if base is None:
        raise OSError('no_private_short_fixture_base')
    root = case.enterContext(TemporaryDirectory(prefix='s-', dir=base))
    case.enterContext(patch.object(S, '_fallback_bases', return_value=[Path(root)]))
