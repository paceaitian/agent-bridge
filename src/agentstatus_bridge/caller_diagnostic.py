"""Read-only caller attribution, projected without identities or process contents."""
from __future__ import annotations

import os

from . import endpoints
from .caller_values import Caller
from .platforms import process as procfs
from .platforms.factory import get_platform

VIAS = frozenset({'ancestry', 'environment', 'daemon', 'windows-claude',
                  'windows-daemon', 'windows-terminal'})
REJECTIONS = frozenset({'subagent', 'platform_unverified'})
TERMINATIONS = frozenset({'root', 'cycle', 'limit', 'parent_reused', 'process_exited',
                         'process_invalid', 'process_unverified', 'process_identity_unverified',
                         'process_snapshot_changed', 'legacy_missing_or_unreadable'})
PROVIDERS = frozenset({'claude', 'codex', 'grok'})


def collect() -> dict[str, object]:
    """Use the real identify path; ancestry is a separate bounded observation.

    Neither observation is authorization for a later command. In particular an
    ordinary user shell is not an attributed agent, even when it may use ab.
    No key/ledger access, message delivery or runtime changes occur here.
    """
    platform = get_platform()
    pid = os.getpid()
    termination, length, nearest = 'unknown', 0, None
    if platform.name == 'windows':
        from .platforms.windows.caller import identify  # layout: allow Windows real attribution, no key access
        from .platforms.windows.process import WindowsProcess, _name  # layout: allow bounded native ancestry
        try:
            if isinstance(platform.process, WindowsProcess):
                chain = platform.process.trace(pid)
                termination, length = chain.termination, len(chain.records)
                nearest = next((_name(row) for row in chain.records if _name(row) in PROVIDERS), None)
            who = identify(pid=pid)
        except OSError:
            who = Caller(None, None, rejection='platform_unverified')
    else:
        try:
            rows = procfs.ancestry(pid)
            length = len(rows)
            parent = rows[-1].ppid if rows else pid
            termination = ('root' if parent == 0 else 'cycle' if parent in {r.pid for r in rows}
                           else 'limit' if length >= 64 else 'legacy_missing_or_unreadable')
            nearest = next((row.comm for row in rows if row.comm in PROVIDERS), None)
            who = endpoints.identify_caller(endpoints.discover(), pid=pid)
        except OSError:
            who = Caller(None, None, rejection='platform_unverified')
    return {
        'attributed': who.endpoint is not None,
        'via': who.via if who.via is None or who.via in VIAS else 'unknown',
        'rejection': who.rejection if who.rejection is None or who.rejection in REJECTIONS else 'unknown',
        'termination': termination if termination in TERMINATIONS else 'unknown',
        'chainLength': length,
        'nearestAgent': nearest,
    }
