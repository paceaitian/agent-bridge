"""Windows caller evidence, not provider enablement; no mux/PEB/argv guesses."""
from __future__ import annotations

from collections.abc import Mapping, Callable
import os
import sys

from ...caller_values import Caller
from ...model import Endpoint, EndpointRef, Provider
from ...transports.codex_native import native_id
from ..factory import get_platform
from ..types import Presence
from .codex_discovery import Discovery, discover
from .local_transport import WindowsPlatform, IdentityEvidence
from .process import WindowsProcess, _name

AGENTS = frozenset({'codex', 'claude', 'grok'})
SHELLS = frozenset({'pwsh', 'powershell', 'cmd', 'bash', 'zsh'})
TERMINALS = frozenset({'windowsterminal', 'openconsole', 'conhost'})
MARKERS = ('CODEX_THREAD_ID', 'CODEX_SESSION_ID', 'CLAUDECODE', 'CLAUDE_PID',
           'CLAUDE_CODE_SESSION_ID', 'CLAUDE_SESSION_ID', 'GROK_SESSION_ID')


def identify(*, pid: int | None = None, environ: Mapping[str, str] | None = None,
             evidence: Discovery | IdentityEvidence | None = None, terminal: bool | None = None,
             evidence_loader: Callable[[], Discovery | IdentityEvidence] | None = None) -> Caller:
    try:
        return _identify(pid=pid, environ=environ, evidence=evidence, terminal=terminal, evidence_loader=evidence_loader)
    except OSError:
        return Caller(None, None, rejection='platform_unverified')


def _identify(*, pid: int | None, environ: Mapping[str, str] | None,
              evidence: Discovery | IdentityEvidence | None, terminal: bool | None,
              evidence_loader: Callable[[], Discovery | IdentityEvidence] | None = None) -> Caller:
    platform = get_platform()
    env = os.environ if environ is None else environ
    marked = any(env.get(key) for key in MARKERS)
    refused = Caller(None, None, agent_env=marked, rejection='platform_unverified')
    thread, session = env.get('CODEX_THREAD_ID'), env.get('CODEX_SESSION_ID')
    process, transport = platform.process, platform.transport
    if not isinstance(process, WindowsProcess) or not isinstance(transport, WindowsPlatform):
        return refused
    chain = process.trace(os.getpid() if pid is None else pid)
    if not chain.records:
        return refused
    agents = [row for row in chain.records if _name(row) in AGENTS]
    if agents and _name(agents[0]) == 'claude':
        from .claude_discovery import inspect  # layout: allow W3 root proof uses native registry plus kernel pipe peer
        nearest = agents[0].identity
        endpoint, _ = inspect(transport, nearest.pid)
        if (endpoint.ref.start_ticks != nearest.stored_generation()
                or env.get('CLAUDE_CODE_SESSION_ID') not in (None, '', endpoint.ref.native_id)
                or any(process.same_generation(row.identity) is not Presence.CURRENT for row in chain.records)):
            return refused
        return Caller(endpoint, None, 'windows-claude', True)
    if thread and session and thread != session:
        return Caller(None, None, agent_env=True, rejection='subagent')
    if thread or session:
        if not thread or thread != session or native_id(thread) != thread:
            return refused
        if not agents or _name(agents[0]) != 'codex':
            return refused
        result = evidence if evidence is not None else evidence_loader() if evidence_loader else discover(transport)
        if (isinstance(result, Discovery) and not result.complete
                or result.daemon is None or not result.root_identity):
            return refused
        pid_value, birth = result.daemon
        closest = agents[0].identity
        if (closest.pid, closest.generation_value) != (pid_value, birth):
            return refused
        label = None
        if isinstance(result, Discovery):
            matches = [r for r in result.rows if r.thread == thread]
            if len(matches) != 1 or not matches[0].eligible:
                return refused
            label = result.target_name(matches[0]).removeprefix('codex@')
        # No stale Toolhelp/daemon evidence survives the attribution boundary.
        if any(process.same_generation(r.identity) is not Presence.CURRENT for r in chain.records):
            return refused
        if platform.files.root_identity(platform.files.codex_home(), platform.files.codex_sqlite_home()) != result.root_identity:
            return refused
        endpoint = Endpoint(EndpointRef(Provider.CODEX, thread, pid_value, closest.stored_generation(),
                                      label=label,
                                      data_root=result.root_identity))
        return Caller(endpoint, None, 'windows-daemon', marked)
    if marked or agents:
        # W1 real hook registrations are unverified. Names/fixtures are not proof.
        return refused
    if terminal is None:
        terminal = bool(sys.stdin and sys.stdin.isatty())
    names = [_name(row) for row in chain.records]
    if (not terminal or len(names) < 2 or names[1] not in SHELLS
            or (chain.termination != 'root' and not any(n in TERMINALS for n in names))):
        return refused
    if any(process.same_generation(r.identity) is not Presence.CURRENT for r in chain.records):
        return refused
    return Caller(None, None, 'windows-terminal', False)
