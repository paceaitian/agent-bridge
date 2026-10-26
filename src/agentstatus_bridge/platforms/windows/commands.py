"""W2 command-scoped proof; no global discovery cache or implicit user identity."""
from __future__ import annotations
from collections.abc import Iterator
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass

from ...caller_values import Caller
from ...model import Endpoint, Provider
from ...transports.codex_native import NativeFailure, native_id
from ..factory import get_platform
from ..types import Presence
from .codex_discovery import Discovery, discover
from .local_transport import WindowsPlatform, IdentityEvidence
from . import claude_discovery as claude

WRITES = frozenset({'send', 'report', 'retry', 'pause', 'resume', 'cancel', 'accept', 'close'})
LIGHT = frozenset({'report', 'accept', 'close', 'pause', 'cancel', 'resume'})
ALLOWED = WRITES | {'doctor', 'tasks', 'status', 'summary', 'peers', 'wait', 'worker', 'federation'}


@dataclass
class Command:
    action: str
    evidence: Discovery | IdentityEvidence
    caller: Caller | None = None
    claude: claude.Discovery | None = None


_current: ContextVar[Command | None] = ContextVar('windows_command', default=None)


def sample() -> Discovery:
    backend = get_platform().transport
    return discover(backend) if isinstance(backend, WindowsPlatform) else Discovery()


def evidence() -> Discovery | IdentityEvidence:
    value = _current.get()
    return value.evidence if value is not None else sample()


def caller() -> Caller | None:
    value = _current.get()
    return value.caller if value is not None else None


def claude_evidence() -> claude.Discovery:
    current = _current.get()
    if current is not None and current.claude is not None:
        return current.claude
    backend = get_platform().transport
    result = claude.discover(backend) if isinstance(backend, WindowsPlatform) else claude.Discovery()
    if current is not None:
        current.claude = result
    return result


def endpoints() -> list[Endpoint]:
    result = evidence()
    return ([result.endpoint(row) for row in result.rows if row.eligible]
            if isinstance(result, Discovery) and result.complete else []) + list(claude_evidence().endpoints)


def resolve(reference: str) -> Endpoint:
    if reference.startswith('claude@'):
        return claude_evidence().select(reference)
    result = evidence()
    if not isinstance(result, Discovery):
        raise NativeFailure('discovery_incomplete')
    if reference.startswith('codex@'):
        return result.endpoint(result.select(reference))
    found: list[Endpoint] = []
    failures: list[NativeFailure] = []
    exact = native_id(reference.removeprefix('id:'))
    selector = 'id:' + exact if exact is not None else reference
    for choose in (lambda: result.endpoint(result.select(selector)), lambda: claude_evidence().select(selector)):
        try:
            found.append(choose())
        except NativeFailure as error:
            if error.reason != 'target_not_found' and not (exact is not None and
                    error.reason in {'discovery_incomplete', 'claude_discovery_incomplete'}):
                raise
            failures.append(error)
    if len(found) > 1:
        raise NativeFailure('target_ambiguous')
    if found:
        return found[0]
    raise next((error for error in failures if error.reason != 'target_not_found'), failures[0])


def receiver_presence(pid: int, start: str) -> Presence:
    """Only for a previously verified same-user, non-elevated Claude receiver."""
    birth = start.removeprefix('win-filetime:')
    if (type(pid) is not int or not 0 < pid < 2**32 or not start.startswith('win-filetime:')
            or not birth.isascii() or not birth.isdecimal() or int(birth) <= 0):
        return Presence.UNKNOWN
    backend = get_platform().transport
    if not isinstance(backend, WindowsPlatform):
        return Presence.UNKNOWN
    try:
        claude.peer_process(backend, pid, birth=birth)
    except claude.Ineligible:
        return Presence.EXITED
    except OSError:
        return Presence.UNKNOWN
    return Presence.CURRENT


@contextmanager
def scope(args) -> Iterator[None]:
    if args.command not in ALLOWED:
        raise NativeFailure('windows_provider_not_enabled')
    if args.command not in WRITES:
        yield
        return
    for key in ('to', 'review_by'):
        selector = getattr(args, key, None)
        if key == 'review_by' and selector is not None and not selector.strip():
            raise NativeFailure('target_explicit_required')
        if selector and selector.startswith('grok@'):
            raise NativeFailure('windows_provider_not_enabled')
    command = Command(args.command, Discovery())
    token = _current.set(command)
    try:
        from .caller import identify  # layout: allow 在命令作用域内共享本次证据，无反向业务导入
        sampled = False
        def load() -> Discovery | IdentityEvidence:
            nonlocal sampled
            if args.command in LIGHT:
                backend = get_platform().transport
                if not isinstance(backend, WindowsPlatform):
                    raise OSError('windows_provider_not_enabled')
                try:
                    command.evidence = backend.caller_identity()
                except OSError as error:
                    raise NativeFailure('caller_unattributed') from error
            else:
                command.evidence = sample()
            sampled = True
            return command.evidence
        command.caller = identify(evidence_loader=load)
        who = command.caller
        if who.rejection == 'subagent':
            raise NativeFailure('reporter_is_subagent' if args.command == 'report' else 'sender_is_subagent')
        if who.endpoint is None and not who.is_user_shell:
            raise NativeFailure('caller_unattributed')
        if who.endpoint is not None and who.endpoint.ref.provider not in (Provider.CODEX, Provider.CLAUDE):
            raise NativeFailure('windows_provider_not_enabled')
        if not sampled and not (args.command in LIGHT and who.endpoint is not None
                                and who.endpoint.ref.provider is Provider.CLAUDE):
            load()
        yield
    finally:
        _current.reset(token)


def check_task(task, attempts) -> None:
    command = _current.get()
    if command is None or command.action not in WRITES:
        return
    refs = [task.origin, task.reviewer, *(a.target for a in attempts)]
    files = get_platform().files
    roots: dict[Provider, str | None] = {Provider.CODEX: command.evidence.root_identity or None}
    claude_roots: set[str] = set()
    claude_paths = None
    for ref in refs:
        if ref is None:
            continue
        if ref.provider is Provider.CLAUDE:
            if ref.data_root and ref.data_root in claude_roots:
                continue
            from .claude_auth import PeerFiles  # layout: allow per-provider root proof, no credential read
            backend = get_platform().transport
            if not isinstance(backend, WindowsPlatform):
                raise NativeFailure('target_root_changed')
            try:
                if claude_paths is None:
                    claude_paths = backend.files.claude_sessions_dirs().roots
                with PeerFiles.from_root(backend.files, ref.data_root, sessions=claude_paths).root() as root:
                    roots[Provider.CLAUDE] = root
                    claude_roots.add(root)
            except OSError:
                raise NativeFailure('target_root_changed') from None
        if ref.provider is Provider.CODEX and not roots[Provider.CODEX]:
            roots[Provider.CODEX] = files.root_identity(files.codex_home(), files.codex_sqlite_home())
        if not ref.data_root or ref.data_root != roots.get(ref.provider):
            raise NativeFailure('target_root_changed')


class WorkerDiscovery:
    """Independent provider completeness: a Codex row cannot prove Claude absence."""
    def __init__(self, backend: WindowsPlatform) -> None:
        self.backend = backend
        self.codex, self.claude = Discovery(), claude.Discovery()

    def __call__(self) -> list[Endpoint]:
        self.codex, self.claude = discover(self.backend), claude.discover(self.backend, connect=False)
        return ([self.codex.endpoint(row) for row in self.codex.rows if row.eligible]
                if self.codex.complete else []) + list(self.claude.endpoints) + list(self.claude.duplicates)

    def provider_complete(self, provider: Provider) -> bool:
        if provider is Provider.CLAUDE:
            return self.claude.complete
        return self.codex.complete and all(r.metadata_verified and r.stable for r in self.codex.rows)

    def complete(self) -> bool:
        return self.provider_complete(Provider.CODEX) and self.provider_complete(Provider.CLAUDE)
