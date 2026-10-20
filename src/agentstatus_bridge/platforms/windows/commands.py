"""W2 command-scoped proof; no global discovery cache or implicit user identity."""
from collections.abc import Iterator
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass

from ...caller_values import Caller
from ...model import Endpoint, Provider
from ...transports.codex_native import NativeFailure
from ..factory import get_platform
from .codex_discovery import Discovery, discover
from .local_transport import WindowsPlatform, IdentityEvidence

WRITES = frozenset({'send', 'report', 'retry', 'pause', 'resume', 'cancel', 'accept', 'close'})
LIGHT = frozenset({'report', 'accept', 'close', 'pause', 'cancel', 'resume'})
ALLOWED = WRITES | {'doctor', 'tasks', 'status', 'summary', 'peers', 'wait', 'worker'}


@dataclass
class Command:
    action: str
    evidence: Discovery | IdentityEvidence
    caller: Caller | None = None


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


def endpoints() -> list[Endpoint]:
    result = evidence()
    return ([result.endpoint(row) for row in result.rows if row.eligible]
            if isinstance(result, Discovery) and result.complete else [])


def resolve(reference: str) -> Endpoint:
    result = evidence()
    if not isinstance(result, Discovery):
        raise NativeFailure('discovery_incomplete')
    return result.endpoint(result.select(reference))


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
        if selector and selector.startswith(('claude@', 'grok@')):
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
        if who.endpoint is not None and who.endpoint.ref.provider is not Provider.CODEX:
            # No qualified Claude root registration in W2. Never infer one.
            raise NativeFailure('windows_provider_not_enabled')
        if not sampled:
            load()
        yield
    finally:
        _current.reset(token)


def check_task(task, attempts) -> None:
    command = _current.get()
    if command is None or command.action not in WRITES:
        return
    refs = [task.origin, task.reviewer, *(a.target for a in attempts)]
    if any(r is not None and r.data_root != command.evidence.root_identity for r in refs):
        raise NativeFailure('target_root_changed')
