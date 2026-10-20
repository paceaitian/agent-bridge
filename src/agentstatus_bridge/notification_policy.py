"""Routing eligibility, distinct from the version/root-specific W2 transport.

Linux retains its historical contract, including readonly-provider diagnostics.
Windows has no Claude/Grok inbox; neither notification construction nor review
may silently schedule one. Future qualified Claude senders must explicitly poll.
"""
from .model import EndpointRef, Provider
from .platforms.factory import get_platform
from dataclasses import replace


def wire_ref(target: EndpointRef) -> EndpointRef:
    """Windows native labels stay local; protocol-generated text uses the id."""
    return replace(target, label=None) if get_platform().name == 'windows' else target


def can_notify(target: EndpointRef) -> bool:
    return get_platform().name != 'windows' or target.provider is Provider.CODEX


def receipt_options(origin: EndpointRef | None, *, no_notify: bool) -> dict[str, object]:
    if get_platform().name != 'windows':
        return {}
    if origin is not None and not can_notify(origin) and not no_notify:
        raise ValueError('receipt_poll_only_required')
    return {'receiptMode': 'poll_only' if no_notify or origin is None else 'push'}
