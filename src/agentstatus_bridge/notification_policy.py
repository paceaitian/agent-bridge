"""Routing eligibility, distinct from the version/root-specific W2 transport.

Linux retains its historical contract, including readonly-provider diagnostics.
Windows Codex and W3 Claude have native inboxes; Grok remains unsupported.
"""
from .model import EndpointRef, Provider
from .platforms.factory import get_platform


def can_notify(target: EndpointRef) -> bool:
    return get_platform().name != 'windows' or target.provider in (Provider.CODEX, Provider.CLAUDE)


def receipt_options(origin: EndpointRef | None, *, no_notify: bool) -> dict[str, object]:
    if get_platform().name != 'windows':
        return {}
    if origin is not None and not can_notify(origin) and not no_notify:
        raise ValueError('receipt_poll_only_required')
    return {'receiptMode': 'poll_only' if no_notify or origin is None else 'push'}
