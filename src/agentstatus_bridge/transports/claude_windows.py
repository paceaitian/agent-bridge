"""Authenticated Windows Claude writes; the worker owns the same-process inbox."""
from __future__ import annotations
from collections.abc import Callable
import json
import time

from ..model import Delivery, Endpoint
from ..store import StoreError
from . import DeliveryContext, DeliveryOutcome
from .claude_peer import ClaudePeerTransport, build_frame
from ..platforms.windows.claude_auth import PeerFiles
from ..platforms.windows.claude_discovery import inspect
from ..platforms.windows.claude_peer import Inbox
from ..platforms.windows.io import WinIO
from ..platforms.windows.local_transport import WindowsPlatform


class Transport(ClaudePeerTransport):
    def __init__(self, backend: WindowsPlatform, inbox: Callable[[], object | None] | None = None) -> None:
        super().__init__()
        self.backend, self._get_inbox = backend, inbox or (lambda: None)

    def ready(self, reply_to: str | None) -> bool:
        inbox = self._get_inbox()
        return isinstance(inbox, Inbox) and inbox.healthy() and reply_to == inbox.address

    def deliver(self, endpoint: Endpoint, text: str, context: DeliveryContext) -> DeliveryOutcome:
        inbox = self._get_inbox()
        if not isinstance(inbox, Inbox) or not inbox.healthy() or context.reply_to != inbox.address:
            return DeliveryOutcome(Delivery.FAILED, 'claude_inbox_unavailable')
        io, handle, message_started = WinIO(self.backend.api), None, False
        try:
            files = PeerFiles.from_root(self.backend.files, endpoint.ref.data_root)
            live, record = inspect(self.backend, endpoint.ref.pid, connect=False, sessions=files.sessions)
            if live.ref != endpoint.ref or live.socket_path != endpoint.socket_path:
                return DeliveryOutcome(Delivery.FAILED, 'claude_target_changed')
            priority = self._priority_for(context)
            # Sender session is native identity, never an identity for the Python inbox itself.
            try:
                frame = build_frame(text, context, priority=priority).encode('utf-8')
            except ValueError:
                return DeliveryOutcome(Delivery.FAILED, 'provider_payload_too_large')
            inbox.register(files, live.ref.data_root)
            deadline = time.monotonic() + 5
            try:
                handle = io.open_pipe(live.socket_path or '')
            except OSError:
                return DeliveryOutcome(Delivery.FAILED, 'claude_socket_connect_failed')
            if io.peer_pid(handle, pipe=True) != live.ref.pid:
                raise OSError('claude_peer_mismatch')
            birth = live.ref.start_ticks.removeprefix('win-filetime:')
            peer = self.backend.api.process(live.ref.pid, expected_birth=birth)
            me = self.backend.api.current_token()
            if peer.token.sid != me.sid or peer.token.elevated:
                raise OSError('claude_peer_mismatch')
            with files.root() as root:
                if root != live.ref.data_root:
                    raise OSError('claude_root_changed')
                token = files.token(live.ref.pid, live.socket_path or '', birth, record)
            auth = (json.dumps({'type': 'auth', 'token': token}, separators=(',', ':')) + '\n').encode()
            token = ''
            written = io.pipe_io(handle, 'write', auth, deadline)
            if written != len(auth):
                raise OSError('claude_auth_write_failed')
            auth = b''
            if self.backend.api.process(live.ref.pid, expected_birth=birth) != peer:
                raise OSError('claude_peer_changed')
            inbox.expect(live, context.message_uuid)
            if context.before_send is not None:
                context.before_send()
            message_started = True
            count = io.pipe_io(handle, 'write', frame, deadline)
            if count != len(frame):
                raise OSError('claude_message_write_failed')
            return DeliveryOutcome(Delivery.WRITTEN, 'claude_written', context.message_uuid,
                {'priority': priority, 'senderClass': context.sender_class or 'unknown'}, native_root=live.ref.data_root)
        except (OSError, ValueError, StoreError):
            return DeliveryOutcome(Delivery.UNKNOWN if message_started else Delivery.FAILED,
                'claude_socket_write_failed' if message_started else 'claude_peer_unverified')
        finally:
            if handle is not None:
                io.close_pipe(handle)
