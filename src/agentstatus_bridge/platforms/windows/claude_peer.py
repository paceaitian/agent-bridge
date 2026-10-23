"""W3 native peer transport: the worker owns both the write and authenticated inbox."""
from __future__ import annotations

import hmac
import json
from pathlib import Path
import queue
import secrets
import threading
import time
from typing import Any

from ...model import Delivery, Endpoint, EndpointRef
from ..transport_codec import MAX_INBOX_BUFFER, encode_address, same_address, parse_receipt, parse_reply
from .claude_auth import PeerFiles, OwnKey, TOKEN
from .files import WindowsPaths
from .io import WinIO


class Decoder:
    """Authentication is per connection; no raw wire or token is returned to the caller."""
    def __init__(self, token: str) -> None:
        self._token, self._buffer, self._total, self.authenticated = token, b'', 0, False

    def feed(self, data: bytes, *, eof: bool = False) -> list[dict[str, Any]]:
        self._total += len(data)
        if self._total > MAX_INBOX_BUFFER:
            raise OSError('claude_inbox_limit')
        lines = (self._buffer + data).split(b'\n')
        self._buffer = lines.pop()
        if eof and self._buffer:
            lines.append(self._buffer)
            self._buffer = b''
        result: list[dict[str, Any]] = []
        for line in lines:
            try:
                value = json.loads(line)
            except (ValueError, UnicodeError):
                raise OSError('claude_inbox_frame_invalid') from None
            if not isinstance(value, dict):
                raise OSError('claude_inbox_frame_invalid')
            if not self.authenticated:
                token = value.get('token')
                if (value.get('type') != 'auth' or not isinstance(token, str) or not TOKEN.fullmatch(token)
                        or not hmac.compare_digest(token, self._token)):
                    raise OSError('claude_inbox_auth_failed')
                self.authenticated, self._token = True, ''
            else:
                result.append(value)
        return result


class Inbox:
    """A single-instance overlapped pipe. Idle accepts block; bounded queue, no polling spin."""
    def __init__(self, files: WindowsPaths, *, name: str | None = None) -> None:
        self.files, self.api = files, files.api
        self.path = Path('\\\\.\\pipe\\LOCAL\\cc-msg-' + (name or secrets.token_hex(16)))
        self.address = encode_address(str(self.path))
        self._io = WinIO(self.api)
        self._handle: int | None = None
        self._key: OwnKey | None = None
        self._keys: dict[str, OwnKey] = {}
        self._token = secrets.token_hex(16)
        self._thread: threading.Thread | None = None
        self._started = False
        self._stop = threading.Event()
        self._failed = False
        self._frames: queue.Queue[object] = queue.Queue(maxsize=256)
        self._expected: dict[str, tuple[EndpointRef, str, float]] = {}
        self._lock = threading.Lock()

    def open(self) -> None:
        if self._handle is not None or self._thread is not None or self._stop.is_set():
            raise OSError('claude_inbox_already_used')
        try:
            pid = int(self.api.k.GetCurrentProcessId())
            fact = self.api.process(pid)
            self._handle = self._io.create_pipe(str(self.path))
            self.api.check_private(self._handle)
            # Existing roots only. register() adds our same registration to each
            # destination's root before opening its timed pipe connection.
            for sessions in self.files.claude_sessions_dirs().roots:
                try:
                    if not sessions.is_dir():
                        continue
                    files = PeerFiles(self.files, sessions)
                    with files.root() as root:
                        self._key = OwnKey(files, pid, str(self.path), str(fact.birth), self._token)
                        self._key.publish()
                        self._keys[root] = self._key
                except OSError:
                    if self._key is not None:
                        self._key.close()
                        self._key = None
                    continue  # One unusable legacy root must not block other roots.
                break
            if not self._keys:
                raise OSError('claude_inbox_unavailable')
            self._thread = threading.Thread(target=self._serve, name='ab-peer-receipts', daemon=True)
            self._thread.start()
            self._started = True
        except BaseException:
            self.close()
            raise

    def healthy(self) -> bool:
        return bool(self._thread and self._thread.is_alive() and not self._failed and not self._stop.is_set())

    def register(self, files: PeerFiles, root: str | None) -> None:
        """打开目标的限时连接前，在已解析的根中准备自有回信登记。"""
        if not self.healthy():
            raise OSError('claude_inbox_unavailable')
        with files.root() as actual:
            if actual != root:
                raise OSError('claude_root_changed')
        if root not in self._keys:
            pid = int(self.api.k.GetCurrentProcessId())
            fact = self.api.process(pid)
            key = OwnKey(files, pid, str(self.path), str(fact.birth), self._token)
            try:
                key.publish()
            except BaseException:
                key.close()
                raise
            self._keys[str(root)] = key

    def expect(self, endpoint: Endpoint, message_id: str) -> None:
        if not self.healthy() or not endpoint.socket_path:
            raise OSError('claude_inbox_unavailable')
        with self._lock:
            now = time.monotonic()
            self._expected = {key: item for key, item in self._expected.items() if item[2] > now}
            if len(self._expected) >= 6400:
                raise OSError('claude_inbox_limit')
            self._expected[message_id.lower()] = endpoint.ref, encode_address(endpoint.socket_path), now + 12 * 60

    def _accepted(self, frame: dict[str, Any], pid: int, birth: str) -> bool:
        receipt, reply = parse_receipt(frame), parse_reply(frame)
        with self._lock:
            now = time.monotonic()
            expected = [value for key, value in self._expected.items()
                        if value[2] > now and value[0].pid == pid and value[0].start_ticks == 'win-filetime:' + birth
                        and (receipt is not None and receipt.message_uuid == key
                             or reply is not None and same_address(reply.reply_address, value[1]))]
        return bool(expected)

    def _connection(self, handle: int) -> None:
        pid = self._io.peer_pid(handle, pipe=True, server=True)
        fact, me = self.api.process(pid), self.api.current_token()
        if fact.token.sid != me.sid or fact.token.elevated or me.elevated:
            raise OSError('claude_inbox_peer_mismatch')
        with self._lock:
            if not any(ref.pid == pid and ref.start_ticks == 'win-filetime:' + str(fact.birth)
                       and expires > time.monotonic() for ref, _, expires in self._expected.values()):
                raise OSError('claude_inbox_peer_mismatch')
        decoder, deadline = Decoder(self._token), time.monotonic() + 5
        while not self._stop.is_set():
            data = self._io.pipe_io(handle, 'read', 65536, deadline)
            if not isinstance(data, bytes):
                raise OSError('claude_inbox_frame_invalid')
            for frame in decoder.feed(data, eof=not data):
                if self.api.process(pid, expected_birth=str(fact.birth)) != fact:
                    raise OSError('claude_inbox_peer_changed')
                if self._accepted(frame, pid, str(fact.birth)):
                    self._frames.put_nowait(frame)
            if not data:
                break

    def _serve(self) -> None:
        handle = self._handle
        if handle is None:
            self._failed = True
            return
        try:
            while not self._stop.is_set():
                try:
                    self._io.pipe_io(handle, 'accept', 0, time.monotonic() + 1)
                except TimeoutError:
                    continue
                try:
                    self._connection(handle)
                except (OSError, queue.Full):
                    pass  # No raw content, unknown client, or authentication failure reaches the dispatcher.
                finally:
                    try:
                        self.api.k.DisconnectNamedPipe(handle)
                    except OSError:
                        pass  # A vanished client must not end the listener.
        except OSError:
            self._failed = not self._stop.is_set()

    def poll(self, timeout: float) -> list[object]:
        frames: list[object] = []
        try:
            frames.append(self._frames.get(timeout=max(0, timeout)))
            while len(frames) < 256:
                frames.append(self._frames.get_nowait())
        except queue.Empty:
            pass
        return frames

    def close(self) -> None:
        self._stop.set()
        try:
            if self._thread is not None and self._started:
                if self._handle is not None:
                    self.api.k.CancelIoEx(self._handle, None)
                self._thread.join(3)
                if self._thread.is_alive():
                    raise OSError('claude_inbox_close_pending')
            if self._handle is not None:
                handle, self._handle = self._handle, None
                self._io.close_pipe(handle)
        finally:
            error = None
            keys = list(self._keys.values())
            if self._key is not None and self._key not in keys:
                keys.append(self._key)
            for key in keys:
                try:
                    key.close()
                except OSError as failure:
                    error = failure
            self._token = ''
            if error is not None:
                raise error
