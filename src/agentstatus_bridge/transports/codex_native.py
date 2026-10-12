"""§69/70 有界连接与只读元数据客户端；原始响应不越过这里的投影边界。"""
from __future__ import annotations

from collections.abc import Callable, Collection, Mapping
from dataclasses import dataclass, field
import json
from pathlib import Path
import re
import time

from ..platforms.transport_types import LocalFailure
from . import local_codex
from .codex_rpc import CLIENT_NAME, parse_server_version
from .websocket import WebSocket, _Closed, _Timeout

VERIFIED_VERSIONS = frozenset({"0.162.1"})
READ_SECONDS = 1.0
MAX_IDS = 32
MAX_RECEIVE_BYTES = 4 * 1024 * 1024
UUID = re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")


def native_id(value: object) -> str | None:
    return value.lower() if isinstance(value, str) and UUID.fullmatch(value) else None


class NativeFailure(Exception):
    """只带固定原因；绝不包装服务端错误全文。"""
    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


@dataclass(frozen=True)
class ThreadMetadata:
    kind: str
    parent: str | None = None


@dataclass(frozen=True)
class NativeBatch:
    records: dict[str, ThreadMetadata] = field(default_factory=dict)
    reason: str = "no_candidates"
    server_version: str = "unknown"
    not_held: tuple[str, ...] = ()


def project_thread(value: object, requested: str) -> ThreadMetadata:
    if not isinstance(value, dict) or native_id(value.get("id")) != requested:
        raise NativeFailure("thread_id_mismatch")
    source = value.get("source")
    kind, nested_parent = "unknown", None
    if isinstance(source, str) and source in {"cli", "vscode", "exec", "appServer"}:
        kind = "root"
    elif isinstance(source, dict) and len(source) == 1:
        if isinstance(source.get("custom"), str):
            kind = "root"
        elif "subAgent" in source:
            sub = source["subAgent"]
            if isinstance(sub, str) and sub in {"review", "compact", "memory_consolidation"}:
                kind = "subagent"
            elif isinstance(sub, dict) and len(sub) == 1:
                if isinstance(sub.get("other"), str):
                    kind = "subagent"
                elif isinstance(sub.get("thread_spawn"), dict):
                    spawn = sub["thread_spawn"]
                    nested_parent = native_id(spawn.get("parent_thread_id"))
                    depth = spawn.get("depth")
                    if nested_parent is not None and type(depth) is int and -(2**31) <= depth < 2**31:
                        kind = "subagent"
                    else:
                        return ThreadMetadata("conflict")
    outer_value = value.get("parentThreadId")
    outer_parent = native_id(outer_value)
    if outer_value is not None and outer_parent is None:
        return ThreadMetadata("conflict")
    if (outer_parent is not None and nested_parent is not None and outer_parent != nested_parent
            or requested in (outer_parent, nested_parent)
            or kind == "root" and outer_parent is not None):
        return ThreadMetadata("conflict")
    return ThreadMetadata(kind, (outer_parent or nested_parent) if kind == "subagent" else None)


class BoundedConnection(WebSocket):
    """协议载体私有；业务只通过 ReadBatchClient / QueueDeleteClient 的窄入口使用。"""
    def __init__(self, home: Path, deadline: float, clock: Callable[[], float]) -> None:
        backend = local_codex.platform()
        link = backend.control_socket_path(home)
        epoch = local_codex.socket_identity(link)
        target = backend.resolve(link)
        if isinstance(target, LocalFailure):
            raise NativeFailure(target.reason)
        self.home, self.link, self.epoch = home, link, epoch
        self.server_version = "unknown"
        super().__init__(backend.new_stream(), clock, backend)
        self.close_deadline = deadline
        self.receive_budget = MAX_RECEIVE_BYTES
        self.strict_size = True
        try:
            self._socket.settimeout(self._remaining(deadline))
            backend.connect(self._socket, target)
            if not self._peer_is_me():
                raise NativeFailure("peer_rejected")
            self._handshake(deadline)
            self._upgraded = True
        except BaseException:
            self.close()
            raise

    def unchanged(self) -> None:
        if self.epoch is None or local_codex.socket_identity(self.link) != self.epoch:
            raise NativeFailure("daemon_changed")

    def initialize(self, version: str, deadline: float, *, experimental: bool) -> None:
        self._send_json({"id": 1, "method": "initialize", "params": {
            "clientInfo": {"name": CLIENT_NAME, "title": None, "version": version},
            "capabilities": {"experimentalApi": experimental},
        }}, deadline)
        response = self.response(1, deadline)
        result = response.get("result")
        if not isinstance(result, dict):
            raise NativeFailure("initialize_failed")
        self.server_version = parse_server_version(result.get("userAgent"))
        if self.server_version not in VERIFIED_VERSIONS:
            raise NativeFailure("version_unverified")
        home = result.get("codexHome")
        if not isinstance(home, str) or not self._platform.home_equal(home, self.home):
            raise NativeFailure("home_mismatch")
        self.unchanged()
        self._send_json({"method": "initialized"}, deadline)

    def response(self, expected: int, deadline: float) -> dict[str, object]:
        while True:
            self._remaining(deadline)
            opcode, payload = self._read_message(deadline)
            if opcode != 1:
                continue
            message = json.loads(payload.decode("utf-8"))
            if not isinstance(message, dict):
                raise NativeFailure("protocol_error")
            if "method" in message:
                if "id" in message:
                    raise NativeFailure("server_request_seen")
                continue
            if (type(message.get("id")) is not int or message.get("id") != expected
                    or ("result" in message) == ("error" in message)):
                raise NativeFailure("response_id_mismatch")
            self.unchanged()
            return message


class ReadBatchClient:
    def __init__(self, version: Callable[[float], str | None], *, clock: Callable[[], float] = time.monotonic) -> None:
        self.version, self.clock = version, clock

    def read(self, home: Path, threads: Collection[str], peers: Mapping[str, Collection[int]]) -> NativeBatch:
        wanted = list(dict.fromkeys(value for item in threads if (value := native_id(item)) is not None))[:MAX_IDS]
        if not wanted:
            return NativeBatch()
        started = self.clock()
        deadline = started + READ_SECONDS
        client: BoundedConnection | None = None
        version = "unknown"
        try:
            # socket缺失时不额外启动版本查询；版本查询本身也共享1秒总预算。
            failure = local_codex.platform().resolve(local_codex.platform().control_socket_path(home))
            if isinstance(failure, LocalFailure):
                return NativeBatch(reason=failure.reason)
            cli = self.version(max(0.001, deadline - self.clock()))
            if cli is None:
                return NativeBatch(reason="version_unavailable")
            if self.clock() >= deadline:
                return NativeBatch(reason="deadline")
            client = BoundedConnection(home, deadline, self.clock)
            not_held = tuple(thread for thread in wanted if client.peer_pid not in peers.get(thread, ()))
            wanted = [thread for thread in wanted if client.peer_pid in peers.get(thread, ())]
            if not wanted:
                return NativeBatch(reason="peer_not_holder", not_held=not_held)
            client.initialize(cli, deadline, experimental=False)
            version = client.server_version
            records: dict[str, ThreadMetadata] = {}
            for request_id, thread in enumerate(wanted, 2):
                client._send_json({"id": request_id, "method": "thread/read", "params": {
                    "threadId": thread, "includeTurns": False,
                }}, deadline)
                response = client.response(request_id, deadline)
                result = response.get("result")
                if isinstance(result, dict):
                    records[thread] = project_thread(result.get("thread"), thread)
                else:
                    records[thread] = ThreadMetadata("unknown")
            client.unchanged()
            return NativeBatch(records, "ok", version, not_held)
        except NativeFailure as error:
            return NativeBatch(reason=error.reason, server_version=client.server_version if client else version)
        except _Timeout:
            return NativeBatch(reason="deadline", server_version=version)
        except Exception:
            return NativeBatch(reason="transport_error", server_version=version)
        finally:
            if client is not None:
                client.close()
