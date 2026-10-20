"""§70 独立delete客户端：仅删精确UUID对，结果不改变原消息的投递/执行含义。"""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
import time

from . import local_codex
from .codex_native import BoundedConnection, NativeFailure, native_id
from .websocket import _Timeout

DELETE_SECONDS = 10.0


@dataclass(frozen=True)
class DeleteResult:
    state: str
    reason: str
    server_version: str = "unknown"


def delete_error(error: object) -> tuple[str, str]:
    if not isinstance(error, dict) or type(error.get("code")) is not int or not isinstance(error.get("message"), str):
        return "unknown", "unrecognized_error"
    code, message = error["code"], error["message"]
    if code == -32601 or code == -32600 and (
        "requires experimentalApi capability" in message or "Invalid request: unknown variant" in message
    ):
        return "refused", "method_unsupported"
    if code == -32600 and any(part in message for part in (
        "thread not found:", "is archived. Run `codex unarchive", "ephemeral thread does not support queued submissions",
        "invalid thread id", "user message queue is unavailable", "Not initialized", "Invalid request:",
    )):
        return "refused", "request_rejected"
    if code == -32001 and message == "Server overloaded":
        return "refused", "server_overloaded"
    if code == -32603 and message.startswith("failed to read thread:"):
        return "refused", "thread_unreadable"
    return "unknown", "storage_error" if code == -32603 and "queued submission operation failed" in message else "unrecognized_error"


class QueueDeleteClient:
    def __init__(self, version: Callable[[float], str | None], *, clock: Callable[[], float] = time.monotonic) -> None:
        self.version, self.clock = version, clock

    def delete(self, home: Path, *, thread: str, item: str, root_identity: str,
               before_send: Callable[[float], None], sqlite_home: Path | None = None) -> DeleteResult:
        deadline = self.clock() + DELETE_SECONDS
        client: BoundedConnection | None = None
        sending, version = False, "unknown"
        try:
            if native_id(thread) != thread or native_id(item) != item:
                return DeleteResult("not_attempted", "invalid_target")
            backend = local_codex.platform()
            if not backend.supported:
                return DeleteResult('not_attempted', 'windows_provider_not_enabled')
            if backend.root_identity(home, sqlite_home) != root_identity:
                return DeleteResult("not_attempted", "root_mismatch")
            cli = self.version(min(3.0, max(0.001, deadline - self.clock()))) or "unknown"
            client = BoundedConnection(home, min(deadline, self.clock() + 3.0), self.clock)
            client.close_deadline = deadline
            client.initialize(cli, min(deadline, self.clock() + 3.0), experimental=True)
            version = client.server_version
            if backend.root_identity(home, sqlite_home) != root_identity:
                raise NativeFailure("root_mismatch")
            client.unchanged()
            request = client._encode({"id": 2, "method": "thread/queue/delete", "params": {
                "threadId": thread, "queuedSubmissionId": item,
            }})
            remaining = client._remaining(deadline)
            try:
                before_send(remaining)  # 回调据剩余预算限账本忙等；提交后才可发帧
            except Exception as error:
                reason = "boundary_store_busy" if getattr(error, "code", None) == "store_busy" else "boundary_record_failed"
                return DeleteResult("not_attempted", reason, version)
            client._remaining(deadline)  # 落账慢而尚未发帧时，不冒称写后 unknown
            def mark_sending() -> None:
                nonlocal sending
                sending = True
            client.on_write_start = mark_sending  # 编帧/设超时也可能用尽预算，直到实际sendall入口才算可能写出
            client._send_frame(1, request, deadline)
            response = client.response(2, deadline)
            if "error" in response:
                state, reason = delete_error(response["error"])
                return DeleteResult(state, reason, version)
            result = response.get("result")
            deleted = result.get("deleted") if isinstance(result, dict) else None
            if type(deleted) is not bool:
                return DeleteResult("unknown", "malformed_result", version)
            return DeleteResult("deleted" if deleted else "absent", "deleted" if deleted else "absent", version)
        except NativeFailure as error:
            return DeleteResult("unknown" if sending else "not_attempted", error.reason,
                                client.server_version if client else version)
        except _Timeout:
            return DeleteResult("unknown" if sending else "not_attempted", "deadline", version)
        except Exception:
            return DeleteResult("unknown" if sending else "not_attempted", "transport_error", version)
        finally:
            if client is not None:
                client.on_write_start = None
                client.close()
