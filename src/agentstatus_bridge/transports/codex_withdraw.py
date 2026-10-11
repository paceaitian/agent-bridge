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
               before_send: Callable[[], None], sqlite_home: Path | None = None) -> DeleteResult:
        deadline = self.clock() + DELETE_SECONDS
        client: BoundedConnection | None = None
        sending, version = False, "unknown"
        try:
            if native_id(thread) != thread or native_id(item) != item:
                return DeleteResult("not_attempted", "invalid_target")
            backend = local_codex.platform()
            if backend.root_identity(home, sqlite_home) != root_identity:
                return DeleteResult("not_attempted", "root_mismatch")
            cli = self.version(min(3.0, max(0.001, deadline - self.clock())))
            if cli is None:
                return DeleteResult("not_attempted", "version_unavailable")
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
            before_send()  # 必须先持久化sending并提交，才可开始发送帧；回调不能持有跨I/O事务
            sending = True
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
                client.close()
