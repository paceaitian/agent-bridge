"""Codex 托管 daemon 的一次性 JSON-RPC 客户端：经 UDS 上的 WebSocket 发一条 `thread/queue/add`（DESIGN §61）。

只用标准库（桥不能 import observer 那份 WebSocket 客户端，且它不合用：拒符号链接、不声明 experimental）。
initialize 的身份与今天的 `codex queue` 完全相同（`codex-tui` + 本机 CLI 版本、`experimentalApi`），所以
daemon 看到的全局身份副作用与今天每次 `codex queue` 一样。

边界只有一条：**add 帧开始发送之前**的任何失败都能证明未入队，返回 `RpcFallback`，由调用方原样回退 CLI 通道；
之后的任何问题只能记 UNKNOWN，绝不换通道重投。本模块内的异常（`Exception`）一律就地接住、按这条边界归类，不冒泡给
dispatch（dispatch 会把冒泡的异常记成 UNKNOWN，把一次本可回退的失败变成「是否入队不明」）；`BaseException`
（用户中断、测试守卫）照常冒出。

`clientUserMessageId` 不是去重键：服务端每次插入都新生成队列项 id，同一个值发两次就是两条。响应会原样回显
全文，读完即弃，不进日志与账本。
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
import re
import time
from typing import Final

from ..model import Delivery
from ..platforms.transport_types import ByteStream, LocalFailure
from . import local_codex
from .websocket import WebSocket, _Closed, _Timeout

# 截止时间（DESIGN §61.2 第 3 条）：initialize 与上游客户端相同；最坏总时长与 CLI 通道的 60 秒相同
CONNECT_SECONDS: Final = 5.0
INITIALIZE_SECONDS: Final = 10.0
ADD_SECONDS: Final = 45.0
# 单条消息上限：响应回显全文，桥正文上限 64 KiB，JSON 转义最坏约 6 倍
MAX_MESSAGE_BYTES: Final = 1024 * 1024
CLIENT_NAME: Final = "codex-tui"
QUEUE_ADD_METHOD: Final = "thread/queue/add"
_INITIALIZE_ID: Final = 1
_ADD_ID: Final = 2

# 回退原因（`rpcFallback` 证据键的取值；version_unavailable 由调用方给出）
FALLBACK_SOCKET_MISSING: Final = "socket_missing"
FALLBACK_SOCKET_REJECTED: Final = "socket_rejected"
FALLBACK_CONNECT_FAILED: Final = "connect_failed"
FALLBACK_HANDSHAKE_FAILED: Final = "handshake_failed"
FALLBACK_INITIALIZE_FAILED: Final = "initialize_failed"
# initialize 成功之后、add 帧发出之前（组装或校验请求时）的意外失败
FALLBACK_REQUEST_FAILED: Final = "request_failed"

OUTPUT_RECOGNIZED: Final = "recognized"
OUTPUT_UNRECOGNIZED: Final = "unrecognized"
UNKNOWN_VERSION: Final = "unknown"

# 版本号形状：与 `codex --version` 里的版本同一套（`codex_queue.parse_version` 由它拼出整行形状）
VERSION_PATTERN: Final = r"\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?"
_VERSION: Final = re.compile(VERSION_PATTERN)
_MAX_VERSION_LENGTH: Final = 64
_UUID: Final = re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")

_UNRECOGNIZED_ERROR: Final = "codex_queue_unrecognized_error"

# (JSON-RPC code, message 子串, 状态, 原因码)：「已知优先」，按表序第一条命中为准（DESIGN §61.2 第 6 条；
# 依据见取证清单 §3.3）。写前的都是 FAILED；`queued submission operation failed` 写前写后都可能，UNKNOWN
_KNOWN_ERRORS: Final[tuple[tuple[int, str, Delivery, str], ...]] = (
    (-32001, "Server overloaded", Delivery.FAILED, "codex_server_overloaded"),
    (-32601, "", Delivery.FAILED, "codex_version_unsupported"),
    (-32600, "requires experimentalApi capability", Delivery.FAILED, "codex_version_unsupported"),
    (-32600, "Invalid request: unknown variant", Delivery.FAILED, "codex_version_unsupported"),
    (-32600, "Not initialized", Delivery.FAILED, "codex_rpc_protocol_error"),
    (-32600, "thread not found:", Delivery.FAILED, "codex_thread_not_found"),
    (-32600, "is archived. Run `codex unarchive", Delivery.FAILED, "codex_thread_archived"),
    (-32600, "ephemeral thread does not support queued submissions", Delivery.FAILED, "codex_thread_ephemeral"),
    (-32600, "not allowed for unloaded spawned sub-agents", Delivery.FAILED, "codex_subagent_unloaded"),
    (-32600, "direct app-server input is not allowed for multi-agent v2 sub-agents", Delivery.FAILED,
     "codex_subagent_unsupported"),
    (-32600, "invalid thread id", Delivery.FAILED, "codex_thread_invalid"),
    (-32600, "user message queue is unavailable", Delivery.FAILED, "codex_queue_unavailable"),
    (-32600, "queue cannot contain more than 100 submissions", Delivery.FAILED, "provider_queue_full"),
    # 这两条只会因桥自己的请求写错而出现：请求在反序列化或校验时被拒，未写
    (-32600, "only user input can be added to the user-message queue", Delivery.FAILED, "codex_rpc_protocol_error"),
    (-32600, "Invalid request:", Delivery.FAILED, "codex_rpc_protocol_error"),
    (-32602, "Input exceeds the maximum length", Delivery.FAILED, "provider_payload_too_large"),
    (-32603, "failed to read thread:", Delivery.FAILED, "codex_thread_unreadable"),
    (-32603, "queued submission operation failed", Delivery.UNKNOWN, "codex_queue_storage_error"),
)


@dataclass(frozen=True)
class RpcFallback:
    """add 帧发送之前就失败了：可证明未入队，调用方应原样回退 CLI 通道。"""

    reason: str


@dataclass(frozen=True)
class RpcResult:
    """add 帧已开始发送（或在发送前可证明不能发）之后的最终结果；不得换通道重投。"""

    delivery: Delivery
    reason: str
    # 服务端版本（initialize 响应的 userAgent），解析不出为 unknown
    server_version: str
    provider_ref: str | None = None
    # 结果是否落在已知接口之内；传输问题（超时、断线）为 None，不评输出
    output: str | None = None


def control_socket_path(codex_home: Path) -> Path:
    return local_codex.platform().control_socket_path(codex_home)


def resolve_socket(link: Path) -> Path | RpcFallback:
    target = local_codex.platform().resolve(link)
    return RpcFallback(target.reason) if isinstance(target, LocalFailure) else target


def parse_server_version(user_agent: object) -> str:
    """服务端版本：与上游 daemon 客户端同法（在第一个 `/` 处切开、取其后第一个空白分隔的词），再严格验形。"""
    if not isinstance(user_agent, str):
        return UNKNOWN_VERSION
    _, separator, rest = user_agent.partition("/")
    words = rest.split()
    if not separator or not words:
        return UNKNOWN_VERSION
    version = words[0]
    if len(version) > _MAX_VERSION_LENGTH or not _VERSION.fullmatch(version):
        return UNKNOWN_VERSION
    return version


def classify_error(error: object) -> tuple[Delivery, str, str]:
    """把 add 的 JSON-RPC error 映射为 (状态, 原因码, 输出证据)；未识别即 UNKNOWN。"""
    if not isinstance(error, dict):
        return Delivery.UNKNOWN, _UNRECOGNIZED_ERROR, OUTPUT_UNRECOGNIZED
    code = error.get("code")
    message = error.get("message")
    if not isinstance(code, int) or isinstance(code, bool) or not isinstance(message, str):
        return Delivery.UNKNOWN, _UNRECOGNIZED_ERROR, OUTPUT_UNRECOGNIZED
    data = error.get("data")
    if code == -32602 and isinstance(data, dict) and data.get("input_error_code") == "input_too_large":
        return Delivery.FAILED, "provider_payload_too_large", OUTPUT_RECOGNIZED
    for known_code, needle, delivery, reason in _KNOWN_ERRORS:
        if code == known_code and needle in message:
            return delivery, reason, OUTPUT_RECOGNIZED
    return Delivery.UNKNOWN, _UNRECOGNIZED_ERROR, OUTPUT_UNRECOGNIZED


def interpret_success(result: object, client_message_id: str) -> tuple[Delivery, str, str | None, str]:
    """成功响应：队列项 id 是 UUID 形状、`clientUserMessageId` 回显等于发出的值才算入队。

    返回 (状态, 原因码, 队列项 id, 输出证据)。形状不认得为 unrecognized；形状认得、回显不符为 recognized
    （与 CLI 通道「thread 不符」同口径）。回显的 `input` 不读。
    """
    submission = result.get("queuedSubmission") if isinstance(result, dict) else None
    if not isinstance(submission, dict):
        return Delivery.UNKNOWN, "codex_queue_unparsed_output", None, OUTPUT_UNRECOGNIZED
    item = submission.get("id")
    echo = submission.get("clientUserMessageId")
    if not isinstance(item, str) or not _UUID.fullmatch(item) or not isinstance(echo, str):
        return Delivery.UNKNOWN, "codex_queue_unparsed_output", None, OUTPUT_UNRECOGNIZED
    if echo != client_message_id:
        return Delivery.UNKNOWN, "codex_queue_unparsed_output", None, OUTPUT_RECOGNIZED
    return Delivery.QUEUED, "codex_queued", item.lower(), OUTPUT_RECOGNIZED


def queue_add(
    link: Path,
    *,
    thread_id: str,
    text: str,
    client_message_id: str,
    client_version: str,
    clock: Callable[[], float] | None = None,
) -> RpcFallback | RpcResult:
    """经 daemon 发一条 `thread/queue/add`；见模块说明里的边界。"""
    if not local_codex.platform().supported:
        return RpcResult(Delivery.FAILED, 'windows_provider_not_enabled', UNKNOWN_VERSION)
    now = clock or time.monotonic
    try:
        target = resolve_socket(link)
    except Exception:
        return RpcFallback(FALLBACK_SOCKET_REJECTED)
    if isinstance(target, RpcFallback):
        return target
    try:
        connection = local_codex.platform().new_stream()
    except Exception:  # 还没外调：与 resolve_socket 同样按写前归类（不接 BaseException，不吞用户中断）
        return RpcFallback(FALLBACK_CONNECT_FAILED)
    client = _Client(connection, now)
    try:
        return client.run(target, thread_id=thread_id, text=text, client_message_id=client_message_id,
                          client_version=client_version)
    except Exception:
        # 意外异常（实现缺陷）：按 add 帧是否已开始发送归类，不冒泡给 dispatch
        if client.add_started:
            return RpcResult(Delivery.UNKNOWN, "codex_transport_error", client.server_version)
        return RpcFallback(client.stage)
    finally:
        client.close()



class _Client(WebSocket):
    """一条连接上的一次投递；状态只活在这一次调用里。"""

    def __init__(self, connection: ByteStream, clock: Callable[[], float]) -> None:
        super().__init__(connection, clock)
        self.stage = FALLBACK_CONNECT_FAILED
        self.add_started = False
        self.server_version = UNKNOWN_VERSION

    def run(self, target: Path, *, thread_id: str, text: str, client_message_id: str,
            client_version: str) -> RpcFallback | RpcResult:
        deadline = self._now() + CONNECT_SECONDS
        try:
            self._socket.settimeout(max(deadline - self._now(), 0.001))
            self._platform.connect(self._socket, target)
        except OSError:
            return RpcFallback(FALLBACK_CONNECT_FAILED)
        if not self._peer_is_me():
            return RpcFallback(FALLBACK_SOCKET_REJECTED)
        self.stage = FALLBACK_HANDSHAKE_FAILED
        try:
            self._handshake(deadline)
        except (_Closed, _Timeout, OSError, ValueError):
            return RpcFallback(FALLBACK_HANDSHAKE_FAILED)
        self._upgraded = True
        self.stage = FALLBACK_INITIALIZE_FAILED
        deadline = self._now() + INITIALIZE_SECONDS
        try:
            self._send_json({
                "id": _INITIALIZE_ID,
                "method": "initialize",
                "params": {
                    "clientInfo": {"name": CLIENT_NAME, "title": None, "version": client_version},
                    "capabilities": {"experimentalApi": True},
                },
            }, deadline)
            response = self._await_response(_INITIALIZE_ID, deadline)
            result = response.get("result")
            if not isinstance(result, dict):
                return RpcFallback(FALLBACK_INITIALIZE_FAILED)
            server_version = self.server_version = parse_server_version(result.get("userAgent"))
            self._send_json({"method": "initialized"}, deadline)
        except (_Closed, _Timeout, OSError, ValueError):
            return RpcFallback(FALLBACK_INITIALIZE_FAILED)
        self.stage = FALLBACK_REQUEST_FAILED
        request = self._encode({
            "id": _ADD_ID,
            "method": QUEUE_ADD_METHOD,
            "params": {
                "threadId": thread_id,
                # 字段名是 snake_case：枚举上的 rename_all 只改变体名（v2/turn.rs:421-431、生成的 UserInput.ts）
                "input": [{"type": "text", "text": text, "text_elements": []}],
                "clientUserMessageId": client_message_id,
            },
        })
        if (len(request) > MAX_MESSAGE_BYTES
                or (self._max_unfragmented is not None and len(request) > self._max_unfragmented)):
            # 还没发：可证明未写；CLI 连的是同一个服务端，回退无益
            return RpcResult(Delivery.FAILED, "provider_payload_too_large", server_version)
        # 从这里起，add 帧可能已部分或全部到达服务端：任何问题都只能记 UNKNOWN
        deadline = self._now() + ADD_SECONDS
        self.add_started = True
        try:
            self._send_frame(0x1, request, deadline)
            response = self._await_response(_ADD_ID, deadline)
        except _Timeout:
            return RpcResult(Delivery.UNKNOWN, "codex_queue_timeout", server_version)
        except (_Closed, OSError, ValueError):
            return RpcResult(Delivery.UNKNOWN, "codex_transport_error", server_version)
        if "error" in response:
            delivery, reason, output = classify_error(response.get("error"))
            return RpcResult(delivery, reason, server_version, output=output)
        delivery, reason, item, output = interpret_success(response.get("result"), client_message_id)
        return RpcResult(delivery, reason, server_version, provider_ref=item, output=output)
