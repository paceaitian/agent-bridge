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

任务内补充消息（`steer=True`，DESIGN §95.5.4）在同一条连接上先做两步只读：`thread/read`（只要元数据）看线程是否
active，`thread/turns/list`（limit 1、倒序、不带 items）取进行中轮的 id；有才发 `turn/steer`。steer 被已知文案
确定拒绝（写入之前返回）时在同一次投递里退回 `thread/queue/add`；steer 帧开始发送之后的其余问题一律 UNKNOWN，
不重发、不换通道。只读步骤读到一半中断（流已失步）时连接不再复用，按写前回退 CLI 通道。
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
import re
import time
from typing import Final, Literal

from ..model import Delivery, Runtime
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
_READ_ID: Final = 3
_TURNS_ID: Final = 4
_STEER_ID: Final = 5

# turn/steer（DESIGN §95.5.4）：两步只读各自的截止时间短于投递；turns/list 每次都重放整份 rollout，给得宽一些
THREAD_READ_SECONDS: Final = 5.0
TURNS_LIST_SECONDS: Final = 15.0
STEER_SECONDS: Final = 45.0
THREAD_READ_METHOD: Final = "thread/read"
TURNS_LIST_METHOD: Final = "thread/turns/list"
STEER_METHOD: Final = "turn/steer"
# 回执里不保留任何 turn id；只认长度有界、无空白的非空串
_MAX_TURN_ID_LENGTH: Final = 128

# 通道选择的路径（`steerPath` 证据键的取值，无正文闭集）：steered 是插入成功；steer_unknown 是 steer 帧已发、结果不明；
# 其余都是「没有 steer 或被确定拒绝」，随后同一次投递走队列
STEER_PATH_STEERED: Final = "steered"
STEER_PATH_THREAD_NOT_ACTIVE: Final = "thread_not_active"
STEER_PATH_THREAD_UNREADABLE: Final = "thread_unreadable"
STEER_PATH_NO_ACTIVE_TURN: Final = "no_active_turn"
STEER_PATH_TURNS_UNREADABLE: Final = "turns_unreadable"
STEER_PATH_REJECTED: Final = "steer_rejected"
STEER_PATH_UNKNOWN: Final = "steer_unknown"
# steerPath 的取值闭集：跨设备只同步闭集内的值（DESIGN §97.3）
STEER_PATHS: Final = frozenset({STEER_PATH_STEERED, STEER_PATH_THREAD_NOT_ACTIVE, STEER_PATH_THREAD_UNREADABLE,
                                STEER_PATH_NO_ACTIVE_TURN, STEER_PATH_TURNS_UNREADABLE, STEER_PATH_REJECTED,
                                STEER_PATH_UNKNOWN})
# 只读步骤读到一半中断：连接失步，不复用，按写前回退 CLI
FALLBACK_STEER_READ_FAILED: Final = "steer_read_failed"

# turn/steer 确定未送入的拒绝（0.169 源码逐条对照；0.163 的 NotSubmitted 文案相同）：都在写入之前返回。匹配方式只有全等、前缀与「任意文案」，
# 不用子串——-32600 里还有 core `steer_turn` 原样透出的 InvalidRequest(message)，文案任意，必须落到 UNKNOWN。
#   message_processor.rs:121-125 `deserialize_client_request`：未知方法/参数形状错 → "Invalid request: …"（-32600）
#   app-server-transport transport/mod.rs:240-253：入站队列满 → -32001 "Server overloaded; retry later."
#   mcp_processor.rs:118-131 / apps_processor.rs:366-380 `load_thread`："invalid thread id: …"、"thread not found: …"
#   thread_input.rs:23-37 `ensure_direct_input_allowed`：多代理 v2 子代理不收直接输入
#   turn_processor.rs:1129-1142：expectedTurnId 为空；`validate_v2_input_limit`（:555-573）-32602 超长
#   turn_processor.rs:1171-1251 NotSubmittedReason：NoActiveTurn/NotIdle/PendingTriggerTurn/PlanMode/Superseded
#     → "no active turn to steer"；ExpectedTurnMismatch；review/compact 轮；EmptyInput；输出 schema 不同；
#     ServerDraining → error_code.rs:10-14 "Server is draining; retry after reconnecting"
#   不在表里、算不明的：`failed to steer turn: …`（-32603，:1166）、InvalidRequest(message) 透出（:1165）、
#     config_load_error / model_provider_error（文案随配置变化）及其他一切未知错误
#   0.163 把 steer_turn 的其余错误一律包成 `failed to steer turn: …`（没有 InvalidRequest 透出），同样落 UNKNOWN
_SteerMatch = Literal["any", "exact", "prefix", "mismatch"]
_STEER_NOT_SUBMITTED: Final[tuple[tuple[int, _SteerMatch, str, str], ...]] = (
    (-32601, "any", "", "codex_steer_unsupported"),
    (-32600, "prefix", "Invalid request: ", "codex_steer_request_rejected"),
    (-32001, "prefix", "Server overloaded", "codex_server_overloaded"),
    (-32600, "prefix", "invalid thread id: ", "codex_thread_invalid"),
    (-32600, "prefix", "thread not found: ", "codex_thread_not_found"),
    (-32600, "exact", "direct app-server input is not allowed for multi-agent v2 sub-agents",
     "codex_subagent_unsupported"),
    (-32600, "exact", "expectedTurnId must not be empty", "codex_rpc_protocol_error"),
    (-32602, "prefix", "Input exceeds the maximum length", "provider_payload_too_large"),
    (-32600, "exact", "no active turn to steer", "codex_steer_no_active_turn"),
    (-32600, "mismatch", "", "codex_steer_turn_changed"),
    (-32600, "exact", "cannot steer a review turn", "codex_steer_review_turn"),
    (-32600, "exact", "cannot steer a compact turn", "codex_steer_compact_turn"),
    (-32600, "exact", "input must not be empty", "codex_rpc_protocol_error"),
    (-32600, "exact", "active turn uses a different output schema", "codex_steer_schema_mismatch"),
    (-32600, "exact", "Server is draining; retry after reconnecting", "codex_server_draining"),
)
# steerRejected 的取值闭集：上表的原因码（`classify_steer_error` 只会返回这些），跨设备只同步这组固定码（§97.3）
STEER_REJECTED_CODES: Final = frozenset(reason for *_, reason in _STEER_NOT_SUBMITTED)
_EXPECTED_TURN_MISMATCH: Final = re.compile(r"expected active turn id `[^`\n]*` but found `[^`\n]*`")

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
    # 补充消息的通道选择路径（STEER_PATH_*）与被确定拒绝时的原因码；普通投递为 None（DESIGN §95.5.4）
    steer_path: str | None = None
    steer_rejected: str | None = None


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


def classify_steer_error(error: object) -> str | None:
    """turn/steer 的 JSON-RPC error：确定未送入时返回原因码（随后退回队列），其余返回 None（记 UNKNOWN）。"""
    if not isinstance(error, dict):
        return None
    code = error.get("code")
    message = error.get("message")
    if not isinstance(code, int) or isinstance(code, bool) or not isinstance(message, str):
        return None
    for known_code, match, text, reason in _STEER_NOT_SUBMITTED:
        if code != known_code:
            continue
        if (match == "any" or (match == "exact" and message == text)
                or (match == "prefix" and message.startswith(text))
                or (match == "mismatch" and _EXPECTED_TURN_MISMATCH.fullmatch(message) is not None)):
            return reason
    return None


def steer_error_reason(error: object) -> str:
    """steer 结果不明时的原因码：服务端明说 steer 失败的单列，其余按未识别。"""
    message = error.get("message") if isinstance(error, dict) else None
    if isinstance(message, str) and message.startswith("failed to steer turn: "):
        return "codex_steer_failed"
    return "codex_steer_unrecognized_error"


def interpret_steer_success(result: object) -> bool:
    """turn/steer 成功响应 `{turnId}`：非空、有界、无空白才算插入成功；turnId 本身不保留。"""
    turn = result.get("turnId") if isinstance(result, dict) else None
    return _valid_turn_id(turn)


def _valid_turn_id(value: object) -> bool:
    return (isinstance(value, str) and 0 < len(value) <= _MAX_TURN_ID_LENGTH
            and not any(ch.isspace() or ord(ch) < 32 for ch in value))


def thread_active(result: object) -> bool | None:
    """metadata-only `thread/read` 的结果：线程 active 为 True、其他已知状态为 False，形状认不出为 None。"""
    thread = result.get("thread") if isinstance(result, dict) else None
    status = thread.get("status") if isinstance(thread, dict) else None
    kind = status.get("type") if isinstance(status, dict) else None
    if kind == "active":
        return True
    if kind in ("idle", "notLoaded", "systemError"):
        return False
    return None


# 上游 ThreadActiveFlag（0.169 v2/thread.rs:1763，serde camelCase 单元变体）序列化成这两个字符串；不认识的旗标当作没有
_WAITING_FLAGS = frozenset({"waitingOnApproval", "waitingOnUserInput"})


def thread_runtime(result: object) -> Runtime:
    """metadata-only `thread/read` 结果的忙闲（DESIGN §96.2，只用于显示）：`idle` 为空闲；`active` 且 activeFlags 含
    等待审批或等待输入为等待用户，其余 active（含 activeFlags 缺失或不是列表）为忙；notLoaded、systemError、形状认不出
    （含错误响应的 None）一律 UNKNOWN。steer 的判定仍用 thread_active，两者互不影响。"""
    thread = result.get("thread") if isinstance(result, dict) else None  # pyright: ignore[reportUnknownMemberType,reportUnknownVariableType]
    status = thread.get("status") if isinstance(thread, dict) else None  # pyright: ignore[reportUnknownMemberType,reportUnknownVariableType]
    kind = status.get("type") if isinstance(status, dict) else None  # pyright: ignore[reportUnknownMemberType,reportUnknownVariableType]
    if kind == "idle":
        return Runtime.IDLE
    if kind != "active":
        return Runtime.UNKNOWN
    flags = status.get("activeFlags")  # pyright: ignore[reportOptionalMemberAccess,reportUnknownMemberType,reportUnknownVariableType]
    waiting = isinstance(flags, list) and any(isinstance(flag, str) and flag in _WAITING_FLAGS for flag in flags)  # pyright: ignore[reportUnknownVariableType]
    return Runtime.WAITING if waiting else Runtime.BUSY


def in_progress_turn(result: object) -> tuple[bool, str | None]:
    """`thread/turns/list`（limit 1、倒序、notLoaded）的结果：(形状认得, 第一条 status==inProgress 的轮 id)。

    只读 id 与 status，items 不加载、其余字段读完即弃；形状认不出（含错误响应的 None）为 (False, None)。
    """
    data = result.get("data") if isinstance(result, dict) else None
    if not isinstance(data, list):
        return False, None
    for turn in data:  # pyright: ignore[reportUnknownVariableType]
        if not isinstance(turn, dict) or not isinstance(turn.get("status"), str):  # pyright: ignore[reportUnknownMemberType]
            return False, None
        if turn.get("status") == "inProgress":  # pyright: ignore[reportUnknownMemberType]
            turn_id = turn.get("id")  # pyright: ignore[reportUnknownMemberType,reportUnknownVariableType]
            return (True, turn_id) if _valid_turn_id(turn_id) else (False, None)  # pyright: ignore[reportUnknownVariableType]
    return True, None


def thread_read_request(request_id: int, thread_id: str) -> dict[str, object]:
    """只要元数据的 thread/read：不带 turns，不读对方会话内容（AGENTS.md）。"""
    return {"id": request_id, "method": THREAD_READ_METHOD, "params": {"threadId": thread_id, "includeTurns": False}}


def turns_list_request(request_id: int, thread_id: str) -> dict[str, object]:
    """最新一轮的 id 与状态：limit 1、倒序、不加载 items。"""
    return {"id": request_id, "method": TURNS_LIST_METHOD, "params": {
        "threadId": thread_id, "limit": 1, "sortDirection": "desc", "itemsView": "notLoaded"}}


def steer_request(request_id: int, thread_id: str, text: str, client_message_id: str, turn_id: str) -> dict[str, object]:
    """turn/steer：expectedTurnId 用只读步骤取到的进行中轮，clientUserMessageId 用这条尝试的消息 id。"""
    return {"id": request_id, "method": STEER_METHOD, "params": {
        "threadId": thread_id, "input": [{"type": "text", "text": text, "text_elements": []}],
        "clientUserMessageId": client_message_id, "expectedTurnId": turn_id}}


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
    steer: bool = False,
) -> RpcFallback | RpcResult:
    """经 daemon 发一条 `thread/queue/add`；steer=True（补充消息）时先按只读结果尝试 turn/steer。见模块说明里的边界。"""
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
                          client_version=client_version, steer=steer)
    except Exception:
        # 意外异常（实现缺陷）：按 add/steer 帧是否已开始发送归类，不冒泡给 dispatch
        if client.add_started:
            return RpcResult(Delivery.UNKNOWN, "codex_transport_error", client.server_version,
                             steer_path=STEER_PATH_UNKNOWN if client.steering else client.steer_path)
        return RpcFallback(client.stage)
    finally:
        client.close()



class _Client(WebSocket):
    """一条连接上的一次投递；状态只活在这一次调用里。"""

    def __init__(self, connection: ByteStream, clock: Callable[[], float]) -> None:
        super().__init__(connection, clock)
        self.stage = FALLBACK_CONNECT_FAILED
        # 写入闩锁：add 或 steer 帧开始发送后置位；steer 被确定拒绝后复位，再走 add（DESIGN §95.5.4）
        self.add_started = False
        self.steering = False
        self.steer_path: str | None = None
        self.steer_rejected: str | None = None
        self.server_version = UNKNOWN_VERSION

    def run(self, target: Path, *, thread_id: str, text: str, client_message_id: str,
            client_version: str, steer: bool = False) -> RpcFallback | RpcResult:
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
        if steer:
            steered = self._steer(thread_id, text, client_message_id, server_version)
            if steered is not None:
                return steered
            self.stage = FALLBACK_REQUEST_FAILED
        return self._add(thread_id, text, client_message_id, server_version)

    def _read(self, request: dict[str, object], request_id: int, seconds: float) -> object | None:
        """一步只读：返回 result（错误响应为 None）；读到一半中断或请求没发完时抛 `_Desynced`，连接不再复用。

        等响应时整条消息都还没开始读就超时，流仍在消息边界上：返回 None，迟到的应答由 `_await_response` 按 id 丢弃。
        """
        deadline = self._now() + seconds
        try:
            self._send_json(request, deadline)
        except (_Closed, _Timeout, OSError, ValueError) as error:
            raise _Desynced() from error  # 请求帧可能只写了一半：后面的帧会被服务端读歪
        try:
            response = self._await_response(request_id, deadline)
        except _Timeout as error:
            if self.desynced:
                raise _Desynced() from error
            return None
        except (_Closed, OSError, ValueError) as error:
            raise _Desynced() from error
        return response.get("result") if "result" in response else None

    def _steer(self, thread_id: str, text: str, client_message_id: str,
               server_version: str) -> RpcFallback | RpcResult | None:
        """补充消息的通道选择（DESIGN §95.5.4）：返回 None 表示走队列（已记下 steer_path）。

        通道只靠两步只读决定，不靠先试 steer 看会不会被拒；steer 帧开始发送后只有「已知拒绝 → 队列」与 UNKNOWN 两种结局。
        """
        self.stage = FALLBACK_STEER_READ_FAILED
        try:
            active = thread_active(self._read(thread_read_request(_READ_ID, thread_id), _READ_ID, THREAD_READ_SECONDS))
            if active is not True:
                self.steer_path = STEER_PATH_THREAD_NOT_ACTIVE if active is False else STEER_PATH_THREAD_UNREADABLE
                return None
            recognized, turn = in_progress_turn(
                self._read(turns_list_request(_TURNS_ID, thread_id), _TURNS_ID, TURNS_LIST_SECONDS))
        except _Desynced:
            return RpcFallback(FALLBACK_STEER_READ_FAILED)
        if turn is None:
            self.steer_path = STEER_PATH_NO_ACTIVE_TURN if recognized else STEER_PATH_TURNS_UNREADABLE
            return None
        self.stage = FALLBACK_REQUEST_FAILED
        request = self._encode(steer_request(_STEER_ID, thread_id, text, client_message_id, turn))
        if (len(request) > MAX_MESSAGE_BYTES
                or (self._max_unfragmented is not None and len(request) > self._max_unfragmented)):
            # 还没发：可证明未写；同一正文的 add 同样超限
            return RpcResult(Delivery.FAILED, "provider_payload_too_large", server_version)
        deadline = self._now() + STEER_SECONDS
        self.add_started = self.steering = True
        try:
            self._send_frame(0x1, request, deadline)
            response = self._await_response(_STEER_ID, deadline)
        except _Timeout:
            return RpcResult(Delivery.UNKNOWN, "codex_steer_timeout", server_version, steer_path=STEER_PATH_UNKNOWN)
        except (_Closed, OSError, ValueError):
            return RpcResult(Delivery.UNKNOWN, "codex_transport_error", server_version, steer_path=STEER_PATH_UNKNOWN)
        if "error" in response:
            rejected = classify_steer_error(response.get("error"))
            if rejected is None:
                return RpcResult(Delivery.UNKNOWN, steer_error_reason(response.get("error")), server_version,
                                 steer_path=STEER_PATH_UNKNOWN)
            # 确定未送入：复位写入闩锁，同一次投递退回队列
            self.add_started = self.steering = False
            self.steer_path, self.steer_rejected = STEER_PATH_REJECTED, rejected
            return None
        if interpret_steer_success(response.get("result")):
            return RpcResult(Delivery.DELIVERED, "codex_steered", server_version, steer_path=STEER_PATH_STEERED)
        return RpcResult(Delivery.UNKNOWN, "codex_steer_unparsed_output", server_version, steer_path=STEER_PATH_UNKNOWN)

    def _add(self, thread_id: str, text: str, client_message_id: str, server_version: str) -> RpcResult:
        """thread/queue/add：与 §61 的投递完全相同；补充消息退回队列时附上通道选择路径。"""
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
            return RpcResult(Delivery.FAILED, "provider_payload_too_large", server_version,
                             steer_path=self.steer_path, steer_rejected=self.steer_rejected)
        # 从这里起，add 帧可能已部分或全部到达服务端：任何问题都只能记 UNKNOWN
        deadline = self._now() + ADD_SECONDS
        self.add_started = True
        try:
            self._send_frame(0x1, request, deadline)
            response = self._await_response(_ADD_ID, deadline)
        except _Timeout:
            return RpcResult(Delivery.UNKNOWN, "codex_queue_timeout", server_version,
                             steer_path=self.steer_path, steer_rejected=self.steer_rejected)
        except (_Closed, OSError, ValueError):
            return RpcResult(Delivery.UNKNOWN, "codex_transport_error", server_version,
                             steer_path=self.steer_path, steer_rejected=self.steer_rejected)
        if "error" in response:
            delivery, reason, output = classify_error(response.get("error"))
            return RpcResult(delivery, reason, server_version, output=output,
                             steer_path=self.steer_path, steer_rejected=self.steer_rejected)
        delivery, reason, item, output = interpret_success(response.get("result"), client_message_id)
        return RpcResult(delivery, reason, server_version, provider_ref=item, output=output,
                             steer_path=self.steer_path, steer_rejected=self.steer_rejected)


class _Desynced(Exception):
    """只读步骤读到一半中断或请求帧没发完：这条连接已失步，不再复用（按写前回退）。"""
