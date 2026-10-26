"""联邦线上编码（DESIGN §88.2/§88.3）：有界 JSONL 帧、严格 JSON、规范化序列化与内容哈希、闭集与标识校验。

只做形状与边界，不做业务判断：信封里 actor/target/authority 的合法性由各端按单写者规则另行核验。
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
import hashlib
import json
import math
import re
from typing import IO, Any

# 单帧上限（不含结尾 LF）；超过即关闭连接，不先读完整行再判断（§88.2）
MAX_FRAME_BYTES = 1_048_576
# 规范化信封上限与自由正文上限（body 与 data.note 合计）
MAX_ENVELOPE_BYTES = 512 * 1024
MAX_FREE_TEXT_BYTES = 64 * 1024
MAX_TITLE_CHARS = 120
MAX_JSON_DEPTH = 16
MAX_REFS = 16
# 附件：单文件、单条消息合计（只算 transfer=blob 的项），以及线上分块
MAX_BLOB_BYTES = 8 * 1024 * 1024
MAX_MESSAGE_BLOB_BYTES = 32 * 1024 * 1024
BLOB_CHUNK_BYTES = 256 * 1024
# checkpoint 是自包含有界对象，纳入信封上限（§88.4）
MAX_CHECKPOINT_BYTES = 128 * 1024
# 转交期限：默认与最大都是 30 天（§88.3）
TRANSFER_TTL_MS = 30 * 86400 * 1000
MAX_INT64 = 2**63 - 1

PROTOCOL_MAJOR = 1
PROTOCOL_MINOR = 0
REQUIRED_CAPABILITIES = frozenset({"origin-authority-v1", "durable-mailbox-v1", "attachments-v1", "sender-class-v1"})

ENVELOPE_KINDS = frozenset(
    {"handoff", "review", "notice", "task_state", "report", "report_decision", "delivery_status", "sync_request", "sync_state"}
)
# 承载原生投递的信封：msg_id 同时是原生 message_id，必须携带 A 的当前 checkpoint（§88.3/§88.4）
ATTEMPT_KINDS = frozenset({"handoff", "review", "notice"})
# 设备之间来回的帧类型闭集；未知类型一律拒绝，不能解释成默认操作
FRAME_TYPES = frozenset(
    {
        "hello", "hello_ack", "ready",
        "directory_put", "directory_ack", "directory_get", "directory_snapshot",
        "blob_begin", "blob_ready", "blob_chunk", "blob_chunk_ack", "blob_finish", "blob_stored",
        "submit", "accepted", "fetch", "item", "fetch_end", "blob_get", "blob_data",
        "ack", "acked", "reject", "rejected", "receipts_get", "receipt_page", "receipt_seen", "receipt_seen_ok",
        "heartbeat", "heartbeat_ack", "error",
    }
)
ERROR_CODES = frozenset(
    {
        "protocol_unsupported", "capability_missing", "frame_invalid", "frame_too_large", "handshake_required",
        "ledger_instance_mismatch", "device_unregistered", "device_revoked", "destination_unknown",
        "connection_superseded", "identity_mismatch", "idempotency_conflict", "cursor_gap", "message_expired",
        "auth_evidence_unavailable", "hub_busy", "hub_unavailable", "hub_storage_full", "attachment_missing",
        "attachment_too_large", "attachment_hash_mismatch", "attachment_offset_invalid",
    }
)
# 只有这些可以用相同 ID 自动重试；其余要展示，不能悄悄换 ID（§88.2）
RETRYABLE_ERRORS = frozenset({"hub_busy", "hub_unavailable", "hub_storage_full"})
SENDER_CLASSES = frozenset({"bypass", "prompting", "unknown"})
# hub 依认证映射盖章或自己生成的字段；不参与发件内容哈希
HUB_STAMPED_FIELDS = frozenset(
    {"sourceDeviceId", "sourceDeviceName", "receivedAt", "acceptedAt", "recipientSeq", "payloadHash", "connectionGeneration"}
)
REF_TRANSFERS = frozenset({"blob", "reference"})
REF_REASONS = frozenset({"single_file_limit", "message_total_limit"})

_HEX32 = re.compile(r"[0-9a-f]{32}")
_HEX64 = re.compile(r"[0-9a-f]{64}")
# 登记名：唯一 ASCII slug（§88.6）
DEVICE_SLUG = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,31}")


class CodecError(ValueError):
    """线上数据不合法；`code` 是 ERROR_CODES 里的闭集码，不回显传入值。"""

    def __init__(self, code: str, detail: str = "") -> None:
        assert code in ERROR_CODES, code
        super().__init__(code if not detail else f"{code}: {detail}")
        self.code = code
        self.detail = detail


def is_hex32(value: object) -> bool:
    """32 位小写十六进制标识（msg_id/operationId/deviceId/taskId 等）。"""
    return isinstance(value, str) and _HEX32.fullmatch(value) is not None


def is_hex64(value: object) -> bool:
    """64 位小写十六进制（sha256）。"""
    return isinstance(value, str) and _HEX64.fullmatch(value) is not None


def is_slug(value: object) -> bool:
    """设备登记名。"""
    return isinstance(value, str) and DEVICE_SLUG.fullmatch(value) is not None


def is_count(value: object, *, maximum: int = MAX_INT64) -> bool:
    """非负 64 位整数；bool 不算整数。"""
    return isinstance(value, int) and not isinstance(value, bool) and 0 <= value <= maximum


def is_positive(value: object, *, maximum: int = MAX_INT64) -> bool:
    """正整数（序号类）。"""
    return is_count(value, maximum=maximum) and value != 0


def _reject_constant(_name: str) -> Any:
    raise CodecError("frame_invalid", "non_finite_number")


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise CodecError("frame_invalid", "duplicate_key")
        result[key] = value
    return result


def _check_depth(value: object, limit: int) -> None:
    # 迭代检查嵌套深度，避免递归本身被深嵌套打爆
    stack: list[tuple[object, int]] = [(value, 1)]
    while stack:
        item, depth = stack.pop()
        if isinstance(item, dict | list):
            if depth > limit:
                raise CodecError("frame_invalid", "too_deep")
            children: Iterable[object] = item.values() if isinstance(item, dict) else item  # pyright: ignore[reportUnknownMemberType,reportUnknownVariableType]
            stack.extend((child, depth + 1) for child in children)
        elif isinstance(item, float) and not math.isfinite(item):
            raise CodecError("frame_invalid", "non_finite_number")


def loads_strict(data: bytes) -> dict[str, Any]:
    """严格解析一帧：UTF-8、顶层 object、无重复键、无 NaN/Infinity、嵌套不超过 16 层。"""
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as error:
        raise CodecError("frame_invalid", "utf8") from error
    try:
        value = json.loads(text, object_pairs_hook=_unique_object, parse_constant=_reject_constant)
    except CodecError:
        raise
    except (ValueError, RecursionError) as error:
        raise CodecError("frame_invalid", "json") from error
    if not isinstance(value, dict):
        raise CodecError("frame_invalid", "not_object")
    _check_depth(value, MAX_JSON_DEPTH)
    return value  # pyright: ignore[reportUnknownVariableType]


def canonical_bytes(value: object) -> bytes:
    """规范化序列化：UTF-8、键排序、紧凑分隔符、保留非 ASCII；同一内容恒得同一字节。"""
    try:
        text = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)
    except ValueError as error:
        raise CodecError("frame_invalid", "non_finite_number") from error
    return text.encode("utf-8")


def sha256_hex(data: bytes) -> str:
    """内容 sha256 十六进制。"""
    return hashlib.sha256(data).hexdigest()


def payload_hash(envelope: Mapping[str, Any]) -> str:
    """发件内容哈希：去掉 hub 盖章字段，保留 refs 与未知字段的原规范化值（§88.3）。"""
    content = {key: value for key, value in envelope.items() if key not in HUB_STAMPED_FIELDS}
    return sha256_hex(canonical_bytes(content))


def encode_frame(frame: Mapping[str, Any]) -> bytes:
    """一帧编码为规范化 JSON 加 LF；超限直接拒绝，不截断。"""
    kind = frame.get("type")
    if kind not in FRAME_TYPES:
        raise CodecError("frame_invalid", "unknown_type")
    data = canonical_bytes(dict(frame))
    if len(data) > MAX_FRAME_BYTES:
        raise CodecError("frame_too_large")
    return data + b"\n"


def decode_frame(line: bytes) -> dict[str, Any]:
    """解码一帧（不含结尾 LF）；类型必须在闭集里。"""
    if len(line) > MAX_FRAME_BYTES:
        raise CodecError("frame_too_large")
    frame = loads_strict(line)
    if frame.get("type") not in FRAME_TYPES:
        raise CodecError("frame_invalid", "unknown_type")
    request = frame.get("requestId")
    if request is not None and not is_hex32(request):
        raise CodecError("frame_invalid", "request_id")
    return frame


def read_frame(stream: IO[bytes]) -> dict[str, Any] | None:
    """从二进制流读一帧；EOF 返回 None。

    最多读 MAX_FRAME_BYTES+1 字节找 LF：还没遇到 LF 就超限说明帧过大，调用方必须关闭连接
    （流已停在一行中间，不能再续读）。读到 EOF 却没有 LF 是截断的帧。
    """
    line = stream.readline(MAX_FRAME_BYTES + 1)
    if not line:
        return None
    if not line.endswith(b"\n"):
        if len(line) > MAX_FRAME_BYTES:
            raise CodecError("frame_too_large")
        raise CodecError("frame_invalid", "truncated")
    return decode_frame(line[:-1])


def write_frame(stream: IO[bytes], frame: Mapping[str, Any]) -> None:
    """写一帧并 flush；编码失败时什么也不写。"""
    data = encode_frame(frame)
    stream.write(data)
    stream.flush()


def error_frame(code: str, *, request_id: str | None = None, retry_after_ms: int | None = None) -> dict[str, Any]:
    """闭集错误帧；不回显异常、SQL、命令或传入值。"""
    if code not in ERROR_CODES:
        raise ValueError(code)
    frame: dict[str, Any] = {"type": "error", "code": code, "retryable": code in RETRYABLE_ERRORS}
    if request_id is not None:
        frame["requestId"] = request_id
    if retry_after_ms is not None:
        frame["retryAfterMs"] = retry_after_ms
    return frame


def utf8_len(text: str) -> int:
    """UTF-8 字节数。"""
    return len(text.encode("utf-8"))


def free_text_bytes(envelope: Mapping[str, Any]) -> int:
    """信封里自由正文的总字节：body 加 data 里的 note（§88.3：禁止藏第二份正文绕过上限）。"""
    total = 0
    body = envelope.get("body")
    if isinstance(body, str):
        total += utf8_len(body)
    data = envelope.get("data")
    if isinstance(data, dict):
        note = data.get("note")  # pyright: ignore[reportUnknownMemberType,reportUnknownVariableType]
        if isinstance(note, str):
            total += utf8_len(note)
    return total


def _check_ref(item: object) -> None:
    if not isinstance(item, dict):
        raise CodecError("frame_invalid", "ref")
    ref: dict[str, Any] = item  # pyright: ignore[reportUnknownVariableType]
    if not is_hex32(ref.get("originDeviceId")):
        raise CodecError("frame_invalid", "ref_origin")
    for key in ("originalPath", "resolvedPath", "name"):
        value = ref.get(key)
        if not isinstance(value, str) or not value or len(value) > 4096 or any(ord(ch) < 32 for ch in value):
            raise CodecError("frame_invalid", f"ref_{key}")
    name = ref["name"]
    if "/" in name or "\\" in name or len(name) > 255:
        raise CodecError("frame_invalid", "ref_name")
    transfer = ref.get("transfer")
    if transfer not in REF_TRANSFERS:
        raise CodecError("frame_invalid", "ref_transfer")
    if not is_count(ref.get("size")):
        raise CodecError("frame_invalid", "ref_size")
    if transfer == "blob":
        if not is_hex64(ref.get("sha256")) or ref.get("reason") is not None or ref.get("hashState") != "frozen":
            raise CodecError("frame_invalid", "ref_blob")
        if ref["size"] > MAX_BLOB_BYTES:
            raise CodecError("attachment_too_large")
    else:
        if ref.get("sha256") is not None or ref.get("reason") not in REF_REASONS:
            raise CodecError("frame_invalid", "ref_reference")
        if ref.get("hashState") != "not_computed_size_limit":
            raise CodecError("frame_invalid", "ref_reference")


def check_refs(refs: object) -> list[dict[str, Any]]:
    """校验 refs：最多 16 项；blob 合计不超过 32 MiB。"""
    if not isinstance(refs, list):
        raise CodecError("frame_invalid", "refs")
    items: list[object] = refs  # pyright: ignore[reportUnknownVariableType]
    if len(items) > MAX_REFS:
        raise CodecError("frame_invalid", "refs_count")
    total = 0
    for item in items:
        _check_ref(item)
        assert isinstance(item, dict)
        if item.get("transfer") == "blob":  # pyright: ignore[reportUnknownMemberType]
            total += int(item["size"])  # pyright: ignore[reportUnknownArgumentType]
    if total > MAX_MESSAGE_BLOB_BYTES:
        raise CodecError("attachment_too_large")
    return items  # pyright: ignore[reportReturnType]


def check_envelope(envelope: Mapping[str, Any]) -> None:
    """信封通用形状（§88.3）：版本、ID、kind、时间、上限、refs、签名/加密必须为空。

    actor/target/authority 是否由正确的写者发出，属于业务核验，不在这里判。
    """
    if envelope.get("v") != 1:
        raise CodecError("frame_invalid", "version")
    for key in ("msg_id", "operationId", "targetDeviceId", "authorityDeviceId", "taskId"):
        if not is_hex32(envelope.get(key)):
            raise CodecError("frame_invalid", key)
    kind = envelope.get("kind")
    if kind not in ENVELOPE_KINDS:
        raise CodecError("frame_invalid", "kind")
    if not is_count(envelope.get("createdAt")) or not is_count(envelope.get("expiresAt")):
        raise CodecError("frame_invalid", "time")
    if not is_positive(envelope.get("authorityRevision")):
        raise CodecError("frame_invalid", "revision")
    attempt = envelope.get("attempt")
    if attempt is not None and not is_positive(attempt, maximum=64):
        raise CodecError("frame_invalid", "attempt")
    related = envelope.get("relatedMessageId")
    if related is not None and not is_hex32(related):
        raise CodecError("frame_invalid", "related")
    if envelope.get("senderClass") not in SENDER_CLASSES:
        raise CodecError("frame_invalid", "sender_class")
    title = envelope.get("title", "")
    if not isinstance(title, str) or len(title) > MAX_TITLE_CHARS:
        raise CodecError("frame_invalid", "title")
    body = envelope.get("body", "")
    if not isinstance(body, str):
        raise CodecError("frame_invalid", "body")
    data = envelope.get("data", {})
    if not isinstance(data, dict):
        raise CodecError("frame_invalid", "data")
    if free_text_bytes(envelope) > MAX_FREE_TEXT_BYTES:
        raise CodecError("frame_invalid", "free_text_too_large")
    check_refs(envelope.get("refs", []))
    if envelope.get("signature") is not None or envelope.get("encryption") is not None:
        # v1 只允许 null：看到非空值不能假装已经验证（§88.3）
        raise CodecError("capability_missing", "signature")
    if kind in ATTEMPT_KINDS and not isinstance(data.get("checkpoint"), dict):  # pyright: ignore[reportUnknownMemberType]
        raise CodecError("frame_invalid", "checkpoint_required")
    if len(canonical_bytes(dict(envelope))) > MAX_ENVELOPE_BYTES:
        raise CodecError("frame_invalid", "envelope_too_large")
