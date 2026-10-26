"""联邦端点与任务快照（DESIGN §88.4/§88.6）：远端端点引用、目标的本机/远端联合、A 的有界 checkpoint。

远端端点没有 PID、pane、进程出生时刻和根路径，不伪装成本机 EndpointRef（不造 pid=0）。
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

from ..model import EndpointRef, Provider
from .codec import (
    MAX_CHECKPOINT_BYTES,
    MAX_TITLE_CHARS,
    CodecError,
    canonical_bytes,
    is_count,
    is_hex32,
    is_positive,
)

MAX_NATIVE_ID_CHARS = 128
MAX_WIRE_TOKEN_CHARS = 64
MAX_LABEL_CHARS = 120
CAPABILITIES = frozenset({"inbox", "eligible", "namesVerified"})
CONTROLS = frozenset({"active", "paused"})
VERDICTS = frozenset({"approved", "changes_requested"})
FLOWS = frozenset({"handoff", "review"})
ROLES = frozenset({"handoff", "review", "notice"})
NOTICE_KINDS = frozenset({"result", "reminder", "closure"})


def _native_id(value: object) -> str:
    # 完整原生 ID；`-` 不是身份（与本机 UNRESOLVED_NATIVE_ID 同口径）
    if not isinstance(value, str) or not value or value == "-" or len(value) > MAX_NATIVE_ID_CHARS:
        raise CodecError("frame_invalid", "native_id")
    if any(ch.isspace() or ord(ch) < 32 for ch in value):
        raise CodecError("frame_invalid", "native_id")
    return value


def _provider(value: object) -> Provider:
    try:
        return Provider(value)
    except ValueError as error:
        raise CodecError("frame_invalid", "provider") from error


def _token(value: object) -> str:
    if not isinstance(value, str) or not value or len(value) > MAX_WIRE_TOKEN_CHARS or any(ch.isspace() for ch in value):
        raise CodecError("frame_invalid", "wire_token")
    return value


@dataclass(frozen=True)
class RemoteEndpointRef:
    """另一台设备上的端点：身份是 deviceId+endpointId+provider/nativeId，标签不参与比较。"""

    device_id: str
    provider: Provider
    native_id: str
    endpoint_id: str
    endpoint_revision: int = 1
    display_label: str | None = field(default=None, compare=False)
    capabilities: tuple[str, ...] = field(default=(), compare=False)

    def to_dict(self) -> dict[str, Any]:
        """线上/账本形状。"""
        data: dict[str, Any] = {
            "deviceId": self.device_id,
            "provider": self.provider.value,
            "nativeId": self.native_id,
            "endpointId": self.endpoint_id,
            "endpointRevision": self.endpoint_revision,
        }
        if self.display_label is not None:
            data["displayLabel"] = self.display_label
        if self.capabilities:
            data["capabilities"] = list(self.capabilities)
        return data

    @classmethod
    def from_dict(cls, data: object) -> RemoteEndpointRef:
        """严格恢复；形状不对抛 CodecError，不猜测。"""
        if not isinstance(data, Mapping):
            raise CodecError("frame_invalid", "remote_ref")
        if not is_hex32(data.get("deviceId")) or not is_hex32(data.get("endpointId")):
            raise CodecError("frame_invalid", "remote_ref_id")
        revision = data.get("endpointRevision", 1)
        if not is_positive(revision):
            raise CodecError("frame_invalid", "remote_ref_revision")
        label = data.get("displayLabel")
        if label is not None and (not isinstance(label, str) or len(label) > MAX_LABEL_CHARS):
            raise CodecError("frame_invalid", "remote_ref_label")
        raw_caps = data.get("capabilities", [])
        if not isinstance(raw_caps, list):
            raise CodecError("frame_invalid", "remote_ref_caps")
        caps: list[object] = raw_caps  # pyright: ignore[reportUnknownVariableType]
        # 未知能力名忽略（向前兼容），但只保留闭集里的
        known = tuple(sorted({cap for cap in caps if isinstance(cap, str) and cap in CAPABILITIES}))
        return cls(
            device_id=str(data["deviceId"]),
            provider=_provider(data.get("provider")),
            native_id=_native_id(data.get("nativeId")),
            endpoint_id=str(data["endpointId"]),
            endpoint_revision=int(revision),  # pyright: ignore[reportArgumentType]
            display_label=label,
            capabilities=known,
        )

    def same_endpoint(self, other: RemoteEndpointRef) -> bool:
        """同一远端端点：deviceId 必须参与比较，同 UUID 不同设备不混。"""
        return (
            self.device_id == other.device_id
            and self.endpoint_id == other.endpoint_id
            and self.provider is other.provider
            and self.native_id == other.native_id
        )


@dataclass(frozen=True)
class WireActor:
    """逻辑发送者：在来源设备按 wire_ref 生成 wireToken 并随事实保存，下游不重造。"""

    device_id: str
    provider: Provider
    native_id: str
    wire_token: str
    endpoint_id: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """线上形状。"""
        data: dict[str, Any] = {
            "deviceId": self.device_id,
            "provider": self.provider.value,
            "nativeId": self.native_id,
            "wireToken": self.wire_token,
        }
        if self.endpoint_id is not None:
            data["endpointId"] = self.endpoint_id
        return data

    @classmethod
    def from_dict(cls, data: object) -> WireActor:
        """严格恢复。"""
        if not isinstance(data, Mapping):
            raise CodecError("frame_invalid", "actor")
        if not is_hex32(data.get("deviceId")):
            raise CodecError("frame_invalid", "actor_device")
        endpoint = data.get("endpointId")
        if endpoint is not None and not is_hex32(endpoint):
            raise CodecError("frame_invalid", "actor_endpoint")
        return cls(
            device_id=str(data["deviceId"]),
            provider=_provider(data.get("provider")),
            native_id=_native_id(data.get("nativeId")),
            wire_token=_token(data.get("wireToken")),
            endpoint_id=endpoint,  # pyright: ignore[reportArgumentType]
        )


@dataclass(frozen=True)
class TargetRef:
    """fed_attempts.target_json 的联合：本机目标存完整 EndpointRef，远端目标存 RemoteEndpointRef（§88.4）。

    对外（信封/checkpoint）一律投影成远端形状，本机字段不出网。
    """

    remote: RemoteEndpointRef
    local: EndpointRef | None = None

    @property
    def is_local(self) -> bool:
        return self.local is not None

    def to_dict(self) -> dict[str, Any]:
        """账本形状（含本机字段）。"""
        if self.local is not None:
            return {"kind": "local", "remote": self.remote.to_dict(), "local": self.local.to_dict()}
        return {"kind": "remote", "remote": self.remote.to_dict()}

    @classmethod
    def from_dict(cls, data: object) -> TargetRef:
        """严格恢复；本机形状缺字段视为损坏，不降级成远端。"""
        if not isinstance(data, Mapping):
            raise CodecError("frame_invalid", "target")
        remote = RemoteEndpointRef.from_dict(data.get("remote"))
        kind = data.get("kind")
        if kind == "remote":
            return cls(remote=remote)
        if kind == "local":
            local = EndpointRef.from_dict(data.get("local"))
            if local is None or local.provider is not remote.provider or local.native_id != remote.native_id:
                raise CodecError("frame_invalid", "target_local")
            return cls(remote=remote, local=local)
        raise CodecError("frame_invalid", "target_kind")


@dataclass(frozen=True)
class AttemptDefinition:
    """checkpoint 里的不可变 attempt 定义加 A 的控制请求与报告高水位；不含正文。"""

    seq: int
    msg_id: str
    role: str
    target: RemoteEndpointRef
    notice_kind: str | None = None
    cancel_requested: bool = False
    superseded: bool = False
    # A 已采纳的最高 reportNo（源设备按它判断哪些报告已被处理）
    report_high: int = 0

    def to_dict(self) -> dict[str, Any]:
        data: dict[str, Any] = {
            "seq": self.seq,
            "msgId": self.msg_id,
            "role": self.role,
            "target": self.target.to_dict(),
            "cancelRequested": self.cancel_requested,
            "superseded": self.superseded,
            "reportHigh": self.report_high,
        }
        if self.notice_kind is not None:
            data["noticeKind"] = self.notice_kind
        return data

    @classmethod
    def from_dict(cls, data: object) -> AttemptDefinition:
        if not isinstance(data, Mapping):
            raise CodecError("frame_invalid", "attempt_def")
        seq = data.get("seq")
        if not is_positive(seq, maximum=64) or not is_hex32(data.get("msgId")):
            raise CodecError("frame_invalid", "attempt_def_id")
        role = data.get("role")
        notice = data.get("noticeKind")
        if role not in ROLES or (notice is not None and (role != "notice" or notice not in NOTICE_KINDS)):
            raise CodecError("frame_invalid", "attempt_def_role")
        flags = (data.get("cancelRequested", False), data.get("superseded", False))
        if not all(isinstance(flag, bool) for flag in flags):
            raise CodecError("frame_invalid", "attempt_def_flags")
        high = data.get("reportHigh", 0)
        if not is_count(high):
            raise CodecError("frame_invalid", "attempt_def_high")
        return cls(
            seq=int(seq),  # pyright: ignore[reportArgumentType]
            msg_id=str(data["msgId"]),
            role=str(role),
            target=RemoteEndpointRef.from_dict(data.get("target")),
            notice_kind=notice,  # pyright: ignore[reportArgumentType]
            cancel_requested=bool(flags[0]),
            superseded=bool(flags[1]),
            report_high=int(high),  # pyright: ignore[reportArgumentType]
        )


def _optional_time(value: object, name: str) -> int | None:
    if value is None:
        return None
    if not is_count(value):
        raise CodecError("frame_invalid", name)
    return int(value)  # pyright: ignore[reportArgumentType]


@dataclass(frozen=True)
class Checkpoint:
    """A 的当前任务快照（§88.4）：有界、自包含，不含历史正文、报告正文、附件字节或本机 PID/路径。

    B 只应用更高 revision；同 revision 不同 hash 是 idempotency_conflict，不挑一份猜。
    """

    authority_device: str
    task_id: str
    revision: int
    title: str
    flow: str
    control: str
    max_seq: int
    current_work_seq: int | None
    attempts: tuple[AttemptDefinition, ...]
    members: tuple[str, ...]
    origin: WireActor | None = None
    reviewer: WireActor | None = None
    verdict: str | None = None
    accepted_at: int | None = None
    closed_at: int | None = None
    close_reason: str | None = None
    notify_origin: bool = True
    allow_shared: bool = False

    @property
    def finished(self) -> bool:
        return self.accepted_at is not None or self.closed_at is not None

    def attempt(self, seq: int) -> AttemptDefinition | None:
        """按序号取 attempt 定义。"""
        for item in self.attempts:
            if item.seq == seq:
                return item
        return None

    def to_dict(self) -> dict[str, Any]:
        data: dict[str, Any] = {
            "authorityDeviceId": self.authority_device,
            "taskId": self.task_id,
            "revision": self.revision,
            "title": self.title,
            "flow": self.flow,
            "control": self.control,
            "maxSeq": self.max_seq,
            "currentWorkSeq": self.current_work_seq,
            "attempts": [item.to_dict() for item in self.attempts],
            "members": list(self.members),
            "origin": self.origin.to_dict() if self.origin else None,
            "reviewer": self.reviewer.to_dict() if self.reviewer else None,
            "verdict": self.verdict,
            "acceptedAt": self.accepted_at,
            "closedAt": self.closed_at,
            "closeReason": self.close_reason,
            "notifyOrigin": self.notify_origin,
            "allowShared": self.allow_shared,
        }
        if len(canonical_bytes(data)) > MAX_CHECKPOINT_BYTES:
            raise CodecError("frame_invalid", "checkpoint_too_large")
        return data

    @classmethod
    def from_dict(cls, data: object) -> Checkpoint:
        if not isinstance(data, Mapping):
            raise CodecError("frame_invalid", "checkpoint")
        if len(canonical_bytes(dict(data))) > MAX_CHECKPOINT_BYTES:  # pyright: ignore[reportUnknownArgumentType]
            raise CodecError("frame_invalid", "checkpoint_too_large")
        if not is_hex32(data.get("authorityDeviceId")) or not is_hex32(data.get("taskId")):
            raise CodecError("frame_invalid", "checkpoint_id")
        revision = data.get("revision")
        max_seq = data.get("maxSeq")
        current = data.get("currentWorkSeq")
        if not is_positive(revision) or not is_count(max_seq, maximum=64):
            raise CodecError("frame_invalid", "checkpoint_seq")
        if current is not None and not is_positive(current, maximum=64):
            raise CodecError("frame_invalid", "checkpoint_current")
        title = data.get("title")
        if not isinstance(title, str) or len(title) > MAX_TITLE_CHARS:
            raise CodecError("frame_invalid", "checkpoint_title")
        flow, control, verdict = data.get("flow"), data.get("control"), data.get("verdict")
        if flow not in FLOWS or control not in CONTROLS or (verdict is not None and verdict not in VERDICTS):
            raise CodecError("frame_invalid", "checkpoint_enum")
        raw_attempts = data.get("attempts")
        raw_members = data.get("members")
        if not isinstance(raw_attempts, list) or not isinstance(raw_members, list):
            raise CodecError("frame_invalid", "checkpoint_lists")
        attempt_items: list[object] = raw_attempts  # pyright: ignore[reportUnknownVariableType]
        member_items: list[object] = raw_members  # pyright: ignore[reportUnknownVariableType]
        attempts = tuple(AttemptDefinition.from_dict(item) for item in attempt_items)
        seqs = [item.seq for item in attempts]
        if len(set(seqs)) != len(seqs) or any(seq > int(max_seq) for seq in seqs):  # pyright: ignore[reportArgumentType]
            raise CodecError("frame_invalid", "checkpoint_attempts")
        if not all(is_hex32(member) for member in member_items) or len(member_items) > 8:
            raise CodecError("frame_invalid", "checkpoint_members")
        reason = data.get("closeReason")
        if reason is not None and (not isinstance(reason, str) or len(reason) > 64):
            raise CodecError("frame_invalid", "checkpoint_reason")
        notify, shared = data.get("notifyOrigin", True), data.get("allowShared", False)
        if not isinstance(notify, bool) or not isinstance(shared, bool):
            raise CodecError("frame_invalid", "checkpoint_options")
        origin, reviewer = data.get("origin"), data.get("reviewer")
        return cls(
            authority_device=str(data["authorityDeviceId"]),
            task_id=str(data["taskId"]),
            revision=int(revision),  # pyright: ignore[reportArgumentType]
            title=title,
            flow=str(flow),
            control=str(control),
            max_seq=int(max_seq),  # pyright: ignore[reportArgumentType]
            current_work_seq=None if current is None else int(current),  # pyright: ignore[reportArgumentType]
            attempts=attempts,
            members=tuple(str(member) for member in member_items),
            origin=None if origin is None else WireActor.from_dict(origin),
            reviewer=None if reviewer is None else WireActor.from_dict(reviewer),
            verdict=verdict,  # pyright: ignore[reportArgumentType]
            accepted_at=_optional_time(data.get("acceptedAt"), "checkpoint_accepted"),
            closed_at=_optional_time(data.get("closedAt"), "checkpoint_closed"),
            close_reason=reason,  # pyright: ignore[reportArgumentType]
            notify_origin=notify,
            allow_shared=shared,
        )
