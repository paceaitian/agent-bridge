"""信封构造（DESIGN §88.3）：各写者按同一形状生成信封，固定 msg_id/operationId 与发件内容哈希。

信封一经写进 outbox 就不再改动；checkpoint 变化另发 task_state，不改变已用 msg_id 的哈希。
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from ..ids import new_id
from .codec import TRANSFER_TTL_MS, check_envelope, payload_hash
from .refs import Checkpoint, RemoteEndpointRef, WireActor


def build(
    *,
    kind: str,
    target_device: str,
    authority_device: str,
    task_id: str,
    revision: int,
    now: int,
    attempt: int | None = None,
    related: str | None = None,
    actor: WireActor | None = None,
    target: RemoteEndpointRef | None = None,
    sender_class: str = "unknown",
    title: str = "",
    body: str = "",
    refs: list[dict[str, Any]] | None = None,
    data: Mapping[str, Any] | None = None,
    msg_id: str | None = None,
    operation_id: str | None = None,
) -> tuple[dict[str, Any], str]:
    """返回 (信封, payloadHash)；形状不合法直接抛 CodecError，不写任何东西。"""
    envelope: dict[str, Any] = {
        "v": 1,
        "msg_id": msg_id or new_id(),
        "operationId": operation_id or new_id(),
        "kind": kind,
        "targetDeviceId": target_device,
        "authorityDeviceId": authority_device,
        "taskId": task_id,
        "attempt": attempt,
        "authorityRevision": revision,
        "relatedMessageId": related,
        "actor": actor.to_dict() if actor is not None else None,
        "target": target.to_dict() if target is not None else None,
        "senderClass": sender_class,
        "senderClassSource": "local-verifier",
        "createdAt": now,
        "expiresAt": now + TRANSFER_TTL_MS,
        "title": title[:120],
        "body": body,
        "refs": list(refs or []),
        "data": dict(data or {}),
        "signature": None,
        "encryption": None,
    }
    check_envelope(envelope)
    return envelope, payload_hash(envelope)


def checkpoint_data(checkpoint: Checkpoint, **extra: Any) -> dict[str, Any]:
    """attempt 类信封与 task_state 的 data：固定携带发送当时的 checkpoint。"""
    return {"checkpoint": checkpoint.to_dict(), **extra}
