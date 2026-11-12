"""T5 旧读方预言机（§91 T5）：照搬 104f286 的 `federation/directory.py` 远端解析（device_row / _parse_selector /
resolve_remote）作为对照，用来证明新写方发出的目录被已发布的 W3.9/104f286 读方读到时，不会按被否证的名字选中。

除 import 外逐字照抄，不随产品改动；产品改了这里也不改。
"""

from __future__ import annotations

from typing import Any

from agentstatus_bridge.federation.fedstore import FederatedStore
from agentstatus_bridge.federation.refs import RemoteEndpointRef, TargetRef
from agentstatus_bridge.model import Provider

MAX_LABEL_CHARS = 120


class DirectoryError(Exception):
    """远端目标解析失败：remote_endpoint_unresolved / target_ambiguous / target_names_unverified / device_unknown。"""

    def __init__(self, code: str, candidates: tuple[str, ...] = ()) -> None:
        super().__init__(code)
        self.code = code
        self.candidates = candidates


def device_row(store: FederatedStore, reference: str) -> dict[str, Any]:
    """按登记 slug 或完整 deviceId 找缓存里的设备；没有就是 device_unknown。"""
    rows = [row for row in store.device_states() if reference in (row["device_id"], row["name"])]
    if len(rows) != 1:
        raise DirectoryError("device_unknown" if not rows else "target_ambiguous",
                             tuple(str(row["device_id"]) for row in rows))
    return rows[0]


def _parse_selector(selector: str) -> tuple[Provider | None, str, bool]:
    provider: Provider | None = None
    rest = selector.strip()
    if "@" in rest:
        prefix, rest = rest.split("@", 1)
        try:
            provider = Provider(prefix)
        except ValueError as error:
            raise DirectoryError("remote_endpoint_unresolved") from error
    exact = rest.startswith("id:")
    return provider, rest[3:] if exact else rest, exact


def resolve_remote(store: FederatedStore, device_reference: str, selector: str) -> TargetRef:
    """在 B 的缓存目录里解析 `--to`：`provider@id:<完整ID>` 精确；名字只在 namesVerified 且唯一时可用。

    stale/offline 的已验证绑定也可排队（输出等 B 复核）；从未见过的 UUID 报 remote_endpoint_unresolved，不按名字猜。
    """
    device = device_row(store, device_reference)
    provider, value, exact = _parse_selector(selector)
    entries = [item for item in device["snapshot"].get("endpoints") or [] if isinstance(item, dict)]
    if provider is not None:
        entries = [item for item in entries if item.get("provider") == provider.value]
    if exact or len(value) >= 32:
        matches = [item for item in entries if str(item.get("nativeId", "")).lower() == value.lower()]
    else:
        # 名字只在目录完整（相关 provider 都报完整）时才能当唯一：没收齐的同名端点无法参与消歧
        snapshot_data = device["snapshot"]
        providers = snapshot_data.get("providers") or {}
        relevant = [provider.value] if provider is not None else list(providers)
        if snapshot_data.get("complete") is not True or any(providers.get(key) is False for key in relevant):
            raise DirectoryError("remote_directory_incomplete")
        named = [item for item in entries if item.get("name") == value]
        if named and not all(item.get("namesVerified") for item in named):
            raise DirectoryError("target_names_unverified")
        matches = named
    if not matches:
        raise DirectoryError("remote_endpoint_unresolved")
    if len(matches) > 1:
        raise DirectoryError("target_ambiguous", tuple(f"{item['provider']}@id:{item['nativeId']}" for item in matches))
    item = matches[0]
    if item.get("inbox") is False:
        raise DirectoryError("target_no_inbox")
    remote = RemoteEndpointRef(device_id=str(device["device_id"]), provider=Provider(item["provider"]),
                               native_id=str(item["nativeId"]), endpoint_id=str(item["endpointId"]),
                               endpoint_revision=int(item.get("endpointRevision") or 1),
                               display_label=str(item["name"])[:MAX_LABEL_CHARS] if item.get("name") else None)
    return TargetRef(remote=remote)
