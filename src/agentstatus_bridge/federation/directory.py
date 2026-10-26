"""端点、绑定与整帧目录（DESIGN §88.6）：本机发现结果 → 最小公开目录；远端目标按缓存目录解析。

endpointId 由所属设备按 (provider, nativeId, 本机根绑定) 持久分配：同根恢复更新 revision 不换 ID，换根换新 ID。
根摘要只留本机，不发网络。目录只公开 provider/完整 ID/绑定标识/名字/收件能力/eligible/namesVerified 与 provider
完整性，不发 cwd、PID、进程路径、pipe/key、transcript；超预算标 complete=false，不截断后谎称完整。
"""

from __future__ import annotations

import hashlib
import json
import os
from collections.abc import Iterable, Mapping
from pathlib import Path
from typing import Any

from ..endpoints import ADAPTERS, Endpoint
from ..model import EndpointRef, Provider
from ..paths import claude_sessions_dirs, codex_home, grok_home
from ..platforms.factory import get_platform
from .codec import canonical_bytes
from .fedstore import FederatedStore
from .refs import RemoteEndpointRef, TargetRef

MAX_ENDPOINTS = 256
MAX_ENDPOINT_BYTES = 2048
MAX_SNAPSHOT_BYTES = 768 * 1024
MAX_LABEL_CHARS = 120
FRESH_MS = 90_000


class DirectoryError(Exception):
    """远端目标解析失败：remote_endpoint_unresolved / target_ambiguous / target_names_unverified / device_unknown。"""

    def __init__(self, code: str, candidates: tuple[str, ...] = ()) -> None:
        super().__init__(code)
        self.code = code
        self.candidates = candidates


def _digest_path(path: Path) -> str:
    try:
        real = os.path.realpath(path)
        info = os.stat(real)
        material = f"{real}\0{info.st_dev}\0{info.st_ino}"
    except OSError:
        material = f"{os.path.realpath(path)}\0missing"
    return hashlib.sha256(material.encode("utf-8")).hexdigest()[:32]


def root_binding(ref: EndpointRef) -> str | None:
    """端点实际所属的 provider 根摘要（只留本机）；核实不了返回 None（不发布成可用绑定，投递时按换根拒绝）。

    Windows 复用现行 dataRoot 身份；Linux Claude 取注册记录与这个端点同 pid、同 sessionId、同进程代际（procStart）
    的那个根（§84 多根，和发现时同一判据，旧代际残留不算）；Codex/Grok 取 provider 家目录的规范路径与 dev/inode
    摘要（本进程环境里的家目录；relay/worker/CLI 环境不一致时投递按换根拒绝，不会投错）。不用默认根补齐。
    """
    if get_platform().name == "windows":
        return hashlib.sha256((ref.data_root or "").encode("utf-8")).hexdigest()[:32]
    if ref.provider is Provider.CLAUDE:
        for root in claude_sessions_dirs():
            registry = root / f"{ref.pid}.json"
            try:
                data = json.loads(registry.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                continue
            if (isinstance(data, dict) and data.get("sessionId") == ref.native_id  # pyright: ignore[reportUnknownMemberType]
                    and data.get("pid") == ref.pid and data.get("procStart") == ref.start_ticks):  # pyright: ignore[reportUnknownMemberType]
                return _digest_path(root)
        return None
    if ref.provider is Provider.CODEX:
        return _digest_path(codex_home())
    return _digest_path(grok_home())


def bind_local(store: FederatedStore, ident_device: str, ref: EndpointRef, *, label: str | None = None) -> TargetRef:
    """本机端点 → TargetRef（本机字段 + 对外远端投影）；分配或复用持久 endpointId。根核实不了报 target_root_unverified。"""
    binding = root_binding(ref)
    if binding is None:
        raise DirectoryError("target_root_unverified")
    endpoint_id, revision = store.bind_endpoint(provider=ref.provider.value, native_id=ref.native_id,
                                                root_binding=binding, local_ref=ref.to_dict())
    text = label or ref.label
    remote = RemoteEndpointRef(device_id=ident_device, provider=ref.provider, native_id=ref.native_id,
                               endpoint_id=endpoint_id, endpoint_revision=revision,
                               display_label=text[:MAX_LABEL_CHARS] if text else None)
    return TargetRef(remote=remote, local=ref)


def snapshot(store: FederatedStore, device_id: str, endpoints: Iterable[Endpoint], *,
             publish_names: bool = True, provider_complete: Mapping[str, bool] | None = None) -> dict[str, Any]:
    """整帧目录：每个本机端点一行（绑定标识、名字、收件能力、eligible）；超预算标 incomplete。"""
    rows: list[dict[str, Any]] = []
    reason = None
    for endpoint in endpoints:
        ref = endpoint.ref
        try:
            target = bind_local(store, device_id, ref, label=endpoint.name)
        except DirectoryError:
            reason = "root_unverified"  # 这一行不发布；目录因此不完整，名字不能据此唯一选中
            continue
        name = (endpoint.name or ref.label) if publish_names else None
        row: dict[str, Any] = {
            "provider": ref.provider.value, "nativeId": ref.native_id, "endpointId": target.remote.endpoint_id,
            "endpointRevision": target.remote.endpoint_revision, "inbox": ADAPTERS[ref.provider].inbox,
            "eligible": not endpoint.blocking_issues, "namesVerified": endpoint.name is not None and publish_names,
        }
        if name:
            row["name"] = name[:MAX_LABEL_CHARS]
        if len(canonical_bytes(row)) > MAX_ENDPOINT_BYTES:
            reason = "endpoint_too_large"
            continue
        if len(rows) >= MAX_ENDPOINTS:
            reason = "too_many_endpoints"
            break
        rows.append(row)
    providers = {key: bool(value) for key, value in (provider_complete or {}).items()}
    complete = reason is None and all(providers.values())
    document: dict[str, Any] = {"endpoints": rows, "complete": complete, "providers": providers}
    if reason is not None:
        document["reason"] = reason
    while len(canonical_bytes(document)) > MAX_SNAPSHOT_BYTES and rows:
        rows.pop()
        document.update(complete=False, reason="snapshot_too_large")
    return document


# ---- 远端解析 ----


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


def peer_devices(store: FederatedStore, device_reference: str | None, *, now: int) -> list[dict[str, Any]]:
    """`peers --device B` / `--all-devices` 的 JSON：remote 行用 scope/remoteRef，不伪造本机进程字段。

    online 只在缓存 ≤90 秒且 hub 报在线时为真；eligible 不等于当前在线（§88.6）。
    """
    rows = store.device_states() if device_reference is None else [device_row(store, device_reference)]
    devices: list[dict[str, Any]] = []
    for row in rows:
        seen = row.get("last_seen")
        fresh = isinstance(seen, int) and now - seen <= FRESH_MS and row["state"] == "online"
        snapshot_data = row["snapshot"]
        peers: list[dict[str, Any]] = []
        for item in snapshot_data.get("endpoints") or []:
            if not isinstance(item, dict):
                continue
            provider, native = str(item.get("provider")), str(item.get("nativeId", ""))
            peers.append({
                "scope": "remote", "device": row["name"],
                "remoteRef": {"deviceId": row["device_id"], "provider": provider, "nativeId": native,
                              "endpointId": item.get("endpointId"), "endpointRevision": item.get("endpointRevision")},
                "name": item.get("name"), "inbox": item.get("inbox", True) is not False,
                "eligible": item.get("eligible", True) is not False, "namesVerified": item.get("namesVerified") is True,
                "target": f"--device {row['name']} --to {provider}@id:{native}",
            })
        devices.append({"device": row["name"], "deviceId": row["device_id"], "online": fresh,
                        "state": "revoked" if row["state"] == "revoked" else ("online" if fresh else "unknown"),
                        "lastSeen": seen if isinstance(seen, int) else None,
                        "complete": snapshot_data.get("complete") is True, "peers": peers})
    return devices


def peer_lines(store: FederatedStore, device_reference: str | None, *, now: int) -> list[str]:
    """文字版：按设备展示缓存目录，附可直接复制的完整目标。"""
    lines: list[str] = []
    for device in peer_devices(store, device_reference, now=now):
        state = {"online": "在线", "revoked": "已撤销"}.get(device["state"], "离线或未知")
        complete = "完整" if device["complete"] else "不完整"
        lines.append(f"设备 {device['device']}〔{str(device['deviceId'])[:8]}〕：{state}，目录{complete}")
        for peer in device["peers"]:
            ref = peer["remoteRef"]
            name = peer["name"] or ref["nativeId"][:8]
            flags = [] if peer["inbox"] else ["只读"]
            if not peer["eligible"]:
                flags.append("暂不可投")
            suffix = f"  （{'、'.join(flags)}）" if flags else ""
            lines.append(f"  {ref['provider']}@{name}〔{ref['nativeId'][:8]}〕 device={device['device']}"
                         f" target={peer['target']}{suffix}")
    return lines
