"""端点、绑定与整帧目录（DESIGN §88.6）：本机发现结果 → 最小公开目录；远端目标按缓存目录解析。

endpointId 由所属设备按 (provider, nativeId, 本机根绑定) 持久分配：同根恢复更新 revision 不换 ID，换根换新 ID。
根摘要只留本机，不发网络。目录只公开 provider/完整 ID/绑定标识/名字/收件能力/eligible/namesVerified 与 provider
完整性，以及可选的工作目录末段 workdir（§95.3，与名字共用 publish_names）；不发完整 cwd、PID、进程路径、pipe/key、
transcript；超预算标 complete=false，不截断后谎称完整（workdir 是附加信息，超预算时先静默去掉，不改完整性）。

名字（§91.4.1）：每行最多一个原生主名，只取端点携带的本轮 NameView（name 是可复制主名、displayName 是转义展示名、
namesVerified 是主名已核实）；不回退 Endpoint.name、tmux 会话名、pane 或 Windows alias。快照带 namePolicy。
"""

from __future__ import annotations

import hashlib
import json
import os
from collections.abc import Iterable, Mapping
from pathlib import Path
from typing import Any

from ..endpoints import ADAPTERS, Endpoint
from ..model import UNRESOLVED_NATIVE_ID, EndpointRef, Provider
from ..native_names import (TARGET_ID_UNVERIFIED, TARGET_PROVIDER_REQUIRED, UUID_SHAPE, SelectorError,
                            id_prefixes, parse_selector, remote_display, remote_workdir, workdir_suffix, workdir_text)
from ..paths import claude_sessions_dirs, codex_home, grok_home
from ..platforms.factory import get_platform
from .codec import CodecError, canonical_bytes, is_hex32, is_slug
from .fedstore import FederatedStore
from .refs import RemoteEndpointRef, TargetRef, verified_label

MAX_ENDPOINTS = 256
MAX_ENDPOINT_BYTES = 2048
MAX_SNAPSHOT_BYTES = 768 * 1024
MAX_LABEL_CHARS = 120
FRESH_MS = 90_000
# last_seen 是 hub 的时刻、now 是本机时刻：hub 钟略快会算出小的负年龄。owner 2026-11-12 定容忍 5 秒（§91.9 D-B）
CLOCK_SKEW_MS = 5_000
NAME_POLICY = "agent-native-v1"
# 对端目录里选中的那一行记录不合法（§103.3 第 4 条）：只出现在 stderr/--json，不进账本；target_ 前缀与两平台的
# EXIT_TARGET 口径一致（联邦路径由 commands.remote_target 显式给退出码 2）
TARGET_REMOTE_INVALID = "target_remote_invalid"
# 本版对端能处理的可选能力，随目录快照发布（可选键 features）；发起方据此决定能不能发跨设备告知（§95.5.7）。
# ask（§104.9 五）：本设备作为发起设备时认汇报帧的可选键 ask（提问会叫醒发起方）；执行方据此决定要不要提示「可能不会叫醒」
FEATURES: tuple[str, ...] = ("fyi", "ask")


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


def published_name(endpoint: Endpoint | None, *, publish_names: bool) -> str | None:
    """可作远端人读旁注的名字：本轮已核实、可复制的原生主名，且发布开关打开；否则 None（§91.4.2/91.4.3）。"""
    view = endpoint.name_view if endpoint is not None and publish_names else None
    return view.name if view is not None and view.verified and view.name is not None else None


def bind_local(store: FederatedStore, ident_device: str, ref: EndpointRef, *, verified_name: str | None) -> TargetRef:
    """本机端点 → TargetRef（本机字段 + 对外远端投影）；分配或复用持久 endpointId。根核实不了报 target_root_unverified。

    displayLabel 只取调用方给的已核实原生主名（published_name），不回退 ref.label——它在 Windows 上可能是本机 alias。
    """
    binding = root_binding(ref)
    if binding is None:
        raise DirectoryError("target_root_unverified")
    endpoint_id, revision = store.bind_endpoint(provider=ref.provider.value, native_id=ref.native_id,
                                                root_binding=binding, local_ref=ref.to_dict())
    label = verified_name if verified_name is not None and len(verified_name) <= MAX_LABEL_CHARS else None
    remote = RemoteEndpointRef(device_id=ident_device, provider=ref.provider, native_id=ref.native_id,
                               endpoint_id=endpoint_id, endpoint_revision=revision, display_label=label)
    return TargetRef(remote=remote, local=ref)


def snapshot(store: FederatedStore, device_id: str, endpoints: Iterable[Endpoint], *,
             publish_names: bool = True, provider_complete: Mapping[str, bool] | None = None,
             ids_complete: Mapping[str, bool] | None = None) -> dict[str, Any]:
    """整帧目录：每个本机端点一行（绑定标识、名字、收件能力、eligible）；超预算标 incomplete。

    名字的证明与否证已在发现时对全集算好（NameView），这里只投影：先对全集定名，再按预算降级，不先裁冲突证据。
    单行超限时先丢名字（降为纯 ID、namesVerified=false）保住身份，并标快照不完整；名字本身超过 120 字符也只丢名字。
    工作目录末段 workdir（§95.3）与名字共用 publish_names；单行或整份超限时都先静默去掉 workdir（不改 reason、
    complete），仍超才走原有降级。顶层能力表 features（§95.5.7）最后才丢：整份超限的顺序是 workdir → 端点行
    （标 snapshot_too_large）→ features；它只有几十字节，丢了跨设备告知就发不出去，所以排在掉行之后。

    完整性分两层（§94.1）：provider_complete 是各 provider 本轮来源是否看全，ids_complete 是身份全集里有没有
    认不出、又不能排除是根会话的端点（缺省或缺键视为完整）。providers[p] 取两者之与，只拒该 provider 的名字与
    前缀；顶层 complete 只看来源与预算，不因某家身份不全连带拒掉别家。
    """
    rows: list[dict[str, Any]] = []
    reason = None
    for endpoint in endpoints:
        ref = endpoint.ref
        view = endpoint.name_view if publish_names else None
        try:
            target = bind_local(store, device_id, ref, verified_name=published_name(endpoint, publish_names=publish_names))
        except DirectoryError:
            reason = "root_unverified"  # 这一行不发布；目录因此不完整，名字不能据此唯一选中
            continue
        row: dict[str, Any] = {
            "provider": ref.provider.value, "nativeId": ref.native_id, "endpointId": target.remote.endpoint_id,
            "endpointRevision": target.remote.endpoint_revision, "inbox": ADAPTERS[ref.provider].inbox,
            "eligible": not endpoint.blocking_issues, "namesVerified": False,
        }
        if view is not None and view.name is not None and len(view.name) <= MAX_LABEL_CHARS:
            row.update(name=view.name, namesVerified=view.verified)
        if view is not None and view.display_name:
            row["displayName"] = view.display_name  # display_text 已转义并限 120 字符
        workdir = workdir_text(endpoint.workdir) if publish_names else None
        if workdir is not None:
            row["workdir"] = workdir  # 与 displayName 同样转义、限 120 字符
            if len(canonical_bytes(row)) > MAX_ENDPOINT_BYTES:
                del row["workdir"]  # 附加信息：先静默去掉，不改 reason/complete
        if len(canonical_bytes(row)) > MAX_ENDPOINT_BYTES:
            for key in ("name", "displayName"):
                row.pop(key, None)
            row["namesVerified"] = False
            reason = "endpoint_too_large"
            if len(canonical_bytes(row)) > MAX_ENDPOINT_BYTES:
                continue  # 连纯 ID 都放不下：不发布这一行
        if len(rows) >= MAX_ENDPOINTS:
            reason = "too_many_endpoints"
            break
        rows.append(row)
    sources = {key: bool(value) for key, value in (provider_complete or {}).items()}
    identities = ids_complete or {}
    providers = {key: value and bool(identities.get(key, True)) for key, value in sources.items()}
    complete = reason is None and all(sources.values())
    document: dict[str, Any] = {"endpoints": rows, "complete": complete, "providers": providers,
                                "namePolicy": NAME_POLICY, "features": list(FEATURES)}
    if reason is not None:
        document["reason"] = reason
    if len(canonical_bytes(document)) > MAX_SNAPSHOT_BYTES:
        for row in rows:
            row.pop("workdir", None)  # 整份超限也先去掉全部 workdir 再量，不因附加信息掉行或改完整性
    while len(canonical_bytes(document)) > MAX_SNAPSHOT_BYTES and rows:
        rows.pop()
        document.update(complete=False, reason="snapshot_too_large")
    if len(canonical_bytes(document)) > MAX_SNAPSHOT_BYTES:
        document.pop("features", None)  # 行已掉光仍超限：最后才丢能力表（对端按不支持处理，只是拒发告知）
    return document


def device_features(store: FederatedStore, device_id: str) -> frozenset[str]:
    """缓存目录里该设备声明的能力（可选键 features）；旧版本不发这个键，按空集（DESIGN §95.5.7）。"""
    for row in store.device_states():
        if row["device_id"] != device_id:
            continue
        snapshot_data = row["snapshot"] if isinstance(row.get("snapshot"), dict) else {}
        raw = snapshot_data.get("features")
        if isinstance(raw, list):
            return frozenset(item for item in raw if isinstance(item, str))  # pyright: ignore[reportUnknownVariableType]
    return frozenset()


# ---- 远端解析 ----


def device_row(store: FederatedStore, reference: str) -> dict[str, Any]:
    """按登记 slug 或完整 deviceId 找缓存里的设备；没有就是 device_unknown。"""
    rows = [row for row in store.device_states() if reference in (row["device_id"], row["name"])]
    if len(rows) != 1:
        raise DirectoryError("device_unknown" if not rows else "target_ambiguous",
                             tuple(str(row["device_id"]) for row in rows))
    return rows[0]


def fresh(device: Mapping[str, Any], *, now: int) -> bool:
    """目录可用于名字/前缀：hub 报在线，且缓存年龄在 [−5 秒, 90 秒]（§91.2.2；负侧容忍两端时钟的小偏差）；
    更大的负年龄与缺字段都不猜。"""
    seen = device.get("last_seen")
    return (device.get("state") == "online" and isinstance(seen, int) and not isinstance(seen, bool)
            and -CLOCK_SKEW_MS <= now - seen <= FRESH_MS)


def _relevant_complete(snapshot_data: Mapping[str, Any], entries: list[dict[str, Any]], provider: Provider | None) -> bool:
    """名字/前缀要求相关 provider 明确完整：快照 complete 为 true，相关 provider 的完整性必须是布尔 true（缺键不算）。

    相关集合取自快照本身（providers 的键并上行里出现的 provider），不取本机枚举：Windows 只发 codex/claude。
    """
    if snapshot_data.get("complete") is not True:
        return False
    raw = snapshot_data.get("providers")
    providers: dict[str, Any] = dict(raw) if isinstance(raw, dict) else {}  # pyright: ignore[reportUnknownArgumentType]
    if provider is not None:
        relevant = {provider.value}
    else:
        relevant = {key for key in providers if isinstance(key, str)} | {str(item.get("provider")) for item in entries}
    return all(providers.get(key) is True for key in relevant)


def _full_id(item: Mapping[str, Any]) -> str:
    return f"{item.get('provider')}@id:{item.get('nativeId')}"


def resolve_remote(store: FederatedStore, device_reference: str, selector: str, *, now: int) -> TargetRef:
    """在 B 的缓存目录里解析 `--to`（§91.2.2）。错误顺序：设备 → 语法/名字须带 provider → 目录完整性 → fresh/online
    → 匹配与名字核实 → 收件资格。

    - 完整 ID（`id:<完整>` 或裸完整 UUID）精确匹配已观察绑定，跳过完整性与时效门；stale/offline 的已验证绑定照样排队，
      由 B 复核；从未见过的 ID 报 remote_endpoint_unresolved，不按名字猜。
    - `id:` 前缀要求相关 provider 明确完整且目录新鲜，否则 remote_directory_incomplete / target_id_unverified。
    - 名字必须带 provider（target_provider_required），只匹配原生主名：规范值命中的每一行都须过 verified_label（逐字
      相等、namesVerified 明确为 true、≤120、copyable），不能先丢掉未核实行再算唯一（§103.3 第 3 条）。
    - 选定的那一行按账本形状严格构造，坏记录报 target_remote_invalid（§103.3 第 4 条）。
    - 历史帧（无或未知 namePolicy）按旧字段理解，不追认来源，但补上同样的门；带 provider、≥32 字符的值沿旧启发式按
      nativeId 精确匹配。
    """
    device = device_row(store, device_reference)
    try:
        wanted = parse_selector(selector)
    except SelectorError as error:
        raise DirectoryError(error.args[0]) from None
    snapshot_data = device["snapshot"] if isinstance(device.get("snapshot"), dict) else {}
    legacy = snapshot_data.get("namePolicy") != NAME_POLICY
    entries = [item for item in snapshot_data.get("endpoints") or [] if isinstance(item, dict)]
    pool = [item for item in entries if wanted.provider is None or item.get("provider") == wanted.provider.value]
    if wanted.kind == "name" and wanted.provider is None:
        raise DirectoryError(TARGET_PROVIDER_REQUIRED)
    if wanted.kind == "id" or (legacy and wanted.kind == "name" and len(wanted.value) >= 32):
        matches = [item for item in pool if str(item.get("nativeId", "")).lower() == wanted.value.lower()]
    else:
        if not _relevant_complete(snapshot_data, entries, wanted.provider):
            raise DirectoryError("remote_directory_incomplete")
        if not fresh(device, now=now):
            raise DirectoryError(TARGET_ID_UNVERIFIED if wanted.kind == "prefix" else "target_names_unverified")
        if wanted.kind == "prefix":
            matches = [item for item in pool if str(item.get("nativeId", "")).lower().startswith(wanted.value)]
        else:
            named = [item for item in pool if isinstance(item.get("name"), str) and item["name"].strip() == wanted.value]
            # 命中的每一行都须过共用判据（已核实、逐字相等、≤120、copyable），与 peers 文字行写成 provider@名字的条件
            # 相同：peers 标「仅展示」的名字在这里也不能按名字选中，新旧帧同一口径（§103.3 第 3 条）
            if any(verified_label(item["name"], item.get("namesVerified")) != wanted.value for item in named):
                raise DirectoryError("target_names_unverified", tuple(_full_id(item) for item in named))
            matches = named
    if not matches:
        raise DirectoryError("remote_endpoint_unresolved")
    if len(matches) > 1:
        raise DirectoryError("target_ambiguous", tuple(_full_id(item) for item in matches))
    item = matches[0]
    if item.get("inbox") is False:
        raise DirectoryError("target_no_inbox")
    # 目录快照逐项不经校验（hub 只限 dict 与大小、relay 原样存）：选定后按账本同一严格形状构造，坏记录（nativeId 含
    # 空白/控制字符或超长、provider 未知、endpointId/endpointRevision 不合规）在这里干净拒绝，不等入库回读时报
    # corrupt_record、也不打 traceback（§103.3 第 4 条）
    try:
        remote = RemoteEndpointRef.from_dict({
            "deviceId": device["device_id"], "provider": item.get("provider"), "nativeId": item.get("nativeId"),
            "endpointId": item.get("endpointId"), "endpointRevision": item.get("endpointRevision") or 1,
            "displayLabel": verified_label(item.get("name"), item.get("namesVerified"))})
    except CodecError:
        raise DirectoryError(TARGET_REMOTE_INVALID) from None
    return TargetRef(remote=remote)


def peer_devices(store: FederatedStore, device_reference: str | None, *, now: int) -> list[dict[str, Any]]:
    """`peers --device B` / `--all-devices` 的 JSON：remote 行用 scope/remoteRef，不伪造本机进程字段。

    online 只在缓存 ≤90 秒且 hub 报在线时为真；eligible 不等于当前在线（§88.6）。
    """
    rows = store.device_states() if device_reference is None else [device_row(store, device_reference)]
    devices: list[dict[str, Any]] = []
    for row in rows:
        seen = row.get("last_seen")
        online = fresh(row, now=now)
        snapshot_data = row["snapshot"] if isinstance(row.get("snapshot"), dict) else {}
        raw_providers = snapshot_data.get("providers")
        # 原样转述快照里各 provider 的完整性表（§94.1 增量键）；历史快照没有就是空表
        providers: dict[str, Any] = dict(raw_providers) if isinstance(raw_providers, dict) else {}  # pyright: ignore[reportUnknownArgumentType]
        # 可复制的 --device 值：登记 slug，没有就用完整 deviceId（device_row 两者都认；8 位前缀解析不了）
        reference = str(row["name"] or row["device_id"])
        peers: list[dict[str, Any]] = []
        for item in snapshot_data.get("endpoints") or []:
            if not isinstance(item, dict):
                continue
            provider, native = str(item.get("provider")), str(item.get("nativeId", ""))
            peers.append({
                "scope": "remote", "device": row["name"],
                "remoteRef": {"deviceId": row["device_id"], "provider": provider, "nativeId": native,
                              "endpointId": item.get("endpointId"), "endpointRevision": item.get("endpointRevision")},
                "name": item.get("name"), "displayName": item.get("displayName"),
                # §95.3 新键：只认字符串，去掉控制/格式字符并限长后才输出（旧字段维持 §94.5 登记，不在这里改）
                "workdir": remote_workdir(item.get("workdir")),
                "inbox": item.get("inbox", True) is not False,
                "eligible": item.get("eligible", True) is not False, "namesVerified": item.get("namesVerified") is True,
                "target": f"--device {reference} --to {provider}@id:{native}",
            })
        devices.append({"device": row["name"], "deviceId": row["device_id"], "online": online,
                        "state": "revoked" if row["state"] == "revoked" else ("online" if online else "unknown"),
                        "lastSeen": seen if isinstance(seen, int) else None,
                        "complete": snapshot_data.get("complete") is True, "providers": providers,
                        "namePolicy": snapshot_data.get("namePolicy"), "peers": peers})
    return devices


def _shown_ids(row: Mapping[str, Any], *, now: int) -> dict[tuple[str, str], str]:
    """peers 文字里的消歧 ID（§91.4.2）：该 provider 目录明确完整且新鲜时取缓存全集上的最短唯一前缀，否则完整 ID。"""
    snapshot_data = row["snapshot"] if isinstance(row.get("snapshot"), dict) else {}
    entries = [item for item in snapshot_data.get("endpoints") or [] if isinstance(item, dict)]
    live = fresh(row, now=now)
    shown: dict[tuple[str, str], str] = {}
    for name in {str(item.get("provider")) for item in entries}:
        try:
            complete = live and _relevant_complete(snapshot_data, entries, Provider(name))
        except ValueError:
            complete = False
        ids = [str(item.get("nativeId", "")) for item in entries if str(item.get("provider")) == name]
        shown.update(((name, native), prefix) for native, prefix in id_prefixes(ids, complete=complete).items())
    return shown


_PROVIDER_KEYS = frozenset(provider.value for provider in Provider)


def _completeness_text(device: Mapping[str, Any]) -> str:
    """设备行的目录完整性（§94.1）：顶层不完整照旧写「不完整」；顶层完整但有 provider 未核全时写部分完整。

    未核全的集合与 _relevant_complete 同口径：providers 的键并上行里出现的 provider，值不是明确 true（含缺键、非布尔）
    即未核全，它们的名字与前缀、以及不带 provider 的前缀都解析不了。文字只列本机认识的 provider 名，对端快照里的
    其他字符串（可能含换行、控制字符）一律合并成「其他」，不原样输出。
    """
    if not device["complete"]:
        return "不完整"
    providers: Mapping[Any, Any] = device["providers"]
    relevant = {key for key in providers if isinstance(key, str)} | {
        str(peer["remoteRef"]["provider"]) for peer in device["peers"]}
    pending = {key for key in relevant if providers.get(key) is not True}
    shown = sorted(pending & _PROVIDER_KEYS) + (["其他"] if pending - _PROVIDER_KEYS else [])
    if not shown:
        return "完整"
    names = "、".join(shown)
    # 远端裸名本来就报 target_provider_required，与完整性无关；这里只列因未核全而不可用的写法（§101.1）
    return f"部分完整（{names} 未核全：{names} 的名字/前缀与不带 provider 的前缀不可用，只能用完整 ID）"


def _copyable_device(device: Mapping[str, Any]) -> str | None:
    """文字行 target= 里的 --device：登记 slug；不是 slug 就退回 32 位十六进制 deviceId（device_row 两者都认），都不是则无。"""
    if is_slug(device["device"]):
        return str(device["device"])
    return str(device["deviceId"]) if is_hex32(device["deviceId"]) else None


def peer_lines(store: FederatedStore, device_reference: str | None, *, now: int) -> list[str]:
    """文字版：按设备展示缓存目录，附可直接复制的完整目标。

    对端给的字符串（设备名、deviceId、provider、nativeId、名字、展示名）一律经 remote_display 转义后才进文字（§101.1）；
    工作目录末段已由 remote_workdir 去掉同一类字符（§95.3）。target= 只由已校验的值拼成：provider 在枚举内、nativeId 是
    UUID 形状（选择器能照抄的唯一完整 ID 形状），--device 取 _copyable_device；判不过的行不给 target=、标出原因：
    「provider 未知」「ID 无效」「设备引用无效」。合法行不得被标成无效：各 provider 的会话 ID 都是 UUID（Claude/Codex
    含子代理与 daemon 线程、Grok 只读行），对端未解析的会话（nativeId 为「-」）照旧显示与旗标，只是没有可照抄的
    完整 ID、不给 target=。--json（peer_devices）不经这里，照给原值。
    """
    lines: list[str] = []
    rows = {str(row["device_id"]): row for row in (store.device_states() if device_reference is None
                                                   else [device_row(store, device_reference)])}
    for device in peer_devices(store, device_reference, now=now):
        shown_ids = _shown_ids(rows.get(str(device["deviceId"])) or {}, now=now)
        state = {"online": "在线", "revoked": "已撤销"}.get(device["state"], "离线或未知")
        device_id = str(device["deviceId"])
        name_text = remote_display(device["device"]) or ""
        lines.append(f"设备 {name_text}〔{remote_display(device_id[:8]) or ''}〕：{state}，目录{_completeness_text(device)}")
        where = name_text or remote_display(device_id) or ""
        reference = _copyable_device(device)
        for peer in device["peers"]:
            ref = peer["remoteRef"]
            provider, native = str(ref["provider"]), str(ref["nativeId"])
            known = provider in _PROVIDER_KEYS
            valid = known and UUID_SHAPE.fullmatch(native) is not None
            provider_text = remote_display(provider) or ""
            short_id = shown_ids.get((provider, native), native) if valid else (remote_display(native) or "")
            # 名字只作带设备的人读旁注：已核实写「provider@名字〔ID〕」，否则「provider@id:<ID> 名称=…（仅展示）」；
            # 可复制的永远是 target 里的完整 ID 与 --device（§91.4.2）。对端自称已核实、名字却过不了 copyable
            # （含会被改动的字符、首尾空白、id: 开头或 UUID 形状）或超过 120 字符（§91 上限，诚实写方不发布更长的）
            # 时按未核实只作展示（由 remote_display 转义并截断），不写成 provider@名字；判据 verified_label 与 resolve_remote、
            # remote_text 共用，展示成名字的才能按名字选中（§103.3 第 3 条）
            name = verified_label(peer["name"], peer["namesVerified"])
            if name is not None:
                shown = f"{provider_text}@{name}〔{short_id}〕"
                shown_name: str | None = name
            else:
                shown_name = remote_display(peer["displayName"]) or remote_display(peer["name"])
                shown = f"{provider_text}@id:{short_id}" + (f" 名称={shown_name}（仅展示）" if shown_name else "")
            flags = [] if peer["inbox"] else ["只读"]
            if not peer["eligible"]:
                flags.append("暂不可投")
            if not known:
                flags.append("provider 未知")
            elif not valid and native != UNRESOLVED_NATIVE_ID:
                flags.append("ID 无效")  # 只留给真正不合法的值；未解析的「-」是合法行，沿用原有旗标
            elif valid and reference is None:
                flags.append("设备引用无效")
            suffix = f"  （{'、'.join(flags)}）" if flags else ""
            target = f" target=--device {reference} --to {provider}@id:{native}" if valid and reference else ""
            workdir = workdir_suffix(peer["workdir"], shown_name)
            lines.append(f"  {shown} device={where}{target}{suffix}{workdir}")
    return lines
