"""协作桥摘要：把账本投影为无正文的 summary.json，供 AgentStatus 扩展只读（DESIGN §45.14）。

摘要是可重建投影：发布失败不改变业务命令的结果；缺失、损坏、schema 不符或落后于账本修订号时随时重建。
"""

from __future__ import annotations

from collections.abc import Collection, Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
import json
import math
from pathlib import Path
import re
import time
from typing import Any
import unicodedata

from .platforms.factory import get_platform
from . import __version__
from .ids import opaque_id, short
from .labels import next_step, reason_text
from .model import PHASE_LABELS, Attempt, EndpointRef, Phase, Provider, Task, TaskView, describe
from .paths import device_name
from .store import Store

SUMMARY_NAME = "summary.json"
LOCK_NAME = "summary.lock"
SCHEMA = 1
# 存储层活跃任务上限为 100，按最长字段估算远低于此值；超限只截断 tasks，attentionIndex 始终完整
MAX_BYTES = 512 * 1024
# 最近投递：只发布消息 id 与角色，条数有界；扩展拿对方开轮时回传的消息 id 与它比对（DESIGN §45.26）
DELIVERY_LIMIT = 64
# 与 envelope 头部、观察者回传的 outcomeOrigin 同一口径
_MESSAGE_ID = re.compile(r"[0-9a-f]{32}")
_DELIVERY_ROLES = frozenset({"handoff", "review", "notice"})
LOCK_WAIT_SECONDS = 2.0
TITLE_CODEPOINTS = 80
INDEX_TITLE_CODEPOINTS = 40
LABEL_CODEPOINTS = 64
ATTENTION_KINDS: tuple[str, ...] = ("result", "decision", "failure")
STATE_LABELS: dict[str, str] = {
    "absent": "未生成",
    "ok": "正常",
    "stale": "落后于账本",
    "invalid": "损坏或版本不兼容",
}
_DROP_CATEGORIES = frozenset({"Cc", "Cf", "Cs", "Co", "Cn", "Zl", "Zp"})
_PHASES = frozenset(phase.value for phase in Phase)
_KINDS = frozenset({"none", *ATTENTION_KINDS})
_SOURCES = frozenset({"delivered", "selected"})
_MATCHES = frozenset({"generation", "session"})
_PANE = re.compile(r"%[0-9]+")


class SummaryError(Exception):
    """摘要发布失败，带固定原因码；不影响已完成的业务操作。"""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


@dataclass(frozen=True)
class PublishResult:
    """发布结果：written 为本次写入；fresh 为现有摘要结构有效且与账本同一标识、同一修订。

    ledger_id 与 revision 是这次读取的快照；调用方以此为已发布水位，不能事后再查最新修订号（3A-F03）。
    """

    status: str
    revision: int
    ledger_id: str = ""


@dataclass(frozen=True)
class LedgerSnapshot:
    """同一 SQLite 读事务里取得的账本标识、修订号与全部未结束任务。"""

    ledger_id: str
    revision: int
    tasks: list[tuple[Task, list[Attempt]]]
    deliveries: list[dict[str, Any]] = field(default_factory=list)


def clean_text(value: str | None, limit: int) -> str:
    """去掉控制、格式与私用字符并合并空白，按码位截断；用于标题与端点标签。"""
    if not value:
        return ""
    text = "".join(" " if unicodedata.category(ch) in _DROP_CATEGORIES else ch for ch in value)
    return " ".join(text.split())[:limit]


def classify(view: TaskView) -> tuple[str, bool]:
    """需关注类别与是否默认通知；覆盖 describe() 的全部原因（DESIGN §45.14 映射表）。"""
    if view.phase is Phase.AWAITING_ACCEPTANCE:
        return "result", True
    if view.phase is not Phase.NEEDS_ATTENTION:
        return "none", False
    if view.reason in {"blocked_reported", "failure_reported"}:
        return "failure", True
    # 用户自己取消的未发送消息仍列为需处理，但不弹通知
    return "decision", view.reason != "cancelled_undelivered"


def attention_at(task: Task, view: TaskView) -> float:
    """造成当前关注状态的账本迁移时刻；无关回执、消费证据与 notice 不改变它。"""
    current = view.current
    if current is None:
        return task.updated_at
    if view.reason.startswith("delivery_") or view.reason == "cancelled_undelivered":
        return current.delivery_at if current.delivery_at is not None else task.updated_at
    if current.work_at is not None:
        return current.work_at
    return current.delivery_at if current.delivery_at is not None else task.updated_at


def attention_token(task: Task, view: TaskView) -> str:
    """这一次关注的令牌：锚点（当前尝试或任务）、原因与迁移时刻；摘要通知与发起方提醒共用同一口径（DESIGN §45.28.3）。"""
    anchor = view.current.id if view.current is not None else task.id
    return f"{anchor}:{view.reason}:{attention_at(task, view):.6f}"


def binding(attempt: Attempt) -> dict[str, Any]:
    """接收方绑定：有实际投递证据时 pane/PID/start/tmux server 整组取自同一投递端点，否则整组取最初选定目标。

    observer 会话键用同一 opaque_id 复算：generation 精确匹配进程代际；session 只表示同一逻辑会话的当前行，
    同一 Claude 会话在原 pane 恢复后仍可匹配，但不证明进程代际未变。
    """
    target = attempt.target
    detail = attempt.delivery_detail
    delivered_pid = detail.get("deliveredPid")
    delivered_start = detail.get("deliveredStart")
    if isinstance(delivered_pid, int) and not isinstance(delivered_pid, bool) and isinstance(delivered_start, str):
        return _observer_binding(
            target.provider, target.native_id, "delivered",
            detail.get("deliveredPane"), delivered_pid, delivered_start, detail.get("deliveredServerPid"),
        )
    return endpoint_binding(target)


def endpoint_binding(ref: EndpointRef) -> dict[str, Any]:
    """按账本记下的端点（source=selected）推导 observer 会话键：发起方、复核方与没有投递证据的接收方共用（DESIGN §45.27.1）。"""
    return _observer_binding(ref.provider, ref.native_id, "selected", ref.pane, ref.pid, ref.start_ticks, ref.server_pid)


def _observer_binding(
    provider: Provider, native_id: str, source: str, pane: object, pid: object, start: object, server: object,
) -> dict[str, Any]:
    if get_platform().name == 'windows':
        return {'source': source, 'pane': None, 'observerKeys': []}
    valid_pane = pane if isinstance(pane, str) and _PANE.fullmatch(pane) else None
    keys: list[dict[str, str]] = []
    if provider is Provider.CLAUDE:
        base = opaque_id("claude", native_id)
        if valid_pane is not None:
            keys.append({"key": opaque_id("claude-gen", base, valid_pane, pid, start), "match": "generation"})
        keys.append({"key": base, "match": "session"})
    elif (
        provider is Provider.CODEX
        and valid_pane is not None
        and isinstance(server, int)
        and not isinstance(server, bool)
        and server > 0
    ):
        keys.append({"key": opaque_id("codex", server, valid_pane, pid, start), "match": "generation"})
    return {"source": source, "pane": valid_pane, "observerKeys": keys}


def read_ledger(store: Store) -> LedgerSnapshot:
    """在同一 SQLite 读事务里取修订号与全部未结束任务，避免拼出不属于同一时刻的摘要。"""
    with store.read_snapshot():
        ledger_id, revision = store.ledger_revision()
        tasks = [(task, store.attempts(task.id)) for task in store.list_tasks()]
        deliveries = store.recent_deliveries(limit=DELIVERY_LIMIT)
    return LedgerSnapshot(ledger_id, revision, tasks, deliveries)


def build_document(snapshot: LedgerSnapshot, *, now: float, device: str) -> dict[str, Any]:
    """组装摘要文档：需处理的任务在前；attentionIndex 独立于 tasks，供通知使用。

    `device` 是这份摘要所属的设备（本机名，由调用方注入以便 golden 固定）：跨设备时 hub 合并的是
    各设备各自的摘要，所以设备记在顶层，不进每个任务或端点（DESIGN §45.35）。
    """
    entries = [_task_entry(task, attempts) for task, attempts in snapshot.tasks]
    entries.sort(key=lambda item: (item["attention"]["kind"] == "none", -float(item["updatedAt"]), item["id"]))
    index = [
        {
            "id": item["id"],
            "kind": item["attention"]["kind"],
            "token": item["attention"]["token"],
            "at": item["attention"]["at"],
            "notify": item["attention"]["notify"],
            "originIsUser": item["originIsUser"],
            "title": item["title"][:INDEX_TITLE_CODEPOINTS],
        }
        for item in entries
        if item["attention"]["kind"] != "none"
    ]
    counts = {"active": len(entries), "attention": len(index)}
    counts.update({kind: sum(1 for item in index if item["kind"] == kind) for kind in ATTENTION_KINDS})
    return {
        "schema": SCHEMA,
        "ledgerId": snapshot.ledger_id,
        "ledgerRevision": snapshot.revision,
        "generatedAt": now,
        "abVersion": __version__,
        "device": device,
        "overflow": False,
        "counts": counts,
        "attentionIndex": index,
        "tasks": entries,
        "deliveries": snapshot.deliveries[:DELIVERY_LIMIT],
    }


def encode(document: dict[str, Any]) -> bytes:
    """紧凑 UTF-8；超过上限时从尾部截断 tasks 并标记 overflow，attentionIndex 保持完整，仍超限则拒绝。"""
    payload = _dump(document)
    if len(payload) <= MAX_BYTES:
        return payload
    tasks = list(document["tasks"])
    trimmed = dict(document, overflow=True)
    while tasks:
        tasks.pop()
        trimmed["tasks"] = tasks
        payload = _dump(trimmed)
        if len(payload) <= MAX_BYTES:
            return payload
    raise SummaryError("summary_too_large")


def is_valid(document: object) -> bool:
    """当前 schema 下整份投影是否可用：逐层校验必需字段、枚举与有限数值，允许新增的可选字段（3A-F01）。

    修订号相同不代表文件健康；这里判为无效的摘要一律重建，不交给界面反复重试。
    """
    if not isinstance(document, dict) or not _is_schema(document.get("schema")):
        return False
    if not isinstance(document.get("ledgerId"), str) or not _is_count(document.get("ledgerRevision")):
        return False
    if (
        not _is_finite(document.get("generatedAt"))
        or not isinstance(document.get("abVersion"), str)
        or not isinstance(document.get("overflow"), bool)
    ):
        return False
    counts, index, tasks = document.get("counts"), document.get("attentionIndex"), document.get("tasks")
    if not isinstance(counts, dict) or any(not _is_count(counts.get(key)) for key in ("active", "attention", *ATTENTION_KINDS)):
        return False
    if not isinstance(index, list) or not isinstance(tasks, list):
        return False
    if not all(_valid_index_item(item) for item in index) or not all(_valid_task(item) for item in tasks):
        return False
    # 设备是可选加法字段：旧摘要没有它照常有效；有则必须是字符串（DESIGN §45.35）
    device = document.get("device")
    if device is not None and not isinstance(device, str):
        return False
    # 最近投递是可选字段：老版本摘要没有它，新版本必须逐项有界（DESIGN §45.22）
    deliveries = document.get("deliveries")
    if deliveries is not None and (
        not isinstance(deliveries, list)
        or len(deliveries) > DELIVERY_LIMIT
        or not all(_valid_delivery(item) for item in deliveries)
    ):
        return False
    # 计数与内容一致：attentionIndex 始终完整；未溢出时 tasks 也完整
    if counts["attention"] != len(index) or any(
        counts[kind] != sum(1 for item in index if item["kind"] == kind) for kind in ATTENTION_KINDS
    ):
        return False
    return counts["active"] >= len(tasks) and (document["overflow"] or counts["active"] == len(tasks))


def _valid_delivery(item: object) -> bool:
    """投递只发布两件事：消息 id 与角色（DESIGN §45.26）。"""

    message_id = item.get("messageId") if isinstance(item, dict) else None
    return (
        isinstance(item, dict)
        and isinstance(message_id, str)
        and _MESSAGE_ID.fullmatch(message_id) is not None
        # role 区分任务投递与结果回执：回执触发的那一轮照常通知（owner 明确要求）
        and item.get("role") in _DELIVERY_ROLES
        # 接收端点：消费者据此确认这条消息确实发给了这个会话（审计 F05）
        and isinstance(item.get("pane"), str)
        and isinstance(item.get("provider"), str)
        # 可选类别：结束回执为 closure（DESIGN §45.31.7）；旧摘要没有这个字段，同样有效
        and ("kind" not in item or isinstance(item["kind"], str))
    )


def _valid_index_item(item: object) -> bool:
    return (
        isinstance(item, dict)
        and isinstance(item.get("id"), str)
        and _is_member(item.get("kind"), ATTENTION_KINDS)
        and _is_token(item.get("token"))
        and _is_finite(item.get("at"))
        and isinstance(item.get("notify"), bool)
        and isinstance(item.get("originIsUser"), bool)
        and isinstance(item.get("title"), str)
    )


def _valid_task(item: object) -> bool:
    if not isinstance(item, dict):
        return False
    if any(not isinstance(item.get(key), str) for key in ("id", "short", "title", "flow", "phaseLabel", "reason", "reasonText")):
        return False
    current, target = item.get("current"), item.get("target")
    return (
        _is_member(item.get("phase"), _PHASES)
        and _valid_attention(item.get("attention"))
        and isinstance(item.get("originIsUser"), bool)
        and _valid_endpoint(item.get("origin"))
        and _valid_endpoint(item.get("reviewer"))
        and _valid_current(current)
        and _valid_target(target)
        and (current is None) == (target is None)
        and _is_finite(item.get("createdAt"))
        and _is_finite(item.get("updatedAt"))
        and _valid_next(item.get("next"))
    )


def _valid_attention(value: object) -> bool:
    if not isinstance(value, dict) or not _is_member(value.get("kind"), _KINDS):
        return False
    if value["kind"] == "none":
        return True
    return _is_token(value.get("token")) and _is_finite(value.get("at")) and isinstance(value.get("notify"), bool)


def _valid_endpoint(value: object) -> bool:
    # binding 是后加的可选字段：旧摘要没有它仍然有效，出现了就按接收方同一口径校验（DESIGN §45.27.1）
    return value is None or (
        isinstance(value, dict)
        and isinstance(value.get("provider"), str)
        and isinstance(value.get("label"), str)
        and _optional_text(value.get("pane"))
        and ("binding" not in value or _valid_binding(value["binding"]))
    )


def _valid_current(value: object) -> bool:
    # current 为 null 是合法状态（例如 no_attempt），类型错误才算损坏
    return value is None or (
        isinstance(value, dict)
        and isinstance(value.get("attemptId"), str)
        and _is_count(value.get("seq"))
        and all(isinstance(value.get(key), str) for key in ("role", "work", "delivery", "consumption"))
        and _optional_finite(value.get("deliveryAt"))
        and _optional_finite(value.get("workAt"))
    )


def _valid_target(value: object) -> bool:
    if value is None:
        return True
    if (
        not isinstance(value, dict)
        or any(not isinstance(value.get(key), str) for key in ("provider", "label", "role"))
        or not _optional_text(value.get("pane"))
    ):
        return False
    return _valid_binding(value.get("binding"))


def _valid_binding(bound: object) -> bool:
    if not isinstance(bound, dict) or not _is_member(bound.get("source"), _SOURCES) or not _optional_text(bound.get("pane")):
        return False
    keys = bound.get("observerKeys")
    return isinstance(keys, list) and all(
        isinstance(key, dict) and isinstance(key.get("key"), str) and _is_member(key.get("match"), _MATCHES) for key in keys
    )


def _valid_next(value: object) -> bool:
    return value is None or (
        isinstance(value, dict)
        and isinstance(value.get("action"), str)
        and isinstance(value.get("text"), str)
        and _optional_text(value.get("command"))
    )


def load(directory: Path) -> dict[str, Any] | None:
    """读取现有摘要；缺失、超限、无法解析或结构不符时返回 None。"""
    try:
        with open(directory / SUMMARY_NAME, "rb") as stream:
            raw = stream.read(MAX_BYTES + 1)
    except OSError:
        return None
    if len(raw) > MAX_BYTES:
        return None
    try:
        # 过深嵌套（RecursionError）与 NaN/Infinity 都按损坏处理，交给重建，不向调用方抛出（3A-F02）
        document = json.loads(raw, parse_constant=_reject_constant)
    except (ValueError, RecursionError):
        return None
    try:
        valid = is_valid(document)
    except Exception:  # 校验器遇到意外输入也只判为损坏，不能让 if-stale 恢复入口失败（3A-R01）
        return None
    return document if valid else None


def publish(store: Store, directory: Path, *, force: bool = False, now: float | None = None) -> PublishResult:
    """发布摘要。if-stale（默认）只在现有摘要结构有效、属于同一账本且修订号相同时跳过；force 总是重建。

    读取账本快照与写入都在 summary.lock 内完成：并发发布者按加锁顺序落盘，旧快照不会覆盖新文件。
    """
    try:
        with _lock(directory):
            snapshot = read_ledger(store)
            if not force:
                existing = load(directory)
                if (
                    existing is not None
                    and existing["ledgerId"] == snapshot.ledger_id
                    and existing["ledgerRevision"] == snapshot.revision
                    and not _lacks_endpoint_bindings(existing)
                ):
                    return PublishResult("fresh", snapshot.revision, snapshot.ledger_id)
            try:
                payload = encode(
                    build_document(snapshot, now=time.time() if now is None else now, device=device_name())
                )
            except ValueError as error:
                raise SummaryError("summary_invalid_value") from error
            _atomic_write(directory, payload)
    except OSError as error:
        raise SummaryError("summary_write_failed") from error
    return PublishResult("written", snapshot.revision, snapshot.ledger_id)


def _lacks_endpoint_bindings(document: dict[str, Any]) -> bool:
    # 旧发布器写出的摘要里发起方/复核方没有 binding：修订号没变也要重建一次，
    # 否则升级后要等下一次账本写入，协作组才对得上发起方（Codex 设计复审 D02）
    return any(
        isinstance(task.get(role), dict) and "binding" not in task[role]
        for task in document.get("tasks", [])
        if isinstance(task, dict)
        for role in ("origin", "reviewer")
    )


def status(directory: Path, store: Store | None) -> dict[str, Any]:
    """摘要状态（不写入）：absent 未生成、ok 正常、stale 落后于账本、invalid 损坏或版本不兼容。"""
    path = directory / SUMMARY_NAME
    document = load(directory)
    state = "absent" if not path.exists() else "invalid" if document is None else "ok"
    result: dict[str, Any] = {"state": state}
    if document is not None:
        result.update(
            revision=document["ledgerRevision"], generatedAt=document["generatedAt"], overflow=document["overflow"]
        )
    if store is not None:
        ledger_id, revision = store.ledger_revision()
        result["ledgerRevision"] = revision
        if document is not None and (document["ledgerId"] != ledger_id or document["ledgerRevision"] != revision):
            result["state"] = "stale"
    return result


def _task_entry(task: Task, attempts: list[Attempt]) -> dict[str, Any]:
    view = describe(task, attempts)
    kind, notify = classify(view)
    current = view.current
    attention: dict[str, Any] = {"kind": kind}
    if kind != "none":
        attention.update(token=attention_token(task, view), at=attention_at(task, view), notify=notify)
    step = next_step(task, attempts, ref=task.id, reserved=0)
    target: dict[str, Any] | None = None
    if current is not None:
        bound = binding(current)
        target = {
            "provider": current.target.provider.value,
            "label": _label(current.target),
            "pane": bound["pane"],
            "role": current.role.value,
            "binding": bound,
        }
    return {
        "id": task.id,
        "short": short(task.id),
        "title": clean_text(task.title, TITLE_CODEPOINTS),
        "flow": task.flow.value,
        "phase": view.phase.value,
        "phaseLabel": PHASE_LABELS[view.phase],
        "reason": view.reason,
        "reasonText": reason_text(view.reason),
        "attention": attention,
        "originIsUser": task.origin is None,
        "origin": _endpoint(task.origin),
        "reviewer": _endpoint(task.reviewer),
        "current": None
        if current is None
        else {
            "attemptId": current.id,
            "seq": current.seq,
            "role": current.role.value,
            "work": current.work.value,
            "delivery": current.delivery.value,
            "consumption": current.consumption.value,
            "deliveryAt": current.delivery_at,
            "workAt": current.work_at,
        },
        "target": target,
        "createdAt": task.created_at,
        "updatedAt": task.updated_at,
        "next": None if step is None else {"action": step.action, "text": step.text, "command": step.command},
    }


def _label(ref: EndpointRef) -> str:
    # 只用 tmux 会话名或 pane 显示，不回退到原生会话 ID
    where = ref.label or ref.pane
    return clean_text(f"{ref.provider.value}@{where}" if where else ref.provider.value, LABEL_CODEPOINTS)


def _endpoint(ref: EndpointRef | None) -> dict[str, Any] | None:
    if ref is None:
        return None
    pane = ref.pane if ref.pane is not None and _PANE.fullmatch(ref.pane) else None
    # binding 让界面把发起方/复核方也对上会话行，协作组才能把两端排在一起（DESIGN §45.27.1）
    return {"provider": ref.provider.value, "label": _label(ref), "pane": pane, "binding": endpoint_binding(ref)}


def _dump(document: dict[str, Any]) -> bytes:
    # allow_nan=False：摘要必须是严格 JSON，界面端 JSON.parse 不接受 NaN/Infinity
    return json.dumps(document, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")


def _is_count(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


def _is_finite(value: object) -> bool:
    if not isinstance(value, (int, float)) or isinstance(value, bool):
        return False
    try:
        # 超出浮点范围的整数在界面端 JSON.parse 后会变成 Infinity，同样视为无效（3A-R01）
        return math.isfinite(float(value))
    except OverflowError:
        return False


def _is_schema(value: object) -> bool:
    # JSON true 在 Python 里等于 1，不能当成格式版本
    return isinstance(value, int) and not isinstance(value, bool) and value == SCHEMA


def _is_member(value: object, allowed: Collection[str]) -> bool:
    # 先确认是字符串再查枚举：JSON 数组/对象不可哈希，直接做集合成员判断会抛 TypeError（3A-R01）
    return isinstance(value, str) and value in allowed


def _optional_finite(value: object) -> bool:
    return value is None or _is_finite(value)


def _optional_text(value: object) -> bool:
    return value is None or isinstance(value, str)


def _is_token(value: object) -> bool:
    return isinstance(value, str) and bool(value)


def _reject_constant(name: str) -> float:
    raise ValueError(f"non-finite constant {name}")


@contextmanager
def _lock(directory: Path) -> Iterator[None]:
    # Capture the owner once: outside using_platform(), each default selection
    # may construct a different backend. Handles/leases must return to their owner.
    lifecycle = get_platform().lifecycle
    descriptor = lifecycle.open_lock(directory / LOCK_NAME, nofollow=True)
    try:
        deadline = time.monotonic() + LOCK_WAIT_SECONDS
        while True:
            try:
                lifecycle.try_lock(descriptor)
                break
            except BlockingIOError:
                if time.monotonic() >= deadline:
                    raise SummaryError("summary_lock_timeout") from None
                time.sleep(0.02)
        try:
            yield
        finally:
            lifecycle.unlock(descriptor)
    finally:
        lifecycle.close_lock(descriptor)


def _atomic_write(directory: Path, payload: bytes) -> None:
    get_platform().files.atomic_write(directory, payload, name=SUMMARY_NAME, prefix=".summary.")
