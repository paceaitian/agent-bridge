"""T05 崩溃矩阵的合成子进程（DESIGN §88.16）：在指定崩溃点对自己 SIGKILL，不跑 finally/except，由父进程复启核对。

只打开父进程给的临时设备根与 hub 根；外调用写盘的假通道代替（每次外调先落一行并 fsync 再返回），绝不连真实会话。
用法：python bridge_federation_crash_child.py '<spec JSON>'；没走到崩溃点就以 0 退出，父进程据此判「崩溃点没触发」。
"""

from __future__ import annotations

import json
import os
import signal
import sys
import threading
from pathlib import Path
from typing import Any

import bridge_support  # noqa: F401  导入即隔离宿主会话环境并装连接守卫

from agentstatus_bridge.federation import attachments
from agentstatus_bridge.federation.authority import Identity
from agentstatus_bridge.federation.config import FederationConfig
from agentstatus_bridge.federation.delivery import FederationDispatcher
from agentstatus_bridge.federation.fedstore import FederatedStore
from agentstatus_bridge.federation.hub import HubSession
from agentstatus_bridge.federation.hubstore import HubStore, auth_fingerprint
from agentstatus_bridge.federation.relay import HubConnection, Relay, RelayPaths
from agentstatus_bridge.federation.transport import StreamTransport
from agentstatus_bridge.model import Delivery, EndpointRef, Provider
from agentstatus_bridge.transports import DeliveryOutcome
from bridge_support import RecordingTransport, endpoint


def die() -> None:
    """强杀自己：SQLite 未提交的事务与 Python 的清理代码都来不及运行。"""
    os.kill(os.getpid(), signal.SIGKILL)


def after(owner: Any, name: str, *, when: Any = None) -> None:
    """包一层：原方法返回后（满足 when 时）强杀。"""
    original = getattr(owner, name)

    def wrapper(*args: Any, **kwargs: Any) -> Any:
        result = original(*args, **kwargs)
        if when is None or when(args, kwargs, result):
            die()
        return result

    setattr(owner, name, wrapper)


def before(owner: Any, name: str, *, when: Any = None) -> None:
    """包一层：调用原方法之前（满足 when 时）强杀。"""
    original = getattr(owner, name)

    def wrapper(*args: Any, **kwargs: Any) -> Any:
        if when is None or when(args, kwargs):
            die()
        return original(*args, **kwargs)

    setattr(owner, name, wrapper)


def native_log_outcome(log: Path, point: str):  # noqa: ANN201 - 返回 RecordingTransport 的结果工厂
    def outcome(_endpoint: Any, text: str, context: Any) -> DeliveryOutcome:
        with open(log, "a", encoding="utf-8") as handle:
            handle.write(json.dumps({"uuid": context.message_uuid, "bytes": len(text)}) + "\n")
            handle.flush()
            os.fsync(handle.fileno())
        if point == "first_byte":
            die()
        return DeliveryOutcome(Delivery.QUEUED, "codex_queued", provider_ref="item-1")

    return outcome


def run_worker(spec: dict[str, Any]) -> None:
    store = FederatedStore.open(Path(spec["storeRoot"]))
    ident = Identity(device_id=spec["deviceId"], device_name=spec["deviceName"], hub_id=spec["hubId"])
    point = spec["point"]
    if point == "prepared":
        before(FederationDispatcher, "_claim")
    elif point == "intent":
        after(FederationDispatcher, "_claim", when=lambda _a, _k, claimed: claimed)
    elif point == "returned":
        before(FederationDispatcher, "_record_outcome")
    elif point == "result":
        after(FederationDispatcher, "_record_outcome")
    ref = EndpointRef.from_dict(spec["live"])
    if ref is None:
        raise SystemExit("bad live endpoint")
    live = endpoint(ref)
    transport = RecordingTransport(Provider(spec["provider"]), native_log_outcome(Path(spec["nativeLog"]), point))
    FederationDispatcher(store, ident, RelayPaths(Path(spec["storeRoot"])), discover=lambda: [live],
                         transports={transport.provider: transport}, clock=lambda: int(spec["clock"]),
                         command="ab").run_once()


def hub_connector(spec: dict[str, Any]):  # noqa: ANN201 - 返回连接工厂
    """与 relay 测试同形：本进程内起一个真实 HubSession 线程，经管道连接；强杀时它也一起消失。"""
    hub_root, auth, name = Path(spec["hubRoot"]), str(spec["authFile"]), spec["deviceName"]

    def connect() -> StreamTransport:
        r1, w1 = os.pipe()
        r2, w2 = os.pipe()
        server = StreamTransport(os.fdopen(r1, "rb"), os.fdopen(w2, "wb"))
        client = StreamTransport(os.fdopen(r2, "rb"), os.fdopen(w1, "wb"))

        def serve() -> None:
            hub = HubStore.open(hub_root)
            try:
                HubSession(hub, server, device_name=name, auth=lambda: auth_fingerprint(auth),
                           clock=lambda: int(spec["clock"]), tick_seconds=0.05).run()
            finally:
                hub.close()

        threading.Thread(target=serve, daemon=True).start()
        return client

    return connect


def run_relay(spec: dict[str, Any]) -> None:
    root = Path(spec["storeRoot"])
    store = FederatedStore.open(root)
    ident = Identity(device_id=spec["deviceId"], device_name=spec["deviceName"], hub_id=spec["hubId"])
    config = FederationConfig(enabled=True, hub_id=spec["hubId"], device_id=spec["deviceId"],
                              device_name=spec["deviceName"], host="hub.example", user="ab-relay",
                              expected_state_root=str(root))
    point = spec["point"]
    if point == "hub_blob":
        after(Relay, "_upload")
    elif point == "l1":
        after(HubConnection, "call", when=lambda args, _k, _r: args[1] == "submit")
    elif point == "b_part":
        after(Relay, "_download")
    elif point == "b_leaf":
        after(attachments, "land")
    elif point == "b_db":
        before(HubConnection, "call", when=lambda args, _k: args[1] == "ack")
    elif point == "l2":
        after(HubConnection, "call", when=lambda args, _k, _r: args[1] == "ack")
    relay = Relay(store, ident, config, RelayPaths(root), connect=hub_connector(spec), on_work=lambda: None,
                  clock=lambda: int(spec["clock"]))
    relay.connect_and_run(cycles=1, wait=lambda _seconds: None)


def run_freeze(spec: dict[str, Any]) -> None:
    if spec["point"] == "source_part":
        before(attachments.os, "replace")  # 私有 part 已写满并 fsync、尚未改名成 <sha>.blob
    attachments.freeze(spec["files"], cwd=Path(spec["cwd"]), origin_device=spec["deviceId"],
                       staging=Path(spec["staging"]))
    if spec["point"] == "source_db":
        die()  # 冻结副本已就位、任务与 manifest 还没写库


def main() -> None:
    spec = json.loads(sys.argv[1])
    os.environ["CODEX_HOME"] = spec["codexHome"]  # bridge_support 导入时清掉了继承的 CODEX_*：按父进程的根复原
    {"worker": run_worker, "relay": run_relay, "freeze": run_freeze}[spec["mode"]](spec)


if __name__ == "__main__":
    main()
