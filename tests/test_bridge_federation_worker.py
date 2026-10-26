"""P5 worker 两库隔离（DESIGN §88.1/§88.12，T11/T13/T14 的 worker 部分）。

覆盖：已启用联邦时 worker 同时投递本机与联邦作业；本机库损坏仍处理联邦作业；联邦库损坏仍处理本机作业；
配置在而联邦库缺失绝不自动建空库；expectedStateRoot 不符时不开联邦库；未配置时不碰联邦。
"""

from __future__ import annotations

import os
import tempfile
import time
import unittest
from collections.abc import Iterator
from contextlib import AbstractContextManager, contextmanager
from pathlib import Path
from unittest.mock import patch

import bridge_support  # noqa: F401  导入即隔离宿主会话环境

from agentstatus_bridge import summary
from agentstatus_bridge import worker as worker_module
from agentstatus_bridge.federation import authority, commands
from agentstatus_bridge.federation.authority import Identity
from agentstatus_bridge.federation.delivery import FederationDispatcher
from agentstatus_bridge.federation.config import FederationConfig, save
from agentstatus_bridge.federation.directory import root_binding
from agentstatus_bridge.federation.fedstore import FED_DB_NAME, FederatedStore
from agentstatus_bridge.federation.refs import RemoteEndpointRef, TargetRef
from agentstatus_bridge.model import Provider
from agentstatus_bridge.store import Store, StoreError
from agentstatus_bridge.worker import LOG_NAME, run_worker
from bridge_support import RecordingTransport, endpoint, new_task, ref

DEVICE = "d" * 32
HUB = "f" * 32



class WorkerDidNotExit(BaseException):
    """测试守卫：worker 超过时限仍未退出。用 BaseException 是为了不被 worker 的单轮异常处理吞掉。"""


@contextmanager
def worker_deadline(test: unittest.TestCase, seconds: float = 20.0) -> Iterator[None]:
    """跑到 worker 自己退出的用例加上限：变异让 worker 永不空闲时按断言失败，不挂住整轮测试（变异 O02 曾挂满 900 秒）。"""
    deadline = time.monotonic() + seconds
    original = worker_module.Dispatcher.run_once

    def guarded(dispatcher: object, *args: object, **kwargs: object) -> object:
        if time.monotonic() > deadline:
            raise WorkerDidNotExit
        return original(dispatcher, *args, **kwargs)  # type: ignore[arg-type]

    with patch.object(worker_module.Dispatcher, "run_once", guarded):
        try:
            yield
        except WorkerDidNotExit:
            test.fail(f"worker 超过 {seconds:g} 秒仍未退出")

class FederationWorkerTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        base = Path(self._tmp.name)
        self.root = base / "bridge"
        self.root.mkdir(mode=0o700)
        self.inbox_dir = base / "socks"
        env = patch.dict(os.environ, {"CODEX_SQLITE_HOME": str(base / "codex")})
        env.start()
        self.addCleanup(env.stop)
        self.transport = RecordingTransport(Provider.CODEX)

    def enable(self, *, expected_root: Path | None = None) -> str:
        """建联邦库与配置，并在库里排一条本机目标的联邦交接；返回 msg_id。"""
        store = FederatedStore.create(self.root)
        try:
            store.set_meta("deviceId", DEVICE)
            store.set_meta("hubId", HUB)
            store.set_meta("enabled", "1")  # 与 federation enable 一致
            local = ref()
            binding = root_binding(local)
            assert binding is not None  # Codex 按家目录计算，总有值
            endpoint_id, revision = store.bind_endpoint(provider="codex", native_id=local.native_id,
                                                        root_binding=binding, local_ref=local.to_dict())
            target = TargetRef(remote=RemoteEndpointRef(device_id=DEVICE, provider=Provider.CODEX,
                                                        native_id=local.native_id, endpoint_id=endpoint_id,
                                                        endpoint_revision=revision), local=local)
            ident = Identity(device_id=DEVICE, device_name="vm", hub_id=HUB)
            _, attempt = authority.create_task(store, ident, title="联邦", flow="handoff", body="FED-BODY", refs=[],
                                               origin=None, origin_actor=None, origin_class="unknown", target=target,
                                               reviewer=None, now=1_800_000_000_000)
        finally:
            store.close()
        save(self.root, FederationConfig(enabled=True, hub_id=HUB, device_id=DEVICE, device_name="vm",
                                         host="hub.example", user="ab-relay",
                                         expected_state_root=str(expected_root or self.root)))
        return attempt.msg_id

    def local_task(self) -> None:
        with Store.open(self.root) as store:
            new_task(store, target=ref(), body="LOCAL-BODY")

    def run_once(self) -> int:
        try:
            return run_worker(root=self.root, once=True, inbox_directory=self.inbox_dir,
                              discover_fn=lambda: [endpoint(ref())], transports={Provider.CODEX: self.transport},
                              loop_seconds=0.05)
        except StoreError as error:
            self.fail(f"worker exited: {error.code}")

    def bodies(self) -> list[str]:
        return ["FED-BODY" if "FED-BODY" in text else "LOCAL-BODY" if "LOCAL-BODY" in text else "?"
                for _, text, _ in self.transport.calls]

    def native_state(self, msg_id: str) -> str:
        with FederatedStore.open(self.root) as store:
            row = store.native(msg_id)
            return str(row["state"]) if row else "absent"

    def log_text(self) -> str:
        path = self.root / LOG_NAME
        return path.read_text(encoding="utf-8") if path.exists() else ""

    def test_both_ledgers_delivered(self) -> None:
        msg_id = self.enable()
        self.local_task()
        self.assertEqual(self.run_once(), 0)
        self.assertEqual(sorted(self.bodies()), ["FED-BODY", "LOCAL-BODY"])
        self.assertEqual(self.native_state(msg_id), "finished")
        fed_text = next(text for _, text, _ in self.transport.calls if "FED-BODY" in text)
        self.assertIn("--origin-device vm --attempt 1", fed_text)

    def test_summary_follows_federation_only_changes(self) -> None:
        msg_id = self.enable()
        self.assertEqual(self.run_once(), 0)
        document = summary.load(self.root)
        assert document is not None
        # 只有联邦库变化（本机库没有任务）：worker 仍按组合水位重发摘要，联邦投递进 deliveries
        self.assertIn(msg_id, [item["messageId"] for item in document["deliveries"]])
        with Store.open(self.root) as store:
            self.assertEqual((document["ledgerId"], document["ledgerRevision"]), summary.ledger_mark(store, self.root))

    def test_worker_mark_matches_the_publisher_when_nothing_changes(self) -> None:
        store = FederatedStore.create(self.root)
        store.set_meta("deviceId", DEVICE)
        store.set_meta("hubId", HUB)
        store.close()
        save(self.root, FederationConfig(enabled=True, hub_id=HUB, device_id=DEVICE, device_name="vm",
                                         host="hub.example", user="ab-relay", expected_state_root=str(self.root)))
        with patch.object(summary, "publish", wraps=summary.publish) as publish:
            self.assertEqual(self.run_once(), 0)
        # 启动时强制发布一次；之后水位与发布器同一组合键，没有变化就不再发布
        self.assertEqual(publish.call_count, 1)

    def test_local_ledger_broken_still_delivers_federation(self) -> None:
        msg_id = self.enable()
        (self.root / "bridge.sqlite3").write_bytes(b"not a sqlite database" * 64)
        self.assertEqual(self.run_once(), 0)
        self.assertEqual(self.bodies(), ["FED-BODY"])
        self.assertEqual(self.native_state(msg_id), "finished")
        self.assertIn("store_error", self.log_text())

    def test_local_runtime_failure_does_not_skip_federation_round(self) -> None:
        msg_id = self.enable()
        self.local_task()  # 启动时两库都正常，运行中本机库出故障
        with patch("agentstatus_bridge.worker.Dispatcher.run_once", side_effect=StoreError("store_busy")):
            self.run_once()
        self.assertEqual(self.native_state(msg_id), "finished")
        self.assertIn("loop_error", self.log_text())

    def test_worker_started_before_enable_attaches_federation(self) -> None:
        msg_id = self.enable()
        real = worker_module._federation_runtime  # pyright: ignore[reportPrivateUsage]
        calls: list[int] = []

        def later(directory: Path, log: object) -> object:
            calls.append(1)
            return None if len(calls) == 1 else real(directory, log)  # type: ignore[arg-type]

        self.local_task()
        with patch.object(worker_module, "_federation_runtime", side_effect=later), \
                patch.object(worker_module, "FEDERATION_PROBE_SECONDS", 0.0):
            self.run_once()
        self.assertEqual(len(calls), 2)  # 启动时还没启用，轮内再看一次接上
        self.assertEqual(self.native_state(msg_id), "finished")
        self.assertIn("federation_attached", self.log_text())

    def run_default_discovery(self, discover: object) -> None:
        """生产接线（不注入 discover_fn），只把发现 I/O 换掉；联邦分发器每次 run_once 连跑两轮、中间推进 601 秒。"""
        original = worker_module._federation_dispatcher  # pyright: ignore[reportPrivateUsage]

        def create(*args: object, **kwargs: object) -> object:
            dispatcher = original(*args, **kwargs)  # type: ignore[arg-type]
            now = [1_800_000_000_001]
            dispatcher.clock = lambda: now[0]
            run = dispatcher.run_once

            def two_rounds() -> dict[str, int]:
                run()
                now[0] += 601_000
                return run()

            dispatcher.run_once = two_rounds
            return dispatcher

        with patch.object(worker_module, "discover", side_effect=discover), \
                patch.object(worker_module, "_federation_dispatcher", side_effect=create):
            run_worker(root=self.root, once=True, inbox_directory=self.inbox_dir,
                       transports={Provider.CODEX: self.transport}, loop_seconds=0.01)

    def delivery_reason(self, msg_id: str) -> object:
        with FederatedStore.open(self.root) as store:
            attempt = store.attempt_by_msg(msg_id)
            assert attempt is not None
            return attempt.delivery.get("reason")

    def test_linux_complete_empty_discovery_reaches_target_gone(self) -> None:
        # Linux 默认发现带本轮完整性：最后一个 agent 退出后联邦作业宽限后判 target_gone（Codex r2-P2-05）
        msg_id = self.enable()
        self.run_default_discovery(lambda _sources=None: [])
        self.assertEqual(self.delivery_reason(msg_id), "target_gone")

    def test_linux_incomplete_discovery_keeps_waiting(self) -> None:
        msg_id = self.enable()

        def unreadable(sources: object) -> list[object]:
            sources.incomplete.add(Provider.CODEX.value)  # type: ignore[attr-defined]  # 本轮没看全 Codex
            return []

        self.run_default_discovery(unreadable)
        self.assertIsNone(self.delivery_reason(msg_id))
        self.assertEqual(self.native_state(msg_id), "prepared")

    def test_federation_only_worker_also_gets_completeness(self) -> None:
        msg_id = self.enable()
        (self.root / "bridge.sqlite3").write_bytes(b"not a sqlite database" * 64)  # 本机库坏：只跑联邦
        self.run_default_discovery(lambda _sources=None: [])
        self.assertEqual(self.delivery_reason(msg_id), "target_gone")

    def rebuild_on_first_round(self) -> AbstractContextManager[object]:
        real_run = FederationDispatcher.run_once
        done: list[int] = []

        def run_once(dispatcher: FederationDispatcher) -> dict[str, int]:
            if not done:
                done.append(1)
                commands.rebuild(self.root, hub_id="e" * 32)  # 运行中换 hub
            return real_run(dispatcher)

        return patch.object(FederationDispatcher, "run_once", run_once)

    def test_rebuild_while_running_reattaches_with_new_identity(self) -> None:
        msg_id = self.enable()
        hubs: list[str] = []
        original = worker_module._federation_dispatcher  # pyright: ignore[reportPrivateUsage]

        def track(runtime: tuple[object, Identity, object], **kwargs: object) -> object:
            hubs.append(runtime[1].hub_id)
            return original(runtime, **kwargs)  # type: ignore[arg-type]

        with self.rebuild_on_first_round(), patch.object(worker_module, "_federation_dispatcher", side_effect=track), \
                patch.object(worker_module, "FEDERATION_PROBE_SECONDS", 0.0), \
                patch.object(worker_module, "IDLE_EXIT_SECONDS", 1.0):
            with worker_deadline(self):
                run_worker(root=self.root, once=False, inbox_directory=self.inbox_dir,
                           discover_fn=lambda: [endpoint(ref())], transports={Provider.CODEX: self.transport},
                           loop_seconds=0.05)
        self.assertEqual(hubs[:2], [HUB, "e" * 32])  # 关掉旧运行时后按新配置重开
        self.assertEqual(self.bodies(), [])  # 旧 hub 路由的作业不投
        self.assertEqual(self.native_state(msg_id), "prepared")
        self.assertIn("federation_detached", self.log_text())

    def test_federation_only_worker_exits_when_identity_goes_stale(self) -> None:
        self.enable()
        (self.root / "bridge.sqlite3").write_bytes(b"not a sqlite database" * 64)
        started = time.monotonic()
        with self.rebuild_on_first_round(), patch.object(worker_module, "IDLE_EXIT_SECONDS", 30.0):
            with worker_deadline(self):
                run_worker(root=self.root, once=False, inbox_directory=self.inbox_dir,
                           discover_fn=lambda: [endpoint(ref())], transports={Provider.CODEX: self.transport},
                           loop_seconds=0.05)
        self.assertLess(time.monotonic() - started, 10.0)  # 不等空闲退出：由下次 ab 或 relay 按新配置拉起
        self.assertEqual(self.bodies(), [])

    def test_persistent_local_failure_does_not_stop_live_federation(self) -> None:
        # 本机库持续故障时，联邦还有待办就不退出；联邦也没有待办了才按连续失败退出（Opus r2-P3-2 N28）
        self.enable()
        rounds: list[int] = []

        def federation_round(_federation: object, _log: object) -> bool:
            rounds.append(1)
            return len(rounds) < 5  # 前四轮联邦仍有待办

        with patch("agentstatus_bridge.worker.Dispatcher.run_once", side_effect=StoreError("store_busy")), \
                patch.object(worker_module, "_federation_round", side_effect=federation_round), \
                patch.object(worker_module, "MAX_CONSECUTIVE_FAILURES", 2):
            with worker_deadline(self):
                run_worker(root=self.root, once=False, inbox_directory=self.inbox_dir,
                           discover_fn=lambda: [endpoint(ref())], transports={Provider.CODEX: self.transport},
                           loop_seconds=0.01)
        self.assertEqual(len(rounds), 5)

    def test_federation_broken_still_delivers_local(self) -> None:
        self.enable()
        (self.root / FED_DB_NAME).write_bytes(b"garbage" * 512)
        for suffix in ("-wal", "-shm"):
            path = self.root / (FED_DB_NAME + suffix)
            if path.exists():
                path.unlink()
        self.local_task()
        self.assertEqual(self.run_once(), 0)
        self.assertEqual(self.bodies(), ["LOCAL-BODY"])
        self.assertIn("federation_store_error", self.log_text())

    def test_missing_federation_store_never_recreated(self) -> None:
        self.enable()
        for suffix in ("", "-wal", "-shm"):
            path = self.root / (FED_DB_NAME + suffix)
            if path.exists():
                path.unlink()
        self.local_task()
        self.assertEqual(self.run_once(), 0)
        self.assertEqual(self.bodies(), ["LOCAL-BODY"])
        self.assertFalse((self.root / FED_DB_NAME).exists())
        self.assertIn("federation_store_missing", self.log_text())

    def test_state_root_mismatch_keeps_federation_closed(self) -> None:
        msg_id = self.enable(expected_root=self.root.parent / "elsewhere")
        self.local_task()
        self.assertEqual(self.run_once(), 0)
        self.assertEqual(self.bodies(), ["LOCAL-BODY"])
        self.assertEqual(self.native_state(msg_id), "prepared")
        self.assertIn("state_root_mismatch", self.log_text())

    def test_federation_round_error_isolated_from_local(self) -> None:
        self.enable()
        self.local_task()
        with patch("agentstatus_bridge.federation.delivery.FederationDispatcher.run_once",
                   side_effect=StoreError("federation_store_unavailable")):
            self.assertEqual(self.run_once(), 0)
        self.assertEqual(self.bodies(), ["LOCAL-BODY"])
        events = [line for line in self.log_text().splitlines() if '"event"' in line]
        self.assertTrue(any('"federation_loop_error"' in line for line in events))
        self.assertFalse(any('"event": "loop_error"' in line for line in events))  # 不计入本机连续失败

    def test_unconfigured_never_touches_federation(self) -> None:
        self.local_task()
        self.assertEqual(self.run_once(), 0)
        self.assertEqual(self.bodies(), ["LOCAL-BODY"])
        self.assertFalse((self.root / FED_DB_NAME).exists())


if __name__ == "__main__":
    unittest.main()
