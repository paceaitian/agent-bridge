"""P5 真实边界崩溃矩阵（DESIGN §88.16 T05）：合成子进程在边界点 SIGKILL，父进程复启真实 relay/worker 收敛。

崩溃点：源端私有 part 已写未改名、冻结副本已就位未写库；hub blob 已传未 submit、L1 已回未落本地；B 下载 part 已写、
交付叶已建未记 ready、镜像已提交未发 L2、L2 已发；worker 领取前、intent 已提交未外调、外调首字节后、外调返回后结果
事务前、结果事务后。子进程必须以 SIGKILL 结束（证明真的停在该点）。判据：外部 native 记录（子进程落盘 + 父进程调用）
合计至多一次；无证据崩溃恢复为 UNKNOWN 且 A 不当作已证明未投；明确写前失败记 FAILED；hub 侧消息与交付叶不重复。
"""

from __future__ import annotations

import json
import os
import signal
import sqlite3
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from typing import Any
from unittest.mock import patch

import bridge_support  # noqa: F401  导入即隔离宿主会话环境

from agentstatus_bridge.federation import authority, retention
from agentstatus_bridge.federation.delivery import FederationDispatcher
from agentstatus_bridge.federation.refs import TargetRef
from agentstatus_bridge.model import Delivery, Provider
from agentstatus_bridge.transports import DeliveryOutcome
from bridge_support import RecordingTransport, endpoint

from test_bridge_federation_delivery import DeliveryTestCase, bind, db_state
from test_bridge_federation_relay import RelayTestCase
from test_bridge_federation_rules import pump

CHILD = Path(__file__).with_name("bridge_federation_crash_child.py")  # bridge_* 命名才进镜像
CHILD_TIMEOUT = 60


def run_child(spec: dict[str, Any]) -> int:
    """跑一个合成子进程；返回码 -SIGKILL 表示停在了崩溃点。子进程继承本进程（已隔离的）环境。"""
    env = dict(os.environ)
    env["PYTHONPATH"] = os.pathsep.join([str(CHILD.parents[1] / "src"), str(CHILD.parent)])
    flags = ["-O"] * sys.flags.optimize  # -O 模式的门禁里子进程同样去掉 assert
    run = subprocess.run([sys.executable, *flags, str(CHILD), json.dumps(spec)], env=env, capture_output=True,
                         text=True, timeout=CHILD_TIMEOUT)
    if run.returncode not in (0, -signal.SIGKILL):
        raise AssertionError(f"子进程异常退出 {run.returncode}：{run.stderr[-2000:]}")
    return run.returncode


class CodexHomeMixin(unittest.TestCase):
    """先切到临时 CODEX_HOME 再绑定端点：父子进程算出同一个根绑定，也不读真实 provider 目录。"""

    def setUp(self) -> None:
        home = tempfile.TemporaryDirectory()
        self.addCleanup(home.cleanup)
        self.codex_home = home.name
        patcher = patch.dict(os.environ, {"CODEX_HOME": home.name})
        patcher.start()
        self.addCleanup(patcher.stop)
        super().setUp()


class WorkerCrashTests(CodexHomeMixin, DeliveryTestCase):
    def crash(self, point: str) -> tuple[str, Path]:
        _, first = self.create()
        pump(self.a, self.b, now=self.clock.now)
        log = self.root / "native.log"
        assert self.worker.local is not None
        code = run_child({"mode": "worker", "point": point, "codexHome": self.codex_home, "clock": self.clock.now,
                          "storeRoot": str(self.root / "win"), "deviceId": self.b.ident.device_id,
                          "deviceName": "win", "hubId": self.b.ident.hub_id, "provider": "codex",
                          "live": self.worker.local.to_dict(), "nativeLog": str(log)})
        self.assertEqual(code, -signal.SIGKILL, f"{point}: 子进程没有停在崩溃点")
        return first.msg_id, log

    def restart(self) -> RecordingTransport:
        transport = RecordingTransport(Provider.CODEX)
        for _ in range(2):  # 复启两轮：恢复轮与再次领取轮都不能重投
            self.dispatcher(self.b, self.b_paths, transport, [self.live(self.worker)]).run_once()
        return transport

    @staticmethod
    def logged(log: Path) -> int:
        return len(log.read_text(encoding="utf-8").splitlines()) if log.exists() else 0

    def assert_matrix(self, point: str, *, child_calls: int, parent_calls: int, final: tuple[str, str]) -> None:
        msg_id, log = self.crash(point)
        transport = self.restart()
        self.assertEqual((self.logged(log), len(transport.calls)), (child_calls, parent_calls), point)
        self.assertLessEqual(self.logged(log) + len(transport.calls), 1)  # native 至多一次
        self.assertEqual(db_state(self.b, msg_id), final, point)
        pump(self.b, self.a, now=self.clock.now)
        attempt = self.a.store.attempt_by_msg(msg_id)
        assert attempt is not None
        if final[0] == "unknown":
            self.assertFalse(authority.proven_undelivered(attempt, self.a.ident))  # 无证据崩溃不算已证明未投

    def test_crash_before_claim_delivers_once_after_restart(self) -> None:
        self.assert_matrix("prepared", child_calls=0, parent_calls=1, final=("finished", "queued"))

    def test_crash_after_intent_before_call_is_unknown(self) -> None:
        self.assert_matrix("intent", child_calls=0, parent_calls=0, final=("unknown", "unknown"))

    def test_crash_after_first_byte_is_unknown(self) -> None:
        self.assert_matrix("first_byte", child_calls=1, parent_calls=0, final=("unknown", "unknown"))

    def test_crash_after_return_before_result_is_unknown(self) -> None:
        self.assert_matrix("returned", child_calls=1, parent_calls=0, final=("unknown", "unknown"))

    def test_crash_after_result_transaction_keeps_result(self) -> None:
        self.assert_matrix("result", child_calls=1, parent_calls=0, final=("finished", "queued"))

    def test_explicit_pre_write_failure_is_failed(self) -> None:
        _, first = self.create()
        pump(self.a, self.b, now=self.clock.now)
        refused = RecordingTransport(Provider.CODEX, DeliveryOutcome(Delivery.FAILED, "socket_missing"))
        self.dispatcher(self.b, self.b_paths, refused, [self.live(self.worker)]).run_once()
        self.dispatcher(self.b, self.b_paths, refused, [self.live(self.worker)]).run_once()
        self.assertEqual(len(refused.calls), 1)
        self.assertEqual(db_state(self.b, first.msg_id), ("finished", "failed"))  # 外调已结束、结果是明确失败
        pump(self.b, self.a, now=self.clock.now)
        attempt = self.a.store.attempt_by_msg(first.msg_id)
        assert attempt is not None
        self.assertEqual(attempt.delivery["state"], "failed")
        self.assertTrue(authority.proven_undelivered(attempt, self.a.ident))  # 写前失败才是已证明未投


class RelayCrashTests(CodexHomeMixin, RelayTestCase):
    def setUp(self) -> None:
        super().setUp()
        self.worker = bind(self.b, Provider.CODEX, "019a0000-0000-7000-8000-0000000000cc")  # type: ignore[arg-type]

    def child(self, device: Any, point: str, **extra: Any) -> None:
        spec = {"mode": "relay", "point": point, "codexHome": self.codex_home, "clock": self.clock.now,
                "storeRoot": str(device.root), "deviceId": device.device_id, "deviceName": device.name,
                "hubId": self.hub.hub_id(), "hubRoot": str(self.root / "hub"),
                "authFile": str(self.root / f"auth-{device.name}"), **extra}
        (self.root / f"auth-{device.name}").write_text(f"publickey {device.key}\n", encoding="utf-8")
        self.assertEqual(run_child(spec), -signal.SIGKILL, f"{point}: 子进程没有停在崩溃点")

    def hub_rows(self, sql: str) -> list[tuple[Any, ...]]:
        with sqlite3.connect(self.root / "hub" / "hub.sqlite3") as conn:
            return conn.execute(sql).fetchall()

    def deliver_on_b(self) -> RecordingTransport:
        transport = RecordingTransport(Provider.CODEX)
        assert self.worker.local is not None
        live = endpoint(self.worker.local)
        for _ in range(2):
            FederationDispatcher(self.b.store, self.b.ident, self.b.paths, discover=lambda: [live],
                                 transports={Provider.CODEX: transport}, clock=self.clock, command="ab").run_once()
        return transport

    def with_attachment(self, content: bytes = b"# spec\nbody") -> tuple[str, str]:
        refs = self.freeze(self.a, ("任务书.md", content))
        task, first = authority.create_task(
            self.a.store, self.a.ident, title="跨设备", flow="handoff", body="请处理", refs=refs,
            origin=self.origin, origin_actor=authority.actor_for(self.origin, wire_token="claude@vm"),
            origin_class="bypass", target=TargetRef(remote=self.worker.remote), reviewer=None, now=self.clock.now)
        return task.task_id, first.msg_id

    def converge_and_deliver_once(self, msg_id: str) -> None:
        for _ in range(2):
            self.tick()
            self.a.cycle()
            self.tick()
            self.b.cycle()
        self.assertEqual(self.hub_rows("SELECT COUNT(*) FROM hub_messages WHERE target_device=(SELECT device_id"
                                       f" FROM hub_devices WHERE name='win')")[0][0], 1)  # hub 上不重复
        native = self.b.store.native(msg_id)
        assert native is not None
        self.assertEqual(len(self.deliver_on_b().calls), 1)  # native 恰好一次
        (manifest,) = self.b.store.attachments(msg_id)
        base = self.b.paths.delivery_base(self.b.store.ledger_instance_id())
        self.assertEqual([path.name for path in base.rglob("*") if path.is_file()],
                         [Path(manifest["local_relpath"]).name])  # 交付叶只有一个

    # ---- 源端 ----

    def freeze_child(self, point: str) -> Path:
        src = self.a.root / "src"
        src.mkdir(exist_ok=True)
        (src / "任务书.md").write_bytes(b"# spec\nbody")
        spec = {"mode": "freeze", "point": point, "codexHome": self.codex_home, "files": ["任务书.md"],
                "cwd": str(src), "deviceId": self.a.device_id, "staging": str(self.a.paths.staging)}
        self.assertEqual(run_child(spec), -signal.SIGKILL)
        self.assertEqual((self.a.store.tasks(), self.a.store.outbox(states=("ready",))), ([], []))  # 库里什么都没有
        return src

    def test_source_part_written_then_killed(self) -> None:
        self.freeze_child("source_part")
        leftovers = [path for path in self.a.paths.staging.iterdir()]
        self.assertTrue(leftovers and all(path.suffix == ".part" for path in leftovers))
        _, msg_id = self.with_attachment()  # 重新发送不受遗留 part 影响
        self.converge_and_deliver_once(msg_id)
        later = retention.sweep(self.a.store, self.a.paths, now=self.clock.now,
                                wall_ms=int((time.time() + 2 * 86_400) * 1000))
        self.assertEqual(later.parts, 1)  # 孤儿 part 24 小时后由留存回收清掉

    def test_source_frozen_but_db_not_written(self) -> None:
        self.freeze_child("source_db")
        self.assertEqual(len(list(self.a.paths.staging.glob("*.blob"))), 1)
        _, msg_id = self.with_attachment()  # 同内容复用同一冻结副本
        self.assertEqual(len(list(self.a.paths.staging.glob("*.blob"))), 1)
        self.converge_and_deliver_once(msg_id)

    # ---- hub 两侧 ----

    def test_blob_uploaded_then_killed_before_submit(self) -> None:
        _, msg_id = self.with_attachment()
        self.child(self.a, "hub_blob")
        self.assertEqual(self.hub_rows("SELECT COUNT(*) FROM hub_blobs")[0][0], 1)
        self.assertEqual(self.hub_rows("SELECT COUNT(*) FROM hub_messages")[0][0], 0)
        self.assertEqual(self.a.store.outbox_item(msg_id)["state"], "ready")  # type: ignore[index]
        self.converge_and_deliver_once(msg_id)

    def test_l1_returned_then_killed_before_local_record(self) -> None:
        _, msg_id = self.with_attachment()
        self.child(self.a, "l1")
        self.assertEqual(self.a.store.outbox_item(msg_id)["state"], "submitting")  # type: ignore[index]
        self.assertEqual(self.hub_rows("SELECT COUNT(*) FROM hub_messages")[0][0], 1)
        self.converge_and_deliver_once(msg_id)  # 重交同一操作：hub 幂等，不出第二条
        self.assertEqual(self.a.store.outbox_item(msg_id)["state"], "received")  # type: ignore[index]

    def test_download_part_written_then_killed(self) -> None:
        _, msg_id = self.with_attachment()
        self.a.cycle()
        self.tick()
        self.child(self.b, "b_part")
        self.assertEqual([path.suffix for path in self.b.paths.parts.iterdir()], [".part"])
        self.assertIsNone(self.b.store.native(msg_id))
        self.converge_and_deliver_once(msg_id)
        self.assertEqual(list(self.b.paths.parts.iterdir()), [])  # 同名 part 被重下覆盖后移走

    def test_leaf_landed_then_killed_before_ready(self) -> None:
        _, msg_id = self.with_attachment()
        self.a.cycle()
        self.tick()
        self.child(self.b, "b_leaf")
        (manifest,) = self.b.store.attachments(msg_id)
        self.assertNotEqual(manifest["state"], "ready")
        self.assertIsNone(self.b.store.native(msg_id))
        self.converge_and_deliver_once(msg_id)  # 复用已落地的同内容叶，不另建一份

    def test_mirror_committed_then_killed_before_l2(self) -> None:
        _, msg_id = self.with_attachment()
        self.a.cycle()
        self.tick()
        self.child(self.b, "b_db")
        self.assertEqual(self.b.store.native(msg_id)["state"], "prepared")  # type: ignore[index]
        self.assertEqual(self.hub_rows("SELECT l2_at FROM hub_messages")[0][0], None)
        self.converge_and_deliver_once(msg_id)  # hub 重推 → 已应用 → 只补 L2
        self.assertIsNotNone(self.hub_rows("SELECT l2_at FROM hub_messages")[0][0])

    def test_l2_sent_then_killed(self) -> None:
        _, msg_id = self.with_attachment()
        self.a.cycle()
        self.tick()
        self.child(self.b, "l2")
        self.assertIsNotNone(self.hub_rows("SELECT l2_at FROM hub_messages")[0][0])
        self.converge_and_deliver_once(msg_id)


if __name__ == "__main__":
    unittest.main()
