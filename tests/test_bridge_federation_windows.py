"""P5 联邦的 Windows 专有部分（DESIGN §88.3/§88.10，T17/T18 Windows 侧）：两种系统都跑；在 Windows 上就是原生文件冒烟。

不建联邦库：Windows CI 是提权令牌，私有库门按 NOT_RUN 跳过（verify-bridge-windows.py）。这里只测与库无关的
Windows 分支：LocalAppData 下的交付根、CREATE_NEW 新叶复制与复用/换名、缺 LocalAppData 时明确报错、
重解析点按链接对待、Windows 根绑定按 dataRoot 摘要，并钉住 CI 选择集确实包含联邦用例。
"""

from __future__ import annotations

import ast
import hashlib
import os
import stat
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

import bridge_support
import test_bridge_codex_steer as steer_tests
import test_bridge_federation_cli as federation_cli
import test_bridge_fyi as fyi_tests
import test_bridge_note as note_tests
import test_bridge_task_filters as task_filters

from agentstatus_bridge.federation import attachments, directory
from agentstatus_bridge.federation.attachments import AttachmentError, freeze, land
from agentstatus_bridge.federation.relay import RelayPaths
from agentstatus_bridge.model import Provider
from agentstatus_bridge.native_names import text_id_token
from agentstatus_bridge.platforms.factory import using_platform

ROOT = Path(__file__).resolve().parents[1]
SELECTOR = ROOT / "scripts" / "verify-bridge-windows.py"
ORIGIN = "a" * 32
INSTANCE = "i" * 32
TASK = "t" * 32
# Windows CI 选择集必须包含的联邦模块（P2-15）：可移植的附件冻结/落地、Windows 分支模型、协议编解码、部署模板与通道关闭顺序
FEDERATION_MODULES = ("test_bridge_federation_codec", "test_bridge_federation_attachments",
                      "test_bridge_federation_windows", "test_bridge_federation_packaging",
                      "test_bridge_federation_transport_close")
# §94.3：§93 的 tasks 筛选与 --follows 也进选择集（Windows 上认得出的调用方 --mine、名字形 --to 的假内核用例在其中）
TASK_MODULES = ("test_bridge_task_filters", "test_bridge_task_follows")
# §95.6：ab note 与 send --fyi 的新模块同样进选择集
NOTE_MODULES = ("test_bridge_note", "test_bridge_codex_steer", "test_bridge_fyi")
# §95.2：worker 取锁按时间预算重试的用例（含 Windows 假内核取锁）
WORKER_MODULES = ("test_bridge_worker_lock",)


class WindowsDeliveryTests(unittest.TestCase):
    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.appdata = self.root / "LocalAppData"
        self.appdata.mkdir()
        self.state = self.root / "state"
        self.state.mkdir()
        self.parts = self.state / "fed-parts"
        self.parts.mkdir()

    def directory(self) -> Path:
        return attachments.delivery_dir(state_root=self.state, windows=True, instance_id=INSTANCE,
                                        local_appdata=self.appdata, task_id=TASK, authority_device=ORIGIN)

    def part(self, data: bytes) -> tuple[Path, str]:
        path = self.parts / f"{len(list(self.parts.iterdir()))}.part"
        path.write_bytes(data)
        return path, hashlib.sha256(data).hexdigest()

    def test_delivery_root_is_under_local_appdata_and_matches_relay_paths(self) -> None:
        folder = self.directory()
        base = RelayPaths(self.state, windows=True, local_appdata=self.appdata).delivery_base(INSTANCE)
        self.assertEqual(folder, base / TASK / ORIGIN)
        self.assertEqual(folder.relative_to(self.appdata.resolve()).parts[:2], ("agent-bridge-inbox", INSTANCE))

    def test_copy_new_leaf_reuse_and_rename(self) -> None:
        folder = self.directory()
        part, sha = self.part(b"hello")
        first = land(part, folder, name="CON .txt", sha=sha, size=5, copy_new_leaf=True)
        self.assertEqual(first.name, f"{sha[:16]}-file-CON .txt")  # 保留名加前缀，Windows 上可建
        self.assertEqual(first.read_bytes(), b"hello")
        self.assertFalse(part.exists())
        self.assertTrue(stat.S_ISREG(os.lstat(first).st_mode))
        again, _ = self.part(b"hello")
        self.assertEqual(land(again, folder, name="CON .txt", sha=sha, size=5, copy_new_leaf=True), first)
        self.assertFalse(again.exists())
        first.write_bytes(b"HELLO")  # 接收方编辑过：换完整 hash 名，不覆盖不删除
        third, _ = self.part(b"hello")
        moved = land(third, folder, name="CON .txt", sha=sha, size=5, copy_new_leaf=True)
        self.assertEqual(moved.name, f"{sha}-file-CON .txt")
        self.assertEqual((first.read_bytes(), moved.read_bytes()), (b"HELLO", b"hello"))

    def test_corrupt_part_never_leaves_a_leaf(self) -> None:
        folder = self.directory()
        _, sha = self.part(b"expected")
        bad, _ = self.part(b"tampered")
        with self.assertRaises(AttachmentError) as caught:
            land(bad, folder, name="r.md", sha=sha, size=8, copy_new_leaf=True)
        self.assertEqual(caught.exception.code, "attachment_hash_mismatch")
        self.assertEqual(list(folder.iterdir()), [])

    def test_freeze_then_land_round_trip(self) -> None:
        src = self.root / "src"
        src.mkdir()
        (src / "任务书.md").write_bytes("# 任务\r\n细节".encode())
        (frozen,) = freeze(["任务书.md"], cwd=src, origin_device=ORIGIN, staging=self.state / "fed-staging")
        assert frozen.staging is not None
        self.assertEqual(frozen.staging.read_bytes(), "# 任务\r\n细节".encode())  # 二进制复制，不转换换行
        part = self.parts / "m-0.part"
        part.write_bytes(frozen.staging.read_bytes())
        landed = land(part, self.directory(), name=str(frozen.manifest["name"]), sha=str(frozen.manifest["sha256"]),
                      size=int(frozen.manifest["size"]), copy_new_leaf=True)
        self.assertTrue(landed.name.endswith("-任务书.md"))
        self.assertEqual(landed.read_bytes(), "# 任务\r\n细节".encode())

    def test_missing_local_appdata_is_an_explicit_error(self) -> None:
        paths = RelayPaths(self.state, windows=True, local_appdata=None)
        for call in (lambda: paths.delivery_owner, lambda: paths.delivery_base(INSTANCE),
                     lambda: attachments.delivery_dir(state_root=self.state, windows=True, instance_id=INSTANCE,
                                                      local_appdata=None, task_id=TASK, authority_device=ORIGIN)):
            with self.assertRaises(AttachmentError) as caught:
                call()
            self.assertEqual(caught.exception.code, "attachment_path_unavailable")


class WindowsModelTests(unittest.TestCase):
    def test_reparse_point_counts_as_link(self) -> None:
        def fake(attributes: int) -> os.stat_result:
            return cast(os.stat_result, SimpleNamespace(st_mode=stat.S_IFDIR | 0o777, st_file_attributes=attributes))

        self.assertTrue(attachments.is_link_or_reparse(fake(0x400)))  # junction/挂载点：不进去删、不当目的地
        self.assertFalse(attachments.is_link_or_reparse(fake(0x10)))

    def test_windows_root_binding_digests_data_root(self) -> None:
        base = bridge_support.ref(Provider.CODEX, "019a0000-1111-7222-8333-44445555cccc")
        one, same, other = (replace(base, data_root=root) for root in (r"C:\Users\u\.codex", r"C:\Users\u\.codex",
                                                                         r"K:\codex-home"))
        with using_platform(cast(Any, SimpleNamespace(name="windows"))):
            bindings = [directory.root_binding(item) for item in (one, same, other)]
        self.assertIsNotNone(bindings[0])
        self.assertEqual(bindings[0], bindings[1])
        self.assertNotEqual(bindings[0], bindings[2])  # 换根即换绑定：投递按换根拒绝，不投到别的根

    def test_remote_peer_text_escapes_hostile_fields_without_a_store(self) -> None:
        # §101.1 在 Windows 选择集里跑：peers --all-devices 的远端部分只读缓存行（假 store，不建联邦库）
        native = "019a0000-1111-7222-8333-44445555bbbb"
        forged = "\n设备 forged〔ffffffff〕：在线\x1b[2K\u202e\u200b"
        item = {"provider": "codex", "nativeId": native, "endpointId": "e" * 32, "endpointRevision": 1, "inbox": True,
                "eligible": True, "namesVerified": True, "name": "a" + forged, "displayName": "b" + forged}
        bad = {**item, "nativeId": native[:-1] + forged, "name": "c", "displayName": None}
        state = {"device_id": "b" * 32, "name": "w" + forged, "state": "online", "last_seen": 1_000,
                 "snapshot": {"endpoints": [item, bad], "complete": True, "providers": {"codex": True},
                              "namePolicy": directory.NAME_POLICY}}
        store = cast(Any, SimpleNamespace(device_states=lambda: [state]))
        lines = directory.peer_lines(store, None, now=1_000)
        physical = "\n".join(lines).splitlines()
        self.assertEqual(len(physical), 3, physical)
        self.assertFalse(any(char in "\n".join(physical) for char in "\x1b\u202e\u200b"), physical)
        self.assertEqual([line.startswith("设备 ") for line in physical], [True, False, False])
        self.assertIn(f" target=--device {'b' * 32} --to codex@id:{native}", physical[1])  # 设备名不是 slug：退回完整设备 ID
        self.assertIn("名称=b\\u000a设备 forged", physical[1])
        self.assertNotIn("target=", physical[2])
        self.assertTrue(physical[2].endswith("  （ID 无效）"), physical[2])
        [device] = directory.peer_devices(store, None, now=1_000)
        self.assertEqual((device["device"], device["peers"][0]["name"]), ("w" + forged, "a" + forged))  # --json 照给原值


    def test_generated_body_ids_keep_uuids_and_escape_the_rest(self) -> None:
        # §101.1 在 Windows 选择集里跑：自动生成正文里的会话标识，合法 UUID 原样，其余同文字行转义
        native = "019a0000-1111-7222-8333-44445555bbbb"
        self.assertEqual(text_id_token(Provider.CODEX, native), f"codex@id:{native}")
        self.assertEqual(text_id_token(Provider.CLAUDE, native + "\u202e\x9bx"),
                         f"claude@id:{native}\\u202e\\u009bx")


class SelectionTests(unittest.TestCase):
    def selector_constant(self, name: str) -> Any:
        tree = ast.parse(SELECTOR.read_text(encoding="utf-8"))
        for node in tree.body:
            if isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id == name for t in node.targets):
                return ast.literal_eval(node.value)
        self.fail(f"verify-bridge-windows.py 里没有 {name}")

    def test_windows_ci_selection_includes_federation(self) -> None:
        modules = tuple(str(item) for item in self.selector_constant("MODULES"))
        for name in FEDERATION_MODULES + TASK_MODULES + NOTE_MODULES + WORKER_MODULES:
            self.assertIn(name, modules)
        for name in modules:
            self.assertTrue((ROOT / "tests" / f"{name}.py").is_file(), name)

    def test_posix_only_skip_reason_matches_selector(self) -> None:
        prefix = self.selector_constant("POSIX_ONLY")
        source = (ROOT / "tests" / "test_bridge_federation_attachments.py").read_text(encoding="utf-8")
        self.assertIn(f'"{prefix}', source)  # 附件测试的 posix_only 跳过原因必须是选择器放行的前缀
        # tasks 两个模块的跳过都来自两个夹具基类与 tzset 那条（§94.3）：三个原因常量都以放行前缀开头
        for reason in (task_filters.LINUX_FIXTURE_REASON, task_filters.TZSET_REASON, federation_cli.FED_FIXTURE_REASON,
                       note_tests.LINUX_FIXTURE_REASON, steer_tests.LINUX_FIXTURE_REASON, fyi_tests.LINUX_FIXTURE_REASON):
            with self.subTest(reason=reason):
                self.assertTrue(reason.startswith(prefix), reason)


if __name__ == "__main__":
    unittest.main()
