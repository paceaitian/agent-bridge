"""P5 设备联邦内容预算（DESIGN §88.11/T15）：占用统计、源端冻结写前拒绝、实际写满、doctor 显示。

占用只算本包自有的 staging、part、交付叶（Windows 在 LocalAppData 下）与库里未清理的信封；不跟随链接。
源端要冻结的副本合计超过剩余就在复制前拒绝；剩余正好够时放行；超限只作引用的文件不占预算。
"""

from __future__ import annotations

import errno
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import bridge_support  # noqa: F401  导入即隔离宿主会话环境

from agentstatus_bridge.federation import attachments, budget
from agentstatus_bridge.federation.attachments import AttachmentError, freeze
from agentstatus_bridge.federation.commands import attachment_usage
from agentstatus_bridge.federation.fedstore import FederatedStore
from agentstatus_bridge.federation.relay import RelayPaths

ORIGIN = "a" * 32
T0 = 1_800_000_000_000


class BudgetCase(unittest.TestCase):
    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.state = self.root / "state"
        self.store = FederatedStore.create(self.state, now=T0)
        self.addCleanup(self.store.close)
        self.paths = RelayPaths(self.state)
        self.src = self.root / "src"
        self.src.mkdir()

    def write(self, folder: Path, name: str, size: int) -> Path:
        folder.mkdir(parents=True, exist_ok=True)
        path = folder / name
        path.write_bytes(b"x" * size)
        return path


class UsageTests(BudgetCase):
    def test_counts_staging_delivery_parts_and_envelopes(self) -> None:
        empty = budget.usage(self.store, self.paths)
        self.write(self.paths.staging, "s.blob", 100)
        self.write(self.paths.delivery_base(self.store.ledger_instance_id()) / "task" / "dev", "d.txt", 30)
        self.write(self.paths.parts, "m-0.part", 7)
        used = budget.usage(self.store, self.paths)
        self.assertEqual((used.file_bytes, used.files, used.partial_bytes), (130, 2, 7))
        self.assertEqual(used.total, 137 + empty.envelope_bytes)

    def test_links_are_not_followed(self) -> None:
        outside = self.write(self.root / "outside", "big.bin", 5000)
        self.paths.staging.mkdir(parents=True)
        (self.paths.staging / "file-link.blob").symlink_to(outside)
        (self.paths.staging / "dir-link").symlink_to(outside.parent, target_is_directory=True)
        self.assertEqual(budget.usage(self.store, self.paths).file_bytes, 0)

    def test_linked_roots_are_not_followed(self) -> None:
        # staging/part 根本身是链接：指向的不是本包内容，不计（Codex r2-P3-01）
        outside = self.write(self.root / "outside", "not-ours.bin", 99)
        self.paths.staging.symlink_to(outside.parent, target_is_directory=True)
        self.paths.parts.symlink_to(outside.parent, target_is_directory=True)
        used = budget.usage(self.store, self.paths)
        self.assertEqual((used.file_bytes, used.files, used.partial_bytes), (0, 0, 0))

    def test_windows_delivery_under_local_appdata_is_counted(self) -> None:
        appdata = self.root / "LocalAppData"
        paths = RelayPaths(self.state, windows=True, local_appdata=appdata)
        self.write(paths.delivery_base(self.store.ledger_instance_id()) / "task" / "dev", "d.txt", 42)
        self.assertEqual(budget.usage(self.store, paths).file_bytes, 42)
        shown = attachment_usage(self.store, paths, 2 * 1024**3)
        self.assertEqual((shown["bytes"], shown["budgetBytes"], shown["incomingDeferredAt"]), (42, 2 * 1024**3, None))

    def test_windows_without_local_appdata_counts_no_delivery(self) -> None:
        paths = RelayPaths(self.state, windows=True, local_appdata=None)
        self.write(paths.staging, "s.blob", 9)
        try:
            used = budget.usage(self.store, paths)
        except Exception as error:  # noqa: BLE001  D11：产品异常记为断言失败
            self.fail(f"缺 LocalAppData 时统计崩溃：{error!r}")
        self.assertEqual(used.file_bytes, 9)

    def test_doctor_shows_last_incoming_deferral(self) -> None:
        self.store.set_meta(budget.DEFERRED_META, str(T0))
        self.assertEqual(attachment_usage(self.store, self.paths, 1)["incomingDeferredAt"], T0)
        self.store.set_meta(budget.DEFERRED_META, "")
        self.assertIsNone(attachment_usage(self.store, self.paths, 1)["incomingDeferredAt"])

    def test_doctor_shows_last_landing_write_failure(self) -> None:
        # 持续的本机落地暂时失败（杀软占用等）要有据可查（Opus r3-P3-2）
        self.assertIsNone(attachment_usage(self.store, self.paths, 1)["incomingWriteFailedAt"])
        self.store.set_meta(attachments.WRITE_FAILED_META, str(T0))
        self.assertEqual(attachment_usage(self.store, self.paths, 1)["incomingWriteFailedAt"], T0)


class FreezeBudgetTests(BudgetCase):
    def test_over_budget_refuses_before_any_copy(self) -> None:
        self.write(self.src, "a.bin", 600)
        self.write(self.src, "b.bin", 400)
        with self.assertRaises(AttachmentError) as caught:
            freeze(["a.bin", "b.bin"], cwd=self.src, origin_device=ORIGIN, staging=self.paths.staging, available=999)
        self.assertEqual(caught.exception.code, "device_storage_full")
        self.assertFalse(self.paths.staging.exists() and any(self.paths.staging.iterdir()))  # 一个副本都没复制

    def test_exact_fit_is_allowed(self) -> None:
        self.write(self.src, "a.bin", 600)
        self.write(self.src, "b.bin", 400)
        try:
            frozen = freeze(["a.bin", "b.bin"], cwd=self.src, origin_device=ORIGIN, staging=self.paths.staging,
                            available=1000)
        except AttachmentError as error:  # D11
            self.fail(f"剩余正好够却被拒：{error.code}")
        self.assertEqual([item.manifest["transfer"] for item in frozen], ["blob", "blob"])

    def test_reference_only_files_do_not_use_budget(self) -> None:
        self.write(self.src, "big.bin", 200)
        self.write(self.src, "small.bin", 50)
        with mock.patch.object(attachments, "MAX_BLOB_BYTES", 100):
            frozen = freeze(["big.bin", "small.bin"], cwd=self.src, origin_device=ORIGIN,
                            staging=self.paths.staging, available=50)
        self.assertEqual([item.manifest["transfer"] for item in frozen], ["reference", "blob"])

    def test_disk_full_during_copy_reports_storage_full_and_leaves_no_temp(self) -> None:
        self.write(self.src, "a.bin", 10)
        with mock.patch("agentstatus_bridge.federation.attachments.os.fsync",
                        side_effect=OSError(errno.ENOSPC, "synthetic disk full")):
            try:
                freeze(["a.bin"], cwd=self.src, origin_device=ORIGIN, staging=self.paths.staging)
            except AttachmentError as error:
                self.assertEqual(error.code, "device_storage_full")
            except OSError as error:  # D11
                self.fail(f"磁盘满以原始 OSError 逃出：{error!r}")
            else:
                self.fail("磁盘满却冻结成功")
        self.assertEqual(list(self.paths.staging.iterdir()), [])

    def test_other_copy_errors_are_not_called_storage_full(self) -> None:
        self.write(self.src, "a.bin", 10)
        with mock.patch("agentstatus_bridge.federation.attachments.os.fsync",
                        side_effect=OSError(errno.EIO, "synthetic io error")):
            with self.assertRaises(OSError) as caught:
                freeze(["a.bin"], cwd=self.src, origin_device=ORIGIN, staging=self.paths.staging)
        self.assertNotIsInstance(caught.exception, AttachmentError)

    def test_size_change_after_planning_is_source_changed(self) -> None:
        self.write(self.src, "a.bin", 10)
        real = attachments._freeze_blob  # pyright: ignore[reportPrivateUsage]

        def grown(path: str, initial: os.stat_result, staging: Path) -> tuple[str, int, str]:
            digest, size, resolved = real(path, initial, staging)
            return digest, size + 1, resolved

        with mock.patch.object(attachments, "_freeze_blob", side_effect=grown):
            with self.assertRaises(AttachmentError) as caught:
                freeze(["a.bin"], cwd=self.src, origin_device=ORIGIN, staging=self.paths.staging, available=10)
        self.assertEqual(caught.exception.code, "attachment_source_changed")


if __name__ == "__main__":
    unittest.main()
