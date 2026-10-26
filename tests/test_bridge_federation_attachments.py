"""P5 联邦附件（DESIGN §88.3，T17/T18 的 Linux 部分）：源端冻结与超限降级、文件名清洗、接收端落地。

覆盖：0B/8MiB/8MiB+1、32MiB 边界与「后面更小的仍尝试」、16/17 项与重复折叠；symlink 正例，目录/FIFO/socket/设备负例；
读中变化、打开前后身份变化；同内容 CAS 去重；保留名 COM0/LPT0/CONIN$/CONOUT$/CON .txt、Unicode、长名；
同名异内容/完整 hash 冲突换叶不覆盖、链接或多链接叶不复用、祖先链接拒绝；Windows 式 CREATE_NEW 复制与 hash 复核。
"""

from __future__ import annotations

import errno
import hashlib
import os
import socket
import stat
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import bridge_support  # noqa: F401  导入即隔离宿主会话环境

from agentstatus_bridge.federation import attachments
from agentstatus_bridge.federation.attachments import AttachmentError, freeze, land, sanitize_name
from agentstatus_bridge.federation.codec import check_refs

MiB = 1024 * 1024
ORIGIN = "a" * 32
# Windows CI 选择集只允许以此开头的跳过原因（scripts/verify-bridge-windows.py）：权限位、FIFO/AF_UNIX、Linux 链接式落地
posix_only = unittest.skipUnless(os.name == "posix", "POSIX-only: 权限位/FIFO/符号链接/Linux 链接式落地")


def sparse(path: Path, size: int) -> Path:
    with open(path, "wb") as handle:
        handle.truncate(size)
    return path


class SanitizeTests(unittest.TestCase):
    def test_reserved_and_forbidden(self) -> None:
        cases = {
            "COM0": "file-COM0", "lpt0.txt": "file-lpt0.txt", "CONIN$": "file-CONIN$", "conout$.log": "file-conout$.log",
            "CON .txt": "file-CON .txt", "aux.tar.gz": "file-aux.tar.gz", "LPT¹": "file-LPT¹", "COM9.x": "file-COM9.x",
            "a<b>:c|d?.txt": "abcd.txt", "trail. . ": "trail", "..": "attachment", "": "attachment",
            "dir/sub\\name.md": "name.md", "ok\x01\x7fname": "okname", "COM10": "COM10", "console": "console",
        }
        for raw, expected in cases.items():
            with self.subTest(raw=raw):
                self.assertEqual(sanitize_name(raw), expected)

    def test_length_limits(self) -> None:
        self.assertEqual(len(sanitize_name("x" * 200)), 64)
        name = sanitize_name("文" * 60)
        self.assertLessEqual(len(name.encode("utf-8")), 128)
        self.assertEqual(name, "文" * 42)


class FreezeTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        self.src = self.root / "src"
        self.src.mkdir()
        self.staging = self.root / "state" / "fed-staging"

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def run_freeze(self, *names: str) -> list[attachments.Frozen]:
        return freeze(list(names), cwd=self.src, origin_device=ORIGIN, staging=self.staging)

    def frozen(self, *names: str) -> list[attachments.Frozen]:
        """期望成功的冻结：失败转成断言失败（变异以 FAIL 而非 ERROR 杀死）。"""
        try:
            return self.run_freeze(*names)
        except AttachmentError as error:
            self.fail(f"freeze failed: {error.code}")

    def test_size_boundaries_and_greedy_total(self) -> None:
        sparse(self.src / "zero", 0)
        sparse(self.src / "eight", 8 * MiB)
        sparse(self.src / "over", 8 * MiB + 1)
        result = self.frozen("zero", "eight", "over")
        self.assertEqual([item.manifest["transfer"] for item in result], ["blob", "blob", "reference"])
        self.assertEqual(result[2].manifest["reason"], "single_file_limit")
        self.assertIsNone(result[2].manifest["sha256"])
        self.assertEqual(result[2].manifest["size"], 8 * MiB + 1)
        self.assertEqual(result[0].manifest["sha256"], hashlib.sha256(b"").hexdigest())
        check_refs([item.manifest for item in result])  # 形状过 wire 校验

    def test_message_total_continues_with_smaller(self) -> None:
        names = []
        for index, size in enumerate((8 * MiB, 8 * MiB, 8 * MiB, 7 * MiB, 2 * MiB, MiB)):
            sparse(self.src / f"f{index}", size)
            names.append(f"f{index}")
        result = self.frozen(*names)
        self.assertEqual([item.manifest["transfer"] for item in result],
                         ["blob", "blob", "blob", "blob", "reference", "blob"])
        self.assertEqual(result[4].manifest["reason"], "message_total_limit")
        total = sum(item.manifest["size"] for item in result if item.manifest["transfer"] == "blob")
        self.assertEqual(total, 32 * MiB)
        self.assertEqual(attachments.transfer_summary(result), (5, 32 * MiB, 1))

    def test_ref_count_and_duplicates(self) -> None:
        for index in range(17):
            (self.src / f"n{index}").write_text(str(index), encoding="utf-8")
        self.assertEqual(len(self.frozen(*[f"n{i}" for i in range(16)], "n0", str(self.src / "n1"))), 16)
        with self.assertRaises(AttachmentError) as caught:
            self.run_freeze(*[f"n{i}" for i in range(17)])
        self.assertEqual(caught.exception.code, "too_many_files")

    @posix_only
    def test_symlink_followed_and_dedupe(self) -> None:
        target = self.src / "real.md"
        target.write_text("同样内容", encoding="utf-8")
        (self.src / "copy.md").write_text("同样内容", encoding="utf-8")
        os.symlink(target, self.src / "link.md")
        result = self.frozen("link.md", "copy.md")
        self.assertEqual(result[0].manifest["originalPath"], str(self.src / "link.md"))
        self.assertEqual(result[0].manifest["resolvedPath"], str(target.resolve()))
        self.assertEqual(result[0].manifest["name"], "link.md")
        self.assertEqual(result[0].staging, result[1].staging)  # 同内容 CAS 只冻一份
        self.assertEqual(len(list(self.staging.iterdir())), 1)
        assert result[0].staging is not None
        self.assertEqual(oct(result[0].staging.stat().st_mode & 0o777), "0o600")
        self.assertEqual(result[0].staging.read_text(encoding="utf-8"), "同样内容")

    @posix_only
    def test_special_files_rejected_without_hanging(self) -> None:
        (self.src / "dir").mkdir()
        os.mkfifo(self.src / "fifo")
        sock = socket.socket(socket.AF_UNIX)
        sock.bind(str(self.src / "sock"))
        self.addCleanup(sock.close)
        for name in ("dir", "fifo", "sock", "/dev/null"):
            with self.subTest(name), self.assertRaises(AttachmentError) as caught:
                self.run_freeze(name)
            self.assertEqual(caught.exception.code, "attachment_not_regular")
        with self.assertRaises(AttachmentError) as missing:
            self.run_freeze("absent")
        self.assertEqual(missing.exception.code, "attachment_unreadable")

    def test_source_changed_during_read(self) -> None:
        path = self.src / "grow.txt"
        path.write_bytes(b"x" * 1000)
        real_read = os.read

        grown: list[bool] = []

        def growing_read(fd: int, n: int) -> bytes:
            data = real_read(fd, n)
            if data and not grown:  # 只追加一次：只能靠前后大小/mtime 复核发现
                grown.append(True)
                with open(path, "ab") as handle:
                    handle.write(b"more")
            return data

        with mock.patch.object(attachments.os, "read", growing_read), self.assertRaises(AttachmentError) as caught:
            self.run_freeze("grow.txt")
        self.assertEqual(caught.exception.code, "attachment_source_changed")
        self.assertEqual([p for p in self.staging.iterdir()], [])  # 未冻结的临时文件已清理

    def test_identity_swapped_between_stat_and_open(self) -> None:
        (self.src / "a").write_text("a", encoding="utf-8")
        other = os.stat(self.src)
        real_stat = os.stat
        with mock.patch.object(attachments.os, "stat", lambda p, *a, **k: other if os.path.basename(str(p)) == "a"
                               else real_stat(p, *a, **k)):
            with self.assertRaises(AttachmentError) as caught:
                self.run_freeze("a")
        # 目录身份的 stat 先被判为非普通文件；换成另一普通文件再测身份不符
        self.assertEqual(caught.exception.code, "attachment_not_regular")
        (self.src / "b").write_text("b", encoding="utf-8")
        swapped = os.stat(self.src / "b")
        with mock.patch.object(attachments.os, "stat", lambda p, *a, **k: swapped if os.path.basename(str(p)) == "a"
                               else real_stat(p, *a, **k)):
            with self.assertRaises(AttachmentError) as changed:
                self.run_freeze("a")
        self.assertEqual(changed.exception.code, "attachment_source_changed")

    @posix_only
    @unittest.skipIf(getattr(os, "geteuid", lambda: -1)() == 0, "root 可读 000 文件")  # Windows 无 geteuid，导入不能失败
    def test_unreadable(self) -> None:
        path = self.src / "secret"
        path.write_text("x", encoding="utf-8")
        path.chmod(0)
        try:
            with self.assertRaises(AttachmentError) as caught:
                self.run_freeze("secret")
        finally:
            path.chmod(0o600)
        self.assertEqual(caught.exception.code, "attachment_unreadable")


class LandTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        self.state = self.root / "state"
        self.state.mkdir(mode=0o700)
        self.parts = self.state / "parts"
        self.parts.mkdir()

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def part(self, data: bytes) -> tuple[Path, str]:
        path = self.parts / f"{len(list(self.parts.iterdir()))}.part"
        path.write_bytes(data)
        return path, hashlib.sha256(data).hexdigest()

    def directory(self) -> Path:
        return attachments.delivery_dir(state_root=self.state, windows=False, instance_id="i" * 32, local_appdata=None,
                                        task_id="t" * 32, authority_device=ORIGIN)

    @posix_only
    def test_land_reuse_and_conflicts(self) -> None:
        directory = self.directory()
        self.assertEqual(oct(directory.stat().st_mode & 0o777), "0o700")
        part, sha = self.part(b"hello")
        first = land(part, directory, name="CON .txt", sha=sha, size=5, copy_new_leaf=False)
        self.assertEqual(first.name, f"{sha[:16]}-file-CON .txt")
        self.assertFalse(part.exists())
        self.assertEqual(first.stat().st_nlink, 1)
        again, _ = self.part(b"hello")
        self.assertEqual(land(again, directory, name="CON .txt", sha=sha, size=5, copy_new_leaf=False), first)
        self.assertFalse(again.exists())
        # 同名叶被编辑过（同长度不同内容）：换完整 hash 名，不覆盖不删除
        first.write_bytes(b"HELLO")
        third, _ = self.part(b"hello")
        moved = land(third, directory, name="CON .txt", sha=sha, size=5, copy_new_leaf=False)
        self.assertEqual(moved.name, f"{sha}-file-CON .txt")
        self.assertEqual(first.read_bytes(), b"HELLO")
        moved.write_bytes(b"edited too")
        fourth, _ = self.part(b"hello")
        random = land(fourth, directory, name="CON .txt", sha=sha, size=5, copy_new_leaf=False)
        self.assertTrue(random.name.startswith(f"{sha}-") and random.name.endswith("-file-CON .txt"))
        self.assertEqual(random.read_bytes(), b"hello")

    def test_local_write_errors_are_classified(self) -> None:
        # 建目录与落叶共用一套分类：写满报 device_storage_full（doctor 与文案的原因要对，Opus r3-P3-3 T10），
        # 其余本机写错误暂时、路径本身不成立才确定失败
        cases = ((errno.ENOSPC, "device_storage_full"), (errno.EACCES, "attachment_write_failed"),
                 (errno.ENAMETOOLONG, "attachment_path_unavailable"))
        directory = self.directory()
        for number, code in cases:
            with self.subTest(errno.errorcode[number]):
                failure = OSError(number, "synthetic")
                with mock.patch.object(attachments.os, "mkdir", side_effect=failure), \
                        self.assertRaises(AttachmentError) as made:
                    attachments.safe_dirs(self.state, [f"fresh-{number}"], private=True)
                self.assertEqual(made.exception.code, code)
                part, sha = self.part(b"leaf")
                with mock.patch.object(attachments, "_copy_new_leaf", side_effect=failure), \
                        self.assertRaises(AttachmentError) as landed:
                    land(part, directory, name="a.md", sha=sha, size=4, copy_new_leaf=True)
                self.assertEqual(landed.exception.code, code)
                self.assertTrue(part.exists())  # 落地失败时 part 留在原处，收端重推时可以直接复用

    @posix_only
    def test_links_not_reused_and_ancestor_link_rejected(self) -> None:
        directory = self.directory()
        part, sha = self.part(b"data")
        elsewhere = self.root / "elsewhere"
        elsewhere.write_bytes(b"data")
        os.symlink(elsewhere, directory / f"{sha[:16]}-a.md")
        landed = land(part, directory, name="a.md", sha=sha, size=4, copy_new_leaf=False)
        self.assertEqual(landed.name, f"{sha}-a.md")  # 链接叶即使内容相同也不复用
        hard_part, _ = self.part(b"data")
        os.link(landed, self.root / "extra-link")
        second = land(hard_part, directory, name="a.md", sha=sha, size=4, copy_new_leaf=False)
        self.assertNotIn(second, (landed,))  # 多链接叶不复用
        other_state = self.root / "state2"
        other_state.mkdir()
        os.symlink(self.root, other_state / "attachments")
        with self.assertRaises(AttachmentError) as caught:
            attachments.delivery_dir(state_root=other_state, windows=False, instance_id="i" * 32, local_appdata=None,
                                     task_id="t" * 32, authority_device=ORIGIN)
        self.assertEqual(caught.exception.code, "attachment_path_unavailable")

    @posix_only
    def test_state_root_behind_symlink_allowed(self) -> None:
        link = self.root / "state-link"
        os.symlink(self.state, link)
        directory = attachments.delivery_dir(state_root=link, windows=False, instance_id="i" * 32, local_appdata=None,
                                             task_id="t" * 32, authority_device=ORIGIN)
        self.assertEqual(directory, (self.state / "attachments" / ("t" * 32) / ORIGIN).resolve())

    def test_windows_style_copy_new_leaf(self) -> None:
        appdata = self.root / "LocalAppData"
        appdata.mkdir()
        directory = attachments.delivery_dir(state_root=self.state, windows=True, instance_id="i" * 32,
                                             local_appdata=appdata, task_id="t" * 32, authority_device=ORIGIN)
        self.assertEqual(directory.relative_to(appdata.resolve()).parts[:2], ("agent-bridge-inbox", "i" * 32))
        self.assertNotEqual(oct(directory.stat().st_mode & 0o777), "0o700")  # 不套私有权限
        part, sha = self.part(b"windows")
        part_inode = part.stat().st_ino
        landed = land(part, directory, name="r.md", sha=sha, size=7, copy_new_leaf=True)
        self.assertEqual(landed.read_bytes(), b"windows")
        self.assertNotEqual(landed.stat().st_ino, part_inode)  # 新建叶，不是把私有 part 改名/链接过去
        self.assertFalse(part.exists())
        bad, _ = self.part(b"corrupt")
        with self.assertRaises(AttachmentError) as caught:
            land(bad, directory, name="x.md", sha=sha, size=7, copy_new_leaf=True)
        self.assertEqual(caught.exception.code, "attachment_hash_mismatch")
        self.assertEqual(sorted(p.name for p in directory.iterdir()), [landed.name])  # 坏叶已删、旧叶不动
        self.assertTrue(stat.S_ISREG(os.lstat(landed).st_mode))

    def test_recover_pending_only_touches_recorded_leaf(self) -> None:
        directory = self.directory()
        data = b"complete"
        sha = hashlib.sha256(data).hexdigest()
        partial = directory / "partial"
        partial.write_bytes(b"comp")
        info = os.lstat(partial)
        recorded = {"dev": info.st_dev, "ino": info.st_ino}
        self.assertIsNone(attachments.recover_pending(partial, recorded, sha=sha, size=len(data)))
        self.assertFalse(partial.exists())  # 本次半成品：回收
        done = directory / "done"
        done.write_bytes(data)
        info = os.lstat(done)
        self.assertEqual(attachments.recover_pending(done, {"dev": info.st_dev, "ino": info.st_ino}, sha=sha,
                                                     size=len(data)), done)  # 已完整：直接采用
        other = directory / "other"
        other.write_bytes(b"someone else")
        self.assertIsNone(attachments.recover_pending(other, recorded, sha=sha, size=len(data)))
        self.assertEqual(other.read_bytes(), b"someone else")  # 身份不符：不动


if __name__ == "__main__":
    unittest.main()
