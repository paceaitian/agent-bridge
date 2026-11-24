"""§104.11 第 5 条：retry 的附件继承、16 个上限与 32 MiB 预算（本机与跨设备）。

- 原样重发与 `--force` 继承当前尝试的附件（与正文同源）；返工取首条的附件加本次 `--ref`（与【原始任务要求】同源）。
- 16 个上限只在本次给了 `--ref` 时判，且只限新增部分带来的超出；本机先去重再计数。
- 跨设备 retry 把继承 blob 计入 32 MiB 预算，超出的新附件降为仅引用；去重键为（来源路径, sha256）；
  信封校验的 CodecError 由命令层兜成闭集码，不打堆栈。
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest import TestCase
from unittest.mock import patch

import bridge_support  # noqa: F401  导入即隔离宿主会话环境
import test_bridge_cli as local_base  # 只借夹具方法；不把 CliTests 导入本模块命名空间，免得被重复收集
import test_bridge_federation_cli as fed_base

from agentstatus_bridge import cli
from agentstatus_bridge.federation import attachments, authority, retention
from agentstatus_bridge.federation.codec import MAX_BLOB_BYTES, MAX_MESSAGE_BLOB_BYTES
from agentstatus_bridge.federation.fedstore import now_ms
from agentstatus_bridge.federation.relay import RelayPaths
from agentstatus_bridge.model import Delivery
from agentstatus_bridge.reports import refs_over_limit
from agentstatus_bridge.store import MAX_FILES

MIB = 1024 * 1024


class LimitRuleTests(TestCase):
    def test_only_growth_by_new_items_beyond_the_limit_is_refused(self) -> None:
        self.assertEqual(MAX_FILES, 16)
        self.assertFalse(refs_over_limit(17, 17))  # 继承本身超过 16、没有新增：照常重发
        self.assertFalse(refs_over_limit(10, 16))
        self.assertTrue(refs_over_limit(10, 17))
        self.assertTrue(refs_over_limit(17, 18))
        self.assertFalse(refs_over_limit(0, 16))
        self.assertTrue(refs_over_limit(0, 17))

    def test_federated_merge_uses_the_same_rule(self) -> None:
        inherited = [{"originalPath": f"/a/{index}", "sha256": str(index)} for index in range(17)]
        self.assertEqual(len(attachments.merge_refs(inherited, [])), 17)
        self.assertEqual(len(attachments.merge_refs(inherited, [inherited[0]])), 17)
        with self.assertRaises(attachments.AttachmentError) as caught:
            attachments.merge_refs(inherited, [{"originalPath": "/b", "sha256": "x"}])
        self.assertEqual(caught.exception.code, "too_many_files")

    def test_freeze_counts_used_bytes_against_the_message_total_but_not_the_device_budget(self) -> None:
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            big = root / "big.bin"
            big.write_bytes(b"a" * (7 * MIB))
            staging = root / "staging"
            # 已占 20 MiB：再加 7 MiB 仍在 32 MiB 内，设备预算只看新复制的 7 MiB（8 MiB 够用）
            [item] = attachments.freeze([str(big)], cwd=root, origin_device="d" * 32, staging=staging,
                                        available=8 * MIB, used=20 * MIB)
            self.assertEqual(item.manifest["transfer"], "blob")
            # 已占 28 MiB：再加 7 MiB 超过 32 MiB，降为仅引用（不复制、不算 hash）
            [item] = attachments.freeze([str(big)], cwd=root, origin_device="d" * 32, staging=staging, used=28 * MIB)
            self.assertEqual((item.manifest["transfer"], item.manifest["reason"]), ("reference", "message_total_limit"))
            self.assertIsNone(item.manifest["sha256"])


class LocalRetryRefTests(TestCase):
    setUp = local_base.CliTests.setUp
    run_cli = local_base.CliTests.run_cli
    send = local_base.CliTests.send
    store = local_base.CliTests.store
    mark_sent = local_base.CliTests.mark_sent

    def files(self, count: int, prefix: str) -> list[str]:
        paths = []
        for index in range(count):
            path = Path(self._tmp.name) / f"{prefix}-{index}.txt"
            path.write_text(f"{prefix} {index}", encoding="utf-8")
            paths.append(str(path))
        return paths

    def latest_handoff(self, task_id: str):  # noqa: ANN201  夹具返回 Attempt
        with self.store() as store:
            return [item for item in store.attempts(task_id) if item.role.value == "handoff"][-1]

    def report(self, task_id: str, *flags: str) -> None:
        self.mark_sent(task_id)
        self.caller = local_base.as_agent(local_base.IMPL)
        self.assertEqual(self.run_cli("report", task_id, *flags)[0], 0)
        self.caller = local_base.USER

    def names(self, refs: list[dict[str, object]]) -> list[str]:
        return [Path(str(item["path"])).name for item in refs]

    def test_resend_and_force_inherit_current_refs_rework_inherits_the_first(self) -> None:
        [spec] = self.files(1, "spec")
        [data] = self.files(1, "data")
        [other] = self.files(1, "other")
        task_id = self.send("--ref", spec)
        self.report(task_id, "--blocked")
        self.assertEqual(self.run_cli("retry", task_id, "--ref", data)[0], 0)
        self.assertEqual(self.names(self.latest_handoff(task_id).refs), ["spec-0.txt", "data-0.txt"])
        # --force：对方还没交结果，正文取当前尝试，附件同源（上一轮 --ref 追加的不丢）
        self.report(task_id, "--progress")
        code, _, err = self.run_cli("retry", task_id, "--force")
        self.assertEqual(code, 0, err)
        self.assertEqual(self.names(self.latest_handoff(task_id).refs), ["spec-0.txt", "data-0.txt"])
        # 原样重发：上一条确定没送到
        self.mark_sent(task_id, Delivery.FAILED)
        code, _, err = self.run_cli("retry", task_id)
        self.assertEqual(code, 0, err)
        self.assertEqual(self.names(self.latest_handoff(task_id).refs), ["spec-0.txt", "data-0.txt"])
        # 返工：首条的附件加本次 --ref（与【原始任务要求】同源），上一轮返工追加的不继承
        self.report(task_id, "--result", "--note", "完成")
        code, _, err = self.run_cli("retry", task_id, "-m", "再补", "--ref", other)
        self.assertEqual(code, 0, err)
        self.assertEqual(self.names(self.latest_handoff(task_id).refs), ["spec-0.txt", "other-0.txt"])

    def test_review_rework_keeps_the_review_attempts_refs(self) -> None:
        # 复核方受阻后的 retry 仍是复核尝试：附件取当前复核尝试的（交接结果文件），不是首条交接的
        [spec] = self.files(1, "spec")
        [out] = self.files(1, "out")
        task_id = self.send("--ref", spec, "--review-by", "claude@review")
        self.mark_sent(task_id)
        self.caller = local_base.as_agent(local_base.IMPL)
        self.assertEqual(self.run_cli("report", task_id, "--result", "--note", "OK", "--file", out)[0], 0)
        self.mark_sent(task_id)
        self.caller = local_base.as_agent(local_base.REVIEW)
        self.assertEqual(self.run_cli("report", task_id, "--blocked", "--note", "缺环境")[0], 0)
        with self.store() as store:
            review = [item for item in store.attempts(task_id) if item.role.value == "review"][-1]
        self.assertEqual(self.names(review.refs), ["out-0.txt"])
        self.caller = local_base.USER
        code, _, err = self.run_cli("retry", task_id)
        self.assertEqual(code, 0, err)
        with self.store() as store:
            latest = [item for item in store.attempts(task_id) if item.role.value != "notice"][-1]
        self.assertEqual((latest.role.value, self.names(latest.refs)), ("review", ["out-0.txt"]))

    def test_inherited_over_the_limit_still_resends_without_new_refs(self) -> None:
        inherited = self.files(17, "inh")
        task_id = self.send(*[flag for path in inherited for flag in ("--ref", path)])  # 本机 send 不限个数
        self.report(task_id, "--blocked")
        code, _, err = self.run_cli("retry", task_id)
        self.assertEqual(code, 0, err)
        self.assertEqual(len(self.latest_handoff(task_id).refs), 17)
        # 只点已继承的文件：没有新增，照常
        self.report(task_id, "--blocked")
        code, _, err = self.run_cli("retry", task_id, "--ref", inherited[0])
        self.assertEqual(code, 0, err)
        self.assertEqual(len(self.latest_handoff(task_id).refs), 17)
        # --force 同样继承 17 个
        self.report(task_id, "--progress")
        code, _, err = self.run_cli("retry", task_id, "--force")
        self.assertEqual(code, 0, err)
        self.assertEqual(len(self.latest_handoff(task_id).refs), 17)
        # 新增 1 个：由新增部分带来的超出，拒绝且不写入
        self.report(task_id, "--blocked")
        with self.store() as store:
            before = [(item.seq, item.delivery) for item in store.attempts(task_id)]
        [extra] = self.files(1, "new")
        code, _, err = self.run_cli("retry", task_id, "--ref", extra)
        self.assertEqual((code, "[too_many_files]" in err), (cli.EXIT_REJECTED, True), err)
        with self.store() as store:
            self.assertEqual([(item.seq, item.delivery) for item in store.attempts(task_id)], before)

    def test_naming_every_inherited_ref_again_is_net_zero_and_reads_nothing(self) -> None:
        # §104.12 第 9 条（Codex P2-04）：重新点名全部 17 个继承附件，净增为 0，照常重发，也不读这些文件
        inherited = self.files(17, "inh")
        argv = [flag for path in inherited for flag in ("--ref", path)]
        task_id = self.send(*argv)
        self.report(task_id, "--blocked")
        with patch.object(cli, "file_reference", wraps=cli.file_reference) as spy:
            code, _, err = self.run_cli("retry", task_id, *argv)
        self.assertEqual(code, 0, err)
        self.assertEqual(spy.call_count, 0)
        self.assertEqual(len(self.latest_handoff(task_id).refs), 17)

    def test_only_paths_outside_the_inherited_set_are_read(self) -> None:
        inherited = self.files(3, "inh")
        task_id = self.send(*[flag for path in inherited for flag in ("--ref", path)])
        self.report(task_id, "--blocked")
        new = self.files(2, "new")
        with patch.object(cli, "file_reference", wraps=cli.file_reference) as spy:
            code, _, err = self.run_cli("retry", task_id, *[f for p in inherited + new for f in ("--ref", p)])
        self.assertEqual(code, 0, err)
        self.assertEqual(sorted(Path(call.args[0]).name for call in spy.call_args_list), ["new-0.txt", "new-1.txt"])
        self.assertEqual(self.names(self.latest_handoff(task_id).refs),
                         ["inh-0.txt", "inh-1.txt", "inh-2.txt", "new-0.txt", "new-1.txt"])

    def test_net_growth_over_the_limit_is_refused_before_reading_any_file(self) -> None:
        inherited = self.files(16, "inh")
        task_id = self.send(*[flag for path in inherited for flag in ("--ref", path)])
        self.report(task_id, "--blocked")
        with self.store() as store:
            before = [(item.seq, item.delivery) for item in store.attempts(task_id)]
        [extra] = self.files(1, "new")
        with patch.object(cli, "file_reference", wraps=cli.file_reference) as spy:
            code, _, err = self.run_cli("retry", task_id, *[f for p in inherited + [extra] for f in ("--ref", p)])
        self.assertEqual((code, "[too_many_files]" in err), (cli.EXIT_REJECTED, True), err)
        self.assertEqual(spy.call_count, 0)
        with self.store() as store:
            self.assertEqual([(item.seq, item.delivery) for item in store.attempts(task_id)], before)

    def test_new_path_missed_by_the_precheck_is_read_inside_the_transaction(self) -> None:
        # 事务外的预判与事务内的继承集合不一致（并发改动）：没算到的新增路径在事务内补算，不会被漏掉
        [spec] = self.files(1, "spec")
        task_id = self.send("--ref", spec)
        self.report(task_id, "--blocked")
        [extra] = self.files(1, "new")
        with patch.object(cli, "_retry_fresh_refs", return_value={}):
            code, _, err = self.run_cli("retry", task_id, "--ref", extra)
        self.assertEqual(code, 0, err)
        self.assertEqual(self.names(self.latest_handoff(task_id).refs), ["spec-0.txt", "new-0.txt"])
        # 同样的情形但净增量超限：事务内先判个数，不为补算去读文件
        inherited = self.files(16, "inh")
        task_id = self.send(*[flag for path in inherited for flag in ("--ref", path)])
        self.report(task_id, "--blocked")
        with patch.object(cli, "_retry_fresh_refs", return_value={}), \
                patch.object(cli, "file_reference", wraps=cli.file_reference) as spy:
            code, _, err = self.run_cli("retry", task_id, "--ref", extra)
        self.assertEqual((code, "[too_many_files]" in err, spy.call_count), (cli.EXIT_REJECTED, True, 0), err)

    def test_named_refs_are_deduplicated_before_counting(self) -> None:
        task_id = self.send()
        self.report(task_id, "--blocked")
        paths = self.files(16, "f")
        relative = Path(paths[0]).relative_to(Path(self._tmp.name))
        argv = [flag for path in paths for flag in ("--ref", path)] + ["--ref", paths[3]]
        with patch.object(cli.Path, "cwd", return_value=Path(self._tmp.name)):
            code, _, err = self.run_cli("retry", task_id, *argv, "--ref", str(relative))
        self.assertEqual(code, 0, err)  # 18 次点名、16 个不同文件
        self.assertEqual(self.names(self.latest_handoff(task_id).refs), [f"f-{index}.txt" for index in range(16)])
        # note 同一判据
        self.mark_sent(task_id)
        code, _, err = self.run_cli("note", task_id, "-m", "看附件", *argv)
        self.assertEqual(code, 0, err)
        with self.store() as store:
            [note] = [item for item in store.attempts(task_id) if item.is_note]
        self.assertEqual(len(note.refs), 16)


class FederatedRetryRefTests(fed_base.FedCliCase):
    origin = fed_base.as_agent(fed_base.ORIGIN)
    worker = fed_base.as_agent(fed_base.WORKER)

    def write(self, name: str, data: bytes) -> str:
        path = self.root / name
        path.write_bytes(data)
        return str(path)

    def sent_with(self, *refs: str) -> str:
        return self.send(*[flag for path in refs for flag in ("--ref", path)])

    def report_on_b(self, task_id: str, *flags: str) -> None:
        self.pump("vm", "win")
        self.deliver_on_b()
        self.assertEqual(self.run_on("win", "report", task_id, *flags, caller=self.worker)[0], 0)
        self.pump("win", "vm")

    def latest(self, task_id: str):  # noqa: ANN201  夹具返回 FedAttempt
        with self.store("vm") as store:
            return [item for item in store.attempts(fed_base.DEV_A, task_id) if item.role != "notice"][-1]

    def staging_files(self) -> list[tuple[str, int]]:
        """A 的 staging 目录里全部文件（名字与大小），被拒的 retry 不得多出副本。"""
        root = self.states["vm"] / "fed-staging"
        return sorted((str(path.relative_to(root)), path.stat().st_size) for path in root.rglob("*") if path.is_file())

    def sweep_a_day_later(self) -> None:
        with self.store("vm") as store:
            retention.sweep(store, RelayPaths(self.states["vm"]), now=now_ms(),
                            wall_ms=now_ms() + retention.STAGING_GRACE_MS + 60_000)

    def attempts_snapshot(self, task_id: str) -> list[tuple[int, str, str]]:
        with self.store("vm") as store:
            return [(item.seq, item.role, item.delivery) for item in store.attempts(fed_base.DEV_A, task_id)]

    def test_force_inherits_current_refs_rework_inherits_the_first(self) -> None:
        spec = self.write("spec.md", "规格".encode())
        data = self.write("data.md", "数据".encode())
        other = self.write("other.md", "其他".encode())
        task_id = self.sent_with(spec)
        self.report_on_b(task_id, "--blocked")
        self.assertEqual(self.run_on("vm", "retry", task_id, "--ref", data, caller=self.origin)[0], 0)
        self.assertEqual([item["name"] for item in self.latest(task_id).refs], ["spec.md", "data.md"])
        self.report_on_b(task_id, "--progress")
        code, _, err = self.run_on("vm", "retry", task_id, "--force", caller=self.origin)
        self.assertEqual(code, 0, err)
        self.assertEqual([item["name"] for item in self.latest(task_id).refs], ["spec.md", "data.md"])
        self.report_on_b(task_id, "--result", "--note", "完成")
        code, _, err = self.run_on("vm", "retry", task_id, "-m", "再补", "--ref", other, caller=self.origin)
        self.assertEqual(code, 0, err)
        self.assertEqual([item["name"] for item in self.latest(task_id).refs], ["spec.md", "other.md"])

    def big_task(self) -> tuple[str, list[str]]:
        """继承 4×7 MiB blob（28 MiB）的受阻任务。"""
        inherited = [self.write(f"in{index}.bin", bytes([65 + index]) * (7 * MIB)) for index in range(4)]
        task_id = self.sent_with(*inherited)
        self.report_on_b(task_id, "--blocked")
        self.assertEqual([item["transfer"] for item in self.latest(task_id).refs], ["blob"] * 4)
        return task_id, inherited

    def test_inherited_blobs_count_against_the_message_budget(self) -> None:
        self.assertEqual((MAX_BLOB_BYTES, MAX_MESSAGE_BLOB_BYTES), (8 * MIB, 32 * MIB))
        task_id, inherited = self.big_task()
        new = [self.write(f"new{index}.bin", bytes([97 + index]) * (7 * MIB)) for index in range(2)]
        # 再点一个已继承的 7 MiB 文件：先剔掉，不占预算、不被降成第二份「仅引用」
        code, _, err = self.run_on("vm", "retry", task_id, "--ref", inherited[0], *[f for p in new for f in ("--ref", p)],
                                   caller=self.origin)
        self.assertEqual(code, 0, err)
        self.assertNotIn("Traceback", err)
        refs = self.latest(task_id).refs
        self.assertEqual([(item["name"], item["transfer"]) for item in refs],
                         [("in0.bin", "blob"), ("in1.bin", "blob"), ("in2.bin", "blob"), ("in3.bin", "blob"),
                          ("new0.bin", "reference"), ("new1.bin", "reference")])
        self.assertEqual({item["reason"] for item in refs[4:]}, {"message_total_limit"})

    def test_codec_error_after_a_stale_precheck_is_a_closed_code_not_a_traceback(self) -> None:
        task_id, _ = self.big_task()
        new = [self.write(f"new{index}.bin", bytes([97 + index]) * (7 * MIB)) for index in range(2)]
        before = self.attempts_snapshot(task_id)
        staged = self.staging_files()
        # 预判时继承集合为空（模拟预判之后任务被并发改动）：两个新附件都冻结成 blob，合计 42 MiB，
        # 由 retry_task 事务里真实的信封校验（codec.check_refs）拒绝并整体回滚
        with patch.object(authority, "retry_inherited_refs", return_value=[]):
            code, out, err = self.run_on("vm", "retry", task_id, *[f for p in new for f in ("--ref", p)],
                                         caller=self.origin)
        self.assertEqual((code, out), (cli.EXIT_REJECTED, ""))
        self.assertIn("[attachment_too_large]", err)
        self.assertNotIn("Traceback", err)
        self.assertEqual(self.attempts_snapshot(task_id), before)
        # 这一支只能在冻结之后判出：两个新副本留在 staging，没有任何行引用，留存回收 24 小时后删掉，继承的副本不动
        residue = [item for item in self.staging_files() if item not in staged]
        self.assertEqual([size for _, size in residue], [7 * MIB, 7 * MIB])
        self.sweep_a_day_later()
        self.assertEqual(self.staging_files(), staged)

    def test_dedupe_key_is_origin_path_and_sha256(self) -> None:
        first = self.write("a.txt", b"same content")
        task_id = self.sent_with(first)
        self.report_on_b(task_id, "--blocked")
        # 内容相同、路径不同：两份都留
        twin = self.write("b.txt", b"same content")
        code, _, err = self.run_on("vm", "retry", task_id, "--ref", twin, caller=self.origin)
        self.assertEqual(code, 0, err)
        self.assertEqual([item["name"] for item in self.latest(task_id).refs], ["a.txt", "b.txt"])
        # 路径相同、内容已变（大小相同）：按 sha256 区分，两份都留
        self.report_on_b(task_id, "--blocked")
        Path(first).write_bytes(b"SAME CONTENT")
        code, _, err = self.run_on("vm", "retry", task_id, "--ref", first, caller=self.origin)
        self.assertEqual(code, 0, err)
        refs = self.latest(task_id).refs
        self.assertEqual([item["name"] for item in refs], ["a.txt", "a.txt"])
        self.assertEqual(len({item["sha256"] for item in refs}), 2)

    def test_full_inheritance_with_only_inherited_refs_is_accepted(self) -> None:
        inherited = [self.write(f"f{index}.txt", f"{index}".encode()) for index in range(16)]
        task_id = self.sent_with(*inherited)
        self.report_on_b(task_id, "--blocked")
        code, _, err = self.run_on("vm", "retry", task_id, "--ref", inherited[5], caller=self.origin)
        self.assertEqual(code, 0, err)
        self.assertEqual(len(self.latest(task_id).refs), 16)
        self.report_on_b(task_id, "--blocked")
        staged, before = self.staging_files(), self.attempts_snapshot(task_id)
        extra = self.write("extra.txt", b"x")
        code, _, err = self.run_on("vm", "retry", task_id, "--ref", extra, caller=self.origin)
        self.assertEqual((code, "[too_many_files]" in err), (cli.EXIT_REJECTED, True), err)
        # 个数超限在冻结之前判出：staging 一个文件都不多，账本不变
        self.assertEqual((self.staging_files(), self.attempts_snapshot(task_id)), (staged, before))

    def test_refusal_inside_retry_task_leaves_only_sweepable_copies(self) -> None:
        # 资格判定（这里是 retry_requires_force）在 retry_task 的事务里，晚于冻结：副本无人引用，留存回收 24 小时后删除
        task_id = self.send()
        self.report_on_b(task_id, "--progress")
        staged, before = self.staging_files(), self.attempts_snapshot(task_id)
        extra = self.write("extra.txt", b"extra")
        code, _, err = self.run_on("vm", "retry", task_id, "--ref", extra, caller=self.origin)
        self.assertEqual((code, "[retry_requires_force]" in err), (cli.EXIT_REJECTED, True), err)
        self.assertEqual(self.attempts_snapshot(task_id), before)
        self.assertEqual(len(self.staging_files()), len(staged) + 1)
        self.sweep_a_day_later()
        self.assertEqual(self.staging_files(), staged)

    def test_changed_content_over_the_limit_is_refused_after_freezing_and_swept_later(self) -> None:
        # 同一路径内容已变：冻结前按路径预判看不出是新增，冻结后的精确合并（来源路径, sha256）才判出超限
        inherited = [self.write(f"f{index}.txt", f"{index}".encode()) for index in range(16)]
        task_id = self.sent_with(*inherited)
        self.report_on_b(task_id, "--blocked")
        staged, before = self.staging_files(), self.attempts_snapshot(task_id)
        Path(inherited[0]).write_bytes(b"changed")
        code, _, err = self.run_on("vm", "retry", task_id, "--ref", inherited[0], caller=self.origin)
        self.assertEqual((code, "[too_many_files]" in err), (cli.EXIT_REJECTED, True), err)
        self.assertEqual(self.attempts_snapshot(task_id), before)
        residue = [item for item in self.staging_files() if item not in staged]
        self.assertEqual([size for _, size in residue], [len(b"changed")])
        self.sweep_a_day_later()
        self.assertEqual(self.staging_files(), staged)


if __name__ == "__main__":
    import unittest

    unittest.main()
