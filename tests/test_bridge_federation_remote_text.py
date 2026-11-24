"""§103.3 跨设备显示加固（DESIGN §103.3 与第 0 步结论）。

其余远端字符串进人读文字前一律转义或按闭集/形状判：镜像标题、B 出具的投递证据 state、镜像关闭原因、裁决 reason、
report kind、附件名与来源路径、提交号；投给本机 agent 的正文里设备引用不是 slug 时退回完整 deviceId；名字共用判据
（peers、resolve_remote、remote_text 一致）；坏远端记录报 target_remote_invalid。入库与 --json 原样不变。
"""

from __future__ import annotations

import json
import os
from pathlib import Path
import re
import sqlite3
import unittest
from typing import Any

import bridge_support  # noqa: F401  导入即隔离宿主会话环境

from agentstatus_bridge import cli
from agentstatus_bridge.closure import CLOSED
from agentstatus_bridge.federation import authority, commands, directory
from agentstatus_bridge.federation.directory import DirectoryError
from agentstatus_bridge.federation.fedstore import now_ms
from agentstatus_bridge.federation.refs import RemoteEndpointRef, TargetRef, verified_label
from agentstatus_bridge.federation.views import remote_text
from agentstatus_bridge.labels import reason_text
from agentstatus_bridge.model import Provider
from agentstatus_bridge.native_names import altered_char, remote_display, remote_path
from agentstatus_bridge.federation.attachments import sanitize_name
from agentstatus_bridge.federation.delivery import FederationDispatcher
from bridge_support import endpoint
from bridge_support import RecordingTransport
from unittest import mock

from test_bridge_federation_cli import ORIGIN, THREAD_B, WORKER, FedCliCase, as_agent
from test_bridge_federation_delivery import DeliveryTestCase, bind
from test_bridge_federation_directory import NOW, THREAD, DirectoryCase, row
from test_bridge_federation_mirror_work import _MirrorCase, document, lines
from test_bridge_federation_rules import DEV_A, DEV_B, T0, deliver, pump
import test_bridge_federation_relay as relay_fixture

# 能伪造整行的串：换行、ESC、RLO、零宽空格（标题、state、reason 这类字段 codec 只限长度）
FORGED = "x\n  #9 handoff → forged codex@id:y  投递 delivered\x1b[2K\u202e\u200b"
FORGED_ESCAPED = "x\\u000a  #9 handoff → forged codex@id:y  投递 delivered\\u001b[2K\\u202e\\u200b"
# 关闭原因 checkpoint 限 64 字
SHORT_FORGED = "r\n  报告 #9.9 result：accepted\x1b\u202e\u200b"
SHORT_ESCAPED = "r\\u000a  报告 #9.9 result：accepted\\u001b\\u202e\\u200b"
# 附件名与路径 codec 只拒 0x20 以下：NEL、U+2028 同样会被 splitlines 断行，外加 DEL、CSI、RLO、零宽
REF_FORGED = "a\x85  #9 forged\u2028b\u202e\u200b\x7f\x9bc"
REF_ESCAPED = "a\\u0085  #9 forged\\u2028b\\u202e\\u200b\\u007f\\u009bc"
THREAD_LOCAL = "019a0000-1111-7222-8333-444455557777"
RAW_CHARS = "\x1b\u202e\u200b\x7f\x9b\x85\u2028"


def physical(text: str) -> list[str]:
    """按 splitlines 量物理行（列表长度量不到元素内的换行）。"""
    return text.splitlines()


class HelperTests(unittest.TestCase):
    """闭集/形状判据与只转义不截断的路径写法。"""

    def test_closed_fields_keep_codes_and_mark_unknown_values(self) -> None:
        self.assertEqual(commands.delivery_text("queued"), "queued")  # 合法值照旧英文码（测试与 ab.md 钉住）
        self.assertEqual(commands.delivery_text(FORGED), f"未知取值（{FORGED_ESCAPED}）")
        self.assertEqual(commands.delivery_text(None), "未知取值（None）")
        self.assertEqual(commands.report_kind_text("approve"), "approve")
        self.assertEqual(commands.report_kind_text("Result"), "未知取值（Result）")
        self.assertEqual(commands.report_kind_text({"k": 1}), "未知取值（{'k': 1}）")
        # 裁决 reason 只判形状，不枚举（读方不比写方严）：将来新增的码照常显示
        self.assertEqual(commands.code_text("stale_attempt"), "stale_attempt")
        self.assertEqual(commands.code_text("future_reason_code"), "future_reason_code")
        self.assertEqual(commands.code_text(FORGED), f"未知取值（{FORGED_ESCAPED}）")
        self.assertEqual(commands.title_text(FORGED), FORGED_ESCAPED)
        self.assertEqual(commands.title_text(""), "")

    def test_remote_path_escapes_without_truncating(self) -> None:
        long = "/srv/" + "d" * 4000 + REF_FORGED
        shown = remote_path(long)
        assert shown is not None
        self.assertTrue(shown.endswith(REF_ESCAPED), shown[-80:])  # 4096 级长度照样完整
        self.assertNotIn("…", shown)
        self.assertEqual(len(physical(shown)), 1)
        self.assertEqual(remote_path(" /a "), '" /a "')  # 首尾空白用引号标出，与 remote_display 同口径
        self.assertIsNone(remote_path(""))
        self.assertIsNone(remote_path("  "))
        self.assertIsNone(remote_path(None))
        self.assertTrue(remote_display(long).endswith("…"))  # type: ignore[union-attr]  对照：名字/标题照常截断

    def test_result_files_and_commit_from_a_remote_report(self) -> None:
        describe = authority._describe_result  # pyright: ignore[reportPrivateUsage]
        lines_out = describe({"note": "", "refs": [{"name": REF_FORGED, "sha256": "ab" * 32}, {"name": REF_FORGED}],
                              "commit": {"commit": "zz\n提交：forged\u202e"}})
        self.assertEqual(lines_out, [f"文件：{REF_ESCAPED}（sha256 {'ab' * 6}）", f"文件：{REF_ESCAPED}（未传输）",
                                     "提交：未知取值（zz\\u000a提交：forged\\u202e）"])
        for commit in ("abc1234", "ABCDEF1234", "a" * 64):
            with self.subTest(commit=commit):
                self.assertEqual(describe({"commit": {"commit": commit}}), [f"提交：{commit}"])
        for commit in ("abc123", "a" * 65, "abc1234g"):
            with self.subTest(commit=commit):
                self.assertEqual(describe({"commit": {"commit": commit}}), [f"提交：未知取值（{commit}）"])


def without_timeline(rows: list[str]) -> list[str]:
    """去掉联邦 status 的时间线块（标题行与其后缩进两格的事件行），保留其余行（如镜像的汇报页脚）。"""
    titles = [index for index, line in enumerate(rows) if line.startswith("时间线")]
    if not titles:
        return rows
    start = end = titles[0]
    end += 1
    while end < len(rows) and rows[end].startswith("  "):
        end += 1
    return rows[:start] + rows[end:]


class MirrorTextTests(_MirrorCase):
    """status 文字（A 与 B 两侧）里的远端字符串：行数不变、无伪造行、无原样控制/格式字符，--json 原值。"""

    def assert_clean(self, text: str, expected_lines: int) -> None:
        rows = physical(text)
        # §104.9 七 起联邦 status 有本设备时间线：逻辑行与物理行一致才伪造不出行；expected_lines 只数时间线以外的行
        self.assertEqual(len(text.rstrip("\n").split("\n")), len(rows), rows)
        rows = without_timeline(rows)
        self.assertEqual(len(rows), expected_lines, rows)
        self.assertFalse(any(line.lstrip().startswith(("#9 handoff", "报告 #9.9", "#9 forged")) for line in rows), rows)
        self.assertFalse(any(char in text for char in RAW_CHARS), text)

    def test_hostile_mirror_title_is_escaped_on_the_mirror_only_in_text(self) -> None:
        self.b.store.remember_device_name(DEV_A, "vm")
        task, _ = authority.create_task(
            self.a.store, self.a.ident, title=FORGED, flow="handoff", body="b", refs=[], origin=self.origin,
            origin_actor=self.origin_actor(), origin_class="bypass", target=self.worker_remote, reviewer=None, now=T0)
        pump(self.a, self.b, now=T0 + 1)
        for device in (self.b, self.a):
            with self.subTest(device=device.ident.device_name):
                text = lines(device, self.root, task.task_id, T0 + 10)
                self.assertTrue(physical(text)[0].endswith(f"  {FORGED_ESCAPED}"), physical(text)[0])
                self.assert_clean(text, 3)  # 标题行、角色行、一条尝试
                self.assertEqual(document(device, self.root, task.task_id, T0 + 10)["title"], FORGED)

    def test_hostile_evidence_state_on_the_authority(self) -> None:
        task, first = self.create()
        pump(self.a, self.b, now=T0 + 1)
        deliver(self.b, first.msg_id, FORGED, now=T0 + 2)
        pump(self.b, self.a, now=T0 + 3)
        text = lines(self.a, self.root, task.task_id, T0 + 10)
        self.assertIn(f"投递 未知取值（{FORGED_ESCAPED}）", text)
        self.assert_clean(text, 3)
        self.assertEqual(document(self.a, self.root, task.task_id, T0 + 10)["attempts"][0]["delivery"], FORGED)

    def test_hostile_close_reason_on_the_mirror(self) -> None:
        self.b.store.remember_device_name(DEV_A, "vm")
        task, _ = self.delivered()
        current = self.a.store.get_task(DEV_A, task.task_id)
        assert current is not None
        authority.finish(self.a.store, self.a.ident, current, state=CLOSED, reason=SHORT_FORGED, decider="user",
                         sender=None, sender_class="unknown", now=T0 + 5)
        pump(self.a, self.b, now=T0 + 6)
        text = lines(self.b, self.root, task.task_id, T0 + 10)
        self.assertIn(f"已结束（{SHORT_ESCAPED}）", text)
        self.assert_clean(text, 4)  # 标题、角色、工作尝试与结束回执
        mirror_task = self.b.store.get_task(DEV_A, task.task_id)
        assert mirror_task is not None
        view = commands.view_of(commands_runtime(self, self.b), mirror_task)
        self.assertEqual(commands.reason_label(commands_runtime(self, self.b), mirror_task, view), SHORT_ESCAPED)
        self.assertEqual(document(self.b, self.root, task.task_id, T0 + 10)["reason"], SHORT_FORGED)  # JSON 原值

    def test_registered_close_reason_on_the_mirror_still_maps_to_its_text(self) -> None:
        task, _ = self.delivered()
        current = self.a.store.get_task(DEV_A, task.task_id)
        assert current is not None
        authority.finish(self.a.store, self.a.ident, current, state=CLOSED, reason=None, decider="user",
                         sender=None, sender_class="unknown", now=T0 + 5)
        pump(self.a, self.b, now=T0 + 6)
        self.assertIn(f"已结束（{reason_text('closed')}）", lines(self.b, self.root, task.task_id, T0 + 10))

    def test_hostile_decision_reason_on_the_mirror(self) -> None:
        self.b.store.remember_device_name(DEV_A, "vm")
        task, _ = self.delivered()
        self.round_trip(task.task_id, "ack", T0 + 4)
        honest = lines(self.b, self.root, task.task_id, T0 + 10)
        self.assertIn("报告 #1.1 ack：accepted", honest)
        with self.b.store.transaction() as conn:
            conn.execute("UPDATE fed_report_decisions SET decision='rejected', reason=?", (FORGED,))
        text = lines(self.b, self.root, task.task_id, T0 + 10)
        self.assertIn(f"报告 #1.1 ack：rejected（未知取值（{FORGED_ESCAPED}））", text)
        self.assert_clean(text, len(without_timeline(physical(honest))))
        with self.b.store.transaction() as conn:
            conn.execute("UPDATE fed_report_decisions SET reason='stale_attempt'")
        self.assertIn("报告 #1.1 ack：rejected（stale_attempt）", lines(self.b, self.root, task.task_id, T0 + 10))

    def test_hostile_report_kind_on_the_authority(self) -> None:
        task, _ = self.delivered()
        self.round_trip(task.task_id, "ack", T0 + 4)
        honest = lines(self.a, self.root, task.task_id, T0 + 10)
        with self.a.store.transaction() as conn:
            conn.execute("UPDATE fed_reports SET report_json=json_set(report_json,'$.kind',?)", (FORGED,))
        text = lines(self.a, self.root, task.task_id, T0 + 10)
        self.assertIn(f"报告 #1.1 未知取值（{FORGED_ESCAPED}）：accepted", text)
        self.assert_clean(text, len(without_timeline(physical(honest))))
        self.assertEqual(document(self.a, self.root, task.task_id, T0 + 10)["reports"][0]["kind"], FORGED)

    def test_hostile_attachment_name_in_status(self) -> None:
        # 显示代码两侧共用；内存泵不走 relay 的 begin_receiving，镜像侧没有附件行，这里在 A 侧量
        ref = {"originDeviceId": DEV_A, "originalPath": "/big/" + REF_FORGED, "resolvedPath": "/big/x",
               "name": REF_FORGED, "transfer": "reference", "reason": "single_file_limit", "size": 9 * 2**20,
               "sha256": None, "hashState": "not_computed_size_limit"}
        task, _ = authority.create_task(
            self.a.store, self.a.ident, title="t", flow="handoff", body="b", refs=[ref], origin=self.origin,
            origin_actor=self.origin_actor(), origin_class="bypass", target=self.worker_remote, reviewer=None, now=T0)
        text = lines(self.a, self.root, task.task_id, T0 + 10)
        self.assertIn(f"     附件 {REF_ESCAPED}：", text)
        self.assert_clean(text, 4)  # 标题、角色、尝试、附件
        attachment = document(self.a, self.root, task.task_id, T0 + 10)["attempts"][0]["attachments"][0]
        self.assertEqual(attachment["name"], REF_FORGED)


def commands_runtime(case: _MirrorCase, device: Any) -> commands.Runtime:
    from test_bridge_federation_mirror_work import runtime  # 同一夹具构造（只用到 store/ident/paths/config.enabled）
    return runtime(device, case.root)


class DeliveryBodyTests(DeliveryTestCase):
    """投给本机 agent 的正文：页脚 --origin-device 与附件来源的设备引用、附件名与来源路径（§103.3 第 1、2 条）。"""

    def deliver_reference(self, *, name: str, path: str) -> str:
        """本机目标（A 上）收到一条带引用附件的任务：附件来源设备是 B（与既有附件用例同一构造）。"""
        local_worker = bind(self.a, Provider.CODEX, THREAD_LOCAL)
        ref = {"originDeviceId": DEV_B, "originalPath": path, "resolvedPath": path, "name": name,
               "transfer": "reference", "reason": "single_file_limit", "size": 9 * 2**20, "sha256": None,
               "hashState": "not_computed_size_limit"}
        self.create(refs=[ref], target=local_worker)
        transport = RecordingTransport(Provider.CODEX)
        self.dispatcher(self.a, self.a_paths, transport, [self.live(local_worker)]).run_once()
        self.assertEqual(len(transport.calls), 1)
        return transport.calls[0][1]

    def deliver_remote(self) -> str:
        """B 上收到 A 的任务：页脚 --origin-device 指向发起设备 A。"""
        self.create()
        pump(self.a, self.b, now=self.clock.now)
        transport = RecordingTransport(Provider.CODEX)
        self.dispatcher(self.b, self.b_paths, transport, [self.live(self.worker)]).run_once()
        self.assertEqual(len(transport.calls), 1)
        return transport.calls[0][1]

    def test_slug_names_are_used_as_before(self) -> None:
        self.assertIn("来源 win:/big/video.mp4，", self.deliver_reference(name="video.mp4", path="/big/video.mp4"))
        self.assertIn("--origin-device vm --attempt 1", self.deliver_remote())

    def test_non_slug_footer_name_falls_back_to_the_device_id(self) -> None:
        honest = physical(self.deliver_remote())
        # 登记名不是 slug（含空格与 RLO；换行会打断消息头 device=，那是「消息头不改」的既有口径，这里不测）
        self.b.store.put_device_state(device_id=DEV_A, name="v m\u202e", revision=0, snapshot={}, last_seen=None,
                                      state="unknown")
        rows = physical(self.deliver_remote())
        self.assertEqual(len(rows), len(honest), rows)
        footers = [line for line in rows if "--origin-device" in line]
        self.assertTrue(footers and all(f"--origin-device {DEV_A} " in line for line in footers), footers)

    def test_attachment_source_device_name_and_path_in_the_body(self) -> None:
        honest = physical(self.deliver_reference(name="video.mp4", path="/big/video.mp4"))
        self.a.store.put_device_state(device_id=DEV_B, name="w i\u202e", revision=0, snapshot={}, last_seen=None,
                                      state="unknown")
        long_path = "/big/" + "d" * 300 + REF_FORGED
        text = self.deliver_reference(name=REF_FORGED, path=long_path)
        rows = physical(text)
        self.assertEqual(len(rows), len(honest), rows)
        self.assertIn(f"- {REF_ESCAPED}：", text)
        self.assertIn(f"来源 {DEV_B}:{remote_path(long_path)}，", text)  # 设备退回 deviceId，路径只转义不截断
        self.assertFalse(any(char in text for char in RAW_CHARS), text)


class LandedBlobPathTests(relay_fixture.RelayTestCase):
    """§103.8 修 2：镜像侧（B）blob 附件经真实 relay 往返落地后的交付路径。落地名清洗掉 copyable 拒绝集合（换成 `_`），
    B 的 status 与 B 投给 agent 的正文按物理行（splitlines）量不出伪造行；按旧规则已落地的叶名在显示时再转义一次。"""

    NAME = "a\x85b c\u202ed\u200be\x9bf.md"  # 审计实验的原名：NEL、RLO、零宽、CSI

    def land_on_b(self) -> tuple[Any, Any, Path]:
        refs = self.freeze(self.a, (self.NAME, b"payload"))
        task, first = self.create(refs)
        self.assertEqual(self.a.cycle(), "connected")
        self.tick()
        self.assertEqual(self.b.cycle(), "connected")
        (manifest,) = self.b.store.attachments(first.msg_id)
        self.assertEqual((manifest["state"], manifest["location"]), ("ready", "delivery"))
        landed = self.b.paths.delivery_base(self.b.store.ledger_instance_id()) / manifest["local_relpath"]
        return task, first, landed

    def b_runtime(self) -> commands.Runtime:
        return commands.Runtime(root=self.b.root, config=self.b.config, store=self.b.store, ident=self.b.ident,
                                paths=self.b.paths)

    def b_status(self, task_id: str) -> tuple[list[str], dict[str, Any]]:
        task = self.b.store.get_task(self.a.device_id, task_id)
        assert task is not None
        runtime = self.b_runtime()
        return (commands.task_lines(runtime, task, now=self.clock.now),
                commands.task_document(runtime, task, now=self.clock.now))

    def b_body(self) -> str:
        transport = RecordingTransport(Provider.CODEX)
        assert self.worker.local is not None
        with mock.patch("agentstatus_bridge.federation.delivery.root_binding", return_value="root"):
            FederationDispatcher(self.b.store, self.b.ident, self.b.paths, discover=lambda: [endpoint(self.worker.local)],
                                 transports={Provider.CODEX: transport}, reply_address=None, clock=self.clock,
                                 command="ab").run_once()
        self.assertEqual(len(transport.calls), 1)
        return transport.calls[0][1]

    def assert_physical(self, text: str) -> None:
        # 逻辑行（按 \n）与物理行（splitlines，NEL/U+2028 等也会断行）相同，且没有原始的拒绝集合字符
        self.assertEqual(len(text.splitlines()), text.count("\n") + 1, text)
        self.assertFalse([char for char in text if altered_char(char) and char != "\n"], text)

    def test_landed_name_is_clean_and_status_and_body_have_no_forged_lines(self) -> None:
        task, _, landed = self.land_on_b()
        self.assertEqual(landed.name.split("-", 1)[1], "a_b c_d_e_f.md")
        self.assertEqual(landed.read_bytes(), b"payload")
        lines_out, document = self.b_status(task.task_id)
        text = "\n".join(lines_out)
        self.assert_physical(text)
        self.assertIn(f"附件 {remote_display(self.NAME)}：ready（7 B） {landed}", text)  # 落地名已安全：路径原样
        self.assertEqual(document["attempts"][0]["attachments"][0]["path"], str(landed))  # --json 原值
        self.assertEqual(document["attempts"][0]["attachments"][0]["name"], self.NAME)
        body = self.b_body()
        self.assert_physical(body)
        self.assertIn(f"- {remote_display(self.NAME)}：{landed}（7 B，", body)

    def test_leaf_landed_under_the_old_rule_is_escaped_on_display(self) -> None:
        task, first, landed = self.land_on_b()
        legacy = landed.with_name(landed.name.split("-", 1)[0] + "-" + self.NAME)  # 旧规则只去 C0/DEL
        os.rename(landed, legacy)
        base = self.b.paths.delivery_base(self.b.store.ledger_instance_id())
        self.b.store.update_attachment(first.msg_id, 0, local_relpath=str(legacy.relative_to(base)))
        lines_out, document = self.b_status(task.task_id)
        text = "\n".join(lines_out)
        self.assert_physical(text)
        self.assertIn(f" {remote_path(str(legacy))}", text)
        self.assertEqual(document["attempts"][0]["attachments"][0]["path"], str(legacy))  # --json 原值
        body = self.b_body()
        self.assert_physical(body)
        self.assertIn(f"- {remote_display(self.NAME)}：{remote_path(str(legacy))}（7 B，", body)

    def test_sanitize_replaces_the_copyable_reject_set(self) -> None:
        self.assertEqual(sanitize_name(self.NAME), "a_b c_d_e_f.md")
        self.assertEqual(sanitize_name("ok\x01\x7fname"), "okname")  # C0 与 DEL 照旧去掉
        self.assertEqual(sanitize_name("x\u2028y\u2029z\ue000w\U000f0000v"), "x_y_z_w_v")
        self.assertEqual(sanitize_name("任务书.md"), "任务书.md")  # 正常名字不变
        self.assertEqual(sanitize_name("CON\u200b.txt"), "CON_.txt")


class ResolveConsistencyTests(DirectoryCase):
    """§103.3 第 3 条：verified_label 是 peers 文字行、resolve_remote（含 label）与 remote_text 的共用判据。"""

    NON_COPYABLE = ("a\u200bb", "a\u202eb", "x" * 121, "a\x7fb")

    def test_shared_predicate(self) -> None:
        self.assertEqual(verified_label("impl", True), "impl")
        self.assertEqual(verified_label("m" * 120, True), "m" * 120)
        for name, verified in (("impl", False), ("impl", "true"), (None, True), ("impl ", True), (" impl", True),
                               ("id:abc", True), (THREAD, True), *((item, True) for item in self.NON_COPYABLE)):
            with self.subTest(name=name, verified=verified):
                self.assertIsNone(verified_label(name, verified))

    def test_non_copyable_verified_names_are_unverified_under_both_frame_policies(self) -> None:
        for policy in (directory.NAME_POLICY, None):
            # 旧帧里 ≥32 字的值沿旧启发式按 nativeId 精确匹配，不是名字（见 resolve_remote 文档）
            for name in (item for item in self.NON_COPYABLE if policy is not None or len(item) < 32):
                with self.subTest(policy=policy, name=name):
                    self.put(row(THREAD, name), policy=policy)
                    with self.assertRaises(DirectoryError) as caught:
                        directory.resolve_remote(self.store, "win", f"codex@{name}", now=NOW)
                    self.assertEqual((caught.exception.code, caught.exception.candidates),
                                     ("target_names_unverified", (f"codex@id:{THREAD}",)))
                    [line] = [item for item in directory.peer_lines(self.store, None, now=NOW) if "codex@" in item]
                    self.assertIn("（仅展示）", line)  # peers 同样不写成 provider@名字

    def test_copyable_verified_names_still_resolve_under_both_frame_policies(self) -> None:
        for policy in (directory.NAME_POLICY, None):
            with self.subTest(policy=policy):
                self.put(row(THREAD, "impl"), policy=policy)
                resolved = directory.resolve_remote(self.store, "win", "codex@impl", now=NOW).remote
                self.assertEqual((resolved.native_id, resolved.display_label), (THREAD, "impl"))

    def test_label_from_an_id_match_uses_the_shared_predicate(self) -> None:
        for name, label in (("impl", "impl"), ("a\u200bb", None), ("x" * 121, None)):
            with self.subTest(name=name):
                self.put(row(THREAD, name))
                resolved = directory.resolve_remote(self.store, "win", f"codex@id:{THREAD}", now=NOW).remote
                self.assertEqual(resolved.display_label, label)
                target = TargetRef(remote=resolved)
                self.assertEqual("target=" in remote_text(target, "win") and "@impl " in remote_text(target, "win"),
                                 label is not None)

    def test_remote_text_rejects_a_stored_non_copyable_label(self) -> None:
        # 本节之前的 resolve_remote 不按 copyable 过滤 label：旧账本里可能存着这样的 display_label，显示时同一判据挡住
        for label, annotated in (("impl", True), ("a\u200bb", False), ("a\u202eb", False), (" impl", False)):
            with self.subTest(label=label):
                remote = RemoteEndpointRef(device_id=DEV_B, provider=Provider.CODEX, native_id=THREAD,
                                           endpoint_id="e" * 32, display_label=label)
                text = remote_text(TargetRef(remote=remote), "win")
                self.assertEqual(text.startswith(f"win 上的 codex@{label} target="), annotated, text)
                if not annotated:
                    self.assertEqual(text, f"win 上的 codex@id:{THREAD}")

    def test_bad_remote_records_report_target_remote_invalid(self) -> None:
        base = row(THREAD, "impl")
        cases: list[tuple[str, dict[str, object], str]] = [
            ("newline", {**base, "nativeId": THREAD + "\nx"}, "codex@impl"),
            ("space", {**base, "nativeId": THREAD + " x"}, "codex@impl"),
            ("long", {**base, "nativeId": THREAD + "x" * 120}, "codex@impl"),
            ("prefix", {**base, "nativeId": THREAD + "\tx"}, "codex@id:019a0000"),
            ("provider", {**base, "provider": "foo"}, THREAD),  # 裸完整 UUID 不按 provider 过滤：原先打 traceback
            ("endpoint_id", {**base, "endpointId": "not-hex"}, f"codex@id:{THREAD}"),
            ("endpoint_missing", {key: value for key, value in base.items() if key != "endpointId"}, "codex@impl"),
            ("revision", {**base, "endpointRevision": "x"}, f"codex@id:{THREAD}"),
            ("legacy_long", {**base, "nativeId": "n" * 130}, "codex@" + "n" * 130),  # 旧帧 ≥32 字按 nativeId
        ]
        for label, item, selector in cases:
            with self.subTest(label=label):
                self.put(item, policy=None if label == "legacy_long" else directory.NAME_POLICY)
                self.assertEqual(self.code(selector), directory.TARGET_REMOTE_INVALID)
        self.put(base)  # 合规记录照常
        self.assertEqual(directory.resolve_remote(self.store, "win", "codex@impl", now=NOW).remote.native_id, THREAD)

    def test_honest_record_shapes_round_trip_through_from_dict(self) -> None:
        self.put(row(THREAD, "impl"))
        resolved = directory.resolve_remote(self.store, "win", f"codex@id:{THREAD}", now=NOW).remote
        self.assertEqual(RemoteEndpointRef.from_dict(resolved.to_dict()), resolved)
        self.assertEqual(resolved.endpoint_revision, 1)


class CliRemoteInvalidTests(FedCliCase):
    """坏远端记录经 send 的完整路径：退出码 2（原先 corrupt_record/3）、闭集码进 stderr、联邦库零写入。"""

    def counts(self) -> dict[str, int]:
        with self.store("vm") as store:
            path = store.path
        with sqlite3.connect(path) as conn:
            return {table: conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
                    for table in ("fed_tasks", "fed_attempts", "fed_outbox")}

    def setUp(self) -> None:
        super().setUp()
        with self.store("vm") as store:
            [state] = store.device_states()
            self.snapshot = dict(state["snapshot"])

    def put_endpoint(self, **changes: object) -> None:
        with self.store("vm") as store:
            snapshot = dict(self.snapshot)
            snapshot["endpoints"] = [{**snapshot["endpoints"][0], **changes}]
            store.put_device_state(device_id=DEV_B, name="win", revision=2, snapshot=snapshot, last_seen=now_ms(),
                                   state="online")

    def test_bad_native_id_and_unknown_provider_exit_2_and_record_nothing(self) -> None:
        before = self.counts()
        cases = (({"nativeId": THREAD_B + "\nx", "name": "impl", "namesVerified": True}, "codex@impl"),
                 ({"nativeId": THREAD_B + " x", "name": "impl", "namesVerified": True}, "codex@impl"),
                 ({"provider": "foo"}, THREAD_B))
        for changes, selector in cases:
            with self.subTest(selector=selector, changes=changes):
                self.put_endpoint(**changes)
                code, out, err = self.run_on("vm", "send", "--device", "win", "--to", selector, "-m", "X",
                                             caller=as_agent(ORIGIN))
                self.assertEqual((code, out), (cli.EXIT_TARGET, ""), err)
                self.assertIn("[target_remote_invalid]", err)
                self.assertNotIn("Traceback", err)
                self.assertEqual(self.counts(), before)


class CliFyiDeliveryTests(FedCliCase):
    """告知任务的投递状态（status 的「已告知（…）」与 tasks --all 的「投递 …」）：B 回传的 state 闭集外写「未知取值」。"""

    def test_hostile_fyi_delivery_state(self) -> None:
        state = "queued\n  #9 forged\x1b\u202e\u200b"
        escaped = "queued\\u000a  #9 forged\\u001b\\u202e\\u200b"
        code, out, err = self.run_on("vm", "send", "--device", "win", "--to", f"codex@id:{THREAD_B}", "--fyi", "-m", "Z",
                                     "--json", caller=as_agent(ORIGIN))
        self.assertEqual(code, 0, err)
        fyi = json.loads(out)["id"]
        with self.store("vm") as store, store.transaction() as conn:
            conn.execute("UPDATE fed_attempts SET delivery_json=json_set(delivery_json,'$.state',?) WHERE task_id=?",
                         (state, fyi))
        tasks = self.run_on("vm", "tasks", "--all")[1]
        [line] = [item for item in physical(tasks) if item.startswith(fyi[:8])]
        self.assertIn(f"投递 未知取值（{escaped}）", line)
        status = self.run_on("vm", "status", fyi)[1]
        self.assertIn(f"已告知（关闭）（未知取值（{escaped}））", status)
        for text in (tasks, status):
            self.assertFalse(any(char in text for char in "\x1b\u202e\u200b"), text)
            self.assertFalse(any(item.lstrip().startswith("#9 forged") for item in physical(text)), text)


class CliTitleTests(FedCliCase):
    """镜像标题进 B 的 tasks 文字、联邦旧任务标题进 status 的「承接任务」：转义、不伪造行，--json 原值。"""

    def test_hostile_title_on_mirror_tasks_and_follow_links(self) -> None:
        title = "t\n  #9 forged\x1b\u202e\u200b"
        escaped = "t\\u000a  #9 forged\\u001b\\u202e\\u200b"
        code, out, err = self.run_on("vm", "send", "--device", "win", "--to", f"codex@id:{THREAD_B}", "-m", "X",
                                     "--title", title, "--json", caller=as_agent(ORIGIN))
        self.assertEqual(code, 0, err)
        first = json.loads(out)["id"]
        self.assertGreaterEqual(self.pump("vm", "win"), 1)
        code, out, err = self.run_on("win", "tasks", caller=as_agent(WORKER))
        self.assertEqual(code, 0, err)
        [line] = [item for item in physical(out) if item.startswith(first[:8])]
        self.assertIn(f" {escaped}  （跨设备·", line)
        self.assertFalse(any(char in out for char in "\x1b\u202e\u200b"), out)
        self.assertFalse(any(item.lstrip().startswith("#9 forged") for item in physical(out)), out)
        tasks_json = json.loads(self.run_on("win", "tasks", "--json", caller=as_agent(WORKER))[1])
        self.assertEqual(tasks_json["federation"][0]["title"], title)
        # 「承接任务」：后续任务承接这条联邦任务，status 里旧标题同样转义
        code, out, err = self.run_on("vm", "send", "--device", "win", "--to", f"codex@id:{THREAD_B}", "-m", "Y",
                                     "--follows", first[:8], "--json", caller=as_agent(ORIGIN))
        self.assertEqual(code, 0, err)
        second = json.loads(out)["id"]
        code, out, err = self.run_on("vm", "status", second)
        self.assertEqual(code, 0, err)
        self.assertIn(f"承接任务 {first[:8]}（{escaped}）", out)
        self.assertFalse(any(char in out for char in "\x1b\u202e\u200b"), out)
        self.assertTrue(re.search(r"^  承接任务 ", out, re.MULTILINE), out)


if __name__ == "__main__":
    unittest.main()
