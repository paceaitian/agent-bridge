"""§104.9 七：跨设备 status 的时间线（文字与 --json）、尝试时刻与投递证据；§104.9 二：status 的「定时发出」行。"""

from __future__ import annotations

import json
import unittest

import bridge_support  # noqa: F401  导入即隔离宿主会话环境
import test_bridge_cli as local_base  # 只借夹具方法
import test_bridge_federation_cli as fed_base

from agentstatus_bridge import views
from agentstatus_bridge.federation import commands as fed_commands
from agentstatus_bridge.federation.fedstore import now_ms
from agentstatus_bridge.labels import (
    DELIVERY_LABELS,
    FEDERATION_EVENT_LABELS,
    REASON_TEXTS,
    TRANSPORT_EVENT_LABELS,
    reason_registered,
    reason_text,
)
from agentstatus_bridge.model import Delivery
from agentstatus_bridge.model import DEFER_OPTION

DEV_A = fed_base.DEV_A


def physical_lines(text: str) -> int:
    return len(text.splitlines())


class FederatedTimelineTests(fed_base.FedCliCase):
    def status(self, device: str, task_id: str, *extra: str) -> str:
        caller = fed_base.as_agent(fed_base.ORIGIN if device == "vm" else fed_base.WORKER)
        code, out, err = self.run_on(device, "status", task_id, *extra, caller=caller)
        self.assertEqual(code, 0, err)
        return out

    def test_authority_text_timeline_uses_local_format_and_device_note(self) -> None:
        task_id = self.delivered_task()
        self.pump("win", "vm")
        text = self.status("vm", task_id)
        lines = text.splitlines()
        [title] = [line for line in lines if line.startswith("时间线")]
        self.assertRegex(title, r"^时间线（UTC[+-]\d{2}:\d{2}，本设备记录）：$")
        timeline = lines[lines.index(title) + 1:]
        self.assertTrue(any(line.endswith(" #1 创建任务") for line in timeline), timeline)
        self.assertTrue(any(" #1 已交出（进入 Codex 队列）" in line or " #1 " in line and "队列" in line
                            for line in timeline), timeline)
        # 页脚以外的行都在时间线之前；A 不是执行方，没有汇报页脚
        self.assertFalse(any(line.startswith("汇报：") for line in lines))

    def test_mirror_shows_its_own_records_without_delivery_events_and_footer_stays_last(self) -> None:
        task_id = self.delivered_task()
        text = self.status("win", task_id)
        lines = text.splitlines()
        [title] = [line for line in lines if line.startswith("时间线")]
        self.assertIn("本设备记录", title)
        timeline = lines[lines.index(title) + 1:-1]
        self.assertTrue(any("收到交接" in line for line in timeline), timeline)
        self.assertTrue(lines[-1].startswith("汇报："), lines[-1])

    def test_json_adds_optional_times_events_and_authority_only_evidence(self) -> None:
        task_id = self.delivered_task()
        self.pump("win", "vm")
        document = json.loads(self.status("vm", task_id, "--json"))
        with self.store("vm") as store:
            [first] = store.attempts(DEV_A, task_id)
            stored_events = store.events(DEV_A, task_id, limit=50)
        row = document["attempts"][0]
        self.assertEqual(row["createdAt"], first.authority_state["createdAt"] / 1000.0)
        self.assertEqual(row["deliveryAt"], first.delivery["at"] / 1000.0)
        self.assertIsInstance(row["createdAt"], float)
        self.assertEqual([(event["kind"], event["at"]) for event in document["events"]],
                         [(event["kind"], event["at"] / 1000.0) for event in stored_events])
        self.assertTrue(row["evidence"])
        self.assertEqual(set(row["evidence"][0]), {"no", "state", "reason", "at"})
        self.assertEqual(row["evidence"][-1]["state"], first.delivery["state"])
        # 镜像端：有时刻与本设备 events，没有 evidence
        mirror = json.loads(self.status("win", task_id, "--json"))
        self.assertIn("createdAt", mirror["attempts"][0])
        self.assertTrue(mirror["events"])
        self.assertNotIn("evidence", mirror["attempts"][0])
        # 复用 task_document 的其他输出只多尝试时刻，不带 events/evidence
        code, out, err = self.run_on("vm", "tasks", "--json", caller=fed_base.as_agent(fed_base.ORIGIN))
        self.assertEqual(code, 0, err)
        [entry] = [item for item in json.loads(out)["federation"] if item["id"] == task_id]
        self.assertNotIn("events", entry)
        self.assertNotIn("evidence", entry["attempts"][0])
        self.assertIn("createdAt", entry["attempts"][0])
        # lastSyncAt 维持毫秒
        self.assertIsInstance(document["lastSyncAt"], int)

    def test_every_federation_only_kind_has_a_label(self) -> None:
        def text(event_kind: str, **detail: object) -> str:
            label, extra = fed_commands.fed_event_text({"attemptSeq": 1, "at": 1.0, "kind": event_kind,
                                                        "detail": detail})
            return f"{label}：{extra}" if extra else label

        for kind, label in FEDERATION_EVENT_LABELS.items():
            self.assertEqual(text(kind), label)
        for state, label in TRANSPORT_EVENT_LABELS.items():
            self.assertEqual(text(f"transport_{state}"), f"传输：{label}")
        self.assertEqual(text("report_result_saved"), "已提交汇报（result），等待发起设备确认")
        self.assertEqual(text("delivery_queued"), "已进入 Codex 队列")
        self.assertEqual(text("origin_reminded", reason="silent", minutes=30), "对方 30 分钟没有汇报，已提醒发起方")
        # 本机也会写的 kind：与本机时间线同一标签与附注
        for event in ({"kind": "origin_reminded", "detail": {"reason": "delivery_failed", "immediate": True}},
                      {"kind": "origin_reminded", "detail": {"reason": "result_submitted"}},
                      {"kind": "created", "detail": {"flow": "handoff"}},
                      {"kind": "delivery_failed", "detail": {"reason": "codex_deadline_before_send"}},
                      {"kind": "review_skipped_capacity", "detail": {"reason": "capacity_pending"}}):
            row = {"attemptSeq": 1, "at": 1.0, **event}
            self.assertEqual(fed_commands.fed_event_text(row), views._local_event_text(row))  # pyright: ignore[reportPrivateUsage]
        self.assertEqual(text("report_rejected", reason="stale_attempt", kind="result"),
                         "汇报未被发起设备采纳：这是旧的一次交接，任务已有更新的尝试；类别 result")
        self.assertTrue(text("notification_skipped", reason="capacity_attempts").startswith("未排通知："))

    def test_hostile_kinds_and_details_are_escaped_in_text_and_raw_in_json(self) -> None:
        task_id = self.send()
        hostile = [
            ("delivery_\n伪造 行", {"reason": "x\ny"}),
            ("transport_\x1b[2K", {"kind": "handoff", "reason": "hub\u202ebusy"}),
            ("report_\u202e坏", {"reason": None}),
            ("report_rejected", {"reason": "stale_attempt", "kind": "\u200b坏\n类"}),
            ("report_\n_saved", {}),
            ("future_\u2028kind", {}),
        ]
        with self.store("vm") as store:
            for kind, detail in hostile:
                store.add_event(DEV_A, task_id, kind, now=now_ms(), attempt_seq=1, detail=detail)
        text = self.status("vm", task_id)
        self.assertEqual(physical_lines(text), text.count("\n") + (0 if text.endswith("\n") else 1))
        for char in ("\x1b", "\u202e", "\u200b", "\u2028"):
            self.assertNotIn(char, text)
        lines = text.splitlines()
        [title] = [line for line in lines if line.startswith("时间线")]
        timeline = lines[lines.index(title) + 1:]
        # 每个注入事件恰好一行：伪造不出新行
        self.assertEqual(len([line for line in timeline if line.startswith("  ")]), len(timeline))
        self.assertTrue(any("投递证据：未知取值（" in line and "未知取值（x\\u000ay）" in line for line in timeline))
        self.assertTrue(any("传输：未知取值（" in line for line in timeline))
        self.assertTrue(any("发起设备裁决：未知取值（" in line for line in timeline))
        self.assertTrue(any("类别 未知取值（" in line for line in timeline))
        self.assertTrue(any("已提交汇报（未知取值（" in line for line in timeline))
        self.assertTrue(any(line.endswith("未知取值（future_\\u2028kind）") for line in timeline), timeline)
        # --json 给原值
        events = json.loads(self.status("vm", task_id, "--json"))["events"]
        self.assertIn("delivery_\n伪造 行", [event["kind"] for event in events])
        self.assertIn("future_\u2028kind", [event["kind"] for event in events])

    def test_unregistered_reason_is_never_expanded_as_a_local_template(self) -> None:
        """§104.12 第 10 条：远端原因码先显式查登记，命中才展开本地文案；其余一律 code_text（不替换占位、转义）。"""
        hostile = ["fixture {command} reason", "{command}", "{ref}", "a{b}c", "{", "x\ny {command}", "\x1b[2K{command}",
                   "delivery_\n{command}", "delivery_failed{command}"]
        for reason in hostile:
            with self.subTest(reason=reason):
                self.assertFalse(reason_registered(reason))
                _, extra = fed_commands.fed_event_text({"kind": "transport_rejected", "detail": {"reason": reason}})
                self.assertEqual(extra, fed_commands.code_text(reason))
                assert isinstance(extra, str)
                self.assertTrue(extra.startswith("未知取值（"), extra)
                for char in ("\n", "\x1b"):
                    self.assertNotIn(char, extra)
                if "{command}" in reason:
                    self.assertIn("{command}", extra)  # 占位原样留着，没有被换成入口名
        # 两层各自成立：即使 reason_text 将来又对未知码展开占位，时间线这一层也不把未登记的码交给它
        from unittest.mock import patch

        def regressed(code: str, **kwargs: object) -> str:
            return reason_text(code) if reason_registered(code) else code.replace("{command}", "EXPANDED")

        with patch.object(fed_commands, "reason_text", side_effect=regressed):
            _, extra = fed_commands.fed_event_text({"kind": "transport_rejected",
                                                    "detail": {"reason": "fixture {command} reason"}})
        self.assertEqual(extra, fed_commands.code_text("fixture {command} reason"))
        # 登记过的码照旧用本地文案，文案里的 {command} 换成入口名
        _, extra = fed_commands.fed_event_text({"kind": "transport_rejected", "detail": {"reason": "capacity_attempts"}})
        self.assertIn("{command}", REASON_TEXTS["capacity_attempts"])
        self.assertEqual(extra, reason_text("capacity_attempts"))
        self.assertNotIn("{command}", str(extra))
        # 合法投递枚举用投递标签；delivery_ 前缀加闭集外取值不算登记，形状合规就原样写码
        _, extra = fed_commands.fed_event_text({"kind": "transport_rejected", "detail": {"reason": "delivery_failed"}})
        self.assertEqual(extra, DELIVERY_LABELS[Delivery.FAILED])
        self.assertFalse(reason_registered("delivery_bogus"))
        _, extra = fed_commands.fed_event_text({"kind": "transport_rejected", "detail": {"reason": "delivery_bogus"}})
        self.assertEqual(extra, "delivery_bogus")
        # 形状合规的未登记码原样写码
        _, extra = fed_commands.fed_event_text({"kind": "transport_rejected", "detail": {"reason": "future_code"}})
        self.assertEqual(extra, "future_code")
        # 本机 reason_text 对未登记的码也不再替换占位
        self.assertEqual(reason_text("fixture {command} reason"), "fixture {command} reason")
        # 端到端：注入进账本的原因在 status 文字里仍是一行、占位不展开
        task_id = self.send()
        with self.store("vm") as store:
            store.add_event(DEV_A, task_id, "transport_rejected", now=now_ms(), attempt_seq=1,
                            detail={"reason": "伪造 {command}\n下一行 {ref}"})
        text = self.status("vm", task_id)
        [line] = [line for line in text.splitlines() if "伪造" in line]
        self.assertIn("未知取值（伪造 {command}\\u000a下一行 {ref}）", line)
        self.assertEqual(len([item for item in text.splitlines() if "下一行" in item]), 1)  # 伪造不出新行

    def test_text_shows_at_most_twenty_events_and_json_fifty(self) -> None:
        task_id = self.send()
        with self.store("vm") as store:
            for index in range(60):
                store.add_event(DEV_A, task_id, "paused" if index % 2 else "resumed", now=now_ms(), attempt_seq=None)
        text = self.status("vm", task_id)
        lines = text.splitlines()
        [title] = [line for line in lines if line.startswith("时间线")]
        self.assertEqual(len(lines[lines.index(title) + 1:]), fed_commands.TIMELINE_TEXT_EVENTS)
        self.assertEqual(len(json.loads(self.status("vm", task_id, "--json"))["events"]),
                         fed_commands.TIMELINE_JSON_EVENTS)

    def test_deferred_remote_attempt_shows_scheduled_time(self) -> None:
        task_id = self.send()
        due = 2_000_000_000.0
        with self.store("vm") as store:
            [first] = store.attempts(DEV_A, task_id)
            store.update_attempt_columns(first.msg_id, options={**first.options, DEFER_OPTION: due})
        text = self.status("vm", task_id)
        self.assertIn(views.deferred_text(due), text)
        self.assertEqual(text.count("定时发出："), 1)


class LocalStatusDeferAndSilentTests(unittest.TestCase):
    setUp = local_base.CliTests.setUp
    run_cli = local_base.CliTests.run_cli
    send = local_base.CliTests.send
    store = local_base.CliTests.store
    mark_sent = local_base.CliTests.mark_sent

    def test_pending_deferred_attempt_prints_scheduled_time_until_sent(self) -> None:
        task_id = self.send()
        due = 2_000_000_000.0
        with self.store() as store:
            [first] = store.attempts(task_id)
            store._conn.execute("UPDATE attempts SET options=? WHERE id=?",  # pyright: ignore[reportPrivateUsage]
                                (json.dumps({**first.options, DEFER_OPTION: due}), first.id))
            store._conn.commit()  # pyright: ignore[reportPrivateUsage]
        code, out, err = self.run_cli("status", task_id)
        self.assertEqual(code, 0, err)
        self.assertIn(f"      {views.deferred_text(due)}", out)
        self.mark_sent(task_id)
        self.assertNotIn("定时发出：", self.run_cli("status", task_id)[1])

    def test_silent_reminder_event_label(self) -> None:
        rows = views._timeline_lines([  # pyright: ignore[reportPrivateUsage]
            {"attemptSeq": 1, "at": 1000.0, "kind": "origin_reminded", "detail": {"reason": "silent", "minutes": 45}},
            {"attemptSeq": 1, "at": 1001.0, "kind": "origin_reminded", "detail": {"reason": "delivery_failed",
                                                                                "immediate": True}},
            {"attemptSeq": 1, "at": 1002.0, "kind": "origin_reminded", "detail": {"reason": "result_submitted"}},
        ])
        self.assertTrue(rows[1].endswith(" #1 对方 45 分钟没有汇报，已提醒发起方"), rows[1])
        self.assertIn("投递未成功，已告知发起方", rows[2])
        self.assertIn("超时未处理，提醒发起方", rows[3])

    def test_silent_reminder_without_minutes_falls_back_with_reason(self) -> None:
        # 合并口径：带分钟数不加附注；缺分钟数（或形状不对）退回固定文字，附注照常写原因（labels.reminded_label 唯一一份）
        rows = views._timeline_lines([  # pyright: ignore[reportPrivateUsage]
            {"attemptSeq": 2, "at": 1000.0, "kind": "origin_reminded", "detail": {"reason": "silent"}},
            {"attemptSeq": 2, "at": 1001.0, "kind": "origin_reminded", "detail": {"reason": "silent", "minutes": True}},
        ])
        for row in rows[1:]:
            self.assertTrue(row.endswith(" #2 对方迟迟没有汇报，已提醒发起方：从锚点起满设定时长没有新的汇报"), row)
        for detail in ({"reason": "silent", "minutes": 30}, {"reason": "silent"}):
            event = {"attemptSeq": 1, "at": 1.0, "kind": "origin_reminded", "detail": detail}
            self.assertEqual(fed_commands.fed_event_text(event), views._local_event_text(event))  # pyright: ignore[reportPrivateUsage]


if __name__ == "__main__":
    unittest.main()
