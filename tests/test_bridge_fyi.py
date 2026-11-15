"""`ab send --fyi`：一句话告知（DESIGN §95.5.7）——建立即关闭、结束后仍投递、页脚、显示、互斥参数与跨设备能力门。

本模块在 `bridge-windows` CI 选择集里（§95.6）：纯函数用例两种系统都跑；替身 Linux 发现与本机账本的夹具类在
Windows 上按选择器放行的 `POSIX-only:` 前缀跳过（与 test_bridge_note 同一做法）。
"""

from __future__ import annotations

import json
import os
import unittest

import bridge_support  # noqa: F401  导入即隔离宿主会话环境
import test_bridge_federation_cli as federation_cli  # 联邦夹具类自带 POSIX-only 跳过（§94.3 已在选择集里导入）

from agentstatus_bridge import envelope
from agentstatus_bridge.dispatch import native_priority
from agentstatus_bridge.labels import EVENT_LABELS, FYI_LABEL, REASON_TEXTS, role_label
from agentstatus_bridge.model import (
    CLOSURE_KIND,
    FYI_KIND,
    FYI_OPTION,
    NOTICE_KIND_OPTION,
    QUIET_NOTICE_KINDS,
    Attempt,
    Delivery,
    Flow,
    Phase,
    Provider,
    Role,
    Task,
    Work,
    describe,
)
from agentstatus_bridge.reminders import pending_reminder
from bridge_support import ref

LINUX_FIXTURE_REASON = "POSIX-only: 替身 Linux 发现与调用方、Linux 私有状态目录（Windows 缺省平台是真实 Win32）"
linux_fixture = unittest.skipUnless(os.name == "posix", LINUX_FIXTURE_REASON)

TASK_ID = "2" * 32
LEAD_REF = ref(Provider.CLAUDE, "lead-session", pid=3000, pane="%3", label="lead")
IMPL_REF = ref(Provider.CODEX, "impl-thread", pid=1000, pane="%1", label="impl")


def fyi_task(**changes: object) -> Task:
    fields: dict[str, object] = dict(id=TASK_ID, created_at=10.0, updated_at=10.0, title="新版已部署", flow=Flow.HANDOFF,
                                     origin=LEAD_REF, reviewer=None, closed_at=10.0, close_reason="fyi",
                                     options={FYI_OPTION: True})
    fields.update(changes)
    return Task(**fields)  # type: ignore[arg-type]


def fyi_attempt(**changes: object) -> Attempt:
    fields: dict[str, object] = dict(
        id="a" * 32, task_id=TASK_ID, seq=1, role=Role.NOTICE, target=IMPL_REF, message_id="b" * 32, created_at=10.0,
        body="新版已部署，旧命令别用", work=Work.NONE, options={NOTICE_KIND_OPTION: FYI_KIND})
    fields.update(changes)
    return Attempt(**fields)  # type: ignore[arg-type]


class FyiModelTests(unittest.TestCase):
    """纯函数：谓词、页脚、优先级、标签、阶段与提醒（两种系统都跑）。"""

    def test_predicates(self) -> None:
        notice = fyi_attempt()
        self.assertTrue(notice.is_fyi and notice.delivers_after_finish and notice.steers)
        # 告知不是结束回执：closure_not_needed、coversWorkMessageIds 等结束回执语义不作用到它
        self.assertFalse(notice.is_closure or notice.is_note)
        closure = fyi_attempt(options={NOTICE_KIND_OPTION: CLOSURE_KIND})
        self.assertTrue(closure.delivers_after_finish)
        self.assertFalse(closure.steers)  # 结束回执本轮不改通道（§95.5.4）
        plain = fyi_attempt(options={})
        self.assertFalse(plain.is_fyi or plain.delivers_after_finish or plain.steers)
        self.assertFalse(fyi_attempt(role=Role.HANDOFF).is_fyi)
        self.assertTrue(fyi_task().is_fyi)
        self.assertFalse(fyi_task(options={}).is_fyi)
        self.assertIn(FYI_KIND, QUIET_NOTICE_KINDS)

    def test_new_reader_accepts_a_fyi_definition(self) -> None:
        # 读方宽于写方（§95.5.5）：写方不写，但 A 回滚到旧代码后旧 build_checkpoint 会写，新读方要收得下
        from agentstatus_bridge.federation.refs import AttemptDefinition
        target = {"deviceId": "b" * 32, "provider": "codex", "nativeId": "019a0000-1111-7222-8333-44445555bbbb",
                  "endpointId": "e" * 32, "endpointRevision": 1}
        definition = AttemptDefinition.from_dict({"seq": 1, "msgId": "1" * 32, "role": "notice", "target": target,
                                                  "noticeKind": "fyi"})
        self.assertEqual(definition.notice_kind, "fyi")

    def test_footer_says_read_only_and_has_no_report_or_decision_commands(self) -> None:
        text = envelope.render(fyi_task(), fyi_attempt(), sender="claude@lead", device="vm", command="ab")
        self.assertEqual(text.splitlines()[0],
                         f"[AgentStatus 协作] task={TASK_ID} attempt=1 msg={'b' * 32} role=notice from=claude@lead device=vm")
        self.assertEqual(text.splitlines()[-1],
                         "（AgentStatus 协作桥告知消息：只需读到，不需要 ab report，也不用回复发起方。）")
        self.assertNotIn("--attempt", text)
        for word in ("accept", "retry", "ab status", "--ack", "--result"):
            self.assertNotIn(word, text)

    def test_priority_label_phase_and_no_reminder(self) -> None:
        notice = fyi_attempt()
        self.assertEqual(native_priority(notice), "next")
        self.assertEqual(role_label(notice), FYI_LABEL)
        for code in ("fyi", "fyi_conflict", "fyi_remote_unsupported"):
            self.assertIn(code, REASON_TEXTS)
        self.assertIn("fyi_created", EVENT_LABELS)
        view = describe(fyi_task(), [notice])
        self.assertEqual((view.phase, view.reason, view.current), (Phase.CLOSED, "fyi", None))
        self.assertIsNone(pending_reminder(fyi_task(), [notice]))


@linux_fixture
class FyiCliTests(unittest.TestCase):
    """本机 CLI（借用 CliTests 的替身发现与隔离状态目录）。"""

    def setUp(self) -> None:
        import test_bridge_cli as cli_tests
        self.cli_tests = cli_tests
        self.IMPL, self.LEAD, self.REVIEW = cli_tests.IMPL, cli_tests.LEAD, cli_tests.REVIEW
        cli_tests.CliTests.setUp(self)  # type: ignore[arg-type]
        from agentstatus_bridge import cli
        self.cli = cli
        self.caller = cli_tests.as_agent(self.LEAD)

    def run_cli(self, *argv: str) -> tuple[int, str, str]:
        return self.cli_tests.CliTests.run_cli(self, *argv)  # type: ignore[arg-type]

    def store(self):  # noqa: ANN201
        return self.cli_tests.CliTests.store(self)  # type: ignore[arg-type]

    def fyi(self, *extra: str) -> dict[str, object]:
        code, out, err = self.run_cli("send", "--fyi", "--to", "codex@impl", "-m", "新版已部署\n旧命令别用", "--json",
                                      *extra)
        self.assertEqual(code, self.cli.EXIT_OK, err)
        return json.loads(out)

    def test_task_is_closed_at_creation_with_one_fyi_notice(self) -> None:
        document = self.fyi()
        self.assertIs(document["fyi"], True)
        self.assertEqual((document["phase"], document["reason"], document["notes"]), ("closed", "fyi", []))
        task_id = str(document["id"])
        with self.store() as store:
            task = store.get_task(task_id)
            assert task is not None
            [notice] = store.attempts(task_id)
            events = [event["kind"] for event in store.events(task_id)]
        self.assertEqual((task.closed_at, task.close_reason, task.options[FYI_OPTION]), (task.created_at, "fyi", True))
        self.assertTrue(task.finished)
        self.assertEqual((notice.seq, notice.role, notice.delivery, notice.work), (1, Role.NOTICE, Delivery.PENDING,
                                                                                  Work.NONE))
        self.assertEqual(notice.options, {NOTICE_KIND_OPTION: FYI_KIND, "allowShared": False})
        self.assertEqual((notice.target, notice.sender, notice.body), (self.IMPL.ref, self.LEAD.ref, "新版已部署\n旧命令别用"))
        self.assertEqual(task.title, "新版已部署")
        self.assertEqual(events, ["fyi_created"])
        self.assertEqual([item["noticeKind"] for item in document["attempts"]], ["fyi"])  # type: ignore[index]

    def test_text_output_and_follows(self) -> None:
        previous = str(self.fyi()["id"])
        code, out, err = self.run_cli("send", "--fyi", "--to", "codex@impl", "-m", "第二句", "--follows", previous[:8])
        self.assertEqual(code, 0, err)
        self.assertIn("告知 ", out)
        self.assertIn("已排队，发给 codex@id:impl-thread", out)
        self.assertIn("对方只需读到，不汇报、不验收", out)
        with self.store() as store:
            [task] = [item for item in store.list_tasks(include_finished=True) if item.id != previous]
        self.assertEqual(task.options.get("follows"), previous)

    def test_conflicting_options_are_rejected_before_any_write(self) -> None:
        for extra in (("--review-by", "claude@review"), ("--review-device", "win"), ("--no-notify",)):
            with self.subTest(extra=extra):
                code, _out, err = self.run_cli("send", "--fyi", "--to", "codex@impl", "-m", "x", *extra)
                self.assertEqual(code, 2, err)
                self.assertIn(REASON_TEXTS["fyi_conflict"], err)
        self.assertEqual(self._tasks(), [])

    def _tasks(self) -> list[Task]:
        with self.store() as store:
            return store.list_tasks(include_finished=True)

    def test_work_commands_report_task_finished(self) -> None:
        task_id = str(self.fyi()["id"])
        self.caller = self.cli_tests.as_agent(self.IMPL)
        code, _out, err = self.run_cli("report", task_id, "--ack")
        self.assertEqual(code, 3, err)
        self.assertIn("task_finished", err)
        self.caller = self.cli_tests.as_agent(self.LEAD)
        for argv in (("accept", task_id), ("close", task_id), ("retry", task_id, "--force"), ("pause", task_id)):
            with self.subTest(argv=argv):
                code, _out, err = self.run_cli(*argv)
                self.assertNotEqual(code, 0, err)
                self.assertIn(REASON_TEXTS["task_finished"], err)
        code, _out, err = self.run_cli("note", task_id, "-m", "x")
        self.assertEqual(code, 3, err)
        # 未发出的告知可以取消（与普通任务的 cancel 同口径）
        code, out, err = self.run_cli("cancel", task_id)
        self.assertEqual(code, 0, err)
        with self.store() as store:
            self.assertEqual(store.attempts(task_id)[0].delivery, Delivery.CANCELLED)

    def test_status_and_tasks_display(self) -> None:
        task_id = str(self.fyi()["id"])
        with self.store() as store:
            notice = store.attempts(task_id)[0]
            store.begin_send(notice.id, now=3.0, pid=1, start_ticks="1")
            store.finish_send(notice.id, delivery=Delivery.DELIVERED, reason="codex_steered", provider_ref=None,
                              detail={"deliveredPane": "%1", "steerPath": "steered"}, now=4.0)
        code, out, _err = self.run_cli("status", task_id)
        self.assertEqual(code, 0)
        self.assertIn(f"任务 {task_id[:8]} 「新版已部署」 已告知（关闭）：已送达", out)
        self.assertIn("流程：告知（只需读到，不汇报、不验收）", out)
        self.assertIn("  告知 #1 → ", out)
        self.assertNotIn("工作：", out)
        code, out, _err = self.run_cli("tasks")
        self.assertNotIn(task_id[:8], out)  # 默认只列未结束任务
        code, out, _err = self.run_cli("tasks", "--all")
        [line] = [item for item in out.splitlines() if item.startswith(task_id[:8])]
        self.assertIn(f"  {FYI_LABEL}", line)
        self.assertIn("已送达", line)

    def test_summary_has_no_task_entry_and_marks_the_delivery_kind(self) -> None:
        from agentstatus_bridge import summary
        task_id = str(self.fyi()["id"])
        with self.store() as store:
            notice = store.attempts(task_id)[0]
            store.begin_send(notice.id, now=3.0, pid=1, start_ticks="1")
            store.finish_send(notice.id, delivery=Delivery.FAILED, reason="codex_steer_read_desync", provider_ref=None,
                              detail={"deliveredPane": "%1"}, now=4.0)
            [other] = [item for item in store.attempts(task_id)]
        self.assertEqual(other.id, notice.id)  # 投递失败不另起任何 attempt（不叫醒发起方）
        self.run_cli("tasks")
        document = json.loads((self.state / summary.SUMMARY_NAME).read_text(encoding="utf-8"))  # type: ignore[attr-defined]
        self.assertNotIn(task_id, json.dumps(document["tasks"]))
        self.assertEqual(document["attentionIndex"], [])
        self.assertTrue(summary.is_valid(document))

    def test_begin_send_releases_only_closure_and_fyi_after_finish(self) -> None:
        # Fable M27（原判等价：结束时 note 已被取消）：直接核对 store.begin_send 的放行，已关闭任务上的 note 不能领取
        from agentstatus_bridge.model import FOR_SEQ_OPTION, NOTE_KIND
        task_id = str(self.fyi()["id"])
        with self.store() as store:
            note = store.add_attempt(task_id, role=Role.NOTICE, target=self.IMPL.ref, body="补充", refs=[], now=5.0,
                                     sender=None, sender_class=None,
                                     options={NOTICE_KIND_OPTION: NOTE_KIND, FOR_SEQ_OPTION: 1})
            fyi = store.attempts(task_id)[0]
            self.assertFalse(store.begin_send(note.id, now=6.0, pid=1, start_ticks="1"))
            self.assertTrue(store.begin_send(fyi.id, now=6.0, pid=1, start_ticks="1"))

    def test_delivered_fyi_is_published_with_kind_fyi(self) -> None:
        from agentstatus_bridge import summary
        task_id = str(self.fyi()["id"])
        with self.store() as store:
            notice = store.attempts(task_id)[0]
            store.begin_send(notice.id, now=3.0, pid=1, start_ticks="1")
            store.finish_send(notice.id, delivery=Delivery.QUEUED, reason="codex_queued", provider_ref="item-1",
                              detail={"deliveredPid": 1000, "deliveredStart": "100", "deliveredPane": "%1"}, now=4.0)
        self.run_cli("tasks")
        document = json.loads((self.state / summary.SUMMARY_NAME).read_text(encoding="utf-8"))  # type: ignore[attr-defined]
        [delivery] = [item for item in document["deliveries"] if item["messageId"] == notice.message_id]
        self.assertEqual(delivery, {"messageId": notice.message_id, "role": "notice", "pane": "%1", "provider": "codex",
                                    "kind": "fyi"})
        # Fable M22：只有 QUIET_NOTICE_KINDS 里的类别写 kind；结果通知、提醒等其他 notice 不带（扩展照常通知）
        with self.store() as store:
            other = store.add_attempt(task_id, role=Role.NOTICE, target=self.IMPL.ref, body="提醒", refs=[], now=5.0,
                                      sender=None, sender_class=None, options={NOTICE_KIND_OPTION: "reminder"})
            store.transition_delivery(other.id, expected=(Delivery.PENDING,), new=Delivery.SENDING, reason=None, now=6.0)
            store.finish_send(other.id, delivery=Delivery.QUEUED, reason="codex_queued", provider_ref="item-2",
                              detail={"deliveredPid": 1000, "deliveredStart": "100", "deliveredPane": "%1"}, now=7.0)
        self.run_cli("tasks")
        document = json.loads((self.state / summary.SUMMARY_NAME).read_text(encoding="utf-8"))  # type: ignore[attr-defined]
        [plain] = [item for item in document["deliveries"] if item["messageId"] == other.message_id]
        self.assertNotIn("kind", plain)


@linux_fixture
class FyiDispatchTests(unittest.TestCase):
    """worker：已关闭任务上的告知照样投递（delivers_after_finish），steer 信号、显示名与优先级。"""

    def setUp(self) -> None:
        import test_bridge_dispatch as dispatch_tests
        self.base = dispatch_tests.DispatchTests
        self.base.setUp(self)  # type: ignore[arg-type]

    def tearDown(self) -> None:
        self.base.tearDown(self)  # type: ignore[arg-type]

    def _run(self) -> None:
        self.base._run(self)  # type: ignore[arg-type]

    def _attempt(self, attempt_id: str) -> Attempt:
        return self.base._attempt(self, attempt_id)  # type: ignore[arg-type]

    def create(self, target, origin=None) -> tuple[Task, Attempt]:  # noqa: ANN001
        return self.store.create_fyi(title="告知", origin=origin, origin_class=None, target=target,  # type: ignore[attr-defined]
                                     body="新版已部署", refs=[], now=self.now)  # type: ignore[attr-defined]

    def test_closed_fyi_task_is_dispatched_to_codex_with_the_steer_signal(self) -> None:
        from bridge_support import endpoint
        from agentstatus_bridge.dispatch import needs_worker
        target = ref(Provider.CODEX, "019a0000-1111-7222-8333-444455556666")
        self.endpoints = [endpoint(target)]
        task, notice = self.create(target)
        self.assertTrue(task.finished)
        self.assertTrue(needs_worker(self.store, self.now))  # type: ignore[attr-defined]
        self._run()
        [(_endpoint, text, context)] = self.codex.calls  # type: ignore[attr-defined]
        self.assertTrue(context.steer)
        self.assertEqual((context.priority, context.sender_name), ("next", "AgentStatus 协作桥（告知）"))
        self.assertIn("告知消息：只需读到，不需要 testcmd report", text)
        self.assertEqual(self._attempt(notice.id).delivery, Delivery.QUEUED)

    def test_claude_target_and_paused_does_not_block(self) -> None:
        from bridge_support import endpoint
        target = ref(Provider.CLAUDE, "claude-session")
        self.endpoints = [endpoint(target, socket_path="/run/test/peer.sock")]
        task, notice = self.create(target, origin=LEAD_REF)
        self.store.update_task(task.id, now=self.now, event="test", control="paused")  # type: ignore[attr-defined]
        self._run()
        [(_endpoint, _text, context)] = self.claude.calls  # type: ignore[attr-defined]
        self.assertEqual(context.priority, "next")
        self.assertTrue(context.steer)  # 信号只按消息种类定（与 note 同）；Claude 传输不读它
        self.assertEqual(self._attempt(notice.id).delivery, Delivery.WRITTEN)

    def test_ordinary_notice_on_a_closed_task_is_still_skipped(self) -> None:
        # 反例：放宽只认告知与结束回执，普通 notice 在已结束任务上照旧不发
        from bridge_support import endpoint
        target = ref(Provider.CODEX, "019a0000-1111-7222-8333-444455556666")
        self.endpoints = [endpoint(target)]
        task, notice = self.create(target)
        self.store.add_attempt(task.id, role=Role.NOTICE, target=target, body="通知", refs=[], now=self.now,  # type: ignore[attr-defined]
                               sender=None, sender_class=None)
        self._run()
        self.assertEqual(len(self.codex.calls), 1)  # type: ignore[attr-defined]
        self.assertEqual(self._attempt(notice.id).delivery, Delivery.QUEUED)


class FyiFederationTests(federation_cli.FedCliCase):
    """跨设备告知（§95.5.7）：A 建已关闭任务，镜像收到的第一封就是 notice；能力门看目标设备目录 features。"""

    def fyi(self) -> str:
        code, out, err = self.run_on("vm", "send", "--device", "win", "--to", f"codex@id:{federation_cli.THREAD_B}",
                                     "--fyi", "-m", "新版已部署", "--json", caller=federation_cli.as_agent(federation_cli.ORIGIN))
        self.assertEqual(code, 0, err)
        document = json.loads(out)
        self.assertIs(document["fyi"], True)
        return str(document["id"])

    def test_round_trip_wire_shape_delivery_and_status(self) -> None:
        from agentstatus_bridge.federation.delivery import FederationDispatcher
        from agentstatus_bridge.federation.relay import RelayPaths
        from agentstatus_bridge.transports import DeliveryOutcome
        from bridge_support import RecordingTransport
        task_id = self.fyi()
        with self.store("vm") as store:
            [envelope_item] = [json.loads(item["envelope_json"]) for item in store.outbox()]
            [task] = store.find_tasks(task_id)
        self.assertEqual((envelope_item["kind"], envelope_item["attempt"]), ("notice", 1))
        data = envelope_item["data"]
        self.assertEqual(data["options"], {"noticeKind": "fyi", "allowShared": False})
        checkpoint = data["checkpoint"]
        # 旧读方的闭合枚举不认 fyi：定义里不写 noticeKind；没有工作尝试，任务已关闭
        self.assertEqual([item.get("noticeKind") for item in checkpoint["attempts"]], [None])
        self.assertEqual((checkpoint["currentWorkSeq"], checkpoint["closeReason"]), (None, "fyi"))
        self.assertIsNotNone(checkpoint["closedAt"])
        self.assertTrue(task.finished and task.is_fyi)
        # 回滚加固（G4 审计 r1 P3-2）：A 本机记 localNoticeKind，旧 build_checkpoint 读不到，线上仍映射成 noticeKind
        with self.store("vm") as store:
            [fyi] = store.attempts(federation_cli.DEV_A, task_id)
        self.assertEqual((fyi.options.get("localNoticeKind"), "noticeKind" in fyi.options), ("fyi", False))
        # 纵深防御：加固前的形状（options.noticeKind=fyi）build_checkpoint 也不写进定义
        from dataclasses import replace
        from agentstatus_bridge.federation import authority
        legacy = replace(fyi, options={"noticeKind": "fyi", "allowShared": False})
        self.assertEqual([item.notice_kind for item in authority.build_checkpoint(task, [legacy]).attempts], [None])
        self.pump("vm", "win")
        with self.store("win") as store:
            [mirrored] = store.find_tasks(task_id)
        self.assertTrue(mirrored.finished and mirrored.is_fyi)
        transport = RecordingTransport(Provider.CODEX, lambda _e, _t, context: DeliveryOutcome(
            Delivery.DELIVERED, "codex_steered", None, {"steerPath": "steered"}) if context.steer else
            DeliveryOutcome(Delivery.QUEUED, "codex_queued", provider_ref="i"))
        with self.store("win") as store:
            FederationDispatcher(store, self.ident("win"), RelayPaths(self.states["win"]),
                                 discover=lambda: [federation_cli.WORKER], transports={Provider.CODEX: transport},
                                 reply_address=None, command="ab").run_once()
            deliveries = [item for _at, item in store.recent_deliveries()]
        [(_endpoint, text, context)] = transport.calls
        self.assertTrue(context.steer)
        self.assertEqual(context.sender_name.split("@")[0], "claude")  # 发起会话名，口径同 sender_name 规则
        self.assertIn("告知消息：只需读到，不需要 ab report，也不用回复发起方。", text)
        self.assertEqual([item.get("kind") for item in deliveries], ["fyi"])
        self.pump("win", "vm")
        code, out, err = self.run_on("vm", "status", task_id, "--json")
        self.assertEqual(code, 0, err)
        status = json.loads(out)
        self.assertEqual((status["phase"], status["reason"], status["fyi"]), ("closed", "fyi", True))
        self.assertEqual([(row["noticeKind"], row["delivery"]) for row in status["attempts"]], [("fyi", "delivered")])
        listing = self.run_on("vm", "tasks", "--all")[1]
        [line] = [item for item in listing.splitlines() if item.startswith(task_id[:8])]
        self.assertIn(f"  {FYI_LABEL} ", line)
        self.assertIn("投递 delivered", line)
        self.assertNotIn(task_id[:8], self.run_on("vm", "tasks")[1])
        text_out = self.run_on("vm", "status", task_id)[1]
        self.assertIn("已告知（关闭）（delivered）", text_out)
        self.assertIn(f"{FYI_LABEL} #1 → win codex@id:", text_out)
        # 镜像上不能汇报
        code, _out, err = self.run_on("win", "report", task_id, "--origin-device", "vm", "--ack",
                                      caller=federation_cli.as_agent(federation_cli.WORKER))
        self.assertEqual(code, 3, err)
        self.assertIn("task_finished", err)
        # 跨设备告知建立即关闭：发起设备上 cancel 也报 task_finished（只有本机告知能取消未发出的那条）
        code, _out, err = self.run_on("vm", "cancel", task_id, caller=federation_cli.as_agent(federation_cli.ORIGIN))
        self.assertNotEqual(code, 0, err)
        self.assertIn("task_finished", err)

    def test_mirror_identity_needs_close_reason_and_no_work_attempt(self) -> None:
        from agentstatus_bridge.federation.fedstore import FedTask
        def task(current: int | None, **state: object) -> FedTask:
            return FedTask(authority_device="a" * 32, task_id="t" * 32, is_authority=False, revision=1,
                           current_work_seq=current, max_seq=1, last_sync_at=0, state=dict(state))
        self.assertTrue(task(None, closeReason="fyi").is_fyi)
        self.assertTrue(task(None, fyi=True).is_fyi)
        # 普通任务 `ab close --reason fyi`：有工作尝试，不是告知
        self.assertFalse(task(1, closeReason="fyi").is_fyi)
        self.assertFalse(task(None, closeReason="closed").is_fyi)

    def test_mirror_does_not_hold_a_fyi_on_a_paused_task(self) -> None:
        # Fable M11（原判等价：联邦 fyi 不可暂停）：直接核对 mirror.blocked 的放行谓词，暂停也不挡告知、挡普通 notice
        from dataclasses import replace
        from agentstatus_bridge.federation import mirror
        task_id = self.fyi()
        self.pump("vm", "win")
        with self.store("win") as store:
            [task] = store.find_tasks(task_id)
            [fyi] = store.attempts(federation_cli.DEV_A, task_id)
            paused = replace(task, state={**task.state, "control": "paused"})
            plain = replace(fyi, options={"allowShared": False})
            self.assertFalse(mirror.blocked(store, self.ident("win"), paused, fyi, now=task.last_sync_at))
            self.assertTrue(mirror.blocked(store, self.ident("win"), paused, plain, now=task.last_sync_at))

    def test_target_device_without_the_feature_is_refused_before_any_write(self) -> None:
        with self.store("vm") as store:
            [row] = [item for item in store.device_states() if item["device_id"] == federation_cli.DEV_B]
            snapshot = {key: value for key, value in row["snapshot"].items() if key != "features"}
            store.put_device_state(device_id=federation_cli.DEV_B, name="win", revision=2, snapshot=snapshot,
                                   last_seen=row["last_seen"], state="online")
        code, _out, err = self.run_on("vm", "send", "--device", "win", "--to", f"codex@id:{federation_cli.THREAD_B}",
                                      "--fyi", "-m", "x", caller=federation_cli.as_agent(federation_cli.ORIGIN))
        self.assertEqual(code, 3, err)
        self.assertIn(REASON_TEXTS["fyi_remote_unsupported"], err)
        with self.store("vm") as store:
            self.assertEqual((store.find_tasks(""), store.outbox()), ([], []))

    def test_feature_declared_only_by_another_device_does_not_open_the_gate(self) -> None:
        # Fable M18 / Opus O15：目录里两台设备，只有非目标设备声明了 fyi，发给目标仍报 fyi_remote_unsupported
        with self.store("vm") as store:
            [row] = [item for item in store.device_states() if item["device_id"] == federation_cli.DEV_B]
            snapshot = {key: value for key, value in row["snapshot"].items() if key != "features"}
            store.put_device_state(device_id=federation_cli.DEV_B, name="win", revision=2, snapshot=snapshot,
                                   last_seen=row["last_seen"], state="online")
            store.put_device_state(device_id="c" * 32, name="mac", revision=1,
                                   snapshot={**snapshot, "endpoints": [], "features": ["fyi"]},
                                   last_seen=row["last_seen"], state="online")
        code, _out, err = self.run_on("vm", "send", "--device", "win", "--to", f"codex@id:{federation_cli.THREAD_B}",
                                      "--fyi", "-m", "x", caller=federation_cli.as_agent(federation_cli.ORIGIN))
        self.assertEqual(code, 3, err)
        self.assertIn(REASON_TEXTS["fyi_remote_unsupported"], err)
        with self.store("vm") as store:
            self.assertEqual(store.outbox(), [])

    def test_conflicting_options_on_the_federated_path(self) -> None:
        code, _out, err = self.run_on("vm", "send", "--device", "win", "--to", f"codex@id:{federation_cli.THREAD_B}",
                                      "--fyi", "--no-notify", "-m", "x", caller=federation_cli.as_agent(federation_cli.ORIGIN))
        self.assertEqual(code, 2, err)
        self.assertIn(REASON_TEXTS["fyi_conflict"], err)


if __name__ == "__main__":
    unittest.main()
