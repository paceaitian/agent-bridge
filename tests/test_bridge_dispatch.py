"""协作桥分发：按消息种类选原生优先级、目标消失、结果不明不重发、回执与消费证据。"""

from __future__ import annotations

from dataclasses import replace
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from agentstatus_bridge.dispatch import (
    CONSUMPTION_WATCH_SECONDS,
    HELD_WATCH_SECONDS,
    TARGET_GONE_GRACE_SECONDS,
    WRITTEN_WATCH_SECONDS,
    Dispatcher,
    message_uuid,
    native_priority,
)
from agentstatus_bridge import dispatch, store as store_module
from agentstatus_bridge.views import project_delivery_detail
from agentstatus_bridge.envelope import parse_header
from agentstatus_bridge.model import (
    CLOSURE_KIND,
    Consumption,
    Delivery,
    Endpoint,
    EndpointRef,
    Flow,
    NOTICE_KIND_OPTION,
    Phase,
    Provider,
    Role,
    Runtime,
    describe,
)
from agentstatus_bridge.store import Store, StoreError
from agentstatus_bridge.transports import DeliveryContext, DeliveryOutcome
from agentstatus_bridge.platforms.transport_codec import encode_address
from bridge_support import RecordingTransport, endpoint, ref


class DispatchTests(unittest.TestCase):
    def test_local_names_do_not_change_protocol_sender_name_or_header(self) -> None:
        origin = ref(Provider.CLAUDE, '2aa904d4-0000-4000-8000-000000000002', label='vm claude')
        target = ref(Provider.CODEX, '01a15e9f-0000-4000-8000-000000000001', label='实现 窗口')
        self.endpoints = [endpoint(target)]
        task, attempt = self._task(target, origin=origin)
        self._run()
        self.assertEqual(len(self.codex.calls), 1)
        _target, text, context = self.codex.calls[0]
        self.assertEqual(context.sender_name, 'claude@vm claude')
        self.assertEqual(text.splitlines()[0], f'[AgentStatus 协作] task={task.id} attempt=1 '
                         f'msg={attempt.message_id} role=handoff from=claude@vm-claude device=testbox')
        from agentstatus_bridge.transports.claude_peer import build_frame
        frame = json.loads(build_frame(text, context))
        self.assertIn('from-name="claude@vm claude"', frame['message']['content'])
        self.assertNotIn('〔', frame['message']['content'])

    def test_linux_pending_uses_discovery_cache(self) -> None:
        from unittest.mock import Mock
        self._task(ref())
        sampler = Mock(return_value=[])
        self.dispatcher.discover = sampler
        for tick in (1000.0, 1000.5, 1001.0):
            self.now = tick
            self.dispatcher.run_once()  # do not clear _endpoints_at as _run does
        sampler.assert_called_once()
        self.now = 1003.0
        self.dispatcher.run_once()
        self.assertEqual(sampler.call_count, 2)

    def setUp(self) -> None:
        self._tmp = TemporaryDirectory()
        # 补丁打在 dispatch 引用的 device_name 上、不给 Dispatcher 显式传 device：
        # 这样「字段确实由 device_name 求值并进到消息头」这条接线才被守住（独立审计 F-E）
        device = patch.object(dispatch, "device_name", return_value="testbox")
        device.start()
        self.addCleanup(device.stop)
        # 命令名同理：补丁打在解析器上，值取一个谁也不会写死的字符串，
        # 这样把 command 改回字面量（`"ab"`）时这条会变红（DESIGN §45.36）
        command = patch.object(dispatch, "command_name", return_value="testcmd")
        command.start()
        self.addCleanup(command.stop)
        self.store = Store.open(Path(self._tmp.name) / "bridge")
        self.now = 1000.0
        self.endpoints: list[Endpoint] = []
        self.codex = RecordingTransport(Provider.CODEX)
        self.claude = RecordingTransport(
            Provider.CLAUDE,
            lambda _endpoint, _text, context: DeliveryOutcome(
                Delivery.WRITTEN, "claude_written", provider_ref=context.message_uuid
            ),
        )
        self.queue_states: dict[str, Consumption] = {}
        self.dispatcher = Dispatcher(
            store=self.store,
            discover=lambda: list(self.endpoints),
            transports={Provider.CODEX: self.codex, Provider.CLAUDE: self.claude},
            reply_address="uds:/run/test/inbox.sock",
            clock=lambda: self.now,
            queue_state=lambda item: self.queue_states.get(item, Consumption.UNKNOWN),
        )

    def tearDown(self) -> None:
        self.store.close()
        self._tmp.cleanup()

    def _task(self, target: EndpointRef, *, origin: EndpointRef | None = None, origin_class: str | None = None):
        return self.store.create_task(
            title="实现",
            flow=Flow.HANDOFF,
            origin=origin,
            origin_class=origin_class,
            reviewer=None,
            target=target,
            body="请实现 X",
            refs=[],
            now=self.now,
        )

    def _run(self) -> None:
        # 跳过发现缓存，模拟时间推进后的新一轮
        self.dispatcher._endpoints_at = None  # pyright: ignore[reportPrivateUsage]
        self.dispatcher.run_once()

    def _attempt(self, attempt_id: str):
        attempt = self.store.get_attempt(attempt_id)
        assert attempt is not None
        return attempt

    def test_idle_target_is_sent_once(self) -> None:
        target = ref()
        self.endpoints = [endpoint(target)]
        task, attempt = self._task(target)
        self._run()
        self._run()
        self.assertEqual(len(self.codex.calls), 1)
        sent = self._attempt(attempt.id)
        self.assertEqual(sent.delivery, Delivery.QUEUED)
        self.assertEqual(sent.provider_ref, "item-1")
        header = parse_header(self.codex.calls[0][1])
        assert header is not None
        self.assertEqual((header.task_id, header.attempt, header.message_id), (task.id, 1, attempt.message_id))
        # 发送方所在设备进消息头（DESIGN §45.35）
        self.assertEqual(header.device, "testbox")

    def test_footer_command_comes_from_the_resolved_entry_name(self) -> None:
        # 页脚是对方照抄的命令：解析发生在 worker 侧，CLI 认得 `ab` 不等于 worker 也认得（DESIGN §45.36）。
        # 与 device 同理，补丁打在 dispatch 引用的解析器上、不给 Dispatcher 显式传 command
        target = ref()
        self.endpoints = [endpoint(target)]
        task, _attempt = self._task(target)
        self._run()
        text = self.codex.calls[0][1]
        self.assertIn(f"testcmd report {task.id} --attempt 1 --ack", text)
        self.assertIn("请用 testcmd 汇报", text)
        self.assertNotIn("agent-bridge", text)
        self.assertNotIn("ab report", text)

    def test_busy_or_waiting_target_is_delivered_not_held(self) -> None:
        """忙闲不再决定投不投（DESIGN §45.42）。

        上游接收路径没有「对方忙就不入队」的条件；扣留换来的撤回窗口 7 天 0 次使用，
        代价却是回执中位延迟 6 分钟、最大 58 分钟。忙闲仍用于显示与查询提示。
        """
        for runtime in (Runtime.BUSY, Runtime.WAITING, Runtime.BACKGROUND, Runtime.IDLE, Runtime.UNKNOWN):
            with self.subTest(runtime=runtime):
                target = ref()
                _task, attempt = self._task(target)
                self.endpoints = [endpoint(target, runtime=runtime)]
                before = len(self.codex.calls)
                self._run()
                self.assertEqual(self._attempt(attempt.id).delivery, Delivery.QUEUED)
                self.assertEqual(len(self.codex.calls), before + 1)

    def test_background_target_is_not_held(self) -> None:
        """本轮已结束、只剩后台工作在跑：消息真的外调发出，而不只是 runtime 取值变了（DESIGN §45.37）。"""
        target = ref()
        _task, attempt = self._task(target)
        self.endpoints = [endpoint(target, runtime=Runtime.BACKGROUND)]
        self._run()
        self.assertEqual(self._attempt(attempt.id).delivery, Delivery.QUEUED)
        self.assertEqual(len(self.codex.calls), 1)

    def test_paused_task_is_not_sent(self) -> None:
        target = ref()
        self.endpoints = [endpoint(target)]
        task, attempt = self._task(target)
        self.store.update_task(task.id, now=self.now, event="paused", control="paused")
        self._run()
        self.assertEqual(self.codex.calls, [])
        self.assertEqual(describe(self.store.get_task(task.id), self.store.attempts(task.id)).reason, "paused")  # type: ignore[arg-type]
        self.assertEqual(self._attempt(attempt.id).delivery, Delivery.PENDING)

    def test_missing_target_fails_only_after_grace(self) -> None:
        target = ref()
        self.endpoints = [endpoint(ref(native="other", pid=2000, pane="%2", label="other"))]
        _task, attempt = self._task(target)
        self._run()
        self.assertEqual(self._attempt(attempt.id).delivery, Delivery.PENDING)
        self.now += TARGET_GONE_GRACE_SECONDS + 1
        self._run()
        failed = self._attempt(attempt.id)
        self.assertEqual(failed.delivery, Delivery.FAILED)
        self.assertEqual(failed.delivery_reason, "target_gone")

    def test_empty_discovery_never_declares_target_gone(self) -> None:
        _task, attempt = self._task(ref())
        self.endpoints = []
        for _ in range(3):
            self._run()
            self.now += TARGET_GONE_GRACE_SECONDS + 1
        self.assertEqual(self._attempt(attempt.id).delivery, Delivery.PENDING)

    def test_target_that_moved_to_new_process_generation_is_still_same_session(self) -> None:
        target = ref()
        self.endpoints = [endpoint(ref(pid=3000, start="555"))]
        _task, attempt = self._task(target)
        self._run()
        self.assertEqual(self._attempt(attempt.id).delivery, Delivery.QUEUED)

    def test_blocking_issue_fails_with_reason(self) -> None:
        target = ref()
        self.endpoints = [endpoint(target, issues=("ambiguous_thread",))]
        _task, attempt = self._task(target)
        self._run()
        failed = self._attempt(attempt.id)
        self.assertEqual((failed.delivery, failed.delivery_reason), (Delivery.FAILED, "target_ambiguous_thread"))
        self.assertEqual(self.codex.calls, [])

    def test_stored_delivery_detail_always_projects_cleanly(self) -> None:
        """dispatch 与 store 写进账本的 delivery_detail 都满足诊断视图规则（DESIGN §45.43 2.3）。

        明细透出后 CLI 就是这些字段的出口。这条读回账本逐行检查，守住今天的写入方没塞进不合形的值；
        并用带合成标记的异常消息证明异常只记类型名、消息正文不落账。
        """
        marker = "SYNTHETIC_PRIVATE_MARKER"
        target = ref()
        self.endpoints = [endpoint(target)]
        scenarios: list[tuple[DeliveryOutcome | None, Exception | None]] = [
            (DeliveryOutcome(Delivery.QUEUED, "codex_queued", provider_ref="item-1"), None),
            (DeliveryOutcome(Delivery.FAILED, "codex_thread_not_found", detail={"exitCode": 1}), None),
            (DeliveryOutcome(Delivery.WRITTEN, "claude_written", provider_ref="m1",
                             detail={"priority": "later", "senderClass": "bypass"}), None),
            (DeliveryOutcome(Delivery.DELIVERED, "claude_delivered", provider_ref="m2",
                             detail={"priority": "next", "senderClass": "bypass", "receipt": "inline"}), None),
            (None, RuntimeError(f"{marker} /tmp/{marker}/file")),
        ]
        for outcome, error in scenarios:
            self.dispatcher.transports[Provider.CODEX] = RecordingTransport(Provider.CODEX, outcome, error)  # type: ignore[index]
            self._task(target)
            self._run()
        rows = [item for task in self.store.list_tasks(include_finished=True) for item in self.store.attempts(task.id)]
        self.assertEqual(len(rows), len(scenarios))
        for attempt in rows:
            with self.subTest(reason=attempt.delivery_reason):
                self.assertFalse(project_delivery_detail(attempt.delivery_detail)[1], attempt.delivery_detail)
                self.assertNotIn(marker, json.dumps(attempt.delivery_detail))
        [crashed] = [item for item in rows if item.delivery_reason == "transport_exception"]
        self.assertEqual(crashed.delivery_detail.get("exception"), "RuntimeError")

    def test_transport_exception_is_unknown_and_never_resent(self) -> None:
        target = ref()
        self.endpoints = [endpoint(target)]
        self.codex.error = RuntimeError("boom")
        task, attempt = self._task(target)
        self._run()
        self._run()
        self.assertEqual(len(self.codex.calls), 1)
        unknown = self._attempt(attempt.id)
        self.assertEqual((unknown.delivery, unknown.delivery_reason), (Delivery.UNKNOWN, "transport_exception"))
        view = describe(self.store.get_task(task.id), self.store.attempts(task.id))  # type: ignore[arg-type]
        self.assertEqual((view.phase, view.reason), (Phase.NEEDS_ATTENTION, "delivery_unknown"))

    def test_claude_waits_without_receipt_inbox(self) -> None:
        target = ref(Provider.CLAUDE, "claude-session")
        self.endpoints = [endpoint(target, socket_path="/run/test/peer.sock")]
        self.dispatcher.reply_address = None
        _task, attempt = self._task(target)
        self._run()
        self.assertEqual(self.claude.calls, [])
        self.assertEqual(self._attempt(attempt.id).delivery, Delivery.PENDING)

    def test_every_role_has_a_native_priority(self) -> None:
        """闭合枚举是合同：新增 role 时漏配在这里变红，而不是被静默打成某个默认值。"""
        self.assertEqual(set(dispatch._ROLE_PRIORITY), set(Role))  # pyright: ignore[reportPrivateUsage]

    def test_native_priority_is_chosen_by_message_kind(self) -> None:
        """取消扣留后，「对方什么时候读它」改由原生优先级表达（DESIGN §45.42）。

        回执类讲的是已经做完的事，被对方当前轮吸收反而更早知道结果；交接类要对方开始做新事，
        `later` 会被原生 max-next 过滤掉、等主轮可 drain。
        """
        target = ref(Provider.CLAUDE, "claude-session")
        self.endpoints = [endpoint(target, socket_path="/run/test/peer.sock")]
        task, handoff = self._task(target)
        cases = [(handoff, "later")]
        for role, expected in ((Role.REVIEW, "later"), (Role.NOTICE, "next")):
            cases.append((
                self.store.add_attempt(
                    task.id, role=role, target=target, body="x", refs=[], now=self.now,
                    sender=None, sender_class=None,
                ),
                expected,
            ))
        for attempt, expected in cases:
            with self.subTest(role=attempt.role):
                self.assertEqual(native_priority(attempt), expected)
        # 结束回执按定义就是 NOTICE，因此天然归回执类；这条断言钉住这个推理，不另设分支
        closure = replace(cases[-1][0], options={NOTICE_KIND_OPTION: CLOSURE_KIND})
        self.assertTrue(closure.is_closure)
        self.assertIs(closure.role, Role.NOTICE)
        self.assertEqual(native_priority(closure), "next")
        # 端到端：真的写进了投递上下文，而不只是函数返回值对
        self._run()
        _endpoint, _text, context = self.claude.calls[0]
        self.assertEqual(context.priority, "later")

    def test_claude_context_declares_origin_class_honestly(self) -> None:
        target = ref(Provider.CLAUDE, "claude-session")
        origin = ref(Provider.CODEX, "origin-thread", pid=1500, pane="%9", label="lead")
        self.endpoints = [endpoint(target, socket_path="/run/test/peer.sock")]
        _task, attempt = self._task(target, origin=origin, origin_class="bypass")
        self._run()
        _endpoint, text, context = self.claude.calls[0]
        self.assertEqual(context.sender_class, "bypass")
        self.assertEqual(context.reply_to, "uds:/run/test/inbox.sock")
        self.assertEqual(context.message_uuid, message_uuid(attempt.message_id))
        self.assertIn("from=codex@lead device=testbox", text.splitlines()[0])
        self.assertEqual(self._attempt(attempt.id).delivery, Delivery.WRITTEN)

    def _claude_written(self, socket_path: str = "/run/test/peer.sock"):
        target = ref(Provider.CLAUDE, "claude-session")
        self.endpoints = [endpoint(target, socket_path=socket_path)]
        task, attempt = self._task(target)
        self._run()
        return task, self._attempt(attempt.id)

    def _receipt(self, attempt_uuid: str, status: str, **extra: object) -> dict[str, object]:
        return {
            "type": "control",
            "action": "peer_message_status",
            "status": status,
            "orig_msg_id": attempt_uuid,
            **extra,
        }

    def test_held_then_delivered_receipts(self) -> None:
        _task, attempt = self._claude_written()
        uuid_text = str(attempt.provider_ref)
        self.assertEqual(self.dispatcher.handle_frame(self._receipt(uuid_text, "held")), "receipt")
        self.assertEqual(self._attempt(attempt.id).delivery, Delivery.HELD)
        self.dispatcher.handle_frame(self._receipt(uuid_text, "delivered"))
        self.assertEqual(self._attempt(attempt.id).delivery, Delivery.DELIVERED)
        # 迟到的 held 不能把已送达倒退
        self.assertIsNone(self.dispatcher.handle_frame(self._receipt(uuid_text, "held")))
        self.assertEqual(self._attempt(attempt.id).delivery, Delivery.DELIVERED)

    def test_held_then_expired_is_proven_undelivered(self) -> None:
        task, attempt = self._claude_written()
        uuid_text = str(attempt.provider_ref)
        self.dispatcher.handle_frame(self._receipt(uuid_text, "held"))
        self.dispatcher.handle_frame(self._receipt(uuid_text, "expired"))
        view = describe(self.store.get_task(task.id), self.store.attempts(task.id))  # type: ignore[arg-type]
        self.assertEqual((view.phase, view.reason), (Phase.NEEDS_ATTENTION, "delivery_expired"))

    def test_refused_detail_and_unknown_message_ids(self) -> None:
        _task, attempt = self._claude_written()
        self.assertIsNone(self.dispatcher.handle_frame(self._receipt("00000000-0000-0000-0000-000000000000", "held")))
        self.dispatcher.handle_frame(self._receipt(str(attempt.provider_ref), "expired", status_detail="refused"))
        self.assertEqual(self._attempt(attempt.id).delivery, Delivery.REFUSED)

    def test_native_reply_is_recorded_as_delivery_evidence(self) -> None:
        _task, attempt = self._claude_written()
        frame = {
            "type": "user",
            "from": "uds:/run/test/peer.sock",
            "message": {
                "role": "user",
                "content": '<cross-session-message from="uds:/run/test/peer.sock" from-name="x">\n收到\n</cross-session-message>',
            },
        }
        self.assertEqual(self.dispatcher.handle_frame(frame), "reply")
        self.assertEqual(self._attempt(attempt.id).delivery, Delivery.DELIVERED)
        kinds = [event["kind"] for event in self.store.events(attempt.task_id)]
        self.assertIn("peer_reply", kinds)

    def test_selected_generation_wins_over_first_listed_same_session(self) -> None:
        first = endpoint(ref(Provider.CLAUDE, "claude-session", pid=2200, pane="%91", label="a"), socket_path="/run/test/a.sock")
        chosen = endpoint(ref(Provider.CLAUDE, "claude-session", pid=2300, pane="%92", label="b"), socket_path="/run/test/b.sock")
        self.endpoints = [first, chosen]
        _task, attempt = self._task(chosen.ref)
        self._run()
        self.assertEqual(self.claude.calls[0][0].ref.pane, "%92")
        self.assertEqual(self._attempt(attempt.id).delivery_detail["deliveredPid"], 2300)

    def test_several_generations_without_the_selected_one_fail_clearly(self) -> None:
        self.endpoints = [
            endpoint(ref(Provider.CLAUDE, "claude-session", pid=2200), socket_path="/run/test/a.sock"),
            endpoint(ref(Provider.CLAUDE, "claude-session", pid=2300), socket_path="/run/test/b.sock"),
        ]
        _task, attempt = self._task(ref(Provider.CLAUDE, "claude-session", pid=9999, start="1"))
        self._run()
        failed = self._attempt(attempt.id)
        self.assertEqual((failed.delivery, failed.delivery_reason), (Delivery.FAILED, "target_generation_ambiguous"))
        self.assertEqual(self.claude.calls, [])

    def test_uncertain_claude_write_is_resolved_by_later_receipt(self) -> None:
        self.dispatcher.transports = {
            Provider.CLAUDE: RecordingTransport(Provider.CLAUDE, DeliveryOutcome(Delivery.UNKNOWN, "claude_socket_write_failed"))
        }
        target = ref(Provider.CLAUDE, "claude-session")
        self.endpoints = [endpoint(target, socket_path="/run/test/peer.sock")]
        _task, attempt = self._task(target)
        self._run()
        uncertain = self._attempt(attempt.id)
        self.assertEqual((uncertain.delivery, uncertain.provider_ref), (Delivery.UNKNOWN, message_uuid(attempt.message_id)))
        self.assertEqual(self.dispatcher.handle_frame(self._receipt(message_uuid(attempt.message_id), "delivered")), "receipt")
        self.assertEqual(self._attempt(attempt.id).delivery, Delivery.DELIVERED)

    def test_shared_codex_thread_needs_recorded_opt_in(self) -> None:
        target = ref()
        self.endpoints = [endpoint(target, issues=("shared_thread",))]
        _task, blocked = self._task(target)
        _task2, allowed = self.store.create_task(
            title="t",
            flow=Flow.HANDOFF,
            origin=None,
            origin_class=None,
            reviewer=None,
            target=target,
            body="x",
            refs=[],
            now=self.now,
            attempt_options={"allowShared": True},
        )
        self._run()
        refused = self._attempt(blocked.id)
        self.assertEqual((refused.delivery, refused.delivery_reason), (Delivery.FAILED, "target_shared_thread"))
        self.assertEqual(self._attempt(allowed.id).delivery, Delivery.QUEUED)
        self.assertEqual(len(self.codex.calls), 1)

    def _reply(self, text: str, *, address: str = "uds:/run/test/peer.sock", attributes: str = "") -> dict[str, object]:
        return {
            "type": "user",
            "from": address,
            "message": {"role": "user", "content": f'<cross-session-message from="{address}"{attributes}>\n{text}\n</cross-session-message>'},
        }

    def test_windows_pipe_attributes_do_not_count_as_reply_ids(self) -> None:
        pipe = r"\\.\pipe\LOCAL\cc-msg-0123456789abcdef0123456789abcdef"
        task, attempt = self._claude_written(pipe)
        records = []
        self.dispatcher.log = lambda event, fields: records.append((event, dict(fields)))
        for address in ("uds:" + pipe, encode_address(pipe)):
            for list_content in (False, True):
                with self.subTest(address=address, list_content=list_content):
                    self.store.transition_delivery(attempt.id, expected=(Delivery.DELIVERED,),
                                                   new=Delivery.WRITTEN, reason="test", now=self.now)
                    frame = self._reply("收到", address=address)
                    text = frame["message"]["content"]
                    if list_content:
                        frame["message"]["content"] = [{"type": "text", "text": text}]
                    self.assertEqual(self._attempt(attempt.id).delivery, Delivery.WRITTEN)
                    self.assertEqual(self.dispatcher.handle_frame(frame), "reply")
                    self.assertEqual((self._attempt(attempt.id).delivery, self._attempt(attempt.id).delivery_reason),
                                     (Delivery.DELIVERED, "receiver_replied"))
                    self.assertEqual(records[-1][1]["association"], "only_candidate")
                    replies = [e for e in self.store.events(task.id) if e["kind"] == "peer_reply"]
                    self.assertEqual(replies[-1]["detail"]["text"], text, "入账仍保留原回复，不修改解析或存储")
        self.assertEqual(len([e for e in self.store.events(task.id) if e["kind"] == "peer_reply"]), 4)

    def test_from_session_uuid_and_other_sender_attributes_are_not_body_ids(self) -> None:
        task, attempt = self._claude_written()
        records = []
        self.dispatcher.log = lambda event, fields: records.append((event, dict(fields)))
        frame = self._reply("收到", attributes=(
            ' from-session="11111111-2222-4333-8444-555555555555"'
            ' from-name=\'name > aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\' from-mode="unknown"'))
        self.assertEqual(self.dispatcher.handle_frame(frame), "reply")
        self.assertEqual(records[-1][1]["association"], "only_candidate")
        self.assertEqual(self._attempt(attempt.id).delivery_reason, "receiver_replied")
        self.assertEqual(len([e for e in self.store.events(task.id) if e["kind"] == "peer_reply"]), 1)

    def test_reply_body_ids_win_over_ids_in_sender_attributes(self) -> None:
        pipe = r"\\.\pipe\LOCAL\cc-msg-0123456789abcdef0123456789abcdef"
        task, first = self._claude_written(pipe)
        other_task, other = self._task(first.target)
        self._run()
        address = encode_address(pipe)
        records = []
        self.dispatcher.log = lambda event, fields: records.append((event, dict(fields)))
        for body in (f"msg={first.message_id}", f"消息 {message_uuid(first.message_id)}", f"task={task.id}"):
            with self.subTest(body=body):
                frame = self._reply(body, address=address,
                                    attributes=f' from-session="{message_uuid(other.message_id)}" from-name="{other_task.id}"')
                self.assertEqual(self.dispatcher.handle_frame(frame), "reply")
                self.assertEqual(records[-1][1]["association"], "task_id" if body.startswith("task=") else "message_id")
                self.assertEqual(self._attempt(first.id).delivery, Delivery.DELIVERED)
                self.assertEqual(self._attempt(other.id).delivery, Delivery.WRITTEN)
        self.assertNotIn("peer_reply", [e["kind"] for e in self.store.events(other_task.id)])

    def test_reply_attempt_number_is_read_only_from_body(self) -> None:
        task, first = self._claude_written()
        second = self.store.add_attempt(task.id, role=Role.HANDOFF, target=first.target,
                                        body="再发", refs=[], now=self.now, sender=None, sender_class=None)
        self._run()
        records = []
        self.dispatcher.log = lambda event, fields: records.append((event, dict(fields)))
        frame = self._reply(f"task={task.id} attempt={second.seq}", attributes=f' from-name="attempt={first.seq}"')
        self.assertEqual(self.dispatcher.handle_frame(frame), "reply")
        self.assertEqual(records[-1][1]["association"], "task_attempt")
        self.assertEqual(self._attempt(first.id).delivery, Delivery.WRITTEN)
        self.assertEqual(self._attempt(second.id).delivery_reason, "receiver_replied")

    def test_windows_reply_unknown_body_id_still_does_not_fall_back(self) -> None:
        pipe = r"\\.\pipe\LOCAL\cc-msg-0123456789abcdef0123456789abcdef"
        task, attempt = self._claude_written(pipe)
        records = []
        self.dispatcher.log = lambda event, fields: records.append((event, dict(fields)))
        for body in ("task=" + "f" * 32, "消息 ffffffff-ffff-4fff-8fff-ffffffffffff"):
            with self.subTest(body=body):
                frame = self._reply(body, address="uds:" + pipe, attributes=f' from-name="{attempt.message_id}"')
                self.assertIsNone(self.dispatcher.handle_frame(frame))
                self.assertEqual(records[-1], ("reply_unmatched", {"mentionedIds": 1}))
                self.assertEqual(self._attempt(attempt.id).delivery, Delivery.WRITTEN)
        self.assertNotIn("peer_reply", [e["kind"] for e in self.store.events(task.id)])

    def test_plain_reply_text_keeps_id_and_only_candidate_rules(self) -> None:
        task, attempt = self._claude_written()
        for text, association in (("收到", "only_candidate"), (f"task={task.id}", "task_id"),
                                  (f"msg={attempt.message_id}", "message_id")):
            with self.subTest(text=text):
                resolved = self.dispatcher.resolve_reply("uds:/run/test/peer.sock", text)
                self.assertIsNotNone(resolved)
                self.assertEqual(resolved.association, association)
                self.assertEqual(resolved.text, text)
        # 正文中引用的标签不是最外层标签，里面真正提到的 ID 仍会被扫描。
        self.assertIsNone(self.dispatcher.resolve_reply("uds:/run/test/peer.sock",
            '引用：<cross-session-message from-session="ffffffff-ffff-4fff-8fff-ffffffffffff">收到</cross-session-message>'))

    def test_truncated_long_reply_still_ignores_complete_opening_tag(self) -> None:
        pipe = r"\\.\pipe\LOCAL\cc-msg-0123456789abcdef0123456789abcdef"
        task, attempt = self._claude_written(pipe)
        self.assertEqual(self.dispatcher.handle_frame(self._reply("收到" * 2200, address="uds:" + pipe)), "reply")
        self.assertEqual(self._attempt(attempt.id).delivery_reason, "receiver_replied")
        replies = [e for e in self.store.events(task.id) if e["kind"] == "peer_reply"]
        self.assertEqual(len(replies[0]["detail"]["text"]), 4000)
        self.assertFalse(replies[0]["detail"]["text"].endswith("</cross-session-message>"))

    def test_reply_naming_a_task_is_associated_exactly(self) -> None:
        target = ref(Provider.CLAUDE, "claude-session")
        self.endpoints = [endpoint(target, socket_path="/run/test/peer.sock")]
        old_task, old = self._task(target)
        new_task, new = self._task(target)
        self._run()
        self.dispatcher.handle_frame(self._receipt(message_uuid(new.message_id), "held"))
        self.assertEqual(self.dispatcher.handle_frame(self._reply(f"任务 {old_task.id} 已完成")), "reply")
        self.assertEqual(self._attempt(old.id).delivery, Delivery.DELIVERED)
        self.assertEqual(self._attempt(new.id).delivery, Delivery.HELD)
        self.assertIn("peer_reply", [event["kind"] for event in self.store.events(old_task.id)])
        self.assertNotIn("peer_reply", [event["kind"] for event in self.store.events(new_task.id)])
        self.dispatcher.handle_frame(self._receipt(message_uuid(new.message_id), "expired"))
        self.assertEqual(self._attempt(new.id).delivery, Delivery.EXPIRED)

    def test_single_candidate_reply_does_not_release_held_message(self) -> None:
        target = ref(Provider.CLAUDE, "claude-session")
        self.endpoints = [endpoint(target, socket_path="/run/test/peer.sock")]
        _task, attempt = self._task(target)
        self._run()
        self.dispatcher.handle_frame(self._receipt(message_uuid(attempt.message_id), "held"))
        self.assertEqual(self.dispatcher.handle_frame(self._reply("收到")), "reply")
        self.assertEqual(self._attempt(attempt.id).delivery, Delivery.HELD)

    def test_ambiguous_reply_changes_no_delivery_state(self) -> None:
        target = ref(Provider.CLAUDE, "claude-session")
        self.endpoints = [endpoint(target, socket_path="/run/test/peer.sock")]
        _a, first = self._task(target)
        second_task, second = self._task(target)
        self._run()
        self.assertEqual(self.dispatcher.handle_frame(self._reply("好的")), "reply")
        self.assertEqual((self._attempt(first.id).delivery, self._attempt(second.id).delivery), (Delivery.WRITTEN, Delivery.WRITTEN))
        replies = [event for event in self.store.events(second_task.id) if event["kind"] == "peer_reply"]
        self.assertEqual(replies[0]["detail"]["ambiguous"], True)

    def test_local_record_failure_after_native_success_is_retried_without_resending(self) -> None:
        target = ref()
        self.endpoints = [endpoint(target)]
        _task, attempt = self._task(target)
        original = Store.finish_send
        calls: list[int] = []

        def fail_once(store: Store, *args: object, **kwargs: object) -> bool:
            calls.append(1)
            if len(calls) == 1:
                raise StoreError("store_busy")
            return original(store, *args, **kwargs)  # type: ignore[arg-type]

        from unittest.mock import patch

        with patch.object(Store, "finish_send", fail_once):
            self._run()
            self.assertEqual(self._attempt(attempt.id).delivery, Delivery.SENDING)
            self.assertTrue(self.dispatcher.has_live_work())
            self._run()
        recorded = self._attempt(attempt.id)
        self.assertEqual((recorded.delivery, recorded.provider_ref), (Delivery.QUEUED, "item-1"))
        self.assertEqual(len(self.codex.calls), 1)

    def test_receipt_arriving_while_record_is_deferred_is_replayed(self) -> None:
        target = ref(Provider.CLAUDE, "claude-session")
        self.endpoints = [endpoint(target, socket_path="/run/test/peer.sock")]
        _task, attempt = self._task(target)
        original = Store.finish_send
        calls: list[int] = []

        def fail_once(store: Store, *args: object, **kwargs: object) -> bool:
            calls.append(1)
            if len(calls) == 1:
                raise StoreError("store_busy")
            return original(store, *args, **kwargs)  # type: ignore[arg-type]

        from unittest.mock import patch

        with patch.object(Store, "finish_send", fail_once):
            self._run()
            self.assertEqual(self._attempt(attempt.id).delivery, Delivery.SENDING)
            self.assertIsNone(self.dispatcher.handle_frame(self._receipt(message_uuid(attempt.message_id), "held")))
            self._run()
        self.assertEqual(self._attempt(attempt.id).delivery, Delivery.HELD)
        self.assertEqual(len(self.claude.calls), 1)

    def test_replayed_receipts_survive_a_transient_store_failure(self) -> None:
        target = ref(Provider.CLAUDE, "claude-session")
        self.endpoints = [endpoint(target, socket_path="/run/test/peer.sock")]
        _task, attempt = self._task(target)
        original_finish = Store.finish_send
        original_transition = Store.transition_delivery
        finish_calls: list[int] = []
        failed: list[int] = []

        def finish(store: Store, *args: object, **kwargs: object) -> bool:
            finish_calls.append(1)
            if len(finish_calls) == 1:
                raise StoreError("store_busy")
            return original_finish(store, *args, **kwargs)  # type: ignore[arg-type]

        def transition(store: Store, *args: object, **kwargs: object) -> bool:
            if kwargs.get("new") is Delivery.HELD and not failed:
                failed.append(1)
                raise StoreError("store_busy")
            return original_transition(store, *args, **kwargs)  # type: ignore[arg-type]

        from unittest.mock import patch

        with patch.object(Store, "finish_send", finish), patch.object(Store, "transition_delivery", transition):
            self._run()
            native = message_uuid(attempt.message_id)
            self.dispatcher.handle_frame(self._receipt(native, "held"))
            self.dispatcher.handle_frame(self._receipt(native, "denied"))
            self._run()
            self.assertEqual(self._attempt(attempt.id).delivery, Delivery.WRITTEN)
            self.now += HELD_WATCH_SECONDS + 1
            self.assertTrue(self.dispatcher.has_live_work())
            self._run()
        self.assertEqual(self._attempt(attempt.id).delivery, Delivery.DENIED)
        self.assertEqual((len(self.claude.calls), len(failed)), (1, 1))

    def test_live_receipt_and_reply_hitting_store_failure_are_retried(self) -> None:
        target = ref(Provider.CLAUDE, "claude-session")
        self.endpoints = [endpoint(target, socket_path="/run/test/peer.sock")]
        task, attempt = self._task(target)
        self._run()
        original_transition = Store.transition_delivery
        failed: list[object] = []

        def transition(store: Store, *args: object, **kwargs: object) -> bool:
            if kwargs.get("new") in (Delivery.HELD, Delivery.DELIVERED) and kwargs.get("new") not in failed:
                failed.append(kwargs.get("new"))
                raise StoreError("store_busy")
            return original_transition(store, *args, **kwargs)  # type: ignore[arg-type]

        from unittest.mock import patch

        with patch.object(Store, "transition_delivery", transition):
            self.assertIsNone(self.dispatcher.handle_frame(self._receipt(message_uuid(attempt.message_id), "held")))
            self.assertEqual(self._attempt(attempt.id).delivery, Delivery.WRITTEN)
            self._run()
            self.assertEqual(self._attempt(attempt.id).delivery, Delivery.HELD)
            self.store.transition_delivery(attempt.id, expected=(Delivery.HELD,), new=Delivery.WRITTEN, reason="test", now=self.now)
            self.assertIsNone(self.dispatcher.handle_frame(self._reply(f"task={task.id} 收到")))
            self.assertEqual([e["kind"] for e in self.store.events(task.id)].count("peer_reply"), 0)
            self._run()
        self.assertEqual(self._attempt(attempt.id).delivery, Delivery.DELIVERED)
        self.assertEqual([e["kind"] for e in self.store.events(task.id)].count("peer_reply"), 1)

    def _failing_reply_write(self):
        from unittest.mock import patch

        original = Store.add_event
        failed: list[int] = []

        def add_event(store: Store, *args: object, **kwargs: object) -> None:
            if args and args[0] == "peer_reply" or kwargs.get("kind") == "peer_reply" or (len(args) > 1 and args[1] == "peer_reply"):
                if not failed:
                    failed.append(1)
                    raise StoreError("store_busy")
            return original(store, *args, **kwargs)  # type: ignore[arg-type]

        return patch.object(Store, "add_event", add_event)

    def test_queued_ambiguous_reply_keeps_its_classification(self) -> None:
        target = ref(Provider.CLAUDE, "claude-session")
        self.endpoints = [endpoint(target, socket_path="/run/test/peer.sock")]
        first, _a = self._task(target)
        second, second_attempt = self._task(target)
        self._run()
        with self._failing_reply_write():
            self.assertIsNone(self.dispatcher.handle_frame(self._reply("好的")))
        self.store.update_task(first.id, now=self.now, event="closed", closed_at=self.now)
        self._run()
        self.assertEqual(self._attempt(second_attempt.id).delivery, Delivery.WRITTEN)
        replies = [e for e in self.store.events(second.id) if e["kind"] == "peer_reply"]
        self.assertEqual((len(replies), replies[0]["detail"].get("ambiguous")), (1, True))

    def test_queued_exact_reply_survives_sender_exit(self) -> None:
        target = ref(Provider.CLAUDE, "claude-session")
        self.endpoints = [endpoint(target, socket_path="/run/test/peer.sock")]
        task, attempt = self._task(target)
        self._run()
        with self._failing_reply_write():
            self.assertIsNone(self.dispatcher.handle_frame(self._reply(f"task={task.id} 完成")))
        self.endpoints = []
        self._run()
        self.assertEqual(self._attempt(attempt.id).delivery, Delivery.DELIVERED)
        self.assertEqual([e["kind"] for e in self.store.events(task.id)].count("peer_reply"), 1)

    def test_later_reply_waits_behind_queued_reply(self) -> None:
        target = ref(Provider.CLAUDE, "claude-session")
        self.endpoints = [endpoint(target, socket_path="/run/test/peer.sock")]
        task, _attempt = self._task(target)
        self._run()
        first = f"task={task.id} 第一条"
        second = f"task={task.id} 第二条"
        with self._failing_reply_write():
            self.assertIsNone(self.dispatcher.handle_frame(self._reply(first)))
        self.now += 1
        self.assertIsNone(self.dispatcher.handle_frame(self._reply(second)))
        self._run()
        texts = [e["detail"]["text"] for e in self.store.events(task.id) if e["kind"] == "peer_reply"]
        self.assertEqual(len(texts), 2)
        self.assertIn("第一条", texts[0])
        self.assertIn("第二条", texts[1])

    def test_reply_naming_finished_task_does_not_deliver_newer_task(self) -> None:
        target = ref(Provider.CLAUDE, "claude-session")
        self.endpoints = [endpoint(target, socket_path="/run/test/peer.sock")]
        old_task, _old = self._task(target)
        self._run()
        self.store.update_task(old_task.id, now=self.now, event="accepted", accepted_at=self.now)
        _new_task, new = self._task(target)
        self._run()
        self.assertEqual(self.dispatcher.handle_frame(self._reply(f"任务 {old_task.id} 早就做完了")), "reply")
        self.assertEqual(self._attempt(new.id).delivery, Delivery.WRITTEN)
        self.assertIsNone(self.dispatcher.handle_frame(self._reply(f"任务 {'f' * 32} 做完了")))
        self.assertEqual(self._attempt(new.id).delivery, Delivery.WRITTEN)

    def test_message_id_disambiguates_attempts_of_one_task(self) -> None:
        target = ref(Provider.CLAUDE, "claude-session")
        self.endpoints = [endpoint(target, socket_path="/run/test/peer.sock")]
        task, old = self._task(target)
        self._run()
        self.store.transition_delivery(old.id, expected=(Delivery.WRITTEN,), new=Delivery.UNKNOWN, reason="test", now=self.now)
        new = self.store.add_attempt(
            task.id, role=Role.HANDOFF, target=target, body="重发", refs=[], now=self.now, sender=None, sender_class=None
        )
        self._run()
        self.dispatcher.handle_frame(self._receipt(message_uuid(new.message_id), "held"))
        header = f"[AgentStatus 协作] task={task.id} attempt=2 msg={new.message_id} role=handoff from=user"
        self.assertEqual(self.dispatcher.handle_frame(self._reply(f"{header}\n收到")), "reply")
        self.assertEqual((self._attempt(old.id).delivery, self._attempt(new.id).delivery), (Delivery.UNKNOWN, Delivery.DELIVERED))
        # 只写任务 ID 与序号也能区分
        third = self.store.add_attempt(
            task.id, role=Role.HANDOFF, target=target, body="再发", refs=[], now=self.now, sender=None, sender_class=None
        )
        self._run()
        self.dispatcher.handle_frame(self._reply(f"task={task.id} attempt=3 已收到"))
        self.assertEqual(self._attempt(third.id).delivery, Delivery.DELIVERED)
        self.assertEqual(self._attempt(old.id).delivery, Delivery.UNKNOWN)
        # 只带消息 ID（UUID 形式）也能精确关联到那一条尝试
        self.assertEqual(self.dispatcher.handle_frame(self._reply(f"回执 {message_uuid(old.message_id)}")), "reply")
        self.assertEqual(self._attempt(old.id).delivery, Delivery.DELIVERED)

    def test_commit_hash_in_reply_is_not_mistaken_for_an_id(self) -> None:
        target = ref(Provider.CLAUDE, "claude-session")
        self.endpoints = [endpoint(target, socket_path="/run/test/peer.sock")]
        _task, attempt = self._task(target)
        self._run()
        self.assertEqual(self.dispatcher.handle_frame(self._reply("已提交 " + "a1b2c3d4" * 5)), "reply")
        self.assertEqual(self._attempt(attempt.id).delivery, Delivery.DELIVERED)

    def test_log_hook_carries_codes_but_no_message_content(self) -> None:
        records: list[tuple[str, dict[str, object]]] = []
        self.dispatcher.log = lambda event, fields: records.append((event, dict(fields)))
        target = ref()
        self.endpoints = [endpoint(target)]
        self._task(target)
        self._run()
        self.assertIn("delivery_result", [event for event, _fields in records])
        self.assertNotIn("请实现", json.dumps(records, ensure_ascii=False))

    def test_worker_watch_windows_for_written_and_held(self) -> None:
        target = ref(Provider.CLAUDE, "claude-session")
        self.endpoints = [endpoint(target, socket_path="/run/test/peer.sock")]
        _task, attempt = self._task(target)
        self._run()
        self.assertTrue(self.dispatcher.has_live_work())
        self.now += WRITTEN_WATCH_SECONDS + 1
        self.assertFalse(self.dispatcher.has_live_work())
        self.dispatcher.handle_frame(self._receipt(message_uuid(attempt.message_id), "held"))
        self.assertTrue(self.dispatcher.has_live_work())
        self.now += HELD_WATCH_SECONDS + 1
        self.assertFalse(self.dispatcher.has_live_work())

    def test_liveness_and_consumption_checks_skip_history_outside_the_windows(self) -> None:
        # 没人汇报的 Claude 回执会一直停在 WRITTEN、未消费的 Codex 项停在 QUEUED：
        # 每秒的驻留判断与消费对账不能把窗口外的历史行连正文读出来（DESIGN §45.29）
        claude = ref(Provider.CLAUDE, "claude-session")
        codex = ref()
        self.endpoints = [endpoint(claude, socket_path="/run/test/peer.sock"), endpoint(codex)]
        for target in (claude, codex, claude, codex):
            self._task(target)
        self._run()
        self.assertTrue(self.dispatcher.has_live_work())
        self.queue_states["item-1"] = Consumption.STILL_QUEUED
        queried: list[str] = []
        real_state = self.dispatcher.queue_state
        self.dispatcher.queue_state = lambda item: queried.append(item) or real_state(item)
        # 窗口上界：入队 29 分 59 秒时仍要对账（Opus 审计 P3-2）
        delivered = self.now
        self.now = delivered + CONSUMPTION_WATCH_SECONDS - 1
        self.dispatcher.reconcile_consumption()
        self.assertEqual(len(queried), 2, "窗口内的两条入队项都要查询")
        self.store.set_consumption(self.store.attempts_in((Delivery.QUEUED,))[0].id, Consumption.NOT_OBSERVED, now=self.now)
        queried.clear()
        self.now = delivered + CONSUMPTION_WATCH_SECONDS
        self.dispatcher.reconcile_consumption()
        self.assertEqual(len(queried), 2, "恰好 30 分钟仍在窗口内（含等于）")
        for item in self.store.attempts_in((Delivery.QUEUED,)):
            self.store.set_consumption(item.id, Consumption.NOT_OBSERVED, now=self.now)
        queried.clear()
        self.now = delivered + 2 * 3600
        with patch.object(store_module, "_attempt_from_row", wraps=store_module._attempt_from_row) as built:  # pyright: ignore[reportPrivateUsage]
            self.assertFalse(self.dispatcher.has_live_work())
            self.dispatcher.reconcile_consumption()
        self.assertEqual(built.call_count, 0, "窗口外的记录不构造、不读正文")
        self.assertEqual(queried, [], "窗口外不再查询")
        self.assertEqual(
            {self._attempt(item.id).consumption for item in self.store.attempts_in((Delivery.QUEUED,))},
            {Consumption.NOT_OBSERVED},
            "超过观察窗口的入队项不再查询消费状态",
        )

    def test_codex_consumption_evidence_and_worker_liveness(self) -> None:
        target = ref()
        self.endpoints = [endpoint(target)]
        _task, attempt = self._task(target)
        self.assertTrue(self.dispatcher.has_live_work())
        self.queue_states["item-1"] = Consumption.STILL_QUEUED
        self._run()
        self.assertEqual(self._attempt(attempt.id).consumption, Consumption.STILL_QUEUED)
        self.assertTrue(self.dispatcher.has_live_work())
        self.queue_states["item-1"] = Consumption.LEFT_QUEUE
        self._run()
        self.assertEqual(self._attempt(attempt.id).consumption, Consumption.LEFT_QUEUE)
        self.assertFalse(self.dispatcher.has_live_work())


if __name__ == "__main__":
    unittest.main()
