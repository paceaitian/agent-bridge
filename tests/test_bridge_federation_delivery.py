"""P5 联邦本机投递（DESIGN §88.5/§88.7/§88.8，T05/T06/T09/T12 的 worker 部分）。

覆盖：外调前 intent 已提交（另一连接可读到）；真实 Linux ClaudePeerTransport（假 socket）与 CodexQueueTransport
（假 runner）首字节/队列请求前 DB 已有 intent、adapter 不调用 before_send 也正确；核验与领取之间插入取消 checkpoint
→ 零外调；intent 后崩溃恢复 UNKNOWN 不重投；通道异常记 UNKNOWN；结束回执在任务结束后仍投、带 --origin-device；
暂停/catchup/需同步只等待；目标消失 15 秒宽限后 target_gone；交付文件被改则不投；本机目标从冻结副本落本机交付叶；
提醒只在权威设备 A 上排；Claude 回执推进证据；消息头/页脚/真实类别。
"""

from __future__ import annotations

import errno
import json
import os
import socket
import sqlite3
import tempfile
import threading
import unittest
from collections.abc import Sequence
from pathlib import Path
from typing import Any
from unittest.mock import patch

import bridge_support  # noqa: F401  导入即隔离宿主会话环境

from types import SimpleNamespace

from agentstatus_bridge import endpoints as endpoint_module
from agentstatus_bridge.closure import ACCEPTED
from agentstatus_bridge.envelope import parse_header
from agentstatus_bridge.federation import attachments, authority, commands, mirror
from agentstatus_bridge.federation import config as fed_config
from agentstatus_bridge.federation.delivery import FederationDispatcher
from agentstatus_bridge.federation.errors import FedCliError
from agentstatus_bridge.federation.fedstore import FederatedStore
from agentstatus_bridge.federation.refs import RemoteEndpointRef, TargetRef
from agentstatus_bridge.federation.relay import RelayPaths
from agentstatus_bridge.federation.directory import root_binding
from agentstatus_bridge.model import Delivery, EndpointRef, Provider
from agentstatus_bridge.observer_dbus import ObserverView
from agentstatus_bridge.platforms.linux import process as procfs
from agentstatus_bridge.platforms.transport_codec import Receipt
from agentstatus_bridge.store import StoreError
from agentstatus_bridge.transports import DeliveryContext, DeliveryOutcome
from agentstatus_bridge.transports.claude_peer import ClaudePeerTransport
from agentstatus_bridge.transports.codex_queue import CodexQueueTransport, RunResult
from agentstatus_bridge.transports.codex_rpc import RpcFallback
from bridge_support import FakeProc, RecordingTransport, endpoint, register_claude_session

from test_bridge_federation_rules import DEV_A, DEV_B, T0, Device, pump

THREAD = "019a0000-1111-7222-8333-444455556666"
ITEM = "019A9999-AAAA-7BBB-8CCC-DDDDEEEEFFFF"
CLAUDE_A = "0000000a-1111-4222-8333-444444444444"


class Clock:
    def __init__(self) -> None:
        self.now = T0 + 10

    def __call__(self) -> int:
        return self.now


def bind(device: Device, provider: Provider, native: str, *, pid: int = 4242, start: str = "777",
         pane: str | None = "%3") -> TargetRef:
    local = EndpointRef(provider=provider, native_id=native, pid=pid, start_ticks=start, pane=pane,
                        label=native[:8])
    if provider is Provider.CLAUDE:
        register_claude_session(local)  # 根绑定按注册记录核实（与发现同判据）
    binding = root_binding(local)
    assert binding is not None
    endpoint_id, revision = device.store.bind_endpoint(provider=provider.value, native_id=native,
                                                       root_binding=binding, local_ref=local.to_dict())
    remote = RemoteEndpointRef(device_id=device.ident.device_id, provider=provider, native_id=native,
                               endpoint_id=endpoint_id, endpoint_revision=revision)
    return TargetRef(remote=remote, local=local)


def db_state(device: Device, msg_id: str) -> tuple[str, str]:
    """另开一个连接读已提交的 native 状态与 attempt delivery：证明 intent 已经 FULL 提交而非只在内存。"""
    with sqlite3.connect(device.store.path) as conn:
        native = conn.execute("SELECT state FROM fed_native_sends WHERE msg_id=?", (msg_id,)).fetchone()[0]
        delivery = json.loads(conn.execute("SELECT delivery_json FROM fed_attempts WHERE msg_id=?",
                                           (msg_id,)).fetchone()[0])["state"]
    return native, delivery


class DeliveryTestCase(unittest.TestCase):
    worker_provider = Provider.CODEX
    worker_native = THREAD

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        sessions = patch.dict(os.environ, {"AB_CLAUDE_SESSIONS_DIR": str(self.root / "claude-sessions")})
        sessions.start()
        self.addCleanup(sessions.stop)
        self.clock = Clock()
        self.a = Device(self.root, DEV_A, "vm")
        self.b = Device(self.root, DEV_B, "win")
        self.origin = bind(self.a, Provider.CLAUDE, CLAUDE_A)
        self.worker = self.worker_target()
        self.b_paths = RelayPaths(self.root / "win")
        self.a_paths = RelayPaths(self.root / "vm")
        # relay 会从 hub 盖章的 sourceDeviceName/目录记下对方登记名；这里直接写入
        self.b.store.remember_device_name(DEV_A, "vm")
        self.a.store.remember_device_name(DEV_B, "win")

    def worker_target(self) -> TargetRef:
        return bind(self.b, self.worker_provider, self.worker_native)

    def tearDown(self) -> None:
        self.a.store.close()
        self.b.store.close()
        self._tmp.cleanup()

    def create(self, *, refs: list[dict[str, Any]] | None = None, target: TargetRef | None = None):
        return authority.create_task(
            self.a.store, self.a.ident, title="跨设备", flow="handoff", body="请处理 X", refs=refs or [],
            origin=self.origin, origin_actor=authority.actor_for(self.origin, wire_token="claude@vm"),
            origin_class="bypass", target=target or TargetRef(remote=self.worker.remote), reviewer=None,
            now=self.clock.now)

    def dispatcher(self, device: Device, paths: RelayPaths, transport: Any, endpoints: list[Any], *,
                   reply: str | None = None) -> FederationDispatcher:
        return FederationDispatcher(device.store, device.ident, paths, discover=lambda: endpoints,
                                    transports={transport.provider: transport}, reply_address=reply,
                                    clock=self.clock, command="ab")

    def live(self, target: TargetRef, **kwargs: Any) -> Any:
        assert target.local is not None
        return endpoint(target.local, **kwargs)


class IntentOrderTests(DeliveryTestCase):
    def test_intent_committed_before_deliver_then_evidence(self) -> None:
        task, first = self.create()
        pump(self.a, self.b, now=self.clock.now)
        seen: list[tuple[str, str]] = []

        def outcome(_endpoint: Any, _text: str, _context: DeliveryContext) -> DeliveryOutcome:
            seen.append(db_state(self.b, first.msg_id))
            return DeliveryOutcome(Delivery.QUEUED, "codex_queued", provider_ref="item-1")

        transport = RecordingTransport(Provider.CODEX, outcome)
        result = self.dispatcher(self.b, self.b_paths, transport, [self.live(self.worker)]).run_once()
        self.assertEqual(result["sent"], 1)
        self.assertEqual(seen, [("intent", "sending")])  # 外调时 intent 已提交，且 delivery 同事务改 sending
        self.assertEqual(db_state(self.b, first.msg_id), ("finished", "queued"))
        (_, text, context) = transport.calls[0]
        header = parse_header(text)
        assert header is not None
        self.assertEqual((header.task_id, header.message_id, header.sender, header.device),
                         (task.task_id, first.msg_id, "claude@vm", "vm"))
        self.assertIn(f"ab report {task.task_id} --origin-device vm --attempt 1 --ack", text)
        self.assertEqual(context.sender_class, "bypass")
        pump(self.b, self.a, now=self.clock.now)
        self.assertEqual(self.a.store.attempt_by_msg(first.msg_id).delivery["state"], "queued")  # type: ignore[union-attr]
        # 再跑一轮不重投
        self.dispatcher(self.b, self.b_paths, transport, [self.live(self.worker)]).run_once()
        self.assertEqual(len(transport.calls), 1)

    def test_checkpoint_between_check_and_claim_means_zero_bytes(self) -> None:
        task, first = self.create()
        pump(self.a, self.b, now=self.clock.now)
        transport = RecordingTransport(Provider.CODEX)
        dispatcher = self.dispatcher(self.b, self.b_paths, transport, [self.live(self.worker)])
        real_render = dispatcher._render  # pyright: ignore[reportPrivateUsage]

        def render_then_cancel(*args: Any, **kwargs: Any) -> Any:
            rendered = real_render(*args, **kwargs)
            current = self.a.store.get_task(DEV_A, task.task_id)
            assert current is not None
            authority.request_cancel(self.a.store, self.a.ident, current, now=self.clock.now)
            pump(self.a, self.b, now=self.clock.now)  # 取消 checkpoint 在核验之后、领取之前到达
            return rendered

        dispatcher._render = render_then_cancel  # type: ignore[method-assign]
        dispatcher.run_once()
        self.assertEqual(transport.calls, [])
        self.assertEqual(db_state(self.b, first.msg_id)[0], "suppressed")

    def _interleave(self, first_msg: str, change: Any) -> RecordingTransport:
        """在核验/渲染之后、领取之前执行 change：领取事务必须在锁内复读控制。"""
        transport = RecordingTransport(Provider.CODEX)
        dispatcher = self.dispatcher(self.b, self.b_paths, transport, [self.live(self.worker)])
        real_render = dispatcher._render  # pyright: ignore[reportPrivateUsage]

        def render_then_change(*args: Any, **kwargs: Any) -> Any:
            rendered = real_render(*args, **kwargs)
            change()
            return rendered

        dispatcher._render = render_then_change  # type: ignore[method-assign]
        dispatcher.dispatch(first_msg, [self.live(self.worker)])
        return transport

    def test_claim_rereads_stale_and_pause_under_lock(self) -> None:
        task, first = self.create()
        pump(self.a, self.b, now=self.clock.now)

        def make_stale() -> None:
            # 只改镜像工作序号、不经 mirror 的同步抑制：只有领取事务内的复读能挡住
            with self.b.store.transaction() as conn:
                conn.execute("UPDATE fed_tasks SET current_work_seq=2")

        transport = self._interleave(first.msg_id, make_stale)
        self.assertEqual(transport.calls, [])
        self.assertEqual(db_state(self.b, first.msg_id)[0], "suppressed")
        task2, second = self.create()
        pump(self.a, self.b, now=self.clock.now)
        current = self.a.store.get_task(DEV_A, task2.task_id)
        assert current is not None

        def pause() -> None:
            authority.set_paused(self.a.store, self.a.ident, current, paused=True, now=self.clock.now)
            pump(self.a, self.b, now=self.clock.now)

        transport = self._interleave(second.msg_id, pause)
        self.assertEqual(transport.calls, [])
        self.assertEqual(db_state(self.b, second.msg_id)[0], "prepared")  # 暂停只等待，不抑制

    def test_unknown_sender_class_not_upgraded(self) -> None:
        authority.create_task(
            self.a.store, self.a.ident, title="t", flow="handoff", body="b", refs=[], origin=self.origin,
            origin_actor=authority.actor_for(self.origin, wire_token="claude@vm"), origin_class="unknown",
            target=TargetRef(remote=self.worker.remote), reviewer=None, now=self.clock.now)
        pump(self.a, self.b, now=self.clock.now)
        transport = RecordingTransport(Provider.CODEX)
        self.dispatcher(self.b, self.b_paths, transport, [self.live(self.worker)]).run_once()
        self.assertIsNone(transport.calls[0][2].sender_class)  # unknown 照 unknown，不借本机权限升级

    def test_running_dispatcher_stops_claiming_after_disable(self) -> None:
        _, first = self.create()
        pump(self.a, self.b, now=self.clock.now)
        transport = RecordingTransport(Provider.CODEX)
        dispatcher = self.dispatcher(self.b, self.b_paths, transport, [self.live(self.worker)])
        self.b.store.set_meta("enabled", "0")  # 与 federation disable 写入的一致
        dispatcher.run_once()
        self.assertEqual(transport.calls, [])
        self.assertFalse(dispatcher.has_live_work())  # 停用后不为未领取作业驻留
        self.assertEqual(db_state(self.b, first.msg_id)[0], "prepared")
        self.b.store.set_meta("enabled", "1")
        dispatcher.run_once()
        self.assertEqual(len(transport.calls), 1)  # 重新启用后接着投

    def test_crash_after_intent_recovers_unknown_without_redelivery(self) -> None:
        _, first = self.create()
        pump(self.a, self.b, now=self.clock.now)
        with self.b.store.transaction() as conn:
            conn.execute("UPDATE fed_native_sends SET state='intent', intent_at=?, worker_generation=? WHERE msg_id=?",
                         (self.clock.now, json.dumps({"pid": 2**22 + 7, "start": "1"}), first.msg_id))
        transport = RecordingTransport(Provider.CODEX)
        result = self.dispatcher(self.b, self.b_paths, transport, [self.live(self.worker)]).run_once()
        self.assertEqual((result["recovered"], transport.calls), (1, []))
        self.assertEqual(db_state(self.b, first.msg_id), ("unknown", "unknown"))
        pump(self.b, self.a, now=self.clock.now)
        attempt = self.a.store.attempt_by_msg(first.msg_id)
        assert attempt is not None
        self.assertFalse(authority.proven_undelivered(attempt, self.a.ident))

    def test_transport_exception_is_unknown(self) -> None:
        _, first = self.create()
        pump(self.a, self.b, now=self.clock.now)
        transport = RecordingTransport(Provider.CODEX, error=RuntimeError("boom"))
        self.dispatcher(self.b, self.b_paths, transport, [self.live(self.worker)]).run_once()
        self.assertEqual(db_state(self.b, first.msg_id), ("unknown", "unknown"))
        self.dispatcher(self.b, self.b_paths, transport, [self.live(self.worker)]).run_once()
        self.assertEqual(len(transport.calls), 1)  # UNKNOWN 不自动重投


class UnreadableProcessTests(DeliveryTestCase):
    """同用户进程还在、却读不到身份或 fd：本轮该 provider 不完整，活着的目标不判 target_gone（Codex r3-P2-01）。

    进程与 fd 读取、发现、目录发布、镜像与分发器都走产品代码；只把 Codex thread 分类固定为 root。
    """

    def sample(self, **overrides: Any) -> endpoint_module.DiscoverySources:
        proc = self.root / "proc"
        home = self.root / "codex"
        FakeProc(proc).add(4242, comm="codex", start="777", tty=1, argv=("codex",),
                           fds=(str(home / "sessions" / f"rollout-a-{THREAD}.jsonl"),))
        values: dict[str, Any] = dict(proc_root=proc, claude_sessions=self.root / "empty-claude", codex_home=home,
                                      grok_home=self.root / "empty-grok", panes=lambda: {}, titles=lambda: {},
                                      runtime=lambda: ObserverView())
        values.update(overrides)
        sources = endpoint_module.DiscoverySources(**values)
        classes = patch.object(endpoint_module, "_classify_codex_threads",
                               return_value=endpoint_module.CodexThreadClasses(kinds={THREAD: "root"}))
        classes.start()
        self.addCleanup(classes.stop)
        self.assertIn(THREAD, [item.ref.native_id for item in endpoint_module.discover(sources)])  # 无故障时看得见
        self.assertTrue(sources.provider_complete(Provider.CODEX))
        return sources

    def denied(self, sources: endpoint_module.DiscoverySources, stage: str) -> tuple[Any, list[str]]:
        hits: list[str] = []
        if stage == "stat":
            target = sources.proc_root / "4242" / "stat"
            original = Path.read_text

            def read(path: Path, *args: Any, **kwargs: Any) -> str:
                if path == target:
                    hits.append(stage)
                    raise PermissionError("synthetic stat unavailable")
                return original(path, *args, **kwargs)

            return patch.object(Path, "read_text", read), hits
        fd_dir = sources.proc_root / "4242" / "fd"
        if stage == "link":
            readlink = os.readlink

            def read_link(path: Any, *args: Any, **kwargs: Any) -> str:
                if Path(path) == fd_dir / "3":  # 目标 rollout 的那条 fd 链接
                    hits.append(stage)
                    raise PermissionError(errno.EACCES, "synthetic fd link unavailable")
                return readlink(path, *args, **kwargs)

            return patch.object(os, "readlink", read_link), hits
        listdir = os.listdir
        calls = [0]

        def listing(path: Any) -> list[str]:
            if Path(path) != fd_dir:
                return listdir(path)
            calls[0] += 1
            # first-list：奇数次列目录失败、紧接着的一次成功——旧实现的事后补列每轮都会抹掉本轮扫描的失败
            if stage == "fd" or calls[0] % 2:
                hits.append(stage)
                raise PermissionError(errno.EACCES, "synthetic fd unavailable")
            return listdir(path)

        return patch.object(os, "listdir", listing), hits

    def deliver_twice(self, sources: endpoint_module.DiscoverySources, stage: str, *,
                      calls: int = 0) -> tuple[str, int]:
        _, first = self.create()
        pump(self.a, self.b, now=self.clock.now)
        transport = RecordingTransport(Provider.CODEX)
        dispatcher = FederationDispatcher(
            self.b.store, self.b.ident, self.b_paths, discover=lambda: endpoint_module.discover(sources),
            transports={Provider.CODEX: transport}, clock=self.clock, command="ab", proc_root=sources.proc_root,
            empty_discovery_complete=sources.complete, provider_discovery_complete=sources.provider_complete)
        failure, hits = self.denied(sources, stage)
        with failure:
            dispatcher.run_once()
            self.clock.now += 16_000  # 超过 15 秒宽限
            dispatcher.run_once()
        self.assertTrue(hits)  # 注入的读失败确实走到了
        self.assertEqual(len(transport.calls), calls)
        self.last_calls = transport.calls
        return db_state(self.b, first.msg_id)[0], len(hits)

    def test_live_target_with_unreadable_fd_keeps_waiting(self) -> None:
        sources = self.sample()
        self.assertEqual(self.deliver_twice(sources, "fd")[0], "prepared")
        self.assertFalse(sources.provider_complete(Provider.CODEX))

    def test_unreadable_fd_link_keeps_waiting(self) -> None:
        # fd 目录列得出、目标那条链接读不到：持有集缺项，这次扫描不算看全（Codex r4-P2-01）
        sources = self.sample()
        self.assertEqual(self.deliver_twice(sources, "link")[0], "prepared")
        self.assertFalse(sources.provider_complete(Provider.CODEX))

    def test_partial_holdings_do_not_prove_target_missing(self) -> None:
        # 读到另一个 thread 不代表看全了：目标那条链接读不到时同样不完整（Codex r4-P2-01）
        sources = self.sample()
        other = THREAD[:-1] + "7"
        os.symlink(sources.codex_home / "sessions" / f"rollout-b-{other}.jsonl", sources.proc_root / "4242" / "fd" / "4")
        self.assertEqual(self.deliver_twice(sources, "link")[0], "prepared")
        self.assertFalse(sources.provider_complete(Provider.CODEX))

    def test_failed_first_listing_is_not_erased_by_a_later_one(self) -> None:
        # 完整性来自同一次扫描：本轮列目录失败就等，哪怕紧接着再列一次能成功；下一轮完整地重新看到目标才投递，
        # 不从失败的采样推出 target_gone（Opus r5-P3-1：只让第一次失败时旧实现第 2 轮也看得见目标，锁不住合同）
        sources = self.sample()
        state, hits = self.deliver_twice(sources, "first-list", calls=1)
        self.assertEqual((state, hits), ("finished", 1))
        self.assertEqual(self.last_calls[0][0].ref.native_id, THREAD)  # 投给的正是重新看到的目标
        self.assertTrue(sources.provider_complete(Provider.CODEX))

    def test_live_target_with_unreadable_stat_keeps_waiting(self) -> None:
        sources = self.sample()
        self.assertEqual(self.deliver_twice(sources, "stat")[0], "prepared")
        self.assertFalse(sources.provider_complete(Provider.CODEX))

    def test_other_users_unreadable_process_does_not_block(self) -> None:
        # 别的用户的进程本来就读不全：不阻断发现，完整的空结果照常宽限后判 target_gone
        sources = self.sample()
        sources.uid += 1  # 这些合成进程目录的属主不再是「本用户」
        self.assertEqual(self.deliver_twice(sources, "fd")[0], "finished")
        self.assertTrue(sources.provider_complete(Provider.CODEX))

    def test_exited_process_is_not_unverified(self) -> None:
        sources = self.sample()
        with patch.object(endpoint_module.procfs, "list_pids", return_value=[4242, 9999]):  # 9999 已退出：目录不在
            endpoint_module.discover(sources)
        self.assertTrue(sources.provider_complete(Provider.CODEX))

    def test_unreadable_claude_and_grok_processes_are_incomplete(self) -> None:
        proc = self.root / "proc"
        FakeProc(proc).add(5151, comm="claude", start="900")
        FakeProc(proc).add(6161, comm="grok", start="901")
        claude = self.root / "claude-reg"
        claude.mkdir()
        (claude / "5151.json").write_text(json.dumps({"pid": 5151, "sessionId": "s-1", "procStart": "900"}),
                                          encoding="utf-8")
        grok = self.root / "grok-home"
        grok.mkdir()
        (grok / "active_sessions.json").write_text(json.dumps([{"pid": 6161, "session_id": "g-1"}]), encoding="utf-8")
        sources = endpoint_module.DiscoverySources(proc_root=proc, claude_sessions=claude, codex_home=self.root / "cx",
                                                   grok_home=grok, panes=lambda: {}, titles=lambda: {},
                                                   runtime=lambda: ObserverView())
        endpoint_module.discover(sources)
        self.assertTrue(sources.complete())
        original = Path.read_text

        def read(path: Path, *args: Any, **kwargs: Any) -> str:
            if path.name == "stat" and path.parent.name in ("5151", "6161"):
                raise PermissionError("synthetic stat unavailable")
            return original(path, *args, **kwargs)

        with patch.object(Path, "read_text", read):
            endpoint_module.discover(sources)
        # 身份读不到的同用户进程也可能是 Codex：三家都标不完整
        self.assertEqual(sources.incomplete, {Provider.CLAUDE.value, Provider.GROK.value, Provider.CODEX.value})

    def test_grok_with_unreadable_fd_is_incomplete(self) -> None:
        proc = self.root / "proc"
        FakeProc(proc).add(6161, comm="grok", start="901")
        grok = self.root / "grok-home"
        grok.mkdir()
        (grok / "active_sessions.json").write_text(json.dumps([{"pid": 6161, "session_id": "g-1"}]), encoding="utf-8")
        sources = endpoint_module.DiscoverySources(proc_root=proc, claude_sessions=self.root / "none",
                                                   codex_home=self.root / "cx", grok_home=grok, panes=lambda: {},
                                                   titles=lambda: {}, runtime=lambda: ObserverView())
        hits: list[str] = []
        listdir = os.listdir
        fd_dir = proc / "6161" / "fd"

        def listing(path: Any) -> list[str]:
            if Path(path) == fd_dir:
                hits.append("grok-fd")
                raise PermissionError("synthetic fd unavailable")
            return listdir(path)

        with patch.object(os, "listdir", listing):
            endpoint_module.discover(sources)
        self.assertTrue(hits)
        self.assertEqual(sources.incomplete, {Provider.GROK.value})

    def test_grok_partial_holdings_are_incomplete(self) -> None:
        # Grok 一个进程持有多个会话是常态：读到其中一个、目标那条链接读不到，同样算没看全（Opus r5-P3-2）
        proc = self.root / "proc"
        grok = self.root / "grok-home"
        target, other = "0000000b-1111-4222-8333-444444444444", "0000000c-1111-4222-8333-444444444444"
        FakeProc(proc).add(6161, comm="grok", start="901", fds=tuple(
            str(grok / "sessions" / "cwd" / session / "events.jsonl") for session in (target, other)))
        grok.mkdir()
        (grok / "active_sessions.json").write_text(json.dumps(
            [{"pid": 6161, "session_id": session} for session in (target, other)]), encoding="utf-8")
        sources = endpoint_module.DiscoverySources(proc_root=proc, claude_sessions=self.root / "none",
                                                   codex_home=self.root / "cx", grok_home=grok, panes=lambda: {},
                                                   titles=lambda: {}, runtime=lambda: ObserverView())
        self.assertEqual(sorted(item.ref.native_id for item in endpoint_module.discover(sources)), [target, other])
        self.assertTrue(sources.complete())
        readlink = os.readlink

        def read_link(path: Any, *args: Any, **kwargs: Any) -> str:
            if Path(path) == proc / "6161" / "fd" / "3":  # 目标会话那条
                raise PermissionError(errno.EACCES, "synthetic fd link unavailable")
            return readlink(path, *args, **kwargs)

        with patch.object(os, "readlink", read_link):
            found = [item.ref.native_id for item in endpoint_module.discover(sources)]
        self.assertEqual(found, [other])  # 读得到的照常发现
        self.assertEqual(sources.incomplete, {Provider.GROK.value})

    def test_other_users_grok_with_unreadable_fd_does_not_block(self) -> None:
        # 别的用户的 Grok 进程本来就读不全 fd：不标不完整（与 Codex 同口径）
        proc = self.root / "proc"
        FakeProc(proc).add(6161, comm="grok", start="901")
        grok = self.root / "grok-home"
        grok.mkdir()
        (grok / "active_sessions.json").write_text(json.dumps([{"pid": 6161, "session_id": "g-1"}]), encoding="utf-8")
        sources = endpoint_module.DiscoverySources(proc_root=proc, claude_sessions=self.root / "none",
                                                   codex_home=self.root / "cx", grok_home=grok, panes=lambda: {},
                                                   titles=lambda: {}, runtime=lambda: ObserverView())
        sources.uid += 1  # 合成进程目录的属主不再是「本用户」
        hits: list[str] = []
        listdir = os.listdir
        fd_dir = proc / "6161" / "fd"

        def listing(path: Any) -> list[str]:
            if Path(path) == fd_dir:
                hits.append("grok-fd")
                raise PermissionError(errno.EACCES, "synthetic fd unavailable")
            return listdir(path)

        with patch.object(os, "listdir", listing):
            endpoint_module.discover(sources)
        self.assertTrue(hits)
        self.assertEqual(sources.incomplete, set())

    def test_publisher_marks_codex_incomplete_when_fd_unreadable(self) -> None:
        sources = self.sample()
        runtime = SimpleNamespace(store=self.b.store, ident=self.b.ident, config=SimpleNamespace(publish_names=True))
        failure, hits = self.denied(sources, "fd")
        with failure, patch.object(commands, "DiscoverySources", return_value=sources):
            snapshot = commands.directory_source(runtime)()  # type: ignore[arg-type]
        self.assertTrue(hits)
        self.assertFalse(snapshot["providers"]["codex"])  # type: ignore[index]


class RuntimeIdentityTests(DeliveryTestCase):
    """运行中的 worker 与 rebuild/disable：返回成功就保证旧运行时停领（Codex r2-P1-01/r2-P2-01）。"""

    def save_config(self) -> None:
        fed_config.save(self.b_paths.state_root, fed_config.FederationConfig(
            enabled=True, hub_id=self.b.ident.hub_id, device_id=self.b.ident.device_id, device_name="win",
            host="example.invalid", user="relay", expected_state_root=str(self.b_paths.state_root)))

    def test_rebuild_fences_dispatcher_already_running_on_old_hub(self) -> None:
        _, first = self.create()
        pump(self.a, self.b, now=self.clock.now)
        self.save_config()
        transport = RecordingTransport(Provider.CODEX)
        dispatcher = self.dispatcher(self.b, self.b_paths, transport, [self.live(self.worker)])
        commands.rebuild(self.b_paths.state_root, hub_id="e" * 32)
        dispatcher.run_once()
        self.assertEqual(len(transport.calls), 0, "rebuild 之后旧运行时仍领取了旧 hub 的作业")
        self.assertEqual((dispatcher.stale, dispatcher.has_live_work()), (True, False))  # worker 据此关掉重开
        self.assertEqual(db_state(self.b, first.msg_id)[0], "prepared")

    @unittest.skipIf(os.name == "nt", "Windows 上打开中的库文件不能移走")
    def test_moved_database_file_marks_runtime_stale(self) -> None:
        # 库文件被移走或删除：持旧句柄的运行时不在孤儿库上继续领取，交给 worker 按现状重开（Opus r3-P3-3 T18）
        _, first = self.create()
        pump(self.a, self.b, now=self.clock.now)
        transport = RecordingTransport(Provider.CODEX)
        dispatcher = self.dispatcher(self.b, self.b_paths, transport, [self.live(self.worker)])
        path = Path(self.b.store.path)
        os.rename(path, path.with_name(path.name + ".moved"))
        dispatcher.run_once()
        self.assertEqual((len(transport.calls), dispatcher.stale), (0, True))
        self.assertEqual((self.b.store.native(first.msg_id) or {}).get("state"), "prepared")  # 经原句柄看移走的库

    def test_rebuild_between_round_start_and_claim_is_fenced_inside_lock(self) -> None:
        _, first = self.create()
        pump(self.a, self.b, now=self.clock.now)
        self.save_config()
        transport = RecordingTransport(Provider.CODEX)
        live = [self.live(self.worker)]

        def discover_then_rebuild() -> list[Any]:
            commands.rebuild(self.b_paths.state_root, hub_id="e" * 32)  # 本轮身份核对之后、领取之前换 hub
            return live

        dispatcher = FederationDispatcher(self.b.store, self.b.ident, self.b_paths, discover=discover_then_rebuild,
                                          transports={Provider.CODEX: transport}, clock=self.clock, command="ab")
        dispatcher.run_once()
        self.assertEqual((len(transport.calls), db_state(self.b, first.msg_id)[0]), (0, "prepared"))

    def test_rebuild_refuses_while_relay_runs(self) -> None:
        self.save_config()
        lifecycle = commands.get_platform().lifecycle
        fd = lifecycle.open_lock(self.b_paths.state_root / commands.RELAY_LOCK)
        lifecycle.try_lock(fd)
        try:
            with self.assertRaises(FedCliError) as caught:
                commands.rebuild(self.b_paths.state_root, hub_id="e" * 32)
        finally:
            lifecycle.unlock(fd)
            lifecycle.close_lock(fd)
        self.assertEqual(caught.exception.code, "relay_running")
        self.assertEqual(self.b.store.meta("hubId"), self.b.ident.hub_id)  # 什么都没改

    def test_interrupted_rebuild_is_reported_and_not_attached(self) -> None:
        # 库已换 hub、配置还没写完（rebuild 中途崩溃）：命令报 rebuild 未完成，worker 不接联邦，重跑 rebuild 补齐
        from agentstatus_bridge import worker as worker_module  # layout: allow 只核 worker 的联邦接入判定

        self.save_config()
        self.b.store.set_meta("hubId", "e" * 32)
        with self.assertRaises(FedCliError) as caught:
            commands.open_runtime(self.b_paths.state_root)
        self.assertEqual(caught.exception.code, "federation_rebuild_incomplete")
        self.assertIsNone(worker_module._federation_runtime(  # pyright: ignore[reportPrivateUsage]
            self.b_paths.state_root, lambda *_args: None))
        commands.rebuild(self.b_paths.state_root, hub_id="e" * 32)
        commands.open_runtime(self.b_paths.state_root).close()

    def test_disable_between_round_start_and_claim_is_fenced_inside_lock(self) -> None:
        # 本轮入口已读过 enabled；领取锁内的 blocked 还要再读一次（Opus r2-P3-2 N39，与 R13 互为镜像）
        _, first = self.create()
        pump(self.a, self.b, now=self.clock.now)
        transport = RecordingTransport(Provider.CODEX)
        live = [self.live(self.worker)]

        def discover_then_disable() -> list[Any]:
            self.b.store.set_meta("enabled", "0")
            return live

        dispatcher = FederationDispatcher(self.b.store, self.b.ident, self.b_paths, discover=discover_then_disable,
                                          transports={Provider.CODEX: transport}, clock=self.clock, command="ab")
        dispatcher.run_once()
        self.assertEqual((len(transport.calls), db_state(self.b, first.msg_id)[0]), (0, "prepared"))

    def test_disable_failure_changes_nothing_and_retry_stops_claims(self) -> None:
        self.create()
        pump(self.a, self.b, now=self.clock.now)
        self.save_config()
        transport = RecordingTransport(Provider.CODEX)
        dispatcher = self.dispatcher(self.b, self.b_paths, transport, [self.live(self.worker)])
        with patch.object(FederatedStore, "open", side_effect=StoreError("store_busy")):
            with self.assertRaises(FedCliError) as caught:
                commands.disable(self.b_paths.state_root)
        self.assertEqual(caught.exception.code, "store_busy")  # 不静默成功
        config = fed_config.load(self.b_paths.state_root)
        self.assertTrue(config is not None and config.enabled)  # 配置不动：仍是一致的「启用」，重试即可
        commands.disable(self.b_paths.state_root)
        dispatcher.run_once()
        self.assertEqual(transport.calls, [])
        config = fed_config.load(self.b_paths.state_root)
        self.assertTrue(config is not None and not config.enabled)


class ControlTests(DeliveryTestCase):
    def test_closure_delivered_after_finish(self) -> None:
        task, first = self.create()
        pump(self.a, self.b, now=self.clock.now)
        transport = RecordingTransport(Provider.CODEX)
        self.dispatcher(self.b, self.b_paths, transport, [self.live(self.worker)]).run_once()
        pump(self.b, self.a, now=self.clock.now)
        current = self.a.store.get_task(DEV_A, task.task_id)
        assert current is not None
        outcome = authority.finish(self.a.store, self.a.ident, current, state=ACCEPTED, reason=None, decider="owner",
                                   sender=authority.actor_for(self.origin, wire_token="claude@vm"),
                                   sender_class="bypass", now=self.clock.now)
        pump(self.a, self.b, now=self.clock.now)
        (closure,) = outcome.closures
        self.dispatcher(self.b, self.b_paths, transport, [self.live(self.worker)]).run_once()
        self.assertEqual(len(transport.calls), 2)
        text = transport.calls[1][1]
        self.assertIn("AgentStatus 协作桥结束回执", text)
        self.assertIn("--origin-device vm）", text)
        self.assertEqual(db_state(self.b, closure.msg_id)[0], "finished")

    def test_paused_catchup_and_sync_only_wait(self) -> None:
        task, first = self.create()
        pump(self.a, self.b, now=self.clock.now)
        transport = RecordingTransport(Provider.CODEX)
        dispatcher = self.dispatcher(self.b, self.b_paths, transport, [self.live(self.worker)])
        self.b.store.set_meta("ingressCatchup", "1")
        self.assertEqual(dispatcher.dispatch(first.msg_id, [self.live(self.worker)]), "waiting")
        self.b.store.set_meta("ingressCatchup", "0")
        with self.b.store.transaction() as conn:
            conn.execute("UPDATE fed_tasks SET sync_required=1")
        self.assertEqual(dispatcher.dispatch(first.msg_id, [self.live(self.worker)]), "waiting")
        with self.b.store.transaction() as conn:
            conn.execute("UPDATE fed_tasks SET sync_required=0")
        current = self.a.store.get_task(DEV_A, task.task_id)
        assert current is not None
        authority.set_paused(self.a.store, self.a.ident, current, paused=True, now=self.clock.now)
        pump(self.a, self.b, now=self.clock.now)
        self.assertEqual(dispatcher.dispatch(first.msg_id, [self.live(self.worker)]), "waiting")
        self.b.store.set_meta("hubStateLost", "1")
        self.assertEqual(dispatcher.dispatch(first.msg_id, [self.live(self.worker)]), "waiting")
        self.assertEqual(transport.calls, [])
        self.assertEqual(db_state(self.b, first.msg_id)[0], "prepared")

    def test_complete_empty_discovery_proves_target_gone_after_grace(self) -> None:
        _, first = self.create()
        pump(self.a, self.b, now=self.clock.now)
        transport = RecordingTransport(Provider.CODEX)
        dispatcher = FederationDispatcher(self.b.store, self.b.ident, self.b_paths, discover=lambda: [],
                                          transports={Provider.CODEX: transport}, clock=self.clock,
                                          provider_discovery_complete=lambda _provider: True)
        dispatcher.run_once()
        self.clock.now += 16_000
        dispatcher.run_once()
        attempt = self.b.store.attempt_by_msg(first.msg_id)
        assert attempt is not None
        self.assertEqual(attempt.delivery.get("reason"), "target_gone")  # 对方已退出：不是「发现失败」，不永久等待
        self.assertFalse(dispatcher.has_live_work())  # worker 不为它永久驻留

    def test_incomplete_provider_discovery_only_waits(self) -> None:
        _, first = self.create()
        pump(self.a, self.b, now=self.clock.now)
        other = self.live(bind(self.b, Provider.CLAUDE, CLAUDE_A))  # 别的 provider 有行
        dispatcher = FederationDispatcher(self.b.store, self.b.ident, self.b_paths, discover=lambda: [other],
                                          transports={Provider.CODEX: RecordingTransport(Provider.CODEX)},
                                          clock=self.clock, provider_discovery_complete=lambda p: p is not Provider.CODEX)
        for _ in range(3):
            dispatcher.run_once()
            self.clock.now += 16_000
        self.assertEqual(db_state(self.b, first.msg_id)[0], "prepared")  # 目标 provider 没发现完整：不开始判消失

    def test_target_gone_after_grace(self) -> None:
        _, first = self.create()
        pump(self.a, self.b, now=self.clock.now)
        other = endpoint(EndpointRef(provider=Provider.CODEX, native_id="019a0000-0000-7000-8000-0000000000ff",
                                     pid=1, start_ticks="1"))
        transport = RecordingTransport(Provider.CODEX)
        dispatcher = self.dispatcher(self.b, self.b_paths, transport, [other])
        self.assertEqual(dispatcher.dispatch(first.msg_id, [other]), "waiting")
        self.clock.now += 16_000
        self.assertEqual(dispatcher.dispatch(first.msg_id, [other]), "failed")
        self.assertEqual(db_state(self.b, first.msg_id), ("finished", "failed"))
        pump(self.b, self.a, now=self.clock.now)
        attempt = self.a.store.attempt_by_msg(first.msg_id)
        assert attempt is not None
        self.assertTrue(authority.proven_undelivered(attempt, self.a.ident))  # 写前确定失败是证据

    def test_same_uuid_on_another_root_is_not_delivered(self) -> None:
        _, first = self.create()
        pump(self.a, self.b, now=self.clock.now)
        transport = RecordingTransport(Provider.CODEX)
        # 绑定时的 provider 根与活端点当前所在根不同（换了 CODEX_HOME）：同 UUID 不能借来投递（§88.6）
        with patch.dict(os.environ, {"CODEX_HOME": str(self.root / "another-codex-home")}):
            result = self.dispatcher(self.b, self.b_paths, transport, [self.live(self.worker)]).dispatch(
                first.msg_id, [self.live(self.worker)])
        self.assertEqual((result, transport.calls), ("failed", []))
        self.assertEqual(db_state(self.b, first.msg_id), ("finished", "failed"))
        attempt = self.b.store.attempt_by_msg(first.msg_id)
        assert attempt is not None
        self.assertEqual(attempt.delivery.get("reason"), "target_root_changed")

    def test_reminder_only_on_authority(self) -> None:
        task, first = self.create()
        pump(self.a, self.b, now=self.clock.now)
        report = {"authorityDeviceId": DEV_A, "taskId": task.task_id, "attempt": 1, "reportNo": 1,
                  "operationId": "7" * 32, "kind": "result", "note": "", "refs": [],
                  "reporter": authority.actor_for(self.worker, wire_token="codex@win").to_dict(),
                  "reporterClass": "bypass", "source": "agent"}
        authority.apply_report_safely(self.a.store, self.a.ident, report, reporter_device=DEV_B, now=self.clock.now)
        claude = RecordingTransport(Provider.CLAUDE, DeliveryOutcome(Delivery.DELIVERED, "claude_delivered"))
        a_dispatcher = self.dispatcher(self.a, self.a_paths, claude, [self.live(self.origin)], reply="uds:/x")
        a_dispatcher.run_once()  # 结果通知交给本机发起方
        self.assertEqual(len(claude.calls), 1)
        self.clock.now += 31 * 60 * 1000
        pump(self.a, self.b, now=self.clock.now)  # B 的镜像也到了「等发起方处理」的状态
        logged: list[str] = []
        b_dispatcher = FederationDispatcher(self.b.store, self.b.ident, self.b_paths, discover=lambda: [],
                                            transports={Provider.CODEX: RecordingTransport(Provider.CODEX)},
                                            clock=self.clock, command="ab",
                                            log=lambda event, _detail: logged.append(event))
        self.assertEqual(b_dispatcher.queue_reminders(), 0)  # B 不催，也不为此尝试分配
        self.assertEqual([event for event in logged if "reminder" in event], [])
        self.assertEqual(a_dispatcher.queue_reminders(), 1)
        reminder = self.a.store.attempts(DEV_A, task.task_id)[-1]
        self.assertEqual(reminder.options["noticeKind"], "reminder")

    def awaiting_origin(self, operation: str) -> tuple[Any, FederationDispatcher, RecordingTransport]:
        """A 上结果通知已交给发起方，再过 31 分钟：提醒到期、还没排出。"""
        task, _ = self.create()
        pump(self.a, self.b, now=self.clock.now)
        report = {"authorityDeviceId": DEV_A, "taskId": task.task_id, "attempt": 1, "reportNo": 1,
                  "operationId": operation * 32, "kind": "result", "note": "", "refs": [],
                  "reporter": authority.actor_for(self.worker, wire_token="codex@win").to_dict(),
                  "reporterClass": "bypass", "source": "agent"}
        authority.apply_report_safely(self.a.store, self.a.ident, report, reporter_device=DEV_B, now=self.clock.now)
        claude = RecordingTransport(Provider.CLAUDE, DeliveryOutcome(Delivery.DELIVERED, "claude_delivered"))
        dispatcher = self.dispatcher(self.a, self.a_paths, claude, [self.live(self.origin)], reply="uds:/x")
        dispatcher.run_once()
        self.assertEqual(len(claude.calls), 1)  # 结果通知
        self.clock.now += 31 * 60 * 1000
        return task, dispatcher, claude

    def test_due_reminder_is_delivered_once(self) -> None:
        # 排出的提醒走完领取与投递，不被自己的记录判成过期（Codex r4-P2-02）；之后不再重复提醒
        task, dispatcher, claude = self.awaiting_origin("5")
        self.assertEqual(dispatcher.run_once()["reminders"], 1)
        reminder = self.a.store.attempts(DEV_A, task.task_id)[-1]
        self.assertEqual((reminder.options["noticeKind"], reminder.delivery["state"]), ("reminder", "delivered"))
        self.assertEqual(len(claude.calls), 2)
        self.clock.now += 31 * 60 * 1000
        self.assertEqual(dispatcher.run_once()["reminders"], 0)
        self.assertEqual(len(claude.calls), 2)

    def test_queued_reminder_is_dropped_once_task_closes(self) -> None:
        # 有效性仍要核对：排出之后任务结束了，这条提醒照样作废，不靠删掉核对来修上面那条
        task, dispatcher, claude = self.awaiting_origin("6")
        self.assertEqual(dispatcher.queue_reminders(), 1)
        reminder = self.a.store.attempts(DEV_A, task.task_id)[-1]
        current = self.a.store.get_task(DEV_A, task.task_id)
        assert current is not None
        authority.finish(self.a.store, self.a.ident, current, state=ACCEPTED, reason=None, decider="owner",
                         sender=authority.actor_for(self.origin, wire_token="claude@vm"), sender_class="bypass",
                         now=self.clock.now)
        closed = self.a.store.get_task(DEV_A, task.task_id)
        assert closed is not None
        # 领取流程里结束的任务先被 suppress_reason 抑制；提醒有效性本身也要对它说「否」，前面的守卫变了也不漏发
        self.assertFalse(dispatcher._reminder_current(closed, reminder))  # pyright: ignore[reportPrivateUsage]
        dispatcher.dispatch(reminder.msg_id, [self.live(self.origin)])
        self.assertEqual(len(claude.calls), 1)
        self.assertEqual(db_state(self.a, reminder.msg_id)[0], "suppressed")

    def test_queued_reminder_is_dropped_once_origin_declines(self) -> None:
        # 排出之后发起方才拒收本次关注的通知：已排的提醒同样作废（与本机 _reminder_outdated 同判据）
        task, dispatcher, claude = self.awaiting_origin("4")
        self.assertEqual(dispatcher.queue_reminders(), 1)
        attempts = self.a.store.attempts(DEV_A, task.task_id)
        notice, reminder = attempts[-2], attempts[-1]
        self.assertEqual((notice.role, reminder.options["noticeKind"]), ("notice", "reminder"))
        self.a.store.update_attempt_columns(notice.msg_id, delivery=dict(notice.delivery, state="refused"))
        dispatcher.dispatch(reminder.msg_id, [self.live(self.origin)])
        self.assertEqual(len(claude.calls), 1)
        self.assertEqual(db_state(self.a, reminder.msg_id)[0], "suppressed")

    def test_disabled_authority_neither_queues_reminders_nor_stays_resident_for_them(self) -> None:
        # 领取另有 mirror.blocked 把关；这里锁住停用分支自己的两条合同：不排提醒、只为中断的 intent 驻留
        task, _ = self.create()
        pump(self.a, self.b, now=self.clock.now)
        report = {"authorityDeviceId": DEV_A, "taskId": task.task_id, "attempt": 1, "reportNo": 1,
                  "operationId": "8" * 32, "kind": "result", "note": "", "refs": [],
                  "reporter": authority.actor_for(self.worker, wire_token="codex@win").to_dict(),
                  "reporterClass": "bypass", "source": "agent"}
        authority.apply_report_safely(self.a.store, self.a.ident, report, reporter_device=DEV_B, now=self.clock.now)
        claude = RecordingTransport(Provider.CLAUDE, DeliveryOutcome(Delivery.DELIVERED, "claude_delivered"))
        a_dispatcher = self.dispatcher(self.a, self.a_paths, claude, [self.live(self.origin)], reply="uds:/x")
        a_dispatcher.run_once()
        self.clock.now += 31 * 60 * 1000
        before = len(self.a.store.attempts(DEV_A, task.task_id))
        self.a.store.set_meta("enabled", "0")
        result = a_dispatcher.run_once()
        self.assertEqual((result["reminders"], len(self.a.store.attempts(DEV_A, task.task_id))), (0, before),
                         "停用后仍排了发起方提醒")
        self.assertFalse(a_dispatcher.has_live_work(), "停用后仍为提醒驻留")
        self.a.store.set_meta("enabled", "1")
        self.assertTrue(a_dispatcher.has_live_work())
        self.assertEqual(a_dispatcher.run_once()["reminders"], 1)  # 重新启用后照常提醒


class ResidencyTests(DeliveryTestCase):
    """worker 只为现在就能处理的作业驻留（§88.1，Opus 审计 P2-1）：冻结/暂停/需同步不驻留也不做整体发现；
    等目标超过 10 分钟停泊；结果事务失败的外调保留结果重写，不永久停在 intent。"""

    def counting(self, endpoints: list[Any]) -> tuple[FederationDispatcher, list[int], RecordingTransport]:
        calls: list[int] = []
        transport = RecordingTransport(Provider.CODEX)

        def discover() -> list[Any]:
            calls.append(1)
            return endpoints

        dispatcher = FederationDispatcher(self.b.store, self.b.ident, self.b_paths, discover=discover,
                                          transports={Provider.CODEX: transport}, clock=self.clock, command="ab")
        return dispatcher, calls, transport

    def test_paused_and_frozen_work_neither_keeps_worker_nor_discovers(self) -> None:
        task, first = self.create()
        pump(self.a, self.b, now=self.clock.now)
        current = self.a.store.get_task(DEV_A, task.task_id)
        assert current is not None
        authority.set_paused(self.a.store, self.a.ident, current, paused=True, now=self.clock.now)
        pump(self.a, self.b, now=self.clock.now)
        dispatcher, calls, transport = self.counting([self.live(self.worker)])
        for _ in range(5):
            dispatcher.run_once()
        self.assertEqual((dispatcher.has_live_work(), len(calls), transport.calls), (False, 0, []))
        for key in ("hubStateLost", "ingressCatchup"):
            with self.subTest(key):
                authority.set_paused(self.a.store, self.a.ident, self.a.store.get_task(DEV_A, task.task_id),  # type: ignore[arg-type]
                                     paused=False, now=self.clock.now)
                pump(self.a, self.b, now=self.clock.now)
                self.b.store.set_meta(key, "1")
                dispatcher.run_once()
                self.assertEqual((dispatcher.has_live_work(), len(calls), transport.calls), (False, 0, []))
                self.b.store.set_meta(key, "0")
                authority.set_paused(self.a.store, self.a.ident, self.a.store.get_task(DEV_A, task.task_id),  # type: ignore[arg-type]
                                     paused=True, now=self.clock.now)
                pump(self.a, self.b, now=self.clock.now)
        self.assertEqual(db_state(self.b, first.msg_id)[0], "prepared")  # 只等待，不抑制

    def test_waiting_for_target_parks_after_ten_minutes(self) -> None:
        _, first = self.create()
        pump(self.a, self.b, now=self.clock.now)
        dispatcher, calls, _ = self.counting([])  # 没有完整性信号的空发现：只能等，不判目标不在
        dispatcher.run_once()
        self.assertTrue(dispatcher.has_live_work())
        self.clock.now += 599_000
        dispatcher.run_once()
        self.assertTrue(dispatcher.has_live_work())
        self.clock.now += 2_000
        dispatcher.run_once()
        self.assertFalse(dispatcher.has_live_work())  # 停泊：不再为它驻留（与本机 600 秒同口径）
        self.assertEqual(db_state(self.b, first.msg_id)[0], "prepared")
        self.assertEqual(len(calls), 3)

    def test_unrecorded_result_is_rewritten_not_left_in_intent(self) -> None:
        _, first = self.create()
        pump(self.a, self.b, now=self.clock.now)
        dispatcher, _, transport = self.counting([self.live(self.worker)])
        real = mirror.record_evidence
        failures = [StoreError("store_busy")]

        def flaky(*args: Any, **kwargs: Any) -> Any:
            if failures:
                raise failures.pop()
            return real(*args, **kwargs)

        with patch.object(mirror, "record_evidence", side_effect=flaky):
            dispatcher.run_once()
        self.assertEqual(db_state(self.b, first.msg_id)[0], "intent")
        self.assertTrue(dispatcher.has_live_work())  # 结果没写成：驻留，下轮重写
        dispatcher.run_once()
        self.assertEqual(db_state(self.b, first.msg_id), ("finished", "queued"))
        self.assertEqual(len(transport.calls), 1)  # 重写结果，不重投
        self.assertFalse(dispatcher.has_live_work())

    def test_own_process_intent_without_result_converges_to_unknown(self) -> None:
        _, first = self.create()
        pump(self.a, self.b, now=self.clock.now)
        me = procfs.read_process(os.getpid())
        assert me is not None
        with self.b.store.transaction() as conn:  # 本进程代际、但这个分发器手里没有结果（例如分发器重建）
            conn.execute("UPDATE fed_native_sends SET state='intent', intent_at=?, worker_generation=? WHERE msg_id=?",
                         (self.clock.now, json.dumps({"pid": me.pid, "start": me.start_ticks}), first.msg_id))
        dispatcher, _, transport = self.counting([self.live(self.worker)])
        dispatcher.run_once()
        self.assertEqual((db_state(self.b, first.msg_id), transport.calls), (("unknown", "unknown"), []))
        self.assertFalse(dispatcher.has_live_work())

    def test_stale_or_clock_rolled_back_mirror_waits_for_sync(self) -> None:
        _, first = self.create()
        pump(self.a, self.b, now=self.clock.now)
        dispatcher, _, transport = self.counting([self.live(self.worker)])
        start = self.clock.now
        for label, now in (("stale", start + 29 * 86_400_000), ("rollback", start - 11 * 60_000)):
            with self.subTest(label):
                self.clock.now = now
                self.assertEqual(dispatcher.dispatch(first.msg_id, [self.live(self.worker)]), "waiting")
                self.assertFalse(dispatcher.has_live_work())
        self.assertEqual(transport.calls, [])
        self.clock.now = start + 1000
        dispatcher.run_once()
        self.assertEqual(len(transport.calls), 1)  # 新鲜镜像照常投


class ClaimRecheckTests(DeliveryTestCase):
    """领取 CAS 锁内复读（§88.5 ⑤⑥⑦，Opus 审计 P2-5）：核验之后、领取之前变了的附件版本、绑定代际、提醒令牌都挡住外调。"""

    def interleave(self, device: Device, paths: RelayPaths, target: TargetRef, msg_id: str, change: Any,
                   provider: Provider = Provider.CODEX, reply: str | None = None) -> RecordingTransport:
        transport = RecordingTransport(provider)
        dispatcher = self.dispatcher(device, paths, transport, [self.live(target)], reply=reply)
        real_render = dispatcher._render  # pyright: ignore[reportPrivateUsage]

        def render_then_change(*args: Any, **kwargs: Any) -> Any:
            rendered = real_render(*args, **kwargs)
            change()
            return rendered

        dispatcher._render = render_then_change  # type: ignore[method-assign]
        dispatcher.dispatch(msg_id, [self.live(target)])
        return transport

    def test_attachment_version_changed_before_claim(self) -> None:
        local_worker = bind(self.a, Provider.CODEX, THREAD)
        src = self.root / "vm" / "src"
        src.mkdir(exist_ok=True)
        (src / "spec.md").write_bytes(b"spec")
        refs = [item.manifest for item in attachments.freeze(["spec.md"], cwd=src, origin_device=DEV_A,
                                                              staging=self.a_paths.staging)]
        _, first = self.create(refs=refs, target=local_worker)

        def relabel() -> None:
            with self.a.store.transaction() as conn:
                conn.execute("UPDATE fed_attachments SET file_identity_json=? WHERE msg_id=?",
                             (json.dumps({"dev": 1, "ino": 2, "size": 4}), first.msg_id))

        transport = self.interleave(self.a, self.a_paths, local_worker, first.msg_id, relabel)
        self.assertEqual(transport.calls, [])
        self.assertEqual(db_state(self.a, first.msg_id)[0], "prepared")

    def test_binding_revision_changed_before_claim(self) -> None:
        _, first = self.create()
        pump(self.a, self.b, now=self.clock.now)
        assert self.worker.local is not None
        local = self.worker.local

        binding = self.b.store.binding(self.worker.remote.endpoint_id)
        assert binding is not None

        def rebind() -> None:  # 同根上会话换了代际（新进程）：endpointId 不变、revision +1
            moved = dict(local.to_dict(), pid=9999, startTicks="999")
            self.b.store.bind_endpoint(provider="codex", native_id=THREAD, root_binding=str(binding["root_binding"]),
                                       local_ref=moved)

        transport = self.interleave(self.b, self.b_paths, self.worker, first.msg_id, rebind)
        self.assertEqual(transport.calls, [])
        self.assertEqual(db_state(self.b, first.msg_id)[0], "prepared")

    def test_reminder_token_outdated_before_claim(self) -> None:
        task, _ = self.create()
        pump(self.a, self.b, now=self.clock.now)
        report = {"authorityDeviceId": DEV_A, "taskId": task.task_id, "attempt": 1, "reportNo": 1,
                  "operationId": "7" * 32, "kind": "result", "note": "", "refs": [],
                  "reporter": authority.actor_for(self.worker, wire_token="codex@win").to_dict(),
                  "reporterClass": "bypass", "source": "agent"}
        authority.apply_report_safely(self.a.store, self.a.ident, report, reporter_device=DEV_B, now=self.clock.now)
        claude = RecordingTransport(Provider.CLAUDE, DeliveryOutcome(Delivery.DELIVERED, "claude_delivered"))
        self.dispatcher(self.a, self.a_paths, claude, [self.live(self.origin)], reply="uds:/x").run_once()
        self.clock.now += 31 * 60 * 1000
        queuer = self.dispatcher(self.a, self.a_paths, claude, [self.live(self.origin)], reply="uds:/x")
        self.assertEqual(queuer.queue_reminders(), 1)
        reminder = self.a.store.attempts(DEV_A, task.task_id)[-1]

        def outdate() -> None:
            options = dict(reminder.options, reminderToken="stale-token")
            with self.a.store.transaction() as conn:
                conn.execute("UPDATE fed_attempts SET options_json=? WHERE msg_id=?",
                             (json.dumps(options), reminder.msg_id))

        transport = self.interleave(self.a, self.a_paths, self.origin, reminder.msg_id, outdate,
                                    provider=Provider.CLAUDE, reply="uds:/x")
        self.assertEqual(transport.calls, [])
        self.assertEqual(db_state(self.a, reminder.msg_id)[0], "suppressed")


class AttachmentDeliveryTests(DeliveryTestCase):
    def freeze(self, device: Device, paths: RelayPaths, data: bytes) -> list[dict[str, Any]]:
        src = device.store.path.parent / "src"
        src.mkdir(exist_ok=True)
        (src / "spec.md").write_bytes(data)
        return [item.manifest for item in attachments.freeze(["spec.md"], cwd=src, origin_device=device.ident.device_id,
                                                              staging=paths.staging)]

    def test_local_target_lands_from_staging(self) -> None:
        local_worker = bind(self.a, Provider.CODEX, THREAD)
        refs = self.freeze(self.a, self.a_paths, b"spec body")
        _, first = self.create(refs=refs, target=local_worker)
        Path(refs[0]["resolvedPath"]).write_bytes(b"edited after send")  # 来源改了也只交付发送时冻结的副本
        transport = RecordingTransport(Provider.CODEX)
        self.dispatcher(self.a, self.a_paths, transport, [self.live(local_worker)]).run_once()
        self.assertEqual(len(transport.calls), 1)
        text = transport.calls[0][1]
        (row,) = self.a.store.attachments(first.msg_id)
        landed = self.a_paths.delivery_base(self.a.store.ledger_instance_id()) / row["local_relpath"]
        self.assertEqual(landed.read_bytes(), b"spec body")
        self.assertIn(f"- spec.md：{landed}", text)
        self.assertIn("来源 vm:", text)
        self.assertNotEqual(landed, Path(refs[0]["originalPath"]))

    def test_tampered_delivery_file_blocks(self) -> None:
        local_worker = bind(self.a, Provider.CODEX, THREAD)
        refs = self.freeze(self.a, self.a_paths, b"original")
        task, first = self.create(refs=refs, target=local_worker)
        transport = RecordingTransport(Provider.CODEX, error=RuntimeError("never reached"))
        dispatcher = self.dispatcher(self.a, self.a_paths, transport, [self.live(local_worker)])
        attempt = self.a.store.attempt_by_msg(first.msg_id)
        assert attempt is not None
        dispatcher._prepare_attachments(task, attempt)  # pyright: ignore[reportPrivateUsage]  先落交付叶（ready）
        (row,) = self.a.store.attachments(first.msg_id)
        self.assertEqual(row["state"], "ready")
        (self.a_paths.delivery_base(self.a.store.ledger_instance_id()) / row["local_relpath"]).write_bytes(b"evil!!!!")
        dispatcher.run_once()  # DB 仍是 ready，但文件内容已变：intent 前复核 SHA，不投
        self.assertEqual(transport.calls, [])
        self.assertEqual(db_state(self.a, first.msg_id), ("finished", "failed"))

    def test_local_landing_disk_full_waits_instead_of_failing(self) -> None:
        # 本机目标落交付叶时写满/写抖动：等下一轮，不记永久失败（Opus r2-P3-1）
        local_worker = bind(self.a, Provider.CODEX, THREAD)
        refs = self.freeze(self.a, self.a_paths, b"spec body")
        _, first = self.create(refs=refs, target=local_worker)
        transport = RecordingTransport(Provider.CODEX)
        dispatcher = self.dispatcher(self.a, self.a_paths, transport, [self.live(local_worker)])
        for code in ("device_storage_full", "attachment_write_failed"):
            with patch.object(attachments, "land", side_effect=attachments.AttachmentError(code)):
                self.assertEqual(dispatcher.run_once()["waiting"], 1, code)
            self.assertEqual(db_state(self.a, first.msg_id)[0], "prepared")
        with patch("agentstatus_bridge.federation.delivery.shutil.copyfile", side_effect=OSError(28, "full")):
            try:
                waiting = dispatcher.run_once()["waiting"]
            except OSError as error:
                self.fail(f"复制私有 part 的本机文件错误冲出了联邦轮次：{error!r}")
            self.assertEqual(waiting, 1)
        dispatcher.run_once()
        self.assertEqual(len(transport.calls), 1)  # 恢复后照常投

    def test_reference_only_rendered_without_local_path(self) -> None:
        local_worker = bind(self.a, Provider.CODEX, THREAD)
        ref = {"originDeviceId": DEV_B, "originalPath": "/big/video.mp4", "resolvedPath": "/big/video.mp4",
               "name": "video.mp4", "transfer": "reference", "reason": "single_file_limit", "size": 9 * 2**20,
               "sha256": None, "hashState": "not_computed_size_limit"}
        self.create(refs=[ref], target=local_worker)
        transport = RecordingTransport(Provider.CODEX)
        self.dispatcher(self.a, self.a_paths, transport, [self.live(local_worker)]).run_once()
        self.assertIn("- video.mp4：未传输：仅源设备引用，不能按此路径在本机读取（单文件超过 8 MiB；来源", transport.calls[0][1])


class ClaudeReceiptTests(DeliveryTestCase):
    worker_provider = Provider.CLAUDE
    worker_native = "0000000b-1111-4222-8333-444444444444"

    def test_receipt_advances_evidence(self) -> None:
        _, first = self.create()
        pump(self.a, self.b, now=self.clock.now)
        transport = RecordingTransport(Provider.CLAUDE, DeliveryOutcome(Delivery.WRITTEN, "claude_written"))
        dispatcher = self.dispatcher(self.b, self.b_paths, transport, [self.live(self.worker)], reply="uds:/x")
        dispatcher.run_once()
        self.assertEqual(db_state(self.b, first.msg_id)[1], "written")
        receipt = Receipt(message_uuid=transport.calls[0][2].message_uuid, delivery=Delivery.DELIVERED,
                          reason="claude_delivered")
        self.assertTrue(dispatcher.apply_receipt(receipt))
        self.assertEqual(db_state(self.b, first.msg_id)[1], "delivered")
        self.assertFalse(dispatcher.apply_receipt(Receipt(message_uuid="0f0f0f0f-0000-4000-8000-000000000001",
                                                          delivery=Delivery.DELIVERED, reason="x")))


class RealLinuxClaudeTests(DeliveryTestCase):
    """真实 ClaudePeerTransport + 假 socket：首字节到达前 DB 里已是 intent（transport 从不调用 before_send）。"""

    worker_provider = Provider.CLAUDE
    worker_native = "0000000b-1111-4222-8333-555555555555"

    def worker_target(self) -> TargetRef:
        me = procfs.read_process(os.getpid())
        assert me is not None
        return bind(self.b, Provider.CLAUDE, self.worker_native, pid=me.pid, start=me.start_ticks)

    def test_first_byte_after_intent(self) -> None:
        _, first = self.create()
        pump(self.a, self.b, now=self.clock.now)
        path = str(self.root / "peer.sock")
        server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        server.bind(path)
        server.listen(1)
        server.settimeout(5.0)
        observed: list[tuple[str, str]] = []
        received = bytearray()

        def serve() -> None:
            try:
                client, _ = server.accept()
            except OSError:
                return
            with client:
                client.settimeout(5.0)
                chunk = client.recv(65536)
                observed.append(db_state(self.b, first.msg_id))  # 首字节到达时
                received.extend(chunk)
                while chunk:
                    chunk = client.recv(65536)
                    received.extend(chunk)
            server.close()

        thread = threading.Thread(target=serve, daemon=True)
        thread.start()
        assert self.worker.local is not None
        live = endpoint(self.worker.local, socket_path=path)
        transport = ClaudePeerTransport()
        with patch("agentstatus_bridge.transports.claude_peer.INLINE_RECEIPT_SECONDS", 0.2):
            self.dispatcher(self.b, self.b_paths, transport, [live], reply="uds:/x").run_once()
        thread.join(5.0)
        self.assertEqual(observed, [("intent", "sending")])
        frame = json.loads(bytes(received).decode("utf-8"))
        self.assertEqual(frame["msg_id"].replace("-", ""), first.msg_id)
        self.assertEqual(db_state(self.b, first.msg_id), ("finished", "written"))


class RealLinuxCodexTests(DeliveryTestCase):
    """真实 CodexQueueTransport + 假 runner：发 queue 请求前 DB 里已是 intent。"""

    def setUp(self) -> None:
        # 先切 CODEX_HOME 再绑定：投递前会核活端点仍在绑定时的 provider 根上（§88.6）
        home = tempfile.TemporaryDirectory(dir="/var/tmp" if os.path.isdir("/var/tmp") else None)
        self.addCleanup(home.cleanup)
        patcher = patch.dict(os.environ, {"CODEX_HOME": home.name})
        patcher.start()
        self.addCleanup(patcher.stop)
        super().setUp()

    def test_queue_request_after_intent(self) -> None:
        _, first = self.create()
        pump(self.a, self.b, now=self.clock.now)
        observed: list[tuple[str, str]] = []

        def runner(argv: Sequence[str], _timeout: float) -> RunResult:
            if "queue" in argv:
                observed.append(db_state(self.b, first.msg_id))
                return RunResult(0, f"Queued message {ITEM} for thread {THREAD}.\n", "")
            return RunResult(0, "codex-cli 0.164.0\n", "")

        def no_daemon(*_args: object, **_kwargs: object) -> RpcFallback:
            return RpcFallback("socket_missing")

        transport = CodexQueueTransport(executable="/usr/bin/codex", runner=runner, rpc=no_daemon)
        self.dispatcher(self.b, self.b_paths, transport, [self.live(self.worker)]).run_once()
        self.assertEqual(observed, [("intent", "sending")])
        self.assertEqual(db_state(self.b, first.msg_id), ("finished", "queued"))


if __name__ == "__main__":
    unittest.main()
