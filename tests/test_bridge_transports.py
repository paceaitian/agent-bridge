"""协作桥原生通道：Codex queue 结果分类、Claude 帧/回执与真实 Unix socket 投递。"""

from __future__ import annotations
from agentstatus_bridge.platforms.transport_codec import encode_address

from collections.abc import Sequence
import json
import os
from pathlib import Path
import socket
import sqlite3
import subprocess
from tempfile import TemporaryDirectory
import threading
import unittest
from unittest.mock import patch

from agentstatus_bridge.platforms.linux import process as procfs
from agentstatus_bridge.views import project_delivery_detail
from agentstatus_bridge.naming import DEFAULT_COMMAND as CMD
from agentstatus_bridge.envelope import parse_header, render
from agentstatus_bridge.model import Attempt, Consumption, Delivery, EndpointRef, Flow, Provider, Role, Task
from agentstatus_bridge.transports import DeliveryContext
from agentstatus_bridge.transports import claude_peer
from agentstatus_bridge.transports.claude_peer import (
    PRIORITY_ENV,
    ClaudeInbox,
    ClaudePeerTransport,
    build_frame,
    normalize_sender_name,
    parse_receipt,
)
from agentstatus_bridge.transports.codex_queue import (
    CHANNEL_KEY,
    FALLBACK_KEY,
    MAX_ARGV_MESSAGE_BYTES,
    OUTPUT_KEY,
    UNKNOWN_VERSION,
    VERSION_KEY,
    VERSION_TIMEOUT_SECONDS,
    CodexQueueTransport,
    RunResult,
    classify_failure,
    cli_version,
    parse_version,
    queue_item_state,
    summarize_queue_evidence,
)
from agentstatus_bridge.transports.codex_rpc import RpcFallback
from bridge_support import endpoint, ref

THREAD = "019a0000-1111-7222-8333-444455556666"
ITEM = "019A9999-AAAA-7BBB-8CCC-DDDDEEEEFFFF"
# CLI 通道的用例：daemon 不在线，RPC 在连接之前就回退（DESIGN §61.2 第 1 条）
CLI_FALLBACK = {CHANNEL_KEY: "cli", FALLBACK_KEY: "socket_missing"}


def no_daemon(*_args: object, **_kwargs: object) -> RpcFallback:
    return RpcFallback("socket_missing")


def _isolate_codex_home(case: unittest.TestCase) -> None:
    """`CODEX_HOME` 指向临时目录（DESIGN §61.2 第 9 条）：用例自己隔离，守卫只是最后一道防线（§61 第 2 轮 Opus P3-2）。"""
    home = TemporaryDirectory(dir="/var/tmp" if os.path.isdir("/var/tmp") else None)
    case.addCleanup(home.cleanup)
    patcher = patch.dict(os.environ, {"CODEX_HOME": home.name})
    patcher.start()
    case.addCleanup(patcher.stop)


class CodexQueueTests(unittest.TestCase):
    def setUp(self) -> None:
        _isolate_codex_home(self)

    def _transport(self, result: RunResult | Exception) -> tuple[CodexQueueTransport, list[Sequence[str]]]:
        calls: list[Sequence[str]] = []

        def runner(argv: Sequence[str], _timeout: float) -> RunResult:
            calls.append(argv)
            if isinstance(result, Exception):
                raise result
            return result

        return CodexQueueTransport(executable="/usr/bin/codex", runner=runner, rpc=no_daemon), calls

    def _deliver(self, transport: CodexQueueTransport, text: str = "hello"):
        context = DeliveryContext(message_uuid="u", sender_name="user")
        return transport.deliver(endpoint(ref(native=THREAD)), text, context)

    def test_success_records_queue_item(self) -> None:
        transport, calls = self._transport(RunResult(0, f"Queued message {ITEM} for thread {THREAD}.\n", ""))
        outcome = self._deliver(transport)
        self.assertEqual((outcome.delivery, outcome.provider_ref), (Delivery.QUEUED, ITEM.lower()))
        self.assertEqual(list(calls[0]), ["/usr/bin/codex", "queue", "--thread", THREAD, "--message", "hello"])

    def test_success_for_other_thread_is_unknown(self) -> None:
        other = "019a0000-0000-7000-8000-000000000000"
        transport, _ = self._transport(RunResult(0, f"Queued message {ITEM} for thread {other}.", ""))
        outcome = self._deliver(transport)
        self.assertEqual((outcome.delivery, outcome.reason), (Delivery.UNKNOWN, "codex_queue_unparsed_output"))

    def test_known_rejections_are_proven_undelivered(self) -> None:
        cases = {
            f"Error: failed to queue session message: thread/queue/add failed: thread not found: {THREAD} (code -32600)": "codex_thread_not_found",
            "Error: thread/queue/add failed: thread x is archived. Run `codex unarchive x` (code -32600)": "codex_thread_archived",
            "Error: thread/queue/add failed: queue cannot contain more than 100 submissions (code -32600)": "provider_queue_full",
            "Error: cannot queue through an embedded app server while a local app-server daemon is running": "codex_daemon_conflict",
            "Error: remote app server does not support thread/queue/add; update or restart the server": "codex_version_unsupported",
        }
        for stderr, reason in cases.items():
            with self.subTest(reason=reason):
                transport, _ = self._transport(RunResult(1, "", stderr))
                outcome = self._deliver(transport)
                self.assertEqual((outcome.delivery, outcome.reason), (Delivery.FAILED, reason))

    def test_storage_transport_and_unrecognized_errors_are_unknown(self) -> None:
        self.assertEqual(
            classify_failure("Error: queued submission operation failed: queue storage failed: locked"),
            (Delivery.UNKNOWN, "codex_queue_storage_error"),
        )
        self.assertEqual(
            classify_failure("Error: thread/queue/add transport error: broken pipe"),
            (Delivery.UNKNOWN, "codex_transport_error"),
        )
        self.assertEqual(classify_failure("Error: something new"), (Delivery.UNKNOWN, "codex_queue_unrecognized_error"))

    def test_usage_error_and_other_pre_insert_rejections(self) -> None:
        transport, _ = self._transport(RunResult(2, "", "error: unexpected argument '--bogus' found"))
        outcome = self._deliver(transport)
        self.assertEqual((outcome.delivery, outcome.reason), (Delivery.FAILED, "codex_cli_usage_error"))
        self.assertEqual(
            classify_failure(
                "Error: failed to queue session message: thread/queue/add failed: invalid thread id: x (code -32600)"
            ),
            (Delivery.FAILED, "codex_thread_invalid"),
        )
        transport, _ = self._transport(RunResult(101, "", "thread 'main' panicked"))
        self.assertEqual(self._deliver(transport).delivery, Delivery.UNKNOWN)

    def test_timeout_is_unknown_and_oversized_message_is_not_attempted(self) -> None:
        transport, _ = self._transport(subprocess.TimeoutExpired(["codex"], 60))
        self.assertEqual(self._deliver(transport).reason, "codex_queue_timeout")
        transport, calls = self._transport(RunResult(0, "", ""))
        outcome = self._deliver(transport, "x" * (MAX_ARGV_MESSAGE_BYTES + 1))
        self.assertEqual((outcome.delivery, outcome.reason), (Delivery.FAILED, "message_too_large_for_argv"))
        self.assertEqual(calls, [])

    def test_missing_cli(self) -> None:
        with patch("agentstatus_bridge.platforms.linux.files.shutil.which", return_value=None):
            outcome = CodexQueueTransport().deliver(
                endpoint(ref(native=THREAD)), "x", DeliveryContext(message_uuid="u", sender_name="user")
            )
        self.assertEqual((outcome.delivery, outcome.reason), (Delivery.FAILED, "codex_cli_missing"))
        # 找不到 codex 就取不到 initialize 要用的版本：不连 socket
        self.assertEqual(outcome.detail, {CHANNEL_KEY: "cli", FALLBACK_KEY: "version_unavailable"})

    def test_outcome_detail_never_carries_command_output(self) -> None:
        """stdout/stderr 只用来分类、不进 detail（DESIGN §45.43 2.3 的负例）。

        标量守卫只约束形状，挡不住一个短字符串形式的正文；所以要直接证明输出文本本身不会被记下。
        """
        marker = "SYNTHETIC_PRIVATE_MARKER"
        results = [
            RunResult(0, f"Queued message {ITEM} for thread {THREAD}.\n{marker}", ""),
            RunResult(0, marker, ""),
            RunResult(1, marker, f"Error: thread/queue/add failed: thread not found: {THREAD} {marker}"),
            RunResult(1, "", f"Error: queued submission operation failed: queue storage failed: {marker}"),
            RunResult(1, "", f"Error: {marker}"),
            RunResult(2, "", f"error: unexpected argument '{marker}' found"),
            RunResult(101, "", f"thread 'main' panicked at {marker}"),
        ]
        for result in results:
            with self.subTest(code=result.returncode, stdout=result.stdout[:16]):
                transport, _ = self._transport(result)
                outcome = self._deliver(transport)
                self.assertNotIn(marker, json.dumps(outcome.detail))
                self.assertFalse(project_delivery_detail(outcome.detail)[1])

    def test_queue_item_state_reads_ids_only(self) -> None:
        with TemporaryDirectory() as tmp:
            database = Path(tmp) / "queue_1.sqlite"
            self.assertEqual(queue_item_state("a", database=database), Consumption.UNKNOWN)
            with sqlite3.connect(database) as connection:
                connection.execute("CREATE TABLE other (id TEXT)")
            self.assertEqual(queue_item_state("a", database=database), Consumption.UNKNOWN)
            with sqlite3.connect(database) as connection:
                connection.execute(
                    "CREATE TABLE queued_items (id TEXT PRIMARY KEY, thread_id TEXT, payload_json TEXT,"
                    " queue_order INTEGER, created_at_ms INTEGER, updated_at_ms INTEGER)"
                )
                connection.execute("INSERT INTO queued_items VALUES ('a', 't', '{}', 1, 0, 0)")
            self.assertEqual(queue_item_state("a", database=database), Consumption.STILL_QUEUED)
            self.assertEqual(queue_item_state("b", database=database), Consumption.LEFT_QUEUE)


class CodexQueueEvidenceTests(unittest.TestCase):
    """每次真正外调 `codex queue` 都留下「哪个版本执行的」与「输出是否落在已知分支」（DESIGN §45.44）。

    夹具仿照 standalone 安装：入口链接 → `current` 链接 → 某个 release。假 runner 可以在 queue 调用期间
    原子切换 `current`，复现自动升级与投递重叠的竞态。
    """

    def setUp(self) -> None:
        _isolate_codex_home(self)
        self._tmp = TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        base = Path(self._tmp.name)
        self.releases: dict[str, Path] = {}
        for version in ("0.155.1", "0.156.0"):
            binary = base / "releases" / version / "bin" / "codex"
            binary.parent.mkdir(parents=True)
            binary.write_text("#!/bin/sh\n")
            self.releases[version] = binary
        self.current = base / "current"
        self.current.symlink_to(base / "releases" / "0.155.1")
        self.entry = base / "codex"
        self.entry.symlink_to(self.current / "bin" / "codex")
        self.calls: list[tuple[list[str], float]] = []
        self.switch_during_queue: str | None = None
        self.queue_result: RunResult | Exception = RunResult(0, f"Queued message {ITEM} for thread {THREAD}.\n", "")
        self.version_results: dict[str, RunResult | Exception] = {}

    def switch(self, version: str) -> None:
        # 与安装器同一种原子切换：先建新链接再 rename 覆盖
        staged = self.current.with_name("current.new")
        staged.symlink_to(self.releases[version].parent.parent)
        os.replace(staged, self.current)

    def runner(self, argv: Sequence[str], timeout: float) -> RunResult:
        self.calls.append((list(argv), timeout))
        if argv[1] == "queue":
            if self.switch_during_queue is not None:
                self.switch(self.switch_during_queue)
            if isinstance(self.queue_result, Exception):
                raise self.queue_result
            return self.queue_result
        if argv[1] == "--version":
            version = Path(argv[0]).parent.parent.name
            result = self.version_results.get(version, RunResult(0, f"codex-cli {version}\n", ""))
            if isinstance(result, Exception):
                raise result
            return result
        raise AssertionError(argv)

    def transport(self) -> CodexQueueTransport:
        return CodexQueueTransport(executable=str(self.entry), runner=self.runner, rpc=no_daemon)

    def deliver(self, transport: CodexQueueTransport | None = None, text: str = "hello"):
        context = DeliveryContext(message_uuid="u", sender_name="user")
        return (transport or self.transport()).deliver(endpoint(ref(native=THREAD)), text, context)

    def version_calls(self) -> list[list[str]]:
        return [argv for argv, _ in self.calls if argv[1] == "--version"]

    def test_output_evidence_for_every_branch(self) -> None:
        other = "019a0000-0000-7000-8000-000000000000"
        cases: dict[str, tuple[RunResult, Delivery, str | None]] = {
            "成功": (RunResult(0, f"Queued message {ITEM} for thread {THREAD}.", ""), Delivery.QUEUED, "recognized"),
            # 格式认得、语义不符：原因码不拆，只在 queueOutput 上区分
            "thread 不符": (RunResult(0, f"Queued message {ITEM} for thread {other}.", ""), Delivery.UNKNOWN, "recognized"),
            "stdout 不认得": (RunResult(0, "something new", ""), Delivery.UNKNOWN, "unrecognized"),
            # 固定 argv 被 clap 拒绝只可能是上游改了接口：这是本节最想抓的信号
            "exit 2": (RunResult(2, "", "error: unexpected argument '--thread' found"), Delivery.FAILED, "unrecognized"),
            "已知拒收": (RunResult(1, "", "Error: thread/queue/add failed: thread not found: x"), Delivery.FAILED, "recognized"),
            "已知不确定": (RunResult(1, "", "Error: thread/queue/add transport error: broken pipe"), Delivery.UNKNOWN, "recognized"),
            "未识别错误": (RunResult(1, "", "Error: something new"), Delivery.UNKNOWN, "unrecognized"),
            "panic": (RunResult(101, "", "thread 'main' panicked"), Delivery.UNKNOWN, "unrecognized"),
            # 被信号终止：进程没有正常结束，无结果可评
            "被信号终止": (RunResult(-9, "", ""), Delivery.UNKNOWN, None),
        }
        for name, (result, delivery, output) in cases.items():
            with self.subTest(case=name):
                self.queue_result = result
                outcome = self.deliver()
                self.assertEqual(outcome.delivery, delivery)
                self.assertEqual(outcome.detail.get(OUTPUT_KEY), output)
                self.assertEqual(outcome.detail[VERSION_KEY], "0.155.1")
                self.assertFalse(project_delivery_detail(outcome.detail)[1])

    def test_timeout_records_the_version_but_not_the_output(self) -> None:
        self.queue_result = subprocess.TimeoutExpired(["codex"], 60)
        outcome = self.deliver()
        self.assertEqual(outcome.reason, "codex_queue_timeout")
        self.assertEqual(outcome.detail, {VERSION_KEY: "0.155.1", **CLI_FALLBACK})

    def test_no_external_call_leaves_no_evidence(self) -> None:
        # 没有外调 CLI 就没有版本与输出证据；通道与回退原因照记
        self.assertEqual(self.deliver(text="x" * (MAX_ARGV_MESSAGE_BYTES + 1)).detail, CLI_FALLBACK)
        self.queue_result = FileNotFoundError("codex")
        self.assertEqual(self.deliver().detail, CLI_FALLBACK)
        with patch("agentstatus_bridge.platforms.linux.files.shutil.which", return_value=None):
            outcome = CodexQueueTransport(runner=self.runner).deliver(
                endpoint(ref(native=THREAD)), "x", DeliveryContext(message_uuid="u", sender_name="user")
            )
        self.assertEqual((outcome.reason, outcome.detail),
                         ("codex_cli_missing", {CHANNEL_KEY: "cli", FALLBACK_KEY: "version_unavailable"}))
        # 前两次投递前各为 RPC 身份查过一次（各自新建 transport、无缓存）；没有外调 CLI 时不再为事后取证另查
        self.assertEqual(len(self.version_calls()), 2)

    def test_version_comes_from_the_release_resolved_before_the_call(self) -> None:
        outcome = self.deliver()
        self.assertEqual(outcome.detail[VERSION_KEY], "0.155.1")
        # 查版本用的是不可变的 release 路径，而 queue 本身仍经原入口调用（不改 argv[0]）；版本在投递前为 RPC
        # 身份查过一次，事后取证命中缓存
        self.assertEqual([argv[0] for argv, _ in self.calls if argv[1] == "queue"], [str(self.entry)])
        self.assertEqual(self.calls[0], ([os.path.realpath(self.releases["0.155.1"]), "--version"], VERSION_TIMEOUT_SECONDS))
        self.assertEqual(len(self.version_calls()), 1)

    def test_entry_switched_during_the_call_is_unknown(self) -> None:
        """Codex V01：投后再解析入口会把旧程序的结果记到新版本头上。"""
        self.switch_during_queue = "0.156.0"
        outcome = self.deliver()
        self.assertEqual((outcome.delivery, outcome.detail[VERSION_KEY]), (Delivery.QUEUED, UNKNOWN_VERSION))
        # 只有投前为 RPC 身份查的那一次（0.155.1）；投后入口已切换，不再查、不归到任何版本
        self.assertEqual(self.version_calls(), [[os.path.realpath(self.releases["0.155.1"]), "--version"]])

    def test_diagnostic_failures_never_rewrite_the_outcome(self) -> None:
        module = "agentstatus_bridge.transports.codex_queue"
        for target in (f"{module}.os.path.realpath", f"{module}.os.stat", f"{module}.cli_version"):
            with self.subTest(target=target):
                transport = self.transport()
                with patch(target, side_effect=RuntimeError("SYNTHETIC")) as failing:  # layout: allow 循环替换同一传输的三个依赖点，逐个注入失败
                    outcome = self.deliver(transport)
                self.assertTrue(failing.called)
                self.assertEqual((outcome.delivery, outcome.provider_ref), (Delivery.QUEUED, ITEM.lower()))
                self.assertEqual(outcome.detail[VERSION_KEY], UNKNOWN_VERSION)
                self.assertEqual(outcome.detail[OUTPUT_KEY], "recognized")
                self.assertEqual(outcome.detail[CHANNEL_KEY], "cli")

    def test_version_is_cached_per_release_and_failures_are_not(self) -> None:
        transport = self.transport()
        self.deliver(transport)
        self.deliver(transport)
        self.assertEqual(len(self.version_calls()), 1)
        # 升级之后 realpath 变了：重新查
        self.switch("0.156.0")
        self.assertEqual(self.deliver(transport).detail[VERSION_KEY], "0.156.0")
        self.assertEqual(len(self.version_calls()), 2)
        # 查询失败得到的 unknown 不缓存：下一次投递重试并能记出版本
        self.switch("0.155.1")
        for failure in (RunResult(1, "", "boom"), subprocess.TimeoutExpired(["codex"], 3)):
            with self.subTest(failure=type(failure).__name__):
                fresh = self.transport()
                self.version_results["0.155.1"] = failure
                self.assertEqual(self.deliver(fresh).detail[VERSION_KEY], UNKNOWN_VERSION)
                del self.version_results["0.155.1"]
                self.assertEqual(self.deliver(fresh).detail[VERSION_KEY], "0.155.1")

    def test_same_release_rewritten_in_place_is_asked_again(self) -> None:
        # 同一路径被原地覆盖（mtime 变、realpath 不变）也要重查：缓存键里的 mtime 就是为这个（Codex 实现复核 C01）
        transport = self.transport()
        self.deliver(transport)
        binary = self.releases["0.155.1"]
        before = binary.stat()
        os.utime(binary, ns=(before.st_atime_ns, before.st_mtime_ns + 1_000_000))
        self.deliver(transport)
        self.assertEqual(len(self.version_calls()), 2)

    def test_realpath_failing_only_after_the_call_keeps_the_outcome(self) -> None:
        real = os.path.realpath
        calls = 0

        def fail_after_the_call(path: str) -> str:
            # 第 1 次是 RPC 准备、第 2 次是 CLI 外调前，第 3 次才是外调之后
            nonlocal calls
            calls += 1
            if calls == 3:
                raise OSError("SYNTHETIC")
            return real(path)

        with patch("agentstatus_bridge.transports.codex_queue.os.path.realpath", side_effect=fail_after_the_call):
            outcome = self.deliver()
        self.assertEqual(calls, 3)
        self.assertEqual((outcome.delivery, outcome.provider_ref), (Delivery.QUEUED, ITEM.lower()))
        self.assertEqual(outcome.detail[VERSION_KEY], UNKNOWN_VERSION)

    def test_version_output_must_have_the_exact_shape(self) -> None:
        accepted = {
            "codex-cli 0.156.0": "0.156.0",
            "  codex-cli 0.156.0\n": "0.156.0",
            "codex-cli 0.156.0-alpha.1": "0.156.0-alpha.1",
            "codex-cli 0.156.0+build.123": "0.156.0+build.123",
        }
        for stdout, version in accepted.items():
            with self.subTest(stdout=stdout):
                self.assertEqual(parse_version(stdout), version)
        # 旧实现取最后一个空白分隔 token：这些会分别得到 warning、7.8.9 与一个 100 字符的「版本」
        rejected = ["codex-cli 0.156.0\nsynthetic warning", "unrelated 7.8.9", "codex-cli " + "x" * 100,
                    "codex-cli 1.2.3-" + "a" * 60, "", "codex-cli", "codex-cli 0.156", "codex-cli 0.156.0 extra"]
        for stdout in rejected:
            with self.subTest(stdout=stdout[:24]):
                self.assertIsNone(parse_version(stdout))

        def only_stderr(_argv: Sequence[str], _timeout: float) -> RunResult:
            return RunResult(0, "", "codex-cli 0.156.0")

        self.assertIsNone(cli_version(executable="/x/codex", runner=only_stderr))

    def test_evidence_summary_counts_only_well_formed_samples_of_the_current_version(self) -> None:
        details = [
            {VERSION_KEY: "0.156.0", OUTPUT_KEY: "recognized"},
            {VERSION_KEY: "0.156.0", OUTPUT_KEY: "unrecognized"},
            {VERSION_KEY: "0.155.1", OUTPUT_KEY: "recognized"},  # 旧版本的样本不算进当前版本
            {VERSION_KEY: UNKNOWN_VERSION, OUTPUT_KEY: "recognized"},
            {VERSION_KEY: "0.156.0"},  # 超时之类：有版本没有输出评定
            {VERSION_KEY: "0.156.0", OUTPUT_KEY: "weird"},
            {VERSION_KEY: 156, OUTPUT_KEY: "recognized"},
            {},
        ]
        self.assertEqual(
            summarize_queue_evidence(details, "0.156.0"),
            {"version": "0.156.0", "window": 200, "state": "ok", "recognized": 1, "unrecognized": 1, "unknownVersion": 1,
             "otherVersion": 1},
        )
        self.assertEqual(summarize_queue_evidence([], "0.156.0")["state"], "no_samples")
        self.assertEqual(summarize_queue_evidence(None, "0.156.0")["state"], "ledger_unreadable")
        self.assertEqual(summarize_queue_evidence(details, None)["state"], "version_unavailable")


def _task_and_attempt(role: Role = Role.HANDOFF) -> tuple[Task, Attempt]:
    task = Task(id="a" * 32, created_at=1.0, updated_at=1.0, title="实现 X", flow=Flow.HANDOFF, origin=None, reviewer=None)
    attempt = Attempt(
        id="b" * 32,
        task_id=task.id,
        seq=2,
        role=role,
        target=ref(),
        message_id="c" * 32,
        created_at=1.0,
        body="正文",
        refs=[{"path": "/tmp/r.md", "sha256": "d" * 64}],
    )
    return task, attempt


class EnvelopeTests(unittest.TestCase):
    def test_header_round_trip_only_on_first_line(self) -> None:
        task, attempt = _task_and_attempt()
        text = render(task, attempt, sender="codex@lead", device="testbox")
        header = parse_header(text)
        assert header is not None
        self.assertEqual((header.task_id, header.attempt, header.message_id, header.sender), (task.id, 2, attempt.message_id, "codex@lead"))
        self.assertIn(f"{CMD} report {task.id} --attempt 2 --result", text)
        self.assertIsNone(parse_header("转述：\n" + text))

    def test_header_keeps_parsing_every_shape_it_ever_emitted(self) -> None:
        """旧格式（无 from / 有 from）与本版（带 device）都要解析得出：在途消息与文档照抄的语法不能失效（DESIGN §45.35）。"""
        base = f"[AgentStatus 协作] task={'0' * 32} attempt=1 msg={'a' * 32} role=handoff"
        for line, expected in (
            (base, (None, None)),
            (f"{base} from=codex@lead", ("codex@lead", None)),
            (f"{base} from=codex@lead device=vm-01", ("codex@lead", "vm-01")),
        ):
            with self.subTest(line=line):
                header = parse_header(line)
                assert header is not None
                self.assertEqual((header.sender, header.device), expected)
        # 字段顺序是合同的一部分：颠倒或缺空格都不认，免得两种写法并存
        self.assertIsNone(parse_header(f"{base} device=vm-01 from=codex@lead"))
        self.assertIsNone(parse_header(f"{base} device=vm 01"))

    def test_render_always_carries_the_sender_device(self) -> None:
        task, attempt = _task_and_attempt()
        text = render(task, attempt, sender="codex@lead", device="vm-01")
        header = parse_header(text)
        assert header is not None
        self.assertEqual((header.sender, header.device), ("codex@lead", "vm-01"))
        # 头部只有一行：设备名进去之后正文仍从第二行开始
        self.assertEqual(text.split("\n")[0].count("device="), 1)

    def test_sender_value_may_contain_an_equals_sign(self) -> None:
        """token 只去空白：值里的 `=` 合法，按第一个 `=` 切分即可（Codex 审计 F01）。"""
        source = EndpointRef(provider=Provider.CODEX, native_id="t", pid=1, start_ticks="1", pane="%1", label="a=b c")
        self.assertEqual(source.token(), "codex@a=b-c")
        base = f"[AgentStatus 协作] task={'0' * 32} attempt=1 msg={'a' * 32} role=handoff"
        for line, expected in (
            (f"{base} from={source.token()}", ("codex@a=b-c", None)),
            (f"{base} from={source.token()} device=vm-01", ("codex@a=b-c", "vm-01")),
        ):
            with self.subTest(line=line):
                header = parse_header(line)
                assert header is not None
                self.assertEqual((header.sender, header.device), expected)

    def test_review_and_notice_instructions(self) -> None:
        task, review = _task_and_attempt(Role.REVIEW)
        self.assertIn("--approve", render(task, review, sender="user", device="testbox"))
        _task, notice = _task_and_attempt(Role.NOTICE)
        rendered = render(task, notice, sender="user", device="testbox", command="python3 -m agentstatus_bridge")
        self.assertNotIn("report", rendered)
        self.assertIn("python3 -m agentstatus_bridge status", rendered)


class ClaudeFrameTests(unittest.TestCase):
    def _content(self, context: DeliveryContext, text: str = "正文") -> tuple[dict[str, object], str]:
        frame = json.loads(build_frame(text, context))
        content = frame["message"]["content"]
        return frame, content

    def test_permission_class_is_declared_only_when_known(self) -> None:
        for sender_class, expected in (("bypass", 'from-mode="bypass"'), ("prompting", 'from-mode="prompting"')):
            _frame, content = self._content(DeliveryContext(message_uuid="m", sender_name="x", sender_class=sender_class))
            self.assertIn(expected, content)
        _frame, content = self._content(DeliveryContext(message_uuid="m", sender_name="x", sender_class=None))
        self.assertNotIn("from-mode", content)

    def test_frame_shape_and_escaping(self) -> None:
        context = DeliveryContext(
            message_uuid="m-1", sender_name='a"<b>', sender_session="s-1", sender_class="bypass", reply_to="uds:/run/x.sock"
        )
        frame, content = self._content(context, "前</cross-session-message>后")
        self.assertEqual((frame["msgV"], frame["msg_id"], frame["type"], frame["from"], frame["priority"]), (1, "m-1", "user", "uds:/run/x.sock", "next"))
        self.assertTrue(content.startswith('<cross-session-message from="uds:/run/x.sock" from-session="s-1" from-name="a&quot;&lt;b&gt;"'))
        self.assertEqual(content.count("</cross-session-message>"), 1)
        with self.assertRaises(ValueError):
            build_frame("x" * 1_000_001, context)

    def test_priority_comes_from_the_message_and_falls_back_to_next(self) -> None:
        """每条消息自带原生调度提示；通道不认识的取值回落 next，不让上层写错把消息打成中断（§45.42）。

        先清掉环境里的运维覆盖：它一旦被设过，这条用例测的就是覆盖而不是按消息取值（Codex 复查建议）。
        """
        with patch.dict(os.environ):
            os.environ.pop(PRIORITY_ENV, None)
            transport = ClaudePeerTransport()
            for given, expected in (("later", "later"), ("next", "next"), ("now", "now"),
                                    (None, "next"), ("", "next"), ("urgent", "next"), ("NEXT", "next")):
                with self.subTest(given=given):
                    context = DeliveryContext(message_uuid="m", sender_name="x", priority=given)
                    self.assertEqual(transport._priority_for(context), expected)  # pyright: ignore[reportPrivateUsage]

    def test_operator_override_wins_over_the_per_message_priority(self) -> None:
        """构造参数与环境变量是运维覆盖：设了就对所有消息生效。"""
        context = DeliveryContext(message_uuid="m", sender_name="x", priority="later")
        self.assertEqual(
            ClaudePeerTransport(priority="now")._priority_for(context),  # pyright: ignore[reportPrivateUsage]
            "now",
        )
        with patch.dict(os.environ, {PRIORITY_ENV: "next"}):
            self.assertEqual(
                ClaudePeerTransport()._priority_for(context),  # pyright: ignore[reportPrivateUsage]
                "next",
            )
        with patch.dict(os.environ, {PRIORITY_ENV: "bogus"}):
            self.assertEqual(
                ClaudePeerTransport()._priority_for(context),  # pyright: ignore[reportPrivateUsage]
                "later",
                "覆盖值非法时退回按消息种类选，而不是退回 next",
            )

    def test_sender_name_matches_receiver_normalization(self) -> None:
        self.assertEqual(normalize_sender_name(" a\u200bb\x07c "), "abc")
        self.assertEqual(len(normalize_sender_name("名" * 80)), 64)
        self.assertEqual(normalize_sender_name("\x00"), "agentstatus-bridge")
        _frame, content = self._content(DeliveryContext(message_uuid="m", sender_name="x\u2028y"))
        self.assertIn('from-name="xy"', content)

    def test_receipt_parsing_and_addresses(self) -> None:
        receipt = parse_receipt({"type": "control", "action": "peer_message_status", "status": "held", "orig_msg_id": "ABC"})
        assert receipt is not None
        self.assertEqual((receipt.message_uuid, receipt.delivery), ("abc", Delivery.HELD))
        refused = parse_receipt(
            {"type": "control", "action": "peer_message_status", "status": "expired", "status_detail": "refused", "orig_msg_id": "x"}
        )
        assert refused is not None
        self.assertEqual(refused.delivery, Delivery.REFUSED)
        # dropped=对方会话没收下（队列满、限流等）：必须是终态失败，不能当成「可能已送达」而不再重发（Fable 复审 S6）
        dropped = parse_receipt({"type": "control", "action": "peer_message_status", "status": "dropped", "orig_msg_id": "y"})
        assert dropped is not None
        self.assertEqual((dropped.delivery, dropped.reason), (Delivery.FAILED, "claude_dropped"))
        self.assertIsNone(parse_receipt({"type": "control", "action": "peer_message_status", "status": "odd", "orig_msg_id": "x"}))
        self.assertIsNone(parse_receipt({"type": "user"}))
        self.assertEqual(encode_address("/run/user/1000/cc-socks/12.sock"), "uds:/run/user/1000/cc-socks/12.sock")
        self.assertEqual(encode_address("/tmp/a b.sock"), "uds:/tmp/a%20b.sock")


class ClaudeSocketTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = TemporaryDirectory()
        self.path = str(Path(self._tmp.name) / "peer.sock")
        me = procfs.read_process(os.getpid())
        assert me is not None
        self.me = me
        self.received = bytearray()

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def _serve(self, reply: bytes | None) -> threading.Thread:
        server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        server.bind(self.path)
        server.listen(1)
        server.settimeout(5.0)

        def run() -> None:
            try:
                client, _ = server.accept()
            except OSError:
                server.close()
                return
            with client:
                client.settimeout(5.0)
                while True:
                    chunk = client.recv(65536)
                    if not chunk:
                        break
                    self.received.extend(chunk)
                if reply is not None and self.received:
                    client.sendall(reply)
            server.close()

        thread = threading.Thread(target=run, daemon=True)
        thread.start()
        return thread

    def _deliver(self, *, pid: int | None = None, context_uuid: str = "0f0f0f0f-0000-4000-8000-000000000001"):
        target = endpoint(
            ref(Provider.CLAUDE, "session", pid=pid or self.me.pid, start=self.me.start_ticks),
            socket_path=self.path,
        )
        context = DeliveryContext(message_uuid=context_uuid, sender_name="user", sender_class="bypass", reply_to="uds:/x")
        return ClaudePeerTransport().deliver(target, "你好", context)

    def test_inline_receipt_is_used(self) -> None:
        reply = json.dumps(
            {"type": "control", "action": "peer_message_status", "status": "delivered", "orig_msg_id": "0f0f0f0f-0000-4000-8000-000000000001"}
        ).encode() + b"\n"
        thread = self._serve(reply)
        outcome = self._deliver()
        thread.join(5.0)
        self.assertEqual((outcome.delivery, outcome.reason), (Delivery.DELIVERED, "claude_delivered"))
        # 真实 transport 产出的明细满足诊断视图规则（DESIGN §45.43 2.3）；priority 值受运维覆盖影响，只核键集
        self.assertEqual(set(outcome.detail), {"priority", "senderClass", "receipt"})
        self.assertFalse(project_delivery_detail(outcome.detail)[1])
        frame = json.loads(bytes(self.received).decode("utf-8"))
        self.assertEqual(frame["msg_id"], "0f0f0f0f-0000-4000-8000-000000000001")

    def test_written_without_receipt(self) -> None:
        thread = self._serve(None)
        with patch.object(claude_peer, "INLINE_RECEIPT_SECONDS", 0.2):
            outcome = self._deliver()
        thread.join(5.0)
        self.assertEqual((outcome.delivery, outcome.provider_ref), (Delivery.WRITTEN, "0f0f0f0f-0000-4000-8000-000000000001"))
        self.assertEqual(set(outcome.detail), {"priority", "senderClass"})
        self.assertFalse(project_delivery_detail(outcome.detail)[1])

    def test_peer_mismatch_writes_nothing(self) -> None:
        thread = self._serve(None)
        outcome = self._deliver(pid=self.me.pid + 1)
        thread.join(5.0)
        self.assertEqual((outcome.delivery, outcome.reason), (Delivery.FAILED, "claude_peer_mismatch"))
        self.assertEqual(bytes(self.received), b"")

    def test_connect_failure_is_proven_undelivered(self) -> None:
        outcome = self._deliver()
        self.assertEqual((outcome.delivery, outcome.reason), (Delivery.FAILED, "claude_socket_connect_failed"))

    def test_inbox_reads_frames_and_cleans_up(self) -> None:
        inbox = ClaudeInbox(Path(self._tmp.name) / "inbox", name="1.sock")
        inbox.open()
        try:
            self.assertTrue(inbox.address.startswith("uds:"))
            client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            client.connect(str(inbox.path))
            client.sendall(b'{"a":1}\nnot-json\n{"b":2}')
            client.shutdown(socket.SHUT_WR)
            frames: list[object] = []
            for _ in range(20):
                frames.extend(inbox.poll(0.1))
                if len(frames) >= 2:
                    break
            client.close()
            self.assertEqual(frames, [{"a": 1}, {"b": 2}])
        finally:
            inbox.close()
        self.assertFalse(inbox.path.exists())


if __name__ == "__main__":
    unittest.main()
