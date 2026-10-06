"""Codex 原生 thread 队列：先经托管 daemon 的 `thread/queue/add`（`codex_rpc`，DESIGN §61），add 帧发出之前失败时
回退 `codex queue` CLI；按已知文案给出可读失败原因，并为每次外调留下通道、版本与输出证据。

两个通道的边界：RPC 在 add 帧开始发送之前的失败可证明未入队，原样回退 CLI，证据记 `rpcFallback`；之后只按 RPC
结果记，绝不换通道重投。下面关于 CLI 输出分类的说明只适用于 CLI 通道。

CLI 通道分类规则的依据是源码审查（DESIGN §45.44 第三节初版为 0.156.0 / `fe74a774`，§53.1 按 0.160.0 复核；RPC 通道的
错误表依据 0.160.0 / `a956835d`，见 `codex_rpc`）：成功时 stdout 为
`Queued message <queue item id> for thread <thread id>.`；运行期错误一律 exit 1，stderr 为 `Error: ...`
错误链。只有在插入队列之前就失败的已知文案才判为 FAILED（可证明未入队）；存储/传输错误、超时、
无法解析的输出都判为 UNKNOWN，不自动重发。分类是「已知子串优先」：一条新错误若恰好包含已知拒收子串
仍会命中 FAILED，所以这里不宣称对未来的错误 fail-safe。

`ab doctor` 只统计已见样本（`codexVersion` / `queueOutput` / `queueChannel` / `rpcFallback` 四个键），不替代源码
审查。这些键是本模块与 doctor 的仓内约定（DESIGN §45.44 四、§61.2 第 7 条）：写方是 `CodexQueueTransport.deliver`，
读方是 `summarize_queue_evidence` 与 `summarize_rpc_evidence`，改名或删除须两处同改。没有 `queueChannel` 的旧样本
都是 CLI 通道的。
"""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, replace
import os
from pathlib import Path
import re
import shutil
import sqlite3
import subprocess

from ..model import Consumption, Delivery, Endpoint, Provider
from ..paths import codex_home
from . import DeliveryContext, DeliveryOutcome, codex_rpc

QUEUE_TIMEOUT_SECONDS = 60.0
# 投递后查版本的超时：它在 finish_send 之前，缓存未命中时本条落账与 worker 发下一条最多因此晚这么久
VERSION_TIMEOUT_SECONDS = 3.0
# Linux 单个 argv 字符串上限为 128 KiB；留余量，超过则可证明未外调
MAX_ARGV_MESSAGE_BYTES = 120 * 1024

_QUEUED = re.compile(
    r"Queued message (?P<item>[0-9a-fA-F-]{36}) for thread (?P<thread>[0-9a-fA-F-]{36})\."
)

# 投递证据（DESIGN §45.44 二.2）：本模块写、summarize_queue_evidence 读
VERSION_KEY = "codexVersion"
OUTPUT_KEY = "queueOutput"
# 通道与回退原因（DESIGN §61.2 第 7 条）：RPC 通道的 codexVersion 是服务端版本，CLI 通道的是 CLI 版本
CHANNEL_KEY = "queueChannel"
FALLBACK_KEY = "rpcFallback"
CHANNEL_RPC = "rpc"
CHANNEL_CLI = "cli"
FALLBACK_VERSION_UNAVAILABLE = "version_unavailable"
UNKNOWN_VERSION = "unknown"
OUTPUT_RECOGNIZED = "recognized"
OUTPUT_UNRECOGNIZED = "unrecognized"
EVIDENCE_WINDOW = 200

# `codex --version` 的整行形状：Clap package version，允许预发布与构建后缀；不截断、不从别的输出里抠
_VERSION_LINE = re.compile(rf"codex-cli (?P<version>{codex_rpc.VERSION_PATTERN})")
_MAX_VERSION_LENGTH = 64
_UNRECOGNIZED_ERROR = "codex_queue_unrecognized_error"

# (stderr 子串, 原因码)：均发生在写入队列之前
_KNOWN_REJECTIONS: tuple[tuple[str, str], ...] = (
    ("thread not found:", "codex_thread_not_found"),
    ("No active session found matching", "codex_thread_not_found"),
    ("Multiple sessions match", "codex_thread_ambiguous"),
    ("Cannot verify a unique session label", "codex_thread_ambiguous"),
    ("is archived. Run `codex unarchive", "codex_thread_archived"),
    ("ephemeral thread does not support queued submissions", "codex_thread_ephemeral"),
    ("not allowed for unloaded spawned sub-agents", "codex_subagent_unloaded"),
    ("queue cannot contain more than 100 submissions", "provider_queue_full"),
    ("Input exceeds the maximum length", "provider_payload_too_large"),
    ("user message queue is unavailable", "codex_queue_unavailable"),
    ("while a local app-server daemon is running", "codex_daemon_conflict"),
    ("does not support thread/queue/add", "codex_version_unsupported"),
    ("failed to initialize state database", "codex_state_unavailable"),
    ("invalid thread id", "codex_thread_invalid"),
    ("direct app-server input is not allowed for multi-agent v2 sub-agents", "codex_subagent_unsupported"),
    ("failed to find Codex home", "codex_home_unavailable"),
    ("failed to discover execution environments", "codex_startup_error"),
    ("failed to parse -c overrides", "codex_config_invalid"),
)

# 可能已经写入的错误：结果不明
_UNCERTAIN_ERRORS: tuple[tuple[str, str], ...] = (
    ("queued submission operation failed", "codex_queue_storage_error"),
    ("thread/queue/add transport error", "codex_transport_error"),
)

READABLE_REASONS: dict[str, str] = {
    "codex_thread_not_found": "Codex 找不到这个会话（可能已换新会话）",
    "codex_thread_ambiguous": "Codex 会话名不唯一",
    "codex_thread_archived": "Codex 会话已归档",
    "codex_thread_ephemeral": "临时 Codex 会话不支持排队消息",
    "codex_subagent_unloaded": "未加载的 Codex 子代理不接受排队消息",
    "provider_queue_full": "Codex 会话队列已满（100 条）",
    "provider_payload_too_large": "消息超过 Codex 长度上限",
    "codex_queue_unavailable": "Codex 队列功能不可用",
    "codex_daemon_conflict": "本机 Codex app-server daemon 与排队方式冲突",
    "codex_version_unsupported": "Codex 版本不支持排队消息",
    "codex_state_unavailable": "Codex 状态库无法打开",
    "codex_thread_invalid": "Codex 会话 ID 无效",
    "codex_subagent_unsupported": "该 Codex 子代理不接受外部输入",
    "codex_home_unavailable": "找不到 Codex 数据目录",
    "codex_startup_error": "Codex 排队命令启动失败，未入队",
    "codex_config_invalid": "Codex 配置覆盖无法解析，未入队",
    "codex_cli_usage_error": "Codex 排队命令参数错误，未入队",
    "codex_cli_missing": "找不到 codex 命令",
    "message_too_large_for_argv": "消息过长，请改用文件引用",
    "codex_queue_storage_error": "Codex 队列写入出错，是否已入队不明",
    "codex_transport_error": "与 Codex 通信出错，是否已入队不明",
    "codex_queue_timeout": "Codex 排队命令超时，是否已入队不明",
    "codex_queue_unrecognized_error": "Codex 返回未识别的错误，是否已入队不明",
    "codex_queue_unparsed_output": "Codex 输出无法识别，是否已入队不明",
    # RPC 通道新增的写前原因（DESIGN §61.2 第 6 条）
    "codex_server_overloaded": "Codex 服务繁忙，未入队，可以直接重发",
    "codex_thread_unreadable": "Codex 读不到这个会话，未入队",
    "codex_rpc_protocol_error": "协作桥发给 Codex 的请求形状或顺序有误，未入队",
}


@dataclass(frozen=True)
class RunResult:
    returncode: int
    stdout: str
    stderr: str


Runner = Callable[[Sequence[str], float], RunResult]


def _default_runner(argv: Sequence[str], timeout: float) -> RunResult:
    completed = subprocess.run(
        list(argv),
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        errors="replace",
        timeout=timeout,
        check=False,
    )
    return RunResult(completed.returncode, completed.stdout[-4096:], completed.stderr[-4096:])


def classify_failure(stderr: str) -> tuple[Delivery, str]:
    """把非零退出的 stderr 映射为 (状态, 原因码)；未识别即 UNKNOWN。"""
    for needle, reason in _KNOWN_REJECTIONS:
        if needle in stderr:
            return Delivery.FAILED, reason
    for needle, reason in _UNCERTAIN_ERRORS:
        if needle in stderr:
            return Delivery.UNKNOWN, reason
    return Delivery.UNKNOWN, _UNRECOGNIZED_ERROR


RpcCall = Callable[..., "codex_rpc.RpcFallback | codex_rpc.RpcResult"]


class CodexQueueTransport:
    """先经 daemon 的 `thread/queue/add` 投递，add 帧发出之前失败时经 `codex queue --thread UUID --message TEXT`。"""

    provider = Provider.CODEX

    def __init__(
        self, *, executable: str | None = None, runner: Runner | None = None, rpc: RpcCall | None = None
    ) -> None:
        self._executable = executable
        self._runner = runner or _default_runner
        self._rpc: RpcCall = rpc or codex_rpc.queue_add
        # 只缓存成功值；键是（release 真实路径, mtime）。worker 单进程单线程，挂在实例上即可
        self._version_cache: tuple[tuple[str, int], str] | None = None

    def _resolve_executable(self) -> str | None:
        return self._executable or shutil.which("codex")

    def deliver(self, endpoint: Endpoint, text: str, context: DeliveryContext) -> DeliveryOutcome:
        attempt = self._deliver_rpc(endpoint.ref.native_id, text, context.message_uuid)
        if isinstance(attempt, DeliveryOutcome):
            return attempt
        outcome = self._deliver_cli(endpoint, text)
        return replace(outcome, detail={**outcome.detail, CHANNEL_KEY: CHANNEL_CLI, FALLBACK_KEY: attempt})

    def _deliver_rpc(self, thread: str, text: str, client_message_id: str) -> DeliveryOutcome | str:
        """RPC 通道；返回最终结果，或 add 帧发出之前的回退原因（这时可证明未入队）。

        initialize 用本机 CLI 的版本（身份与 `codex queue` 相同）；取不到就不连 socket，不拿假版本去覆盖
        daemon 的 UA 后缀。准备步骤的异常就地按回退处理；`queue_add` 自己不冒泡（见 `codex_rpc` 说明）。
        """
        try:
            executable = self._resolve_executable()
            release = _realpath(executable) if executable is not None else None
            version = self._release_version(release) if release is not None else None
            if version is None:
                return FALLBACK_VERSION_UNAVAILABLE
            link = codex_rpc.control_socket_path(codex_home())
        except Exception:
            return FALLBACK_VERSION_UNAVAILABLE
        result = self._rpc(link, thread_id=thread, text=text, client_message_id=client_message_id,
                           client_version=version)
        if isinstance(result, codex_rpc.RpcFallback):
            return result.reason
        detail: dict[str, object] = {CHANNEL_KEY: CHANNEL_RPC, VERSION_KEY: result.server_version}
        if result.output is not None:
            detail[OUTPUT_KEY] = result.output
        return DeliveryOutcome(result.delivery, result.reason, provider_ref=result.provider_ref, detail=detail)

    def _deliver_cli(self, endpoint: Endpoint, text: str) -> DeliveryOutcome:
        """CLI 通道：与 §61 之前的投递完全相同。"""
        if len(text.encode("utf-8")) > MAX_ARGV_MESSAGE_BYTES:
            return DeliveryOutcome(Delivery.FAILED, "message_too_large_for_argv")
        executable = self._resolve_executable()
        if executable is None:
            return DeliveryOutcome(Delivery.FAILED, "codex_cli_missing")
        thread = endpoint.ref.native_id
        argv = [executable, "queue", "--thread", thread, "--message", text]
        # 外调前先记下入口此刻指向哪个 release：自动升级会在投递期间原子切换 `current` 链接
        before = _realpath(executable)
        try:
            result = self._runner(argv, QUEUE_TIMEOUT_SECONDS)
        except subprocess.TimeoutExpired:
            # 没拿到完整的命令结果：记版本，不评输出（可能有部分 stdout，不据此判断）
            return DeliveryOutcome(
                Delivery.UNKNOWN, "codex_queue_timeout", detail=self._evidence(executable, before, None)
            )
        except OSError:
            # 启动进程失败发生在任何写入之前；根本没有外调，不留证据
            return DeliveryOutcome(Delivery.FAILED, "codex_cli_missing")
        outcome, output = _interpret(result, thread)
        return replace(outcome, detail={**outcome.detail, **self._evidence(executable, before, output)})

    def _evidence(self, executable: str, before: str | None, output: str | None) -> dict[str, object]:
        evidence: dict[str, object] = {VERSION_KEY: self._executed_version(executable, before)}
        if output is not None:
            evidence[OUTPUT_KEY] = output
        return evidence

    def _executed_version(self, executable: str, before: str | None) -> str:
        """执行这次投递的 codex 版本；取不到、或不能确定前后是同一个程序时为 unknown。

        诊断步骤的**任何**异常都在这里就地吞掉：dispatch 会把 transport 冒泡出来的异常改成 UNKNOWN，
        一旦冒泡就会把已经拿到的 QUEUED 覆盖掉（DESIGN §45.44 二.5）。
        """
        try:
            after = os.path.realpath(executable)
            if before is None or after != before:
                # 投递期间入口被切换：不把这次的结果归到任何一个版本
                return UNKNOWN_VERSION
            return self._release_version(before) or UNKNOWN_VERSION
        except Exception:
            return UNKNOWN_VERSION

    def _release_version(self, release: str) -> str | None:
        """这个 release 路径上的 codex 版本，按（路径, mtime）缓存；取不到为 None。"""
        # 用外调前解析出的 release 路径查版本；mtime 是归档时间，只防同一路径被原地覆盖
        key = (release, os.stat(release).st_mtime_ns)
        if self._version_cache is not None and self._version_cache[0] == key:
            return self._version_cache[1]
        version = cli_version(executable=release, runner=self._runner, timeout=VERSION_TIMEOUT_SECONDS)
        if version is None:
            # 失败不缓存：否则首次超时一次，整个 worker 生命周期都会因「程序没变」而永远记 unknown
            return None
        self._version_cache = (key, version)
        return version


def _realpath(path: str) -> str | None:
    try:
        return os.path.realpath(path)
    except Exception:  # 诊断步骤不能影响投递本身
        return None


def _interpret(result: RunResult, thread: str) -> tuple[DeliveryOutcome, str | None]:
    """把一次完整结束的 `codex queue` 映射为投递结局，外加这次输出是否落在已知接口之内。

    `queueOutput` 不等于投递成功：已知拒收（FAILED）、存储/传输错误与 thread 不符（UNKNOWN）都算 recognized。
    """
    code = result.returncode
    if code < 0:
        # 被信号终止：进程没有正常结束，没有结果可评，不写 queueOutput
        delivery, reason = classify_failure(result.stderr)
        return DeliveryOutcome(delivery, reason, detail={"exitCode": code}), None
    if code == 2:
        # clap 参数错误在任何请求之前退出。我们的 argv 是固定的，被拒只可能是上游改了接口，
        # 所以记 unrecognized——否则上游改掉 `--thread` 后每次投递都失败，doctor 却报「未识别 0 次」
        return (
            DeliveryOutcome(Delivery.FAILED, "codex_cli_usage_error", detail={"exitCode": 2}),
            OUTPUT_UNRECOGNIZED,
        )
    if code != 0:
        delivery, reason = classify_failure(result.stderr)
        output = OUTPUT_UNRECOGNIZED if reason == _UNRECOGNIZED_ERROR else OUTPUT_RECOGNIZED
        return DeliveryOutcome(delivery, reason, detail={"exitCode": code}), output
    match = _QUEUED.search(result.stdout)
    if match is None:
        return DeliveryOutcome(Delivery.UNKNOWN, "codex_queue_unparsed_output"), OUTPUT_UNRECOGNIZED
    if match.group("thread").lower() != thread.lower():
        # 格式认得、语义不符：原因码仍与「格式不认得」共用，只在 queueOutput 上区分
        return DeliveryOutcome(Delivery.UNKNOWN, "codex_queue_unparsed_output"), OUTPUT_RECOGNIZED
    return (
        DeliveryOutcome(Delivery.QUEUED, "codex_queued", provider_ref=match.group("item").lower()),
        OUTPUT_RECOGNIZED,
    )


def queue_database_path() -> Path:
    """Codex 队列库位置：`CODEX_SQLITE_HOME` 优先，否则 `CODEX_HOME`。"""
    configured = os.environ.get("CODEX_SQLITE_HOME")
    base = Path(configured).expanduser() if configured else codex_home()
    return base / "queue_1.sqlite"


def queue_item_state(item_id: str, *, database: Path | None = None) -> Consumption:
    """只读查询队列项是否仍在（不读取 payload 列）；查询失败返回 UNKNOWN。"""
    path = database or queue_database_path()
    if not path.exists():
        return Consumption.UNKNOWN
    try:
        connection = sqlite3.connect(f"file:{path}?mode=ro", uri=True, timeout=1.0)
    except sqlite3.Error:
        return Consumption.UNKNOWN
    try:
        row = connection.execute("SELECT COUNT(*) FROM queued_items WHERE id = ?", (item_id,)).fetchone()
    except sqlite3.Error:
        return Consumption.UNKNOWN
    finally:
        connection.close()
    if row is None:
        return Consumption.UNKNOWN
    return Consumption.STILL_QUEUED if int(row[0]) > 0 else Consumption.LEFT_QUEUE


def cli_version(
    *, executable: str | None = None, runner: Runner | None = None, timeout: float = 10.0
) -> str | None:
    """读取 `codex --version`（纯元数据命令），只接受整行恰为 `codex-cli <版本>` 的输出。"""
    binary = executable or shutil.which("codex")
    if binary is None:
        return None
    try:
        result = (runner or _default_runner)([binary, "--version"], timeout)
    except (OSError, subprocess.TimeoutExpired):
        return None
    if result.returncode != 0:
        return None
    return parse_version(result.stdout)


def parse_version(stdout: str) -> str | None:
    """严格验形：多行、额外输出、其他前缀、超长一律 None，绝不截断冒充一个版本（DESIGN §45.44 二.4）。"""
    match = _VERSION_LINE.fullmatch(stdout.strip())
    if match is None:
        return None
    version = match.group("version")
    return version if len(version) <= _MAX_VERSION_LENGTH else None


def summarize_queue_evidence(
    details: Sequence[Mapping[str, object]] | None, version: str | None
) -> dict[str, object]:
    """doctor 用：把最近最多 EVIDENCE_WINDOW 条 Codex 尝试的 delivery_detail 汇成计数（DESIGN §45.44 二.6）。

    `details` 为 None 表示账本读取失败——**不伪装成零样本**。只有 `queueOutput` 取合法枚举、
    `codexVersion` 是字符串的记录才算样本；缺失、未知枚举都不解释成成功或失败。
    """
    evidence: dict[str, object] = {"version": version, "window": EVIDENCE_WINDOW}
    if version is None:
        return {**evidence, "state": "version_unavailable"}
    if details is None:
        return {**evidence, "state": "ledger_unreadable"}
    recognized = unrecognized = unknown_version = other_version = 0
    for detail in details:
        if detail.get(CHANNEL_KEY, CHANNEL_CLI) != CHANNEL_CLI:
            # 只数 CLI 通道：RPC 样本记的是服务端版本，与当前 CLI 版本比对没有意义（DESIGN §61.2 第 7 条）
            continue
        output = detail.get(OUTPUT_KEY)
        seen = detail.get(VERSION_KEY)
        if output not in (OUTPUT_RECOGNIZED, OUTPUT_UNRECOGNIZED) or not isinstance(seen, str):
            continue
        if seen == UNKNOWN_VERSION:
            unknown_version += 1
        elif seen != version:
            # 记在别的版本下：自动升级后的常态，窗口里多半全是升级前的样本（Fable 实现复核 P3-1）
            other_version += 1
        elif output == OUTPUT_RECOGNIZED:
            recognized += 1
        else:
            unrecognized += 1
    return {
        **evidence,
        "state": "ok" if recognized or unrecognized else "no_samples",
        "recognized": recognized,
        "unrecognized": unrecognized,
        "unknownVersion": unknown_version,
        "otherVersion": other_version,
    }


def summarize_rpc_evidence(details: Sequence[Mapping[str, object]] | None) -> dict[str, object]:
    """doctor 用：RPC 通道样本与回退次数（DESIGN §61.2 第 7 条）。

    参照版本取窗口内**最近一条能解析出服务端版本**的 RPC 样本（`unknown` 跳过、单独计数）——这是诊断，不证明
    daemon 此刻的版本。回退按
    `rpcFallback` 计次并给出最常见的原因；`details` 为 None 表示账本读取失败，不伪装成零样本。
    """
    evidence: dict[str, object] = {"window": EVIDENCE_WINDOW}
    if details is None:
        return {**evidence, "state": "ledger_unreadable"}
    samples = [
        detail for detail in details
        if detail.get(CHANNEL_KEY) == CHANNEL_RPC
        and detail.get(OUTPUT_KEY) in (OUTPUT_RECOGNIZED, OUTPUT_UNRECOGNIZED)
        and isinstance(detail.get(VERSION_KEY), str)
    ]
    fallbacks: dict[str, int] = {}
    for detail in details:
        reason = detail.get(FALLBACK_KEY)
        if detail.get(CHANNEL_KEY) == CHANNEL_CLI and isinstance(reason, str):
            fallbacks[reason] = fallbacks.get(reason, 0) + 1
    evidence["fallbacks"] = sum(fallbacks.values())
    if fallbacks:
        # 次数相同时按原因码排序取第一个，输出稳定
        evidence["topFallback"] = min(fallbacks, key=lambda reason: (-fallbacks[reason], reason))
    reference = next((str(detail[VERSION_KEY]) for detail in samples if detail[VERSION_KEY] != UNKNOWN_VERSION), None)
    evidence["version"] = reference
    recognized = unrecognized = unknown_version = other_version = 0
    for detail in samples:
        seen = detail[VERSION_KEY]
        if seen == UNKNOWN_VERSION:
            unknown_version += 1
        elif seen != reference:
            other_version += 1
        elif detail[OUTPUT_KEY] == OUTPUT_RECOGNIZED:
            recognized += 1
        else:
            unrecognized += 1
    return {
        **evidence,
        "state": "ok" if recognized or unrecognized else "no_samples",
        "recognized": recognized,
        "unrecognized": unrecognized,
        "unknownVersion": unknown_version,
        "otherVersion": other_version,
    }
