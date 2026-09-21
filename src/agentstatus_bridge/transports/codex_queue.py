"""Codex 原生 thread 队列：调用 `codex queue`，并按固定版本的已知文案给出可读失败原因。

依据 codex-cli 0.154.0（rust-v0.154.0 源码）：成功时 stdout 为
`Queued message <queue item id> for thread <thread id>.`；运行期错误一律 exit 1，
stderr 为 `Error: ...` 错误链。只有在插入队列之前就失败的已知文案才判为 FAILED
（可证明未入队）；存储/传输错误、超时、无法解析的输出都判为 UNKNOWN，不自动重发。
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import dataclass
import os
from pathlib import Path
import re
import shutil
import sqlite3
import subprocess

from ..model import Consumption, Delivery, Endpoint, Provider
from ..paths import codex_home
from . import DeliveryContext, DeliveryOutcome

VERIFIED_VERSION_PREFIX = "0.154."
QUEUE_TIMEOUT_SECONDS = 60.0
# Linux 单个 argv 字符串上限为 128 KiB；留余量，超过则可证明未外调
MAX_ARGV_MESSAGE_BYTES = 120 * 1024

_QUEUED = re.compile(
    r"Queued message (?P<item>[0-9a-fA-F-]{36}) for thread (?P<thread>[0-9a-fA-F-]{36})\."
)

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
    return Delivery.UNKNOWN, "codex_queue_unrecognized_error"


class CodexQueueTransport:
    """经 `codex queue --thread UUID --message TEXT` 投递。"""

    provider = Provider.CODEX

    def __init__(self, *, executable: str | None = None, runner: Runner | None = None) -> None:
        self._executable = executable
        self._runner = runner or _default_runner

    def _resolve_executable(self) -> str | None:
        return self._executable or shutil.which("codex")

    def deliver(self, endpoint: Endpoint, text: str, context: DeliveryContext) -> DeliveryOutcome:
        del context  # Codex 队列不携带发送方元数据
        if len(text.encode("utf-8")) > MAX_ARGV_MESSAGE_BYTES:
            return DeliveryOutcome(Delivery.FAILED, "message_too_large_for_argv")
        executable = self._resolve_executable()
        if executable is None:
            return DeliveryOutcome(Delivery.FAILED, "codex_cli_missing")
        thread = endpoint.ref.native_id
        argv = [executable, "queue", "--thread", thread, "--message", text]
        try:
            result = self._runner(argv, QUEUE_TIMEOUT_SECONDS)
        except subprocess.TimeoutExpired:
            return DeliveryOutcome(Delivery.UNKNOWN, "codex_queue_timeout")
        except OSError:
            # 启动进程失败发生在任何写入之前
            return DeliveryOutcome(Delivery.FAILED, "codex_cli_missing")
        if result.returncode == 2:
            # clap 参数错误在任何请求之前退出
            return DeliveryOutcome(Delivery.FAILED, "codex_cli_usage_error", detail={"exitCode": 2})
        if result.returncode != 0:
            delivery, reason = classify_failure(result.stderr)
            return DeliveryOutcome(delivery, reason, detail={"exitCode": result.returncode})
        match = _QUEUED.search(result.stdout)
        if match is None or match.group("thread").lower() != thread.lower():
            return DeliveryOutcome(Delivery.UNKNOWN, "codex_queue_unparsed_output")
        return DeliveryOutcome(Delivery.QUEUED, "codex_queued", provider_ref=match.group("item").lower())


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


def cli_version(*, executable: str | None = None, runner: Runner | None = None) -> str | None:
    """读取 `codex --version`（纯元数据命令）。"""
    binary = executable or shutil.which("codex")
    if binary is None:
        return None
    try:
        result = (runner or _default_runner)([binary, "--version"], 10.0)
    except (OSError, subprocess.TimeoutExpired):
        return None
    if result.returncode != 0:
        return None
    parts = result.stdout.strip().split()
    return parts[-1] if parts else None
