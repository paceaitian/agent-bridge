"""按需 worker：持有 Claude 回执收件箱，分发桥内排队的消息，没有待办一段时间后退出。

同一账本目录只有一个 worker（flock）；`ab send/report/resume/retry`、其他命令结束时的补查与扩展定时的
`ab summary --if-stale` 在需要时拉起它。worker 不启动、不恢复任何模型会话，只处理用户已交给桥的消息（DESIGN §45.6）。
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
import json
import os
from pathlib import Path
import time
from types import FrameType

from .platforms.factory import get_platform
from . import summary
from .dispatch import Dispatcher, LogFn
from .codex_metadata import MetadataCache
from .endpoints import ADAPTERS, DiscoverySources, discover
from .model import Endpoint, Provider
from .naming import COMMAND_ENV, command_name
from .paths import ensure_private_dir, state_dir
from .platforms.path_values import STATE_DIR_ENV
from .store import Store, StoreError
from .transports import Transport
from .transports.claude_peer import ClaudeInbox, ClaudePeerTransport
from .transports.codex_queue import CodexQueueTransport

LOCK_NAME = "worker.lock"
LOG_NAME = "worker.log"
LOOP_SECONDS = 1.0
IDLE_EXIT_SECONDS = 120.0
MAX_CONSECUTIVE_FAILURES = 30
MAX_LOG_BYTES = 256 * 1024



class WorkerLog:
    """无正文的 worker 日志：时间、事件名与固定字段（短 ID、原因码、计数、异常类名），有界轮转。"""

    def __init__(self, path: Path) -> None:
        self.path = path

    def __call__(self, event: str, fields: Mapping[str, object]) -> None:
        line = json.dumps(
            {"at": round(time.time(), 3), "pid": os.getpid(), "event": event, **fields},
            ensure_ascii=False,
            sort_keys=True,
            default=str,
        )
        try:
            get_platform().files.append_log(self.path, (line + "\n").encode("utf-8"), MAX_LOG_BYTES)
        except OSError:
            pass  # 日志失败不能影响投递


def read_log_tail(root: Path | None = None, *, lines: int = 5) -> list[str]:
    """读取 worker 日志最后几行（供 ab doctor 显示）。"""
    path = (root or state_dir()) / LOG_NAME
    try:
        data = path.read_bytes()[-16384:]
    except OSError:
        return []
    return data.decode("utf-8", errors="replace").splitlines()[-lines:]


def _lock_path(root: Path) -> Path:
    return ensure_private_dir(root) / LOCK_NAME


def worker_running(root: Path | None = None) -> bool:
    """探测 worker 锁是否被占用（只瞬时持锁）。

    用共享锁探测：worker 持排他锁时拿不到，判为在运行；多个探测同时发生互不冲突，不会把彼此误判成 worker。
    探测与新 worker 取锁撞在同一刻时，由 worker 取锁重试消化（_acquire_worker_lock，DESIGN §45.30.6）。
    """
    path = _lock_path(root or state_dir())
    lifecycle = get_platform().lifecycle
    fd = lifecycle.open_lock(path)
    try:
        lifecycle.try_lock(fd, shared=True)
    except BlockingIOError:
        if get_platform().name == 'windows':
            from .platforms.windows.worker_identity import verify  # layout: allow Windows锁还须验证其属主代际/镜像
            from .platforms.windows.files import WindowsPaths  # layout: allow 仅Windows窄原语
            files = get_platform().files
            if not isinstance(files, WindowsPaths):
                raise OSError('worker_identity_unverified')
            verify(files, path.parent)
        return True
    else:
        lifecycle.unlock(fd)
        return False
    finally:
        lifecycle.close_lock(fd)


def wait_for_worker(root: Path | None = None, *, timeout: float = 2.0) -> bool:
    """等待新拉起的 worker 拿到单实例锁；刚 Popen 时锁尚未持有，不能据此判定未运行。"""
    directory = root or state_dir()
    deadline = time.monotonic() + timeout
    while True:
        if worker_running(directory):
            return True
        if time.monotonic() >= deadline:
            return False
        time.sleep(0.05)



def ensure_worker(root: Path | None = None) -> bool:
    """确保后台 worker 在运行；需要时以独立会话拉起，返回是否新启动。"""
    directory = root or state_dir()
    if worker_running(directory):
        return False
    env = get_platform().lifecycle.worker_environment(os.environ)
    env[STATE_DIR_ENV] = str(directory)
    # worker 由 `python -m` 拉起，argv0 是解释器：把调用方解析出的命令名显式传下去，
    # 否则页脚会退回默认名而不是用户实际敲的那个（DESIGN §45.36）
    env[COMMAND_ENV] = command_name()
    get_platform().lifecycle.spawn_worker(directory, env)
    return True


def default_transports() -> dict[Provider, Transport]:
    """各 provider 的投递通道；只读 provider（适配器 inbox=False）不在其中（DESIGN §45.34）。"""
    if get_platform().name == 'windows':
        from .platforms.windows.codex_delivery import CodexTransport  # layout: allow Windows只有RPC Codex，无Claude listener
        return {Provider.CODEX: CodexTransport()}
    transports: dict[Provider, Transport] = {
        Provider.CODEX: CodexQueueTransport(),
        Provider.CLAUDE: ClaudePeerTransport(),
    }
    return {provider: transport for provider, transport in transports.items() if ADAPTERS[provider].inbox}


def _open_inbox(directory: Path | None) -> ClaudeInbox | None:
    inbox = ClaudeInbox(directory)
    try:
        inbox.open()
    except OSError:
        inbox.close()
        return None  # 无法接收 Claude 回执：Claude 消息留在桥内排队，Codex 照常
    return inbox


def _publish_summary(store: Store, directory: Path, log: LogFn, *, force: bool) -> summary.PublishResult | None:
    """发布摘要并返回实际发布的快照；失败只记原因码并返回 None，由主循环保持驻留重试（DESIGN §45.14）。"""
    try:
        result = summary.publish(store, directory, force=force)
    except Exception as error:  # 摘要失败不能拖垮 worker 启动或投递循环
        log("summary_write_failed", {"code": getattr(error, "code", type(error).__name__)})
        return None
    if result.status == "written":
        log("summary_published", {"revision": result.revision})
    return result


def run_worker(
    *,
    root: Path | None = None,
    once: bool = False,
    inbox_directory: Path | None = None,
    discover_fn: Callable[[], list[Endpoint]] | None = None,
    transports: Mapping[Provider, Transport] | None = None,
    loop_seconds: float = LOOP_SECONDS,
) -> int:
    """worker 主循环；已有 worker 时立即返回 0。账本打不开时抛 StoreError，且不留下收件箱。

    单轮异常只记日志并退避重试，连续失败过多才退出，不让排队静默停摆（DESIGN §45.6）。
    """
    platform = get_platform()
    lifecycle = platform.lifecycle
    directory = root or state_dir()
    lock_fd = lifecycle.open_lock(_lock_path(directory))
    if not lifecycle.acquire_worker_lock(lock_fd):
        lifecycle.close_lock(lock_fd)
        return 0
    stopping = False

    def _stop(_signum: int, _frame: FrameType | None) -> None:
        nonlocal stopping
        stopping = True

    previous = lifecycle.install_stop(_stop)
    log = WorkerLog(directory / LOG_NAME)
    try:
        if platform.name == 'windows':
            from .platforms.windows.worker_identity import register  # layout: allow 持锁后发布本代启动回执
            from .platforms.windows.files import WindowsPaths  # layout: allow 私有回执只用已选择的F
            if not isinstance(platform.files, WindowsPaths):
                raise OSError('worker_identity_unverified')
            register(platform.files, directory)
        # 先开账本再绑收件箱：账本失败时不在 Claude socket 目录留下残留
        try:
            opened = Store.open(directory)
        except StoreError as error:
            log("store_error", {"code": error.code})
            raise
        with opened as store:
            inbox = None if platform.name == 'windows' else _open_inbox(inbox_directory)
            try:
                pruned = store.prune(now=time.time())
            except StoreError as error:
                pruned = 0
                log("prune_error", {"code": error.code})
            log("start", {"inbox": inbox is not None, "pruned": pruned})
            # 启动时无条件重建：修复损坏、不兼容或上次进程提交后未发布的摘要
            started = _publish_summary(store, directory, log, force=True)
            summary_pending = started is None
            # 水位取实际发布的快照：发布之后才提交的修订不能记作已发布（3A-F03）
            summary_seen = None if started is None else (started.ledger_id, started.revision)
            summary_failures = 1 if summary_pending else 0
            sources = None if platform.name == 'windows' else DiscoverySources(native_metadata=MetadataCache())
            attempt_queue_state = None
            empty_complete = None
            selected_discover = discover_fn
            pending_backoff = None
            if platform.name == 'windows':
                from .platforms.windows.pending_backoff import PendingBackoff  # layout: allow Windows待投递独立退避
                pending_backoff = PendingBackoff()
                from .platforms.windows.codex_consumption import state  # layout: allow Windows存在性必须同成功投递根
                from .platforms.windows.codex_discovery import WorkerDiscovery  # layout: allow 完整空集合不是发现失败
                from .platforms.windows.local_transport import WindowsPlatform  # layout: allow W2专用认证后端
                attempt_queue_state = state
                if selected_discover is None:
                    if not isinstance(platform.transport, WindowsPlatform):
                        raise OSError('windows_provider_not_enabled')
                    selected_discover = sampling = WorkerDiscovery(platform.transport)
                    empty_complete = sampling.complete
            dispatcher = Dispatcher(
                store=store,
                discover=selected_discover or (lambda: discover(sources)),
                transports=transports or default_transports(),
                attempt_queue_state=attempt_queue_state,
                empty_discovery_complete=empty_complete,
                pending_ready=pending_backoff.ready if pending_backoff else None,
                pending_observe=pending_backoff.observe if pending_backoff else None,
                reply_address=inbox.address if inbox is not None else None,
                command=command_name(),
                log=log,
            )
            idle_since: float | None = None
            failures = 0
            try:
                while not stopping:
                    try:
                        dispatcher.run_once()
                        if inbox is not None and not inbox.healthy():
                            # 收件箱文件被外部清理：重建后更新回复地址
                            inbox.close()
                            inbox = _open_inbox(inbox_directory)
                            dispatcher.reply_address = inbox.address if inbox is not None else None
                            log("inbox_reopened", {"inbox": inbox is not None})
                        if inbox is not None:
                            for frame in inbox.poll(loop_seconds):
                                dispatcher.handle_frame(frame)
                        else:
                            time.sleep(loop_seconds)
                        live = dispatcher.has_live_work()
                        mark = store.ledger_revision()
                        if not summary_pending and mark != summary_seen:
                            summary_failures = 0  # 账本有新变化：重新开始计数
                        if summary_pending or mark != summary_seen:
                            published = _publish_summary(store, directory, log, force=False)
                            if published is not None:
                                summary_seen = (published.ledger_id, published.revision)
                                summary_pending, summary_failures = False, 0
                            else:
                                summary_failures += 1
                                # 有界重试：连续失败达到上限后不再为摘要驻留，下次任一 ab 调用或启动时补写
                                summary_pending = summary_failures < MAX_CONSECUTIVE_FAILURES
                                if not summary_pending:
                                    summary_seen = mark  # 放弃这一修订的补写，账本再变化时重试
                        live = live or summary_pending
                        failures = 0
                    except Exception as error:  # 单轮失败不让 worker 静默退出
                        failures += 1
                        log(
                            "loop_error",
                            {
                                "error": type(error).__name__,
                                "code": getattr(error, "code", None),
                                "consecutive": failures,
                            },
                        )
                        if once or failures >= MAX_CONSECUTIVE_FAILURES:
                            break
                        time.sleep(min(loop_seconds * failures, 10.0))
                        continue
                    if once:
                        break
                    now = time.monotonic()
                    if live:
                        idle_since = None
                    elif idle_since is None:
                        idle_since = now
                    elif now - idle_since >= IDLE_EXIT_SECONDS:
                        break
            finally:
                if inbox is not None:
                    inbox.close()
                log("stop", {"consecutiveFailures": failures})
    finally:
        lifecycle.restore_stop(previous)
        lifecycle.unlock(lock_fd)
        lifecycle.close_lock(lock_fd)
    return 0
