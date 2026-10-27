"""relay 停止控制与运行诊断（DESIGN §90.5/§90.6）：两平台共用的控制线程、SIGTERM 标志与 Windows 诊断三键发布。

- SIGTERM 处理函数只做一次普通赋值；控制线程每 ≤0.5 秒把它转成一次性 Event，每 ≤1 秒读一次本地配置
  （停用判定的唯一读者），Windows 上兼做 launch anchor 句柄等待。
- 停止时控制线程中止当前连接的 ssh 并唤醒读方；主线程只看 Event.is_set()，不再自己读配置。
- 控制线程不写库、不关 Python 流；诊断三键只由主线程发布（RelayDiagnostics.tick）。
"""

from __future__ import annotations

import importlib.metadata
import signal
import threading
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any, Protocol

from ..store import StoreError
from . import config as fed_config
from .fedstore import FederatedStore

POLL_S = 0.5
CONFIG_EVERY_S = 1.0
JOIN_S = 2.0
DISTRIBUTION = "agent-bridge"  # Windows 安装包的分发名（scripts/build-bridge.py）；Linux 不读
MAX_VERSION_CHARS = 128
# 停止来源；stop_controller_failed 表示控制线程意外退出，relay 以非零状态结束、交给服务管理器重启
STOP_REASONS = frozenset({"anchor_exited", "disabled", "signal", "stop_controller_failed"})


class Abortable(Protocol):
    def abort(self) -> None: ...


class Anchor(Protocol):
    """launch anchor：wait(0) 返回 exited / alive / failed（WAIT_FAILED 或无法判断）。"""

    def wait(self, milliseconds: int) -> str: ...

    def close(self) -> None: ...


def utc_ms() -> int:
    """UTC Unix epoch 毫秒；与维护脚本的 T0（time.time_ns() // 1_000_000）同一口径（§90.6）。"""
    return time.time_ns() // 1_000_000


def config_disabled(root: Path) -> bool:
    """控制线程的停用判定（§90.5）：合法配置 enabled=false，或配置文件确实不存在，才算停用。

    解析失败、IO 失败（含 Windows 上与 os.replace 竞争的 winerror 5）只算这一轮没读到，下一轮再读（Opus r3 P3-1）。
    """
    try:
        current = fed_config.load(root)
    except fed_config.ConfigError:
        return False
    return current is None or not current.enabled


def valid_distribution_version(value: object) -> bool:
    """分发版本只接受非空、≤128 字符的可打印 ASCII 文本（§90.6）；不合法的值不发布也不投影。"""
    return isinstance(value, str) and 0 < len(value) <= MAX_VERSION_CHARS and value.isascii() and value.isprintable()


def distribution_version() -> str | None:
    """Windows 读已安装分发的版本；取不到或不合法就不发布，relay 照常运行（§90.6）。"""
    try:
        value = importlib.metadata.version(DISTRIBUTION)
    except Exception:  # PackageNotFoundError 与损坏的元数据一样处理：只是没有版本可报
        return None
    return value if valid_distribution_version(value) else None


class StopController:
    """一次性停止事件、停止原因、当前连接引用与 launch anchor。

    锚点句柄在控制线程认领后归它独占；认领之前（含没启动、启动失败）仍归主线程，由 close() 关闭（DESIGN §90.13）。
    """

    def __init__(self, *, read_disabled: Callable[[], bool], anchor: Anchor | None = None, poll: float = POLL_S,
                 config_every: float = CONFIG_EVERY_S, sleep: Callable[[float], None] = time.sleep,
                 monotonic: Callable[[], float] = time.monotonic) -> None:
        self._event = threading.Event()
        # 保护连接引用、停止原因、_closing/_claimed 认领仲裁与锚点交换；绝不在持锁时等待子进程或句柄
        self._lock = threading.Lock()
        self._transport: Abortable | None = None
        self._anchor = anchor
        self._read_disabled = read_disabled
        self._poll, self._config_every = poll, config_every
        self._sleep, self._monotonic = sleep, monotonic
        self._closing = False
        self._claimed = False  # 控制线程是否已接手锚点；与 _closing 在 _lock 内互相仲裁，句柄只归一方
        self._thread: threading.Thread | None = None
        self.signal_requested: str | None = None
        self.reason: str | None = None
        self.anchor_watch = "active" if anchor is not None else "unavailable"

    # ---- 主线程 ----

    def is_set(self) -> bool:
        return self._event.is_set()

    def on_signal(self, _signum: int, _frame: object) -> None:
        """SIGTERM 处理函数：只做一次普通赋值，不碰 Event、锁、队列、日志或数据库（§90.5）。"""
        self.signal_requested = "signal"

    def start(self) -> None:
        """启动控制线程；起不来时原异常照常抛出（Opus P3-r2-3）。

        先登记再启动：启动后任何时刻被中断（SIGINT 转成的 KeyboardInterrupt），close() 都找得到这个线程。
        「线程是否存在」不再代表句柄归谁，归属由 _run 开头的认领在锁内决定（Codex AS90-I-r3-C-P3-01）。
        """
        self._thread = threading.Thread(target=self._run, name="federation-relay-stop", daemon=True)
        self._thread.start()

    def bind(self, transport: Abortable) -> None:
        """登记当前连接；停止已经请求时立即中止它，不让新连接继续。

        登记与读 Event 在同一把锁内，request 也在这把锁内置位并取快照：两边必有一方看到对方，
        不会出现「request 取到旧的空引用、bind 又没看到停止」的漏中止（Codex AS90-I-C-P2-01）。两边都中止也无妨，abort 幂等。
        """
        with self._lock:
            self._transport = transport
            stopped = self._event.is_set()
        if stopped:
            transport.abort()

    def unbind(self) -> None:
        with self._lock:
            self._transport = None

    def close(self, timeout: float = JOIN_S) -> bool:
        """主线程收尾：请控制线程退出并有界 join；不从别的线程抢关它持有的句柄。

        返回 true 表示此后不会再有控制线程碰句柄或连接：线程已退出，或从未认领（启动中被中断时 OS 线程
        可能稍后才跑到认领，看到 _closing 即返回，不起作用）。返回 false 表示 join 超时后线程仍活着：已认领时句柄仍归它，
        未认领时它跑到认领处就会退出、不碰句柄（Codex AS90-I-r3e-C-P3-01、Opus r3e）。

        控制线程没认领（没启动、启动失败、或启动后还没跑到认领）时句柄归主线程，由这里关；
        迟到的线程认领时看到 _closing 直接退出，不碰句柄。已认领则只 join，join 超时也不抢关。
        未启动的线程不能 join（会抛 RuntimeError 盖住原异常），只 join 活着的。
        """
        with self._lock:
            self._closing = True
            claimed = self._claimed
        if not claimed:
            self._drop_anchor(failed=False)
        thread = self._thread
        if thread is not None and thread.is_alive():
            thread.join(timeout)
        return thread is None or not thread.is_alive()

    # ---- 控制线程 ----

    def request(self, reason: str) -> None:
        """设置停止（原因以第一次为准）并中止当前连接：锁内置位并复制引用，释放锁后再中止，绝不持锁等子进程。"""
        with self._lock:
            if self.reason is None:
                self.reason = reason
            self._event.set()
            transport = self._transport
        if transport is not None:
            transport.abort()

    def _run(self) -> None:
        with self._lock:
            if self._closing:
                return  # 主线程已收尾并关了句柄：迟到的线程什么也不做
            self._claimed = True
        try:
            next_config = self._monotonic()
            while not self._closing and not self._event.is_set():
                try:
                    if self.signal_requested is not None:
                        self.request(self.signal_requested)
                        break
                    now = self._monotonic()
                    if now >= next_config:
                        next_config = now + self._config_every
                        if self._read_disabled():
                            self.request("disabled")
                            break
                    self._watch_once()
                except Exception:
                    self._sleep(self._poll)  # 本轮意外失败：有界 sleep 后继续消费信号与停用，不空转、不无声退出
        finally:
            self._drop_anchor(failed=False)
            if not self._closing and not self._event.is_set():
                self.request("stop_controller_failed")  # 控制线程意外退出：停 relay 并给闭集原因，不静默丢掉停止能力

    def _watch_once(self) -> None:
        anchor = self._anchor
        if anchor is None:
            self._sleep(self._poll)
            return
        try:
            state = anchor.wait(0)
        except Exception:
            state = "failed"
        if state == "exited":
            self.request("anchor_exited")
        elif state == "alive":
            self._sleep(self._poll)
        else:
            self._drop_anchor(failed=True)  # WAIT_FAILED：关闭一次、不再等待失效句柄
            self._sleep(self._poll)

    def _drop_anchor(self, *, failed: bool) -> None:
        with self._lock:  # 取出并置空是一次交换：主线程与控制线程不会各拿到同一个句柄、关两次
            anchor, self._anchor = self._anchor, None
        if failed:
            self.anchor_watch = "unavailable"
        if anchor is not None:
            try:
                anchor.close()
            except Exception:
                pass


class RelayDiagnostics:
    """诊断三键的主线程发布者（§90.6）：启动时清旧值；Windows 整组发布，anchorWatch 变化或上次写失败时重发。

    Linux 只清残留，不读分发版本、不发布。发布失败不阻断服务，下一次 tick 再试。
    """

    def __init__(self, store: FederatedStore, controller: StopController, *, windows: bool,
                 version: Callable[[], str | None] = distribution_version,
                 clock: Callable[[], int] | None = None) -> None:
        self.store = store
        self.controller = controller
        self.windows = windows
        self._version_source = version
        self._version: str | None = None
        self._clock = clock or utc_ms
        self._published: str | None = None
        self._dirty = True

    def initialize(self) -> None:
        try:
            self.store.clear_relay_diagnostics()
        except StoreError:
            pass  # 清除失败不要紧：发布是整组替换，不会留下旧版本配新时间
        if self.windows:
            self._version = self._version_source()
            self.tick()

    def tick(self) -> None:
        if not self.windows:
            return
        current = self.controller.anchor_watch
        if not self._dirty and current == self._published:
            return
        try:
            self.store.publish_relay_diagnostics(anchor_watch=current, version=self._version,
                                                 published_at=self._clock())
        except StoreError:
            self._dirty = True
            return
        self._published, self._dirty = current, False


def install_sigterm(controller: StopController) -> Callable[[], None]:
    """只在主线程接管 SIGTERM（嵌入式/测试的非主线程须显式注入停止源）；返回恢复原处理函数的回调。"""
    if threading.current_thread() is not threading.main_thread():
        return lambda: None
    previous: Any = signal.signal(signal.SIGTERM, controller.on_signal)

    def restore() -> None:
        signal.signal(signal.SIGTERM, previous if previous is not None else signal.SIG_DFL)

    return restore
