"""worker 单实例锁的取锁重试：按单调时钟的总预算重试，Linux 与 Windows 共用（DESIGN §95.2）。"""
from __future__ import annotations

from collections.abc import Callable
import time

# 总预算（秒）：探测瞬时持共享锁、或进程在 CPU 受限的机器上被挂起时，新 worker 不至于误以为已有实例而退出。
# 代价只在已有 worker 真在运行时：多拉起的那个最多等这么久才退出。Linux 的 ensure_worker 不等它；Windows 的
# spawn_worker 等新 worker 持锁后写的启动回执，放弃的实例本就写不出回执，前台等满 10 秒报错，与预算长短无关。
LOCK_RETRY_BUDGET_SECONDS = 1.0
# 每次失败后的间隔（秒）
LOCK_RETRY_INTERVAL_SECONDS = 0.02


def retry_lock(attempt: Callable[[], object]) -> bool:
    """反复调用 attempt 取非阻塞锁：取到返回 True；被占用（BlockingIOError）就隔 20 ms 再试，
    预算用完前最后再试一次，仍拿不到返回 False。其他异常照常抛出。时钟与睡眠在调用时取本模块的 time。

    失败之后进程若被挂起越过截止时刻（SIGSTOP、cgroup 冻结、Windows 睡眠计入单调时钟），最近一次尝试早于
    截止时刻，不能据此放弃：补试一次再返回（审计 r1 P3-1）。"""
    deadline = time.monotonic() + LOCK_RETRY_BUDGET_SECONDS
    while True:
        tried_at = time.monotonic()
        try:
            attempt()
            return True
        except BlockingIOError:
            pass
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            if tried_at >= deadline:
                return False
            try:
                attempt()  # 最近一次尝试早于截止时刻：截止之后补试一次
                return True
            except BlockingIOError:
                return False
        time.sleep(min(LOCK_RETRY_INTERVAL_SECONDS, remaining))
