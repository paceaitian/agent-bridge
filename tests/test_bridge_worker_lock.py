"""worker 单实例锁的时间预算重试（DESIGN §95.2）：共用的 retry_lock 与 Windows 假内核上的取锁，两种系统都跑。

用虚拟时钟替换 lock_retry 模块里的 time：不真等、不起线程。Linux 的端到端用例（真实 flock 与 run_worker）在
test_bridge_worker 里。
"""

from __future__ import annotations

from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
from typing import Callable
import unittest
from unittest.mock import patch

import bridge_support  # noqa: F401  导入即装测试守卫与宿主环境隔离
from bridge_winapi import Kernel

from agentstatus_bridge.platforms import lock_retry
from agentstatus_bridge.platforms.factory import make_platform
from agentstatus_bridge.platforms.lock_retry import LOCK_RETRY_BUDGET_SECONDS, LOCK_RETRY_INTERVAL_SECONDS, retry_lock


class VirtualTime:
    """lock_retry 用的虚拟时钟：sleep 只推进时间，并在推进后调用 on_advance（模拟持锁方在某一时刻释放）。"""

    def __init__(self, on_advance: Callable[[float], None] | None = None) -> None:
        self.now = 1000.0
        self.slept: list[float] = []
        self.on_advance = on_advance

    def monotonic(self) -> float:
        return self.now

    def sleep(self, seconds: float) -> None:
        self.slept.append(seconds)
        self.now += seconds
        if self.on_advance is not None:
            self.on_advance(self.now - 1000.0)

    def patched(self):  # noqa: ANN201 - patch 上下文
        return patch.object(lock_retry, "time", SimpleNamespace(monotonic=self.monotonic, sleep=self.sleep))


class RetryLockTests(unittest.TestCase):
    def test_budget_is_one_second_with_twenty_millisecond_steps(self) -> None:
        self.assertEqual((LOCK_RETRY_BUDGET_SECONDS, LOCK_RETRY_INTERVAL_SECONDS), (1.0, 0.02))

    def test_first_success_does_not_sleep(self) -> None:
        clock = VirtualTime()
        with clock.patched():
            self.assertTrue(retry_lock(lambda: None))
        self.assertEqual(clock.slept, [])

    def test_a_holder_releasing_after_200_ms_is_outlasted(self) -> None:
        # 共享锁持有约 200 ms：旧的 5×20 ms 会放弃，时间预算内照常取到
        held = {"until": 0.2}
        attempts: list[float] = []

        def attempt() -> None:
            attempts.append(clock.now - 1000.0)
            if clock.now - 1000.0 < held["until"]:
                raise BlockingIOError()

        clock = VirtualTime()
        with clock.patched():
            self.assertTrue(retry_lock(attempt))
        self.assertGreaterEqual(attempts[-1], 0.2)
        self.assertGreater(len(attempts), 5)

    def test_a_holder_that_never_releases_is_given_up_at_the_deadline(self) -> None:
        attempts: list[float] = []

        def attempt() -> None:
            attempts.append(clock.now - 1000.0)
            raise BlockingIOError()

        clock = VirtualTime()
        with clock.patched():
            self.assertFalse(retry_lock(attempt))
        # 每次最多睡 20 ms、不睡过截止时刻；截止时刻再试最后一次后才放弃
        self.assertTrue(all(0 < item <= LOCK_RETRY_INTERVAL_SECONDS for item in clock.slept))
        self.assertAlmostEqual(sum(clock.slept), LOCK_RETRY_BUDGET_SECONDS, places=9)
        self.assertAlmostEqual(attempts[-1], LOCK_RETRY_BUDGET_SECONDS, places=9)
        self.assertEqual(len(attempts), len(clock.slept) + 1)

    def test_an_off_grid_clock_still_gets_the_last_try_at_the_deadline(self) -> None:
        # 第一次取锁本身耗时 10 ms（被调度挂起）：之后的重试点不再落在 20 ms 网格上，剩不到一个间隔时
        # 也要睡到截止时刻再试最后一次，不能提前放弃
        attempts: list[float] = []

        def attempt() -> None:
            attempts.append(clock.now - 1000.0)
            if len(attempts) == 1:
                clock.now += 0.01
            raise BlockingIOError()

        clock = VirtualTime()
        with clock.patched():
            self.assertFalse(retry_lock(attempt))
        self.assertAlmostEqual(attempts[-1], LOCK_RETRY_BUDGET_SECONDS, places=9)
        self.assertLess(clock.slept[-1], LOCK_RETRY_INTERVAL_SECONDS - 0.005)  # 最后一段只睡剩下的部分

    def test_a_suspension_past_the_deadline_still_gets_one_more_try(self) -> None:
        # 审计 r1 P3-1：第 1 次失败后进程被挂起 5 秒（越过截止时刻），锁其实在 0.1 秒时已释放；
        # 最近一次尝试早于截止时刻，不能就此放弃，要补试一次
        attempts: list[float] = []

        def attempt() -> None:
            attempts.append(clock.now - 1000.0)
            if clock.now - 1000.0 < 0.1:
                clock.now += 5.0  # 失败之后、读时钟之前被挂起
                raise BlockingIOError()

        clock = VirtualTime()
        with clock.patched():
            self.assertTrue(retry_lock(attempt))
        self.assertEqual(attempts, [0.0, 5.0])
        self.assertEqual(clock.slept, [])

    def test_a_suspension_past_the_deadline_gives_up_after_the_extra_try(self) -> None:
        attempts: list[float] = []

        def attempt() -> None:
            attempts.append(clock.now - 1000.0)
            if len(attempts) == 1:
                clock.now += 5.0
            raise BlockingIOError()

        clock = VirtualTime()
        with clock.patched():
            self.assertFalse(retry_lock(attempt))
        self.assertEqual(attempts, [0.0, 5.0])  # 只补一次，不在截止之后继续重试

    def test_other_errors_are_not_retried(self) -> None:
        clock = VirtualTime()

        def attempt() -> None:
            raise PermissionError("not a busy lock")

        with clock.patched(), self.assertRaises(PermissionError):
            retry_lock(attempt)
        self.assertEqual(clock.slept, [])


class WindowsWorkerLockTests(unittest.TestCase):
    """Windows 后端的 acquire_worker_lock 走同一个预算（假 Win32 内核的 LockFileEx 冲突矩阵）。"""

    def setUp(self) -> None:
        temporary = TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.kernel = Kernel(self.root)
        self.lifecycle = make_platform("windows", win_api=self.kernel.api).lifecycle
        self.addCleanup(lambda: self.assertEqual(self.kernel.handles, {}))

    def handles(self) -> tuple[int, int]:
        worker, other = self.lifecycle.open_lock(self.root / "worker.lock"), self.lifecycle.open_lock(self.root / "worker.lock")
        self.addCleanup(self.lifecycle.close_lock, other)
        self.addCleanup(self.lifecycle.close_lock, worker)
        return worker, other

    def test_a_probe_holding_the_shared_lock_for_200_ms_does_not_stop_the_worker(self) -> None:
        worker, probe = self.handles()
        self.lifecycle.try_lock(probe, shared=True)
        released: list[float] = []

        def release(elapsed: float) -> None:
            if elapsed >= 0.2 and not released:
                self.lifecycle.unlock(probe)
                released.append(elapsed)

        clock = VirtualTime(release)
        with clock.patched():
            self.assertTrue(self.lifecycle.acquire_worker_lock(worker))
        self.assertTrue(released)
        self.assertGreater(len(clock.slept), 4)  # 旧的 5 次重试在这里已经放弃
        self.lifecycle.unlock(worker)

    def test_an_exclusive_holder_makes_the_worker_give_up_at_the_deadline(self) -> None:
        worker, holder = self.handles()
        self.lifecycle.try_lock(holder)
        clock = VirtualTime()
        with clock.patched():
            self.assertFalse(self.lifecycle.acquire_worker_lock(worker))
        self.assertAlmostEqual(sum(clock.slept), LOCK_RETRY_BUDGET_SECONDS, places=9)
        self.lifecycle.unlock(holder)


if __name__ == "__main__":
    unittest.main()
