"""relay 的 SSH 子进程通道关闭顺序（DESIGN §89，Codex AS89-C-P2-04、AS89-r2-C-P3-01/02）。

用真实本地子进程与真实管道，不连 SSH、不用账本：后台读线程阻塞在 readline 上时，close 必须先终止并回收子进程，
不能卡在关读端。可移植：同时进入 Windows CI 选择集（scripts/verify-bridge-windows.py），只有「忽略 SIGTERM」
一条按 POSIX-only 跳过（Windows 的 terminate 即 TerminateProcess，无法忽略）。
"""

from __future__ import annotations

import os
import subprocess
import sys
import threading
import unittest
from typing import Any

from agentstatus_bridge.federation.relay import SubprocessTransport


class SubprocessTransportCloseTests(unittest.TestCase):
    def spawn(self, code: str) -> subprocess.Popen[bytes]:
        """拉起只做 sleep 的本地子进程；先等它在 stdout 写出 READY，确认已就绪（含信号处理器已装好）。"""
        process = subprocess.Popen([sys.executable, "-I", "-c", code], stdin=subprocess.PIPE,
                                   stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        self.addCleanup(self._reap, process)
        assert process.stdout is not None
        self.assertEqual(process.stdout.readline().strip(), b"READY")
        return process

    @staticmethod
    def _reap(process: subprocess.Popen[bytes]) -> None:
        if process.returncode is None:
            process.kill()
            process.wait()

    def close_within(self, transport: SubprocessTransport, seconds: float) -> None:
        """在线程里 close，有界等待；线程里的异常带回主测试（不能只看线程结束了没有）。"""
        errors: list[BaseException] = []

        def run() -> None:
            try:
                transport.close()
            except BaseException as error:  # noqa: BLE001  原样带回主线程判定
                errors.append(error)

        worker = threading.Thread(target=run, daemon=True)
        worker.start()
        worker.join(seconds)
        self.assertFalse(worker.is_alive(), "close 没有在时限内返回")
        self.assertEqual(errors, [])

    def assert_closed(self, transport: SubprocessTransport, process: subprocess.Popen[bytes]) -> None:
        """三条路径共同的后置条件：子进程已被 close 回收（不先 poll，免得测试替实现回收）、两端流已关、通道已标记关闭。"""
        self.assertIsNotNone(process.returncode)
        reader: Any = transport._reader  # pyright: ignore[reportPrivateUsage]
        writer: Any = transport._writer  # pyright: ignore[reportPrivateUsage]
        self.assertTrue(reader.closed and writer.closed)
        self.assertTrue(transport._closed)  # pyright: ignore[reportPrivateUsage]

    def test_close_terminates_a_silent_child_while_the_reader_is_blocked(self) -> None:
        process = self.spawn("import sys, time; print('READY', flush=True); time.sleep(60)")
        transport = SubprocessTransport(process)
        self.close_within(transport, 10.0)
        self.assert_closed(transport, process)
        thread: threading.Thread = transport._thread  # pyright: ignore[reportPrivateUsage]
        thread.join(2.0)
        self.assertFalse(thread.is_alive())

    @unittest.skipUnless(os.name == "posix", "POSIX-only: Windows 的 terminate 即 TerminateProcess，无法忽略")
    def test_close_kills_a_child_that_ignores_terminate(self) -> None:
        process = self.spawn("import signal, time; signal.signal(signal.SIGTERM, signal.SIG_IGN); "
                             "print('READY', flush=True); time.sleep(60)")
        transport = SubprocessTransport(process)
        transport.TERMINATE_GRACE_S = 0.5
        self.close_within(transport, 5.0)
        self.assert_closed(transport, process)
        self.assertEqual(process.returncode, -9)

    def test_close_after_the_child_exited(self) -> None:
        process = self.spawn("print('READY', flush=True)")
        process.wait(10)
        transport = SubprocessTransport(process)
        self.close_within(transport, 5.0)
        self.assert_closed(transport, process)
        self.assertEqual(process.returncode, 0)


if __name__ == "__main__":
    unittest.main()
