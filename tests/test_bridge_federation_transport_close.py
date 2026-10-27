"""relay 的 SSH 子进程通道关闭顺序（DESIGN §89，Codex AS89-C-P2-04、AS89-r2-C-P3-01/02）。

用真实本地子进程与真实管道，不连 SSH、不用账本：后台读线程阻塞在 readline 上时，close 必须先终止并回收子进程，
不能卡在关读端。可移植：同时进入 Windows CI 选择集（scripts/verify-bridge-windows.py），只有「忽略 SIGTERM」
一条按 POSIX-only 跳过（Windows 的 terminate 即 TerminateProcess，无法忽略）。
"""

from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from typing import Any

from agentstatus_bridge.federation.relay import SubprocessTransport


class ChildMixin(unittest.TestCase):
    def spawn(self, code: str, *args: str) -> subprocess.Popen[bytes]:
        """拉起只做 sleep 的本地子进程；先等它在 stdout 写出 READY，确认已就绪（含信号处理器已装好）。"""
        process = subprocess.Popen([sys.executable, "-I", "-c", code, *args], stdin=subprocess.PIPE,
                                   stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        self.addCleanup(self._reap, process)
        assert process.stdout is not None
        self.assertEqual(process.stdout.readline().strip(), b"READY")
        return process

    @staticmethod
    def _kill_pid(pid: int) -> None:
        """结束测试自己拉起的孙进程（按精确 PID，不按名字）；已退出则忽略。"""
        try:
            if os.name == "nt":
                subprocess.run(["taskkill", "/PID", str(pid), "/F"], capture_output=True, check=False)
            else:
                os.kill(pid, 9)
        except OSError:
            pass

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



class SubprocessTransportCloseTests(ChildMixin):
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



class SubprocessTransportAbortTests(ChildMixin):
    """§90.5：停止控制线程的 abort 唤醒阻塞的读与写、回收子进程、幂等，且不关 Python 流（流由主线程 close 关）。"""

    def in_thread(self, target: Any) -> tuple[threading.Thread, list[Any]]:
        results: list[Any] = []

        def run() -> None:
            try:
                results.append(target())
            except BaseException as error:  # noqa: BLE001  带回主线程判定
                results.append(error)

        worker = threading.Thread(target=run, daemon=True)
        worker.start()
        return worker, results

    def test_abort_wakes_a_reader_blocked_in_the_queue(self) -> None:
        # 孙进程继承 stdout 并一直开着：结束子进程也等不到 EOF，只有停止哨兵能唤醒读方（不能等 60 秒读超时）
        with tempfile.TemporaryDirectory() as tmp:
            marker = os.path.join(tmp, "grandchild.pid")
            process = self.spawn(
                "import subprocess, sys, time\n"
                "g = subprocess.Popen([sys.executable, '-I', '-c', 'import time; time.sleep(60)'])\n"
                "open(sys.argv[1], 'w').write(str(g.pid))\n"
                "print('READY', flush=True); time.sleep(60)", marker)
            grandchild = int(open(marker).read())
        self.addCleanup(self._kill_pid, grandchild)
        transport = SubprocessTransport(process)
        reader, results = self.in_thread(lambda: transport.read_frame(timeout=60.0))
        reader.join(0.3)
        self.assertTrue(reader.is_alive(), "读方应阻塞在队列上")
        started = time.monotonic()
        transport.abort()
        reader.join(5.0)
        self.assertFalse(reader.is_alive(), "abort 没有唤醒读方")
        self.assertLess(time.monotonic() - started, 5.0)
        self.assertEqual(results, [None])  # 停止按 EOF 返回，之后的读也一样
        self.assertIsNone(transport.read_frame(timeout=0.01))
        self.assertIsNotNone(process.returncode)  # abort 自己回收了子进程
        writer: Any = transport._writer  # pyright: ignore[reportPrivateUsage]
        self.assertFalse(writer.closed)  # 控制线程不关 Python 流
        transport.abort()  # 幂等
        self._kill_pid(grandchild)  # 释放管道，读线程才会退出 readline、close 才能关读端
        self.close_within(transport, 5.0)
        self.assert_closed(transport, process)

    def test_abort_unblocks_a_writer_stuck_on_a_full_pipe(self) -> None:
        process = self.spawn("import sys, time; print('READY', flush=True); time.sleep(60)")  # 从不读 stdin
        transport = SubprocessTransport(process)
        frame = {"type": "heartbeat", "requestId": "0" * 32, "pad": "x" * (512 * 1024)}  # 单帧不超 1 MiB 上限

        def flood() -> None:
            for _ in range(64):  # 32 MiB 远超管道缓冲：对端不读时必然阻塞在 flush 上
                transport.write_frame(frame)

        writer, results = self.in_thread(flood)
        writer.join(0.5)
        self.assertTrue(writer.is_alive(), "写方应阻塞在满管道上")
        transport.abort()
        writer.join(10.0)
        self.assertFalse(writer.is_alive(), "abort 没有让阻塞的写返回")
        self.assertEqual(len(results), 1)
        self.assertIsInstance(results[0], OSError)
        self.close_within(transport, 5.0)
        self.assertIsNotNone(process.returncode)

    def test_abort_and_close_race_without_errors(self) -> None:
        process = self.spawn("import sys, time; print('READY', flush=True); time.sleep(60)")
        transport = SubprocessTransport(process)
        aborter, results = self.in_thread(transport.abort)
        self.close_within(transport, 15.0)
        aborter.join(15.0)
        self.assertFalse(aborter.is_alive())
        self.assertEqual(results, [None])
        self.assert_closed(transport, process)


if __name__ == "__main__":
    unittest.main()
