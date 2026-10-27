"""Small real Win32 CI smoke, not a provider/Windows install qualification.

Everything belongs to this process or a fresh private child directory. No
network, socket, pipe, agent root, hook, RMUX or existing state is consulted.
"""
import ctypes as C
import os
from pathlib import Path
import sys
from tempfile import TemporaryDirectory
import unittest

import bridge_platform_guard


@unittest.skipUnless(sys.platform=='win32','real Win32: NOT_RUN on this OS')
class NativeTests(unittest.TestCase):
    def test_own_process_filetime_token_and_known_folder(self):
        from agentstatus_bridge.platforms.windows.api import WinApi
        api=WinApi()
        first=api.process(os.getpid());second=api.process(os.getpid())
        self.assertGreater(first.birth,0)
        self.assertTrue(first==second)  # no identity/token bytes in failure output
        self.assertTrue(bool(first.token.sid))
        self.assertTrue(Path(api.local_app_data()).is_absolute())
        self.assertEqual(C.sizeof(C.c_void_p),8)

    def test_non_elevated_private_store_acl_lock_and_atomic_write(self):
        from agentstatus_bridge.platforms.windows.api import WinApi
        from agentstatus_bridge.platforms.factory import make_platform,using_platform
        from agentstatus_bridge.store import Store
        api=WinApi()
        if api.token(api.k.GetCurrentProcess()).elevated:
            self.skipTest('non-elevated Store/DACL gate NOT_RUN: hosted runner elevated')
        p=make_platform('windows',win_api=api)
        with TemporaryDirectory(prefix='ab-ci-w1-') as temp,using_platform(p):
            root=Path(temp)/'private'
            p.files.ensure_private_dir(root)
            with Store.open(root) as store:
                self.assertEqual(store.list_tasks(),[])
                p.files.validate_file(root/'bridge.sqlite3')
                p.files.atomic_write(root,b'fixture',name='probe',prefix='.probe.')
                self.assertEqual((root/'probe').read_bytes(),b'fixture')
                handle=p.lifecycle.open_lock(root/'probe.lock')
                try:p.lifecycle.try_lock(handle);p.lifecycle.unlock(handle)
                finally:p.lifecycle.close_lock(handle)
                # §90.6 只读探锁：持有排他锁时为忙，释放后可取；缺失按 FileNotFoundError（不新建）
                held=p.lifecycle.open_lock(root/'relay.lock')
                try:
                    p.lifecycle.try_lock(held)
                    self.assertTrue(p.lifecycle.probe_lock(root/'relay.lock'))
                    p.lifecycle.unlock(held)
                    self.assertFalse(p.lifecycle.probe_lock(root/'relay.lock'))
                finally:p.lifecycle.close_lock(held)
                with self.assertRaises(FileNotFoundError):
                    p.lifecycle.probe_lock(root/'absent.lock')
                self.assertFalse((root/'absent.lock').exists())

    def test_read_data_handle_takes_a_shared_lock(self):
        # §90.6 只读探锁依赖的 Win32 事实：只带 READ_CONTROL|FILE_READ_DATA 的句柄能做共享 LockFileEx，与写句柄的
        # 排他锁冲突时报 33。直接调 kernel32，不经产品私有 ACL 路径，所以提权的 CI 令牌上也跑（Opus 实现审计 §90.11-1）
        from agentstatus_bridge.platforms.windows import abi as A
        from agentstatus_bridge.platforms.windows.api import WinApi
        api=WinApi()
        with TemporaryDirectory(prefix='ab-ci-90-') as temp:
            path=os.path.join(temp,'relay.lock')
            open(path,'wb').close()
            writer=api.handle(api.k.CreateFileW(A.wide(path),0xC0000000,3,None,3,0x80,None))
            try:
                reader=api.handle(api.k.CreateFileW(A.wide(path),0x20001,3,None,3,0x80,None))
                try:
                    held=A.OVERLAPPED()
                    self.assertTrue(api.k.LockFileEx(writer,3,0,1,0,C.byref(held)))  # 排他、立即失败模式
                    probe=A.OVERLAPPED()
                    self.assertFalse(api.k.LockFileEx(reader,1,0,1,0,C.byref(probe)))
                    self.assertEqual(api.last_error(),33)  # ERROR_LOCK_VIOLATION → 探锁判「忙」
                    self.assertTrue(api.k.UnlockFileEx(writer,0,1,0,C.byref(held)))
                    probe=A.OVERLAPPED()
                    self.assertTrue(api.k.LockFileEx(reader,1,0,1,0,C.byref(probe)))  # 可取 → 判「未运行」
                    self.assertTrue(api.k.UnlockFileEx(reader,0,1,0,C.byref(probe)))
                finally:api.close(reader)
            finally:api.close(writer)

    def test_launch_anchor_handle_waits_on_a_real_child(self):
        # §90.6：QUERY_LIMITED|SYNCHRONIZE 同代句柄，子进程结束后变为 signaled；不需要非提权令牌
        import subprocess
        from agentstatus_bridge.platforms.windows import anchor
        from agentstatus_bridge.platforms.windows.api import WinApi
        api=WinApi()
        child=subprocess.Popen([sys.executable,'-I','-c','import time; time.sleep(60)'],
                               stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        try:
            birth=api.process(child.pid).birth
            with self.assertRaises(OSError):
                api.open_wait_handle(child.pid,birth+1)  # 代际不符不交出句柄
            held=anchor.LaunchAnchor(api,api.open_wait_handle(child.pid,birth),child.pid,birth)
            try:
                self.assertEqual(held.wait(0),'alive')
                child.kill();child.wait(10)
                self.assertEqual(held.wait(1000),'exited')
            finally:held.close()
            self.assertEqual(held.wait(0),'failed')
        finally:
            if child.poll() is None:child.kill();child.wait(10)
        found=anchor.bind(api,pid=os.getpid(),system_root=os.environ.get('SystemRoot'))
        if found is not None:found.close()  # CI 祖先链不确定：只证明定位不抛、不泄漏句柄
