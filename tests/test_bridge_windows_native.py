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
