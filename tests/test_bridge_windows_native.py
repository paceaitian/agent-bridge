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

    def test_command_line_to_argv_matches_fixture_model_and_is_freed(self):
        # §92.7：真实 CommandLineToArgvW 与 Fake 分词模型逐项一致；产品分词按 argc/NUL 界定、结果只闭集
        from bridge_winapi import split_command_line
        from test_bridge_windows_process_role import SPLIT_CORPUS
        from agentstatus_bridge.platforms.windows import process_role as R
        from agentstatus_bridge.platforms.windows.api import WinApi
        api=WinApi()
        for line in SPLIT_CORPUS:
            with self.subTest(line=line[:40]):
                raw=C.create_unicode_buffer(line);argc=C.c_int()
                argv=api.dll['shell32'].CommandLineToArgvW(raw,C.byref(argc))
                self.assertTrue(argv)
                try:
                    slots=C.cast(argv,C.POINTER(C.c_void_p))
                    got=[C.wstring_at(slots[i]) for i in range(argc.value)]
                finally:self.assertIsNone(api.k.LocalFree(argv))
                self.assertEqual(got,split_command_line(line))
                own=(C.c_char*(len(line)*2+2)).from_buffer_copy(line.encode('utf-16-le')+b'\0\0')
                self.assertIn(R._split(api,own,len(line)*2,R.classify),{R.HELPER,R.NOT_PROVEN,R.UNKNOWN})
        line='claude.exe --type='+'a'*248
        own=(C.c_char*(len(line)*2+2)).from_buffer_copy(line.encode('utf-16-le')+b'\0\0')
        self.assertEqual(R._split(api,own,len(line)*2,R.classify),R.HELPER)  # 255 码元 + NUL 读完整
        line+='a'
        own=(C.c_char*(len(line)*2+2)).from_buffer_copy(line.encode('utf-16-le')+b'\0\0')
        self.assertEqual(R._split(api,own,len(line)*2,R.classify),R.UNKNOWN)  # 256 个非 NUL：截断

    def test_class60_on_suspended_own_children(self):
        # §92.7：挂起的自有子进程，参数从不执行；只用 QUERY_LIMITED|SYNCHRONIZE 读命令行，核缓冲形状与扩容
        import subprocess,time
        from agentstatus_bridge.platforms.windows import abi as A,process_role as R
        from agentstatus_bridge.platforms.windows.api import WinApi
        api=WinApi();query=api.dll['ntdll'].NtQueryInformationProcess
        long=[f'--k{i}='+'v'*40 for i in range(60)]
        for args,expected in ((['--type=renderer','--lang=en-US'],R.HELPER),(['-p','--type=renderer'],R.NOT_PROVEN),
                              (['--type=gpu-process',*long],R.HELPER)):
            with self.subTest(args=args[:2]):
                child=subprocess.Popen([sys.executable,*args],creationflags=0x4,stdin=subprocess.DEVNULL,
                                       stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
                try:
                    with api.owned(api.handle(api.k.OpenProcess(R.QUERY_ACCESS,False,child.pid))) as handle:
                        small=C.create_string_buffer(16);returned=A.DWORD()
                        self.assertIn(query(handle,60,small,16,C.byref(returned))&0xFFFFFFFF,R.RETRY_STATUS)
                        self.assertTrue(16<returned.value<=R.QUERY_LIMIT)
                        buf=C.create_string_buffer(returned.value)
                        self.assertEqual(query(handle,60,buf,len(buf),C.byref(returned)),0)
                        head=A.UNICODE_STRING.from_buffer(buf);base=C.addressof(buf)
                        self.assertTrue(base+16<=head.buffer and head.buffer+head.length<=base+returned.value)
                        self.assertEqual(C.wstring_at(head.buffer,head.length//2),subprocess.list2cmdline([sys.executable,*args]))
                        self.assertEqual(R.read_role(api,handle,time.monotonic()+5),expected)
                finally:child.kill();child.wait(10)

    def test_parent_witness_facts_from_a_controlled_parent(self):
        # §92.7：受控父进程只跑本脚本，创建 helper 形状的挂起孩子；核实际 PPID/FILETIME/映像后跑纯父证。
        # 生产资格筛选（claude.exe）不加测试开关：python.exe 父子在产品判定里必须不成立。
        # 清理只认本次创建：父进程把孩子放进自己的 Job（KILL_ON_JOB_CLOSE）。Assign 成功之后，父以任何方式退出
        # （含超时被杀）内核都会结束孩子；父进程内 Popen 到 Assign 之间仍有微秒级窗口，那里失败由父自己 kill。
        # 本测试不持有可终止句柄、不按 PID 终止任何进程（Codex r1 P1-01）。父进程用自己持有的孩子句柄报告
        # 创建时刻，外层按 PID 取得的样本必须与它一致，才算本次创建的孩子。正常路径父收 EOF 后不 kill、直接
        # 退出，由外层等待句柄观测到 Job 真的结束了孩子（Opus r2 P3-r2-1）。
        import subprocess,tempfile,threading,time
        from agentstatus_bridge.platforms.windows import abi as A,process_role as R
        from agentstatus_bridge.platforms.windows.api import WinApi
        api=WinApi()
        def image(pid):
            with api.owned(api.handle(api.k.OpenProcess(0x1000,False,pid))) as handle:
                buf=(A.WCHAR*32768)();size=A.DWORD(len(buf))
                api.check(api.k.QueryFullProcessImageNameW(handle,0,buf,C.byref(size)))
                return A.read_wide(buf,size.value)
        def role(pid):
            with api.owned(api.handle(api.k.OpenProcess(R.QUERY_ACCESS,False,pid))) as handle:
                return R.read_role(api,handle,time.monotonic()+5)
        # JOBOBJECT_EXTENDED_LIMIT_INFORMATION（Win64 共 144 字节）：LimitFlags 在偏移 16，0x2000=KILL_ON_JOB_CLOSE
        script=('import ctypes,subprocess,sys\n'
                'k=ctypes.WinDLL("kernel32",use_last_error=True);H=ctypes.c_void_p\n'
                'k.CreateJobObjectW.restype=H;k.CreateJobObjectW.argtypes=[H,H]\n'
                'k.SetInformationJobObject.argtypes=[H,ctypes.c_int,H,ctypes.c_uint32]\n'
                'k.AssignProcessToJobObject.argtypes=[H,H]\n'
                'k.IsProcessInJob.argtypes=[H,H,ctypes.POINTER(ctypes.c_int32)]\n'
                'k.QueryInformationJobObject.argtypes=[H,ctypes.c_int,H,ctypes.c_uint32,H]\n'
                'k.GetProcessTimes.argtypes=[H]+[ctypes.POINTER(ctypes.c_uint64)]*4\n'
                'job=k.CreateJobObjectW(None,None)\n'
                'if not job:raise OSError(ctypes.get_last_error(),"CreateJobObjectW")\n'
                'info=(ctypes.c_ubyte*144)();ctypes.c_uint32.from_buffer(info,16).value=0x2000\n'
                'if not k.SetInformationJobObject(job,9,ctypes.addressof(info),144):raise OSError(ctypes.get_last_error(),"SetInformationJobObject")\n'
                'c=subprocess.Popen([sys.executable,"--type=renderer","--lang=en-US"],creationflags=4,'
                'stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)\n'
                'try:\n'
                ' if not k.AssignProcessToJobObject(job,int(c._handle)):raise OSError(ctypes.get_last_error(),"AssignProcessToJobObject")\n'
                ' t=[ctypes.c_uint64() for _ in range(4)]\n'
                ' if not k.GetProcessTimes(int(c._handle),*(ctypes.byref(x) for x in t)):raise OSError(ctypes.get_last_error(),"GetProcessTimes")\n'
                # 正向自检：孩子确在本 Job、Job 确带 KILL_ON_JOB_CLOSE；读回的事实交外层断言（Fable r2 P3-1）
                ' inside=ctypes.c_int32()\n'
                ' if not k.IsProcessInJob(int(c._handle),job,ctypes.byref(inside)):raise OSError(ctypes.get_last_error(),"IsProcessInJob")\n'
                ' back=(ctypes.c_ubyte*144)()\n'
                ' if not k.QueryInformationJobObject(job,9,ctypes.addressof(back),144,None):raise OSError(ctypes.get_last_error(),"QueryInformationJobObject")\n'
                ' flags=ctypes.c_uint32.from_buffer(back,16).value\n'
                # 调用成功但事实为否（漏 Assign、标志写错）也要抛错落进收尾，否则不 kill 的正常路径会遗留孩子（Fable de9 P3）
                ' if inside.value!=1 or not flags&0x2000:raise OSError("job_not_bound",inside.value,flags)\n'
                ' print(c.pid,t[0].value,inside.value,flags,flush=True)\n'
                'except BaseException:\n'
                ' c.kill();c.wait(10);raise\n'  # 报告前任何失败（含 Popen→Assign 窗口）父自己收尾
                'sys.stdin.read()\n')  # 正常路径：EOF 后直接退出，关掉最后一个 Job 句柄，孩子由内核结束
        # stderr 收进临时文件：Job API 失败时把 winerror 带进断言信息（Opus r2 P3-r2-4）
        err=tempfile.TemporaryFile(mode='w+',encoding='utf-8',errors='replace')
        try:
            parent=subprocess.Popen([sys.executable,'-I','-c',script],stdin=subprocess.PIPE,stdout=subprocess.PIPE,
                                    stderr=err,text=True)
        except BaseException:
            err.close();raise
        watch=None;lower=None;child=None
        try:
            assert parent.stdout is not None and parent.stdin is not None
            line:list[str]=[]
            reader=threading.Thread(target=lambda:line.append(parent.stdout.readline()),daemon=True)
            reader.start();reader.join(30)  # 握手有界：父进程报告前卡住也走得到下面的清理
            fields=line[0].split() if line else []
            if not (len(fields)==4 and all(f.isdigit() for f in fields)):
                try:parent.wait(10)
                except subprocess.TimeoutExpired:pass
                err.seek(0)
                self.fail('controlled parent did not report its child: '+err.read()[-2000:])
            child,created=int(fields[0]),int(fields[1])
            # 清理依赖 Job：孩子必须在父的 Job 里，且 Job 带 KILL_ON_JOB_CLOSE，否则父被杀时孩子会遗留
            self.assertEqual(int(fields[2]),1)
            self.assertTrue(int(fields[3])&0x2000)
            upper=api.process(parent.pid)
            rows={pid:ppid for pid,ppid,_ in api.process_table()}
            self.assertEqual(rows[child],parent.pid)
            lower=api.process(child)
            self.assertEqual(lower.birth,created)  # 与父进程用自己句柄读到的创建时刻一致：确是本次创建的孩子
            self.assertLess(upper.birth,lower.birth)
            # 只等待、不终止（SYNCHRONIZE|QUERY_LIMITED）；同样先核出生时刻，核不上就只关句柄
            held=api.handle(api.k.OpenProcess(0x101000,False,child))
            try:
                times=[A.FILETIME() for _ in range(4)]
                api.check(api.k.GetProcessTimes(held,*(C.byref(t) for t in times)))
                self.assertEqual(times[0].number(),created)
            except BaseException:
                api.close(held);raise
            watch=held
            self.assertEqual(image(parent.pid),image(child))
            roles={parent.pid:role(parent.pid),child:role(child)}
            self.assertEqual(roles,{parent.pid:R.NOT_PROVEN,child:R.HELPER})
            self.assertTrue(R.witness(upper.birth,image(parent.pid),lower.birth,roles[child],image(child)))
            self.assertFalse(R.witness(upper.birth,image(parent.pid),upper.birth,roles[child],image(child)))
            if not api.token(api.k.GetCurrentProcess()).elevated:
                self.assertFalse(R.Roles(api,time.monotonic()+5).exempt(parent.pid,str(upper.birth),frozenset()))
        finally:
            try:
                if parent.stdin is not None:parent.stdin.close()  # 父进程收到 EOF 后直接退出
                try:parent.wait(30)
                except subprocess.TimeoutExpired:parent.kill();parent.wait(10)  # 父退出即关 Job：内核结束孩子
            finally:
                try:
                    if watch is not None:
                        # 父没有 kill 孩子：这里等到的结束只能来自 KILL_ON_JOB_CLOSE
                        try:self.assertEqual(api.k.WaitForSingleObject(watch,10000),0)
                        finally:api.close(watch)
                finally:err.close()
        if child is not None and lower is not None:
            with self.assertRaises(OSError):
                api.process(child,expected_birth=str(lower.birth))  # 退出窗口：旧代际事实不再可用

    def test_command_role_positive_on_a_suspended_claude_image(self):
        # §92.7 非提权策略正例：复制本解释器为 claude.exe 并挂起创建（加载器尚未运行，不需要它的 DLL），
        # 经完整的产品资格链得到 helper。提权令牌只能证明原语，这里如实 NOT_RUN
        import shutil,subprocess,time
        from agentstatus_bridge.platforms.windows import process_role as R
        from agentstatus_bridge.platforms.windows.api import WinApi
        api=WinApi()
        elevated=api.token(api.k.GetCurrentProcess()).elevated
        with TemporaryDirectory(prefix='ab-ci-92-',ignore_cleanup_errors=True) as temp:
            exe=os.path.join(temp,'claude.exe');shutil.copyfile(sys.executable,exe)
            child=subprocess.Popen([exe,'--type=renderer'],creationflags=0x4,stdin=subprocess.DEVNULL,
                                   stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
            try:
                birth=str(api.process(child.pid).birth)
                role=R.command_role(api,child.pid,birth,deadline=time.monotonic()+5)
                # High 令牌下资格链必须拒绝（产品只服务非提权），这是可在托管 runner 上跑的负例（Opus 实现审计 P3-8）
                self.assertEqual(role,R.UNKNOWN if elevated else R.HELPER)
            finally:child.kill();child.wait(10)
        if elevated:
            self.skipTest('non-elevated command_role positive NOT_RUN: hosted runner elevated; W3.10 acceptance covers it')
