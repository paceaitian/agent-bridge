"""W1 Windows后端在Linux上也全部执行；不是skip掉后称通过。"""
import ctypes as C
import importlib
from contextlib import redirect_stdout, redirect_stderr
from dataclasses import replace
import io
import json
import os
from pathlib import Path
import subprocess
import sys
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch
from unittest.mock import Mock

import bridge_support
from bridge_winapi import Kernel
from bridge_winapi_sdk import SDK
import bridge_winapi_sdk as S
from agentstatus_bridge import cli, worker, summary, endpoints
from agentstatus_bridge.platforms.factory import make_platform, using_platform
from agentstatus_bridge.platforms.types import Presence, ProcessIdentity
from agentstatus_bridge.platforms.windows import abi as A
from agentstatus_bridge.platforms.windows.api import WinFailure
from agentstatus_bridge.platforms.windows.files import local_path
from agentstatus_bridge.store import Store, StoreError
from agentstatus_bridge.model import Provider, Delivery
from agentstatus_bridge.codex_metadata import MetadataCache
from agentstatus_bridge.transports.codex_native import NativeBatch, ThreadMetadata


class WindowsTests(unittest.TestCase):
    def setUp(self):
        S.assert_file_layout(self,A.FILE_INFORMATION)
        self.tmp = TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.k = Kernel(self.root)
        self.p = make_platform('windows', win_api=self.k.api)
        self.version_patch = patch('agentstatus_bridge.platforms.windows.codex_version.read_cli_version', return_value=None)
        self.version_patch.start()
        self.addCleanup(self.version_patch.stop)
        self.addCleanup(lambda: self.assertEqual(self.k.handles, {}))

    def test_abi_layout_signatures_and_high_handles(self):
        self.assertEqual(WinFailure(5).winerror,5)
        self.assertEqual([C.sizeof(t) for t in (A.DWORD,A.BOOL,A.WCHAR,A.HANDLE,A.SOCKET)], [4,4,2,8,8])
        self.assertEqual(C.sizeof(A.OVERLAPPED),32)
        self.assertEqual((A.OVERLAPPED.event.offset,A.PROCESSENTRY32W.exe.offset,C.sizeof(A.PROCESSENTRY32W)),(24,44,568))
        self.assertEqual(C.sizeof(A.FILE_INFORMATION),52)
        self.assertEqual((C.sizeof(A.FILE_ATTRIBUTE_TAG_INFO),A.FILE_ATTRIBUTE_TAG_INFO.tag.offset),(8,4))
        self.assertEqual(A.IO_REPARSE_TAG_AF_UNIX,0x80000023)
        self.assertEqual(A.SIGNATURES['kernel32']['GetFileInformationByHandleEx'],
                         (A.BOOL,[A.HANDLE,C.c_int32,A.PTR,A.DWORD]))
        self.assertEqual(set(A.SIGNATURES), set(SDK))
        for dll, functions in SDK.items():
            self.assertEqual(set(A.SIGNATURES[dll]), set(functions))
            for name,(result,args) in functions.items():
                fn = getattr(self.k.api.dll[dll],name)
                self.assertIs(fn.restype,result)
                self.assertEqual(fn.argtypes,args)
                self.assertIsInstance(fn.callback,C._CFuncPtr)
        h = self.k.api.open_file(str(self.root),directory=True)
        self.assertGreater(h,2**32)
        self.k.api.close(h)
        self.assertEqual(A.read_wide(A.wide('非BMP😀/a')), '非BMP😀/a')
        for value in ('bad\0path','x'*32767):
            with self.assertRaises(OSError): A.wide(value)

    def test_fake_file_io_preserves_binary_bytes_and_releases_descriptor(self):
        leaf = self.root / 'binary-fixture'
        payload = b'{"n":1}\n{"n":2}\r\n\x1a\x00\xff'
        self.p.files.atomic_write(self.root, payload, name=leaf.name, prefix='.binary.')
        self.assertEqual(leaf.read_bytes(), payload, 'CRT text conversion corrupted fake WriteFile')
        handle = self.k.api.open_file(str(leaf), read_data=True)
        fd = self.k.handles[handle]['fd']
        try:
            self.assertEqual(self.k.api.read(handle, 4096), payload)
        finally:
            self.k.api.close(handle)
        with self.assertRaises(OSError):
            os.fstat(fd)

    def test_sdk_high_handles_cross_both_argument_and_result_marshalling(self):
        self.k.next_handle=2**40+4
        h=self.k.api.open_file(str(self.root),directory=True)
        self.assertGreater(h,2**40)
        self.k.api.close(h)
        self.assertIn(('CloseHandle',(h,)),self.k.calls)
        fact=self.k.api.process(100)
        self.assertEqual(fact.pid,100)
        ws=self.k.api.dll['ws2_32']
        s=ws.socket(1,1,0)
        self.assertGreater(s,2**40)
        pid,written=A.DWORD(),A.DWORD()
        self.assertEqual(ws.WSAIoctl(s,0x58000100,None,0,C.byref(pid),4,C.byref(written),None,None),0)
        self.assertEqual(self.k.calls[-1][1][0],s)
        self.assertEqual(pid.value,100)
        self.assertEqual(ws.closesocket(s),0)
        # Calibration: the fake itself must really marshal, not just expose a
        # callback object while calling Python directly. No production signature
        # is changed here; intentionally wrong caller-side types lose bits.
        self.k.next_handle=2**40+4
        original=ws.socket.restype
        try:
            ws.socket.restype=C.c_uint32
            self.assertEqual(ws.socket(1,1,0),5)
        finally:
            ws.socket.restype=original
            ws.closesocket(2**40+5)
        h=self.k.alloc('event');close=self.k.api.k.CloseHandle;original=close.argtypes
        try:
            close.argtypes=[C.c_uint32]
            error=None
            try:close(h)
            except AssertionError as exc:error=exc
            self.assertIsInstance(error,AssertionError)
            self.assertIn(('CloseHandle',(h & 0xffffffff,)),self.k.calls)
        finally:
            close.argtypes=original
            self.k.api.close(h)

    def test_acl_real_multi_ace_layout_and_all_untrusted_cases(self):
        everyone=bytes.fromhex('010100000000000100000000')
        admins=bytes.fromhex('01020000000000052000000020020000')
        system=bytes.fromhex('010100000000000512000000')
        own=(0,3,0x1f01ff,self.k.sid)
        cases={'everyone':[own,(0,3,0x1f01ff,everyone)],
               'everyone-inherit-only':[own,(0,0x0b,0x1f01ff,everyone)],
               'admins':[own,(0,3,0x1f01ff,admins)],
               'system-only':[(0,3,0x1f01ff,system)],
               'inherit-only':[(0,8,0x1f01ff,self.k.sid)],
               'label':[own,(0x11,0,1,self.k.sid)],
               'callback':[own,(9,0,0x1f01ff,self.k.sid)],
               'null':None, 'readonly':[(0,3,0x120089,self.k.sid)]}
        for name,aces in cases.items():
            with self.subTest(name=name):
                self.k.files[str(self.root)]={'aces':aces}
                error=None
                try:
                    with self.k.api.owned(self.k.api.open_file(str(self.root), directory=True)) as handle:
                        self.k.api.check_private(handle, protected=True)
                except Exception as exc:error=exc
                self.assertIsInstance(error,OSError)
                self.assertEqual(self.k.handles,{})
        self.k.files[str(self.root)]={'aces':[own,(0,3,0x1f01ff,system)]}
        error=None
        try:self.p.files.ensure_private_dir(self.root)
        except OSError as exc:error=exc
        self.assertIsNone(error)
        self.assertTrue(any(n=='GetAce' and args[1]==1 for n,args in self.k.calls))

    def test_sdk_layout_and_invalid_are_independent_from_production(self):
        self.assertEqual(A.INVALID, S.INVALID_HANDLE_VALUE)
        pairs=[(A.FILETIME,S.FILETIME,{'low':'dwLowDateTime','high':'dwHighDateTime'}),
               (A.FILE_INFORMATION,S.BY_HANDLE_FILE_INFORMATION,
                dict(zip(('attributes','creation','access','write','volume','size_high','size_low','links','index_high','index_low'),
                         (name for name,_ in S.BY_HANDLE_FILE_INFORMATION._fields_)))),
               (A.PROCESSENTRY32W,S.PROCESSENTRY32W,
                dict(zip(('size','usage','pid','heap','module','threads','ppid','priority','flags','exe'),
                         (name for name,_ in S.PROCESSENTRY32W._fields_)))),
               (A.SOCKADDR_UN,S.SOCKADDR_UN,{'family':'sun_family','path':'sun_path'}),
               (A.OVERLAPPED,S.OVERLAPPED,{'internal':'Internal','internal_high':'InternalHigh','event':'hEvent'})]
        for production,oracle,fields in pairs:
            self.assertEqual(C.sizeof(production),C.sizeof(oracle))
            for actual,expected in fields.items():
                with self.subTest(struct=production.__name__,field=actual):
                    self.assertEqual(getattr(production,actual).offset,getattr(oracle,expected).offset)
        self.assertEqual(A.OVERLAPPED.offset.offset,S.OVERLAPPED.data.offset+S._Offsets.Offset.offset)
        self.assertEqual(A.OVERLAPPED.offset_high.offset,S.OVERLAPPED.data.offset+S._Offsets.OffsetHigh.offset)
        path=self.root/'nonzero-size';path.write_bytes(b'12345678901')
        h=self.k.api.open_file(str(path))
        try:
            info=self.k.api.file_info(h)
            self.assertEqual((info.volume,info.size_high,info.size_low,info.links),(7,0,11,1))
            self.assertEqual((info.index_high<<32)|info.index_low,path.stat().st_ino)
        finally:self.k.api.close(h)
        error=None
        try:self.k.api.open_file(str(self.root/'missing'))
        except OSError as exc:error=exc
        self.assertIsInstance(error,OSError)
        self.assertEqual(error.winerror,2)

    def test_fake_callback_preserves_unexpected_errors_and_asserts_contracts(self):
        fn=self.k.api.k.GetCurrentProcessId
        for problem in (KeyError('fixture'),ValueError('fixture'),OSError('fixture'),
                        AssertionError('explicit contract'),RuntimeError('fixture')):
            with self.subTest(kind=type(problem).__name__),patch.object(self.k,'GetCurrentProcessId',side_effect=problem):
                error=None
                try:fn()
                except BaseException as exc:error=exc
                self.assertIs(error,problem)
        self.assertEqual(fn(),100)  # no stale callback error
        for call in (lambda:self.k.api.k.GetProcessTimes(5,*[C.byref(S.FILETIME()) for _ in range(4)]),
                     lambda:self.k.api.k.CloseHandle(5)):
            error=None
            try:call()
            except Exception as exc:error=exc
            self.assertIsInstance(error,AssertionError)
            self.assertIn('truncated',str(error))

    def test_help_never_operates_and_windows_tests_are_not_skipped(self):
        with using_platform(self.p),patch.object(cli,'discover',side_effect=AssertionError('help discovered')):
            for command in ([],['doctor'],['send'],['withdraw'],['report'],['worker']):
                with redirect_stdout(io.StringIO()),self.assertRaises(SystemExit) as cm:
                    cli.main([*command,'--help'])
                self.assertEqual(cm.exception.code,0)
        self.assertEqual(self.k.calls,[])
        self.assertEqual(list(self.root.iterdir()),[])
        with (using_platform(self.p),patch.object(self.p.transport,'codex_cli_version',return_value=None) as version,
              patch.dict(os.environ,{'CODEX_HOME':str(self.root/'absent-home')})):
            self.assertEqual(endpoints.discover(),[])
            self.assertEqual(endpoints.codex_title_report(),{'state':'discovery_unverified'})
            self.assertEqual(version.call_count,0)  # absent home is complete empty; no provider subprocess or connect
        self.assertFalse(any(n=='connect' for n,_ in self.k.calls))
        for module_name in ('test_bridge_windows','test_bridge_windows_streams'):
            module=importlib.import_module(module_name)
            classes=[v for v in vars(module).values() if isinstance(v,type) and issubclass(v,unittest.TestCase)]
            self.assertTrue(classes)
            for cls in classes:
                self.assertFalse(getattr(cls,'__unittest_skip__',False))
                for name in unittest.defaultTestLoader.getTestCaseNames(cls):
                    self.assertFalse(getattr(getattr(cls,name),'__unittest_skip__',False))

    def test_native_cache_drops_a_reused_pid_generation(self):
        reader=Mock()
        thread='019a0000-0000-7000-8000-000000000001'
        reader.read.return_value=NativeBatch({thread:ThreadMetadata('root')},'ok','0.162.1')
        cache=MetadataCache(reader,clock=lambda:0)
        backend=Mock()
        backend.control_socket_path.return_value=self.root/'absent-synthetic'
        backend.socket_identity.return_value=None
        with using_platform(replace(self.p,transport=backend)):
            cache.read(self.root,{thread:((100,'1'),)})
            self.assertEqual(reader.read.call_count,1)
            cache.read(self.root,{thread:((100,'2'),)})
            self.assertEqual(reader.read.call_count,2)

    def test_summary_failure_with_revive_false_never_starts_windows_worker(self):
        with (using_platform(self.p),patch.object(cli,'state_dir',side_effect=OSError('fixture')),
              patch.object(cli,'_start_worker') as spawn,patch.object(cli,'_revive_worker') as revive):
            self.assertIsNone(cli._refresh_summary(revive=False))  # manual/withdraw read path still never revives
            cli._revive_from_summary(Mock())
            spawn.assert_not_called()
            revive.assert_not_called()
            with patch.object(cli,'_worker_ensured',False):
                self.assertIsNone(cli._refresh_summary(revive=True))
            spawn.assert_called_once_with()
            revive.assert_not_called()

    def test_summary_without_ledger_still_validates_root_before_reading(self):
        self.k.files[str(self.root)]={'reparse':True}
        with (using_platform(self.p),patch.dict(os.environ,{'AB_STATE_DIR':str(self.root)}),
              patch.object(summary,'status',side_effect=AssertionError('untrusted summary read')),
              redirect_stderr(io.StringIO())):
            self.assertEqual(cli.main(['summary','--json']),8)
            self.assertIsNone(cli._refresh_summary())
        self.assertTrue(any(n=='GetFileInformationByHandle' for n,_ in self.k.calls))

    def test_filetime_low_bit_access_denied_and_order(self):
        p = self.p.process
        fact = p.read(100)
        self.assertIs(fact.state,Presence.CURRENT)
        identity = fact.record.identity
        self.assertEqual(identity.stored_generation(),'win-filetime:134362090001712230')
        # Native birth checking now also rejects this case early. Independently
        # retain the same_generation value-projection contract at its seam.
        different=replace(fact,record=replace(fact.record,identity=replace(identity,generation_value='134362090001712231')))
        with patch.object(p,'_read',return_value=different):
            self.assertIs(p.same_generation(identity),Presence.EXITED)
        self.assertIs(p.same_generation(replace(identity,generation_value='134362090001712231')),Presence.EXITED)
        self.assertIs(p.read(999).state,Presence.EXITED)
        for invalid in (0,-1,True,2**32):
            self.assertIs(p.read(invalid).state,Presence.UNKNOWN)
        self.k.faults['OpenProcess'] = 5
        self.assertIs(p.read(100).state,Presence.UNKNOWN)
        self.assertIs(p.same_generation(identity),Presence.UNKNOWN)
        self.k.faults.clear()
        self.k.processes[101] = (100,134362090001712229,self.k.sid,False,'claude.exe')
        self.assertEqual(p.ancestry(101),())  # parent newer
        self.k.processes[101] = (100,134362090001712231,self.k.sid,False,'codex.exe')
        self.assertEqual([x.identity.pid for x in p.ancestry(101)],[101,100])
        self.assertEqual(p.ancestry(101,1),())
        self.k.processes[100] = (101,134362090001712230,self.k.sid,False,'codex.exe')
        self.assertEqual(p.ancestry(101),())
        self.assertIsNone(p.pid_namespace())
        with self.assertRaises(OSError): p.legacy()

    def test_reused_generation_precedes_sid_and_elevation_and_uses_wait(self):
        self.k.restricted_process_stage = 'token'  # queryable birth; token is unavailable to this user
        identity=ProcessIdentity('windows',101,'win-filetime','134362090001712229')
        for sid,elevated in [(self.k.sid,True),(bytes.fromhex('01010000000000052b000000'),False)]:
            self.k.processes[101]=(0,134362090001712231,sid,elevated,'reused')
            self.assertIs(self.p.process.same_generation(identity),Presence.EXITED)
        self.k.exited.add(100)
        self.assertIs(self.p.process.read(100).state,Presence.EXITED)
        self.assertFalse(any(n=='GetExitCodeProcess' for n,_ in self.k.calls))
        self.assertTrue(any(n=='WaitForSingleObject' and args[1]==0 for n,args in self.k.calls))
        self.k.exited.clear()
        # WAIT_FAILED rather than signalled; API errors must not claim EXITED.
        for code in (5,6,87,1168):
            def failed_wait(*_):
                self.k.error=code
                return 0xffffffff
            with self.subTest(last_error=code),patch.object(self.k,'WaitForSingleObject',side_effect=failed_wait):
                self.assertIs(self.p.process.read(100).state,Presence.UNKNOWN)
                self.assertIs(self.p.process.same_generation(
                    ProcessIdentity('windows',100,'win-filetime','134362090001712230')),Presence.UNKNOWN)
                self.assertEqual(self.k.handles,{})

    def test_toolhelp_revalidation_and_utf16_surrogates(self):
        original=self.k.api.process_table
        def changed():
            rows=original()
            old=self.k.processes[100]
            self.k.processes[100]=(old[0],old[1]+1,*old[2:])
            return rows
        with patch.object(self.k.api,'process_table',side_effect=changed):
            self.assertIs(self.p.process.read(100).state,Presence.UNKNOWN)
        for value in ('x\ud800','\udfff-x','\U0001f600'):
            self.assertEqual(A.read_wide(A.wide(value)),value)
        self.k.processes[100]=(0,134362090001712230,self.k.sid,False,'x\ud800')
        self.assertEqual(self.p.process.read(100).record.comm,'x\ud800')
        with patch.object(A,'read_wide',side_effect=ValueError('fixture invalid units')):
            # 未转换的 ValueError 只会成 ERROR；显式转成断言失败，删掉生产侧转换时本例 FAIL
            try:state=self.p.process.read(100).state
            except ValueError:self.fail('进程名解码 ValueError 未投影为 OSError/UNKNOWN')
            self.assertIs(state,Presence.UNKNOWN)

    def test_directory_creation_race_and_drive_type_are_validated(self):
        path=self.root/'race'
        original=self.k.CreateDirectoryW
        def race(raw,sa):
            path.mkdir(exist_ok=True)
            return original(raw,sa)
        with patch.object(self.k,'CreateDirectoryW',side_effect=race):
            error=None
            try:self.p.files.ensure_private_dir(path)
            except OSError as exc:error=exc
            self.assertIsNone(error)
        self.assertTrue(path.is_dir())
        self.k.files[str(path)]={'private':False}
        self.assertEqual(self.p.files.ensure_private_dir(path),path)
        self.assertTrue(self.k.files[str(path)]['private'])
        for drive in (0,1,2,4,5,6):
            self.k.drive_type=drive
            with self.subTest(drive=drive),self.assertRaises(OSError):self.p.files.ensure_private_dir(self.root)

    def test_summary_invalid_root_and_unknown_platform_have_stable_errors(self):
        for root in ('relative',r'\\server\share'):
            out,err=io.StringIO(),io.StringIO()
            with using_platform(self.p),patch.dict(os.environ,{'AB_STATE_DIR':root}),redirect_stdout(out),redirect_stderr(err):
                self.assertEqual(cli.main(['summary','--json']),8)
            self.assertIn('store_unavailable',out.getvalue()+err.getvalue())
            self.assertNotIn('Traceback',out.getvalue()+err.getvalue())
        out,err=io.StringIO(),io.StringIO()
        with patch.object(cli,'get_platform',side_effect=ValueError('platform_unsupported')),redirect_stdout(out),redirect_stderr(err):
            self.assertEqual(cli.main(['doctor','--json']),3)
        self.assertIn('platform_unsupported',out.getvalue()+err.getvalue())
        self.assertEqual(self.k.calls,[])

    def test_worker_probe_uses_one_lifecycle_even_without_platform_scope(self):
        platforms=[]
        def fresh():
            result=make_platform('windows',win_api=self.k.api)
            platforms.append(result)
            return result
        with patch('agentstatus_bridge.platforms.factory.make_platform',side_effect=fresh):
            outcome=None
            try:outcome=worker.worker_running(self.root)
            except Exception as exc:outcome=exc
            self.assertIs(outcome,False)
        self.assertEqual(self.k.handles,{})
        self.assertTrue(platforms)

    def test_tokens_unknown_elevated_other_user_never_authorize(self):
        for sid,elevated in [(b'\x01\x01'+b'\0'*6+b'\x01\0\0\0',False),(self.k.sid,True)]:
            self.k.processes[101]=(100,134362090001712231,sid,elevated,'codex.exe')
            self.assertIs(self.p.process.read(101).state,Presence.UNKNOWN)
        self.assertIs(self.p.process.same_generation(ProcessIdentity('windows',100,'linux-proc-ticks','1')),Presence.UNKNOWN)

    def test_unverified_windows_caller_is_not_user_or_bypass(self):
        self.assertEqual(self.k.calls,[])  # constructing the platform is still IO-free
        with using_platform(self.p):
            caller=endpoints.identify_caller([],pid=999,environ={})
            self.assertFalse(caller.is_user_shell)
            self.assertEqual(caller.rejection,'platform_unverified')
            self.assertIsNone(endpoints.permission_class(caller))
            self.assertIsNone(endpoints.permission_class(endpoints.Caller(None,None)))
        # W2-3 samples the explicitly requested PID; permission projection adds no IO.
        self.assertEqual(self.k.calls,[('OpenProcess',(0x101000,0,999))])

    def test_lock_matrix_conflict_io_and_lease_lifetime(self):
        l = self.p.lifecycle
        for left,right,allowed in [(True,True,True),(True,False,False),(False,True,False),(False,False,False)]:
            a,b = l.open_lock(self.root/'worker.lock'),l.open_lock(self.root/'worker.lock')
            self.assertNotEqual(a,b)
            self.assertEqual(os.fstat(self.k.handles[a]['fd']).st_ino,(self.root/'worker.lock').stat().st_ino)
            try:
                l.try_lock(a,shared=left)
                if allowed:
                    outcome=True
                    try: l.try_lock(b,shared=right)
                    except BlockingIOError: outcome=False
                    self.assertTrue(outcome)
                    l.unlock(b)
                else:
                    with self.assertRaises(BlockingIOError): l.try_lock(b,shared=right)
                l.unlock(a)
            finally:
                l.close_lock(a);l.close_lock(b)
        handle=l.open_lock(self.root/'worker.lock')
        try:
            self.k.faults['LockFileEx']=5
            with self.assertRaises(OSError) as cm: l.try_lock(handle,shared=True)
            self.assertNotIsInstance(cm.exception,BlockingIOError)
            self.assertTrue(any(v['kind']=='directory' for v in self.k.handles.values()))
        finally: l.close_lock(handle)
        self.assertFalse(any(c[0]=='DeleteFileW' for c in self.k.calls))

    def test_private_creation_and_acl_reparse_ntfs_negatives(self):
        f=self.p.files
        path=self.root/'新建😀'
        f.ensure_private_dir(path)
        self.assertTrue(self.k.files[str(path)]['private'])
        for key,value in [('private',False),('owner',bytes.fromhex('01010000000000052b000000')),('reparse',True),('fs','FAT32'),('protected',False)]:
            old=dict(self.k.files[str(path)])
            self.k.files[str(path)][key]=value
            with self.subTest(key=key):
                if key in {'private', 'protected'}:
                    self.assertEqual(f.ensure_private_dir(path),path)
                    self.assertTrue(self.k.files[str(path)]['protected'])
                else:
                    with self.assertRaises(OSError): f.ensure_private_dir(path)
            self.k.files[str(path)]=old
        for path in [Path('//server/share'),Path('relative'),self.root/'stream:extra',self.root/'..'/'outside',self.root/'trailing.',self.root/'NUL.txt',self.root/'COM¹']:
            with self.subTest(path=path),self.assertRaises(OSError): local_path(path)
        self.k.faults['OpenProcessToken']=5
        with self.assertRaises(OSError): f.ensure_private_dir(self.root/'unknown')
        self.assertFalse((self.root/'unknown').exists())

    def test_atomic_short_write_failure_preserves_old_and_releases(self):
        f=self.p.files
        f.atomic_write(self.root,b'old',name='summary.json',prefix='.summary.')
        self.k.short_write=2
        f.atomic_write(self.root,b'new complete',name='summary.json',prefix='.summary.')
        self.assertEqual((self.root/'summary.json').read_bytes(),b'new complete')
        self.k.faults['MoveFileExW']=32
        with self.assertRaises(OSError): f.atomic_write(self.root,b'broken',name='summary.json',prefix='.summary.')
        self.assertTrue((self.root/'summary.json').exists())
        self.assertEqual((self.root/'summary.json').read_bytes(),b'new complete')
        self.assertEqual([p.name for p in self.root.iterdir()],['summary.json'])
        self.assertEqual(self.k.handles,{})

    def test_directory_lease_shares_delete_and_metadata_only_control(self):
        leaf=self.root/'leaf';leaf.mkdir()
        target=self.root/'moved'
        # Independent metadata-only CreateFile control: no deletion sharing is
        # NOT a lease without data/delete access. This must succeed in the fake.
        with self.k.api.private_attributes() as sa:
            handle=self.k.api.handle(self.k.api.k.CreateFileW(A.wide(str(leaf)),0x20000,3,
                C.byref(sa),3,0x2200000,None))
        try:
            error=None
            try:self.k.api.replace(str(leaf),str(target))
            except OSError as exc:error=exc
            self.assertIsNone(error)
            self.assertTrue(target.is_dir())
        finally:self.k.api.close(handle)
        target.rename(leaf)
        with self.p.files.lease(leaf):
            error=None
            try:self.k.api.replace(str(leaf),str(target))
            except OSError as exc:error=exc
            self.assertIsNone(error)
            self.assertTrue(all(h.get('sharing',7) & 4 for h in self.k.handles.values()))
            self.assertFalse(leaf.exists())
            self.assertTrue(target.exists())
        self.assertTrue(target.exists())
        self.assertEqual(self.k.handles,{})

    def test_existing_file_wrong_owner_rejected_without_leases(self):
        path=self.root/'existing';path.write_bytes(b'old')
        self.k.files[str(path)]={'owner':bytes.fromhex('01010000000000052b000000')}
        with self.assertRaisesRegex(OSError,'windows_owner_mismatch'):
            self.p.files.validate_file(path)
        self.assertEqual(path.read_bytes(),b'old')
        self.assertEqual(self.k.handles,{})

    def test_windows_device_name_uses_hostname_without_wmi(self):
        from agentstatus_bridge.platforms.path_values import DEVICE_ENV
        with (patch.dict(os.environ,{},clear=True),patch('socket.gethostname',return_value='win host') as hostname,
              patch('platform.node',side_effect=AssertionError('WMI called'))):
            self.assertEqual(self.p.files.device_name(),'win-host')
            hostname.assert_called_once_with()
            with patch.dict(os.environ,{DEVICE_ENV:'explicit'}):
                self.assertEqual(self.p.files.device_name(),'explicit')
                hostname.assert_called_once_with()

    def test_windows_device_label_matches_frozen_linux_vectors(self):
        from agentstatus_bridge.platforms.path_values import DEVICE_CHARS
        cases = [(None,'host.internal','host'), ('','host.internal','host'),
                 (' \t','host.internal','host'), (' chosen ','unused','chosen'),
                 ('---','unused','local'), (None,'','local'), (None,'.domain','local'),
                 ('x'*(DEVICE_CHARS-1)+' -tail','unused','x'*(DEVICE_CHARS-1))]
        for explicit, host, expected in cases:
            env = {} if explicit is None else {'AB_DEVICE':explicit}
            with self.subTest(explicit=explicit), patch.dict(os.environ,env,clear=True), patch('socket.gethostname',return_value=host) as call:
                self.assertEqual(self.p.files.device_name(),expected)
                self.assertEqual(call.call_count,0 if explicit and explicit.strip() else 1)

    def test_summary_default_backend_keeps_lock_owner_and_releases_on_failure(self):
        from agentstatus_bridge.platforms import factory
        with using_platform(self.p):store=Store.open(self.root)
        self.addCleanup(store.close)
        baseline=dict(self.k.handles)  # Store still owns its separate root lease.
        selected=[]
        def select_default():
            result=make_platform('windows',win_api=self.k.api)
            selected.append(result)
            return result
        with patch.object(factory,'make_platform',side_effect=select_default):
            for fault in (None,'MoveFileExW','LockFileEx'):
                self.k.faults.clear()
                if fault:self.k.faults[fault]=5
                outcome=None
                try:outcome=summary.publish(store,self.root,force=True)
                except Exception as exc:outcome=exc
                if fault:self.assertIsInstance(outcome,summary.SummaryError)
                else:self.assertEqual(getattr(outcome,'status',None),'written')
                self.assertEqual(self.k.handles,baseline)
                self.assertTrue(all(not x.lifecycle._leases for x in selected))
                self.assertEqual(self.k.locks,{})
        self.k.faults.clear()
        store.close()
        self.assertEqual(self.k.handles,{})

    def test_real_store_transactions_wal_and_failure(self):
        with using_platform(self.p):
            with Store.open(self.root) as store:
                self.assertEqual(store._conn.execute('PRAGMA journal_mode').fetchone()[0],'wal')
                self.assertTrue(any(v['kind']=='directory' for v in self.k.handles.values()))
                before=store.ledger_revision()
                with self.assertRaisesRegex(RuntimeError,'rollback'):
                    with store.transaction() as conn:
                        conn.execute("CREATE TABLE fixture_rollback(x)")
                        raise RuntimeError('rollback')
                self.assertEqual(store.ledger_revision(),before)
                self.assertEqual(store._conn.execute("SELECT name FROM sqlite_master WHERE name='fixture_rollback'").fetchall(),[])
                self.assertTrue((self.root/'bridge.sqlite3-wal').exists())
                self.p.files.validate_database(self.root/'bridge.sqlite3')
            self.assertEqual(self.k.handles,{})
            self.k.faults['CreateFileW']=5
            with self.assertRaises(StoreError): Store.open(self.root)

    def test_windows_owner_unknown_preserved_and_timeout(self):
        # Existing business fixture reused, no new business-result oracle.
        self.assertTrue(hasattr(Store,'recover_withdrawals'))
        for state,expected in [(Presence.CURRENT,'alive'),(Presence.EXITED,'gone'),(Presence.UNKNOWN,'identity_unverified')]:
            row={'state':'sending','owner_pid':100,'owner_start':'win-filetime:134362090001712230','owner_pid_namespace':None}
            with using_platform(self.p),patch.object(self.p.process,'same_generation',return_value=state):
                self.assertEqual(Store._withdrawal_owner_status(row,Path('/not-proc')),expected)
        thread='019a0000-0000-7000-8000-000000000001'
        item='019a0000-0000-7000-8000-000000000002'
        start='win-filetime:134362090001712230'
        with using_platform(self.p),Store.open(self.root) as store:
            task,attempt=bridge_support.new_task(store,target=bridge_support.ref(native=thread))
            self.assertTrue(store.begin_send(attempt.id,now=10,pid=100,start_ticks=start))
            self.k.faults['OpenProcess']=5
            self.assertEqual(store.recover_interrupted(now=20),0)
            self.assertIs(store.get_attempt(attempt.id).delivery,Delivery.SENDING)
            store.finish_send(attempt.id,delivery=Delivery.QUEUED,reason='fixture',provider_ref=item,detail={},now=21,native_root='a'*64)
            operation,created=store.prepare_withdrawal(task.id,1,root_identity='a'*64,now=30,pid=100,start=start)
            self.assertTrue(created)
            store.begin_withdrawal(operation['id'],now=31,pid=100,start=start)
            store.recover_withdrawals(now=630)
            self.assertEqual(store.withdrawals(task.id)[0]['state'],'sending')
            store.recover_withdrawals(now=630.01)
            self.assertEqual(store.withdrawals(task.id)[0]['state'],'unknown')
            self.assertEqual(store.withdrawals(task.id)[0]['reason'],'owner_timeout')
            self.assertEqual(store.list_tasks()[0].id,task.id)
            summary.publish(store,self.root,force=True)
            self.assertNotIn('claude-gen',(self.root/'summary.json').read_text(encoding='utf-8'))
            with patch.dict(os.environ,{'AB_STATE_DIR':str(self.root)}),redirect_stdout(io.StringIO()):
                self.assertEqual(cli.main(['status',task.id,'--json']),0)

    def test_fixture_stop_is_generation_bound(self):
        from agentstatus_bridge.platforms.windows.stop import request_stop, stop_requested, stop_name
        identity=ProcessIdentity('windows',100,'win-filetime','134362090001712230')
        self.assertFalse(stop_requested(self.p.files,self.root,identity))
        request_stop(self.p.files,self.root,identity)
        self.assertTrue(stop_requested(self.p.files,self.root,identity))
        self.assertFalse(stop_requested(self.p.files,self.root,replace(identity,generation_value='134362090001712231')))
        self.p.files.atomic_write(self.root,b'{"version":1,"identity":{}}',name=stop_name(identity),prefix='.stop.')
        self.assertFalse(stop_requested(self.p.files,self.root,identity))

    def test_windows_business_gates_before_any_side_effect(self):
        commands=[['send','--to','grok@x','-m','x'],
                  ['withdraw','a','--attempt','1']]
        with (using_platform(self.p),patch.object(cli,'_refresh_summary',side_effect=AssertionError('refresh')),
                patch.object(cli,'discover',side_effect=AssertionError('discovery'))):
            for command in commands:
                out=io.StringIO()
                with redirect_stderr(out): code=cli.main(command)
                self.assertEqual(code,9)
                self.assertIn('windows_provider_not_enabled',out.getvalue())
                self.assertIn('尚未写入任务',out.getvalue())
            self.assertEqual(set(worker.default_transports()),{Provider.CODEX,Provider.CLAUDE})
            self.assertNotIn(Provider.GROK,worker.default_transports())
        self.assertEqual(self.k.calls,[])
        self.assertEqual(list(self.root.iterdir()),[])

    def test_doctor_and_local_summary_no_provider_queries_or_idle(self):
        with using_platform(self.p),patch.dict(os.environ,{'AB_STATE_DIR':str(self.root), 'CODEX_HOME':str(self.root/'absent-home')}),patch.object(cli,'_start_worker',side_effect=AssertionError('spawn')):
            output=io.StringIO()
            with redirect_stdout(output): self.assertEqual(cli.main(['doctor','--json']),0)
            doc=json.loads(output.getvalue())
            self.assertTrue(doc['ledgerReadable'])
            self.assertTrue(doc['providerEnabled'])
            self.assertEqual(doc['codexVersion'],'unknown')
            self.assertEqual(doc['codexDaemon']['reason'], 'read_unavailable')
            self.assertEqual(doc['codexDaemon']['cliVersion'], 'unknown')
            self.assertFalse(any(n == 'connect' for n, _ in self.k.calls))
            self.assertNotIn('discovery', doc)
            self.assertEqual(summary._observer_binding(Provider.CLAUDE,'synthetic','selected','%1',100,'s',10)['observerKeys'],[])
            with redirect_stdout(io.StringIO()):
                self.assertEqual(cli.main(['summary','--if-stale','--json']),0)
                self.assertEqual(cli.main(['tasks','--json']),0)
            self.assertEqual(self.p.runtime.view().states,{})

    def test_spawn_flags_environment_and_job_not_conflated(self):
        l=self.p.lifecycle
        env=l.worker_environment({'cLaUdE_cOdE_MeSsAgInG_tOkEn':'SECRET','claudecode':'x','Path':'a;b','codex_home':'fixture'})
        self.assertNotIn('CLAUDE_CODE_MESSAGING_TOKEN',env)
        self.assertNotIn('CLAUDECODE',env)
        self.assertEqual(env['PATH'],'a;b')
        self.assertEqual(env['CODEX_HOME'],'fixture')
        self.assertNotIn('.local/bin',env['PATH'])
        self.p.files.atomic_write(self.root,b'pass',name='worker.py',prefix='.worker.')
        with patch('subprocess.Popen') as spawn:
            l.spawn_fixture(self.root/'worker.py',self.root,popen=spawn)
        self.assertEqual(spawn.call_args.kwargs['creationflags'],0x9000200)  # §89 无窗口控制台
        self.assertTrue(spawn.call_args.kwargs['close_fds'])
        self.assertEqual(spawn.call_args.args[0][0],sys.executable)
        self.assertEqual(self.k.api.context(),{'consoleDetached':True,'inJob':True,'outlivesJob':False})


if __name__=='__main__': unittest.main()
