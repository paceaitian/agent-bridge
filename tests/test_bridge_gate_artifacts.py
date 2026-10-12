"""Artifact tests only: no Windows runtime/fixture gate is executed on Linux."""
import ast
import ctypes as C
from contextlib import contextmanager
import importlib.util
import os
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch
import sys
import bridge_platform_guard as guard

ROOT=Path(__file__).resolve().parents[1]/'scripts/windows'
sys.path.insert(0,str(ROOT))
spec=importlib.util.spec_from_file_location('gate_r2',ROOT/'W1-gate-run.py')
gate=importlib.util.module_from_spec(spec);spec.loader.exec_module(gate)
import w1_gate_native as native
TREE=ast.parse((ROOT/'W1-gate-run.py').read_text())


class GateTests(unittest.TestCase):
    def test_fixture_frame_fragments_and_eof_are_bounded(self):
        for parts in ([b'ab',b'c\n',b'ha',b'lf'],[bytes([x]) for x in b'abc\nhalf']):
            stream=Mock();stream.recv.side_effect=parts
            self.assertEqual(gate.read_fixture_frame(stream),b'abc\nhalf')
            self.assertLessEqual(stream.recv.call_count,8)
        for parts in ([b''],[b'ab',b''],[b'xx']*4):
            stream=Mock();stream.recv.side_effect=parts
            with self.assertRaises(AssertionError):gate.read_fixture_frame(stream)
            self.assertLessEqual(stream.recv.call_count,8)

    def test_warmup_is_only_isolated_stdlib_popen_wait_close(self):
        process=Mock();process.wait.return_value=0
        process.__enter__=Mock(return_value=process);process.__exit__=Mock(return_value=False)
        with (patch.object(gate.subprocess,'Popen',return_value=process) as popen,
              patch.object(gate,'config',side_effect=AssertionError('package warmup forbidden')),
              patch.object(gate,'warmup_native',return_value=['pipe','raw']) as raw):
            outcome=gate.warmup_stdlib(Path('fixture'))
        self.assertEqual(popen.call_args.args[0],[gate.sys.executable,'-I','-B','-S','-c','pass'])
        self.assertTrue(popen.call_args.kwargs['close_fds'])
        process.wait.assert_called_once_with(timeout=10)
        process._handle.Close.assert_called_once_with()
        self.assertFalse(outcome['packageWarmup'])
        self.assertEqual(len(outcome['operations']),3)
        self.assertNotIn(('unix','fixture/warm.sock'),gate.allowed)
        raw.assert_called_once_with(Path('fixture'))
        node=next(x for x in TREE.body if isinstance(x,ast.FunctionDef) and x.name=='warmup_stdlib')
        self.assertFalse(any(isinstance(x,(ast.Import,ast.ImportFrom)) for x in ast.walk(node)))
        calls=[ast.unparse(x.func) for x in ast.walk(node) if isinstance(x,ast.Call)]
        self.assertEqual(set(calls),{'subprocess.Popen','proc.wait','proc.poll','proc.kill',"getattr(proc, '_handle').Close",'getattr','warmup_native','str','allowed.add','allowed.discard'})

    def test_ready_read_shares_delete_closes_and_keeps_other_errors(self):
        k=Mock();k.CreateFileW.return_value=2**40+7;k.CloseHandle.return_value=1
        def read(handle,buffer,size,count,_):
            self.assertEqual(handle,2**40+7)
            C.memmove(buffer,b'{"ready":true}',14)
            C.cast(count,C.POINTER(C.c_uint32)).contents.value=14
            return 1
        k.ReadFile.side_effect=read
        self.assertEqual(native.read_shared(Path('ready'),k),'{"ready":true}')
        self.assertEqual(k.CreateFileW.call_args.args[2],7)
        self.assertIs(k.CreateFileW.restype,C.c_void_p)
        k.CloseHandle.assert_called_once_with(2**40+7)
        k.ReadFile.side_effect=None;k.ReadFile.return_value=0
        with self.assertRaisesRegex(OSError,'fixture_read_failed'):native.read_shared(Path('ready'),k)
        self.assertEqual(k.CloseHandle.call_count,2)
        with patch.object(gate,'read_shared',side_effect=[FileNotFoundError(),'{"ok":1}']),patch.object(gate.time,'sleep'):
            self.assertEqual(gate.until_file(Path('ready')),{'ok':1})
        with patch.object(gate,'read_shared',side_effect=PermissionError('not a sharing race')), patch.object(gate.time,'monotonic',side_effect=[0,0,10]), patch.object(gate.time,'sleep'):
            error=None
            try:gate.until_file(Path('ready'))
            except Exception as exc:error=exc
            self.assertIsInstance(error,PermissionError)

    def test_native_warmup_never_imports_package_and_uses_peer_and_own_child(self):
        source=(ROOT/'w1_gate_native.py').read_text()
        tree=ast.parse(source)
        imported=[]
        for item in ast.walk(tree):
            if isinstance(item,ast.Import):imported.extend(x.name for x in item.names)
            if isinstance(item,ast.ImportFrom):imported.append(item.module)
        self.assertEqual(set(imported),{'ctypes','os','pathlib','subprocess','sys','time'})
        calls={ast.unparse(x.func) for x in ast.walk(tree) if isinstance(x,ast.Call)}
        for required in ('raw.peer','proc.communicate','raw.close',"getattr(proc, '_handle').Close",'self.w.WSAIoctl'):
            self.assertIn(required,calls)
        self.assertIn('0x58000100',source)
        self.assertIn('stdout=subprocess.PIPE',source)
        self.assertIn("[sys.executable,'-I','-B','-S'",source)
        self.assertIn('raw.peer(sock)!=proc.pid',source)
        ps=(ROOT/'W1-gate.ps1').read_text()
        self.assertIn("'W1-gate-run.py','w1_gate_native.py'",ps)
        self.assertIn("-Destination (Join-Path $root 'w1_gate_native.py')",ps)

    def test_raw_warmup_client_calls_pid_query_and_releases_on_rejection(self):
        for peer in (123,124):
            with TemporaryDirectory(prefix='ab-w1-') as temp:
                root=Path(temp);(root/'warm.ready').write_text('{}')
                proc=Mock(pid=123,returncode=0)
                proc.__enter__=Mock(return_value=proc);proc.__exit__=Mock(return_value=False)
                proc.poll.return_value=0;proc.communicate.return_value=(b'',None)
                raw=Mock();raw.socket.return_value=2**40+5;raw.address.return_value=native.Address(1,b'x')
                raw.w.ioctlsocket.return_value=0;raw.w.connect.return_value=0;raw.peer.return_value=peer
                with patch.object(native.subprocess,'Popen',return_value=proc) as popen,patch.object(native,'RawUnix',return_value=raw),guard.windows_fixture('unix',str(root/'warm.sock')):
                    error=None
                    try:operations=native.warmup_native(root)
                    except OSError as exc:error=exc;operations=[]
                self.assertEqual(isinstance(error,OSError),peer!=123)
                self.assertEqual(popen.call_args.kwargs['stdout'],gate.subprocess.PIPE)
                self.assertEqual(len(operations),2 if peer==123 else 0)
                raw.peer.assert_called_once_with(2**40+5)
                raw.close.assert_called_once_with();proc._handle.Close.assert_called_once_with()
                self.assertFalse((root/'warm.done').exists())

    def test_raw_warmup_cannot_bypass_lowest_connection_guard(self):
        with TemporaryDirectory(prefix='ab-w1-') as temp:
            root=Path(temp);(root/'warm.ready').write_text('{}')
            proc=Mock(pid=123,returncode=0)
            proc.__enter__=Mock(return_value=proc);proc.__exit__=Mock(return_value=False)
            proc.poll.return_value=0;proc.communicate.return_value=(b'',None)
            raw=Mock();raw.socket.return_value=42;raw.address.return_value=native.Address(1,b'x')
            raw.w.ioctlsocket.return_value=0;raw.w.connect.return_value=0;raw.peer.return_value=123
            with patch.object(native.subprocess,'Popen',return_value=proc),patch.object(native,'RawUnix',return_value=raw),self.assertRaises(guard.ProductionSocketUse):
                native.warmup_native(root)
            raw.w.connect.assert_not_called()
            raw.close.assert_called_once_with()

    def test_raw_peer_query_uses_winsock_out_parameter(self):
        raw=native.RawUnix.__new__(native.RawUnix);raw.w=Mock()
        def ioctl(sock,code,_,size,output,n,count,*tail):
            self.assertEqual((sock,code,n),(2**40+9,0x58000100,4))
            C.cast(output,C.POINTER(C.c_uint32)).contents.value=123
            return 0
        raw.w.WSAIoctl.side_effect=ioctl
        self.assertEqual(raw.peer(2**40+9),123)
        raw.w.WSAIoctl.side_effect=None;raw.w.WSAIoctl.return_value=1
        with self.assertRaisesRegex(OSError,'warmup_peer_pid'):raw.peer(2**40+9)

    def test_each_round_delta_exactly_zero_cleanup_before_after(self):
        for delta in (0,1,-1,27):
            calls=[];numbers=iter([100,100+delta])
            def count():calls.append('count');return next(numbers)
            with patch.object(gate.gc,'collect',side_effect=lambda:calls.append('gc')):
                doc=gate.measured_round(lambda:calls.append('body'),count,lambda:calls.append('cleanup'))
            self.assertEqual(calls,['count','body','cleanup','gc','count'])
            self.assertEqual(doc['delta'],delta)
            self.assertIs(doc['passed'],delta==0)
        loops=[x for x in ast.walk(TREE) if isinstance(x,ast.For) and ast.unparse(x.target)=='round_number']
        self.assertEqual(len(loops),1)
        self.assertEqual(ast.unparse(loops[0].iter),'range(1, 4)')

    def test_socket_cleanup_validates_before_delete(self):
        calls=[];api=Mock();files=Mock();path=Path('fixture/s')
        files.validate_socket.side_effect=lambda _:calls.append('check')
        api.delete.side_effect=lambda _:calls.append('delete')
        gate.remove_fixture_socket(api,files,path)
        self.assertEqual(calls,['check','delete'])
        files.validate_socket.side_effect=OSError('bad tag')
        with self.assertRaises(OSError):gate.remove_fixture_socket(api,files,path)
        api.delete.assert_called_once_with(str(path))
        child=next(x for x in TREE.body if isinstance(x,ast.FunctionDef) and x.name=='child')
        self.assertTrue(any(isinstance(x,ast.Try) and any(
            isinstance(c,ast.Call) and ast.unparse(c.func)=='remove_fixture_socket'
            for f in x.finalbody for c in ast.walk(f)) for x in ast.walk(child)))

    def test_cleanup_only_exact_af_unix_files_never_reparse_directories(self):
        with TemporaryDirectory(prefix='ab-w1-test-') as temp:
            root=Path(temp);leaf=root/'s';leaf.touch();directory=root/'sub';directory.mkdir()
            real_scandir=os.scandir
            tags={leaf:(0x400,0x80000023)}
            def info(path):
                attributes,tag=tags.get(Path(path),(0x10 if Path(path)==root or Path(path)==directory else 0x80,0))
                return SimpleNamespace(st_file_attributes=attributes,st_reparse_tag=tag)
            @contextmanager
            def scan(path):
                self.assertNotIn(Path(path),[k for k,v in tags.items() if v[0]&0x400])
                with real_scandir(path) as entries:
                    yield [SimpleNamespace(path=x.path,stat=lambda follow_symlinks,p=x.path:info(p)) for x in entries]
            with patch.object(gate.os,'scandir',scan),patch.object(Path,'lstat',lambda p:info(p)):
                for attributes,tag in [(0x400,0xA000000C),(0x400,0xA0000003),(0x410,0x80000023)]:
                    tags[directory]=(attributes,tag)
                    try:outcome=gate.cleanup_reparse_tree(root)
                    except Exception as error:outcome=error
                    self.assertIsInstance(outcome,dict)
                    self.assertFalse(outcome['safe'])
                    self.assertTrue(leaf.exists())
                tags.pop(directory)
                self.assertEqual(gate.cleanup_reparse_tree(root),{'safe':True,'removedSockets':1,'unknownReparse':0})
                self.assertFalse(leaf.exists())

    def test_derived_files_are_checked_inside_open_store_and_registration_v1(self):
        local=next(x for x in ast.walk(TREE) if isinstance(x,ast.FunctionDef) and x.name=='local_core')
        scopes=[x for x in ast.walk(local) if isinstance(x,ast.With) and any('Store.open(' in ast.unparse(i.context_expr) for i in x.items)]
        self.assertEqual(len(scopes),1)
        evidence=[x for x in ast.walk(scopes[0]) if isinstance(x,ast.For) and 'bridge.sqlite3-wal' in ast.unparse(x.iter)]
        self.assertEqual(len(evidence),1)
        self.assertIn('bridge.sqlite3-shm',ast.unparse(evidence[0]))
        source=(ROOT/'W1-gate-run.py').read_text()
        self.assertIn("/'registrations'/'v1'",source)
        self.assertIn("len(list(reg.root.glob('*.json')))==1",source)
        self.assertIn('unittest.TestCase.id(test)',source)
        self.assertIn("doc['errors']==0 and doc['failures']==0 and doc['skipped']==0",source)
        ps=(ROOT/'W1-gate.ps1').read_text()
        self.assertIn('--cleanup-reparse',ps)
        self.assertIn('$last.rootName -ne [IO.Path]::GetFileName($root)',ps)
        self.assertIn('$null -eq $boundary.evidence.ownedLive',ps)


if __name__=='__main__':unittest.main()
