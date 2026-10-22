"""W1流的真实ABI/资源故障向量，生产连接守卫必须越过RPC。"""
from dataclasses import replace
from pathlib import Path
from tempfile import TemporaryDirectory
import time
import unittest
from unittest.mock import Mock, patch

import bridge_support
from bridge_short_socket import short_root
from bridge_platform_guard import ProductionSocketUse, windows_fixture
from bridge_winapi import Kernel, put
from bridge_winapi_sdk import assert_file_layout
from agentstatus_bridge.platforms.windows import abi as A
from agentstatus_bridge.platforms.factory import make_platform, using_platform
from agentstatus_bridge.platforms.types import ProcessIdentity
from agentstatus_bridge.platforms.windows.streams import WinsockStream, PipeStream, PipeListener
from agentstatus_bridge.platforms.windows.io import WinIO, reap, _quarantine, unix_address
from agentstatus_bridge.transports.codex_rpc import queue_add


class StreamTests(unittest.TestCase):
    def setUp(self):
        bridge_support.bridge_short_socket_guard.isolate(self)
        assert_file_layout(self,A.FILE_INFORMATION)
        self.tmp=short_root();self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name);self.k=Kernel(self.root)
        self.p=make_platform('windows',win_api=self.k.api)
        self.expected=ProcessIdentity('windows',100,'win-filetime','134362090001712230')
        self.unix=self.root/'s';self.unix.touch()
        self.k.files[str(self.unix)]={'reparse':True,'tag':0x80000023}
        self.pipe=r'\\.\pipe\agent-bridge-w1-fixture'
    def tearDown(self):
        self.assertEqual(self.k.handles,{})
        self.assertEqual(self.k.ws_count,0)
        self.assertEqual(_quarantine,[])
    def unix_stream(self, expected=None):
        with windows_fixture('unix',str(self.unix)):
            return WinsockStream(self.k.api,self.p.files,self.unix,expected or self.expected)
    def pipe_stream(self, expected=None):
        with windows_fixture('pipe',self.pipe):
            return PipeStream(self.k.api,self.p.files,self.root,self.pipe,expected or self.expected)
    def outcome(self, fn):
        try: return fn()
        except Exception as error: return error
    def test_unix_address_surrogates_are_os_errors_before_connect(self):
        for address in ('x\ud800','x\udfff','\ud800\udfff'):
            with self.subTest(address=ascii(address)):
                error=self.outcome(lambda:unix_address(address))
                self.assertIsInstance(error,OSError)
                self.assertEqual(str(error),'windows_socket_path_invalid')
                self.assertFalse(any(n=='connect' for n,_ in self.k.calls))
        self.assertEqual(bytes(unix_address('非BMP😀').path),'非BMP😀'.encode('utf-8'))
    def test_lowest_connect_guard_prevents_native_calls_and_escapes_exception(self):
        for make,name in [(self.unix_stream,'unix'),(self.pipe_stream,'pipe')]:
            # Native entry, outside wrappers that register fixture names.
            caught=False
            try:
                try:
                    if name=='unix': WinsockStream(self.k.api,self.p.files,self.unix,self.expected)
                    else: PipeStream(self.k.api,self.p.files,self.root,self.pipe,self.expected)
                except Exception:
                    self.fail('RPC-like Exception fallback swallowed boundary')
            except ProductionSocketUse:
                caught=True
            self.assertTrue(caught)
        self.assertFalse(any(n=='connect' for n,args in self.k.calls))
        self.assertFalse(any(n=='CreateFileW' and not args[3] for n,args in self.k.calls))
    def test_real_rpc_does_not_turn_win32_guard_into_fallback(self):
        for kind in ('unix','pipe'):
            backend=Mock()
            backend.resolve.return_value=self.unix
            connection=Mock()
            backend.new_stream.return_value=connection
            if kind=='unix':
                io=WinIO(self.k.api);handle=io.socket()
                connection.close.side_effect=lambda: io.close_socket(handle)
                backend.connect.side_effect=lambda *_: io.connect_unix(handle,str(self.unix),time.monotonic()+1)
            else:
                backend.connect.side_effect=lambda *_: WinIO(self.k.api).open_pipe(self.pipe)
            with using_platform(replace(self.p,transport=backend)),self.assertRaises(ProductionSocketUse):
                queue_add(self.unix,thread_id='synthetic',text='fixture',client_message_id='fixture',client_version='fixture')
            connection.close.assert_called_once()
    def test_unix_peer_zero_bytes_short_writes_eof_and_timeout(self):
        result=self.outcome(self.unix_stream)
        self.assertIsInstance(result,WinsockStream)
        with self.add_stream(result) as stream:
            self.k.short_write=2
            stream.sendall(b'abcdefgh')
            self.assertEqual(self.k.socket_out,b'abcdefgh')
            self.assertEqual(stream.recv(3),b'par')
            self.k.socket_in.clear()
            self.assertEqual(stream.recv(8),b'')
            self.k.ws_error=10035
            with self.assertRaises(TimeoutError): stream.recv(8)
        self.assertTrue(any(n=='WSAIoctl' for n,_ in self.k.calls))
    def add_stream(self, stream):
        from contextlib import closing
        return closing(stream)
    def test_peer_pid_sid_elevation_generation_fail_closed(self):
        self.k.processes[101]=(0,134362090001712230,self.k.sid,False,'same-user-server')
        self.k.peer=101
        with self.assertRaises(OSError): self.unix_stream()
        self.k.peer=100
        cases=('pid','sid','elevated','generation','empty','count')
        for update,stage in ((update,stage) for update in cases for stage in ('process','token','queryable')):
            old=dict(self.k.processes)
            self.k.restricted_process_stage=stage
            self.k.peer=100;self.k.peer_written=True;self.k.peer_bytes=0
            expected=self.expected
            if update=='pid': expected=replace(expected,pid=101)
            if update=='sid': self.k.processes[101]=(0,134362090001712230,bytes.fromhex('01010000000000052b000000'),False,'s');self.k.peer=101;expected=replace(expected,pid=101)
            if update=='elevated': self.k.processes[101]=(0,134362090001712230,self.k.sid,True,'s');self.k.peer=101;expected=replace(expected,pid=101)
            if update=='generation': expected=replace(expected,generation_value='134362090001712231')
            if update=='empty': self.k.peer_written=False
            if update=='count': self.k.peer_bytes=2
            with self.subTest(update=update,stage=stage),self.assertRaises(OSError):
                with self.add_stream(self.unix_stream(expected)): pass
            self.k.processes=old
        self.k.peer_written=True;self.k.peer_bytes=0
        with self.add_stream(self.unix_stream()) as stream:
            self.k.processes[100]=(0,134362090001712231,self.k.sid,False,'s')
            with self.assertRaises(OSError): stream.sendall(b'not-written')
            self.assertEqual(self.k.socket_out,b'')

    def test_af_unix_exception_is_exact_and_only_for_socket_leaf(self):
        with self.add_stream(self.unix_stream()) as stream:
            self.assertEqual(stream.recv(2),b'pa')
        with self.assertRaisesRegex(OSError,'windows_reparse_unsupported'):
            self.p.files.validate_file(self.unix)
        for tag in (0,0xA0000003,0xA000000C,0x80000024):
            self.k.files[str(self.unix)]['tag']=tag
            with self.subTest(tag=tag),self.assertRaisesRegex(OSError,'windows_reparse_unsupported'):
                self.unix_stream()
            self.assertEqual(self.k.handles,{})
        self.k.files[str(self.unix)]['tag']=0x80000023
        for tag in (0x80000023,0xA0000003):
            self.k.files[str(self.root)]={'reparse':True,'tag':tag}
            with self.assertRaisesRegex(OSError,'windows_reparse_unsupported'):self.unix_stream()
        self.k.files.pop(str(self.root))
        self.k.faults['GetFileInformationByHandleEx']=5
        with self.assertRaises(OSError):self.unix_stream()
        self.k.faults.clear()
        self.k.files[str(self.unix)]['owner']=bytes.fromhex('01010000000000052b000000')
        with self.assertRaisesRegex(OSError,'windows_acl_untrusted'):self.unix_stream()
        self.k.files[str(self.unix)].pop('owner')
        self.k.files[str(self.unix)]['private']=False
        with self.assertRaisesRegex(OSError,'windows_acl_untrusted'):self.unix_stream()
        self.assertEqual(self.k.handles,{})

    def test_two_socket_attributes_noninherit_and_exact_sqos(self):
        self.k.files[str(self.unix)]['tag_attributes']=0x400
        result=self.outcome(self.unix_stream)
        if isinstance(result,WinsockStream):result.close()
        self.assertIsInstance(result,OSError)
        del self.k.files[str(self.unix)]['tag_attributes']
        with self.add_stream(self.unix_stream()) as stream:
            self.assertIn(('SetHandleInformation',(stream.handle,1,0)),self.k.calls)
        with self.add_stream(self.pipe_stream()):
            flags=[args[5] for name,args in self.k.calls if name=='CreateFileW' and args[3] is None]
            self.assertEqual([flag & 0x1f0000 for flag in flags],[0x110000])
        self.k.files[self.pipe]={'owner':bytes.fromhex('01010000000000052b000000')}
        result=self.outcome(self.pipe_stream)
        if isinstance(result,PipeStream):result.close()
        self.assertIsInstance(result,OSError)
        self.assertEqual(self.k.handles,{})

    def test_listener_pending_cancel_retains_handle_until_explicit_transfer(self):
        listener=PipeListener(self.k.api,self.p.files,self.root,self.pipe)
        handle=listener.handle
        self.k.io_pending=True;self.k.cancel_stalls=True
        try:
            self.assertIsInstance(self.outcome(lambda:listener.accept(self.expected,timeout=.01)),TimeoutError)
            self.assertEqual(len(_quarantine),1)
            self.assertFalse(_quarantine[0].owned)
            self.assertEqual([args[1] for n,args in self.k.calls if n=='WaitForSingleObject' and args[1]==1000],[1000])
            self.k.cancel_stalls=False
            self.assertTrue(reap())
            self.assertIn(handle,self.k.handles)
        finally:
            self.k.cancel_stalls=False
            reap()
            listener.close()
        self.assertEqual([args for n,args in self.k.calls if n=='CloseHandle' and args==(handle,)],[(handle,)])

    def test_pipe_pid_query_failure_never_uses_partial_output(self):
        # A failed API can leave plausible output: success flag still required.
        def failed(handle,out):
            put(out,A.DWORD,100)
            self.k.error=5
            return 0
        for server in (False,True):
            name='GetNamedPipeClientProcessId' if server else 'GetNamedPipeServerProcessId'
            listener=PipeListener(self.k.api,self.p.files,self.root,self.pipe) if server else None
            stream=None
            try:
                with patch.object(self.k,name,side_effect=failed):
                    outcome=self.outcome(lambda:listener.accept(self.expected) if listener else self.pipe_stream())
                if isinstance(outcome,PipeStream):stream=outcome
                self.assertIsInstance(outcome,OSError)
                self.assertEqual(getattr(outcome,'winerror',None),5)
                self.assertEqual(self.k.socket_out,b'')
            finally:
                if stream:stream.close()
                if listener:listener.close()
            self.assertEqual(self.k.handles,{})
    def test_pipe_parts_disconnect_cancellation_and_drain_ownership(self):
        stream=self.pipe_stream()
        self.assertEqual(stream.recv(2),b'pa')
        self.k.short_write=2
        stream.sendall(b'abcd')
        self.assertEqual(self.k.socket_out,b'abcd')
        self.k.faults['ReadFile']=233
        self.assertEqual(self.outcome(lambda:stream.recv(8)),b'')
        self.k.faults.clear();self.k.io_pending=True
        self.assertIsInstance(self.outcome(lambda:stream.recv(8)),TimeoutError)
        self.assertEqual(stream.handle,None)
        self.assertEqual(self.k.pending,{})
        self.assertTrue(any(n=='CancelIoEx' for n,_ in self.k.calls))
        stream.close()
    def test_stalled_cancel_never_frees_live_buffers_or_root_lease(self):
        stream=self.pipe_stream()
        self.k.io_pending=True;self.k.cancel_stalls=True
        with self.assertRaises(TimeoutError): stream.recv(8)
        self.assertEqual(len(_quarantine),1)
        pending=_quarantine[0]
        self.assertIn(pending.handle,self.k.handles)
        self.assertIn(pending.overlap.event,self.k.handles)
        self.assertTrue(any(x['kind']=='directory' for x in self.k.handles.values()))
        with self.assertRaisesRegex(OSError,'cancel_pending'): self.pipe_stream()
        self.k.cancel_stalls=False
        self.assertTrue(reap())
        self.assertEqual(self.k.handles,{})
    def test_pipe_listener_flags_peer_and_no_remote(self):
        listener=PipeListener(self.k.api,self.p.files,self.root,self.pipe)
        stream=listener.accept(self.expected)
        try:
            self.assertEqual(stream.recv(2),b'pa')
        finally:
            stream.close();listener.close()
        for name in (r'\\server\pipe\x',r'\\.\pipe\x\y'):
            with self.assertRaises(OSError): WinIO(self.k.api).open_pipe(name)
        self.assertTrue(any(n=='GetNamedPipeClientProcessId' for n,_ in self.k.calls))


if __name__=='__main__': unittest.main()
