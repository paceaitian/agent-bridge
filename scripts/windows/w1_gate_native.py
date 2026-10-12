"""Gate-only raw Win32 operations. NO agentstatus_bridge imports or calls.

Only an owned private rendezvous is used. This helper must travel with the gate
runner, never with a provider. Explicit ABI is duplicated here intentionally:
the warmup cannot exercise or hide a leak in the product under measurement.
"""
import ctypes as C
import os
from pathlib import Path
import subprocess
import sys
import time


def read_shared(path, kernel=None):
    """Read a ready file while its writer may still hold MoveFileEx DELETE access."""
    k = kernel or getattr(C,'WinDLL')('kernel32',use_last_error=True)
    k.CreateFileW.argtypes = [C.c_wchar_p,C.c_uint32,C.c_uint32,C.c_void_p,C.c_uint32,C.c_uint32,C.c_void_p]
    k.CreateFileW.restype = C.c_void_p
    k.ReadFile.argtypes = [C.c_void_p,C.c_void_p,C.c_uint32,C.POINTER(C.c_uint32),C.c_void_p]
    k.ReadFile.restype = C.c_int32
    k.CloseHandle.argtypes = [C.c_void_p]
    k.CloseHandle.restype = C.c_int32
    handle = k.CreateFileW(str(path),0x80000000,0x7,None,3,0,None)
    if handle in (None,0,C.c_void_p(-1).value):
        code = getattr(C,'get_last_error')()
        if code in (2,3):raise FileNotFoundError('fixture_not_ready')
        raise OSError(code,'fixture_read_open_failed')
    try:
        buf = C.create_string_buffer(65537)
        count = C.c_uint32()
        if not k.ReadFile(handle,buf,len(buf),C.byref(count),None):
            raise OSError('fixture_read_failed')
        if count.value > 65536:raise ValueError('fixture_ready_too_large')
        return buf.raw[:count.value].decode('utf-8')
    finally:
        if not k.CloseHandle(handle):raise OSError('fixture_read_close_failed')


class Address(C.Structure):
    _fields_ = [('family',C.c_uint16),('path',C.c_char*108)]


class FdSet(C.Structure):
    _fields_ = [('count',C.c_uint32),('items',C.c_size_t*64)]


class Timeval(C.Structure):
    _fields_ = [('seconds',C.c_int32),('micros',C.c_int32)]


class RawUnix:
    def __init__(self):
        self.w = getattr(C,'WinDLL')('ws2_32',use_last_error=True)
        signatures = {
            'WSAStartup':(C.c_int32,[C.c_uint16,C.c_void_p]), 'WSACleanup':(C.c_int32,[]),
            'WSAGetLastError':(C.c_int32,[]),
            'WSASocketW':(C.c_size_t,[C.c_int32,C.c_int32,C.c_int32,C.c_void_p,C.c_uint32,C.c_uint32]),
            'bind':(C.c_int32,[C.c_size_t,C.c_void_p,C.c_int32]),
            'connect':(C.c_int32,[C.c_size_t,C.c_void_p,C.c_int32]),
            'listen':(C.c_int32,[C.c_size_t,C.c_int32]),
            'accept':(C.c_size_t,[C.c_size_t,C.c_void_p,C.c_void_p]),
            'closesocket':(C.c_int32,[C.c_size_t]),
            'ioctlsocket':(C.c_int32,[C.c_size_t,C.c_int32,C.POINTER(C.c_uint32)]),
            'select':(C.c_int32,[C.c_int32,C.POINTER(FdSet),C.POINTER(FdSet),C.POINTER(FdSet),C.POINTER(Timeval)]),
            'WSAIoctl':(C.c_int32,[C.c_size_t,C.c_uint32,C.c_void_p,C.c_uint32,C.c_void_p,C.c_uint32,C.POINTER(C.c_uint32),C.c_void_p,C.c_void_p]),
        }
        for name,(result,args) in signatures.items():
            fn = getattr(self.w,name);fn.restype=result;fn.argtypes=args
        data = C.create_string_buffer(512)
        if self.w.WSAStartup(0x202,data):raise OSError('warmup_startup')
        self.sockets = []

    def socket(self):
        sock = self.w.WSASocketW(1,1,0,None,0,0x80)
        if sock == C.c_size_t(-1).value:raise OSError('warmup_socket')
        self.sockets.append(sock)
        return sock

    @staticmethod
    def address(path):
        raw = os.fsencode(path)
        if len(raw)>=108:raise ValueError('warmup_path_too_long')
        return Address(1,raw)

    def wait(self,sock,write=False):
        ready=FdSet();ready.count=1;ready.items[0]=sock
        timeout=Timeval(5,0)
        if self.w.select(0,None if write else C.byref(ready),C.byref(ready) if write else None,None,C.byref(timeout))!=1:
            raise TimeoutError('warmup_socket_deadline')

    def peer(self,sock):
        pid=C.c_uint32();count=C.c_uint32()
        if self.w.WSAIoctl(sock,0x58000100,None,0,C.byref(pid),4,C.byref(count),None,None) or not pid.value:
            raise OSError('warmup_peer_pid')
        return pid.value

    def close(self):
        failed=False
        try:
            for sock in self.sockets:
                if self.w.closesocket(sock):failed=True
        finally:self.w.WSACleanup()
        if failed:raise OSError('warmup_close')


def serve(root):
    """Only the root passed by the owning runner, not a daemon/provider endpoint."""
    if not root.name.startswith('ab-w1-') or root.is_symlink():raise ValueError('warmup_root')
    path=root/'warm.sock';ready=root/'warm.ready'
    if path.exists() or ready.exists():raise ValueError('warmup_fixture_exists')
    raw=RawUnix();bound=False
    try:
        sock=raw.socket();address=raw.address(path)
        if raw.w.bind(sock,C.byref(address),C.sizeof(address)):raise OSError('warmup_bind')
        bound=True
        if raw.w.listen(sock,1):raise OSError('warmup_listen')
        ready.write_text('{}',encoding='utf-8')
        raw.wait(sock)
        peer=raw.w.accept(sock,None,None)
        if peer==C.c_size_t(-1).value:raise OSError('warmup_accept')
        raw.sockets.append(peer)
        # Hold server side until the client performed GETPEERPID.
        deadline=time.monotonic()+5
        while not (root/'warm.done').exists():
            if time.monotonic()>=deadline:raise TimeoutError('warmup_client')
            time.sleep(.01)
    finally:
        raw.close()
        if bound:path.unlink(missing_ok=True)
        ready.unlink(missing_ok=True)


def warmup_native(root):
    # One stdout=PIPE Popen + one raw AF_UNIX client, no package imported in either.
    if not root.name.startswith('ab-w1-') or root.is_symlink():raise ValueError('warmup_root')
    command=[sys.executable,'-I','-B','-S',str(Path(__file__).resolve()),str(root)]
    with subprocess.Popen(command,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,
                          stderr=subprocess.DEVNULL,close_fds=True) as proc:
        raw=None
        try:
            deadline=time.monotonic()+5
            while not (root/'warm.ready').exists():
                if proc.poll() is not None or time.monotonic()>=deadline:raise TimeoutError('warmup_ready')
                time.sleep(.01)
            raw=RawUnix();sock=raw.socket();address=raw.address(root/'warm.sock')
            nonblock=C.c_uint32(1)
            if raw.w.ioctlsocket(sock,-2147195266,C.byref(nonblock)):raise OSError('warmup_nonblock')
            sys.audit('agent_bridge.windows.connect','unix',str(root/'warm.sock'))
            result=raw.w.connect(sock,C.byref(address),C.sizeof(address))
            if result and raw.w.WSAGetLastError()!=10035:raise OSError('warmup_connect')
            raw.wait(sock,write=True)
            if raw.peer(sock)!=proc.pid:raise OSError('warmup_wrong_peer')
            (root/'warm.done').write_text('done',encoding='ascii')
            stdout,_=proc.communicate(timeout=10)
            if proc.returncode!=0 or stdout:raise OSError('warmup_fixture_failed')
        finally:
            try:
                if raw:raw.close()
            finally:
                if proc.poll() is None:proc.kill()
                proc.wait(timeout=5)
                getattr(proc, '_handle').Close()
                (root/'warm.done').unlink(missing_ok=True)
    return ['Popen(stdout=PIPE)+communicate+close','raw ctypes AF_UNIX client+SIO_AF_UNIX_GETPEERPID+close']


if __name__=='__main__':
    serve(Path(sys.argv[1]))
