"""Stateful fake Win32 kernel: fills ABI buffers, tracks ownership/locks and real temp files.

Not a Windows qualification: injected DLL calls exercise WinApi marshalling and
the SAME Windows backend. Only fixture bytes ever enter these objects.
"""
import ctypes as C
import os
import struct
from pathlib import Path
from types import SimpleNamespace

import bridge_winapi_sdk as S
from agentstatus_bridge.platforms.windows.api import WinApi
from bridge_winapi_sdk import SDK


def put(pointer, kind, value):
    C.cast(pointer, C.POINTER(kind)).contents.value = value


def text(pointer):
    p = C.cast(pointer, C.POINTER(S.U16))
    units = []
    for i in range(32767):
        if not p[i]:
            return b''.join(int(v).to_bytes(2, 'little') for v in units).decode('utf-16-le', 'surrogatepass')
        units.append(p[i])
    raise AssertionError('unterminated wide input')


class Fn:
    def __init__(self, kernel, name, prototype):
        self.kernel, self.name = kernel, name
        self.restype = self.argtypes = None
        self.callback_error = None
        result, args = prototype
        self.callback = C.CFUNCTYPE(result, *args)(self._dispatch)

    def _dispatch(self, *args):
        # ctypes otherwise prints and suppresses exceptions from callbacks.
        try:
            return self._invoke(*args)
        except BaseException as error:
            self.callback_error = error
            return None if self.callback.restype is None else 0

    def __call__(self, *args):
        self.callback_error = None
        caller = C.CFUNCTYPE(self.restype, *self.argtypes)(C.cast(self.callback, C.c_void_p).value)
        value = caller(*args)
        if self.callback_error is not None:
            raise self.callback_error
        return value

    def _invoke(self, *args):
        self.kernel.calls.append((self.name, args))
        fault = self.kernel.faults.get(self.name)
        if fault is not None:
            self.kernel.error = fault
            if self.name in {'WSAIoctl','connect','send','recv','select','getsockopt','ioctlsocket'}:
                self.kernel.ws_error=fault
                return -1
            return 0 if self.name not in {'CreateFileW','OpenProcess'} else S.INVALID_HANDLE_VALUE
        return getattr(self.kernel, self.name)(*args)


class Kernel:
    def __init__(self, root):
        self.root = Path(root)
        self.calls, self.handles, self.buffers, self.faults = [], {}, [], {}
        self.error = 0
        self.next_handle = 2**40
        self.sid = bytes.fromhex('01010000000000052a000000')
        self.processes = {100: (0, 134362090001712230, self.sid, False, 'python.exe')}
        self.current = 100
        self.files, self.locks = {}, {}
        self.short_write = None
        self.in_job = True
        self.socket_out = bytearray()
        self.socket_in = bytearray(b'part1\npart2\nhalf')
        self.peer = 100
        self.peer_bytes = 0
        self.peer_written = True
        self.ws_error = 0
        self.ws_count = 0
        self.io_pending = False
        self.cancel_stalls = False
        self.pending = {}
        self.exited = set()
        self.drive_type = 3
        self.acls, self.descriptors = {}, {}
        libraries = {name: SimpleNamespace(**{f: Fn(self, f, prototype) for f, prototype in functions.items()})
                     for name, functions in SDK.items()}
        self.api = WinApi(libraries, lambda: self.error)

    def alloc(self, kind, **values):
        self.next_handle += 1
        self.handles[self.next_handle] = {'kind': kind, **values}
        return self.next_handle

    def record(self, handle):
        # Unknown/truncated handles are API contract violations, not incidental
        # dict KeyErrors. Unexpected fixture errors retain their original type.
        assert handle in self.handles, 'unknown or truncated HANDLE/SOCKET'
        return self.handles[handle]

    def buffer(self, value):
        self.buffers.append(value)
        return C.addressof(value)

    def fail(self, error):
        self.error = error
        return 0

    def CloseHandle(self, handle):
        assert handle in self.handles, 'double close or truncated HANDLE'
        record = self.handles.pop(handle)
        if 'fd' in record:
            os.close(record['fd'])
        self.locks.pop(handle, None)
        return 1

    def GetCurrentProcess(self): return self.current
    def GetCurrentProcessId(self): return self.current
    def OpenProcess(self, access, inherit, pid):
        assert access == 0x101000 and not inherit
        if pid not in self.processes:
            self.error = 87
            return 0
        return self.alloc('process', pid=pid)
    def GetProcessTimes(self, handle, creation, exit_, kernel, user):
        fact = self.processes[self.record(handle)['pid']]
        t = C.cast(creation, C.POINTER(S.FILETIME)).contents
        t.dwLowDateTime, t.dwHighDateTime = fact[1] & 0xffffffff, fact[1] >> 32
        return 1
    def GetExitCodeProcess(self, handle, out):
        put(out, S.U32, 259)
        return 1
    def OpenProcessToken(self, handle, access, out):
        assert access == 8
        pid = handle if handle == self.current else self.record(handle)['pid']
        put(out, S.H, self.alloc('token', pid=pid))
        return 1
    def GetTokenInformation(self, handle, kind, buf, size, needed):
        fact = self.processes[self.record(handle)['pid']]
        if kind == 1:
            put(needed, S.U32, 16)
            if not buf: return self.fail(122)
            ptr = self.buffer(C.create_string_buffer(fact[2]))
            put(buf, S.P, ptr)
        else:
            assert kind == 20 and size == 4
            put(needed, S.U32, 4)
            put(buf, S.U32, int(fact[3]))
        return 1
    def IsValidSid(self, ptr): return 1 if ptr else 0
    def GetLengthSid(self, ptr): return 8 + C.string_at(ptr, 2)[1] * 4
    def ConvertSidToStringSidW(self, sid, out):
        put(out, S.P, self.buffer(S.wide('S-1-5-42')))
        return 1
    def ConvertStringSecurityDescriptorToSecurityDescriptorW(self, string, revision, out, size):
        assert text(string) == 'O:S-1-5-42D:P(A;OICI;FA;;;S-1-5-42)(A;OICI;FA;;;SY)'
        put(out, S.P, self.buffer(C.create_string_buffer(64)))
        return 1
    def LocalFree(self, pointer): return 0
    def CoTaskMemFree(self, pointer): pass
    def SHGetKnownFolderPath(self, folder, flags, token, out):
        put(out, S.P, self.buffer(S.wide(str(self.root))))
        return 0
    def CreateToolhelp32Snapshot(self, flags, pid):
        assert (flags, pid) == (2, 0)
        return self.alloc('snapshot', position=-1)
    def Process32FirstW(self, handle, out): return self.Process32NextW(handle, out)
    def Process32NextW(self, handle, out):
        self.record(handle)['position'] += 1
        i = self.record(handle)['position']
        rows = list(self.processes.items())
        if i >= len(rows): return self.fail(18)
        entry = C.cast(out, C.POINTER(S.PROCESSENTRY32W)).contents
        assert entry.dwSize == C.sizeof(S.PROCESSENTRY32W)
        pid, fact = rows[i]
        entry.th32ProcessID, entry.th32ParentProcessID = pid, fact[0]
        encoded = S.wide(fact[4])
        for n, unit in enumerate(encoded): entry.szExeFile[n] = unit
        return 1
    def CreateDirectoryW(self, path, sa):
        self._attributes(sa)
        p = Path(text(path))
        try:p.mkdir()
        except FileExistsError:return self.fail(183)
        self.files[str(p)] = {'private': True, 'protected': True}
        return 1
    def _attributes(self, sa):
        assert sa, 'public create'
        attributes = C.cast(sa, C.POINTER(S.SECURITY_ATTRIBUTES)).contents
        assert attributes.nLength == C.sizeof(S.SECURITY_ATTRIBUTES)
        assert attributes.lpSecurityDescriptor and not attributes.bInheritHandle
    def CreateFileW(self, path, access, sharing, sa, disposition, flags, template):
        if text(path).startswith('\\\\.\\pipe\\'):
            assert flags & 0x40000000 and flags & 0x1f0000 == 0x110000
            return self.alloc('pipe',path=text(path))
        self._attributes(sa)
        assert sharing == 3 and flags & 0x200000, 'no directory pin/reparse guard'
        p = Path(text(path))
        if not p.exists() and disposition == 3:
            self.error = 2
            return S.INVALID_HANDLE_VALUE
        if flags & 0x2000000:
            return self.alloc('directory', path=str(p), access=access, sharing=sharing)
        if disposition == 1 and p.exists():
            self.error = 80
            return S.INVALID_HANDLE_VALUE
        existed = p.exists()
        fd = os.open(p, os.O_RDWR | (os.O_CREAT if disposition in (1, 4) else 0) | (os.O_EXCL if disposition == 1 else 0), 0o600)
        if not existed: self.files[str(p)] = {'private': True, 'protected': True}
        return self.alloc('file', path=str(p), fd=fd, access=access, sharing=sharing)
    def GetFileInformationByHandle(self, handle, out):
        p = Path(self.record(handle)['path'])
        info = C.cast(out, C.POINTER(S.BY_HANDLE_FILE_INFORMATION)).contents
        meta = self.files.get(str(p), {})
        stat = p.lstat()
        info.dwFileAttributes = (0x10 if p.is_dir() else 0x80) | (0x400 if p.is_symlink() or meta.get('reparse') else 0)
        info.dwVolumeSerialNumber, info.nFileIndexHigh, info.nFileIndexLow = 7, stat.st_ino >> 32, stat.st_ino & 0xffffffff
        info.nFileSizeHigh, info.nFileSizeLow = stat.st_size >> 32, stat.st_size & 0xffffffff
        info.nNumberOfLinks = stat.st_nlink if p.is_file() else 1
        return 1
    def GetFileInformationByHandleEx(self, handle, kind, out, size):
        assert kind == 9 and size == 8
        info = S.BY_HANDLE_FILE_INFORMATION()
        self.GetFileInformationByHandle(handle, C.byref(info))
        result = C.cast(out, C.POINTER(S.FILE_ATTRIBUTE_TAG_INFO)).contents
        meta = self.files.get(self.record(handle)['path'], {})
        result.FileAttributes = meta.get('tag_attributes', info.dwFileAttributes)
        result.ReparseTag = meta.get('tag', 0xA000000C if info.dwFileAttributes & 0x400 else 0)
        return 1
    def GetVolumeInformationByHandleW(self, handle, name, length, serial, maxlen, flags, fs, fslen):
        kind = self.files.get(self.record(handle)['path'], {}).get('fs', 'NTFS')
        C.memmove(fs, S.wide(kind), (len(kind)+1)*2)
        return 1
    def GetFinalPathNameByHandleW(self, handle, out, size, flags):
        name = '\\\\?\\C:\\fixture'
        C.memmove(out,S.wide(name),(len(name)+1)*2)
        return len(name)
    def GetDriveTypeW(self, root): return self.drive_type
    def GetSecurityInfo(self, handle, kind, flags, owner, group, dacl, sacl, descriptor):
        meta = self.files.get(self.record(handle)['path'], {})
        sid = meta.get('owner', self.sid)
        put(owner, S.P, self.buffer(C.create_string_buffer(sid)))
        default_sid = self.sid if meta.get('private', True) else bytes.fromhex('010100000000000100000000')
        entries = meta.get('aces', [(0, 3, 0x1f01ff, default_sid)])
        if entries is None:
            put(dacl, S.P, 0)
        else:
            # SDK ACL header (8 bytes) followed by real ACE headers and SID bytes.
            raw_aces = [struct.pack('<BBHI', kind, flags, 8 + len(sid), mask) + sid
                        for kind, flags, mask, sid in entries]
            raw = struct.pack('<BBHHH', 2, 0, 8 + sum(map(len, raw_aces)), len(entries), 0) + b''.join(raw_aces)
            address = self.buffer(C.create_string_buffer(raw))
            offsets, offset = [], 8
            for ace in raw_aces:
                offsets.append(offset)
                offset += len(ace)
            self.acls[address] = offsets
            put(dacl, S.P, address)
        sd = self.buffer(C.create_string_buffer(64))
        self.descriptors[sd] = meta.get('protected', True)
        put(descriptor, S.P, sd)
        return 0
    def GetSecurityDescriptorControl(self, descriptor, control, rev):
        put(control, S.U16, 0x1000 if self.descriptors[descriptor] else 0)
        put(rev, S.U32, 1)
        return 1
    def GetAce(self, acl, index, out):
        offsets = self.acls[acl]
        if index >= len(offsets):
            return self.fail(87)
        put(out, S.P, acl + offsets[index])
        return 1
    def LockFileEx(self, handle, flags, reserved, low, high, overlap):
        ov = C.cast(overlap, C.POINTER(S.OVERLAPPED)).contents
        assert (reserved, low, high, ov.data.offsets.Offset, ov.data.offsets.OffsetHigh) == (0, 1, 0, 0, 0)
        assert flags & 1
        path = self.record(handle)['path']
        shared = not bool(flags & 2)
        if any(self.record(h)['path'] == path and not (s and shared) for h, s in self.locks.items()):
            return self.fail(33)
        self.locks[handle] = shared
        return 1
    def UnlockFileEx(self, handle, reserved, low, high, overlap):
        assert (reserved, low, high) == (0, 1, 0)
        self.locks.pop(handle, None)
        return 1
    def WriteFile(self, handle, buf, size, written, overlap):
        if self.record(handle)['kind']=='pipe':
            count=min(size,self.short_write or size)
            self.socket_out.extend(C.string_at(buf,count))
            put(written,S.U32,count)
            return 1
        size = min(size, self.short_write) if self.short_write else size
        count = os.write(self.record(handle)['fd'], C.string_at(buf, size))
        put(written, S.U32, count)
        return 1
    def FlushFileBuffers(self, handle):
        os.fsync(self.record(handle)['fd'])
        return 1
    def MoveFileExW(self, source, dest, flags):
        source, dest = text(source), text(dest)
        assert flags == 9
        # NTFS share checking excludes metadata-only handles (READ_CONTROL).
        for row in self.handles.values():
            if (row.get('path') in (source, dest) and row.get('access', 0) & 0xF0010027
                    and not row.get('sharing', 0) & 4):
                return self.fail(32)
        os.replace(source, dest)
        self.files[dest] = self.files.pop(source, {})
        return 1
    def DeleteFileW(self, path):
        Path(text(path)).unlink()
        return 1
    def IsProcessInJob(self, process, job, out):
        put(out, S.I32, int(self.in_job))
        return 1
    def GetConsoleWindow(self): return 0
    def SetHandleInformation(self, handle, mask, flags):
        assert handle in self.handles and (mask,flags)==(1,0)
        return 1
    def WSAStartup(self, version, data):
        assert version==0x202
        self.ws_count+=1
        return 0
    def WSACleanup(self):
        self.ws_count-=1
        return 0
    def WSAGetLastError(self): return self.ws_error
    def socket(self, family, kind, protocol):
        assert (family,kind,protocol)==(1,1,0)
        return self.alloc('socket')
    def closesocket(self, handle):
        self.CloseHandle(handle)
        return 0
    def ioctlsocket(self, handle, code, value):
        assert code & 0xffffffff==0x8004667e
        assert C.cast(value,C.POINTER(S.U32)).contents.value==1
        return 0
    def connect(self, handle, address, size):
        assert size==110 and C.cast(address,C.POINTER(S.SOCKADDR_UN)).contents.sun_family==1
        return 0
    def WSAIoctl(self, handle, code, src, srclen, target, size, written, overlap, callback):
        assert handle in self.handles and self.record(handle)['kind']=='socket', 'truncated SOCKET'
        assert code==0x58000100 and size==4
        if self.peer_written: put(target,S.U32,self.peer)
        put(written,S.U32,self.peer_bytes)
        return 0
    def select(self, n, reads, writes, errors, timeout):
        return 0 if self.ws_error==10035 else 1
    def getsockopt(self, handle, level, option, out, size):
        put(out,S.U32,0)
        return 0
    def send(self, handle, buf, size, flags):
        if self.ws_error: return -1
        count=min(size,self.short_write or size)
        self.socket_out.extend(C.string_at(buf,count))
        return count
    def recv(self, handle, buf, size, flags):
        if self.ws_error: return -1
        data=bytes(self.socket_in[:size]);del self.socket_in[:size]
        C.memmove(buf,data,len(data))
        return len(data)
    def CreateEventW(self, attributes, manual, initial, name):
        assert not attributes and manual and not initial and name is None
        return self.alloc('event')
    def CreateNamedPipeW(self, name, flags, mode, instances, outsize, insize, timeout, sa):
        self._attributes(sa)
        assert flags==3|0x40000000|0x80000 and mode==8 and instances==1
        return self.alloc('pipe',path=text(name))
    def GetNamedPipeServerProcessId(self, handle, out):
        put(out,S.U32,self.peer)
        return 1
    GetNamedPipeClientProcessId=GetNamedPipeServerProcessId
    def ReadFile(self, handle, buf, size, count, overlap):
        if self.io_pending:
            self.pending[handle]=(overlap,buf,count,size)
            return self.fail(997)
        data=bytes(self.socket_in[:size]);del self.socket_in[:size]
        C.memmove(buf,data,len(data));put(count,S.U32,len(data))
        return 1
    def ConnectNamedPipe(self, handle, overlap):
        if self.io_pending:
            self.pending[handle]=(overlap,self.buffer(C.create_string_buffer(1)),None,1)
            return self.fail(997)
        return self.fail(535)
    def DisconnectNamedPipe(self, handle): return 1
    def WaitForSingleObject(self, event, timeout):
        if self.record(event)['kind']=='process':
            assert timeout==0
            return 0 if self.record(event)['pid'] in self.exited else 258
        return 258 if self.pending else 0
    def CancelIoEx(self, handle, overlap):
        assert handle in self.pending
        # OVERLAPPED + buffer must still be alive at cancellation and completion.
        C.cast(overlap,C.POINTER(S.OVERLAPPED)).contents.Internal=99
        return 1
    def GetOverlappedResult(self, handle, overlap, count, wait):
        assert not wait, 'unbounded wait'
        if self.cancel_stalls: return self.fail(996)
        if handle in self.pending:
            old,buf,_,size=self.pending.pop(handle)
            assert C.cast(old,C.POINTER(S.OVERLAPPED)).contents.Internal==99
            C.memmove(buf,b'Z',1)
            put(count,S.U32,0)
            return self.fail(995)
        return 1
