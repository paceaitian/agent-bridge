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


def fixture_fd(root, path, disposition):
    """Real fixture storage; sharing/ACL policy is enforced by Kernel, not CRT.

    Windows os.open defaults to text mode and omits FILE_SHARE_DELETE. Either
    would silently add host restrictions not present in our modeled CreateFileW.
    Only a regular leaf below this test's private root may use the native shim.
    """
    if not path.resolve().is_relative_to(root.resolve()):
        raise AssertionError('fixture_file_outside_root')
    if os.name != 'nt':
        return os.open(path, os.O_RDWR | (os.O_CREAT if disposition in (1, 4) else 0)
                       | (os.O_EXCL if disposition == 1 else 0), 0o600)
    import msvcrt
    native = C.WinDLL('kernel32', use_last_error=True)
    native.CreateFileW.argtypes = [C.c_wchar_p, S.U32, S.U32, S.P, S.U32, S.U32, S.H]
    native.CreateFileW.restype = S.H
    native.CloseHandle.argtypes = [S.H]
    native.CloseHandle.restype = S.I32
    handle = native.CreateFileW(str(path), 0xc0000000, 7, None, disposition, 0x200000, None)
    if handle == S.INVALID_HANDLE_VALUE:
        raise C.WinError(C.get_last_error())
    try:
        return msvcrt.open_osfhandle(handle, os.O_RDWR | os.O_BINARY)
    except BaseException:
        native.CloseHandle(handle)
        raise


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
            if self.name in {'SetSecurityInfo', 'GetSecurityInfo'}:
                return fault
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
        # Denying same-user elevated peers at OpenProcess is an unverified
        # fixture assumption, NOT Windows qualification. Security tests must
        # also cover token denial and queryable peers so downstream guards run.
        self.restricted_process_stage = 'process'  # also token/queryable
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
        self.logons = {}  # pid -> (AuthenticationId, SessionId, SECURITY_LOGON_TYPE)
        self.images = {}  # explicit executable paths for process image API tests
        self.environments = {}  # synthetic UTF-16 blocks, never host process memory
        self.environment_addresses = {}  # pid -> optional non-page-aligned base
        self.environment_limits = {}  # pid -> readable bytes from base; default ends at the last mapped page
        self.lsa_allocations = set()
        self.acls, self.descriptors = {}, {}
        self.descriptor_acls = {}
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
        if handle not in self.handles:
            raise AssertionError('unknown or truncated HANDLE/SOCKET')
        return self.handles[handle]

    def buffer(self, value):
        self.buffers.append(value)
        return C.addressof(value)

    def fail(self, error):
        self.error = error
        return 0

    def CloseHandle(self, handle):
        if handle not in self.handles:
            raise AssertionError('double close or truncated HANDLE')
        record = self.handles.pop(handle)
        if 'fd' in record:
            os.close(record['fd'])
        if record.get('delete_on_close'):
            path = Path(record['path'])
            path.relative_to(self.root)  # fixture-only exact leaf; never an external deletion
            path.unlink()
        self.locks.pop(handle, None)
        return 1

    def GetCurrentProcess(self): return self.current
    def GetCurrentProcessId(self): return self.current
    def restricted_process(self, pid):
        me, other = self.processes[self.current], self.processes[pid]
        return other[2] != me[2] or other[3] and not me[3]
    def OpenProcess(self, access, inherit, pid):
        assert access in (0x101000, 0x101010) and not inherit
        if pid not in self.processes:
            self.error = 87
            return 0
        if self.restricted_process_stage == 'process' and self.restricted_process(pid):
            return self.fail(5)
        return self.alloc('process', pid=pid, access=access)
    def IsWow64Process(self, handle, out):
        put(out, S.I32, 0)
        return 1
    def NtQueryInformationProcess(self, handle, kind, out, size, returned):
        assert kind == 0 and size == 48
        if self.record(handle)['pid'] not in self.environments:
            return -1073741790
        data = (S.P * 6)(0, 0x10000, 0, 0, self.record(handle)['pid'], 0)
        C.memmove(out, data, 48)
        return 0
    def ReadProcessMemory(self, handle, address, out, size, returned):
        record = self.record(handle)
        assert record['access'] & 0x10
        pid = record['pid']
        base = self.environment_addresses.get(pid, 0x30000)
        if address == 0x10020:
            data = (0x20000).to_bytes(8, 'little')
        elif address == 0x20080:
            data = base.to_bytes(8, 'little')
        elif address >= base:
            block = self.environments[pid]
            limit = self.environment_limits.get(pid, ((base + len(block) + 4095) // 4096) * 4096 - base)
            offset = address - base
            if offset + size > limit:
                return self.fail(299)
            # Zero padding models only the readable tail of the final mapped
            # page; an unmapped next page must not manufacture a terminator.
            data = block[offset:offset+size].ljust(size, b'\0')
        else:
            return self.fail(299)
        assert len(data) == size
        C.memmove(out, data, size); put(returned, C.c_size_t, size)
        return 1
    def GetProcessTimes(self, handle, creation, exit_, kernel, user):
        fact = self.processes[self.record(handle)['pid']]
        t = C.cast(creation, C.POINTER(S.FILETIME)).contents
        t.dwLowDateTime, t.dwHighDateTime = fact[1] & 0xffffffff, fact[1] >> 32
        return 1
    def GetExitCodeProcess(self, handle, out):
        put(out, S.U32, 259)
        return 1
    def QueryFullProcessImageNameW(self, handle, flags, output, size):
        assert flags == 0
        pid = self.record(handle)['pid']
        if pid not in self.images:
            return self.fail(5)
        raw = self.images[pid].encode('utf-16-le', 'surrogatepass')
        capacity = C.cast(size, C.POINTER(S.U32)).contents.value
        if len(raw)//2 >= capacity:
            return self.fail(122)
        C.memmove(output, raw+b'\0\0', len(raw)+2)
        put(size, S.U32, len(raw)//2)
        return 1
    def OpenProcessToken(self, handle, access, out):
        assert access == 8
        pid = handle if handle == self.current else self.record(handle)['pid']
        if self.restricted_process_stage == 'token' and self.restricted_process(pid):
            return self.fail(5)
        put(out, S.H, self.alloc('token', pid=pid))
        return 1
    def GetTokenInformation(self, handle, kind, buf, size, needed):
        pid = self.record(handle)['pid']
        fact = self.processes[pid]
        if kind == 1:
            put(needed, S.U32, 16)
            if not buf: return self.fail(122)
            ptr = self.buffer(C.create_string_buffer(fact[2]))
            put(buf, S.P, ptr)
        elif kind == 10:
            assert size == C.sizeof(S.TOKEN_STATISTICS)
            value = C.cast(buf, C.POINTER(S.TOKEN_STATISTICS)).contents
            luid, _, _ = self.logons.get(pid, (123, 1, 2))
            value.TokenId.LowPart = 999  # must compare AuthenticationId, not TokenId
            value.AuthenticationId.LowPart = luid & 0xffffffff
            value.AuthenticationId.HighPart = luid >> 32
            put(needed, S.U32, C.sizeof(value))
        elif kind == 12:
            assert size == 4
            put(needed, S.U32, 4)
            put(buf, S.U32, self.logons.get(pid, (123, 1, 2))[1])
        else:
            assert kind == 20 and size == 4
            put(needed, S.U32, 4)
            put(buf, S.U32, int(fact[3]))
        return 1
    def LsaGetLogonSessionData(self, luid_pointer, out):
        luid = C.cast(luid_pointer, C.POINTER(S.LUID)).contents
        number = (luid.HighPart << 32) | luid.LowPart
        _, session, kind = next((v for v in self.logons.values() if v[0] == number), (123, 1, 2))
        row = S.SECURITY_LOGON_SESSION_PREFIX()
        row.Size, row.LogonId = C.sizeof(row), luid
        row.LogonType, row.Session = kind, session
        row.UserName.Buffer = row.LogonDomain.Buffer = row.AuthenticationPackage.Buffer = 1
        address = self.buffer(row)
        self.lsa_allocations.add(address)
        put(out, S.P, address)
        return 0
    def LsaFreeReturnBuffer(self, pointer):
        assert pointer in self.lsa_allocations
        self.lsa_allocations.remove(pointer)
        return 0
    def IsValidSid(self, ptr): return 1 if ptr else 0
    def GetLengthSid(self, ptr): return 8 + C.string_at(ptr, 2)[1] * 4
    def ConvertSidToStringSidW(self, sid, out):
        put(out, S.P, self.buffer(S.wide('S-1-5-42')))
        return 1
    def ConvertStringSecurityDescriptorToSecurityDescriptorW(self, string, revision, out, size):
        value = text(string)
        assert value in {'O:S-1-5-42D:P(A;OICI;FA;;;S-1-5-42)(A;OICI;FA;;;SY)',
                         'O:S-1-5-42D:P(A;;FA;;;S-1-5-42)(A;;FA;;;SY)'}
        flags = 3 if 'OICI' in value else 0
        entries = [(0, flags, 0x1f01ff, self.sid), (0, flags, 0x1f01ff, bytes.fromhex('010100000000000512000000'))]
        raw = b''.join(struct.pack('<BBHI', k, f, 8+len(s), m)+s for k,f,m,s in entries)
        acl = self.buffer(C.create_string_buffer(struct.pack('<BBHHH',2,0,8+len(raw),2,0)+raw))
        sd = self.buffer(C.create_string_buffer(64))
        self.descriptor_acls[sd] = acl
        put(out, S.P, sd)
        return 1
    def GetSecurityDescriptorDacl(self, descriptor, present, dacl, defaulted):
        put(present, S.I32, 1);put(defaulted, S.I32, 0)
        put(dacl, S.P, self.descriptor_acls[descriptor])
        return 1
    def SetSecurityInfo(self, handle, kind, flags, owner, group, dacl, sacl):
        record = self.record(handle)
        if flags == 1:
            if not record['access'] & 0x80000:
                return 5  # WRITE_OWNER is an access requirement, not an exact-mask oracle.
            assert (kind, group, dacl, sacl) == (1, None, None, None)
            if not owner or C.string_at(owner, self.GetLengthSid(owner)) != self.sid:
                return 1307  # ordinary token may assign its own SID only in this fixture
            self.files.setdefault(record['path'], {})['owner'] = self.sid
            return 0
        if not record['access'] & 0x40000:
            return 5  # WRITE_DAC required
        assert (kind, flags, owner, group, sacl) == (1, 0x80000004, None, None, None)
        revision, _, size, count, _ = struct.unpack('<BBHHH', C.string_at(dacl,8))
        assert revision == 2 and dacl and 8 <= size <= 1024
        entries, offset = [], 8
        for _ in range(count):
            k,f,n,m = struct.unpack('<BBHI', C.string_at(dacl+offset,8))
            entries.append((k,f,m,C.string_at(dacl+offset+8,n-8)))
            offset += n
        assert offset == size
        meta = self.files.setdefault(record['path'], {})
        meta.update(aces=entries, protected=True, private=True, deny_data=False)
        if record['kind'] == 'directory':
            parent = Path(record['path'])
            # Model inheritable ACEs on known private fixture objects, including
            # hardlink aliases. Never enumerate an external directory tree.
            for name, child in list(self.files.items()):
                path = Path(name)
                if path == parent or not path.is_relative_to(parent) or child.get('protected', True):
                    continue
                inherited = [(k, (f | 0x10) if path.is_dir() else 0x10, m, s)
                             for k, f, m, s in entries if f & (2 if path.is_dir() else 1)]
                explicit = [ace for ace in child.get('aces', []) if not ace[1] & 0x10]
                child['aces'] = explicit + inherited
                if path.is_file():
                    for alias, other in list(self.files.items()):
                        if alias != name and Path(alias).is_file() and os.path.samefile(path, alias):
                            other['aces'] = list(child['aces'])
        return 0
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
        assert sharing in (0,3,7) and flags & 0x200000, 'no directory pin/reparse guard'
        p = Path(text(path))
        if self.files.get(str(p), {}).get('deny_owner') and access & 0x80000:
            self.error = 5
            return S.INVALID_HANDLE_VALUE
        # Owner metadata rights do not imply FILE_LIST_DIRECTORY/data access.
        if self.files.get(str(p),{}).get('deny_data') and access & 0xc0000001:
            self.error=5
            return S.INVALID_HANDLE_VALUE
        def data_access(mask):
            return ((1 if mask & 0xb0000021 else 0) | (2 if mask & 0x50000006 else 0)
                    | (4 if mask & 0x10010000 else 0))
        wanted = data_access(access)
        for record in self.handles.values():
            existing = data_access(record.get('access', 0))
            if (record.get('path') == str(p) and wanted and existing
                    and (wanted & ~record.get('sharing', 0) or existing & ~sharing)):
                self.error=32
                return S.INVALID_HANDLE_VALUE
        if not p.exists() and disposition == 3:
            self.error = 2
            return S.INVALID_HANDLE_VALUE
        if flags & 0x2000000:
            return self.alloc('directory', path=str(p), access=access, sharing=sharing)
        if disposition == 1 and p.exists():
            self.error = 80
            return S.INVALID_HANDLE_VALUE
        existed = p.exists()
        fd = fixture_fd(self.root, p, disposition)
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
        if kind == 18:
            if size != 24:
                raise AssertionError('FILE_ID_INFO size')
            record = self.record(handle)
            meta = self.files.get(record['path'], {})
            info = C.cast(out, C.POINTER(S.FILE_ID_INFO)).contents
            info.VolumeSerialNumber = meta.get('volume64', 2082046436356788024)
            number = meta.get('file_id128', os.fstat(record['fd']).st_ino)
            for index, value in enumerate(number.to_bytes(16, 'little')):
                info.FileId[index] = value
            return 1
        assert kind == 9 and size == 8
        info = S.BY_HANDLE_FILE_INFORMATION()
        self.GetFileInformationByHandle(handle, C.byref(info))
        result = C.cast(out, C.POINTER(S.FILE_ATTRIBUTE_TAG_INFO)).contents
        meta = self.files.get(self.record(handle)['path'], {})
        result.FileAttributes = meta.get('tag_attributes', info.dwFileAttributes)
        result.ReparseTag = meta.get('tag', 0xA000000C if info.dwFileAttributes & 0x400 else 0)
        return 1
    def SetFileInformationByHandle(self, handle, kind, value, size):
        record = self.record(handle)
        if kind != 4 or size != 1:
            raise AssertionError('unexpected disposition class/size')
        if not record.get('access', 0) & 0x10000:
            return self.fail(5)
        if C.cast(value, C.POINTER(C.c_ubyte)).contents.value != 1:
            raise AssertionError('DeleteFile must be TRUE')
        record['delete_on_close'] = True
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
        if flags == 1:
            put(descriptor, S.P, self.buffer(C.create_string_buffer(64)))
            return 0
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
        # Conservative MoveFileExW target model from third-party NTFS reports:
        # even FILE_SHARE_DELETE does not permit replacing an occupied target.
        if any(row.get('path') == dest for row in self.handles.values()):
            return self.fail(5)
        # NTFS share checking excludes metadata-only handles (READ_CONTROL).
        for row in self.handles.values():
            if (row.get('path') == source and row.get('access', 0) & 0xF0010027
                    and not row.get('sharing', 0) & 4):
                return self.fail(32)
        os.replace(source, dest)
        self.files[dest] = self.files.pop(source, {})
        return 1
    def DeleteFileW(self, path):
        path = text(path)
        for row in self.handles.values():
            if (row.get('path') == path and row.get('access', 0) & 0xF0010027
                    and not row.get('sharing', 0) & 4):
                return self.fail(32)
        Path(path).unlink()
        self.files.pop(path, None)
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
        record = self.record(handle)
        if record['kind'] == 'file':
            assert overlap is None and record['access'] & 1
            data = os.read(record['fd'], size)
            C.memmove(buf, data, len(data)); put(count, S.U32, len(data))
            return 1
        if self.io_pending:
            self.pending[handle]=(overlap,buf,count,size)
            return self.fail(997)
        data=bytes(self.socket_in[:size]);del self.socket_in[:size]
        C.memmove(buf,data,len(data));put(count,S.U32,len(data))
        return 1
    def ConnectNamedPipe(self, handle, overlap):
        code = self.record(handle).get('connect_error')
        if code is not None:
            return self.fail(code)  # 232: buffered closed client; 231: busy, never success.
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
