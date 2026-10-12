"""有限 Win32 API 封装；DLL/last-error 可注入，固定原因码，不输出 SID/路径。"""
from __future__ import annotations
import ctypes as C
from contextlib import contextmanager
from dataclasses import dataclass, field
from collections.abc import Iterator, Callable, Mapping
from typing import Any
import uuid

from . import abi as A


class WinFailure(OSError):
    def __init__(self, code: int, reason: str = 'windows_api_failed') -> None:
        super().__init__(code, reason)
        self.winerror = code  # after OSError initialization (also on native Windows)


@dataclass(frozen=True)
class Token:
    sid: bytes = field(repr=False)
    elevated: bool


@dataclass(frozen=True)
class ProcessFact:
    pid: int
    birth: int
    token: Token


class WinApi:
    def __init__(self, libraries: Mapping[str, Any] | None = None,
                 last_error: Callable[[], int] | None = None) -> None:
        if libraries is None:
            loader = getattr(C, 'WinDLL', None)
            if loader is None:
                raise OSError('windows_api_unavailable')
            libraries = {name: loader(name, use_last_error=True) for name in A.SIGNATURES}
        self.dll = dict(libraries)
        self.last_error = last_error or getattr(C, 'get_last_error', lambda: 0)
        for name, funcs in A.SIGNATURES.items():
            for symbol, (result, args) in funcs.items():
                fn = getattr(self.dll[name], symbol)
                fn.restype, fn.argtypes = result, args
        self.k = self.dll['kernel32']
        self.a = self.dll['advapi32']
        self.ws = self.dll['ws2_32']
        self._winsock = False

    def check(self, result: object) -> None:
        if not result:
            raise WinFailure(self.last_error())

    def handle(self, value: int | None) -> int:
        if value in (None, 0, A.INVALID):
            raise WinFailure(self.last_error())
        assert value is not None
        return value

    def close(self, handle: int) -> None:
        self.check(self.k.CloseHandle(handle))

    @contextmanager
    def owned(self, handle: int) -> Iterator[int]:
        try:
            yield handle
        finally:
            self.close(handle)

    def _sid(self, pointer: Any) -> bytes:
        if not pointer or not self.a.IsValidSid(pointer):
            raise OSError('windows_identity_unknown')
        size = self.a.GetLengthSid(pointer)
        if not 8 <= size <= 68:
            raise OSError('windows_identity_unknown')
        return C.string_at(pointer, size)

    def token(self, process: int) -> Token:
        out = A.HANDLE()
        self.check(self.a.OpenProcessToken(process, 8, C.byref(out)))
        with self.owned(self.handle(out.value)) as token:
            needed = A.DWORD()
            # TokenUser is a SID_AND_ATTRIBUTES at the beginning; bounded buffer.
            self.a.GetTokenInformation(token, 1, None, 0, C.byref(needed))
            if not 8 <= needed.value <= 65536:
                raise OSError('windows_identity_unknown')
            buf = C.create_string_buffer(needed.value)
            self.check(self.a.GetTokenInformation(token, 1, buf, len(buf), C.byref(needed)))
            sid = self._sid(C.cast(buf, C.POINTER(A.PTR)).contents.value)
            elevated = A.DWORD()
            self.check(self.a.GetTokenInformation(token, 20, C.byref(elevated), 4, C.byref(needed)))
            if needed.value != 4 or elevated.value not in (0, 1):
                raise OSError('windows_identity_unknown')
            return Token(sid, bool(elevated.value))

    def current_token(self) -> Token:
        token = self.token(self.k.GetCurrentProcess())
        if token.elevated:
            raise OSError('windows_elevated_unsupported')
        return token

    def process(self, pid: int, *, expected_birth: str | None = None) -> ProcessFact:
        if isinstance(pid, bool) or not 0 < pid < 2**32:
            raise WinFailure(87, 'windows_process_invalid')
        # Both creation time and token come from this one process handle.
        with self.owned(self.handle(self.k.OpenProcess(0x1000 | 0x100000, False, pid))) as handle:
            times = [A.FILETIME() for _ in range(4)]
            self.check(self.k.GetProcessTimes(handle, *(C.byref(t) for t in times)))
            if expected_birth is not None and str(times[0].number()) != expected_birth:
                raise WinFailure(1168, 'windows_process_reused')
            wait = self.k.WaitForSingleObject(handle, 0)
            if wait == 0:
                raise WinFailure(1168, 'windows_process_exited')
            if wait != 258:
                # WAIT_FAILED 不能证明 PID 已不存在；不带 winerror 上抛，免得 87/1168 落进 EXITED 投影
                raise OSError('windows_process_unverified')
            if times[0].number() <= 0:
                raise OSError('windows_identity_unknown')
            return ProcessFact(pid, times[0].number(), self.token(handle))

    def process_table(self) -> list[tuple[int, int, str]]:
        with self.owned(self.handle(self.k.CreateToolhelp32Snapshot(2, 0))) as handle:
            entry = A.PROCESSENTRY32W()
            entry.size = C.sizeof(entry)
            ok = self.k.Process32FirstW(handle, C.byref(entry))
            rows = []
            while ok:
                if len(rows) >= 65536:
                    raise OSError('windows_process_table_incomplete')
                try:
                    name = A.read_wide(entry.exe)
                except ValueError as error:
                    raise OSError('windows_process_name_unverified') from error
                rows.append((int(entry.pid), int(entry.ppid), name))
                ok = self.k.Process32NextW(handle, C.byref(entry))
            if self.last_error() != 18:
                raise WinFailure(self.last_error())
            return rows

    def local_app_data(self) -> str:
        folder = (C.c_ubyte * 16).from_buffer_copy(uuid.UUID('f1b32785-6fba-4fcf-9d55-7b8e7f157091').bytes_le)
        out = A.PTR()
        if self.dll['shell32'].SHGetKnownFolderPath(folder, 0, None, C.byref(out)) != 0 or not out.value:
            raise OSError('windows_known_folder_unavailable')
        try:
            ptr = C.cast(out, C.POINTER(A.WCHAR))
            units = []
            for i in range(32767):
                if ptr[i] == 0:
                    return A.read_wide((A.WCHAR * (len(units) + 1))(*units, 0))
                units.append(ptr[i])
            raise OSError('windows_path_invalid')
        finally:
            self.dll['ole32'].CoTaskMemFree(out)

    @contextmanager
    def private_attributes(self) -> Iterator[A.SECURITY_ATTRIBUTES]:
        sid = self.current_token().sid
        raw = C.create_string_buffer(sid)
        sid_text = A.PTR()
        self.check(self.a.ConvertSidToStringSidW(raw, C.byref(sid_text)))
        try:
            ptr = C.cast(sid_text, C.POINTER(A.WCHAR))
            chars = []
            for i in range(256):
                if ptr[i] == 0:
                    break
                chars.append(chr(ptr[i]))
            else:
                raise OSError('windows_identity_unknown')
            principal = ''.join(chars)
        finally:
            self.k.LocalFree(sid_text)
        descriptor = A.PTR()
        # Private at creation; inheritance only to our children, protected DACL.
        sddl = f'O:{principal}D:P(A;OICI;FA;;;{principal})(A;OICI;FA;;;SY)'
        self.check(self.a.ConvertStringSecurityDescriptorToSecurityDescriptorW(
            A.wide(sddl), 1, C.byref(descriptor), None))
        try:
            yield A.SECURITY_ATTRIBUTES(C.sizeof(A.SECURITY_ATTRIBUTES), descriptor, False)
        finally:
            self.k.LocalFree(descriptor)

    def create_directory(self, path: str) -> None:
        with self.private_attributes() as sa:
            if not self.k.CreateDirectoryW(A.wide(path), C.byref(sa)) and self.last_error() != 183:
                raise WinFailure(self.last_error())

    def open_file(self, path: str, *, create: bool = False, write: bool = False,
                  directory: bool = False, exclusive_create: bool = False) -> int:
        flags = 0x00200000 | (0x02000000 if directory else 0x80)  # no reparse traversal
        # READ_CONTROL alone does not participate in NTFS sharing arbitration.
        # A directory lease needs FILE_LIST_DIRECTORY, not delete privileges.
        access = 0x20000 | (0x40000000 if write else 0) | (0x1 if directory else 0)
        disposition = 1 if exclusive_create else (4 if create else 3)
        # Never FILE_SHARE_DELETE; data-access directory leases pin this generation.
        with self.private_attributes() as sa:
            return self.handle(self.k.CreateFileW(A.wide(path), access, 3, C.byref(sa), disposition, flags, None))

    def file_info(self, handle: int, *, af_unix: bool = False) -> A.FILE_INFORMATION:
        info = A.FILE_INFORMATION()
        self.check(self.k.GetFileInformationByHandle(handle, C.byref(info)))
        if af_unix:
            # Exception ONLY for an AF_UNIX rendezvous leaf, never a directory.
            tag = A.FILE_ATTRIBUTE_TAG_INFO()
            self.check(self.k.GetFileInformationByHandleEx(handle, 9, C.byref(tag), C.sizeof(tag)))
            if (tag.tag != A.IO_REPARSE_TAG_AF_UNIX or tag.attributes != info.attributes
                    or not info.attributes & 0x400 or info.attributes & 0x10):
                raise OSError('windows_reparse_unsupported')
        elif info.attributes & 0x400:
            raise OSError('windows_reparse_unsupported')
        return info

    def check_ntfs(self, handle: int) -> None:
        final = (A.WCHAR * 32768)()
        length = self.k.GetFinalPathNameByHandleW(handle, final, len(final), 0)
        if not 0 < length < len(final):
            raise OSError('windows_path_unverified')
        name = A.read_wide(final)
        if not (name.startswith('\\\\?\\') and len(name) >= 7 and name[5:7] == ':\\'):
            raise OSError('windows_path_unsupported')
        if self.k.GetDriveTypeW(A.wide(name[4:7])) != 3:
            raise OSError('windows_volume_unsupported')
        fs = (A.WCHAR * 32)()
        self.check(self.k.GetVolumeInformationByHandleW(handle, None, 0, None, None, None, fs, 32))
        if A.read_wide(fs).upper() != 'NTFS':
            raise OSError('windows_filesystem_unsupported')

    def check_private(self, handle: int, *, protected: bool = False) -> None:
        principal = self.current_token().sid
        owner, dacl, descriptor = A.PTR(), A.PTR(), A.PTR()
        status = self.a.GetSecurityInfo(handle, 1, 5, C.byref(owner), None, C.byref(dacl), None, C.byref(descriptor))
        if status:
            raise WinFailure(status)
        try:
            if self._sid(owner) != principal or not dacl.value:
                raise OSError('windows_acl_untrusted')
            control, revision = A.WORD(), A.DWORD()
            self.check(self.a.GetSecurityDescriptorControl(descriptor, C.byref(control), C.byref(revision)))
            if protected and not control.value & 0x1000:
                raise OSError('windows_acl_untrusted')
            acl = C.cast(dacl, C.POINTER(A.ACL)).contents
            if not 0 < acl.count <= 128:
                raise OSError('windows_acl_untrusted')
            system = bytes.fromhex('010100000000000512000000')
            own_allow = False
            for index in range(acl.count):
                pointer = A.PTR()
                self.check(self.a.GetAce(dacl, index, C.byref(pointer)))
                if pointer.value is None:
                    raise OSError('windows_acl_untrusted')
                ace = C.cast(pointer, C.POINTER(A.ACE)).contents
                if ace.kind not in (0, 1) or ace.size < 16:
                    raise OSError('windows_acl_untrusted')
                sid = self._sid(pointer.value + 8)
                # Reject unknown grant types and any grants to other principals.
                if ace.kind == 0 and sid not in (principal, system):
                    raise OSError('windows_acl_untrusted')
                if ace.kind == 0 and sid == principal and not ace.flags & 8 and (ace.mask & 0x1f01ff) == 0x1f01ff:
                    own_allow = True
            if not own_allow:
                raise OSError('windows_acl_untrusted')
        finally:
            if descriptor.value:
                self.k.LocalFree(descriptor)

    def lock(self, handle: int, *, shared: bool) -> None:
        overlap = A.OVERLAPPED()  # [0,1), identical for shared probes/exclusive holders
        if not self.k.LockFileEx(handle, 1 | (0 if shared else 2), 0, 1, 0, C.byref(overlap)):
            code = self.last_error()
            if code == 33:
                raise BlockingIOError('windows_lock_conflict')
            raise WinFailure(code)

    def unlock(self, handle: int) -> None:
        overlap = A.OVERLAPPED()
        self.check(self.k.UnlockFileEx(handle, 0, 1, 0, C.byref(overlap)))

    def write(self, handle: int, data: bytes) -> None:
        cursor = 0
        while cursor < len(data):
            buf = C.create_string_buffer(data[cursor:])
            written = A.DWORD()
            self.check(self.k.WriteFile(handle, buf, len(data) - cursor, C.byref(written), None))
            if not 0 < written.value <= len(data) - cursor:
                raise OSError('windows_short_write')
            cursor += written.value

    def flush(self, handle: int) -> None:
        self.check(self.k.FlushFileBuffers(handle))

    def replace(self, source: str, dest: str) -> None:
        self.check(self.k.MoveFileExW(A.wide(source), A.wide(dest), 1 | 8))

    def delete(self, path: str) -> None:
        self.check(self.k.DeleteFileW(A.wide(path)))

    def context(self) -> dict[str, bool]:
        in_job = A.BOOL()
        self.check(self.k.IsProcessInJob(self.k.GetCurrentProcess(), None, C.byref(in_job)))
        return {'consoleDetached': not bool(self.k.GetConsoleWindow()), 'inJob': bool(in_job.value),
                'outlivesJob': False}  # never inferred from DETACHED_PROCESS
