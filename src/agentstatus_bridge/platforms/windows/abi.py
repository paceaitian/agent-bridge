"""Windows LLP64 ABI，用固定宽度类型；Linux 的 c_long/wchar 大小不是 Windows ABI。"""
import ctypes as C

DWORD = C.c_uint32
WORD = C.c_uint16
BOOL = C.c_int32
HANDLE = C.c_void_p
SOCKET = C.c_size_t
PTR = C.c_void_p
WCHAR = C.c_uint16
INVALID = C.c_void_p(-1).value
IO_REPARSE_TAG_AF_UNIX = 0x80000023


class FILE_ATTRIBUTE_TAG_INFO(C.Structure):
    _fields_ = [('attributes', DWORD), ('tag', DWORD)]


class FILE_ID_INFO(C.Structure):
    _fields_ = [('volume', C.c_uint64), ('file_id', C.c_ubyte * 16)]


class FILETIME(C.Structure):
    _fields_ = [('low', DWORD), ('high', DWORD)]

    def number(self) -> int:
        return (int(self.high) << 32) | int(self.low)


class LUID(C.Structure):
    _fields_ = [('low', DWORD), ('high', C.c_int32)]


class TOKEN_STATISTICS(C.Structure):
    _fields_ = [('token', LUID), ('authentication', LUID), ('expiration', C.c_int64),
                ('kind', C.c_int32), ('impersonation', C.c_int32), ('charged', DWORD),
                ('available', DWORD), ('groups', DWORD), ('privileges', DWORD), ('modified', LUID)]


class LSA_STRING(C.Structure):
    _fields_ = [('length', WORD), ('maximum', WORD), ('buffer', PTR)]


class LOGON_PREFIX(C.Structure):
    # Only this numeric prefix is read, never dereference user/domain/auth strings.
    _fields_ = [('size', DWORD), ('id', LUID), ('user', LSA_STRING),
                ('domain', LSA_STRING), ('auth', LSA_STRING), ('kind', DWORD), ('session', DWORD)]


class SECURITY_ATTRIBUTES(C.Structure):
    _fields_ = [('length', DWORD), ('descriptor', PTR), ('inherit', BOOL)]


class OVERLAPPED(C.Structure):
    _fields_ = [('internal', C.c_size_t), ('internal_high', C.c_size_t),
                ('offset', DWORD), ('offset_high', DWORD), ('event', HANDLE)]


class PROCESSENTRY32W(C.Structure):
    _fields_ = [('size', DWORD), ('usage', DWORD), ('pid', DWORD), ('heap', C.c_size_t),
                ('module', DWORD), ('threads', DWORD), ('ppid', DWORD), ('priority', C.c_int32),
                ('flags', DWORD), ('exe', WCHAR * 260)]


class UNICODE_STRING(C.Structure):
    # Win64：Length/MaximumLength 后有 4 字节对齐，Buffer 在偏移 8（§92.3 class 60 返回的头）
    _fields_ = [('length', WORD), ('maximum', WORD), ('buffer', PTR)]


class FILE_INFORMATION(C.Structure):
    _fields_ = [('attributes', DWORD), ('creation', FILETIME), ('access', FILETIME),
                ('write', FILETIME), ('volume', DWORD), ('size_high', DWORD), ('size_low', DWORD),
                ('links', DWORD), ('index_high', DWORD), ('index_low', DWORD)]


class ACL(C.Structure):
    _fields_ = [('revision', C.c_uint8), ('sbz1', C.c_uint8), ('size', WORD),
                ('count', WORD), ('sbz2', WORD)]


class ACE(C.Structure):
    _fields_ = [('kind', C.c_uint8), ('flags', C.c_uint8), ('size', WORD), ('mask', DWORD)]


class SOCKADDR_UN(C.Structure):
    _fields_ = [('family', WORD), ('path', C.c_char * 108)]


class TIMEVAL(C.Structure):
    _fields_ = [('sec', C.c_int32), ('usec', C.c_int32)]


class FD_SET(C.Structure):
    _fields_ = [('count', DWORD), ('sockets', SOCKET * 64)]


def wide(value: str) -> C.Array:
    if '\0' in value or len(value.encode('utf-16-le', 'surrogatepass')) > 65532:
        raise OSError('windows_path_invalid')
    raw = value.encode('utf-16-le', 'surrogatepass') + b'\0\0'
    return (WCHAR * (len(raw) // 2)).from_buffer_copy(raw)


def read_wide(value: C.Array, length: int | None = None) -> str:
    count = len(value) if length is None else length
    if not 0 <= count <= len(value):
        raise ValueError('wide_length_invalid')
    raw = C.string_at(C.addressof(value), count * C.sizeof(WCHAR))
    return raw.decode('utf-16-le', 'surrogatepass').partition('\0')[0]


# 每个实际调用都显式声明；不依赖ctypes默认c_int，尤其HANDLE/SOCKET。
SIGNATURES = {
    'kernel32': {
        'GetCurrentProcess': (HANDLE, []), 'GetCurrentProcessId': (DWORD, []),
        'OpenProcess': (HANDLE, [DWORD, BOOL, DWORD]), 'CloseHandle': (BOOL, [HANDLE]),
        'ReadProcessMemory': (BOOL, [HANDLE, PTR, PTR, C.c_size_t, PTR]),
        'IsWow64Process': (BOOL, [HANDLE, PTR]),
        'GetProcessTimes': (BOOL, [HANDLE, PTR, PTR, PTR, PTR]),
        'QueryFullProcessImageNameW': (BOOL, [HANDLE, DWORD, PTR, PTR]),
        'GetExitCodeProcess': (BOOL, [HANDLE, PTR]),
        'CreateToolhelp32Snapshot': (HANDLE, [DWORD, DWORD]),
        'Process32FirstW': (BOOL, [HANDLE, PTR]), 'Process32NextW': (BOOL, [HANDLE, PTR]),
        'LocalFree': (PTR, [PTR]), 'LocalSize': (C.c_size_t, [PTR]),
        'CreateFileW': (HANDLE, [PTR, DWORD, DWORD, PTR, DWORD, DWORD, HANDLE]),
        'CreateDirectoryW': (BOOL, [PTR, PTR]),
        'GetFileInformationByHandle': (BOOL, [HANDLE, PTR]),
        'GetFileInformationByHandleEx': (BOOL, [HANDLE, C.c_int32, PTR, DWORD]),
        'SetFileInformationByHandle': (BOOL, [HANDLE, C.c_int32, PTR, DWORD]),
        'GetVolumeInformationByHandleW': (BOOL, [HANDLE, PTR, DWORD, PTR, PTR, PTR, PTR, DWORD]),
        'GetFinalPathNameByHandleW': (DWORD, [HANDLE, PTR, DWORD, DWORD]),
        'GetDriveTypeW': (DWORD, [PTR]),
        'LockFileEx': (BOOL, [HANDLE, DWORD, DWORD, DWORD, DWORD, PTR]),
        'UnlockFileEx': (BOOL, [HANDLE, DWORD, DWORD, DWORD, PTR]),
        'FlushFileBuffers': (BOOL, [HANDLE]),
        'WriteFile': (BOOL, [HANDLE, PTR, DWORD, PTR, PTR]),
        'ReadFile': (BOOL, [HANDLE, PTR, DWORD, PTR, PTR]),
        'SetFilePointerEx': (BOOL, [HANDLE, C.c_int64, PTR, DWORD]),
        'MoveFileExW': (BOOL, [PTR, PTR, DWORD]), 'DeleteFileW': (BOOL, [PTR]),
        'CreateEventW': (HANDLE, [PTR, BOOL, BOOL, PTR]),
        'WaitForSingleObject': (DWORD, [HANDLE, DWORD]),
        'GetOverlappedResult': (BOOL, [HANDLE, PTR, PTR, BOOL]),
        'CancelIoEx': (BOOL, [HANDLE, PTR]),
        'CreateNamedPipeW': (HANDLE, [PTR, DWORD, DWORD, DWORD, DWORD, DWORD, DWORD, PTR]),
        'ConnectNamedPipe': (BOOL, [HANDLE, PTR]), 'DisconnectNamedPipe': (BOOL, [HANDLE]),
        'GetNamedPipeServerProcessId': (BOOL, [HANDLE, PTR]),
        'GetNamedPipeClientProcessId': (BOOL, [HANDLE, PTR]),
        'IsProcessInJob': (BOOL, [HANDLE, HANDLE, PTR]),
        'GetConsoleWindow': (HANDLE, []),
        'SetHandleInformation': (BOOL, [HANDLE, DWORD, DWORD]),
    },
    'ntdll': {'NtQueryInformationProcess': (C.c_int32, [HANDLE, DWORD, PTR, DWORD, PTR])},
    'advapi32': {
        'OpenProcessToken': (BOOL, [HANDLE, DWORD, PTR]),
        'GetTokenInformation': (BOOL, [HANDLE, DWORD, PTR, DWORD, PTR]),
        'GetLengthSid': (DWORD, [PTR]), 'IsValidSid': (BOOL, [PTR]),
        'ConvertSidToStringSidW': (BOOL, [PTR, PTR]),
        'ConvertStringSecurityDescriptorToSecurityDescriptorW': (BOOL, [PTR, DWORD, PTR, PTR]),
        'GetSecurityInfo': (DWORD, [HANDLE, DWORD, DWORD, PTR, PTR, PTR, PTR, PTR]),
        'GetSecurityDescriptorControl': (BOOL, [PTR, PTR, PTR]),
        'GetSecurityDescriptorDacl': (BOOL, [PTR, PTR, PTR, PTR]),
        'SetSecurityInfo': (DWORD, [HANDLE, DWORD, DWORD, PTR, PTR, PTR, PTR]),
        'GetAce': (BOOL, [PTR, DWORD, PTR]),
    },
    'shell32': {'SHGetKnownFolderPath': (C.c_int32, [PTR, DWORD, HANDLE, PTR]),
                'CommandLineToArgvW': (PTR, [PTR, PTR])},
    'ole32': {'CoTaskMemFree': (None, [PTR])},
    'secur32': {'LsaGetLogonSessionData': (C.c_int32, [PTR, PTR]),
               'LsaFreeReturnBuffer': (C.c_int32, [PTR])},
    'ws2_32': {
        'WSAStartup': (C.c_int32, [WORD, PTR]), 'WSACleanup': (C.c_int32, []),
        'WSAGetLastError': (C.c_int32, []),
        'socket': (SOCKET, [C.c_int32, C.c_int32, C.c_int32]),
        'closesocket': (C.c_int32, [SOCKET]),
        'ioctlsocket': (C.c_int32, [SOCKET, C.c_int32, PTR]),
        'connect': (C.c_int32, [SOCKET, PTR, C.c_int32]),
        'bind': (C.c_int32, [SOCKET, PTR, C.c_int32]),
        'listen': (C.c_int32, [SOCKET, C.c_int32]),
        'accept': (SOCKET, [SOCKET, PTR, PTR]),
        'select': (C.c_int32, [C.c_int32, PTR, PTR, PTR, PTR]),
        'getsockopt': (C.c_int32, [SOCKET, C.c_int32, C.c_int32, PTR, PTR]),
        'send': (C.c_int32, [SOCKET, PTR, C.c_int32, C.c_int32]),
        'recv': (C.c_int32, [SOCKET, PTR, C.c_int32, C.c_int32]),
        'WSAIoctl': (C.c_int32, [SOCKET, DWORD, PTR, DWORD, PTR, DWORD, PTR, PTR, PTR]),
    },
}
