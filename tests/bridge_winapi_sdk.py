"""Independent x64 Windows SDK oracle (no imports from bridge production code).

Win32 metadata: https://github.com/microsoft/win32metadata/tree/main/generation/WinSDK/RecompiledIdlHeaders
um/{fileapi,processthreadsapi,synchapi,securitybaseapi,aclapi,tlhelp32,winsock2}.h
LP* parameters are pointer-width; BOOL/HRESULT/int are signed 32 bit, DWORD is
unsigned 32 bit, HANDLE/UINT_PTR(SOCKET) retain all 64 bits. Written independently
of abi.SIGNATURES: changing that production table must not change this oracle.
CFUNCTYPE uses the host ABI to exercise widths on Linux; Windows x64 has one
calling convention. This is not a substitute for a native Windows qualification.
"""
import ctypes as C

U32, I32, U16 = C.c_uint32, C.c_int32, C.c_uint16
P, H, S = C.c_void_p, C.c_void_p, C.c_size_t

# Independently transcribed from the public SDK definitions (Windows x64).
# References: Microsoft Learn fileapi BY_HANDLE_FILE_INFORMATION, tlhelp32
# PROCESSENTRY32W, minwinbase FILETIME/OVERLAPPED, and the SDK shared/afunix.h.
# No production types/values participate in the buffers written by the fake.
INVALID_HANDLE_VALUE = (1 << 64) - 1  # SDK ((HANDLE)(LONG_PTR)-1)


class FILETIME(C.Structure):
    _fields_ = [('dwLowDateTime', U32), ('dwHighDateTime', U32)]


class LUID(C.Structure):
    _fields_ = [('LowPart', U32), ('HighPart', I32)]


class TOKEN_STATISTICS(C.Structure):
    _fields_ = [('TokenId', LUID), ('AuthenticationId', LUID), ('ExpirationTime', C.c_int64),
                ('TokenType', I32), ('ImpersonationLevel', I32), ('DynamicCharged', U32),
                ('DynamicAvailable', U32), ('GroupCount', U32), ('PrivilegeCount', U32), ('ModifiedId', LUID)]


class LSA_UNICODE_STRING(C.Structure):
    _fields_ = [('Length', U16), ('MaximumLength', U16), ('Buffer', P)]


class SECURITY_LOGON_SESSION_PREFIX(C.Structure):
    _fields_ = [('Size', U32), ('LogonId', LUID), ('UserName', LSA_UNICODE_STRING),
                ('LogonDomain', LSA_UNICODE_STRING), ('AuthenticationPackage', LSA_UNICODE_STRING),
                ('LogonType', U32), ('Session', U32)]


class BY_HANDLE_FILE_INFORMATION(C.Structure):
    _fields_ = [('dwFileAttributes', U32), ('ftCreationTime', FILETIME),
                ('ftLastAccessTime', FILETIME), ('ftLastWriteTime', FILETIME),
                ('dwVolumeSerialNumber', U32), ('nFileSizeHigh', U32),
                ('nFileSizeLow', U32), ('nNumberOfLinks', U32),
                ('nFileIndexHigh', U32), ('nFileIndexLow', U32)]


class PROCESSENTRY32W(C.Structure):
    _fields_ = [('dwSize', U32), ('cntUsage', U32), ('th32ProcessID', U32),
                ('th32DefaultHeapID', C.c_uint64), ('th32ModuleID', U32),
                ('cntThreads', U32), ('th32ParentProcessID', U32),
                ('pcPriClassBase', I32), ('dwFlags', U32), ('szExeFile', U16 * 260)]


class _Offsets(C.Structure):
    _fields_ = [('Offset', U32), ('OffsetHigh', U32)]


class _OverlappedUnion(C.Union):
    _fields_ = [('offsets', _Offsets), ('Pointer', P)]


class OVERLAPPED(C.Structure):
    _fields_ = [('Internal', C.c_uint64), ('InternalHigh', C.c_uint64),
                ('data', _OverlappedUnion), ('hEvent', H)]


class SOCKADDR_UN(C.Structure):
    _fields_ = [('sun_family', U16), ('sun_path', C.c_char * 108)]


class SECURITY_ATTRIBUTES(C.Structure):
    _fields_ = [('nLength', U32), ('lpSecurityDescriptor', P), ('bInheritHandle', I32)]


class FILE_ATTRIBUTE_TAG_INFO(C.Structure):
    _fields_ = [('FileAttributes', U32), ('ReparseTag', U32)]


class FILE_ID_INFO(C.Structure):
    _fields_ = [('VolumeSerialNumber', C.c_uint64), ('FileId', C.c_ubyte * 16)]


def wide(value):
    raw = value.encode('utf-16-le', 'surrogatepass') + b'\0\0'
    return (U16 * (len(raw) // 2)).from_buffer_copy(raw)


def assert_file_layout(case, actual):
    """Test precondition: never run file scenarios with an invalid buffer ABI.

    A wrong link-count offset otherwise cascades into unrelated positive Store
    setup errors. This is a specific independent layout assertion, NOT generic
    exception conversion in the fake or in the test runner.
    """
    case.assertEqual(C.sizeof(actual), C.sizeof(BY_HANDLE_FILE_INFORMATION))
    names = ('attributes', 'creation', 'access', 'write', 'volume', 'size_high',
             'size_low', 'links', 'index_high', 'index_low')
    for name, (sdk_name, _) in zip(names, BY_HANDLE_FILE_INFORMATION._fields_):
        case.assertEqual(getattr(actual, name).offset,
                         getattr(BY_HANDLE_FILE_INFORMATION, sdk_name).offset, name)

SDK = {
    'kernel32': {
        'GetCurrentProcess': (H, []),
        'GetCurrentProcessId': (U32, []),
        'OpenProcess': (H, [U32, I32, U32]),
        'CloseHandle': (I32, [H]),
        'GetProcessTimes': (I32, [H, P, P, P, P]),
        'QueryFullProcessImageNameW': (I32, [H, U32, P, P]),
        'GetExitCodeProcess': (I32, [H, P]),
        'CreateToolhelp32Snapshot': (H, [U32, U32]),
        'Process32FirstW': (I32, [H, P]),
        'Process32NextW': (I32, [H, P]),
        'LocalFree': (P, [P]),
        'CreateFileW': (H, [P, U32, U32, P, U32, U32, H]),
        'CreateDirectoryW': (I32, [P, P]),
        'GetFileInformationByHandle': (I32, [H, P]),
        'GetFileInformationByHandleEx': (I32, [H, I32, P, U32]),
        'SetFileInformationByHandle': (I32, [H, I32, P, U32]),
        'GetVolumeInformationByHandleW': (I32, [H, P, U32, P, P, P, P, U32]),
        'GetFinalPathNameByHandleW': (U32, [H, P, U32, U32]),
        'GetDriveTypeW': (U32, [P]),
        'LockFileEx': (I32, [H, U32, U32, U32, U32, P]),
        'UnlockFileEx': (I32, [H, U32, U32, U32, P]),
        'FlushFileBuffers': (I32, [H]),
        'WriteFile': (I32, [H, P, U32, P, P]),
        'ReadFile': (I32, [H, P, U32, P, P]),
        'MoveFileExW': (I32, [P, P, U32]),
        'DeleteFileW': (I32, [P]),
        'CreateEventW': (H, [P, I32, I32, P]),
        'WaitForSingleObject': (U32, [H, U32]),
        'GetOverlappedResult': (I32, [H, P, P, I32]),
        'CancelIoEx': (I32, [H, P]),
        'CreateNamedPipeW': (H, [P, U32, U32, U32, U32, U32, U32, P]),
        'ConnectNamedPipe': (I32, [H, P]),
        'DisconnectNamedPipe': (I32, [H]),
        'GetNamedPipeServerProcessId': (I32, [H, P]),
        'GetNamedPipeClientProcessId': (I32, [H, P]),
        'IsProcessInJob': (I32, [H, H, P]),
        'GetConsoleWindow': (H, []),
        'SetHandleInformation': (I32, [H, U32, U32]),
    },
    'advapi32': {
        'OpenProcessToken': (I32, [H, U32, P]),
        'GetTokenInformation': (I32, [H, U32, P, U32, P]),
        'GetLengthSid': (U32, [P]),
        'IsValidSid': (I32, [P]),
        'ConvertSidToStringSidW': (I32, [P, P]),
        'ConvertStringSecurityDescriptorToSecurityDescriptorW': (I32, [P, U32, P, P]),
        'GetSecurityInfo': (U32, [H, U32, U32, P, P, P, P, P]),
        'GetSecurityDescriptorControl': (I32, [P, P, P]),
        'GetSecurityDescriptorDacl': (I32, [P, P, P, P]),
        'SetSecurityInfo': (U32, [H, U32, U32, P, P, P, P]),
        'GetAce': (I32, [P, U32, P]),
    },
    'shell32': {'SHGetKnownFolderPath': (I32, [P, U32, H, P])},
    'ole32': {'CoTaskMemFree': (None, [P])},
    'secur32': {'LsaGetLogonSessionData': (I32, [P, P]), 'LsaFreeReturnBuffer': (I32, [P])},
    'ws2_32': {
        'WSAStartup': (I32, [U16, P]), 'WSACleanup': (I32, []),
        'WSAGetLastError': (I32, []),
        'socket': (S, [I32, I32, I32]), 'closesocket': (I32, [S]),
        'ioctlsocket': (I32, [S, I32, P]),
        'connect': (I32, [S, P, I32]), 'bind': (I32, [S, P, I32]),
        'listen': (I32, [S, I32]), 'accept': (S, [S, P, P]),
        'select': (I32, [I32, P, P, P, P]),
        'getsockopt': (I32, [S, I32, I32, P, P]),
        'send': (I32, [S, P, I32, I32]), 'recv': (I32, [S, P, I32, I32]),
        'WSAIoctl': (I32, [S, U32, P, U32, P, U32, P, P, P]),
    },
}
