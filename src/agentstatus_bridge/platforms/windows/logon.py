"""Bounded numeric logon projection; diagnostic only, not a same-LUID gate.

Public SDK: winnt.h TOKEN_STATISTICS and ntsecapi.h SECURITY_LOGON_SESSION_DATA.
No username/domain strings are dereferenced, returned or logged.
"""
from __future__ import annotations
import ctypes as C
from typing import Any

from . import abi as A
from .api import ProcessFact


def _session(api: Any, process: int) -> tuple[A.LUID, int]:
    handle = A.HANDLE()
    api.check(api.a.OpenProcessToken(process, 8, C.byref(handle)))
    with api.owned(api.handle(handle.value)) as token:
        size = A.DWORD()
        stats, session = A.TOKEN_STATISTICS(), A.DWORD()
        api.check(api.a.GetTokenInformation(token, 10, C.byref(stats), C.sizeof(stats), C.byref(size)))
        if size.value != C.sizeof(stats):
            raise OSError('windows_logon_unverified')
        api.check(api.a.GetTokenInformation(token, 12, C.byref(session), C.sizeof(session), C.byref(size)))
        if size.value != C.sizeof(session):
            raise OSError('windows_logon_unverified')
        return stats.authentication, int(session.value)


def logon_info(api: Any, peer: ProcessFact) -> dict[str, object]:
    with api.owned(api.handle(api.k.OpenProcess(0x101000, False, peer.pid))) as process:
        times = [A.FILETIME() for _ in range(4)]
        api.check(api.k.GetProcessTimes(process, *(C.byref(t) for t in times)))
        if times[0].number() != peer.birth or api.k.WaitForSingleObject(process, 0) != 258:
            raise OSError('windows_logon_unverified')
        luid, session = _session(api, process)
    caller_luid, caller_session = _session(api, api.k.GetCurrentProcess())
    pointer = A.PTR()
    library = api.dll['secur32']
    if library.LsaGetLogonSessionData(C.byref(luid), C.byref(pointer)) != 0 or not pointer.value:
        raise OSError('windows_logon_unverified')
    try:
        if C.cast(pointer, C.POINTER(A.DWORD)).contents.value < C.sizeof(A.LOGON_PREFIX):
            raise OSError('windows_logon_unverified')
        row = C.cast(pointer, C.POINTER(A.LOGON_PREFIX)).contents
        if bytes(row.id) != bytes(luid) or row.session != session:
            raise OSError('windows_logon_unverified')
        return {'logonType': {2: 'INTERACTIVE', 3: 'NETWORK', 4: 'BATCH', 5: 'SERVICE',
                              7: 'UNLOCK', 10: 'REMOTE_INTERACTIVE', 11: 'CACHED_INTERACTIVE'}
                .get(row.kind, 'OTHER'), 'sessionZero': session == 0,
                'sameLogon': bytes(luid) == bytes(caller_luid), 'sameSession': session == caller_session}
    finally:
        library.LsaFreeReturnBuffer(pointer)
