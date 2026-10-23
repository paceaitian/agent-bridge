"""§84 x64 PEB config-key probe; no argv, other environment output, or writes.

PEB internals may change. Unsupported ABI/read failure is a reason to use the
bounded reclaude directory fallback, never permission to elevate or inject.
"""
import ctypes as C
from pathlib import PureWindowsPath
import time
from typing import Any

from ..claude_roots import MAX_ENV_BYTES, environment_config, ConfigValue
from . import abi as A


def claude_config(api: Any, pid: int, birth: str) -> ConfigValue:
    fact, me = api.process(pid, expected_birth=birth), api.current_token()
    if (fact.token.sid != me.sid or fact.token.elevated
            or PureWindowsPath(api.process_image(pid, birth)).name.lower() != 'claude.exe'):
        raise OSError('claude_environment_ineligible')
    if C.sizeof(A.PTR) != 8:
        raise OSError('claude_environment_architecture')
    with api.owned(api.handle(api.k.OpenProcess(0x101010, False, pid))) as handle:
        times = [A.FILETIME() for _ in range(4)]
        api.check(api.k.GetProcessTimes(handle, *(C.byref(t) for t in times)))
        if str(times[0].number()) != birth or api.token(handle) != me:
            raise OSError('claude_environment_changed')
        wow = A.BOOL()
        api.check(api.k.IsWow64Process(handle, C.byref(wow)))
        if wow.value:
            raise OSError('claude_environment_architecture')
        info = (A.PTR * 6)()
        status = api.dll['ntdll'].NtQueryInformationProcess(handle, 0, info, C.sizeof(info), None)
        if status != 0 or not info[1]:
            raise OSError('claude_environment_unavailable')

        def read(address: int, size: int) -> bytes:
            if address <= 0 or not 0 < size <= 4096:
                raise OSError('claude_environment_pointer')
            buf, done = C.create_string_buffer(size), C.c_size_t()
            api.check(api.k.ReadProcessMemory(handle, address, buf, size, C.byref(done)))
            if done.value != size:
                raise OSError('claude_environment_partial')
            return buf.raw

        params = int.from_bytes(read(int(info[1]) + 0x20, 8), 'little')
        address = int.from_bytes(read(params + 0x80, 8), 'little')
        raw, offset, deadline = bytearray(), 0, time.monotonic() + 0.5
        try:
            while offset < MAX_ENV_BYTES and time.monotonic() < deadline:
                size = min(4096 - (address + offset) % 4096, MAX_ENV_BYTES - offset)
                raw.extend(read(address + offset, size))
                start = max(0, offset - 2)
                offset += size
                end = next((i for i in range(start, len(raw) - 3, 2) if raw[i:i+4] == b'\0'*4), None)
                if end is not None:
                    if (int.from_bytes(read(params + 0x80, 8), 'little') != address
                            or api.process(pid, expected_birth=birth) != fact):
                        raise OSError('claude_environment_changed')
                    return environment_config(bytes(raw[:end+2]), windows=True)
            raise OSError('claude_environment_limit')
        finally:
            raw[:] = b'\0' * len(raw)
