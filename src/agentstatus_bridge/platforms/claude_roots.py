"""有界配置根与采样结果；不返回或记录完整进程环境。"""
from collections.abc import Mapping
from pathlib import Path
from dataclasses import dataclass
from typing import Literal

MAX_ROOTS = 128
MAX_ENV_BYTES = 1024 * 1024
CONFIG_KEY = 'CLAUDE_CONFIG_DIR'
OVERRIDE = 'AB_CLAUDE_SESSIONS_DIR'


def unique(paths: list[Path]) -> tuple[Path, ...]:
    # Do not resolve symlinks: Windows validates each original path component.
    return tuple(dict.fromkeys(paths))[:MAX_ROOTS]


@dataclass(frozen=True)
class ConfigValue:
    """目标环境键的三态投影：缺失、有值或不确定。"""
    state: Literal['absent', 'value', 'unknown']
    value: str | None = None


@dataclass(frozen=True)
class RootScan:
    """一次多根扫描的不可变结果，附完整性、未定位 PID 和闭集诊断。"""
    roots: tuple[Path, ...]
    complete: bool = True
    unlocated: frozenset[int] = frozenset()
    live: tuple[tuple[int, Path], ...] = ()
    diagnostics: tuple[tuple[Path, str], ...] = ()
    exclusive: bool = False


def environment_config(raw: bytes, *, windows: bool = False) -> ConfigValue:
    """先按字节匹配，仅解码目标值；异常不携带原始环境。"""
    if len(raw) > MAX_ENV_BYTES or windows and len(raw) % 2:
        return ConfigValue('unknown')
    encoding = 'utf-16-le' if windows else 'utf-8'
    prefix = (CONFIG_KEY + '=').encode(encoding)
    if windows:
        ends = [i for i in range(0, len(raw), 2) if raw[i:i+2] == b'\0\0']
        parts, start = [], 0
        for end in ends:
            parts.append(raw[start:end]); start = end + 2
        if start < len(raw):
            return ConfigValue('unknown')
    else:
        if raw and not raw.endswith(b'\0'):
            return ConfigValue('unknown')
        parts = raw.split(b'\0')
    found = [part[len(prefix):] for part in parts
             if (part[:len(prefix)].upper() if windows else part[:len(prefix)]) == prefix]
    if not found:
        return ConfigValue('absent')
    if len(found) != 1:
        return ConfigValue('unknown')
    try:
        value = found[0].decode(encoding)
    except UnicodeError:
        return ConfigValue('unknown')
    return ConfigValue('value', value) if value else ConfigValue('absent')


def configured(home: Path, env: Mapping[str, str]) -> list[Path]:
    value = env.get(CONFIG_KEY)
    return ([Path(value).expanduser()] if value else []) + [home / '.claude']
