"""Only the read-only CLI version command; not a general subprocess backend."""
import re
import shutil
import subprocess
from pathlib import Path

_cache: dict[tuple[int, int, int], str] = {}


def read_cli_version() -> str | None:
    executable = shutil.which('codex')
    if executable is None:
        return None
    try:
        # resolve(strict=True) follows Windows junctions, including nested
        # release indirections. stat supplies volume/file index on Windows.
        target = Path(executable).resolve(strict=True)
        stat = target.stat()
        key = (stat.st_dev, stat.st_ino, stat.st_mtime_ns)
        if key in _cache:
            return _cache[key]
        executable = str(target)
        result = subprocess.run([executable, '--version'], stdout=subprocess.PIPE,
                                stderr=subprocess.DEVNULL, timeout=3.0, check=False,
                                shell=False, close_fds=True, encoding='utf-8', errors='strict')
    except (OSError, UnicodeError, subprocess.SubprocessError):
        return None
    if result.returncode != 0 or len(result.stdout) > 128:
        return None
    matched = re.fullmatch(r'codex-cli ([0-9]+\.[0-9]+\.[0-9]+)\r?\n?', result.stdout)
    if matched:
        # Bound per-process storage; failures never mask a later successful read.
        _cache.clear()
        _cache[key] = matched.group(1)
        return matched.group(1)
    return None
