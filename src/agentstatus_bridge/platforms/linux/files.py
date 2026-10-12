"""Linux F：路径与私有对象原语；保持原调用顺序与错误投影。"""

from __future__ import annotations

import os
from pathlib import Path
import socket
import stat
import tempfile
import hashlib
import shutil

from ..policy import CLAUDE_SYSTEM_DIRS, GROK_SYSTEM_DIRS

from ..path_values import (STATE_DIR_ENV, BINDING_ENV, CLAUDE_SESSIONS_ENV, DEVICE_ENV,
                           STATE_DIR_NAME, DEVICE_CHARS, DEVICE_UNSAFE)


def state_base() -> Path:
    """状态根的上级目录：`XDG_STATE_HOME` 或 `~/.local/state`。"""
    xdg = os.environ.get("XDG_STATE_HOME")
    return Path(xdg).expanduser() if xdg else Path.home() / ".local/state"


def state_dir() -> Path:
    """返回桥账本所在目录；测试和试验可用 `AB_STATE_DIR` 指向隔离目录。

    默认是独立版的 `<状态根>/agent-bridge`。AgentStatus 集成版由安装器生成的入口脚本把
    `AB_STATE_DIR` 绑回 `<状态根>/agentstatus/bridge`（`agentstatus.bridge_integration`，DESIGN §45.36）——
    桥账本与 observer 的 `state.db` 始终是不同文件：observer 约定不含正文，桥账本保存任务正文（DESIGN §45.3）。
    """
    configured = os.environ.get(STATE_DIR_ENV)
    if configured:
        return Path(configured).expanduser()
    return state_base() / STATE_DIR_NAME


def state_dir_source() -> str:
    """状态根从哪来：`integration`（集成入口绑定）、`env`（调用方显式指定）或 `default`。

    集成入口写的标记形如 `<绑定方>:<它绑定的根>`。**必须比对根**而不是只看标记在不在：
    环境会被子进程继承，「继承了标记又自己改根」的进程否则会被报成 integration（DESIGN §45.36）。
    """
    configured = os.environ.get(STATE_DIR_ENV)
    if not configured:
        return "default"
    bound = os.environ.get(BINDING_ENV, "").partition(":")[2]
    return "integration" if bound and bound == configured else "env"


def ensure_private_dir(path: Path) -> Path:
    """创建仅本用户可访问的目录；账本含任务正文，目录权限是主要保护。

    沿用 observer `StateStore` 的加固：拒绝符号链接与他人拥有的目录。
    """
    if path.is_symlink():
        raise PermissionError("state directory must not be a symlink")
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    status = path.stat()
    if status.st_uid != os.getuid() or not stat.S_ISDIR(status.st_mode):
        raise PermissionError("state directory must be owned by the current user")
    os.chmod(path, 0o700)
    return path


def device_name() -> str:
    """本机设备名：`AB_DEVICE` 优先，否则主机名第一段；过滤并截断成能进消息头与 JSON 的形状。

    设备是**路由属性不是身份**：它只出现在消息头、摘要顶层与 `ab peers`，不进会话身份与账本（DESIGN §45.35）。
    只取主机名第一段：主机名不是秘密，但没有理由把内网域名一起发进跨会话消息。
    """
    configured = os.environ.get(DEVICE_ENV, "")
    raw = configured.strip() or socket.gethostname().split(".", 1)[0]
    cleaned = DEVICE_UNSAFE.sub("-", raw).strip("-")[:DEVICE_CHARS].strip("-")
    return cleaned or "local"


def codex_home() -> Path:
    """Codex 数据根目录，与 CLI 一样尊重 `CODEX_HOME`。"""
    configured = os.environ.get("CODEX_HOME")
    return Path(configured).expanduser() if configured else Path.home() / ".codex"


def codex_sqlite_home() -> Path | None:
    """Codex 状态库目录：上游 `CODEX_SQLITE_HOME` 设置时用它，否则由调用方退回 codex_home（DESIGN §45.48 R2）。"""
    configured = os.environ.get("CODEX_SQLITE_HOME")
    return Path(configured).expanduser() if configured else None


def grok_home() -> Path:
    """Grok 数据根目录；尊重 `GROK_HOME`（grok 自己用它定位 `config.toml` 与 `trace-exports/`）。"""
    configured = os.environ.get("GROK_HOME")
    return Path(configured).expanduser() if configured else Path.home() / ".grok"


def claude_sessions_dir() -> Path:
    """Claude 会话注册表目录（2.1.x 固定在 `~/.claude/sessions`）。"""
    configured = os.environ.get(CLAUDE_SESSIONS_ENV)
    return Path(configured).expanduser() if configured else Path.home() / ".claude/sessions"


CLAUDE_SYSTEM_DIR = Path(CLAUDE_SYSTEM_DIRS["linux"])
GROK_SYSTEM_DIR = Path(str(GROK_SYSTEM_DIRS["linux"]))

def _present(path: Path) -> bool:
    """不能确认不存在时按在处理；不读取策略内容。"""
    try:
        path.lstat()
    except (FileNotFoundError, NotADirectoryError):
        return False
    except OSError:
        return True
    return True


def prepare_database(path: Path) -> None:
    if not path.exists():
        os.close(os.open(path, os.O_CREAT | os.O_WRONLY, 0o600))


def append_log(path: Path, payload: bytes, limit: int) -> None:
    if path.exists() and path.stat().st_size > limit:
        os.replace(path, path.with_name(path.name + ".1"))
    fd = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
    try:
        os.write(fd, payload)
    finally:
        os.close(fd)


def atomic_write(directory: Path, payload: bytes, *, name: str, prefix: str) -> None:
    descriptor, temporary_name = tempfile.mkstemp(prefix=prefix, suffix=".tmp", dir=directory)
    temporary = Path(temporary_name)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, directory / name)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise
    folder = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(folder)
    finally:
        os.close(folder)


class LinuxPaths:
    state_base = staticmethod(state_base)
    state_dir = staticmethod(state_dir)
    state_dir_source = staticmethod(state_dir_source)
    ensure_private_dir = staticmethod(ensure_private_dir)
    device_name = staticmethod(device_name)
    codex_home = staticmethod(codex_home)
    codex_sqlite_home = staticmethod(codex_sqlite_home)
    grok_home = staticmethod(grok_home)
    claude_sessions_dir = staticmethod(claude_sessions_dir)
    prepare_database = staticmethod(prepare_database)
    append_log = staticmethod(append_log)
    atomic_write = staticmethod(atomic_write)
    present = staticmethod(_present)

    @staticmethod
    def uid() -> int:
        return os.getuid()

    @staticmethod
    def policy_dir(provider: str) -> Path:
        if provider == "claude":
            return CLAUDE_SYSTEM_DIR
        if provider == "grok":
            return GROK_SYSTEM_DIR
        raise ValueError("policy_provider_unsupported")

    @staticmethod
    def sqlite_uri(path: Path, *, escaped: bool) -> str:
        return (path.as_uri() if escaped else f"file:{path}") + "?mode=ro"


    @staticmethod
    def root_identity(home: Path, sqlite_home: Path | None = None) -> str | None:
        # 只持久摘要，不保存绝对路径。ctime/mtime 会随正常写文件改变，不能充当根代际。
        try:
            parts: list[str] = []
            for root in (home, sqlite_home or home):
                resolved = root.resolve(strict=True)
                info = resolved.stat()
                if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid():
                    return None
                parts.extend((str(resolved), str(info.st_uid), str(info.st_dev), str(info.st_ino)))
            return hashlib.sha256("\0".join(parts).encode()).hexdigest()
        except (OSError, ValueError):
            return None

    @staticmethod
    def home_equal(reported: str, expected: Path) -> bool:
        return Path(reported).resolve() == expected.resolve()

    @staticmethod
    def socket_identity(target: Path) -> tuple[str, int, int, int]:
        info = target.stat()
        return str(target), info.st_dev, info.st_ino, info.st_ctime_ns

    @staticmethod
    def which(name: str) -> str | None:
        return shutil.which(name)

    @staticmethod
    def realpath(path: str) -> str:
        return os.path.realpath(path)

    @staticmethod
    def mtime_ns(path: str) -> int:
        return os.stat(path).st_mtime_ns

