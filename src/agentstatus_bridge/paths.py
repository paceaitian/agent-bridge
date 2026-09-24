"""协作桥使用的本机路径：私有状态目录与各 provider 的只读发现位置。"""

from __future__ import annotations

import os
from pathlib import Path
import re
import socket
import stat

STATE_DIR_ENV = "AB_STATE_DIR"
# 集成入口绑定状态根时留下的标记：让 `doctor` 能分清「集成版绑的」和「有人自己 export 的」（DESIGN §45.36）
BINDING_ENV = "AB_BINDING"
CLAUDE_SESSIONS_ENV = "AB_CLAUDE_SESSIONS_DIR"
DEVICE_ENV = "AB_DEVICE"
# 独立版的账本目录名；集成版由入口脚本把 `AB_STATE_DIR` 绑回 `agentstatus/bridge`（DESIGN §45.36）
STATE_DIR_NAME = "agent-bridge"
# 设备名要能进消息头的 token 位与 JSON：除了这几类字符全部换成 `-`（`=` 也不允许，它是消息头的分隔符）
_DEVICE_UNSAFE = re.compile(r"[^A-Za-z0-9._-]+")
DEVICE_CHARS = 32


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
    cleaned = _DEVICE_UNSAFE.sub("-", raw).strip("-")[:DEVICE_CHARS].strip("-")
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
