"""Codex 启动参数识别：是不是交互 TUI、权限类别由哪些参数与配置决定（DESIGN §45.33.2、§45.44 二.7）。

只按有界 argv 与本地 config.toml 判断，不执行 codex、不读会话内容。名单依据写在各常量上方；
Codex 升级改了子命令或全局选项时只改这里（审计 H2；§48 R5 从 endpoints 搬出）。
"""

from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path
import tomllib


# 这些 Codex 子命令不是交互 TUI，不能作为任务目标（DESIGN §45.33.2、§45.44 二.7）。名单依据：0.156.0 `--help`
# 可见的非交互子命令 + 固定源码（`fe74a774`）中 `hide=true` 的隐藏子命令 `tcp-tunnel`（`--help` 不列隐藏子命令）；
# 另含 `--help` 未列出（已删或隐藏）的历史名。`agents`/`resume`/`fork` 是交互，故意不在内；
# `app` 只在 macOS/Windows 编译，本桥 Linux 范围不收
_CODEX_NON_TUI = frozenset(
    {
        "app-server",
        "apply",
        "a",
        "archive",
        "cloud",
        "cloud-tasks",
        "completion",
        "debug",
        "delete",
        "doctor",
        "exec",
        "e",
        "exec-server",
        "execpolicy",
        "features",
        "help",
        "login",
        "logout",
        "mcp",
        "mcp-server",
        "migrate-rollouts",
        "plugin",
        "proto",
        "queue",
        "remote-control",
        "responses-api-proxy",
        "review",
        "sandbox",
        "stdio-to-uds",
        "tcp-tunnel",
        "unarchive",
        "update",
    }
)


# 取值型全局选项：识别启动模式时要连它的取值一起跳过，否则 `--profile x exec` 会被误判成交互会话
_CODEX_VALUE_OPTIONS = frozenset(
    {
        "-a",
        "--add-dir",
        "--ask-for-approval",
        "-c",
        "-C",
        "--cd",
        "--config",
        "--disable",
        "--enable",
        "-i",
        "--image",
        "--local-provider",
        "-m",
        "--model",
        "-p",
        "--profile",
        "--remote",
        "--remote-auth-token-env",
        "-s",
        "--sandbox",
    }
)


# 多值选项（上游 num_args = 1..）：空格写法后续非选项 token 仍属于它，直到出现下一个选项；
# 所以 `-i a.png exec` 里的 exec 是图片名（仍是交互 TUI）。内联写法 `--image=a.png`/`-i=a.png` 只带一个取值，其后的 exec 仍是子命令。
_CODEX_MULTI_VALUE_OPTIONS = frozenset({"-i", "--image"})


# 交互子命令：扫到它就确定是 TUI，不再看后面的 token
_CODEX_TUI_SUBCOMMANDS = frozenset({"agents", "fork", "resume"})


def _codex_non_interactive(tokens: Sequence[str]) -> bool:
    """按有界 argv 判断 Codex 是否以明确的非交互子命令启动（DESIGN §45.33.2、§45.33.6）。

    跟随上游 0.154 的解析（0.156.0 已按源码逐项核对取值型全局选项，2026-09-22）：跳过已知全局选项及其取值（多值选项的空格写法吞掉后续非选项 token，内联写法只带一个），
    `--` 之后是字面参数；**位置参数之后仍可能出现子命令**（`codex hello exec` 实际进入 exec），所以未知 token 不终止扫描，
    继续找第一个落在子命令表里的 token；一个都没有就是交互（裸 `codex`、`codex "初始要求"`）。
    """
    index = 0
    while index < len(tokens):
        token = tokens[index]
        if token == "--":
            return False
        if token.startswith("-"):
            name, inline, _ = token.partition("=")
            if not inline and name in _CODEX_MULTI_VALUE_OPTIONS:
                index += 1
                while index < len(tokens) and not tokens[index].startswith("-"):
                    index += 1
                continue
            index += 2 if not inline and name in _CODEX_VALUE_OPTIONS else 1
            continue
        if token in _CODEX_NON_TUI:
            return True
        if token in _CODEX_TUI_SUBCOMMANDS:
            return False
        index += 1
    return False


def _toml_string(raw: str) -> str:
    text = raw.strip()
    try:
        parsed = tomllib.loads(f"v = {text}").get("v")
    except tomllib.TOMLDecodeError:
        return text.strip("'\"")
    return parsed if isinstance(parsed, str) else text


def _codex_cli_overrides(tokens: list[str]) -> tuple[str | None, str | None, bool, bool]:
    """解析 Codex 启动参数：(审批策略, 沙箱模式, 是否完全绕过, 是否选了 profile)。

    专用参数 `-a/-s` 优先于 `-c` 覆盖，与出现顺序无关；同一类内后出现者生效。
    """
    flag_approval: str | None = None
    flag_sandbox: str | None = None
    kv_approval: str | None = None
    kv_sandbox: str | None = None
    bypass = False
    profile = False
    index = 1
    while index < len(tokens):
        token = tokens[index]
        name, separator, inline = token.partition("=")
        if separator:
            value: str | None = inline
            step = 1
        else:
            value = tokens[index + 1] if index + 1 < len(tokens) else None
            step = 2
        if token in ("--dangerously-bypass-approvals-and-sandbox", "--yolo"):
            bypass = True
            step = 1
        elif name in ("-a", "--ask-for-approval") and value is not None:
            flag_approval = value
        elif name in ("-s", "--sandbox") and value is not None:
            flag_sandbox = value
        elif name in ("-p", "--profile") and value is not None:
            profile = True
        elif name in ("-c", "--config") and value is not None:
            key, equals, raw = value.partition("=")
            if equals:
                key = key.strip()
                if key == "approval_policy":
                    kv_approval = _toml_string(raw)
                elif key == "sandbox_mode":
                    kv_sandbox = _toml_string(raw)
                elif key == "profile":
                    profile = True
        else:
            step = 1
        index += step
    approval = flag_approval if flag_approval is not None else kv_approval
    sandbox = flag_sandbox if flag_sandbox is not None else kv_sandbox
    return approval, sandbox, bypass, profile


def _codex_class(tokens: list[str], config_path: Path) -> str | None:
    """按 Codex 的配置优先级（启动参数 > -c 覆盖 > profile > 用户配置）判断权限类别。"""
    approval, sandbox, bypass, profile = _codex_cli_overrides(tokens)
    if bypass:
        return "bypass"
    try:
        with config_path.open("rb") as handle:
            config = tomllib.load(handle)
    except (OSError, tomllib.TOMLDecodeError):
        config = {}
    if "profile" in config:
        profile = True
    if not profile:
        # 选了 profile 时其取值无法可靠重建，只用启动参数里明确给出的值
        if approval is None and isinstance(config.get("approval_policy"), str):
            approval = config["approval_policy"]
        if sandbox is None and isinstance(config.get("sandbox_mode"), str):
            sandbox = config["sandbox_mode"]
    if approval is None:
        return None
    if approval != "never":
        return "prompting"
    return "bypass" if sandbox == "danger-full-access" else None
