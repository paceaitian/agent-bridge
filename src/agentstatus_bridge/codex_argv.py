"""Codex 启动参数识别：是不是交互 TUI、权限类别由哪些参数与配置决定（DESIGN §45.33.2、§45.44 二.7、§58）。

只按有界 argv 与本地 config.toml 判断，不执行 codex、不读会话内容。名单依据写在各常量上方（2026-10-04 按
0.160.0 源码复核，DESIGN §58.1）；Codex 升级改了子命令或全局选项时只改这里（审计 H2；§48 R5 从 endpoints 搬出）。
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field
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


# 带自己一份 TUI 参数、按上游 merge_interactive_cli_flags 与根层合并的子命令（DESIGN §58.1）
_CODEX_SESSION_SUBCOMMANDS = frozenset({"fork", "resume"})


# 权限参数（DESIGN §58.1，0.160.0）：`--yolo` 类与 `--approve-for-me` 类都是无值布尔；
# `--approve-for-me` 被上游转成追加在全部 `-c` 之后的覆盖，这里只取与类别有关的两条
_CODEX_BYPASS_FLAGS = frozenset({"--dangerously-bypass-approvals-and-sandbox", "--yolo"})
_CODEX_AUTO_REVIEW_FLAGS = frozenset({"--approve-for-me", "--not-so-yolo"})
_CODEX_AUTO_REVIEW_OVERRIDES: tuple[tuple[str, str], ...] = (
    ("approval_policy", "on-request"),
    ("sandbox_mode", "workspace-write"),
)


# clap 允许短选项粘连取值（`-sX`、`-s=X`、`-cK=V`），权限相关的四个短选项按带值处理（DESIGN §58.2）
_CODEX_ATTACHED_SHORTS = frozenset({"-a", "-c", "-p", "-s"})


def _codex_subcommand(tokens: Sequence[str]) -> str | None:
    """按有界 argv 找出 Codex 的子命令名；没有就返回 None（扫描规则见 `_codex_subcommand_index`）。"""
    index = _codex_subcommand_index(tokens)
    return tokens[index] if index is not None else None


def _codex_subcommand_index(tokens: Sequence[str]) -> int | None:
    """按有界 argv 找出 Codex 子命令的位置：第一个落在子命令表（非交互或交互）里的 token；没有就返回 None。

    子命令识别与权限参数切层共用这一处扫描，免得两份扫描在 `--` 与取值型选项上漂移（DESIGN §58.2）。

    跟随上游 0.154 的解析（0.156.0 已按源码逐项核对取值型全局选项，2026-09-22）：跳过已知全局选项及其取值（多值选项的空格写法吞掉后续非选项 token，内联写法只带一个），
    `--` 之后是字面参数；**位置参数之后仍可能出现子命令**（`codex hello exec` 实际进入 exec），所以未知 token 不终止扫描，
    继续找第一个落在子命令表里的 token；一个都没有就是交互（裸 `codex`、`codex "初始要求"`）。
    """
    index = 0
    while index < len(tokens):
        token = tokens[index]
        if token == "--":
            return None
        if token.startswith("-"):
            name, inline, _ = token.partition("=")
            if not inline and name in _CODEX_MULTI_VALUE_OPTIONS:
                index += 1
                while index < len(tokens) and not tokens[index].startswith("-"):
                    index += 1
                continue
            index += 2 if not inline and name in _CODEX_VALUE_OPTIONS else 1
            continue
        if token in _CODEX_NON_TUI or token in _CODEX_TUI_SUBCOMMANDS:
            return index
        index += 1
    return None


def _codex_non_interactive(tokens: Sequence[str]) -> bool:
    """按有界 argv 判断 Codex 是否以明确的非交互子命令启动（DESIGN §45.33.2、§45.33.6）。"""
    return _codex_subcommand(tokens) in _CODEX_NON_TUI


def codex_app_server(tokens: Sequence[str]) -> bool:
    """argv 的子命令是不是 `app-server`（DESIGN §53.3.0）。

    托管 daemon、桌面版与插件起的 app-server 都算；`exec`、`review`、`mcp-server` 等别的非交互子命令不算——
    只有 app-server 会承载别的窗口的 thread。daemon 模式判定、pane 归组停止点、调用者 `D`、hook 模式判定与
    权限类别五处共用这一个判据。
    """
    return _codex_subcommand(tokens) == "app-server"


def _toml_string(raw: str) -> str:
    text = raw.strip()
    try:
        parsed = tomllib.loads(f"v = {text}").get("v")
    except tomllib.TOMLDecodeError:
        return text.strip("'\"")
    return parsed if isinstance(parsed, str) else text


@dataclass(slots=True)
class _CodexLayer:
    """一层启动参数（根层或子命令层）里与权限类别有关的部分。"""

    bypass: bool = False
    sandbox: str | None = None
    auto_review: bool = False
    approval: str | None = None
    # 本层出现过 `-c`（任何键）：`-c` 是 clap 全局参数，子命令层出现就整组替换根层（DESIGN §58.1）
    has_config: bool = False
    config: list[tuple[str, str]] = field(default_factory=list)
    profile: bool = False

    @property
    def selects_sandbox(self) -> bool:
        """本层是否选了沙箱组（`-s`、`--approve-for-me`、`--yolo`）；选了就整组替换上一层。"""
        return self.bypass or self.sandbox is not None or self.auto_review


def _codex_layer(tokens: Sequence[str]) -> _CodexLayer:
    """解析一层启动参数：遇到 `--` 停止，取值型选项跳过取值，位置参数不终止扫描；同类后出现者生效。"""
    layer = _CodexLayer()
    index = 0
    while index < len(tokens):
        token = tokens[index]
        if token == "--":
            break
        name, separator, inline = token.partition("=")
        if separator:
            value: str | None = inline
            step = 1
        else:
            value = tokens[index + 1] if index + 1 < len(tokens) else None
            step = 2
        if len(token) > 2 and token[:2] in _CODEX_ATTACHED_SHORTS:
            name, value, step = token[:2], token[2:].removeprefix("="), 1
        if token in _CODEX_BYPASS_FLAGS:
            layer.bypass = True
            step = 1
        elif token in _CODEX_AUTO_REVIEW_FLAGS:
            layer.auto_review = True
            step = 1
        elif name in ("-a", "--ask-for-approval") and value is not None:
            layer.approval = value
        elif name in ("-s", "--sandbox") and value is not None:
            layer.sandbox = value
        elif name in ("-p", "--profile") and value is not None:
            layer.profile = True
        elif name in ("-c", "--config") and value is not None:
            layer.has_config = True
            key, equals, raw = value.partition("=")
            if equals:
                key = key.strip()
                if key in ("approval_policy", "sandbox_mode"):
                    layer.config.append((key, _toml_string(raw)))
                elif key == "profile":
                    layer.profile = True
        elif not separator and name in _CODEX_MULTI_VALUE_OPTIONS:
            index += 1
            while index < len(tokens) and not tokens[index].startswith("-"):
                index += 1
            continue
        elif separator or name not in _CODEX_VALUE_OPTIONS:
            # 位置参数、布尔选项与内联写法：只前进一个 token
            step = 1
        index += step
    return layer


def _codex_cli_overrides(tokens: list[str]) -> tuple[str | None, str | None, bool, bool]:
    """解析 Codex 启动参数：(审批策略, 沙箱模式, 是否完全绕过, 是否选了 profile)。

    按上游 0.160.0 的合并顺序（DESIGN §58.1）：根层与子命令层分开解析；子命令层选了沙箱组就整组替换根层；
    生效的 `-c` 是子命令层出现过 `-c` 时的那一组、否则根层那一组，两层 `--approve-for-me` 的覆盖依次追加在后，
    同键后者生效；`resume`/`fork` 层的 `--approve-for-me` 清掉根层 `-a`，否则子命令层 `-a` 优先；
    专用参数 `-a/-s` 压过 `-c`。非交互子命令沿用同一合并，是近似（DESIGN §58.2 第 3 条）。
    """
    arguments = tokens[1:]
    index = _codex_subcommand_index(arguments)
    root = _codex_layer(arguments if index is None else arguments[:index])
    sub = _codex_layer(() if index is None else arguments[index + 1 :])
    chosen = sub if sub.selects_sandbox else root
    config = list(sub.config if sub.has_config else root.config)
    if root.auto_review:
        config.extend(_CODEX_AUTO_REVIEW_OVERRIDES)
    if sub.auto_review:
        config.extend(_CODEX_AUTO_REVIEW_OVERRIDES)
    settled = dict(config)
    if index is not None and arguments[index] in _CODEX_SESSION_SUBCOMMANDS and sub.auto_review:
        approval: str | None = None
    else:
        approval = sub.approval if sub.approval is not None else root.approval
    if approval is None:
        approval = settled.get("approval_policy")
    sandbox = chosen.sandbox if chosen.sandbox is not None else settled.get("sandbox_mode")
    return approval, sandbox, chosen.bypass, root.profile or sub.profile


def _codex_class(tokens: list[str], config_path: Path) -> str | None:
    """按 Codex 的配置优先级判断权限类别：分层合并后的启动参数（`_codex_cli_overrides`）> profile > 用户配置。"""
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
