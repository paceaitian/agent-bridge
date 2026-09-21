"""AgentStatus 可选协作桥：在本机已运行的 Codex/Claude 终端会话之间交接任务。

与 observer（`agentstatus` 包）职责分离：observer 只观察会话状态、不保存正文；本包保存用户
交给它的任务正文、引用与结构化结果，经原生通道（Codex queue、Claude 会话消息 socket）投递，
并记录回执、进展、结果与验收（DESIGN §45）。
"""

from __future__ import annotations

__all__ = ["PROTOCOL_VERSION", "__version__"]

__version__ = "0.1.0.dev0"
# 消息头与报告协议版本；不兼容变更须递增并保留旧版本拒绝路径
PROTOCOL_VERSION = 1
