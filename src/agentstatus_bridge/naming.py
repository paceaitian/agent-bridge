"""对外命令名：装出来的命令是 `agent-bridge`，`ab` 是可选别名与集成版的名字。

生成给对方 agent 的页脚、提醒与「下一步」都必须写**用户实际能敲的那个名字**：写错了对方照抄，
`ab` 在没装本工具的机器上很可能是 ApacheBench（DESIGN §45.36）。
"""

from __future__ import annotations

import os
from pathlib import Path
import sys

COMMAND_ENV = "AB_COMMAND"
DEFAULT_COMMAND = "agent-bridge"
# 认得的入口名：正式命令与可选别名。argv0 只在命中这两个时才采信——其余情况（`python -m`、
# 解释器路径、`-c`）说明调用方式不是命令行入口，猜不出用户敲的是什么。
KNOWN_COMMANDS: tuple[str, ...] = (DEFAULT_COMMAND, "ab")


def command_name() -> str:
    """本进程对外的命令名：`AB_COMMAND` > argv0（限认得的入口名）> `agent-bridge`。

    worker 由 `python -m agentstatus_bridge worker` 拉起，argv0 是解释器，认不出命令名，
    所以拉起它的 CLI 必须把解析结果显式写进子进程环境（`worker.ensure_worker`）。
    """
    configured = os.environ.get(COMMAND_ENV, "").strip()
    if configured:
        return configured
    argv0 = sys.argv[0] if sys.argv else ""
    name = Path(argv0).name if argv0 else ""
    return name if name in KNOWN_COMMANDS else DEFAULT_COMMAND
