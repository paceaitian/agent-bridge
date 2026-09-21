"""`python3 -m agentstatus_bridge` 入口：**独立版**语义。

argv0 是解释器，认不出命令名，所以用独立版默认值（账本根 `~/.local/state/agent-bridge`、命令名
`agent-bridge`）——与安装后的集成命令 `ab` **不等价**。要对集成版账本操作请显式给 `AB_STATE_DIR`
（DESIGN §45.36）。
"""

from .cli import main

raise SystemExit(main())
