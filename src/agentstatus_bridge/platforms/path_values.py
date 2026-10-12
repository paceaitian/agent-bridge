"""跨平台共享的桥环境键与设备标签合同。"""
import re

STATE_DIR_ENV = "AB_STATE_DIR"
# 集成入口绑定状态根时留下的标记：让 `doctor` 能分清「集成版绑的」和「有人自己 export 的」（DESIGN §45.36）
BINDING_ENV = "AB_BINDING"
CLAUDE_SESSIONS_ENV = "AB_CLAUDE_SESSIONS_DIR"
DEVICE_ENV = "AB_DEVICE"
# 独立版的账本目录名；集成版由入口脚本把 `AB_STATE_DIR` 绑回 `agentstatus/bridge`（DESIGN §45.36）
STATE_DIR_NAME = "agent-bridge"
# 设备名要能进消息头的 token 位与 JSON：除了这几类字符全部换成 `-`（`=` 也不允许，它是消息头的分隔符）
DEVICE_UNSAFE = re.compile(r"[^A-Za-z0-9._-]+")
DEVICE_CHARS = 32

