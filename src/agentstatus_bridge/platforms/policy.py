"""系统策略目录只定义路径；存在性/权限未知不能被解释成无策略。"""
from pathlib import PurePath, PurePosixPath, PureWindowsPath

# 官方 managed-settings 页（2026-10-11），不读取文件或注册表。
CLAUDE_SYSTEM_DIRS: dict[str, PurePath] = {
    'linux': PurePosixPath('/etc/claude-code'),
    'darwin': PurePosixPath('/Library/Application Support/ClaudeCode'),
    'windows': PureWindowsPath(r'C:\Program Files\ClaudeCode'),
}
GROK_SYSTEM_DIRS: dict[str, PurePath | None] = {
    'linux': PurePosixPath('/etc/grok'), 'windows': None, 'darwin': None,
}
