"""避免 help/factory 导入 DLL；注入对象与实际 WinAPI 走相同后端代码。"""
from typing import Any


class LazyApi:
    def __init__(self) -> None:
        self._instance: Any = None

    def __getattr__(self, name: str) -> Any:
        if self._instance is None:
            from .api import WinApi  # layout: allow 首次操作才装载Win32 DLL，help/工厂不做IO
            self._instance = WinApi()
        return getattr(self._instance, name)
