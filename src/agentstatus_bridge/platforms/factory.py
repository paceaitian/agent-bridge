"""唯一后端选择点；构造不做IO，Windows阶段能力默认关闭。"""
from pathlib import Path
import sys
from contextlib import contextmanager
from contextvars import ContextVar
from collections.abc import Iterator
from typing import Any

from .null import NullMux, NullRuntime
from .types import BridgePlatform, Capability


def make_platform(name: str | None = None, *, proc_root: Path | None = None, win_api: Any = None) -> BridgePlatform:
    selected = sys.platform if name is None else name
    if selected == 'linux':
        from .linux.process_backend import LinuxProcess  # layout: allow 只在选中Linux时导入；Windows不加载Linux原语
        from .linux.mux import LinuxMux  # layout: allow 同一组合根的Linux M后端
        from .linux.runtime import LinuxRuntime  # layout: allow 同一组合根的Linux R后端
        from .linux.files import LinuxPaths  # layout: allow 同一组合根的Linux F后端
        from .linux.lifecycle import LinuxLifecycle  # layout: allow 同一组合根的Linux L后端
        from .linux.local_transport import LinuxPlatform  # layout: allow 同一组合根的Linux T，复用§69接缝
        files = LinuxPaths()
        return BridgePlatform('linux', LinuxProcess(proc_root), LinuxMux(), LinuxRuntime(), Capability.VERIFIED,
                              files, LinuxLifecycle(), LinuxPlatform(files))
    if selected in {'win32', 'windows'}:
        from .windows.lazy import LazyApi  # layout: allow 仅选中Windows时组装，不装载DLL
        from .windows.process import WindowsProcess  # layout: allow Windows P
        from .windows.files import WindowsPaths  # layout: allow Windows F
        from .windows.lifecycle import WindowsLifecycle  # layout: allow Windows L
        from .windows.local_transport import WindowsPlatform  # layout: allow W2只读T；写能力仍未开放
        api = win_api if win_api is not None else LazyApi()
        files = WindowsPaths(api)
        return BridgePlatform('windows', WindowsProcess(api), NullMux(), NullRuntime(), Capability.UNVERIFIED,
                              files, WindowsLifecycle(api, files), WindowsPlatform(api, files))
    raise ValueError('platform_unsupported')


_selected: ContextVar[BridgePlatform | None] = ContextVar('bridge_platform', default=None)


def get_platform() -> BridgePlatform:
    """所有间接消费者共享的组合根；构造不采样，显式注入按调用作用域恢复。"""
    return _selected.get() or make_platform()


@contextmanager
def using_platform(platform: BridgePlatform) -> Iterator[None]:
    token = _selected.set(platform)
    try:
        yield
    finally:
        _selected.reset(token)
