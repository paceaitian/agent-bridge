"""M 组合根入口；旧函数签名留作明确的采样注入接缝。"""
from collections.abc import Mapping
from .factory import get_platform
from .pane import PaneInfo


def tmux_panes() -> Mapping[int, PaneInfo]:
    return get_platform().mux.panes()


def tmux_pane_titles() -> Mapping[str, str]:
    return get_platform().mux.titles()
