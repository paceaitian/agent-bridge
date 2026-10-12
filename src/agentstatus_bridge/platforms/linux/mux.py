"""Linux tmux 只读采样：保持两条命令、原先解析/空表/超时合同。"""
import re
import subprocess

from ..pane import PaneInfo, _with_title
from ..types import Capability, MuxSnapshot, SampleState

def tmux_panes() -> dict[int, PaneInfo]:
    """读取默认 tmux server 的 pane（只读 list-panes）；tmux 不可用时返回空。"""
    try:
        completed = subprocess.run(
            # #{pid} 是 tmux server PID：observer 的 Codex 会话键含它，摘要据此复算绑定（DESIGN §45.14）
            ["tmux", "list-panes", "-a", "-F", "#{pane_pid}\t#{pane_id}\t#{pid}\t#{session_name}"],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            errors="replace",
            timeout=3.0,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return {}
    if completed.returncode != 0:
        return {}
    panes: dict[int, PaneInfo] = {}
    for line in completed.stdout.splitlines():
        parts = line.split("\t", 3)
        if (
            len(parts) != 4
            or not parts[0].isdigit()
            or not re.fullmatch(r"%[0-9]+", parts[1])
            or not parts[2].isdigit()
        ):
            continue
        panes[int(parts[0])] = PaneInfo(
            pane_id=parts[1], pane_pid=int(parts[0]), session_name=parts[3][:80], server_pid=int(parts[2])
        )
    return panes


def tmux_pane_titles() -> dict[str, str]:
    """读取各 pane 的标题（只读 list-panes）：pane_id → 原始标题，只在内存里用于抽 thread-id；tmux 不可用时返回空。

    与 `tmux_panes` 分两次调用：现有格式里 `session_name` 放最后并允许含 tab，两个自由文本字段只能有一个
    放末尾（DESIGN §53.3.2）。两次之间 pane 有变化时，对不上的 pane 当作没有标题，下次发现即恢复。
    `-u` 让 tmux 不看调用方的 locale 也按 UTF-8 输出：非 UTF-8 环境下 tmux 会把 spinner 换成 `_`，
    标题生成那几秒就认不出 thread-id（Opus 实现复核 P3-3）。
    """
    try:
        completed = subprocess.run(
            ["tmux", "-u", "list-panes", "-a", "-F", "#{pane_id}\t#{pane_title}"],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            errors="replace",
            timeout=3.0,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return {}
    if completed.returncode != 0:
        return {}
    titles: dict[str, str] = {}
    for line in completed.stdout.splitlines():
        pane_id, separator, title = line.partition("\t")
        if separator and re.fullmatch(r"%[0-9]+", pane_id):
            titles[pane_id] = title
    return titles


class LinuxMux:
    capability = Capability.VERIFIED
    @staticmethod
    def panes() -> dict[int, PaneInfo]:
        return tmux_panes()
    @staticmethod
    def titles() -> dict[str, str]:
        return tmux_pane_titles()
    def sample(self) -> MuxSnapshot:
        titles = self.titles()
        panes = {pid: _with_title(pane, titles.get(pane.pane_id)) for pid, pane in self.panes().items()}
        return MuxSnapshot(SampleState.AVAILABLE if panes else SampleState.EMPTY, panes)
