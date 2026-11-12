"""联邦命令的错误类型（DESIGN §88.7）：单独成轻量模块，cli 顶层可导入而不加载联邦实现。"""

from __future__ import annotations


class FedCliError(Exception):
    """联邦命令失败：闭集原因码与退出码（沿 cli 的 2/3/6/8/9 口径）。"""

    def __init__(self, code: str, exit_code: int = 3, *, hint: str | None = None) -> None:
        super().__init__(code)
        self.code = code
        self.exit_code = exit_code
        self.hint = hint  # 可直接照抄的候选写法（只进 stderr，不进 --json 的闭集字段）
