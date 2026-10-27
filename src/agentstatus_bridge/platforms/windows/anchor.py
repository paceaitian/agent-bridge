"""Windows relay 的 launch anchor（DESIGN §90.6）：沿祖先链找到计划任务的 action conhost，持有同一代的等待句柄。

Stop-ScheduledTask 只结束 action 进程（headless conhost），cmd、venv 重定向器、relay 与 ssh 都会留下（AS-20261026-023）。
relay 持有这个 conhost 的 QUERY_LIMITED|SYNCHRONIZE 句柄；句柄变为 signaled 即任务实例已结束，由控制线程走同一关闭路径。
只沿已知祖先链向上最多 12 层，核相邻出生时刻（父不晚于子）与映像，不枚举全机命令行、不读其他会话。
定位不到就返回 None（unavailable）：relay 照常服务，只是结束任务不会随之停止 relay。
"""

from __future__ import annotations

import ntpath
from typing import Any

MAX_DEPTH = 12
WAIT_OBJECT_0 = 0
WAIT_TIMEOUT = 258


class LaunchAnchor:
    """持有的 conhost 等待句柄；只由停止控制线程等待与关闭。"""

    def __init__(self, api: Any, handle: int, pid: int, birth: int) -> None:
        self.api = api
        self.handle: int | None = handle
        self.pid, self.birth = pid, birth

    def wait(self, milliseconds: int) -> str:
        if self.handle is None:
            return "failed"
        code = self.api.k.WaitForSingleObject(self.handle, milliseconds)
        if code == WAIT_OBJECT_0:
            return "exited"
        return "alive" if code == WAIT_TIMEOUT else "failed"

    def close(self) -> None:
        handle, self.handle = self.handle, None
        if handle is not None:
            self.api.close(handle)


def bind(api: Any, *, pid: int, system_root: str | None) -> LaunchAnchor | None:
    """从 pid 向上找最近的 %SystemRoot%\\System32\\conhost.exe 祖先并持有同代句柄；任何一步失败都返回 None，不抛。"""
    if not system_root:
        return None
    expected = ntpath.normcase(ntpath.join(system_root, "System32", "conhost.exe"))
    try:
        parents = {row[0]: row[1] for row in api.process_table()}
        child_birth = api.process(pid).birth
        current = pid
        for _ in range(MAX_DEPTH):
            parent = parents.get(current, 0)
            if not parent or parent == current:
                return None
            fact = api.process(parent)
            if fact.birth > child_birth:
                return None  # 父 PID 已被复用：新进程比子进程晚生，不能当祖先
            # 同用户、非提权，映像查询前后核同一代（process_image）
            image = api.process_image(parent, str(fact.birth))
            if ntpath.normcase(image) == expected:
                return LaunchAnchor(api, api.open_wait_handle(parent, fact.birth), parent, fact.birth)
            child_birth, current = fact.birth, parent
    except OSError:
        return None
    return None
