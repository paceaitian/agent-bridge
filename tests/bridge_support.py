"""协作桥测试夹具：合成 /proc、端点与可记录调用的假投递通道。"""

from __future__ import annotations

from collections.abc import Callable, Sequence
import os
from pathlib import Path

from agentstatus_bridge.model import Delivery, Endpoint, EndpointRef, Provider, Runtime
from agentstatus_bridge.transports import DeliveryContext, DeliveryOutcome


class FakeProc:
    """在临时目录里构造 /proc 的最小子集：stat、cmdline 与 fd 符号链接。"""

    def __init__(self, root: Path) -> None:
        self.root = root

    def add(
        self,
        pid: int,
        *,
        comm: str,
        ppid: int = 1,
        start: str = "100",
        argv: Sequence[str] = (),
        fds: Sequence[str] = (),
        tty: int = 0,
    ) -> int:
        directory = self.root / str(pid)
        (directory / "fd").mkdir(parents=True, exist_ok=True)
        # stat 去掉 pid 与 (comm) 后：[0]=state [1]=ppid [2]=pgrp [3]=session [4]=tty_nr … [19]=starttime
        fields = ["0"] * 17
        fields[2] = str(tty)
        filler = " ".join(fields)
        (directory / "stat").write_text(f"{pid} ({comm}) S {ppid} {filler} {start} 0 0\n", encoding="utf-8")
        payload = b"\0".join(item.encode("utf-8") for item in argv)
        (directory / "cmdline").write_bytes(payload + (b"\0" if argv else b""))
        for index, target in enumerate(fds):
            os.symlink(target, directory / "fd" / str(index + 3))
        return pid


def ref(
    provider: Provider = Provider.CODEX,
    native: str = "thread-impl",
    *,
    pid: int = 1000,
    start: str = "100",
    pane: str | None = "%1",
    label: str | None = "work",
) -> EndpointRef:
    return EndpointRef(provider=provider, native_id=native, pid=pid, start_ticks=start, pane=pane, label=label)


def endpoint(
    reference: EndpointRef,
    *,
    runtime: Runtime = Runtime.IDLE,
    issues: Sequence[str] = (),
    socket_path: str | None = None,
    name: str | None = None,
) -> Endpoint:
    return Endpoint(
        ref=reference,
        runtime=runtime,
        runtime_source="test",
        socket_path=socket_path,
        name=name,
        issues=tuple(issues),
    )


OutcomeFactory = Callable[[Endpoint, str, DeliveryContext], DeliveryOutcome]


class RecordingTransport:
    """记录每次外调；结果可以是固定值、按调用生成，或抛出异常。"""

    def __init__(
        self,
        provider: Provider,
        outcome: DeliveryOutcome | OutcomeFactory | None = None,
        error: Exception | None = None,
    ) -> None:
        self.provider = provider
        self.calls: list[tuple[Endpoint, str, DeliveryContext]] = []
        self._outcome = outcome or DeliveryOutcome(Delivery.QUEUED, "codex_queued", provider_ref="item-1")
        self.error = error

    def deliver(self, endpoint: Endpoint, text: str, context: DeliveryContext) -> DeliveryOutcome:
        self.calls.append((endpoint, text, context))
        if self.error is not None:
            raise self.error
        if callable(self._outcome):
            return self._outcome(endpoint, text, context)
        return self._outcome
