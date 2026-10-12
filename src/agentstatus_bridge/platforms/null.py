"""未接入的平台能力；空值不冒称采样成功、会话退出、idle或无头shell。"""
from ..observer_dbus import ObserverView
from .types import Capability, MuxSnapshot, RuntimeSnapshot, SampleState
from .pane import PaneInfo


class NullMux:
    capability = Capability.UNVERIFIED
    def panes(self) -> dict[int, PaneInfo]:
        return {}
    def titles(self) -> dict[str, str]:
        return {}
    def sample(self) -> MuxSnapshot:
        return MuxSnapshot(SampleState.UNVERIFIED)


class NullRuntime:
    capability = Capability.UNSUPPORTED
    def sample(self) -> RuntimeSnapshot:
        return RuntimeSnapshot(SampleState.UNAVAILABLE)
    def view(self) -> ObserverView:
        return self.sample().view
