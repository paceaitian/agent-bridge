"""R接口：Linux可选observer。状态与证据时刻始终来自同一整行。"""
from ... import observer_dbus
from ..types import Capability, RuntimeSnapshot, SampleState


class LinuxRuntime:
    capability = Capability.VERIFIED
    @staticmethod
    def sample() -> RuntimeSnapshot:
        rows = observer_dbus._observer_rows()
        return RuntimeSnapshot(SampleState.UNAVAILABLE if rows is None else SampleState.AVAILABLE,
                               observer_dbus._view_from_rows(rows or []))
    @staticmethod
    def view() -> observer_dbus.ObserverView:
        return LinuxRuntime.sample().view
