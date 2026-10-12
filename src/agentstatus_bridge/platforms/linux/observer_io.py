"""R的Linux D-Bus读取边界：一次ListSessions，不自动启动daemon。"""

def read_reply(bus_name: str, object_path: str, interface_name: str) -> object:
    """读一次 ListSessions 并返回其中的对象行（可能为空）；不可用、超限或格式不对时返回 None。"""
    try:
        import gi

        gi.require_version("Gio", "2.0")
        from gi.repository import Gio  # pyright: ignore[reportAttributeAccessIssue]

        proxy = Gio.DBusProxy.new_for_bus_sync(
            Gio.BusType.SESSION,
            Gio.DBusProxyFlags.DO_NOT_AUTO_START,
            None,
            bus_name,
            object_path,
            interface_name,
            None,
        )
        flags = getattr(Gio.DBusCallFlags, "NO_AUTO_START", Gio.DBusCallFlags.NONE)
        reply = proxy.call_sync("ListSessions", None, flags, 2000, None)
        raw = reply.unpack()[0]
    except Exception:  # 可选数据源：任何失败都只意味着“状态未知”
        return None
    return raw
