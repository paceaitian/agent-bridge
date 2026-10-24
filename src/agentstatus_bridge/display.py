"""本机人读端点名称（§85）；不用于协议、JSON、选择器或身份判断。"""

from .model import EndpointRef, UNRESOLVED_NATIVE_ID


def endpoint_text(ref: EndpointRef, *, label: str | None = None, id_prefix: str | None = None) -> str:
    """名字旁附原生 ID；已有的消歧 ID 前缀保留，不为显示追加发现 I/O。"""
    if ref.native_id.strip() in ('', UNRESOLVED_NATIVE_ID):
        return ref.display()
    minimum = min(8, len(ref.native_id))
    name = label or ref.label or ref.pane
    named_id = name.removeprefix('id:') if name else ''
    is_id = len(named_id) >= minimum and ref.native_id.startswith(named_id)
    prefix = (id_prefix if id_prefix and len(id_prefix) >= minimum and ref.native_id.startswith(id_prefix)
              else ref.native_id[:8])
    if is_id:
        # Windows target_name 可返回长前缀或 id:完整 UUID，不能截短后再引入歧义。
        prefix = named_id if len(named_id) > len(prefix) else prefix
    if not name or is_id:
        return f'{ref.provider.value}@{prefix}'
    return f'{ref.provider.value}@{name}〔{prefix}〕'
