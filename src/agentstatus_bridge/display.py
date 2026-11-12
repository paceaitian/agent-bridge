"""本机人读端点名称（§85；§91 起改由 NameView 投影）；不用于协议、JSON、选择器或身份判断。"""

from .model import EndpointRef
from .native_names import NO_NAMES, NameBook


def endpoint_text(ref: EndpointRef, names: NameBook = NO_NAMES) -> str:
    """本机人读文本：只查本命令已有的 NameView，不回退 ref.label/pane，也不为排版另做发现（§91.4.2）。

    同绑定已核实写 `provider@名字〔消歧ID〕`；否则写 `provider@id:<ID>`，有展示名时附 `名称=…（仅展示）`。
    """
    return names.text(ref)
