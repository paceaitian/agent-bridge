"""Claude UDS 地址的纯编码，与Linux listener和peer帧共用。"""
import re

MAX_INBOX_BUFFER = 2 * 1024 * 1024

_ADDRESS_UNSAFE = re.compile(r"[^A-Za-z0-9:_/.\-]")

def encode_address(path: str) -> str:
    """回复地址：`uds:` + 路径，非安全字符按 %XX 编码。"""
    encoded = _ADDRESS_UNSAFE.sub(lambda match: "".join(f"%{byte:02X}" for byte in match.group(0).encode("utf-8")), path)
    return f"uds:{encoded}"
