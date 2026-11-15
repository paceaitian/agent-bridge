"""Local display/selection names, never identity or a full cwd."""
import ntpath
import unicodedata

from ...model import NameSource
from ...native_names import codex_source

NATIVE_LIMIT = 96  # 与本机显示上限一致；超出时保存截断事实（§91.3）


def safe_name(value: object) -> str:
    if not isinstance(value, str):
        return ''
    return ''.join(f'\\u{ord(c):04x}' if unicodedata.category(c).startswith('C') else c
                   for c in value.strip()[:96])[:96]


def names(value: dict) -> tuple[str, str]:
    cwd = value.get('cwd')
    return (safe_name(value.get('name')),
            safe_name(ntpath.basename(cwd.rstrip('/\\'))) if isinstance(cwd, str) else '')


def fields_valid(value: dict) -> bool:
    return all(value.get(key) is None or isinstance(value.get(key), str) for key in ('name', 'cwd'))


def _tail(cwd: str) -> str:
    return ntpath.basename(cwd.rstrip('/\\'))


def name_from_cwd(value: dict) -> bool:
    """原生主名是否取自 cwd 末段（与 codex_source 的分支一致：name 缺失值或为空串、cwd 有内容）。

    响应里没有 name 键或字段类型非法时名字来源未知，不算取自 cwd。本机显示据此判断目录是否与名字重复（§95.3，
    审计 r1 Opus P3-7：名字按 96 字符截断，与 120 字符的目录比较字符串会误判成不同）。"""
    if 'name' not in value or not fields_valid(value):
        return False
    name, cwd = value.get('name'), value.get('cwd')
    return not (isinstance(name, str) and name != '') and isinstance(cwd, str) and bool(cwd.strip())


def native_source(value: dict) -> NameSource | None:
    """原生主名事实（§91.3）：保留原文与截断事实，不转义、不 strip；与 names() 的 cwd 末段取法一致。

    响应里没有 name 键是旧服务端（上游 Thread.name 总会序列化），返回 None 表示来源未知；字段类型非法同样未知。
    """
    if 'name' not in value or not fields_valid(value):
        return None
    return codex_source(value.get('name'), value.get('cwd'), basename=_tail, limit=NATIVE_LIMIT)
