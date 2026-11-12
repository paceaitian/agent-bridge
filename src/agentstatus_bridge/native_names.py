"""ab 原生主名与 ID 寻址的纯投影（DESIGN §91）：选择器语法、NameFacts→NameView、跨设备名字输出。

身份始终是 provider/nativeId 加绑定；原生名字只是当前便利入口。本模块不做 I/O、不读 tmux/pane/alias，
平台适配器负责采样原生名字并提供本机碰撞证据（否证钩子），这里只做唯一一套判定。
"""
from __future__ import annotations

from collections.abc import Callable, Hashable, Iterable, Mapping
from dataclasses import dataclass, field
import re
from typing import Literal
import unicodedata

from .model import Endpoint, EndpointRef, NameSource, NameView, Provider, UNRESOLVED_NATIVE_ID

UUID_TEMPLATE = 'xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx'
UUID_SHAPE = re.compile(r'[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}')
MIN_PREFIX = 8
WIRE_TOKEN = re.compile(r'\S{1,64}')
DISPLAY_LIMIT = 120

# 本节新增的 CLI 错误码；只出现在 stderr/--json，不进账本、信封或 hub（§91.2.2）
TARGET_PROVIDER_REQUIRED = 'target_provider_required'
TARGET_ID_INVALID = 'target_id_invalid'
TARGET_ID_UNVERIFIED = 'target_id_unverified'


class SelectorError(ValueError):
    """选择器语法错误；args[0] 是闭集错误码。"""


@dataclass(frozen=True)
class Selector:
    """解析后的 `--to` 值：provider 可缺；kind 决定只按名字、完整 ID 或显式 ID 前缀匹配，三者互不回退。"""
    provider: Provider | None
    kind: Literal['name', 'id', 'prefix']
    value: str


def _uuid_prefix(value: str) -> bool:
    """逐位置核对标准带短横线 UUID 的前缀形状。"""
    if not MIN_PREFIX <= len(value) <= len(UUID_TEMPLATE):
        return False
    for char, slot in zip(value, UUID_TEMPLATE):
        if slot == '-':
            if char != '-':
                return False
        elif char not in '0123456789abcdef':
            return False
    return True


def parse_selector(raw: str) -> Selector:
    """按 §91.2.1 解析选择器：显式 `id:` 只认 ≥8 位 UUID 前缀或完整 ID；裸完整 UUID 只按完整 ID；其余只按名字。

    名字区分大小写、不折空白；未命中名字绝不改按 ID 前缀找。空值报 target_explicit_required。
    """
    text = raw.strip()
    provider: Provider | None = None
    head, sep, tail = text.partition('@')
    if sep:
        try:
            provider = Provider(head.strip().lower())
        except ValueError:
            provider = None
        else:
            text = tail.strip()
    if not text:
        raise SelectorError('target_explicit_required')
    if text[:3].lower() == 'id:':
        value = text[3:].strip().lower()
        if not _uuid_prefix(value):
            raise SelectorError(TARGET_ID_INVALID)
        return Selector(provider, 'id' if len(value) == len(UUID_TEMPLATE) else 'prefix', value)
    if UUID_SHAPE.fullmatch(text):
        return Selector(provider, 'id', text.lower())
    return Selector(provider, 'name', text)


UNKNOWN_NAME = NameSource('unknown')
NO_NAME = NameSource('unnamed')


def name_source(value: object, *, limit: int | None = None, known: bool = True) -> NameSource:
    """把原生字段投影成 NameSource：非字符串或空白视为无名；超过 limit 时保存截断事实（恰好等于不算）。"""
    if not known:
        return UNKNOWN_NAME
    if not isinstance(value, str) or not value.strip():
        return NO_NAME
    if limit is not None and len(value) > limit:
        return NameSource('named', value[:limit], True)
    return NameSource('named', value)


def codex_source(name: object, cwd: object, *, basename: Callable[[str], str], limit: int | None = None) -> NameSource:
    """Codex 主名（§91.3）：thread.name 原文非空就用它，即使只有空白或不安全也不降到 cwd；
    只有确认无名（None 或空串）才用原生 thread cwd 的末段。调用方须先确认名字字段已读到。
    """
    if isinstance(name, str) and name != '':
        if limit is not None and len(name) > limit:
            return NameSource('named', name[:limit], True)
        return NameSource('named', name)
    if isinstance(cwd, str) and cwd.strip():
        return name_source(basename(cwd), limit=limit)
    return NO_NAME


@dataclass(frozen=True)
class NameFacts:
    """本轮一个实际绑定的命名事实；binding 是去重键（本机含 PID/出生代际，远端含 endpointId/revision）。"""
    binding: Hashable
    provider: Provider
    native_id: str
    source: NameSource


def canonical(source: NameSource) -> str | None:
    """参与碰撞否证的规范值：原文去首尾空白；无名/未知为 None。显示用的原文不受影响。"""
    if source.state != 'named' or source.raw is None:
        return None
    value = source.raw.strip()
    return value or None


def _altered_char(char: str) -> bool:
    """某个真实消费者会改动的字符：Claude 帧发送方名删掉 Cc/Cf/Cs/Zl/Zp，Windows safe_name 把 C* 全部转义；取并集。"""
    category = unicodedata.category(char)
    return category[0] == 'C' or category in ('Zl', 'Zp')


def _altered_by_a_consumer(value: str) -> bool:
    """名字里是否有会被改动的字符；这类名字照抄后与原名不等（例如零宽空格、emoji 的 ZWJ），只能作展示（§91.4.2 不改名字）。"""
    return any(_altered_char(char) for char in value)


def copyable(source: NameSource) -> bool:
    """规范值能否作为可复制名字：首尾无空白、未截断、没有会被消费者改动的字符，且不是 `id:` 开头或 UUID 形状。"""
    value = canonical(source)
    return (value is not None and source.raw == value and not source.truncated
            and not _altered_by_a_consumer(value) and value[:3].lower() != 'id:' and not UUID_SHAPE.fullmatch(value))


def _escape(char: str) -> str:
    """展示用转义：BMP 内写 \\uXXXX，之外写 \\UXXXXXXXX，免得 U+F0000 加「y」与 U+F000 加「0y」看起来一样（Opus r3 P3-1）。"""
    code = ord(char)
    return f'\\u{code:04x}' if code <= 0xFFFF else f'\\U{code:08x}'


def display_text(source: NameSource) -> str | None:
    """转义后的展示名：会被消费者改动的字符（同 copyable 的拒绝集合，含 RLO、零宽字符）写成 \\uXXXX（BMP 之外写定长
    \\UXXXXXXXX），免得同一行后面的 target= 被视觉倒排或两个名字看起来相同；首尾空白用引号标出，截断与超长加省略
    号，总长不超 120。"""
    if source.state != 'named' or source.raw is None or not source.raw.strip():
        return None
    text = ''.join(_escape(char) if _altered_char(char) else char for char in source.raw)
    if source.raw != source.raw.strip():
        text = f'"{text}"'
    if source.truncated:
        text += '…'
    return text if len(text) <= DISPLAY_LIMIT else text[:DISPLAY_LIMIT - 1] + '…'


def id_prefix(native_id: str, ids: Iterable[str], *, complete: bool) -> str:
    """展示用 ID：从 8 位起增长到同 provider 完整候选全集中唯一；全集不完整或无法唯一时给完整 ID。"""
    return id_prefixes({native_id, *ids}, complete=complete)[native_id]


def id_prefixes(ids: Iterable[str], *, complete: bool) -> dict[str, str]:
    """一次算出全集中每个 ID 的消歧前缀，结果同 id_prefix。

    排序后只需与前后邻居比公共前缀（与任一他者的最长公共前缀必在相邻处取到），O(N log N)；
    Windows Codex 最多 4096 行，逐行扫全集会变成平方级（§91.3 一次索引）。
    """
    ordered = sorted(set(ids))
    if not complete:
        return {native_id: native_id for native_id in ordered}

    def common(left: str, right: str) -> int:
        size = 0
        for a, b in zip(left, right):
            if a != b:
                break
            size += 1
        return size
    result: dict[str, str] = {}
    for index, native_id in enumerate(ordered):
        shared = max((common(native_id, ordered[other]) for other in (index - 1, index + 1)
                      if 0 <= other < len(ordered)), default=0)
        length = max(MIN_PREFIX, shared + 1)
        result[native_id] = native_id[:length] if length < len(native_id) else native_id
    return result


Negation = Callable[[NameFacts, str], bool]


def project(facts: Iterable[NameFacts], *, complete: Mapping[Provider, bool],
            negated: Negation | None = None) -> dict[Hashable, NameView]:
    """按 §91.3 计算每个绑定的 NameView。顺序不可倒置：先原生全集唯一，再交适配器否证（只能 true→false）。

    同一 provider 全集不完整，或其中有任一绑定名字来源未知，该 provider 的原生名一律未核实；
    消歧前缀只取决于身份全集是否完整。
    名字比较区分大小写；不可复制的名字（边缘空白、截断、保留形状）仍以规范值参与否证别人。
    """
    rows = list({fact.binding: fact for fact in facts}.values())  # 同绑定重复来源只算一次
    owners: dict[tuple[Provider, str], set[Hashable]] = {}
    unknown: set[Provider] = set()
    ids: dict[Provider, set[str]] = {}
    for fact in rows:
        ids.setdefault(fact.provider, set()).add(fact.native_id)
        if fact.source.state == 'unknown':
            unknown.add(fact.provider)
        value = canonical(fact.source)
        if value is not None:
            owners.setdefault((fact.provider, value), set()).add(fact.binding)
    # 消歧前缀只看身份全集是否完整；名字来源未知不等于身份缺证（§91.2.2：namesVerified 与前缀全集证明互不替代）
    prefixes = {provider: id_prefixes(values, complete=bool(complete.get(provider))) for provider, values in ids.items()}
    views: dict[Hashable, NameView] = {}
    for fact in rows:
        whole = bool(complete.get(fact.provider)) and fact.provider not in unknown
        value = canonical(fact.source)
        name = value if copyable(fact.source) else None
        verified = (name is not None and whole and owners[(fact.provider, name)] == {fact.binding}
                    and not (negated is not None and negated(fact, name)))
        resolved = fact.native_id.strip() not in ('', UNRESOLVED_NATIVE_ID)
        views[fact.binding] = NameView(
            fact.provider, fact.native_id, name, display_text(fact.source), verified,
            prefixes[fact.provider][fact.native_id] if resolved else fact.native_id)
    return views


LOCAL = 'local'


def wire_name(view: NameView, *, endpoint_device: str | None, render_device: str | None) -> str:
    """跨设备可复制标识（§91.4.2，附注 P3-5/P3-7）：只有端点与最终呈现都在本机（LOCAL）且主名已核实、
    整个 `provider@名字` 满足 \\S{1,64} 才用原生名；其余一律 `provider@id:<完整ID>`。

    设备未知（None）不默认本机。完整 ID 形式超过 64 字符或含空白时，回退为带省略号的仅展示 token：
    它不是合法选择器，照抄只会报 target_id_invalid，不会误选。
    """
    if (endpoint_device == LOCAL and render_device == LOCAL and view.verified and view.name is not None
            and WIRE_TOKEN.fullmatch(f'{view.provider.value}@{view.name}')):
        return f'{view.provider.value}@{view.name}'
    token = f'{view.provider.value}@id:{view.native_id}'
    if WIRE_TOKEN.fullmatch(token):
        return token
    head = f'{view.provider.value}@id:'
    visible = ''.join(char for char in view.native_id if not char.isspace())
    return head + visible[:63 - len(head)] + '…'


def endpoint_text(view: NameView) -> str:
    """本机人读文本：已核实写 `provider@名字〔消歧ID〕`；否则写 `provider@id:<前缀或全ID>`，另有展示名时附
    `名称=…（仅展示）`；ID 未解析写 `provider（ID未解析）`。不用于协议、JSON 或选择器。
    """
    provider = view.provider.value
    if view.native_id.strip() in ('', UNRESOLVED_NATIVE_ID):
        return f'{provider}（ID未解析）'
    if view.verified and view.name is not None:
        return f'{provider}@{view.name}〔{view.id_prefix}〕'
    text = f'{provider}@id:{view.id_prefix}'
    return f'{text} 名称={view.display_name}（仅展示）' if view.display_name else text


Binding = tuple[Provider, str, int, str, str | None]


def binding(ref: EndpointRef) -> Binding:
    """本机实际绑定键（唯一定义，Linux 适配器与 NameBook 共用）：provider、原生 ID（小写）、进程代际与数据根；
    同一 ID 的不同进程、代际或根是不同绑定，不按 nativeId 折叠。"""
    return (ref.provider, ref.native_id.lower(), ref.pid, ref.start_ticks, ref.data_root)


def unnamed(ref: EndpointRef) -> NameView:
    """没有同绑定名字证据时的视图（旧账本、已退出、只有 ref）：无名、未核实、完整 ID，不为排版另做发现。"""
    return NameView(ref.provider, ref.native_id, None, None, False, ref.native_id)


@dataclass(frozen=True)
class NameBook:
    """本命令或本轮 worker 已有的 NameView，按本机绑定查（§91.4.2）；只查表，不做 I/O、不回退 ref.label/pane。"""
    views: dict[Binding, NameView] = field(default_factory=dict)

    @classmethod
    def of(cls, endpoints: Iterable[Endpoint]) -> NameBook:
        """从本轮发现的端点收集它们携带的 NameView；没带的端点就是没有名字证据。"""
        return cls({binding(item.ref): item.name_view for item in endpoints if item.name_view is not None})

    def view(self, ref: EndpointRef) -> NameView:
        return self.views.get(binding(ref)) or unnamed(ref)

    def wire(self, ref: EndpointRef, *, endpoint_device: str | None, render_device: str | None) -> str:
        """可复制标识：设备上下文必须显式给出，未知不当本机。"""
        return wire_name(self.view(ref), endpoint_device=endpoint_device, render_device=render_device)

    def local_wire(self, ref: EndpointRef) -> str:
        """纯本机路径（无联邦）：端点与最终呈现都在本机，显式标 LOCAL。"""
        return self.wire(ref, endpoint_device=LOCAL, render_device=LOCAL)

    def text(self, ref: EndpointRef) -> str:
        """本机人读文本（endpoint_text）。"""
        return endpoint_text(self.view(ref))


NO_NAMES = NameBook()


def id_token(provider: Provider, native_id: str) -> str:
    """按结构化身份（provider + 原生 ID）生成的可复制标识：`provider@id:<完整ID>`，超长 ID 回退为仅展示 token。

    跨设备文本（联邦消息头、from-name、自动正文）一律用它，不照抄对端给的 wireToken 或 displayLabel（§91.4.2）。
    """
    return wire_name(NameView(provider, native_id, None, None, False, native_id), endpoint_device=None,
                     render_device=None)


SENDER_NAME_LIMIT = 64  # 与 transports.claude_peer.MAX_SENDER_NAME_CODEPOINTS 一致；接收端按它截断


def sender_display(token: str, device: str) -> str:
    """跨设备帧 from-name：`{token}（{设备}）`，总长不超过 64 码点。

    超长时只截设备名并加省略号，token 保持完整可复制（接收端截断会切掉 token 尾部，ID 就不可用了）。
    """
    budget = SENDER_NAME_LIMIT - len(token) - 2
    if budget >= len(device):
        return f'{token}（{device}）'
    if budget >= 2:
        return f'{token}（{device[:budget - 1]}…）'
    return token


def full_id_token(ref: EndpointRef) -> str:
    """跨设备、随事实保存或转发的标识（联邦 wireToken 等）：一律完整 ID，不绑定任何展示地点（§91.4.2）。"""
    return id_token(ref.provider, ref.native_id)
