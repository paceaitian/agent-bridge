"""协作桥测试夹具：合成 /proc、端点、可记录调用的假投递通道与临时账本用例基类；布局守卫的扫描与判定（DESIGN §48 R0）。"""

from __future__ import annotations

import ast
from collections.abc import Callable, Collection, Iterable, Sequence
from dataclasses import dataclass, replace
import functools
import importlib
import io
import json
import os
from pathlib import Path
import symtable
from tempfile import TemporaryDirectory
import tokenize
import types
from typing import Any
import unittest


def _isolate_host_session_environment() -> None:
    """Drop inherited identity/routing inputs before importing bridge code.

    Keep runner paths, private runtime/DBus locations, CI controls and golden
    switches; tests needing session inputs must explicitly patch them in.
    """
    names = {'CLAUDECODE', 'CLAUDE_PID', 'CLAUDE_SESSION_ID', 'CLAUDE_CONFIG_DIR', 'TMUX', 'TMUX_PANE'}
    for name in tuple(os.environ):
        upper = name.upper()
        if upper.endswith('_WRITE_GOLDEN'):
            continue  # verify must still detect/reject inherited golden writes
        if upper in names or upper.startswith(('AB_', 'CLAUDE_CODE_', 'CODEX_', 'GROK_')):
            os.environ.pop(name, None)


_isolate_host_session_environment()

from agentstatus_bridge import summary
from agentstatus_bridge.endpoints import DiscoverySources
from agentstatus_bridge.model import Attempt, Delivery, Endpoint, EndpointRef, Flow, Provider, Runtime, Task
from agentstatus_bridge.observer_dbus import ObserverView
from agentstatus_bridge.store import Store
from agentstatus_bridge.transports import DeliveryContext, DeliveryOutcome


from bridge_platform_guard import ProductionSocketUse  # 兼容已有用例；导入即安装平台连接守卫
import bridge_short_socket_guard  # 独立于受变异 helper，禁止测试回收真实共享目录


def _isolate_host_policy_dirs() -> None:
    """桥判类默认按宿主 Claude/Grok 系统策略目录是否存在来决定能否声明 bypass；测试一律改指不存在的临时路径，
    免得受管机器或 WSL（官方：`/etc/claude-code` 在 WSL 上用户可写）上的 core 因宿主环境变红（§73.7）。
    需要「存在」的用例自己传目录或再补丁。这里用不停止的 patch.object：测试里不要调用 `patch.stopall()`，
    否则这层隔离会悄悄失效。"""
    import atexit
    import shutil
    import tempfile
    from unittest import mock

    root = Path(tempfile.mkdtemp(prefix="agentstatus-test-policy-"))
    atexit.register(shutil.rmtree, root, ignore_errors=True)
    # §84: install BEFORE default discovery can inspect live /proc environ.
    os.environ['AB_CLAUDE_SESSIONS_DIR'] = str(root / 'isolated-sessions')
    # 回滚门加载真实旧src；按真实拥有者选择隔离目标，新版不能留一个不生效的旧模块patch。
    try:
        from agentstatus_bridge.platforms.linux import files as policy_owner
    except ImportError:
        # 仅真实历史src回滚子进程走这里；当前拥有者由直接import及隔离用例钉住。
        policy_owner = importlib.import_module(".".join(("agentstatus_bridge", "endpoints")))
    # 回滚旧版可能没有这些常量：有才改
    if hasattr(policy_owner, "CLAUDE_SYSTEM_DIR"):
        mock.patch.object(policy_owner, "CLAUDE_SYSTEM_DIR", root / "claude-absent").start()  # layout: allow 历史src才用旧拥有者，当前Linux files由正式隔离用例核对
    if hasattr(policy_owner, "GROK_SYSTEM_DIR"):
        mock.patch.object(policy_owner, "GROK_SYSTEM_DIR", root / "grok-absent").start()  # layout: allow 同上，兼容真实87eff52与dc3b61b回滚门


_isolate_host_policy_dirs()


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
    server: int | None = None,
) -> EndpointRef:
    return EndpointRef(
        provider=provider, native_id=native, pid=pid, start_ticks=start, pane=pane, label=label, server_pid=server
    )


def register_claude_session(reference: EndpointRef) -> Path:
    """在当前生效的 Claude 会话注册目录写一份与端点同 pid/sessionId/procStart 的记录（联邦根绑定按它核实）。

    调用方应先把 AB_CLAUDE_SESSIONS_DIR 指到本用例的临时目录，免得不同用例的同 PID 记录互相覆盖。
    """
    # 函数内导入：回滚门用当前 tests 导入历史 src，历史版本没有 claude_sessions_dirs
    from agentstatus_bridge.paths import claude_sessions_dirs  # layout: allow 兼容回滚门的历史 src

    root = claude_sessions_dirs()[0]
    root.mkdir(parents=True, exist_ok=True)
    path = root / f"{reference.pid}.json"
    path.write_text(json.dumps({"pid": reference.pid, "sessionId": reference.native_id,
                                "procStart": reference.start_ticks}), encoding="utf-8")
    return path


def endpoint(
    reference: EndpointRef,
    *,
    runtime: Runtime = Runtime.IDLE,
    issues: Sequence[str] = (),
    socket_path: str | None = None,
    name: str | None = None,
    native_name: object = "label",
) -> Endpoint:
    """测试端点。§91 起 ab 只按原生主名寻址：旧夹具用 tmux label 表达「这个会话叫 impl」，这里默认把 label
    注入为 Codex/Claude 的原生主名采样（Claude 有注册表 name 时用 name），保留按名字寻址的用例意图；
    要测「label 不是名字」时显式传 native_name=None（无名）或一个 NameSource。
    """
    from agentstatus_bridge.native_names import NO_NAME, NameSource, name_source  # layout: allow 回滚门用当前 tests 导入历史 src

    if native_name == "label":
        raw = name if name is not None else reference.label
        source = None if reference.provider is Provider.GROK else name_source(raw)
    elif native_name is None:
        source = NO_NAME
    else:
        assert isinstance(native_name, NameSource)
        source = native_name
    return Endpoint(
        ref=reference,
        runtime=runtime,
        runtime_source="test",
        socket_path=socket_path,
        name=name,
        issues=tuple(issues),
        name_source=source,
    )


def with_name_views(items: Iterable[Endpoint]) -> list[Endpoint]:
    """模拟真实 Linux 发现的最后一步（§91.4.2，`endpoints._discover_selected` 末尾）：按本轮全部端点算 NameView
    并随端点携带。假 discover 直接返回夹具端点时不带 name_view，输出侧只能给完整 ID；
    要测「名字会出现在输出里」就先经它附上，不要改回 ref.label。
    """
    from agentstatus_bridge.endpoints import name_views  # layout: allow 回滚门用当前 tests 导入历史 src

    found = list(items)
    views = name_views(found)
    return [replace(item, name_view=views[id(item)]) for item in found]


def discovering(
    endpoints: Callable[[], list[Endpoint]],
    seen: list[tuple[DiscoverySources | None, ObserverView]] | None = None,
) -> Callable[..., list[Endpoint]]:
    """`discover` 的替身：照真实 discover 的取数方式调一次 `config.runtime()`，再返回给定端点（DESIGN §55.4）。

    这样「每条命令读几次 D-Bus」能在最底层的 `_observer_rows` 上数出来；`seen` 记下收到的
    `sources` 与这次读到的快照。在 `setUp` 里生成：借用 `CliTests.setUp` 的测试类拿不到别的方法。
    """

    def fake(sources: DiscoverySources | None = None) -> list[Endpoint]:
        config = sources or DiscoverySources()
        observed = config.runtime()
        if seen is not None:
            seen.append((sources, observed))
        return endpoints()

    return fake


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


def new_task(store: Store, **changes: Any) -> tuple[Task, Attempt]:
    """用一组固定的默认字段建一条任务，`changes` 覆盖其中任意字段。"""
    options: dict[str, Any] = {
        "title": "实现 X",
        "flow": Flow.HANDOFF,
        "origin": None,
        "origin_class": None,
        "reviewer": None,
        "target": ref(),
        "body": "正文哨兵 BODY-SENTINEL",
        "refs": [],
        "now": 100.0,
    }
    options.update(changes)
    return store.create_task(**options)


class LedgerCase(unittest.TestCase):
    """每条用例一个临时账本：建任务、模拟投递、发布与读取 summary.json 的辅助方法。"""

    def setUp(self) -> None:
        temporary = TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name) / "bridge"
        self.store = Store.open(self.root)
        self.addCleanup(lambda: self.store.close())

    def create(self, **changes: Any) -> tuple[Task, Attempt]:
        return new_task(self.store, **changes)

    def deliver(self, attempt: Attempt, delivery: Delivery, *, now: float = 110.0, detail: dict[str, Any] | None = None) -> None:
        self.assertTrue(self.store.begin_send(attempt.id, now=now - 1, pid=os.getpid(), start_ticks="1"))
        self.assertTrue(
            self.store.finish_send(
                attempt.id, delivery=delivery, reason="synthetic", provider_ref=None, detail=detail or {}, now=now
            )
        )

    def publish(self, **options: Any) -> summary.PublishResult:
        return summary.publish(self.store, self.root, **options)

    def document(self) -> dict[str, Any]:
        return json.loads((self.root / summary.SUMMARY_NAME).read_text(encoding="utf-8"))

    def entry(self, task_id: str) -> dict[str, Any]:
        return next(item for item in self.document()["tasks"] if item["id"] == task_id)

    def current(self, attempt: Attempt) -> Attempt:
        loaded = self.store.get_attempt(attempt.id)
        assert loaded is not None
        return loaded

    def keys(self, attempt: Attempt) -> list[dict[str, str]]:
        return summary.binding(self.current(attempt))["observerKeys"]


# ---------------------------------------------------------------------------
# 布局守卫（DESIGN §48 R0；§49 D0c 从这里复用，两边口径一致）
#
# 规则 1 patch 目标：测试替换的位置必须真能改变运行时行为；
# 规则 2 搬移登记表：被搬的名字不能留在旧模块，也不能被纯持有（回导出）；
# 规则 3 import 图：顶层与函数内合并后无环，包内不做函数内 import；
# 规则 4 层次：指定模块之间不许 import。
# 全部是静态扫描加最小限度的运行期解析（类的 MRO、包外模块的 hasattr）。
# ---------------------------------------------------------------------------

ALLOW_MARK = "# layout: allow"
_MOCK = "unittest.mock"
_PATCH_FORMS = {
    f"{_MOCK}.patch": "patch",
    f"{_MOCK}.patch.object": "patch.object",
    f"{_MOCK}.patch.multiple": "patch.multiple",
    f"{_MOCK}.patch.dict": "patch.dict",
}


@dataclass(frozen=True)
class LayoutFinding:
    """守卫的一条发现：文件、行号、规则与说明。"""

    path: str
    line: int
    rule: str
    detail: str

    def __str__(self) -> str:
        return f"{self.path}:{self.line}: [{self.rule}] {self.detail}"


@dataclass(frozen=True)
class PatchSite:
    """测试里的一处 patch 目标。`targets` 是「容器.名」形式的点号路径，可能有多个候选；
    `nonliteral` 非空时表示静态解析不出（或首参是调用），值是原因。"""

    path: str
    line: int
    end_line: int
    form: str
    targets: tuple[str, ...] = ()
    nonliteral: str = ""
    allowed: bool = False


@dataclass(frozen=True)
class _Value:
    """表达式的静态解析结果：dotted（点号路径候选）、constant、nonliteral、call 或 other。"""

    kind: str
    paths: tuple[str, ...] = ()
    reason: str = ""


_OTHER = _Value("other")


class _Scope:
    """测试模块或函数的一层作用域：import 别名与赋值绑定（本地名 → 候选值）。
    同一本地名的多个 import 来源（分支或顺序覆盖）全部保留，不让后一条覆盖前一条（Codex 补审② 复验 R01）。"""

    def __init__(self, parent: _Scope | None) -> None:
        self.parent = parent
        self.imports: dict[str, list[str]] = {}
        self.bindings: dict[str, list[ast.expr | _Value]] = {}

    def bind(self, name: str, value: ast.expr | _Value) -> None:
        self.bindings.setdefault(name, []).append(value)

    def bind_import(self, name: str, path: str) -> None:
        self.imports.setdefault(name, []).append(path)


def _scope_statements(body: Iterable[ast.stmt]) -> Iterable[ast.stmt]:
    """逐条给出同一作用域里的语句：进入复合语句，不进入嵌套的函数与类。"""
    for statement in body:
        yield statement
        if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            continue
        for field_name in ("body", "orelse", "finalbody"):
            nested = getattr(statement, field_name, None)
            if isinstance(nested, list):
                yield from _scope_statements(item for item in nested if isinstance(item, ast.stmt))
        if isinstance(statement, ast.Try) or type(statement).__name__ == "TryStar":
            for handler in getattr(statement, "handlers", []):
                yield from _scope_statements(handler.body)
        if isinstance(statement, ast.Match):
            for case in statement.cases:
                yield from _scope_statements(case.body)


def _bind_target(scope: _Scope, target: ast.expr, value: ast.expr | _Value) -> None:
    if isinstance(target, ast.Name):
        scope.bind(target.id, value)
    elif isinstance(target, (ast.Tuple, ast.List)):
        values = value.elts if isinstance(value, (ast.Tuple, ast.List)) else None
        if values is not None and len(values) == len(target.elts):
            for element, item in zip(target.elts, values):
                _bind_target(scope, element, item)
        else:
            for element in target.elts:
                _bind_target(scope, element, _OTHER)
    elif isinstance(target, ast.Starred):
        _bind_target(scope, target.value, _OTHER)


def _collect_scope(scope: _Scope, body: Iterable[ast.stmt]) -> None:
    for statement in _scope_statements(body):
        if isinstance(statement, ast.Import):
            for alias in statement.names:
                if alias.asname:
                    scope.bind_import(alias.asname, alias.name)
                else:
                    top = alias.name.split(".")[0]
                    scope.bind_import(top, top)
        elif isinstance(statement, ast.ImportFrom):
            if statement.level == 0 and statement.module:
                for alias in statement.names:
                    scope.bind_import(alias.asname or alias.name, f"{statement.module}.{alias.name}")
        elif isinstance(statement, ast.Assign):
            for target in statement.targets:
                _bind_target(scope, target, statement.value)
        elif isinstance(statement, ast.AnnAssign) and statement.value is not None:
            _bind_target(scope, statement.target, statement.value)
        elif isinstance(statement, ast.AugAssign):
            _bind_target(scope, statement.target, _OTHER)
        elif isinstance(statement, (ast.For, ast.AsyncFor)):
            if isinstance(statement.iter, (ast.Tuple, ast.List, ast.Set)) and isinstance(statement.target, ast.Name):
                for element in statement.iter.elts:
                    scope.bind(statement.target.id, element)
            else:
                _bind_target(scope, statement.target, _OTHER)
        elif isinstance(statement, (ast.With, ast.AsyncWith)):
            for item in statement.items:
                if item.optional_vars is not None:
                    _bind_target(scope, item.optional_vars, _OTHER)
        elif isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            scope.bind(statement.name, _OTHER)
        if isinstance(statement, ast.Try):
            for handler in statement.handlers:
                if handler.name:
                    scope.bind(handler.name, _OTHER)


def _merge(values: Sequence[_Value]) -> _Value:
    """候选值合并：任一候选是必须审阅的非字面量就按非字面量，不能被可解析的候选消掉（Codex 补审② F01）；
    否则有模块候选就逐个判；全是常量才是常量。"""
    for value in values:
        if value.kind == "nonliteral":
            return value
    dotted = tuple(path for value in values if value.kind == "dotted" for path in value.paths)
    if dotted:
        return _Value("dotted", tuple(dict.fromkeys(dotted)))
    if values and all(value.kind == "constant" for value in values):
        return _Value("constant", tuple(path for value in values for path in value.paths))
    return _OTHER


def _resolve(expr: ast.expr | _Value, scope: _Scope, depth: int = 0) -> _Value:
    """把测试里的表达式静态解析成模块路径候选；认 import 别名、属性链、赋值与循环追值、
    `importlib.import_module("…")`、`sys.modules["…"]`、条件表达式（DESIGN §48 R0 规则 1 第 5 版）。"""
    if isinstance(expr, _Value):
        return expr
    if depth > 12:
        return _OTHER
    if isinstance(expr, ast.Constant) and isinstance(expr.value, str):
        return _Value("constant", (expr.value,))
    if isinstance(expr, ast.Name):
        current: _Scope | None = scope
        while current is not None:
            if expr.id in current.imports or expr.id in current.bindings:
                # 同一作用域里 import 的名字又被赋值时，两个来源都是候选，不能 import 一命中就返回（Codex 补审② F01）；
                # 同名的多个 import 来源也全是候选（复验 R01）
                candidates = [_Value("dotted", tuple(current.imports[expr.id]))] if expr.id in current.imports else []
                candidates.extend(_resolve(value, current, depth + 1) for value in current.bindings.get(expr.id, ()))
                return _merge(candidates)
            current = current.parent
        return _OTHER
    if isinstance(expr, ast.Attribute):
        base = _resolve(expr.value, scope, depth + 1)
        if base.kind == "dotted":
            return _Value("dotted", tuple(f"{path}.{expr.attr}" for path in base.paths))
        return base if base.kind == "nonliteral" else _OTHER
    if isinstance(expr, ast.Call):
        function = _resolve(expr.func, scope, depth + 1)
        if function.kind == "dotted" and "importlib.import_module" in function.paths:
            argument = expr.args[0] if expr.args else None
            if isinstance(argument, ast.Constant) and isinstance(argument.value, str):
                return _Value("dotted", (argument.value,))
            return _Value("nonliteral", reason="import_module 的参数不是字面量")
        if isinstance(expr.func, ast.Name) and expr.func.id == "__import__" and function.kind == "other":
            # 不带 fromlist 时 __import__ 返回顶层包，不能当子模块前缀解析（Opus 第 4 轮）
            return _Value("nonliteral", reason="__import__ 的结果不按模块前缀解析")
        return _Value("call")
    if isinstance(expr, ast.Subscript):
        base = _resolve(expr.value, scope, depth + 1)
        if base.kind == "dotted" and "sys.modules" in base.paths:
            key = expr.slice
            if isinstance(key, ast.Constant) and isinstance(key.value, str):
                return _Value("dotted", (key.value,))
            return _Value("nonliteral", reason="sys.modules 的键不是字面量")
        return _OTHER
    if isinstance(expr, ast.IfExp):
        return _merge([_resolve(expr.body, scope, depth + 1), _resolve(expr.orelse, scope, depth + 1)])
    return _OTHER


def _comment_lines(source: str) -> dict[int, str]:
    """用 tokenize 取注释所在行，不按文本搜 `#`（字符串里的 `#` 不算注释）。"""
    lines: dict[int, str] = {}
    try:
        for token in tokenize.generate_tokens(io.StringIO(source).readline):
            if token.type == tokenize.COMMENT:
                lines[token.start[0]] = token.string
    except (tokenize.TokenError, SyntaxError):
        pass
    return lines


def _allowed(comments: dict[int, str], node: ast.AST) -> bool:
    """放行注释认调用节点 lineno…end_lineno 覆盖的任一行。"""
    first = getattr(node, "lineno", 0)
    last = getattr(node, "end_lineno", None) or first
    return any(ALLOW_MARK in comments.get(line, "") for line in range(first, last + 1))


# patch.multiple 与 patch.dict 自己的参数名，不是被替换的属性
_MULTIPLE_OPTIONS = frozenset({"target", "spec", "create", "spec_set", "autospec", "new_callable"})
_DICT_OPTIONS = frozenset({"in_dict", "values", "clear"})


def _keyword(node: ast.Call, name: str) -> ast.expr | None:
    return next((keyword.value for keyword in node.keywords if keyword.arg == name), None)


def _module_dict(node: ast.expr | None) -> ast.expr | str | None:
    """patch.dict 的第一个参数若是某个对象的属性字典，给出那个对象（表达式或点号字符串）；否则 None。

    认 `X.__dict__`、`vars(X)` 与字符串 `"a.b.__dict__"`（mock 会 import 这个字符串，Opus 实现复核 P3-1）。
    """
    if isinstance(node, ast.Attribute) and node.attr == "__dict__":
        return node.value
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "vars" and len(node.args) == 1:
        return node.args[0]
    if isinstance(node, ast.Constant) and isinstance(node.value, str) and node.value.endswith(".__dict__"):
        return node.value[: -len(".__dict__")]
    return None


class _PatchCollector(ast.NodeVisitor):
    def __init__(self, path: str, tree: ast.Module, comments: dict[int, str]) -> None:
        self.path = path
        self.comments = comments
        self.sites: list[PatchSite] = []
        self.scope = _Scope(None)
        _collect_scope(self.scope, tree.body)

    # -- 作用域 --
    def _enter(self, node: ast.FunctionDef | ast.AsyncFunctionDef | ast.Lambda) -> None:
        outer = self.scope
        inner = _Scope(outer)
        arguments = node.args
        for argument in (*arguments.posonlyargs, *arguments.args, *arguments.kwonlyargs):
            inner.bind(argument.arg, _OTHER)
        for argument in (arguments.vararg, arguments.kwarg):
            if argument is not None:
                inner.bind(argument.arg, _OTHER)
        if not isinstance(node, ast.Lambda):
            _collect_scope(inner, node.body)
            for decorator in node.decorator_list:
                self.visit(decorator)
            for default in (*arguments.defaults, *arguments.kw_defaults):
                if default is not None:
                    self.visit(default)
            self.scope = inner
            for statement in node.body:
                self.visit(statement)
        else:
            self.scope = inner
            self.visit(node.body)
        self.scope = outer

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._enter(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._enter(node)

    def visit_Lambda(self, node: ast.Lambda) -> None:
        self._enter(node)

    # -- 记录 --
    def _site(self, node: ast.AST, form: str, *, targets: Sequence[str] = (), nonliteral: str = "") -> None:
        self.sites.append(
            PatchSite(
                path=self.path,
                line=getattr(node, "lineno", 0),
                end_line=getattr(node, "end_lineno", None) or getattr(node, "lineno", 0),
                form=form,
                targets=tuple(targets),
                nonliteral=nonliteral,
                allowed=_allowed(self.comments, node),
            )
        )

    def _object_targets(self, node: ast.Call, form: str, first: ast.expr, names: Sequence[ast.expr | str]) -> None:
        if isinstance(first, ast.Call):
            self._site(node, form, nonliteral="第一个参数本身是调用")
            return
        prefix = _resolve(first, self.scope)
        if prefix.kind == "nonliteral":
            self._site(node, form, nonliteral=prefix.reason)
            return
        if prefix.kind != "dotted":
            return  # 实例、局部变量、参数：不在范围内（已知限制）
        literal: list[str] = []
        for name in names:
            if isinstance(name, str):
                literal.append(name)
            elif isinstance(name, ast.Constant) and isinstance(name.value, str):
                literal.append(name.value)
            else:
                self._site(node, form, targets=prefix.paths, nonliteral="属性名不是字面量")
                return
        self._site(node, form, targets=[f"{path}.{name}" for path in prefix.paths for name in literal])

    def visit_Call(self, node: ast.Call) -> None:
        function = _resolve(node.func, self.scope)
        form = next((_PATCH_FORMS[path] for path in function.paths if path in _PATCH_FORMS), None)
        if function.kind == "dotted" and form is not None:
            self._patch_call(node, form)
        elif isinstance(node.func, ast.Name) and node.func.id == "setattr" and function.kind == "other":
            if len(node.args) >= 2:
                self._object_targets(node, "setattr", node.args[0], [node.args[1]])
        self.generic_visit(node)

    def _patch_call(self, node: ast.Call, form: str) -> None:
        if form == "patch":
            target: ast.expr | None = node.args[0] if node.args else None
            for keyword in node.keywords:
                if keyword.arg == "target":
                    target = keyword.value
            if target is None:
                return
            if isinstance(target, ast.Constant) and isinstance(target.value, str):
                self._site(node, form, targets=[target.value])
            else:
                self._site(node, form, nonliteral="目标字符串不是字面量")
        elif form == "patch.object":
            # 位置参数与关键字参数都认（Opus 实现复核 P3-1：全关键字的调用曾被整条跳过）
            first = node.args[0] if node.args else _keyword(node, "target")
            attribute = node.args[1] if len(node.args) >= 2 else _keyword(node, "attribute")
            if first is not None and attribute is not None:
                self._object_targets(node, form, first, [attribute])
        elif form == "patch.multiple":
            first = node.args[0] if node.args else _keyword(node, "target")
            if first is None:
                return
            if any(keyword.arg is None for keyword in node.keywords):
                self._site(node, form, nonliteral="**kwargs 展开的名字")
                return
            # spec、create 等是 patch.multiple 自己的选项，不是被替换的名字
            names = [keyword.arg for keyword in node.keywords if keyword.arg is not None and keyword.arg not in _MULTIPLE_OPTIONS]
            if isinstance(first, ast.Constant) and isinstance(first.value, str):
                self._site(node, form, targets=[f"{first.value}.{name}" for name in names])
            else:
                self._object_targets(node, form, first, names)
        elif form == "patch.dict":
            first = node.args[0] if node.args else _keyword(node, "in_dict")
            container = _module_dict(first)
            if container is None:
                return  # 替换普通字典（os.environ、sys.modules 等），不是模块属性
            if any(keyword.arg is None for keyword in node.keywords):
                self._site(node, form, nonliteral="**kwargs 展开的名字")
                return
            # 被替换的键 = values 字典的键 + 关键字参数（clear、in_dict、values 是选项）
            names: list[ast.expr | str] = [
                keyword.arg for keyword in node.keywords if keyword.arg is not None and keyword.arg not in _DICT_OPTIONS
            ]
            values = node.args[1] if len(node.args) >= 2 else _keyword(node, "values")
            if values is not None:
                if not (isinstance(values, ast.Dict) and all(
                    isinstance(key, ast.Constant) and isinstance(key.value, str) for key in values.keys
                )):
                    self._site(node, form, nonliteral="patch.dict 的键不是字面量")
                    return
                names.extend(key for key in values.keys if key is not None)
            if isinstance(container, str):
                literal = [name if isinstance(name, str) else str(getattr(name, "value")) for name in names]
                self._site(node, form, targets=[f"{container}.{name}" for name in literal])
            else:
                self._object_targets(node, form, container, names)

    def visit_Assign(self, node: ast.Assign) -> None:
        for target in node.targets:
            self._assigned(node, target)
        self.generic_visit(node)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        # 带注解的直接赋值同样替换属性；只有注解、没有值的不赋值
        if node.value is not None:
            self._assigned(node, node.target)
        self.generic_visit(node)

    def _assigned(self, node: ast.stmt, target: ast.expr) -> None:
        if isinstance(target, ast.Attribute):
            prefix = _resolve(target.value, self.scope)
            if prefix.kind == "dotted":
                self._site(node, "assign", targets=[f"{path}.{target.attr}" for path in prefix.paths])


def symtable_function_reads(source: str, filename: str = "<module>") -> set[str]:
    """独立预言机：函数与 lambda（含其中的推导式）里对隐式全局名的读取，由标准库 symtable 给出。

    与 `_function_body_reads` 的启发式各算一遍再对照（手写扫描器配独立预言机，Opus 实现复核第 2 轮 P3-1 的建议）。
    模块层、类体里的推导式在定义期求值，不算函数体；其中的 lambda 算。函数里的类体在函数被调用时执行，算
    （第 3 轮两方 P3）。
    口径按带 `from __future__ import annotations` 的模块：不带时先补上再交给 symtable——否则它把局部变量
    注解算成引用，而运行时局部注解从不求值（第 3 轮两方 P3）。仓内不带的只有 `__init__`、`__main__`。
    """
    reads: set[str] = set()
    comprehensions = {"listcomp", "setcomp", "dictcomp", "genexpr"}
    tree = ast.parse(source, filename)
    if not any(
        isinstance(node, ast.ImportFrom) and node.module == "__future__" and any(alias.name == "annotations" for alias in node.names)
        for node in tree.body
    ):
        # 插在模块文档字符串与既有 future 导入之后：只有它们能出现在 future 导入前面
        leading = 0
        for position, node in enumerate(tree.body):
            docstring = position == 0 and isinstance(node, ast.Expr) and isinstance(node.value, ast.Constant) and isinstance(node.value.value, str)
            if not (docstring or (isinstance(node, ast.ImportFrom) and node.module == "__future__")):
                break
            leading = position + 1
        tree.body.insert(leading, ast.ImportFrom(module="__future__", names=[ast.alias(name="annotations")], level=0))
        source = ast.unparse(ast.fix_missing_locations(tree))

    def walk(table: symtable.SymbolTable, in_function: bool) -> None:
        for child in table.get_children():
            if child.get_type() == "class" and in_function:
                reads.update(
                    symbol.get_name() for symbol in child.get_symbols() if symbol.is_referenced() and symbol.is_global()
                )
            if child.get_type() != "function":
                walk(child, in_function)
                continue
            counts = in_function or child.get_name() not in comprehensions
            if counts:
                reads.update(
                    symbol.get_name() for symbol in child.get_symbols() if symbol.is_referenced() and symbol.is_global()
                )
            walk(child, counts)

    walk(symtable.symtable(source, filename, "exec"), False)
    return reads


def function_read_mismatches(paths: Iterable[Path]) -> list[LayoutFinding]:
    """每个模块上，扫描器与预言机对「函数体读了哪些被 import 的名字」的结论必须相同。

    只比被 import 的名字：规则 1 只在这些名字上用函数体读取做判定，未被 import 的名字上的差异不影响结论。
    扫描器多算会把无效的 patch 放行（误判绿），少算会把有效的判红。
    """
    findings: list[LayoutFinding] = []
    for path in paths:
        source = path.read_text(encoding="utf-8")
        facts = _module_facts(os.fspath(path))
        scanner = set(facts.function_reads) & facts.imported
        oracle = symtable_function_reads(source, os.fspath(path)) & facts.imported
        for name in sorted(scanner - oracle):
            findings.append(LayoutFinding(os.fspath(path), 0, "reads-oracle", f"扫描器多算了 {name}（可能误判绿）"))
        for name in sorted(oracle - scanner):
            findings.append(LayoutFinding(os.fspath(path), 0, "reads-oracle", f"扫描器少算了 {name}（可能误判红）"))
    return findings


def collect_patch_sites(path: Path) -> list[PatchSite]:
    """扫描一个测试文件里的全部 patch 形态（DESIGN §48 R0 规则 1 的范围）。"""
    source = path.read_text(encoding="utf-8")
    tree = ast.parse(source, filename=str(path))
    collector = _PatchCollector(str(path), tree, _comment_lines(source))
    collector.visit(tree)
    return collector.sites


def _first_segment(dotted: str) -> str:
    return dotted.split(".", 1)[0]


def _import_object(dotted: str) -> object:
    """照 unittest.mock 的解析办法逐段取对象：先 getattr，取不到再 import 子模块。"""
    parts = dotted.split(".")
    current: object = importlib.import_module(parts[0])
    walked = parts[0]
    for part in parts[1:]:
        walked = f"{walked}.{part}"
        try:
            current = getattr(current, part)
        except AttributeError:
            importlib.import_module(walked)
            current = getattr(current, part)
    return current


@dataclass(frozen=True)
class _ModuleFacts:
    defined: dict[str, int]
    imported: frozenset[str]
    function_reads: frozenset[str]


def _module_level_definitions(tree: ast.Module) -> tuple[dict[str, int], set[str]]:
    defined: dict[str, int] = {}
    imported: set[str] = set()

    def add(name: str) -> None:
        defined[name] = defined.get(name, 0) + 1

    def targets(node: ast.expr) -> None:
        if isinstance(node, ast.Name):
            add(node.id)
        elif isinstance(node, (ast.Tuple, ast.List)):
            for element in node.elts:
                targets(element)
        elif isinstance(node, ast.Starred):
            targets(node.value)

    for statement in _scope_statements(tree.body):
        if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            add(statement.name)
        elif isinstance(statement, ast.Assign):
            for target in statement.targets:
                targets(target)
        elif isinstance(statement, (ast.AnnAssign, ast.AugAssign)):
            if isinstance(statement, ast.AugAssign) or statement.value is not None:
                targets(statement.target)
        elif isinstance(statement, (ast.For, ast.AsyncFor)):
            targets(statement.target)
        elif isinstance(statement, ast.Import):
            for alias in statement.names:
                imported.add(alias.asname or alias.name.split(".")[0])
        elif isinstance(statement, ast.ImportFrom):
            for alias in statement.names:
                imported.add(alias.asname or alias.name)
    return defined, imported


_NESTED_SCOPES = (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)
# 推导式也是嵌套作用域：推导变量不泄漏到外层函数（Opus 实现复核 P3-2）
_COMPREHENSIONS = (ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp)


def _walk_scope(node: ast.AST) -> Iterable[ast.AST]:
    """遍历子树但不进入嵌套的函数、类、lambda 与推导式（它们自身会给出，内部不给）。

    根节点本身是嵌套作用域时同样不展开：`_function_locals` 逐条语句调用这里，函数体里直接写的
    `def`/`class` 就是根节点，展开它会把内层的局部名与 `nonlocal` 漏到外层（Opus 实现复核第 2 轮 P3-3）。
    """
    stack = [node]
    while stack:
        current = stack.pop()
        yield current
        if not isinstance(current, (*_NESTED_SCOPES, *_COMPREHENSIONS)):
            stack.extend(ast.iter_child_nodes(current))


def _walrus_targets(node: ast.AST) -> set[str]:
    """推导式里海象赋值的目标：它们绑定到外层函数；下探嵌套推导式，遇到 lambda 与定义就停（那里的海象归它们自己）。"""
    names: set[str] = set()
    for child in ast.iter_child_nodes(node):
        if isinstance(child, _NESTED_SCOPES):
            continue
        if isinstance(child, ast.NamedExpr) and isinstance(child.target, ast.Name):
            names.add(child.target.id)
        names |= _walrus_targets(child)
    return names


def _function_locals(node: ast.FunctionDef | ast.AsyncFunctionDef | ast.Lambda) -> set[str]:
    """函数的局部名：参数、赋值目标、函数内 import 与嵌套定义，减去 global/nonlocal 声明。"""
    arguments = node.args
    names = {argument.arg for argument in (*arguments.posonlyargs, *arguments.args, *arguments.kwonlyargs)}
    names |= {argument.arg for argument in (arguments.vararg, arguments.kwarg) if argument is not None}
    if isinstance(node, ast.Lambda):
        return names
    declared: set[str] = set()
    for statement in node.body:
        for child in _walk_scope(statement):
            if isinstance(child, (ast.Global, ast.Nonlocal)):
                declared.update(child.names)
            elif isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                names.add(child.name)
            elif isinstance(child, (ast.Import, ast.ImportFrom)):
                for alias in child.names:
                    names.add(alias.asname or alias.name.split(".")[0])
            elif isinstance(child, ast.Name) and isinstance(child.ctx, ast.Store):
                names.add(child.id)
            elif isinstance(child, _COMPREHENSIONS):
                # 推导变量属于推导式自己；推导式里海象赋值的目标仍绑定到外层函数
                names |= _walrus_targets(child)
    return names - declared


def _comprehension_targets(node: ast.ListComp | ast.SetComp | ast.DictComp | ast.GeneratorExp) -> set[str]:
    return {item.id for generator in node.generators for item in ast.walk(generator.target) if isinstance(item, ast.Name)}


def _function_body_reads(tree: ast.Module) -> set[str]:
    """函数体（含方法、lambda）里对模块全局的读取；默认值、装饰器与注解在定义期求值，不算。"""
    reads: set[str] = set()

    def walk_body(nodes: Iterable[ast.AST], shadowed: frozenset[str]) -> None:
        for node in nodes:
            visit(node, shadowed)

    def visit(node: ast.AST, shadowed: frozenset[str]) -> None:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            inner = shadowed | _function_locals(node)
            walk_body(node.body, frozenset(inner))
            return
        if isinstance(node, ast.Lambda):
            visit(node.body, frozenset(shadowed | _function_locals(node)))
            return
        if isinstance(node, ast.AnnAssign):
            # 局部变量的注解运行时从不求值，不是读取（symtable 预言机对照发现，2026-09-28）
            visit(node.target, shadowed)
            if node.value is not None:
                visit(node.value, shadowed)
            return
        if isinstance(node, _COMPREHENSIONS):
            inner = frozenset(shadowed | _comprehension_targets(node))
            for index, generator in enumerate(node.generators):
                # 第一个 iter 在外层作用域求值，其余部分看得见推导变量
                visit(generator.iter, shadowed if index == 0 else inner)
                for condition in generator.ifs:
                    visit(condition, inner)
            for part in ((node.key, node.value) if isinstance(node, ast.DictComp) else (node.elt,)):
                visit(part, inner)
            return
        if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load) and node.id not in shadowed:
            reads.add(node.id)
        for child in ast.iter_child_nodes(node):
            visit(child, shadowed)

    def find_functions(node: ast.AST) -> None:
        for child in ast.iter_child_nodes(node):
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                walk_body(child.body, frozenset(_function_locals(child)))
                for decorator in child.decorator_list:
                    find_functions(decorator)
                for default in (*child.args.defaults, *child.args.kw_defaults):
                    if default is not None:
                        find_functions(default)
            elif isinstance(child, ast.Lambda):
                visit(child.body, frozenset(_function_locals(child)))
            else:
                find_functions(child)

    find_functions(tree)
    return reads


@functools.lru_cache(maxsize=None)
def _module_facts(path: str) -> _ModuleFacts:
    tree = ast.parse(Path(path).read_text(encoding="utf-8"), filename=path)
    defined, imported = _module_level_definitions(tree)
    return _ModuleFacts(defined, frozenset(imported), frozenset(_function_body_reads(tree)))


def judge_patch_target(target: str, *, form: str, packages: Collection[str]) -> str | None:
    """判定一个「容器.名」目标。返回 "" 表示有效，None 表示不在范围内，其余是问题说明。

    - 容器是包内模块：自己定义这个名字，或 import 了它且在函数体里读取；
    - 容器是包外模块（标准库、C 扩展）：前缀可解析且 hasattr（第 4 版，Opus 第 3 轮 P3-1）；
    - 容器是类：MRO 上有类在类体里定义了该属性；
    - 直接赋值只在前缀是模块时算。
    """
    prefix, _, name = target.rpartition(".")
    if not prefix:
        return "目标没有容器"
    try:
        container = _import_object(prefix)
    except Exception as error:  # noqa: BLE001 - 解析失败本身就是要报的问题
        if form == "assign":
            return None
        return f"前缀 {prefix} 解析不了（{type(error).__name__}）"
    if form == "assign" and not isinstance(container, types.ModuleType):
        return None  # 给 mock 或别的对象赋值，不是模块属性
    if isinstance(container, type):
        if any(name in vars(klass) for klass in container.__mro__):
            return ""
        return f"类 {container.__qualname__} 的 MRO 上没有定义 {name}"
    if not isinstance(container, types.ModuleType):
        return f"中间段 {prefix} 解析成了既非模块也非类的对象"
    module_name = container.__name__
    if _first_segment(module_name) not in packages:
        return "" if hasattr(container, name) else f"包外模块 {module_name} 没有属性 {name}"
    submodule = getattr(container, name, None)
    if isinstance(submodule, types.ModuleType) and submodule.__name__ == f"{module_name}.{name}":
        return ""
    source = getattr(container, "__file__", None)
    if not source:
        return f"包内模块 {module_name} 找不到源码"
    facts = _module_facts(os.fspath(source))
    if name in facts.defined:
        return ""
    if name in facts.imported:
        if name in facts.function_reads:
            return ""
        return f"{module_name} import 了 {name}，但函数体里不读它（只在模块层、类体或默认值里读，或者完全不读），patch 这里无效"
    return f"{module_name} 没有 {name}"


def check_patch_sites(
    sites: Iterable[PatchSite],
    *,
    package: str,
    owns_nonliteral: Callable[[str], bool],
    packages: Collection[str],
) -> tuple[list[LayoutFinding], int]:
    """按归属判定：字面量目标看第一段是否精确等于 `package`；非字面量看文件是否归本守卫。
    返回（发现列表，本守卫判过的字面量目标数）。"""
    findings: list[LayoutFinding] = []
    judged = 0
    for site in sites:
        if site.nonliteral:
            owned = owns_nonliteral(site.path)
            if not owned:
                continue
            if not site.allowed:
                findings.append(LayoutFinding(site.path, site.line, "patch-nonliteral", f"{site.form}：{site.nonliteral}，需要在调用上写 `{ALLOW_MARK} <原因>`"))
            continue
        for target in site.targets:
            if _first_segment(target) != package:
                continue
            problem = judge_patch_target(target, form=site.form, packages=packages)
            if problem is None:
                continue
            judged += 1
            if problem:
                findings.append(LayoutFinding(site.path, site.line, "patch-target", f"{site.form} {target}：{problem}"))
    return findings, judged


# -- 规则 2：搬移登记表 --


@dataclass(frozen=True)
class Move:
    """一条搬移登记：「旧模块:名字 → 新模块:名字」，模块名相对包根（如 `transports.codex_queue`）。"""

    old: str
    new: str
    name: str
    aliases: tuple[str, ...] = ()

    @classmethod
    def parse(cls, text: str, *, aliases: Sequence[str] = ()) -> Move:
        left, _, right = text.partition("→")
        old, _, old_name = left.strip().partition(":")
        new, _, new_name = right.strip().partition(":")
        if not (old and old_name and new and new_name) or old_name != new_name:
            raise ValueError(f"登记格式应为「旧模块:名字 → 新模块:名字」且名字不改：{text!r}")
        return cls(old.strip(), new.strip(), old_name.strip(), tuple(aliases))


def package_modules(package_dir: Path, package: str) -> dict[str, Path]:
    """包内全部模块：点号名 → 源文件。"""
    modules: dict[str, Path] = {}
    for path in sorted(package_dir.rglob("*.py")):
        if "__pycache__" in path.parts:
            continue
        relative = path.relative_to(package_dir).with_suffix("")
        parts = [package, *relative.parts]
        if parts[-1] == "__init__":
            parts = parts[:-1]
        modules[".".join(parts)] = path
    return modules


def _resolve_from(module: str, is_package: bool, node: ast.ImportFrom) -> str | None:
    if node.level == 0:
        return node.module
    base = module.split(".") if is_package else module.split(".")[:-1]
    if node.level > 1:
        base = base[: len(base) - (node.level - 1)]
    if node.module:
        base = [*base, *node.module.split(".")]
    return ".".join(base) if base else None


@dataclass(frozen=True)
class _ImportBinding:
    local: str
    source_module: str
    source_name: str
    line: int


def _module_import_bindings(modules: dict[str, Path], module: str) -> list[_ImportBinding]:
    path = modules[module]
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    is_package = path.name == "__init__.py"
    bindings: list[_ImportBinding] = []
    for statement in _scope_statements(tree.body):
        if isinstance(statement, ast.ImportFrom):
            source = _resolve_from(module, is_package, statement)
            if source is None:
                continue
            for alias in statement.names:
                bindings.append(_ImportBinding(alias.asname or alias.name, source, alias.name, statement.lineno))
    return bindings


def _name_reads(path: Path) -> dict[str, int]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    counts: dict[str, int] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load):
            counts[node.id] = counts.get(node.id, 0) + 1
    return counts


def check_moved_registry(
    package_dir: Path,
    package: str,
    moves: Sequence[Move],
    *,
    holding_exceptions: Collection[tuple[str, str]] = (),
) -> list[LayoutFinding]:
    """规则 2：旧模块不再定义、新模块恰好定义一次、包内没有纯持有（DESIGN §48 R0 第 3 版口径）。

    纯持有 = import 绑定的本地名在 import 语句以外一次都没作为 Name(Load) 出现；
    注解、类体、默认值、模块层表达式都算读取，字符串注解不算。无关的同名定义不管。
    `holding_exceptions` 里是允许纯持有的「模块:本地名」（相对包根）。
    经中间模块转手、同名有多个来源且只有部分是登记身份时，报 `moved-ambiguous-hold`（复验 R02）。
    """
    modules = package_modules(package_dir, package)
    facts = {module: _module_facts(os.fspath(path)) for module, path in modules.items()}
    bindings = {module: _module_import_bindings(modules, module) for module in modules}
    findings: list[LayoutFinding] = []

    def full(name: str) -> str:
        return package if name in ("", package) else f"{package}.{name}"

    def short(name: str) -> str:
        return name[len(package) + 1:] if name.startswith(f"{package}.") else ""

    def identities(module: str, name: str) -> frozenset[tuple[str, str]]:
        """沿静态 import 别名追到全部可能的「定义模块, 定义名」；经中间模块改名转手的也追得到（Codex 补审② F02）。

        同一模块里同名的定义与多条 import（分支或顺序覆盖）全部保留，不取首条当最终身份（复验 R02）；
        不设层数上限（复验 N02）。按「可达的定义节点」求，每次查询共用一个已访问集合：环自然终止，
        汇聚与重复的来源只走一次，工作量随节点与边数线性增长（第 3 轮 C01；import 环另由规则 3 报）。
        包外或包里找不到的来源记成不透明身份，不当作空集合，与登记身份混在一起时归歧义（第 3 轮 C02）。
        """
        found: set[tuple[str, str]] = set()
        seen: set[tuple[str, str]] = set()
        pending = [(module, name)]
        while pending:
            key = pending.pop()
            if key in seen:
                continue
            seen.add(key)
            current, local = key
            if current not in facts:
                found.add(key)
                continue
            if local in facts[current].defined:
                found.add(key)
            pending.extend((binding.source_module, binding.source_name) for binding in bindings[current] if binding.local == local)
        return frozenset(found)

    tracked: set[tuple[str, str]] = set()
    for move in moves:
        old, new = full(move.old), full(move.new)
        if new not in modules:
            findings.append(LayoutFinding(move.new, 0, "moved-new-missing", f"新模块 {new} 不存在"))
            continue
        if old in facts and facts[old].defined.get(move.name, 0):
            findings.append(LayoutFinding(os.fspath(modules[old]), 0, "moved-old-still-defines", f"{old} 仍然定义 {move.name}（复制而没删原件）"))
        count = facts[new].defined.get(move.name, 0)
        if count != 1:
            findings.append(LayoutFinding(os.fspath(modules[new]), 0, "moved-new-count", f"{new} 定义了 {move.name} {count} 次，应恰好 1 次"))
        tracked |= {(new, move.name), *((new, alias) for alias in move.aliases)}
    # 先归一到定义身份再比，不按中间模块里的名字筛：`from .x import moved as other` 再转手也认得出（Codex 补审② F02）
    for module, module_bindings in bindings.items():
        reads: dict[str, int] | None = None
        for binding in module_bindings:
            found = identities(binding.source_module, binding.source_name)
            hit = found & tracked
            if not hit or (short(module), binding.local) in holding_exceptions:
                continue
            if reads is None:
                reads = _name_reads(modules[module])
            if reads.get(binding.local, 0):
                continue
            if found <= tracked:
                rule = "moved-pure-hold"
                detail = f"{module} import 了 {binding.source_name}（本地名 {binding.local}）却一次都不读：回导出或残留 import"
            else:
                # 来源里既有搬移符号又有别的：静态定不了到底持有哪个，不冒充确定的纯持有，也不放过（复验 R02）
                rule = "moved-ambiguous-hold"
                moved = "、".join(f"{source}:{name}" for source, name in sorted(hit))
                others = "、".join(f"{source}:{name}" for source, name in sorted(found - tracked))
                detail = (
                    f"{module} import 的 {binding.local} 一次都不读，而它在中间模块里有多个同名来源："
                    f"搬移符号 {moved}，以及 {others}；删掉这条不读的 import，或让中间模块改用不同本地名"
                )
            findings.append(LayoutFinding(os.fspath(modules[module]), binding.line, rule, detail))
    return findings


# -- 规则 3、4：import 图与层次 --


@dataclass(frozen=True)
class ImportEdge:
    """包内的一条 import 边。"""

    source: str
    target: str
    line: int
    in_function: bool
    allowed: bool


def package_import_edges(package_dir: Path, package: str) -> list[ImportEdge]:
    """包内全部 import 边：顶层（含类体、if/try）与函数内分开标记；只收指向本包的边。"""
    modules = package_modules(package_dir, package)
    edges: list[ImportEdge] = []
    for module, path in modules.items():
        source = path.read_text(encoding="utf-8")
        tree = ast.parse(source, filename=str(path))
        comments = _comment_lines(source)
        is_package = path.name == "__init__.py"

        def targets_of(node: ast.Import | ast.ImportFrom) -> list[str]:
            found: list[str] = []
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if _first_segment(alias.name) == package:
                        found.append(alias.name)
                return found
            base = _resolve_from(module, is_package, node)
            if base is None or _first_segment(base) != package:
                return found
            for alias in node.names:
                candidate = f"{base}.{alias.name}"
                found.append(candidate if candidate in modules else base)
            return found

        def walk(node: ast.AST, in_function: bool) -> None:
            for child in ast.iter_child_nodes(node):
                if isinstance(child, (ast.Import, ast.ImportFrom)):
                    for target in targets_of(child):
                        if target != module:
                            edges.append(ImportEdge(module, target, child.lineno, in_function, _allowed(comments, child)))
                walk(child, in_function or isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)))

        walk(tree, False)
    return edges


def find_import_cycles(edges: Iterable[ImportEdge]) -> list[list[str]]:
    """合并图（顶层与函数内的边都算）里的环，每个环给出一条回路。"""
    graph: dict[str, set[str]] = {}
    for edge in edges:
        graph.setdefault(edge.source, set()).add(edge.target)
    cycles: list[list[str]] = []
    state: dict[str, int] = {}
    stack: list[str] = []

    def dfs(node: str) -> None:
        state[node] = 1
        stack.append(node)
        for target in sorted(graph.get(node, ())):
            if state.get(target) == 1:
                cycles.append([*stack[stack.index(target):], target])
            elif not state.get(target):
                dfs(target)
        stack.pop()
        state[node] = 2

    for node in sorted(graph):
        if not state.get(node):
            dfs(node)
    return cycles


def function_level_package_imports(edges: Iterable[ImportEdge]) -> list[LayoutFinding]:
    """包内的函数内 import：没有放行注释就报（可选依赖 gi 不是包内 import，不受影响）。"""
    return [
        LayoutFinding(edge.source, edge.line, "function-level-import", f"{edge.source} 在函数内 import {edge.target}，需要 `{ALLOW_MARK} <原因>`")
        for edge in edges
        if edge.in_function and not edge.allowed
    ]


def check_layer_rules(
    edges: Iterable[ImportEdge],
    modules: Collection[str],
    package: str,
    rules: Sequence[tuple[str, str]],
    *,
    unconditional: bool,
) -> list[LayoutFinding]:
    """规则 4：`(甲, 乙)` 表示甲不许 import 乙。模块缺失时，有条件模式跳过、无条件模式报红。"""
    edge_list = list(edges)
    findings: list[LayoutFinding] = []
    for source, forbidden in rules:
        left, right = f"{package}.{source}", f"{package}.{forbidden}"
        if left not in modules or right not in modules:
            if unconditional:
                findings.append(LayoutFinding(source, 0, "layer-missing-module", f"层次规则 {source} ↛ {forbidden} 涉及的模块不存在"))
            continue
        for edge in edge_list:
            if edge.source == left and edge.target == right:
                findings.append(LayoutFinding(edge.source, edge.line, "layer", f"{source} 不许 import {forbidden}"))
    return findings
