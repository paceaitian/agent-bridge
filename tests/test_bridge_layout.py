"""桥的布局守卫（DESIGN §48 R0）：patch 目标有效、搬移登记表、import 图与层次规则。

可移植：不依赖 observer 包，随镜像走。扫描与判定在 `bridge_support`，§49 D0c 复用同一套函数。
每个搬移提交把自己搬的条目加进 `MOVED`；R2、R7 分别清空两张「已知」表，R9 把层次规则改为无条件。
"""

from __future__ import annotations

import importlib
from pathlib import Path
import sys
from tempfile import TemporaryDirectory
import textwrap
import time
import unittest
from unittest.mock import patch
import uuid

import agentstatus_bridge
import bridge_support
from bridge_support import (
    ALLOW_MARK,
    ImportEdge,
    LayoutFinding,
    Move,
    check_layer_rules,
    check_moved_registry,
    check_patch_sites,
    collect_patch_sites,
    find_import_cycles,
    function_read_mismatches,
    function_level_package_imports,
    package_import_edges,
    package_modules,
)

PACKAGE = "agentstatus_bridge"
PACKAGE_DIR = Path(agentstatus_bridge.__file__).resolve().parent
TESTS_DIR = Path(__file__).resolve().parent
# 包内/包外按这两个包判：包外模块（标准库、C 扩展）的属性只查 hasattr（§48 R0 规则 1 第 4 版）
KNOWN_PACKAGES = frozenset({PACKAGE, "agentstatus"})

# 搬移登记表：「旧模块:名字 → 新模块:名字」，模块名相对包根
MOVED: tuple[str, ...] = (
    # R2：账本记录上限与其他上限放在一起，labels 不再 import reports
    "reports:MAX_FILES → store:MAX_FILES",
    # R6：展示层从 cli 搬进 views（名字不改）
    "cli:_age → views:_age",
    "cli:_clock → views:_clock",
    "cli:_ref_document → views:_ref_document",
    "cli:_DETAIL_KEY → views:_DETAIL_KEY",
    "cli:_DETAIL_STRING_LIMIT → views:_DETAIL_STRING_LIMIT",
    "cli:project_delivery_detail → views:project_delivery_detail",
    "cli:_is_short_scalar → views:_is_short_scalar",
    "cli:_attempt_document → views:_attempt_document",
    "cli:_TargetHint → views:_TargetHint",
    "cli:_NO_HINT → views:_NO_HINT",
    "cli:_task_document → views:_task_document",
    "cli:_next_step → views:_next_step",
    "cli:_describe_result → views:_describe_result",
    "cli:_print_task → views:_print_task",
    "cli:_closure_document → views:_closure_document",
    "cli:_print_closure → views:_print_closure",
    # R7：doctor 拆出（collect_checks、print_checks 是 cmd_doctor 的前后两段，不是改名搬移）
    "cli:queue_evidence_text → doctor:queue_evidence_text",
    # R3：AgentStatus D-Bus 可选数据源从 endpoints 搬进 observer_dbus
    "endpoints:AGENTSTATUS_BUS_NAME → observer_dbus:AGENTSTATUS_BUS_NAME",
    "endpoints:AGENTSTATUS_OBJECT_PATH → observer_dbus:AGENTSTATUS_OBJECT_PATH",
    "endpoints:AGENTSTATUS_INTERFACE_NAME → observer_dbus:AGENTSTATUS_INTERFACE_NAME",
    "endpoints:_OBSERVER_KEY → observer_dbus:_OBSERVER_KEY",
    "endpoints:_positive_count → observer_dbus:_positive_count",
    "endpoints:_has_background_work → observer_dbus:_has_background_work",
    "endpoints:_map_agentstatus_runtime → observer_dbus:_map_agentstatus_runtime",
    "endpoints:_pane_state → observer_dbus:_pane_state",
    "endpoints:ObserverRow → observer_dbus:ObserverRow",
    "endpoints:ObserverView → observer_dbus:ObserverView",
    "endpoints:agentstatus_view → observer_dbus:agentstatus_view",
    "endpoints:agentstatus_runtime → observer_dbus:agentstatus_runtime",
    "endpoints:agentstatus_panes → observer_dbus:agentstatus_panes",
    "endpoints:_observer_rows → observer_dbus:_observer_rows",
    # R5：Codex 启动参数识别从 endpoints 搬进 codex_argv（只依赖标准库）
    "endpoints:_CODEX_NON_TUI → codex_argv:_CODEX_NON_TUI",
    "endpoints:_CODEX_VALUE_OPTIONS → codex_argv:_CODEX_VALUE_OPTIONS",
    "endpoints:_CODEX_MULTI_VALUE_OPTIONS → codex_argv:_CODEX_MULTI_VALUE_OPTIONS",
    "endpoints:_CODEX_TUI_SUBCOMMANDS → codex_argv:_CODEX_TUI_SUBCOMMANDS",
    "endpoints:_codex_non_interactive → codex_argv:_codex_non_interactive",
    "endpoints:_toml_string → codex_argv:_toml_string",
    "endpoints:_codex_cli_overrides → codex_argv:_codex_cli_overrides",
    "endpoints:_codex_class → codex_argv:_codex_class",
)
# 允许纯持有的「模块:本地名」；§48 没有例外（第 3 版口径下注解、类体、默认值里的读取都算读取）
HOLDING_EXCEPTIONS: frozenset[tuple[str, str]] = frozenset()

# 规则 4：(甲, 乙) 表示甲不许 import 乙；R9 起模块缺失即红
LAYER_RULES = (
    ("views", "cli"),
    ("doctor", "cli"),
    ("observer_dbus", "endpoints"),
    ("codex_argv", "endpoints"),
    ("labels", "reports"),
)
LAYER_RULES_UNCONDITIONAL = True


def _short(module: str) -> str:
    return module[len(PACKAGE) + 1:] if module.startswith(f"{PACKAGE}.") else module


def _owns_nonliteral(path: str) -> bool:
    """非字面量目标看不出指向哪个包，按文件归属：桥测试与 bridge_support 归本守卫，其余归 §49 D0c。"""
    name = Path(path).name
    return name.startswith("test_bridge_") or name == "bridge_support.py"


def _lines(findings: list[LayoutFinding]) -> list[str]:
    return [str(finding) for finding in findings]


class RealTreeTests(unittest.TestCase):
    """真实代码树上的四组规则。"""

    def test_patch_targets_are_effective(self) -> None:
        sites = [site for path in sorted(TESTS_DIR.glob("*.py")) for site in collect_patch_sites(path)]
        findings, judged = check_patch_sites(
            sites, package=PACKAGE, owns_nonliteral=_owns_nonliteral, packages=KNOWN_PACKAGES
        )
        self.assertEqual([], _lines(findings))
        # 扫描器坏到什么都扫不到时也要变红：HEAD 上全仓 104 处、镜像里 103 处
        self.assertGreaterEqual(judged, 90)

    def test_function_reads_agree_with_the_symtable_oracle(self) -> None:
        # 规则 1 的「函数体读取」是手写启发式：每个模块上与标准库 symtable 各算一遍，被 import 的名字上结论必须相同
        self.assertEqual([], _lines(function_read_mismatches(sorted(PACKAGE_DIR.rglob("*.py")))))

    def test_moved_registry(self) -> None:
        moves = [Move.parse(entry) for entry in MOVED]
        findings = check_moved_registry(PACKAGE_DIR, PACKAGE, moves, holding_exceptions=HOLDING_EXCEPTIONS)
        self.assertEqual([], _lines(findings))

    def test_combined_import_graph_is_acyclic(self) -> None:
        # 顶层与函数内的 import 合并成一张图（R2 启用；HEAD 上 labels → reports → labels 有环）
        cycles = find_import_cycles(package_import_edges(PACKAGE_DIR, PACKAGE))
        self.assertEqual([], [" → ".join(_short(module) for module in cycle) for cycle in cycles])

    def test_no_function_level_package_imports(self) -> None:
        # R7 启用：cmd_doctor 的 3 处局部 import 随 doctor 拆分上提到模块顶层；今后确需懒加载写放行注释
        findings = function_level_package_imports(package_import_edges(PACKAGE_DIR, PACKAGE))
        self.assertEqual([], _lines(findings))

    def test_layer_rules(self) -> None:
        edges = package_import_edges(PACKAGE_DIR, PACKAGE)
        modules = package_modules(PACKAGE_DIR, PACKAGE)
        findings = check_layer_rules(edges, modules, PACKAGE, LAYER_RULES, unconditional=LAYER_RULES_UNCONDITIONAL)
        self.assertEqual([], _lines(findings))


class _FakeTree:
    """临时目录里的假包与假测试。源码里的 `PKG` 换成唯一包名；
    结束后从 sys.modules 与 sys.path 里清掉，免得用例互相影响（Opus 第 3 轮 P3-4）。"""

    def __init__(self, package: dict[str, str], tests: dict[str, str] | None = None, *, extra_packages: dict[str, dict[str, str]] | None = None) -> None:
        self.package_sources = package
        self.test_sources = tests or {}
        self.extra = extra_packages or {}
        self.name = f"lgfake{uuid.uuid4().hex[:10]}"

    def _render(self, text: str) -> str:
        return textwrap.dedent(text).replace("PKG", self.name)

    def __enter__(self) -> _FakeTree:
        self._temporary = TemporaryDirectory(prefix="layout-guard.")
        self.root = Path(self._temporary.name)
        self.package_dir = self.root / self.name
        packages = {self.name: self.package_sources} | {self.name + suffix: files for suffix, files in self.extra.items()}
        for package, files in packages.items():
            for relative, text in {"__init__.py": "", **files}.items():
                path = self.root / package / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(self._render(text), encoding="utf-8")
        self.tests_dir = self.root / "tests"
        self.tests_dir.mkdir()
        for relative, text in self.test_sources.items():
            (self.tests_dir / relative).write_text(self._render(text), encoding="utf-8")
        sys.path.insert(0, str(self.root))
        importlib.invalidate_caches()
        return self

    def __exit__(self, *exc: object) -> None:
        for module in [name for name in sys.modules if name == self.name or name.startswith(self.name)]:
            del sys.modules[module]
        sys.path.remove(str(self.root))
        self._temporary.cleanup()

    def patch_findings(self, *, owns: bool = True) -> tuple[list[LayoutFinding], int]:
        sites = [site for path in sorted(self.tests_dir.glob("*.py")) for site in collect_patch_sites(path)]
        return check_patch_sites(sites, package=self.name, owns_nonliteral=lambda _: owns, packages={self.name})

    def registry_findings(self, moves: list[str], *, aliases: dict[str, tuple[str, ...]] | None = None, exceptions: frozenset[tuple[str, str]] = frozenset()) -> list[LayoutFinding]:
        parsed = [Move.parse(entry, aliases=(aliases or {}).get(entry, ())) for entry in moves]
        return check_moved_registry(self.package_dir, self.name, parsed, holding_exceptions=exceptions)


# 规则 1 合成用例共用的假包：ver 定义 cli_version；observer 定义 _observer_rows；
# endpoints 只 import 不读（回导出形态）；cli 在函数体里读 cli_version；models 有基类方法。
_RULE1_PACKAGE = {
    "ver.py": "def cli_version():\n    return 1\n",
    "observer.py": "def _observer_rows():\n    return []\n",
    "endpoints.py": "from .observer import _observer_rows\n",
    "cli.py": """\
        import socket

        from .ver import cli_version


        def run():
            return cli_version()


        def host():
            return socket.gethostname()
        """,
    "models.py": """\
        class Base:
            def add(self):
                return 1


        class Store(Base):
            def finish(self):
                return 2
        """,
}


def _test_file(body: str, *, imports: str = "") -> str:
    """把一段用例体包成假测试文件；`body` 写在函数里。"""
    header = "import importlib\nimport sys\nfrom unittest.mock import patch\n" + textwrap.dedent(imports)
    return header + "\n\ndef test_case():\n" + textwrap.indent(textwrap.dedent(body), "    ") + "\n"


# 作用域形态语料：每段是一个模块，扫描器与 symtable 预言机在被 import 的名字上必须给出同一个「函数体读取」集合
_SCOPE_SHAPES = {
    "comprehension variable shadows only inside": "from m import g\ndef f(xs):\n    names = [g for g in xs]\n    return g, names\n",
    "first iter is outer": "from m import g\ndef f():\n    return [g for g in g()]\n",
    "later iter sees the variable": "from m import g\ndef f(xs):\n    return [v for g in xs for v in g]\n",
    "element and condition": "from m import g\ndef f(xs):\n    return [g for g in xs if g]\n",
    "dict comprehension": "from m import g, h\ndef f(xs):\n    return {g: h for g in xs}\n",
    "nested comprehension": "from m import g, h\ndef f(xs):\n    return [[g for g in h] for h in xs]\n",
    "walrus binds the function": "from m import g\ndef f(xs):\n    [(g := x) for x in xs]\n    return g\n",
    "walrus inside a lambda stays there": "from m import g\ndef f(xs):\n    [(lambda: (g := 1)) for x in xs]\n    return g\n",
    "lambda sees the comprehension variable": "from m import g\ndef f(xs):\n    return [lambda: g for g in xs]\n",
    "nested def locals stay inside": "from m import g\ndef f():\n    def inner():\n        g = 1\n        return g\n    return g, inner\n",
    "nested nonlocal does not leak out": "from m import g\ndef f():\n    g = 1\n    def inner():\n        nonlocal g\n        g = 2\n    inner()\n    return g\n",
    "local annotation is not evaluated": "from m import g\ndef f():\n    x: g = 1\n    return x\n",
    "global declaration": "from m import g\ndef f():\n    global g\n    g = 1\n    return g\n",
    # 第 3 轮两方 P3：预言机自身的分支与没覆盖到的形态
    "class body inside a function": "from m import g\ndef f():\n    class C:\n        attr = g\n    return C\n",
    "genexpr in a class body inside a function": "from m import g\ndef f():\n    class C:\n        items = tuple(g for _ in range(3))\n    return C\n",
    "module level genexpr is not a function body": "from m import g\nX = tuple(g for _ in range(3))\n",
    "method reads only inside a comprehension": "from m import g\nclass C:\n    def m(self, xs):\n        return [g(x) for x in xs]\n",
    "walrus in a nested comprehension binds the function": "from m import g\ndef f(xs):\n    [[(g := y) for y in x] for x in xs]\n    return g\n",
    "global assigned but not read": "from m import g\ndef f():\n    global g\n    g = 1\n",
}


class ScopeOracleTests(unittest.TestCase):
    """推导式、海象、嵌套定义、局部注解等作用域形态上，扫描器与独立预言机一致（Opus 实现复核第 2 轮 P3-1、P3-3）。"""

    def test_shapes_agree_with_the_symtable_oracle(self) -> None:
        with TemporaryDirectory() as temporary:
            for index, (label, source) in enumerate(_SCOPE_SHAPES.items()):
                path = Path(temporary, f"shape_{index}.py")
                # 与仓内模块一样带 future annotations：不带时 symtable 会把局部注解算成引用，
                # 而运行时局部注解从不求值（字节码里没有加载）
                path.write_text("from __future__ import annotations\n" + source, encoding="utf-8")
                with self.subTest(shape=label):
                    self.assertEqual([], _lines(function_read_mismatches([path])))

    def test_modules_without_future_annotations_use_the_same_premise(self) -> None:
        """不带 future 导入的模块，预言机先补上再算：局部注解照样不算读取；文档字符串与既有 future 导入之后插入仍合法。"""
        shapes = {
            "bare": "from m import g\ndef f():\n    x: g = 1\n    return x\n",
            "docstring and another future import": '"""模块说明"""\nfrom __future__ import division\nfrom m import g\ndef f():\n    x: g = 1\n    return x\n',
        }
        with TemporaryDirectory() as temporary:
            for index, (label, source) in enumerate(shapes.items()):
                path = Path(temporary, f"bare_{index}.py")
                path.write_text(source, encoding="utf-8")
                with self.subTest(shape=label):
                    self.assertEqual([], _lines(function_read_mismatches([path])))

    def test_mismatches_are_reported_in_both_directions(self) -> None:
        """对照函数本身的正向对照：预言机给出不同结论时，恰好报出那一条（Opus 实现复核第 3 轮 P3-1）。"""
        with TemporaryDirectory() as temporary:
            reads = Path(temporary, "reads.py")
            reads.write_text("from __future__ import annotations\nfrom m import g\ndef f():\n    return g\n", encoding="utf-8")
            idle = Path(temporary, "idle.py")
            idle.write_text("from __future__ import annotations\nfrom m import g\ndef f():\n    return 1\n", encoding="utf-8")
            with patch.object(bridge_support, "symtable_function_reads", return_value=set()):
                found = function_read_mismatches([reads])
            self.assertEqual([("reads-oracle", "扫描器多算了 g（可能误判绿）")], [(item.rule, item.detail) for item in found])
            with patch.object(bridge_support, "symtable_function_reads", return_value={"g"}):
                found = function_read_mismatches([idle])
            self.assertEqual([("reads-oracle", "扫描器少算了 g（可能误判红）")], [(item.rule, item.detail) for item in found])


class PatchTargetGuardTests(unittest.TestCase):
    """规则 1 的合成用例：每条针对一种写错的实现（DESIGN §48.3「守卫自身的变异反证」）。"""

    def _run(self, body: str, *, imports: str = "", package: dict[str, str] | None = None, owns: bool = True) -> tuple[list[LayoutFinding], int]:
        files = dict(_RULE1_PACKAGE)
        files.update(package or {})
        with _FakeTree(files, {"test_case.py": _test_file(body, imports=imports)}) as tree:
            return tree.patch_findings(owns=owns)

    def assertRed(self, body: str, rule: str, **kwargs: object) -> None:
        findings, _ = self._run(body, **kwargs)  # type: ignore[arg-type]
        self.assertTrue(findings, "应当判红")
        self.assertIn(rule, {finding.rule for finding in findings}, _lines(findings))

    def assertGreen(self, body: str, *, judged: int | None = None, **kwargs: object) -> None:
        findings, count = self._run(body, **kwargs)  # type: ignore[arg-type]
        self.assertEqual([], _lines(findings))
        if judged is not None:
            self.assertEqual(judged, count)

    # -- 判红 --
    def test_residual_import_not_read_in_function_body(self) -> None:
        package = {"cli.py": "from .ver import cli_version\n\n\ndef run():\n    return 0\n"}
        self.assertRed("with patch('PKG.cli.cli_version'):\n    pass\n", "patch-target", package=package)

    def test_import_read_only_at_module_level(self) -> None:
        package = {"cli.py": "from .ver import cli_version\n\nTABLE = [cli_version]\n"}
        self.assertRed("with patch('PKG.cli.cli_version'):\n    pass\n", "patch-target", package=package)

    def test_import_read_only_in_class_body_and_defaults(self) -> None:
        package = {"cli.py": textwrap.dedent("""\
            from .ver import cli_version


            class Sources:
                version = cli_version

                def __init__(self, version=cli_version):
                    self.version = version
            """)}
        self.assertRed(
            "with patch.object(cli, 'cli_version'):\n    pass\n", "patch-target", imports="from PKG import cli\n", package=package
        )

    def test_missing_name(self) -> None:
        self.assertRed("with patch('PKG.cli.nope'):\n    pass\n", "patch-target")

    def test_class_attribute_missing_from_mro(self) -> None:
        self.assertRed(
            "with patch.object(Store, 'missing'):\n    pass\n", "patch-target", imports="from PKG.models import Store\n"
        )

    def test_outside_module_attribute_must_exist(self) -> None:
        self.assertRed("with patch('PKG.cli.socket.no_such_attribute'):\n    pass\n", "patch-target")

    def test_fable_bypass_forms_literal(self) -> None:
        # Fable 第 1 轮的 10 种绕过形态里能静态解析的 6 种：按目标判定，回导出的 _observer_rows 必须红
        forms = {
            "keyword target": "with patch(target='PKG.endpoints._observer_rows'):\n    pass\n",
            "patch.multiple": "with patch.multiple(endpoints, _observer_rows=None):\n    pass\n",
            "patch.dict": "with patch.dict(endpoints.__dict__, {'_observer_rows': None}):\n    pass\n",
            "setattr": "setattr(endpoints, '_observer_rows', None)\n",
            "direct assign": "endpoints._observer_rows = None\n",
            "sys.modules": "sys.modules['PKG.endpoints']._observer_rows = None\n",
        }
        for label, body in forms.items():
            with self.subTest(form=label):
                self.assertRed(body, "patch-target", imports="from PKG import endpoints\n")

    def test_fable_bypass_forms_nonliteral(self) -> None:
        forms = {
            "f-string": "name = '_observer_rows'\nwith patch(f'PKG.endpoints.{name}'):\n    pass\n",
            "concat": "with patch('PKG.endpoints.' + '_observer_rows'):\n    pass\n",
            "variable": "target = 'PKG.endpoints._observer_rows'\nwith patch(target):\n    pass\n",
            "__name__": "with patch(endpoints.__name__ + '._observer_rows'):\n    pass\n",
        }
        for label, body in forms.items():
            with self.subTest(form=label):
                self.assertRed(body, "patch-nonliteral", imports="from PKG import endpoints\n")

    def test_three_segment_direct_assignment(self) -> None:
        self.assertRed("PKG.cli.nope = 1\n", "patch-target", imports="import PKG.cli\n")

    def test_first_argument_is_a_call(self) -> None:
        self.assertRed(
            "with patch.object(importlib.import_module('PKG.cli'), 'run'):\n    pass\n", "patch-nonliteral"
        )

    def test_local_name_bound_by_import_module(self) -> None:
        body = "mod = importlib.import_module('PKG.endpoints')\nwith patch.object(mod, '_observer_rows'):\n    pass\n"
        self.assertRed(body, "patch-target")

    def test_function_level_import_alias(self) -> None:
        body = "from PKG import endpoints as local\nwith patch.object(local, '_observer_rows'):\n    pass\n"
        self.assertRed(body, "patch-target")

    def test_module_level_import_module_binding(self) -> None:
        self.assertRed(
            "with patch.object(MOD, '_observer_rows'):\n    pass\n",
            "patch-target",
            imports="import importlib as _importlib\nMOD = _importlib.import_module('PKG.endpoints')\n",
        )

    def test_assignment_and_loop_values_are_traced(self) -> None:
        cases = {
            "assign": "m = endpoints\nwith patch.object(m, '_observer_rows'):\n    pass\n",
            "loop": "for m in (cli, endpoints):\n    with patch.object(m, '_observer_rows'):\n        pass\n",
            "ifexp": "m = endpoints if sys.argv else cli\nwith patch.object(m, '_observer_rows'):\n    pass\n",
        }
        for label, body in cases.items():
            with self.subTest(case=label):
                self.assertRed(body, "patch-target", imports="from PKG import cli, endpoints\n")

    def test_import_name_rebound_in_the_same_scope_keeps_both_candidates(self) -> None:
        # Codex 补审② F01 反例 A：import 别名又被重新赋值，实际 patch 的是重新赋的那个模块（回导出），函数内与模块层都要红
        rebind = "from PKG import observer as target, endpoints\ntarget = endpoints\n"
        self.assertRed(rebind + "with patch.object(target, '_observer_rows'):\n    pass\n", "patch-target")
        self.assertRed("with patch.object(target, '_observer_rows'):\n    pass\n", "patch-target", imports=rebind)
        # 对照：直接 patch 定义方照常是绿
        self.assertGreen("with patch.object(observer, '_observer_rows'):\n    pass\n", imports="from PKG import observer\n")

    def test_same_name_imported_from_two_sources_keeps_both(self) -> None:
        # Codex 补审② 复验 R01：两个分支各 import 一个模块到同一本地名，后一条不能覆盖前一条；
        # 实际命中回导出方 endpoints 时 patch 无效，必须红；再经一次赋值转手也一样
        branches = "if sys.argv:\n    from PKG import endpoints as target\nelse:\n    from PKG import observer as target\n"
        reversed_branches = "if sys.argv:\n    from PKG import observer as target\nelse:\n    from PKG import endpoints as target\n"
        patched = "with patch.object({}, '_observer_rows'):\n    pass\n"
        cases = {
            "函数内": dict(body=branches + patched.format("target")),
            "函数内反序": dict(body=reversed_branches + patched.format("target")),
            "模块层": dict(body=patched.format("target"), imports=branches),
            "赋值转手": dict(body=branches + "chosen = target\n" + patched.format("chosen")),
        }
        for label, kwargs in cases.items():
            with self.subTest(case=label):
                self.assertRed(rule="patch-target", **kwargs)  # type: ignore[arg-type]
        # 对照：两支来自同一定义方（含同源重复 import）照常是绿
        same = "if sys.argv:\n    from PKG import observer as target\nelse:\n    from PKG import observer as target\n"
        self.assertGreen(same + patched.format("target"), judged=1)

    def test_nonliteral_candidate_is_not_hidden_by_a_resolvable_one(self) -> None:
        # 反例 B：条件表达式一支可解析、另一支是非字面量，仍然要求放行说明
        forms = {
            "import_module": "name = 'PKG.endpoints'\n"
                             "target = observer if sys.argv else importlib.import_module(name)\n"
                             "with patch.object(target, '_observer_rows'):\n    pass\n",
            "__import__": "target = observer if sys.argv else __import__('PKG.endpoints', fromlist=['_observer_rows'])\n"
                          "with patch.object(target, '_observer_rows'):\n    pass\n",
        }
        for label, body in forms.items():
            with self.subTest(form=label):
                self.assertRed(body, "patch-nonliteral", imports="from PKG import observer\n")

    def test_dunder_import_is_nonliteral(self) -> None:
        body = "m = __import__('PKG.endpoints')\nwith patch.object(m, '_observer_rows'):\n    pass\n"
        self.assertRed(body, "patch-nonliteral")

    def test_allow_comment_on_previous_line_does_not_count(self) -> None:
        body = f"target = 'PKG.cli.run'\n{ALLOW_MARK} 写在上一行\nwith patch(target):\n    pass\n"
        self.assertRed(body, "patch-nonliteral")

    def test_keyword_and_dict_forms(self) -> None:
        # Opus 实现复核 P3-1：全关键字、patch.dict 的字符串形式与关键字键、vars()、带注解的直接赋值都按目标判定
        forms = {
            "patch.object 全关键字": "with patch.object(target=endpoints, attribute='_observer_rows'):\n    pass\n",
            "patch.multiple 关键字 target": "with patch.multiple(target=endpoints, _observer_rows=None):\n    pass\n",
            "patch.dict 字符串": "with patch.dict('PKG.endpoints.__dict__', {'_observer_rows': None}):\n    pass\n",
            "patch.dict 关键字键": "with patch.dict(endpoints.__dict__, {}, _observer_rows=None):\n    pass\n",
            "patch.dict vars()": "with patch.dict(vars(endpoints), {'_observer_rows': None}):\n    pass\n",
            "带注解的直接赋值": "endpoints._observer_rows: object = None\n",
            "patch.dict 全关键字": "with patch.dict(in_dict=endpoints.__dict__, values={'_observer_rows': None}):\n    pass\n",
        }
        for label, body in forms.items():
            with self.subTest(form=label):
                self.assertRed(body, "patch-target", imports="from PKG import endpoints\n")

    def test_patch_dict_star_kwargs_is_nonliteral(self) -> None:
        self.assertRed("with patch.dict(endpoints.__dict__, **{'_observer_rows': None}):\n    pass\n", "patch-nonliteral",
                       imports="from PKG import endpoints\n")

    def test_later_comprehension_iter_reads_the_comprehension_variable(self) -> None:
        # 第二个 iter 看得见第一个推导变量：函数没有读模块全局，patch 无效
        package = {"cli.py": textwrap.dedent("""\
            from .ver import cli_version


            def run(items):
                return [value for cli_version in items for value in cli_version]
            """)}
        self.assertRed("with patch.object(cli, 'cli_version'):\n    pass\n", "patch-target",
                       imports="from PKG import cli\n", package=package)

    def test_local_annotation_is_not_a_read(self) -> None:
        # 局部变量注解运行时不求值：只在注解里出现的名字，patch 无效
        package = {"cli.py": "from .ver import cli_version\n\n\ndef run():\n    value: cli_version = 1\n    return value\n"}
        self.assertRed("with patch.object(cli, 'cli_version'):\n    pass\n", "patch-target",
                       imports="from PKG import cli\n", package=package)

    def test_walrus_in_comprehension_binds_the_function_local(self) -> None:
        # 推导式里的海象赋值绑定到外层函数：之后读到的 cli_version 是局部名，patch 模块属性无效
        package = {"cli.py": textwrap.dedent("""\
            from .ver import cli_version


            def run(items):
                [(cli_version := item) for item in items]
                return cli_version
            """)}
        self.assertRed("with patch.object(cli, 'cli_version'):\n    pass\n", "patch-target",
                       imports="from PKG import cli\n", package=package)

    def test_comprehension_element_and_condition_read_the_comprehension_variable(self) -> None:
        # elt 与 if 读的都是推导变量，函数从不读模块全局：残留 import，patch 无效（Fable 实现复核第 2 轮 P3-1）
        package = {"cli.py": textwrap.dedent("""\
            from .ver import cli_version


            def run(items):
                return [cli_version for cli_version in items if cli_version]
            """)}
        self.assertRed("with patch.object(cli, 'cli_version'):\n    pass\n", "patch-target",
                       imports="from PKG import cli\n", package=package)

    # -- 判绿 --
    def test_import_read_in_function_body(self) -> None:
        self.assertGreen("with patch('PKG.cli.cli_version'):\n    pass\n", judged=1)

    def test_defined_in_module(self) -> None:
        self.assertGreen("with patch('PKG.ver.cli_version'):\n    pass\n", judged=1)

    def test_class_attribute_defined_on_base(self) -> None:
        self.assertGreen("with patch.object(Store, 'add'):\n    pass\n", imports="from PKG.models import Store\n", judged=1)

    def test_nonliteral_with_allow_comment(self) -> None:
        self.assertGreen(f"target = 'PKG.cli.run'\nwith patch(target):  {ALLOW_MARK} 循环替换\n    pass\n")

    def test_multiline_call_allow_on_last_line(self) -> None:
        body = f"target = 'PKG.cli.run'\nwith patch(\n    target,\n    return_value=1,  {ALLOW_MARK} 多行调用\n):\n    pass\n"
        self.assertGreen(body)

    def test_patch_multiple_options_are_not_targets(self) -> None:
        # create、spec 是 patch.multiple 的选项，不是 cli 的属性
        self.assertGreen("with patch.multiple(cli, create=True, cli_version=None):\n    pass\n",
                         imports="from PKG import cli\n", judged=1)

    def test_comprehension_variable_does_not_hide_a_function_body_read(self) -> None:
        # Opus 实现复核 P3-2：推导变量不泄漏到函数，函数体里的 cli_version() 读的是模块全局
        package = {"cli.py": textwrap.dedent("""\
            from .ver import cli_version


            def run(items):
                names = [cli_version for cli_version in items]
                return cli_version(), names
            """)}
        self.assertGreen("with patch.object(cli, 'cli_version'):\n    pass\n", imports="from PKG import cli\n",
                         package=package, judged=1)

    def test_first_comprehension_iter_is_read_in_the_outer_scope(self) -> None:
        # 第一个 iter 在外层作用域求值：这里的 cli_version() 读的是模块全局（Fable 实现复核第 2 轮 P3-1）
        package = {"cli.py": textwrap.dedent("""\
            from .ver import cli_version


            def run():
                return [cli_version for cli_version in cli_version()]
            """)}
        self.assertGreen("with patch.object(cli, 'cli_version'):\n    pass\n", imports="from PKG import cli\n",
                         package=package, judged=1)

    def test_walrus_inside_a_lambda_does_not_bind_the_function(self) -> None:
        # lambda 里的海象归 lambda 自己：外层读的 cli_version 仍是模块全局
        package = {"cli.py": textwrap.dedent("""\
            from .ver import cli_version


            def run(items):
                [(lambda: (cli_version := 1)) for item in items]
                return cli_version()
            """)}
        self.assertGreen("with patch.object(cli, 'cli_version'):\n    pass\n", imports="from PKG import cli\n",
                         package=package, judged=1)

    def test_patch_dict_options_are_not_targets(self) -> None:
        # clear 是 patch.dict 的选项，不出 cli.clear 这个目标
        self.assertGreen("with patch.dict(cli.__dict__, {'cli_version': None}, clear=True):\n    pass\n",
                         imports="from PKG import cli\n", judged=1)

    def test_annotation_only_attribute_is_not_an_assignment(self) -> None:
        self.assertGreen("cli.nope: int\n", imports="from PKG import cli\n", judged=0)

    def test_mock_attribute_assignment_is_not_a_target(self) -> None:
        self.assertGreen("cli.run.side_effect = None\n", imports="from PKG import cli\n", judged=0)

    def test_instance_first_argument_is_out_of_scope(self) -> None:
        body = "store = Store()\nwith patch.object(store, 'missing'):\n    pass\n"
        self.assertGreen(body, imports="from PKG.models import Store\n", judged=0)

    def test_outside_module_attribute(self) -> None:
        self.assertGreen("with patch('PKG.cli.socket.gethostname'):\n    pass\n", judged=1)

    def test_import_module_binding_valid(self) -> None:
        body = "mod = importlib.import_module('PKG.ver')\nwith patch.object(mod, 'cli_version'):\n    pass\n"
        self.assertGreen(body, judged=1)

    def test_attribution_compares_first_segment_exactly(self) -> None:
        # 前缀是 PKG_bridge 的目标不归 PKG 的守卫（字符串 startswith 会误认，Opus 第 4 轮）
        with _FakeTree(dict(_RULE1_PACKAGE), {"test_case.py": _test_file("with patch('PKG_bridge.cli.nope'):\n    pass\n")},
                       extra_packages={"_bridge": {"cli.py": "X = 1\n"}}) as tree:
            findings, judged = tree.patch_findings()
        self.assertEqual([], _lines(findings))
        self.assertEqual(0, judged)

    def test_nonliteral_in_files_owned_by_the_other_guard_is_skipped(self) -> None:
        findings, _ = self._run("target = 'PKG.cli.run'\nwith patch(target):\n    pass\n", owns=False)
        self.assertEqual([], _lines(findings))


class MovedRegistryGuardTests(unittest.TestCase):
    """规则 2 的合成用例：旧模块不再定义、新模块恰好一次、没有纯持有（DESIGN §48 R0 第 3 版口径）。"""

    ENTRY = "old:f → new:f"

    def _findings(self, files: dict[str, str], moves: list[str] | None = None, **kwargs: object) -> list[LayoutFinding]:
        with _FakeTree({name: textwrap.dedent(text) for name, text in files.items()}) as tree:
            return tree.registry_findings(moves or [self.ENTRY], **kwargs)  # type: ignore[arg-type]

    def assertRule(self, files: dict[str, str], rule: str | None, **kwargs: object) -> None:
        findings = self._findings(files, **kwargs)  # type: ignore[arg-type]
        if rule is None:
            self.assertEqual([], _lines(findings))
        else:
            self.assertIn(rule, {finding.rule for finding in findings}, _lines(findings))

    def test_copy_without_delete(self) -> None:
        self.assertRule({"new.py": "def f():\n    return 1\n", "old.py": "def f():\n    return 1\n"}, "moved-old-still-defines")

    def test_re_export(self) -> None:
        self.assertRule({"new.py": "def f():\n    return 1\n", "old.py": "from .new import f\n"}, "moved-pure-hold")

    def test_pure_hold_through_another_module(self) -> None:
        files = {
            "new.py": "def f():\n    return 1\n",
            "old.py": "from .new import f\n\n\ndef use():\n    return f()\n",
            "third.py": "from .old import f\n",
        }
        self.assertRule(files, "moved-pure-hold")

    def test_string_annotation_is_not_a_read(self) -> None:
        files = {"new.py": "def f():\n    return 1\n", "user.py": "from .new import f\n\n\ndef g(x: 'f') -> None:\n    return None\n"}
        self.assertRule(files, "moved-pure-hold")

    def test_new_module_defines_twice(self) -> None:
        self.assertRule({"new.py": "def f():\n    return 1\n\n\nf = f\n"}, "moved-new-count")

    def test_new_module_defines_nothing(self) -> None:
        self.assertRule({"new.py": "X = 1\n", "elsewhere.py": "def f():\n    return 1\n"}, "moved-new-count")

    def test_unrelated_same_name_is_ignored(self) -> None:
        # 照 cli._describe_result 与 reports._describe_result：无关的同名定义不管
        self.assertRule({"new.py": "def f():\n    return 1\n", "third.py": "def f():\n    return 2\n"}, None)

    def test_annotation_only_use_counts_as_read(self) -> None:
        files = {
            "new.py": "class F:\n    pass\n",
            "user.py": "from __future__ import annotations\n\nfrom .new import F\n\n\ndef g(x: F) -> None:\n    return None\n",
        }
        self.assertRule(files, None, moves=["old:F → new:F"])

    def test_class_body_default_and_module_level_use_count_as_reads(self) -> None:
        files = {
            "new.py": "def f():\n    return 1\n",
            "user.py": "from .new import f\n\nTABLE = [f]\n\n\nclass D:\n    runtime = f\n",
        }
        self.assertRule(files, None)

    def test_pure_hold_through_a_renaming_transit_module(self) -> None:
        # Codex 补审② F02：第一层改名 import 并真的读取，第二层按改名后的名字转手却一次不读，也要红
        files = {
            "new.py": "def f():\n    return 1\n",
            "transit.py": "from .new import f as moved\n\n\ndef use():\n    return moved()\n",
            "holder.py": "from .transit import moved\n",
        }
        self.assertRule(files, "moved-pure-hold")
        # 对照：转手的是同一模块里没有搬移的别的名字，不算
        files = {
            "new.py": "def f():\n    return 1\n\n\ndef g():\n    return 2\n",
            "transit.py": "from .new import f as moved, g as other\n\n\ndef use():\n    return moved(), other()\n",
            "holder.py": "from .transit import other\n",
        }
        self.assertRule(files, None)

    def test_same_local_name_with_several_sources_in_the_transit_module(self) -> None:
        # Codex 补审② 复验 R02：中间模块同一本地名有多个 import 来源，不能只认首条
        transit = "{}\n\n\ndef use():\n    return item\n"
        holder = {"holder.py": "from .transit import item\n"}
        base = {"new.py": "def f():\n    return 1\n\n\ndef g():\n    return 2\n", "other.py": "def h():\n    return 3\n"}
        ambiguous = {
            "先别的后搬移": "from .other import h as item\nfrom .new import f as item",
            "先搬移后别的": "from .new import f as item\nfrom .new import g as item",
            "分支": "import sys\n\nif sys.argv:\n    from .new import f as item\nelse:\n    from .other import h as item",
            # 第 3 轮见证：中间模块自己又定义了同名对象，定义也是一个来源
            "本模块又定义同名": "from .new import f as item\nORIGINAL = item\n\n\ndef item():\n    return ORIGINAL()",
        }
        for label, imports in ambiguous.items():
            with self.subTest(case=label):
                rules = {finding.rule for finding in self._findings({**base, "transit.py": transit.format(imports), **holder})}
                # 来源混杂时给歧义诊断，不冒充确定的纯持有
                self.assertEqual({"moved-ambiguous-hold"}, rules)
        # 对照：同源重复 import 仍是确定的纯持有
        self.assertRule({**base, "transit.py": transit.format("from .new import f as item\nfrom .new import f as item"), **holder}, "moved-pure-hold")
        # 对照：多个来源都不是搬移符号；或持有方真的读了它
        self.assertRule({**base, "transit.py": transit.format("from .new import g as item\nfrom .other import h as item"), **holder}, None)
        reading = {"holder.py": "from .transit import item\n\n\ndef run():\n    return item()\n"}
        self.assertRule({**base, "transit.py": transit.format("from .other import h as item\nfrom .new import f as item"), **reading}, None)

    def test_transit_chain_has_no_depth_cap_and_cycles_terminate(self) -> None:
        # 复验 N02：旧实现超过 10 层就当作「不是搬移符号」；改为不设层数上限，只按路径断环
        files = {"new.py": "def f():\n    return 1\n", "t0.py": "from .new import f as x0\n\n\ndef use():\n    return x0\n"}
        for level in range(1, 12):
            files[f"t{level}.py"] = f"from .t{level - 1} import x{level - 1} as x{level}\n\n\ndef use():\n    return x{level}\n"
        files["holder.py"] = "from .t11 import x11\n"
        self.assertRule(files, "moved-pure-hold")
        # 互相转手成环：能结束，环外的纯持有照样认得出
        cycle = {
            "new.py": "def f():\n    return 1\n",
            "a.py": "from .new import f as x\nfrom .b import x\n\n\ndef use():\n    return x\n",
            "b.py": "from .a import x\n\n\ndef use():\n    return x\n",
            "holder.py": "from .b import x\n",
        }
        self.assertRule(cycle, "moved-pure-hold")

    def test_several_registrations_are_all_tracked(self) -> None:
        # Codex 补审② 第 3 轮 C03：纯持有检查先汇总全部登记身份，任何顺序、重复登记都不能丢掉前面的
        files = {
            "new.py": "def f():\n    return 1\n\n\ndef g():\n    return 2\n",
            "holder_f.py": "from .new import f\n",
            "holder_g.py": "from .new import g\n",
        }
        entries = ["old:f → new:f", "old:g → new:g"]
        for moves in (entries, entries[::-1], entries + entries):
            with self.subTest(moves=moves):
                self.assertEqual(["moved-pure-hold"] * 2, [finding.rule for finding in self._findings(files, moves)])
        # 两个来源都是登记身份、经同一名字转手：确定的纯持有，只报一次
        transit = {
            "new.py": files["new.py"],
            "transit.py": "from .new import f as x\nfrom .new import g as x\nUSED = x\n",
            "holder.py": "from .transit import x\n",
        }
        self.assertEqual(["moved-pure-hold"], [finding.rule for finding in self._findings(transit, entries)])

    def test_outside_source_is_an_opaque_identity(self) -> None:
        # 第 3 轮 C02：中间模块同名的另一个来源在包外，不当作空集合；与登记身份混在一起时归歧义，正反两种顺序
        base = {"new.py": "def f():\n    return 1\n", "holder.py": "from .transit import f\n"}
        for imports in ("from .new import f\nfrom math import sqrt as f\n", "from math import sqrt as f\nfrom .new import f\n"):
            with self.subTest(imports=imports):
                rules = {finding.rule for finding in self._findings({**base, "transit.py": imports + "USED = f\n"})}
                self.assertEqual({"moved-ambiguous-hold"}, rules)
        # 对照：持有方直接从包外 import，不是搬移符号
        self.assertRule({"new.py": base["new.py"], "holder.py": "from math import sqrt as f\n"}, None)

    def test_converging_sources_are_walked_once(self) -> None:
        # 第 3 轮 C01：每层两个模块、都从上一层两个模块转手的菱形图；按路径展开是指数级，按可达遍历是线性
        files = {"new.py": "def f():\n    return 1\n", "a0.py": "from .new import f\nUSED = f\n", "b0.py": "from .new import f\nUSED = f\n"}
        # 24 层：按路径展开要一分钟左右、以断言失败变红，而不是让门禁卡死
        for level in range(1, 24):
            for side in "ab":
                files[f"{side}{level}.py"] = f"from .a{level - 1} import f\nfrom .b{level - 1} import f\nUSED = f\n"
        files["holder.py"] = "from .a23 import f\n"
        started = time.monotonic()
        self.assertRule(files, "moved-pure-hold")
        self.assertLess(time.monotonic() - started, 10.0)

    def test_import_as_alias_is_checked_by_local_name(self) -> None:
        # 照 §49 M6：`from .new import ORDER as _ORDER`，登记 _ORDER 与它的公开别名 ORDER
        entry = "old:_ORDER → new:_ORDER"
        new = "_ORDER = (1, 2)\nORDER = _ORDER\n"
        used = {"new.py": new, "old.py": "from .new import ORDER as _ORDER\n\n\ndef first():\n    return _ORDER[0]\n"}
        unused = {"new.py": new, "old.py": "from .new import ORDER as _ORDER\n"}
        self.assertRule(used, None, moves=[entry], aliases={entry: ("ORDER",)})
        self.assertRule(unused, "moved-pure-hold", moves=[entry], aliases={entry: ("ORDER",)})

    def test_holding_exception(self) -> None:
        files = {"new.py": "def f():\n    return 1\n", "old.py": "from .new import f\n"}
        self.assertRule(files, None, exceptions=frozenset({("old", "f")}))

    def test_entry_format(self) -> None:
        self.assertEqual(Move("a.b", "c", "x"), Move.parse("a.b:x → c:x"))
        with self.assertRaises(ValueError):
            Move.parse("a:x → c:y")


class ImportGraphGuardTests(unittest.TestCase):
    """规则 3、4 的合成用例。"""

    def _edges(self, files: dict[str, str]) -> tuple[list[ImportEdge], dict[str, Path], str]:
        with _FakeTree({name: textwrap.dedent(text) for name, text in files.items()}) as tree:
            return package_import_edges(tree.package_dir, tree.name), package_modules(tree.package_dir, tree.name), tree.name

    def test_combined_cycle_through_function_level_import(self) -> None:
        edges, _, _ = self._edges({"a.py": "from .b import y\nx = 1\n", "b.py": "y = 1\n\n\ndef late():\n    from .a import x\n    return x\n"})
        self.assertTrue(find_import_cycles(edges))

    def test_function_level_import_needs_allow(self) -> None:
        edges, _, _ = self._edges({"a.py": "def late():\n    from .b import y\n    return y\n", "b.py": "y = 1\n"})
        self.assertEqual(["function-level-import"], [finding.rule for finding in function_level_package_imports(edges)])

    def test_function_level_import_with_allow(self) -> None:
        edges, _, _ = self._edges({"a.py": f"def late():\n    from .b import y  {ALLOW_MARK} 懒加载\n    return y\n", "b.py": "y = 1\n"})
        self.assertEqual([], function_level_package_imports(edges))

    def test_optional_dependency_import_is_not_package_internal(self) -> None:
        edges, _, _ = self._edges({"a.py": "def late():\n    import gi\n    return gi\n"})
        self.assertEqual([], function_level_package_imports(edges))

    def test_layer_violation(self) -> None:
        edges, modules, name = self._edges({"cli.py": "X = 1\n", "views.py": "from .cli import X\n"})
        findings = check_layer_rules(edges, modules, name, [("views", "cli")], unconditional=False)
        self.assertEqual(["layer"], [finding.rule for finding in findings])

    def test_missing_module_is_red_only_when_unconditional(self) -> None:
        edges, modules, name = self._edges({"cli.py": "X = 1\n"})
        self.assertEqual([], check_layer_rules(edges, modules, name, [("views", "cli")], unconditional=False))
        findings = check_layer_rules(edges, modules, name, [("views", "cli")], unconditional=True)
        self.assertEqual(["layer-missing-module"], [finding.rule for finding in findings])


if __name__ == "__main__":
    unittest.main()
