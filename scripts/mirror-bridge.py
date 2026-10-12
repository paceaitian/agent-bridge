#!/usr/bin/env python3
"""协作桥镜像工具：本仓是权威源，`agent-bridge` 是它的逐字节镜像（计划 §7 P4b，方向 b）。

**方向**：源码只在本仓改；镜像仓不接受本地编辑，只接受从这里重新导出。镜像自己的
`scripts/check-import-manifest.py` 只能证明「镜像内部没漂移」，证明不了「它是否还等于
本仓当前内容」——那正是这个工具补的那一半。

**清单是推导出来的，不是手维护的**：手维护的白名单会在有人新增桥模块时静默漏掉它。
推导规则（`portable_paths`）：

- `src/agentstatus_bridge/**/*.py` 全部收；
- `tests/test_bridge_*.py` 与 `tests/bridge_support.py` 里**不 import `agentstatus` 包**的那些
  （import 了的是跨边界测试，必须留在本仓，因为它们要同时看两侧）；
- 上面这些可移植测试里按文件名字面引用到的 `tests/fixtures/*`。

判据用「是否 import agentstatus」而不是文件名清单：它是文件自身的客观属性，新增文件时
自动归类，归类错了 `tests/test_mirror_bridge.py` 会变红。
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
import subprocess
import sys
from pathlib import Path
from pathlib import PurePosixPath
import stat

ROOT = Path(__file__).resolve().parents[1]

# 只匹配 agentstatus 包本身：`agentstatus_bridge` 后面跟的是下划线，不在这个字符类里
_IMPORTS_AGENTSTATUS = re.compile(r"^\s*(?:from|import)\s+agentstatus(?=[.\s]|$)", re.MULTILINE)

MIRROR_REPOSITORY = "agentstatus"
MANIFEST_RELPATH = "docs/import-manifest.json"
PORTABLE_TOOLS = ('scripts/mirror-bridge.py', 'scripts/build-bridge.py',
                  'scripts/verify-bridge-windows.py')


def _test_candidates(root: Path) -> list[Path]:
    """可能属于桥的测试文件：命名约定 + 共享支撑模块。"""
    tests = sorted((root / "tests").glob("test_bridge_*.py"))
    for name in ("bridge_support.py", "bridge_platform_guard.py", "bridge_winapi.py", "bridge_winapi_sdk.py"):
        support = root / "tests" / name
        if support.is_file():
            tests.append(support)
    return tests


def portable_paths(root: Path = ROOT) -> list[str]:
    """推导镜像白名单（仓库相对路径，已排序）。"""
    paths: list[str] = [
        path.relative_to(root).as_posix()
        for path in sorted((root / "src/agentstatus_bridge").rglob("*.py"))
        if "__pycache__" not in path.parts
    ]

    portable_tests: list[Path] = []
    for path in _test_candidates(root):
        if _IMPORTS_AGENTSTATUS.search(path.read_text(encoding="utf-8")):
            continue  # 跨边界测试：要同时看两侧，留在本仓
        portable_tests.append(path)
    paths.extend(path.relative_to(root).as_posix() for path in portable_tests)
    paths.extend(name for name in PORTABLE_TOOLS if (root/name).is_file())
    paths.extend(path.relative_to(root).as_posix()
                 for path in sorted((root/'scripts/windows').glob('*'))
                 if path.is_file() and path.suffix in {'.py','.ps1'})

    # 夹具按「文件名在可移植测试里出现过」收：夹具路径是拼出来的，扫路径字面量扫不到
    blobs = [path.read_text(encoding="utf-8") for path in portable_tests]
    fixtures = root / "tests/fixtures"
    if fixtures.is_dir():
        for fixture in sorted(fixtures.iterdir()):
            if fixture.is_file() and any(fixture.name in text for text in blobs):
                paths.append(fixture.relative_to(root).as_posix())

    return sorted(paths)


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def build_manifest(root: Path = ROOT, commit: str | None = None) -> dict[str, object]:
    """生成与镜像仓 `docs/import-manifest.json` 同形的清单。"""
    if commit is None:
        commit = subprocess.run(
            ["git", "-C", str(root), "rev-parse", "HEAD"],
            capture_output=True, text=True, check=True,
        ).stdout.strip()
    return {
        "files": {name: digest(root / name) for name in portable_paths(root)},
        "source": {"commit": commit, "repository": MIRROR_REPOSITORY},
    }


def compare(root: Path, mirror: Path) -> dict[str, object]:
    """把本仓当前内容与镜像记录的清单比对，给出差异明细。"""
    manifest_path = mirror / MANIFEST_RELPATH
    recorded: dict[str, str] = json.loads(manifest_path.read_text(encoding="utf-8"))["files"]
    source = json.loads(manifest_path.read_text(encoding="utf-8"))["source"]
    current = {name: digest(root / name) for name in portable_paths(root)}

    changed = sorted(n for n in current.keys() & recorded.keys() if current[n] != recorded[n])
    added = sorted(current.keys() - recorded.keys())
    removed = sorted(recorded.keys() - current.keys())
    return {
        "mirroredCommit": source.get("commit"),
        "changed": changed,
        "added": added,
        "removed": removed,
        "inSync": not (changed or added or removed),
    }


def _target(mirror: Path, name: str) -> Path:
    parts = PurePosixPath(name).parts
    if (not parts or PurePosixPath(name).is_absolute() or '..' in parts or '\\' in name
            or str(PurePosixPath(name)) != name or parts[0] not in {'src', 'tests', 'scripts', 'docs'}):
        raise SystemExit('镜像清单路径不安全')
    target = mirror
    for part in parts:
        target = target / part
        if target.is_symlink():
            raise SystemExit('镜像目标不允许符号链接')
    return target


def export(root: Path, mirror: Path, commit: str | None = None, *, init: bool = False) -> dict[str, object]:
    """把白名单文件逐字节拷入镜像并重写清单；拷完逐文件回读校验。"""
    manifest = build_manifest(root, commit)
    files: dict[str, str] = manifest["files"]  # type: ignore[assignment]

    if mirror.is_symlink() or (mirror.exists() and not mirror.is_dir()):
        raise SystemExit('镜像目标必须为普通目录')
    recorded: dict[str, str] = {}
    if mirror.exists() and any(path.name != '.git' for path in mirror.iterdir()):
        try:
            old = json.loads(_target(mirror, MANIFEST_RELPATH).read_text(encoding='utf-8'))
            if old['source']['repository'] != MIRROR_REPOSITORY or not isinstance(old['files'], dict):
                raise ValueError('manifest')
            recorded = old['files']
            if any(not isinstance(n, str) or not isinstance(h, str) or not re.fullmatch('[a-f0-9]{64}', h)
                   for n,h in recorded.items()):
                raise ValueError('manifest')
        except (OSError, ValueError, KeyError, TypeError) as error:
            raise SystemExit('已有内容的镜像目录需要有效 import-manifest.json') from error
    elif not init:
        raise SystemExit('空镜像目录需要显式 --init')
    # Validate the entire closed set before copying or deleting anything.
    for name in set(recorded) | set(files) | {MANIFEST_RELPATH}:
        path = _target(mirror, name)
        if path.exists() and not stat.S_ISREG(path.lstat().st_mode):
            raise SystemExit('镜像清单目标不是普通文件')
    removed = sorted(set(recorded) - set(files))
    for name in removed:
        path = _target(mirror, name)
        if path.exists() and digest(path) != recorded[name]:
            raise SystemExit('旧清单残留已被修改，停止导出：' + name)

    for name, expected in files.items():
        target = _target(mirror, name)
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(root / name, target)
        if digest(target) != expected:  # 拷贝后回读：证明镜像里那份就是这里这份
            raise SystemExit(f"拷贝后内容不一致：{name}")

    for name in removed:
        path = _target(mirror, name)
        if path.exists():
            path.unlink()
            print('已删除旧清单文件：' + name)

    (mirror / MANIFEST_RELPATH).parent.mkdir(parents=True, exist_ok=True)
    (mirror / MANIFEST_RELPATH).write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return manifest


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="协作桥镜像清单与一致性检查")
    parser.add_argument("action", choices=("list", "manifest", "check", "export"))
    parser.add_argument("--mirror", type=Path, help="agent-bridge 仓库路径（check/export 必需）")
    parser.add_argument("--json", action="store_true", help="机器可读输出")
    parser.add_argument('--init', action='store_true', help='显式初始化空镜像目录（不绕过已有内容的清单守卫）')
    args = parser.parse_args(argv)

    if args.action == "list":
        for name in portable_paths():
            print(name)
        return 0

    if args.action == "manifest":
        print(json.dumps(build_manifest(), ensure_ascii=False, indent=2, sort_keys=True))
        return 0

    if args.mirror is None:
        parser.error(f"{args.action} 需要 --mirror")
    mirror: Path = args.mirror.expanduser().resolve()
    if args.action == 'check' and not (mirror / MANIFEST_RELPATH).is_file():
        print(f"镜像仓不可用（找不到 {MANIFEST_RELPATH}）：{mirror}", file=sys.stderr)
        return 2

    if args.action == "check":
        result = compare(ROOT, mirror)
        if args.json:
            print(json.dumps(result, ensure_ascii=False, indent=2))
        elif result["inSync"]:
            print(f"镜像与本仓一致（镜像记录的来源提交 {str(result['mirroredCommit'])[:12]}）")
        else:
            print(f"镜像已陈旧：记录的来源提交 {str(result['mirroredCommit'])[:12]}")
            for label, key in (("内容已变", "changed"), ("本仓新增", "added"), ("本仓已删", "removed")):
                names = result[key]
                assert isinstance(names, list)
                if names:
                    print(f"  {label}（{len(names)}）:")
                    for name in names:
                        print(f"    {name}")
        return 0 if result["inSync"] else 1

    manifest = export(ROOT, mirror, init=args.init)
    source, files = manifest["source"], manifest["files"]
    assert isinstance(source, dict) and isinstance(files, dict)
    print(f"已导出 {len(files)} 个文件 → {mirror}（来源提交 {str(source['commit'])[:12]}）")
    print("镜像仓仍需自行提交；提交前请在镜像仓跑 scripts/check-import-manifest.py 与全量测试。")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
