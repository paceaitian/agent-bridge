#!/usr/bin/env python3
"""核对导入清单：本仓库的桥代码必须与 `docs/import-manifest.json` 记录的上游内容逐字节相同。

首版的方向是 agentstatus → agent-bridge 的**镜像**：这里的文件是从上游那个提交逐字节拷来的，
所以「内容 SHA 相同」本身就是「这个仓库等于已部署的代码」的证明。有意修改时要**同时**更新清单
（并说明改动理由），让下一个人看得出这是刻意的而不是漂移。
"""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def main() -> int:
    manifest = json.loads((ROOT / "docs/import-manifest.json").read_text(encoding="utf-8"))
    recorded: dict[str, str] = manifest["files"]
    problems: list[str] = []

    for name, digest in sorted(recorded.items()):
        path = ROOT / name
        if not path.is_file():
            problems.append(f"清单里有但仓库里没有：{name}")
            continue
        actual = hashlib.sha256(path.read_bytes()).hexdigest()
        if actual != digest:
            problems.append(f"内容与上游不同：{name}")

    tracked = {
        path.relative_to(ROOT).as_posix()
        for path in list((ROOT / "src").rglob("*.py")) + list((ROOT / "tests").rglob("*"))
        if path.is_file() and "__pycache__" not in path.parts
    }
    for name in sorted(tracked - set(recorded)):
        problems.append(f"不在清单里的文件（新增请先决定它属于上游还是本仓）：{name}")

    if problems:
        print(f"导入清单核对失败（来源 {manifest['source']['repository']}@{manifest['source']['commit'][:12]}）：")
        print("\n".join(f"  - {item}" for item in problems))
        return 1

    print(f"导入清单一致：{len(recorded)} 个文件，来源 {manifest['source']['repository']}@{manifest['source']['commit'][:12]}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
