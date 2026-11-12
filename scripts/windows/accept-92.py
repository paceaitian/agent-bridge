"""W3.10 §92 现场验收探针（只读，DESIGN §92.7 ⑤⑥）：用已安装 release 的产品原语，逐个 claude.exe 计算 T 与 P。

只输出 pid、闭集角色与原因、布尔和计数；不输出命令行、映像路径、SID 或配置值，不写文件、不连管道、不读 key。
须在非提权令牌下、用 ab 当前 release 的 Python 以 -I 运行（W3.10 包装脚本负责定位并拒绝提权令牌）。
⑤ 对每个不是 helper 的 claude.exe 无条件计算 P（Opus 最终确认 P3-1），CLI 的 pProven=false 也作现场负例保留；
productExempt 是产品 Roles.exempt 的结论，consistent 核对探针原因与它一致。保护集取产品同一轮发现的事实：
有效登记端点加当前代际的非交互登记（Discovery.noninteractive），与 discover 的裁决口径相同。
"""
from __future__ import annotations

import json
import sys
import time

from agentstatus_bridge.platforms.factory import get_platform
from agentstatus_bridge.platforms.windows import claude_discovery as D, process_role as R
from agentstatus_bridge.platforms.windows.api import WinApi
from agentstatus_bridge.platforms.windows.local_transport import WindowsPlatform

REASONS = ('proven', 'registered', 'parent_role_unknown', 'parent_is_helper', 'no_witness',
           'witness_unverified', 'budget_exhausted')


def parent_reason(api: WinApi, roles: R.Roles, pid: int, birth: str, children: list[int],
                  registered: frozenset[int]) -> str:
    """⑤ 的闭集原因：预算优先（任何出口跨过截止都记 budget_exhausted），其次父登记、父角色；
    截止前完成复核的合格见证即 proven，否则区分读取未知与没有见证。
    """
    reason = _parent_reason(api, roles, pid, birth, children, registered)
    return 'budget_exhausted' if time.monotonic() > roles.deadline else reason


def _parent_reason(api: WinApi, roles: R.Roles, pid: int, birth: str, children: list[int],
                   registered: frozenset[int]) -> str:
    if time.monotonic() > roles.deadline:
        return 'budget_exhausted'
    if pid in registered:
        return 'registered'
    role = roles.role(pid, birth)
    if role != R.NOT_PROVEN:
        return 'parent_is_helper' if role == R.HELPER else 'parent_role_unknown'
    try:
        parent = api.process(pid, expected_birth=birth)
        image = api.process_image(pid, birth)
    except OSError:
        return 'parent_role_unknown'
    unverified = False
    for child in children:
        if child == pid or child in registered:
            continue
        if time.monotonic() > roles.deadline:
            return 'budget_exhausted'
        try:
            fact = api.process(child)
            role = roles.role(child, str(fact.birth))
            if role == R.UNKNOWN:
                unverified = True
                continue
            if not R.witness(int(birth), image, fact.birth, role, api.process_image(child, str(fact.birth))):
                continue
            if (api.process(child, expected_birth=str(fact.birth)) != fact
                    or api.process(pid, expected_birth=birth) != parent):
                unverified = True
                continue
        except OSError:
            unverified = True
            continue
        # 截止前完成复核的见证记 proven；只有复核本身跨过截止时刻才记预算耗尽（Opus 最终确认 P3-3）
        return 'budget_exhausted' if time.monotonic() > roles.deadline else 'proven'
    return 'witness_unverified' if unverified else 'no_witness'


def main() -> int:
    backend = get_platform().transport
    if not isinstance(backend, WindowsPlatform):
        raise SystemExit('windows_required')
    api = backend.api
    found = D.discover(backend, connect=False)
    registered = frozenset(e.ref.pid for e in (*found.endpoints, *found.duplicates)) | found.noninteractive
    scan = backend.files.claude_sessions_dirs()
    unreadable = {r['path'] for r in found.registries if not r['readable'] and r['reason'] == 'unreadable'}
    # 与 discover 同口径的「未定位」：环境读不出，或定位到的根整体读不了
    unlocated = set(scan.unlocated) | {pid for pid, root in scan.live if str(root) in unreadable}
    table = [(pid, ppid) for pid, ppid, name in api.process_table() if name.lower() == 'claude.exe']
    children: dict[int, list[int]] = {}
    for pid, ppid in table:
        children.setdefault(ppid, []).append(pid)
    roles = R.Roles(api, time.monotonic() + D.SECONDS, allow_parent=not scan.exclusive)
    rows: list[dict[str, object]] = []
    births: dict[int, str] = {}
    for pid, ppid in table:
        row: dict[str, object] = {'pid': pid, 'ppid': ppid, 'fact': False, 'role': R.UNKNOWN, 'configKey': 'unknown',
                                  'registered': pid in registered, 'unlocated': pid in unlocated}
        rows.append(row)
        try:
            birth = str(api.process(pid).birth)
        except OSError:
            continue
        births[pid] = birth  # 只在内存里配对，不进输出
        row.update(fact=True, role=roles.role(pid, birth))
        try:
            row['configKey'] = api.claude_config_dir(pid, birth).state
        except (OSError, RuntimeError, ValueError):
            pass
        if row['role'] != R.HELPER:
            reason = parent_reason(api, roles, pid, birth, children.get(pid, []), registered)
            exempt = roles.exempt(pid, birth, registered)
            row.update(pProven=reason == 'proven', pReason=reason, productExempt=exempt,
                       consistent=(reason == 'proven') == exempt)
    parents = {row['pid'] for row in rows if row.get('pProven')}
    family = [row for row in rows if row['ppid'] in parents and not row['registered'] and row['unlocated']]
    for row in family:
        # 「无 type」须读全前导段且没有 type 键；重复/非法 type 不算无 type（Codex 实现审计 P2-02）。
        # 只有 not_proven_helper 需要区分；helper 不计，unknown 已按角色计入未知。这是另一次有界读取，
        # 与角色那次不是同一样本（共用的只是 _scan 规则）；这次判定不出同样计入未知
        pid = int(str(row['pid']))
        if row['role'] == R.NOT_PROVEN:
            row['typeKeys'] = R.command_role(api, pid, births[pid], deadline=roles.deadline, judge=R.type_presence)
    print(json.dumps({
        'status': 'OBSERVED', 'complete': found.complete, 'endpoints': len(found.endpoints),
        'exclusiveOverride': scan.exclusive, 'budgetExhausted': time.monotonic() > roles.deadline,
        'rows': rows,
        'noTypeUnlocatedChildren': sum(1 for row in family if row.get('typeKeys') == R.NO_TYPE),
        'unknownUnlocatedChildren': sum(1 for row in family if row['role'] == R.UNKNOWN
                                        or row.get('typeKeys') == R.UNKNOWN),
        'typeRegistered': sum(1 for row in rows if row['role'] == R.HELPER and row['registered']),
    }, ensure_ascii=False, indent=1))
    return 0


if __name__ == '__main__':
    sys.exit(main())
