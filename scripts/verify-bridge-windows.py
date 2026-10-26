#!/usr/bin/env python3
"""Lightweight Windows CI selection; never launches agents or enables providers.

Fake tests run on both OSes. Native tests explicitly SKIP on non-Windows, and
the private Store gate explicitly SKIPs elevated tokens instead of weakening ACL.
Federation (DESIGN 88): portable attachment freeze/land, the Windows delivery
model and protocol codec run here; tests needing POSIX permission bits, FIFOs,
symlinks or Linux link-based landing SKIP with a reason starting "POSIX-only:".
"""
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
MODULES = ('test_bridge_windows', 'test_bridge_windows_streams',
           'test_bridge_windows_codex',
           'test_bridge_windows_discovery',
           'test_bridge_windows_callers',
           'test_bridge_windows_delivery',
           'test_bridge_windows_boundaries',
           'test_bridge_windows_storage',
           'test_bridge_windows_roots',
           'test_bridge_windows_roots_rework',
           'test_bridge_registration', 'test_bridge_labels', 'test_bridge_hints',
           'test_bridge_windows_native', 'test_bridge_local_display',
           'test_bridge_federation_codec', 'test_bridge_federation_attachments',
           'test_bridge_federation_windows', 'test_bridge_federation_packaging',
           'test_bridge_federation_transport_close')
# Only these skips may appear; any other skip means a module silently did not qualify.
NATIVE_PREFIX = 'test_bridge_windows_native.'
POSIX_ONLY = "POSIX-only:"


def main() -> int:
    sys.path[:0] = [str(ROOT/'src'),str(ROOT/'tests')]
    # 守卫须在任何测试与 Win32 调用之前装上；tests/ 只在上一行运行时加入 sys.path，pyright 静态解析不到
    import bridge_platform_guard  # pyright: ignore[reportMissingImports]
    suite = unittest.defaultTestLoader.loadTestsFromNames(MODULES)
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    # Unexpected module-wide skips or empty selection cannot qualify Fake tests.
    expected_skips = all(unittest.TestCase.id(t).startswith(NATIVE_PREFIX) or reason.startswith(POSIX_ONLY)
                         for t,reason in result.skipped)
    return 0 if result.wasSuccessful() and result.testsRun >= 50 and expected_skips else 1


if __name__=='__main__':
    raise SystemExit(main())
