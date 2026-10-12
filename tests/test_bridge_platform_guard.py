"""W1-0：守卫自身负对照只调检查器/假stream，绝不试连生产端点。"""
from agentstatus_bridge.platforms.linux import local_transport as linux_transport
import os
from pathlib import Path
import unittest
from unittest.mock import patch

import bridge_platform_guard as guard
from agentstatus_bridge.transports import codex_rpc, local_codex


class PlatformGuardTests(unittest.TestCase):
    def test_posix_roots_boundaries_and_bus(self):
        roots = ('/fixture/real-home/.codex/', '/fixture/bridge/', '/tmp/codex-daemon-321/')
        for address in ('/fixture/real-home/.codex/server', b'/fixture/bridge/leader.sock',
                        Path('/tmp/codex-daemon-321/a.sock'), '/run/user/321/bus',
                        '/run/dbus/system_bus_socket'):
            with self.subTest(address=address), self.assertRaises(guard.ProductionSocketUse):
                guard.check_posix(address, roots, 321)
        for address in ('/fixture/real-home/.codex-other/socket', '/fixture/test/socket', '\0fixture'):
            guard.check_posix(address, roots, 321)

    def test_windows_requires_exact_fixture_and_releases_it(self):
        for kind in ('unix', 'pipe'):
            address = r'C:\temporary-fixture\a.sock' if kind == 'unix' else r'\\.\pipe\temporary-fixture'
            with self.assertRaises(guard.ProductionSocketUse):
                guard.check_windows(kind, address)
            with guard.windows_fixture(kind, address):
                guard.check_windows(kind, address.upper())
                with self.assertRaises(guard.ProductionSocketUse):
                    guard.check_windows(kind, address + '-different')
                with guard.windows_fixture(kind, address):
                    guard.check_windows(kind, address)
                guard.check_windows(kind, address)
            with self.assertRaises(guard.ProductionSocketUse):
                guard.check_windows(kind, address)

    def test_rpc_cannot_swallow_the_platform_guard(self):
        class Stream:
            def settimeout(self, _seconds): pass
            def close(self): pass
        def reject(*_args, **_kwargs):
            guard.check_windows('unix', r'C:\unregistered-fixture\socket')
        with patch.object(codex_rpc, 'resolve_socket', return_value=Path('/fake')), \
                patch.object(linux_transport.LinuxPlatform, 'new_stream', return_value=Stream()), \
                patch.object(linux_transport.LinuxPlatform, 'connect', side_effect=reject), \
                self.assertRaises(guard.ProductionSocketUse):
            codex_rpc.queue_add(Path('/fake'), thread_id='fixture', text='fixture',
                                client_message_id='fixture', client_version='fixture')
