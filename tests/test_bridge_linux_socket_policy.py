"""Client policy witnesses without connecting to any socket."""
from pathlib import Path
import os
import socket
import stat
import struct
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from agentstatus_bridge.platforms.linux.local_transport import LinuxPlatform
from agentstatus_bridge.platforms.transport_types import LocalFailure


class LinuxSocketPolicyTests(unittest.TestCase):
    target = Path('/fixture/control/socket')

    def resolve(self, platform, *, mode=stat.S_IFSOCK | 0o600, owner=None,
                parent_mode=0o700, parent_owner=None, parent_error=False):
        uid = os.getuid()
        def fake_stat(path):
            if path == self.target:
                return SimpleNamespace(st_mode=mode, st_uid=uid if owner is None else owner)
            if parent_error:
                raise PermissionError('fixture')
            return SimpleNamespace(st_mode=stat.S_IFDIR | parent_mode,
                                   st_uid=uid if parent_owner is None else parent_owner)
        with patch('os.path.lexists', return_value=True), \
                patch('os.path.realpath', return_value=str(self.target)), \
                patch.object(Path, 'stat', autospec=True, side_effect=fake_stat):
            return platform.resolve(Path('/fixture/link'))

    def test_modes_and_parent_are_observations_not_client_rejections(self):
        for options in ({'mode': stat.S_IFSOCK | 0o666}, {'parent_mode': 0o755},
                        {'parent_owner': os.getuid() + 1}, {'parent_error': True}):
            with self.subTest(options=options):
                platform = LinuxPlatform()
                with self.assertLogs('agentstatus_bridge.platforms.linux.local_transport', level='DEBUG') as logs:
                    self.assertEqual(self.resolve(platform, **options), self.target)
                self.assertEqual(len(logs.output), 1)
                self.assertIn('codex_socket_permissions_observed', logs.output[0])
                self.assertNotIn('/fixture', logs.output[0])
                with self.assertNoLogs('agentstatus_bridge.platforms.linux.local_transport', level='DEBUG'):
                    self.assertEqual(self.resolve(platform, **options), self.target)

    def test_socket_kind_and_owner_still_reject(self):
        for options in ({'mode': stat.S_IFREG | 0o600}, {'owner': os.getuid() + 1}):
            with self.subTest(options=options):
                value = self.resolve(LinuxPlatform(), **options)
                self.assertIsInstance(value, LocalFailure)
                self.assertEqual(value.reason, 'socket_rejected')

    def test_authenticated_peer_uid_is_still_required(self):
        stream = Mock(spec=socket.socket)
        stream.getsockopt.return_value = struct.pack('3i', 17, os.getuid() + 1, 0)
        self.assertIsNone(LinuxPlatform().peer_pid(stream))
        stream.getsockopt.return_value = struct.pack('3i', 17, os.getuid(), 0)
        self.assertEqual(LinuxPlatform().peer_pid(stream), 17)


if __name__ == '__main__':
    unittest.main()
