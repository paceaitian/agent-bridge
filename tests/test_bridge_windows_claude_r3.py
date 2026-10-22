"""Third-review guards use queryable peers, not only early Fake access denial."""
import unittest
from unittest.mock import patch

import test_bridge_windows_claude as fixture
from agentstatus_bridge.model import Delivery
from agentstatus_bridge.platforms.types import Presence
from agentstatus_bridge.platforms.windows import claude_discovery as discovery, commands
from agentstatus_bridge.transports import claude_windows as transport_module


class GuardTests(unittest.TestCase):
    setUp = fixture.NativeTests.setUp
    write = fixture.NativeTests.write
    inbox = fixture.NativeTests.inbox
    sending = fixture.NativeTests.sending

    def test_current_elevation_is_rejected_by_real_token_api_before_peer_query(self):
        original = self.k.processes[100]
        for stage in ('process', 'token', 'queryable'):
            with self.subTest(stage=stage):
                self.k.restricted_process_stage = stage
                self.k.processes[100] = (*original[:3], True, original[4])
                with patch.object(self.k.api, 'process', wraps=self.k.api.process) as query:
                    with self.assertRaisesRegex(OSError, 'windows_elevated_unsupported'):
                        discovery.peer_process(self.p.transport, 200)
                    self.assertIs(commands.receiver_presence(200, 'win-filetime:' + fixture.BIRTH), Presence.UNKNOWN)
                    query.assert_not_called()

    def test_process_image_rejects_queryable_foreign_and_elevated_peer(self):
        original = self.k.processes[200]
        foreign = bytes.fromhex('01010000000000052b000000')
        for stage in ('process', 'token', 'queryable'):
            for sid, elevated in ((foreign, False), (self.k.sid, True)):
                with self.subTest(stage=stage, elevated=elevated):
                    self.k.restricted_process_stage = stage
                    self.k.processes[200] = (*original[:2], sid, elevated, original[4])
                    self.k.calls.clear()
                    with self.assertRaises(OSError) as caught:
                        self.k.api.process_image(200, fixture.BIRTH)
                    if stage == 'queryable':
                        self.assertEqual(str(caught.exception), 'worker_identity_unverified')
                    self.assertFalse(any(name == 'QueryFullProcessImageNameW' for name, _ in self.k.calls))
        self.k.processes[200] = original
        self.assertEqual(self.k.api.process_image(200, fixture.BIRTH), self.k.images[200])

    def test_delivery_rechecks_queryable_token_after_inspect_before_key_or_write(self):
        original = self.k.processes[200]
        foreign = bytes.fromhex('01010000000000052b000000')
        for stage in ('process', 'token', 'queryable'):
            for sid, elevated in ((foreign, False), (self.k.sid, True)):
                with self.subTest(stage=stage, elevated=elevated):
                    self.k.processes[200] = original
                    self.k.restricted_process_stage = stage
                    with self.sending() as (transport, endpoint, context, writes, boundary):
                        opening = transport_module.WinIO.open_pipe
                        def changed(io, address):
                            handle = opening(io, address)
                            self.k.processes[200] = (*original[:2], sid, elevated, original[4])
                            return handle
                        with patch.object(transport_module.WinIO, 'open_pipe', changed), patch.object(
                                transport_module.PeerFiles, 'token', wraps=fixture.A.PeerFiles(self.p.files).token) as key:
                            result = transport.deliver(endpoint, 'fixture', context)
                        self.assertIs(result.delivery, Delivery.FAILED)
                        self.assertEqual(result.reason, 'claude_peer_unverified')
                        key.assert_not_called()
                        self.assertEqual(writes, [])
                        boundary.assert_not_called()

    def test_pipe_open_failure_matches_linux_without_key_read_or_send(self):
        for code in (2, 5, 231):
            with self.subTest(winerror=code), self.sending() as (transport, endpoint, context, writes, boundary):
                error = OSError('synthetic open failure'); error.winerror = code
                with patch.object(transport_module.WinIO, 'open_pipe', side_effect=error) as opening, patch.object(
                        transport_module.PeerFiles, 'token') as key:
                    result = transport.deliver(endpoint, 'fixture', context)
                self.assertIs(result.delivery, Delivery.FAILED)
                self.assertEqual(result.reason, 'claude_socket_connect_failed')
                opening.assert_called_once()
                key.assert_not_called()
                boundary.assert_not_called()
                self.assertEqual(writes, [])


if __name__ == '__main__':
    unittest.main()
