"""Amended G1: external ACLs are not a gate; own resources stay private."""
import json
import os
import unittest
from unittest.mock import Mock, patch

import test_bridge_windows_claude as fixture
from agentstatus_bridge.model import Delivery
from agentstatus_bridge.platforms.windows import claude_auth as auth, claude_discovery as discovery
from agentstatus_bridge.platforms.windows import claude_peer as peer, caller

SYSTEM = bytes.fromhex('010100000000000512000000')
ADMINISTRATORS = bytes.fromhex('01020000000000052000000020020000')
READER = bytes.fromhex('010100000000000563000000')  # synthetic, not the owner's group SID
FULL = 0x1f01ff
READ_EXECUTE_SYNC = 0x1200a9
INHERITED = 0x10


class AclTests(unittest.TestCase):
    setUp = fixture.NativeTests.setUp
    write = fixture.NativeTests.write
    inbox = fixture.NativeTests.inbox
    own = fixture.NativeTests.own
    sending = fixture.NativeTests.sending

    def external(self):
        names = ('200.json', auth.key_name(200, fixture.PIPE))
        for name in names:
            self.k.files[str(self.sessions / name)] = {
                'owner': self.k.sid, 'protected': False,
                'aces': [(0, INHERITED, READ_EXECUTE_SYNC, READER),
                         (0, INHERITED, FULL, SYSTEM), (0, INHERITED, FULL, ADMINISTRATORS),
                         (0, INHERITED, FULL, self.k.sid)]}
        return names

    def read_external(self, name):
        try:
            value = auth.PeerFiles(self.p.files).read(name)
        except OSError:
            self.fail('valid external fixture must be readable without an owner/DACL gate')
        self.assertIsInstance(value, dict)

    def test_observed_inherited_readers_allow_discovery_caller_key_and_delivery_without_acl_writes(self):
        names = self.external()
        before = {name: (self.sessions / name).read_bytes() for name in names}
        metadata = {name: dict(self.k.files[str(self.sessions / name)]) for name in names}
        found = discovery.discover(self.p.transport)
        self.assertTrue(found.complete)
        self.assertEqual(len(found.endpoints), 1)
        self.assertEqual(found.select(fixture.UUID).ref.native_id, fixture.UUID)
        self.assertEqual(caller.identify(pid=100, environ={}).endpoint.ref.native_id, fixture.UUID)
        self.assertEqual(auth.PeerFiles(self.p.files).token(200, fixture.PIPE, fixture.BIRTH, self.record), fixture.TOKEN)
        with self.sending() as (transport, endpoint, context, writes, boundary):
            result = transport.deliver(endpoint, 'fixture', context)
        self.assertIs(result.delivery, Delivery.WRITTEN)
        self.assertEqual(len(writes), 2)
        boundary.assert_called_once()
        self.assertEqual(before, {name: (self.sessions / name).read_bytes() for name in names})
        self.assertEqual(metadata, {name: self.k.files[str(self.sessions / name)] for name in names})
        self.assertFalse(any(name == 'SetSecurityInfo' for name, _ in self.k.calls))

    def test_external_third_party_write_bits_do_not_block_read_or_send(self):
        for filename in self.external():
            for mask in (0x2, 0x4, 0x10, 0x40, 0x100, 0x10000, 0x40000, 0x80000, 0x10000000, 0x40000000):
                for flags in (INHERITED, INHERITED | 8):
                    with self.subTest(kind=filename.endswith('.key'), mask=mask, flags=flags):
                        self.external()
                        with self.sending() as (transport, endpoint, context, writes, boundary):
                            meta = self.k.files[str(self.sessions / filename)]
                            meta['aces'][0] = (0, flags, READ_EXECUTE_SYNC | mask, READER)
                            with patch.object(self.k.api, 'check_private', wraps=self.k.api.check_private) as check:
                                self.read_external(filename)
                                check.assert_not_called()
                            result = transport.deliver(endpoint, 'fixture', context)
                        self.assertIs(result.delivery, Delivery.WRITTEN)
                        self.assertEqual(len(writes), 2)
                        boundary.assert_called_once()
                        self.assertFalse(any(name == 'SetSecurityInfo' for name, _ in self.k.calls))

    def test_external_owner_is_not_a_product_gate(self):
        for name in self.external():
            for owner in (READER, SYSTEM, ADMINISTRATORS):
                with self.subTest(key=name.endswith('.key'), owner_kind=owner == SYSTEM):
                    self.external()
                    self.k.files[str(self.sessions / name)]['owner'] = owner
                    with patch.object(self.k.api, 'check_private', wraps=self.k.api.check_private) as check:
                        self.read_external(name)
                        check.assert_not_called()

    def test_external_full_allow_is_not_a_product_gate(self):
        for name in self.external():
            for entry in (None, (0, INHERITED, READ_EXECUTE_SYNC, self.k.sid),
                          (0, INHERITED | 8, FULL, self.k.sid)):
                with self.subTest(key=name.endswith('.key'), missing=entry is None):
                    self.external()
                    meta = self.k.files[str(self.sessions / name)]
                    meta['aces'] = meta['aces'][:-1] + ([] if entry is None else [entry])
                    with patch.object(self.k.api, 'check_private', wraps=self.k.api.check_private) as check:
                        self.read_external(name)
                        check.assert_not_called()

    def sized(self, name, size):
        value = self.record if name.endswith('.json') else {'peerToken': fixture.TOKEN}
        value = {**value, 'padding': ''}
        overhead = len(json.dumps(value, separators=(',', ':')).encode())
        value['padding'] = 'x' * (size - overhead)
        raw = json.dumps(value, separators=(',', ':')).encode()
        self.assertEqual(len(raw), size)
        (self.sessions / name).write_bytes(raw)

    def test_records_between_four_and_sixty_four_kib_are_read_and_delivered(self):
        from agentstatus_bridge.endpoints import MAX_REGISTRY_BYTES
        self.assertEqual(auth.MAX_JSON, MAX_REGISTRY_BYTES)
        self.assertEqual(auth.MAX_JSON, 64 * 1024)
        for size in (4097, 32 * 1024, 64 * 1024):
            with self.subTest(size=size):
                for name in self.external():
                    self.sized(name, size)
                found = discovery.discover(self.p.transport)
                self.assertTrue(found.complete)
                self.assertEqual(found.select(fixture.UUID).ref.native_id, fixture.UUID)
                with self.sending() as (transport, endpoint, context, writes, boundary):
                    self.assertIs(transport.deliver(endpoint, 'fixture', context).delivery, Delivery.WRITTEN)
                self.assertEqual(len(writes), 2)
                boundary.assert_called_once()

    def test_valid_json_one_byte_over_limit_is_rejected_after_bounded_read(self):
        for name in self.external():
            with self.subTest(key=name.endswith('.key')):
                self.sized(name, 64 * 1024 + 1)
                with patch.object(self.k.api, 'read', wraps=self.k.api.read) as read:
                    with self.assertRaisesRegex(OSError, 'claude_file_changed'):
                        auth.PeerFiles(self.p.files).read(name)
                    self.assertEqual(read.call_count, 1)
                    self.assertEqual(read.call_args.args[1], 64 * 1024 + 1)

    def test_external_identity_change_during_read_remains_rejected(self):
        for name in self.external():
            with self.subTest(key=name.endswith('.key')):
                read = self.k.api.read
                def changed(*args):
                    value = read(*args)
                    self.k.files[str(self.sessions / name)]['file_id128'] = 2**120 + 1
                    return value
                with patch.object(self.k.api, 'read', side_effect=changed):
                    with self.assertRaisesRegex(OSError, 'claude_file_changed'):
                        auth.PeerFiles(self.p.files).read(name)

    def test_external_multiple_links_remain_rejected(self):
        for name in self.external():
            alias = self.sessions / 'fixture-hardlink'
            os.link(self.sessions / name, alias)
            try:
                with self.assertRaisesRegex(OSError, 'claude_file_untrusted'):
                    auth.PeerFiles(self.p.files).read(name)
            finally:
                alias.unlink()

    def test_invalid_filename_never_reads_even_an_existing_fixture(self):
        (self.sessions.parent / 'outside.json').write_text('{"fixture":true}')
        with patch.object(self.k.api, 'read', wraps=self.k.api.read) as read:
            with self.assertRaisesRegex(OSError, 'claude_file_name_invalid'):
                auth.PeerFiles(self.p.files).read('../outside.json')
            read.assert_not_called()

    def test_own_key_stays_protected_and_rejects_readers_and_administrators(self):
        for extra, protected in (((0, 0, READ_EXECUTE_SYNC, READER), True),
                                 ((0, 0, FULL, ADMINISTRATORS), True), (None, False)):
            with self.subTest(reader=extra is not None, protected=protected):
                own = self.own()
                opening = own.files.open_own
                def changed(name, *, create):
                    handle = opening(name, create=create)
                    self.k.files[str(self.sessions / name)].update(
                        protected=protected, aces=[(0, 0, FULL, self.k.sid), (0, 0, FULL, SYSTEM)]
                        + ([] if extra is None else [extra]))
                    return handle
                try:
                    with patch.object(own.files, 'open_own', side_effect=changed), patch.object(
                            self.k.api, 'write', wraps=self.k.api.write) as write:
                        with self.assertRaisesRegex(OSError, 'windows_acl_untrusted'):
                            own.publish()
                        write.assert_not_called()
                finally:
                    own.close()
                self.assertFalse((self.sessions / own.name).exists())

    def test_own_inbox_stays_private_and_rejects_readers_and_administrators(self):
        for extra in ((0, 0, READ_EXECUTE_SYNC, READER), (0, 0, FULL, ADMINISTRATORS)):
            with self.subTest(reader=extra[2] == READ_EXECUTE_SYNC):
                box = peer.Inbox(self.p.files)
                self.k.files[str(box.path)] = {'aces': [(0, 0, FULL, self.k.sid), (0, 0, FULL, SYSTEM), extra]}
                thread = Mock(is_alive=Mock(return_value=False))
                with patch.object(peer.threading, 'Thread', return_value=thread), patch.object(
                        self.k.api.k, 'CancelIoEx', return_value=1), patch.object(auth.OwnKey, 'publish') as publish:
                    try:
                        with self.assertRaisesRegex(OSError, 'windows_acl_untrusted'):
                            box.open()
                        publish.assert_not_called()
                        thread.start.assert_not_called()
                    finally:
                        box.close()


if __name__ == '__main__':
    unittest.main()
