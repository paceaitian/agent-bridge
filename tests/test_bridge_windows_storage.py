"""§86: real Store flow over the SDK Fake; synthetic owner/ACL metadata only."""
import ctypes as C
from contextlib import ExitStack, contextmanager, redirect_stdout
import io
import json
import os
from pathlib import Path
import sqlite3
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import bridge_support
from bridge_winapi import Kernel
from agentstatus_bridge import doctor
from agentstatus_bridge.platforms.factory import make_platform, using_platform
from agentstatus_bridge.platforms.windows.api import WinFailure
from agentstatus_bridge.platforms.windows.private_file import pinned_file
from agentstatus_bridge.store import Store, StoreError

ADMIN = bytes.fromhex('01020000000000052000000020020000')
SYSTEM = bytes.fromhex('010100000000000512000000')
OTHER = bytes.fromhex('010100000000000563000000')


class StorageRepairTests(unittest.TestCase):
    def setUp(self):
        temp = TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.state = self.root / 'state'
        self.state.mkdir()
        self.k = Kernel(self.root)
        self.p = make_platform('windows', win_api=self.k.api)
        self.addCleanup(lambda: self.assertEqual(self.k.handles, {}))
        self.enterContext(patch.dict(os.environ, AB_STATE_DIR=str(self.state)))
        self.enterContext(using_platform(self.p))

    def sidecars(self, owner=ADMIN):
        with Store.open() as store:
            self.assertEqual(store._conn.execute('PRAGMA user_version').fetchone()[0], 2)
        paths = [self.state / ('bridge.sqlite3' + suffix) for suffix in ('-wal', '-shm')]
        for path, size in zip(paths, (0, 32768)):
            path.write_bytes(b'\0' * size)
            self.k.files[str(path)] = {'owner': owner, 'protected': False,
                                      'aces': [(0, 16, 0x1f01ff, self.k.sid), (0, 16, 0x1f01ff, SYSTEM)]}
        return paths

    def security_calls(self):
        return [args for name, args in self.k.calls if name == 'SetSecurityInfo']

    @contextmanager
    def successful(self):
        try:
            yield
        except (StoreError, OSError) as error:
            self.fail('authorized fixture operation failed: ' + type(error).__name__)

    def test_incident_old_gate_fails_then_sidecars_heal_and_store_opens(self):
        paths = self.sidecars()
        with patch.object(self.p.files, '_owner_repair', side_effect=OSError('windows_owner_mismatch')):
            with self.assertRaises(StoreError) as caught:
                Store.open()
            self.assertEqual(caught.exception.code, 'store_unavailable')
        self.assertEqual(self.security_calls(), [])
        with self.successful(), self.assertLogs('agentstatus_bridge.platforms.windows.files', level='WARNING') as logs:
            with Store.open() as store:
                self.assertEqual(store._conn.execute('PRAGMA user_version').fetchone()[0], 2)
                for path in paths:
                    self.assertEqual(self.k.files[str(path)]['owner'], self.k.sid)
                    self.assertTrue(self.k.files[str(path)]['protected'])
        self.assertEqual(sum(args[2] == 1 for args in self.security_calls()), 2)
        self.assertTrue(self.p.files.acl_observation())
        marker = json.loads((self.state / 'acl-repair.json').read_bytes())
        self.assertEqual(marker, {'previousAclUntrusted': True, 'reasons': ['owner_administrators']})
        self.assertIn('owner_administrators', ''.join(logs.output))
        self.assertNotIn(str(self.state), ''.join(logs.output))

    def test_administrators_and_system_roots_heal_with_metadata_only_access(self):
        for owner, reason in ((ADMIN, 'owner_administrators'), (SYSTEM, 'owner_system')):
            with self.subTest(reason=reason):
                self.k.files[str(self.state)] = {'owner': owner, 'protected': False, 'deny_data': True}
                with self.successful():
                    self.p.files.ensure_private_dir(self.state)
                meta = self.k.files[str(self.state)]
                self.assertEqual(meta['owner'], self.k.sid)
                self.assertTrue(meta['protected'])
                self.assertIn(reason, self.p.files.repair_reasons)

    def test_system_sidecars_and_owned_receipt_and_lock_paths(self):
        paths = self.sidecars(SYSTEM)
        with self.successful(), Store.open():
            self.assertTrue(all(self.k.files[str(p)]['owner'] == self.k.sid for p in paths))
        receipt = self.state / 'worker.json'
        receipt.write_bytes(b'fixture')
        self.k.files[str(receipt)] = {'owner': ADMIN}
        with self.successful(), pinned_file(self.p.files, receipt) as handle:
            self.assertEqual(self.k.api.read(handle, 128), b'fixture')
        lock = self.state / 'worker.lock'
        lock.touch()
        self.k.files[str(lock)] = {'owner': ADMIN}
        with self.successful():
            fd = self.p.lifecycle.open_lock(lock)
            self.p.lifecycle.close_lock(fd)
        self.assertEqual(self.k.files[str(lock)]['owner'], self.k.sid)

    def test_main_database_owner_heals_then_reacquires_data_access(self):
        with Store.open():
            pass
        path = self.state / 'bridge.sqlite3'
        self.k.files[str(path)] = {'owner': ADMIN, 'deny_data': True}
        with self.successful(), Store.open() as store:
            self.assertEqual(store._conn.execute('PRAGMA user_version').fetchone()[0], 2)
        self.assertEqual(self.k.files[str(path)]['owner'], self.k.sid)
        self.assertFalse(self.k.files[str(path)]['deny_data'])
        self.assertTrue(self.p.files.acl_observation())

    def test_untrusted_owner_root_leaf_and_external_admin_never_repaired(self):
        leaf = self.state / 'foreign'
        leaf.touch()
        for path in (leaf, self.state):
            with self.subTest(directory=path == self.state):
                self.k.files[str(path)] = {'owner': OTHER}
                with self.assertRaisesRegex(OSError, 'windows_owner_mismatch'):
                    if path == self.state:
                        self.p.files.ensure_private_dir(path)
                    else:
                        self.p.files.validate_file(path)
                self.k.files[str(path)] = {}
        outside = self.root / 'outside'
        outside.touch()
        self.k.files[str(outside)] = {'owner': ADMIN}
        with self.assertRaisesRegex(OSError, 'windows_owner_mismatch'):
            self.p.files.validate_file(outside)
        with self.assertRaisesRegex(OSError, 'windows_acl_untrusted'):
            with pinned_file(self.p.files, outside, external=True):
                self.fail('foreign owner accepted')
        self.assertEqual(self.security_calls(), [])

    def test_repair_reopen_identity_link_type_and_owner_changes_are_rejected(self):
        leaf = self.state / 'receipt'
        leaf.write_bytes(b'unchanged')
        original = self.k.api.file_info
        for directory in (False, True):
            path = self.state if directory else leaf
            for field in ('index_low', 'links', 'attributes', 'owner'):
                with self.subTest(directory=directory, field=field):
                    self.k.files[str(path)] = {'owner': ADMIN}
                    def changed(handle, **kw):
                        info = original(handle, **kw)
                        if self.k.record(handle)['access'] & 0x80000:
                            if field == 'owner':
                                self.k.files[str(path)]['owner'] = OTHER
                            elif field == 'attributes':
                                info.attributes ^= 16
                            else:
                                setattr(info, field, getattr(info, field) + 1)
                        return info
                    with patch.object(self.k.api, 'file_info', side_effect=changed):
                        with self.assertRaises(OSError):
                            if directory:
                                self.p.files.ensure_private_dir(path)
                            else:
                                self.p.files.validate_file(path)
                    self.k.files[str(path)] = {}
        self.assertEqual(self.security_calls(), [])
        self.assertEqual(leaf.read_bytes(), b'unchanged')

    def test_reparse_hardlinks_and_non_ntfs_refused(self):
        leaf = self.state / 'receipt'
        leaf.touch()
        for flags in ({'reparse': True}, {'fs': 'FAT32'}, {'hardlink': True}):
            with self.subTest(case=flags):
                self.k.files[str(leaf)] = {'owner': ADMIN, **flags}
                link = self.state / 'alias'
                if flags.get('hardlink'):
                    os.link(leaf, link)
                try:
                    with self.assertRaises(OSError):
                        self.p.files.validate_file(leaf)
                finally:
                    link.unlink(missing_ok=True)
        self.assertEqual(self.security_calls(), [])

    def test_write_owner_denied_no_retry_and_failure_projects_winerror(self):
        leaf = self.state / 'receipt'
        leaf.touch()
        self.k.files[str(leaf)] = {'owner': ADMIN, 'deny_owner': True}
        with self.assertRaises(OSError) as caught:
            self.p.files.validate_file(leaf)
        self.assertEqual(caught.exception.winerror, 5)
        self.assertEqual(doctor.storage_subreason(caught.exception), 'winerror_5')
        opens = [args for name, args in self.k.calls if name == 'CreateFileW' and args[1] & 0x80000]
        self.assertEqual(len(opens), 1)
        self.assertEqual(self.security_calls(), [])
        self.assertEqual(self.k.files[str(leaf)]['owner'], ADMIN)

    def test_fake_owner_operation_requires_right_not_exact_mask(self):
        leaf = self.state / 'rights'
        leaf.touch()
        for granted in (False, True):
            self.k.files[str(leaf)] = {'owner': ADMIN}
            with self.k.api.owned(self.k.api.open_file(str(leaf), read_data=True, write_owner=granted)) as h:
                if granted:
                    with self.successful():
                        self.k.api.restore_owner(h, 'administrators')
                    self.assertEqual(self.k.files[str(leaf)]['owner'], self.k.sid)
                else:
                    with self.assertRaises(OSError) as caught:
                        self.k.api.restore_owner(h, 'administrators')
                    self.assertEqual(caught.exception.winerror, 5)
                    self.assertEqual(self.k.files[str(leaf)]['owner'], ADMIN)

    def test_dacl_failure_after_owner_fix_is_observed_without_retry(self):
        leaf = self.state / 'partial'
        leaf.touch()
        self.k.files[str(leaf)] = {'owner': ADMIN, 'private': False}
        with patch.object(self.k.api, 'repair_private', side_effect=WinFailure(5)):
            with self.assertRaises(OSError) as caught:
                self.p.files.validate_file(leaf)
        self.assertEqual(caught.exception.winerror, 5)
        self.assertEqual(self.k.files[str(leaf)]['owner'], self.k.sid)
        self.assertTrue(self.p.files.acl_observation())
        self.assertIn('owner_administrators', self.p.files.repair_reasons)
        self.assertEqual(len(self.security_calls()), 1)

    def test_doctor_adds_closed_subreason_without_changing_existing_reason(self):
        cases = [(OSError('windows_owner_mismatch'), 'windows_owner_mismatch'),
                 (OSError('windows_acl_untrusted'), 'windows_acl_untrusted'),
                 (WinFailure(5), 'winerror_5'), (WinFailure(32), 'winerror_32'),
                 (sqlite3.OperationalError('private SQL'), 'sqlite_error'),
                 (OSError('secret arbitrary path'), 'unknown')]
        for cause, expected in cases:
            with self.subTest(expected=expected), ExitStack() as stack:
                error = StoreError('store_unavailable')
                error.__cause__ = cause
                stack.enter_context(patch.object(doctor, 'daemon_diagnostic', return_value={'cliVersion': 'unknown'}))
                stack.enter_context(patch.object(doctor, 'caller_diagnostic', return_value={}))
                stack.enter_context(patch('agentstatus_bridge.platforms.windows.commands.claude_evidence',
                    return_value=SimpleNamespace(complete=True, reason='complete', endpoints=(), root_diagnostics=(), registries=())))
                stack.enter_context(patch.object(Store, 'open', side_effect=error))
                checks = doctor.collect_checks()
                self.assertFalse(checks['ledgerReadable'])
                self.assertEqual(checks['storageReason'], 'windows_storage_unverified')
                self.assertEqual(checks['storageSubreason'], expected)
                self.assertNotIn('secret', json.dumps(checks))
                self.assertNotIn('private SQL', json.dumps(checks))

    def test_subreason_cycle_unknown_winerror_and_context_are_bounded(self):
        error = OSError('secret')
        error.__cause__ = error
        self.assertEqual(doctor.storage_subreason(error), 'unknown')
        error = WinFailure(99999)
        self.assertEqual(doctor.storage_subreason(error), 'unknown')
        error.__context__ = OSError('windows_owner_mismatch')
        self.assertEqual(doctor.storage_subreason(error), 'windows_owner_mismatch')

    def test_concurrent_owner_already_restored_accepts_same_file_and_directory(self):
        leaf = self.state / 'concurrent'
        leaf.write_bytes(b'fixture')
        original = self.k.api.file_info
        for directory in (False, True):
            path = self.state if directory else leaf
            for owner in (ADMIN, SYSTEM):
                with self.subTest(directory=directory, system=owner == SYSTEM):
                    self.k.files[str(path)] = {'owner': owner, 'private': False, 'protected': False}
                    before = len(self.security_calls())
                    wins = []
                    def peer_wins(handle, **kw):
                        info = original(handle, **kw)
                        if self.k.record(handle)['access'] & 0x80000:
                            self.k.files[str(path)]['owner'] = self.k.sid
                            wins.append(handle)
                        return info
                    with self.successful(), patch.object(self.k.api, 'file_info', side_effect=peer_wins):
                        if directory:
                            self.p.files.ensure_private_dir(path)
                        else:
                            self.p.files.validate_file(path)
                    self.assertTrue(wins, 'fixture must switch owner on the reopened repair handle')
                    calls = self.security_calls()[before:]
                    self.assertEqual([args[2] for args in calls], [0x80000004], 'only DACL remains to repair')
                    self.assertEqual(self.k.files[str(path)]['owner'], self.k.sid)
                    self.assertTrue(self.k.files[str(path)]['protected'])
        self.assertEqual(leaf.read_bytes(), b'fixture')

    def test_builtin_alias_owners_never_match_administrators(self):
        users = bytes.fromhex('01020000000000052000000021020000')
        backup_operators = bytes.fromhex('01020000000000052000000027020000')
        leaf = self.state / 'builtin'
        leaf.touch()
        for directory in (False, True):
            path = self.state if directory else leaf
            for owner in (users, backup_operators):
                with self.subTest(directory=directory, backup=owner == backup_operators):
                    self.k.files[str(path)] = {'owner': owner, 'protected': False}
                    with self.assertRaisesRegex(OSError, 'windows_owner_mismatch'):
                        if directory:
                            self.p.files.ensure_private_dir(path)
                        else:
                            self.p.files.validate_file(path)
                    self.assertEqual(self.security_calls(), [])
                    self.assertEqual(self.k.files[str(path)]['owner'], owner)
                    self.k.files[str(path)] = {}

    def test_system_owned_directory_outside_state_never_repaired(self):
        path = self.root / 'outside-directory'
        path.mkdir()
        for owner in (ADMIN, SYSTEM):
            with self.subTest(system=owner == SYSTEM):
                self.k.files[str(path)] = {'owner': owner, 'protected': False}
                with self.assertRaisesRegex(OSError, 'windows_owner_mismatch'):
                    self.p.files.ensure_private_dir(path)
                self.assertEqual(self.security_calls(), [])
                self.assertEqual(self.k.files[str(path)]['owner'], owner)

    def test_failed_set_owner_never_records_observation_or_success_log(self):
        leaf = self.state / 'set-owner-failed'
        leaf.touch()
        for directory in (False, True):
            path = self.state if directory else leaf
            with self.subTest(directory=directory):
                self.k.files[str(path)] = {'owner': ADMIN, 'protected': False}
                self.k.faults['SetSecurityInfo'] = 1307
                before = len(self.security_calls())
                with self.assertNoLogs('agentstatus_bridge.platforms.windows.files', level='WARNING'):
                    with self.assertRaises(OSError) as caught:
                        if directory:
                            self.p.files.ensure_private_dir(path)
                        else:
                            self.p.files.validate_file(path)
                self.assertEqual(caught.exception.winerror, 1307)
                self.assertEqual([args[2] for args in self.security_calls()[before:]], [1])
                self.assertEqual(self.k.files[str(path)]['owner'], ADMIN)
                self.assertFalse(self.p.files.acl_repaired)
                self.assertEqual(self.p.files.repair_reasons, set())
                self.assertFalse((self.state / 'acl-repair.json').exists())
                self.k.files[str(path)] = {}
                self.k.faults.pop('SetSecurityInfo')

    def test_partial_owner_restore_keeps_observation_without_repaired_log(self):
        leaf = self.state / 'partial-log'
        leaf.touch()
        for directory in (False, True):
            path = self.state if directory else leaf
            with self.subTest(directory=directory):
                self.k.files[str(path)] = {'owner': ADMIN, 'private': False, 'protected': False}
                with self.assertNoLogs('agentstatus_bridge.platforms.windows.files', level='WARNING'):
                    with patch.object(self.k.api, 'repair_private', side_effect=WinFailure(5)):
                        with self.assertRaises(OSError):
                            if directory:
                                self.p.files.ensure_private_dir(path)
                            else:
                                self.p.files.validate_file(path)
                self.assertEqual(self.k.files[str(path)]['owner'], self.k.sid)
                self.assertTrue(self.p.files.acl_repaired)
                self.assertIn('owner_administrators', self.p.files.repair_reasons)
                self.assertFalse((self.state / 'acl-repair.json').exists())
                self.k.files[str(path)] = {}

    def test_doctor_success_has_no_storage_subreason(self):
        with ExitStack() as stack:
            stack.enter_context(patch.object(doctor, 'daemon_diagnostic', return_value={'cliVersion': 'unknown'}))
            stack.enter_context(patch.object(doctor, 'caller_diagnostic', return_value={}))
            stack.enter_context(patch('agentstatus_bridge.platforms.windows.commands.claude_evidence',
                return_value=SimpleNamespace(complete=True, reason='complete', endpoints=(), root_diagnostics=(), registries=())))
            checks = doctor.collect_checks()
        self.assertTrue(checks['ledgerReadable'])
        self.assertNotIn('storageReason', checks)
        self.assertNotIn('storageSubreason', checks)

    def test_invalid_owner_winerror_is_a_closed_subreason(self):
        error = StoreError('store_unavailable')
        error.__cause__ = WinFailure(1307)
        self.assertEqual(doctor.storage_subreason(error), 'winerror_1307')

    def test_storage_causes_have_chinese_print_labels(self):
        output = io.StringIO()
        with redirect_stdout(output):
            doctor.print_checks({'storageReason': 'windows_storage_unverified',
                                 'storageSubreason': 'winerror_1307'})
        self.assertEqual(output.getvalue(), '存储状态原因：windows_storage_unverified\n存储故障子原因：winerror_1307\n')


if __name__ == '__main__':
    unittest.main()
