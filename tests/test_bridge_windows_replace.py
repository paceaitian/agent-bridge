"""Occupied-target retry via SDK Fake and virtual time; never launches Windows."""
from contextlib import contextmanager
import os
from unittest.mock import Mock, patch
import unittest

import test_bridge_windows_delivery as F
from test_bridge_windows_discovery import uuid
from agentstatus_bridge import cli
from agentstatus_bridge.model import Delivery
from agentstatus_bridge.store import Store
from agentstatus_bridge.platforms.windows import api as A, worker_identity as W
from agentstatus_bridge.platforms.windows.private_file import pinned_file


class ReplaceTests(unittest.TestCase):
    setUp = F.DeliveryTests.setUp
    rebuild = F.DeliveryTests.rebuild
    scope = F.DeliveryTests.scope
    chain = F.DeliveryTests.chain
    run_cli = F.DeliveryTests.run_cli

    @contextmanager
    def clock(self, on_sleep=lambda _: None):
        now = [0.0]
        sleeps = []
        def sleep(seconds):
            sleeps.append(seconds)
            if seconds <= 0 or len(sleeps) > 200:
                raise AssertionError('replace retry must make bounded forward progress')
            now[0] += seconds
            # A mutation must fail by assertion, not hang until outer timeout.
            if now[0] > 20:
                raise AssertionError('unbounded replace retry')
            on_sleep(now[0])
        with patch.object(A, 'monotonic', side_effect=lambda: now[0]), patch.object(A, 'sleep', side_effect=sleep):
            yield now, sleeps

    def test_occupied_destination_all_shares_and_metadata_handles_fail_five(self):
        source, dest = self.root/'new', self.root/'old'
        source.write_bytes(b'new'); dest.write_bytes(b'old')
        for sharing in (3, 7):
            for metadata in (False, True):
                with self.k.api.owned(self.k.api.open_file(str(dest), sharing=sharing, metadata_only=metadata)):
                    with self.clock() as (now, sleeps):
                        with self.assertRaises(OSError) as caught:
                            self.k.api.replace(str(source), str(dest))
                    self.assertEqual(caught.exception.winerror, 5)
                    self.assertAlmostEqual(now[0], 2.0)
                    self.assertEqual(sleeps[:4], [0.02, 0.04, 0.08, 0.16])
                    self.assertTrue(all(0 < s <= 0.16 for s in sleeps))
                    self.assertEqual(dest.read_bytes(), b'old')
                    self.assertTrue(source.exists())

    def test_reader_released_within_budget_allows_atomic_write_and_rotation(self):
        with self.scope():
            for rotation in (False, True):
                name = 'worker.log.1' if rotation else W.RECEIPT
                self.p.files.atomic_write(self.state, b'old', name=name, prefix='.first.')
                dest = self.state/name
                if rotation:
                    self.p.files.atomic_write(self.state, b'long-log', name='worker.log', prefix='.log.')
                reader = self.k.api.open_file(str(dest), read_data=True, sharing=7)
                def release(now):
                    if now >= .14 and reader in self.k.handles:
                        self.k.api.close(reader)
                error = None
                try:
                    with self.clock(release) as (now, _):
                        try:
                            if rotation: self.p.files.append_log(self.state/'worker.log', b'next', 2)
                            else: self.p.files.atomic_write(self.state, b'new', name=name, prefix='.next.')
                        except OSError as exc: error = exc
                    self.assertIsNone(error)
                    self.assertGreaterEqual(now[0], .14)
                    self.assertLess(now[0], 2.0)
                    self.assertEqual(dest.read_bytes(), b'long-log' if rotation else b'new')
                finally:
                    if reader in self.k.handles: self.k.api.close(reader)

    def test_only_five_and_thirty_two_retry_and_original_error_is_preserved(self):
        for code in (5, 32, 2, 3, 6, 87):
            self.k.faults['MoveFileExW'] = code
            before = sum(n == 'MoveFileExW' for n, _ in self.k.calls)
            with self.clock() as (now, sleeps):
                with self.assertRaises(A.WinFailure) as caught:
                    self.k.api.replace(str(self.root/'new'), str(self.root/'old'))
            self.assertEqual(caught.exception.winerror, code)
            count = sum(n == 'MoveFileExW' for n, _ in self.k.calls) - before
            self.assertEqual(now[0], 2.0 if code in (5,32) else 0.0)
            self.assertEqual(count, len(sleeps)+1)
            self.assertEqual(bool(sleeps), code in (5,32))
        self.k.faults.clear()

    def test_registration_timeout_cli_six_and_later_status_restarts(self):
        binary = self.root/'python.exe'; binary.touch(); self.k.images[100] = str(binary)
        env = self.chain(); self.k.loaded = [uuid(1), uuid(2)]
        spawned, failures = [], []
        def spawn(argv, directory, launch):
            spawned.append(1)
            with patch.dict(os.environ, launch):
                try: W.register(self.p.files, directory)
                except OSError as exc: failures.append(exc.winerror)
            return Mock(pid=100)
        with (self.scope(), patch.dict(os.environ, env), patch.object(W, 'executable', return_value=binary),
              patch('agentstatus_bridge.platforms.windows.caller.os.getpid', return_value=100),
              patch.object(self.p.lifecycle, '_spawn', side_effect=spawn), self.clock() as (now, _),
              patch('time.monotonic', side_effect=lambda: now[0]),
              patch('time.sleep', side_effect=lambda seconds: now.__setitem__(0, now[0]+seconds)),
              patch.object(cli, '_worker_ensured', False)):
            W.register(self.p.files, self.state)
            with pinned_file(self.p.files, self.state/W.RECEIPT, share_delete=True):
                # Isolate the first launch; main's normal final revive would
                # attempt another identical launch while the reader still holds.
                with patch.object(cli, '_revive_worker'):
                    code, _, _ = self.run_cli('send', '--to', uuid(2), '-m', 'fixture', '--no-wait', '--json')
                self.assertEqual(code, 6)
                self.assertEqual(failures, [5])
                self.assertEqual(len(spawned), 1)
                with Store.open(self.state) as store:
                    task = store.list_tasks()[0]
                    self.assertIs(store.attempts(task.id)[0].delivery, Delivery.PENDING)
            code, _, _ = self.run_cli('status', task.id, '--json')
            self.assertEqual(code, 0)
            self.assertEqual(len(spawned), 2)
            self.assertEqual(failures, [5])
            self.assertEqual(W.verify(self.p.files, self.state)['pid'], 100)
            self.assertFalse(list(self.state.glob('.worker.*')))


if __name__ == '__main__': unittest.main()
