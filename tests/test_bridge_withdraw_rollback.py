"""V70-08：固定旧release通过git archive验证；不复制/修改旧实现，不接触真实端点。"""
from __future__ import annotations

import io
from contextlib import contextmanager
import json
import os
from pathlib import Path
import subprocess
import sys
import tarfile
import textwrap
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from bridge_support import LedgerCase, ref
from agentstatus_bridge.model import Delivery
from agentstatus_bridge.store import Store
from agentstatus_bridge.platforms.linux import process as procfs
from agentstatus_bridge.transports import local_codex

OLD = "87eff52af368938fd51b491db936f1de5ac72bc4"  # b3e4198^，尚未实现§69/70
CURRENT_OLD = "dc3b61b"  # §73部署前现役，已经实现§69/70，尚无命名空间列
THREAD = "019a0000-0000-7000-8000-000000000001"
ITEM = "019a0000-0000-7000-8000-000000000002"


class WithdrawalRollbackTests(LedgerCase):
    @contextmanager
    def current_old_source(self):
        repo = Path(__file__).resolve().parents[1]
        if subprocess.run(["git", "cat-file", "-e", f"{CURRENT_OLD}:src"], cwd=repo, capture_output=True).returncode:
            self.skipTest("fixed current release source unavailable in this checkout (mirror)")
        archive = subprocess.run(["git", "archive", CURRENT_OLD, "src"], cwd=repo, capture_output=True, check=True).stdout
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            with tarfile.open(fileobj=io.BytesIO(archive)) as source:
                source.extractall(root, filter="data")
            yield root

    def run_current_old(self, source, state, home, code, *args):
        tests = Path(__file__).resolve().parent
        preamble = '''
import contextlib, io, json, os, sys
from pathlib import Path
from unittest.mock import patch
import bridge_support
fixture_environment = json.loads(sys.argv.pop(1))
with patch.dict(os.environ, fixture_environment):
'''
        context = '''
from bridge_support import ref
from agentstatus_bridge import cli
from agentstatus_bridge.endpoints import Caller
from agentstatus_bridge.model import Delivery, Flow
from agentstatus_bridge.store import Store
from agentstatus_bridge.transports.codex_withdraw import QueueDeleteClient, DeleteResult
root = Path(os.environ["AB_STATE_DIR"])
'''
        fixture_environment = {"AB_STATE_DIR": str(state), "CODEX_HOME": str(home), "CODEX_SQLITE_HOME": str(home)}
        runner = {key: value for key, value in os.environ.items() if key in {
            'TMPDIR', 'TMP', 'TEMP', 'XDG_RUNTIME_DIR', 'DBUS_SESSION_BUS_ADDRESS',
            'DBUS_SYSTEM_BUS_ADDRESS', 'TMUX_TMPDIR', 'LANG'}}
        runner.update(PATH=os.environ.get("PATH", "/usr/bin:/bin"), HOME=str(source),
                      PYTHONPATH=str(source / "src") + os.pathsep + str(tests), PYTHONDONTWRITEBYTECODE="1")
        result = subprocess.run([sys.executable, "-c", preamble + textwrap.indent(context + code, '    '),
                                 json.dumps(fixture_environment), *args], cwd=source, env=runner,
            capture_output=True, text=True, timeout=15)
        self.assertEqual(result.returncode, 0, result.stderr)
        return json.loads(result.stdout)

    def test_current_release_reads_again_prunes_and_new_reads_null_namespace(self):
        home = self.root.parent / "rollback-home"
        home.mkdir()
        stamp = local_codex.platform().root_identity(home)
        assert stamp is not None
        pairs = []
        for i in (1, 3):
            thread, item = f"019a0000-0000-7000-8000-{i:012x}", f"019a0000-0000-7000-8000-{i + 1:012x}"
            task, attempt = self.create(target=ref(native=thread))
            self.store.begin_send(attempt.id, now=100, pid=1, start_ticks="1")
            self.store.finish_send(attempt.id, delivery=Delivery.QUEUED, reason="codex_queued", provider_ref=item,
                                   detail={}, native_root=stamp, now=101)
            operation, _ = self.store.prepare_withdrawal(task.id, 1, root_identity=stamp, now=102, pid=1, start="1")
            self.store.finish_withdrawal(operation["id"], thread=thread, item=item, state="unknown" if i == 1 else "deleted",
                                        reason="owner_timeout" if i == 1 else "deleted", version="0.162.1", now=103)
            pairs.append((task, attempt))
        self.store.update_task(pairs[1][0].id, now=200, event="closed", closed_at=200)
        with self.current_old_source() as source:
            doc = self.run_current_old(source, self.root, home, '''
def fake_delete(home, **kwargs):
    kwargs["before_send"]()
    return DeleteResult("deleted", "deleted", "0.162.1")
result = {}
with patch.object(cli, "discover", return_value=[]), patch.object(cli, "identify_caller", return_value=Caller(None,None)), patch.object(cli, "_refresh_summary"), patch.object(QueueDeleteClient, "delete", side_effect=fake_delete):
    for key, argv in (("status", ["status", sys.argv[1], "--json"]), ("again", ["withdraw", sys.argv[1], "--attempt", "1", "--again", "--json"]), ("retry", ["retry", sys.argv[1]])):
        output = io.StringIO()
        with contextlib.redirect_stdout(output), contextlib.redirect_stderr(output):
            rc = cli.main(argv)
        result[key] = {"rc": rc, "doc": json.loads(output.getvalue())} if key != "retry" else {"rc": rc, "force": "--force" in output.getvalue()}
with Store.open(root) as store:
    result["pruned"] = store.prune(now=200 + 40 * 86400)
    result["remaining"] = [tuple(row) for row in store._conn.execute("SELECT state,owner_pid_namespace IS NULL FROM native_withdrawals ORDER BY created_at,rowid")]
print(json.dumps(result))
''', pairs[0][0].id)
        self.assertEqual(doc["status"]["rc"], 0)
        self.assertEqual(doc["status"]["doc"]["nativeWithdrawals"]["operations"][0]["state"], "unknown")
        self.assertEqual(doc["again"]["rc"], 0)
        self.assertEqual(doc["again"]["doc"]["operation"]["state"], "deleted")
        self.assertEqual(doc["retry"], {"rc": 3, "force": True})
        self.assertEqual(doc["pruned"], 1)
        self.assertEqual(doc["remaining"], [["unknown", 0], ["deleted", 1]])
        with Store.open(self.root) as reopened:
            self.assertTrue(reopened.withdrawals_readable)
            self.assertEqual([row["state"] for row in reopened.withdrawals(pairs[0][0].id)], ["unknown", "deleted"])
            attempt = reopened.get_attempt(pairs[0][1].id)
            self.assertIsNotNone(attempt)
            assert attempt is not None
            self.assertEqual(attempt.delivery, Delivery.QUEUED)

    def test_current_release_first_then_column_upgrade_preserves_revision(self):
        home = self.root.parent / "old-first-home"
        home.mkdir()
        state = self.root.parent / "old-first-state"
        with self.current_old_source() as source:
            doc = self.run_current_old(source, state, home, '''
with Store.open(root) as store:
    task, attempt = store.create_task(title="synthetic", flow=Flow.HANDOFF, origin=None, origin_class=None, reviewer=None,
        target=ref(native=sys.argv[1]), body="synthetic", refs=[], now=100)
    store.begin_send(attempt.id, now=101, pid=1, start_ticks="1")
    store.finish_send(attempt.id, delivery=Delivery.QUEUED, reason="codex_queued", provider_ref=sys.argv[2], detail={}, now=102, native_root="a"*64)
    store.prepare_withdrawal(task.id, 1, root_identity="a"*64, now=103, pid=999999, start="1")
    print(json.dumps({"task": task.id, "revision": store.ledger_revision(), "columns": [row[1] for row in store._conn.execute("PRAGMA table_info(native_withdrawals)")]}))
''', THREAD, ITEM)
            self.assertNotIn("owner_pid_namespace", doc["columns"])
            with Store.open(state) as upgraded:
                self.assertIn("owner_pid_namespace", [row[1] for row in upgraded._conn.execute("PRAGMA table_info(native_withdrawals)")])
                self.assertEqual(list(upgraded.ledger_revision()), doc["revision"], "只补列不改业务修订号")
                self.assertIsNone(upgraded._conn.execute("SELECT owner_pid_namespace FROM native_withdrawals").fetchone()[0])
                with patch.object(procfs, "read_process", return_value=None):
                    upgraded.recover_withdrawals(now=110)
                self.assertEqual(upgraded.withdrawals(doc["task"])[0]["state"], "not_attempted")
                self.assertEqual(upgraded.withdrawals(doc["task"])[0]["reason"], "owner_gone")
                revision = upgraded.ledger_revision()
            old_again = self.run_current_old(source, state, home, '''
with Store.open(root) as store:
    print(json.dumps({"state":store.withdrawals(sys.argv[1])[0]["state"], "revision":store.ledger_revision()}))
''', doc["task"])
            self.assertEqual(old_again, {"state": "not_attempted", "revision": list(revision)})
            with Store.open(state) as reopened:
                self.assertEqual(reopened.ledger_revision(), revision)

    def test_old_release_reads_writes_and_retry_still_needs_force(self):
        repo = Path(__file__).resolve().parents[1]
        check = subprocess.run(["git", "cat-file", "-e", f"{OLD}:src"], cwd=repo, capture_output=True)
        if check.returncode:
            # 镜像没有源仓库历史；source core必须实际执行，交付时单列这道门。
            self.skipTest("fixed old source unavailable in this checkout (mirror)")
        archive = subprocess.run(["git", "archive", OLD, "src"], cwd=repo, capture_output=True, check=True).stdout
        task, attempt = self.create(target=ref(native=THREAD))
        self.store.begin_send(attempt.id, now=100, pid=1, start_ticks="1")
        self.store.finish_send(attempt.id, delivery=Delivery.QUEUED, reason="codex_queued", provider_ref=ITEM,
                               detail={}, native_root="a" * 64, now=101)
        operation, _ = self.store.prepare_withdrawal(task.id, 1, root_identity="a" * 64, now=102, pid=1, start="1")
        self.store.finish_withdrawal(operation["id"], thread=THREAD, item=ITEM, state="deleted", reason="deleted",
                                    version="0.162.1", now=103)
        revision = self.store.ledger_revision()[1]
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            with tarfile.open(fileobj=io.BytesIO(archive)) as source:
                source.extractall(root, filter="data")
            code = '''
import contextlib, io, json, sys
from pathlib import Path
from unittest.mock import patch
from agentstatus_bridge import cli
from agentstatus_bridge.endpoints import Caller
from agentstatus_bridge.store import Store
output = io.StringIO()
with patch.object(cli, "discover", return_value=[]), patch.object(cli, "identify_caller", return_value=Caller(None,None)), patch.object(cli, "_refresh_summary"), contextlib.redirect_stdout(output), contextlib.redirect_stderr(output):
    status = cli.main(["retry", sys.argv[2]])
with Store.open(Path(sys.argv[1])) as store:
    delivery = store.get_attempt(sys.argv[3]).delivery.value
    store.update_task(sys.argv[2], now=104, event="rollback_fixture", control="paused")
    states = [row[0] for row in store._conn.execute("SELECT state FROM native_withdrawals")]
print(json.dumps({"status":status,"force":"--force" in output.getvalue(),"delivery":delivery,"states":states}))
'''
            result = subprocess.run([sys.executable, "-c", code, str(self.root), task.id, attempt.id], cwd=root,
                env={"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "HOME": str(root),
                     "AB_STATE_DIR": str(self.root), "PYTHONPATH": str(root / "src"),
                     "CODEX_HOME": str(root / "codex"), "PYTHONDONTWRITEBYTECODE": "1"},
                capture_output=True, text=True, timeout=15)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(json.loads(result.stdout), {"status": 3, "force": True, "delivery": "queued", "states": ["deleted"]})
        with Store.open(self.root) as reopened:
            self.assertEqual(reopened.get_task(task.id).control, "paused")
            self.assertGreater(reopened.ledger_revision()[1], revision)
            self.assertEqual(reopened.withdrawals(task.id)[0]["state"], "deleted")


if __name__ == "__main__":
    unittest.main()
