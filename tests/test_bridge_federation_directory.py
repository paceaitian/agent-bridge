"""P5 端点目录与远端寻址（DESIGN §88.6）：根绑定、整帧目录预算、名字只在已验证且唯一时可用。"""

from __future__ import annotations

import json
import os
from dataclasses import replace
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import bridge_support  # noqa: F401  导入即隔离宿主会话环境

from types import SimpleNamespace

from agentstatus_bridge import endpoints as endpoint_module
from agentstatus_bridge.federation import commands, directory
from agentstatus_bridge.federation.directory import DirectoryError
from agentstatus_bridge.federation.fedstore import FederatedStore
from agentstatus_bridge.federation.refs import RemoteEndpointRef
from agentstatus_bridge.model import EndpointRef, Provider
from agentstatus_bridge.observer_dbus import ObserverView
from bridge_support import endpoint, ref

DEV_A = "a" * 32
DEV_B = "b" * 32
THREAD = "019a0000-1111-7222-8333-44445555bbbb"


def row(native: str, name: str | None = None, *, verified: bool = True, inbox: bool = True,
        provider: str = "codex") -> dict[str, object]:
    item: dict[str, object] = {"provider": provider, "nativeId": native, "endpointId": native[-8:].ljust(32, "0"),
                               "endpointRevision": 1, "inbox": inbox, "eligible": True, "namesVerified": verified}
    if name:
        item["name"] = name
    return item


class DirectoryCase(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.root = Path(self._tmp.name)
        self.store = FederatedStore.create(self.root / "vm")
        self.addCleanup(self.store.close)
        self.store.set_meta("deviceId", DEV_A)

    def put(self, *rows: dict[str, object], name: str = "win") -> None:
        self.store.put_device_state(device_id=DEV_B, name=name, revision=1,
                                    snapshot={"endpoints": list(rows), "complete": True, "providers": {}},
                                    last_seen=None, state="unknown")


class ResolveTests(DirectoryCase):
    def test_exact_id_and_verified_unique_name(self) -> None:
        self.put(row(THREAD, "impl"))
        self.assertEqual(directory.resolve_remote(self.store, "win", f"codex@id:{THREAD}").remote.native_id, THREAD)
        self.assertEqual(directory.resolve_remote(self.store, DEV_B, "codex@impl").remote.device_id, DEV_B)
        with self.assertRaises(DirectoryError) as caught:
            directory.resolve_remote(self.store, "win", "codex@id:019a0000")  # 前缀不是精确 ID，也不按名字猜
        self.assertEqual(caught.exception.code, "remote_endpoint_unresolved")

    def test_unverified_names_ambiguity_and_no_inbox(self) -> None:
        other = THREAD.replace("b", "c")
        self.put(row(THREAD, "impl", verified=False))
        with self.assertRaises(DirectoryError) as caught:
            directory.resolve_remote(self.store, "win", "codex@impl")
        self.assertEqual(caught.exception.code, "target_names_unverified")
        self.put(row(THREAD, "impl"), row(other, "impl"))
        with self.assertRaises(DirectoryError) as caught:
            directory.resolve_remote(self.store, "win", "codex@impl")
        self.assertEqual(caught.exception.code, "target_ambiguous")
        self.assertEqual(set(caught.exception.candidates), {f"codex@id:{THREAD}", f"codex@id:{other}"})
        self.put(row(THREAD, "grok", inbox=False, provider="grok"))
        with self.assertRaises(DirectoryError) as caught:
            directory.resolve_remote(self.store, "win", f"grok@id:{THREAD}")
        self.assertEqual(caught.exception.code, "target_no_inbox")
        with self.assertRaises(DirectoryError) as caught:
            directory.resolve_remote(self.store, "nowhere", "codex@impl")
        self.assertEqual(caught.exception.code, "device_unknown")


class CompletenessTests(DirectoryCase):
    def test_names_need_a_complete_directory_but_exact_ids_do_not(self) -> None:
        self.store.put_device_state(device_id=DEV_B, name="win", revision=1, snapshot={
            "endpoints": [row(THREAD, "impl")], "complete": False, "providers": {"codex": False}},
            last_seen=None, state="unknown")
        self.assertEqual(directory.resolve_remote(self.store, "win", f"codex@id:{THREAD}").remote.native_id, THREAD)
        for selector in ("codex@impl", "impl"):
            with self.assertRaises(DirectoryError) as caught:
                directory.resolve_remote(self.store, "win", selector)  # 没收齐的同名端点无法参与消歧
            self.assertEqual(caught.exception.code, "remote_directory_incomplete")

    def test_unverifiable_root_is_left_out_and_marks_the_snapshot_incomplete(self) -> None:
        live = endpoint(ref(Provider.CODEX, THREAD, pid=4242), name="impl")
        with patch.object(directory, "root_binding", return_value=None):
            document = directory.snapshot(self.store, DEV_A, [live], provider_complete={"codex": True})
        self.assertEqual((document["endpoints"], document["complete"], document["reason"]),
                         ([], False, "root_unverified"))


class LinuxPublisherTests(DirectoryCase):
    """Linux 目录发布按本轮实际采样的完整性，而不是平台能力常量（Codex r2-P2-06）。"""

    def collect(self, *, denied: bool) -> dict[str, object]:
        claude = self.root / "claude"
        claude.mkdir()
        proc = self.root / "proc"
        proc.mkdir()
        sources = endpoint_module.DiscoverySources(
            proc_root=proc, claude_sessions=claude, codex_home=self.root / "codex", grok_home=self.root / "grok",
            panes=lambda: {}, titles=lambda: {}, runtime=lambda: ObserverView())
        runtime = SimpleNamespace(store=self.store, ident=SimpleNamespace(device_id=DEV_A),
                                  config=SimpleNamespace(publish_names=True))
        real_iterdir = Path.iterdir
        seen: list[Path] = []

        def iterdir(path: Path):  # noqa: ANN202 - 与 Path.iterdir 同签名
            if denied and path == claude:
                seen.append(path)
                raise PermissionError("synthetic registry denied")
            return real_iterdir(path)

        with patch.object(Path, "iterdir", iterdir), patch.object(commands, "DiscoverySources", return_value=sources):
            snapshot = commands.directory_source(runtime)()  # type: ignore[arg-type]
        self.assertEqual(bool(seen), denied)  # 注入的读失败确实走到了
        return snapshot

    def test_unreadable_registry_marks_that_provider_incomplete(self) -> None:
        snapshot = self.collect(denied=True)
        self.assertFalse(snapshot["complete"])
        self.assertEqual(snapshot["providers"], {"claude": False, "codex": True, "grok": True})  # type: ignore[index]

    def test_fully_read_empty_sample_is_complete(self) -> None:
        snapshot = self.collect(denied=False)
        self.assertTrue(snapshot["complete"])


class DiscoveryCompletenessTests(unittest.TestCase):
    """Linux 发现记录本轮没看全的 provider：读失败与预算截断算没看全，不存在的根与确定无效的记录不算。"""

    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.claude = self.root / "claude"
        self.claude.mkdir()
        self.grok = self.root / "grok"
        self.grok.mkdir()
        (self.root / "proc").mkdir()

    def discover(self, **overrides: object) -> endpoint_module.DiscoverySources:
        values: dict[str, object] = dict(proc_root=self.root / "proc", claude_sessions=self.claude,
                                         codex_home=self.root / "codex", grok_home=self.grok,
                                         panes=lambda: {}, titles=lambda: {}, runtime=lambda: ObserverView())
        values.update(overrides)
        sources = endpoint_module.DiscoverySources(**values)  # type: ignore[arg-type]
        sources.incomplete.add("stale")  # 上一轮的结果：每次发现开始时清空
        endpoint_module.discover(sources)
        return sources

    def test_absent_sources_and_invalid_records_are_still_complete(self) -> None:
        (self.claude / "123.json").write_text("{not json", encoding="utf-8")
        sources = self.discover(claude_sessions=self.root / "no-such-root")
        self.assertTrue(sources.complete())
        sources = self.discover()
        self.assertTrue(sources.complete())  # 确定无效的单条记录照常跳过

    def test_registry_budget_truncation_is_incomplete(self) -> None:
        for pid in (101, 102):
            (self.claude / f"{pid}.json").write_text("{}", encoding="utf-8")
        with patch.object(endpoint_module, "MAX_REGISTRY_FILES", 1):
            sources = self.discover()
        self.assertEqual((sources.provider_complete(Provider.CLAUDE), sources.provider_complete(Provider.CODEX)),
                         (False, True))

    def test_unreadable_registry_file_is_incomplete_but_vanished_file_is_not(self) -> None:
        record = self.claude / "123.json"
        record.write_text("{}", encoding="utf-8")
        real_read = Path.read_text

        def read(path: Path, *args: object, **kwargs: object) -> str:
            if path == record:
                raise error
            return real_read(path, *args, **kwargs)  # type: ignore[arg-type]

        for error, complete in ((PermissionError("denied"), False), (FileNotFoundError("gone"), True)):
            with patch.object(Path, "read_text", read):
                sources = self.discover()
            self.assertEqual(sources.provider_complete(Provider.CLAUDE), complete, repr(error))

    def test_grok_registry_absent_is_complete_but_unparsable_is_not(self) -> None:
        self.assertTrue(self.discover().provider_complete(Provider.GROK))
        (self.grok / "active_sessions.json").write_text("[{", encoding="utf-8")
        self.assertFalse(self.discover().provider_complete(Provider.GROK))

    def test_unlistable_proc_marks_every_provider_incomplete(self) -> None:
        sources = self.discover(proc_root=self.root / "no-proc")
        self.assertEqual(sources.incomplete, {provider.value for provider in Provider})


class RemoteIdentityTests(unittest.TestCase):
    def test_same_uuid_on_two_devices_is_not_the_same_endpoint(self) -> None:
        here = RemoteEndpointRef(device_id=DEV_A, provider=Provider.CODEX, native_id=THREAD, endpoint_id="e" * 32,
                                 endpoint_revision=1)
        self.assertFalse(here.same_endpoint(replace(here, device_id=DEV_B)))
        self.assertTrue(here.same_endpoint(replace(here, endpoint_revision=2, display_label="改名")))  # label 不参与


class SnapshotTests(DirectoryCase):
    def test_minimal_public_rows_and_name_publishing_switch(self) -> None:
        live = endpoint(ref(Provider.CODEX, THREAD, pid=4242, pane="%3", label="impl"), name="impl")
        document = directory.snapshot(self.store, DEV_A, [live], provider_complete={"codex": True})
        [item] = document["endpoints"]
        self.assertEqual(set(item), {"provider", "nativeId", "endpointId", "endpointRevision", "inbox", "eligible",
                                     "namesVerified", "name"})
        self.assertTrue(document["complete"])
        self.assertNotIn("4242", json.dumps(document))  # 不发 PID/pane
        hidden = directory.snapshot(self.store, DEV_A, [live], publish_names=False)
        self.assertNotIn("name", hidden["endpoints"][0])
        self.assertFalse(hidden["endpoints"][0]["namesVerified"])
        # 同一根上重复采样：endpointId 稳定
        self.assertEqual(hidden["endpoints"][0]["endpointId"], item["endpointId"])

    def test_budgets_mark_incomplete_instead_of_truncating_silently(self) -> None:
        many = [endpoint(ref(Provider.CODEX, f"019a0000-0000-7000-8000-{index:012d}", pid=1000 + index))
                for index in range(directory.MAX_ENDPOINTS + 2)]
        document = directory.snapshot(self.store, DEV_A, many)
        self.assertEqual((len(document["endpoints"]), document["complete"], document["reason"]),
                         (directory.MAX_ENDPOINTS, False, "too_many_endpoints"))
        partial = directory.snapshot(self.store, DEV_A, many[:1], provider_complete={"claude": False})
        self.assertFalse(partial["complete"])  # 一个 provider 不完整就不是完整目录


class RootBindingTests(unittest.TestCase):
    def test_claude_binding_follows_the_root_that_holds_the_registry(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            first, second = Path(tmp) / "one", Path(tmp) / "two"
            first.mkdir()
            second.mkdir()
            session = "0000000a-1111-4222-8333-444444444444"
            (second / "4242.json").write_text(json.dumps({"sessionId": session, "pid": 4242, "procStart": "1"}),
                                              encoding="utf-8")
            live = EndpointRef(provider=Provider.CLAUDE, native_id=session, pid=4242, start_ticks="1")
            with patch.object(directory, "claude_sessions_dirs", return_value=[first, second]):
                bound = directory.root_binding(live)
            self.assertEqual(bound, directory._digest_path(second))  # pyright: ignore[reportPrivateUsage]
            with patch.object(directory, "claude_sessions_dirs", return_value=[second]):
                self.assertEqual(directory.root_binding(live), bound)
            with patch.object(directory, "claude_sessions_dirs", return_value=[first]):
                self.assertIsNone(directory.root_binding(live))  # 核实不了：不给常量冒充绑定
            other = EndpointRef(provider=Provider.CLAUDE, native_id="0000000b-1111-4222-8333-444444444444", pid=4242,
                                start_ticks="1")
            with patch.object(directory, "claude_sessions_dirs", return_value=[second]):
                self.assertIsNone(directory.root_binding(other))  # 注册记录不是这个会话

    def test_stale_registry_of_an_older_generation_does_not_bind(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            old, new = Path(tmp) / "old", Path(tmp) / "new"
            old.mkdir()
            new.mkdir()
            session = "0000000a-1111-4222-8333-444444444444"
            for root, start in ((old, "111"), (new, "777")):  # 同 PID 同会话：旧根是上一代进程的残留
                (root / "4242.json").write_text(json.dumps({"sessionId": session, "pid": 4242, "procStart": start}),
                                                encoding="utf-8")
            live = EndpointRef(provider=Provider.CLAUDE, native_id=session, pid=4242, start_ticks="777")
            with patch.object(directory, "claude_sessions_dirs", return_value=[old, new]):
                self.assertEqual(directory.root_binding(live), directory._digest_path(new))  # pyright: ignore[reportPrivateUsage]

    def test_codex_binding_changes_with_codex_home(self) -> None:
        live = EndpointRef(provider=Provider.CODEX, native_id=THREAD, pid=1, start_ticks="1")
        with tempfile.TemporaryDirectory() as tmp:
            with patch.dict(os.environ, {"CODEX_HOME": str(Path(tmp) / "a")}):
                first = directory.root_binding(live)
            with patch.dict(os.environ, {"CODEX_HOME": str(Path(tmp) / "b")}):
                self.assertNotEqual(directory.root_binding(live), first)


if __name__ == "__main__":
    unittest.main()
