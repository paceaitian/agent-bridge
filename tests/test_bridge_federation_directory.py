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
from agentstatus_bridge.federation.codec import canonical_bytes
from agentstatus_bridge.federation.directory import DirectoryError
from agentstatus_bridge.federation.fedstore import FederatedStore
from agentstatus_bridge.federation.refs import RemoteEndpointRef
from agentstatus_bridge.model import EndpointRef, Provider
from agentstatus_bridge.observer_dbus import ObserverView
import bridge_legacy_directory_104f286 as legacy
from bridge_support import endpoint, ref, with_name_views

DEV_A = "a" * 32
DEV_B = "b" * 32
THREAD = "019a0000-1111-7222-8333-44445555bbbb"
NOW = 1_800_000_000_000


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

    def put(self, *rows: dict[str, object], name: str = "win", fresh: bool = True,
            policy: str | None = directory.NAME_POLICY) -> None:
        """写入 B 的缓存目录：默认新版名字策略、相关 provider 明确完整、hub 报在线且刚收到（§91.2.2 的门都满足）。"""
        snapshot: dict[str, object] = {"endpoints": list(rows), "complete": True,
                                       "providers": {str(item["provider"]): True for item in rows}}
        if policy is not None:
            snapshot["namePolicy"] = policy
        self.store.put_device_state(device_id=DEV_B, name=name, revision=1, snapshot=snapshot,
                                    last_seen=NOW if fresh else None, state="online" if fresh else "unknown")

    def code(self, selector: str, device: str = "win") -> str:
        with self.assertRaises(DirectoryError) as caught:
            directory.resolve_remote(self.store, device, selector, now=NOW)
        return caught.exception.code


class ResolveTests(DirectoryCase):
    def test_exact_id_and_verified_unique_name(self) -> None:
        self.put(row(THREAD, "impl"))
        self.assertEqual(directory.resolve_remote(self.store, "win", f"codex@id:{THREAD}", now=NOW).remote.native_id,
                         THREAD)
        resolved = directory.resolve_remote(self.store, DEV_B, "codex@impl", now=NOW).remote
        self.assertEqual((resolved.device_id, resolved.display_label), (DEV_B, "impl"))
        # 显式 id: 前缀在目录完整且新鲜时可用（§91.2.2）；名字未命中不改按前缀找，裸名字必须带 provider
        self.assertEqual(directory.resolve_remote(self.store, "win", "codex@id:019a0000", now=NOW).remote.native_id,
                         THREAD)
        self.assertEqual(self.code("codex@019a0000"), "remote_endpoint_unresolved")
        self.assertEqual(self.code("impl"), "target_provider_required")
        # 不新鲜：完整 ID 照样精确匹配，前缀与名字都拒绝
        self.put(row(THREAD, "impl"), fresh=False)
        self.assertEqual(directory.resolve_remote(self.store, "win", f"codex@id:{THREAD}", now=NOW).remote.native_id,
                         THREAD)
        self.assertEqual(self.code("codex@id:019a0000"), "target_id_unverified")
        self.assertEqual(self.code("codex@impl"), "target_names_unverified")

    def test_unverified_names_ambiguity_and_no_inbox(self) -> None:
        other = THREAD.replace("b", "c")
        self.put(row(THREAD, "impl", verified=False))
        self.assertEqual(self.code("codex@impl"), "target_names_unverified")
        # 同名的一行已核实、一行未核实：不能先丢掉未核实行再算唯一
        self.put(row(THREAD, "impl"), row(other, "impl", verified=False))
        with self.assertRaises(DirectoryError) as caught:
            directory.resolve_remote(self.store, "win", "codex@impl", now=NOW)
        self.assertEqual((caught.exception.code, set(caught.exception.candidates)),
                         ("target_names_unverified", {f"codex@id:{THREAD}", f"codex@id:{other}"}))
        self.put(row(THREAD, "impl "))  # 规范值命中但不逐字相等
        self.assertEqual(self.code("codex@impl"), "target_names_unverified")
        self.put(row(THREAD, "impl"), row(other, "impl"))
        with self.assertRaises(DirectoryError) as caught:
            directory.resolve_remote(self.store, "win", "codex@impl", now=NOW)
        self.assertEqual(caught.exception.code, "target_ambiguous")
        self.assertEqual(set(caught.exception.candidates), {f"codex@id:{THREAD}", f"codex@id:{other}"})
        self.put(row(THREAD, "grok", inbox=False, provider="grok"))
        self.assertEqual(self.code(f"grok@id:{THREAD}"), "target_no_inbox")
        self.assertEqual(self.code("codex@impl", device="nowhere"), "device_unknown")


class GateTests(DirectoryCase):
    """名字/前缀的两道门（§91.2.2）：fresh 要求 hub 报在线且缓存年龄在 [−5 秒, 90 秒]；完整性要求明确的布尔 true。"""

    def test_fresh_needs_online_state_and_a_non_negative_age(self) -> None:
        # 负侧只容忍 5 秒的时钟偏差（owner 2026-11-12，D-B）：hub 钟略快照常可用，再多就不猜
        self.put(row(THREAD, "impl"))
        snapshot = self.store.device_states()[0]["snapshot"]
        cases = (("offline", NOW, "target_names_unverified"), ("online", NOW + 1, THREAD),
                 ("online", NOW + directory.CLOCK_SKEW_MS, THREAD),
                 ("online", NOW + directory.CLOCK_SKEW_MS + 1, "target_names_unverified"),
                 ("online", NOW - directory.FRESH_MS, THREAD), ("online", NOW - directory.FRESH_MS - 1,
                                                                "target_names_unverified"))
        for state, seen, expected in cases:
            with self.subTest(state=state, seen=seen):
                self.store.put_device_state(device_id=DEV_B, name="win", revision=1, snapshot=snapshot,
                                            last_seen=seen, state=state)
                try:
                    got = directory.resolve_remote(self.store, "win", "codex@impl", now=NOW).remote.native_id
                except DirectoryError as error:
                    got = error.code
                self.assertEqual(got, expected)

    def test_completeness_needs_explicit_true_for_every_relevant_provider(self) -> None:
        for snapshot in ({"endpoints": [row(THREAD, "impl")], "complete": True, "providers": {}},  # 缺键不算完整
                         {"endpoints": [row(THREAD, "impl")], "complete": False, "providers": {"codex": True}}):
            with self.subTest(snapshot=snapshot):
                snapshot["namePolicy"] = directory.NAME_POLICY
                self.store.put_device_state(device_id=DEV_B, name="win", revision=1, snapshot=snapshot,
                                            last_seen=NOW, state="online")
                self.assertEqual(self.code("codex@impl"), "remote_directory_incomplete")

    def test_display_label_only_comes_from_a_verified_name(self) -> None:
        self.put(row(THREAD, "impl", verified=False))
        resolved = directory.resolve_remote(self.store, "win", f"codex@id:{THREAD}", now=NOW).remote
        self.assertIsNone(resolved.display_label)  # 完整 ID 能选中，但未核实的名字不作旁注


class WindowsAliasPrivacyTests(DirectoryCase):
    """T5（§91.4.1/§91.6）：Windows 本机别名只能经否证布尔影响目录（digest 随之变化），别名本身不进目录。"""

    def snapshot(self, aliases: dict[str, str]) -> dict[str, object]:
        from agentstatus_bridge.platforms.windows import codex_discovery as wd  # layout: allow 合成 Windows 候选
        from agentstatus_bridge.platforms.windows.target_aliases import AliasSet  # layout: allow 合成 Windows 候选
        from agentstatus_bridge.model import NameSource

        first, second = "019a0000-0000-7000-8000-00000000000a", "019a0000-0000-7000-8000-00000000000b"
        rows = tuple(wd.Candidate(thread, "root", None, name, True, name, "", True, stable=True,
                                  name_source=NameSource("named", name)) for thread, name in ((first, "alpha"), (second, "x")))
        found = wd.Discovery(rows, True, "complete", "a" * 64, (200, "1"), AliasSet(dict(aliases), "ok"), "b" * 64)
        endpoints = [found.endpoint(item) for item in rows]
        with patch.object(directory, "root_binding", return_value="f" * 32):
            return directory.snapshot(self.store, DEV_A, endpoints, provider_complete={"codex": True})

    def test_alias_changes_the_directory_only_through_negation(self) -> None:
        plain = self.snapshot({})
        private = self.snapshot({"work": "019a0000-0000-7000-8000-00000000000a"})
        self.assertNotIn("work", json.dumps(private, ensure_ascii=False))  # 别名（也是 EndpointRef.label）不外泄
        # 不撞任何原生名的别名不改变公开字段；endpointRevision 可能因本机私有 label（别名）变化而递增，设计允许（§91.6）
        def public(document: dict[str, object]) -> list[dict[str, object]]:
            return [{key: value for key, value in item.items() if key != "endpointRevision"}
                    for item in document["endpoints"]]  # type: ignore[union-attr]
        self.assertEqual(public(private), public(plain))
        negating = self.snapshot({"x": "019a0000-0000-7000-8000-00000000000a"})
        names = {item["nativeId"]: (item.get("name"), item["namesVerified"]) for item in negating["endpoints"]}  # type: ignore[union-attr]
        self.assertEqual(names["019a0000-0000-7000-8000-00000000000b"], ("x", False))  # 别名否证了另一绑定的原生 x
        self.assertEqual(names["019a0000-0000-7000-8000-00000000000a"], ("alpha", True))  # 别名不成为主名
        self.assertNotEqual(canonical_bytes(negating), canonical_bytes(plain))  # digest/revision 因此变化


class PeerTextTests(DirectoryCase):
    """peers 文字的 〔ID〕：目录完整且新鲜时取缓存全集上的最短唯一前缀，否则完整 ID（§91.4.2；不固定截 8 位）。"""

    def test_shared_eight_digit_prefixes_grow_and_stale_directories_show_full_ids(self) -> None:
        first, second = "019a0000-1111-7222-8333-44445555bbbb", "019a0000-2222-7222-8333-44445555cccc"
        self.put(row(first, "impl"), row(second))
        text = "\n".join(directory.peer_lines(self.store, "win", now=NOW))
        self.assertIn("codex@impl〔019a0000-1〕", text)
        self.assertIn("codex@id:019a0000-2 ", text)
        self.assertIn(f"target=--device win --to codex@id:{first}", text)
        self.put(row(first, "impl"), row(second), fresh=False)
        text = "\n".join(directory.peer_lines(self.store, "win", now=NOW))
        self.assertIn(f"codex@impl〔{first}〕", text)
        self.assertIn(f"codex@id:{second} ", text)

    def test_unverified_names_are_shown_only_as_display_text(self) -> None:
        # 同一目录一行已核实、一行未核实：未核实的名字只作「名称=…（仅展示）」，不写成 provider@名字（Fable r1 X18）
        first, second = "019a0000-1111-7222-8333-44445555bbbb", "019a0000-2222-7222-8333-44445555cccc"
        self.put(row(first, "impl"), row(second, "dup", verified=False))
        text = "\n".join(directory.peer_lines(self.store, "win", now=NOW))
        self.assertIn("codex@impl〔019a0000-1〕", text)
        self.assertIn("codex@id:019a0000-2 名称=dup（仅展示）", text)
        self.assertNotIn("codex@dup", text)

    def test_ineligible_rows_still_take_part_in_prefix_growth(self) -> None:
        # 消歧按缓存全集算：不可投（eligible=false）的行也会让前缀变长，否则〔ID〕在全集上不唯一
        first, second = "019a0000-1111-7222-8333-44445555bbbb", "019a0000-1111-7222-8333-44445555cccc"
        hidden = row(second)
        hidden["eligible"] = False
        self.put(row(first, "impl"), hidden)
        text = "\n".join(directory.peer_lines(self.store, "win", now=NOW))
        self.assertIn("codex@impl〔019a0000-1111-7222-8333-44445555b〕", text)


class CompletenessTests(DirectoryCase):
    def test_names_need_a_complete_directory_but_exact_ids_do_not(self) -> None:
        self.store.put_device_state(device_id=DEV_B, name="win", revision=1, snapshot={
            "endpoints": [row(THREAD, "impl")], "complete": False, "providers": {"codex": False}},
            last_seen=NOW, state="online")
        self.assertEqual(directory.resolve_remote(self.store, "win", f"codex@id:{THREAD}", now=NOW).remote.native_id,
                         THREAD)
        for selector in ("codex@impl", "codex@id:019a0000"):
            self.assertEqual(self.code(selector), "remote_directory_incomplete")  # 没收齐的同名/同前缀端点无法参与消歧
        self.assertEqual(self.code("impl"), "target_provider_required")  # 语法门先于完整性门

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

    def test_real_discovery_carries_verified_names_into_the_directory(self) -> None:
        # 走真实 _discover_selected：名字视图在发现末尾附上，目录据此发布（换成不附视图，名字就发不出去）
        named = endpoint(ref(Provider.CODEX, THREAD, pid=4242), name="impl")
        fakes = {provider: replace(adapter, discover=(lambda *_a: [named]) if provider is Provider.CODEX
                                   else (lambda *_a: []))
                 for provider, adapter in endpoint_module.ADAPTERS.items()}
        with patch.dict(endpoint_module.ADAPTERS, fakes), patch.object(directory, "root_binding", return_value="f" * 32):
            snapshot = self.collect(denied=False)
        [item] = snapshot["endpoints"]  # type: ignore[misc]
        self.assertEqual((item["nativeId"], item.get("name"), item["namesVerified"]), (THREAD, "impl", True))

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
        bare = endpoint(ref(Provider.CODEX, THREAD, pid=4242, pane="%3", label="impl"), name="impl")
        # 没带 NameView 的端点没有名字证据：不发名字，也不从 ref.label 补（§91.4.3）
        unnamed = directory.snapshot(self.store, DEV_A, [bare], provider_complete={"codex": True})
        self.assertNotIn("name", unnamed["endpoints"][0])
        self.assertFalse(unnamed["endpoints"][0]["namesVerified"])
        [live] = with_name_views([bare])
        document = directory.snapshot(self.store, DEV_A, [live], provider_complete={"codex": True})
        [item] = document["endpoints"]
        self.assertEqual(set(item), {"provider", "nativeId", "endpointId", "endpointRevision", "inbox", "eligible",
                                     "namesVerified", "name", "displayName"})  # §91.4.1 只新增行 displayName
        self.assertEqual((item["name"], item["namesVerified"], document["namePolicy"]),
                         ("impl", True, directory.NAME_POLICY))
        self.assertTrue(document["complete"])
        self.assertNotIn("4242", json.dumps(document))  # 不发 PID/pane
        hidden = directory.snapshot(self.store, DEV_A, [live], publish_names=False)
        self.assertNotIn("name", hidden["endpoints"][0])
        self.assertNotIn("displayName", hidden["endpoints"][0])  # publishNames=false 连展示名也不发（§91.4.4）
        self.assertFalse(hidden["endpoints"][0]["namesVerified"])
        # 同一根上重复采样：endpointId 稳定
        self.assertEqual(hidden["endpoints"][0]["endpointId"], item["endpointId"])

    def test_bind_local_never_falls_back_to_ref_label(self) -> None:
        labelled = ref(Provider.CODEX, THREAD, pid=4242, pane="%3", label="tmux-name")
        self.assertIsNone(directory.bind_local(self.store, DEV_A, labelled, verified_name=None).remote.display_label)
        self.assertEqual(directory.bind_local(self.store, DEV_A, labelled, verified_name="impl").remote.display_label,
                         "impl")
        bare = endpoint(labelled, name="impl")  # 有名字但没带 NameView：不算已核实，不发布
        self.assertIsNone(directory.published_name(bare, publish_names=True))
        [named] = with_name_views([bare])
        self.assertEqual((directory.published_name(named, publish_names=True),
                          directory.published_name(named, publish_names=False)), ("impl", None))
        twins = with_name_views([endpoint(ref(Provider.CODEX, THREAD, pid=4245), name="dup"),
                                 endpoint(ref(Provider.CODEX, THREAD.replace("b", "c"), pid=4246), name="dup")])
        self.assertEqual([directory.published_name(item, publish_names=True) for item in twins], [None, None])

    def test_overlong_names_and_rows_drop_the_name_but_keep_the_identity(self) -> None:
        with patch.object(directory, "root_binding", return_value="f" * 32):
            [long_name] = with_name_views([endpoint(ref(Provider.CODEX, THREAD, pid=4242), name="n" * 121)])
            document = directory.snapshot(self.store, DEV_A, [long_name], provider_complete={"codex": True})
            [item] = document["endpoints"]
            self.assertNotIn("name", item)  # 名字超过 120 字符只丢名字
            self.assertIs(item["namesVerified"], False)
            # 单行超 2 KiB：先丢名字与展示名保住身份，标快照不完整
            huge = "019a0000-0000-7000-8000-" + "f" * 1800
            [wide] = with_name_views([endpoint(ref(Provider.CODEX, huge, pid=4243), name="名" * 100)])
            document = directory.snapshot(self.store, DEV_A, [wide], provider_complete={"codex": True})
            self.assertEqual(len(document["endpoints"]), 1)  # 行保住，不整行丢弃
            item = document["endpoints"][0]
            self.assertEqual((item["nativeId"], item["namesVerified"], "name" in item, "displayName" in item),
                             (huge, False, False, False))
            self.assertEqual((document["complete"], document["reason"]), (False, "endpoint_too_large"))
            # 纯 ID 仍放不下才整行不发
            [hopeless] = with_name_views([endpoint(ref(Provider.CODEX, "0" * 2100, pid=4244), name="x")])
            document = directory.snapshot(self.store, DEV_A, [hopeless], provider_complete={"codex": True})
            self.assertEqual((document["endpoints"], document["reason"]), ([], "endpoint_too_large"))

    def test_budgets_mark_incomplete_instead_of_truncating_silently(self) -> None:
        many = [endpoint(ref(Provider.CODEX, f"019a0000-0000-7000-8000-{index:012d}", pid=1000 + index))
                for index in range(directory.MAX_ENDPOINTS + 2)]
        document = directory.snapshot(self.store, DEV_A, many)
        self.assertEqual((len(document["endpoints"]), document["complete"], document["reason"]),
                         (directory.MAX_ENDPOINTS, False, "too_many_endpoints"))
        partial = directory.snapshot(self.store, DEV_A, many[:1], provider_complete={"claude": False})
        self.assertFalse(partial["complete"])  # 一个 provider 不完整就不是完整目录


def _codex(index: int) -> str:
    return f"019a0000-0000-7000-8000-{index:012d}"


CLAUDE_LEAD = "0000000a-1111-4222-8333-000000000001"


class LegacyReaderTests(DirectoryCase):
    """T5（§91.4.1）：新写方目录交给 104f286 旧读方与新读方，四种写/读组合都不按被否证的名字选中。"""

    def setUp(self) -> None:
        super().setUp()
        bound = patch.object(directory, "root_binding", return_value="f" * 32)  # 只测名字投影，不测根核实
        bound.start()
        self.addCleanup(bound.stop)
        raw = [endpoint(ref(Provider.CODEX, _codex(1), pid=5001), name="solo"),
               endpoint(ref(Provider.CODEX, _codex(2), pid=5002), name="dup"),
               endpoint(ref(Provider.CODEX, _codex(3), pid=5003), name="dup"),
               endpoint(ref(Provider.CODEX, _codex(4), pid=5004), name="edge "),  # 边缘空白：只展示，仍否证 edge
               endpoint(ref(Provider.CODEX, _codex(5), pid=5005), name="edge"),
               endpoint(ref(Provider.CODEX, _codex(6), pid=5006), native_name=None),
               endpoint(ref(Provider.CLAUDE, CLAUDE_LEAD, pid=5007), name="lead")]
        self.live = with_name_views(raw)
        self.selectors = ["codex@solo", "codex@dup", "codex@edge", "codex@edge ", "claude@lead", "solo", "dup",
                          "edge", "lead", "codex@id:019a0000", *(f"{item.ref.provider.value}@id:{item.ref.native_id}"
                                                                 for item in self.live)]

    def publish(self, document: dict[str, object]) -> None:
        self.store.put_device_state(device_id=DEV_B, name="win", revision=1, snapshot=document, last_seen=NOW,
                                    state="online")

    def old(self, selector: str) -> str:
        try:
            return legacy.resolve_remote(self.store, "win", selector).remote.native_id
        except legacy.DirectoryError as error:
            return error.code

    def new(self, selector: str) -> str:
        try:
            return directory.resolve_remote(self.store, "win", selector, now=NOW).remote.native_id
        except DirectoryError as error:
            return error.code

    def rows(self, document: dict[str, object]) -> dict[str, dict[str, object]]:
        return {str(item["nativeId"]): item for item in document["endpoints"]}  # type: ignore[union-attr]

    def assert_old_reader_never_picks_a_refuted_name(self, document: dict[str, object]) -> None:
        rows = self.rows(document)
        for selector in self.selectors:
            picked = self.old(selector)
            if picked not in rows or "@id:" in selector:
                continue
            item = rows[picked]
            # 旧读方按名字选中的行，新写方必须已核实这个主名，且新读方（带 provider）选中同一行
            self.assertIs(item["namesVerified"], True, selector)
            self.assertEqual(item["name"], selector.split("@", 1)[-1].strip(), selector)
            qualified = selector if "@" in selector else f"{item['provider']}@{selector}"
            self.assertEqual(self.new(qualified), picked, selector)

    def test_long_verified_names_resolve_for_the_new_reader(self) -> None:
        # 91.5 新→新：≥32 字符的已核实主名按名字可选（Linux Codex 的 thread 名常是长句）；≥32 字符按 nativeId 的
        # 旧启发式只用于历史快照（Opus r1 X10）。同一份目录交给 104f286 旧读方，它按 nativeId 理解，选不到
        long_name = "fix the flaky relay reconnect test"
        self.assertGreaterEqual(len(long_name), 32)
        live = with_name_views([endpoint(ref(Provider.CODEX, _codex(7), pid=5008), name=long_name)])
        self.publish(directory.snapshot(self.store, DEV_B, live, provider_complete={"codex": True}))
        self.assertEqual(self.new(f"codex@{long_name}"), _codex(7))
        self.assertEqual(self.old(f"codex@{long_name}"), "remote_endpoint_unresolved")

    def test_new_writer_refutes_names_for_the_old_reader(self) -> None:
        document = directory.snapshot(self.store, DEV_B, self.live, provider_complete={"codex": True, "claude": True})
        self.publish(document)
        rows = self.rows(document)
        # 不新增、不丢行；收件能力照适配器；可投行不因否证变成不可投
        self.assertEqual(set(rows), {item.ref.native_id for item in self.live})
        for item in self.live:
            row = rows[item.ref.native_id]
            self.assertEqual((row["inbox"], row["eligible"]), (endpoint_module.ADAPTERS[item.ref.provider].inbox, True))
        verified = {key: (row.get("name"), row["namesVerified"]) for key, row in rows.items()}
        self.assertEqual(verified, {_codex(1): ("solo", True), _codex(2): ("dup", False), _codex(3): ("dup", False),
                                    _codex(4): (None, False), _codex(5): ("edge", False), _codex(6): (None, False),
                                    CLAUDE_LEAD: ("lead", True)})
        self.assertEqual(rows[_codex(4)].get("displayName"), '"edge "')  # 不安全名字只作展示：加引号让边缘空白可见
        expected_old = {"codex@solo": _codex(1), "codex@dup": "target_names_unverified",
                        "codex@edge": "target_names_unverified", "codex@edge ": "target_names_unverified",
                        "claude@lead": CLAUDE_LEAD, "codex@id:019a0000": "remote_endpoint_unresolved"}
        expected_new = {"codex@solo": _codex(1), "codex@dup": "target_names_unverified",
                        "codex@edge": "target_names_unverified", "codex@edge ": "target_names_unverified",
                        "claude@lead": CLAUDE_LEAD, "solo": "target_provider_required",
                        "codex@id:019a0000": "target_ambiguous"}
        self.assertEqual({key: self.old(key) for key in expected_old}, expected_old)
        self.assertEqual({key: self.new(key) for key in expected_new}, expected_new)
        for item in self.live:  # 完整 ID 两代读方都精确命中
            token = f"{item.ref.provider.value}@id:{item.ref.native_id}"
            self.assertEqual((self.old(token), self.new(token)), (item.ref.native_id, item.ref.native_id))
        self.assert_old_reader_never_picks_a_refuted_name(document)

    def test_publish_names_off_leaves_only_full_ids_for_both_readers(self) -> None:
        document = directory.snapshot(self.store, DEV_B, self.live, publish_names=False,
                                      provider_complete={"codex": True, "claude": True})
        self.publish(document)
        for row in document["endpoints"]:  # type: ignore[union-attr]
            self.assertFalse({"name", "displayName"} & set(row))
            self.assertIs(row["namesVerified"], False)
        self.assertEqual((self.old("codex@solo"), self.new("codex@solo")),
                         ("remote_endpoint_unresolved", "remote_endpoint_unresolved"))
        self.assertEqual(self.old(f"codex@id:{_codex(1)}"), _codex(1))
        self.assert_old_reader_never_picks_a_refuted_name(document)

    def test_new_reader_reads_a_104f286_directory_with_the_same_gates(self) -> None:
        # 104f286 写方：只有 Claude 设 Endpoint.name，namesVerified=true；Codex 行的 name 是 tmux label、未核实
        long_name = "x" * 40
        self.publish({"endpoints": [
            {"provider": "claude", "nativeId": CLAUDE_LEAD, "endpointId": "1" * 32, "endpointRevision": 1,
             "inbox": True, "eligible": True, "namesVerified": True, "name": "lead"},
            {"provider": "codex", "nativeId": _codex(1), "endpointId": "2" * 32, "endpointRevision": 1,
             "inbox": True, "eligible": True, "namesVerified": False, "name": "impl"},
            {"provider": "claude", "nativeId": "0000000a-1111-4222-8333-000000000002", "endpointId": "3" * 32,
             "endpointRevision": 1, "inbox": True, "eligible": True, "namesVerified": True, "name": long_name},
        ], "complete": True, "providers": {"claude": True, "codex": True}})
        for selector, expected in (("claude@lead", CLAUDE_LEAD), ("codex@impl", "target_names_unverified"),
                                   (f"claude@{long_name}", "remote_endpoint_unresolved")):  # ≥32 字符沿旧启发式按 ID
            self.assertEqual((self.old(selector), self.new(selector)), (expected, expected), selector)
        self.assertEqual(self.new("lead"), "target_provider_required")  # 新读方的语法门同样适用于旧目录
        self.store.put_device_state(device_id=DEV_B, name="win", revision=2,
                                    snapshot=self.store.device_states()[0]["snapshot"], last_seen=None,
                                    state="unknown")
        self.assertEqual(self.new("claude@lead"), "target_names_unverified")  # 旧目录也补上新鲜门
        self.assertEqual(self.new(f"claude@id:{CLAUDE_LEAD}"), CLAUDE_LEAD)


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
