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
from agentstatus_bridge.model import UNRESOLVED_NATIVE_ID, EndpointRef, NameView, Provider
from agentstatus_bridge.observer_dbus import ObserverView
from agentstatus_bridge.platforms.factory import make_platform, using_platform
import bridge_legacy_directory_104f286 as legacy
from bridge_support import endpoint, ref, with_name_views
from bridge_winapi import Kernel
import test_bridge_codex_daemon as daemon_fixture

DEV_A = "a" * 32
DEV_B = "b" * 32
THREAD = "019a0000-1111-7222-8333-44445555bbbb"
NOW = 1_800_000_000_000
# D-A（§94.1）用例：两个同前缀的 Codex 会话（一个看得清、一个看不清）与一个 Claude 会话
DA_CODEX = "019a1234-0000-7000-8000-000000000001"
DA_HIDDEN = "019a1234-1111-7000-8000-000000000002"
DA_CLAUDE = "019a7777-0000-4000-8000-000000000002"


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

    def assert_only_codex_lowered(self, snapshot: dict[str, object]) -> None:
        """D-A 的读方后果（§94.1）：把写方真实发布的目录交给真实读方 resolve_remote。

        Codex 身份不全只拒 Codex 名字/前缀与无 provider 的前缀；带 provider 的 Claude 名字与前缀照常，完整 ID 不受门限制。
        """
        self.store.put_device_state(device_id=DEV_B, name="win", revision=1, snapshot=snapshot, last_seen=NOW,
                                    state="online")
        for selector in (f"codex@id:{DA_CODEX[:8]}", f"id:{DA_CODEX[:8]}", f"id:{DA_CLAUDE[:8]}", "codex@impl"):
            with self.subTest(selector=selector):
                self.assertEqual(self.code(selector), "remote_directory_incomplete")
        self.assertEqual(self.code("lead"), "target_provider_required")  # 远端裸名本来就拒，与 D-A 无关
        for selector in ("claude@lead", f"claude@id:{DA_CLAUDE[:8]}"):
            with self.subTest(selector=selector):
                self.assertEqual(directory.resolve_remote(self.store, "win", selector, now=NOW).remote.native_id,
                                 DA_CLAUDE)
        self.assertEqual(directory.resolve_remote(self.store, "win", f"codex@id:{DA_CODEX}", now=NOW).remote.native_id,
                         DA_CODEX)


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


class PeerCompletenessTests(DirectoryCase):
    """peers 设备行的三种目录完整性与 JSON 的 providers 增量键（§94.1）。"""

    def snapshot(self, *, complete: bool, providers: object) -> None:
        document: dict[str, object] = {"endpoints": [row(DA_CODEX, "impl"), row(DA_CLAUDE, "lead", provider="claude")],
                                       "complete": complete, "namePolicy": directory.NAME_POLICY}
        if providers is not None:
            document["providers"] = providers
        self.store.put_device_state(device_id=DEV_B, name="win", revision=1, snapshot=document, last_seen=NOW,
                                    state="online")

    def device_line(self) -> str:
        return directory.peer_lines(self.store, "win", now=NOW)[0]

    def test_three_device_line_forms(self) -> None:
        self.snapshot(complete=True, providers={"codex": True, "claude": True})
        self.assertEqual(self.device_line(), f"设备 win〔{DEV_B[:8]}〕：在线，目录完整")
        self.snapshot(complete=True, providers={"codex": False, "claude": True, "grok": False})
        # §101.1：远端裸名本来就报 target_provider_required，文案只列因未核全而不可用的写法
        self.assertEqual(self.device_line(), f"设备 win〔{DEV_B[:8]}〕：在线，目录部分完整（codex、grok 未核全：codex、grok"
                                             " 的名字/前缀与不带 provider 的前缀不可用，只能用完整 ID）")
        # 部分完整时 Codex 行的〔ID〕回到完整 ID（同一 _relevant_complete 判据），Claude 行仍取最短唯一前缀
        text = "\n".join(directory.peer_lines(self.store, "win", now=NOW))
        self.assertIn(f"codex@impl〔{DA_CODEX}〕", text)
        self.assertIn("claude@lead〔019a7777〕", text)
        self.snapshot(complete=False, providers={"codex": False, "claude": True})
        self.assertEqual(self.device_line(), f"设备 win〔{DEV_B[:8]}〕：在线，目录不完整")

    def assert_line_matches_reader(self, providers: object, pending: str | None) -> None:
        """设备行与真实读方同口径（§94.1，r1 两方 P3）：写部分完整当且仅当不带 provider 的前缀被拒。"""
        self.snapshot(complete=True, providers=providers)
        line = self.device_line()
        try:
            directory.resolve_remote(self.store, "win", f"id:{DA_CLAUDE[:8]}", now=NOW)
            rejected = False
        except DirectoryError as error:
            self.assertEqual(error.code, "remote_directory_incomplete")
            rejected = True
        self.assertEqual(rejected, pending is not None, line)
        if pending is None:
            self.assertTrue(line.endswith("目录完整"), line)
        else:
            self.assertIn(f"目录部分完整（{pending} 未核全：", line)

    def test_non_boolean_and_missing_keys_count_as_unverified(self) -> None:
        self.assert_line_matches_reader({"codex": 1, "claude": True}, "codex")  # 非布尔：不是明确 true
        self.assert_line_matches_reader({"codex": None, "claude": True}, "codex")
        self.assert_line_matches_reader({"codex": True}, "claude")  # 行里有 Claude、providers 缺键
        self.assert_line_matches_reader({"codex": True, "claude": True}, None)

    def test_hostile_provider_keys_are_never_printed(self) -> None:
        # 对端快照里的键只经 hub 布尔校验：带换行与 ESC 的键不能在本机文字里伪造出第二行设备行或终端控制序列
        forged = "x\n设备 forged〔ffffffff〕：在线，目录完整\x1b[2K"
        self.assert_line_matches_reader({"codex": True, "claude": True, forged: False}, "其他")
        lines = directory.peer_lines(self.store, "win", now=NOW)
        text = "\n".join(lines)
        self.assertNotIn("forged", text)
        self.assertNotIn("\x1b", text)
        self.assertFalse(any(line.startswith("设备 forged") for line in lines))
        self.assertEqual(sum(line.startswith("设备 ") for line in lines), 1)
        # JSON 原样转述完整的表（键名由 JSON 编码负责转义），文字只说「其他」
        [device] = directory.peer_devices(self.store, "win", now=NOW)
        self.assertIn(forged, device["providers"])
        self.assert_line_matches_reader({"codex": False, "claude": True, forged: False}, "codex、其他")

    def test_json_relays_the_provider_table_verbatim(self) -> None:
        table = {"codex": False, "claude": True}
        self.snapshot(complete=True, providers=table)
        [device] = directory.peer_devices(self.store, "win", now=NOW)
        self.assertEqual((device["complete"], device["providers"]), (True, table))
        self.snapshot(complete=True, providers=None)  # 历史快照没有 providers：空表，不猜
        [device] = directory.peer_devices(self.store, "win", now=NOW)
        self.assertEqual(device["providers"], {})


class HostilePeerTextTests(DirectoryCase):
    """§101.1：peers 文字行里一切来自远端的字符串与本机名字同一套转义；target= 只由已校验的值拼成；--json 照给原值。"""

    FIRST, SECOND = "019a0000-1111-7222-8333-44445555bbbb", "019a0000-2222-7222-8333-44445555cccc"
    # 换行、ESC、RLO、零宽空格各自单测（转义写法同 native_names.display_text），外加一条能伪造整行设备行的串
    HOSTILE = (("\n", "\\u000a"), ("\x1b", "\\u001b"), ("\u202e", "\\u202e"), ("\u200b", "\\u200b"),
               ("\n设备 forged〔ffffffff〕：在线，目录完整", "\\u000a设备 forged〔ffffffff〕：在线，目录完整"))

    def put_raw(self, *items: dict[str, object], device_id: str = DEV_B, name: str = "win") -> None:
        self.store.put_device_state(device_id=device_id, name=name, revision=1, snapshot={
            "endpoints": list(items), "complete": True, "providers": {"codex": True}, "namePolicy": directory.NAME_POLICY},
            last_seen=NOW, state="online")

    def text(self, peers: int) -> list[str]:
        """全部设备的文字行，并断言没被伪造出新行：按 splitlines 量（列表长度量不到元素内的换行）。"""
        lines = directory.peer_lines(self.store, None, now=NOW)
        physical = "\n".join(lines).splitlines()
        self.assertEqual(len(physical), 1 + peers, physical)
        self.assertEqual(sum(line.startswith("设备 ") for line in physical), 1, physical)
        self.assertFalse(any(line.startswith("设备 forged") for line in physical), physical)
        self.assertFalse(any(char in "".join(physical) for char in "\x1b\u202e\u200b"), physical)
        return lines

    def raw_peer(self) -> dict[str, object]:
        [device] = directory.peer_devices(self.store, None, now=NOW)
        return device["peers"][0]

    def test_names_and_display_names_are_escaped(self) -> None:
        good = f"target=--device win --to codex@id:{self.FIRST}"
        for char, escaped in self.HOSTILE:
            hostile = f"a{char}b"
            cases = {
                # 对端自称已核实但名字过不了 copyable：不写成 provider@名字，只作「名称=…（仅展示）」
                "verified-name": row(self.FIRST, hostile, verified=True),
                "unverified-name": row(self.FIRST, hostile, verified=False),
                "display-name": {**row(self.FIRST, "impl", verified=False), "displayName": hostile},
            }
            for field, item in cases.items():
                with self.subTest(char=repr(char), field=field):
                    self.put_raw(item)
                    line = self.text(1)[1]
                    self.assertIn(f"codex@id:019a0000 名称=a{escaped}b（仅展示） device=win ", line)
                    self.assertIn(good, line)
                    self.assertNotIn(f"codex@a{char}", line)
                    key = "displayName" if field == "display-name" else "name"
                    self.assertEqual(self.raw_peer()[key], hostile)  # --json 照给原值

    def test_verified_names_over_the_label_limit_are_only_displayed_and_truncated(self) -> None:
        # 长度上限照 §91（120 字符）：对端自称已核实的超长名字不整段写成 provider@名字，改作展示并按 120 截断
        self.put_raw(row(self.FIRST, "n" * 120), row(self.SECOND, "m" * 121))
        lines = self.text(2)
        self.assertIn(f"codex@{'n' * 120}〔019a0000-1〕 device=win", lines[1])
        self.assertIn(f"codex@id:019a0000-2 名称={'m' * 119}…（仅展示） device=win target=--device win", lines[2])

    def test_device_name_and_id_are_escaped_and_target_falls_back_to_the_full_device_id(self) -> None:
        for char, escaped in self.HOSTILE:
            hostile = f"w{char}in"
            with self.subTest(char=repr(char)):
                self.put_raw(row(self.FIRST, "impl"), name=hostile)
                lines = self.text(1)
                self.assertTrue(lines[0].startswith(f"设备 w{escaped}in〔{DEV_B[:8]}〕："), lines[0])
                self.assertIn(f" device=w{escaped}in target=--device {DEV_B} --to codex@id:{self.FIRST}", lines[1])
                [device] = directory.peer_devices(self.store, None, now=NOW)
                self.assertEqual(device["device"], hostile)  # --json 照给原值
                self.assertEqual(device["peers"][0]["target"], f"--device {hostile} --to codex@id:{self.FIRST}")
        self.store.connection.execute("DELETE FROM fed_device_state")
        # deviceId 也不是 32 位十六进制：设备行与 device= 照样转义，没有可照抄的 --device，不给 target=
        forged_id = "\n设备 forged" + "f" * 30
        self.put_raw(row(self.FIRST, "impl"), device_id=forged_id, name="w\nin")
        lines = self.text(1)
        # 首尾空白（这里截出的 8 位以换行开头）照 display_text 用引号标出
        self.assertTrue(lines[0].startswith('设备 w\\u000ain〔"\\u000a设备 forg"〕：'), lines[0])
        self.assertNotIn("target=", lines[1])
        self.assertTrue(lines[1].endswith("  （设备引用无效）"), lines[1])
        # 没有登记名：device= 退回 deviceId，同样转义
        self.store.connection.execute("DELETE FROM fed_device_state")
        self.put_raw(row(self.FIRST, "impl"), device_id=forged_id, name="")
        lines = self.text(1)
        self.assertTrue(lines[0].startswith('设备 〔"\\u000a设备 forg"〕：'), lines[0])
        self.assertIn(' device="\\u000a设备 forged' + "f" * 30 + '"  （设备引用无效）', lines[1])

    def test_invalid_provider_or_native_id_rows_get_no_target(self) -> None:
        # 已核实与未核实两条显示分支都要转义（r1，opus2 o14：未核实分支的 provider 曾无断言）
        for char, escaped in self.HOSTILE:
            for field, name in (("provider", "impl"), ("provider", None), ("nativeId", "impl"), ("nativeId", None)):
                with self.subTest(char=repr(char), field=field, named=name is not None):
                    item = row(self.FIRST, name)
                    item[field] = f"{item[field]}{char}x"
                    self.put_raw(item, row(self.SECOND, "lead"))
                    lines = self.text(2)
                    bad = lines[1]
                    self.assertIn(f"{escaped}x", bad)
                    self.assertNotIn("target=", bad)
                    flag = "provider 未知" if field == "provider" else "ID 无效"
                    self.assertTrue(bad.endswith(f"  （{flag}）"), bad)
                    # 同设备的正常行照旧可照抄
                    self.assertIn(f"target=--device win --to codex@id:{self.SECOND}", "\n".join(lines))
                    self.assertEqual(self.raw_peer()["remoteRef"][field], item[field])  # --json 照给原值

    def test_unknown_provider_and_invalid_ids_are_flagged_separately(self) -> None:
        # 原因分开写（team-lead §101 答复）：新版对端的未知 provider 不算 ID 无效；只有不合法的 ID 值才写「ID 无效」
        future = {**row(self.FIRST), "provider": "gemini"}
        bad_id = row("not-a-uuid", "x")
        self.put_raw(future, bad_id, row(self.SECOND, "lead"))
        lines = self.text(3)
        self.assertEqual(lines[1], f"  gemini@id:{self.FIRST} device=win  （provider 未知）")
        self.assertEqual(lines[2], "  codex@x〔not-a-uuid〕 device=win  （ID 无效）")  # 名字照常作旁注，只是没有 target=

    def test_legit_rows_of_every_provider_keep_their_display(self) -> None:
        # 真实发布方造各 provider 的合法行：Codex 命名、无名的子代理/daemon 类线程、未解析「-」，Claude，Grok 只读。
        # 与改前（2b11bc5）逐行比对只差一处：「-」行不再给照抄也会报 target_id_invalid 的 target=，旗标照旧；
        # 合法行一律不得出现「ID 无效」「provider 未知」「设备引用无效」
        items = [
            endpoint(ref(Provider.CODEX, DA_CODEX, pid=4242, pane="%1"), name="impl"),
            endpoint(ref(Provider.CODEX, DA_HIDDEN, pid=4242, pane=None, label=None), issues=("title_shows_subagent",),
                     native_name=None),
            endpoint(ref(Provider.CODEX, UNRESOLVED_NATIVE_ID, pid=4343, pane=None, label=None),
                     issues=("title_thread_missing",), native_name=None),
            endpoint(ref(Provider.CLAUDE, DA_CLAUDE, pid=4444, pane="%2", label="lead"), name="lead"),
            endpoint(ref(Provider.GROK, self.SECOND, pid=4545, pane="%3", label="grok")),
        ]
        with patch.object(directory, "root_binding", return_value="f" * 32):
            frame = directory.snapshot(self.store, DEV_B, with_name_views(items),
                                       provider_complete={"codex": True, "claude": True, "grok": True})
        self.store.put_device_state(device_id=DEV_B, name="win", revision=1, snapshot=frame, last_seen=NOW,
                                    state="online")
        target = "device=win target=--device win --to"
        self.assertEqual(self.text(5), [
            f"设备 win〔{DEV_B[:8]}〕：在线，目录完整",
            f"  codex@id:019a1234-0 名称=impl（仅展示） {target} codex@id:{DA_CODEX}",
            f"  codex@id:019a1234-1 {target} codex@id:{DA_HIDDEN}  （暂不可投）",
            "  codex@id:- device=win  （暂不可投）",
            f"  claude@lead〔019a7777〕 {target} claude@id:{DA_CLAUDE}",
            f"  grok@id:019a0000 {target} grok@id:{self.SECOND}  （只读）"])

    def test_honest_frames_are_unchanged(self) -> None:
        # 诚实写方发布的 displayName 已经转义过（反斜杠是普通字符）：再转义一遍逐字节不变
        published = directory.remote_display("a\u202eb")
        self.assertEqual(published, "a\\u202eb")
        item = {**row(self.FIRST, "impl", verified=False), "displayName": published}
        self.put_raw(item, row(self.SECOND, "lead"))
        self.assertEqual(self.text(2), [
            f"设备 win〔{DEV_B[:8]}〕：在线，目录完整",
            f"  codex@id:019a0000-1 名称=a\\u202eb（仅展示） device=win target=--device win --to codex@id:{self.FIRST}",
            f"  codex@lead〔019a0000-2〕 device=win target=--device win --to codex@id:{self.SECOND}"])


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
        sources = self.sources = endpoint_module.DiscoverySources(
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

    def adapters(self, *, claude_unread: bool = False) -> dict[Provider, object]:
        """Codex 一个看得清的会话加一个认不出 thread 的窗口（不能排除是根会话），Claude 一个已命名会话。"""
        seen = endpoint(ref(Provider.CODEX, DA_CODEX, pid=4242, pane="%1"), name="impl")
        hidden = endpoint(ref(Provider.CODEX, UNRESOLVED_NATIVE_ID, pid=4343, pane=None, label=None),
                          issues=("title_thread_missing",), native_name=None)
        lead = endpoint(ref(Provider.CLAUDE, DA_CLAUDE, pid=4444, pane="%2", label="lead"), name="lead")

        def claude(config: endpoint_module.DiscoverySources, *_rest: object) -> list[object]:
            if claude_unread:
                config.incomplete.add("claude")  # 与注册表读失败同一记账：本轮 Claude 来源没看全
            return [lead]

        found = {Provider.CODEX: lambda *_a: [seen, hidden], Provider.CLAUDE: claude}
        return {provider: replace(adapter, discover=found.get(provider, lambda *_a: []))
                for provider, adapter in endpoint_module.ADAPTERS.items()}

    def test_codex_identity_gap_only_lowers_providers_codex(self) -> None:
        # D-A（§94.1）：认不出 thread 的 Codex 窗口只让 providers.codex=false，顶层 complete 仍按来源为 true
        with patch.dict(endpoint_module.ADAPTERS, self.adapters()), \
                patch.object(directory, "root_binding", return_value="f" * 32):
            snapshot = self.collect(denied=False)
            found = endpoint_module.discover(self.sources)  # 同一份夹具来源与替身再发现一次，取本机判据（不碰宿主 tmux/D-Bus）
        self.assertEqual((snapshot["complete"], snapshot["providers"]),
                         (True, {"claude": True, "codex": False, "grok": True}))
        # 发布值与本机 --to 解析、名字投影是同一判据（selection_complete），不另算一份
        self.assertEqual(snapshot["providers"],
                         {provider.value: endpoint_module.selection_complete(found, provider) for provider in Provider})
        self.assert_only_codex_lowered(snapshot)

    def test_source_gap_still_clears_the_top_level_flag(self) -> None:
        # 来源没看全仍让顶层 complete=false：D-A 只把身份不全从顶层拆出去，来源不全照旧连带
        with patch.dict(endpoint_module.ADAPTERS, self.adapters(claude_unread=True)), \
                patch.object(directory, "root_binding", return_value="f" * 32):
            snapshot = self.collect(denied=False)
        self.assertEqual((snapshot["complete"], snapshot["providers"]),
                         (False, {"claude": False, "codex": False, "grok": True}))
        self.store.put_device_state(device_id=DEV_B, name="win", revision=1, snapshot=snapshot, last_seen=NOW,
                                    state="online")
        self.assertEqual(self.code("claude@lead"), "remote_directory_incomplete")


class DaemonPublisherTests(daemon_fixture.DaemonBase):
    """D-A 在真实 Linux 发现上（§94.1）：托管 daemon 下有一个认不出 thread 的 TUI 时，目录发布 providers.codex=false。"""

    def test_unreadable_tui_title_lowers_only_codex(self) -> None:
        self.daemon(self.lock(DA_CODEX), self.lock(DA_HIDDEN))
        self.tui(1000, "%1", shows=DA_CODEX)
        self.tui(3000, None, tty=34817)  # 实际显示另一个 thread，但在 tmux 外、没有标题可读
        self.state_db({DA_CODEX: "cli", DA_HIDDEN: "cli"})
        sources = self.sources()
        store = FederatedStore.create(self.root / "fed")
        self.addCleanup(store.close)
        store.set_meta("deviceId", DEV_A)
        runtime = SimpleNamespace(store=store, ident=SimpleNamespace(device_id=DEV_A),
                                  config=SimpleNamespace(publish_names=True))
        with patch.object(commands, "DiscoverySources", return_value=sources), \
                patch.object(directory, "root_binding", return_value="f" * 32):
            snapshot = commands.directory_source(runtime)()  # type: ignore[arg-type]
        self.assertTrue(sources.provider_complete(Provider.CODEX))  # 来源看全了：缺的是身份
        self.assertEqual((snapshot["complete"], snapshot["providers"]["codex"]), (True, False))  # type: ignore[index]
        self.assertEqual(sorted(item["nativeId"] for item in snapshot["endpoints"]),  # type: ignore[union-attr]
                         sorted([DA_CODEX, UNRESOLVED_NATIVE_ID]))

    def test_daemon_threads_publish_their_workdir(self) -> None:
        # §95.3 端到端：托管 daemon 下按标题认出的 thread，目录末段经真实发现与 directory_source 进快照行
        import sqlite3  # 本用例自建带 name/cwd 列的状态库

        self.daemon(self.lock(DA_CODEX))
        self.tui(1000, "%1", shows=DA_CODEX)
        with sqlite3.connect(self.codex_home / "state_5.sqlite") as db:
            db.execute("CREATE TABLE threads (id TEXT, source TEXT, name TEXT, cwd TEXT, history_mode TEXT)")
            db.execute("INSERT INTO threads VALUES (?,?,?,?,?)", (DA_CODEX, "cli", "impl", "/home/u/repo-a", "paginated"))
        store = FederatedStore.create(self.root / "fed")
        self.addCleanup(store.close)
        store.set_meta("deviceId", DEV_A)
        runtime = SimpleNamespace(store=store, ident=SimpleNamespace(device_id=DEV_A),
                                  config=SimpleNamespace(publish_names=True))
        with patch.object(commands, "DiscoverySources", return_value=self.sources()), \
                patch.object(directory, "root_binding", return_value="f" * 32):
            snapshot = commands.directory_source(runtime)()  # type: ignore[arg-type]
        [item] = snapshot["endpoints"]  # type: ignore[misc]
        self.assertEqual((item["nativeId"], item.get("name"), item.get("workdir")), (DA_CODEX, "impl", "repo-a"))


class WindowsPublisherTests(DirectoryCase):
    """D-A 的 Windows 写方（§94.1）：一行 Codex 元数据未核实只降 providers.codex，Claude 远端名字与前缀不连带失效。

    假内核只提供 Windows 平台组合根；Codex/Claude 发现结果按真实数据类型合成，经真实 directory_source 发布。
    """

    def discoveries(self, *, codex_complete: bool = True, hidden_verified: bool = False,
                    hidden_stable: bool = True, workdirs: bool = False) -> tuple[object, object]:
        """合成的 Codex 与 Claude 发现结果：Codex 一行已核实且稳定，另一行按参数（元数据核实、稳定）合成。"""
        from agentstatus_bridge.platforms.windows import claude_discovery as wc  # layout: allow 合成 Windows 发现结果
        from agentstatus_bridge.platforms.windows import codex_discovery as wd  # layout: allow 合成 Windows 发现结果
        from agentstatus_bridge.platforms.windows.target_aliases import AliasSet  # layout: allow 合成 Windows 候选
        from agentstatus_bridge.model import NameSource

        rows = (wd.Candidate(DA_CODEX, "root", None, "impl", True, "impl", "", True, stable=True,
                             name_source=NameSource("named", "impl"), workdir="proj-a" if workdirs else None),
                wd.Candidate(DA_HIDDEN, "root", None, "", hidden_verified, "", "", False, stable=hidden_stable))
        codex = wd.Discovery(rows, codex_complete, "metadata_unverified", "a" * 64, (200, "1"), AliasSet({}, "ok"),
                             "b" * 64)
        lead = replace(endpoint(EndpointRef(Provider.CLAUDE, DA_CLAUDE, 300, "win-filetime:1", data_root="c" * 64)),
                       name_view=NameView(Provider.CLAUDE, DA_CLAUDE, "lead", "lead", True, DA_CLAUDE[:8]),
                       workdir="lead-dir" if workdirs else None)
        return codex, wc.Discovery((lead,), True, "complete")

    def collect(self, **kwargs: bool) -> dict[str, object]:
        from agentstatus_bridge.platforms.windows import claude_discovery as wc  # layout: allow 合成 Windows 发现结果
        from agentstatus_bridge.platforms.windows import commands as wcommands  # layout: allow 合成 Windows 发现结果

        codex, claude = self.discoveries(**kwargs)
        kernel = Kernel(self.root)
        runtime = SimpleNamespace(store=self.store, ident=SimpleNamespace(device_id=DEV_A),
                                  config=SimpleNamespace(publish_names=True))
        with using_platform(make_platform("windows", win_api=kernel.api)), \
                patch.object(wcommands, "discover", return_value=codex), \
                patch.object(wc, "discover", return_value=claude):
            return commands.directory_source(runtime)()  # type: ignore[arg-type]

    def test_windows_rows_publish_their_workdir(self) -> None:
        # §95.3 端到端：Codex 候选经 Discovery.endpoint() 带出 workdir，Claude 端点原样带出，都进快照行
        snapshot = self.collect(hidden_verified=True, workdirs=True)
        rows = {item["nativeId"]: item.get("workdir") for item in snapshot["endpoints"]}  # type: ignore[union-attr]
        self.assertEqual(rows, {DA_CODEX: "proj-a", DA_HIDDEN: None, DA_CLAUDE: "lead-dir"})

    LONG_DIR = "d" * 100

    def publish_long_directory(self) -> dict[str, object]:
        """审计 r1 Opus P3-7 远端一侧：同一个 100 字符目录下一个无名线程（主名取自 cwd 末段、按 96 字符截断）、
        一个有名线程，经真实 directory_source 发布。"""
        from agentstatus_bridge.platforms.windows import claude_discovery as wc  # layout: allow 合成 Windows 发现结果
        from agentstatus_bridge.platforms.windows import codex_discovery as wd  # layout: allow 合成 Windows 发现结果
        from agentstatus_bridge.platforms.windows import commands as wcommands  # layout: allow 合成 Windows 发现结果
        from agentstatus_bridge.platforms.windows.target_aliases import AliasSet  # layout: allow 合成 Windows 候选
        from agentstatus_bridge.model import NameSource

        long_dir = self.LONG_DIR
        rows = (wd.Candidate(DA_CODEX, "root", None, "", True, "", long_dir[:96], True, stable=True,
                             name_source=NameSource("named", long_dir[:96], True), workdir=long_dir, name_from_cwd=True),
                wd.Candidate(DA_HIDDEN, "root", None, "Fix bug", True, "Fix bug", long_dir[:96], True, stable=True,
                             name_source=NameSource("named", "Fix bug"), workdir=long_dir))
        codex = wd.Discovery(rows, True, "complete", "a" * 64, (200, "1"), AliasSet({}, "ok"), "b" * 64)
        runtime = SimpleNamespace(store=self.store, ident=SimpleNamespace(device_id=DEV_A),
                                  config=SimpleNamespace(publish_names=True))
        with using_platform(make_platform("windows", win_api=Kernel(self.root).api)), \
                patch.object(wcommands, "discover", return_value=codex), \
                patch.object(wc, "discover", return_value=wc.Discovery((), True, "complete")):
            return commands.directory_source(runtime)()  # type: ignore[arg-type]

    def test_a_name_taken_from_the_directory_is_published_without_workdir(self) -> None:
        # 无名行不带 workdir（名字就是目录名），有名行照常带；键集不变，旧读方不受影响
        published = {item["nativeId"]: item for item in self.publish_long_directory()["endpoints"]}  # type: ignore[union-attr]
        self.assertNotIn("workdir", published[DA_CODEX])
        self.assertEqual(published[DA_CODEX]["displayName"], self.LONG_DIR[:96] + "…")
        self.assertEqual(published[DA_HIDDEN]["workdir"], self.LONG_DIR)

    def test_the_remote_reader_does_not_repeat_a_long_directory_name(self) -> None:
        # 远端读方读这份快照：100 字符目录名的无名行不重复显示「目录」，有名行照常
        long_dir = self.LONG_DIR
        snapshot = self.publish_long_directory()
        self.store.put_device_state(device_id=DEV_B, name="win", revision=1, snapshot=snapshot, last_seen=NOW,
                                    state="online")
        lines = directory.peer_lines(self.store, "win", now=NOW)
        unnamed = next(line for line in lines if f"codex@id:{DA_CODEX}" in line)
        named = next(line for line in lines if f"codex@id:{DA_HIDDEN}" in line)
        self.assertNotIn("目录", unnamed)
        self.assertTrue(named.endswith(f"  目录 {long_dir}"), named)
        [device] = directory.peer_devices(self.store, "win", now=NOW)
        self.assertEqual({peer["remoteRef"]["nativeId"]: peer["workdir"] for peer in device["peers"]},
                         {DA_CODEX: None, DA_HIDDEN: long_dir})

    def test_unverified_codex_row_only_lowers_providers_codex(self) -> None:
        snapshot = self.collect()
        self.assertEqual((snapshot["complete"], snapshot["providers"]), (True, {"codex": False, "claude": True}))
        self.assertEqual(sorted(item["nativeId"] for item in snapshot["endpoints"]),  # type: ignore[union-attr]
                         sorted([DA_CODEX, DA_CLAUDE]))  # 未核实的行不可投，不发布
        self.assert_only_codex_lowered(snapshot)

    def test_verified_rows_publish_complete_and_source_gap_clears_the_top_level_flag(self) -> None:
        self.assertEqual(self.collect(hidden_verified=True)["providers"], {"codex": True, "claude": True})
        snapshot = self.collect(codex_complete=False)
        self.assertEqual((snapshot["complete"], snapshot["providers"]), (False, {"codex": False, "claude": True}))

    def test_verified_but_unstable_row_only_lowers_providers_codex(self) -> None:
        # 身份判据的另一半（§94.1「全部行 metadata_verified and stable」）：元数据已核实但不稳定的行同样降 providers.codex
        snapshot = self.collect(hidden_verified=True, hidden_stable=False)
        self.assertEqual((snapshot["complete"], snapshot["providers"]), (True, {"codex": False, "claude": True}))
        self.assert_only_codex_lowered(snapshot)

    def test_worker_keeps_the_combined_provider_completeness(self) -> None:
        # 给 worker 的 provider_complete 保持「来源 and 身份」组合语义（§94.1）；目录发布才拆开用两半
        from agentstatus_bridge.platforms.windows import commands as wcommands  # layout: allow 合成 Windows 发现结果

        sampler = wcommands.WorkerDiscovery(make_platform("windows", win_api=Kernel(self.root).api).transport)  # type: ignore[arg-type]
        cases = {"未核实": dict(hidden_verified=False), "不稳定": dict(hidden_verified=True, hidden_stable=False),
                 "全部核实": dict(hidden_verified=True), "来源不全": dict(hidden_verified=True, codex_complete=False)}
        expected = {"未核实": (True, False, False), "不稳定": (True, False, False), "全部核实": (True, True, True),
                    "来源不全": (False, True, False)}
        for label, kwargs in cases.items():
            with self.subTest(case=label):
                sampler.codex, sampler.claude = self.discoveries(**kwargs)  # type: ignore[assignment]
                self.assertEqual((sampler.source_complete(Provider.CODEX), sampler.ids_complete(Provider.CODEX),
                                  sampler.provider_complete(Provider.CODEX)), expected[label])
                self.assertTrue(sampler.provider_complete(Provider.CLAUDE))
                self.assertEqual(sampler.complete(), expected[label][2])


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


class WorkdirSnapshotTests(DirectoryCase):
    """§95.3 写方：行里可选键 workdir（已转义、限长的末段），与名字共用 publish_names；超预算先静默去掉它。"""

    def setUp(self) -> None:
        super().setUp()
        bound = patch.object(directory, "root_binding", return_value="f" * 32)  # 只测投影与预算，不测根核实
        bound.start()
        self.addCleanup(bound.stop)

    def live(self, native: str = THREAD, *, name: str = "impl", workdir: str | None = "repo-a",
             pid: int = 4242) -> object:
        [item] = with_name_views([replace(endpoint(ref(Provider.CODEX, native, pid=pid), name=name), workdir=workdir)])
        return item

    def test_workdir_is_escaped_and_follows_the_name_switch(self) -> None:
        document = directory.snapshot(self.store, DEV_A, [self.live(workdir="a\u202eb")], provider_complete={"codex": True})
        [item] = document["endpoints"]
        self.assertEqual(item["workdir"], "a\\u202eb")  # 与 displayName 同一套转义
        self.assertTrue(document["complete"])
        hidden = directory.snapshot(self.store, DEV_A, [self.live()], publish_names=False)
        self.assertNotIn("workdir", hidden["endpoints"][0])  # publishNames=false：名字与目录末段都不发
        unknown = directory.snapshot(self.store, DEV_A, [self.live(workdir=None)])
        self.assertNotIn("workdir", unknown["endpoints"][0])  # 不知道就不带键（不发 null）
        long = directory.snapshot(self.store, DEV_A, [self.live(workdir="d" * 300)])
        self.assertEqual(len(long["endpoints"][0]["workdir"]), 120)

    def padded(self, size: int, *, workdir: str | None) -> object:
        """nativeId 补齐到让「不带 workdir 的行」恰好 size 字节。"""
        head = "019a0000-0000-7000-8000-"
        probe = directory.snapshot(self.store, DEV_A, [self.live(head, workdir=None)])["endpoints"][0]
        native = head + "f" * (size - len(canonical_bytes(probe)))
        return self.live(native, workdir=workdir)

    def test_a_row_that_fits_exactly_without_workdir_only_loses_the_workdir(self) -> None:
        exact = self.padded(directory.MAX_ENDPOINT_BYTES, workdir=None)
        bare = directory.snapshot(self.store, DEV_A, [exact], provider_complete={"codex": True})
        self.assertEqual(len(canonical_bytes(bare["endpoints"][0])), directory.MAX_ENDPOINT_BYTES)
        document = directory.snapshot(self.store, DEV_A, [self.padded(directory.MAX_ENDPOINT_BYTES, workdir="repo-a")],
                                      provider_complete={"codex": True})
        # 只丢 workdir：名字、namesVerified、complete 都不变，不写 reason；与不带 workdir 的结果逐字节相同
        self.assertEqual(canonical_bytes(document), canonical_bytes(bare))
        self.assertEqual((document["endpoints"][0]["name"], document["endpoints"][0]["namesVerified"]), ("impl", True))
        self.assertNotIn("reason", document)

    def test_a_row_that_fits_exactly_with_workdir_keeps_it(self) -> None:
        room = len(canonical_bytes({"workdir": "repo-a"})) - 1  # 多一个键要多一个逗号，花括号已在行里
        document = directory.snapshot(self.store, DEV_A,
                                      [self.padded(directory.MAX_ENDPOINT_BYTES - room, workdir="repo-a")],
                                      provider_complete={"codex": True})
        [item] = document["endpoints"]
        self.assertEqual(len(canonical_bytes(item)), directory.MAX_ENDPOINT_BYTES)
        self.assertEqual(item["workdir"], "repo-a")
        self.assertTrue(document["complete"])

    def test_a_row_too_large_even_without_workdir_still_degrades(self) -> None:
        document = directory.snapshot(self.store, DEV_A, [self.padded(directory.MAX_ENDPOINT_BYTES + 1, workdir="repo-a")],
                                      provider_complete={"codex": True})
        [item] = document["endpoints"]
        self.assertFalse({"workdir", "name", "displayName"} & set(item))
        self.assertEqual((item["namesVerified"], document["complete"], document["reason"]),
                         (False, False, "endpoint_too_large"))

    def many(self, *, workdir: str | None) -> list[object]:
        return [self.live(_codex(index), name=f"n{index}", workdir=workdir, pid=6000 + index) for index in range(1, 6)]

    def test_whole_snapshot_budget_strips_workdirs_before_dropping_rows(self) -> None:
        bare = directory.snapshot(self.store, DEV_A, self.many(workdir=None), provider_complete={"codex": True})
        limit = len(canonical_bytes(bare))
        with patch.object(directory, "MAX_SNAPSHOT_BYTES", limit):
            document = directory.snapshot(self.store, DEV_A, self.many(workdir="repo-a"),
                                          provider_complete={"codex": True})
        # 带 workdir 超限、去掉后放得下：不掉行，complete 不变，不写 reason
        self.assertEqual(canonical_bytes(document), canonical_bytes(bare))
        with patch.object(directory, "MAX_SNAPSHOT_BYTES", limit - 1):
            stripped = directory.snapshot(self.store, DEV_A, self.many(workdir="repo-a"),
                                          provider_complete={"codex": True})
            plain = directory.snapshot(self.store, DEV_A, self.many(workdir=None), provider_complete={"codex": True})
        # 去掉后仍超：按原降级从尾部弹行、标 snapshot_too_large；与没有 workdir 的快照结果相同
        self.assertEqual((len(stripped["endpoints"]), stripped["complete"], stripped["reason"]),
                         (4, False, "snapshot_too_large"))
        self.assertEqual(canonical_bytes(stripped), canonical_bytes(plain))

    def test_without_workdirs_the_snapshot_is_unchanged(self) -> None:
        # 夹具端点不带 workdir：行的键集与 §91 相同（逐字节对旧写方的对照在跨版本工装里做）
        document = directory.snapshot(self.store, DEV_A, self.many(workdir=None), provider_complete={"codex": True})
        self.assertTrue(all("workdir" not in item for item in document["endpoints"]))
        self.assertNotIn("workdir", canonical_bytes(document).decode())


class RemoteWorkdirTests(DirectoryCase):
    """§95.3 读方：远端行文字加「目录 <末段>」、JSON 加 workdir；显示前去掉控制/格式字符（只对新字段）。"""

    FIRST, SECOND = "019a0000-1111-7222-8333-44445555bbbb", "019a0000-2222-7222-8333-44445555cccc"

    def put_workdirs(self, first: object, second: object = None) -> None:
        named, unnamed = row(self.FIRST, "impl"), row(self.SECOND, "dup", verified=False)
        named["displayName"] = "impl"
        unnamed["displayName"] = "dup"
        for item, value in ((named, first), (unnamed, second)):
            if value is not None:
                item["workdir"] = value
        self.put(named, unnamed)

    def lines(self) -> list[str]:
        return directory.peer_lines(self.store, "win", now=NOW)

    def test_remote_rows_show_the_directory_unless_it_equals_the_shown_name(self) -> None:
        self.put_workdirs("repo-a", "dup")
        first, second = self.lines()[1:]
        self.assertTrue(first.endswith(f"target=--device win --to codex@id:{self.FIRST}  目录 repo-a"), first)
        self.assertTrue(second.endswith(f"target=--device win --to codex@id:{self.SECOND}"), second)  # 与展示名相同
        [device] = directory.peer_devices(self.store, "win", now=NOW)
        self.assertEqual([peer["workdir"] for peer in device["peers"]], ["repo-a", "dup"])

    def test_hostile_workdirs_are_cleaned_before_display(self) -> None:
        forged = "a\n设备 forged〔ffffffff〕：在线\u202e\u200b\x1b[2K"
        self.put_workdirs(forged, 5)
        lines = self.lines()
        self.assertEqual(len(lines), 3)  # 换行不能伪造出新行
        self.assertTrue(lines[1].endswith("  目录 a设备 forged〔ffffffff〕：在线[2K"), lines[1])
        self.assertFalse(any(char in "\n\x1b\u202e\u200b" for char in "".join(lines)))
        [device] = directory.peer_devices(self.store, "win", now=NOW)
        self.assertEqual([peer["workdir"] for peer in device["peers"]], ["a设备 forged〔ffffffff〕：在线[2K", None])
        self.put_workdirs("\n\t", "x" * 300)  # 去完只剩空白当作没有；超长按 120 字符截断
        [device] = directory.peer_devices(self.store, "win", now=NOW)
        self.assertEqual([peer["workdir"] for peer in device["peers"]], [None, "x" * 119 + "…"])

    def test_remote_length_limit_keeps_120_and_cuts_121(self) -> None:
        # 审计 r1 MN4/Y14：恰好 120 字符原样保留，121 字符截成 119 字符加省略号
        self.put_workdirs("x" * 120, "y" * 121)
        [device] = directory.peer_devices(self.store, "win", now=NOW)
        self.assertEqual([peer["workdir"] for peer in device["peers"]], ["x" * 120, "y" * 119 + "…"])

    def test_unverified_rows_compare_with_the_display_name(self) -> None:
        # 审计 r1 MN6/Y11：未核实且没有 name 的行，显示的是 displayName；它与目录相同就不重复写目录
        bare = row(self.SECOND)
        bare.update(namesVerified=False, displayName="dir-x", workdir="dir-x")
        self.put(row(self.FIRST, "impl"), bare)
        line = self.lines()[2]
        self.assertIn("名称=dir-x（仅展示）", line)
        self.assertNotIn("目录", line)

    def test_old_frames_without_workdir_keep_the_old_text(self) -> None:
        self.put_workdirs(None)
        self.assertEqual(self.lines()[1:], [
            f"  codex@impl〔019a0000-1〕 device=win target=--device win --to codex@id:{self.FIRST}",
            f"  codex@id:019a0000-2 名称=dup（仅展示） device=win target=--device win --to codex@id:{self.SECOND}"])
        [device] = directory.peer_devices(self.store, "win", now=NOW)
        self.assertEqual([peer["workdir"] for peer in device["peers"]], [None, None])


class WorkdirAndFeaturesTests(DirectoryCase):
    """G2 的行键 workdir（§95.3）与 fyi 的顶层键 features（§95.5.7）同在一份快照：预算顺序与新旧读方。"""

    def setUp(self) -> None:
        super().setUp()
        bound = patch.object(directory, "root_binding", return_value="f" * 32)  # 只测投影与预算，不测根核实
        bound.start()
        self.addCleanup(bound.stop)

    def live(self, index: int, *, workdir: str | None = "repo-a") -> object:
        [item] = with_name_views([replace(endpoint(ref(Provider.CODEX, _codex(index), pid=7000 + index),
                                                   name=f"w{index}"), workdir=workdir)])
        return item

    def test_budget_drops_workdir_then_rows_then_features(self) -> None:
        rows = [self.live(index) for index in range(1, 6)]
        full = directory.snapshot(self.store, DEV_A, rows, provider_complete={"codex": True})
        self.assertEqual(full["features"], ["fyi"])
        self.assertTrue(all("workdir" in item for item in full["endpoints"]))
        bare = directory.snapshot(self.store, DEV_A, [self.live(index, workdir=None) for index in range(1, 6)],
                                  provider_complete={"codex": True})
        # 只差 workdir：先静默去掉全部 workdir，不掉行，features 照发
        with patch.object(directory, "MAX_SNAPSHOT_BYTES", len(canonical_bytes(bare))):
            stripped = directory.snapshot(self.store, DEV_A, rows, provider_complete={"codex": True})
        self.assertEqual(canonical_bytes(stripped), canonical_bytes(bare))
        # 再紧：掉行并标不完整，features 仍在
        with patch.object(directory, "MAX_SNAPSHOT_BYTES", len(canonical_bytes(bare)) - 1):
            dropped = directory.snapshot(self.store, DEV_A, rows, provider_complete={"codex": True})
        self.assertEqual((len(dropped["endpoints"]), dropped["reason"], dropped["features"]),
                         (4, "snapshot_too_large", ["fyi"]))
        self.assertFalse(any("workdir" in item for item in dropped["endpoints"]))
        # 行掉光仍超限：最后才丢 features
        empty = directory.snapshot(self.store, DEV_A, [], provider_complete={"codex": True})
        with patch.object(directory, "MAX_SNAPSHOT_BYTES", len(canonical_bytes(empty)) - 1):
            last = directory.snapshot(self.store, DEV_A, rows, provider_complete={"codex": True})
        self.assertEqual(last["endpoints"], [])
        self.assertNotIn("features", last)

    def test_new_and_old_readers_with_a_workdir_row_and_features(self) -> None:
        document = directory.snapshot(self.store, DEV_A, [self.live(1), self.live(2, workdir=None)],
                                      provider_complete={"codex": True})
        self.assertEqual((document["features"], document["endpoints"][0]["workdir"]), (["fyi"], "repo-a"))
        self.store.put_device_state(device_id=DEV_B, name="win", revision=1, snapshot=document, last_seen=NOW,
                                    state="online")
        # 新读方：能力表与 workdir 都认，寻址不受影响
        self.assertEqual(directory.device_features(self.store, DEV_B), frozenset({"fyi"}))
        [device] = directory.peer_devices(self.store, "win", now=NOW)
        self.assertEqual([peer["workdir"] for peer in device["peers"]], ["repo-a", None])
        for selector, expected in (("codex@w1", _codex(1)), (f"codex@id:{_codex(1)}", _codex(1)),
                                   ("codex@w2", _codex(2))):
            with self.subTest(selector=selector):
                self.assertEqual(directory.resolve_remote(self.store, "win", selector, now=NOW).remote.native_id,
                                 expected)
                # 旧读方（104f286 预言机，不认这两个键）：照常按名字/完整 ID 选中同一行
                self.assertEqual(legacy.resolve_remote(self.store, "win", selector).remote.native_id, expected)


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
