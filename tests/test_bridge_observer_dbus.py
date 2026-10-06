"""observer 的 D-Bus 回复解析（DESIGN §48 R4）与 pane 状态的取行（§55）。

回复解析：顺序与过滤、非字符串、按字符数的 4 MiB 上限、坏 JSON 与深嵌套；读不到（None）与零会话（空表）分开（§59）。
pane 状态：从 view 为该 pane 选中的同一行整行派生，不从别的行补字段。
枚举字段不是字符串时按缺字段处理，不抛 TypeError（§59）。

可移植：不依赖 observer 包，随镜像走。只替换最底层的 `_observer_rows`，不连 session bus。
"""

from __future__ import annotations

import json
import sys
import unittest
from unittest import mock

from agentstatus_bridge import observer_dbus
from agentstatus_bridge.hints import PaneState
from agentstatus_bridge.model import Provider, Runtime
from agentstatus_bridge.observer_dbus import _parse_observer_reply, agentstatus_view  # pyright: ignore[reportPrivateUsage]

LIMIT = 4 * 1024 * 1024


def _document_of_length(characters: int) -> str:
    """恰好 `characters` 个字符的合法 JSON 数组，内容用多字节汉字填充（UTF-8 字节数约为字符数的 3 倍）。"""
    head, tail = '[{"k":"', '"}]'
    return head + "中" * (characters - len(head) - len(tail)) + tail


class ParseObserverReplyTests(unittest.TestCase):
    def test_keeps_object_rows_in_order(self) -> None:
        raw = json.dumps([{"key": "a"}, 3, "x", {"key": "b"}, None, [], {"key": "c"}])
        self.assertEqual([{"key": "a"}, {"key": "b"}, {"key": "c"}], _parse_observer_reply(raw))

    def test_non_string_reply_is_unreadable(self) -> None:
        for raw in (None, b"[]", 123, [{"key": "a"}], {"key": "a"}):
            with self.subTest(raw=type(raw).__name__):
                self.assertIsNone(_parse_observer_reply(raw))

    def test_an_array_without_object_rows_is_readable_and_empty(self) -> None:
        # 零会话是「可读、空表」，不是「读不到」：doctor 靠这一点区分（DESIGN §59）
        for raw in ("[]", json.dumps([3, "x", None, []])):
            with self.subTest(raw=raw):
                self.assertEqual([], _parse_observer_reply(raw))

    def test_limit_counts_characters_not_bytes(self) -> None:
        # 字符数恰好 4 MiB、UTF-8 字节数远超 4 MiB：按字符数算必须接受；多 1 个字符必须拒绝（Opus P3-3）
        exact = _document_of_length(LIMIT)
        self.assertEqual(LIMIT, len(exact))
        self.assertGreater(len(exact.encode("utf-8")), LIMIT)
        self.assertEqual(1, len(_parse_observer_reply(exact)))
        over = _document_of_length(LIMIT + 1)
        json.loads(over)  # 多出的那个字符不影响 JSON 合法性，拒绝只因为超限
        self.assertIsNone(_parse_observer_reply(over))

    def test_bad_json_deep_nesting_and_non_array_are_unreadable(self) -> None:
        deep = "[" * 200_000 + "]" * 200_000
        with self.assertRaises(RecursionError):
            json.loads(deep)  # 前提：深嵌套抛的是 RecursionError，不是 ValueError
        for raw in ("[{", "not json", deep, json.dumps({"key": "a"}), json.dumps("text")):
            with self.subTest(raw=raw[:12]):
                self.assertIsNone(_parse_observer_reply(raw))


class ReadabilityTests(unittest.TestCase):
    """doctor 的「忙闲状态可读」：读不到是 None，零会话是空表，view 照旧把读不到当空（DESIGN §59）。"""

    def test_unreadable_zero_and_some_sessions_are_distinct(self) -> None:
        row: dict[str, object] = {"key": "claude:abc", "paneId": "%5", "freshness": "fresh", "runtimeState": "ready"}
        cases: list[tuple[list[dict[str, object]] | None, dict[str, Runtime] | None]] = [
            (None, None),
            ([], {}),
            ([row], {"%5": Runtime.IDLE, "claude:abc": Runtime.IDLE}),
        ]
        for reply, expected in cases:
            with self.subTest(reply=reply), mock.patch.object(observer_dbus, "_observer_rows", return_value=reply):
                self.assertEqual(expected, observer_dbus.agentstatus_runtime())
                try:
                    states = agentstatus_view().states
                except TypeError as error:  # 读不到时 view 当空：让回归以 FAIL 出现（Fable P3-2、Opus P3-5）
                    self.fail(f"读不到时 view 抛出 {error!r}")
                self.assertEqual(expected or {}, states)

    def test_each_call_reads_the_observer_once(self) -> None:
        # doctor 的 runtime 包装与 view 各自只读一次 ListSessions，不为判可读另读（Codex §59 复核 N01）
        for name, call in (("runtime", observer_dbus.agentstatus_runtime), ("view", agentstatus_view)):
            with self.subTest(call=name), mock.patch.object(observer_dbus, "_observer_rows", return_value=[]) as reads:
                call()
                self.assertEqual(1, reads.call_count)

    def test_a_failed_bus_call_is_unreadable(self) -> None:
        # 拿不到 gi 时 import 失败，与 D-Bus 调用失败走同一个分支：返回 None，不是空表
        with mock.patch.dict(sys.modules, {"gi": None}):
            self.assertIsNone(observer_dbus._observer_rows())  # pyright: ignore[reportPrivateUsage]


class NonStringEnumTests(unittest.TestCase):
    """`freshness`、`runtimeState` 不是字符串时按缺字段处理：不抛 TypeError，结果与删掉该字段完全相同（DESIGN §59）。"""

    BASE: dict[str, object] = {
        "key": "claude:abc", "paneId": "%5", "freshness": "fresh", "runtimeState": "ready", "lastTurnEndedAt": 100,
    }

    def _row_of(self, item: dict[str, object]) -> observer_dbus.ObserverRow:
        try:
            with mock.patch.object(observer_dbus, "_observer_rows", return_value=[item]):
                row = agentstatus_view().row("%5")
        except TypeError as error:  # 让缺陷以 FAIL 出现，而不是 ERROR
            self.fail(f"非字符串的枚举值让选行抛出 {error!r}")
        assert row is not None
        return row

    def test_non_string_values_behave_like_a_missing_field(self) -> None:
        for field in ("freshness", "runtimeState"):
            expected = self._row_of({key: value for key, value in self.BASE.items() if key != field})
            for value in ([], ["stale"], {}, {"state": "ready"}):
                with self.subTest(field=field, value=value):
                    got = self._row_of({**self.BASE, field: value})
                    self.assertEqual((expected.runtime, expected.fresh), (got.runtime, got.fresh))

    def test_string_values_keep_their_meaning(self) -> None:
        stale = self._row_of({**self.BASE, "freshness": "stale"})
        self.assertEqual((Runtime.UNKNOWN, False), (stale.runtime, stale.fresh))
        ready = self._row_of(dict(self.BASE))
        self.assertEqual((Runtime.IDLE, True), (ready.runtime, ready.fresh))
        # 现行语义：缺 freshness 算新鲜，缺 runtimeState 得 UNKNOWN
        no_freshness = self._row_of({key: value for key, value in self.BASE.items() if key != "freshness"})
        self.assertEqual((Runtime.IDLE, True), (no_freshness.runtime, no_freshness.fresh))
        no_state = self._row_of({key: value for key, value in self.BASE.items() if key != "runtimeState"})
        self.assertEqual((Runtime.UNKNOWN, True), (no_state.runtime, no_state.fresh))
        # 读方不比写方严：将来新增的 freshness 取值与缺字段同样算新鲜（59.4 保留的现行语义，Opus P3-6）
        future = self._row_of({**self.BASE, "freshness": "some-future-value"})
        self.assertEqual((no_freshness.runtime, no_freshness.fresh), (future.runtime, future.fresh))

    def test_time_fields_that_are_not_finite_behave_like_a_missing_field(self) -> None:
        # 超大整数、NaN、无穷：不抛，与缺字段相同（DESIGN §59，Opus P3-1）
        for field in ("runtimeUpdatedAt", "lastTurnEndedAt"):
            for value in (10**400, float("nan"), float("inf"), float("-inf")):
                with self.subTest(field=field, value=repr(value)[:12]):
                    try:
                        row = self._row_of({**self.BASE, field: value})
                    except (OverflowError, ValueError) as error:
                        self.fail(f"时刻字段让选行抛出 {error!r}")
                    self.assertIsNone(row.runtime_at if field == "runtimeUpdatedAt" else row.last_turn_ended_at)
        # 对照：有限数值照收
        self.assertEqual(100.0, self._row_of(dict(self.BASE)).last_turn_ended_at)


# 行模板：`lastTurnEndedAt` 是每行的身份标记，`runtimeUpdatedAt` 故意取不同的值，读错字段就会变红（§55.4 用例 1）
_STATES: dict[str, dict[str, object]] = {
    "idle": {"runtimeState": "ready"},
    "busy": {"runtimeState": "working"},
    "wait": {"runtimeState": "working", "attentionState": "action_required"},
}
_FRESHNESS = {"F": "fresh", "A": "aging", "S": "stale", "U": "unavailable"}


def _row(template: str, ended: float | None, *, pane: str = "%5") -> dict[str, object]:
    """`F-idle` 这类模板 → 一条 ListSessions 行；ended 为 None 时不带 `lastTurnEndedAt`。"""
    freshness, state = template.split("-")
    row: dict[str, object] = {"paneId": pane, "freshness": _FRESHNESS[freshness], **_STATES[state]}
    if ended is not None:
        row["lastTurnEndedAt"] = ended
        row["runtimeUpdatedAt"] = ended + 1000
    return row


def _selected(rows: list[dict[str, object]], pane: str = "%5") -> PaneState | None:
    with mock.patch.object(observer_dbus, "_observer_rows", return_value=rows):
        return agentstatus_view().pane_state(pane, Provider.CLAUDE)  # 行不带 agent：任意 provider 都匹配


class ProviderPaneTests(unittest.TestCase):
    """按 pane 取行只认同 provider 的行，不借同 pane 别家的行（DESIGN §62 ④）。"""

    def view(self, rows: list[dict[str, object]]):
        with mock.patch.object(observer_dbus, "_observer_rows", return_value=rows):
            return agentstatus_view()

    def test_each_provider_gets_its_own_row_on_a_shared_pane(self) -> None:
        view = self.view([
            {"paneId": "%5", "agent": "claude", "runtimeState": "ready", "freshness": "fresh", "lastTurnEndedAt": 100.0},
            {"paneId": "%5", "agent": "codex", "runtimeState": "working", "freshness": "fresh", "lastTurnEndedAt": 200.0},
        ])
        claude, codex = view.pane_state("%5", Provider.CLAUDE), view.pane_state("%5", Provider.CODEX)
        assert claude is not None and codex is not None
        self.assertEqual((claude.runtime, claude.last_turn_ended_at), (Runtime.IDLE, 100.0))
        self.assertEqual((codex.runtime, codex.last_turn_ended_at), (Runtime.BUSY, 200.0))
        self.assertIsNone(view.pane_state("%5", Provider.GROK))
        self.assertIsNone(view.pane_runtime("%5", Provider.GROK))

    def test_selection_rules_apply_within_a_provider(self) -> None:
        # 同 provider 两行：新鲜优先；另一家的新鲜行不参与这一组的选择
        view = self.view([
            {"paneId": "%5", "agent": "codex", "runtimeState": "ready", "freshness": "fresh", "lastTurnEndedAt": 101.0},
            {"paneId": "%5", "agent": "codex", "runtimeState": "ready", "freshness": "stale", "lastTurnEndedAt": 102.0},
            {"paneId": "%5", "agent": "claude", "runtimeState": "working", "attentionState": "action_required",
             "freshness": "fresh"},
        ])
        codex = view.pane_state("%5", Provider.CODEX)
        assert codex is not None
        self.assertEqual((codex.runtime, codex.fresh, codex.last_turn_ended_at), (Runtime.IDLE, True, 101.0))
        self.assertIs(view.pane_runtime("%5", Provider.CLAUDE), Runtime.WAITING)

    def test_rows_without_an_agent_match_any_provider_but_lose_to_a_matching_one(self) -> None:
        # 不发 agent 的写方照旧按 pane 匹配（读方不比写方严）；同 provider 的行在场时以它为准
        bare = {"paneId": "%5", "runtimeState": "ready", "freshness": "fresh", "lastTurnEndedAt": 100.0}
        view = self.view([bare])
        for provider in Provider:
            with self.subTest(provider=provider.value):
                self.assertIs(view.pane_runtime("%5", provider), Runtime.IDLE)
        view = self.view([bare, {"paneId": "%5", "agent": "codex", "runtimeState": "working", "freshness": "fresh"}])
        self.assertIs(view.pane_runtime("%5", Provider.CODEX), Runtime.BUSY)
        self.assertIs(view.pane_runtime("%5", Provider.CLAUDE), Runtime.IDLE)

    def test_a_non_string_agent_is_treated_as_missing(self) -> None:
        view = self.view([{"paneId": "%5", "agent": 5, "runtimeState": "ready", "freshness": "fresh"}])
        row = view.pane_row("%5", Provider.CLAUDE)
        assert row is not None
        self.assertIsNone(row.agent)


class PaneStateTests(unittest.TestCase):
    """pane 状态取 view 为该 pane 选中的那一行，三个字段整行同出（DESIGN §55.2 第 2 条、§55.4 用例 1、2）。"""

    def test_whole_row_comes_from_the_row_the_view_selects(self) -> None:
        # 一般规则的代表：新鲜 IDLE 行后面还有不新鲜的行时，旧的「取末行」会选错；两种行序都要选中新鲜那一行
        cases: list[tuple[list[tuple[str, float]], float]] = [
            ([("F-idle", 101.0), ("S-idle", 102.0)], 101.0),
            ([("S-idle", 102.0), ("F-idle", 101.0)], 101.0),
            ([("A-idle", 103.0), ("U-idle", 104.0)], 103.0),
            ([("U-idle", 104.0), ("A-idle", 103.0)], 103.0),
            ([("F-idle", 105.0), ("S-busy", 106.0)], 105.0),
            ([("S-busy", 106.0), ("F-idle", 105.0)], 105.0),
            # 三行：没有新鲜 WAITING 时取最后一条新鲜行
            ([("F-busy", 107.0), ("F-idle", 108.0), ("S-idle", 109.0)], 108.0),
            ([("S-idle", 109.0), ("F-idle", 108.0), ("F-busy", 107.0)], 107.0),
        ]
        expected_state = {101.0: Runtime.IDLE, 103.0: Runtime.IDLE, 105.0: Runtime.IDLE, 107.0: Runtime.BUSY, 108.0: Runtime.IDLE}
        for rows, chosen in cases:
            with self.subTest(rows=[name for name, _ in rows]):
                state = _selected([_row(name, ended) for name, ended in rows])
                self.assertEqual(state, PaneState(expected_state[chosen], chosen, True))

    def test_missing_end_time_on_the_selected_row_is_not_borrowed(self) -> None:
        # 胜出行没有结束时刻：仍返回胜出行，不从败选行补（Codex N04）
        state = _selected([_row("F-idle", None), _row("S-idle", 110.0)])
        self.assertEqual(state, PaneState(Runtime.IDLE, None, True))

    def test_first_fresh_waiting_row_is_kept(self) -> None:
        state = _selected([_row("F-wait", 111.0), _row("F-wait", 112.0), _row("F-idle", 113.0)])
        self.assertEqual(state, PaneState(Runtime.WAITING, 111.0, True))

    def test_last_row_wins_when_none_is_fresh(self) -> None:
        # 全不新鲜时 runtime 都是 UNKNOWN：按结束时刻判断取的是哪一行
        state = _selected([_row("S-idle", 114.0), _row("U-busy", 115.0)])
        self.assertEqual(state, PaneState(Runtime.UNKNOWN, 115.0, False))

    def test_single_row_mapping(self) -> None:
        """单行映射（迁自原 `_pane_state` 用例）：aging 算新鲜，非数值与布尔的结束时刻丢弃。"""
        cases: list[tuple[dict[str, object], PaneState]] = [
            ({"runtimeState": "ready", "freshness": "fresh", "lastTurnEndedAt": 1700000000.5}, PaneState(Runtime.IDLE, 1700000000.5, True)),
            ({"runtimeState": "ready", "freshness": "stale", "lastTurnEndedAt": True}, PaneState(Runtime.UNKNOWN, None, False)),
            ({"runtimeState": "ready", "freshness": "fresh", "lastTurnEndedAt": "200"}, PaneState(Runtime.IDLE, None, True)),
            ({"runtimeState": "working", "attentionState": "action_required", "freshness": "aging"}, PaneState(Runtime.WAITING, None, True)),
            (
                {"runtimeState": "ready", "freshness": "fresh", "activeChildren": 1, "lastTurnEndedAt": 1700000000.5},
                PaneState(Runtime.BACKGROUND, 1700000000.5, True),
            ),
        ]
        for item, expected in cases:
            with self.subTest(item=item):
                self.assertEqual(_selected([{"paneId": "%5", **item}]), expected)

    def test_rows_without_a_pane_have_no_pane_state(self) -> None:
        rows: list[dict[str, object]] = [
            {"key": "claude:" + "a" * 24, "runtimeState": "ready", "freshness": "fresh", "lastTurnEndedAt": 120.0},
            {"paneId": 5, "runtimeState": "ready", "freshness": "fresh", "lastTurnEndedAt": 121.0},
        ]
        with mock.patch.object(observer_dbus, "_observer_rows", return_value=rows):
            view = agentstatus_view()
        self.assertEqual(set(view.rows), {"claude:" + "a" * 24})
        self.assertIsNone(view.pane_state("%5", Provider.CLAUDE))
        self.assertIsNone(view.pane_state("5", Provider.CLAUDE))


if __name__ == "__main__":
    unittest.main()
