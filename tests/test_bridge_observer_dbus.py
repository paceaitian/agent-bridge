"""observer 的 D-Bus 回复解析（DESIGN §48 R4）：顺序与过滤、非字符串、按字符数的 4 MiB 上限、坏 JSON 与深嵌套。

可移植：不依赖 observer 包，随镜像走。只测纯函数 `_parse_observer_reply`，不连 session bus。
"""

from __future__ import annotations

import json
import unittest

from agentstatus_bridge.observer_dbus import _parse_observer_reply  # pyright: ignore[reportPrivateUsage]

LIMIT = 4 * 1024 * 1024


def _document_of_length(characters: int) -> str:
    """恰好 `characters` 个字符的合法 JSON 数组，内容用多字节汉字填充（UTF-8 字节数约为字符数的 3 倍）。"""
    head, tail = '[{"k":"', '"}]'
    return head + "中" * (characters - len(head) - len(tail)) + tail


class ParseObserverReplyTests(unittest.TestCase):
    def test_keeps_object_rows_in_order(self) -> None:
        raw = json.dumps([{"key": "a"}, 3, "x", {"key": "b"}, None, [], {"key": "c"}])
        self.assertEqual([{"key": "a"}, {"key": "b"}, {"key": "c"}], _parse_observer_reply(raw))

    def test_non_string_reply_is_empty(self) -> None:
        for raw in (None, b"[]", 123, [{"key": "a"}], {"key": "a"}):
            with self.subTest(raw=type(raw).__name__):
                self.assertEqual([], _parse_observer_reply(raw))

    def test_limit_counts_characters_not_bytes(self) -> None:
        # 字符数恰好 4 MiB、UTF-8 字节数远超 4 MiB：按字符数算必须接受；多 1 个字符必须拒绝（Opus P3-3）
        exact = _document_of_length(LIMIT)
        self.assertEqual(LIMIT, len(exact))
        self.assertGreater(len(exact.encode("utf-8")), LIMIT)
        self.assertEqual(1, len(_parse_observer_reply(exact)))
        over = _document_of_length(LIMIT + 1)
        json.loads(over)  # 多出的那个字符不影响 JSON 合法性，拒绝只因为超限
        self.assertEqual([], _parse_observer_reply(over))

    def test_bad_json_deep_nesting_and_non_array_are_empty(self) -> None:
        deep = "[" * 200_000 + "]" * 200_000
        with self.assertRaises(RecursionError):
            json.loads(deep)  # 前提：深嵌套抛的是 RecursionError，不是 ValueError
        for raw in ("[{", "not json", deep, json.dumps({"key": "a"}), json.dumps("text")):
            with self.subTest(raw=raw[:12]):
                self.assertEqual([], _parse_observer_reply(raw))


if __name__ == "__main__":
    unittest.main()
