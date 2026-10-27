"""P5 relay 部署模板（DESIGN §88.10/§88.14，T13）：Linux user service 与 Windows Limited 计划任务的约束钉住。

两个 relay 模板随镜像仓 agent-bridge 一起导出（scripts/mirror-bridge.py 的 PORTABLE_PACKAGING），本测试也随之进镜像。
"""

from __future__ import annotations

import configparser
import re
import unittest
import xml.etree.ElementTree as ET
from pathlib import Path

from agentstatus_bridge import cli

ROOT = Path(__file__).resolve().parents[1]
UNIT = ROOT / "packaging/systemd/agent-bridge-relay.service"
TASK = ROOT / "packaging/windows/agent-bridge-relay.task.xml"
NS = {"t": "http://schemas.microsoft.com/windows/2004/02/mit/task"}
# 公开模板不得写入私有部署路径（§88.14）；具体的私有部署名不写进随镜像公开的本文件，
# 由不导出的本仓测试 tests/test_mirror_bridge.py 对整个导出集检查
PRIVATE = re.compile(r"K:\\\\|/home/", re.IGNORECASE)


class LinuxUnitTests(unittest.TestCase):
    def setUp(self) -> None:
        parser = configparser.ConfigParser(strict=False, interpolation=None)  # systemd 允许多行 Environment=
        parser.optionxform = str  # type: ignore[assignment,method-assign]
        parser.read_string(UNIT.read_text(encoding="utf-8"))
        self.service = parser["Service"]
        self.install = parser["Install"]

    def test_runs_the_bound_ab_entry_without_a_shell(self) -> None:
        self.assertEqual(self.service["ExecStart"], "%h/.local/bin/ab federation relay")
        self.assertEqual(self.service["Type"], "simple")

    def test_restart_policy_matches_relay_exit_codes_and_backoff(self) -> None:
        self.assertEqual(self.service["Restart"], "on-failure")
        seconds = int(self.service["RestartSec"].removesuffix("s"))
        self.assertGreaterEqual(seconds, 30)  # 服务级重启不能快过自动重连下限
        self.assertEqual(self.service["RestartPreventExitStatus"], str(cli.EXIT_STORE))

    def test_worker_is_not_killed_or_sandboxed_with_the_relay(self) -> None:
        self.assertEqual(self.service["KillMode"], "process")
        for key in ("ProtectHome", "ProtectSystem", "ReadWritePaths", "PrivateTmp"):
            with self.subTest(key=key):
                self.assertNotIn(key, self.service)
        self.assertEqual(self.install["WantedBy"], "default.target")

    def test_no_private_values(self) -> None:
        self.assertIsNone(PRIVATE.search(UNIT.read_text(encoding="utf-8")))


class WindowsTaskTests(unittest.TestCase):
    def setUp(self) -> None:
        self.root = ET.fromstring(TASK.read_text(encoding="utf-8"))

    def text(self, path: str) -> str:
        node = self.root.find(path, NS)
        assert node is not None and node.text is not None, path
        return node.text

    def test_limited_interactive_logon_task(self) -> None:
        self.assertIsNotNone(self.root.find("t:Triggers/t:LogonTrigger", NS))
        self.assertEqual(self.text("t:Principals/t:Principal/t:LogonType"), "InteractiveToken")
        self.assertEqual(self.text("t:Principals/t:Principal/t:RunLevel"), "LeastPrivilege")

    def test_single_instance_no_time_limit_restart_after_a_minute(self) -> None:
        self.assertEqual(self.text("t:Settings/t:MultipleInstancesPolicy"), "IgnoreNew")
        self.assertEqual(self.text("t:Settings/t:ExecutionTimeLimit"), "PT0S")
        self.assertEqual(self.text("t:Settings/t:RestartOnFailure/t:Interval"), "PT1M")

    def test_watchdog_is_a_past_time_trigger_repeating_forever(self) -> None:
        # §89：conhost 不透传退出码、失败重启拿不到 relay 退出码；登录触发器的重复要等下次登录才生效，
        # 所以看门狗是起点在过去的时间触发器，注册当下即按 5 分钟重复；登录触发器只负责登录即启动
        self.assertIsNone(self.root.find("t:Triggers/t:LogonTrigger/t:Repetition", NS))
        self.assertEqual(self.text("t:Triggers/t:TimeTrigger/t:StartBoundary"), "2026-01-01T00:00:00")
        self.assertEqual(self.text("t:Triggers/t:TimeTrigger/t:Repetition/t:Interval"), "PT5M")
        self.assertEqual(self.text("t:Triggers/t:TimeTrigger/t:Repetition/t:StopAtDurationEnd"), "false")
        self.assertIsNone(self.root.find("t:Triggers/t:TimeTrigger/t:Repetition/t:Duration", NS))  # 无期限
        self.assertIsNone(self.root.find("t:Triggers/t:TimeTrigger/t:EndBoundary", NS))

    def test_triggers_stay_enabled(self) -> None:
        # Enabled 省略即默认 true（避开微软两份文档对它与 StartBoundary 先后的分歧）；写了也只能是 true
        triggers = self.root.findall("t:Triggers/*", NS)
        self.assertEqual([t.tag.split("}")[1] for t in triggers], ["LogonTrigger", "TimeTrigger"])
        for trigger in triggers:
            with self.subTest(trigger=trigger.tag):
                self.assertIn(trigger.findtext("t:Enabled", default="true", namespaces=NS), ("true",))

    def test_trigger_children_follow_the_schema_sequence(self) -> None:
        # 官方 schema（triggerBaseType/logonTriggerType）要求子元素按序：Enabled、StartBoundary、EndBoundary、
        # Repetition、ExecutionTimeLimit，登录触发器再接 UserId、Delay
        order = ["Enabled", "StartBoundary", "EndBoundary", "Repetition", "ExecutionTimeLimit", "UserId", "Delay"]
        for trigger in self.root.findall("t:Triggers/*", NS):
            names = [child.tag.split("}")[1] for child in trigger]
            with self.subTest(trigger=trigger.tag):
                self.assertEqual(names, sorted(names, key=order.index))

    def test_runs_ab_cmd_under_headless_conhost(self) -> None:
        # §89：交互令牌任务直接拉控制台程序会留常驻窗口；headless conhost 无窗口，ab.cmd 路径跨升级不变
        # §90：relay 监视启动它的 action conhost，Stop-ScheduledTask 结束 conhost 时随之停止
        self.assertEqual(self.text("t:Actions/t:Exec/t:Command"), "@SYSTEMROOT@\\System32\\conhost.exe")
        self.assertEqual(self.text("t:Actions/t:Exec/t:Arguments"),
                         '--headless "@SYSTEMROOT@\\System32\\cmd.exe" /d /c "@AB_CMD@" federation relay'
                         ' --watch-launch-anchor')

    def test_only_documented_placeholders(self) -> None:
        self.assertEqual(set(re.findall(r"@[A-Z_]+@", TASK.read_text(encoding="utf-8"))),
                         {"@USER@", "@SYSTEMROOT@", "@AB_CMD@"})

    def test_substituted_template_round_trips_through_xml(self) -> None:
        # 只证明 XML 层：替换值按 XML 转义写入后解析出的文本原样一致；命令行语义见下一条
        from xml.sax.saxutils import escape

        text = TASK.read_text(encoding="utf-8")
        values = {"@USER@": r"PC\A & B", "@SYSTEMROOT@": r"C:\Windows",
                  "@AB_CMD@": r"C:\Users\A B\.local\bin\ab.cmd"}
        for placeholder, value in values.items():
            text = text.replace(placeholder, escape(value))
        root = ET.fromstring(text)
        self.assertEqual(root.findtext("t:Actions/t:Exec/t:Command", namespaces=NS), r"C:\Windows\System32\conhost.exe")
        self.assertEqual(root.findtext("t:Actions/t:Exec/t:Arguments", namespaces=NS),
                         r'--headless "C:\Windows\System32\cmd.exe" /d /c "C:\Users\A B\.local\bin\ab.cmd" federation relay'
                         ' --watch-launch-anchor')
        self.assertEqual(root.findtext("t:Principals/t:Principal/t:UserId", namespaces=NS), r"PC\A & B")

    def test_command_line_reaches_ab_cmd_through_conhost_and_cmd(self) -> None:
        # 命令行语义的模型（不是实机证据，实机门另核）：conhost 先 CommandLineToArgvW 再逐项转义重拼
        # （OpenConsole ConsoleArguments.cpp），也考虑原样转交；cmd /c 按 `cmd /?` 的规则 1/2 处理引号
        arguments = self.text("t:Actions/t:Exec/t:Arguments").replace("@SYSTEMROOT@", r"C:\Windows")
        for path in (r"C:\Users\alice\.local\bin\ab.cmd", r"C:\Users\A B\.local\bin\ab.cmd"):
            for reescape in (True, False):
                with self.subTest(path=path, reescape=reescape):
                    self.assertEqual(_run_chain(arguments.replace("@AB_CMD@", path), reescape),
                                     (path, "federation relay --watch-launch-anchor"))

    def test_cmd_special_characters_in_the_path_are_not_supported(self) -> None:
        # 模板注释写明 ab.cmd 路径不得含 cmd 特殊字符（注册前校验）：模型里 & 会把命令拆开
        arguments = self.text("t:Actions/t:Exec/t:Arguments").replace("@SYSTEMROOT@", r"C:\Windows")
        for path in (r"C:\Users\A&B\ab.cmd", r"C:\Users\A & B\ab.cmd"):
            with self.subTest(path=path):
                self.assertNotEqual(_run_chain(arguments.replace("@AB_CMD@", path), True)[0], path)
        self.assertIn("路径不得含", TASK.read_text(encoding="utf-8"))

    def test_old_nested_quoting_breaks_on_spaces(self) -> None:
        # 反例：上一版 `/d /c ""@AB_CMD@" federation relay"` 经 conhost 重拼后，路径含空格时 cmd 拿到错误的程序
        old = r'--headless "C:\Windows\System32\cmd.exe" /d /c ""C:\Users\A B\ab.cmd" federation relay"'
        self.assertNotEqual(_run_chain(old, True)[0], r"C:\Users\A B\ab.cmd")

    def test_no_private_values(self) -> None:
        self.assertIsNone(PRIVATE.search(TASK.read_text(encoding="utf-8")))


_CMD_SPECIAL = set('&<>()@^|')


def _split_argv(line: str) -> list[str]:
    """CommandLineToArgvW 的反斜杠/引号规则（2n 个反斜杠加引号 → n 个反斜杠并切换引号；2n+1 → 字面引号）。"""
    args: list[str] = []
    current, quoted, have, i = "", False, False, 0
    while i < len(line):
        char = line[i]
        if char == "\\":
            count = 0
            while i < len(line) and line[i] == "\\":
                count += 1
                i += 1
            if i < len(line) and line[i] == '"':
                current += "\\" * (count // 2)
                if count % 2:
                    current += '"'
                    i += 1
                have = True
            else:
                current += "\\" * count
                have = True
            continue
        if char == '"':
            quoted, have = not quoted, True
        elif char in " \t" and not quoted:
            if have:
                args.append(current)
            current, have = "", False
        else:
            current, have = current + char, True
        i += 1
    if have:
        args.append(current)
    return args


def _escape_argument(arg: str) -> str:
    """OpenConsole 的 EscapeArgument：含空白或引号时加引号，引号前的反斜杠加倍。"""
    if arg and not any(c in arg for c in ' \t"'):
        return arg
    out, backslashes = '"', 0
    for char in arg:
        if char == "\\":
            backslashes += 1
            continue
        out += "\\" * (backslashes * 2 + 1) + '"' if char == '"' else "\\" * backslashes + char
        backslashes = 0
    return out + "\\" * (backslashes * 2) + '"'


def _cmd_c(command: str) -> tuple[str, str]:
    """cmd /c 的引号规则（`cmd /?`）：恰好两个引号、其间无特殊字符且含空白、是可执行文件名（模型按扩展名判，
    假定 .cmd 算）时保留引号；否则以引号开头时去掉第一个与最后一个引号。引号外的 & | < > 会把命令拆开，
    模型返回空程序表示失败。返回（程序，其余参数）。"""
    quotes = [i for i, c in enumerate(command) if c == '"']
    inner = command[1:quotes[1]] if len(quotes) >= 2 else ""
    keep = (len(quotes) == 2 and quotes[0] == 0 and not (set(inner) & _CMD_SPECIAL)
            and any(c in " \t" for c in inner) and inner.lower().endswith((".cmd", ".bat", ".exe", ".com")))
    if not keep and command.startswith('"') and quotes:
        last = quotes[-1]
        command = command[1:last] + command[last + 1:]
    quoted = False
    for char in command:
        quoted = not quoted if char == '"' else quoted
        if char in "&|<>" and not quoted:
            return "", command
    if command.startswith('"'):
        end = command.index('"', 1)
        return command[1:end], command[end + 1:].strip()
    program, _, rest = command.partition(" ")
    return program, rest.strip()


def _run_chain(arguments: str, reescape: bool) -> tuple[str, str]:
    """计划任务 Arguments → conhost（重拼或原样）→ cmd.exe /d /c → 最终执行的（程序，参数）。"""
    argv = _split_argv("conhost.exe " + arguments)
    assert argv[1] == "--headless"
    client = " ".join(_escape_argument(a) for a in argv[2:]) if reescape else arguments.split(" ", 1)[1]
    cmd_argv = _split_argv(client)
    assert cmd_argv[0].lower().endswith("cmd.exe") and cmd_argv[1:3] == ["/d", "/c"]
    return _cmd_c(client.split(" /c ", 1)[1])


if __name__ == "__main__":
    unittest.main()
