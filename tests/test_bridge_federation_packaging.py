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

    def test_runs_the_native_entry_with_relay_arguments(self) -> None:
        self.assertEqual(self.text("t:Actions/t:Exec/t:Command"), "@AB_EXE@")
        self.assertEqual(self.text("t:Actions/t:Exec/t:Arguments"), "federation relay")

    def test_no_private_values(self) -> None:
        self.assertIsNone(PRIVATE.search(TASK.read_text(encoding="utf-8")))


if __name__ == "__main__":
    unittest.main()
