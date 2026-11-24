"""§104.4 正文输入统一：retry 的可选正文、report 说明的三种来源与 note_too_large（本机与跨设备）。"""

from __future__ import annotations

import json
import sys
import unittest
from io import BytesIO, TextIOWrapper
from pathlib import Path
from unittest.mock import patch

import bridge_support  # noqa: F401  导入即隔离宿主会话环境
import test_bridge_cli as local_base  # 只借夹具方法；不把 CliTests 导入本模块命名空间，免得被重复收集
import test_bridge_federation_cli as fed_base

from agentstatus_bridge import cli
from agentstatus_bridge.federation import commands as fed_commands
from agentstatus_bridge.labels import REASON_TEXTS
from agentstatus_bridge.model import Delivery, ReportKind, Work
from agentstatus_bridge.reports import MAX_NOTE_CHARS, ReportError, ReportInput, apply_report, checked_note
from agentstatus_bridge.store import MAX_BODY_BYTES
from agentstatus_bridge.transports import DeliveryOutcome


class _ExplodingStdin:
    """非终端 stdin，读一下就抛：证明可选正文不给 `-` 时不碰标准输入。"""

    class _Buffer:
        def read(self, *_args: object) -> bytes:
            raise AssertionError("stdin was read")

    buffer = _Buffer()

    def isatty(self) -> bool:
        return False

    def read(self, *_args: object) -> str:
        raise AssertionError("stdin was read")


class LocalInputTests(unittest.TestCase):
    setUp = local_base.CliTests.setUp
    run_cli = local_base.CliTests.run_cli
    send = local_base.CliTests.send
    store = local_base.CliTests.store
    mark_sent = local_base.CliTests.mark_sent

    def with_stdin(self, data: bytes, *argv: str) -> tuple[int, str, str]:
        # 文字层故意用 cp1252：读到的必须是原始字节（与 send 的 §101.2 用例同一手法）
        with TextIOWrapper(BytesIO(data), encoding="cp1252") as stream, patch.object(sys, "stdin", stream):
            return self.run_cli(*argv)

    def sent_task(self) -> str:
        task_id = self.send()
        self.mark_sent(task_id)
        self.caller = local_base.as_agent(local_base.IMPL)
        return task_id

    def note_of(self, task_id: str) -> object:
        with self.store() as store:
            work = [item for item in store.attempts(task_id) if item.role.value == "handoff"][-1]
            return (work.result or {}).get("note")

    # ---- report 说明 ----

    def test_report_note_from_stdin_and_file(self) -> None:
        task_id = self.sent_task()
        code, _, err = self.with_stdin("中文说明😀\n第二行".encode("utf-8"), "report", task_id, "--progress",
                                       "--note", "-")
        self.assertEqual(code, 0, err)
        with self.store() as store:
            [event] = [item for item in store.events(task_id) if item["kind"] == "progress"]
        self.assertEqual(event["detail"]["note"], "中文说明😀\n第二行")
        path = Path(self._tmp.name) / "note.txt"
        path.write_bytes("  文件里的结论  \n".encode("utf-8"))
        code, _, err = self.run_cli("report", task_id, "--result", "--note-file", str(path))
        self.assertEqual(code, 0, err)
        self.assertEqual(self.note_of(task_id), "文件里的结论")

    def test_note_and_note_file_conflict(self) -> None:
        task_id = self.sent_task()
        path = Path(self._tmp.name) / "note.txt"
        path.write_text("x", encoding="utf-8")
        code, _, err = self.run_cli("report", task_id, "--result", "--note", "a", "--note-file", str(path))
        self.assertEqual(code, cli.EXIT_REJECTED)
        self.assertIn("[note_and_file_conflict]", err)
        self.assertIn(REASON_TEXTS["note_and_file_conflict"], err)
        self.assertIsNone(self.note_of(task_id))

    def test_note_too_large_is_rejected_before_any_lookup_or_write(self) -> None:
        task_id = self.sent_task()
        # 恰好上限（strip 后按字符计）可交；首尾空白不计
        code, _, err = self.run_cli("report", task_id, "--progress", "--note", "  " + "字" * MAX_NOTE_CHARS + "\n")
        self.assertEqual(code, 0, err)
        with self.store() as store:
            before = (len(store.events(task_id, limit=1000)), [item.work for item in store.attempts(task_id)])
        # 多一个字：拒绝，且在找任务（含联邦查找）之前——任务、账本都没被碰
        with patch.object(cli, "_fed_lookup", side_effect=AssertionError("looked up before note check")), \
                patch.object(cli, "_open_store", side_effect=AssertionError("opened store before note check")):
            code, out, err = self.run_cli("report", task_id, "--result", "--note", "字" * (MAX_NOTE_CHARS + 1))
        self.assertEqual(code, cli.EXIT_REJECTED)
        self.assertEqual(out, "")
        self.assertIn("[note_too_large]", err)
        self.assertIn("--file", err)  # 提示改用附件
        with self.store() as store:
            after = (len(store.events(task_id, limit=1000)), [item.work for item in store.attempts(task_id)])
        self.assertEqual(after, before)
        self.assertIsNone(self.note_of(task_id))

    def test_note_too_large_from_stdin_and_oversized_file(self) -> None:
        task_id = self.sent_task()
        code, _, err = self.with_stdin(("x" * (MAX_NOTE_CHARS + 1)).encode(), "report", task_id, "--result",
                                       "--note", "-")
        self.assertEqual((code, "[note_too_large]" in err), (cli.EXIT_REJECTED, True), err)
        # 文件超过 64 KiB 同样报 note_too_large（不是正文的 message_too_large）
        path = Path(self._tmp.name) / "big.txt"
        path.write_bytes(b"y" * (MAX_BODY_BYTES + 1))
        code, _, err = self.run_cli("report", task_id, "--result", "--note-file", str(path))
        self.assertEqual((code, "[note_too_large]" in err), (cli.EXIT_REJECTED, True), err)
        stdin_big = b"z" * (MAX_BODY_BYTES + 1)
        code, _, err = self.with_stdin(stdin_big, "report", task_id, "--result", "--note", "-")
        self.assertEqual((code, "[note_too_large]" in err), (cli.EXIT_REJECTED, True), err)
        self.assertIsNone(self.note_of(task_id))

    def test_note_file_errors_and_non_utf8_path_is_exempt(self) -> None:
        task_id = self.sent_task()
        bad = Path(self._tmp.name) / "bad.txt"
        bad.write_bytes(b"caf\xe9")
        code, _, err = self.run_cli("report", task_id, "--result", "--note-file", str(bad))
        self.assertEqual((code, "[message_invalid_utf8]" in err), (cli.EXIT_REJECTED, True), err)
        code, _, err = self.run_cli("report", task_id, "--result", "--note-file", str(bad) + ".missing")
        self.assertEqual((code, "[file_unreadable]" in err), (cli.EXIT_REJECTED, True), err)
        # --note-file 只是来源路径：编码不成 UTF-8 的文件名不按参数非法拒绝，交给文件系统（这里文件不存在）
        code, _, err = self.run_cli("report", task_id, "--result", "--note-file", "/nonexistent/\udcff.txt")
        self.assertEqual((code, "[file_unreadable]" in err), (cli.EXIT_REJECTED, True), err)
        # --note 本身仍受统一参数检查
        code, _, err = self.run_cli("report", task_id, "--result", "--note", "x\udcff")
        self.assertIn("[argument_invalid_utf8]", err)

    def test_ask_reads_the_validated_note_from_any_source(self) -> None:
        # 合并口径：--ask 读 cmd_report 顶部 _read_note 读好、校验过长度的 args.note
        task_id = self.sent_task()
        path = Path(self._tmp.name) / "question.txt"
        path.write_text("用方案 A 还是 B？", encoding="utf-8")
        code, _, err = self.run_cli("report", task_id, "--ask", "--note-file", str(path))
        self.assertEqual(code, 0, err)
        with self.store() as store:
            work = [item for item in store.attempts(task_id) if item.role.value == "handoff"][-1]
        self.assertEqual(work.options.get("ask", {}).get("note"), "用方案 A 还是 B？")
        # 超长说明在 --ask 下同样在找任务与任何写入之前报 note_too_large
        with patch.object(cli, "_fed_lookup", side_effect=AssertionError("looked up before note check")):
            code, _, err = self.run_cli("report", task_id, "--ask", "--note", "问" * (MAX_NOTE_CHARS + 1))
        self.assertEqual((code, "[note_too_large]" in err), (cli.EXIT_REJECTED, True), err)

    def test_report_without_note_never_reads_non_tty_stdin(self) -> None:
        task_id = self.sent_task()
        with patch.object(sys, "stdin", _ExplodingStdin()):
            code, _, err = self.run_cli("report", task_id, "--ack")
        self.assertEqual(code, 0, err)

    def test_apply_report_keeps_the_same_check_as_defence(self) -> None:
        self.assertEqual(checked_note("  ok \n"), "ok")
        self.assertEqual(checked_note(None), "")
        with self.assertRaises(ReportError) as caught:
            checked_note("a" * (MAX_NOTE_CHARS + 1))
        self.assertEqual(caught.exception.code, "note_too_large")
        task_id = self.sent_task()
        with self.store() as store, self.assertRaises(ReportError) as caught:
            apply_report(store, ReportInput(task_ref=task_id, kind=ReportKind.RESULT,
                                            note="b" * (MAX_NOTE_CHARS + 1)),
                         caller=self.caller, caller_class="bypass", now=10.0, cwd=Path(self._tmp.name))
        self.assertEqual(caught.exception.code, "note_too_large")
        self.assertIsNone(self.note_of(task_id))

    # ---- retry 可选正文 ----

    def blocked_task(self) -> str:
        task_id = self.sent_task()
        self.assertEqual(self.run_cli("report", task_id, "--blocked", "--note", "缺权限")[0], 0)
        self.caller = local_base.USER  # send() 由用户发起：用户可以返工
        return task_id

    def latest_body(self, task_id: str) -> str:
        with self.store() as store:
            return [item for item in store.attempts(task_id) if item.role.value == "handoff"][-1].body

    # ---- 返工措辞（端到端） ----

    def result_task(self) -> str:
        task_id = self.sent_task()
        self.assertEqual(self.run_cli("report", task_id, "--result", "--note", "已实现")[0], 0)
        self.caller = local_base.USER
        return task_id

    def test_retry_after_result_uses_new_wording_and_reassignment_label(self) -> None:
        task_id = self.result_task()
        code, _, err = self.run_cli("retry", task_id, "-m", "补测试")
        self.assertEqual(code, 0, err)
        body = self.latest_body(task_id)
        self.assertTrue(body.startswith("【返工】\n发起方看过结果，请按下面的要求继续：\n补测试\n你上次的结论：已实现"), body)
        self.mark_sent(task_id)
        self.caller = local_base.as_agent(local_base.IMPL)
        self.assertEqual(self.run_cli("report", task_id, "--result", "--note", "第二版")[0], 0)
        self.caller = local_base.USER
        code, _, err = self.run_cli("retry", task_id, "--to", "codex@lead", "-m", "换人看看")
        self.assertEqual(code, 0, err)
        body = self.latest_body(task_id)
        self.assertIn("上一位执行方的结论：第二版", body)
        self.assertNotIn("你上次的结论", body)

    def test_forced_retry_after_rework_keeps_the_rework_requirement_once(self) -> None:
        task_id = self.result_task()
        self.assertEqual(self.run_cli("retry", task_id, "-m", "改 X")[0], 0)
        for round_ in (1, 2):
            self.mark_sent(task_id)
            self.caller = local_base.as_agent(local_base.IMPL)
            self.assertEqual(self.run_cli("report", task_id, "--progress")[0], 0)
            self.caller = local_base.USER
            code, _, err = self.run_cli("retry", task_id, "--force", "-m", f"第 {round_} 次重发")
            self.assertEqual(code, 0, err)
            body = self.latest_body(task_id)
            self.assertTrue(body.startswith(cli.RESEND_HEADER + f"\n补充：第 {round_} 次重发"), body)
            self.assertEqual(body.count("【重发】"), 1)
            self.assertIn("改 X", body)

    def test_forced_retry_of_a_review_resends_the_review_request(self) -> None:
        task_id = self.send("--review-by", "claude@review")
        self.mark_sent(task_id)
        self.caller = local_base.as_agent(local_base.IMPL)
        self.assertEqual(self.run_cli("report", task_id, "--result", "--note", "OK")[0], 0)
        self.mark_sent(task_id)
        with self.store() as store:
            review = [item for item in store.attempts(task_id) if item.role.value == "review"][-1]
        self.caller = local_base.USER
        code, _, err = self.run_cli("retry", task_id, "--force")
        self.assertEqual(code, 0, err)
        with self.store() as store:
            latest = [item for item in store.attempts(task_id) if item.role.value == "review"][-1]
        self.assertGreater(latest.seq, review.seq)
        self.assertEqual(latest.body, f"{cli.RESEND_HEADER}\n\n{review.body.rstrip()}")

    def test_forced_retry_while_in_progress_is_a_resend_notice(self) -> None:
        task_id = self.sent_task()
        self.assertEqual(self.run_cli("report", task_id, "--progress", "--note", "进行中")[0], 0)
        self.caller = local_base.USER
        code, _, err = self.run_cli("retry", task_id, "--force", "-m", "再看一下")
        self.assertEqual(code, 0, err)
        body = self.latest_body(task_id)
        self.assertTrue(body.startswith(cli.RESEND_HEADER + "\n补充：再看一下"), body)

    def test_forced_retry_to_another_session_is_a_handover_not_a_resend(self) -> None:
        # §104.11 一并修：--force --to 改派到另一个会话，对方没收过上一条，不写「可能已经送达」
        task_id = self.sent_task()
        self.assertEqual(self.run_cli("report", task_id, "--progress")[0], 0)
        self.caller = local_base.USER
        code, _, err = self.run_cli("retry", task_id, "--force", "--to", "codex@lead", "-m", "接手")
        self.assertEqual(code, 0, err)
        body = self.latest_body(task_id)
        self.assertTrue(body.startswith(cli.REASSIGN_HEADER + "\n补充：接手\n\n实现 X"), body)
        self.assertNotIn("【重发】", body)
        # 接着对同一会话 --force：回到【重发】，上一轮的改派首行被替换，不嵌套
        self.mark_sent(task_id)
        code, _, err = self.run_cli("retry", task_id, "--force")
        self.assertEqual(code, 0, err)
        body = self.latest_body(task_id)
        self.assertTrue(body.startswith(cli.RESEND_HEADER + "\n\n补充：接手\n\n实现 X"), body)
        self.assertNotIn("【改派】", body)

    def test_forced_retry_after_review_approved_asks_for_a_fresh_review(self) -> None:
        task_id = self.send("--review-by", "claude@review")
        self.mark_sent(task_id)
        self.caller = local_base.as_agent(local_base.IMPL)
        self.assertEqual(self.run_cli("report", task_id, "--result", "--note", "OK")[0], 0)
        self.mark_sent(task_id)
        self.caller = local_base.as_agent(local_base.REVIEW)
        self.assertEqual(self.run_cli("report", task_id, "--approve", "--note", "通过")[0], 0)
        with self.store() as store:
            review = [item for item in store.attempts(task_id) if item.role.value == "review"][-1]
        self.caller = local_base.USER
        code, _, err = self.run_cli("retry", task_id, "--force")
        self.assertEqual(code, 0, err)
        with self.store() as store:
            latest = [item for item in store.attempts(task_id) if item.role.value == "review"][-1]
        self.assertEqual(latest.body, f"{cli.REREVIEW_HEADER}\n\n{review.body.rstrip()}")
        self.assertNotIn("【重发】", latest.body)

    def test_retry_dash_reads_stdin_instead_of_literal_dash(self) -> None:
        task_id = self.blocked_task()
        code, _, err = self.with_stdin("已授权\n第二行要求".encode("utf-8"), "retry", task_id, "-m", "-")
        self.assertEqual(code, 0, err)
        body = self.latest_body(task_id)
        self.assertIn("补充：已授权\n第二行要求", body)
        self.assertNotIn("补充：-", body)

    def test_retry_file_and_conflict(self) -> None:
        task_id = self.blocked_task()
        path = Path(self._tmp.name) / "ask.txt"
        path.write_text("按文件里的要求继续", encoding="utf-8")
        code, _, err = self.run_cli("retry", task_id, "-m", "x", "--file", str(path))
        self.assertEqual((code, "[message_and_file_conflict]" in err), (cli.EXIT_REJECTED, True), err)
        code, _, err = self.run_cli("retry", task_id, "--file", str(path))
        self.assertEqual(code, 0, err)
        self.assertIn("补充：按文件里的要求继续", self.latest_body(task_id))

    def test_retry_without_message_never_reads_non_tty_stdin(self) -> None:
        task_id = self.blocked_task()
        with patch.object(sys, "stdin", _ExplodingStdin()):
            code, _, err = self.run_cli("retry", task_id)
        self.assertEqual(code, 0, err)
        self.assertNotIn("补充：", self.latest_body(task_id))

    def test_send_and_note_keep_implicit_stdin(self) -> None:
        # 必填正文维持现状：不给 -m 且 stdin 不是终端时照旧读 stdin
        code, out, err = self.with_stdin("隐式正文".encode("utf-8"), "send", "--to", "codex@impl", "--no-wait",
                                         "--json")
        self.assertEqual(code, 0, err)
        with self.store() as store:
            [first] = store.attempts(json.loads(out)["id"])
        self.assertEqual(first.body, "隐式正文")
        self.assertIs(first.delivery, Delivery.PENDING)
        self.assertIs(first.work, Work.AWAITING_ACK)

    # ---- retry/note --ref ----

    def files(self, count: int, prefix: str) -> list[str]:
        paths = []
        for index in range(count):
            path = Path(self._tmp.name) / f"{prefix}-{index}.txt"
            path.write_text(f"{prefix} {index}", encoding="utf-8")
            paths.append(str(path))
        return paths

    def test_retry_ref_appends_after_inherited_refs_and_dedupes_by_path(self) -> None:
        [spec] = self.files(1, "spec")
        task_id = self.send("--ref", spec)
        self.mark_sent(task_id)
        self.caller = local_base.as_agent(local_base.IMPL)
        self.assertEqual(self.run_cli("report", task_id, "--blocked", "--note", "缺数据")[0], 0)
        self.caller = local_base.USER
        [data] = self.files(1, "data")
        code, _, err = self.run_cli("retry", task_id, "--ref", data, "--ref", spec, "--ref", data)
        self.assertEqual(code, 0, err)
        with self.store() as store:
            latest = [item for item in store.attempts(task_id) if item.role.value == "handoff"][-1]
        self.assertEqual([item["path"] for item in latest.refs], [str(Path(spec).resolve()), str(Path(data).resolve())])

    def test_retry_ref_over_limit_is_refused_inside_the_transaction_without_writes(self) -> None:
        [spec] = self.files(1, "spec")
        task_id = self.send("--ref", spec)
        self.mark_sent(task_id)
        self.caller = local_base.as_agent(local_base.IMPL)
        self.assertEqual(self.run_cli("report", task_id, "--blocked")[0], 0)
        self.caller = local_base.USER
        with self.store() as store:
            before = [(item.seq, item.delivery) for item in store.attempts(task_id)]
        extra = self.files(16, "more")
        code, _, err = self.run_cli("retry", task_id, *[flag for path in extra for flag in ("--ref", path)])
        self.assertEqual((code, "[too_many_files]" in err), (cli.EXIT_REJECTED, True), err)
        with self.store() as store:
            # 未作废还没发出的受阻回执，也没有新尝试
            self.assertEqual([(item.seq, item.delivery) for item in store.attempts(task_id)], before)
        code, _, err = self.run_cli("retry", task_id, *[flag for path in self.files(17, "x") for flag in ("--ref", path)])
        self.assertEqual((code, "[too_many_files]" in err), (cli.EXIT_REJECTED, True), err)

    def test_note_ref_is_recorded_and_rendered(self) -> None:
        task_id = self.send()
        self.mark_sent(task_id)
        [extra] = self.files(1, "note")
        code, _, err = self.run_cli("note", task_id, "-m", "补一份数据", "--ref", extra)
        self.assertEqual(code, 0, err)
        with self.store() as store:
            [note] = [item for item in store.attempts(task_id) if item.is_note]
            task = store.get_task(task_id)
        self.assertEqual([item["path"] for item in note.refs], [str(Path(extra).resolve())])
        from agentstatus_bridge import envelope
        assert task is not None
        text = envelope.render(task, note, sender="user", device="vm", command="ab")
        self.assertIn("引用文件：", text)
        self.assertIn(str(Path(extra).resolve()), text)
        code, _, err = self.run_cli("note", task_id, "-m", "x", *[f for p in self.files(17, "n") for f in ("--ref", p)])
        self.assertEqual((code, "[too_many_files]" in err), (cli.EXIT_REJECTED, True), err)

    def test_undelivered_resend_with_large_supplement_is_message_too_large(self) -> None:
        task_id = self.send()
        self.mark_sent(task_id, Delivery.FAILED)
        path = Path(self._tmp.name) / "long.txt"
        path.write_bytes(b"x" * MAX_BODY_BYTES)
        code, _, err = self.run_cli("retry", task_id, "--file", str(path))
        self.assertEqual((code, "[message_too_large]" in err), (cli.EXIT_REJECTED, True), err)
        with self.store() as store:
            self.assertEqual(len(store.attempts(task_id)), 1)


class ReworkBodyTests(unittest.TestCase):
    """§104.4 返工措辞：_rework_body 六种情形（本机与跨设备共用）。"""

    def setUp(self) -> None:
        from agentstatus_bridge.model import Attempt, EndpointRef, Flow, Provider, Role, Task
        self.Role, self.Work = Role, Work
        target = EndpointRef(provider=Provider.CODEX, native_id="impl-thread", pid=1, start_ticks="1")
        self.task = Task(id="1" * 32, created_at=1.0, updated_at=1.0, title="T", flow=Flow.HANDOFF, origin=None,
                         reviewer=None)
        self.first = Attempt(id="2" * 32, task_id=self.task.id, seq=1, role=Role.HANDOFF, target=target,
                             message_id="3" * 32, created_at=1.0, body="原始要求")

    def current(self, work: Work, note: str | None = "做完了", role: object = None) -> object:
        from dataclasses import replace
        result = {"note": note, "files": [], "source": "agent"} if work in (Work.RESULT, Work.FAILED) else None
        return replace(self.first, seq=2, work=work, result=result, role=role or self.Role.HANDOFF)

    def body(self, current: object, extra: str | None = None, reassigned: bool = False, task: object = None) -> str:
        return cli._rework_body(self.first, current, task or self.task, extra, reassigned)  # type: ignore[arg-type]

    def test_after_result_puts_the_requirement_first_and_labels_the_conclusion(self) -> None:
        text = self.body(self.current(Work.RESULT), "补测试\n再跑一遍")
        self.assertEqual(text, "【返工】\n发起方看过结果，请按下面的要求继续：\n补测试\n再跑一遍\n你上次的结论：做完了"
                               "\n\n【原始任务要求】\n原始要求")
        self.assertNotIn("意见", text)
        self.assertNotIn("补充：", text)
        self.assertEqual(self.body(self.current(Work.RESULT)),
                         "【返工】\n发起方看过结果，请继续处理。\n你上次的结论：做完了\n\n【原始任务要求】\n原始要求")
        self.assertIn("上一位执行方的结论：做完了", self.body(self.current(Work.RESULT), "x", reassigned=True))

    def test_failed_labels_the_executors_own_explanation(self) -> None:
        text = self.body(self.current(Work.FAILED, "缺权限"), "已授权")
        self.assertEqual(text, "【返工】\n上次未能完成，请按下面的要求重新处理。\n你上次的说明：缺权限\n补充：已授权"
                               "\n\n【原始任务要求】\n原始要求")
        self.assertIn("上一位执行方的说明：缺权限", self.body(self.current(Work.FAILED, "缺权限"), reassigned=True))

    def test_blocked_and_review_changes_keep_their_wording(self) -> None:
        self.assertEqual(self.body(self.current(Work.BLOCKED), "已处理"),
                         "【返工】\n上次处理受阻，情况已处理，请继续。\n补充：已处理\n\n【原始任务要求】\n原始要求")
        from dataclasses import replace
        from agentstatus_bridge.model import Flow, Verdict
        changed = replace(self.task, flow=Flow.REVIEW, verdict=Verdict.CHANGES)
        review = self.current(Work.RESULT, "补边界用例", role=self.Role.REVIEW)
        text = self.body(review, "按复核改", task=changed)
        self.assertEqual(text, "【返工】\n复核方 codex@id:impl-thread 要求修改。\n意见：补边界用例\n补充：按复核改"
                               "\n\n【原始任务要求】\n原始要求")

    def test_forced_resend_before_any_result_says_it_may_duplicate(self) -> None:
        for work in (Work.AWAITING_ACK, Work.ACKNOWLEDGED, Work.IN_PROGRESS):
            with self.subTest(work=work):
                text = self.body(self.current(work), "再发一次")
                self.assertEqual(text, f"{cli.RESEND_HEADER}\n补充：再发一次\n\n原始要求")
                self.assertTrue(text.startswith("【重发】上一条消息可能已经送达；如果你已经在做，按这一条继续，不要重复执行。"))
                self.assertNotIn("意见", text)
                self.assertNotIn("看过结果", text)

    def test_forced_resend_carries_the_latest_message_with_a_single_header(self) -> None:
        from dataclasses import replace
        rework = replace(self.current(Work.IN_PROGRESS),
                         body="【返工】\n发起方看过结果，请按下面的要求继续：\n改 X\n\n【原始任务要求】\n原始要求")
        once = self.body(rework, "第一次重发")
        self.assertTrue(once.startswith(cli.RESEND_HEADER + "\n补充：第一次重发\n\n【返工】"), once)
        self.assertIn("改 X", once)
        twice = self.body(replace(rework, seq=3, body=once), "第二次重发")
        self.assertEqual(twice.count("【重发】"), 1)
        self.assertIn("改 X", twice)
        self.assertTrue(twice.startswith(cli.RESEND_HEADER + "\n补充：第二次重发\n\n补充：第一次重发\n\n【返工】"), twice)
        # 复核尝试被重发：复核方收到的是复核请求本身，不是首条实现正文
        review = replace(self.current(Work.ACKNOWLEDGED, role=self.Role.REVIEW), body="请复核这项工作。\n\n【结果】\n结论：OK")
        text = self.body(review)
        self.assertEqual(text, f"{cli.RESEND_HEADER}\n\n请复核这项工作。\n\n【结果】\n结论：OK")
        self.assertNotIn("原始要求", text)

    def test_forced_header_depends_on_reassignment_and_review_verdict(self) -> None:
        from dataclasses import replace
        from agentstatus_bridge.model import Flow, Verdict
        working = self.current(Work.IN_PROGRESS)
        self.assertEqual(self.body(working, "接手", reassigned=True), f"{cli.REASSIGN_HEADER}\n补充：接手\n\n原始要求")
        approved = replace(self.task, flow=Flow.REVIEW, verdict=Verdict.APPROVED)
        review = replace(self.current(Work.RESULT, role=self.Role.REVIEW), body="请复核这项工作。")
        self.assertEqual(self.body(review, task=approved), f"{cli.REREVIEW_HEADER}\n\n请复核这项工作。")
        # 复核还没给结论：仍是重发；改派给另一位复核方：改派优先
        self.assertEqual(self.body(review), f"{cli.RESEND_HEADER}\n\n请复核这项工作。")
        self.assertEqual(self.body(review, task=approved, reassigned=True), f"{cli.REASSIGN_HEADER}\n\n请复核这项工作。")
        # 要求修改是返工，不走 --force 的首行
        changed = replace(self.task, flow=Flow.REVIEW, verdict=Verdict.CHANGES)
        self.assertTrue(self.body(review, task=changed).startswith("【返工】"))

    def test_forced_headers_never_nest_across_kinds(self) -> None:
        from dataclasses import replace
        body = "原始要求"
        for seq, reassigned in enumerate((False, True, False, True), start=2):
            body = self.body(replace(self.current(Work.IN_PROGRESS), seq=seq, body=body), f"第 {seq} 次",
                             reassigned=reassigned)
            heads = [line for line in body.splitlines() if line in (cli.RESEND_HEADER, cli.REASSIGN_HEADER,
                                                                    cli.REREVIEW_HEADER)]
            self.assertEqual(heads, [cli.REASSIGN_HEADER if reassigned else cli.RESEND_HEADER], body)
        self.assertTrue(body.endswith("补充：第 4 次\n\n补充：第 3 次\n\n补充：第 2 次\n\n原始要求"), body)

    def test_oversized_body_is_truncated_with_a_marker(self) -> None:
        text = self.body(self.current(Work.RESULT), "长" * MAX_BODY_BYTES)
        self.assertLessEqual(len(text.encode("utf-8")), MAX_BODY_BYTES)
        self.assertTrue(text.endswith("\n…（已截断）"))

class FederatedNoteTests(fed_base.FedCliCase):
    def test_remote_report_note_too_large_is_refused_before_freezing_attachments(self) -> None:
        task_id = self.delivered_task()
        result = self.root / "result.txt"
        result.write_text("结果", encoding="utf-8")
        staging = self.states["win"] / "fed-staging"
        with patch.object(fed_commands, "freeze_refs", side_effect=AssertionError("froze before note check")):
            code, out, err = self.run_on("win", "report", task_id, "--origin-device", "vm", "--result",
                                         "--note", "长" * (MAX_NOTE_CHARS + 1), "--file", str(result),
                                         caller=fed_base.as_agent(fed_base.WORKER))
        self.assertEqual(code, cli.EXIT_REJECTED)
        self.assertEqual(out, "")
        self.assertIn("[note_too_large]", err)
        self.assertFalse(staging.exists() and any(staging.iterdir()))
        with self.store("win") as store:
            self.assertEqual(store.reports(fed_base.DEV_A, task_id), [])
        # 库函数自身也在冻结前拒绝（CLI 入口之外的防御）
        with self.store("win") as store:
            [task] = store.find_tasks(task_id)
        with patch.object(fed_commands, "freeze_refs", side_effect=AssertionError("froze before note check")):
            rt = fed_commands.open_runtime(self.states["win"])
            try:
                with self.assertRaises(fed_commands.FedCliError) as caught:
                    fed_commands.report(rt, task=task, kind=ReportKind.RESULT, attempt_seq=None,
                                        note="长" * (MAX_NOTE_CHARS + 1), files=[str(result)], commit=None,
                                        manual=False, caller=fed_base.as_agent(fed_base.WORKER), caller_class="bypass",
                                        cwd=self.root)
            finally:
                rt.close()
        self.assertEqual(caught.exception.code, "note_too_large")

    def test_remote_report_note_from_file_round_trips(self) -> None:
        task_id = self.delivered_task()
        path = self.root / "note.txt"
        path.write_text("跨设备结论", encoding="utf-8")
        code, _, err = self.run_on("win", "report", task_id, "--origin-device", "vm", "--result", "--note-file",
                                   str(path), caller=fed_base.as_agent(fed_base.WORKER))
        self.assertEqual(code, 0, err)
        with self.store("win") as store:
            [row] = store.reports(fed_base.DEV_A, task_id)
        self.assertEqual(row["report"]["note"], "跨设备结论")

    def blocked_remote_task(self) -> str:
        task_id = self.delivered_task()
        self.assertEqual(self.run_on("win", "report", task_id, "--blocked", "--note", "缺数据",
                                     caller=fed_base.as_agent(fed_base.WORKER))[0], 0)
        self.pump("win", "vm")
        return task_id

    def queued_ref_names(self, msg_id: str) -> tuple[list[str], list[str]]:
        """A 侧：这条尝试的信封里带的附件名，与为它登记的附件行状态（内存泵不走 relay 的收件登记，B 侧落地
        由共用的 begin_receiving/_prepare_attachments 负责，不分消息类别）。"""
        with self.store("vm") as store:
            item = store.outbox_item(msg_id)
            assert item is not None
            envelope = json.loads(item["envelope_json"])
            rows = store.attachments(msg_id)
        return [ref["name"] for ref in envelope["refs"]], [row["state"] for row in rows]

    def test_remote_retry_ref_is_frozen_appended_and_queued(self) -> None:
        task_id = self.blocked_remote_task()
        data = self.root / "data.txt"
        data.write_text("补充数据", encoding="utf-8")
        code, _, err = self.run_on("vm", "retry", task_id, "-m", "数据在附件里", "--ref", str(data), "--ref", str(data),
                                   caller=fed_base.as_agent(fed_base.ORIGIN))
        self.assertEqual(code, 0, err)
        with self.store("vm") as store:
            latest = store.attempts(fed_base.DEV_A, task_id)[-1]
        self.assertEqual([item["name"] for item in latest.refs], ["data.txt"])
        self.assertEqual(self.queued_ref_names(latest.msg_id), (["data.txt"], ["staged"]))

    def test_remote_retry_ref_over_limit_is_refused_before_freezing(self) -> None:
        task_id = self.blocked_remote_task()
        paths = []
        for index in range(17):
            path = self.root / f"f{index}.txt"
            path.write_text(str(index), encoding="utf-8")
            paths.append(str(path))
        with patch.object(fed_commands, "freeze_refs", side_effect=AssertionError("froze before count check")):
            code, _, err = self.run_on("vm", "retry", task_id, *[f for p in paths for f in ("--ref", p)],
                                       caller=fed_base.as_agent(fed_base.ORIGIN))
        self.assertEqual((code, "[too_many_files]" in err), (cli.EXIT_REJECTED, True), err)
        with self.store("vm") as store:
            self.assertEqual(store.attempts(fed_base.DEV_A, task_id)[-1].role, "notice")  # 没有新的交接尝试

    def test_remote_note_ref_is_frozen_and_queued(self) -> None:
        task_id = self.delivered_task()
        self.pump("win", "vm")  # A 先收到投递证据，当前尝试才算已发出、可以补充
        extra = self.root / "hint.txt"
        extra.write_text("提示", encoding="utf-8")
        code, _, err = self.run_on("vm", "note", task_id, "-m", "看附件", "--ref", str(extra),
                                   caller=fed_base.as_agent(fed_base.ORIGIN))
        self.assertEqual(code, 0, err)
        with self.store("vm") as store:
            [note] = [item for item in store.attempts(fed_base.DEV_A, task_id) if item.is_note]
        self.assertEqual(self.queued_ref_names(note.msg_id), (["hint.txt"], ["staged"]))

    def test_remote_undelivered_resend_with_large_supplement_is_refused_not_a_traceback(self) -> None:
        task_id = self.send()
        self.pump("vm", "win")
        self.deliver_on_b(DeliveryOutcome(Delivery.FAILED, "codex_cli_missing"))
        self.pump("win", "vm")
        path = self.root / "long.txt"
        path.write_bytes(b"x" * MAX_BODY_BYTES)
        code, _, err = self.run_on("vm", "retry", task_id, "--file", str(path), caller=fed_base.as_agent(fed_base.ORIGIN))
        self.assertEqual((code, "[message_too_large]" in err), (cli.EXIT_REJECTED, True), err)
        self.assertNotIn("Traceback", err)
        with self.store("vm") as store:
            self.assertEqual(len(store.attempts(fed_base.DEV_A, task_id)), 1)


    def test_remote_retry_after_result_uses_new_wording(self) -> None:
        task_id = self.delivered_task()
        self.assertEqual(self.run_on("win", "report", task_id, "--result", "--note", "跨设备完成",
                                     caller=fed_base.as_agent(fed_base.WORKER))[0], 0)
        self.pump("win", "vm")
        code, _, err = self.run_on("vm", "retry", task_id, "-m", "补一个用例", caller=fed_base.as_agent(fed_base.ORIGIN))
        self.assertEqual(code, 0, err)
        with self.store("vm") as store:
            latest = store.attempts(fed_base.DEV_A, task_id)[-1]
        self.assertTrue(latest.body.startswith("【返工】\n发起方看过结果，请按下面的要求继续：\n补一个用例\n你上次的结论：跨设备完成"),
                        latest.body)

    def test_remote_retry_ref_already_inherited_is_recorded_once(self) -> None:
        spec = self.root / "spec.md"
        spec.write_text("规格", encoding="utf-8")
        code, out, err = self.run_on("vm", "send", "--device", "win", "--to", f"codex@id:{fed_base.THREAD_B}", "-m", "X",
                                     "--ref", str(spec), "--json", caller=fed_base.as_agent(fed_base.ORIGIN))
        self.assertEqual(code, 0, err)
        task_id = json.loads(out)["id"]
        self.pump("vm", "win")
        self.deliver_on_b()
        self.assertEqual(self.run_on("win", "report", task_id, "--blocked", caller=fed_base.as_agent(fed_base.WORKER))[0], 0)
        self.pump("win", "vm")
        extra = self.root / "extra.md"
        extra.write_text("补充", encoding="utf-8")
        code, _, err = self.run_on("vm", "retry", task_id, "--ref", str(spec), "--ref", str(extra),
                                   caller=fed_base.as_agent(fed_base.ORIGIN))
        self.assertEqual(code, 0, err)
        with self.store("vm") as store:
            latest = store.attempts(fed_base.DEV_A, task_id)[-1]
        # 同一来源路径、同一 sha256 只记一次，新附件接在继承的之后
        self.assertEqual([item["name"] for item in latest.refs], ["spec.md", "extra.md"])

    def test_remote_retry_reassigned_after_result_labels_the_previous_executor(self) -> None:
        task_id = self.delivered_task()
        self.assertEqual(self.run_on("win", "report", task_id, "--result", "--note", "B 的结论",
                                     caller=fed_base.as_agent(fed_base.WORKER))[0], 0)
        self.pump("win", "vm")
        code, _, err = self.run_on("vm", "retry", task_id, "--to", "codex@review", "-m", "换本机复核方接着做",
                                   caller=fed_base.as_agent(fed_base.ORIGIN))
        self.assertEqual(code, 0, err)
        with self.store("vm") as store:
            latest = store.attempts(fed_base.DEV_A, task_id)[-1]
        self.assertEqual(latest.target_device, fed_base.DEV_A)
        self.assertIn("上一位执行方的结论：B 的结论", latest.body)
        self.assertNotIn("你上次的结论", latest.body)

    def test_remote_forced_retry_after_rework_keeps_the_requirement_once(self) -> None:
        task_id = self.delivered_task()
        worker = fed_base.as_agent(fed_base.WORKER)
        origin = fed_base.as_agent(fed_base.ORIGIN)
        self.assertEqual(self.run_on("win", "report", task_id, "--result", "--note", "第一版", caller=worker)[0], 0)
        self.pump("win", "vm")
        self.assertEqual(self.run_on("vm", "retry", task_id, "-m", "改 X", caller=origin)[0], 0)
        for round_ in (1, 2):
            self.pump("vm", "win")
            self.deliver_on_b()
            self.assertEqual(self.run_on("win", "report", task_id, "--progress", caller=worker)[0], 0)
            self.pump("win", "vm")
            code, _, err = self.run_on("vm", "retry", task_id, "--force", "-m", f"第 {round_} 次重发", caller=origin)
            self.assertEqual(code, 0, err)
            with self.store("vm") as store:
                latest = store.attempts(fed_base.DEV_A, task_id)[-1]
            self.assertTrue(latest.body.startswith(f"【重发】上一条消息可能已经送达；如果你已经在做，按这一条继续，不要重复执行。"
                                                   f"\n补充：第 {round_} 次重发"), latest.body)
            self.assertEqual(latest.body.count("【重发】"), 1)
            self.assertIn("改 X", latest.body)

    def test_remote_forced_retry_of_a_local_review_resends_the_review_request(self) -> None:
        task_id = self.local_review_requested()
        with self.store("vm") as store:
            review = [item for item in store.attempts(fed_base.DEV_A, task_id) if item.role == "review"][-1]
        code, _, err = self.run_on("vm", "retry", task_id, "--force", caller=fed_base.as_agent(fed_base.ORIGIN))
        self.assertEqual(code, 0, err)
        with self.store("vm") as store:
            latest = store.attempts(fed_base.DEV_A, task_id)[-1]
        self.assertEqual((latest.role, latest.seq > review.seq), ("review", True))
        self.assertEqual(latest.body, f"{cli.RESEND_HEADER}\n\n{review.body.rstrip()}")

    def test_remote_forced_reassignment_is_a_handover(self) -> None:
        task_id = self.delivered_task()
        self.assertEqual(self.run_on("win", "report", task_id, "--progress", caller=fed_base.as_agent(fed_base.WORKER))[0],
                         0)
        self.pump("win", "vm")
        code, _, err = self.run_on("vm", "retry", task_id, "--force", "--to", "codex@review", "-m", "换本机接手",
                                   caller=fed_base.as_agent(fed_base.ORIGIN))
        self.assertEqual(code, 0, err)
        with self.store("vm") as store:
            latest = store.attempts(fed_base.DEV_A, task_id)[-1]
        self.assertEqual(latest.target_device, fed_base.DEV_A)
        self.assertTrue(latest.body.startswith(cli.REASSIGN_HEADER + "\n补充：换本机接手\n\n请处理 X"), latest.body)
        self.assertNotIn("【重发】", latest.body)

    def test_remote_forced_retry_after_local_review_approved_asks_for_a_fresh_review(self) -> None:
        task_id = self.local_review_requested()
        code, _, err = self.run_on("vm", "report", task_id, "--approve", "--note", "通过",
                                   caller=fed_base.as_agent(fed_base.LOCAL_REVIEW))
        self.assertEqual(code, 0, err)
        with self.store("vm") as store:
            review = [item for item in store.attempts(fed_base.DEV_A, task_id) if item.role == "review"][-1]
        code, _, err = self.run_on("vm", "retry", task_id, "--force", caller=fed_base.as_agent(fed_base.ORIGIN))
        self.assertEqual(code, 0, err)
        with self.store("vm") as store:
            latest = store.attempts(fed_base.DEV_A, task_id)[-1]
        self.assertEqual(latest.role, "review")
        self.assertEqual(latest.body, f"{cli.REREVIEW_HEADER}\n\n{review.body.rstrip()}")

if __name__ == "__main__":
    unittest.main()
