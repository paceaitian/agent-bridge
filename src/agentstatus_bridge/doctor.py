"""协作桥的 doctor：收集诊断事实（`collect_checks`）并按插入顺序打印（`print_checks`）（DESIGN §48 R7，审计 H1）。

从 `cli.cmd_doctor` 拆出：前半收集、后半打印，语句原样搬移；`cli` 只留收集、`--json` 或打印、返回的薄入口。
本模块的 import 全部在顶层，不 import `cli`（它要用 cli 的退出码与 `_print_json`，反过来会成环）。
"""

from __future__ import annotations

from collections.abc import Mapping
import os
from pathlib import Path
import sqlite3

from . import __version__, summary
from .endpoints import codex_title_report
from .naming import command_name
from .observer_dbus import agentstatus_runtime
from .paths import claude_sessions_dir, device_name, state_dir, state_dir_source
from .store import Store, StoreError
from .transports.claude_peer import inbox_directory
from .transports.codex_queue import EVIDENCE_WINDOW, cli_version, summarize_queue_evidence, summarize_rpc_evidence
from .worker import read_log_tail, worker_running


def package_path() -> str:
    """本进程实际加载的桥包目录（解开符号链接），在 home 下时缩写成 `~/…`（DESIGN §48 R9）。

    release 的 `.pth` 指向 `releases/<release id>/python`，所以值里带 release id；`PYTHONPATH` 让 `ab`
    加载了开发树时也一眼看得出。它只说明当前 CLI 进程，说明不了常驻 worker 跑的是哪个 release。
    """
    package = Path(__file__).resolve().parent  # 本模块就在包目录里
    try:
        home = Path.home()
    except RuntimeError:  # 没有 HOME、pwd 也查不到时给完整路径
        return str(package)
    if not home.is_absolute():  # HOME 是相对路径时 resolve 会把当前目录当成 home
        return str(package)
    home = home.resolve()
    # 与解析后的 home 比：HOME 本身含符号链接时，拿未解析的值比会缩写不上、把用户名带进输出；
    # home 是根目录时不缩写，否则每个绝对路径都会变成 `~/…`
    if home.parent != home and package.is_relative_to(home):
        return str(Path("~", package.relative_to(home)))
    return str(package)


def collect_checks() -> dict[str, object]:
    """收集 doctor 的全部事实；`checks` 的插入顺序就是文字输出的顺序（JSON 用 sort_keys 看不出），原样保留。"""
    version = cli_version()
    root = state_dir()
    # 账本根与命令名是「这套装置到底在用哪个账本」的可读事实：默认值是独立版的，
    # 集成版由入口脚本绑回现役根，绑没绑上只看这两行（DESIGN §45.36）
    checks: dict[str, object] = {
        "abVersion": __version__,
        "packagePath": package_path(),
        "command": command_name(),
        "device": device_name(),
        "ledger": str(root),
        "stateRoot": str(root),
        "stateRootSource": state_dir_source(),
    }
    try:
        checks["workerRunning"] = worker_running(root)
    except OSError as error:
        # 锁文件异常时给出原因，拉起失败的提示把人指到这里（Opus 复审 P3-b）
        checks["workerRunning"] = False
        checks["workerLockError"] = f"{type(error).__name__}（errno {error.errno}）"
    checks.update({
        # 只显示、不判定：Codex 会自动升级，写死的版本前缀每升一次就自己过期一次（DESIGN §45.44）
        "codexVersion": version,
        # 托管 daemon 下按标题认会话：只有计数（DESIGN §53.5）
        "codexThreadTitle": codex_title_report(),
        # 占位保住显示顺序，读完账本后填入
        "codexQueueEvidence": summarize_queue_evidence(None, version),
        "codexRpcEvidence": summarize_rpc_evidence(None),
        "claudeRegistryReadable": os.access(claude_sessions_dir(), os.R_OK),
        "claudeInboxDirectory": inbox_directory().is_dir(),
        # 可读≠有会话：observer 在线、零可见会话时也算可读（DESIGN §59）
        "agentstatusRuntimeAvailable": agentstatus_runtime() is not None,
        "workerLog": read_log_tail(root, lines=5),
    })
    try:
        with Store.open(root) as store:
            checks["ledgerOk"] = True
            checks["archivedWithNativeRisk"] = store.archived_risk_count()
            checks["summaryState"] = summary.STATE_LABELS.get(summary.status(root, store)["state"], "未知")
            try:
                details = store.recent_codex_details(limit=EVIDENCE_WINDOW)
            except sqlite3.Error:
                details = None  # 读失败就说读失败，不伪装成零样本
            checks["codexQueueEvidence"] = summarize_queue_evidence(details, version)
            checks["codexRpcEvidence"] = summarize_rpc_evidence(details)
    except StoreError as error:
        checks["ledgerOk"] = False
        checks["ledgerError"] = error.code
    return checks


def print_checks(checks: dict[str, object]) -> None:
    """按插入顺序把 doctor 的事实打印成中文标签的文字。"""
    labels = {
        "abVersion": f"{command_name()} 版本",
        "packagePath": "包路径",
        "command": "对外命令名",
        "device": "本机设备名",
        "ledger": "任务账本目录",
        "stateRoot": "状态根目录",
        "stateRootSource": "状态根来源",
        "workerRunning": "后台 worker 运行中",
        "workerLockError": "worker 锁文件异常",
        "codexVersion": "Codex CLI 版本",
        "claudeRegistryReadable": "Claude 会话注册表可读",
        "claudeInboxDirectory": "Claude 回执目录存在",
        "agentstatusRuntimeAvailable": "AgentStatus 忙闲状态可读",
        "ledgerOk": "任务账本正常",
        "ledgerError": "账本错误",
        "archivedWithNativeRisk": "已关闭但对方可能仍在执行的任务",
        "summaryState": "协作摘要",
        "workerLog": "worker 最近日志",
    }
    for key, value in checks.items():
        if key == "codexQueueEvidence" and isinstance(value, dict):
            print(queue_evidence_text(value))
            continue
        if key == "codexRpcEvidence" and isinstance(value, dict):
            print(rpc_evidence_text(value))
            continue
        if key == "codexThreadTitle" and isinstance(value, dict):
            for line in thread_title_lines(value):
                print(line)
            continue
        if isinstance(value, list):
            print(f"{labels.get(key, key)}：" + ("（无）" if not value else ""))
            for line in value:
                print(f"  {line}")
            continue
        shown = "是" if value is True else "否" if value is False else value
        print(f"{labels.get(key, key)}：{shown}")


def thread_title_lines(report: Mapping[str, object]) -> list[str]:
    """doctor 的「Codex 窗口标题」几行（DESIGN §53.5）：只有计数与提示，不输出标题原文与 thread id。"""
    if report.get("daemonMode") is not True:
        return ["Codex 托管 daemon：未检测到 daemon 持有的会话（可能没用 daemon，或所有窗口都停在选择器）"]
    lines = [f"Codex 窗口标题里的会话 id：{report.get('withThreadId')} 个能认出"]
    short = report.get("shortThreadId")
    if isinstance(short, int) and short > 0:
        lines.append(
            f"  其中 {short} 个的会话 id 被截短（标题超过 240 字符）：协作桥仍可能认出；走托管 daemon 的窗口，轮次结局不在面板上公开"
            "（按进程关系定位的旧版或 --no-daemon 窗口不受影响）；缩短 terminal_title 配置后新开或重开窗口生效"
        )
    not_parsed = report.get("uuidNotParsed")
    if isinstance(not_parsed, int) and not_parsed > 0:
        lines.append(
            f"  {not_parsed} 个标题里有会话 id 但认不出：确认 \"thread-id\" 已加在 [tui] terminal_title 列表末尾，"
            "并且不紧挨 activity（紧挨时两者之间是空格，忙时粘在一起、空闲时又正常）"
        )
    missing = report.get("withoutThreadId")
    if isinstance(missing, int) and missing > 0:
        lines.append(
            f"  {missing} 个 Codex 窗口的标题里没有会话 id：可能停在选择器、标题超过 240 字符，或没加 \"thread-id\"；"
            "新开或重开 Codex 窗口生效"
        )
    if report.get("stateDbUnavailable") is True:
        lines.append("  Codex 状态库读不到：正在看子代理的窗口可能被当成主会话")
    native = report.get("nativeMetadata")
    if isinstance(native, dict):
        lines.append(f"Codex 原生元数据：{native.get('state')}；确认 {native.get('confirmed')}，"
                     f"冲突 {native.get('conflicts')}，SQL 回退 {native.get('sqlFallback')}；"
                     f"SQL：{native.get('sqlState')}（未查询不代表可用）")
    return lines


def rpc_evidence_text(evidence: Mapping[str, object]) -> str:
    """doctor 的「Codex RPC 证据」一行（DESIGN §61.2 第 7 条）。计数只说明响应落没落在已知分支，不说投递成败。"""
    if evidence.get("state") == "ledger_unreadable":
        return "Codex RPC 证据：账本读取失败，无法统计"
    head = f"Codex RPC 证据（最近最多 {evidence.get('window')} 条 Codex 尝试）："
    version = evidence.get("version")
    unknown = evidence.get("unknownVersion")
    has_unknown = isinstance(unknown, int) and unknown > 0
    if evidence.get("state") == "ok":
        text = (
            f"{head}服务端 {version}（取最近一条能解析出服务端版本的可分类 RPC 响应样本，不证明 daemon 此刻的版本）命中已知分支 "
            f"{evidence.get('recognized')} 次，未识别 {evidence.get('unrecognized')} 次；此统计不代表投递成功"
        )
    elif version is None and has_unknown:
        # 有可分类的响应样本，只是都没解析出服务端版本：不能说「没有样本」
        text = f"{head}经 daemon 得到的 {unknown} 条可分类响应样本都未能解析服务端版本，无法按版本关联"
        has_unknown = False
    else:
        # add 之后断线、超时的尝试经过 RPC，但没有可分类的响应，不计入（§61 第 2 轮 Codex C01）
        text = f"{head}在本次查询窗口内没有可分类的 RPC 响应样本（传输失败的尝试不计入此项）"
    other = evidence.get("otherVersion")
    if isinstance(other, int) and other > 0:
        text += f"；另有 {other} 次记于其他服务端版本"
    if has_unknown:
        text += f"；另有 {unknown} 次未能解析服务端版本"
    fallbacks = evidence.get("fallbacks")
    if isinstance(fallbacks, int) and fallbacks > 0:
        text += f"；回退 CLI {fallbacks} 次（最常见：{evidence.get('topFallback')}）"
    return text


def queue_evidence_text(evidence: Mapping[str, object]) -> str:
    """doctor 的「Codex CLI 输出证据」一行（DESIGN §45.44 二.6）。计数只说明输出落没落在已知分支，不说投递成败。"""
    state = evidence.get("state")
    if state == "version_unavailable":
        return "Codex CLI 输出证据：当前 codex 版本不可用，无法关联样本"
    if state == "ledger_unreadable":
        return "Codex CLI 输出证据：账本读取失败，无法统计"
    version = evidence.get("version")
    head = f"Codex CLI 输出证据（最近最多 {evidence.get('window')} 条 Codex 尝试）："
    if state == "ok":
        unrecognized = evidence.get("unrecognized")
        text = (
            f"{head}{version} 命中已知分支 {evidence.get('recognized')} 次，未识别 {unrecognized} 次；"
            "此统计不代表投递成功、执行完成或所有错误分支都已验证；CLI 版本也不证明它所连 app-server 的版本"
        )
        if isinstance(unrecognized, int) and unrecognized > 0:
            # 未识别的尝试之后仍可能由接收方汇报确证而变成已送达，所以不说「是否送达不明」
            text += f"；上游输出或接口可能变了，这些尝试的当前投递状态以 `{command_name()} status` 为准，可能已由接收方汇报确证"
    else:
        text = f"{head}{version} 在本次查询窗口内没有可用样本（旧记录可能未记这两个字段）"
    other = evidence.get("otherVersion")
    if isinstance(other, int) and other > 0:
        # 升级后第一次看 doctor 的常态：样本都在，只是记在升级前的版本下
        text += f"；另有 {other} 次记于其他版本（多半是升级前的投递）"
    unknown = evidence.get("unknownVersion")
    if isinstance(unknown, int) and unknown > 0:
        text += f"；另有 {unknown} 次未能确定执行投递的版本"
    return text
