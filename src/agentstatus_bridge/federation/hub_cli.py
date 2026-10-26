"""`agent-bridge hub …` 管理与 stdio 入口（DESIGN §88.1）：只给 hub 运维用户与 forced command 使用。

管理命令不读私钥、不编辑 authorized_keys；`stdio` 只按 forced command 绑定的 slug 服务，不解释 SSH_ORIGINAL_COMMAND。
本模块只依赖标准库、codec 与 hub 存储，不导入 provider/GNOME。
"""

from __future__ import annotations

import argparse
import json
import os
import shlex
import sys
from collections.abc import Sequence
from pathlib import Path

from .codec import CodecError
from .hub import EXIT_OK, EXIT_REFUSED, HubSession, now_ms
from .hubstore import HubStore, auth_fingerprint, openssh_fingerprint, parse_public_key
from .transport import StreamTransport

DEFAULT_STATE = "~/.local/state/agent-bridge-hub"
EXIT_USAGE = 2


def _state_dir(value: str | None) -> Path:
    raw = value or os.environ.get("AB_HUB_STATE_DIR") or DEFAULT_STATE
    return Path(raw).expanduser().resolve()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="agent-bridge hub", description="协作桥跨设备 hub（存储转发）")
    parser.add_argument("--state-dir", help=f"hub 状态目录（默认 $AB_HUB_STATE_DIR 或 {DEFAULT_STATE}）")
    commands = parser.add_subparsers(dest="hub_command", required=True)
    commands.add_parser("init", help="新建 hub 库；已存在只核 schema，不重置")
    add = commands.add_parser("add-device", help="登记设备并打印 authorized_keys 行（不编辑该文件）")
    add.add_argument("--name", required=True, help="设备 slug：[A-Za-z0-9][A-Za-z0-9._-]{0,31}")
    add.add_argument("--public-key-file", required=True, help="该设备 relay 专用公钥文件（.pub）")
    add.add_argument("--device-id", help="仅 hub 重建且本机账本完整时保留原 32hex deviceId")
    add.add_argument("--command-path", help="forced command 里的绝对入口（默认当前程序路径）")
    remove = commands.add_parser("remove-device", help="撤销设备：DB fence 后一秒内停旧连接")
    remove.add_argument("--device", required=True, help="slug 或完整 deviceId")
    status = commands.add_parser("status", help="设备在线、积压、附件字节与存储状态")
    status.add_argument("--json", action="store_true", help="输出 JSON")
    commands.add_parser("gc", help="回收到期信封、无引用 CAS 和不完整上传")
    stdio = commands.add_parser("stdio", help="forced command 入口：在 stdin/stdout 上服务一台登记设备")
    stdio.add_argument("--device", required=True, help="authorized_keys 绑定的设备 slug")
    return parser


def _forced_line(command_path: str, state_dir: Path, name: str, key_line: str, *, explicit_state: bool) -> str:
    parts = [command_path, "hub"]
    if explicit_state:
        parts += ["--state-dir", str(state_dir)]
    parts += ["stdio", "--device", name]
    command = " ".join(shlex.quote(item) for item in parts)
    key_type, encoded = key_line.split()[:2]
    return f'restrict,command="{command}" {key_type} {encoded} agent-bridge-relay:{name}'


def main(argv: Sequence[str]) -> int:
    """hub 子命令入口；返回退出码。"""
    args = build_parser().parse_args(list(argv))
    state = _state_dir(args.state_dir)
    if args.hub_command == "stdio":
        return _stdio(state, args.device)
    if args.hub_command == "init":
        store, created = HubStore.init(state, now=now_ms())
        print(json.dumps({"hubId": store.hub_id(), "created": created, "stateDir": str(state)}, ensure_ascii=False))
        store.close()
        return EXIT_OK
    try:
        store = HubStore.open(state)
    except CodecError as error:
        print(f"hub_unavailable: {error.detail or error.code}（先运行 hub init）", file=sys.stderr)
        return EXIT_REFUSED
    try:
        if args.hub_command == "add-device":
            try:
                key_line = Path(args.public_key_file).read_text(encoding="utf-8").strip().splitlines()[0]
                _, blob = parse_public_key(key_line)
            except (OSError, IndexError, UnicodeDecodeError, CodecError):
                print("public_key_unreadable: 需要一行 OpenSSH 普通公钥（不支持证书）", file=sys.stderr)
                return EXIT_USAGE
            try:
                device_id = store.add_device(name=args.name, fingerprint=openssh_fingerprint(blob),
                                             device_id=args.device_id)
            except ValueError as error:
                print(f"{error}", file=sys.stderr)
                return EXIT_REFUSED
            command_path = args.command_path or os.path.abspath(sys.argv[0])
            print(json.dumps({"deviceId": device_id, "name": args.name, "fingerprint": openssh_fingerprint(blob)},
                             ensure_ascii=False))
            print(_forced_line(command_path, state, args.name, key_line,
                               explicit_state=bool(args.state_dir or os.environ.get("AB_HUB_STATE_DIR"))))
            return EXIT_OK
        if args.hub_command == "remove-device":
            try:
                device_id = store.remove_device(args.device, now=now_ms())
            except ValueError as error:
                print(f"{error}", file=sys.stderr)
                return EXIT_REFUSED
            print(json.dumps({"deviceId": device_id, "revoked": True}, ensure_ascii=False))
            print("已在 hub 账本撤销；请运维同时从 authorized_keys 移除该设备的 key 行。", file=sys.stderr)
            return EXIT_OK
        if args.hub_command == "status":
            report = store.status(now=now_ms())
            if args.json:
                print(json.dumps(report, ensure_ascii=False, sort_keys=True))
            else:
                for device in report["devices"]:
                    state_text = "在线" if device["online"] else ("已撤销" if device["status"] != "active" else "离线")
                    print(f"{device['name']}\t{state_text}\t积压 {device['backlog']}")
                print(f"占用 {report['usageBytes']}/{report['budgetBytes']} B，blob {report['blobs']['bytes']} B")
                if report["storageReason"]:
                    print(f"存储：{report['storageReason']}")
            return EXIT_OK
        if args.hub_command == "gc":
            counts = store.gc(now=now_ms(), owner="admin")
            print(json.dumps(counts if counts is not None else {"skipped": "lease_held"}, ensure_ascii=False))
            return EXIT_OK
    finally:
        store.close()
    return EXIT_USAGE


def _stdio(state: Path, device: str) -> int:
    """forced command：stdout 只写帧，stderr 只写闭集码。"""
    try:
        store = HubStore.open(state)
    except CodecError:
        sys.stdout.buffer.write(b'{"code":"hub_unavailable","retryable":true,"type":"error"}\n')
        sys.stdout.buffer.flush()
        return EXIT_REFUSED
    transport = StreamTransport(sys.stdin.buffer, sys.stdout.buffer)
    session = HubSession(store, transport, device_name=device,
                         auth=lambda: auth_fingerprint(os.environ.get("SSH_USER_AUTH")))
    try:
        return session.run()
    finally:
        store.close()
