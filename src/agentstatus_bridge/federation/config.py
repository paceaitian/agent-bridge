"""联邦配置 federation.json 与 SSH 参数（DESIGN §88.10/§88.12）：没有配置就不开网络。

配置只存路径不存 key 内容；不设 senderClass/harness override；不硬编码主机、用户名或账号目录。
SSH 用 argv 数组与专用 `-F` 配置文件：不 Include 用户全局配置、不复用管理 ControlMaster、不自动接受 host key。
"""

from __future__ import annotations

import json
import os
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .codec import CodecError, is_hex32, is_slug, loads_strict

CONFIG_NAME = "federation.json"
SSH_CONFIG_NAME = "federation-ssh.conf"
CONFIG_SCHEMA = 1
DEFAULT_BUDGET = 2 * 1024**3
HUB_ALIAS = "agent-bridge-hub"


class ConfigError(Exception):
    """配置不可用：config_invalid / state_root_mismatch。"""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


@dataclass(frozen=True)
class FederationConfig:
    """federation.json 的已校验内容。"""

    enabled: bool
    hub_id: str
    device_id: str
    device_name: str
    host: str
    user: str
    expected_state_root: str
    port: int = 22
    ssh_executable: str = "ssh"
    identity_file: str = ""
    known_hosts_file: str = ""
    publish_names: bool = True
    storage_budget: int = DEFAULT_BUDGET
    reconnect_min: int = 30
    reconnect_max: int = 300
    extra: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            **self.extra, "schema": CONFIG_SCHEMA, "enabled": self.enabled, "hubId": self.hub_id,
            "deviceId": self.device_id, "deviceName": self.device_name,
            "hub": {"host": self.host, "port": self.port, "user": self.user},
            "sshExecutable": self.ssh_executable, "identityFile": self.identity_file,
            "knownHostsFile": self.known_hosts_file, "expectedStateRoot": self.expected_state_root,
            "directory": {"publishNames": self.publish_names}, "storageBudgetBytes": self.storage_budget,
            "reconnectMin": self.reconnect_min, "reconnectMax": self.reconnect_max,
        }


def _text(data: dict[str, Any], key: str, *, required: bool = True) -> str:
    value = data.get(key, "")
    if not isinstance(value, str) or (required and not value) or any(ord(ch) < 32 for ch in value):
        raise ConfigError("config_invalid")
    return value


def _int(value: object, *, low: int, high: int) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or not low <= value <= high:
        raise ConfigError("config_invalid")
    return value


def parse(data: object) -> FederationConfig:
    """校验配置对象；未知顶层字段保留（向前兼容），已知字段类型不对就是 config_invalid。"""
    if not isinstance(data, dict):
        raise ConfigError("config_invalid")
    raw: dict[str, Any] = data  # pyright: ignore[reportUnknownVariableType]
    if raw.get("schema") != CONFIG_SCHEMA or not isinstance(raw.get("enabled"), bool):
        raise ConfigError("config_invalid")
    hub = raw.get("hub")
    directory = raw.get("directory", {})
    if not isinstance(hub, dict) or not isinstance(directory, dict):
        raise ConfigError("config_invalid")
    hub_section: dict[str, Any] = hub  # pyright: ignore[reportUnknownVariableType]
    directory_section: dict[str, Any] = directory  # pyright: ignore[reportUnknownVariableType]
    hub_id, device_id, name = raw.get("hubId"), raw.get("deviceId"), raw.get("deviceName")
    if not is_hex32(hub_id) or not is_hex32(device_id) or not is_slug(name):
        raise ConfigError("config_invalid")
    publish = directory_section.get("publishNames", True)
    if not isinstance(publish, bool):
        raise ConfigError("config_invalid")
    reconnect_min = _int(raw.get("reconnectMin", 30), low=30, high=3600)  # 自动重连永不短于 30 秒
    reconnect_max = _int(raw.get("reconnectMax", 300), low=reconnect_min, high=86400)
    known = {"schema", "enabled", "hubId", "deviceId", "deviceName", "hub", "sshExecutable", "identityFile",
             "knownHostsFile", "expectedStateRoot", "directory", "storageBudgetBytes", "reconnectMin", "reconnectMax"}
    return FederationConfig(
        enabled=bool(raw["enabled"]), hub_id=str(hub_id), device_id=str(device_id), device_name=str(name),
        host=_text(hub_section, "host"), user=_text(hub_section, "user"),
        port=_int(hub_section.get("port", 22), low=1, high=65535),
        ssh_executable=_text(raw, "sshExecutable", required=False) or "ssh",
        identity_file=_text(raw, "identityFile", required=False),
        known_hosts_file=_text(raw, "knownHostsFile", required=False),
        expected_state_root=_text(raw, "expectedStateRoot"), publish_names=publish,
        storage_budget=_int(raw.get("storageBudgetBytes", DEFAULT_BUDGET), low=64 * 1024**2, high=2**50),
        reconnect_min=reconnect_min, reconnect_max=reconnect_max,
        extra={key: value for key, value in raw.items() if key not in known},
    )


def load(state_root: Path) -> FederationConfig | None:
    """读配置；不存在返回 None（不开网络）。"""
    path = state_root / CONFIG_NAME
    try:
        raw = path.read_bytes()
    except FileNotFoundError:
        return None
    except OSError as error:
        raise ConfigError("config_invalid") from error
    try:
        return parse(loads_strict(raw))
    except CodecError as error:
        raise ConfigError("config_invalid") from error


def save(state_root: Path, config: FederationConfig) -> None:
    """原子写配置（0600）。"""
    data = json.dumps(config.to_dict(), ensure_ascii=False, sort_keys=True, indent=2).encode("utf-8") + b"\n"
    fd, tmp = tempfile.mkstemp(dir=state_root, prefix=".federation-", suffix=".tmp")
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp, state_root / CONFIG_NAME)
    except BaseException:
        if os.path.exists(tmp):
            os.unlink(tmp)
        raise


def check_state_root(config: FederationConfig, state_root: Path) -> None:
    """开库/联网前核对 expectedStateRoot（规范化后比较）；不符停在 state_root_mismatch。"""
    if os.path.normcase(os.path.realpath(config.expected_state_root)) != os.path.normcase(os.path.realpath(state_root)):
        raise ConfigError("state_root_mismatch")


def ssh_config_text(config: FederationConfig) -> str:
    """专用 ssh 配置：只列所需连接项，不 Include 全局配置，避免带入 LocalCommand/ProxyCommand 等副作用。"""

    def quote(value: str) -> str:
        return '"' + value.replace('"', "") + '"'

    lines = [
        f"Host {HUB_ALIAS}",
        f"  HostName {config.host}",
        f"  Port {config.port}",
        f"  User {config.user}",
        "  BatchMode yes",
        "  IdentitiesOnly yes",
        # 不用任何 ssh-agent：管理 key 绝不能成为无人值守 relay 的身份（只认专用 IdentityFile）
        "  IdentityAgent none",
        "  StrictHostKeyChecking yes",
        "  UpdateHostKeys no",
        "  ControlMaster no",
        "  ControlPath none",
        "  RequestTTY no",
        "  ForwardAgent no",
        "  ForwardX11 no",
        "  PermitLocalCommand no",
        "  ClearAllForwardings yes",
        "  ConnectTimeout 15",
        "  ConnectionAttempts 1",
        "  ServerAliveInterval 30",
        "  ServerAliveCountMax 3",
    ]
    if config.identity_file:
        lines.append(f"  IdentityFile {quote(config.identity_file)}")
    if config.known_hosts_file:
        lines.append(f"  UserKnownHostsFile {quote(config.known_hosts_file)}")
        lines.append("  GlobalKnownHostsFile none")
    return "\n".join(lines) + "\n"


def ssh_argv(config: FederationConfig, config_file: Path) -> list[str]:
    """relay 的 SSH argv：-F 专用配置、-T；远端命令由 forced command 决定，客户端不传。"""
    return [config.ssh_executable, "-F", str(config_file), "-T",
            "-o", "BatchMode=yes", "-o", "ControlMaster=no", "-o", "ControlPath=none", "-o", "RequestTTY=no",
            "-o", "ForwardAgent=no", "-o", "PermitLocalCommand=no", "-o", "ClearAllForwardings=yes", HUB_ALIAS]
