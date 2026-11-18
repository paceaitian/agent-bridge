# agent-bridge

让本地 AI 编码 agent 会话之间互相交接任务：把活交给另一个会话、请它复核、把结果回传，全程有账本可查。支持 **Linux** 与**原生 Windows**；可选的跨设备协作经一个只做存储转发的 hub（SSH）。

目前支持 **Codex CLI**（原生队列投递）、**Claude Code**（会话 socket 投递）与 **Grok Build**（只读，可作为发起方，不能作为收件目标）。

```console
$ agent-bridge peers                    # 列出可投递的会话；每行的 target= 可直接照抄
$ agent-bridge send --to codex@id:<完整ID> -m "实现 X，完成后请复核" --review-by claude@id:<完整ID>
$ agent-bridge status <任务ID>
```

## 它做什么

- **交接**：把一段任务投进另一个 agent 会话的收件通道，附上机器可读的消息头与「怎么汇报」的说明。
- **追踪**：任务、尝试、投递结果、对方汇报全部落在本机 SQLite 账本里；`status` 给出时间线与下一步。
- **复核流程**：交接 → 交结果 → 转给复核方 → 通过/要求修改 → 验收。
- **不做的事**：不启动、不恢复、不唤醒任何模型会话；只把消息放进对方已有的收件通道，对方什么时候读由它自己决定。

## 安装

只用标准库，无第三方依赖，要求 Python ≥ 3.12：

```console
$ pip install --user .
$ agent-bridge doctor
```

也可以不安装直接跑：`PYTHONPATH=src python3 -m agentstatus_bridge doctor`。

### 可选：把命令名缩成 `ab`

```console
$ ln -s ~/.local/bin/agent-bridge ~/.local/bin/ab
```

生成给对方 agent 的命令串会跟着你实际调用的名字走（`ab …` 还是 `agent-bridge …`），也可以用 `AB_COMMAND` 显式指定。

> `ab` 在很多发行版上是 ApacheBench（Debian 装机率约两成）。所以它只是可选别名，装什么名字由你决定——但**别让页脚写一个用户敲不出来的名字**，这是命令名按入口解析的原因。

### 与 AgentStatus 集成版共存

本项目的代码同时以**内容快照**的形式随 AgentStatus（作者的桌面状态面板项目，未公开）发布，那边的安装器会在 `~/.local/bin/ab` 建一条指向它自己 release 的符号链接，并把账本根绑定到 `~/.local/state/agentstatus/bridge`。

如果你两边都装：

- **不要**让本项目也装出一个叫 `ab` 的脚本（所以 `pyproject.toml` 只声明 `agent-bridge`）。pip 写同名脚本时会用普通文件顶掉那条符号链接且**不给任何警告**，结果是现役入口被换成未绑定的开发态脚本，落到另一个账本根上——任务看起来凭空消失。
- 两边**默认用不同的账本**：本项目默认 `~/.local/state/agent-bridge`，集成版绑定 `~/.local/state/agentstatus/bridge`。这是有意的，不做自动合并。
- 拿不准时跑 `agent-bridge doctor`：它会显示 `stateRoot`（用的哪个根）、`stateRootSource`（`default` / `env` / `integration`）与 `command`（对外命令名）。

## 状态与配置

| 变量 | 作用 |
| --- | --- |
| `AB_STATE_DIR` | 账本目录；默认 `${XDG_STATE_HOME:-~/.local/state}/agent-bridge`，权限 0700 |
| `AB_COMMAND` | 生成给 agent 的命令名；默认按实际入口名解析 |
| `AB_DEVICE` | 消息头里的设备名；默认取主机名第一段 |
| `CODEX_HOME` / `GROK_HOME` / `AB_CLAUDE_SESSIONS_DIR` | 各 provider 的只读发现位置 |

账本（`bridge.sqlite3`）里**含任务正文**，目录与文件都是 owner-only，只供本机同一用户读写。跨设备任务由 relay 经 hub 存储转发，发起设备的账本是该任务的权威，其他设备只保留镜像。

## 已知边界

- **依赖上游未正式承诺稳定的本机接口**：Claude Code 的会话注册记录与 `peerProtocol 1` socket；Codex 的原生队列与 app-server。**上游变动可能让投递失效**——Codex 不设精确版本门（`doctor` 只记录 Codex CLI 版本，是否支持按上游实际应答判定），Claude 只认 `peerProtocol 1`；遇到不认识的形状时报「找不到目标」或「不支持的协议版本」，不会静默乱投。
- Grok Build 目前**没有收件通道**，只能作为发起方；把它设成目标会在发送前被拒（`target_no_inbox`）。
- 面板/桌面通知等集成属于 AgentStatus，不在本项目内；没有它也能完整使用命令行。
- 消息投递依赖对方会话仍在运行；对方退出后消息不会补投，`status` 会提示。

## 开发

```console
$ PYTHONPATH=src python3 -m unittest discover -s tests -t tests
```

无需第三方依赖、无需 tmux、无需 GNOME、无需安装 AgentStatus。Windows 上跑选择集：`python -B scripts/verify-bridge-windows.py`。

**关于注释里的文档引用**：源码与测试里的 `DESIGN §45.x`、`docs/…` 指的是**上游 AgentStatus 仓库**的设计文档与说明，不是本仓库的文件。这批代码是从那里逐字节导入的（来源提交见 [`docs/import-manifest.json`](docs/import-manifest.json)），保留这些引用是为了让两边的实现史可追溯。

跨进程/跨语言的对照测试（桥算出的绑定键 vs AgentStatus 面板公开的会话行、以及 `summary.json` 合同的 Python/JS 双端校验）留在上游仓库，因为它们必须同时看两侧。

## 许可

尚未选定许可证。在补上 LICENSE 之前按默认版权处理（保留所有权利），公开仓库仅供阅读与参考。
