# Agent Safeguard

Local sensitive information protection for coding agents. Currently supports Claude Code.

[MIT License](LICENSE) · [GitHub](https://github.com/yipengfei329/agent-safeguard)

面向编程智能体的本地敏感信息防护项目，目前已实现 Claude Code 适配。版本 0.1.6，已在本机 Claude Code 2.1.312 和桌面端引擎 2.1.325 验证工具结果拦截。命中时扣留结果并停止下一次推理；检测和规则加载均在本地完成。

**实验性开源版本，已验证 Claude Code 工具结果配置的用户级自动加载。** 严格上下文配置仍有阻断普通任务的兼容性问题；工具结果配置可正常运行，但不检查自动上下文。详见 [验收报告](docs/acceptance.md)。

项目目录、npm 包、启动脚本和 Claude 插件统一命名为 `agent-safeguard`。命令行入口为 `bin/agent-safeguard.mjs`，状态命令为 `/agent-safeguard-status`。

## 自动加载

安装器会安装并启用 `agent-safeguard@agent-safeguard-local`，scope 为 user。完成安装后直接运行 `claude` 即可；同机 Claude App 的本地 Code 会话按官方共享设置机制加载，无需启动器、开机服务或额外参数。已有会话需重启或新建会话后加载；没有改动运行中的会话。

普通 Claude Chat 不运行 Hooks，本插件不保护普通聊天。Cowork 从账号 Customize 加载插件，本次本地安装不覆盖它；远程/云端 Code 也不继承本机安装。已在测试机器核实桌面 Code 的共享配置路径，尚未做桌面 UI 内的实际会话验收。

默认安装启用工具结果和用户输入检查；自动上下文仍不在当前配置覆盖范围。`/agent-safeguard-status` 可查询 pluginVersion、ready、blocked、lastEvent、lastRule 与规则版本，但不用每次启动手动开启。禁用 Mods 的宿主设置或启动参数可能让插件缺席。

安装前需要 Node.js 22+、npm 和支持 Mods 的 Claude Code。当前验证版本为 CLI 2.1.312 与桌面引擎 2.1.325；其他版本需验证兼容性。先确认 `claude` 命令可用，再执行：

```sh
git clone https://github.com/yipengfei329/agent-safeguard.git
cd agent-safeguard
npm ci
npm run install:user
```

安装器将运行文件复制到 `~/.local/share/agent-safeguard/marketplace`，注册本地 marketplace 并做用户级安装；首次选择已验证的工具结果配置，保留该目录已有规则。新版本发布需递增插件版本并通过 Claude 的 update 命令更新；重复 install 不等于升级缓存。

禁用和卸载：

```sh
claude plugin disable agent-safeguard@agent-safeguard-local --scope user
claude plugin uninstall agent-safeguard@agent-safeguard-local --scope user
```

开发时仍可用 `--plugin-dir` 或 `bin/agent-safeguard.mjs`。安装版和开发版不要在同一会话重复加载。

## 当前路径和邮箱策略

用户目录路径是正常编程输入：`/Users/…` 和 `/home/…` 在提示词及工具返回中均不再单独触发拦截。邮箱地址也不再单独触发自动拦截，正常 Git 作者与共同作者信息允许通过。主机名字段、非豁免 IP、凭据和设备标识的检查保留。路径内容中的其他敏感信息仍会被检测；路径不是整条内容的放行条件。

## 当前本机和内网 IP 策略（0.1.4）

`network.address.detector.excludeCidrs` 是可迭代的网段豁免配置，加载时预编译，仅豁免当前规则中匹配的那个地址。同一内容中的其他地址、密码、设备标识和自定义精确规则仍检查。IPv4 映射的 IPv6 地址按其内嵌 IPv4 同样判断。

| 类型 | 默认放行范围 |
| --- | --- |
| IPv4 私网 | `10.0.0.0/8`、`172.16.0.0/12`、`192.168.0.0/16` |
| 本机回环 | `127.0.0.0/8`、`::1/128` |
| 链路本地 | `169.254.0.0/16`、`fe80::/10`（支持 zone） |
| IPv6 ULA | `fc00::/7` |
| 共享地址（CGNAT） | `100.64.0.0/10` |
| 基准测试地址，兼容代理 Fake IP 使用 | `198.18.0.0/15` |
| 未指定/监听地址、有限广播 | `0.0.0.0/32`、`::/128`、`255.255.255.255/32` |

地址分类参考 [IANA IPv4](https://www.iana.org/assignments/iana-ipv4-special-registry/) 和 [IANA IPv6](https://www.iana.org/assignments/iana-ipv6-special-registry/)。共享地址与基准测试地址单独列出，不混称 RFC 1918 私网。不会动态收集本机出口并加入豁免；公网出口及本机的全局 IPv6 地址仍检查。文档示例地址不默认放行，继续用于合成拦截测试。

删除或调整 `excludeCidrs` 后用规则 apply 命令加载，新会话生效。旧配置没有该字段时保留原来的全部 IP 检测行为；升级程序保留用户规则；已有配置若要使用新的放行范围，需要显式合并该字段。

## 规则迭代

```sh
npm run rules -- validate config/rules.example.json
npm run rules -- apply /absolute/path/to/private-rules.json --user
npm run rules -- rollback --user
```

配置先做校验，再原子替换规则并保存上一版。`--user` 修改用户安装源下的 `local/rules.json`；不带该参数则修改项目开发配置。只在新会话加载，不对运行中会话热切换。真实个人规则不提交到 Git。

支持 IP/CIDR、精确值、域名、凭据、设备标识和个人环境检测器。block 扣留结果；observe 只累计规则编号，可通过状态命令查看，不提供保护。默认 IP 规则按下表排除本机及内网地址；范围之外的地址继续阻断。按来源和工具范围收窄规则时，保护范围也随之收窄。

## 复现测试

```sh
npm test
npm run test:mods
npm run test:e2e
npm run bench
npm run validate
```

测试仅使用 [虚构历史场景](fixtures/replays.json)。真实 CLI 测试使用临时 HOME、虚构 API key 和本机 HTTP 模型桩，不使用真实账号凭据。MCP、子代理内容的真实 CLI 回放由 Bash 输出模拟；原生 Mods 测试另外覆盖 MCP 事件，不能冒充真实远端 MCP/后台子代理全链路验收。

## 当前边界

- 已验证：成功和失败结果、文本及嵌套 JSON、常见地址与设备信息、并发阻断状态、配置错误、下一步模型请求阻断。
- 不保证：任意编码或混淆、图片/PDF 内容识别、遥测、附件上传、工具直接联网、历史会话、恶意插件、插件缺席或 worker 崩溃后的宿主行为。
- 未支持：运行中规则热切换、全量历史上下文重验、持久审计、自动脱敏和个人资产自动发现。观察计数仅保存在当前插件实例中。
- 工具结果扣留不撤销已完成的命令；模型已知内容无法撤回；网络请求本身的出口 IP 不由本插件隐藏。
- 扫描有 4 MiB/深度/节点/100 ms 协作式预算，超限扣留。预算不能抢占单条同步操作，也不能保证宿主失效时仍关闭出站。

[一期设计](docs/v1-design.md) 是目标规格，以上状态和验收报告描述实际实现。项目不是 Anthropic 官方产品。

## 参与贡献

欢迎提交新的 Agent 适配器、检测器和误报修复。请用虚构的最小样本补充回归测试；不要在 Issue、PR、日志或截图中提供真实 IP、Token、设备标识或私有规则。开发约定见 [AGENTS.md](AGENTS.md)。核心测试不需要 Claude 账号；原生插件测试需要兼容的 Claude Code，本地模型桩回放使用虚构 API key。

## 协议

本项目采用 [MIT 协议](LICENSE)。
