# Agent Safeguard

Local sensitive information protection for coding agents. Currently supports Claude Code.

[MIT License](LICENSE) · [GitHub](https://github.com/yipengfei329/agent-safeguard)

面向编程智能体的本地敏感信息防护项目，目前已实现 Claude Code 适配。版本 0.2.1，已在本机 Claude Code 2.1.312 和桌面端引擎 2.1.325 验证工具结果拦截。命中时扣留结果并停止下一次推理；检测和规则加载均在本地完成。

**实验性开源版本，已验证 Claude Code 工具结果配置的用户级自动加载。** 严格上下文配置仍有阻断普通任务的兼容性问题；工具结果配置可正常运行，但不检查自动上下文。详见 [验收报告](docs/acceptance.md)。

项目目录、npm 包、启动脚本和 Claude 插件统一命名为 `agent-safeguard`。命令行入口为 `bin/agent-safeguard.mjs`，状态命令为 `/agent-safeguard-status`。

## 输入扫描超时恢复（0.2.1）

修复 Write 等输入检查故障被宿主显示为“Nothing refused it”的问题：先返回明确拒绝，再拦住后续模型请求。单次扫描超时后，旧工作结束、下一条可信用户消息通过检查，并且当前规则快照的本地自检通过，才可恢复。资源超限、内部异常、上下文污染仍保留原来的故障门禁；不重放旧工具，也不提高扫描预算。详见 [修复与验证记录](docs/timeout-recovery.md)。

## IP 脱敏与拦截后恢复（0.2.0）

新增可选择启用的 schema 2：支持的同步 Bash 诊断输出可在本地替换受保护 IP，并在重检后继续任务；其余敏感规则仍扣留结果。普通拦截只暂停当前轮次，旧调用和子代理结束后，下一条安全消息可继续原会话。错误、超时和上下文污染保留独立故障门禁。

已有规则保持原行为；先更新插件，再从当前配置生成、review 并保存迁移草稿，新插件实例加载。桌面也提供草稿按钮。操作步骤、宿主限制及验证范围见 [使用说明](docs/recovery-redaction.md) 和 [验收记录](docs/recovery-redaction-acceptance.md)。

## 自动加载

Rust + GPUI Kit 桌面端 0.3.1 已接通安装管理、会话概览、拦截历史和表单式规则编辑，并采用紧凑的深色界面。检测引擎保持不变；桌面内嵌规则校验，普通用户无需安装 Node。当前已验证本机 macOS，三平台正式发布仍待验收。使用方法与边界见 [桌面端说明](desktop/README.md)，验证记录见 [桌面一期验收](docs/desktop-v1-acceptance.md)。

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

## 不支持的内容（0.1.9）

图片、音频、PDF 等暂不支持检查的二进制内容默认放行，不再因此锁住会话。该行为不代表图片内的信息已被检测；同一结果中的文本、标题、URL 等仍按规则检查。配置项 `policy.onUnsupportedContent` 默认为 `allow`，可显式改为 `block`。扫描超时、文本超限和内部异常仍阻断。已有规则需更新此配置，已有会话需重新加载插件或重启后生效。

## 当前路径和邮箱策略

用户目录路径是正常编程输入：`/Users/…` 和 `/home/…` 在提示词及工具返回中均不再单独触发拦截。邮箱地址也不再单独触发自动拦截，正常 Git 作者与共同作者信息允许通过。主机名字段、非豁免 IP、凭据和设备标识的检查保留。路径内容中的其他敏感信息仍会被检测；路径不是整条内容的放行条件。

## 模拟器设备标识（0.1.16）

同一条完整设备记录中，`platform` 明确为 `iOS Simulator`、`tvOS Simulator`、`watchOS Simulator` 或 `visionOS Simulator` 时，仅对该记录的 UUID 格式 `deviceId`/`device_id`/`device-id`/`udid` 放行。支持结构化工具结果、JSON 和包含 grep 行号/上下文前缀的日志。例外不会传播到相邻设备、子对象或整个输出；序列号、硬件 UUID、MAC、主机名、凭据及其他规则继续检查。

没有平台标记、只有描述里的 Simulator 字样、不完整/无法解析的记录继续按设备规则检查。这是基于工具输出元数据的判断，无法验证设备物理身份；自定义精确规则仍可拦截指定模拟器 UUID。已有会话需重新启动后加载新引擎。测试与边界见 [模拟器检测说明](docs/simulator-identifiers.md)。

## 凭据与身份字段检测（0.1.25）

0.1.25 区分明确的 Secret/变量名称声明、完整引用和实际凭据值。普通赋值、结构化数据及注释中的密钥继续检查；名称和值采用分离的缓存，保留相邻值和字面量拼接检测。没有具体名称白名单，详情见 [凭据检测说明](docs/credential-detection.md)。

0.1.24 减少密集代码的重复类型解析、逐词扫描和候选值处理，保持 100 ms 预算。新增重复/逐行唯一源码以及 1 MiB 末尾凭据的完整原生 hook 回归；测量口径与复现方法见 [密集代码扫描说明](docs/dense-scanning.md)。

0.1.23 对通用 Token 增加有界词形证据判断：短数字前后缀，以及词形前缀后的短、单一大小写字母数字材料，不再仅凭整串长度和熵阻断。密码字段、显式密钥格式、认证 URL 和精确规则仍检查。该策略不能区分同形的真实短 Token，应使用精确规则保护必须拦截的已知值。

0.1.22 将凭据、设备标识和主机名接入统一的值提取器，移除身份规则把任意右侧文本按长度拦截的分支。调用（包括截断调用）、代码引用、类型、条件表达式和容器不再当作实际身份值；明确字面量、结构化数据及相邻敏感值继续检查。设备标识、主机名和计算机显示名称分别检查值形态，状态命令新增不含原值的 `lastReason`。这是有界词法识别，不是完整语言解析；模糊片段、未知字符串语法及非常规标识符仍有限制。

0.1.21 改为先识别凭据材料的字符形态，再判断长度与熵；引用标签及其括号、冒号等语法不能被合并成秘密值证据。令牌、混合字符密码和密码短语分别判定，语法包裹中的实际密钥仍会被检查。没有增加针对某个占位符名称的白名单。普通文本与证据不足的值放行，因此仍不保证任意弱密码、自然语言口令或未知编码都能检出。

0.1.20 修复空 shell 赋值误吞下一字段；按完整词识别 `DB_PASSWORD`、`serviceApiToken` 等字段，保留元数据与类型声明的局部例外。模板中的固定片段单独检查，纯变量引用继续放行；认证 URL 支持空用户名。该判断不是完整语言解析，含模板的固定片段仍需满足原有秘密证据阈值。

0.1.19 将语法提取与值证据拆分：完整 TypeScript interface / 对象类型声明中的字段不当作运行时赋值；字符串按解码后的值判断，保留原始偏移处理拼接。通用凭据判断降低对字段标签、受限提示语、可读路径、MIME 和占位符的误报；不影响独立 Token 格式、认证 URL、私钥或自定义精确规则。新增局部词法判断不是完整 AST，短片段仍可能有歧义。具体策略、Gitleaks / detect-secrets 实测对照及研究依据见 [凭据检测说明](docs/credential-detection.md)。

凭据检测先提取具体值，再检查秘密特征；无法识别的源代码表达式默认放行。支持 `.string(key)` 等变量表达式放行和 `.string("具体值")` 的值检查，不再仅因字段叫 `token/password` 就阻断。Rust 等语言的类型声明、变量引用、占位符和证据不足的短字符串放行；私钥、认证 URL、已支持的 Token 格式，以及凭据字段中具有明确秘密值特征的内容继续拦截。JSON 转义不再被误当成秘密值的一部分。放行只针对当前表达式，不豁免整行、整个文件或相邻字段。

该策略优先降低误报，因此无法保证拦截短密码、弱密码和未知格式的短 Token；需要强制保护的特定值可以配置 `exact` 规则。

每次修复须同时添加“正常代码应放行”和“相邻真实凭据应阻断”的测试。实现、限制与复测方法见 [凭据检测说明](docs/credential-detection.md)。

IPv6 匹配从 0.1.10 起要求完整结束边界，避免将 `grep -n` 输出的 `9::root`、CSS 伪元素等截成地址片段。相邻的真实地址仍会独立检测。

## 当前 IP 策略（0.1.13）

默认 `network.address` 使用 `mode: "country", country: "CN", onUnknown: "allow"`。HK/MO/TW 等单独地区代码不属于 CN。IPv4 与 IPv6 均离线查询，IPv4-mapped IPv6 使用内嵌 IPv4 的分类。可加载引擎中的数据库内容缺失或损坏是初始化错误，会阻断并显示 `initialization.failed`，不会伪装成未知地址。`/agent-safeguard-status` 的 `geoip` 显示数据库月份和策略。

数据预编译后随插件发布，单次查询无网络、文件读取或子进程。每个插件实例首次启用国家规则时加载一次；新增规则重用索引。数据库按月更新需维护者运行 [更新脚本](scripts/update-geoip.py)、测试、发布新版，不在会话里自动下载。详情与性能见 [GeoIP 方案](docs/geoip-selection.md)。

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

地址分类参考 [IANA IPv4](https://www.iana.org/assignments/iana-ipv4-special-registry/) 和 [IANA IPv6](https://www.iana.org/assignments/iana-ipv6-special-registry/)。共享地址与基准测试地址单独列出，不混称 RFC 1918 私网。不会动态收集本机出口并加入豁免；公网出口及本机的全局 IPv6 地址仍检查。默认使用离线 GeoIP，仅拦截分类为 `CN` 的地址。其他地区和未知地址放行，文档示例地址因此放行；不影响同一内容中的密钥等规则。

删除或调整 `excludeCidrs` 后用规则 apply 命令加载，新会话生效。升级程序保留用户规则；旧 `mode: "any"` 和 `mode: "cidr"` 仍有效，不会自动被改写。已有配置需要显式把目标 IP 规则改成国家模式，并保留原有 `excludeCidrs`。

## 规则迭代

```sh
npm run rules -- validate config/rules.example.json
npm run rules -- apply /absolute/path/to/private-rules.json --user
npm run rules -- rollback --user
```

配置先做校验，再原子替换规则并保存上一版。`--user` 修改用户安装源下的 `local/rules.json`；不带该参数则修改项目开发配置。只在新会话加载，不对运行中会话热切换。真实个人规则不提交到 Git。

支持 IP/CIDR、精确值、域名、凭据、设备标识和个人环境检测器。block 扣留结果；observe 只累计规则编号，可通过状态命令查看，不提供保护。默认 IP 规则按下表排除本机及内网地址；范围之外的地址继续阻断。按来源和工具范围收窄规则时，保护范围也随之收窄。

0.1.11 对全部规则进行了组合自测，修复身份字段代码误报、句尾地址漏检和敏感数组/数字值漏检；详见 [规则自测](docs/rule-audit.md)。

## 复现测试

```sh
npm test
npm run test:mods
npm run test:e2e
npm run test:recovery
npm run bench:recovery
npm run bench
npm run validate
```

测试仅使用 [虚构历史场景](fixtures/replays.json)。真实 CLI 测试使用临时 HOME、虚构 API key 和本机 HTTP 模型桩，不使用真实账号凭据。MCP、子代理内容的真实 CLI 回放由 Bash 输出模拟；原生 Mods 测试另外覆盖 MCP 事件，不能冒充真实远端 MCP/后台子代理全链路验收。

## 当前边界

- 已验证：成功和失败结果、文本及嵌套 JSON、常见地址与设备信息、并发阻断状态、配置错误、下一步模型请求阻断。
- 不保证：任意编码或混淆、图片/PDF 内容识别、遥测、附件上传、工具直接联网、历史会话、恶意插件、插件缺席或 worker 崩溃后的宿主行为。
- 未支持：运行中规则热切换、全量历史上下文重验、完整持久审计、通用敏感信息脱敏和个人资产自动发现。观察计数仅保存在当前插件实例中。
- 工具结果扣留不撤销已完成的命令；模型已知内容无法撤回；网络请求本身的出口 IP 不由本插件隐藏。
- 扫描有 4 MiB/深度/节点/100 ms 协作式预算，超限扣留。预算不能抢占单条同步操作，也不能保证宿主失效时仍关闭出站。

[一期设计](docs/v1-design.md) 是目标规格，以上状态和验收报告描述实际实现。项目不是 Anthropic 官方产品。

## 参与贡献

欢迎提交新的 Agent 适配器、检测器和误报修复。请用虚构的最小样本补充回归测试；不要在 Issue、PR、日志或截图中提供真实 IP、Token、设备标识或私有规则。开发约定见 [AGENTS.md](AGENTS.md)。核心测试不需要 Claude 账号；原生插件测试需要兼容的 Claude Code，本地模型桩回放使用虚构 API key。

## 协议

项目代码采用 [MIT 协议](LICENSE)。内置 IP 国家数据由 [DB-IP](https://db-ip.com/) 提供，来自 [DB-IP Country Lite](https://db-ip.com/db/download/ip-to-country-lite)，采用 [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/)。我们把国家代码缩减为 CN / 其他 / 未知，合并相邻区间后编码；插件及桌面内嵌数据同样适用该许可。数据并不能证明用户的实际位置。
