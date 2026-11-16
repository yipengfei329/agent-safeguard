# Agent Safeguard 桌面端 0.3.0

Rust + GPUI Kit 管理端。三页为概览、安装管理、规则编辑，管理本机 Claude Code 用户范围插件。随应用内置插件 0.2.0，与 `src/core.js` / `src/credentials.js` 共用检测引擎；适配层提供状态上报和桌面规则路径。

## 使用流程

1. 打开应用，在“安装管理”中自动发现或手动选择 Claude Code，安装插件。普通用户不需要 Git、npm、Rust 或 Node。
2. 在 Claude Code 中新建会话。“概览”显示正在保护的会话，以及独立保存的拦截历史。
3. 在“规则编辑”中开关内置规则、添加精确文本，点击“保存更改”。保存保留上一版，新建会话加载；旧会话不会热更新或解锁。
4. “恢复上一版到草稿”先恢复草稿，检查变化后再保存。卸载默认保留规则。

正常模式读取本机配置。`--demo` 使用临时规则目录和虚构安装信息，禁用宿主变更与在线更新，不伪造真实会话。真实测试均在临时 HOME / CLAUDE_CONFIG_DIR 中运行。

## 恢复与脱敏草稿

规则页新增“生成安全恢复草稿”和“生成恢复与 IP 脱敏草稿”，生成后需检查并保存；保留现有规则范围和上一版。先更新插件再保存 schema 2，新插件实例生效。会话详情显示脱敏、替换、暂停与恢复计数；可恢复的暂停有单独文案。完整流程与范围见 [恢复与脱敏说明](../docs/recovery-redaction.md)。

## 构建与验证

开发需要 Node.js 22+、Rust stable 和平台原生构建依赖；这些不是最终用户依赖。

```sh
npm ci
npm run build
cargo test --release --locked --manifest-path desktop/Cargo.toml
cargo run --release --manifest-path desktop/Cargo.toml -- --demo
python3 desktop/scripts/package.py
python3 desktop/scripts/smoke.py
python3 desktop/scripts/flow.py
python3 desktop/scripts/validation-matrix.py
python3 desktop/scripts/measure.py --runs 20 --seconds 30
```

- `package.py` 生成 macOS arm64 app、ZIP、DMG，附第三方许可；本地 ad-hoc 签名，未公证。
- `smoke.py` 验证真实 CLI 安装/更新/启停/卸载和失败恢复，隔离用户配置。
- `flow.py` 使用真实已安装插件与本机虚构模型桩，检查自动报告、心跳、保存规则、新会话阻断和真实模型请求次数。
- `validation-matrix.py` 比对原 Node 检测器和内嵌 QuickJS 校验结果，包括 Unicode、错误 CIDR、重复 ID 与观察规则。
- `.github/workflows/desktop.yml` 配置三个系统的构建测试。未运行的 CI 和非本机平台不能视为已验收；当前安装器仍仅 macOS arm64。

## 实现边界

**安装。** 安装/更新后重新查询 Claude 注册信息。内置版本来自应用自身；低于已安装源版本时拒绝降级。调用失败恢复安装源文件，但宿主注册和缓存不保证一起回滚，界面要求重新检测。

**更新。** 用户手动检查固定项目 GitHub Release 源，不扫描任意 URL。更新资产 `agent-safeguard-plugin.json` 由 `plugin-package.py` 生成，需要 GitHub Release API 提供 SHA-256 digest。仅接受规定的六个文件、4 MiB 内的包，先核对来源、摘要、版本和清单，再安装。真实性依赖固定 GitHub 仓库与 HTTPS，摘要是完整性验证，不冒充独立开发者签名。检测引擎字节变更时要求同步更新桌面应用，避免新引擎配旧校验器。生成资产不等于发布；当前环境无法连接 GitHub API，线上发布源实测仍待完成。

**概览。** 上方按会话标题、项目、Agent 和模型展示 45 秒内报告、已就绪且未阻断/结束的会话；按真实宿主会话 ID 合并重复插件实例。标题来自宿主可选字段，未提供时显示“未命名会话”，不会读取聊天全文或调用模型生成。下方按拦截时间显示所属会话、项目、Agent、具体规则与处理结果。工具名称和子代理类型在可取得时显示；完整路径、会话 ID、插件及规则版本放在详情。当前仅支持 Claude Code。

**采集。** 复用本机 Mods 生命周期字段，在后台查询一次会话 ID、项目根目录和模型。扫描路径只记录有界元数据和脏标志，首次拦截额外调度一次后台写入，不等待文件写入；后台每秒检查变更并合并报告，15 秒心跳，单写入在途。桌面每 2 秒在后台读取，文件未变化时复用解析缓存。拦截归属在事件发生时快照，schema 2 的第一次拦截独立归档；schema 3 按每次拦截 recordId 归档，心跳不重复记日志。原检测逻辑和规则语义保留。

**边界。** “防护已接入”表示插件报告已就绪，不能证明所有内容均被检查；二进制内容默认放行，其他扫描错误目前统一为 `inspection.failed`。扣留结果不撤销已执行操作。失去心跳不标为已结束，也不再列入正在保护。旧版报告不能补出标题和项目；需要更新插件并新建会话。状态通道失败不改变检测判定；崩溃前尚未异步落盘的记录可能丢失，不作为完整审计。状态文件不能防御同用户进程伪造。

**规则。** 原引擎编译成桌面专用 IIFE，由内嵌 QuickJS 运行；仅校验，不执行用户脚本，不访问网络。执行限制 64 MiB、512 KiB 栈、2 秒。新增精确文本使用 block 与已支持的三个来源；高级规则只读保留，不重建配置或改写 observe。配置摘要检查与进程锁防止桌面并发覆盖；非协作外部写入者仍需避免同时保存。显示名独立存储，并绑定配置摘要。原子替换规则，保存上一版；元数据写入中崩溃最多丢失显示名称，不改变规则语义。

**本地数据。** 默认 `~/.local/share/agent-safeguard/`：marketplace 下的 `local/rules.json`、`rule-names.json` 与上一版；`sessions/` 下的报告及 `interceptions/` 下的历史。Unix 目录 0700、规则文件 0600。保留最近 100 个插件实例和 500 条拦截记录，历史每页 10 条。桌面打开时清理超出保留数且已过期的报告。记录包含用户要求的标题、项目路径和规则 ID，仅保存在本机；不保存命中值、工具参数、工具输出或聊天正文。旧版自定义规则显示名在当前配置版本匹配时解析；schema 3 将自定义规则编号归为 custom.rule，不记录自定义命中内容。

详细设计见 [一期页面规格](../docs/design/desktop-v1.md)，本轮验收见 [桌面一期验收](../docs/desktop-v1-acceptance.md)。原型历史测量保留在 [原型报告](../docs/desktop-prototype.md)。

## 概览验收

实现、接口依据、性能对照和验证范围见 [概览观测说明](../docs/desktop-overview-observability.md)。
