# Agent Safeguard 桌面端 0.2.0

Rust + GPUI Kit 管理端。三页为概览、工具、规则，管理本机 Claude Code 用户范围插件。随应用内置插件 0.1.11，与 `src/core.js` / `src/credentials.js` 共用检测引擎；适配层提供状态上报和桌面规则路径。

## 使用流程

1. 打开应用，在“工具”中自动发现或手动选择 Claude Code，安装插件。普通用户不需要 Git、npm、Rust 或 Node。
2. 在 Claude Code 中新建会话。“概览”自动显示插件实例、规则版本、最近状态与阻断/异常详情。
3. 在“规则”中开关内置规则、添加精确文本，点击“保存更改”。保存保留上一版，新建会话加载；旧会话不会热更新或解锁。
4. “恢复上一版到草稿”先恢复草稿，检查变化后再保存。卸载默认保留规则。

正常模式读取本机配置。`--demo` 使用临时规则目录和虚构安装信息，禁用宿主变更与在线更新，不伪造真实会话。真实测试均在临时 HOME / CLAUDE_CONFIG_DIR 中运行。

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

**状态。** 本机生成的 Claude Code 2.1.325 类型声明确认了 `$.fs.read/write`、`$.clock.every`。插件异步报告最小元数据：随机实例 ID、序号、版本、时间、ready/blocked/ended、允许列表内的事件和原因。不报告工具参数、输出、路径、命中值或用户自定义规则 ID。每次变化触发合并写入，单写入在途；15 秒心跳；桌面每 2 秒读取，45 秒无新报告显示待确认。读取部分文件失败保留上次有效状态，不推断为正常。退出窗口不影响检测；宿主退出前报告可能来不及写入，因此结束报告是尽力而为，缺失时通过过期处理。

“会话”目前是插件加载实例；热重载、恢复会话会产生新实例 ID，不宣称能关联主会话、后台子代理或所有宿主窗口。不支持的二进制内容默认放行且不检查其中的信息；文本等可检查部分仍检查。对于其他扫描错误，当前检测器只返回 `inspection.failed`，无法可靠细分超时、内容限制与其他扫描异常，界面明确显示这一限制。状态文件由同一用户进程写入，是管理可见性，不能防御恶意同用户进程伪造。

**规则。** 原引擎编译成桌面专用 IIFE，由内嵌 QuickJS 运行；仅校验，不执行用户脚本，不访问网络。执行限制 64 MiB、512 KiB 栈、2 秒。新增精确文本使用 block 与已支持的三个来源；高级规则只读保留，不重建配置或改写 observe。配置摘要检查与进程锁防止桌面并发覆盖；非协作外部写入者仍需避免同时保存。显示名独立存储，并绑定配置摘要。原子替换规则，保存上一版；元数据写入中崩溃最多丢失显示名称，不改变规则语义。

**本地数据。** 默认 `~/.local/share/agent-safeguard/`：marketplace 下的 `local/rules.json`、`rule-names.json` 与上一版；`sessions/` 下的报告。Unix 目录 0700、规则文件 0600。桌面只显示最近 100 个实例、最多 100 条变化记录，窗口内最近显示 10 条；读取时清理超出保留数且已过期的报告。桌面关闭时不运行清理服务，文件会在下一次打开时整理。报告不含敏感原文，仍按本地私有数据处理。

详细设计见 [一期页面规格](../docs/design/desktop-v1.md)，本轮验收见 [桌面一期验收](../docs/desktop-v1-acceptance.md)。原型历史测量保留在 [原型报告](../docs/desktop-prototype.md)。
