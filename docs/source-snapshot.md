# 当前源码快照

本源码版本包含客户端 gitlink、服务端 Rust 基线、管理 Web 和安装工具。它不是正式发行包，也不表示整套产品已通过新目录下的构建或运行验收。

## 已纳入范围

- 私有主仓：`vickkk-kkk/vp-product`。
- 公开客户端 fork：`vickkk-kkk/vpn-parser`；gitlink 固定 [`51ccda91cae9c68ca4725a44dd836e985a611db1`](https://github.com/vickkk-kkk/vpn-parser/commit/51ccda91cae9c68ca4725a44dd836e985a611db1)，模式 `160000`。该提交来自 `work/client-foundation`，包含共享业务层、完整 parser 抽取及更新器保护；上游来源基线仍为 `cf3bfcf8fc70518e75d036bd4db72fcee8713541`。
- 服务端与共享库：根 Cargo workspace、`crates/`、`contracts/`、核心锁与补丁。
- 管理 Web：`flutter/apps/vp_admin/` 和 `vp_contracts`、`vp_design_system`、`vp_features`、`vp_runtime_platform`、`vp_api_client` 五个共享包。
- 部署工具：`tools/install/` 的本地 bundle 与生命周期源码，以及 `tools/core/` 的核心重建工具。没有由此安装或部署服务。

328 个导入源码及技术资产文件的来源 blob、SHA-256 和明确变更记录见 [源码导入清单](../source-export-manifest.json)。选用基线为 `e267153e7a9c3443a32158c00a1d86ecc1f7fb78`；更新的 TLS 服务端候选未合并，其测试不能归给本版本。

旧 Flutter 客户端及其原生宿主、运行状态、缓存、SDK、构建产物、研究笔记、会话和审批记录均不属于交付树。

## 核心源码重建是构建前提

`integration/vp_core/` 不随源码提交。必须按 `core-lock.json` 固定的上游身份、有序补丁与结果身份重建；参见 [核心重建说明](../tools/core/README.md)。即使可选 feature 未启用，Cargo 也可能要求这些 path 依赖先存在。不能将缺失依赖误判为无需核心源码，也不能以复制开发机缓存代替重建。

## 已完成检查与未完成验证

| 对象 | 已有检查 | 不代表什么 |
| --- | --- | --- |
| 客户端 submodule | URL、完整提交、`160000` 模式核对 | 已绑定定制源码，不代表完成 GUI 或平台验收 |
| 客户端共享业务层改造 | 实际客户端 workspace 的 core 测试 71/71 通过，覆盖共享业务层与完整 parser 抽取 | 不是完整 workspace、GUI 或原生 VPN 验收；完整客户端与平台验证仍待完成 |
| 原始 fork 根目录 Linux headless 测试 | Rust 1.88 常规编译测试 harness，根 features=[]；更新器保护提交经过常规增量编译，11 个指定纯逻辑测试通过（原有 8 项 + 3 项更新器保护测试） | 不是 GUI 构建、完整测试套件或平台验收；未启动主程序、应用或引擎运行时 |
| 导入源码 | 源文件摘要、Python AST、TOML/JSON、核心补丁哈希检查 | 不是 Rust/Web 构建或部署验证 |
| 核心流水线工具 | 20 个合成 Git 仓库单元测试通过 | 不是实际核心补丁重放或协议互通 |

当前源码检查点为 `51ccda91cae9c68ca4725a44dd836e985a611db1`。完整 parser 抽取先前已在实际 workspace 通过 71 项 core 测试；更新器保护提交另经根目录 Linux headless 常规增量编译，11 个指定测试通过。没有运行实时 collector、网络请求、主程序、GUI 或引擎运行时；编译告警保留，不宣称 warning-clean。

更新器保护已发布并纳入锁定提交；About 界面相关变更仅完成静态审查，尚未进行 GUI 编译。已有 `collector/mod.rs` 诊断日志修复仅覆盖该模块日志，存储与 UI 错误未改变，不代表全应用隐私整改。

主仓通过精确 gitlink 绑定定制源码，后续 clone 将获取这个可复现的开发源码检查点。它不是可安装的二进制发行版，也不代表 GUI、原生 VPN 或完整平台验收通过。

服务端归集目录下尚未完成 Rust 构建与真实核心重放；Flutter 构建/API 联调、客户端 GUI 构建、协议互通、移动平台验收和部署也仍待完成。秘密特征扫描及文件审查不能作为绝无秘密或已完成安全认证的保证。

## 公开测试材料例外

源码保留一份来自 `ring` 0.17.14 公开源码归档的 RSA 测试私钥，连同来源说明与许可。其归档摘要与 Cargo.lock 对照，文件摘要与基线一致。这是刻意公开、不安全的测试夹具，严禁部署使用；它不允许提交真实密钥、凭据或运行时私密状态。字体等第三方资产保留各自来源与许可，客户端 MIT 许可不覆盖全部主仓组件。
