# 架构与目录

## 目录原则

客户端独立 fork，主仓使用一个 `client/` Git submodule。服务端、管理 Web、部署工具和产品契约在主仓维护，不再建立彼此独立且漂移的产品副本。

**以下是本源码版本的布局。** `integration/vp_core/` 是唯一需要按锁重建的核心工作树，不随源码提交；其他列出的组件入口已纳入。保留原有构建相对路径优先于为了外观搬动文件。

```text
privatevp-product/
├── README.md
├── client/                   # Git submodule；独立 Cargo.toml / Cargo.lock
├── Cargo.toml / Cargo.lock   # 服务端与产品共享 Rust workspace
├── rust-toolchain.toml
├── crates/                   # domain / api / control / storage / core-adapter …
├── contracts/                # Schema、OpenAPI、能力目录与测试夹具
├── core-lock.json            # vp_core 来源与补丁身份
├── patches/vp_core/          # 可审查、可重放补丁
├── integration/vp_core/      # 按锁重建；不复制开发机工作树
├── flutter/
│   ├── apps/vp_admin/        # Web 管理端；不包含旧 vp_client
│   └── packages/             # 仅 Web 所需共享包
├── tools/install/            # 原有安装器与本地 bundle 工具
└── docs/                     # 产品与贡献者文档
```

## 为什么暂时保留这些路径

- 服务端 workspace 使用 `crates/*` 相对依赖；核心适配器引用 `../../integration/vp_core/crates/*`。即使是可选依赖，缺失路径也可能阻断 Cargo 解析。
- Web 的 `vp_admin` 引用 `../../packages/*`；所需包是 `vp_contracts`、`vp_design_system`、`vp_features`、`vp_runtime_platform`、`vp_api_client`。设计系统字体等许可资产须一并保留。
- 安装与打包工具引用 `core-lock.json`、`contracts/` 以及 Web 产物路径，不能仅移动脚本后假定可运行。
- 后续如要收拢到实体 `server/`、`web/`、`deploy/`，必须单独提交路径迁移，并重新验证构建、代码生成、测试、打包和许可证资产。不要混入功能变更。

## 所有权与接口

| 边界 | 维护位置 | 约束 |
| --- | --- | --- |
| 客户端界面与共享 Rust 业务层 | 客户端 fork | 保留上游格式兼容；网络、进程与平台 VPN 生命周期隔离在适配层 |
| 产品领域模型与管理契约 | 主仓 `crates/`、`contracts/` | DTO、Schema、夹具和消费者协调修改 |
| Linux 管理服务与运行器 | 主仓 `crates/` | 管理 API 不绕过控制层直接改核心配置 |
| 核心依赖和补丁 | 主仓适配层及锁清单 | 生产核心依赖集中在适配边界；保持来源可追溯 |
| Web 管理界面 | 主仓 Flutter Web | 不把原生 VPN 插件或 FFI 加入 Web 依赖图 |
| 安装与发布 | 主仓工具及版本记录 | 清单拥有的文件、精确摘要、失败可见；不把安装成功等同于转发可用 |

客户端与服务端共享协议语义，不默认共享全部实现或锁文件。跨仓接口变化先定义兼容策略，再更新消费者与主仓 submodule 指针。
