# 开发指南

## 先确认代码状态

此工程已有真实 `.gitmodules` 与 `client` gitlink。本版本同时包含服务端、Web 和安装源码；下列命令只用于克隆与核对代码，不是构建或安装。

需要 Git 和私有主仓的读取权限。首次获取：

```sh
git clone --recurse-submodules https://github.com/vickkk-kkk/vp-product.git
cd vp-product
```

在产品主仓根目录检查：

```sh
git submodule update --init --recursive
git submodule status --recursive
git ls-tree HEAD client
git -C client rev-parse HEAD
git status --short
```

`git ls-tree` 中客户端条目的模式应为 `160000`，提交应与客户端 `HEAD` 一致。submodule 状态行前缀 `-` 表示未初始化，`+` 表示与主仓记录不一致，`U` 表示冲突；先解决再继续。

客户端实际绑定以 `git ls-tree HEAD client` 为准；本源码检查点固定定制提交 `d1a72b2a871295bbd556cf36728ebc56cfb784e1`，并非只含上游基线。精确范围与验证记录见 [当前快照](source-snapshot.md)。克隆得到的是固定源码检查点，不保证已有可安装二进制。

## 构建先决条件

| 组件 | 必须准备 | 当前限制 |
| --- | --- | --- |
| 客户端 | fork 锁文件对应的 Rust 依赖；桌面目标所需图形系统库 | 上游可运行不等于本 fork 已验收；移动平台另行验证 |
| 服务端 | `rust-toolchain.toml`、`Cargo.lock`；按 `core-lock.json` 重建的核心源码与补丁 | 不复制旧缓存或机器特定链接；核心 path 依赖必须完整 |
| Web 管理端 | 锁定的 Flutter/Dart SDK、依赖锁及 Web 所需共享包 | 不引入旧客户端和原生 VPN 插件依赖 |
| 安装工具 | Python 3、受支持 Linux 环境；真实构建产物与可信摘要 | 不自动下载、签名、部署或修改主机网络 |

本版本的静态检查不包含完整构建。本文不发布未经验证的 `cargo build`、`flutter build` 或安装脚本命令。剩余任务见 [源码归集清单](source-integration.md)。原目录的构建记录只能作为迁移基线。

### 服务端核心必须先重建

新 clone 不包含 `integration/vp_core/`。先阅读 [核心重建工具说明](../tools/core/README.md)，准备独立、干净且精确匹配 `core-lock.json` 的上游 checkout，再执行工具的 verify / prepare / check 流程。工具会向该专用上游仓库写入确定性 Git 对象并登记工作树；不要使用无关开发 checkout。

这一流程不是编译，也不等于协议测试。当前归集目录仅通过了工具的 20 个合成 Git 测试，尚未完成真实核心重放。即使不开启可选运行时 feature，Cargo 解析也可能要求这些 path 依赖存在。保留已提交锁文件和工具链，不用浮动更新绕过缺失依赖。

## 日常修改

- **客户端**：在 fork 的工作分支修改、测试并提交，再由主仓更新 gitlink。submodule 默认处于 detached HEAD，用于复现主仓锁定版本。需要贡献时，在 fork 中从已审查的 `work/client-foundation` 提交建立个人工作分支，修改、测试、提交并审查后，再按 [版本指南](releases.md) 更新主仓 gitlink。不要在锁定 checkout 上用 `git pull` 或直接拉取上游覆盖定制；上游同步应在独立分支审查合并。
- **服务端与 Web**：在主仓修改；协议变更同时更新契约、生成代码与测试夹具。
- **共享文件**：`Cargo.toml`、锁文件、领域模型和 Schema 每轮由一个集成负责人协调，避免并行覆盖。
- **测试顺序**：格式与契约漂移 → 纯单元测试 → ABI/接口测试 → 独立回环互通 → 平台生命周期 → 完整用户流程。

记录命令、提交、工具链、目标平台与结果。`not-run`、`blocked`、`failed` 和 `passed` 分开记录。测试替身只能验证控制逻辑，不能作为真实引擎连接证据。

## 本地文件

构建缓存、下载内核、配置数据库、真实订阅和认证材料留在 Git 之外。脱敏测试数据使用保留域名与显式占位值。不要提交开发机绝对路径，也不要通过符号链接让发布源码依赖工作区之外的私有目录。
