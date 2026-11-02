# 源码归集检查单

本页用于基础版本之后的源码接入审查。服务端、Web 和安装工具已在本地归集，但尚未纳入首个基础提交；未勾选项仍需审查或验证。详见 [当前快照](source-snapshot.md)。

## 服务端

- [ ] 确认选用的候选版本，按文件比较基线，记录真实代码身份。
- [ ] 保留根 Cargo workspace、`crates/`、`contracts/`、必要工具及 lock 文件的相对结构。
- [ ] 复核 `vp-core-adapter` 的核心 path 依赖；保留来源锁与补丁重放流程，不导入私有绝对路径或外部符号链接。
- [ ] 区分服务端、共享库与旧客户端专用资产；逐项审核后才纳入。
- [ ] 在新目录重新运行适用检查，记录实际命令和结果，补充开发指南。

## Web

- [x] 本地归集 `flutter/apps/vp_admin/`；远程源码提交待审查。
- [ ] 归集 `vp_contracts`、`vp_design_system`、`vp_features`、`vp_runtime_platform`、`vp_api_client`，再核对传递依赖。
- [ ] 保留字体与其他资产的来源和许可；不带入 build、SDK 或 pub cache。
- [ ] 不归集旧 `flutter/apps/vp_client/`，不宣称旧客户端运行测试属于新 egui 客户端。
- [ ] 在归集后验证 Web 构建及管理 API 联调，确认没有原生 VPN/FFI 依赖泄漏。

## 部署与发布

- [ ] 归集 `tools/install/` 源码、必要测试与经过清理的使用文档，保留既有路径关系。
- [ ] 核对 schema-1 / schema-2 等流程边界，不统一宣称升级、回滚和恢复已可用。
- [ ] 验证本地 bundle 构建所引用的实际二进制、Web 根目录和契约文件。
- [ ] 不执行安装、服务 hooks 或主机网络变更来“验证目录”。

## 客户端与仓库卫生

- [x] 已核实 `vickkk-kkk/vpn-parser` fork 与基线 commit，建立真实 `client/` submodule。
- [x] 已确认 `.gitmodules` URL 与 `160000` gitlink；远程基础提交完成后另行检查克隆。
- [ ] 检查许可证、版权与引擎再分发条件；不要擅自为整个主仓选许可证。
- [ ] 排除秘密、运行数据库、真实订阅、内部研究/会话/审批记录和编译缓存。
- [ ] 更新 README 的实际目录与状态；所有相对文档链接可达。
