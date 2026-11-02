# 版本与发布

## 版本由主仓组装

一个产品版本至少固定以下身份：

- 主仓 Git commit；
- `client/` gitlink commit 与 fork 来源；
- 服务端 `core-lock.json` 中的上游 commit、补丁摘要和集成身份；
- 客户端、服务端与 Web 的实际锁文件及工具链；
- 每个附带引擎的精确版本、来源与下载资产 SHA-256；
- 产物摘要、兼容性与存储版本、测试结果、第三方许可清单。

客户端上游基线：`cf3bfcf8fc70518e75d036bd4db72fcee8713541`。这只是初始来源，不是未来永远不变的发布指针；实际绑定以主仓的 gitlink 为准。

## 更新客户端 submodule

以下步骤仅在真实 submodule 已建立且工作树干净时使用。先在客户端 fork 完成代码提交、审查和所需验证；不要自动追踪浮动分支。

```sh
git -C client status --short
git -C client fetch origin
# 把下一行的 COMMIT 替换为已审查、已存在于 fork 的完整提交 SHA。
git -C client checkout --detach COMMIT
git -C client rev-parse HEAD
git diff --submodule=log -- client
```

核对差异和测试记录后，再将 `client` gitlink 与对应版本记录一起提交主仓。不要用 `git submodule update --remote` 代替精确版本选择，也不要只改 `.gitmodules` 而漏掉 gitlink。若客户端存在未提交工作，先处理，不能强制覆盖。

## 发布检查

1. 从干净 checkout 初始化所有固定依赖，验证不依赖开发机外部路径。
2. 在声明的平台完成构建与验收；标出未运行和不支持项。
3. 验证配置迁移、升级、回滚和数据保留行为。不同 bundle schema 的能力不能互相套用。
4. 审核源码、日志、配置和 Web 产物中的秘密；检查许可、版权、字体及内核再分发条件。
5. 生成产物摘要与版本记录，复核安装命令和可信来源。
6. 发布和签名使用明确配置的渠道与身份，不把本地开发包描述为已签名正式版。

当前没有声明正式发行版本、签名身份、下载地址或完整平台认证。
