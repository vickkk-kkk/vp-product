# 第三方来源与许可

本文件记录来源边界，不替代各组件许可证，也不表示已完成法律或再分发审查。

| 组件 | 来源 | 当前说明 |
| --- | --- | --- |
| 客户端基础 | https://github.com/mateo-ki/vpn-parser | 基线 `cf3bfcf8fc70518e75d036bd4db72fcee8713541`；MIT；保留上游 LICENSE 及 Copyright (c) 2026 mateo-ki |
| 服务端核心 | https://github.com/mateo-ki/vp_core | 以归集后的 `core-lock.json` 为准；锁定来源、补丁和集成身份；发布前核查许可 |
| 其他客户端引擎 | sing-box、Mihomo、Xray、Shoes、Meow 各自上游 | 每个适配器分别登记精确来源和再分发条件，不默认随产品打包 |
| Flutter Web 字体及资源 | 对应资产目录中的来源与许可证 | 迁移时一并保留，不因更换 UI 而删去版权声明 |

独立编写的安装工具不复制参考安装器实现或模板。主仓尚未选择统一许可证；客户端的 MIT 不覆盖服务端核心、外部引擎、字体或所有主仓代码。正式分发前应补齐依赖清单、许可证文本和所需 notices。
