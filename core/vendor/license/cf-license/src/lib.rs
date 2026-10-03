//! cf-license —— 官方许可判定器（占位替身）。
//!
//! ⚠️ 本文件是**占位替身**：公开仓提交的替身内容，保证裸克隆 + 离线构建可解析。
//! 官方构建前由 tools/bootstrap_official_license.sh 从私有仓拷贝真源覆盖本文件
//! （真源经 `*.workspace = true` 绑定公开工作区依赖）；提交公开仓前必须
//! `git restore core/vendor/license` 恢复占位替身——私有代码禁止进入公开仓。
//!
//! 真源职责（见私有仓）：许可证序列号解析 / 校验（Crockford Base32 + Ed25519
//! 签名）、试用期判定、机器指纹，提供 LicenseService 与 LicenseGate。
//! 替身阶段本 crate 为空 lib，feature `official-license` 关闭时不参与编译。

#![allow(unused_crate_dependencies)]
