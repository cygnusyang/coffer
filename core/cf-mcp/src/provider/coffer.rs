//! Coffer 自家 Secret Store 数据源（feature `coffer-store`，docs/20 §4.5）。
//!
//! 依赖链 `cf-mcp → cf-session → cf-store`（单向，docs/20 §2.2 只下不上）。
//! **本版仅骨架**：Coffer 现有存储模型是 条目/字段（密码管理器），无 Secret /
//! Environment / 权限实体 —— `secret_ref → (item, field)` 映射、AS-7 权限矩阵、
//! 生命周期元数据（AS-9）均属 v2.x 存储模型扩展（不可逆决策，docs/20 §8 ④），
//! 不在本版实现。启用 `coffer-store` feature 后 workspace 依赖树新增
//! `cf-mcp → cf-session` 边（docs/20 §9.2 互斥矩阵核对）。
//!
//! # 状态
//!
//! 仅声明 [`CofferStoreProvider`] 结构；[`SecretProvider`] 各方法一律
//! `unimplemented!` 占位（编译通过、调用即 panic），等 v2.x 建模落定后替换。
//! 默认 feature 关闭，本文件不进入普通构建（`cargo check/test` 无此 feature）。

#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used, clippy::expect_used)]
// 骨架占位：结构被 v2.x 建模前刻意不构造（无构造器），死代码警告属预期，
// 允许以便 `clippy -D warnings` 门禁在 coffer-store feature 下保持绿色。
#![allow(dead_code)]

use crate::provider::{ProviderError, RunSpec, SecretMeta, SecretProvider};

/// Coffer 自家库 provider（骨架，docs/20 §4.5）。
///
/// 解锁经主 App 流程（[`cf_session::VaultSession`]），复用 1001 门禁 + usecase。
/// 本版不提供构造器 —— v2.x 存储模型落定后随实现一并给出。
pub struct CofferStoreProvider {
    /// 主 App 会话（解锁态门禁，1001 复用）；本版仅为依赖方向占位。
    _session: cf_session::VaultSession,
}

impl SecretProvider for CofferStoreProvider {
    fn list_secret_names(&self, _vault: Option<&str>) -> Result<Vec<String>, ProviderError> {
        unimplemented!("CofferStoreProvider 骨架：v2.x Secret 实体未建模（docs/20 §4.5）")
    }

    fn list_secrets(&self, _vault: Option<&str>) -> Result<Vec<SecretMeta>, ProviderError> {
        unimplemented!("CofferStoreProvider 骨架：v2.x Secret 实体未建模（docs/20 §4.5）")
    }

    fn get_secret_metadata(&self, _secret_ref: &str) -> Result<SecretMeta, ProviderError> {
        unimplemented!("CofferStoreProvider 骨架：v2.x Secret 实体未建模（docs/20 §4.5）")
    }

    fn run_with_secret(&self, _spec: &RunSpec) -> Result<i32, ProviderError> {
        unimplemented!("CofferStoreProvider 骨架：v2.x Secret 实体未建模（docs/20 §4.5）")
    }
}
