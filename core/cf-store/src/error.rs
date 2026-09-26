//! 错误统一（docs/07 §5 冲突清单 C-6 / §2.1）。
//!
//! cf-store **不自持错误类型**：全部错误统一为 [`cf_domain::CfError`]。
//! 本模块只提供别名（兼容旧名 [`CfStoreError`]）与底层错误 → [`CfError`]
//! 的转换助手。
//!
//! ## 信息泄露纪律（docs/04 §4.2）
//!
//! - `rusqlite::Error` → [`CfError::StorageError`]：SQLite 错误文本只含
//!   表/列名与 SQL 语法信息（schema 本就是公开设计），不含敏感值；
//! - `cf_crypto::CfCryptoError` → [`CfError::CryptoError`]：**丢弃全部
//!   底层细节**（含 `InvalidLength` 中的密文长度信息），只保留"解密失败"
//!   这一统一语义，不给攻击者降低攻击成本的线索。
//!
//! ## 分层边界
//!
//! `impl From<rusqlite::Error> for CfError` 因孤儿规则不能落在本 crate
//! （`CfError` 属于 cf-domain，`rusqlite::Error` 是外部类型），故以
//! [`RusqliteResultExt::store`] / [`CryptoResultExt::crypto`] 扩展 trait
//! 提供 `?` 等价的人体工学。

use cf_crypto::CfCryptoError;
pub use cf_domain::CfError;

/// cf-store 错误类型（C-6 统一）。
///
/// 旧名 [`CfStoreError`] 保留为类型别名：cf-session 现有
/// `From<CfStoreError> for SessionError` 转换无需改动即可继续工作。
pub type CfStoreError = CfError;

/// cf-store 结果别名。
pub type CfStoreResult<T> = Result<T, CfStoreError>;

/// `rusqlite::Error` → [`CfError::StorageError`]。
pub fn db_err(e: rusqlite::Error) -> CfError {
    CfError::StorageError(e.to_string())
}

/// `CfCryptoError` → [`CfError::CryptoError`]。
///
/// 刻意**不透传**底层错误文本：`CfCryptoError` 的载荷可能含密文长度等
/// 细节（见 `cf-crypto::error`），统一折叠为无载荷的 `CryptoError`。
pub fn crypto_err(_e: CfCryptoError) -> CfError {
    CfError::CryptoError
}

/// [`rusqlite::Result`] 的错误转换扩展（等价于 `From` + `?`）。
pub trait RusqliteResultExt<T> {
    /// 把 SQLite 错误映射为 [`CfError::StorageError`]。
    fn store(self) -> CfStoreResult<T>;
}

impl<T> RusqliteResultExt<T> for rusqlite::Result<T> {
    fn store(self) -> CfStoreResult<T> {
        self.map_err(db_err)
    }
}

/// [`Result`]`<_, `[`CfCryptoError`]`>` 的错误转换扩展。
pub trait CryptoResultExt<T> {
    /// 把 cf-crypto 错误折叠为 [`CfError::CryptoError`]（不透传细节）。
    fn crypto(self) -> CfStoreResult<T>;
}

impl<T> CryptoResultExt<T> for Result<T, CfCryptoError> {
    fn crypto(self) -> CfStoreResult<T> {
        self.map_err(crypto_err)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// rusqlite 错误折叠为 StorageError（1009）
    #[test]
    fn sqlite错误折叠为存储错误() {
        let raw: rusqlite::Result<()> = Err(rusqlite::Error::InvalidColumnName("nope".into()));
        assert_eq!(raw.store().unwrap_err().code(), 1009);
    }

    /// cf-crypto 错误折叠为 CryptoError（1008），且不透出底层细节文本
    #[test]
    fn 加密错误折叠且不泄露细节() {
        let raw: Result<(), CfCryptoError> = Err(CfCryptoError::InvalidLength("sealed data length 3".into()));
        let got = raw.crypto().unwrap_err();
        assert_eq!(got.code(), 1008);
        assert_eq!(got.to_string(), "crypto error");
        assert!(!got.to_string().contains("length"), "不得泄露密文长度线索");
    }
}
