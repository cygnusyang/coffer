//! FFI 错误映射：`cf_domain::CfError` → [`FfiError`]（docs/07 §2.3）。
//!
//! UI 层按 [`FfiError::code`] 本地化，不解析 `message` 文本——错误码与
//! `docs/03-详细设计.md` §12 错误码表逐一对应（映射即 `CfError::code()`，
//! 由 cf-domain 的冻结测试 `error_codes_match_design_doc_section_12` 保证
//! 不漂移；本模块测试钉住「跨 FFI 后码不变」）。
//!
//! ## 5999：docs/03 §12 之外的增补码
//!
//! Rust panic 经 [`crate::ffi_guard`] 捕获后映射为 [`FfiError::InternalPanic`]，
//! 码取 **5999**（系统级 5001–5002 段之后的保留位）。这是 FFI 层自有的
//! 防御性兜底——业务代码不应产出该码；若 UI 收到 5999 说明触发了
//! Rust 侧不变量破坏，应上报日志（message 为 panic 摘要，不含敏感值，
//! panic hook 侧已声明过滤）。

use cf_domain::CfError;

/// FFI 层统一错误（docs/07 §2.3：`code: u16` + `message`）。
///
/// UniFFI error enum：Swift 侧每个变体对应一个 error case。
/// `Coffer` 承载全部业务错误（按码本地化）；`InternalPanic` 是
/// panic 兜底（docs/07 §5 C-8 / R-2）。
#[derive(Debug, PartialEq, thiserror::Error, uniffi::Error)]
pub enum FfiError {
    /// 业务错误：`code` 为 docs/03 §12 错误码（1001 锁定 / 1002 解锁失败 /
    /// 1003 库不存在 / 1004 库已存在 / 1005 损坏 / 1006 版本过新 / 1007 KDF /
    /// 1008 解密 / 1009 存储 / 1010 弱密码 / 1011 条目不存在 / 1012 校验 /
    /// 2001 导入格式 / 2002 导入失败 / 2003 导出失败 / 3001 TOTP /
    /// 4001–4002 生物识别 / 5001 IO / 5002 参数）。
    #[error("{message}")]
    Coffer {
        /// docs/03 §12 稳定错误码
        code: u16,
        /// 错误摘要（日志用；UI 按 code 本地化，不解析本字段）
        message: String,
    },

    /// Rust panic 兜底（错误码 5999，见模块文档）。
    #[error("internal panic: {message}")]
    InternalPanic {
        /// panic 摘要（非敏感）
        message: String,
    },
}

impl FfiError {
    /// 稳定错误码：业务错误透传 `CfError::code()`；panic 固定 5999。
    #[must_use]
    pub fn code(&self) -> u16 {
        match self {
            Self::Coffer { code, .. } => *code,
            Self::InternalPanic { .. } => 5999,
        }
    }
}

impl From<CfError> for FfiError {
    fn from(e: CfError) -> Self {
        Self::Coffer {
            code: e.code(),
            message: e.to_string(),
        }
    }
}

/// panic 载荷归一为 [`FfiError::InternalPanic`]。
pub(crate) fn panic_payload_to_error(payload: Box<dyn std::any::Any + Send>) -> FfiError {
    let message = if let Some(s) = payload.downcast_ref::<String>() {
        s.clone()
    } else if let Some(s) = payload.downcast_ref::<&str>() {
        (*s).to_string()
    } else {
        "non-string panic payload".to_string()
    };
    FfiError::InternalPanic { message }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 错误码跨 FFI 不漂移：CfError → FfiError 后 code 与 docs/03 §12 一致
    #[test]
    fn 错误码跨ffi映射_与docs03第12节一致() {
        let cases: [(CfError, u16); 20] = [
            (CfError::VaultLocked, 1001),
            (CfError::UnlockFailed, 1002),
            (CfError::VaultNotFound, 1003),
            (CfError::VaultExists, 1004),
            (CfError::Corrupted("x".into()), 1005),
            (CfError::UnsupportedFormat(9), 1006),
            (CfError::KdfError, 1007),
            (CfError::CryptoError, 1008),
            (CfError::StorageError("x".into()), 1009),
            (CfError::WeakPassword, 1010),
            (CfError::ItemNotFound, 1011),
            (CfError::Validation("x".into()), 1012),
            (CfError::ImportUnknownFormat, 2001),
            (CfError::ImportFailed("x".into()), 2002),
            (CfError::ExportFailed("x".into()), 2003),
            (CfError::TotpError("x".into()), 3001),
            (CfError::BiometricUnavailable, 4001),
            (CfError::BiometricInvalidated, 4002),
            (CfError::Io("x".into()), 5001),
            (CfError::InvalidArgument("x".into()), 5002),
        ];
        for (domain, expected) in cases {
            let display = domain.to_string();
            let ffi = FfiError::from(domain);
            assert_eq!(ffi.code(), expected, "错误码漂移：{display}");
            // message 保留 Display 文本，供日志排障
            let message = match &ffi {
                FfiError::Coffer { message, .. } => message.clone(),
                _ => String::new(),
            };
            assert_eq!(message, display);
        }
    }

    /// panic 兜底码固定 5999（docs/03 §12 之外的自有保留位）
    #[test]
    fn panic兜底错误码为5999() {
        let err = panic_payload_to_error(Box::new("boom"));
        assert_eq!(err.code(), 5999);
        assert!(matches!(err, FfiError::InternalPanic { ref message } if message == "boom"));
    }
}
