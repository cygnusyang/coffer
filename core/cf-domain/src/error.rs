//! 领域层统一错误类型。
//!
//! 定义见 `docs/03-详细设计.md` §4.4，错误码表见 §12。
//! 本类型是**单一错误来源**：所有 cf-* crate 向上抛错都用 [`CfError`]，
//! UI 层只做错误码 → 本地化文案的映射，不解析错误消息文本。
//!
//! ## 载荷纪律（构造 [`CfError`] 时必守）
//!
//! 带 `String` 载荷的变体（[`CfError::Corrupted`]、[`CfError::StorageError`]、
//! [`CfError::Io`]、[`CfError::ImportFailed`]、[`CfError::ExportFailed`]、
//! [`CfError::TotpError`]、[`CfError::InvalidArgument`]、[`CfError::Validation`]）
//! 会被写入日志，
//! 因此载荷**不得**包含：
//!
//! - 口令、密钥、明文敏感值（载荷是普通 `String`，不受
//!   [`crate::secret::SecretString`] 的析构清零保护）；
//! - 可直接降低攻击成本的细节（如解密失败的中间值、密钥派生的中间状态）。
//!
//! 构造处必须做归一化或打码后传入。同层 `cf-crypto` / `cf-format` 的错误类型
//! 有同样的纪律声明。
//!
//! ## 与其他 crate 错误类型的转换
//!
//! [`CfError`] 是**对外**契约；`cf-crypto` / `cf-format` / `cf-store` 各自
//! 持有内部错误类型。转换必须落在 `cf-session`（分层禁止 cf-domain 反向依赖），
//! **该转换表尚未实现**。实现时须保持 FR-1.4：错误密码的 AEAD 失败与
//! header/MANIFEST 篡改**都**归一到 [`CfError::UnlockFailed`]（1002），
//! 不得把后者映射成 [`CfError::Corrupted`]（1005）。
//!
//! ## 与设计文档 §4.4 的两处已知偏离
//!
//! 1. [`CfError::StorageError`] 的消息模板为 `storage error: {0}`，而 §4.4
//!    写作 `storage error`（无插值）。此处刻意保留插值：§4.4 中同为
//!    `String` 载荷的 [`CfError::Corrupted`] 与 [`CfError::Io`] 都带 `: {0}`，
//!    且存储细节对排障有实质价值。**待同步修订 §4.4 与 §12 第 1009 行。**
//! 2. §4.4 的 `#[derive]` 未列 `PartialEq`，实现中需要（测试与 UI 层比对）。
//!
//! ## v0.1 纵切增补（docs/07 §2.1 / §2.2，C-6 / T01 / T02）
//!
//! 以下三个变体由 `docs/07-macOS纵切设计.md` 增补，已同步 `docs/03` §4.4 / §12：
//!
//! - [`CfError::WeakPassword`]（1010）：主密码强度门禁（zxcvbn score < 3 拒绝建库）；
//! - [`CfError::ItemNotFound`]（1011）：条目不存在（cf-store 仓库层写操作的前置校验）；
//! - [`CfError::Validation`]（1012）：领域/存储层校验失败（可操作的用户提示）。

use thiserror::Error;

/// Coffer 统一错误类型。
///
/// 每个变体对应 `docs/03-详细设计.md` §12 错误码表中的一个错误码，
/// 命名与文档逐项对齐。UI 层依据 [`CfError::code`]（而非消息文本）做本地化，
/// 数字码由 `error_codes_match_design_doc_section_12` 测试冻结为跨版本契约。
#[derive(Debug, Error, PartialEq)]
pub enum CfError {
    /// 保险库已锁定，须先解锁
    #[error("vault is locked")]
    VaultLocked,

    /// 解锁失败。
    ///
    /// **密码错 与 数据损坏 刻意不区分**（需求 FR-1.4）：
    /// 攻击者无法通过错误码判断自己是否拿到了正确的库文件。
    #[error("unlock failed")]
    UnlockFailed,

    /// 找不到该保险库
    #[error("vault not found")]
    VaultNotFound,

    /// 保险库已存在
    #[error("vault already exists")]
    VaultExists,

    /// 数据文件损坏。{0} 为损坏细节。
    #[error("corrupted container: {0}")]
    Corrupted(String),

    /// 文件格式版本高于当前 App 支持范围。{0} 为格式版本号。
    #[error("unsupported format version: {0}")]
    UnsupportedFormat(u16),

    /// 密钥派生失败
    #[error("kdf error")]
    KdfError,

    /// 解密失败
    #[error("crypto error")]
    CryptoError,

    /// 数据读写失败。{0} 为存储层细节，**不得含敏感值**（见模块级载荷纪律）。
    #[error("storage error: {0}")]
    StorageError(String),

    /// 主密码强度不足（zxcvbn score < 3，docs/07 §2.2 建库门禁）。
    ///
    /// 用户可见文案不得提示"再试哪个密码能过"——只提示强度要求。
    #[error("password too weak")]
    WeakPassword,

    /// 条目不存在（写操作的前置校验失败，docs/07 §2.1）。
    #[error("item not found")]
    ItemNotFound,

    /// 数据校验失败。{0} 为可操作的错误说明（docs/07 §2.1）。
    #[error("validation failed: {0}")]
    Validation(String),

    /// 导入失败。{0} 为失败原因。
    #[error("import failed: {0}")]
    ImportFailed(String),

    /// 无法识别导入文件格式。
    ///
    /// 识别失败时**明确报错，不做猜测性尝试**（`03` §6.1）。
    #[error("import source unrecognized")]
    ImportUnknownFormat,

    /// 导出失败。{0} 为失败原因。
    #[error("export failed: {0}")]
    ExportFailed(String),

    /// 验证码生成失败。{0} 为细节。
    #[error("totp error: {0}")]
    TotpError(String),

    /// 当前设备不支持生物识别。可回退主密码解锁。
    #[error("biometric unavailable")]
    BiometricUnavailable,

    /// 生物识别凭据已变更。须回退主密码解锁。
    #[error("biometric invalidated")]
    BiometricInvalidated,

    /// 文件读写错误。{0} 为系统 IO 信息。
    #[error("io error: {0}")]
    Io(String),

    /// 参数无效。{0} 为可操作的错误说明。
    #[error("invalid argument: {0}")]
    InvalidArgument(String),
}

impl CfError {
    /// 返回 `docs/03-详细设计.md` §12 错误码表中的稳定错误码。
    ///
    /// UI 层应当用本方法（而非 [`Display`](std::fmt::Display) 文本）做
    /// 本地化映射 —— 消息文本可随措辞调整，错误码是跨版本契约。
    ///
    /// 段的划分：1001–1012 保险库与加密与存储校验，2001–2003 导入导出，
    /// 3001 验证码，4001–4002 生物识别，5001–5002 系统级。
    ///
    /// **无 `_` 兜底分支**：新增变体时编译器会强制在此补码。
    ///
    /// # 示例
    ///
    /// ```
    /// use cf_domain::CfError;
    ///
    /// // UI 层按码查本地化文案，不解析消息文本
    /// let err = CfError::InvalidArgument("password is required".into());
    /// match err.code() {
    ///     1002 => println!("密码不正确，或数据文件已损坏"),
    ///     5002 => println!("参数无效"),
    ///     other => println!("未知错误码 {other}"),
    /// }
    ///
    /// // 1002 同时覆盖"密码错"与"数据损坏"，见 FR-1.4
    /// assert_eq!(CfError::UnlockFailed.code(), 1002);
    /// ```
    #[must_use]
    pub fn code(&self) -> u16 {
        match self {
            Self::VaultLocked => 1001,
            Self::UnlockFailed => 1002,
            Self::VaultNotFound => 1003,
            Self::VaultExists => 1004,
            Self::Corrupted(_) => 1005,
            Self::UnsupportedFormat(_) => 1006,
            Self::KdfError => 1007,
            Self::CryptoError => 1008,
            Self::StorageError(_) => 1009,
            Self::WeakPassword => 1010,
            Self::ItemNotFound => 1011,
            Self::Validation(_) => 1012,
            Self::ImportUnknownFormat => 2001,
            Self::ImportFailed(_) => 2002,
            Self::ExportFailed(_) => 2003,
            Self::TotpError(_) => 3001,
            Self::BiometricUnavailable => 4001,
            Self::BiometricInvalidated => 4002,
            Self::Io(_) => 5001,
            Self::InvalidArgument(_) => 5002,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// **编译期闸门**：无 `_` 兜底分支的穷尽 `match`。
    ///
    /// 给 [`CfError`] 新增变体时，此处会**编译失败**，迫使作者回到测试模块
    /// 补齐三处：本函数、[`all_variants`]、以及错误码期望表。
    ///
    /// 这是本模块唯一能真正拦住"新变体悄悄拿到重复错误码"的机制 ——
    /// 光靠 `code()` 自身的穷尽 `match` 不够，那只会强制补一个数字，
    /// 不会强制把这个变体加入下面那两个硬编码长度的表。
    fn tag(err: &CfError) -> &'static str {
        match err {
            CfError::VaultLocked => "VaultLocked",
            CfError::UnlockFailed => "UnlockFailed",
            CfError::VaultNotFound => "VaultNotFound",
            CfError::VaultExists => "VaultExists",
            CfError::Corrupted(_) => "Corrupted",
            CfError::UnsupportedFormat(_) => "UnsupportedFormat",
            CfError::KdfError => "KdfError",
            CfError::CryptoError => "CryptoError",
            CfError::StorageError(_) => "StorageError",
            CfError::WeakPassword => "WeakPassword",
            CfError::ItemNotFound => "ItemNotFound",
            CfError::Validation(_) => "Validation",
            CfError::ImportUnknownFormat => "ImportUnknownFormat",
            CfError::ImportFailed(_) => "ImportFailed",
            CfError::ExportFailed(_) => "ExportFailed",
            CfError::TotpError(_) => "TotpError",
            CfError::BiometricUnavailable => "BiometricUnavailable",
            CfError::BiometricInvalidated => "BiometricInvalidated",
            CfError::Io(_) => "Io",
            CfError::InvalidArgument(_) => "InvalidArgument",
        }
    }

    /// 全部 20 个变体各一份实例。
    ///
    /// 载荷取值刻意做成互不相同，便于失败时从调试输出直接定位。
    fn all_variants() -> Vec<CfError> {
        vec![
            CfError::VaultLocked,
            CfError::UnlockFailed,
            CfError::VaultNotFound,
            CfError::VaultExists,
            CfError::Corrupted("bad hmac".into()),
            CfError::UnsupportedFormat(3),
            CfError::KdfError,
            CfError::CryptoError,
            CfError::StorageError("sqlite busy".into()),
            CfError::WeakPassword,
            CfError::ItemNotFound,
            CfError::Validation("title is empty".into()),
            CfError::ImportUnknownFormat,
            CfError::ImportFailed("row 7".into()),
            CfError::ExportFailed("disk full".into()),
            CfError::TotpError("secret too short".into()),
            CfError::BiometricUnavailable,
            CfError::BiometricInvalidated,
            CfError::Io("permission denied".into()),
            CfError::InvalidArgument("empty password".into()),
        ]
    }

    /// 按 `docs/03-详细设计.md` §12 顺序排列的 20 个变体名。
    const EXPECTED_VARIANTS: [&str; 20] = [
        "VaultLocked",
        "UnlockFailed",
        "VaultNotFound",
        "VaultExists",
        "Corrupted",
        "UnsupportedFormat",
        "KdfError",
        "CryptoError",
        "StorageError",
        "WeakPassword",
        "ItemNotFound",
        "Validation",
        "ImportUnknownFormat",
        "ImportFailed",
        "ExportFailed",
        "TotpError",
        "BiometricUnavailable",
        "BiometricInvalidated",
        "Io",
        "InvalidArgument",
    ];

    #[test]
    fn all_variants_covers_every_enum_variant() {
        // 这道断言的意义：`tag()` 保证"编译器知道的变体"与"测试知道的变体"
        // 必须一致。若有人把新变体加进 `all_variants()` 却忘了 `tag()`，
        // 编译就过不去；反之若只加进 `tag()`，下面这行会失败。
        let tags: Vec<&'static str> = all_variants().iter().map(tag).collect();
        assert_eq!(tags.as_slice(), EXPECTED_VARIANTS);

        // 同时防重复：`all_variants()` 里若误抄同一变体两次，长度对不上。
        assert_eq!(all_variants().len(), EXPECTED_VARIANTS.len());
    }

    #[test]
    fn error_codes_match_design_doc_section_12() {
        // 期望值逐项抄自 docs/03-详细设计.md §12 错误码表。
        // 1010–1012 为 docs/07 纵切增补（已同步 docs/03 §12）。
        // 本表是**冻结快照**：改动必须同步文档，且走评审。
        let expected: [(CfError, u16); 20] = [
            (CfError::VaultLocked, 1001),
            (CfError::UnlockFailed, 1002),
            (CfError::VaultNotFound, 1003),
            (CfError::VaultExists, 1004),
            (CfError::Corrupted(String::new()), 1005),
            (CfError::UnsupportedFormat(0), 1006),
            (CfError::KdfError, 1007),
            (CfError::CryptoError, 1008),
            (CfError::StorageError(String::new()), 1009),
            (CfError::WeakPassword, 1010),
            (CfError::ItemNotFound, 1011),
            (CfError::Validation(String::new()), 1012),
            (CfError::ImportUnknownFormat, 2001),
            (CfError::ImportFailed(String::new()), 2002),
            (CfError::ExportFailed(String::new()), 2003),
            (CfError::TotpError(String::new()), 3001),
            (CfError::BiometricUnavailable, 4001),
            (CfError::BiometricInvalidated, 4002),
            (CfError::Io(String::new()), 5001),
            (CfError::InvalidArgument(String::new()), 5002),
        ];

        for (err, code) in &expected {
            assert_eq!(err.code(), *code, "错误码不匹配：{err:?}");
        }

        // 与 tag() 走同一份变体清单，避免两个表各自漂移。
        let tagged: Vec<&'static str> = expected.iter().map(|(e, _)| tag(e)).collect();
        assert_eq!(tagged.as_slice(), EXPECTED_VARIANTS);
    }

    #[test]
    fn error_codes_are_unique_and_nonzero() {
        let codes: Vec<u16> = all_variants().iter().map(CfError::code).collect();

        for code in &codes {
            assert_ne!(*code, 0, "错误码 0 是保留值，不可用作任何变体");
        }

        let mut sorted = codes.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), codes.len(), "错误码存在重复：{codes:?}");
    }

    #[test]
    fn display_messages_are_stable() {
        // UI 层不解析消息文本，但这些字符串是日志与调试的对外契约，
        // 变更时应被显式察觉而非悄悄漂移。
        assert_eq!(CfError::VaultLocked.to_string(), "vault is locked");
        assert_eq!(CfError::UnlockFailed.to_string(), "unlock failed");
        assert_eq!(CfError::VaultNotFound.to_string(), "vault not found");
        assert_eq!(CfError::VaultExists.to_string(), "vault already exists");
        assert_eq!(CfError::KdfError.to_string(), "kdf error");
        assert_eq!(CfError::CryptoError.to_string(), "crypto error");
        assert_eq!(
            CfError::ImportUnknownFormat.to_string(),
            "import source unrecognized"
        );
        assert_eq!(
            CfError::BiometricUnavailable.to_string(),
            "biometric unavailable"
        );
        assert_eq!(
            CfError::BiometricInvalidated.to_string(),
            "biometric invalidated"
        );
    }

    #[test]
    fn display_interpolates_payloads() {
        // 覆盖全部 8 个带载荷的变体 —— 前 7 条与设计文档 §4.4 的消息模板对齐，
        // 最后一条 StorageError 是 §4.4 的已知偏离（见模块级文档）。
        assert_eq!(
            CfError::Corrupted("bad hmac".into()).to_string(),
            "corrupted container: bad hmac"
        );
        assert_eq!(
            CfError::UnsupportedFormat(3).to_string(),
            "unsupported format version: 3"
        );
        assert_eq!(
            CfError::StorageError("sqlite busy".into()).to_string(),
            "storage error: sqlite busy"
        );
        // 1010–1012：docs/07 纵切增补的三个变体
        assert_eq!(CfError::WeakPassword.to_string(), "password too weak");
        assert_eq!(CfError::ItemNotFound.to_string(), "item not found");
        assert_eq!(
            CfError::Validation("title is empty".into()).to_string(),
            "validation failed: title is empty"
        );
        assert_eq!(
            CfError::ImportFailed("row 7".into()).to_string(),
            "import failed: row 7"
        );
        assert_eq!(
            CfError::ExportFailed("disk full".into()).to_string(),
            "export failed: disk full"
        );
        assert_eq!(
            CfError::TotpError("secret too short".into()).to_string(),
            "totp error: secret too short"
        );
        assert_eq!(
            CfError::Io("permission denied".into()).to_string(),
            "io error: permission denied"
        );
        assert_eq!(
            CfError::InvalidArgument("empty password".into()).to_string(),
            "invalid argument: empty password"
        );
    }

    #[test]
    fn unlock_failed_code_differs_from_corrupted() {
        // 需求 FR-1.4 / 设计文档 §4.4：**密码错**与**数据损坏**在解锁路径上
        // 必须归一到同一个 UnlockFailed（1002），攻击者据此无法判断自己是否
        // 拿到了正确的库文件。
        //
        // 注意本测试**不能**直接验证那条归一化 —— 那发生在 cf-session 的
        // 解锁路径（AEAD 失败 / header 校验失败 → UnlockFailed），cf-domain
        // 内无从调起。此处的职责边界是守住下面这条**反碰撞**性质：
        // 1002 不得与 Corrupted（1005）撞码，否则两种失败会呈现不同的
        // 用户可见文案，归一化就白做了。归一化本身须由 cf-session 侧测试覆盖。
        assert_ne!(
            CfError::UnlockFailed.code(),
            CfError::Corrupted(String::new()).code(),
            "UnlockFailed 与 Corrupted 必须使用不同错误码，否则 FR-1.4 的不可区分性失效"
        );
        // 两者的用户可见文案也必须不同 —— 同样的理由。
        assert_ne!(
            CfError::UnlockFailed.to_string(),
            CfError::Corrupted(String::new()).to_string()
        );
    }

    #[test]
    fn equality_distinguishes_payloads() {
        assert_eq!(
            CfError::Corrupted("a".into()),
            CfError::Corrupted("a".into())
        );
        assert_ne!(
            CfError::Corrupted("a".into()),
            CfError::Corrupted("b".into())
        );
        assert_ne!(CfError::UnsupportedFormat(2), CfError::UnsupportedFormat(3));
        // 跨变体永不相等，即使载荷相同。
        assert_ne!(CfError::StorageError("x".into()), CfError::Io("x".into()));
    }

    #[test]
    fn error_implements_std_error() {
        // 必须是 std::error::Error，才能用 `?` 向上传播并被 anyhow 等封装。
        fn assert_is_std_error<E: std::error::Error>(_: &E) {}
        assert_is_std_error(&CfError::VaultLocked);

        // 所有变体都摊平了底层错误（如 Io 丢弃 std::io::Error 的 ErrorKind），
        // source() 恒为 None。这是**有意取舍**：换取 PartialEq 可比与
        // FFI 边界友好。若日后需要诊断链，Io 变体须携带 source，
        // 代价是失去 PartialEq derive —— 需架构裁决。
        use std::error::Error;
        for err in all_variants() {
            assert!(
                err.source().is_none(),
                "{err:?} 意外携带了 source，与摊平设计不符"
            );
        }
    }
}
