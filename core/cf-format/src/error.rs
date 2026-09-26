//! 本 crate 的错误类型。
//!
//! 设计原则（见 `docs/04-系统设计.md` §4.2「Information Disclosure」）：
//! **错误信息不得泄露可用于降低攻击成本的信息**。
//!
//! 各变体与 `docs/03-详细设计.md` §12 错误码表的语义对应关系：
//!
//! | 本类型变体 | §12 错误码 | 说明 |
//! | --- | --- | --- |
//! | [`InvalidHeader`](CfFormatError::InvalidHeader) | `1005 Corrupted` | header.json 畸形 / 字段非法 / 校验失败 |
//! | [`UnsupportedVersion`](CfFormatError::UnsupportedVersion) | `1006 UnsupportedFormat` | 格式版本高于 App 支持（TooNew），或迁移目标版本尚无实现 |
//! | [`Io`](CfFormatError::Io) | `5001 Io` | 文件系统读写失败 |
//! | [`ContainerLayout`](CfFormatError::ContainerLayout) | `1003 VaultNotFound` / `1005 Corrupted` | 目录缺少必需文件（header.json / db.sqlite） |
//! | [`ManifestMismatch`](CfFormatError::ManifestMismatch) | `1005 Corrupted` | MANIFEST 校验失败：篡改 / 缺文件 / 错钥 |

use thiserror::Error;

/// `cf-format` 的错误类型。
///
/// UI 层应**按错误码映射本地化文案**，不要解析错误消息文本
/// （见 `docs/03-详细设计.md` §12 的约定）。
#[derive(Debug, Error, PartialEq, Eq)]
pub enum CfFormatError {
    /// 头部非法：JSON 畸形、字段缺失、base64 失败、长度不符、
    /// 算法常量不符、KDF 参数越界（防 OOM，见 `docs/04-系统设计.md` §4.3）。
    #[error("头部非法：{0}")]
    InvalidHeader(String),

    /// 格式版本不受支持。
    ///
    /// 两种触发场景：
    /// 1. `format_version` **高于**当前 App 支持范围（TooNew）——对应
    ///    §12 错误码 `1006 UnsupportedFormat`，提示升级 App；
    /// 2. 迁移目标版本尚无实现（M1 迁移表为空）。
    #[error("不支持的格式版本：{0}")]
    UnsupportedVersion(u16),

    /// 文件系统读写失败。
    #[error("IO 错误：{0}")]
    Io(String),

    /// 容器布局不完整：目录形态缺少必需文件（header.json / db.sqlite）。
    #[error("容器布局不完整：{0}")]
    ContainerLayout(String),

    /// MANIFEST 完整性校验失败。
    ///
    /// 不区分具体失败原因（HMAC 不符 / 文件缺失 / 大小不符 / 内容不符），
    /// 与解锁错误不区分「密码错误」/「数据损坏」是同一条信息泄露纪律。
    #[error("MANIFEST 校验失败：{0}")]
    ManifestMismatch(String),
}
