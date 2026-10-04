//! OPVault 原始数据模型（docs/24 §1.1 / §1.4 布局）。
//!
//! 只承载 `profile.js` / `folders.js` / `band_*.js` 的**明文 JSON 字段**；
//! `k`/`o`/`d`/`overview` 等加密值以 base64 字符串原样保留，解密在
//! [`super::mapping`] 层进行（纯密码学在 `cf_crypto::opvault`）。
//!
//! serde 宽松策略：band 条目键集按类别变化（部分条目无 `folder`、
//! `trashed`、`fave`），非必需键一律 `default`；`k`/`o`/`d`/`category`
//! 为解锁所必需，缺则解析失败（结构层 2001，docs/22 §4）。

use serde::Deserialize;

/// `profile.js` 元数据（明文，docs/24 §1.1）。
#[derive(Debug, Clone, Deserialize)]
pub struct ProfileMeta {
    /// profile 目录 UUID（大写十六进制）。
    pub uuid: String,
    /// profile 名（默认 `default`）。
    #[serde(rename = "profileName")]
    pub profile_name: String,
    /// 密码提示（官方明确不混淆，明文存储）。
    #[serde(rename = "passwordHint")]
    #[serde(default)]
    pub password_hint: Option<String>,
    /// PBKDF2 盐（base64，16 字节）。
    pub salt: String,
    /// PBKDF2 迭代次数。
    pub iterations: u32,
    /// 加密 masterKey（base64 opdata01，明文 256B）。
    #[serde(rename = "masterKey")]
    pub master_key: String,
    /// 加密 overviewKey（base64 opdata01，明文 64B）。
    #[serde(rename = "overviewKey")]
    pub overview_key: String,
}

/// 一条 band 条目（明文字段 + 加密载荷，docs/24 §1.4）。
#[derive(Debug, Clone, Deserialize)]
pub struct RawItem {
    /// 三位十进制分类码（如 `001` Login、`099` Tombstone）。
    pub category: String,
    /// 创建时间（Unix 秒）。
    #[serde(default)]
    pub created: i64,
    /// 更新时间（Unix 秒）。
    #[serde(default)]
    pub updated: i64,
    /// 最后修改事务时间戳（Unix 秒）。
    #[serde(default)]
    pub tx: i64,
    /// 所属文件夹 UUID（可选）。
    #[serde(default)]
    pub folder: Option<String>,
    /// 归档标记（`true` = 归档，docs/24 §1.4）。
    #[serde(default)]
    pub trashed: Option<bool>,
    /// 收藏排序索引（可选，ASCII 无符号长整）。
    #[serde(default)]
    pub fave: Option<i64>,
    /// 条目 UUID（大写十六进制；解析时以外层对象键覆盖）。
    #[serde(default)]
    pub uuid: String,
    /// 加密 item keys（base64，无头布局 `[IV]‖[ct]‖[MAC]`）。
    pub k: String,
    /// 加密 overview（base64 opdata01，overview 密钥）。
    pub o: String,
    /// 加密 details（base64 opdata01，item 密钥）。
    pub d: String,
    /// 条目级 HMAC（base64；本版跳过校验，docs/24 §5 #4——MAC 唯一
    /// 防线是各 opdata 的 MAC）。
    #[serde(default)]
    pub hmac: Option<String>,
}

/// `folders.js` 一条文件夹（overview 加密，docs/24 §1.4）。
#[derive(Debug, Clone, Deserialize)]
pub struct RawFolder {
    /// 文件夹 UUID（对象键）。
    pub uuid: String,
    /// 加密 overview（base64 opdata01，文件夹标题等）。
    pub overview: String,
    /// 归档标记（`true` = 归档）。
    #[serde(default)]
    pub trashed: Option<bool>,
    /// 创建时间（Unix 秒）。
    #[serde(default)]
    pub created: i64,
    /// 更新时间（Unix 秒）。
    #[serde(default)]
    pub updated: i64,
}
