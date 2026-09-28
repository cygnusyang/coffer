//! attachments 表仓库（FR-9.1 / FR-9.2 附件存储内核，docs/09 v0.3.0）。
//!
//! v0.3.0 内核只使用 **file 形态**：附件密文落
//! `vault_dir/attachments/<附件行uuid>` 旁路文件（该目录被备份 ZIP 的
//! `collect_recursive` 递归覆盖，cf-exporter/src/backup.rs），DB 行只存
//! 元数据 + 相对路径。inline DDL 支持但内核不写（留位）；`chunk_count`
//! 恒 1（D-3 不分块，字段留位）。
//!
//! ## 加密与完整性（docs/09 v0.3.0 冻结裁决）
//!
//! - **机密性**：复用 `file_key`（`cf/file/v1`）做 AEAD seal，AAD 沿用
//!   全仓库层统一约定（O-1）：`field_aad("attachments", 附件行uuid, 列名)`，
//!   列名 [`COLUMN_CONTENT`] / [`COLUMN_FILENAME`]——密文钉死在附件行
//!   uuid 上，跨行搬运解密失败；
//! - **完整性**：`attach_mac_key`（`cf/attach-mac/v1`）对**密文**算
//!   HMAC-SHA256，base64 后存 `content_mac` 列——不解密即可检出截断/替换，
//!   与 MANIFEST 对密文文件的 content_mac 语义对齐（cf-format/src/manifest.rs）；
//! - 明文哈希被禁止（`03` 修正 B：会泄露"两个附件是否相同"）。
//!
//! ## 写入顺序（先文件后行）与孤儿容忍
//!
//! seal → 写 `attachments/.tmp-<uuid>` → fsync → rename 正式名 → 在调用方
//! 的 [`crate::ItemStore::with_tx`] 事务内 INSERT 行。两条容忍规则：
//!
//! - **文件在行无**（写入后事务回滚 / rename 后进程崩溃）：孤儿文件，
//!   unlock 时 [`AttachmentRepo::cleanup_orphans`] 清理；
//! - **行在文件无**（文件被外部删除）：读时报 [`CfError::Corrupted`]。
//!
//! 删除顺序相反：先删行（调用方事务）后删文件。
//!
//! ## 大小上限
//!
//! 单附件明文 [`MAX_ATTACHMENT_BYTES`]（100 MiB）硬上限，超限
//! [`CfError::Validation`]（调用方在发起上传前也应做同等预检）。

use std::fs;
use std::io::Write as _;
use std::path::Path;

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use cf_crypto::aead::{open, seal, SessionKey, KEY_LEN};
use hmac::digest::generic_array::GenericArray;
use hmac::digest::KeyInit;
use hmac::{Hmac, Mac};
use rusqlite::Connection;
use sha2::Sha256;

use crate::error::{CfError, CfStoreResult, CryptoResultExt, RusqliteResultExt};
use crate::repo::{field_aad, unix_now, uuid_bytes};

/// content AAD 列名（冻结契约：`field_aad("attachments", 附件行uuid, "content")`）。
pub const COLUMN_CONTENT: &str = "content";

/// filename AAD 列名（冻结契约：`field_aad("attachments", 附件行uuid, "filename")`）。
pub const COLUMN_FILENAME: &str = "filename";

/// 附件旁路文件目录名（相对 vault_dir；备份 ZIP 的 `collect_recursive`
/// 递归覆盖该目录，cf-exporter/src/backup.rs）。
pub const ATTACHMENTS_DIR: &str = "attachments";

/// 单附件明文大小上限：100 MiB（v0.3.0 设计裁决，超限 [`CfError::Validation`]）。
pub const MAX_ATTACHMENT_BYTES: usize = 100 * 1024 * 1024;

/// `chunk_count` 恒 1（D-3 不分块；字段为未来分块方案留位）。
const CHUNK_COUNT: i64 = 1;

/// HMAC-SHA256 的类型别名。
type HmacSha256 = Hmac<Sha256>;

/// SHA-256 的 HMAC 分组长度（字节，RFC 2104 §2）。
const HMAC_SHA256_BLOCK_LEN: usize = 64;

/// 附件元数据（docs/09 v0.3.0 冻结契约；filename 为解密后明文）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttachmentMeta {
    /// 附件行 UUID（主键；旁路文件名与其相同）。
    pub uuid: String,
    /// 所属条目 UUID。
    pub item_uuid: String,
    /// 文件名（解密后明文）。
    pub filename: String,
    /// 明文长度（字节）。
    pub size_bytes: i64,
    /// 创建时间（Unix 秒）。
    pub created_at: i64,
}

/// 单行查询的中间结构（内部使用）。
struct AttachmentRow {
    uuid: String,
    item_uuid: String,
    enc_filename: Vec<u8>,
    file_path: String,
    size_bytes: i64,
    content_mac: String,
    created_at: i64,
}

/// attachments 表仓库（借用连接，可参与事务）。
pub struct AttachmentRepo<'a> {
    conn: &'a Connection,
    file_key: &'a SessionKey,
    attach_mac_key: &'a SessionKey,
}

impl<'a> AttachmentRepo<'a> {
    /// 构造仓库（v0.3.0 冻结签名：显式传入两把子密钥）。
    pub fn new(
        conn: &'a Connection,
        file_key: &'a SessionKey,
        attach_mac_key: &'a SessionKey,
    ) -> Self {
        Self {
            conn,
            file_key,
            attach_mac_key,
        }
    }

    /// 新增附件（FR-9.1）。
    ///
    /// `filename` 为**明文**文件名字节（UTF-8），`plain` 为明文内容；本方法
    /// 负责 seal（AAD 钉附件行 uuid）→ 写 `attachments/.tmp-<uuid>` →
    /// fsync → rename 正式名 → INSERT 行。**调用方须包在
    /// [`crate::ItemStore::with_tx`] 内**；若事务随后回滚，旁路文件成为
    /// 孤儿（容忍，unlock 时 [`AttachmentRepo::cleanup_orphans`] 清理）。
    ///
    /// # 错误
    ///
    /// - `plain` 超过 [`MAX_ATTACHMENT_BYTES`] → [`CfError::Validation`]；
    /// - `item_uuid` 非法 uuid / 条目不存在（外键）→ 校验 / 存储错误；
    /// - 文件系统失败 → [`CfError::Io`]。
    pub fn add(
        &self,
        item_uuid: &str,
        filename: &[u8],
        plain: &[u8],
        vault_dir: &Path,
    ) -> CfStoreResult<AttachmentMeta> {
        // 大小硬上限先于任何 IO / 密码运算判定（快失败）
        if plain.len() > MAX_ATTACHMENT_BYTES {
            return Err(CfError::Validation(format!(
                "attachment exceeds limit: {MAX_ATTACHMENT_BYTES} bytes"
            )));
        }
        uuid_bytes(item_uuid)?;

        let attachment_uuid = uuid::Uuid::now_v7().to_string();
        let aad_content = field_aad("attachments", &attachment_uuid, COLUMN_CONTENT)?;
        let aad_filename = field_aad("attachments", &attachment_uuid, COLUMN_FILENAME)?;

        let enc_content = seal(self.file_key, &aad_content, plain).crypto()?;
        let enc_filename = seal(self.file_key, &aad_filename, filename).crypto()?;
        let content_mac = content_mac_b64(self.attach_mac_key, &enc_content);

        // 先文件后行：tmp + fsync + rename 原子落定（FR-8.6 同款纪律）
        let dir = vault_dir.join(ATTACHMENTS_DIR);
        fs::create_dir_all(&dir).map_err(|e| CfError::Io(format!("创建附件目录失败：{e}")))?;
        let final_path = dir.join(&attachment_uuid);
        let tmp_path = dir.join(format!(".tmp-{attachment_uuid}"));
        {
            let mut f = fs::File::create(&tmp_path)
                .map_err(|e| CfError::Io(format!("创建附件临时文件失败：{e}")))?;
            f.write_all(&enc_content)
                .map_err(|e| CfError::Io(format!("写入附件临时文件失败：{e}")))?;
            f.sync_all()
                .map_err(|e| CfError::Io(format!("fsync 附件临时文件失败：{e}")))?;
        }
        fs::rename(&tmp_path, &final_path)
            .map_err(|e| CfError::Io(format!("落定附件文件失败：{e}")))?;

        // 同一调用方事务内 INSERT；file_path 存正斜杠相对路径，与备份 ZIP
        // 条目坐标系一致（docs/03 §1.4：路径相对库根，ZIP 内统一 `/`）
        let file_path = format!("{ATTACHMENTS_DIR}/{attachment_uuid}");
        let created_at = unix_now()?;
        self.conn
            .execute(
                "INSERT INTO attachments (uuid, item_uuid, enc_filename, storage,
                                          inline_data, file_path, size_bytes,
                                          chunk_count, content_mac, created_at)
                 VALUES (?1, ?2, ?3, 'file', NULL, ?4, ?5, ?6, ?7, ?8)",
                rusqlite::params![
                    attachment_uuid,
                    item_uuid,
                    enc_filename,
                    file_path,
                    plain.len() as i64,
                    CHUNK_COUNT,
                    content_mac,
                    created_at,
                ],
            )
            .store()?;

        Ok(AttachmentMeta {
            filename: self.decrypt_filename(&enc_filename, &attachment_uuid)?,
            uuid: attachment_uuid,
            item_uuid: item_uuid.to_owned(),
            size_bytes: plain.len() as i64,
            created_at,
        })
    }

    /// 读取附件元数据（FR-9.2；filename 解密）。
    ///
    /// 行不存在 → [`CfError::Validation`]；行在文件无 →
    /// [`CfError::Corrupted`]（见模块文档「孤儿容忍」）。
    pub fn read(&self, attachment_uuid: &str, vault_dir: &Path) -> CfStoreResult<AttachmentMeta> {
        let row = self.query_row(attachment_uuid)?;
        if !vault_dir.join(&row.file_path).is_file() {
            return Err(CfError::Corrupted(format!(
                "attachment file missing: {attachment_uuid}"
            )));
        }
        Ok(AttachmentMeta {
            filename: self.decrypt_filename(&row.enc_filename, attachment_uuid)?,
            uuid: row.uuid,
            item_uuid: row.item_uuid,
            size_bytes: row.size_bytes,
            created_at: row.created_at,
        })
    }

    /// 读取并解密附件内容（FR-9.2）。
    ///
    /// 先校 `content_mac`（HMAC over 密文，不解密即可检出截断/替换），
    /// 再 AEAD open。密文篡改 → [`CfError::Corrupted`]；AAD 不匹配
    /// （跨行搬运）→ [`CfError::CryptoError`]。
    pub fn read_content(&self, attachment_uuid: &str, vault_dir: &Path) -> CfStoreResult<Vec<u8>> {
        let row = self.query_row(attachment_uuid)?;
        let ciphertext = fs::read(vault_dir.join(&row.file_path)).map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                CfError::Corrupted(format!("attachment file missing: {attachment_uuid}"))
            } else {
                CfError::Io(format!("读取附件文件失败：{e}"))
            }
        })?;
        verify_content_mac(self.attach_mac_key, &ciphertext, &row.content_mac)?;
        let aad = field_aad("attachments", attachment_uuid, COLUMN_CONTENT)?;
        open(self.file_key, &aad, &ciphertext).crypto()
    }

    /// 列出某条目的全部附件（created_at 升序；filename 解密）。
    pub fn list_for_item(&self, item_uuid: &str) -> CfStoreResult<Vec<AttachmentMeta>> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT uuid, item_uuid, enc_filename, size_bytes, created_at
                 FROM attachments WHERE item_uuid = ?1 ORDER BY created_at, uuid",
            )
            .store()?;
        let mut rows = stmt.query(rusqlite::params![item_uuid]).store()?;
        let mut out = Vec::new();
        while let Some(row) = rows.next().store()? {
            let uuid: String = row.get(0).store()?;
            let item: String = row.get(1).store()?;
            let enc_filename: Vec<u8> = row.get(2).store()?;
            let size_bytes: i64 = row.get(3).store()?;
            let created_at: i64 = row.get(4).store()?;
            out.push(AttachmentMeta {
                filename: self.decrypt_filename(&enc_filename, &uuid)?,
                uuid,
                item_uuid: item,
                size_bytes,
                created_at,
            });
        }
        Ok(out)
    }

    /// 删除附件（FR-9.2）：**先删行（调用方事务）后删文件**。
    ///
    /// 行不存在 → [`CfError::Validation`]。旁路文件已不存在（孤儿容忍的
    /// 反向情形）视为删除成功；其他文件系统错误向上传播。
    pub fn remove(&self, attachment_uuid: &str, vault_dir: &Path) -> CfStoreResult<()> {
        let row = self.query_row(attachment_uuid)?;
        let deleted = self
            .conn
            .execute(
                "DELETE FROM attachments WHERE uuid = ?1",
                rusqlite::params![attachment_uuid],
            )
            .store()?;
        if deleted != 1 {
            return Err(CfError::Corrupted(format!(
                "attachment row delete count != 1: {attachment_uuid}"
            )));
        }
        match fs::remove_file(vault_dir.join(&row.file_path)) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(CfError::Io(format!("删除附件文件失败：{e}"))),
        }
    }

    /// 清理孤儿旁路文件（unlock 时调用）：删除 `attachments/` 下未被任何
    /// DB 行引用的文件（含崩溃残留的 `.tmp-` 半截文件），返回删除数。
    ///
    /// 目录不存在视为无孤儿（`Ok(0)`）；单文件删除失败向上传播
    /// （不静默降级——调用方可重试）。
    pub fn cleanup_orphans(vault_dir: &Path, conn: &Connection) -> CfStoreResult<usize> {
        let dir = vault_dir.join(ATTACHMENTS_DIR);
        if !dir.is_dir() {
            return Ok(0);
        }

        // DB 已引用的文件基名集合（file_path 坐标系恒为 `attachments/<uuid>`）
        let mut referenced = std::collections::HashSet::new();
        let mut stmt = conn.prepare("SELECT file_path FROM attachments").store()?;
        let mut rows = stmt.query([]).store()?;
        while let Some(row) = rows.next().store()? {
            let file_path: String = row.get(0).store()?;
            if let Some(name) = file_path.rsplit('/').next() {
                referenced.insert(name.to_owned());
            }
        }

        let mut removed = 0usize;
        for entry in fs::read_dir(&dir).map_err(|e| CfError::Io(format!("读取附件目录失败：{e}")))? {
            let entry = entry.map_err(|e| CfError::Io(format!("读取附件目录项失败：{e}")))?;
            let path = entry.path();
            if !path.is_file() {
                continue;
            }
            let name = entry.file_name().to_string_lossy().to_string();
            if referenced.contains(&name) {
                continue;
            }
            fs::remove_file(&path).map_err(|e| CfError::Io(format!("清理孤儿附件失败：{e}")))?;
            removed += 1;
        }
        Ok(removed)
    }

    /// 读取单行元数据；行不存在 → [`CfError::Validation`]。
    fn query_row(&self, attachment_uuid: &str) -> CfStoreResult<AttachmentRow> {
        self.conn
            .query_row(
                "SELECT uuid, item_uuid, enc_filename, file_path, size_bytes,
                        content_mac, created_at
                 FROM attachments WHERE uuid = ?1",
                rusqlite::params![attachment_uuid],
                |r| {
                    Ok(AttachmentRow {
                        uuid: r.get(0)?,
                        item_uuid: r.get(1)?,
                        enc_filename: r.get(2)?,
                        file_path: r.get(3)?,
                        size_bytes: r.get(4)?,
                        content_mac: r.get(5)?,
                        created_at: r.get(6)?,
                    })
                },
            )
            .map_err(|e| match e {
                rusqlite::Error::QueryReturnedNoRows => {
                    CfError::Validation(format!("attachment not found: {attachment_uuid}"))
                }
                other => crate::error::db_err(other),
            })
    }

    /// 解密 filename：AEAD open（AAD 钉附件行 uuid）→ UTF-8 校验。
    fn decrypt_filename(&self, enc_filename: &[u8], attachment_uuid: &str) -> CfStoreResult<String> {
        let aad = field_aad("attachments", attachment_uuid, COLUMN_FILENAME)?;
        let plain = open(self.file_key, &aad, enc_filename).crypto()?;
        String::from_utf8(plain)
            .map_err(|_| CfError::Corrupted("attachment filename is not utf-8".into()))
    }
}

/// 以 `attach_mac_key`（恒 32 字节）构造 HMAC-SHA256 实例。
///
/// 按 RFC 2104 §2 将 32 字节密钥零填充到分组长度（64B）后走 infallible
/// 的 `Mac::new`——两者逐字节等价（HMAC 对短密钥的约定行为），生产路径
/// 无 panic 面（与 cf-audit watchtower 同一模式）。
fn new_attach_mac(key: &SessionKey) -> HmacSha256 {
    let mut padded = [0u8; HMAC_SHA256_BLOCK_LEN];
    padded[..KEY_LEN].copy_from_slice(key.as_bytes());
    <HmacSha256 as KeyInit>::new(GenericArray::from_slice(&padded))
}

/// 计算密文的 content_mac：`base64(HMAC-SHA256(attach_mac_key, 密文))`。
fn content_mac_b64(key: &SessionKey, ciphertext: &[u8]) -> String {
    let mut mac = new_attach_mac(key);
    mac.update(ciphertext);
    BASE64.encode(mac.finalize().into_bytes())
}

/// 常量时间校验密文的 content_mac；不符 → [`CfError::Corrupted`]。
fn verify_content_mac(key: &SessionKey, ciphertext: &[u8], stored: &str) -> CfStoreResult<()> {
    let expected = BASE64
        .decode(stored)
        .map_err(|_| CfError::Corrupted("attachment content_mac is not valid base64".into()))?;
    let mut mac = new_attach_mac(key);
    mac.update(ciphertext);
    mac.verify_slice(&expected)
        .map_err(|_| CfError::Corrupted("attachment content_mac mismatch".into()))
}
