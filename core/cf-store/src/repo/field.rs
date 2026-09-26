//! fields / sections 表仓库（`docs/07-macOS纵切设计.md` §2.1）。
//!
//! update 语义 = **按 item 批量替换**（删旧插新），天然覆盖字段的增删改。
//!
//! sections 本没有独立仓库文件（docs/07 §2.1 的六文件清单未列），因
//! fields.section_uuid 引用 sections 表，故把分区的批量替换与读出并入
//! 本文件——这是一处对文件清单的最小偏离，职责上仍属"字段周边"。
//!
//! 加密：`enc_name` / `enc_value` / `enc_title` 用 `field_key`
//! （分区标题用 `item_key`，见 [`crate::repo`] 模块文档的映射表），
//! AAD 钉死在（表名, 各自行 uuid, 列名）上（表名命名空间，O-1）。

use cf_crypto::aead::{open, seal};
use cf_crypto::subkeys::SubKeys;
use cf_domain::field::{Designation, FieldType};
use cf_domain::secret::SecretString;
use rusqlite::Connection;

use crate::error::{CfError, CfStoreResult, CryptoResultExt, RusqliteResultExt};
use crate::repo::url::require_item;
use crate::repo::field_aad;

/// 列名常量（AAD 成分）。
pub const COLUMN_SECTION_TITLE: &str = "enc_title";
/// 列名常量（AAD 成分）。
pub const COLUMN_FIELD_NAME: &str = "enc_name";
/// 列名常量（AAD 成分）。
pub const COLUMN_FIELD_VALUE: &str = "enc_value";

/// sections 表一行。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SectionRow {
    /// 分区 ID。
    pub uuid: String,
    /// 所属条目 ID。
    pub item_uuid: String,
    /// 分区标题（解密后的输入 / 加密前的明文由调用方持 `SecretString`）。
    pub title: String,
    /// 排序位置。
    pub position: i64,
}

/// sections 表一行（读出：标题已解密为 `SecretString`）。
#[derive(Debug)]
pub struct SectionDecrypted {
    /// 行数据（不含标题明文）。
    pub uuid: String,
    /// 所属条目 ID。
    pub item_uuid: String,
    /// 解密后的标题。
    pub title: SecretString,
    /// 排序位置。
    pub position: i64,
}

/// fields 表一行（写入形态：name / value 为明文输入）。
#[derive(Debug, Clone)]
pub struct FieldRow {
    /// 字段 ID。
    pub uuid: String,
    /// 所属条目 ID。
    pub item_uuid: String,
    /// 所属分区；`None` 表示直接挂在条目下。
    pub section_uuid: Option<String>,
    /// 字段数据类型。
    pub field_type: FieldType,
    /// 语义标识；`None` 表示无。
    pub designation: Option<Designation>,
    /// 字段名（明文输入）。
    pub name: String,
    /// 字段值（明文输入）；`None` 表示仅有名称（如布尔标记）。
    pub value: Option<String>,
    /// 排序位置。
    pub position: i64,
}

/// fields 表一行（读出形态：name / value 已解密）。
#[derive(Debug)]
pub struct FieldDecrypted {
    /// 字段 ID。
    pub uuid: String,
    /// 所属条目 ID。
    pub item_uuid: String,
    /// 所属分区。
    pub section_uuid: Option<String>,
    /// 字段数据类型。
    pub field_type: FieldType,
    /// 语义标识。
    pub designation: Option<Designation>,
    /// 解密后的字段名。
    pub name: SecretString,
    /// 解密后的字段值。
    pub value: Option<SecretString>,
    /// 排序位置。
    pub position: i64,
}

/// fields / sections 表仓库。
pub struct FieldsRepo<'a> {
    conn: &'a Connection,
    subkeys: &'a SubKeys,
}

impl<'a> FieldsRepo<'a> {
    /// 构造仓库。
    pub fn new(conn: &'a Connection, subkeys: &'a SubKeys) -> Self {
        Self { conn, subkeys }
    }

    // ------------------------------------------------------------ sections

    /// 按条目批量替换分区（删旧插新）。
    pub fn replace_sections_for_item(
        &self,
        item_uuid: &str,
        sections: &[SectionRow],
    ) -> CfStoreResult<()> {
        require_item(self.conn, item_uuid)?;
        self.conn
            .execute("DELETE FROM sections WHERE item_uuid=?1", [item_uuid])
            .store()?;
        for s in sections {
            let aad = field_aad("sections", &s.uuid, COLUMN_SECTION_TITLE)?;
            let enc_title = seal(&self.subkeys.item_key, &aad, s.title.as_bytes()).crypto()?;
            self.conn
                .execute(
                    "INSERT INTO sections (uuid, item_uuid, enc_title, position)
                     VALUES (?1, ?2, ?3, ?4)",
                    rusqlite::params![s.uuid, s.item_uuid, enc_title, s.position],
                )
                .store()?;
        }
        Ok(())
    }

    /// 读出条目全部分区（按 position 升序），标题解密。
    pub fn read_sections_for_item(&self, item_uuid: &str) -> CfStoreResult<Vec<SectionDecrypted>> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT uuid, item_uuid, enc_title, position
                 FROM sections WHERE item_uuid=?1 ORDER BY position ASC",
            )
            .store()?;
        let mut rows = stmt.query([item_uuid]).store()?;
        let mut out = Vec::new();
        while let Some(r) = rows.next().store()? {
            let uuid: String = r.get(0).store()?;
            let enc_title: Vec<u8> = r.get(2).store()?;
            let aad = field_aad("sections", &uuid, COLUMN_SECTION_TITLE)?;
            let plain = open(&self.subkeys.item_key, &aad, &enc_title).crypto()?;
            let title = String::from_utf8(plain)
                .map_err(|_| CfError::Corrupted("section title not utf-8".into()))?;
            out.push(SectionDecrypted {
                uuid,
                item_uuid: r.get(1).store()?,
                title: SecretString::from_exposed(title),
                position: r.get(3).store()?,
            });
        }
        Ok(out)
    }

    // -------------------------------------------------------------- fields

    /// 按条目批量替换字段（删旧插新，update 语义）。
    ///
    /// 引用了不存在的 section_uuid 时整体失败（外键约束 → `StorageError`），
    /// 调用方应在事务内使用以获得原子性。
    pub fn replace_fields_for_item(
        &self,
        item_uuid: &str,
        fields: &[FieldRow],
    ) -> CfStoreResult<()> {
        require_item(self.conn, item_uuid)?;
        self.conn
            .execute("DELETE FROM fields WHERE item_uuid=?1", [item_uuid])
            .store()?;
        for f in fields {
            let enc_name = seal(
                &self.subkeys.field_key,
                &field_aad("fields", &f.uuid, COLUMN_FIELD_NAME)?,
                f.name.as_bytes(),
            )
            .crypto()?;
            let enc_value = match &f.value {
                Some(v) => {
                    let aad = field_aad("fields", &f.uuid, COLUMN_FIELD_VALUE)?;
                    Some(seal(&self.subkeys.field_key, &aad, v.as_bytes()).crypto()?)
                }
                None => None,
            };
            let designation_json: Option<String> = match &f.designation {
                Some(d) => Some(serde_json::to_string(d).map_err(|_| {
                    CfError::StorageError("designation serialize failed".into())
                })?),
                None => None,
            };
            self.conn
                .execute(
                    "INSERT INTO fields
                        (uuid, item_uuid, section_uuid, field_type, designation,
                         enc_name, enc_value, position)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                    rusqlite::params![
                        f.uuid,
                        f.item_uuid,
                        f.section_uuid,
                        serde_json::to_string(&f.field_type)
                            .map_err(|_| CfError::StorageError(
                                "field_type serialize failed".into()
                            ))?,
                        designation_json,
                        enc_name,
                        enc_value,
                        f.position,
                    ],
                )
                .store()?;
        }
        Ok(())
    }

    /// 读出条目全部字段（按 position 升序），name / value 解密。
    pub fn read_fields_for_item(&self, item_uuid: &str) -> CfStoreResult<Vec<FieldDecrypted>> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT uuid, item_uuid, section_uuid, field_type, designation,
                        enc_name, enc_value, position
                 FROM fields WHERE item_uuid=?1 ORDER BY position ASC",
            )
            .store()?;
        let mut rows = stmt.query([item_uuid]).store()?;
        let mut out = Vec::new();
        while let Some(r) = rows.next().store()? {
            let uuid: String = r.get(0).store()?;

            let enc_name: Vec<u8> = r.get(5).store()?;
            let aad_name = field_aad("fields", &uuid, COLUMN_FIELD_NAME)?;
            let name = open(&self.subkeys.field_key, &aad_name, &enc_name).crypto()?;
            let name = String::from_utf8(name)
                .map_err(|_| CfError::Corrupted("field name not utf-8".into()))?;

            let enc_value: Option<Vec<u8>> = r.get(6).store()?;
            let value = match enc_value {
                Some(ct) => {
                    let aad_value = field_aad("fields", &uuid, COLUMN_FIELD_VALUE)?;
                    let plain = open(&self.subkeys.field_key, &aad_value, &ct).crypto()?;
                    let plain = String::from_utf8(plain)
                        .map_err(|_| CfError::Corrupted("field value not utf-8".into()))?;
                    Some(plain)
                }
                None => None,
            };

            let field_type_json: String = r.get(3).store()?;
            let field_type: FieldType = serde_json::from_str(&field_type_json)
                .map_err(|_| CfError::Corrupted("unknown field_type".into()))?;
            let designation: Option<Designation> = match r.get::<_, Option<String>>(4).store()? {
                Some(json) => Some(
                    serde_json::from_str(&json)
                        .map_err(|_| CfError::Corrupted("unknown designation".into()))?,
                ),
                None => None,
            };

            out.push(FieldDecrypted {
                uuid,
                item_uuid: r.get(1).store()?,
                section_uuid: r.get(2).store()?,
                field_type,
                designation,
                name: SecretString::from_exposed(name),
                value: value.map(SecretString::from_exposed),
                position: r.get(7).store()?,
            });
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn setup() -> (Connection, SubKeys) {
        let mut conn = Connection::open_in_memory().unwrap();
        crate::schema::init(&mut conn).unwrap();
        let keys = SubKeys::derive(&[0x42u8; 32], &[0x11u8; 16]).unwrap();
        (conn, keys)
    }

    fn item(conn: &Connection, uuid: &str) {
        conn.execute(
            "INSERT INTO items (uuid, category, created_at, updated_at, enc_title)
             VALUES (?1, 'login', 0, 0, x'00')",
            rusqlite::params![uuid],
        )
        .unwrap();
    }

    fn field(seed: u8, item: &str, name: &str, value: Option<&str>) -> FieldRow {
        FieldRow {
            uuid: uuid::Uuid::from_bytes([seed; 16]).to_string(),
            item_uuid: item.to_owned(),
            section_uuid: None,
            field_type: FieldType::Concealed,
            designation: Some(Designation::Password),
            name: name.to_owned(),
            value: value.map(str::to_owned),
            position: 0,
        }
    }

    /// 字段批量替换写入 → 读出：往返一致（含加密值与 designation）
    #[test]
    fn 字段往返一致() {
        let (conn, keys) = setup();
        let repo = FieldsRepo::new(&conn, &keys);
        item(&conn, "i-1");

        let fields = vec![
            field(1, "i-1", "密码", Some("p@ssw0rd-明文")),
            FieldRow {
                uuid: uuid::Uuid::from_bytes([2; 16]).to_string(),
                item_uuid: "i-1".into(),
                section_uuid: None,
                field_type: FieldType::Text,
                designation: Some(Designation::Other("custom.x".into())),
                name: "只读标记".into(),
                value: None,
                position: 1,
            },
        ];
        repo.replace_fields_for_item("i-1", &fields).unwrap();

        let got = repo.read_fields_for_item("i-1").unwrap();
        assert_eq!(got.len(), 2);
        assert_eq!(got[0].name.expose(), "密码");
        assert_eq!(got[0].value.as_ref().unwrap().expose(), "p@ssw0rd-明文");
        assert_eq!(got[0].field_type, FieldType::Concealed);
        assert_eq!(got[0].designation, Some(Designation::Password));
        assert_eq!(got[1].designation, Some(Designation::Other("custom.x".into())));
        assert!(got[1].value.is_none());
    }

    /// 再次替换 = 覆盖（删旧插新）
    #[test]
    fn 重复替换覆盖旧值() {
        let (conn, keys) = setup();
        let repo = FieldsRepo::new(&conn, &keys);
        item(&conn, "i-1");

        repo.replace_fields_for_item("i-1", &[field(1, "i-1", "旧", Some("v1"))])
            .unwrap();
        repo.replace_fields_for_item("i-1", &[field(9, "i-1", "新", Some("v2"))])
            .unwrap();

        let got = repo.read_fields_for_item("i-1").unwrap();
        assert_eq!(got.len(), 1, "旧字段必须被删除");
        assert_eq!(got[0].name.expose(), "新");
        assert_eq!(got[0].value.as_ref().unwrap().expose(), "v2");
    }

    /// 字段密文落盘：enc_name / enc_value 的 BLOB 里找不到明文
    #[test]
    fn 字段明文不落盘() {
        let (conn, keys) = setup();
        let repo = FieldsRepo::new(&conn, &keys);
        item(&conn, "i-1");
        repo.replace_fields_for_item("i-1", &[field(1, "i-1", "字段名甲", Some("机密值乙"))])
            .unwrap();

        for (sql, col) in [
            ("SELECT enc_name FROM fields WHERE uuid=?1", "字段名甲"),
            ("SELECT enc_value FROM fields WHERE uuid=?1", "机密值乙"),
        ] {
            let blob: Vec<u8> = conn.query_row(sql, rusqlite::params![uuid::Uuid::from_bytes([1; 16]).to_string()], |r| r.get(0)).unwrap();
            assert!(!windows_contains(&blob, col.as_bytes()), "{col} 明文不得落盘");
        }
    }

    /// 条目不存在 → ItemNotFound，且不写入
    #[test]
    fn 字段写入要求条目存在() {
        let (conn, keys) = setup();
        let repo = FieldsRepo::new(&conn, &keys);
        let result = repo.replace_fields_for_item("ghost", &[field(1, "ghost", "n", None)]);
        assert!(matches!(result, Err(CfError::ItemNotFound)));
    }

    /// 分区批量替换 + 字段挂到分区，往返一致
    #[test]
    fn 分区与字段关联往返() {
        let (conn, keys) = setup();
        let repo = FieldsRepo::new(&conn, &keys);
        item(&conn, "i-1");

        let sec_uuid = uuid::Uuid::from_bytes([7; 16]).to_string();
        repo.replace_sections_for_item(
            "i-1",
            &[SectionRow {
                uuid: sec_uuid.clone(),
                item_uuid: "i-1".into(),
                title: "安全信息".into(),
                position: 0,
            }],
        )
        .unwrap();

        let mut f = field(1, "i-1", "恢复码", Some("1111-2222"));
        f.section_uuid = Some(sec_uuid.clone());
        repo.replace_fields_for_item("i-1", &[f]).unwrap();

        let sections = repo.read_sections_for_item("i-1").unwrap();
        assert_eq!(sections.len(), 1);
        assert_eq!(sections[0].title.expose(), "安全信息");

        let fields = repo.read_fields_for_item("i-1").unwrap();
        assert_eq!(fields[0].section_uuid.as_deref(), Some(sec_uuid.as_str()));
    }

    /// 空替换 = 清空该条目全部字段
    #[test]
    fn 空替换清空字段() {
        let (conn, keys) = setup();
        let repo = FieldsRepo::new(&conn, &keys);
        item(&conn, "i-1");
        repo.replace_fields_for_item("i-1", &[field(1, "i-1", "n", Some("v"))])
            .unwrap();
        repo.replace_fields_for_item("i-1", &[]).unwrap();
        assert!(repo.read_fields_for_item("i-1").unwrap().is_empty());
    }

    /// 子串查找（避免引入 substring 依赖的小助手，仅测试用）
    fn windows_contains(haystack: &[u8], needle: &[u8]) -> bool {
        haystack.windows(needle.len()).any(|w| w == needle)
    }
}
