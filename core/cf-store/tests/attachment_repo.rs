//! FR-9.1 / FR-9.2 附件存储内核验收用例（docs/09 v0.3.0）。
//!
//! 内存库 + 临时 vault_dir fixture；判据 = docs/09 v0.3.0 附件内核设计
//! （先文件后行、孤儿容忍、content_mac 对密文、AAD 钉附件行 uuid、
//! 100 MiB 硬上限、与备份打包路径坐标系一致）。

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use cf_crypto::subkeys::SubKeys;
use cf_domain::category::ItemCategory;
use cf_domain::item::ItemState;
use cf_domain::secret::SecretString;
use cf_store::{ItemRow, ItemStore, MAX_ATTACHMENT_BYTES};
use rusqlite::Connection;

/// 内存库 + 固定子密钥（不走解锁流；docs/10 §0.4：内存 fixture）。
fn memory_store() -> ItemStore {
    let conn = Connection::open_in_memory().unwrap();
    let subkeys = SubKeys::derive(&[0x42u8; 32], &[0x11u8; 16]).unwrap();
    ItemStore::open(conn, subkeys).unwrap()
}

/// 唯一临时 vault 目录（pid + 进程内原子计数器，不引入 tempfile 依赖）。
///
/// 修复 BUG-12：原实现 pid+纳秒 在 macOS 粗时钟下同 pid 同 tick 撞名
/// （并行测试 remove_dir_all 互相拆台，见 `temp_vault_dir并行不撞名`）；
/// 计数器按构造保证进程内唯一。
fn temp_vault_dir() -> PathBuf {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let seq = COUNTER.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!("coffer-attach-test-{}-{seq}", std::process::id()));
    fs::create_dir_all(&dir).unwrap();
    dir
}

/// 直接插一个 Active 条目行（仓库层测试不经过 validate / 编排）。
fn host_item(store: &ItemStore, uuid: &str) {
    store
        .repos()
        .items
        .insert(
            &ItemRow {
                uuid: uuid.to_owned(),
                category: ItemCategory::Login,
                state: ItemState::Active,
                is_favorite: false,
                fav_index: 0,
                created_at: 1_000,
                updated_at: 1_000,
                trashed_at: None,
                position: 0,
            },
            &SecretString::from_exposed("GitHub 登录"),
        )
        .unwrap();
}

fn item_uuid(seed: u8) -> String {
    uuid::Uuid::from_bytes([seed; 16]).to_string()
}

/// 在事务内 add 一个附件（内核冻结用法：调用方包在 with_tx 内）。
fn add_attachment(
    store: &mut ItemStore,
    item: &str,
    filename: &str,
    plain: &[u8],
    vault_dir: &Path,
) -> cf_store::AttachmentMeta {
    let filename = filename.as_bytes().to_vec();
    store
        .with_tx(|repos| repos.attachments.add(item, &filename, plain, vault_dir))
        .unwrap()
}

/// 读 DB 里的 content_mac 列（TEXT）。
fn db_content_mac(store: &ItemStore, attachment: &str) -> String {
    store
        .connection()
        .query_row(
            "SELECT content_mac FROM attachments WHERE uuid = ?1",
            rusqlite::params![attachment],
            |r| r.get(0),
        )
        .unwrap()
}

/// FR-9.1 add → read/read_content 回环：内容逐字节还原、filename 解密、
/// 元数据（item_uuid / size_bytes / chunk_count=1）正确。
#[test]
fn add与read_content回环含filename解密() {
    let mut store = memory_store();
    let item = item_uuid(1);
    host_item(&store, &item);
    let vault = temp_vault_dir();

    let plain = b"secret attachment bytes \xe4\xbd\xa0\xe5\xa5\xbd";
    let meta = add_attachment(&mut store, &item, "合同扫描件.pdf", plain, &vault);

    // 元数据回环
    let back = store.repos().attachments.read(&meta.uuid, &vault).unwrap();
    assert_eq!(back, meta, "read 必须与 add 返回逐字段一致");
    assert_eq!(back.filename, "合同扫描件.pdf", "filename 必须解密还原");
    assert_eq!(back.item_uuid, item);
    assert_eq!(back.size_bytes, plain.len() as i64);

    // 内容回环
    let content = store
        .repos()
        .attachments
        .read_content(&meta.uuid, &vault)
        .unwrap();
    assert_eq!(content, plain);

    // chunk_count 恒 1（D-3 留位）且 storage = 'file'
    let (chunk, storage): (i64, String) = store
        .connection()
        .query_row(
            "SELECT chunk_count, storage FROM attachments WHERE uuid = ?1",
            rusqlite::params![meta.uuid],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    assert_eq!((chunk, storage.as_str()), (1, "file"));

    fs::remove_dir_all(&vault).unwrap();
}

/// FR-9.2 落盘为密文：旁路文件字节 ≠ 明文，且 content_mac ==
/// base64(HMAC-SHA256(attach_mac_key, 密文))（与 MANIFEST 对密文语义对齐）。
#[test]
fn 落盘为密文且content_mac对齐密文() {
    let mut store = memory_store();
    let item = item_uuid(2);
    host_item(&store, &item);
    let vault = temp_vault_dir();

    let plain = b"top secret content";
    let meta = add_attachment(&mut store, &item, "notes.txt", plain, &vault);

    let file_path = vault.join("attachments").join(&meta.uuid);
    let ciphertext = fs::read(&file_path).unwrap();
    assert_ne!(ciphertext, plain, "附件明文不得落盘");
    assert_eq!(
        ciphertext.len(),
        24 + plain.len() + 16,
        "sealed = nonce(24) ‖ ct ‖ tag(16)"
    );
    assert!(
        !ciphertext
            .windows(plain.len().min(ciphertext.len()))
            .any(|w| w == plain),
        "明文字节序列不得以任何偏移出现在密文中"
    );

    // DB 内 enc_filename 也是密文
    let enc_filename: Vec<u8> = store
        .connection()
        .query_row(
            "SELECT enc_filename FROM attachments WHERE uuid = ?1",
            rusqlite::params![meta.uuid],
            |r| r.get(0),
        )
        .unwrap();
    assert_ne!(enc_filename, b"notes.txt", "文件名明文不得落库");

    // content_mac 独立复算：HMAC over 密文（attach_mac_key）
    let subkeys = SubKeys::derive(&[0x42u8; 32], &[0x11u8; 16]).unwrap();
    use hmac::digest::KeyInit;
    use hmac::{Hmac, Mac as _};
    use sha2::Sha256;
    let mut mac =
        <Hmac<Sha256> as KeyInit>::new_from_slice(subkeys.attach_mac_key.as_bytes()).unwrap();
    mac.update(&ciphertext);
    let expected = BASE64.encode(mac.finalize().into_bytes());
    assert_eq!(db_content_mac(&store, &meta.uuid), expected);

    fs::remove_dir_all(&vault).unwrap();
}

/// FR-9.2 content_mac 检出截断与替换：密文被截断 / 整体替换 →
/// Corrupted（不解密即可判定）。
#[test]
fn content_mac篡改检出() {
    let mut store = memory_store();
    let item = item_uuid(3);
    host_item(&store, &item);
    let vault = temp_vault_dir();

    let meta = add_attachment(&mut store, &item, "a.bin", b"0123456789", &vault);
    let file_path = vault.join("attachments").join(&meta.uuid);

    // 截断（删掉最后 8 字节）
    let mut truncated = fs::read(&file_path).unwrap();
    truncated.truncate(truncated.len() - 8);
    fs::write(&file_path, &truncated).unwrap();
    let result = store.repos().attachments.read_content(&meta.uuid, &vault);
    assert!(
        matches!(result, Err(cf_domain::CfError::Corrupted(_))),
        "截断必须被 content_mac 检出"
    );

    // 替换（换成另一段合法密文形态的字节）
    fs::write(&file_path, vec![0xEEu8; 64]).unwrap();
    let result = store.repos().attachments.read_content(&meta.uuid, &vault);
    assert!(
        matches!(result, Err(cf_domain::CfError::Corrupted(_))),
        "整体替换必须被 content_mac 检出"
    );

    fs::remove_dir_all(&vault).unwrap();
}

/// O-1 AAD 钉死：把附件 A 的密文搬到附件 B 的旁路文件（content_mac 由
/// 测试方用密钥重算放行 MAC 关卡）→ AEAD open 失败（CryptoError）。
#[test]
fn 密文跨附件搬运解密失败() {
    let mut store = memory_store();
    let item = item_uuid(4);
    host_item(&store, &item);
    let vault = temp_vault_dir();

    let a = add_attachment(&mut store, &item, "a.bin", b"content of a", &vault);
    let b = add_attachment(&mut store, &item, "b.bin", b"content of b", &vault);

    // 把 a 的密文搬到 b 的文件，并重算 b 的 content_mac 放行 MAC 关卡，
    // 剩下的只有 AAD（钉附件行 uuid）一道关卡
    let ct_a = fs::read(vault.join("attachments").join(&a.uuid)).unwrap();
    fs::write(vault.join("attachments").join(&b.uuid), &ct_a).unwrap();

    let subkeys = SubKeys::derive(&[0x42u8; 32], &[0x11u8; 16]).unwrap();
    use hmac::digest::KeyInit;
    use hmac::{Hmac, Mac as _};
    use sha2::Sha256;
    let mut mac =
        <Hmac<Sha256> as KeyInit>::new_from_slice(subkeys.attach_mac_key.as_bytes()).unwrap();
    mac.update(&ct_a);
    let fixed_mac = BASE64.encode(mac.finalize().into_bytes());
    store
        .connection()
        .execute(
            "UPDATE attachments SET content_mac = ?1 WHERE uuid = ?2",
            rusqlite::params![fixed_mac, b.uuid],
        )
        .unwrap();

    let result = store.repos().attachments.read_content(&b.uuid, &vault);
    assert!(
        matches!(result, Err(cf_domain::CfError::CryptoError)),
        "跨附件搬运（AAD 行级钉死）必须解密失败"
    );

    fs::remove_dir_all(&vault).unwrap();
}

/// 100 MiB 硬上限：超限 → Validation，且不产生任何文件与 DB 行。
#[test]
fn 超限拒绝且零残留() {
    let mut store = memory_store();
    let item = item_uuid(5);
    host_item(&store, &item);
    let vault = temp_vault_dir();

    let oversized = vec![0u8; MAX_ATTACHMENT_BYTES + 1];
    let filename = b"big.bin".to_vec();
    let result = store.with_tx(|repos| repos.attachments.add(&item, &filename, &oversized, &vault));
    assert!(
        matches!(result, Err(cf_domain::CfError::Validation(_))),
        "超限必须报 Validation"
    );

    let rows: i64 = store
        .connection()
        .query_row("SELECT COUNT(*) FROM attachments", [], |r| r.get(0))
        .unwrap();
    assert_eq!(rows, 0, "超限不得写行");
    let dir = vault.join("attachments");
    assert!(
        !dir.exists() || fs::read_dir(&dir).unwrap().next().is_none(),
        "超限不得写文件"
    );

    fs::remove_dir_all(&vault).unwrap();
}

/// FR-9.2 删除顺序：先删行（事务）后删文件；行与文件同时消失。
#[test]
fn remove先行后文件() {
    let mut store = memory_store();
    let item = item_uuid(6);
    host_item(&store, &item);
    let vault = temp_vault_dir();

    let meta = add_attachment(&mut store, &item, "gone.bin", b"bye", &vault);
    assert!(vault.join("attachments").join(&meta.uuid).is_file());

    store
        .with_tx(|repos| repos.attachments.remove(&meta.uuid, &vault))
        .unwrap();

    let rows: i64 = store
        .connection()
        .query_row("SELECT COUNT(*) FROM attachments", [], |r| r.get(0))
        .unwrap();
    assert_eq!(rows, 0, "行必须先删");
    assert!(
        !vault.join("attachments").join(&meta.uuid).exists(),
        "文件必须随后删"
    );

    fs::remove_dir_all(&vault).unwrap();
}

/// 孤儿容忍（文件在行无）：事务回滚留下孤儿文件 + 手工 .tmp- 残留 →
/// cleanup_orphans 全部清理并返回正确计数；在行文件保留。
#[test]
fn cleanup_orphans清理孤儿与tmp残留() {
    let mut store = memory_store();
    let item = item_uuid(7);
    host_item(&store, &item);
    let vault = temp_vault_dir();

    let keep = add_attachment(&mut store, &item, "keep.bin", b"kept", &vault);

    // 事务内 add 后注入失败 → 行回滚、文件成孤儿
    let filename = b"orphan.bin".to_vec();
    let err: cf_store::CfStoreResult<()> = store.with_tx(|repos| {
        repos
            .attachments
            .add(&item, &filename, b"orphaned", &vault)?;
        Err(cf_domain::CfError::Validation("injected".into()))
    });
    assert!(err.is_err());
    let rows: i64 = store
        .connection()
        .query_row("SELECT COUNT(*) FROM attachments", [], |r| r.get(0))
        .unwrap();
    assert_eq!(rows, 1, "事务回滚后只剩 keep 一行");

    // 手工放置 .tmp- 半截文件（模拟 rename 前崩溃）
    fs::write(vault.join("attachments").join(".tmp-deadbeef"), b"half").unwrap();

    let removed = cf_store::AttachmentRepo::cleanup_orphans(&vault, store.connection()).unwrap();
    assert_eq!(removed, 2, "孤儿文件 + .tmp- 残留都应被清理");
    assert!(
        vault.join("attachments").join(&keep.uuid).is_file(),
        "在行文件必须保留"
    );
    assert!(
        !vault.join("attachments").join(".tmp-deadbeef").exists(),
        ".tmp- 残留必须被清理"
    );

    fs::remove_dir_all(&vault).unwrap();
}

/// 孤儿容忍（行在文件无）：旁路文件被外部删除 → read / read_content 报
/// Corrupted，而非 IO NotFound。
#[test]
fn 行在文件无报损坏() {
    let mut store = memory_store();
    let item = item_uuid(8);
    host_item(&store, &item);
    let vault = temp_vault_dir();

    let meta = add_attachment(&mut store, &item, "lost.bin", b"lost", &vault);
    fs::remove_file(vault.join("attachments").join(&meta.uuid)).unwrap();

    let read = store.repos().attachments.read(&meta.uuid, &vault);
    assert!(matches!(read, Err(cf_domain::CfError::Corrupted(_))));
    let read_content = store.repos().attachments.read_content(&meta.uuid, &vault);
    assert!(matches!(
        read_content,
        Err(cf_domain::CfError::Corrupted(_))
    ));

    fs::remove_dir_all(&vault).unwrap();
}

/// 备份打包路径坐标系一致性：DB 存相对路径 `attachments/<uuid>`，
/// vault_dir.join(file_path) 命中真实文件，且该相对路径出现在
/// collect_recursive 同构的递归枚举（相对库根、正斜杠）结果中。
#[test]
fn 与备份打包路径坐标系一致() {
    let mut store = memory_store();
    let item = item_uuid(9);
    host_item(&store, &item);
    let vault = temp_vault_dir();

    let meta = add_attachment(&mut store, &item, "report.pdf", b"report", &vault);

    // DB 中 file_path 为相对路径且用正斜杠（与备份 ZIP 条目坐标系一致）
    let file_path: String = store
        .connection()
        .query_row(
            "SELECT file_path FROM attachments WHERE uuid = ?1",
            rusqlite::params![meta.uuid],
            |r| r.get(0),
        )
        .unwrap();
    assert!(
        file_path.starts_with("attachments/") && !file_path.contains('\\'),
        "file_path 必须是 attachments/ 前缀的正斜杠相对路径，实际：{file_path}"
    );
    assert!(!meta.uuid.contains('/'), "file_path 不得包含绝对路径成分");

    // 相对路径在库根坐标系下命中真实文件
    assert!(vault.join(&file_path).is_file());

    // collect_recursive 同构枚举（递归、相对库根）：附件必须出现在结果里
    fn walk_relative(root: &Path, dir: &Path, out: &mut Vec<String>) {
        for entry in fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                walk_relative(root, &path, out);
            } else {
                let rel = path.strip_prefix(root).unwrap().to_string_lossy();
                out.push(rel.replace('\\', "/"));
            }
        }
    }
    let mut packed = Vec::new();
    walk_relative(&vault, &vault, &mut packed);
    packed.sort();
    assert!(
        packed.contains(&file_path),
        "附件旁路文件必须被备份打包范围（collect_recursive 视角）覆盖，打包列表：{packed:?}"
    );

    fs::remove_dir_all(&vault).unwrap();
}

/// 条目隔离与缺失行：list_for_item 只返回本条目附件；不存在的附件
/// → Validation（不存在不算容器损坏）。
#[test]
fn 条目隔离与缺失附件() {
    let mut store = memory_store();
    let a = item_uuid(10);
    let b = item_uuid(11);
    host_item(&store, &a);
    host_item(&store, &b);
    let vault = temp_vault_dir();

    let m1 = add_attachment(&mut store, &a, "1.txt", b"one", &vault);
    add_attachment(&mut store, &a, "2.txt", b"two", &vault);

    let list_a = store.repos().attachments.list_for_item(&a).unwrap();
    assert_eq!(list_a.len(), 2);
    assert!(list_a.iter().all(|m| m.item_uuid == a));
    assert!(store
        .repos()
        .attachments
        .list_for_item(&b)
        .unwrap()
        .is_empty());

    let missing = store
        .repos()
        .attachments
        .read(&uuid::Uuid::now_v7().to_string(), &vault);
    assert!(matches!(missing, Err(cf_domain::CfError::Validation(_))));

    // remove 不存在的附件同样 Validation，且不动任何文件
    let remove_missing = store.with_tx(|repos| repos.attachments.remove(&m1.uuid, &vault));
    assert!(remove_missing.is_ok(), "remove 已存在附件必须成功");
    let remove_missing = store.with_tx(|repos| {
        repos
            .attachments
            .remove(&uuid::Uuid::now_v7().to_string(), &vault)
    });
    assert!(matches!(
        remove_missing,
        Err(cf_domain::CfError::Validation(_))
    ));

    fs::remove_dir_all(&vault).unwrap();
}

/// BUG-12 回归警戒：并行满载下 temp_vault_dir() 必须永不撞名。
///
/// 旧实现用 pid+纳秒 命名，同进程（同 pid）内两个并行测试在同一时钟
/// tick 调用即撞名——某用例收尾 remove_dir_all 会拆掉另一用例的现场，
/// 导致密文/结构断言偶发失败（macOS 时钟分辨率粗于测试步进，撞名窗口
/// 实际存在）。修复为 pid+进程内原子计数器后，进程内唯一性由构造保证，
/// 本测试必须稳定全绿。
#[test]
fn temp_vault_dir并行不撞名() {
    const THREADS: usize = 32;
    const PER_THREAD: usize = 16; // 共 512 次调用，barrier 压缩到同一 tick
    let barrier = std::sync::Barrier::new(THREADS);
    let dirs: Vec<PathBuf> = std::thread::scope(|s| {
        let handles: Vec<_> = (0..THREADS)
            .map(|_| {
                let barrier = &barrier;
                s.spawn(move || {
                    barrier.wait(); // 同时开跑，最大化同 tick 撞名概率
                    (0..PER_THREAD)
                        .map(|_| temp_vault_dir())
                        .collect::<Vec<_>>()
                })
            })
            .collect();
        handles
            .into_iter()
            .flat_map(|h| h.join().unwrap())
            .collect()
    });
    let mut seen = std::collections::HashSet::new();
    for dir in &dirs {
        assert!(
            seen.insert(dir.clone()),
            "temp_vault_dir 撞名：{dir:?}（修复前 pid+纳秒 粗时钟可复现，BUG-12）"
        );
        let _ = fs::remove_dir_all(dir);
    }
    assert_eq!(seen.len(), THREADS * PER_THREAD, "全部目录必须互不相同");
}
