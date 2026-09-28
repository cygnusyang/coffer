//! 跨库复制条目（FR-2.10，v0.4.0-T01）。
//!
//! 把源库中某条目的**当前版本**完整复制为目标库中的新条目，返回目标库
//! 新条目 uuid。设计裁决（冻结）：
//!
//! - **锁纪律：绝不同时持两个 state 锁**——先在源库侧一次性读出全部
//!   载荷（[`super::history::snapshot_current`] + 附件明文）后立即释放
//!   src guard，再进入目标库写路径。顺序化持锁消除
//!   `copy(a, b)` / `copy(b, a)` 的死锁面（判据 ⑪）；
//! - **内容管线**：不走 [`super::items::create_item`]（其 uuid 与时间戳
//!   硬编码不可注入）。快照 → [`super::history::draft_from_snapshot`] →
//!   [`cf_domain::validate::validate_item`]（复用全部不变量，校验失败
//!   目标库零写入）→ 目标库 `with_tx` 内 `ItemsRepo::insert`
//!   （created_at / updated_at 从快照注入保留）+
//!   [`super::items::write_children`] 同款 replace_* 写从表；子表行
//!   uuid 全部重新生成（now_v7）——AAD 密文随新行 uuid 天然换绑到
//!   目标库 SubKeys（判据 ③）；
//! - **产物形态**：恒用新 uuidv7（结构上无冲突）；源条目零改动；标题
//!   不加「副本」后缀。产物 `state` 沿用源条目（归档语义可跨库迁移），
//!   唯一例外是回收站态强制落为 Active——`trashed_at` 不在快照中，
//!   无法忠实迁移，且复制产物是新条目，落在回收站没有用户语义；
//! - **附件**（FR-9.1/9.2）：源库 `read_content`（src key 解封）→
//!   目标库 `AttachmentRepo::add`（item_uuid = 新 uuid、vault_dir = 目标
//!   库目录，dst key 重新 seal）。先文件后行的既有纪律不变；
//! - **部分失败**：目标库全部写入收口在单个 `with_tx` 内
//!   all-or-nothing；任一 `Err` 路径收尾调
//!   [`cf_store::AttachmentRepo::cleanup_orphans`] 清理回滚孤儿
//!   （v0.3 LOW-2 登记的非导入路径清理时机，见 attachment.rs 模块注释）；
//! - **历史**：只复制当前版本，目标库 history 为空（判据 ⑥）；
//! - **审计**：源库 / 目标库各打一条
//!   [`cf_store::AuditEvent::ItemCopy`]，detail 只含库 uuid 与条目
//!   uuid（非敏感纪律）；打点失败静默（沿 change_password 纪律，
//!   不否定已成功的复制）。注意：旧版本 App 读含 `item_copy` 的库会
//!   Corrupted——封闭枚举纪律的已知风险，设计评审接受（见
//!   cf-store repo/audit.rs 模块注释）。

use cf_domain::item::{ItemDraft, ItemState};
use cf_domain::secret::SecretString;
use cf_domain::snapshot::ItemSnapshot;
use cf_domain::totp_data::TotpUpdate;
use cf_domain::CfError;

use crate::vault::VaultSession;
use crate::SessionResult;

/// src 侧一次性读出的附件载荷（filename / content 均为明文字节）。
struct AttachmentPayload {
    /// 文件名明文字节（UTF-8；`AttachmentRepo::add` 的 filename 参数）。
    filename: Vec<u8>,
    /// 附件明文内容（src key 解封后的字节）。
    content: Vec<u8>,
}

/// src 侧一次性读出的复制载荷：条目快照 + 附件明文。
struct CopyPayload {
    snapshot: ItemSnapshot,
    attachments: Vec<AttachmentPayload>,
}

/// 跨库复制条目（FR-2.10）：`src` 库的 `src_item_id` 当前版本 →
/// `dst` 库新条目，返回目标库新条目 uuid（UUIDv7 文本）。
///
/// 双方均须处于解锁态（错误码 1001）；源条目不存在 → 1011；
/// 内容未通过 [`cf_domain::validate::validate_item`] → 5002（目标库
/// 零写入）。锁纪律见模块文档（绝不同时持两个 state 锁）。
pub fn copy_item(src: &VaultSession, src_item_id: &str, dst: &VaultSession) -> SessionResult<String> {
    // ---- 阶段一：src 侧一次性读出载荷，立即释放 src state 锁 ----
    let payload = {
        let guard = src.unlocked()?;
        let state = guard.as_ref().ok_or(CfError::VaultLocked)?;
        let repos = state.store.repos();
        let snapshot = super::history::snapshot_current(&repos, src_item_id)?;
        let mut attachments = Vec::new();
        for meta in repos.attachments.list_for_item(src_item_id)? {
            let content = repos.attachments.read_content(&meta.uuid, src.vault_dir())?;
            attachments.push(AttachmentPayload {
                filename: meta.filename.into_bytes(),
                content,
            });
        }
        CopyPayload {
            snapshot,
            attachments,
        }
    }; // src guard 在此 drop——写路径开始前不持有任何锁

    // ---- 校验：复用全部不变量；失败 → dst 零写入 ----
    let draft: ItemDraft = super::history::draft_from_snapshot(&payload.snapshot)?;
    cf_domain::validate::validate_item(&draft)?;

    let new_uuid = uuid::Uuid::now_v7().to_string();
    let dst_dir = dst.vault_dir().to_path_buf();
    let title = SecretString::from_exposed(payload.snapshot.title.clone());
    // 回收站态产物强制 Active（trashed_at 不在快照中，无法忠实迁移；
    // 其余状态语义原样跨库），见模块文档「产物形态」
    let state = match payload.snapshot.state {
        ItemState::Trashed => ItemState::Active,
        other => other,
    };
    let row = cf_store::ItemRow {
        uuid: new_uuid.clone(),
        category: payload.snapshot.category,
        state,
        is_favorite: payload.snapshot.is_favorite,
        fav_index: payload.snapshot.fav_index,
        created_at: payload.snapshot.created_at,
        updated_at: payload.snapshot.updated_at,
        trashed_at: None,
        position: 0,
    };
    let totp = match &payload.snapshot.totp {
        Some(data) => TotpUpdate::Replace(data.clone()),
        None => TotpUpdate::Remove,
    };

    // ---- 阶段二：dst 写路径（单事务 all-or-nothing；附件先文件后行）----
    let write_result = {
        let mut guard = dst.unlocked()?;
        let state = guard.as_mut().ok_or(CfError::VaultLocked)?;
        match state.store.with_tx(|repos| {
            repos.items.insert(&row, &title)?;
            super::items::write_children(repos, &new_uuid, &draft, &totp)?;
            for att in &payload.attachments {
                repos
                    .attachments
                    .add(&new_uuid, &att.filename, &att.content, &dst_dir)?;
            }
            repos.meta.add_item_count(1)?;
            Ok(())
        }) {
            Ok(()) => Ok(()),
            Err(e) => {
                // FR-2.10 收尾：附件先文件后行，事务回滚后旁路文件成为
                // 孤儿，统一清理（v0.3 LOW-2 非导入路径的清理时机）。
                // 清理失败静默：不掩盖主错误；下次解锁的 unlock 级
                // 清理仍可兜底（attachment.rs 模块文档「孤儿容忍」）。
                let _ = cf_store::AttachmentRepo::cleanup_orphans(
                    &dst_dir,
                    state.store.connection(),
                );
                Err(e)
            }
        }
    };
    write_result?;

    // ---- 阶段三：审计（源库 / 目标库各一条；打点失败静默）----
    // 顺序化短持锁：写路径锁已释放，这里逐库短暂加锁追加，两库同会话
    // （同库复制）时也只是串行两次加锁，无死锁面。
    audit_copy(
        dst,
        format!("src:{} item:{src_item_id}", src.vault_uuid()),
    );
    audit_copy(src, format!("dst:{} item:{new_uuid}", dst.vault_uuid()));

    Ok(new_uuid)
}

/// 追加一条跨库复制审计事件（打点失败静默，沿 change_password 纪律）。
///
/// 会话在复制成功后可能已被并发 `lock()`：门禁失败同样静默——审计是
/// 尽力而为，不否定已成功的数据写入。
fn audit_copy(session: &VaultSession, detail: String) {
    let Ok(guard) = session.unlocked() else {
        return;
    };
    let Some(state) = guard.as_ref() else {
        return;
    };
    if let Ok(now) = crate::unix_now() {
        let _ = state
            .store
            .repos()
            .audit
            .append(now, cf_store::AuditEvent::ItemCopy, Some(&detail));
    }
}

#[cfg(test)]
mod tests {
    use cf_crypto::kdf::KdfParams;
    use cf_domain::category::ItemCategory;
    use cf_domain::field::{Designation, FieldType};
    use cf_domain::item::{FieldDraft, ItemDraft, SectionDraft, UrlDraft};
    use cf_domain::totp_data::{TotpAlgo, TotpData};
    use cf_domain::validate::MAX_TITLE_CHARS;
    use crate::unlock::{create_vault_with_kdf, open_vault};

    use super::copy_item;
    use crate::vault::VaultSession;

    /// 强密码（zxcvbn score ≥ 3，可过建库门禁）。
    const STRONG: &str = "correct-horse-battery-staple-42!";

    /// 快速 KDF 档位。
    fn fast_kdf() -> KdfParams {
        KdfParams::new(8 * 1024, 1, 1).unwrap()
    }

    /// 建库 + 解锁。
    fn unlocked_vault(base: &std::path::Path, tag: &str) -> VaultSession {
        let brief = create_vault_with_kdf(base, tag, STRONG, fast_kdf()).unwrap();
        let session = open_vault(&base.join(brief.uuid.to_string())).unwrap();
        session.unlock(STRONG).unwrap();
        session
    }

    /// 内容丰富的 Login 草稿（含分区挂接字段 + TOTP）。
    fn rich_draft(title: &str) -> ItemDraft {
        ItemDraft {
            title: title.to_owned(),
            category: ItemCategory::Login,
            urls: vec![UrlDraft {
                label: Some("登录页".to_owned()),
                url: "https://github.com/login".to_owned(),
                is_primary: true,
                position: 0,
            }],
            tags: vec!["工作".to_owned()],
            sections: vec![SectionDraft {
                title: "服务器".to_owned(),
                position: 0,
            }],
            fields: vec![
                FieldDraft {
                    name: "用户名".to_owned(),
                    value: Some("alice@example.com".to_owned()),
                    field_type: FieldType::Text,
                    designation: Some(Designation::Username),
                    section_index: None,
                    position: 0,
                },
                FieldDraft {
                    name: "密码".to_owned(),
                    value: Some("hunter2-secret".to_owned()),
                    field_type: FieldType::Concealed,
                    designation: Some(Designation::Password),
                    section_index: None,
                    position: 1,
                },
            ],
            totp: Some(TotpData {
                secret: b"0123456789abcdef0123".to_vec(),
                algo: TotpAlgo::Sha1,
                digits: 6,
                period: 30,
            }),
        }
    }

    /// 在源条目名下通过 with_tx 直写一个附件（v0.4 会话层尚未暴露
    /// 附件新增 API，内核写法与 cf-store attachment_repo 测试一致）。
    fn add_attachment(session: &VaultSession, item_id: &str, filename: &[u8], plain: &[u8]) {
        let mut guard = session.unlocked().unwrap();
        let state = guard.as_mut().unwrap();
        let vault_dir = session.vault_dir().to_path_buf();
        state
            .store
            .with_tx(|repos| {
                repos
                    .attachments
                    .add(item_id, filename, plain, &vault_dir)
                    .map(|_| ())
            })
            .unwrap();
    }

    // ------------------------------------------------------------ 判据 ⑦

    /// 判据 ⑦：含附件条目跨库复制——目标库 read_content 逐字节一致、
    /// 文件落目标库 vault_dir/attachments/ 下的新文件（新附件行 uuid），
    /// 且 secret 以 dst key 重密封（目标库 TOTP 可出码）。
    #[test]
    fn 含附件条目跨库复制逐字节一致且文件落目标库() {
        let base = crate::tests_support::temp_dir("xcopy_attach");
        let src = unlocked_vault(&base, "附件源库");
        let dst = unlocked_vault(&base, "附件目标库");

        let src_id = src.create_item(&rich_draft("带附件条目")).unwrap();
        let plain_a = b"ssh private key bytes \xe2\x9c\x93".to_vec();
        let plain_b = b"second attachment".to_vec();
        add_attachment(&src, &src_id, b"id_rsa.txt", &plain_a);
        add_attachment(&src, &src_id, b"notes.md", &plain_b);

        let new_id = copy_item(&src, &src_id, &dst).unwrap();

        // 目标库侧逐字节读回一致（dst key 解封成功 = 换绑成立）
        let guard = dst.unlocked().unwrap();
        let state = guard.as_ref().unwrap();
        let repos = state.store.repos();
        let metas = repos.attachments.list_for_item(&new_id).unwrap();
        assert_eq!(metas.len(), 2, "两个附件都应复制到目标库");
        assert_eq!(metas[0].filename, "id_rsa.txt");
        assert_eq!(metas[1].filename, "notes.md");
        let got_a = repos
            .attachments
            .read_content(&metas[0].uuid, dst.vault_dir())
            .unwrap();
        let got_b = repos
            .attachments
            .read_content(&metas[1].uuid, dst.vault_dir())
            .unwrap();
        assert_eq!(got_a, plain_a, "附件内容必须逐字节一致");
        assert_eq!(got_b, plain_b);

        // 文件确实落在目标库 vault_dir/attachments/ 下（新附件行 uuid 命名）
        for meta in &metas {
            let path = dst.vault_dir().join("attachments").join(&meta.uuid);
            assert!(path.is_file(), "目标库缺少旁路文件 {}", path.display());
        }
        // guard / repos 留待作用域结束自然释放（Repos 非 Drop，无需显式 drop）

        // 源库附件不动：源库侧逐字节读回一致
        let guard = src.unlocked().unwrap();
        let state = guard.as_ref().unwrap();
        let repos = state.store.repos();
        let src_metas = repos.attachments.list_for_item(&src_id).unwrap();
        assert_eq!(src_metas.len(), 2);
        assert_eq!(
            repos
                .attachments
                .read_content(&src_metas[0].uuid, src.vault_dir())
                .unwrap(),
            plain_a
        );
    }

    // ------------------------------------------------------------ 判据 ⑧

    /// 判据 ⑧（注入一）：目标库 `attachments/` 路径被同名常规文件阻塞 →
    /// `AttachmentRepo::add` 落盘失败 → 整个 dst 事务回滚，目标库零残留
    /// （无条目、无从表行、无附件行），且错误收尾的孤儿清理不出错。
    ///
    /// 可移植注入：不依赖平台权限位，用「目录路径被文件占用」这一
    /// 跨平台确定的 IO 失败形态。
    #[test]
    fn 附件落盘失败_目标库事务回滚零残留() {
        let base = crate::tests_support::temp_dir("xcopy_inject_file");
        let src = unlocked_vault(&base, "注入源库");
        let dst = unlocked_vault(&base, "注入目标库");

        let src_id = src.create_item(&rich_draft("注入条目")).unwrap();
        add_attachment(&src, &src_id, b"blocker.bin", b"data");

        // 目标库 attachments 路径预置为常规文件 → create_dir_all 必败
        std::fs::write(dst.vault_dir().join("attachments"), b"not a dir").unwrap();

        let err = copy_item(&src, &src_id, &dst).unwrap_err();
        assert_eq!(err.code(), 5001, "文件系统失败应报 Io(5001)：{err:?}");

        // 零残留：无条目、无附件行
        assert_eq!(dst.list_items(None).unwrap().len(), 0);
        let guard = dst.unlocked().unwrap();
        let state = guard.as_ref().unwrap();
        let n: i64 = state
            .store
            .connection()
            .query_row("SELECT COUNT(*) FROM attachments", [], |r| r.get(0))
            .unwrap();
        assert_eq!(n, 0, "回滚后目标库不得残留附件行");
        let items: i64 = state
            .store
            .connection()
            .query_row("SELECT COUNT(*) FROM items", [], |r| r.get(0))
            .unwrap();
        assert_eq!(items, 0, "回滚后目标库不得残留条目行");

        // 孤儿清理收尾已执行且不掩盖主错误：attachments 仍是被文件占用
        // 的形态（本次注入下本就没有文件落盘），后续手动清理不受影响
        drop(guard);
        assert!(dst.vault_dir().join("attachments").is_file());

        // 复现对照：解除阻塞后同一复制可成功（失败不留下脏状态）
        std::fs::remove_file(dst.vault_dir().join("attachments")).unwrap();
        copy_item(&src, &src_id, &dst).unwrap();
        assert_eq!(dst.list_items(None).unwrap().len(), 1);
    }

    /// 判据 ⑧（注入二）：真实孤儿——第一个附件「文件 + 行」写成功后，
    /// 第二个附件行 INSERT 被 SQLite 触发器 RAISE(ABORT) 注入失败 →
    /// 整个事务回滚（附件行全消失），但两个旁路文件已落盘成为孤儿 →
    /// 错误收尾的 [`cf_store::AttachmentRepo::cleanup_orphans`] 必须把
    /// 它们清干净（v0.3 LOW-2 非导入路径清理时机的落点验证）。
    #[test]
    fn 附件写入失败_回滚孤儿文件被收尾清理() {
        let base = crate::tests_support::temp_dir("xcopy_orphan");
        let src = unlocked_vault(&base, "孤儿源库");
        let dst = unlocked_vault(&base, "孤儿目标库");

        let src_id = src.create_item(&rich_draft("孤儿条目")).unwrap();
        add_attachment(&src, &src_id, b"one.bin", b"first attachment");
        add_attachment(&src, &src_id, b"two.bin", b"second attachment");

        // 注入：目标库 attachments 表在已有 ≥1 行时拒绝再 INSERT
        // （第二个附件在文件落定后于行写入处失败 → 真实孤儿形态）
        {
            let guard = dst.unlocked().unwrap();
            let state = guard.as_ref().unwrap();
            state
                .store
                .connection()
                .execute_batch(
                    "CREATE TRIGGER fail_second_attachment
                     BEFORE INSERT ON attachments
                     WHEN (SELECT COUNT(*) FROM attachments) >= 1
                     BEGIN
                         SELECT RAISE(ABORT, 'injected failure');
                     END;",
                )
                .unwrap();
        }

        let err = copy_item(&src, &src_id, &dst).unwrap_err();
        assert!(err.code() != 0, "注入失败必须向上传播：{err:?}");

        // 事务回滚：附件行 / 条目行全消失
        {
            let guard = dst.unlocked().unwrap();
            let state = guard.as_ref().unwrap();
            let atts: i64 = state
                .store
                .connection()
                .query_row("SELECT COUNT(*) FROM attachments", [], |r| r.get(0))
                .unwrap();
            assert_eq!(atts, 0, "回滚后不得残留附件行");
        }
        assert_eq!(dst.list_items(None).unwrap().len(), 0);

        // 孤儿清理：错误收尾必须清空已落盘的旁路文件
        let dir = dst.vault_dir().join("attachments");
        assert!(dir.is_dir(), "附件目录应已建立（第一个附件落盘过）");
        let leftover: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .filter_map(Result::ok)
            .collect();
        assert!(
            leftover.is_empty(),
            "回滚孤儿必须被 cleanup_orphans 清理，残留：{:?}",
            leftover.iter().map(|e| e.file_name()).collect::<Vec<_>>()
        );
    }

    // ------------------------------------------------------------ 判据 ⑩

    /// 判据 ⑩：validate 失败（超长标题，`MAX_TITLE_CHARS` 真实上限）
    /// → 目标库零写入。构造方式：源库经仓库层 `update_title` 直写
    /// （该路径不校验，模拟旧版本 / 损坏数据形态），跨库复制必须在
    /// validate 处拒绝且目标库零写入。
    #[test]
    fn 校验失败超长标题_目标库零写入() {
        let base = crate::tests_support::temp_dir("xcopy_validate");
        let src = unlocked_vault(&base, "校验源库");
        let dst = unlocked_vault(&base, "校验目标库");

        let src_id = src.create_item(&rich_draft("待校验条目")).unwrap();

        // 仓库层直写超长标题（绕过 validate_item 的合法写路径）
        let overlong: String = "长".repeat(MAX_TITLE_CHARS + 1);
        {
            let mut guard = src.unlocked().unwrap();
            let state = guard.as_mut().unwrap();
            state
                .store
                .with_tx(|repos| {
                    repos
                        .items
                        .update_title(&src_id, &cf_domain::secret::SecretString::from_exposed(overlong))
                })
                .unwrap();
        }

        let err = copy_item(&src, &src_id, &dst).unwrap_err();
        assert_eq!(err.code(), 5002, "超长标题应报 InvalidArgument：{err:?}");

        // dst 零写入
        assert_eq!(dst.list_items(None).unwrap().len(), 0);
        // 源条目零改动（原样保留超长标题）
        assert_eq!(
            src.get_item(&src_id).unwrap().unwrap().title.expose().chars().count(),
            MAX_TITLE_CHARS + 1
        );
    }
}
