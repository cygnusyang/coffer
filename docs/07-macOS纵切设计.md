# Coffer macOS 纵切设计（v0.1）

| 项 | 内容 |
| --- | --- |
| 文档编号 | LV-SLICE-007 |
| 版本 | v0.1 |
| 状态 | 评审中 |
| 创建日期 | 2026-09-27 |
| 上游文档 | `01-需求分析.md`、`02-概要设计.md`、`03-详细设计.md`、`04-系统设计.md`、`06-开发计划.md` |
| 定位 | **增量设计**：重排 M1 剩余工作为「最短路径交付可日常使用的 macOS App」，不推翻既有设计决策 |

---

## 0. 背景与目标

决策已定（本文档的前提，不再论证）：

1. **纵切优先**：跳过「M1 拟真 CLI → M2 全量导入器 → M3 macOS」的横向顺序，直接切一条竖直能力线：**建库 → 解锁 → 条目 CRUD → 搜索 → 复制密码/TOTP → 自动锁定 → CSV 导入**，交付 macOS v0.1。
2. **CSV 导入保底**：第一版数据迁移只做 CSV（RFC 4180），1PUX 等真实样本校准后再做。
3. 技术栈不变：Rust workspace（11 crate）、macOS 14+ Apple Silicon、SwiftUI、UniFFI（`uniffi 0.32.2`，proc-macro 模式）。
4. 存储路线不变：**rusqlite (bundled) + 字段级 AEAD**，不引入 SQLCipher（理由见 §6.3）。

基线现状（提交 `7ccf35b`，157 测试全绿）：cf-crypto / cf-totp / cf-domain（22 类模型）/ cf-format（容器主体）可用；cf-session 只有 TOTP 门禁骨架、**无真实解锁流**；cf-store 只有 `totp_secrets` 单表、**无条目主表与事务**；cf-ffi / cf-importer 为空占位；macOS 工程未开始。

---

## 1. 纵切范围定义

### 1.1 v0.1 做什么

| 能力 | 说明 | 覆盖需求 |
| --- | --- | --- |
| 建库 | 目录形态工作库（`header.json` + `db.sqlite`），主密码创建，zxcvbn 强度门禁（score < 3 拒绝） | FR-1.1 / FR-1.3 |
| 解锁 / 锁定 | 主密码 → Argon2id → DEK 解封 → verifier 校验；锁定清零内存密钥；错误码 1002 合并（不区分密码错/损坏） | FR-1.4 / FR-1.7 |
| 自动锁定 | 空闲超时 + 系统锁屏/休眠/屏保触发；Rust 侧纯函数判定，Swift 侧驱动 | FR-1.6 / FR-12.1 |
| 条目 CRUD | 4 类模板全功能 + Custom 兜底（见 §1.3）；软删（回收站）+ 恢复 + 收藏 | FR-2.1（子集）/ FR-2.10 / FR-2.7 / FR-2.8 |
| 搜索 | 标题子串 + 多关键词全命中，全量解密内存搜索（方案 A） | FR-11.1 / FR-11.2 / FR-11.4 |
| 复制 | 复制密码 / 字段值 / TOTP 验证码到剪贴板，30 s 自动清除（TOTP 复制不清除，FR-5.5） | FR-4.6 / FR-4.7 / FR-5.4 |
| TOTP | otpauth URI 粘贴录入（仅 SHA-1）、验证码实时显示 | FR-5.1（SHA-1）/ FR-5.3 / FR-5.4 |
| CSV 导入 | 1Password 9 列 CSV，预检 → 确认 → 单事务导入 | FR-7.2 / FR-7.4（最小形态） |
| 密码生成器 | 参数化（长度 8–100、字符集）+ 强度指示 | FR-3.1 / FR-3.2 / FR-3.4 |
| Schema | 一次建齐 docs/03 §3.1 DDL v1 **全部表**（含 attachments/history/passkeys），仓库层只实现子集——格式冻结，后续功能不改表 | — |

### 1.2 v0.1 明确不做（推后清单）

| 推后项 | 版本 | 推后理由 |
| --- | --- | --- |
| Touch ID / 生物识别解锁 | v0.2 | 依赖 Keychain 封装链路（`wrapped_dek_biometric`）与 LocalAuthentication，独立横切面；主密码路径已闭环可用 |
| 菜单栏常驻 + 全局快捷键 | v0.2 | 纯 UX 增强，主窗口流程先行验证数据链路 |
| 1PUX / opvault / KDBX 导入 | v0.2+ | `categoryUuid` 映射表待真实样本校准（M0-③，D-02）；CSV 已覆盖最常见迁移需求 |
| Watchtower 体检（重复/弱 URL/陈旧） | v0.2 | zxcvbn 强度已在创建/编辑时复用；批量体检非日常刚需 |
| 拟真 CLI | 推后（可能取消） | 纵切后 macOS App 本身就是端到端验证载体，CLI 的验证价值被取代 |
| 条目历史版本 / 附件 / Passkey / 改主密码 / 多保险库 UI / 明文导出 | v0.2+ | 非日常使用最小集；表结构已建，仓库层后补 |
| SHA-256/512 TOTP | 保持现状 | cf-session 显式拒绝（有意推迟，非遗漏） |
| 深度搜索（用户名/URL/备注） | v0.1 仅标题 | docs/03 §3.3 + D-08 建议；性能实测后再开 |

### 1.3 v0.1 条目类型清单（建议）

| 类别 | v0.1 能力 | 说明 |
| --- | --- | --- |
| **Login** | 完整 CRUD | 最高频：用户名、密码、URL、TOTP、备注 |
| **Password** | 完整 CRUD | 纯密码条目 |
| **Secure Note** | 完整 CRUD | 多行备注 |
| **Credit Card** | 完整 CRUD | 卡号（Concealed）、有效期、CVV |
| **其余 18 类 + Custom** | 只读展示（导入兜底） | CSV 导入本就只产 Login 类数据；其余类别由 1PUX（v0.2）引入，`cf-domain` 模型已备好，届时只加模板 UI |

---

## 2. 模块设计

### 2.1 cf-store：表与事务框架

**Schema（对齐 docs/03 §3.1，缺口与修正见 §5 冲突清单 C-2/C-4）**：

- 新增 `schema.rs`：一次性执行 §3.1 完整 DDL（meta / items / sections / fields / urls / tags / attachments / history / audit_local / totp / passkeys + 全部索引），PRAGMA 按 DDL 头注释（WAL、synchronous=FULL、foreign_keys=ON、page_size=4096），并写 `meta.schema_version = 1`。
- **attachments / history / passkeys 三表只建不用**：格式一次性冻结为 v1，避免 v0.2 加表触发 schema 迁移（当前迁移执行体为空，`migrate()` 恒不支持——现在多建表是最便宜的"迁移"）。

**仓库层（新增 `repo/` 模块）**：

| 文件 | 职责 |
| --- | --- |
| `repo/item.rs` | items 表 CRUD：insert / update（含 state 迁移）/ get / list（分页、按 state+category 过滤）/ soft_delete / restore / set_favorite。`enc_title` 用 `item_key` 加解密，AAD = `build_field_aad(item_uuid, "enc_title")`（复用 cf-crypto 现有函数） |
| `repo/field.rs` | fields 表：按 item 批量替换写入（update 语义 = 删旧插新，天然覆盖字段增删改）、按 item 读出 |
| `repo/url.rs` / `repo/tag.rs` | urls / tags 表：同上批量替换模式 |
| `repo/meta.rs` | meta 表键值读写（`item_count`、`schema_version` 等） |
| `repo/totp.rs` | 现有 `TotpStore` 迁入并改造：`field_key` 改由会话注入的 `SubKeys.field_key` 提供；`issuer/account` 对齐 DDL 改为 `enc_issuer`/`enc_account` 加密列（见冲突 C-2） |

**事务框架（新增 `tx.rs`）**：

```rust
/// 单事务内执行写入闭包；闭包返回 Err 时 ROLLBACK 并向上传播。
/// 成功后维护 meta.item_count 增量（防删除检测的 record_count/root_mac 推后，见 C-4）。
pub fn with_tx<T>(conn: &mut Connection, f: impl FnOnce(&Transaction) -> CfStoreResult<T>)
    -> CfStoreResult<T>;
```

- 条目写入（create/update/delete）与 CSV 导入都必须走 `with_tx`，满足 NFR-REL-01。
- `CfStoreError` 增补 `Validation(String)` 与 `ItemNotFound` 变体；错误码映射统一到 `cf-domain::CfError`（冲突 C-6）。

### 2.2 cf-session：真实解锁流

数据流（对齐 docs/02 §6.1 与 docs/03 §2.2–2.6）：

```
create_vault(dir, name, password):
  password NFC 归一化（cf-crypto::normalize_password）
  → zxcvbn 强度门禁（score < 3 → CfError::WeakPassword，新增错误码 1010）
  → DEK = SessionKey::random()；salt = random_salt()
  → KEK = derive_key(password, salt, KdfParams 默认档位)
  → wrapped_dek = seal(KEK, aad=vault_uuid_bytes‖b"wrapped_dek", DEK)
  → verifier = seal(KEK, aad=vault_uuid_bytes‖b"verifier", 固定常量)   # §2.6
  → cf-format::write_header + cf-store::schema::init(db.sqlite)
  → 返回 VaultBrief

unlock(password):
  cf-format::open_container(dir)                      # 版本三态（已实现）
  → normalize_password(password)
  → KEK = derive_key(password, salt, header.kdf)      # Argon2id，0.5–1.0s
  → DEK = open(KEK, aad=vault_uuid‖"wrapped_dek", wrapped_dek)
        或 open(KEK, aad=vault_uuid‖"verifier", verifier)   # 任一失败 → UnlockFailed(1002)
  → SubKeys::derive(&dek, vault_uuid_bytes)           # HKDF 7 子密钥（已实现）
  → Connection::open(db.sqlite) + 附加只读校验（schema_version）
  → password 明文在此 drop（zeroize）；Session 只持有 SubKeys
```

**新增/修改结构**：

- `vault.rs`：`VaultSession`——docs/03 §11.1 `Session` 的落地版：

```rust
pub struct VaultSession {
    vault_dir: PathBuf,
    vault_uuid: VaultId,
    state: Mutex<Option<UnlockedState>>,   // 锁定时为 None
    last_activity: AtomicI64,
    idle_timeout_secs: AtomicI64,
}
struct UnlockedState {
    subkeys: SubKeys,          // 全部 ZeroizeOnDrop（已有）
    store: ItemStore,          // cf-store 仓库集合，持 conn + 各子密钥
}
impl Drop — UnlockedState 释放即清零；store 内明文缓存无（见搜索缓存决策）
```

- `unlock.rs`：`create_vault` / `unlock` / `lock` 编排（如上数据流）。
- `idle.rs`：`set_last_activity(ts)`、`is_expired(now, timeout)` 纯函数（时间注入，平台侧定时器驱动，docs/03 §11.2 决策对齐）。
- `usecase/items.rs`：CRUD 编排——`cf-domain::validate_item` 前置校验 → `with_tx` 写库；update 前读旧快照（为 v0.2 history 预留接口，v0.1 不写 history 表）。
- `usecase/search.rs`：方案 A 内存搜索（docs/03 §3.3 伪代码）。**v0.1 不做常驻明文缓存**（autofill_cache 类似物）——每次搜索现解密（1000 条 ≈ 数毫秒级），锁定即无需清理，牺牲微小性能换内存清零边界的简单。
- `lib.rs`：`SessionError` 迁移到 `cf_domain::CfError`（见 C-6）；现有 TotpSession/TOTP 编排保留，改从 `VaultSession` 取 `field_key`。

**内存清零边界（明确声明）**：

| 位置 | 策略 |
| --- | --- |
| 主密码 | unlock/create 函数内 `Zeroizing`/显式 zeroize，返回前清零 |
| DEK / 子密钥 | `SessionKey` / `SubKeys` 已 ZeroizeOnDrop；`lock()` 置 `state = None` 触发 drop |
| 条目明文（Rust 内） | 每次查询临时解密，随返回值生命周期结束；不常驻缓存 |
| 跨 FFI | 明文以 `String` 传给 Swift **不可避免**（docs/03 §11.3 已声明）；Rust 侧只保证「一次一个字段、用完即弃」 |
| Swift 侧 | `String` 值类型不可清零——见 §4.2 暴露面控制 |

### 2.3 cf-ffi：UniFFI 接口清单

**关键决策点**：

| 决策 | 结论 | 理由 |
| --- | --- | --- |
| 绑定模式 | proc-macro（`#[uniffi::export]`），不用 UDL | 0.32 推荐，类型定义即接口定义，无两处维护 |
| 同步 vs 异步 | **全部同步**，Swift 侧用 `Task.detached` 包裹耗时调用 | UniFFI async 的 Swift 生成代码在 0.3x 存在 Sendable/并发注解兼容坑（§6.1 风险 R-3）；v0.1 只有 unlock/导入两个慢调用，手工包 Task 成本更低且可控 |
| 会话对象生命周期 | `VaultSession` 为 `#[uniffi::export(Object)]`（Rust `Arc<VaultSession>`）；**新增 `CofferApp` 工厂 Object** 持有 `Mutex<HashMap<uuid, Arc<VaultSession>>>` | Swift 只持 Arc 引用计数，不管理生命周期；重复 `open_vault` 同一 uuid 返回同一实例，避免双会话并发写库；`lock_all()` 供 Swift 侧系统事件批量锁定 |
| 密钥暴露面 | **DEK / SubKeys 永不跨 FFI**（类型不出现在任何接口签名中）；跨 FFI 只有条目明文字段 | 会话门禁 + 加解密全部在 Rust 侧强制（docs/02 §4.3） |
| 错误映射 | cf-ffi 自持 `FfiError` enum（`#[derive(uniffi::Error)]`，带 `code: u16` + `message`），从 `cf_domain::CfError` 的错误码表（docs/03 §12）映射 | thiserror 类型不跨 FFI；UI 按 code 本地化，不解析 message 文本 |
| 平台回调 | v0.1 **无** callback interface | 无生物识别（不回调）；剪贴板归 Swift（C-5）；CSV 导入量级小无进度条需求。`PlatformHost` 整体推后到 v0.2 生物识别时再定 |

**v0.1 接口清单**（docs/03 §5 的子集，命名沿用）：

```
object CofferApp:
  list_vaults(base_dir)              -> Vec<VaultBrief>          # 只读 header.json
  create_vault(base_dir, name, password) -> VaultBrief
  open_vault(base_dir, vault_uuid)   -> Arc<VaultSession>        # 幂等
  lock_all()

object VaultSession:
  # 生命周期
  unlock(password)                   -> VaultInfo
  lock() / is_unlocked() -> bool
  set_last_activity(unix_secs) / auto_lock_if_expired(now_secs) -> bool
  # 条目
  list_items(filter: Option<ItemFilter>)        -> Vec<ItemSummary>
  get_item(item_id)                             -> ItemDetails
  create_item(draft: ItemDraft)                 -> String   # 返回 item_id
  update_item(item_id, draft)                   -> ()
  delete_item(item_id, hard: bool)              -> ()       # hard=false 进回收站
  restore_item(item_id) / set_favorite(item_id, fav: bool)
  search(query)                                 -> Vec<ItemSummary>
  # 取值与 TOTP
  get_field_value(item_id, field_uuid)          -> String   # 密码等敏感值，随取随走
  totp_code(item_id)                            -> TotpCode {code, secs_remaining}
  parse_otpauth_uri(uri)                        -> TotpDraft
  # 生成器
  generate_password(opts: PasswordGenOptions)   -> String
  strength_estimate(candidate)                  -> StrengthEstimate {score, warnings}
  # 导入
  precheck_csv(path)                            -> CsvPrecheckReport
  import_csv(path)                              -> CsvImportResult
```

跨 FFI 数据类型（`types.rs`）：`VaultBrief`、`VaultInfo`、`ItemSummary`、`ItemDetails`、`ItemDraft`/`FieldDraft`/`UrlDraft`（包装 `cf-domain` Draft，敏感值用 `String`）、`ItemFilter {state, category}`、`TotpCode`、`TotpDraft`、`PasswordGenOptions`、`StrengthEstimate`、`CsvPrecheckReport`、`CsvImportResult`、`FfiError`。时间戳统一 **i64 Unix 秒**（规避 UniFFI u64 ↔ Swift UInt 与 Kotlin 无符号坑，docs/02 §5）。

**构建链**（`tools/build_swift_bindings.sh`）：`cargo build -p cf-ffi --release` → `uniffi-bindgen generate --library ... --language swift`（产出 `.swift` + `.h` + `modulemap`）→ 拷入 `macos/Coffer/CoreBindings/`。Xcode 工程以静态库 + 生成源码方式引入。

### 2.4 SwiftUI 壳（概要）

```
macos/Coffer/
├── CofferApp.swift            # @main，窗口场景
├── AppModel.swift             # @MainActor ObservableObject：持 CofferApp 与当前 VaultSession 引用、
│                              #   appPhase(locked/unlocked)、自动锁定定时器驱动
├── Views/
│   ├── VaultSetupView.swift   # 无库时：创建库（名称 + 主密码 + 强度条）
│   ├── LockView.swift         # 解锁界面（错误提示只按 code 1002）
│   ├── ItemListView.swift     # 侧栏（分类筛选）+ 列表 + 搜索框
│   ├── ItemDetailView.swift   # 字段掩码/显示切换、复制按钮、TOTP 倒计时环
│   ├── ItemEditView.swift     # 按 category 模板渲染表单（4 类完整模板）
│   ├── TrashView.swift        # 回收站（软删列表 + 恢复/硬删）
│   └── ImportView.swift       # 选 CSV → 预检报告 → 确认导入 → 结果
└── Platform/
    ├── Clipboard.swift        # NSPasteboard 写入 + changeCount 轮询 30s 清除（TOTP 复制例外）
    └── AutoLockMonitor.swift  # NSWorkspace screenIsLocked/screensDidSleep/屏保 → 立即 lock()；
                               #   CGEventSource.secondsSinceLastEventType 空闲检测 → set_last_activity
```

UI 原则：密码默认掩码；锁屏后 AppModel 清空已取回的明文状态；错误提示按 `FfiError.code` 映射本地文案。非本次重点，不再展开。

---

## 3. CSV 导入设计

### 3.1 解析（cf-importer/csv）

- **RFC 4180**：`""` 转义、引号内换行、`\n` 与 `\r\n` 兼容。选型：**自写解析器**（约 150 行），理由：格式足够简单、可精确施加 DoS 上限、避免 `csv` crate 配置漂移；配 RFC 4180 边界用例测试（含引号内逗号/换行/引号、跨行字段）。
- **DoS 上限**（docs/04 §4.2 D 类威胁）：文件 ≤ 50 MB、行数 ≤ 10 000、单字段 ≤ 64 KiB、列数 ≤ 64；超限报 `ImportFailed` 并指明行号。
- **编码**：v0.1 支持 UTF-8（含 BOM 剥离）；无效 UTF-8 → 报错提示「请将导出文件转为 UTF-8 后重试」。GBK 回退（`encoding_rs`）推后 v0.2（见 C-7）。
- 前导零：全列按字符串处理，禁止数值化。

### 3.2 字段映射（对齐 docs/03 §6.4.4）

| CSV 列（1Password 9 列） | 映射目标 |
| --- | --- |
| Title | `items.enc_title` |
| Website | `urls`（is_primary=1） |
| Username | field(designation=Username) |
| Password | field(designation=Password, type=Concealed) |
| One-time password | `otpauth://` 解析（cf-totp）→ `totp` 表；解析失败的行，原始值并入 Notes 并告警（不丢弃） |
| Favorite status | `items.is_favorite` |
| Archived status | `items.state`（仅接受 true/false） |
| Tags | `tags`（逗号/分号分隔） |
| Notes | field(designation=NotesPlain, type=Multiline) |

- **表头识别**：大小写不敏感匹配上述 9 列名；无法识别的表头 → 整文件拒绝（格式校验），**非空数据列的未知表头** → 记入 `unmapped_columns` 并在预检报告展示（不静默丢弃原则：未知列的值并入该条目 Notes，前缀「[未映射列 <名>]」）。
- 缺失 Title 的行：预检告警，导入时以 `（无标题）` 兜底；全空行跳过。
- **公式注入**：导入侧对以 `= + - @ \t` 开头的 Username/Notes/未映射列值**保留原值存储**（数据完整性优先），在预检 `warnings` 中按行号提示「该字段以公式前缀字符开头，若导出为 CSV 时将被转义」；**防护主战场在导出侧**（v0.2 导出时加 `'` 前缀，docs/03 §6.4.4）。Password 列不告警（密码以 `=` 开头合法且常见，Concealed 不可被表格软件解释为公式以外的攻击面——它本来就是要被复制出去的）。

### 3.3 预检报告（最小形态）

```rust
pub struct CsvPrecheckReport {
    pub total_rows: u32,
    pub valid_rows: u32,
    pub skipped_rows: Vec<u32>,        // 全空行号
    pub rows_without_title: Vec<u32>,
    pub rows_with_bad_totp: Vec<u32>,  // otpauth 解析失败的行号
    pub unmapped_columns: Vec<String>, // 未识别的数据列名
    pub formula_like_cells: Vec<(u32, String)>, // (行号, 列名)
    pub warnings: Vec<String>,
}
```

流程：`precheck_csv`（只读、可反复调用）→ UI 展示 → 用户确认 → `import_csv`：**单事务**全部写入（`with_tx`），任一行入库失败 ROLLBACK，已有数据零影响（NFR-REL-04）。v0.1 固定「全部新建（UUIDv7）」策略——CSV 无 uuid，无冲突语义，docs/03 §6.6 的 ConflictPolicy 推后到 1PUX 导入。UI 强制提示：CSV 不含安全问题、自定义字段、附件；导入完成后删除源 CSV（明文密码文件）。

---

## 4. 安全要点汇总

### 4.1 Rust 侧（继承既有纪律）

- 错误码 1002 合并 UnlockFailed；错误信息不泄露降低攻击成本的线索（docs/04 §4.2）：`CorruptData`/`Crypto` 类错误的 message 不得包含密钥派生进度、密文长度等细节。
- 全链路 zeroize 边界见 §2.2；`panic` hook 过滤敏感值。
- 剪贴板清除逻辑在 Swift 侧：默认 30 s，TOTP 复制不清除（FR-5.5）。

### 4.2 Swift 侧明文暴露面控制（诚实声明）

Swift `String` 不可清零、`NSArray`/值类型复制语义无法保证擦除。v0.1 策略是**缩短暴露时间与范围**而非宣称不存在（docs/03 §11.3）：

1. 明文只在取值那一刻跨越 FFI（`get_field_value` / `totp_code`），ItemDetails 结构体中 Password 字段只回掩码占位（如 `""`），真实值单独按需取。
2. 取回即用（写剪贴板/临时展示），不进 AppModel 状态、不进 SwiftUI 环境对象持久化。
3. Keychain（v0.2 生物识别用）一律 `ThisDeviceOnly`；库文件允许系统备份，密钥材料绝不跨设备（既有约束，重申）。

---

## 5. 文档与现状冲突清单

| # | 冲突 | 现状证据 | 处理建议 |
| --- | --- | --- | --- |
| C-1 | `macos/README.md` 写「计划 **M5** 阶段」，与概要设计 v1.2 / 开发计划的「macOS 优先（M3）」矛盾 | `macos/README.md` 首行 | 更新 README 状态段（纵切交付时一并改） |
| C-2 | docs/03 §3.1 DDL 的 `totp` 表用 `enc_issuer`/`enc_account`（加密），现有 `TotpStore` 实现为明文 `issuer`/`account` TEXT；且实现多了 `created_at` 列（DDL 没有） | `core/cf-store/src/lib.rs` vs `docs/03` L424-434 | **以 DDL 为准**：v0.1 重构 `repo/totp.rs` 时改加密列；DDL 补 `created_at` 列（回改 docs/03，升 DDL v1 冻结前完成） |
| C-3 | docs/02 §4.2 仍描述 `vault.lvvault` 为单 SQLite 文件，已被 docs/03 修正 A（目录形态）取代，02 未回改，且 `cf-format` 按目录实现 | `docs/02` §4.2 vs `cf-format/container.rs` | 在 docs/02 加一行指向修正 A 的标注（低优先） |
| C-4 | meta 表的 `record_count` + `root_mac` 防删除/防回滚校验（docs/03 §3.1、docs/02 §8.2）现状无实现 | `cf-store` 无 meta 逻辑 | v0.1：建表含字段但只维护 `item_count`；`root_mac` 每事务重算全量 HMAC 成本高且解锁时校验语义未定，**推后 v0.2**，诚实告知（与 §8.2「无法绝对防回滚」一致） |
| C-5 | docs/03 §5.5 `PlatformHost.copy_to_clipboard` 回调与 docs/02 §2.3 职责矩阵「macOS 层：剪贴板」矛盾 | 03 §5.5 vs 02 §2.3 | **剪贴板归 Swift 层**（changeCount 轮询清除必须走 AppKit，Rust 做不了）；从 §5.5 删除该回调或标注仅 Android 用 |
| C-6 | docs/03 §4.4 错误契约要求统一 `CfError`（含错误码表 §12），但 cf-store/cf-session 现状各自持私有错误类型（注释自称「待 cf-domain 落地后统一」） | `cf-store/src/lib.rs` L38-54、`cf-session/src/lib.rs` L26-49 | cf-domain 已落地，v0.1 必须完成迁移（FFI 错误映射依赖统一错误码），纳入 T01 |
| C-7 | docs/03 §6.4.4 要求 CSV「无 BOM 则 UTF-8 失败回退 GBK」；GBK 解码需 `encoding_rs`（新增依赖） | docs/03 L1018 | v0.1 仅 UTF-8（BOM 剥离），GBK 回退随 v0.2 一并做；`encoding_rs` 为 MIT/Apache，许可无障碍 |
| C-8 | workspace `[profile.release] panic = "abort"` 与 UniFFI 的 panic→FFI 错误转换机制冲突：UniFFI 依赖 unwind 捕获 Rust panic 转为抛给 Swift 的错误，panic=abort 会让任何 Rust panic 直接杀死整个 App | `core/Cargo.toml` L120 | cf-ffi 的发布构建改为可 unwind（`[profile.release.package.cf-ffi]` 不可行，需改用自定义 profile 或将 panic 策略放宽为 `panic = "unwind"` + FFI 层 `catch_unwind` 兜底）；**在 T04 第一周验证** |
| C-9 | docs/06 §9「近期工作重点」仍是「M1 收尾 → 拟真 CLI → M2 → M3」横向顺序，与纵切决策冲突 | `docs/06` §9 | 纵切方案批准后更新 docs/06（本设计为准，06 只记进度） |

---

## 6. 风险与待明确事项

### 6.1 UniFFI / Swift 侧已知坑

| # | 风险 | 缓解 |
| --- | --- | --- |
| R-1 | **绑定版本漂移**：生成的 Swift 绑定与 Rust 侧 uniffi runtime 版本强耦合，混用版本导致 protocol 不匹配/链接失败 | 绑定只由 `tools/build_swift_bindings.sh` 统一生成，脚本头部断言 `uniffi` 版本；CoreBindings 目录 .gitignore 生成物还是入库？——**建议入库**并锁定版本，避免工程师环境差异 |
| R-2 | **panic=abort**（见 C-8） | T04 首项验证；短期可在 FFI 边界 `catch_unwind` 包装 + 避免 panic（现有 crate 已禁 unwrap/expect，风险面小） |
| R-3 | UniFFI async 的 Swift 并发注解兼容性（0.3x 系列多次改动 Sendable 标注） | 本设计全同步接口，绕开；v0.2 若引入 async 需重新评估 |
| R-4 | Object 类型（`Arc<VaultSession>`）在 Swift 侧被提前释放导致 DEK drop | `CofferApp` 注册表持强引用，App 退出时统一 `lock_all()`；Session 释放即密钥清零，不存在悬垂密钥 |
| R-5 | 静态库 + modulemap 引入 Xcode 的签名/搜索路径问题（首次搭建最常见卡点） | T04 用最小 Demo（一个 `add(a,b)` 函数）先打通端到端构建再上真实接口（即 M0-① 的补课） |
| R-6 | `uniffi-bindgen` 生成代码依赖 Swift 5.7+ 特性，Xcode 版本差异 | 锁定 Xcode 15+（macOS 14 SDK 本就要求） |

### 6.2 待明确事项（开工前需主理人拍板）

| # | 事项 | 建议 |
| --- | --- | --- |
| Q-1 | Argon2id 创建库时的默认 KdfParams 档位（docs/05 只做了开发机摸底，M 系入门机实测 M0-② 未做） | 沿用 docs/05 开发机档位为 v0.1 默认，参数写进 header 可后调；创建界面给出「解锁约需 x 秒」提示 |
| Q-2 | v0.1 是否允许打开多库（架构天然支持，UI 是否做库切换） | 架构支持、UI 只做单库（最近创建/最近打开的一个），`list_vaults` 接口保留 |
| Q-3 | CSV 导入的「全部新建」策略是否需要 UI 上的去重提示（同名 Title） | 仅预检 warnings 提示重名计数，不做逐条询问（Ask 策略推后） |

### 6.3 SQLCipher 路线确认

**确认沿用 rusqlite (bundled) + 字段级 AEAD，不换 SQLCipher。** 理由：① 字段级方案已实现且有 AAD 防搬运测试覆盖；② 威胁模型与元数据泄露清单（docs/03 §3.5）按字段级声明，换 SQLCipher 需重写威胁模型且引入额外构建链；③ 纵切目标是交付，不中途换加密路线。SQLCipher 仅在「元数据泄露被证明不可接受」时作为 v2 备选重新评估。

---

## 7. 任务列表（按实现顺序）

| ID | 任务 | 主要文件 | 依赖 | 优先级 | 验收标准（可测试） |
| --- | --- | --- | --- | --- | --- |
| **T01** | **cf-store 存储引擎 + 错误统一** | `core/cf-store/src/{schema.rs,tx.rs,error.rs,lib.rs}`、`repo/{item.rs,field.rs,url.rs,tag.rs,meta.rs,totp.rs}`、`core/cf-domain/src/error.rs`（补 1010 WeakPassword 等）、`docs/03-详细设计.md`（DDL 补 created_at，回 C-2） | 无 | P0 | ① schema.rs 一键建齐 §3.1 全部 11 表 + 索引，重复执行幂等，`schema_version=1` 写入 meta；② items/fields/urls/tags 仓库 CRUD 往返测试通过；③ enc_title 密文落盘断言（BLOB ≠ 明文）+ 密文跨行搬运解密失败断言（沿 TotpStore 测试模式）；④ with_tx 内注入失败 → 全部回滚（行数不变）；⑤ cf-store/cf-session 错误类型迁移到 `cf_domain::CfError`，`cargo test --workspace` 全绿、clippy 零警告；⑥ 既有 157 测试不回归 |
| **T02** | **cf-session 解锁流 + CRUD/搜索编排 + 生成器参数化** | `core/cf-session/src/{vault.rs,unlock.rs,idle.rs,lib.rs}`、`usecase/{items.rs,search.rs}`、`core/cf-audit/src/lib.rs`（generate_password 参数化） | T01 | P0 | ① create_vault→lock→unlock 往返：正确密码解锁成功、错误密码/篡改 wrapped_dek/篡改 verifier 三者返回**同一**错误码 1002；② lock() 后 require_unlocked 拒绝且内存中 SubKeys drop（可用 mimalloc 外断言或 Drop 观测测试）；③ NFC 归一化：合成主密码两种 Unicode 形式均可解锁；④ ItemDraft 校验失败（cf-domain::validate_item）→ 拒绝且不落库；⑤ CRUD 编排集成测试（临时目录真文件库）；⑥ 搜索：子串命中、多关键词全命中、1000 条模拟 ≤200ms 基线记录；⑦ idle 纯函数边界测试；⑧ zxcvbn score<3 拒绝建库 |
| **T03** | **cf-importer CSV 导入** | `core/cf-importer/src/{csv/parser.rs,csv/mapping.rs,precheck.rs,lib.rs}`、`core/cf-session/src/usecase/import_csv.rs`、`tests/fixtures/csv/*.csv`（边界样本：BOM、引号内换行、公式前缀、坏 otpauth、未知列、GBK 误投） | T01（T02 后集成） | P0 | ① RFC 4180 全边界解析测试（引号转义/内嵌换行/CRLF）；② 超限 DoS 用例（10k+ 行、64KiB 字段）被拒并报行号；③ 9 列映射往返：CSV → ImportModel → 写库 → 读回逐字段相等；④ 公式前缀值原样入库 + warnings 命中；⑤ 坏 otpauth 行不丢数据（并入 Notes）+ 预检行号准确；⑥ 未知列并入 Notes + unmapped_columns 列出；⑦ 导入中途注入失败 → 库零变化（事务回滚）；⑧ 无效 UTF-8 文件被拒 |
| **T04** | **cf-ffi UniFFI 绑定 + Swift 构建链** | `core/cf-ffi/src/{lib.rs,api.rs,types.rs,error.rs}`、`core/cf-ffi/Cargo.toml`、`tools/build_swift_bindings.sh`、`core/Cargo.toml`（panic 策略调整，回 C-8） | T02、T03 | P0 | ① 最小 Demo（`add(a,b)`）经 `build_swift_bindings.sh` 生成 Swift 绑定并在 Xcode 命令行测试 target 调用成功（M0-① 补课）；② §2.3 全部接口跨 FFI 冒烟：Rust 单元测试 + Swift 侧一条端到端测试（建临时库→解锁→建条目→搜索→取密码）；③ 错误映射：锁定态调 get_field_value → Swift 捕获 code=1001；密码错误 → code=1002；④ Rust panic（注入测试）不杀死进程，转为 FFI 错误；⑤ `list_vaults`/`open_vault` 幂等：同 uuid 两次 open 返回同一会话（is_unlocked 状态共享） |
| **T05** | **macOS SwiftUI 壳 + 端到端闭环** | `macos/Coffer.xcodeproj`、`macos/Coffer/{CofferApp.swift,AppModel.swift,Info.plist,Coffer.entitlements}`、`Views/{VaultSetupView,LockView,ItemListView,ItemDetailView,ItemEditView,TrashView,ImportView}.swift`、`Platform/{Clipboard,AutoLockMonitor}.swift`、`macos/README.md`（状态更新，回 C-1） | T04 | P0 | ① 手工验收脚本走通全流程：创建库（弱密码被拒）→ 锁定 → 解锁 → 新建 Login（含 otpauth URI）→ 搜索命中 → 复制密码 30s 后剪贴板为空（changeCount 断言）→ 复制 TOTP 不清除 → 编辑 → 回收站 → 恢复 → 硬删；② 导入 tests/fixtures/csv 样本后条目数与预检一致；③ 系统锁屏/休眠触发立即锁定（NSWorkspace 通知手工验证）；④ 空闲超时自动锁定（超时可配置，默认 5 分钟）；⑤ entitlements 不含 network.*（代码评审 + `codesign -d` 核查）；⑥ 密码默认掩码、错误文案按 code 映射 |

依赖链：T01 → T02 → T04；T01 → T03 → T04；T04 → T05。T02 与 T03 可并行。

---

## 8. 交付后回填

- 更新 `docs/06-开发计划.md`：里程碑重排为纵切结构（回 C-9）、§5/§6 状态矩阵刷新；
- `docs/03-详细设计.md`：DDL 补 `totp.created_at`（C-2）、§5.5 回调修正（C-5）、§6.4.4 标注 GBK 推后（C-7）；
- `core/M1_IMPLEMENTATION_PLAN.md` 标注被纵切取代的条目。

*文档结束。*
