# 24-opvault 布局交叉验证报告（D-04 前置验收）

> 状态：**D-04 闭环**（T02 实现前置调研结论）
> 调研日期：2026-10-04
> 依据时效：官方设计文档（support.1password.com/opvault-design/，2026 版页面）+ 5 个第三方独立实现 + 1 个真实样本端到端解密实证（本调研已跑通）
> 定位：对 `docs/22` §2.2.1 与 `docs/03` §6.3 的 opvault 布局假设做逐字节交叉验证。**结论先行：两个关键假设需修正**（opdata 布局、目录结构），其余密码学链大体与设计一致。

---

## 0. 结论先行（推荐方案一句话）

**opdata 对象实际布局为 `[magic "opdata01":8]‖[plaintext_len:8 LE]‖[IV:16]‖[AES-256-CBC ct]‖[HMAC-SHA256:32]`，且 CBC 填充为「前置随机字节」（解密取末 plen 字节）而非 PKCS#7；`docs/22` §2.2.1 假设的 `[IV:16]‖[ct]‖[MAC:32]` 仅对条目 `k` 字段（item keys 块，无 header）成立——T02 实现必须按本报告的修正布局落地，否则真实 opvault 全量解密失败。**

目录结构同理修正：opvault **没有** `contents.js`、`data/*.opdata`、`masterkey.js`、独立 `passwordhint.txt`（这些是前身 AgileKeychain 格式的特征）；真实布局为 `profile.js + folders.js + band_0.js~band_F.js + <itemUUID>_<attachUUID>.attachment`。

---

## 1. 布局逐字节结论表（vs docs/22 §2.2 / docs/03 §6.3 假设）

### 1.1 目录结构

```
xxx.opvault/
└── default/                          # profile 目录（以含 profile.js 判定；可多 profile）
    ├── profile.js                    # 前缀 "var profile=" + JSON + 尾分号 ";"；明文
    ├── folders.js                    # 前缀 "loadFolders(" + JSON + ")"；文件夹 overview 加密
    ├── band_0.js … band_F.js         # 前缀 "ld(" + JSON + ");"；条目本体；按 UUID 十六进制首字符分桶
    └── <itemUUID>_<attachUUID>.attachment   # 附件（OPCLDAT 头，条目密钥加密）
```

| 项 | docs/03 §6.3 / docs/22 假设 | 实际（官方文档 + 5 实现 + 真实样本） | 判定 |
| --- | --- | --- | --- |
| 条目承载 | `contents.js`（条目索引）+ `<item_uuid>.js`（每条目一文件） | 16 个 `band_[0-F].js`（按 UUID 首字符分桶）；无 contents.js | **纠正** |
| 文件夹 | （未覆盖） | `folders.js`（`loadFolders(` 前缀） | 补充 |
| 附件 | （未覆盖） | 独立 `.attachment` 文件（`OPCLDAT` 头，条目密钥加密） | 补充（官方已文档化） |
| passwordHint | 独立 `passwordhint.txt`（任务假设） | `profile.js` 内的一个**字段** `passwordHint`，明文存储（官方明确「不混淆」） | **纠正** |
| masterKey | 独立 `masterkey.js`（任务假设） | `profile.js` 内的**字段** `masterKey`（base64 opdata01） | **纠正** |
| profile.js 格式 | 未提前缀 | `var profile={...};`——12 字节前缀 + JSON + 尾分号；解析需剥前缀 | 补充 |
| band 文件格式 | 未提 | `ld({...});`——3 字节前缀 + JSON + `);` | 补充 |

> **来源**：官方文档「Directory layout / Band files / folders.js / profile.js」；实证见 1.5 真实样本（detunized/opvault-ruby `test.opvault`，目录内仅有 profile.js、folders.js、band_3/6/D/E.js）。

### 1.2 opdata01 二进制布局（核心修正）

| 偏移 | 长度 | 内容 | 说明 |
| --- | --- | --- | --- |
| 0 | 8 | `"opdata01"` | 魔数（ASCII） |
| 8 | 8 | plaintext 长度 | uint64 **小端** |
| 16 | 16 | IV | 随机 |
| 32 | 变长 | AES-256-CBC 密文 | 填充见下 |
| 末尾 | 32 | HMAC-SHA256 | 256-bit 不截断，**覆盖 [0 : 末尾-32] 全量**（含 header/长度/IV/密文） |

**CBC 填充（官方明文，非 PKCS#7）**：明文若为块大小的整倍数，则**前置** 1 块（16 字节）随机数据；否则**前置** 1~15 字节随机数据凑整。解密后**取末 `plaintext_len` 字节**即为明文。官方理由：前置填充兼作「附加的 mini-IV」，且规避 PKCS#7 padding-oracle CCA。

| 项 | docs/22 §2.2.1 / docs/03 §6.3 假设 | 实际 | 判定 |
| --- | --- | --- | --- |
| opdata 布局 | `[IV:16]‖[ct]‖[MAC:32]` | `[magic:8]‖[plen:8 LE]‖[IV:16]‖[ct]‖[MAC:32]` | **纠正** |
| CBC 填充 | 未明示（按标准 PKCS#7 推断） | **前置随机字节**，解密取末 plen 字节 | **纠正**（PKCS#7 去除会剥掉明文头） |
| MAC 覆盖 | 未明示 | header+长度+IV+密文全量 | 补充 |
| Encrypt-then-MAC | 是 | 是（先验 MAC 再解密，官方「Verify-and-only-then-Decrypt」） | 一致 |
| HMAC 算法 | HMAC-SHA256 | HMAC-SHA256（256-bit 不截断） | 一致 |
| AES | 256-CBC（非 GCM） | AES-256-CBC（官方「only AES and SHA-2」） | 一致 |

> **特别澄清（对 `k` 字段）**：`[IV:16]‖[ct]‖[MAC:32]` 布局**确实存在于 `k`（加密 item keys）**，但 `k` 不是 opdata01（无 magic/长度头）。两者解码路径不同，T02 需实现两套：`opdata01_decrypt`（d/o/masterKey/overviewKey）与 `item_keys_decrypt`（k）。

### 1.3 密钥派生链（与设计一致，一处澄清）

| 步骤 | docs 假设 | 实际（官方 + 实证） | 判定 |
| --- | --- | --- | --- |
| ① PBKDF2 | HMAC-SHA512；iterations 读 profile；salt=16B | 同：`PBKDF2-HMAC-SHA512(password, salt=profile.salt(16B), iterations=profile.iterations, dkLen=64)` | 一致 |
| 密码编码 | UTF-8 + NUL 结尾 | UTF-8 **原始字节**；「NUL 结尾」只是 CommonCrypto C 字符串表示，**NUL 本身不进 PBKDF2 输入**（5 实现全用原始字节，本调研用 `"password"` 原始字节解密成功） | **澄清**（勿实现为追加 NUL） |
| ② 派生拆分 | 前 256bit 加密钥 / 后 256bit MAC 钥 | 同（`derived[0:32]` / `derived[32:64]`） | 一致 |
| ③ masterKey | 明文 256B 随机 → SHA-512 → 前 32 加密 / 后 32 MAC | 同（实证 256B；SHA-512 劈分） | 一致 |
| ④ overviewKey | 明文 64B 随机 → SHA-512 劈分 | 同（实证 64B） | 一致 |
| ⑤ item keys | {crypto_key:32, mac_key:32} | 同；`k` = `[IV:16]‖[AES-CBC(master_enc, IV) 密文]‖[HMAC-SHA256(master_mac, IV‖ct):32]`，解密后 `[crypto:32]‖[mac:32]`（实证 112B→64B） | 一致 |

### 1.4 条目字段（band 文件内 JSON）

| 字段 | 含义 | 加密 | 判定 |
| --- | --- | --- | --- |
| `category` | 三位十进制分类码（001~111） | 否 | 一致（官方同表，见 §3） |
| `created` / `updated` / `tx` | Unix 时间（ASCII 十进制） | 否 | 补充 |
| `fave` | 收藏排序索引（ASCII 无符号长整，可选） | 否 | 补充 |
| `folder` | 所属文件夹 UUID（可选） | 否 | 补充 |
| `uuid` | 条目 UUID（大写十六进制） | 否 | 补充 |
| `trashed` | `true` 表示归档（可选，默认 false） | 否 | 一致 |
| `k` | 加密 item keys（base64，布局见 1.3⑤） | 是 | 一致 |
| `o` | 加密 overview（base64 opdata01，overview 密钥） | 是 | 一致 |
| `d` | 加密 details（base64 opdata01，**item 密钥**） | 是 | 一致 |
| `hmac` | HMAC-SHA256(overview MAC key)，base64 | — | 见下 |

**`hmac` 字段覆盖范围（官方 + 实证）**：对所有元素按键的**字典序**排序，逐元素 `HMAC(key) ‖ HMAC(value)` 拼接后做 HMAC-SHA256；**排除 `hmac` 自身与 `folder`**（folder 因「改夹时可无 MAC 密钥」而豁免）；`trashed` 布尔在计算时按 **0/1 整数**参与。官方原话：「The MAC is calculated over all the items (in C lexicographic order) except for hmac itself and folder.」

> 实证：对真实样本中**带 folder 的条目**，排除 folder 时 MAC 匹配（incl=False / excl=True）；无 folder 条目两法皆 True。**与官方一致**。

### 1.5 真实样本实证（本调研已跑通）

- 样本：`detunized/opvault-ruby` 仓库 `test.opvault`（MIT，密码 `"password"`，iterations=40000），3 个 Login（facebook.com / google.com / github.com）+ 2 个文件夹。
- 本调研编写 Python 脚本（PBKDF2 → master/overview 密钥 → 条目密钥 → overview/details 全链解密）**全部成功**，逐字节确认：masterKey 明文 256B（272B 密文 = 256B + 16B 前置填充）、overviewKey 明文 64B、`k` 112B→64B、salt 16B。
- 解密出的真实 details（Login 类）：`{"notesPlain":"…","fields":[{"type":"T","name":"username","value":"mark","designation":"username"},{"type":"P","name":"password","value":"secret","designation":"password"}]}`；overview：`{"title":"facebook.com","URLs":[{"u":"http://facebook.com"}],"url":"http://facebook.com","ps":6,"ainfo":"mark"}`。
- 该脚本逻辑与验证结果随本报告提供（`tools/` 侧留档参考，开发期可直接对照）。

---

## 2. 第三方实现对照表

| 实现 | 语言 | 来源 URL | 维护状态 | 布局结论（与本报告一致项） |
| --- | --- | --- | --- | --- |
| miquella/opvault | Go | https://github.com/miquella/opvault | 2016 起，最后提交 2023-03 | opdata01 全布局 ✓；PBKDF2 拆分 ✓；目录=band+folders+profile ✓ |
| evantbyrne/1password-opvault | Go | https://github.com/evantbyrne/1password-opvault | 2024~2026 活跃（导出工具） | opdata01 逐字节同 miquella ✓（跨十年代码一致，佐证布局稳定） |
| carlosmn/opvault-rs | Rust | https://github.com/carlosmn/opvault-rs | 2016 起，最后 2020-08 | opdata01 ✓；分类码同表 ✓；**hmac verify 含 folder、定序非字典序——与官方+实证不符（见 §5 风险）** |
| OblivionCloudControl/opvault | Python | https://github.com/OblivionCloudControl/opvault | 2018 起 | opdata01 ✓；PBKDF2 ✓；field types P/T/E/N/R/TEL/C/U ✓ |
| detunized/opvault-ruby | Ruby | https://github.com/detunized/opvault-ruby | 2017~2022 | opdata01 ✓；**自带真实 test.opvault fixture（本报告实证样本）**；hmac 计算**含 folder**（与官方分歧，但该 fixture 无 folder 条目故未被自身测试暴露） |
| bitemyapp/opvault | Haskell | https://github.com/bitemyapp/opvault | 2019 停更 | 存在（docs/03 §6.3 勘误提及的「声称 GCM/ZIP」文章即围绕此类实现；官方已明确非 GCM，本调研亦确认） |

> 交叉验证结论：5 个实现 + 官方文档在 opdata01 布局、密钥派生、分类码上**完全一致**；分歧仅在 `hmac` 字段覆盖范围（Rust 含 folder、Ruby 含 folder，官方+实证排除 folder）。GCM/ZIP 说法为误传，官方「only AES and SHA-2」+ Encrypt-then-MAC 已多次确认。

---

## 3. 字段类型表初稿（details JSON）

### 3.1 顶层 Login 字段 `type` 码（go-opvault / Python / Rust 三源并集 + 真实样本）

| `type` 码 | 含义 | docs/22 §2.2.3 假设 | 校正后 Coffer 映射 |
| --- | --- | --- | --- |
| `T` | Text | Text → Text | Text |
| `P` | Password | Password → Concealed | Concealed |
| `E` | Email | （未列） | Text（可标 Email） |
| `N` | **Number** | **docs/22 误作「N(Notes)」** | Text（数字字段按字符串） |
| `R` | Radio | （未列） | Text |
| `TEL` | Telephone | **docs/22 误作「B(Phone)」** | Text（可标 Phone） |
| `C` | Checkbox | （未列） | Text/Boolean |
| `U` | URL | URL → Text(URL 行) | Text(URL) |
| `I` / `B`(Button) / `S` | Rust 额外观测 | （未列） | Text 降级 + 报告 |

> **docs/22 §2.2.3 假设的 `N`（Notes）/ `M`（Multiline）/ `D`（Date）/ `B`（Phone）type 码在真实格式中不存在**：`N`=Number、`M`/`D` 未见、电话=`TEL`。多行备注（Multiline/Notes）在 details 中的承载是**顶层 `notesPlain` 键**与 section 字段的 `k=concealed`，不是 `type` 码。T02 的「未映射字段」报告需按真实码表校准，避免把 `N` 误当 Notes 映射到 Multiline。

### 3.2 section 字段 `k`（kind）码（Rust detail.rs + go-opvault SectionField）

`concealed`、`string`、`date`、`monthYear`、`menu`、`cctype`、`gender`、`email`、`phone`、`URL`、`address`（`address` 的 `v` 为嵌套对象 city/zip/state/country/street）。

### 3.3 designation（`designation` 键）

真实样本实证：`username`、`password`。业界实践另见 `totp`/`otp`（docs/22 假设成立）、`notesPlain`（1PUX 侧概念，opvault 的 notes 是顶层 `notesPlain` 键而非 designation 值）。**建议**：designation 按 docs/22 §2.2.3 映射（username/password/totp→对应 Coffer Designation，其余原样保留为 `Designation::Other`），与 `docs/03` §6.4.3 一致。

### 3.4 details 顶层键（Login 类）

实证：`fields[]`、`notesPlain`；Rust 另见 `htmlForm`、`backupKeys`（base64 字节，语义未知）；Generic 类：`sections[]`、`notesPlain`。**docs/22 §2.2.3 已定「解析策略而非硬编码表」+ 未知降级 Text + 报告——本报告支持该策略**；字段码表以真实样本为基线冻结。

### 3.5 overview 结构（解密后）

`title`、`url`、`URLs[]`（`{u:…}`）、`ps`（密码强度）、`ainfo`（账户信息）、`tags[]`、`trashed` 等；Login 的 overview 含 username。overview 由 `o`（overview 密钥）解密，用于列表/搜索。

---

## 4. 合成 fixture 构造路径建议（开发期 RED 测试）

1. **首选（强于合成）**：vendor 真实第三方样本 `detunized/opvault-ruby/test.opvault`（MIT，密码 `"password"`）为开发期 fixture。它是真实 1Password 客户端产物（仓库「Test vault」提交携带），且**本报告已给出全部预期明文**（3 个 Login 的 overview/details、2 个文件夹），可固化为断言。置于 `core/cf-importer/tests/fixtures/`，README 注明来源与密码（测试专用，无敏感信息）。
2. **自造合成器（次选，仅测自洽）**：按本报告 §1 规格实现 encrypter（PBKDF2 → 派生 → 随机 master/overview/item 密钥 → opdata01 打包：前置随机填充 + MAC），再用待测 decrypt 往返。**只能证明自产自销自洽，不能证明与真实 1Password 互操作**——互操作性由路径 1 覆盖。
3. **边界用例**：基于真实样本可加的变体——① 前置填充为 1 字节与整块 16 字节两种极值；② 带/不带 `folder`、`fave`、`trashed` 的条目；③ 多 profile 目录；④ `k` 与 opdata01 两条解码路径混用回归。
4. **纪律区分**：以上仅用于开发期 RED 测试；**验收仍需用户提供真实 .opvault 样本**（T02 验收门槛，lead 纪律），vendor 样本与验收样本分开对待。

---

## 5. 差异与风险清单

| # | 风险 / 差异 | 级别 | 处置 |
| --- | --- | --- | --- |
| 1 | **opdata 布局**：按 docs/22 §2.2.1 的 `[IV]‖[ct]‖[MAC]` 实现将导致真实 opvault 全量解密失败（magic 字节被误当 IV） | 高（T02 必改） | T02 实现按本报告 §1.2 布局；`opdata_decrypt` 签名不变但内部实现必须含 header 解析 + 前置填充剥离 |
| 2 | **CBC 填充**：PKCS#7 去除会剥掉明文头字节 | 高 | 解密取**末 plen 字节**；不按 PKCS#7 验尾 |
| 3 | **`k` 与 opdata01 布局不同**（k 无 header） | 中 | 两条解码路径分别实现、分别测试（§1.2 澄清） |
| 4 | **`hmac` 字段覆盖分歧**：Rust/Ruby 含 folder，官方+实证排除 folder | 低（导入侧可豁免） | 导入时**跳过条目级 hmac 校验**，以各 opdata 的 MAC 作为完整性校验（这才是真实防线）；若实现校验则按官方（排除 hmac 与 folder、字典序、trashed 按 0/1） |
| 5 | **JS 前缀**：`var profile=` / `ld(` / `loadFolders(` + 尾分号 | 低 | 解析器按格式剥离前缀（与 go-opvault 12/3 字节前缀一致） |
| 6 | 附件 `.attachment` 存在但首版 out-of-scope | 中 | 官方已文档化格式（OPCLDAT 头 + metadata/icon/contents 三段 opdata）；首版跳过+计数可行；注意附件的**存在性**可从 `.attachment` 文件名（`<itemUUID>_` 前缀）得知，不影响详情解析 |
| 7 | **多 profile** 目录 | 低 | 取 `default/`（docs/22 已定），其余 profile 目录列出不导入 |
| 8 | 密码「NUL 结尾」误解 | 中（实现细节） | **勿**把 NUL 字节追加进 PBKDF2 输入；用 UTF-8 原始字节 |
| 9 | 真实样本覆盖不足：本报告实证仅 Login（001）类 | 中 | 其余类别（002~111）字段结构由第三方代码（Rust detail.rs / go-opvault）佐证，但**字段码表冻结仍需更广真实样本**；T02 按「未知降级 + 报告」策略兜底 |
| 10 | overview `URLs` 数组与 `url` 并存 | 低 | 取 primary URL（`url` 或 `URLs[0].u`）落 Coffer urls |

---

## 6. 对 T02 实现的集成注意点（直接影响）

- `cf-crypto/src/opvault.rs`（docs/22 §3.2 草案）的 `opdata_decrypt` 注释「opdata 布局 [IV:16]‖[ct]‖[MAC:32]」**需改写**为 §1.2 布局；函数签名不变。
- 依赖（docs/22 §2.2.4）`pbkdf2` + `aes`/`cbc` + `hmac`/`sha2` + `subtle` 足够，无需新增。AES-CBC 用 RustCrypto 时注意**关闭 PKCS#7 padding**（手动按 plen 截取末段）。
- `precheck_opvault` 结构预检（docs/22 §2.2.3）判定要素应为：目录 + `profile.js` 存在且可解析（剥前缀）+ `iterations`/`salt`/`masterKey`/`overviewKey` 读数，**不触密码**；`folders.js`/`band_*.js` 属解锁后内容。
- 建议 T02 引入第 1 项 vendor 真实样本，把本报告 §1.5 的预期明文直接固化为 RED 断言（先红后绿），互操作证据链完整。

---

*文档结束。本报告将 `docs/22` §2.2.1 与 `docs/03` §6.3 的布局假设逐条校正；`docs/03` §6.3 目录结构（contents.js / 每条目一文件）与 opdata 填充描述建议在 T11 收尾时一并修订。*
