# KNOWN-ISSUES —— 已知问题登记簿

> 本文件是 Coffer 项目**未修复缺陷与延后决策**的唯一登记处。
> 修复后请把状态改为 ✅ 并在 docs/06-开发计划.md 修订记录中注明。
> 登记纪律：每条必须有——现象、精确根因（有证据）、影响面、修复路径选项、当前状态。
>
> **登记字段最小集（IEEE 829 异常报告，2026-09-28 起强制）**：编号、标题、
> **严重级**（S1 数据错误/安全语义/崩溃 · S2 主要功能受损 · S3 次要功能/基建 · S4 体验）、
> **优先级**（P1~P3，与严重级解耦）、来源版本、发现版本、复现步骤、
> 预期/实际、状态、**核销记录**（修复 commit + 复验测试名/验收方式）。
> 未登记的 bug 视为未发现；已登记未核销的 bug 视为未修复。
> 既有条目（BUG-2/3/4）已按最小集回填分级；新增条目直接按模板（文末）登记。

---

## BUG-2（✅ 已修复）：Touch ID 启用失败——Keychain -34018

**登记日期**：2026-09-27
**发现环境**：cygnus 真机（MacBookPro17,1 / macOS 26.6.2 / Touch ID 已录入）
**分级回填（2026-09-28）**：严重级 S2（主要功能——bio 解锁完全不可用）；优先级 P1；来源版本 v0.1（交付期）；发现版本 v0.1
**状态**：✅ 已修复（2026-09-27 真机验收通过，修复记录见下方「修复记录」）
**核销记录**：修复 = 方案 A.2（commit `51ad7c5` 真证书 + entitlement/profile 链）；复验 = 2026-09-27 cygnus 真机验收（启用 Touch ID 全路径），无自动化测试（Swift 侧无门禁，见 docs/09 §4 纪律 3）
**证据**：`~/Library/Containers/app.coffer.Coffer/Data/Library/Logs/Coffer-diag.log`（历史 -34018 / -50 记录留档；最后一条失败为 06:54:41 UTC 的 -50）
**方案 A 落地进展（2026-09-27，历史留档）**：构建脚本已改为 Apple Development 真证书签名（commit `51ad7c5`），待证书就位后做正路径验收——**BUG-2 状态保持 🔴 不变**（正路径未验收即未解除）。**此判断被后续验证修正**：真证书就位后 -34018 依旧复现，见下方「根因修正」。

### 现象

设置页点击「启用 Touch ID 解锁」并输入正确主密码后，弹窗报：
`错误 4001：生物识别解锁不可用（Keychain 异常 -34018），请使用主密码解锁。`
K_bio 未写入，header 未变（有测试断言的补偿逻辑生效）。

### 根因（已实证）

-34018 = `errSecMissingEntitlement`。**ad-hoc 签名（临时签名）的 App 没有代码签名身份，钥匙串系统拒绝其创建带访问控制（ACL）的条目**。三条路全部实证堵死：

| 尝试 | 结果 |
| --- | --- |
| 文件型登录钥匙串 + biometryCurrentSet ACL | ❌ -34018 |
| 数据保护钥匙串（kSecUseDataProtectionKeychain=true） | ❌ -34018（DP 钥匙串访问凭证绑定 application-identifier，ad-hoc 没有） |
| 加 `keychain-access-groups` entitlement | ❌ **App 直接拒绝启动**（launchd error 163，entitlement 对 ad-hoc 非法），已回滚 |

### 根因修正（2026-09-27 验收阶段实证，取代上节结论的「充分性」）

原结论「ad-hoc 签名导致」**必要但不充分**。真证书签名后 -34018 依旧复现（diag log 06:28 UTC 记录，该 App 已是 `TeamIdentifier=A6DS985SJJ` 真证书签名），逐层实证后根因是**三层叠加**：

1. **entitlement 层（-34018 的真根因）**：TN3137 明言 macOS 数据保护钥匙串的访问组列表**完全由代码签名 entitlements 构建**——`Coffer.entitlements` 缺 `keychain-access-groups`，访问组列表为空，与签名身份无关地报 `errSecMissingEntitlement`。
2. **profile 授权层（拒启动的真根因）**：`keychain-access-groups` 属**受限 entitlement，必须经 provisioning profile 授权**。真证书 + 该 entitlement 但无 profile → 进程 spawn 即被 AMFI SIGKILL（`open` 报 launchd error 163，与上表第三行 ad-hoc 时期同症——**当初的「拒启动」根因同样是缺 profile 授权，而非 ad-hoc 本身**）。本机 Mac 设备注册 + profile 生成以 `xcodebuild -allowProvisioningUpdates -allowProvisioningDeviceRegistration` 借 Xcode 已登录的免费 Apple ID 自动完成。
3. **代码层（-50，被 -34018 掩盖）**：entitlement 修好后露出 `errSecParam(-50)`——`BiometricKeychain.save` 的 requireBiometry 分支**同时设置 `kSecAttrAccessible` 与 `kSecAttrAccessControl`**（两者互斥，SecItemAdd 必返回参数错误）。此前从未暴露，因 entitlement 层先失败。

### 修复记录（2026-09-27，方案 A.2 落地——安全语义零妥协；方案 B/C 作废未采用）

| # | 改动 | 说明 |
| --- | --- | --- |
| 1 | `macos/Coffer/Coffer.entitlements` | 新增 `keychain-access-groups = [A6DS985SJJ.app.coffer.Coffer]`（TeamID 硬编码——codesign 不展开 `$(AppIdentifierPrefix)` 变量） |
| 2 | `tools/profilegen/`（新增） | 一次性最小 Xcode 工程（bundle id `app.coffer.Coffer` + 团队 `A6DS985SJJ` + 自动签名），用于生成/刷新开发描述文件 |
| 3 | `tools/make_provisioning_profile.sh`（新增） | 生成/刷新 profile → `macos/build/app.coffer.Coffer.provisionprofile`（git 忽略）。**免费账号 profile 仅 7 天有效**（本次到期 2026-10-04），过期重跑刷新 |
| 4 | `tools/build_macos_app.sh` | 签名前自动嵌入 profile 为 `Contents/embedded.provisionprofile`；缺失即 fail-fast 并指路刷新命令 |
| 5 | `macos/Coffer/Platform/BiometricKeychain.swift` | `save` 的 requireBiometry 分支删除 `kSecAttrAccessible` 键（与 `kSecAttrAccessControl` 互斥），可访问性已包含在 ACL 对象内 |

**验收（2026-09-27 真机）**：设置页「启用 Touch ID 解锁」→ 主密码确认 → Touch ID 弹窗出现，K_bio 写入成功，无 4001 报错；diag log 此后无新增失败记录。构建链全绿：真证书签名 + `keychain-access-groups` + profile 嵌入 + App Sandbox（无任何 network.*）。

**过程事故留档**：修复期间一次 `git reset --hard`（14:41）将未提交的 entitlements 修改连带回滚，导致 06:44/06:53 UTC 两次「修复后仍 -34018」的假象；重新应用后闭环。教训：**跨多文件的修复应尽快提交**，避免被并行的 git 整理操作冲掉。

**运维注意（长期有效）**：profile 过期后 App **无法启动**（SIGKILL）——症状回到 launchd error 163。处置：`./tools/make_provisioning_profile.sh && ./tools/build_macos_app.sh`。

### 复现与诊断

1. 构建：`./tools/build_macos_app.sh && open macos/build/Coffer.app`
2. 解锁 → 工具栏「安全设置」→ 启用 Touch ID → 输主密码
3. 读证据：`cat ~/Library/Containers/app.coffer.Coffer/Data/Library/Logs/Coffer-diag.log`

### 相关改动（已落地，方案 A 时直接复用）

- `BiometricKeychain` 全接口带 `useDataProtection` 测试缝隙（默认 true）
- `DiagLog` 共享诊断日志（Support/DiagLog.swift）+ 模块内步级日志
- 历史回滚记录：ad-hoc 时期的 keychain-access-groups 尝试曾撤销（拒启动）——现已随方案 A.2 在「真证书 + profile 授权」前提下重新加入并验收通过，见上方修复记录

---

## BUG-3（✅ 已修复）：安全设置 sheet 无关闭控件——失败后被困页面

**登记日期**：2026-09-27（cygnus 真机报告）
**分级回填（2026-09-28）**：严重级 S4（体验——被困页面，有主路径替代）；优先级 P3；来源版本 v0.1（交付期）；发现版本 v0.1
**状态**：✅ 已修复（见下方修复记录）
**核销记录**：修复 = commit `a01b151`（SecuritySettingsView 完成按钮）；复验 = cygnus 真机（2026-09-27），无自动化测试

### 现象

点「启用 Touch ID 解锁」→ 展开主密码确认行 → 启用失败（BUG-2 的 -34018）→
错误弹窗点掉后，**安全设置 sheet 没有任何可见的关闭方式**，用户被困在页面内。
（无 Touch ID 解锁失败的场景同样触发——该 sheet 从一开始就没有退出口。）

### 根因（代码审计确认）

`SecuritySettingsView` 经 `MainView.swift:105` 的
`.sheet(isPresented: $showSecuritySettings)` 呈现，但视图内部：
- 无 toolbar / 无「完成」按钮 / 无 `@Environment(\.dismiss)` 调用
- 密码确认行的「取消」只收起确认行（cancelPrompt），不关闭 sheet
- Form 固定 frame 460×260，无拖拽关闭的标题栏区域

### 修复记录（2026-09-27）

- `SecuritySettingsView` 加 `@Environment(\.dismiss) private var dismiss`
- Form 末尾新增独立 Section：「完成」按钮（与 ImportView / ItemEditView 的
  内容区关闭按钮保持同一模式，未引入 toolbar 新样式）
- 窗口高度 260 → 340 容纳按钮
- 复查：MainView 的其余 sheet（新建条目 / CSV 导入 / 建库）均有 dismiss 控件，
  本缺陷仅存在于安全设置页，无同类遗漏

备注：BUG-2 修复后本页仍需此控件——无论启用成功、失败或取消都要能退出。

---

## BUG-4（✅ 已修复）：测试套件不可作为门禁——一条 flaky 断言 + 一条资源耗尽用例

**登记日期**：2026-09-27
**发现环境**：`main` @ `3596467`，8 核 / 16 GiB macOS；WI-1 状态声明独立核验
**分级回填（2026-09-28）**：严重级 S3（测试基建缺陷，非产品缺陷——但具门禁否决力）；优先级 P1（门禁是所有版本出口判据的地基）；来源版本 v0.1.1（`main` @ `3596467`）；发现版本 v0.1.1
**状态**：✅ 已修复（2026-09-27，修复记录见下「修复路径」各条 ✅ 标注）
**核销记录**：修复 = commit `84aa7bb`（分档 + N=3 min 采样 + 一拆二 + `#[ignore]`）+ `aa24441`（v0.2 模糊搜索语义适配）；复验 = `cargo test -p cf-session --lib 千条搜索基线` 连续 20/20 通过（BUG-4 修复路径 1 内记录）
**证据**：`cf-session/src/usecase/search.rs` 的 `千条搜索基线`、`cf-session/tests/adversarial.rs` 的 `极端kdf参数建库记录与解锁往返`（按测试名定位——libtest 名字写错会静默不报错，行号同理随代码漂移不可靠，故本条不再引用行号）

> **性质说明**：本条**不是产品缺陷，是测试基础设施缺陷**。产品的搜索性能与 KDF 行为均无问题 —— 详见「影响面」。误按「性能降级」处理会去改无辜的搜索代码。

### 现象

三个事实互相纠缠，共同导致 `cargo test --workspace` **不能作为任何版本的 DoD 门禁**：

1. **`千条搜索基线` 是单次墙钟断言，随机失败。**
   `search.rs:198-199` 断言 1000 条搜索 `< 200 ms`，**只采样一次**。
   独立复测：**20 次记录执行中 3 次失败**（三次失败的耗时见下文「影响面」）。
   计数口径与逐条出处见 `docs/06-开发计划.md` 修订记录 r2.5（历史留档）——
   分母是**被声明的边界**（换口径则为 28），**引用时必须连同边界一起写**。
   执行条件不受控（load 2.95–19 波动），**足以确证 flaky，不足以给出失败率** ——
   **不得引用任何百分比**（比率不可导出，勿由 20 / 3 换算）。
   其中**两次**失败发生在**仅选中该 1 条**时（`41 filtered out`，机器输出）
   → **与同 binary 兄弟测试的并发无关**；同一 load（13.64）下亦出现一失败一通过 → **与负载无关**。
   ⚠️ **证据纪律**：libtest 不回显 argv，故 `grep --test-threads` 的**零命中不能**证明
   「未用该 flag」；反之，日志里的段落标题是**人工写入的标注**，**也不能**证明「用了该 flag」。
   本条只引用机器输出（`41 filtered out`）。
2. **`极端kdf参数建库记录与解锁往返` 在 debug 档资源耗尽。**
   修复前的原合体用例里既建 `m=8 MiB, t=1, p=1`（极小档）又建
   `m=1 GiB, t=10, p=1`（极端档；该合体用例现已一拆二为极小/极端两条，
   见修复路径 2）；极端档单进程 RSS ≈ 1.0 GB，
   内存压力下长时间无进展（观测到 **>20 分钟**仍未结束）。
   核验时该 binary 其余 26 条已 ok、**0 条失败** —— 判定为**资源饿死，不是失败**。
3. **后果：`--workspace` 首败即停 + 跑不完。**
   首败即停使其在失败时给出**假绿**（首个失败目标之后的 crate 与**全部 doc-test 一次都不跑**）；
   上述重量用例又可能让它长时间不结束。两个方向都让它失去门禁资格。

### 根因（已实证 / 待查）

**两件事不是同一类问题，必须分开处置：**

| 对比项 | `千条搜索基线` | `极端kdf…往返` |
| --- | --- | --- |
| 根因 | **单次采样**（无统计口径，**已实证**：`search.rs:198` 单次读取 + 160 样本探针实测分布）+ **profile 错配**（阈值按 release 直觉设在 debug 档，**待查**：**无 release 档对照实测**；间接迹象是 `:199` 用平硬 200 ms，未按 `cf-totp/src/lib.rs:626-630` 的 `cfg!(debug_assertions)` 既有范式分档） | **资源耗尽**（1 GiB Argon2id × 并发，**已实证**：`swap used ≈ 19914M / 20480M`、单进程 RSS ≈ 1.0 GB） |
| 表现 | 随机失败，**与负载高低不相关** | 长时间无进展 / 进程被饿死 |
| 证据 | 失败发生在 **load 13.64**，而 **load 16.86–17.72 下连续 12/12 全过** → 触发因素是**瞬时停顿**（swap 换入换出 / 页错误 / 调度抖动），不是持续 CPU 争抢。⚠️ 该证据**支持**「与负载高低不相关」，**不支持**「profile 错配」—— 后者是**待查假设**，尚无 release 档对照实测，勿由本行读作已证 | 核验时 `swap used ≈ 19914M / 20480M`，单测试进程 RSS ≈ 1.0 GB |

### 影响面（**必须与「性能降级」区分**）

> **FR-11.4 的定性是「需求满足、证据链不可用」，不是「性能降级」。**
> 独立只读探针（复刻同样负载、把断言换成打印分布）4 批次共 **160 样本**：
> **p50 ≈ 75–77 ms，max ≈ 93 ms，无一 ≥ 200 ms，余量 2.6×**。
> 测试失败时的 **273 / 339 / 362 ms** 是 p50 的 3.5–4.7 倍 —— 需要一次约 250 ms 的
> 瞬时系统停顿才能触发。**该断言测的是机器抖动，不是代码性能。**

- 对**发布判断**：当前 `cargo test --workspace` 无门禁资格 → 需显式 DoD 命令（见修复方向 3）。
- 对**文档**：`docs/06-开发计划.md` §2 已按正确口径登记（全量 **422 用例**；门禁命令下 **420 执行通过 + 2 条排除**），并显式写明「**421 通过 / 1 失败**」这一构成**不成立**。
- 对**代码**：**不影响** FR-11.4 的性能结论，也不影响任何功能正确性。

### 修复路径（2026-09-27 已落地）

1. ✅ **`search.rs` —— 分档 + 取最小值**（两条都做了，缺一不可）：
   - **分档**：参照 `core/cf-totp/src/lib.rs:626-630` 的 `cfg!(debug_assertions)` 先例。
     release 档保持 `200 ms`；debug 档取**实测标定值 400 ms**（2026-09-27 标定：
     30 样本 p50 ≈ 78 ms、max ≈ 81 ms，阈值 = max(p50×5, 300ms) = 390 → 向上取整到
     50 ms 倍数 → 400 ms）。未照抄 cf-totp 的 50× 比例（搜索按 50× 得 10000 ms，无意义）。
   - **单次采样改 N=3 取最小值**修抖动（取 min 而非均值，才不被瞬时停顿污染）。
   - **保留在默认测试集，未 `#[ignore]`** —— 它守的是真实需求。
     落地后复验：`cargo test -p cf-session --lib 千条搜索基线` 连续 **20/20 通过**。
2. ✅ **`adversarial.rs` 的 `极端kdf参数建库记录与解锁往返` —— 一拆二 + `#[ignore]` + release 串行独占**：
   - 拆成 `极小kdf参数建库记录与解锁往返`（轻量断言：header 如实记录 8 MiB 参数、
     解锁往返、错密码 1002，留在默认测试集）与 `极端kdf参数建库记录与解锁往返`
     （1 GiB 重量用例，原内容不动）两条，轻量断言不再被 1 GiB 用例绑架。
   - 极端档加 **`#[ignore]`**（**全仓首例**，落地前 `grep -rn '#\[ignore' core/` 为 0），
     人工执行命令（**`--test-threads=1` 必须带**）：
     `cargo test --release -p cf-session --test adversarial 极端kdf参数建库记录与解锁往返 -- --ignored --test-threads=1`
3. ✅ **给出可信的门禁命令**（1、2 落地后，不再需要 `--skip`）：
   `cargo test --workspace --no-fail-fast`
   —— `--no-fail-fast` 去掉假绿；拆分落地后 `极端kdf参数建库记录与解锁往返` 带
   `#[ignore]`，**默认不跑**（`--no-fail-fast` 之外的参数不再需要；忽略态用例不占用门禁执行数，
   门禁口径见 `docs/06-开发计划.md` §2）。

> ⚠️ `#[ignore]` 在全仓原本零命中，BUG-4 修复引入**首例**（极端档一处）。

### 复现与诊断

1. 抖动：`cargo test -p cf-session --lib 千条搜索基线` 重复十余次（与 load 无关，首次即可能失败）
2. 资源：`cargo test -p cf-session --test adversarial 极端kdf参数建库记录与解锁往返`，debug 档观察 RSS 与耗时
3. 假绿：`cargo test --workspace` —— 检查失败目标之后的 crate 与 doc-test 是否执行

---

## BUG-6（✅ 已修复）：1PUX 合成样本生成器附件 off-by-one——JSON 引用与 ZIP 条目错位

**登记日期**：2026-09-28（v0.3.0-T01 开发期由 dev-coder 发现、lead 登记）
**发现环境**：feature/v0.2-completion @ `d1aaa6a` 前工作树；工具 `tools/make_test_sample.py`
**分级**：严重级 S3（测试基建缺陷，非产品缺陷——但使附件导入 E2E 验收永不可达）；优先级 P1（阻塞 v0.3.0 出口判据①的附件部分）；来源版本 v0.1（fixture 自 v0.1 入库即带病）；发现版本 v0.3.0-T01
**状态**：✅ 已修复

### 现象（预期/实际）

- 预期：1PUX 样本内 `item.file.path` 引用的 `files/docN.pdf` 与 ZIP 内 `files/` 条目一致。
- 实际：JSON 引用 doc1/6/11/16/21.pdf（`build_item(i+1, has_file=(i%5==0))`，0 基判定），
  ZIP 内实为 doc5/10/15/20.pdf（`for i in 1..=22 if i%5==0`，1 基判定）——附件解析永远悬空。

### 根因

同文件两处循环基数不一致（0 基枚举构造条目、1 基枚举写附件），生成器无自检断言。

### 复现与诊断

`python3 tools/inspect_1pux.py tests/fixtures/sample_coverage.1pux`（修复前）对比 JSON 引用与 `files/` 列表。

### 修复与核销记录

- 修复 = commit `a0c7ba2`：ZIP 循环改 `(idx-1)%5==0`；用修复后脚本重生成 fixture（export.data 语义不变，描述字段随项目更名对齐 Coffer）。
- 核销 = `core/cf-importer/tests/pux_import.rs` 附件逐字节回环用例（4/5 附件 read_content 全等；`cargo test -p cf-importer` 88 passed）。

---

## BUG-5（✅ 已修复）：导入 CSV sheet 无关闭控件——v0.1 起被困选文件页

**登记日期**：2026-09-28
**发现环境**：v0.2.0 真机验收（Round 1 准备阶段，用户实测发现）
**分级**：S4 / P2 / 来源版本 v0.1.0（存量） / 发现版本 v0.2.0（验收阶段）
**状态**：✅ 已修复（2026-09-28）
**核销记录**：修复 commit（本轮验收修复批）；复验 = 真机重开「导入 CSV」sheet，标题栏右侧出现「关闭」，Esc 可关闭
**证据**：用户验收反馈「导入CSV 这个页面没有退出」

### 现象（预期/实际 分行写）

- 预期：打开「导入 CSV」sheet 后任何步骤均可退出。
- 实际：`ImportView` 仅在导入完成的 done 页有「完成」按钮——**初始选文件页与预检报告页无任何关闭控件**；macOS sheet 点外部不关闭、无按钮时 Esc 无效 → 用户被困页面（不愿导入时只能强退 App）。

### 根因（已实证 / 待查）

已实证：`ImportView.swift` 的 `dismiss` 只在 `doneBody` 被调用；v0.1 实现时顶部 HStack 未放关闭按钮。**与 BUG-3 同类**（安全设置 sheet 无关闭控件，2026-09-27 修复）——本条是同类缺陷的第二个实例；第三个实例（AuditLogView，T-I）在独立验证中已同步修复。三个实例共同根因：**项目级纪律缺失——「macOS sheet 必须自带显式关闭出口」未写入 docs/07 UI 纪律**，靠 review 记忆不可靠。

### 修复路径

1. ImportView 标题栏右侧补「关闭」按钮（`.keyboardShortcut(.cancelAction)`，Esc 生效），导入事务执行中禁用（防丢结果页；事务 all-or-nothing 无数据风险）。
2. T-I（AuditLogView）已于合入前修复（toolbar「完成」+ dismiss）。
3. **全量 sheet 审计（2026-09-28，验收中发现 ExportView 同病后触发）**：9 处 `.sheet` 挂载 8 个目标 View 逐一核查——ExportView（备份/CSV 两流的选路径与确认页）与 RestoreBackupView（选文件与确认页）同样缺失，已按同款修复（标题栏「关闭」+ cancelAction，exporting/restoring/verifying 执行中禁用）。其余 6 个（SettingsView / ChangePasswordView / AuditLogView / ImportView / ItemEditView / VaultBioEnableOfferView）确认合格。
4. **流程改进**：docs/07 §2.4 UI 纪律补一条「macOS sheet 必须提供显式关闭出口（关闭/完成按钮，含 cancelAction 快捷键）；执行中需禁用时必须保证可从错误/取消路径返回」——防第四个实例。

### 复现与诊断

打开工具栏「导入 CSV」→ 观察选文件页右上角无任何关闭控件 → 尝试 Esc / 点外部均无法退出。

---

## BUG-7（✅ 已修复）：加密备份导出传工作目录而非库目录——必 1012

**登记日期**：2026-09-28
**发现环境**：v0.2.0 验收自动化回环测试（`tools/run_clipboard_tier_tests.sh` T8 段，真实库数据）——用户尚未手测到 Round 3 即被抓出
**分级**：S3 / P1 / 来源版本 v0.2.0-T06（本轮引入） / 发现版本 v0.2.0（验收阶段）
**状态**：✅ 已修复（2026-09-28）
**核销记录**：修复 commit（本轮验收批）；复验 = `run_clipboard_tier_tests.sh` T8 段（真实库 导出 verified=true → 校验 → 恢复产物 uuid 一致 → 1004 负向）20/20 全绿
**证据**：测试输出 `Coffer(code: 1012, message: "validation failed: 源目录不是合法库目录：容器布局不完整：缺少必需文件 header.json（vault_dir=…Documents/Coffer）")`

### 现象（预期/实际 分行写）

- 预期：ExportView 导出成功，done 页 verified=true。
- 实际：`exportBackup(vaultDir: model.baseDir.path, …)` 传的是**工作目录**（`Documents/Coffer`），而 FFI 契约（api.rs）要求**库目录**（`<base>/<uuid>`，含 header.json）→ 恒 1012，导出功能完全不可用。

### 根因（已实证 / 待查）

已实证：T-E 接线时混淆了两级目录语义——`export_backup(vault_dir)` 参数是库目录，`restore_backup(target_base_dir)` 参数才是工作目录；同名前缀 `vaultDir` 变量名掩盖了差异。Rust 侧契约测试（`backup_ffi_semantics.rs`）传的是临时库目录所以全绿，**FFI 层测试覆盖不了 Swift 侧传参错误**。

### 修复路径

1. AppModel 新增 `vaultDirPath` 计算属性（`<baseDir>/<vaultUUID>`，注释标注两级目录语义差异）；
2. ExportView `doExport` 改传 `model.vaultDirPath`；
3. `run_clipboard_tier_tests.sh` T8 段保留「真实库回环」为回归警戒（按 briefs[0].vaultUuid 构造库目录）。

### 复现与诊断

修复前：App 内任意导出 → 「错误 1012：源目录不是合法库目录」；修复后导出成功且 verified=true。

---

## BUG-8（✅ 已修复）：日志出口统一往 Clipboard.swift 引入 DiagLog 依赖——验收脚本编译清单未同步，run_clipboard_tier_tests.sh 编译失败

**登记日期**：2026-09-29
**发现环境**：v0.4.0 发版回归（任务 #8），`tools/run_clipboard_tier_tests.sh` 实跑
**分级**：S3（测试基建）/ P2 / 来源版本 v0.4.0（`741c157` + `1f00650` 日志出口统一批引入） / 发现版本 v0.4.0（发版回归）
**状态**：✅ 已修复（2026-09-29，回归批内闭环）
**核销记录**：修复 = `tools/run_clipboard_tier_tests.sh` swiftc 文件清单补 `macos/Coffer/Support/DiagLog.swift`（回归批内修改，未占独立 commit 时随回归批入库）；复验 = 脚本重跑 **20/20 全绿**（基线 26 = 20 自动段 + 6 T8 真实库段；T8 段因 BUG-10 改 opt-in，转用户陪跑清单——见任务 #8 回归报告）
**证据**：回归日志 `~/.claude/jobs/dc7a41d3/tmp/regress_clipboard.log`——`Clipboard.swift:142/152 error: cannot find 'DiagLog' in scope`，脚本 exit 1

### 现象（预期/实际 分行写）

- 预期：`run_clipboard_tier_tests.sh` 26/26 全绿（v0.3.0 基线，计数只增不减）。
- 实际：swiftc 编译失败（`Clipboard.swift` 两处 `cannot find 'DiagLog' in scope`），脚本 exit 1，零用例执行。

### 根因（已实证 / 待查）

已实证：`741c157` / `1f00650`（#7 审查 LOW 项「日志出口统一」）给 `Clipboard.swift` 新增了 `DiagLog.append` 调用；App 构建不受影响（`build_macos_app.sh` 编 35 文件含 DiagLog.swift，门禁全绿），但 `run_clipboard_tier_tests.sh` 的 swiftc 清单（3 文件）未同步补 `DiagLog.swift` → 验收脚本与 App 构建的文件清单双轨漂移。**暴露的过程缺口**：Swift 侧改动只过了 cargo 门禁 + App 构建，未跑 Swift 验收脚本——脚本基线（26/26）不在任何自动门禁内，回退只能靠发版回归人工实跑（本次即由它兜住）。

### 修复路径

1. `run_clipboard_tier_tests.sh` swiftc 清单补 `Support/DiagLog.swift`；
2. 重跑脚本至 26/26 全绿（本条核销判据）；
3. 留档声明：Swift 验收脚本基线依赖 App 源文件闭包，源文件新增跨文件依赖（如 DiagLog）时须同步检查 `tools/` 下两套脚本的 swiftc 清单（顺带核 `run_1pux_real_sample_acceptance.sh`——本次实核未受影响，12/12 全绿）。

### 复现与诊断

修复前：`./tools/run_clipboard_tier_tests.sh` → swiftc 编译错误 exit 1；修复后同命令 → 20/20 全绿（T8 opt-in，见 BUG-10）。

---

## BUG-9（✅ 已核销：#19 发版回归 TC-G5 四步程序）：socket 清点判据命令 `lsof -i -p <pid>` 缺 `-a`——OR 语义下「空输出断言」结构性不可满足

**登记日期**：2026-09-29
**发现环境**：v0.4.0 发版回归（任务 #8）TC2-B 实跑，带阳性对照
**分级**：S3（测试判据）/ P2 / 来源版本 docs/15 r1.1（0 socket 判据映射引入时） / 发现版本 v0.4.0（发版回归）
**状态**：✅ 已核销（2026-09-30 实跑 / 2026-10-02 登记闭环，#19 发版回归 TC-G5 四步程序：① docs/15 内容锚实核通过——§3.3.2/§3.3.6 现行文本均为 `lsof -a -i -p` 修正口径；② 实跑零命中——关窗驻留态 Coffer 0 行；③ 阳性对照命中——python 本地监听 2 行；④ 登记闭环 + docs/16 TC2-B 声明闭环）
**核销记录**：docs/15 §3.3.2 命令改为 `lsof -a -i -p <pid>` 后由下一轮回归复验（本轮已实跑正确命令：Coffer 运行态 0 行 / 阳性对照 2 行，判据②实质通过）→ **核销闭环（#19 发版回归 TC-G5，2026-09-30 实跑 / 2026-10-02 登记）**：关窗驻留态 Coffer PID 47042 `lsof -a -i -p` = 0 行；阳性对照 python http.server PID 47244 = 2 行（TCP LISTEN 命中）；四步齐备核销
**证据**：本轮实跑读数——`lsof -i -p <Coffer_pid>` 402 行、同命令对本地 python 监听进程 330 行（两读数均被系统级 socket 集主导，进程间不可区分）；改 `lsof -a -i -p` 后 Coffer 0 行、python 监听 2 行（LISTEN 条目命中）

### 现象（预期/实际 分行写）

- 预期：`lsof -i -p <pid>` 对零网络 App 输出为空（docs/15 §3.3.2 判据②）。
- 实际：lsof 的 `-i` 与 `-p` 缺 `-a` 时是 **OR** 组合——输出 = 全系统 internet 文件 ∪ 该进程全部文件，恒非空；零网络 App 与持网进程读数同量级（402 vs 330），断言永不成立也无法区分。

### 根因（已实证 / 待查）

已实证：lsof 谓词组合语义（无 `-a` 即 OR）；判据起草时未带阳性对照实跑——本轮回归按「零命中与查询失败输出相同，唯一区分手段是阳性对照」纪律带上对照才暴露。**教训落条**：判据命令首次入册前必须在「应命中」与「应零命中」两个对象上各实跑一次。

### 修复路径

1. 判据命令定为 `lsof -a -i -p <pid>`（AND 语义）并保留阳性对照必配（已知持 socket 进程跑同命令须非空）；
2. docs/16 r1.6 TC2-B / §1 判据② 已按此口径更新（本轮）；
3. docs/15 §3.3.2 原文修正转 dev-architect（同工单），此条核销以其合入为准。

### 复现与诊断

对任意进程跑 `lsof -i -p <pid>`（无 `-a`）——有网环境下永不空；加 `-a` 后零网络进程输出 0 行、监听进程输出非空。

---

## BUG-10（🟡 处置基本完成：根因排查收口 + T8 timeout 加固，触发态待查）：真实库回环段无人值守执行挂起——`listVaults` 于容器路径 `opendir` 阻塞

**登记日期**：2026-09-29
**发现环境**：v0.4.0 发版回归（任务 #8），`run_clipboard_tier_tests.sh` 无人值守实跑（两次复现）
**分级**：S3（测试基建）/ P2 / 来源版本 早期（T8 默认指向容器路径的行为先于 docs/14 §5 禁令） / 发现版本 v0.4.0（发版回归）
**状态**：🟡 处置基本完成（2026-10-03 v0.5.1 循环排查收口）：①根因排查三档结论（见下）；②T8 段 timeout 加固 `6cce031`；③复发协议留档。挂起为环境/状态相关瞬态，今日三路实证不复现；彻底关闭需触发态再现时实证（dtruss/fs_usage 需关 SIP）
**核销记录**：加固 commit `6cce031`（T8 二进制外层套 `timeout`，默认 `T8_TIMEOUT_SECS=240`——实测正常全流程 81.5s 的 ~3 倍余量；超时 WARN+SKIP 不算 FAIL、真实失败退出码原样传播；含 `|| status=$?` 退出码捕获修正与三路用例验证；复跑 20/20 ALL GREEN；**加固后全路径（T8 opt-in 带容器路径）复跑 26/26 ALL GREEN、exit 0、WARN 0 行——timeout 包裹下无回归无误报**）。脚本修订 + 加固 = 处置完成口径；根因查清后可另行关闭
**证据**：09-29 挂起 `~/.claude/jobs/dc7a41d3/tmp/regress_clipboard2.log` / `regress_clipboard3.log`；2026-10-03 排查 `/tmp/bug10_probe/`——原生产二进制 T8 opt-in 全流程 26/26 ALL GREEN、忠实 FFI 探针 listVaults 55ms、纯 Rust read_dir 556µs（同机 uptime 20 天未重启，同内核状态）；根因结论：**已实证不复现；高度可疑（未实证）= macOS TCC/沙盒对容器路径的按客户端首访介导在无人值守下阻塞**（shell `ls` 正常 vs 测试二进制阻塞 ⇒ 按客户端区分；open$NOCANCEL+CPU≈0 介导形态；容器路径每进程首访 ~36-55ms 佐证）；FileProvider/iCloud/libcurl 均排除。**复发协议四件套**：sample 栈 + 同路径 ls 对照 + 新编译无关二进制同路径对照 + 无人值守状态记录

### 现象（预期/实际 分行写）

- 预期：T8 真实库回环（listVaults → 导出 → 校验 → 恢复 → 1004 负向，6 项断言）随脚本无人值守执行（2026-09-28 基线 26/26 曾两轮全绿）。
- 实际：测试二进制于 T8 首个 FFI 调用 `listVaults(容器路径)` 的 `opendir` 上无限阻塞（两次复现，各 6 分钟以上无进展、CPU ≈ 0）；同路径 shell `ls` 正常；App 退出后复现不变。

### 根因（已实证 / 待查）

已实证：阻塞点为 FFI `list_vaults` 内 `read_dir` 的 `open()` 系统调用；阻塞特定于该测试二进制进程上下文（shell 同路径访问正常），与 App 是否运行无关。
待查：容器目录对非 App 上下文 `opendir` 的挂起机制（TCC/沙盒扩展/文件系统层，dtruss 级诊断需关闭 SIP，本轮未做）。

### 修复路径

1. `run_clipboard_tier_tests.sh` T8 段改**显式 opt-in**：不再默认自动追加容器路径 `--vault-dir`，不传即 SKIP T8（本轮已改，注释留档三条理由——docs/14 §5 禁令、挂起复现、真实数据应显式授权）；
2. 自动化回归口径：脚本其余段 20/20 全绿（T8 的 6 项断言不删除，opt-in 后仍可执行）；
3. T8 真实库回环转**用户陪跑/真机清单**（涉真实数据 + 无人值守挂起），v0.4.0 发版附带清单移交；
4. 根因诊断（dtruss / 新建非 App 上下文对照）留待后续，不阻塞发版。

### 复现与诊断

无人值守跑 `./tools/run_clipboard_tier_tests.sh`（修订前版本，容器目录存在即自动进 T8）→ 二进制挂起于 listVaults；`/usr/bin/sample <pid> 2` 可见单点 `opendir` 栈；修订后同命令 → SKIP T8，其余段全绿。

---

## BUG-11（🟡 显式顺延，缓解已内置）：Bitwarden 真实导出的 passkey 私钥恒为 EncString 加密形态——当前导入路径对真实导出「passkey 全部不可导入」

**登记日期**：2026-09-29
**发现环境**：v0.5.0 降级版 #18 增量审查（dev-reviewer 第一轮，PK2 批 4268f23 声明范围核查）
**分级**：严重级 S3（功能弱于宣称——导入通道存在但真实世界 passkey 导入面 ≈ 0，条目本体与密码导入不受影响）/ P2 / 来源版本 v0.5.0-PK2（`4268f23`） / 发现版本 v0.5.0（审查阶段）
**状态**：🟡 未来待办（2026-10-04 用户裁定：不排入任何版本，转 backlog；缓解已内置：预检将此类行逐条列入 bad_passkeys/不可导入清单，用户可见、不静默丢弃；条目本体照常导入。**注意**：下方「发版文案约束」第 3 条继续生效——真实样本核对关闭前，README/docs/16 不得声称「Bitwarden passkey 导入可用」）
**核销记录**：待回填（修复版本 + 测试名）

### 现象（预期/实际 分行写）

- 预期：FR-10.1 降级导入——Bitwarden JSON 导出中的 passkey（fido2Credentials）可导入为库内 passkey 行。
- 实际：Bitwarden **真实未加密导出**中 passkey 私钥字段 `encryptedPrivateKey` 恒为 EncString 加密形态（attach key 不随导出解包）——PK2 解析器将其列入 bad_passkeys，passkey 行实际全部不可导入；仅合成/手工构造的明文 PKCS#8 JSON 可导入。调研 v2「Bitwarden JSON 导出含 passkey」的【文档】级结论对私钥字段不成立（导出含条目、不含可用私钥）。

### 根因（已实证 / 待查）

已实证：EncString 形态由 Bitwarden 客户端导出模型决定（非 Coffer 解析缺陷）。修复需支持 Bitwarden **密码保护导出格式**（EncString 经用户主密码解密）——独立特性面（KDF + AES 解密链），非小改。

### 修复路径

1. 支持 Bitwarden password-protected export 解密（用户输入导出密码 → 解出 fido2Credentials 私钥 → 归一化 PKCS#8）——目标版本待定（ADP/后续版本卡均可，量级 ≈ 1 周内）；**解法方向 2 设计规格 + 真实样本获取协议已于 2026-10-04 留档：`docs/22-v0.7实现方案.md` §2.6（v0.7.0 T10，规格留档不排实现——真实样本 + 版本卡排期为前置）**；
2. 或接受现状并显式声明（UI 预检已逐条列出不可导入原因）；
3. **发版文案约束（审查裁定，即时生效）**：TCB-1 真实样本核对关闭前，README/docs/16 判据不得声称「Bitwarden passkey 导入可用」。

### 复现与诊断

真实 Bitwarden 未加密导出（含 passkey 条目）→ `precheck_bitwarden_json` → fido2Credentials 行全部进 bad_passkeys（EncString 形态拒收）。

---

## BUG-12（✅ 已修复）：cf-store `attachment_repo` 测试基建并行时序 flake——`temp_vault_dir()` pid+纳秒命名可撞名

**登记日期**：2026-09-29
**发现环境**：v0.5.0 PW 批门禁（workspace 并行满载首跑 FAIL、复跑全绿；日志 `/tmp/coffer-gate-084749.log`（FAIL）/ `/tmp/coffer-gate-085126.log`（全绿）——dev-coder-ffi 发现上报，lead 按源码与日志复核证实）
**分级**：严重级 S3（测试基建缺陷，BUG-4 同族——具门禁否决力：并行满载下偶发假红）/ P1 / 来源版本 v0.1（fixture 自入库即带病） / 发现版本 v0.5.0-PW 批门禁
**状态**：✅ 已修复（2026-09-30，commit `97be64b`）
**核销记录**：修复 = commit `97be64b`（`attachment_repo.rs` 的 `temp_vault_dir()` 改 pid + 进程内 `AtomicU64` 计数器，进程内唯一由构造保证）；复验 = `temp_vault_dir并行不撞名`（`core/cf-store/tests/attachment_repo.rs` 回归警戒：32 线程 × 16 次 = 512 次并行调用断言全异；commit 消息记录 cf-store 6 轮 + workspace 3 轮全绿）。**遗留跟进 → 已开批量工单 B-1（用户 2026-09-30 裁定）**：commit 同批全仓 `pid+nanos` 同型扫描命中 `cf-format/src/testutil.rs` 等 22 处，超出 `cf-store/tests/**` 闭集。lead 复扫定位全部命中点（`cf-format`/`cf-session`/`cf-ffi`/`cf-exporter` 的测试支持代码 + `cf-exporter/src/backup.rs` 生产临时文件命名），**批量工单 B-1** 已开并派发 dev-coder 逐处改为 BUG-12 同款「pid + 进程内原子计数器」模式；cf-mcp 同型命中（本版新增）随 MCP 收尾统一对齐（本条只核销 cf-store 闭集内 flake）。

### 现象（预期/实际 分行写）

- 预期：`cargo test --workspace --no-fail-fast` 并行满载下 `cf-store --test attachment_repo` 稳定全绿。
- 实际：偶发 `密文跨附件搬运解密失败` / `content_mac篡改检出` 两用例 FAILED（8 passed / 2 failed），单跑即过、复跑全绿——非产品缺陷（本批代码不涉 cf-store）。

### 根因（已实证）

`attachment_repo.rs:29` `temp_vault_dir()` 用 `pid + SystemTime 纳秒` 命名临时目录：同进程（同 pid）内两个并行测试在同一时钟 tick 内调用即撞名；某用例收尾 `remove_dir_all` 拆掉另一用例的现场 → 密文/结构断言失败。macOS 时钟分辨率粗于测试步进使撞名窗口实际存在。

### 修复路径

目录名加入测试名（或进程内原子计数器）消除同 pid 撞名；同时检查全仓 `tests/` 内同型 `pid+nanos` 命名模式一并修复（BUG-4「测试基建门禁否决力」同族，修后按其复验口径连续多次全量门禁验证）。

### 复现与诊断

并行满载重复跑 `cargo test --workspace --no-fail-fast`（或 `./tools/run_gate.sh --skip-build`）至偶发 attachment_repo 2 用例失败 → 单跑该 target 即过 → 对照 `/tmp/coffer-gate-084749.log`。

---

## BUG-13（✅ 已修复，属 v0.5 工作线）：CI 在仓库根跑 cargo 必失败——根无 Cargo.toml（workspace 在 `core/`），且 `Run acceptance tests` 步骤的 `acceptance_v05` 测试是孤儿（在根 `tests/`，无 manifest 归属）

**登记日期**：2026-09-30
**发现环境**：G-G（mcp-e2e）新增 CI 冒烟步骤时发现既有 CI 在根执行 cargo 必败（根无 Cargo.toml），其 smoke 步骤实际走不到；lead 复核确认
**分级**：严重级 S2（CI 对 main 分支形同虚设）/ 优先级 P2 / 来源版本 v0.5.0（CI 既定缺陷，非 MCP 引入）/ 发现版本 v2.0.0（G-G 集成）
**状态**：✅ 已修复（2026-09-30 核销）
**核销记录**：2026-09-30 核销——裁定=用户「删孤儿+撤专用步骤」（删除根 `tests/acceptance_v05.rs` + 移除 rust.yml「Run acceptance tests」「Upload acceptance test log」两步）；修复=commit `ebaa66d`（原 `4eaa393` 经 amend 并入本登记后改名落位，dev-coder-ffi；reviewer 2026-09-30 指出 `4eaa393` 为悬空对象，已改引）；复验=CI `Run tests` 步骤（working-directory: core）跑全量测试含 `v05_ffi_semantics`（v0.5 验收真身，8 用例全绿）。
**证据**：`.github/workflows/rust.yml` 原 Build/Run tests/Run acceptance 均在仓库根跑 `cargo`（根无 Cargo.toml，workspace 在 `core/`）；`tests/acceptance_v05.rs` 位于根 `tests/` 且无根 manifest 归属。

### 现象（预期/实际 分行写）

- 预期：main 分支 push/PR 时 CI 执行构建、全量测试、v0.5 验收、MCP 冒烟。
- 实际：既有三个 cargo 步骤在根执行必报 `could not find Cargo.toml`；`acceptance_v05` 无 manifest 归属，任何工作目录下 `cargo test --test acceptance_v05` 都找不到 target。

### 处置（用户 2026-09-30 两轮裁定：先「加 working-directory: core」、后「删孤儿+撤专用步骤」）

- Build / Run tests 已补 `working-directory: core`（随 `33a9e27` 后的 lead CI 修复落地）；
- MCP smoke 步骤自包含（脚本内部 cd 到 `core/`）保持在根执行；
- `Run acceptance tests` / `Upload acceptance test log` 两步已移除、根 `tests/acceptance_v05.rs` 已删除（随 `ebaa66d`）——用户 2026-09-30 再裁定「删孤儿+撤专用步骤」；v0.5 验收真身 = `core/cf-ffi/tests/v05_ffi_semantics.rs`，由 `Run tests`（working-directory: core）覆盖，无需专用步骤。
- 注：workspace `cargo test` 含 MCP D-1 基线的 23 条预期红灯（v2.x 存根），CI 全绿需等 v2.0.0 MCP 存根补齐。

---

## M-1（✅ 已修复：72e4af6）：run_with_secret 目标子进程 stderr 整体吞掉 + 子进程继承 OP_SESSION（blast-radius 未文档化）

**登记日期**：2026-09-30
**发现环境**：dev-reviewer 对 G-C（mcp-op）审查发现，非阻断项（docs/20 §9.1 G-F 登记）
**分级**：严重级 S3（dev-reviewer 判 MEDIUM——子进程 stderr 对调用方不可见，且 OP_SESSION 落入目标子进程 env 的 blast-radius 未明示）/ 优先级 P2 / 来源版本 v2.0.0（MCP，docs/20 §4.2） / 发现版本 v2.0.0（G-C 审查）
**状态**：✅ 已修复（v2.0.0，commit `72e4af6`，2026-10-05）
**核销记录**：修复 = commit `72e4af6`（2026-10-05，方案 1 文档 + 方案 2 子集 stderr 透传）。透传语义 = 目标子进程**非零退出**时其 stderr 透传到 cf-mcp 自身 stderr 诊断通道（`COFFER_MCP_LOG` 缺省 = stderr），截断至 16 KiB 取末段（`MAX_FORWARDED_CHILD_STDERR`）、**标注不脱敏**（子进程输出不受 Coffer 控制，§3.5-3 诚实边界延伸）；**成功路径与 op 层失败路径不透传**（op stderr 仅按关键字归类为稳定文案，不进错误载荷，§4.2）。blast-radius 文档化 = docs/20 §3.5-6 / §4.4 补注（本次 G-F 核销批次）。复验 = `forward_child_stderr_labels_content_and_caps`（op.rs 单测）+ `run_with_secret_child_stderr_does_not_break_exit_code_contract`（core/cf-mcp/tests/provider_op_run.rs）→ cf-mcp 全测试 / clippy `-D warnings` 绿
**证据**：`core/cf-mcp/src/provider/op.rs` run_with_secret（`cmd.stdout(Stdio::null())` + `output()` 捕获 stderr 仅作 op 层分类，不向调用方透出）；`op_command()` 设 `OP_SESSION`，经 `op run` spawn 的目标子进程继承之

### 现象（预期/实际 分行写）

- 预期：目标子进程 stderr 可被 Agent/用户排查；OP_SESSION 的暴露面（blast-radius）在文档中明示。
- 实际：run_with_secret 丢弃子进程 stdout（协议帧纪律，§3.1），stderr 仅在 op 层错误分类时被消费、其余整体吞掉——子进程输出对调用方不可见；目标子进程经 `op run` 继承含 `OP_SESSION` 的完整环境（若子进程打印 env 或经 `/proc` 泄露，会话 token 暴露半径含任意被注入 secret 的进程）。

### 根因（已实证）

stderr 捕获后归一为稳定错误文案（剥离敏感值，§3.5-4 日志禁值纪律），**无向调用方透传子进程 stderr 的通道**；`OP_SESSION` 继承是进程环境语义（非缺陷，属设计），但 blast-radius 未文档化。

### 修复路径（2026-10-05 已落地：方案 1 + 方案 2 子集）

1. 文档明示 blast-radius（docs/20 §3.5/§4.4 补一句：`op run` 启动的目标子进程继承 `OP_SESSION`，须视为凭据暴露半径的一部分）——✅ 落地：docs/20 §3.5-6 / §4.4 补注（本次 G-F 核销批次）；
2. 子进程 stderr 透传/日志化取舍：stdout 恒为协议帧不可让渡，stderr 可经日志文件（`COFFER_MCP_LOG`）落盘或加开关透传——泄露面 vs 可诊断性，需架构裁定——✅ 落地子集：非零退出路径透传（16 KiB 截断、不脱敏标注），成功路径与 op 层失败路径不透传（保持剥离纪律）；
3. 不动作（MVP 保持吞掉）亦可接受——登记留档。

### 复现与诊断

fake op fixture + 子进程写 stderr（`sh -c 'echo oops >&2; exit 1'`）→ run_with_secret 返回 `Ok(1)`，stderr 对调用方不可见；目标子进程内 `printenv | grep OP_SESSION` 可见 token 已注入。

---

## M-4（✅ 已修复：72e4af6）：run_with_secret 缺省 env_name 取整个 secret 串——`op://` 引用必 7005

**登记日期**：2026-09-30
**发现环境**：dev-reviewer 对 G-C 审查发现，跨层联动（G-B `tools.rs` 缺省 vs G-C `op.rs` 校验），非阻断项（docs/20 §9.1 G-F 登记）
**分级**：严重级 S3（dev-reviewer 判 MEDIUM——带 `op://` 引用且省略 env_name 的 run_with_secret 调用恒 7005，功能面缺口）/ 优先级 P2 / 来源版本 v2.0.0（MCP，G-B/G-C 契约） / 发现版本 v2.0.0（G-C 审查）
**状态**：✅ 已修复（v2.0.0，commit `72e4af6`，2026-10-05）
**核销记录**：修复 = commit `72e4af6`（2026-10-05，方案 2：缺省取 `op://` 引用末段——新增 `default_env_name`，field 名优先、退化取 item 名，规则随 L-3 一并锁定）；API 签名不变（env_name 保持可选，**不触 D-1 冻结契约**）。复验 = `default_env_name_takes_reference_last_segment`（op.rs 单测）+ `run_uses_default_env_name_derived_from_reference`（core/cf-mcp/tests/provider_op_run.rs）→ cf-mcp 全测试 / clippy `-D warnings` 绿
**证据**：`core/cf-mcp/src/tools.rs:218` `optional_string(args, "env_name").unwrap_or_else(|| secret.clone())`（缺省取整个 secret 串）；`core/cf-mcp/src/provider/op.rs` `is_valid_env_name`（`[A-Za-z_][A-Za-z0-9_]*`）——`op://vault/item/field` 含 `/`/`:` 必不匹配 → 7005

### 现象（预期/实际 分行写）

- 预期：缺省 env_name 时注入到合理的默认变量名（或明确要求必填）。
- 实际：tools.rs 缺省取**整个 secret 串**作 env_name——对 `op://vault/item/field` 引用恒 7005（`InvalidParameter`）。run_with_secret 的 inputSchema 标注「default: the secret name」，对 `op://` 形态不成立。

### 根因（已实证）

G-B 工具层把 env_name 缺省定义为「secret 名」，对 `op://` 引用的「名字」理解与 G-C 的 env 名合法性校验不一致——`op://vault/item/field` 整串不是合法环境变量名。跨层契约缺口。

### 修复路径（2026-10-05 已落地：方案 2 缺省取引用末段）

1. env_name 改必填（inputSchema `required` 增 env_name）——API 签名变更，触 D-1 冻结契约，需用户确认；
2. 缺省取 `op://` 引用末段（field/item 名）作默认变量名——需定义「从引用提取默认变量名」规则（field 歧义，见 L-3）；
3. 文档明示：`op://` 形态必须显式给 env_name（最小改动）。

### 复现与诊断

`run_with_secret {secret: "op://Personal/OPENAI_API_KEY/password", cmd: "env"}`（省略 env_name）→ 7005 InvalidParameter。

---

## L-1（✅ 已修复：72e4af6）：临时 dotenv 非 unix 分支无 0600 权限约束

**登记日期**：2026-09-30
**发现环境**：dev-reviewer 对 G-C 审查（L 系列，可选登记项）
**分级**：S4 / P3 / 来源版本 v2.0.0（MCP，docs/20 §4.2） / 发现版本 v2.0.0（G-C 审查）
**状态**：✅ 已修复（v2.0.0，commit `72e4af6`，2026-10-05）
**核销记录**：修复 = commit `72e4af6`（2026-10-05，方案 B：非 unix 分支随不支持平台一并拒编译——模块级 `#[cfg(not(unix))] compile_error!`，消除无权限约束缺口面）；复验 = `temp_dotenv_writes_with_0600_permissions`（op.rs 单测）→ cf-mcp 全测试 / clippy `-D warnings` 绿
**证据**：`core/cf-mcp/src/provider/op.rs` `TempDotenv::write`——`#[cfg(unix)]` 分支 `OpenOptionsExt::mode(0o600)`，`#[cfg(not(unix))]` 分支 `File::create` 无权限约束

`TempDotenv` 内容仅 `ENV_NAME=op://…` 引用（无明文值，§4.4），cf-mcp 目标平台 macOS（unix）故当前无实际暴露；非 unix 分支权限缺口登记留档。修复（2026-10-05 已落地）= 随不支持的平台一并拒编译（`#[cfg(not(unix))] compile_error!`）。

---

## L-2（✅ 已修复：72e4af6）：临时 dotenv `create_new` 撞名直接 7006，无重试

**登记日期**：2026-09-30
**发现环境**：dev-reviewer 对 G-C 审查（L 系列，可选登记项）
**分级**：S4 / P3 / 来源版本 v2.0.0 / 发现版本 v2.0.0
**状态**：✅ 已修复（v2.0.0，commit `72e4af6`，2026-10-05）
**核销记录**：修复 = commit `72e4af6`（2026-10-05，写入抽成 `write_with_path_gen` 可重试路径——`create_new` 撞名（`AlreadyExists`）换路径重试，上限 `ENV_FILE_WRITE_ATTEMPTS` = 8；路径唯一性由 `temp_env_path`（pid + 纳秒 + 进程内原子计数器 `ENV_FILE_COUNTER`）保证，其他 IO 错误不重试直接 7006）；复验 = `temp_dotenv_retries_on_create_new_collision` + `temp_env_path_is_unique_per_call`（op.rs 单测）→ cf-mcp 全测试 / clippy `-D warnings` 绿
**证据**：`core/cf-mcp/src/provider/op.rs` `TempDotenv::write` 用 `create_new(true)`——文件已存在则直接 `Internal`（7006）

路径含 pid + 进程内原子计数器（`temp_env_path`），跨进程由 pid 隔离、进程内由计数器保证，实际碰撞面 ≈ 0；无重试可接受，登记留档。

---

## L-3（✅ 已修复：72e4af6，规则锁定 + 接受留档）：`op://vault/item/field` 末段恒判为 field——item 名含 `/` 的无 field 引用无法表达

**登记日期**：2026-09-30
**发现环境**：dev-reviewer 对 G-C 审查（L 系列，可选登记项）
**分级**：S4 / P3 / 来源版本 v2.0.0 / 发现版本 v2.0.0
**状态**：✅ 已修复（v2.0.0，commit `72e4af6`，2026-10-05，规则锁定 + 接受留档）
**核销记录**：commit `72e4af6`（2026-10-05）与 M-4 一并定规则并锁定——引用解析与缺省 env_name 统一「末段恒判 field，无 field 引用取 item 名」；`default_env_name_rule_is_locked_for_run_path`（provider_op_run.rs）哨兵测试锁规则（`op://Personal/a/b` → `b`，item 名含 `/` 恒判末段为 field）；item 名含 `/` 的无 field 引用无法表达一项**接受留档**（op 实测语义冲突面小，必要时引入显式 field designation 语法）。复验 = `default_env_name_rule_is_locked_for_run_path` → cf-mcp 全测试 / clippy `-D warnings` 绿
**证据**：`core/cf-mcp/src/provider/op.rs` `parse_secret_ref`——`op://vault/item/field` 剥除末段作 field；item 名本身含 `/`（op 允许）且无 field 时歧义（`op://vault/a/b` 被解析为 item="a"、field="b"）

当前 `get_secret_metadata` 用其取 item，歧义会解析错 item；op 实测语义（末段 = field）与「item 名含 /」冲突面小，登记留档。必要时引入显式 field designation 语法。

---

## L-4（✅ 已核销）：`CofferStoreProvider` 骨架方法 `unimplemented!` 占位——v2.x 建模前调用即 panic

**登记日期**：2026-09-30
**发现环境**：dev-reviewer 对 G-C 审查（L 系列，可选登记项）
**分级**：S4 / P3 / 来源版本 v2.0.0 / 发现版本 v2.0.0
**状态**：✅ 已核销（v2.0.0，2026-10-07：实现 `74a4538` + 接入 `f623eb9`，核销条件「实现 + 接入」两段齐备）
**核销记录**：实现 = commit `74a4538`（feature 门控生产实现：trait 4 方法 + 8 操作同语义映射 cf-store，`unimplemented!` 占位全部替换）；接入 = commit `f623eb9`（`coffer mcp --provider coffer` 经 `coffer-store` feature 门控接线 McpServer/CLI，库路径/密码走 §4.3 env 约定 `COFFER_VAULT_DIR` / `COFFER_VAULT_PASSWORD`）。docs/20 §4.5 已同步为生产实现 + 已接入。复验 = coffer.rs 单测 17 条 + cli 接入测试（`coffer_provider_serves_on_stdio_with_valid_vault` / `coffer_provider_missing_env_config_exits_1` / `coffer_provider_vault_dir_missing_exits_1` / `coffer_provider_wrong_password_exits_3` / `coffer_provider_unsupported_when_feature_off`，tests/cli.rs）→ cf-mcp feature 门禁绿
**证据**：`core/cf-mcp/src/provider/coffer.rs` 各 `SecretProvider` 方法 `unimplemented!("CofferStoreProvider 骨架：v2.x Secret 实体未建模")`

编译通过、调用即 panic 属显式占位（docs/20 §4.5 明示），非隐藏缺陷。已接受，不设修复工单。

---

## BUG-14（✅ 已修复）：run_with_secret 接受裸 item id——被 op run 当字面量注入子进程 env（静默注入错误"值"）

**登记日期**：2026-09-30
**发现环境**：dev-reviewer 对 v2.0.0 MCP 合并集终审（H-1，HIGH——合并前应修复）
**分级**：严重级 S2（主要功能受损——run 面静默注入错误"值"至子进程 env，行为不可预期且极难排查）/ 优先级 P1 / 来源版本 v2.0.0（MCP，docs/20 §4.2） / 发现版本 v2.0.0（MCP 终审）
**状态**：✅ 已修复（2026-09-30）
**核销记录**：修复 = commit `6585218`；复验 = `run_with_secret_rejects_bare_item_id`（core/cf-mcp/tests/provider_op_run.rs，裸 id → 7005）+ cf-mcp 全测试 / clippy `-D warnings` 绿
**证据**：`core/cf-mcp/src/provider/op.rs` 原 `validate_run_spec`（裸 id 经 `is_valid_secret_ref` 放行）→ `TempDotenv::write` 写 `ENV_NAME=<裸 id>` → `op run` 不解析、原样 export 字面量

### 现象（预期/实际 分行写）

- 预期：run_with_secret 的临时 dotenv 只承载 `op://` 引用（docs/20 §4.2），子进程 env 拿到的是 op 解析出的真实 secret 值。
- 实际：secret_ref 传裸 item id（如 `fixture-item-api-key`，`is_valid_secret_ref` 明确放行）时，dotenv 写 `MY_KEY=fixture-item-api-key`，`op run` 当字面量透传——子进程 env 注入的是 **id 字符串本身，不是 secret 明文**；子进程以为注入了真凭据，静默产生错误行为。`provider_op_run.rs` 全部用例只用 `op://` 引用，此路径无测试覆盖。

### 根因（已实证）

run 面把「secret_ref 非明文」校验与元数据面共用 `is_valid_secret_ref`（`op://` 引用与裸 id 两种形态皆可），未约束 run 必须为 `op://` 引用形态——与 docs/20 §4.2「dotenv 内容为 `ENV_NAME=op://vault/item/field`」协议不一致。

### 修复路径（2026-09-30 已落地）

1. `validate_run_spec` 要求 secret_ref 必须 `op://` 前缀 + 结构校验（vault/item 非空、无控制字符）；裸 id / 明文 → 7005（与 §4.2 run 协议对齐）。
2. 错误消息去掉入参回显（§3.4 载荷禁值纪律，联动 M-5）。
3. `get_secret_metadata` 补同口径边界校验（联动 L-6）；元数据面仍兼容裸 id（list 返回的稳定标识）。

### 复现与诊断

`run_with_secret {secret_ref: "fixture-item-api-key", cmd: "env"}` → 修复前子进程 env 得字面量 id；修复后 7005 InvalidParameter。

---

## M-5（✅ 已修复）：7xxx 错误载荷回显外部输入——违反 §3.4「载荷不得含 Secret 值」不变量

**登记日期**：2026-09-30
**发现环境**：dev-reviewer 对 v2.0.0 MCP 合并集终审（其 M-1，MEDIUM）
**分级**：S3（安全纪律——错误帧不经 SecretRedactor，回显可污染 Agent 侧显示/日志）/ P2 / 来源版本 v2.0.0 / 发现版本 v2.0.0
**状态**：✅ 已修复（2026-09-30）
**核销记录**：修复 = commit `6585218`（validate_run_spec / get_secret_metadata 错误消息全部去入参回显，改通用文案）；复验 = provider_op_* 错误码用例全绿（测试不断言消息文本，仅码值）
**证据**：`core/cf-mcp/src/provider/op.rs` 原 `InvalidParameter(format!("…{:?}", spec.secret_ref))` 等三处回显；`lib.rs::error_frame` 不经 SecretRedactor（仅 `content[0].text` 过 redact）

### 现象（预期/实际 分行写）

- 预期：§3.4「7xxx 消息载荷不得含 Secret 值」；§3.5-2 redact 只覆盖 `content[0].text`，错误帧天然绕开。
- 实际：Agent 误把明文值当作 secret 入参（§3.3 要防的场景）时，InvalidParameter 载荷原样回显该串且未经脱敏——值虽来自发起方，但进入 Agent 侧错误显示/日志，污染协议面。

### 根因（已实证）

错误归一消息直接 `format!` 拼接外部入参；错误帧不经 Redactor。

### 修复路径（2026-09-30 已落地）

全部错误消息改通用文案（`secret_ref must be an op:// reference` / `not a valid op:// reference` / `env_name is not a valid environment variable name` / `cwd is not a directory`），不携带任意外部串。

### 复现与诊断

`run_with_secret {secret_ref: "<含敏感串的明文>", …}` → 修复前 7005 载荷回显该串；修复后通用文案。

---

## M-6（🟡 登记待后续）：op/子进程 stderr 共缓冲——子进程日志「时间戳形态 + 命中关键字」可被误判为 op 层失败

**登记日期**：2026-09-30
**发现环境**：dev-reviewer 对 v2.0.0 MCP 合并集终审（其 M-2，MEDIUM）
**分级**：S3（错误归类误判——目标子进程非零退出可能被归一为 7003/7004/7006，违背「退出码原样返回」契约）/ P2 / 来源版本 v2.0.0 / 发现版本 v2.0.0
**状态**：🟡 登记待后续处理（MVP 接受启发式边界；`is_op_level_error` 注释已明示残余边界）
**核销记录**：待回填
**证据**：`core/cf-mcp/src/provider/op.rs` `is_op_level_error` / `classify_run_failure`——`op run` 把 op 与子进程 stderr 汇入同一缓冲；`op_error_detection_requires_timestamp_shape` 只覆盖「无时间戳形态」反例

### 现象（预期/实际 分行写）

- 预期：子进程非零退出码原样返回（mcp_acceptance 契约），不误报 Err。
- 实际：子进程日志若**恰好**为 `[ERROR] YYYY/MM/DD HH:MM:SS …` 时间戳形态（不少 CLI 工具正是此格式）**且**含 `could not find` / `could not resolve` 等关键字，`is_op_level_error` 返回 true → 归一为 7003/7004/7006，违背退出码原样返回契约。

### 根因（已实证）

`op run` 无原生开关分隔 op 与子进程 stderr；时间戳形态是唯一的近似判据，对「恰好同形态」的子进程日志存在误伤。

### 修复路径（候选）

1. 补该形态用例并文档明示边界（已部分落地：注释）；2. 后续若引入 wrapper 层可分隔两路 stderr；3. 不动作（MVP 接受，子进程输出不受控属 §3.5-3 诚实边界延伸）。

### 复现与诊断

`sh -c 'echo "[ERROR] 2026/09/30 15:45:51 could not find X" >&2; exit 7'` 经 op run → 当前被归类为 7003 而非返回 7。

---

## M-7（🟡 登记待后续）：`redact_known_values`（精确已知值脱敏）是生产死代码——更强的纵深防御面未接线

**登记日期**：2026-09-30
**发现环境**：dev-reviewer 对 v2.0.0 MCP 合并集终审（其 M-3，MEDIUM）
**分级**：S3（安全纪律——精确值替换强于前缀指纹 `sk-`，却仅被测试引用）/ P3 / 来源版本 v2.0.0 / 发现版本 v2.0.0
**状态**：🟡 登记待后续处理
**核销记录**：待回填
**证据**：`core/cf-mcp/src/redact.rs:89-98` 仅 `protocol_redact.rs:90-100` 引用；生产路径 `tools.rs:153` 的 `redact()` 只做前缀指纹（`sk-` + 阈值 8）

### 现象（预期/实际 分行写）

- 预期：docs/20 §3.5-2 输出 Redactor 管道（AS-11）为纵深防御；精确已知值替换是更强防御面。
- 实际：`redact_known_values` 从未被生产路径调用——已知值清单未接线到 `McpServer`。

### 修复路径（候选）

1. 接入 `McpServer`（持有 provider 已知值清单）；2. 明确标注为未来 `reveal_for_broker()` 配套；3. 删除避免误导。注意方法内 `replace` 对多个已知值存在级联/子串误伤隐患，接入前需定义语义。

### 复现与诊断

grep 显示 `redact_known_values` 生产路径零调用；`protocol_redact.rs` 有测试、生产无接线。

---

## L-5（✅ 已核销）：tools.rs `tracing::warn!` 无 subscriber——审计失败告警恒被丢弃

**登记日期**：2026-09-30
**发现环境**：dev-reviewer 对 v2.0.0 MCP 合并集终审（其 L-1，LOW）
**分级**：S4 / P3 / 来源版本 v2.0.0 / 发现版本 v2.0.0
**状态**：✅ 已核销（v2.1.0，2026-10-07 回填）
**核销记录**：修复 = commit `a2cbd36`（v2.1.0：手写 `DiagnosticSubscriber`，cli.rs:333-347、接线 :526，只放行 WARN/ERROR，**零新依赖**——不引 tracing-subscriber）；复验 = `src/cli.rs::audit_failure_warn_observable_through_server`（真实 McpServer + FailingAudit 走 run_with_secret → tools.rs warn! → 诊断通道，断言 [WARN] + "audit record failed" + error/secret 平铺无值，且审计失败**不阻断协议** isError=false / exit_code=0）+ `tracing_warn_is_routed_to_diagnostic_sink` + `tracing_error_is_routed_but_debug_is_filtered`（docs/28 §1.3 全判据已验收）
**证据**：`core/cf-mcp/src/tools.rs:242` `tracing::warn!(error = ?e, secret = %secret, "audit record failed")`——仓库从未初始化 tracing subscriber

当前 NoopAudit 不会失败（不可达），但 D-3 JSONL 落地后审计失败将**静默**（违反「错误不静默吞」纪律）。修复 = 改用 `cli::Logger` 或初始化 subscriber / 文档化。

> **回填修订（2026-10-07，browser-docs G-F 追加任务）**：本条目此前状态为「🟡 显式顺延 v2.1（2026-10-07 lead 裁定，不修复不核销）」——v2.1.0 发版批（docs/09 r2.17）未回填本条目，致实际已核销（docs/28 §1.3：a2cbd36 手写 DiagnosticSubscriber + `audit_failure_warn_observable_through_server` 已验收，docs/28 行 76「v2.1.0 落位」）但登记簿滞留 🟡。本条为核销回填：标题/状态/核销记录按 v2.1.0 实况更新，**历史登记行（登记日期/发现环境/分级/证据/分析段）不改写**，仅追加本说明。

---

## L-6（✅ 已修复）：get_secret_metadata 无边界校验——畸形 op:// 引用落到 op item get 按 7003 归类

**登记日期**：2026-09-30
**发现环境**：dev-reviewer 对 v2.0.0 MCP 合并集终审（其 L-2，LOW）
**分级**：S4 / P3 / 来源版本 v2.0.0 / 发现版本 v2.0.0
**状态**：✅ 已修复（2026-09-30）
**核销记录**：修复 = commit `6585218`（get_secret_metadata 前置 `is_valid_secret_ref`，畸形引用入界即拒 7005）；复验 = `get_secret_metadata_rejects_malformed_op_reference` / `get_secret_metadata_rejects_plaintext_value`（provider_op_list.rs）
**证据**：`core/cf-mcp/src/provider/op.rs` 原 `get_secret_metadata` 不调用 `is_valid_secret_ref`；`\n` 校验也只在 run 面

### 现象（预期/实际 分行写）

- 预期：get_secret_metadata 与 run 面同口径边界校验（畸形引用 7005）。
- 实际：`op://Personal`（无 item）等畸形引用落到 `op item get "op://Personal"` → 7003，与 run 面 7005 不一致。

### 修复路径（2026-09-30 已落地）

入口补 `is_valid_secret_ref`（空 / 换行 / 控制字符 / 明文值 → 7005）；元数据面仍兼容裸 item id（list 返回的稳定标识）。

### 复现与诊断

`get_secret_metadata("op://Personal")` → 修复前 7003；修复后 7005。

---

## L-7（✅ 已修复：7c0a217）：parse_frame 对单行长度无上限——恶意/失控客户端可发超大单行造成内存压力

**登记日期**：2026-09-30
**发现环境**：dev-reviewer 对 v2.0.0 MCP 合并集终审（其 L-3，LOW）
**分级**：S4 / P3 / 来源版本 v2.0.0 / 发现版本 v2.0.0
**状态**：✅ 已修复（v2.0.0，commit `7c0a217`，2026-10-05）
**核销记录**：修复 = commit `7c0a217`（2026-10-05，传输层有界读取：单行超限拒收 7005、连接拒绝退出；边界内行正常处理）；复验 = `parse_frame_rejects_line_above_max_length_with_7005` / `parse_frame_accepts_line_at_max_length_boundary` / `handle_line_rejects_overlong_line_with_7005_frame` / `serve_with_overlong_line_emits_7005_then_returns_fatal_err` / `serve_with_processes_normal_lines_and_returns_ok_on_eof`（core/cf-mcp/tests/protocol_frames.rs）→ cf-mcp 全测试 / clippy `-D warnings` 绿
**证据**：`core/cf-mcp/src/protocol.rs:89-103` `parse_frame` 对单行长度无上限

本地 stdio 传输，影响面小；按行长度截断（超限报 7005/连接拒绝）已落地（7c0a217）。

---

## PL-1（✅ 已修复：adda134 哨兵单测合入）：passkey 域 L-2 哨兵测试缺失——「改 reason 文案分类不变」无独立变换断言

**登记日期**：2026-09-30
**发现环境**：#18 增量审查补审（dev-reviewer 专项 L-2 落点核验，结论：结构已落地、哨兵测试待补）
**分级**：S3（回归警戒缺口——调用侧若改回文本分类且当前文案未变，现有测试全部测不出）/ P2 / 来源版本 v0.5.0 / 发现版本 v0.5.0
**状态**：✅ 已修复（dev-coder-passkey-import，commit `adda134`，2026-09-30）
**核销记录**：commit `adda134` 补哨兵 `同分类异reason文案分类不变`（lib 单测，mapping.rs `#[cfg(test)] mod tests`，+72 行）——经分类唯一入口 `map_passkey_row` 构造同 kind 异 reason 输入（keyCurve p384/p521 → 均 KeyCurveMismatch、keyAlgorithm eddsa/rsa → 均 KeyAlgorithmMismatch、缺 rpId → MissingRpId），`assert_ne!(reason)` 自检文案确实不同 + 非空转实证（临时改名称特异分类 → 哨兵 FAIL，已还原）；门禁 `cargo test -p cf-importer` = lib 77 + 集成 49 = 126 passed / 0 failed；`cargo clippy -p cf-importer -- -D warnings` 干净
**证据**：`core/cf-importer/src/bitwarden/mapping.rs:636-641`（`非es256族按枚举判定`）、`core/cf-importer/tests/bitwarden_import.rs:204-260`、`core/cf-ffi/tests/v05_ffi_semantics.rs` 三处均只固定枚举 kind 与列表归属，无一独立变换 reason 文案再断言分类不变。

### 现象（预期/实际 分行写）

- 预期：L-2 纪律（docs/17 r2.4 §9.1 / docs/19 §7）「按数据不按文案」有回归哨兵——同分类数据、不同 reason 文案 → 分类不变。
- 实际：哨兵测试按字面不存在。现有三处最近测试只锁枚举 kind 与列表归属（`BwPasskeyFailureKind::is_non_es256()` 枚举→bool、fixture→kind、跨 FFI 计数），无「同数据两条不同 reason → kind/is_non_es256 一致」的独立变换断言；调用侧若改回文本分类且当前文案未变，三处全测不出来。

### 根因（已实证 / 待查）

分类唯一调用点 `mapping.rs:290` `failure.kind.is_non_es256()`，全仓 grep 零 reason 文本参与分类——**结构要求已满足**；缺口纯在测试层（无哨兵）。编号说明：docs/19 原以「L-2」引用（passkey 域），与 MCP 域 L 系列（L-1~L-7）撞号，本次以 `PL-` 前缀再登记。

### 修复路径

补哨兵单测：经 `map_passkey_row`（或预检路径）构造同 kind、异 reason 的两输入（如 keyCurve `p384` 与 `p521` 均 → KeyCurveMismatch、reason 文案不同），断言 kind 一致 + is_non_es256 反映枚举。或由 lead 将 docs/19 验收口径改为与现有功能断言对齐（本条目按补测处理）。

### 复现与诊断

N/A（测试缺口，非运行期缺陷）。

---

## PL-2（✅ 已接受，不改）：FFI From 映射的 `try_from().unwrap_or(哨兵值)` 饱和转换

**登记日期**：2026-09-30
**发现环境**：#18 增量审查补审（dev-reviewer 其 LOW 建议 3）
**分级**：S4 / P3 / 来源版本 v0.5.0 / 发现版本 v0.5.0
**状态**：✅ 已接受（遵循仓库既有 saturating convention，L-3/L-4 同款先例）
**核销记录**：接受不改——`types.rs:1426` 已文档化「usize → u32 饱和转换」既有纪律（`u32::try_from().unwrap_or(u32::MAX)` 同款）；新映射（algorithm / sign_count 等）同构。库内契约下不可达（algorithm 恒 -7 ES256、sign_count 非负，上游由 `BwPasskeyFailureKind` 枚举强制）。
**证据**：`core/cf-ffi/src/types.rs`（`i32::try_from(...).unwrap_or(i32::MIN)` 等）

---

## PL-3（✅ 已修复：b459f6e）：菜单栏「数据」菜单缺「导入 Bitwarden (.json)…」入口——Bitwarden 向导仅工具栏可达

**登记日期**：2026-10-02
**发现环境**：#19 发版回归真机陪跑 TC-M5-8（用户实跑发现：菜单栏「数据」菜单无 Bitwarden 项）
**分级**：S3（功能可达但主入口缺失/双入口不一致）/ P2 / 来源版本 v0.5.0 / 发现版本 v0.5.0
**状态**：✅ 已修复（commit `b459f6e`，2026-10-02：菜单栏「数据」补「导入 Bitwarden (.json)…」，与工具栏三格式并列；构建验证 `tools/build_macos_app.sh` 退出 0）
**核销记录**：修复 = commit `b459f6e`（2026-10-02：`CofferApp.swift` `CommandMenu("数据")` 在 1PUX 项后补 Bitwarden 项，复用 `model.showImportBitwarden` 旗标，同 CSV/1PUX 锁态禁用纪律）；复验 = `tools/build_macos_app.sh` 退出 0（swiftc 编译 41 源文件零警告，产物 `macos/build/Coffer.app`）
**证据**：`macos/Coffer/CofferApp.swift:44-60` CommandMenu("数据") 仅 导入 CSV… / 导入 1Password (.1pux)… / 导出… / 设置…；`macos/Coffer/Views/MainView.swift:148-155` 工具栏「导入」菜单三项齐全（CSV / 1PUX / Bitwarden）。a25acf4 接线只覆盖工具栏菜单。

### 现象（预期/实际 分行写）

- 预期：两个导入入口三格式并列——菜单栏「数据」（⌘I 主路径，v0.3 起即导入主入口）与工具栏「导入」菜单均含 Bitwarden (.json)…。
- 实际：菜单栏「数据」菜单无 Bitwarden 项；用户（TC-M5-8 实跑）在菜单栏找不到 Bitwarden 导入，向导仅可经工具栏「导入」菜单触达。

### 根因（已实证 / 待查）

已实证：a25acf4 接线范围只含 MainView 工具栏菜单 + AppModel 旗标 + sheet；CofferApp.swift 的 CommandMenu("数据") 未同步。两入口共用 AppModel.showImportBitwarden 旗标，sheet 本身无缺。

### 修复路径

CommandMenu("数据") 在 1PUX 项后增 `Button("导入 Bitwarden (.json)…") { model.showImportBitwarden = true }.disabled(model.phase != .unlocked)`（同 CSV/1PUX 锁定态禁用纪律；import_bitwarden_json 有 1001 门禁）。

### 复现与诊断

菜单栏「数据」→ 仅两项导入；工具栏「导入」→ 三项。二进制字符串实核含 "Bitwarden (.json)"（工具栏项在包内），排除构建遗漏。

---

## PL-4（✅ 已核销）：Touch ID 解锁链路弹两次指纹框——「启动到拿到密码一次授权」被破坏

**登记日期**：2026-10-02
**发现环境**：#19 发版回归真机陪跑（用户实跑报告，AskUserQuestion 确认：第①次=启动后触控 ID 指纹框，第②次=又弹一次指纹框）
**分级**：S3（主解锁路径体验缺陷，非阻断，可降级主密码）/ P1 / 来源版本 v0.5.0 / 发现版本 v0.5.0
**状态**：✅ 已核销（2026-10-04 用户真机复验全部通过，见核销记录末尾复验确认；代码修复 commit `e04070b` + `4f05139`）
**核销记录**：修复 = commit `e04070b`（2026-10-02：删除 App 侧 `authenticateWithBiometrics` 预认证；`read` 查询改带全新 LAContext + localizedReason——`kSecUseOperationPrompt` 自 macOS 11 弃用改用本字段，单次弹窗）+ commit `4f05139`（2026-10-03：itemExists 探测查询加 LAContext.interactionNotAllowed=true 禁弹 UI——macOS 26 上元数据查询亦触发完整 ACL 认证 UI，消启动 ~1s 自动弹窗；`kSecUseAuthenticationUIFail` 自 macOS 11 弃用改用本字段；返回语义改三态：存在 / 存在但认证锁定返 true / 不存在）。**取消语义漂移已接受 → 本轮彻底修（reviewer HIGH 处置选 B，2026-10-03）**：改前取消 = App 侧预认证报 4001，改后取消 = 钥匙串认证报 4002（文案「凭据已失效」对单纯取消有误导）——顺延项「`errSecUserCanceled` 独立呈现」本轮核销关闭：`BiometricKeychainError` 增 `.userCanceled`（`mapStatus` 拆分 `errSecUserCanceled`，不再归入 `authFailed`）；`ErrorPresenter` 对 `.userCanceled` 返回空串不弹（`FfiErrorAlert` 空串不弹双保险）；`unlockWithTouchID` catch 改按错误类型分派——取消完全静默（手动/自动一致）、失效（itemNotFound/authFailed）呈现 4002 + 置 `touchIDStatus = .stale`（§4.1 stale 终判落地：LockView 按钮消失引导主密码）、其余照常呈现；`isAutoPrompt` 参数移除，静默语义改由错误类型驱动（docs/08 §7.3/§7.6 + KeychainTests 7c1 哨兵同步；build 退出 0，TouchIDStatus 19/19 + AutoPrompt 30/30 回归无损）。复验 = 待真机（#19 回归同法：启动零弹窗 + 点击解锁单弹窗 + 取消静默无 4002 + 指纹变更后按钮消失）。KeychainTests 哨兵（9a/9b/9c + 7c1）编译零警告，运行时断言需签名宿主执行（沙盒/裸二进制 -34018），**以用户真机解锁复验为准**。**真机复验确认（lead 落档 2026-10-04）**：①启动单弹/正常解锁——2026-10-03 用户确认「可以了 正常了」（4f05139 后）；②取消静默——2026-10-04 用户确认「取消自动引导指纹框 没有问题」（自动弹出的指纹框点取消 → 无错误框、按钮可再点，userCanceled 静默路径真机走通）；③持久失效 4002 → stale 路径 2026-10-03 真机事件已走通（诊断日志 -25293→4002 + 主密码恢复）。「指纹变更后按钮消失」子项未单独演练，由 ②③ 的 stale 终判机制与真机 4002 事件覆盖。
**证据**：代码面——`AppModel.swift:580` 仅一次 evaluatePolicy；`BiometricKeychain.swift:139` 读取绑定同一 LAContext（kSecUseAuthenticationContext，设计为不二次弹窗）；`LockView.swift` 无 onAppear 自动触发；启动路径 `openSession`/`lock()` 均跑 `refreshTouchIDStatus` → `itemExists`（AppModel.swift:351/509）碰 biometryCurrentSet 项。日志面——沙盒 diag log 2026-10-02 **零记录**（两次认证均无失败落盘，与「第二次弹窗来自 Keychain 读取自行认证且成功」假说相容）；2026-09-28 曾有 `itemExists 失败 status=-25293`（errSecAuthFailed）记录。

### 现象（预期/实际 分行写）

- 预期：Touch ID 解锁全程只弹 1 次指纹框（docs/08 §3.2「读取时复用认证结果、不再二次弹窗」；用户裁定基线：启动到拿到密码一次授权）。
- 实际：用户报告弹了 2 次指纹框才完成解锁。

### 根因（已实证 / 待查）

**已实证（2026-10-02 真机 log stream 取证，/tmp/coffer-pl4-repro.log）**：`kSecUseAuthenticationContext` 复用在本机 macOS 26 上未生效。时序：①用户点按钮 → App 主动 `evaluatePolicy`（rid 30292）→ 指纹匹配 ✓（22:16:40.37）；②200ms 后 `BiometricKeychain.read` 的 `SecItemCopyMatching`（BiometricKeychain.swift:139 绑定同一已认证 context）→ securityd **不认该认证结果**，自行发起 1008 策略认证（传感器监听，无 UI）；③securityd 经 Coffer 进程内 LAContext 驱动第二次 UI 认证（rid 30295，22:16:51.5 弹出）→ 匹配后 **`externalizedContextWithReply` rid:30296**（22:16:53.35，认证结果外化交钥匙串）→ 读取成功。两次认证均无失败落盘（diag log 10-02 零记录），与「第二次为钥匙串重认证且成功」完全相容。排除项：代码无启动自动触发（unlockWithTouchID 仅 LockView 按钮/CrossCopySheet 两个调用点）；itemExists 元数据查询未触发弹窗；首次弹窗于启动后约 1 秒出现系用户点击快，非自动弹。

**补证（2026-10-03 真机 log stream 取证，新构建已无 App 侧预认证）**：仍有两次弹窗，且第一次是**自动弹**——①**启动路径**：`refreshTouchIDStatus → itemExists`（AppModel.swift:351/509，openSession/lock 均调用）对挂 biometryCurrentSet ACL 的 DP 钥匙串项做元数据查询（SecItemCopyMatching 不带 kSecReturnData），macOS 26 亦触发完整 ACL 认证 UI（rid 30354，进程启动 +1.3s 弹出，无任何用户点击）；授权结果被 App 丢弃（纯探测）。docs/08 Q-2「itemExists 不触发弹窗」结论作废——09-28 的 `itemExists 失败 status=-25293` 静默形态与今日弹 UI 系同一机制两态。②**点击解锁**：`read` 钥匙串自有单次认证 = 正常唯一一次（rid 30360，externalize/import 机械可证）——e04070b 这半已修好。**结论：PL-4 = 双源**（启动自动弹：itemExists 元数据查询；点击双弹：预认证 + 读取再认证），e04070b 消后者，`4f05139` 消前者。

### 修复路径

删除 App 侧预认证（AppModel.swift:578-580 authenticateWithBiometrics 调用），解锁改为**钥匙串自有单次认证**：`BiometricKeychain.read` 查询带 `kSecUseOperationPrompt`（提示文案，实际落地因 macOS 11 弃用改用 LAContext.localizedReason）+ 全新 LAContext，系统弹唯一一次指纹框，读取成功即继续 FFI unlockWithBiometric。取消（errSecUserCanceled）/指纹集失效（errSecAuthFailed）→ 既有 4002 降级主密码（错误码映射未变；**取消语义漂移已接受**——改前取消经 App 侧预认证报 4001，改后经钥匙串认证报 4002）；4001 前置门禁（hasBiometricWrap + isBiometricsAvailable）保留。同步更新 docs/08 §7.2 时序 / §3.2 / §7.4 锚点（「不再二次弹窗」由设计声明变为实证行为）。CrossCopySheet 的 authenticateWithBiometrics 不涉 Keychain 读取（纯 FFI 确认），无此缺陷，不动。

补（2026-10-03，commit `4f05139`，双源①）：`itemExists` 探测查询加全新 LAContext + interactionNotAllowed=true（`kSecUseAuthenticationUI = kSecUseAuthenticationUIFail` 自 macOS 11 弃用，改用本字段），需认证时立即返回 `errSecInteractionNotAllowed` / `errSecAuthFailed`，不打扰用户；返回语义改三态——success → true、authFailed/interactionNotAllowed → true（项物理存在但认证锁定，可读性终判以 read 失败为准，docs/08 §4.1；TouchIDStatus 保持 .enabled，LockView 按钮不消失，点按后由 read 弹单次认证）、itemNotFound → false。

### 复现与诊断

启动 App（Touch ID 已启用态）→ 锁定页点「使用 Touch ID 解锁」→ 第 1 次指纹框授权通过后，仍出现第 2 次指纹框。

---

## PL-5（🟡 顺延 v0.5.1）：CrossCopySheet 目标库 Touch ID 解锁同型双弹窗——PL-4 修复后 read 带全新 context 稳定双弹

**登记日期**：2026-10-02
**发现环境**：v0.5.0 代码审查（dev-reviewer 复查 PL-4 时发现 CrossCopySheet.swift:300 亦涉 K_bio 读取，存在与 PL-4 同型的「预认证 + Keychain 读」双弹窗）
**分级**：S3（目标库解锁体验缺陷，可降级主密码）/ P3 / 来源版本 v0.5.0 / 发现版本 v0.5.0
**状态**：✅ 已核销（v0.5.1 修复路径①落地，2026-10-04 用户真机确认）
**核销记录**：修复 commit `1943fd0`（fix v0.5.1——删除 CrossCopySheet 预认证 `authenticateWithBiometrics`，仅保留 Keychain 自有单次认证，与 AppModel 解锁同型；错误呈现统一走 `TouchIDUnlockPresentation.resolve`，TouchIDError 拆分至 `Support/TouchIDError.swift`）。复验 = 用户真机确认跨库复制目标库解锁步骤指纹框**只弹 1 次**。回归测试全绿：run_touchid_error_presentation_tests.sh 9/9（新增）+ run_touchid_status_tests.sh 19/19 + run_auto_prompt_biometric_tests.sh 30/30 + run_touchid_auth_failure_tests.sh 6/6（新增）。
**证据**：代码面——`CrossCopySheet.swift:297` 保留 `authenticateWithBiometrics(context:)` 预认证（PL-4 只删了 AppModel 侧，此调用点当时判为纯 FFI 确认未动）；`:300` `BiometricKeychain.read` 现带全新 LAContext（PL-4 签名变更后的最小适配点）。

### 现象（预期/实际 分行写）

- 预期：CrossCopySheet 目标库 Touch ID 确认全程只弹 1 次指纹框。
- 实际：PL-4 修复后（`read` 改带全新 LAContext），此路径在 macOS 26 上**稳定双弹**——预认证弹 1 次，Keychain 读取自行认证再弹 1 次；旧系统复用同 context 时原本单弹，修复后由单变双（回归劣化）。

### 根因（已实证 / 待查）

同型于 PL-4：`CrossCopySheet.swift:297` 先 `evaluatePolicy` 预认证，随后 `:300` 的 `SecItemCopyMatching` 因 PL-4 签名变更绑定**全新** LAContext，macOS 26 securityd 不认预认证结果，自行发起第二次 UI 认证。PL-4 修复只覆盖 AppModel 解锁路径，未覆盖 CrossCopySheet 目标库读取路径（当时判「不涉 Keychain 读取」有误，dev-reviewer 已纠正）。

### 修复路径

顺延 v0.5.1，同 PL-4 做法二选一：①删除 CrossCopySheet 侧预认证，仅保留 Keychain 自有单次认证（与 AppModel 解锁一致）；②顺序对调——先 `read` 弹唯一一次认证框，成功后凭读取结果确认目标库，删除 `evaluatePolicy` 预认证。

### 复现与诊断

待真机复验（登记时推断未实跑：CrossCopySheet 目标库解锁在 macOS 26 上应稳定双弹；v0.5.1 修复后回归同法核验弹窗次数 = 1）。

---

## PL-6（✅ 已修复：134f9b5→da24a5d 两轮 + 接线返工 8045557）：macOS 26 MenuBarExtra 图标空白 + AppDelegate 接线临时实例陷阱

**登记日期**：2026-10-03
**发现环境**：v0.5.0 发版回归真机陪跑（用户报告「系统的状态栏上需要一个常驻的图标」，菜单栏上看不到 Coffer 图标）
**分级**：S2（FR-13.3 菜单栏常驻入口不可见）/ P2 / 来源版本 v0.4 引入（v0.5.0 回归发现）
**状态**：✅ 已核销
**核销记录**：134f9b5（NSStatusItem 取代 MenuBarExtra）+ 8045557（接线返工：strong model + RootView.onAppear attach）+ da24a5d（图标返工：经典挂锁轮廓）；复验方式 = 用户真机目视（图标可见、菜单弹出、样式「先这样」接受）
**证据**：AX 取证（旧版状态项存在但像素级前景像素=0）；返工前 AX 查无 menu bar 2；启动日志 SwiftUI 运行时警告「Accessing StateObject's object without being installed on a View」

### 现象（预期/实际 分行写）

- 预期：菜单栏常驻图标（FR-13.3），锁定/解锁两态可辨，点击弹出五项菜单。
- 实际：两段式故障——①旧 MenuBarExtra 在 macOS 26 上图标渲染空白（AX 存在、像素=0）；②首轮 NSStatusItem 修复后状态项根本未创建（AX 查无 menu bar 2）。

### 根因（已实证）

①macOS 26 SwiftUI MenuBarExtra(.menu) 图标不渲染（同屏其他 App 的 AppKit NSStatusItem 全部正常，本机实证）；②首轮修复踩中既有接线陷阱：`CofferMainApp.init()` 访问未安装的 `@StateObject` 产生临时 AppModel 实例（运行时警告实证），赋给 weak `appDelegate.model` 随即释放归 nil，`applicationDidFinishLaunching` 的 `if let model` 静默跳过 start()——同陷阱连坐 applicationWillTerminate 的 lockAllForTermination 与呼出自动引导。

### 修复路径

AppKit NSStatusItem + 程序化 template 图标（StatusItemController.swift）；接线改 strong model + RootView.onAppear 幂等 attach；图标返工为经典挂锁轮廓（用户验收）。AX 对 Coffer 进程在 macOS 26 上存在系统性失明（三个构建均复现，app 本体前台菜单完好时仍报 0），真机验证以用户目视+像素扫描为准。

### 复现与诊断

复现：macOS 26 上运行 v0.5.0 构建观察菜单栏。诊断：AX 枚举 + screencapture 像素扫描（注意 System Events 失明干扰，需以像素/目视为准）。

---

## PL-7（✅ 已修复：eca2186）：瞬时 errSecAuthFailed 被判持久凭据失效——长时间空闲自动锁定后 Touch ID 按钮消失只剩主密码

**登记日期**：2026-10-03
**发现环境**：v0.5.0 发版回归真机陪跑（用户报告「很久没有操作后 touch id 失效了 只能输入密码 这是不应该的」）
**分级**：S2（生物识别解锁通道被瞬时故障整段关闭，降级路径仅剩主密码；恢复依赖主密码解锁）/ P2 / 来源版本 v0.5.0 / 发现版本 v0.5.0
**状态**：✅ 已核销
**核销记录**：修复 commit eca2186（瞬时/持久双分道 + TouchIDError.transientUnavailable Swift-only 文案 + TouchIDAuthFailure.disposition 纯函数）；复验测试 run_touchid_auth_failure_tests.sh 6/6、run_touchid_status_tests.sh 19/19、run_auto_prompt_biometric_tests.sh 30/30；用户真机复验通过（2026-10-03「可以了 正常了」）
**证据**：诊断日志 `~/Library/Containers/app.coffer.Coffer/Data/Library/Logs/Coffer-diag.log`：
```
2026-10-03 10:11:00 +0000 Keychain.read 失败 status=-25293（01a0e023…）
2026-10-03 10:11:00 +0000 错误 4002：生物识别凭据已失效（可能因指纹变更），请使用主密码解锁后在设置中重新启用 Touch ID。
```

### 现象（预期/实际 分行写）

- 预期：长时间空闲自动锁定后回来，Touch ID 解锁按钮可用（或因传感器未就绪/系统锁定暂时不可用时给出「稍后重试」类提示，按钮保留）。
- 实际：自动锁定后 Touch ID「失效」，LockView 只剩主密码输入；伴随 4002 弹窗（「可能因指纹变更」文案在瞬时场景下误导）。

### 根因（已实证 / 待查）

AppModel.unlockWithTouchID 的 catch 把 `.authFailed`（read 返回 errSecAuthFailed -25293）一律按持久凭据失效处置：`touchIDStatus = .stale` 终判（docs/08 §4.1）+ 4002 → LockView 按钮 `touchIDStatus == .enabled` 条件不满足，整段隐藏直至主密码解锁后 openSession 刷新。但 -25293 成因有两类：持久（指纹集变更 biometryCurrentSet 失效，现行处置正确）与瞬时（系统锁屏/刚唤醒传感器未就绪/系统级 biometry lockout——本日多次无人应答的启动自动引导弹框超时可能累计失败计数触发）。瞬时被误判为持久。

### 修复路径

catch 的 `.authFailed` 分支按失败瞬间 `BiometricKeychain.isBiometricsAvailable()` 双分道：false → 瞬时（不置 stale，按钮保留，静态温和文案「暂时不可用请稍后重试」，DiagLog 记判定依据）；true → 维持 4002 + .stale 终判。.itemNotFound 分支不动。判定抽纯函数补单测；docs/08 §7.3 补两行。

### 复现与诊断

复现：长时间空闲（自动锁定触发 + 系统锁屏/传感器暂不可用）→ 回来点 Touch ID（或呼出自动引导）→ read 返回 -25293 → 4002 + 按钮消失。诊断：诊断日志 `Keychain.read 失败 status=-25293` + 4002 记录对时。核验：修复后同场景按钮保留且提示为「暂时不可用」文案；持久场景（删指纹重录）仍走 4002+stale。

---

## LOW-1（✅ 已核销）：UDS accept 后无读超时——连接后不发数据则 server 挂起至对端动作

**登记日期**：2026-10-07（v2.1.0 终审发现，docs/28 §7 顺延登记 v2.2.0；本条为核销回填）
**发现环境**：v2.1.0 终审（dev-reviewer-v210，审 01a6ca9..HEAD，2026-10-07），`core/cf-mcp/src/uds.rs` accept 后无读超时
**分级**：S4（availability-only，非安全缺口）/ P3 / 来源版本 v2.1.0 / 发现版本 v2.1.0（终审）
**状态**：✅ 已核销（v2.2.0，G1d 实现，2026-10-07）
**核销记录**：修复 = v2.2.0 G1d（`core/cf-mcp/src/uds.rs` 逐帧 idle 读超时，commit 待 lead 收口）——accept 后 `set_read_timeout`（SO_RCVTIMEO，非阻塞读超时）：每读到数据即隐式重置计时（下一帧读窗从该帧处理完毕重新起算），超过超时值无任何数据到达 → 读返回 WouldBlock → 干净退出 0（连接生命周期完成，对照 peer 拒绝路径）；challenge / initialize 握手阶段同受窗约束（未完成握手的不活动同样超时断开）。缺省 120 s；env `COFFER_MCP_UDS_READ_TIMEOUT_SECS` 可配、下限 10 s（低于/非数字 → 配置错误退出 1）、**不提供 0=off 关闭路径**（fail-closed）。**边界诚实声明（任务口径）**：语义「任何数据到达重置」实现近似「**有效帧重置**」——逐字节慢滴（字节间隔 < 超时值）的非法/半帧数据流理论可维持连接存活（慢滴理论存活）；LOW-1 为 availability-only（非安全缺口），可用性意图（消除无界挂起）已满足，边界接受。复验 = `uds_idle_read_timeout_disconnects` / `uds_idle_timeout_resets_on_valid_frame` / `uds_active_session_not_timed_out` / `uds_handshake_inactivity_times_out` / `uds_idle_timeout_default_is_120s` / `uds_idle_timeout_below_min_rejected`（uds.rs 单测，docs/30 §1.5/§2 先红后绿）+ 既有 UDS 防护全套回归（peer / challenge / 单调 id / 单次 connect / 权限）全绿。缺省值 / 下限 / env 名已落 docs/20 §4.3
**证据**：`core/cf-mcp/src/uds.rs`（`UDS_ENV_READ_TIMEOUT` / `DEFAULT_READ_TIMEOUT_SECS` / `MIN_READ_TIMEOUT_SECS` / `set_read_timeout` / `is_idle_timeout`）；docs/28 §7 顺延登记（⏳ 目标 v2.2.0）

### 现象（预期/实际 分行写）

- 预期：UDS 连接建立后若对端不发数据，server 连接生命周期受控，不应无限期挂起。
- 实际：`uds.rs::run` accept 后无读超时——连接方不发数据则 server 挂起至对端动作（availability-only，非安全缺口）。

### 根因（已实证）

accept 后的读循环无超时窗；`set_read_timeout`（SO_RCVTIMEO）未设置，对端静默即无界挂起。

### 修复路径（2026-10-07 已落地，v2.2.0 G1d）

逐帧 idle 读超时（SO_RCVTIMEO，每读到数据重置 + 超时无数据 → 干净退出 0）；缺省 120 s、env 可配、下限 10 s、不提供关闭（fail-closed）。lead 裁定语义落 docs/30 §1.5（逐帧 idle / 握手同受窗约束）。

### 复现与诊断

`coffer mcp --uds <path>` 建立连接后不发数据 → 修复前 server 无限挂起；修复后超过超时值干净退出 0（socket 文件清理）。

---

## B-1（🟡 设计期登记）：item 模型新增 `origin_bindings` 字段的格式兼容——D-3 存储冻结后改格式须迁移

**登记日期**：2026-10-07（v2.3.0 设计期，docs/31 §10 风险 4「G-F 登记」）
**发现环境**：docs/31 §10 风险登记；docs/31a D-3（origin 三型冻结，🔴 不可逆存储格式类）
**分级**：S3（旧库升级路径，additive 字段非数据损坏）/ P2 / 来源版本 v2.3.0（计划）/ 发现版本 v2.3.0（设计期）
**状态**：🟡 设计期登记——D-3 已随用户批准冻结（2026-10-07），**实施待 G-A 落**（`origin_bindings` 字段 additive + `#[serde(default)]` 兼容旧库，零 format_version / DDL 变更）。**废弃（2026-10-09）**：浏览器扩展整体废弃（用户裁定，扩展连商城上架都不要），随 v2.3.0 App 侧集成移除；本登记作废留档，不实施
**核销记录**：—（实现后回填；预期 = G-A `cf-domain` item 模型新增字段 + 旧库读取回归全绿）
**证据**：docs/31 §10 风险 4；docs/31a D-3

### 现象（预期/实际 分行写）

- 预期：v2.3.0 新增 item 结构化 `origin_bindings` 字段后，旧版本库文件仍可正常打开读写，既有条目不丢。
- 实际：当前为设计期登记、实施未落地；若字段非 additive 破坏既有序列化布局，旧库升级将失败（待 G-A 实现后以测试核验）。

### 根因（已实证 / 待查）

待查（设计期）。缓解设计 = additive 字段 + `#[serde(default)]`（docs/29 D-3 先例），D-3 已冻结格式为三型
（exact / subdomain / domain，无 regex，匹配优先级 exact > subdomain > domain）；**发布后改格式 / 改类型集 =
既有条目绑定需迁移**（🔴 不可逆，docs/31a D-3）。

### 修复路径

G-A 实施时按 additive + `#[serde(default)]` 加字段（对齐 docs/29 §5.1 先例），零 format_version / DDL 变更；旧库读取单测覆盖；
发布后格式变更走 D-3 迁移流程（用户裁定后）。

### 复现与诊断

（实施后补）旧版库 → 升级新二进制读取 → 断言 `origin_bindings` 缺省为空、既有条目不丢、可正常写回。

---

## B-2（🟡 已接受残余）：扩展侧配对 PSK 存于 chrome.storage 的窃取面——PSK 单独不足以冒充

**登记日期**：2026-10-07（v2.3.0 设计期，docs/31 §10 风险 8「文档声明」）
**发现环境**：docs/31 §10 风险登记 8（T-7）
**分级**：S4（安全残余，非缺口——PSK 单因子不足）/ P3 / 来源版本 v2.3.0（计划）/ 发现版本 v2.3.0（设计期）
**状态**：🟡 已接受残余——缓解已定（认证链④须签名浏览器 ② 层 + 签名 host ③ 层才可建立会话；PSK 可轮换），本文档声明即缓解落地。**废弃（2026-10-09）**：浏览器扩展整体废弃，随 v2.3.0 App 侧集成移除；本残余登记作废留档（扩展仓保留，README 已标废弃）
**核销记录**：—（无修复意图；随 v2.3.0 安全门禁 G-R 按 docs/10 §5 纪律复核）
**证据**：docs/31 §10 风险 8、§3.3（「扩展零密钥材料」界定：传输层材料属扩展持有边界）

### 现象（预期/实际 分行写）

- 预期：扩展侧配对 PSK 被窃取（chrome.storage 非安全存储面）不构成通道冒充。
- 实际：PSK 单独不足以冒充——认证链④仍须签名浏览器 + 签名 host 才可建立会话；PSK 泄露仅暴露重放面，可轮换，
  且 E2E 每会话独立密钥（ephemeral ECDH，前向保密）不使泄露回溯既往会话。

### 根因（已实证）

chrome.storage 非安全存储面；PSK 属扩展持有边界（传输层材料，非库密钥——与「扩展零密钥材料」界定显式区分，docs/31 §3.3）。

### 修复路径

不修（已接受残余）；缓解 = 认证链④依赖 ②③ 层签名验证 + PSK 轮换路径 + 本文档声明。G-R 安全门禁复核本条。

### 复现与诊断

（设计期接受项，不适用复现）实现后由 G-R 按 docs/10 §5 纪律复核本条边界声明是否与实现一致。

---

## BUG-15（✅ 已修复：测试侧组内顺序断言去序化）：cf-session `audit_orchestration::report_end_to_end` 门禁 flake——`updated_at DESC` 并列无次级排序键，同密码条目组内顺序不定

**登记日期**：2026-10-08
**发现环境**：G-A/G-B 返工后 default 全量门禁（`cargo test --workspace --no-fail-fast --offline -- --skip 极端kdf参数建库记录与解锁往返 --skip 千条搜索基线`，日志 /tmp/coffer-v200-dev/gb-shape-ws-default-rerun.log）
**分级**：严重级 S3（测试基建 flake，具门禁否决力——偶发假红）/ 优先级 P2 / 来源版本 v2.2.0（既有测试）/ 发现版本 v2.3.0
**状态**：✅ 已修复（2026-10-08，dev-tester 核销）——归因**测试侧缺陷**：判据（docs/10 §5 TC-WTW-08）只要求「三个清单各命中预期 item_id + 无误报」，**不约束组内顺序**，`report_end_to_end` 断言 `[dup1, dup2]` 属超规格，依赖 `ItemStore::list` 无次级键的并列顺序（非契约）→ 偶发反转。修复 = 重复组断言去序化（排序后比较成员集合），**不改生产代码**。
**核销记录**：修复 = `core/cf-session/tests/audit_orchestration.rs` `report_end_to_end` 重复组断言改排序后集合比较；复验 = 定向 `report_end_to_end` 连续 12/12 绿、`audit_orchestration` 全 binary 3/3 轮全绿（日志 /tmp/coffer-wave4/bug15-{baseline,fixed,fullbin}.log）
**证据**：`/tmp/coffer-v200-dev/gb-shape-ws-default-rerun.log:1331`（`report_end_to_end` panic：`duplicate_groups` 两条同密码条目组内顺序反转为 `[dup2, dup1]`，断言期望 `[dup1, dup2]`）

### 现象（预期/实际 分行写）

- 预期：`cf-session/tests/audit_orchestration.rs:126` 断言 `duplicate_groups == vec![vec![dup1, dup2]]`——两条同密码条目组内按创建顺序。
- 实际：一次门禁运行中报告为 `[dup2, dup1]`（反转），断言失败；隔离单跑 6/6 全绿、后续全量重跑未复现——随机触发。

### 根因（已定位，非全实证）

`ItemStore::list` 为 `ORDER BY updated_at DESC`（`core/cf-store/src/repo/item.rs:223`）且**无次级排序键**：同毫秒/同精度内先后创建的条目 `updated_at` 并列时，SQLite 对并列行的返回顺序不保证（rowid/插入序为常见实现但非契约）→ `fps` 输入顺序不定 → `find_duplicate_groups`（`core/cf-audit/src/watchtower.rs:87`，BTreeMap 按指纹保序、组内保输入序）组内顺序随之不定。**与 G-A/G-B 改动无关**：cf-session 不依赖 cf-mcp（依赖清单核实；cf-browser 已随扩展废弃移除）。

### 修复路径

① ✅ **已落地（2026-10-08，dev-tester 核销）**：`report_end_to_end` 重复组断言改为排序后集合比较——判据只要求命中与无误报（docs/10 §5 TC-WTW-08），组内顺序非契约，断言 `[dup1, dup2]` 属超规格。测试侧缺陷，已自行修复，不改生产代码。
② ⏳ **顺延建议（非阻塞，生产侧）**：`ItemStore::list` `ORDER BY updated_at DESC` 补次级排序键（如 `, uuid`）使 UI 列表并列顺序稳定——S3 级一致性问题，**非报告契约违约**（Watchtower 报告不承诺组内顺序），交 cf-session coder / lead 择期评估；本 flake 修复不依赖其落地。

### 复现与诊断

随机触发（并列 + SQLite 实现细节），无法可靠本地复现。已记录一次失败证据见上；修复前基线隔离复验 `cargo test -p cf-session --test audit_orchestration report_end_to_end -- --exact` 8/8 绿（flake 随机触发，隔离不可复现属预期）。修复后复验（2026-10-08）：`report_end_to_end` 定向连续 12/12 绿；`audit_orchestration` 全 binary 3 轮全绿——修复消除了顺序依赖本身，故并列翻转不再具失败力。

---

## M-2（🟡 顺延登记）：BrokerIdentity::derive 派生域调整受冻结 KAT 帧约束——改域须重冻结跨语言断言，成本高于 MEDIUM 收益

**登记日期**：2026-10-08
**发现环境**：v2.3.0 G-R 安全审查（reviewer-browser 首轮，评审面 G-A..G-E 全部改动）MEDIUM 项 M-2
**分级**：S3（安全卫生，非缺口——派生域可辨，无非预期碰撞）/ P3 / 来源版本 v2.3.0（设计期）/ 发现版本 v2.3.0
**状态**：🟡 顺延登记——本次不修，随下次 KAT 重冻结窗口协同处理。**废弃（2026-10-09）**：浏览器扩展整体废弃（用户裁定，扩展连商城上架都不要），随 v2.3.0 App 侧集成移除；本顺延登记作废留档，不重冻结
**核销记录**：—（待重冻结时 G-C 协同，lead 裁定 2026-10-08）
**证据**：docs/31 §3.3 冻结 KAT 帧 md5=`ef82fd23434b8857f010e7fadb93c057`（跨语言字节级断言，G-A/Rust 与 G-C/TS 双侧一致）

### 现象（预期/实际 分行写）

- 预期：`BrokerIdentity::derive` 派生域（domain separation）可独立演进以符合 DR 语义。
- 实际：改派生域即改变 broker identity seed → 破坏冻结 KAT 帧（md5=`ef82fd…`）的逐字节跨语言断言，须 G-A/G-C 双侧协同重冻结 + 更新 docs/31 §3.3 锚。修复成本高于 MEDIUM 收益，顺延。

### 根因（已实证）

冻结 KAT 帧是 v2.3.0 E2E 契约的交叉语言互操作锁（docs/31 §3.3）：任意密钥派生改动都要求双侧向量同步重算并重锁。

### 修复路径

（待排期）随下一次 KAT 重冻结窗口一并做：G-A/Rust 与 G-C/TS 双侧重算冻结向量 + 更新 docs/31 §3.3 锚与 KAT 断言常量，同一提交内完成以保持跨语言字节一致。本次不修。

### 复现与诊断

不适用（设计期顺延项，非缺陷复现）。处置依据：lead 裁定「成本高于 MEDIUM 收益」2026-10-08。

---

## M-4（🟡 顺延登记）：origin 绑定手势/TTL/持久化属 merge-time 集成——绑定键含 action 触及 D-3 冻结语义不重开

**登记日期**：2026-10-08
**发现环境**：v2.3.0 G-R 安全审查 MEDIUM 项 M-4（手势确认 + 绑定 TTL + 持久化归 G-D/G-T merge-time）
**分级**：S3（安全卫生——手势/持久化非本次 Wave 落地面）/ P3 / 来源版本 v2.3.0（设计期）/ 发现版本 v2.3.0
**状态**：🟡 顺延登记——绑定键含 action 触及 D-3 冻结语义，不重开已冻结设计。**废弃（2026-10-09）**：浏览器扩展整体废弃（用户裁定，扩展连商城上架都不要），随 v2.3.0 App 侧集成移除；本顺延登记作废留档，不 merge-time 承接
**核销记录**：—（merge-time 由 G-D 集成方案 / G-T 判据承接，lead 裁定 2026-10-08）
**证据**：docs/31 §5 填充流（手势确认基线）、D-3 origin_bindings 冻结语义、G-D H-2/3 集成设计

### 现象（预期/实际 分行写）

- 预期：origin 绑定具备手势确认、TTL 过期、可持久化。
- 实际：三者均属浏览器填充链的集成面（G-D 原生桥接线 / G-T 判据），本次 Wave 未落地；绑定键含 action（`origin‖action`）触及 D-3 已冻结的 origin_bindings 语义，不重开。

### 根因（已实证）

手势+TTL+持久化需要在 host↔App 集成（H-2/H-3 接线）完成后才有承载面；绑定键域已随 D-3 冻结，改动即破坏契约锚。

### 修复路径

（merge-time）G-D 集成方案承接手势/TTL/持久化承载；G-T 判据登记「broker 接线后 get_entries 须按 origin 过滤」；绑定键保持 D-3 冻结域不重开。本次不修。

### 复现与诊断

不适用（设计期顺延项）。处置依据：lead 裁定 2026-10-08。

---

## M-6（🟡 顺延登记）：Swift spawn 写 stdin 非 throwing `write(payload)`——broker 早退时 EPIPE 触发 NSFileHandleOperationException → App 崩溃

**登记日期**：2026-10-08
**发现环境**：v2.3.0 集成轮 G-R 复审（da237da 5 文件独立验证）MEDIUM-1
**分级**：S3（当前 dormant——brokerStdinSecrets()=nil 不 spawn，接线后暴露）/ P2 / 来源版本 v2.3.0（集成轮）/ 发现版本 v2.3.0
**状态**：🟡 顺延登记——归 merge-time 接线轮（§8 第 4 项 DEK 来源接线时一并处理）。**废弃（2026-10-09）**：浏览器扩展整体废弃，随 v2.3.0 App 侧集成移除（BrowserIntegration.swift 已删）；本顺延登记作废留档
**核销记录**：—（merge-time 接线轮，G-R 建议「接线前处理」，lead 裁定 2026-10-08）
**证据**：macos/Coffer/Platform/BrowserIntegration.swift spawn 内 `stdinPipe.fileHandleForWriting.write(payload)`；G-D §8 第 4 项未接线

### 现象（预期/实际 分行写）

- 预期：broker 在 spawn 后即时死亡（如 --uds 参数异常早退）→ 写 stdin 失败 → App 进入 .failed 状态（fail-closed 呈现）。
- 实际：`write(payload)` 非 throwing → EPIPE 触发 `NSFileHandleOperationException`（Objective-C 异常，非 Swift error）→ **App 崩溃**而非 .failed。

### 根因（已实证）

Foundation `FileHandle.write` 对 EPIPE 抛 Objective-C 异常而非 Swift error；当前 seam nil 处于 dormant，接线后 spawn 路径激活即暴露。

### 修复路径

（merge-time 接线轮）改 throwing 变体 `try write(contentsOf:)` + catch 归入 spawn 失败路径（.brokerSpawnFailed / .failed 呈现）；随 §8 第 4 项 DEK/UUID/PSK 取值接线同一提交落地。

### 复现与诊断

不适用（dormant——brokerStdinSecrets() 现恒 nil，spawn 未被调用）。处置依据：G-R MEDIUM-1 + lead 裁定 2026-10-08。

---

## M-7（🟡 已接受残余）：Swift zeroize COW 脆弱性——只零化序列化副本，源串/中间拷贝不零化（best-effort 纵深）

**登记日期**：2026-10-08
**发现环境**：v2.3.0 集成轮 G-R 复审（da237da）MEDIUM-2
**分级**：S3（纵深卫生——H-3 实质成果「密钥不经 env/argv」不因此受损）/ P3 / 来源版本 v2.3.0（集成轮）/ 发现版本 v2.3.0
**状态**：🟡 已接受残余——归 merge-time 引入密钥类型（SecretString 单 owner）时收口；同类：read_stdin_to_eof 超时后 reader 线程缓冲 dropped 不零化（进程将退出，边际）+ 512B chunk 栈数组不零化（G-R LOW L-1）一并在此账。**废弃（2026-10-09）**：具体实例（browser spawn 的 DEK/UUID/PSK zeroize）已随浏览器集成移除（BrowserIntegration.swift 已删）；general 纵深卫生如仍需要，另行登记
**核销记录**：—（merge-time 密钥类型轮，lead 裁定 2026-10-08）
**证据**：macos/Coffer/Platform/BrowserIntegration.swift `zeroize` 仅零化传入的 inout Data 副本；源 String（CoW）恒不零化

### 现象（预期/实际 分行写）

- 预期：DEK/UUID/PSK 材料生命周期内所有缓冲副本零化。
- 实际：spawn 内 `var local = payload` + `zeroize(&local)` 只零化 COW 拷贝（真实缓冲靠 AppModel 引用计数回 1 后释放）；`secrets` 的 hex String 永不零化；spawn 栈帧中间 Data 拷贝释放不零化。属 best-effort 纵深。

### 根因（已实证）

Swift `Data`/`String` 为 COW 值类型——零化一个副本不触及共享底层缓冲；密钥类型未引入（merge-time）。

### 修复路径

（merge-time 密钥类型轮）引入单 owner 缓冲 / `SecretString` 类持有并在生命周期终点零化；stdin 源串接线时一并处理。本次不修（H-3 实质不损）。

### 复现与诊断

不适用（纵深卫生项）。处置依据：G-R MEDIUM-2 + lead 裁定 2026-10-08。

---

## LOW-2（🟡 merge-time 核验项）：well-known UDS 两端取径须一致——Swift userHomeDirectory(getpwuid) vs Rust $HOME

**登记日期**：2026-10-08
**发现环境**：v2.3.0 集成轮 G-R 复审 LOW L-3
**分级**：S4 / P3 / 来源版本 v2.3.0（集成轮）/ 发现版本 v2.3.0
**状态**：🟡 merge-time 核验项——正常 GUI 启动路径 $HOME==pw_dir（Design Y 非沙盒）；自定义 HOME 启动会错位 → fail-closed 功能断（非安全缺口）。**废弃（2026-10-09）**：well-known broker UDS 已随浏览器集成移除（BrowserStatusProbe 已删），本核验项作废留档
**核销记录**：—（merge-time 接线轮核验，lead 裁定 2026-10-08）
**证据**：Swift `BrowserStatusProbe.userHomeDirectory()` = getpwuid(pw_dir)；Rust `well_known_broker_uds()` = `$HOME`（冻结 §4.2/§6 明示许可「libc getpwuid 或 $HOME 兜底」）

### 现象（预期/实际 分行写）

- 预期：App spawn broker 传 `--uds <getpwuid路径>`，host 以 `$HOME` 计算 well-known——正常路径两侧一致。
- 实际：`launchctl setenv HOME=...` 或自定义启动环境使 $HOME ≠ pw_dir → App（getpwuid）与 host（$HOME）计算不同 socket 路径 → host 连不上 broker → fail-closed 功能断（无安全后果）。

### 根因（已实证）

冻结规格对 Rust 侧明示允许 $HOME；两侧取径源不同，依赖 GUI 会话 $HOME==pw_dir 的常态成立。

### 修复路径

（merge-time 核验）接线轮在真实启动环境核验两侧落点一致；若需抗 HOME 篡改可后续引入 sys 封装 getpwuid（cf-uds-sys 先例）。本次不修。

### 复现与诊断

不适用（核验项）。处置依据：G-R LOW L-3 + lead 裁定 2026-10-08。

---

## NOTE-1（🟢 知悉项，非缺陷）：空库错 DEK 不被 verify_integrity 检出（自举分支用错 key 重写基线）

**登记日期**：2026-10-08
**发现环境**：merge-time 接线轮组 A（session-seam）`unlock_with_dek` 直开 seam 实现时如实发现
**分级**：S4（防御纵深注记，无实际攻击路径）/ P3 / 来源版本 既有 / 发现版本 v2.3.0（merge-time 轮）
**状态**：🟢 知悉项——cf-store `verify_integrity` 既有行为（docs/07 §5 C-4 旧库兼容自举语义），**非本 seam 引入**；不阻塞。**失效注记（2026-10-09）**：触发 seam `unlock_with_dek` 已随 v2.4.0 DEK retention 层整体裁除（浏览器集成移除轮），本注记核心关注点（直开 seam 空库错 DEK）路径不再可达；cf-store 自举语义本身不变，登记留档
**核销记录**：—（知悉项；如需空库也 fail-closed 属 cf-store 改动，另议）
**证据**：`core/cf-store/src/repo/meta.rs:180-215`——`(stored_count, stored_mac)` 任一行缺失 → `bump_integrity(key)` 自举；`core/cf-session/src/unlock.rs:378-388` finish_unlock 调 `verify_integrity(&store.subkeys().root_mac_key)`

### 现象（预期/实际 分行写）

- 预期：错 DEK 直开（`unlock_with_dek`）在任何库态都 1002 fail-closed。
- 实际：**空库**（无条目、无 root_mac 基线）下错 DEK 走自举分支——用错 key 重写基线 → 返回 Ok。`「错 DEK → 1002」仅在有基线（≥1 条目）时成立`。

### 根因（已实证）

`verify_integrity` 对「meta 基线缺失」采用自举（旧库兼容，docs/07 §5 C-4）：缺行即用传入 key 重算基线落盘。空库首次打开时无基线 → 任何 key 都触发自举。属既有设计，非 unlock_with_dek 引入。

### 修复路径

不修。broker 场景 DEK 恒来自 App 自身解锁会话（正确 DEK），空库 + 错 DEK 无实际到达路径；防御纵深上边际价值有限。若后续需空库也 fail-closed：可在自举分支加「空库快照校验」（如 header wrapped_dek verifier 对照），属 cf-store 改动另议。

### 复现与诊断

空库 + 任意非正确 32B DEK 直开 → Ok（verify_integrity 自举）。处置依据：组 A 如实发现 + lead 裁定 2026-10-08（知悉项，不阻塞）。

---

## BUG-16（✅ 已核销：拒绝提示可达，真机实证）：批准 sheet 点「拒绝」→ 扩展侧「配对已拒绝」提示缺失（初始报告）——实为 popup 不实时刷新所致

**登记日期**：2026-10-08
**发现环境**：cygnus 真机（FR-16.1 前置批准 sheet 真机验收中，用户主动拒绝测试）
**分级**：严重级 S3（次要功能——拒绝决策本身已生效（sheet 关、不配对），初始缺失的是扩展侧用户反馈提示）/ 优先级 P2 / 来源版本 v2.3.0（FR-16.1）/ 发现版本 v2.3.0
**状态**：✅ 已核销（2026-10-08 用户真机实证：**扩展侧可以拿到「配对已拒绝。可重新发起配对。」**，提示正常渲染）。**废弃（2026-10-09）**：浏览器扩展整体废弃，随 v2.3.0 App 侧集成移除；本核销登记留档
**核销记录**：真机复核（2026-10-08，用户反馈「浏览器的插件上是可以拿到'配对已拒绝'的」）；代码路径 `src/ui/popup.ts` renderState `ErrCode.UserRejected`（8006）→「未连接 + 配对已拒绝。可重新发起配对。」+ `src/background.ts` `handlePairResult`（approved:false → `applyPairingEvent(result, pairRejectErrorCode(reason))` → 8006）+ `pairing.test.ts` 拒绝态状态机覆盖均已在架（修复前即存在，无需代码改动）。初始「无提示」观察归因 = **popup 不实时刷新**：popup 仅在打开时 `load()` 拉一次 `get_state`（`src/ui/popup.ts` DOMContentLoaded），期间拒绝在 App 侧发生 → 已打开的 popup 保持旧态，需重开 popup（或点「刷新」）才显示拒绝提示——非拒绝链路断裂。残留子项 **popup 无实时状态推送（LOW）已闭合**：FR-16.2（用户裁定 2026-10-08）给 popup 加 `chrome.runtime.onMessage` 监听 background `{type:state}` 广播实时重拉，并移除「刷新」按钮（扩展仓 2f0de9b，测试 77/77）。

### 现象（预期/实际）
- **预期**：App 点「拒绝」→ sheet 关 → 扩展 popup 显示「配对已拒绝」（契约 §8-3 拒绝路径 + popup 三态文案区分——docs/32 §1.4「pair_result reason 单通道」判据真机复核点）。
- **实际（初始）**：sheet 正常关闭，**已打开的**扩展 popup 无任何「已拒绝」提示（popup 打开期间状态不刷新，需重开/刷新才渲染）。
- **实际（复核）**：重开 popup（重新拉取 `get_state`）→ 正常显示「未连接 + 配对已拒绝。可重新发起配对。」（2026-10-08 用户真机实证）。

### 根因（已实证 / 待查）
**已实证**：拒绝链路完整在架且可达——App `rejectPendingPairing` → responder 转发 → broker pair_result(approved:false, reason:rejected) → 扩展 `handlePairResult` → 8006 → popup 渲染拒绝提示。初始「无提示」= popup 只在打开时拉一次状态、**无 live state push**（background `setState` 虽广播 `{type:"state"}`，但 `popup.ts` 未监听该消息）→ 打开中的 popup 过期不刷新。~~候选①③（seam 断裂 / 结果只落 background）排除~~。

### 修复路径
已核销，无需修复。残留：popup 实时刷新缺失（LOW）——与「刷新」按钮去留联动（见会话记录 / docs/31 §2.4）：若 popup 监听 `{type:"state"}` 实时刷新，「刷新」按钮即冗余可删（用户 2026-10-08 提出两按钮去留评估）。

### 复现与诊断
扩展发起配对 → App 弹 sheet → 点「拒绝」→ 观察扩展 popup：**保持打开时**无提示（旧态）；**重开 popup** 显示「配对已拒绝。可重新发起配对。」（已核销）。

---

## BUG-17（🟡 已实现（待真机核销）：超时锁定后窗口可见状态下再次打开不弹 Touch ID）

**登记日期**：2026-10-09
**发现环境**：cygnus 真机（v2.4.0 移除轮后，用户手动触发自动锁定后再次打开观察）
**分级**：严重级 S3（次要交互——解锁可达（LockView 手点），缺的是自动引导便捷性）/ 优先级 P2 / 来源版本 既有（用户 2026-10-03 裁定自动引导起即有，非回归）/ 发现版本 v2.4.0
**状态**：🟡 **已裁定「是」（2026-10-09 用户裁「是」），随 v2.5.0 实现**——用户 2026-10-09 提出「coffer 超时锁定后再次打开没触发 Touch ID」；**既有已知未裁定行为**（代码注释明示，非回归）：窗口开着时自动锁定后再解锁不自动弹（用户未裁定，不实现）。用户补充动机（2026-10-09 截图+说明）：主密码有时会忘记，期望 Touch ID 始终可解锁——LockView 手点入口已在（L75，「使用 Touch ID 解锁」，`touchIDStatus == .enabled` 时显示），缺的是**可见窗口锁定态激活时自动弹**（需求=启动自动引导同体验）。**深挖**：用户动机暴露的是主密码遗忘恢复缺口 → 已立项 FR-17.1 / FR-17.2（`01-需求分析.md` §5-Q，v2.5.0，用户裁定 A+B 都做）。**已实现（2026-10-09，v2.5.0）**：commit `6b983a9`（App 侧触发面扩展）+ `5b1e516`（回归测试），完整构建 BUILD_EXIT=0——**待真机核销**（可见窗口锁定态激活弹 Touch ID）
**核销记录**：修复版本 **v2.5.0**（2026-10-09）；修复 = commit `6b983a9`（App 侧：`summonMainWindow` 去 `wasHidden` 门 + AppDelegate `applicationDidBecomeActive` 钩子，覆盖可见窗口锁定态激活）+ `5b1e516`（回归测试：`AutoPromptBiometricTests` 可见锁定态激活允许一次提示）——完整构建 BUILD_EXIT=0；**待真机核销**（可见窗口锁定态激活弹 Touch ID，核销后回填复验记录）
**证据**：`macos/Coffer/CofferApp.swift:150-168` summonMainWindow——`let wasHidden = !window.isVisible`，仅 `wasHidden` 才调 `maybeAutoPromptBiometric`；注释「窗口本就可见（自动锁定后直接手点解锁）不自动弹（用户未裁定，不实现）」。`macos/Coffer/AppModel.swift:391-404` maybeAutoPromptBiometric——`phase == .locked` 前置 + `AutoPromptBiometric.shouldAutoPromptBiometric`（vaultCount==1 ∧ 支持 ∧ .enabled ∧ 未弹过 ∧ !isBusy）+ `session.hasBiometricWrap()`；`autoPromptBiometricFired` 一次性旗标（L38，phase 离开 .locked 复位 L44-46）。`macos/Coffer/Support/AutoPromptBiometric.swift` 纯函数判定

### 现象（预期/实际 分行写）
- **预期**：App 超时自动锁定后，用户再次打开/激活窗口即弹 Touch ID 认证框（与启动自动引导同体验）。用户补充：主密码可能忘记，Touch ID 应始终可解锁。
- **实际**：窗口在超时时**保持可见**（未被隐藏）→ 用户点窗口/激活 → `wasHidden == false` → `maybeAutoPromptBiometric()` 不被调用 → 不弹 Touch ID → 落到 LockView 手点「Touch ID 解锁」/输主密码。手点入口存在（`macos/Coffer/Views/LockView.swift:75`），但需**主动点一次**，非自动。
- **边界**：窗口**从隐藏恢复**（关窗驻留/⌥⌘P 呼出）时 `wasHidden == true` → 会弹（既有行为正常）。

### 根因（已实证 / 待查）
**已实证**：触发面只覆盖「窗口从隐藏恢复」，未覆盖「窗口可见态下的锁定 → 激活」。注释明示为**未裁定行为**（用户 2026-10-03 只裁了启动/呼出自动引导）。非回归——自 2026-10-03 起一直如此。

### 修复路径
**已裁定（2026-10-09 用户裁「是」）**：`summonMainWindow` 去掉/放宽 `wasHidden` 门（或改在激活回调里统一调 `maybeAutoPromptBiometric`），使**可见窗口锁定态激活也自动弹 Touch ID**（与启动自动引导同体验）；复核 `autoPromptBiometricFired` 防重入（避免手点取消后反复骚扰）。随 v2.5.0（FR-17.1 生物识别重置主密码）一并交付，回归测试入 AutoPromptBiometricTests。

### 复现与诊断
设置自动锁定 → 打开库（窗口保持可见）→ 空闲至自动锁定 → 点窗口激活 → 观察：无 Touch ID 弹框，仅 LockView。对照：⌥⌘P 呼出（窗口从隐藏恢复）→ 弹 Touch ID。

---

```
## BUG-N（🔴/🟡/✅ 状态）：一句话标题

**登记日期**：YYYY-MM-DD
**发现环境**：
**分级**：严重级 S1~S4 / 优先级 P1~P3 / 来源版本 / 发现版本
**状态**：
**核销记录**：修复 commit + 复验测试名/验收方式（核销时回填）
**证据**：（日志/截图路径）

### 现象（预期/实际 分行写）
### 根因（已实证 / 待查）
### 修复路径
### 复现与诊断
```
