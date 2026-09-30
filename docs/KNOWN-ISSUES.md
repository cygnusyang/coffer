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

## BUG-9（🟡 判据修正待回填 docs/15）：socket 清点判据命令 `lsof -i -p <pid>` 缺 `-a`——OR 语义下「空输出断言」结构性不可满足

**登记日期**：2026-09-29
**发现环境**：v0.4.0 发版回归（任务 #8）TC2-B 实跑，带阳性对照
**分级**：S3（测试判据）/ P2 / 来源版本 docs/15 r1.1（0 socket 判据映射引入时） / 发现版本 v0.4.0（发版回归）
**状态**：🟡 docs/16 已按正确口径落条（r1.6）；docs/15 §3.3.2 原文待 architect 同工单修正
**核销记录**：docs/15 §3.3.2 命令改为 `lsof -a -i -p <pid>` 后由下一轮回归复验（本轮已实跑正确命令：Coffer 运行态 0 行 / 阳性对照 2 行，判据②实质通过）
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

## BUG-10（🟡 处置中：T8 已改 opt-in，根因待查）：真实库回环段无人值守执行挂起——`listVaults` 于容器路径 `opendir` 阻塞

**登记日期**：2026-09-29
**发现环境**：v0.4.0 发版回归（任务 #8），`run_clipboard_tier_tests.sh` 无人值守实跑（两次复现）
**分级**：S3（测试基建）/ P2 / 来源版本 早期（T8 默认指向容器路径的行为先于 docs/14 §5 禁令） / 发现版本 v0.4.0（发版回归）
**状态**：🟡 T8 改显式 opt-in（回归批内已改脚本）；挂起根因待查
**核销记录**：脚本修订即视为处置完成（T8 转用户陪跑/真机清单）；根因查清后可另行关闭
**证据**：`~/.claude/jobs/dc7a41d3/tmp/regress_clipboard2.log` / `regress_clipboard3.log`（二进制零输出挂起）；`/usr/bin/sample` 栈——`main → listVaults(baseDir:) → uniffi…list_vaults → std fs read_dir → opendir → open$NOCANCEL` 单点阻塞（2 秒采样 1550 样本全在该栈）；同路径 shell `ls` 实测正常（阳性对照：`~/.cargo/bin` 与容器路径均秒回）

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
**状态**：🟡 显式顺延（缓解已内置：预检将此类行逐条列入 bad_passkeys/不可导入清单，用户可见、不静默丢弃；条目本体照常导入）
**核销记录**：待回填（修复版本 + 测试名）

### 现象（预期/实际 分行写）

- 预期：FR-10.1 降级导入——Bitwarden JSON 导出中的 passkey（fido2Credentials）可导入为库内 passkey 行。
- 实际：Bitwarden **真实未加密导出**中 passkey 私钥字段 `encryptedPrivateKey` 恒为 EncString 加密形态（attach key 不随导出解包）——PK2 解析器将其列入 bad_passkeys，passkey 行实际全部不可导入；仅合成/手工构造的明文 PKCS#8 JSON 可导入。调研 v2「Bitwarden JSON 导出含 passkey」的【文档】级结论对私钥字段不成立（导出含条目、不含可用私钥）。

### 根因（已实证 / 待查）

已实证：EncString 形态由 Bitwarden 客户端导出模型决定（非 Coffer 解析缺陷）。修复需支持 Bitwarden **密码保护导出格式**（EncString 经用户主密码解密）——独立特性面（KDF + AES 解密链），非小改。

### 修复路径

1. 支持 Bitwarden password-protected export 解密（用户输入导出密码 → 解出 fido2Credentials 私钥 → 归一化 PKCS#8）——目标版本待定（ADP/后续版本卡均可，量级 ≈ 1 周内）；
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
**核销记录**：2026-09-30 核销——裁定=用户「删孤儿+撤专用步骤」（删除根 `tests/acceptance_v05.rs` + 移除 rust.yml「Run acceptance tests」「Upload acceptance test log」两步）；修复=commit `4eaa393`（PW FFI 批内，dev-coder-ffi）；复验=CI `Run tests` 步骤（working-directory: core）跑全量测试含 `v05_ffi_semantics`（v0.5 验收真身，8 用例全绿）。
**证据**：`.github/workflows/rust.yml` 原 Build/Run tests/Run acceptance 均在仓库根跑 `cargo`（根无 Cargo.toml，workspace 在 `core/`）；`tests/acceptance_v05.rs` 位于根 `tests/` 且无根 manifest 归属。

### 现象（预期/实际 分行写）

- 预期：main 分支 push/PR 时 CI 执行构建、全量测试、v0.5 验收、MCP 冒烟。
- 实际：既有三个 cargo 步骤在根执行必报 `could not find Cargo.toml`；`acceptance_v05` 无 manifest 归属，任何工作目录下 `cargo test --test acceptance_v05` 都找不到 target。

### 处置（用户 2026-09-30 两轮裁定：先「加 working-directory: core」、后「删孤儿+撤专用步骤」）

- Build / Run tests 已补 `working-directory: core`（随 `33a9e27` 后的 lead CI 修复落地）；
- MCP smoke 步骤自包含（脚本内部 cd 到 `core/`）保持在根执行；
- `Run acceptance tests` / `Upload acceptance test log` 两步已移除、根 `tests/acceptance_v05.rs` 已删除（随 `4eaa393`）——用户 2026-09-30 再裁定「删孤儿+撤专用步骤」；v0.5 验收真身 = `core/cf-ffi/tests/v05_ffi_semantics.rs`，由 `Run tests`（working-directory: core）覆盖，无需专用步骤。
- 注：workspace `cargo test` 含 MCP D-1 基线的 23 条预期红灯（v2.x 存根），CI 全绿需等 v2.0.0 MCP 存根补齐。

---

## M-1（🟡 登记待后续处理）：run_with_secret 目标子进程 stderr 整体吞掉 + 子进程继承 OP_SESSION（blast-radius 未文档化）

**登记日期**：2026-09-30
**发现环境**：dev-reviewer 对 G-C（mcp-op）审查发现，非阻断项（docs/20 §9.1 G-F 登记）
**分级**：严重级 S3（dev-reviewer 判 MEDIUM——子进程 stderr 对调用方不可见，且 OP_SESSION 落入目标子进程 env 的 blast-radius 未明示）/ 优先级 P2 / 来源版本 v2.0.0（MCP，docs/20 §4.2） / 发现版本 v2.0.0（G-C 审查）
**状态**：🟡 登记待后续处理（MVP 保持现状可接受，需架构裁定透传/日志化取舍）
**核销记录**：待回填
**证据**：`core/cf-mcp/src/provider/op.rs` run_with_secret（`cmd.stdout(Stdio::null())` + `output()` 捕获 stderr 仅作 op 层分类，不向调用方透出）；`op_command()` 设 `OP_SESSION`，经 `op run` spawn 的目标子进程继承之

### 现象（预期/实际 分行写）

- 预期：目标子进程 stderr 可被 Agent/用户排查；OP_SESSION 的暴露面（blast-radius）在文档中明示。
- 实际：run_with_secret 丢弃子进程 stdout（协议帧纪律，§3.1），stderr 仅在 op 层错误分类时被消费、其余整体吞掉——子进程输出对调用方不可见；目标子进程经 `op run` 继承含 `OP_SESSION` 的完整环境（若子进程打印 env 或经 `/proc` 泄露，会话 token 暴露半径含任意被注入 secret 的进程）。

### 根因（已实证）

stderr 捕获后归一为稳定错误文案（剥离敏感值，§3.5-4 日志禁值纪律），**无向调用方透传子进程 stderr 的通道**；`OP_SESSION` 继承是进程环境语义（非缺陷，属设计），但 blast-radius 未文档化。

### 修复路径（候选，未拍板）

1. 文档明示 blast-radius（docs/20 §3.5/§4.4 补一句：`op run` 启动的目标子进程继承 `OP_SESSION`，须视为凭据暴露半径的一部分）；
2. 子进程 stderr 透传/日志化取舍：stdout 恒为协议帧不可让渡，stderr 可经日志文件（`COFFER_MCP_LOG`）落盘或加开关透传——泄露面 vs 可诊断性，需架构裁定；
3. 不动作（MVP 保持吞掉）亦可接受——登记留档。

### 复现与诊断

fake op fixture + 子进程写 stderr（`sh -c 'echo oops >&2; exit 1'`）→ run_with_secret 返回 `Ok(1)`，stderr 对调用方不可见；目标子进程内 `printenv | grep OP_SESSION` 可见 token 已注入。

---

## M-4（🟡 登记待协商）：run_with_secret 缺省 env_name 取整个 secret 串——`op://` 引用必 7005

**登记日期**：2026-09-30
**发现环境**：dev-reviewer 对 G-C 审查发现，跨层联动（G-B `tools.rs` 缺省 vs G-C `op.rs` 校验），非阻断项（docs/20 §9.1 G-F 登记）
**分级**：严重级 S3（dev-reviewer 判 MEDIUM——带 `op://` 引用且省略 env_name 的 run_with_secret 调用恒 7005，功能面缺口）/ 优先级 P2 / 来源版本 v2.0.0（MCP，G-B/G-C 契约） / 发现版本 v2.0.0（G-C 审查）
**状态**：🟡 登记待协商（属 G-B/G-C 契约联动，需协商确定 env_name 缺省语义；改 API 签名触 D-1 冻结契约需用户确认）
**核销记录**：待回填
**证据**：`core/cf-mcp/src/tools.rs:218` `optional_string(args, "env_name").unwrap_or_else(|| secret.clone())`（缺省取整个 secret 串）；`core/cf-mcp/src/provider/op.rs` `is_valid_env_name`（`[A-Za-z_][A-Za-z0-9_]*`）——`op://vault/item/field` 含 `/`/`:` 必不匹配 → 7005

### 现象（预期/实际 分行写）

- 预期：缺省 env_name 时注入到合理的默认变量名（或明确要求必填）。
- 实际：tools.rs 缺省取**整个 secret 串**作 env_name——对 `op://vault/item/field` 引用恒 7005（`InvalidParameter`）。run_with_secret 的 inputSchema 标注「default: the secret name」，对 `op://` 形态不成立。

### 根因（已实证）

G-B 工具层把 env_name 缺省定义为「secret 名」，对 `op://` 引用的「名字」理解与 G-C 的 env 名合法性校验不一致——`op://vault/item/field` 整串不是合法环境变量名。跨层契约缺口。

### 修复路径（候选，需协商）

1. env_name 改必填（inputSchema `required` 增 env_name）——API 签名变更，触 D-1 冻结契约，需用户确认；
2. 缺省取 `op://` 引用末段（field/item 名）作默认变量名——需定义「从引用提取默认变量名」规则（field 歧义，见 L-3）；
3. 文档明示：`op://` 形态必须显式给 env_name（最小改动）。

### 复现与诊断

`run_with_secret {secret: "op://Personal/OPENAI_API_KEY/password", cmd: "env"}`（省略 env_name）→ 7005 InvalidParameter。

---

## L-1（🟡 LOW）：临时 dotenv 非 unix 分支无 0600 权限约束

**登记日期**：2026-09-30
**发现环境**：dev-reviewer 对 G-C 审查（L 系列，可选登记项）
**分级**：S4 / P3 / 来源版本 v2.0.0（MCP，docs/20 §4.2） / 发现版本 v2.0.0（G-C 审查）
**状态**：🟡 登记待后续处理
**核销记录**：待回填
**证据**：`core/cf-mcp/src/provider/op.rs` `TempDotenv::write`——`#[cfg(unix)]` 分支 `OpenOptionsExt::mode(0o600)`，`#[cfg(not(unix))]` 分支 `File::create` 无权限约束

`TempDotenv` 内容仅 `ENV_NAME=op://…` 引用（无明文值，§4.4），cf-mcp 目标平台 macOS（unix）故当前无实际暴露；非 unix 分支权限缺口登记留档。修复 = 非 unix 分支补平台权限 API，或随不支持的平台一并拒编译。

---

## L-2（🟡 LOW）：临时 dotenv `create_new` 撞名直接 7006，无重试

**登记日期**：2026-09-30
**发现环境**：dev-reviewer 对 G-C 审查（L 系列，可选登记项）
**分级**：S4 / P3 / 来源版本 v2.0.0 / 发现版本 v2.0.0
**状态**：🟡 登记待后续处理
**核销记录**：待回填
**证据**：`core/cf-mcp/src/provider/op.rs` `TempDotenv::write` 用 `create_new(true)`——文件已存在则直接 `Internal`（7006）

路径含 pid + 进程内原子计数器（`temp_env_path`），跨进程由 pid 隔离、进程内由计数器保证，实际碰撞面 ≈ 0；无重试可接受，登记留档。

---

## L-3（🟡 LOW）：`op://vault/item/field` 末段恒判为 field——item 名含 `/` 的无 field 引用无法表达

**登记日期**：2026-09-30
**发现环境**：dev-reviewer 对 G-C 审查（L 系列，可选登记项）
**分级**：S4 / P3 / 来源版本 v2.0.0 / 发现版本 v2.0.0
**状态**：🟡 登记待后续处理（与 M-4 缺省 env_name 规则联动）
**核销记录**：待回填
**证据**：`core/cf-mcp/src/provider/op.rs` `parse_secret_ref`——`op://vault/item/field` 剥除末段作 field；item 名本身含 `/`（op 允许）且无 field 时歧义（`op://vault/a/b` 被解析为 item="a"、field="b"）

当前 `get_secret_metadata` 用其取 item，歧义会解析错 item；op 实测语义（末段 = field）与「item 名含 /」冲突面小，登记留档。必要时引入显式 field designation 语法。

---

## L-4（✅ 已接受）：`CofferStoreProvider` 骨架方法 `unimplemented!` 占位——v2.x 建模前调用即 panic

**登记日期**：2026-09-30
**发现环境**：dev-reviewer 对 G-C 审查（L 系列，可选登记项）
**分级**：S4 / P3 / 来源版本 v2.0.0 / 发现版本 v2.0.0
**状态**：✅ 已接受（设计内占位：feature `coffer-store` 默认关闭不进入普通构建；docs/20 §4.5 明示本版仅骨架，v2.x 存储模型落定后替换）
**核销记录**：随 v2.x CofferStoreProvider 落地核销
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

## L-5（🟡 LOW）：tools.rs `tracing::warn!` 无 subscriber——审计失败告警恒被丢弃

**登记日期**：2026-09-30
**发现环境**：dev-reviewer 对 v2.0.0 MCP 合并集终审（其 L-1，LOW）
**分级**：S4 / P3 / 来源版本 v2.0.0 / 发现版本 v2.0.0
**状态**：🟡 登记待后续处理
**核销记录**：待回填
**证据**：`core/cf-mcp/src/tools.rs:242` `tracing::warn!(error = ?e, secret = %secret, "audit record failed")`——仓库从未初始化 tracing subscriber

当前 NoopAudit 不会失败（不可达），但 D-3 JSONL 落地后审计失败将**静默**（违反「错误不静默吞」纪律）。修复 = 改用 `cli::Logger` 或初始化 subscriber / 文档化。

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

## L-7（🟡 LOW）：parse_frame 对单行长度无上限——恶意/失控客户端可发超大单行造成内存压力

**登记日期**：2026-09-30
**发现环境**：dev-reviewer 对 v2.0.0 MCP 合并集终审（其 L-3，LOW）
**分级**：S4 / P3 / 来源版本 v2.0.0 / 发现版本 v2.0.0
**状态**：🟡 登记待后续处理
**核销记录**：待回填
**证据**：`core/cf-mcp/src/protocol.rs:89-103` `parse_frame` 对单行长度无上限

本地 stdio 传输，影响面小；可选按行长度截断（超限报 7005/连接拒绝）。

---

## 模板（新条目按此格式追加）

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
