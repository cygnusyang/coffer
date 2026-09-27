# KNOWN-ISSUES —— 已知问题登记簿

> 本文件是 Coffer 项目**未修复缺陷与延后决策**的唯一登记处。
> 修复后请把状态改为 ✅ 并在 docs/06-开发计划.md 修订记录中注明。
> 登记纪律：每条必须有——现象、精确根因（有证据）、影响面、修复路径选项、当前状态。

---

## BUG-2（🔴 未修复，延后）：Touch ID 启用失败——Keychain -34018

**登记日期**：2026-09-27
**发现环境**：cygnus 真机（MacBookPro17,1 / macOS 26.6.2 / Touch ID 已录入）
**状态**：🔴 延后修复——等待签名身份决策（方案 A/B/C 见下）
**证据**：`~/Library/Containers/app.coffer.Coffer/Data/Library/Logs/Coffer-diag.log`（两条 -34018 记录）

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

### 修复路径（按优先级）

- **方案 A（推荐）**：cygnus 在 Xcode → Settings → Accounts 登录 Apple ID（免费账号即可），Xcode 自动生成「Apple Development」证书。构建脚本改用真证书签名 → DP 钥匙串 + biometryCurrentSet ACL 按原设计工作，**安全语义零妥协**。代码侧无需改动（`useDataProtection` 缝隙已就位）。
- **方案 B（立即可用，安全降级）**：`save/read` 改为 `requireBiometry: false`（去掉条目级 ACL），K_bio 以普通 ThisDeviceOnly 项存储；解锁时 App 层 LAContext 把关。**安全降级**：门禁从「系统强制」降为「App 自律」，理论上同用户权限的恶意程序可读取。需在 README 与 docs/08 标注。
- **方案 C**：先 B 后 A——构建脚本检测到真证书自动用 A，否则降级 B。

### 复现与诊断

1. 构建：`./tools/build_macos_app.sh && open macos/build/Coffer.app`
2. 解锁 → 工具栏「安全设置」→ 启用 Touch ID → 输主密码
3. 读证据：`cat ~/Library/Containers/app.coffer.Coffer/Data/Library/Logs/Coffer-diag.log`

### 相关改动（已落地，方案 A 时直接复用）

- `BiometricKeychain` 全接口带 `useDataProtection` 测试缝隙（默认 true）
- `DiagLog` 共享诊断日志（Support/DiagLog.swift）+ 模块内步级日志
- 回滚记录：keychain-access-groups entitlement 尝试已撤销（导致拒启动）

---

## BUG-3（✅ 已修复）：安全设置 sheet 无关闭控件——失败后被困页面

**登记日期**：2026-09-27（cygnus 真机报告）
**状态**：✅ 已修复（见下方修复记录）

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

## BUG-4（🟡 未修复，登记）：测试套件不可作为门禁——一条 flaky 断言 + 一条资源耗尽用例

**登记日期**：2026-09-27
**发现环境**：`main` @ `3596467`，8 核 / 16 GiB macOS；WI-1 状态声明独立核验
**状态**：🟡 未修复 —— **本条只登记，不改测试代码**（修复方向见下，待排期）
**证据**：`cf-session/src/usecase/search.rs:183-202`、`cf-session/tests/adversarial.rs:792-820`

> **性质说明**：本条**不是产品缺陷，是测试基础设施缺陷**。产品的搜索性能与 KDF 行为均无问题 —— 详见「影响面」。误按「性能降级」处理会去改无辜的搜索代码。

### 现象

三个事实互相纠缠，共同导致 `cargo test --workspace` **不能作为任何版本的 DoD 门禁**：

1. **`千条搜索基线` 是单次墙钟断言，随机失败。**
   `search.rs:198-199` 断言 1000 条搜索 `< 200 ms`，**只采样一次**。
   独立复测：**20 次记录执行中 3 次失败**（三次失败的耗时见下文「影响面」）。
   计数口径与逐条出处见 `docs/09-版本路线图.md` §1.3 与附录 B.4 ——
   分母是**被声明的边界**（换口径则为 28），**引用时必须连同边界一起写**。
   执行条件不受控（load 2.95–19 波动），**足以确证 flaky，不足以给出失败率** ——
   **不得引用任何百分比**（比率不可导出，勿由 20 / 3 换算）。
   其中**两次**失败发生在**仅选中该 1 条**时（`41 filtered out`，机器输出）
   → **与同 binary 兄弟测试的并发无关**；同一 load（13.64）下亦出现一失败一通过 → **与负载无关**。
   ⚠️ **证据纪律**：libtest 不回显 argv，故 `grep --test-threads` 的**零命中不能**证明
   「未用该 flag」；反之，日志里的段落标题是**人工写入的标注**，**也不能**证明「用了该 flag」。
   本条只引用机器输出（`41 filtered out`）。
2. **`极端kdf参数建库记录与解锁往返` 在 debug 档资源耗尽。**
   `adversarial.rs:792` 同一条用例里既建 `m=8 MiB, t=1, p=1`（极小档）又建
   `m=1 GiB, t=10, p=1`（极端档，`:807`）；极端档单进程 RSS ≈ 1.0 GB，
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

### 修复路径（待办，暂不改代码）

1. **`search.rs` —— 分档 + 取最小值**（两条都要，缺一不可）：
   - **分档**：参照 `core/cf-totp/src/lib.rs:626-630` 的 `cfg!(debug_assertions)` 先例。
     **依据是「既有范式 + 工程卫生」，不是已证实的根因** —— `:124` 的「profile 错配」
     仍是**待查**，`:126` 的负载证据**不支持**它。即：无论 profile 是不是本次 flaky 的主因，
     一条平硬的 `Duration::from_millis(200)` 都应收敛到仓库已有的分档范式。
     ⚠️ **不要照抄那里的 50× 比例** —— 搜索若按 50× 得 10000 ms，无意义；
     debug 档取 **~500 ms**（此值本身也**未经实测标定**，落地时需实测确认）。
   - **单次采样改 N=3 取最小值**修抖动（取 min 而非均值，才不被瞬时停顿污染）。
   - **保留在默认测试集，不要 `#[ignore]`** —— 它守的是真实需求。
2. **`adversarial.rs:792` —— `#[ignore]` + release 串行独占**：
   - 资源耗尽类，与上面的阈值抖动**不同类**，处置方式也不同。
   - 建议**拆成「极小档」「极端档」两条**，把轻量断言（header 如实记录 8 MiB 参数、
     错密码 1002）从重量用例中解放，避免被 1 GiB 用例绑架。
3. **给出可信的门禁命令**（在 1、2 落地前即可用）：
   `cargo test --workspace --no-fail-fast -- --skip 极端kdf参数建库记录与解锁往返 --skip 千条搜索基线`
   —— `--no-fail-fast` 去掉假绿；`--` 之后的参数才交给 libtest（**缺了 `--` 会被 cargo 自身拒绝**）；
   `--skip` 去掉跑不完与不可用的两条。

   > ⚠️ **两个名字必须逐字与源码一致**（`adversarial.rs:792` / `search.rs:183`）。
   > 写错名字时 libtest **不报错**，只是**静默不跳过** —— 门禁看似启动正常，实际仍会卡在
   > 1 GiB 用例上。这正是本条要消灭的那类静默假绿。

> ⚠️ **`#[ignore]` 在全仓当前零命中**（`grep -rn '#\[ignore' core/` → **0**），
> 本项将是**首例**，无先例可循。

### 复现与诊断

1. 抖动：`cargo test -p cf-session --lib 千条搜索基线` 重复十余次（与 load 无关，首次即可能失败）
2. 资源：`cargo test -p cf-session --test adversarial 极端kdf参数建库记录与解锁往返`，debug 档观察 RSS 与耗时
3. 假绿：`cargo test --workspace` —— 检查失败目标之后的 crate 与 doc-test 是否执行

---

## 模板（新条目按此格式追加）

```
## BUG-N（🔴/🟡/✅ 状态）：一句话标题

**登记日期**：YYYY-MM-DD
**发现环境**：
**状态**：
**证据**：（日志/截图路径）

### 现象
### 根因（已实证 / 待查）
### 修复路径
### 复现与诊断
```
