# OPVault 导入测试 fixtures

## 来源与许可（归属注记）

`test.opvault/` 为 **vendor 真实第三方样本**，逐字节复制自
[`detunized/opvault-ruby`](https://github.com/detunized/opvault-ruby) 仓库
的 `test.opvault`（该仓库「Test vault」提交携带，是真实 1Password
OPVault 客户端产物）。

- **许可证**：MIT License（Copyright (c) 2018 Dmitry Yakimenko），
  与 Coffer 同许可证族（NFR-LEGAL-02 复核通过）。
- **完整许可证文本**：见 detunized/opvault-ruby 仓库根目录 `LICENSE`；
  本目录不重复携带全文，以本注记 + 上游 URL 为准。
- **样本参数**（`docs/05-技术研究/02-opvault布局交叉验证报告.md` §1.5，仲裁事实源）：
  - 主密码：`password`
  - `iterations`：40000
  - 条目：3 个 Login（category 001）+ 2 个文件夹
  - 目录结构：`profile.js` + `folders.js` + `band_3/6/D/E.js`（`ld(` 前缀）
  - 无 `.attachment`（附件面不覆盖，见 `docs/03-功能设计/07-v0.7实现方案.md` §2.2.3 out-of-scope）

## 使用纪律

- 该样本只含合成/演示凭据（`mark`/`secret` 等），无真实账号信息，
  可安全进入版本库（对齐 `docs/04-测试与验收/05-v0.5验收判据骨架.md` §3 TCB-1 注记）。
- 互操作性断言以本样本为**开发期锚点**（TC-OPV-13）；**用户真实
  OPVault 样本仍为 T02 验收门槛**（TC-OPV-14，未到手验收挂起，不冒进）。
- 预期明文（`docs/05-技术研究/02-opvault布局交叉验证报告.md` §1.5 实证）：3 个 Login 的 overview/details、
  2 个文件夹，固化进 `core/cf-importer/tests/opvault_import.rs` 断言。
- 合成 fixtures 另以自洽往返断言双解码路径（opdata01 带头 /
  item keys `k` 无头），不替代本真实样本的互操作验证。
