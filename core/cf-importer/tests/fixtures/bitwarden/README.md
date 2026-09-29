# Bitwarden 导入测试 fixtures（全部合成数据）

**纪律：真实凭据不进仓库**（docs/18 §3 / TCB-1 注记）。本目录全部为手工
合成的 Bitwarden JSON 导出样本；所有密钥、密码、凭据 ID 均为测试专用
一次性生成值，不对应任何真实账号。

## 字段形态注记（TCB-1 状态）

`fido2Credentials` 的 schema 为【单源】（Bitwarden 官方文档未承诺第三方
互通，docs/17 §4.2）。lead 裁定（2026-09-29）：**合成样本先行开发，
真实导出样本的逆向核对降级为 TCB-1 回归门禁**。当前 fixtures 采用：

- 键名对齐 Bitwarden 客户端源码的导出模型（`Fido2Key`）：`credentialId` /
  `keyType` / `keyAlgorithm` / `keyCurve` / `rpId` / `rpName` / `userHandle` /
  `userName` / `userDisplayName` / `counter` / `discoverable` /
  `creationDate` / `encryptedPrivateKey` / `encryptedUserKey`；
- `encryptedPrivateKey` 在真实未加密导出中**仍为 EncString 密文**
  （attach key 不随导出解包）——解析器对该形态显式列为「不可导入
  passkey 行」（不静默丢弃），条目本体照常导入（FR-10.6）；
- 解析器同时容忍 `encryptedPrivateKey` 携带可解析的 ES256 私钥编码
  （PKCS#8 / SEC1 DER，base64）——本 fixtures 用此形态验证归一化路径；
  真实样本核对（TCB-1）若推翻上述任一形态，须同步修订 fixtures 与
  解析器并留档注记。

## 文件清单

- `login_with_passkey.json` —— 含密码+passkey 条目 / 纯密码条目（回环与
  FR-10.6 主样本）；
- `passkey_variants.json` —— SEC1 私钥 / 非 ES256 / 坏 credentialId /
  EncString 私钥 / 缺 rpId / 负 counter / 降级 card / 回收站条目；
- `encrypted_export.json` —— password-protected 加密导出（整体拒绝）。
