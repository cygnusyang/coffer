# TOTP 功能实现任务列表

| 项 | 内容 |
| --- | --- |
| 文档编号 | LV-TASK-TOTP-001 |
| 状态 | Phase 2-6 待实施 |
| 关联设计 | [docs/TOTP-design.md](./TOTP-design.md) |

---

## Phase 1：基础架构（已完成）

| 任务 ID | 描述 | 负责人 | 状态 |
| --- | --- | --- | --- |
| T-01 | 创建 `cf-totp/Cargo.toml`，定义依赖版本 | Coffer Team | ✅ 完成 |
| T-02 | 编写设计文档 [docs/TOTP-design.md](./TOTP-design.md) | Coffer Team | ✅ 完成 |
| T-03 | 分析 cf-crypto 代码风格与错误处理模式 | Coffer Team | ✅ 完成 |
| T-04 | 识别安全风险点（时间同步、熵源、防重放） | Coffer Team | ✅ 完成 |
| T-05 | 制定 RFC 6238 Appendix B 测试向量验证计划 | Coffer Team | ✅ 完成 |

---

## Phase 2：基础实现

| 任务 ID | 描述 | 负责人 | 状态 |
| --- | --- | --- | --- |
| **T-06** | **定义 `CfTotpError` 错误类型**（此 error） | Coffer Team | 🔄 待实施 |
| | - `InvalidTimestamp(String)` - 时间戳不合法 | | |
| | - `InvalidSeedLength(String)` - 种子长度不符 | | |
| | - `UriParseFailed(String)` - URI 解析失败 | | |
| | - `CalculationFailed` - 计算失败（底层错误） | | |
| **T-07** | **实现 HOTP 基础函数** `generate_hotp(key: &[u8; N], counter: u32) -> Result<u32, CfTotpError>` | Coffer Team | 🔄 待实施 |
| | - RFC 4226 §5.3 Truncated-HMAC 算法实现 | | |
| | - HMAC-SHA1（默认）+ SHA-256/SHA-512 扩展 | | |
| **T-08** | **实现 TOTP 计算函数** `generate_totp(key: &[u8; N], timestamp: u64) -> Result<String, CfTotpError>` | Coffer Team | 🔄 待实施 |
| | - 时间窗口计算 `counter = floor(timestamp / 30)` | | |
| | - RFC 6238 §4 共享窗口（±1 分钟） | | |
| **T-09** | **实现 otpauth URI 解析器** `parse_uri(uri: &str) -> Result<OtpAuthInfo, CfTotpError>` | Coffer Team | 🔄 待实施 |
| | - Base32 解码密钥（`data-encoding` crate） | | |
| | - 提取 issuer、account、algorithm、digits、period | | |
| **T-10** | **常量定义与配置** | Coffer Team | 🔄 待实施 |
| | - `TIME_STEP: u32 = 30` - RFC 默认步长 | | |
| | - `SHARED_WINDOW: i64 = 60` - ±1 分钟窗口 | | |
| | - `KEY_LEN_SHA1: usize = 20` - SHA-1 输出（bytes） | | |

---

## Phase 3：测试实现

| 任务 ID | 描述 | 负责人 | 状态 |
| --- | --- | --- | --- |
| **T-11** | **RFC 6238 Appendix B 测试向量（核心）** | Coffer Team | 🔄 待实施 |
| | - 用例 01：密钥=`JBSWY3DPEHPK3PXP`，offset=0 → `94287082` | | |
| | - 用例 02：密钥=`GEZDGNBV...`，offset=0 → `05743173` | | |
| | - 用例 03-18：剩余 16 条向量完整实现 | | |
| **T-12** | **边界场景测试** | Coffer Team | 🔄 待实施 |
| | - 未来时间戳（当前 +10 分钟） → 应在 T+2 窗口匹配 | | |
| | - 过去时间戳（负数） → `InvalidTimestamp` | | |
| | - URI 缺少 `secret` 参数 → `UriParseFailed` | | |
| **T-13** | **性能基准测试** | Coffer Team | 🔄 待实施 |
| | - TOTP 单步生成 ≤50μs（release） | | |
| | - 批量生成（每分钟窗口）≤200μs/次 | | |
| **T-14** | **错误类型覆盖测试** | Coffer Team | 🔄 待实施 |
| | - 密钥长度<16 bytes → `InvalidSeedLength` | | |
| | - 密钥长度>40 bytes → `InvalidSeedLength` | | |

---

## Phase 4：文档完善

| 任务 ID | 描述 | 负责人 | 状态 |
| --- | --- | --- | --- |
| **T-15** | API 使用示例（含完整注释） | Coffer Team | 🔄 待实施 |
| **T-16** | RFC 测试向量完整列表与计算说明 | Coffer Team | 🔄 待实施 |
| **T-17** | 常见问题 FAQ（时间同步问题等） | Coffer Team | 🔄 待实施 |

---

## Phase 5：代码审查与安全审计

| 任务 ID | 描述 | 负责人 | 状态 |
| --- | --- | --- | --- |
| **T-18** | `ecc:code-reviewer` 代码审查 | Coffer Team | 🔄 待实施 |
| **T-19** | `ecc:security-reviewer` 安全审计 | Coffer Team | 🔄 待实施 |
| **T-20** | 第三方依赖（hmac/sha1/data-encoding）漏洞扫描 | Coffer Team | 🔄 待实施 |

---

## Phase 6：集成与验收

| 任务 ID | 描述 | 负责人 | 状态 |
| --- | --- | --- | --- |
| **T-21** | 集成到 `cf-session`（用例编排） | Coffer Team | 🔄 待实施 |
| **T-22** | 验收测试：RFC 6238 Appendix B 18 条全部通过 | Coffer Team | 🔄 待实施 |
| **T-23** | 性能基准测试报告生成 | Coffer Team | 🔄 待实施 |

---

## 关键里程碑

| 里程碑 | 目标 | 截止 |
| --- | --- | --- |
| **M1** | Phase 1 基础架构完成（当前状态） | ✅ 已完成 |
| **M2** | Phase 2 基础实现完成，RFC 测试向量通过 | M0-3 内 |
| **M3** | Phase 3 测试与文档完善 | M1-1 内 |
| **M4** | Phase 4-5 代码审查与安全审计 | M1-2 内 |
| **M5** | Phase 6 集成验收，准备发布 | M2-0 内 |

---

## 依赖关系图

```
Phase 1 (基础架构)
    ↓
Phase 2 (基础实现) → T-13(T-14)测试
    ↓               ↗
T-13→T-17文档   ↖
    ↓            ↖
Phase 3 (测试) → T-18→T-19代码审查
    ↓          ↗
Phase 4 (文档) ← T-20安全审计
    ↓
Phase 5 (审计)
    ↓
Phase 6 (验收)
```

---

## 风险评估（见 [docs/TOTP-Risk.md](./TOTP-Risk.md)）

| 风险点 | 影响 | 缓解措施 |
| --- | --- | --- |
| 时间同步问题 | Medium | RFC 共享窗口±1 分钟 |
| 熵源质量 | Low（不影响计算，仅由调用方提供密钥） | 复用 cf-crypto 的 getrandom |
| Base32 解码错误 | Low | `data-encoding` crate 已测试 |
| SHA-1 哈希碰撞 | Low（理论风险，实际场景可忽略） | RFC 6238 标准采用 SHA-1 |

---

*文档结束。任务状态同步至 GitHub Projects/线性工作区。*
