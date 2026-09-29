//! 许可门禁端口（FR-15，`docs/02-概要设计.md` §10.2 / `docs/03-详细设计.md` §14.6）。
//!
//! 定义只读门禁的**端口 trait** 与开源默认实现 [`PermitAllGate`]。
//! 闭源激活模块（cf-license，私有仓库）以实现本 trait 的方式注入官方产物，
//! 公开仓库不出现任何条件编译的商业化分叉（C-05 构建隔离，Q-19 方案 A）。
//!
//! ## 设计要点
//!
//! - 本模块**无密钥、无 IO、无判定逻辑**：gate 只收 [`LicensedOp`] 操作枚举，
//!   只输出允许 / 拒绝及拒绝码类别（FR-15.8：激活模块不接触密钥材料与条目明文）；
//! - 拒绝码刻意只区分两类：试用到期 [`LicenseDenial::TrialExpired`]（6002，
//!   引导用户去激活）与激活态异常退化 [`LicenseDenial::StateUnavailable`]（6003，
//!   引导重启 / 重装）——拆分属 UX 引导需要，见 `docs/03` §14.5；
//! - 序列号验证失败（6001）与许可存储不可用（6004）**不经本端口**：
//!   它们只产生于闭源激活模块内部，公开侧契约仅在 [`crate::error::CfError`]
//!   登记码位（`docs/03` §12），开源产物不存在产生路径。
//!
//! ## 纪律
//!
//! cf-session / cf-ffi 只依赖本 trait，不知道 cf-license 的存在；
//! 依赖方向严格单向：cf-license ──► cf-domain ✅（闭源依赖开源），
//! cf-domain ──✗──► cf-license（开源依赖闭源，一条都不存在）。

/// 受门禁管辖的写操作类别（`docs/03-详细设计.md` §14.6 拒绝面五组）。
///
/// 新增写用例必须归入既有组之一（或经评审新增组）——这是
/// 「新增写用例必过门禁」的结构性保证（TC-GATE-12）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LicensedOp {
    /// 条目写：create / update / delete / restore / duplicate / move /
    /// set_archived / set_favorite / restore_history / 附件增删。
    ItemWrite,
    /// 库级写：create_vault / rename_vault / delete_vault / change_password /
    /// enable·disable_biometric。
    VaultWrite,
    /// 导入与恢复：execute_import / import_vault_package / restore_backup。
    ImportRestore,
    /// 数据出口（FR-15.2 明确全拒，即便只读用户有备份诉求）：
    /// export_backup / export_vault_package / export_one_pux / export_csv。
    ExportData,
    /// Passkey 写：create_passkey / delete_passkey。
    /// 断言（get_passkey_assertion）**不属于本组**——属「使用 / 复制」类，
    /// 在只读模式允许（`docs/03` §14.6 边界裁决）。
    PasskeyWrite,
}

/// 门禁拒绝的原因类别（对应两个刻意拆分的拒绝码，`docs/03` §14.5）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LicenseDenial {
    /// 试用期已结束未激活 → 错误码 6002。引导用户去激活（正常路径）。
    TrialExpired,
    /// 激活态异常退化（如凭证读取失败且无法证明未到期）→ 错误码 6003。
    /// 引导重启 / 重装，仍异常再联系支持。
    StateUnavailable,
}

impl LicenseDenial {
    /// 本拒绝对应的 §12 错误码（6002 / 6003）。
    #[must_use]
    pub fn code(self) -> u16 {
        match self {
            Self::TrialExpired => 6002,
            Self::StateUnavailable => 6003,
        }
    }
}

/// 门禁判定结果：允许，或拒绝并给出原因类别。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LicenseDecision {
    /// 放行。
    Allow,
    /// 拒绝该写操作（只读模式）。
    Deny(LicenseDenial),
}

/// 许可门禁端口。
///
/// 生产实现：开源 = [`PermitAllGate`]；官方产物 = cf-license（私有仓库）。
/// 测试实现：双态 FakeGate（拒绝态注入 6002 / 6003，见 docs/12 TC-GATE）。
pub trait LicenseGate: Send + Sync {
    /// 对单个受管辖写操作给出判定。
    ///
    /// 调用方（cf-session 统一写守卫 / cf-ffi 应用级写装配点）保证在
    /// 锁定检查（1001）之后、写事务之前调用；拒绝时调用方必须保证
    /// **不落任何半截数据**（TC-GATE-08）。
    fn check(&self, op: LicensedOp) -> LicenseDecision;
}

/// 开源默认门禁：恒放行。
///
/// 「从公开源码自行编译的产物不含激活模块，等价于全功能免费版」
/// 的可执行形式（C-05 / TC-GATE-10）。无状态、无 IO。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PermitAllGate;

impl LicenseGate for PermitAllGate {
    fn check(&self, _op: LicensedOp) -> LicenseDecision {
        LicenseDecision::Allow
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 恒拒绝（试用到期态）的测试 gate。
    struct DenyExpiredGate;

    impl LicenseGate for DenyExpiredGate {
        fn check(&self, _op: LicensedOp) -> LicenseDecision {
            LicenseDecision::Deny(LicenseDenial::TrialExpired)
        }
    }

    const ALL_OPS: [LicensedOp; 5] = [
        LicensedOp::ItemWrite,
        LicensedOp::VaultWrite,
        LicensedOp::ImportRestore,
        LicensedOp::ExportData,
        LicensedOp::PasskeyWrite,
    ];

    #[test]
    fn permit_all_gate_allows_every_op() {
        // TC-GATE-10 的域层基元：默认装配（自编译免费版契约）对全部
        // 受管辖操作恒放行。
        for op in ALL_OPS {
            assert_eq!(PermitAllGate.check(op), LicenseDecision::Allow);
        }
    }

    #[test]
    fn denial_codes_match_design_doc_section_12() {
        // 6002 / 6003 拆分语义，docs/03 §12 / §14.5。
        assert_eq!(LicenseDenial::TrialExpired.code(), 6002);
        assert_eq!(LicenseDenial::StateUnavailable.code(), 6003);
    }

    #[test]
    fn custom_gate_decision_flows_through() {
        // 端口语义：注入实现的判定原样到达调用方（官方 cf-license 的
        // 注入路径在私有仓库，此处以测试 gate 验证流转）。
        assert_eq!(
            DenyExpiredGate.check(LicensedOp::ItemWrite),
            LicenseDecision::Deny(LicenseDenial::TrialExpired)
        );
    }
}
