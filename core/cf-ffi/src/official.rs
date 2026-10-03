//! 官方许可装配（feature `official-license` 门控，TC-BLD-02）。
//!
//! 官方产物（闭源 vendored，`core/vendor/license/` 经
//! `tools/bootstrap_official_license.sh` 覆盖为真实副本后 `--features
//! official-license` 构建）的许可接线：本模块是公开仓 cf-ffi 与闭源
//! `cf-assemble` 之间的**唯一**装配点，执行 lead 契约 #2 的初始化序列：
//!
//! ```text
//! CofferApp::new()                     // ① 启动早期（AppModel.init）
//!   → build_official_assembly(...)     // ② 构造判定服务 + 只读门禁
//!   → service.state()                  // ③ Q-17a：首次判定锚定试用起点
//!   → set_license_gate(asm.gate)       // ④ 注入门禁（Rust API，不进 UniFFI 面）
//! ```
//!
//! ## 公开产物不受影响（TC-BLD-02）
//!
//! 本模块整体 `#[cfg(feature = "official-license")]`——默认（feature 关闭）不
//! 编译、不产生任何导出符号：公开仓自编译的 Swift 绑定不含 `installOfficialLicense`
//! （`nm` / `strings` 扫不到 `LicenseService` / `activate` 符号，判据①），6xxx
//! 变体无产生路径（判据②）。行为 = `PermitAllGate` 全功能免费版。
//!
//! ## 与 Swift 侧的接线（契约 #2 ④）
//!
//! `install_official_license` 只做 **Rust 侧**装配（gate 注入 + 试用起点预热），
//! 返回 `Result<(), FfiError>`——不返回任何闭源类型（跨 crate UniFFI 对象跨 FFI
//! 返回会扩大导出面）。Swift 侧 `LicenseAssembly.shared` 的官方适配对象另行包装
//! `cf-assemble` 生成的 `LicenseService` 绑定（其 UniFFI 构造器与装配共用
//! `OFFICIAL_VERIFY_KEY` 与同一套真实依赖），两者状态同源于真实 Keychain 记录，
//! 行为一致（见 macos/Coffer/Support/OfficialLicenseService.swift）。
//!
//! ## 依赖方向纪律
//!
//! 仅在官方 feature 下，cf-ffi 单向依赖 cf-assemble（→ cf-license → cf-domain），
//! 与 cf-ffi 对 cf-domain 的既有依赖同一包，无重复 cf-domain 冲突。

use std::sync::Arc;

use cf_assemble::assembly::build_official_assembly;
use cf_assemble::{OFFICIAL_PUBKEY_VER, OFFICIAL_VERIFY_KEY};
use cf_keychain::MacKeychainStore;
use cf_license::clock::SystemTimeSource;
use cf_license::fingerprint::MacFingerprintSource;
use cf_license::state::{ConservativeDataPresence, LicenseState};

use crate::api::CofferApp;
use crate::error::FfiError;

#[uniffi::export]
impl CofferApp {
    /// 官方许可装配（官方产物启动早期调用，**任何 vault 操作之前**；公开产物
    /// 不含本方法，TC-BLD-02）。
    ///
    /// 执行契约 #2 序列：`build_official_assembly`（真实 KeychainStore / 机器
    /// 指纹 / 系统时钟 / 数据存在性探针）→ `state()` best-effort 预热（Q-17a：
    /// 首次判定写入 trial 起始记录，锚定试用起点）→ `set_license_gate` 注入只读
    /// 门禁。
    /// 门禁注入后，应用级写操作（create_vault / export_backup / restore_backup）
    /// 与全部 `open_vault` 会话共用官方判定源（`docs/03` §14.6 拒绝面）。
    ///
    /// # Errors
    ///
    /// 返回错误的路径只有一个：`build_official_assembly` 装配失败（构建期
    /// 不变量破坏——`OFFICIAL_VERIFY_KEY` 无法解析为 Ed25519 公钥），映射为
    /// 既有 6xxx 码位（6004，许可模块不可用），无新增码位。
    ///
    /// `state()` 预热**不可失败**（返回 [`LicenseState`] 而非 `Result`）——
    /// 运行时 Keychain IO 失败按 §14.8 折入 `LicenseState` 退化变体
    /// （`StateUnavailable` / 试用退化），不作为错误返回，也不阻断启动；
    /// 预热结果落 `tracing::debug!`/`warn!` 日志（当前 app 未挂 subscriber，
    /// 事件静默丢弃，机制与私有仓内部日志一致）。门禁已注入，下一次
    /// `licenseStatus()` 会重试同一判定（瞬时故障自愈；持续故障在 Swift UI
    /// 侧显形，与失败推迟到状态呈现一致）。
    pub fn install_official_license(&self) -> Result<(), FfiError> {
        let asm = build_official_assembly(
            OFFICIAL_VERIFY_KEY,
            OFFICIAL_PUBKEY_VER,
            Arc::new(MacKeychainStore::new()),
            Arc::new(MacFingerprintSource::new()),
            Arc::new(SystemTimeSource),
            Arc::new(ConservativeDataPresence),
        )
        .map_err(license_error_to_ffi)?;
        // Q-17a：首次判定（state() 有副作用：无记录时写入 trial 起始）。
        // state() 不可失败（返回 LicenseState，Keychain IO 失败按 §14.8 折入
        // 退化变体 StateUnavailable / 试用退化；trial 写失败已在 cf-license
        // 内部 tracing::warn! 落日志「下次启动重试」，自愈语义——与私有仓同
        // 机制）。装配侧仅落 tracing 日志作诊断勾稽（当前 app 未挂 subscriber，
        // 事件静默丢弃；若将来接 DiagLog 即生效），不传播、不阻断启动——门禁
        // 已注入，预热退化由下一次 licenseStatus() 重新判定显形（或 UI 侧呈现）。
        let warmup = asm.service.state();
        if let LicenseState::StateUnavailable = warmup {
            tracing::warn!(state = ?warmup, "official license warmup degraded (StateUnavailable); self-heals on next licenseStatus()");
        } else {
            tracing::debug!(state = ?warmup, "official license warmup ok");
        }
        // 门禁注入（Rust 装配 API，刻意不进 `#[uniffi::export]`，TC-BLD-02）
        self.set_license_gate(asm.gate);
        Ok(())
    }
}

/// `cf-assemble::LicenseError` → [`FfiError`]（6xxx 码位透传，无新增）。
///
/// `LicenseError` 只有 `License { code, message }` 单一变体（错误码 6001 /
/// 6004，docs/03 §12 冻结码位）；本层只透传，不重新组合——与公开仓
/// `From<CfError> for FfiError` 同纪律（UI 按 code 本地化，不解析 message）。
fn license_error_to_ffi(e: cf_assemble::LicenseError) -> FfiError {
    match e {
        cf_assemble::LicenseError::License { code, message } => FfiError::Coffer { code, message },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 错误码透传：LicenseError（6001 / 6004）→ FfiError 码与 message 原样，
    /// 无新增码位（docs/03 §12 冻结）。
    #[test]
    fn license_error_maps_to_ffi_preserving_code() {
        let cases = [
            (6001, "license serial invalid"),
            (6004, "license store unavailable"),
        ];
        for (code, message) in cases {
            let ffi = license_error_to_ffi(cf_assemble::LicenseError::License {
                code,
                message: message.to_string(),
            });
            assert_eq!(ffi.code(), code);
            match ffi {
                FfiError::Coffer { code: c, message: m } => {
                    assert_eq!((c, m.as_str()), (code, message));
                }
                other => panic!("应映射为 Coffer，实际 {other:?}"),
            }
        }
    }

    /// 装配构造（无 Keychain IO）：`OFFICIAL_VERIFY_KEY` 可解析 + 真实依赖
    /// 装配成功（构建期不变量）。不调用 `state()` / `install_official_license`
    /// ——那会写真实 Keychain 记录，不适合进程内单测（由 app 冒烟承担）。
    #[test]
    fn real_assembly_constructs() {
        let asm = build_official_assembly(
            OFFICIAL_VERIFY_KEY,
            OFFICIAL_PUBKEY_VER,
            Arc::new(MacKeychainStore::new()),
            Arc::new(MacFingerprintSource::new()),
            Arc::new(SystemTimeSource),
            Arc::new(ConservativeDataPresence),
        );
        assert!(asm.is_ok(), "OFFICIAL_VERIFY_KEY 必须可解析（构建期不变量）");
    }
}
