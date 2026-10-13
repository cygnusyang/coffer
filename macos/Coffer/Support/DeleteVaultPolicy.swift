// DeleteVaultPolicy.swift —— 库删除向导/管理面纯函数策略（v2.10.0 D1）。
//
// 归口本文件的原则：凡是可被纯函数描述、可脱离 AppModel 单测的逻辑，
// 一律在此定义，视图与 AppModel 只做组装与 IO。依赖仅为 LicenseStatus
// （LicenseServicing.swift，同为零 CoreBindings 纯状态模型）与 FfiVaultBrief
// （绑定只读元数据，非密钥材料）——可独立单测
// （tools/run_vault_delete_tests.sh，同 TouchIDStatusTests 纪律）。
//
// 对照：docs/03-功能设计/16-库删除设计.md §4/§5（UDR-1 trim 比对 / UDR-7
// 只读隐藏 / D-5.1/5.3 masked UUID）+ docs/03-功能设计/17-库删除实现接线.md
// §3 落位选择。

import Foundation

/// deleteVault 编排内部守卫错误（isBusy 防重入等）。非用户面向——UI 已按
/// isBusy 禁用按钮，此路径为防御性短路，不置 lastErrorMessage（不弹框）。
enum DeleteVaultPolicyError: Error {
    /// 有慢调用（建库 / 解锁 / 切换 / 其他删除）进行中，删除被拒。
    case busy
}

enum DeleteVaultPolicy {
    /// 只读许可判定（UDR-7 / C6，AC-2.10.0-EN-7）：试用已结束（Rust VaultWrite
    /// 门禁 6002 拦截写）为只读态 → 隐藏「管理密码库…」入口与行内 [删除…]。
    /// 公开构建默认 .unactivated（全功能免费版）恒可管理；.unavailable（激活
    /// 模块异常）归可管理——非既定只读态，调用时由 Rust 门禁兜底（与
    /// create_vault 拒绝口径一致：UI 不逐项预判，写拒绝走 FFI 错误面）。
    static func canManage(licenseStatus: LicenseStatus) -> Bool {
        switch licenseStatus {
        case .expired:
            return false
        default:
            return true
        }
    }

    /// masked UUID（D-5.1/5.3 长内容纪律）：取前 8 字符 + "…"。列表行 /
    /// 向导目标展示 / Step3 同名库消歧共用。
    static func maskedUUID(_ uuid: String) -> String {
        guard uuid.count > 8 else { return uuid }
        return String(uuid.prefix(8)) + "…"
    }

    /// Step3 库名逐字符确认（UDR-1，AC-2.10.0-CF-2）：输入与库名**各 trim**
    /// 后精确匹配；全空白输入不匹配（库名经 core create_vault 禁全空白，
    /// 空输入必不匹配，此处显式 guard 兜底防御）。
    static func confirmName(input: String, vaultName: String) -> Bool {
        let trimmedInput = input.trimmingCharacters(in: .whitespacesAndNewlines)
        let trimmedName = vaultName.trimmingCharacters(in: .whitespacesAndNewlines)
        return !trimmedInput.isEmpty && trimmedInput == trimmedName
    }

    /// 删除后落位选择（docs/17 §3.2/§3.3，AC-2.10.0-DL-5）：从剩余库
    /// （剔除被删 uuid）中取 createdAt 最近者。空剩余 → nil（单库 → .noVault）。
    /// 视图/AppModel 据此决定是否 openSession 或保持当前会话（删非当前库
    /// 语义见 AppModel.deleteVault 编排，本函数只回答「最近者是谁」）。
    static func selectLandingVault(
        briefs: [FfiVaultBrief], deletedUUID: String
    ) -> FfiVaultBrief? {
        briefs
            .filter { $0.vaultUuid != deletedUUID }
            .max { $0.createdAt < $1.createdAt }
    }
}
