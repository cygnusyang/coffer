// OfficialLicenseService.swift —— 官方产物许可服务适配（#if OFFICIAL_LICENSE）。
//
// 把 cf-assemble 经 UniFFI 生成的 LicenseService 绑定适配为公开仓
// LicenseServicing protocol（docs/03 §14.9，C-05 官方装配面）。本文件整体
// `#if OFFICIAL_LICENSE`——公开构建（无 `-D OFFICIAL_LICENSE` 编译标志）不
// 编译本文件，不引用任何许可绑定类型（TC-BLD-02 的 Swift 侧对应：公开 App
// 二进制不含许可路径 / 符号）。
//
// 三方法适配（对齐 cf-assemble service.rs 契约表）：
//   - machineFingerprint：Option<String> → String（nil → 空串，契约 #1）
//   - licenseStatus：FfiLicenseStatus → LicenseStatus（五态映射，docs/03 §14.9）
//   - activate：LicenseError → LicenseActivationError
//     （6001 → serialInvalid；6004 → storageUnavailable；其余防御性统一 6001
//     ——激活失败不可区分纪律 FR-15.6，不泄露失败原因）
//
// 时序（契约 #2）：app 启动早期、任何 vault 操作前，AppModel.bootstrap 装配：
//   CofferApp()（init）→ factory.installOfficialLicense()（Rust 侧 gate 注入
//   + Q-17a 试用起点预热）→ LicenseAssembly.shared = OfficialLicenseService()
//   （Swift 侧适配注入）。

#if OFFICIAL_LICENSE
import Foundation

/// 官方产物许可服务适配：包装 cf-assemble 生成的 `LicenseService` 绑定。
struct OfficialLicenseService: LicenseServicing {
    private let inner: LicenseService

    /// 构造：`LicenseService()` 是可失败构造器（OFFICIAL_VERIFY_KEY 解析失败，
    /// 构建期不变量，理论不可达）。
    init() throws {
        self.inner = try LicenseService()
    }

    var isLicensingAvailable: Bool { true }

    func machineFingerprint() -> String {
        // 指纹不可读（部分 VM / Hackintosh）→ nil → 空串（契约 #1）；许可页
        // 显示空指纹，激活路径按不可区分 6001 拒绝（docs/03 §14.8）
        inner.machineFingerprint() ?? ""
    }

    func licenseStatus() -> LicenseStatus {
        LicenseStatus(inner.licenseStatus())
    }

    func activate(serial: String) throws -> LicenseStatus {
        do {
            return LicenseStatus(try inner.activate(serial: serial))
        } catch let error as LicenseError {
            throw mapActivationError(error)
        } catch {
            // 绑定层未知错误（防御性兜底）：统一 6001 不可区分语义（FR-15.6）
            throw LicenseActivationError.serialInvalid
        }
    }
}

/// `FfiLicenseStatus` → `LicenseStatus` 五态映射（docs/03 §14.9）。
extension LicenseStatus {
    init(_ status: FfiLicenseStatus) {
        switch status {
        case .unactivated:
            self = .unactivated
        case .trial(let remainingDays):
            self = .trial(remainingDays: Int(remainingDays))
        case .active(let serialMasked):
            self = .active(serialMasked: serialMasked)
        case .expired:
            self = .expired
        case .unavailable:
            self = .unavailable
        }
    }
}

/// `LicenseError` → `LicenseActivationError`（docs/03 §14.9 activate 失败面）。
///
/// 6001 → `serialInvalid`；6004 → `storageUnavailable`；其余码防御性统一
/// `serialInvalid`——激活路径不泄露失败原因（FR-15.6 不可区分纪律）。
func mapActivationError(_ error: LicenseError) -> LicenseActivationError {
    switch error {
    case .License(let code, _):
        switch code {
        case 6001:
            return .serialInvalid
        case 6004:
            return .storageUnavailable
        default:
            // 6002 / 6003 由门禁（写守卫）产生、不经 activate；防御性兜底
            return .serialInvalid
        }
    }
}
#endif
