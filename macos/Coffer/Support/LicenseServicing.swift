// LicenseServicing.swift —— 许可服务抽象（FR-15，docs/03 §14.9）。
//
// 公开仓纪律（C-05：公开产物与官方产物差异仅为激活模块）：本文件定义
// Swift 侧许可服务协议 LicenseServicing，公开产物用 PermitAllLicenseService
// 桩实现（未激活 / 全功能免费版，与公开仓默认 PermitAllGate 语义一致，
// docs/03 §14.9「公开产物：协议抽象 + 构建脚本空实现」）；官方装配壳
// （私有仓 cf-license 经 UniFFI）在 LicenseAssembly.shared 注入真实现，
// 本文件与 UI 零依赖。
//
// 本文件零 CoreBindings 依赖（纯协议 + 状态模型 + 桩），可独立单测
// （tools/run_license_status_tests.sh，同 TouchIDErrorPresentationTests 纪律）。
//
// 状态模型对齐 docs/03 §14.9 FfiLicenseStatus：trial{remaining_days} |
// active | expired；另按 §14.8 失败模式补 unavailable（指纹读取失败 →
// 激活不可用）与公开产物未激活态 unactivated。

import Foundation

/// 许可状态（docs/03 §14.9 FfiLicenseStatus；Equatable 以独立单测）。
enum LicenseStatus: Equatable {
    /// 未激活（全功能）：公开产物桩默认态——公开构建不含许可模块，全功能免费
    case unactivated
    /// 试用中，含剩余天数（docs/03 §14.3 首启计时）
    case trial(remainingDays: Int)
    /// 已激活（买断制永久有效，Q-12；`serialMasked` 只回掩码，docs/03 §14.1
    /// ——掩码由 Rust 侧计算，Swift 侧不持有原始序列号）
    case active(serialMasked: String)
    /// 试用已结束（写操作被门禁 6002 拦截，只读）
    case expired
    /// 许可模块不可用（机器指纹读取失败等，docs/03 §14.8）：激活不可用，
    /// 许可页提示
    case unavailable

    /// 许可页状态行文案（纯函数，可独立单测）。`active` 只回掩码。
    var displayText: String {
        switch self {
        case .unactivated:
            return "未激活（全功能免费版）"
        case .trial(let remainingDays):
            return "试用中，剩余 \(remainingDays) 天"
        case .active(let serialMasked):
            return "已激活（许可键 \(serialMasked)）"
        case .expired:
            return "试用已结束（只读模式）"
        case .unavailable:
            return "许可模块不可用"
        }
    }
}

/// 许可服务协议（docs/03 §14.9 LicenseService 三方法 + 模块可用性）。
protocol LicenseServicing {
    /// 本构建是否含许可模块：公开产物 false（许可页显示「本构建不含许可模块
    /// （全功能免费版）」并隐藏激活入口）；官方产物 true。
    var isLicensingAvailable: Bool { get }

    /// 机器指纹哈希（docs/03 §14.2，SHA-256 前 16 字节）：供用户复制给签发方
    /// 申请序列号。公开产物无激活模块，返回空串。
    func machineFingerprint() -> String

    /// 当前许可状态。
    func licenseStatus() -> LicenseStatus

    /// 激活：成功写 activation record（docs/03 §14.4）并返回新状态；任何失败
    /// 统一抛 `LicenseActivationError.serialInvalid`（6001，FR-15.6 不可区分
    /// 纪律——格式 / 签名 / 他机 / 版本不支持同码同文案，docs/03 §14.1）。
    func activate(serial: String) throws -> LicenseStatus
}

/// 公开产物许可服务桩实现：未激活 / 全功能免费版（与公开仓默认 PermitAllGate
/// 一致，docs/03 §14.9「公开产物：协议抽象 + 构建脚本空实现」）——保证公开
/// 构建行为与现在完全相同（无门禁、无激活模块）。
struct PermitAllLicenseService: LicenseServicing {
    var isLicensingAvailable: Bool { false }
    func machineFingerprint() -> String { "" }
    func licenseStatus() -> LicenseStatus { .unactivated }
    func activate(serial: String) throws -> LicenseStatus {
        // 公开产物无激活模块：任何激活尝试统一 6001（与官方失败分支同构，
        // 不区分原因、不泄露任何细节）
        throw LicenseActivationError.serialInvalid
    }
}

/// 许可服务装配点：公开产物默认 `PermitAllLicenseService`；官方装配壳
/// （私有仓 cf-license）启动时替换为真实现（docs/03 §14.9）。
enum LicenseAssembly {
    static var shared: LicenseServicing = PermitAllLicenseService()
}
