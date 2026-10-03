// LicenseStatusTests/main.swift —— 许可域纯逻辑单元测试（FR-15，docs/03 §12/§14）。
//
// 编译运行：tools/run_license_status_tests.sh
//
// 被测单元（Support/LicenseServicing.swift + Support/LicenseError.swift）均为
// 纯逻辑：零 IO / 零 FFI / 零 CoreBindings 依赖（同 TouchIDErrorPresentationTests
// 纪律），任何环境（含 CI 沙盒）均可运行，不设 SKIP 路径。
//   - LicenseStatus —— 状态模型（docs/03 §14.9 FfiLicenseStatus）+ displayText
//   - LicenseErrorText.text(forCode:) —— 6xxx 文案映射（6001 不可区分纪律）
//   - LicenseActivationError —— 激活失败统一 6001
//   - PermitAllLicenseService —— 公开产物桩行为（未激活 / 全功能免费版）
//   - LicenseAssembly —— 装配点默认公开产物桩

import Foundation

var passed = 0
var failed = 0

func check(_ condition: Bool, _ name: String) {
    if condition {
        passed += 1
        print("✓ \(name)")
    } else {
        failed += 1
        print("✗ \(name)")
    }
}

// ---- 1. LicenseStatus 状态模型（docs/03 §14.9：trial / active / expired；
//        另含公开产物未激活态 unactivated 与不可用态 unavailable，§14.8）----

check(LicenseStatus.unactivated == .unactivated, "未激活态存在（公开产物默认）")
check(LicenseStatus.trial(remainingDays: 5) == .trial(remainingDays: 5), "试用态含剩余天数")
check(LicenseStatus.active(serialMasked: "ABCDE-FGHIJ") == .active(serialMasked: "ABCDE-FGHIJ"), "已激活态含许可键掩码")
check(LicenseStatus.expired == .expired, "试用已结束态存在")
check(LicenseStatus.unavailable == .unavailable, "许可模块不可用态存在（§14.8 指纹读取失败）")
check(LicenseStatus.trial(remainingDays: 1) != .trial(remainingDays: 2), "试用态按剩余天数区分")

// ---- 2. displayText 状态行文案（只回掩码，docs/03 §14.1）----

check(LicenseStatus.unactivated.displayText == "未激活（全功能免费版）", "未激活状态行文案")
check(LicenseStatus.trial(remainingDays: 3).displayText == "试用中，剩余 3 天", "试用剩余天数文案")
check(LicenseStatus.active(serialMasked: "AB12C-…").displayText == "已激活（许可键 AB12C-…）", "已激活展示许可键掩码")
check(LicenseStatus.expired.displayText == "试用已结束（只读模式）", "试用结束状态行文案")
check(LicenseStatus.unavailable.displayText == "许可模块不可用", "不可用状态行文案")

// ---- 3. LicenseErrorText 6xxx 文案映射（docs/03 §12 6xxx 段 / §14.5）----

check(LicenseErrorText.text(forCode: 6001) == "序列号无效", "6001 → 统一「序列号无效」")
let t6001 = LicenseErrorText.text(forCode: 6001) ?? ""
check(
    !t6001.contains("格式") && !t6001.contains("签名") && !t6001.contains("机器")
        && !t6001.contains("版本") && !t6001.contains("他机"),
    "6001 文案不含任何失败原因（FR-15.6 不可区分纪律）"
)
check(LicenseErrorText.text(forCode: 6002)?.contains("激活") == true, "6002 → 试用到期引导激活（正常路径）")
check(LicenseErrorText.text(forCode: 6003)?.contains("重启") == true, "6003 → 门禁异常引导重启 / 重装")
check(LicenseErrorText.text(forCode: 6004) == "许可信息存储暂不可用，请稍后重试。", "6004 → 存储暂不可用文案")
check(LicenseErrorText.text(forCode: 5001) == nil, "非 6xxx 码 → nil（调用方走默认直出）")
check(LicenseErrorText.text(forCode: 0) == nil, "未知码 → nil")

// ---- 4. LicenseActivationError（docs/03 §14.9 activate 失败面：
//         6001 不可区分（FR-15.6）+ 6004 存储暂不可用）----

check(LicenseActivationError.serialInvalid.userText == "序列号无效", "激活错误 userText = 6001「序列号无效」")
check(LicenseActivationError.serialInvalid == .serialInvalid, "6001 不可区分：无失败原因字段（FR-15.6）")
check(LicenseActivationError.storageUnavailable.userText == "许可信息存储暂不可用，请稍后重试。", "激活错误 userText = 6004「存储暂不可用」")
check(LicenseActivationError.storageUnavailable == .storageUnavailable, "6004 存储暂不可用独立成态")
check(LicenseActivationError.serialInvalid != .storageUnavailable, "6001 / 6004 两态按码区分（docs/03 §12）")

// ---- 5. PermitAllLicenseService 公开产物桩（docs/03 §14.9：未激活 / 全功能免费版）----

let stub = PermitAllLicenseService()
check(stub.isLicensingAvailable == false, "公开产物不含许可模块")
check(stub.licenseStatus() == .unactivated, "公开产物许可状态 = 未激活")
check(stub.machineFingerprint().isEmpty, "公开产物无机器指纹（无激活模块）")
do {
    _ = try stub.activate(serial: "any-serial")
    check(false, "公开产物 activate 应失败（无激活模块）")
} catch let error as LicenseActivationError {
    check(error == .serialInvalid, "公开产物激活失败 = 统一 6001 serialInvalid")
} catch {
    check(false, "公开产物激活失败类型应为 LicenseActivationError")
}

// ---- 6. LicenseAssembly 装配点（默认公开产物桩）----

check(LicenseAssembly.shared is PermitAllLicenseService, "装配点默认公开产物桩（官方装配壳替换真实现）")

print("")
print(failed == 0
      ? "LICENSE STATUS TESTS OK —— \(passed) 项断言全部通过"
      : "LICENSE STATUS TESTS FAILED —— \(failed)/\(passed + failed) 项断言失败")
if failed > 0 { exit(1) }
