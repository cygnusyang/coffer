// OfficialLicenseAdapterTests/main.swift —— 官方许可适配纯逻辑测试（FR-15）。
//
// 被测单元（Support/OfficialLicenseService.swift 中的纯映射函数，`#if
// OFFICIAL_LICENSE`）：
//   - LicenseStatus(_ status: FfiLicenseStatus) —— 五态映射（docs/03 §14.9）
//   - mapActivationError(_ error: LicenseError) —— 6001 / 6004 / 防御性兜底
//
// 编译运行：tools/run_official_license_adapter_tests.sh（需官方构建产物：
// core/vendor 已 bootstrap + `--features official-license` 生成的 CoreBindings
// 与 libcf_ffi.a——见 Task 4b 验证）。
//
// 只构造 `LicenseError` / `FfiLicenseStatus` 纯 Swift 枚举值、不调任何 FFI——
// 零 Keychain / 零指纹副作用，可在进程内安全运行（契约 #1 慢调用不适用）。

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

// ---- 1. FfiLicenseStatus → LicenseStatus 五态映射（docs/03 §14.9）----

check(LicenseStatus(FfiLicenseStatus.unactivated) == .unactivated, "unactivated → .unactivated")
check(LicenseStatus(FfiLicenseStatus.trial(remainingDays: 5)) == .trial(remainingDays: 5), "trial(5) → .trial(remainingDays: 5)")
let masked = "AB12C-****-Y7890"
check(LicenseStatus(FfiLicenseStatus.active(serialMasked: masked)) == .active(serialMasked: masked), "active(掩码) → .active(掩码)")
check(LicenseStatus(FfiLicenseStatus.expired) == .expired, "expired → .expired")
check(LicenseStatus(FfiLicenseStatus.unavailable) == .unavailable, "unavailable → .unavailable")

// ---- 2. mapActivationError（6001 / 6004 / 防御性兜底）----

check(
    mapActivationError(LicenseError.License(code: 6001, message: "license serial invalid")) == .serialInvalid,
    "6001 → serialInvalid（FR-15.6 不可区分）"
)
check(
    mapActivationError(LicenseError.License(code: 6004, message: "license store unavailable")) == .storageUnavailable,
    "6004 → storageUnavailable"
)
check(
    mapActivationError(LicenseError.License(code: 6002, message: "trial expired")) == .serialInvalid,
    "6002（门禁码，不经 activate）→ 防御性统一 serialInvalid"
)
check(
    mapActivationError(LicenseError.License(code: 6003, message: "state unavailable")) == .serialInvalid,
    "6003（门禁码，不经 activate）→ 防御性统一 serialInvalid"
)

print("")
print(failed == 0
      ? "OFFICIAL LICENSE ADAPTER TESTS OK —— \(passed) 项断言全部通过"
      : "OFFICIAL LICENSE ADAPTER TESTS FAILED —— \(failed)/\(passed + failed) 项断言失败")
if failed > 0 { exit(1) }
