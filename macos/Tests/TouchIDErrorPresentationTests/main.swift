// TouchIDErrorPresentationTests —— Touch ID 解锁错误呈现分道纯函数单元测试
// （PL-5：修复 CrossCopySheet 目标库 Touch ID 解锁与主解锁路径呈现一致；
// docs/08 §7.3/§7.6）。
//
// 被测单元 TouchIDUnlockPresentation.resolve（Support/TouchIDError.swift）
// 是纯函数：无 IO / 无 FFI / 无 Keychain 依赖（文件零 CoreBindings 依赖），
// 任何环境（含 CI 沙盒）均可运行，不设 SKIP 路径（同
// run_touchid_auth_failure_tests.sh 纪律）。
//
// 背景：AppModel.unlockWithTouchID 与 CrossCopySheet.unlockWithBiometric 的
// 错误呈现必须一致——用户取消静默、authFailed 按瞬时/持久分道（PL-7）、
// 其余交回 ErrorPresenter.text（FfiError 等，本函数无法判定故 .fallback）。

import Foundation

func check(_ cond: @autoclosure () -> Bool, _ label: String) {
    if cond() {
        print("✓ \(label)")
    } else {
        print("✗ \(label)")
        exit(1)
    }
}

struct GenericTestError: Error {}

// ---- 1. userCanceled → silent（取消静默，两路径一致）----
check(TouchIDUnlockPresentation.resolve(error: BiometricKeychainError.userCanceled, biometryAvailable: true) == .silent,
      "userCanceled → silent（取消静默）")
check(TouchIDUnlockPresentation.resolve(error: BiometricKeychainError.userCanceled, biometryAvailable: false) == .silent,
      "userCanceled + 不可用 → 仍 silent（取消优先）")

// ---- 2. itemNotFound → 4002 stale 文案（项不存在 = 持久失效）----
check(TouchIDUnlockPresentation.resolve(error: BiometricKeychainError.itemNotFound, biometryAvailable: true) == .text(TouchIDError.stale.userText),
      "itemNotFound → 4002 stale 文案")

// ---- 3. authFailed 瞬时（biometryAvailable=false）→ 温和文案（PL-7）----
check(TouchIDUnlockPresentation.resolve(error: BiometricKeychainError.authFailed, biometryAvailable: false) == .text(TouchIDError.transientUnavailable.userText),
      "authFailed + 不可用 → 瞬时温和文案")
check(TouchIDUnlockPresentation.resolve(error: BiometricKeychainError.authFailed, biometryAvailable: false) != .text(TouchIDError.stale.userText),
      "瞬时文案 ≠ 4002 stale 文案")

// ---- 4. authFailed 持久（biometryAvailable=true）→ 4002 ----
check(TouchIDUnlockPresentation.resolve(error: BiometricKeychainError.authFailed, biometryAvailable: true) == .text(TouchIDError.stale.userText),
      "authFailed + 可用 → 持久 4002 文案")

// ---- 5. 其余错误 → fallback（调用方回退 ErrorPresenter.text）----
check(TouchIDUnlockPresentation.resolve(error: BiometricKeychainError.unexpected(-34018), biometryAvailable: true) == .fallback,
      "unexpected → fallback（调用方回退 ErrorPresenter.text）")
check(TouchIDUnlockPresentation.resolve(error: BiometricKeychainError.invalidKeyLength(16), biometryAvailable: false) == .fallback,
      "invalidKeyLength → fallback")
check(TouchIDUnlockPresentation.resolve(error: GenericTestError(), biometryAvailable: true) == .fallback,
      "其他 Error（FfiError 等）→ fallback")

print("TOUCH ID ERROR PRESENTATION TESTS OK —— 9 项断言全部通过")
