// TouchIDAuthFailureTests —— Touch ID 解锁失败瞬时/持久分道纯函数单元测试
// （PL-7，2026-10-03 用户反馈）。
//
// 被测单元 TouchIDAuthFailure.disposition（Support/TouchIDAuthFailure.swift）
// 是纯函数：无 IO / 无 FFI / 无 Keychain 依赖，任何环境（含 CI 沙盒）均可
// 运行，不设 SKIP 路径（同 docs/08 §9 T04 纯函数纪律与
// run_touchid_status_tests.sh / run_auto_prompt_biometric_tests.sh 同款）。
//
// 背景：read 返回 errSecAuthFailed（-25293）有两类成因——持久（指纹集变更，
// biometryCurrentSet 失效）与瞬时（系统锁屏/刚唤醒传感器未就绪/biometry
// lockout）。瞬时不应判死（不置 stale、按钮保留可再点），持久维持 4002 +
// .stale 终判（docs/08 §4.1）。判别信号 = 失败瞬间 isBiometricsAvailable()。

import Foundation

func check(_ cond: @autoclosure () -> Bool, _ label: String) {
    if cond() {
        print("✓ \(label)")
    } else {
        print("✗ \(label)")
        exit(1)
    }
}

// ---- 1. 瞬时：isBiometricsAvailable=false ----
// 传感器未就绪 / biometry lockout / 系统刚唤醒 → canEvaluatePolicy 不过 →
// 判定为瞬时，不判死（保留按钮）
check(TouchIDAuthFailure.disposition(biometryAvailable: false) == .transient,
      "isBiometricsAvailable=false → 瞬时（不判死）")

// ---- 2. 持久：isBiometricsAvailable=true 但 read 仍 authFailed ----
// 指纹集变更 / ACL 失效：项物理仍在，canEvaluatePolicy 通过，read 才失败
// → 判定为持久（4002 + stale）
check(TouchIDAuthFailure.disposition(biometryAvailable: true) == .persistent,
      "isBiometricsAvailable=true → 持久（4002 + stale）")

// ---- 3. 分道互斥（sanity）----
check(TouchIDAuthFailure.transient != TouchIDAuthFailure.persistent,
      "transient ≠ persistent（分道互斥）")

// ---- 4. 穷举 false/true 全覆盖 ----
check(TouchIDAuthFailure.disposition(biometryAvailable: false) != .persistent,
      "穷举 false → 非持久")
check(TouchIDAuthFailure.disposition(biometryAvailable: true) != .transient,
      "穷举 true → 非瞬时")

print("TOUCH ID AUTH FAILURE TESTS OK —— 6 项断言全部通过")
