// TouchIDStatusTests/main.swift —— Touch ID 三态判定纯函数单元测试
// （docs/08 §9 T04 验收②：状态行三态判定逻辑有单元测试，注入 bio 状态）。
//
// 编译运行：tools/run_touchid_status_tests.sh
//
// 被测单元为 TouchIDStatus.resolve 纯函数（Support/TouchIDStatus.swift）：
// 无 IO / 无 FFI / 无 Keychain 依赖，任何环境（含 CI 沙盒）均可运行。

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

// ---- 1. disabled 组合（docs/08 §8 降级矩阵第一列）----

check(
    TouchIDStatus.resolve(headerWrapAvailable: false, keychainItemExists: false, sessionOpen: true) == .disabled,
    "header 未启用 + 无 Keychain 项 → disabled"
)
check(
    TouchIDStatus.resolve(headerWrapAvailable: false, keychainItemExists: true, sessionOpen: true) == .disabled,
    "header 未启用 + Keychain 孤儿项残留 → disabled（孤儿项不影响判定，docs/08 §4.1）"
)
check(
    TouchIDStatus.resolve(headerWrapAvailable: true, keychainItemExists: true, sessionOpen: false) == .disabled,
    "无会话 → disabled（优先级最高）"
)
check(
    TouchIDStatus.resolve(headerWrapAvailable: true, keychainItemExists: false, sessionOpen: false) == .disabled,
    "无会话 + header 启用 + 无项 → disabled"
)

// ---- 2. enabled / stale 组合 ----

check(
    TouchIDStatus.resolve(headerWrapAvailable: true, keychainItemExists: true, sessionOpen: true) == .enabled,
    "header 启用 + Keychain 项存在 → enabled"
)
check(
    TouchIDStatus.resolve(headerWrapAvailable: true, keychainItemExists: false, sessionOpen: true) == .stale,
    "header 启用 + Keychain 项缺失 → stale（BioStale，docs/08 §4.1）"
)

// ---- 3. sessionOpen 默认参数（调用方省略形式）----

check(
    TouchIDStatus.resolve(headerWrapAvailable: true, keychainItemExists: true) == .enabled,
    "默认 sessionOpen=true：启用组合 → enabled"
)

// ---- 4. 全组合穷举（2³ = 8，无遗漏）----

for header in [false, true] {
    for keychain in [false, true] {
        for session in [false, true] {
            let expectedStatus: TouchIDStatus
            if !session || !header {
                expectedStatus = .disabled
            } else if keychain {
                expectedStatus = .enabled
            } else {
                expectedStatus = .stale
            }
            let actual = TouchIDStatus.resolve(
                headerWrapAvailable: header,
                keychainItemExists: keychain,
                sessionOpen: session
            )
            check(actual == expectedStatus,
                  "穷举 (header=\(header), keychain=\(keychain), session=\(session)) → \(expectedStatus)")
        }
    }
}

// ---- 5. 状态行文案（docs/08 §7.5）----

check(TouchIDStatus.disabled.label == "已停用", "disabled 文案")
check(TouchIDStatus.enabled.label == "已启用", "enabled 文案")
check(TouchIDStatus.stale.label == "凭据已失效（需重新启用）", "stale 文案")

// ---- 6. Equatable 可用（视图层 switch / 比较依赖）----

check(TouchIDStatus.enabled != TouchIDStatus.stale, "三态两两不等（sanity）")

print("")
print(failed == 0
      ? "TOUCHID STATUS TESTS OK —— \(passed) 项断言全部通过"
      : "TOUCHID STATUS TESTS FAILED —— \(failed)/\(passed + failed) 项断言失败")
if failed > 0 { exit(1) }
