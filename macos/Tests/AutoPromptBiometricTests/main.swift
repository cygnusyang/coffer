// AutoPromptBiometricTests/main.swift —— 启动自动 Touch ID 引导判定纯函数
// 单元测试（用户 2026-10-03 裁定 feat：单库 + Touch ID 可用 → 启动不经点击
// 直接弹指纹认证框，一次授权直达主界面）。
//
// 编译运行：tools/run_auto_prompt_biometric_tests.sh
//
// 被测单元 AutoPromptBiometric.shouldAutoPromptBiometric
// （Support/AutoPromptBiometric.swift）是纯函数：无 IO / 无 FFI / 无 Keychain
// 依赖，任何环境（含 CI 沙盒）均可运行（参照 TouchIDStatus 测试同纪律，
// docs/08 §9 T04 验收②）。

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

// ---- 1. 库数量边界（工作目录内仅一个密码库才自动弹）----

check(
    AutoPromptBiometric.shouldAutoPromptBiometric(vaultCount: 0, isSupported: true, status: .enabled) == false,
    "0 库（无库可解锁）→ 不自动弹"
)
check(
    AutoPromptBiometric.shouldAutoPromptBiometric(vaultCount: 2, isSupported: true, status: .enabled) == false,
    "2 库（需用户选择）→ 不自动弹"
)
check(
    AutoPromptBiometric.shouldAutoPromptBiometric(vaultCount: 1, isSupported: true, status: .enabled) == true,
    "1 库 + 支持 + enabled → 自动弹"
)

// ---- 2. 设备支持边界 ----

check(
    AutoPromptBiometric.shouldAutoPromptBiometric(vaultCount: 1, isSupported: false, status: .enabled) == false,
    "单库但设备不支持（无 Touch ID / 未录入指纹）→ 不自动弹"
)

// ---- 3. TouchIDStatus 边界（disabled / stale 均不自动弹）----

check(
    AutoPromptBiometric.shouldAutoPromptBiometric(vaultCount: 1, isSupported: true, status: .disabled) == false,
    "单库 + 支持但通道 disabled（未启用）→ 不自动弹"
)
check(
    AutoPromptBiometric.shouldAutoPromptBiometric(vaultCount: 1, isSupported: true, status: .stale) == false,
    "单库 + 支持但通道 stale（凭据失效）→ 不自动弹"
)

// ---- 4. 全组合穷举（3 × 2 × 3 = 18，无遗漏）----

let counts = [0, 1, 2]
let supports = [false, true]
let statuses: [TouchIDStatus] = [.disabled, .enabled, .stale]
for count in counts {
    for supported in supports {
        for status in statuses {
            let expected = (count == 1) && supported && (status == .enabled)
            let actual = AutoPromptBiometric.shouldAutoPromptBiometric(
                vaultCount: count, isSupported: supported, status: status)
            check(actual == expected,
                  "穷举 (count=\(count), supported=\(supported), status=\(status)) → \(expected)")
        }
    }
}

print("")
print(failed == 0
      ? "AUTO PROMPT BIOMETRIC TESTS OK —— \(passed) 项断言全部通过"
      : "AUTO PROMPT BIOMETRIC TESTS FAILED —— \(failed)/\(passed + failed) 项断言失败")
if failed > 0 { exit(1) }
