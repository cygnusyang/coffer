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

// ---- 5. 防重入判重（docs/08 §7.6 呼出场景：同一次锁定态只弹一次）----
// 完整判定 = 基础条件 ∧ !firedInLockState（同锁定态未弹过）∧ !isBusy（无
// 认证进行中）。基础条件取「全满足」组合（count=1 ∧ supported ∧ .enabled）。

let satisfied = AutoPromptBiometric.shouldAutoPromptBiometric(
    vaultCount: 1, isSupported: true, status: .enabled)
check(satisfied, "基础条件全满足（sanity，供判重组对照）")

check(
    AutoPromptBiometric.shouldAutoPromptBiometric(
        vaultCount: 1, isSupported: true, status: .enabled,
        firedInLockState: true, isBusy: false) == false,
    "同锁定态已弹过（fired）→ 不重复弹"
)
check(
    AutoPromptBiometric.shouldAutoPromptBiometric(
        vaultCount: 1, isSupported: true, status: .enabled,
        firedInLockState: false, isBusy: true) == false,
    "自动认证进行中（isBusy）→ 不重复触发"
)
check(
    AutoPromptBiometric.shouldAutoPromptBiometric(
        vaultCount: 1, isSupported: true, status: .enabled,
        firedInLockState: true, isBusy: true) == false,
    "fired ∧ isBusy → 不弹"
)
check(
    AutoPromptBiometric.shouldAutoPromptBiometric(
        vaultCount: 1, isSupported: true, status: .enabled,
        firedInLockState: false, isBusy: false) == true,
    "未弹过 ∧ 非忙碌 ∧ 基础满足 → 弹（呼出/启动首次）"
)
check(
    AutoPromptBiometric.shouldAutoPromptBiometric(
        vaultCount: 2, isSupported: true, status: .enabled,
        firedInLockState: false, isBusy: false) == false,
    "多库 + 未弹 + 非忙碌 → 不弹（基础条件优先短路）"
)

// ---- 6. BUG-17 回归：可见锁定态激活应允许一次提示（v2.5.0）----
// 触发面扩展（CofferApp summonMainWindow 去 wasHidden 门 + AppDelegate
// applicationDidBecomeActive 钩子，二者统一调 maybeAutoPromptBiometric）后，
// 可见窗口锁定态激活与隐藏恢复激活走同一纯函数判定——本函数签名无
// wasHidden/窗口可见性输入，激活源不可区分；防重入唯一由 firedInLockState
// 旗标保证。回归目标：扩展触发面 = 每次激活放行一次提示，但不得放宽
// 基础门禁（单库 / 支持 / enabled）与防重入（fired / isBusy）。
// （docs/KNOWN-ISSUES.md BUG-17 §修复路径；AppDelegate 接线属 UI 级，
//   附真机手工核销。）

// 6a. 可见锁定态激活（此前 wasHidden==false 死路径，BUG-17 扩展面）首次
// → 允许一次提示
check(
    AutoPromptBiometric.shouldAutoPromptBiometric(
        vaultCount: 1, isSupported: true, status: .enabled,
        firedInLockState: false, isBusy: false) == true,
    "可见锁定态激活首次 → 允许一次提示（BUG-17 扩展面）"
)
// 6b. 同锁定态再次激活（任何激活源，已 fired）→ 不重复弹——多次激活安全
check(
    AutoPromptBiometric.shouldAutoPromptBiometric(
        vaultCount: 1, isSupported: true, status: .enabled,
        firedInLockState: true, isBusy: false) == false,
    "同锁定态再次激活（已弹过一次）→ 不重复弹"
)
// 6c. 激活时自动认证进行中（未 fired 但 isBusy）→ 不并发触发
check(
    AutoPromptBiometric.shouldAutoPromptBiometric(
        vaultCount: 1, isSupported: true, status: .enabled,
        firedInLockState: false, isBusy: true) == false,
    "激活时自动认证进行中 → 不并发触发"
)
// 6d. 扩展触发面不得放宽基础门禁（可见激活路径同样短路）
check(
    AutoPromptBiometric.shouldAutoPromptBiometric(
        vaultCount: 2, isSupported: true, status: .enabled,
        firedInLockState: false, isBusy: false) == false,
    "可见激活 + 多库 → 不弹（基础条件优先短路）"
)
check(
    AutoPromptBiometric.shouldAutoPromptBiometric(
        vaultCount: 1, isSupported: true, status: .disabled,
        firedInLockState: false, isBusy: false) == false,
    "可见激活 + 通道 disabled → 不弹（基础条件优先短路）"
)

print("")
print(failed == 0
      ? "AUTO PROMPT BIOMETRIC TESTS OK —— \(passed) 项断言全部通过"
      : "AUTO PROMPT BIOMETRIC TESTS FAILED —— \(failed)/\(passed + failed) 项断言失败")
if failed > 0 { exit(1) }
