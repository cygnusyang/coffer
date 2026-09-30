// McpStatusTests/main.swift —— MCP 设置页纯逻辑单元测试
// （docs/20 §6.1 状态行 / §5.4 注册命令）。
//
// 编译运行：tools/run_mcp_status_tests.sh
//
// 被测单元（Support/McpStatus*.swift）均为纯函数 / 常量：
//   - McpStatus.resolve —— 就绪四态判定（无 IO / 无 FFI / 无进程依赖）
//   - McpStatus.label —— 状态行文案
//   - McpRegisterCommand.build / shellQuote —— 注册命令构造（docs/20 §5.4）
//   - McpProvider —— provider 常量（MVP 恒 op，Coffer 灰态预留）
//   - McpSettings.normalizedVaultName / hasConfiguredVault —— vault 名归一化
//
// 依项目测试纪律（同 TouchIDStatusTests）：只测纯逻辑；UserDefaults 读写等
// IO 薄封装不在此测（KeyboardTier/ClipboardTier 同规）。

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

// ---- 1. McpStatus.resolve：disabled 优先级最高（docs/20 §6.1 开关）----

check(
    McpStatus.resolve(enabled: false, opBinaryAvailable: false, cofferBinaryAvailable: false, sessionAvailable: false) == .disabled,
    "未启用 + 全部缺失 → disabled"
)
check(
    McpStatus.resolve(enabled: false, opBinaryAvailable: true, cofferBinaryAvailable: true, sessionAvailable: true) == .disabled,
    "未启用 + 前置全就绪 → disabled（开关优先，docs/20 §6.1）"
)

// ---- 2. McpStatus.resolve：ready ----

check(
    McpStatus.resolve(enabled: true, opBinaryAvailable: true, cofferBinaryAvailable: true, sessionAvailable: true) == .ready,
    "启用 + op/coffer/会话全就绪 → ready"
)

// ---- 3. McpStatus.resolve：notReady 缺项（按 op → coffer → session 顺序判定）----

check(
    McpStatus.resolve(enabled: true, opBinaryAvailable: false, cofferBinaryAvailable: true, sessionAvailable: true) == .notReady(.missingOpBinary),
    "缺 op 二进制 → missingOpBinary"
)
check(
    McpStatus.resolve(enabled: true, opBinaryAvailable: true, cofferBinaryAvailable: false, sessionAvailable: true) == .notReady(.missingCofferBinary),
    "缺 coffer 二进制 → missingCofferBinary"
)
check(
    McpStatus.resolve(enabled: true, opBinaryAvailable: true, cofferBinaryAvailable: true, sessionAvailable: false) == .notReady(.missingSession),
    "缺会话 → missingSession"
)
check(
    McpStatus.resolve(enabled: true, opBinaryAvailable: false, cofferBinaryAvailable: false, sessionAvailable: false) == .notReady(.missingOpBinary),
    "全缺 → 报第一个缺项（op 优先，sanity）"
)

// ---- 4. McpStatus：Equatable（视图层 switch / 比较依赖）----

check(McpStatus.ready != McpStatus.disabled, "ready ≠ disabled（sanity）")
check(
    McpStatus.notReady(.missingOpBinary) != McpStatus.notReady(.missingSession),
    "不同缺项互不相等（sanity）"
)

// ---- 5. McpStatus.label 状态行文案（docs/20 §6.1 状态行）----

check(McpStatus.disabled.label == "已停用", "disabled 文案")
check(McpStatus.ready.label == "就绪", "ready 文案")
check(McpStatus.notReady(.missingOpBinary).label == "未找到 1Password CLI（op）", "missingOpBinary 文案")
check(McpStatus.notReady(.missingCofferBinary).label == "未找到 coffer 命令", "missingCofferBinary 文案")
check(McpStatus.notReady(.missingSession).label == "未检测到 1Password 会话", "missingSession 文案")

// ---- 6. McpRegisterCommand.build（docs/20 §5.4 注册命令，对齐「Connect to Claude」）----

check(
    McpRegisterCommand.build(provider: "op", vault: nil) == "claude mcp add coffer -- coffer mcp --provider op",
    "无 vault → 省略 --vault（§5.4 基础形态）"
)
check(
    McpRegisterCommand.build(provider: "op", vault: "") == "claude mcp add coffer -- coffer mcp --provider op",
    "空 vault → 省略 --vault"
)
check(
    McpRegisterCommand.build(provider: "op", vault: "  ") == "claude mcp add coffer -- coffer mcp --provider op",
    "全空白 vault → 归一化后省略 --vault"
)
check(
    McpRegisterCommand.build(provider: "op", vault: "Personal") == "claude mcp add coffer -- coffer mcp --provider op --vault Personal",
    "vault=Personal → 追加 --vault Personal"
)
check(
    McpRegisterCommand.build(provider: "op", vault: "My Vault") == "claude mcp add coffer -- coffer mcp --provider op --vault 'My Vault'",
    "vault 含空格 → shell 单引号包裹（粘贴到终端可原样执行）"
)
check(
    McpRegisterCommand.build(provider: "op", vault: " Bob's ") == "claude mcp add coffer -- coffer mcp --provider op --vault 'Bob'\\''s'",
    "vault 含单引号 + 首尾空白 → 归一化 + 单引号转义"
)

// ---- 7. McpRegisterCommand.shellQuote（纯函数边界）----

check(McpRegisterCommand.shellQuote("plain") == "'plain'", "shellQuote 普通串")
check(McpRegisterCommand.shellQuote("a'b") == "'a'\\''b'", "shellQuote 内嵌单引号转义")
check(McpRegisterCommand.shellQuote("") == "''", "shellQuote 空串 → 空参数")

// ---- 8. McpProvider 常量（docs/20 §6.1 Provider 下拉：MVP 恒 op，Coffer 灰态预留）----

check(McpProvider.defaultProvider == .op, "默认 provider = op")
check(McpProvider.op.rawValue == "op", "op 的 CLI flag 值 = op（§5.4 命令用）")
check(McpProvider.op.displayName == "1Password CLI", "op 展示名 = 1Password CLI")
check(McpProvider.coffer.displayName == "Coffer 自家库", "coffer 展示名 = Coffer 自家库（灰态预留）")
check(McpProvider.op.isAvailableInMvp, "op 在本版可用（D-2：MVP 数据源 = op）")
check(!McpProvider.coffer.isAvailableInMvp, "coffer 本版不可用（灰态预留）")

// ---- 9. McpSettings vault 名归一化（纯函数）----

check(McpSettings.normalizedVaultName("  Personal  ") == "Personal", "vault 首尾空白剔除")
check(McpSettings.normalizedVaultName("   ") == "", "全空白 → 空串（未配置）")
check(McpSettings.normalizedVaultName("") == "", "空串 → 空串")
check(McpSettings.hasConfiguredVault("Personal"), "有值 → 已配置")
check(!McpSettings.hasConfiguredVault("  "), "全空白 → 未配置")
check(!McpSettings.hasConfiguredVault(""), "空串 → 未配置")

print("")
print(failed == 0
      ? "MCP STATUS TESTS OK —— \(passed) 项断言全部通过"
      : "MCP STATUS TESTS FAILED —— \(failed)/\(passed + failed) 项断言失败")
if failed > 0 { exit(1) }
