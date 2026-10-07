// McpStatusTests/main.swift —— MCP 设置页纯逻辑单元测试
// （docs/20 §6.1 状态行 / §5.4 注册命令；docs/29 §7.1 翻转 + §5.2 escrow 三态）。
//
// 编译运行：tools/run_mcp_status_tests.sh
//
// 被测单元（Support/McpStatus*.swift）均为纯函数 / 常量：
//   - McpStatus.resolve —— 就绪四态判定（provider 分流，docs/29 §7.1）
//   - McpStatus.label —— 状态行文案
//   - McpEscrowStatus.resolve —— MCP 解锁托管三态判定（docs/29 §5.2）
//   - McpEscrowStatus.label —— 托管状态行文案
//   - McpRegisterCommand.build / shellQuote —— 注册命令构造（docs/20 §5.4 /
//     docs/29 §7.1 coffer 版）
//   - McpProvider —— provider 常量（v2.2.0 默认 coffer，两 provider 均可用）
//   - McpSettings.normalizedVaultName / hasConfiguredVault —— vault 名归一化
//
// 依项目测试纪律（同 TouchIDStatusTests）：只测纯逻辑；UserDefaults 读写等
// IO 薄封装不在此测（KeyboardTier/ClipboardTier 同规）。McpEscrowKeychain
// 走真实 Keychain（IO），归 KeychainTests 域，不在本文件。

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
    McpStatus.resolve(provider: .op, enabled: false, opBinaryAvailable: false, cofferBinaryAvailable: false, sessionAvailable: false, escrowEnabled: false) == .disabled,
    "op：未启用 + 全部缺失 → disabled"
)
check(
    McpStatus.resolve(provider: .op, enabled: false, opBinaryAvailable: true, cofferBinaryAvailable: true, sessionAvailable: true, escrowEnabled: false) == .disabled,
    "op：未启用 + 前置全就绪 → disabled（开关优先，docs/20 §6.1）"
)
check(
    McpStatus.resolve(provider: .coffer, enabled: false, opBinaryAvailable: true, cofferBinaryAvailable: true, sessionAvailable: true, escrowEnabled: true) == .disabled,
    "coffer：未启用 + 前置全就绪 → disabled（开关优先）"
)

// ---- 2. McpStatus.resolve：op 分支 ready 与缺项（op → coffer → session 顺序）----

check(
    McpStatus.resolve(provider: .op, enabled: true, opBinaryAvailable: true, cofferBinaryAvailable: true, sessionAvailable: true, escrowEnabled: false) == .ready,
    "op：启用 + op/coffer/会话全就绪 → ready（escrow 信号不参与 op 分支）"
)
check(
    McpStatus.resolve(provider: .op, enabled: true, opBinaryAvailable: false, cofferBinaryAvailable: true, sessionAvailable: true, escrowEnabled: false) == .notReady(.missingOpBinary),
    "op：缺 op 二进制 → missingOpBinary"
)
check(
    McpStatus.resolve(provider: .op, enabled: true, opBinaryAvailable: true, cofferBinaryAvailable: false, sessionAvailable: true, escrowEnabled: false) == .notReady(.missingCofferBinary),
    "op：缺 coffer 二进制 → missingCofferBinary"
)
check(
    McpStatus.resolve(provider: .op, enabled: true, opBinaryAvailable: true, cofferBinaryAvailable: true, sessionAvailable: false, escrowEnabled: false) == .notReady(.missingSession),
    "op：缺会话 → missingSession"
)
check(
    McpStatus.resolve(provider: .op, enabled: true, opBinaryAvailable: false, cofferBinaryAvailable: false, sessionAvailable: false, escrowEnabled: false) == .notReady(.missingOpBinary),
    "op：全缺 → 报第一个缺项（op 优先，sanity）"
)

// ---- 3. McpStatus.resolve：coffer 分支（docs/29 §7.1：只查 coffer 二进制 + 托管）----

check(
    McpStatus.resolve(provider: .coffer, enabled: true, opBinaryAvailable: true, cofferBinaryAvailable: true, sessionAvailable: true, escrowEnabled: true) == .ready,
    "coffer：启用 + coffer/托管全就绪 → ready（op 信号完全不参与组合）"
)
check(
    McpStatus.resolve(provider: .coffer, enabled: true, opBinaryAvailable: false, cofferBinaryAvailable: true, sessionAvailable: false, escrowEnabled: true) == .ready,
    "coffer：op 二进制/会话全缺失仍 ready（docs/29 §7.1：op 告警仅 op 路径显示）"
)
check(
    McpStatus.resolve(provider: .coffer, enabled: true, opBinaryAvailable: true, cofferBinaryAvailable: false, sessionAvailable: true, escrowEnabled: true) == .notReady(.missingCofferBinary),
    "coffer：缺 coffer 二进制 → missingCofferBinary"
)
check(
    McpStatus.resolve(provider: .coffer, enabled: true, opBinaryAvailable: true, cofferBinaryAvailable: true, sessionAvailable: true, escrowEnabled: false) == .notReady(.missingEscrow),
    "coffer：缺托管 → missingEscrow"
)
check(
    McpStatus.resolve(provider: .coffer, enabled: true, opBinaryAvailable: true, cofferBinaryAvailable: false, sessionAvailable: true, escrowEnabled: false) == .notReady(.missingCofferBinary),
    "coffer：全缺 → 报第一个缺项（coffer 优先于托管，sanity）"
)

// ---- 4. McpStatus：Equatable（视图层 switch / 比较依赖）----

check(McpStatus.ready != McpStatus.disabled, "ready ≠ disabled（sanity）")
check(
    McpStatus.notReady(.missingOpBinary) != McpStatus.notReady(.missingSession),
    "不同缺项互不相等（sanity）"
)
check(
    McpStatus.notReady(.missingEscrow) != McpStatus.notReady(.missingCofferBinary),
    "missingEscrow ≠ missingCofferBinary（sanity）"
)

// ---- 5. McpStatus.label 状态行文案（docs/20 §6.1 状态行）----

check(McpStatus.disabled.label == "已停用", "disabled 文案")
check(McpStatus.ready.label == "就绪", "ready 文案")
check(McpStatus.notReady(.missingOpBinary).label == "未找到 1Password CLI（op）", "missingOpBinary 文案")
check(McpStatus.notReady(.missingCofferBinary).label == "未找到 coffer 命令", "missingCofferBinary 文案")
check(McpStatus.notReady(.missingSession).label == "未检测到 1Password 会话", "missingSession 文案")
check(McpStatus.notReady(.missingEscrow).label == "未启用 MCP 解锁托管", "missingEscrow 文案")

// ---- 6. McpEscrowStatus.resolve：三态判定（docs/29 §5.2，镜像 TouchIDStatus）----

check(
    McpEscrowStatus.resolve(headerMcpWrapAvailable: false, keychainItemExists: true, sessionOpen: true) == .disabled,
    "header 未启用 + Keychain 项存在 → disabled（意图信号优先）"
)
check(
    McpEscrowStatus.resolve(headerMcpWrapAvailable: false, keychainItemExists: false, sessionOpen: true) == .disabled,
    "header 未启用 + 无 Keychain 项 → disabled"
)
check(
    McpEscrowStatus.resolve(headerMcpWrapAvailable: true, keychainItemExists: false, sessionOpen: false) == .disabled,
    "无会话 + header 启用 → disabled（无库会话一律停用）"
)
check(
    McpEscrowStatus.resolve(headerMcpWrapAvailable: true, keychainItemExists: true, sessionOpen: true) == .enabled,
    "header 启用 + Keychain 项存在 → enabled"
)
check(
    McpEscrowStatus.resolve(headerMcpWrapAvailable: true, keychainItemExists: true) == .enabled,
    "sessionOpen 缺省 true → enabled（sanity）"
)
check(
    McpEscrowStatus.resolve(headerMcpWrapAvailable: true, keychainItemExists: false, sessionOpen: true) == .stale,
    "header 启用 + Keychain 项缺失 → stale（外部删除 → 诚实未托管）"
)

// ---- 7. McpEscrowStatus.label（docs/29 §7.2）----

check(McpEscrowStatus.disabled.label == "已停用", "escrow disabled 文案")
check(McpEscrowStatus.enabled.label == "已启用", "escrow enabled 文案")
check(McpEscrowStatus.stale.label == "凭据已失效（需重新启用）", "escrow stale 文案")

// ---- 8. McpRegisterCommand.build（docs/20 §5.4 注册命令，op 版回归 + coffer 版新增）----

// coffer 二进制路径：App 包内嵌套 bundle（docs/20 §5.4 / docs/29 §8 D-6，
// `Contents/Helpers/coffer.app/Contents/MacOS/coffer`，不入 PATH、拷出即 SIGKILL）。
// build 以纯参数接收（不引用 McpStatusProbe，测试进程不装配 bundle 也能测）。
let cofferBin = "/Applications/Coffer.app/Contents/Helpers/coffer.app/Contents/MacOS/coffer"

check(
    McpRegisterCommand.build(provider: "op", vault: nil, cofferBinaryPath: cofferBin) == "claude mcp add coffer -- \(cofferBin) mcp --provider op",
    "op：无 vault → 省略 --vault（§5.4 基础形态，coffer 用包内绝对路径）"
)
check(
    McpRegisterCommand.build(provider: "op", vault: "", cofferBinaryPath: cofferBin) == "claude mcp add coffer -- \(cofferBin) mcp --provider op",
    "op：空 vault → 省略 --vault"
)
check(
    McpRegisterCommand.build(provider: "op", vault: "  ", cofferBinaryPath: cofferBin) == "claude mcp add coffer -- \(cofferBin) mcp --provider op",
    "op：全空白 vault → 归一化后省略 --vault"
)
check(
    McpRegisterCommand.build(provider: "op", vault: "Personal", cofferBinaryPath: cofferBin) == "claude mcp add coffer -- \(cofferBin) mcp --provider op --vault Personal",
    "op：vault=Personal → 追加 --vault Personal"
)
check(
    McpRegisterCommand.build(provider: "op", vault: "My Vault", cofferBinaryPath: cofferBin) == "claude mcp add coffer -- \(cofferBin) mcp --provider op --vault 'My Vault'",
    "op：vault 含空格 → shell 单引号包裹（粘贴到终端可原样执行）"
)
check(
    McpRegisterCommand.build(provider: "op", vault: " Bob's ", cofferBinaryPath: cofferBin) == "claude mcp add coffer -- \(cofferBin) mcp --provider op --vault 'Bob'\\''s'",
    "op：vault 含单引号 + 首尾空白 → 归一化 + 单引号转义"
)

// coffer 版（docs/29 §7.1：-e COFFER_VAULT_DIR=，不含密码 env；路径同样按需引号）
check(
    McpRegisterCommand.build(provider: "coffer", vault: nil, vaultDirPath: "/Users/me/Coffer/Vault", cofferBinaryPath: cofferBin) == "claude mcp add coffer -e COFFER_VAULT_DIR=/Users/me/Coffer/Vault -- \(cofferBin) mcp --provider coffer",
    "coffer：vaultDirPath 常规路径 → 原样（§7.1 形态）"
)
check(
    McpRegisterCommand.build(provider: "coffer", vault: "ignored", vaultDirPath: "/Users/me/Library/Containers/app.coffer.Coffer/Data/Documents/Coffer/uuid", cofferBinaryPath: cofferBin) == "claude mcp add coffer -e COFFER_VAULT_DIR=/Users/me/Library/Containers/app.coffer.Coffer/Data/Documents/Coffer/uuid -- \(cofferBin) mcp --provider coffer",
    "coffer：沙盒容器路径 → 原样（vault 参数被忽略，走 vaultDirPath）"
)
check(
    McpRegisterCommand.build(provider: "coffer", vault: nil, vaultDirPath: "/Users/my name/Coffer", cofferBinaryPath: cofferBin) == "claude mcp add coffer -e COFFER_VAULT_DIR='/Users/my name/Coffer' -- \(cofferBin) mcp --provider coffer",
    "coffer：路径含空格 → shell 单引号包裹"
)
check(
    McpRegisterCommand.build(provider: "coffer", vault: nil, vaultDirPath: "  /Users/me/Coffer  ", cofferBinaryPath: cofferBin) == "claude mcp add coffer -e COFFER_VAULT_DIR=/Users/me/Coffer -- \(cofferBin) mcp --provider coffer",
    "coffer：路径含首尾空白 → 归一化"
)

// coffer 二进制路径本身的引号（包内路径亦可含空格，D-6 装配不约束安装目录）
let spacedCofferBin = "/Applications/My App/Coffer.app/Contents/Helpers/coffer.app/Contents/MacOS/coffer"
check(
    McpRegisterCommand.build(provider: "op", vault: nil, cofferBinaryPath: spacedCofferBin) == "claude mcp add coffer -- '/Applications/My App/Coffer.app/Contents/Helpers/coffer.app/Contents/MacOS/coffer' mcp --provider op",
    "coffer 二进制路径含空格 → shell 单引号包裹（App 可装在含空格目录）"
)
check(
    McpRegisterCommand.build(provider: "coffer", vault: nil, vaultDirPath: "/Users/me/Coffer/Vault", cofferBinaryPath: spacedCofferBin) == "claude mcp add coffer -e COFFER_VAULT_DIR=/Users/me/Coffer/Vault -- '/Applications/My App/Coffer.app/Contents/Helpers/coffer.app/Contents/MacOS/coffer' mcp --provider coffer",
    "coffer：二进制路径含空格 + vaultDirPath 常规 → 各自按需引号"
)

// ---- 9. McpRegisterCommand.shellQuote（纯函数边界）----

check(McpRegisterCommand.shellQuote("plain") == "'plain'", "shellQuote 普通串")
check(McpRegisterCommand.shellQuote("a'b") == "'a'\\''b'", "shellQuote 内嵌单引号转义")
check(McpRegisterCommand.shellQuote("") == "''", "shellQuote 空串 → 空参数")

// ---- 10. McpProvider 常量（docs/29 §7.1 翻转：默认 coffer，两 provider 均可用）----

check(McpProvider.defaultProvider == .coffer, "默认 provider = coffer（docs/29 §7.1 翻转）")
check(McpProvider.op.rawValue == "op", "op 的 CLI flag 值 = op（§5.4 命令用）")
check(McpProvider.coffer.rawValue == "coffer", "coffer 的 CLI flag 值 = coffer")
check(McpProvider.op.displayName == "1Password CLI", "op 展示名 = 1Password CLI")
check(McpProvider.coffer.displayName == "Coffer 自家库", "coffer 展示名 = Coffer 自家库")
check(McpProvider.op.isAvailableInMvp, "op 本版可用（docs/29 §7.1）")
check(McpProvider.coffer.isAvailableInMvp, "coffer 本版可用（取消灰态，docs/29 §7.1）")

// ---- 11. McpSettings vault 名归一化（纯函数）----

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
