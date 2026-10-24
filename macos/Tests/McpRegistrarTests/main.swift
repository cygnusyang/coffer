// McpRegistrarTests/main.swift —— MCP 一键注册 helper 纯逻辑单元测试
// （CofferMcpHelper.app：McpRegisterSpec 命令结构 + McpRegisterRequest 配置校验）。
//
// 编译运行：tools/run_mcp_registrar_tests.sh
//
// 被测单元（均为纯函数 / 纯数据结构，无 IO / 无进程 / 无 AppKit）：
//   - McpRegisterSpec —— 注册/移除命令 argv 构造**单源**（lead 裁定修正：同一
//     spec 同时编译进 App 与 helper 两个 target，单源落在「同一 spec 构造 argv」，
//     config 只传 vaultDir/cofferBinaryPath 两值，argv **不**经 config 传递，
//     无注入面）。
//   - McpRegisterRequest.validate / isExpectedHelperPath —— 配置校验：coffer
//     二进制路径必须位于 `<某>.app/Contents/Helpers/` 下（安全契约：防其他进程
//     投喂恶意 config 借 helper 注册任意命令）。
//   - McpRegistrar 纯函数（openLaunchArgs / configEnvironment / request /
//     encodeRequest / decodeResult / errorMessage / removeErrorMessage /
//     resultPollDeadline / helperBundleURL）。
//
// 与 run_mcp_status_tests.sh 同纪律：只测纯逻辑；IO（claude resolve / spawn /
// 结果文件读写）归 helper 主入口 main.swift，不在本文件（helper 主入口经
// macos/build 装配验证，standalone 不测 IO 路径）。

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

// 与 MacOS 实际路径同构的样例（docs/20 §5.4 / D-6 嵌套 bundle）
let bundledCoffer = "/Applications/Coffer.app/Contents/Helpers/coffer.app/Contents/MacOS/coffer"
let claudePath = "/Users/me/.local/bin/claude"
let vaultDir = "/Users/me/Library/Containers/top.cygnusyang.coffer/Data/Documents/Coffer/uuid"

// ---- 1. McpRegisterSpec：注册/移除命令 argv 构造（单源，lead 裁定安全契约）----

let commandArgs = McpRegisterSpec.commandArgs(vaultDir: vaultDir, cofferBinaryPath: bundledCoffer)
let fullArgv = McpRegisterSpec.fullArgv(claudePath: claudePath, vaultDir: vaultDir, cofferBinaryPath: bundledCoffer)

check(
    commandArgs == [
        "mcp", "add", "coffer",
        "--scope", "user",
        "-e", "COFFER_VAULT_DIR=\(vaultDir)",
        "--",
        bundledCoffer,
        "mcp", "--provider", "coffer",
    ],
    "commandArgs：注册命令 argv 结构硬编码正确（coffer 版，含 --scope user）"
)
check(fullArgv == [claudePath] + commandArgs, "fullArgv：= [claudePath] + commandArgs（helper 完整 spawn argv）")
check(commandArgs.contains("coffer"), "commandArgs：服务器名恒为 coffer")
check(commandArgs.contains("--scope"), "commandArgs：含 --scope")
check(!commandArgs.contains(where: { $0.contains("PASSWORD") || $0.contains("password") }), "commandArgs：不含任何密码（R2 纪律）")
check(commandArgs.filter { $0.hasPrefix("COFFER_VAULT_DIR=") }.count == 1, "commandArgs：COFFER_VAULT_DIR 恰一份 env 参数")
check(
    McpRegisterSpec.commandArgs(vaultDir: "/v a u", cofferBinaryPath: bundledCoffer)
        .contains("COFFER_VAULT_DIR=/v a u"),
    "commandArgs：vaultDir 含空格仍作单一 argv 元素（无 shell 拼接，无需引号）"
)

// remove 命令（开关 OFF 自动移除；lead 裁定：claude mcp remove coffer --scope user）
check(
    McpRegisterSpec.removeCommandArgs() == ["mcp", "remove", "coffer", "--scope", "user"],
    "removeCommandArgs：claude mcp remove coffer --scope user 结构"
)
check(
    McpRegisterSpec.removeFullArgv(claudePath: claudePath) == [claudePath, "mcp", "remove", "coffer", "--scope", "user"],
    "removeFullArgv：= [claudePath] + removeCommandArgs（helper spawn 用）"
)
check(McpRegisterSpec.removeCommandArgs().filter { $0.hasPrefix("-e") }.isEmpty,
      "removeCommandArgs：移除命令不携带 env 值（无注入面）")

// ---- 2. McpRegisterRequest.validate：配置校验（安全契约）----

// register 合法配置
let validRegister = McpRegisterRequest(
    mode: .register, vaultDir: "/Users/me/Vault", cofferBinaryPath: bundledCoffer, resultPath: "/tmp/result.json"
)
check(validRegister.validate() == nil, "register 合法配置 → 无错误")

// register 缺 vaultDir
let noVault = McpRegisterRequest(mode: .register, vaultDir: nil, cofferBinaryPath: bundledCoffer, resultPath: "/tmp/r.json")
check(noVault.validate() == .missingVaultDir, "register 缺 vaultDir → missingVaultDir")

// register 缺 coffer 二进制
let noBinary = McpRegisterRequest(mode: .register, vaultDir: "/v", cofferBinaryPath: nil, resultPath: "/tmp/r.json")
check(noBinary.validate() == .missingBinary, "register 缺 cofferBinaryPath → missingBinary")

// register coffer 二进制不在 Contents/Helpers/ 下（恶意 config 投喂防御）
let evilBinary = McpRegisterRequest(mode: .register, vaultDir: "/v", cofferBinaryPath: "/tmp/evil", resultPath: "/tmp/r.json")
check(evilBinary.validate() == .binaryOutsideHelpers, "register coffer 二进制不在 Contents/Helpers/ 下 → binaryOutsideHelpers")

// register 缺 resultPath
let noResult = McpRegisterRequest(mode: .register, vaultDir: "/v", cofferBinaryPath: bundledCoffer, resultPath: "")
check(noResult.validate() == .missingResultPath, "register 缺 resultPath → missingResultPath")

// check 模式：仅需 resultPath（vaultDir/二进制可为 nil——check 只读 ~/.claude.json）
let validCheck = McpRegisterRequest(mode: .check, vaultDir: nil, cofferBinaryPath: nil, resultPath: "/tmp/r.json")
check(validCheck.validate() == nil, "check 合法配置（无 vaultDir/二进制）→ 无错误")

let checkNoResult = McpRegisterRequest(mode: .check, vaultDir: nil, cofferBinaryPath: nil, resultPath: "")
check(checkNoResult.validate() == .missingResultPath, "check 缺 resultPath → missingResultPath")

// remove 模式：与 check 同，仅需 resultPath（无 vaultDir/二进制——只 spawn 固定移除命令）
let validRemove = McpRegisterRequest(mode: .remove, vaultDir: nil, cofferBinaryPath: nil, resultPath: "/tmp/r.json")
check(validRemove.validate() == nil, "remove 合法配置（无 vaultDir/二进制）→ 无错误")

let removeNoResult = McpRegisterRequest(mode: .remove, vaultDir: nil, cofferBinaryPath: nil, resultPath: "")
check(removeNoResult.validate() == .missingResultPath, "remove 缺 resultPath → missingResultPath")

// ---- 3. McpRegisterRequest.isExpectedHelperPath：路径白名单校验 ----

check(
    McpRegisterRequest.isExpectedHelperPath(bundledCoffer),
    "isExpectedHelperPath：嵌套 bundle 路径（.app/Contents/Helpers/…）→ true"
)
check(
    McpRegisterRequest.isExpectedHelperPath("/Applications/Coffer.app/Contents/Helpers/coffer.app/Contents/MacOS/coffer"),
    "isExpectedHelperPath：App 包内 Helpers 路径 → true"
)
check(
    !McpRegisterRequest.isExpectedHelperPath("/bin/ls"),
    "isExpectedHelperPath：/bin/ls → false"
)
check(
    !McpRegisterRequest.isExpectedHelperPath("/tmp/evil"),
    "isExpectedHelperPath：/tmp/evil → false"
)
check(
    !McpRegisterRequest.isExpectedHelperPath("rm -rf ~"),
    "isExpectedHelperPath：任意命令串 → false"
)
check(
    !McpRegisterRequest.isExpectedHelperPath("/usr/bin/Contents/Helpers/x"),
    "isExpectedHelperPath：/usr/bin 前缀的伪 Helpers 路径 → false（须 .app 包语义）"
)

// ---- 4. 单源一致性（lead 裁定：App/helper 共享同一 spec 构造 argv，防漂移）----

// App 侧 McpRegisterCommand.buildArgs（coffer 分支）委托 spec.commandArgs；
// helper spawn 用 spec.fullArgv —— 单源真义=同一 spec 构造 argv，一致性由构造
// 保证而非测试比对兜底。
let appCofferArgs = McpRegisterCommand.buildArgs(
    provider: "coffer", vault: nil,
    vaultDirPath: "/Users/me/Coffer/Vault", cofferBinaryPath: bundledCoffer
)
check(
    appCofferArgs == McpRegisterSpec.commandArgs(vaultDir: "/Users/me/Coffer/Vault", cofferBinaryPath: bundledCoffer),
    "单源一致性：App McpRegisterCommand.buildArgs（coffer）== McpRegisterSpec.commandArgs"
)
let helperFull = McpRegisterSpec.fullArgv(claudePath: claudePath, vaultDir: "/Users/me/Coffer/Vault", cofferBinaryPath: bundledCoffer)
check(
    Array(helperFull.dropFirst()) == appCofferArgs,
    "单源一致性：helper fullArgv.dropFirst() == App buildArgs（仅差 claudePath）"
)
check(
    helperFull.count == appCofferArgs.count + 1,
    "单源一致性：数组长度差恰为 1（仅 claudePath）"
)

// ---- 5. mode rawValue 稳定（config JSON 契约）----

check(McpRegisterRequest.Mode.register.rawValue == "register", "mode rawValue=register")
check(McpRegisterRequest.Mode.check.rawValue == "check", "mode rawValue=check")
check(McpRegisterRequest.Mode.remove.rawValue == "remove", "mode rawValue=remove")

// ---- 6. McpRegistrar 纯函数（App 侧协调器可测边界：启动参数 / env 注入 /
//        config/result 编解码 / 错误码文案 / 轮询预算）----

// 6.1 open(1) 启动参数（BUG-29/30 同款）
let helper = URL(fileURLWithPath: "/Applications/Coffer.app/Contents/Helpers/CofferMcpHelper.app")
check(
    McpRegistrar.openLaunchArgs(helper: helper, args: ["--config", "/tmp/c.json"]) == [
        "-n", "/Applications/Coffer.app/Contents/Helpers/CofferMcpHelper.app",
        "--args", "--config", "/tmp/c.json",
    ],
    "openLaunchArgs：-n <helper> --args <args> 结构"
)

// 6.2 env 注入（三层取参第一源）
check(
    McpRegistrar.configEnvironment(from: ["--config", "/tmp/c.json"]) ==
        [McpRegistrar.configEnvironmentKey: "/tmp/c.json"],
    "configEnvironment：含 --config → 注入 COFFER_MCP_REGISTER_CONFIG"
)
check(
    McpRegistrar.configEnvironment(from: ["--config"]) == nil,
    "configEnvironment：--config 缺值 → nil"
)
check(
    McpRegistrar.configEnvironment(from: []) == nil,
    "configEnvironment：无 --config → nil"
)

// 6.3 request 构造（register 需 vaultDir/二进制；check/remove 可空；resultPath=固定名）
let regRequest = McpRegistrar.request(mode: .register, vaultDir: "/Users/me/Vault", cofferBinaryPath: bundledCoffer)
check(regRequest.mode == .register && regRequest.vaultDir == "/Users/me/Vault"
    && regRequest.cofferBinaryPath == bundledCoffer, "request：register 携带 vaultDir/二进制")
check(
    regRequest.resultPath.hasSuffix("/" + McpRegistrar.resultFileName),
    "request：resultPath 指向固定名 result（容器 tmp）"
)
let checkRequest = McpRegistrar.request(mode: .check, vaultDir: nil, cofferBinaryPath: nil)
check(checkRequest.mode == .check && checkRequest.vaultDir == nil && checkRequest.cofferBinaryPath == nil,
      "request：check 无 vaultDir/二进制")
check(checkRequest.validate() == nil, "request：register/check 均过 validate（合法契约）")
let removeRequest = McpRegistrar.request(mode: .remove, vaultDir: nil, cofferBinaryPath: nil)
check(removeRequest.mode == .remove && removeRequest.vaultDir == nil && removeRequest.cofferBinaryPath == nil,
      "request：remove 无 vaultDir/二进制")
check(removeRequest.validate() == nil, "request：remove 过 validate")

// 6.4 config 编解码往返（sortedKeys 确定性序列化 ↔ helper 同 schema）
let encoded = try McpRegistrar.encodeRequest(regRequest)
let decodedBack = try JSONDecoder().decode(McpRegisterRequest.self, from: encoded)
check(decodedBack == regRequest, "encodeRequest/decode 往返一致（App↔helper config schema）")
let encodedJSON = String(data: encoded, encoding: .utf8) ?? ""
check(encodedJSON.contains("\"mode\":\"register\""), "config JSON 含 mode 字段（helper 解码所需）")
let encodedRemove = try McpRegistrar.encodeRequest(removeRequest)
let encodedRemoveJSON = String(data: encodedRemove, encoding: .utf8) ?? ""
check(encodedRemoveJSON.contains("\"mode\":\"remove\""), "config JSON remove 模式含 mode 字段")

// 6.5 result 解码（helper 写回 schema）
let helperResultJSON = """
{"success":false,"code":"claudeNotFound","message":"注册失败：未找到 Claude Code CLI。","registered":false,"vaultDir":null}
""".data(using: .utf8)!
let decodedResult = try McpRegistrar.decodeResult(helperResultJSON)
check(decodedResult.success == false && decodedResult.code == .claudeNotFound && decodedResult.registered == false,
      "decodeResult：helper result JSON 解析（code/registered）")
let okJSON = """
{"success":true,"code":"ok","message":"已注册","registered":true,"vaultDir":"/Users/me/Vault"}
""".data(using: .utf8)!
let okResult = try McpRegistrar.decodeResult(okJSON)
check(okResult.success && okResult.registered == true && okResult.vaultDir == "/Users/me/Vault",
      "decodeResult：成功结果含 vaultDir 提取")

// 6.6 错误码文案（全部有非空映射；关键分支可区分；注册/移除两套语境）
let allCodes: [ResultCode] = [.ok, .configInvalid, .cofferBinaryInvalid, .claudeNotFound,
                              .claudeTimeout, .claudeAddFailed, .claudeRemoveFailed,
                              .notRegistered, .checkFailed, .resultWriteFailed]
check(allCodes.allSatisfy { !McpRegistrar.errorMessage(for: $0).isEmpty }, "errorMessage：全部 code 有非空文案")
check(McpRegistrar.errorMessage(for: .ok) != McpRegistrar.errorMessage(for: .claudeNotFound),
      "errorMessage：成功与 claude 缺失文案可区分")
check(McpRegistrar.errorMessage(for: .resultWriteFailed).contains("超时") ||
      McpRegistrar.errorMessage(for: .resultWriteFailed).contains("结果"),
      "errorMessage：resultWriteFailed 指向超时兜底（可操作）")
check(allCodes.allSatisfy { !McpRegistrar.removeErrorMessage(for: $0).isEmpty },
      "removeErrorMessage：全部 code 有非空文案")
check(McpRegistrar.removeErrorMessage(for: .ok).contains("已停用"), "removeErrorMessage：ok 为已停用语义")
check(McpRegistrar.removeErrorMessage(for: .claudeNotFound).contains("claude mcp remove"),
      "removeErrorMessage：claude 缺失含手动清理指引（claude mcp remove coffer）")
check(McpRegistrar.removeErrorMessage(for: .claudeRemoveFailed).contains("claude mcp remove"),
      "removeErrorMessage：移除失败含手动清理指引")

// 6.7 轮询预算（≤15s 硬超时）
let deadline = McpRegistrar.resultPollDeadline(from: Date(timeIntervalSince1970: 1_000))
check(abs(deadline.timeIntervalSince1970 - 1_000 - McpRegistrar.resultPollTimeout) < 0.01,
      "resultPollDeadline：now + resultPollTimeout 预算")

// 6.8 helper bundle 路径（App 包内嵌套位置，与 build 脚本 3.7 装配点一致）
let appBundle = URL(fileURLWithPath: "/Applications/Coffer.app")
check(
    McpRegistrar.helperBundleURL(appBundle: appBundle).path ==
        "/Applications/Coffer.app/Contents/Helpers/CofferMcpHelper.app",
    "helperBundleURL：Contents/Helpers/CofferMcpHelper.app（build 3.7 装配点）"
)

// ---- 7. McpAgentTarget：target 元数据（v2.12.0 多 AI 工具注册）----

check(McpAgentTarget.allCases.count == 8, "target：allCases 恰 8 家")
check(McpAgentTarget.autoRegisterTargets == [.claudeCode, .codeBuddy, .codex],
      "target：自动注册组顺序固定 Claude Code → CodeBuddy → Codex")
check(McpAgentTarget.autoRegisterTargets.count == 3, "target：自动注册组恰 3 家")
check(Set(McpAgentTarget.autoRegisterTargets.map(\.displayName)) == Set(["Claude Code", "CodeBuddy", "Codex"]),
      "target：自动注册组 displayName 集合恰为三家（字面量）")
check(McpAgentTarget.copyOnlyTargets.count == 5, "target：copy-only 恰 5 家")
check(Set(McpAgentTarget.copyOnlyTargets.map(\.rawValue)) == Set(["gemini-cli", "cursor", "vscode", "windsurf", "zed"]),
      "target：copy-only 集合字面量（gemini-cli/cursor/vscode/windsurf/zed）")
check(Set(McpAgentTarget.allCases.map(\.displayName)).count == 8, "target：8 个 displayName 两两不同")
check(McpAgentTarget.allCases.allSatisfy { !$0.displayName.isEmpty }, "target：displayName 均非空")
check(McpAgentTarget.autoRegisterTargets.allSatisfy { $0.isAutoRegister },
      "target：autoRegisterTargets 内每家的 isAutoRegister 均为 true")
check(McpAgentTarget.copyOnlyTargets.allSatisfy { !$0.isAutoRegister },
      "target：copyOnlyTargets 内每家的 isAutoRegister 均为 false")

// 逐家钉死 displayName / isAutoRegister / cliName（字面量断言：防常量被改成互相引用后自洽）
let targetExpectations: [(McpAgentTarget, String, Bool, String?)] = [
    (.claudeCode, "Claude Code", true, "claude"),
    (.codeBuddy, "CodeBuddy", true, "codebuddy"),
    (.codex, "Codex", true, "codex"),
    (.geminiCLI, "Gemini CLI", false, nil),
    (.cursor, "Cursor", false, nil),
    (.vscode, "VS Code", false, nil),
    (.windsurf, "Windsurf", false, nil),
    (.zed, "Zed", false, nil),
]
for (target, expectedName, expectedAuto, expectedCLI) in targetExpectations {
    check(target.displayName == expectedName, "target：\(expectedName) displayName 字面量")
    check(target.isAutoRegister == expectedAuto, "target：\(expectedName) isAutoRegister=\(expectedAuto)")
    check(target.cliName == expectedCLI, "target：\(expectedName) cliName=\(expectedCLI ?? "nil")")
}
check(McpAgentTarget.allCases.filter { $0.cliName == nil }.count == 5,
      "target：cliName 为 nil 的恰 5 家（= copy-only，不探测）")

// ---- 8. 自动注册 argv：Claude/CodeBuddy 冻结形状 + Codex --env 形态 ----

let freezeAdd: [String] = [
    "mcp", "add", "coffer",
    "--scope", "user",
    "-e", "COFFER_VAULT_DIR=\(vaultDir)",
    "--",
    bundledCoffer,
    "mcp", "--provider", "coffer",
]
let claudeAddArgs = McpAgentTarget.claudeCode.addArgs(vaultDir: vaultDir, cofferBinaryPath: bundledCoffer)
let codeBuddyAddArgs = McpAgentTarget.codeBuddy.addArgs(vaultDir: vaultDir, cofferBinaryPath: bundledCoffer)
let codexAddArgs = McpAgentTarget.codex.addArgs(vaultDir: vaultDir, cofferBinaryPath: bundledCoffer)

check(claudeAddArgs == freezeAdd,
      "argv：Claude add 与 v2.11.1 冻结形状逐元素一致（--scope user / -e / -- <bin> / mcp --provider coffer）")
check(claudeAddArgs == McpRegisterSpec.commandArgs(vaultDir: vaultDir, cofferBinaryPath: bundledCoffer),
      "argv：Claude add 与 McpRegisterSpec.commandArgs 同构（单源未分叉）")
check(McpRegisterSpec.fullArgv(claudePath: claudePath, vaultDir: vaultDir, cofferBinaryPath: bundledCoffer)
        == [claudePath] + (claudeAddArgs ?? []),
      "argv：Claude fullArgv = [cliPath] + addArgs（仅差 CLI 路径）")
check(codeBuddyAddArgs == freezeAdd,
      "argv：CodeBuddy add 与 Claude 同形（C1 裁决：--scope user + -e）")
check(codeBuddyAddArgs != codexAddArgs,
      "argv：CodeBuddy 与 Codex argv 不同构（防两 target 复用同一份 argv）")

check(codexAddArgs == [
    "mcp", "add", "coffer",
    "--env", "COFFER_VAULT_DIR=\(vaultDir)",
    "--",
    bundledCoffer,
    "mcp", "--provider", "coffer",
], "argv：Codex add 用 --env 且逐元素一致")
check(codexAddArgs?.contains("--scope") == false, "argv：Codex add 不含 --scope（无 scope 概念）")
check(codexAddArgs?.contains("user") == false, "argv：Codex add 不含 scope 值 user")
check(McpAgentTarget.codex.removeArgs() == ["mcp", "remove", "coffer"], "argv：Codex remove 逐元素一致")
check(McpAgentTarget.codex.removeArgs()?.contains("--scope") == false, "argv：Codex remove 不含 --scope")
check(McpAgentTarget.claudeCode.removeArgs() == ["mcp", "remove", "coffer", "--scope", "user"],
      "argv：Claude remove 与 v2.11.1 一致（--scope user）")
check(McpAgentTarget.codeBuddy.removeArgs() == ["mcp", "remove", "coffer", "--scope", "user"],
      "argv：CodeBuddy remove 与 Claude 一致（--scope user）")

// env 形参必须匹配 target（只数 COFFER_VAULT_DIR= 前缀会漏掉 -e / --env 混淆）
func argumentBefore(_ needle: String, in args: [String]?) -> String? {
    guard let args, let index = args.firstIndex(where: { $0.hasPrefix(needle) }), index > 0 else { return nil }
    return args[index - 1]
}
check(argumentBefore("COFFER_VAULT_DIR=", in: claudeAddArgs) == "-e", "argv：Claude 的 vaultDir 形参是 -e")
check(argumentBefore("COFFER_VAULT_DIR=", in: codeBuddyAddArgs) == "-e", "argv：CodeBuddy 的 vaultDir 形参是 -e")
check(argumentBefore("COFFER_VAULT_DIR=", in: codexAddArgs) == "--env", "argv：Codex 的 vaultDir 形参是 --env")
check(claudeAddArgs?.filter { $0.hasPrefix("COFFER_VAULT_DIR=") }.count == 1,
      "argv：Claude 的 COFFER_VAULT_DIR env 恰一份")
check(codexAddArgs?.filter { $0.hasPrefix("COFFER_VAULT_DIR=") }.count == 1,
      "argv：Codex 的 COFFER_VAULT_DIR env 恰一份")

// 注入面：值永远是单个 argv 元素（原样保留，不做 shell 转义）
let hostileVaultDir = "/v a u'e; rm -rf ~"
let hostileClaudeArgs = McpAgentTarget.claudeCode.addArgs(vaultDir: hostileVaultDir, cofferBinaryPath: bundledCoffer) ?? []
let hostileCodexArgs = McpAgentTarget.codex.addArgs(vaultDir: hostileVaultDir, cofferBinaryPath: bundledCoffer) ?? []
check(hostileClaudeArgs.contains("COFFER_VAULT_DIR=" + hostileVaultDir),
      "argv：含空格/引号/shell 元字符的 vaultDir 仍是单一 argv 元素（原样不转义）")
check(hostileClaudeArgs.count == freezeAdd.count, "argv：恶意 vaultDir 不改变 Claude argv 形状")
check(hostileCodexArgs.contains("COFFER_VAULT_DIR=" + hostileVaultDir),
      "argv：恶意 vaultDir 在 Codex 侧同样是单一 argv 元素")
check(hostileCodexArgs.count == (codexAddArgs?.count ?? -1), "argv：恶意 vaultDir 不改变 Codex argv 形状")
check(hostileClaudeArgs.allSatisfy { $0 != "sh" && $0 != "bash" && $0 != "-c" },
      "argv：无 shell 解释器元素（值不经 shell）")
check((claudeAddArgs ?? []).allSatisfy { !$0.uppercased().contains("PASSWORD") },
      "argv：Claude argv 不含密码")
check((codexAddArgs ?? []).allSatisfy { !$0.uppercased().contains("PASSWORD") },
      "argv：Codex argv 不含密码")

check(McpAgentTarget.copyOnlyTargets.allSatisfy {
    $0.addArgs(vaultDir: vaultDir, cofferBinaryPath: bundledCoffer) == nil
}, "argv：copy-only 5 家 addArgs 均为 nil（无自动注册面）")
check(McpAgentTarget.copyOnlyTargets.allSatisfy { $0.removeArgs() == nil },
      "argv：copy-only 5 家 removeArgs 均为 nil")
check(McpAgentTarget.autoRegisterTargets.allSatisfy {
    $0.addArgs(vaultDir: vaultDir, cofferBinaryPath: bundledCoffer) != nil && $0.removeArgs() != nil
}, "argv：auto 3 家 add/remove argv 均存在")

// ---- 9. 配置落点与解析（JSON / TOML / 坏输入）----

let fakeHome = "/Users/me"
check(McpAgentTarget.claudeCode.configPaths(home: fakeHome) == [fakeHome + "/.claude.json"],
      "configPaths：Claude = ~/.claude.json（顶层 mcpServers）")
check(McpAgentTarget.codex.configPaths(home: fakeHome) == [fakeHome + "/.codex/config.toml"],
      "configPaths：Codex = ~/.codex/config.toml")
check(McpAgentTarget.codeBuddy.configPaths(home: fakeHome).first == fakeHome + "/.codebuddy/mcp.json",
      "configPaths：CodeBuddy 首候选 = ~/.codebuddy/mcp.json（优先）")
check(McpAgentTarget.codeBuddy.configPaths(home: fakeHome).count == 3,
      "configPaths：CodeBuddy 3 条候选（路径演进）且首候选固定")
check(McpAgentTarget.copyOnlyTargets.allSatisfy { $0.configPaths(home: fakeHome).isEmpty },
      "configPaths：copy-only 无注册落点（不读不写）")
check(McpAgentTarget.claudeCode.configFormat == .json
        && McpAgentTarget.codeBuddy.configFormat == .json
        && McpAgentTarget.codex.configFormat == .toml
        && McpAgentTarget.zed.configFormat == .none,
      "configFormat：Claude/CodeBuddy=json、Codex=toml、copy-only=none")

let claudeConfigJSON = """
{"mcpServers":{"coffer":{"command":"\(bundledCoffer)","args":["mcp","--provider","coffer"],"env":{"COFFER_VAULT_DIR":"/Users/me/Vault"}}}}
"""
let parsedClaudeState = McpAgentTarget.claudeCode.parseRegisteredVaultDir(text: claudeConfigJSON)
check(parsedClaudeState.registered && parsedClaudeState.vaultDir == "/Users/me/Vault",
      "config：Claude 顶层 mcpServers.coffer 解析出 registered + vaultDir")

let projectOnlyJSON = """
{"projects":{"/x":{"mcpServers":{"coffer":{"command":"x"}}}},"mcpServers":{}}
"""
check(!McpAgentTarget.claudeCode.parseRegisteredVaultDir(text: projectOnlyJSON).registered,
      "config：仅项目级 mcpServers 有条目不算全局注册（防越权误判）")

let noEnvJSON = """
{"mcpServers":{"coffer":{"command":"x","args":[]}}}
"""
let noEnvState = McpAgentTarget.claudeCode.parseRegisteredVaultDir(text: noEnvJSON)
check(noEnvState.registered && noEnvState.vaultDir == nil,
      "config：已注册但 env 缺失 → registered=true / vaultDir=nil（不得当作目录匹配）")

let noCofferJSON = """
{"mcpServers":{"other":{"command":"x"}}}
"""
check(!McpAgentTarget.claudeCode.parseRegisteredVaultDir(text: noCofferJSON).registered,
      "config：mcpServers 无 coffer 键 → 未注册")

check(!McpAgentTarget.claudeCode.parseRegisteredVaultDir(text: "{\"mcpServers\":{").registered,
      "config：截断 JSON → 未注册（不崩溃）")
check(!McpAgentTarget.claudeCode.parseRegisteredVaultDir(text: "").registered,
      "config：空文本 → 未注册（不崩溃）")
check(!McpAgentTarget.claudeCode.parseRegisteredVaultDir(text: "[1,2,3]").registered,
      "config：根为数组 → 未注册（不崩溃）")
check(!McpAgentTarget.claudeCode.parseRegisteredVaultDir(text: "{\"mcpServers\":{\"coffer\":42}}").registered,
      "config：coffer 值非对象 → 未注册（不崩溃）")

let codexConfigTOML = """
[mcp_servers.coffer]
command = "\(bundledCoffer)"
args = ["mcp", "--provider", "coffer"]

[mcp_servers.coffer.env]
COFFER_VAULT_DIR = "/Users/me/Vault"
"""
let parsedCodexState = McpAgentTarget.codex.parseRegisteredVaultDir(text: codexConfigTOML)
check(parsedCodexState.registered && parsedCodexState.vaultDir == "/Users/me/Vault",
      "config：Codex [mcp_servers.coffer] + [.env] 解析出 registered + vaultDir")

let otherServerTOML = """
[mcp_servers.other]
command = "x"

[mcp_servers.other.env]
COFFER_VAULT_DIR = "/wrong"
"""
check(!McpAgentTarget.codex.parseRegisteredVaultDir(text: otherServerTOML).registered,
      "config：其它工具的 mcp_servers 表不算 coffer 注册（防正则扫字样假绿）")

let mainTableOnlyTOML = """
[mcp_servers.coffer]
command = "\(bundledCoffer)"
"""
let mainOnlyState = McpAgentTarget.codex.parseRegisteredVaultDir(text: mainTableOnlyTOML)
check(mainOnlyState.registered && mainOnlyState.vaultDir == nil,
      "config：有主表无 .env 子表 → registered=true / vaultDir=nil")

check(!McpAgentTarget.codex.parseRegisteredVaultDir(text: "[mcp_servers.coffer").registered,
      "config：未闭合表头 → 未注册（不崩溃）")

let escapedTOML = #"""
[mcp_servers.coffer.env]
COFFER_VAULT_DIR = "/a \" b"
"""#
check(McpAgentTarget.codex.parseRegisteredVaultDir(text: escapedTOML).vaultDir == "/a \" b",
      "config：TOML 基本字符串的 \" 转义还原")

let literalTOML = #"""
[mcp_servers.coffer.env]
COFFER_VAULT_DIR = '/a \ b'
"""#
check(McpAgentTarget.codex.parseRegisteredVaultDir(text: literalTOML).vaultDir == "/a \\ b",
      "config：TOML 字面量字符串（单引号）不做反斜杠转义")

let unclosedQuoteTOML = """
[mcp_servers.coffer.env]
COFFER_VAULT_DIR = "/a
"""
let unclosedState = McpAgentTarget.codex.parseRegisteredVaultDir(text: unclosedQuoteTOML)
check(unclosedState.registered && unclosedState.vaultDir == nil,
      "config：值引号未闭合 → vaultDir=nil（不返回半截字符串）")

// ---- 10. copy-only 复制内容：键名 / 可回读 / 转义 ----

let copyVaultDir = "/Users/me/Vault"
let geminiCopy = McpAgentTarget.geminiCLI.copyCommand(vaultDir: copyVaultDir, cofferBinaryPath: bundledCoffer)
check(geminiCopy.hasPrefix("gemini mcp add coffer "), "copy：Gemini 以 gemini mcp add coffer 开头")
check(geminiCopy.contains(" -s user"), "copy：Gemini 用 -s user")
check(!geminiCopy.contains("--scope"), "copy：Gemini 不含 --scope（防抄 Claude 形状）")
check(geminiCopy.contains(" -e COFFER_VAULT_DIR=" + copyVaultDir), "copy：Gemini 带 -e COFFER_VAULT_DIR")
check(geminiCopy.hasSuffix(bundledCoffer + " mcp --provider coffer -s user -e COFFER_VAULT_DIR=\(copyVaultDir)"),
      "copy：Gemini 命令尾为 <bin> mcp --provider coffer + -s/-e")

func jsonBody(of command: String, prefix: String) -> String? {
    guard command.hasPrefix(prefix) else { return nil }
    var body = String(command.dropFirst(prefix.count))
    if body.hasPrefix("'"), body.hasSuffix("'"), body.count >= 2 {
        body = String(body.dropFirst().dropLast())
    }
    return body
}
func jsonRoot(_ text: String?) -> [String: Any]? {
    guard let text, let data = text.data(using: .utf8) else { return nil }
    return (try? JSONSerialization.jsonObject(with: data)) as? [String: Any]
}
func envValue(_ root: [String: Any]?, _ table: String) -> String? {
    let entry = root?[table] as? [String: Any]
    return (entry?["env"] as? [String: Any])?["COFFER_VAULT_DIR"] as? String
}

let cursorCopy = McpAgentTarget.cursor.copyCommand(vaultDir: copyVaultDir, cofferBinaryPath: bundledCoffer)
let cursorRoot = jsonRoot(jsonBody(of: cursorCopy, prefix: "cursor --add-mcp "))
check(cursorRoot?["name"] as? String == "coffer", "copy：Cursor 载荷 name=coffer")
check(cursorRoot?["command"] as? String == bundledCoffer, "copy：Cursor 载荷 command=<bin>")
check((cursorRoot?["args"] as? [String]) == ["mcp", "--provider", "coffer"], "copy：Cursor 载荷 args")
check((cursorRoot?["env"] as? [String: Any])?["COFFER_VAULT_DIR"] as? String == copyVaultDir,
      "copy：Cursor 载荷 env.COFFER_VAULT_DIR 逐字节一致")

let vscodeCopy = McpAgentTarget.vscode.copyCommand(vaultDir: copyVaultDir, cofferBinaryPath: bundledCoffer)
let vscodeRoot = jsonRoot(jsonBody(of: vscodeCopy, prefix: "code --add-mcp "))
check(vscodeRoot?["name"] as? String == "coffer", "copy：VS Code 载荷 name=coffer")
check(vscodeRoot?["type"] as? String == "stdio", "copy：VS Code 载荷 type=stdio")
check(vscodeRoot?["command"] as? String == bundledCoffer, "copy：VS Code 载荷 command=<bin>")
check((vscodeRoot?["env"] as? [String: Any])?["COFFER_VAULT_DIR"] as? String == copyVaultDir,
      "copy：VS Code 载荷 env.COFFER_VAULT_DIR")
check((vscodeRoot?["args"] as? [String]) == ["mcp", "--provider", "coffer"], "copy：VS Code 载荷 args")

let windsurfRoot = jsonRoot(McpAgentTarget.windsurf.copyCommand(vaultDir: copyVaultDir, cofferBinaryPath: bundledCoffer))
check(windsurfRoot?["mcpServers"] != nil, "copy：Windsurf 顶层键 mcpServers")
check(windsurfRoot?["servers"] == nil && windsurfRoot?["context_servers"] == nil,
      "copy：Windsurf 不混用 servers/context_servers 顶层键")
check(((windsurfRoot?["mcpServers"] as? [String: Any])?["coffer"] as? [String: Any])?["command"] as? String == bundledCoffer,
      "copy：Windsurf mcpServers.coffer.command=<bin>")
check(envValue(windsurfRoot?["mcpServers"] as? [String: Any], "coffer") == copyVaultDir,
      "copy：Windsurf mcpServers.coffer.env.COFFER_VAULT_DIR")

let zedRoot = jsonRoot(McpAgentTarget.zed.copyCommand(vaultDir: copyVaultDir, cofferBinaryPath: bundledCoffer))
check(zedRoot?["context_servers"] != nil, "copy：Zed 顶层键 context_servers")
check(zedRoot?["mcpServers"] == nil && zedRoot?["servers"] == nil,
      "copy：Zed 不混用 mcpServers/servers 顶层键")
let zedEntry = (zedRoot?["context_servers"] as? [String: Any])?["coffer"] as? [String: Any]
check(zedEntry?["source"] as? String == "custom", "copy：Zed context_servers.coffer.source=custom")
check(zedEntry?["command"] as? String == bundledCoffer, "copy：Zed coffer.command=<bin>")
check((zedEntry?["args"] as? [String]) == ["mcp", "--provider", "coffer"], "copy：Zed coffer.args")
check((zedEntry?["env"] as? [String: Any])?["COFFER_VAULT_DIR"] as? String == copyVaultDir,
      "copy：Zed coffer.env.COFFER_VAULT_DIR")

// 自动注册目标的复制串 = 完整 shell 命令（与 v2.11.1 展示串一致）
let claudeCopy = McpAgentTarget.claudeCode.copyCommand(vaultDir: copyVaultDir, cofferBinaryPath: bundledCoffer)
check(claudeCopy == "claude mcp add coffer --scope user -e COFFER_VAULT_DIR=\(copyVaultDir) -- \(bundledCoffer) mcp --provider coffer",
      "copy：Claude 复制串与 v2.11.1 展示串逐字符一致")
check(claudeCopy == McpRegisterCommand.build(provider: "coffer", vault: nil,
                                             vaultDirPath: copyVaultDir, cofferBinaryPath: bundledCoffer),
      "copy：Claude 复制串与 McpRegisterCommand.build 同源（App 展示未分叉）")
check(McpAgentTarget.codex.copyCommand(vaultDir: copyVaultDir, cofferBinaryPath: bundledCoffer)
        .hasPrefix("codex mcp add coffer --env COFFER_VAULT_DIR="),
      "copy：Codex 复制串用 codex + --env 形态")

// 转义：shell 通道 vs JSON 通道不可混用
let quotedVaultDir = "/Users/me/Vault's"
let geminiQuotedCopy = McpAgentTarget.geminiCLI.copyCommand(vaultDir: quotedVaultDir, cofferBinaryPath: bundledCoffer)
check(geminiQuotedCopy.contains("'\\''"), "copy：shell 串把值内单引号转义为 '\\''")
check(!geminiQuotedCopy.contains("\\u0027"), "copy：shell 串不出现 JSON 转义 \\u0027")

let spacedVaultDir = "/Users/me/Vault Dir"
let geminiSpacedCopy = McpAgentTarget.geminiCLI.copyCommand(vaultDir: spacedVaultDir, cofferBinaryPath: bundledCoffer)
check(geminiSpacedCopy.contains("'COFFER_VAULT_DIR=\(spacedVaultDir)'"),
      "copy：含空格值整体单引号包裹（可粘贴）")

let windsurfQuotedRoot = jsonRoot(McpAgentTarget.windsurf.copyCommand(vaultDir: quotedVaultDir, cofferBinaryPath: bundledCoffer))
let windsurfQuotedEnv = (windsurfQuotedRoot?["mcpServers"] as? [String: Any])
check(((windsurfQuotedEnv?["coffer"] as? [String: Any])?["env"] as? [String: Any])?["COFFER_VAULT_DIR"] as? String
        == quotedVaultDir,
      "copy：JSON 通道含单引号值可回读且不被 shell 转义污染")
let windsurfSpacedRoot = jsonRoot(McpAgentTarget.windsurf.copyCommand(vaultDir: spacedVaultDir, cofferBinaryPath: bundledCoffer))
check(((windsurfSpacedRoot?["mcpServers"] as? [String: Any])?["coffer"] as? [String: Any]) != nil,
      "copy：JSON 通道含空格值仍可解析")

let allCopyStrings = McpAgentTarget.allCases.map {
    $0.copyCommand(vaultDir: copyVaultDir, cofferBinaryPath: bundledCoffer)
}
check(allCopyStrings.allSatisfy { !$0.isEmpty }, "copy：8 家 copyCommand 均非空")
check(allCopyStrings.allSatisfy { !$0.uppercased().contains("PASSWORD") }, "copy：复制内容不含密码")
check(allCopyStrings.allSatisfy { !$0.contains(McpRegistrar.configFileName) },
      "copy：复制内容不含内部 config 文件名")

// ---- 11. probe：mode / request / result 编解码 ----

check(McpRegisterRequest.Mode.probe.rawValue == "probe", "probe：mode rawValue=probe")
check(McpRegisterResult(success: true, code: .ok, message: "m", registered: false, vaultDir: nil).installedTargets == nil,
      "probe：非 probe 结果 installedTargets 为 nil（旧 helper 兼容）")

let probeRequest = McpRegistrar.request(mode: .probe, target: .codex, vaultDir: nil, cofferBinaryPath: nil)
check(probeRequest.target == .codex, "probe：request 显式携带 target（不被缺省吞掉）")
check(probeRequest.resolvedTarget == .codex, "probe：resolvedTarget 回落到显式 target")
check(probeRequest.validate() == nil, "probe：probe 模式仅需 resultPath，校验通过")
check(McpRegistrar.request(mode: .check, vaultDir: nil, cofferBinaryPath: nil).resolvedTarget == .claudeCode,
      "probe：旧调用点（无 target）回落 Claude Code（v2.11.1 兼容）")

let probeResultJSON = #"{"success":true,"code":"ok","message":"已检测","registered":false,"vaultDir":null,"installedTargets":["codex"]}"#
    .data(using: .utf8)!
let decodedProbe = try McpRegistrar.decodeResult(probeResultJSON)
check(decodedProbe.installedTargets == ["codex"], "probe：result 解码 installedTargets（rawValue 数组）")
check(decodedProbe.code == .ok && !decodedProbe.registered, "probe：成功检测 registered 恒 false（不改配置）")
check(McpAgentTarget.autoRegisterTargets.map(\.rawValue) == ["claude-code", "codebuddy", "codex"],
      "probe：installedTargets 使用稳定 rawValue（顺序同 autoRegisterTargets）")

let probeResultPayload = McpRegisterResult(success: true, code: .ok, message: "m", registered: false,
                                           vaultDir: nil, installedTargets: ["claude-code", "codex"])
let probeEncoded = try JSONEncoder().encode(probeResultPayload)
let probeEncodedText = String(data: probeEncoded, encoding: .utf8) ?? ""
check(probeEncodedText.contains("\"installedTargets\""), "probe：result JSON 含 installedTargets 键（App↔helper 契约）")
let probeRoundTrip = try JSONDecoder().decode(McpRegisterResult.self, from: probeEncoded)
check(probeRoundTrip.installedTargets == ["claude-code", "codex"], "probe：installedTargets 编解码往返一致")

let encodedTargets = try JSONEncoder().encode([McpAgentTarget.geminiCLI, .zed])
let decodedTargets = try JSONDecoder().decode([McpAgentTarget].self, from: encodedTargets)
check(decodedTargets == [.geminiCLI, .zed], "probe：target 编解码往返（rawValue 契约稳定）")

// ---- 12. SAFE：copy-only 误调 register / 文案随 target ----

check(McpAgentTarget.copyOnlyTargets.allSatisfy {
    !$0.isAutoRegister
        && $0.addArgs(vaultDir: vaultDir, cofferBinaryPath: bundledCoffer) == nil
        && $0.removeArgs() == nil
}, "SAFE：copy-only 三件事同时成立（非 auto / 无 add argv / 无 remove argv）")
check(McpRegistrar.errorMessage(for: .targetUnsupported, target: .geminiCLI).contains("Gemini CLI"),
      "SAFE：copy-only 注册拒绝文案含 displayName（targetUnsupported）")
check(McpRegistrar.errorMessage(for: .targetUnsupported).contains("Claude Code"),
      "SAFE：缺省 target 的 targetUnsupported 文案回落 Claude Code")
check(McpRegistrar.errorMessage(for: .claudeNotFound, target: .codeBuddy).contains("CodeBuddy"),
      "SAFE：注册失败文案随 target 显示 CodeBuddy")
check(McpRegistrar.errorMessage(for: .claudeNotFound, target: .codex).contains("Codex"),
      "SAFE：注册失败文案随 target 显示 Codex")
check(McpRegistrar.errorMessage(for: .claudeNotFound, target: .claudeCode)
        == "注册失败：未找到 Claude Code（claude）。请先安装 Claude Code，或用「复制注册命令」手动注册。",
      "SAFE：Claude 注册失败文案与 v2.11.1 逐字一致")
check(McpRegistrar.removeErrorMessage(for: .claudeNotFound, target: .codex).contains("codex mcp remove coffer"),
      "SAFE：Codex 清理指引 = codex mcp remove coffer")
check(!McpRegistrar.removeErrorMessage(for: .claudeNotFound, target: .codex).contains("--scope"),
      "SAFE：Codex 清理指引不含 --scope")
check(McpRegistrar.removeErrorMessage(for: .claudeNotFound, target: .codeBuddy)
        .contains("codebuddy mcp remove coffer --scope user"),
      "SAFE：CodeBuddy 清理指引含 --scope user")
check(McpRegistrar.removeErrorMessage(for: .claudeNotFound).contains("claude mcp remove coffer --scope user"),
      "SAFE：缺省 target 清理指引 = claude 版（v2.11.1 兼容）")

let allCodesWithTarget: [ResultCode] = [.ok, .configInvalid, .cofferBinaryInvalid, .claudeNotFound,
                                        .claudeTimeout, .claudeAddFailed, .claudeRemoveFailed,
                                        .notRegistered, .checkFailed, .resultWriteFailed,
                                        .targetUnsupported]
check(allCodesWithTarget.count == 11, "SAFE：ResultCode 枚举 11 个（targetUnsupported 已纳入）")
check(allCodesWithTarget.allSatisfy { !McpRegistrar.errorMessage(for: $0, target: .codex).isEmpty },
      "SAFE：全部 code 在 Codex 语境有非空注册文案")
check(allCodesWithTarget.allSatisfy { !McpRegistrar.removeErrorMessage(for: $0, target: .codex).isEmpty },
      "SAFE：全部 code 在 Codex 语境有非空移除文案")

// ---- 13. SPAWN：脚本型 CLI 解释器 PATH 注入（#1）----

check(SpawnEnvironment.envInterpreterName(fromShebangLine: "#!/usr/bin/env node") == "node",
      "SPAWN：#!/usr/bin/env node → 解释器名 node")
check(SpawnEnvironment.envInterpreterName(fromShebangLine: "#!/usr/bin/env -S node --no-warnings") == "node",
      "SPAWN：env -S 变体跳过选项取 node")
check(SpawnEnvironment.envInterpreterName(fromShebangLine: "#!/usr/bin/env node\r") == "node",
      "SPAWN：CRLF 行尾不影响解析")
check(SpawnEnvironment.envInterpreterName(fromShebangLine: "#!/opt/homebrew/bin/node") == nil,
      "SPAWN：绝对路径解释器不注入（内核直接 exec）")
check(SpawnEnvironment.envInterpreterName(fromShebangLine: "#!/bin/sh") == nil,
      "SPAWN：sh 脚本不注入（无 env 间接层）")
check(SpawnEnvironment.envInterpreterName(fromShebangLine: "") == nil,
      "SPAWN：空行 / 无 shebang（Mach-O 原生）→ nil")

let injectedPATH = SpawnEnvironment.commandPATH(current: "/usr/bin:/bin",
                                                prepending: ["/Users/me/.local/bin"])
check(injectedPATH.hasPrefix("/Users/me/.local/bin:/usr/bin:/bin"),
      "SPAWN：解释器目录前置，现有 PATH 顺序保留")
check(injectedPATH.contains("/opt/homebrew/bin") && injectedPATH.hasSuffix("/sbin"),
      "SPAWN：系统默认目录兜底（Homebrew 前缀 + /sbin）")
let dedupPATH = SpawnEnvironment.commandPATH(current: "/usr/bin:/bin", prepending: ["/usr/bin"])
check(dedupPATH.split(separator: ":").filter { $0 == "/usr/bin" }.count == 1,
      "SPAWN：重复目录去重（前置优先，保序）")
check(SpawnEnvironment.commandPATH(current: nil, prepending: []).hasPrefix("/opt/homebrew/bin:/usr/local/bin:/usr/bin"),
      "SPAWN：无现有 PATH 时回落系统默认集")

// ---- 摘要 ----
print("----------------------------------------")
print("McpRegistrarTests: \(passed) passed, \(failed) failed")
if failed > 0 { exit(1) }
