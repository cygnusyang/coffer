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

// ---- 摘要 ----
print("----------------------------------------")
print("McpRegistrarTests: \(passed) passed, \(failed) failed")
if failed > 0 { exit(1) }
