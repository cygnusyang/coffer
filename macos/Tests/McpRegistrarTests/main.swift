// McpRegistrarTests/main.swift —— MCP 一键注册 helper 纯逻辑单元测试
// （CofferMcpHelper.app：RegisterCommandBuilder 命令结构 + McpRegisterRequest 配置校验）。
//
// 编译运行：tools/run_mcp_registrar_tests.sh
//
// 被测单元（均为纯函数 / 纯数据结构，无 IO / 无进程 / 无 AppKit）：
//   - RegisterCommandBuilder.buildArgs —— 注册命令 argv 结构硬编码（lead 裁定
//     「helper 命令模式硬编码，禁止 shell 字符串拼接」）。与 App 侧
//     McpRegisterCommand.buildArgs 的**同构性**由一致性断言保证（单源，防漂移）。
//   - McpRegisterRequest.validate / isExpectedHelperPath —— 配置校验：coffer 二进制
//     路径必须位于 `<某>.app/Contents/Helpers/` 下（安全契约：防其他进程投喂
//     恶意 config 借 helper 注册任意命令）。
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

// ---- 1. RegisterCommandBuilder.buildArgs：命令结构硬编码（lead 裁定安全契约）----

let args = RegisterCommandBuilder.buildArgs(
    claudePath: "/Users/me/.local/bin/claude",
    vaultDir: "/Users/me/Library/Containers/top.cygnusyang.coffer/Data/Documents/Coffer/uuid",
    cofferBinaryPath: bundledCoffer
)
check(
    args == [
        "/Users/me/.local/bin/claude",
        "mcp", "add", "coffer",
        "--scope", "user",
        "-e", "COFFER_VAULT_DIR=/Users/me/Library/Containers/top.cygnusyang.coffer/Data/Documents/Coffer/uuid",
        "--",
        bundledCoffer,
        "mcp", "--provider", "coffer",
    ],
    "buildArgs：argv 结构与 --scope user 硬编码正确（coffer 版）"
)
check(args.contains("coffer"), "buildArgs：服务器名恒为 coffer")
check(args.contains("--scope"), "buildArgs：含 --scope")
check(!args.contains(where: { $0.contains("PASSWORD") || $0.contains("password") }), "buildArgs：不含任何密码（R2 纪律）")
check(args.filter { $0.hasPrefix("COFFER_VAULT_DIR=") }.count == 1, "buildArgs：COFFER_VAULT_DIR 恰一份 env 参数")
check(
    RegisterCommandBuilder.buildArgs(claudePath: "/usr/bin/claude", vaultDir: "/v a u", cofferBinaryPath: "/Applications/Coffer.app/Contents/Helpers/coffer.app/Contents/MacOS/coffer")
        .contains("COFFER_VAULT_DIR=/v a u"),
    "buildArgs：vaultDir 含空格仍作单一 argv 元素（无 shell 拼接，无需引号）"
)

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

// ---- 4. App↔helper 单源一致性（lead 裁定「Helper 和 UI 共享同一套生成逻辑，
//        禁止字符串重复」）----

// helper buildArgs 首位是 claudePath（整条 argv）；App buildArgs 是 claude 之后
// 的 argv。逐 token 同构（含 --scope user / 服务器名 / 顺序），防两处漂移。
let appCofferArgs = McpRegisterCommand.buildArgs(
    provider: "coffer", vault: nil,
    vaultDirPath: "/Users/me/Coffer/Vault", cofferBinaryPath: bundledCoffer
)
let helperCofferArgs = RegisterCommandBuilder.buildArgs(
    claudePath: "/Users/me/.local/bin/claude",
    vaultDir: "/Users/me/Coffer/Vault", cofferBinaryPath: bundledCoffer
)
check(
    appCofferArgs == Array(helperCofferArgs.dropFirst()),
    "一致性：App buildArgs（coffer 版）== helper buildArgs 去掉 claudePath（含 --scope user）"
)
check(
    appCofferArgs.count == helperCofferArgs.count - 1,
    "一致性：App/helper 数组长度差恰为 1（仅 claudePath）"
)
check(
    helperCofferArgs[1...] == ArraySlice(appCofferArgs),
    "一致性：helper 从下标 1 起与 App 完全一致"
)

// ---- 5. mode rawValue 稳定（config JSON 契约）----

check(McpRegisterRequest.Mode.register.rawValue == "register", "mode rawValue=register")
check(McpRegisterRequest.Mode.check.rawValue == "check", "mode rawValue=check")

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

// 6.3 request 构造（register 需 vaultDir/二进制；check 可空；resultPath=固定名）
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

// 6.4 config 编解码往返（sortedKeys 确定性序列化 ↔ helper 同 schema）
let encoded = try McpRegistrar.encodeRequest(regRequest)
let decodedBack = try JSONDecoder().decode(McpRegisterRequest.self, from: encoded)
check(decodedBack == regRequest, "encodeRequest/decode 往返一致（App↔helper config schema）")
let encodedJSON = String(data: encoded, encoding: .utf8) ?? ""
check(encodedJSON.contains("\"mode\":\"register\""), "config JSON 含 mode 字段（helper 解码所需）")

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

// 6.6 错误码文案（全部有非空映射；关键分支可区分）
let allCodes: [ResultCode] = [.ok, .configInvalid, .cofferBinaryInvalid, .claudeNotFound,
                              .claudeTimeout, .claudeAddFailed, .notRegistered, .checkFailed,
                              .resultWriteFailed]
check(allCodes.allSatisfy { !McpRegistrar.errorMessage(for: $0).isEmpty }, "errorMessage：全部 code 有非空文案")
check(McpRegistrar.errorMessage(for: .ok) != McpRegistrar.errorMessage(for: .claudeNotFound),
      "errorMessage：成功与 claude 缺失文案可区分")
check(McpRegistrar.errorMessage(for: .resultWriteFailed).contains("超时") ||
      McpRegistrar.errorMessage(for: .resultWriteFailed).contains("结果"),
      "errorMessage：resultWriteFailed 指向超时兜底（可操作）")

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
