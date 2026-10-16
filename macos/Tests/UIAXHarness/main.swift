// UIAXHarness/main.swift —— L3 AX 黑盒 harness 编排层（docs/04-测试与验收/
// 19-UI测试自动化分层设计.md §5.6/§5.7，W4 交付）。
//
// 与 UIAXDriver 的分工：
//   - UIAXDriver（macos/Tests/UIAXTests/main.swift）= 纯 AX 能力面（黑盒只读/驱动），
//     运行期断言全走 driver 子命令（trusted/windows/tree/find/label/press/enabled/type）；
//   - 本编排层 = 建库前置（FFI 侧，脚本无法裸调 core）：`create <testDir>` 在容器内
//     固定测试目录创建测试库，stdout 输出 VAULTUUID\t<uuid>，供脚本写 defaults
//     （coffer.testBaseDir + lastVaultUUID + debugDisableTouchID）。
//
// 形态（docs/19 §3.3 FFI-linked，PuxRealSampleTests 骨架）：swiftc + cf_ffi.swift
// + libcf_ffi.a（release）编译，唯一目的是 setup 阶段的建库；运行期不用本进程 AX。
//
// R2 安全纪律（docs/19 §10）：
//   - 密码只走 env COFFER_TEST_PASSWORD，绝不进 argv/源码/日志——create 从 env 读取
//     建库密码（与 driver `type` 子命令同一 env 来源，保证解锁一致）；
//   - 测试目录 = 容器内固定路径（docs/19 §5.3 补注：/tmp 被沙盒拒 error 5001，
//     须放容器内）；本进程双重门禁：必须落在容器内 + 不得命中真实库前缀
//     Data/Documents（R2：绝不触碰真实用户库）；
//   - 临时测试目录由脚本侧 trap 清理（finally 语义），本进程不做库删除。
//
// 用法：
//   UIAXHarness create <testDir>       建测试库 → VAULTUUID\t<uuid>
//   UIAXHarness bookmark <dir>         为放置区目录建 security-scoped bookmark
//                                      → BOOKMARK\t<hex>（S0→S1 预置通路，spike ①）
//   env: COFFER_TEST_PASSWORD 必填（建库密码，与 driver type 一致）
//   退出码：0 成功；1 建库失败；2 用法/安全拦截/环境错误。
import Foundation

func fatal(_ msg: String) -> Never {
    print("ERROR  \(msg)")
    exit(2)
}

// MARK: - 入参与安全门禁

let args = Array(CommandLine.arguments.dropFirst())
guard args.count >= 2 else {
    fatal("用法：UIAXHarness <create|bookmark> <路径>")
}
let sub = args[0]
let target = args[1]

let home = FileManager.default.homeDirectoryForCurrentUser.standardizedFileURL.path
let containerPrefix = home + "/Library/Containers/top.cygnusyang.coffer"
let realVaultPrefix = containerPrefix + "/Data/Documents"
let normalized = URL(fileURLWithPath: target).standardizedFileURL.path

// 双门禁：必须在容器内（正），不得命中真实库（负）。
guard normalized.hasPrefix(containerPrefix + "/") else {
    fatal("安全拦截：路径 \(target) 不在容器 \(containerPrefix) 内——L3 测试目录须放容器内（沙盒禁 /tmp，docs/19 §5.3）")
}
guard !normalized.hasPrefix(realVaultPrefix) else {
    fatal("安全拦截：路径 \(target) 命中真实库前缀 \(realVaultPrefix)，拒绝执行")
}

// MARK: - create：建测试库

if sub == "create" {
    guard let testPassword = ProcessInfo.processInfo.environment["COFFER_TEST_PASSWORD"],
          !testPassword.isEmpty else {
        fatal("缺 env COFFER_TEST_PASSWORD（R2：测试密码只走 env，与 driver type 同源）")
    }
    let fm = FileManager.default
    if fm.fileExists(atPath: normalized) {
        try? fm.removeItem(atPath: normalized)
    }
    let app = CofferApp()
    let brief: FfiVaultBrief
    let session: VaultSession
    do {
        brief = try app.createVault(baseDir: normalized, name: "L3 AX 测试库", password: testPassword)
        session = try app.openVault(baseDir: normalized, vaultUuid: brief.vaultUuid)
        _ = try session.unlock(password: testPassword)
    } catch {
        fatal("建库/解锁失败：\(error)")
    }
    // 已解锁会话就地销毁（进程退出即释放，无需显式 lock——临时库本进程自建）。
    _ = session
    print("VAULTUUID\t\(brief.vaultUuid)")
    print("TESTDIR\t\(normalized)")
    print("SETUP OK")
    exit(0)
}

// MARK: - bookmark：为放置区目录建 security-scoped bookmark（S0→S1 预置，spike ①）

if sub == "bookmark" {
    let url = URL(fileURLWithPath: normalized)
    do {
        let data = try url.bookmarkData(options: [.withSecurityScope],
                                        includingResourceValuesForKeys: nil,
                                        relativeTo: nil)
        let hex = data.map { String(format: "%02x", $0) }.joined()
        print("BOOKMARK\t\(hex)")
        print("SETUP OK")
        exit(0)
    } catch {
        fatal("建 bookmark 失败（\(url.path)）：\(error)")
    }
}

fatal("未知子命令：\(sub)（仅 create/bookmark）")
