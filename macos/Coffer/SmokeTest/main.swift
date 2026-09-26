// Swift 冒烟测试：验证 CoreBindings（UniFFI 生成的 Swift 绑定）能 import、
// 能调 Rust 侧 CofferApp（list_vaults / create_vault / open_vault / unlock），
// 且能链接 release staticlib（libcf_ffi.a）。
//
// 编译命令见本目录 README 或 tools/build_swift_bindings.sh 尾部注释。
// 全同步接口（docs/07 §2.3），冒烟直接同步调用即可。

import Foundation

// ---- 临时工作目录（测完清理） ----
let base = URL(fileURLWithPath: NSTemporaryDirectory())
    .appendingPathComponent("coffer-smoke-\(UUID().uuidString)")
try FileManager.default.createDirectory(at: base, withIntermediateDirectories: true)
defer { try? FileManager.default.removeItem(at: base) }

let app = CofferApp()

// 1. 空目录枚举 → 空列表
let empty = try app.listVaults(baseDir: base.path)
precondition(empty.isEmpty, "空目录应枚举出 0 个库，实际 \(empty.count)")
print("✓ list_vaults 空目录 → 0 个库")

// 2. 建库（强密码过 zxcvbn 门禁）+ 再枚举
let strongPassword = "correct-horse-battery-staple-42!"
let brief = try app.createVault(baseDir: base.path, name: "冒烟库", password: strongPassword)
let listed = try app.listVaults(baseDir: base.path)
precondition(listed.count == 1, "建库后应枚举出 1 个库，实际 \(listed.count)")
precondition(listed[0].displayName == "冒烟库", "显示名不符：\(listed[0].displayName)")
print("✓ create_vault + list_vaults → \(listed[0].displayName) uuid=\(listed[0].vaultUuid)")

// 3. 打开会话并解锁
let session = try app.openVault(baseDir: base.path, vaultUuid: brief.vaultUuid)
let info = try session.unlock(password: strongPassword)
precondition(info.itemCount == 0, "新库条目数应为 0，实际 \(info.itemCount)")
print("✓ open_vault + unlock → 解锁成功，条目 \(info.itemCount) 条")

// 4. 锁定后条目访问应被门禁拦截（错误码 1001，docs/03 §12）
session.lock()
do {
    _ = try session.listItems(filter: nil)
    fatalError("锁定态 list_items 不应成功")
} catch let error as FfiError {
    guard case let .Coffer(code, _) = error else {
        fatalError("锁定态访问应返回业务错误 .Coffer，实际 \(error)")
    }
    precondition(code == 1001, "锁定态错误码应为 1001，实际 \(code)")
    print("✓ 锁定态访问 → 错误码 \(code)（1001 会话锁定）")
}

print("SMOKE OK —— Swift 绑定链路全通")
