// UpdatePasswordTests/main.swift —— 条目「更新密码」快捷动作（FR-18.1，v2.5.0）
// 的 Swift 侧自动化验收。
//
// 覆盖（docs/34 §4 + docs/01 FR-18.1 验收要点）：
//   - 纯逻辑：密码字段定位（designation == .password；缺失 → nil）；
//   - 纯逻辑：makeDraft 只改密码字段，其余字段 / URL / 标签 / 分区 / 标题
//     原样保留（Concealed 经闭包在保存时取回明文，同 ItemEditView 掩码纪律）；
//   - 纯逻辑：缺密码字段 / 空新密码 → 显式报错（fail-closed，不构造草稿）；
//   - 门禁：isStrongEnough（score ≥ 3）+ 真实 zxcvbn（工厂版）强/弱对照；
//   - 集成：真实临时库会话 —— 仅改密码字段后其它字段 / URL / 标签 / 标题 /
//     收藏态不变、密码已变、updatedAt 递增、历史 append +1（FR-2.9）。
//
// 密码纪律：新旧密码明文只用于断言比对，绝不 print（docs/34 §3）。
//
// 驱动：tools/run_update_password_tests.sh（swiftc 编译 CoreBindings +
// Support/UpdatePassword.swift + 本文件，链接 release libcf_ffi.a）。

import Foundation

// MARK: - 断言与汇总

var failures: [String] = []
var passCount = 0

func check(_ tc: String, _ name: String, _ cond: Bool, _ detail: String = "") {
    if cond {
        passCount += 1
        print("PASS  \(tc)  \(name)")
    } else {
        failures.append("\(tc) \(name) \(detail)")
        print("FAIL  \(tc)  \(name)  \(detail)")
    }
}

// MARK: - 测试夹具

/// 构造一条带 2 个 Concealed（密码 + 自定义安全问题）+ 文本 + 备注 + 分区
/// + URL + 标签的 login 详情。Concealed 值按掩码纪律为 nil。
func makeFixtureDetails() -> FfiItemDetails {
    let sectionA = FfiSectionDetail(uuid: "sec-a", title: "附加信息", position: 0)
    let fields = [
        FfiFieldDetail(uuid: "f-pw", sectionUuid: nil, fieldType: .concealed,
                       designation: .password, name: "密码", value: nil, position: 0),
        FfiFieldDetail(uuid: "f-user", sectionUuid: nil, fieldType: .text,
                       designation: .username, name: "用户名", value: "alice@example.com", position: 1),
        FfiFieldDetail(uuid: "f-notes", sectionUuid: nil, fieldType: .multiline,
                       designation: .notesPlain, name: "备注", value: "原始备注", position: 2),
        FfiFieldDetail(uuid: "f-sec", sectionUuid: "sec-a", fieldType: .concealed,
                       designation: nil, name: "安全问题", value: nil, position: 3),
    ]
    let urls = [
        FfiUrlDetail(uuid: "u1", label: nil, url: "https://example.com", isPrimary: true, position: 0),
        FfiUrlDetail(uuid: "u2", label: "备用", url: "https://example.org", isPrimary: false, position: 1),
    ]
    return FfiItemDetails(
        uuid: "item-1", category: .login, state: .active, isFavorite: true, favIndex: 2,
        createdAt: 1000, updatedAt: 2000, title: "GitHub", urls: urls,
        tags: ["工作", "开发"], sections: [sectionA], fields: fields, totp: nil)
}

// MARK: - TC-UPD-01/02 密码字段定位

do {
    let details = makeFixtureDetails()
    let pw = UpdatePassword.passwordField(in: details)
    check("TC-UPD-01", "designation == .password 字段被识别", pw?.uuid == "f-pw",
          "实际 \(pw?.uuid ?? "nil")")

    var noPw = details
    noPw.fields = noPw.fields.filter { $0.designation != .password }
    check("TC-UPD-02", "无 password designation → nil",
          UpdatePassword.passwordField(in: noPw) == nil)

    // 仅有 Concealed 但非 password designation（如信用卡 CVV）不应被误判为密码
    var cvvOnly = details
    cvvOnly.fields = [
        FfiFieldDetail(uuid: "f-cvv", sectionUuid: nil, fieldType: .concealed,
                       designation: nil, name: "安全码", value: nil, position: 0),
    ]
    check("TC-UPD-02", "Concealed 但非 password designation → 不识别为密码",
          UpdatePassword.passwordField(in: cvvOnly) == nil)
}

// MARK: - TC-UPD-03 makeDraft 只改密码字段、其余原样保留

do {
    let details = makeFixtureDetails()
    let draft = try UpdatePassword.makeDraft(
        details: details,
        newPassword: "N3w-P@ss-42",
        concealedValue: { fieldId in fieldId == "f-sec" ? "我的答案" : nil })

    let pwDraft = draft.fields.first { $0.name == "密码" }
    check("TC-UPD-03", "密码字段值被替换为新密码", pwDraft?.value == "N3w-P@ss-42",
          "实际 \(pwDraft?.value ?? "nil")")
    check("TC-UPD-03", "密码字段类型/designation 保留（concealed + .password）",
          pwDraft?.fieldType == .concealed && pwDraft?.designation == .password)

    check("TC-UPD-03", "用户名（文本）值保留",
          draft.fields.first { $0.name == "用户名" }?.value == "alice@example.com")
    check("TC-UPD-03", "备注（multiline）值保留",
          draft.fields.first { $0.name == "备注" }?.value == "原始备注")
    check("TC-UPD-03", "自定义 Concealed 经闭包取回明文",
          draft.fields.first { $0.name == "安全问题" }?.value == "我的答案")

    check("TC-UPD-03", "字段总数不变（4）", draft.fields.count == 4,
          "实际 \(draft.fields.count)")
    check("TC-UPD-03", "分区内字段 sectionIndex 映射正确",
          draft.fields.first { $0.name == "安全问题" }?.sectionIndex == 0)

    check("TC-UPD-03", "标题 / 类别保留",
          draft.title == "GitHub" && draft.category == .login)
    check("TC-UPD-03", "URL 两条保留（主 + 标签非主）",
          draft.urls.count == 2
          && draft.urls[0].url == "https://example.com" && draft.urls[0].isPrimary
          && draft.urls[1].url == "https://example.org" && draft.urls[1].label == "备用")
    check("TC-UPD-03", "标签保留", draft.tags == ["工作", "开发"])
    check("TC-UPD-03", "分区保留（标题/位置）",
          draft.sections.count == 1 && draft.sections[0].title == "附加信息"
          && draft.sections[0].position == 0)
    check("TC-UPD-03", "totp 为 nil（更新路径以三态参数为准）", draft.totp == nil)
}

// MARK: - TC-UPD-04/05 fail-closed：缺密码字段 / 空新密码 → 显式报错

do {
    var noPw = makeFixtureDetails()
    noPw.fields = noPw.fields.filter { $0.designation != .password }
    do {
        _ = try UpdatePassword.makeDraft(details: noPw, newPassword: "X",
                                         concealedValue: { _ in nil })
        check("TC-UPD-04", "缺密码字段 → 报错（fail-closed）", false, "竟然没报错")
    } catch {
        check("TC-UPD-04", "缺密码字段 → 报错（fail-closed）", true)
    }

    let details = makeFixtureDetails()
    do {
        _ = try UpdatePassword.makeDraft(details: details, newPassword: "",
                                         concealedValue: { _ in nil })
        check("TC-UPD-05", "空新密码 → 报错（fail-closed）", false, "竟然没报错")
    } catch {
        check("TC-UPD-05", "空新密码 → 报错（fail-closed）", true)
    }
}

// MARK: - TC-UPD-06 强度门禁决策（score ≥ 3 = 「强」）

do {
    check("TC-UPD-06", "score 3 → 通过", UpdatePassword.isStrongEnough(score: 3))
    check("TC-UPD-06", "score 4 → 通过", UpdatePassword.isStrongEnough(score: 4))
    check("TC-UPD-06", "score 2 → 拒绝", !UpdatePassword.isStrongEnough(score: 2))
    check("TC-UPD-06", "score 0 → 拒绝", !UpdatePassword.isStrongEnough(score: 0))
}

// MARK: - TC-UPD-07 真实 zxcvbn（工厂版）强 / 弱对照

do {
    let app = CofferApp()
    let strong = try app.strengthEstimate(candidate: "7u8;Strong-Passw0rd!-2026")
    check("TC-UPD-07", "强密码 → zxcvbn score ≥ 3", strong.score >= 3,
          "score=\(strong.score)")
    let weak = try app.strengthEstimate(candidate: "123456")
    check("TC-UPD-07", "弱密码 → zxcvbn score < 3", weak.score < 3,
          "score=\(weak.score)")
}

// MARK: - TC-UPD-08 集成：真实临时库会话 —— 仅改密码、其它不动、历史 append

do {
    let app = CofferApp()
    let tmp = FileManager.default.temporaryDirectory
        .appendingPathComponent("coffer-upd-\(Int(Date().timeIntervalSince1970))", isDirectory: true)
    try FileManager.default.createDirectory(at: tmp, withIntermediateDirectories: true)
    defer { try? FileManager.default.removeItem(at: tmp) }

    let masterPassword = "Master-Vault-2026!x"
    let brief = try app.createVault(baseDir: tmp.path, name: "更新密码测试库", password: masterPassword)
    let session = try app.openVault(baseDir: tmp.path, vaultUuid: brief.vaultUuid)
    _ = try session.unlock(password: masterPassword)

    let fields = [
        FfiFieldDraft(name: "用户名", value: "alice@example.com", fieldType: .text,
                      designation: .username, sectionIndex: nil, position: 0),
        FfiFieldDraft(name: "密码", value: "Old-Pass-42!", fieldType: .concealed,
                      designation: .password, sectionIndex: nil, position: 1),
        FfiFieldDraft(name: "安全问题", value: "我的答案", fieldType: .concealed,
                      designation: nil, sectionIndex: nil, position: 2),
        FfiFieldDraft(name: "备注", value: "原始备注", fieldType: .multiline,
                      designation: .notesPlain, sectionIndex: nil, position: 3),
    ]
    let itemId = try session.createItem(draft: FfiItemDraft(
        title: "GitHub", category: .login,
        urls: [FfiUrlDraft(label: nil, url: "https://github.com", isPrimary: true, position: 0)],
        tags: ["工作"], sections: [], fields: fields, totp: nil))

    let before = try session.getItem(itemId: itemId)!
    let historyBefore = try session.listHistory(itemId: itemId).count

    // 用 makeDraft（Concealed 经 getFieldValue 取回明文）构造仅改密码的草稿
    let newPassword = "N3w-P@ss-2026!"
    let draft = try UpdatePassword.makeDraft(
        details: before,
        newPassword: newPassword,
        concealedValue: { fieldId in
            try session.getFieldValue(itemId: itemId, fieldId: fieldId)
        })
    try session.updateItem(itemId: itemId, draft: draft)

    let after = try session.getItem(itemId: itemId)!

    func value(_ field: FfiFieldDetail) -> String? {
        try? session.getFieldValue(itemId: itemId, fieldId: field.uuid)
    }

    let pwAfter = after.fields.first { $0.designation == .password }!
    check("TC-UPD-08", "密码已更新为明文新值", value(pwAfter) == newPassword)
    check("TC-UPD-08", "用户名不变", value(after.fields.first { $0.designation == .username }!) == "alice@example.com")
    check("TC-UPD-08", "自定义 Concealed（安全问题）不变",
          value(after.fields.first { $0.name == "安全问题" }!) == "我的答案")
    check("TC-UPD-08", "备注（multiline）不变",
          after.fields.first { $0.name == "备注" }?.value == "原始备注")
    check("TC-UPD-08", "字段总数不变（4）", after.fields.count == 4,
          "实际 \(after.fields.count)")
    check("TC-UPD-08", "标题不变", after.title == "GitHub")
    check("TC-UPD-08", "URL 不变", after.urls.count == 1 && after.urls[0].url == "https://github.com")
    check("TC-UPD-08", "标签不变", after.tags == ["工作"])
    check("TC-UPD-08", "收藏态不变", after.isFavorite == before.isFavorite)
    check("TC-UPD-08", "updatedAt 不倒退", after.updatedAt >= before.updatedAt)
    check("TC-UPD-08", "历史版本 append +1（FR-2.9）",
          try session.listHistory(itemId: itemId).count == historyBefore + 1,
          "before=\(historyBefore) after=\(try session.listHistory(itemId: itemId).count)")
} catch {
    check("TC-UPD-08", "集成：临时库会话异常", false, "\(error)")
}

// MARK: - 汇总

print("--------------------------------------------------")
print("结果：\(passCount) passed / \(failures.count) failed")
if !failures.isEmpty {
    failures.forEach { print("  FAILED: \($0)") }
    exit(1)
}
print("ALL GREEN")
