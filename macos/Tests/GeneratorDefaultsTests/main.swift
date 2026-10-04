// GeneratorDefaultsTests/main.swift —— 生成器默认参数 + 诊断 FFI 的 Swift 侧自动化验收
// （docs/22 §2.4；docs/23 §1.4 TC-GEN / §1.5 TC-DIAG Swift 侧部分）。
//
// 定位（Round 1 由代理调接口自测，不经手 GUI）：
//   - TC-GEN-01/03/04/05：GeneratorDefaults（偏好读写 / 校验 / 回退 / 极端参数）
//     纯逻辑面，驱动真实 UserDefaults（保存原值并恢复，同 ClipboardTierTests 纪律）；
//   - TC-GEN-03 负向的 FFI 侧：真实临时库会话上调用 generate_password /
//     generate_passphrase，断言非法参数 → 1012（与 GeneratorDefaults.isValid
//     同语义，互证校验对齐内核）；
//   - TC-DIAG-02（Swift 侧）：CofferApp.formatVersion() = 内核常量经 FFI 暴露；
//   - TC-DIAG-06（Swift 侧）：新建空库 diagnosticSummary() 条目数 = 0
//     （顺带回归 T03 重生成的 Swift 绑定）。
//
// 边界（真机人工项不在此执行，移交发版回归）：
//   - TC-GEN-02 重启持久 → TC-M-GEN-2；TC-DIAG-04 锁定态 UI → 真机。
//
// 驱动：tools/run_generator_defaults_tests.sh（swiftc 编译 CoreBindings +
// GeneratorDefaults.swift + 本文件，链接 release libcf_ffi.a）。

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

// MARK: - 环境保存（测试后恢复）

let defaultsKey = GeneratorDefaults.defaultsKey
let originalValue = UserDefaults.standard.object(forKey: defaultsKey)

// MARK: - TC-GEN-01 正向：偏好读写（另存为默认 → 读回一致）

do {
    UserDefaults.standard.removeObject(forKey: defaultsKey)
    var custom = GeneratorDefaults.builtin
    custom.length = 32
    custom.symbols = true
    custom.excludeSimilarCharacters = false
    custom.wordCount = 8
    // 自定义分隔符须为 ASCII 可打印字符（对齐内核 is_printable）；
    // 非 ASCII（如「·」中圆点）是非法项，见 TC-GEN-03 负向。
    custom.separator = "!~"
    custom.capitalize = false
    custom.numberSuffix = false
    check("TC-GEN-01", "修改后校验通过", custom.isValid)
    check("TC-GEN-01", "另存为默认成功（save 返回 true）", custom.save())
    let loaded = GeneratorDefaults.load()
    check("TC-GEN-01", "重新读回与存档一致（六字段+passphrase 逐项）",
          loaded == custom, "loaded=\(loaded) custom=\(custom)")
}

// MARK: - TC-GEN-04 边界：首用无偏好 / 偏好损坏回退默认（不崩溃）

do {
    UserDefaults.standard.removeObject(forKey: defaultsKey)
    check("TC-GEN-04", "无偏好 → 内置默认", GeneratorDefaults.load() == GeneratorDefaults.builtin)
    check("TC-GEN-04", "内置默认本身合法", GeneratorDefaults.builtin.isValid)

    UserDefaults.standard.set(Data("不是 JSON".utf8), forKey: defaultsKey)
    check("TC-GEN-04", "损坏偏好（非法 JSON）→ 回退默认不崩溃",
          GeneratorDefaults.load() == GeneratorDefaults.builtin)

    UserDefaults.standard.set(Data("{\"length\":0}".utf8), forKey: defaultsKey)
    check("TC-GEN-04", "损坏偏好（可解码但校验不过）→ 回退默认",
          GeneratorDefaults.load() == GeneratorDefaults.builtin)
}

// MARK: - TC-GEN-03 负向：非法参数校验失败、不保存（对齐 1012 语义）

do {
    let valid = GeneratorDefaults.builtin

    var lenLow = valid; lenLow.length = 7
    check("TC-GEN-03", "长度越界（7<8）→ 非法", !lenLow.isValid)
    check("TC-GEN-03", "长度越界（7）save 返回 false 不落盘", !lenLow.save())

    var lenHigh = valid; lenHigh.length = 101
    check("TC-GEN-03", "长度越界（101>100）→ 非法", !lenHigh.isValid)

    var noCharset = valid
    noCharset.numbers = false; noCharset.lowercaseLetters = false
    noCharset.uppercaseLetters = false; noCharset.symbols = false
    check("TC-GEN-03", "字符集全关 → 非法", !noCharset.isValid)

    var wordsLow = valid; wordsLow.wordCount = 2
    check("TC-GEN-03", "词数越界（2<3）→ 非法", !wordsLow.isValid)

    var sepEmpty = valid; sepEmpty.separator = ""
    check("TC-GEN-03", "分隔符为空 → 非法", !sepEmpty.isValid)

    var sepLong = valid; sepLong.separator = "abcd"
    check("TC-GEN-03", "分隔符超长（4>3）→ 非法", !sepLong.isValid)

    var sepNonPrint = valid; sepNonPrint.separator = "中"
    check("TC-GEN-03", "分隔符含非可打印字符（中文）→ 非法", !sepNonPrint.isValid)

    var sepNonAscii = valid; sepNonAscii.separator = "·"
    check("TC-GEN-03", "分隔符含非 ASCII 可打印字符（·）→ 非法", !sepNonAscii.isValid)

    // 非法不落盘：先存合法值，再尝试存非法值，读回仍是合法值。
    check("TC-GEN-03", "前置：存入合法存档", valid.save())
    let before = GeneratorDefaults.load()
    _ = lenLow.save()
    check("TC-GEN-03", "非法参数不保存（读回仍为原合法存档）",
          GeneratorDefaults.load() == before)
}

// MARK: - TC-GEN-05 边界：极端参数（最小/最大长度）保存并回读一致

do {
    var minCase = GeneratorDefaults.builtin
    minCase.length = 8
    minCase.numbers = true
    minCase.lowercaseLetters = false
    minCase.uppercaseLetters = false
    minCase.symbols = false
    minCase.wordCount = 3
    minCase.separator = " "
    check("TC-GEN-05", "最小长度 8 / 词数 3 / 单字符集 → 合法", minCase.isValid)
    check("TC-GEN-05", "最小极端参数保存成功", minCase.save())
    check("TC-GEN-05", "最小极端参数回读一致", GeneratorDefaults.load() == minCase)

    var maxCase = GeneratorDefaults.builtin
    maxCase.length = 100
    maxCase.wordCount = 10
    maxCase.separator = "###"
    check("TC-GEN-05", "最大长度 100 / 词数 10 / 3 字符分隔符 → 合法", maxCase.isValid)
    check("TC-GEN-05", "最大极端参数保存成功", maxCase.save())
    check("TC-GEN-05", "最大极端参数回读一致", GeneratorDefaults.load() == maxCase)
}

// MARK: - TC-DIAG-02（Swift 侧）：format_version 经 FFI = 内核常量

do {
    let app = CofferApp()
    // cf_format::FORMAT_VERSION = 1（core/cf-format/src/header.rs:26）。
    // 断言为常量字符串形态（T03 已把该常量钉在 Rust 侧，此处验 Swift 绑定回读）。
    check("TC-DIAG-02", "formatVersion() 经 FFI = \"1\"", app.formatVersion() == "1",
          "实际 \(app.formatVersion())")
}

// MARK: - TC-GEN-03（FFI 驱动）+ TC-DIAG-06（Swift 侧）：真实临时库会话

do {
    let app = CofferApp()
    let tmp = FileManager.default.temporaryDirectory
        .appendingPathComponent("coffer-gen-\(Int(Date().timeIntervalSince1970))", isDirectory: true)
    try FileManager.default.createDirectory(at: tmp, withIntermediateDirectories: true)
    defer { try? FileManager.default.removeItem(at: tmp) }

    let password = "Gen-Pass-42@x"
    let brief = try app.createVault(baseDir: tmp.path, name: "生成器测试临时库", password: password)
    let session = try app.openVault(baseDir: tmp.path, vaultUuid: brief.vaultUuid)
    _ = try session.unlock(password: password)

    // TC-DIAG-06（Swift 侧）：新建空库 → 条目数 = 0（真实值直出）。
    let diag = try session.diagnosticSummary()
    check("TC-DIAG-06", "空库条目数 = 0", diag.itemCount == 0, "实际 \(diag.itemCount)")
    check("TC-DIAG-01", "附件数 = 0 / uuid 前缀 8 字符",
          diag.attachmentCount == 0 && diag.vaultUuidPrefix.count == 8,
          "att=\(diag.attachmentCount) prefix=\(diag.vaultUuidPrefix)")
    check("TC-DIAG-01", "库创建时间 > 0（真实时间戳）", diag.vaultCreatedAt > 0)

    // TC-GEN-03（FFI 驱动）：非法参数 → 1012（与 GeneratorDefaults.isValid 同语义互证）。
    func errCode(_ error: Error) -> Int {
        if case let FfiError.Coffer(code, _) = error { return Int(code) }
        return -1
    }
    do {
        _ = try session.generatePassword(opts: FfiPasswordGenOptions(
            length: 7, numbers: true, lowercaseLetters: true,
            uppercaseLetters: true, symbols: true, excludeSimilarCharacters: false))
        check("TC-GEN-03", "FFI：长度 7 → 1012", false, "竟然成功")
    } catch {
        check("TC-GEN-03", "FFI：长度 7 → 1012", errCode(error) == 1012, "\(error)")
    }
    do {
        _ = try session.generatePassword(opts: FfiPasswordGenOptions(
            length: 20, numbers: false, lowercaseLetters: false,
            uppercaseLetters: false, symbols: false, excludeSimilarCharacters: false))
        check("TC-GEN-03", "FFI：字符集全关 → 1012", false, "竟然成功")
    } catch {
        check("TC-GEN-03", "FFI：字符集全关 → 1012", errCode(error) == 1012, "\(error)")
    }
    do {
        _ = try session.generatePassphrase(opts: FfiPassphraseOptions(
            wordCount: 2, separator: "-", capitalize: true, numberSuffix: true))
        check("TC-GEN-03", "FFI：词数 2 → 1012", false, "竟然成功")
    } catch {
        check("TC-GEN-03", "FFI：词数 2 → 1012", errCode(error) == 1012, "\(error)")
    }
    // 对照：合法参数生成成功（结构性质断言：非空、长度为 20）。
    let okPw = try session.generatePassword(opts: FfiPasswordGenOptions(
        length: 20, numbers: true, lowercaseLetters: true,
        uppercaseLetters: true, symbols: true, excludeSimilarCharacters: false))
    check("TC-GEN-03", "FFI：合法参数生成成功（长度 20 对照）",
          okPw.count == 20 && !okPw.isEmpty, "实际长度 \(okPw.count)")
} catch {
    check("TC-GEN/TC-DIAG", "临时库会话异常", false, "\(error)")
}

// MARK: - 清理（测试数据全部清掉；UserDefaults 原值恢复）

if let originalValue {
    UserDefaults.standard.set(originalValue, forKey: defaultsKey)
} else {
    UserDefaults.standard.removeObject(forKey: defaultsKey)
}
print("CLEANUP  UserDefaults key restored")

// MARK: - 汇总

print("--------------------------------------------------")
print("结果：\(passCount) passed / \(failures.count) failed")
if !failures.isEmpty {
    failures.forEach { print("  FAILED: \($0)") }
    exit(1)
}
print("ALL GREEN")
