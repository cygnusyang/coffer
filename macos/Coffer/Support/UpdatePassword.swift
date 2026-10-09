// UpdatePassword.swift —— 条目「更新密码」快捷动作的纯逻辑辅助（FR-18.1，v2.5.0）。
//
// 与 View 解耦：密码字段定位、强度门禁决策、draft 组装均为纯函数 / 闭包注入，
// 便于 standalone swiftc 测试（不依赖 SwiftUI / AppModel 全量），测试见
// Tests/UpdatePasswordTests。
//
// 纪律（docs/34 §3 / §4 + FR-18.1 验收）：
//   - 只动密码字段：其余字段 / URL / 标签 / 分区 / 标题原样保留；Concealed
//     明文不落 details（掩码纪律），除被替换的密码字段外，全部 Concealed 字段
//     经闭包在保存时取回真实明文（同 ItemEditView.buildDraft）；
//   - 强度门禁 = zxcvbn score ≥ 3（「强」，与 PasswordStrengthSection / 1010
//     语义对齐；1010 只作用于主密码，条目密码须在本层自守）；
//   - 密码值不进日志（测试断言亦不打印明文）。

import Foundation

/// 更新密码流程的显式错误（fail-closed：不满足前置条件时不构造草稿）。
enum UpdatePasswordError: Error, LocalizedError {
    /// 条目没有 password designation 字段（不应走到保存，UI 已隐藏入口）。
    case missingPasswordField
    /// 新密码为空（防御性兜底，UI 层强度门禁已先行）。
    case emptyPassword

    var errorDescription: String? {
        switch self {
        case .missingPasswordField:
            return "该条目没有密码字段，无法更新密码。"
        case .emptyPassword:
            return "新密码不能为空。"
        }
    }
}

enum UpdatePassword {
    /// 密码字段定位：designation == .password 的字段（登录 / 密码等类别的
    /// 密码字段）。无密码 designation（如信用卡条目的安全码 Concealed）返回
    /// nil —— 该条目不提供「更新密码」入口，避免把 CVV 之类误当密码。
    static func passwordField(in details: FfiItemDetails) -> FfiFieldDetail? {
        details.fields.first { $0.designation == .password }
    }

    /// 强度门禁决策：zxcvbn score ≥ 3 =「强」以上（与 PasswordStrengthSection
    /// / 1010 语义对齐；「密码强度需达到强或以上」文案见 sheet）。
    static func isStrongEnough(score: Int) -> Bool {
        score >= 3
    }

    /// 组装「仅改密码」的完整草稿。
    ///
    /// 整体替换语义：以现有详情为基底重排 draft，唯一差异是密码字段的值被
    /// `newPassword` 替换；其它字段（Concealed 经 `concealedValue` 取回明文）、
    /// URL、标签、分区原样保留；`draft.totp` 置 nil（更新路径以
    /// `updateItem` 的 Keep 语义为准，见 ItemStore / core 更新路径注释）。
    ///
    /// - Parameters:
    ///   - details: 条目详情（`getItem` 掩码态，Concealed 值为 nil）。
    ///   - newPassword: 新密码明文（调用方保证非空且强度已过门禁）。
    ///   - concealedValue: 取 Concealed 字段明文（形参为字段 ID，返回真实
    ///     明文或 nil）；密码字段本身不经此闭包（值直接替换）。
    /// - Throws: `UpdatePasswordError`（缺密码字段 / 空新密码）。
    static func makeDraft(
        details: FfiItemDetails,
        newPassword: String,
        concealedValue: (String) throws -> String?
    ) throws -> FfiItemDraft {
        guard let passwordField = passwordField(in: details) else {
            throw UpdatePasswordError.missingPasswordField
        }
        guard !newPassword.isEmpty else {
            throw UpdatePasswordError.emptyPassword
        }

        // 分区映射：draft 用 sectionIndex 下标指向 sections 列表
        let sections = details.sections.enumerated().map { index, section in
            FfiSectionDraft(title: section.title, position: Int32(section.position))
        }
        let sectionIndexByUUID = Dictionary(
            uniqueKeysWithValues: details.sections.enumerated().map {
                ($0.element.uuid, Int64($0.offset))
            })

        var fields: [FfiFieldDraft] = []
        for field in details.fields {
            var value: String?
            if field.uuid == passwordField.uuid {
                value = newPassword
            } else if field.fieldType == .concealed {
                // 掩码纪律：Concealed 明文取回；取回为空 → 保持 nil（同
                // ItemEditView「(value?.isEmpty == true) ? nil : value」）。
                if let resolved = try concealedValue(field.uuid), !resolved.isEmpty {
                    value = resolved
                } else {
                    value = nil
                }
            } else {
                value = field.value
            }
            fields.append(FfiFieldDraft(
                name: field.name,
                value: value,
                fieldType: field.fieldType,
                designation: field.designation,
                sectionIndex: field.sectionUuid.flatMap { sectionIndexByUUID[$0] },
                position: Int32(field.position)
            ))
        }

        let urls: [FfiUrlDraft] = details.urls.map { url in
            FfiUrlDraft(label: url.label, url: url.url,
                        isPrimary: url.isPrimary, position: Int32(url.position))
        }

        return FfiItemDraft(
            title: details.title,
            category: details.category,
            urls: urls,
            tags: details.tags,
            sections: sections,
            fields: fields,
            totp: nil
        )
    }
}
