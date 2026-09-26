// ItemTemplates.swift —— 条目类别展示信息 + 四类可编辑模板。
//
// 模板字段表与 Rust 侧 cf-domain::template 保持一致（docs/07 §1.3）：
// v0.1 仅 Login / Password / SecureNote / CreditCard 四类可编辑，
// 其余类别（含导入兜底的 Custom）只读展示。

import Foundation

// MARK: - 类别展示信息

extension FfiItemCategory {
    /// v0.1 支持完整 CRUD 的四类。
    static let editableCategories: [FfiItemCategory] = [.login, .password, .secureNote, .creditCard]

    var isEditable: Bool {
        Self.editableCategories.contains(self)
    }

    var displayName: String {
        switch self {
        case .login: return "登录"
        case .password: return "密码"
        case .apiCredential: return "API 凭据"
        case .server: return "服务器"
        case .database: return "数据库"
        case .creditCard: return "信用卡"
        case .membership: return "会员"
        case .passport: return "护照"
        case .softwareLicense: return "软件许可证"
        case .outdoorLicense: return "户外许可"
        case .secureNote: return "安全笔记"
        case .wirelessRouter: return "无线路由器"
        case .bankAccount: return "银行账户"
        case .driverLicense: return "驾照"
        case .identity: return "身份"
        case .rewardProgram: return "奖励计划"
        case .document: return "文档"
        case .emailAccount: return "邮箱账户"
        case .socialSecurityNumber: return "社保号"
        case .medicalRecord: return "医疗记录"
        case .sshKey: return "SSH 密钥"
        case .cryptoWallet: return "加密钱包"
        case .person: return "联系人"
        case .custom: return "自定义"
        }
    }

    var symbolName: String {
        switch self {
        case .login: return "person.crop.circle"
        case .password: return "key"
        case .apiCredential: return "terminal"
        case .server: return "server.rack"
        case .database: return "cylinder"
        case .creditCard: return "creditcard"
        case .membership: return "person.text.rectangle"
        case .passport: return "book.closed"
        case .softwareLicense: return "doc.badge.gearshape"
        case .outdoorLicense: return "leaf"
        case .secureNote: return "note.text"
        case .wirelessRouter: return "wifi.router"
        case .bankAccount: return "banknote"
        case .driverLicense: return "car"
        case .identity: return "person.badge.id.card"
        case .rewardProgram: return "gift"
        case .document: return "doc"
        case .emailAccount: return "envelope"
        case .socialSecurityNumber: return "number"
        case .medicalRecord: return "cross.case"
        case .sshKey: return "key.radiowaves.forward"
        case .cryptoWallet: return "bitcoinsign.circle"
        case .person: return "person"
        case .custom: return "square.grid.2x2"
        }
    }
}

// MARK: - 列表行 Identifiable

extension FfiItemSummary: Identifiable {
    public var id: String { uuid }
}

// MARK: - 侧栏过滤

/// 侧栏过滤条件。
enum SidebarFilter: Hashable {
    case all
    case favorites
    case category(FfiItemCategory)
    case trash
}

// MARK: - 四类字段模板（与 cf-domain::template 对齐）

struct TemplateFieldSpec {
    let name: String
    let fieldType: FfiFieldType
    let designation: FfiDesignation
    let required: Bool
}

enum ItemTemplates {
    /// 返回某类别的模板字段（新建表单的初始字段集）。
    static func fields(for category: FfiItemCategory) -> [TemplateFieldSpec] {
        switch category {
        case .login:
            return [
                TemplateFieldSpec(name: "用户名", fieldType: .text, designation: .username, required: true),
                TemplateFieldSpec(name: "密码", fieldType: .concealed, designation: .password, required: true),
                TemplateFieldSpec(name: "备注", fieldType: .multiline, designation: .notesPlain, required: false),
            ]
        case .password:
            return [
                TemplateFieldSpec(name: "密码", fieldType: .concealed, designation: .password, required: true),
                TemplateFieldSpec(name: "备注", fieldType: .multiline, designation: .notesPlain, required: false),
            ]
        case .secureNote:
            return [
                TemplateFieldSpec(name: "备注", fieldType: .multiline, designation: .notesPlain, required: false),
            ]
        case .creditCard:
            return [
                TemplateFieldSpec(name: "持卡人", fieldType: .text, designation: .other(value: "cardholder"), required: false),
                TemplateFieldSpec(name: "卡号", fieldType: .text, designation: .other(value: "cc-number"), required: true),
                TemplateFieldSpec(name: "有效期", fieldType: .monthYear, designation: .other(value: "expiry"), required: false),
                TemplateFieldSpec(name: "安全码", fieldType: .concealed, designation: .other(value: "cvv"), required: false),
                TemplateFieldSpec(name: "备注", fieldType: .multiline, designation: .notesPlain, required: false),
            ]
        default:
            return []
        }
    }
}
