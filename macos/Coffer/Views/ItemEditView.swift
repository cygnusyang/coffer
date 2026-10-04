// ItemEditView.swift —— 新建 / 编辑条目表单（按类别模板渲染）。
//
// 掩码纪律（docs/07 §4.2）：
//   - 编辑时 Concealed 字段不回填明文，显示占位「未修改」；
//     保存时若用户未改动，才经 getFieldValue 取回真实值随 draft 提交。
//   - TOTP 密钥不可读回（FFI 无此接口，安全设计）：编辑含 TOTP 条目时
//     默认「保留既有 TOTP」（totp_config 只下发元数据供展示，保存走
//     updateItemWithTotp(.keep)，存储里的加密行完全不动）；粘贴新
//     otpauth URI 才替换（.replace）；提供显式「移除」按钮（.remove）。
//     三态显式，不再有 v0.1 的静默丢失 / 确认弹窗。
//   - 模板外字段（导入带来的自定义字段）原样保留，不做静默丢弃。

import SwiftUI

struct ItemEditView: View {
    enum Mode {
        case create(FfiItemCategory)
        case edit(FfiItemDetails)
    }

    enum DismissAction {
        case created(String)
        case updated
    }

    @EnvironmentObject
    private var model: AppModel

    @Environment(\.dismiss)
    private var dismiss

    let mode: Mode

    // MARK: - 表单状态

    @State private var title = ""
    @State private var rows: [EditFieldRow] = []
    @State private var urlText = ""
    @State private var tagsText = ""
    @State private var otpauthText = ""
    /// TOTP 扫码 sheet 展示旗标（FR-5.3，T09）。
    @State private var showScan = false
    /// otpauth URI 输入框焦点（扫码拒权降级「手动输入」后聚焦）。
    @FocusState private var otpauthFocused: Bool
    @State private var isSaving = false
    @State private var saveError: String?
    /// 既有 TOTP 元数据（编辑模式加载；绝不含 secret）。
    @State private var existingTotpMeta: FfiTotpMeta?
    /// 用户显式点了「移除」：保存时提交 .remove（粘贴新 URI 会覆盖本标记）。
    @State private var totpRemoved = false

    private var category: FfiItemCategory {
        switch mode {
        case .create(let category): return category
        case .edit(let details): return details.category
        }
    }

    private var existingDetails: FfiItemDetails? {
        if case .edit(let details) = mode { return details }
        return nil
    }

    private var hasExistingTotp: Bool {
        existingTotpMeta != nil && !totpRemoved
    }

    var body: some View {
        VStack(spacing: 0) {
            header
            Form {
                TextField("标题", text: $title)

                ForEach($rows) { $row in
                    EditFieldRowView(row: $row, itemId: existingDetails?.uuid)
                }

                if category == .login {
                    TextField("网址（可选）", text: $urlText, prompt: Text("https://example.com"))
                }

                TextField("标签（逗号分隔）", text: $tagsText, prompt: Text("工作, 邮箱"))

                if category == .login {
                    totpSection
                }
            }
            .formStyle(.grouped)
            footer
        }
        .frame(width: 560, height: 560)
        .onAppear(perform: populate)
        .sheet(isPresented: $showScan) {
            TotpScanView(
                onScanned: { uri in
                    // 回填原始 URI 字符串（TC-QR-02）；保存走既有 save()（ItemWrite 门禁复用）
                    otpauthText = uri
                    showScan = false
                    otpauthFocused = true
                },
                onDismiss: { showScan = false },
                onManualInput: {
                    // TCC 拒权兜底（TC-QR-08）：关闭扫描、聚焦 URI 输入框手动输入
                    showScan = false
                    otpauthFocused = true
                }
            )
            .environmentObject(model)
        }
        .ffiErrorAlert($model.lastErrorMessage)
        .alert("无法保存", isPresented: Binding(
            get: { saveError != nil },
            set: { if !$0 { saveError = nil } }
        )) {
            Button("好", role: .cancel) {}
        } message: {
            Text(saveError ?? "")
        }
    }

    // MARK: - TOTP 三态区（保留 / 替换 / 移除）

    /// 编辑含 TOTP 条目时展示既有元数据（SHA-1 · 6 位 · 30s），默认保留；
    /// 粘贴新 URI 才替换；提供显式「移除」（可撤销）。无既有 TOTP 时
    /// 仅显示 URI 输入框（新建即写入）。
    @ViewBuilder
    private var totpSection: some View {
        if let meta = existingTotpMeta, !totpRemoved {
            VStack(alignment: .leading, spacing: 4) {
                HStack(spacing: 6) {
                    Image(systemName: "clock.badge.checkmark")
                        .foregroundStyle(.secondary)
                    Text(verbatim: "已有 TOTP（\(Self.algoLabel(meta.algo)) · \(meta.digits) 位 · \(meta.period)s）")
                        .font(.callout)
                        .foregroundStyle(.secondary)
                    Spacer()
                    Button("移除", role: .destructive) { totpRemoved = true }
                        .controlSize(.small)
                }
                Text("保存时保留现有动态验证码；粘贴新 URI 可替换。")
                    .font(.caption2)
                    .foregroundStyle(.tertiary)
            }
        } else if totpRemoved {
            HStack(spacing: 6) {
                Image(systemName: "clock.badge.xmark")
                    .foregroundStyle(.secondary)
                Text("保存后移除现有 TOTP")
                    .font(.callout)
                    .foregroundStyle(.secondary)
                Spacer()
                Button("撤销") { totpRemoved = false }
                    .controlSize(.small)
            }
        }
        HStack(spacing: 8) {
            SecureField(
                hasExistingTotp ? "otpauth URI（粘贴以替换现有 TOTP）" : "otpauth URI（可选）",
                text: $otpauthText,
                prompt: Text("otpauth://totp/…?secret=…")
            )
            .focused($otpauthFocused)
            Button("扫码") { showScan = true }
                .controlSize(.small)
                .help("用相机扫描 TOTP otpauth:// 二维码（FR-5.3）")
        }
    }

    /// DDL 算法名 → 展示名（运行时仅 sha1，兜底原文）。
    private static func algoLabel(_ algo: String) -> String {
        switch algo {
        case "sha1": return "SHA-1"
        case "sha256": return "SHA-256"
        case "sha512": return "SHA-512"
        default: return algo.uppercased()
        }
    }

    // MARK: - 头尾

    private var header: some View {
        HStack {
            Text(existingDetails == nil ? "新建\(category.displayName)" : "编辑条目")
                .font(.headline)
            Spacer()
        }
        .padding()
    }

    private var footer: some View {
        HStack {
            Spacer()
            Button("取消") { dismiss() }
                .keyboardShortcut(.cancelAction)
            Button {
                save()
            } label: {
                if isSaving {
                    ProgressView().controlSize(.small).frame(width: 44)
                } else {
                    Text("保存").frame(minWidth: 32)
                }
            }
            .keyboardShortcut(.defaultAction)
            .disabled(!canSave || isSaving)
        }
        .padding()
    }

    private var canSave: Bool {
        !title.trimmingCharacters(in: .whitespaces).isEmpty && !isSaving
    }

    // MARK: - 填充表单

    private func populate() {
        if let details = existingDetails {
            title = details.title
            urlText = details.urls.first(where: { $0.isPrimary })?.url ?? ""
            tagsText = details.tags.joined(separator: ", ")
            rows = Self.buildRows(for: details)
            // 既有 TOTP 元数据（绝不含 secret）：展示「已有 TOTP」并默认保留
            existingTotpMeta = try? model.totpConfig(itemId: details.uuid)
        } else {
            rows = ItemTemplates.fields(for: category).map { spec in
                EditFieldRow(
                    name: spec.name,
                    value: "",
                    fieldType: spec.fieldType,
                    designation: spec.designation,
                    isTemplateField: true,
                    isRequired: spec.required,
                    unchanged: false,
                    fieldId: nil
                )
            }
        }
    }

    /// 编辑模式：模板字段按 designation 匹配详情字段；未匹配上的详情字段
    /// 作为保留行追加（不静默丢弃）；模板中详情缺失的字段补空行。
    private static func buildRows(for details: FfiItemDetails) -> [EditFieldRow] {
        var rows: [EditFieldRow] = []
        var consumedFieldIDs = Set<String>()

        let specs = ItemTemplates.fields(for: details.category)
        for spec in specs {
            let matched = details.fields.first { field in
                Self.designationMatches(field.designation, spec.designation)
            }
            if let matched {
                consumedFieldIDs.insert(matched.uuid)
                rows.append(EditFieldRow(
                    name: matched.name,
                    value: matched.value ?? "", // Concealed 详情恒为 nil（掩码纪律）
                    fieldType: matched.fieldType,
                    designation: matched.designation,
                    isTemplateField: true,
                    isRequired: spec.required,
                    unchanged: matched.fieldType == .concealed,
                    fieldId: matched.uuid
                ))
            } else {
                rows.append(EditFieldRow(
                    name: spec.name,
                    value: "",
                    fieldType: spec.fieldType,
                    designation: spec.designation,
                    isTemplateField: true,
                    isRequired: spec.required,
                    unchanged: false,
                    fieldId: nil
                ))
            }
        }

        // 模板外字段：保留原样
        for field in details.fields where !consumedFieldIDs.contains(field.uuid) {
            rows.append(EditFieldRow(
                name: field.name,
                value: field.value ?? "",
                fieldType: field.fieldType,
                designation: field.designation,
                isTemplateField: false,
                isRequired: false,
                unchanged: field.fieldType == .concealed,
                fieldId: field.uuid
            ))
        }
        return rows
    }

    private static func designationMatches(
        _ lhs: FfiDesignation?,
        _ rhs: FfiDesignation
    ) -> Bool {
        guard let lhs else { return false }
        switch (lhs, rhs) {
        case (.username, .username),
             (.password, .password),
             (.totp, .totp),
             (.notesPlain, .notesPlain),
             (.email, .email):
            return true
        case let (.other(a), .other(b)):
            return a == b
        default:
            return false
        }
    }

    // MARK: - 保存

    private func save() {
        guard canSave else { return }

        do {
            let draft = try buildDraft()
            isSaving = true
            if let details = existingDetails {
                // 编辑：TOTP 三态显式（粘贴新 URI → 替换；点了移除 → 删除；
                // 其余 → 保留既有加密行，与 draft.totp 无关）
                let trimmed = otpauthText.trimmingCharacters(in: .whitespacesAndNewlines)
                let totpUpdate: FfiTotpUpdate
                if !trimmed.isEmpty {
                    totpUpdate = .replace(draft: try model.parseOtpauth(uri: trimmed))
                } else if totpRemoved {
                    totpUpdate = .remove
                } else {
                    totpUpdate = .keep
                }
                try model.updateItem(itemId: details.uuid, draft: draft, totpUpdate: totpUpdate)
            } else {
                _ = try model.createItem(draft: draft)
            }
            // 表单内的临时明文（新输入的密码等）随 sheet 关闭丢弃
            rows = []
            otpauthText = ""
            isSaving = false
            dismiss()
        } catch {
            isSaving = false
            saveError = ErrorPresenter.text(error)
        }
    }

    /// 组装 FfiItemDraft：模板 + 保留字段、URL、标签、TOTP。
    ///
    /// TOTP：编辑模式下 draft.totp 恒为 nil（更新路径以三态参数为准，
    /// 且 FFI 拿不到原 secret 也无需构造）；新建模式解析粘贴的 URI 写入。
    private func buildDraft() throws -> FfiItemDraft {
        var fields: [FfiFieldDraft] = []

        for (index, row) in rows.enumerated() {
            var value: String? = row.value
            // 掩码纪律：未修改的 Concealed 字段，保存时才取回真实值
            if row.fieldType == .concealed && row.unchanged {
                if let fieldId = row.fieldId, let itemId = existingDetails?.uuid {
                    value = try model.fieldValue(itemId: itemId, fieldId: fieldId) ?? ""
                } else {
                    value = ""
                }
            }
            if (value ?? "").isEmpty && row.isRequired && row.isTemplateField {
                // 必填字段即使值为空也要存在（cf-domain 校验按 designation 判存在）
                value = nil
            }
            fields.append(FfiFieldDraft(
                name: row.name,
                value: (value?.isEmpty == true) ? nil : value,
                fieldType: row.fieldType,
                designation: row.designation,
                sectionIndex: nil,
                position: Int32(index)
            ))
        }

        // URL：编辑时保留非主 URL，主 URL 用表单值替换
        var urls: [FfiUrlDraft] = []
        let trimmedUrl = urlText.trimmingCharacters(in: .whitespaces)
        if let details = existingDetails {
            let nonPrimary = details.urls.filter { !$0.isPrimary }
            if !trimmedUrl.isEmpty {
                urls.append(FfiUrlDraft(label: nil, url: trimmedUrl, isPrimary: true, position: 0))
                for (offset, url) in nonPrimary.enumerated() {
                    urls.append(FfiUrlDraft(label: url.label, url: url.url, isPrimary: false, position: Int32(offset + 1)))
                }
            } else {
                for (offset, url) in nonPrimary.enumerated() {
                    urls.append(FfiUrlDraft(label: url.label, url: url.url, isPrimary: false, position: Int32(offset)))
                }
            }
        } else if !trimmedUrl.isEmpty {
            urls.append(FfiUrlDraft(label: nil, url: trimmedUrl, isPrimary: true, position: 0))
        }

        // 标签：中英文逗号分隔
        let tags = tagsText
            .split(whereSeparator: { $0 == "," || $0 == "，" || $0 == ";" || $0 == "；" })
            .map { $0.trimmingCharacters(in: .whitespaces) }
            .filter { !$0.isEmpty }

        // TOTP：编辑模式恒 nil（三态参数另行提交）；新建解析粘贴的 URI
        var totp: FfiTotpDraft?
        if existingDetails == nil {
            let trimmedOtpauth = otpauthText.trimmingCharacters(in: .whitespacesAndNewlines)
            if !trimmedOtpauth.isEmpty {
                totp = try model.parseOtpauth(uri: trimmedOtpauth)
            }
        }

        return FfiItemDraft(
            title: title.trimmingCharacters(in: .whitespaces),
            category: category,
            urls: urls,
            tags: tags,
            sections: [],
            fields: fields,
            totp: totp
        )
    }
}

// MARK: - 表单行数据

struct EditFieldRow: Identifiable {
    let id = UUID()
    var name: String
    /// 用户输入或详情掩码值（Concealed 未修改时为空串）。
    var value: String
    var fieldType: FfiFieldType
    var designation: FfiDesignation?
    /// 模板字段（必填字段始终写入 draft）。
    var isTemplateField: Bool
    var isRequired: Bool
    /// Concealed 且用户未改动：保存时经 getFieldValue 取回真实值。
    var unchanged: Bool
    /// 详情字段 ID（编辑模式；新建为 nil）。
    var fieldId: String?
}

// MARK: - 单行编辑控件

struct EditFieldRowView: View {
    @EnvironmentObject
    private var model: AppModel

    @Binding
    var row: EditFieldRow

    let itemId: String?

    /// 密码生成器 popover（FR-3.2 / FR-3.3，MC-2：仅密码 designation 的
    /// 掩码行提供；生成结果写入 row.value，经 SecureField 的 onChange
    /// 自然进入「已改动」语义）。
    @State private var showGenerator = false

    var body: some View {
        switch row.fieldType {
        case .multiline:
            VStack(alignment: .leading, spacing: 4) {
                Text(row.name).font(.callout).foregroundStyle(.secondary)
                TextEditor(text: $row.value)
                    .frame(minHeight: 80)
                    .font(.body)
                    .scrollContentBackground(.hidden)
                    .padding(4)
                    .background(RoundedRectangle(cornerRadius: 6).fill(.quaternary.opacity(0.4)))
            }
        case .concealed:
            HStack {
                SecureField(row.name, text: $row.value, prompt: Text(row.unchanged ? "未修改" : ""))
                    .onChange(of: row.value) { _, newValue in
                        // 与 buildDraft 的 unchanged 契约：unchanged==true 的行在保存时
                        // 经 getFieldValue 取回旧值，row.value 会被覆盖丢弃。因此：
                        //   - 用户输入非空 → 视为改动（unchanged=false），新值随 draft 提交；
                        //   - 清空回空串 → 恢复 unchanged=true，语义为「留空 = 不修改」，
                        //     保存时仍取回旧值（仅对有 fieldId 的既有字段成立）。
                        if !newValue.isEmpty {
                            row.unchanged = false
                        } else if row.fieldId != nil {
                            row.unchanged = true
                        }
                    }
                if row.unchanged {
                    Text("未修改")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
                if row.designation == .password {
                    // 密码生成器（FR-3.2 随机字符 / FR-3.3 密码短语双模式，
                    // docs/15 §3.3.4）：popover 点外部即收起，无 sheet 困锁面。
                    Button {
                        showGenerator = true
                    } label: {
                        Label("生成", systemImage: "wand.and.stars")
                    }
                    .controlSize(.small)
                    .popover(isPresented: $showGenerator, arrowEdge: .bottom) {
                        PasswordGeneratorPopover { generated in
                            row.value = generated
                            showGenerator = false
                        }
                        .environmentObject(model)
                        .frame(width: 340)
                    }
                }
            }
        default:
            TextField(row.name, text: $row.value)
        }
    }
}

// MARK: - 密码生成器（FR-3.2 随机字符 / FR-3.3 密码短语，MC-2）

/// 生成器 popover：模式切换「随机字符 / 密码短语」，参数与结果同走强度
/// 指示（Rust 工厂版 zxcvbn，ChangePasswordView / VaultSetupView 同款）。
/// 生成与使用都发生在本 popover 行内，结果写入字段值后即随闭包丢弃——
/// 生成结果不进 AppModel。
struct PasswordGeneratorPopover: View {
    @EnvironmentObject
    private var model: AppModel

    /// 「使用」回调：把生成结果写回字段行。
    let onUse: (String) -> Void

    enum GenMode: Hashable {
        case random
        case passphrase
    }

    /// 分隔符预设（FR-3.3：`-` / `.` / 空格 / 自定义 1–3 个可打印字符）。
    enum SeparatorChoice: Hashable {
        case dash, dot, space, custom
    }

    // 随机字符参数（内核约束：长度 8..=100，至少一个字符集）
    @State private var mode: GenMode = .random
    @State private var length = 20.0
    @State private var useNumbers = true
    @State private var useLowercase = true
    @State private var useUppercase = true
    @State private var useSymbols = false
    @State private var excludeSimilar = true

    // 密码短语参数（内核约束：词数 3..=10、分隔符 1..=3 可打印字符）
    @State private var wordCount = 5.0
    @State private var separatorChoice: SeparatorChoice = .dash
    @State private var customSeparator = ""
    @State private var capitalize = true
    @State private var numberSuffix = true

    @State private var result = ""
    @State private var generationError: String?

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Picker("模式", selection: $mode) {
                Text("随机字符").tag(GenMode.random)
                Text("密码短语").tag(GenMode.passphrase)
            }
            .pickerStyle(.segmented)
            .onChange(of: mode) { _, _ in
                result = ""
                generationError = nil
            }

            switch mode {
            case .random: randomOptions
            case .passphrase: passphraseOptions
            }

            HStack {
                Button("生成") { generate() }
                    .buttonStyle(.borderedProminent)
                if !result.isEmpty {
                    Text(result)
                        .font(.body.monospaced())
                        .textSelection(.enabled)
                        .lineLimit(2)
                        .truncationMode(.middle)
                        .help(result)
                    Spacer()
                    Button("使用") { onUse(result) }
                        .buttonStyle(.bordered)
                } else {
                    Spacer()
                }
            }

            if let generationError {
                Text(generationError)
                    .font(.caption)
                    .foregroundStyle(.red)
            }

            if !result.isEmpty {
                strengthSection
            }
        }
        .padding()
    }

    // MARK: 参数区

    @ViewBuilder
    private var randomOptions: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack {
                Text("长度 \(Int(length))")
                Slider(value: $length, in: 8...100, step: 1)
                    .frame(maxWidth: .infinity)
            }
            Toggle("数字", isOn: $useNumbers)
            Toggle("小写字母", isOn: $useLowercase)
            Toggle("大写字母", isOn: $useUppercase)
            Toggle("符号", isOn: $useSymbols)
            Toggle("排除易混淆字符（iI1loO0…）", isOn: $excludeSimilar)
        }
        .font(.callout)
    }

    @ViewBuilder
    private var passphraseOptions: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack {
                Text("词数 \(Int(wordCount))")
                Slider(value: $wordCount, in: 3...10, step: 1)
                    .frame(maxWidth: .infinity)
            }
            Picker("分隔符", selection: $separatorChoice) {
                Text("连字符（-）").tag(SeparatorChoice.dash)
                Text("句点（.）").tag(SeparatorChoice.dot)
                Text("空格").tag(SeparatorChoice.space)
                Text("自定义").tag(SeparatorChoice.custom)
            }
            if separatorChoice == .custom {
                TextField("1–3 个字符", text: $customSeparator)
                    .frame(maxWidth: 120)
            }
            Toggle("词首大写", isOn: $capitalize)
            Toggle("末尾追加数字", isOn: $numberSuffix)
        }
        .font(.callout)
    }

    // MARK: 生成

    private var resolvedSeparator: String {
        switch separatorChoice {
        case .dash: return "-"
        case .dot: return "."
        case .space: return " "
        case .custom: return customSeparator
        }
    }

    private func generate() {
        guard let session = model.session else { return }
        generationError = nil
        do {
            switch mode {
            case .random:
                // 内核约束：长度 8..=100、至少一个字符集（越界 1012）
                result = try session.generatePassword(opts: FfiPasswordGenOptions(
                    length: UInt32(Int(length)),
                    numbers: useNumbers,
                    lowercaseLetters: useLowercase,
                    uppercaseLetters: useUppercase,
                    symbols: useSymbols,
                    excludeSimilarCharacters: excludeSimilar
                ))
            case .passphrase:
                // 内核约束：词数 3..=10、分隔符 1..=3 可打印字符（越界 1012）
                result = try session.generatePassphrase(opts: FfiPassphraseOptions(
                    wordCount: UInt32(Int(wordCount)),
                    separator: resolvedSeparator,
                    capitalize: capitalize,
                    numberSuffix: numberSuffix
                ))
            }
        } catch {
            result = ""
            generationError = ErrorPresenter.text(error)
        }
    }

    // MARK: 强度条（展示用途；与 ChangePasswordView / VaultSetupView 同款）

    @ViewBuilder
    private var strengthSection: some View {
        let score = currentScore
        VStack(alignment: .leading, spacing: 4) {
            HStack(spacing: 4) {
                ForEach(0..<5, id: \.self) { index in
                    Capsule()
                        .fill(index <= score ? strengthColor(score) : Color.secondary.opacity(0.2))
                        .frame(height: 5)
                }
                Text(verbatim: PasswordStrength.label(score))
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
            if let estimate = model.estimateStrength(result), !estimate.warnings.isEmpty {
                Text(estimate.warnings.joined(separator: "；"))
                    .font(.caption2)
                    .foregroundStyle(.secondary)
            }
        }
    }

    /// Rust zxcvbn 估算（有会话恒可用；估算失败用本地粗估兜底）。
    private var currentScore: Int {
        if let estimate = model.estimateStrength(result) {
            return Int(estimate.score)
        }
        return PasswordStrength.localScore(result)
    }

    private func strengthColor(_ score: Int) -> Color {
        switch score {
        case 0: return .red
        case 1: return .orange
        case 2: return .yellow
        case 3: return .green
        default: return .mint
        }
    }
}
