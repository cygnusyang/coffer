// GeneratorSettingsView.swift —— 生成器默认参数设置页（FR-14.3，docs/22 §2.4；
// docs/23 §1.4 TC-GEN）。
//
// 语义：本页编辑的是**存档默认值**（generatorDefaultsV1，GeneratorDefaults.swift），
// 供生成器面板首次打开预填（TC-GEN-01）。编辑在本地草稿进行，只有用户显式
// 「另存为默认」才经 AppModel.saveGeneratorDefaults 校验落盘——非法参数不保存
// （TC-GEN-03，对齐 generate_password 1012 Validation 语义）；「放弃」/关闭不留痕。
//
// 参数范围镜像 ItemEditView 生成器（长度 8..=100 / 词数 3..=10 / 分隔符预设 /
// 字符集开关），保持两处 UI 一致；校验语义统一收敛在 GeneratorDefaults.isValid，
// 不在视图内重复散落的边界判断。

import SwiftUI

struct GeneratorSettingsView: View {
    @EnvironmentObject
    private var model: AppModel
    @Environment(\.dismiss)
    private var dismiss

    /// 编辑草稿（@State 本地，不直接写存档；onAppear 从当前存档初始化）。
    /// 默认值先置内置默认，onAppear 装载真实存档（TC-GEN-04 语义）。
    @State private var draft = GeneratorDefaults.builtin
    /// 草稿已装载标记（防止 onAppear 覆盖编辑中的草稿）。
    @State private var didLoad = false
    /// 保存反馈：nil=未操作；true=已保存（TC-GEN-01）；false=校验失败（TC-GEN-03）。
    @State private var saveOutcome: Bool?

    /// 分隔符 UI 预设（镜像 ItemEditView 同款选择器；存储侧是解析后的字符串，
    /// 预设只是展示层映射，见 `separatorChoice` 绑定）。
    private enum SeparatorChoice: Hashable {
        case dash, dot, space, custom
    }

    /// 分隔符选择器当前选中项（独立 @State，避免与 draft.separator 互为因果：
    /// 若绑定读侧由 draft.separator 推导，选中「自定义」但草稿仍是旧预设时
    /// 自定义输入框不会出现）。
    @State private var sepChoice: SeparatorChoice = .dash

    /// 选择器状态 ↔ 草稿 separator 字符串的映射：
    /// 非 custom 预设选中即回写草稿；custom 由 TextField 直接编辑草稿
    /// （选中 custom 保持原值，不覆盖）。
    private var separatorChoice: Binding<SeparatorChoice> {
        Binding(
            get: { sepChoice },
            set: { choice in
                sepChoice = choice
                switch choice {
                case .dash: draft.separator = "-"
                case .dot: draft.separator = "."
                case .space: draft.separator = " "
                case .custom: break
                }
            }
        )
    }

    /// 存档分隔符字符串 → 预设（不匹配任何预设视为自定义）。
    private static func choice(for separator: String) -> SeparatorChoice {
        switch separator {
        case "-": return .dash
        case ".": return .dot
        case " ": return .space
        default: return .custom
        }
    }

    /// 长度滑块（Double 驱动，草稿存 UInt32——与 ItemEditView 同转换）。
    private var lengthBinding: Binding<Double> {
        Binding(
            get: { Double(draft.length) },
            set: { draft.length = UInt32($0) }
        )
    }

    /// 词数滑块（同上）。
    private var wordCountBinding: Binding<Double> {
        Binding(
            get: { Double(draft.wordCount) },
            set: { draft.wordCount = UInt32($0) }
        )
    }

    var body: some View {
        NavigationStack {
            Form {
                randomSection
                passphraseSection
                saveSection
            }
            .formStyle(.grouped)
            .navigationTitle("生成器默认参数")
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("放弃") { dismiss() }
                }
            }
        }
        .frame(width: 480)
        .onAppear {
            // 装载当前存档（TC-GEN-02 重启持久 / TC-GEN-04 回退默认）。
            guard !didLoad else { return }
            draft = model.generatorDefaults
            sepChoice = Self.choice(for: draft.separator)
            didLoad = true
        }
    }

    // MARK: - 随机字符参数（镜像 ItemEditView.randomOptions）

    private var randomSection: some View {
        Section {
            HStack {
                Text("长度 \(Int(draft.length))")
                Slider(value: lengthBinding, in: 8...100, step: 1)
            }
            Toggle("数字", isOn: $draft.numbers)
            Toggle("小写字母", isOn: $draft.lowercaseLetters)
            Toggle("大写字母", isOn: $draft.uppercaseLetters)
            Toggle("符号", isOn: $draft.symbols)
            Toggle("排除易混淆字符（iI1loO0…）", isOn: $draft.excludeSimilarCharacters)
        } header: {
            Text("随机字符")
        } footer: {
            Text("至少启用一个字符集，否则视为非法参数（与密码生成器 1012 校验同语义）。")
        }
    }

    // MARK: - 密码短语参数（镜像 ItemEditView.passphraseOptions）

    private var passphraseSection: some View {
        Section {
            HStack {
                Text("词数 \(Int(draft.wordCount))")
                Slider(value: wordCountBinding, in: 3...10, step: 1)
            }
            Picker("分隔符", selection: separatorChoice) {
                Text("连字符（-）").tag(SeparatorChoice.dash)
                Text("句点（.）").tag(SeparatorChoice.dot)
                Text("空格").tag(SeparatorChoice.space)
                Text("自定义").tag(SeparatorChoice.custom)
            }
            if sepChoice == .custom {
                TextField("1–3 个字符", text: $draft.separator)
                    .frame(maxWidth: 120)
            }
            Toggle("词首大写", isOn: $draft.capitalize)
            Toggle("末尾追加数字", isOn: $draft.numberSuffix)
        } header: {
            Text("密码短语")
        } footer: {
            Text("分隔符需为 1–3 个可打印字符；词数 3–10。")
        }
    }

    // MARK: - 保存（TC-GEN-01 正向 / TC-GEN-03 负向）

    private var saveSection: some View {
        Section {
            Button("另存为默认") { save() }
                .buttonStyle(.borderedProminent)
            if let outcome = saveOutcome {
                Text(outcome ? "已保存为默认值。" : "参数无效，未保存。请调整后重试。")
                    .font(.caption)
                    .foregroundStyle(outcome ? Color.secondary : Color.red)
            }
        } footer: {
            Text("保存后，新建条目的生成器将用这些参数预填；也可随时回到本页改回。")
        }
    }

    private func save() {
        saveOutcome = model.saveGeneratorDefaults(draft)
    }
}
