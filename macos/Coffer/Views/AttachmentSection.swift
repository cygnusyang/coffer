// AttachmentSection.swift —— 条目详情附件区（FR-9.3 / FR-9.4，docs/15 §3.1.4）。
//
// 明文暴露面（docs/15 §3.1.4 诚实声明体裁）：
//   - 预览不落盘：图片 / PDF 在尺寸上限内走内存预览（NSImage / PDFDocument
//     直接以 Data 构造），明文不写磁盘；预览 Data 仅本区行内局部状态持有，
//     关闭预览即置 nil 释放，不进 AppModel（docs/15 §6.1 S2 切片：零
//     AppModel 改动，附件区自持状态）。
//   - 打开 = 显式导出：非预览类型走 NSSavePanel 导出后 NSWorkspace.open；
//     UI 固定提示「导出文件为明文，请用后删除」。大文件优化不做（D-3）。
//   - readAttachment 取回的 Data 不进 @Published、不进环境对象（与
//     getFieldValue 同纪律，docs/07 §4.2）。
//
// 慢调用纪律（docs/07 §2.4）：add / read 的载荷可达 100 MiB（D-3 整块
// Vec<u8>），Task.detached 包裹避免卡主线程；list / remove 为毫秒级，
// 与 ItemStore CRUD 同模式直接主线程调用（ItemDetailView::refreshHistoryCount
// 同款 session 直连，不新增 AppModel 包装）。
//
// 错误纪律：code 1001（会话锁定）经 model.handleFfiError 切回锁定界面，
// 其余 code+message 直出（ErrorPresenter）；错误弹窗复用宿主
// ItemDetailView 已挂的 ffiErrorAlert，本区不重复挂载（同绑定的两个
// alert 会产生双重呈现冲突）。

import PDFKit
import SwiftUI

struct AttachmentSection: View {
    @EnvironmentObject
    private var model: AppModel

    let itemId: String

    @State private var attachments: [FfiAttachmentMeta] = []
    @State private var isBusy = false
    /// 待确认删除的附件（nil = 无确认对话框）。
    @State private var pendingRemove: FfiAttachmentMeta?
    /// 内存预览载荷（仅本区局部状态；关闭预览即置 nil 释放明文）。
    @State private var preview: PreviewPayload?
    @State private var showPreview = false

    // MARK: - 常量

    /// 内存预览尺寸上限：附件明文 ≤ 32 MiB 且类型可预览才读明文进内存
    /// （docs/15 §3.1.4「图片 ≤ 一定尺寸」的具体取值；超限走显式导出）。
    private static let previewMaxBytes: Int64 = 32 * 1024 * 1024

    /// 可内存预览的图片扩展名（小写比较；PDF 单列）。
    private static let imageExtensions: Set<String> = [
        "png", "jpg", "jpeg", "gif", "heic", "tiff", "tif", "bmp", "webp",
    ]

    // MARK: - 预览载荷

    /// 预览 sheet 的载荷（Identifiable 供 sheet(item:) 使用；持有明文 Data，
    /// 生命周期 = 预览打开期间）。
    struct PreviewPayload: Identifiable {
        let id = UUID()
        let filename: String
        let data: Data
        let isPDF: Bool
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack {
                Text("附件").font(.headline)
                Spacer()
                if isBusy {
                    ProgressView().controlSize(.small)
                }
                Button {
                    addAttachments()
                } label: {
                    Label("添加", systemImage: "plus")
                }
                .controlSize(.small)
                .disabled(isBusy)
            }
            if attachments.isEmpty {
                Text("暂无附件")
                    .font(.callout)
                    .foregroundStyle(.tertiary)
            } else {
                ForEach(attachments, id: \.attachmentUuid) { meta in
                    attachmentRow(meta)
                }
            }
            // FR-9.4 固定风险提示：打开/保存都是显式导出明文
            Text("打开或保存的附件文件为明文，请用后删除。")
                .font(.caption2)
                .foregroundStyle(.secondary)
        }
        .task {
            reload()
        }
        .confirmationDialog(
            "删除附件「\(pendingRemove?.filename ?? "")」？附件将从库中永久删除，此操作不可恢复。",
            isPresented: Binding(
                get: { pendingRemove != nil },
                set: { if !$0 { pendingRemove = nil } }
            ),
            titleVisibility: .visible
        ) {
            Button("删除附件", role: .destructive) {
                if let meta = pendingRemove {
                    removeAttachment(meta)
                }
            }
            Button("取消", role: .cancel) {}
        }
        .sheet(item: $preview) { payload in
            previewSheet(payload)
        }
    }

    // MARK: - 列表行

    private func attachmentRow(_ meta: FfiAttachmentMeta) -> some View {
        HStack(alignment: .firstTextBaseline, spacing: 8) {
            Image(systemName: Self.isPDF(meta) ? "doc.richtext" : "doc")
                .foregroundStyle(.secondary)
            VStack(alignment: .leading, spacing: 2) {
                Text(meta.filename)
                    .textSelection(.enabled)
                    .lineLimit(1)
                    .truncationMode(.middle)
                Text("\(Self.byteCount(meta.sizeBytes)) · \(Self.timestamp(meta.createdAt))")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
            Spacer()
            if isPreviewable(meta) {
                Button("预览") { loadPreview(meta) }
                    .controlSize(.small)
                    .disabled(isBusy)
            } else {
                Button("打开") { exportThenOpen(meta) }
                    .controlSize(.small)
                    .disabled(isBusy)
            }
            Menu("更多") {
                Button("保存…") { exportThenSave(meta) }
                Divider()
                Button("删除…", role: .destructive) { pendingRemove = meta }
            }
            .controlSize(.small)
            .fixedSize()
        }
        .padding(.vertical, 2)
    }

    // MARK: - 预览（内存预览，不落盘）

    @ViewBuilder
    private func previewSheet(_ payload: PreviewPayload) -> some View {
        VStack(spacing: 12) {
            Text(verbatim: payload.filename)
                .font(.headline)
                .lineLimit(1)
                .truncationMode(.middle)
                .help(payload.filename)
            if payload.isPDF, let document = PDFDocument(data: payload.data) {
                PDFKitPreview(document: document)
            } else if let image = NSImage(data: payload.data) {
                Image(nsImage: image)
                    .resizable()
                    .scaledToFit()
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
            } else {
                ContentUnavailableView(
                    "无法预览该附件",
                    systemImage: "questionmark.folder",
                    description: Text("可改用「更多 → 保存…」导出后打开。")
                )
            }
            HStack {
                Spacer()
                Button("关闭") {
                    // 明文 Data 随载荷置 nil 释放（docs/15 §3.1.4 即用即弃）
                    preview = nil
                }
                .keyboardShortcut(.cancelAction)
            }
            .padding([.horizontal, .bottom])
        }
        .frame(width: 640, height: 560)
    }

    /// NSViewRepresentable：PDFKit 预览（Data 内存构造，不落盘）。
    private struct PDFKitPreview: NSViewRepresentable {
        let document: PDFDocument

        func makeNSView(context: Context) -> PDFView {
            let view = PDFView()
            view.document = document
            view.autoScales = true
            return view
        }

        func updateNSView(_ view: PDFView, context: Context) {
            view.document = document
        }
    }

    // MARK: - 动作

    /// 列表重载（元数据 + filename 解密，毫秒级；与 CRUD 同模式主线程直调）。
    private func reload() {
        guard let session = model.session else { return }
        do {
            attachments = try session.listAttachments(itemId: itemId)
        } catch {
            model.handleFfiError(error)
        }
    }

    /// 添加附件：NSOpenPanel 多选 → 逐个读明文 + FFI 写入（Task.detached，
    /// 载荷可达 100 MiB）。部分失败不中断其余文件，首个错误统一呈现。
    private func addAttachments() {
        let panel = NSOpenPanel()
        panel.canChooseDirectories = false
        panel.canChooseFiles = true
        panel.allowsMultipleSelection = true
        panel.message = "选择要添加的附件（单文件上限 100 MiB）"
        guard panel.runModal() == .OK, !panel.urls.isEmpty else { return }
        guard let session = model.session else { return }

        let urls = panel.urls
        isBusy = true
        Task.detached(priority: .userInitiated) {
            var firstError: Error?
            for url in urls {
                do {
                    let content = try Data(contentsOf: url)
                    _ = try session.addAttachment(
                        itemId: itemId,
                        filename: url.lastPathComponent,
                        content: content
                    )
                } catch {
                    // 容忍部分失败：继续导入其余文件，首个错误收口呈现
                    if firstError == nil { firstError = error }
                }
            }
            // var 不跨闭包捕获（Swift 6 Sendable 纪律）：复制为 let 再进
            // MainActor.run
            let failure = firstError
            await MainActor.run {
                isBusy = false
                reload()
                if let failure {
                    model.handleFfiError(failure)
                }
            }
        }
    }

    /// 删除附件：先删行后删文件在内核侧完成；确认对话框文案见 confirmationDialog。
    private func removeAttachment(_ meta: FfiAttachmentMeta) {
        guard let session = model.session else { return }
        do {
            try session.removeAttachment(attachmentUuid: meta.attachmentUuid)
            reload()
        } catch {
            model.handleFfiError(error)
        }
    }

    /// 预览路径：尺寸上限内的图片 / PDF 读明文进内存（Task.detached），
    /// Data 只进本区行内局部状态。
    private func loadPreview(_ meta: FfiAttachmentMeta) {
        guard let session = model.session else { return }
        isBusy = true
        let isPDF = Self.isPDF(meta)
        Task.detached(priority: .userInitiated) {
            do {
                let data = try session.readAttachment(attachmentUuid: meta.attachmentUuid)
                await MainActor.run {
                    isBusy = false
                    preview = PreviewPayload(
                        filename: meta.filename,
                        data: data,
                        isPDF: isPDF
                    )
                }
            } catch {
                await MainActor.run {
                    isBusy = false
                    model.handleFfiError(error)
                }
            }
        }
    }

    /// 打开 = 显式导出：NSSavePanel 选路径 → 写明文 → NSWorkspace.open。
    private func exportThenOpen(_ meta: FfiAttachmentMeta) {
        export(meta) { url in
            NSWorkspace.shared.open(url)
        }
    }

    /// 保存 = 显式导出（不自动打开）。
    private func exportThenSave(_ meta: FfiAttachmentMeta) {
        export(meta) { _ in }
    }

    /// 导出公共路径：NSSavePanel → 读明文（Task.detached）→ 原子写盘 → 收尾。
    private func export(_ meta: FfiAttachmentMeta, completion: @escaping (URL) -> Void) {
        let panel = NSSavePanel()
        panel.nameFieldStringValue = meta.filename
        panel.message = "附件将导出为明文文件，请用后删除"
        guard panel.runModal() == .OK, let url = panel.url else { return }
        guard let session = model.session else { return }

        isBusy = true
        Task.detached(priority: .userInitiated) {
            do {
                let data = try session.readAttachment(attachmentUuid: meta.attachmentUuid)
                try data.write(to: url, options: .atomic)
                await MainActor.run {
                    isBusy = false
                    completion(url)
                }
            } catch {
                await MainActor.run {
                    isBusy = false
                    model.handleFfiError(error)
                }
            }
        }
    }

    // MARK: - 判定与格式化

    /// 是否可内存预览：类型可预览 且 明文尺寸在上限内（超限走显式导出）。
    private func isPreviewable(_ meta: FfiAttachmentMeta) -> Bool {
        meta.sizeBytes <= Self.previewMaxBytes
            && (Self.isPDF(meta) || Self.isImage(meta))
    }

    private static func isPDF(_ meta: FfiAttachmentMeta) -> Bool {
        extensionLowercased(meta.filename) == "pdf"
    }

    private static func isImage(_ meta: FfiAttachmentMeta) -> Bool {
        imageExtensions.contains(extensionLowercased(meta.filename))
    }

    private static func extensionLowercased(_ filename: String) -> String {
        (filename as NSString).pathExtension.lowercased()
    }

    /// 人读文件大小（ByteCountFormatter，跟随系统 locale）。
    private static func byteCount(_ bytes: Int64) -> String {
        ByteCountFormatter.string(fromByteCount: bytes, countStyle: .file)
    }

    /// 创建时间（详情区「信息」同款格式）。
    private static func timestamp(_ unixSecs: Int64) -> String {
        Date(timeIntervalSince1970: TimeInterval(unixSecs))
            .formatted(date: .abbreviated, time: .shortened)
    }
}
