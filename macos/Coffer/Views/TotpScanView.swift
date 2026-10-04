// TotpScanView.swift —— TOTP QR 相机实时扫描（FR-5.3，T09，裁定 A）。
//
// 数据流（docs/22 §2.5.1）：AVCaptureSession 实时预览 + 取景框 →
// AVCaptureMetadataOutput 识别 QR 原始 stringValue → 视图注入的校验函数
// （复用 model.parseOtpauth = cf-ffi parse_otpauth_uri，api.rs:586，纯函数
// 直调、零新 FFI；失败统一 1012 Validation）：
//   - Ok(FfiTotpDraft) → sheet 内预览 issuer/account/位数/周期 +「使用此 URI」
//     → onScanned(原始 URI 字符串) 回填 ItemEditView.otpauthText → 既有 save
//     落库（ItemWrite 门禁复用）
//   - Err → sheet 内拒绝提示「不是有效的 otpauth URI」，保持扫描不退出
// TCC 三态：authorized 实时扫描；notDetermined 首弹授权窗（NSCameraUsageDescription）；
// denied/restricted → 明示「相机权限被拒绝」+「手动输入」兜底（TC-QR-08 负路径，
// 拒权后不反复弹权限）。本视图无写路径、无门禁；仅回填 URI，落库走既有 save()。

import AVFoundation
import SwiftUI

/// TOTP QR 扫描入口 sheet。
///
/// 接口（docs/22 §2.5.1 契约 + TCC 拒权聚焦配套）：
///   - `onScanned(原始URI)`：识别有效 otpauth URI 后「使用此 URI」回填
///   - `onDismiss()`：关闭扫描（取消）
///   - `onManualInput()`：TCC 拒权降级「手动输入」——关闭扫描并聚焦 otpauth 输入框
struct TotpScanView: View {
    var onScanned: (String) -> Void
    var onDismiss: () -> Void
    var onManualInput: () -> Void

    @EnvironmentObject
    private var model: AppModel

    @StateObject
    private var controller = QRScanController()

    init(
        onScanned: @escaping (String) -> Void,
        onDismiss: @escaping () -> Void,
        onManualInput: @escaping () -> Void
    ) {
        self.onScanned = onScanned
        self.onDismiss = onDismiss
        self.onManualInput = onManualInput
        _controller = StateObject(wrappedValue: QRScanController())
    }

    var body: some View {
        VStack(spacing: 0) {
            header
            content
                .frame(maxWidth: .infinity, maxHeight: .infinity)
            footer
        }
        .frame(width: 460, height: 560)
        .onAppear {
            // 校验复用既有 parse_otpauth（与 save 同源，避免双份解析逻辑漂移）
            controller.validate = { try model.parseOtpauth(uri: $0) }
            controller.start()
        }
        .onDisappear {
            controller.stop()
        }
    }

    // MARK: - 头尾

    private var header: some View {
        HStack {
            Text("扫描 TOTP 二维码")
                .font(.headline)
            Spacer()
            Button { onDismiss() } label: {
                Image(systemName: "xmark.circle.fill")
                    .foregroundStyle(.secondary)
            }
            .buttonStyle(.plain)
            .help("关闭扫描")
        }
        .padding()
    }

    private var footer: some View {
        HStack {
            Spacer()
            Button("取消") { onDismiss() }
                .keyboardShortcut(.cancelAction)
        }
        .padding()
    }

    // MARK: - 主体（TCC 三态分支）

    @ViewBuilder
    private var content: some View {
        switch controller.phase {
        case .starting:
            ProgressView("正在检查相机…")
        case .requesting:
            ProgressView("正在请求相机权限…")
        case .scanning:
            scanningContent
        case .denied(let message):
            deniedContent(message)
        }
    }

    /// 已授权：实时预览 + 识别；识别成功后切换为预览卡片。
    @ViewBuilder
    private var scanningContent: some View {
        if let parsed = controller.parsed {
            previewCard(parsed)
        } else {
            VStack(spacing: 12) {
                CameraPreviewView(session: controller.session)
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
                    .clipShape(RoundedRectangle(cornerRadius: 10))
                    .overlay(viewfinder)
                if let rejection = controller.rejection {
                    Label(rejection, systemImage: "exclamationmark.triangle.fill")
                        .font(.caption)
                        .foregroundStyle(.red)
                        .frame(maxWidth: .infinity, alignment: .leading)
                }
                Text("将 otpauth:// 二维码对准取景框")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
            .padding(.horizontal)
        }
    }

    private var viewfinder: some View {
        RoundedRectangle(cornerRadius: 10)
            .stroke(Color.accentColor, style: StrokeStyle(lineWidth: 2, dash: [6]))
            .padding(28)
            .allowsHitTesting(false)
    }

    /// 识别成功预览：issuer/account/位数/周期 + 确认/重扫。
    private func previewCard(_ parsed: (raw: String, draft: FfiTotpDraft)) -> some View {
        VStack(alignment: .leading, spacing: 12) {
            Label("识别成功", systemImage: "checkmark.circle.fill")
                .font(.headline)
                .foregroundStyle(.green)
            VStack(alignment: .leading, spacing: 6) {
                Text(verbatim: "发行方：\(parsed.draft.issuer ?? "未提供")")
                Text(verbatim: "账户：\(parsed.draft.account ?? "未提供")")
                Text(verbatim: "位数：\(parsed.draft.digits) 位 · 周期：\(parsed.draft.period) 秒")
            }
            .font(.callout)
            .textSelection(.enabled)
            Text("确认后将该 otpauth URI 填入表单，保存时写入条目。")
                .font(.caption)
                .foregroundStyle(.secondary)
            Spacer()
            HStack {
                Button("重新扫描") { controller.resumeScanning() }
                Spacer()
                Button("使用此 URI") { onScanned(parsed.raw) }
                    .keyboardShortcut(.defaultAction)
                    .buttonStyle(.borderedProminent)
            }
        }
        .padding(20)
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
    }

    /// TCC 拒权 / 无摄像头：明示 + 手动输入兜底（TC-QR-08）。
    private func deniedContent(_ message: String) -> some View {
        VStack(spacing: 16) {
            Image(systemName: "video.slash")
                .font(.system(size: 40))
                .foregroundStyle(.secondary)
            Text(message)
                .font(.callout)
                .multilineTextAlignment(.center)
            Text("仍可手动输入 otpauth:// URI 添加 TOTP。")
                .font(.caption)
                .foregroundStyle(.secondary)
            Button("手动输入") { onManualInput() }
                .buttonStyle(.borderedProminent)
        }
        .padding(40)
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }
}

// MARK: - 扫描会话控制器

/// 扫描会话控制器：AVCaptureSession 生命周期 + TCC 三态 + QR 识别。
///
/// 识别到 QR 原始 stringValue 后交给 `validate`（视图注入，复用
/// model.parseOtpauth）：Ok 暂停会话进入预览态（防同码反复触发）；
/// Err 拒绝提示不退出（TC-QR-02）。无写路径、无门禁。
final class QRScanController: NSObject, ObservableObject {
    /// TCC 三态 + 装配阶段。
    enum Phase {
        case starting        // 初始：尚未检查权限
        case requesting      // TCC 授权弹窗进行中
        case scanning        // 已授权：实时预览 + 识别
        case denied(String)  // 拒权/受限/无摄像头：明示文案
    }

    @Published private(set) var phase: Phase = .starting
    /// 识别成功：原始 URI + 解析结果（sheet 内预览 + 回填）。
    @Published private(set) var parsed: (raw: String, draft: FfiTotpDraft)?
    /// 非 otpauth 拒绝提示（保持扫描，不退出）。
    @Published private(set) var rejection: String?

    /// 视图注入的校验函数（复用 model.parseOtpauth；失败统一 1012）。
    var validate: ((String) throws -> FfiTotpDraft)?

    let session = AVCaptureSession()
    private let sessionQueue = DispatchQueue(label: "coffer.qr.session")
    private let metadataQueue = DispatchQueue(label: "coffer.qr.metadata")
    /// sheet 已关闭后禁止再装配/启动会话（防授权回调晚到）。
    private var active = false

    // MARK: - 生命周期

    /// TCC 检查 + 装配 + 启动（onAppear 调用，主线程）。
    func start() {
        active = true
        switch AVCaptureDevice.authorizationStatus(for: .video) {
        case .authorized:
            phase = .scanning
            configureAndStart()
        case .notDetermined:
            // 首弹授权窗（NSCameraUsageDescription，TC-QR-03）
            phase = .requesting
            AVCaptureDevice.requestAccess(for: .video) { [weak self] granted in
                DispatchQueue.main.async {
                    guard let self, self.active else { return }
                    if granted {
                        self.phase = .scanning
                        self.configureAndStart()
                    } else {
                        // 拒权降级，此后状态为 denied 不再反复弹权限（TC-QR-08）
                        self.phase = .denied(Self.noCameraAccessMessage)
                    }
                }
            }
        case .denied, .restricted:
            // 已在系统设置拒权/受限：直接降级，不弹窗（TC-QR-08）
            phase = .denied(Self.noCameraAccessMessage)
        @unknown default:
            // 未来新增未知状态：按拒权降级（不启用相机，安全默认）
            phase = .denied(Self.noCameraAccessMessage)
        }
    }

    /// 停止会话（onDisappear 调用，主线程）。
    func stop() {
        active = false
        sessionQueue.async { [weak self] in
            if self?.session.isRunning == true {
                self?.session.stopRunning()
            }
        }
    }

    /// 「重新扫描」：清空预览态，恢复实时识别。
    func resumeScanning() {
        parsed = nil
        rejection = nil
        sessionQueue.async { [weak self] in
            self?.session.startRunning()
        }
    }

    // MARK: - 会话装配

    /// 在 sessionQueue 上装配输入/输出并启动（startRunning 可能阻塞，勿在主线程）。
    private func configureAndStart() {
        sessionQueue.async { [weak self] in
            guard let self, self.active else { return }
            guard let device = AVCaptureDevice.default(for: .video) else {
                DispatchQueue.main.async {
                    self.phase = .denied("未检测到可用摄像头，请手动输入 otpauth URI。")
                }
                return
            }
            do {
                let input = try AVCaptureDeviceInput(device: device)
                let output = AVCaptureMetadataOutput()
                self.session.beginConfiguration()
                if self.session.canAddInput(input) {
                    self.session.addInput(input)
                }
                if self.session.canAddOutput(output) {
                    self.session.addOutput(output)
                    // metadataObjectTypes 须在 output 加入 session 后设置
                    output.setMetadataObjectsDelegate(self, queue: self.metadataQueue)
                    if output.availableMetadataObjectTypes.contains(.qr) {
                        output.metadataObjectTypes = [.qr]
                    }
                }
                self.session.commitConfiguration()
                self.session.startRunning()
            } catch {
                DispatchQueue.main.async {
                    self.phase = .denied("相机启动失败，请手动输入 otpauth URI。")
                }
            }
        }
    }

    private static let noCameraAccessMessage = "相机权限被拒绝。可在系统设置 → 隐私与安全性 → 相机中允许 Coffer 后重试。"
}

// MARK: - QR 识别

extension QRScanController: AVCaptureMetadataOutputObjectsDelegate {
    func metadataOutput(
        _ output: AVCaptureMetadataOutput,
        didOutput metadataObjects: [AVMetadataObject],
        from connection: AVCaptureConnection
    ) {
        // 取第一个可读 QR 的原始 stringValue（显式遍历，避开链式尾闭包在
        // guard 条件内的解析歧义）
        var raw: String?
        for object in metadataObjects {
            if let readable = object as? AVMetadataMachineReadableCodeObject,
               let value = readable.stringValue {
                raw = value
                break
            }
        }
        guard let raw, let validate = validate else { return }

        do {
            let draft = try validate(raw)
            DispatchQueue.main.async { [weak self] in
                guard let self, self.active, self.parsed == nil else { return }
                // 识别到有效 URI：暂停实时识别，进入预览态（防同码反复触发）
                self.sessionQueue.async { self.session.stopRunning() }
                self.parsed = (raw: raw, draft: draft)
                self.rejection = nil
            }
        } catch {
            DispatchQueue.main.async { [weak self] in
                guard let self, self.active else { return }
                // 拒绝提示不退出（TC-QR-02 Err 分支）；错误码 1012 随消息直出
                self.rejection = "不是有效的 otpauth URI：\(ErrorPresenter.text(error))"
            }
        }
    }
}

// MARK: - 相机预览

/// AVCaptureVideoPreviewLayer 的 SwiftUI 包装（NSViewRepresentable）。
struct CameraPreviewView: NSViewRepresentable {
    let session: AVCaptureSession

    final class Coordinator {
        var preview: AVCaptureVideoPreviewLayer?
    }

    func makeCoordinator() -> Coordinator {
        Coordinator()
    }

    func makeNSView(context: Context) -> NSView {
        let view = NSView()
        view.wantsLayer = true
        let preview = AVCaptureVideoPreviewLayer(session: session)
        preview.videoGravity = .resizeAspectFill
        preview.frame = view.bounds
        view.layer?.addSublayer(preview)
        context.coordinator.preview = preview
        return view
    }

    func updateNSView(_ nsView: NSView, context: Context) {
        context.coordinator.preview?.frame = nsView.bounds
    }
}
