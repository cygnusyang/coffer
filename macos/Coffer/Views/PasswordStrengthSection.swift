// PasswordStrengthSection.swift —— 主密码强度要求 + 实时强度条（共享组件）。
//
// 1010 弱密码门禁 = zxcvbn score ≥ 3（「强」以上，cf-domain/src/error.rs；
// Rust 侧 Display 为 "password too weak"，无要求说明——用户 2026-10-09 反馈
// 重置密码时弹窗只提示太弱、没说要求）。
//
// 用法：新密码 SecureField 下方挂 `PasswordStrengthSection(password: $field)`。
//   - 静态要求文本**常驻**（未输入也显示，让用户知道通过条件）；
//   - 输入后展示实时强度条 + zxcvbn 改进建议（warnings）。
// estimateStrength 走 Rust 工厂版 zxcvbn（纯计算、无会话依赖，建库前/锁态
// 均可用，见 AppModel.estimateStrength）；估算失败用 PasswordStrength.localScore
// 本地粗估兜底（同 ChangePasswordView / VaultSetupView 旧纪律）。
//
// 消费方：RecoveryResetSheet（Touch ID / 恢复码两分支）、ChangePasswordView。

import SwiftUI

struct PasswordStrengthSection: View {
    @EnvironmentObject
    private var model: AppModel

    /// 绑定的新密码输入（实时估算强度）。
    @Binding var password: String

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            // 常驻要求说明（1010 门禁 = zxcvbn score ≥ 3；建议措辞对齐
            // zxcvbn 判分偏好：长度优先、避免字典词/序列/个人信息）
            Text("要求：密码强度需达到「强」或以上（zxcvbn 3/4）。建议长度 ≥ 12、混用大小写 / 数字 / 符号，避免常见单词、键盘连续键与个人信息。")
                .font(.caption)
                .foregroundStyle(.secondary)

            if !password.isEmpty {
                let score = currentScore
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
                if let estimate = model.estimateStrength(password),
                   !estimate.warnings.isEmpty {
                    Text(estimate.warnings.joined(separator: "；"))
                        .font(.caption2)
                        .foregroundStyle(.secondary)
                }
            }
        }
    }

    /// Rust zxcvbn 估算（工厂版、无会话依赖）；估算失败本地粗估兜底。
    /// 判分与 UpdatePasswordSheet 共用 PasswordStrength.score，避免两处漂移。
    private var currentScore: Int {
        PasswordStrength.score(password, estimate: model.estimateStrength)
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
