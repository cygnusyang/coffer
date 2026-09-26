// MainView.swift —— 解锁后的主界面。
//
// v0.1 阶段占位：条目列表 / 详情 / 编辑在 T05 阶段二接入。

import SwiftUI

struct MainView: View {
    @EnvironmentObject
    private var model: AppModel

    var body: some View {
        VStack(spacing: 12) {
            Text(model.vaultName).font(.title2.bold())
            Text("解锁成功。条目管理将在下一阶段提供。")
                .foregroundStyle(.secondary)
            Button("锁定") { model.lock() }
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }
}
