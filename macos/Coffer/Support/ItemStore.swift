// ItemStore.swift —— AppModel 的条目操作扩展（列表 / 详情 / CRUD / 搜索）。
//
// FFI 调用为同步接口（docs/07 §2.3），CRUD 均为毫秒级，直接在 MainActor 调用；
// 建库 / 解锁 / 导入等慢调用才走 Task.detached。
//
// 错误纪律：code 1001（会话锁定）特殊处理 —— 说明会话已被锁定（如自动锁定
// 或系统锁屏触发），UI 切回锁定界面而非弹错误框。

import Foundation

extension AppModel {
    // MARK: - 列表与搜索

    /// 按 sidebarFilter + searchText 重载条目列表。
    /// 搜索词非空（且回收站视图除外）时走 search 接口（标题多关键词全命中）。
    func reloadItems() {
        guard let session, phase == .unlocked else { return }
        do {
            let trimmed = searchText.trimmingCharacters(in: .whitespaces)
            if !trimmed.isEmpty && sidebarFilter != .trash {
                var list = try session.search(query: trimmed)
                if case let .category(category) = sidebarFilter {
                    list = list.filter { $0.category == category }
                }
                items = list
            } else {
                let state: FfiItemState? = (sidebarFilter == .trash) ? .trashed : .active
                var list = try session.listItems(
                    filter: FfiItemFilter(state: state, category: nil, offset: nil, limit: nil)
                )
                switch sidebarFilter {
                case .favorites:
                    list = list.filter { $0.isFavorite }
                case .category(let category):
                    list = list.filter { $0.category == category }
                case .all, .trash:
                    break
                }
                items = list
            }
        } catch {
            handleFfiError(error)
        }
    }

    /// 选中条目变化时加载详情（Concealed 已掩码）。
    func loadSelectedDetails() {
        guard let id = selectedItemID else {
            currentDetails = nil
            return
        }
        do {
            currentDetails = try session?.getItem(itemId: id)
        } catch {
            handleFfiError(error)
        }
    }

    /// 选中条目的摘要（若仍在当前列表中）。
    var selectedItemSummary: FfiItemSummary? {
        items.first { $0.uuid == selectedItemID }
    }

    // MARK: - CRUD（视图层在 Task 中调用，异常已转 lastErrorMessage）

    /// 新建条目，返回新条目 ID。
    func createItem(draft: FfiItemDraft) throws -> String {
        guard let session else { throw FfiError.Coffer(code: 1001, message: "会话不存在") }
        let id = try session.createItem(draft: draft)
        reloadItems()
        return id
    }

    /// 更新条目（整体替换）。
    func updateItem(itemId: String, draft: FfiItemDraft) throws {
        guard let session else { throw FfiError.Coffer(code: 1001, message: "会话不存在") }
        try session.updateItem(itemId: itemId, draft: draft)
        reloadItems()
        if selectedItemID == itemId {
            loadSelectedDetails()
        }
    }

    /// 删除条目：hard=false 进回收站，hard=true 级联硬删。
    func deleteItem(itemId: String, hard: Bool) throws {
        guard let session else { throw FfiError.Coffer(code: 1001, message: "会话不存在") }
        try session.deleteItem(itemId: itemId, hard: hard)
        if selectedItemID == itemId {
            selectedItemID = nil
            currentDetails = nil
        }
        reloadItems()
    }

    /// 从回收站恢复。
    func restoreItem(itemId: String) throws {
        guard let session else { throw FfiError.Coffer(code: 1001, message: "会话不存在") }
        try session.restoreItem(itemId: itemId)
        reloadItems()
    }

    /// 收藏切换。
    func setFavorite(itemId: String, favorite: Bool) throws {
        guard let session else { throw FfiError.Coffer(code: 1001, message: "会话不存在") }
        try session.setFavorite(itemId: itemId, favorite: favorite)
        reloadItems()
        if selectedItemID == itemId {
            loadSelectedDetails()
        }
    }

    // MARK: - 按需取值

    /// 取字段明文值（密码等敏感值，随取随走；不进全局状态）。
    func fieldValue(itemId: String, fieldId: String) throws -> String? {
        guard let session else { throw FfiError.Coffer(code: 1001, message: "会话不存在") }
        return try session.getFieldValue(itemId: itemId, fieldId: fieldId)
    }

    /// 生成条目当前 TOTP 验证码。
    func totpCode(itemId: String) throws -> FfiTotpCode {
        guard let session else { throw FfiError.Coffer(code: 1001, message: "会话不存在") }
        return try session.totpCode(itemId: itemId)
    }

    /// 解析 otpauth:// URI（仅 SHA-1；失败 → 码 1012）。
    func parseOtpauth(uri: String) throws -> FfiTotpDraft {
        guard let session else { throw FfiError.Coffer(code: 1001, message: "会话不存在") }
        return try session.parseOtpauthUri(uri: uri)
    }

    // MARK: - 错误分流

    /// 统一错误处理：1001 切回锁定界面，其余 code+message 直出。
    func handleFfiError(_ error: Error) {
        if case let .Coffer(code, _) = error as? FfiError, code == 1001 {
            // 会话已被锁定（自动锁定 / 系统锁屏 / 他人手动），UI 回锁定界面
            phase = session != nil ? .locked : .noVault
            return
        }
        lastErrorMessage = ErrorPresenter.text(error)
    }
}
