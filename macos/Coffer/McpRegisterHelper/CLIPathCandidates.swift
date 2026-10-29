// GUI 启动不继承终端 PATH；固定候选保持命令行安装优先，再补已核验的 App 内嵌 CLI。
// 纯函数独立测试；文件可执行性由调用方注入，生产仍使用 FileManager 校验。
enum CLIPathCandidates {
    static func paths(named name: String, homeDirectory: String) -> [String] {
        var paths = [homeDirectory + "/.local/bin/" + name]
        paths += ["/usr/local/bin", "/opt/homebrew/bin", "/usr/bin"].map { $0 + "/" + name }
        if name == "codex" {
            let suffix = "/ChatGPT.app/Contents/Resources/codex-cli/CodexCLI.app/Contents/MacOS/codex"
            paths += ["/Applications" + suffix, homeDirectory + "/Applications" + suffix]
        }
        return paths
    }

    static func firstExecutable(in paths: [String], isExecutable: (String) -> Bool) -> String? {
        paths.first(where: isExecutable)
    }
}
