#!/usr/bin/env bash
# tools/check_no_network.sh —— NFR-SEC-07「零网络可验证」自动化检查
#
# 背景：docs/06-开发计划.md NFR-SEC-07（零网络）标 🟡。README 已有手工验证命令
# （观察进程无 socket），本脚本是其**依赖图侧**的自动化补充：枚举 workspace
# 全部 normal 依赖，断言不出现具备网络能力的 crate。
#
# ⚠️ 边界声明：依赖图检查 ≠ 运行时行为证明。本脚本只证明「依赖树中无网络
# crate / 无 net feature」；运行时零 socket 的证明由 v0.4.0 出口判据②
# （关主窗口后 App 驻留且 0 socket）在 macOS 真机验证，见
# docs/09-版本开发计划.md §2 v0.4.0。
#
# 退出码：0 = 通过（允许有可疑 warning）；1 = 黑名单命中或 cargo tree 失败。
#
# 纪律（docs/09 §4）：cargo tree 输出写入临时文件再解析，不用管道取退出码，
# 避免「管道吞退出码」导致假绿。
set -o pipefail
set -u

# 前提：cargo 可能不在 PATH 上（非交互 shell / 脚本），参照 docs/09 §4 门禁写法
command -v cargo >/dev/null 2>&1 || export PATH="$HOME/.cargo/bin:$PATH"
command -v cargo >/dev/null 2>&1 || {
    echo "ERROR: cargo 不存在（PATH 与 \$HOME/.cargo/bin 均未找到），无法执行依赖图检查" >&2
    exit 1
}

# cargo 工作区根是 core/，不是仓库根（docs/09 §4 前提 2）
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
CORE_DIR="$SCRIPT_DIR/../core"
if [ ! -f "$CORE_DIR/Cargo.toml" ]; then
    echo "ERROR: 未找到 $CORE_DIR/Cargo.toml，请确认脚本位于仓库 tools/ 下" >&2
    exit 1
fi
cd "$CORE_DIR"

TREE_FILE="$(mktemp)"
trap 'rm -f "$TREE_FILE"' EXIT

echo "==> cargo tree --workspace -e normal（工作区根：$CORE_DIR）"
if ! cargo tree --workspace -e normal >"$TREE_FILE"; then
    echo "ERROR: cargo tree 执行失败，无法验证零网络（不要带病放行）" >&2
    exit 1
fi

# 提取依赖名：匹配 "name vX.Y.Z"；排除 workspace 成员自身（行尾带本地路径 "(...)"）
# 并排除 cargo tree 的 "(*)" 去重标记。grep -oE 保证 bash/zsh/macOS 兼容（不用 -P）。
DEPS_FILE="$(mktemp)"
trap 'rm -f "$TREE_FILE" "$DEPS_FILE"' EXIT
grep -vE '\(/\S*\)$' "$TREE_FILE" \
    | grep -oE '[a-zA-Z][a-zA-Z0-9_-]* v[0-9][0-9A-Za-z.-]*' \
    | sed 's/ v.*//' \
    | sort -u >"$DEPS_FILE"
TOTAL="$(wc -l <"$DEPS_FILE" | tr -d ' ')"
echo "==> 依赖总数（去重，不含 workspace 成员自身）：$TOTAL"

# 黑名单：具备网络能力的 crate。tokio 单独判定（见下）。
BLACKLIST="reqwest hyper tokio curl ureq attohttpc surf isahc native-tls rustls quinn tungstenite tokio-tungstenite websocket"
HITS=""

# 注意：zsh 默认不对未引用的参数展开做分词，$BLACKLIST 整串会成一个词；
# 用命令子替换（zsh 对 $(...) 输出默认分词）保证 bash/zsh 行为一致。
for dep in $(printf '%s\n' "$BLACKLIST"); do
    grep -qx "$dep" "$DEPS_FILE" || continue
    if [ "$dep" = "tokio" ]; then
        # tokio 特例：可能被传递引入且默认不启用 net feature。
        # 判定：cargo tree -e features 反查其启用 feature，含 net 或 full 即判失败；
        # 无 net/full 则放行，并在报告中说明判定依据。
        FEAT_FILE="$(mktemp)"
        if cargo tree -e features -i tokio >"$FEAT_FILE" 2>/dev/null \
            && grep -qE 'feature "(net|full)"' "$FEAT_FILE"; then
            echo "FAIL: tokio 出现在依赖图中且启用了 net/full feature（重大发现，停止检查并人工排查引入路径）"
            echo "      复查命令：cd core && cargo tree -e features -i tokio"
            rm -f "$FEAT_FILE"
            exit 1
        fi
        echo "WARN: tokio 出现在依赖图中，但未启用 net/full feature（默认 I/O 调度无网络能力），放行"
        echo "      判定依据：cargo tree -e features -i tokio 输出中无 feature \"net\" / \"full\""
        echo "      复查命令：cd core && cargo tree -e features -i tokio"
        rm -f "$FEAT_FILE"
    else
        echo "FAIL: 依赖图中出现网络能力 crate：$dep"
        echo "      复查命令：cd core && cargo tree -i $dep"
        HITS="$HITS $dep"
    fi
done

if [ -n "$HITS" ]; then
    echo "==> 结果：FAIL（黑名单命中：$HITS）"
    exit 1
fi

# 兜底：依赖名含 http / tls / socket / net 的可疑项 → warning 清单供人工复核，不 fail。
# 正则按词边界匹配子串，避免与黑名单重复报 tokio-tungstenite 已覆盖项。
SUSPICIOUS="$(grep -E '(http|tls|socket|net)' "$DEPS_FILE" || true)"
if [ -n "$SUSPICIOUS" ]; then
    echo "==> 可疑项（仅 warning，须人工复核是否具备网络能力）："
    echo "$SUSPICIOUS" | sed 's/^/    - /'
else
    echo "==> 可疑项：无（依赖名不含 http / tls / socket / net 子串）"
fi

echo "==> 结果：PASS（依赖总数 $TOTAL，黑名单 0 命中）"
echo "    本结果仅证明依赖图无网络 crate；运行时零 socket 见 v0.4.0 出口判据②（macOS 真机）。"
exit 0
