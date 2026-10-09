#!/usr/bin/env bash
# run_install_helper_tests.sh —— OTA install helper（CofferUpdater.app 内 coffer-update）
# 自测（v2.7.0，组 B；docs/35 §6.4 r0.4 配置文件 + result 文件协议）。
#
# 编译 macos/Coffer/Installer/*.swift → /tmp 临时二进制，构造 config 文件跑 helper，
# 断言退出码 + result 文件内容。测试构建**不加** -D COFFER_UPDATER_PRODUCTION
# （生产锚读 env COFFER_UPDATER_TEST_ANCHOR，每例导出），使 currentAppPath 锚可注入。
#
# 安全门（C-1/H-1，2026-10-10 dev-reviewer 修复轮）：
#   - currentAppPath 硬锚定：≠ 锚 → exit 4（零副作用）
#   - newAppPath 载荷：basename 必须为 Coffer.app + 静态验签（DR: anchor apple generic
#     and certificate leaf[subject.OU]="A6DS985SJJ" and identifier "app.coffer.Coffer"）
#     + embedded.provisionprofile 存在且未过期 → 任一失败 exit 2（零副作用）
#   故凡需走到替换/relaunch 的用例，新包必须是「Coffer.app 命名 + Apple Development
#   签名 + 有效 profile」（make_signed_new_app 构造，依赖本机 Apple Development 身份——
#   与 build_macos_app.sh 同一前提）。
#
# 用例：
#   T1 参数/配置解析：无参/未知参/缺值/配置不存在/非法 JSON/缺字段/相对路径/非法 pid → exit 4
#   T2 成功路径：等待→备份→替换→relaunch→写 result → exit 0 + result {success:true,code:0}
#   T3 备份失败：→ exit 1 + result {success:false,code:1} + 目标未被改动
#   T4 替换失败：→ exit 2 + result {success:false,code:2} + 备份完整（权限触发，root 跳过）
#   T5 relaunch 失败（签名有效但可执行不可运行）：→ exit 3 + result {success:false,code:3}
#   T6 current 缺失前置校验：→ exit 1 + result code 1
#   T7 newApp 缺失前置校验：→ exit 2 + result code 2
#   T8 等待 App 退出超时（RUN_SLOW_HELPER_TEST=1 启用）：→ exit 3 + 零修改
#   T9 currentAppPath≠锚：→ exit 4 + 零副作用
#   T10 newApp 文件名非 Coffer.app：→ exit 2（拒装）
#   T11 newApp 未签名（DR 验签失败）：→ exit 2 + result code 2
#   T12 newApp profile 过期 / 缺失：→ exit 2 + result code 2（fail-closed）
#   T13 relaunch 失败（exit 3）后已尽力恢复：目标恢复为备份内容
#   T14 TOCTOU 闭环：等待窗内换包 → 已安装结果验签失败 → exit 2 + 目标恢复为备份
#   T15 C-2 relaunch gate：等待窗换包 + backup 父目录在等待窗内翻转为 symlink →
#       forceRestore 恢复未验内容后，单点 gate 拦截 relaunch（fake-relaunch 桩未调用，
#       COFFER_UPDATER_TEST_FAKE_RELAUNCH）→ exit 2 + 目标恢复为备份内容
#   T16 backupPath 含 symlink 分量 → exit 4（零修改，防备份/恢复被链接定向劫持）
#   T17 backupPath == currentAppPath → exit 4（零修改，防 backupCurrentApp 先删目标本体 DoS）
#   T18 newAppPath == currentAppPath（含 "../" 规范化等价）→ exit 4（零修改）
#   T19 backupPath 为 currentAppPath 的 case 变体（目录大小写不同，APFS 卷不敏感别名）
#       → exit 4（零修改，防判等被大小写绕开导致 backupCurrentApp 先删目标本体 DoS）
#
# helper 无 FFI/Rust 依赖，swiftc 直编即可；不依赖 build_macos_app.sh 产物。
# LaunchServices 启动（open -n <CofferUpdater.app> --args）的端到端替换归真机核销；
# 本测试直接 exec helper 二进制，relaunch 用真 open -n 验证 LaunchServices 接受/拒绝。
# result JSON 断言用 python3（仓库已有 python 依赖先例）。
# 兼容 bash 3.2（macOS 自带 /bin/bash）。
#
# 用法：./tools/run_install_helper_tests.sh
set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
# 允许外部注入源码目录（如对「去掉 gate/加固的变体」做 RED 回归验证）——
# 常规运行不设该变量，用仓库真实源码。
HELPER_SRC_DIR="${COFFER_HELPER_SRC_DIR:-${ROOT_DIR}/macos/Coffer/Installer}"

command -v swiftc >/dev/null 2>&1 || { echo "ERROR: 未找到 swiftc。" >&2; exit 1; }
command -v python3 >/dev/null 2>&1 || { echo "ERROR: 未找到 python3。" >&2; exit 1; }
command -v security >/dev/null 2>&1 || { echo "ERROR: 未找到 security。" >&2; exit 1; }

# 签名身份（CN 兼作 security cms -S 的证书昵称）。载荷 DR 验签依赖真实 Apple Development
# 签名，缺失即无法测 C-1 门——与 build_macos_app.sh 的同一前置（找不到即明确失败）。
SIGNING_IDENTITY="$(security find-identity -v -p codesigning 2>/dev/null \
  | awk -F'"' '/Apple Development/{print $2; exit}')"
if [[ -z "${SIGNING_IDENTITY}" ]]; then
  echo "ERROR: 未找到 Apple Development 签名身份（载荷 DR 验签与 profile 伪造依赖真实签名）。" >&2
  exit 1
fi

ARCH="$(uname -m)"
TMP_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/coffer-helper-test.XXXXXX")"
HELPER_BIN="${TMP_ROOT}/coffer-update"
HELLO_BIN="${TMP_ROOT}/hello"

PASS=0
FAIL=0

cleanup() { rm -rf "${TMP_ROOT}"; }
trap cleanup EXIT

log() { printf '%s\n' "$1"; }
ok()  { PASS=$((PASS+1)); }
bad() { printf 'FAIL: %s\n' "$1" >&2; FAIL=$((FAIL+1)); }

# ---- 编译 helper 与最小可执行（open 对 script CFBundleExecutable 可能拒收，用真 Mach-O）----
# 测试构建不加 -D COFFER_UPDATER_PRODUCTION：生产锚经 env 注入；-framework Security 供
# SecStaticCodeCheckValidity（C-1 静态验签）。
compile_helper() {
  local sources=()
  while IFS= read -r f; do
    sources+=("${f}")
  done < <(find "${HELPER_SRC_DIR}" -name '*.swift' | sort)
  if [[ ${#sources[@]} -eq 0 ]]; then
    echo "ERROR: ${HELPER_SRC_DIR} 无 Swift 源文件。" >&2
    exit 1
  fi
  swiftc -O -swift-version 5 -target "${ARCH}-apple-macos14.0" \
    -framework Security \
    "${sources[@]}" -o "${HELPER_BIN}" \
    || { echo "ERROR: helper 编译失败。" >&2; exit 1; }

  printf 'import Foundation\nprint("mini-app")\n' > "${TMP_ROOT}/hello.swift"
  swiftc -O -swift-version 5 -target "${ARCH}-apple-macos14.0" "${TMP_ROOT}/hello.swift" -o "${HELLO_BIN}" \
    || { echo "ERROR: 最小可执行编译失败。" >&2; exit 1; }
}

# 造一个 open 能接受的最小 .app（真 Mach-O 可执行 + Info.plist + marker）。
# bundle id 带随机后缀，避免多测试同时 launch 的 LaunchServices 冲突。
# 未签名——仅用于 current（旧包，helper 不对其做 DR 验签）。
# marker 放 Contents/Resources/：codesign 对 Contents 根目录的未知散置文件会按
# 嵌套代码处理（"code object is not signed at all"）导致签名失败（实证），
# Resources 子目录正常封存。
make_mini_app() {
  local app_dir="$1" marker="$2" bundle_suffix="$3"
  mkdir -p "${app_dir}/Contents/MacOS" "${app_dir}/Contents/Resources"
  cp "${HELLO_BIN}" "${app_dir}/Contents/MacOS/hello"
  cat > "${app_dir}/Contents/Info.plist" <<PLIST_EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>CFBundleIdentifier</key>
	<string>com.coffer.helper.test.${bundle_suffix}</string>
	<key>CFBundleExecutable</key>
	<string>hello</string>
	<key>CFBundleName</key>
	<string>mini</string>
	<key>CFBundlePackageType</key>
	<string>APPL</string>
</dict>
</plist>
PLIST_EOF
  printf '%s' "${marker}" > "${app_dir}/Contents/Resources/${marker}"
}

# 造一个能通过 helper 载荷门的「新包」：Coffer.app 命名 + CFBundleIdentifier=app.coffer.Coffer
# + Apple Development 签名 + embedded.provisionprofile（security cms -S 伪造，ExpirationDate 受控）。
# $1=app 目录（含 Coffer.app）；$2=marker；$3=mode：valid(未来过期) / expired(过去) / noprofile(无 profile)
# 顺序：先写 Info.plist + profile，再 codesign（签名封存整包资源，对齐真实 App 装配）。
make_signed_new_app() {
  local app_dir="$1" marker="$2" mode="$3"
  mkdir -p "${app_dir}/Contents/MacOS" "${app_dir}/Contents/Resources"
  cp "${HELLO_BIN}" "${app_dir}/Contents/MacOS/hello"
  cat > "${app_dir}/Contents/Info.plist" <<PLIST_EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>CFBundleIdentifier</key>
	<string>app.coffer.Coffer</string>
	<key>CFBundleExecutable</key>
	<string>hello</string>
	<key>CFBundleName</key>
	<string>coffer</string>
	<key>CFBundlePackageType</key>
	<string>APPL</string>
</dict>
</plist>
PLIST_EOF
  if [[ "${mode}" != "noprofile" ]]; then
    local exp_date="2036-01-01T00:00:00Z"
    [[ "${mode}" == "expired" ]] && exp_date="2020-01-01T00:00:00Z"
    local prof_plist="${TMP_ROOT}/prof_${marker}.plist"
    cat > "${prof_plist}" <<PLIST_EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>ExpirationDate</key>
	<date>${exp_date}</date>
	<key>Name</key>
	<string>coffer-test</string>
</dict>
</plist>
PLIST_EOF
    security cms -S -N "${SIGNING_IDENTITY}" -i "${prof_plist}" \
      -o "${app_dir}/Contents/embedded.provisionprofile" >/dev/null 2>&1 \
      || { echo "ERROR: 伪造 profile（security cms -S）失败。" >&2; exit 1; }
  fi
  printf '%s' "${marker}" > "${app_dir}/Contents/Resources/${marker}"
  codesign --force --sign "${SIGNING_IDENTITY}" "${app_dir}" >/dev/null 2>&1 \
    || { echo "ERROR: 新包签名失败（${app_dir}）。" >&2; exit 1; }
}

# 写 config JSON：$1=config 路径；$2..$6 = new/current/backup/result/pid
write_config() {
  local cfg="$1"
  cat > "${cfg}" <<EOF
{
  "newAppPath": "$2",
  "currentAppPath": "$3",
  "backupPath": "$4",
  "resultFilePath": "$5",
  "pid": $6
}
EOF
}

# 取一个已退出进程的 pid（后台 sleep 结束 + wait 收割，kill($pid,0) 必 ESRCH）
dead_pid() {
  sleep 0.2 &
  local pid=$!
  wait "${pid}" 2>/dev/null
  printf '%s' "${pid}"
}

# 断言 result 文件：$1=result 路径；$2=期望 success(true/false)；$3=期望 code
# 同时断言 JSON 恰含 {success, code, message} 三字段且 message 为字符串——
# 与 App 侧 OTAInstaller.InstallResult(success: Bool, code: Int, message: String) 同构。
result_check() {
  python3 - "$1" "$2" "$3" <<'PYEOF'
import json, sys
path, exp_success, exp_code = sys.argv[1], sys.argv[2], int(sys.argv[3])
with open(path) as f:
    d = json.load(f)
keys_ok = set(d.keys()) == {"success", "code", "message"} and isinstance(d.get("message"), str)
ok = keys_ok and (d.get("success") == (exp_success == "true")) and (d.get("code") == exp_code)
sys.exit(0 if ok else 1)
PYEOF
}

# ---- T1 参数/配置解析 → exit 4 ----
run_usage_tests() {
  local rc ok=1

  "${HELPER_BIN}" >/dev/null 2>&1; rc=$?
  [[ $rc -eq 4 ]] || { bad "T1.1 缺参数: 期望 4 实得 ${rc}"; ok=0; }

  "${HELPER_BIN}" --bogus >/dev/null 2>&1; rc=$?
  [[ $rc -eq 4 ]] || { bad "T1.2 未知参数: 期望 4 实得 ${rc}"; ok=0; }

  "${HELPER_BIN}" --config >/dev/null 2>&1; rc=$?
  [[ $rc -eq 4 ]] || { bad "T1.3 --config 缺值: 期望 4 实得 ${rc}"; ok=0; }

  "${HELPER_BIN}" --config "${TMP_ROOT}/nonexistent.json" >/dev/null 2>&1; rc=$?
  [[ $rc -eq 4 ]] || { bad "T1.4 配置不存在: 期望 4 实得 ${rc}"; ok=0; }

  printf 'not-json' > "${TMP_ROOT}/bad.json"
  "${HELPER_BIN}" --config "${TMP_ROOT}/bad.json" >/dev/null 2>&1; rc=$?
  [[ $rc -eq 4 ]] || { bad "T1.5 非法 JSON: 期望 4 实得 ${rc}"; ok=0; }

  printf '{"newAppPath":"/a"}' > "${TMP_ROOT}/short.json"
  "${HELPER_BIN}" --config "${TMP_ROOT}/short.json" >/dev/null 2>&1; rc=$?
  [[ $rc -eq 4 ]] || { bad "T1.6 缺字段: 期望 4 实得 ${rc}"; ok=0; }

  write_config "${TMP_ROOT}/rel.json" "relative/a" "/b" "/c" "/d" 123
  "${HELPER_BIN}" --config "${TMP_ROOT}/rel.json" >/dev/null 2>&1; rc=$?
  [[ $rc -eq 4 ]] || { bad "T1.7 相对路径: 期望 4 实得 ${rc}"; ok=0; }

  write_config "${TMP_ROOT}/pid0.json" "/a" "/b" "/c" "/d" 0
  "${HELPER_BIN}" --config "${TMP_ROOT}/pid0.json" >/dev/null 2>&1; rc=$?
  [[ $rc -eq 4 ]] || { bad "T1.8 pid 0（非法）: 期望 4 实得 ${rc}"; ok=0; }

  write_config "${TMP_ROOT}/pidneg.json" "/a" "/b" "/c" "/d" -5
  "${HELPER_BIN}" --config "${TMP_ROOT}/pidneg.json" >/dev/null 2>&1; rc=$?
  [[ $rc -eq 4 ]] || { bad "T1.9 pid 负数（非法）: 期望 4 实得 ${rc}"; ok=0; }

  printf '{"newAppPath":"/a","currentAppPath":"/b","backupPath":"/c","resultFilePath":"/d","pid":"abc"}' \
    > "${TMP_ROOT}/pidstr.json"
  "${HELPER_BIN}" --config "${TMP_ROOT}/pidstr.json" >/dev/null 2>&1; rc=$?
  [[ $rc -eq 4 ]] || { bad "T1.10 pid 非整数: 期望 4 实得 ${rc}"; ok=0; }

  if [[ $ok -eq 1 ]]; then ok; fi
}

# ---- T2 成功路径：等待→备份→替换→relaunch→写 result → exit 0 ----
run_success_test() {
  local d="${TMP_ROOT}/t2"
  mkdir -p "${d}/target" "${d}/new"
  make_mini_app "${d}/target/Coffer.app" old.marker t2old
  make_signed_new_app "${d}/new/Coffer.app" new.marker valid
  export COFFER_UPDATER_TEST_ANCHOR="${d}/target/Coffer.app"

  local pid
  pid="$(dead_pid)"
  write_config "${d}/config.json" "${d}/new/Coffer.app" "${d}/target/Coffer.app" \
      "${d}/backup/Coffer.app" "${d}/result.json" "${pid}"
  "${HELPER_BIN}" --config "${d}/config.json" >/dev/null 2>&1
  local rc=$? ok=1

  [[ $rc -eq 0 ]] || { bad "T2 成功路径: 期望 0 实得 ${rc}"; ok=0; }
  result_check "${d}/result.json" true 0 || { bad "T2 result 应为 success:true code:0"; ok=0; }
  [[ -f "${d}/target/Coffer.app/Contents/Resources/new.marker" ]] || { bad "T2 目标未含新包 marker"; ok=0; }
  [[ -f "${d}/backup/Coffer.app/Contents/Resources/old.marker" ]] || { bad "T2 备份未含旧包 marker"; ok=0; }
  [[ ! -e "${d}/new/Coffer.app" ]] || { bad "T2 新包源未移走"; ok=0; }

  if [[ $ok -eq 1 ]]; then ok; fi
}

# ---- T3 备份失败 → exit 1 + result code 1 + 目标未被改动 ----
run_backup_failure_test() {
  local d="${TMP_ROOT}/t3"
  mkdir -p "${d}/target" "${d}/new"
  make_mini_app "${d}/target/Coffer.app" old.marker t3old
  make_signed_new_app "${d}/new/Coffer.app" new.marker valid
  # backup 路径的父级是一个普通文件 → createDirectory/copyItem 必失败（ENOTDIR），与 uid 无关
  touch "${d}/blocker"
  export COFFER_UPDATER_TEST_ANCHOR="${d}/target/Coffer.app"

  local pid
  pid="$(dead_pid)"
  write_config "${d}/config.json" "${d}/new/Coffer.app" "${d}/target/Coffer.app" \
      "${d}/blocker/Coffer.app" "${d}/result.json" "${pid}"
  "${HELPER_BIN}" --config "${d}/config.json" >/dev/null 2>&1
  local rc=$? ok=1

  [[ $rc -eq 1 ]] || { bad "T3 备份失败: 期望 1 实得 ${rc}"; ok=0; }
  result_check "${d}/result.json" false 1 || { bad "T3 result 应为 success:false code:1"; ok=0; }
  [[ -f "${d}/target/Coffer.app/Contents/Resources/old.marker" ]] || { bad "T3 备份失败后目标被改动"; ok=0; }

  if [[ $ok -eq 1 ]]; then ok; fi
}

# ---- T4 替换失败 → exit 2 + result code 2 + 备份完整（备份先成功，替换阶段失败）----
run_replace_failure_test() {
  local d="${TMP_ROOT}/t4"
  mkdir -p "${d}/target" "${d}/new"
  make_mini_app "${d}/target/Coffer.app" old.marker t4old
  make_signed_new_app "${d}/new/Coffer.app" new.marker valid
  # target 父目录只读 → 移除/移动目标失败；备份在别处，先成功
  chmod 555 "${d}/target"
  export COFFER_UPDATER_TEST_ANCHOR="${d}/target/Coffer.app"

  local pid
  pid="$(dead_pid)"
  write_config "${d}/config.json" "${d}/new/Coffer.app" "${d}/target/Coffer.app" \
      "${d}/backup/Coffer.app" "${d}/result.json" "${pid}"
  "${HELPER_BIN}" --config "${d}/config.json" >/dev/null 2>&1
  local rc=$?
  chmod 755 "${d}/target"
  local ok=1

  [[ $rc -eq 2 ]] || { bad "T4 替换失败: 期望 2 实得 ${rc}"; ok=0; }
  result_check "${d}/result.json" false 2 || { bad "T4 result 应为 success:false code:2"; ok=0; }
  [[ -f "${d}/backup/Coffer.app/Contents/Resources/old.marker" ]] || { bad "T4 备份未保留旧包"; ok=0; }

  if [[ $ok -eq 1 ]]; then ok; fi
}

# ---- T5 relaunch 失败 → exit 3 + result code 3 ----
# 新包签名 + profile 均有效（通过 C-1/H-1 门），仅可执行文件 chmod -x 使 open 无法启动
# （launchd spawn 失败）→ 替换成功后 relaunch 阶段失败 → exit 3。
run_relaunch_failure_test() {
  local d="${TMP_ROOT}/t5"
  mkdir -p "${d}/target" "${d}/new"
  make_mini_app "${d}/target/Coffer.app" old.marker t5old
  make_signed_new_app "${d}/new/Coffer.app" new.marker valid
  chmod -x "${d}/new/Coffer.app/Contents/MacOS/hello"
  export COFFER_UPDATER_TEST_ANCHOR="${d}/target/Coffer.app"

  local pid
  pid="$(dead_pid)"
  write_config "${d}/config.json" "${d}/new/Coffer.app" "${d}/target/Coffer.app" \
      "${d}/backup/Coffer.app" "${d}/result.json" "${pid}"
  "${HELPER_BIN}" --config "${d}/config.json" >/dev/null 2>&1
  local rc=$? ok=1

  [[ $rc -eq 3 ]] || { bad "T5 relaunch 失败: 期望 3 实得 ${rc}"; ok=0; }
  result_check "${d}/result.json" false 3 || { bad "T5 result 应为 success:false code:3"; ok=0; }

  if [[ $ok -eq 1 ]]; then ok; fi
}

# ---- T6 current 缺失前置校验 → exit 1 + result code 1 ----
run_current_missing_test() {
  local d="${TMP_ROOT}/t6"
  mkdir -p "${d}/new"
  make_signed_new_app "${d}/new/Coffer.app" new.marker valid
  export COFFER_UPDATER_TEST_ANCHOR="${d}/missing/Coffer.app"

  local pid
  pid="$(dead_pid)"
  write_config "${d}/config.json" "${d}/new/Coffer.app" "${d}/missing/Coffer.app" \
      "${d}/backup/Coffer.app" "${d}/result.json" "${pid}"
  "${HELPER_BIN}" --config "${d}/config.json" >/dev/null 2>&1
  local rc=$? ok=1

  [[ $rc -eq 1 ]] || { bad "T6 current 缺失: 期望 1 实得 ${rc}"; ok=0; }
  result_check "${d}/result.json" false 1 || { bad "T6 result 应为 success:false code:1"; ok=0; }

  if [[ $ok -eq 1 ]]; then ok; fi
}

# ---- T7 newApp 缺失前置校验 → exit 2 + result code 2 + 目标未被改动 ----
run_newapp_missing_test() {
  local d="${TMP_ROOT}/t7"
  mkdir -p "${d}/target"
  make_mini_app "${d}/target/Coffer.app" old.marker t7old
  export COFFER_UPDATER_TEST_ANCHOR="${d}/target/Coffer.app"

  local pid
  pid="$(dead_pid)"
  write_config "${d}/config.json" "${d}/missing/Coffer.app" "${d}/target/Coffer.app" \
      "${d}/backup/Coffer.app" "${d}/result.json" "${pid}"
  "${HELPER_BIN}" --config "${d}/config.json" >/dev/null 2>&1
  local rc=$? ok=1

  [[ $rc -eq 2 ]] || { bad "T7 newApp 缺失: 期望 2 实得 ${rc}"; ok=0; }
  result_check "${d}/result.json" false 2 || { bad "T7 result 应为 success:false code:2"; ok=0; }
  [[ -f "${d}/target/Coffer.app/Contents/Resources/old.marker" ]] || { bad "T7 newApp 缺失时目标被改动"; ok=0; }

  if [[ $ok -eq 1 ]]; then ok; fi
}

# ---- T8 等待 App 退出超时 → exit 3 + result code 3 + 未做任何修改 ----
# waitTimeout 在 helper 内硬编码 30s（不可注入），故本测试耗时 ~31s：默认跳过，
# 显式设 RUN_SLOW_HELPER_TEST=1 才执行（真机/手动慢回归用）。
run_timeout_test() {
  if [[ -z "${RUN_SLOW_HELPER_TEST:-}" ]]; then
    log "NOTE: 跳过 T8 等待超时慢测试（waitTimeout=30s，约耗时 31s；设 RUN_SLOW_HELPER_TEST=1 启用）"
    return 0
  fi
  local d="${TMP_ROOT}/t8"
  mkdir -p "${d}/target" "${d}/new"
  make_mini_app "${d}/target/Coffer.app" old.marker t8old
  make_signed_new_app "${d}/new/Coffer.app" new.marker valid
  export COFFER_UPDATER_TEST_ANCHOR="${d}/target/Coffer.app"
  sleep 60 &
  local live_pid=$!
  write_config "${d}/config.json" "${d}/new/Coffer.app" "${d}/target/Coffer.app" \
      "${d}/backup/Coffer.app" "${d}/result.json" "${live_pid}"
  "${HELPER_BIN}" --config "${d}/config.json" >/dev/null 2>&1
  local rc=$? ok=1
  kill "${live_pid}" 2>/dev/null

  [[ $rc -eq 3 ]] || { bad "T8 等待超时: 期望 3 实得 ${rc}"; ok=0; }
  result_check "${d}/result.json" false 3 || { bad "T8 result 应为 success:false code:3"; ok=0; }
  [[ -f "${d}/target/Coffer.app/Contents/Resources/old.marker" ]] || { bad "T8 超时后目标被改动"; ok=0; }
  [[ ! -e "${d}/backup/Coffer.app" ]] || { bad "T8 超时应未做备份"; ok=0; }

  if [[ $ok -eq 1 ]]; then ok; fi
}

# ---- T9 currentAppPath≠锚 → exit 4 + 零副作用（目标/备份/result 均未动）----
run_anchor_mismatch_test() {
  local d="${TMP_ROOT}/t9"
  mkdir -p "${d}/target" "${d}/new"
  make_mini_app "${d}/target/Coffer.app" old.marker t9old
  make_signed_new_app "${d}/new/Coffer.app" new.marker valid
  # 锚指向 target，配置里 currentAppPath 指向另一路径 → 锚定校验失败
  export COFFER_UPDATER_TEST_ANCHOR="${d}/target/Coffer.app"

  local pid
  pid="$(dead_pid)"
  write_config "${d}/config.json" "${d}/new/Coffer.app" "${d}/wrong/Coffer.app" \
      "${d}/backup/Coffer.app" "${d}/result.json" "${pid}"
  "${HELPER_BIN}" --config "${d}/config.json" >/dev/null 2>&1
  local rc=$? ok=1

  [[ $rc -eq 4 ]] || { bad "T9 锚定不符: 期望 4 实得 ${rc}"; ok=0; }
  [[ -f "${d}/target/Coffer.app/Contents/Resources/old.marker" ]] || { bad "T9 锚定不符后目标被改动"; ok=0; }
  [[ ! -e "${d}/backup/Coffer.app" ]] || { bad "T9 锚定不符后产生备份"; ok=0; }
  [[ ! -e "${d}/result.json" ]] || { bad "T9 锚定不符后写 result"; ok=0; }

  if [[ $ok -eq 1 ]]; then ok; fi
}

# ---- T10 newApp 文件名非 Coffer.app → exit 2（拒装，零副作用）----
run_basename_test() {
  local d="${TMP_ROOT}/t10"
  mkdir -p "${d}/target" "${d}/new"
  make_mini_app "${d}/target/Coffer.app" old.marker t10old
  make_mini_app "${d}/new/Other.app" other.marker t10other
  export COFFER_UPDATER_TEST_ANCHOR="${d}/target/Coffer.app"

  local pid
  pid="$(dead_pid)"
  write_config "${d}/config.json" "${d}/new/Other.app" "${d}/target/Coffer.app" \
      "${d}/backup/Coffer.app" "${d}/result.json" "${pid}"
  "${HELPER_BIN}" --config "${d}/config.json" >/dev/null 2>&1
  local rc=$? ok=1

  [[ $rc -eq 2 ]] || { bad "T10 文件名不符: 期望 2 实得 ${rc}"; ok=0; }
  result_check "${d}/result.json" false 2 || { bad "T10 result 应为 success:false code:2"; ok=0; }
  [[ -f "${d}/target/Coffer.app/Contents/Resources/old.marker" ]] || { bad "T10 拒装后目标被改动"; ok=0; }

  if [[ $ok -eq 1 ]]; then ok; fi
}

# ---- T11 newApp 未签名（DR 验签失败）→ exit 2 + result code 2 ----
run_unsigned_payload_test() {
  local d="${TMP_ROOT}/t11"
  mkdir -p "${d}/target" "${d}/new"
  make_mini_app "${d}/target/Coffer.app" old.marker t11old
  make_mini_app "${d}/new/Coffer.app" unsigned.marker t11new
  export COFFER_UPDATER_TEST_ANCHOR="${d}/target/Coffer.app"

  local pid
  pid="$(dead_pid)"
  write_config "${d}/config.json" "${d}/new/Coffer.app" "${d}/target/Coffer.app" \
      "${d}/backup/Coffer.app" "${d}/result.json" "${pid}"
  "${HELPER_BIN}" --config "${d}/config.json" >/dev/null 2>&1
  local rc=$? ok=1

  [[ $rc -eq 2 ]] || { bad "T11 未签名载荷: 期望 2 实得 ${rc}"; ok=0; }
  result_check "${d}/result.json" false 2 || { bad "T11 result 应为 success:false code:2"; ok=0; }
  [[ -f "${d}/target/Coffer.app/Contents/Resources/old.marker" ]] || { bad "T11 拒装后目标被改动"; ok=0; }

  if [[ $ok -eq 1 ]]; then ok; fi
}

# ---- T12 newApp profile 过期 / 缺失 → exit 2 + result code 2（fail-closed）----
run_profile_expired_test() {
  local d="${TMP_ROOT}/t12"
  mkdir -p "${d}/target" "${d}/new"
  make_mini_app "${d}/target/Coffer.app" old.marker t12old
  export COFFER_UPDATER_TEST_ANCHOR="${d}/target/Coffer.app"
  local pid rc ok=1

  # T12a 过期 profile（签名有效、DR 通过，仅 profile 过期被拒）
  make_signed_new_app "${d}/new/Coffer.app" exp.marker expired
  pid="$(dead_pid)"
  write_config "${d}/config.json" "${d}/new/Coffer.app" "${d}/target/Coffer.app" \
      "${d}/backup/Coffer.app" "${d}/result.json" "${pid}"
  "${HELPER_BIN}" --config "${d}/config.json" >/dev/null 2>&1; rc=$?
  [[ $rc -eq 2 ]] || { bad "T12a profile 过期: 期望 2 实得 ${rc}"; ok=0; }
  result_check "${d}/result.json" false 2 || { bad "T12a result 应为 success:false code:2"; ok=0; }

  # T12b 缺失 profile（签名有效但无 embedded.provisionprofile → fail-closed）
  make_signed_new_app "${d}/new2/Coffer.app" noprofile.marker noprofile
  pid="$(dead_pid)"
  write_config "${d}/config2.json" "${d}/new2/Coffer.app" "${d}/target/Coffer.app" \
      "${d}/backup/Coffer.app" "${d}/result2.json" "${pid}"
  "${HELPER_BIN}" --config "${d}/config2.json" >/dev/null 2>&1; rc=$?
  [[ $rc -eq 2 ]] || { bad "T12b profile 缺失: 期望 2 实得 ${rc}"; ok=0; }
  result_check "${d}/result2.json" false 2 || { bad "T12b result 应为 success:false code:2"; ok=0; }

  [[ -f "${d}/target/Coffer.app/Contents/Resources/old.marker" ]] || { bad "T12 拒装后目标被改动"; ok=0; }

  if [[ $ok -eq 1 ]]; then ok; fi
}

# ---- T14 TOCTOU 闭环：等待窗内换包 → 已安装结果验签失败 → exit 2 + 目标恢复为备份 ----
# 模拟 C-1 复审攻击路径：newApp 为合法签名 Coffer.app（过前置验签），pid 填长驻进程；
# helper 越过前置验签进入 30s 等待窗后，测试把 newApp 可执行文件篡改（破坏签名封存）
# 再 kill pid → helper 替换后对已安装目标再验签（verifyInstalledResult）→ 失败 →
# exit 2 + forceRestore 恢复备份。成功路径（已安装结果验签通过）由 T2 覆盖（T2 现在
# 替换后也走 verifyInstalledResult 再 relaunch）。
run_toctou_swap_test() {
  local d="${TMP_ROOT}/t14"
  mkdir -p "${d}/target" "${d}/new"
  make_mini_app "${d}/target/Coffer.app" old.marker t14old
  make_signed_new_app "${d}/new/Coffer.app" new.marker valid
  export COFFER_UPDATER_TEST_ANCHOR="${d}/target/Coffer.app"

  sleep 60 &
  local live_pid=$!
  write_config "${d}/config.json" "${d}/new/Coffer.app" "${d}/target/Coffer.app" \
      "${d}/backup/Coffer.app" "${d}/result.json" "${live_pid}"
  "${HELPER_BIN}" --config "${d}/config.json" >/dev/null 2>&1 &
  local helper_pid=$!

  # 前置验签亚秒级、等待窗 30s：sleep 3 后 helper 必已进入等待窗，此时换包 + kill pid。
  # （极端情况下换包早于前置验签，仍退化为前置拒装 exit 2，观测断言同样成立。）
  sleep 3
  printf 'tampered' > "${d}/new/Coffer.app/Contents/MacOS/hello"
  kill "${live_pid}" 2>/dev/null

  wait "${helper_pid}"
  local rc=$? ok=1
  kill "${live_pid}" 2>/dev/null

  [[ $rc -eq 2 ]] || { bad "T14 TOCTOU 换包: 期望 2 实得 ${rc}"; ok=0; }
  result_check "${d}/result.json" false 2 || { bad "T14 result 应为 success:false code:2"; ok=0; }
  # 已安装结果验签失败 → forceRestore：目标恢复为备份内容（旧包 marker，新包 marker 不在）
  [[ -f "${d}/target/Coffer.app/Contents/Resources/old.marker" ]] || { bad "T14 目标未恢复为旧包内容"; ok=0; }
  [[ ! -f "${d}/target/Coffer.app/Contents/Resources/new.marker" ]] || { bad "T14 目标仍含新包 marker（未恢复）"; ok=0; }

  if [[ $ok -eq 1 ]]; then ok; fi
}

# ---- T15 C-2 relaunch gate：等待窗换包 + backup 父目录翻转为 symlink → gate 拦截 relaunch ----
# 覆盖 C-2 收敛不变式：任何被 relaunch 的包必须刚通过 DR。等待窗内换包（T14 机制）触发
# step5.5 验签失败 → forceRestore 从 backup 恢复（内容未验）；恢复后 rollback 尝试 relaunch
# 目标时，relaunchApp 的 C-2 gate 必须先验签——未过 DR 绝不启动。用 fake-relaunch 桩
# （COFFER_UPDATER_TEST_FAKE_RELAUNCH=<记录文件>）断言：gate 拦截后桩从未被调用。
# backup 父目录在启动时是普通目录（过 validateConfig 的 symlink 检查），等待窗内翻转为
# symlink——模拟残余竞速（备份解析路径中途变化）；无论 forceRestore 读到什么，gate 兜底。
run_gate_relaunch_test() {
  local d="${TMP_ROOT}/t15"
  mkdir -p "${d}/target" "${d}/new" "${d}/backup" "${d}/real2"
  make_mini_app "${d}/target/Coffer.app" old.marker t15old
  make_signed_new_app "${d}/new/Coffer.app" new.marker valid
  export COFFER_UPDATER_TEST_ANCHOR="${d}/target/Coffer.app"
  export COFFER_UPDATER_TEST_FAKE_RELAUNCH="${d}/relaunch.log"

  sleep 60 &
  local live_pid=$!
  write_config "${d}/config.json" "${d}/new/Coffer.app" "${d}/target/Coffer.app" \
      "${d}/backup/Coffer.app" "${d}/result.json" "${live_pid}"
  "${HELPER_BIN}" --config "${d}/config.json" >/dev/null 2>&1 &
  local helper_pid=$!

  sleep 3
  # 等待窗：换包（T14 机制）+ backup 父目录翻转为 symlink（残余竞速模拟）
  printf 'tampered' > "${d}/new/Coffer.app/Contents/MacOS/hello"
  rm -rf "${d}/backup"
  ln -s "${d}/real2" "${d}/backup"
  kill "${live_pid}" 2>/dev/null

  wait "${helper_pid}"
  local rc=$? ok=1
  kill "${live_pid}" 2>/dev/null

  [[ $rc -eq 2 ]] || { bad "T15 C-2 gate: 期望 2 实得 ${rc}"; ok=0; }
  result_check "${d}/result.json" false 2 || { bad "T15 result 应为 success:false code:2"; ok=0; }
  # 不变式：gate 拦截后任何 relaunch 桩都未被调用（fake-relaunch 记录文件不存在）
  [[ ! -e "${d}/relaunch.log" ]] || { bad "T15 未验内容被 relaunch（gate 未拦截）"; ok=0; }
  # 目标恢复为备份内容（旧包 marker 在、新包 marker 不在）
  [[ -f "${d}/target/Coffer.app/Contents/Resources/old.marker" ]] || { bad "T15 目标未恢复为旧包内容"; ok=0; }
  [[ ! -f "${d}/target/Coffer.app/Contents/Resources/new.marker" ]] || { bad "T15 目标仍含新包 marker（未恢复）"; ok=0; }

  if [[ $ok -eq 1 ]]; then ok; fi
}

# ---- T16 backupPath 含 symlink 分量 → exit 4（零修改）----
# C-2 加固：备份/新包/result 任一含符号链接分量 → 配置非法，未做任何修改。
run_symlink_backup_test() {
  local d="${TMP_ROOT}/t16"
  mkdir -p "${d}/target" "${d}/new" "${d}/real"
  make_mini_app "${d}/target/Coffer.app" old.marker t16old
  make_signed_new_app "${d}/new/Coffer.app" new.marker valid
  ln -s "${d}/real" "${d}/link"
  export COFFER_UPDATER_TEST_ANCHOR="${d}/target/Coffer.app"

  local pid
  pid="$(dead_pid)"
  write_config "${d}/config.json" "${d}/new/Coffer.app" "${d}/target/Coffer.app" \
      "${d}/link/Coffer.app" "${d}/result.json" "${pid}"
  "${HELPER_BIN}" --config "${d}/config.json" >/dev/null 2>&1
  local rc=$? ok=1

  [[ $rc -eq 4 ]] || { bad "T16 backupPath symlink 分量: 期望 4 实得 ${rc}"; ok=0; }
  [[ -f "${d}/target/Coffer.app/Contents/Resources/old.marker" ]] || { bad "T16 目标被改动"; ok=0; }
  [[ ! -e "${d}/real/Coffer.app" ]] || { bad "T16 经链接写入了备份"; ok=0; }
  [[ ! -e "${d}/result.json" ]] || { bad "T16 写了 result"; ok=0; }

  if [[ $ok -eq 1 ]]; then ok; fi
}

# ---- T17 backupPath == currentAppPath → exit 4（零修改）----
# C-2 加固：backup==current 会让 backupCurrentApp 先 removeItem 删掉目标本体再失败回滚
# （MEDIUM DoS）；配置校验阶段直接拒绝，目标不被触碰。
run_backup_equals_current_test() {
  local d="${TMP_ROOT}/t17"
  mkdir -p "${d}/target" "${d}/new"
  make_mini_app "${d}/target/Coffer.app" old.marker t17old
  make_signed_new_app "${d}/new/Coffer.app" new.marker valid
  export COFFER_UPDATER_TEST_ANCHOR="${d}/target/Coffer.app"

  local pid
  pid="$(dead_pid)"
  write_config "${d}/config.json" "${d}/new/Coffer.app" "${d}/target/Coffer.app" \
      "${d}/target/Coffer.app" "${d}/result.json" "${pid}"
  "${HELPER_BIN}" --config "${d}/config.json" >/dev/null 2>&1
  local rc=$? ok=1

  [[ $rc -eq 4 ]] || { bad "T17 backup==current: 期望 4 实得 ${rc}"; ok=0; }
  [[ -f "${d}/target/Coffer.app/Contents/Resources/old.marker" ]] || { bad "T17 目标被改动（绝不可先删目标本体）"; ok=0; }
  [[ ! -e "${d}/result.json" ]] || { bad "T17 写了 result"; ok=0; }

  if [[ $ok -eq 1 ]]; then ok; fi
}

# ---- T18 newAppPath == currentAppPath（含 "../" 规范化等价）→ exit 4（零修改）----
# C-2 收尾：new==current 无合法场景（replace 先删 current 再 move 源已删，回滚混乱），
# 与 backup==current/new 一并拒绝；相等判定用规范化路径（".."/重复斜杠归并后判等，
# 防 "../Coffer.app" 等等价路径绕过）。
run_newapp_equals_current_test() {
  local d="${TMP_ROOT}/t18"
  mkdir -p "${d}/target" "${d}/new"
  make_mini_app "${d}/target/Coffer.app" old.marker t18old
  export COFFER_UPDATER_TEST_ANCHOR="${d}/target/Coffer.app"
  local pid rc ok=1

  # T18a 字面相等：newAppPath == currentAppPath
  pid="$(dead_pid)"
  write_config "${d}/config.json" "${d}/target/Coffer.app" "${d}/target/Coffer.app" \
      "${d}/backup/Coffer.app" "${d}/result.json" "${pid}"
  "${HELPER_BIN}" --config "${d}/config.json" >/dev/null 2>&1; rc=$?
  [[ $rc -eq 4 ]] || { bad "T18a new==current（字面）: 期望 4 实得 ${rc}"; ok=0; }
  [[ -f "${d}/target/Coffer.app/Contents/Resources/old.marker" ]] || { bad "T18a 目标被改动"; ok=0; }
  [[ ! -e "${d}/result.json" ]] || { bad "T18a 写了 result"; ok=0; }

  # T18b 规范化等价：newAppPath = "${d}/new/../target/Coffer.app"（标准化后与 target 同路径）
  pid="$(dead_pid)"
  write_config "${d}/config2.json" "${d}/new/../target/Coffer.app" "${d}/target/Coffer.app" \
      "${d}/backup/Coffer.app" "${d}/result2.json" "${pid}"
  "${HELPER_BIN}" --config "${d}/config2.json" >/dev/null 2>&1; rc=$?
  [[ $rc -eq 4 ]] || { bad "T18b new==current（../ 规范化等价）: 期望 4 实得 ${rc}"; ok=0; }
  [[ -f "${d}/target/Coffer.app/Contents/Resources/old.marker" ]] || { bad "T18b 目标被改动"; ok=0; }
  [[ ! -e "${d}/result2.json" ]] || { bad "T18b 写了 result"; ok=0; }

  if [[ $ok -eq 1 ]]; then ok; fi
}

# ---- T19 backupPath 为 currentAppPath 的 case 变体 → exit 4（零修改）----
# M-A（第 4 轮 MEDIUM 闭环）：APFS 默认卷大小写不敏感（/var/folders 实测，Coffer.App
# 与 Coffer.app 为同一目录项），backupPath 用目录 case 变体（TARGET/ vs target/）可与
# current 解析为同一目录——大小写敏感字符串判等可被绕过：backupCurrentApp 的 removeItem
# 会先删掉运行中 App 本体，再因源缺失复制失败，无备份可恢复（需管理员写权，不构成提权，
# 防御纵深补齐）。判等两侧小写化后 case 变体同样 exit 4 零修改。
run_backup_casevariant_test() {
  local d="${TMP_ROOT}/t19"
  mkdir -p "${d}/target" "${d}/new"
  make_mini_app "${d}/target/Coffer.app" old.marker t19old
  make_signed_new_app "${d}/new/Coffer.app" new.marker valid
  export COFFER_UPDATER_TEST_ANCHOR="${d}/target/Coffer.app"

  local pid
  pid="$(dead_pid)"
  # backupPath 父目录用 case 变体（TARGET/ == target/，本卷大小写不敏感）
  write_config "${d}/config.json" "${d}/new/Coffer.app" "${d}/target/Coffer.app" \
      "${d}/TARGET/Coffer.app" "${d}/result.json" "${pid}"
  "${HELPER_BIN}" --config "${d}/config.json" >/dev/null 2>&1
  local rc=$? ok=1

  [[ $rc -eq 4 ]] || { bad "T19 backup case 变体: 期望 4 实得 ${rc}"; ok=0; }
  [[ -f "${d}/target/Coffer.app/Contents/Resources/old.marker" ]] || { bad "T19 目标被改动（case 变体绕判等删本体）"; ok=0; }
  [[ ! -e "${d}/result.json" ]] || { bad "T19 写了 result"; ok=0; }

  if [[ $ok -eq 1 ]]; then ok; fi
}

# ---- T13 relaunch 失败（exit 3）后已尽力恢复：目标恢复为备份内容 ----
run_relaunch_fail_rollback_test() {
  local d="${TMP_ROOT}/t13"
  mkdir -p "${d}/target" "${d}/new"
  make_mini_app "${d}/target/Coffer.app" old.marker t13old
  make_signed_new_app "${d}/new/Coffer.app" new.marker valid
  chmod -x "${d}/new/Coffer.app/Contents/MacOS/hello"
  export COFFER_UPDATER_TEST_ANCHOR="${d}/target/Coffer.app"

  local pid
  pid="$(dead_pid)"
  write_config "${d}/config.json" "${d}/new/Coffer.app" "${d}/target/Coffer.app" \
      "${d}/backup/Coffer.app" "${d}/result.json" "${pid}"
  "${HELPER_BIN}" --config "${d}/config.json" >/dev/null 2>&1
  local rc=$? ok=1

  [[ $rc -eq 3 ]] || { bad "T13 relaunch 失败: 期望 3 实得 ${rc}"; ok=0; }
  result_check "${d}/result.json" false 3 || { bad "T13 result 应为 success:false code:3"; ok=0; }
  # M-1：已尽力恢复——目标恢复为备份内容（旧包 marker，新包 marker 不在）
  [[ -f "${d}/target/Coffer.app/Contents/Resources/old.marker" ]] || { bad "T13 目标未恢复为旧包内容"; ok=0; }
  [[ ! -f "${d}/target/Coffer.app/Contents/Resources/new.marker" ]] || { bad "T13 目标仍含新包 marker（未恢复）"; ok=0; }

  if [[ $ok -eq 1 ]]; then ok; fi
}

# ---- 主流程 ----
compile_helper
log "编译完成: ${HELPER_BIN}"

run_usage_tests
run_success_test
run_backup_failure_test
if [[ "$(id -u)" -eq 0 ]]; then
  log "NOTE: 当前为 root，跳过权限触发的替换失败测试（T4）。"
else
  run_replace_failure_test
fi
run_relaunch_failure_test
run_current_missing_test
run_newapp_missing_test
run_anchor_mismatch_test
run_basename_test
run_unsigned_payload_test
run_profile_expired_test
run_relaunch_fail_rollback_test
run_toctou_swap_test
run_gate_relaunch_test
run_symlink_backup_test
run_backup_equals_current_test
run_newapp_equals_current_test
run_backup_casevariant_test
run_timeout_test

log ""
log "install helper 测试: PASS=${PASS} FAIL=${FAIL}"
if [[ ${FAIL} -gt 0 ]]; then
  log "RESULT: FAIL" >&2
  exit 1
fi
log "RESULT: PASS"
exit 0
