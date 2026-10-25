#!/bin/bash
# export_ci_secrets_gitlab.sh —— 导出本机签名证书与 provisioning profile，
# 写入 GitLab CI/CD variables（内网 GitLab 主线 coffer），供 .gitlab-ci.yml
# release job（tag v*）自动构建签名使用。
#
# 用法:
#   ./tools/export_ci_secrets_gitlab.sh            # 只导出并打印 glab 写入命令
#   ./tools/export_ci_secrets_gitlab.sh --push     # 导出并直接写 GitLab variables
#
# 前置:
#   1) Xcode → Settings → Accounts 已登录 Apple ID（Apple Development 证书
#      在 login keychain 中，build_macos_app.sh 方案 A 同源，BUG-2 纪律）；
#   2) 已跑过 ./tools/make_provisioning_profile.sh 生成
#      macos/build/top.cygnusyang.coffer.provisionprofile（免费账号 7 天有效）；
#   3) glab 已登录（token 在 macOS 钥匙串）；
#   4) ⚠️ security export 首次访问私钥会触发钥匙串 ACL 弹窗，须本人在场点
#      「始终允许」——2026-10-11 实证：用户不在场时 export 挂起。
#
# 写入的 variables（protected=true；UPDATE_SIGNING_KEY_BASE64 / RELEASE_TOKEN
# 已另行手工设置，本脚本不覆盖）:
#   APPLE_CERT_P12_BASE64 / APPLE_CERT_PASSWORD / APPLE_PROVISIONING_PROFILE_BASE64
#
# 每次 profile 过期（7 天）只需重跑本脚本 --push 刷新 profile 变量。
# 默认目标仓 cygnusyang/coffer（内网 GitLab），可用 GITLAB_PROJECT 覆盖。

set -euo pipefail
cd "$(dirname "$0")/.."

PROJECT="${GITLAB_PROJECT:-cygnusyang/coffer}"
OUT=/tmp/coffer-ci-secrets
mkdir -p "$OUT"

echo "==> 定位 Apple Development 签名身份"
IDENTITY=$(security find-identity -v -p codesigning \
  | awk -F'"' '/Apple Development/{print $2; exit}')
if [ -z "$IDENTITY" ]; then
  echo "!! 未找到 Apple Development 证书。请先在 Xcode → Settings → Accounts 登录 Apple ID 生成证书。" >&2
  exit 1
fi
echo "    身份: ${IDENTITY}"

KC=$(security default-keychain)
# 坑（2026-10-09 实测）：security default-keychain 输出带 4 个前导空格 +
# 尾部双引号，只剥引号不剥空白 → -k 指向带空格路径，export 报
# "SecKeychainItemExport: The specified item could not be found"。须剥净。
KC=$(printf '%s' "$KC" | tr -d '"' | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')
echo "    默认 keychain: ${KC}"

echo "==> 导出证书+私钥为 p12（将提示两次密码：keychain 解锁 + 新导出密码）"
echo "    ⚠️ 若触发钥匙串 ACL 弹窗，请点「始终允许」（首次导出必现）。"
read -r -s -p "    为导出 p12 设置密码（将作为 CI 的 APPLE_CERT_PASSWORD）: " P12_PASS
echo
if [ -z "$P12_PASS" ]; then
  echo "!! p12 密码不能为空。" >&2
  exit 1
fi
read -r -s -p "    再输一次确认: " P12_PASS2
echo
[ "$P12_PASS" = "$P12_PASS2" ] || { echo "!! 两次输入不一致。" >&2; exit 1; }

rm -f "$OUT/coffer_ci_cert.p12"
if ! security export -k "$KC" -t identities -f pkcs12 -P "$P12_PASS" \
  -o "$OUT/coffer_ci_cert.p12" 2>"$OUT/export.err"; then
  echo "!! security export 失败：$(cat "$OUT/export.err")" >&2
  echo "   提示：确认 keychain 已解锁（security unlock-keychain -p 密码 \"$KC\"），再重跑本脚本。" >&2
  rm -f "$OUT/export.err"
  exit 1
fi
rm -f "$OUT/export.err"
[ -s "$OUT/coffer_ci_cert.p12" ] || { echo "!! 导出的 p12 为空。" >&2; exit 1; }
echo "    已导出: $OUT/coffer_ci_cert.p12"

PROFILE="macos/build/top.cygnusyang.coffer.provisionprofile"
if [ ! -f "$PROFILE" ]; then
  echo "!! 缺少 ${PROFILE}（先跑 ./tools/make_provisioning_profile.sh）。" >&2
  exit 1
fi
echo "==> provisioning profile: ${PROFILE}"

base64 -i "$OUT/coffer_ci_cert.p12" | tr -d '\n' > "$OUT/cert.p12.b64"
base64 -i "$PROFILE" | tr -d '\n' > "$OUT/profile.b64"

CERT_N=$(wc -c < "$OUT/cert.p12.b64")
PROF_N=$(wc -c < "$OUT/profile.b64")
echo
echo "==> 已生成（${OUT}）:"
ls -lh "$OUT" | awk 'NR>1{print "    " $5 "  " $9}'
[ "$CERT_N" -ge 500 ] || { echo "!! p12 base64 过短（${CERT_N} 字符），导出可能不完整。" >&2; exit 1; }
[ "$PROF_N" -ge 1000 ] || { echo "!! profile base64 过短（${PROF_N} 字符）。" >&2; exit 1; }

echo
echo "==> 将写入 GitLab 项目 ${PROJECT} 的 CI/CD variables（protected=true）："
echo "    APPLE_CERT_P12_BASE64 / APPLE_CERT_PASSWORD（masked） / APPLE_PROVISIONING_PROFILE_BASE64"
echo "    （UPDATE_SIGNING_KEY_BASE64 / RELEASE_TOKEN 已另行手工设置，本脚本不覆盖）"

if [ "${1:-}" = "--push" ]; then
  echo "==> 执行 glab variable set（需 glab 已登录且有项目维护者权限）"
  glab variable set APPLE_CERT_P12_BASE64 --repo "$PROJECT" --protected < "$OUT/cert.p12.b64"
  printf '%s' "$P12_PASS" | glab variable set APPLE_CERT_PASSWORD --repo "$PROJECT" --protected --masked
  glab variable set APPLE_PROVISIONING_PROFILE_BASE64 --repo "$PROJECT" --protected < "$OUT/profile.b64"
  echo "==> 三个 variables 已写入。打 tag（git tag vX.Y.Z && git push）即触发 GitLab release 流水线。"
else
  echo
  echo "==> 未执行（默认只导出）。确认无误后加 --push 自动写入 GitLab variables。"
fi
