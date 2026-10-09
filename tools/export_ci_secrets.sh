#!/bin/bash
# export_ci_secrets.sh —— 导出本机签名证书与 provisioning profile，供
# GitHub Actions（.github/workflows/release.yml）tag v* 自动构建签名使用。
#
# 用法:
#   ./tools/export_ci_secrets.sh            # 只导出并打印 gh secret set 命令
#   ./tools/export_ci_secrets.sh --push     # 导出并直接 gh secret set（需已 gh auth login）
#
# 前置:
#   1) Xcode → Settings → Accounts 已登录 Apple ID（Apple Development 证书
#      在 login keychain 中，build_macos_app.sh 方案 A 同源，BUG-2 纪律）；
#   2) 已跑过 ./tools/make_provisioning_profile.sh 生成
#      macos/build/app.coffer.Coffer.provisionprofile（免费账号 7 天有效）。
#
# 输出: /tmp/coffer-ci-secrets/
#   coffer_ci_cert.p12    —— 证书+私钥（导出密码 = CI 的 APPLE_CERT_PASSWORD）
#   cert.p12.b64          —— 上者的 base64（单行）
#   profile.b64           —— provisioning profile 的 base64（单行）
#
# 每次 profile 过期（7 天）只需重跑本脚本刷新 APPLE_PROVISIONING_PROFILE_BASE64。

set -euo pipefail
cd "$(dirname "$0")/.."

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

PROFILE="macos/build/app.coffer.Coffer.provisionprofile"
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
echo "==> 在 GitHub 仓库 Settings → Secrets and variables → Actions 设置以下三个 secret："
echo "    （也可直接执行下方 gh secret set 命令）"
cat <<CMDS
gh secret set APPLE_CERT_P12_BASE64 < "$OUT/cert.p12.b64"
gh secret set APPLE_CERT_PASSWORD --body '<上面设置的 p12 导出密码>'
gh secret set APPLE_PROVISIONING_PROFILE_BASE64 < "$OUT/profile.b64"
CMDS

if [ "${1:-}" = "--push" ]; then
  echo
  echo "==> 执行 gh secret set（需 gh 已登录且有仓库写权限）"
  gh secret set APPLE_CERT_P12_BASE64 < "$OUT/cert.p12.b64"
  gh secret set APPLE_CERT_PASSWORD --body "$P12_PASS"
  gh secret set APPLE_PROVISIONING_PROFILE_BASE64 < "$OUT/profile.b64"
  echo "==> 三个 secret 已设置。打 tag（git tag vX.Y.Z && git push origin vX.Y.Z）即触发 release 流水线。"
else
  echo
  echo "==> 未执行（默认只打印）。确认无误后加 --push 自动设置。"
fi
