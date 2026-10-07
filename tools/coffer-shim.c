/*
 * tools/coffer-shim.c —— browser native messaging host shim（v2.3.0 G-E，docs/31 §2.1 D-2）
 *
 * 背景（docs/31 L289 + P-S spike ③）：native messaging manifest 的 `path` 不能传参，
 * Chrome 拉起时把扩展 origin 作为 argv[1] 注入。故 manifest `path` 指向本 shim，
 * 由其补上 `browser-agent` 子命令并 exec 真正的 coffer 二进制——exec 保持 PID 与
 * 父进程链（host 验父进程 = 浏览器仍成立，auth 层 ② 端点，P-S 实证 shim.pid == host.pid
 * 且 parent == Chrome 主进程），从而规避「manifest 不能传参」。
 *
 * 纪律（docs/31 L295 + lead 裁定 2026-10-08）：shim **无受限 entitlement**（AMFI 门禁
 * 不适用），与 coffer 同身份签名。装配在 tools/build_macos_app.sh step 3.5。
 *
 * argv 策略（P-S 交叉发现 #2 + G-B parse_agent_args 只认 --log）：
 *   浏览器把 origin（chrome-extension://… / moz-extension://…）作为 argv[1] 注入，
 *   而 coffer browser-agent 的 parse_agent_args（core/cf-mcp/src/cli.rs）对未知 flag
 *   返回 Err → config error 1。origin 由浏览器 enforced（allowed_origins，auth 层 ①）
 *   且可伪造，host 不消费（② 层验父进程靠 getppid()，非 argv）——故本 shim **丢弃
 *   origin 类参数**，其余参数原样透传（--log 等）；手动以 --log 调用 shim 仍可用。
 *
 * 退出码：exec 成功则永不返回（PID 保持）；exec 失败返回 127（fail-closed）。
 */
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <libgen.h>
#include <mach-o/dyld.h>

/* Chrome/Edge（Chromium）与 Firefox 注入的扩展 origin 前缀 */
static int is_browser_origin(const char *arg) {
    return strncmp(arg, "chrome-extension://", 19) == 0
        || strncmp(arg, "moz-extension://", 16) == 0;
}

int main(int argc, char **argv) {
    /* 自身绝对路径：App 可能被移动/重装，不硬编码安装位置（_NSGetExecutablePath
     * 返回真实可执行路径，再 realpath 消除符号链接/相对成分） */
    char self[PATH_MAX];
    uint32_t size = sizeof(self);
    if (_NSGetExecutablePath(self, &size) != 0) {
        return 127;
    }
    char resolved[PATH_MAX];
    if (realpath(self, resolved) == NULL) {
        return 127;
    }
    /* BSD dirname 就地修改并返回入参指针；此处 resolved 之后不再用，安全 */
    char *dir = dirname(resolved); /* .../Contents/Helpers */
    /* coffer 二进制：与 shim 同 App bundle 内的嵌套 bundle */
    char coffer[PATH_MAX];
    int n = snprintf(coffer, sizeof(coffer),
                     "%s/coffer.app/Contents/MacOS/coffer", dir);
    if (n < 0 || (size_t)n >= sizeof(coffer)) {
        return 127;
    }

    /* 组装 exec 参数：coffer browser-agent [透传（丢弃浏览器注入的 origin）] */
    char *out_argv[16];
    int out_argc = 0;
    out_argv[out_argc++] = coffer;
    out_argv[out_argc++] = "browser-agent";
    for (int i = 1; i < argc && out_argc < 15; i++) {
        if (is_browser_origin(argv[i])) {
            continue; /* 浏览器注入的 origin：G-B 不消费，丢弃 */
        }
        out_argv[out_argc++] = argv[i];
    }
    out_argv[out_argc] = NULL;

    execv(coffer, out_argv);
    /* exec 失败：stderr 提示 + fail-closed */
    fprintf(stderr, "coffer-shim: exec %s failed: %s\n", coffer, strerror(errno));
    return 127;
}
