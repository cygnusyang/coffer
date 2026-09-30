//! `[[bin]] coffer` 入口（docs/20 §5.1）。
//!
//! 薄入口：把 `argv[1..]` 交给 [`cf_mcp::cli::run`]（参数解析 + provider 构建 +
//! stdio 服务 + 退出码映射，docs/20 §5.2/§5.3），透传其返回码作为进程退出码。
//!
//! stdout 永为协议帧（§3.1）；所有日志/错误经 [`cf_mcp::cli`] 的 Logger / stderr。

#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used, clippy::expect_used)]

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    std::process::exit(cf_mcp::cli::run(&args));
}
