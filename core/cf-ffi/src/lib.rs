//! # cf-ffi —— FFI 绑定层
//!
//! 通过 UniFFI（proc-macro 模式，`uniffi 0.32.2`）暴露接口给 Kotlin / Swift，
//! 负责类型映射、错误映射与接口暴露。
//!
//! ## 对应设计文档
//!
//! - `docs/07-macOS纵切设计.md` §2.3（v0.1 接口清单，**T04 权威规格**）
//! - `docs/03-详细设计.md` §5（FFI 接口清单）、§12（错误码表）
//! - `docs/02-概要设计.md` §5（FFI 接口概要）
//!
//! ## 模块划分（T04 阶段 2）
//!
//! - [`error`]：[`FfiError`]——UniFFI error enum，UI 按 `code` 本地化
//!   （错误码与 docs/03 §12 一致），panic 兜底码 5999
//! - [`types`]：跨 FFI 数据类型（`Record` / `Enum`）与双向转换
//! - [`api`]：[`api::CofferApp`] 工厂 + [`api::VaultSession`] 会话门面
//!   （全同步接口；Swift 侧用 `Task.detached` 包裹耗时调用，docs/07 §2.3）
//!
//! ## 安全不变量
//!
//! 1. **DEK / SubKeys 永不跨 FFI**——任何接口签名都不含密钥类型；
//!    会话门禁与加解密全部在 Rust 侧强制。
//! 2. **敏感值单独按需取**——`get_item` 详情中 Concealed 字段只回掩码
//!    （value 为空），真实值仅经 `get_field_value` / `totp_code` 随取随走
//!    （docs/07 §4.2）。
//! 3. **panic 不杀进程**——所有会穿透 FFI 的调用经 [`session_call`]
//!    （`catch_unwind` → 错误），依赖 workspace `panic = "unwind"`
//!    （阶段 1，C-8）。
//! 4. **错误码跨版本契约**——[`FfiError::Coffer.code`] 与
//!    `cf_domain::CfError::code`（docs/03 §12）逐一对应，UI 不解析 message。

#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used, clippy::expect_used)]
#![warn(missing_docs)]

use std::panic::{self, AssertUnwindSafe};

pub mod api;
pub mod error;
pub mod types;

pub use error::FfiError;

// UniFFI scaffolding（proc-macro 模式；生成物与 uniffi-bindgen 版本由
// 本 crate 内置的 uniffi-bindgen bin 保证一致，见 Cargo.toml [[bin]]）
uniffi::setup_scaffolding!();

/// FFI 层统一错误（阶段 2 前的过渡形态：panic 兜底 + 业务错误双态）。
///
/// [`error::FfiError`] 落地后，各 FFI 签名统一为 `Result<T, FfiError>`，
/// 本类型只作为 [`session_call`] 的内部中间态。
#[derive(Debug, PartialEq, thiserror::Error)]
pub enum FfiErrorOr<E> {
    /// 业务错误（`cf_domain::CfError` 等）
    #[error(transparent)]
    Domain(E),
    /// panic 兜底
    #[error(transparent)]
    Panic(crate::FfiError),
}

/// FFI 边界守卫：捕获 Rust panic 并转为 [`FfiError`]（docs/07 §5 C-8 / R-2）。
///
/// 依赖 release profile 的 `panic = "unwind"`——`panic = "abort"` 下本函数
/// 无法捕获、进程直接终止（这正是 C-8 的雷点）。
pub fn ffi_guard<T>(f: impl FnOnce() -> T + std::panic::UnwindSafe) -> Result<T, FfiError> {
    panic::catch_unwind(f).map_err(error::panic_payload_to_error)
}

/// [`ffi_guard`] 的 `Result` 便利版：包装返回 `Result` 的调用，
/// panic 与业务错误统一为 `Result<T, FfiErrorOr<E>>`。
pub fn ffi_guard_result<T, E>(
    f: impl FnOnce() -> Result<T, E> + std::panic::UnwindSafe,
) -> Result<T, FfiErrorOr<E>> {
    match panic::catch_unwind(f) {
        Ok(Ok(value)) => Ok(value),
        Ok(Err(e)) => Err(FfiErrorOr::Domain(e)),
        Err(payload) => Err(FfiErrorOr::Panic(error::panic_payload_to_error(payload))),
    }
}

/// 会话层调用统一入口：`catch_unwind` + `CfError → FfiError` 映射。
///
/// 所有导出方法的实现体都长这样：
/// ```ignore
/// session_call(AssertUnwindSafe(|| self.inner.unlock(&password)))
/// ```
/// `AssertUnwindSafe` 是显式声明：FFI 入口的参数来自外部语言运行时，
/// panic 后不存在跨调用共享的可变状态被观察到半更新。
pub(crate) fn session_call<T>(
    f: impl FnOnce() -> cf_session::SessionResult<T>,
) -> Result<T, FfiError> {
    match ffi_guard_result(AssertUnwindSafe(f)) {
        Ok(value) => Ok(value),
        Err(FfiErrorOr::Domain(e)) => Err(FfiError::from(e)),
        Err(FfiErrorOr::Panic(p)) => Err(p),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// C-8 验证：panic 被 ffi_guard 捕获转为 FfiError::InternalPanic，
    /// 进程（测试本体）存活继续执行后续断言——若 panic 策略为 abort，
    /// 本测试将直接终止而非断言失败。
    #[test]
    fn panic_被ffi_guard捕获转为错误() {
        let result = ffi_guard(|| -> i32 {
            panic!("模拟不变量破坏");
        });

        assert!(matches!(result, Err(FfiError::InternalPanic { .. })));
        assert_eq!(result.unwrap_err().code(), 5999);

        // 捕获后进程存活：守卫之后的代码正常执行（能走到这里即是证据）
        let ok = ffi_guard(|| 42);
        assert_eq!(ok, Ok(42));
    }

    /// 载荷脱敏（QA F-1）：panic 文案（可能内嵌敏感值）的内容绝不进入
    /// message——只保留固定文案 + 类型/字节数指纹。
    #[test]
    fn panic载荷脱敏_内容不透传() {
        const SENSITIVE: &str = "TOPSECRET-主密码-p@ssw0rd";
        let err = ffi_guard(|| panic!("unlock failed: password={SENSITIVE}")).unwrap_err();
        assert_eq!(err.code(), 5999);
        match &err {
            FfiError::InternalPanic { message } => {
                assert!(!message.contains(SENSITIVE), "泄漏敏感值: {message:?}");
                assert!(!message.contains("unlock failed"), "panic 文案透传: {message:?}");
                assert!(
                    message.contains("panic payload redacted (type=String"),
                    "message 应为脱敏指纹，实际 {message:?}"
                );
            }
            other => panic!("应为 InternalPanic，实际 {other:?}"),
        }

        // String 载荷同样脱敏（panic_any 动态构造场景）
        let err = ffi_guard(|| std::panic::panic_any(String::from("内容含{敏感值}"))).unwrap_err();
        match &err {
            FfiError::InternalPanic { message } => {
                assert!(!message.contains("敏感值"));
                assert!(message.contains("type=String"));
            }
            other => panic!("应为 InternalPanic，实际 {other:?}"),
        }
    }

    /// 非字符串载荷归一为脱敏指纹（type=non-string，无字节长度语义）
    #[test]
    fn panic载荷归一为脱敏指纹() {
        let static_payload = ffi_guard(|| panic!("静态panic"));
        assert!(matches!(
            static_payload,
            Err(FfiError::InternalPanic { ref message })
                if message.contains("type=&str") && !message.contains("静态panic")
        ));

        let other = ffi_guard(|| std::panic::panic_any(vec![1u8, 2, 3]));
        assert!(matches!(
            other,
            Err(FfiError::InternalPanic { ref message })
                if message.contains("type=non-string")
        ));
    }

    /// ffi_guard_result：正常值 / 业务错误 / panic 三路分派
    #[test]
    fn ffi_guard_result三路分派() {
        // 正常值
        assert_eq!(
            ffi_guard_result(|| -> Result<i32, &'static str> { Ok(7) }),
            Ok(7)
        );

        // 业务错误原样透传（Domain 态）
        assert_eq!(
            ffi_guard_result(|| -> Result<i32, &'static str> { Err("业务错误") }),
            Err(FfiErrorOr::Domain("业务错误"))
        );

        // panic → Panic 态（message 已脱敏，不含载荷内容）
        assert!(matches!(
            ffi_guard_result(|| -> Result<i32, &'static str> { panic!("炸了") }),
            Err(FfiErrorOr::Panic(FfiError::InternalPanic { .. }))
        ));
    }

    /// 借用参数经 AssertUnwindSafe 包装后可用（FFI 入口的常见形态：
    /// 字符串引用来自外部语言运行时，panic 时无跨调用共享状态）。
    #[test]
    fn 借用参数经断言可安全捕获() {
        let input = String::from("来自Swift的参数");
        let result = ffi_guard(AssertUnwindSafe(|| -> usize {
            let len = input.len();
            if len > 0 {
                panic!("借用参数场景的panic");
            }
            len
        }));
        assert!(matches!(result, Err(FfiError::InternalPanic { .. })));
    }
}
