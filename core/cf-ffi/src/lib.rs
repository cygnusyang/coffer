//! # cf-ffi —— FFI 绑定层
//!
//! 通过 UniFFI 暴露接口给 Kotlin / Swift，负责类型与错误映射。
//!
//! ## 对应设计文档
//!
//! - `docs/02-概要设计.md` §5（FFI 接口概要）
//! - `docs/03-详细设计.md` §5（FFI 接口清单）
//! - `docs/03-详细设计.md` §5.5（平台回调）
//! - `docs/07-macOS纵切设计.md` §2.3（v0.1 接口清单，T04 权威规格）
//!
//! ## 职责边界
//!
//! **不含业务逻辑** —— 只做类型映射、错误映射与接口暴露。
//!
//! ## panic 纪律（docs/07 §5 C-8 / R-2）
//!
//! workspace `[profile.release]` 已改为 `panic = "unwind"`（T04 阶段 1），
//! 使 FFI 边界的 [`ffi_guard`]（`catch_unwind`）能捕获 Rust panic 并转为
//! [`FfiError::InternalPanic`] 抛给 Swift，而不是杀死整个 App。
//! 若未来有人改回 `panic = "abort"`，`ffi_guard` 将静默失效——这正是
//! 本 crate 测试 `panic_被ffi_guard捕获转为错误` 要钉住的行为。
//!
//! ## 状态
//!
//! **阶段 1 已完成**（C-8 panic 策略修复 + FFI panic 捕获验证）；
//! UniFFI 接口清单在阶段 2 实现。

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use std::panic::{self, UnwindSafe};

/// FFI 层统一错误（docs/07 §2.3：UI 按 code 本地化，不解析 message 文本）。
///
/// 阶段 2 将扩展为完整错误码映射（`cf_domain::CfError` → 错误码，
/// 对齐 `docs/03-详细设计.md` §12）；本阶段先落 panic 兜底变体。
#[derive(Debug, PartialEq, thiserror::Error)]
pub enum FfiError {
    /// Rust 侧 panic 被 [`ffi_guard`] 捕获后的兜底错误。
    ///
    /// {0} 为 panic 摘要（`String` 载荷则取其内容，否则记 `non-string panic`）。
    /// **载荷纪律**：panic hook 侧已声明过滤敏感值；此处摘要只用于日志排障。
    #[error("internal panic: {0}")]
    InternalPanic(String),
}

/// FFI 边界守卫：捕获 Rust panic 并转为 [`FfiError`]（docs/07 §5 C-8 / R-2）。
///
/// 依赖 release profile 的 `panic = "unwind"`——`panic = "abort"` 下本函数
/// 无法捕获、进程直接终止（这正是 C-8 的雷点）。依赖变更需 `UnwindSafe`
/// 时由调用侧用 `AssertUnwindSafe` 显式声明（FFI 入口的参数来自外部进程，
/// panic 后不存在跨调用共享的可变状态被观察到半更新）。
pub fn ffi_guard<T>(f: impl FnOnce() -> T + UnwindSafe) -> Result<T, FfiError> {
    panic::catch_unwind(f).map_err(|payload| {
        let summary = if let Some(s) = payload.downcast_ref::<String>() {
            s.clone()
        } else if let Some(s) = payload.downcast_ref::<&str>() {
            (*s).to_string()
        } else {
            "non-string panic payload".to_string()
        };
        FfiError::InternalPanic(summary)
    })
}

/// [`ffi_guard`] 的 `Result` 便利版：包装返回 `Result` 的 FFI 入口，
/// panic 与业务错误统一为 `Result<T, FfiError>`。
pub fn ffi_guard_result<T, E>(
    f: impl FnOnce() -> Result<T, E> + UnwindSafe,
) -> Result<T, FfiErrorOr<E>> {
    match panic::catch_unwind(f) {
        Ok(Ok(value)) => Ok(value),
        Ok(Err(e)) => Err(FfiErrorOr::Domain(e)),
        Err(payload) => {
            let summary = if let Some(s) = payload.downcast_ref::<String>() {
                s.clone()
            } else if let Some(s) = payload.downcast_ref::<&str>() {
                (*s).to_string()
            } else {
                "non-string panic payload".to_string()
            };
            Err(FfiErrorOr::Panic(FfiError::InternalPanic(summary)))
        }
    }
}

/// [`ffi_guard_result`] 的双态错误：业务错误（`E`）或 panic 兜底
/// （[`FfiError::InternalPanic`]）。阶段 2 落地 UniFFI error enum 后，
/// 各 FFI 签名将收敛到 `FfiError` 单态，本类型随之退役。
#[derive(Debug, PartialEq, thiserror::Error)]
pub enum FfiErrorOr<E> {
    /// 业务错误（如 `cf_domain::CfError`）
    #[error(transparent)]
    Domain(E),
    /// panic 兜底
    #[error(transparent)]
    Panic(FfiError),
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::panic::AssertUnwindSafe;

    /// C-8 验证：panic 被 ffi_guard 捕获转为 FfiError::InternalPanic，
    /// 进程（测试本体）存活继续执行后续断言——若 panic 策略为 abort，
    /// 本测试将直接终止而非断言失败。
    #[test]
    fn panic_被ffi_guard捕获转为错误() {
        let result = ffi_guard(|| -> i32 {
            panic!("模拟不变量破坏");
        });

        assert_eq!(
            result,
            Err(FfiError::InternalPanic("模拟不变量破坏".to_string()))
        );

        // 捕获后进程存活：守卫之后的代码正常执行（能走到这里即是证据）
        let ok = ffi_guard(|| 42);
        assert_eq!(ok, Ok(42));
    }

    /// String 载荷与非字符串载荷都归一为 String 摘要
    #[test]
    fn panic载荷归一为字符串摘要() {
        let s_payload = ffi_guard(|| std::panic::panic_any(String::from("动态构造的panic")));
        assert_eq!(
            s_payload,
            Err(FfiError::InternalPanic("动态构造的panic".to_string()))
        );

        let static_payload = ffi_guard(|| panic!("静态panic"));
        assert_eq!(
            static_payload,
            Err(FfiError::InternalPanic("静态panic".to_string()))
        );

        let other = ffi_guard(|| std::panic::panic_any(vec![1u8, 2, 3]));
        assert_eq!(
            other,
            Err(FfiError::InternalPanic("non-string panic payload".to_string()))
        );
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

        // panic → Panic 态
        assert_eq!(
            ffi_guard_result(|| -> Result<i32, &'static str> { panic!("炸了") }),
            Err(FfiErrorOr::Panic(FfiError::InternalPanic("炸了".to_string())))
        );
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
        assert!(matches!(result, Err(FfiError::InternalPanic(_))));
    }
}
