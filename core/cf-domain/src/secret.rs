//! 内存安全字符串：析构清零、禁止明文输出。

use std::fmt;

use serde::{de::Deserializer, ser::Serializer, Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// 内存安全的敏感字符串（`docs/03-详细设计.md` §4.3）。
///
/// 强制约束：
///
/// - **不实现** [`std::fmt::Display`] —— 明文只能通过 [`SecretString::expose`] 显式取用，
///   让代码中"何处使用了明文"可被 grep 出来审计；
/// - [`Debug`] 输出固定为 `SecretString(***)`，不泄露内容；
/// - 实现 [`ZeroizeOnDrop`]，析构时清零底层 `String` 的内存；
/// - 不实现 [`Clone`] —— 避免不经意的明文复制。
///
/// # 序列化警示
///
/// [`Serialize`] / [`Deserialize`] 按架构师设计**仅供内部加密快照使用**
/// （历史版本 CBOR 快照在加密前的内存态）。序列化会输出明文，**禁止**
/// 用于 FFI 边界或任何明文传输路径。
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SecretString(String);

impl SecretString {
    /// 从明文构造。调用方须确认该明文是进入敏感字符串的正当场景。
    pub fn from_exposed(s: impl Into<String>) -> Self {
        Self(s.into())
    }

    /// 显式取用明文引用。这是明文暴露面的唯一入口。
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for SecretString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretString(***)")
    }
}

impl Serialize for SecretString {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for SecretString {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        String::deserialize(deserializer).map(SecretString)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use zeroize::Zeroize;

    #[test]
    fn expose_returns_plaintext() {
        let s = SecretString::from_exposed("hunter2");
        assert_eq!(s.expose(), "hunter2");
    }

    #[test]
    fn debug_masks_content() {
        let s = SecretString::from_exposed("super-secret-value");
        // 任何 Debug 输出（含类型名变体）都不得泄露内容
        assert_eq!(format!("{s:?}"), "SecretString(***)");
        assert!(!format!("{s:?}").contains("super-secret-value"));
    }

    #[test]
    fn zeroize_clears_inner_string() {
        let mut s = SecretString::from_exposed("clearme");
        // 显式调用 zeroize：底层 String 应被清零（长度清 0）。
        Zeroize::zeroize(&mut s);
        assert_eq!(s.expose(), "");
    }

    #[test]
    fn zeroize_on_drop_is_implemented() {
        // 编译期确认 ZeroizeOnDrop 已派生 —— drop 时必然调用 zeroize，
        // 由 zeroize crate 契约保证（借用借用检查器无法在安全代码中
        // 观察 drop 后的内存，故以 trait 约束 + 上面的显式 zeroize 测试替代）。
        fn assert_traits<T: ZeroizeOnDrop>() {}
        assert_traits::<SecretString>();
    }
}
