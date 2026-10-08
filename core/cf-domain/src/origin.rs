//! 条目 origin 绑定（D-3，docs/31 §5.3，冻结：exact / subdomain / domain）。
//!
//! 本模块是**存储形态**的绑定类型：`item.origin_bindings` 落库、读改写
//! 的载体（cf-domain → cf-store → cf-session 单向依赖链上唯一可承载的
//! 绑定类型）。匹配语义按 D-3 冻结（`exact > subdomain > domain` 优先级、
//! `scheme+host+port` 规范化、host 校验，语义定义见 docs/31 §5.3）；本处
//! 承载三型枚举 + 绑定串，serde 形态固定（`kind` snake_case + `value`
//! 字符串），保证存储与匹配两侧无歧义互认。
//!
//! 三型语义（冻结）：
//! - `Exact`：`https://example.com`——scheme+host+port 规范化后全匹配；
//! - `Subdomain`：`*.example.com`——匹配真子域，不含 apex；
//! - `Domain`：`example.com`——含 apex + 全部子域。
//!
//! 无 regex、无 prefix 通配（D-3 硬约束）。未知 kind 反序列化失败
//! （三型冻结，不设 `#[serde(other)]` 兜底）。

use serde::{Deserialize, Serialize};

/// 绑定类型（D-3 冻结三型，无其他）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OriginBindingKind {
    /// `https://example.com`——scheme+host+port 规范化全匹配。
    Exact,
    /// `*.example.com`——真子域（不含 apex）。
    Subdomain,
    /// `example.com`——含 apex + 全部子域。
    Domain,
}

impl OriginBindingKind {
    /// 存储用规范文本（`exact` / `subdomain` / `domain`，与 serde 一致）。
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Exact => "exact",
            Self::Subdomain => "subdomain",
            Self::Domain => "domain",
        }
    }

    /// 存储文本 → 枚举；未知文本返回 `None`（读路径视为数据损坏）。
    ///
    /// 命名刻意与 [`OriginBindingKind::as_str`] 成对（[`ItemCategory`] 两向
    /// 转换惯例同款），返回 `Option` 而非 `Result`，非 [`std::str::FromStr`]
    /// trait 实现，故允许 `should_implement_trait` 提示。
    #[must_use]
    #[allow(clippy::should_implement_trait)]
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "exact" => Some(Self::Exact),
            "subdomain" => Some(Self::Subdomain),
            "domain" => Some(Self::Domain),
            _ => None,
        }
    }
}

/// 一条 origin 绑定（kind + 值）。
///
/// `value` 语义随 kind（冻结三型）：
/// - `Exact`：规范化 `scheme://host:port` 字符串；
/// - `Subdomain` / `Domain`：小写 host（无 scheme/port/`*.` 前缀）。
///
/// serde 形态固定：外部标记结构体 + `kind` snake_case。存储层读改写、
/// 历史快照均用本类型。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OriginBinding {
    /// 绑定类型。
    pub kind: OriginBindingKind,
    /// 绑定值（见类型级注释的语义）。
    pub value: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn binding(kind: OriginBindingKind, value: &str) -> OriginBinding {
        OriginBinding {
            kind,
            value: value.to_owned(),
        }
    }

    /// serde 往返：三型 kind 与 value 无损。
    #[test]
    fn binding_serde_round_trip_all_kinds() {
        for b in [
            binding(OriginBindingKind::Exact, "https://example.com:443"),
            binding(OriginBindingKind::Subdomain, "example.com"),
            binding(OriginBindingKind::Domain, "example.com"),
        ] {
            let json = serde_json::to_string(&b).unwrap();
            let back: OriginBinding = serde_json::from_str(&json).unwrap();
            assert_eq!(b, back, "往返失败: {b:?} -> {json}");
        }
    }

    /// 序列化形态固定（kind snake_case）。
    #[test]
    fn binding_serde_shape_matches_frozen() {
        let b = binding(OriginBindingKind::Exact, "https://example.com");
        let json = serde_json::to_string(&b).unwrap();
        assert_eq!(json, r#"{"kind":"exact","value":"https://example.com"}"#);
    }

    /// kind 的存储文本 ↔ 枚举：往返一致，未知文本为 None（读路径损坏面）。
    #[test]
    fn kind_as_str_from_str_round_trip() {
        for k in [
            OriginBindingKind::Exact,
            OriginBindingKind::Subdomain,
            OriginBindingKind::Domain,
        ] {
            assert_eq!(OriginBindingKind::from_str(k.as_str()), Some(k));
        }
        assert_eq!(OriginBindingKind::from_str("regex"), None);
        assert_eq!(OriginBindingKind::from_str(""), None);
    }

    /// 未知 kind 文本反序列化失败（三型冻结，不静默兜底）。
    #[test]
    fn unknown_kind_rejected_on_deserialize() {
        let json = r#"{"kind":"wildcard","value":"example.com"}"#;
        assert!(serde_json::from_str::<OriginBinding>(json).is_err());
    }
}
