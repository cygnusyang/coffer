//! origin 三型绑定与匹配（docs/31 §5.3 D-3，冻结：exact / subdomain / domain）。
//!
//! 硬约束（D-3）：**无 regex、无 prefix 通配**（regex = 用户误配 + 过宽匹配 =
//! 钓鱼放大，docs/31 §5.3）。匹配优先级 **exact > subdomain > domain**；
//! 无匹配 → 不填充。填充前 UI 恒展示目标 origin 与条目绑定（用户可见复核）。
//!
//! 三型语义：
//! - `exact`：`https://example.com`——scheme + host + port 规范化后全匹配；
//! - `subdomain`：`*.example.com`——匹配**真子域**（`www.example.com`、
//!   `a.b.example.com`），**不含 apex** `example.com`；
//! - `domain`：`example.com`——含 apex + 全部子域。
//!
//! 本模块为纯逻辑（无 IO/无加密），绑定值的序列化（item `origin_bindings`
//! 字段，additive `#[serde(default)]`）由领域/存储层承接（docs/31 §9 风险 4），
//! 本处类型已带 `serde` derive 以便未来直接嵌入。

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::error::CfBrowserError;

/// 绑定类型（D-3 冻结：exact / subdomain / domain，无其他）。
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

/// 规范化后的有效 origin（当前页 origin，或 exact 绑定值）。
///
/// `to_string()` 恒输出 `scheme://host:port`（端口为显式值或按 scheme 的
/// 默认端口 80/443 归一），保证 `exact` 匹配无歧义：`https://example.com`
/// 与 `https://example.com:443` 归一后相同。
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Origin {
    scheme: String,
    host: String,
    port: u16,
}

impl Origin {
    /// 从 `scheme://host[:port]` 解析并规范化。
    ///
    /// 规范化规则（docs/31 §5.3「scheme+host+port 规范化」）：
    /// - scheme 仅接受 `http`/`https`，小写；
    /// - host 小写、去尾点、校验字符集（`[a-z0-9.-]`，无 `..`、不首尾为 `.`）——
    ///   浏览器 origin 的 host 为 punycode 后的 ASCII，IDN 在扩展侧转换；
    /// - port 缺省取 scheme 默认（http→80，https→443），范围 1..=65535。
    ///
    /// # 错误
    ///
    /// scheme 不支持 / host 非法 / port 越界 → [`CfBrowserError::InvalidOrigin`]。
    pub fn parse(s: &str) -> Result<Self, CfBrowserError> {
        let (scheme, rest) = s
            .split_once("://")
            .ok_or_else(|| CfBrowserError::InvalidOrigin(format!("missing scheme in {s:?}")))?;
        let scheme = scheme.to_ascii_lowercase();
        if scheme != "http" && scheme != "https" {
            return Err(CfBrowserError::InvalidOrigin(format!(
                "unsupported scheme {scheme:?}"
            )));
        }

        let (host, port) = match rest.rsplit_once(':') {
            // 形如 host:port 或 host:（IPv6 不在本范围，浏览器 origin host 为域名）
            Some((h, p)) if !p.is_empty() => {
                let port: u16 = p
                    .parse()
                    .map_err(|_| CfBrowserError::InvalidOrigin(format!("invalid port {p:?}")))?;
                if port == 0 {
                    return Err(CfBrowserError::InvalidOrigin(format!(
                        "port 0 out of range for {s:?}"
                    )));
                }
                (h, port)
            }
            _ => (rest, if scheme == "https" { 443 } else { 80 }),
        };

        let host = host.trim_end_matches('.').to_ascii_lowercase();
        validate_host(&host)?;

        Ok(Self {
            scheme,
            host,
            port,
        })
    }

    /// origin 的 host（小写，无尾点）。
    #[must_use]
    pub fn host(&self) -> &str {
        &self.host
    }

    /// origin 的 scheme（`http` / `https`）。
    #[must_use]
    pub fn scheme(&self) -> &str {
        &self.scheme
    }

    /// origin 的有效端口（显式值或 scheme 默认）。
    #[must_use]
    pub fn port(&self) -> u16 {
        self.port
    }
}

impl fmt::Display for Origin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}://{}:{}", self.scheme, self.host, self.port)
    }
}

/// 一条 origin 绑定（kind + 规范化值）。
///
/// `value` 语义随 kind：
/// - `Exact`：规范化 `scheme://host:port` 字符串；
/// - `Subdomain` / `Domain`：小写 host（无 scheme/port/`*.` 前缀）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OriginBinding {
    /// 绑定类型。
    pub kind: OriginBindingKind,
    /// 绑定值（见类型级注释的语义）。
    pub value: String,
}

impl OriginBinding {
    /// 从绑定字符串解析（自动判定类型，docs/31 §5.3 三型）。
    ///
    /// - 前缀 `*.` → `Subdomain`（值 = 去掉 `*.` 后的 host）；
    /// - 含 `://` → `Exact`（规范化 `scheme://host:port`）；
    /// - 否则 → `Domain`（host 校验）。
    ///
    /// # 错误
    ///
    /// 非法 scheme / host / port → [`CfBrowserError::InvalidOrigin`]。
    pub fn parse(s: &str) -> Result<Self, CfBrowserError> {
        if let Some(rest) = s.strip_prefix("*.") {
            let host = rest.trim_end_matches('.').to_ascii_lowercase();
            validate_host(&host)?;
            Ok(Self {
                kind: OriginBindingKind::Subdomain,
                value: host,
            })
        } else if s.contains("://") {
            let exact = Origin::parse(s)?;
            Ok(Self {
                kind: OriginBindingKind::Exact,
                value: exact.to_string(),
            })
        } else {
            let host = s.trim_end_matches('.').to_ascii_lowercase();
            validate_host(&host)?;
            Ok(Self {
                kind: OriginBindingKind::Domain,
                value: host,
            })
        }
    }

    /// 当前 origin 是否命中本绑定。
    #[must_use]
    pub fn matches(&self, origin: &Origin) -> bool {
        match self.kind {
            OriginBindingKind::Exact => self.value == origin.to_string(),
            OriginBindingKind::Subdomain => is_subdomain(origin.host(), &self.value),
            OriginBindingKind::Domain => {
                origin.host() == self.value || is_subdomain(origin.host(), &self.value)
            }
        }
    }
}

/// 从绑定集合中取**优先级最高**的匹配（exact > subdomain > domain）。
///
/// 同优先级多条命中（冗余绑定）时返回**第一个**（文档化行为，不承诺次序）；
/// 无命中返回 `None`（→ 不填充，docs/31 §5.3）。
pub fn best_match<'a>(bindings: &'a [OriginBinding], origin: &Origin) -> Option<&'a OriginBinding> {
    let mut best: Option<(&'a OriginBinding, u8)> = None;
    for b in bindings {
        if !b.matches(origin) {
            continue;
        }
        let prio = match b.kind {
            OriginBindingKind::Exact => 3,
            OriginBindingKind::Subdomain => 2,
            OriginBindingKind::Domain => 1,
        };
        if best.is_none_or(|(_, p)| prio > p) {
            best = Some((b, prio));
        }
    }
    best.map(|(b, _)| b)
}

/// host 是否为 `domain` 的**真**子域（`x.` + domain，x 非空；边界点校验防
/// `notexample.com` 误配 `example.com`）。
fn is_subdomain(host: &str, domain: &str) -> bool {
    host.len() > domain.len()
        && host.ends_with(domain)
        && host.as_bytes()[host.len() - domain.len() - 1] == b'.'
}

/// host 字符集校验：非空、`[a-z0-9.-]`、无 `..`、不首尾为 `.`。
fn validate_host(host: &str) -> Result<(), CfBrowserError> {
    if host.is_empty() {
        return Err(CfBrowserError::InvalidOrigin("empty host".into()));
    }
    if host.starts_with('.') || host.ends_with('.') || host.contains("..") {
        return Err(CfBrowserError::InvalidOrigin(format!(
            "host has invalid dot structure: {host:?}"
        )));
    }
    if !host
        .bytes()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'.')
    {
        return Err(CfBrowserError::InvalidOrigin(format!(
            "host contains invalid characters: {host:?}"
        )));
    }
    Ok(())
}
