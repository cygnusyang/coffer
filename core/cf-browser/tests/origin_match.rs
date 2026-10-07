//! origin 三型绑定匹配（docs/31 §5.3 D-3）：exact / subdomain / domain + 优先级。
//!
//! 覆盖：三型各自语义（含真子域边界、apex 排除）、优先级 exact > subdomain > domain、
//! 冗余绑定取首个、非法输入拒绝、端口归一。

use cf_browser::error::CfBrowserError;
use cf_browser::origin::{best_match, Origin, OriginBinding, OriginBindingKind};

// ---------------------------------------------------------------- 解析与归一

#[test]
fn exact_normalizes_scheme_host_port() {
    // 默认端口归一：https 显式 :443 与缺省相同
    let a = Origin::parse("https://example.com").expect("ok");
    let b = Origin::parse("https://example.com:443").expect("ok");
    assert_eq!(a, b);
    assert_eq!(a.to_string(), "https://example.com:443");

    // 大小写归一
    let c = Origin::parse("HTTPS://EXAMPLE.COM").expect("ok");
    assert_eq!(a, c);

    // http 默认 80
    let d = Origin::parse("http://example.com").expect("ok");
    assert_eq!(d.to_string(), "http://example.com:80");
    assert_ne!(a, d, "scheme 不同 → origin 不同");
}

#[test]
fn origin_rejects_invalid_input() {
    for bad in [
        "ftp://example.com",          // 非 http/https
        "example.com",                // 无 scheme
        "http://",                    // 空 host
        "http://.example.com",        // host 首字符为点
        "http://exa..mple.com",       // 连续点
        "http://example.com:0",       // 端口 0 非法
        "http://example.com:99999",   // 端口越界
        "http://example.com:notaport", // 端口非数字
        "http://[::1]:8080",          // IPv6（本范围不支持）
    ] {
        assert!(
            matches!(Origin::parse(bad), Err(CfBrowserError::InvalidOrigin(_))),
            "应拒绝 {bad:?}"
        );
    }
}

#[test]
fn origin_accepts_trailing_dot_host() {
    // 去尾点归一（浏览器 origin host 无尾点，绑定值手动输入时宽容）
    let a = Origin::parse("https://example.com.").expect("ok");
    let b = Origin::parse("https://example.com").expect("ok");
    assert_eq!(a, b);
}

// ---------------------------------------------------------------- 三型语义

#[test]
fn exact_matches_identical_origin_only() {
    let binding = OriginBinding::parse("https://example.com").expect("ok");
    assert_eq!(binding.kind, OriginBindingKind::Exact);

    assert!(binding.matches(&Origin::parse("https://example.com").expect("ok")));
    assert!(binding.matches(&Origin::parse("https://example.com:443").expect("ok")));
    // 不同端口不匹配（exact = scheme+host+port 全等）
    assert!(!binding.matches(&Origin::parse("https://example.com:444").expect("ok")));
    // 不同 scheme 不匹配
    assert!(!binding.matches(&Origin::parse("http://example.com").expect("ok")));
    // 子域不是 exact 匹配
    assert!(!binding.matches(&Origin::parse("https://www.example.com").expect("ok")));
}

#[test]
fn subdomain_matches_true_subdomain_not_apex() {
    let binding = OriginBinding::parse("*.example.com").expect("ok");
    assert_eq!(binding.kind, OriginBindingKind::Subdomain);
    assert_eq!(binding.value, "example.com");

    assert!(binding.matches(&Origin::parse("https://www.example.com").expect("ok")));
    assert!(binding.matches(&Origin::parse("https://a.b.example.com").expect("ok")));
    // apex 不匹配（真子域定义，D-3）
    assert!(!binding.matches(&Origin::parse("https://example.com").expect("ok")));
    // 边界点：notexample.com 不是子域
    assert!(!binding.matches(&Origin::parse("https://notexample.com").expect("ok")));
    // 多级后缀
    let uk = OriginBinding::parse("*.co.uk").expect("ok");
    assert!(uk.matches(&Origin::parse("https://www.co.uk").expect("ok")));
    assert!(!uk.matches(&Origin::parse("https://co.uk").expect("ok")));
}

#[test]
fn domain_matches_apex_and_subdomains() {
    let binding = OriginBinding::parse("example.com").expect("ok");
    assert_eq!(binding.kind, OriginBindingKind::Domain);

    assert!(binding.matches(&Origin::parse("https://example.com").expect("ok")));
    assert!(binding.matches(&Origin::parse("https://www.example.com").expect("ok")));
    assert!(binding.matches(&Origin::parse("https://a.b.example.com").expect("ok")));
    // 边界点
    assert!(!binding.matches(&Origin::parse("https://notexample.com").expect("ok")));
}

#[test]
fn binding_parse_auto_detects_kind() {
    assert_eq!(
        OriginBinding::parse("https://example.com").expect("ok").kind,
        OriginBindingKind::Exact
    );
    assert_eq!(
        OriginBinding::parse("*.example.com").expect("ok").kind,
        OriginBindingKind::Subdomain
    );
    assert_eq!(
        OriginBinding::parse("example.com").expect("ok").kind,
        OriginBindingKind::Domain
    );
    // 非法绑定值拒绝
    assert!(matches!(
        OriginBinding::parse("*.foo..bar"),
        Err(CfBrowserError::InvalidOrigin(_))
    ));
    assert!(matches!(
        OriginBinding::parse("ftp://example.com"),
        Err(CfBrowserError::InvalidOrigin(_))
    ));
}

// ---------------------------------------------------------------- 优先级

fn binding(kind: OriginBindingKind, value: &str) -> OriginBinding {
    OriginBinding { kind, value: value.to_string() }
}

#[test]
fn priority_exact_over_subdomain_over_domain() {
    let bindings = vec![
        binding(OriginBindingKind::Domain, "example.com"),
        binding(OriginBindingKind::Subdomain, "example.com"),
        binding(OriginBindingKind::Exact, "https://www.example.com:443"),
    ];

    // www.example.com：exact 命中 → 优先级最高
    let www = Origin::parse("https://www.example.com").expect("ok");
    let best = best_match(&bindings, &www).expect("有匹配");
    assert_eq!(best.kind, OriginBindingKind::Exact);

    // a.b.example.com：exact 不命中（host 不同），subdomain 命中
    let sub = Origin::parse("https://a.b.example.com").expect("ok");
    let best = best_match(&bindings, &sub).expect("有匹配");
    assert_eq!(best.kind, OriginBindingKind::Subdomain);

    // example.com（apex）：仅 domain 命中
    let apex = Origin::parse("https://example.com").expect("ok");
    let best = best_match(&bindings, &apex).expect("有匹配");
    assert_eq!(best.kind, OriginBindingKind::Domain);
}

#[test]
fn priority_respects_port_exact() {
    // exact 绑定带端口 vs 无端口：端口不同则 exact 不命中，回退 domain
    let bindings = vec![
        binding(OriginBindingKind::Domain, "example.com"),
        binding(OriginBindingKind::Exact, "https://example.com:8080"),
    ];
    let www = Origin::parse("https://example.com:8080").expect("ok");
    assert_eq!(
        best_match(&bindings, &www).expect("有匹配").kind,
        OriginBindingKind::Exact
    );
    let www443 = Origin::parse("https://example.com").expect("ok");
    assert_eq!(
        best_match(&bindings, &www443).expect("有匹配").kind,
        OriginBindingKind::Domain
    );
}

#[test]
fn best_match_none_when_unbound() {
    let bindings = vec![binding(OriginBindingKind::Domain, "example.com")];
    assert!(best_match(&bindings, &Origin::parse("https://other.org").expect("ok")).is_none());
    assert!(best_match(&[], &Origin::parse("https://other.org").expect("ok")).is_none());
}

#[test]
fn best_match_tie_returns_first() {
    // 同优先级冗余绑定：返回第一个（文档化行为，不承诺次序）
    let bindings = vec![
        binding(OriginBindingKind::Domain, "example.com"),
        binding(OriginBindingKind::Domain, "example.com"),
    ];
    let origin = Origin::parse("https://example.com").expect("ok");
    let best = best_match(&bindings, &origin).expect("有匹配");
    assert_eq!(best.value, "example.com");
    // 第一个命中
    assert!(std::ptr::eq(best, &bindings[0]));
}
