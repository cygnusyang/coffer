//! header.json 解析面的属性测试（模糊测试基建，docs/09 §2 v1.0.0 卡片）。
//!
//! 本机无 nightly / cargo-fuzz（`docs/09` §2 模糊测试判据的环境替代方案），
//! 以 proptest 承担同等判据：
//!
//! 1. **任意字节不 panic**：`serde_json::from_slice::<Header>` +
//!    `validate_header` 对任意输入只允许 Ok / Err，不允许 panic；
//! 2. **单字节变异不 panic**：从合法 header JSON 出发做任意位置单字节
//!    篡改（模拟「半可信输入」，docs/04 §4.3），解析路径同样只许
//!    Ok / Err；解析成功者必须满足「再序列化 → 再解析 == 自身」的
//!    往返不变量（防解析引入不可重序列化的中间态）；
//! 3. **合法输入往返不变**：任意合法字段值（display_name / 时间戳 /
//!    KDF 参数区间内取值）构造的 Header 序列化 → 解析逐字段相等，
//!    且通过 `validate_header`；
//! 4. **字段变异不变量**：任一受约束字段（format_version / KDF 参数 /
//!    algo / salt_b64）越界 → `validate_header` 必拒（字段独立强制）；
//! 5. **KDF 参数全空间往返**：m / t / p 三维在完整合法区间内任意取值
//!    的往返不变量（性质 3 只变 m，此处补 t / p）；
//! 6. **序列化确定性**：同一 Header 两次序列化逐字节一致。
//!
//! CI 口径：默认测试集内直接执行（单轮 256 例，耗时秒级，无需
//! `#[ignore]`；参照 cf-audit 的先例仅对release 人工独占项用 ignore）。

use base64::Engine as _;
use cf_crypto::kdf::{
    MAX_M_COST_KIB, MAX_P_COST, MAX_T_COST, MIN_M_COST_KIB, MIN_P_COST, MIN_T_COST,
};
use cf_format::header::{
    AeadSection, BiometricWrap, Header, HeaderFlags, KdfSection, McpWrap, VerifierSection,
    WrappedKey, AEAD_ALGO, ARGON2_VERSION, FORMAT_VERSION, KDF_ALGO, NONCE_LEN, SALT_LEN,
    VERIFIER_CT_MIN, WRAPPED_DEK_CT_MIN,
};
use cf_format::validate_header;
use proptest::prelude::*;

/// 任意字节序列（含非法 UTF-8 / 空 / 超长截断）。
fn arbitrary_bytes() -> impl Strategy<Value = Vec<u8>> {
    proptest::collection::vec(any::<u8>(), 0..512)
}

/// 构造一个满足全部校验的合法 Header（形状对照 docs/03 §1.3 示例），
/// 可变字段（display_name / 时间戳 / KDF 参数）由属性注入。
fn valid_header(
    display_name: String,
    created_at: i64,
    m_cost_kib: u32,
    t_cost: u32,
    p_cost: u32,
) -> Header {
    let b64 = |bytes: &[u8]| base64::engine::general_purpose::STANDARD.encode(bytes);
    Header {
        format_version: FORMAT_VERSION,
        // 校验只查 UUID 文本形状（36 字符 + 连字符位置），不查版本位
        vault_uuid: "01932b3c-4d5e-7f80-9abc-def012345678".to_string(),
        display_name,
        created_at,
        modified_at: created_at,
        kdf: KdfSection {
            algo: KDF_ALGO.to_string(),
            argon2_version: ARGON2_VERSION,
            m_cost_kib,
            t_cost,
            p_cost,
            salt_b64: b64(&[0x42u8; SALT_LEN]),
        },
        aead: AeadSection {
            algo: AEAD_ALGO.to_string(),
        },
        wrapped_dek: WrappedKey {
            nonce_b64: b64(&[0x11u8; NONCE_LEN]),
            ct_b64: b64(&[0x22u8; WRAPPED_DEK_CT_MIN]),
        },
        verifier: VerifierSection {
            nonce_b64: b64(&[0x33u8; NONCE_LEN]),
            ct_b64: b64(&[0x44u8; VERIFIER_CT_MIN]),
        },
        biometric_wrap: BiometricWrap {
            available: false,
            provider: None,
            key_alias: None,
            wrapped_dek_b64: None,
        },
        mcp_wrap: McpWrap {
            available: false,
            provider: None,
            key_alias: None,
            wrapped_dek_b64: None,
        },
        flags: HeaderFlags {
            sort_key_enabled: false,
            attachments_inline: false,
        },
    }
}

/// 单个受约束字段的越界取值（其余字段保持合法）——用于验证
/// `validate_header` 对每个受约束字段**独立**强制：任一字段越界必须拒绝，
/// 不得因「其他字段合法」而放行。
#[derive(Debug, Clone)]
enum BadField {
    /// `m_cost_kib` 越界（MIN-1 / MAX+1 / 0 / u32::MAX）。
    MCostKib(u32),
    /// `t_cost` 越界（0 / MAX+1 / u32::MAX）。
    TCost(u32),
    /// `p_cost` 越界（0 / MAX+1 / u32::MAX）。
    PCost(u32),
    /// `format_version` 不等于 `FORMAT_VERSION`。
    FormatVersion(u16),
    /// `kdf.algo` 不等于 `KDF_ALGO`（前缀 `x` 保证与 `argon2id` 不同）。
    KdfAlgo(String),
    /// `kdf.salt_b64` 非法 base64 或解码后长度 ≠ `SALT_LEN`。
    SaltB64(String),
}

/// 生成一个越界字段取值。
fn bad_field() -> impl Strategy<Value = BadField> {
    prop_oneof![
        prop_oneof![
            Just(MIN_M_COST_KIB - 1),
            Just(MAX_M_COST_KIB + 1),
            Just(0u32),
            Just(u32::MAX),
        ]
        .prop_map(BadField::MCostKib),
        prop_oneof![
            Just(0u32),
            Just(MAX_T_COST + 1),
            Just(u32::MAX),
        ]
        .prop_map(BadField::TCost),
        prop_oneof![
            Just(0u32),
            Just(MAX_P_COST + 1),
            Just(u32::MAX),
        ]
        .prop_map(BadField::PCost),
        any::<u16>()
            .prop_filter("必须是合法版本号之外的值", |v| *v != FORMAT_VERSION)
            .prop_map(BadField::FormatVersion),
        any::<char>().prop_map(|c| BadField::KdfAlgo(format!("x{c}"))),
        // 盐：非 base64 垃圾，或 base64 但解码后长度 ≠ SALT_LEN
        prop_oneof![
            Just("%%%not-base64%%%".to_string()),
            any::<Vec<u8>>()
                .prop_filter("解码后恰为 SALT_LEN 时不是越界", |v| v.len() != SALT_LEN)
                .prop_map(|v| base64::engine::general_purpose::STANDARD.encode(v)),
        ]
        .prop_map(BadField::SaltB64),
    ]
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    /// 性质 1：任意字节 → 解析 + 校验只许 Ok / Err，不许 panic。
    #[test]
    fn prop_parse_arbitrary_bytes_never_panics(bytes in arbitrary_bytes()) {
        // 解析成功也要能走完内容校验（只许 Err，不许 panic）
        if let Ok(h) = serde_json::from_slice::<Header>(&bytes) {
            let _ = validate_header(&h);
        }
    }

    /// 性质 2：合法 header 的单字节变异 → 不 panic；解析成功者满足
    /// 「再序列化 → 再解析 == 自身」往返不变量。
    #[test]
    fn prop_single_byte_mutation_never_panics(
        display_name in ".*",
        pos in any::<usize>(),
        byte in any::<u8>(),
    ) {
        let h = valid_header(display_name, 1_790_000_000, 262_144, 3, 4);
        let mut json = serde_json::to_vec(&h).expect("合法 header 必可序列化");
        let idx = pos % json.len();
        json[idx] = byte;

        if let Ok(parsed) = serde_json::from_slice::<Header>(&json) {
            let _ = validate_header(&parsed);
            let re = serde_json::to_vec(&parsed).expect("解析结果必可再序列化");
            let back: Header = serde_json::from_slice(&re).expect("往返必可解析");
            prop_assert_eq!(back, parsed);
        }
    }

    /// 性质 3：合法输入往返不变——任意合法字段值构造的 Header，
    /// 序列化 → 解析逐字段相等，且 validate_header 通过。
    #[test]
    fn prop_valid_header_roundtrip(
        display_name in ".*",
        created_at in 0i64..4_102_444_800, // 2100 年前
        m_cost_kib in 8_192u32..=1_048_576, // KDF 区间内取值（MiB 级上限内）
    ) {
        let h = valid_header(display_name, created_at, m_cost_kib, 3, 4);
        validate_header(&h).expect("构造的 header 必须合法");
        let json = serde_json::to_vec(&h).expect("序列化成功");
        let back: Header = serde_json::from_slice(&json).expect("反序列化成功");
        prop_assert_eq!(back, h);
    }

    /// 性质 4（header 字段变异不变量）：任一受约束字段越界 → validate_header
    /// 必拒。每次只改动一个字段、其余保持合法，拒绝必须归因于该字段——
    /// 防止校验只覆盖部分字段、其他字段被静默放行。
    #[test]
    fn prop_constrained_field_out_of_domain_rejected(bad in bad_field()) {
        let base = valid_header("t".to_string(), 1_790_000_000, 262_144, 3, 4);
        let mut h = base.clone();
        match &bad {
            BadField::MCostKib(v) => h.kdf.m_cost_kib = *v,
            BadField::TCost(v) => h.kdf.t_cost = *v,
            BadField::PCost(v) => h.kdf.p_cost = *v,
            BadField::FormatVersion(v) => h.format_version = *v,
            BadField::KdfAlgo(s) => h.kdf.algo = s.clone(),
            BadField::SaltB64(s) => h.kdf.salt_b64 = s.clone(),
        }
        prop_assert!(
            validate_header(&h).is_err(),
            "字段 {bad:?} 越界时 validate_header 必须拒绝"
        );
    }

    /// 性质 5：合法输入的 KDF 参数**全空间**往返——m / t / p 三个维度都在
    /// 各自完整合法区间内任意取值（现有性质 3 只变 m，此处补 t / p），
    /// 序列化 → 解析逐字段相等且通过 validate_header，防区间边界附近
    /// 解析丢精度 / 校验误拒。
    #[test]
    fn prop_valid_header_full_kdf_param_space_roundtrips(
        display_name in ".*",
        created_at in 0i64..4_102_444_800,
        m_cost_kib in MIN_M_COST_KIB..=MAX_M_COST_KIB,
        t_cost in MIN_T_COST..=MAX_T_COST,
        p_cost in MIN_P_COST..=MAX_P_COST,
    ) {
        let h = valid_header(display_name, created_at, m_cost_kib, t_cost, p_cost);
        validate_header(&h).expect("构造的 header 必须合法");
        let json = serde_json::to_vec(&h).expect("序列化成功");
        let back: Header = serde_json::from_slice(&json).expect("反序列化成功");
        prop_assert_eq!(back, h);
    }

    /// 性质 6：同一 Header 的 JSON 序列化确定性——两次序列化逐字节一致。
    /// 防未来在 Serialize 实现中引入 HashMap 序 / 时间戳等非确定来源。
    #[test]
    fn prop_header_json_serialization_deterministic(
        display_name in ".*",
        created_at in 0i64..4_102_444_800,
        m_cost_kib in MIN_M_COST_KIB..=MAX_M_COST_KIB,
    ) {
        let h = valid_header(display_name, created_at, m_cost_kib, 3, 4);
        let j1 = serde_json::to_vec(&h).expect("序列化成功");
        let j2 = serde_json::to_vec(&h).expect("序列化成功");
        prop_assert_eq!(j1, j2, "同一 header 两次序列化必须逐字节一致");
    }
}
