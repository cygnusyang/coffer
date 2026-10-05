//! Argon2id 标准测试向量（KAT）——验证底层依赖 `argon2` crate 的正确性。
//!
//! 向量来源：**draft-irtf-cfrg-argon2-12 §5**（Argon2 参考实现 / PHC 获奖者
//! 已知答案向量；argon2 crate 自带的 tests/kat.rs 亦以此节为源——本测试
//! 独立于 crate 自带 KAT 重新录入期望值，防止依赖自带测试被裁剪或修改后
//! 失真的情况）。
//!
//! 参数：Argon2id **v0x13**（0x13 = 19，与 RFC 9106 及 Coffer 生产
//! `KdfParams` 同版本），m_cost=32 KiB、t_cost=3、p_cost=4、tag=32 字节
//! （256-bit，高于任务单「至少 128-bit」下限）。输入：password=[0x01;32]、
//! salt=[0x02;16]、secret=[0x03;8]、associated_data=[0x04;12]。
//!
//! 该向量带 secret 与 associated_data，均为生产 `KdfParams`（`derive_key`）
//! 不使用的参数路径，故采用任务单允许的「独立 argon2 crate 调用」方式；
//! 生产 KDF 路径由 `kdf` 模块既有单测覆盖。

use argon2::{Algorithm, Argon2, AssociatedData, ParamsBuilder, Version};

/// draft-irtf-cfrg-argon2-12 §5 期望 tag（32 字节）。
const EXPECTED_TAG: [u8; 32] = [
    0x0d, 0x64, 0x0d, 0xf5, 0x8d, 0x78, 0x76, 0x6c, //
    0x08, 0xc0, 0x37, 0xa3, 0x4a, 0x8b, 0x53, 0xc9, //
    0xd0, 0x1e, 0xf0, 0x45, 0x2d, 0x75, 0xb6, 0x5e, //
    0xb5, 0x25, 0x20, 0xe9, 0x6b, 0x01, 0xe6, 0x59, //
];

/// Argon2id v0x13 参考向量：`hash_password_into` 输出须与 §5 逐字节一致。
#[test]
fn argon2id_v0x13_draft_section5_kat() {
    let params = ParamsBuilder::new()
        .m_cost(32)
        .t_cost(3)
        .p_cost(4)
        .data(AssociatedData::new(&[0x04; 12]).expect("12 字节 AD 长度合法"))
        .build()
        .expect("参数在合法域内");

    let ctx = Argon2::new_with_secret(&[0x03; 8], Algorithm::Argon2id, Version::V0x13, params)
        .expect("new_with_secret 构造失败");

    let mut out = [0u8; 32];
    ctx.hash_password_into(&[0x01; 32], &[0x02; 16], &mut out)
        .expect("hash_password_into 失败");

    assert_eq!(
        out, EXPECTED_TAG,
        "tag 与 draft-irtf-cfrg-argon2-12 §5 不符——argon2 依赖行为异常"
    );
}
