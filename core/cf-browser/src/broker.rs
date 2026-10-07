//! broker 侧会话骨架（docs/31 §4.2 身份 / §4.3 端点）。
//!
//! - [`BrokerIdentity`]：确定性身份密钥派生（`HKDF(DEK, vault_uuid, "cf/browser/v1")`
//!   → 归约 mod n 得 P-256 私钥，换库即自然重配对，docs/31 §4.2）；
//! - [`BrokerEndpoint`]：单会话握手编排（responder 侧状态机 + [`ResponderHandshake`]），
//!   每次握手**独立 ephemeral**（前向保密 + 会话隔离，docs/31 §3.4）；
//! - 并发：v2.3.0 范围为**单会话**（App 单实例单通道，docs/31 §3.1「三段通道第 3 段」），
//!   多会话轮询由进程侧（G-D）在 `coffer` bin 编排。
//!
//! PSK 与 DEK 均由进程侧（G-D）注入（`broker init --pair 配对流`，docs/31 §5.3）；
//! 本模块不接触持久化，会话密钥仅存内存。

use p256::{PublicKey, SecretKey};

use crate::e2e::{derive_identity_key, ResponderHandshake};
use crate::error::CfBrowserError;
use crate::protocol::HandshakeMessage;

/// broker 确定性身份（docs/31 §4.2）。
///
/// 私钥由 `DEK + vault_uuid` 确定性派生——App 重启/进程被杀后重建身份不变，
/// 扩展侧 pin 的公钥不变，无需重新配对流（`desktop:coffer:pair` 一次性）。
#[derive(Debug)]
pub struct BrokerIdentity {
    secret: SecretKey,
}

impl BrokerIdentity {
    /// 从 DEK 与 vault UUID 派生 broker 身份密钥。
    ///
    /// # 错误
    ///
    /// 派生/归约失败 → [`CfBrowserError::CryptoError`]（不降级，失败即不可用）。
    pub fn derive(dek: &[u8; 32], vault_uuid: &[u8; 16]) -> Result<Self, CfBrowserError> {
        let secret = derive_identity_key(dek, vault_uuid)?;
        Ok(Self { secret })
    }

    /// 静态公钥（扩展侧 pin 用）。
    #[must_use]
    pub fn public_key(&self) -> PublicKey {
        self.secret.public_key()
    }

    /// 私钥引用（握手签名用；不导出副本）。
    pub(crate) fn secret_key(&self) -> &SecretKey {
        &self.secret
    }
}

/// broker 单会话端点（responder 侧握手编排，docs/31 §3.3）。
///
/// 持有固定身份与 PSK；`on_init` 消费 msg1 产出 msg2 + 待确认态，
/// 待确认态校验 msg3（PSK）后建立 [`crate::e2e::Session`]。
pub struct BrokerEndpoint {
    identity: BrokerIdentity,
    psk: [u8; 32],
}

impl BrokerEndpoint {
    /// 新建端点（进程侧注入身份与 PSK）。
    ///
    /// # 错误
    ///
    /// 身份密钥非法 → [`CfBrowserError::CryptoError`]。
    pub fn new(identity: BrokerIdentity, psk: [u8; 32]) -> Self {
        Self { identity, psk }
    }

    /// 处理 msg1（init）→ (msg2, 待确认态)。
    ///
    /// 每次调用生成**独立 responder ephemeral**（前向保密）。
    pub fn on_init(
        &self,
        msg: &HandshakeMessage,
    ) -> Result<(HandshakeMessage, BrokerPendingConfirm), CfBrowserError> {
        let handshake = ResponderHandshake::new(self.identity.secret_key().clone(), self.psk)?;
        let (resp, pending) = handshake.on_init(msg)?;
        Ok((resp, BrokerPendingConfirm { pending }))
    }

    /// 直接以固定 ephemeral 处理 msg1（KAT / 测试注入用）。
    ///
    /// # 安全
    ///
    /// **仅测试与 KAT 使用**：固定 ephemeral 无前向保密。
    pub fn on_init_with_ephemeral(
        &self,
        msg: &HandshakeMessage,
        e_resp_priv: SecretKey,
    ) -> Result<(HandshakeMessage, BrokerPendingConfirm), CfBrowserError> {
        let handshake =
            ResponderHandshake::new_with_ephemeral(self.identity.secret_key().clone(), self.psk, e_resp_priv)?;
        let (resp, pending) = handshake.on_init(msg)?;
        Ok((resp, BrokerPendingConfirm { pending }))
    }
}

/// broker 侧待确认态（封装 [`crate::e2e::PendingConfirm`]，不导出内部秘密）。
///
/// 不含 `Debug`：内部持有会话秘密（ee/es/PSK），可派生 Debug 会泄露——对齐
/// e2e 模块秘密类型纪律。
pub struct BrokerPendingConfirm {
    pending: crate::e2e::PendingConfirm,
}

impl BrokerPendingConfirm {
    /// 校验 msg3（PSK 确认）→ 建立会话。
    ///
    /// # 错误
    ///
    /// 令牌不符 → [`CfBrowserError::AuthFailed`]（会话不建立）。
    pub fn on_confirm(self, msg: &HandshakeMessage) -> Result<crate::e2e::Session, CfBrowserError> {
        self.pending.on_confirm(msg)
    }
}
