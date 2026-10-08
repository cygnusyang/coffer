/**
 * Mock broker for the Node E2E tests (G-C acceptance: "E2E 握手 mock broker 双向通过").
 * Mirrors the responder side of the frozen cf-browser contract (ResponderHandshake /
 * BrokerEndpoint in e2e.rs): on msg1 it computes ee/es, signs msg2 over
 * (e_init_pub‖e_resp_pub) with the static broker key, and verifies msg3 (PSK confirm)
 * before establishing the session.
 *
 * Reuses the exact same WebCrypto derivation code as the extension client
 * (src/crypto/e2e.ts) so the tests prove both sides converge on the same session key —
 * and the cross-language KAT test pins those keys to the Rust frozen hex.
 *
 * This is a test-only transport; the real broker is the Rust `browser-broker` (G-A/G-B).
 */
import {
  generateEphemeralKeyPair,
  exportRawPublicKey,
  importRawPublicKey,
  reimportJwkAsEcdh,
  ecdhShared,
  signMessage,
  buildSigMessage,
  deriveSessionKeys,
  verifyConfirm,
  SessionCipher,
  type AssembledKeyPair,
  type OpenedMessage,
} from "../crypto/e2e";
import {
  PROTOCOL_VERSION,
  SEC1_LEN,
  ProtocolError,
  ErrCode,
  hexEncode,
  hexDecode,
  type InitFrame,
  type ResponseFrame,
  type ConfirmFrame,
  type SessionFrame,
  type AppMessage,
  type PairRequestFrame,
  type PairResultFrame,
} from "../protocol";

export class MockBroker {
  private eRespKeyPair: CryptoKeyPair | null = null;
  private eRespPub: Uint8Array | null = null;
  private pending: { psk: Uint8Array; ee: Uint8Array; es: Uint8Array; eInitPub: Uint8Array; eRespPub: Uint8Array } | null = null;
  private cipher: SessionCipher | null = null;
  private readonly brokerEcdh: Promise<CryptoKey>;

  constructor(
    readonly identity: CryptoKeyPair, // ECDSA P-256 static broker key (sign/verify)
    private readonly psk: Uint8Array,
    opts?: { eRespKeyPair?: AssembledKeyPair },
  ) {
    // Same scalar as ECDH so pk_b doubles as the es-binder and the signature verifier.
    this.brokerEcdh = exportKeyJwk(identity.privateKey).then((jwk) => reimportJwkAsEcdh(jwk));
    this.eRespKeyPair = (opts?.eRespKeyPair ?? null) as CryptoKeyPair | null;
  }

  /** Broker static identity public key for pinning (65-byte uncompressed point). */
  async publicKeyRaw(): Promise<Uint8Array> {
    return exportRawPublicKey(this.identity.publicKey);
  }

  /**
   * Pairing responder (design §2.3 / §3.1): validate a pair_request and emit the verdict.
   * The psk is the mock's own (constructor) and pk_b its self-reported public key — the
   * same material the subsequent E2E handshake uses (constructive consistency, §3.1: the
   * extension pins pair_result.pk_b ≡ msg2.pk_b from the same BrokerIdentity).
   */
  async onPairRequest(req: PairRequestFrame, opts?: { approved?: boolean }): Promise<PairResultFrame> {
    if (
      !req ||
      req.type !== "pair_request" ||
      typeof req.browser !== "string" ||
      !(["chrome", "edge", "firefox"] as string[]).includes(req.browser) ||
      typeof req.extension_id !== "string" ||
      req.extension_id.length === 0
    ) {
      throw new ProtocolError(ErrCode.SessionNotEstablished, "malformed pair_request");
    }
    if (opts?.approved === false) {
      return { type: "pair_result", approved: false, error: ErrCode.UserRejected };
    }
    return {
      type: "pair_result",
      approved: true,
      psk: hexEncode(this.psk),
      pk_b: hexEncode(await this.publicKeyRaw()),
    };
  }

  /** Handle msg1 (Init) → msg2 (Response) + pending confirm state. */
  async onInit(init: InitFrame): Promise<ResponseFrame> {
    if (!init || init.type !== "init" || init.version !== PROTOCOL_VERSION) {
      throw new ProtocolError(ErrCode.SessionNotEstablished, "malformed init");
    }
    let eInitPub: Uint8Array;
    try {
      eInitPub = hexDecode(init.e_init);
    } catch {
      throw new ProtocolError(ErrCode.SessionNotEstablished, "malformed init encoding");
    }
    if (eInitPub.length !== SEC1_LEN || eInitPub[0] !== 0x04) {
      throw new ProtocolError(ErrCode.SessionNotEstablished, "bad initiator ephemeral");
    }

    if (!this.eRespKeyPair) this.eRespKeyPair = await generateEphemeralKeyPair();
    this.eRespPub = await exportRawPublicKey(this.eRespKeyPair.publicKey);

    // ee = ECDH(e_resp, e_init); es = ECDH(broker_key, e_init); sign over e_init‖e_resp.
    const eInitPk = await importRawPublicKey(eInitPub);
    const ee = await ecdhShared(this.eRespKeyPair.privateKey, eInitPk);
    const es = await ecdhShared(await this.brokerEcdh, eInitPk);
    const sig = await signMessage(this.identity.privateKey, buildSigMessage(eInitPub, this.eRespPub));

    this.pending = { psk: this.psk, ee, es, eInitPub, eRespPub: this.eRespPub };
    return {
      type: "response",
      version: PROTOCOL_VERSION,
      e_resp: hexEncode(this.eRespPub),
      pk_b: hexEncode(await this.publicKeyRaw()),
      signature: hexEncode(sig),
    };
  }

  /** Handle msg3 (Confirm): verify p = HMAC(PSK, okm); only then establish the session. */
  async onConfirm(confirm: ConfirmFrame): Promise<void> {
    if (!this.pending) {
      throw new ProtocolError(ErrCode.SessionNotEstablished, "onInit() not called");
    }
    if (!confirm || confirm.type !== "confirm" || confirm.version !== PROTOCOL_VERSION) {
      throw new ProtocolError(ErrCode.SessionNotEstablished, "malformed confirm");
    }
    let token: Uint8Array;
    try {
      token = hexDecode(confirm.p);
    } catch {
      throw new ProtocolError(ErrCode.SessionNotEstablished, "malformed confirm encoding");
    }
    const { psk, ee, es, eInitPub, eRespPub } = this.pending;
    const keys = await deriveSessionKeys(ee, es, eInitPub, eRespPub);
    const ok = await verifyConfirm(psk, keys.okm, token);
    if (!ok) {
      throw new ProtocolError(ErrCode.SessionNotEstablished, "confirm token mismatch (PSK)");
    }
    this.cipher = new SessionCipher(keys.encKey, keys.macKey);
    this.pending = null;
  }

  isReady(): boolean {
    return this.cipher !== null;
  }

  async seal(body: AppMessage): Promise<SessionFrame> {
    if (!this.cipher) {
      throw new ProtocolError(ErrCode.SessionNotEstablished, "broker session not established");
    }
    return this.cipher.seal(body);
  }

  async open(frame: SessionFrame): Promise<OpenedMessage> {
    if (!this.cipher) {
      throw new ProtocolError(ErrCode.SessionNotEstablished, "broker session not established");
    }
    return this.cipher.open(frame);
  }
}

async function exportKeyJwk(key: CryptoKey): Promise<JsonWebKey> {
  return crypto.subtle.exportKey("jwk", key);
}
