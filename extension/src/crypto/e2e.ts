/**
 * E2E session crypto (docs/31 §3.3, D-6) — WebCrypto native, zero JS crypto
 * dependencies, zero WASM. Canonical contract = G-A/cf-browser Rust
 * (core/cf-browser/src/e2e.rs, tests/e2e_kat.rs frozen vectors).
 *
 * IKpsk2-style handshake (hand-rolled, no Noise framework): P-256 ECDH + HKDF-SHA256 +
 * AES-256-GCM + HMAC-SHA256. `es` term required (lead ruling r0.2):
 *   ee = ECDH(e_ext_eph, e_broker_eph);  es = ECDH(e_ext_eph, pk_b)
 *   okm = HKDF-SHA256(ikm = ee‖es, salt = e_init_pub‖e_resp_pub,
 *                     info = "cf/browser/session/v1", L = 64)
 *   enc_key = okm[0:32], mac_key = okm[32:64]
 *
 * Frame (per message): plaintext = seq(8 LE)‖payload_json →
 *   ct_tag = AES-256-GCM(enc_key, nonce12, plaintext, aad="")
 *   mac = HMAC-SHA256(mac_key, nonce‖ct_tag); frame = nonce‖ct‖tag‖mac
 *
 * Material held by the extension:
 *   - session key: memory only, never chrome.storage (MV3 SW restart => re-handshake)
 *   - pairing PSK + pinned broker public key: chrome.storage.local (docs/31 §3.3)
 *
 * Primitives here are shared by the mock broker (src/tests/mock_broker.ts) so the Node
 * two-way handshake + cross-language KAT tests exercise the exact same derivation code
 * as production.
 */
import {
  PROTOCOL_VERSION,
  SESSION_KDF_INFO,
  SEC1_LEN,
  GCM_NONCE_LEN,
  GCM_TAG_LEN,
  FRAME_MAC_LEN,
  SESSION_KEY_LEN,
  ECDSA_SIG_LEN,
  ProtocolError,
  ErrCode,
  b64encode,
  b64decode,
  b64urlEncode,
  hexEncode,
  hexDecode,
  encodeUtf8,
  decodeUtf8,
  type InitFrame,
  type ResponseFrame,
  type ConfirmFrame,
  type SessionFrame,
  type AppMessage,
} from "../protocol";

/** Pin material (docs/31 §5.3 pairing): broker static P-256 public key + 32-byte PSK. */
export interface PairingMaterial {
  /** Broker static identity public key, 65-byte uncompressed P-256 point (SEC1). */
  brokerPublicKeyRaw: Uint8Array;
  /** 32-byte pre-shared key, independent of library keys, rotatable. */
  psk: Uint8Array;
}

/** A P-256 key pair assembled from raw material (KAT fixed-ephemeral injection). */
export interface AssembledKeyPair {
  privateKey: CryptoKey;
  publicKey: CryptoKey;
}

// --- ECDH P-256 ----------------------------------------------------------------------

export async function generateEphemeralKeyPair(): Promise<CryptoKeyPair> {
  return crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, true, ["deriveBits"]);
}

/** Export a P-256 public key as a 65-byte uncompressed point. */
export async function exportRawPublicKey(key: CryptoKey): Promise<Uint8Array> {
  const raw = await crypto.subtle.exportKey("raw", key);
  const bytes = new Uint8Array(raw);
  if (bytes.length !== SEC1_LEN || bytes[0] !== 0x04) {
    throw new ProtocolError(ErrCode.SessionNotEstablished, "unexpected P-256 public key encoding");
  }
  return bytes;
}

export async function importRawPublicKey(raw: Uint8Array): Promise<CryptoKey> {
  if (raw.length !== SEC1_LEN || raw[0] !== 0x04) {
    throw new ProtocolError(ErrCode.SessionNotEstablished, "invalid P-256 public key");
  }
  // Public-key usages stay empty: the "deriveBits" usage lives on the private key.
  // (Node's WebCrypto rejects "deriveBits" as a public-key usage; Chrome/Firefox accept
  // empty usages and still allow the key in deriveBits.)
  // extractable=true: the extension must re-export its own ephemeral public key in
  // msg1 (E2EClient.start), incl. KAT fixed-ephemeral injection. Public keys are public.
  return crypto.subtle.importKey("raw", raw as unknown as BufferSource, { name: "ECDH", namedCurve: "P-256" }, true, []);
}

/** ECDH shared secret (32 bytes for P-256). */
export async function ecdhShared(priv: CryptoKey, peerPub: CryptoKey): Promise<Uint8Array> {
  const bits = await crypto.subtle.deriveBits({ name: "ECDH", public: peerPub }, priv, 256);
  return new Uint8Array(bits);
}

/**
 * Build a private P-256 key from explicit scalars (x, y, d) — KAT / test fixed-ephemeral
 * injection only (production uses generateEphemeralKeyPair). Node WebCrypto cannot import
 * a bare scalar; a JWK with x/y/d is the supported route.
 * extractable=true: the mock broker re-exports the frozen identity private key to JWK so
 * the same scalar doubles as the ECDH key for the `es` term.
 */
export async function importEcJwkPrivate(
  x: Uint8Array,
  y: Uint8Array,
  d: Uint8Array,
  alg: "ECDH" | "ECDSA",
  usages: KeyUsage[],
): Promise<CryptoKey> {
  const jwk: JsonWebKey = {
    kty: "EC",
    crv: "P-256",
    x: b64urlEncode(x),
    y: b64urlEncode(y),
    d: b64urlEncode(d),
  };
  return crypto.subtle.importKey("jwk", jwk, { name: alg, namedCurve: "P-256" }, true, usages);
}

/** Split a SEC1 point into X and Y coordinates (32 B each). */
export function sec1ToXY(raw: Uint8Array): { x: Uint8Array; y: Uint8Array } {
  if (raw.length !== SEC1_LEN || raw[0] !== 0x04) {
    throw new ProtocolError(ErrCode.SessionNotEstablished, "invalid SEC1 point");
  }
  return { x: raw.slice(1, 33), y: raw.slice(33, 65) };
}

/** Assemble a fixed ECDH keypair from a SEC1 public point and a private scalar. */
export async function assembleEcdhKeyPair(sec1Pub: Uint8Array, privScalar: Uint8Array): Promise<AssembledKeyPair> {
  const { x, y } = sec1ToXY(sec1Pub);
  const privateKey = await importEcJwkPrivate(x, y, privScalar, "ECDH", ["deriveBits"]);
  const publicKey = await importRawPublicKey(sec1Pub);
  return { privateKey, publicKey };
}

// --- HKDF-SHA256 ---------------------------------------------------------------------

export async function hkdfBytes(ikm: Uint8Array, salt: Uint8Array, info: Uint8Array, lengthBytes: number): Promise<Uint8Array> {
  const base = await crypto.subtle.importKey(
    "raw",
    ikm as unknown as BufferSource,
    "HKDF",
    false,
    ["deriveBits"],
  );
  const bits = await crypto.subtle.deriveBits(
    { name: "HKDF", hash: "SHA-256", salt: salt as unknown as BufferSource, info: info as unknown as BufferSource },
    base,
    lengthBytes * 8,
  );
  return new Uint8Array(bits);
}

// --- session key derivation (docs/31 §3.3, KAT frozen) -------------------------------

export interface SessionKeys {
  ee: Uint8Array;
  es: Uint8Array;
  okm: Uint8Array;
  encKey: Uint8Array;
  macKey: Uint8Array;
}

/**
 * okm = HKDF-SHA256(ikm = ee‖es, salt = e_init_pub‖e_resp_pub,
 *                   info = "cf/browser/session/v1", L = 64); enc = okm[0:32], mac = okm[32:64].
 */
export async function deriveSessionKeys(
  ee: Uint8Array,
  es: Uint8Array,
  eInitPub: Uint8Array,
  eRespPub: Uint8Array,
): Promise<SessionKeys> {
  const okm = await hkdfBytes(concat(ee, es), concat(eInitPub, eRespPub), encodeUtf8(SESSION_KDF_INFO), SESSION_KEY_LEN);
  return {
    ee,
    es,
    okm,
    encKey: okm.slice(0, 32),
    macKey: okm.slice(32),
  };
}

/** ECDH pairs for the extension client: ee = ECDH(eph_ext, e_resp), es = ECDH(eph_ext, pk_b). */
export async function deriveClientSharedSecrets(
  ephSk: CryptoKey,
  brokerEphPub: CryptoKey,
  brokerStaticPub: CryptoKey,
): Promise<{ ee: Uint8Array; es: Uint8Array }> {
  const ee = await ecdhShared(ephSk, brokerEphPub);
  const es = await ecdhShared(ephSk, brokerStaticPub);
  return { ee, es };
}

// --- HMAC-SHA256 (PSK proof / frame MAC) ---------------------------------------------

async function importHmacKey(keyBytes: Uint8Array, usages: KeyUsage[]): Promise<CryptoKey> {
  return crypto.subtle.importKey("raw", keyBytes as unknown as BufferSource, { name: "HMAC", hash: "SHA-256" }, false, usages);
}

/** p = HMAC-SHA256(key = PSK, msg = okm) — msg3 confirm token (e2e.rs compute_confirm). */
export async function computeConfirm(psk: Uint8Array, okm: Uint8Array): Promise<Uint8Array> {
  const key = await importHmacKey(psk, ["sign"]);
  const mac = await crypto.subtle.sign("HMAC", key, okm as unknown as BufferSource);
  return new Uint8Array(mac);
}

/** Constant-time verification of the confirm token (WebCrypto verify is constant-time). */
export async function verifyConfirm(psk: Uint8Array, okm: Uint8Array, token: Uint8Array): Promise<boolean> {
  const key = await importHmacKey(psk, ["verify"]);
  return crypto.subtle.verify("HMAC", key, token as unknown as BufferSource, okm as unknown as BufferSource);
}

/** Frame MAC: HMAC-SHA256(mac_key, nonce ‖ ct_tag) (e2e.rs frame_mac). */
export async function frameMac(macKey: Uint8Array, nonce: Uint8Array, ctTag: Uint8Array): Promise<Uint8Array> {
  const key = await importHmacKey(macKey, ["sign"]);
  const mac = await crypto.subtle.sign("HMAC", key, concat(nonce, ctTag) as unknown as BufferSource);
  return new Uint8Array(mac);
}

/** Constant-time frame MAC check (verified before GCM decrypt — e2e.rs ordering). */
export async function verifyFrameMac(macKey: Uint8Array, nonce: Uint8Array, ctTag: Uint8Array, mac: Uint8Array): Promise<boolean> {
  const key = await importHmacKey(macKey, ["verify"]);
  return crypto.subtle.verify("HMAC", key, mac as unknown as BufferSource, concat(nonce, ctTag) as unknown as BufferSource);
}

// --- ECDSA-P256 (broker identity binding, msg2) --------------------------------------

export async function generateBrokerIdentity(): Promise<CryptoKeyPair> {
  return crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
}

export async function importRawEcdsaPublicKey(raw: Uint8Array): Promise<CryptoKey> {
  if (raw.length !== SEC1_LEN || raw[0] !== 0x04) {
    throw new ProtocolError(ErrCode.SessionNotEstablished, "invalid broker public key");
  }
  // extractable=true: public keys are public; the mock broker re-exports its own raw
  // public point for pk_b (KAT frozen injection).
  return crypto.subtle.importKey("raw", raw as unknown as BufferSource, { name: "ECDSA", namedCurve: "P-256" }, true, ["verify"]);
}

/** Re-import a JWK (from an ECDSA key) as an ECDH key — same scalar, same public point. */
export async function reimportJwkAsEcdh(jwk: JsonWebKey): Promise<CryptoKey> {
  // Node stamps key_ops/alg on JWK export (e.g. ["sign"] + "ECDSA"); a fresh ECDH import
  // must not carry them or validateKeyOps rejects the ["deriveBits"] request.
  const clean: JsonWebKey = { kty: jwk.kty, crv: jwk.crv, x: jwk.x, y: jwk.y, d: jwk.d };
  return crypto.subtle.importKey("jwk", clean, { name: "ECDH", namedCurve: "P-256" }, false, ["deriveBits"]);
}

/** Sign with an ECDSA-P256 private key; returns raw r‖s (64 bytes, P1363). */
export async function signMessage(sk: CryptoKey, message: Uint8Array): Promise<Uint8Array> {
  const sig = await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, sk, message as unknown as BufferSource);
  const bytes = new Uint8Array(sig);
  if (bytes.length !== ECDSA_SIG_LEN) {
    throw new ProtocolError(ErrCode.SessionNotEstablished, "unexpected ECDSA signature length");
  }
  return bytes;
}

/** Verify a raw r‖s ECDSA-P256 signature over `message` against a public key. */
export async function verifySignature(pk: CryptoKey, message: Uint8Array, sig: Uint8Array): Promise<boolean> {
  if (sig.length !== ECDSA_SIG_LEN) return false;
  return crypto.subtle.verify({ name: "ECDSA", hash: "SHA-256" }, pk, sig as unknown as BufferSource, message as unknown as BufferSource);
}

/** Handshake signature message: e_init_pub(65) ‖ e_resp_pub(65) (e2e.rs sig_message). */
export function buildSigMessage(eInitPub: Uint8Array, eRespPub: Uint8Array): Uint8Array {
  return concat(eInitPub, eRespPub);
}

// --- per-message frame primitives (e2e.rs encrypt_payload / frame_mac) ----------------

async function importAesKey(bytes: Uint8Array): Promise<CryptoKey> {
  return crypto.subtle.importKey("raw", bytes as unknown as BufferSource, { name: "AES-GCM" }, false, ["encrypt", "decrypt"]);
}

/** AES-256-GCM encrypt → ct ‖ tag(16), aad = "" (e2e.rs encrypt_payload). */
export async function encryptPayload(encKey: Uint8Array, nonce: Uint8Array, plaintext: Uint8Array): Promise<Uint8Array> {
  const key = await importAesKey(encKey);
  const ct = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv: nonce as unknown as BufferSource, additionalData: new Uint8Array(0) },
    key,
    plaintext as unknown as BufferSource,
  );
  return new Uint8Array(ct);
}

/** AES-256-GCM decrypt of `ct ‖ tag` (aad = ""). Throws 8004 on tag failure. */
export async function decryptPayload(encKey: Uint8Array, nonce: Uint8Array, ctTag: Uint8Array): Promise<Uint8Array> {
  const key = await importAesKey(encKey);
  try {
    const pt = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: nonce as unknown as BufferSource, additionalData: new Uint8Array(0) },
      key,
      ctTag as unknown as BufferSource,
    );
    return new Uint8Array(pt);
  } catch {
    throw new ProtocolError(ErrCode.SessionNotEstablished, "AEAD verification failed");
  }
}

/** Assemble the raw frame bytes: nonce(12) ‖ ct ‖ tag(16) ‖ mac(32). */
export function buildFrameBytes(nonce: Uint8Array, ctTag: Uint8Array, mac: Uint8Array): Uint8Array {
  return concat(nonce, ctTag, mac);
}

export interface ParsedFrame {
  nonce: Uint8Array;
  ctTag: Uint8Array;
  mac: Uint8Array;
}

/** Split a raw frame into nonce / ct_tag / mac, validating lengths. */
export function parseFrameBytes(raw: Uint8Array): ParsedFrame {
  const minLen = GCM_NONCE_LEN + GCM_TAG_LEN + FRAME_MAC_LEN;
  if (raw.length < minLen) {
    throw new ProtocolError(ErrCode.SessionNotEstablished, "frame too short");
  }
  const macEnd = raw.length - FRAME_MAC_LEN;
  return { nonce: raw.slice(0, GCM_NONCE_LEN), ctTag: raw.slice(GCM_NONCE_LEN, macEnd), mac: raw.slice(macEnd) };
}

// --- session cipher (AES-256-GCM + outer HMAC envelope) ------------------------------

export interface OpenedMessage {
  seq: number;
  body: AppMessage;
}

/** Serialize an AppMessage exactly as serde does: snake_case `type` tag first, fields in declaration order. */
export function serializeAppMessage(body: AppMessage): Uint8Array {
  return encodeUtf8(JSON.stringify(body));
}

function u64Le(value: number): Uint8Array {
  const out = new Uint8Array(8);
  new DataView(out.buffer).setBigUint64(0, BigInt(value), true);
  return out;
}

/**
 * Authenticated session envelope (e2e.rs Session):
 *   frame = nonce(12) ‖ AES-256-GCM(enc_key, nonce, seq(8 LE)‖payload, aad="") ‖
 *           HMAC-SHA256(mac_key, nonce‖ct_tag)
 *   seq monotonic per direction; first outbound seq = 1; reject inbound seq ≤ max.
 */
export class SessionCipher {
  private readonly encKeyBytes: Uint8Array;
  private readonly macKeyBytes: Uint8Array;
  private outSeq = 0;
  private recvSeq = 0;

  constructor(encKeyBytes: Uint8Array, macKeyBytes: Uint8Array) {
    this.encKeyBytes = encKeyBytes;
    this.macKeyBytes = macKeyBytes;
  }

  /** Encrypt one application message → SessionFrame {type:"e2e", v, frame: b64}. */
  async seal(body: AppMessage): Promise<SessionFrame> {
    const seq = this.outSeq + 1;
    const plaintext = concat(u64Le(seq), serializeAppMessage(body));
    const nonce = crypto.getRandomValues(new Uint8Array(GCM_NONCE_LEN));
    const ctTag = await encryptPayload(this.encKeyBytes, nonce, plaintext);
    const mac = await frameMac(this.macKeyBytes, nonce, ctTag);
    this.outSeq = seq;
    return { type: "e2e", v: PROTOCOL_VERSION, frame: b64encode(buildFrameBytes(nonce, ctTag, mac)) };
  }

  /** Decrypt + authenticate a session frame → { seq, body } (Rust decrypt ordering). */
  async open(frame: SessionFrame): Promise<OpenedMessage> {
    if (!frame || frame.type !== "e2e" || frame.v !== PROTOCOL_VERSION) {
      throw new ProtocolError(ErrCode.SessionNotEstablished, "malformed session frame");
    }
    let raw: Uint8Array;
    try {
      raw = b64decode(frame.frame);
    } catch {
      throw new ProtocolError(ErrCode.SessionNotEstablished, "malformed session frame encoding");
    }
    const { nonce, ctTag, mac } = parseFrameBytes(raw);
    const ok = await verifyFrameMac(this.macKeyBytes, nonce, ctTag, mac);
    if (!ok) {
      throw new ProtocolError(ErrCode.SessionNotEstablished, "frame MAC verification failed");
    }
    const plaintext = await decryptPayload(this.encKeyBytes, nonce, ctTag);
    if (plaintext.length < 8) {
      throw new ProtocolError(ErrCode.SessionNotEstablished, "malformed frame plaintext");
    }
    const seq = Number(new DataView(plaintext.buffer, plaintext.byteOffset, 8).getBigUint64(0, true));
    if (seq <= this.recvSeq) {
      throw new ProtocolError(ErrCode.SessionNotEstablished, "out-of-order or replayed session frame");
    }
    this.recvSeq = seq;
    let body: unknown;
    try {
      body = JSON.parse(decodeUtf8(plaintext.slice(8)));
    } catch {
      throw new ProtocolError(ErrCode.SessionNotEstablished, "malformed frame payload JSON");
    }
    if (typeof body !== "object" || body === null || !("type" in (body as Record<string, unknown>))) {
      throw new ProtocolError(ErrCode.SessionNotEstablished, "malformed frame payload");
    }
    return { seq, body: body as AppMessage };
  }
}

// --- client handshake -----------------------------------------------------------------

/**
 * E2E initiator (extension side). Mirrors cf-browser InitiatorHandshake:
 *   start() → msg1 Init; processReply(msg2) → verifies pin + signature, derives the
 *   session key (ee‖es), emits msg3 Confirm; the established SessionCipher handles all
 *   subsequent traffic. Any verification failure → 8004 (fail closed).
 */
export class E2EClient {
  private ephKeyPair: CryptoKeyPair | null = null;
  private eInitPub: Uint8Array | null = null;
  private cipher: SessionCipher | null = null;
  private readonly brokerEcdsa: Promise<CryptoKey>;
  private readonly brokerEcdh: Promise<CryptoKey>;

  constructor(
    private readonly pairing: PairingMaterial,
    opts?: { ephKeyPair?: CryptoKeyPair },
  ) {
    if (pairing.brokerPublicKeyRaw.length !== SEC1_LEN || pairing.brokerPublicKeyRaw[0] !== 0x04) {
      throw new ProtocolError(ErrCode.SessionNotEstablished, "invalid pinned broker public key");
    }
    this.brokerEcdsa = importRawEcdsaPublicKey(pairing.brokerPublicKeyRaw);
    this.brokerEcdh = importRawPublicKey(pairing.brokerPublicKeyRaw);
    this.ephKeyPair = opts?.ephKeyPair ?? null;
  }

  /** Step 1: emit initiator ephemeral → msg1 Init (SEC1 hex). */
  async start(): Promise<InitFrame> {
    if (!this.ephKeyPair) this.ephKeyPair = await generateEphemeralKeyPair();
    this.eInitPub = await exportRawPublicKey(this.ephKeyPair.publicKey);
    return { type: "init", version: PROTOCOL_VERSION, e_init: hexEncode(this.eInitPub) };
  }

  /** Step 2: verify msg2 (pin + signature), derive session key, emit msg3 Confirm. */
  async processReply(resp: ResponseFrame): Promise<{ confirm: ConfirmFrame; session: SessionCipher }> {
    if (!this.ephKeyPair || !this.eInitPub) {
      throw new ProtocolError(ErrCode.SessionNotEstablished, "start() not called");
    }
    if (!resp || resp.type !== "response" || resp.version !== PROTOCOL_VERSION) {
      throw new ProtocolError(ErrCode.SessionNotEstablished, "malformed response frame");
    }
    let eRespPub: Uint8Array;
    let pkB: Uint8Array;
    let sig: Uint8Array;
    try {
      eRespPub = hexDecode(resp.e_resp);
      pkB = hexDecode(resp.pk_b);
      sig = hexDecode(resp.signature);
    } catch {
      throw new ProtocolError(ErrCode.SessionNotEstablished, "malformed response encoding");
    }
    if (eRespPub.length !== SEC1_LEN || eRespPub[0] !== 0x04) {
      throw new ProtocolError(ErrCode.SessionNotEstablished, "bad broker ephemeral");
    }
    if (pkB.length !== SEC1_LEN || pkB[0] !== 0x04) {
      throw new ProtocolError(ErrCode.SessionNotEstablished, "bad broker public key");
    }
    if (sig.length !== ECDSA_SIG_LEN) {
      throw new ProtocolError(ErrCode.SessionNotEstablished, "bad signature length");
    }

    // 1. Broker public key must equal the pinned key (MITM / key swap).
    if (!bytesEqual(pkB, this.pairing.brokerPublicKeyRaw)) {
      throw new ProtocolError(ErrCode.SessionNotEstablished, "broker public key does not match pinned key");
    }
    // 2. Verify the identity-bound signature over e_init_pub‖e_resp_pub.
    const message = buildSigMessage(this.eInitPub, eRespPub);
    const ok = await verifySignature(await this.brokerEcdsa, message, sig);
    if (!ok) {
      throw new ProtocolError(ErrCode.SessionNotEstablished, "broker signature verification failed");
    }
    // 3. Derive session key: ee = ECDH(eph_ext, e_resp), es = ECDH(eph_ext, pk_b).
    const brokerEphPub = await importRawPublicKey(eRespPub);
    const { ee, es } = await deriveClientSharedSecrets(this.ephKeyPair.privateKey, brokerEphPub, await this.brokerEcdh);
    const keys = await deriveSessionKeys(ee, es, this.eInitPub, eRespPub);
    // 4. msg3 confirm token = HMAC(PSK, okm).
    const confirm = await computeConfirm(this.pairing.psk, keys.okm);
    this.cipher = new SessionCipher(keys.encKey, keys.macKey);
    return {
      confirm: { type: "confirm", version: PROTOCOL_VERSION, p: hexEncode(confirm) },
      session: this.cipher,
    };
  }

  isReady(): boolean {
    return this.cipher !== null;
  }

  async seal(body: AppMessage): Promise<SessionFrame> {
    if (!this.cipher) {
      throw new ProtocolError(ErrCode.SessionNotEstablished, "session not established");
    }
    return this.cipher.seal(body);
  }

  async open(frame: SessionFrame): Promise<OpenedMessage> {
    if (!this.cipher) {
      throw new ProtocolError(ErrCode.SessionNotEstablished, "session not established");
    }
    return this.cipher.open(frame);
  }
}

// --- helpers -------------------------------------------------------------------------

function concat(...parts: Uint8Array[]): Uint8Array {
  const total = parts.reduce((n, p) => n + p.length, 0);
  const out = new Uint8Array(total);
  let off = 0;
  for (const p of parts) {
    out.set(p, off);
    off += p.length;
  }
  return out;
}

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i]! ^ b[i]!;
  return diff === 0;
}
