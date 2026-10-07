/**
 * E2E protocol tests (docs/31 §3.3). Two layers:
 *
 * 1. CROSS-LANGUAGE KAT (the interop lock): re-derive the cf-browser frozen vectors
 *    (core/cf-browser/tests/e2e_kat.rs, independent-Python-primed) in JS with WebCrypto
 *    and assert every value byte-for-byte — session keys, confirm token, msg2 signature
 *    verification, and the full per-message frame. This is what actually pins the two
 *    implementations to each other (docs/32 §5 cross-language contract face).
 *
 * 2. Two-way mock-broker handshake + negative cases (isolation, wrong pin, wrong PSK,
 *    tamper, replay) and gesture format/TTL.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import {
  E2EClient,
  SessionCipher,
  assembleEcdhKeyPair,
  deriveSessionKeys,
  computeConfirm,
  verifySignature,
  buildSigMessage,
  encryptPayload,
  frameMac,
  buildFrameBytes,
  generateBrokerIdentity,
  exportRawPublicKey,
  importEcJwkPrivate,
  importRawEcdsaPublicKey,
  importRawPublicKey,
  sec1ToXY,
  ecdhShared,
  hkdfBytes,
  type PairingMaterial,
} from "../crypto/e2e";
import {
  PROTOCOL_VERSION,
  GESTURE_TTL_MS,
  ECDSA_SIG_LEN,
  ProtocolError,
  ErrCode,
  b64encode,
  b64decode,
  b64urlEncode,
  hexEncode,
  hexDecode,
  encodeUtf8,
  makeGesture,
  parseGesture,
  gestureWithinTtl,
  type AppMessage,
} from "../protocol";
import { MockBroker } from "./mock_broker";

// --- frozen vectors (e2e_kat.rs) -----------------------------------------------------

const DEK = "4242424242424242424242424242424242424242424242424242424242424242";
const VAULT_UUID = "11111111111111111111111111111111";
const E_INIT_PRIV = "101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f";
const E_RESP_PRIV = "303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f";
const PSK = "505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f";
const FRAME_NONCE = "a0a1a2a3a4a5a6a7a8a9aaab";

const SEED = "21bf849cce3b2f62246098bae6adeab591b6ddf4bc80e8f68a71e3a407e16093";
const PK_B = "047f6d0fa52e7f430c2ab0947c0271f241bb3ae2a853cb5025c8008131fcd79ee201ff4953a2842535094aaf8b98b4f7ce7e4c1fc500ba885a2bdfb39911993bf5";
const E_INIT_PUB = "048e71ca9d7a62917be7f0db9896b47bf9b91c8b86628eed55d47fe750e65e5bcb75937f2ef48092880eaa8335c33f344c181e9de1797f239955a0bb2d56f84099";
const E_RESP_PUB = "048ed57ec2b8f5e75e9192327b51e5661c87c8e5db0170721309a517fc6e1046b15481e8ae3b39d323778e451cb1efeb541e1325a7667edd877c68faf705007575";
const EE = "127ad1f6c80cce916e0c123831003369ee321654c8841412456d23742d0e4c25";
const ES = "73d838d2da5d0b3f70b60b9ea85ff71095582c21c9f2cfe942d4706029836e3c";
const OKM = "37cda6c871a2141e6d20cff7214874cd5933937a2939065397cd2e40acd31ebe4ec75e27d834d2d34e4d0d2990409dcd1806ec0fcb7a4e5d591e3874959b3b44";
const ENC_KEY = "37cda6c871a2141e6d20cff7214874cd5933937a2939065397cd2e40acd31ebe";
const MAC_KEY = "4ec75e27d834d2d34e4d0d2990409dcd1806ec0fcb7a4e5d591e3874959b3b44";
const P_CONFIRM = "b591b4c925e15a85a094c00e0d430933d3c091db476a4bd00c4dedf675c4e2c8";
const SIG = "411040076db3a5c33e781153df25cebab4efc9560923556ec260dcade96c4cd38281271885aff8412010c49c331fbb5682a89249f6017aaab63004e94651123f";
// 2026-10-08 多字段契约重算（request_id=1, fields=["username","password"], seq=1）——
// e2e_kat.rs FROZEN_FRAME 冻结 hex，md5 = FROZEN_FRAME_MD5。
const PLAINTEXT = "01000000000000007b2274797065223a226765745f736563726574222c22726571756573745f6964223a312c22656e747279223a2264656d6f222c226669656c6473223a5b22757365726e616d65222c2270617373776f7264225d2c226f726967696e223a2268747470733a2f2f6578616d706c652e636f6d222c2267657374757265223a22616263313233227d";
const CT_TAG = "7e789f2a03990e20a5f9f8ab5ec192565477852420534670a3c40b58139f46517fe00c7232273348124fa3e432d3215ac7f32d49bec482396c43f05caa7d0aea96af88db45423b1fb6a27c4d79316b2c74e673c52f7ccb9f5edc8c25d2392d0658d51745d76a27e5b38bd9c48d587589bd7132e060e4cd97ecc423c9487304d80c7f06bcccbf6f57bf5587f0fb5547fb5378bd4d632210e4838e0b59628e";
const MAC = "f480c97f3927313bec96f92152e3836eed3faeda4233d5f8fe7e572d5f549a34";
const FROZEN_FRAME = "a0a1a2a3a4a5a6a7a8a9aaab" + CT_TAG + MAC;
const FROZEN_FRAME_MD5 = "ef82fd23434b8857f010e7fadb93c057"; // G-A 2026-10-08 多字段重算锚

const hx = (s: string): Uint8Array => hexDecode(s);
const eqHex = (actual: Uint8Array, expected: string): void => assert.equal(hexEncode(actual), expected);

/** Frozen broker static keypair (ECDSA sign + same scalar as ECDH) from SEED/PK_B. */
async function frozenBrokerKeyPair(): Promise<CryptoKeyPair> {
  const { x, y } = sec1ToXY(hx(PK_B));
  // Node rejects `verify` on an ECDSA *private* key — sign only (public half verifies).
  const privateKey = await importEcJwkPrivate(x, y, hx(SEED), "ECDSA", ["sign"]);
  const publicKey = await importRawEcdsaPublicKey(hx(PK_B));
  return { privateKey, publicKey };
}

function frozenPairing(): PairingMaterial {
  return { brokerPublicKeyRaw: hx(PK_B), psk: hx(PSK) };
}

function u64Le(value: number): Uint8Array {
  const out = new Uint8Array(8);
  new DataView(out.buffer).setBigUint64(0, BigInt(value), true);
  return out;
}

// ===================================================================================
// 1. CROSS-LANGUAGE KAT (frozen vectors — docs/31 §3.3, e2e_kat.rs)
// ===================================================================================

test("kat: broker identity seed derivation matches frozen (HKDF(salt=uuid, ikm=DEK))", async () => {
  const seed = await hkdfBytes(hx(DEK), hx(VAULT_UUID), encodeUtf8("cf/browser/v1"), 32);
  eqHex(seed, SEED);
});

test("kat: session keys (ee/es/okm/enc/mac) match frozen byte-for-byte", async () => {
  const eInit = await assembleEcdhKeyPair(hx(E_INIT_PUB), hx(E_INIT_PRIV));

  const ee = await ecdhShared(eInit.privateKey, await importRawPublicKey(hx(E_RESP_PUB)));
  const es = await ecdhShared(eInit.privateKey, await importRawPublicKey(hx(PK_B)));
  eqHex(ee, EE);
  eqHex(es, ES);

  const keys = await deriveSessionKeys(ee, es, hx(E_INIT_PUB), hx(E_RESP_PUB));
  eqHex(keys.okm, OKM);
  eqHex(keys.encKey, ENC_KEY);
  eqHex(keys.macKey, MAC_KEY);
});

test("kat: confirm token p = HMAC(PSK, okm) matches frozen", async () => {
  const p = await computeConfirm(hx(PSK), hx(OKM));
  eqHex(p, P_CONFIRM);
});

test("kat: msg2 signature (ECDSA over e_init‖e_resp) verifies with frozen sig", async () => {
  const pk = await importRawEcdsaPublicKey(hx(PK_B));
  const message = buildSigMessage(hx(E_INIT_PUB), hx(E_RESP_PUB));
  const sig = hx(SIG);
  assert.equal(sig.length, ECDSA_SIG_LEN);
  assert.equal(await verifySignature(pk, message, sig), true);

  const tampered = hx(E_INIT_PUB);
  tampered[10]! ^= 0x01;
  assert.equal(await verifySignature(pk, buildSigMessage(tampered, hx(E_RESP_PUB)), sig), false);
});

test("kat: frame primitives (plaintext/ct_tag/mac/frame) match frozen byte-for-byte", async () => {
  const enc = hx(ENC_KEY);
  const macKey = hx(MAC_KEY);
  const nonce = hx(FRAME_NONCE);

  // Plaintext: seq(1, LE) ‖ exact serde JSON of multi-field get_secret (frozen field order:
  // type, request_id, entry, fields, origin, gesture — matches Rust serde declaration order).
  const plaintext = new Uint8Array([
    ...u64Le(1),
    ...encodeUtf8('{"type":"get_secret","request_id":1,"entry":"demo","fields":["username","password"],"origin":"https://example.com","gesture":"abc123"}'),
  ]);
  eqHex(plaintext, PLAINTEXT);

  const ctTag = await encryptPayload(enc, nonce, plaintext);
  eqHex(ctTag, CT_TAG);

  const mac = await frameMac(macKey, nonce, ctTag);
  eqHex(mac, MAC);

  eqHex(buildFrameBytes(nonce, ctTag, mac), FROZEN_FRAME);
  assert.equal(createHash("md5").update(hx(FROZEN_FRAME)).digest("hex"), FROZEN_FRAME_MD5);
});

test("kat: session decrypts the frozen frame (seq=1, multi-field get_secret) and rejects replay", async () => {
  const session = new SessionCipher(hx(ENC_KEY), hx(MAC_KEY));
  const opened = await session.open({ type: "e2e", v: PROTOCOL_VERSION, frame: b64encode(hx(FROZEN_FRAME)) });
  assert.equal(opened.seq, 1);
  const body = opened.body as { type: string; request_id: number; entry: string; fields: string[]; origin: string; gesture: string };
  assert.equal(body.type, "get_secret");
  assert.equal(body.request_id, 1);
  assert.equal(body.entry, "demo");
  assert.deepEqual(body.fields, ["username", "password"]);
  assert.equal(body.origin, "https://example.com");
  assert.equal(body.gesture, "abc123");

  // Same frame replayed (seq 1 ≤ max seen) → rejected.
  await assert.rejects(
    session.open({ type: "e2e", v: PROTOCOL_VERSION, frame: b64encode(hx(FROZEN_FRAME)) }),
    (e: unknown) => e instanceof ProtocolError && e.code === ErrCode.SessionNotEstablished,
  );
});

test("kat: full handshake with fixed ephemerals → frozen confirm + interoperating session", async () => {
  const eInit = await assembleEcdhKeyPair(hx(E_INIT_PUB), hx(E_INIT_PRIV));
  const eResp = await assembleEcdhKeyPair(hx(E_RESP_PUB), hx(E_RESP_PRIV));
  const brokerPair = await frozenBrokerKeyPair();

  const client = new E2EClient(frozenPairing(), { ephKeyPair: eInit });
  const init = await client.start();
  assert.equal(init.e_init, E_INIT_PUB);

  const mock = new MockBroker(brokerPair, hx(PSK), { eRespKeyPair: eResp });
  const resp = await mock.onInit(init);
  assert.equal(resp.pk_b, PK_B);

  const { confirm, session } = await client.processReply(resp);
  assert.equal(confirm.p, P_CONFIRM); // full-chain okm consistency with Rust
  await mock.onConfirm(confirm);
  assert.equal(mock.isReady(), true);

  // Two-way round trip over the established session.
  const req: AppMessage = { type: "get_secret", request_id: 1, entry: "demo", fields: ["username", "password"], origin: "https://example.com", gesture: "abc123" };
  const sealed = await client.seal(req);
  const got = await mock.open(sealed);
  assert.deepEqual(got.body, req);

  const respMsg: AppMessage = { type: "get_secret_result", request_id: 1, values: { username: "demo-user", password: "s3cr3t" } };
  const sealedResp = await mock.seal(respMsg);
  const gotResp = await client.open(sealedResp);
  assert.deepEqual(gotResp.body, respMsg);
  void session;
});

// ===================================================================================
// 2. Two-way mock-broker handshake + negative cases
// ===================================================================================

/** One broker identity, both the pairing (client pin) and the mock responder share it. */
async function randomIdentityPairing(): Promise<{ pairing: PairingMaterial; identity: CryptoKeyPair; psk: Uint8Array }> {
  const identity = await generateBrokerIdentity();
  const psk = crypto.getRandomValues(new Uint8Array(32));
  return { pairing: { brokerPublicKeyRaw: await exportRawPublicKey(identity.publicKey), psk }, identity, psk };
}

async function handshake(pairing: PairingMaterial, identity: CryptoKeyPair, psk: Uint8Array): Promise<{ client: E2EClient; mock: MockBroker }> {
  const client = new E2EClient(pairing);
  const mock = new MockBroker(identity, psk);
  const init = await client.start();
  const resp = await mock.onInit(init);
  const { confirm } = await client.processReply(resp);
  await mock.onConfirm(confirm);
  return { client, mock };
}

test("two-way handshake: random ephemerals, round-trip, tamper + replay rejected", async () => {
  const { pairing, identity, psk } = await randomIdentityPairing();

  const { client, mock } = await handshake(pairing, identity, psk);
  assert.equal(mock.isReady(), true);
  assert.equal(client.isReady(), true);

  const req: AppMessage = { type: "lock" };
  const sealed = await client.seal(req);
  assert.deepEqual((await mock.open(sealed)).body, req);

  // Tampered frame: flip a byte in the ciphertext region → MAC/decrypt fails.
  const tampered = await client.seal(req);
  const raw = b64decode(tampered.frame);
  raw[20]! ^= 0x01;
  await assert.rejects(
    mock.open({ type: "e2e", v: PROTOCOL_VERSION, frame: b64encode(raw) }),
    (e: unknown) => e instanceof ProtocolError && e.code === ErrCode.SessionNotEstablished,
  );

  // Replay of an already-seen frame (seq ≤ max) → rejected.
  await assert.rejects(
    mock.open(sealed),
    (e: unknown) => e instanceof ProtocolError && e.code === ErrCode.SessionNotEstablished,
  );
});

test("session isolation: cross-session decrypt fails (fresh ephemerals)", async () => {
  const { pairing: p1, identity: i1, psk: p1Psk } = await randomIdentityPairing();
  const { client: c1, mock: m1 } = await handshake(p1, i1, p1Psk);

  const { pairing: p2, identity: i2, psk: p2Psk } = await randomIdentityPairing();
  const { client: c2, mock: m2 } = await handshake(p2, i2, p2Psk);

  const fromA = await c1.seal({ type: "lock" });
  await assert.rejects(
    m2.open(fromA), // session B must not decrypt A's frame
    (e: unknown) => e instanceof ProtocolError,
  );
  const fromB = await m1.seal({ type: "locked" });
  await assert.rejects(
    c2.open(fromB),
    (e: unknown) => e instanceof ProtocolError,
  );
});

test("wrong pinned broker key rejected: extension pins A, broker is B", async () => {
  const identityA = await generateBrokerIdentity();
  const identityB = await generateBrokerIdentity();
  const psk = crypto.getRandomValues(new Uint8Array(32));
  const pairing: PairingMaterial = { brokerPublicKeyRaw: await exportRawPublicKey(identityA.publicKey), psk };

  const client = new E2EClient(pairing);
  const mock = new MockBroker(identityB, psk);
  const init = await client.start();
  const resp = await mock.onInit(init);
  await assert.rejects(
    client.processReply(resp),
    (e: unknown) => e instanceof ProtocolError && e.code === ErrCode.SessionNotEstablished,
  );
});

test("wrong PSK rejected: broker refuses the confirm token (8004, no session)", async () => {
  const { pairing, identity, psk: goodPsk } = await randomIdentityPairing();
  const badPsk = new Uint8Array(goodPsk);
  badPsk[0]! ^= 0x01;

  const client = new E2EClient(pairing);
  const mock = new MockBroker(identity, badPsk);
  const init = await client.start();
  const resp = await mock.onInit(init);
  const { confirm } = await client.processReply(resp);
  await assert.rejects(
    mock.onConfirm(confirm),
    (e: unknown) => e instanceof ProtocolError && e.code === ErrCode.SessionNotEstablished,
  );
  assert.equal(mock.isReady(), false);
});

// ===================================================================================
// 3. Gesture format / TTL (docs/31 §6.1, D-7)
// ===================================================================================

test("gesture: format, TTL window, and malformed input", () => {
  const g = makeGesture(1_700_000_000_000);
  const parsed = parseGesture(g);
  assert.ok(parsed);
  assert.equal(parsed.issuedAtMs, 1_700_000_000_000);
  assert.equal(parsed.nonce.length, 16);

  assert.equal(gestureWithinTtl(makeGesture(Date.now() - 5_000)), true);
  assert.equal(gestureWithinTtl(makeGesture(Date.now() - GESTURE_TTL_MS - 1)), false);
  assert.equal(gestureWithinTtl(makeGesture(Date.now() + 60_000)), false); // issued in the future
  assert.equal(gestureWithinTtl(""), false);
  assert.equal(gestureWithinTtl("not-base64!!"), false);
  assert.equal(parseGesture("AAAA"), null); // wrong length
});

test("hex/base64url codecs round-trip", () => {
  const bytes = new Uint8Array([0x00, 0x01, 0xfe, 0xff, 0x42]);
  assert.equal(hexEncode(bytes), "0001feff42");
  assert.deepEqual(hexDecode("0001feff42"), bytes);
  assert.equal(b64urlEncode(new Uint8Array([0xfb, 0xff])), "-_8"); // base64url (no +/=)
  assert.ok(b64decode("QUJD").length === 3);
});
