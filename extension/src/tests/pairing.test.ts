/**
 * Pairing integration tests (design §5/§7 X group, lead contract points 1-6). Three layers:
 *
 * 1. STATE MACHINE (pure, chrome-free): the pairing phase transitions of §5.1 / §8 —
 *    idle --start--> pairing; pairing --result{approved}--> approved;
 *    pairing --result{rejected}--> rejected; pairing --disconnect--> app_unavailable (决策⑥);
 *    pairing --timeout(120s)--> idle (§8.3); retry out of app_unavailable/rejected.
 *    Driven through src/pairing_state.ts (dependency-free), not the chrome-glue background.
 *
 * 2. FRAME CODECS: buildPairRequest / pairResultToMaterial — the pair_request wire shape and
 *    the approved pair_result -> PairingMaterial decode with fail-closed validation
 *    (32 B PSK, 65 B SEC1 pk_b, hex).
 *
 * 3. MOCK-BROKER PAIRING PATH: pair_request -> pair_result{approved} -> PairingMaterial
 *    -> E2EClient handshake against the same MockBroker succeeds. This pins the frozen
 *    contract invariant: pair_result.psk / pair_result.pk_b are exactly what the broker
 *    uses for msg3 confirm / msg2 pin (design §3.1 constructive consistency).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import {
  buildPairRequest,
  pairResultToMaterial,
  hexEncode,
  hexDecode,
  ErrCode,
  SEC1_LEN,
  type PairResultFrame,
} from "../protocol";
import {
  pairingTransition,
  pairingOutcome,
  PAIRING_TIMEOUT_MS,
  type PairingPhase,
  type PairingEvent,
} from "../pairing_state";
import { MockBroker } from "./mock_broker";
import { E2EClient, generateBrokerIdentity, exportRawPublicKey } from "../crypto/e2e";

const hx = (s: string): Uint8Array => hexDecode(s);

// ===================================================================================
// 1. Pairing state machine (§5.1 / §8, pure)
// ===================================================================================

test("state machine: idle --start--> pairing (§5.1)", () => {
  assert.deepEqual(pairingTransition({ kind: "idle" }, { kind: "start" }), { kind: "pairing" });
});

test("state machine: pairing --result{approved}--> approved (§5.1)", () => {
  assert.deepEqual(pairingTransition({ kind: "pairing" }, { kind: "result", approved: true }), { kind: "approved" });
});

test("state machine: pairing --result{rejected}--> rejected — popup 配对已拒绝 (8006 语义)", () => {
  assert.deepEqual(pairingTransition({ kind: "pairing" }, { kind: "result", approved: false }), { kind: "rejected" });
  assert.equal(pairingOutcome({ kind: "rejected" }).status, "idle");
  assert.equal(pairingOutcome({ kind: "rejected" }).defaultErrorCode, ErrCode.UserRejected);
});

test("state machine: pairing --disconnect--> app_unavailable — 决策⑥ explicit hint, no silent fail", () => {
  assert.deepEqual(pairingTransition({ kind: "pairing" }, { kind: "disconnect" }), { kind: "app_unavailable" });
  assert.equal(pairingOutcome({ kind: "app_unavailable" }).status, "idle");
  assert.equal(pairingOutcome({ kind: "app_unavailable" }).defaultErrorCode, ErrCode.BrokerUnavailable);
});

test("state machine: pairing --timeout--> idle — 120s 超时回到未配对态 (§8.3, lead point 4)", () => {
  assert.deepEqual(pairingTransition({ kind: "pairing" }, { kind: "timeout" }), { kind: "idle" });
  assert.equal(PAIRING_TIMEOUT_MS, 120_000);
});

test("state machine: idle ignores non-start events (disconnect/timeout/result outside pairing)", () => {
  const idle: PairingPhase = { kind: "idle" };
  for (const ev of [{ kind: "disconnect" }, { kind: "timeout" }, { kind: "result", approved: true }] as PairingEvent[]) {
    assert.deepEqual(pairingTransition(idle, ev), idle);
  }
});

test("state machine: single-flight — pairing --start--> pairing (lead point 5: 不排队/回拒)", () => {
  assert.deepEqual(pairingTransition({ kind: "pairing" }, { kind: "start" }), { kind: "pairing" });
});

test("state machine: retry out of app_unavailable / rejected — start re-enters pairing (lead point 6 保留重试)", () => {
  assert.deepEqual(pairingTransition({ kind: "app_unavailable" }, { kind: "start" }), { kind: "pairing" });
  assert.deepEqual(pairingTransition({ kind: "rejected" }, { kind: "start" }), { kind: "pairing" });
});

test("state machine: outcomes map to SessionState status", () => {
  assert.equal(pairingOutcome({ kind: "idle" }).status, "idle");
  assert.equal(pairingOutcome({ kind: "pairing" }).status, "pairing");
  assert.equal(pairingOutcome({ kind: "approved" }).status, "connecting");
});

// ===================================================================================
// 2. Frame codecs (§2.3 / §7 X)
// ===================================================================================

test("pair_request frame: buildPairRequest emits type/browser/extension_id (蛇形契约)", () => {
  const frame = buildPairRequest("chrome", "abcdefghijklmnopabcdefghijklmnop");
  assert.deepEqual(frame, {
    type: "pair_request",
    browser: "chrome",
    extension_id: "abcdefghijklmnopabcdefghijklmnop",
  });
  for (const kind of ["chrome", "edge", "firefox"] as const) {
    assert.equal(buildPairRequest(kind, "id").browser, kind);
  }
});

test("pair_result frame: approved payload decodes into PairingMaterial (32 B psk, 65 B SEC1 pk_b)", () => {
  const pkB = crypto.getRandomValues(new Uint8Array(SEC1_LEN));
  pkB[0] = 0x04;
  const psk = crypto.getRandomValues(new Uint8Array(32));
  const result: PairResultFrame = {
    type: "pair_result",
    approved: true,
    psk: hexEncode(psk),
    pk_b: hexEncode(pkB),
  };
  const material = pairResultToMaterial(result);
  assert.ok(material, "approved pair_result must parse");
  assert.deepEqual(material.psk, psk);
  assert.deepEqual(material.brokerPublicKeyRaw, pkB);
});

test("pair_result frame: approved:false → null (no keys carried, lead point 3)", () => {
  assert.equal(
    pairResultToMaterial({ type: "pair_result", approved: false, error: ErrCode.UserRejected }),
    null,
  );
});

test("pair_result frame: malformed payload fails closed (missing / short / non-SEC1 pk_b)", () => {
  const pkB = crypto.getRandomValues(new Uint8Array(SEC1_LEN));
  pkB[0] = 0x04;
  const psk = crypto.getRandomValues(new Uint8Array(32));

  // missing keys
  assert.equal(pairResultToMaterial({ type: "pair_result", approved: true }), null);
  // psk wrong length (16 B)
  assert.equal(
    pairResultToMaterial({ type: "pair_result", approved: true, psk: hexEncode(psk.slice(0, 16)), pk_b: hexEncode(pkB) }),
    null,
  );
  // pk_b not a SEC1 point (0x03 compressed prefix)
  const compressed = new Uint8Array(pkB);
  compressed[0] = 0x03;
  assert.equal(
    pairResultToMaterial({ type: "pair_result", approved: true, psk: hexEncode(psk), pk_b: hexEncode(compressed) }),
    null,
  );
  // odd-length hex
  assert.equal(
    pairResultToMaterial({ type: "pair_result", approved: true, psk: "0a0b", pk_b: hexEncode(pkB).slice(0, 3) }),
    null,
  );
});

// ===================================================================================
// 3. Mock-broker pairing path (pair_result material must drive the real handshake)
// ===================================================================================

test("pairing path: pair_request -> approved pair_result -> E2E handshake succeeds", async () => {
  const identity = await generateBrokerIdentity();
  const psk = crypto.getRandomValues(new Uint8Array(32));
  const mock = new MockBroker(identity, psk);

  // 1. Extension initiates pairing (frame codec).
  const req = buildPairRequest("chrome", "ext-id-123");
  // 2. Broker serves the approval with its own psk + self-reported pk_b (design §3.1).
  const result = await mock.onPairRequest(req);
  assert.equal(result.type, "pair_result");
  assert.equal(result.approved, true);
  assert.equal(result.psk, hexEncode(psk));
  assert.equal(result.pk_b, hexEncode(await mock.publicKeyRaw()));

  // 3. Extension decodes + pins.
  const material = pairResultToMaterial(result);
  assert.ok(material);
  assert.deepEqual(material.psk, psk);
  assert.deepEqual(material.brokerPublicKeyRaw, await mock.publicKeyRaw());

  // 4. 分连接 (lead point 1): fresh E2E handshake against the SAME broker identity.
  const client = new E2EClient(material);
  const init = await client.start();
  const resp = await mock.onInit(init);
  // Contract invariant (§3.1): pair_result.pk_b ≡ msg2.pk_b (constructive consistency).
  assert.equal(resp.pk_b, result.pk_b);
  const { confirm } = await client.processReply(resp);
  await mock.onConfirm(confirm);
  assert.equal(mock.isReady(), true);
  assert.equal(client.isReady(), true);
});

test("pairing path: rejected pair_result leaves the extension unpaired (approved:false, no material)", async () => {
  const identity = await generateBrokerIdentity();
  const psk = crypto.getRandomValues(new Uint8Array(32));
  const mock = new MockBroker(identity, psk);

  const req = buildPairRequest("firefox", "ext-id-456");
  const result = await mock.onPairRequest(req, { approved: false });
  assert.equal(result.type, "pair_result");
  assert.equal(result.approved, false);
  assert.equal(result.error, ErrCode.UserRejected);
  assert.equal(result.psk, undefined);
  assert.equal(result.pk_b, undefined);
  // Fail-closed: no material to pin, extension stays unpaired.
  assert.equal(pairResultToMaterial(result), null);
  assert.deepEqual(pairingTransition({ kind: "pairing" }, { kind: "result", approved: false }), { kind: "rejected" });
});

test("pairing path: malformed pair_request rejected by the broker (fail fast, 8004)", async () => {
  const identity = await generateBrokerIdentity();
  const mock = new MockBroker(identity, crypto.getRandomValues(new Uint8Array(32)));
  await assert.rejects(
    mock.onPairRequest({ type: "pair_request" } as never),
    (e: unknown) => e instanceof Error,
  );
  await assert.rejects(
    mock.onPairRequest({ type: "pair_request", browser: "chrome", extension_id: "" }),
    (e: unknown) => e instanceof Error,
  );
});
