/**
 * Pure pairing phase state machine (design §5.1 / §8 — frozen). Chrome-free by design so
 * the transitions are unit-testable (src/tests/pairing.test.ts); background.ts maps the
 * outcome onto the SessionState it broadcasts.
 *
 * States (§5.1):
 *   idle (未配对) --start--> pairing
 *   pairing --result{approved}--> approved (background persists + reopens E2E — 分连接 §8.4)
 *   pairing --result{rejected}--> rejected (popup「配对已拒绝」, 8006)
 *   pairing --disconnect--> app_unavailable (决策⑥「请打开 Coffer 并启用浏览器集成」)
 *   pairing --timeout(120s)--> idle (§8.3 — 超时回到未配对态, lead point 4)
 *   app_unavailable / rejected --start--> pairing (retry, lead point 6)
 *   pairing --start--> pairing (single-flight, lead point 5 — 不排队)
 */
import { ErrCode } from "./protocol";

export type PairingPhase =
  | { kind: "idle" }
  | { kind: "pairing" }
  | { kind: "approved" }
  | { kind: "app_unavailable" }
  | { kind: "rejected" };

export type PairingEvent =
  | { kind: "start" }
  | { kind: "result"; approved: boolean }
  | { kind: "disconnect" }
  | { kind: "timeout" };

/** Pairing approval timeout — 120 s (§8.3 frozen, lead point 4). */
export const PAIRING_TIMEOUT_MS = 120_000;

export function pairingTransition(phase: PairingPhase, event: PairingEvent): PairingPhase {
  switch (phase.kind) {
    case "idle":
      return event.kind === "start" ? { kind: "pairing" } : phase;
    case "pairing":
      switch (event.kind) {
        case "result":
          return event.approved ? { kind: "approved" } : { kind: "rejected" };
        case "disconnect":
          return { kind: "app_unavailable" };
        case "timeout":
          return { kind: "idle" };
        case "start":
          return phase; // single-flight
      }
      return phase;
    case "approved":
      return event.kind === "start" ? { kind: "pairing" } : phase;
    case "app_unavailable":
    case "rejected":
      return event.kind === "start" ? { kind: "pairing" } : phase;
  }
}

export interface PairingOutcome {
  status: "idle" | "pairing" | "connecting";
  defaultErrorCode?: number;
}

/** SessionState-relevant mapping for a pairing phase (background surfaces errorCode). */
export function pairingOutcome(phase: PairingPhase): PairingOutcome {
  switch (phase.kind) {
    case "idle":
      return { status: "idle" };
    case "pairing":
      return { status: "pairing" };
    case "approved":
      return { status: "connecting" };
    case "app_unavailable":
      return { status: "idle", defaultErrorCode: ErrCode.BrokerUnavailable };
    case "rejected":
      return { status: "idle", defaultErrorCode: ErrCode.UserRejected };
  }
}
