/**
 * Fill last-hop authorization (Wave-4 HIGH-1 hardening, G-R).
 *
 * Pure decision module (no browser APIs — unit-tested under Node). The plaintext write
 * must land ONLY on the field elements captured at the user's focusin (menu trigger),
 * never on fields re-found at write time: a page could have prepended a decoy
 * `<input type=password>` after the menu opened (a re-find would pick passwords[0] =
 * decoy and the real password would leak to page JS), or navigated the frame so the
 * fill lands in a foreign document.
 *
 * Fail-closed: any doubt (no captured target, origin drift, captured field removed,
 * form action no longer same-origin) → reject, no fill.
 */
export type FillRejectReason =
  | "no_target" // no captured field refs in this frame (fresh document / nothing focused)
  | "origin_mismatch" // document origin ≠ approved origin (navigation to another site)
  | "target_disconnected" // captured password field was removed from the DOM (swap/teardown)
  | "cross_origin_action"; // captured form's action no longer submits same-origin (enemy action)

/** The field refs captured at focusin, plus the checks evaluated at write time. */
export interface CapturedFillTarget {
  usernameEl: unknown;
  passwordEl: unknown;
  usernameConnected: boolean;
  passwordConnected: boolean;
  /** Does the captured form still submit to the document origin? */
  sameOriginAction: boolean;
}

export interface FillAuthorization {
  ok: boolean;
  reason?: FillRejectReason;
  /** Only present when ok: the exact elements to write to (the captured refs). */
  targets?: { usernameEl: unknown; passwordEl: unknown };
}

export function authorizeFill(opts: {
  approvedOrigin: string;
  currentOrigin: string;
  target: CapturedFillTarget | null;
}): FillAuthorization {
  if (!opts.target) return { ok: false, reason: "no_target" };
  if (opts.currentOrigin !== opts.approvedOrigin) return { ok: false, reason: "origin_mismatch" };
  if (!opts.target.passwordConnected) return { ok: false, reason: "target_disconnected" };
  if (!opts.target.sameOriginAction) return { ok: false, reason: "cross_origin_action" };
  return {
    ok: true,
    targets: {
      usernameEl: opts.target.usernameConnected ? opts.target.usernameEl : null,
      passwordEl: opts.target.passwordEl,
    },
  };
}
