/**
 * Origin binding — three-type matching (docs/31 §5.3, D-3).
 *
 * Binding types are frozen: `exact` / `subdomain` / `domain`. No regex, no prefix
 * wildcards (regex = misconfiguration + over-broad matching = phishing amplifier).
 * Match priority: exact > subdomain > domain.
 *
 * - exact     "https://example.com:8443"  scheme+host+port, canonical equality (default ports dropped)
 * - subdomain "*.example.com"             any subdomain, never the apex
 * - domain    "example.com"               apex + all subdomains, host-only (scheme/port agnostic)
 *
 * Pure module: no browser APIs. Unit-tested under Node (src/tests/origin.test.ts).
 */

export type OriginBindingType = "exact" | "subdomain" | "domain";

export interface OriginBinding {
  type: OriginBindingType;
  /** Human-entered pattern: full origin (exact) or hostname with optional `*.` (subdomain/domain). */
  pattern: string;
}

export interface ParsedOrigin {
  scheme: "http" | "https";
  host: string;
  port: number | null;
  /** Canonical form via URL.origin semantics (default ports dropped, lowercase). */
  canonical: string;
}

export interface ValidatedBinding {
  type: OriginBindingType;
  /** Normalized pattern (lowercase, canonical). */
  pattern: string;
  /** Normalized base hostname for subdomain/domain; null for exact. */
  baseHost: string | null;
}

const MAX_HOSTNAME_LENGTH = 253;

/** Lowercase and strip a single trailing dot. Does not validate. */
function normalizeHost(host: string): string {
  let h = host.trim().toLowerCase();
  if (h.endsWith(".")) h = h.slice(0, -1);
  return h;
}

const LABEL_RE = /^(?!-)[a-z0-9-]{1,63}(?<!-)$/;
const IPV4_RE = /^(\d{1,3})(\.\d{1,3}){3}$/;

/** A valid DNS-style hostname: no IP literals, no scheme/port/path, labels well-formed. */
function isHostname(host: string): boolean {
  if (host.length === 0 || host.length > MAX_HOSTNAME_LENGTH) return false;
  if (host.includes(":")) return false; // no IPv6 literal, no port
  if (IPV4_RE.test(host)) return false; // IPs are bound via `exact` only
  const labels = host.split(".");
  if (labels.some((l) => l.length === 0 || !LABEL_RE.test(l))) return false;
  return true;
}

/**
 * Parse a browser origin string ("https://example.com", "http://host:8080").
 * Returns null for anything that is not http(s) or is unparseable.
 * `canonical` uses URL.origin semantics (default ports dropped, lowercase).
 */
export function parseOrigin(input: string): ParsedOrigin | null {
  if (!input || typeof input !== "string") return null;
  let url: URL;
  try {
    url = new URL(input);
  } catch {
    return null;
  }
  if (url.protocol !== "http:" && url.protocol !== "https:") return null;
  if (url.origin === "null") return null;
  const host = normalizeHost(url.hostname);
  if (host.length === 0) return null;
  const port = url.port ? Number(url.port) : null;
  return {
    scheme: url.protocol === "https:" ? "https" : "http",
    host,
    port,
    canonical: url.origin,
  };
}

/** Canonical origin string, or null if the input is not a valid http(s) origin. */
export function canonicalOrigin(input: string): string | null {
  return parseOrigin(input)?.canonical ?? null;
}

/**
 * Validate + normalize a binding. Returns null for malformed patterns (fail fast —
 * never trust user-entered binding text). `baseHost` is the normalized hostname for
 * host-only types and null for exact.
 */
export function validateBinding(binding: OriginBinding): ValidatedBinding | null {
  const type = binding.type;
  const raw = binding.pattern;
  if (!raw || typeof raw !== "string") return null;
  const p = raw.trim();

  if (type === "exact") {
    const o = parseOrigin(p);
    if (!o) return null;
    return { type, pattern: o.canonical, baseHost: null };
  }

  if (type === "subdomain") {
    let base = p;
    if (base.startsWith("*.")) base = base.slice(2);
    else if (base.startsWith("*")) return null; // bare "*" or "*foo" are not hostnames
    const host = normalizeHost(base);
    if (!isHostname(host)) return null;
    return { type, pattern: `*.${host}`, baseHost: host };
  }

  if (type === "domain") {
    if (p.startsWith("*")) return null;
    const host = normalizeHost(p);
    if (!isHostname(host)) return null;
    return { type, pattern: host, baseHost: host };
  }

  return null;
}

/** Internal: does a parsed origin match a validated binding? */
function matches(o: ParsedOrigin, v: ValidatedBinding): boolean {
  switch (v.type) {
    case "exact": {
      if (v.baseHost !== null) return false; // unreachable; defensive
      return o.canonical === v.pattern;
    }
    case "subdomain": {
      const base = v.baseHost ?? "";
      return o.host !== base && o.host.endsWith(`.${base}`);
    }
    case "domain": {
      const base = v.baseHost ?? "";
      return o.host === base || o.host.endsWith(`.${base}`);
    }
    default:
      return false;
  }
}

/** Single-binding match. Invalid origin or binding => no match. */
export function matchBinding(origin: string, binding: OriginBinding): boolean {
  const o = parseOrigin(origin);
  if (!o) return false;
  const v = validateBinding(binding);
  if (!v) return false;
  return matches(o, v);
}

const PRIORITY: Record<OriginBindingType, number> = { exact: 0, subdomain: 1, domain: 2 };

/**
 * Pick the highest-priority binding that matches the origin (exact > subdomain > domain),
 * or null when nothing matches. Invalid bindings are skipped. Returns the caller's
 * original binding object (not the validated copy).
 */
export function matchBindings(origin: string, bindings: OriginBinding[]): OriginBinding | null {
  const o = parseOrigin(origin);
  if (!o) return null;
  let best: { binding: OriginBinding; rank: number } | null = null;
  for (const b of bindings) {
    const v = validateBinding(b);
    if (!v || !matches(o, v)) continue;
    const rank = PRIORITY[v.type] ?? 3;
    if (!best || rank < best.rank) best = { binding: b, rank };
  }
  return best ? best.binding : null;
}
