/**
 * Origin binding matching tests (docs/31 §5.3, D-3).
 *
 * Three binding types, no regex, no prefix wildcards:
 *   exact      "https://example.com"        scheme+host+port normalized, full equality
 *   subdomain  "*.example.com"              any subdomain, NOT the apex
 *   domain     "example.com"                apex + all subdomains
 * Match priority: exact > subdomain > domain.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import {
  parseOrigin,
  canonicalOrigin,
  originOfUrl,
  type OriginBinding,
  validateBinding,
  matchBinding,
  matchBindings,
} from "../origin";

// --- parseOrigin / canonicalOrigin -------------------------------------------------

test("parseOrigin: normalizes scheme/host and drops default ports", () => {
  const o = parseOrigin("HTTPS://Example.COM:443/path?q=1");
  assert.ok(o);
  assert.equal(o.scheme, "https");
  assert.equal(o.host, "example.com");
  assert.equal(o.port, null);
  assert.equal(o.canonical, "https://example.com");
});

test("parseOrigin: keeps non-default port", () => {
  const o = parseOrigin("http://example.com:8080/");
  assert.ok(o);
  assert.equal(o.port, 8080);
  assert.equal(o.canonical, "http://example.com:8080");
});

test("parseOrigin: canonicalOrigin of a bare URL equals URL.origin", () => {
  assert.equal(canonicalOrigin("https://example.com"), "https://example.com");
  assert.equal(canonicalOrigin("https://sub.example.com:443"), "https://sub.example.com");
  assert.equal(canonicalOrigin("http://example.com:80"), "http://example.com");
});

test("parseOrigin: rejects non-http(s) and schemeless input", () => {
  assert.equal(parseOrigin("file:///etc/passwd"), null);
  assert.equal(parseOrigin("about:blank"), null);
  assert.equal(parseOrigin("javascript:void(0)"), null);
  assert.equal(parseOrigin("example.com"), null);
  assert.equal(parseOrigin(""), null);
});

test("parseOrigin: IP origins parse (exact may bind them)", () => {
  const o = parseOrigin("http://192.168.1.1:8080");
  assert.ok(o);
  assert.equal(o.canonical, "http://192.168.1.1:8080");
});

// --- validateBinding ----------------------------------------------------------------

test("validateBinding: accepts well-formed bindings of all three types", () => {
  assert.deepEqual(validateBinding({ type: "exact", pattern: "https://example.com:8443" }), {
    type: "exact",
    pattern: "https://example.com:8443",
    baseHost: null,
  });
  assert.deepEqual(validateBinding({ type: "subdomain", pattern: "*.example.com" }), {
    type: "subdomain",
    pattern: "*.example.com",
    baseHost: "example.com",
  });
  assert.deepEqual(validateBinding({ type: "domain", pattern: "Example.COM" }), {
    type: "domain",
    pattern: "example.com",
    baseHost: "example.com",
  });
});

test("validateBinding: rejects regex/glob/prefix wildcards and scheme-bearing host patterns", () => {
  assert.equal(validateBinding({ type: "domain", pattern: "exam*.com" }), null); // glob char
  assert.equal(validateBinding({ type: "domain", pattern: ".+example.com" }), null); // regex
  assert.equal(validateBinding({ type: "domain", pattern: "https://example.com" }), null); // scheme
  assert.equal(validateBinding({ type: "domain", pattern: "example.com/path" }), null); // path
  assert.equal(validateBinding({ type: "subdomain", pattern: "*example.com" }), null); // bad star
  assert.equal(validateBinding({ type: "exact", pattern: "example.com" }), null); // exact needs scheme
});

test("validateBinding: rejects IP patterns for subdomain/domain (host patterns only)", () => {
  assert.equal(validateBinding({ type: "domain", pattern: "192.168.1.1" }), null);
  assert.equal(validateBinding({ type: "subdomain", pattern: "*.192.168.1.1" }), null);
  assert.equal(validateBinding({ type: "domain", pattern: "[::1]" }), null);
});

test("validateBinding: rejects invalid hostnames and localhost-style patterns for domain", () => {
  assert.equal(validateBinding({ type: "domain", pattern: "local host.com" }), null);
  assert.equal(validateBinding({ type: "domain", pattern: "-bad.example.com" }), null);
  assert.equal(validateBinding({ type: "domain", pattern: "" }), null);
});

// --- matchBinding ------------------------------------------------------------------

test("exact: matches normalized equality, not http-vs-https, not other host", () => {
  const b: OriginBinding = { type: "exact", pattern: "https://example.com" };
  assert.equal(matchBinding("https://example.com", b), true);
  assert.equal(matchBinding("https://example.com:443", b), true); // default port normalized away
  assert.equal(matchBinding("http://example.com", b), false); // scheme mismatch
  assert.equal(matchBinding("https://sub.example.com", b), false);
  assert.equal(matchBinding("https://example.com:8443", b), false); // non-default port
});

test("subdomain: matches subdomains but never the apex", () => {
  const b: OriginBinding = { type: "subdomain", pattern: "*.example.com" };
  assert.equal(matchBinding("https://sub.example.com", b), true);
  assert.equal(matchBinding("https://a.b.example.com", b), true); // multi-level
  assert.equal(matchBinding("https://example.com", b), false); // apex excluded
  assert.equal(matchBinding("https://notexample.com", b), false);
  assert.equal(matchBinding("https://example.com.evil.com", b), false);
});

test("domain: matches apex and all subdomains", () => {
  const b: OriginBinding = { type: "domain", pattern: "example.com" };
  assert.equal(matchBinding("https://example.com", b), true);
  assert.equal(matchBinding("https://sub.example.com", b), true);
  assert.equal(matchBinding("http://a.b.example.com:8080", b), true); // host-only match, any scheme/port
  assert.equal(matchBinding("https://notexample.com", b), false);
});

test("subdomain/domain: host-only matching ignores scheme and port", () => {
  const d: OriginBinding = { type: "domain", pattern: "example.com" };
  assert.equal(matchBinding("http://example.com:8080", d), true);
  const s: OriginBinding = { type: "subdomain", pattern: "*.example.com" };
  assert.equal(matchBinding("http://sub.example.com:8080", s), true);
});

// --- matchBindings (priority) -------------------------------------------------------

test("matchBindings: priority exact > subdomain > domain", () => {
  const bindings: OriginBinding[] = [
    { type: "domain", pattern: "example.com" },
    { type: "exact", pattern: "https://example.com" },
    { type: "subdomain", pattern: "*.example.com" },
  ];
  // exact wins over domain for the apex
  const m = matchBindings("https://example.com", bindings);
  assert.ok(m);
  assert.equal(m.type, "exact");
});

test("matchBindings: subdomain wins over domain for a subdomain", () => {
  const bindings: OriginBinding[] = [
    { type: "domain", pattern: "example.com" },
    { type: "subdomain", pattern: "*.example.com" },
  ];
  const m = matchBindings("https://sub.example.com", bindings);
  assert.ok(m);
  assert.equal(m.type, "subdomain");
});

test("matchBindings: exact non-default-port binding isolates a specific port", () => {
  const bindings: OriginBinding[] = [
    { type: "exact", pattern: "https://example.com:8443" },
    { type: "domain", pattern: "example.com" },
  ];
  assert.equal(matchBindings("https://example.com:8443", bindings)?.type, "exact");
  assert.equal(matchBindings("https://example.com", bindings)?.type, "domain");
});

test("matchBindings: no match returns null (and ignores unparseable input)", () => {
  const bindings: OriginBinding[] = [{ type: "domain", pattern: "example.com" }];
  assert.equal(matchBindings("https://attacker.example", bindings), null);
  assert.equal(matchBindings("about:blank", bindings), null);
  assert.equal(matchBindings("", bindings), null);
  assert.equal(matchBindings("https://example.com", []), null);
});

test("matchBindings: invalid bindings are skipped, valid ones still match", () => {
  const bindings: OriginBinding[] = [
    { type: "domain", pattern: "not a host" },
    { type: "domain", pattern: "example.com" },
  ];
  assert.equal(matchBindings("https://example.com", bindings)?.type, "domain");
});

test("matchBindings: deterministic first-wins within equal priority", () => {
  const bindings: OriginBinding[] = [
    { type: "domain", pattern: "example.com" },
    { type: "domain", pattern: "sub.example.com" },
  ];
  assert.equal(matchBindings("https://sub.example.com", bindings)?.pattern, "example.com");
});

// --- originOfUrl (HIGH-1 tab re-verification; fail-closed) --------------------------

test("originOfUrl: parses http(s) tab URLs and canonicalizes", () => {
  assert.equal(originOfUrl("https://example.com/path?q=1"), "https://example.com");
  assert.equal(originOfUrl("http://Example.COM:80/"), "http://example.com");
  assert.equal(originOfUrl("https://example.com:8443/x"), "https://example.com:8443");
});

test("originOfUrl: unverifiable tab URLs → null (fail-closed, tab check rejects)", () => {
  assert.equal(originOfUrl(undefined), null);
  assert.equal(originOfUrl(null), null);
  assert.equal(originOfUrl(""), null);
  assert.equal(originOfUrl("about:blank"), null);
  assert.equal(originOfUrl("chrome-extension://abc/foo"), null);
  assert.equal(originOfUrl("data:text/html,hi"), null);
  assert.equal(originOfUrl("not a url"), null);
});
