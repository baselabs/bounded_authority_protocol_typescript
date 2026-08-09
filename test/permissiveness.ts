// T5 permissiveness mutation-gate — the per-language falsifier the frozen corpus cannot be
// (ADR 0005:240-246; ADR 0014 Decision 6/7). The corpus has no parser-layer permissiveness cases
// (host parsers are not in its input algebra), so each closure below is proven red-capable IN THE
// LANGUAGE WHOSE HOST RUNTIME IT TARGETS: construct the host-specific permissive defect the closure
// defeats, assert the SDK REJECTS it.
//
// DEFECT-INJECTION BATTERY (8 items — the ADR 0005:240-246 "prove red-when-removed" half). Each
// item below was defect-injected at authoring: the named closure/gate was mechanically removed or
// broken, the named test/gate went RED, and the change was reverted. The record:
//   1. duplicate-reject (REQ1-JSON-no-duplicate): remove `if (members.has(...)) fail(...)` in json.ts
//      → "duplicate member at depth 3" goes RED.
//   2. __proto__ null-prototype (REQ1-SELECTOR-semantic-identity): add `if (name === "__proto__")
//      continue` to json.ts (simulate prototype absorption) → "__proto__ member preserved" + "does
//      not collapse identity" go RED.
//   3. raw-lexeme 64-byte ceiling (REQ1-JSON-raw-lexeme): remove the lexeme.length check in json.ts
//      → "66-byte number lexeme" goes RED (the 66-byte tiny-float value 1e-64 passes magnitude but
//      fails ONLY the lexeme ceiling — a genuinely falsifiable case, not magnitude-redundant).
//   4. single-value/trailing (REQ1-JSON-single-value): remove the `ctx.pos !== src.length` check in
//      json.ts → "trailing bytes" + "two top-level values" go RED.
//   5. int/float tag distinction: collapse the float tag to integer in digest.ts typedProject →
//      "integer 1 and float 1.0 distinct identity" + "equals selector distinguishes" go RED.
//   6. census two-boundary (ADR 0014 D9): make importPublicKey in ed25519.ts NOT register the
//      fingerprint → conformance/run.ts census aborts ("declared by a valid verification case but
//      never imported at the Ed25519 verify boundary").
//   7. purity lint (ADR 0014 D8): inject `Date.now()` into a src/ module → eslint no-restricted-
//      syntax fails ("Date.now() forbidden in the verify path").
//   8. license check (ADR 0014 D8): add a non-allowlisted runtime dep to package.json →
//      tools/license-check.mjs fails ("not in the allowlist").
//
// Closures (design § Invariant conformance):
//  1. REQ1-JSON-no-duplicate  — hand-rolled duplicate-rejecting decoder (NOT JSON.parse).
//  2. REQ1-SELECTOR-semantic-identity / __proto__ — null-prototype containers (Map storage).
//  3. REQ1-JSON-raw-lexeme — number magnitude + 64-byte ceiling scanned on the raw lexeme.
//  4. REQ1-JSON-single-value — trailing bytes after the top-level value reject.
//  5. int/float tag distinction — 1 ≠ 1.0 in selector semantic identity.
import { test } from "node:test";
import assert from "node:assert/strict";
import { jsonDecode, strUtf8, type Tagged } from "../src/json.js";
import { InvalidError } from "../src/error.js";
import { parseSelector, selectorMatches, semanticIdentity } from "../src/selector.js";
import { jcsEncode } from "../src/jcs.js";
import { uriNormalize } from "../src/uri.js";

const dec = (s: string) => jsonDecode(strUtf8(s));

function rejects(label: string, fn: () => unknown): void {
  test(`permissiveness: ${label}`, () => {
    assert.throws(fn, InvalidError, `expected ${label} to reject with InvalidError`);
  });
}

// 1. REQ1-JSON-no-duplicate — the host defect: JSON.parse silently last-wins duplicates. The SDK's
// hand-rolled decoder rejects at EVERY depth. (The corpus catches depth-1 duplicates via json/decode
// invalid_duplicate; this closure's distinct value is depth≥3 + the guarantee that no host-parser
// fallback exists anywhere in the SDK path.)
rejects("duplicate member at depth 3 (JSON.parse would last-wins)", () =>
  dec('{"a":{"b":{"c":1,"c":2}}}'));
test("permissiveness: distinct members accepted (duplicate closure intact)", () => {
  const v = dec('{"a":1,"b":2}');
  assert.equal(v.t, "object");
});

// 2. REQ1-SELECTOR-semantic-identity / __proto__ — the host defect: on a plain object,
// {"__proto__": v} invokes the prototype setter, so the member VANISHES from the object and two
// structurally different objects canonicalize identically (the ADR 0005:184-192 collapse). The SDK
// decodes into null-prototype containers (a Map), so __proto__ is DATA.
test("permissiveness: __proto__ member preserved as data (null-prototype container)", () => {
  const v = dec('{"__proto__":{"evil":1},"ok":2}') as Extract<Tagged, { t: "object" }>;
  assert.equal(v.t, "object");
  assert.ok(v.v.has("__proto__"), "__proto__ must be present as a data key (not absorbed into the prototype)");
  assert.ok(v.v.has("ok"));
});
test("permissiveness: __proto__ selector value does not collapse identity", () => {
  // Two objects that differ ONLY in a __proto__ member must have distinct semantic identity. If the
  // closure were removed (host Object absorbed __proto__), both would canonicalize identically.
  const a = dec('{"__proto__":1,"x":2}');
  const b = dec('{"x":2}');
  assert.notEqual(toHex(semanticIdentity(a)), toHex(semanticIdentity(b)));
});

// 3. REQ1-JSON-raw-lexeme — the host defect: Number() rounds a long lexeme to a finite value, so a
// magnitude check AFTER conversion accepts it. The SDK scans the raw lexeme (64-byte ceiling) BEFORE
// conversion. The 66-byte tiny-float below has value 1e-64 (finite, within magnitude) — it is
// rejected ONLY by the lexeme ceiling, which is what makes this case a genuine falsifier (removing
// the ceiling → this test goes RED; the magnitude check alone cannot catch it).
rejects("66-byte number lexeme (Number rounds to a finite within-magnitude float)", () =>
  dec("0." + "0".repeat(63) + "1"));
rejects("integer magnitude over bound (2^53)", () =>
  dec("9007199254740992")); // MAXIMA.integer_magnitude + 1

// 4. REQ1-JSON-single-value — the host defect: JSON.parse accepts trailing data after the top-level
// value in some configurations. The SDK rejects any byte after the single value (whitespace-only).
rejects("trailing bytes after the top-level value", () => dec('{} junk'));
rejects("two top-level values", () => dec('1 2'));

// 5. int/float tag distinction — the host defect: JSON.parse collapses `1` and `1.0` to the same JS
// number, so a selector identity comparison that used the raw number would treat them as equal. The
// SDK's tagged algebra preserves the distinction; the typed projection wraps them differently.
test("permissiveness: integer 1 and float 1.0 have distinct semantic identity", () => {
  const intOne = dec("1");
  const floatOne = dec("1.0");
  assert.equal(intOne.t, "int");
  assert.equal(floatOne.t, "float");
  assert.notEqual(toHex(semanticIdentity(intOne)), toHex(semanticIdentity(floatOne)));
});
test("permissiveness: equals selector distinguishes int path from float value", () => {
  // A selector looking for integer 1 must NOT match a float 1.0 at the path (and vice versa).
  const args = dec('{"n":1}'); // integer 1
  const selInt = parseSelector(dec('{"kind":"equals","path":["n"],"value":1}'));
  const selFloat = parseSelector(dec('{"kind":"equals","path":["n"],"value":1.0}'));
  assert.equal(selectorMatches(selInt, args), true);
  assert.equal(selectorMatches(selFloat, args), false); // float 1.0 ≠ integer 1
});

// 6. JCS float canonicalization (RFC 8785 §3.2.2 / ECMAScript Number.prototype.toString). V8's
// JSON.stringify already produces the ECMAScript form; these pin it so a future drift is caught.
test("permissiveness: jcs float serialization matches ECMAScript (1.0 → 1, 1e-7 → 1e-7)", () => {
  assert.deepEqual(Array.from(jcsEncode(dec("1.0"))), Array.from(strUtf8("1")));
  assert.deepEqual(Array.from(jcsEncode(dec("10.0"))), Array.from(strUtf8("10")));
  assert.deepEqual(Array.from(jcsEncode(dec("1e-7"))), Array.from(strUtf8("1e-7")));
  assert.deepEqual(Array.from(jcsEncode(dec("1.5"))), Array.from(strUtf8("1.5")));
});

// 7. JCS astral codepoint emits 4-byte UTF-8 (RFC 8785 keeps astral chars as UTF-8 bytes, not \u).
// The defect: a 3-byte-cap appendUtf8Bytes produces F0 80 80 ... for astral chars.
test("permissiveness: jcs astral codepoint emits 4-byte UTF-8", () => {
  const v = dec('"\\ud800\\udc00"'); // U+10000 (𐀀) as a surrogate pair
  const out = jcsEncode(v);
  // opening " + F0 90 80 80 + closing "
  assert.deepEqual(Array.from(out), [0x22, 0xf0, 0x90, 0x80, 0x80, 0x22]);
});

// === BAP-09 cross-vendor remediation — fail-closed + reference-parity closures (defect-injected) ===
// Each closure below was verified divergent against the RUNNING Elixir reference, fixed to match the
// reference verdict, then proven red-capable by mechanically removing/breaking the fix and watching
// the named test go RED. The reference verdict is the contract (AGENTS rule 7); RFC 8785 is cited
// only where the reference agrees with it.

// Cross-vendor #14: malformed UTF-8 in an object member name must fail closed (InvalidError), not
// throw a non-InvalidError TypeError via the fatal TextDecoder. Defect: revert parseObject to the
// bare `utf8Str(nameBytes)` (no DECODER.decode try/catch) → this throws TypeError.
test("permissiveness: malformed UTF-8 member name fails closed (cross-vendor #14)", () => {
  // {"<0xFF>":1} — a member name with an invalid UTF-8 lead byte.
  const input = new Uint8Array([0x7b, 0x22, 0xff, 0x22, 0x3a, 0x31, 0x7d]);
  assert.throws(() => jsonDecode(input), InvalidError);
  // Control: a valid name still decodes.
  const ok = new Uint8Array([0x7b, 0x22, 0x61, 0x22, 0x3a, 0x31, 0x7d]); // {"a":1}
  const r = jsonDecode(ok);
  assert.equal(r.t, "object");
});

// Cross-vendor #7: a float lexeme whose value exceeds the maximum but rounds to it under Number()
// (9007199254740991.0001 → 9007199254740991) MUST be rejected on the raw lexeme. Defect: revert to
// the post-conversion Math.abs(n) > MAX check → this lexeme is accepted (lossy).
rejects("float magnitude checked on raw lexeme not lossy conversion (cross-vendor #7)", () =>
  jsonDecode(strUtf8("9007199254740991.0001")));
test("permissiveness: float raw-lexeme magnitude controls (cross-vendor #7)", () => {
  // Exactly MAX (int) is valid; MAX+1 as int is rejected on the raw lexeme.
  assert.equal(jsonDecode(strUtf8("9007199254740991")).t, "int");
  assert.throws(() => jsonDecode(strUtf8("9007199254740992")), InvalidError);
  // A float strictly under MAX is valid.
  assert.equal(jsonDecode(strUtf8("9007199254740990.5")).t, "float");
});

// Cross-vendor #6: structurally-invalid IPv6 literals must be rejected, not normalized. Defect:
// revert ipv6Kind to the regex-only branch → [:::] normalizes to Ok.
test("permissiveness: malformed IPv6 literal rejected (cross-vendor #6)", () => {
  const bad = ["https://[:::]/", "https://[1:2:3:4:5:6:7:8:9]/", "https://[1::2::3]/", "https://[gggg]/"];
  for (const u of bad) {
    assert.equal(uriNormalize(strUtf8(u)).ok, false, `${u} should be invalid`);
  }
  // Controls: valid IPv6 literals still normalize.
  const good = ["https://[::1]/", "https://[2001:db8::1]/", "https://[1:2:3:4:5:6:7:8]/", "https://[::ffff:192.0.2.1]/"];
  for (const u of good) {
    assert.equal(uriNormalize(strUtf8(u)).ok, true, `${u} should be valid`);
  }
});

// Cross-vendor #8: JCS DEL (U+007F) MUST emit the raw byte 0x7f, matching the Elixir reference
// (jcs.ex has no DEL case → general codepoint branch passes it raw). RFC 8785 §3.2.2.3 mandates
// \u007f, but the reference bytes are the contract (AGENTS rule 7). Defect: revert to the appendU
// branch → bytes differ ([34,120,92,117,48,48,55,102,121,34]).
test("permissiveness: jcs DEL emits raw byte matching reference (cross-vendor #8)", () => {
  const v: Tagged = { t: "string", v: strUtf8("x\u007fy") };
  assert.deepEqual(Array.from(jcsEncode(v)), [34, 120, 127, 121, 34]); // "x<raw DEL>y"
});

// Cross-vendor #9: the JCS encoder MUST enforce per-node resource bounds DURING encode (mirrors
// jcs.ex:27-101 encode_value), not only the final jcs_bytes total. A 257-item array (array_items
// bound 256), a depth-33 nested array (depth bound 32), and an 8193-byte string (string_bytes bound
// 8192) must all reject — the reference rejects each. Defect: revert emit to the boundless recurse
// (no level/nodes/length checks) → all three encode successfully.
test("permissiveness: jcs enforces per-node bounds at encode (cross-vendor #9)", () => {
  const int = (n: number): Tagged => ({ t: "int", v: n });
  // 257-item array (over array_items=256).
  assert.throws(() => jcsEncode({ t: "array", v: Array.from({ length: 257 }, (_, i) => int(i)) }), InvalidError);
  // Control: 256 items is the boundary and encodes.
  assert.ok(jcsEncode({ t: "array", v: Array.from({ length: 256 }, (_, i) => int(i)) }) instanceof Uint8Array);
  // depth-33 nested array (over depth=32).
  let deep: Tagged = int(0);
  for (let i = 0; i < 33; i++) deep = { t: "array", v: [deep] };
  assert.throws(() => jcsEncode(deep), InvalidError);
  // Control: depth-32 encodes.
  let deep32: Tagged = int(0);
  for (let i = 0; i < 32; i++) deep32 = { t: "array", v: [deep32] };
  assert.ok(jcsEncode(deep32) instanceof Uint8Array);
  // oversized string (over string_bytes=8192).
  assert.throws(() => jcsEncode({ t: "string", v: new Uint8Array(8193) }), InvalidError);
  // Control: exactly 8192 bytes encodes.
  assert.ok(jcsEncode({ t: "string", v: new Uint8Array(8192) }) instanceof Uint8Array);
});

function toHex(b: Uint8Array): string {
  let s = "";
  for (let i = 0; i < b.length; i++) s += b[i]!.toString(16).padStart(2, "0");
  return s;
}
