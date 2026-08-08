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

function toHex(b: Uint8Array): string {
  let s = "";
  for (let i = 0; i < b.length; i++) s += b[i]!.toString(16).padStart(2, "0");
  return s;
}
