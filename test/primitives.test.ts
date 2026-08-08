// Red-before-green primitives test — exercises the core permissiveness closures + JCS.
// Run: pnpm test
import { test } from "node:test";
import assert from "node:assert/strict";
import { jsonDecode, strUtf8, type Tagged } from "../src/json.js";
import { jcsEncode } from "../src/jcs.js";
import { base64urlDecode, base64urlEncode } from "../src/base64url.js";
import { boundsNew, MAXIMA } from "../src/bounds.js";
import { InvalidError } from "../src/error.js";

const dec = (s: string) => jsonDecode(strUtf8(s));

function rejects(label: string, fn: () => unknown) {
  test(`rejects ${label}`, () => {
    assert.throws(fn, InvalidError, `expected ${label} to reject with InvalidError`);
  });
}

// REQ1-JSON-no-duplicate — the load-bearing closure.
rejects("duplicate member at depth 1", () => dec('{"a":1,"a":2}'));
rejects("duplicate member at depth 3", () => dec('{"a":{"b":{"c":1,"c":2}}}'));
test("accepts distinct members", () => {
  const v = dec('{"a":1,"b":2}');
  assert.equal(v.t, "object");
});

// REQ1-JSON-single-value — trailing bytes reject.
rejects("trailing bytes", () => dec('{} junk'));
rejects("two top-level values", () => dec('1 2'));
test("accepts trailing whitespace only", () => {
  const v = dec('  42  \n');
  assert.equal(v.t, "int");
  assert.equal((v as { v: number }).v, 42);
});

// REQ1-SELECTOR-semantic-identity / __proto__ — null-prototype container.
// A "__proto__" key must be DATA, not a prototype mutation. After decode, the object must have the
// __proto__ member present (it was not absorbed into the prototype).
test("__proto__ member is preserved as data (null-prototype)", () => {
  const v = dec('{"__proto__":{"evil":1},"ok":2}') as Extract<Tagged, { t: "object" }>;
  assert.equal(v.t, "object");
  assert.ok(v.v.has("__proto__"), "__proto__ member must be present as data");
  assert.ok(v.v.has("ok"));
});

// int/float tag distinction.
test("int vs float tag preserved", () => {
  assert.equal(dec("1").t, "int");
  assert.equal(dec("1.0").t, "float");
  assert.equal(dec("1e2").t, "float");
  assert.equal(dec("-5").t, "int");
});

// REQ1-JSON-raw-lexeme — magnitude bound.
rejects("integer magnitude over bound", () => dec(String(MAXIMA.integer_magnitude + 1)));
rejects("number lexeme over 64-byte ceiling", () => dec("9".repeat(65)));

// JCS round-trip + canonical form.
test("jcs encodes object with sorted keys", () => {
  const v = dec('{"b":1,"a":2}');
  const out = utf8(jcsEncode(v));
  assert.equal(out, '{"a":2,"b":1}');
});
test("jcs encodes int vs float identically (1 vs 1.0 → 1)", () => {
  assert.equal(utf8(jcsEncode(dec("1"))), "1");
  assert.equal(utf8(jcsEncode(dec("1.0"))), "1");
});
test("jcs encodes nested array order preserved", () => {
  const v = dec('[3,{"z":1,"a":2},true]');
  assert.equal(utf8(jcsEncode(v)), '[3,{"a":2,"z":1},true]');
});

// base64url canonical decode + encode.
test("base64url round-trips canonical", () => {
  const raw = strUtf8("hello world");
  const enc = base64urlEncode(raw);
  const dec2 = base64urlDecode(enc);
  assert.deepEqual(Array.from(dec2), Array.from(raw));
});
rejects("base64url non-canonical (padding)", () => base64urlDecode(strUtf8("YWJjPQ==")));
rejects("base64url length mod 4 == 1", () => base64urlDecode(strUtf8("Y")));

// bounds.new tightening-only.
test("bounds.new tightens a maximum", () => {
  const b = boundsNew({ depth: 16 });
  assert.equal(b.overrides.get("depth"), 16);
});
rejects("bounds.new widening", () => boundsNew({ depth: 999 }));
rejects("bounds.new fixed-width key", () => boundsNew({ signature_bytes: 64 }));
rejects("bounds.new unknown key", () => boundsNew({ bogus: 1 } as Record<string, number>));

const utf8 = (b: Uint8Array) => new TextDecoder().decode(b);
