// Red-before-green primitives test — exercises the core permissiveness closures + JCS.
// Run: pnpm test
import { test } from "node:test";
import assert from "node:assert/strict";
import { jsonDecode, strUtf8, type Tagged } from "../src/json.js";
import { jcsEncode } from "../src/jcs.js";
import { base64urlDecode, base64urlEncode } from "../src/base64url.js";
import { boundsNew, MAXIMA } from "../src/bounds.js";
import { InvalidError } from "../src/error.js";
import { jwkFromPublicKey, thumbprint, jwkEncodePublic, jwkDecodePublic, thumbprintRaw, publicKeyThumbprintRaw } from "../src/jwk.js";
import { uriNormalize } from "../src/uri.js";
import { ed25519Verify, importPublicKey, _resetCensus, sha256 } from "../src/ed25519.js";

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

// --- JWK + Ed25519 + SHA-256 known-answer (from the corpus) ---
const KNOWN_X = "W1s7yE9fGDMBbmdpqYVwQ1hDCXtzOePUD3fIf1t7FDk";
const KNOWN_TP = "d4ucEZwvJTfwxXCN4f2xmIE5ZBFoH5i5mlzeWZaB3yI";

test("jwk.thumbprint known-answer", () => {
  const raw = base64urlDecode(strUtf8(KNOWN_X));
  assert.equal(raw.length, 32);
  assert.equal(thumbprint(jwkFromPublicKey(raw)), KNOWN_TP);
});
test("jwk.encode_public known-answer (canonical OKP JSON)", () => {
  const raw = base64urlDecode(strUtf8(KNOWN_X));
  const enc = jwkEncodePublic(raw);
  assert.equal(utf8(enc), `{"crv":"Ed25519","kty":"OKP","x":"${KNOWN_X}"}`);
});
test("jwk.decode_public round-trips encode_public", () => {
  const raw = base64urlDecode(strUtf8(KNOWN_X));
  const enc = jwkEncodePublic(raw);
  const dec2 = jwkDecodePublic(enc);
  assert.equal(dec2.ok, true);
  if (dec2.ok) assert.deepEqual(Array.from(dec2.value), Array.from(raw));
});
test("thumbprintRaw == publicKeyThumbprintRaw", () => {
  const raw = base64urlDecode(strUtf8(KNOWN_X));
  assert.deepEqual(Array.from(thumbprintRaw(jwkFromPublicKey(raw))), Array.from(publicKeyThumbprintRaw(raw)));
});
test("ed25519 rejects a forged signature", () => {
  _resetCensus();
  const raw = base64urlDecode(strUtf8(KNOWN_X));
  const key = importPublicKey(raw, KNOWN_TP);
  const msg = strUtf8("hello");
  const badSig = new Uint8Array(64); // all zeros — never valid
  assert.equal(ed25519Verify(msg, badSig, key), false);
});
test("sha256 known-answer", () => {
  // SHA-256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
  const h = sha256();
  assert.equal(utf8(base64urlEncode(h)), "47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU");
});

// --- URI normalize known-answer (from the corpus) ---
function uriEq(input: string, expected: string) {
  test(`uri.normalize ${input} → ${expected}`, () => {
    const r = uriNormalize(strUtf8(input));
    assert.equal(r.ok, true, `expected ok for ${input}`);
    if (r.ok) assert.equal(utf8(r.value), expected);
  });
}
uriEq("https://example.test/path", "https://example.test/path");
uriEq("https://EXAMPLE.test/", "https://example.test/");
uriEq("https://example.com:443/", "https://example.com/");
uriEq("https://example.com:0443/", "https://example.com/");
uriEq("https://example.com:8443/a%2Fb", "https://example.com:8443/a%2Fb");
uriEq("https://example.com/%7e", "https://example.com/~");
uriEq("https://example.com/a/../b", "https://example.com/b");
uriEq("https://[2001:db8::1]/", "https://[2001:db8::1]/");
uriEq("https://192.0.2.1/", "https://192.0.2.1/");
test("uri.normalize rejects http scheme (returns Err)", () => {
  const r = uriNormalize(strUtf8("http://example.com/"));
  assert.equal(r.ok, false);
});
test("uri.normalize rejects malformed (returns Err)", () => {
  const r = uriNormalize(strUtf8("https://example.com:99999/"));
  assert.equal(r.ok, false);
});
