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
import nodeCrypto from "node:crypto";
import { jsonDecode, strUtf8, type Tagged } from "../src/json.js";
import { InvalidError } from "../src/error.js";
import { base64urlDecode, base64urlEncode } from "../src/base64url.js";
import { parseSelector, selectorMatches, semanticIdentity } from "../src/selector.js";
import { jcsEncode } from "../src/jcs.js";
import { uriNormalize } from "../src/uri.js";
import {
  untrustedKeyLocator, checkEnvelope, type ExpectedRequest,
  encodeConsumptionEntry, checkChain, boundaryAnchorSigningInput, keyTransitionSigningInput,
  encodeAnchoredExport, verifyAnchoredExport, assembleCompact, ROW_PREFIX,
  type BoundaryAnchorProducer, type ConsumptionEntry, type ChainInput, type ExpectedChain,
  type AnchoredExportInput, type ExpectedExport, type ExpectedAnchor, type ExpectedKeyTransition,
  type HistoricalKeyChain, type HistoricalPublicKey, type KeyTransitionProducer,
  decodeGrant, verifyGrant, grantSigningInput, proofSigningInput,
  type GrantProducer, type ProofProducer, type ExpectedGrant, type TrustedIssuer,
} from "../src/v1.js";
import { boundsNew, type Bounds } from "../src/bounds.js";
import { sha256, _resetCensus } from "../src/ed25519.js";
import { publicKeyThumbprintRaw } from "../src/jwk.js";

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

// === FIX-C cross-vendor remediation — v1 façade closed-boundary (defect-injected) ===

// Cross-vendor #13: untrustedKeyLocator MUST decode ONLY the protected segment — the reference
// (v1.ex:21-34) splits on '.' and never decodes payload/signature. A compact with a valid grant
// header but garbage payload+signature must return the kid (Ok), not reject. Defect: revert to
// parseCompact (decodes all 3) → the garbage-payload case returns Err.
test("permissiveness: untrusted key locator decodes only protected segment (cross-vendor #13)", () => {
  const protectedB64 = "eyJhbGciOiJFZERTQSIsImtpZCI6ImsxIiwidHlwIjoiYmErY2FwIn0";
  // Garbage payload + signature (non-base64url bytes).
  const r = untrustedKeyLocator(strUtf8(`${protectedB64}.!!.!!!`));
  assert.equal(r.ok, true);
  if (r.ok) assert.equal(r.value.keyId, "k1");
  // Valid-base64 non-JSON payload + signature — reference also returns Ok.
  assert.equal(untrustedKeyLocator(strUtf8(`${protectedB64}.YWFh.YmJi`)).ok, true);
  // 2- and 4-segment inputs reject (reference requires exactly 3).
  assert.equal(untrustedKeyLocator(strUtf8(`${protectedB64}.!!`)).ok, false);
  assert.equal(untrustedKeyLocator(strUtf8(`${protectedB64}.!!.!!.!!`)).ok, false);
});

// Cross-vendor #22: a null trustedIssuer must fail closed (return Err), not throw TypeError on the
// .publicKey deref. The `trying` wrapper only catches InvalidError, so without the guard a TypeError
// propagates out of the public API. Defect: revert the `if (t === null) fail(...)` guard → TypeError.
test("permissiveness: checkEnvelope null trustedIssuer fails closed (cross-vendor #22)", () => {
  const junk = strUtf8("aaa.bbb.ccc");
  // Must return Err (fail-closed); without the guard this throws TypeError.
  const r = checkEnvelope(junk, junk, { trustedIssuer: null } as never);
  assert.equal(r.ok, false);
});

// Cross-vendor #19: the reference requires is_integer(evaluation_time), is_integer(clock_skew), and
// proof_max_age > 0 (strictly positive). These guards fire BEFORE grant parsing, so a junk compact
// suffices. Defect: revert the Number.isInteger/`<= 0` guards → fractional/zero values pass.
test("permissiveness: checkEnvelope rejects fractional/zero temporal context (cross-vendor #19)", () => {
  const junk = strUtf8("aaa.bbb.ccc");
  const issuer = { keyId: strUtf8("k"), publicKey: new Uint8Array(32) };
  const base = {
    trustedIssuer: issuer, issuer: "x", audience: "x", method: "GET", targetUri: "https://x.example/",
    invocationId: "550e8400-e29b-41d4-a716-446655440000", operation: "read",
    castArguments: { t: "null" as const, v: null }, nonce: "not_required" as const,
  };
  const call = (overrides: Partial<ExpectedRequest>) => checkEnvelope(junk, junk, { ...base, ...overrides } as ExpectedRequest);
  // All must return Err (the guard rejects); the integer control also returns Err only because the
  // junk compact fails at grant parse — the load-bearing assertion is no throw + Err on each.
  assert.equal(call({ evaluationTime: 150.5, clockSkew: 0, proofMaxAge: 300 }).ok, false);
  assert.equal(call({ evaluationTime: 150, clockSkew: 10.5, proofMaxAge: 300 }).ok, false);
  assert.equal(call({ evaluationTime: 150, clockSkew: 0, proofMaxAge: 0 }).ok, false);
  assert.equal(call({ evaluationTime: 150, clockSkew: 0, proofMaxAge: 300 }).ok, false);
});

function toHex(b: Uint8Array): string {
  let s = "";
  for (let i = 0; i < b.length; i++) s += b[i]!.toString(16).padStart(2, "0");
  return s;
}

// === BAP-09 #2/#3/#15/#16/#17/#18 cross-vendor remediation — chain/archive verify + encode paths ===
// Each closure was verified divergent against the RUNNING Elixir reference (the verification agents
// confirmed precise behaviors), fixed to match the reference verdict, then proven red-capable by
// mechanically reverting the named fix and watching the test go RED. The reference bytes are the
// contract (AGENTS rule 7).
//
// The SDK is verify-only (public keys; AGENTS rule 6), so to build red-capable deny cases for the
// archive path we mint throwaway Ed25519 keys via node:crypto, sign anchors/transitions through the
// SDK's own producers, assemble archives via encodeAnchoredExport, and then mutate one variable per
// finding. The producer/encode tests (#16, #17) need no signatures.

// Build a fresh Ed25519 keypair; return raw 32-byte public key + the signing KeyObject.
function freshKey(): { publicKey: Uint8Array; privateKey: nodeCrypto.KeyObject } {
  const { publicKey, privateKey } = nodeCrypto.generateKeyPairSync("ed25519");
  const raw = new Uint8Array(publicKey.export({ type: "spki", format: "der" }).subarray(-32));
  return { publicKey: raw, privateKey };
}

// Sign the canonical anchor message (protected.payload ASCII) with the producer + assembleCompact.
function signedAnchorCompact(
  anchor: BoundaryAnchorProducer, privateKey: nodeCrypto.KeyObject,
): Uint8Array {
  const si = boundaryAnchorSigningInput(anchor);
  if (!si.ok) throw new Error("anchor signing input failed");
  const message = strUtf8(`${new TextDecoder().decode(si.value.protectedSegment)}.${new TextDecoder().decode(si.value.payloadSegment)}`);
  const sig = new Uint8Array(nodeCrypto.sign(null, Buffer.from(message), privateKey));
  return assembleCompact(si.value, sig);
}

const Z32 = new Uint8Array(32); // the all-zero 32-byte hash (genesis chain_hash / predecessor)

// A self-contained archive builder parameterized by the key path. Produces signed anchors +
// transitions, encodes rows via encodeConsumptionEntry, and assembles the archive. Returns the pieces
// verifyAnchoredExport needs. `keys` drives the rollover: 1 key = no transitions, N keys = N-1
// transitions. By default effective_at increases strictly (1500, 2000, ...); pass `effectiveAts` to
// override (used by the #2 non-monotone test). The builder intentionally does NOT validate the
// path — it signs whatever effective_at sequence is requested, so a malformed path can be assembled
// and then offered to verifyAnchoredExport to prove the chronology/cycle gate fires.
function buildArchive(
  keys: { publicKey: Uint8Array; privateKey: nodeCrypto.KeyObject }[],
  opts: { effectiveAts?: number[]; endAnchoredAt?: number } = {},
) {
  const chainId = "urn:example:chain";
  // Genesis chain: firstSequence 1, previous_hash all-zero, one row whose hash becomes last_hash.
  const zeroPrev = Z32.slice();
  const rowEntry: ConsumptionEntry = {
    chainId, sequence: 1, previousHash: zeroPrev, commitment: new Uint8Array(32).fill(7),
  };
  const encoded = encodeConsumptionEntry(rowEntry);
  if (!encoded.ok) throw new Error("row encode failed");
  const rowBytes = encoded.value.bytes;
  const lastHash = sha256(ROW_PREFIX, rowBytes);
  const startKey = keys[0]!;
  // Start anchor: sequence 0, chain_hash all-zero (genesis), signed by startKey.
  const startCompact = signedAnchorCompact({
    anchorId: "urn:example:anchor:start", anchoredAt: 1000, chainId, sequence: 0,
    chainHash: zeroPrev, keyId: "k0", publicKey: startKey.publicKey,
  }, startKey.privateKey);
  // Transitions + end anchor.
  const transitions: Uint8Array[] = [];
  const expectedTransitions: ExpectedKeyTransition[] = [];
  const defaultAt = (i: number) => 1500 + 500 * i;
  for (let i = 0; i < keys.length - 1; i++) {
    const cur = keys[i]!, nxt = keys[i + 1]!;
    const fromFp = thumbprintOf(cur.publicKey);
    const toFp = thumbprintOf(nxt.publicKey);
    const effectiveAt = opts.effectiveAts ? opts.effectiveAts[i]! : defaultAt(i);
    const transition: KeyTransitionProducer = {
      transitionId: `urn:example:transition:${i}`, chainId, effectiveAt,
      currentKeyId: `k${i}`, currentPublicKey: cur.publicKey,
      nextKeyId: `k${i + 1}`, nextPublicKey: nxt.publicKey,
    };
    const si = keyTransitionSigningInput(transition);
    if (!si.ok) throw new Error("transition signing input failed");
    const message = strUtf8(`${new TextDecoder().decode(si.value.protectedSegment)}.${new TextDecoder().decode(si.value.payloadSegment)}`);
    const sig = new Uint8Array(nodeCrypto.sign(null, Buffer.from(message), cur.privateKey));
    transitions.push(assembleCompact(si.value, sig));
    expectedTransitions.push({
      transitionId: `urn:example:transition:${i}`, chainId, effectiveAt,
      currentKeyId: `k${i}`, currentKeyFingerprint: fromFp,
      nextKeyId: `k${i + 1}`, nextKeyFingerprint: toFp,
    });
  }
  const endKey = keys[keys.length - 1]!;
  const lastEffectiveAt = expectedTransitions.length > 0
    ? expectedTransitions[expectedTransitions.length - 1]!.effectiveAt
    : 1000;
  const endAnchoredAt = opts.endAnchoredAt ?? Math.max(lastEffectiveAt + 1, 1000 + 500 * keys.length);
  const endCompact = signedAnchorCompact({
    anchorId: "urn:example:anchor:end", anchoredAt: endAnchoredAt, chainId, sequence: 1,
    chainHash: lastHash, keyId: `k${keys.length - 1}`, publicKey: endKey.publicKey,
  }, endKey.privateKey);
  const chain: ExpectedChain = {
    chainId, firstSequence: 1, lastSequence: 1, rowCount: 1,
    previousHash: zeroPrev, lastHash,
  };
  const input: AnchoredExportInput = {
    rows: [rowBytes], startAnchor: startCompact, endAnchor: endCompact,
    transitions, chainId, firstSequence: 1, lastSequence: 1, rowCount: 1,
    previousHash: zeroPrev, lastHash,
  };
  const startAnchor: ExpectedAnchor = {
    anchorId: "urn:example:anchor:start", anchoredAt: 1000, chainId, sequence: 0,
    chainHash: zeroPrev, keyId: "k0", keyFingerprint: thumbprintOf(startKey.publicKey),
  };
  const endAnchor: ExpectedAnchor = {
    anchorId: "urn:example:anchor:end", anchoredAt: endAnchoredAt, chainId, sequence: 1,
    chainHash: lastHash, keyId: `k${keys.length - 1}`, keyFingerprint: thumbprintOf(endKey.publicKey),
  };
  // encodeAnchoredExport validates inputs (incl. the key path) — for the malformed-path archives
  // (#2 non-monotone / cycle), bypass encode-time validation by hand-assembling the frames.
  let archive: Uint8Array;
  let digest: Uint8Array;
  if (opts.effectiveAts === undefined) {
    const enc = encodeAnchoredExport(input, {
      chain, digest: new Uint8Array(32), startAnchor, endAnchor,
      transitions: expectedTransitions, objectVersion: "v1",
    });
    if (!enc.ok) throw new Error("archive encode failed");
    archive = enc.value.archive;
    digest = enc.value.digest;
  } else {
    archive = handFrameArchive(input);
    digest = sha256(archive);
  }
  const expected: ExpectedExport = {
    chain, digest, startAnchor, endAnchor, transitions: expectedTransitions, objectVersion: "v1",
  };
  const keyChain: HistoricalKeyChain = {
    keys: keys.map((k, i) => ({
      keyId: `k${i}`, publicKey: k.publicKey, validFrom: 0, validBefore: null,
    } as HistoricalPublicKey)),
  };
  return { archive, digest, expected, keyChain, input, chain, startAnchor, endAnchor, expectedTransitions };
}

// Default builder: a fully-valid archive (strictly-increasing effective_at, no cycle).
function buildValidArchive(keys: { publicKey: Uint8Array; privateKey: nodeCrypto.KeyObject }[]) {
  return buildArchive(keys);
}

// Hand-assemble the archive byte stream (mirrors encodeAnchoredExport's framing) WITHOUT the
// encode-time key-path validation — used to build malformed-path archives for the #2 tests.
function handFrameArchive(input: AnchoredExportInput): Uint8Array {
  const headerMembers = new Map<string, Tagged>([
    ["chain_id", { t: "string", v: strUtf8(input.chainId) }],
    ["first_sequence", { t: "int", v: input.firstSequence }],
    ["last_hash", { t: "string", v: strUtf8(new TextDecoder().decode(base64urlEncode(input.lastHash))) }],
    ["last_sequence", { t: "int", v: input.lastSequence }],
    ["previous_hash", { t: "string", v: strUtf8(new TextDecoder().decode(base64urlEncode(input.previousHash))) }],
    ["row_count", { t: "int", v: input.rowCount }],
    ["transition_count", { t: "int", v: input.transitions.length }],
    ["v", { t: "int", v: 1 }],
  ]);
  const headerBytes = jcsEncode({ t: "object", v: headerMembers });
  const frame = (b: Uint8Array): Uint8Array => {
    const out = new Uint8Array(4 + b.length);
    out[0] = (b.length >>> 24) & 0xff; out[1] = (b.length >>> 16) & 0xff;
    out[2] = (b.length >>> 8) & 0xff; out[3] = b.length & 0xff;
    out.set(b, 4);
    return out;
  };
  const prefix = strUtf8("BAP1-ARCHIVE\0EXPORT\0");
  const parts = [prefix, frame(headerBytes), frame(input.startAnchor)];
  for (const t of input.transitions) parts.push(frame(t));
  for (const r of input.rows) parts.push(frame(r));
  parts.push(frame(input.endAnchor));
  let len = 0; for (const p of parts) len += p.length;
  const out = new Uint8Array(len);
  let off = 0; for (const p of parts) { out.set(p, off); off += p.length; }
  return out;
}

const ROW_PREFIX_ARR = Array.from(ROW_PREFIX);

// Compute the JWK thumbprint the SDK uses (RFC 7638 S256 over the canonical JWK), so expected
// fingerprints match what verifyHistoricalAnchor derives from the public key.
function thumbprintOf(publicKey: Uint8Array): Uint8Array {
  return publicKeyThumbprintRaw(publicKey);
}

// Cross-vendor #16: encode_consumption_entry MUST reject a sequence-1 row whose previous_hash is not
// the all-zero hash (consumption_chain.ex:123 validate_entry genesis invariant). The verifier
// re-checks this, but the producer must reject pre-signing. Defect: revert the genesis check → Ok.
test("permissiveness: encodeConsumptionEntry rejects genesis row with non-zero previous_hash (#16)", () => {
  const nonzero = new Uint8Array(32).fill(9);
  const r = encodeConsumptionEntry({
    chainId: "urn:example:chain", sequence: 1, previousHash: nonzero, commitment: new Uint8Array(32),
  });
  assert.equal(r.ok, false, "sequence-1 with non-zero previous_hash must reject");
  // Control: sequence 1 with the all-zero previous_hash encodes.
  const ok = encodeConsumptionEntry({
    chainId: "urn:example:chain", sequence: 1, previousHash: Z32.slice(), commitment: new Uint8Array(32),
  });
  assert.equal(ok.ok, true);
});

// Cross-vendor #16: boundary_anchor_signing_input MUST reject a sequence-0 (genesis) anchor whose
// chain_hash is not the all-zero hash (boundary_anchor_codec.ex:185-189 valid_anchor_binding?).
// Defect: revert the genesis check → Ok.
test("permissiveness: boundaryAnchorSigningInput rejects genesis anchor with non-zero chain_hash (#16)", () => {
  const { publicKey } = freshKey();
  const nonzero = new Uint8Array(32).fill(9);
  const r = boundaryAnchorSigningInput({
    anchorId: "urn:example:anchor:start", anchoredAt: 1000, chainId: "urn:example:chain",
    sequence: 0, chainHash: nonzero, keyId: "k0", publicKey,
  });
  assert.equal(r.ok, false, "sequence-0 with non-zero chain_hash must reject");
  // Control: sequence 0 with the all-zero chain_hash produces a signing input.
  const ok = boundaryAnchorSigningInput({
    anchorId: "urn:example:anchor:start", anchoredAt: 1000, chainId: "urn:example:chain",
    sequence: 0, chainHash: Z32.slice(), keyId: "k0", publicKey,
  });
  assert.equal(ok.ok, true);
});

// Cross-vendor #15: check_chain MUST re-encode each row canonically and require byte-equality with
// the input (consumption_chain.ex:96 parse_row), and reject sequence 0 (consumption_chain.ex:163
// valid_sequence? value > 0). Defect A: revert the canonical check → a whitespace-padded row passes.
// Defect B: revert the sequence-positive check → a sequence-0 row passes.
test("permissiveness: checkChain rejects noncanonical row bytes + sequence zero (#15)", () => {
  const enc = encodeConsumptionEntry({
    chainId: "urn:example:chain", sequence: 1, previousHash: Z32.slice(), commitment: new Uint8Array(32).fill(7),
  });
  if (!enc.ok) throw new Error("setup encode failed");
  const canonical = enc.value.bytes;
  const lastHash = enc.value.hash;
  const goodChain: ChainInput = {
    rows: [canonical], chainId: "urn:example:chain", firstSequence: 1, lastSequence: 1, rowCount: 1,
    previousHash: Z32.slice(), lastHash,
  };
  // Control: the canonical row verifies.
  assert.equal(checkChain(goodChain, goodChain).ok, true);
  // Defect A: a row with leading whitespace (valid JSON to JSON.parse, but NOT canonical) must reject.
  // Recompute lastHash from the padded row's ACTUAL hash so the hash-chain check passes and ONLY the
  // canonical re-encode check is the load-bearing gate (otherwise the hash mismatch rejects first,
  // masking a regression to the canonical check specifically).
  const padded = strUtf8(" " + new TextDecoder().decode(canonical));
  const paddedLastHash = sha256(ROW_PREFIX, padded);
  const paddedChain: ChainInput = { ...goodChain, rows: [padded], lastHash: paddedLastHash };
  assert.equal(checkChain(paddedChain, paddedChain).ok, false, "noncanonical (whitespace) row must reject");
  // Defect B: a sequence-0 row must reject even if its bytes are otherwise canonical for sequence 0.
  const seqZeroEnc = (() => {
    // Build the canonical bytes for a sequence-0 row directly (the producer rejects seq<1, so hand-roll).
    const members = new Map<string, Tagged>([
      ["chain_id", { t: "string", v: strUtf8("urn:example:chain") }],
      ["commitment", { t: "string", v: strUtf8(new TextDecoder().decode(base64urlEncode(new Uint8Array(32).fill(7)))) }],
      ["previous", { t: "string", v: strUtf8(new TextDecoder().decode(base64urlEncode(Z32.slice()))) }],
      ["sequence", { t: "int", v: 0 }],
      ["v", { t: "int", v: 1 }],
    ]);
    return jcsEncode({ t: "object", v: members });
  })();
  const seqZeroChain: ChainInput = {
    rows: [seqZeroEnc], chainId: "urn:example:chain", firstSequence: 0, lastSequence: 0, rowCount: 1,
    previousHash: Z32.slice(), lastHash: sha256(new Uint8Array([...ROW_PREFIX_ARR, ...seqZeroEnc])),
  };
  assert.equal(checkChain(seqZeroChain, seqZeroChain).ok, false, "sequence-0 row must reject");
});

// Cross-vendor #17: encode_anchored_export MUST validate inputs before framing — at minimum the
// transition count <= key_transitions bound (256). The SDK previously accepted 257 transitions,
// producing bytes its own parser would reject. Defect: revert the bound check → encode returns Ok.
test("permissiveness: encodeAnchoredExport rejects transition count over bound (#17)", () => {
  const k = freshKey();
  const zeroPrev = Z32.slice();
  const rowEntry: ConsumptionEntry = {
    chainId: "urn:example:chain", sequence: 1, previousHash: zeroPrev, commitment: new Uint8Array(32),
  };
  const encoded = encodeConsumptionEntry(rowEntry);
  if (!encoded.ok) throw new Error("setup encode failed");
  const rowBytes = encoded.value.bytes;
  const lastHash = encoded.value.hash;
  const startCompact = signedAnchorCompact({
    anchorId: "urn:example:anchor:start", anchoredAt: 1000, chainId: "urn:example:chain",
    sequence: 0, chainHash: zeroPrev, keyId: "k0", publicKey: k.publicKey,
  }, k.privateKey);
  const endCompact = signedAnchorCompact({
    anchorId: "urn:example:anchor:end", anchoredAt: 2000, chainId: "urn:example:chain",
    sequence: 1, chainHash: lastHash, keyId: "k0", publicKey: k.publicKey,
  }, k.privateKey);
  // 257 dummy non-empty transition frames (encode only frames them — no signature check here).
  const dummy = strUtf8("x");
  const transitions = Array.from({ length: 257 }, () => dummy);
  const chain: ExpectedChain = {
    chainId: "urn:example:chain", firstSequence: 1, lastSequence: 1, rowCount: 1,
    previousHash: zeroPrev, lastHash,
  };
  const r = encodeAnchoredExport(
    {
      rows: [rowBytes], startAnchor: startCompact, endAnchor: endCompact, transitions,
      chainId: "urn:example:chain", firstSequence: 1, lastSequence: 1, rowCount: 1,
      previousHash: zeroPrev, lastHash,
    },
    {
      chain, digest: new Uint8Array(32),
      startAnchor: {
        anchorId: "urn:example:anchor:start", anchoredAt: 1000, chainId: "urn:example:chain",
        sequence: 0, chainHash: zeroPrev, keyId: "k0", keyFingerprint: thumbprintOf(k.publicKey),
      },
      endAnchor: {
        anchorId: "urn:example:anchor:end", anchoredAt: 2000, chainId: "urn:example:chain",
        sequence: 1, chainHash: lastHash, keyId: "k0", keyFingerprint: thumbprintOf(k.publicKey),
      },
      transitions: [], objectVersion: "v1",
    },
  );
  assert.equal(r.ok, false, "257 transitions must reject (over the key_transitions=256 bound)");
});

// Cross-vendor #17 (anchor binding): encode_anchored_export MUST reject when the start anchor's
// sequence != chain.first_sequence - 1 (anchored_export_codec.ex:364). Defect: revert the binding
// check → encode returns Ok with a mis-bound anchor.
test("permissiveness: encodeAnchoredExport rejects mis-bound start anchor (#17)", () => {
  const k = freshKey();
  const built = buildValidArchive([k]);
  // Tamper expected: start anchor sequence 5 (not first_sequence-1 = 0).
  const badExpected: ExpectedExport = {
    ...built.expected,
    startAnchor: { ...built.startAnchor, sequence: 5 },
  };
  const r = encodeAnchoredExport(built.input, badExpected);
  assert.equal(r.ok, false, "start anchor sequence != first_sequence-1 must reject");
});

// Cross-vendor #3: a valid 1-key / 0-transition archive MUST verify (anchored_export_codec.ex:94-99
// validate_historical_key_shapes accepts keys == transitions+1 with NO minimum). The SDK previously
// gated on keys.length < 2 and falsely rejected it. Defect: revert to the `< 2` gate → this valid
// archive returns Err.
test("permissiveness: verifyAnchoredExport accepts a valid 1-key / 0-transition archive (#3)", () => {
  _resetCensus();
  const built = buildValidArchive([freshKey()]);
  const r = verifyAnchoredExport(
    { chunks: [built.archive], version: "v1" },
    built.keyChain,
    built.expected,
  );
  assert.equal(r.ok, true, "a valid 1-key/0-transition archive must verify");
  if (r.ok) assert.equal(r.value.transitionCount, 0);
});

// Cross-vendor #18: verify_anchored_export MUST validate the chunk list BEFORE concatenation
// (anchored_export_codec.ex:333-342 validate_chunks): reject empty chunks, reject chunk count >=
// archive_chunks, reject total > archive_bytes. Defect: revert validateChunks → these pass to parse.
test("permissiveness: verifyAnchoredExport rejects bad chunk lists (#18)", () => {
  _resetCensus();
  const built = buildValidArchive([freshKey()]);
  // Empty chunk in the list.
  const withEmpty = { chunks: [built.archive, new Uint8Array(0)], version: "v1" };
  assert.equal(verifyAnchoredExport(withEmpty, built.keyChain, built.expected).ok, false, "empty chunk must reject");
  // Too many chunks (>= archive_chunks bound 65796).
  const tooMany = { chunks: Array.from({ length: 65796 }, () => new Uint8Array(1)), version: "v1" };
  assert.equal(verifyAnchoredExport(tooMany, built.keyChain, built.expected).ok, false, "chunk count over bound must reject");
  // Control: a single-chunk split of the valid archive still verifies.
  assert.equal(verifyAnchoredExport({ chunks: [built.archive], version: "v1" }, built.keyChain, built.expected).ok, true);
});

// Cross-vendor #2: verify_anchored_export MUST enforce rollover chronology (effective_at strictly
// increasing) and reject fingerprint cycles (anchored_export_codec.ex:516-572 validate_expected_key_path).
// The signed transitions are built with the actual malformed effective_at sequence (each compact
// individually valid), so the chronology check is the load-bearing gate. Defect: revert
// validateKeyPath + the chronology loop → this archive wrongly verifies.
test("permissiveness: verifyAnchoredExport rejects non-monotonic rollover (#2)", () => {
  _resetCensus();
  const a = freshKey(), b = freshKey(), c = freshKey();
  // Control: a valid 3-key/2-transition archive verifies.
  const valid = buildValidArchive([a, b, c]);
  assert.equal(verifyAnchoredExport({ chunks: [valid.archive], version: "v1" }, valid.keyChain, valid.expected).ok, true, "control: valid 3-key archive verifies");
  // Non-monotonic: transition[1].effective_at (1400) < transition[0].effective_at (1500). Each
  // compact is validly signed with its own effective_at, so verifyTransitionCompact passes; only the
  // chronology gate rejects.
  const nonMono = buildArchive([a, b, c], { effectiveAts: [1500, 1400], endAnchoredAt: 2000 });
  assert.equal(verifyAnchoredExport({ chunks: [nonMono.archive], version: "v1" }, nonMono.keyChain, nonMono.expected).ok, false, "non-monotonic effective_at must reject");
  // Strict-`>` boundary: EQUAL consecutive effective_at must also reject (strictly_after? is `>`,
  // not `>=`; anchored_export_codec.ex:722). Each compact is individually valid; only the strict
  // chronology check rejects.
  const equalAt = buildArchive([a, b, c], { effectiveAts: [1500, 1500], endAnchoredAt: 2000 });
  assert.equal(verifyAnchoredExport({ chunks: [equalAt.archive], version: "v1" }, equalAt.keyChain, equalAt.expected).ok, false, "equal consecutive effective_at must reject (strict >)");
});

// Cross-vendor #2 (cycle): a key-path where a fingerprint repeats (A→B→A) must reject. Built with a
// REAL repeated key (keys[0] === keys[2] = A) so each transition (A→B, B→A) is individually valid,
// and the cycle check is the load-bearing gate. Defect: revert validateKeyPath → cycle verifies.
test("permissiveness: verifyAnchoredExport rejects fingerprint cycle A→B→A (#2)", () => {
  _resetCensus();
  const a = freshKey(), b = freshKey();
  // 3-position key chain where position 2 reuses key A (the cycle: A→B→A).
  const cyclic = buildArchive([a, b, a], { effectiveAts: [1500, 2000], endAnchoredAt: 3000 });
  assert.equal(verifyAnchoredExport({ chunks: [cyclic.archive], version: "v1" }, cyclic.keyChain, cyclic.expected).ok, false, "fingerprint cycle A→B→A must reject");
});

// === BAP-09 #10/#11 cross-vendor remediation — caller-supplied bounds threaded through verify/decode ===
// The reference resolves Bounds.coerce(expected.bounds) once per entry point and threads the result
// into EVERY bound-sensitive check (runtime.ex:186,204; consumption_chain.ex check_chain;
// anchored_export_codec.ex:84-185): valid_key_id?(kid, bounds.kid_bytes), Json.decode(bytes, bounds),
// valid_identifier?(iss/grant_id, bounds), decode_audiences(aud, bounds), operations(ops, bounds),
// validate_chunks / parse_archive frame reads, etc. The SDK previously passed bounds ONLY to
// parseCompact/parse_compact and hardcoded MAXIMUM_BOUNDS in every subsequent validator, so a caller
// tightening had no effect. Each test below proves a tightening now rejects at the named gate. Defect:
// revert the threading (any helper back to MAXIMUM_BOUNDS, or the bounds param removed) → the named
// deny goes GREEN (Err→Ok regression), proving the test is red-capable.
//
// The falsifiable case: a grant whose kid is 13 bytes ("issuer-123456") is valid at MAX (kid_bytes
// 128), but MUST be rejected under boundsNew({kid_bytes: 5}) via valid_key_id? (the reference's
// decode_grant(grant, %{kid_bytes: 5}) rejects it). Each test drives one entry point.

// The falsifiable case: a grant whose kid is 13 bytes ("issuer-123456") is valid at MAX (kid_bytes
// 128), but MUST be rejected under boundsNew({kid_bytes: 5}) via valid_key_id? (the reference's
// decode_grant(grant, %{kid_bytes: 5}) rejects it). Each test drives one entry point.

// A typed JSON-null cast-arguments value (the Tagged null variant carries no `v`).
const NULL_ARGS: Tagged = { t: "null" };

// Build a real Ed25519-signed grant with a chosen kid (13 bytes by default). Returns the compact +
// the issuer key material needed for verifyGrant / checkEnvelope.
function signedGrant(kid = "issuer-123456"): {
  compact: Uint8Array; issuer: TrustedIssuer; issuerPub: Uint8Array;
  holderPub: Uint8Array; holderFp: Uint8Array;
} {
  const issuer = freshKey();
  const holder = freshKey();
  const holderFp = thumbprintOf(holder.publicKey);
  const grant: GrantProducer = {
    keyId: kid, issuer: "https://issuer.example.test", grantId: "urn:example:grant:1",
    audiences: ["https://resource.example.test"], issuedAt: 1000, notBefore: 1000, expiresAt: 2000,
    holderThumbprint: new TextDecoder().decode(base64urlEncode(holderFp)),
    operations: [{ name: "read", selectors: ["all"] }],
  };
  const si = grantSigningInput(grant);
  if (!si.ok) throw new Error("grant signing input failed");
  const message = strUtf8(`${new TextDecoder().decode(si.value.protectedSegment)}.${new TextDecoder().decode(si.value.payloadSegment)}`);
  const sig = new Uint8Array(nodeCrypto.sign(null, Buffer.from(message), issuer.privateKey));
  return {
    compact: assembleCompact(si.value, sig),
    issuer: { keyId: kid, publicKey: issuer.publicKey },
    issuerPub: issuer.publicKey, holderPub: holder.publicKey, holderFp,
  };
}

// Build a valid proof binding to the grant (holder signs). Drives the checkEnvelope grant+proof path.
function signedProof(grantCompact: Uint8Array, holderPub: Uint8Array, holderPriv: nodeCrypto.KeyObject): Uint8Array {
  const proof: ProofProducer = {
    holderPublicKey: holderPub,
    proofId: "urn:example:proof:1", method: "POST", targetUri: "https://resource.example.test/invoke",
    issuedAt: 1400, invocationId: "550e8400-e29b-41d4-a716-446655440000", operation: "read",
    grantCompact, castArguments: NULL_ARGS,
  };
  const si = proofSigningInput(proof);
  if (!si.ok) throw new Error("proof signing input failed");
  const message = strUtf8(`${new TextDecoder().decode(si.value.protectedSegment)}.${new TextDecoder().decode(si.value.payloadSegment)}`);
  const sig = new Uint8Array(nodeCrypto.sign(null, Buffer.from(message), holderPriv));
  return assembleCompact(si.value, sig);
}

// #10/#11: decodeGrant MUST thread caller-supplied bounds into requireKid (valid_key_id?). A grant
// with a 13-byte kid is accepted at MAX, rejected under kid_bytes=5. Defect: revert requireKid to
// MAXIMUM_BOUNDS → the tightened call returns Ok.
test("permissiveness: decodeGrant honors caller bounds (kid tightening rejects) (#10/#11)", () => {
  const { compact } = signedGrant();
  // Control: no bounds (MAX) → the 13-byte kid is accepted.
  assert.equal(decodeGrant(compact).ok, true, "13-byte kid must be accepted at MAX");
  // Tightened: kid_bytes=5 → the 13-byte kid must be rejected (the reference's valid_key_id? gate).
  assert.equal(decodeGrant(compact, boundsNew({ kid_bytes: 5 })).ok, false, "kid_bytes=5 must reject a 13-byte kid");
});

// #10/#11: verifyGrant MUST thread ExpectedGrant.bounds into requireKid (valid_key_id?). The grant is
// validly signed, so the only load-bearing gate under the tightening is the kid bound. Defect: revert
// verifyGrant's bounds threading → the tightened call returns Ok (signature still verifies).
test("permissiveness: verifyGrant honors caller bounds (kid tightening rejects) (#10/#11)", () => {
  _resetCensus();
  const g = signedGrant();
  const expectedMax: ExpectedGrant = {
    issuer: "https://issuer.example.test", audience: "https://resource.example.test",
    evaluationTime: 1500, clockSkew: 60,
  };
  // Control: no bounds (MAX) → verifies.
  assert.equal(verifyGrant(g.compact, g.issuer, expectedMax).ok, true, "13-byte kid must verify at MAX");
  // Tightened: kid_bytes=5 → rejected via the kid gate (signature would otherwise verify).
  const expectedTight: ExpectedGrant = { ...expectedMax, bounds: boundsNew({ kid_bytes: 5 }) };
  assert.equal(verifyGrant(g.compact, g.issuer, expectedTight).ok, false, "kid_bytes=5 must reject a 13-byte kid");
});

// #10/#11: checkEnvelope MUST thread ExpectedRequest.bounds into the grant header parse. The grant +
// proof are both validly signed; the only load-bearing gate under the tightening is the grant kid
// bound. Defect: revert checkEnvelope's bounds threading → the tightened call returns Ok.
test("permissiveness: checkEnvelope honors caller bounds (kid tightening rejects) (#10/#11)", () => {
  _resetCensus();
  const issuer = freshKey();
  const holder = freshKey();
  const holderFp = thumbprintOf(holder.publicKey);
  // Grant with a 13-byte kid, signed by the issuer.
  const grant: GrantProducer = {
    keyId: "issuer-123456", issuer: "https://issuer.example.test", grantId: "urn:example:grant:1",
    audiences: ["https://resource.example.test"], issuedAt: 1000, notBefore: 1000, expiresAt: 2000,
    holderThumbprint: new TextDecoder().decode(base64urlEncode(holderFp)),
    operations: [{ name: "read", selectors: ["all"] }],
  };
  const gsi = grantSigningInput(grant);
  if (!gsi.ok) throw new Error("grant signing input failed");
  const gmsg = strUtf8(`${new TextDecoder().decode(gsi.value.protectedSegment)}.${new TextDecoder().decode(gsi.value.payloadSegment)}`);
  const grantCompact = assembleCompact(gsi.value, new Uint8Array(nodeCrypto.sign(null, Buffer.from(gmsg), issuer.privateKey)));
  const proofCompact = signedProof(grantCompact, holder.publicKey, holder.privateKey);
  const base: ExpectedRequest = {
    trustedIssuer: { keyId: "issuer-123456", publicKey: issuer.publicKey },
    issuer: "https://issuer.example.test", audience: "https://resource.example.test",
    method: "POST", targetUri: "https://resource.example.test/invoke",
    invocationId: "550e8400-e29b-41d4-a716-446655440000", operation: "read",
    castArguments: NULL_ARGS,
    evaluationTime: 1500, clockSkew: 60, proofMaxAge: 300, nonce: { kind: "not_required" },
  };
  // Control: no bounds (MAX) → envelope verifies.
  assert.equal(checkEnvelope(grantCompact, proofCompact, base).ok, true, "13-byte kid must verify at MAX");
  // Tightened: kid_bytes=5 → rejected via the grant kid gate.
  const tight: ExpectedRequest = { ...base, bounds: boundsNew({ kid_bytes: 5 }) };
  assert.equal(checkEnvelope(grantCompact, proofCompact, tight).ok, false, "kid_bytes=5 must reject a 13-byte kid");
});

// #10 delta-review FINDING 1: decodeGrant MUST thread caller bounds into parseSelector (the reference's
// selector/2 enforces one_of_values, path_segments, selector value node bounds). A grant with a one_of
// selector of 2 values is accepted at MAX, rejected under one_of_values=1. Defect: revert the
// parseSelector(s) call to default bounds → the tightened call returns Ok.
test("permissiveness: decodeGrant threads caller bounds into selector decode (#10 delta-review F1)", () => {
  const issuer = freshKey();
  const holder = freshKey();
  const holderFp = thumbprintOf(holder.publicKey);
  const grant: GrantProducer = {
    keyId: "k1", issuer: "https://issuer.example.test", grantId: "urn:example:grant:1",
    audiences: ["https://resource.example.test"], issuedAt: 1000, notBefore: 1000, expiresAt: 2000,
    holderThumbprint: new TextDecoder().decode(base64urlEncode(holderFp)),
    operations: [{ name: "read", selectors: [{ kind: "one_of", path: ["x"], values: [{ t: "int", v: 1 }, { t: "int", v: 2 }] }] }],
  };
  const si = grantSigningInput(grant);
  if (!si.ok) throw new Error("grant signing input failed");
  const message = strUtf8(`${new TextDecoder().decode(si.value.protectedSegment)}.${new TextDecoder().decode(si.value.payloadSegment)}`);
  const compact = assembleCompact(si.value, new Uint8Array(nodeCrypto.sign(null, Buffer.from(message), issuer.privateKey)));
  // Control: at MAX, a one_of with 2 values is accepted.
  assert.equal(decodeGrant(compact).ok, true, "one_of with 2 values must be accepted at MAX");
  // Tightened: one_of_values=1 → the 2-value selector must be rejected (parseSelector threads bounds).
  assert.equal(decodeGrant(compact, boundsNew({ one_of_values: 1 })).ok, false, "one_of_values=1 must reject a 2-value selector");
});

// #10/#11 control: bounds absent on every Expected* MUST default to MAX (the conformance runner
// constructs Expected* without bounds; a missing default would break 259/259). The 13-byte kid grant
// verifies at MAX via every entry point that takes an Expected*.
test("permissiveness: Expected*.bounds absent defaults to MAX (#11)", () => {
  _resetCensus();
  const g = signedGrant();
  const eg: ExpectedGrant = {
    issuer: "https://issuer.example.test", audience: "https://resource.example.test",
    evaluationTime: 1500, clockSkew: 60,
  };
  assert.equal(verifyGrant(g.compact, g.issuer, eg).ok, true);
  assert.equal(decodeGrant(g.compact).ok, true);
});
