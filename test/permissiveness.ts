// Language-specific permissiveness tests complement the independent corpus. Each constructs
// host-runtime defects and requires the SDK to reject them. The authoring mutation battery
// removed each corresponding guard and observed its named test fail:
// 1. Removing duplicate detection admits a duplicate member at depth 3.
// 2. Dropping __proto__ members collapses distinct selector identities.
// 3. Removing the 64-byte lexeme ceiling admits the 66-byte spelling of 1e-64. Its finite
//    value satisfies the magnitude bound, isolating the lexeme check.
// 4. Removing full-input consumption admits trailing bytes and two top-level values.
// 5. Collapsing integer and float tags makes 1 and 1.0 share selector identity.
// 6. Disabling key-import registration breaks the two-boundary census.
// 7. Adding Date.now() to verification fails the purity lint.
// 8. Adding a runtime dependency outside the allowlist fails the license check.
// The decoder uses Maps to retain member data and checks raw lexemes before conversion.
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
  encodeAnchoredExport, verifyAnchoredExport, ROW_PREFIX,
  type BoundaryAnchorProducer, type ConsumptionEntry, type ChainInput, type ExpectedChain,
  type AnchoredExportInput, type ExpectedExport, type ExpectedAnchor, type ExpectedKeyTransition,
  type HistoricalKeyChain, type HistoricalPublicKey, type KeyTransitionProducer,
  decodeGrant, verifyGrant, grantSigningInput, proofSigningInput,
  type GrantProducer, type ProofProducer, type ExpectedGrant, type TrustedIssuer,
  type SigningInput,
} from "../src/v1.js";
import { boundsNew, MAXIMA, type Bounds } from "../src/bounds.js";
import { assembleSegments, assembleSegmentsEs256 } from "../src/compact.js";
import { sha256, _resetCensus, acceptablePublicKey } from "../src/ed25519.js";
import { publicKeyThumbprintRaw } from "../src/jwk.js";

const dec = (s: string) => jsonDecode(strUtf8(s));

function rejects(label: string, fn: () => unknown): void {
  test(`permissiveness: ${label}`, () => {
    assert.throws(fn, InvalidError, `expected ${label} to reject with InvalidError`);
  });
}

// Duplicate detection must reject at every depth. JSON.parse keeps the last repeated
// value; these depth-3 cases isolate the SDK decoder beyond the depth-1 corpus case.
rejects("duplicate member at depth 3 (JSON.parse would last-wins)", () =>
  dec('{"a":{"b":{"c":1,"c":2}}}'));
test("permissiveness: distinct members accepted (duplicate closure intact)", () => {
  const v = dec('{"a":1,"b":2}');
  assert.equal(v.t, "object");
});

// Maps preserve __proto__ as member data. Plain-object assignment can invoke its
// prototype setter, erase the member and collapse two distinct selector identities.
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

// The 66-byte spelling below represents finite 1e-64 and satisfies the magnitude bound.
// Only the raw 64-byte lexeme ceiling rejects it, isolating that parser guard.
rejects("66-byte number lexeme (Number rounds to a finite within-magnitude float)", () =>
  dec("0." + "0".repeat(63) + "1"));
rejects("integer magnitude over bound (2^53)", () =>
  dec("9007199254740992")); // MAXIMA.integer_magnitude + 1

// Full-input consumption permits whitespace after one value and rejects further values
// or non-whitespace bytes.
rejects("trailing bytes after the top-level value", () => dec('{} junk'));
rejects("two top-level values", () => dec('1 2'));

// JSON.parse collapses 1 and 1.0 into one JavaScript number. Tagged projection must
// preserve their distinct selector identities.
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

// These fail-closed parser and URI cases pin normative rejection rules. The authoring
// mutation run removed each guard and observed its named test fail.

// Cross-vendor #14: malformed UTF-8 in an object member name must fail closed (InvalidError), not
// throw a non-InvalidError TypeError via the fatal TextDecoder. Defect: revert parseObject to the
// bare `utf8Str(nameBytes)` (no DECODER.decode try/catch) → this throws TypeError.
test("permissiveness: malformed UTF-8 member name fails closed (cross-vendor #14)", () => {
  // The member name begins with the invalid UTF-8 byte 0xFF.
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
  // Dotted IPv4 text is legal only in the final IPv6 group. The non-tail group here
  // must fail the hexadecimal-group parser.
  const bad = ["https://[:::]/", "https://[1:2:3:4:5:6:7:8:9]/", "https://[1::2::3]/", "https://[gggg]/", "https://[1.2.3.4:5::6]/"];
  for (const u of bad) {
    assert.equal(uriNormalize(strUtf8(u)).ok, false, `${u} should be invalid`);
  }
  // Controls: valid IPv6 literals still normalize.
  const good = ["https://[::1]/", "https://[2001:db8::1]/", "https://[1:2:3:4:5:6:7:8]/", "https://[::ffff:192.0.2.1]/"];
  for (const u of good) {
    assert.equal(uriNormalize(strUtf8(u)).ok, true, `${u} should be valid`);
  }
});

// Cross-vendor #8: JCS DEL (U+007F) MUST emit the raw byte 0x7f. This is RFC-CONFORMANT, not a
// deviation: RFC 8785 §3.2.2.2 escapes only U+0000–U+001F plus quote (0x22) and backslash (0x5c);
// DEL (0x7f) is outside that range, so it is serialized "as is" (raw). The reference (jcs.ex:142-148:
// the < 0x20 branch skips DEL, the general codepoint clause emits it raw) and JSON.stringify agree.
// Defect: revert to the appendU branch → bytes differ ([34,120,92,117,48,48,55,102,121,34]).
test("permissiveness: jcs DEL emits raw byte matching reference (cross-vendor #8)", () => {
  const v: Tagged = { t: "string", v: strUtf8("x\u007fy") };
  assert.deepEqual(Array.from(jcsEncode(v)), [34, 120, 127, 121, 34]); // "x<raw DEL>y"
});

// JCS encoding must enforce per-node limits during traversal. A 257-item array, depth-33
// array and 8193-byte string exceed their respective limits of 256, 32 and 8192. Removing
// traversal checks admits these cases even when final output size remains acceptable.
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

// The v1 public boundary returns closed Results for malformed caller inputs.

// The untrusted key locator reads only the protected segment. Garbage payload and
// signature bytes must not prevent header discovery. Full compact parsing would
// incorrectly reject these header-only inputs.
test("permissiveness: untrusted key locator decodes only protected segment (cross-vendor #13)", () => {
  const protectedB64 = "eyJhbGciOiJFZERTQSIsImtpZCI6ImsxIiwidHlwIjoiYmErY2FwIn0";
  // Garbage payload + signature (non-base64url bytes).
  const r = untrustedKeyLocator(strUtf8(`${protectedB64}.!!.!!!`));
  assert.equal(r.ok, true);
  if (r.ok) assert.equal(r.value.keyId, "k1");
  // The ignored payload has a valid base64url spelling but does not contain JSON.
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
  // A REAL generated key: the all-zero array is an order-4 point that key acceptance refuses, so it would
  // make the integer-context control below reject for the key instead of for the junk compact it names.
  const issuer = { keyId: strUtf8("k"), publicKey: freshKey().publicKey };
  assert.equal(acceptablePublicKey(issuer.publicKey), true, "control: the generated issuer key passes key acceptance");
  const base = {
    trustedIssuer: issuer, issuer: "x", audience: "x", method: "GET", targetUri: "https://x.example/",
    invocationId: "550e8400-e29b-41d4-a716-446655440000", operation: "read",
    castArguments: { t: "null" as const, v: null }, nonce: "not_required" as const,
  };
  const call = (overrides: Partial<ExpectedRequest>) => checkEnvelope(junk, junk, { ...base, ...overrides } as ExpectedRequest);
  // All malformed arguments must return Err without throwing. The integer control also
  // returns Err because its junk compact fails grant parsing.
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

// Chain and archive tests generate real Ed25519 keys and signatures, then mutate one
// variable per case. Malformed paths use hand-framed archives so encode-time guards
// cannot hide missing verification-time chronology or cycle checks.

// Unwrap a Result<Uint8Array> from the low-level assembler in test helpers (failure is a test-setup
// bug). Uses assembleSegments (not the validating façade) so permissiveness cases can build compacts
// freely and then prove the VERIFY path (or the façade) rejects them.
function mustAssemble(si: SigningInput, sig: Uint8Array): Uint8Array {
  const c = assembleSegments(si, sig);
  if (!c.ok) throw new Error("assembleSegments failed in test helper");
  return c.value;
}

// The ES256 form for contract-major 3 fixtures (the two suites have separate assemblers, as the
// reference does; erratum 3 gates each by its own signature rule).
function mustAssembleEs256(si: SigningInput, sig: Uint8Array): Uint8Array {
  const c = assembleSegmentsEs256(si, sig);
  if (!c.ok) throw new Error("assembleSegmentsEs256 failed in test helper");
  return c.value;
}

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
  return mustAssemble(si.value, sig);
}

const Z32 = new Uint8Array(32); // the all-zero 32-byte hash (genesis chain_hash / predecessor)

// Build an archive with a chosen key path: N keys yield N-1 transitions. effective_at
// normally increases as 1500, 2000 and onward; effectiveAts can supply malformed chronology.
// Rows use encodeConsumptionEntry. Invalid paths are hand-framed, allowing verification
// to reject them independently of the encoder.
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
    transitions.push(mustAssemble(si.value, sig));
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
  // Hand-frame malformed paths so the encoder cannot intercept these verification cases.
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

// Frame archive bytes without encode-time path validation for malformed-path tests.
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

// Encoding must enforce the 256-transition ceiling before framing. Removing the check
// admits a 257-transition archive that its decoder would reject.
test("permissiveness: encodeAnchoredExport rejects transition count over bound (#17)", () => {
  const zeroPrev = Z32.slice();
  const rowEntry: ConsumptionEntry = {
    chainId: "urn:example:chain", sequence: 1, previousHash: zeroPrev, commitment: new Uint8Array(32),
  };
  const encoded = encodeConsumptionEntry(rowEntry);
  if (!encoded.ok) throw new Error("setup encode failed");
  const rowBytes = encoded.value.bytes;
  const lastHash = encoded.value.hash;
  // FIX-D delta-review FINDING 2: supply 257 matching ExpectedKeyTransition entries over a 258-key
  // chain so the count-mismatch check passes and the key_transitions=256 BOUND check is the
  // load-bearing gate (otherwise expected.transitions=[] makes count-mismatch fire first). Build a
  // chronology-clean path (distinct keys, strictly-increasing effectiveAt, no fingerprint cycle).
  const keys = Array.from({ length: 258 }, () => freshKey());
  const startKey = keys[0]!;
  const endKey = keys[257]!;
  const startCompact = signedAnchorCompact({
    anchorId: "urn:example:anchor:start", anchoredAt: 1000, chainId: "urn:example:chain",
    sequence: 0, chainHash: zeroPrev, keyId: "k0", publicKey: startKey.publicKey,
  }, startKey.privateKey);
  const endCompact = signedAnchorCompact({
    anchorId: "urn:example:anchor:end", anchoredAt: 100000, chainId: "urn:example:chain",
    sequence: 1, chainHash: lastHash, keyId: "k257", publicKey: endKey.publicKey,
  }, endKey.privateKey);
  const transitions: Uint8Array[] = Array.from({ length: 257 }, () => strUtf8("x"));
  const expectedTransitions: ExpectedKeyTransition[] = keys.slice(0, 257).map((_, i) => ({
    transitionId: `urn:example:t:${i}`, chainId: "urn:example:chain", effectiveAt: 2000 + i,
    currentKeyId: `k${i}`, currentKeyFingerprint: thumbprintOf(keys[i]!.publicKey),
    nextKeyId: `k${i + 1}`, nextKeyFingerprint: thumbprintOf(keys[i + 1]!.publicKey),
  }));
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
        sequence: 0, chainHash: zeroPrev, keyId: "k0", keyFingerprint: thumbprintOf(startKey.publicKey),
      },
      endAnchor: {
        anchorId: "urn:example:anchor:end", anchoredAt: 100000, chainId: "urn:example:chain",
        sequence: 1, chainHash: lastHash, keyId: "k257", keyFingerprint: thumbprintOf(endKey.publicKey),
      },
      transitions: expectedTransitions, objectVersion: "v1",
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

// Cross-vendor re-review F2: a zero-key key chain MUST fail closed (Err), not raise TypeError on
// keyChain.keys[0]. The length check (keys == transitions+1) must fire BEFORE the keys[0] deref.
test("permissiveness: verifyAnchoredExport rejects zero-key chain fail-closed (cv re-review F2)", () => {
  _resetCensus();
  const built = buildValidArchive([freshKey()]);
  const emptyChain: HistoricalKeyChain = { keys: [] };
  const r = verifyAnchoredExport(
    { chunks: [built.archive], version: "v1" },
    emptyChain,
    built.expected,
  );
  assert.equal(r.ok, false, "zero-key chain must reject (keys != transitions+1), fail closed");
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
  // The archive_chunks limit is inclusive at 65796. Use 65797 chunks to isolate this
  // count guard; exactly 65796 would fail only the later digest check.
  const tooMany = { chunks: Array.from({ length: 65797 }, () => new Uint8Array(1)), version: "v1" };
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

// Every bound-sensitive check must use caller Bounds, including identifiers, JSON,
// selectors and archive frames. A 13-byte kid satisfies the 128-byte maximum but fails
// a 5-byte caller limit. Replacing a threaded bound with the maximum admits the case.

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
    compact: mustAssemble(si.value, sig),
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
  return mustAssemble(si.value, sig);
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
  const grantCompact = mustAssemble(gsi.value, new Uint8Array(nodeCrypto.sign(null, Buffer.from(gmsg), issuer.privateKey)));
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
  const compact = mustAssemble(si.value, new Uint8Array(nodeCrypto.sign(null, Buffer.from(message), issuer.privateKey)));
  // Control: at MAX, a one_of with 2 values is accepted.
  assert.equal(decodeGrant(compact).ok, true, "one_of with 2 values must be accepted at MAX");
  // Tightened: one_of_values=1 → the 2-value selector must be rejected (parseSelector threads bounds).
  assert.equal(decodeGrant(compact, boundsNew({ one_of_values: 1 })).ok, false, "one_of_values=1 must reject a 2-value selector");
});

// #10/#11 control: bounds absent on every Expected* MUST default to MAX (the conformance runner
// constructs Expected* without bounds; a missing default would break 283/283). The 13-byte kid grant
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

// Cross-vendor F2: a hand-crafted Bounds (structural interface) with a WIDENING override bypasses
// boundsNew; resolve() trusts it. Every entry point must re-validate (mirrors reference Bounds.coerce).
// Defect: revert coerceBounds in v1.ts/jcs.ts/compact.ts/digest.ts → a forged widening is honored.
test("permissiveness: forged widening Bounds rejected at every entry point (F2)", () => {
  _resetCensus();
  const forged: Bounds = { maximum: MAXIMA, overrides: new Map([["compact_bytes", 1000000]]) };
  // resolve() WOULD honor the override (1_000_000 > MAXIMA.compact_bytes 65_536); verifyGrant must
  // re-validate via coerceBounds and reject the forged bounds rather than trust the widening.
  const g = signedGrant();
  const eg: ExpectedGrant = {
    issuer: "https://issuer.example.test", audience: "https://resource.example.test",
    evaluationTime: 1500, clockSkew: 60, bounds: forged,
  };
  assert.equal(verifyGrant(g.compact, g.issuer, eg).ok, false, "forged widening bounds must reject");
});

// Cross-vendor F3: a non-integer int-tag value (1.5) or a boolean must fail closed at jcsEncode
// (reference guard `when is_integer(value)`, jcs.ex:38), not canonicalize to "1.5"/"true".
// Defect: remove the Number.isInteger check in jcs.ts int case → {t:"int",v:1.5} emits "1.5".
test("permissiveness: jcsEncode rejects non-integer int-tag value (F3)", () => {
  // Control: a valid integer int-tag encodes.
  assert.equal(jcsEncode({ t: "int", v: 2 }).length > 0, true, "control: integer int-tag encodes");
  // An int tag carrying 1.5 must reject. jcsEncode signals the failure with InvalidError.
  let threw = false;
  try { jcsEncode({ t: "int", v: 1.5 } as unknown as Tagged); } catch { threw = true; }
  assert.equal(threw, true, "{t:'int', v:1.5} must fail closed (non-integer int-tag)");
  let threwBool = false;
  try { jcsEncode({ t: "int", v: true } as unknown as Tagged); } catch { threwBool = true; }
  assert.equal(threwBool, true, "{t:'int', v:true} must fail closed (bool is not an integer)");
});

// Cross-vendor (JCS UTF-8): a programmatically-built JString with invalid UTF-8 bytes must fail
// closed at jcsEncode (reference String.valid?, jcs.ex:58), not throw a TypeError past the contract.
// Defect: remove the isValidUtf8 gate in jcs.ts string case → invalid bytes reach utf8Str → TypeError.
test("permissiveness: jcsEncode rejects invalid-UTF-8 string (closed-result, not TypeError)", () => {
  let threwInvalid = false;
  let threwTypeError = false;
  try { jcsEncode({ t: "string", v: new Uint8Array([0x80, 0x81]) }); }
  catch (e) { threwInvalid = e instanceof InvalidError; threwTypeError = e instanceof TypeError; }
  assert.equal(threwInvalid, true, "invalid-UTF-8 string must fail as InvalidError");
  assert.equal(threwTypeError, false, "must NOT escape as TypeError (closed-result contract)");
});

// The header-only locator accepts empty payload and signature segments. Reintroducing
// full-compact empty-segment rejection makes this locator test fail.
test("permissiveness: untrustedKeyLocator accepts empty payload/signature segments (reference parity)", () => {
  _resetCensus();
  const g = signedGrant();
  // Use a valid protected header followed by two empty segments.
  const compactStr = new TextDecoder().decode(g.compact);
  const protectedSeg = compactStr.split(".")[0]!;
  const emptyPs = new TextEncoder().encode(protectedSeg + "..");
  const r = untrustedKeyLocator(emptyPs);
  assert.equal(r.ok, true, "empty payload+signature segments must be accepted (reference decodes protected only)");
  if (r.ok) assert.equal(r.value.keyId, g.issuer.keyId);
});

// Cross-vendor (nested bounds pinning): the reference pins every nested bounds == top-level
// (anchored_export_codec.ex:352-354). A nested anchor carrying a DIFFERENT bounds must reject.
// Defect: remove requireBoundsEqual in verifyAnchoredExport → a tightened top + nested default-MAX
// (or a divergent nested override) is silently accepted.
test("permissiveness: verifyAnchoredExport rejects nested bounds mismatch (reference pin)", () => {
  _resetCensus();
  const built = buildValidArchive([freshKey()]);
  // Tighten the top-level bounds; the nested anchors carry no bounds (default MAX) → pin must reject.
  const tightened: ExpectedExport = {
    ...built.expected,
    bounds: boundsNew({ identifier_bytes: 4 }),
  };
  assert.equal(verifyAnchoredExport({ chunks: [built.archive], version: "v1" }, built.keyChain, tightened).ok, false,
    "nested bounds absent under a tightened top must reject (reference pin)");
});

// Cross-vendor (fail-closed shallow): a malformed trusted issuer ({}, missing publicKey/keyId) must
// fail closed as Err, not throw a native TypeError past the Result contract (the reference pattern-
// matches %TrustedIssuer{} and returns {:error,:invalid}). Defect: revert the shape check → TypeError.
test("permissiveness: malformed trusted issuer fails closed (verifyGrant + checkEnvelope)", () => {
  _resetCensus();
  const g = signedGrant();
  const eg: ExpectedGrant = {
    issuer: "https://issuer.example.test", audience: "https://resource.example.test",
    evaluationTime: 1500, clockSkew: 60,
  };
  // Missing publicKey and keyId must return Err without throwing.
  const r = verifyGrant(g.compact, {} as unknown as TrustedIssuer, eg);
  assert.equal(r.ok, false, "malformed trusted issuer {} must fail closed (verifyGrant)");
  const er: ExpectedRequest = {
    trustedIssuer: {} as unknown as TrustedIssuer,
    issuer: "https://issuer.example.test", audience: "https://resource.example.test",
    method: "POST", targetUri: "https://resource.example.test/invoke", invocationId: "i",
    operation: "read", castArguments: NULL_ARGS, evaluationTime: 1500, clockSkew: 60, proofMaxAge: 300,
    nonce: { kind: "not_required" },
  };
  const ce = checkEnvelope(g.compact, g.compact, er);
  assert.equal(ce.ok, false, "malformed trusted issuer {} must fail closed (checkEnvelope)");
});

// Cross-vendor F4: the genesis chain (firstSequence==1) must not return an unchecked chain.previousHash
// as a verified fact. The reference returns expected.previous_hash; the SDK now validates
// chain.previousHash == expected.previousHash in BOTH cases (genesis + non-genesis).
// Defect: revert the equality check + return chain.previousHash → a forged genesis input flows through.
test("permissiveness: checkChain rejects genesis chain.previousHash != expected.previousHash (F4)", () => {
  _resetCensus();
  const ZERO = new Uint8Array(32); // all-zero genesis predecessor (DEFAULT_HASH in v1.ts)
  // Build a minimal valid genesis chain input.
  const chainId = "ba://chain-f4";
  const commitment = sha256(strUtf8("commitment-f4"));
  const row0Result = encodeConsumptionEntry({ chainId, sequence: 1, previousHash: ZERO, commitment });
  if (!row0Result.ok) throw new Error("row encode failed");
  const row0 = row0Result.value.bytes;
  const lastHash = sha256(ROW_PREFIX, row0);
  const chain: ChainInput = {
    rows: [row0], chainId, firstSequence: 1, lastSequence: 1, rowCount: 1,
    previousHash: ZERO, lastHash,
  };
  const expected: ExpectedChain = {
    chainId, firstSequence: 1, lastSequence: 1, rowCount: 1,
    previousHash: ZERO, lastHash,
  };
  // Control: matching previousHash verifies.
  assert.equal(checkChain(chain, expected).ok, true, "control: genesis chain with matching previousHash verifies");
  // Forge a nonzero previousHash while the expected genesis hash remains zero. The input
  // must satisfy both the expected binding and the genesis rule.
  const forgedChain: ChainInput = { ...chain, previousHash: sha256(strUtf8("forged")) };
  assert.equal(checkChain(forgedChain, expected).ok, false,
    "genesis chain.previousHash != expected.previousHash must reject (F4)");
});
// All 17 v1 operations must shape-check caller inputs before dereferencing or coercion.
// Bytes must be Uint8Array, structures must contain consumed fields and strings must
// be strings. Otherwise null dereferences throw TypeError or TextEncoder silently
// converts non-string inputs. Removing one closedShape guard at a time made that
// operation's malformed-input tests fail in the authoring mutation run.

import * as v1 from "../src/v1.js";
import {
  assembleCompact, decodeProof, requestDigest, verifyHistoricalAnchor, verifyKeyTransition,
} from "../src/v1.js";
import { thumbprintRaw, jwkFromPublicKey } from "../src/jwk.js";

function sweepFixtures() {
  const issuer = freshKey();
  const holder = freshKey();
  const holderFp = thumbprintRaw(jwkFromPublicKey(holder.publicKey));
  const holderThumb = new TextDecoder().decode(base64urlEncode(holderFp));
  const gsi = grantSigningInput({
    keyId: "issuer-123456", issuer: "https://issuer.example.test", grantId: "urn:example:grant:1",
    audiences: ["https://resource.example.test"], issuedAt: 1000, notBefore: 1000, expiresAt: 2000,
    holderThumbprint: holderThumb,
    operations: [{ name: "read", selectors: ["all"] }],
  });
  if (!gsi.ok) throw new Error("grant signing input failed");
  const gmsg = `${new TextDecoder().decode(gsi.value.protectedSegment)}.${new TextDecoder().decode(gsi.value.payloadSegment)}`;
  const gc = mustAssemble(gsi.value, new Uint8Array(nodeCrypto.sign(null, Buffer.from(gmsg), issuer.privateKey)));
  const psi = proofSigningInput({
    holderPublicKey: holder.publicKey, proofId: "urn:example:proof:1", method: "POST",
    targetUri: "https://resource.example.test/invoke", issuedAt: 1400,
    invocationId: "550e8400-e29b-41d4-a716-446655440000", operation: "read",
    grantCompact: gc, castArguments: { t: "null" } as Tagged,
  });
  if (!psi.ok) throw new Error("proof signing input failed");
  const pmsg = `${new TextDecoder().decode(psi.value.protectedSegment)}.${new TextDecoder().decode(psi.value.payloadSegment)}`;
  const pc = mustAssemble(psi.value, new Uint8Array(nodeCrypto.sign(null, Buffer.from(pmsg), holder.privateKey)));
  const baseReq = {
    trustedIssuer: { keyId: "issuer-123456", publicKey: issuer.publicKey },
    issuer: "https://issuer.example.test", audience: "https://resource.example.test",
    method: "POST", targetUri: "https://resource.example.test/invoke",
    invocationId: "550e8400-e29b-41d4-a716-446655440000", operation: "read",
    castArguments: { t: "null" } as Tagged, evaluationTime: 1500, clockSkew: 60,
    proofMaxAge: 300, nonce: { kind: "not_required" } as const,
  };
  const Z32 = new Uint8Array(32);
  const enc = encodeConsumptionEntry({ chainId: "urn:example:chain", sequence: 1, previousHash: Z32, commitment: new Uint8Array(32).fill(7) });
  if (!enc.ok) throw new Error("row encode failed");
  const goodChain = {
    rows: [enc.value.bytes], chainId: "urn:example:chain", firstSequence: 1, lastSequence: 1,
    rowCount: 1, previousHash: Z32, lastHash: enc.value.hash,
  };
  const expectedChain = { ...goodChain };
  const ka = freshKey();
  const kb = freshKey();
  const fpA = thumbprintRaw(jwkFromPublicKey(ka.publicKey));
  const fpB = thumbprintRaw(jwkFromPublicKey(kb.publicKey));
  const anchorProd = {
    anchorId: "a0", anchoredAt: 1000, chainId: "chain-x", sequence: 0,
    chainHash: Z32, keyId: "ka", publicKey: ka.publicKey,
  };
  const asi = boundaryAnchorSigningInput(anchorProd);
  if (!asi.ok) throw new Error("anchor signing input failed");
  const amsg = `${new TextDecoder().decode(asi.value.protectedSegment)}.${new TextDecoder().decode(asi.value.payloadSegment)}`;
  const startCompact = mustAssemble(asi.value, new Uint8Array(nodeCrypto.sign(null, Buffer.from(amsg), ka.privateKey)));
  const tProd = {
    transitionId: "t1", chainId: "chain-x", effectiveAt: 1500,
    currentKeyId: "ka", currentPublicKey: ka.publicKey, nextKeyId: "kb", nextPublicKey: kb.publicKey,
  };
  const tsi = keyTransitionSigningInput(tProd);
  if (!tsi.ok) throw new Error("transition signing input failed");
  const tmsg = `${new TextDecoder().decode(tsi.value.protectedSegment)}.${new TextDecoder().decode(tsi.value.payloadSegment)}`;
  const tCompact = mustAssemble(tsi.value, new Uint8Array(nodeCrypto.sign(null, Buffer.from(tmsg), ka.privateKey)));
  const built = buildArchive([ka, kb]);
  return { gc, pc, baseReq, goodChain, expectedChain, anchorProd, startCompact, tProd, tCompact, built, Z32, fpA, fpB, gsi: gsi.value, ka, kb };
}

// The sweep's dispatch table: façade name → positional-args invoker. Substitution happens
// positionally so each sentinel lands in exactly one parameter.
const SWEEP_TABLE: Record<string, (...a: unknown[]) => { ok: boolean }> = {
  untrustedKeyLocator: (...a) => untrustedKeyLocator(a[0] as never),
  decodeGrant: (...a) => v1.decodeGrant(a[0] as never),
  decodeProof: (...a) => decodeProof(a[0] as never),
  verifyGrant: (...a) => v1.verifyGrant(a[0] as never, a[1] as never, a[2] as never),
  checkEnvelope: (...a) => checkEnvelope(a[0] as never, a[1] as never, a[2] as never),
  requestDigest: (...a) => requestDigest(a[0] as never, a[1] as never),
  encodeConsumptionEntry: (...a) => encodeConsumptionEntry(a[0] as never),
  checkChain: (...a) => checkChain(a[0] as never, a[1] as never),
  grantSigningInput: (...a) => grantSigningInput(a[0] as never),
  proofSigningInput: (...a) => proofSigningInput(a[0] as never),
  assembleCompact: (...a) => assembleCompact(a[0] as never, a[1] as never),
  boundaryAnchorSigningInput: (...a) => boundaryAnchorSigningInput(a[0] as never),
  keyTransitionSigningInput: (...a) => keyTransitionSigningInput(a[0] as never),
  encodeAnchoredExport: (...a) => encodeAnchoredExport(a[0] as never, a[1] as never),
  verifyHistoricalAnchor: (...a) => verifyHistoricalAnchor(a[0] as never, a[1] as never, a[2] as never),
  verifyKeyTransition: (...a) => verifyKeyTransition(a[0] as never, a[1] as never, a[2] as never, a[3] as never),
  verifyAnchoredExport: (...a) => verifyAnchoredExport(a[0] as never, a[1] as never, a[2] as never),
};

test("closed-Result family param sweep (all 17 façades)", () => {
  const f = sweepFixtures();
  const nullTag: Tagged = { t: "null" };
  const expectedGrant = { issuer: "https://issuer.example.test", audience: "https://resource.example.test", evaluationTime: 1500, clockSkew: 60 };
  const histKeyA = { keyId: "ka", publicKey: f.ka.publicKey, validFrom: 0, validBefore: null };
  const histKeyB = { keyId: "kb", publicKey: f.kb.publicKey, validFrom: 1500, validBefore: null };
  const expAnchor = { anchorId: "a0", anchoredAt: 1000, chainId: "chain-x", sequence: 0, chainHash: f.Z32, keyId: "ka", keyFingerprint: f.fpA };
  const expTransition = { transitionId: "t1", chainId: "chain-x", effectiveAt: 1500, currentKeyId: "ka", currentKeyFingerprint: f.fpA, nextKeyId: "kb", nextKeyFingerprint: f.fpB };
  const archiveObj = { chunks: [f.built.archive], version: "v1" };
  // Valid positional args per façade, with per-position kinds for the expectation matrix.
  const okThumb = new TextDecoder().decode(base64urlEncode(f.fpA));
  const entries: Array<[string, unknown[], string[]]> = [
    ["untrustedKeyLocator", [f.gc], ["bytes"]],
    ["decodeGrant", [f.gc], ["bytes"]],
    ["decodeProof", [f.pc], ["bytes"]],
    ["verifyGrant", [f.gc, f.baseReq.trustedIssuer, expectedGrant], ["bytes", "struct", "struct"]],
    ["checkEnvelope", [f.gc, f.pc, f.baseReq], ["bytes", "bytes", "struct"]],
    ["requestDigest", ["read", nullTag], ["str", "tagged"]],
    ["encodeConsumptionEntry", [{ chainId: "chain-x", sequence: 1, previousHash: f.Z32, commitment: f.Z32 }], ["struct"]],
    ["checkChain", [f.goodChain, f.expectedChain], ["struct", "struct"]],
    ["grantSigningInput", [{ keyId: "k1", issuer: "https://issuer.example.test", grantId: "urn:example:grant:1", audiences: ["https://resource.example.test"], issuedAt: 1000, notBefore: 1000, expiresAt: 2000, holderThumbprint: okThumb, operations: [{ name: "read", selectors: ["all"] }] }], ["struct"]],
    ["proofSigningInput", [{ holderPublicKey: f.ka.publicKey, proofId: "urn:example:proof:1", method: "POST", targetUri: "https://resource.example.test/invoke", issuedAt: 1400, invocationId: "550e8400-e29b-41d4-a716-446655440000", operation: "read", grantCompact: f.gc, castArguments: nullTag }], ["struct"]],
    ["assembleCompact", [f.gsi, new Uint8Array(64).fill(5)], ["struct", "bytes"]],
    ["boundaryAnchorSigningInput", [f.anchorProd], ["struct"]],
    ["keyTransitionSigningInput", [f.tProd], ["struct"]],
    ["encodeAnchoredExport", [f.built.input, f.built.expected], ["struct", "struct"]],
    ["verifyHistoricalAnchor", [f.startCompact, histKeyA, expAnchor], ["bytes", "struct", "struct"]],
    ["verifyKeyTransition", [f.tCompact, histKeyA, histKeyB, expTransition], ["bytes", "struct", "struct", "struct"]],
    ["verifyAnchoredExport", [archiveObj, f.built.keyChain, f.built.expected], ["struct", "struct", "struct"]],
  ];
  // Controls: every valid call must be Ok (proves the fixtures, prevents vacuous sweeps).
  for (const [name, args] of entries) {
    const r = SWEEP_TABLE[name]!(...args);
    assert.equal(r.ok, true, `control failed: ${name}`);
  }
  const SENTINELS: Array<[unknown, string]> = [
    [null, "null"], [undefined, "undefined"], [123, "123"], [true, "true"],
    ["s", "s"], [[1, 2, 3], "array"], [{}, "object"],
  ];
  const failures: string[] = [];
  for (const [name, args, kinds] of entries) {
    for (let i = 0; i < kinds.length; i++) {
      const kind = kinds[i]!;
      for (const [sentinel, slabel] of SENTINELS) {
        const probe = args.slice();
        probe[i] = sentinel;
        let r: { ok: boolean } | "THROWN" = "THROWN";
        try {
          r = SWEEP_TABLE[name]!(...probe);
        } catch {
          r = "THROWN";
        }
        const mayOk = kind === "str" && slabel === "s";
        if (r === "THROWN") {
          failures.push(`${name}[${i}]=${slabel}: THREW past the closed Result`);
        } else if (!mayOk && r.ok) {
          failures.push(`${name}[${i}]=${slabel}: wrong-typed input returned Ok`);
        }
      }
    }
  }
  assert.deepEqual(failures, [], `closed-Result family escapes (${failures.length}): ${failures.slice(0, 12).join("; ")}`);
});

test("requestDigest non-string operation must fail closed (the coercion defect)", () => {
  const nullTag: Tagged = { t: "null" };
  for (const bad of [123, true, null, {}, [1], 3.5]) {
    const r = requestDigest(bad as never, nullTag);
    assert.equal(r.ok, false, `operation=${String(bad)} must not be silently coerced and digested`);
  }
});

test("null/undefined arguments must fail closed, not throw TypeError", () => {
  const f = sweepFixtures();
  const cases: Array<[string, () => unknown]> = [
    ["encodeConsumptionEntry(null)", () => encodeConsumptionEntry(null as never)],
    ["encodeConsumptionEntry(undefined)", () => encodeConsumptionEntry(undefined as never)],
    ["encodeConsumptionEntry(chainId=null)", () => encodeConsumptionEntry({ chainId: null, sequence: 1, previousHash: f.Z32, commitment: f.Z32 } as never)],
    ["encodeConsumptionEntry(previousHash=null)", () => encodeConsumptionEntry({ chainId: "c", sequence: 1, previousHash: null, commitment: f.Z32 } as never)],
    ["verifyGrant(expected=null)", () => v1.verifyGrant(f.gc, f.baseReq.trustedIssuer, null as never)],
    ["decodeGrant(null)", () => v1.decodeGrant(null as never)],
    ["checkEnvelope(expected=null)", () => checkEnvelope(f.gc, f.pc, null as never)],
    ["verifyAnchoredExport(archived=null)", () => verifyAnchoredExport(null as never, f.built.keyChain, f.built.expected)],
  ];
  for (const [label, call] of cases) {
    let r: unknown;
    try {
      r = call();
    } catch (e) {
      assert.fail(`${label}: threw ${(e as object).constructor.name} past the closed Result`);
    }
    assert.equal((r as { ok: boolean }).ok, false, `${label}: must be Err`);
  }
});

// Expected chain, anchor and transition structures must be validated before hashing.
// Later equality checks can produce the same rejection verdict, so this structural pin
// checks the actual validation statement against the digest call. It does not measure
// hash work or use an immutable ESM binding as a fake counter.

import { readFileSync } from "node:fs";

test("expected-struct well-formedness gates sit BEFORE the archive digest (structural order pin)", () => {
  const src = readFileSync(new URL("../src/v1.ts", import.meta.url), "utf8");
  const hoist = src.indexOf("const bpre = coerceBounds(expected.bounds ?? MAXIMUM_BOUNDS);");
  const digest = src.indexOf("const digest = sha256Concat(archived.chunks)");
  assert.ok(hoist > 0, "the pre-digest context validation statement must exist in v1.ts");
  assert.ok(digest > 0, "the archive digest call must exist in v1.ts");
  assert.ok(hoist < digest, "the expected-struct well-formedness gates must run BEFORE the archive digest (reference ordering)");
});

test("verifyAnchoredExport malformed-expected verdict matrix (hoist regression pins)", () => {
  const f = sweepFixtures();
  const built = buildArchive([freshKey(), freshKey()]);
  const z31 = new Uint8Array(31);
  const mutate = (fn: (e: typeof built.expected) => typeof built.expected) => fn(built.expected);
  const malformed: Array<[string, typeof built.expected]> = [
    ["anchor_id over identifier_bytes", mutate((e) => ({ ...e, startAnchor: { ...e.startAnchor, anchorId: "x".repeat(600) } }))],
    ["anchor key_id charset", mutate((e) => ({ ...e, startAnchor: { ...e.startAnchor, keyId: "bad key!" } }))],
    ["anchored_at over magnitude", mutate((e) => ({ ...e, startAnchor: { ...e.startAnchor, anchoredAt: 1e16 } }))],
    ["anchor sequence negative", mutate((e) => ({ ...e, startAnchor: { ...e.startAnchor, sequence: -1 } }))],
    ["key_fingerprint width", mutate((e) => ({ ...e, startAnchor: { ...e.startAnchor, keyFingerprint: z31 } }))],
    ["chain row_count zero", mutate((e) => ({ ...e, chain: { ...e.chain, rowCount: 0 } }))],
    ["transition_id over identifier_bytes", mutate((e) => ({ ...e, transitions: [{ ...e.transitions[0]!, transitionId: "x".repeat(600) }] }))],
    ["effective_at over magnitude", mutate((e) => ({ ...e, transitions: [{ ...e.transitions[0]!, effectiveAt: 1e16 }] }))],
  ];
  for (const [label, expected] of malformed) {
    const r = verifyAnchoredExport({ chunks: [built.archive], version: "v1" }, built.keyChain, expected);
    assert.equal(r.ok, false, `${label}: must reject`);
  }
  void f;
});

// assembleCompact must apply caller limits to encoded segments, the full compact and
// its kind-specific re-parse. These cases fail if the third argument is ignored or
// a helper replaces caller Bounds with the maximum.

test("assembleCompact threads caller bounds", () => {
  const f = sweepFixtures();
  const sig = new Uint8Array(64).fill(5);
  // Control: absent bounds = maximum → assembly succeeds.
  const control = assembleCompact(f.gsi, sig);
  assert.ok(control.ok, "control: maximum-bounds assembly must succeed");
  if (!control.ok) return;
  const n = control.value.length;
  assert.equal(
    assembleCompact(f.gsi, sig, boundsNew({ compact_bytes: n - 1 })).ok,
    false,
    "tightened compact_bytes must reject the assembly",
  );
  // signature_bytes is a fixed 64-byte width and cannot be tightened.
  assert.equal(
    assembleCompact(f.gsi, sig, boundsNew({ encoded_segment_bytes: f.gsi.protectedSegment.length - 1 })).ok,
    false,
    "tightened encoded_segment_bytes must reject the protected segment",
  );
  assert.equal(
    assembleCompact(f.gsi, sig, boundsNew({ kid_bytes: 1 })).ok,
    false,
    "tightened kid_bytes must reject at the kind re-parse (the produced kid is 13 bytes)",
  );
});

// These verdict cases reject malformed export contexts. The structural ordering pin
// complements them; verdict equality alone cannot establish hashing work.

test("round-12..14 pre-digest export gates: verdict matrix", () => {
  const built = buildArchive([freshKey(), freshKey()]);
  const z = new Uint8Array(32);
  const base = { chunks: [built.archive], version: "v1" };
  const extraKey = { keyId: "k-x", publicKey: freshKey().publicKey, validFrom: 0, validBefore: null };
  const badCharset = { ...built.keyChain.keys[0]!, keyId: "bad key!" };
  const huge = { ...built.keyChain.keys[1]!, validBefore: 1e16 };
  const longVersion = "x".repeat(600);
  const cases: Array<[string, () => { ok: boolean }]> = [
    ["control", () => verifyAnchoredExport(base, built.keyChain, built.expected)],
    ["version shape", () => verifyAnchoredExport({ chunks: [built.archive], version: longVersion }, built.keyChain, { ...built.expected, objectVersion: longVersion })],
    ["version equality", () => verifyAnchoredExport({ chunks: [built.archive], version: "v2" }, built.keyChain, built.expected)],
    ["key count", () => verifyAnchoredExport(base, { keys: [...built.keyChain.keys, extraKey] }, built.expected)],
    ["key charset", () => verifyAnchoredExport(base, { keys: [badCharset, built.keyChain.keys[1]!] }, built.expected)],
    ["key magnitude", () => verifyAnchoredExport(base, { keys: [built.keyChain.keys[0]!, huge] }, built.expected)],
  ];
  for (const [label, run] of cases) {
    const r = run();
    if (label === "control") assert.ok(r.ok, "control must verify");
    else assert.equal(r.ok, false, `${label}: must reject`);
  }
  void z;
});

// Nested expected-export shapes must include every field later read. An object-only
// check admits missing chain hashes and anchor fields, allowing TypeError to escape.
// These cases require closed rejection before dereferencing.

test("shape gate rejects malformed nested expected-export structs (no deref escapes)", () => {
  const built = buildArchive([freshKey(), freshKey()]);
  const z = new Uint8Array(32);
  const obj = { chunks: [built.archive], version: "v1" };
  const malformed: Array<[string, unknown]> = [
    ["chain missing previousHash", { ...built.expected, chain: { chainId: "c", firstSequence: 1, lastSequence: 1, rowCount: 1, lastHash: z } }],
    ["startAnchor empty object", { ...built.expected, startAnchor: {} }],
    ["endAnchor missing chainHash", { ...built.expected, endAnchor: { anchorId: "a", anchoredAt: 1600, chainId: "c", sequence: 1, keyId: "k", keyFingerprint: z } }],
    ["transition missing effectiveAt", { ...built.expected, transitions: [{ ...built.expected.transitions[0]!, effectiveAt: undefined }] }],
  ];
  for (const [label, expected] of malformed) {
    let r: unknown;
    try {
      r = verifyAnchoredExport(obj, built.keyChain, expected as never);
    } catch (e) {
      assert.fail(`${label}: threw ${(e as object).constructor.name} past the closed Result — the nested shape spec is too shallow`);
    }
    assert.equal((r as { ok: boolean }).ok, false, `${label}: must be Err`);
    // Encoding shares the nested-shape contract.
    let re: unknown;
    try {
      re = encodeAnchoredExport(built.input, expected as never);
    } catch (e) {
      assert.fail(`${label} (encode): threw ${(e as object).constructor.name} past the closed Result`);
    }
    assert.equal((re as { ok: boolean }).ok, false, `${label} (encode): must be Err`);
  }
});

// v2 adds inclusive, same-tag lte/gte comparisons while v1 keeps its three closed kinds.
// The authoring mutation battery changed inclusive comparisons to strict ones, admitted
// cross-tag operands, swapped decode dispatch and allowed v:1 at the v2 boundary. Each
// named test and the corresponding independent corpus cases failed. Real signatures
// also exercise selector boundary equality through the full envelope.

import * as v2 from "../src/v2.js";
import { parseSelector as parseSelectorV1, selectorMatches as selectorMatchesV1 } from "../src/selector.js";

// A tagged {amount: N} cast-arguments object (the int/float tag is the load-bearing dimension).
function amountArgs(n: number, float = false): Tagged {
  return { t: "object", v: new Map<string, Tagged>([["amount", float ? { t: "float", v: n } : { t: "int", v: n }]]) };
}

const decSel = (s: string) => jsonDecode(strUtf8(s));

// (a) INCLUSIVE: the boundary-equal pair must match. A `<`/`>` mutation flips exactly this.
test("permissiveness: v2 lte/gte are inclusive at the boundary (mutation a)", () => {
  const lte = v2.parseSelector(decSel('{"kind":"lte","path":["amount"],"value":5000}'));
  const gte = v2.parseSelector(decSel('{"kind":"gte","path":["amount"],"value":50}'));
  assert.equal(v2.selectorMatches(lte, amountArgs(5000)), true, "lte must match value == bound");
  assert.equal(v2.selectorMatches(gte, amountArgs(50)), true, "gte must match value == bound");
  assert.equal(v2.selectorMatches(lte, amountArgs(5001)), false, "lte must reject value > bound");
  assert.equal(v2.selectorMatches(gte, amountArgs(49)), false, "gte must reject value < bound");
  // The float-tagged domain is inclusive too (same-tag arms).
  const lteF = v2.parseSelector(decSel('{"kind":"lte","path":["amount"],"value":10.5}'));
  assert.equal(v2.selectorMatches(lteF, amountArgs(10.5, true)), true, "float lte must match at the bound");
});

// (b) SAME-TAG ONLY: a cross-tag pair never matches, fail closed; a non-numeric operand at the
// path never matches; a missing path fails closed exactly as equals/one_of. Removing the tag
// pairing flips exactly this.
test("permissiveness: v2 cross-tag range operands never match (mutation b)", () => {
  const lteFloat = v2.parseSelector(decSel('{"kind":"lte","path":["amount"],"value":10.5}'));
  const gteInt = v2.parseSelector(decSel('{"kind":"gte","path":["amount"],"value":50}'));
  assert.equal(v2.selectorMatches(lteFloat, amountArgs(5)), false, "int 5 never satisfies a float 10.5 bound");
  assert.equal(v2.selectorMatches(gteInt, amountArgs(50.0, true)), false, "float 50.0 never satisfies an int 50 bound");
  // Non-numeric operands: string/boolean/null/array/object at the path never match.
  const strArgs: Tagged = { t: "object", v: new Map<string, Tagged>([["amount", { t: "string", v: strUtf8("75") }]]) };
  assert.equal(v2.selectorMatches(gteInt, strArgs), false, "a string operand never satisfies a range bound");
  // Missing path: fail closed (REQ1-SELECTOR-path-required).
  const otherArgs: Tagged = { t: "object", v: new Map<string, Tagged>([["other", { t: "int", v: 75 }]]) };
  assert.equal(v2.selectorMatches(gteInt, otherArgs), false, "a missing path never matches");
});

// (c) DECODE DISPATCH: lte and gte are distinct kinds with distinct closed member shapes; a
// non-numeric bound is rejected at DECODE (the reference numeric_bound? gate); swapping the
// dispatch arms flips exactly this.
test("permissiveness: v2 range-kind decode dispatch is distinct (mutation c)", () => {
  const lte = v2.parseSelector(decSel('{"kind":"lte","path":["amount"],"value":5000}'));
  const gte = v2.parseSelector(decSel('{"kind":"gte","path":["amount"],"value":50}'));
  assert.equal(lte.kind, "lte");
  assert.equal(gte.kind, "gte");
  // A non-numeric bound rejects at decode, not at match time.
  assert.throws(() => v2.parseSelector(decSel('{"kind":"lte","path":["amount"],"value":"5000"}')), InvalidError,
    "a string bound must reject at decode");
  assert.throws(() => v2.parseSelector(decSel('{"kind":"gte","path":["amount"], "value": null}')), InvalidError,
    "a null bound must reject at decode");
  // The member-set discipline is unchanged: {kind, path, value} exactly.
  assert.throws(() => v2.parseSelector(decSel('{"kind":"lte","path":["amount"],"values":[5000]}')), InvalidError);
  // The producer rejects a non-numeric bound pre-signing.
  const badProducer = v2.grantSigningInput({
    keyId: "k1", issuer: "https://issuer.example.test", grantId: "urn:example:grant:1",
    audiences: ["https://resource.example.test"], issuedAt: 1000, notBefore: 1000, expiresAt: 2000,
    holderThumbprint: new TextDecoder().decode(base64urlEncode(new Uint8Array(32))),
    operations: [{ name: "transfer", selectors: [{ kind: "lte", path: ["amount"], value: { t: "string", v: strUtf8("5000") } }] }],
  });
  assert.equal(badProducer.ok, false, "the producer must reject a non-numeric bound");
});

// Both majors reject the other's bytes. v1 also keeps its selector kinds closed to
// all, equals and one_of independently of the payload-version gate.
test("permissiveness: v2 rejects v1 bytes cross-major; v1 stays closed to the range kinds (mutation d)", () => {
  const issuer = freshKey();
  const holder = freshKey();
  const holderFp = thumbprintOf(holder.publicKey);
  const baseGrant = {
    keyId: "k1", issuer: "https://issuer.example.test", grantId: "urn:example:grant:1",
    audiences: ["https://resource.example.test"], issuedAt: 1000, notBefore: 1000, expiresAt: 2000,
    holderThumbprint: new TextDecoder().decode(base64urlEncode(holderFp)),
  };
  // A v:1 grant with an all selector is legal v1 input and must reject on v2.
  const firstMajorSi = v1.grantSigningInput({ ...baseGrant, operations: [{ name: "read", selectors: ["all"] }] });
  if (!firstMajorSi.ok) throw new Error("v1 grant signing input failed");
  const firstMajorCompact = mustAssemble(firstMajorSi.value, new Uint8Array(nodeCrypto.sign(null,
    Buffer.from(`${new TextDecoder().decode(firstMajorSi.value.protectedSegment)}.${new TextDecoder().decode(firstMajorSi.value.payloadSegment)}`),
    issuer.privateKey)));
  assert.equal(v2.decodeGrant(firstMajorCompact).ok, false, "v2 must reject a v:1 grant payload");
  // A v:2 grant with lte violates both the v1 version gate and its selector closed set.
  const secondMajorSi = v2.grantSigningInput({ ...baseGrant, operations: [{ name: "read", selectors: [{ kind: "lte", path: ["amount"], value: { t: "int", v: 100 } }] }] });
  if (!secondMajorSi.ok) throw new Error("v2 grant signing input failed");
  const secondMajorCompact = mustAssemble(secondMajorSi.value, new Uint8Array(nodeCrypto.sign(null,
    Buffer.from(`${new TextDecoder().decode(secondMajorSi.value.protectedSegment)}.${new TextDecoder().decode(secondMajorSi.value.payloadSegment)}`),
    issuer.privateKey)));
  assert.equal(v1.decodeGrant(secondMajorCompact).ok, false, "v1 must reject a v:2 payload");
  // The v1 selector algebra stays closed: lte/gte reject at the v1 parseSelector gate.
  assert.throws(() => parseSelectorV1(decSel('{"kind":"lte","path":["amount"],"value":1}')), InvalidError,
    "v1 must keep rejecting the lte kind");
  assert.throws(() => parseSelectorV1(decSel('{"kind":"gte","path":["amount"],"value":1}')), InvalidError,
    "v1 must keep rejecting the gte kind");
  assert.equal(selectorMatchesV1(parseSelectorV1(decSel('{"kind":"equals","path":["amount"],"value":1}')), amountArgs(1)), true,
    "control: the v1 equals kind still matches");
  assert.equal(v2.decodeGrant(secondMajorCompact).ok, true, "control: the v2 façade accepts its own bytes");
});

// v2 uses BAP2 separators. Identical arguments must produce request and row hashes
// distinct from v1, and prefix bytes must match the exact BAP2 forms.
test("permissiveness: v2 domain separators are the BAP2 forms (not v1's BAP1 prefixes)", () => {
  const args: Tagged = { t: "object", v: new Map<string, Tagged>([["n", { t: "int", v: 1 }]]) };
  const d1 = v1.requestDigest("read", args);
  const d2 = v2.requestDigest("read", args);
  assert.equal(d1.ok && d2.ok, true);
  if (!d1.ok || !d2.ok) return;
  assert.notEqual(Buffer.from(d1.value).toString("hex"), Buffer.from(d2.value).toString("hex"),
    "the BAP1-REQUEST and BAP2-REQUEST separators must produce distinct digests");
  // BAP2-CHAIN\0 = 42 41 50 32 2d 43 48 41 49 4e 00 (the v1 form carries 0x31, not 0x32).
  assert.deepEqual(Array.from(v2.ROW_PREFIX), [0x42, 0x41, 0x50, 0x32, 0x2d, 0x43, 0x48, 0x41, 0x49, 0x4e, 0x00]);
  assert.deepEqual(Array.from(v2.REQUEST_PREFIX), [0x42, 0x41, 0x50, 0x32, 0x2d, 0x52, 0x45, 0x51, 0x55, 0x45, 0x53, 0x54, 0x00]);
  assert.deepEqual(Array.from(v2.ARCHIVE_PREFIX), Array.from(strUtf8("BAP2-ARCHIVE\0EXPORT\0")));
  // A consumption row hash differs across majors for identical entries (the row prefix feeds the hash).
  const entry = { chainId: "urn:example:chain", sequence: 1, previousHash: new Uint8Array(32), commitment: new Uint8Array(32).fill(7) };
  const r1 = v1.encodeConsumptionEntry(entry);
  const r2 = v2.encodeConsumptionEntry(entry);
  assert.equal(r1.ok && r2.ok, true);
  if (!r1.ok || !r2.ok) return;
  assert.notEqual(Buffer.from(r1.value.hash).toString("hex"), Buffer.from(r2.value.hash).toString("hex"),
    "the BAP1-CHAIN and BAP2-CHAIN row prefixes must produce distinct row hashes");
});

// The signed envelope verifies an amount exactly equal to the inclusive lte bound,
// complementing the direct selector comparison with real keys and signatures.
test("permissiveness: v2 envelope verifies at the inclusive boundary (mutation a, signed)", () => {
  _resetCensus();
  const issuer = freshKey();
  const holder = freshKey();
  const holderFp = thumbprintOf(holder.publicKey);
  const gsi = v2.grantSigningInput({
    keyId: "issuer-1", issuer: "https://issuer.example.test", grantId: "urn:example:grant:2",
    audiences: ["https://resource.example.test"], issuedAt: 1000, notBefore: 1000, expiresAt: 2000,
    holderThumbprint: new TextDecoder().decode(base64urlEncode(holderFp)),
    operations: [{ name: "transfer", selectors: [
      { kind: "gte", path: ["amount"], value: { t: "int", v: 50 } },
      { kind: "lte", path: ["amount"], value: { t: "int", v: 5000 } },
    ] }],
  });
  if (!gsi.ok) throw new Error("grant signing input failed");
  const gmsg = `${new TextDecoder().decode(gsi.value.protectedSegment)}.${new TextDecoder().decode(gsi.value.payloadSegment)}`;
  const grantCompact = mustAssemble(gsi.value, new Uint8Array(nodeCrypto.sign(null, Buffer.from(gmsg), issuer.privateKey)));
  const castArguments = amountArgs(5000); // boundary-equal: amount == the lte bound
  const psi = v2.proofSigningInput({
    holderPublicKey: holder.publicKey, proofId: "urn:example:proof:2", method: "POST",
    targetUri: "https://resource.example.test/invoke", issuedAt: 1400,
    invocationId: "550e8400-e29b-41d4-a716-446655440000", operation: "transfer",
    grantCompact, castArguments,
  });
  if (!psi.ok) throw new Error("proof signing input failed");
  const pmsg = `${new TextDecoder().decode(psi.value.protectedSegment)}.${new TextDecoder().decode(psi.value.payloadSegment)}`;
  const proofCompact = mustAssemble(psi.value, new Uint8Array(nodeCrypto.sign(null, Buffer.from(pmsg), holder.privateKey)));
  const expected = {
    trustedIssuer: { keyId: "issuer-1", publicKey: issuer.publicKey },
    issuer: "https://issuer.example.test", audience: "https://resource.example.test",
    method: "POST", targetUri: "https://resource.example.test/invoke",
    invocationId: "550e8400-e29b-41d4-a716-446655440000", operation: "transfer",
    castArguments, evaluationTime: 1500, clockSkew: 60, proofMaxAge: 300,
    nonce: { kind: "not_required" } as const,
  };
  const at = v2.checkEnvelope(grantCompact, proofCompact, expected);
  assert.equal(at.ok, true, "boundary-equal amount (5000 == lte bound) must verify — inclusive comparison");
  // One past the bound rejects (the gte/lte envelope closes at exactly the bound).
  const over = v2.checkEnvelope(grantCompact, proofCompact, { ...expected, castArguments: amountArgs(5001) });
  assert.equal(over.ok, false, "amount 5001 > the lte bound must reject (the proof's ba_req also mismatches)");
});

// Assembly re-parses each compact under its artifact kind. The authoring mutations
// removed grant decoding, canonical payload checks and anchor genesis binding. The
// malformed-member, whitespace and nonzero-genesis-hash tests respectively failed.
// Certified v2 headers keep the artifact kind valid while each payload is forged.
{
  const readCase = (file: string, id: string): { compact: string } => {
    const doc = JSON.parse(readFileSync(new URL(`../conformance/corpus-v2/cases/${file}`, import.meta.url), "utf8")) as { cases: Array<{ id: string; input: { compact: string } }> };
    const c = doc.cases.find((x) => x.id === id);
    if (!c) throw new Error(`case ${id} not found in ${file}`);
    return c.input;
  };
  type Si = Parameters<typeof v2.assembleCompact>[0];
  const grantCompact = readCase("grant-decode/decode.json", "grant-decode-v2-valid").compact;
  const anchorCompact = readCase("boundary-anchor/verify.json", "verify-historical-anchor-v2-valid").compact;
  const transitionCompact = readCase("key-transition/verify.json", "verify-key-transition-v2-valid").compact;
  const sig = new Uint8Array(64);
  const seg = (c: string) => c.split(".");
  // payloadSegment is base64url TEXT: the raw payload bytes are b64url-encoded first.
  const si = (kind: "grant" | "boundary_anchor" | "key_transition", c: string, payloadBytes: Uint8Array): Si => ({
    kind, protectedSegment: new TextEncoder().encode(seg(c)[0]!),
    payloadSegment: base64urlEncode(payloadBytes), // the b64url text bytes of the payload
  });
  const forged = (raw: string) => new TextEncoder().encode(raw);
  const decodeUtf8 = (b: Uint8Array) => new TextDecoder().decode(b);

  test("permissiveness: v2 assembly revalidation — member set (mutation e1)", () => {
    // {"aud":"a"} decodes as JSON but is no grant/anchor/transition payload.
    const bad = forged('{"aud":"a"}');
    for (const [kind, compact] of [["grant", grantCompact], ["boundary_anchor", anchorCompact], ["key_transition", transitionCompact]] as const) {
      const r = v2.assembleCompact(si(kind, compact, bad), sig);
      assert.equal(r.ok, false, `kind ${kind}: assembly must reject a well-formed input with invalid payload members`);
    }
  });

  test("permissiveness: v2 assembly revalidation — canonical payload (mutation e2)", () => {
    // Whitespace retains the members and genesis values but changes canonical bytes.
    const nonCanon = (c: string) => {
      const payloadJson = decodeUtf8(base64urlDecode(strUtf8(seg(c)[1]!)));
      return new TextEncoder().encode("{ " + payloadJson.slice(1));
    };
    for (const [kind, compact] of [["boundary_anchor", anchorCompact], ["key_transition", transitionCompact]] as const) {
      const r = v2.assembleCompact(si(kind, compact, nonCanon(compact)), sig);
      assert.equal(r.ok, false, `kind ${kind}: assembly must reject a non-canonical payload segment`);
    }
  });

  test("permissiveness: v2 assembly revalidation — anchor genesis binding (mutation e3)", () => {
    // A JCS-canonical, closed-member anchor payload with sequence 0 and a NON-zero chain hash
    // (the reference's BoundaryAnchorCodec.parse genesis binding).
    const payload = jsonDecode(base64urlDecode(strUtf8(seg(anchorCompact)[1]!)));
    if (payload.t !== "object") throw new Error("anchor payload must be an object");
    const members: Array<[string, Tagged]> = [];
    for (const [k, v] of payload.v) members.push([k, k === "chain_hash" ? { t: "string", v: new TextEncoder().encode("Q".repeat(42) + "A") } : v]);
    const genesis = jcsEncode({ t: "object", v: new Map(members) });
    const r = v2.assembleCompact(si("boundary_anchor", anchorCompact, genesis), sig);
    assert.equal(r.ok, false, "assembly must reject a sequence-0 anchor with a non-zero chain hash");
  });
}

// v3 applies the normative ES256 substitutions: v:3, BAP3 separators, raw 65-byte SEC1
// keys, closed {crv,kty,x,y} JWKs and low-S P1363 signatures. The authoring mutations
// isolated seven guards:
// a. Removing low-S rejection admits a valid high-S counterpart accepted by Node.
// b. Removing r/s range checks changes InvalidError into backend false. OpenSSL also
//    rejects these scalars, so final verdicts cannot isolate the required ordering.
// c. Admitting a fifth JWK member makes the closed-member test fail.
// d. Removing coordinate widths admits an on-curve x=256 short-coordinate fixture.
//    The corpus's off-curve short-coordinate case is subsumed by curve validation;
//    its padded spelling violates both base64url and width guards.
// e. Removing point arithmetic admits off-curve points and x=p, y=sqrt(b). The latter
//    satisfies the equation modulo p and isolates strict coordinate range checking.
// f. Widening v admits v:1/v:2 under an ES256 header. Ordinary v1/v2 compacts also
//    fail the algorithm guard and cannot isolate payload version.
// g. Disabling fingerprint registration breaks the EC verification-import census.
import * as v3 from "../src/v3.js";
import { validateEcPublicKey, es256Verify, importEcPublicKey } from "../src/es256.js";
import { publicKeyThumbprintRaw as ecPublicKeyThumbprintRaw } from "../src/ec_jwk.js";

// P-256 constants for the locally constructed falsifiers (mirror src/es256.ts).
const P256_N = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n;

// A fresh P-256 key pair: the raw public key is the 65-byte uncompressed SEC1 point.
function freshEcKey(): { publicKey: Uint8Array; privateKey: nodeCrypto.KeyObject } {
  const { publicKey, privateKey } = nodeCrypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
  const jwk = publicKey.export({ format: "jwk" }) as { x: string; y: string };
  const xb = base64urlDecode(strUtf8(jwk.x));
  const yb = base64urlDecode(strUtf8(jwk.y));
  const raw = new Uint8Array(65);
  raw[0] = 0x04;
  raw.set(xb, 1);
  raw.set(yb, 33);
  return { publicKey: raw, privateKey };
}

// Sign P1363 r||s and replace high s with n-s. Node can emit either equivalent form;
// the profile requires low-S.
function signP1363(message: Uint8Array, privateKey: nodeCrypto.KeyObject): Uint8Array {
  const sig = new Uint8Array(nodeCrypto.sign("sha256", Buffer.from(message), { key: privateKey, dsaEncoding: "ieee-p1363" }));
  const s = BigInt("0x" + Buffer.from(sig.subarray(32)).toString("hex"));
  if (s <= (P256_N - 1n) / 2n) return sig;
  const sLow = P256_N - s;
  const out = new Uint8Array(64);
  out.set(sig.subarray(0, 32), 0);
  const hex = sLow.toString(16).padStart(64, "0");
  for (let i = 0; i < 32; i++) out[32 + i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
}

// Full corpus-case reader for the v3 fixtures (the grant-verify signature-matrix inputs).
function readV3Case(file: string, id: string): Record<string, unknown> {
  const doc = JSON.parse(readFileSync(new URL(`../conformance/corpus-v3/cases/${file}`, import.meta.url), "utf8")) as { cases: Array<{ id: string; input: Record<string, unknown> }> };
  const c = doc.cases.find((x) => x.id === id);
  if (!c) throw new Error(`case ${id} not found in ${file}`);
  return c.input;
}

// (a)+(b) the signature canonicality matrix through the full verify_grant façade, on the corpus's
// own signed fixtures (real P-256 artifacts, doctored exactly one encoding dimension at a time).
{
  const valid = readV3Case("grant-verify/verify.json", "verify-grant-v3-valid");
  const tryVerify = (input: Record<string, unknown>): boolean =>
    v3.verifyGrant(
      strUtf8(input.compact as string),
      { keyId: input.key_id as string, publicKey: base64urlDecode(strUtf8(input.public_key as string)) },
      { issuer: input.issuer as string, audience: input.audience as string, evaluationTime: input.evaluation_time as number, clockSkew: input.clock_skew as number },
    ).ok;

  test("permissiveness: v3 positive control — the valid corpus grant verifies (mutation a/b control)", () => {
    assert.equal(tryVerify(valid), true, "the untouched fixture must verify");
  });

  test("permissiveness: v3 rejects the high-S malleable counterpart Node's backend accepts (mutation a)", () => {
    // Node accepts the mathematically equivalent (r, n-s) form. Only the low-S guard
    // prevents that alternate encoding from verifying.
    assert.equal(tryVerify(readV3Case("grant-verify/verify.json", "verify-grant-v3-invalid-signature-high-s")), false,
      "the high-S re-spelling of a valid signature must be invalid");
  });

  test("permissiveness: v3 rejects zero r / zero s / r = n / s = n as invalid encodings before the backend (mutation b)", () => {
    // OpenSSL rejects these scalar values even without the profile's range guard.
    for (const id of ["verify-grant-v3-invalid-signature-zero-r", "verify-grant-v3-invalid-signature-zero-s", "verify-grant-v3-invalid-signature-r-at-n", "verify-grant-v3-invalid-signature-s-at-n"]) {
      assert.equal(tryVerify(readV3Case("grant-verify/verify.json", id)), false, `${id} must be invalid`);
    }
    // The range guard must throw InvalidError before the backend returns false.
    const issuer = freshEcKey();
    const key = importEcPublicKey(issuer.publicKey, "census-red-proof-key");
    const message = strUtf8("ordering pin");
    const mk = (rHex: string, sHex: string): Uint8Array => {
      const out = new Uint8Array(64);
      const rb = Buffer.from(rHex, "hex"); const sb = Buffer.from(sHex, "hex");
      out.set(rb, 0); out.set(sb, 32);
      return out;
    };
    const N_HEX = "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551";
    const LOW_S = "7fffffff800000007fffffffffffffffde737d56d38bcf4279dce5617e3192a7"; // (n-1)/2
    for (const [label, sig] of [
      ["zero r", mk("00".repeat(32), LOW_S)],
      ["zero s", mk(LOW_S, "00".repeat(32))],
      ["r = n", mk(N_HEX, LOW_S)],
      ["s = n", mk(LOW_S, N_HEX)],
    ] as const) {
      assert.throws(() => es256Verify(message, sig, key), InvalidError, `${label} must reject as an invalid encoding at the gate`);
    }
  });

  test("permissiveness: v3 rejects tampered r and tampered s (encoding-level signature bytes)", () => {
    for (const id of ["verify-grant-v3-tamper-signature-r", "verify-grant-v3-tamper-signature-s"]) {
      assert.equal(tryVerify(readV3Case("grant-verify/verify.json", id)), false, `${id} must be invalid`);
    }
  });
}

// A fifth proof-JWK member is valid JSON but violates the closed member set.
test("permissiveness: v3 proof JWK rejects an extra member (mutation c)", () => {
  const compact = readV3Case("proof-decode/decode.json", "proof-decode-v3-valid").compact as string;
  const segs = compact.split(".");
  const headerText = new TextDecoder().decode(base64urlDecode(strUtf8(segs[0]!)));
  const doctored = headerText.replace('"kty":"EC"', '"d":"AAAA","kty":"EC"');
  const doctoredSeg = new TextDecoder().decode(base64urlEncode(strUtf8(doctored)));
  const r = v3.decodeProof(strUtf8(`${doctoredSeg}.${segs[1]}.${segs[2]}`));
  assert.equal(r.ok, false, "a 5-member EC JWK (carrying private d) must fail the closed member set");
});

// Use the on-curve point with x=256 and spell x with fewer than 32 bytes. Its SEC1
// point is valid, isolating the fixed-width coordinate guard.
test("permissiveness: v3 JWK coordinates must be canonical unpadded base64url of exactly 32 bytes (mutation d)", () => {
  const short = readV3Case("jwk/jwk.json", "jwk-decode-public-invalid-short-coordinate").text as string;
  assert.equal(v3.jwkDecodePublic(strUtf8(short)).ok, false, "a short coordinate must reject");
  const padded = readV3Case("jwk/jwk.json", "jwk-decode-public-invalid-padded-coordinate").text as string;
  assert.equal(v3.jwkDecodePublic(strUtf8(padded)).ok, false, "a padded (non-canonical) coordinate must reject");
  // The width-only falsifier: on-curve as assembled, wrong coordinate WIDTH.
  const shortOnCurve = '{"crv":"P-256","kty":"EC","x":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQ","y":"LNLfpMLrtOjTWd83WjDVrq6pSJbtVtGcM79voJy55MU"}';
  assert.equal(v3.jwkDecodePublic(strUtf8(shortOnCurve)).ok, false,
    "a 31-byte x spelling whose assembled point (256, y) is on the curve must reject on width alone");
});

// At x=p, y=sqrt(b), the curve equation holds modulo p. Only the strict x<p guard
// rejects this pair.
{
  const SQRT_B = 0x66485c780e2f83d72433bd5d84a06bb6541c2af31dae871728bf856a174f93f4n;
  const hexBytes = (v: bigint, n: number): Uint8Array => {
    const out = new Uint8Array(n);
    const hex = v.toString(16).padStart(n * 2, "0");
    for (let i = 0; i < n; i++) out[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
    return out;
  };
  const P = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffffn;
  const jwkText = (x: bigint, y: bigint): Uint8Array => strUtf8(
    `{"crv":"P-256","kty":"EC","x":"${new TextDecoder().decode(base64urlEncode(hexBytes(x, 32)))}","y":"${new TextDecoder().decode(base64urlEncode(hexBytes(y, 32)))}"}`,
  );

  test("permissiveness: v3 rejects a coordinate at the field prime even when the curve equation holds (mutation e)", () => {
    assert.equal(v3.jwkDecodePublic(jwkText(P, SQRT_B)).ok, false,
      "x=p, y=√b satisfies y²=x³−3x+b mod p — only the x<p gate rejects this pair");
  });

  test("permissiveness: v3 rejects an off-curve point with no crypto backend in the path (mutation e)", () => {
    const offCurve = readV3Case("jwk/jwk.json", "jwk-decode-public-invalid-off-curve").text as string;
    assert.equal(v3.jwkDecodePublic(strUtf8(offCurve)).ok, false, "an off-curve point must reject at decode");
    // The same arithmetic, applied directly to the doctored coordinates, must fail (pure validation).
    assert.throws(() => {
      const raw = new Uint8Array(65);
      raw[0] = 0x04;
      raw.set(base64urlDecode(strUtf8("fPJ7GI0DT36KUjgDBLUaw8CJaeJ38hs1pgtI_EdmmXk")), 1);
      raw.set(base64urlDecode(strUtf8("B3dVENuO0EApPZrGn3Qw27p9reY86YIpngS3nSJ4c9E")), 33);
      validateEcPublicKey(raw);
    }, InvalidError, "the doctored corpus coordinates must fail the pure point validation");
  });

  test("permissiveness: v3 rejects an off-curve proof JWK (mutation e, header path)", () => {
    // The modified point is off-curve; header parsing must reject before crypto.
    const compact = readV3Case("proof-decode/decode.json", "proof-decode-v3-valid").compact as string;
    const segs = compact.split(".");
    const headerText = new TextDecoder().decode(base64urlDecode(strUtf8(segs[0]!)));
    const m = /"x":"([^"]+)"/.exec(headerText);
    if (!m) throw new Error("proof header carries no x member");
    const doctoredX = m[1]!.slice(0, -1) + (m[1]!.endsWith("g") ? "k" : "g");
    const doctored = headerText.replace(m[0]!, `"x":"${doctoredX}"`);
    const doctoredSeg = new TextDecoder().decode(base64urlEncode(strUtf8(doctored)));
    const r = v3.decodeProof(strUtf8(`${doctoredSeg}.${segs[1]}.${segs[2]}`));
    assert.equal(r.ok, false, "an off-curve proof JWK must reject");
  });
}

// (f) cross-major: v3 rejects v1 and v2 bytes; v1 and v2 reject v3 bytes. Widening any v gate
// flips exactly its leg (and the corpus cross-major cases).
test("permissiveness: v3 rejects v1 and v2 bytes; v1 and v2 reject v3 bytes (mutation f)", () => {
  const readCompact = (url: string, id: string): string => {
    const doc = JSON.parse(readFileSync(new URL(url, import.meta.url), "utf8")) as { cases: Array<{ id: string; input: { compact: string } }> };
    const c = doc.cases.find((x) => x.id === id);
    if (!c) throw new Error(`case ${id} not found in ${url}`);
    return c.input.compact;
  };
  const v1Grant = readCompact("../conformance/corpus/cases/grant-decode/decode.json", "grant-decode-valid");
  const v2Grant = readCompact("../conformance/corpus-v2/cases/grant-decode/decode.json", "grant-decode-v2-valid");
  const v3Grant = readV3Case("grant-decode/decode.json", "grant-decode-v3-valid").compact as string;
  assert.equal(v3.decodeGrant(strUtf8(v1Grant)).ok, false, "v3 must reject a v:1 grant payload");
  assert.equal(v3.decodeGrant(strUtf8(v2Grant)).ok, false, "v3 must reject a v:2 grant payload");
  assert.equal(decodeGrant(strUtf8(v3Grant)).ok, false, "v1 must reject a v:3 payload");
  assert.equal(v2.decodeGrant(strUtf8(v3Grant)).ok, false, "v2 must reject a v:3 payload");
  assert.equal(v3.decodeGrant(strUtf8(v3Grant)).ok, true, "control: the v3 façade accepts its own bytes");
  // Keep the ES256 header and change only payload v, isolating the version gate.
  for (const other of [1, 2]) {
    const segs = v3Grant.split(".");
    const payloadText = new TextDecoder().decode(base64urlDecode(strUtf8(segs[1]!)));
    const swapped = payloadText.replace('"v":3', `"v":${other}`);
    if (swapped === payloadText) throw new Error("v3 grant payload carries no v:3 member");
    const swappedSeg = new TextDecoder().decode(base64urlEncode(strUtf8(swapped)));
    assert.equal(v3.decodeGrant(strUtf8(`${segs[0]}.${swappedSeg}.${segs[2]}`)).ok, false,
      `a v3-headered grant with payload v:${other} must reject at the v gate`);
  }
});

// The ES256 signed envelope must verify at the inclusive selector boundary.
test("permissiveness: v3 envelope verifies at the inclusive boundary over the ES256 suite", () => {
  const issuer = freshEcKey();
  const holder = freshEcKey();
  const holderFp = ecPublicKeyThumbprintRaw(holder.publicKey);
  const gsi = v3.grantSigningInput({
    keyId: "issuer-1", issuer: "https://issuer.example.test", grantId: "urn:example:grant:v3",
    audiences: ["https://resource.example.test"], issuedAt: 1000, notBefore: 1000, expiresAt: 2000,
    holderThumbprint: new TextDecoder().decode(base64urlEncode(holderFp)),
    operations: [{ name: "transfer", selectors: [
      { kind: "gte", path: ["amount"], value: { t: "int", v: 50 } },
      { kind: "lte", path: ["amount"], value: { t: "int", v: 5000 } },
    ] }],
  });
  if (!gsi.ok) throw new Error("v3 grant signing input failed");
  const gmsg = `${new TextDecoder().decode(gsi.value.protectedSegment)}.${new TextDecoder().decode(gsi.value.payloadSegment)}`;
  const grantCompact = mustAssembleEs256(gsi.value, signP1363(strUtf8(gmsg), issuer.privateKey));
  const castArguments: Tagged = { t: "object", v: new Map<string, Tagged>([["amount", { t: "int", v: 5000 }]]) };
  const psi = v3.proofSigningInput({
    holderPublicKey: holder.publicKey, proofId: "urn:example:proof:v3", method: "POST",
    targetUri: "https://resource.example.test/invoke", issuedAt: 1400,
    invocationId: "550e8400-e29b-41d4-a716-446655440000", operation: "transfer",
    grantCompact, castArguments,
  });
  if (!psi.ok) throw new Error("v3 proof signing input failed");
  const pmsg = `${new TextDecoder().decode(psi.value.protectedSegment)}.${new TextDecoder().decode(psi.value.payloadSegment)}`;
  const proofCompact = mustAssembleEs256(psi.value, signP1363(strUtf8(pmsg), holder.privateKey));
  const expected = {
    trustedIssuer: { keyId: "issuer-1", publicKey: issuer.publicKey },
    issuer: "https://issuer.example.test", audience: "https://resource.example.test",
    method: "POST", targetUri: "https://resource.example.test/invoke",
    invocationId: "550e8400-e29b-41d4-a716-446655440000", operation: "transfer",
    castArguments, evaluationTime: 1500, clockSkew: 60, proofMaxAge: 300,
    nonce: { kind: "not_required" } as const,
  };
  const at = v3.checkEnvelope(grantCompact, proofCompact, expected);
  assert.equal(at.ok, true, "boundary-equal amount (5000 == lte bound) must verify over ES256");
  if (at.ok) assert.equal(at.value.version, 3, "the envelope facts carry version 3");
  const over = v3.checkEnvelope(grantCompact, proofCompact, { ...expected, castArguments: { t: "object", v: new Map<string, Tagged>([["amount", { t: "int", v: 5001 }]]) } });
  assert.equal(over.ok, false, "amount 5001 > the lte bound must reject");
});

// The role-attestation mutation battery covers endpoint magnitude and integer tags,
// integer evaluation time, self-attestation by material and key ID, nbf/exp containment,
// the half-open now window, kid and subject bindings, closed roles, canonical payload
// bytes and signature verification. Removing each guard made its named test fail.
//
// The v:1 integer-tag gate is subsumed by canonical payload checking: JCS encodes 1.0
// as 1. This does not apply to fractional window endpoints such as 1000.5, whose JCS
// spelling is canonical and whose integer-tag guard has a discriminating signed fixture.
// Header canonicality is isolated by reordering members and signing those exact bytes.
// Mutation specificity is measured in this file; overlapping unit tests can also fail
// when shared guards are removed.
import * as roleAttestation from "../src/role_attestation.js";
import { decodeAttestation as raDecode, verifyAttestation as raVerify } from "../src/role_attestation.js";

const RA_MAX = 9007199254740991; // MAXIMA.integer_magnitude (2^53 - 1)

function raFixture() {
  const attestor = freshKey();
  const subject = freshKey();
  const si = roleAttestation.attestationSigningInput({
    keyId: "attestor-1", jti: "urn:example:attestation:ra",
    subjectKeyId: "subject-1", subjectPublicKey: subject.publicKey,
    role: "issuer", notBefore: 1000, expiresAt: 2000,
  });
  if (!si.ok) throw new Error("ra fixture signing input failed");
  const message = strUtf8(`${new TextDecoder().decode(si.value.protectedSegment)}.${new TextDecoder().decode(si.value.payloadSegment)}`);
  const sig = new Uint8Array(nodeCrypto.sign(null, Buffer.from(message), attestor.privateKey));
  const compact = roleAttestation.assembleAttestationCompact(si.value, sig);
  if (!compact.ok) throw new Error("ra fixture assembly failed");
  const expected = {
    attestor: { keyId: "attestor-1", publicKey: attestor.publicKey, validFrom: 500, validBefore: 2500 },
    subjectKeyId: "subject-1",
    subjectPublicKey: subject.publicKey,
    now: 1500,
  };
  return { attestor, subject, compact: compact.value, expected };
}

// RA-1 + RA-2: the caller-supplied attestor context and now are magnitude-bounded integers.
// The host defect: JS numbers are doubles; without an explicit gate a 2^62 valid_from or a
// fractional now enters the window arithmetic silently.
test("permissiveness: attestor window endpoints are integer, magnitude-bounded (2^53-1, both signs)", () => {
  const f = raFixture();
  assert.equal(raVerify(f.compact, { ...f.expected, attestor: { ...f.expected.attestor, validFrom: RA_MAX + 1 } }).ok, false);
  assert.equal(raVerify(f.compact, { ...f.expected, attestor: { ...f.expected.attestor, validFrom: -RA_MAX - 1 } }).ok, false);
  assert.equal(raVerify(f.compact, { ...f.expected, attestor: { ...f.expected.attestor, validFrom: 500.5 } }).ok, false);
  assert.equal(raVerify(f.compact, { ...f.expected, attestor: { ...f.expected.attestor, validBefore: RA_MAX + 1 } }).ok, false);
  assert.equal(raVerify(f.compact, { ...f.expected, attestor: { ...f.expected.attestor, validBefore: -RA_MAX - 1 } }).ok, false);
  assert.equal(raVerify(f.compact, { ...f.expected, attestor: { ...f.expected.attestor, validBefore: 2500.5 } }).ok, false);
});
test("permissiveness: attestation now must be an integer within magnitude (fractional now would verify)", () => {
  const f = raFixture();
  assert.equal(raVerify(f.compact, { ...f.expected, now: 1500.5 }).ok, false, "fractional now inside the window must fail closed");
  assert.equal(raVerify(f.compact, { ...f.expected, now: RA_MAX + 1 }).ok, false);
  assert.equal(raVerify(f.compact, { ...f.expected, now: 0.5 }).ok, false);
});

// Put the forbidden self-attestation material or key ID on the wire and supply a
// matching expected binding. Each guard must reject independently; changing only the
// expected context would exercise an unrelated binding check.
function raSigned(
  f: ReturnType<typeof raFixture>,
  producer: { subjectKeyId: string; subjectPublicKey: Uint8Array },
): Uint8Array {
  const si = roleAttestation.attestationSigningInput({
    keyId: "attestor-1", jti: "urn:example:attestation:ra",
    subjectKeyId: producer.subjectKeyId, subjectPublicKey: producer.subjectPublicKey,
    role: "issuer", notBefore: 1000, expiresAt: 2000,
  });
  if (!si.ok) throw new Error("ra producer failed");
  const message = strUtf8(`${new TextDecoder().decode(si.value.protectedSegment)}.${new TextDecoder().decode(si.value.payloadSegment)}`);
  const sig = new Uint8Array(nodeCrypto.sign(null, Buffer.from(message), f.attestor.privateKey));
  const compact = roleAttestation.assembleAttestationCompact(si.value, sig);
  if (!compact.ok) throw new Error("ra assembly failed");
  return compact.value;
}
test("permissiveness: self-attestation rejected on material alone and on key id alone", () => {
  const f = raFixture();
  // This expected-only mismatch rejects at subject binding. The wire-carried fixture
  // above isolates the self-attestation guard.
  assert.equal(
    raVerify(f.compact, { ...f.expected, subjectKeyId: "attestor-1", subjectPublicKey: f.attestor.publicKey }).ok,
    false,
    "expected-context mismatch (binding gate)",
  );
  // Material alone: the wire subject IS the attestor key; the expected binding matches it.
  const materialCompact = raSigned(f, { subjectKeyId: "subject-1", subjectPublicKey: f.attestor.publicKey });
  assert.equal(raDecode(materialCompact).ok, true, "self-material fixture decodes");
  assert.equal(
    raVerify(materialCompact, { ...f.expected, subjectPublicKey: f.attestor.publicKey }).ok,
    false,
    "attestor thumbprint == subject thumbprint (distinct key ids)",
  );
  // Key id alone: the wire subject key id IS the attestor key id; the expected binding matches.
  const keyIdCompact = raSigned(f, { subjectKeyId: "attestor-1", subjectPublicKey: f.subject.publicKey });
  assert.equal(raDecode(keyIdCompact).ok, true, "self-key-id fixture decodes");
  assert.equal(
    raVerify(keyIdCompact, { ...f.expected, subjectKeyId: "attestor-1" }).ok,
    false,
    "attestor key id == subject key id (distinct key material)",
  );
});

// RA-5 + RA-6 + RA-7: containment and the half-open now window.
test("permissiveness: attestation window must be contained in the attestor key window", () => {
  const f = raFixture();
  assert.equal(raVerify(f.compact, { ...f.expected, attestor: { ...f.expected.attestor, validFrom: 1001 } }).ok, false, "nbf < valid_from");
  assert.equal(raVerify(f.compact, { ...f.expected, attestor: { ...f.expected.attestor, validBefore: 1999 } }).ok, false, "exp > valid_before");
  // The boundary equalities accept (containment, not strict containment).
  assert.equal(raVerify(f.compact, { ...f.expected, attestor: { ...f.expected.attestor, validFrom: 1000 } }).ok, true);
  assert.equal(raVerify(f.compact, { ...f.expected, attestor: { ...f.expected.attestor, validBefore: 2000 } }).ok, true);
});
test("permissiveness: now window is half-open [nbf, exp) — now == exp rejects", () => {
  const f = raFixture();
  assert.equal(raVerify(f.compact, { ...f.expected, now: 1000 }).ok, true, "now == nbf accepts");
  assert.equal(raVerify(f.compact, { ...f.expected, now: 1999 }).ok, true);
  assert.equal(raVerify(f.compact, { ...f.expected, now: 2000 }).ok, false, "now == exp rejects");
  assert.equal(raVerify(f.compact, { ...f.expected, now: 999 }).ok, false, "now < nbf rejects");
});

// RA-8 + RA-9: the kid and subject-binding gates.
test("permissiveness: attestation kid binding and subject raw-byte binding are exact", () => {
  const f = raFixture();
  assert.equal(raVerify(f.compact, { ...f.expected, attestor: { ...f.expected.attestor, keyId: "attestor-2" } }).ok, false, "header kid must equal the attestor key id");
  const otherSubject = freshKey();
  assert.equal(raVerify(f.compact, { ...f.expected, subjectPublicKey: otherSubject.publicKey }).ok, false, "raw public_key byte-equality");
  assert.equal(raVerify(f.compact, { ...f.expected, subjectKeyId: "subject-2" }).ok, false, "subject key id equality");
});

// RA-10 + RA-11 + RA-13: the decode-level closures. Built from raw segment text so the wire
// bytes are exactly the falsifier (the producer cannot emit any of them).
function raWireCompact(payloadText: string, f: ReturnType<typeof raFixture>): Uint8Array {
  const segs = new TextDecoder().decode(f.compact).split(".");
  const payloadSegment = new TextDecoder().decode(base64urlEncode(strUtf8(payloadText)));
  return strUtf8(`${segs[0]}.${payloadSegment}.${segs[2]}`);
}
test("permissiveness: attestation role closed set, canonical payload bytes, and integer v tag", () => {
  const f = raFixture();
  const segs = new TextDecoder().decode(f.compact).split(".");
  const payloadText = new TextDecoder().decode(base64urlDecode(strUtf8(segs[1]!)));

  // RA-10: role outside the closed set.
  const auditor = payloadText.replace('"role":"issuer"', '"role":"auditor"');
  if (auditor === payloadText) throw new Error("fixture payload carries no role member");
  assert.equal(raDecode(raWireCompact(auditor, f)).ok, false, "role outside {issuer, holder}");

  // Move the existing v member to the front without duplicating it. Only canonical
  // ordering changes, so duplicate detection cannot mask this guard.
  const nonCanonical = payloadText
    .replace('{"exp":', '{"v":1,"exp":')
    .replace(',"v":1}', "}");
  assert.notEqual(nonCanonical, payloadText);
  assert.equal(nonCanonical.split('"v":').length - 1, 1, "the reorder must not duplicate v");
  assert.equal(raDecode(raWireCompact(nonCanonical, f)).ok, false, "payload must equal its JCS re-encoding");

  // A float spelling 1.0 for v is non-canonical because JCS re-encodes it as 1. The
  // canonical check subsumes the semantic tag guard at the wire boundary. This assertion
  // retains corpus behavior without claiming isolated mutation coverage for that tag.
  const floatV = payloadText.replace('"v":1}', '"v":1.0}');
  if (floatV === payloadText) throw new Error("fixture payload carries no v member");
  assert.equal(raDecode(raWireCompact(floatV, f)).ok, false, "float-encoded v must reject");
});

// Flip a middle signature byte while preserving base64url spelling and width.
// Final-character padding constraints do not apply at this position.
test("permissiveness: attestation signature gate rejects a tampered signature", () => {
  const f = raFixture();
  const chars = new TextDecoder().decode(f.compact).split("");
  const dot = chars.lastIndexOf(".");
  chars[dot + 20] = chars[dot + 20] === "A" ? "B" : "A";
  const tampered = strUtf8(chars.join(""));
  assert.equal(raDecode(tampered).ok, true, "canonical-width signature still decodes");
  assert.equal(raVerify(tampered, f.expected).ok, false, "the signature must verify under the attestor key");
});

// REQ-RA1-CLAIM-canonical covers both segments. Reorder protected members and sign
// those exact bytes, isolating header canonicality from signature verification.
test("permissiveness: attestation protected header must equal its JCS re-encoding", () => {
  const f = raFixture();
  const segs = new TextDecoder().decode(f.compact).split(".");
  const payloadSegment = segs[1]!;
  const headerText = new TextDecoder().decode(base64urlDecode(strUtf8(segs[0]!)));
  // JCS order is alg,kid,typ; rebuild as typ,kid,alg (a legal JSON re-order, illegal JCS).
  const reordered = '{"typ":"ba+role-attestation","kid":"attestor-1","alg":"EdDSA"}';
  assert.notEqual(reordered, headerText);
  const headerSegment = new TextDecoder().decode(base64urlEncode(strUtf8(reordered)));
  const message = strUtf8(`${headerSegment}.${payloadSegment}`);
  const sig = new Uint8Array(nodeCrypto.sign(null, Buffer.from(message), f.attestor.privateKey));
  const nonCanonicalHeader = strUtf8(`${headerSegment}.${payloadSegment}.${new TextDecoder().decode(base64urlEncode(sig))}`);
  assert.equal(raDecode(nonCanonicalHeader).ok, false, "the protected header must equal its JCS re-encoding");
  assert.equal(raVerify(nonCanonicalHeader, f.expected).ok, false, "and must never verify");
});

// REQ-RA1-CLAIM-closed-required forbids float tags for nbf and exp. A fractional
// endpoint such as 1000.5 is canonical JCS, so these signed cases isolate integer-tag
// validation from canonicality and window comparisons.
test("permissiveness: nbf and exp must carry integer tags (float endpoints are canonical, not caught by RA-14/RA-11)", () => {
  const f = raFixture();
  const segs = new TextDecoder().decode(f.compact).split(".");
  const payloadText = new TextDecoder().decode(base64urlDecode(strUtf8(segs[1]!)));
  const floatWindow = payloadText.replace('"nbf":1000,', '"nbf":1000.5,').replace('"exp":2000,', '"exp":2000.5,');
  if (floatWindow === payloadText) throw new Error("fixture payload carries no integer window to falsify");
  const payloadSegment = new TextDecoder().decode(base64urlEncode(strUtf8(floatWindow)));
  const message = strUtf8(`${segs[0]}.${payloadSegment}`);
  const sig = new Uint8Array(nodeCrypto.sign(null, Buffer.from(message), f.attestor.privateKey));
  const floatCompact = strUtf8(`${segs[0]}.${payloadSegment}.${new TextDecoder().decode(base64urlEncode(sig))}`);
  assert.equal(raDecode(floatCompact).ok, false, "float-encoded nbf/exp must reject at the integer-tag gate");
  assert.equal(raVerify(floatCompact, f.expected).ok, false, "and must never verify");
});
