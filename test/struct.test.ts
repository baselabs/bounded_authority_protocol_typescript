// T4 structural tests — digest (typed projection), selector identity, compact parse/assemble.
// Known-answer vectors from the corpus.
import { test } from "node:test";
import assert from "node:assert/strict";
import { strUtf8 } from "../src/json.js";
import { jsonDecode } from "../src/json.js";
import { requestDigestB64url, requestDigest } from "../src/digest.js";
import { parseSelector, selectorMatches, semanticIdentity } from "../src/selector.js";
import { parseCompact, assembleSegments, type SigningInput } from "../src/compact.js";
import { base64urlDecode, base64urlEncode } from "../src/base64url.js";
import { sha256, sha256Concat } from "../src/ed25519.js";
import { ok } from "../src/error.js";

const utf8 = (b: Uint8Array) => new TextDecoder().decode(b);

// request_digest known-answer (corpus: request-digest-valid).
test("request_digest known-answer: read {limit:10,record:{id:rec-1}}", () => {
  const castArgs = jsonDecode(strUtf8('{"limit":10,"record":{"id":"rec-1"}}'));
  const r = requestDigestB64url("read", castArgs);
  assert.equal(r.ok, true);
  if (!r.ok) return;
  assert.equal(r.value, "uv20PiC8tRQoOy9-eRlBFPQngtiDXkw_SCbbgzxjC2g");
});
test("request_digest exact-bound depth-15 nested array", () => {
  // 15-deep nested array of 0
  const castArgs = jsonDecode(strUtf8('[[[[[[[[[[[[[[[0]]]]]]]]]]]]]]]'));
  const r = requestDigestB64url("read", castArgs);
  assert.equal(r.ok, true);
  if (!r.ok) return;
  assert.equal(r.value, "h9bznN0cMUdoyW3mrhnPmbP3rKVBaVF5HK97Mt_tqPk");
});
test("request_digest exact-bound 128-char operation", () => {
  const castArgs = jsonDecode(strUtf8('{}'));
  const op = "a".repeat(128);
  const r = requestDigestB64url(op, castArgs);
  assert.equal(r.ok, true);
  if (!r.ok) return;
  assert.equal(r.value, "8FNOgHe05K3vT5ZF5gfZ4_v-1zmXrxLRebsusFJI0hc");
});

// Selector semantic identity: int vs float distinct.
test("semantic identity distinguishes int from float", () => {
  const intOne = jsonDecode(strUtf8("1"));
  const floatOne = jsonDecode(strUtf8("1.0"));
  // Both JCS-serialize to "1" as bytes, but the typed projection wraps them differently.
  const intId = semanticIdentity(intOne);
  const floatId = semanticIdentity(floatOne);
  // ["integer",1] vs ["float",1] → different canonical bytes.
  assert.notEqual(utf8(intId), utf8(floatId));
});

// Selector matching: equals requires path; all matches anything.
test("selector all matches any root", () => {
  const sel = parseSelector(jsonDecode(strUtf8('{"kind":"all"}')));
  assert.equal(selectorMatches(sel, jsonDecode(strUtf8('{"x":1}'))), true);
});
test("selector equals matches present path", () => {
  const sel = parseSelector(jsonDecode(strUtf8('{"kind":"equals","path":["id"],"value":"rec-1"}')));
  assert.equal(selectorMatches(sel, jsonDecode(strUtf8('{"id":"rec-1"}'))), true);
  assert.equal(selectorMatches(sel, jsonDecode(strUtf8('{"id":"rec-2"}'))), false);
  assert.equal(selectorMatches(sel, jsonDecode(strUtf8('{}'))), false); // path required
});
test("selector one_of matches any value", () => {
  const sel = parseSelector(jsonDecode(strUtf8('{"kind":"one_of","path":["k"],"values":["a","b"]}')));
  assert.equal(selectorMatches(sel, jsonDecode(strUtf8('{"k":"a"}'))), true);
  assert.equal(selectorMatches(sel, jsonDecode(strUtf8('{"k":"b"}'))), true);
  assert.equal(selectorMatches(sel, jsonDecode(strUtf8('{"k":"c"}'))), false);
});
test("selector rejects unknown kind", () => {
  assert.throws(() => parseSelector(jsonDecode(strUtf8('{"kind":"bogus"}'))));
});

// Compact parse: 3 segments. Build a valid-shape compact with our own encoder so the sig is correct.
test("parseCompact splits 3 segments", () => {
  const sigB64 = utf8(base64urlEncode(new Uint8Array(64)));
  const compact = strUtf8("eyJhbGciOiJFZERTQSIsImtpZCI6Imlzc3VlciIsInR5cCI6ImJhK2NhcCJ9.eyJ2IjoxfQ." + sigB64);
  const seg = parseCompact(compact);
  assert.equal(utf8(seg.protectedBytes), '{"alg":"EdDSA","kid":"issuer","typ":"ba+cap"}');
  assert.equal(utf8(seg.payloadBytes), '{"v":1}');
  assert.equal(seg.signature.length, 64);
  assert.equal(utf8(seg.signingInput), "eyJhbGciOiJFZERTQSIsImtpZCI6Imlzc3VlciIsInR5cCI6ImJhK2NhcCJ9.eyJ2IjoxfQ");
});
test("parseCompact rejects 2 segments", () => {
  assert.throws(() => parseCompact(strUtf8("aaa.bbb")));
});
test("parseCompact rejects 4 segments", () => {
  assert.throws(() => parseCompact(strUtf8("aaa.bbb.ccc.ddd")));
});

// assemble_segments round-trip (low-level assembler): encode 64 zero bytes with our own encoder for the expected suffix.
test("assembleSegments builds 3-segment compact", () => {
  const si: SigningInput = {
    kind: "grant",
    protectedSegment: strUtf8("eyJ2IjoxfQ"),
    payloadSegment: strUtf8("eyJ2IjoyfQ"),
  };
  const sig = new Uint8Array(64); // zeros
  const r = assembleSegments(si, sig);
  assert.equal(r.ok, true, "valid assemble must succeed");
  if (!r.ok) return;
  const expected = "eyJ2IjoxfQ.eyJ2IjoyfQ." + utf8(base64urlEncode(new Uint8Array(64)));
  assert.equal(utf8(r.value), expected);
  const seg = parseCompact(r.value);
  assert.equal(seg.signature.length, 64);
});
test("assembleSegments rejects bad kind", () => {
  const r = assembleSegments({ kind: "bogus" as never, protectedSegment: strUtf8("a"), payloadSegment: strUtf8("b") }, new Uint8Array(64));
  assert.equal(r.ok, false, "bad kind must return Err");
});
test("assembleSegments rejects short signature", () => {
  const r = assembleSegments({ kind: "grant", protectedSegment: strUtf8("a"), payloadSegment: strUtf8("b") }, new Uint8Array(32));
  assert.equal(r.ok, false, "short signature must return Err");
});

test("sha256Concat hashes a >65534-element list without V8's spread RangeError", () => {
  // archive_chunks (65796) exceeds V8's ~65534 call-argument ceiling. sha256Concat feeds the list as
  // an array (loop), never spread into call args, so this must NOT throw and must equal SHA-256 of
  // the joined bytes. Reverting sha256Concat to `sha256(...parts)` throws RangeError here (red).
  const n = 65535;
  const parts: Uint8Array[] = Array.from({ length: n }, () => new Uint8Array([0x61]));
  const joined = new Uint8Array(n).fill(0x61);
  const viaConcat = sha256Concat(parts);
  assert.equal(viaConcat.length, 32);
  assert.deepEqual(Array.from(viaConcat), Array.from(sha256(joined)));
});

void ok; void base64urlDecode; void requestDigest;
