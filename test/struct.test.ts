// T4 structural tests — digest (typed projection), selector identity, compact parse/assemble.
// Known-answer vectors from the corpus.
import { test } from "node:test";
import assert from "node:assert/strict";
import { strUtf8 } from "../src/json.js";
import { jsonDecode } from "../src/json.js";
import { requestDigestB64url, requestDigest } from "../src/digest.js";
import { parseSelector, selectorMatches, semanticIdentity } from "../src/selector.js";
import { parseCompact, assembleCompact, type SigningInput } from "../src/compact.js";
import { base64urlDecode, base64urlEncode } from "../src/base64url.js";
import { ok } from "../src/error.js";

const utf8 = (b: Uint8Array) => new TextDecoder().decode(b);

// request_digest known-answer (corpus: request-digest-valid).
test("request_digest known-answer: read {limit:10,record:{id:rec-1}}", () => {
  const castArgs = jsonDecode(strUtf8('{"limit":10,"record":{"id":"rec-1"}}'));
  const d = requestDigestB64url("read", castArgs);
  assert.equal(d, "uv20PiC8tRQoOy9-eRlBFPQngtiDXkw_SCbbgzxjC2g");
});
test("request_digest exact-bound depth-15 nested array", () => {
  // 15-deep nested array of 0
  const castArgs = jsonDecode(strUtf8('[[[[[[[[[[[[[[[0]]]]]]]]]]]]]]]'));
  const d = requestDigestB64url("read", castArgs);
  assert.equal(d, "h9bznN0cMUdoyW3mrhnPmbP3rKVBaVF5HK97Mt_tqPk");
});
test("request_digest exact-bound 128-char operation", () => {
  const castArgs = jsonDecode(strUtf8('{}'));
  const op = "a".repeat(128);
  const d = requestDigestB64url(op, castArgs);
  assert.equal(d, "8FNOgHe05K3vT5ZF5gfZ4_v-1zmXrxLRebsusFJI0hc");
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

// assemble_compact round-trip: encode 64 zero bytes with our own encoder for the expected suffix.
test("assembleCompact builds 3-segment compact", () => {
  const si: SigningInput = {
    kind: "grant",
    protectedSegment: strUtf8("eyJ2IjoxfQ"),
    payloadSegment: strUtf8("eyJ2IjoyfQ"),
  };
  const sig = new Uint8Array(64); // zeros
  const compact = assembleCompact(si, sig);
  const expected = "eyJ2IjoxfQ.eyJ2IjoyfQ." + utf8(base64urlEncode(new Uint8Array(64)));
  assert.equal(utf8(compact), expected);
  const seg = parseCompact(compact);
  assert.equal(seg.signature.length, 64);
});
test("assembleCompact rejects bad kind", () => {
  assert.throws(() =>
    assembleCompact({ kind: "bogus" as never, protectedSegment: strUtf8("a"), payloadSegment: strUtf8("b") }, new Uint8Array(64)),
  );
});
test("assembleCompact rejects short signature", () => {
  assert.throws(() =>
    assembleCompact({ kind: "grant", protectedSegment: strUtf8("a"), payloadSegment: strUtf8("b") }, new Uint8Array(32)),
  );
});

void ok; void base64urlDecode; void requestDigest;
