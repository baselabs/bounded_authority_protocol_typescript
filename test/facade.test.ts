// T4 façade tests — the 17-function v1 surface against corpus known-answer vectors. Each test
// drives a façade function on the published corpus fixtures (the same inputs the conformance
// runner will recompute every verdict from in T5). The corpus is the byte-level arbiter; these
// known-answer assertions are the red-before-green evidence for the 13 functions landed in this
// slice (grant/proof/anchor/transition signing-input producers, checkEnvelope, checkChain,
// encodeConsumptionEntry, verifyHistoricalAnchor, verifyKeyTransition, encodeAnchoredExport,
// verifyAnchoredExport, requestDigest façade, assemble_compact).
import { test } from "node:test";
import assert from "node:assert/strict";
import { strUtf8 } from "../src/json.js";
import { base64urlDecode, base64urlEncode } from "../src/base64url.js";
import { jwkFromPublicKey, thumbprintRaw } from "../src/jwk.js";
import type { HistoricalKeyChain } from "../src/v1.js";
import {
  untrustedKeyLocator, decodeGrant, decodeProof, verifyGrant, checkEnvelope,
  requestDigest, encodeConsumptionEntry, checkChain, grantSigningInput, proofSigningInput,
  assembleCompact, boundaryAnchorSigningInput, keyTransitionSigningInput, encodeAnchoredExport,
  verifyHistoricalAnchor, verifyKeyTransition, verifyAnchoredExport,
} from "../src/v1.js";
import * as crypto from "node:crypto";
import { sha256 } from "../src/ed25519.js";
import { _resetCensus, _importedFingerprints } from "../src/ed25519.js";
import { jsonDecode } from "../src/json.js";
import { boundsNew } from "../src/bounds.js";

const utf8 = (b: Uint8Array) => new TextDecoder().decode(b);
const b64d = (s: string) => base64urlDecode(strUtf8(s));
const b64e = (b: Uint8Array) => utf8(base64urlEncode(b));

// ---- corpus fixtures (exact bytes from priv/conformance/v1/corpus/) ----

const GRANT_COMPACT =
  "eyJhbGciOiJFZERTQSIsImtpZCI6Imlzc3VlciIsInR5cCI6ImJhK2NhcCJ9." +
  "eyJhdWQiOlsiaHR0cHM6Ly9yZXNvdXJjZS5leGFtcGxlLnRlc3QiXSwiY25mIjp7ImprdCI6ImQ0dWNFWnd2SlRmd3hYQ040ZjJ4bUlFNVpCRm9INWk1bWx6ZVdaYUIzeUkifSwiZXhwIjoyMDAwLCJpYXQiOjEwMDAsImlzcyI6Imh0dHBzOi8vaXNzdWVyLmV4YW1wbGUudGVzdCIsImp0aSI6InVybjpleGFtcGxlOmdyYW50OjEiLCJuYmYiOjEwMDAsIm9wZXJhdGlvbnMiOlt7Im5hbWUiOiJyZWFkIiwic2VsZWN0b3JzIjpbeyJraW5kIjoiYWxsIn1dfV0sInYiOjF9." +
  "NaCpUf3ebKldiRpjHtKcJuvCjSVLSsmgZVWXa3Sz6Zvas3TeTEm3LqVDsUL8yc1VuakYOvFmsYxqQw8PV23uDA";

const PROOF_COMPACT =
  "eyJhbGciOiJFZERTQSIsImp3ayI6eyJjcnYiOiJFZDI1NTE5Iiwia3R5IjoiT0tQIiwieCI6Ilcxczd5RTlmR0RNQmJtZHBxWVZ3UTFoRENYdHpPZVBVRDNmSWYxdDdGRGsifSwidHlwIjoiZHBvcCtqd3QifQ." +
  "eyJhdGgiOiJzVjhkZ1ZLcFExTHZpa1lrNmVvOEd2RGZhYkpyMWd0VlhrdkRnazdxLVpZIiwiYmFfaW52IjoiNTUwZTg0MDAtZTI5Yi00MWQ0LWE3MTYtNDQ2NjU1NDQwMDAwIiwiYmFfb3AiOiJyZWFkIiwiYmFfcmVxIjoidXYyMFBpQzh0UlFvT3k5LWVSbEJGUFFuZ3RpRFhrd19TQ2JiZ3p4akMyZyIsImh0bSI6IlBPU1QiLCJodHUiOiJodHRwczovL3Jlc291cmNlLmV4YW1wbGUudGVzdC9pbnZva2UiLCJpYXQiOjExMDAsImp0aSI6InVybjpleGFtcGxlOnByb29mOjEiLCJ2IjoxfQ." +
  "BUONibEL8cesx2D905h2CwHhL8sdtZ33sABKd7jRl27UdBOo0jpQX9UGl8VLlpEVxSFiZlhBGwNg85VBakhwAw";

const ISSUER_PUB = "146FPz0L9OK-SZ4z9nC1Xk7rUCSYAoIiBBDp1tsLZI8";
const ISSUER_FP = "eGPJdenILo5TLcdbdZa046_Z-t9wGJl11N6_QJQrob8";
const HOLDER_PUB = "W1s7yE9fGDMBbmdpqYVwQ1hDCXtzOePUD3fIf1t7FDk";
const HOLDER_FP = "d4ucEZwvJTfwxXCN4f2xmIE5ZBFoH5i5mlzeWZaB3yI";

// grant_signing_input expected message (corpus: grant-signing-input-valid).
const GRANT_SI_MESSAGE =
  "eyJhbGciOiJFZERTQSIsImtpZCI6Imlzc3VlciIsInR5cCI6ImJhK2NhcCJ9." +
  "eyJhdWQiOlsiaHR0cHM6Ly9yZXNvdXJjZS5leGFtcGxlLnRlc3QiXSwiY25mIjp7ImprdCI6ImQ0dWNFWnd2SlRmd3hYQ040ZjJ4bUlFNVpCRm9INWk1bWx6ZVdaYUIzeUkifSwiZXhwIjoyMDAwLCJpYXQiOjEwMDAsImlzcyI6Imh0dHBzOi8vaXNzdWVyLmV4YW1wbGUudGVzdCIsImp0aSI6InVybjpleGFtcGxlOmdyYW50OjEiLCJuYmYiOjEwMDAsIm9wZXJhdGlvbnMiOlt7Im5hbWUiOiJyZWFkIiwic2VsZWN0b3JzIjpbeyJraW5kIjoiYWxsIn1dfV0sInYiOjF9";

// proof_signing_input expected message (corpus: proof-signing-input-valid).
const PROOF_SI_MESSAGE =
  "eyJhbGciOiJFZERTQSIsImp3ayI6eyJjcnYiOiJFZDI1NTE5Iiwia3R5IjoiT0tQIiwieCI6Ilcxczd5RTlmR0RNQmJtZHBxWVZ3UTFoRENYdHpPZVBVRDNmSWYxdDdGRGsifSwidHlwIjoiZHBvcCtqd3QifQ." +
  "eyJhdGgiOiJzVjhkZ1ZLcFExTHZpa1lrNmVvOEd2RGZhYkpyMWd0VlhrdkRnazdxLVpZIiwiYmFfaW52IjoiNTUwZTg0MDAtZTI5Yi00MWQ0LWE3MTYtNDQ2NjU1NDQwMDAwIiwiYmFfb3AiOiJyZWFkIiwiYmFfcmVxIjoidXYyMFBpQzh0UlFvT3k5LWVSbEJGUFFuZ3RpRFhrd19TQ2JiZ3p4akMyZyIsImh0bSI6IlBPU1QiLCJodHUiOiJodHRwczovL3Jlc291cmNlLmV4YW1wbGUudGVzdC9pbnZva2UiLCJpYXQiOjExMDAsImp0aSI6InVybjpleGFtcGxlOnByb29mOjEiLCJ2IjoxfQ";

// === 1. untrusted_key_locator ===
test("untrustedKeyLocator returns the grant kid", () => {
  const r = untrustedKeyLocator(strUtf8(GRANT_COMPACT));
  assert.equal(r.ok, true);
  if (r.ok) {
    assert.equal(r.value.keyId, "issuer");
    assert.equal(r.value.trust, "not_evaluated");
  }
});
test("untrustedKeyLocator rejects a 2-segment compact", () => {
  const r = untrustedKeyLocator(strUtf8("aaa.bbb"));
  assert.equal(r.ok, false);
});

// === 2. decode_grant ===
test("decodeGrant extracts the grant fields", () => {
  const r = decodeGrant(strUtf8(GRANT_COMPACT));
  assert.equal(r.ok, true);
  if (r.ok) {
    assert.equal(r.value.keyId, "issuer");
    assert.equal(r.value.issuer, "https://issuer.example.test");
    assert.equal(r.value.grantId, "urn:example:grant:1");
    assert.deepEqual(r.value.audiences, ["https://resource.example.test"]);
    assert.equal(r.value.issuedAt, 1000);
    assert.equal(r.value.notBefore, 1000);
    assert.equal(r.value.expiresAt, 2000);
    assert.equal(b64e(r.value.holderThumbprint), HOLDER_FP);
    assert.equal(r.value.verification, "not_evaluated");
  }
});

// === 3. decode_proof ===
test("decodeProof extracts the proof id + holder thumbprint", () => {
  const r = decodeProof(strUtf8(PROOF_COMPACT));
  assert.equal(r.ok, true);
  if (r.ok) {
    assert.equal(r.value.proofId, "urn:example:proof:1");
    assert.equal(b64e(r.value.holderThumbprint), HOLDER_FP);
    assert.equal(r.value.verification, "not_evaluated");
  }
});

// === 4. verify_grant (valid signature) ===
test("verifyGrant accepts a validly-signed grant", () => {
  _resetCensus();
  const r = verifyGrant(
    strUtf8(GRANT_COMPACT),
    { keyId: "issuer", publicKey: b64d(ISSUER_PUB) },
    { issuer: "https://issuer.example.test", audience: "https://resource.example.test", evaluationTime: 1500, clockSkew: 60 },
  );
  assert.equal(r.ok, true);
  if (r.ok) {
    assert.equal(r.value.version, 1);
    assert.equal(r.value.issuer, "https://issuer.example.test");
    assert.equal(r.value.grantId, "urn:example:grant:1");
    assert.equal(b64e(r.value.issuerKeyFingerprint), ISSUER_FP);
    assert.equal(r.value.matchedAudience, "https://resource.example.test");
    assert.equal(r.value.authorization, "not_evaluated");
  }
});
test("verifyGrant rejects a wrong issuer key", () => {
  _resetCensus();
  const r = verifyGrant(
    strUtf8(GRANT_COMPACT),
    { keyId: "issuer", publicKey: b64d(HOLDER_PUB) }, // wrong key
    { issuer: "https://issuer.example.test", audience: "https://resource.example.test", evaluationTime: 1500, clockSkew: 60 },
  );
  assert.equal(r.ok, false);
});

// === 5. check_envelope ===
test("checkEnvelope accepts a valid grant+proof pair", () => {
  _resetCensus();
  const r = checkEnvelope(strUtf8(GRANT_COMPACT), strUtf8(PROOF_COMPACT), {
    trustedIssuer: { keyId: "issuer", publicKey: b64d(ISSUER_PUB) },
    issuer: "https://issuer.example.test",
    audience: "https://resource.example.test",
    method: "POST",
    targetUri: "https://resource.example.test/invoke",
    invocationId: "550e8400-e29b-41d4-a716-446655440000",
    operation: "read",
    castArguments: jsonDecode(strUtf8('{"limit":10,"record":{"id":"rec-1"}}')),
    evaluationTime: 1200,
    clockSkew: 60,
    proofMaxAge: 300,
    nonce: { kind: "not_required" },
  });
  assert.equal(r.ok, true);
  if (r.ok) {
    assert.equal(r.value.operation, "read");
    assert.equal(r.value.uri, "https://resource.example.test/invoke");
    assert.equal(r.value.invocationId, "550e8400-e29b-41d4-a716-446655440000");
    assert.equal(r.value.authorization, "not_evaluated");
  }
});
test("checkEnvelope rejects a wrong request method", () => {
  _resetCensus();
  const r = checkEnvelope(strUtf8(GRANT_COMPACT), strUtf8(PROOF_COMPACT), {
    trustedIssuer: { keyId: "issuer", publicKey: b64d(ISSUER_PUB) },
    issuer: "https://issuer.example.test",
    audience: "https://resource.example.test",
    method: "GET", // proof is POST
    targetUri: "https://resource.example.test/invoke",
    invocationId: "550e8400-e29b-41d4-a716-446655440000",
    operation: "read",
    castArguments: jsonDecode(strUtf8('{"limit":10,"record":{"id":"rec-1"}}')),
    evaluationTime: 1200,
    clockSkew: 60,
    proofMaxAge: 300,
    nonce: { kind: "not_required" },
  });
  assert.equal(r.ok, false);
});

// === 6. request_digest (façade returns Ok<raw 32 bytes> | Err) ===
test("requestDigest returns the raw 32-byte digest", () => {
  const r = requestDigest("read", jsonDecode(strUtf8('{"limit":10,"record":{"id":"rec-1"}}')));
  assert.equal(r.ok, true);
  if (!r.ok) return;
  assert.equal(r.value.length, 32);
  assert.equal(b64e(r.value), "uv20PiC8tRQoOy9-eRlBFPQngtiDXkw_SCbbgzxjC2g");
});

// === 7. encode_consumption_entry ===
test("encodeConsumptionEntry produces canonical bytes + chain hash", () => {
  const r = encodeConsumptionEntry({
    chainId: "urn:example:chain",
    sequence: 1,
    previousHash: b64d("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
    commitment: b64d("lQXKy3xxDtFxJfzGyzZp6N3KbIzYr2ox9rPNZGBMMJg"),
  });
  assert.equal(r.ok, true);
  if (r.ok) {
    assert.equal(
      utf8(r.value.bytes),
      '{"chain_id":"urn:example:chain","commitment":"lQXKy3xxDtFxJfzGyzZp6N3KbIzYr2ox9rPNZGBMMJg","previous":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","sequence":1,"v":1}',
    );
    assert.equal(b64e(r.value.hash), "dcCClEuq-ywQNcN1sTC0ERFIoNsrBJBWoeAojFALwHM");
  }
});
test("encodeConsumptionEntry rejects a zero sequence", () => {
  const r = encodeConsumptionEntry({
    chainId: "urn:example:chain",
    sequence: 0,
    previousHash: b64d("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
    commitment: b64d("lQXKy3xxDtFxJfzGyzZp6N3KbIzYr2ox9rPNZGBMMJg"),
  });
  assert.equal(r.ok, false);
});

// === 8. check_chain (valid + tampered) ===
const ROW1 = "eyJjaGFpbl9pZCI6InVybjpleGFtcGxlOmNoYWluIiwiY29tbWl0bWVudCI6IjBQWXh5aDNicU5zN3o4dWVCWHpjbU5BM254dnVBT2RhVkZGSG9uMnQyWUkiLCJwcmV2aW91cyI6IkFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUEiLCJzZXF1ZW5jZSI6MSwidiI6MX0";
const ROW2 = "eyJjaGFpbl9pZCI6InVybjpleGFtcGxlOmNoYWluIiwiY29tbWl0bWVudCI6Im5BcS1VY2JtWlYyQjNpMEVUVS14bEpNZkJZd0VKc1o4Y29YWTlXVi0xa28iLCJwcmV2aW91cyI6IkZydmpWdFdhdlJMUkFoSkVUbVBWYWJPLUdrRm9JRUNZdVpUYXEzRDJyenciLCJzZXF1ZW5jZSI6MiwidiI6MX0";
test("checkChain accepts a valid 2-row chain", () => {
  const r = checkChain(
    {
      rows: [b64d(ROW1), b64d(ROW2)],
      chainId: "urn:example:chain", firstSequence: 1, lastSequence: 2, rowCount: 2,
      previousHash: b64d("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
      lastHash: b64d("nlI60Ae0aih559j_4EinXcdPFzOuXcwTs8BYcCP95bs"),
    },
    {
      chainId: "urn:example:chain", firstSequence: 1, lastSequence: 2, rowCount: 2,
      previousHash: b64d("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
      lastHash: b64d("nlI60Ae0aih559j_4EinXcdPFzOuXcwTs8BYcCP95bs"),
    },
  );
  assert.equal(r.ok, true);
  if (r.ok) {
    assert.equal(r.value.chainId, "urn:example:chain");
    assert.equal(r.value.rowCount, 2);
    assert.equal(r.value.trust, "not_evaluated");
  }
});
test("checkChain rejects a tampered last hash", () => {
  const r = checkChain(
    {
      rows: [b64d(ROW1), b64d(ROW2)],
      chainId: "urn:example:chain", firstSequence: 1, lastSequence: 2, rowCount: 2,
      previousHash: b64d("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
      lastHash: b64d("AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE"), // wrong
    },
    {
      chainId: "urn:example:chain", firstSequence: 1, lastSequence: 2, rowCount: 2,
      previousHash: b64d("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
      lastHash: b64d("AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE"),
    },
  );
  assert.equal(r.ok, false);
});

// === 9. grant_signing_input (producer known-answer) ===
test("grantSigningInput produces the canonical message", () => {
  const r = grantSigningInput({
    keyId: "issuer", issuer: "https://issuer.example.test", grantId: "urn:example:grant:1",
    audiences: ["https://resource.example.test"], issuedAt: 1000, notBefore: 1000, expiresAt: 2000,
    holderThumbprint: HOLDER_FP,
    operations: [{ name: "read", selectors: ["all"] }],
  });
  assert.equal(r.ok, true);
  if (r.ok) {
    const message = `${utf8(r.value.protectedSegment)}.${utf8(r.value.payloadSegment)}`;
    assert.equal(message, GRANT_SI_MESSAGE);
  }
});
test("grantSigningInput rejects an empty audience", () => {
  const r = grantSigningInput({
    keyId: "issuer", issuer: "https://issuer.example.test", grantId: "urn:example:grant:1",
    audiences: [], issuedAt: 1000, notBefore: 1000, expiresAt: 2000,
    holderThumbprint: HOLDER_FP,
    operations: [{ name: "read", selectors: ["all"] }],
  });
  assert.equal(r.ok, false);
});

// === 10. proof_signing_input (producer known-answer) ===
test("proofSigningInput produces the canonical message", () => {
  const r = proofSigningInput({
    holderPublicKey: b64d(HOLDER_PUB),
    proofId: "urn:example:proof:1", method: "POST", targetUri: "https://resource.example.test/invoke",
    issuedAt: 1100, invocationId: "550e8400-e29b-41d4-a716-446655440000", operation: "read",
    grantCompact: strUtf8(GRANT_COMPACT),
    castArguments: jsonDecode(strUtf8('{"limit":10,"record":{"id":"rec-1"}}')),
  });
  assert.equal(r.ok, true);
  if (r.ok) {
    const message = `${utf8(r.value.protectedSegment)}.${utf8(r.value.payloadSegment)}`;
    assert.equal(message, PROOF_SI_MESSAGE);
  }
});
test("proofSigningInput rejects a non-https target uri", () => {
  const r = proofSigningInput({
    holderPublicKey: b64d(HOLDER_PUB),
    proofId: "urn:example:proof:1", method: "POST", targetUri: "http://insecure.test/",
    issuedAt: 1100, invocationId: "550e8400-e29b-41d4-a716-446655440000", operation: "read",
    grantCompact: strUtf8(GRANT_COMPACT),
    castArguments: jsonDecode(strUtf8('{"limit":10,"record":{"id":"rec-1"}}')),
  });
  assert.equal(r.ok, false);
});

// === 11. assemble_compact (round-trip the grant signing input) ===
test("assembleCompact builds a 3-segment compact from a signing input", () => {
  const si = grantSigningInput({
    keyId: "issuer", issuer: "https://issuer.example.test", grantId: "urn:example:grant:1",
    audiences: ["https://resource.example.test"], issuedAt: 1000, notBefore: 1000, expiresAt: 2000,
    holderThumbprint: HOLDER_FP,
    operations: [{ name: "read", selectors: ["all"] }],
  });
  assert.equal(si.ok, true);
  if (!si.ok) return;
  const sig = b64d("NaCpUf3ebKldiRpjHtKcJuvCjSVLSsmgZVWXa3Sz6Zvas3TeTEm3LqVDsUL8yc1VuakYOvFmsYxqQw8PV23uDA");
  const r = assembleCompact(si.value, sig);
  assert.equal(r.ok, true);
  if (!r.ok) return;
  assert.equal(utf8(r.value), GRANT_COMPACT);
});

// === 12. boundary_anchor_signing_input (producer known-answer) ===
const ANCHOR_PUB = "lz36DS8epQY1S82KipNyGEI4hRU21dlr3N30L8QXAHY";
const ANCHOR_FP = "7VjCxMImm16N6RYUjklULyDjbw2aGEOgNNtKBP9r-i0";
test("boundaryAnchorSigningInput produces the canonical message", () => {
  const r = boundaryAnchorSigningInput({
    anchorId: "urn:example:anchor:start", anchoredAt: 1000, chainId: "urn:example:chain",
    sequence: 0, chainHash: b64d("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
    keyId: "anchor-a", publicKey: b64d(ANCHOR_PUB),
  });
  assert.equal(r.ok, true);
  if (r.ok) {
    const message = `${utf8(r.value.protectedSegment)}.${utf8(r.value.payloadSegment)}`;
    assert.equal(
      message,
      "eyJhbGciOiJFZERTQSIsImtpZCI6ImFuY2hvci1hIiwidHlwIjoiYmErY2hhaW4tYW5jaG9yIn0." +
      "eyJhbmNob3JfaWQiOiJ1cm46ZXhhbXBsZTphbmNob3I6c3RhcnQiLCJhbmNob3JlZF9hdCI6MTAwMCwiY2hhaW5faGFzaCI6IkFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUEiLCJjaGFpbl9pZCI6InVybjpleGFtcGxlOmNoYWluIiwia2V5X2ZpbmdlcnByaW50IjoiN1ZqQ3hNSW1tMTZONlJZVWprbFVMeURqYncyYUdFT2dOTnRLQlA5ci1pMCIsInNlcXVlbmNlIjowLCJ2IjoxfQ",
    );
  }
});
test("boundaryAnchorSigningInput rejects a short public key", () => {
  const r = boundaryAnchorSigningInput({
    anchorId: "urn:example:anchor:start", anchoredAt: 1000, chainId: "urn:example:chain",
    sequence: 0, chainHash: b64d("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
    keyId: "anchor-a", publicKey: b64d("AAEC"), // 2 bytes
  });
  assert.equal(r.ok, false);
});

// === 13. key_transition_signing_input (producer known-answer) ===
const NEXT_PUB = "SLLslJOnUaFDS_8T4dGoB7e-6JXly92guv_9hS3tGH0";
const NEXT_FP = "3x4aFGRFbZvTCoSGCd1yA55MYDITwK0MFDlrUFvPoF4";
test("keyTransitionSigningInput produces the canonical message", () => {
  const r = keyTransitionSigningInput({
    transitionId: "urn:example:transition:a-b", chainId: "urn:example:chain", effectiveAt: 1500,
    currentKeyId: "anchor-a", currentPublicKey: b64d(ANCHOR_PUB),
    nextKeyId: "anchor-b", nextPublicKey: b64d(NEXT_PUB),
  });
  assert.equal(r.ok, true);
  if (r.ok) {
    const message = `${utf8(r.value.protectedSegment)}.${utf8(r.value.payloadSegment)}`;
    assert.equal(
      message,
      "eyJhbGciOiJFZERTQSIsImtpZCI6ImFuY2hvci1hIiwidHlwIjoiYmEra2V5LXRyYW5zaXRpb24ifQ." +
      "eyJjaGFpbl9pZCI6InVybjpleGFtcGxlOmNoYWluIiwiZWZmZWN0aXZlX2F0IjoxNTAwLCJmcm9tX2tleV9maW5nZXJwcmludCI6IjdWakN4TUltbTE2TjZSWVVqa2xVTHlEamJ3MmFHRU9nTk50S0JQOXItaTAiLCJ0b19rZXlfZmluZ2VycHJpbnQiOiIzeDRhRkdSRmJadlRDb1NHQ2QxeUE1NU1ZRElUd0swTUZEbHJVRnZQb0Y0IiwidG9fa2V5X2lkIjoiYW5jaG9yLWIiLCJ0cmFuc2l0aW9uX2lkIjoidXJuOmV4YW1wbGU6dHJhbnNpdGlvbjphLWIiLCJ2IjoxfQ",
    );
  }
});
test("keyTransitionSigningInput rejects identical keys", () => {
  const r = keyTransitionSigningInput({
    transitionId: "urn:example:transition:a-b", chainId: "urn:example:chain", effectiveAt: 1500,
    currentKeyId: "anchor-a", currentPublicKey: b64d(ANCHOR_PUB),
    nextKeyId: "anchor-b", nextPublicKey: b64d(ANCHOR_PUB), // same as current
  });
  assert.equal(r.ok, false);
});

// === 14. encode_anchored_export (producer known-answer: byte_count + digest) ===
const START_ANCHOR_COMPACT =
  "eyJhbGciOiJFZERTQSIsImtpZCI6ImFyY2hpdmUtYSIsInR5cCI6ImJhK2NoYWluLWFuY2hvciJ9." +
  "eyJhbmNob3JfaWQiOiJ1cm46ZXhhbXBsZTphbmNob3I6c3RhcnQiLCJhbmNob3JlZF9hdCI6MTAwMCwiY2hhaW5faGFzaCI6IkFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUEiLCJjaGFpbl9pZCI6InVybjpleGFtcGxlOmNoYWluIiwia2V5X2ZpbmdlcnByaW50IjoibzdnbDByZHhTUFUtcVhibU5vZDRSQWtWNXBVamFCNDdKaFBBNDNod0tQOCIsInNlcXVlbmNlIjowLCJ2IjoxfQ." +
  "Falux3uXvUy7PqELqVP_UNWWr3FDT6jUxT7IwtbHY27dqPqHxdsUrSvE216PAtOku9jjPCgoWHYds8YMLD4gAQ";
const END_ANCHOR_COMPACT =
  "eyJhbGciOiJFZERTQSIsImtpZCI6ImFyY2hpdmUtYiIsInR5cCI6ImJhK2NoYWluLWFuY2hvciJ9." +
  "eyJhbmNob3JfaWQiOiJ1cm46ZXhhbXBsZTphbmNob3I6ZW5kIiwiYW5jaG9yZWRfYXQiOjIwMDAsImNoYWluX2hhc2giOiJGcnZqVnRXYXZSTFJBaEpFVG1QVmFiTy1Ha0ZvSUVDWXVaVGFxM0Qycnp3IiwiY2hhaW5faWQiOiJ1cm46ZXhhbXBsZTpjaGFpbiIsImtleV9maW5nZXJwcmludCI6ImluR2h0a29DbzRmQ2hIeGRURXNBdE1yQ2VidFc4NEdNXzd2MnJQYm93b2siLCJzZXF1ZW5jZSI6MSwidiI6MX0." +
  "XUkGaomDgRT1UpYqbhAIANPyv8dYoMp0weep29wht-tu3ImSCxRK6ZOg7qE9vO27bh8H6ubp0YR7mRe0db7HBg";
const TRANSITION_COMPACT =
  "eyJhbGciOiJFZERTQSIsImtpZCI6ImFyY2hpdmUtYSIsInR5cCI6ImJhK2tleS10cmFuc2l0aW9uIn0." +
  "eyJjaGFpbl9pZCI6InVybjpleGFtcGxlOmNoYWluIiwiZWZmZWN0aXZlX2F0IjoxNTAwLCJmcm9tX2tleV9maW5nZXJwcmludCI6Im83Z2wwcmR4U1BVLXFYYm1Ob2Q0UkFrVjVwVWphQjQ3SmhQQTQzaHdLUDgiLCJ0b19rZXlfZmluZ2VycHJpbnQiOiJpbkdodGtvQ280ZkNoSHhkVEVzQXRNckNlYnRXODRHTV83djJyUGJvd29rIiwidG9fa2V5X2lkIjoiYXJjaGl2ZS1iIiwidHJhbnNpdGlvbl9pZCI6InVybjpleGFtcGxlOnRyYW5zaXRpb246YS1iIiwidiI6MX0." +
  "2m3Q9HC2esQQUMTI_iu7EKQvxOZWwbta6v7GTZbeRb8h1uzUwz8xFQYongUv9AOVNow0Gcusc2bOMLro7PKZCQ";
const CHAIN_ROW1 = "eyJjaGFpbl9pZCI6InVybjpleGFtcGxlOmNoYWluIiwiY29tbWl0bWVudCI6IjBQWXh5aDNicU5zN3o4dWVCWHpjbU5BM254dnVBT2RhVkZGSG9uMnQyWUkiLCJwcmV2aW91cyI6IkFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUEiLCJzZXF1ZW5jZSI6MSwidiI6MX0";
const ARCHIVE_DIGEST = "-Bu4a_eh6TYrOYgk0pL68Oc6uXVnyg-lyMyejnhuDKE";

test("encodeAnchoredExport produces the canonical archive (digest + byte_count)", () => {
  const r = encodeAnchoredExport(
    {
      rows: [b64d(CHAIN_ROW1)],
      startAnchor: strUtf8(START_ANCHOR_COMPACT),
      endAnchor: strUtf8(END_ANCHOR_COMPACT),
      transitions: [strUtf8(TRANSITION_COMPACT)],
      chainId: "urn:example:chain", firstSequence: 1, lastSequence: 1, rowCount: 1,
      previousHash: b64d("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
      lastHash: b64d("FrvjVtWavRLRAhJETmPVabO-GkFoIECYuZTaq3D2rzw"),
    },
    {
      chain: {
        chainId: "urn:example:chain", firstSequence: 1, lastSequence: 1, rowCount: 1,
        previousHash: b64d("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
        lastHash: b64d("FrvjVtWavRLRAhJETmPVabO-GkFoIECYuZTaq3D2rzw"),
      },
      digest: b64d(ARCHIVE_DIGEST),
      startAnchor: {
        anchorId: "urn:example:anchor:start", anchoredAt: 1000, chainId: "urn:example:chain",
        sequence: 0, chainHash: b64d("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
        keyId: "archive-a", keyFingerprint: b64d("o7gl0rdxSPU-qXbmNod4RAkV5pUjaB47JhPA43hwKP8"),
      },
      endAnchor: {
        anchorId: "urn:example:anchor:end", anchoredAt: 2000, chainId: "urn:example:chain",
        sequence: 1, chainHash: b64d("FrvjVtWavRLRAhJETmPVabO-GkFoIECYuZTaq3D2rzw"),
        keyId: "archive-b", keyFingerprint: b64d("inGhtkoCo4fChHxdTEsAtMrCebtW84GM_7v2rPbowok"),
      },
      transitions: [{
        transitionId: "urn:example:transition:a-b", chainId: "urn:example:chain", effectiveAt: 1500,
        currentKeyId: "archive-a", currentKeyFingerprint: b64d("o7gl0rdxSPU-qXbmNod4RAkV5pUjaB47JhPA43hwKP8"),
        nextKeyId: "archive-b", nextKeyFingerprint: b64d("inGhtkoCo4fChHxdTEsAtMrCebtW84GM_7v2rPbowok"),
      }],
      objectVersion: "v1",
    },
  );
  assert.equal(r.ok, true);
  if (r.ok) {
    assert.equal(r.value.archive.length, 1900);
    assert.equal(b64e(r.value.digest), ARCHIVE_DIGEST);
    // The archive SHA-256 is independently verifiable.
    assert.deepEqual(Array.from(sha256(r.value.archive)), Array.from(r.value.digest));
  }
});

// === 15. verify_historical_anchor (valid signature) ===
const ARCHIVE_A_PUB = "YXgT52I83qBmbNzq_RMxiYT1T_EELrAj9rUkjCaSkP4";
const ARCHIVE_A_FP = "o7gl0rdxSPU-qXbmNod4RAkV5pUjaB47JhPA43hwKP8";
test("verifyHistoricalAnchor accepts a validly-signed anchor", () => {
  _resetCensus();
  const r = verifyHistoricalAnchor(
    strUtf8(START_ANCHOR_COMPACT),
    { keyId: "archive-a", publicKey: b64d(ARCHIVE_A_PUB), validFrom: 0, validBefore: 3000 },
    {
      anchorId: "urn:example:anchor:start", anchoredAt: 1000, chainId: "urn:example:chain",
      sequence: 0, chainHash: b64d("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
      keyId: "archive-a", keyFingerprint: b64d(ARCHIVE_A_FP),
    },
  );
  assert.equal(r.ok, true);
  if (r.ok) {
    assert.equal(r.value.anchorId, "urn:example:anchor:start");
    assert.equal(r.value.sequence, 0);
    assert.equal(r.value.trust, "not_evaluated");
  }
});

// === 16. verify_key_transition (valid signature) ===
const ARCHIVE_B_PUB = "XG9480jOPYDgf2f545Fjd6YiqLjyA5-jp0RYRnxgHTs";
const ARCHIVE_B_FP = "inGhtkoCo4fChHxdTEsAtMrCebtW84GM_7v2rPbowok";
test("verifyKeyTransition accepts a validly-signed transition", () => {
  _resetCensus();
  const r = verifyKeyTransition(
    strUtf8(TRANSITION_COMPACT),
    { keyId: "archive-a", publicKey: b64d(ARCHIVE_A_PUB), validFrom: 0, validBefore: 3000 },
    { keyId: "archive-b", publicKey: b64d(ARCHIVE_B_PUB), validFrom: 0, validBefore: 3000 },
    {
      transitionId: "urn:example:transition:a-b", chainId: "urn:example:chain", effectiveAt: 1500,
      currentKeyId: "archive-a", currentKeyFingerprint: b64d(ARCHIVE_A_FP),
      nextKeyId: "archive-b", nextKeyFingerprint: b64d(ARCHIVE_B_FP),
    },
  );
  assert.equal(r.ok, true);
  if (r.ok) {
    assert.equal(r.value.transitionId, "urn:example:transition:a-b");
    assert.equal(r.value.effectiveAt, 1500);
    assert.equal(r.value.trust, "not_evaluated");
  }
});

// === 17. verify_anchored_export (valid full archive) ===
test("verifyAnchoredExport accepts a valid archive", () => {
  _resetCensus();
  // The corpus verify case's chunks (base64url-encoded, arbitrary binary split of the archive stream;
  // a single frame may span chunk boundaries, so they are concatenated before parsing).
  const chunks = [
    "QkFQMS1BUkNISVZFAEVYUE9SVAA",
    "AAAA5nsiY2hhaW5faWQiOiJ1cm46ZXhhbXBsZTpjaGFpbiIsImZpcnN0X3NlcXVlbmNlIjoxLCJsYXN0X2hhc2giOiJGcnZqVnRXYXZSTFJBaEpFVG1QVmFiTy1Ha0ZvSUVDWXVaVGFxM0Qycnp3IiwibGFzdF9zZXF1ZW5jZSI6MSwicHJldmlvdXNfaGFzaCI6IkFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUEiLCJyb3dfY291bnQiOjEsInRyYW5zaXRpb25fY291bnQiOjEsInYiOjF9",
    "AAAB2mV5SmhiR2NpT2lKRlpFUlRRU0lzSW10cFpDSTZJbUZ5WTJocGRtVXRZU0lzSW5SNWNDSTZJbUpoSzJOb1lXbHVMV0Z1WTJodmNpSjkuZXlKaGJtTm9iM0pmYVdRaU9pSjFjbTQ2WlhoaGJYQnNaVHBoYm1Ob2IzSTZjM1JoY25RaUxDSmhibU5vYjNKbFpGOWhkQ0k2TVRBd01Dd2lZMmhoYVc1ZmFHRnphQ0k2SWtGQlFVRkJRVUZCUVVGQlFVRkJRVUZCUVVGQlFVRkJRVUZCUVVGQlFVRkJRVUZCUVVGQlFVRkJRVUVpTENKamFHRnBibDlwWkNJNkluVnlianBsZUdGdGNHeGxPbU5vWVdsdUlpd2lhMlY1WDJacGJtZGxjbkJ5YVc1MElqb2liemRuYkRCeVpIaFRVRlV0Y1ZoaWJVNXZaRFJTUVd0V05YQlZhbUZDTkRkS2FGQkJORE5vZDB0UU9DSXNJbk5sY1hWbGJtTmxJam93TENKMklqb3hmUS5GYWx1eDN1WHZVeTdQcUVMcVZQX1VOV1dyM0ZEVDZqVXhUN0l3dGJIWTI3ZHFQcUh4ZHNVclN2RTIxNlBBdE9rdTlqalBDZ29XSFlkczhZTUxENGdBUQ",
    "AAACBmV5SmhiR2NpT2lKRlpFUlRRU0lzSW10cFpDSTZJbUZ5WTJocGRtVXRZU0lzSW5SNWNDSTZJbUpoSzJ0bGVTMTBjbUZ1YzJsMGFXOXVJbjAuZXlKamFHRnBibDlwWkNJNkluVnlianBsZUdGdGNHeGxPbU5vWVdsdUlpd2laV1ptWldOMGFYWmxYMkYwSWpveE5UQXdMQ0ptY205dFgydGxlVjltYVc1blpYSndjbWx1ZENJNkltODNaMnd3Y21SNFUxQlZMWEZZWW0xT2IyUTBVa0ZyVmpWd1ZXcGhRalEzU21oUVFUUXphSGRMVURnaUxDSjBiMTlyWlhsZlptbHVaMlZ5Y0hKcGJuUWlPaUpwYmtkb2RHdHZRMjgwWmtOb1NIaGtWRVZ6UVhSTmNrTmxZblJYT0RSSFRWODNkakp5VUdKdmQyOXJJaXdpZEc5ZmEyVjVYMmxrSWpvaVlYSmphR2wyWlMxaUlpd2lkSEpoYm5OcGRHbHZibDlwWkNJNkluVnlianBsZUdGdGNHeGxPblJ5WVc1emFYUnBiMjQ2WVMxaUlpd2lkaUk2TVgwLjJtM1E5SEMyZXNRUVVNVElfaXU3RUtRdnhPWld3YnRhNnY3R1RaYmVSYjhoMXV6VXd6OHhGUVlvbmdVdjlBT1ZOb3cwR2N1c2MyYk9NTHJvN1BLWkNR",
    "AAAAp3siY2hhaW5faWQiOiJ1cm46ZXhhbXBsZTpjaGFpbiIsImNvbW1pdG1lbnQiOiIwUFl4eWgzYnFOczd6OHVlQlh6Y21OQTNueHZ1QU9kYVZGRkhvbjJ0MllJIiwicHJldmlvdXMiOiJBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBIiwic2VxdWVuY2UiOjEsInYiOjF9",
    "AAAB12V5SmhiR2NpT2lKRlpFUlRRU0lzSW10cFpDSTZJbUZ5WTJocGRtVXRZaUlzSW5SNWNDSTZJbUpoSzJOb1lXbHVMV0Z1WTJodmNpSjkuZXlKaGJtTm9iM0pmYVdRaU9pSjFjbTQ2WlhoaGJYQnNaVHBoYm1Ob2IzSTZaVzVrSWl3aVlXNWphRzl5WldSZllYUWlPakl3TURBc0ltTm9ZV2x1WDJoaGMyZ2lPaUpHY25acVZuUlhZWFpTVEZKQmFFcEZWRzFRVm1GaVR5MUhhMFp2U1VWRFdYVmFWR0Z4TTBReWNucDNJaXdpWTJoaGFXNWZhV1FpT2lKMWNtNDZaWGhoYlhCc1pUcGphR0ZwYmlJc0ltdGxlVjltYVc1blpYSndjbWx1ZENJNkltbHVSMmgwYTI5RGJ6Um1RMmhJZUdSVVJYTkJkRTF5UTJWaWRGYzRORWROWHpkMk1uSlFZbTkzYjJzaUxDSnpaWEYxWlc1alpTSTZNU3dpZGlJNk1YMC5YVWtHYW9tRGdSVDFVcFlxYmhBSUFOUHl2OGRZb01wMHdlZXAyOXdodC10dTNJbVNDeFJLNlpPZzdxRTl2TzI3Ymg4SDZ1YnAwWVI3bVJlMGRiN0hCZw",
  ].map((c) => b64d(c));
  const r = verifyAnchoredExport(
    { chunks, version: "v1" },
    {
      keys: [
        { keyId: "archive-a", publicKey: b64d(ARCHIVE_A_PUB), validFrom: 0, validBefore: 2000 },
        { keyId: "archive-b", publicKey: b64d(ARCHIVE_B_PUB), validFrom: 1000, validBefore: 3000 },
      ],
    },
    {
      chain: {
        chainId: "urn:example:chain", firstSequence: 1, lastSequence: 1, rowCount: 1,
        previousHash: b64d("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
        lastHash: b64d("FrvjVtWavRLRAhJETmPVabO-GkFoIECYuZTaq3D2rzw"),
      },
      digest: b64d(ARCHIVE_DIGEST),
      startAnchor: {
        anchorId: "urn:example:anchor:start", anchoredAt: 1000, chainId: "urn:example:chain",
        sequence: 0, chainHash: b64d("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
        keyId: "archive-a", keyFingerprint: b64d(ARCHIVE_A_FP),
      },
      endAnchor: {
        anchorId: "urn:example:anchor:end", anchoredAt: 2000, chainId: "urn:example:chain",
        sequence: 1, chainHash: b64d("FrvjVtWavRLRAhJETmPVabO-GkFoIECYuZTaq3D2rzw"),
        keyId: "archive-b", keyFingerprint: b64d(ARCHIVE_B_FP),
      },
      transitions: [{
        transitionId: "urn:example:transition:a-b", chainId: "urn:example:chain", effectiveAt: 1500,
        currentKeyId: "archive-a", currentKeyFingerprint: b64d(ARCHIVE_A_FP),
        nextKeyId: "archive-b", nextKeyFingerprint: b64d(ARCHIVE_B_FP),
      }],
      objectVersion: "v1",
    },
  );
  assert.equal(r.ok, true);
  if (r.ok) {
    assert.equal(r.value.rowCount, 1);
    assert.equal(r.value.transitionCount, 1);
    assert.equal(r.value.objectVersion, "v1");
    assert.equal(r.value.trust, "not_evaluated");
    assert.equal(r.value.authorization, "not_evaluated");
  }
});

// === BAP-09 derisk: cross-vendor reference-divergence tripwires ===

// #9 producer ath scan: proof_signing_input MUST scan the grant compact (shape+size) before hashing
// it into `ath` (compact_jws.ex:16-27 scan gates ath/hash). A 2-segment grant compact is not a
// valid compact JWS; the producer must reject it rather than embed sha256(garbage) in the proof.
test("proofSigningInput rejects a malformed (2-segment) grant compact", () => {
  const r = proofSigningInput({
    holderPublicKey: b64d(HOLDER_PUB),
    proofId: "urn:example:proof:1", method: "POST", targetUri: "https://resource.example.test/invoke",
    issuedAt: 1100, invocationId: "550e8400-e29b-41d4-a716-446655440000", operation: "read",
    grantCompact: strUtf8("eyJhbGciOiJFZERTQSJ9.bm90YWNvbXBhY3Q"), // 2 segments — not a compact
    castArguments: jsonDecode(strUtf8('{"limit":10}')),
  });
  assert.equal(r.ok, false);
});

// #4 archive encode aggregate bounds: encode_anchored_export MUST enforce archive_chunks (frame
// COUNT) during encode (anchored_export_codec.ex:69 validate_chunks), not only archive_bytes. The
// corpus archive frames into 6 chunks (prefix+header+start+transition+row+end); tightening
// archive_chunks below 6 must reject at encode even though archive_bytes is still ample.
test("encodeAnchoredExport rejects when archive_chunks frame count is exceeded", () => {
  const r = encodeAnchoredExport(
    {
      rows: [b64d(CHAIN_ROW1)],
      startAnchor: strUtf8(START_ANCHOR_COMPACT),
      endAnchor: strUtf8(END_ANCHOR_COMPACT),
      transitions: [strUtf8(TRANSITION_COMPACT)],
      chainId: "urn:example:chain", firstSequence: 1, lastSequence: 1, rowCount: 1,
      previousHash: b64d("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
      lastHash: b64d("FrvjVtWavRLRAhJETmPVabO-GkFoIECYuZTaq3D2rzw"),
    },
    {
      bounds: boundsNew({ archive_chunks: 5 }), // 6 frames > 5 → reject
      chain: {
        chainId: "urn:example:chain", firstSequence: 1, lastSequence: 1, rowCount: 1,
        previousHash: b64d("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
        lastHash: b64d("FrvjVtWavRLRAhJETmPVabO-GkFoIECYuZTaq3D2rzw"),
      },
      digest: b64d(ARCHIVE_DIGEST),
      startAnchor: {
        anchorId: "urn:example:anchor:start", anchoredAt: 1000, chainId: "urn:example:chain",
        sequence: 0, chainHash: b64d("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
        keyId: "archive-a", keyFingerprint: b64d("o7gl0rdxSPU-qXbmNod4RAkV5pUjaB47JhPA43hwKP8"),
      },
      endAnchor: {
        anchorId: "urn:example:anchor:end", anchoredAt: 2000, chainId: "urn:example:chain",
        sequence: 1, chainHash: b64d("FrvjVtWavRLRAhJETmPVabO-GkFoIECYuZTaq3D2rzw"),
        keyId: "archive-b", keyFingerprint: b64d("inGhtkoCo4fChHxdTEsAtMrCebtW84GM_7v2rPbowok"),
      },
      transitions: [{
        transitionId: "urn:example:transition:a-b", chainId: "urn:example:chain", effectiveAt: 1500,
        currentKeyId: "archive-a", currentKeyFingerprint: b64d("o7gl0rdxSPU-qXbmNod4RAkV5pUjaB47JhPA43hwKP8"),
        nextKeyId: "archive-b", nextKeyFingerprint: b64d("inGhtkoCo4fChHxdTEsAtMrCebtW84GM_7v2rPbowok"),
      }],
      objectVersion: "v1",
    },
  );
  assert.equal(r.ok, false);
});

// #11 assemble_compact content validation: the public façade must validate the signing input
// (kind↔typ, segment bounds, base64url payload) and re-parse the composed compact per kind
// (runtime.ex:151 validate_assembled_compact). It must NOT assemble a mislabeled or malformed compact.
const GRANT_PROTECTED = strUtf8(GRANT_COMPACT.split(".")[0]!);
const PROOF_PROTECTED = strUtf8(PROOF_COMPACT.split(".")[0]!);

test("assembleCompact rejects a kind/typ mismatch (grant kind, proof header)", () => {
  const r = assembleCompact(
    { kind: "grant", protectedSegment: PROOF_PROTECTED, payloadSegment: strUtf8("e30") },
    new Uint8Array(64),
  );
  assert.equal(r.ok, false);
});

test("assembleCompact rejects an oversized protected segment", () => {
  const r = assembleCompact(
    { kind: "grant", protectedSegment: new Uint8Array(32769).fill(0x41), payloadSegment: strUtf8("e30") },
    new Uint8Array(64),
  );
  assert.equal(r.ok, false);
});

test("assembleCompact rejects a non-base64url payload segment", () => {
  const r = assembleCompact(
    { kind: "grant", protectedSegment: GRANT_PROTECTED, payloadSegment: strUtf8("not-valid!@#") },
    new Uint8Array(64),
  );
  assert.equal(r.ok, false);
});

test("assembleCompact rejects a structurally-invalid grant payload (re-parse)", () => {
  // Valid grant header + a payload that is valid base64url + valid JSON but NOT a valid grant
  // (empty object, missing every required field). The per-kind re-parse must reject it.
  const r = assembleCompact(
    { kind: "grant", protectedSegment: GRANT_PROTECTED, payloadSegment: strUtf8("e30") },
    new Uint8Array(64),
  );
  assert.equal(r.ok, false);
});

test("assembleCompact rejects a well-formed grant payload with a numeric iss (field re-parse)", () => {
  // Cross-vendor (codex): the grant re-parse must validate FIELD values, not just the closed key-set.
  // This payload has every required key with the right types EXCEPT `iss` (numeric, not a string) —
  // the structural validator alone accepts it; the full decode_grant re-parse must reject it.
  const json = '{"v":1,"iss":123,"jti":"urn:example:g:1","aud":["https://resource.example.test"],' +
    '"iat":1000,"nbf":1000,"exp":2000,"cnf":{"jkt":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"},' +
    '"operations":[{"name":"read","selectors":[{"kind":"all"}]}]}';
  const r = assembleCompact(
    { kind: "grant", protectedSegment: GRANT_PROTECTED, payloadSegment: base64urlEncode(strUtf8(json)) },
    new Uint8Array(64),
  );
  assert.equal(r.ok, false);
});

// Canonical-form (reference BoundaryAnchorCodec.parse:95-96,118-119 / KeyTransitionCodec.parse): the
// protected AND payload segments of an anchor/transition compact must be the exact JCS encoding.
// The SDK parse helpers now enforce this (parseAnchorHeader/parseTransitionHeader on the protected
// segment; validateAnchorPayload/validateTransitionPayload on the payload). These prove BOTH sites
// fire — without the check the façade accepts the non-canonical compact.
const ANCHOR_HEADER = strUtf8(START_ANCHOR_COMPACT.split(".")[0]!);   // canonical anchor header
const ANCHOR_PAYLOAD = strUtf8(START_ANCHOR_COMPACT.split(".")[1]!);   // canonical anchor payload

test("assembleCompact rejects a non-canonical anchor protected header (canonical-form)", () => {
  // Same members as the canonical anchor header, but in a non-JCS order → bytes != Jcs.encode.
  const nonCanonical = base64urlEncode(strUtf8('{"typ":"ba+chain-anchor","alg":"EdDSA","kid":"archive-a"}'));
  const r = assembleCompact({ kind: "boundary_anchor", protectedSegment: nonCanonical, payloadSegment: ANCHOR_PAYLOAD }, new Uint8Array(64));
  assert.equal(r.ok, false);
});

test("assembleCompact rejects a non-canonical anchor payload (canonical-form)", () => {
  // Canonical header + the canonical payload's members in reverse (non-JCS) order, values unchanged.
  const canon = JSON.parse(utf8(base64urlDecode(ANCHOR_PAYLOAD))) as Record<string, unknown>;
  const reversed = "{" + Object.keys(canon).reverse().map(k => `${JSON.stringify(k)}:${JSON.stringify(canon[k])}`).join(",") + "}";
  const nonCanonicalPayload = base64urlEncode(strUtf8(reversed));
  const r = assembleCompact({ kind: "boundary_anchor", protectedSegment: ANCHOR_HEADER, payloadSegment: nonCanonicalPayload }, new Uint8Array(64));
  assert.equal(r.ok, false);
});

test("decodeGrant rejects a compact with a wrong-width signature (signature-width gate)", () => {
  // Reference parse_grant (runtime.ex:237) requires byte_size(signature) == signature_bytes (64).
  // The SDK decode path now enforces this (compact.ts parseCompact); a grant compact with a 32-byte
  // signature segment must reject where it previously decoded to Ok.
  const parts = GRANT_COMPACT.split(".");
  const wrongSig = utf8(base64urlEncode(new Uint8Array(32)));
  const r = decodeGrant(strUtf8(`${parts[0]!}.${parts[1]!}.${wrongSig}`));
  assert.equal(r.ok, false);
});

test("assembleCompact rejects a non-canonical transition protected header (canonical-form)", () => {
  // Same members as the canonical transition header, but in a non-JCS order → bytes != Jcs.encode
  // (reference KeyTransitionCodec.parse:127-128). Symmetric to the anchor-header test above.
  const nonCanonical = base64urlEncode(strUtf8('{"typ":"ba+key-transition","alg":"EdDSA","kid":"anchor-a"}'));
  const payload = strUtf8(TRANSITION_COMPACT.split(".")[1]!);
  const r = assembleCompact({ kind: "key_transition", protectedSegment: nonCanonical, payloadSegment: payload }, new Uint8Array(64));
  assert.equal(r.ok, false);
});

test("assembleCompact rejects a non-canonical transition payload (canonical-form)", () => {
  // Canonical header + the canonical payload's members in reverse (non-JCS) order, values unchanged
  // (reference KeyTransitionCodec.parse:151-152). Symmetric to the anchor-payload test above.
  const header = strUtf8(TRANSITION_COMPACT.split(".")[0]!);
  const canon = JSON.parse(utf8(base64urlDecode(strUtf8(TRANSITION_COMPACT.split(".")[1]!)))) as Record<string, unknown>;
  const reversed = "{" + Object.keys(canon).reverse().map(k => `${JSON.stringify(k)}:${JSON.stringify(canon[k])}`).join(",") + "}";
  const nonCanonicalPayload = base64urlEncode(strUtf8(reversed));
  const r = assembleCompact({ kind: "key_transition", protectedSegment: header, payloadSegment: nonCanonicalPayload }, new Uint8Array(64));
  assert.equal(r.ok, false);
});

// === census sanity: the valid verify surfaces imported their keys ===
test("census tracks imported fingerprints", () => {
  _resetCensus();
  verifyGrant(
    strUtf8(GRANT_COMPACT),
    { keyId: "issuer", publicKey: b64d(ISSUER_PUB) },
    { issuer: "https://issuer.example.test", audience: "https://resource.example.test", evaluationTime: 1500, clockSkew: 60 },
  );
  // After verify_grant, the issuer fingerprint is in the census.
  assert.ok(_importedFingerprints().has(ISSUER_FP), "issuer fingerprint must be tracked");
});

// ============================================================================
// Encode-path validation parity (reference anchored_export_codec.ex encode):
// the row chain re-check + gated parses + full matches for both anchors and
// every transition. One red-capable leg per NEW clause; each leg's mutation =
// neutralize that clause in encodeAnchoredExport / parseAndMatchAnchor /
// parseAndMatchTransition / the checkChain call (proven in the task log).
// ============================================================================

const KEY_A = new Uint8Array(32).fill(7);
const KEY_B = new Uint8Array(32).fill(8);
const Z32T = new Uint8Array(32);
const SIG64T = new Uint8Array(64);
const SIG32T = new Uint8Array(32);

function conformantExportT() {
  const rowR = encodeConsumptionEntry({ chainId: "chain-x", sequence: 1, previousHash: Z32T, commitment: new Uint8Array(32).fill(5) });
  assert.equal(rowR.ok, true);
  const row = (rowR as { ok: true; value: { bytes: Uint8Array; hash: Uint8Array } }).value.bytes;
  const head = (rowR as { ok: true; value: { bytes: Uint8Array; hash: Uint8Array } }).value.hash;
  const fpOf = (k: Uint8Array) => thumbprintRaw(jwkFromPublicKey(k));
  const startR = boundaryAnchorSigningInput({ anchorId: "anchor-start", anchoredAt: 1000, chainId: "chain-x", sequence: 0, chainHash: Z32T, keyId: "anchor-a", publicKey: KEY_A });
  assert.equal(startR.ok, true);
  const startCompact = (assembleCompact((startR as { ok: true; value: import("../src/compact.js").SigningInput }).value, SIG64T) as { ok: true; value: Uint8Array }).value;
  const endR = boundaryAnchorSigningInput({ anchorId: "anchor-end", anchoredAt: 1600, chainId: "chain-x", sequence: 1, chainHash: head, keyId: "anchor-b", publicKey: KEY_B });
  assert.equal(endR.ok, true);
  const endCompact = (assembleCompact((endR as { ok: true; value: import("../src/compact.js").SigningInput }).value, SIG64T) as { ok: true; value: Uint8Array }).value;
  const tR = keyTransitionSigningInput({ transitionId: "transition-1", chainId: "chain-x", effectiveAt: 1500, currentKeyId: "anchor-a", currentPublicKey: KEY_A, nextKeyId: "anchor-b", nextPublicKey: KEY_B });
  assert.equal(tR.ok, true);
  const tCompact = (assembleCompact((tR as { ok: true; value: import("../src/compact.js").SigningInput }).value, SIG64T) as { ok: true; value: Uint8Array }).value;
  const chain = { chainId: "chain-x", firstSequence: 1, lastSequence: 1, rowCount: 1, previousHash: Z32T, lastHash: head };
  const expected = {
    chain,
    digest: Z32T,
    startAnchor: { anchorId: "anchor-start", anchoredAt: 1000, chainId: "chain-x", sequence: 0, chainHash: Z32T, keyId: "anchor-a", keyFingerprint: fpOf(KEY_A) },
    endAnchor: { anchorId: "anchor-end", anchoredAt: 1600, chainId: "chain-x", sequence: 1, chainHash: head, keyId: "anchor-b", keyFingerprint: fpOf(KEY_B) },
    transitions: [{ transitionId: "transition-1", chainId: "chain-x", effectiveAt: 1500, currentKeyId: "anchor-a", currentKeyFingerprint: fpOf(KEY_A), nextKeyId: "anchor-b", nextKeyFingerprint: fpOf(KEY_B) }],
    objectVersion: "v1",
  };
  const input = { rows: [row], startAnchor: startCompact, endAnchor: endCompact, transitions: [tCompact], ...chain };
  return { input, expected, fpOf };
}

function expectEncodeErr(input: unknown, expected: unknown): void {
  const r = encodeAnchoredExport(input as never, expected as never);
  assert.equal(r.ok, false, "encode must reject");
}

test("encode-parity control: the conformant export encodes Ok", () => {
  const { input, expected } = conformantExportT();
  const r = encodeAnchoredExport(input, expected);
  assert.equal(r.ok, true);
});

test("encode-parity: a tampered row byte rejects (rows chain re-check)", () => {
  const { input, expected } = conformantExportT();
  const bad = Uint8Array.from(input.rows[0]!);
  bad[0]! ^= 1;
  expectEncodeErr({ ...input, rows: [bad] }, expected);
});

test("encode-parity: a start-anchor field mismatch rejects (7-field match)", () => {
  const { input, expected } = conformantExportT();
  const wrong = boundaryAnchorSigningInput({ anchorId: "anchor-WRONG", anchoredAt: 1000, chainId: "chain-x", sequence: 0, chainHash: Z32T, keyId: "anchor-a", publicKey: KEY_A });
  const wrongCompact = (assembleCompact((wrong as { ok: true; value: import("../src/compact.js").SigningInput }).value, SIG64T) as { ok: true; value: Uint8Array }).value;
  expectEncodeErr({ ...input, startAnchor: wrongCompact }, expected);
});

test("encode-parity: an end-anchor field mismatch rejects (7-field match)", () => {
  const { input, expected } = conformantExportT();
  const wrong = boundaryAnchorSigningInput({ anchorId: "anchor-WRONG", anchoredAt: 1600, chainId: "chain-x", sequence: 1, chainHash: expected.chain.lastHash, keyId: "anchor-b", publicKey: KEY_B });
  const wrongCompact = (assembleCompact((wrong as { ok: true; value: import("../src/compact.js").SigningInput }).value, SIG64T) as { ok: true; value: Uint8Array }).value;
  expectEncodeErr({ ...input, endAnchor: wrongCompact }, expected);
});

test("encode-parity: a non-canonical end anchor rejects (gated parse)", () => {
  const { input, expected } = conformantExportT();
  const segs = new TextDecoder().decode(input.endAnchor).split(".");
  const payloadObj = JSON.parse(new TextDecoder().decode(b64d(segs[1]!)));
  const reversed = "{" + Object.keys(payloadObj).reverse().map(k => `${JSON.stringify(k)}:${JSON.stringify(payloadObj[k])}`).join(",") + "}";
  const nonCanonical = segs[0]! + "." + b64e(strUtf8(reversed)) + "." + segs[2]!;
  expectEncodeErr({ ...input, endAnchor: strUtf8(nonCanonical) }, expected);
});

test("encode-parity: a wrong-width end-anchor signature rejects (gated parse)", () => {
  const { input, expected } = conformantExportT();
  const segs = new TextDecoder().decode(input.endAnchor).split(".");
  const rebuilt = segs[0]! + "." + segs[1]! + "." + b64e(SIG32T);
  expectEncodeErr({ ...input, endAnchor: strUtf8(rebuilt) }, expected);
});

test("encode-parity: a transition field mismatch rejects (7-field match)", () => {
  const { input, expected } = conformantExportT();
  const wrong = keyTransitionSigningInput({ transitionId: "transition-1", chainId: "chain-x", effectiveAt: 1501, currentKeyId: "anchor-a", currentPublicKey: KEY_A, nextKeyId: "anchor-b", nextPublicKey: KEY_B });
  const wrongCompact = (assembleCompact((wrong as { ok: true; value: import("../src/compact.js").SigningInput }).value, SIG64T) as { ok: true; value: Uint8Array }).value;
  expectEncodeErr({ ...input, transitions: [wrongCompact] }, expected);
});

test("encode-parity: a non-canonical transition rejects (gated parse)", () => {
  const { input, expected } = conformantExportT();
  const segs = new TextDecoder().decode(input.transitions[0]!).split(".");
  const payloadObj = JSON.parse(new TextDecoder().decode(b64d(segs[1]!)));
  const reversed = "{" + Object.keys(payloadObj).reverse().map(k => `${JSON.stringify(k)}:${JSON.stringify(payloadObj[k])}`).join(",") + "}";
  const nonCanonical = segs[0]! + "." + b64e(strUtf8(reversed)) + "." + segs[2]!;
  expectEncodeErr({ ...input, transitions: [strUtf8(nonCanonical)] }, expected);
});

test("encode-parity: a wrong-width transition signature rejects (gated parse)", () => {
  const { input, expected } = conformantExportT();
  const segs = new TextDecoder().decode(input.transitions[0]!).split(".");
  const rebuilt = segs[0]! + "." + segs[1]! + "." + b64e(SIG32T);
  expectEncodeErr({ ...input, transitions: [strUtf8(rebuilt)] }, expected);
});

test("encode-parity: a tightened outer bounds takes effect at the row re-check (F1)", () => {
  const { input, expected } = conformantExportT();
  // chain_row_bytes 156 < the 157-byte row: the row walk must run under the OUTER
  // bounds (anchored_export_codec.ex:33-39) and reject, not under the chain's
  // default-to-maximum nested resolution (correctness-lens F1).
  const tight = boundsNew({ chain_row_bytes: 156 });
  const r = encodeAnchoredExport(input, { ...expected, bounds: tight });
  assert.equal(r.ok, false, "tightened outer bounds must reject the oversized row at encode");
});

test("encode-parity: a start-anchor nested-bounds mismatch rejects (the four-pin sweep)", () => {
  const { input, expected } = conformantExportT();
  // The reference pins ALL FOUR nested bounds to the outer (anchored_export_codec.ex:352-354,
  // :404-406); the F1 fix landed only the chain pin — this leg pins the anchor sweep.
  const anchorTight = boundsNew({ chain_row_bytes: 156 });
  const r = encodeAnchoredExport(input, { ...expected, startAnchor: { ...expected.startAnchor, bounds: anchorTight } });
  assert.equal(r.ok, false, "a nested anchor-bounds mismatch must reject at encode");
});

test("encode-parity: identity overrides (explicit maxima) are NOT tightening (absent nested accepted)", () => {
  const { input, expected } = conformantExportT();
  // An outer bounds built from an explicit MAXIMUM value is an identity override: the
  // reference merges it into the full maximum struct and the pin's struct equality
  // accepts absent nested bounds. Map-size gating wrong-rejected this (cross-vendor).
  const identity = boundsNew({ chain_row_bytes: 4096 }); // == MAXIMA.chain_row_bytes
  const r = encodeAnchoredExport(input, { ...expected, bounds: identity });
  assert.equal(r.ok, true, "identity overrides must encode (not tightening)");
});

test("encode-parity: an end-anchor nested-bounds mismatch rejects (the four-pin sweep)", () => {
  const { input, expected } = conformantExportT();
  const anchorTight = boundsNew({ chain_row_bytes: 156 });
  const r = encodeAnchoredExport(input, { ...expected, endAnchor: { ...expected.endAnchor, bounds: anchorTight } });
  assert.equal(r.ok, false, "an end-anchor nested-bounds mismatch must reject at encode");
});

test("encode-parity: a transition nested-bounds mismatch rejects (the four-pin sweep)", () => {
  const { input, expected } = conformantExportT();
  const anchorTight = boundsNew({ chain_row_bytes: 156 });
  const r = encodeAnchoredExport(input, { ...expected, transitions: [{ ...expected.transitions[0]!, bounds: anchorTight }] });
  assert.equal(r.ok, false, "a transition nested-bounds mismatch must reject at encode");
});

test("encode-parity: the chain nested-bounds pin rejects a mismatched chain.bounds (isolated)", () => {
  const { input, expected } = conformantExportT();
  // Isolates the CHAIN pin: the row (157 bytes) FITS under the tightened limit
  // chosen here (chain_row_bytes 4096 stays above the row), so the row walk
  // cannot backstop — only the pin fires on the mismatched chain.bounds
  // (delta-review finding 1: the F1 leg's 156 ceiling made it joint-only).
  // Isolated the diff-review's way: the OUTER stays at maximum (untightened —
  // the sibling absent-nested pins pass); ONLY chain.bounds carries a different
  // value (4000 < 4096, row-safe). The prior fixture tightened the OUTER, so
  // the sibling absent-nested pins backstopped it — vacuous under the mutation.
  const r = encodeAnchoredExport(input, { ...expected, chain: { ...expected.chain, bounds: boundsNew({ chain_row_bytes: 4000 }) } });
  assert.equal(r.ok, false, "a chain nested-bounds mismatch must reject at encode (isolated)");
});

test("encode-parity: a tightened anchor_bytes rejects the anchor compacts at encode (round 2)", () => {
  const { input, expected } = conformantExportT();
  // The codex probe: anchor_bytes=1 tightened outer — parseCompact only gates
  // compact_bytes (65536), so without the explicit per-anchor ceiling the ~440-byte
  // anchors framed fine (the reference codec gates anchor_bytes at :82/:114).
  const tight = boundsNew({ anchor_bytes: 1 });
  const r = encodeAnchoredExport(input, { ...expected, bounds: tight });
  assert.equal(r.ok, false, "tightened anchor_bytes must reject the anchor compacts at encode");
});

test("verify-parity: a caller-inconsistent expected end-anchor chain_id rejects (round 2)", () => {
  const { input, expected } = conformantExportT();
  const enc = encodeAnchoredExport(input, expected);
  assert.equal(enc.ok, true);
  const value = (enc as { ok: true; value: { archive: Uint8Array; digest: Uint8Array } }).value;
  // reframe into chunks: magic(20) + frames
  const chunks: Uint8Array[] = [];
  let off = 20;
  const b = value.archive;
  while (off < b.length) {
    const len = (b[off]! << 24) | (b[off + 1]! << 16) | (b[off + 2]! << 8) | b[off + 3]!;
    chunks.push(b.slice(off + 4, off + 4 + len));
    off += 4 + len;
  }
  const keys: HistoricalKeyChain = {
    keys: [
      { keyId: "anchor-a", publicKey: KEY_A, validFrom: 900, validBefore: null },
      { keyId: "anchor-b", publicKey: KEY_B, validFrom: 1400, validBefore: null },
    ],
  };
  const vExpected = {
    chain: expected.chain,
    digest: value.digest,
    startAnchor: expected.startAnchor,
    endAnchor: { ...expected.endAnchor, chainId: "chain-OTHER" },
    transitions: expected.transitions,
    objectVersion: "v1",
  };
  const r = verifyAnchoredExport({ chunks, version: "v1" }, keys, vExpected as never);
  assert.equal(r.ok, false, "a caller-inconsistent expected anchor chain_id must reject at verify");
});

test("bounds-parity: an out-of-magnitude bounded validBefore rejects at verify (all-SDK convergence)", () => {
  // A REAL runtime-generated signature (node:crypto; nothing persisted) so the
  // control verifies Ok and only the magnitude gate can reject the bad case.
  const { generateKeyPairSync, sign: nodeSign } = crypto as typeof import("node:crypto");
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const jwk = publicKey.export({ format: "jwk" }) as { x: string };
  const pubRaw = Buffer.from(jwk.x, "base64url");
  const key = new Uint8Array(pubRaw.subarray(0, 32));
  const si = boundaryAnchorSigningInput({ anchorId: "anchor-mag", anchoredAt: 1000, chainId: "chain-x", sequence: 0, chainHash: Z32T, keyId: "anchor-a", publicKey: key });
  assert.equal(si.ok, true);
  const siValue = (si as { ok: true; value: import("../src/compact.js").SigningInput }).value;
  const message = new Uint8Array(siValue.protectedSegment.length + 1 + siValue.payloadSegment.length);
  message.set(siValue.protectedSegment, 0);
  message[siValue.protectedSegment.length] = ".".charCodeAt(0);
  message.set(siValue.payloadSegment, siValue.protectedSegment.length + 1);
  const sig = new Uint8Array(nodeSign(null, message, privateKey));
  const compact = assembleCompact(siValue, sig);
  assert.equal(compact.ok, true);
  const comp = (compact as { ok: true; value: Uint8Array }).value;
  const fp = thumbprintRaw(jwkFromPublicKey(key));
  const expected = { anchorId: "anchor-mag", anchoredAt: 1000, chainId: "chain-x", sequence: 0, chainHash: Z32T, keyId: "anchor-a", keyFingerprint: fp };
  // Control: normal windows — the real signature verifies Ok.
  const rOk = verifyHistoricalAnchor(comp, { keyId: "anchor-a", publicKey: key, validFrom: 0, validBefore: 2000 }, expected as never);
  assert.equal(rOk.ok, true, "control: the signed anchor verifies at normal windows");
  // Huge bounded validBefore (2^62): membership holds; only the magnitude gate fires.
  const rBad = verifyHistoricalAnchor(comp, { keyId: "anchor-a", publicKey: key, validFrom: 0, validBefore: 4611686018427387904 }, expected as never);
  assert.equal(rBad.ok, false, "out-of-magnitude bounded valid_before must reject");
});

test("bounds-parity: the validFrom magnitude half rejects at verify (delta)", () => {
  // The runtime-generated key fixture; the NEGATIVE out-of-magnitude validFrom
  // (membership holds; the unsigned-abs symmetry fires).
  const { generateKeyPairSync, sign: nodeSign } = crypto as typeof import("node:crypto");
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const jwk = publicKey.export({ format: "jwk" }) as { x: string };
  const key = new Uint8Array(Buffer.from(jwk.x, "base64url").subarray(0, 32));
  const si = boundaryAnchorSigningInput({ anchorId: "anchor-mag2", anchoredAt: 1000, chainId: "chain-x", sequence: 0, chainHash: Z32T, keyId: "anchor-a", publicKey: key });
  const siValue = (si as { ok: true; value: import("../src/compact.js").SigningInput }).value;
  const message = new Uint8Array(siValue.protectedSegment.length + 1 + siValue.payloadSegment.length);
  message.set(siValue.protectedSegment, 0);
  message[siValue.protectedSegment.length] = ".".charCodeAt(0);
  message.set(siValue.payloadSegment, siValue.protectedSegment.length + 1);
  const sig = new Uint8Array(nodeSign(null, message, privateKey));
  const compact = assembleCompact(siValue, sig);
  const comp = (compact as { ok: true; value: Uint8Array }).value;
  const expected = { anchorId: "anchor-mag2", anchoredAt: 1000, chainId: "chain-x", sequence: 0, chainHash: Z32T, keyId: "anchor-a", keyFingerprint: thumbprintRaw(jwkFromPublicKey(key)) };
  assert.equal(verifyHistoricalAnchor(comp, { keyId: "anchor-a", publicKey: key, validFrom: 0, validBefore: 2000 }, expected as never).ok, true);
  assert.equal(verifyHistoricalAnchor(comp, { keyId: "anchor-a", publicKey: key, validFrom: -4611686018427387904, validBefore: 2000 }, expected as never).ok, false);
});

test("bounds-parity: fractional/NaN key-validity endpoints reject at verify (cross-vendor)", () => {
  const { generateKeyPairSync, sign: nodeSign } = crypto as typeof import("node:crypto");
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const jwk = publicKey.export({ format: "jwk" }) as { x: string };
  const key = new Uint8Array(Buffer.from(jwk.x, "base64url").subarray(0, 32));
  const si = boundaryAnchorSigningInput({ anchorId: "anchor-int", anchoredAt: 1000, chainId: "chain-x", sequence: 0, chainHash: Z32T, keyId: "anchor-a", publicKey: key });
  const siValue = (si as { ok: true; value: import("../src/compact.js").SigningInput }).value;
  const message = new Uint8Array(siValue.protectedSegment.length + 1 + siValue.payloadSegment.length);
  message.set(siValue.protectedSegment, 0);
  message[siValue.protectedSegment.length] = ".".charCodeAt(0);
  message.set(siValue.payloadSegment, siValue.protectedSegment.length + 1);
  const sig = new Uint8Array(nodeSign(null, message, privateKey));
  const comp = (assembleCompact(siValue, sig) as { ok: true; value: Uint8Array }).value;
  const expected = { anchorId: "anchor-int", anchoredAt: 1000, chainId: "chain-x", sequence: 0, chainHash: Z32T, keyId: "anchor-a", keyFingerprint: thumbprintRaw(jwkFromPublicKey(key)) };
  for (const bad of [0.5, NaN, -0.5]) {
    const r = verifyHistoricalAnchor(comp, { keyId: "anchor-a", publicKey: key, validFrom: bad, validBefore: 2000 }, expected as never);
    assert.equal(r.ok, false, `validFrom ${bad} must reject`);
  }
  const r2 = verifyHistoricalAnchor(comp, { keyId: "anchor-a", publicKey: key, validFrom: 0, validBefore: 2000.5 }, expected as never);
  assert.equal(r2.ok, false, "fractional validBefore must reject");
});
