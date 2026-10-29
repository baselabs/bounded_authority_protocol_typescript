// Producer-canonicality refusals (erratum 3, REQ1-SIGNING-ed25519-producer-canonical,
// REQ2-SIGNING-ed25519-producer-canonical, REQ3-SIGNING-producer-canonical): every producer
// surface — compact assembly for contract-majors 1, 2 and 3 and the three sibling profiles,
// anchored-export encoding for majors 1, 2 and 3 — frames a signature and verifies none, and
// MUST refuse a signature that no conforming signer emits, never rewriting accepted bytes.
//
// Ed25519 (majors 1 and 2, local loopback, role attestation, content assertion): S >= L, or R
// non-canonical (y >= p, or the sign bit set on an x = 0 point), or R of small order.
// ES256 (major 3): r or s outside 0 < r < n, 0 < s <= floor(n/2).
//
// The certified vectors live in the vendored bap-producer-canonicality/1 corpus
// (conformance:producer-canonicality, 75 cases); this file is the rule matrix with independent
// fixtures — one leg per refusal clause per suite, the exact-bound accepts with byte-equality,
// a real-signature positive control per surface, and the export-encode gates over locally
// built archives.
//
// Defect-injection record (at authoring, the battery's discipline): removing the
// assemble_segments Ed25519 gate turned 7 tests here red and the corpus runner disagreed at
// assemble-v1-grant-s-equals-l; removing the v3 assemble_compact ES256 gate turned 4 red
// (corpus disagreement at assemble-v3-grant-r-zero); removing the v1 encodeAnchoredExport
// canonical-signature gate turned the v1 export leg red. Each was restored and re-run green.
import { test } from "node:test";
import assert from "node:assert/strict";
import nodeCrypto from "node:crypto";

import * as v1 from "../src/v1.js";
import * as v2 from "../src/v2.js";
import * as v3 from "../src/v3.js";
import * as roleAttestation from "../src/role_attestation.js";
import * as contentAssertion from "../src/content_assertion.js";
import { base64urlDecode, base64urlEncode } from "../src/base64url.js";
import { strUtf8, utf8Str } from "../src/json.js";
import { thumbprintRaw, jwkFromPublicKey } from "../src/jwk.js";
import type { SigningInput } from "../src/compact.js";

// ---- Ed25519 constants (little-endian wire order) ----

const L = 0x1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3edn;
const P = 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffedn;

const le = (v: bigint): Uint8Array => {
  const out = new Uint8Array(32);
  let x = v;
  for (let i = 0; i < 32; i++) {
    out[i] = Number(x & 0xffn);
    x >>= 8n;
  }
  return out;
};

const be = (v: bigint): Uint8Array => {
  const out = new Uint8Array(32);
  let x = v;
  for (let i = 31; i >= 0; i--) {
    out[i] = Number(x & 0xffn);
    x >>= 8n;
  }
  return out;
};

// ---- P-256 constants (big-endian wire order) ----

const N = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n;
const HALF_N = (N - 1n) / 2n; // floor(n / 2); N is odd

const utf8 = (b: Uint8Array) => utf8Str(b);

// ---- key and signature fixtures ----

function edKey(): { publicKey: Uint8Array; privateKey: nodeCrypto.KeyObject } {
  const { publicKey, privateKey } = nodeCrypto.generateKeyPairSync("ed25519");
  const raw = new Uint8Array(publicKey.export({ type: "spki", format: "der" }).subarray(-32));
  return { publicKey: raw, privateKey };
}

const edSign = (message: Uint8Array, key: nodeCrypto.KeyObject): Uint8Array =>
  new Uint8Array(nodeCrypto.sign(null, Buffer.from(message), key));

const messageOf = (si: SigningInput): Uint8Array =>
  strUtf8(`${utf8(si.protectedSegment)}.${utf8(si.payloadSegment)}`);

// Frame a compact directly (protected.payload.base64url(signature)), independent of the
// producer surface under test.
const frame = (si: SigningInput, sig: Uint8Array): Uint8Array =>
  strUtf8(`${utf8(si.protectedSegment)}.${utf8(si.payloadSegment)}.${utf8(base64urlEncode(sig))}`);

function ecKey(): { publicKey: Uint8Array; privateKey: nodeCrypto.KeyObject } {
  const { publicKey, privateKey } = nodeCrypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
  const { x, y } = publicKey.export({ format: "jwk" }) as { x: string; y: string };
  const raw = new Uint8Array(Buffer.concat([Buffer.from([4]), Buffer.from(x, "base64url"), Buffer.from(y, "base64url")]));
  return { publicKey: raw, privateKey };
}

const ecSignLowS = (message: Uint8Array, key: nodeCrypto.KeyObject): Uint8Array => {
  const sig = new Uint8Array(nodeCrypto.sign("sha256", Buffer.from(message), { key, dsaEncoding: "ieee-p1363" }));
  const s = BigInt(`0x${Buffer.from(sig.subarray(32)).toString("hex")}`);
  if (s <= HALF_N) return sig;
  const out = sig.slice();
  out.set(be(N - s), 32);
  return out;
};

const edHolder = edKey();
const edIssuer = edKey();
const edThumb = utf8(base64urlEncode(thumbprintRaw(jwkFromPublicKey(edHolder.publicKey))));

const v1Grant = v1.grantSigningInput({
  keyId: "issuer", issuer: "https://issuer.example.test", grantId: "urn:example:grant:pc-1",
  audiences: ["https://resource.example.test"], issuedAt: 1000, notBefore: 1000, expiresAt: 2000,
  holderThumbprint: edThumb,
  operations: [{ name: "read", selectors: ["all"] }],
});
if (!v1Grant.ok) throw new Error("v1 grant signing input failed");

// A REAL signature over the v1 grant: its R is canonical and not of small order, its S < L.
const honestEd = edSign(messageOf(v1Grant.value), edIssuer.privateKey);
const edWithS = (s: bigint): Uint8Array => {
  const out = honestEd.slice();
  out.set(le(s), 32);
  return out;
};
const edWithR = (r: Uint8Array): Uint8Array => {
  const out = honestEd.slice();
  out.set(r, 0);
  return out;
};

const ecHolder = ecKey();
const ecIssuer = ecKey();
const ecThumb = utf8(base64urlEncode(v3.thumbprintRaw(v3.jwkFromPublicKey(ecHolder.publicKey))));

const v3Grant = v3.grantSigningInput({
  keyId: "issuer", issuer: "https://issuer.example.test", grantId: "urn:example:grant:pc-3",
  audiences: ["https://resource.example.test"], issuedAt: 1000, notBefore: 1000, expiresAt: 2000,
  holderThumbprint: ecThumb,
  operations: [{ name: "transfer", selectors: [{ kind: "lte", path: ["amount"], value: { t: "int", v: 50 } }] }],
});
if (!v3Grant.ok) throw new Error("v3 grant signing input failed");

const honestEc = ecSignLowS(messageOf(v3Grant.value), ecIssuer.privateKey);
const ecWithR = (r: bigint): Uint8Array => {
  const out = honestEc.slice();
  out.set(be(r), 0);
  return out;
};
const ecWithS = (s: bigint): Uint8Array => {
  const out = honestEc.slice();
  out.set(be(s), 32);
  return out;
};

// ==== 1. The Ed25519 rule matrix on the v1 assembler ====

test("producer: v1 assembleCompact refuses S = L and S > L, accepts S = L - 1 unchanged (exact bound)", () => {
  assert.equal(v1.assembleCompact(v1Grant.value, edWithS(L)).ok, false, "S = L must refuse");
  assert.equal(v1.assembleCompact(v1Grant.value, edWithS(L + 1n)).ok, false, "S = L + 1 must refuse");
  assert.equal(v1.assembleCompact(v1Grant.value, edWithS(2n * L)).ok, false, "S = 2L must refuse");
  const bound = edWithS(L - 1n);
  const r = v1.assembleCompact(v1Grant.value, bound);
  assert.equal(r.ok, true, "S = L - 1 must assemble");
  if (r.ok) {
    assert.equal(utf8(r.value), utf8(frame(v1Grant.value, bound)), "accepted bytes emitted unchanged");
  }
});

test("producer: v1 assembleCompact refuses a small-order R (identity and order-2 points)", () => {
  const identity = new Uint8Array(32); identity[0] = 1; // 01 00..00, order 1
  const order2 = new Uint8Array(32).fill(0xff); order2[0] = 0xec; order2[31] = 0x7f; // order 2
  assert.equal(v1.assembleCompact(v1Grant.value, edWithR(identity)).ok, false, "identity R must refuse");
  assert.equal(v1.assembleCompact(v1Grant.value, edWithR(order2)).ok, false, "order-2 R must refuse");
});

test("producer: v1 assembleCompact refuses a non-canonical R (y >= p, and the x=0 sign bit)", () => {
  assert.equal(v1.assembleCompact(v1Grant.value, edWithR(le(P))).ok, false, "R = p must refuse");
  const pSigned = le(P); pSigned[31]! |= 0x80;
  assert.equal(v1.assembleCompact(v1Grant.value, edWithR(pSigned)).ok, false, "R = p with sign bit must refuse");
  const oneSigned = le(1n); oneSigned[31]! |= 0x80; // y = 1 is an x = 0 point; the sign bit is not canonical
  assert.equal(v1.assembleCompact(v1Grant.value, edWithR(oneSigned)).ok, false, "y = 1 with sign bit must refuse");
});

test("producer: v1 assembleCompact accepts and re-emits a real signature (positive control)", () => {
  const r = v1.assembleCompact(v1Grant.value, honestEd);
  assert.equal(r.ok, true, "an honest signature must assemble");
  if (r.ok) {
    assert.equal(utf8(r.value), utf8(frame(v1Grant.value, honestEd)));
  }
});

// ==== 2. The ES256 rule matrix on the v3 assembler ====

test("producer: v3 assembleCompact refuses r = 0 and r = n", () => {
  assert.equal(v3.assembleCompact(v3Grant.value, ecWithR(0n)).ok, false, "r = 0 must refuse");
  assert.equal(v3.assembleCompact(v3Grant.value, ecWithR(N)).ok, false, "r = n must refuse");
});

test("producer: v3 assembleCompact refuses s = 0 and s = n", () => {
  assert.equal(v3.assembleCompact(v3Grant.value, ecWithS(0n)).ok, false, "s = 0 must refuse");
  assert.equal(v3.assembleCompact(v3Grant.value, ecWithS(N)).ok, false, "s = n must refuse");
});

test("producer: v3 assembleCompact refuses s = floor(n/2) + 1, accepts s = floor(n/2) unchanged (exact bound)", () => {
  assert.equal(v3.assembleCompact(v3Grant.value, ecWithS(HALF_N + 1n)).ok, false, "s = floor(n/2) + 1 must refuse");
  const bound = ecWithS(HALF_N);
  const r = v3.assembleCompact(v3Grant.value, bound);
  assert.equal(r.ok, true, "s = floor(n/2) must assemble");
  if (r.ok) {
    assert.equal(utf8(r.value), utf8(frame(v3Grant.value, bound)), "accepted bytes emitted unchanged");
  }
});

test("producer: v3 assembleCompact refuses the high-S twin of a real low-S signature", () => {
  const s = BigInt(`0x${Buffer.from(honestEc.subarray(32)).toString("hex")}`);
  if (s === 0n || s >= N) throw new Error("fixture signature s out of range");
  if (s > HALF_N) throw new Error("fixture signature is not low-S");
  const highS = honestEc.slice();
  highS.set(be(N - s), 32);
  // The twin verifies under raw ECDSA (the corpus's construction); the producer must still refuse it.
  assert.equal(v3.assembleCompact(v3Grant.value, highS).ok, false, "the high-S twin must refuse");
  assert.equal(v3.assembleCompact(v3Grant.value, honestEc).ok, true, "the low-S original must assemble");
});

// ==== 3. Wiring: every Ed25519 producer surface refuses S = L (its honest control assembles) ====

test("producer: v2 assembleCompact refuses S = L", () => {
  const si = v2.grantSigningInput({
    keyId: "issuer", issuer: "https://issuer.example.test", grantId: "urn:example:grant:pc-2",
    audiences: ["https://resource.example.test"], issuedAt: 1000, notBefore: 1000, expiresAt: 2000,
    holderThumbprint: edThumb,
    operations: [{ name: "read", selectors: ["all"] }],
  });
  if (!si.ok) throw new Error("v2 grant signing input failed");
  const honest = edSign(messageOf(si.value), edIssuer.privateKey);
  const bad = honest.slice(); bad.set(le(L), 32);
  assert.equal(v2.assembleCompact(si.value, bad).ok, false, "v2 S = L must refuse");
  assert.equal(v2.assembleCompact(si.value, honest).ok, true, "v2 honest control");
});

test("producer: local-loopback assembly refuses S = L", () => {
  const si = v1.localLoopbackHttpProofSigningInput({
    holderPublicKey: edHolder.publicKey, proofId: "urn:example:proof:pc-l", method: "POST",
    targetUri: "http://127.0.0.1:8080/invoke", issuedAt: 1400,
    invocationId: "550e8400-e29b-41d4-a716-446655440000", operation: "read",
    grantCompact: frame(v1Grant.value, honestEd), castArguments: { t: "null" },
    nonce: "nonce-pc-1",
  });
  if (!si.ok) throw new Error(`loopback signing input failed: ${JSON.stringify(si)}`);
  const honest = edSign(messageOf(si.value), edHolder.privateKey);
  const bad = honest.slice(); bad.set(le(L), 32);
  assert.equal(v1.assembleLocalLoopbackHttpCompact(si.value, bad).ok, false, "loopback S = L must refuse");
  assert.equal(v1.assembleLocalLoopbackHttpCompact(si.value, honest).ok, true, "loopback honest control");
});

test("producer: role-attestation assembly refuses S = L", () => {
  const si = roleAttestation.attestationSigningInput({
    keyId: "attestor", jti: "urn:example:attestation:pc-1", subjectKeyId: "subject",
    subjectPublicKey: edHolder.publicKey, role: "holder", notBefore: 1000, expiresAt: 2000,
  });
  if (!si.ok) throw new Error("attestation signing input failed");
  const honest = edSign(messageOf(si.value), edIssuer.privateKey);
  const bad = honest.slice(); bad.set(le(L), 32);
  assert.equal(roleAttestation.assembleAttestationCompact(si.value, bad).ok, false, "attestation S = L must refuse");
  assert.equal(roleAttestation.assembleAttestationCompact(si.value, honest).ok, true, "attestation honest control");
});

test("producer: content-assertion assembly refuses S = L", () => {
  const si = contentAssertion.assertionSigningInput({
    attestorKeyId: "attestor", jti: "urn:example:assertion:pc-1",
    iss: "https://issuer.example.test", aud: "https://resource.example.test",
    sub: "urn:example:subject:pc-1", profile: "https://profiles.example.test/pc/v1",
    profileDigest: new Uint8Array(32).fill(3), contentDigest: new Uint8Array(32).fill(5),
    gen: 1, prev: new Uint8Array(32), iat: 1000, nbf: 1000, exp: 2000,
  });
  if (!si.ok) throw new Error("assertion signing input failed");
  const honest = edSign(messageOf(si.value), edIssuer.privateKey);
  const bad = honest.slice(); bad.set(le(L), 32);
  assert.equal(contentAssertion.assembleCompact(si.value, bad).ok, false, "assertion S = L must refuse");
  assert.equal(contentAssertion.assembleCompact(si.value, honest).ok, true, "assertion honest control");
});

// ==== 4. Anchored-export encoding refuses a non-canonical framed signature ====

// Rebuild a compact with a replaced signature, bypassing the (refusing) producer surface: the
// export encoder receives compacts as bytes, and its own gate must do the refusing.
const reframe = (compact: Uint8Array, signature: Uint8Array): Uint8Array => {
  const parts = utf8(compact).split(".");
  return strUtf8(`${parts[0]}.${parts[1]}.${utf8(base64urlEncode(signature))}`);
};
const signatureOf = (compact: Uint8Array): Uint8Array => base64urlDecode(strUtf8(utf8(compact).split(".")[2]!));
const withSL = (compact: Uint8Array): Uint8Array => {
  const sig = signatureOf(compact).slice();
  sig.set(le(L), 32);
  return reframe(compact, sig);
};
const withIdentityR = (compact: Uint8Array): Uint8Array => {
  const sig = signatureOf(compact).slice();
  sig.set(le(1n), 0); // the identity encoding 01 00..00
  return reframe(compact, sig);
};

interface ArchiveFixture {
  readonly input: Parameters<typeof v1.encodeAnchoredExport>[0];
  readonly expected: Parameters<typeof v1.encodeAnchoredExport>[1];
}

// v1/v2 share the Ed25519 suite; build each major's archive through that major's own producers.
function edArchive(major: typeof v1 | typeof v2, chainId: string, objectVersion: string): ArchiveFixture {
  const ka = edKey();
  const kb = edKey();
  const zero = new Uint8Array(32);
  const row = major.encodeConsumptionEntry({ chainId, sequence: 1, previousHash: zero, commitment: new Uint8Array(32).fill(7) });
  if (!row.ok) throw new Error("row encode failed");
  const lastHash = row.value.hash;
  const startSi = major.boundaryAnchorSigningInput({
    anchorId: `${chainId}-start`, anchoredAt: 1000, chainId, sequence: 0,
    chainHash: zero, keyId: "ka", publicKey: ka.publicKey,
  });
  if (!startSi.ok) throw new Error("start anchor signing input failed");
  const endSi = major.boundaryAnchorSigningInput({
    anchorId: `${chainId}-end`, anchoredAt: 2000, chainId, sequence: 1,
    chainHash: lastHash, keyId: "kb", publicKey: kb.publicKey,
  });
  if (!endSi.ok) throw new Error("end anchor signing input failed");
  const tSi = major.keyTransitionSigningInput({
    transitionId: `${chainId}-t1`, chainId, effectiveAt: 1500,
    currentKeyId: "ka", currentPublicKey: ka.publicKey, nextKeyId: "kb", nextPublicKey: kb.publicKey,
  });
  if (!tSi.ok) throw new Error("transition signing input failed");
  const fp = (k: Uint8Array) => thumbprintRaw(jwkFromPublicKey(k));
  const input = {
    rows: [row.value.bytes],
    startAnchor: frame(startSi.value, edSign(messageOf(startSi.value), ka.privateKey)),
    endAnchor: frame(endSi.value, edSign(messageOf(endSi.value), kb.privateKey)),
    transitions: [frame(tSi.value, edSign(messageOf(tSi.value), ka.privateKey))],
    chainId, firstSequence: 1, lastSequence: 1, rowCount: 1,
    previousHash: zero, lastHash,
  };
  const expected = {
    chain: { chainId, firstSequence: 1, lastSequence: 1, rowCount: 1, previousHash: zero, lastHash },
    digest: new Uint8Array(32), // the encode side computes the digest; the placeholder is never checked
    startAnchor: {
      anchorId: `${chainId}-start`, anchoredAt: 1000, chainId, sequence: 0,
      chainHash: zero, keyId: "ka", keyFingerprint: fp(ka.publicKey),
    },
    endAnchor: {
      anchorId: `${chainId}-end`, anchoredAt: 2000, chainId, sequence: 1,
      chainHash: lastHash, keyId: "kb", keyFingerprint: fp(kb.publicKey),
    },
    transitions: [{
      transitionId: `${chainId}-t1`, chainId, effectiveAt: 1500,
      currentKeyId: "ka", currentKeyFingerprint: fp(ka.publicKey),
      nextKeyId: "kb", nextKeyFingerprint: fp(kb.publicKey),
    }],
    objectVersion,
  };
  return { input, expected } as ArchiveFixture;
}

function ecArchiveV3(): { input: Parameters<typeof v3.encodeAnchoredExport>[0]; expected: Parameters<typeof v3.encodeAnchoredExport>[1] } {
  const ka = ecKey();
  const kb = ecKey();
  const zero = new Uint8Array(32);
  const chainId = "urn:example:chain:pc3";
  const row = v3.encodeConsumptionEntry({ chainId, sequence: 1, previousHash: zero, commitment: new Uint8Array(32).fill(7) });
  if (!row.ok) throw new Error("v3 row encode failed");
  const lastHash = row.value.hash;
  const startSi = v3.boundaryAnchorSigningInput({
    anchorId: `${chainId}-start`, anchoredAt: 1000, chainId, sequence: 0,
    chainHash: zero, keyId: "ka", publicKey: ka.publicKey,
  });
  if (!startSi.ok) throw new Error("v3 start anchor signing input failed");
  const endSi = v3.boundaryAnchorSigningInput({
    anchorId: `${chainId}-end`, anchoredAt: 2000, chainId, sequence: 1,
    chainHash: lastHash, keyId: "kb", publicKey: kb.publicKey,
  });
  if (!endSi.ok) throw new Error("v3 end anchor signing input failed");
  const tSi = v3.keyTransitionSigningInput({
    transitionId: `${chainId}-t1`, chainId, effectiveAt: 1500,
    currentKeyId: "ka", currentPublicKey: ka.publicKey, nextKeyId: "kb", nextPublicKey: kb.publicKey,
  });
  if (!tSi.ok) throw new Error("v3 transition signing input failed");
  const fp = (k: Uint8Array) => v3.thumbprintRaw(v3.jwkFromPublicKey(k));
  const input = {
    rows: [row.value.bytes],
    startAnchor: frame(startSi.value, ecSignLowS(messageOf(startSi.value), ka.privateKey)),
    endAnchor: frame(endSi.value, ecSignLowS(messageOf(endSi.value), kb.privateKey)),
    transitions: [frame(tSi.value, ecSignLowS(messageOf(tSi.value), ka.privateKey))],
    chainId, firstSequence: 1, lastSequence: 1, rowCount: 1,
    previousHash: zero, lastHash,
  };
  const expected = {
    chain: { chainId, firstSequence: 1, lastSequence: 1, rowCount: 1, previousHash: zero, lastHash },
    startAnchor: {
      anchorId: `${chainId}-start`, anchoredAt: 1000, chainId, sequence: 0,
      chainHash: zero, keyId: "ka", keyFingerprint: fp(ka.publicKey),
    },
    endAnchor: {
      anchorId: `${chainId}-end`, anchoredAt: 2000, chainId, sequence: 1,
      chainHash: lastHash, keyId: "kb", keyFingerprint: fp(kb.publicKey),
    },
    transitions: [{
      transitionId: `${chainId}-t1`, chainId, effectiveAt: 1500,
      currentKeyId: "ka", currentKeyFingerprint: fp(ka.publicKey),
      nextKeyId: "kb", nextKeyFingerprint: fp(kb.publicKey),
    }],
  };
  return { input: input as Parameters<typeof v3.encodeAnchoredExport>[0], expected: expected as Parameters<typeof v3.encodeAnchoredExport>[1] };
}

test("producer: v1 encodeAnchoredExport refuses S = L on the start anchor and a small-order R on the transition", () => {
  const { input, expected } = edArchive(v1, "urn:example:chain:pc1", "v1");
  assert.equal(v1.encodeAnchoredExport(input, expected).ok, true, "the honest archive must encode (positive control)");
  assert.equal(v1.encodeAnchoredExport({ ...input, startAnchor: withSL(input.startAnchor) }, expected).ok, false, "start-anchor S = L must refuse");
  const identityTransitions = input.transitions.map((t, i) => (i === 0 ? withIdentityR(t) : t));
  assert.equal(v1.encodeAnchoredExport({ ...input, transitions: identityTransitions }, expected).ok, false, "transition identity R must refuse");
});

test("producer: v2 encodeAnchoredExport refuses S = L on the framed start anchor", () => {
  const { input, expected } = edArchive(v2, "urn:example:chain:pc2", "v2");
  assert.equal(v2.encodeAnchoredExport(input, expected).ok, true, "the honest v2 archive must encode (positive control)");
  assert.equal(v2.encodeAnchoredExport({ ...input, startAnchor: withSL(input.startAnchor) }, expected).ok, false, "v2 start-anchor S = L must refuse");
});

test("producer: v3 encodeAnchoredExport refuses the high-S twin on start anchor, end anchor and transition", () => {
  const { input, expected } = ecArchiveV3();
  assert.equal(v3.encodeAnchoredExport(input, expected).ok, true, "the honest v3 archive must encode (positive control)");
  const highTwin = (compact: Uint8Array): Uint8Array => {
    const sig = signatureOf(compact);
    const s = BigInt(`0x${Buffer.from(sig.subarray(32)).toString("hex")}`);
    if (s === 0n || s >= N) throw new Error("fixture signature s out of range");
    if (s > HALF_N) throw new Error("fixture is not low-S");
    const twin = sig.slice();
    twin.set(be(N - s), 32);
    return reframe(compact, twin);
  };
  assert.equal(v3.encodeAnchoredExport({ ...input, startAnchor: highTwin(input.startAnchor) }, expected).ok, false, "start-anchor high-S must refuse");
  assert.equal(v3.encodeAnchoredExport({ ...input, endAnchor: highTwin(input.endAnchor) }, expected).ok, false, "end-anchor high-S must refuse");
  const twinTransitions = input.transitions.map((t, i) => (i === 0 ? highTwin(t) : t));
  assert.equal(v3.encodeAnchoredExport({ ...input, transitions: twinTransitions }, expected).ok, false, "transition high-S must refuse");
});
