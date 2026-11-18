import assert from "node:assert/strict";
import { createHash, generateKeyPairSync, sign, type KeyObject } from "node:crypto";
import { v3, type Result, type SigningInput } from "@bounded-authority-protocol/verifier";
const { assembleCompact, boundaryAnchorSigningInput, encodeAnchoredExport, encodeConsumptionEntry, keyTransitionSigningInput, publicKeyThumbprintRaw, verifyAnchoredExport, verifyHistoricalAnchor } = v3;
type HistoricalPublicKey = v3.HistoricalPublicKey;

const raw = (key: KeyObject): Uint8Array => Buffer.concat([Buffer.from([4]), Buffer.from(key.export({ format: "jwk" }).x!, "base64url"), Buffer.from(key.export({ format: "jwk" }).y!, "base64url")]);
function lowSign(message: Uint8Array, privateKey: KeyObject): Uint8Array {
  const raw = sign("sha256", message, { key: privateKey, dsaEncoding: "ieee-p1363" });
  const n = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n;
  const s = BigInt("0x" + raw.subarray(32).toString("hex"));
  if (s > n / 2n) raw.set(Buffer.from((n - s).toString(16).padStart(64, "0"), "hex"), 32);
  return raw;
}
function signCompact(input: Result<SigningInput>, privateKey: KeyObject): Uint8Array {
  assert.ok(input.ok);
  const message = Buffer.concat([input.value.protectedSegment, Buffer.from("."), input.value.payloadSegment]);
  const compact = assembleCompact(input.value, lowSign(message, privateKey));
  assert.ok(compact.ok);
  return compact.value;
}

// Three rows.
const chainId = "audit:approvals";
const zero = new Uint8Array(32);
const rows: Uint8Array[] = [];
let head: Uint8Array = zero;
for (let sequence = 1; sequence <= 3; sequence++) {
  const commitment = createHash("sha256").update(`approval ${sequence}`).digest();
  const entry = encodeConsumptionEntry({ chainId, sequence, previousHash: head, commitment });
  assert.ok(entry.ok);
  rows.push(entry.value.bytes);
  head = entry.value.hash;
}

// Two archive keys with overlapping windows.
const a = generateKeyPairSync("ec", { namedCurve: "P-256" });
const b = generateKeyPairSync("ec", { namedCurve: "P-256" });
const keyA: HistoricalPublicKey = { keyId: "archive-a", publicKey: raw(a.publicKey), validFrom: 1_000, validBefore: 3_000 };
const keyB: HistoricalPublicKey = { keyId: "archive-b", publicKey: raw(b.publicKey), validFrom: 2_000, validBefore: null };
const fingerprintA = publicKeyThumbprintRaw(keyA.publicKey);
const fingerprintB = publicKeyThumbprintRaw(keyB.publicKey);

// The signed pieces: start anchor (key A), handover A to B, end anchor (key B).
const startAnchor = signCompact(boundaryAnchorSigningInput({
  anchorId: "anchor-0", anchoredAt: 1_500, chainId, sequence: 0, chainHash: zero, keyId: "archive-a", publicKey: keyA.publicKey,
}), a.privateKey);
const transition = signCompact(keyTransitionSigningInput({
  transitionId: "rotation-1", chainId, effectiveAt: 2_500, currentKeyId: "archive-a", currentPublicKey: keyA.publicKey,
  nextKeyId: "archive-b", nextPublicKey: keyB.publicKey,
}), a.privateKey);
const endAnchor = signCompact(boundaryAnchorSigningInput({
  anchorId: "anchor-3", anchoredAt: 2_600, chainId, sequence: 3, chainHash: head, keyId: "archive-b", publicKey: keyB.publicKey,
}), b.privateKey);

// What the verifier expects, from its own records.
const chain = { chainId, firstSequence: 1, lastSequence: 3, rowCount: 3, previousHash: zero, lastHash: head };
const expectedStart = { anchorId: "anchor-0", anchoredAt: 1_500, chainId, sequence: 0, chainHash: zero, keyId: "archive-a", keyFingerprint: fingerprintA };
const expectedEnd = { anchorId: "anchor-3", anchoredAt: 2_600, chainId, sequence: 3, chainHash: head, keyId: "archive-b", keyFingerprint: fingerprintB };
const expectedTransition = {
  transitionId: "rotation-1", chainId, effectiveAt: 2_500,
  currentKeyId: "archive-a", currentKeyFingerprint: fingerprintA, nextKeyId: "archive-b", nextKeyFingerprint: fingerprintB,
};

// A single anchor verifies on its own against its key.
const anchorFacts = verifyHistoricalAnchor(startAnchor, keyA, expectedStart);
assert.ok(anchorFacts.ok);
assert.equal(anchorFacts.value.verification, "signature_and_window");

// Encoding uses ExpectedExport; stored-object verification also binds digest and objectVersion.
const encoded = encodeAnchoredExport(
  { rows, startAnchor, endAnchor, transitions: [transition], ...chain },
  { chain, startAnchor: expectedStart, endAnchor: expectedEnd, transitions: [expectedTransition] },
);
assert.ok(encoded.ok);

// Store it (here: split into two chunks), then verify the stored object.
const archive = encoded.value.archive;
const stored = { chunks: [archive.subarray(0, 100), archive.subarray(100)], version: "object-version-7" };
const exported = verifyAnchoredExport(stored, { keys: [keyA, keyB] }, {
  chain, digest: encoded.value.digest, objectVersion: "object-version-7",
  startAnchor: expectedStart, endAnchor: expectedEnd, transitions: [expectedTransition],
});
assert.ok(exported.ok);
assert.equal(exported.value.rowCount, 3);
assert.equal(exported.value.transitionCount, 1);
assert.equal(exported.value.verification, "anchored_export");

// One flipped byte anywhere changes the digest and rejects.
const tampered = Buffer.from(archive);
tampered[tampered.length - 1] = tampered[tampered.length - 1]! ^ 1;
assert.deepEqual(
  verifyAnchoredExport({ chunks: [tampered], version: "object-version-7" }, { keys: [keyA, keyB] }, {
    chain, digest: encoded.value.digest, objectVersion: "object-version-7",
    startAnchor: expectedStart, endAnchor: expectedEnd, transitions: [expectedTransition],
  }),
  { ok: false },
);
