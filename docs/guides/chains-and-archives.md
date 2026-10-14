# Consumption chains and archives

A resource that executes authorized requests can record each execution as a row in a hash chain,
sign the chain's ends with **boundary anchors**, and package a range of rows, its anchors and any
key handovers into one **anchored export** that a third party can verify offline years later. This
package builds and checks every one of those byte formats; storing rows, choosing what a
commitment covers, and keeping archive keys are the host's job. Every sample runs as written on
Node.js.

## Consumption rows

A row is the canonical JSON object
`{"chain_id","commitment","previous","sequence","v"}`. `commitment` is 32 bytes you choose, for
example a SHA-256 over your own record of the execution; the protocol treats it as opaque, so keep
its preimage private. `previous` is the hash of the preceding row, and the first row
(`sequence: 1`) uses 32 zero bytes. A row's hash is `SHA-256("BAP1-CHAIN\0" || row bytes)`
(`ROW_PREFIX` holds the prefix bytes).

`encodeConsumptionEntry` produces the exact row bytes and hash. `checkChain` takes a contiguous
range of raw rows and the range you expect (chain id, first and last sequence, count, the hash
before the range and the head hash after it) and re-derives every link.

```ts
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { checkChain, encodeConsumptionEntry } from "@bounded-authority-protocol/verifier";

const chainId = "ledger:documents";
const zero = new Uint8Array(32);
const rows: Uint8Array[] = [];
const hashes: Uint8Array[] = [];
let previousHash: Uint8Array = zero;
for (let sequence = 1; sequence <= 4; sequence++) {
  const commitment = createHash("sha256").update(`execution record ${sequence}`).digest();
  const entry = encodeConsumptionEntry({ chainId, sequence, previousHash, commitment });
  assert.ok(entry.ok);
  rows.push(entry.value.bytes);
  hashes.push(entry.value.hash);
  previousHash = entry.value.hash;
}

// The whole chain, from genesis.
const whole = { chainId, firstSequence: 1, lastSequence: 4, rowCount: 4, previousHash: zero, lastHash: hashes[3]! };
const facts = checkChain({ rows, ...whole }, whole);
assert.ok(facts.ok);
assert.equal(facts.value.verification, "boundary_consistent");

// Any contiguous range: rows 2 to 4 hang off the hash of row 1.
const tail = { chainId, firstSequence: 2, lastSequence: 4, rowCount: 3, previousHash: hashes[0]!, lastHash: hashes[3]! };
assert.ok(checkChain({ rows: rows.slice(1), ...tail }, tail).ok);

// Reordered rows, a dropped row, or a wrong head all reject.
assert.deepEqual(checkChain({ rows: [rows[0]!, rows[2]!, rows[1]!, rows[3]!], ...whole }, whole), { ok: false });
assert.deepEqual(checkChain({ rows: rows.slice(0, 3), ...whole, rowCount: 3 }, { ...whole, rowCount: 3 }), { ok: false });
assert.deepEqual(checkChain({ rows, ...whole }, { ...whole, lastHash: hashes[2]! }), { ok: false });
```

`checkChain` returns `ChainFacts` with `trust: "not_evaluated"`: consistent links prove the rows
belong together, not who wrote them. Signatures come from anchors.

## Boundary anchors

An anchor signs one point of a chain: its chain id, a sequence number and the chain hash at that
sequence, with the anchor id and time, under an archive key. Sequence 0 is the start of the chain
and requires the all-zero hash. `verifyHistoricalAnchor` takes the archive key as a
`HistoricalPublicKey` (key id, raw key and validity window `[validFrom, validBefore)`) and checks
the signature, every expected value, the key's derived fingerprint, and that `anchoredAt` is inside
the key's window.

## Anchored exports

An anchored export is one byte string: the `BAP1-ARCHIVE\0EXPORT\0` prefix, then length-framed
entries for a header, the start anchor, each key transition in order, each row, and the end anchor.
`encodeAnchoredExport` checks every component and produces the archive and its SHA-256 digest.
`verifyAnchoredExport` takes the stored archive as a list of chunks (any split, for example the
parts of a multipart object), the archive keys in order, and the expected context, and verifies the
digest, both anchors, every transition and every row.

The sample below records three executions, anchors the start with key A, hands over to key B, and
anchors the end with key B.

```ts
import assert from "node:assert/strict";
import { createHash, generateKeyPairSync, sign, type KeyObject } from "node:crypto";
import {
  assembleCompact, boundaryAnchorSigningInput, encodeAnchoredExport, encodeConsumptionEntry,
  keyTransitionSigningInput, publicKeyThumbprintRaw, verifyAnchoredExport, verifyHistoricalAnchor,
  type HistoricalPublicKey, type Result, type SigningInput,
} from "@bounded-authority-protocol/verifier";

const raw = (key: KeyObject): Uint8Array => Buffer.from(key.export({ format: "jwk" }).x!, "base64url");
function signCompact(input: Result<SigningInput>, privateKey: KeyObject): Uint8Array {
  assert.ok(input.ok);
  const message = Buffer.concat([input.value.protectedSegment, Buffer.from("."), input.value.payloadSegment]);
  const compact = assembleCompact(input.value, sign(null, message, privateKey));
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
const a = generateKeyPairSync("ed25519");
const b = generateKeyPairSync("ed25519");
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

// Encode. In major 1 the export context also has digest and objectVersion members, which encoding
// does not read (the v2 and v3 namespaces split the two contexts); any placeholder will do here.
const encoded = encodeAnchoredExport(
  { rows, startAnchor, endAnchor, transitions: [transition], ...chain },
  { chain, digest: zero, objectVersion: "unused", startAnchor: expectedStart, endAnchor: expectedEnd, transitions: [expectedTransition] },
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
```

What `verifyAnchoredExport` requires, beyond the digest and the per-piece checks:

- `keys` has exactly one more entry than there are transitions; the start anchor verifies under
  `keys[0]`, each transition `i` under `keys[i]` handing over to `keys[i + 1]`, and the end anchor
  under the last key;
- transition times strictly increase after the start anchor's time, no key fingerprint repeats,
  and the end anchor is at or after the last transition (with no transitions, the start and end
  anchors use the same key and the end is not earlier than the start);
- the start anchor sits at `firstSequence - 1` with the chain's `previousHash`, and the end anchor
  at `lastSequence` with its `lastHash`;
- the stored object's `version` equals `objectVersion` exactly. The version is out-of-band context
  from your object store (for example an object version id); it is not inside the archive.

The returned `AnchoredExportFacts` carries `trust` and `authorization` both `"not_evaluated"`:
whether the archive keys were the right ones to trust remains your decision.

## Limits

Rows are at most 4,096 bytes each and a chain range at most 65,536 rows; anchors and transitions at
most 8,192 bytes; an export at most 256 transitions, 65,796 chunks and 270,820,384 bytes. All of
these can be tightened per call with `boundsNew` (see the [reference](../reference.md#bounds)). For
an export, the nested `chain`, anchor and transition contexts must resolve to the same limits as
`expected.bounds`: with no tightening, leave every `bounds` unset; when you tighten, set the same
`Bounds` value on `expected` and on each nested context. Any difference rejects.
