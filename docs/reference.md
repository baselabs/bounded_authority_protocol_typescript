# API reference

This page lists every export of `@bounded-authority-protocol/verifier` 0.7.0. The task guides show
the functions in context; every `ts` sample on this page and in the guides is typechecked and run
by the repository's test suite.

- [Conventions](#conventions)
- [Contract-major 1: the package root](#contract-major-1-the-package-root)
- [Local-loopback proof profile](#local-loopback-proof-profile)
- [Input types](#input-types)
- [Facts and decoded types](#facts-and-decoded-types)
- [Primitives](#primitives)
- [Bounds](#bounds)
- [Results and errors](#results-and-errors)
- [The `v2` namespace](#the-v2-namespace)
- [The `v3` namespace](#the-v3-namespace)
- [The `roleAttestation` namespace](#the-roleattestation-namespace)
- [The `contentAssertion` namespace](#the-contentassertion-namespace)

## Conventions

- **Results.** Unless a section says otherwise, a function returns `Result<T>`:
  `{ ok: true, value: T }` or the closed `{ ok: false }`, which carries no reason. "Rejects" below
  means it returns `{ ok: false }`. A thrown exception other than `InvalidError` is a bug, never a
  verdict ([Handle errors](guides/handle-errors.md)).
- **Bytes.** Compact JWS values, raw keys, signatures, digests and hashes are `Uint8Array`. A compact
  is its ASCII bytes. Raw Ed25519 keys are 32 bytes, raw P-256 keys 65 bytes, signatures 64 bytes,
  digests and fingerprints 32 bytes. Node's `Buffer` is a `Uint8Array` and is accepted.
- **Times** are integer seconds you supply. Nothing reads a clock.
- **Strings** such as issuers, audiences and ids compare exactly, byte for byte. Identifier fields
  must be RFC 7519 StringOrURI values (a bare string, or a URI with a valid scheme and authority)
  of at most 512 UTF-8 bytes; key ids (`kid`) are 1 to 128 characters from `A-Z a-z 0-9 . _ ~ -`.
- **Bounds.** Most functions take an optional `bounds` (or `expected.bounds`) that can only tighten
  the profile limits; see [Bounds](#bounds).
- **Signing inputs.** A producer returns a `SigningInput`; the bytes to sign are
  `protectedSegment`, one `.` byte, then `payloadSegment`. The package never signs.

## Contract-major 1: the package root

### `verifyGrant(compact, trusted, expected): Result<GrantFacts>`

Verifies a grant alone. `trusted` is a [`TrustedIssuer`](#trustedissuer); `expected` an
[`ExpectedGrant`](#expectedgrant). Rejects unless the header is exactly
`{alg: "EdDSA", kid, typ: "ba+cap"}` with `kid === trusted.keyId`, the payload is a valid major-1
grant, `iss === expected.issuer`, `aud` contains `expected.audience`, `iat < exp`, `nbf < exp`,
`iat` and `nbf` are at most `evaluationTime + clockSkew`, `exp > evaluationTime - clockSkew`, and
the signature verifies under `trusted.publicKey` (rule S1). Also rejects a non-integer
`evaluationTime`, a `clockSkew` outside 0 to 60 (or above a tightened `clock_skew`), and a trusted
key that is not an acceptable 32-byte key. Example: [Quickstart](../README.md#quickstart-issue-and-verify-a-grant).

### `checkEnvelope(grantCompact, proofCompact, expected): Result<EnvelopeFacts>`

Verifies a grant and a holder proof against one request. `expected` is an
[`ExpectedRequest`](#expectedrequest). Every check is listed in
[Verify requests](guides/verify-requests.md#what-checkenvelope-checks), which also has the example.

### `untrustedKeyLocator(compact, bounds?): Result<KeyLocator>`

Reads only the protected header of a grant and returns its `kid` with `trust: "not_evaluated"`.
Use it to select a trusted key, never as trust. Rejects unless the compact has three segments and
the protected segment decodes to exactly `{alg: "EdDSA", kid, typ: "ba+cap"}` with a valid `kid`;
the payload and signature segments are not read. Example: [Rotate keys](guides/rotate-keys.md#rotate-an-issuer-key).

### `decodeGrant(compact, bounds?): Result<GrantDecoded>`

Parses and validates a grant's structure and claims (closed header and payload, encodings,
coherent times) without checking the signature or any context. Returns
`verification: "not_evaluated"`. For display and debugging only. Example:
[Handle errors](guides/handle-errors.md#finding-why-a-request-rejects).

### `decodeProof(compact, bounds?): Result<ProofDecoded>`

Parses and validates a standard (`dpop+jwt`) holder proof without checking its signature or any
context. Returns the proof id and the holder key thumbprint with `verification: "not_evaluated"`.

### `requestDigest(operation, castArguments, bounds?): Result<Uint8Array>`

The 32-byte request digest a proof carries as `ba_req`:
`SHA-256("BAP1-REQUEST\0" || JCS([operation, typedProject(castArguments)]))`. `operation` must be
1 to 128 printable ASCII bytes. Rejects an operation or argument value over the limits (the typed
projection doubles nesting depth, so with the default `depth` of 32, objects in the arguments nest
at most 15 levels deep).

### `grantSigningInput(grant, bounds?): Result<SigningInput>`

Builds the exact signing input of a grant from a [`GrantProducer`](#grantproducer). The header is
`{alg: "EdDSA", kid, typ: "ba+cap"}` and the payload `{aud, cnf: {jkt}, exp, iat, iss, jti, nbf,
operations, v: 1}`, both JCS. Rejects an invalid `keyId`, a non-StringOrURI `issuer`, `grantId` or
audience, 0 or more than 64 audiences or operations, non-integer times, a `holderThumbprint` that
is not base64url of 32 bytes, an operation name that is not 1 to 128 printable ASCII bytes, and 0
or more than 64 selectors per operation, or a malformed selector. Example:
[Quickstart](../README.md#quickstart-issue-and-verify-a-grant).

### `proofSigningInput(proof, bounds?): Result<SigningInput>`

Builds the signing input of a standard holder proof from a [`ProofProducer`](#proofproducer). The
header carries the holder's public JWK; the payload binds `ath` (SHA-256 of `grantCompact`),
`ba_inv`, `ba_op`, `ba_req`, `htm`, `htu`, `iat`, `jti`, `v` and the optional `nonce`. Rejects an
unacceptable holder key, a method that is not an HTTP token of 1 to 32 bytes, a `targetUri` not
already in normal form, an `invocationId` that is not a lowercase RFC 4122 UUID (versions 1 to 5),
a `proofId` that is not StringOrURI, a non-integer `issuedAt`, an invalid operation, a `nonce` that
is empty, over 512 bytes or not well-formed Unicode, and a `grantCompact` that is not a bounded
three-segment compact. Example: [Verify requests](guides/verify-requests.md#the-full-flow).

### `assembleCompact(input, signature, bounds?): Result<Uint8Array>`

Joins a signing input and a 64-byte signature into a compact JWS, then re-parses the result
according to `input.kind` (`grant`, `proof`, `boundary_anchor` or `key_transition`) and rejects
anything the matching decoder would reject. It does not verify the signature. Takes a signature,
never a key or a signing callback.

### `boundaryAnchorSigningInput(anchor, bounds?): Result<SigningInput>`

Builds the signing input of a boundary anchor (`typ: "ba+chain-anchor"`) from a
[`BoundaryAnchorProducer`](#boundaryanchorproducer). The payload binds the anchor id and time, chain
id, sequence, chain hash and the RFC 7638 fingerprint of `publicKey`. Rejects an invalid key id or
identifier, a negative or non-integer sequence, a non-32-byte hash or key, an unacceptable key,
and sequence 0 with a non-zero chain hash. Example:
[Consumption chains and archives](guides/chains-and-archives.md#anchored-exports).

### `keyTransitionSigningInput(transition, bounds?): Result<SigningInput>`

Builds the signing input of a key transition (`typ: "ba+key-transition"`, `kid` = the current key
id) from a [`KeyTransitionProducer`](#keytransitionproducer). Rejects equal current and next keys,
invalid key ids or identifiers, a non-integer `effectiveAt`, and unacceptable keys. Example:
[Rotate keys](guides/rotate-keys.md#hand-over-an-archive-key-with-an-authenticated-transition).

### `verifyHistoricalAnchor(compact, key, expected): Result<AnchorFacts>`

Verifies a boundary anchor under one [`HistoricalPublicKey`](#historicalpublickey) and an
[`ExpectedAnchor`](#expectedanchor). Rejects unless the header `kid` and `expected.keyId` equal
`key.keyId`, every payload value equals the expected one, the key's derived fingerprint equals
`expected.keyFingerprint`, sequence 0 carries the all-zero hash, `validFrom <= anchoredAt <
validBefore` (no upper bound when `validBefore` is `null`), the compact is at most 8,192 bytes, and
the signature verifies. Example:
[Consumption chains and archives](guides/chains-and-archives.md#anchored-exports).

### `verifyKeyTransition(compact, oldKey, newKey, expected): Result<KeyTransitionFacts>`

Verifies that `oldKey` signed a handover to `newKey`; see
[Rotate keys](guides/rotate-keys.md#hand-over-an-archive-key-with-an-authenticated-transition) for
the checks and the example.

### `encodeConsumptionEntry(entry, bounds?): Result<EncodedConsumptionEntry>`

Encodes a [`ConsumptionEntry`](#consumptionentry) as its canonical row bytes and returns them with
the row hash `SHA-256("BAP1-CHAIN\0" || bytes)`. Rejects a sequence below 1, non-32-byte hashes, an
invalid chain id, a first row (`sequence: 1`) whose `previousHash` is not all zeros, and a row over
4,096 bytes. Example: [Consumption chains and archives](guides/chains-and-archives.md#consumption-rows).

### `checkChain(chain, expected): Result<ChainFacts>`

Verifies a contiguous range of raw rows ([`ChainInput`](#chaininput)) against an
[`ExpectedChain`](#expectedchain): equal chain ids, sequences and counts, `lastSequence =
firstSequence + rowCount - 1`, at least one and at most 65,536 rows, each row canonical and linked
to the previous hash, the first link equal to `previousHash` (all zeros when `firstSequence` is
1), and the last hash equal to `lastHash`. Example:
[Consumption chains and archives](guides/chains-and-archives.md#consumption-rows).

### `encodeAnchoredExport(input, expected): Result<EncodedAnchoredExport>`

Checks the rows, both anchors and every transition of an
[`AnchoredExportInput`](#anchoredexportinput) against an [`ExpectedExport`](#expectedexport), checks
the key path (each transition hands over from the previous key, times strictly increase, no
fingerprint repeats, the end anchor uses the last key), and frames the archive. Returns the archive
bytes and their SHA-256 digest. In major 1, `expected.digest` and `expected.objectVersion` are
required by the type but not read here. Rejects more than 256 transitions, 65,796 chunks or
270,820,384 bytes. Example: [Consumption chains and archives](guides/chains-and-archives.md#anchored-exports).

### `verifyAnchoredExport(archived, keyChain, expected): Result<AnchoredExportFacts>`

Verifies a stored archive ([`ArchivedObject`](#archivedobject-and-historicalkeychain), any chunking) under the ordered
archive keys ([`HistoricalKeyChain`](#archivedobject-and-historicalkeychain)) and an [`ExpectedExport`](#expectedexport):
the object version and digest, the framing to exact end of input, the header, both anchors, every
transition and every row. Example and the full list of checks:
[Consumption chains and archives](guides/chains-and-archives.md#anchored-exports).

## Local-loopback proof profile

The `bap-application-proof/local-loopback-http/1` profile lets a local development server accept
proofs for `http://127.0.0.1` or `http://[::1]` targets. Its proofs have `typ:
"ba+loopback-proof"`, always carry a nonce, and pair with an ordinary major-1 grant. The standard
proof functions reject them and these functions reject standard proofs.

| Function | Like | Differences |
|---|---|---|
| `localLoopbackHttpProofSigningInput(proof, bounds?)` | `proofSigningInput` | loopback `targetUri`; `nonce` required; `proofId` 1 to 512 bytes |
| `assembleLocalLoopbackHttpCompact(input, signature, bounds?)` | `assembleCompact` | accepts only `kind: "local_loopback_http_proof"` |
| `decodeLocalLoopbackHttpProof(compact, bounds?)` | `decodeProof` | loopback header and payload |
| `checkLocalLoopbackHttpEnvelope(grant, proof, expected)` | `checkEnvelope` | requires `nonce: { kind: "required", value }` and a loopback `targetUri` |
| `localLoopbackHttpUriNormalize(input, bounds?)` | `uriNormalize` | `http` scheme, host exactly `127.0.0.1` or `[::1]`, port 1 to 65535 with `:80` dropped |

```ts
import assert from "node:assert/strict";
import { generateKeyPairSync, randomUUID, sign, type KeyObject } from "node:crypto";
import {
  assembleCompact, assembleLocalLoopbackHttpCompact, checkEnvelope, checkLocalLoopbackHttpEnvelope,
  decodeLocalLoopbackHttpProof, decodeProof, grantSigningInput, jwkFromPublicKey,
  localLoopbackHttpProofSigningInput, localLoopbackHttpUriNormalize, strUtf8, thumbprint, utf8Str,
  type SigningInput, type Tagged,
} from "@bounded-authority-protocol/verifier";

const raw = (key: KeyObject): Uint8Array => Buffer.from(key.export({ format: "jwk" }).x!, "base64url");
const message = (i: SigningInput): Uint8Array => Buffer.concat([i.protectedSegment, Buffer.from("."), i.payloadSegment]);
const issuer = generateKeyPairSync("ed25519");
const holder = generateKeyPairSync("ed25519");

const normal = localLoopbackHttpUriNormalize(strUtf8("http://127.0.0.1:80/dev/./run"));
assert.ok(normal.ok);
assert.equal(utf8Str(normal.value), "http://127.0.0.1/dev/run");
assert.deepEqual(localLoopbackHttpUriNormalize(strUtf8("http://localhost:8080/")), { ok: false });

const g = grantSigningInput({
  keyId: "dev-issuer", issuer: "https://issuer.example", grantId: "grant-dev", audiences: ["http://127.0.0.1:8080"],
  issuedAt: 1_000, notBefore: 1_000, expiresAt: 9_000,
  holderThumbprint: thumbprint(jwkFromPublicKey(raw(holder.publicKey))),
  operations: [{ name: "build.run", selectors: ["all"] }],
});
assert.ok(g.ok);
const grant = assembleCompact(g.value, sign(null, message(g.value), issuer.privateKey));
assert.ok(grant.ok);

const castArguments: Tagged = { t: "object", v: new Map() };
const invocationId = randomUUID();
const p = localLoopbackHttpProofSigningInput({
  holderPublicKey: raw(holder.publicKey), proofId: "proof-dev-1", method: "POST",
  targetUri: "http://127.0.0.1:8080/build", issuedAt: 1_100, invocationId, operation: "build.run",
  grantCompact: grant.value, castArguments, nonce: "dev-nonce-1",
});
assert.ok(p.ok);
const proof = assembleLocalLoopbackHttpCompact(p.value, sign(null, message(p.value), holder.privateKey));
assert.ok(proof.ok);

const expected = {
  trustedIssuer: { keyId: "dev-issuer", publicKey: raw(issuer.publicKey) },
  issuer: "https://issuer.example", audience: "http://127.0.0.1:8080", method: "POST",
  targetUri: "http://127.0.0.1:8080/build", invocationId, operation: "build.run", castArguments,
  evaluationTime: 1_120, clockSkew: 60, proofMaxAge: 300, nonce: { kind: "required" as const, value: "dev-nonce-1" },
};
assert.ok(checkLocalLoopbackHttpEnvelope(grant.value, proof.value, expected).ok);
assert.deepEqual(checkEnvelope(grant.value, proof.value, expected), { ok: false }); // not a dpop+jwt proof
assert.equal(decodeLocalLoopbackHttpProof(proof.value).ok, true);
assert.deepEqual(decodeProof(proof.value), { ok: false });
```

## Input types

All input types are exported from the package root as TypeScript types. Every field is required
unless marked optional; `bounds` is always optional except where noted.

### `TrustedIssuer`

`{ keyId: string; publicKey: Uint8Array }`: the issuer key you trust, raw 32 bytes (65 in `v3`).

### `ExpectedGrant`

`{ issuer; audience; evaluationTime; clockSkew; bounds? }`. `issuer` and `audience` are exact
strings; `evaluationTime` integer seconds; `clockSkew` an integer from 0 to 60.

### `ExpectedRequest`

| Field | Type | Meaning |
|---|---|---|
| `trustedIssuer` | `TrustedIssuer` | the issuer key selected for this grant's `kid` |
| `issuer`, `audience` | `string` | the grant's `iss` must equal `issuer`; its `aud` must contain `audience` |
| `method` | `string` | the HTTP method, exact (case-sensitive) |
| `targetUri` | `string` | the request URI, already in normal form ([`uriNormalize`](#urinormalizeinput-bounds-resultuint8array)) |
| `invocationId` | `string` | the invocation id carried with the request |
| `operation` | `string` | the operation this endpoint performs |
| `castArguments` | `Tagged` | the arguments as your server parsed them |
| `evaluationTime` | `number` | integer seconds |
| `clockSkew` | `number` | integer, 0 to 60 |
| `proofMaxAge` | `number` | integer, 1 to 300 |
| `nonce` | `{ kind: "not_required" }` or `{ kind: "required"; value: string }` | the nonce policy |
| `bounds` | `Bounds` (optional) | tightened limits for the grant and the proof |

### `HistoricalPublicKey`

`{ keyId; publicKey; validFrom: number; validBefore: number | null }`: an archive or attestor key
with its validity window `[validFrom, validBefore)`; `null` means open-ended. Window values are
integers within 2^53 - 1, and `validBefore` must be greater than `validFrom`.

### `ExpectedAnchor`

`{ anchorId; anchoredAt; chainId; sequence; chainHash; keyId; keyFingerprint; bounds? }`, where
`chainHash` and `keyFingerprint` are raw 32 bytes.

### `ExpectedKeyTransition`

`{ transitionId; chainId; effectiveAt; currentKeyId; currentKeyFingerprint; nextKeyId;
nextKeyFingerprint; bounds? }`, fingerprints raw 32 bytes.

### `ConsumptionEntry`

`{ chainId; sequence; previousHash; commitment }`, the hashes raw 32 bytes.

### `ChainInput`

`{ rows: Uint8Array[]; chainId; firstSequence; lastSequence; rowCount; previousHash; lastHash }`:
raw canonical rows and the range they claim.

### `ExpectedChain`

`{ chainId; firstSequence; lastSequence; rowCount; previousHash; lastHash; bounds? }`.

### `SelectorInput` and `OperationInput`

`OperationInput` is `{ name: string; selectors: SelectorInput[] }`. A `SelectorInput` is `"all"`,
`{ kind: "all" }`, `{ kind: "equals"; path: string[]; value: Tagged }` or
`{ kind: "one_of"; path: string[]; values: Tagged[] }` (the `v2` and `v3` forms add `lte` and
`gte` with a numeric `value`). Paths have 1 to 32 segments of 1 to 128 bytes; `one_of` has 1 to
256 values.

### `GrantProducer`

`{ keyId; issuer; grantId; audiences: string[]; issuedAt; notBefore; expiresAt; holderThumbprint:
string; operations: OperationInput[] }`. `holderThumbprint` is the base64url RFC 7638 thumbprint of
the holder key (`thumbprint(jwkFromPublicKey(raw))`).

### `ProofProducer`

`{ holderPublicKey; proofId; method; targetUri; issuedAt; invocationId; operation; grantCompact;
castArguments; nonce? }`.

### `BoundaryAnchorProducer`

`{ anchorId; anchoredAt; chainId; sequence; chainHash; keyId; publicKey }`.

### `KeyTransitionProducer`

`{ transitionId; chainId; effectiveAt; currentKeyId; currentPublicKey; nextKeyId; nextPublicKey }`.

### `AnchoredExportInput`

`{ rows; startAnchor; endAnchor; transitions: Uint8Array[]; chainId; firstSequence; lastSequence;
rowCount; previousHash; lastHash }`: the raw rows and the anchor and transition compacts in order.

### `ExpectedExport`

`{ chain: ExpectedChain; digest; startAnchor: ExpectedAnchor; endAnchor: ExpectedAnchor;
transitions: ExpectedKeyTransition[]; objectVersion: string; bounds? }`. `digest` is the archive's
raw SHA-256 and `objectVersion` the stored object's version (both read only by
`verifyAnchoredExport` in major 1). The nested `bounds` must resolve to the same limits as
`expected.bounds`.

### `ArchivedObject` and `HistoricalKeyChain`

`ArchivedObject` is `{ chunks: Uint8Array[]; version: string }`: the stored archive in any number
of chunks (at least one) and the version your object store reports. `HistoricalKeyChain` is
`{ keys: HistoricalPublicKey[] }`, ordered from the start anchor's key to the end anchor's key.

### `SigningInput`, `EncodedConsumptionEntry`, `EncodedAnchoredExport`

`SigningInput` is `{ kind; protectedSegment: Uint8Array; payloadSegment: Uint8Array }` (the two
segments are base64url text bytes; `kind` names the artifact). `EncodedConsumptionEntry` is
`{ bytes; hash }`; `EncodedAnchoredExport` is `{ archive; digest }`.

## Facts and decoded types

Facts are plain readonly objects. They carry identifiers, times and digests, never arguments,
selector values, signatures, JWK containers or nonces, and none of them is a credential. No facts
type has an "allowed" or decision field.

New in 0.8.0 (unreleased): facts follow the profile's redaction rule ("fixed redacted rendering and
no generic encoder, string, or enumeration protocol"). Every field reads by name, unchanged. Every
generic rendering gives the fixed text `#BoundedAuthorityProtocol.V1.GrantFacts<redacted>` (with the
major and type; `RoleAttestation.V1.AttestationFacts` and `ContentAssertion.V1.ContentAssertionFacts`
for the sibling profiles), the Elixir reference's text: Node's, Deno's and Bun's inspection
(`console.log`, `util.inspect`), `String()`, template literals and `JSON.stringify`. Nothing
enumerates: `Object.keys`, `for...in` and spreading see no field. Facts are frozen. A decoded content
assertion is not a facts value: its fields stay enumerable and only its inspection is redacted.

To log or store facts, copy the fields you need by name, for example
`const { grantId, invocationId } = envelopeFacts` (a rest element `...rest` captures nothing).

```ts since=0.8.0
import assert from "node:assert/strict";
import { generateKeyPairSync, sign } from "node:crypto";
import { inspect } from "node:util";
import { assembleCompact, grantSigningInput, jwkFromPublicKey, thumbprint, verifyGrant } from "@bounded-authority-protocol/verifier";

const issuerKeys = generateKeyPairSync("ed25519");
const raw = Buffer.from(issuerKeys.publicKey.export({ format: "jwk" }).x!, "base64url");
const input = grantSigningInput({
  keyId: "k", issuer: "https://issuer.example", grantId: "g-1", audiences: ["https://api.example"],
  issuedAt: 1, notBefore: 1, expiresAt: 100, holderThumbprint: thumbprint(jwkFromPublicKey(raw)),
  operations: [{ name: "files.list", selectors: ["all"] }],
});
assert.ok(input.ok);
const grant = assembleCompact(input.value, sign(null, Buffer.concat([input.value.protectedSegment, Buffer.from("."), input.value.payloadSegment]), issuerKeys.privateKey));
assert.ok(grant.ok);
const facts = verifyGrant(grant.value, { keyId: "k", publicKey: raw }, { issuer: "https://issuer.example", audience: "https://api.example", evaluationTime: 50, clockSkew: 0 });
assert.ok(facts.ok);
const rendering = "#BoundedAuthorityProtocol.V1.GrantFacts<redacted>";
assert.equal(inspect(facts.value), rendering);
assert.equal(String(facts.value), rendering);
assert.equal(JSON.stringify({ facts: facts.value }), JSON.stringify({ facts: rendering }));
assert.deepEqual(Object.keys(facts.value), []);
assert.equal(facts.value.grantId, "g-1"); // fields read by name
const { grantId, issuer } = facts.value; // copy what you log or store, by name
assert.deepEqual({ grantId, issuer }, { grantId: "g-1", issuer: "https://issuer.example" });
```

| Type | Returned by | Fields |
|---|---|---|
| `GrantFacts` | `verifyGrant` | `version`, `issuer`, `grantId`, `issuerKeyFingerprint`, `holderThumbprint`, `matchedAudience`, `issuedAt`, `notBefore`, `expiresAt`, `authorization: "not_evaluated"` |
| `EnvelopeFacts` | `checkEnvelope` | `version`, `issuer`, `grantId`, `issuerKeyFingerprint`, `holderThumbprint`, `matchedAudience`, `grantIssuedAt`, `grantNotBefore`, `grantExpiresAt`, `proofId`, `invocationId`, `operation`, `uri`, `grantHash` (`ath`), `requestHash` (`ba_req`), `proofIssuedAt`, `authorization: "not_evaluated"` |
| `ChainFacts` | `checkChain` | `version`, `chainId`, `firstSequence`, `lastSequence`, `rowCount`, `previousHash`, `lastHash`, `verification: "boundary_consistent"`, `trust: "not_evaluated"` |
| `AnchorFacts` | `verifyHistoricalAnchor` | `version`, `anchorId`, `anchoredAt`, `chainId`, `sequence`, `chainHash`, `keyFingerprint`, `verification: "signature_and_window"`, `trust: "not_evaluated"` |
| `KeyTransitionFacts` | `verifyKeyTransition` | `version`, `transitionId`, `chainId`, `effectiveAt`, `currentKeyFingerprint`, `nextKeyFingerprint`, `verification: "authenticated_transition"`, `trust: "not_evaluated"` |
| `AnchoredExportFacts` | `verifyAnchoredExport` | `version`, `chainId`, `firstSequence`, `lastSequence`, `rowCount`, `previousHash`, `lastHash`, `digest`, `startAnchorId`, `startAnchoredAt`, `startKeyFingerprint`, `endAnchorId`, `endAnchoredAt`, `endKeyFingerprint`, `transitionCount`, `objectVersion`, `verification: "anchored_export"`, `trust` and `authorization` both `"not_evaluated"` |
| `GrantDecoded` | `decodeGrant` | `keyId`, `issuer`, `grantId`, `audiences`, `issuedAt`, `notBefore`, `expiresAt`, `holderThumbprint`, `verification: "not_evaluated"` |
| `ProofDecoded` | `decodeProof`, `decodeLocalLoopbackHttpProof` | `proofId`, `holderThumbprint`, `verification: "not_evaluated"` |
| `KeyLocator` | `untrustedKeyLocator` | `keyId`, `trust: "not_evaluated"` |

Fingerprints, thumbprints and hashes are raw 32-byte `Uint8Array`s; `version` is the major (1, 2
or 3).

## Primitives

### JSON and canonical JSON

- **`Tagged`**: the tagged JSON algebra. `{ t: "null" }`, `{ t: "bool"; v: boolean }`,
  `{ t: "int"; v: number }`, `{ t: "float"; v: number }`, `{ t: "string"; v: Uint8Array }` (UTF-8
  bytes), `{ t: "array"; v: Tagged[] }`, `{ t: "object"; v: ReadonlyMap<string, Tagged> }`.
- **`jsonDecode(bytes, bounds?): Tagged`** decodes exactly one strict JSON value: UTF-8 required,
  duplicate member names rejected at any depth, numbers tagged `int` or `float` by their lexeme,
  every limit enforced. Throws `InvalidError`.
- **`jcsEncode(value, bounds?): Uint8Array`** encodes a `Tagged` value as RFC 8785 canonical JSON
  (members sorted by UTF-16 code units, ECMAScript number text). Throws `InvalidError`.
- **`strUtf8(text): Uint8Array`** and **`utf8Str(bytes): string`** convert between strings and UTF-8;
  `utf8Str` throws `InvalidError` on invalid UTF-8.

### Selectors and digests

- **`parseSelector(tagged, bounds?): Selector`** validates a decoded selector object for major 1
  (`all`, `equals`, `one_of`) and throws `InvalidError` otherwise. `Selector` is the parsed type.
- **`selectorMatches(selector, castArguments): boolean`** applies one selector.
- **`semanticIdentity(value): Uint8Array`** is the canonical bytes selectors compare: the JCS of the
  typed projection. Equal values with different member order have equal identities; `1` and `1.0`
  do not.
- **`typedProject(value): Tagged`** is that typed projection: every value becomes `["tag", value]`
  (`null`, `boolean`, `integer`, `float`, `string`, `array`, `object`).
- **`REQUEST_PREFIX`**, **`ROW_PREFIX`**, **`ARCHIVE_PREFIX`**: the major-1 domain separators
  `BAP1-REQUEST\0`, `BAP1-CHAIN\0` and `BAP1-ARCHIVE\0EXPORT\0` as bytes.

```ts
import assert from "node:assert/strict";
import {
  REQUEST_PREFIX, jcsEncode, jsonDecode, requestDigest, semanticIdentity, sha256, strUtf8, typedProject, utf8Str,
} from "@bounded-authority-protocol/verifier";

const args = jsonDecode(strUtf8('{"zone":"b2","count":3}'));

// JCS sorts members and drops whitespace.
assert.equal(utf8Str(jcsEncode(args)), '{"count":3,"zone":"b2"}');
// The typed projection keeps the JSON type of every value.
assert.equal(utf8Str(jcsEncode(typedProject(args))), '["object",{"count":["integer",3],"zone":["string","b2"]}]');

// requestDigest is SHA-256 over the prefix and the JCS of [operation, typed(arguments)].
const digest = requestDigest("inventory.count", args);
assert.ok(digest.ok);
const manual = sha256(REQUEST_PREFIX, jcsEncode({ t: "array", v: [{ t: "string", v: strUtf8("inventory.count") }, typedProject(args)] }));
assert.deepEqual(digest.value, manual);

// Member order does not change identity; the int/float tag does.
const reordered = jsonDecode(strUtf8('{"count":3,"zone":"b2"}'));
assert.deepEqual(semanticIdentity(reordered), semanticIdentity(args));
assert.notDeepEqual(semanticIdentity(jsonDecode(strUtf8("3"))), semanticIdentity(jsonDecode(strUtf8("3.0"))));
```

### Keys, JWKs and thumbprints (Ed25519)

- **`jwkFromPublicKey(raw32): OkpPublic`** returns the public JWK object; the `OkpPublic` type is
  `{ crv: "Ed25519"; kty: "OKP"; x: string }` with `x` the base64url of the raw key.
- **`jwkEncodePublic(raw32, bounds?): Uint8Array`** returns that JWK as canonical JSON bytes.
- **`jwkDecodePublic(bytes, bounds?): Result<Uint8Array>`** parses exactly that JWK (no other
  member, including a private `d`) and returns the raw key.
- **`thumbprintPreimage(jwk)`**, **`thumbprint(jwk): string`**, **`thumbprintRaw(jwk)`** and
  **`publicKeyThumbprintRaw(raw32)`**: the RFC 7638 preimage `{"crv","kty","x"}`, its base64url
  SHA-256, the raw 32-byte SHA-256, and the raw thumbprint straight from a raw key.

Every one of these applies rule S1 key acceptance and throws `InvalidError` for a key that is not
32 bytes or not acceptable (`jwkDecodePublic` returns the closed result instead). The three that take
a JWK object (`thumbprintPreimage`, `thumbprint`, `thumbprintRaw`) also throw for an object with any
member besides `crv`, `kty` and `x`, such as a private `d` or an `alg` (new in 0.8.0 (unreleased); the
`v3` forms likewise require exactly `crv`, `kty`, `x` and `y`).

```ts
import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import {
  base64urlEncode, jwkDecodePublic, jwkEncodePublic, jwkFromPublicKey, publicKeyThumbprintRaw,
  thumbprint, thumbprintPreimage, thumbprintRaw, utf8Str,
} from "@bounded-authority-protocol/verifier";

const x = generateKeyPairSync("ed25519").publicKey.export({ format: "jwk" }).x!;
const key = Buffer.from(x, "base64url");
const jwk = jwkFromPublicKey(key);

assert.equal(utf8Str(thumbprintPreimage(jwk)), `{"crv":"Ed25519","kty":"OKP","x":"${x}"}`);
assert.equal(utf8Str(jwkEncodePublic(key)), `{"crv":"Ed25519","kty":"OKP","x":"${x}"}`);
assert.equal(thumbprint(jwk), utf8Str(base64urlEncode(thumbprintRaw(jwk))));
assert.deepEqual(publicKeyThumbprintRaw(key), thumbprintRaw(jwk));

const decoded = jwkDecodePublic(jwkEncodePublic(key));
assert.ok(decoded.ok);
assert.deepEqual(Buffer.from(decoded.value), key);
assert.deepEqual(jwkDecodePublic(new TextEncoder().encode(`{"crv":"Ed25519","d":"AA","kty":"OKP","x":"${x}"}`)), { ok: false });
```

### Signatures

- **`verifyStrict(message, signature, publicKey): boolean`**: Ed25519 under rule S1. Never throws.
- **`acceptablePublicKey(publicKey): boolean`**: 32 bytes, canonical, not small order, on the curve.
- **`torsionFree(publicKey): boolean`**: acceptable and `[L]A = O`; for key enrollment, not per request.
- **`es256VerifyStrict(message, signature, publicKey): boolean`**: ES256 with a 65-byte uncompressed
  on-curve key, a raw 64-byte `r || s` signature, `0 < r < n` and low-S. Never throws.

Examples: [Strict Ed25519](../README.md#strict-ed25519-rule-s1) and
[Contract-majors 2 and 3](guides/contract-majors.md#major-3-es256).

### Encodings and hashing

- **`base64urlEncode(bytes): Uint8Array`** returns unpadded base64url as ASCII bytes.
- **`base64urlDecode(text, maxDecodedBytes?): Uint8Array`** accepts only canonical unpadded
  base64url (no padding, whitespace or non-zero trailing bits) and throws `InvalidError` otherwise.
- **`sha256(...parts): Uint8Array`** hashes the concatenation of its parts; every part must be a
  `Uint8Array`, or it throws `InvalidError`.

```ts
import assert from "node:assert/strict";
import { base64urlDecode, base64urlEncode, sha256, strUtf8, utf8Str } from "@bounded-authority-protocol/verifier";

assert.equal(Buffer.from(sha256(strUtf8("ab"), strUtf8("c"))).toString("hex"),
  "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"); // SHA-256("abc")
assert.equal(utf8Str(base64urlEncode(new Uint8Array([0xfb, 0xff]))), "-_8");
assert.deepEqual([...base64urlDecode(strUtf8("-_8"))], [0xfb, 0xff]);
assert.throws(() => base64urlDecode(strUtf8("-_9")), { name: "InvalidError" }); // non-zero trailing bits
```

### URIs

#### `uriNormalize(input, bounds?): Result<Uint8Array>`

Returns the normal form of an HTTPS target URI, or rejects one that is not HTTPS, has user
information, a query or a fragment, is not ASCII, or is malformed. Example:
[Verify requests](guides/verify-requests.md#target-uris). `localLoopbackHttpUriNormalize` is the
loopback profile's form ([above](#local-loopback-proof-profile)).

### `BACKEND_ID` and `BackendId`

`BACKEND_ID` is `"node"` or `"portable"`, the crypto backend this build resolved; `BackendId` is
that union type. See [Browsers, Deno, Bun and workers](../README.md#browsers-deno-bun-and-workers).

## Bounds

Every limit of the profile has a maximum in `MAXIMA`. A `Bounds` value can only tighten them.

- **`boundsNew(tightening?): Bounds`** takes `{ limitName: value }`. Throws `InvalidError` for an
  unknown name, a non-integer, zero or negative value, a value above the maximum, or any change to
  the fixed widths `digest_bytes`, `public_key_bytes` and `signature_bytes` (which may only be set
  to their maximum). With no argument it returns `MAXIMUM_BOUNDS`.
- **`boundsMaximum(): Bounds`** returns a new untightened value.
- **`MAXIMUM_BOUNDS`** is the shared untightened value; do not mutate it.
- **`MAXIMA`** is the table below; **`MaximaKey`** is the union of its names; **`Bounds`** is
  `{ maximum; overrides: ReadonlyMap<MaximaKey, number> }`. Build it with `boundsNew`: every entry
  point re-validates a hand-built value and rejects one that widens a limit.

| Limit | Maximum | Limit | Maximum |
|---|---|---|---|
| `compact_bytes` | 65,536 | `content_bytes` | 65,536 |
| `encoded_segment_bytes` | 32,768 | `decoded_segment_bytes` | 24,576 |
| `json_bytes` | 65,536 | `jcs_bytes` | 65,536 |
| `depth` | 32 | `total_nodes` | 4,096 |
| `object_members` | 64 | `array_items` | 256 |
| `string_bytes` | 8,192 | `key_bytes` | 128 |
| `number_lexeme_bytes` | 64 | `integer_magnitude` | 9,007,199,254,740,991 |
| `float_magnitude` | 9,007,199,254,740,991 | `kid_bytes` | 128 |
| `uri_bytes` | 8,192 | `identifier_bytes` | 512 |
| `nonce_bytes` | 512 | `method_bytes` | 32 |
| `operation_bytes` | 128 | `audiences` | 64 |
| `operations` | 64 | `selectors` | 64 |
| `path_segments` | 32 | `one_of_values` | 256 |
| `public_key_bytes` (fixed) | 32 | `signature_bytes` (fixed) | 64 |
| `digest_bytes` (fixed) | 32 | `clock_skew` | 60 |
| `proof_max_age` | 300 | `chain_row_bytes` | 4,096 |
| `chain_rows` | 65,536 | `anchor_bytes` | 8,192 |
| `archive_header_bytes` | 8,192 | `archive_chunks` | 65,796 |
| `archive_bytes` | 270,820,384 | `object_version_bytes` | 512 |
| `key_transitions` | 256 | | |

```ts
import assert from "node:assert/strict";
import { MAXIMA, boundsNew, jsonDecode, strUtf8 } from "@bounded-authority-protocol/verifier";

assert.equal(MAXIMA.compact_bytes, 65_536);
const strict = boundsNew({ depth: 4, string_bytes: 64 });
assert.equal(jsonDecode(strUtf8('{"a":{"b":1}}'), strict).t, "object");
assert.throws(() => jsonDecode(strUtf8(`{"a":"${"x".repeat(65)}"}`), strict), { name: "InvalidError" });
assert.throws(() => boundsNew({ compact_bytes: 70_000 }), { name: "InvalidError" }); // widening
assert.throws(() => boundsNew({ signature_bytes: 32 }), { name: "InvalidError" }); // fixed width
assert.throws(() => boundsNew({ compact_byte: 10 }), { name: "InvalidError" }); // unknown name
```

## Results and errors

- **`Result<T>`**: `{ readonly ok: true; readonly value: T } | { readonly ok: false }`.
- **`InvalidError`**: the package's single error class (`name: "InvalidError"`), thrown by the
  primitives listed in [Handle errors](guides/handle-errors.md#functions-that-return-booleans-or-throw).
- **`ok(value)`** and **`err()`** build the two result forms.
- **`trying(fn)`** runs `fn`, returns `ok(result)`, converts a thrown `InvalidError` into `err()`,
  and rethrows anything else.
- **`fail(message?)`** throws `InvalidError`; **`assert(condition, message?)`** throws it when the
  condition is falsy.

```ts
import assert from "node:assert/strict";
import { InvalidError, assert as check, err, fail, ok, trying } from "@bounded-authority-protocol/verifier";

assert.deepEqual(ok(5), { ok: true, value: 5 });
assert.deepEqual(err(), { ok: false });
assert.deepEqual(trying(() => fail("nope")), { ok: false });
assert.deepEqual(trying(() => { check(1 + 1 === 2, "math"); return "fine"; }), { ok: true, value: "fine" });
assert.throws(() => trying(() => { throw new TypeError("a bug"); }), TypeError); // not a verdict
assert.ok(new InvalidError() instanceof Error);
```

## The `v2` namespace

`import { v2 } from "@bounded-authority-protocol/verifier"`. Contract-major 2: payload `v: 2`,
suite `BAP2-Ed25519-SHA256`, separators `BAP2-REQUEST\0`, `BAP2-CHAIN\0`,
`BAP2-ARCHIVE\0EXPORT\0`, and the `lte`/`gte` selector kinds. It rejects major-1 and major-3 bytes.

Functions, each with the same signature and checks as the root function of the same name:
`untrustedKeyLocator`, `decodeGrant`, `decodeProof`, `verifyGrant`, `checkEnvelope`,
`requestDigest`, `encodeConsumptionEntry`, `checkChain`, `grantSigningInput`, `proofSigningInput`,
`assembleCompact`, `boundaryAnchorSigningInput`, `keyTransitionSigningInput`,
`encodeAnchoredExport`, `verifyHistoricalAnchor`, `verifyKeyTransition`, `verifyAnchoredExport`,
`parseSelector` and `selectorMatches` (the five-kind algebra), plus the shared `jwkEncodePublic`,
`jwkDecodePublic`, `thumbprint`, `sha256`, `base64urlDecode`, `base64urlEncode`, `boundsNew`,
`boundsMaximum`, `MAXIMUM_BOUNDS`, `MAXIMA`, `uriNormalize`, `typedProject` and the major-2
`REQUEST_PREFIX`, `ROW_PREFIX`, `ARCHIVE_PREFIX`.

Differences from the root: no local-loopback functions; `v2.encodeAnchoredExport` takes
`v2.ExpectedExport` (`{ chain, startAnchor, endAnchor, transitions, bounds? }`, no digest or
version) and `v2.verifyAnchoredExport` takes `v2.ExpectedAnchoredExport` (that plus `digest` and
`objectVersion`); the chain, anchor, transition and export facts have `version: 2`. Its types
(`v2.GrantProducer`, `v2.SelectorInput`, `v2.Selector`, `v2.ExpectedRequest`, and so on) are the
root types with the range selectors added. Example:
[Contract-majors 2 and 3](guides/contract-majors.md#major-2-range-selectors).

## The `v3` namespace

`import { v3 } from "@bounded-authority-protocol/verifier"`. Contract-major 3: payload `v: 3`,
suite `BAP3-ES256-SHA256` (`alg: "ES256"`), separators `BAP3-*`, and the major-2 selector algebra.
It has the same function list as `v2`, with these key and signature forms:

- every raw public key (trusted issuer, holder, historical, producer inputs) is a 65-byte
  uncompressed SEC1 P-256 point `0x04 || x || y`, with both coordinates below the field prime and
  the point on the curve;
- signatures are raw 64-byte `r || s` with `0 < r < n` and `0 < s <= (n - 1) / 2`;
- the key helpers are the P-256 forms, with the root's names and shapes. Each throws `InvalidError`
  for a key or JWK whose point is not an acceptable P-256 key (65 bytes, the `0x04` prefix, both
  coordinates below p, on the curve), as the Elixir `V3.EcJwk` functions refuse it:

| Function | Returns |
|---|---|
| `v3.jwkFromPublicKey(raw65)` | the `v3.EcPublic` object `{ crv: "P-256"; kty: "EC"; x: string; y: string }` |
| `v3.jwkEncodePublic(raw65, bounds?)` | that JWK as canonical JSON bytes |
| `v3.jwkDecodePublic(bytes, bounds?)` | `Result<Uint8Array>`: the raw 65-byte key of exactly that JWK |
| `v3.thumbprintPreimage(jwk)` | the RFC 7638 preimage `{"crv","kty","x","y"}` |
| `v3.thumbprint(jwk)` | its unpadded base64url SHA-256: the `holderThumbprint` of a v3 grant |
| `v3.thumbprintRaw(jwk)` | the same digest as 32 raw bytes |
| `v3.publicKeyThumbprintRaw(raw65)` | the raw thumbprint straight from a raw key: the `keyFingerprint` of v3 anchors and transitions |

```ts
import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import { v3 } from "@bounded-authority-protocol/verifier";

const { x, y } = generateKeyPairSync("ec", { namedCurve: "P-256" }).publicKey.export({ format: "jwk" });
const raw = Buffer.concat([Buffer.from([0x04]), Buffer.from(x!, "base64url"), Buffer.from(y!, "base64url")]);

const jwk: v3.EcPublic = v3.jwkFromPublicKey(raw);
assert.deepEqual(jwk, { crv: "P-256", kty: "EC", x, y });
assert.equal(new TextDecoder().decode(v3.jwkEncodePublic(raw)), `{"crv":"P-256","kty":"EC","x":"${x}","y":"${y}"}`);
assert.deepEqual(Buffer.from(v3.publicKeyThumbprintRaw(raw)).toString("base64url"), v3.thumbprint(jwk));

const offCurve = Buffer.from(raw);
offCurve[64] = offCurve[64]! ^ 1;
assert.throws(() => v3.jwkFromPublicKey(offCurve), { name: "InvalidError" });
```

Example in context: [Contract-majors 2 and 3](guides/contract-majors.md#major-3-es256).

## The `roleAttestation` namespace

`import { roleAttestation } from "@bounded-authority-protocol/verifier"`. The
`bap-role-attestation/1` profile ([guide](guides/role-attestations.md)).

| Function | Returns | Purpose |
|---|---|---|
| `attestationSigningInput(attestation, bounds?)` | `Result<SigningInput>` | the signing input of an attestation from an `AttestationProducer` |
| `assembleAttestationCompact(input, signature, bounds?)` | `Result<Uint8Array>` | joins a `role_attestation` signing input and a 64-byte signature, then re-parses it |
| `decodeAttestation(compact, bounds?)` | `Result<AttestationDecoded>` | structure only, `verification: "not_evaluated"` |
| `verifyAttestation(compact, expected)` | `Result<AttestationFacts>` | the full check ([guide](guides/role-attestations.md#what-verifyattestation-checks)) |

Types:

- `AttestationProducer`: `{ keyId; jti; subjectKeyId; subjectPublicKey; role: "issuer" | "holder";
  notBefore; expiresAt }`, with `notBefore < expiresAt` and an acceptable 32-byte subject key.
- `ExpectedAttestation`: `{ attestor: AttestorKey; subjectKeyId; subjectPublicKey; now; bounds? }`.
- `AttestorKey`: the same shape as `HistoricalPublicKey`.
- `AttestationDecoded`: `{ keyId; jti; subjectKeyId; subjectPublicKey; role; notBefore; expiresAt;
  verification: "not_evaluated" }`.
- `AttestationFacts`: `{ version: 1; attestorKeyId; attestorKeyFingerprint; subjectKeyId;
  subjectKeyFingerprint; role; jti; notBefore; expiresAt; verification: "signature_and_window";
  trust: "not_evaluated" }`.

```ts
import assert from "node:assert/strict";
import { generateKeyPairSync, sign } from "node:crypto";
import { roleAttestation } from "@bounded-authority-protocol/verifier";

const subject = Buffer.from(generateKeyPairSync("ed25519").publicKey.export({ format: "jwk" }).x!, "base64url");
const input = roleAttestation.attestationSigningInput({
  keyId: "root-1", jti: "att-7", subjectKeyId: "agent-key-3", subjectPublicKey: subject,
  role: "holder", notBefore: 100, expiresAt: 200,
});
assert.ok(input.ok);
const attestor = generateKeyPairSync("ed25519");
const signature = sign(null, Buffer.concat([input.value.protectedSegment, Buffer.from("."), input.value.payloadSegment]), attestor.privateKey);
const compact = roleAttestation.assembleAttestationCompact(input.value, signature);
assert.ok(compact.ok);

const decoded = roleAttestation.decodeAttestation(compact.value);
assert.ok(decoded.ok);
assert.equal(decoded.value.role, "holder");
assert.equal(decoded.value.verification, "not_evaluated");
```

## The `contentAssertion` namespace

`import { contentAssertion } from "@bounded-authority-protocol/verifier"`. The
`bap-content-assertion/1` profile ([guide](guides/content-assertions.md)).

| Function | Returns | Purpose |
|---|---|---|
| `contentDigest(content, bounds?)` | `Result<Uint8Array>` | `SHA-256("BAP1-CONTENT\0" \|\| content)` for 1 to 65,536 content bytes (`content_bytes`) |
| `assertionSigningInput(producer, bounds?)` | `Result<SigningInput>` | the signing input from a `ContentAssertionProducer` |
| `assembleCompact(input, signature, bounds?)` | `Result<Uint8Array>` | joins a `content_assertion` signing input and a 64-byte signature, then re-parses it |
| `decodeAssertion(compact, bounds?)` | `Result<DecodedContentAssertion>` | structure only, `verification: "not_evaluated"` |
| `assertionDigest(compact, bounds?)` | `Result<Uint8Array>` | SHA-256 of the exact compact after a structure check; no signature claim |
| `verifyAssertion(compact, expected)` | `Result<ContentAssertionFacts>` | the full check ([guide](guides/content-assertions.md#publish-and-verify-one-assertion)) |
| `verifySuccessor(predecessor, successor, bounds)` | `Result<void>` | compares two facts values ([guide](guides/content-assertions.md#successors)) |

Types:

- `ContentAssertionProducer`: `{ attestorKeyId; jti; iss; aud; sub; profile; profileDigest;
  contentDigest; gen; prev; iat; nbf; exp }`. Identifiers are StringOrURI of at most 512 bytes;
  `profileDigest`, `contentDigest` and `prev` are 32 bytes; `gen >= 1`, and `prev` is all zeros
  exactly when `gen` is 1; `iat <= nbf < exp`.
- `ExpectedContentAssertion`: `{ attestor: HistoricalPublicKey; issuer; audience; subject; profile;
  profileDigest; contentDigest; now; bounds }`. Here `bounds` is required: pass `boundsNew()` for
  the profile maximum.
- `DecodedContentAssertion`: the producer fields plus `version: 1` and
  `verification: "not_evaluated"`.
- `ContentAssertionFacts`: the producer fields plus `version: 1`, `attestorKeyFingerprint`,
  `digest` (SHA-256 of the compact), `verification: "signature_and_window"` and
  `trust: "not_evaluated"`. It follows the facts redaction rule ([Facts and decoded types](#facts-and-decoded-types)).

```ts
import assert from "node:assert/strict";
import { generateKeyPairSync, sign } from "node:crypto";
import { contentAssertion, sha256, strUtf8 } from "@bounded-authority-protocol/verifier";

const content = contentAssertion.contentDigest(strUtf8("route table v12"));
assert.ok(content.ok);
const input = contentAssertion.assertionSigningInput({
  attestorKeyId: "ops-1", jti: "routes-12", iss: "https://ops.example", aud: "https://edge.example",
  sub: "routes:eu", profile: "urn:example:routes:2", profileDigest: sha256(strUtf8("routes schema 2")),
  contentDigest: content.value, gen: 1, prev: new Uint8Array(32), iat: 10, nbf: 10, exp: 20,
});
assert.ok(input.ok);
const signer = generateKeyPairSync("ed25519");
const signature = sign(null, Buffer.concat([input.value.protectedSegment, Buffer.from("."), input.value.payloadSegment]), signer.privateKey);
const compact = contentAssertion.assembleCompact(input.value, signature);
assert.ok(compact.ok);

const decoded = contentAssertion.decodeAssertion(compact.value);
assert.ok(decoded.ok);
assert.equal(decoded.value.sub, "routes:eu");
const digest = contentAssertion.assertionDigest(compact.value);
assert.ok(digest.ok);
assert.deepEqual(digest.value, sha256(compact.value));
assert.deepEqual(contentAssertion.contentDigest(new Uint8Array(0)), { ok: false }); // empty content
```
