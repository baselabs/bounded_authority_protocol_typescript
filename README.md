# @bounded-authority-protocol/verifier

[![npm](https://img.shields.io/npm/v/@bounded-authority-protocol/verifier)](https://www.npmjs.com/package/@bounded-authority-protocol/verifier)
[![CI](https://github.com/baselabs/bounded_authority_protocol_typescript/actions/workflows/ci.yml/badge.svg)](https://github.com/baselabs/bounded_authority_protocol_typescript/actions/workflows/ci.yml)
[![license](https://img.shields.io/badge/license-Apache--2.0-blue)](LICENSE)

Deterministic, fail-closed verification for the **Bounded Authority Protocol** — bounded
proof-of-possession authority for services and AI agents, in pure TypeScript.

The SDK verifies the protocol's three wire profiles (contract-majors 1, 2, and 3): compact-JWS
grants, holder proofs, consumption chains, boundary anchors, key transitions, and archived
exports. It is a TypeScript reimplementation of the reference profiles — derived from the
published specifications and certified conformance corpora, with zero runtime dependencies
(Ed25519 and ES256 via `node:crypto`; canonicalization hand-rolled from the RFCs). It also
carries the protocol's byte-distinct sibling profile for role attestations
(`bap-role-attestation/1`, under the `roleAttestation` namespace), parsed by no contract-major
and parsing none of them.

**It verifies; it never authorizes.** A successful result proves that caller-supplied bytes
satisfy caller-supplied trusted inputs and expected context — nothing more. There is no
`allowed`, no `authorized`, no decision anywhere in the API: results are value-bearing,
redacted facts, and every failure is a single closed rejection.

## Install

```bash
npm install @bounded-authority-protocol/verifier
```

Requires Node.js `>= 22`. Zero runtime dependencies.

## Quickstart — verify a grant

```ts
import { verifyGrant } from "@bounded-authority-protocol/verifier";

// The raw compact-JWS grant bytes (ASCII), produced out-of-band by an issuer.
const grantCompact = Buffer.from(
  "eyJhbGciOiJFZERTQSIsInR5cCI6ImJhK2NhcCIsImtpZCI6Imlzc3Vlci1rZXkifQ." +
    "<payload>.<signature>",
  "ascii",
);

const result = verifyGrant(
  grantCompact,
  {
    keyId: "issuer-key",            // must match the grant header `kid` exactly
    publicKey: issuerPublicKey32,   // raw 32-byte Ed25519 public key — public keys only
  },
  {
    issuer: "https://issuer.example",
    audience: "https://resource.example",
    evaluationTime: 1_731_728_000,  // caller-supplied, seconds since epoch — the SDK reads no clock
    clockSkew: 60,
  },
);

if (result.ok) {
  const facts = result.value;       // GrantFacts — value-bearing, redacted
  facts.holderThumbprint;           // Uint8Array(32) — the bound holder key
  facts.authorization;              // "not_evaluated" — verification is not authority
} else {
  // { ok: false } — every structural, signature, header, claim, or time-window
  // failure lands here. Closed and value-free: no reason, no partial data.
}
```

Every public function returns the same `Result<T>` shape — `{ ok: true, value }` or
`{ ok: false }` — mirroring the reference's `{:ok, value} | {:error, :invalid}`.

## Wire contract-majors

The protocol versions its wire formats as complete, parallel **contract-majors**. All three live
in this package; each verifies only its own bytes — there is no fallback or downgrade in any
direction.

| Major | Import | Selector kinds | Suite | Notes |
|---|---|---|---|---|
| 1 | `import { verifyGrant, ... }` | `all`, `equals`, `one_of` | `BAP1-Ed25519-SHA256` | The original profile |
| 2 | `import { v2 } from "@bounded-authority-protocol/verifier"` | `+ lte`, `gte` | `BAP2-Ed25519-SHA256` | Adds inclusive same-tag range selectors (intervals compose conjunctively) |
| 3 | `import { v3 } from "@bounded-authority-protocol/verifier"` | same five as v2 | `BAP3-ES256-SHA256` | The ES256 suite: ECDSA over NIST P-256, raw 65-byte SEC1 public keys, low-S raw `r\|\|s` signatures |

The `v2` namespace mirrors the full v1 surface — `v2.verifyGrant`, `v2.checkEnvelope`,
`v2.grantSigningInput`, and so on — under the major-2 separators, suite name, and `v: 2`
payloads. The `v3` namespace mirrors it again under the ES256 suite: `alg: "ES256"`, the
65-byte uncompressed-SEC1 raw public-key form, the `{crv, kty, x, y}` proof JWK with its
RFC 7638 thumbprint, and the RFC 7518 §3.4 raw `r||s` signature form with low-S enforced at
verification (Node's crypto backend accepts the malleable high-S counterpart; the profile
gate is load-bearing). Every v1 and v2 artifact rejects under `v3` with the single closed
error, and vice versa.

```ts
import { v2 } from "@bounded-authority-protocol/verifier";

const result = v2.checkEnvelope(grantV2, proofV2, {
  trustedIssuer: { keyId: "issuer-key", publicKey: issuerPublicKey32 },
  issuer: "https://issuer.example",
  audience: "https://resource.example",
  method: "POST",
  targetUri: "https://api.example.test/invoke",
  invocationId: "…", operation: "transfer",
  castArguments: { t: "object", v: new Map([["amount", { t: "int", v: 5000 }]]) },
  evaluationTime: 1_731_728_000, clockSkew: 60, proofMaxAge: 300,
  nonce: { kind: "not_required" },
});
// The grant above may carry { kind: "lte", path: ["amount"], value: 5000 } —
// amount 5001 rejects; 5000 verifies inclusively; cross-tag operands never match.
```

`castArguments` uses the SDK's tagged JSON algebra (int/float/string/object tags carry the
selector operand domain); the [`Tagged` type](src/json.ts) is exported from the package root.

## API surface

The v1 façade (the `v2` namespace mirrors it):

| Function | Returns | Purpose |
|---|---|---|
| `verifyGrant` | `Result<GrantFacts>` | Verify a compact grant against a trusted issuer + expected context |
| `checkEnvelope` | `Result<EnvelopeFacts>` | Re-verify the grant and bind the holder proof, request, nonce, and selectors |
| `decodeGrant` / `decodeProof` | `Result<GrantDecoded \| ProofDecoded>` | Structural decode (verification: not_evaluated) |
| `untrustedKeyLocator` | `Result<KeyLocator>` | Header-only key id (trust: not_evaluated) |
| `requestDigest` | `Uint8Array(32)` | Typed, type-preserving request hash (major-bound domain prefix) |
| `encodeConsumptionEntry` / `checkChain` | `Result<EncodedConsumptionEntry \| ChainFacts>` | Canonical consumption rows + range verification |
| `grantSigningInput` / `proofSigningInput` | `Result<SigningInput>` | Deterministic producer signing inputs |
| `assembleCompact` | `Uint8Array` | External signature assembly — the SDK holds no private keys |
| `boundaryAnchorSigningInput` / `keyTransitionSigningInput` | `Result<SigningInput>` | Anchor and historical-key-transition producers |
| `encodeAnchoredExport` / `verifyAnchoredExport` | `Result<EncodedAnchoredExport \| AnchoredExportFacts>` | Deterministic archive framing + atomic verification |
| `verifyHistoricalAnchor` / `verifyKeyTransition` | `Result<AnchorFacts \| KeyTransitionFacts>` | Historical boundary + authenticated rollover verification |

Plus the versioned primitives (`jwkEncodePublic`, `thumbprint`, `uriNormalize`, `boundsNew`,
`jcsEncode`, `base64urlDecode`/`Encode`, the tagged JSON algebra), the byte-distinct
local-development proof profile (`localLoopbackHttpProofSigningInput` and friends — literal
`127.0.0.1`/`[::1]` targets only, mandatory nonce; standard `dpop+jwt` rejects its bytes), and
the standalone role-attestation sibling profile (`bap-role-attestation/1`): the
`roleAttestation` namespace's four surfaces — `attestationSigningInput` (external signature
only), `assembleAttestationCompact`, `decodeAttestation`, and `verifyAttestation` — bind a
subject key to a role (`issuer`/`holder`) for a window contained in the attestor key's
validity, with self-attestation rejected and facts carrying `trust: "not_evaluated"` and no
authorization marker. The full export list is [`src/index.ts`](src/index.ts).

## Pairing with the signer

This package verifies; it never signs and never holds a private key. Its sibling
[`@bounded-authority-protocol/signer`](https://www.npmjs.com/package/@bounded-authority-protocol/signer)
produces the signed bytes — see the whole three-role flow run live in your browser at the
[envelope playground](https://baselabs.github.io/bounded_authority_signer_typescript/) — and it does so by calling THIS package's producer functions
(`grantSigningInput`, `proofSigningInput`, `boundaryAnchorSigningInput`,
`keyTransitionSigningInput`) and delegating the cryptography to a caller-owned key handle.
The dependency direction is one-way: the signer depends on the verifier at runtime
(`^0.2.0`), never the reverse. Compatibility between the two is governed by the wire
contract-majors — both packages carry majors 1 and 2 side by side — not by package
version numbers.

A production flow has three roles: the issuer mints a grant, the holder binds one
invocation of it with a proof, and the resource verifies the pair through this package.

```ts
// Issuer — mint a grant. The private key never enters the signer; your handle
// routes each sign() to your own custody (KMS, HSM, or an in-process test key).
import { signGrant, signReport, type KeyHandle } from "@bounded-authority-protocol/signer";
import { checkEnvelope } from "@bounded-authority-protocol/verifier";

const issuerHandle: KeyHandle = {
  sign: (message) => issuerCustody.sign(message),  // Ed25519, 64 bytes
  publicKey: () => issuerPublicKey32,
  thumbprint: () => issuerThumbprint,              // RFC 7638, base64url
  // Grants additionally require an atomic issuer-role identity — the C1 gate:
  // a holder-role handle fails closed before sign() is ever called.
  signingIdentity: () => ({ role: "issuer", keyId: "issuer-key", publicKey: issuerPublicKey32 }),
};

// SignerResult mirrors this package's Result<T>: check ok before reading value.
const grantResult = await signGrant(
  {
    issuer: "https://issuer.example",
    grantId: "g-1",
    audiences: ["https://resource.example"],
    issuedAt: 1_731_728_000,
    notBefore: 1_731_728_000,
    expiresAt: 1_733_728_000,
    holderThumbprint,  // RFC 7638 base64url of the holder's public JWK (the thumbprint primitive)
    operations: [
      { name: "transfer", selectors: [{ kind: "equals", path: ["amount"], value: { t: "int", v: 5000 } }] },
    ],
  },
  issuerHandle,
);
if (!grantResult.ok) throw new Error(`signing failed: ${grantResult.error}`);
const grantCompact = grantResult.value.grant;

// Holder — bind one invocation of that grant with a holder proof. The holder's
// handle is constructed exactly like the issuer's (reports need no
// signingIdentity — proofs are holder-signed by definition), and the proof
// timestamp is pinned the same way: this verifier reads no clock.
const proofResult = await signReport(
  {
    grantCompact: grantCompact,
    operation: "transfer",
    method: "POST",
    targetUri: "https://api.example.test/invoke",
    invocationId: "9a1b2c3d-4e5f-4a6b-8c7d-0e1f2a3b4c5d",  // a lowercase RFC 4122 UUID — the wire requires it
    castArguments: { t: "object", v: new Map([["amount", { t: "int", v: 5000 }]]) },
  },
  holderHandle,
  { issuedAt: 1_731_728_030 },
);
if (!proofResult.ok) throw new Error(`signing failed: ${proofResult.error}`);
const envelope = proofResult.value;

// Resource — THIS package, and nothing else. Facts, never a decision.
const result = checkEnvelope(envelope.grant, envelope.proof, {
  trustedIssuer: { keyId: "issuer-key", publicKey: issuerPublicKey32 },
  issuer: "https://issuer.example",
  audience: "https://resource.example",
  method: "POST",
  targetUri: "https://api.example.test/invoke",
  invocationId: "9a1b2c3d-4e5f-4a6b-8c7d-0e1f2a3b4c5d",
  operation: "transfer",
  castArguments: { t: "object", v: new Map([["amount", { t: "int", v: 5000 }]]) },
  evaluationTime: 1_731_728_060,
  clockSkew: 60,
  proofMaxAge: 300,
  nonce: { kind: "not_required" },
});
```

Two properties make the pairing safe to build against:

- **Key custody stays at the caller.** The signer's `KeyHandle` is a callback interface
  (`sign`/`publicKey`/`thumbprint`, plus atomic `keyIdentity`/`signingIdentity` snapshots
  for anchors, transitions, and role-gated grant signing). A handle fault or a
  wrong-key rotation race fails loudly as `signing_failed` — the signer verifies every
  signature against the resolved public key before assembly. The full contract is
  documented in the [signer's README](https://github.com/baselabs/bounded_authority_signer_typescript#readme).
- **The two packages cross-validate in CI.** The signer's test oracle produces
  compacts through its own surface and verifies every one of them through THIS
  package before release — signing-side drift is caught in the signer's CI against
  the verifier version its lockfile resolves, and verifier-side changes are gated
  by this package's certified conformance corpora.

## Certified, not self-tested

Every release of this SDK is verified against the protocol's published, cryptographically
certified conformance corpora — **283 vectors** for contract-major 1, **268** for
contract-major 2, **292** for contract-major 3, and **40** for the `bap-role-attestation/1`
sibling profile — recomputing every verdict from scratch,
with each corpus `index.json`
SHA-256 asserted at load so a drifted snapshot fails loudly. Permissiveness bugs (a parser
accepting what the spec forbids) are invisible to corpus agreement by construction, so the
suite additionally carries a per-language mutation gate that proves each closure
**red-capable**: mechanically remove a check, watch its test fail.

CI runs the full matrix on every push: strict typecheck, build, lint (including a library
purity rule — no I/O, clock, or randomness in `src/`), license check, unit tests, the
mutation gate, and all four conformance corpora against the vendored snapshots.

Releases are published only from this repository's release workflow, via npm trusted
publishing (GitHub Actions OIDC — no long-lived tokens) with npm provenance on every
artifact.

## Versioning

Package versions follow SemVer. Wire contract-majors are a separate axis: a new
contract-major lands **additively** (a minor release — this package already carries majors 1,
2, and 3 side by side), and a package major is owed only when a shipped profile or public API is
removed or changes verdicts. Wire artifacts self-declare their major (payload `v`, the
`BAP<n>-…` suite name, major-bound domain separators), so the package number never needs to
encode it.

## What this SDK does not do

It is a verifier, not an authority runtime. It holds no private keys, makes no network or
filesystem calls, reads no clock, and performs no replay reservation, revocation check, or
policy decision. Selecting trusted keys, reserving replay, and granting execution belong to
the host — a facts value is evidence, never a credential.

## Protocol documentation

- [BAP v1 specification](https://github.com/baselabs/bounded_authority_protocol/blob/main/spec/bap-v1.md) ·
  [v2 specification](https://github.com/baselabs/bounded_authority_protocol/blob/main/spec/bap-v2.md) ·
  [v3 specification](https://github.com/baselabs/bounded_authority_protocol/blob/main/spec/bap-v3.md) ·
  [role-attestation profile specification](https://github.com/baselabs/bounded_authority_protocol/blob/main/spec/bap-role-attestation-v1.md)
- [Certified conformance corpora](https://github.com/baselabs/bounded_authority_protocol/tree/main/priv/conformance/)
- [ADR 0014 — cross-language verifier SDKs](https://github.com/baselabs/bounded_authority_protocol/blob/main/docs/adr/0014-cross-language-verifier-sdks.md) ·
  [ADR 0015 — graduation and publish topology](https://github.com/baselabs/bounded_authority_protocol/blob/main/docs/adr/0015-sdk-graduation-and-publish-topology.md) ·
  [ADR 0036 — the role-attestation sibling profile](https://github.com/baselabs/bounded_authority_protocol/blob/main/docs/adr/0036-role-attestation-profile.md)

## Related packages

- [bounded_authority_protocol (monorepo)](https://github.com/baselabs/bounded_authority_protocol) —
  the protocol source: specifications, ADRs, the certified conformance corpora this
  package vendors, and the reference Elixir implementation.
- [@bounded-authority-protocol/signer](https://www.npmjs.com/package/@bounded-authority-protocol/signer) —
  the holder/issuer companion: signs proofs, grants, boundary anchors, and key
  transitions through a caller-owned key handle. This verifier holds no private keys;
  the signer produces the bytes it checks (see [Pairing with the signer](#pairing-with-the-signer)).
- This package on npm:
  [@bounded-authority-protocol/verifier](https://www.npmjs.com/package/@bounded-authority-protocol/verifier).

## Development

```bash
pnpm install
pnpm typecheck && pnpm build && pnpm lint && pnpm license-check
pnpm test                    # unit + struct + façade corpus-vector tests
pnpm test:permissiveness     # the mutation gate
pnpm conformance             # 283/283 + key census (vendored v1 snapshot)
pnpm conformance:v2          # 268/268 + key census (vendored v2 snapshot)
pnpm conformance:v3          # 292/292 + key census (vendored v3 snapshot)
pnpm conformance:role-attestation # 40/40 + cross-profile legs (vendored sibling-profile snapshot)
pnpm check:currency          # dependency-currency gate (latest-first)
```

## License

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
