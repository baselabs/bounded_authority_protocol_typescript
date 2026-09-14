# @bounded-authority/verifier

[![npm](https://img.shields.io/npm/v/@bounded-authority/verifier)](https://www.npmjs.com/package/@bounded-authority/verifier)
[![CI](https://github.com/baselabs/bounded_authority_protocol_typescript/actions/workflows/ci.yml/badge.svg)](https://github.com/baselabs/bounded_authority_protocol_typescript/actions/workflows/ci.yml)
[![license](https://img.shields.io/badge/license-Apache--2.0-blue)](LICENSE)

Deterministic, fail-closed verification for the **Bounded Authority Protocol** — bounded
proof-of-possession authority for services and AI agents, in pure TypeScript.

The SDK verifies the protocol's two wire profiles (contract-majors 1 and 2): compact-JWS
grants, holder proofs, consumption chains, boundary anchors, key transitions, and archived
exports. It is a TypeScript reimplementation of the reference profile — derived from the
published specifications and certified conformance corpora, with zero runtime dependencies
(Ed25519 via `node:crypto`; canonicalization hand-rolled from the RFCs).

**It verifies; it never authorizes.** A successful result proves that caller-supplied bytes
satisfy caller-supplied trusted inputs and expected context — nothing more. There is no
`allowed`, no `authorized`, no decision anywhere in the API: results are value-bearing,
redacted facts, and every failure is a single closed rejection.

## Install

```bash
npm install @bounded-authority/verifier
```

Requires Node.js `>= 22`. Zero runtime dependencies.

## Quickstart — verify a grant

```ts
import { verifyGrant } from "@bounded-authority/verifier";

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

The protocol versions its wire formats as complete, parallel **contract-majors**. Both live in
this package; each verifies only its own bytes — there is no fallback or downgrade in either
direction.

| Major | Import | Selector kinds | Notes |
|---|---|---|---|
| 1 | `import { verifyGrant, ... }` | `all`, `equals`, `one_of` | The original profile |
| 2 | `import { v2 } from "@bounded-authority/verifier"` | `+ lte`, `gte` | Adds inclusive same-tag range selectors (intervals compose conjunctively) |

The `v2` namespace mirrors the full v1 surface — `v2.verifyGrant`, `v2.checkEnvelope`,
`v2.grantSigningInput`, and so on — under the major-2 separators, suite name, and `v: 2`
payloads.

```ts
import { v2 } from "@bounded-authority/verifier";

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
`jcsEncode`, `base64urlDecode`/`Encode`, the tagged JSON algebra) and the byte-distinct
local-development proof profile (`localLoopbackHttpProofSigningInput` and friends — literal
`127.0.0.1`/`[::1]` targets only, mandatory nonce; standard `dpop+jwt` rejects its bytes).
The full export list is [`src/index.ts`](src/index.ts).

## Certified, not self-tested

Every release of this SDK is verified against the protocol's published, cryptographically
certified conformance corpora — **283 vectors** for contract-major 1 and **268** for
contract-major 2 — recomputing every verdict from scratch, with the corpus `index.json`
SHA-256 asserted at load so a drifted snapshot fails loudly. Permissiveness bugs (a parser
accepting what the spec forbids) are invisible to corpus agreement by construction, so the
suite additionally carries a per-language mutation gate that proves each closure
**red-capable**: mechanically remove a check, watch its test fail.

CI runs the full matrix on every push: strict typecheck, build, lint (including a library
purity rule — no I/O, clock, or randomness in `src/`), license check, unit tests, the
mutation gate, and both conformance corpora against the vendored snapshots.

Releases are published only from this repository's release workflow, via npm trusted
publishing (GitHub Actions OIDC — no long-lived tokens) with npm provenance on every
artifact.

## Versioning

Package versions follow SemVer. Wire contract-majors are a separate axis: a new
contract-major lands **additively** (a minor release — this package already carries majors 1
and 2 side by side), and a package major is owed only when a shipped profile or public API is
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
  [v2 specification](https://github.com/baselabs/bounded_authority_protocol/blob/main/spec/bap-v2.md)
- [Certified conformance corpora](https://github.com/baselabs/bounded_authority_protocol/tree/main/priv/conformance/)
- [ADR 0014 — cross-language verifier SDKs](https://github.com/baselabs/bounded_authority_protocol/blob/main/docs/adr/0014-cross-language-verifier-sdks.md) ·
  [ADR 0015 — graduation and publish topology](https://github.com/baselabs/bounded_authority_protocol/blob/main/docs/adr/0015-sdk-graduation-and-publish-topology.md)

## Development

```bash
pnpm install
pnpm typecheck && pnpm build && pnpm lint && pnpm license-check
pnpm test                    # unit + struct + façade corpus-vector tests
pnpm test:permissiveness     # the mutation gate
pnpm conformance             # 283/283 + key census (vendored v1 snapshot)
pnpm conformance:v2          # 268/268 + key census (vendored v2 snapshot)
```

## License

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
