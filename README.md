# `@bounded-authority/verifier`

A provider-neutral, deterministic **verifier** SDK for bounded proof-of-possession authority — a
typed TypeScript reimplementation of the BAP v1 verification profile.

This is one of two cross-language verifier SDKs ([ADR 0014][adr14]) that reimplement the frozen v1
profile from the published [spec][spec] and [conformance corpus][corpus] alone, with no code-level
derivation from the Elixir reference. It is a **verification** library: a successful result proves
only that caller-supplied bytes satisfy caller-supplied trusted inputs and expected context. It never
selects trusted keys, reserves replay, grants execution, or overrides a host policy.

[adr14]: https://github.com/baselabs/bounded_authority_protocol/blob/main/docs/adr/0014-cross-language-verifier-sdks.md
[spec]: https://github.com/baselabs/bounded_authority_protocol/blob/main/docs/protocol-v1.md
[corpus]: https://github.com/baselabs/bounded_authority_protocol/blob/main/priv/conformance/v1/corpus/

## Status

`0.1.0` — SemVer 0.x (pre-1.0). The public v1 façade is frozen; breaking changes bump the major
version once 1.0 lands. The SDK targets Node `>= 22` and has **zero runtime dependencies** (Ed25519
via `node:crypto`; SHA-256, base64url, and JSON canonicalization hand-rolled from the RFCs).

## Conformance

This SDK is certified against the published corpus (`priv/conformance/v1/corpus/`) and passes every
one of its **280** valid + invalid vectors, recomputed from scratch — not cached verdicts. The
conformance runner asserts the corpus `index.json` SHA-256 at startup
(`c3b0bcf7665c217ea45843a9c49c2769a61c21c4998d8b85249cf6cb757084dd`), so a consumer who vendors a
mismatched corpus snapshot gets a hard failure rather than a silent drift ([ADR 0014 D4][adr14]).

```bash
pnpm install
pnpm conformance   # 280/280 + two-boundary key census
```

Permissiveness is invisible to corpus agreement by construction, so each parser-layer closure is
additionally proven **red-capable** by a per-language mutation-gate
(`pnpm test:permissiveness`) — the ADR 0005 discipline applied per-language: construct the host-specific
defect the closure defeats, assert the SDK rejects it, and prove the test goes red when the closure is
mechanically removed ([ADR 0014 D6/D7][adr14]).

## Install

```bash
pnpm add @bounded-authority/verifier
# or
npm install @bounded-authority/verifier
```

## Quickstart — verify a grant

`verifyGrant` checks a compact-JWS grant against a caller-trusted issuer key and expected context
(issuer, audience, evaluation time, clock skew, bounds). It returns `Ok<GrantFacts>` on success or
`Err(Invalid)` on any failure — never a decision.

```ts
import { verifyGrant, ok, err } from "@bounded-authority/verifier";

// The raw compact-JWS grant bytes (ASCII), produced out-of-band by an issuer.
const grantCompact = Buffer.from(
  "eyJhbGciOiJFZERTQSIsInR5cCI6ImJhK2NhcCIsImtpZCI6Imlzc3Vlci1rZXkifQ."
  + "<payload>.<signature>",
  "ascii",
);

const result = verifyGrant(
  grantCompact,
  {
    keyId: "issuer-key",                       // must match the grant header `kid` exactly
    publicKey: issuerPublicKey32,              // raw 32-byte Ed25519 public key
  },
  {
    issuer: "https://issuer.example",
    audience: "https://resource.example",
    evaluationTime: 1_731_728_000,            // caller-supplied, seconds since epoch
    clockSkew: 60,
  },
);

if (result.ok) {
  const facts = result.value;                  // GrantFacts — value-bearing, redacted
  facts.issuerKeyFingerprint;                  // Uint8Array(32) — raw SHA-256 thumbprint
  facts.holderThumbprint;                      // Uint8Array(32) — the bound holder key
  facts.authorization;                         // "not_evaluated" — NOT a decision
} else {
  // result is { ok: false } — a closed, value-free rejection. Any structural,
  // signature, header, claim, or time-window failure lands here. The SDK fails
  // closed and carries no detail (mirrors {:error, :invalid}).
}
```

The `Result<T>` shape mirrors the Elixir `{:ok, value} | {:error, :invalid}`: `{ ok: true, value }` or
`{ ok: false }` — the failure branch carries no value and no reason. There is no `allowed`,
`authorized`, `decision`, or receipt — facts are value-bearing and redacted, never execution
credentials.

## The public façade

The 17 frozen v1 functions ([protocol-v1.md § Public verification contract][spec]):

| Function | Returns | Purpose |
|---|---|---|
| `verifyGrant` | `Result<GrantFacts>` | Verify a compact grant against a trusted issuer + expected context |
| `checkEnvelope` | `Result<EnvelopeFacts>` | Re-verify the grant and bind the holder proof, request, nonce, and selectors |
| `decodeGrant` / `decodeProof` | `Result<GrantDecoded\|ProofDecoded>` | Structural decode (verification: not_evaluated) |
| `untrustedKeyLocator` | `Result<KeyLocator>` | Header-only key id (trust: not_evaluated) |
| `requestDigest` | `Uint8Array(32)` | Typed, type-preserving request hash (`BAP1-REQUEST` prefix) |
| `encodeConsumptionEntry` / `checkChain` | `Result<EncodedConsumptionEntry\|ChainFacts>` | Canonical consumption rows + range verification |
| `grantSigningInput` / `proofSigningInput` | `Result<SigningInput>` | Deterministic producer signing inputs |
| `assembleCompact` | `Uint8Array` | External signature assembly (no private keys in the SDK) |
| `boundaryAnchorSigningInput` / `keyTransitionSigningInput` | `Result<SigningInput>` | Anchor + historical-key-transition producers |
| `encodeAnchoredExport` / `verifyAnchoredExport` | `Result<EncodedAnchoredExport\|AnchoredExportFacts>` | Deterministic archive framing + atomic verification |
| `verifyHistoricalAnchor` / `verifyKeyTransition` | `Result<AnchorFacts\|KeyTransitionFacts>` | Historical boundary + authenticated rollover verification |

Plus the versioned primitives: `jwkEncodePublic`, `jwkDecodePublic`, `thumbprint`,
`uriNormalize`, `boundsNew`, `boundsMaximum`, `jcsEncode`, `base64urlDecode`/`Encode`, and the tagged
JSON algebra. See [`src/index.ts`](src/index.ts) for the full export list.

## What this SDK does NOT do

It is a **verifier**, not an authority runtime. It holds no private keys, makes no network or
filesystem calls, reads no clock (`evaluationTime` is an explicit input), and performs no replay
reservation, revocation check, or policy decision. Selecting trusted keys, reserving replay, and
granting execution belong to the host — a `GrantFacts`/`EnvelopeFacts` value is evidence, not a
credential. See [AGENTS.md § Critical rules][agents] and [ADR 0014 D3][adr14].

[agents]: https://github.com/baselabs/bounded_authority_protocol/blob/main/AGENTS.md

## Development

```bash
pnpm install
pnpm typecheck       # tsc --noEmit, strict (noUncheckedIndexedAccess + exactOptionalPropertyTypes)
pnpm lint            # eslint . — includes the library-path purity rule (no I/O/clock/RNG/network in src/)
pnpm license-check   # dependency-license gate (zero runtime deps expected)
pnpm test            # unit + struct + façade corpus-vector tests
pnpm conformance     # 280/280 + two-boundary key census
pnpm test:permissiveness   # the per-language mutation-gate
```

## License

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
