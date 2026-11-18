# Integration security

Verification is a deterministic predicate over caller-supplied bytes, trusted keys and expected
context. It neither establishes that a key deserves trust nor decides whether execution is safe.
The host's complete boundary is enrollment, reconstruction, verification, durable admission,
revocation and policy, followed by execution and recovery.

## Trusted-key enrollment

Enroll issuer and archive keys through an authenticated administrative channel. An untrusted
`kid` is only a bounded lookup hint into that store. Never fetch a key from an artifact-selected
URL, accept a presenter-supplied issuer key, or automatically trust an attestation's subject.
Call `acceptablePublicKey` and `torsionFree` for Ed25519 at enrollment, trust installation and
before deny-list/revocation comparisons. Major 3 requires an acceptable 65-byte uncompressed
P-256 point; use its checked thumbprint helpers. Associate each key with its permitted issuer,
role, contract major and validity window. Plan emergency removal independently of graceful
rotation. [Rotate keys](rotate-keys.md) contains executable enrollment and overlap recipes.

## Reconstruct exactly what will execute

Choose audience, issuer and operation from host configuration and routing. Use the actual method
and original target from the trusted ingress, and parse/cast arguments once with strict bounded
JSON. Retain integer versus float tags; ordinary JSON parsing can lose them. Include every input
that can affect execution in the signed argument projection. Reject duplicate credentials,
ambiguous paths, oversized bodies, unsupported media types and unknown wire profiles before work.

Terminate TLS at a configured ingress. Allowlist the public origin and proxy hops; reject
unexpected `Host` and forwarded origin values. Do not trust arbitrary `Forwarded` or
`X-Forwarded-*` headers. Preserve original paths across rewrites, normalize by the selected BAP
profile, and reject a mismatch rather than trying several candidate targets. HTTPS and the
nonce-mandatory literal-loopback profile are explicit separate choices.
[Request adapters](framework-integration.md) covers the whole class of host request boundaries.

## Time, admission and policy

Supply integer Unix seconds from the host's authoritative clock. Skew is at most 60 seconds and
proof age 1 to 300 seconds, with optional tighter bounds. Do not copy time claims into expected
time. Use the replay store's time, or account for the maximum clock difference across every
accepting process and the store. Reserve `(issuer, grantId, invocationId)` atomically before
execution through grant expiry plus the largest accepted skew. Refreshed proofs do not create a
new invocation. Nonce freshness does not replace replay persistence.

Check current revocation and host policy after verification and before execution. Treat key-store,
replay-store and revocation-store failures as failed admission. A verified role is not enrollment;
a verified content assertion is not schema validation, rollback protection or permission to load.
Keep highest accepted generations durably and define fork/bootstrap policy. Chains prove a
bounded range's consistency, not global completeness or absence of deletion.

## Limits and disclosures

Tighten bounds to the workload; never widen cryptographic widths. Cap accepted grant lifetimes
because replay records must survive that lifetime. Rate-limit unauthenticated work and bound
request concurrency. A closed `{ ok: false }` reveals no reason or partial data but still reveals
refusal. The package makes no constant-time or zero-information claim. The host controls status
mapping, timing, retries and diagnostic access. Return one stable refusal shape to callers.

Never log credentials, signed bodies, full facts, nonces or private material. Project only approved
fields; identifiers can be sensitive and high cardinality. Browser verdicts are display-only:
page scripts and extensions can alter both inputs and results. Trusted execution decisions require
a trusted host verifying raw credentials. See [operations](operations-observability.md) for failures,
monitoring and recovery, and [SECURITY.md](../../SECURITY.md) for reporting vulnerabilities.

---

Documentation navigation: [Previous: Durable replay reservations](durable-replay.md) · [Next: Operations and observability](operations-observability.md)
