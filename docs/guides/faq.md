# FAQ

## Does success authorize execution?

No. It proves the supplied bytes satisfy the supplied trusted key and expected context. The host
owns replay reservation, revocation, policy and execution. Facts retain explicit unevaluated markers.

## Can I use a decoded key locator to establish trust?

No. It is a hint into an already enrolled key set. Unknown keys refuse; a signature binds the key
selected by the host only when verification succeeds.

## Does a new proof avoid replay?

No. The invocation tuple survives refreshed proofs until the grant can no longer verify anywhere.
Nonce lifecycle and invocation replay are distinct host responsibilities.

## Why can facts be read but not stringified?

To reduce accidental disclosure. Explicit approved-field projections remain possible and need host
review. Persist content lineage in a protected schema, not a general log sink.

## Is a browser result evidence of authority?

No. It is display-only. Scripts and extensions can alter the artifact, expected inputs and answer.
A trusted host must verify raw credentials independently.

## Is package version 2 wire major 2?

No. Package 2.0.0 supports wire majors 1, 2 and 3. Select the root, `v2` or `v3` explicitly;
profiles do not negotiate or fall back. See [contract majors](contract-majors.md).

## Where are signing keys stored?

Outside this verifier. The companion signer 2.0.0 depends on verifier `^2.0.0` and delegates to
caller-owned handles. The verifier accepts public keys only. Notebooks generate temporary
in-memory demonstration keys and never print or persist them.

---

Documentation navigation: [Previous: Adopt a certified corpus](corpus-adoption.md) · [Next: Glossary](glossary.md)
