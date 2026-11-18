# Integrator usage rules

- Import only from `@bounded-authority-protocol/verifier` and its explicit namespaces. Deep imports are closed.
- Select one wire profile deliberately; never try parsers until one accepts.
- Supply enrolled public keys, host-owned time and independently reconstructed request context.
- Treat decoded claims and key locators as untrusted diagnostics. Never fetch trust from their URLs.
- Check the result discriminant before accessing facts. Every closed failure refuses admission.
- Facts are not authority. Reserve replay durably, check revocation and host policy, then execute.
- Use integer Unix seconds and exact raw byte widths. Preserve tagged JSON numeric types.
- Enroll acceptable, torsion-free Ed25519 keys; use checked P-256 helpers for major 3.
- Retain replay tuples through grant expiry plus the largest accepted skew, under an authoritative clock.
- Treat storage and key-distribution failure as failed admission. Never discard a live reservation on retry.
- Project only approved logging fields. Do not serialize or spread whole facts into events or responses.
- Browser results are display-only. Trusted hosts verify raw credentials themselves.
- Generate demonstration keys only in example code; private keys never enter verifier functions.
- Validate signed content against the application's schema and persist rollback/fork protection separately.

Candidate notebook and consumer journeys install this repository's package from the packed candidate.
`publish.yml` waits up to ten minutes in the upload job for npm to serve the exact inspected
archive. Pending owner approval fails that run clearly; dispatch the same commit after approval.
The keyless `published-notebooks` job runs only after byte-for-byte registry read-back succeeds.
A maintainer can run `pnpm notebooks:published` and `pnpm docs:checks:published` on demand
once that version is available. The upload job and its environment gate are separate.
