# Security policy

## Reporting a vulnerability

Report a vulnerability privately through GitHub: open this repository's **Security** tab and choose
**Report a vulnerability** (or go to
<https://github.com/baselabs/bounded_authority_protocol_typescript/security/advisories/new>).
Private vulnerability reporting is enabled for this repository. Do not open a public issue, pull
request or discussion that contains an exploit, a private key, a credential, production data or
details of an unfixed vulnerability.

A useful report names the affected package version or commit, the protocol property that breaks
(for example "a grant verifies under a key it was not signed with"), a minimal reproduction that
uses generated keys and no production data, and the outcome you expected. We acknowledge, triage
and fix through the private advisory and coordinate disclosure there.

A vulnerability in the protocol itself (the specification, the conformance corpora, or the Elixir
reference) belongs to the protocol repository's own private reporting:
<https://github.com/baselabs/bounded_authority_protocol/security/advisories/new>.

## Supported versions

The latest published release line of `@bounded-authority-protocol/verifier` on npm is supported
(0.7.x). Releases before 0.6.0 accept Ed25519 signatures that the strict rule S1 rejects and are
deprecated on npm with a pointer to the advisory
[GHSA-prrq-qm8j-7j67](https://github.com/baselabs/bounded_authority_protocol_typescript/security/advisories/GHSA-prrq-qm8j-7j67);
upgrade to the latest release.

## What the package does and does not do

The package verifies bytes against the trusted keys, time and context you pass and returns redacted,
non-authorizing facts. It does not choose which keys to trust, hold private keys, reserve replay,
check live revocation or authorize an action; those belong to the service that uses it. A report
that a verified result was acted on without those host checks is about the host, not this package.

Releases from 0.2.1 on are published from this repository's release workflow through npm trusted publishing with
provenance; `npm audit signatures` verifies the registry signatures and attestations of an install.
