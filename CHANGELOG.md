# Changelog

## [Unreleased]

- Aligned with BAP 0.4.1 (published 2026-09-17; no wire-format or public-API change):
  the vendored v1, v2, and local-loopback conformance snapshots were compared
  byte-for-byte against the monorepo's `priv/conformance` at `main` — no delta, so no
  corpus rotation is required.
- Tri-platform CI (the family build bar): the verify battery now runs on ubuntu-24.04,
  macos-latest, and windows-latest, and a `.gitattributes` eol policy keeps the
  byte-exact corpora conversion-free on any clone.
- Dependency-currency gate (latest-first, the family ADR 0032 shape):
  `tools/check-currency.mjs` classifies `pnpm outdated` data — resolvable drift fails,
  deliberate pins carry inline reasons (typescript stays on 6.x pending the 7.x
  native-compiler review), and an unverifiable currency state fails closed. Dev
  dependencies refreshed to latest: tsx 4.23.13, @types/node 26.6.1, eslint 10.10.0,
  typescript-eslint 8.70.0.
- Node toolchain pinned in lockstep: `.tool-versions` (asdf, 22.23.1 — the family pin)
  and CI's `node-version` now agree; `engines.node >= 22` stays the consumer-facing
  floor.
- README: related-packages cross-links (the protocol monorepo, this package's npm page,
  and the `@bounded-authority-protocol/signer` sibling).

## [0.2.1] — 2026-09-14

- The first provenance-bound release of this package: identical library content to 0.2.0
  (which was terminal-seeded during the graduation rename and carries no registry
  attestation), published through this repository's release workflow under npm trusted
  publishing — the workflow stages with a signed provenance statement and a human approves
  under 2FA.

All notable changes to `@bounded-authority-protocol/verifier` are documented here.

## [0.2.0] — 2026-09-14

### Added

- Per-language mutation-gate entries for v2 assembly revalidation (the reference's
  `validate_assembled_compact`): a well-formed signing input whose payload violates the
  profile must not assemble — the closed member set (grant/anchor/transition), the
  canonical-payload binding (the segment must equal the JCS encoding, anchor/transition), and
  the anchor genesis binding (sequence 0 carries the all-zero chain hash). Each leg is
  red-capable: mechanically removing the named check fails its test.

### Changed

- **Package renamed `@bounded-authority/verifier` → `@bounded-authority-protocol/verifier`**
  before the second publication (the scope now matches the protocol repository naming). The
  `@bounded-authority/verifier` 0.1.0 seed stays on the registry permanently and is
  deprecated with a pointer to this package.
- README rewritten as the package landing page (wire contract-majors section, tagged-algebra
  quickstart for `v2.checkEnvelope`, consumer-oriented conformance and versioning sections).
- `dist/` now ships only the compiled library (`src/`); conformance runners and tests are no
  longer emitted into the published tarball.

## [0.1.0] — 2026-09-14

- First npm publication. Wire contract-majors 1 (283 certified conformance vectors) and 2
  (268 vectors, `lte`/`gte` range selectors) in one package; zero runtime dependencies;
  published as the SDK's graduated per-repository publish surface (the seed publish executed
  from the repository checkout under the owner's npm session; every subsequent release
  publishes from the release workflow via npm trusted publishing with provenance).
