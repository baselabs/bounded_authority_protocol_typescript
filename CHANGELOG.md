# Changelog

All notable changes to `@bounded-authority/verifier` are documented here.

## [0.2.0] — 2026-09-14

### Added

- Per-language mutation-gate entries for v2 assembly revalidation (the reference's
  `validate_assembled_compact`): a well-formed signing input whose payload violates the
  profile must not assemble — the closed member set (grant/anchor/transition), the
  canonical-payload binding (the segment must equal the JCS encoding, anchor/transition), and
  the anchor genesis binding (sequence 0 carries the all-zero chain hash). Each leg is
  red-capable: mechanically removing the named check fails its test.

### Changed

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
