# Changelog

## [Unreleased]

## [0.4.0] — 2026-09-23

The role-attestation release (ADR 0036 Decision 1.8: the first `0.x.0` bearing the
`bap-role-attestation/1` profile). Additive public surface — the `roleAttestation` namespace —
with zero verdict changes on existing input (all four certified corpora agree at unchanged
counts); the Result-contract sweep closes crash-past-`Result` and silent-coercion defects on
malformed caller context across the v1/v2/v3 façades.
### Fixed

- **Malformed caller context now fails closed on every contract-major surface** (the
  owner-authorized sweep of the cross-vendor review's m1/m2 findings, first closed for the
  role-attestation profile at its landing). `bounds.ts`'s `coerceBounds` and the leaf
  `resolve` reject a structurally malformed `Bounds` object — a non-object, a missing
  maximum table, or an `overrides` that is missing, `null`, a bare array of non-pairs, or a
  string — with the single closed error instead of throwing a native `TypeError` past the
  `Result` contract, and `untrustedKeyLocator` in v1/v2/v3 now COERCES its caller bounds
  (it resolved them ahead of any coercion, so a forged widening override was honored — the
  cross-vendor F2 class surviving in exactly one surface). Pinning note: a hand-rolled
  non-`Map` `ReadonlyMap` implementation now fails closed rather than iterating — an
  undocumented shape no documented producer ever emitted. The producers gain the field-level
  shape gates they lacked: `grantSigningInput` in v1/v2/v3 (previously a `null`/numeric
  `keyId` COERCED into a wire `kid` `"null"`/`"123"` — likewise a `null` operation name into
  `"name":"null"` — and nine other junk field shapes threw native `TypeError`s) and
  `boundaryAnchorSigningInput` in v1/v2/v3 (the same coercion class on `keyId`). The
  selector producer leaves harden the caller-shaped selector items in all three majors: a
  non-array `path` previously iterated as CHARACTERS when handed a string and was silently
  minted into the signed grant (`path: "abc"` → `["a","b","c"]` — a scope rewrite), numeric
  path members coerced to strings, and null selector/value/`values` items threw native
  `TypeError`s. No verdict changes on legal input: all four certified corpora, the census
  legs, and the pre-existing suites are unchanged; the context-fail-closed suite (new,
  RED-first) carries the 8+1 malformed-bounds shapes × 14 surfaces, the legal-bounds
  controls, and the grant/anchor/selector junk-field matrices across v1/v2/v3.

### Added

- **The `bap-role-attestation/1` sibling profile** (the protocol's ADR 0036; the release
  precondition for any `0.x.0` bearing the profile), exported as the `roleAttestation`
  namespace and re-derived from the normative sources alone (`spec/bap-role-attestation-v1.md`
  + the certified corpus — ADR 0014's no-derivation bar): a standalone, grant-unbound compact
  JWS under contract-major-1 mechanics (Ed25519/EdDSA, `BAP1-Ed25519-SHA256`) in which an
  attestor key binds a subject key to a role (`issuer`/`holder`) for a window contained in the
  attestor key's validity. Four surfaces — `attestationSigningInput` (external signature only;
  the SDK holds no private key), `assembleAttestationCompact` (revalidates header, payload
  member rules, segment bounds, and signature width before returning bytes),
  `decodeAttestation` (bounded decode, no trust evaluation), and `verifyAttestation` (the
  citation surface): closed header `{alg, kid, typ: "ba+role-attestation"}` and payload
  `{v, jti, key_id, public_key, role, nbf, exp}` sets, JCS canonical byte-equality on both
  segments, kid==attestor binding plus Ed25519 signature, subject binding by key-id equality
  and raw public-key byte-equality, self-attestation rejected on either leg (thumbprint or key
  id), window containment with `exp == valid_before` accepting, and the half-open
  `now ∈ [nbf, exp)`. The attestor context (`HistoricalPublicKey`) window endpoints and `now`
  are integer- and magnitude-bounded (2^53−1) — the `verifyHistoricalAnchor` parity the
  sibling Python/Go legs landed without and repaired same-day. `AttestationFacts` carry the
  anchor posture (`verification: "signature_and_window"`, `trust: "not_evaluated"`, RFC 7638
  fingerprints, and NO authorization marker). Parsed by no contract-major: attestation bytes
  reject at the v1/v2/v3 surfaces and a live v1 grant rejects at attestation decode.
- The vendored certified role-attestation corpus snapshot
  (`conformance/corpus-role-attestation`, revision 1, 40 cases, index SHA-256
  `be5275c69539a0f31734242ff00a484c2f855f39181c55689d8b0f671195d62a` pinned at load; the exact
  two-file set, profile identity, revision, and case counts verified before the per-file
  digests are trusted) plus `conformance/run_role_attestation.ts`: 40/40 decode + verify
  agreement, producer/assembly byte symmetry against the certified valid compact, and
  cross-profile rejection in both directions. Wired into CI and the release lane's
  verification gate (`pnpm conformance:role-attestation`).
- Permissiveness mutation-gate battery for the profile's named closures (14 defect-injection
  entries; twelve red-proven within the battery's run with exactly one targeted test each, two
  adjudicated by injection): attestor window-endpoint magnitude, non-integer `now` (a
  fractional now inside the window would otherwise verify), self-attestation ×2 (each leg
  discriminated on the wire, behind no other gate), containment ×2, the half-open now window,
  kid binding, subject raw-byte binding, role closed set, canonical payload bytes, the
  signature gate, the protected-header canonical gate, and the `nbf`/`exp` integer tags. Two
  adjudications from the injection driver, both verified rather than assumed: the `v`
  integer-tag distinction is byte-level redundant (JCS re-encodes `1.0` to `1`, so the
  canonical gate subsumes float lexemes for `v` — relaxing the tag check changed zero
  verdicts), while float `nbf`/`exp` endpoints are canonical (`1000.5` re-encodes
  byte-identically) and carry their own red-proven closure. The first cross-vendor review
  pass caught the two missing closures (header canonical, window integer tags) plus a
  double-encoded test header; all repaired with re-run red proofs and the full battery.
- `SigningInputKind` gains `role_attestation` (the `assembleSegments` kind list; assembly for
  every existing kind is byte-unchanged) — the TypeScript form of ADR 0036 D7's labeled
  kind touch.

## [0.3.0] — 2026-09-22

### Added

- **Wire contract-major 3 — the `BAP3-ES256-SHA256` suite** (the protocol's ADR 0035 activation),
  exported as the `v3` namespace and re-derived from the normative sources alone
  (`spec/bap-v3.md` + the incorporated v1/v2 sections + the certified corpus): ECDSA over NIST
  P-256 with SHA-256 (`alg: "ES256"`), `v: 3` payloads, the `BAP3-REQUEST\0` / `BAP3-CHAIN\0` /
  `BAP3-ARCHIVE\0EXPORT\0` domain separators, and the v2 selector algebra (all five kinds)
  incorporated unchanged. Suite specifics: raw public keys are 65-byte uncompressed SEC1
  points (`0x04||x||y`) with pure-arithmetic coordinate-range and on-curve validation before
  any backend; the proof JWK is exactly `{crv:"P-256", kty:"EC", x, y}` with the RFC 7638
  thumbprint over that member set; signatures are the RFC 7518 §3.4 raw `r||s` form (64 bytes)
  with `0 < r < n`, `0 < s ≤ (n−1)/2` — low-S required and load-bearing (Node's backend
  accepts the malleable high-S counterpart; the mutation gate proves the gate red-capable).
  Every v1 and v2 artifact rejects under `v3` with the single closed error, and vice versa.
- New modules `src/es256.ts` (the P-256 arithmetic + `node:crypto` ECDSA layer, with its own
  census tracking for the runner's verify-import leg) and `src/ec_jwk.ts` (the EC JWK
  encode/decode/thumbprint layer); `src/v3.ts` mirrors the v2 façade module exactly.
- The vendored v3 corpus snapshot (`conformance/corpus-v3`, 292 certified vectors, index
  SHA-256 pinned at load) plus the curated census sidecar (`conformance/curated-inputs-v3.json`),
  byte-synced from the monorepo; `conformance/run_v3.ts` recomputes every verdict (292/292
  agree) and runs the census legs (curated == index two-way; discovery ⊆ declared;
  verify-import ⊇ expected-verify keys).
- Corpus-repair rotation (same slice): the certified v3 corpus was repaired upstream — the
  signing-input case files had carried v2-shaped 32-byte Ed25519 public keys, so their
  valid-class cases were mislabeled verdict invalid; inputs were re-keyed to v3 EC shapes and
  expected re-derived. The vendored snapshot was re-synced byte-for-byte (`rsync -a --delete`),
  the certified index pin rotated to the re-certified digest
  (`a5c8075e7534345c3bb6611d0b40292904bcfa3af0702e07ae014fa66926433c`, base64url
  `pcgHXnU0NFw7tmEdC0ApKQS8-jrwcC4HrgFPpmkmQzw`), and the curated census sidecar re-vendored
  (11 keys; discovery stays a strict 8-of-11 subset). 292/292 agreement re-proven; the v1/v2
  corpora and pins are unchanged.
- Permissiveness mutation-gate battery for the ES256 closure classes (7 defect-injection
  entries, each red-proven at authoring): low-S acceptance, r/s integer range (the
  encoding-level ordering pin — OpenSSL rejects zero/≥n itself, so the verdict legs stay green
  without the gates), EC JWK member set, coordinate width (via an on-curve x=256 falsifier
  whose short spelling passes every arithmetic gate), coordinate range + on-curve (via the
  x=p/√b pair, which satisfies the curve equation so only the `< p` gate rejects it), and the
  cross-major `v` gate (same-header v-swap falsifiers; v1/v2 bytes also reject at the `alg`
  gate). The census verify-import leg closes over the ES256 boundary.
- CI: a third conformance lane (`pnpm conformance:v3`) on every OS of the tri-platform matrix;
  `.gitattributes` extends the byte-exact eol exemption to `conformance/corpus-v3/**`. The
  release lane now runs the same three-corpus verification gate before staging (it had been
  left at v1+v2 when the corpus landed) and enforces tag/manifest version match — the signer
  lane's guard, back-ported.
- **The verifier bench** — this package's public GitHub Pages site: the real verify path
  running in the visitor's browser. A static bundle built from this repository's verifier
  source plus the published signer package (demo issuance only; no backend, deploy-only
  permissions): check an envelope, decode grants and proofs, and read the cryptographic facts,
  with keys minted in the browser that never leave it. The page's npm badge tracks the
  released version.
- README: the contract-major 3 sections — the majors table row (the `BAP3-ES256-SHA256` suite
  summary), the `v3` namespace walkthrough, the 292-vector corpus count, and the
  versioning statement now reading "majors 1, 2, and 3".

## [0.2.2] — 2026-09-17

No library-code change — toolchain and documentation alignment with the protocol family's
2026-09-17 state (BAP 0.4.1, the tri-platform build bar, the dependency-currency gate).

- BAP 0.4.1 (published 2026-09-17; no wire-format or public-API change): the vendored
  v1, v2, and local-loopback conformance snapshots were compared byte-for-byte against
  the monorepo's `priv/conformance` at `main` — no delta, so no corpus rotation was
  required.
- Tri-platform CI (the family build bar): the verify battery now runs on ubuntu-24.04,
  macos-latest, and windows-latest — observed green on all three lanes — and a
  `.gitattributes` eol policy keeps the byte-exact corpora conversion-free on any clone.
- Dependency-currency gate (latest-first, the family ADR 0032 shape):
  `tools/check-currency.mjs` classifies `pnpm outdated` data with the canonical
  `semver` range resolver — in-range resolvable drift fails (never pinnable),
  deliberate pins cover only out-of-range latests and carry inline reasons
  (typescript stays on 6.x pending the 7.x native-compiler review), and an
  unverifiable currency state fails closed. Dev dependencies refreshed to latest:
  tsx 4.23.13, @types/node 26.6.1, eslint 10.10.0, typescript-eslint 8.70.0,
  semver 7.8.5 (the gate's resolver).
- Node toolchain pinned in lockstep: `.tool-versions` (asdf, 22.23.1 — the family pin)
  and CI's `node-version` agree; `engines.node >= 22` stays the consumer-facing floor.
  The release lane pins its Node exactly (24.19.0, matching the signer's lane) and
  SHA-pins `pnpm/action-setup` like every other action.
- README: "Pairing with the signer" — the three-role production flow (issuer signs,
  holder proves, resource verifies through this package), the key-custody and
  cross-validation properties, and related-package cross-links.

## [0.2.1] — 2026-09-14

- The first provenance-bound release of this package: identical library content to 0.2.0
  (which was terminal-seeded during the graduation rename and carries no registry
  attestation), published through this repository's release workflow under npm trusted
  publishing — the workflow stages with a signed provenance statement and a human approves
  under 2FA.

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

All notable changes to `@bounded-authority-protocol/verifier` are documented here.
