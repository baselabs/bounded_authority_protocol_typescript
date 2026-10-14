# Changelog

All notable changes to `@bounded-authority-protocol/verifier` are documented here.

## [Unreleased]

Documentation only. No library behavior, public API or verdict changes.

### Documentation

- README rewritten for a first read: what the package is and is not, a quickstart that issues and
  verifies a grant, and links to new task guides under `docs/guides/` (verify requests,
  contract-majors 2 and 3, rotate keys, consumption chains and archives, role attestations, content
  assertions, handle errors, test your integration) and a complete API reference in
  `docs/reference.md`.
- Every `ts` sample in the README and in `docs/` is now typechecked against the source and run on
  both backends by `pnpm test` (`test/docs-samples.test.ts`), which also fails if the reference
  misses a public export or if its bounds table drifts from `MAXIMA`. CI no longer skips pushes
  that change only Markdown.
- TSDoc on every exported function, so editors show its contract on hover.
- Corrections: the README API table showed `requestDigest` and `assembleCompact` returning bare
  bytes (both return `Result<Uint8Array>`); the README said the signer produces majors 1 and 3
  (signer 0.5.0 signs majors 1, 2 and 3); the v2 example passed an untagged selector bound;
  `NOTICE` named the retired `@bounded-authority/verifier` package; the bench page said the
  package has zero runtime dependencies (it has three since 0.7.0) and that the verifier never sees
  keys (it takes public keys).

## [0.7.0] — 2026-10-13

Browser-safe builds. The package now loads and runs in browsers, Deno, Bun and workers, with no
`node:crypto`, no `Buffer` and no other Node API outside the Node backend, and with verdicts
identical to Node. The public API keeps its shape (synchronous, `Result<T>`); everything below is
additive except the internal types noted under deep imports. No verdict changes.

### Added

- A portable crypto backend (pure JavaScript over `@noble/ed25519`, `@noble/curves` and
  `@noble/hashes`) beside the `node:crypto` one, selected by the package's `"imports"` conditions
  `bap-source`, `bap-portable`, `deno`, `bun`, `workerd`, `worker`, `node`, `types`, `default`:
  Node.js keeps `node:crypto` by default; browsers, bundlers targeting them, Deno, Bun and builds with
  the `workerd` or `worker` condition get the portable backend; Node.js gets it too under
  `--conditions=bap-portable`. A build that sets `node` and none of the earlier conditions (webpack's
  Electron targets, esbuild `--platform=node`, Rollup with `exportConditions: ["node"]`, Vite SSR)
  gets the node backend. `bap-source` is a development condition for this repository's tests; its
  targets are in `src/`, which is not shipped, so consumers must not set it. The portable Ed25519 check is the
  explicit cofactorless equation behind the unchanged rule S1 gate (noble's own verify is cofactored in
  both of its modes and is not used); portable P-256 passes `lowS: false`, so the profile's low-S gate
  stays the only one; neither backend uses WebCrypto.
- `BACKEND_ID` (`"node"` or `"portable"`, type `BackendId`): which backend this build resolved.
- `es256VerifyStrict(message, signature, publicKey)`: the synchronous, never-throwing ES256 sibling of
  `verifyStrict` (uncompressed on-curve P-256 key, `0 < r < n`, `0 < s <= (n - 1) / 2`, then the
  backend). An SDK helper mirroring `REQ3-SIGNING-*`; the Elixir reference has no public counterpart.
- An `"exports"` map (`"."`, `"./package.json"`, and a `"./*"` passthrough) and `"sideEffects": false`.
- Scripts: `test:portable` and `conformance:portable` (the unit, mutation and conformance gates under
  the portable backend), `conformance:local-loopback-http`, `typecheck:browser`, `guard:browser`,
  `size`, `test:tarball`, `test:runtimes` (Deno, Bun) and `test:browser` (Playwright).

### Changed

- Three runtime dependencies, pinned exactly and MIT-licensed, loaded only by the portable backend:
  `@noble/ed25519` 3.2.0, `@noble/curves` 2.4.0 (which depends on `@noble/hashes`) and
  `@noble/hashes` 2.4.0. The package previously had none. `tools/license-check.mjs` and `NOTICE` list
  them.
- Node.js verdicts are unchanged. Every certified corpus's verdict digest (SHA-256 over the canonical
  JSON of `[case id, verdict]` per case, `conformance/verdict-digests.json`) was recorded from the
  0.6.0 source and is reproduced by both backends on Node 22.23.1 and 24.19.0, on Deno 2.5.6 and Bun
  1.3.14, and in Chromium 153 (observed locally; CI also runs Firefox and WebKit): v1 `c90b903a…` (283), v2 `72176430…` (268), v3 `79aa0344…` (292),
  local-loopback-http `8b6f4ecf…` (44), role-attestation `e27f5ce5…` (40), content-assertion
  `9207c4cc…` (154), strict-ed25519 `cf0fe815…` (2410).
- **API behavior change.** `sha256` (exported from the package root and the `v2` and `v3`
  namespaces) now throws `InvalidError`, the package's closed error, for any part that is not a
  `Uint8Array` (a subclass such as Node's `Buffer` still is one), identically on both backends. 0.6.0
  coerced strings, number arrays, `ArrayBuffer`s and other typed arrays through `Buffer.from` and hashed
  a `DataView` as empty input. The internal `sha256Concat` applies the same rule and also requires an
  array.
- The node backend's P-256 key import now requires exactly 65 bytes with the `0x04` prefix itself, as
  the portable backend does; a hybrid (`0x06`/`0x07`) or other prefix was previously imported as the
  same point. Every profile already refused such keys before reaching the backend, so no verdict
  changes.
- The Pages bench builds this repository's source on the portable backend. Its `node:crypto` adapter
  remains only for the published signer it imports for demo issuance, and delegates to the portable
  backend.

### Deep imports

The new `"exports"` map changes which deep imports resolve. Fully specified paths with the `.js`
extension, such as `@bounded-authority-protocol/verifier/dist/src/v3.js`, keep resolving through the
`"./*"` passthrough. Extensionless deep paths, such as `.../dist/src/v3`, which bundlers and
TypeScript's `node10` resolution used to complete, no longer resolve. The crypto backends
(`dist/src/crypto/*`) are not exported at all, so the ungated backends cannot be deep-imported; they
are reachable only through the package's own `"#crypto"` import. Deep imports remain unsupported API
and may be closed in a future 0.x minor; import from the package root. In this release the internal `importPublicKey`, `ed25519Verify`,
`importEcPublicKey` and `es256Verify` (reachable only by deep import) take and return an opaque
`BackendPublicKey` instead of a `node:crypto` `KeyObject`, so no published declaration references
`node:crypto` or any DOM type.

### Maintenance

- The conformance runners are split into runtime-neutral cores (`conformance/core/`) with thin
  loaders, so the same verdict logic runs on Node, Deno, Bun and in browsers; every runner holds its
  verdict digest to the pin.
- Guards, each with a red-proof against the real configuration: a browser typecheck
  (`tsconfig.browser.json`); lint rules banning every Node built-in module and Node global (also
  through `globalThis`), dynamic `import()`, `eval`, implied eval and the `Function` constructor in
  `src/`, and allowing `@noble` only in the portable backend through verification and hash entry
  points; a scope-aware unresolved-globals scan of the browser bundle; a packed-tarball consumer
  typecheck with `skipLibCheck: false` under each resolution, library and condition set; and a
  bundle-size budget at the first measurement plus 10%.
- CI (Linux only) adds the portable-backend gates, Deno and Bun lanes, Playwright Chromium, Firefox
  and WebKit lanes under a strict CSP, the tarball check, and `npm audit signatures`; the release gate
  runs the same lanes. Linux WebKit is evidence for this pure-JavaScript verifier only, not for Safari.
- The 0.6.0 playground-shim test is retargeted to the portable backend with its coverage kept.
- The bench's demo-issuance dev dependency moves to `@bounded-authority-protocol/signer` 0.4.0.

## [0.6.0] — 2026-10-13

Strict Ed25519 verification: reject small-order and non-canonical keys and points. Security
advisory: [GHSA-prrq-qm8j-7j67](https://github.com/baselabs/bounded_authority_protocol_typescript/security/advisories/GHSA-prrq-qm8j-7j67). Before 1.0 the
minor position is the breaking boundary, so this release also carries the API and behavior changes
below.

### Added

- `verifyStrict`, `acceptablePublicKey` and `torsionFree` (exported from the package root), the
  TypeScript spelling of rule S1. `verifyStrict` is total (wrong widths and non-byte input return
  `false`, it never throws). `acceptablePublicKey` is the key-entry check: canonical, not one of the
  eight small-order encodings, and on the curve. `torsionFree` additionally requires `[L]A = O` in pure
  BigInt arithmetic (no new dependency); a host calls it at key enrollment, at trust install, and
  before any deny-list or revocation comparison, never on the verify path.
- The `conformance:strict-ed25519` command over the vendored, additive strict-Ed25519 corpus (2410
  cases in 14 families; index SHA-256
  `732117dfe1881b553998126a9524a95bfb1171257e388d5430a0a099f2287cb9`), run in local, CI and release
  verification. The existing v1, v2, v3, loopback, role-attestation and content-assertion corpora and
  their pins are unchanged.
- A Node 24.19.0 CI leg beside Node 22.23.1; verdicts are identical on both.

### Changed (verdicts in shipped profiles)

- Every Ed25519 verification applies rule S1 before the backend: the key and the signature point must
  be canonical encodings, neither may be a small-order encoding, and `S < L`; the backend then
  computes the cofactorless equation. Only inputs that no conforming signer emits change from accept
  to reject, and no existing corpus verdict changes.
- A key that fails `acceptablePublicKey` is refused with the closed error wherever it enters: trusted
  issuer, historical and archive keys, proof-header JWKs, the role-attestation subject key (also at
  decode), and every producer input.
- **API behavior change.** The JWK functions are now fallible for such a key: `jwkFromPublicKey`,
  `jwkEncodePublic`, `thumbprintPreimage`, `thumbprint`, `thumbprintRaw` and `publicKeyThumbprintRaw`
  throw `InvalidError`, and `jwkDecodePublic` returns the closed error. The raw hash-only
  `thumbprintDigestUnchecked` (internal, not exported from the package) serves censuses and generators;
  the v1 and v2 conformance censuses use it.
- The browser playground shim verifies with an explicit cofactorless check behind the same gate instead
  of the default noble verify (which is cofactored).

### Fixed

- JCS string encoding: the UTF-8 validator masked the lead byte too narrowly, so it rejected valid
  text in U+0400 to U+047F, U+8000 to U+87FF and U+100000 to U+10FFFF (a false reject of the request
  digest and signing inputs the reference accepts) and admitted some invalid sequences (surrogates,
  values above U+10FFFF) that then threw a native error past the closed-Result contract. Every Unicode
  scalar value is now admitted byte for byte and every invalid sequence is a closed rejection.
- JCS string encoding no longer drops a leading U+FEFF from a string value or member name.

### Maintenance

- Test fixtures that used all-zero or repeated-byte placeholders as public keys now use generated keys,
  each with a positive control proving the key reaches and passes key acceptance.

## [0.5.0] — 2026-09-27

The content-assertion release. Before 1.0 the minor position is the breaking boundary, so this
release is also the package-major step for the identifier-admission tightening below.

### Added

- The explicitly selected `contentAssertion` namespace for the standalone
  `bap-content-assertion/1` profile: bounded exact-content hashing, external-signature
  production and assembly, structural decode, explicit-context verification, and pairwise
  successor comparison. Facts retain the non-authorizing posture.
- The tightenable `content_bytes` ceiling (65,536 maximum), real-Ed25519 behavior tests,
  in-memory source-mutation checks, and the `conformance:content-assertion` command over the
  vendored revision-1 corpus (131 assertion, 9 digest, 14 successor cases; index SHA-256
  `14b7436ccf7cc91fece52a1578c3760df6720a93494d147ee5ab523e2ce21876`) in local, CI, and
  release verification. Matches protocol package 0.7.0.

### Changed (verdicts in shipped profiles)

- Tighten shared StringOrURI admission in the v1, v2, v3, and role-attestation profiles:
  reject repeated fragment delimiters, raw brackets in userinfo or outside authority, and
  malformed bracketed IPv6 hosts such as `http://[abc]/x`. Compressed IPv6 and valid final
  IPv4 groups remain accepted; escaped userinfo brackets remain accepted. Identifier
  validation preserves the original bytes; target-URI normalization keeps its existing
  reference behavior.

### Fixed

- Reject unknown structural bounds keys before formatting errors, so malformed inputs keep
  the closed result.

### Maintenance

- CI runs on Linux only; macOS and Windows jobs are removed. Developer portability is
  unchanged.
- Dev dependencies moved to latest: `@types/node` 26.6.3 and
  `@bounded-authority-protocol/signer` 0.2.1. TypeScript stays on 6.0.3: a 7.0.2 probe failed
  typecheck (the compiler API the mutation tests use is absent) and lint (typescript-eslint
  8.70.1 peers `typescript <6.1.0`).

## [0.4.1] — 2026-09-23

### Fixed

- **Producer/consumer bounds agreement on emitted bytes** (the cross-vendor finding-4 class,
  transferred from the protocol repository's repair patch 0.6.1): `attestationSigningInput`
  now enforces the caller-resolved limits on what it EMITS — encoded and decoded
  `segment_bytes`, `json_bytes`, `jcs_bytes` over the emitted payload JSON, and the
  projected `compact_bytes` (segments + separators + the 86-char signature encoding) — so the
  producer cannot mint bytes its own decoder rejects under the caller's bounds. Each gate is
  injection-proven red-capable against its named leg. The emitted-number-lexeme class is
  closed one layer down: any exponent-form integer is far past the shared JCS encoder's
  2^53−1 magnitude bound (probe: `jcsEncode` throws `jcs: integer bound`); a producer-side
  lexeme gate is structurally unreachable in this surface and is documented in the test
  rather than shipped as dead coverage. No verdict changes on legal input (all four
  certified corpora agree at unchanged counts).


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

