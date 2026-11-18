# Contributing

```bash
pnpm install --frozen-lockfile
pnpm typecheck && pnpm build && pnpm lint && pnpm license-check
pnpm docs:api                # strict TypeDoc reference in site-dist/api-development, stamped with package version
pnpm test:network            # real npm release API, normative spec anchors and built-site version checks
pnpm test                    # builds, then unit, struct and facade tests and every docs sample
pnpm test:permissiveness     # the mutation gate
pnpm conformance                       # vendored contract-major v1, including its key census
pnpm conformance:v2                    # vendored contract-major v2
pnpm conformance:v3                    # vendored contract-major v3
pnpm conformance:role-attestation      # and the cross-profile legs
pnpm conformance:content-assertion     # and producer/assembly byte agreement
pnpm conformance:strict-ed25519        # strict-Ed25519 verdicts
pnpm conformance:local-loopback-http   # local-loopback proof verdicts
pnpm conformance:producer-canonicality # producer-surface canonicality verdicts
pnpm conformance:selector-float-zero   # selector float-zero verdicts (decode, producer, envelope)
pnpm test:portable           # unit tests and the mutation gate under --conditions=bap-portable
pnpm conformance:portable              # every corpus under the portable backend (same verdict digests)
pnpm typecheck:browser       # src/ under DOM + ES2022, no ambient types
pnpm guard:browser           # browser bundle: portable backend only, no unresolved globals or eval
pnpm size                    # browser bundle-size budget
pnpm pack:release            # the release tarball, packed from a staging copy (build first)
pnpm test:tarball            # packed tarball: consumer typecheck and Node/Deno/Bun runs
pnpm test:runtimes           # Deno and Bun conformance lanes (BAP_RUNTIMES=deno,bun)
pnpm test:browser            # Playwright lanes (BAP_BROWSERS=chromium,firefox,webkit)
pnpm check:corpus            # complete snapshot and documentation self-consistency (offline)
pnpm check:corpus:artifact   # real Hex identity, both checksums, and whole-tree byte comparison
pnpm secrets                 # full-history, sensitivity, staged and unstaged secret scans
pnpm check:currency          # dependency-currency gate (latest-first)
pnpm test:readback           # post-publish read-back
pnpm readback <version> --sha256 <hex>  # read back a release: registry, bytes, provenance, signatures, fresh consumers
```

TypeDoc discovers entry points from `package.json`'s `exports` map; `typedoc.json` deliberately
leaves `entryPoints` unset so a new public subpath cannot bypass documentation coverage. Build the
bench with `pnpm build:site` before `pnpm docs:api`: the site builder recreates `site-dist`, and the
development API build adds `site-dist/api-development`. CI rejects undocumented declarations and warnings. The Pages
workflow uploads both outputs together. `pnpm docs:api` is the local, strict source-tree build.
The hosted `/api-development/` uses that strict source build. The hosted `/api/` uses `pnpm docs:api:release`, built from the npm-latest release tag and stamped
"released vX.Y.Z", with version, tag and commit recorded in `release.json`.

Run `pnpm notebooks:local` and `pnpm notebooks:published` with the pinned Deno and Python
versions and `uv sync --frozen`. Both use the real Deno Jupyter kernel. Install it with
`uv run --frozen deno jupyter --install`. Every authored TypeScript fence, TSDoc example and
`docs/examples/` module is discovered and tested. Keep the ordered docs manifest current; every
notebook must have persisted safe semantic output and clean up its resources.

Qualification runs once on `kci/**`; the last `qualified` job requires every lane. Publication
and Pages are maintainer-dispatched on the default branch with their existing environment gates.
Contributors do not publish, tag or dispatch workflows. Report vulnerabilities through the
[security policy](SECURITY.md). Use real services and real signatures in integration tests.
