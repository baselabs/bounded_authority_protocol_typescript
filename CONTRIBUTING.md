# Contributing

```bash
pnpm install --frozen-lockfile
pnpm typecheck && pnpm build && pnpm lint && pnpm license-check
pnpm docs:api                # strict TypeDoc reference in build-docs/api, stamped with package version
pnpm test:network            # normative spec anchors; released registry checks run after upload
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
leaves `entryPoints` unset so a new public subpath cannot bypass documentation coverage.
`pnpm docs:api` is the strict development-source check, writing only `build-docs/api` outside
the Pages artifact. CI rejects undocumented declarations and warnings. Pages builds `/api/`
from the immutable tag matching npm latest, using that tag's documentation and declarations.
Its version, tag and commit are recorded in `release.json`.

For notebooks, run `uv lock --check`, `uv sync --frozen` and `pnpm notebooks:local`
with the exact tool pins. The shared runner is
`scripts/check_notebooks.py`; it installs an isolated real Deno Jupyter kernel. See
[notebook checks](docs/notebooks/README.md) for archive-origin and saved-output checks.
Every authored TypeScript fence, TSDoc example and `docs/examples/` module is discovered and
tested. Keep guides in `docs/manifest.json` and notebooks in `docs/notebooks/registry.json`.
Every notebook must have saved safe semantic results and clean up its resources.

Qualification runs once on `kci/**`; the last `qualified` job requires every candidate lane.
Candidate notebook and consumer journeys install this repository's package from the packed candidate.
`publish.yml` runs published notebooks and the other registry checks after each upload in the
keyless `published-notebooks` job. That job waits up to ten minutes for npm to serve the exact
version. A maintainer can run `pnpm notebooks:published` and `pnpm docs:checks:published` on demand
once that version is available. The upload job and its environment gate are separate.

Publication
and Pages are maintainer-dispatched on the default branch with their existing environment gates.
Contributors do not publish, tag or dispatch workflows. Report vulnerabilities through the
[security policy](SECURITY.md). Use real services and real signatures in integration tests.
