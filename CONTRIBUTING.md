# Contributing

```bash
pnpm install --frozen-lockfile
pnpm typecheck && pnpm build && pnpm lint && pnpm license-check
pnpm docs:api                # strict TypeDoc reference in build-docs/api, stamped with package version
pnpm site --source=commit    # complete qualification site from HEAD, independent of own registry state
pnpm site                    # Pages site from npm latest, including release and version checks
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
Its package, version, `source: "release"`, tag and commit are recorded in `release.json`.
Qualification selects `source: "commit"` and records HEAD with its committed package version,
without a release tag.

`pnpm site` runs the web typecheck, bench build, API build, API checks, version checks and
browser bundle scan, in that order. The separate `site` qualification job selects
`pnpm site --source=commit` from a frozen install before any library build. Pages uses the same
ordered pipeline with the default release source. CI checks claims and `documentation.json`
against HEAD's package version; Pages checks them against npm latest. CI never reads this
package's registry metadata or resolves a release tag. Both API sources use a separate clean
checkout and its own TypeDoc, plugins and types from a frozen install, failing closed if that
install has no TypeDoc. Commit mode clones locally without tags or hardlinks and detaches at
HEAD, excluding uncommitted files and installed dependencies while retaining Git source links.

For notebooks, run `scripts/toolchain.sh` to read the exact Node, Deno, Python and uv versions
from `.tool-versions`, install them and activate the declared pnpm. The reader emits each tool's
default and JSON compatibility lanes. Notebook checks use the first Node version; CI verifies
both the default and compatibility lanes. After each workflow or composite-action setup,
`scripts/toolchain.sh --installed TOOL=VERSION` checks Node, Deno, Bun, Python and uv against the
same reader output or matrix lane used for installation, under the same condition. The notebook
runner also checks Node through the reader. Run `pnpm install --frozen-lockfile`, `uv lock --check`
and `uv sync --frozen`, then `pnpm notebooks:local`.

Both notebook scripts call `scripts/check_notebooks.py`. Register every notebook in
`docs/notebooks/registry.json`: schema 1 records the package identity, exact npm package pins,
and an ordered `notebooks` list of `file` and `title` entries. The file list must match the
notebook directory in both directions.

`--local` installs the candidate tarball from `tools/pack.mjs`, the same packer the package gate
inspects. `--published` installs exact releases from `https://registry.npmjs.org/` and checks
registry identity, tarball URL and SHA-512 integrity. Both compare installed files with the archive
bytes and check in the real kernel that `npm:` imports resolve to that inspected installation.
Notebook cells are unchanged in both modes.

The runner uses nbclient and a fresh real Deno Jupyter kernel for each notebook. It never
concatenates cells. Saved Jupyter outputs are the sole expected outputs; it normalizes stdout
chunks, line endings, ANSI color and display counts before comparing semantic text. Assertions
stay in each cell. Never persist keys, signatures, nonce values or wall-clock times.

Missing files, unregistered notebooks, empty code, missing output, kernel errors, output
mismatches, changed files and filesystem residue fail the run. The runner shuts down kernels
and removes its scratch consumers, inspected tarballs, temporary kernel registration and caches,
including on failure. Generated development API documentation is a qualification check; publication
uses the immutable release documentation.

Every authored TypeScript fence, TSDoc example and `docs/examples/` module is discovered and
tested. Keep guides in `docs/manifest.json` and notebooks in `docs/notebooks/registry.json`.
Every notebook must have saved safe semantic results and clean up its resources.

Qualification runs once on `kci/**`; the last `qualified` job requires every candidate lane.
Candidate notebook and consumer journeys install this repository's package from the packed candidate.
`publish.yml` waits up to ten minutes in the upload job for npm to serve the exact inspected
archive. Pending owner approval fails that run clearly; dispatch the same commit after approval.
The keyless `published-notebooks` job runs only after byte-for-byte registry read-back succeeds.
A maintainer can run `pnpm notebooks:published` and `pnpm docs:checks:published` on demand
once that version is available. Infra tags the release; `pages.yml` then runs `pnpm site`,
which builds `/api/` from that tag and checks it with `pnpm test:network:pages`.
Qualification checks HEAD through the same pipeline with `--source=commit`; no publication job waits on a tag.
The upload job and its environment gate are separate.

Publication
and Pages are maintainer-dispatched on the default branch with their existing environment gates.
Contributors do not publish, tag or dispatch workflows. Report vulnerabilities through the
[security policy](SECURITY.md). Use real services and real signatures in integration tests.

## Maintainer checks

Install the tracked hooks with `bash scripts/install-hooks.sh`. Local confidential-identifier
checks require an ignored owner policy; contributors without it get an inactive notice.
See the [maintainer checks](https://github.com/baselabs/bounded_authority_protocol_typescript/blob/main/docs/maintainer-checks.md)
for activation, coverage and the standalone guard tests. Public CI uses only synthetic identifiers.
