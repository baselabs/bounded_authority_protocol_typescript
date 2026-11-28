# Adopt a certified corpus

The certification artifact is the entire `priv/conformance/` subtree of the Hex release
[`bounded_authority_protocol`](https://hex.pm/packages/bounded_authority_protocol)
named by `conformance/SOURCE`.
This checkout preserves it byte for byte at `conformance/priv/conformance/`, including the
schemas and auxiliary vectors outside the indexed corpus directories. Tests read only this snapshot.
The npm package's `files` allowlist contains runtime output and package documentation, so none of
the corpus, tests, or development tooling ships in the npm tarball.

## SOURCE

`conformance/SOURCE` is UTF-8 JSON with two-space indentation and a final newline. Its closed
`bap-corpus-source/1` format contains `package`, `version`, `checksum`, `tree_sha256`, and `indexes`. The checksum
is lowercase hexadecimal SHA-256 of the whole Hex tarball, obtained from the
[release API](https://hex.pm/api/packages/bounded_authority_protocol), selecting the version in SOURCE.
`indexes` has exactly one key per catalogued corpus, sorted lexicographically. Each key is a corpus directory relative
to `priv/conformance`; its value is unpadded base64url SHA-256 of that directory's `index.json`.
The pins prove only offline self-consistency against SOURCE, not origin. The online artifact job
and release gate bind SOURCE and every snapshot byte to the checksum-verified Hex release.

`tree_sha256` is lowercase hexadecimal SHA-256 of a complete path-and-content listing:
list every regular file recursively under `conformance/priv/conformance/`, using relative paths
with `/` separators. Sort paths lexicographically by UTF-16 code units (ECMAScript's default
string sort). For each path, form `[path, lowercase_hex_sha256_of_exact_file_bytes]`. Encode the
array of these pairs as compact JSON (ECMAScript `JSON.stringify`, equivalent to JCS for these
strings), in UTF-8 with no BOM or trailing newline, and hash those bytes with SHA-256. Every file
participates, including `v1/schemas`, `v1/vectors`, and root `verdict-digests.json` when present.
Links and special files are refused. Every conformance core checks this digest offline in every
runtime lane, even when only one corpus is run.

For a candidate, `version` and `checksum` are JSON null and `candidate` is the full lowercase
40-character monorepo commit SHA. The other members and index pins follow the same rules. A
candidate is for amendment verification with the candidate commands below. The artifact job compares candidate bytes against the immutable commit archive. Its promotion
gate (`offline --main`) and publication require a released source.

## Vendor and verify

From the repository root, the development tool uses Node built-ins and no runtime dependency:

```bash
version=$(node --input-type=module -e 'import {readFileSync} from "node:fs"; console.log(JSON.parse(readFileSync("conformance/SOURCE")).version)')
corepack pnpm vendor "$version"
corepack pnpm check:corpus         # offline self-consistency
corepack pnpm check:corpus:artifact # online artifact binding
corepack pnpm conformance:all
corepack pnpm conformance:portable
```

The tool fetches the release metadata, refuses retirement, fetches the tarball from `repo.hex.pm`,
and checks its outer SHA-256 against the registry. It then verifies Hex's inner `CHECKSUM` over
`VERSION || metadata.config || contents.tar.gz`, safely reads the inner archive, and extracts only
`priv/conformance`. It verifies every index pin and every indexed file before staging SOURCE
and the whole snapshot together. Staging uses a temporary directory on the destination filesystem;
renames install the completed tree with rollback on failure. The tool removes its temporary files.
A changed checksum for an already pinned version fails closed and requires investigation.

The artifact CI job performs the same fetch and checksum verification and compares the complete
tree in both directions, including auxiliary files. The tests themselves stay offline. Every
corpus checks recorded file digests, the exact file set, counts, unique ids, total applicability,
and that every certified id executes exactly once. Every result digest must equal the expected
digest derived from the corpus, independently of the per-case comparator.

## Candidate verification

The GitHub commit archive over HTTPS is the equivalent of archiving a monorepo commit's subtree.
The tool uses `https://codeload.github.com/baselabs/bounded_authority_protocol/tar.gz/<commit>`
and selects only that commit's `priv/conformance/`. Pass the full commit SHA under review:

```bash
corepack pnpm vendor --candidate 95ac5caf772c4cd18797674c46b796525b24d3b0
```

Candidate branch CI compares the snapshot to that immutable commit archive. After the amendment has been released on Hex and its
revert window closes, vendor the released version and run the release gate:

```bash
version=$(node --input-type=module -e 'import {readFileSync} from "node:fs"; console.log(JSON.parse(readFileSync("conformance/SOURCE")).version)')
corepack pnpm vendor "$version"
corepack pnpm check:corpus:release
```

## Adoption and release eligibility

The weekly `corpus-adoption.yml` workflow finds the newest non-retired eligible Hex version,
vendors it transactionally on `automation/adopt-corpus-<version>`, including the generated README
summary, and pushes that branch. It opens or updates one landing issue, deduplicated by exact
title across open and closed issues, with the version, branch, compare URL and commit. Infra
reviews it and runs the maintainer qualification command for the exact commit; the resulting `kci/**` push is the
only qualification run. Adoption creates no PR and needs only `contents: write` and
`issues: write`. Repository permission to create and approve PRs stays disabled. Maintainers
can run the same selection manually:

```bash
node scripts/check-corpus.mjs adopt
```

The maintainer-dispatched `publish.yml`, running from the default branch in environment `publish`,
requires SOURCE to name that newest eligible version, with its registry
checksum, and byte-compares its complete artifact. Per-push CI compares only the named release:
a newer eligible version does not require immediate adoption on a push. A Hex outage or retirement
of the pinned version fails `corpus-artifact` by design; this behavior is fail closed.

Eligibility follows the [Hex revert policy](https://hex.pm/docs/faq#packages):
a release must be at least 60 minutes old, and the package
must be at least 24 hours old. Both windows must have closed. Retirement excludes a version, as do prerelease identifiers and build metadata.
Adoption uses the checksum obtained with eligibility metadata and refuses a changed checksum on
re-fetch. If SOURCE is ahead of the newest eligible release while its window closes, adoption
prints that fact, keeps the snapshot, and exits successfully.
After the window, a corpus repair needs a new release and retirement of the faulty one; the tool
never accepts replacement bytes under the old identity.

## Verdict digest contract

For each corpus, take case files in the order declared by `index.json`, then each case in its file's
order. The nested loopback `uri_cases` list participates; profile and revision headers do not.
Encode `[[id, value], ...]` with JCS (RFC 8785), hash with SHA-256, and use unpadded base64url.
`value` is the case's `expected` member verbatim when present. Otherwise these are the only
projected outcome members:

| Corpus | Surface or case list | Outcome members |
|---|---|---|
| Contract majors 1, 2, 3 | Every case | `expected` verbatim |
| Local-loopback HTTP | `profile.json` URI cases | `valid`, plus `normalized` when valid |
| Local-loopback HTTP | Proof cases | `decode_local`, `decode_standard`, `envelope_local` |
| Role-attestation | Attestation cases | `decode`, `verify` (booleans) |
| Content-assertion | Assertion, digest, successor cases | `expected` verbatim |
| Strict Ed25519 | `local_loopback_http` | `decode_local`, `decode_standard`, `envelope_local` |
| Strict Ed25519 | `role_attestation` | `decode`, `verify` (booleans) |
| Strict Ed25519 | All other surfaces, including `content_assertion` | `expected` verbatim |
| Producer canonicality | Every case | `expected` verbatim |
| Selector float-zero | Every case | `expected` verbatim |
| ES256 content assertions and action approval | Every case | `expected` verbatim |

Inputs and modifiers never enter the projection. An unknown or incomplete outcome schema fails.
The runner computes the corresponding values from SDK results and orders them using the index,
even when its internal loader accumulates cases differently.

Tests derive the expected digest from the snapshot cases. When the snapshot includes
`priv/conformance/verdict-digests.json`, the runner also requires its entry
to match. Its closed format is `bap-corpus-verdict-digests/1`, with `corpora` keyed by the same
relative directory paths, each holding `index_sha256_base64url`, `case_count`, and
`verdict_digest_sha256_base64url`. An offline test copies the real snapshot into a temporary
directory, generates this file, proves agreement, changes its digest, and proves rejection.
The profile indexes for ES256 content assertions and action approval additionally pin
the reference and full-SDK verdict digests. These use the indexed file name followed by
the case ID as the row identity.

## Derived documentation and secret scanning

The marked `corpus-source` block in README is the only current corpus version/count summary.
`vendor` and scheduled adoption rewrite it from SOURCE and the snapshot indexes. `check:corpus`
is offline: it checks the complete tree and indexes, requires the exact generated summary, and
rejects copied numeric corpus versions/counts elsewhere in tracked docs and workflows. Released
changelog sections remain historical. Runner counts come from the checked indexes at runtime.

CI installs checksum-verified Gitleaks 8.30.1 with `scripts/install_gitleaks.sh` and scans complete,
merge-aware history using `.gitleaks.toml`. Developers run `pnpm secrets` with that version on PATH;
`--check` proves sensitivity in a disposable scratch tree, `--history` scans history only, and the
default also scans staged and unstaged changes. Rule-scoped anchored corpus path exceptions are
limited to fixture rules, with byte identity checked against the immutable source artifact. Historical removed paths are limited to the exact commits that carried them;
non-corpus fixture exceptions still require exact matched bytes and paths.

---

Documentation navigation: [Previous: Upgrade index](upgrading.md) · [Next: FAQ](faq.md)

Candidate notebook and consumer journeys install this repository's package from the packed candidate.
`publish.yml` waits up to ten minutes in the upload job for npm to serve the exact inspected
archive. Pending owner approval fails that run clearly; dispatch the same commit after approval.
The keyless `published-notebooks` job runs only after byte-for-byte registry read-back succeeds.
A maintainer can run `pnpm notebooks:published` and `pnpm docs:checks:published` on demand
once that version is available. The upload job and its environment gate are separate.
