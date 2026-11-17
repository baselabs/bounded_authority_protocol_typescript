# Adopt a certified corpus

The certification artifact is the entire `priv/conformance/` subtree of the Hex release
[`bounded_authority_protocol` 1.0.0](https://hex.pm/packages/bounded_authority_protocol/1.0.0).
This checkout preserves it byte for byte at `conformance/priv/conformance/`, including the
schemas and auxiliary vectors outside the nine corpus directories. Tests read only this snapshot.
The npm package's `files` allowlist contains runtime output and package documentation, so none of
the corpus, tests, or development tooling ships in the npm tarball.

## SOURCE

`conformance/SOURCE` is UTF-8 JSON with two-space indentation and a final newline. Its closed
`bap-corpus-source/1` format contains `package`, `version`, `checksum`, and `indexes`. The checksum
is lowercase hexadecimal SHA-256 of the whole Hex tarball, obtained from the
[release API](https://hex.pm/api/packages/bounded_authority_protocol/releases/1.0.0).
`indexes` has exactly nine keys, sorted lexicographically. Each key is a corpus directory relative
to `priv/conformance`; its value is unpadded base64url SHA-256 of that directory's `index.json`.
It binds each runner to the certified index before the runner trusts the index's file digests.

For a candidate, `version` and `checksum` are JSON null and `candidate` is the full lowercase
40-character monorepo commit SHA. The other members and index pins follow the same rules. A
candidate is for amendment verification on a PR branch. Main CI and the release gate refuse it.

## Vendor and verify

From the repository root, the development tool uses Node built-ins and no runtime dependency:

```bash
corepack pnpm vendor 1.0.0
corepack pnpm check:corpus
corepack pnpm conformance:all
corepack pnpm conformance:portable
```

The tool fetches the release metadata, refuses retirement, fetches the tarball from `repo.hex.pm`,
and checks its outer SHA-256 against the registry. It then verifies Hex's inner `CHECKSUM` over
`VERSION || metadata.config || contents.tar.gz`, safely reads the inner archive, and extracts only
`priv/conformance`. It verifies all nine index pins and every indexed file before staging SOURCE
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
and selects only that commit's `priv/conformance/`. For example, this immutable commit contains
the 1.0.0 corpus:

```bash
corepack pnpm vendor --candidate 61d26051eb1a400c9cbabf135a6c1e808bb73c30
```

Replace the example SHA with the full commit SHA under review. Candidate PR CI compares the
snapshot to that immutable commit archive. After the amendment has been released on Hex and its
revert window closes, vendor the released version and run the release gate:

```bash
corepack pnpm vendor 1.0.0
corepack pnpm check:corpus:release
```

## Adoption and release eligibility

The weekly `corpus-adoption.yml` workflow finds the newest non-retired eligible Hex version,
vendors it transactionally, and opens an adoption PR with SOURCE and the snapshot. Maintainers
can run the same selection manually:

```bash
node scripts/check-corpus.mjs adopt
```

The release workflow requires SOURCE to name that newest eligible version, with its registry
checksum, and byte-compares its complete artifact. Per-push CI compares only the named release:
a new upstream release cannot make an unrelated push fail.

Eligibility follows the [Hex revert policy](https://hex.pm/docs/faq#packages):
a release must be at least 60 minutes old, and the package
must be at least 24 hours old. Both windows must have closed. Retirement excludes a version.
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

Inputs and modifiers never enter the projection. An unknown or incomplete outcome schema fails.
The runner computes the corresponding values from SDK results and orders them using the index,
even when its internal loader accumulates cases differently.

Hex 1.0.0 has no `priv/conformance/verdict-digests.json`, so tests derive the expected digest from
the certified cases. If a future snapshot includes that file, the runner also requires its entry
to match. Its closed format is `bap-corpus-verdict-digests/1`, with `corpora` keyed by the same
relative directory paths, each holding `index_sha256_base64url`, `case_count`, and
`verdict_digest_sha256_base64url`. An offline test copies the real snapshot into a temporary
directory, generates this file, proves agreement, changes its digest, and proves rejection.
