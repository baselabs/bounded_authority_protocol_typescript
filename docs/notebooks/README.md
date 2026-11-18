---
title: "Executable notebooks"
category: Notebooks
---

# Executable notebooks

To use a notebook, install Deno, run `deno jupyter --install`, and open the file in a Jupyter
front end such as JupyterLab or VS Code. Select **Deno**, then Run All in a fresh kernel.
The exact published npm imports and saved outputs are visible in each notebook on GitHub.

- [Request verification with nonces](verify-requests.ipynb)
- [HTTP endpoint protection and replay](http-server.ipynb)
- [Local-loopback development](local-loopback.ipynb)
- [Key enrollment and rotation](rotate-keys.ipynb)
- [Chains and anchored archives](chains-and-archives.ipynb)
- [Role attestations](role-attestations.ipynb)
- [Content assertions and successors](content-assertions.ipynb)

## Contributor checks

Install the exact Node, Deno, Python and uv versions in `.tool-versions`, and activate the pnpm
version declared in `package.json`. The second Node version on the `nodejs` line is the extra
compatibility lane; notebook checks use the first. Install dependencies and check the lock:

```bash
pnpm install --frozen-lockfile
uv lock --check
uv sync --frozen
pnpm notebooks:local
```

Candidate notebook and consumer journeys install this repository's package from the packed candidate.
`publish.yml` runs published notebooks and the other registry checks after each upload in the
keyless `published-notebooks` job. That job waits up to ten minutes for npm to serve the exact
version. A maintainer can run `pnpm notebooks:published` and `pnpm docs:checks:published` on demand
once that version is available. Released API checks also need the immutable release tag that
infra creates after publication. The upload job and its environment gate are separate.

Both package scripts call `scripts/check_notebooks.py`. Register every notebook in
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
