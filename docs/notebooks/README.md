# Executable notebooks

These Jupyter notebooks use the real Deno TypeScript kernel. Install the exact Deno and Python
versions in `.tool-versions`, install the locked Python tools with `uv sync --frozen`, then run
`uv run --frozen deno jupyter --install`. Open an `.ipynb` in JupyterLab or an editor's Jupyter
extension, select Deno and Run All. Every notebook imports exact published verifier 2.0.0 and needs
no external keys, credentials or hidden data. Demonstration keys remain in memory.

```bash
pnpm notebooks:local
pnpm notebooks:published
```

Local mode builds and packs the same release candidate as the package check, installs it in a
fresh consumer, and rewrites imports in a temporary notebook copy. Published mode executes the
notebooks unchanged with exact `npm:` imports in an isolated Deno cache and verifies registry
origin and the resolved package version. Each notebook runs top to bottom in a fresh real kernel;
cells are never concatenated into a script. Saved outputs are safe expected semantic text, compared
to kernel results. The checked-in notebooks are not rewritten by the runner.

The runner rejects absent code, errors, absent outputs, output differences, unknown/unregistered
notebooks and filesystem residue. It removes consumers, caches, tarballs, kernel configuration
and temporary execution directories in `finally`. It never prints generated key material.

- [Request verification with nonces](verify-requests.ipynb)
- [HTTP endpoint protection and replay](http-server.ipynb)
- [Local-loopback development](local-loopback.ipynb)
- [Key enrollment and rotation](rotate-keys.ipynb)
- [Chains and anchored archives](chains-and-archives.ipynb)
- [Role attestations](role-attestations.ipynb)
- [Content assertions and successors](content-assertions.ipynb)
