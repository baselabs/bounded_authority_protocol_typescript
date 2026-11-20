## CI/CD and releases

Releases, deployments, and publications are done by the infra session (infra-1).
The project lands on the default branch with `kimosabe-land --repo . --sha <full sha>`
and stops there. Requirements live in the infra repository at `baselabs/docs/ci.md`,
"What infra requires of every product".

The `site` qualification job runs `pnpm site` in GitHub CI on ubuntu-24.04 from a frozen
install, before any library build. It is required by `qualified`. Pages uses the same command
to typecheck and build the bench, build and check the released API, check npm version claims,
and scan the browser bundle. The release's own TypeDoc uses its frozen dependency graph.
