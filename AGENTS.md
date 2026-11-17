## CI/CD and releases

Releases, deployments, and publications are done by the infra session (infra-1).
The project lands on the default branch with `kimosabe-land --repo . --sha <full sha>`
and stops there. Requirements live in the infra repository at `baselabs/docs/ci.md`,
"What infra requires of every product".
