## CI/CD and releases

Releases, deployments, and publications are done by the infrastructure maintainers.
Changes land on the default branch through the project's landing tool after the `qualified`
CI job passes, and stop there. Requirements live in the infrastructure repository's
CI requirements document.

The `site` qualification job runs `pnpm site --source=commit` in GitHub CI on ubuntu-24.04
from a frozen install, before any library build. It is required by `qualified`. CI exports HEAD,
builds the API with that export's own frozen TypeDoc, and checks version claims against the
committed package version, without querying this package's registry metadata or release tags.
Pages runs the same ordered pipeline with `pnpm site`: typecheck and build the bench, build and
check the API from the npm-latest release tag, check claims against npm latest, and scan the
browser bundle. Both sources fail closed if their separate frozen install has no TypeDoc.
