import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";

const read = (file: string): string => readFileSync(new URL(`../${file}`, import.meta.url), "utf8");
const ci = read(".github/workflows/ci.yml");
const publication = read(".github/workflows/publish.yml");
const scripts = (JSON.parse(read("package.json")) as { scripts: Record<string, string> }).scripts;

test("qualification reaches only candidate owning-package journeys", () => {
  assert.ok(!ci.includes("notebooks-published") && !ci.includes(":published"));
  const checked = new Set<string>();
  function candidateOnly(name: string): void {
    if (checked.has(name)) return;
    checked.add(name);
    const command = scripts[name];
    if (!command) return;
    assert.doesNotMatch(command, /:published|BAP_SAMPLE_MODE=published|BAP_SAMPLE_MODE=both/, name);
    for (const match of command.matchAll(/\bpnpm(?: run)? ([\w:-]+)/g)) candidateOnly(match[1]!);
  }
  for (const match of ci.matchAll(/\bpnpm(?: run)? ([\w:-]+)/g)) candidateOnly(match[1]!);
  assert.match(scripts["test:tarball"]!, /BAP_SAMPLE_MODE=candidate/);
  assert.match(read("test/reader.ts"), /BAP_SAMPLE_MODE \?\? "candidate"/);
});

test("candidate notebook cells are formatted before they run", () => {
  const job = ci.split("\n  notebooks-local:\n")[1]?.split(/\n  [\w-]+:\n/)[0];
  assert.ok(job, "notebooks-local is required");
  const format = job.indexOf("deno fmt docs/notebooks/*.ipynb\n          git diff --exit-code -- docs/notebooks\n");
  assert.ok(format > job.indexOf("uses: ./.github/actions/notebook-tools"), "format check follows the pinned toolchain");
  assert.ok(format < job.indexOf("run: pnpm notebooks:local"), "format check precedes execution");
});

test("one keyless job checks the exact published version after the upload", () => {
  const job = publication.split("\n  published-notebooks:\n")[1];
  assert.ok(job, "published-notebooks is required");
  const upload = publication.split("\n  publish:\n")[1]!.split("\n  published-notebooks:\n")[0]!;
  const uploadIf = upload.match(/^    if: (.+)$/m)?.[1];
  assert.ok(uploadIf, "publish requires a job-level condition");
  assert.equal(job.match(/^    if: (.+)$/m)?.[1], uploadIf, "post-upload condition must equal publish");
  assert.match(job, /^    needs: publish$/m); assert.match(job, /runs-on: ubuntu-24\.04/);
  assert.match(job, /timeout-minutes: 90 # no green run yet/);
  assert.doesNotMatch(job, /environment:|secrets\.|id-token:|NODE_AUTH_TOKEN|NPM_TOKEN/);
  assert.match(job, /actions\/checkout@[a-f\d]{40} # v\d+\.\d+\.\d+/);
  assert.match(job, /persist-credentials: false/);
  const order = ["name: Check out source", "uses: ./.github/actions/notebook-tools",
    "run: pnpm notebooks:published", "name: Wait for infra's tag on the published commit",
    "run: pnpm docs:checks:published"].map((step) => job.indexOf(step));
  assert.ok(order.every((position, index) => position >= 0 && (index === 0 || position > order[index - 1]!)));
  assert.match(job, /deadline = time\.monotonic\(\) \+ 600/);
  assert.match(job, /commit == os\.environ\['GITHUB_SHA'\]/);
  assert.match(job, /release checks are incomplete/);
  assert.match(scripts["docs:checks:published"]!, /pnpm docs:samples:published/);
});

test("publication resumes only an identical, nondeprecated release and reads its archive back", () => {
  const upload = publication.split("\n  publish:\n")[1]!.split("\n  published-notebooks:\n")[0]!;
  const steps = upload.split(/^      - name: /m).slice(1);
  const step = (name: string): string => {
    const found = steps.find((source) => source.startsWith(`${name}\n`));
    assert.ok(found, `missing publication step: ${name}`);
    return found;
  };
  assert.match(upload, /timeout-minutes: 90 # no green run yet/);
  const tag = step("Refuse a tagged version");
  assert.match(tag, /ls-remote.*refs\/tags\/v\$\{version\}/);
  assert.match(tag, /assert\.equal\(tags\.trim\(\), ''/);
  assert.doesNotMatch(tag, /already published|npm.*view/);
  const compare = step("Compare any served version with the inspected archive");
  assert.match(compare, /id: registry/);
  assert.match(compare, /sha512-' \+ base64\.b64encode\(hashlib\.sha512\(archive\)\.digest\(\)\)/);
  assert.match(compare, /if error\.code != 404:\s+raise\s+stage = True/);
  assert.match(compare, /else:[\s\S]*assert not release\.get\('deprecated'\)/);
  assert.match(compare, /assert release\.get\('dist', \{\}\)\.get\('integrity'\) == integrity/);
  assert.match(compare, /stage = False/);
  assert.match(compare, /output\.write\(f'stage=/);
  const stage = step("Stage the inspected archive with trusted publishing");
  assert.match(stage, /if: steps\.registry\.outputs\.stage == 'true'/);
  assert.match(stage, /npm stage publish \.\/artifacts\/package\.tgz --provenance/);
  assert.match(stage, /already staged\|previously staged/);
  assert.match(stage, /::error::Version is already staged, awaiting owner approval on npmjs\.com/);
  assert.match(stage, /exit 1/);
  assert.doesNotMatch(stage, /continue-on-error|--force|npm (?:unpublish|stage (?:approve|reject|list))/);
  const readback = step("Read back the exact inspected bytes or report pending approval");
  assert.match(readback, /deadline = time\.monotonic\(\) \+ 600/);
  assert.match(readback, /release\.get\('name'\), release\.get\('version'\)/);
  assert.match(readback, /assert not release\.get\('deprecated'\)/);
  assert.match(readback, /assert release\.get\('dist', \{\}\)\.get\('integrity'\) == integrity/);
  assert.match(readback, /tarball\.scheme == 'https' and tarball\.netloc == 'registry\.npmjs\.org'/);
  assert.match(readback, /assert served == archive/);
  assert.match(readback, /raise SystemExit\(f'::error::.*staged, awaiting owner approval/);
  const order = ["Refuse a package name the registry has never had", "Refuse a tagged version",
    "Build the library and documentation", "Pack the package archive", "Inspect the exact package archive",
    "Verify the inspected archive checksum", "Compare any served version with the inspected archive",
    "Stage the inspected archive with trusted publishing", "Read back the exact inspected bytes or report pending approval",
    "Upload the inspected release assets"].map((name) => upload.indexOf(`name: ${name}\n`));
  assert.ok(order.every((position, index) => position >= 0 && (index === 0 || position > order[index - 1]!)));
});

test("the finishing run retains all consumer release assets, including while approval is pending", () => {
  const upload = publication.split("\n  publish:\n")[1]!.split("\n  published-notebooks:\n")[0]!;
  assert.match(upload, /name: Inspect the exact package archive\n        id: inspect/);
  assert.equal((upload.match(/uses: actions\/upload-artifact@/g) ?? []).length, 1);
  const assets = upload.split("      - name: Upload the inspected release assets\n")[1]!;
  assert.match(assets, /if: \$\{\{ !cancelled\(\) && steps\.inspect\.outcome == 'success' \}\}/);
  assert.match(assets, /actions\/upload-artifact@cf430e030ddbb5b0abf93d22962f4752f3646cd9 # v7\.0\.2/);
  assert.match(assets, /name: release-assets\n/);
  assert.match(assets, /path: \|\n            artifacts\/package\.tgz\n            artifacts\/SHA256SUMS\n/);
  assert.match(assets, /if-no-files-found: error/);
  assert.doesNotMatch(publication, /gh release|softprops\/action-gh-release|tags:/);
  for (const file of ["README.md", "SECURITY.md"]) {
    const guide = read(file);
    assert.match(guide, /npm registry provenance/);
    assert.match(guide, /\[GitHub release\]\(https:\/\/github\.com\/baselabs\/[^)]+\/releases\)/);
    assert.match(guide, /`v<version>`/);
    assert.match(guide, /sha256sum --check SHA256SUMS/);
  }
});

test("qualified keeps its exact check name and requires every candidate job", () => {
  const qualified = ci.split("\n  qualified:\n")[1]!;
  assert.ok(qualified);
  assert.match(qualified, /^    if: always\(\)$/m);
  assert.doesNotMatch(qualified, /^    name:/m);
  const needs = qualified.match(/^    needs: \[([^\]]+)\]$/m)?.[1]?.split(/,\s*/);
  const jobs = [...ci.split("\njobs:\n")[1]!.matchAll(/^  ([\w-]+):$/gm)]
    .map((match) => match[1]!).filter((name) => name !== "qualified");
  assert.deepEqual(new Set(needs), new Set(jobs));
  assert.match(qualified, /job\['result'\] != 'success'/);
  assert.doesNotMatch(ci, /workflow_dispatch:|schedule:|time\.sleep|time\.monotonic/);
});
