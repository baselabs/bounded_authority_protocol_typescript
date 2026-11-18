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
  const order = ["name: Check out source", "uses: ./.github/actions/notebook-tools", "name: Wait for the exact npm release",
    "run: pnpm notebooks:published", "run: pnpm docs:checks:published"].map((step) => job.indexOf(step));
  assert.ok(order.every((position, index) => position >= 0 && (index === 0 || position > order[index - 1]!)));
  assert.match(job, /deadline = time\.monotonic\(\) \+ 600/);
  assert.match(job, /release\.get\('name'\), release\.get\('version'\)/);
  assert.match(job, /::error::npm did not serve/);
  assert.match(scripts["docs:checks:published"]!, /pnpm docs:samples:published/);
});
