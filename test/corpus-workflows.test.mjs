// Parse the actual workflow documents, including the publishing and Pages paths.
import {test} from "node:test";
import assert from "node:assert/strict";
import {readFileSync} from "node:fs";
import {parse} from "yaml";
const workflow = name => parse(readFileSync(new URL(`../.github/workflows/${name}.yml`, import.meta.url), "utf8"));
test("CI checks named artifacts while both release jobs enforce freshness", () => {
  const ci = workflow("ci"), release = workflow("release");
  const ciRun = ci.jobs["corpus-artifact"].steps.map(s => s.run ?? "").join("\n");
  assert.match(ciRun, /ci --main/); assert.match(ciRun, /pnpm check:corpus:artifact/);
  assert.doesNotMatch(ciRun, /check:corpus:release|check-corpus.mjs (release|adopt)/);
  for (const name of ["verify", "publish"]) {
    const steps = release.jobs[name].steps;
    const gate = steps.findIndex(s => s.run === "pnpm check:corpus:release");
    assert.ok(gate >= 0 && gate < steps.findIndex(s => s.name === "Build"));
  }
});
test("weekly adoption dispatches CI and maintains one exact-title issue and preserves the public repository's runner", () => {
  const job = workflow("corpus-adoption");
  assert.equal(job.on.schedule.length, 1); assert.equal(job.on.push, undefined);
  assert.equal(job.jobs.adopt["runs-on"], "ubuntu-24.04");
  const run = job.jobs.adopt.steps.map(s => s.run ?? "").join("\n");
  assert.match(run, /check-corpus.mjs adopt/); assert.match(run, /gh workflow run ci.yml --ref/);
  assert.match(run, /gh issue create/); assert.match(run, /gh issue edit/);
  assert.match(run, /select\(\.pull_request == null and \.title ==/); assert.match(run, /state=all/);
  assert.equal(job.permissions.actions, "write"); assert.equal(job.permissions.issues, "write");
  assert.equal(job.permissions["pull-requests"], undefined);
  assert.doesNotMatch(run, /gh pr/);
  assert.doesNotMatch(run, /--force|reset --hard|stash/);
});
test("Pages builds the site, released API, then checks it, in that order", () => {
  const steps = workflow("pages").jobs.build.steps.map(s => s.run);
  const order = ["pnpm build:site", "pnpm docs:api:release", "pnpm check:site"].map(c => steps.indexOf(c));
  assert.ok(order.every(i => i >= 0)); assert.ok(order[0] < order[1] && order[1] < order[2]);
});

test("main, PRs targeting main, and dispatch on main all enforce release SOURCE", () => {
  const ci = workflow("ci");
  assert.ok(Object.hasOwn(ci.on, "workflow_dispatch"));
  const step = ci.jobs["corpus-artifact"].steps.find(s => s.env?.REQUIRE_HEX_RELEASE);
  assert.equal(step.env.REQUIRE_HEX_RELEASE, "${{ github.ref == 'refs/heads/main' || github.base_ref == 'main' }}");
  assert.match(step.run, /REQUIRE_HEX_RELEASE.*true/);
  assert.match(step.run, /check-corpus.mjs ci --main/);
});
test("every conformance lane checks complete snapshot self-consistency offline", () => {
  for (const name of ["verify", "runtimes", "package", "browser-conformance"]) {
    assert.ok(workflow("ci").jobs[name].steps.some(s => s.run === "pnpm check:corpus"), name);
  }
});
test("CI installs pinned checksum-verified gitleaks and scans full history", () => {
  const steps = workflow("ci").jobs.secrets.steps;
  assert.equal(steps[0].with["fetch-depth"], 0);
  const commands = steps.map(s => s.run ?? "").join("\n");
  assert.match(commands, /scripts\/install_gitleaks.sh/);
  assert.match(commands, /secret_scan.sh --check/); assert.match(commands, /secret_scan.sh --history/);
});
