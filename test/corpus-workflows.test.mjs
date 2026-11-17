// Parse the actual workflow documents, including the publishing and Pages paths.
import {test} from "node:test";
import assert from "node:assert/strict";
import {readFileSync} from "node:fs";
import {parse} from "yaml";
const workflow = name => parse(readFileSync(new URL(`../.github/workflows/${name}.yml`, import.meta.url), "utf8"));
test("CI checks named artifacts while both release jobs enforce freshness", () => {
  const ci = workflow("ci"), release = workflow("release");
  const ciRun = ci.jobs["corpus-artifact"].steps.map(s => s.run ?? "").join("\n");
  assert.match(ciRun, /ci --main/); assert.match(ciRun, /pnpm check:corpus/);
  assert.doesNotMatch(ciRun, /check:corpus:release|check-corpus.mjs (release|adopt)/);
  for (const name of ["verify", "publish"]) {
    const steps = release.jobs[name].steps;
    const gate = steps.findIndex(s => s.run === "pnpm check:corpus:release");
    assert.ok(gate >= 0 && gate < steps.findIndex(s => s.name === "Build"));
  }
});
test("weekly adoption opens a PR and preserves the public repository's runner", () => {
  const job = workflow("corpus-adoption");
  assert.equal(job.on.schedule.length, 1); assert.equal(job.on.push, undefined);
  assert.equal(job.jobs.adopt["runs-on"], "ubuntu-24.04");
  const run = job.jobs.adopt.steps.map(s => s.run ?? "").join("\n");
  assert.match(run, /check-corpus.mjs adopt/); assert.match(run, /gh pr create/);
  assert.doesNotMatch(run, /--force|reset --hard|stash/);
});
test("Pages builds the site, released API, then checks it, in that order", () => {
  const steps = workflow("pages").jobs.build.steps.map(s => s.run);
  const order = ["pnpm build:site", "pnpm docs:api:release", "pnpm check:site"].map(c => steps.indexOf(c));
  assert.ok(order.every(i => i >= 0)); assert.ok(order[0] < order[1] && order[1] < order[2]);
});
