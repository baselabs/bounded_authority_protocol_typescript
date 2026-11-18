// Parse the actual workflow documents, including publishing and Pages.
import {test} from "node:test";
import assert from "node:assert/strict";
import {existsSync, readFileSync} from "node:fs";
import {parse} from "yaml";
const workflow = name => parse(readFileSync(new URL(`../.github/workflows/${name}.yml`, import.meta.url), "utf8"));
const commands = job => job.steps.map(s => s.run ?? "").join("\n");
const owners = `contains(fromJSON('["corepay","palermo-git"]'), github.actor) && contains(fromJSON('["corepay","palermo-git"]'), github.triggering_actor)`;

test("candidate CI checks the named artifact and dispatch publication enforces freshness", () => {
  const ci = workflow("ci"), publish = workflow("publish");
  const ciRun = commands(ci.jobs["corpus-artifact"]);
  assert.match(ciRun, /check-corpus.mjs ci --main/);
  assert.doesNotMatch(ciRun, /check:corpus:release|check-corpus.mjs (release|adopt)/);
  assert.deepEqual(ci.on, {push: {branches: ["kci/**"]}});
  assert.equal(ci.jobs.qualified.if, "always()");
  assert.deepEqual(new Set(ci.jobs.qualified.needs), new Set(Object.keys(ci.jobs).filter(n => n !== "qualified")));
  assert.match(commands(ci.jobs.qualified), /job\['result'\] != 'success'/);
  assert.equal(existsSync(new URL("../.github/workflows/release.yml", import.meta.url)), false);
  const steps = publish.jobs.publish.steps;
  const gate = steps.findIndex(s => s.run === "pnpm check:corpus:release");
  assert.ok(gate >= 0 && gate < steps.findIndex(s => s.name === "Build the library and documentation"));
  assert.match(commands(publish.jobs.publish), /npm stage publish \.\/artifacts\/package\.tgz --provenance/);
  assert.doesNotMatch(commands(publish.jobs.publish), /npm publish|git tag|gh release|readback/);
  assert.doesNotMatch(commands(ci.jobs.package), /test:readback|tools\/readback/);
});

test("publication confirms the package exists before checking its version or staging", () => {
  const steps = workflow("publish").jobs.publish.steps;
  const gate = steps.findIndex(s => s.name === "Refuse a package name the registry has never had");
  const version = steps.findIndex(s => s.name === "Refuse a published or tagged version");
  assert.ok(gate >= 0 && version === gate + 1);
  assert.ok(version < steps.findIndex(s => s.run?.includes("npm stage publish")));
  const run = steps[gate].run;
  assert.match(run, /const \{name\} = JSON\.parse\(readFileSync\('package\.json', 'utf8'\)\)/);
  assert.match(run, /fetch\(`https:\/\/registry\.npmjs\.org\/\$\{encodeURIComponent\(name\)\}`/);
  assert.match(run, /signal: AbortSignal\.timeout\(30_000\)/);
  assert.match(run, /catch \{\s+throw new Error\(`npm registry could not be read for \$\{name\}`\)/);
  assert.match(run, /assert\.notEqual\(packageResponse\.status, 404, `\$\{name\} has never been published to npm: this workflow publishes new versions of existing packages only\. A first publication is the owner's decision\.`\)/);
  assert.match(run, /assert\.equal\(packageResponse\.status, 200, `npm registry could not be read/);
});

test("weekly adoption maintains one exact-title landing issue without dispatching qualification", () => {
  const job = workflow("corpus-adoption");
  assert.equal(job.on.schedule.length, 1);
  assert.equal(job.on.push, undefined);
  assert.equal(job.jobs.adopt["runs-on"], "ubuntu-24.04");
  const run = commands(job.jobs.adopt);
  assert.match(run, /check-corpus.mjs adopt/);
  assert.match(run, /gh issue create/); assert.match(run, /gh issue edit/);
  assert.match(run, /select\(\.pull_request == null and \.title ==/); assert.match(run, /state=all/);
  assert.match(run, /kimosabe-land --repo \. --sha \$sha/);
  assert.equal(job.permissions.actions, undefined); assert.equal(job.permissions.issues, "write");
  assert.equal(job.permissions["pull-requests"], undefined);
  assert.doesNotMatch(run, /gh pr|gh workflow run|--force|reset --hard|stash/);
});

test("publication and every Pages job require both owners and refuse nondefault refs first", () => {
  for (const name of ["publish", "pages"]) {
    assert.deepEqual(workflow(name).on, {workflow_dispatch: null});
    for (const job of Object.values(workflow(name).jobs)) {
      assert.equal(job.if, owners);
      assert.equal(typeof job.environment === "string" ? job.environment : job.environment.name,
        name === "publish" ? "publish" : "github-pages");
      assert.match(job.steps[0].run, /test "\$GITHUB_REF" = "refs\/heads\/\$DEFAULT_BRANCH"/);
      assert.equal(job.steps[0].env.DEFAULT_BRANCH, "${{ github.event.repository.default_branch }}");
      assert.doesNotMatch(commands(job), /gh workflow run ci.yml/);
    }
  }
});

test("Pages builds the site, released API, then checks it, in that order", () => {
  const steps = workflow("pages").jobs.build.steps.map(s => s.run);
  const order = ["pnpm build:site", "pnpm docs:api:release", "pnpm check:site"].map(c => steps.indexOf(c));
  assert.ok(order.every(i => i >= 0)); assert.ok(order[0] < order[1] && order[1] < order[2]);
});

test("every conformance lane checks complete snapshot self-consistency offline", () => {
  for (const name of ["verify", "runtimes", "package", "browser-conformance"]) {
    assert.ok(workflow("ci").jobs[name].steps.some(s => s.run === "pnpm check:corpus"), name);
  }
});

test("every dependency install uses Corepack's declared pnpm without a cache writer", () => {
  for (const name of ["ci", "publish", "pages", "corpus-adoption"]) {
    for (const job of Object.values(workflow(name).jobs)) {
      if (!commands(job).includes("pnpm install")) continue;
      assert.match(commands(job), /corepack prepare "\$manager" --activate/);
      assert.match(commands(job), /test "pnpm@\$\(pnpm --version\)" = "\$manager"/);
      assert.match(commands(job), /pnpm install --frozen-lockfile/);
      for (const step of job.steps) {
        assert.doesNotMatch(step.uses ?? "", /^actions\/cache@|^pnpm\/action-setup@/);
        assert.equal(step.with?.cache, undefined);
        if (step.uses?.startsWith("actions/setup-node@")) assert.equal(step.with["package-manager-cache"], false);
      }
    }
  }
});

test("CI installs pinned checksum-verified gitleaks and scans full history", () => {
  const steps = workflow("ci").jobs.secrets.steps;
  assert.equal(steps[0].with["fetch-depth"], 0);
  const run = commands(workflow("ci").jobs.secrets);
  assert.match(run, /scripts\/install_gitleaks.sh/);
  assert.match(run, /secret_scan.sh --check/); assert.match(run, /secret_scan.sh --history/);
});
