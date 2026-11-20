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
  assert.equal(ci.jobs.qualified.name, undefined);
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
  const version = steps.findIndex(s => s.name === "Refuse a tagged version");
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
  assert.equal(job.jobs.adopt["timeout-minutes"], 90);
  assert.match(job.jobs.adopt.steps[0].run, /test "\$GITHUB_REF" = "refs\/heads\/\$DEFAULT_BRANCH"/);
  assert.equal(job.jobs.adopt.steps[0].env.DEFAULT_BRANCH, "${{ github.event.repository.default_branch }}");
  const run = commands(job.jobs.adopt);
  assert.match(run, /check-corpus.mjs adopt/);
  assert.match(run, /gh issue create/); assert.match(run, /gh issue edit/);
  assert.match(run, /select\(\.pull_request == null and \.title ==/); assert.match(run, /state=all/);
  assert.match(run, /kimosabe-land --repo \. --sha \$sha/);
  assert.equal(job.permissions.actions, undefined); assert.equal(job.permissions.issues, "write");
  assert.equal(job.permissions["pull-requests"], undefined);
  assert.doesNotMatch(run, /gh pr|gh workflow run|--force|reset --hard|stash/);
});

test("the upload and every Pages job require both owners and refuse nondefault refs first", () => {
  for (const name of ["publish", "pages"]) {
    assert.deepEqual(workflow(name).on, {workflow_dispatch: null});
    for (const [id, job] of Object.entries(workflow(name).jobs)) {
      if (name === "publish" && id !== "publish") continue;
      assert.equal(job.if, owners);
      assert.equal(typeof job.environment === "string" ? job.environment : job.environment.name,
        name === "publish" ? "publish" : "github-pages");
      assert.match(job.steps[0].run, /test "\$GITHUB_REF" = "refs\/heads\/\$DEFAULT_BRANCH"/);
      assert.equal(job.steps[0].env.DEFAULT_BRANCH, "${{ github.event.repository.default_branch }}");
      assert.doesNotMatch(commands(job), /gh workflow run ci.yml/);
    }
  }
});

test("Pages and qualification run the same complete site pipeline without a prior library build", () => {
  const pages = workflow("pages"), ci = workflow("ci");
  const scripts = JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8")).scripts;
  assert.deepEqual(scripts.site.split(" && "), ["pnpm typecheck:web", "pnpm build:site",
    "pnpm docs:api:release", "pnpm test:network:pages", "pnpm check:site", "pnpm guard:site"]);
  assert.equal(scripts["guard:site"], "node tools/browser-guard.mjs --scan site-dist/app.js");
  const pagesRuns = pages.jobs.build.steps.filter(s => s.run).map(s => s.run);
  const site = ci.jobs.site;
  assert.ok(site, "site must be a qualification job");
  assert.equal(pagesRuns.at(-1), "pnpm site");
  assert.deepEqual(site.steps.filter(s => s.run).map(s => s.run), pagesRuns.slice(1),
    "CI uses the same setup and sole build command as Pages, without the deployment ref gate");
  assert.doesNotMatch(commands(site), /\bpnpm (?:run )?build(?:\s|$)/);
  assert.equal(ci.defaults.run.shell, "bash");
  assert.equal(site["runs-on"], "ubuntu-24.04");
  assert.equal(site["timeout-minutes"], 5);
  assert.ok(ci.jobs.qualified.needs.includes("site"));
  for (const step of site.steps.filter(s => s.uses)) {
    assert.match(step.uses, /@[a-f\d]{40}$/);
    if (step.uses.startsWith("actions/checkout@")) assert.equal(step.with["persist-credentials"], false);
    if (step.uses.startsWith("actions/setup-node@")) assert.equal(step.with["package-manager-cache"], false);
  }
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
      assert.match(commands(job), /pnpm_version=\$\(pnpm --version\)\s+test "pnpm@\$pnpm_version" = "\$manager"/);
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
