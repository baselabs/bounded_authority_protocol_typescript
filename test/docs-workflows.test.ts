import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import { parse } from "yaml";

interface Step { uses?: string; run?: string; with?: Record<string, unknown> }
interface Job { "runs-on": string; "timeout-minutes": number; steps: Step[]; needs?: string[] }
const workflow = parse(readFileSync(new URL("../.github/workflows/ci.yml", import.meta.url), "utf8")) as { jobs: Record<string, Job> };
const notebookTools = parse(readFileSync(new URL("../.github/actions/notebook-tools/action.yml", import.meta.url), "utf8")) as { runs: { using: string; steps: Step[] } };

test("qualification runs candidate notebooks and durable replay, without cache writes", () => {
  assert.equal(notebookTools.runs.using, "composite");
  for (const [name, command] of [["notebooks-local", "pnpm notebooks:local"], ["durable-replay", "pnpm test:docs-replay"]]) {
    const job = workflow.jobs[name!]!;
    assert.ok(job); assert.equal(job["runs-on"], "ubuntu-24.04"); assert.ok(job["timeout-minutes"] > 0);
    assert.ok(workflow.jobs.qualified!.needs!.includes(name!));
    assert.ok(job.steps.some((step) => step.run === command));
    const steps = job.steps.flatMap((step) => step.uses === "./.github/actions/notebook-tools" ? notebookTools.runs.steps : [step]);
    const run = steps.map((step) => step.run ?? "").join("\n");
    assert.match(run, /pnpm install --frozen-lockfile/);
    if (name!.startsWith("notebooks-")) {
      assert.ok(job.steps.some((step) => step.uses === "./.github/actions/notebook-tools"));
      assert.match(run, /uv sync --frozen/); assert.match(run, /tool-versions\.sh check python/);
      assert.match(run, /tool-versions\.sh check deno/); assert.match(run, /tool-versions\.sh check uv/);
      assert.match(run, /tool-versions\.sh read nodejs deno python uv/);
      assert.ok(run.indexOf("uv lock --check") >= 0 && run.indexOf("uv lock --check") < run.indexOf("uv sync --frozen"));
    }
    for (const step of steps.filter((step) => step.uses)) {
      assert.match(step.uses!, /@[a-f\d]{40}$/);
      assert.ok(!step.uses!.startsWith("actions/cache@"));
      assert.equal(step.with?.cache, undefined);
      if (step.uses!.startsWith("actions/checkout@")) assert.equal(step.with?.["persist-credentials"], false);
      if (step.uses!.startsWith("actions/setup-node@")) assert.equal(step.with?.["package-manager-cache"], false);
      if (step.uses!.startsWith("astral-sh/setup-uv@")) {
        assert.equal(step.with?.["enable-cache"], false); assert.equal(step.with?.["save-cache"], false);
      }
    }
  }
});

test("development API coverage cannot enter the Pages artifact", () => {
  const pages = readFileSync(new URL("../.github/workflows/pages.yml", import.meta.url), "utf8");
  const development = readFileSync(new URL("../tools/build-docs.mjs", import.meta.url), "utf8");
  const release = readFileSync(new URL("../tools/build-release-api.mjs", import.meta.url), "utf8");
  assert.match(development, /build-docs\/api/);
  assert.ok(!pages.includes("run: pnpm docs:api\n"));
  assert.ok(!pages.includes("api-development"));
  assert.ok(!release.includes("buildDocumentation"));
  assert.ok(release.includes('join(release, "typedoc.json")'));
  assert.ok(workflow.jobs.verify!.steps.some((step) => step.run === "pnpm docs:api"));
});
