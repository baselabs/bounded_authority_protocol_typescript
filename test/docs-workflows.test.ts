import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import { parse } from "yaml";

interface Step { uses?: string; run?: string; with?: Record<string, unknown> }
interface Job { "runs-on": string; "timeout-minutes": number; steps: Step[]; needs?: string[] }
const workflow = parse(readFileSync(new URL("../.github/workflows/ci.yml", import.meta.url), "utf8")) as { jobs: Record<string, Job> };

test("qualification runs both real-kernel notebook modes and durable replay, without cache writes", () => {
  for (const [name, command] of [["notebooks-local", "pnpm notebooks:local"], ["notebooks-published", "pnpm notebooks:published"], ["durable-replay", "pnpm test:docs-replay"]]) {
    const job = workflow.jobs[name!]!;
    assert.ok(job); assert.equal(job["runs-on"], "ubuntu-24.04"); assert.ok(job["timeout-minutes"] > 0);
    assert.ok(workflow.jobs.qualified!.needs!.includes(name!));
    assert.ok(job.steps.some((step) => step.run === command));
    const run = job.steps.map((step) => step.run ?? "").join("\n");
    assert.match(run, /pnpm install --frozen-lockfile/);
    if (name!.startsWith("notebooks-")) {
      assert.match(run, /uv sync --frozen/); assert.match(run, /python --version/);
      assert.match(run, /deno --version/); assert.match(run, /uv --version/);
      assert.match(run, /\.tool-versions/);
    }
    for (const step of job.steps.filter((step) => step.uses)) {
      assert.match(step.uses!, /@[a-f\d]{40}$/);
      assert.ok(!step.uses!.startsWith("actions/cache@"));
      assert.equal(step.with?.cache, undefined);
      if (step.uses!.startsWith("actions/checkout@")) assert.equal(step.with?.["persist-credentials"], false);
      if (step.uses!.startsWith("actions/setup-node@")) assert.equal(step.with?.["package-manager-cache"], false);
      if (step.uses!.startsWith("astral-sh/setup-uv@")) assert.equal(step.with?.["enable-cache"], false);
    }
  }
});
