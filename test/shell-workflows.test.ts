import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { parse } from "yaml";

interface Defaults { run?: { shell?: string } }
interface Step { run?: string; shell?: string }
interface Workflow { defaults?: Defaults; jobs: Record<string, { defaults?: Defaults; steps?: Step[] }> }
interface Action { runs?: { using?: string; steps?: Step[] } }

const REPO = fileURLToPath(new URL("..", import.meta.url));

test("workflows, composite actions and tracked shell scripts preserve command failures", () => {
  const files = execFileSync("git", ["ls-files", "-z"], { cwd: REPO, encoding: "utf8" })
    .split("\0").filter((file) => file.length > 0)
    .map((file) => ({ file, source: readFileSync(join(REPO, file), "utf8") }));
  const workflows = files.filter(({ file }) => /^\.github\/workflows\/[^/]+\.ya?ml$/.test(file));
  const actions = files.filter(({ file }) => /(?:^|\/)action\.ya?ml$/.test(file));
  const scripts = files.filter(({ file, source }) => /\.(?:ba|da|k|z)?sh$/.test(file)
    || /^#![^\n]*\b(?:bash|sh|dash|ksh|zsh)\b/.test(source));
  assert.ok(workflows.length > 0, "workflows must be checked");
  assert.ok(actions.length > 0, "composite actions must be checked");
  assert.ok(scripts.length > 0, "tracked shell scripts must be checked");

  for (const { file, source } of workflows) {
    const workflow = parse(source) as Workflow;
    assert.equal(workflow.defaults?.run?.shell, "bash", file);
    for (const [name, job] of Object.entries(workflow.jobs)) {
      assert.equal(job.defaults?.run?.shell ?? "bash", "bash", `${file}: ${name}`);
      for (const step of job.steps ?? []) {
        if (step.run !== undefined) assert.equal(step.shell ?? "bash", "bash", `${file}: ${step.run}`);
      }
    }
  }
  for (const { file, source } of actions) {
    const action = parse(source) as Action;
    if (action.runs?.using !== "composite") continue;
    assert.ok(action.runs.steps, `${file}: composite steps are required`);
    for (const step of action.runs.steps) {
      if (step.run !== undefined) assert.equal(step.shell, "bash", `${file}: ${step.run}`);
    }
  }
  for (const { file, source } of scripts) {
    const lines = source.split(/\r?\n/);
    assert.equal(lines[0], "#!/usr/bin/env bash", file);
    const statement = lines.slice(1).map((line) => line.trim())
      .find((line) => line.length > 0 && !line.startsWith("#")) ?? "";
    assert.match(statement, /^set -(?=[a-z]*e)(?=[a-z]*u)[a-z]*o pipefail(?:\s+#.*)?$/, file);
  }
  for (const { file, source } of [...workflows, ...actions, ...scripts]) {
    const commands = source.replace(/\\\r?\n/g, " ");
    assert.doesNotMatch(commands, /\|\|\s*(?:true|:)(?=$|[\s;&|)])/m, file);
    assert.doesNotMatch(commands, /\becho\b[^\n;]*\$\(/, file);
    assert.doesNotMatch(commands, /\bfor\s+\w+\s+in\b[^\n;]*\$\(/, file);
    assert.doesNotMatch(commands, /<\(/, file);
  }
});
