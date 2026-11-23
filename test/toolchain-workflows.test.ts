import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync, readdirSync, statSync } from "node:fs";
import { test } from "node:test";
import { parse } from "yaml";

interface Step { id?: string; uses?: string; run?: string; with?: Record<string, unknown> }
interface Job {
  needs?: string | string[];
  outputs?: Record<string, string>;
  strategy?: { matrix: Record<string, unknown> };
  steps: Step[];
}
interface Workflow { jobs: Record<string, Job> }
interface Action { runs: { using: string; steps: Step[] } }

function yamlFiles(directory: URL): URL[] {
  return readdirSync(directory, { withFileTypes: true }).flatMap((entry) => {
    const file = new URL(entry.name, directory);
    return entry.isDirectory() ? yamlFiles(new URL(`${entry.name}/`, directory))
      : /\.ya?ml$/.test(entry.name) ? [file] : [];
  });
}

const readPins = 'scripts/toolchain.sh >> "$GITHUB_OUTPUT"';
const primary = "${{ steps.pins.outputs.nodejs }}";
const compatibility = "${{ fromJSON(steps.pins.outputs.nodejs_lanes)[0] }}";
const lane = "${{ matrix.node-version }}";
const ci = parse(readFileSync(new URL("../.github/workflows/ci.yml", import.meta.url), "utf8")) as Workflow;

test("the shared toolchain reader has its required bytes and executable mode", () => {
  const reader = new URL("../scripts/toolchain.sh", import.meta.url);
  assert.equal(createHash("sha256").update(readFileSync(reader)).digest("hex"),
    "b29bfeb6ec4ec8f5b7e3ac3c963f04b6d3c73483172e5bd59ea40f20b102f1eb");
  assert.equal(statSync(reader).mode & 0o777, 0o755);
  assert.ok(ci.jobs.toolchain!.steps.some((step) => step.run === "scripts/toolchain.sh --self-test"));
});

test("every runtime setup uses shared outputs and checks supported tools after installation", () => {
  const files = yamlFiles(new URL("../.github/", import.meta.url));
  const setups = [
    ["actions/setup-node@", "node-version", "nodejs"],
    ["denoland/setup-deno@", "deno-version", "deno"],
    ["oven-sh/setup-bun@", "bun-version", "bun"],
    ["actions/setup-python@", "python-version", "python"],
    ["astral-sh/setup-uv@", "version", "uv"],
  ] as const;
  let checked = 0;
  for (const file of files) {
    const source = readFileSync(file, "utf8");
    assert.doesNotMatch(source, /(?:bash|sh) scripts\/toolchain\.sh|--installed (?:deno|bun|python|uv)=/, file.pathname);
    const document = parse(source) as Workflow | Action;
    const groups = "jobs" in document ? Object.values(document.jobs).map((job) => job.steps)
      : document.runs.using === "composite" ? [document.runs.steps] : [];
    for (const steps of groups) {
      for (const [index, step] of steps.entries()) {
        for (const [input, value] of Object.entries(step.with ?? {})) {
          assert.doesNotMatch(input, /version.*file|file.*version/, `${file.pathname}: ${input}`);
          assert.notEqual(value, ".tool-versions", `${file.pathname}: ${input}`);
        }
        const setup = setups.find(([action]) => step.uses?.startsWith(action));
        if (!setup) continue;
        checked++;
        const [, input, tool] = setup;
        const reader = steps.findIndex((candidate) => candidate.id === "pins" && candidate.run === readPins);
        assert.ok(reader >= 0 && reader < index, `${file.pathname}: ${tool} needs the reader before setup`);
        const version = step.with?.[input];
        if (tool === "nodejs") {
          assert.ok([primary, compatibility, lane].includes(String(version)), `${file.pathname}: ${input}`);
          assert.equal(steps[index + 1]?.run, `scripts/toolchain.sh --installed nodejs=${String(version)}`,
            `${file.pathname}: refuse a different Node before using it`);
        } else {
          assert.equal(version, "${{ steps.pins.outputs." + tool + " }}", `${file.pathname}: ${input}`);
        }
        if (tool === "python") {
          assert.equal(step.with?.["check-latest"], false);
          assert.equal(step.with?.["allow-prereleases"], false);
        }
      }
    }
  }
  assert.ok(checked > 0, "runtime setup actions must be checked");
});

test("Node compatibility versions drive the matrix while existing check names stay stable", () => {
  const toolchain = ci.jobs.toolchain!;
  assert.deepEqual(toolchain.outputs, {
    nodejs: primary,
    nodejs_lanes: "${{ steps.pins.outputs.nodejs_lanes }}",
  });
  const verify = ci.jobs.verify!;
  assert.equal(verify.needs, "toolchain");
  assert.deepEqual(verify.strategy!.matrix, {
    os: ["ubuntu-24.04"],
    "node-version": "${{ fromJSON(needs.toolchain.outputs.nodejs_lanes) }}",
    include: [
      { "node-line": "nodejs-next" },
      { os: "ubuntu-24.04", "node-version": "${{ needs.toolchain.outputs.nodejs }}", "node-line": "nodejs" },
    ],
  });
  const auditSetup = ci.jobs["supply-chain"]!.steps.find((step) => step.uses?.startsWith("actions/setup-node@"));
  assert.equal(auditSetup?.with?.["node-version"], compatibility);
});
