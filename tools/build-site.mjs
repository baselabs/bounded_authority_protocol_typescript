// Pages and qualification render and check one site; only the API source changes.
import assert from "node:assert/strict";
import spawn from "cross-spawn";
import { dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { parseArgs } from "node:util";

const { values } = parseArgs({ options: { source: { type: "string", default: "release" } } });
const source = values.source;
assert.ok(source === "release" || source === "commit", "source must be release or commit");
const root = dirname(dirname(fileURLToPath(import.meta.url)));
const steps = [
  "typecheck:web",
  "build:site",
  "docs:api:release",
  "test:network:pages",
  "check:site",
  "guard:site"
];
for (const step of steps) {
  const args = ["run", step];
  if (step === "docs:api:release" || step === "check:site") args.push(`--source=${source}`);
  const result = spawn.sync("pnpm", args, {
    cwd: root, env: { ...process.env, BAP_SITE_SOURCE: source }, stdio: "inherit",
  });
  if (result.error) throw result.error;
  assert.equal(result.status, 0, `${step} failed for ${source} source`);
}
