#!/usr/bin/env node
// The browser bundle-size gate (pnpm size, after pnpm build). Measures the published entry
// (dist/src/index.js) as a browser bundler tree-shakes it, minified, in bytes and gzip bytes (level 9),
// for three import shapes, and fails when any measurement exceeds its budget in
// tools/bundle-size-budget.json. The budgets were set at the first measurement plus 10%; raising one
// is a deliberate, reviewed edit of that file. test/bundle-size.ts red-proofs the gate.
import { build } from "esbuild";
import { readFileSync } from "node:fs";
import { gzipSync } from "node:zlib";
import { dirname, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const ROOT = dirname(dirname(fileURLToPath(import.meta.url)));
export const BUDGET_FILE = join(ROOT, "tools/bundle-size-budget.json");

export const SHAPES = {
  "root (every export)": 'export * from "./dist/src/index.js";',
  "{ v3 }": 'export { v3 } from "./dist/src/index.js";',
  "{ checkEnvelope } (v1)": 'export { checkEnvelope } from "./dist/src/index.js";',
};

export async function measure() {
  const out = {};
  for (const [shape, contents] of Object.entries(SHAPES)) {
    const result = await build({
      stdin: { contents, resolveDir: ROOT, sourcefile: "size-entry.js", loader: "js" },
      absWorkingDir: ROOT, bundle: true, write: false, format: "esm", platform: "browser", target: "es2022",
      minify: true, metafile: true, logLevel: "silent",
    });
    const bytes = result.outputFiles[0].contents;
    out[shape] = { min: bytes.length, gzip: gzipSync(bytes, { level: 9 }).length };
  }
  return out;
}

// Returns the list of measurements over budget (empty when within budget). A shape with no budget is
// a failure too: the gate never passes an unbudgeted measurement.
export function overBudget(measured, budget) {
  const problems = [];
  for (const [shape, m] of Object.entries(measured)) {
    const b = budget[shape];
    if (!b) { problems.push(`${shape}: no budget`); continue; }
    if (m.min > b.min) problems.push(`${shape}: ${m.min} minified bytes > budget ${b.min}`);
    if (m.gzip > b.gzip) problems.push(`${shape}: ${m.gzip} gzip bytes > budget ${b.gzip}`);
  }
  return problems;
}

async function main() {
  const measured = await measure();
  const budget = JSON.parse(readFileSync(BUDGET_FILE, "utf8")).budgets;
  for (const [shape, m] of Object.entries(measured)) {
    console.log(`bundle-size: ${shape}: ${m.min} B minified, ${m.gzip} B gzip (budget ${budget[shape]?.min ?? "none"} / ${budget[shape]?.gzip ?? "none"})`);
  }
  const problems = overBudget(measured, budget);
  if (problems.length > 0) {
    for (const p of problems) console.error(`bundle-size: OVER ${p}`);
    process.exit(1);
  }
  console.log("bundle-size: PASS (every shape within budget)");
}

if (process.argv[1] && pathToFileURL(process.argv[1]).href === import.meta.url) await main();
