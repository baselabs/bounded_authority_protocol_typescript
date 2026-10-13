// The bundle-size gate (pnpm size, which builds first): the committed budgets hold, and the gate is
// red-capable (a budget one byte below the current measurement fails, as does a missing budget).
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
// @ts-expect-error tools/bundle-size.mjs is untyped JavaScript
import { BUDGET_FILE, measure, overBudget } from "../tools/bundle-size.mjs";

type Sizes = Record<string, { min: number; gzip: number }>;
const measured = (await measure()) as Sizes;
const budget = (JSON.parse(readFileSync(BUDGET_FILE, "utf8")) as { budgets: Sizes }).budgets;

test("every shape is within its committed budget", (t) => {
  assert.deepEqual(overBudget(measured, budget), []);
  for (const [shape, m] of Object.entries(measured)) t.diagnostic(`${shape}: ${m.min} B minified, ${m.gzip} B gzip`);
});

test("red-proof: a budget one byte below the current measurement fails, for each shape and each measure", () => {
  for (const [shape, m] of Object.entries(measured)) {
    for (const key of ["min", "gzip"] as const) {
      const tight: Sizes = { ...budget, [shape]: { ...budget[shape]!, [key]: m[key] - 1 } };
      assert.equal(overBudget(measured, tight).length, 1, `${shape} ${key}`);
    }
  }
});

test("red-proof: a shape without a budget fails", () => {
  const { [Object.keys(measured)[0]!]: _dropped, ...rest } = budget;
  assert.equal(overBudget(measured, rest).length, 1);
});
