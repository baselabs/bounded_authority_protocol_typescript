// Every lane asserts which crypto backend it is exercising before it trusts a verdict (design M1).
// On Node under the package's test conditions (bap-source) the backend is the node:crypto one, and
// with bap-portable added (pnpm test:portable) it is the portable one; the Deno, Bun and browser lanes
// assert "portable" on their own.
import { test } from "node:test";
import assert from "node:assert/strict";
import { BACKEND_ID } from "../src/index.js";

// The lane's expectation comes from the flag the lane was started with, never from the module under
// test: --conditions=bap-portable (or -C bap-portable) must resolve the portable backend.
const portableFlag = process.execArgv.some((a, i, all) =>
  a === "--conditions=bap-portable" || a === "-C=bap-portable" ||
  ((a === "--conditions" || a === "-C") && all[i + 1] === "bap-portable"));
const EXPECTED = portableFlag ? "portable" : "node";

test(`BACKEND_ID is "${EXPECTED}" in this lane`, () => {
  assert.equal(BACKEND_ID, EXPECTED);
});
