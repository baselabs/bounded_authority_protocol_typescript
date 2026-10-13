// Every lane asserts which crypto backend it is exercising before it trusts a verdict (design M1).
// Under the package's test conditions on Node (bap-source, no bap-portable) the backend is the
// node:crypto one; conformance:portable and the Deno, Bun and browser lanes assert "portable".
import { test } from "node:test";
import assert from "node:assert/strict";
import { BACKEND_ID } from "../src/index.js";

const EXPECTED = process.env.BAP_EXPECT_BACKEND ?? "node";

test(`BACKEND_ID is "${EXPECTED}" in this lane`, () => {
  assert.equal(BACKEND_ID, EXPECTED);
});
