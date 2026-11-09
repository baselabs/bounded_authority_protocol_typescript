#!/usr/bin/env tsx
// Node runner for the selector-float-zero corpus: the runtime-neutral core in
// conformance/core/selector_float_zero.ts, loaded from disk.
import { runCore } from "./node_main.js";
import { core } from "./core/selector_float_zero.js";

runCore(core);
