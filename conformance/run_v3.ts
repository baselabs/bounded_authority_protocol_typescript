#!/usr/bin/env tsx
// Node runner for the v3 corpus: the runtime-neutral core in conformance/core/v3.ts, loaded from disk.
import { runCore } from "./node_main.js";
import { core } from "./core/v3.js";

runCore(core);
