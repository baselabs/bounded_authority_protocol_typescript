#!/usr/bin/env tsx
// Node runner for the v2 corpus: the runtime-neutral core in conformance/core/v2.ts, loaded from disk.
import { runCore } from "./node_main.js";
import { core } from "./core/v2.js";

runCore(core);
