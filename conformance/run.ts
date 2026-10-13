#!/usr/bin/env tsx
// Node runner for the v1 corpus: the runtime-neutral core in conformance/core/v1.ts, loaded from disk.
import { runCore } from "./node_main.js";
import { core } from "./core/v1.js";

runCore(core);
