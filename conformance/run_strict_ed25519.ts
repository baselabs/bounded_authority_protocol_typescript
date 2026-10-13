#!/usr/bin/env tsx
// Node runner for the strict-ed25519 corpus: the runtime-neutral core in conformance/core/strict_ed25519.ts, loaded from disk.
import { runCore } from "./node_main.js";
import { core } from "./core/strict_ed25519.js";

runCore(core);
