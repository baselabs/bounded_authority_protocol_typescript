#!/usr/bin/env tsx
// Node runner for the producer-canonicality corpus: the runtime-neutral core in
// conformance/core/producer_canonicality.ts, loaded from disk.
import { runCore } from "./node_main.js";
import { core } from "./core/producer_canonicality.js";

runCore(core);
