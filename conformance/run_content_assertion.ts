#!/usr/bin/env tsx
// Node runner for the content-assertion corpus: the runtime-neutral core in conformance/core/content_assertion.ts, loaded from disk.
import { runCore } from "./node_main.js";
import { core } from "./core/content_assertion.js";

runCore(core);
