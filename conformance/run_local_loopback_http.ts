#!/usr/bin/env tsx
// Node runner for the local-loopback-http corpus: the runtime-neutral core in conformance/core/local_loopback_http.ts, loaded from disk.
import { runCore } from "./node_main.js";
import { core } from "./core/local_loopback_http.js";

runCore(core);
