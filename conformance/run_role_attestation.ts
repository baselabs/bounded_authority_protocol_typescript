#!/usr/bin/env tsx
// Node runner for the role-attestation corpus: the runtime-neutral core in conformance/core/role_attestation.ts, loaded from disk.
import { runCore } from "./node_main.js";
import { core } from "./core/role_attestation.js";

runCore(core);
