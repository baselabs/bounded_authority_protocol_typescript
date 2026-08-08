#!/usr/bin/env tsx
// Standalone two-boundary key census for @bounded-authority/verifier (BAP-09 T5). Runs ONLY the
// census (no verdict recompute): loads the corpus, dispatches every case so the verify surfaces
// import their keys at the Ed25519 boundary, then asserts discovery == verify-import ⊇ expected-
// verify-keys == index public_key_fingerprints (ADR 0005 § Census evolution; ADR 0014 Decision 9).
//
// This is the V4-hole guard as a standalone gate: a verify-surface case whose key is never actually
// fed to Ed25519 verify aborts here, catching a runner that certifies a verdict it did not compute.
import { runCensusStandalone } from "./run.js";

runCensusStandalone();
