#!/usr/bin/env node
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { assertReleaseSource, compareSnapshot, parseSource, treeFiles, validateArtifact, releaseArtifact, vendor } from "./corpus-artifact.mjs";
import { adoptionDecision, assertCurrent, eligibleRelease } from "./corpus-policy.mjs";
import { assertDocumentation } from "./corpus-docs.mjs";
const root = fileURLToPath(new URL("..", import.meta.url));
const [mode, flag, ...rest] = process.argv.slice(2);
try {
  if (!["offline", "ci", "release", "adopt"].includes(mode) || (flag !== undefined && !(["offline", "ci"].includes(mode) && flag === "--main")) || rest.length) throw new Error("usage: node scripts/check-corpus.mjs offline [--main] | ci [--main] | release | adopt");
  const source = parseSource(readFileSync(new URL("../conformance/SOURCE", import.meta.url)));
  const files = treeFiles(fileURLToPath(new URL("../conformance/priv/conformance", import.meta.url)));
  validateArtifact(files, source);
  assertDocumentation(root, files, source);
  if (mode === "offline") {
    if (flag === "--main") assertReleaseSource(source, true);
  } else if (mode === "ci" && source.candidate !== undefined && flag !== "--main") {
    // Candidate PRs compare against the immutable commit archive, never an unrelated Hex release.
    const { mkdtempSync, rmSync } = await import("node:fs");
    const { join } = await import("node:path");
    const temp = mkdtempSync(join(root, ".corpus-compare-"));
    try {
      await vendor(temp, undefined, source.candidate);
      compareSnapshot(root, treeFiles(join(temp, "conformance/priv/conformance")), source);
    } finally { rmSync(temp, {recursive: true, force: true}); }
  } else {
    assertReleaseSource(source, flag === "--main");
    if (mode === "adopt") {
      const newest = await eligibleRelease();
      // Pin replacement always fails closed, including scheduled adoption.
      const decision = adoptionDecision(source, newest);
      if (decision === "adopt") { await vendor(root, newest.version, undefined, newest.checksum); console.log(`Adopted Hex ${newest.version}`); }
      else if (decision === "ahead") console.log(`SOURCE ${source.version} is ahead of newest eligible Hex ${newest.version}; keeping the pinned snapshot while its release window closes.`);
    } else {
      if (mode === "release") assertCurrent(source, await eligibleRelease());
      const {files} = await releaseArtifact(source.version, source.checksum);
      compareSnapshot(root, files, source);
    }
  }
  console.log(`corpus ${mode}: PASS`);
} catch (error) { console.error(error.message); process.exitCode = 1; }
