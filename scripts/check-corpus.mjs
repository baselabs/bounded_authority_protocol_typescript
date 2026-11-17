#!/usr/bin/env node
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import semver from "semver";
import { assertReleaseSource, compareSnapshot, parseSource, releaseArtifact, vendor } from "./corpus-artifact.mjs";
import { assertCurrent, eligibleRelease } from "./corpus-policy.mjs";
const root = fileURLToPath(new URL("..", import.meta.url));
const [mode, flag, ...rest] = process.argv.slice(2);
try {
  if (!["ci", "release", "adopt"].includes(mode) || (flag !== undefined && !(mode === "ci" && flag === "--main")) || rest.length) throw new Error("usage: node scripts/check-corpus.mjs ci [--main] | release | adopt");
  const source = parseSource(readFileSync(new URL("../conformance/SOURCE", import.meta.url)));
  if (mode === "ci" && source.candidate !== undefined && flag !== "--main") {
    // Candidate PRs compare against the immutable commit archive, never an unrelated Hex release.
    const { mkdtempSync, rmSync } = await import("node:fs");
    const { join } = await import("node:path");
    const temp = mkdtempSync(join(root, ".corpus-compare-"));
    try {
      const { treeFiles } = await import("./corpus-artifact.mjs");
      await vendor(temp, undefined, source.candidate);
      compareSnapshot(root, treeFiles(join(temp, "conformance/priv/conformance")), source);
    } finally { rmSync(temp, {recursive: true, force: true}); }
  } else {
    assertReleaseSource(source, flag === "--main");
    if (mode === "adopt") {
      const newest = await eligibleRelease();
      // Pin replacement always fails closed, including scheduled adoption.
      if (source.version === newest.version) assertCurrent(source, newest);
      else if (semver.gt(newest.version, source.version)) { await vendor(root, newest.version); console.log(`Adopted Hex ${newest.version}`); }
    } else {
      if (mode === "release") assertCurrent(source, await eligibleRelease());
      const {files} = await releaseArtifact(source.version, source.checksum);
      compareSnapshot(root, files, source);
    }
  }
  console.log(`corpus ${mode}: PASS`);
} catch (error) { console.error(error.message); process.exitCode = 1; }
