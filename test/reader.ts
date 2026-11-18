// Installed declarations and samples use the candidate in qualification, npm after upload.
import { test } from "node:test";
import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdtempSync, readFileSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import ts from "typescript";
import semver from "semver";
// @ts-expect-error tools/pack.mjs is untyped JavaScript
import { pack } from "../tools/pack.mjs";
import { authoredSamples, type Sample } from "./support/documents.js";

const REPO = fileURLToPath(new URL("..", import.meta.url));
const SAMPLES = authoredSamples(REPO);
const SIGNER_ENTRY = realpathSync(fileURLToPath(import.meta.resolve("@bounded-authority-protocol/signer")));
const label = (sample: Sample): string => `${sample.doc}:${sample.line}`;
const mode = process.env.BAP_SAMPLE_MODE ?? "candidate";
assert.ok(mode === "candidate" || mode === "published", "BAP_SAMPLE_MODE must be candidate or published");
const VERSION = (JSON.parse(readFileSync(join(REPO, "package.json"), "utf8")) as { version: string }).version;
const SIGNER_VERSION = (JSON.parse(readFileSync(join(SIGNER_ENTRY, "..", "..", "..", "package.json"), "utf8")) as { version: string }).version;
const READER = SAMPLES.filter((s) => s.since === undefined || semver.lte(s.since, VERSION));
let consumer = "";
const readerFiles = new Map<Sample, string>();

test(`${mode}: install the inspected package in a fresh consumer`, () => {
  assert.ok(semver.valid(VERSION), `package version must be valid (${VERSION})`);
  assert.ok(READER.some((s) => s.doc === "README.md"), "the README quickstart is on the reader path");
  consumer = mkdtempSync(join(tmpdir(), "bap-docs-reader-"));
  const artifact = mode === "candidate" ? pack(join(consumer, "packed")).file : undefined;
  const metadata = mode === "published" ? JSON.parse(execFileSync("npm", ["view", `@bounded-authority-protocol/verifier@${VERSION}`, "--json", "--registry=https://registry.npmjs.org/"], { encoding: "utf8" })) as {
    name: string; version: string; dist: { tarball: string; integrity: string };
  } : undefined;
  if (metadata) {
    assert.equal(metadata.name, "@bounded-authority-protocol/verifier"); assert.equal(metadata.version, VERSION);
    assert.ok(metadata.dist.tarball.startsWith("https://registry.npmjs.org/"));
  }
  writeFileSync(join(consumer, "package.json"), JSON.stringify({
    name: "bap-docs-reader", private: true, type: "module",
    dependencies: { "@bounded-authority-protocol/verifier": artifact ? pathToFileURL(artifact).href : VERSION, "@bounded-authority-protocol/signer": SIGNER_VERSION },
  }));
  execFileSync("npm", ["install", "--ignore-scripts", "--no-audit", "--no-fund", "--loglevel=error", "--registry=https://registry.npmjs.org/"], { cwd: consumer, stdio: "ignore" });
  const installed = JSON.parse(readFileSync(join(consumer, "node_modules/@bounded-authority-protocol/verifier/package.json"), "utf8")) as { name: string; version: string };
  assert.equal(installed.name, "@bounded-authority-protocol/verifier"); assert.equal(installed.version, VERSION);
  const locked = JSON.parse(readFileSync(join(consumer, "package-lock.json"), "utf8")).packages["node_modules/@bounded-authority-protocol/verifier"] as { resolved: string; integrity: string };
  if (artifact) {
    assert.ok(locked.resolved.startsWith("file:"), "candidate must resolve to the packed archive");
    assert.equal(locked.integrity, "sha512-" + createHash("sha512").update(readFileSync(artifact)).digest("base64"));
  } else {
    assert.equal(locked.resolved, metadata!.dist.tarball); assert.equal(locked.integrity, metadata!.dist.integrity);
  }
  for (const [i, sample] of READER.entries()) {
    const file = join(consumer, `sample-${i}.mts`);
    writeFileSync(file, sample.code);
    readerFiles.set(sample, file);
  }
  // One strict program checks every eligible module before any sample is executed. Neither
  // module paths nor conditions can resolve the source tree from this fresh consumer.
  const diagnostics = installedDiagnostics([...readerFiles.values()]).map((diagnostic) => {
    const file = diagnostic.file?.fileName;
    const sample = READER.find((item) => readerFiles.get(item) === file);
    return `${sample ? label(sample) : file ?? "declaration"}: ${ts.flattenDiagnosticMessageText(diagnostic.messageText, "\n")}`;
  });
  assert.deepEqual(diagnostics, [], "all reader samples must typecheck against installed declarations before execution");
});

function installedDiagnostics(files: string[]): readonly ts.Diagnostic[] {
  // No paths map, source conditions or declaration substitution. Resolution starts in the fresh
  // consumer, so every verifier symbol comes from the installed package's own exports and .d.ts.
  return ts.getPreEmitDiagnostics(ts.createProgram(files, {
    target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.NodeNext, moduleResolution: ts.ModuleResolutionKind.NodeNext,
    strict: true, noUncheckedIndexedAccess: true, exactOptionalPropertyTypes: true, skipLibCheck: false,
    noEmit: true, lib: ["lib.es2022.d.ts"], types: ["node"], typeRoots: [join(REPO, "node_modules/@types")],
  }));
}

test("installed declaration gate rejects an import of a type absent from the artifact", () => {
  const file = join(consumer, "unreleased-type-probe.mts");
  writeFileSync(file, 'import type { DocumentationTypeNotInThePublishedRelease } from "@bounded-authority-protocol/verifier";\n');
  const candidate = join(consumer, "candidate-only.d.mts");
  writeFileSync(candidate, "export interface DocumentationTypeNotInThePublishedRelease { candidate: true }\n");
  const sourceMapped = ts.createProgram([file], {
    target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.NodeNext, moduleResolution: ts.ModuleResolutionKind.NodeNext,
    noEmit: true, strict: true, skipLibCheck: false,
    paths: { "@bounded-authority-protocol/verifier": [candidate] },
  });
  assert.deepEqual(ts.getPreEmitDiagnostics(sourceMapped), [], "a candidate source mapping accepts this unshipped type (positive control)");
  const diagnostics = installedDiagnostics([file]);
  assert.ok(diagnostics.some((diagnostic) => diagnostic.code === 2305 &&
    ts.flattenDiagnosticMessageText(diagnostic.messageText, " ").includes("DocumentationTypeNotInThePublishedRelease")),
  "the same checker used for samples must reject an unshipped type");
  writeFileSync(file, 'import type { ExpectedRequest } from "@bounded-authority-protocol/verifier";\n');
  assert.deepEqual(installedDiagnostics([file]), [], "a shipped type is the positive control");
});

for (const sample of READER) {
  test(`${mode}: docs sample on the installed package: ${label(sample)}`, () => {
    assert.ok(consumer !== "", "the consumer was installed");
    const file = readerFiles.get(sample)!;
    const conditions = process.execArgv.filter((a) => a === "--conditions=bap-portable");
    const child = spawnSync(process.execPath, [...conditions, file], { cwd: consumer, encoding: "utf8" });
    assert.equal(child.status, 0, `${label(sample)} fails on the ${mode} ${VERSION}:\n${child.stderr}`);
  });
}

test.after(() => { if (consumer !== "") rmSync(consumer, { recursive: true, force: true }); });
