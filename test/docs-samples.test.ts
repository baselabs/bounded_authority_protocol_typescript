// Every TypeScript sample in the public docs runs here: each ```ts fence in README.md and docs/**/*.md
// is a complete module that is typechecked (strict, against this repository's source) and then executed
// on the backend the test run selects (node by default, portable under test:portable). A sample asserts
// its own result with node:assert, so a sample that silently stops verifying fails here. No mocks: the
// samples generate real keys with node:crypto, sign real bytes and verify them through the package.
//
// The two package specifiers a sample may import are rewritten to this repository's source
// (@bounded-authority-protocol/verifier) and to the installed signer dev dependency
// (@bounded-authority-protocol/signer). A sample that imports the signer runs in a child Node process
// against this repository's BUILT package (dist/, so pnpm test builds first) without the bap-source
// condition: the signer loads its own published verifier, whose "#crypto" map would send bap-source to
// source files a published package does not ship. A fence tagged anything other than `ts` (bash, json, text) is
// not executed; `typescript`, `js` and `javascript` fences are refused so no sample can escape this
// harness by its tag.
import { test } from "node:test";
import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync, readdirSync, realpathSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, relative } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import ts from "typescript";
import semver from "semver";
import { commentProse } from "./comments.js";

const REPO = fileURLToPath(new URL("..", import.meta.url));
const VERIFIER_SOURCE = join(REPO, "src", "index.ts");
const VERIFIER_BUILT = join(REPO, "dist", "src", "index.js");
const SIGNER_ENTRY = realpathSync(fileURLToPath(import.meta.resolve("@bounded-authority-protocol/signer")));
const SIGNER_TYPES = SIGNER_ENTRY.replace(/\.js$/, ".d.ts");
const SPECIFIERS: Record<string, { run: string; types: string }> = {
  "@bounded-authority-protocol/verifier": { run: pathToFileURL(VERIFIER_SOURCE).href, types: VERIFIER_SOURCE },
  "@bounded-authority-protocol/signer": { run: pathToFileURL(SIGNER_ENTRY).href, types: SIGNER_TYPES },
};

interface Sample { readonly doc: string; readonly line: number; readonly code: string; readonly since?: string }

function docFiles(): string[] {
  const out = [join(REPO, "README.md")];
  const walk = (dir: string): void => {
    for (const name of readdirSync(dir).sort()) {
      const full = join(dir, name);
      if (statSync(full).isDirectory()) walk(full);
      else if (name.endsWith(".md")) out.push(full);
    }
  };
  walk(join(REPO, "docs"));
  return out;
}

// A fence opens with three or more backticks or tildes and an info string, at any indent (a sample
// inside a list item is indented); its content is dedented by that indent, and it closes at a line of
// the same character, at least as long, with the same indent (CommonMark). The first word of the
// info string is the language; `ts since=<version>` marks a sample that needs that release (see the
// reader-path test below).
function samplesOf(file: string): Sample[] {
  const lines = readFileSync(file, "utf8").split("\n");
  const samples: Sample[] = [];
  for (let i = 0; i < lines.length; i++) {
    const open = /^( *)(`{3,}|~{3,})(.*)$/.exec(lines[i]!);
    if (open === null) continue;
    const indent = open[1]!;
    const marker = open[2]!;
    const [tag = "", ...attributes] = open[3]!.trim().split(/\s+/);
    const closes = new RegExp(`^${indent}${marker[0] === "\`" ? "\`" : "~"}{${marker.length},}\\s*$`);
    const start = i;
    i++;
    while (i < lines.length && !closes.test(lines[i]!)) i++;
    assert.ok(i < lines.length, `${relative(REPO, file)}:${start + 1}: unterminated fence`);
    assert.ok(!["typescript", "js", "javascript", "mjs", "mts", "tsx"].includes(tag),
      `${relative(REPO, file)}:${start + 1}: tag code samples \`ts\` so they are executed`);
    if (tag !== "ts") continue;
    const since = attributes.find((a) => a.startsWith("since="))?.slice("since=".length);
    assert.ok(attributes.every((a) => a.startsWith("since=")) && (since === undefined || /^\d+\.\d+\.\d+$/.test(since)),
      `${relative(REPO, file)}:${start + 1}: the only fence attribute is since=<version>`);
    const code = lines.slice(start + 1, i).map((l) => (l.startsWith(indent) ? l.slice(indent.length) : l)).join("\n");
    samples.push({ doc: relative(REPO, file), line: start + 1, code, ...(since === undefined ? {} : { since }) });
  }
  return samples;
}

const SAMPLES = docFiles().flatMap(samplesOf);
const label = (s: Sample): string => `${s.doc}:${s.line}`;

function rewrite(code: string, target: "run" | "built" | "types"): string {
  return code.replace(/from "(@bounded-authority-protocol\/[^"]*)"/g, (whole, specifier: string) => {
    const mapped = SPECIFIERS[specifier];
    assert.ok(mapped !== undefined, `unsupported package import ${specifier}`);
    if (target === "types") return whole;
    if (target === "built" && specifier === "@bounded-authority-protocol/verifier") return `from "${pathToFileURL(VERIFIER_BUILT).href}"`;
    return `from "${mapped.run}"`;
  });
}
const usesSigner = (s: Sample): boolean => s.code.includes('from "@bounded-authority-protocol/signer"');

test("the docs carry samples (a known-positive for the fence scan)", () => {
  assert.ok(SAMPLES.some((s) => s.doc === "README.md"), "README.md has no ts sample");
  assert.ok(SAMPLES.length >= 20, `only ${SAMPLES.length} samples found`);
});

test("every docs sample typechecks under strict settings against the source", () => {
  const dir = mkdtempSync(join(tmpdir(), "bap-docs-types-"));
  try {
    const files = SAMPLES.map((s, i) => {
      const file = join(dir, `sample-${i}.mts`);
      writeFileSync(file, rewrite(s.code, "types"));
      return file;
    });
    const options: ts.CompilerOptions = {
      target: ts.ScriptTarget.ES2022,
      module: ts.ModuleKind.NodeNext,
      moduleResolution: ts.ModuleResolutionKind.NodeNext,
      customConditions: ["bap-source"],
      strict: true,
      noUncheckedIndexedAccess: true,
      exactOptionalPropertyTypes: true,
      skipLibCheck: true,
      noEmit: true,
      lib: ["lib.es2022.d.ts"],
      types: ["node"],
      typeRoots: [join(REPO, "node_modules", "@types")],
      paths: Object.fromEntries(Object.entries(SPECIFIERS).map(([name, m]) => [name, [m.types]])),
    };
    const program = ts.createProgram(files, options);
    const diagnostics = ts.getPreEmitDiagnostics(program).map((d) => {
      const at = d.file === undefined ? "" : (() => {
        const index = files.indexOf(d.file.fileName);
        const { line } = d.file.getLineAndCharacterOfPosition(d.start ?? 0);
        return index >= 0 ? `${label(SAMPLES[index]!)} (+${line + 1}): ` : `${d.file.fileName}:${line + 1}: `;
      })();
      return at + ts.flattenDiagnosticMessageText(d.messageText, "\n");
    });
    assert.deepEqual(diagnostics, []);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

// Public readers must be able to follow every normative citation without private records.
function filesUnder(dir: string): string[] {
  return readdirSync(dir).sort().flatMap((name) => {
    const file = join(dir, name);
    return statSync(file).isDirectory() ? filesUnder(file) : [file];
  });
}

const PUBLIC_FILES = [...new Set([
  ...docFiles(), ...readdirSync(REPO).filter((name) => /\.(?:md|json|js|mjs|yml)$/.test(name))
    .map((name) => join(REPO, name)),
  ...["src", "web", "tools", "scripts", ".github/workflows"].flatMap((dir) => filesUnder(join(REPO, dir))),
  ...["test", "conformance", "browser"].flatMap((dir) => filesUnder(join(REPO, dir)))
    .filter((file) => /\.(?:ts|js|mjs)$/.test(file)),
])].filter((file) => /\.(?:md|ts|js|mjs|html|css|json|yml)$/.test(file));
const privateRecord = /(?<![a-z])adrs?(?=$|[^a-z])|architecture[ -]decision[ -]records?/i;

test("private-record hygiene recognizes citation spellings", () => {
  for (const citation of ["ADR", "ADRs", "ADR 14", "ADR-0014", "ADR0014", "ADR_0014", "ADR:0014",
    "ADR#0014", "adr/0014", "docs/adr/0014.md", ".kimosabe/adr/0014", "architecture decision record"]) {
    assert.ok(privateRecord.test(citation), citation);
  }
  assert.equal(privateRecord.test("address and quadrant"), false);
});

test("private-record comment scanning preserves offsets after templates and regexes", () => {
  const source = [
    'const template = `first ${1} tail`;',
    '// ADR-123 is private',
    'const regex = /[/*]/;',
    '/* docs/adr/456.md is private */',
  ].join("\n");
  const hits = commentProse(source, "probe.ts").split("\n")
    .flatMap((line, i) => privateRecord.test(line) ? [i + 1] : []);
  assert.deepEqual(hits, [2, 4]);
});

test("public prose and source cite no unpublished decision record", () => {
  const hits = PUBLIC_FILES.flatMap((file) =>
    (/\.md$/.test(file) ? readFileSync(file, "utf8") : publicProse(file)).split("\n").flatMap((line, i) =>
      (privateRecord.test(line) || /docs\/adr\/|\bADR[ -]?\d/.test(line)) ? [`${relative(REPO, file)}:${i + 1}: ${line.trim()}`] : []));
  assert.deepEqual(hits, []);
});

// Code literals and vectors keep their punctuation. For source files, examine comment trivia
// at their original offsets rather than operators or literals. The private-record gate reads
// full Markdown, including fences; sentence-style checks omit fenced code.
function publicProse(file: string): string {
  const source = readFileSync(file, "utf8");
  if (/\.(?:ts|js|mjs)$/.test(file)) {
    return commentProse(source, file);
  }
  if (file.endsWith(".css")) return source.replace(/(\/\*[\s\S]*?\*\/)|[^\r\n]/g, (text, comment: string | undefined) => comment ?? " ");
  if (file.endsWith(".html")) return source.replace(/<[^>]*>/g, (tag) => tag.startsWith("<!--") ? tag : tag.replace(/[^\r\n]/g, " "));
  if (file.endsWith(".yml")) return source.split("\n").map((line) => /^\s*#/.test(line) ? line : line.replace(/[^\r\n]/g, " ")).join("\n");
  return source.replace(/^\s*(`{3,}|~{3,})[^\n]*\n[\s\S]*?^\s*\1\s*$/gm, (block) => block.replace(/[^\r\n]/g, " "));
}
const proseDash = /—|[a-z][.,;:!?]?[ \t]+-[ \t]+(?=[a-z])/i;

test("prose hygiene distinguishes sentence dashes from code and subtraction", () => {
  assert.ok(proseDash.test("Request bytes — signed exactly."));
  assert.ok(proseDash.test("Request bytes - signed exactly."));
  assert.equal(proseDash.test("2^53 - 1; rowCount - 1; - a list item"), false);
});

test("public prose uses sentences without em dashes or spaced hyphen dashes", () => {
  const hits = PUBLIC_FILES.flatMap((file) => publicProse(file).replace(/`[^`]*`/g, "").split("\n")
    .flatMap((line) => proseDash.test(line) ? [`${relative(REPO, file)}: ${line.trim()}`] : []));
  assert.deepEqual(hits, []);
});

// The reference must name every export: values and types of the package root and of each namespace,
// read from the compiler's view of src/index.ts (so a new export without a reference entry fails).
test("docs/reference.md names every public export", () => {
  const program = ts.createProgram([VERIFIER_SOURCE], {
    target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.NodeNext, moduleResolution: ts.ModuleResolutionKind.NodeNext,
    customConditions: ["bap-source"], noEmit: true, skipLibCheck: true, types: ["node"],
    typeRoots: [join(REPO, "node_modules", "@types")],
  });
  const checker = program.getTypeChecker();
  const moduleSymbol = checker.getSymbolAtLocation(program.getSourceFile(VERIFIER_SOURCE)!)!;
  const names = new Set<string>();
  for (const symbol of checker.getExportsOfModule(moduleSymbol)) {
    names.add(symbol.name);
    const target = symbol.flags & ts.SymbolFlags.Alias ? checker.getAliasedSymbol(symbol) : symbol;
    if (target.flags & ts.SymbolFlags.ValueModule) {
      for (const member of checker.getExportsOfModule(target)) names.add(member.name);
    }
  }
  assert.ok(names.has("verifyGrant") && names.has("ExpectedAnchoredExport") && names.has("AttestorKey"),
    "the export walk must see root values, namespace types and namespace members");
  const reference = readFileSync(join(REPO, "docs", "reference.md"), "utf8");
  const missing = [...names].sort().filter((name) => !new RegExp("`(?:v2\\.|v3\\.)?" + name + "\\b").test(reference));
  assert.deepEqual(missing, []);
});

// The reference's bounds table must equal MAXIMA exactly (no drift between the table and the code).
test("the reference bounds table equals MAXIMA", async () => {
  const { MAXIMA } = await import(pathToFileURL(VERIFIER_SOURCE).href) as { MAXIMA: Record<string, number> };
  const reference = readFileSync(join(REPO, "docs", "reference.md"), "utf8");
  const table = new Map<string, number>();
  for (const match of reference.matchAll(/\| `([a-z_]+)`(?: \(fixed\))? \| ([\d,]+) /g)) {
    table.set(match[1]!, Number(match[2]!.replaceAll(",", "")));
  }
  assert.deepEqual(Object.fromEntries([...table].sort()), Object.fromEntries(Object.entries(MAXIMA).sort()));
});

for (const sample of SAMPLES) {
  test(`docs sample runs: ${label(sample)}`, async () => {
    const dir = mkdtempSync(join(tmpdir(), "bap-docs-run-"));
    try {
      const file = join(dir, "sample.mts");
      if (!usesSigner(sample)) {
        writeFileSync(file, rewrite(sample.code, "run"));
        await import(pathToFileURL(file).href);
        return;
      }
      assert.ok(existsSync(VERIFIER_BUILT), "dist/ is missing: run pnpm build first (pnpm test does)");
      writeFileSync(file, rewrite(sample.code, "built"));
      // The parent's conditions (bap-portable under test:portable), minus bap-source.
      const conditions = process.execArgv.filter((a) => a.startsWith("--conditions=") && a !== "--conditions=bap-source");
      const child = spawnSync(process.execPath, [...conditions, "--import", "tsx/esm", file], { cwd: REPO, encoding: "utf8" });
      assert.equal(child.status, 0, `${label(sample)} failed:\n${child.stderr}`);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
}

// Release step for the docs: replace every "2.0.0 (unreleased)" (the version being released) with
// the bare version. The `since=` fences stay; once that version is published they run here against it.
//
// The reader path: every sample that does not need an unreleased version runs exactly as a reader runs
// it, against the PUBLISHED package from npm, so the docs cannot claim published behavior that is not
// published. A sample that needs a newer release is fenced `ts since=<version>` and its prose says
// "new in <version> (unreleased)"; once that version is published, the same sample runs here against
// it. The consumer is a fresh directory with "type": "module", the published verifier and the signer
// version this repository tests with, installed by frozen pnpm; each sample runs with Node's own TypeScript
// type stripping, under the backend condition of this run (bap-portable under test:portable).
const PUBLISHED = execFileSync("npm", ["view", "@bounded-authority-protocol/verifier", "version"], { encoding: "utf8" }).trim();
const SIGNER_VERSION = (JSON.parse(readFileSync(join(SIGNER_ENTRY, "..", "..", "..", "package.json"), "utf8")) as { version: string }).version;
const READER = SAMPLES.filter((s) => s.since === undefined || semver.lte(s.since, PUBLISHED));
let consumer = "";

test("reader path: install the published package in a fresh consumer", () => {
  assert.ok(semver.valid(PUBLISHED), `npm reports a published version (${PUBLISHED})`);
  assert.ok(READER.some((s) => s.doc === "README.md"), "the README quickstart is on the reader path");
  consumer = mkdtempSync(join(tmpdir(), "bap-docs-reader-"));
  writeFileSync(join(consumer, "package.json"), JSON.stringify({
    name: "bap-docs-reader", private: true, type: "module",
    dependencies: { "@bounded-authority-protocol/verifier": PUBLISHED, "@bounded-authority-protocol/signer": SIGNER_VERSION },
  }));
  execFileSync("pnpm", ["install", "--frozen-lockfile", "--ignore-scripts"], { cwd: consumer, stdio: "ignore" });
});

for (const sample of READER) {
  test(`docs sample on the published package (reader path): ${label(sample)}`, () => {
    assert.ok(consumer !== "", "the consumer was installed");
    const file = join(consumer, `sample-${sample.doc.replace(/[^A-Za-z0-9]/g, "_")}-${sample.line}.mts`);
    writeFileSync(file, sample.code);
    const conditions = process.execArgv.filter((a) => a === "--conditions=bap-portable");
    const child = spawnSync(process.execPath, [...conditions, file], { cwd: consumer, encoding: "utf8" });
    assert.equal(child.status, 0, `${label(sample)} fails on the published ${PUBLISHED}:\n${child.stderr}`);
  });
}

test.after(() => { if (consumer !== "") rmSync(consumer, { recursive: true, force: true }); });
