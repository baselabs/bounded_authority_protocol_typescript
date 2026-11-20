// CommonMark docs, complete recipe sources and public TSDoc examples are checked against both
// source, then executed with real keys, requests and stores. Installed artifacts use test/reader.ts.
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync, readdirSync, realpathSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, relative } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import ts from "typescript";
import { commentProse } from "./comments.js";
import { authoredSamples, docFiles as discoverDocs, type Sample } from "./support/documents.js";

const REPO = fileURLToPath(new URL("..", import.meta.url));
const VERIFIER_SOURCE = join(REPO, "src", "index.ts");
const VERIFIER_BUILT = join(REPO, "dist", "src", "index.js");
const SIGNER_ENTRY = realpathSync(fileURLToPath(import.meta.resolve("@bounded-authority-protocol/signer")));
const SIGNER_TYPES = SIGNER_ENTRY.replace(/\.js$/, ".d.ts");
const SPECIFIERS: Record<string, { run: string; types: string }> = {
  "@bounded-authority-protocol/verifier": { run: pathToFileURL(VERIFIER_SOURCE).href, types: VERIFIER_SOURCE },
  "@bounded-authority-protocol/signer": { run: pathToFileURL(SIGNER_ENTRY).href, types: SIGNER_TYPES },
};

const docFiles = (): string[] => discoverDocs(REPO);
const SAMPLES = authoredSamples(REPO);
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
  assert.ok(SAMPLES.length >= 37, `only ${SAMPLES.length} samples found`);
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

// The private-record and spaced-hyphen gates examine source comment trivia at its original
// offsets rather than operators or literals. The private-record gate reads full Markdown,
// including fences; the spaced-hyphen check omits fenced code. The em-dash gate reads raw text.
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
const emDash = new RegExp(String.fromCodePoint(0x2014) + "|\\\\u" + "2014", "i");
const proseDash = /[a-z][.,;:!?]?[ \t]+-[ \t]+(?=[a-z])/i;

test("prose hygiene distinguishes sentence dashes from code and subtraction", () => {
  assert.ok(emDash.test("Request bytes " + String.fromCodePoint(0x2014) + " signed exactly."));
  assert.ok(emDash.test("Request bytes " + "\\u" + "2014 signed exactly."));
  assert.ok(proseDash.test("Request bytes - signed exactly."));
  assert.equal(proseDash.test("2^53 - 1; rowCount - 1; - a list item"), false);
});

test("tracked public text contains no em dashes", () => {
  const tracked = spawnSync("git", ["ls-files", "-z"], { cwd: REPO, encoding: "utf8" });
  assert.equal(tracked.status, 0, tracked.stderr);
  // conformance/priv/conformance/ is the immutable corpus/vector/schema snapshot pinned by
  // conformance/SOURCE. Binary files are not text. No source or placeholder file is exempt.
  const files = tracked.stdout.split("\0").filter((file) => file !== "" && !file.startsWith("conformance/priv/conformance/"));
  assert.ok(files.includes("test/docs-samples.test.ts"), "the tracked-text scan must include itself");
  const hits = files.flatMap((file) => {
    const source = readFileSync(join(REPO, file));
    if (source.includes(0)) return [];
    return source.toString("utf8").split("\n").flatMap((line, i) =>
      emDash.test(line) ? [`${file}:${i + 1}: ${line.trim()}`] : []);
  });
  assert.deepEqual(hits, []);
});

test("public prose uses sentences without spaced hyphen dashes", () => {
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
      if (!usesSigner(sample) && !sample.doc.endsWith(".ts")) {
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
