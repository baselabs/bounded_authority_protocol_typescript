// The no-Node-API guards and their red-proofs, each against the REAL configuration file: the browser
// typecheck (tsconfig.browser.json), the library lint (eslint.config.js), and the browser-bundle guard
// (tools/browser-guard.mjs: esbuild with platform "browser", then a scope-aware unresolved-globals scan
// of the bundle with ESLint no-undef). Every banned form has its own probe that must trip its rule, and
// the real src/ must be clean. The real-runtime lanes stay the behavioral backstop.
import { test } from "node:test";
import assert from "node:assert/strict";
import { existsSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { ESLint } from "eslint";
import ts from "typescript";

const REPO = fileURLToPath(new URL("..", import.meta.url));
const eslint = new ESLint({ cwd: REPO, overrideConfigFile: join(REPO, "eslint.config.js") });

async function lintRules(code: string, filePath: string): Promise<string[]> {
  const [result] = await eslint.lintText(code, { filePath: join(REPO, filePath) });
  return (result?.messages ?? []).map((m) => m.ruleId ?? `fatal: ${m.message}`);
}

// ---- lint: one probe per banned form, in a profile module ----

const LINT_PROBES: ReadonlyArray<readonly [string, string, string]> = [
  // Node builtins, prefixed and bare.
  ["import node:crypto", 'import { createHash } from "node:crypto";\nexport const p = createHash;', "no-restricted-imports"],
  ["import crypto", 'import { createHash } from "crypto";\nexport const p = createHash;', "no-restricted-imports"],
  ["import node:buffer", 'import { Buffer as B } from "node:buffer";\nexport const p = B;', "no-restricted-imports"],
  ["import node:module", 'import { createRequire } from "node:module";\nexport const p = createRequire;', "no-restricted-imports"],
  ["import node:util", 'import { inspect } from "node:util";\nexport const p = inspect;', "no-restricted-imports"],
  ["import node:fs", 'import { readFileSync } from "node:fs";\nexport const p = readFileSync;', "no-restricted-imports"],
  ["import path", 'import { join } from "path";\nexport const p = join;', "no-restricted-imports"],
  ["re-export node:crypto", 'export { createHash } from "node:crypto";', "no-restricted-imports"],
  // Node globals.
  ["Buffer", 'export const p = Buffer.from("x");', "no-restricted-globals"],
  ["process", "export const p = process.version;", "no-restricted-globals"],
  ["global", "export const p = global;", "no-restricted-globals"],
  ["require", 'export const p = require("x");', "no-restricted-globals"],
  ["__dirname", "export const p = __dirname;", "no-restricted-globals"],
  ["__filename", "export const p = __filename;", "no-restricted-globals"],
  ["globalThis.Buffer", "export const p = globalThis.Buffer;", "no-restricted-properties"],
  ["globalThis.process", "export const p = globalThis.process;", "no-restricted-properties"],
  ["globalThis.require", "export const p = globalThis.require;", "no-restricted-properties"],
  ["globalThis['Buffer']", 'export const p = globalThis["Buffer"];', "no-restricted-properties"],
  // Dynamic code and dynamic loading.
  ["dynamic import()", 'export const p = import("./v1.js");', "no-restricted-syntax"],
  ["eval", 'export const p = eval("1");', "no-eval"],
  ["new Function", 'export const p = new Function("return 1");', "no-new-func"],
  ["Function()", 'export const p = Function("return 1");', "no-new-func"],
  ["implied eval", 'globalThis.setTimeout("1", 0);', "no-implied-eval"],
  // @noble is reachable only from the portable backend.
  ["@noble outside the portable backend", 'import { sha256 } from "@noble/hashes/sha2.js";\nexport const p = sha256;', "no-restricted-imports"],
];

for (const [label, code, rule] of LINT_PROBES) {
  test(`lint probe trips ${rule}: ${label}`, async () => {
    assert.ok((await lintRules(code, "src/guard-probe.ts")).includes(rule), `${label} must trip ${rule}`);
  });
}

// ---- lint: the portable backend may import only noble's verification and hash entry points ----

const NOBLE_PROBES: ReadonlyArray<readonly [string, string, string]> = [
  ["import { sign } from @noble/ed25519", 'import { sign } from "@noble/ed25519";\nexport const p = sign;', "no-restricted-imports"],
  ["import { signAsync }", 'import { signAsync } from "@noble/ed25519";\nexport const p = signAsync;', "no-restricted-imports"],
  ["import { keygen }", 'import { keygen } from "@noble/ed25519";\nexport const p = keygen;', "no-restricted-imports"],
  ["import { keygenAsync }", 'import { keygenAsync } from "@noble/ed25519";\nexport const p = keygenAsync;', "no-restricted-imports"],
  ["import { getPublicKey }", 'import { getPublicKey } from "@noble/ed25519";\nexport const p = getPublicKey;', "no-restricted-imports"],
  ["import { getPublicKeyAsync }", 'import { getPublicKeyAsync } from "@noble/ed25519";\nexport const p = getPublicKeyAsync;', "no-restricted-imports"],
  ["import { utils }", 'import { utils } from "@noble/ed25519";\nexport const p = utils;', "no-restricted-imports"],
  ["import { hashes } (a mutable global registry)", 'import { hashes } from "@noble/ed25519";\nexport const p = hashes;', "no-restricted-imports"],
  ["import * from @noble/ed25519", 'import * as ed from "@noble/ed25519";\nexport const p = ed;', "no-restricted-imports"],
  ["a non-allowlisted noble path", 'import { ed25519 } from "@noble/curves/ed25519.js";\nexport const p = ed25519;', "no-restricted-imports"],
  ["noble utils path", 'import { randomBytes } from "@noble/hashes/utils.js";\nexport const p = randomBytes;', "no-restricted-imports"],
  [".sign", 'import { p256 } from "@noble/curves/nist.js";\nexport const p = p256.sign;', "no-restricted-properties"],
  [".keygen", 'import { p256 } from "@noble/curves/nist.js";\nexport const p = p256.keygen;', "no-restricted-properties"],
  [".getPublicKey", 'import { p256 } from "@noble/curves/nist.js";\nexport const p = p256.getPublicKey;', "no-restricted-properties"],
  [".getSharedSecret", 'import { p256 } from "@noble/curves/nist.js";\nexport const p = p256.getSharedSecret;', "no-restricted-properties"],
  [".randomSecretKey", 'import { p256 } from "@noble/curves/nist.js";\nexport const p = p256.utils.randomSecretKey;', "no-restricted-properties"],
  [".utils", 'import { p256 } from "@noble/curves/nist.js";\nexport const p = p256.utils;', "no-restricted-properties"],
];

for (const [label, code, rule] of NOBLE_PROBES) {
  test(`noble verify-only probe trips ${rule} in src/crypto/portable.ts: ${label}`, async () => {
    assert.ok((await lintRules(code, "src/crypto/portable.ts")).includes(rule), `${label} must trip ${rule}`);
  });
}

test("the portable backend's own noble imports are allowed", async () => {
  const code = [
    'import { Point } from "@noble/ed25519";',
    'import { p256 } from "@noble/curves/nist.js";',
    'import { sha256, sha512 } from "@noble/hashes/sha2.js";',
    "export const p = [Point, p256.verify, p256.Point, sha256, sha512];",
  ].join("\n");
  assert.deepEqual(await lintRules(code, "src/crypto/portable.ts"), []);
});

test("the node backend alone may import node:crypto and use Buffer, and nothing else from Node", async () => {
  assert.deepEqual(await lintRules('import { createHash } from "node:crypto";\nexport const p = [createHash, Buffer.from("x")];', "src/crypto/node.ts"), []);
  assert.ok((await lintRules('import { readFileSync } from "node:fs";\nexport const p = readFileSync;', "src/crypto/node.ts")).includes("no-restricted-imports"));
  assert.ok((await lintRules("export const p = process.version;", "src/crypto/node.ts")).includes("no-restricted-globals"));
  assert.ok((await lintRules('import { sign } from "@noble/ed25519";\nexport const p = sign;', "src/crypto/node.ts")).includes("no-restricted-imports"));
});

test("the real src/ is lint-clean under these rules", async () => {
  const results = await eslint.lintFiles(["src/**/*.ts"]);
  assert.ok(results.length >= 25, `linted ${results.length} files`);
  const problems = results.flatMap((r) => r.messages.map((m) => `${r.filePath}:${m.line} ${m.ruleId} ${m.message}`));
  assert.deepEqual(problems, []);
});

// ---- browser typecheck: the real tsconfig.browser.json, extended by one fixture at a time ----

function browserDiagnostics(extraFile: string | null): string[] {
  const base = join(REPO, "tsconfig.browser.json");
  assert.ok(existsSync(base), "tsconfig.browser.json exists");
  // The probe config lives inside the package directory (under the ignored node_modules/.cache):
  // TypeScript maps the "#crypto" types target in dist/ back to its src/ input only for a config file
  // inside the package, exactly as for the real tsconfig.browser.json.
  mkdirSync(join(REPO, "node_modules/.cache"), { recursive: true });
  const dir = mkdtempSync(join(REPO, "node_modules/.cache/bap-guard-"));
  const config = join(dir, "tsconfig.json");
  try {
    writeFileSync(config, JSON.stringify({ extends: base, files: extraFile === null ? [] : [join(REPO, extraFile)] }));
    const parsed = ts.getParsedCommandLineOfConfigFile(config, {}, { ...ts.sys, onUnRecoverableConfigFileDiagnostic: () => {} });
    assert.ok(parsed, "the config parses");
    const program = ts.createProgram({ rootNames: parsed.fileNames, options: parsed.options });
    return ts.getPreEmitDiagnostics(program).map((d) => {
      const where = d.file ? d.file.fileName.replace(REPO, "") : "";
      return `${where} TS${d.code}: ${ts.flattenDiagnosticMessageText(d.messageText, " ")}`;
    });
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

test("browser typecheck: the real src/ (minus the node backend) is clean under DOM + ES2022 with no types", () => {
  assert.deepEqual(browserDiagnostics(null), []);
});

for (const [fixture, needle] of [
  ["test/fixtures/guard/buffer-global.ts", "Cannot find name 'Buffer'"],
  ["test/fixtures/guard/process-global.ts", "Cannot find name 'process'"],
  ["test/fixtures/guard/node-crypto-import.ts", "'node:crypto'"],
] as const) {
  test(`browser typecheck red-proof: ${fixture} is refused`, () => {
    const diagnostics = browserDiagnostics(fixture);
    const name = fixture.slice(fixture.lastIndexOf("/") + 1);
    assert.ok(diagnostics.some((d) => d.includes(name) && d.includes(needle)), diagnostics.join("\n"));
    assert.ok(diagnostics.every((d) => d.includes(name)), `only the fixture is diagnosed:\n${diagnostics.join("\n")}`);
  });
}

// ---- bundle guard: esbuild for the browser, then the unresolved-globals scan ----

interface Guard {
  bundleForBrowser(options: { entry?: string; stdin?: string }): Promise<{ ok: true; code: string; bytes: number } | { ok: false; errors: string[] }>;
  scanUnresolvedGlobals(code: string): Promise<string[]>;
}
const guard = async (): Promise<Guard> => (await import(pathToFileURL(join(REPO, "tools/browser-guard.mjs")).href)) as Guard;

test("bundle guard red-proof: an entry that imports node:crypto fails the browser build", async () => {
  const result = await (await guard()).bundleForBrowser({ stdin: 'export { createHash } from "node:crypto";' });
  assert.equal(result.ok, false);
  if (!result.ok) assert.ok(result.errors.some((e) => e.includes("node:crypto")), result.errors.join("\n"));
});

test("bundle guard red-proof: a bundle with a free Buffer (and a free process) reference is caught by no-undef", async () => {
  const found = await (await guard()).scanUnresolvedGlobals('var a = Buffer.from("x"); var b = process.env; var ok = new TextEncoder();');
  assert.deepEqual(found.sort(), ["Buffer", "process"]);
});

test("bundle guard red-proof: eval and new Function in a bundle are caught", async () => {
  const found = await (await guard()).scanUnresolvedGlobals('var a = eval("1"); var f = new Function("return 1");');
  assert.ok(found.some((f) => f.includes("eval")) && found.some((f) => f.includes("Function")), found.join("\n"));
});
