#!/usr/bin/env node
// The browser-bundle guard (pnpm guard:browser, after pnpm build). Two layers over the PUBLISHED entry
// (dist/src/index.js), as a browser bundler sees it:
//   1. esbuild with platform "browser": an import of any Node built-in that is not resolvable for the
//      browser fails the build, and the metafile must not name src/crypto/node.js or node:crypto.
//   2. a scope-aware unresolved-globals scan of the bundled output: ESLint no-undef with the ES2022 and
//      browser globals only, so a free Buffer, process, require or __dirname reference anywhere in the
//      bundle (ours or a dependency's) is a finding; eval, implied eval and the Function constructor
//      are findings too (the strict CSP in the browser lane forbids them).
// test/guards.test.ts red-proofs both layers through the exported functions.
import { build } from "esbuild";
import { Linter } from "eslint";
import globals from "globals";
import { dirname, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const ROOT = dirname(dirname(fileURLToPath(import.meta.url)));

export async function bundleForBrowser({ entry, stdin, minify = false }) {
  try {
    const result = await build({
      ...(stdin === undefined
        ? { entryPoints: [entry ?? join(ROOT, "dist/src/index.js")] }
        : { stdin: { contents: stdin, resolveDir: ROOT, sourcefile: "guard-entry.js", loader: "js" } }),
      absWorkingDir: ROOT,
      bundle: true,
      write: false,
      format: "esm",
      platform: "browser",
      target: "es2022",
      minify,
      metafile: true,
      logLevel: "silent",
    });
    const code = result.outputFiles[0].text;
    return { ok: true, code, bytes: result.outputFiles[0].contents.length, metafile: result.metafile };
  } catch (e) {
    const errors = (e.errors ?? [{ text: String(e) }]).map((x) => `${x.text}${x.location ? ` (${x.location.file}:${x.location.line})` : ""}`);
    return { ok: false, errors };
  }
}

const SCAN_CONFIG = [
  {
    languageOptions: { ecmaVersion: 2022, sourceType: "module", globals: { ...globals.es2022, ...globals.browser } },
    rules: { "no-undef": "error", "no-eval": "error", "no-implied-eval": "error", "no-new-func": "error" },
  },
];

// Returns the free (unresolved) global names, and "rule: message" for dynamic-code findings.
export async function scanUnresolvedGlobals(code) {
  const messages = new Linter({ configType: "flat" }).verify(code, SCAN_CONFIG);
  const out = new Set();
  for (const m of messages) {
    if (m.fatal) out.add(`parse: ${m.message}`);
    else if (m.ruleId === "no-undef") out.add(/'([^']+)' is not defined/.exec(m.message)?.[1] ?? m.message);
    else out.add(`${m.ruleId}: ${m.message}`);
  }
  return [...out];
}

async function main() {
  const result = await bundleForBrowser({});
  if (!result.ok) {
    console.error("browser-guard: the browser build of dist/src/index.js failed:");
    for (const e of result.errors) console.error(`  ${e}`);
    process.exit(1);
  }
  const inputs = Object.keys(result.metafile.inputs);
  const nodeOnly = inputs.filter((p) => /src\/crypto\/node\.js$/.test(p) || /^node:|^(crypto|buffer)$/.test(p));
  if (nodeOnly.length > 0) {
    console.error(`browser-guard: the browser bundle reaches the node backend: ${nodeOnly.join(", ")}`);
    process.exit(1);
  }
  if (!inputs.some((p) => /src\/crypto\/portable\.js$/.test(p))) {
    console.error("browser-guard: the browser bundle does not contain the portable backend");
    process.exit(1);
  }
  const findings = await scanUnresolvedGlobals(result.code);
  if (findings.length > 0) {
    console.error(`browser-guard: ${findings.length} finding(s) in the browser bundle:`);
    for (const f of findings) console.error(`  ${f}`);
    process.exit(1);
  }
  console.log(`browser-guard: PASS (${inputs.length} modules, ${result.bytes} bytes unminified; portable backend only; no unresolved globals, eval or Function constructor)`);
}

if (process.argv[1] && pathToFileURL(process.argv[1]).href === import.meta.url) await main();
