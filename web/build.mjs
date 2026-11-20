// Builds the bench (pnpm build:site): bundles web/main.ts with esbuild and copies the static site
// pieces next to it. The cross-platform build uses no shell and cache-busts
// the asset URLs: every deploy gets styles.css/app.js suffixed with the commit SHA, so returning
// visitors can never be served a stale stylesheet from an unchanged URL.
//
// The bundle runs one verifier: this repository's source, on the portable backend. The published
// signer (demo issuance only) imports the package by name, and its lock entry links that name to
// this checkout (see "the companion signer resolves only this checkout's verifier" in
// test/engines.test.ts). Package resolution would send it to dist/, which Pages never builds, and
// would bundle a second verifier beside src/. So the build resolves the package name to
// src/index.ts and "#crypto" to src/crypto/portable.ts for importers inside src/, and refuses a
// bundle that reads anything from dist/ or from a registry copy of the verifier.
import { cpSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { execFileSync } from "node:child_process";
import { dirname, join, sep } from "node:path";
import { fileURLToPath } from "node:url";
import { build } from "esbuild";

const web = dirname(fileURLToPath(import.meta.url));
const out = join(web, "..", "site-dist");
rmSync(out, { recursive: true, force: true });
mkdirSync(out, { recursive: true });

let version = "dev";
try {
  version = execFileSync("git", ["rev-parse", "--short", "HEAD"], { cwd: join(web, "..") }).toString().trim();
} catch {
  // An exported tree may lack Git; use a development asset tag in that case.
}

let html = readFileSync(join(web, "index.html"), "utf8");
html = html.replace(/\.\/styles\.css"/g, `./styles.css?v=${version}"`).replace(/\.\/app\.js"/g, `./app.js?v=${version}"`);
writeFileSync(join(out, "index.html"), html);
cpSync(join(web, "styles.css"), join(out, "styles.css"));
console.log(`site: static assets staged in ${out} (asset version ?v=${version})`);

const repo = join(web, "..");
const sourceDir = join(repo, "src") + sep;
const candidateVerifier = {
  name: "bench-candidate-verifier",
  setup(b) {
    b.onResolve({ filter: /^@bounded-authority-protocol\/verifier$/ }, () => ({ path: join(repo, "src", "index.ts") }));
    b.onResolve({ filter: /^#crypto$/ }, (args) =>
      args.importer.startsWith(sourceDir) ? { path: join(repo, "src", "crypto", "portable.ts") } : undefined);
  },
};
const result = await build({
  entryPoints: [join(web, "main.ts")], absWorkingDir: repo, bundle: true, minify: true, format: "iife",
  target: "es2022", platform: "browser", conditions: ["bap-portable"], outfile: join(out, "app.js"),
  plugins: [candidateVerifier], metafile: true, logLevel: "info",
});
const foreign = Object.keys(result.metafile.inputs)
  .filter((input) => input.startsWith("dist/") || input.includes("node_modules/@bounded-authority-protocol/verifier/"));
if (foreign.length > 0) {
  throw new Error(`site: the bench must bundle only this repository's verifier source; it read ${foreign.join(", ")}`);
}
