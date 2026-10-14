// Builds the bench (pnpm build:site): bundles web/main.ts with esbuild and copies the static site
// pieces next to it (managed-language, cross-platform — no shell in the build path), cache-busting
// the asset URLs: every deploy gets styles.css/app.js suffixed with the commit SHA, so returning
// visitors can never be served a stale stylesheet from an unchanged URL.
//
// The bundle runs this repository's verifier source on the portable backend, and the published
// signer (demo issuance only) on its own published verifier dependency. The bap-source condition
// cannot be set globally for that: it would also send the published verifier's "#crypto" to
// src/crypto/, which a published package does not ship. So the build sets only bap-portable and
// resolves "#crypto" to src/crypto/portable.ts for importers inside this repository's src/.
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
  // no git (e.g., an exported tree) — fall back to a content-free tag
}

let html = readFileSync(join(web, "index.html"), "utf8");
html = html.replace(/\.\/styles\.css"/g, `./styles.css?v=${version}"`).replace(/\.\/app\.js"/g, `./app.js?v=${version}"`);
writeFileSync(join(out, "index.html"), html);
cpSync(join(web, "styles.css"), join(out, "styles.css"));
console.log(`site: static assets staged in ${out} (asset version ?v=${version})`);

const repo = join(web, "..");
const sourceDir = join(repo, "src") + sep;
const sourceCrypto = {
  name: "bench-source-crypto",
  setup(b) {
    b.onResolve({ filter: /^#crypto$/ }, (args) =>
      args.importer.startsWith(sourceDir) ? { path: join(repo, "src", "crypto", "portable.ts") } : undefined);
  },
};
await build({
  entryPoints: [join(web, "main.ts")], absWorkingDir: repo, bundle: true, minify: true, format: "iife",
  target: "es2022", platform: "browser", conditions: ["bap-portable"], outfile: join(out, "app.js"),
  plugins: [sourceCrypto], logLevel: "info",
});
