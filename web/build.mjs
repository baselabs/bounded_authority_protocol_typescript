// Copies the static site pieces next to esbuild's bundle (managed-language,
// cross-platform — no shell in the build path).
import { cpSync, mkdirSync, rmSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const web = dirname(fileURLToPath(import.meta.url));
const out = join(web, "..", "site-dist");
rmSync(out, { recursive: true, force: true });
mkdirSync(out, { recursive: true });
for (const f of ["index.html", "styles.css"]) cpSync(join(web, f), join(out, f));
console.log(`site: static assets staged in ${out}`);
