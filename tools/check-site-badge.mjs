// Check every built HTML page, including API pages, metadata, badges, headers and footers.
// Standalone semantic versions are claims, except dependency source paths and SVG geometry.
// Four-part addresses are not versions.
// Development-source labels and local release tags never exempt a claim from npm latest.
import assert from "node:assert/strict";
import spawn from "cross-spawn";
import { readFileSync, readdirSync } from "node:fs";
import { join, relative } from "node:path";

const root = process.argv[2] ?? process.cwd();
const pkg = JSON.parse(readFileSync(join(root, "package.json"), "utf8"));
const result = spawn.sync("npm", ["view", `${pkg.name}@latest`, "version", "--fetch-retries=1", "--fetch-timeout=20000"], {
  cwd: root, encoding: "utf8", timeout: 90_000, stdio: ["ignore", "pipe", "pipe"],
});
if (result.error) throw result.error;
assert.equal(result.status, 0, "could not read npm latest; site version checks fail closed");
const latest = result.stdout.trim();
assert.match(latest, /^\d+\.\d+\.\d+$/, "npm latest must be a stable release");
const packageCoordinate = pkg.name.replace("/", "+") + "@";
const versions = /(?<![\w.])v?(\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?)(?!\w|\.\d|-[0-9A-Za-z])/g;
let pages = 0;
const stale = [];
function check(dir) {
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const path = join(dir, entry.name);
    if (entry.isDirectory()) check(path);
    else if (entry.name.endsWith(".html")) {
      pages++;
      const text = readFileSync(path, "utf8");
      // SVG drawing coordinates can look like versions, but carry no package claim. Retain offsets.
      const claims = text.replace(/(<(?:path|polygon|polyline)\b[^>]*?\b(?:d|points)\s*=\s*)(["'])([\s\S]*?)\2/gi,
        (_match, prefix, quote, coordinates) => prefix + quote + coordinates.replace(/[^\r\n]/g, " ") + quote)
        // TypeDoc includes inherited dependency declarations with pnpm versioned source paths.
        .replace(/node_modules\/\.pnpm\/([^/<>"'\s]+)\/node_modules\//g,
          (dependencyPath, coordinate) => coordinate.startsWith(packageCoordinate)
            ? dependencyPath : dependencyPath.replace(/[^\r\n]/g, " "));
      for (const match of claims.matchAll(versions)) {
        if (match[1] !== latest) stale.push(`${relative(root, path)}:${text.slice(0, match.index).split("\n").length}: ${match[1]}`);
      }
    }
  }
}
check(join(root, "site-dist"));
assert.ok(pages > 0, "the built site must contain HTML");
assert.deepEqual(stale, [], `every site version claim must equal npm latest ${latest}`);
console.log(`site badge: PASS (${pages} built pages, npm latest ${latest})`);
