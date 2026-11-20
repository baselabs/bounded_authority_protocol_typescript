// Check every built HTML page, including API pages, metadata, badges, headers and footers.
// Standalone semantic versions are claims, except dependency source paths and SVG geometry.
// Four-part addresses are not versions.
// Claims must match the selected source: npm latest for Pages, HEAD package version for CI.
import assert from "node:assert/strict";
import spawn from "cross-spawn";
import { existsSync, readFileSync, readdirSync } from "node:fs";
import { join, relative } from "node:path";
import { parseArgs } from "node:util";

const { values, positionals } = parseArgs({
  options: { source: { type: "string", default: "release" } }, allowPositionals: true,
});
const source = values.source;
assert.ok(source === "release" || source === "commit", "source must be release or commit");
assert.ok(positionals.length <= 1, "expected at most one site root");
const root = positionals[0] ?? process.cwd();
const pkg = JSON.parse(readFileSync(join(root, "package.json"), "utf8"));
const run = (command, args) => {
  const result = spawn.sync(command, args, {
    cwd: root, encoding: "utf8", timeout: 90_000, stdio: ["ignore", "pipe", "pipe"],
  });
  if (result.error) throw result.error;
  assert.equal(result.status, 0, command === "npm"
    ? "could not read npm latest; site version checks fail closed" : `could not read committed package: ${result.stderr}`);
  return result.stdout.trim();
};
let expected, commit;
if (source === "commit") {
  commit = run("git", ["rev-parse", "HEAD"]);
  const committed = JSON.parse(run("git", ["show", `${commit}:package.json`]));
  assert.equal(committed.name, pkg.name);
  expected = committed.version;
} else {
  expected = run("npm", ["view", `${pkg.name}@latest`, "version", "--fetch-retries=1", "--fetch-timeout=20000"]);
  assert.match(expected, /^\d+\.\d+\.\d+$/, "npm latest must be a stable release");
}
const expectation = source === "release" ? `npm latest ${expected}` : `commit ${commit} version ${expected}`;
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
      let claims = text.replace(/(<(?:path|polygon|polyline)\b[^>]*?\b(?:d|points)\s*=\s*)(["'])([\s\S]*?)\2/gi,
        (_match, prefix, quote, coordinates) => prefix + quote + coordinates.replace(/[^\r\n]/g, " ") + quote)
        // TypeDoc includes inherited dependency declarations with pnpm versioned source paths.
        .replace(/node_modules\/\.pnpm\/([^/<>"'\s]+)\/node_modules\//g,
          (dependencyPath, coordinate) => coordinate.startsWith(packageCoordinate)
            ? dependencyPath : dependencyPath.replace(/[^\r\n]/g, " "));
      const metadataPath = join(root, "site-dist/api/documentation.json");
      if (existsSync(metadataPath)) {
        const metadata = JSON.parse(readFileSync(metadataPath, "utf8"));
        assert.equal(metadata.version, expected, "site documentation must target the selected source version");
        const allowed = new Set(metadata.historicalVersions);
        // Only text in an authored TypeDoc article can mention earlier releases or dependencies.
        // Site titles, metadata, footers and arbitrary HTML remain claims about the selected source version.
        // TypeDoc also repeats authored historical headings in its article outline.
        const scopes = []; const articles = []; let start;
        for (const token of claims.matchAll(/<!--[\s\S]*?-->|<(\/?)([a-z][\w:-]*)\b[^>]*>/gi)) {
          if (!token[2]) continue;
          const closing = token[1] === "/"; const tag = token[2].toLowerCase();
          if (closing) {
            const index = scopes.map((scope) => scope.tag).lastIndexOf(tag);
            if (index < 0) continue;
            const removed = scopes.splice(index);
            if (removed.some((scope) => scope.article) && !scopes.some((scope) => scope.article)) {
              articles.push([start, token.index]); start = undefined;
            }
          } else if (!/^(?:area|base|br|col|embed|hr|img|input|link|meta|param|source|track|wbr)$/.test(tag) && !token[0].endsWith("/>")) {
            const article = /\bclass=["'][^"']*\b(?:tsd-typography|tsd-page-navigation)\b/.test(token[0]);
            if (article && !scopes.some((scope) => scope.article)) start = token.index + token[0].length;
            scopes.push({ tag, article });
          }
        }
        claims = claims.replace(versions, (claim, version, offset) => allowed.has(version) &&
          articles.some(([from, to]) => offset >= from && offset < to) ? " ".repeat(claim.length) : claim);
      }
      for (const match of claims.matchAll(versions)) {
        if (match[1] !== expected) stale.push(`${relative(root, path)}:${text.slice(0, match.index).split("\n").length}: ${match[1]}`);
      }
    }
  }
}
const site = join(root, "site-dist");
check(site);
const releaseFile = join(site, "api/release.json");
if (existsSync(releaseFile)) {
  const release = JSON.parse(readFileSync(releaseFile, "utf8"));
  assert.equal(release.package, pkg.name);
  assert.equal(release.version, expected, "API version must match the selected source");
  assert.equal(release.source, source);
  if (source === "commit") {
    assert.equal(release.commit, commit);
    assert.equal(release.tag, undefined, "commit API must not claim a release tag");
  } else assert.equal(release.tag, `v${release.version}`);
}
const documentation = join(site, "api/documentation.json");
if (existsSync(documentation)) {
  assert.equal(JSON.parse(readFileSync(documentation, "utf8")).version, expected,
    "site documentation must target the selected source version");
}
assert.ok(pages > 0, "the built site must contain HTML");
assert.deepEqual(stale, [], `every site version claim must equal ${expectation}`);
console.log(`site badge: PASS (${pages} built pages, ${expectation})`);
