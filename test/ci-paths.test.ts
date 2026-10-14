// CI skips pushes that change only paths in ci.yml's push.paths-ignore (a CI-minutes decision). A skip
// is safe only for a path no check reads, so this guard fails when an ignored glob matches any tracked
// file a check reads:
//   - every Markdown file the docs-sample test executes (README.md, docs/**/*.md);
//   - every file of the packed package (npm pack --dry-run, scripts ignored), which the tarball check
//     installs and runs;
//   - every tracked file under the source, test, conformance, tool, browser and site directories, and the
//     root configuration the checks load.
// GitHub filter globs: `*` stays within one path segment, `**` crosses segments, `**/` also matches none.
import { test } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

const REPO = fileURLToPath(new URL("..", import.meta.url));
const CHECKED_DIRS = ["src/", "test/", "conformance/", "tools/", "browser/", "web/", "docs/", ".github/workflows/"];
const CHECKED_ROOT_FILES = [
  "README.md", "package.json", "pnpm-lock.yaml", "tsconfig.json", "tsconfig.build.json", "tsconfig.browser.json",
  "tsconfig.web.json", "eslint.config.js", ".tool-versions",
];

export function pushPathsIgnore(workflow: string): string[] {
  const lines = workflow.split("\n");
  const push = lines.findIndex((l) => /^ {2}push:\s*$/.test(l));
  assert.ok(push >= 0, "ci.yml has no push trigger");
  const globs: string[] = [];
  let inList = false;
  for (const line of lines.slice(push + 1)) {
    if (/^ {2}\S/.test(line) || /^\S/.test(line)) break; // the next trigger or top-level key
    if (/^ {4}paths-ignore:\s*$/.test(line)) { inList = true; continue; }
    if (!inList) continue;
    const item = /^ {6}- "([^"]+)"\s*$/.exec(line);
    if (item !== null) { globs.push(item[1]!); continue; }
    if (/^\s*#/.test(line)) continue;
    if (/^ {4}\S/.test(line)) break;
  }
  return globs;
}

export function globToRegExp(glob: string): RegExp {
  let out = "";
  for (let i = 0; i < glob.length; i++) {
    const c = glob[i]!;
    if (c === "*" && glob[i + 1] === "*" && glob[i + 2] === "/") { out += "(?:.*/)?"; i += 2; } // zero or more directories
    else if (c === "*" && glob[i + 1] === "*") { out += ".*"; i++; }
    else if (c === "*") out += "[^/]*";
    else if (c === "?") out += "[^/]";
    else out += c.replace(/[.+^${}()|[\]\\]/g, "\\$&");
  }
  return new RegExp(`^${out}$`);
}

function readByChecks(): Set<string> {
  const tracked = execFileSync("git", ["ls-files"], { cwd: REPO, encoding: "utf8" }).split("\n").filter(Boolean);
  const read = new Set<string>();
  for (const file of tracked) {
    if (CHECKED_ROOT_FILES.includes(file) || CHECKED_DIRS.some((d) => file.startsWith(d))) read.add(file);
  }
  const [packed] = JSON.parse(execFileSync("npm", ["pack", "--dry-run", "--json", "--ignore-scripts"], { cwd: REPO, encoding: "utf8" })) as Array<{ files: Array<{ path: string }> }>;
  for (const { path } of packed!.files) read.add(path);
  return read;
}

test("no push.paths-ignore glob in ci.yml matches a file a check reads", () => {
  const read = readByChecks();
  for (const known of ["README.md", "docs/reference.md", "src/index.ts", "LICENSE", "NOTICE", "package.json"]) {
    assert.ok(read.has(known), `the read set must see ${known}`);
  }
  const globs = pushPathsIgnore(readFileSync(join(REPO, ".github/workflows/ci.yml"), "utf8"));
  assert.ok(globs.length > 0, "ci.yml declares no push.paths-ignore: the parser found nothing");
  const violations = globs.flatMap((glob) => [...read].filter((f) => globToRegExp(glob).test(f)).map((f) => `${glob} skips ${f}`));
  assert.deepEqual(violations, []);
});

test("the glob reading follows GitHub filter rules", () => {
  assert.equal(globToRegExp("docs/**").test("docs/guides/a.md"), true);
  assert.equal(globToRegExp("**/*.md").test("README.md"), true); // `**/` also matches the root
  assert.equal(globToRegExp("**/*.md").test("docs/guides/a.md"), true);
  assert.equal(globToRegExp("**.md").test("README.md"), true);
  assert.equal(globToRegExp("*.md").test("docs/a.md"), false);
  assert.equal(globToRegExp("LICENSE*").test("LICENSE"), true);
});
