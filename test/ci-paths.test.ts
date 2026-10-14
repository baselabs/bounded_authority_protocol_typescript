// CI skips pushes that change only paths in a trigger's paths-ignore list (a CI-minutes decision). A
// skip is safe only for a path no check reads, so this guard reads every paths-ignore list of every
// trigger in ci.yml with a YAML parser (any quoting, any indent) and fails when a glob matches any
// tracked file outside UNREAD. Every tracked file is taken to be read by some check (source, tests,
// corpora, tools, configuration, the docs Markdown whose samples run, and the files packed into the
// tarball the package job installs) unless it is listed here with the reason no check reads it.
// GitHub filter globs: `*` stays within one path segment, `**` crosses segments, `**/` also matches none.
import { test } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { parse } from "yaml";

const REPO = fileURLToPath(new URL("..", import.meta.url));
const UNREAD: Record<string, string> = {
  "CHANGELOG.md": "release notes: no check, test, build or pack step reads them",
};

export function ignoredGlobs(workflow: string): string[] {
  const doc = parse(workflow) as { on?: unknown };
  const on = doc.on;
  assert.ok(on !== null && typeof on === "object", "the workflow has an `on` mapping");
  const globs: string[] = [];
  for (const trigger of Object.values(on as Record<string, unknown>)) {
    if (trigger === null || typeof trigger !== "object") continue;
    const list = (trigger as Record<string, unknown>)["paths-ignore"];
    if (list === undefined) continue;
    assert.ok(Array.isArray(list) && list.every((g) => typeof g === "string"), "paths-ignore is a list of strings");
    globs.push(...(list as string[]));
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

export function violations(globs: string[], tracked: string[]): string[] {
  return globs.flatMap((glob) => tracked.filter((f) => globToRegExp(glob).test(f) && !(f in UNREAD)).map((f) => `${glob} skips ${f}`));
}

const TRACKED = execFileSync("git", ["ls-files"], { cwd: REPO, encoding: "utf8" }).split("\n").filter(Boolean);

test("every paths-ignore glob in ci.yml matches only tracked files no check reads", () => {
  for (const known of ["README.md", "docs/reference.md", "src/index.ts", "LICENSE", "CHANGELOG.md"]) {
    assert.ok(TRACKED.includes(known), `the tracked-file walk must see ${known}`);
  }
  const globs = ignoredGlobs(readFileSync(join(REPO, ".github/workflows/ci.yml"), "utf8"));
  assert.ok(globs.length > 0, "ci.yml declares no paths-ignore: the parser found nothing");
  assert.ok(globs.some((g) => globToRegExp(g).test("CHANGELOG.md")), "known positive: CHANGELOG.md is skipped");
  assert.deepEqual(violations(globs, TRACKED), []);
});

test("the glob reading follows GitHub filter rules", () => {
  assert.equal(globToRegExp("docs/**").test("docs/guides/a.md"), true);
  assert.equal(globToRegExp("**/*.md").test("README.md"), true); // `**/` also matches the root
  assert.equal(globToRegExp("**/*.md").test("docs/guides/a.md"), true);
  assert.equal(globToRegExp("**.md").test("README.md"), true);
  assert.equal(globToRegExp("*.md").test("docs/a.md"), false);
  assert.equal(globToRegExp("LICENSE*").test("LICENSE"), true);
});

// Planted forms a line-based reading missed: unquoted and single-quoted globs at another indent, on
// two triggers.
const PLANTED = `name: CI
on:
    push:
        branches: [main]
        paths-ignore:
            - docs/**
            - 'README.md'
    pull_request:
      paths-ignore: ["LICENSE*"]
`;
test("planted paths-ignore forms (unquoted, single-quoted, flow list, any indent) are read and caught", () => {
  const globs = ignoredGlobs(PLANTED);
  assert.deepEqual([...globs].sort(), ["LICENSE*", "README.md", "docs/**"]);
  const found = violations(globs, TRACKED);
  for (const f of ["README.md", "LICENSE", "docs/reference.md"]) assert.ok(found.some((v) => v.endsWith(` skips ${f}`)), f);
});
