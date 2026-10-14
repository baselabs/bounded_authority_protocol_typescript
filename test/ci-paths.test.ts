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

// GitHub filter semantics per trigger. Patterns apply in order and a `!pattern` reverses an earlier
// match, so a file's state is set by the last pattern that matches it. With `paths`, a file runs CI
// only if that last match is positive (every other file is skipped); with `paths-ignore`, a file is
// skipped if that last match is positive. Returns "<trigger>: <file>" for every skipped tracked file
// that some check reads.
function lastMatch(patterns: string[], file: string): boolean {
  let matched = false;
  for (const p of patterns) {
    const negated = p.startsWith("!");
    if (globToRegExp(negated ? p.slice(1) : p).test(file)) matched = !negated;
  }
  return matched;
}

export function skippedReadFiles(workflow: string, tracked: string[]): string[] {
  const doc = parse(workflow) as { on?: unknown };
  assert.ok(doc.on !== null && typeof doc.on === "object", "the workflow has an `on` mapping");
  const out: string[] = [];
  for (const [name, trigger] of Object.entries(doc.on as Record<string, unknown>)) {
    if (trigger === null || typeof trigger !== "object") continue;
    const lists: Record<string, string[] | undefined> = {};
    for (const key of ["paths", "paths-ignore"]) {
      const list: unknown = (trigger as Record<string, unknown>)[key];
      assert.ok(list === undefined || (Array.isArray(list) && list.every((g) => typeof g === "string")), `${name}.${key} is a list of strings`);
      lists[key] = list as string[] | undefined;
    }
    for (const f of tracked) {
      if (f in UNREAD) continue;
      const skipped = (lists["paths"] !== undefined && !lastMatch(lists["paths"], f))
        || (lists["paths-ignore"] !== undefined && lastMatch(lists["paths-ignore"], f));
      if (skipped) out.push(`${name}: ${f}`);
    }
  }
  return out;
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
  assert.deepEqual(skippedReadFiles(readFileSync(join(REPO, ".github/workflows/ci.yml"), "utf8"), TRACKED), []);
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

// `paths` filters and `!` negations: a `paths` list runs CI only for matching files (so it skips the
// rest), and a later `!pattern` reverses an earlier match, in either list.
const FILTERED = `on:
  push:
    paths:
      - "src/**"
      - "!src/crypto/**"
  pull_request:
    paths-ignore:
      - "**.md"
      - "!README.md"
`;
test("paths filters and ! negations: the skipped files are computed as GitHub does", () => {
  const found = skippedReadFiles(FILTERED, TRACKED);
  assert.ok(found.includes("push: src/crypto/node.ts"), "a negated path inside paths is skipped");
  assert.ok(found.includes("push: README.md"), "a path outside paths is skipped");
  assert.ok(!found.some((v) => v === "push: src/index.ts"), "a path inside paths runs CI");
  assert.ok(found.includes("pull_request: docs/reference.md"), "an ignored path is skipped");
  assert.ok(!found.includes("pull_request: README.md"), "a negated ignore is not skipped");
});
