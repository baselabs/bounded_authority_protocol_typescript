import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { cpSync, existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { test } from "node:test";

const root = fileURLToPath(new URL("..", import.meta.url));
const source = process.env.BAP_SITE_SOURCE ?? "release";
assert.ok(source === "release" || source === "commit", "source must be release or commit");

test("published API uses the release's own TypeDoc without checkout TypeDoc or development declarations", { skip: source !== "release" }, () => {
  const scratch = mkdtempSync(join(tmpdir(), "bap-release-api-test-"));
  try {
    mkdirSync(join(scratch, "tools"));
    for (const path of ["package.json", "typedoc.json", "tools/build-release-api.mjs", "tools/build-docs.mjs", "tools/docs-plugin.mjs", "docs", "README.md", "usage-rules.md", "CONTRIBUTING.md", "SECURITY.md", "CHANGELOG.md", "LICENSE", "NOTICE"]) cpSync(join(root, path), join(scratch, path), { recursive: true });
    mkdirSync(join(scratch, "node_modules"));
    symlinkSync(join(root, "node_modules/cross-spawn"), join(scratch, "node_modules/cross-spawn"), process.platform === "win32" ? "junction" : "dir");
    assert.equal(existsSync(join(scratch, "node_modules/typedoc")), false, "the checkout must not supply TypeDoc");
    mkdirSync(join(scratch, "src"));
    writeFileSync(join(scratch, "src/index.ts"), "/** Development only. */\nexport const unreleasedDocumentationProbe = 1;\n");
    const output = execFileSync(process.execPath, [join(scratch, "tools/build-release-api.mjs")], {
      cwd: scratch, encoding: "utf8", timeout: 120_000,
    });
    const api = join(scratch, "site-dist/api");
    const release = JSON.parse(readFileSync(join(api, "release.json"), "utf8")) as { version: string; source: string; tag: string; commit: string };
    assert.equal(release.source, "release");
    assert.equal(JSON.parse(readFileSync(join(api, "documentation.json"), "utf8")).version, release.version);
    assert.equal(release.tag, `v${release.version}`);
    assert.match(release.commit, /^[a-f0-9]{40}$/);
    assert.match(output, /Released API:/);
    const index = readFileSync(join(api, "index.html"), "utf8");
    assert.ok(index.includes(`released ${release.tag}`));
    assert.ok(index.includes(release.version));
    const html = readdirSync(api, { recursive: true }).filter((path) => typeof path === "string" && path.endsWith(".html"))
      .map((path) => readFileSync(join(api, path as string), "utf8")).join("\n");
    assert.ok(!html.includes("unreleasedDocumentationProbe"));
    assert.ok(html.includes(`/blob/${release.commit}/`), "source links must point to the release commit");
    console.log(output.trim());
  } finally {
    rmSync(scratch, { recursive: true, force: true });
  }
});

test("commit API uses committed files and its own TypeDoc without registry or tag access", { skip: source !== "commit" }, () => {
  const scratch = mkdtempSync(join(tmpdir(), "bap-commit-api-test-"));
  try {
    const checkout = join(scratch, "checkout");
    const head = execFileSync("git", ["rev-parse", "HEAD"], { cwd: root, encoding: "utf8" }).trim();
    const pkg = JSON.parse(execFileSync("git", ["show", `${head}:package.json`], { cwd: root, encoding: "utf8" })) as { name: string; version: string };
    execFileSync("git", ["clone", "--quiet", "--no-hardlinks", "--no-tags", "--no-checkout", root, checkout]);
    execFileSync("git", ["-c", "advice.detachedHead=false", "checkout", "--quiet", "--detach", head], { cwd: checkout });
    mkdirSync(join(checkout, "node_modules"));
    symlinkSync(join(root, "node_modules/cross-spawn"), join(checkout, "node_modules/cross-spawn"), process.platform === "win32" ? "junction" : "dir");
    assert.equal(existsSync(join(checkout, "node_modules/typedoc")), false, "the checkout must not supply TypeDoc");
    writeFileSync(join(checkout, "src/index.ts"), "/** Working tree only. */\nexport const uncommittedDocumentationProbe = 1;\n");
    writeFileSync(join(checkout, "src/untracked-probe.ts"), "/** Untracked only. */\nexport const untrackedDocumentationProbe = 1;\n");
    // The site's initial frozen install has populated the real pnpm store. A fresh, offline
    // npm cache refuses registry metadata; file-only Git refuses every remote tag lookup.
    const output = execFileSync(process.execPath, [join(checkout, "tools/build-release-api.mjs"), "--source=commit"], {
      cwd: checkout, encoding: "utf8", timeout: 180_000,
      env: { ...process.env, npm_config_offline: "true", npm_config_cache: join(scratch, "empty-npm-cache"), GIT_ALLOW_PROTOCOL: "file" },
    });
    const api = join(checkout, "site-dist/api");
    const release = JSON.parse(readFileSync(join(api, "release.json"), "utf8")) as Record<string, unknown>;
    assert.deepEqual(release, { package: pkg.name, version: pkg.version, source: "commit", commit: head });
    assert.equal(JSON.parse(readFileSync(join(api, "documentation.json"), "utf8")).version, pkg.version);
    assert.match(output, /Commit API:/);
    const index = readFileSync(join(api, "index.html"), "utf8");
    assert.ok(index.includes(`commit ${head}`));
    assert.ok(index.includes(pkg.version));
    const html = readdirSync(api, { recursive: true }).filter((path) => typeof path === "string" && path.endsWith(".html"))
      .map((path) => readFileSync(join(api, path as string), "utf8")).join("\n");
    assert.ok(!html.includes("uncommittedDocumentationProbe"));
    assert.ok(!html.includes("untrackedDocumentationProbe"));
    assert.ok(html.includes(`/blob/${head}/`), "source links must point to HEAD");
    assert.equal(existsSync(join(checkout, "node_modules/typedoc")), false, "TypeDoc must stay in the separate export");
    console.log(output.trim());
  } finally {
    rmSync(scratch, { recursive: true, force: true });
  }
});
