import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { test } from "node:test";

const root = fileURLToPath(new URL("..", import.meta.url));
const pkg = JSON.parse(readFileSync(join(root, "package.json"), "utf8")) as { name: string };

test("commit site claims use HEAD's package version without registry or tag access", () => {
  const scratch = mkdtempSync(join(tmpdir(), "bap-commit-site-badge-"));
  try {
    const packageFile = join(scratch, "package.json");
    writeFileSync(packageFile, JSON.stringify({ name: pkg.name, version: "99.0.0" }));
    execFileSync("git", ["init", "-q", scratch]);
    execFileSync("git", ["add", "package.json"], { cwd: scratch });
    execFileSync("git", ["-c", "user.name=badge-test", "-c", "user.email=badge-test@example.invalid", "-c", "commit.gpgsign=false", "commit", "-qm", "fixture"], { cwd: scratch });
    const head = execFileSync("git", ["rev-parse", "HEAD"], { cwd: scratch, encoding: "utf8" }).trim();
    writeFileSync(packageFile, JSON.stringify({ name: pkg.name, version: "100.0.0" }));
    const api = join(scratch, "site-dist/api");
    mkdirSync(api, { recursive: true });
    const html = join(api, "index.html");
    const releaseFile = join(api, "release.json");
    const metadata = join(api, "documentation.json");
    const release = { package: pkg.name, version: "99.0.0", source: "commit", commit: head };
    writeFileSync(html, `<header>${pkg.name}@99.0.0</header>`);
    writeFileSync(releaseFile, JSON.stringify(release));
    writeFileSync(metadata, JSON.stringify({ version: "99.0.0", historicalVersions: [] }));
    const run = () => {
      const result = spawnSync(process.execPath, [join(root, "tools/check-site-badge.mjs"), scratch, "--source=commit"], {
        cwd: root, encoding: "utf8", timeout: 30_000,
        env: { ...process.env, npm_config_offline: "true", npm_config_cache: join(scratch, "empty-npm-cache"), GIT_ALLOW_PROTOCOL: "file" },
      });
      assert.ifError(result.error);
      return { status: result.status, output: result.stdout + result.stderr };
    };
    let result = run();
    assert.equal(result.status, 0, result.output);
    assert.ok(result.output.includes(`commit ${head} version 99.0.0`));
    writeFileSync(html, `<footer>${pkg.name}@100.0.0</footer>`);
    result = run();
    assert.equal(result.status, 1, result.output);
    assert.match(result.output, /100\.0\.0/);
    writeFileSync(html, `<header>${pkg.name}@99.0.0</header>`);
    writeFileSync(metadata, JSON.stringify({ version: "100.0.0", historicalVersions: [] }));
    result = run();
    assert.equal(result.status, 1, result.output);
    assert.match(result.output, /site documentation must target the selected source version/);
    writeFileSync(metadata, JSON.stringify({ version: "99.0.0", historicalVersions: [] }));
    for (const patch of [{ source: "release" }, { commit: "0".repeat(40) }, { tag: "v99.0.0" }, { version: "100.0.0" }]) {
      writeFileSync(releaseFile, JSON.stringify({ ...release, ...patch }));
      result = run();
      assert.equal(result.status, 1, result.output);
    }
  } finally {
    rmSync(scratch, { recursive: true, force: true });
  }
});
