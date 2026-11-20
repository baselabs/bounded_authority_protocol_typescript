import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { cpSync, existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { test } from "node:test";

const root = fileURLToPath(new URL("..", import.meta.url));

test("published API uses the release's own TypeDoc without checkout TypeDoc or development declarations", () => {
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
    const release = JSON.parse(readFileSync(join(api, "release.json"), "utf8")) as { version: string; tag: string; commit: string };
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
