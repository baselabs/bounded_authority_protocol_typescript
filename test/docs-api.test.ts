import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { cpSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

const REPO = fileURLToPath(new URL("..", import.meta.url));

test("TypeDoc discovers exports, rejects undocumented API and stamps the package version", () => {
  const scratch = mkdtempSync(join(tmpdir(), "bap-api-docs-"));
  try {
    for (const name of ["src", "package.json", "typedoc.json", "tsconfig.json", "tsconfig.build.json"]) {
      cpSync(join(REPO, name), join(scratch, name), { recursive: true });
    }
    symlinkSync(join(REPO, "node_modules"), join(scratch, "node_modules"), process.platform === "win32" ? "junction" : "dir");
    const manifest = JSON.parse(readFileSync(join(scratch, "package.json"), "utf8")) as {
      version: string; exports: Record<string, unknown>;
    };
    // Add a genuine package subpath to prove entry-point discovery follows the exports map.
    manifest.exports["./documentation-probe"] = {
      types: "./dist/src/documentation-probe.d.ts", default: "./dist/src/documentation-probe.js",
    };
    writeFileSync(join(scratch, "package.json"), JSON.stringify(manifest));
    const probe = join(scratch, "src", "documentation-probe.ts");
    const declaration = "export const documentationCoverageProbe = 1;\n";
    writeFileSync(probe, declaration);
    const run = (): ReturnType<typeof spawnSync> => spawnSync(process.execPath,
      [join(REPO, "node_modules", "typedoc", "bin", "typedoc"), "--options", "typedoc.json"],
      { cwd: scratch, encoding: "utf8", timeout: 120_000 });
    const red = run();
    assert.equal(red.status, 4, `${String(red.stdout)}\n${String(red.stderr)}`);
    assert.match(String(red.stdout) + String(red.stderr), /documentationCoverageProbe.*does not have any documentation/);
    writeFileSync(probe, "/** A constant used to verify documentation coverage on exported package subpaths. */\n" + declaration);
    const green = run();
    assert.equal(green.status, 0, `${String(green.stdout)}\n${String(green.stderr)}`);
    const index = readFileSync(join(scratch, "site-dist", "api", "index.html"), "utf8");
    assert.ok(index.includes(manifest.version), "API reference must display the package version");
    assert.ok(index.includes("documentation-probe"), "API reference must include the added export subpath");
  } finally {
    rmSync(scratch, { recursive: true, force: true });
  }
});
