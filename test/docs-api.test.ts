import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { cpSync, mkdtempSync, readFileSync, readdirSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

const REPO = fileURLToPath(new URL("..", import.meta.url));

test("TypeDoc discovers exports, rejects undocumented API and stamps the package version", () => {
  const scratch = mkdtempSync(join(tmpdir(), "bap-api-docs-"));
  try {
    for (const name of ["src", "package.json", "typedoc.json", "tsconfig.json", "tsconfig.build.json", "tools", "docs", "README.md", "usage-rules.md", "CONTRIBUTING.md", "SECURITY.md", "CHANGELOG.md", "LICENSE", "NOTICE"]) {
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
      [join(scratch, "tools/build-docs.mjs")],
      { cwd: scratch, encoding: "utf8", timeout: 240_000 });
    const red = run();
    assert.notEqual(red.status, 0, `${String(red.stdout)}\n${String(red.stderr)}`);
    assert.match(String(red.stdout) + String(red.stderr), /documentationCoverageProbe.*does not have any documentation/);
    writeFileSync(probe, "/** A constant used to verify documentation coverage on exported package subpaths. */\n" + declaration);
    const green = run();
    assert.equal(green.status, 0, `${String(green.stdout)}\n${String(green.stderr)}`);
    const index = readFileSync(join(scratch, "build-docs", "api", "index.html"), "utf8");
    assert.ok(index.includes(manifest.version), "API reference must display the package version");
    const output = join(scratch, "build-docs/api");
    const pages = readdirSync(output, { recursive: true }).filter((path): path is string => typeof path === "string" && path.endsWith(".html"));
    // The README is the site's front page, so the added subpath gets its own module page.
    assert.ok(pages.some((path) => /(?:^|\/)documentation-probe\.html$/.test(path)), "API reference must include the added export subpath");
    const page = (name: string, namespace = ""): string => {
      const path = pages.find((path) => new RegExp(`(?:/|\\.)${namespace ? namespace + "\\." : ""}${name}\\.html$`).test(path) && (namespace !== "" || !/\.v[23]\./.test(path) && !/\/v[23]\./.test(path)));
      assert.ok(path, `${namespace}.${name}: generated page missing`);
      return readFileSync(join(output, path), "utf8").replace(/<[^>]*>/g, " ").replace(/\s+/g, " ");
    };
    const grant = page("GrantFacts");
    assert.match(grant, /integer Unix seconds/); assert.match(grant, /32-byte/);
    assert.match(grant, /not_evaluated/); assert.match(grant, /no operational authorization decision/);
    assert.match(page("TrustedIssuer"), /32-byte Ed25519 public key/);
    assert.match(page("TrustedIssuer", "v3"), /65-byte/);
    assert.match(page("ExpectedRequest"), /Host-supplied integer Unix seconds/);
    assert.match(page("InvalidError"), /Construct a diagnostic error/);
    assert.ok(!page("InvalidError").includes("captureStackTrace"), "inherited Node Error internals are hidden");
    assert.ok(pages.some((path) => path.includes("getting-started")), "guides share the API site");
    // Headings that contain code keep their GitHub anchors on the API site.
    const site = pages.map((path) => readFileSync(join(output, path), "utf8")).join("\n");
    for (const [level, inner, id] of [
      [3, "<code>TrustedIssuer</code>", "trustedissuer"],
      [4, "<code>uriNormalize\\(input, bounds\\?\\): Result&lt;Uint8Array&gt;</code>", "urinormalizeinput-bounds-resultuint8array"],
      [2, "What <code>checkEnvelope</code> checks", "what-checkenvelope-checks"],
    ] as const) {
      const heading = new RegExp(`<h${level}\\b[^>]*\\bid="([^"]*)"[^>]*>\\s*${inner}`).exec(site);
      assert.equal(heading?.[1], id, `API-site anchor for ${inner}`);
    }
    assert.ok(pages.some((path) => path.includes("notebooks") && path.includes("local-loopback")), "notebooks share the API site");
    // Removing a field or constructor description must fail the same strict site builder.
    for (const [file, pattern] of [
      ["src/facts.ts", /  \/\*\* Issue timestamp[^]*?\*\/\n/],
      ["src/error.ts", /  \/\*\*\n   \* Construct a diagnostic error[^]*?\*\/\n/],
    ] as const) {
      const path = join(scratch, file); const original = readFileSync(path, "utf8");
      const mutated = original.replace(pattern, ""); assert.notEqual(mutated, original);
      writeFileSync(path, mutated);
      const refused = run();
      assert.notEqual(refused.status, 0, String(refused.stdout) + String(refused.stderr));
      assert.match(String(refused.stdout) + String(refused.stderr), /does not have any documentation/);
      writeFileSync(path, original);
    }
  } finally {
    rmSync(scratch, { recursive: true, force: true });
  }
});
