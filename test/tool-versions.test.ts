import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { copyFileSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";

function yamlFiles(directory: URL): URL[] {
  return readdirSync(directory, { withFileTypes: true }).flatMap((entry) => {
    const file = new URL(entry.name, directory);
    return entry.isDirectory() ? yamlFiles(new URL(`${entry.name}/`, directory))
      : /\.ya?ml$/.test(entry.name) ? [file] : [];
  });
}

test("workflows and composite actions cannot bypass the sole tool-version reader", () => {
  const files = yamlFiles(new URL("../.github/", import.meta.url));
  assert.ok(files.length > 0);
  for (const file of files) {
    const source = readFileSync(file, "utf8").split("\n")
      .map((line) => line.replace(/\s+#.*$/, "")).filter((line) => !line.trimStart().startsWith("#")).join("\n");
    assert.doesNotMatch(source, /node-version-file|\.tool-versions/, file.pathname);
    if (/uses: (?:actions\/setup-(?:node|python)|denoland\/setup-deno|oven-sh\/setup-bun|astral-sh\/setup-uv)@/.test(source)) {
      assert.match(source, /run: scripts\/tool-versions\.sh read /, file.pathname);
      assert.match(source, /scripts\/tool-versions\.sh check /, file.pathname);
      for (const line of source.split("\n").filter((line) => /^\s+(?:node-version|deno-version|bun-version|python-version|version):/.test(line))) {
        assert.match(line, /\$\{\{ steps\.pins\.outputs(?:\.|\[)/, `${file.pathname}: ${line}`);
      }
    }
  }
});

test("the reader validates the entire table and selects exact primary and compatibility pins", () => {
  const directory = mkdtempSync(join(tmpdir(), "tool-versions-"));
  try {
    mkdirSync(join(directory, "scripts"));
    copyFileSync(new URL("../scripts/tool-versions.sh", import.meta.url), join(directory, "scripts/tool-versions.sh"));
    const output = join(directory, "outputs");
    const invoke = (...args: string[]) => spawnSync("bash", [join(directory, "scripts/tool-versions.sh"), ...args], {
      cwd: tmpdir(), encoding: "utf8", env: { ...process.env, GITHUB_OUTPUT: output },
    });
    const table = (value: string): void => {
      writeFileSync(join(directory, ".tool-versions"), value);
      writeFileSync(output, "");
    };
    table("# exact pins\n\nnodejs 1.2.3 4.5.6 # compatibility\ndeno 7.8.9");
    assert.equal(invoke("read", "nodejs", "deno").status, 0);
    assert.equal(readFileSync(output, "utf8"), "nodejs=1.2.3\nnodejs-next=4.5.6\ndeno=7.8.9\n");
    for (const args of [["read"], ["read", "unknown"], ["read", "uv"], ["check", "uv"],
      ["check", "nodejs", "unknown"], ["check", "deno", "next"], ["unknown"]]) {
      assert.notEqual(invoke(...args).status, 0, args.join(" "));
    }
    for (const value of ["nodejs 1.2", "nodejs ^1.2.3", "nodejs 1.2.3.", "nodejs 1.2.3-beta.1",
      "nodejs 01.2.3", "nodejs 1.2.3 4.5", "nodejs 1.2.3 1.2.3", "nodejs 1.2.3 4.5.6 7.8.9",
      "nodejs 1.2.3\nnodejs 4.5.6", "unknown 1.2.3", "nodejs 1.2.3\nuv latest"]) {
      table(value);
      assert.notEqual(invoke("read", "nodejs").status, 0, value);
      assert.equal(readFileSync(output, "utf8"), "", "invalid input must emit no pins");
    }
    table(`nodejs ${process.versions.node} 0.0.0\n`);
    assert.equal(invoke("check", "nodejs").status, 0);
    assert.equal(invoke("check", "nodejs", "primary").status, 0);
    const mismatch = invoke("check", "nodejs", "next");
    assert.notEqual(mismatch.status, 0);
    assert.match(mismatch.stderr, /nodejs-next version mismatch/);
    table(`nodejs 0.0.0 ${process.versions.node}\n`);
    assert.equal(invoke("check", "nodejs", "next").status, 0);
    assert.notEqual(invoke("check", "nodejs").status, 0);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test("the lock cannot resolve this repository's own package from a registry", () => {
  const manifest = JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8")) as { name: string };
  const lock = readFileSync(new URL("../pnpm-lock.yaml", import.meta.url), "utf8");
  const escaped = manifest.name.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  // pnpm records every registry package (including aliases) under name@version.
  assert.doesNotMatch(lock, new RegExp(`${escaped}@[^\\s'\"]+`));
});
