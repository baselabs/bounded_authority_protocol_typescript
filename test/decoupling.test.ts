// The crypto import boundary, read from esbuild's metafile of the real package entry: node:crypto is
// imported only by src/crypto/node.ts, and the profile modules reach a backend only through the
// "#crypto" package import (never a relative path into src/crypto/node.ts or portable.ts).
import { test } from "node:test";
import assert from "node:assert/strict";
import { fileURLToPath } from "node:url";
import { build, type Metafile } from "esbuild";

const REPO = fileURLToPath(new URL("..", import.meta.url));

async function metafile(conditions: string[]): Promise<Metafile> {
  const result = await build({
    entryPoints: [`${REPO}src/index.ts`],
    absWorkingDir: REPO,
    bundle: true,
    write: false,
    format: "esm",
    platform: "node",
    conditions,
    metafile: true,
    logLevel: "silent",
  });
  return result.metafile;
}

const NODE_BUILTIN = /^(node:)?(crypto|buffer|fs|path|os|process|util|stream|url|child_process|net|http|https|worker_threads)$/;

test("node:crypto is imported only by src/crypto/node.ts (node backend build)", async () => {
  const meta = await metafile(["bap-source"]);
  const importers = Object.entries(meta.inputs)
    .filter(([, input]) => input.imports.some((i) => i.external && NODE_BUILTIN.test(i.path)))
    .map(([path]) => path)
    .sort();
  assert.deepEqual(importers, ["src/crypto/node.ts"]);
  assert.ok("src/crypto/node.ts" in meta.inputs, "the node backend is in the node build");
  assert.ok(!("src/crypto/portable.ts" in meta.inputs), "the portable backend is not in the node build");
});

test("profile modules reach a backend only through #crypto", async () => {
  const meta = await metafile(["bap-source"]);
  for (const [path, input] of Object.entries(meta.inputs)) {
    if (path.startsWith("src/crypto/")) continue;
    for (const imp of input.imports) {
      if (/^src\/crypto\/(node|portable)\.ts$/.test(imp.path)) {
        assert.equal(imp.original, "#crypto", `${path} imports ${imp.path} as ${imp.original ?? "?"}`);
      }
    }
  }
});
