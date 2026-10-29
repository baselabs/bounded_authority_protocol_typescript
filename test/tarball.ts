// The packed package as a consumer receives it (pnpm test:tarball, which builds first). It packs the
// real tarball, installs it offline into a scratch consumer outside the repository, and then:
//   - typechecks a consumer of the whole public API (the package root is the only import; deep
//     imports are closed as of 1.0.0) with skipLibCheck false and
//     types [], under NodeNext and Bundler resolution, lib ES2022 alone and ES2022 + DOM, and each
//     condition set a consumer can select (none, bap-portable, deno, bun): no public declaration may
//     need a Node or DOM global type;
//   - red-proof: the same typecheck fails once one public declaration in the installed copy leaks a
//     node:crypto type;
//   - runs the consumer: Node resolves the node backend, Node with --conditions=bap-portable, Deno and
//     Bun resolve the portable one; a probe asserts every deep import now refuses.
import { test } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { appendFileSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import ts from "typescript";
import { build } from "esbuild";
import { createHash } from "node:crypto";
import { chmodSync, existsSync, statSync } from "node:fs";
// @ts-expect-error tools/pack.mjs is untyped JavaScript
import { pack } from "../tools/pack.mjs";

const REPO = fileURLToPath(new URL("..", import.meta.url));
const MANIFEST = JSON.parse(readFileSync(join(REPO, "package.json"), "utf8")) as Record<string, unknown>;
const NAME = "@bounded-authority-protocol/verifier";
const run = (cmd: string, args: string[], cwd: string) => execFileSync(cmd, args, { cwd, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });

const scratch = mkdtempSync(join(tmpdir(), "bap-tarball-"));
const consumer = join(scratch, "consumer");
let tarball = "";


const CONSUMER_TS = `
import {
  BACKEND_ID, checkEnvelope, decodeGrant, verifyGrant, verifyStrict, acceptablePublicKey, torsionFree,
  es256VerifyStrict, sha256, jcsEncode, jsonDecode, thumbprint, base64urlEncode, v2, v3, roleAttestation,
  contentAssertion, InvalidError, type BackendId, type ExpectedRequest, type GrantFacts, type Result, type Tagged,
} from "${NAME}";
const id: BackendId = BACKEND_ID;
const ok: boolean = verifyStrict(new Uint8Array(0), new Uint8Array(64), new Uint8Array(32)) && acceptablePublicKey(new Uint8Array(32)) && torsionFree(new Uint8Array(32));
const es: boolean = es256VerifyStrict(new Uint8Array(0), new Uint8Array(64), new Uint8Array(65));
const digest: Uint8Array = sha256(new Uint8Array(1));
const tagged: Tagged = jsonDecode(Uint8Array.of(0x7b, 0x7d));
const r: Result<GrantFacts> = verifyGrant(new Uint8Array(0), { keyId: "k", publicKey: new Uint8Array(32) }, { issuer: "i", audience: "a", evaluationTime: 0, clockSkew: 0 });
export const all = [id, ok, es, digest, tagged, r, checkEnvelope, decodeGrant, jcsEncode, thumbprint, base64urlEncode, v2.verifyGrant, v3.verifyGrant,
  roleAttestation.verifyAttestation, contentAssertion.verifyAssertion, InvalidError] as const;
export type Uses = ExpectedRequest;
`;

// RFC 8032 section 7.1 TEST 1, verified through the installed package.
const CONSUMER_JS = `
import { BACKEND_ID, verifyStrict, es256VerifyStrict } from "${NAME}";
const hex = (h) => Uint8Array.from(h.match(/../g) ?? [], (b) => parseInt(b, 16));
const rfc = verifyStrict(new Uint8Array(0),
  hex("e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"),
  hex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"));
console.log(JSON.stringify({ backend: BACKEND_ID, rfc8032: rfc, es256Garbage: es256VerifyStrict(new Uint8Array(0), new Uint8Array(64), new Uint8Array(65)) }));
`;

test.before(() => {
  // The tarball the release publishes: BAP_TARBALL when the release workflow packed it already,
  // otherwise packed here by the same script (tools/pack.mjs).
  tarball = process.env.BAP_TARBALL ?? (pack(join(scratch, "packed")) as { file: string }).file;
  mkdirSync(consumer);
  writeFileSync(join(consumer, "package.json"), JSON.stringify({ name: "bap-consumer", private: true, type: "module", dependencies: { [NAME]: `file:${tarball}` } }));
  // --prefer-offline, not --offline: a fresh CI runner has no pnpm metadata cache for the
  // packed tarball's own dependencies, so it must be allowed to fetch them.
  run("pnpm", ["install", "--prefer-offline", "--ignore-scripts", "--config.confirmModulesPurge=false"], consumer);
  writeFileSync(join(consumer, "consumer.ts"), CONSUMER_TS);
  writeFileSync(join(consumer, "main.mjs"), CONSUMER_JS);
});
test.after(() => rmSync(scratch, { recursive: true, force: true }));

function typecheck(moduleResolution: "NodeNext" | "Bundler", lib: string[], customConditions: string[]): string[] {
  const options: ts.CompilerOptions = {
    target: ts.ScriptTarget.ES2022,
    module: moduleResolution === "NodeNext" ? ts.ModuleKind.NodeNext : ts.ModuleKind.ESNext,
    moduleResolution: moduleResolution === "NodeNext" ? ts.ModuleResolutionKind.NodeNext : ts.ModuleResolutionKind.Bundler,
    lib: lib.map((l) => `lib.${l.toLowerCase()}.d.ts`),
    types: [],
    strict: true,
    skipLibCheck: false,
    noEmit: true,
    ...(customConditions.length > 0 ? { customConditions } : {}),
  };
  const program = ts.createProgram({ rootNames: [join(consumer, "consumer.ts")], options });
  return ts.getPreEmitDiagnostics(program).map((d) => `${d.file?.fileName.replace(consumer, "") ?? ""} TS${d.code}: ${ts.flattenDiagnosticMessageText(d.messageText, " ")}`);
}

test("the manifest declares the exports map, the imports conditions and no side effects", () => {
  assert.equal(MANIFEST.sideEffects, false);
  assert.deepEqual(MANIFEST.exports, {
    ".": { types: "./dist/src/index.d.ts", default: "./dist/src/index.js" },
    "./package.json": "./package.json",
    "./dist/src/crypto/*": null,
  });
  const crypto = (MANIFEST.imports as Record<string, Record<string, unknown>>)["#crypto"]!;
  assert.deepEqual(Object.keys(crypto), ["bap-source", "bap-portable", "deno", "bun", "workerd", "worker", "node", "types", "default"]);
});

test("the tarball ships the built backends and no source", () => {
  const files = run("tar", ["-tzf", tarball], scratch).split("\n").filter(Boolean);
  for (const f of ["package/dist/src/crypto/node.js", "package/dist/src/crypto/portable.js", "package/dist/src/crypto/backend.d.ts", "package/dist/src/index.d.ts"]) {
    assert.ok(files.includes(f), `${f} is packed`);
  }
  assert.ok(!files.some((f) => f.startsWith("package/src/") || f.startsWith("package/test/") || f.startsWith("package/conformance/")), "no source, tests or corpora");
});

// The packed package.json must point only at packed files: every string target of "exports" and
// "imports" (wildcard targets by their fixed prefix) is in the tarball. The repository's own
// development condition (bap-source, targets in src/) is stripped at pack time (tools/pack-manifest.mjs).
function targets(value: unknown, out: string[] = []): string[] {
  if (typeof value === "string") out.push(value);
  else if (value !== null && typeof value === "object") for (const v of Object.values(value)) targets(v, out);
  return out;
}
test("pack check: every exports and imports target in the packed package.json is a packed file", () => {
  const files = new Set(run("tar", ["-tzf", tarball], scratch).split("\n").filter(Boolean));
  const packed = JSON.parse(run("tar", ["-xzOf", tarball, "package/package.json"], scratch)) as Record<string, unknown>;
  const all = [...targets(packed.exports), ...targets(packed.imports)];
  assert.ok(all.includes("./dist/src/crypto/portable.js"), "the walk must see the #crypto targets");
  const missing = all.filter((t) => {
    assert.ok(t.startsWith("./"), `target ${t} is relative`);
    const path = `package/${t.slice(2)}`;
    if (!t.includes("*")) return !files.has(path);
    const prefix = path.slice(0, path.indexOf("*"));
    return ![...files].some((f) => f.startsWith(prefix));
  });
  assert.deepEqual(missing, []);
  const crypto = (packed.imports as Record<string, Record<string, unknown>>)["#crypto"]!;
  assert.deepEqual(Object.keys(crypto), ["bap-portable", "deno", "bun", "workerd", "worker", "node", "types", "default"]);
});

const sha256 = (file: string): string => createHash("sha256").update(readFileSync(file)).digest("hex");

// The published files carry no internal process markers: repository-internal rule ids, internal
// runner file names, review labels and ids, or internal tooling names.
export const INTERNAL_MARKERS = /AGENTS rule|corpus_independent|\bowner-|cross-vendor|re-review|review round|\bFinding \d+|\bBAP-\d+\b|kimosabe/i;
test("pack check: no packed file contains an internal process marker", () => {
  const files = run("tar", ["-tzf", tarball], scratch).split("\n").filter((f) => /\.(js|ts|map|json|md)$/.test(f));
  assert.ok(files.includes("package/dist/src/index.js") && files.includes("package/README.md"), "the scan sees the packed files");
  const hits = files.flatMap((f) => {
    const text = run("tar", ["-xzOf", tarball, f], scratch);
    return text.split("\n").flatMap((line, i) => (INTERNAL_MARKERS.test(line) ? [`${f}:${i + 1}: ${line.trim().slice(0, 100)}`] : []));
  });
  assert.deepEqual(hits, []);
});

test("pack: packing leaves the repository's package.json byte for byte unchanged", () => {
  assert.deepEqual(JSON.parse(readFileSync(join(REPO, "package.json"), "utf8")), MANIFEST);
  assert.equal(readdirSync(REPO).filter((f) => f.startsWith("package.json.")).length, 0, "no manifest copy left behind");
});

test("pack: an interrupted pack (an unreadable dist file) fails and leaves package.json untouched", () => {
  const before = readFileSync(join(REPO, "package.json"));
  const victim = join(REPO, "dist/src/v1.js");
  const mode = statSync(victim).mode & 0o7777;
  chmodSync(victim, 0o000);
  let failed = false;
  try {
    run("node", [join(REPO, "tools/pack.mjs"), "--out", join(scratch, "interrupted")], REPO);
  } catch {
    failed = true;
  } finally {
    chmodSync(victim, mode);
  }
  assert.equal(statSync(victim).mode & 0o7777, mode, "the dist file's original mode is restored");
  assert.equal(failed, true, "the pack must fail on an unreadable packed file");
  assert.deepEqual(readFileSync(join(REPO, "package.json")), before);
  assert.equal(readdirSync(REPO).filter((f) => f.startsWith("package.json.")).length, 0);
  assert.equal(existsSync(join(scratch, "interrupted")) ? readdirSync(join(scratch, "interrupted")).length : 0, 0, "no tarball");
});

test("pack: packing again gives the same bytes as the tarball checked here (the release compares this hash)", (t) => {
  const again = (pack(join(scratch, "again")) as { file: string; sha256: string });
  assert.equal(again.sha256, sha256(tarball));
  t.diagnostic(`checked tarball ${tarball.split("/").pop()} sha256 ${again.sha256}`);
});

for (const moduleResolution of ["NodeNext", "Bundler"] as const) {
  for (const lib of [["ES2022"], ["ES2022", "DOM"]]) {
    for (const conditions of [[], ["bap-portable"], ["deno"], ["bun"], ["workerd"], ["worker"]]) {
      test(`consumer typecheck: ${moduleResolution}, lib ${lib.join("+")}, conditions [${conditions.join(",")}], skipLibCheck false, types []`, () => {
        assert.deepEqual(typecheck(moduleResolution, lib, conditions), []);
      });
    }
  }
}

for (const [label, args, want] of [
  ["node (default conditions)", ["node", "main.mjs"], "node"],
  ["node --conditions=bap-portable", ["node", "--conditions=bap-portable", "main.mjs"], "portable"],
  // A consumer build or tool that happens to set this repository's development condition still
  // resolves the shipped backend: the packed manifest carries no bap-source branch.
  ["node --conditions=bap-source", ["node", "--conditions=bap-source", "main.mjs"], "node"],
  ["node --conditions=workerd", ["node", "--conditions=workerd", "main.mjs"], "portable"],
  ["node --conditions=worker", ["node", "--conditions=worker", "main.mjs"], "portable"],
  ["deno", ["deno", "run", "--allow-read", "--allow-env", "main.mjs"], "portable"],
  ["bun", ["bun", "main.mjs"], "portable"],
] as const) {
  test(`consumer runtime: ${label} resolves the ${want} backend; RFC 8032 TEST 1 verifies`, () => {
    const [cmd, ...rest] = args;
    const out = JSON.parse(run(cmd, [...rest], consumer).trim()) as Record<string, unknown>;
    assert.deepEqual(out, { backend: want, rfc8032: true, es256Garbage: false });
  });
}

// The backends are reachable only through "#crypto": a deep import cannot pick the ungated one.
test("deep imports: closed — the backends are not exported and no deep path resolves", () => {
  const probe = (specifier: string) => {
    writeFileSync(join(consumer, "probe.mjs"), `import(${JSON.stringify(specifier)}).then((m) => console.log(typeof m.verifyGrant), (e) => console.log(e.code));`);
    return run("node", ["probe.mjs"], consumer).trim();
  };
  for (const backend of ["node", "portable", "backend", "types", "parts"]) {
    assert.equal(probe(`${NAME}/dist/src/crypto/${backend}.js`), "ERR_PACKAGE_PATH_NOT_EXPORTED", backend);
  }
  // Deep imports are closed (1.0.0): the passthrough is gone, so every deep spelling refuses.
  assert.equal(probe(`${NAME}/dist/src/v3.js`), "ERR_PACKAGE_PATH_NOT_EXPORTED");
  assert.equal(probe(`${NAME}/dist/src/v3`), "ERR_PACKAGE_PATH_NOT_EXPORTED");
  assert.equal(probe(`${NAME}/dist/src/index.js`), "ERR_PACKAGE_PATH_NOT_EXPORTED");
});

// Bundlers: which backend a bundle of the installed package carries, read from esbuild's metafile.
for (const [label, platform, conditions, want] of [
  ["esbuild platform node", "node", [], "node"],
  ["esbuild platform node + workerd", "node", ["workerd"], "portable"],
  ["esbuild platform node + worker", "node", ["worker"], "portable"],
  ["esbuild platform browser", "browser", [], "portable"],
  ["esbuild platform neutral", "neutral", [], "portable"],
] as const) {
  test(`bundler resolution: ${label} carries the ${want} backend`, async () => {
    const result = await build({
      stdin: { contents: `export { BACKEND_ID } from "${NAME}";`, resolveDir: consumer, loader: "js" },
      bundle: true, write: false, format: "esm", platform, conditions: [...conditions], metafile: true, logLevel: "silent",
    });
    const backends = Object.keys(result.metafile.inputs).filter((p) => /dist\/src\/crypto\/(node|portable)\.js$/.test(p)).map((p) => /(node|portable)\.js$/.exec(p)![1]);
    assert.deepEqual(backends, [want]);
  });
}

test("red-proof: a node:crypto type leaked into one public declaration fails the ES2022-only typecheck", () => {
  const installed = join(consumer, "node_modules", ...NAME.split("/"), "dist/src/es256.d.ts");
  const original = readFileSync(installed, "utf8");
  try {
    appendFileSync(installed, '\nimport type { KeyObject } from "node:crypto";\nexport declare function leaked(): KeyObject;\n');
    const diagnostics = typecheck("NodeNext", ["ES2022"], []);
    assert.ok(diagnostics.some((d) => d.includes("es256.d.ts") && d.includes("node:crypto")), diagnostics.join("\n"));
  } finally {
    writeFileSync(installed, original);
  }
  assert.deepEqual(typecheck("NodeNext", ["ES2022"], []), [], "restored");
});
