// The packed package as a consumer receives it (pnpm test:tarball, which builds first). It packs the
// real tarball, installs it offline into a scratch consumer outside the repository, and then:
//   - typechecks a consumer of the whole public API plus one deep import with skipLibCheck false and
//     types [], under NodeNext and Bundler resolution, lib ES2022 alone and ES2022 + DOM, and each
//     condition set a consumer can select (none, bap-portable, deno, bun): no public declaration may
//     need a Node or DOM global type;
//   - red-proof: the same typecheck fails once one public declaration in the installed copy leaks a
//     node:crypto type;
//   - runs the consumer: Node resolves the node backend, Node with --conditions=bap-portable, Deno and
//     Bun resolve the portable one, and the deep import through the "./*" passthrough works everywhere.
import { test } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { appendFileSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import ts from "typescript";

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
import { verifyGrant as deepVerifyGrant } from "${NAME}/dist/src/v3.js";
const id: BackendId = BACKEND_ID;
const ok: boolean = verifyStrict(new Uint8Array(0), new Uint8Array(64), new Uint8Array(32)) && acceptablePublicKey(new Uint8Array(32)) && torsionFree(new Uint8Array(32));
const es: boolean = es256VerifyStrict(new Uint8Array(0), new Uint8Array(64), new Uint8Array(65));
const digest: Uint8Array = sha256(new Uint8Array(1));
const tagged: Tagged = jsonDecode(Uint8Array.of(0x7b, 0x7d));
const r: Result<GrantFacts> = verifyGrant(new Uint8Array(0), { keyId: "k", publicKey: new Uint8Array(32) }, { issuer: "i", audience: "a", evaluationTime: 0, clockSkew: 0 });
export const all = [id, ok, es, digest, tagged, r, checkEnvelope, decodeGrant, jcsEncode, thumbprint, base64urlEncode, v2.verifyGrant, v3.verifyGrant,
  roleAttestation.verifyAttestation, contentAssertion.verifyAssertion, InvalidError, deepVerifyGrant] as const;
export type Uses = ExpectedRequest;
`;

// RFC 8032 section 7.1 TEST 1, verified through the installed package.
const CONSUMER_JS = `
import { BACKEND_ID, verifyStrict, es256VerifyStrict } from "${NAME}";
import { verifyGrant } from "${NAME}/dist/src/v3.js";
const hex = (h) => Uint8Array.from(h.match(/../g) ?? [], (b) => parseInt(b, 16));
const rfc = verifyStrict(new Uint8Array(0),
  hex("e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"),
  hex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"));
console.log(JSON.stringify({ backend: BACKEND_ID, rfc8032: rfc, es256Garbage: es256VerifyStrict(new Uint8Array(0), new Uint8Array(64), new Uint8Array(65)), deep: typeof verifyGrant }));
`;

test.before(() => {
  run("pnpm", ["pack", "--pack-destination", scratch], REPO);
  tarball = join(scratch, readdirSync(scratch).find((f) => f.endsWith(".tgz"))!);
  mkdirSync(consumer);
  writeFileSync(join(consumer, "package.json"), JSON.stringify({ name: "bap-consumer", private: true, type: "module", dependencies: { [NAME]: `file:${tarball}` } }));
  run("pnpm", ["install", "--offline", "--ignore-scripts", "--config.confirmModulesPurge=false"], consumer);
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
    "./*": "./*",
  });
  const crypto = (MANIFEST.imports as Record<string, Record<string, unknown>>)["#crypto"]!;
  assert.deepEqual(Object.keys(crypto), ["bap-source", "bap-portable", "deno", "bun", "node", "types", "default"]);
});

test("the tarball ships the built backends and no source", () => {
  const files = run("tar", ["-tzf", tarball], scratch).split("\n").filter(Boolean);
  for (const f of ["package/dist/src/crypto/node.js", "package/dist/src/crypto/portable.js", "package/dist/src/crypto/backend.d.ts", "package/dist/src/index.d.ts"]) {
    assert.ok(files.includes(f), `${f} is packed`);
  }
  assert.ok(!files.some((f) => f.startsWith("package/src/") || f.startsWith("package/test/") || f.startsWith("package/conformance/")), "no source, tests or corpora");
});

for (const moduleResolution of ["NodeNext", "Bundler"] as const) {
  for (const lib of [["ES2022"], ["ES2022", "DOM"]]) {
    for (const conditions of [[], ["bap-portable"], ["deno"], ["bun"]]) {
      test(`consumer typecheck: ${moduleResolution}, lib ${lib.join("+")}, conditions [${conditions.join(",")}], skipLibCheck false, types []`, () => {
        assert.deepEqual(typecheck(moduleResolution, lib, conditions), []);
      });
    }
  }
}

for (const [label, args, want] of [
  ["node (default conditions)", ["node", "main.mjs"], "node"],
  ["node --conditions=bap-portable", ["node", "--conditions=bap-portable", "main.mjs"], "portable"],
  ["deno", ["deno", "run", "--allow-read", "--allow-env", "main.mjs"], "portable"],
  ["bun", ["bun", "main.mjs"], "portable"],
] as const) {
  test(`consumer runtime: ${label} resolves the ${want} backend; RFC 8032 TEST 1 verifies; the deep import resolves`, () => {
    const [cmd, ...rest] = args;
    const out = JSON.parse(run(cmd, [...rest], consumer).trim()) as Record<string, unknown>;
    assert.deepEqual(out, { backend: want, rfc8032: true, es256Garbage: false, deep: "function" });
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
