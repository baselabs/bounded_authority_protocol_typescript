// Real offline snapshots and deliberate mutations, with cleanup owned by each test.
import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { cpSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { build } from "esbuild";
import { fileURLToPath } from "node:url";
import { fsSource, CONFORMANCE_DIR } from "../conformance/node_source.js";
import { CORES } from "../conformance/core/index.js";
import { CoreAbort, type Core, type VerdictEntry } from "../conformance/core/types.js";
import { assertVerdictDigest, certifyCorpus, completeVerdicts, expectedOutcome, expectedVerdicts, snapshotDigest, assertSnapshot } from "../conformance/certification.js";
import { firstDifferences, hash64, jcs, verdictDigest } from "../conformance/digest.js";
const source = fsSource();
const root = fileURLToPath(new URL("..", import.meta.url));
function fixture(run: (dir: string) => void): void {
  const dir = mkdtempSync(join(tmpdir(), "bap-corpus-"));
  try { cpSync(join(CONFORMANCE_DIR, "priv"), join(dir, "priv"), {recursive: true}); cpSync(join(CONFORMANCE_DIR, "SOURCE"), join(dir, "SOURCE")); run(dir); }
  finally { rmSync(dir, {recursive: true, force: true}); }
}
function repinTree(dir: string): void {
  const path = join(dir, "SOURCE"), pin = JSON.parse(readFileSync(path, "utf8"));
  pin.tree_sha256 = snapshotDigest(fsSource(dir));
  writeFileSync(path, JSON.stringify(pin));
}
function red(label: string, run: () => unknown, pattern: RegExp): void {
  assert.throws(run, (error: Error) => { assert.match(error.message, pattern); console.log(`RED ${label}: ${error.message}`); return true; });
}
test("nine cores and nine SOURCE pins", () => {
  assert.equal(CORES.length, 9);
  const pins = JSON.parse(readFileSync(join(CONFORMANCE_DIR, "SOURCE"), "utf8")).indexes;
  assert.deepEqual(Object.keys(pins).sort(), CORES.map(c => c.dir.slice("priv/conformance/".length)).sort());
});
for (const core of CORES) {
  test(`${core.corpus}: all cases, index order, and corpus-derived digest`, () => {
    const report = core.run(source);
    assert.deepEqual(report.failures, []);
    assert.equal(jcs(report.verdicts), jcs(expectedVerdicts(source, core.dir)));
    assert.equal(verdictDigest(report.verdicts), createHash("sha256").update(jcs(expectedVerdicts(source, core.dir))).digest("base64url"));
    console.log(`GREEN ${core.corpus}: ${assertVerdictDigest(source, core.dir, report.verdicts)} (${report.verdicts.length} cases)`);
  });
  for (const mutation of ["index byte", "case byte", "extra file", "missing file", "missing snapshot directory"] as const) {
    test(`${core.corpus}: ${mutation} is refused before execution`, () => fixture(dir => {
      const cert = certifyCorpus(source, core.dir), file = cert.cases[0]!.file;
      const target = join(dir, core.dir, mutation === "index byte" ? "index.json" : file);
      const original = readFileSync(target);
      if (mutation === "extra file") writeFileSync(join(dir, core.dir, "extra.json"), "{}");
      else if (mutation === "missing file") rmSync(target);
      else if (mutation === "missing snapshot directory") rmSync(join(dir, "priv"), {recursive: true});
      else writeFileSync(target, Buffer.concat([original, Buffer.from(" ")]));
      red(`${core.corpus} ${mutation}`, () => core.run(fsSource(dir)), mutation === "index byte" ? /SOURCE pin mismatch/ : mutation === "case byte" ? /recorded digest mismatch/ : /file set differs|ENOENT/);
      rmSync(join(dir, "priv"), {recursive: true, force: true});
      cpSync(join(CONFORMANCE_DIR, "priv"), join(dir, "priv"), {recursive: true});
      const restored = core.run(fsSource(dir)); assert.deepEqual(restored.failures, []);
      assertVerdictDigest(fsSource(dir), core.dir, restored.verdicts);
      console.log(`GREEN ${core.corpus} restored after ${mutation}`);
    }));
  }
  test(`${core.corpus}: a duplicate cannot replace a skipped execution`, () => {
    const entries = expectedVerdicts(source, core.dir);
    red(`${core.corpus} duplicate replacing skip`, () => completeVerdicts(source, core.dir, [entries[0]!, ...entries.slice(0, -1)]), /duplicate executed id/);
    red(`${core.corpus} skip`, () => completeVerdicts(source, core.dir, entries.slice(1)), /skip or unknown id/);
    assert.deepEqual(completeVerdicts(source, core.dir, entries), entries);
  });
}
test("every raw sidecar is hashed before execution", () => fixture(dir => {
  for (const core of CORES) {
    const raws = source.list(core.dir).filter(p => p.endsWith(".raw"));
    for (const file of raws) {
      const target = join(dir, core.dir, file), bytes = readFileSync(target), changed = Buffer.from(bytes);
      changed[0] = changed[0]! ^ 1; writeFileSync(target, changed);
      red(`${core.corpus} raw byte ${file}`, () => core.run(fsSource(dir)), /recorded digest mismatch/);
      writeFileSync(target, bytes);
    }
    assert.deepEqual(core.run(fsSource(dir)).failures, []);
  }
}));
test("duplicate certified ids are enforced even after rehashing a candidate", () => fixture(dir => {
  const core = CORES[0]!, file = certifyCorpus(source, core.dir).cases[0]!.file;
  const target = join(dir, core.dir, file), indexPath = join(dir, core.dir, "index.json"), sourcePath = join(dir, "SOURCE");
  const doc = JSON.parse(readFileSync(target, "utf8")), index = JSON.parse(readFileSync(indexPath, "utf8")), pin = JSON.parse(readFileSync(sourcePath, "utf8"));
  doc.cases[1].id = doc.cases[0].id;
  writeFileSync(target, JSON.stringify(doc));
  index.files.find((f: {path: string}) => f.path === file).sha256_base64url = hash64(readFileSync(target));
  writeFileSync(indexPath, JSON.stringify(index)); pin.indexes[core.dir.slice("priv/conformance/".length)] = hash64(readFileSync(indexPath)); writeFileSync(sourcePath, JSON.stringify(pin)); repinTree(dir);
  red("duplicate certified id", () => core.run(fsSource(dir)), /duplicate or invalid case id/);
}));
test("applicability and counts remain total even when an index is rehashed", () => fixture(dir => {
  const core = CORES[0]!, indexPath = join(dir, core.dir, "index.json"), pinPath = join(dir, "SOURCE");
  const bytes = readFileSync(indexPath), pin = JSON.parse(readFileSync(pinPath, "utf8"));
  for (const mutation of ["surface", "class", "count", "total"] as const) {
    const index = JSON.parse(bytes.toString()), surface = Object.keys(index.applicability)[0]!;
    if (mutation === "surface") delete index.applicability[surface];
    else if (mutation === "class") delete index.applicability[surface][Object.keys(index.applicability[surface])[0]!];
    else if (mutation === "count") index.files.find((f: {cases: number}) => f.cases > 0).cases++;
    else index.total_cases++;
    writeFileSync(indexPath, JSON.stringify(index));
    pin.indexes[core.dir.slice("priv/conformance/".length)] = hash64(readFileSync(indexPath)); writeFileSync(pinPath, JSON.stringify(pin)); repinTree(dir);
    red(`rehash ${mutation}`, () => certifyCorpus(fsSource(dir), core.dir), /applicability is not total|case count mismatch/);
  }
  writeFileSync(indexPath, bytes); cpSync(join(CONFORMANCE_DIR, "SOURCE"), pinPath);
  assertVerdictDigest(fsSource(dir), core.dir, core.run(fsSource(dir)).verdicts);
}));
test("future published digests are checked from a real snapshot plus a generated file", () => fixture(dir => {
  const corpora = Object.fromEntries(CORES.map(core => { const cert = certifyCorpus(source, core.dir); return [cert.path, {index_sha256_base64url: cert.indexSha, case_count: cert.cases.length, verdict_digest_sha256_base64url: verdictDigest(expectedVerdicts(source, core.dir))}]; }));
  const path = join(dir, "priv/conformance/verdict-digests.json");
  const write = () => { writeFileSync(path, JSON.stringify({format: "bap-corpus-verdict-digests/1", corpora}, null, 2) + "\n"); repinTree(dir); };
  write();
  for (const core of CORES) assertVerdictDigest(fsSource(dir), core.dir, core.run(fsSource(dir)).verdicts);
  const core = CORES[0]!, pin = corpora[certifyCorpus(source, core.dir).path]!, original = pin.verdict_digest_sha256_base64url;
  pin.verdict_digest_sha256_base64url = "A".repeat(43); write();
  red("published verdict digest", () => assertVerdictDigest(fsSource(dir), core.dir, core.run(fsSource(dir)).verdicts), /published verdict digest mismatch/);
  pin.verdict_digest_sha256_base64url = original; write();
  assertVerdictDigest(fsSource(dir), core.dir, core.run(fsSource(dir)).verdicts);
}));
test("always-pass comparator cannot conceal a wrong computed result", async () => {
  const core = CORES.find(c => c.corpus === "v2")!;
  const invalid = certifyCorpus(source, core.dir).cases.find(c => c.data.surface === "base64url.decode" && (c.value as {verdict: string}).verdict === "invalid")!;
  const result = await build({stdin: {contents: 'export { core } from "./conformance/core/v2.ts";', resolveDir: root, loader: "ts"}, bundle: true, platform: "node", format: "esm", write: false,
    plugins: [{name: "comparator-mutation", setup(b) {
      b.onResolve({filter: /^#crypto$/}, () => ({path: join(root, "src/crypto/node.ts")}));
      b.onLoad({filter: /conformance[\/]core[\/]v2\.ts$/}, args => {
        const original = readFileSync(args.path, "utf8");
        const changed = original.replace(/function compareVerdict\([\s\S]*?(?=function compareField)/, "function compareVerdict(): boolean { return true; }\n\n")
          .replace("const actual = dispatch(c.surface, input, raws);", `const actual = c.id === ${JSON.stringify(invalid.id)} ? {} : dispatch(c.surface, input, raws);`);
        assert.notEqual(changed, original); assert.ok(changed.includes("return true;"));
        return {contents: changed, loader: "ts"};
      });
    }}]});
  const mutant = await import(`data:text/javascript;base64,${Buffer.from(result.outputFiles[0]!.text).toString("base64")}`) as {core: Core};
  const report = mutant.core.run(source); assert.deepEqual(report.failures, [], "the mutated comparator always agrees");
  red("always-pass comparator", () => assertVerdictDigest(source, core.dir, report.verdicts), /verdict digest mismatch/);
  assertVerdictDigest(source, core.dir, core.run(source).verdicts);
});
test("outcome schemas exclude inputs and fail closed on missing outcomes", () => {
  const record = {id: "case", compact: "input", decode: false, verify: false, expected_overrides: {now: 1}};
  assert.deepEqual(expectedOutcome("attestation-profiles/role-attestation/v1", "attestation-cases.json", record), {decode: false, verify: false});
  assert.throws(() => expectedOutcome("strict-ed25519", "cases/ra1/a.json", {id: "case", surface: "role_attestation", decode: true}), CoreAbort);
  assert.throws(() => expectedOutcome("strict-ed25519", "cases/a.json", {id: "case", surface: "unknown"}), CoreAbort);
});
test("JCS is structured, ordered, field-sensitive, and refuses non-JSON", () => {
  const entries: VerdictEntry[] = [["a", {z: -0, a: 1e-7}], ["b", {verdict: "invalid"}]];
  assert.equal(jcs(entries), '[["a",{"a":1e-7,"z":0}],["b",{"verdict":"invalid"}]]');
  assert.notEqual(verdictDigest(entries), verdictDigest([...entries].reverse()));
  assert.notEqual(verdictDigest(entries), verdictDigest([["a", {a: 1e-7, z: 1}], entries[1]!]));
  assert.equal(verdictDigest(entries).length, 43);
  assert.deepEqual(firstDifferences(entries, entries), []);
  for (const value of [undefined, NaN, Infinity, "\ud800"]) assert.throws(() => jcs(value));
});

test("every core refuses auxiliary snapshot mutations, including a root digest file", () => fixture(dir => {
  for (const path of ["v1/schemas/corpus-index.schema.json", "v1/vectors/grant-holder-proof.json", "verdict-digests.json"]) {
    const target = join(dir, "priv/conformance", path);
    const original = path === "verdict-digests.json" ? undefined : readFileSync(target);
    writeFileSync(target, original ? Buffer.concat([original, Buffer.from(" ")]) : "{}");
    for (const core of CORES) red(`${core.corpus} auxiliary ${path}`, () => core.run(fsSource(dir)), /tree SHA-256/);
    if (original) writeFileSync(target, original); else rmSync(target);
  }
  assertSnapshot(fsSource(dir));
}));
test("a repinned real attestation case can grow the corpus without editing a runner count", () => fixture(dir => {
  const core = CORES.find(c => c.corpus === "role-attestation")!;
  const casePath = join(dir, core.dir, "attestation-cases.json"), indexPath = join(dir, core.dir, "index.json"), pinPath = join(dir, "SOURCE");
  const cases = JSON.parse(readFileSync(casePath, "utf8")), index = JSON.parse(readFileSync(indexPath, "utf8")), pin = JSON.parse(readFileSync(pinPath, "utf8"));
  cases.push({...cases[0], id: "adoption-count-growth-control"});
  writeFileSync(casePath, JSON.stringify(cases));
  index.attestation_cases = cases.length;
  index.files.find((f: {path: string}) => f.path === "attestation-cases.json").sha256 = createHash("sha256").update(readFileSync(casePath)).digest("hex");
  writeFileSync(indexPath, JSON.stringify(index));
  pin.indexes[core.dir.slice("priv/conformance/".length)] = hash64(readFileSync(indexPath));
  writeFileSync(pinPath, JSON.stringify(pin)); repinTree(dir);
  const report = core.run(fsSource(dir));
  assert.deepEqual(report.failures, []);
  assert.equal(report.verdicts.length, cases.length);
  assertVerdictDigest(fsSource(dir), core.dir, report.verdicts);
}));
