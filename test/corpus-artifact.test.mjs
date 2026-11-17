// No network substitution: exercise real archive parsing and pure release policy offline.
import { test } from "node:test";
import assert from "node:assert/strict";
import { gzipSync } from "node:zlib";
import { cpSync, existsSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { fileURLToPath } from "node:url";
import { assertReleaseSource, compareSnapshot, hash, installSnapshot, parseSource, readTar, sourceFor, treeDigest, treeFiles, unpackHex, validateReleaseMetadata } from "../scripts/corpus-artifact.mjs";
import { adoptionDecision, assertCurrent, newestEligible } from "../scripts/corpus-policy.mjs";
import { assertDocumentation, corpusSummary, rewriteCorpusSummary } from "../scripts/corpus-docs.mjs";
const root = fileURLToPath(new URL("..", import.meta.url));
const source = parseSource(readFileSync(join(root, "conformance/SOURCE")));
const files = treeFiles(join(root, "conformance/priv/conformance"));
function tar(entries) {
  const chunks = [];
  for (const [path, data, type = "0"] of entries) {
    const header = Buffer.alloc(512), bytes = Buffer.from(data);
    const split = Buffer.byteLength(path) < 100 ? -1 : path.lastIndexOf("/");
    const name = path.slice(split + 1), prefix = split < 0 ? "" : path.slice(0, split);
    assert.ok(Buffer.byteLength(name) < 100 && Buffer.byteLength(prefix) <= 155);
    header.write(name); header.write(prefix, 345); header.write("0000644\0", 100); header.write("0000000\0", 108); header.write("0000000\0", 116);
    header.write(bytes.length.toString(8).padStart(11, "0") + "\0", 124); header.write("00000000000\0", 136); header.fill(32, 148, 156); header[156] = type.charCodeAt(0);
    header.write("ustar\0", 257); header.write("00", 263);
    header.write([...header].reduce((n, b) => n + b, 0).toString(8).padStart(6, "0") + "\0 ", 148);
    chunks.push(header, bytes, Buffer.alloc((512 - bytes.length % 512) % 512));
  }
  return Buffer.concat([...chunks, Buffer.alloc(1024)]);
}
function hex(badInner = false) {
  const version = Buffer.from("3"), metadata = Buffer.from('{<<"name">>,<<"bounded_authority_protocol">>}.\n');
  const contents = gzipSync(tar([...files].map(([p, b]) => ["priv/conformance/" + p, b])));
  const checksum = badInner ? "0".repeat(64) : hash(Buffer.concat([version, metadata, contents])).toUpperCase();
  return tar([["VERSION", version], ["CHECKSUM", checksum], ["metadata.config", metadata], ["contents.tar.gz", contents]]);
}
function red(label, run, pattern) { assert.throws(run, error => {assert.match(error.message, pattern); console.log(`RED ${label}: ${error.message}`); return true;}); }
test("Hex outer and inner checksums fail closed, then the whole real subtree unpacks", () => {
  const bytes = hex();
  red("replaced tarball checksum", () => unpackHex(bytes, "0".repeat(64)), /outer tarball checksum mismatch/);
  const badInner = hex(true);
  red("inner CHECKSUM", () => unpackHex(badInner, hash(badInner)), /inner CHECKSUM mismatch/);
  assert.deepEqual(unpackHex(bytes, hash(bytes)), files);
  console.log("GREEN Hex checksums: verified outer and inner, whole snapshot equal");
});
test("unsafe and truncated archives are refused", () => {
  for (const path of ["../bad", "/bad", "a/../bad", "a\\bad"]) assert.throws(() => readTar(tar([[path, "x"]])), /unsafe/);
  const bytes = tar([["valid", "x"]]); bytes[0] ^= 1;
  assert.throws(() => readTar(bytes), /header checksum/);
  assert.throws(() => readTar(tar([["valid", "x"]]).subarray(0, 515)), /truncated/);
});
test("transaction stages completely and removes its own residue on failure and success", () => {
  const dir = mkdtempSync(join(tmpdir(), "bap-vendor-"));
  try {
    cpSync(join(root, "conformance"), join(dir, "conformance"), {recursive: true});
    const before = treeFiles(join(dir, "conformance"));
    const broken = new Map([...files, ["collision", Buffer.from("x")], ["collision/child", Buffer.from("x")]]);
    red("transactional failure", () => installSnapshot(dir, broken, sourceFor(broken, {version: source.version, checksum: source.checksum})), /EEXIST|ENOTDIR/);
    assert.deepEqual(treeFiles(join(dir, "conformance")), before);
    assert.deepEqual(readdirSync(dir), ["conformance"]);
    installSnapshot(dir, files, source);
    compareSnapshot(dir, files, source);
    assert.deepEqual(readdirSync(dir), ["conformance"]);
    const extra = new Map([...files, ["extra", Buffer.from("x")]]);
    red("whole-tree extra file", () => compareSnapshot(dir, extra, source), /tree SHA-256|file set differs/);
    compareSnapshot(dir, files, source);
  } finally { rmSync(dir, {recursive: true, force: true}); }
  assert.equal(existsSync(dir), false);
});
test("stale SOURCE and candidate SOURCE fail release and main gates, then release pin is green", () => {
  const newest = {version: "1.0.0", checksum: source.checksum};
  red("stale SOURCE", () => assertCurrent({...source, version: "0.9.1"}, newest), /stale SOURCE/);
  const candidate = sourceFor(files, {candidate: "a".repeat(40)});
  red("candidate SOURCE on main", () => assertReleaseSource(candidate, true), /candidate SOURCE refused on main/);
  red("candidate release", () => assertCurrent(candidate, newest), /candidate SOURCE refused by release gate/);
  assertCurrent(source, newest); assertReleaseSource(source, true);
  console.log("GREEN release gates: current release SOURCE accepted");
});
test("eligibility observes both revert windows, retirement and semantic version order", () => {
  const now = Date.parse("2026-11-17T12:00:00Z"), old = "2026-11-10T12:00:00Z";
  const metadata = {inserted_at: old, retirements: {"3.0.0": {reason: "invalid"}}, releases: [
    {version: "1.0.0", inserted_at: old}, {version: "1.10.0", inserted_at: old}, {version: "1.9.0", inserted_at: old},
    {version: "2.0.0", inserted_at: new Date(now - 3599999).toISOString()}, {version: "3.0.0", inserted_at: old}, {version: "99.0.0-rc.1", inserted_at: old}, {version: "98.0.0+build.1", inserted_at: old}]};
  assert.equal(newestEligible(metadata, now), "1.10.0");
  assert.equal(newestEligible(metadata, now + 1), "2.0.0");
  const initial = {...metadata, inserted_at: new Date(now - 24 * 3600000 + 1).toISOString()};
  assert.throws(() => newestEligible(initial, now), /no non-retired release/);
  assert.equal(newestEligible(initial, now + 1), "2.0.0");
});
test("release metadata refuses retirement and missing retirement before accepting a checksum", () => {
  const metadata = {version: source.version, checksum: source.checksum, retirement: null};
  red("retired release", () => validateReleaseMetadata({...metadata, retirement: {reason: "security"}}, source.version), /retired release/);
  assert.throws(() => validateReleaseMetadata({version: source.version, checksum: source.checksum}, source.version), /invalid metadata/);
  assert.deepEqual(validateReleaseMetadata(metadata, source.version), metadata);
});

test("prereleases and build metadata never become a source, adoption target, or release target", () => {
  for (const version of ["99.0.0-rc.1", "99.0.0+build.1"]) {
    assert.throws(() => parseSource(JSON.stringify({...source, version})), /invalid release/);
    assert.throws(() => adoptionDecision(source, {version, checksum: source.checksum}), /stable versions/);
    assert.throws(() => assertCurrent(source, {version, checksum: source.checksum}), /stable versions/);
  }
  assert.equal(adoptionDecision(source, {...source, version: "1.1.0"}), "adopt");
  assert.equal(adoptionDecision(source, source), "same");
  assert.equal(adoptionDecision({...source, version: "1.1.0"}, source), "ahead");
});
test("re-fetched registry metadata must agree with the eligibility checksum", () => {
  const metadata = {version: source.version, checksum: source.checksum, retirement: null};
  assert.deepEqual(validateReleaseMetadata(metadata, source.version, source.checksum), metadata);
  assert.throws(() => validateReleaseMetadata({...metadata, checksum: "0".repeat(64)}, source.version, source.checksum), /differs from pinned eligibility/);
});
test("subtree selection ignores irrelevant links but refuses every non-regular corpus entry", () => {
  const prefix = "bounded_authority_protocol-commit/priv/conformance/";
  for (const type of ["1", "2", "3", "4", "6", "7"]) {
    const bytes = tar([["bounded_authority_protocol-commit/elsewhere/link", "", type], [prefix + "real.json", "{}"]]);
    assert.deepEqual([...readTar(bytes, prefix).keys()], [prefix + "real.json"]);
    assert.throws(() => readTar(tar([[prefix + "link", "", type]]), prefix), /unsupported entry type/);
  }
  assert.throws(() => readTar(tar([[prefix + "../escape", "x"]]), prefix), /unsafe/);
});
test("offline whole-tree digest covers auxiliary schemas, vectors, additions and removals", () => {
  for (const path of ["v1/schemas/corpus-index.schema.json", "v1/vectors/grant-holder-proof.json"]) {
    const changed = new Map(files); changed.set(path, Buffer.concat([files.get(path), Buffer.from(" ")]));
    assert.notEqual(treeDigest(changed), source.tree_sha256);
    assert.throws(() => installSnapshot(root, changed, source), /tree SHA-256/);
  }
  const added = new Map([...files, ["verdict-digests.json", Buffer.from("{}")]]);
  assert.notEqual(treeDigest(added), source.tree_sha256);
  const missing = new Map(files); missing.delete("v1/vectors/grant-holder-proof.json");
  assert.notEqual(treeDigest(missing), source.tree_sha256);
  assert.equal(treeDigest(files), source.tree_sha256);
  assert.equal(treeDigest(new Map([...files].reverse())), source.tree_sha256);
});
test("adoption rewrites the sole corpus summary and offline checks reject stale prose/workflows", () => {
  const dir = mkdtempSync(join(tmpdir(), "bap-corpus-docs-"));
  try {
    cpSync(join(root, "README.md"), join(dir, "README.md"));
    const next = {...source, version: "1.1.0"};
    assert.throws(() => assertDocumentation(dir, files, next, ["README.md"]), /summary differs/);
    rewriteCorpusSummary(dir, files, next);
    assertDocumentation(dir, files, next, ["README.md"]);
    assert.ok(readFileSync(join(dir, "README.md"), "utf8").includes(corpusSummary(files, next)));
    for (const [path, text] of [["guide.md", "Hex bounded_authority_protocol 0.1.0"], ["ci.yml", "name: conformance (9999 cases)"], ["page.html", "corpus: 9999/9999"]]) {
      writeFileSync(join(dir, path), text);
      assert.throws(() => assertDocumentation(dir, files, next, [path]), /copied corpus version\/count/);
    }
  } finally { rmSync(dir, {recursive: true, force: true}); }
});
