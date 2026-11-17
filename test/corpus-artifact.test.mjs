// No network substitution: exercise real archive parsing and pure release policy offline.
import { test } from "node:test";
import assert from "node:assert/strict";
import { gzipSync } from "node:zlib";
import { cpSync, existsSync, mkdtempSync, readdirSync, readFileSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { fileURLToPath } from "node:url";
import { assertReleaseSource, compareSnapshot, hash, installSnapshot, parseSource, readTar, sourceFor, treeFiles, unpackHex, validateReleaseMetadata } from "../scripts/corpus-artifact.mjs";
import { assertCurrent, newestEligible } from "../scripts/corpus-policy.mjs";
const root = fileURLToPath(new URL("..", import.meta.url));
const source = parseSource(readFileSync(join(root, "conformance/SOURCE")));
const files = treeFiles(join(root, "conformance/priv/conformance"));
function tar(entries) {
  const chunks = [];
  for (const [path, data] of entries) {
    const header = Buffer.alloc(512), bytes = Buffer.from(data);
    const split = Buffer.byteLength(path) < 100 ? -1 : path.lastIndexOf("/");
    const name = path.slice(split + 1), prefix = split < 0 ? "" : path.slice(0, split);
    assert.ok(Buffer.byteLength(name) < 100 && Buffer.byteLength(prefix) <= 155);
    header.write(name); header.write(prefix, 345); header.write("0000644\0", 100); header.write("0000000\0", 108); header.write("0000000\0", 116);
    header.write(bytes.length.toString(8).padStart(11, "0") + "\0", 124); header.write("00000000000\0", 136); header.fill(32, 148, 156); header[156] = 48;
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
    red("transactional failure", () => installSnapshot(dir, broken, source), /EEXIST|ENOTDIR/);
    assert.deepEqual(treeFiles(join(dir, "conformance")), before);
    assert.deepEqual(readdirSync(dir), ["conformance"]);
    installSnapshot(dir, files, source);
    compareSnapshot(dir, files, source);
    assert.deepEqual(readdirSync(dir), ["conformance"]);
    const extra = new Map([...files, ["extra", Buffer.from("x")]]);
    red("whole-tree extra file", () => compareSnapshot(dir, extra, source), /file set differs/);
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
    {version: "2.0.0", inserted_at: new Date(now - 3599999).toISOString()}, {version: "3.0.0", inserted_at: old}]};
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
