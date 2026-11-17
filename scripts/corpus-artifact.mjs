// Development tooling only. Hex's outer checksum binds the entire archive; its inner checksum
// binds VERSION || metadata.config || contents.tar.gz (hexpm/hex_core, hex_tarball.erl).
import { createHash } from "node:crypto";
import { gunzipSync } from "node:zlib";
import { cpSync, existsSync, lstatSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, renameSync, rmSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { rewriteCorpusSummary } from "./corpus-docs.mjs";
import catalogue from "../conformance/catalogue.json" with { type: "json" };

export const PACKAGE = "bounded_authority_protocol";
export const API = `https://hex.pm/api/packages/${PACKAGE}`;
export const CORPORA = Object.values(catalogue).sort();
export const hash = (bytes, encoding = "hex") => createHash("sha256").update(bytes).digest(encoding);
const fail = (message) => { throw new Error(message); };
const same = (a, b) => JSON.stringify(a) === JSON.stringify(b);
const safePath = (path) => typeof path === "string" && path.length > 0 && !path.includes("\\") && !path.includes("\0") && path.split("/").every(p => p !== "" && p !== "." && p !== "..");

export function parseSource(bytes) {
  const source = JSON.parse(bytes.toString());
  const candidate = Object.hasOwn(source, "candidate");
  const keys = ["format", "package", "version", "checksum", "tree_sha256", "indexes", ...(candidate ? ["candidate"] : [])].sort();
  if (!same(Object.keys(source).sort(), keys) || source.format !== "bap-corpus-source/1" || source.package !== PACKAGE) fail("SOURCE: invalid closed format or package");
  if (candidate ? typeof source.candidate !== "string" || !/^[a-f0-9]{40}$/.test(source.candidate) || source.version !== null || source.checksum !== null
    : typeof source.version !== "string" || !/^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$/.test(source.version) || !/^[a-f0-9]{64}$/.test(source.checksum)) fail("SOURCE: invalid release or candidate identity");
  if (typeof source.tree_sha256 !== "string" || !/^[a-f0-9]{64}$/.test(source.tree_sha256)) fail("SOURCE: invalid tree_sha256");
  if (!source.indexes || !same(Object.keys(source.indexes).sort(), CORPORA) || Object.values(source.indexes).some(v => typeof v !== "string" || !/^[A-Za-z0-9_-]{43}$/.test(v))) fail("SOURCE: exactly nine index pins required");
  return source;
}

export function assertReleaseSource(source, main = false) {
  if (Object.hasOwn(source, "candidate")) fail(`candidate SOURCE refused${main ? " on main" : " by release gate"}`);
}

export function treeFiles(root) {
  if (!existsSync(root) || !lstatSync(root).isDirectory()) fail(`snapshot directory missing: ${root}`);
  const files = new Map();
  function walk(dir, prefix) {
    for (const name of readdirSync(dir).sort()) {
      const path = join(dir, name), info = lstatSync(path), rel = prefix + name;
      if (info.isDirectory()) walk(path, rel + "/");
      else if (info.isFile()) files.set(rel, readFileSync(path));
      else fail(`snapshot contains a link or special file: ${rel}`);
    }
  }
  walk(root, "");
  return files;
}

// SHA-256 of compact UTF-8 JSON [[relative path, lowercase file SHA-256], ...],
// sorted by path in UTF-16 code-unit order. No BOM or trailing newline.
export const treeDigest = files => hash(JSON.stringify([...files.keys()].sort().map(path => [path, hash(files.get(path))])));
export function assertTree(files, source) {
  if (treeDigest(files) !== source.tree_sha256) fail("snapshot tree SHA-256 differs from SOURCE");
}

export function validateArtifact(files, source) {
  assertTree(files, source);
  const indexes = [...files.keys()].filter(p => p.endsWith("/index.json")).map(p => p.slice(0, -11)).sort();
  if (!same(indexes, CORPORA)) fail("artifact: index inventory differs from the nine certified corpora");
  for (const path of CORPORA) {
    const indexBytes = files.get(`${path}/index.json`);
    if (!indexBytes || hash(indexBytes, "base64url") !== source.indexes[path]) fail(`${path}/index.json: SOURCE pin mismatch`);
    const index = JSON.parse(indexBytes);
    const declared = new Set(["index.json"]);
    for (const file of index.files) {
      if (!safePath(file.path) || declared.has(file.path)) fail(`${path}: duplicate or unsafe indexed path`);
      declared.add(file.path);
      const bytes = files.get(`${path}/${file.path}`);
      const major = Object.hasOwn(file, "sha256_base64url");
      if (!bytes || hash(bytes, major ? "base64url" : "hex") !== (major ? file.sha256_base64url : file.sha256)) fail(`${path}/${file.path}: recorded digest mismatch or missing file`);
    }
    const actual = [...files.keys()].filter(p => p.startsWith(path + "/")).map(p => p.slice(path.length + 1)).sort();
    if (!same(actual, [...declared].sort())) fail(`${path}: actual file set differs from index`);
  }
}

// A bounded in-memory tar reader. It never writes archive paths. Links, devices, duplicates,
// traversal, truncated records and invalid header checksums fail before staging anything.
// With a subtree, irrelevant entries (including links) are ignored; structural tar headers
// are still checked. Only directories and regular files are allowed inside the subtree.
export function readTar(bytes, subtree) {
  const files = new Map(), names = new Set();
  let pax = {}, globalPax = {}, ended = false;
  const text = (buf) => buf.toString("utf8").replace(/\0.*$/s, "");
  const octal = (buf) => { const s = text(buf).trim(); if (!/^[0-7]+$/.test(s)) fail("tar: invalid octal field"); return parseInt(s, 8); };
  function readPax(data) {
    const values = {};
    for (let pos = 0; pos < data.length;) {
      const space = data.indexOf(32, pos), size = Number(data.subarray(pos, space).toString());
      if (space < 0 || !Number.isSafeInteger(size) || size <= space - pos + 1 || pos + size > data.length) fail("tar: invalid PAX record");
      const line = data.subarray(space + 1, pos + size - 1).toString(), eq = line.indexOf("=");
      if (eq < 1 || data[pos + size - 1] !== 10) fail("tar: invalid PAX value");
      values[line.slice(0, eq)] = line.slice(eq + 1); pos += size;
    }
    return values;
  }
  for (let pos = 0; pos + 512 <= bytes.length;) {
    const header = bytes.subarray(pos, pos + 512); pos += 512;
    if (header.every(b => b === 0)) { if (bytes.subarray(pos).some(b => b !== 0)) fail("tar: data after end marker"); ended = true; break; }
    const expected = octal(header.subarray(148, 156));
    let checksum = 0;
    for (let i = 0; i < 512; i++) checksum += i >= 148 && i < 156 ? 32 : header[i];
    if (checksum !== expected) fail("tar: header checksum mismatch");
    const size = octal(header.subarray(124, 136));
    if (!Number.isSafeInteger(size) || pos + Math.ceil(size / 512) * 512 > bytes.length) fail("tar: truncated entry");
    const data = bytes.subarray(pos, pos + size); pos += Math.ceil(size / 512) * 512;
    const type = String.fromCharCode(header[156]);
    if (type === "g" || type === "x") { if (type === "g") globalPax = {...globalPax, ...readPax(data)}; else pax = readPax(data); continue; }
    const attributes = {...globalPax, ...pax}; pax = {};
    const prefix = text(header.subarray(345, 500));
    const name = (attributes.path ?? `${prefix ? prefix + "/" : ""}${text(header.subarray(0, 100))}`).replace(/\/$/, "");
    if (subtree !== undefined && name !== subtree.slice(0, -1) && !name.startsWith(subtree)) continue;
    if (!safePath(name) || names.has(name)) fail(`tar: unsafe or duplicate path ${name}`);
    names.add(name);
    if (type === "5") { if (size !== 0) fail("tar: directory with data"); continue; }
    if (type !== "0" && type !== "\0") fail(`tar: unsupported entry type ${type}`);
    if (attributes.size !== undefined && Number(attributes.size) !== size) fail("tar: inconsistent PAX size");
    files.set(name, data);
  }
  if (!ended) fail("tar: missing end marker");
  return files;
}

export function unpackHex(bytes, checksum) {
  if (!/^[a-f0-9]{64}$/.test(checksum) || hash(bytes) !== checksum) fail("Hex outer tarball checksum mismatch");
  const outer = readTar(bytes);
  if (!same([...outer.keys()].sort(), ["CHECKSUM", "VERSION", "contents.tar.gz", "metadata.config"].sort())) fail("Hex: unexpected outer file set");
  if (outer.get("VERSION").toString() !== "3") fail("Hex: unsupported archive VERSION");
  const inner = hash(Buffer.concat([outer.get("VERSION"), outer.get("metadata.config"), outer.get("contents.tar.gz")]));
  if (outer.get("CHECKSUM").toString().toLowerCase() !== inner) fail("Hex inner CHECKSUM mismatch");
  const contents = readTar(gunzipSync(outer.get("contents.tar.gz"), {maxOutputLength: 64 * 1024 * 1024}), "priv/conformance/");
  return new Map([...contents].filter(([p]) => p.startsWith("priv/conformance/")).map(([p, b]) => [p.slice("priv/conformance/".length), b]));
}

async function fetchBytes(url) {
  const response = await fetch(url, {signal: AbortSignal.timeout(60_000)});
  if (!response.ok) fail(`${url}: HTTP ${response.status}`);
  const bytes = Buffer.from(await response.arrayBuffer());
  if (bytes.length > 64 * 1024 * 1024) fail("download exceeds 64 MiB");
  return bytes;
}
export const fetchJson = async (url) => JSON.parse(await fetchBytes(url));

export function validateReleaseMetadata(release, version, pinnedChecksum) {
  if (release.version !== version || !Object.hasOwn(release, "retirement") || release.retirement !== null) fail(`Hex ${version}: retired release or invalid metadata`);
  if (!/^[a-f0-9]{64}$/.test(release.checksum)) fail("Hex: invalid registry checksum");
  if (pinnedChecksum !== undefined && pinnedChecksum !== release.checksum) fail("Hex registry checksum differs from pinned eligibility metadata or SOURCE");
  return release;
}
export async function releaseMetadata(version, pinnedChecksum) {
  if (typeof version !== "string" || !/^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$/.test(version)) fail("invalid Hex version");
  const release = await fetchJson(`${API}/releases/${version}`);
  return validateReleaseMetadata(release, version, pinnedChecksum);
}

export async function releaseArtifact(version, pinnedChecksum) {
  const release = await releaseMetadata(version, pinnedChecksum);
  const tarball = await fetchBytes(`https://repo.hex.pm/tarballs/${PACKAGE}-${version}.tar`);
  return {files: unpackHex(tarball, release.checksum), release};
}

export function sourceFor(files, identity) {
  const source = {format: "bap-corpus-source/1", package: PACKAGE, version: null, checksum: null, ...identity,
    tree_sha256: treeDigest(files),
    indexes: Object.fromEntries(CORPORA.map(path => [path, hash(files.get(`${path}/index.json`) ?? fail(`${path}: index missing`), "base64url")]))};
  parseSource(JSON.stringify(source));
  validateArtifact(files, source);
  return source;
}

// Preserve runner source and SOURCE together. All fetch/parse/hash work finishes first. The two
// synchronous renames have rollback; an error cannot expose a partially written snapshot.
export function installSnapshot(root, files, source) {
  validateArtifact(files, source);
  const destination = join(root, "conformance"), temp = mkdtempSync(join(root, ".corpus-vendor-"));
  const next = join(temp, "next"), previous = join(temp, "previous");
  let moved = false;
  try {
    if (existsSync(destination)) cpSync(destination, next, {recursive: true}); else mkdirSync(next);
    rmSync(join(next, "priv"), {recursive: true, force: true});
    for (const [path, bytes] of files) {
      if (!safePath(path)) fail(`unsafe snapshot path ${path}`);
      const target = join(next, "priv/conformance", path);
      mkdirSync(dirname(target), {recursive: true}); writeFileSync(target, bytes);
    }
    writeFileSync(join(next, "SOURCE"), JSON.stringify(source, null, 2) + "\n");
    validateArtifact(treeFiles(join(next, "priv/conformance")), parseSource(readFileSync(join(next, "SOURCE"))));
    if (existsSync(destination)) { renameSync(destination, previous); moved = true; }
    try { renameSync(next, destination); } catch (error) { if (moved) renameSync(previous, destination); throw error; }
  } finally { rmSync(temp, {recursive: true, force: true}); }
}

export async function vendor(root, version, candidate, pinnedChecksum) {
  let files, source;
  if (candidate !== undefined) {
    if (!/^[a-f0-9]{40}$/.test(candidate)) fail("candidate must be a full lowercase monorepo commit SHA");
    const prefix = `${PACKAGE}-${candidate}/priv/conformance/`;
    const archive = readTar(gunzipSync(await fetchBytes(`https://codeload.github.com/baselabs/${PACKAGE}/tar.gz/${candidate}`), {maxOutputLength: 64 * 1024 * 1024}), prefix);
    files = new Map([...archive].filter(([p]) => p.startsWith(prefix)).map(([p, b]) => [p.slice(prefix.length), b]));
    source = sourceFor(files, {candidate});
  } else {
    const artifact = await releaseArtifact(version, pinnedChecksum);
    files = artifact.files; source = sourceFor(files, {version, checksum: artifact.release.checksum});
    const current = join(root, "conformance/SOURCE");
    if (existsSync(current)) {
      const old = parseSource(readFileSync(current));
      if (old.version === version && old.checksum !== source.checksum) fail("Hex checksum changed for pinned version; owner investigation required");
    }
  }
  installSnapshot(root, files, source);
  rewriteCorpusSummary(root, files, source);
  return source;
}

export function compareSnapshot(root, files, source) {
  const actual = treeFiles(join(root, "conformance/priv/conformance"));
  validateArtifact(actual, source); validateArtifact(files, source);
  if (!same([...actual.keys()].sort(), [...files.keys()].sort())) fail("snapshot file set differs from Hex release (both directions)");
  for (const [path, bytes] of actual) if (!bytes.equals(files.get(path))) fail(`${path}: snapshot bytes differ from Hex release`);
}
