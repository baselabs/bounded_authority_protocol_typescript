// Runtime-neutral snapshot integrity and execution contract, used by every conformance core.
import catalogue from "./catalogue.json" with { type: "json" };
import { CoreAbort, type CorpusSource, type VerdictEntry } from "./core/types.js";
import { hash64, hashHex, jcs, verdictDigest } from "./digest.js";

export const SNAPSHOT = "priv/conformance";
const paths = Object.values(catalogue).sort();
const stop = (message: string): never => { throw new CoreAbort("corpus certification", message); };
const json = (source: CorpusSource, path: string): Record<string, unknown> => JSON.parse(new TextDecoder("utf-8", {fatal: true}).decode(source.read(path))) as Record<string, unknown>;
const safe = (path: string) => path.length > 0 && !path.includes("\\") && path.split("/").every(p => p !== "" && p !== "." && p !== "..");
export const corpusDir = (name: keyof typeof catalogue): string => `${SNAPSHOT}/${catalogue[name]}`;
export interface CertifiedCase { id: string; file: string; value: unknown; data: Record<string, unknown> }
export interface Certification { cases: CertifiedCase[]; indexSha: string; path: string }

export function sourcePins(source: CorpusSource): Record<string, string> {
  const pin = json(source, "SOURCE"), candidate = Object.hasOwn(pin, "candidate");
  const keys = ["format", "package", "version", "checksum", "tree_sha256", "indexes", ...(candidate ? ["candidate"] : [])].sort();
  if (jcs(Object.keys(pin).sort()) !== jcs(keys) || pin.format !== "bap-corpus-source/1" || pin.package !== "bounded_authority_protocol") stop("SOURCE: closed format or package mismatch");
  if (candidate ? typeof pin.candidate !== "string" || !/^[a-f0-9]{40}$/.test(pin.candidate) || pin.version !== null || pin.checksum !== null
    : typeof pin.version !== "string" || !/^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$/.test(pin.version) || typeof pin.checksum !== "string" || !/^[a-f0-9]{64}$/.test(pin.checksum)) stop("SOURCE: invalid release or candidate");
  const indexes = pin.indexes as Record<string, string>;
  if (!indexes || jcs(Object.keys(indexes).sort()) !== jcs(paths) || Object.values(indexes).some(v => typeof v !== "string" || !/^[A-Za-z0-9_-]{43}$/.test(v))) stop("SOURCE: exactly nine index pins required");
  if (typeof pin.tree_sha256 !== "string" || !/^[a-f0-9]{64}$/.test(pin.tree_sha256)) stop("SOURCE: invalid tree_sha256");
  return indexes;
}

// Only profile-declared outcome members are selected. Inputs and modifiers never enter a digest.
export function expectedOutcome(path: string, file: string, c: Record<string, unknown>): unknown {
  if (Object.hasOwn(c, "expected")) {
    jcs(c.expected); return c.expected;
  }
  let members: string[];
  if (path === catalogue["local-loopback-http"] && file === "profile.json") {
    members = c.valid === true ? ["valid", "normalized"] : ["valid"];
    if (typeof c.valid !== "boolean" || (c.valid === false && Object.hasOwn(c, "normalized"))) stop(`${c.id}: invalid URI outcome schema`);
  } else if ((path === catalogue["local-loopback-http"] && file === "proof-cases.json") || (path === catalogue["strict-ed25519"] && c.surface === "local_loopback_http")) {
    members = ["decode_local", "decode_standard", "envelope_local"];
    if (members.some(k => typeof c[k] !== "boolean")) stop(`${c.id}: invalid loopback outcome schema`);
  } else if ((path === catalogue["role-attestation"] && file === "attestation-cases.json") || (path === catalogue["strict-ed25519"] && c.surface === "role_attestation")) {
    members = ["decode", "verify"];
    if (members.some(k => typeof c[k] !== "boolean")) stop(`${c.id}: invalid attestation outcome schema`);
  } else return stop(`${c.id}: no expected or declared outcome schema`);
  const result = Object.fromEntries(members.map(k => [k, c[k]]));
  jcs(result); return result;
}

export function snapshotDigest(source: CorpusSource): string {
  const files = source.list(SNAPSHOT).sort();
  if (files.some(p => !safe(p)) || new Set(files).size !== files.length) stop("snapshot: unsafe or duplicate path");
  return hashHex(new TextEncoder().encode(jcs(files.map(path => [path, hashHex(source.read(`${SNAPSHOT}/${path}`))]))));
}
export function assertSnapshot(source: CorpusSource): void {
  sourcePins(source);
  if (snapshotDigest(source) !== json(source, "SOURCE").tree_sha256) stop("snapshot tree SHA-256 differs from SOURCE");
}

export function certifyCorpus(source: CorpusSource, dir: string): Certification {
  try {
    const path = dir.slice(SNAPSHOT.length + 1), pins = sourcePins(source);
    if (!paths.includes(path)) stop(`unknown corpus ${path}`);
    const indexSha = hash64(source.read(`${dir}/index.json`));
    if (pins[path] !== indexSha) stop(`${path}/index.json: SOURCE pin mismatch`);
    const index = json(source, `${dir}/index.json`);
    const files = index.files as {path: string; cases?: number; sha256?: string; sha256_base64url?: string}[];
    if (!Array.isArray(files) || files.length === 0) stop(`${path}: no indexed files`);
    const declared = ["index.json", ...files.map(f => f.path)];
    if (declared.some(p => typeof p !== "string" || !safe(p)) || new Set(declared).size !== declared.length) stop(`${path}: duplicate or unsafe indexed path`);
    if (jcs(source.list(dir).sort()) !== jcs([...declared].sort())) stop(`${path}: actual file set differs from index (extra or missing file)`);
    const cases: CertifiedCase[] = [], ids = new Set<string>(), byFile = new Map<string, number>();
    for (const f of files) {
      const bytes = source.read(`${dir}/${f.path}`), major = Object.hasOwn(f, "sha256_base64url");
      if ((major ? hash64(bytes) : hashHex(bytes)) !== (major ? f.sha256_base64url : f.sha256)) stop(`${path}/${f.path}: recorded digest mismatch`);
      let records: Record<string, unknown>[] = [];
      if (f.path.endsWith(".json")) {
        const doc = JSON.parse(new TextDecoder("utf-8", {fatal: true}).decode(bytes)) as unknown;
        if (Array.isArray(doc)) records = doc as Record<string, unknown>[];
        else if (doc && typeof doc === "object") {
          const object = doc as Record<string, unknown>;
          if (Object.hasOwn(object, "cases")) { if (!Array.isArray(object.cases)) stop(`${f.path}: invalid cases`); records = object.cases as Record<string, unknown>[]; }
          else if (path === catalogue["local-loopback-http"] && f.path === "profile.json") { if (!Array.isArray(object.uri_cases)) stop("URI cases missing"); records = object.uri_cases as Record<string, unknown>[]; }
        }
      }
      for (const c of records) {
        const id = c.id;
        if (typeof id !== "string" || id.length === 0 || ids.has(id)) return stop(`${path}: duplicate or invalid case id ${String(id)}`);
        ids.add(id); cases.push({id, file: f.path, value: expectedOutcome(path, f.path, c), data: c});
      }
      byFile.set(f.path, records.length);
      if (f.cases !== undefined && (!Number.isSafeInteger(f.cases) || records.length !== f.cases)) stop(`${f.path}: per-file case count mismatch`);
    }
    const total = index.total_cases ?? (path === catalogue["local-loopback-http"] ? Number(index.proof_cases) + Number(index.uri_cases)
      : path === catalogue["role-attestation"] ? index.attestation_cases : Number(index.assertion_cases) + Number(index.digest_cases) + Number(index.successor_cases));
    if (!Number.isSafeInteger(total) || cases.length !== total) stop(`${path}: total case count mismatch`);
    const checkCount = (key: string, names: string[]) => { if (names.reduce((n, f) => n + (byFile.get(f) ?? 0), 0) !== index[key]) stop(`${path}: ${key} count mismatch`); };
    if (path === catalogue["local-loopback-http"]) { checkCount("uri_cases", ["profile.json"]); checkCount("proof_cases", ["proof-cases.json"]); }
    if (path === catalogue["role-attestation"]) checkCount("attestation_cases", ["attestation-cases.json"]);
    if (path === catalogue["content-assertion"]) { checkCount("assertion_cases", ["assertion-structure-cases.json", "assertion-verification-cases.json"]); checkCount("digest_cases", ["digest-cases.json"]); checkCount("successor_cases", ["successor-cases.json"]); }
    if (index.applicability !== undefined) {
      const matrix = index.applicability as Record<string, Record<string, unknown>>;
      if (jcs(Object.keys(matrix).sort()) !== jcs([...new Set(cases.map(c => c.data.surface))].sort())) stop(`${path}: applicability is not total over surfaces`);
      const classes = Object.keys(Object.values(matrix)[0] ?? {}).sort();
      for (const [surface, row] of Object.entries(matrix)) {
        if (jcs(Object.keys(row).sort()) !== jcs(classes)) stop(`${surface}: applicability is not total over classes`);
        for (const [kind, cell] of Object.entries(row)) {
          const count = cases.filter(c => c.data.surface === surface && c.data.class === kind).length;
          if (typeof cell === "number" ? !Number.isSafeInteger(cell) || cell < 1 || count !== cell : !cell || typeof cell !== "object" || Object.keys(cell).join() !== "n_a" || typeof (cell as {n_a?: unknown}).n_a !== "string" || (cell as {n_a: string}).n_a.length === 0 || count !== 0) stop(`${surface}/${kind}: applicability mismatch`);
        }
      }
      if (cases.some(c => typeof c.data.class !== "string" || !classes.includes(c.data.class))) stop(`${path}: undeclared case class`);
    }
    assertSnapshot(source);
    return {cases, indexSha, path};
  } catch (error) { if (error instanceof CoreAbort) throw error; return stop(`${dir}: ${String(error)}`); }
}
export const expectedVerdicts = (source: CorpusSource, dir: string): VerdictEntry[] => certifyCorpus(source, dir).cases.map(c => [c.id, c.value]);

// Every unique execution resolves to its unique declaring file. Then impose index order.
export function completeVerdicts(source: CorpusSource, dir: string, executed: readonly VerdictEntry[]): VerdictEntry[] {
  const certificate = certifyCorpus(source, dir), values = new Map<string, unknown>();
  for (const [id, value] of executed) { if (values.has(id)) stop(`${certificate.path}: duplicate executed id ${id}`); values.set(id, value); }
  if (values.size !== certificate.cases.length || certificate.cases.some(c => !values.has(c.id))) stop(`${certificate.path}: executed ids differ from certified set (skip or unknown id)`);
  return certificate.cases.map(c => [c.id, values.get(c.id)]);
}
export function assertVerdictDigest(source: CorpusSource, dir: string, executed: readonly VerdictEntry[]): string {
  const certificate = certifyCorpus(source, dir), ordered = completeVerdicts(source, dir, executed);
  if (jcs(ordered) !== jcs(executed)) stop(`${certificate.path}: verdicts are not in index order`);
  const digest = verdictDigest(ordered), expected = verdictDigest(certificate.cases.map(c => [c.id, c.value]));
  if (digest !== expected) stop(`${certificate.path}: verdict digest mismatch (${digest} != ${expected})`);
  if (source.list(SNAPSHOT).includes("verdict-digests.json")) {
    const doc = json(source, `${SNAPSHOT}/verdict-digests.json`), corpora = doc.corpora as Record<string, unknown>;
    if (doc.format !== "bap-corpus-verdict-digests/1" || jcs(Object.keys(doc).sort()) !== jcs(["corpora", "format"]) || !corpora || jcs(Object.keys(corpora).sort()) !== jcs(paths)) stop("published verdict-digests.json: invalid format or corpus inventory");
    const pin = {index_sha256_base64url: certificate.indexSha, case_count: certificate.cases.length, verdict_digest_sha256_base64url: digest};
    if (jcs(corpora[certificate.path]) !== jcs(pin)) stop(`${certificate.path}: published verdict digest mismatch`);
  }
  return digest;
}
