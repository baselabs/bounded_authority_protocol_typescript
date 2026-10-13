// Conformance runner for the strict-Ed25519 corpus (rule S1, bap-strict-ed25519/1) of
// @bounded-authority-protocol/verifier. Loads the vendored byte-identical snapshot
// (conformance/corpus-strict-ed25519), recomputes EVERY verdict from scratch by calling the SDK
// (the strict helpers, the contract-major v1 and v2 façades, the loopback, role-attestation and
// content-assertion surfaces, the JWK and JCS primitives), and asserts agreement on all cases.
//
// The corpus index.json SHA-256 is pinned below and asserted at startup; the exact file set is
// required; every file's recorded SHA-256 is verified; the per-family counts are checked against the
// index BEFORE any case is trusted. The corpus is additive: the existing v1, v2, v3, loopback,
// role-attestation and content-assertion corpora keep their own runners and pins unchanged.
//
// Derivation: the verdicts in the corpus come from pure BigInt arithmetic (strict RFC 8032 decode,
// [8]P = O, the cofactorless equation) in the corpus generator, with no backend and no blocklist; this
// runner only consumes them. A verdict that disagrees aborts nonzero with the case id.
import { sha256 as nobleSha256 } from "@noble/hashes/sha2.js";
import { CoreAbort, type Core, type CorpusSource, type VerdictEntry } from "./types.js";

import * as v1 from "../../src/v1.js";
import * as v2 from "../../src/v2.js";
import * as ra from "../../src/role_attestation.js";
import * as ca from "../../src/content_assertion.js";
import { acceptablePublicKey, torsionFree, verifyStrict } from "../../src/ed25519.js";
import { base64urlDecode, base64urlEncode } from "../../src/base64url.js";
import { jcsEncode } from "../../src/jcs.js";
import { jsonDecode, strUtf8, utf8Str, type Tagged } from "../../src/json.js";
import { jwkDecodePublic, jwkEncodePublic, publicKeyThumbprintRaw, thumbprint, thumbprintPreimage, thumbprintRaw, type OkpPublic } from "../../src/jwk.js";
import { MAXIMUM_BOUNDS } from "../../src/bounds.js";
import { InvalidError } from "../../src/error.js";

const utf8 = (b: Uint8Array) => utf8Str(b);
const b64d = (s: string): Uint8Array => base64urlDecode(strUtf8(s));
const b64e = (b: Uint8Array): string => utf8(base64urlEncode(b));
// The corpus integrity hash is @noble/hashes, independent of the package backend under test.
const sha256Hex = (b: Uint8Array) => Array.from(nobleSha256(b), (x) => x.toString(16).padStart(2, "0")).join("");

// Vendored snapshot beside this runner (ADR 0014 D4 binding, ADR 0015 D3 graduation discipline).
const DIR = "corpus-strict-ed25519";

// The certified index.json SHA-256 (hex). Pinned here and in test/strict-ed25519-corpus.test.ts; rotate
// every pin in the same change as any corpus revision.
const CERTIFIED_INDEX_SHA256 = "732117dfe1881b553998126a9524a95bfb1171257e388d5430a0a099f2287cb9";
const PROFILE_IDENTITY = "bap-strict-ed25519/1";
const CERTIFIED_REVISION = 1;
const CERTIFIED_CASES = 2410;

function abort(message: string): never {
  throw new CoreAbort("strict-ed25519 conformance", message);
}

// ---- verdict algebra ----

const INVALID = Symbol("invalid");
type Verdict = Record<string, unknown> | typeof INVALID;

// Only a genuine protocol rejection maps to INVALID; a thrown non-InvalidError is a runner/SDK bug and
// aborts (the InvalidError whitelist discipline, ADR 0014 Decision 6).
function runThunk<T>(fn: () => T): T | typeof INVALID {
  try {
    return fn();
  } catch (e) {
    if (e instanceof InvalidError) return INVALID;
    throw e;
  }
}

function fail(msg: string): never {
  throw new InvalidError(msg);
}

// ---- corpus loading ----

type Json = Record<string, unknown>;
interface CorpusCase extends Json {
  readonly id: string;
  readonly surface: string;
  readonly rule: string;
}
interface Loaded {
  readonly index: { families: Record<string, number>; files: Array<{ path: string; cases?: number; sha256: string }>; total_cases: number };
  readonly cases: Array<{ family: string; file: string; c: CorpusCase }>;
}

function loadCorpus(source: CorpusSource): Loaded {
  const indexBytes = source.read(`${DIR}/index.json`);
  const indexSha = sha256Hex(indexBytes);
  if (indexSha !== CERTIFIED_INDEX_SHA256) {
    abort(`index.json SHA-256 mismatch: got ${indexSha}, certified ${CERTIFIED_INDEX_SHA256}`);
  }
  const index = JSON.parse(utf8(indexBytes)) as Loaded["index"] & { profile: string; revision: number; private_material_tracked: boolean };
  if (index.profile !== PROFILE_IDENTITY) abort(`profile identity: ${index.profile}`);
  if (index.revision !== CERTIFIED_REVISION) abort(`revision: ${index.revision}`);
  if (index.total_cases !== CERTIFIED_CASES) abort(`total_cases: ${index.total_cases}`);
  if (index.private_material_tracked !== false) abort("private_material_tracked must be false");
  // The exact file set: every file on disk is listed (or is index.json itself), and every listed file exists.
  const listed = index.files.map((f) => f.path).sort();
  const onDisk = source.list(DIR).filter((p) => p !== "index.json").sort();
  if (JSON.stringify(listed) !== JSON.stringify(onDisk)) abort("exact corpus file set required (unlisted or missing file)");
  const cases: Loaded["cases"] = [];
  for (const entry of index.files) {
    const bytes = source.read(`${DIR}/${entry.path}`);
    const digest = sha256Hex(bytes);
    if (digest !== entry.sha256) abort(`${entry.path}: SHA-256 mismatch (${digest} != ${entry.sha256})`);
    if (!entry.path.startsWith("cases/")) continue; // profile.json, revision.json: identity checked by digest
    const file = JSON.parse(utf8(bytes)) as { family: string; cases: CorpusCase[] };
    if (file.cases.length !== entry.cases) abort(`${entry.path}: ${file.cases.length} cases, index declares ${entry.cases}`);
    for (const c of file.cases) cases.push({ family: file.family, file: entry.path, c });
  }
  if (cases.length !== index.total_cases) abort(`loaded ${cases.length} cases, index declares ${index.total_cases}`);
  const perFamily: Record<string, number> = {};
  for (const { family } of cases) perFamily[family] = (perFamily[family] ?? 0) + 1;
  if (JSON.stringify(Object.entries(perFamily).sort()) !== JSON.stringify(Object.entries(index.families).sort())) {
    abort("per-family case counts disagree with the index");
  }
  const ids = new Set(cases.map(({ c }) => c.id));
  if (ids.size !== cases.length) abort("duplicate case id");
  return { index, cases };
}

// ---- input helpers ----

function str(o: Json, key: string, ctx: string): string {
  const v = o[key];
  if (typeof v !== "string") fail(`${ctx}: missing ${key}`);
  return v;
}
function int(o: Json, key: string, ctx: string): number {
  const v = o[key];
  if (typeof v !== "number" || !Number.isSafeInteger(v)) fail(`${ctx}: integer ${key}`);
  return v;
}
function bin(o: Json, key: string, ctx: string): Uint8Array {
  return b64d(str(o, key, ctx));
}
function obj(o: Json, key: string): Json {
  return (o[key] ?? {}) as Json;
}
function binList(o: Json, key: string, ctx: string): Uint8Array[] {
  const list = o[key];
  if (!Array.isArray(list)) fail(`${ctx}: list ${key}`);
  return list.map((item, i) => {
    if (typeof item !== "string") fail(`${ctx}: ${key}[${i}]`);
    return b64d(item);
  });
}
function inputBytes(input: Json, ctx: string): Uint8Array {
  if (typeof input.text === "string") return strUtf8(input.text);
  if (typeof input.base64url === "string") return b64d(input.base64url);
  return fail(`${ctx}: no input bytes`);
}

// Convert plain JS (from JSON.parse) to the tagged algebra, preserving the int/float distinction.
function jsToTagged(value: unknown): Tagged {
  if (value === null) return { t: "null" };
  if (typeof value === "boolean") return { t: "bool", v: value };
  if (typeof value === "string") return { t: "string", v: strUtf8(value) };
  if (typeof value === "number") return Number.isInteger(value) ? { t: "int", v: value } : { t: "float", v: value };
  if (Array.isArray(value)) return { t: "array", v: value.map(jsToTagged) };
  if (typeof value === "object") {
    const m = new Map<string, Tagged>();
    for (const [k, v] of Object.entries(value as Json)) m.set(k, jsToTagged(v));
    return { t: "object", v: m };
  }
  return fail("jsToTagged: unsupported value");
}

// The inverse of jsToTagged, for comparing a decoded value against the case's expected JSON. Strings
// decode through the SDK's own utf8Str, so a leading U+FEFF survives exactly as the SDK keeps it.
function taggedToJs(value: Tagged): unknown {
  switch (value.t) {
    case "null": return null;
    case "bool": case "int": case "float": return value.v;
    case "string": return utf8Str(value.v);
    case "array": return value.v.map(taggedToJs);
    case "object": {
      const out: Record<string, unknown> = Object.create(null) as Record<string, unknown>;
      for (const [k, v] of value.v) out[k] = taggedToJs(v);
      return out;
    }
  }
}

// Structural equality over JSON values (member order ignored, int and float compared by value).
function sameJson(a: unknown, b: unknown): boolean {
  if (a === null || b === null || typeof a !== "object" || typeof b !== "object") return a === b;
  if (Array.isArray(a) !== Array.isArray(b)) return false;
  const ka = Object.keys(a as object).sort(), kb = Object.keys(b as object).sort();
  if (ka.length !== kb.length || ka.some((k, i) => k !== kb[i])) return false;
  return ka.every((k) => sameJson((a as Record<string, unknown>)[k], (b as Record<string, unknown>)[k]));
}

// ---- surface dispatch: call the SDK, project the result into the expected-field shape ----

// v1 and v2 expose the same façade names and shapes; the case's `major` selects the module.
const major = (c: Json): typeof v1 => (c.major === 2 ? v2 : v1) as unknown as typeof v1;

type Handler = (c: CorpusCase) => Verdict;

const ok = (v: unknown, project: () => Json = () => ({})): Verdict => {
  const r = v as { ok: boolean };
  return r.ok ? project() : INVALID;
};
const valid = (b: boolean): Verdict => (b ? {} : INVALID);

function historicalKey(k: Json, ctx: string): v1.HistoricalPublicKey {
  return {
    keyId: str(k, "key_id", ctx), publicKey: bin(k, "public_key", ctx), validFrom: int(k, "valid_from", ctx),
    validBefore: k.valid_before === undefined || k.valid_before === null ? null : (k.valid_before as number),
  };
}
function expectedAnchor(e: Json, ctx: string): v1.ExpectedAnchor {
  return {
    anchorId: str(e, "anchor_id", ctx), anchoredAt: int(e, "anchored_at", ctx), chainId: str(e, "chain_id", ctx),
    sequence: int(e, "sequence", ctx), chainHash: bin(e, "chain_hash", ctx), keyId: str(e, "key_id", ctx),
    keyFingerprint: bin(e, "key_fingerprint", ctx),
  };
}
function expectedTransition(e: Json, ctx: string): v1.ExpectedKeyTransition {
  return {
    transitionId: str(e, "transition_id", ctx), chainId: str(e, "chain_id", ctx), effectiveAt: int(e, "effective_at", ctx),
    currentKeyId: str(e, "current_key_id", ctx), currentKeyFingerprint: bin(e, "current_key_fingerprint", ctx),
    nextKeyId: str(e, "next_key_id", ctx), nextKeyFingerprint: bin(e, "next_key_fingerprint", ctx),
  };
}
function expectedExport(input: Json): v1.ExpectedExport {
  const e = obj(input, "expected");
  const chain = obj(e, "chain");
  return {
    chain: {
      chainId: str(chain, "chain_id", "export chain"), firstSequence: int(chain, "first_sequence", "export chain"),
      lastSequence: int(chain, "last_sequence", "export chain"), rowCount: int(chain, "row_count", "export chain"),
      previousHash: bin(chain, "previous_hash", "export chain"), lastHash: bin(chain, "last_hash", "export chain"),
    },
    digest: bin(e, "digest", "export"),
    startAnchor: expectedAnchor(obj(e, "start_anchor"), "export start_anchor"),
    endAnchor: expectedAnchor(obj(e, "end_anchor"), "export end_anchor"),
    transitions: ((e.transitions ?? []) as Json[]).map((t) => expectedTransition(t, "export transition")),
    objectVersion: str(e, "object_version", "export"),
  };
}
function expectedRequest(e: Json, ctx: string): v1.ExpectedRequest {
  const trusted = obj(e, "trusted_issuer");
  let nonce: v1.ExpectedRequest["nonce"];
  if (e.nonce === undefined || e.nonce === null) nonce = { kind: "not_required" };
  else if (typeof e.nonce === "object" && typeof (e.nonce as Json).required === "string") {
    nonce = { kind: "required", value: (e.nonce as Json).required as string };
  } else fail(`${ctx}: expected nonce shape`);
  return {
    trustedIssuer: { keyId: str(trusted, "key_id", ctx), publicKey: bin(trusted, "public_key", ctx) },
    issuer: str(e, "issuer", ctx), audience: str(e, "audience", ctx), method: str(e, "method", ctx),
    targetUri: str(e, "target_uri", ctx), invocationId: str(e, "invocation_id", ctx), operation: str(e, "operation", ctx),
    castArguments: jsToTagged(e.cast_arguments ?? fail(`${ctx}: cast_arguments`)),
    evaluationTime: int(e, "evaluation_time", ctx), clockSkew: int(e, "clock_skew", ctx),
    proofMaxAge: int(e, "proof_max_age", ctx), nonce,
  };
}

// A public OKP JWK exactly as the case spells it (closed three members); key acceptance is the SDK's.
function exactPublicJwk(value: Tagged): OkpPublic {
  if (value.t !== "object" || value.v.size !== 3) fail("jwk: closed members");
  const crv = value.v.get("crv"), kty = value.v.get("kty"), x = value.v.get("x");
  if (!crv || crv.t !== "string" || utf8(crv.v) !== "Ed25519") fail("jwk: crv");
  if (!kty || kty.t !== "string" || utf8(kty.v) !== "OKP") fail("jwk: kty");
  if (!x || x.t !== "string") fail("jwk: x");
  return { crv: "Ed25519", kty: "OKP", x: utf8(x.v) };
}

const HANDLERS: Record<string, Handler> = {
  // ---- primitives ----
  "ed25519.verify_strict": (c) => {
    const i = obj(c, "input");
    return valid(verifyStrict(bin(i, "message", c.id), bin(i, "signature", c.id), bin(i, "public_key", c.id)));
  },
  "ed25519.acceptable_public_key": (c) => valid(acceptablePublicKey(bin(obj(c, "input"), "public_key", c.id))),
  "ed25519.torsion_free": (c) => valid(torsionFree(bin(obj(c, "input"), "public_key", c.id))),

  // ---- JWK (fallible set) ----
  "jwk.encode_public": (c) => {
    const raw = bin(obj(c, "input"), "public_key", c.id);
    const r = runThunk(() => jwkEncodePublic(raw));
    return r === INVALID ? INVALID : { encoded: utf8(r) };
  },
  "jwk.decode_public": (c) => {
    const bytes = inputBytes(obj(c, "input"), c.id);
    const r = runThunk(() => jwkDecodePublic(bytes));
    if (r === INVALID || !r.ok) return INVALID;
    return { public_key: b64e(r.value) };
  },
  "jwk.thumbprint_preimage": (c) => {
    const bytes = inputBytes(obj(c, "input"), c.id);
    const r = runThunk(() => thumbprintPreimage(exactPublicJwk(jsonDecode(bytes))));
    return r === INVALID ? INVALID : { preimage: utf8(r) };
  },
  "jwk.thumbprint": (c) => {
    const bytes = inputBytes(obj(c, "input"), c.id);
    const r = runThunk(() => thumbprint(exactPublicJwk(jsonDecode(bytes))));
    return r === INVALID ? INVALID : { thumbprint: r };
  },
  "jwk.thumbprint_raw": (c) => {
    const bytes = inputBytes(obj(c, "input"), c.id);
    const r = runThunk(() => thumbprintRaw(exactPublicJwk(jsonDecode(bytes))));
    return r === INVALID ? INVALID : {};
  },
  "jwk.public_key_thumbprint_raw": (c) => {
    const raw = bin(obj(c, "input"), "public_key", c.id);
    return runThunk(() => publicKeyThumbprintRaw(raw)) === INVALID ? INVALID : {};
  },

  // ---- JCS / JSON / request digest ----
  "jcs.encode": (c) => {
    const bytes = inputBytes(obj(c, "input"), c.id);
    const r = runThunk(() => jcsEncode(jsonDecode(bytes)));
    return r === INVALID ? INVALID : { encoded: utf8(r) };
  },
  "json.decode": (c) => {
    const bytes = inputBytes(obj(c, "input"), c.id);
    const r = runThunk(() => jsonDecode(bytes));
    return r === INVALID ? INVALID : { value: taggedToJs(r) };
  },
  "request_digest": (c) => {
    const i = obj(c, "input");
    const r = runThunk(() => major(c).requestDigest(str(i, "operation", c.id), jsToTagged(i.cast_arguments ?? fail("cast_arguments"))));
    if (r === INVALID || !r.ok) return INVALID;
    return { digest: b64e(r.value) };
  },

  // ---- contract-major verification surfaces (v1 and v2) ----
  "verify_grant": (c) => {
    const i = obj(c, "input");
    const r = runThunk(() => major(c).verifyGrant(
      strUtf8(str(i, "compact", c.id)),
      { keyId: str(i, "key_id", c.id), publicKey: bin(i, "public_key", c.id) },
      { issuer: str(i, "issuer", c.id), audience: str(i, "audience", c.id), evaluationTime: int(i, "evaluation_time", c.id), clockSkew: int(i, "clock_skew", c.id) },
    ));
    if (r === INVALID || !r.ok) return INVALID;
    return { grant_id: r.value.grantId, issuer: r.value.issuer };
  },
  "verify_historical_anchor": (c) => {
    const i = obj(c, "input");
    const r = runThunk(() => major(c).verifyHistoricalAnchor(
      strUtf8(str(i, "compact", c.id)), historicalKey(obj(i, "key"), c.id), expectedAnchor(obj(i, "expected"), c.id)));
    return r === INVALID || !r.ok ? INVALID : c.major === 2 ? { anchor_id: (r.value as { anchorId: string }).anchorId } : {};
  },
  "verify_key_transition": (c) => {
    const i = obj(c, "input");
    const r = runThunk(() => major(c).verifyKeyTransition(
      strUtf8(str(i, "compact", c.id)), historicalKey(obj(i, "current_key"), c.id), historicalKey(obj(i, "next_key"), c.id),
      expectedTransition(obj(i, "expected"), c.id)));
    return r === INVALID || !r.ok ? INVALID : c.major === 2 ? { transition_id: (r.value as { transitionId: string }).transitionId } : {};
  },
  "check_envelope": (c) => {
    const i = obj(c, "input");
    const r = runThunk(() => major(c).checkEnvelope(
      strUtf8(str(i, "grant", c.id)), strUtf8(str(i, "proof", c.id)), expectedRequest(obj(i, "expected"), c.id)));
    return r === INVALID ? INVALID : ok(r);
  },
  "verify_anchored_export": (c) => {
    const i = obj(c, "input");
    const keys = ((i.keys ?? []) as Json[]).map((k, n) => historicalKey(k, `${c.id} key ${n}`));
    const r = runThunk(() => major(c).verifyAnchoredExport(
      { chunks: binList(i, "chunks", c.id), version: str(i, "version", c.id) }, { keys }, expectedExport(i)));
    return r === INVALID || !r.ok ? INVALID : c.major === 2 ? { chain_id: (r.value as { chainId: string }).chainId } : {};
  },
};

// ---- sibling profiles: the loopback proof, role attestation, content assertion ----
// These carry their own flag sets instead of a single verdict, so they are checked by dedicated
// functions that compare every flag. Each returns an error string or null.

function checkLoopback(c: CorpusCase): [string, string | null] {
  const issuer = obj(c, "issuer");
  const request = obj(c, "request");
  const compact = strUtf8(str(c, "compact", c.id));
  const expected: v1.ExpectedRequest = {
    trustedIssuer: { keyId: str(issuer, "key_id", c.id), publicKey: bin(issuer, "public_key", c.id) },
    issuer: str(issuer, "issuer", c.id), audience: str(issuer, "audience", c.id), method: str(request, "method", c.id),
    targetUri: str(c, "target_uri", c.id), invocationId: str(request, "invocation_id", c.id),
    operation: str(request, "operation", c.id), castArguments: jsToTagged(request.cast_arguments),
    evaluationTime: int(request, "evaluation_time", c.id), clockSkew: int(request, "clock_skew", c.id),
    proofMaxAge: int(request, "proof_max_age", c.id), nonce: { kind: "required", value: str(c, "nonce", c.id) },
  };
  const decodeLocal = v1.decodeLocalLoopbackHttpProof(compact).ok;
  const decodeStandard = v1.decodeProof(compact).ok;
  const envelopeLocal = v1.checkLocalLoopbackHttpEnvelope(strUtf8(str(c, "grant", c.id)), compact, expected).ok;
  const projection = `decode_local=${decodeLocal};decode_standard=${decodeStandard};envelope_local=${envelopeLocal}`;
  if (decodeLocal !== c.decode_local) return [projection, `decode_local: expected ${String(c.decode_local)}, got ${decodeLocal}`];
  if (decodeStandard !== c.decode_standard) return [projection, `decode_standard: expected ${String(c.decode_standard)}, got ${decodeStandard}`];
  if (envelopeLocal !== c.envelope_local) return [projection, `envelope_local: expected ${String(c.envelope_local)}, got ${envelopeLocal}`];
  return [projection, null];
}

function checkRoleAttestation(c: CorpusCase): [string, string | null] {
  const attestor = obj(c, "attestor");
  const subject = obj(c, "subject");
  const compact = strUtf8(str(c, "compact", c.id));
  const expected: ra.ExpectedAttestation = {
    attestor: {
      keyId: str(attestor, "key_id", c.id), publicKey: bin(attestor, "public_key", c.id),
      validFrom: int(attestor, "valid_from", c.id), validBefore: int(attestor, "valid_before", c.id),
    },
    subjectKeyId: str(subject, "key_id", c.id), subjectPublicKey: bin(subject, "public_key", c.id), now: int(c, "now", c.id),
  };
  const decoded = runThunk(() => ra.decodeAttestation(compact));
  const verified = runThunk(() => ra.verifyAttestation(compact, expected));
  const d = decoded !== INVALID && decoded.ok;
  const v = verified !== INVALID && verified.ok;
  const projection = `decode=${d};verify=${v}`;
  if (d !== c.decode) return [projection, `decode: expected ${String(c.decode)}, got ${d}`];
  if (v !== c.verify) return [projection, `verify: expected ${String(c.verify)}, got ${v}`];
  return [projection, null];
}

function checkContentAssertion(c: CorpusCase): [string, string | null] {
  const attestor = obj(c, "attestor");
  const ctx = obj(c, "expected_context");
  const compact = strUtf8(str(c, "compact", c.id));
  const expected: ca.ExpectedContentAssertion = {
    attestor: {
      keyId: str(attestor, "key_id", c.id), publicKey: bin(attestor, "public_key", c.id),
      validFrom: int(attestor, "valid_from", c.id), validBefore: attestor.valid_before === null ? null : int(attestor, "valid_before", c.id),
    },
    issuer: str(ctx, "issuer", c.id), audience: str(ctx, "audience", c.id), subject: str(ctx, "subject", c.id),
    profile: str(ctx, "profile", c.id), profileDigest: bin(ctx, "profile_digest", c.id),
    contentDigest: bin(ctx, "content_digest", c.id), now: int(ctx, "now", c.id), bounds: MAXIMUM_BOUNDS,
  };
  const decoded = runThunk(() => ca.decodeAssertion(compact, MAXIMUM_BOUNDS));
  const verified = runThunk(() => ca.verifyAssertion(compact, expected));
  const want = c.expected as { decode: string; verify: string };
  const d = decoded !== INVALID && decoded.ok ? "valid" : "invalid";
  const v = verified !== INVALID && verified.ok ? "valid" : "invalid";
  const projection = `decode=${d};verify=${v}`;
  if (d !== want.decode) return [projection, `decode: expected ${want.decode}, got ${d}`];
  if (v !== want.verify) return [projection, `verify: expected ${want.verify}, got ${v}`];
  return [projection, null];
}

const FLAG_SURFACES: Record<string, (c: CorpusCase) => [string, string | null]> = {
  local_loopback_http: checkLoopback,
  role_attestation: checkRoleAttestation,
  content_assertion: checkContentAssertion,
};

// ---- verdict comparison ----

function compareVerdict(c: CorpusCase, actual: Verdict): string | null {
  const expected = c.expected as Json;
  if (expected.verdict === "invalid") return actual === INVALID ? null : "expected invalid, got valid";
  if (expected.verdict !== "valid") return `unknown expected verdict ${String(expected.verdict)}`;
  if (actual === INVALID) return "expected valid, got invalid";
  for (const [key, want] of Object.entries(expected)) {
    if (key === "verdict") continue;
    const got = actual[key];
    if (got === undefined) return `valid result carries no ${key} to compare`;
    if (!sameJson(got, want)) return `${key}: expected ${JSON.stringify(want)}, got ${JSON.stringify(got)}`;
  }
  return null;
}

// Canonical JSON (sorted keys) of a computed verdict, for the cross-lane verdict digest.
function canonicalJson(v: unknown): string {
  if (v === null || typeof v !== "object") return JSON.stringify(v) ?? String(v);
  if (Array.isArray(v)) return `[${v.map(canonicalJson).join(",")}]`;
  const keys = Object.keys(v).sort();
  return `{${keys.map((k) => `${JSON.stringify(k)}:${canonicalJson((v as Record<string, unknown>)[k])}`).join(",")}}`;
}

// ---- the runtime-neutral entry ----

function runAll(source: CorpusSource): { failures: string[]; verdicts: VerdictEntry[]; summary: string[] } {
  const { index, cases } = loadCorpus(source);
  const failures: string[] = [];
  const verdicts: VerdictEntry[] = [];
  const perSurface: Record<string, number> = {};
  for (const { family, c } of cases) {
    perSurface[c.surface] = (perSurface[c.surface] ?? 0) + 1;
    const flag = FLAG_SURFACES[c.surface];
    let problem: string | null;
    let projection: string;
    if (flag) [projection, problem] = flag(c);
    else {
      const handler = HANDLERS[c.surface];
      if (!handler) abort(`${c.id}: unknown surface ${c.surface}`);
      const actual = handler(c);
      projection = actual === INVALID ? "invalid" : canonicalJson(actual);
      problem = compareVerdict(c, actual);
    }
    verdicts.push([c.id, projection]);
    if (problem !== null) failures.push(`${family} ${c.id} [${c.rule}]: ${problem}`);
  }
  const pass = cases.length - failures.length;
  return {
    failures,
    verdicts,
    summary: [
      `strict-ed25519 conformance: ${pass}/${cases.length} cases agree (profile ${PROFILE_IDENTITY}, revision ${CERTIFIED_REVISION}, index SHA-256 ${CERTIFIED_INDEX_SHA256.slice(0, 8)}…)`,
      `families: ${Object.entries(index.families).map(([k, n]) => `${k} ${n}`).join(", ")}`,
      `surfaces: ${Object.entries(perSurface).sort().map(([k, n]) => `${k} ${n}`).join(", ")}`,
      "strict-ed25519 conformance: PASS (every case agrees)",
    ],
  };
}

export const core: Core = {
  corpus: "strict-ed25519",
  dir: DIR,
  run(source: CorpusSource) {
    try {
      return { corpus: "strict-ed25519", ...runAll(source) };
    } catch (e) {
      if (e instanceof InvalidError) abort(`unexpected InvalidError escaped a Result surface: ${e.message}`);
      throw e;
    }
  },
};
