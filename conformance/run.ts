#!/usr/bin/env tsx
// Conformance runner for @bounded-authority/verifier (BAP-09 T5). Loads the published corpus from
// priv/conformance/v1/corpus/, recomputes EVERY verdict from scratch by calling the SDK façade
// (sdks/typescript/src/v1.ts), and asserts agreement on all 283 cases. Asserts the index.json
// SHA-256 at startup (ADR 0014 D4: the SDK binds to the exact corpus it was certified against).
// Runs the two-boundary key census (discovery == verify-import == index public_key_fingerprints).
//
// This is the independent conformance proof: the SDK is the implementation under test, the corpus
// is the arbiter. A disagreement aborts nonzero with the case id + the expected/actual verdict.
//
// Derivation: the corpus is the published normative artifact (BAP-05); the runner is a consumer.
// The SDK façade was derived from spec/bap-v1.md + ADR 0004 + RFCs; this runner exercises it.
import { readFileSync } from "node:fs";
import { join, resolve as pathResolve } from "node:path";
import { fileURLToPath } from "node:url";
import * as v1 from "../src/v1.js";
import { jsonDecode, strUtf8, utf8Str, type Tagged } from "../src/json.js";
import { base64urlDecode, base64urlEncode } from "../src/base64url.js";
import { jcsEncode } from "../src/jcs.js";
import { sha256, _importedFingerprints, _resetCensus } from "../src/ed25519.js";
import { thumbprintRaw, jwkFromPublicKey, jwkEncodePublic, thumbprintPreimage } from "../src/jwk.js";
import { uriNormalize } from "../src/uri.js";
import { parseSelector } from "../src/selector.js";
import { boundsNew, MAXIMA } from "../src/bounds.js";
import { InvalidError } from "../src/error.js";

const utf8 = (b: Uint8Array) => utf8Str(b);
const b64d = (s: string): Uint8Array => base64urlDecode(strUtf8(s));
const b64e = (b: Uint8Array): string => utf8(base64urlEncode(b));

// Locate the corpus: repo-relative priv/conformance/v1/corpus/ (dev mode). The runner is invoked
// from sdks/typescript/, so the repo root is two levels up.
const REPO_ROOT = pathResolve(fileURLToPath(import.meta.url), "..", "..", "..", "..");
const CORPUS_DIR = join(REPO_ROOT, "priv", "conformance", "v1", "corpus");

// The INVALID sentinel: any genuine protocol rejection maps to this; a thrown non-InvalidError is a
// runner/SDK bug and MUST abort (the InvalidError whitelist discipline, ADR 0014 Decision 6).
const INVALID = Symbol("invalid");
type Verdict = Record<string, unknown> | typeof INVALID;

function runThunk<T>(fn: () => T): T | typeof INVALID {
  try {
    return fn();
  } catch (e) {
    if (e instanceof InvalidError) return INVALID;
    throw e; // a bug — not a verdict
  }
}

// ---- corpus loading ----

interface CaseFile {
  readonly rel: string;
  readonly cases: ReadonlyArray<CorpusCase>;
}
interface CorpusCase {
  readonly id: string;
  readonly surface: string;
  readonly class: string;
  readonly expected: Record<string, unknown>;
  readonly input: Record<string, unknown>;
  readonly tamper?: Record<string, unknown>;
}
interface Raws extends Map<string, Uint8Array> {}

// The certified index.json SHA-256 (base64url of the SHA-256 digest). ADR 0014 D4: the SDK binds to
// the exact corpus it was certified against; a mismatched vendored corpus fails closed rather than
// drifting silently. Same digest as the Python and Rust runners' hex pins — rotate every pin with
// scripts/regen_corpus_digests.exs in the same change.
const CERTIFIED_INDEX_SHA = "TLUHKrQP_UsRFlnm1KsgIJICOAUF8fhCS5bSLlM8uRs";

function loadCorpus(): { index: Record<string, unknown>; cases: CorpusCase[]; raws: Raws } {
  const indexPath = join(CORPUS_DIR, "index.json");
  const indexRaw = readFileSync(indexPath);
  const index = JSON.parse(indexRaw.toString("utf8"));
  // ADR 0014 D4: assert the index.json SHA-256 matches the certified snapshot. (The SDK tracks the
  // published corpus; a mismatched vendored corpus fails closed rather than drifting silently.) In
  // dev mode the in-repo corpus IS the certified snapshot, so this asserts self-consistency.
  const indexSha = b64e(sha256(indexRaw));
  if (indexSha !== CERTIFIED_INDEX_SHA) {
    abort(`index.json SHA mismatch: got ${indexSha}, certified ${CERTIFIED_INDEX_SHA}`);
  }
  const totalCases = index.total_cases as number;
  const cases: CorpusCase[] = [];
  const raws: Raws = new Map();
  // Load every case file named in the index.
  for (const entry of index.files as Array<{
    path: string;
    cases: number;
    sha256_base64url?: string;
  }>) {
    if (entry.path.endsWith(".raw")) {
      // Raw sidecar: load bytes + verify the recorded SHA.
      const rawPath = join(CORPUS_DIR, entry.path);
      const bytes = readFileSync(rawPath);
      raws.set(entry.path, new Uint8Array(bytes));
      continue;
    }
    // The revision sidecar occupies the one reserved non-case JSON path: verify its SHA (it has
    // no agreement backstop) and its closed shape, then carry nothing — it declares zero cases.
    if (entry.path === "revision.json") {
      const bytes = readFileSync(join(CORPUS_DIR, entry.path));
      if (!entry.sha256_base64url || b64e(sha256(bytes)) !== entry.sha256_base64url) {
        abort(`revision.json: hash mismatch`);
      }
      const sidecar = JSON.parse(bytes.toString("utf8"));
      const keys = Object.keys(sidecar).sort().join(",");
      if (keys !== "format,generated_from,revision") abort("revision.json: closed member set");
      if (entry.cases !== 0) abort("revision.json: case-free declaration");
      if (sidecar.format !== "bounded-authority-protocol-v1-conformance-corpus-revision") {
        abort("revision.json: format");
      }
      if (!Number.isSafeInteger(sidecar.revision) || sidecar.revision < 1) {
        abort("revision.json: monotone integer revision");
      }
      if (
        typeof sidecar.generated_from !== "string" ||
        sidecar.generated_from.length < 1 ||
        sidecar.generated_from.length > 256
      ) {
        abort("revision.json: generated_from provenance string");
      }
      continue;
    }
    const fileText = readFileSync(join(CORPUS_DIR, entry.path), "utf8");
    const fileJson = JSON.parse(fileText) as { cases: CorpusCase[] };
    cases.push(...fileJson.cases);
  }
  if (cases.length !== totalCases) {
    abort(`corpus case count mismatch: index says ${totalCases}, loaded ${cases.length}`);
  }
  // Verify each raw sidecar's recorded SHA (mirrors the loader's raw_file integrity check).
  for (const entry of index.files as Array<{ path: string; sha256_base64url?: string }>) {
    if (!entry.path.endsWith(".raw")) continue;
    const bytes = raws.get(entry.path);
    if (!bytes || !entry.sha256_base64url) abort(`raw ${entry.path}: missing bytes or hash`);
    if (b64e(sha256(bytes)) !== entry.sha256_base64url) abort(`raw ${entry.path}: hash mismatch`);
  }
  return { index, cases, raws };
}

// ---- tamper application (mirrors corpus.ex tamper_target_bytes/2) ----
// A tamper case references a base case; the runner re-derives base-with-one-flip and the SDK must
// reject it. Target resolution: default/text/base64url + compact/grant/proof/rows[i]/chunks[i].
function applyTamper(baseInput: Record<string, unknown>, tamper: Record<string, unknown>, raws: Raws): Record<string, unknown> {
  const target = tamper.target as string | undefined;
  const xor = (tamper.xor as number) ?? 0;
  const byteIndex = tamper.byte_index as number;
  const input: Record<string, unknown> = JSON.parse(JSON.stringify(baseInput));
  const flip = (bytes: Uint8Array): Uint8Array => {
    if (byteIndex < 0 || byteIndex >= bytes.length) abort(`tamper byte_index ${byteIndex} out of range (len ${bytes.length})`);
    const out = new Uint8Array(bytes);
    out[byteIndex] = (out[byteIndex]! ^ xor) & 0xff;
    return out;
  };
  const b64flip = (encoded: string): string => b64e(flip(b64d(encoded)));
  switch (target) {
    case undefined:
    case "input.text":
      if (typeof input.text === "string") { input.text = utf8(flip(strUtf8(input.text))); return input; }
      if (typeof input.base64url === "string") { input.base64url = b64flip(input.base64url); return input; }
      break;
    case "input.base64url":
      if (typeof input.base64url === "string") { input.base64url = b64flip(input.base64url); return input; }
      break;
    case "compact":
      if (typeof input.compact === "string") { input.compact = utf8(flip(strUtf8(input.compact))); return input; }
      break;
    case "grant":
      if (typeof input.grant === "string") { input.grant = utf8(flip(strUtf8(input.grant))); return input; }
      break;
    case "proof":
      if (typeof input.proof === "string") { input.proof = utf8(flip(strUtf8(input.proof))); return input; }
      break;
    default: {
      const m = /^(rows|chunks)\[(\d+)\]$/.exec(target);
      if (m) {
        const list = input[m[1]!] as string[];
        const i = Number(m[2]);
        if (Array.isArray(list) && typeof list[i] === "string") {
          list[i] = b64flip(list[i]!);
          return input;
        }
      }
    }
  }
  abort(`unresolved tamper target ${target ?? "<default>"}`);
}

// ---- input extraction helpers (mirror the runner's fetchBinary/b64Field/intField/inputBytes) ----

function fetchBinary(input: Record<string, unknown>, key: string, ctx: string): string {
  const v = input[key];
  if (typeof v !== "string") fail(`${ctx}: missing ${key}`);
  return v;
}
function b64Field(input: Record<string, unknown>, key: string, ctx: string): Uint8Array {
  return b64d(fetchBinary(input, key, ctx));
}
function intField(input: Record<string, unknown>, key: string, ctx: string): number {
  const v = input[key];
  if (typeof v !== "number" || !Number.isSafeInteger(v)) fail(`${ctx}: integer ${key}`);
  return v;
}
function inputBytes(input: Record<string, unknown>, raws: Raws, ctx: string): Uint8Array {
  if (typeof input.text === "string") return strUtf8(input.text);
  if (typeof input.base64url === "string") return b64d(input.base64url);
  if (typeof input.raw_file === "string") {
    const b = raws.get(input.raw_file);
    if (!b) fail(`${ctx}: missing raw_file`);
    return b;
  }
  fail(`${ctx}: no input bytes`);
}
function inputPublicKey(input: Record<string, unknown>, ctx: string): Uint8Array {
  return b64d(fetchBinary(input, "public_key", ctx));
}
function byteList(input: Record<string, unknown>, key: string, ctx: string): Uint8Array[] {
  const list = input[key];
  if (!Array.isArray(list)) fail(`${ctx}: list ${key}`);
  return list.map((item, i) => {
    if (typeof item !== "string") fail(`${ctx}: ${key}[${i}]`);
    return b64d(item);
  });
}
function fail(msg: string): never { throw new InvalidError(msg); }

// ---- surface dispatch: call the SDK façade, project the result into expected-field shape ----

function dispatch(surface: string, input: Record<string, unknown>, raws: Raws): Verdict {
  switch (surface) {
    case "json.decode": return dispatchJsonDecode(input, raws);
    case "base64url.decode": return dispatchBase64UrlDecode(input);
    case "jcs.encode": return dispatchJcsEncode(input, raws);
    case "uri.normalize": return dispatchUriNormalize(input, raws);
    case "jwk.encode_public": return dispatchJwkEncodePublic(input);
    case "jwk.decode_public": return dispatchJwkDecodePublic(input, raws);
    case "jwk.thumbprint_preimage": return dispatchJwkThumbprintPreimage(input, raws);
    case "jwk.thumbprint": return dispatchJwkThumbprint(input, raws);
    case "jwk.thumbprint_raw": return dispatchJwkThumbprintRaw(input, raws);
    case "jwk.public_key_thumbprint_raw": return dispatchJwkPublicKeyThumbprintRaw(input);
    case "bounds.new": return dispatchBoundsNew(input);
    case "untrusted_key_locator": return dispatchUntrustedKeyLocator(input);
    case "grant_signing_input": return dispatchGrantSigningInput(input);
    case "proof_signing_input": return dispatchProofSigningInput(input);
    case "boundary_anchor_signing_input": return dispatchBoundaryAnchorSigningInput(input);
    case "key_transition_signing_input": return dispatchKeyTransitionSigningInput(input);
    case "assemble_compact": return dispatchAssembleCompact(input);
    case "decode_grant": return dispatchDecodeGrant(input);
    case "decode_proof": return dispatchDecodeProof(input);
    case "encode_consumption_entry": return dispatchEncodeConsumptionEntry(input);
    case "check_chain": return dispatchCheckChain(input);
    case "request_digest": return dispatchRequestDigest(input);
    case "verify_grant": return dispatchVerifyGrant(input);
    case "verify_historical_anchor": return dispatchVerifyHistoricalAnchor(input);
    case "verify_key_transition": return dispatchVerifyKeyTransition(input);
    case "check_envelope": return dispatchCheckEnvelope(input);
    case "encode_anchored_export": return dispatchEncodeAnchoredExport(input);
    case "verify_anchored_export": return dispatchVerifyAnchoredExport(input);
    default: abort(`unknown surface: ${surface}`);
  }
}

function dispatchJsonDecode(input: Record<string, unknown>, raws: Raws): Verdict {
  const bytes = inputBytes(input, raws, "json.decode");
  const value = runThunk(() => jsonDecode(bytes));
  if (value === INVALID) return INVALID;
  return { value: taggedToJs(value) };
}

function dispatchBase64UrlDecode(input: Record<string, unknown>): Verdict {
  let segment: string;
  if (typeof input.base64url === "string") segment = input.base64url;
  else segment = utf8(inputBytes(input, new Map(), "base64url.decode"));
  if (segment.length === 0) fail("base64url.decode: empty segment");
  const decoded = runThunk(() => b64d(segment));
  if (decoded === INVALID) return INVALID;
  return { decoded: utf8(decoded) };
}

function dispatchJcsEncode(input: Record<string, unknown>, raws: Raws): Verdict {
  const bytes = inputBytes(input, raws, "jcs.encode");
  const encoded = runThunk(() => jcsEncode(jsonDecode(bytes)));
  if (encoded === INVALID) return INVALID;
  return { encoded: utf8(encoded) };
}

function dispatchUriNormalize(input: Record<string, unknown>, raws: Raws): Verdict {
  const bytes = inputBytes(input, raws, "uri.normalize");
  const r = runThunk(() => uriNormalize(bytes));
  if (r === INVALID) return INVALID;
  if (!r.ok) return INVALID;
  return { normalized: utf8(r.value) };
}

function dispatchJwkEncodePublic(input: Record<string, unknown>): Verdict {
  const raw = inputPublicKey(input, "jwk.encode_public");
  const encoded = runThunk(() => jwkEncodePublic(raw));
  if (encoded === INVALID) return INVALID;
  return { encoded: utf8(encoded) };
}
function dispatchJwkDecodePublic(input: Record<string, unknown>, raws: Raws): Verdict {
  const bytes = inputBytes(input, raws, "jwk.decode_public");
  const r = runThunk(() => {
    const v = jsonDecode(bytes);
    return decodePublicJwkRaw(v);
  });
  if (r === INVALID) return INVALID;
  return { public_key: b64e(r) };
}
function dispatchJwkThumbprintPreimage(input: Record<string, unknown>, raws: Raws): Verdict {
  const bytes = inputBytes(input, raws, "jwk.thumbprint_preimage");
  const r = runThunk(() => thumbprintPreimage(exactPublicJwk(jsonDecode(bytes))));
  if (r === INVALID) return INVALID;
  return { preimage: utf8(r) };
}
function dispatchJwkThumbprint(input: Record<string, unknown>, raws: Raws): Verdict {
  const bytes = inputBytes(input, raws, "jwk.thumbprint");
  const r = runThunk(() => b64e(sha256(thumbprintPreimage(exactPublicJwk(jsonDecode(bytes))))));
  if (r === INVALID) return INVALID;
  return { thumbprint: r };
}
function dispatchJwkThumbprintRaw(input: Record<string, unknown>, raws: Raws): Verdict {
  const bytes = inputBytes(input, raws, "jwk.thumbprint_raw");
  const r = runThunk(() => sha256(thumbprintPreimage(exactPublicJwk(jsonDecode(bytes)))));
  if (r === INVALID) return INVALID;
  return { thumbprint_raw: r };
}
function dispatchJwkPublicKeyThumbprintRaw(input: Record<string, unknown>): Verdict {
  const raw = inputPublicKey(input, "jwk.public_key_thumbprint_raw");
  const r = runThunk(() => sha256(thumbprintPreimage(jwkFromPublicKey(raw))));
  if (r === INVALID) return INVALID;
  return { thumbprint_raw: r };
}

function dispatchBoundsNew(input: Record<string, unknown>): Verdict {
  const overrides = (input.overrides ?? {}) as Record<string, number>;
  const r = runThunk(() => boundsNew(overrides));
  if (r === INVALID) return INVALID;
  return { bounds: overrides };
}

function dispatchUntrustedKeyLocator(input: Record<string, unknown>): Verdict {
  const compact = strUtf8(fetchBinary(input, "compact", "untrusted_key_locator"));
  const r = runThunk(() => v1.untrustedKeyLocator(compact));
  if (r === INVALID || !r.ok) return INVALID;
  return { kid: r.value.keyId };
}

function dispatchGrantSigningInput(input: Record<string, unknown>): Verdict {
  const r = runThunk(() => v1.grantSigningInput(buildGrantProducer(input)));
  if (r === INVALID || !r.ok) return INVALID;
  return {
    protected_segment: utf8(r.value.protectedSegment),
    payload_segment: utf8(r.value.payloadSegment),
    message: `${utf8(r.value.protectedSegment)}.${utf8(r.value.payloadSegment)}`,
  };
}

function buildGrantProducer(input: Record<string, unknown>): v1.GrantProducer {
  return {
    keyId: fetchBinary(input, "key_id", "grant_signing_input"),
    issuer: fetchBinary(input, "issuer", "grant_signing_input"),
    grantId: fetchBinary(input, "grant_id", "grant_signing_input"),
    audiences: (input.audiences as string[]) ?? fail("grant_signing_input: audiences"),
    issuedAt: intField(input, "issued_at", "grant_signing_input"),
    notBefore: intField(input, "not_before", "grant_signing_input"),
    expiresAt: intField(input, "expires_at", "grant_signing_input"),
    holderThumbprint: fetchBinary(input, "holder_thumbprint", "grant_signing_input"),
    operations: (input.operations as v1.OperationInput[]) ?? fail("grant_signing_input: operations"),
  };
}

function dispatchProofSigningInput(input: Record<string, unknown>): Verdict {
  const castArguments = input.cast_arguments;
  if (castArguments === undefined) fail("proof_signing_input: cast_arguments");
  // cast_arguments arrives as plain JS; the façade consumes Tagged. Convert via JSON round-trip.
  const taggedCast = jsToTagged(castArguments);
  const producer: v1.ProofProducer = {
    holderPublicKey: b64Field(input, "holder_public_key", "proof_signing_input"),
    proofId: fetchBinary(input, "proof_id", "proof_signing_input"),
    method: fetchBinary(input, "method", "proof_signing_input"),
    targetUri: fetchBinary(input, "target_uri", "proof_signing_input"),
    issuedAt: intField(input, "issued_at", "proof_signing_input"),
    invocationId: fetchBinary(input, "invocation_id", "proof_signing_input"),
    operation: fetchBinary(input, "operation", "proof_signing_input"),
    grantCompact: strUtf8(fetchBinary(input, "grant_compact", "proof_signing_input")),
    castArguments: taggedCast,
    ...(typeof input.nonce === "string" ? { nonce: input.nonce } : {}),
  };
  const r = runThunk(() => v1.proofSigningInput(producer));
  if (r === INVALID || !r.ok) return INVALID;
  return {
    protected_segment: utf8(r.value.protectedSegment),
    payload_segment: utf8(r.value.payloadSegment),
    message: `${utf8(r.value.protectedSegment)}.${utf8(r.value.payloadSegment)}`,
  };
}

function dispatchBoundaryAnchorSigningInput(input: Record<string, unknown>): Verdict {
  const r = runThunk(() => v1.boundaryAnchorSigningInput({
    anchorId: fetchBinary(input, "anchor_id", "boundary_anchor_signing_input"),
    anchoredAt: intField(input, "anchored_at", "boundary_anchor_signing_input"),
    chainId: fetchBinary(input, "chain_id", "boundary_anchor_signing_input"),
    sequence: intField(input, "sequence", "boundary_anchor_signing_input"),
    chainHash: b64Field(input, "chain_hash", "boundary_anchor_signing_input"),
    keyId: fetchBinary(input, "key_id", "boundary_anchor_signing_input"),
    publicKey: b64Field(input, "public_key", "boundary_anchor_signing_input"),
  }));
  if (r === INVALID || !r.ok) return INVALID;
  return {
    protected_segment: utf8(r.value.protectedSegment),
    payload_segment: utf8(r.value.payloadSegment),
    message: `${utf8(r.value.protectedSegment)}.${utf8(r.value.payloadSegment)}`,
  };
}

function dispatchKeyTransitionSigningInput(input: Record<string, unknown>): Verdict {
  const r = runThunk(() => v1.keyTransitionSigningInput({
    transitionId: fetchBinary(input, "transition_id", "key_transition_signing_input"),
    chainId: fetchBinary(input, "chain_id", "key_transition_signing_input"),
    effectiveAt: intField(input, "effective_at", "key_transition_signing_input"),
    currentKeyId: fetchBinary(input, "current_key_id", "key_transition_signing_input"),
    currentPublicKey: b64Field(input, "current_public_key", "key_transition_signing_input"),
    nextKeyId: fetchBinary(input, "next_key_id", "key_transition_signing_input"),
    nextPublicKey: b64Field(input, "next_public_key", "key_transition_signing_input"),
  }));
  if (r === INVALID || !r.ok) return INVALID;
  return {
    protected_segment: utf8(r.value.protectedSegment),
    payload_segment: utf8(r.value.payloadSegment),
    message: `${utf8(r.value.protectedSegment)}.${utf8(r.value.payloadSegment)}`,
  };
}

function dispatchAssembleCompact(input: Record<string, unknown>): Verdict {
  const kind = fetchBinary(input, "kind", "assemble_compact");
  const r = runThunk(() => v1.assembleCompact(
    {
      kind: kind as v1.SigningInput["kind"],
      protectedSegment: strUtf8(fetchBinary(input, "protected_segment", "assemble_compact")),
      payloadSegment: strUtf8(fetchBinary(input, "payload_segment", "assemble_compact")),
    },
    b64Field(input, "signature", "assemble_compact"),
  ));
  if (r === INVALID || !r.ok) return INVALID;
  return { compact: utf8(r.value) };
}

function dispatchDecodeGrant(input: Record<string, unknown>): Verdict {
  const compact = strUtf8(fetchBinary(input, "compact", "decode_grant"));
  const r = runThunk(() => v1.decodeGrant(compact));
  if (r === INVALID || !r.ok) return INVALID;
  return { key_id: r.value.keyId };
}

function dispatchDecodeProof(input: Record<string, unknown>): Verdict {
  const compact = strUtf8(fetchBinary(input, "compact", "decode_proof"));
  const r = runThunk(() => v1.decodeProof(compact));
  if (r === INVALID || !r.ok) return INVALID;
  return { proof_id: r.value.proofId };
}

function dispatchEncodeConsumptionEntry(input: Record<string, unknown>): Verdict {
  const r = runThunk(() => v1.encodeConsumptionEntry({
    chainId: fetchBinary(input, "chain_id", "encode_consumption_entry"),
    sequence: intField(input, "sequence", "encode_consumption_entry"),
    previousHash: b64Field(input, "previous_hash", "encode_consumption_entry"),
    commitment: b64Field(input, "commitment", "encode_consumption_entry"),
  }));
  if (r === INVALID || !r.ok) return INVALID;
  return { bytes: utf8(r.value.bytes), hash: b64e(r.value.hash) };
}

function dispatchCheckChain(input: Record<string, unknown>): Verdict {
  const rows = byteList(input, "rows", "check_chain");
  const expected = {
    chainId: fetchBinary(input, "chain_id", "check_chain"),
    firstSequence: intField(input, "first_sequence", "check_chain"),
    lastSequence: intField(input, "last_sequence", "check_chain"),
    rowCount: intField(input, "row_count", "check_chain"),
    previousHash: b64Field(input, "previous_hash", "check_chain"),
    lastHash: b64Field(input, "last_hash", "check_chain"),
  };
  const r = runThunk(() => v1.checkChain({ rows, ...expected }, expected));
  if (r === INVALID || !r.ok) return INVALID;
  return {};
}

function dispatchRequestDigest(input: Record<string, unknown>): Verdict {
  const operation = fetchBinary(input, "operation", "request_digest");
  if (input.cast_arguments === undefined) fail("request_digest: cast_arguments");
  const castArgs = jsToTagged(input.cast_arguments);
  const r = runThunk(() => v1.requestDigest(operation, castArgs));
  if (r === INVALID || !r.ok) return INVALID;
  return { digest: b64e(r.value) };
}

function dispatchVerifyGrant(input: Record<string, unknown>): Verdict {
  const r = runThunk(() => v1.verifyGrant(
    strUtf8(fetchBinary(input, "compact", "verify_grant")),
    { keyId: fetchBinary(input, "key_id", "verify_grant"), publicKey: b64Field(input, "public_key", "verify_grant") },
    {
      issuer: fetchBinary(input, "issuer", "verify_grant"),
      audience: fetchBinary(input, "audience", "verify_grant"),
      evaluationTime: intField(input, "evaluation_time", "verify_grant"),
      clockSkew: intField(input, "clock_skew", "verify_grant"),
    },
  ));
  if (r === INVALID || !r.ok) return INVALID;
  return {
    version: r.value.version, issuer: r.value.issuer, grant_id: r.value.grantId,
    issuer_key_fingerprint: b64e(r.value.issuerKeyFingerprint),
    holder_thumbprint: b64e(r.value.holderThumbprint),
    matched_audience: r.value.matchedAudience,
    issued_at: r.value.issuedAt, not_before: r.value.notBefore, expires_at: r.value.expiresAt,
    authorization: r.value.authorization,
  };
}

function buildHistoricalKey(k: Record<string, unknown>, ctx: string): v1.HistoricalPublicKey {
  return {
    keyId: fetchBinary(k, "key_id", ctx),
    publicKey: b64Field(k, "public_key", ctx),
    validFrom: intField(k, "valid_from", ctx),
    validBefore: k.valid_before === undefined || k.valid_before === null ? null : (k.valid_before as number),
  };
}

function buildExpectedAnchor(e: Record<string, unknown>, ctx: string): v1.ExpectedAnchor {
  return {
    anchorId: fetchBinary(e, "anchor_id", ctx), anchoredAt: intField(e, "anchored_at", ctx),
    chainId: fetchBinary(e, "chain_id", ctx), sequence: intField(e, "sequence", ctx),
    chainHash: b64Field(e, "chain_hash", ctx), keyId: fetchBinary(e, "key_id", ctx),
    keyFingerprint: b64Field(e, "key_fingerprint", ctx),
  };
}
function buildExpectedTransition(e: Record<string, unknown>, ctx: string): v1.ExpectedKeyTransition {
  return {
    transitionId: fetchBinary(e, "transition_id", ctx), chainId: fetchBinary(e, "chain_id", ctx),
    effectiveAt: intField(e, "effective_at", ctx),
    currentKeyId: fetchBinary(e, "current_key_id", ctx), currentKeyFingerprint: b64Field(e, "current_key_fingerprint", ctx),
    nextKeyId: fetchBinary(e, "next_key_id", ctx), nextKeyFingerprint: b64Field(e, "next_key_fingerprint", ctx),
  };
}

function dispatchVerifyHistoricalAnchor(input: Record<string, unknown>): Verdict {
  const key = buildHistoricalKey((input.key ?? {}) as Record<string, unknown>, "verify_historical_anchor key");
  const expected = buildExpectedAnchor((input.expected ?? {}) as Record<string, unknown>, "verify_historical_anchor expected");
  const r = runThunk(() => v1.verifyHistoricalAnchor(strUtf8(fetchBinary(input, "compact", "verify_historical_anchor")), key, expected));
  if (r === INVALID || !r.ok) return INVALID;
  return {};
}

function dispatchVerifyKeyTransition(input: Record<string, unknown>): Verdict {
  const currentKey = buildHistoricalKey((input.current_key ?? {}) as Record<string, unknown>, "verify_key_transition current");
  const nextKey = buildHistoricalKey((input.next_key ?? {}) as Record<string, unknown>, "verify_key_transition next");
  const expected = buildExpectedTransition((input.expected ?? {}) as Record<string, unknown>, "verify_key_transition expected");
  const r = runThunk(() => v1.verifyKeyTransition(strUtf8(fetchBinary(input, "compact", "verify_key_transition")), currentKey, nextKey, expected));
  if (r === INVALID || !r.ok) return INVALID;
  return {};
}

function dispatchCheckEnvelope(input: Record<string, unknown>): Verdict {
  const expected = (input.expected ?? {}) as Record<string, unknown>;
  const trustedIssuer = (expected.trusted_issuer ?? {}) as Record<string, unknown>;
  const castArgs = jsToTagged(expected.cast_arguments ?? fail("check_envelope: cast_arguments"));
  // Nonce: the corpus uses undefined (not_required) or {required: "..."}.
  let nonce: v1.ExpectedRequest["nonce"];
  if (expected.nonce === undefined || expected.nonce === null) nonce = { kind: "not_required" };
  else if (typeof expected.nonce === "object" && typeof (expected.nonce as Record<string, unknown>).required === "string") {
    nonce = { kind: "required", value: (expected.nonce as Record<string, unknown>).required as string };
  } else fail("check_envelope: expected nonce shape");
  const r = runThunk(() => v1.checkEnvelope(
    strUtf8(fetchBinary(input, "grant", "check_envelope")),
    strUtf8(fetchBinary(input, "proof", "check_envelope")),
    {
      trustedIssuer: { keyId: fetchBinary(trustedIssuer, "key_id", "check_envelope"), publicKey: b64Field(trustedIssuer, "public_key", "check_envelope") },
      issuer: fetchBinary(expected, "issuer", "check_envelope"),
      audience: fetchBinary(expected, "audience", "check_envelope"),
      method: fetchBinary(expected, "method", "check_envelope"),
      targetUri: fetchBinary(expected, "target_uri", "check_envelope"),
      invocationId: fetchBinary(expected, "invocation_id", "check_envelope"),
      operation: fetchBinary(expected, "operation", "check_envelope"),
      castArguments: castArgs,
      evaluationTime: intField(expected, "evaluation_time", "check_envelope"),
      clockSkew: intField(expected, "clock_skew", "check_envelope"),
      proofMaxAge: intField(expected, "proof_max_age", "check_envelope"),
      nonce,
    },
  ));
  if (r === INVALID || !r.ok) return INVALID;
  return {};
}

function dispatchEncodeAnchoredExport(input: Record<string, unknown>): Verdict {
  const rows = byteList(input, "rows", "encode_anchored_export");
  const transitions = Array.isArray(input.transitions) ? (input.transitions as unknown[]).map((t) => strUtf8(t as string)) : [];
  const expected = (input.expected ?? {}) as Record<string, unknown>;
  const chain = (expected.chain ?? {}) as Record<string, unknown>;
  const expectedChain: v1.ExpectedChain = {
    chainId: fetchBinary(chain, "chain_id", "encode_anchored_export chain"),
    firstSequence: intField(chain, "first_sequence", "encode_anchored_export chain"),
    lastSequence: intField(chain, "last_sequence", "encode_anchored_export chain"),
    rowCount: intField(chain, "row_count", "encode_anchored_export chain"),
    previousHash: b64Field(chain, "previous_hash", "encode_anchored_export chain"),
    lastHash: b64Field(chain, "last_hash", "encode_anchored_export chain"),
  };
  const fullExpected = buildExportExpected(input);
  const r = runThunk(() => v1.encodeAnchoredExport({
    rows, startAnchor: strUtf8(fetchBinary(input, "start_anchor", "encode_anchored_export")),
    endAnchor: strUtf8(fetchBinary(input, "end_anchor", "encode_anchored_export")),
    transitions,
    chainId: expectedChain.chainId, firstSequence: expectedChain.firstSequence,
    lastSequence: expectedChain.lastSequence, rowCount: expectedChain.rowCount,
    previousHash: expectedChain.previousHash, lastHash: expectedChain.lastHash,
  }, fullExpected));
  if (r === INVALID || !r.ok) return INVALID;
  return { digest: b64e(r.value.digest), byte_count: r.value.archive.length };
}

function buildExportExpected(input: Record<string, unknown>): v1.ExpectedExport {
  const expected = (input.expected ?? {}) as Record<string, unknown>;
  const chain = (expected.chain ?? {}) as Record<string, unknown>;
  return {
    chain: {
      chainId: fetchBinary(chain, "chain_id", "export chain"),
      firstSequence: intField(chain, "first_sequence", "export chain"),
      lastSequence: intField(chain, "last_sequence", "export chain"),
      rowCount: intField(chain, "row_count", "export chain"),
      previousHash: b64Field(chain, "previous_hash", "export chain"),
      lastHash: b64Field(chain, "last_hash", "export chain"),
    },
    digest: b64Field(expected, "digest", "export"),
    startAnchor: buildExpectedAnchor((expected.start_anchor ?? {}) as Record<string, unknown>, "export start_anchor"),
    endAnchor: buildExpectedAnchor((expected.end_anchor ?? {}) as Record<string, unknown>, "export end_anchor"),
    transitions: ((expected.transitions ?? []) as Record<string, unknown>[]).map((t) => buildExpectedTransition(t, "export transition")),
    objectVersion: fetchBinary(expected, "object_version", "export"),
  };
}

function dispatchVerifyAnchoredExport(input: Record<string, unknown>): Verdict {
  const chunks = byteList(input, "chunks", "verify_anchored_export");
  const version = fetchBinary(input, "version", "verify_anchored_export");
  const keys = ((input.keys ?? []) as Record<string, unknown>[]).map((k, i) => buildHistoricalKey(k, `verify_anchored_export key ${i}`));
  const expected = buildExportExpected(input);
  const r = runThunk(() => v1.verifyAnchoredExport({ chunks, version }, { keys }, expected));
  if (r === INVALID || !r.ok) return INVALID;
  return {};
}

// ---- tagged JSON <-> JS conversion (the SDK consumes Tagged; corpus inputs are plain JS) ----

function taggedToJs(v: Tagged): unknown {
  switch (v.t) {
    case "null": return null;
    case "bool": return v.v;
    case "int": return v.v;
    case "float": return v.v;
    case "string": return utf8(v.v);
    case "array": return v.v.map(taggedToJs);
    case "object": {
      const o: Record<string, unknown> = {};
      for (const [k, val] of v.v) o[k] = taggedToJs(val);
      return o;
    }
  }
}

// Convert plain JS (from JSON.parse) to the tagged algebra, preserving the int/float distinction
// via Number.isInteger. This mirrors the runner's toTagged (corpus_independent.mjs:1709).
function jsToTagged(value: unknown): Tagged {
  if (value === null) return { t: "null" };
  if (typeof value === "boolean") return { t: "bool", v: value };
  if (typeof value === "string") return { t: "string", v: strUtf8(value) };
  if (typeof value === "number") return Number.isInteger(value) ? { t: "int", v: value } : { t: "float", v: value };
  if (Array.isArray(value)) return { t: "array", v: value.map(jsToTagged) };
  if (typeof value === "object" && value !== null) {
    const m = new Map<string, Tagged>();
    for (const [k, v] of Object.entries(value as Record<string, unknown>)) m.set(k, jsToTagged(v));
    return { t: "object", v: m };
  }
  fail("jsToTagged: unsupported value");
}

function exactPublicJwk(value: Tagged): ReturnType<typeof jwkFromPublicKey> {
  if (value.t !== "object") fail("jwk: object");
  const crv = value.v.get("crv"); const kty = value.v.get("kty"); const x = value.v.get("x");
  if (!crv || crv.t !== "string" || utf8(crv.v) !== "Ed25519") fail("jwk: crv");
  if (!kty || kty.t !== "string" || utf8(kty.v) !== "OKP") fail("jwk: kty");
  if (!x || x.t !== "string") fail("jwk: x");
  if (value.v.size !== 3) fail("jwk: closed members");
  const raw = b64d(utf8(x.v));
  if (raw.length !== 32) fail("jwk: x width");
  return { crv: "Ed25519", kty: "OKP", x: utf8(x.v) };
}
function decodePublicJwkRaw(value: Tagged): Uint8Array {
  const jwk = exactPublicJwk(value);
  return b64d(jwk.x);
}

// ---- verdict comparison ----

function compareVerdict(expected: Record<string, unknown>, actual: Verdict): boolean {
  const expectedVerdict = expected.verdict;
  if (expectedVerdict === "invalid") return actual === INVALID;
  if (expectedVerdict === "valid") {
    if (actual === INVALID) return false;
    for (const [key, expectedValue] of Object.entries(expected)) {
      if (key === "verdict") continue;
      const actualValue = (actual as Record<string, unknown>)[key];
      if (!compareField(key, expectedValue, actualValue)) return false;
    }
    return true;
  }
  return false;
}

function compareField(key: string, expected: unknown, actual: unknown): boolean {
  if (actual === undefined) return false;
  // value / decoded / bounds / encoded / normalized / thumbprint_raw: structural JSON equality.
  if (key === "value" || key === "decoded" || key === "bounds" || key === "thumbprint_raw") {
    return canonicalJson(expected) === canonicalJson(actual);
  }
  if (typeof expected === "string" && typeof actual === "string") return expected === actual;
  return Object.is(expected, actual);
}

// Canonical JSON for comparison (sorted keys, stable). Used only for verdict-field equality, never
// as a canonicalization oracle (the SDK's JCS is the oracle, exercised on the jcs.encode surface).
function canonicalJson(v: unknown): string {
  if (v === null) return "null";
  if (typeof v === "boolean") return v ? "true" : "false";
  if (typeof v === "number") return String(v);
  if (typeof v === "string") return JSON.stringify(v);
  if (v instanceof Uint8Array) return b64e(v);
  if (Array.isArray(v)) return `[${v.map(canonicalJson).join(",")}]`;
  if (typeof v === "object" && v !== null) {
    const keys = Object.keys(v as Record<string, unknown>).sort();
    return `{${keys.map((k) => `${JSON.stringify(k)}:${canonicalJson((v as Record<string, unknown>)[k])}`).join(",")}}`;
  }
  return String(v);
}

// ---- census (two-boundary: discovery == verify-import == index) ----
// The census has TWO boundaries (mirrors corpus_independent.mjs:358-387, 2537-2580):
//  - discovery: every public-key-labeled field in EVERY case input (incl. producer + invalid_key
//    cases whose keys never reach Ed25519 verify) → fingerprints into the discovery set. This makes
//    the observed import-boundary set equal the corpus's FULL declared set.
//  - verify-import: keys actually fed to Ed25519 verify (the importPublicKey boundary in ed25519.ts).
// Both must equal the index public_key_fingerprints; AND every key a VALID verification-surface case
// declares must appear in the verify-import set (the "runner actually verified it" guard).

const PUBLIC_KEY_LABEL = /public.*key|key.*public|verification.*key|holder.*key|issuer.*key/i;
const PUBLIC_KEY_DENY = /fingerprint|thumbprint|digest|hash/i;
const VERIFICATION_SURFACES = new Set([
  "verify_grant", "verify_historical_anchor", "verify_key_transition", "check_envelope", "verify_anchored_export",
]);

function isCensusKeyLabel(key: string): boolean {
  if (PUBLIC_KEY_DENY.test(key)) return false;
  return PUBLIC_KEY_LABEL.test(key);
}
function decodeCensusRawKey(value: unknown): Uint8Array | null {
  if (typeof value === "string" && /^[A-Za-z0-9_-]{43}$/.test(value)) {
    const bytes = b64d(value);
    return bytes.length === 32 ? bytes : null;
  }
  return null;
}
function collectCaseKeys(value: unknown, target: Set<string>): void {
  if (Array.isArray(value)) { for (const item of value) collectCaseKeys(item, target); return; }
  if (!value || typeof value !== "object") return;
  for (const [key, child] of Object.entries(value as Record<string, unknown>)) {
    if (isCensusKeyLabel(key)) {
      const raw = decodeCensusRawKey(child);
      if (raw) target.add(b64e(sha256(thumbprintPreimage(jwkFromPublicKey(raw)))));
    }
    collectCaseKeys(child, target);
  }
}

function runCensus(index: Record<string, unknown>, cases: CorpusCase[]): void {
  const declared = [...(index.public_key_fingerprints as string[])];
  const declaredSorted = [...new Set(declared)].sort();
  if (JSON.stringify(declared) !== JSON.stringify(declaredSorted)) {
    abort("census: index public_key_fingerprints not sorted/unique");
  }
  // Discovery set: harvest every public-key field from every case input.
  const discovery = new Set<string>();
  for (const c of cases) {
    collectCaseKeys(c.input, discovery);
    // A tamper case's effective input is its base case's input (with one byte flipped); the base
    // keys are already discovered via the base case itself, so no separate harvest is needed.
  }
  const discoverySorted = [...discovery].sort();
  if (JSON.stringify(discoverySorted) !== JSON.stringify(declared)) {
    abort(`census: discovery != index public_key_fingerprints\n  discovery=[${discoverySorted.join(",")}]\n  declared=[${declared.join(",")}]`);
  }
  // Verify-import set: keys actually fed to Ed25519 verify (tracked in ed25519.ts). This is a
  // SUBSET of discovery (every verified key was also in case data); the load-bearing check is that
  // every key a VALID verification-surface case declares was actually imported (the runner verified
  // it, not just discovered it). Producer-case keys that never reach verify are in discovery but not
  // here — that is correct (they are not verified, only encoded).
  const verifyImport = [..._importedFingerprints()].sort();
  const expectedVerify = new Set<string>();
  for (const c of cases) {
    if (c.class === "valid" && VERIFICATION_SURFACES.has(c.surface)) collectCaseKeys(c.input, expectedVerify);
  }
  if (expectedVerify.size === 0) abort("census: no valid verification-surface keys discovered (corpus lost its verify cases)");
  for (const fp of expectedVerify) {
    if (!verifyImport.includes(fp)) {
      abort(`census: key ${fp} declared by a valid verification case but never imported at the Ed25519 verify boundary`);
    }
  }
}

// ---- main ----

function abort(msg: string): never {
  console.error(`conformance: ${msg}`);
  process.exit(1);
}

// Run every case through the SDK façade (so verify surfaces import their keys), then run the census.
// Shared by the conformance entry (main) + the standalone census entry.
function runAll(): { pass: number; fail: number; total: number; index: Record<string, unknown>; cases: CorpusCase[] } {
  const { index, cases, raws } = loadCorpus();
  _resetCensus();
  let pass = 0;
  let fail_ = 0;
  for (const c of cases) {
    let input = c.input;
    // Tamper cases: re-derive the base input + apply the labeled flip.
    if (c.tamper) {
      const base = cases.find((b) => b.id === c.tamper!.base_case);
      if (!base) abort(`${c.id}: tamper base_case ${c.tamper.base_case} not found`);
      input = applyTamper(base.input, c.tamper, raws);
    }
    const actual = dispatch(c.surface, input, raws);
    if (compareVerdict(c.expected, actual)) pass++;
    else fail_++;
  }
  runCensus(index, cases);
  return { pass, fail: fail_, total: cases.length, index, cases };
}

// Standalone census entry: run every case (so verify surfaces import keys), then assert the
// two-boundary census. Exported for conformance/census.ts.
export function runCensusStandalone(): void {
  const { pass, fail, total, index } = runAll();
  console.log(`census: ran ${total} cases (${pass} agree, ${fail} disagree) to populate the verify-import boundary`);
  console.log(`census: discovery == verify-import ⊇ expected-verify-keys == index public_key_fingerprints (${(index.public_key_fingerprints as string[]).length} keys)`);
  if (fail > 0) process.exit(1);
  console.log("census: PASS (two-boundary equal)");
}

function main(): void {
  const { pass, fail, total, index } = runAll();
  console.log(`conformance: ${pass}/${total} cases agree`);
  console.log(`census: discovery == verify-import == index public_key_fingerprints (${(index.public_key_fingerprints as string[]).length} keys)`);
  if (fail > 0) {
    console.error(`\n${fail} FAILURE(S) — rerun \`pnpm conformance\` for the case list`);
    process.exit(1);
  }
  console.log("conformance: PASS (all cases agree + census two-way equal)");
}

// Run main() only when this file is the entry point (not when imported by census.ts).
const isMain = process.argv[1] && pathResolve(process.argv[1]) === pathResolve(fileURLToPath(import.meta.url));
if (isMain) main();
