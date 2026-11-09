// Conformance runner for the bap-selector-float-zero/1 corpus (erratum 6) of
// @bounded-authority-protocol/verifier. Loads the vendored certified corpus snapshot
// (conformance/corpus-selector-float-zero) and drives every case through its contract-major's own
// surface: decode_grant, grant_signing_input (the package's grant producer) and check_envelope, for
// majors 1, 2 and 3, asserting the certified verdict on all 161 cases.
//
// REQ1/2/3-SELECTOR-float-zero: grant decode rejects an `equals` value or `one_of` member holding a
// float-tagged number equal to zero at any depth, whatever its sign or spelling (`0.0`, `-0e0`,
// `1e-400`, ...); range bounds and inert `all` members are unchanged.
// REQ1/2/3-SIGNING-integral-float-selector: the grant producer refuses any float-tagged integral
// selector value, including the major-2 and major-3 range bounds.
// REQ2/3-SELECTOR-range-signed-zero: range bounds compare numerically, -0.0 = 0.0.
//
// Values whose float tag matters travel as JSON TEXT (`input.operations_json`,
// `input.expected.cast_arguments_json`) and are decoded here with the package's own lexeme-aware
// tagged decoder (jsonDecode); JSON.parse would collapse `10.0` to an integer and `-0.0` to `0`.
//
// Corpus integrity discipline (the family pin rule): the index.json SHA-256 is asserted at startup,
// the exact twelve-file set is required, and profile identity, revision and per-family case counts
// are checked BEFORE the per-file digests are trusted.
//
// Derivation: the corpus is the arbiter (BAP erratum 6); the SDK is the implementation under test.
import { sha256 as nobleSha256 } from "@noble/hashes/sha2.js";
import { CoreAbort, type Core, type CorpusSource, type VerdictEntry } from "./types.js";
import * as v1 from "../../src/v1.js";
import * as v2 from "../../src/v2.js";
import * as v3 from "../../src/v3.js";
import { base64urlDecode } from "../../src/base64url.js";
import { jsonDecode, strUtf8, utf8Str, type Tagged } from "../../src/json.js";
import { InvalidError } from "../../src/error.js";

const utf8 = (b: Uint8Array) => utf8Str(b);
// The corpus integrity hash is @noble/hashes, independent of the package backend under test.
const sha256Hex = (b: Uint8Array) => Array.from(nobleSha256(b), (x) => x.toString(16).padStart(2, "0")).join("");

// Vendored snapshot beside this runner (ADR 0014 D4 binding, ADR 0015 D3 graduation discipline —
// no monorepo-relative path), byte-synced to the certified corpus of BAP erratum 6
// (priv/conformance/selector-float-zero).
const DIR = "corpus-selector-float-zero";

// The certified index.json SHA-256, revision 1 (161 cases), hex
// 97fd7a99cdbf3acc0a78f5ba1c6556e23a63e0ad66f533e31fd69f82dc5f3003
// (base64url l_16mc2_OswKePW6HGVW4jpj4K1m9TPjH9afgtxfMAM). Pinned independently here, in the
// protocol repository, and in every SDK consumer; rotate every pin in the same change as any
// corpus revision.
const CERTIFIED_INDEX_SHA256 = "97fd7a99cdbf3acc0a78f5ba1c6556e23a63e0ad66f533e31fd69f82dc5f3003";
const PROFILE_IDENTITY = "bap-selector-float-zero/1";
const CERTIFIED_REVISION = 1;
const CERTIFIED_CASES = 161;
const CERTIFIED_FAMILIES: Readonly<Record<string, number>> = { envelope: 35, "grant-decode": 78, "grant-signing-input": 48 };
const FAMILY_SURFACE: Readonly<Record<string, Surface>> = {
  envelope: "check_envelope",
  "grant-decode": "decode_grant",
  "grant-signing-input": "grant_signing_input",
};
const MAJORS = [1, 2, 3] as const;
// Every valid case's certified output fields, per surface: a valid verdict without them would be
// vacuous, and an extra field would go unchecked.
const VALID_FIELDS: Readonly<Record<Surface, string>> = {
  decode_grant: "key_id",
  grant_signing_input: "message,payload_segment,protected_segment",
  check_envelope: "",
};

type Surface = "decode_grant" | "grant_signing_input" | "check_envelope";
type Major = (typeof MAJORS)[number];

function abort(message: string): never {
  throw new CoreAbort("selector-float-zero conformance", message);
}

// ---- corpus loading (the family pin discipline) ----

interface FloatZeroCase {
  readonly id: string;
  readonly rule: string;
  readonly major: Major;
  readonly surface: Surface;
  readonly class: "invalid_selector" | "valid";
  readonly construction: string;
  readonly input: Record<string, unknown>;
  readonly expected: Record<string, unknown> & { readonly verdict: "valid" | "invalid" };
}

interface Family {
  readonly name: string;
  readonly major: Major;
  readonly cases: readonly FloatZeroCase[];
}

function loadCorpus(source: CorpusSource): Family[] {
  const indexBytes = source.read(`${DIR}/index.json`);
  const indexSha = sha256Hex(indexBytes);
  if (indexSha !== CERTIFIED_INDEX_SHA256) {
    abort(`index.json SHA-256 mismatch: got ${indexSha}, certified ${CERTIFIED_INDEX_SHA256}`);
  }
  const index = JSON.parse(utf8(indexBytes)) as {
    profile: string; revision: number; total_cases: number;
    families: Record<string, number>;
    files: Array<{ path: string; sha256: string; cases: number }>;
  };
  // Identity, revision, total, and per-family counts BEFORE the per-file digests are trusted.
  if (index.profile !== PROFILE_IDENTITY) abort(`profile identity: ${index.profile}`);
  if (index.revision !== CERTIFIED_REVISION) abort(`revision: ${index.revision}`);
  if (index.total_cases !== CERTIFIED_CASES) abort(`total cases: ${index.total_cases}`);
  if (JSON.stringify(sortedEntries(index.families)) !== JSON.stringify(sortedEntries(CERTIFIED_FAMILIES))) {
    abort(`family counts: ${JSON.stringify(index.families)}`);
  }
  const caseFiles = Object.keys(CERTIFIED_FAMILIES).flatMap((family) => MAJORS.map((major) => `cases/${family}/major-${major}.json`));
  const expectedPaths = [...caseFiles, "profile.json", "revision.json"].sort();
  const paths = index.files.map((f) => f.path).sort();
  if (JSON.stringify(paths) !== JSON.stringify(expectedPaths)) {
    abort(`exact twelve-file set required: ${JSON.stringify(paths)}`);
  }
  for (const file of index.files) {
    const digest = sha256Hex(source.read(`${DIR}/${file.path}`));
    if (digest !== file.sha256) abort(`${file.path}: SHA-256 mismatch (${digest} != ${file.sha256})`);
  }

  const families: Family[] = [];
  const perFamily: Record<string, number> = {};
  for (const file of index.files) {
    const match = /^cases\/([a-z-]+)\/major-([123])\.json$/.exec(file.path);
    if (!match) continue; // profile.json, revision.json: digest-checked above, zero cases
    const name = match[1]!;
    const major = Number(match[2]) as Major;
    const doc = JSON.parse(utf8(source.read(`${DIR}/${file.path}`))) as { family?: unknown; cases?: unknown };
    if (doc.family !== name) abort(`${file.path}: family ${String(doc.family)}`);
    if (!Array.isArray(doc.cases) || doc.cases.length !== file.cases) {
      abort(`${file.path}: holds ${Array.isArray(doc.cases) ? doc.cases.length : "no"} cases, index declares ${file.cases}`);
    }
    const cases = doc.cases as FloatZeroCase[];
    for (const c of cases) {
      if (c.major !== major) abort(`${c.id}: major ${String(c.major)} in ${file.path}`);
      if (c.surface !== FAMILY_SURFACE[name]) abort(`${c.id}: surface ${String(c.surface)} in family ${name}`);
      const verdictClass = c.expected?.verdict === "invalid" ? "invalid_selector" : "valid";
      if (c.class !== verdictClass) abort(`${c.id}: class ${String(c.class)} with verdict ${String(c.expected?.verdict)}`);
    }
    perFamily[name] = (perFamily[name] ?? 0) + cases.length;
    families.push({ name: file.path, major, cases });
  }
  if (JSON.stringify(sortedEntries(perFamily)) !== JSON.stringify(sortedEntries(CERTIFIED_FAMILIES))) {
    abort(`loaded family counts: ${JSON.stringify(perFamily)}`);
  }
  return families;
}

function sortedEntries(record: Readonly<Record<string, number>>): Array<[string, number]> {
  return Object.entries(record).sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
}

// ---- typed text and input fields ----

// The tag-preserving decode of a typed-text field. A corpus text that does not decode is a corpus
// defect, never a verdict.
function typedText(text: unknown, ctx: string): Tagged {
  if (typeof text !== "string") abort(`${ctx}: typed JSON text missing`);
  try {
    return jsonDecode(strUtf8(text));
  } catch (e) {
    if (e instanceof InvalidError) abort(`${ctx}: typed JSON text does not decode`);
    throw e;
  }
}

function str(record: Record<string, unknown>, key: string, ctx: string): string {
  const value = record[key];
  if (typeof value !== "string") abort(`${ctx}: ${key} string`);
  return value;
}

function int(record: Record<string, unknown>, key: string, ctx: string): number {
  const value = record[key];
  if (typeof value !== "number" || !Number.isSafeInteger(value)) abort(`${ctx}: ${key} integer`);
  return value;
}

function member(obj: Tagged, key: string, ctx: string): Tagged {
  if (obj.t !== "object") abort(`${ctx}: object`);
  return obj.v.get(key) ?? abort(`${ctx}: ${key}`);
}

function taggedString(v: Tagged, ctx: string): string {
  if (v.t !== "string") abort(`${ctx}: string`);
  return utf8(v.v);
}

// The decoded operations text, as the producer's typed OperationInput: selector values stay the
// decoder's tagged values, so a float-tagged 10.0 reaches the producer as a float.
type SelectorShape =
  | { kind: "all" }
  | { kind: "equals" | "lte" | "gte"; path: string[]; value: Tagged }
  | { kind: "one_of"; path: string[]; values: Tagged[] };

function operationsOf(text: unknown, ctx: string): Array<{ name: string; selectors: SelectorShape[] }> {
  const ops = typedText(text, `${ctx} operations_json`);
  if (ops.t !== "array") abort(`${ctx}: operations array`);
  return ops.v.map((op) => {
    const selectors = member(op, "selectors", ctx);
    if (selectors.t !== "array") abort(`${ctx}: selectors array`);
    return {
      name: taggedString(member(op, "name", ctx), `${ctx} name`),
      selectors: selectors.v.map((s): SelectorShape => {
        const kind = taggedString(member(s, "kind", ctx), `${ctx} kind`);
        if (kind === "all") return { kind: "all" };
        const pathV = member(s, "path", ctx);
        if (pathV.t !== "array") abort(`${ctx}: path array`);
        const path = pathV.v.map((p) => taggedString(p, `${ctx} path`));
        if (kind === "one_of") {
          const values = member(s, "values", ctx);
          if (values.t !== "array") abort(`${ctx}: values array`);
          return { kind, path, values: values.v };
        }
        if (kind !== "equals" && kind !== "lte" && kind !== "gte") abort(`${ctx}: selector kind ${kind}`);
        return { kind, path, value: member(s, "value", ctx) };
      }),
    };
  });
}

// ---- case driving ----

const INVALID = Symbol("invalid");
type Outcome = Record<string, string> | typeof INVALID;

// The SDK's Result contract maps every rejection to { ok: false }; a thrown InvalidError escaping a
// Result surface is an SDK bug and aborts (ADR 0014 Decision 6).
function settle<T>(run: () => { ok: true; value: T } | { ok: false }, project: (value: T) => Record<string, string>): Outcome {
  let r: { ok: true; value: T } | { ok: false };
  try {
    r = run();
  } catch (e) {
    if (e instanceof InvalidError) abort(`unexpected InvalidError escaped a Result surface: ${e.message}`);
    throw e;
  }
  return r.ok ? project(r.value) : INVALID;
}

function runDecode(c: FloatZeroCase): Outcome {
  const compact = strUtf8(str(c.input, "compact", c.id));
  const project = (g: { keyId: string }) => ({ key_id: g.keyId });
  if (c.major === 1) return settle(() => v1.decodeGrant(compact), project);
  if (c.major === 2) return settle(() => v2.decodeGrant(compact), project);
  return settle(() => v3.decodeGrant(compact), project);
}

function runSigningInput(c: FloatZeroCase): Outcome {
  const audiences = c.input.audiences;
  if (!Array.isArray(audiences) || !audiences.every((a) => typeof a === "string")) abort(`${c.id}: audiences`);
  const producer = {
    keyId: str(c.input, "key_id", c.id),
    issuer: str(c.input, "issuer", c.id),
    grantId: str(c.input, "grant_id", c.id),
    audiences: audiences as string[],
    issuedAt: int(c.input, "issued_at", c.id),
    notBefore: int(c.input, "not_before", c.id),
    expiresAt: int(c.input, "expires_at", c.id),
    holderThumbprint: str(c.input, "holder_thumbprint", c.id),
    operations: operationsOf(c.input.operations_json, c.id),
  };
  const project = (si: { protectedSegment: Uint8Array; payloadSegment: Uint8Array }) => ({
    protected_segment: utf8(si.protectedSegment),
    payload_segment: utf8(si.payloadSegment),
    message: `${utf8(si.protectedSegment)}.${utf8(si.payloadSegment)}`,
  });
  if (c.major === 1) {
    // Major 1 has no range kinds: a corpus lte/gte in a major-1 case is a corpus defect.
    if (producer.operations.some((op) => op.selectors.some((s) => s.kind === "lte" || s.kind === "gte"))) {
      abort(`${c.id}: range selector in a major-1 case`);
    }
    return settle(() => v1.grantSigningInput(producer as v1.GrantProducer), project);
  }
  if (c.major === 2) return settle(() => v2.grantSigningInput(producer as v2.GrantProducer), project);
  return settle(() => v3.grantSigningInput(producer as v3.GrantProducer), project);
}

function runEnvelope(c: FloatZeroCase): Outcome {
  const expected = (c.input.expected ?? abort(`${c.id}: expected`)) as Record<string, unknown>;
  const trusted = (expected.trusted_issuer ?? abort(`${c.id}: trusted_issuer`)) as Record<string, unknown>;
  if (expected.nonce !== undefined) abort(`${c.id}: this corpus carries no nonce`);
  const request = {
    trustedIssuer: {
      keyId: str(trusted, "key_id", c.id),
      publicKey: base64urlDecode(strUtf8(str(trusted, "public_key", c.id))),
    },
    issuer: str(expected, "issuer", c.id),
    audience: str(expected, "audience", c.id),
    method: str(expected, "method", c.id),
    targetUri: str(expected, "target_uri", c.id),
    invocationId: str(expected, "invocation_id", c.id),
    operation: str(expected, "operation", c.id),
    castArguments: typedText(expected.cast_arguments_json, `${c.id} cast_arguments_json`),
    evaluationTime: int(expected, "evaluation_time", c.id),
    clockSkew: int(expected, "clock_skew", c.id),
    proofMaxAge: int(expected, "proof_max_age", c.id),
    nonce: { kind: "not_required" as const },
  };
  const grant = strUtf8(str(c.input, "grant", c.id));
  const proof = strUtf8(str(c.input, "proof", c.id));
  const project = () => ({});
  if (c.major === 1) return settle(() => v1.checkEnvelope(grant, proof, request), project);
  if (c.major === 2) return settle(() => v2.checkEnvelope(grant, proof, request), project);
  return settle(() => v3.checkEnvelope(grant, proof, request), project);
}

function runCase(c: FloatZeroCase): Outcome {
  if (c.surface === "decode_grant") return runDecode(c);
  if (c.surface === "grant_signing_input") return runSigningInput(c);
  return runEnvelope(c);
}

function projection(outcome: Outcome): string {
  if (outcome === INVALID) return "invalid";
  return JSON.stringify(Object.fromEntries(Object.entries(outcome).sort(([a], [b]) => (a < b ? -1 : 1))));
}

function agrees(c: FloatZeroCase, outcome: Outcome): boolean {
  if (c.expected.verdict === "invalid") return outcome === INVALID;
  if (outcome === INVALID) return false;
  for (const [key, value] of Object.entries(c.expected)) {
    if (key === "verdict") continue;
    if (outcome[key] !== value) return false;
  }
  return true;
}

function main(source: CorpusSource): { summary: string[]; verdicts: VerdictEntry[]; failures: string[] } {
  const families = loadCorpus(source);
  const verdicts: VerdictEntry[] = [];
  const failures: string[] = [];
  const seen = new Set<string>();
  let rejected = 0;
  let accepted = 0;

  for (const family of families) {
    for (const c of family.cases) {
      if (seen.has(c.id)) abort(`duplicate case id ${c.id}`);
      seen.add(c.id);
      if (c.expected.verdict === "valid") {
        const fields = Object.keys(c.expected).filter((k) => k !== "verdict").sort().join(",");
        if (fields !== VALID_FIELDS[c.surface]) abort(`${c.id}: valid case certifies fields {${fields}}`);
      } else if (Object.keys(c.expected).length !== 1) {
        abort(`${c.id}: an invalid case certifies only its verdict`);
      }
      const outcome = runCase(c);
      verdicts.push([c.id, projection(outcome)]);
      if (agrees(c, outcome)) {
        if (outcome === INVALID) rejected++;
        else accepted++;
      } else {
        failures.push(`${c.id} [${c.surface}, major ${c.major}] (${c.construction}): expected ${c.expected.verdict}, got ${projection(outcome)}`);
      }
    }
  }
  if (seen.size !== CERTIFIED_CASES) abort(`case census: ${seen.size} != ${CERTIFIED_CASES}`);

  const byFamily = sortedEntries(CERTIFIED_FAMILIES).map(([name, n]) => `${name} ${n}`).join(", ");
  return { verdicts, failures, summary: [
    `selector-float-zero conformance: PASS — ${CERTIFIED_CASES}/${CERTIFIED_CASES} verdict agreement ` +
      `(${rejected} rejected, ${accepted} accepted with certified outputs; revision ${CERTIFIED_REVISION}, ` +
      `index SHA-256 ${CERTIFIED_INDEX_SHA256.slice(0, 8)}…; ${byFamily}).`,
  ] };
}

export const core: Core = {
  corpus: "selector-float-zero",
  dir: DIR,
  run(source: CorpusSource) {
    return { corpus: "selector-float-zero", ...main(source) };
  },
};
