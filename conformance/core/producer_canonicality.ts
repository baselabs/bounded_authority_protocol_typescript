// Conformance runner for the bap-producer-canonicality/1 corpus (erratum 3) of
// @bounded-authority-protocol/verifier. Loads the vendored certified corpus snapshot
// (conformance/corpus-producer-canonicality), drives every case through the package's PRODUCER
// surfaces — compact assembly for contract-majors 1, 2 and 3 and the three sibling profiles,
// anchored-export encoding for majors 1, 2 and 3 — and asserts the certified verdict on all 75
// cases: a refused signature is the closed error, an accepted signature's bytes are emitted
// unchanged (byte-equality against the certified compact for every accepted case).
//
// REQ1/2/3-SIGNING-*-producer-canonical: the producer surfaces frame a signature and verify
// none; they refuse a signature that no conforming signer emits (Ed25519: S >= L, or R
// non-canonical or of small order; ES256: r or s outside 0 < r < n, 0 < s <= floor(n/2)) and
// never rewrite accepted bytes. Every BAP verifier already rejected these signatures, so no
// verification verdict changes anywhere in this corpus or the existing ones.
//
// Corpus integrity discipline (the family pin rule): the index.json SHA-256 is asserted at
// startup, the exact six-file set is required, and profile identity, revision and per-family
// case counts are checked BEFORE the per-file digests are trusted.
//
// Derivation: the corpus is the arbiter (BAP package 0.9.0, erratum 3); the SDK is the
// implementation under test.
import { sha256 as nobleSha256 } from "@noble/hashes/sha2.js";
import { CoreAbort, type Core, type CorpusSource, type VerdictEntry } from "./types.js";
import * as v1 from "../../src/v1.js";
import * as v2 from "../../src/v2.js";
import * as v3 from "../../src/v3.js";
import * as roleAttestation from "../../src/role_attestation.js";
import * as contentAssertion from "../../src/content_assertion.js";
import { base64urlDecode } from "../../src/base64url.js";
import { strUtf8, utf8Str } from "../../src/json.js";
import type { SigningInput, SigningInputKind } from "../../src/compact.js";
import type { Result } from "../../src/error.js";
import type { Bounds } from "../../src/bounds.js";
import { InvalidError } from "../../src/error.js";

const utf8 = (b: Uint8Array) => utf8Str(b);
// The corpus integrity hash is @noble/hashes, independent of the package backend under test.
const sha256Hex = (b: Uint8Array) => Array.from(nobleSha256(b), (x) => x.toString(16).padStart(2, "0")).join("");

// Vendored snapshot beside this runner (ADR 0014 D4 binding, ADR 0015 D3 graduation
// discipline — no monorepo-relative path), byte-synced to the certified corpus in BAP package
// 0.9.0 (the erratum-3 release).
const DIR = "corpus-producer-canonicality";

// The certified index.json SHA-256, revision 1 (75 cases), hex
// 99ee6fbbf32758b03d4630647f721d8d4e349f0628d860493d667fe6e762c601
// Pinned independently here, in the protocol repository's errata registry, and in every SDK
// consumer; rotate every pin in the same change as any corpus revision.
const CERTIFIED_INDEX_SHA256 = "99ee6fbbf32758b03d4630647f721d8d4e349f0628d860493d667fe6e762c601";
const PROFILE_IDENTITY = "bap-producer-canonicality/1";
const CERTIFIED_REVISION = 1;
const CERTIFIED_CASES = 75;
const FAMILY_FILES: Readonly<Record<string, string>> = {
  "ed25519-assemble": "cases/ed25519-assemble/assemble.json",
  "ed25519-export-encode": "cases/ed25519-export-encode/encode.json",
  "es256-assemble": "cases/es256-assemble/assemble.json",
  "es256-export-encode": "cases/es256-export-encode/encode.json",
};

function abort(message: string): never {
  throw new CoreAbort("producer-canonicality conformance", message);
}

// ---- corpus loading (the family pin discipline) ----

interface AssembleCase {
  readonly id: string;
  readonly rule: string;
  readonly surface: "assemble_compact";
  readonly class: "invalid_encoding" | "exact_bound";
  readonly major?: 1 | 2 | 3;
  readonly profile?: string;
  readonly input: { readonly kind?: string; readonly protected_segment: string; readonly payload_segment: string; readonly signature: string };
  readonly expected: { readonly verdict: "valid" | "invalid"; readonly compact?: string };
}

interface ExportCase {
  readonly id: string;
  readonly rule: string;
  readonly surface: "encode_anchored_export";
  readonly class: "invalid_encoding" | "exact_bound";
  readonly major: 1 | 2 | 3;
  readonly input: {
    readonly rows: readonly string[];
    readonly start_anchor: string;
    readonly end_anchor: string;
    readonly transitions: readonly string[];
    readonly expected: {
      readonly chain: ExpectedChainJson;
      readonly start_anchor: ExpectedAnchorJson;
      readonly end_anchor: ExpectedAnchorJson;
      readonly transitions: readonly ExpectedTransitionJson[];
      readonly digest?: string;
      readonly object_version?: string;
    };
  };
  readonly expected: { readonly verdict: "valid" | "invalid" };
}

interface ExpectedChainJson {
  readonly chain_id: string; readonly first_sequence: number; readonly last_sequence: number;
  readonly row_count: number; readonly previous_hash: string; readonly last_hash: string;
}
interface ExpectedAnchorJson {
  readonly anchor_id: string; readonly anchored_at: number; readonly chain_id: string;
  readonly sequence: number; readonly chain_hash: string; readonly key_id: string; readonly key_fingerprint: string;
}
interface ExpectedTransitionJson {
  readonly transition_id: string; readonly chain_id: string; readonly effective_at: number;
  readonly current_key_id: string; readonly current_key_fingerprint: string;
  readonly next_key_id: string; readonly next_key_fingerprint: string;
}

interface FamilyDoc {
  readonly cases: readonly (AssembleCase | ExportCase)[];
}

function loadCorpus(source: CorpusSource): { families: Array<{ name: string; cases: readonly (AssembleCase | ExportCase)[] }> } {
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
  const familyNames = Object.keys(FAMILY_FILES).sort();
  const indexFamilies = Object.keys(index.families).sort();
  if (JSON.stringify(indexFamilies) !== JSON.stringify(familyNames)) {
    abort(`family set: ${JSON.stringify(indexFamilies)}`);
  }
  const paths = index.files.map((f) => f.path).sort();
  const expectedPaths = [
    ...Object.values(FAMILY_FILES),
    "profile.json",
    "revision.json",
  ].sort();
  if (JSON.stringify(paths) !== JSON.stringify(expectedPaths)) {
    abort(`exact six-file set required: ${JSON.stringify(paths)}`);
  }
  for (const file of index.files) {
    const bytes = source.read(`${DIR}/${file.path}`);
    const digest = sha256Hex(bytes);
    if (digest !== file.sha256) abort(`${file.path}: SHA-256 mismatch (${digest} != ${file.sha256})`);
  }
  const families: Array<{ name: string; cases: readonly (AssembleCase | ExportCase)[] }> = [];
  let counted = 0;
  for (const name of familyNames) {
    const doc = JSON.parse(utf8(source.read(`${DIR}/${FAMILY_FILES[name]!}`))) as FamilyDoc;
    if (!Array.isArray(doc.cases) || doc.cases.length !== index.families[name]) {
      abort(`${name}: holds ${doc.cases?.length ?? "no"} cases, index declares ${index.families[name]}`);
    }
    counted += doc.cases.length;
    families.push({ name, cases: doc.cases });
  }
  if (counted !== CERTIFIED_CASES) abort(`family case sum ${counted} != ${CERTIFIED_CASES}`);
  return { families };
}

// ---- case driving ----

const MAJOR_ASSEMBLERS: Readonly<Record<1 | 2 | 3, (input: SigningInput, signature: Uint8Array) => Result<Uint8Array>>> = {
  1: (input, signature) => v1.assembleCompact(input, signature),
  2: (input, signature) => v2.assembleCompact(input, signature),
  3: (input, signature) => v3.assembleCompact(input, signature),
};

const PROFILE_ASSEMBLERS: Readonly<Record<string, (input: SigningInput, signature: Uint8Array) => Result<Uint8Array>>> = {
  "bap-application-proof/local-loopback-http/1": (input, signature) => v1.assembleLocalLoopbackHttpCompact(input, signature),
  "bap-role-attestation/1": (input, signature) => roleAttestation.assembleAttestationCompact(input, signature),
  "bap-content-assertion/1": (input, signature) => contentAssertion.assembleCompact(input, signature),
};

const PROFILE_KINDS: Readonly<Record<string, SigningInputKind>> = {
  "bap-application-proof/local-loopback-http/1": "local_loopback_http_proof",
  "bap-role-attestation/1": "role_attestation",
  "bap-content-assertion/1": "content_assertion",
};

function runAssembleCase(entry: AssembleCase): Result<Uint8Array> {
  const signature = base64urlDecode(strUtf8(entry.input.signature));
  const segments = {
    protectedSegment: strUtf8(entry.input.protected_segment),
    payloadSegment: strUtf8(entry.input.payload_segment),
  };
  if (entry.major !== undefined) {
    const kind = entry.input.kind as SigningInputKind;
    return MAJOR_ASSEMBLERS[entry.major]({ kind, ...segments }, signature);
  }
  const profile = entry.profile ?? abort(`${entry.id}: neither major nor profile`);
  const assembler = PROFILE_ASSEMBLERS[profile] ?? abort(`${entry.id}: unknown profile ${profile}`);
  return assembler({ kind: PROFILE_KINDS[profile]!, ...segments }, signature);
}

// The corpus rows are base64url of the canonical row bytes; the digests are base64url raw-32.
function raw(b64: string): Uint8Array {
  return base64urlDecode(strUtf8(b64));
}

function expectedChainOf(json: ExpectedChainJson, bounds?: Bounds): v1.ExpectedChain {
  return {
    chainId: json.chain_id, firstSequence: json.first_sequence, lastSequence: json.last_sequence,
    rowCount: json.row_count, previousHash: raw(json.previous_hash), lastHash: raw(json.last_hash),
    ...(bounds === undefined ? {} : { bounds }),
  };
}

function expectedAnchorOf(json: ExpectedAnchorJson, bounds?: Bounds): v1.ExpectedAnchor {
  return {
    anchorId: json.anchor_id, anchoredAt: json.anchored_at, chainId: json.chain_id, sequence: json.sequence,
    chainHash: raw(json.chain_hash), keyId: json.key_id, keyFingerprint: raw(json.key_fingerprint),
    ...(bounds === undefined ? {} : { bounds }),
  };
}

function expectedTransitionOf(json: ExpectedTransitionJson, bounds?: Bounds): v1.ExpectedKeyTransition {
  return {
    transitionId: json.transition_id, chainId: json.chain_id, effectiveAt: json.effective_at,
    currentKeyId: json.current_key_id, currentKeyFingerprint: raw(json.current_key_fingerprint),
    nextKeyId: json.next_key_id, nextKeyFingerprint: raw(json.next_key_fingerprint),
    ...(bounds === undefined ? {} : { bounds }),
  };
}

function runExportCase(entry: ExportCase): { ok: boolean } {
  const e = entry.input.expected;
  const input = {
    rows: entry.input.rows.map((row) => raw(row)),
    startAnchor: strUtf8(entry.input.start_anchor),
    endAnchor: strUtf8(entry.input.end_anchor),
    transitions: entry.input.transitions.map((t) => strUtf8(t)),
    chainId: e.chain.chain_id, firstSequence: e.chain.first_sequence, lastSequence: e.chain.last_sequence,
    rowCount: e.chain.row_count, previousHash: raw(e.chain.previous_hash), lastHash: raw(e.chain.last_hash),
  };
  if (entry.major === 3) {
    // v3 splits the export context: the encode side carries no digest or object version.
    const expected: v3.ExpectedExport = {
      chain: expectedChainOf(e.chain),
      startAnchor: expectedAnchorOf(e.start_anchor),
      endAnchor: expectedAnchorOf(e.end_anchor),
      transitions: e.transitions.map((t) => expectedTransitionOf(t)),
    };
    return v3.encodeAnchoredExport(input, expected);
  }
  const digest = e.digest; // v1 cases carry it; the encode side never reads it (the verify side owns it)
  const expected: v1.ExpectedExport = {
    chain: expectedChainOf(e.chain),
    digest: digest === undefined ? new Uint8Array(32) : raw(digest),
    objectVersion: e.object_version ?? "v2", // same: encode never reads it (the reference's encode context has neither field)
    startAnchor: expectedAnchorOf(e.start_anchor),
    endAnchor: expectedAnchorOf(e.end_anchor),
    transitions: e.transitions.map((t) => expectedTransitionOf(t)),
  };
  return entry.major === 1 ? v1.encodeAnchoredExport(input, expected) : v2.encodeAnchoredExport(input, expected);
}

function main(source: CorpusSource): { summary: string[]; verdicts: VerdictEntry[] } {
  const { families } = loadCorpus(source);
  const verdicts: VerdictEntry[] = [];
  const seen = new Set<string>();
  let refused = 0;
  let accepted = 0;

  for (const { name, cases } of families) {
    for (const entry of cases) {
      if (seen.has(entry.id)) abort(`duplicate case id ${entry.id}`);
      seen.add(entry.id);
      const wantValid = entry.expected.verdict === "valid";

      if (entry.surface === "assemble_compact") {
        const result = runAssembleCase(entry);
        if (result.ok !== wantValid) {
          abort(`${entry.id} (${name}, ${entry.class}): expected verdict ${entry.expected.verdict}, got ${result.ok ? "valid" : "invalid"}`);
        }
        if (wantValid) {
          // Never rewrites accepted bytes: the assembled compact equals the certified compact.
          if (!result.ok) abort(`${entry.id}: accepted without a value`);
          const certified = entry.expected.compact ?? abort(`${entry.id}: accepted case without a certified compact`);
          if (utf8(result.value) !== certified) {
            abort(`${entry.id}: assembled bytes differ from the certified compact`);
          }
          accepted++;
        } else {
          refused++;
        }
        verdicts.push([entry.id, `ok=${result.ok}`]);
        continue;
      }

      const result = runExportCase(entry);
      if (result.ok !== wantValid) {
        abort(`${entry.id} (${name}, ${entry.class}): expected verdict ${entry.expected.verdict}, got ${result.ok ? "valid" : "invalid"}`);
      }
      if (wantValid) {
        // No certified export artifact is carried today (every export-encode case in revision 1
        // is a refusal); an accepted case without one would need a byte pin to stay meaningful.
        abort(`${entry.id}: accepted export-encode case without a certified artifact (unsupported by this runner)`);
      }
      refused++;
      verdicts.push([entry.id, `ok=${result.ok}`]);
    }
  }
  if (seen.size !== CERTIFIED_CASES) abort(`case census: ${seen.size} != ${CERTIFIED_CASES}`);

  const byFamily = families.map((f) => `${f.name} ${f.cases.length}`).join(", ");
  return { verdicts, summary: [
    `producer-canonicality conformance: PASS — ${CERTIFIED_CASES}/${CERTIFIED_CASES} verdict agreement ` +
      `(${refused} refused, ${accepted} accepted with bytes unchanged; revision ${CERTIFIED_REVISION}, ` +
      `index SHA-256 ${CERTIFIED_INDEX_SHA256.slice(0, 8)}…; ${byFamily}).`,
  ] };
}

// The INVALID sentinel discipline: every case above maps through the SDK's Result contract; a
// thrown non-InvalidError anywhere is a runner/SDK bug and aborts (ADR 0014 Decision 6).
export const core: Core = {
  corpus: "producer-canonicality",
  dir: DIR,
  run(source: CorpusSource) {
    try {
      return { corpus: "producer-canonicality", failures: [], ...main(source) };
    } catch (e) {
      if (e instanceof InvalidError) abort(`unexpected InvalidError escaped a Result surface: ${e.message}`);
      throw e;
    }
  },
};
