// Check cross-profile rejection in both directions. The corpus sends a live v1
// grant to attestation decode; these cases send attestations to each contract-major
// decode and verification surface with well-formed contexts.
import { sha256 as nobleSha256 } from "@noble/hashes/sha2.js";
import { certifyCorpus, completeVerdicts, corpusDir } from "../certification.js";
import { CoreAbort, type Core, type CorpusSource, type VerdictEntry } from "./types.js";
import {
  attestationSigningInput,
  assembleAttestationCompact,
  decodeAttestation,
  verifyAttestation,
  type ExpectedAttestation,
} from "../../src/role_attestation.js";
import { base64urlDecode } from "../../src/base64url.js";
import { strUtf8, utf8Str } from "../../src/json.js";
import { assembleCompact, decodeGrant, verifyGrant } from "../../src/v1.js";
import * as v2 from "../../src/v2.js";
import * as v3 from "../../src/v3.js";
import { InvalidError } from "../../src/error.js";

const utf8 = (b: Uint8Array) => utf8Str(b);
// The corpus integrity hash is @noble/hashes, independent of the package backend under test.
const sha256Hex = (b: Uint8Array) => Array.from(nobleSha256(b), (x) => x.toString(16).padStart(2, "0")).join("");

// Load the certified snapshot vendored beside this runner. Its digest and exact file
// set bind the runner to published bytes without consulting a sibling checkout.
const DIR = corpusDir("role-attestation");

// SOURCE carries the index pin; profile identity is checked independently.
const PROFILE_IDENTITY = "bap-role-attestation/1";
const CERTIFIED_REVISION = 1;
const CERTIFIED_CASES = 40;

function abort(message: string): never {
  throw new CoreAbort("role-attestation conformance", message);
}

// ---- corpus loading (REQ-RA1-CONFORMANCE-certified-pin discipline) ----

interface CaseEntry {
  readonly id: string;
  readonly compact: string;
  readonly decode: boolean;
  readonly verify: boolean;
  readonly v1_grant?: boolean;
  readonly expected_overrides?: Record<string, unknown>;
}

interface ProfileContext {
  readonly attestor: {
    readonly key_id: string;
    readonly public_key: string;
    readonly valid_from: number;
    readonly valid_before: number;
  };
  readonly subject: { readonly key_id: string; readonly public_key: string };
  readonly now: number;
}

function loadCorpus(source: CorpusSource): { profile: ProfileContext; cases: CaseEntry[] } {
  certifyCorpus(source, DIR);
  const indexBytes = source.read(`${DIR}/index.json`);
  const index = JSON.parse(utf8(indexBytes)) as {
    profile: string;
    revision: number;
    attestation_cases: number;
    files: Array<{ path: string; sha256: string }>;
  };
  // Identity, revision, and case count BEFORE the per-file digests are trusted.
  if (index.profile !== PROFILE_IDENTITY) abort(`profile identity: ${index.profile}`);
  if (index.revision !== CERTIFIED_REVISION) abort(`revision: ${index.revision}`);
  if (index.attestation_cases !== CERTIFIED_CASES) abort(`case count: ${index.attestation_cases}`);
  const paths = index.files.map((f) => f.path).sort();
  if (JSON.stringify(paths) !== JSON.stringify(["attestation-cases.json", "profile.json"])) {
    abort(`exact two-file set required: ${JSON.stringify(paths)}`);
  }
  for (const file of index.files) {
    const bytes = source.read(`${DIR}/${file.path}`);
    const digest = sha256Hex(bytes);
    if (digest !== file.sha256) abort(`${file.path}: SHA-256 mismatch (${digest} != ${file.sha256})`);
  }
  const profile = JSON.parse(utf8(source.read(`${DIR}/profile.json`))) as ProfileContext;
  const cases = JSON.parse(utf8(source.read(`${DIR}/attestation-cases.json`))) as CaseEntry[];
  if (cases.length !== index.attestation_cases) {
    abort(`attestation-cases.json holds ${cases.length} cases, index declares ${index.attestation_cases}`);
  }
  return { profile, cases };
}

// ---- verdict recomputation ----

function baseExpected(profile: ProfileContext): ExpectedAttestation {
  return {
    attestor: {
      keyId: profile.attestor.key_id,
      publicKey: base64urlDecode(strUtf8(profile.attestor.public_key)),
      validFrom: profile.attestor.valid_from,
      validBefore: profile.attestor.valid_before,
    },
    subjectKeyId: profile.subject.key_id,
    subjectPublicKey: base64urlDecode(strUtf8(profile.subject.public_key)),
    now: profile.now,
  };
}

const OVERRIDE_KEYS = ["attestor_public_key", "subject_key_id", "subject_public_key", "now"] as const;

function applyOverrides(base: ExpectedAttestation, raw: Record<string, unknown> | undefined): ExpectedAttestation {
  if (!raw) return base;
  for (const key of Object.keys(raw)) {
    if (!(OVERRIDE_KEYS as readonly string[]).includes(key)) abort(`unknown expected override ${key}`);
  }
  return {
    attestor: {
      ...base.attestor,
      ...(raw.attestor_public_key === undefined ? {} : { publicKey: base64urlDecode(strUtf8(raw.attestor_public_key as string)) }),
    },
    subjectKeyId: (raw.subject_key_id as string | undefined) ?? base.subjectKeyId,
    subjectPublicKey: raw.subject_public_key === undefined ? base.subjectPublicKey : base64urlDecode(strUtf8(raw.subject_public_key as string)),
    now: (raw.now as number | undefined) ?? base.now,
  };
}

function main(source: CorpusSource): { summary: string[]; verdicts: VerdictEntry[] } {
  const { profile, cases } = loadCorpus(source);
  const verdicts: VerdictEntry[] = [];
  const base = baseExpected(profile);

  let decodeAgree = 0;
  let verifyAgree = 0;
  const seen = new Set<string>();
  for (const entry of cases) {
    if (seen.has(entry.id)) abort(`duplicate case id ${entry.id}`);
    seen.add(entry.id);
    const compact = strUtf8(entry.compact);
    const expected = applyOverrides(base, entry.expected_overrides);

    const decoded = decodeAttestation(compact);
    if (decoded.ok !== entry.decode) {
      abort(`decode disagreement on ${entry.id}: expected ${entry.decode}, got ${decoded.ok}`);
    }
    decodeAgree++;

    const verified = verifyAttestation(compact, expected);
    verdicts.push([entry.id, {decode: decoded.ok, verify: verified.ok}]);
    if (verified.ok !== entry.verify) {
      abort(`verify disagreement on ${entry.id}: expected ${entry.verify}, got ${verified.ok}`);
    }
    verifyAgree++;
    if (!decoded.ok && verified.ok) {
      // A structurally invalid attestation can never verify: decode:false implies verify:false.
      abort(`${entry.id}: decode false but verify true`);
    }
  }
  if (seen.size !== CERTIFIED_CASES) abort(`case census: ${seen.size} != ${CERTIFIED_CASES}`);

  // ---- producer/assembly byte symmetry against the certified valid compact ----
  const valid = cases.find((c) => c.id === "issuer-valid");
  if (!valid) abort("issuer-valid case missing");
  const validCompact = strUtf8(valid.compact);
  const decoded = decodeAttestation(validCompact);
  if (!decoded.ok) abort("issuer-valid failed to decode");
  const produced = attestationSigningInput({
    keyId: profile.attestor.key_id,
    jti: decoded.value.jti,
    subjectKeyId: decoded.value.subjectKeyId,
    subjectPublicKey: decoded.value.subjectPublicKey,
    role: decoded.value.role === "holder" ? "holder" : "issuer",
    notBefore: decoded.value.notBefore,
    expiresAt: decoded.value.expiresAt,
  });
  if (!produced.ok) abort("attestationSigningInput rejected the certified valid producer input");
  const [certifiedProtected, certifiedPayload, certifiedSignature] = valid.compact.split(".");
  if (utf8(produced.value.protectedSegment) !== certifiedProtected) abort("producer protected segment != certified bytes");
  if (utf8(produced.value.payloadSegment) !== certifiedPayload) abort("producer payload segment != certified bytes");
  const assembled = assembleAttestationCompact(produced.value, base64urlDecode(strUtf8(certifiedSignature!)));
  if (!assembled.ok) abort("assembleAttestationCompact rejected the certified input + signature");
  if (utf8(assembled.value) !== valid.compact) abort("assembled compact != certified bytes");
  // The profile's facts agree with its own re-verified assembly.
  const roundTrip = verifyAttestation(assembled.value, base);
  if (!roundTrip.ok) abort("assembled compact failed verification");
  if (roundTrip.value.jti !== decoded.value.jti || roundTrip.value.role !== decoded.value.role) {
    abort("round-trip facts disagree with decode");
  }

  // Check cross-profile rejection in both directions. The corpus sends a live v1
  // grant to attestation decode; these cases send attestations to each contract-major
  // decode and verification surface with well-formed contexts.
  const wellFormedIssuer = { keyId: profile.attestor.key_id, publicKey: base64urlDecode(strUtf8(profile.attestor.public_key)) };
  const wellFormedGrantContext = {
    issuer: "https://issuer.example.test",
    audience: "https://resource.example.test",
    evaluationTime: profile.now,
    clockSkew: 60,
  };
  const v3IssuerShape = { keyId: profile.attestor.key_id, publicKey: new Uint8Array(65) };
  if (decodeGrant(validCompact).ok) abort("v1 decodeGrant accepted attestation bytes");
  if (v2.decodeGrant(validCompact).ok) abort("v2 decodeGrant accepted attestation bytes");
  if (v3.decodeGrant(validCompact).ok) abort("v3 decodeGrant accepted attestation bytes");
  if (verifyGrant(validCompact, wellFormedIssuer, wellFormedGrantContext).ok) abort("v1 verifyGrant accepted attestation bytes");
  if (v2.verifyGrant(validCompact, wellFormedIssuer, wellFormedGrantContext).ok) abort("v2 verifyGrant accepted attestation bytes");
  if (v3.verifyGrant(validCompact, v3IssuerShape, wellFormedGrantContext).ok) abort("v3 verifyGrant accepted attestation bytes");
  // Kind discipline: the v1 assembler rejects the attestation signing input.
  if (assembleCompact(produced.value, base64urlDecode(strUtf8(certifiedSignature!))).ok) {
    abort("v1 assembleCompact accepted a role_attestation signing input");
  }

  const crossProfileGrant = cases.find((c) => c.v1_grant === true);
  if (!crossProfileGrant) abort("cross-profile v1-grant case missing");

  return { verdicts: completeVerdicts(source, DIR, verdicts), summary: [
    `role-attestation conformance: PASS: ${decodeAgree}/${CERTIFIED_CASES} decode + ` +
      `${verifyAgree}/${CERTIFIED_CASES} verify agreement (revision ${CERTIFIED_REVISION}, ` +
      `index SHA-256 ${certifyCorpus(source, DIR).indexSha.slice(0, 8)}…), producer/assembly byte symmetry ` +
      `against the certified compact, cross-profile rejection both directions ` +
      `(${crossProfileGrant.id} in-corpus + v1/v2/v3 out-of-profile).`,
  ] };
}

// Only protocol rejection maps to INVALID. Unexpected thrown errors are runner or
// SDK defects and abort rather than becoming conformance verdicts.
export const core: Core = {
  corpus: "role-attestation",
  dir: DIR,
  run(source: CorpusSource) {
    try {
      return { corpus: "role-attestation", failures: [], ...main(source) };
    } catch (e) {
      if (e instanceof InvalidError) abort(`unexpected InvalidError escaped a Result surface: ${e.message}`);
      throw e;
    }
  },
};
