// Conformance core for the certified local-loopback HTTP application-proof profile
// (bap-application-proof/local-loopback-http/1, ADR 0027). The verdict logic is the corpus block of
// test/local-loopback-http.test.ts, unchanged in substance, moved here so every runtime lane runs it:
// the index pin and exact file list, the URI cases, producer/assembly byte symmetry for both
// certified proofs, and every proof case's three flags (decode_local, decode_standard,
// envelope_local).
import { sha256 as nobleSha256 } from "@noble/hashes/sha2.js";
import { CoreAbort, type Core, type CorpusSource, type VerdictEntry } from "./types.js";
import { base64urlDecode } from "../../src/base64url.js";
import { strUtf8, utf8Str } from "../../src/json.js";
import { localLoopbackHttpUriNormalize } from "../../src/uri.js";
import {
  assembleCompact,
  assembleLocalLoopbackHttpCompact,
  checkLocalLoopbackHttpEnvelope,
  decodeLocalLoopbackHttpProof,
  decodeProof,
  localLoopbackHttpProofSigningInput,
  type ExpectedRequest,
  type ProofProducer,
} from "../../src/v1.js";

const DIR = "corpus-local-loopback-http";
const CERTIFIED_INDEX_SHA256 = "10fc4cf05affcddc9e6340ff392c247e25ab038cd938f2557829a7ce63b1a5e4";
const PREFIX = "local-loopback-http conformance";
const hex = (b: Uint8Array) => Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
const sha256Hex = (b: Uint8Array) => hex(nobleSha256(b));

function abort(message: string): never {
  throw new CoreAbort(PREFIX, message);
}
function check(condition: boolean, message: string): asserts condition {
  if (!condition) abort(message);
}

interface Profile {
  grant_compact: string;
  holder_public_key: string;
  issuer: { key_id: string; public_key: string; issuer: string; audience: string };
  request: {
    method: string; invocation_id: string; operation: string; evaluation_time: number;
    clock_skew: number; proof_max_age: number;
  };
  proofs: Record<"ipv4" | "ipv6", { target_uri: string; nonce: string; compact: string; proof_id: string }>;
  uri_cases: Array<{ id: string; input: string; valid: boolean; normalized?: string }>;
}
interface ProofCase {
  id: string; compact: string; decode_local: boolean; decode_standard: boolean; envelope_local: boolean;
  expected_overrides?: { trusted_issuer_public_key?: string; invocation_id?: string };
}

function main(source: CorpusSource): { summary: string[]; failures: string[]; verdicts: VerdictEntry[] } {
  const read = (name: string) => source.read(`${DIR}/${name}`);
  const indexBytes = read("index.json");
  check(sha256Hex(indexBytes) === CERTIFIED_INDEX_SHA256, `index.json SHA-256 mismatch: got ${sha256Hex(indexBytes)}, certified ${CERTIFIED_INDEX_SHA256}`);
  const index = JSON.parse(utf8Str(indexBytes)) as {
    files: Array<{ path: string; sha256: string }>;
    profile: string; revision: number; proof_cases: number; uri_cases: number;
  };
  check(index.profile === "bap-application-proof/local-loopback-http/1", `profile identity: ${index.profile}`);
  check(index.revision === 1, `revision: ${index.revision}`);
  check(index.proof_cases === 8, `proof_cases: ${index.proof_cases}`);
  check(index.uri_cases === 36, `uri_cases: ${index.uri_cases}`);
  check(JSON.stringify(index.files.map((file) => file.path)) === JSON.stringify(["profile.json", "proof-cases.json"]), "exact file list");
  for (const file of index.files) check(sha256Hex(read(file.path)) === file.sha256, `${file.path}: SHA-256 mismatch`);

  const profile = JSON.parse(utf8Str(read("profile.json"))) as Profile;
  const verdicts: VerdictEntry[] = [];
  const failures: string[] = [];
  check(profile.uri_cases.length === index.uri_cases, "uri case count");
  for (const uriCase of profile.uri_cases) {
    const result = localLoopbackHttpUriNormalize(strUtf8(uriCase.input));
    const projection = result.ok ? `valid;normalized=${utf8Str(result.value)}` : "invalid";
    verdicts.push([uriCase.id, projection]);
    const want = uriCase.valid ? `valid;normalized=${uriCase.normalized}` : "invalid";
    if (projection !== want) failures.push(`${uriCase.id}: expected ${want}, got ${projection}`);
  }

  const [protectedSegment, payloadSegment, signatureSegment] = profile.proofs.ipv4.compact.split(".");
  check(Boolean(protectedSegment && payloadSegment && signatureSegment), "ipv4 compact has three segments");
  const castArguments = () => ({ t: "object" as const, v: new Map([["record_id", { t: "string" as const, v: strUtf8("record-1") }]]) });
  const certifiedProducer: ProofProducer = {
    holderPublicKey: base64urlDecode(strUtf8(profile.holder_public_key)),
    proofId: profile.proofs.ipv4.proof_id,
    method: profile.request.method,
    targetUri: profile.proofs.ipv4.target_uri,
    issuedAt: profile.request.evaluation_time,
    invocationId: profile.request.invocation_id,
    operation: profile.request.operation,
    grantCompact: strUtf8(profile.grant_compact),
    castArguments: castArguments(),
    nonce: profile.proofs.ipv4.nonce,
  };
  const certifiedInput = localLoopbackHttpProofSigningInput(certifiedProducer);
  check(certifiedInput.ok, "ipv4 producer rejected the certified input");
  check(utf8Str(certifiedInput.value.protectedSegment) === protectedSegment, "ipv4 producer protected segment != certified bytes");
  check(utf8Str(certifiedInput.value.payloadSegment) === payloadSegment, "ipv4 producer payload segment != certified bytes");
  const certifiedSignature = base64urlDecode(strUtf8(signatureSegment!));
  const certifiedAssembly = assembleLocalLoopbackHttpCompact(certifiedInput.value, certifiedSignature);
  check(certifiedAssembly.ok && utf8Str(certifiedAssembly.value) === profile.proofs.ipv4.compact, "ipv4 assembly != certified bytes");
  check(!assembleCompact(certifiedInput.value, certifiedSignature).ok, "the standard assembler accepted a loopback input");

  const expected: ExpectedRequest = {
    trustedIssuer: { keyId: profile.issuer.key_id, publicKey: base64urlDecode(strUtf8(profile.issuer.public_key)) },
    issuer: profile.issuer.issuer,
    audience: profile.issuer.audience,
    method: profile.request.method,
    targetUri: profile.proofs.ipv4.target_uri,
    invocationId: profile.request.invocation_id,
    operation: profile.request.operation,
    castArguments: castArguments(),
    evaluationTime: profile.request.evaluation_time,
    clockSkew: profile.request.clock_skew,
    proofMaxAge: profile.request.proof_max_age,
    nonce: { kind: "required", value: profile.proofs.ipv4.nonce },
  };

  const ipv6 = profile.proofs.ipv6;
  const ipv6Input = localLoopbackHttpProofSigningInput({ ...certifiedProducer, proofId: ipv6.proof_id, targetUri: ipv6.target_uri, nonce: ipv6.nonce });
  check(ipv6Input.ok, "ipv6 producer rejected the certified input");
  const [ipv6Protected, ipv6Payload, ipv6Signature] = ipv6.compact.split(".");
  check(utf8Str(ipv6Input.value.protectedSegment) === ipv6Protected, "ipv6 producer protected segment != certified bytes");
  check(utf8Str(ipv6Input.value.payloadSegment) === ipv6Payload, "ipv6 producer payload segment != certified bytes");
  const ipv6Assembly = assembleLocalLoopbackHttpCompact(ipv6Input.value, base64urlDecode(strUtf8(ipv6Signature!)));
  check(ipv6Assembly.ok && utf8Str(ipv6Assembly.value) === ipv6.compact, "ipv6 assembly != certified bytes");
  check(decodeLocalLoopbackHttpProof(ipv6Assembly.value).ok, "ipv6 assembly does not decode");
  check(checkLocalLoopbackHttpEnvelope(strUtf8(profile.grant_compact), ipv6Assembly.value, {
    ...expected, targetUri: ipv6.target_uri, nonce: { kind: "required", value: ipv6.nonce },
  }).ok, "ipv6 envelope does not check");

  const cases = JSON.parse(utf8Str(read("proof-cases.json"))) as ProofCase[];
  check(cases.length === index.proof_cases, "proof case count");
  for (const proofCase of cases) {
    const compact = strUtf8(proofCase.compact);
    const overrides = proofCase.expected_overrides ?? {};
    check(Object.keys(overrides).every((key) => key === "trusted_issuer_public_key" || key === "invocation_id"), `${proofCase.id}: unsupported expected override`);
    check(Object.keys(overrides).length <= 1, `${proofCase.id}: ambiguous expected override`);
    const caseExpected: ExpectedRequest = {
      ...expected,
      ...(overrides.invocation_id === undefined ? {} : { invocationId: overrides.invocation_id }),
      ...(overrides.trusted_issuer_public_key === undefined ? {} : {
        trustedIssuer: { ...expected.trustedIssuer, publicKey: base64urlDecode(strUtf8(overrides.trusted_issuer_public_key)) },
      }),
    };
    const decodeLocal = decodeLocalLoopbackHttpProof(compact).ok;
    const decodeStandard = decodeProof(compact).ok;
    const envelopeLocal = checkLocalLoopbackHttpEnvelope(strUtf8(profile.grant_compact), compact, caseExpected).ok;
    const projection = `decode_local=${decodeLocal};decode_standard=${decodeStandard};envelope_local=${envelopeLocal}`;
    verdicts.push([proofCase.id, projection]);
    const want = `decode_local=${proofCase.decode_local};decode_standard=${proofCase.decode_standard};envelope_local=${proofCase.envelope_local}`;
    if (projection !== want) failures.push(`${proofCase.id}: expected ${want}, got ${projection}`);
  }
  return {
    verdicts,
    failures,
    summary: [
      `${PREFIX}: ${verdicts.length - failures.length}/${verdicts.length} cases agree (${index.uri_cases} URI, ${index.proof_cases} proof; index SHA-256 ${CERTIFIED_INDEX_SHA256.slice(0, 8)}…), producer/assembly byte symmetry for the ipv4 and ipv6 proofs`,
    ],
  };
}

export const core: Core = {
  corpus: "local-loopback-http",
  dir: DIR,
  run: (source: CorpusSource) => ({ corpus: "local-loopback-http", ...main(source) }),
};
