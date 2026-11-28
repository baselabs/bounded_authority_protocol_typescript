import * as api from "../../src/index.js";
import type { Result } from "../../src/error.js";
import { corpusDir } from "../certification.js";
import { CoreAbort } from "./types.js";
import { acceptsCompact, candidateCore, check, fixture, project, raw, take } from "./candidate.js";

const hca = api.holderCustodyAttestation;
const corpus = "holder-custody-attestation";
const dir = corpusDir(corpus);

interface Subject {
  readonly key_id: string;
  readonly public_key: string;
}

interface Profile {
  readonly profile: string;
  readonly revision: number;
  readonly attestor: Subject & { readonly valid_from: number; readonly valid_before: number | "unbounded" };
  readonly subject: Subject;
  readonly now: number;
  readonly signing: {
    readonly payload: { readonly jti: string; readonly custody_class: "standard" | "hosted"; readonly nbf: number; readonly exp: number } & Subject;
    readonly compact: string;
    readonly signature: string;
  };
}

function signingInput(compact: string): api.SigningInput {
  const [header, payload] = compact.split(".");
  return {kind: "holder_custody_attestation", protectedSegment: api.strUtf8(header!), payloadSegment: api.strUtf8(payload!)};
}

function outcome<T>(result: Result<T>, projectValue: (value: T) => unknown = project): unknown {
  if (result.ok) return projectValue(result.value);
  check(result, {ok: false}, "closed attestation failure");
  return "invalid";
}

export const core = candidateCore(corpus, dir, (source, cases) => {
  const profile = JSON.parse(api.utf8Str(source.read(`${dir}/profile.json`))) as Profile;
  check(profile.profile, "bap-holder-custody-attestation/1", "profile identity");
  check(profile.revision, 1, "profile revision");

  const {payload, compact, signature} = profile.signing;
  const producer = {
    keyId: profile.attestor.key_id, jti: payload.jti, subjectKeyId: payload.key_id,
    subjectPublicKey: raw(payload.public_key), custodyClass: payload.custody_class,
    notBefore: payload.nbf, expiresAt: payload.exp,
  };
  const signed = raw(signature);
  const atBound = api.boundsNew({anchor_bytes: compact.length});
  const belowBound = api.boundsNew({anchor_bytes: compact.length - 1});
  const produced = take(hca.attestationSigningInput(producer, atBound));
  check(project(produced), project(signingInput(compact)), "exact signing input");
  check(api.utf8Str(take(hca.assembleAttestationCompact(produced, signed, atBound))), compact, "exact compact");
  check(hca.attestationSigningInput(producer, belowBound), {ok: false}, "producer anchor bound");
  check(hca.assembleAttestationCompact(produced, signed, belowBound), {ok: false}, "assembly anchor bound");
  const foreignKind = {...produced, kind: "role_attestation" as const};
  check(hca.assembleAttestationCompact(foreignKind, signed), {ok: false}, "assembly rejects foreign kind");
  for (const profile of [api, api.v2, api.v3]) {
    check(profile.assembleCompact(produced, signed), {ok: false}, "foreign assembler rejects custody kind");
  }
  for (const id of ["unknown-custody-class", "wrong-typ", "noncanonical-payload", "noncanonical-scalar", "small-order-r"]) {
    const invalid = cases.find(c => c.id === id)?.data.compact;
    if (typeof invalid !== "string") throw new CoreAbort(corpus, `missing assembly fixture ${id}`);
    check(hca.assembleAttestationCompact(signingInput(invalid), raw(invalid.split(".")[2]!)), {ok: false}, `assembly rejects ${id}`);
  }
  return profile;
}, ({id, file, data}, profile) => {
  if (file === "custody-separation-cases.json") {
    const candidate = api.strUtf8(data.candidate as string);
    check(hca.decodeAttestation(candidate).ok, true, `${id}: custody positive control`);
    const foreign = data.foreign as string;
    if (id === "action-approval-record") {
      const record = raw(foreign);
      check(api.actionApproval.decodeRecord(record).ok, true, `${id}: foreign positive control`);
      return !hca.decodeAttestation(record).ok && !api.actionApproval.decodeRecord(candidate).ok
        ? "both_reject" : "unexpected";
    }
    check(acceptsCompact(id, foreign), true, `${id}: foreign positive control`);
    return !hca.decodeAttestation(api.strUtf8(foreign)).ok && !acceptsCompact(id, data.candidate as string)
      ? "both_reject" : "unexpected";
  }
  if (file !== "attestation-cases.json") throw new CoreAbort(corpus, `unknown case family ${file}`);
  const compact = api.strUtf8(data.compact as string);
  const subject = (data.subject ?? profile.subject) as Subject;
  const expected = fixture({
    attestor: data.attestor ?? profile.attestor,
    subject_key_id: subject.key_id,
    now: data.now ?? profile.now,
    bounds: data.bounds ?? {},
  }) as Omit<api.holderCustodyAttestation.ExpectedAttestation, "subjectPublicKey">;
  const decoded = hca.decodeAttestation(compact, expected.bounds);
  const verified = hca.verifyAttestation(compact, {...expected, subjectPublicKey: raw(subject.public_key)});
  return {
    decode: outcome(decoded, ({keyId, subjectKeyId, subjectPublicKey, notBefore, expiresAt, ...fields}) =>
      project({...fields, attestorKeyId: keyId, keyId: subjectKeyId, publicKey: subjectPublicKey, nbf: notBefore, exp: expiresAt})),
    verify: outcome(verified, ({notBefore, expiresAt, ...fields}) => project({...fields, nbf: notBefore, exp: expiresAt})),
  };
});
