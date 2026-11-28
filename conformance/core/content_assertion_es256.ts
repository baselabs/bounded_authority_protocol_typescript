import * as api from "../../src/index.js";
import { ES256_FACTS } from "../../src/content_assertion_stages.js";
import { utf8Str, strUtf8 } from "../../src/json.js";
import { boundsNew } from "../../src/bounds.js";
import { trying } from "../../src/error.js";
import { corpusDir } from "../certification.js";
import { base64url } from "../digest.js";
import { CoreAbort } from "./types.js";
import { candidateCore, check, fixture, project, raw, take } from "./candidate.js";

const ca = api.contentAssertionEs256;
type Producer = api.contentAssertionEs256.ContentAssertionProducer;
type Facts = api.contentAssertionEs256.ContentAssertionFacts;
const dir = corpusDir("content-assertion-es256");

function foreign(id: string, compact: string): boolean {
  const bytes = strUtf8(compact);
  if (id === "ca1") return api.contentAssertion.decodeAssertion(bytes).ok;
  if (id === "role-attestation") return api.roleAttestation.decodeAttestation(bytes).ok;
  if (id === "loopback") return api.decodeLocalLoopbackHttpProof(bytes).ok;
  const [major, artifact] = id.split("-");
  const profile = major === "v1" ? api : major === "v2" ? api.v2 : api.v3;
  if (artifact === "grant") return profile.decodeGrant(bytes).ok;
  if (artifact === "proof") return profile.decodeProof(bytes).ok;
  const [header, payload, signature] = compact.split(".");
  if (artifact !== "anchor" && artifact !== "transition") throw new CoreAbort("candidate conformance", "unknown compact profile");
  return profile.assembleCompact({
    kind: artifact === "anchor" ? "boundary_anchor" : "key_transition",
    protectedSegment: strUtf8(header!), payloadSegment: strUtf8(payload!),
  }, raw(signature!)).ok;
}

export const core = candidateCore("content-assertion-es256", dir, source => {
  const {signing} = JSON.parse(utf8Str(source.read(`${dir}/profile.json`))) as {
    signing: {payload: Record<string, unknown>; kid: string; expected: unknown; signature: string; compact: string};
  };
  const producer = fixture({...signing.payload, attestor_key_id: signing.kid}) as Producer;
  const input = take(ca.assertionSigningInput(producer));
  const protected_segment = utf8Str(input.protectedSegment), payload_segment = utf8Str(input.payloadSegment);
  check({kind: input.kind, protected_segment, payload_segment, message: `${protected_segment}.${payload_segment}`}, signing.expected, "exact signing input");
  check(utf8Str(take(ca.assembleCompact(input, raw(signing.signature)))), signing.compact, "exact compact");
  check(api.contentAssertion.assembleCompact(input, raw(signing.signature)).ok, false, "Ed25519 assembler rejects ES256 kind");
  check(api.v3.assembleCompact(input, raw(signing.signature)).ok, false, "grant-major assembler rejects ES256 assertion kind");
  return input;
}, ({id, file, data: c}, input) => {
  switch (file) {
    case "assertion-structure-cases.json": {
      const compact = strUtf8(c.compact as string);
      const bounds = trying(() => boundsNew(c.bounds as Record<string, number>));
      const decoded = bounds.ok ? ca.decodeAssertion(compact, bounds.value) : bounds;
      const digest = bounds.ok ? ca.assertionDigest(compact, bounds.value) : bounds;
      check(digest.ok, decoded.ok, `${id}: structural digest gate`);
      if (!decoded.ok || !digest.ok) return "invalid";
      const projected = project(decoded.value) as Record<string, unknown>;
      delete projected.version;
      delete projected.verification;
      return {...projected, v: 1, digest: base64url(digest.value)};
    }
    case "assertion-verification-cases.json": {
      const context = fixture({...c.context as object, bounds: {}}) as api.contentAssertionEs256.ExpectedContentAssertion;
      const result = ca.verifyAssertion(strUtf8(c.compact as string), context);
      return result.ok ? project(result.value) : "invalid";
    }
    case "digest-cases.json": {
      const bounds = trying(() => boundsNew(c.bounds as Record<string, number>));
      if (!bounds.ok) return "invalid";
      const content = raw(c.input as string);
      const eddsa = api.contentAssertion.contentDigest(content, bounds.value);
      const es256 = ca.contentDigest(content, bounds.value);
      check(project(eddsa), project(es256), `${id}: shared digest`);
      return es256.ok ? base64url(es256.value) : "invalid";
    }
    case "assembly-cases.json": {
      const result = ca.assembleCompact(input, raw(c.signature as string));
      return result.ok ? utf8Str(result.value) : "invalid";
    }
    case "successor-cases.json": {
      const restore = (suite: unknown, input: unknown) => {
        const facts = fixture(input) as Facts;
        return suite === "es256" ? {...facts, [ES256_FACTS]: true as const} : facts;
      };
      const previous = restore(c.previous_suite, c.predecessor), next = restore(c.next_suite, c.successor);
      if (c.previous_suite !== c.next_suite) check(api.contentAssertion.verifySuccessor(previous, next, boundsNew()).ok, false, "Ed25519 mixed lineage");
      return ca.verifySuccessor(previous, next, boundsNew()).ok ? "ok" : "invalid";
    }
    case "separation-cases.json":
      return !ca.decodeAssertion(strUtf8(c.foreign as string)).ok &&
        foreign(id, c.foreign as string) && !foreign(id, c.candidate as string) ? "both_reject" : "unexpected";
    default: throw new CoreAbort("candidate conformance", `unknown ES256 case family ${file}`);
  }
});
