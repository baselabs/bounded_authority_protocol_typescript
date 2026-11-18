import { fail, trying, type Result } from "./error.js";
import { sha256 } from "./ed25519.js";
import { jcsEncode } from "./jcs.js";
import { base64urlEncode } from "./base64url.js";
import { strUtf8, type Tagged } from "./json.js";
import { resolve, coerceBounds, type Bounds, MAXIMUM_BOUNDS, type MaximaKey } from "./bounds.js";

/**
 * Exact 13-byte ASCII domain separator `BAP1-REQUEST\0` for request hashing. Treat these bytes as
 * immutable; mutation changes the wire contract.
 * @see https://github.com/baselabs/bounded_authority_protocol/blob/main/spec/bap-v1.md#datamodel
 * @category Canonical bytes
 */
export const REQUEST_PREFIX = new Uint8Array([
  0x42, 0x41, 0x50, 0x31, 0x2d, 0x52, 0x45, 0x51, 0x55, 0x45, 0x53, 0x54, 0x00, // "BAP1-REQUEST\0"
]);

/**
 * The typed projection behind request digests and selector identity. Null becomes `["null"]`;
 * every other value becomes `[tag, value]` with recursively projected containers.
 * @see https://github.com/baselabs/bounded_authority_protocol/blob/main/spec/bap-v1.md#datamodel
 * @returns The recursively tagged projection; null projects to ["null"] and other variants to [tag, value].
 * @throws InvalidError for an unknown variant tag. This low-level projection requires a well-formed Tagged value; it does not validate bounds.
 * @category Canonical bytes
 * @example
 * ```ts
 * import assert from "node:assert/strict";
 * import * as api from "@bounded-authority-protocol/verifier";
 * assert.equal(api.typedProject({ t: "null" }).t, "array");
 * ```
 */
export function typedProject(value: Tagged): Tagged {
  switch (value.t) {
    case "null": return { t: "array", v: [{ t: "string", v: strUtf8("null") }] };
    case "bool": return { t: "array", v: [{ t: "string", v: strUtf8("boolean") }, { t: "bool", v: value.v }] };
    case "int": return { t: "array", v: [{ t: "string", v: strUtf8("integer") }, { t: "int", v: value.v }] };
    case "float": return { t: "array", v: [{ t: "string", v: strUtf8("float") }, { t: "float", v: value.v }] };
    case "string": return { t: "array", v: [{ t: "string", v: strUtf8("string") }, { t: "string", v: value.v }] };
    case "array": return { t: "array", v: [{ t: "string", v: strUtf8("array") }, { t: "array", v: value.v.map(typedProject) }] };
    case "object": {
      const out = new Map<string, Tagged>();
      for (const [k, v] of value.v) out.set(k, typedProject(v));
      return { t: "array", v: [{ t: "string", v: strUtf8("object") }, { t: "object", v: out }] };
    }
    default: fail("typed: unknown tag");
  }
}

// Validate the operation as 1 to 128 printable ASCII bytes and hash the typed argument
// projection with the selected major-specific domain separator. The request-digest algorithm is
// otherwise shared across majors.
export function requestDigest(operation: string, castArguments: Tagged, bounds: Bounds = MAXIMUM_BOUNDS): Uint8Array {
  return digestWithPrefix(REQUEST_PREFIX, operation, castArguments, bounds);
}

// The major-independent digest core: SHA-256(prefix || JCS([operation, typed(cast_arguments)])).
// The domain separator is the only per-major input (REQ1-SIGNING-digest-prefix; the v2 profile
// uses BAP2-REQUEST\0 as defined in spec/bap-v2.md#substitutions).
export function digestWithPrefix(
  prefix: Uint8Array,
  operation: string,
  castArguments: Tagged,
  bounds: Bounds = MAXIMUM_BOUNDS,
): Uint8Array {
  // Re-validate caller-supplied bounds (Bounds is a structural interface; a caller can hand-craft
  // widening overrides that bypass boundsNew). Mirrors the reference's Bounds.coerce.
  const b = coerceBounds(bounds);
  // operation: 1..operation_bytes, printable ASCII.
  const opBytes = strUtf8(operation);
  if (opBytes.length < 1 || opBytes.length > resolve(b, "operation_bytes" as MaximaKey)) {
    fail("request_digest: operation bound");
  }
  for (let i = 0; i < opBytes.length; i++) {
    const byte = opBytes[i]!;
    if (byte < 0x20 || byte > 0x7e) fail("request_digest: operation printable ASCII");
  }
  // The projection: [operation_string, typed(cast_arguments)].
  const projected = typedProject(castArguments);
  const array: Tagged = { t: "array", v: [{ t: "string", v: opBytes }, projected] };
  // Per-node bounds on the TYPED projection (not the raw args): `typed` deepens/triples the tree, so
  // the depth boundary is ~15 (not 32) and total_nodes is reachable inline. Mirrors the Elixir
  // reference's per-node JCS gate.
  if (!withinTaggedBounds(array, 0, b)) fail("request_digest: cast_arguments bounds");
  if (countTaggedNodes(array) > resolve(b, "total_nodes" as MaximaKey)) fail("request_digest: total_nodes");
  // JCS over the projection, enforcing jcs_bytes bound.
  const jcs = jcsEncode(array, b);
  if (jcs.length > resolve(b, "jcs_bytes" as MaximaKey)) fail("request_digest: jcs_bytes bound");
  const digest = sha256(prefix, jcs);
  return digest; // raw 32 bytes
}

// Per-node-type bounds gate over the tagged algebra: a SCALAR is valid at level <= depth; a
// CONTAINER at level < depth (its children sit at level+1). Root value at level 0. Also enforces
// members/items/string-bytes/magnitude per node.
function withinTaggedBounds(v: Tagged, level: number, bounds: Bounds): boolean {
  switch (v.t) {
    case "null":
    case "bool":
      return level <= resolve(bounds, "depth" as MaximaKey);
    case "int":
      return level <= resolve(bounds, "depth" as MaximaKey) && Math.abs(v.v) <= resolve(bounds, "integer_magnitude" as MaximaKey);
    case "float":
      return level <= resolve(bounds, "depth" as MaximaKey) && Number.isFinite(v.v) && Math.abs(v.v) <= resolve(bounds, "float_magnitude" as MaximaKey);
    case "string":
      return level <= resolve(bounds, "depth" as MaximaKey) && v.v.length <= resolve(bounds, "string_bytes" as MaximaKey);
    case "array":
      return level < resolve(bounds, "depth" as MaximaKey)
        && v.v.length <= resolve(bounds, "array_items" as MaximaKey)
        && v.v.every((item) => withinTaggedBounds(item, level + 1, bounds));
    case "object":
      return level < resolve(bounds, "depth" as MaximaKey)
        && v.v.size <= resolve(bounds, "object_members" as MaximaKey)
        && [...v.v.values()].every((val) => withinTaggedBounds(val, level + 1, bounds));
  }
}

// Node count: one node per value (scalar OR container); object keys are not nodes. Mirrors the
// official next_node! (jcs.ex:105) for the total_nodes gate on the typed projection.
function countTaggedNodes(v: Tagged): number {
  switch (v.t) {
    case "array": return 1 + v.v.reduce((n, item) => n + countTaggedNodes(item), 0);
    case "object": return 1 + [...v.v.values()].reduce((n, val) => n + countTaggedNodes(val), 0);
    default: return 1;
  }
}

// Base64url-encoded form (for comparison against proof.ba_req which is base64url). Returns
// Ok<string> | Err.
export function requestDigestB64url(operation: string, castArguments: Tagged, bounds: Bounds = MAXIMUM_BOUNDS): Result<string> {
  return trying(() => {
    const raw = requestDigest(operation, castArguments, bounds);
    return new TextDecoder().decode(base64urlEncode(raw));
  });
}
