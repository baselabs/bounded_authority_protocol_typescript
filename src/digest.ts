import { fail, trying, type Result } from "./error.js";
import { sha256 } from "./ed25519.js";
import { jcsEncode } from "./jcs.js";
import { base64urlEncode } from "./base64url.js";
import { strUtf8, type Tagged } from "./json.js";
import { resolve, type Bounds, MAXIMUM_BOUNDS, type MaximaKey } from "./bounds.js";

// The request digest (protocol-v1.md § Signing and digest inputs, L238-264):
//   base64url(SHA-256("BAP1-REQUEST\0" || JCS([operation, typed(cast_arguments)])))
// The prefix is exact ASCII including its final zero byte (REQ1-SIGNING-digest-prefix). typed()
// projects the tagged JSON algebra to the closed ["tag", value] JSON form before JCS, preserving the
// int/float distinction (REQ1-SELECTOR-semantic-identity depends on it).
export const REQUEST_PREFIX = new Uint8Array([
  0x42, 0x41, 0x50, 0x31, 0x2d, 0x52, 0x45, 0x51, 0x55, 0x45, 0x53, 0x54, 0x00, // "BAP1-REQUEST\0"
]);

// typed() projection: tagged value → ["tag", value] JSON array (protocol-v1.md:247-256).
//   :null → ["null"]; bool → ["boolean",v]; int → ["integer",v]; float → ["float",v];
//   string → ["string",v]; array → ["array", [typed(v)...]]; object → ["object", {k: typed(v)...}]
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

// request_digest(operation, cast_arguments, bounds?). operation is validated printable ASCII 1..128.
export function requestDigest(operation: string, castArguments: Tagged, bounds: Bounds = MAXIMUM_BOUNDS): Uint8Array {
  // operation: 1..operation_bytes, printable ASCII.
  const opBytes = strUtf8(operation);
  if (opBytes.length < 1 || opBytes.length > resolve(bounds, "operation_bytes" as MaximaKey)) {
    fail("request_digest: operation bound");
  }
  for (let i = 0; i < opBytes.length; i++) {
    const b = opBytes[i]!;
    if (b < 0x20 || b > 0x7e) fail("request_digest: operation printable ASCII");
  }
  // The projection: [operation_string, typed(cast_arguments)].
  const projected = typedProject(castArguments);
  const array: Tagged = { t: "array", v: [{ t: "string", v: opBytes }, projected] };
  // Per-node bounds on the TYPED projection (not the raw args): `typed` deepens/triples the tree, so
  // the depth boundary is ~15 (not 32) and total_nodes is reachable inline. Mirrors the official
  // Jcs.encode per-node gate (corpus_independent.mjs:1913 withinJsonBounds + countJsonNodes).
  if (!withinTaggedBounds(array, 0, bounds)) fail("request_digest: cast_arguments bounds");
  if (countTaggedNodes(array) > resolve(bounds, "total_nodes" as MaximaKey)) fail("request_digest: total_nodes");
  // JCS over the projection, enforcing jcs_bytes bound.
  const jcs = jcsEncode(array, bounds);
  if (jcs.length > resolve(bounds, "jcs_bytes" as MaximaKey)) fail("request_digest: jcs_bytes bound");
  const digest = sha256(REQUEST_PREFIX, jcs);
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

// base64url-encoded form (for comparison against proof.ba_req which is base64url). Returns
// Ok<string> | Err (cross-vendor #21 + the bounds-ignored note: thread bounds into the digest).
export function requestDigestB64url(operation: string, castArguments: Tagged, bounds: Bounds = MAXIMUM_BOUNDS): Result<string> {
  return trying(() => {
    const raw = requestDigest(operation, castArguments, bounds);
    return new TextDecoder().decode(base64urlEncode(raw));
  });
}
