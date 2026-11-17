import { fail } from "./error.js";
import { jcsEncode } from "./jcs.js";
import { utf8Str, type Tagged } from "./json.js";
import { typedProject } from "./digest.js";
import { resolve, type Bounds, MAXIMUM_BOUNDS, type MaximaKey } from "./bounds.js";

// Closed selector algebra (spec/bap-v1.md § Selectors, L179-199; REQ1-SELECTOR-closed-set).
// Three recognized member sets. `all` may use any of them and ignores the
// other members; equals and one_of use their matching three-member set:
//   all      → {kind} | {kind,path,value} | {kind,path,values}
//   equals   → {kind:"equals", path:[names], value:<JSON>}
//   one_of   → {kind:"one_of", path:[names], values:[<JSON>...]}
// path is an array of object-member names (1..32, each 1..128 bytes) traversing OBJECTS only.
// Semantic identity (REQ1-SELECTOR-semantic-identity) = JCS of the typed-projected form, so the
// int/float distinction survives (REQ1-SELECTOR-no-tag-collapse).

/**
 * A validated closed selector. all always matches; equals and one_of compare tagged semantic identity.
 * Paths traverse objects only; missing members refuse. Integer and float tags never collapse.
 * Constraints alone make no authorization decision.
 * @see https://github.com/baselabs/bounded_authority_protocol/blob/main/spec/bap-v1.md#selectors
 */
export type Selector = {
    /** Unrestricted selector; other recognized wire members are inert. */
    readonly kind: "all";
  }
  | {
    /** Require exact tagged semantic equality at path. */
    readonly kind: "equals";
    /** Object-member path: 1 to 32 names of 1 to 128 UTF-8 bytes each; array indices are unsupported. */
    readonly path: string[];
    /** Tagged equality candidate; object member order is irrelevant. */
    readonly value: Tagged;
  }
  | {
    /** Require membership in the tagged candidate set at path. */
    readonly kind: "one_of";
    /** Object-member path: 1 to 32 names of 1 to 128 UTF-8 bytes each; array indices are unsupported. */
    readonly path: string[];
    /** Nonempty list of at most 256 tagged candidates, compared without collapsing integer and float tags. */
    readonly values: Tagged[];
  };

const SELECTOR_KINDS = new Set(["all", "equals", "one_of"]);
const SELECTOR_MEMBER_SETS = new Set(["kind", "kind,path,value", "kind,path,values"]);

/**
 * Validates a decoded selector object for major 1 (`all`, `equals`, `one_of`). Throws
 * `InvalidError` otherwise.
 * @see https://github.com/baselabs/bounded_authority_protocol/blob/main/spec/bap-v1.md#selectors
 * @returns The validated selector with its closed discriminant and typed operands.
 * @throws InvalidError when the documented representation or resource limits are violated.
 */
export function parseSelector(obj: Tagged, bounds: Bounds = MAXIMUM_BOUNDS): Selector {
  if (obj.t !== "object") fail("selector: object");
  const kindV = obj.v.get("kind");
  if (!kindV || kindV.t !== "string") fail("selector: kind");
  const kind = utf8Str(kindV.v);
  if (!SELECTOR_KINDS.has(kind)) fail("selector: kind closed set");
  const memberSet = [...obj.v.keys()].sort().join(",");
  if (!SELECTOR_MEMBER_SETS.has(memberSet)) fail("selector: member set");
  // The reference accepts kind:"all" on any recognized member set. The
  // path/value(s) are inert and need not satisfy the active-kind shapes.
  if (kind === "all") return { kind: "all" };
  // equals / one_of need path + value/values.
  if (kind === "equals") {
    if (obj.v.size !== 3) fail("selector: equals members");
    const path = parsePath(obj.v.get("path"), bounds);
    const value = obj.v.get("value") ?? fail("selector: value");
    validateSelectorValue(value, bounds);
    if (!floatZeroFree(value)) fail("selector: float zero");
    return { kind: "equals", path, value };
  }
  // one_of
  if (obj.v.size !== 3) fail("selector: one_of members");
  const path = parsePath(obj.v.get("path"), bounds);
  const valuesV = obj.v.get("values") ?? fail("selector: values");
  if (valuesV.t !== "array") fail("selector: values array");
  if (valuesV.v.length < 1 || valuesV.v.length > resolve(bounds, "one_of_values" as MaximaKey)) {
    fail("selector: values count");
  }
  const values = valuesV.v.map((v) => {
    validateSelectorValue(v, bounds);
    if (!floatZeroFree(v)) fail("selector: float zero");
    return v;
  });
  return { kind: "one_of", path, values };
}

function parsePath(pathV: Tagged | undefined, bounds: Bounds): string[] {
  if (!pathV || pathV.t !== "array") fail("selector: path array");
  if (pathV.v.length < 1 || pathV.v.length > resolve(bounds, "path_segments" as MaximaKey)) {
    fail("selector: path length");
  }
  const names: string[] = [];
  for (const seg of pathV.v) {
    if (seg.t !== "string") fail("selector: path segment string");
    const b = seg.v;
    if (b.length < 1 || b.length > resolve(bounds, "key_bytes" as MaximaKey)) fail("selector: path segment bytes");
    names.push(utf8Str(b));
  }
  return names;
}

function validateSelectorValue(v: Tagged, bounds: Bounds): void {
  // Per-node bounds on selector values (depth, members, items, string, magnitude).
  checkNode(v, 1, bounds);
}

function checkNode(v: Tagged, depth: number, bounds: Bounds): void {
  if (depth > resolve(bounds, "depth" as MaximaKey)) fail("selector: value depth");
  switch (v.t) {
    case "string":
      if (v.v.length > resolve(bounds, "string_bytes" as MaximaKey)) fail("selector: string bytes");
      return;
    case "int":
      if (Math.abs(v.v) > resolve(bounds, "integer_magnitude" as MaximaKey)) fail("selector: int magnitude");
      return;
    case "float":
      if (Math.abs(v.v) > resolve(bounds, "float_magnitude" as MaximaKey)) fail("selector: float magnitude");
      return;
    case "array": {
      if (v.v.length > resolve(bounds, "array_items" as MaximaKey)) fail("selector: array items");
      for (const item of v.v) checkNode(item, depth + 1, bounds);
      return;
    }
    case "object": {
      if (v.v.size > resolve(bounds, "object_members" as MaximaKey)) fail("selector: object members");
      for (const [, val] of v.v) checkNode(val, depth + 1, bounds);
      return;
    }
    default: return;
  }
}

// Erratum 6 (selector float-zero soundness), one walker for every contract-major and both sides.
// RFC 8785 writes every float-tagged zero (0.0, -0.0, 0e0, 1e-400, ...) as the integer text "0",
// so a signed grant could not keep the float tag its issuer meant; and a float-tagged integral
// value of any size loses its tag the same way. The checks key on the decoded value, never the
// lexeme, so every spelling is covered. Callers run them after the per-node bound checks.
function everyFloat(v: Tagged, admissible: (n: number) => boolean): boolean {
  switch (v.t) {
    case "float": return admissible(v.v);
    case "array": return v.v.every((item) => everyFloat(item, admissible));
    case "object": {
      for (const [, member] of v.v) if (!everyFloat(member, admissible)) return false;
      return true;
    }
    default: return true;
  }
}

// Verification (REQ1/2/3-SELECTOR-float-zero): an `equals` value or `one_of` member is admissible
// only when it holds no float-tagged zero, of either sign, at any depth. Not applied to `lte`/`gte`
// bounds (they compare numerically, -0.0 = 0.0) or to the inert members of `all`.
export function floatZeroFree(v: Tagged): boolean {
  return everyFloat(v, (n) => n !== 0);
}

// Producer selector values for equals, one_of, lte and gte must contain no float-tagged
// integral number at any depth. See REQ1/REQ2/REQ3-SIGNING-integral-float-selector.
export function integralFloatFree(v: Tagged): boolean {
  return everyFloat(v, (n) => !Number.isInteger(n));
}

/**
 * The canonical bytes selectors compare: the JCS of the typed projection. Member order does not
 * matter; integer and float tags do.
 * @see https://github.com/baselabs/bounded_authority_protocol/blob/main/spec/bap-v1.md#selectors
 * @returns RFC 8785 canonical UTF-8 bytes of the typed projection.
 * @throws InvalidError when the documented representation or resource limits are violated.
 */
export function semanticIdentity(value: Tagged): Uint8Array {
  return jcsEncode(typedProject(value));
}

// Traverse a path over an OBJECT (paths never index arrays). Returns the value or undefined.
function traversePath(root: Tagged, path: string[]): Tagged | undefined {
  let cur: Tagged | undefined = root;
  for (const name of path) {
    if (!cur || cur.t !== "object") return undefined;
    cur = cur.v.get(name);
  }
  return cur;
}

/**
 * Applies one parsed major-1 selector to the cast arguments. A missing path never matches.
 * @see https://github.com/baselabs/bounded_authority_protocol/blob/main/spec/bap-v1.md#selectors
 * @returns Whether the parsed selector matches. A missing path or a value/tag mismatch returns `false`.
 * @throws InvalidError if computing tagged identity violates the bounded JSON contract.
 */
export function selectorMatches(sel: Selector, castArguments: Tagged): boolean {
  if (sel.kind === "all") return true;
  const target = traversePath(castArguments, sel.path);
  if (target === undefined) return false; // path required
  const targetId = semanticIdentity(target);
  if (sel.kind === "equals") {
    return bytesEqual(semanticIdentity(sel.value), targetId);
  }
  // one_of
  for (const v of sel.values) {
    if (bytesEqual(semanticIdentity(v), targetId)) return true;
  }
  return false;
}

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}
