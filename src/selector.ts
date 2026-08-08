import { fail, assert } from "./error.js";
import { jcsEncode } from "./jcs.js";
import { strUtf8, utf8Str, type Tagged } from "./json.js";
import { typedProject } from "./digest.js";
import { resolve, type Bounds, MAXIMUM_BOUNDS, type MaximaKey } from "./bounds.js";

// Closed selector algebra (protocol-v1.md § Selectors, L179-199; REQ1-SELECTOR-closed-set).
// Three kinds, exact member sets:
//   all      → {kind:"all"}
//   equals   → {kind:"equals", path:[names], value:<JSON>}
//   one_of   → {kind:"one_of", path:[names], values:[<JSON>...]}
// path is an array of object-member names (1..32, each 1..128 bytes) traversing OBJECTS only.
// Semantic identity (REQ1-SELECTOR-semantic-identity) = JCS of the typed-projected form, so the
// int/float distinction survives (REQ1-SELECTOR-no-tag-collapse).

export type Selector =
  | { readonly kind: "all" }
  | { readonly kind: "equals"; readonly path: string[]; readonly value: Tagged }
  | { readonly kind: "one_of"; readonly path: string[]; readonly values: Tagged[] };

const SELECTOR_KINDS = new Set(["all", "equals", "one_of"]);

// Validate + parse a selector from a decoded tagged object. Rejects unknown members, bad shapes.
export function parseSelector(obj: Tagged, bounds: Bounds = MAXIMUM_BOUNDS): Selector {
  if (obj.t !== "object") fail("selector: object");
  const kindV = obj.v.get("kind");
  if (!kindV || kindV.t !== "string") fail("selector: kind");
  const kind = utf8Str(kindV.v);
  if (!SELECTOR_KINDS.has(kind)) fail("selector: kind closed set");
  if (kind === "all") {
    if (obj.v.size !== 1) fail("selector: all members");
    return { kind: "all" };
  }
  // equals / one_of need path + value/values.
  if (kind === "equals") {
    if (obj.v.size !== 3) fail("selector: equals members");
    const path = parsePath(obj.v.get("path"), bounds);
    const value = obj.v.get("value") ?? fail("selector: value");
    validateSelectorValue(value, bounds);
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
  const values = valuesV.v.map((v) => { validateSelectorValue(v, bounds); return v; });
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

// Semantic identity = JCS of the typed-projected form. Returns canonical bytes for comparison.
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

// Does this selector match the given cast_arguments? equals/one_of REQUIRE the path to exist
// (REQ1-SELECTOR-path-required): missing path → no match (not an error).
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
