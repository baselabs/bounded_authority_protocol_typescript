import { fail } from "./error.js";

// The facts protocol, as the Elixir reference implements it (spec/bap-v1.md: "Facts are value-bearing
// and redacted, with fixed redacted rendering and no generic encoder, string, or enumeration
// protocol", REQ1-VERIFY-facts-redacted; the content-assertion profile: "Inspection MUST redact
// values"). Elixir facts are maps whose fields read and copy normally; their Inspect renders
// #BoundedAuthorityProtocol.<Module><redacted>, and with no Jason.Encoder and no String.Chars, JSON
// encoding and to_string fail loudly. A facts value here is therefore:
//   - a frozen (shallowly: the Uint8Array fields stay ordinary byte arrays) object whose fields are
//     ordinary enumerable, read-only properties, so they read, spread, structuredClone and compare
//     by content;
//   - rendered redacted by Node's, Deno's and Bun's inspection (the nodejs.util.inspect.custom hook);
//     browser developer tools ignore that hook and may show the fields;
//   - not serializable or stringifiable: toJSON (so JSON.stringify), toString and Symbol.toPrimitive
//     (so String(), template literals and +) throw InvalidError naming the rule.
// The hooks are non-enumerable symbol or method properties, so copies carry the fields only.
const INSPECT = Symbol.for("nodejs.util.inspect.custom");

const hidden = (value: unknown): PropertyDescriptor => ({ value, enumerable: false, writable: false, configurable: false });

export function redacted<T extends object>(fields: T, module: string): T {
  const rendering = `#BoundedAuthorityProtocol.${module}<redacted>`;
  const refuse = (what: string) => (): never =>
    fail(`${rendering}: facts have no ${what} (REQ1-VERIFY-facts-redacted); read the fields you need by name`);
  Object.defineProperties(fields, {
    [INSPECT]: hidden(() => rendering),
    toJSON: hidden(refuse("JSON encoding")),
    toString: hidden(refuse("string conversion")),
    [Symbol.toPrimitive]: hidden(refuse("primitive conversion")),
  });
  return Object.freeze(fields);
}

// Redacted inspection only, for a decoded (not verified) value that the Elixir reference also
// inspects as redacted.
export function redactedInspection<T extends object>(value: T, module: string): T {
  const rendering = `#BoundedAuthorityProtocol.${module}<redacted>`;
  Object.defineProperty(value, INSPECT, hidden(() => rendering));
  return value;
}

// Approval results use a static rendering in inspection, string and JSON output.
export function redactedRendering<T extends object>(fields: T, name: string): T {
  const render = () => `#BoundedAuthorityProtocol.${name}<redacted>`;
  return staticRendering(fields, render);
}

export function staticRendering<T extends object>(fields: T, render: () => string, markers: readonly (keyof T)[] = []): T {
  // Browser inspectors ignore the Node hook. Store values behind named getters so default
  // previews, enumeration and descriptor inspection expose only the public markers.
  for (const key of Reflect.ownKeys(fields) as (keyof T)[]) {
    if (markers.includes(key)) continue;
    const value = fields[key];
    Object.defineProperty(fields, key, {get: () => value, enumerable: false, configurable: false});
  }
  Object.defineProperties(fields, {
    [INSPECT]: hidden(render), toJSON: hidden(render), toString: hidden(render),
    [Symbol.toPrimitive]: hidden(render),
  });
  return Object.freeze(fields);
}
