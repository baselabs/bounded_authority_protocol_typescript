// The facts protocol (spec/bap-v1.md: "Facts are value-bearing and redacted, with fixed redacted
// rendering and no generic encoder, string, or enumeration protocol", REQ1-VERIFY-facts-redacted; the
// content-assertion profile: "Inspection MUST redact values"). A facts value:
//   - is value-bearing: every field reads by name, as a non-enumerable, read-only property;
//   - has a fixed redacted rendering: Node's, Deno's and Bun's inspection (the
//     nodejs.util.inspect.custom hook), String(), template literals and JSON.stringify (toJSON) all
//     yield #BoundedAuthorityProtocol.<Module><redacted>, the Elixir reference's Inspect text;
//   - enumerates nothing: Object.keys, for-in and spreading see no field.
// The value is frozen.
const INSPECT = Symbol.for("nodejs.util.inspect.custom");

const hidden = (value: unknown): PropertyDescriptor => ({ value, enumerable: false, writable: false, configurable: false });

export function redacted<T extends object>(fields: T, module: string): T {
  const rendering = `#BoundedAuthorityProtocol.${module}<redacted>`;
  const render = (): string => rendering;
  const facts = {};
  for (const [name, value] of Object.entries(fields)) Object.defineProperty(facts, name, hidden(value));
  Object.defineProperties(facts, {
    toJSON: hidden(render),
    toString: hidden(render),
    [Symbol.toPrimitive]: hidden(render),
    [INSPECT]: hidden(render),
  });
  return Object.freeze(facts) as T;
}

// Redacted inspection only, for a decoded (not verified) value that the Elixir reference also
// inspects as redacted: its fields stay ordinary enumerable data.
export function redactedInspection<T extends object>(value: T, module: string): T {
  const rendering = `#BoundedAuthorityProtocol.${module}<redacted>`;
  Object.defineProperty(value, INSPECT, hidden(() => rendering));
  return value;
}
