// The fixed redacted rendering of facts (spec/bap-v1.md: "Facts are value-bearing and redacted, with
// fixed redacted rendering and no generic encoder, string, or enumeration protocol";
// REQ1-VERIFY-facts-redacted). The text matches the Elixir reference's Inspect implementations. The hook
// is Node's inspect symbol (console.log and util.inspect read it; other runtimes ignore it), defined
// non-enumerable so field access, Object.keys, spreading and JSON.stringify see only the fields.
const INSPECT = Symbol.for("nodejs.util.inspect.custom");

export function redacted<T extends object>(facts: T, module: string): T {
  const rendering = `#BoundedAuthorityProtocol.${module}<redacted>`;
  Object.defineProperty(facts, INSPECT, { value: () => rendering, enumerable: false });
  return facts;
}
