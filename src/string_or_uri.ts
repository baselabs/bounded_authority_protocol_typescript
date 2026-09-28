import { ipv6GroupShape } from "./ip_literal.js";
// Internal RFC 7519 StringOrURI admission shared by every protocol profile.
// This validates component syntax without normalizing identifier bytes.
function isWellFormed(s: string): boolean {
  const anyStr = s as string & { isWellFormed?: () => boolean };
  return typeof anyStr.isWellFormed === "function"
    ? anyStr.isWellFormed()
    : !/[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?:^|[^\uD800-\uDBFF])[\uDC00-\uDFFF]/.test(s);
}

export function isStringOrUri(s: string): boolean {
  if (!isWellFormed(s)) return false;
  const colon = s.indexOf(":");
  if (colon === -1) return true; // bare string: always a StringOrURI
  const scheme = s.slice(0, colon);
  if (!/^[A-Za-z][A-Za-z0-9+\-.]*$/.test(scheme)) return false;
  // uri_bytes shape: unreserved + reserved punctuation, or a %HH escape.
  if (!/^(?:%[0-9A-Fa-f]{2}|[A-Za-z0-9\-._~:/?#[\]@!$&'()*+,;=])*$/.test(s)) return false;
  // RFC 3986: fragment occurs at most once; raw brackets belong only to IP literals.
  if (s.indexOf("#") !== s.lastIndexOf("#")) return false;
  const rest = s.slice(colon + 1);
  const authority = rest.startsWith("//") ? rest.slice(2).split(/[/?#]/, 1)[0]! : null;
  const pathQueryFragment = authority === null ? rest : rest.slice(2 + authority.length);
  if (/[\[\]]/.test(pathQueryFragment)) return false;
  return authority === null || validUriAuthority(authority);
}

// RFC 3986 authority validation matching URI.new for the cases the profile can produce.
function validUriAuthority(authority: string): boolean {
  const at = authority.indexOf("@");
  if (at !== -1 && /[\[\]]/.test(authority.slice(0, at))) return false;
  const hostport = at === -1 ? authority : authority.slice(at + 1);
  if (hostport.includes("@")) return false; // a second @ lands in the host — invalid.
  if (hostport.startsWith("[")) {
    const close = hostport.indexOf("]");
    if (close === -1) return false; // unterminated IPv6 literal.
    if (!isIpv6(hostport.slice(1, close))) return false;
    const suffix = hostport.slice(close + 1);
    return suffix === "" || /^:\d*$/.test(suffix);
  }
  if (hostport.includes("[") || hostport.includes("]")) return false; // stray bracket in host.
  if ((hostport.match(/:/g) ?? []).length > 1) return false; // host/port ambiguity.
  const sep = hostport.lastIndexOf(":");
  return sep === -1 || /^\d*$/.test(hostport.slice(sep + 1));
}

function isIpv6(literal: string): boolean {
  // StringOrURI rejects a dotted group before a later colon, including before ::.
  // The target-URI normalizer has distinct observed group-shape semantics; no normalization here.
  if (literal.includes(".") && literal.indexOf(".") < literal.lastIndexOf(":")) return false;
  return ipv6GroupShape(literal);
}

