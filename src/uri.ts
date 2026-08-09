import { fail, type Result, ok, err } from "./error.js";
import { resolve, type Bounds, MAXIMUM_BOUNDS, type MaximaKey } from "./bounds.js";
import { utf8Str, strUtf8 } from "./json.js";

// Bounded HTTPS URI normalization (protocol-v1.md § URI normalization, L201-219; RFC 3986 §6).
// No DNS, IDNA, or network work (REQ1-URI-no-network). Both expected and proof URIs MUST already
// equal the normal form (REQ1-URI-pre-normalized). Reject-list: HTTP, other scheme, authority-less
// form, malformed percent escapes, ambiguous authority/port, control/non-ASCII, out-of-range ports
// (REQ1-URI-reject-list).
//
// Normalization: lowercase scheme + host; uppercase percent hex; decode only percent-encoded
// unreserved octets; preserve percent-encoded reserved octets as path data; remove complete dot
// segments; empty path → "/"; drop port 443; preserve a valid nondefault port + all other path bytes.

export function uriNormalize(input: Uint8Array, bounds: Bounds = MAXIMUM_BOUNDS): Result<Uint8Array> {
  try {
    return ok(strUtf8(normalize(input, bounds)));
  } catch (e) {
    if (e instanceof Error && e.name === "InvalidError") return err();
    throw e;
  }
}

function normalize(input: Uint8Array, bounds: Bounds): string {
  if (input.length > resolve(bounds, "uri_bytes" as MaximaKey)) fail("uri: byte bound");
  const uri = utf8Str(input);
  // UTF-8 validity (re-encode check) + ASCII-only (REQ1-URI-reject-list: control/non-ASCII invalid).
  if (!bytesEqualUtf8(input, uri)) fail("uri: UTF-8");
  if (!/^[\x21-\x7E]+$/.test(uri)) fail("uri: ASCII");
  const match = /^([A-Za-z][A-Za-z0-9+.-]*):\/\/([^/?#]*)([^?#]*)$/.exec(uri);
  if (match === null) fail("uri: hierarchical shape");
  if (match[1]!.toLowerCase() !== "https") fail("uri: scheme");

  const authority = match[2]!;
  if (authority.length === 0 || authority.includes("@")) fail("uri: authority");
  let host = "";
  let port = "";

  if (authority.startsWith("[")) {
    const close = authority.indexOf("]");
    if (close <= 1) fail("uri: IPv6 host");
    const literal = authority.slice(1, close);
    const kind = ipv6Kind(literal);
    if (kind === null) fail("uri: IP-literal syntax");
    host = kind === "future" ? `[${literal}]` : `[${literal.toLowerCase()}]`;
    const suffix = authority.slice(close + 1);
    if (suffix !== "" && !/^:\d+$/.test(suffix)) fail("uri: IPv6 port");
    port = suffix.slice(1);
  } else {
    const colonCount = (authority.match(/:/g) ?? []).length;
    if (colonCount > 1) fail("uri: host/port ambiguity");
    const separator = authority.lastIndexOf(":");
    if (separator >= 0) {
      host = authority.slice(0, separator);
      port = authority.slice(separator + 1);
      if (port.length === 0) fail("uri: empty port");
    } else {
      host = authority;
    }
    if (host.length === 0) fail("uri: host");
    if (/^[0-9.]+$/.test(host)) {
      if (!isCanonicalIpv4(host)) fail("uri: IPv4 syntax");
    } else {
      assertRegName(host);
      host = lowercaseOutsideEscapes(normalizePercentEncoding(host));
    }
  }

  if (port !== "") {
    if (!/^\d+$/.test(port)) fail("uri: port");
    const portNumber = Number(port);
    if (portNumber < 1 || portNumber > 65535) fail("uri: port range");
    port = portNumber === 443 ? "" : `:${portNumber}`;
  }

  const path = match[3] === "" ? "/" : match[3]!;
  const normalizedPath = removeDotSegments(normalizePercentEncoding(path));
  if (!normalizedPath.startsWith("/")) fail("uri: absolute path");
  return `https://${host}${port}${normalizedPath}`;
}

function bytesEqualUtf8(bytes: Uint8Array, s: string): boolean {
  return strUtf8(s).length === bytes.length && strUtf8(s).every((b, i) => b === bytes[i]);
}

function isCanonicalIpv4(host: string): boolean {
  const octets = host.split(".");
  return (
    octets.length === 4 &&
    octets.every((o) => /^(?:0|[1-9]\d{0,2})$/.test(o) && Number(o) <= 255)
  );
}

const REG_NAME_CHAR = /[A-Za-z0-9\-._~!$&'()*+,;=]/;
function assertRegName(host: string): void {
  for (let i = 0; i < host.length; i++) {
    const ch = host[i]!;
    if (REG_NAME_CHAR.test(ch)) continue;
    if (
      ch === "%" &&
      i + 2 < host.length &&
      /^[0-9A-Fa-f]{2}$/.test(host.slice(i + 1, i + 3))
    ) {
      i += 2;
      continue;
    }
    fail("uri: reg-name");
  }
}

const UNRESERVED = /[A-Za-z0-9\-._~]/;
function normalizePercentEncoding(value: string): string {
  let result = "";
  for (let i = 0; i < value.length; i++) {
    if (value[i] !== "%") {
      result += value[i];
      continue;
    }
    if (i + 2 >= value.length || !/^[0-9A-Fa-f]{2}$/.test(value.slice(i + 1, i + 3))) {
      fail("uri: escape");
    }
    const octet = Number.parseInt(value.slice(i + 1, i + 3), 16);
    const ch = String.fromCharCode(octet);
    result += UNRESERVED.test(ch)
      ? ch
      : `%${octet.toString(16).toUpperCase().padStart(2, "0")}`;
    i += 2;
  }
  return result;
}

function lowercaseOutsideEscapes(value: string): string {
  let result = "";
  for (let i = 0; i < value.length; i++) {
    if (value[i] === "%") {
      result += value.slice(i, i + 3);
      i += 2;
    } else {
      result += value[i]!.toLowerCase();
    }
  }
  return result;
}

// RFC 3986 §6.2.2.3 dot-segment removal (the canonical algorithm).
function removeDotSegments(path: string): string {
  let input = path;
  let output = "";
  while (input.length > 0) {
    if (input.startsWith("../")) input = input.slice(3);
    else if (input.startsWith("./")) input = input.slice(2);
    else if (input.startsWith("/./")) input = input.slice(2);
    else if (input === "/.") input = "/";
    else if (input.startsWith("/../")) {
      input = input.slice(3);
      output = output.replace(/\/?[^/]*$/, "");
    } else if (input === "/..") {
      input = "/";
      output = output.replace(/\/?[^/]*$/, "");
    } else if (input === "." || input === "..") {
      input = "";
    } else {
      const startAt = input.startsWith("/") ? 1 : 0;
      const nextSlash = input.indexOf("/", startAt);
      const end = nextSlash === -1 ? input.length : nextSlash;
      output += input.slice(0, end);
      input = input.slice(end);
    }
  }
  return output;
}

function ipv6Kind(literal: string): 6 | "future" | null {
  if (/^[0-9A-Fa-f:.]+$/.test(literal) && validIpv6Literal(literal)) return 6;
  if (/^v[0-9A-Fa-f]+\.[A-Za-z0-9._~!$&'()*+,;=:-]+$/.test(literal)) return "future";
  return null;
}

// Structural IPv6 validation mirroring the reference (uri.ex:181-226 valid_ipv6_literal? /
// ipv6_side_length / ipv6_groups_length). Rejects malformed literals like ":::", "1:2:3:4:5:6:7:8:9"
// (too many groups), and a "::" that does not actually compress (< 8 groups required). The prior
// implementation only checked the character class, so structurally-invalid literals normalized.
function validIpv6Literal(literal: string): boolean {
  const parts = literal.split("::");
  if (parts.length === 1) {
    return ipv6SideLength(parts[0]!) === 8;
  }
  if (parts.length === 2) {
    const left = ipv6SideLength(parts[0]!);
    const right = ipv6SideLength(parts[1]!);
    if (left === null || right === null) return false;
    return left + right < 8;
  }
  return false; // multiple "::" compressions
}

// Count groups on one side of "::". Returns null if any group is malformed.
function ipv6SideLength(side: string): number | null {
  if (side === "") return 0;
  const groups = side.split(":");
  let total = 0;
  for (let i = 0; i < groups.length; i++) {
    const group = groups[i]!;
    const isLast = i === groups.length - 1;
    if (group.includes(".")) {
      // An IPv4-style group is valid ONLY in the tail position (reference ipv6_groups_length checks
      // non-last groups as hex-only via valid_hex_group?). A non-tail IPv4 group is a malformed
      // literal the reference rejects.
      if (!isLast || !isCanonicalIpv4(group)) return null;
      total += 2;
    } else {
      if (!(group.length >= 1 && group.length <= 4) || !/^[0-9A-Fa-f]+$/.test(group)) return null;
      total += 1;
    }
  }
  return total;
}
