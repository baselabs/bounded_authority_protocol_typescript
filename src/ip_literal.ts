// Internal IP group parsing shared by identifier admission and target-URI normalization.
// ipv6GroupShape preserves the normalizer's existing per-side IPv4-tail rule.
// StringOrURI additionally requires a dotted group at the overall literal tail.
export function isCanonicalIpv4(host: string): boolean {
  const octets = host.split(".");
  return (
    octets.length === 4 &&
    octets.every((o) => /^(?:0|[1-9]\d{0,2})$/.test(o) && Number(o) <= 255)
  );
}

export function ipv6GroupShape(literal: string): boolean {
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
      // Count an IPv4-style group only at the end of this side of ::.
      // StringOrURI separately requires it at the end of the entire literal.
      if (!isLast || !isCanonicalIpv4(group)) return null;
      total += 2;
    } else {
      if (!(group.length >= 1 && group.length <= 4) || !/^[0-9A-Fa-f]+$/.test(group)) return null;
      total += 1;
    }
  }
  return total;
}
