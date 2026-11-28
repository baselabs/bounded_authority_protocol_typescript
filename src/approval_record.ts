// Closed approval record grammar and the bounds that apply independently of the compact.
import { assert } from "./error.js";
import { base64urlEncode } from "./base64url.js";
import { MAXIMA, resolve, type Bounds, type MaximaKey } from "./bounds.js";
import { jsonDecode, strUtf8, utf8Str } from "./json.js";
import { bytes, digest, equal, exact, identifier, int, object, string } from "./content_assertion_stages.js";
import { redactedRendering } from "./redact.js";
import type { ApprovalRecord } from "./action_approval.js";

const MAX = {string_bytes: 1024, resource_count: 4096, record_bytes: 65536} as const;
type Ceiling = keyof typeof MAX;
export type Tightening = Readonly<Partial<Record<Ceiling, number>>>;

export interface Limits {
  readonly stringBytes: number;
  readonly resourceCount: number;
  readonly recordBytes: number;
}

export function limits(ca: Bounds, options: Tightening): Limits {
  object(options);
  assert(Object.getPrototypeOf(options) === Object.prototype || Object.getPrototypeOf(options) === null, "record bounds object");
  for (const key of Reflect.ownKeys(options)) {
    assert(typeof key === "string" && Object.hasOwn(MAX, key), "known record bound");
    const value = options[key as Ceiling];
    assert(value !== undefined && Number.isInteger(value) && value > 0 && value <= MAX[key as Ceiling], "record bound");
  }
  return {
    stringBytes: options.string_bytes ?? MAX.string_bytes,
    resourceCount: options.resource_count ?? MAX.resource_count,
    recordBytes: Math.min(options.record_bytes ?? MAX.record_bytes, resolve(ca, "content_bytes")),
  };
}

export function scalar(value: unknown, max: number): asserts value is string {
  assert(typeof value === "string" && value.length > 0 && value.length <= max, "bounded string");
  assert(!/[\uD800-\uDFFF]/u.test(value) && strUtf8(value).length <= max, "scalar UTF-8");
}

export function requestId(value: unknown, b: Limits, ca: Bounds): asserts value is string {
  scalar(value, Math.min(b.stringBytes, resolve(ca, "identifier_bytes")));
  identifier(value, ca);
}

function compare(a: Uint8Array, b: Uint8Array): number {
  for (let i = 0; i < Math.min(a.length, b.length); i++) {
    const diff = a[i]! - b[i]!;
    if (diff !== 0) return diff;
  }
  return a.length - b.length;
}

export function resources(value: readonly string[], b: Limits, canonicalize: boolean): readonly string[] {
  assert(Array.isArray(value) && value.length > 0 && value.length <= b.resourceCount, "resource count");
  if (canonicalize) {
    const unique = new Map<string, Uint8Array>();
    for (const name of value) {
      scalar(name, b.stringBytes);
      unique.set(name, strUtf8(name));
    }
    return [...unique].sort((a, z) => compare(a[1], z[1])).map(([name]) => name);
  }
  let previous: Uint8Array | undefined;
  for (const name of value) {
    scalar(name, b.stringBytes);
    const current = strUtf8(name);
    assert(previous === undefined || compare(previous, current) < 0, "resource order");
    previous = current;
  }
  return value;
}

const FIELDS = ["action", "approverRole", "requestId", "resources", "revisionDigest", "subject"] as const;
const WIRE = ["action", "approver_role", "request_id", "resources", "revision_digest", "subject", "v"] as const;

export function encode(record: ApprovalRecord, ca: Bounds, b: Limits, canonicalize: boolean): Uint8Array {
  object(record);
  assert(FIELDS.every(k => Object.hasOwn(record, k)) && Object.keys(record).every(k => FIELDS.some(field => field === k)), "closed record fields");
  assert(typeof canonicalize === "boolean", "canonicalize option");
  scalar(record.action, b.stringBytes);
  scalar(record.approverRole, b.stringBytes);
  scalar(record.subject, b.stringBytes);
  requestId(record.requestId, b, ca);
  bytes(record.revisionDigest, 32);
  const names = resources(record.resources, b, canonicalize);
  const parts: Uint8Array[] = [];
  let size = 0;
  const append = (part: string) => {
    const raw = strUtf8(part);
    size += raw.length;
    assert(size <= b.recordBytes, "encoded record bound");
    parts.push(raw);
  };
  // The member names are in JCS order and the only number is the literal 1.
  append(`{"action":${JSON.stringify(record.action)},"approver_role":${JSON.stringify(record.approverRole)},"request_id":${JSON.stringify(record.requestId)},"resources":[`);
  for (let i = 0; i < names.length; i++) append((i === 0 ? "" : ",") + JSON.stringify(names[i]));
  append(`],"revision_digest":"${utf8Str(base64urlEncode(record.revisionDigest))}","subject":${JSON.stringify(record.subject)},"v":1}`);
  const output = new Uint8Array(size);
  let offset = 0;
  for (const raw of parts) {
    output.set(raw, offset);
    offset += raw.length;
  }
  return output;
}

export function decode(wire: Uint8Array, ca: Bounds, b: Limits): ApprovalRecord {
  assert(wire instanceof Uint8Array && wire.length > 0 && wire.length <= b.recordBytes, "record bytes");
  // The record grammar has its own array and node ceilings. The JWS JSON ceilings apply to the assertion.
  const overrides = new Map<MaximaKey, number>([
    ["json_bytes", b.recordBytes], ["string_bytes", Math.max(b.stringBytes, 43)],
    ["array_items", b.resourceCount], ["depth", 2], ["object_members", WIRE.length],
    ["total_nodes", b.resourceCount + WIRE.length + 1],
  ]);
  const value = exact(jsonDecode(wire, {maximum: MAXIMA, overrides}), WIRE).v;
  const names = value.get("resources");
  assert(names?.t === "array" && int(value.get("v")) === 1, "record schema");
  const result: ApprovalRecord = {
    action: string(value.get("action")), approverRole: string(value.get("approver_role")),
    requestId: string(value.get("request_id")), resources: Object.freeze(names.v.map(string)),
    revisionDigest: digest(value.get("revision_digest")), subject: string(value.get("subject")),
  };
  assert(equal(encode(result, ca, b, false), wire), "canonical record");
  return redactedRendering(result, "ActionApproval.V1.Record");
}
