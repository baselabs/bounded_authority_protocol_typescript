import { fail } from "./error.js";

/**
 * The profile maxima, one entry per limit name. `boundsNew` can only tighten these.
 * @see https://github.com/baselabs/bounded_authority_protocol/blob/main/spec/bap-v1.md#maxima
 */
export const MAXIMA = {
  /** Maximum compact size in bytes. */
  compact_bytes: 65536,
  /** Maximum content size in bytes. */
  content_bytes: 65536, // spec/bap-content-assertion-v1.md: exact external content bytes, tightenable.
  /** Maximum encoded segment size in bytes. */
  encoded_segment_bytes: 32768,
  /** Maximum decoded segment size in bytes. */
  decoded_segment_bytes: 24576,
  /** Maximum input JSON size in bytes. */
  json_bytes: 65536,
  /** Maximum nesting levels, with the root at depth zero. */
  depth: 32,
  /** Maximum members per JSON object. */
  object_members: 64,
  /** Maximum elements per JSON array. */
  array_items: 256,
  /** Maximum JSON value nodes, including scalar and container nodes. */
  total_nodes: 4096,
  /** Maximum decoded JSON string size in UTF-8 bytes. */
  string_bytes: 8192,
  /** Maximum decoded JSON member-name size in UTF-8 bytes. */
  key_bytes: 128,
  /** Maximum number lexeme size in bytes. */
  number_lexeme_bytes: 64,
  /** Maximum absolute integer magnitude (2^53 - 1). */
  integer_magnitude: 9007199254740991,
  /** Maximum absolute finite binary64 magnitude (2^53 - 1). */
  float_magnitude: 9007199254740991,
  /** Maximum protected-header key ID size in ASCII bytes. */
  kid_bytes: 128,
  /** Maximum canonical JSON output size in bytes. */
  jcs_bytes: 65536,
  /** Maximum ASCII target URI size in bytes. */
  uri_bytes: 8192,
  /** Maximum identifier size in bytes. */
  identifier_bytes: 512,
  /** Maximum nonce size in bytes. */
  nonce_bytes: 512,
  /** Maximum method size in bytes. */
  method_bytes: 32,
  /** Maximum operation size in bytes. */
  operation_bytes: 128,
  /** Maximum distinct audiences per grant. */
  audiences: 64,
  /** Maximum distinct operations per grant. */
  operations: 64,
  /** Maximum selectors per operation. */
  selectors: 64,
  /** Maximum member-name segments per selector path. */
  path_segments: 32,
  /** Maximum candidates in a one_of selector. */
  one_of_values: 256,
  /** Exact raw Ed25519 key width in bytes. Major 3 checks its 65-byte P-256 keys separately. */
  public_key_bytes: 32,
  /** Exact raw signature width in bytes, immutable for all supported suites. */
  signature_bytes: 64,
  /** Exact SHA-256 digest width in bytes, immutable for all supported suites. */
  digest_bytes: 32,
  /** Maximum allowed clock skew in seconds. Zero is allowed in expected context. */
  clock_skew: 60,
  /** Maximum allowed proof age in seconds. Expected proof age must be positive. */
  proof_max_age: 300,
  /** Maximum chain row size in bytes. */
  chain_row_bytes: 4096,
  /** Maximum rows per checked consumption range. */
  chain_rows: 65536,
  /** Maximum anchor or key-transition compact size in bytes. */
  anchor_bytes: 8192,
  /** Maximum archive header size in bytes. */
  archive_header_bytes: 8192,
  /** Maximum framed or transport chunks in an archive input. */
  archive_chunks: 65796,
  /** Maximum archive size in bytes. */
  archive_bytes: 270820384,
  /** Maximum object version size in bytes. */
  object_version_bytes: 512,
  /** Maximum archive-key transitions. */
  key_transitions: 256,
} as const;

/**
 * A recognized MAXIMA limit name. Names ending in bytes count octets; clock_skew and proof_max_age use
 * seconds; other entries count structures or bound numeric magnitude.
 * @see https://github.com/baselabs/bounded_authority_protocol/blob/main/spec/bap-v1.md#maxima
 */
export type MaximaKey = keyof typeof MAXIMA;

/**
 * Immutable-view resource limits. Use boundsNew to tighten positive ceilings. Digest, public-key and
 * signature widths are fixed suite constants. Public boundaries revalidate caller-constructed values.
 * @see https://github.com/baselabs/bounded_authority_protocol/blob/main/spec/bap-v1.md#maxima
 */
export interface Bounds {
  /** Fixed profile ceiling table. Raw digests and signatures are 32 and 64 bytes; Ed25519 keys are 32 bytes. Major 3 checks its 65-byte P-256 keys separately. */
  readonly maximum: typeof MAXIMA;
  /** Recognized positive tightened ceilings; cryptographic widths must stay exact. */
  readonly overrides: ReadonlyMap<MaximaKey, number>;
}

/**
 * The shared untightened `Bounds` value. Do not mutate it; build tightened bounds with
 * `boundsNew`.
 * @see https://github.com/baselabs/bounded_authority_protocol/blob/main/spec/bap-v1.md#maxima
 */
export const MAXIMUM_BOUNDS: Bounds = { maximum: MAXIMA, overrides: new Map() };

/**
 * A new, untightened `Bounds` value (the profile maxima).
 * @see https://github.com/baselabs/bounded_authority_protocol/blob/main/spec/bap-v1.md#maxima
 * @returns Fresh untightened bounds using the profile ceiling table. No input is accepted and no protocol rejection occurs.
 */
export function boundsMaximum(): Bounds {
  // Return a FRESH Bounds each call so a caller cannot mutate a shared singleton's overrides Map
  // to widen the profile maximum globally (ReadonlyMap is compile-time only; runtime mutation is
  // otherwise possible). REQ1-BOUNDS-tighten-only.
  return { maximum: MAXIMA, overrides: new Map() };
}

// REQ1-BOUNDS-reject-list (L397): unknown, non-integer, zero, negative, widening, or fixed-width-
// changing limits are invalid. Fixed-width keys (L395) cannot be tightened or widened.
const FIXED_WIDTH_KEYS: ReadonlySet<MaximaKey> = new Set<MaximaKey>([
  "digest_bytes",
  "public_key_bytes",
  "signature_bytes",
]);

/**
 * A `Bounds` value that tightens named limits. Throws `InvalidError` for an unknown name, a
 * non-integer, non-positive or widening value, or a change to a fixed width.
 * @see https://github.com/baselabs/bounded_authority_protocol/blob/main/spec/bap-v1.md#maxima
 * @returns Bounds containing the validated tighten-only overrides; omitted input returns MAXIMUM_BOUNDS.
 * @throws InvalidError when the documented representation or resource limits are violated.
 */
export function boundsNew(tightening?: Readonly<Record<string, number>>): Bounds {
  if (tightening === undefined) return MAXIMUM_BOUNDS;
  const overrides = new Map<MaximaKey, number>();
  for (const [key, value] of Object.entries(tightening)) {
    if (!Object.hasOwn(MAXIMA, key)) fail(`bounds.new: unknown limit ${key}`);
    if (!Number.isInteger(value)) fail(`bounds.new: non-integer limit ${key}`);
    const mk = key as MaximaKey;
    if (FIXED_WIDTH_KEYS.has(mk)) {
      // REQ1-BOUNDS-fixed-widths: fixed-width keys cannot be tightened or widened, but setting to
      // the exact maximum is an identity no-op (valid). Any other value rejects.
      if (value !== MAXIMA[mk]) fail(`bounds.new: fixed-width key ${key} must equal maximum`);
    } else {
      if (value <= 0) fail(`bounds.new: non-positive limit ${key}`);
      if (value > MAXIMA[mk]) fail(`bounds.new: widening limit ${key}`);
    }
    overrides.set(mk, value);
  }
  return { maximum: MAXIMA, overrides };
}

// Revalidate structural Bounds at each public boundary and in leaf resolution. Callers can
// construct objects without boundsNew. Require a non-null object in maximum and validate every
// override against MAXIMA; do not inspect maximum entries. resolve uses MAXIMA for defaults.
// Reject widening overrides and malformed structure with InvalidError.
// Overrides must be a Map; arbitrary ReadonlyMap implementations are not accepted. This
// prevents native iteration errors and forged limits.
export function coerceBounds(b: Bounds): Bounds {
  if (typeof b !== "object" || b === null) fail("bounds.coerce: object required");
  if (typeof b.maximum !== "object" || b.maximum === null) fail("bounds.coerce: maximum table required");
  if (!(b.overrides instanceof Map)) fail("bounds.coerce: overrides map required");
  // instanceof narrows to the unparameterized Map default; re-establish the typed view.
  const overrides: ReadonlyMap<MaximaKey, number> = b.overrides;
  for (const [key, value] of overrides) {
    if (typeof key !== "string" || !Object.hasOwn(MAXIMA, key)) fail("bounds.coerce: unknown limit");
    if (!Number.isInteger(value)) fail(`bounds.coerce: non-integer limit ${key}`);
    if (FIXED_WIDTH_KEYS.has(key)) {
      if (value !== MAXIMA[key]) fail(`bounds.coerce: fixed-width key ${key} must equal maximum`);
    } else {
      if (value <= 0) fail(`bounds.coerce: non-positive limit ${key}`);
      if (value > MAXIMA[key]) fail(`bounds.coerce: widening limit ${key}`);
    }
  }
  return b;
}

// Resolve a bound: the override if present, else the maximum. The leaf every bound-sensitive check
// funnels through, so it carries the same structural gate as coerceBounds: a path that resolves
// caller bounds BEFORE coercing (untrustedKeyLocator resolves compact_bytes ahead of any parse)
// must fail closed on a garbage object here, not throw a TypeError on `.overrides.get` of
// undefined.
export function resolve(b: Bounds, key: MaximaKey): number {
  if (typeof b !== "object" || b === null || !(b.overrides instanceof Map)) {
    fail("bounds.resolve: malformed bounds object");
  }
  return b.overrides.get(key) ?? MAXIMA[key];
}
