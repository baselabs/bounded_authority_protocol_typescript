// The single closed error value. Mirrors the Elixir {:error, :invalid} — no reason, no partial.
// Verification is not authority, and every check fails closed. Every public façade function
// returns Ok<T> | Err on this. A GENUINE protocol rejection throws/returns InvalidError; a runner/SDK
// bug (TypeError, RangeError, uncaught library throw) is a distinct class that must NOT map to Invalid
// (the conformance runners follow the same discipline: only a genuine protocol rejection maps to
// INVALID; everything else is a bug).
/**
 * The package's single error class (`name: "InvalidError"`). Thrown by the primitives on invalid
 * input; the result-returning functions convert it into `{ ok: false }`.
 * @see https://github.com/baselabs/bounded_authority_protocol_typescript/blob/main/docs/reference.md
 */
export class InvalidError extends Error {
  override readonly name = "InvalidError";
  constructor(message = "invalid") {
    super(message);
  }
}

// The Result shape: Ok<T> | Err. Mirrors {:ok, value} | {:error, :invalid}.
/**
 * The closed result: `{ ok: true, value }` or `{ ok: false }`, which carries no reason.
 * @see https://github.com/baselabs/bounded_authority_protocol_typescript/blob/main/docs/reference.md
 */
export type Result<T> = { readonly ok: true; readonly value: T } | { readonly ok: false };

/**
 * Builds `{ ok: true, value }`.
 * @see https://github.com/baselabs/bounded_authority_protocol_typescript/blob/main/docs/reference.md
 */
export const ok = <T>(value: T): Result<T> => ({ ok: true, value });
/**
 * Builds the closed `{ ok: false }`.
 * @see https://github.com/baselabs/bounded_authority_protocol_typescript/blob/main/docs/reference.md
 */
export const err = (): Result<never> => ({ ok: false });

// Convenience: run a thunk that may throw InvalidError; convert to Result. Any NON-Invalid throw
// propagates (a bug, not a verdict) — this is the whitelist.
/**
 * Runs `fn` and returns its value as a result, converting a thrown `InvalidError` into the closed
 * `{ ok: false }`. Any other exception is rethrown.
 * @see https://github.com/baselabs/bounded_authority_protocol_typescript/blob/main/docs/reference.md
 */
export function trying<T>(fn: () => T): Result<T> {
  try {
    return ok(fn());
  } catch (e) {
    if (e instanceof InvalidError) return err();
    throw e;
  }
}

/**
 * Throws the closed `InvalidError`.
 * @see https://github.com/baselabs/bounded_authority_protocol_typescript/blob/main/docs/reference.md
 */
export function fail(message?: string): never {
  throw new InvalidError(message);
}

/**
 * Throws the closed `InvalidError` when `condition` is falsy.
 * @see https://github.com/baselabs/bounded_authority_protocol_typescript/blob/main/docs/reference.md
 */
export function assert(condition: unknown, message?: string): asserts condition {
  if (!condition) fail(message);
}
