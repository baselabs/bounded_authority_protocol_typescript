/**
 * The package's single error class (`name: "InvalidError"`). Thrown by the primitives on invalid
 * input; the result-returning functions convert it into `{ ok: false }`.
 * @see https://github.com/baselabs/bounded_authority_protocol/blob/main/spec/bap-v1.md#verification
 */
export class InvalidError extends Error {
  /** Stable diagnostic class name; no protocol values are included. */
  override readonly name = "InvalidError";
  constructor(message = "invalid") {
    super(message);
  }
}

/**
 * The closed result: `{ ok: true, value }` or `{ ok: false }`, which carries no reason.
 * @see https://github.com/baselabs/bounded_authority_protocol/blob/main/spec/bap-v1.md#verification
 */
export type Result<T> = {
  /** Success discriminant. */
  readonly ok: true;
  /** Successful value, absent on failure. */
  readonly value: T;
} | {
  /** Closed failure discriminant; no reason or partial result. */
  readonly ok: false;
};

/**
 * Builds `{ ok: true, value }`.
 * @see https://github.com/baselabs/bounded_authority_protocol/blob/main/spec/bap-v1.md#verification
 */
export const ok = <T>(value: T): Result<T> => ({ ok: true, value });
/**
 * Builds the closed `{ ok: false }`.
 * @see https://github.com/baselabs/bounded_authority_protocol/blob/main/spec/bap-v1.md#verification
 */
export const err = (): Result<never> => ({ ok: false });

/**
 * Runs `fn` and returns its value as a result, converting a thrown `InvalidError` into the closed
 * `{ ok: false }`. Any other exception is rethrown.
 * @see https://github.com/baselabs/bounded_authority_protocol/blob/main/spec/bap-v1.md#verification
 * @returns A success Result containing fn output, or the closed failure for InvalidError. Other exceptions propagate. Failure is value-free { ok: false } for invalid, over-limit or mismatched inputs.
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
 * @see https://github.com/baselabs/bounded_authority_protocol/blob/main/spec/bap-v1.md#verification
 * @throws InvalidError on every call. The message is diagnostic and never part of a closed Result failure.
 */
export function fail(message?: string): never {
  throw new InvalidError(message);
}

/**
 * Throws the closed `InvalidError` when `condition` is falsy.
 * @see https://github.com/baselabs/bounded_authority_protocol/blob/main/spec/bap-v1.md#verification
 * @throws InvalidError when condition is falsy; otherwise returns normally.
 */
export function assert(condition: unknown, message?: string): asserts condition {
  if (!condition) fail(message);
}
