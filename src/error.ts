// The single closed error value. Mirrors the Elixir {:error, :invalid} — no reason, no partial.
// AGENTS rule 1: verification is not authority; rule 3: fail closed. Every public façade function
// returns Ok<T> | Err on this. A GENUINE protocol rejection throws/returns InvalidError; a runner/SDK
// bug (TypeError, RangeError, uncaught library throw) is a distinct class that must NOT map to Invalid
// (mirrors the Node runner's InvalidError whitelist discipline, corpus_independent.mjs:88-102 — only a
// genuine protocol rejection maps to INVALID; everything else is a bug).
export class InvalidError extends Error {
  override readonly name = "InvalidError";
  constructor(message = "invalid") {
    super(message);
  }
}

// The Result shape: Ok<T> | Err. Mirrors {:ok, value} | {:error, :invalid}.
export type Result<T> = { readonly ok: true; readonly value: T } | { readonly ok: false };

export const ok = <T>(value: T): Result<T> => ({ ok: true, value });
export const err = (): Result<never> => ({ ok: false });

// Convenience: run a thunk that may throw InvalidError; convert to Result. Any NON-Invalid throw
// propagates (a bug, not a verdict) — this is the whitelist.
export function trying<T>(fn: () => T): Result<T> {
  try {
    return ok(fn());
  } catch (e) {
    if (e instanceof InvalidError) return err();
    throw e;
  }
}

export function fail(message?: string): never {
  throw new InvalidError(message);
}

export function assert(condition: unknown, message?: string): asserts condition {
  if (!condition) fail(message);
}
