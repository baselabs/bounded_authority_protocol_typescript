# Durable replay reservations

The [runnable SQLite integration](../examples/durable-replay.ts) uses Node's real `node:sqlite`
store and twelve independent verifier processes checking the same real signed request and racing
on one primary key. Exactly one succeeds; after
all children exit, reopening the database still refuses the reserved tuple. It also checks
independent issuer/grant scopes and expired reservations, then closes connections and deletes
its demonstration directory. CI runs the actual source with Node's type stripping. No database
or clock is mocked.

After `checkEnvelope` succeeds, call the store with `facts.issuer`, `facts.grantId`,
`facts.invocationId`, and `facts.grantExpiresAt + largestAcceptedSkew`. Use the store's `now()`
as `evaluationTime` too. The SQL conflict condition keeps a reservation at the retention boundary
and only reclaims it when the store clock is strictly later. Clock rollback retains records
longer; a forward jump can invalidate your timing assumptions, so monitor and bound it. Store
failure refuses admission. Never delete reservations just because a handler failed.

This is durable admission, not exactly-once effects. A process can fail after reservation and
before execution. Use transactional application state or an outbox and recovery policy if effects
must be recoverable. The notebook HTTP recipe uses an in-memory store to explain the sequence;
use this durable contract for a persistent host. SQLite is suitable for processes sharing one
reliable local filesystem. Distributed hosts need a transactional shared store with the same
atomic tuple constraint and authoritative clock; do not copy a SQLite file across instances.

The database is host infrastructure, never a dependency or side effect of the pure verifier.
Protect it, back it up, test recovery, size retention for accepted grant lifetimes, and purge only
expired rows in bounded batches using the same clock. Run the example in a directory you control:

```bash
node docs/examples/durable-replay.ts
```

---

Documentation navigation: [Previous: Content assertions](content-assertions.md) · [Next: Integration security](integration-security.md)
