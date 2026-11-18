# Integration recipes

The complete modules below are type-checked and executed against both the checkout and the exact
published package. They generate demonstration keys, assert success and refusal, and clean up.

- [Native and Fetch-style request adapters](../examples/request-adapters.ts): real HTTP requests,
  strict credentials, request reconstruction, tampering, success and replay refusal.
- [Durable replay](../examples/durable-replay.ts): a real SQLite file, independent processes,
  atomic contention and restart persistence. Host deployment requirements are in [Durable replay](durable-replay.md).
- [Local loopback](../examples/local-loopback.ts): literal loopback HTTP, mandatory nonce and
  refusal under the standard HTTPS profile.
- [Major 2 archives](../examples/v2-archives.ts) and [major 3 archives](../examples/v3-archives.ts):
  complete chain and signed boundary verification using each major's own suite.
- [Upgrade assertions](../examples/upgrade.ts): standard JWS framing, closed deep imports and
  explicit facts projections.
- [Canonical primitives](../examples/primitives.ts): byte encodings, keys, fingerprints and limits.

Use the [notebooks](../notebooks/README.md) for guided, interactive execution in the Deno kernel.
The [integration-security](integration-security.md) and [operations](operations-observability.md)
guides name what the host must supply before any verified facts can support an operational decision.

---

Documentation navigation: [Previous: Handle errors](handle-errors.md) · [Next: Test your integration](test-your-integration.md)
