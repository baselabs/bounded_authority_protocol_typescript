# Operations and observability

The package emits no telemetry and owns no operational health. Logging, metrics, tracing,
key distribution, replay persistence, revocation, clocks and execution recovery belong to the host.
Monitor the entire admission path rather than equating signature success with a healthy service.

| Signal | Meaning and response |
|---|---|
| verification refusals, by configured operation | inspect recent key/profile/configuration changes; avoid caller-controlled metric labels |
| unexpected exception | fail admission, record a redacted defect event and alert; never convert it into success |
| key/attestor enrollment failures | check encoding, suite, subgroup and authenticated source before trust installation |
| unknown `kid` count | distinguish rotation lag from probing in restricted diagnostics; do not fetch arbitrary keys |
| replay collisions and reservation latency | check retries and duplicates; store outage refuses execution |
| revocation query latency and availability | apply the host's fail-closed policy; do not silently reuse stale trust |
| clock offset and jumps | compare accepting processes and store; bound offset and retain records through the maximum acceptance window |
| queue depth and verifier CPU/memory | constrain concurrency, input size and accepted lifetime before saturation |
| archive failures and content generation forks | preserve protected evidence; never silently skip anchors or roll back lineage |

Use low-cardinality outcome labels such as `verified`, `refused`, `replay` and `dependency_failure`.
Project approved fields into an event, for example `operation` from the configured route and the
host outcome. Do not spread facts. Redaction hooks cover common runtime inspection and coercion,
not browser consoles, object spreading, cloning, or access to individual fields. A caller can
serialize an explicit projection; that is a disclosure decision the host must review.

Use stable caller-facing refusals. Retry a transient infrastructure failure only before effects,
with a bounded retry budget. Once reserved, an invocation stays reserved even when execution
fails; recovery needs durable application state or an outbox. A replay reservation does not prove
an effect completed. Test crash points before reservation, after reservation and after execution.

During rotation, distribute the enrolled new key before issuing new grants and retain the old key
through the last accepted old grant plus skew unless revoked. Alert on partial rollout and key
window disagreement. Back up replay and lineage state, exercise restoration, and verify that
restoration cannot admit old invocations or roll back accepted generations. Never purge active
reservations to recover capacity. See the [durable replay integration](durable-replay.md).

---

Documentation navigation: [Previous: Integration security](integration-security.md) · [Next: Handle errors](handle-errors.md)
