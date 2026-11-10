# Upgrading from 1.x

2.0.0 (unreleased) carries one change: the protocol's erratum 6, the selector float-zero
soundness repair. The exports, the types, the error shape and every other verdict are 1.0.0's,
and no wire contract-major changes. It is a package major only because 1.0.0 promised one for any
verdict change ([Versioning](../../README.md#versioning)).

## What changes

| Where | 1.0.0 | 2.0.0 |
|---|---|---|
| Grant decode (`decodeGrant`, `verifyGrant`, `checkEnvelope`, `parseSelector`; root, `v2` and `v3`) | accepts an `equals` value or `one_of` member holding a float-tagged zero (`0.0`, `-0.0`, `-0e0`, `1e-400`) at any depth | rejects it with the closed error |
| Grant producer (`grantSigningInput`; root, `v2` and `v3`) | accepts a selector value holding a float-tagged integral number (`0.0`, `10.0`, `{ t: "float", v: 3 }`) in any kind | refuses it with `{ ok: false }` |

Range bounds (`lte`, `gte`), the inert members of `all`, integer zero, and floats with a
fractional part are unchanged. The [Verify requests](verify-requests.md#arguments-and-selectors)
guide has a runnable example of both rows.

## Who is affected

- **Resource servers** reject a grant whose signed selector holds a float-tagged zero. No
  conforming producer writes one: JCS writes a float zero as `0`, which decodes as an integer. Such
  a grant comes only from a producer that does not write JCS. Before the repair, conforming
  verifiers disagreed on whether `0.0` and `-0.0` were the same selector value, so a constraint
  the issuer signed could be enforced by one host and not by another.
- **Issuers** that build grants with `grantSigningInput` (directly, or through a signer that calls
  it) get `{ ok: false }` for a selector value holding a float-tagged integral number. 1.0.0
  signed it, but JCS wrote it as integer text, so the signed grant held an integer: it matched
  integer arguments, never the float the issuer meant. Use `{ t: "int", v: 3 }` when you mean an
  integer, or a float with a fractional part.
- **Grants already issued by a conforming producer**, including 1.0.0's, are unaffected: their
  bytes hold integers where the input held integral floats, and they verify under 2.0.0 exactly
  as under 1.0.0.

To find selector values your issuer would now have refused, walk them with the same rule the
producer applies. This runs on 1.x and 2.x alike:

```ts
import assert from "node:assert/strict";
import { jsonDecode, strUtf8, type Tagged } from "@bounded-authority-protocol/verifier";

// True when a selector value holds a float-tagged integral number at any depth: 2.0.0's grant
// producer refuses it, and a float-tagged zero in an equals value or one_of member also fails decode.
function holdsIntegralFloat(value: Tagged): boolean {
  switch (value.t) {
    case "float": return Number.isInteger(value.v);
    case "array": return value.v.some(holdsIntegralFloat);
    case "object": return [...value.v.values()].some(holdsIntegralFloat);
    default: return false;
  }
}

// Selector values as your issuer configures them, decoded with the tag-preserving jsonDecode.
const configured = {
  "rooms.book": '{"capacity":4}',
  "sensors.calibrate": '{"offset":0.0}',
  "reports.export": '{"formats":["pdf","csv"],"scale":1.5}',
  "jobs.retry": '{"limits":{"attempts":3.0}}',
};
const affected = Object.entries(configured)
  .filter(([, json]) => holdsIntegralFloat(jsonDecode(strUtf8(json))))
  .map(([operation]) => operation);
assert.deepEqual(affected, ["sensors.calibrate", "jobs.retry"]);
```

## Steps

1. Run a check like the one above over the selector values your issuers emit, and change each
   hit to an integer or to a float with a fractional part.
2. Move the dependency to `^2.0.0` (`npm install @bounded-authority-protocol/verifier@^2.0.0`).
3. Run your own tests. Nothing else in your code changes: no import, function name, parameter or
   result shape moved.

If you use the companion [signer](https://www.npmjs.com/package/@bounded-authority-protocol/signer),
it resolves the verifier through its own caret range, so installing verifier 2.0.0 in your project
does not change the verifier copy a signer 1.x release uses. The signer's changelog names the
release that moves to `^2.0.0`.

## Staying on 1.x

1.0.0 stays installable and is not deprecated: erratum 6 is signer-bound (every affected value sits
inside issuer-signed bytes), so under the protocol's governance it has no security advisory, and
the [errata registry](https://github.com/baselabs/bounded_authority_protocol/blob/main/docs/errata.md)
entry is the disclosure. 1.x returns the pre-repair verdict for the inputs above, and only
the latest release line receives fixes ([SECURITY.md](../../SECURITY.md#supported-versions)).
