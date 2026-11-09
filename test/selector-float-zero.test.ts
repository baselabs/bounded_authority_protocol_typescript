// Selector float-zero soundness (erratum 6; REQ1/2/3-SELECTOR-float-zero,
// REQ1/2/3-SIGNING-integral-float-selector, REQ2/3-SELECTOR-range-signed-zero).
//
// Verification, contract-majors 1, 2 and 3: grant decode rejects an `equals` value or a `one_of`
// member holding a float-tagged zero at any depth, of either sign and any spelling. Range bounds
// and the inert members of `all` are unchanged; integer-tagged 0 and -0 and non-zero integral
// floats such as 10.0 still decode. Producers: grantSigningInput refuses any float-tagged
// integral selector value in every kind, range bounds included.
//
// The certified vectors live in the vendored bap-selector-float-zero/1 corpus
// (conformance:selector-float-zero, 161 cases); this file is the rule matrix with independent
// fixtures built here.
//
// Defect-injection record (at authoring): removing the float-zero gate from the major-1
// parseSelector (src/selector.ts), the major-2 parseSelector or the major-3 parseSelector turned
// that major's decode legs here red and the corpus runner disagreed on that major's decode and
// envelope cases; removing producerValueGate from the major-1, major-2 or major-3 producer turned
// that major's producer legs red and the corpus disagreed on that major's signing-input cases.
// Each was restored and re-run green.
import { test } from "node:test";
import assert from "node:assert/strict";

import * as v1 from "../src/v1.js";
import * as v2 from "../src/v2.js";
import * as v3 from "../src/v3.js";
import { parseSelector, floatZeroFree, integralFloatFree } from "../src/selector.js";
import { base64urlEncode } from "../src/base64url.js";
import { jsonDecode, strUtf8, utf8Str, type Tagged } from "../src/json.js";

const decode = (text: string): Tagged => jsonDecode(strUtf8(text));
const b64 = (text: string): string => utf8Str(base64urlEncode(strUtf8(text)));

const ZERO_SPELLINGS = ["0.0", "-0.0", "0e0", "-0e0", "-0E0", "-0e-5", "0.000", "1e-400", "-1e-400"];

// A grant compact whose payload carries `selectors` as raw JSON text, so every lexeme reaches the
// decoder exactly as written. The signature is 64 placeholder bytes: decode never verifies it.
function grantCompact(major: 1 | 2 | 3, selectors: string): Uint8Array {
  const header = `{"alg":"${major === 3 ? "ES256" : "EdDSA"}","kid":"issuer","typ":"ba+cap"}`;
  const payload =
    `{"aud":["https://resource.example.test"],"cnf":{"jkt":"${"A".repeat(43)}"},"exp":2000,"iat":1000,` +
    `"iss":"https://issuer.example.test","jti":"urn:example:grant:1","nbf":1000,` +
    `"operations":[{"name":"transfer","selectors":[${selectors}]}],"v":${major}}`;
  const signature = utf8Str(base64urlEncode(new Uint8Array(64).fill(0x11)));
  return strUtf8(`${b64(header)}.${b64(payload)}.${signature}`);
}

const DECODERS = { 1: v1.decodeGrant, 2: v2.decodeGrant, 3: v3.decodeGrant } as const;
const decodes = (major: 1 | 2 | 3, selectors: string): boolean => DECODERS[major](grantCompact(major, selectors)).ok;

test("the shared predicates key on the decoded value, at any depth", () => {
  for (const zero of ZERO_SPELLINGS) {
    assert.equal(floatZeroFree(decode(zero)), false, zero);
    assert.equal(floatZeroFree(decode(`{"a":[1,{"b":${zero}}]}`)), false, `nested ${zero}`);
    assert.equal(integralFloatFree(decode(zero)), false, `integral ${zero}`);
  }
  for (const fine of ["0", "-0", "0.5", "-2.25", "10.0", "1e1", '"0.0"', "null", "[0,1.5]", '{"a":0}']) {
    assert.equal(floatZeroFree(decode(fine)), true, fine);
  }
  for (const integral of ["10.0", "-3.0", "1e1", "4503599627370496.0", "[1,2.0]", '{"a":{"b":7.0}}']) {
    assert.equal(integralFloatFree(decode(integral)), false, integral);
  }
  for (const fine of ["0", "-0", "10", "0.5", "-2.25", "[1,0.5]", '{"a":"10.0"}']) {
    assert.equal(integralFloatFree(decode(fine)), true, fine);
  }
});

for (const major of [1, 2, 3] as const) {
  test(`major ${major}: decode rejects a float-tagged zero in an equals value or one_of member`, () => {
    for (const zero of ZERO_SPELLINGS) {
      assert.equal(decodes(major, `{"kind":"equals","path":["x"],"value":${zero}}`), false, `equals ${zero}`);
      assert.equal(decodes(major, `{"kind":"one_of","path":["x"],"values":[1,${zero}]}`), false, `one_of ${zero}`);
    }
    assert.equal(decodes(major, `{"kind":"equals","path":["x"],"value":{"a":{"b":0.0}}}`), false, "object depth");
    assert.equal(decodes(major, `{"kind":"equals","path":["x"],"value":[1,-0.0]}`), false, "array depth");
    assert.equal(decodes(major, `{"kind":"one_of","path":["x"],"values":[[0e0]]}`), false, "nested one_of");
  });

  test(`major ${major}: integers, fractions, non-zero integral floats and inert all members still decode`, () => {
    for (const value of ["0", "-0", "0.5", "10.0", "1e1", "[0,1.5]", '"0.0"']) {
      assert.equal(decodes(major, `{"kind":"equals","path":["x"],"value":${value}}`), true, value);
    }
    assert.equal(decodes(major, `{"kind":"one_of","path":["x"],"values":[0,10.0,-2.25]}`), true);
    assert.equal(decodes(major, `{"kind":"all","path":["x"],"value":-0.0}`), true, "inert all value");
    assert.equal(decodes(major, `{"kind":"all","path":["x"],"values":[0.0]}`), true, "inert all values");
  });
}

for (const major of [2, 3] as const) {
  test(`major ${major}: range bounds keep float zero and compare -0.0 equal to 0.0`, () => {
    for (const kind of ["lte", "gte"]) {
      for (const zero of ["0.0", "-0.0", "-0e0"]) {
        assert.equal(decodes(major, `{"kind":"${kind}","path":["x"],"value":${zero}}`), true, `${kind} ${zero}`);
      }
    }
    const ns = major === 2 ? v2 : v3;
    const lte = ns.parseSelector(decode('{"kind":"lte","path":["x"],"value":0.0}'));
    const gte = ns.parseSelector(decode('{"kind":"gte","path":["x"],"value":-0.0}'));
    assert.equal(ns.selectorMatches(lte, decode('{"x":-0.0}')), true);
    assert.equal(ns.selectorMatches(gte, decode('{"x":0.0}')), true);
    assert.equal(ns.selectorMatches(lte, decode('{"x":0.5}')), false);
  });
}

test("the public parseSelector of each major throws for a float-tagged zero", () => {
  const equalsZero = decode('{"kind":"equals","path":["x"],"value":-0.0}');
  const oneOfZero = decode('{"kind":"one_of","path":["x"],"values":[1,0e0]}');
  for (const parse of [parseSelector, v2.parseSelector, v3.parseSelector]) {
    assert.throws(() => parse(equalsZero), { name: "InvalidError" });
    assert.throws(() => parse(oneOfZero), { name: "InvalidError" });
  }
});

// ---- producers ----

function producer(selectors: unknown[]) {
  return {
    keyId: "issuer",
    issuer: "https://issuer.example.test",
    grantId: "urn:example:grant:1",
    audiences: ["https://resource.example.test"],
    issuedAt: 1000,
    notBefore: 1000,
    expiresAt: 2000,
    holderThumbprint: "A".repeat(43),
    operations: [{ name: "transfer", selectors }],
  };
}

const PRODUCERS = {
  1: (s: unknown[]) => v1.grantSigningInput(producer(s) as v1.GrantProducer).ok,
  2: (s: unknown[]) => v2.grantSigningInput(producer(s) as v2.GrantProducer).ok,
  3: (s: unknown[]) => v3.grantSigningInput(producer(s) as v3.GrantProducer).ok,
} as const;

for (const major of [1, 2, 3] as const) {
  test(`major ${major}: grantSigningInput refuses a float-tagged integral selector value at any depth`, () => {
    const produces = PRODUCERS[major];
    for (const integral of ["0.0", "-0.0", "10.0", "-3.0", "4503599627370496.0", "[1,0.0]", '{"a":10.0}']) {
      assert.equal(produces([{ kind: "equals", path: ["x"], value: decode(integral) }]), false, `equals ${integral}`);
      assert.equal(produces([{ kind: "one_of", path: ["x"], values: [decode("1"), decode(integral)] }]), false, `one_of ${integral}`);
    }
    // A caller-built tag counts the same as a decoded one.
    assert.equal(produces([{ kind: "equals", path: ["x"], value: { t: "float", v: 3 } }]), false, "built float 3");
    for (const fine of ["0", "10", "0.5", "-2.25", "[0,1.5]", '{"a":"10.0"}']) {
      assert.equal(produces([{ kind: "equals", path: ["x"], value: decode(fine) }]), true, `equals ${fine}`);
    }
    assert.equal(produces([{ kind: "one_of", path: ["x"], values: [decode("10"), decode("0.5")] }]), true);
    assert.equal(produces(["all"]), true);
  });
}

for (const major of [2, 3] as const) {
  test(`major ${major}: grantSigningInput refuses a float-tagged integral range bound`, () => {
    const produces = PRODUCERS[major];
    for (const kind of ["lte", "gte"]) {
      for (const integral of ["0.0", "-0.0", "10.0"]) {
        assert.equal(produces([{ kind, path: ["x"], value: decode(integral) }]), false, `${kind} ${integral}`);
      }
      assert.equal(produces([{ kind, path: ["x"], value: decode("0.5") }]), true, `${kind} 0.5`);
      assert.equal(produces([{ kind, path: ["x"], value: decode("0") }]), true, `${kind} 0`);
    }
  });
}
