import { test } from "node:test";
import assert from "node:assert/strict";
import nodeCrypto from "node:crypto";

import { strUtf8 } from "../src/json.js";
import { MAXIMA, boundsNew } from "../src/bounds.js";
import { base64urlEncode } from "../src/base64url.js";
import * as v1 from "../src/v1.js";
import * as v2 from "../src/v2.js";
import * as v3 from "../src/v3.js";
import type { GrantProducer } from "../src/v1.js";

// The Result contract on every public surface: a malformed CALLER CONTEXT — a garbage Bounds
// object, or a grant producer with junk field types — returns the single closed error. It
// never throws a native TypeError past `trying()` (which re-throws non-InvalidError as a
// bug, crashing the caller) and never silently coerces (a null keyId minting kid "null").
// The role-attestation profile closed these classes at its own landing; this suite sweeps
// the contract-major façades (v1/v2/v3) — cross-vendor review m1/m2, owner-authorized sweep.

const utf8 = (bytes: Uint8Array) => new TextDecoder().decode(bytes);

// A byte-shape-only compact ("x.y.z" — 3 segments, garbage content): every decode/verify path
// must reject it as INVALID for CONTENT reasons; the bounds gate must reject BEFORE any of
// that, so the verdict with a malformed Bounds is the closed error regardless.
const GARBAGE_COMPACT = strUtf8("x.y.z");

const GRANT: GrantProducer = {
  keyId: "issuer-1",
  issuer: "https://issuer.example.test",
  grantId: "urn:example:grant:1",
  audiences: ["https://resource.example.test"],
  issuedAt: 1000,
  notBefore: 1000,
  expiresAt: 2000,
  holderThumbprint: utf8(base64urlEncode(new Uint8Array(32).fill(1))),
  operations: [{ name: "read", selectors: ["all"] }],
};
// The v1-style 32-byte thumbprint shape is valid at all three producers' shape gates (each
// major applies its own suite-specific fingerprint semantics after the field-type gate).

const HIST_KEY = { keyId: "k", publicKey: new Uint8Array(32), validFrom: 0, validBefore: null };

// A REAL P-256 uncompressed point for v3 surfaces: the all-zero 65-byte array fails v3's
// on-curve validation before the bounds gate is ever reached (a vacuous cell — review F4).
function freshEcPublicKey(): Uint8Array {
  const { publicKey } = nodeCrypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
  return new Uint8Array(publicKey.export({ type: "spki", format: "der" }).subarray(-65));
}

// Every surface that accepts caller bounds (directly or inside an expected struct).
function boundsSurfaces(): Array<[string, (bounds: unknown) => unknown]> {
  return [
    ["v1.untrustedKeyLocator", (b) => v1.untrustedKeyLocator(GARBAGE_COMPACT, b as never)],
    ["v1.decodeGrant", (b) => v1.decodeGrant(GARBAGE_COMPACT, b as never)],
    ["v1.decodeProof", (b) => v1.decodeProof(GARBAGE_COMPACT, b as never)],
    ["v1.assembleCompact", (b) => v1.assembleCompact({ kind: "grant", protectedSegment: strUtf8("a"), payloadSegment: strUtf8("b") }, new Uint8Array(64), b as never)],
    ["v1.grantSigningInput", (b) => v1.grantSigningInput(GRANT, b as never)],
    ["v1.verifyGrant", (b) => v1.verifyGrant(GARBAGE_COMPACT, { keyId: "k", publicKey: new Uint8Array(32) }, { issuer: "i", audience: "a", evaluationTime: 1, clockSkew: 0, bounds: b as never })],
    ["v1.verifyHistoricalAnchor", (b) => v1.verifyHistoricalAnchor(GARBAGE_COMPACT, HIST_KEY, { anchorId: "a", anchoredAt: 1, chainId: "c", sequence: 1, chainHash: new Uint8Array(32), keyId: "k", keyFingerprint: new Uint8Array(32), bounds: b as never })],
    ["v1.encodeConsumptionEntry", (b) => v1.encodeConsumptionEntry({ chainId: "c", sequence: 1, previousHash: new Uint8Array(32), commitment: new Uint8Array(32) }, b as never)],
    ["v2.decodeGrant", (b) => v2.decodeGrant(GARBAGE_COMPACT, b as never)],
    ["v2.grantSigningInput", (b) => v2.grantSigningInput(GRANT, b as never)],
    ["v2.verifyGrant", (b) => v2.verifyGrant(GARBAGE_COMPACT, { keyId: "k", publicKey: new Uint8Array(32) }, { issuer: "i", audience: "a", evaluationTime: 1, clockSkew: 0, bounds: b as never })],
    ["v3.decodeGrant", (b) => v3.decodeGrant(GARBAGE_COMPACT, b as never)],
    ["v3.grantSigningInput", (b) => v3.grantSigningInput(GRANT, b as never)],
    ["v3.verifyGrant", (b) => v3.verifyGrant(GARBAGE_COMPACT, { keyId: "k", publicKey: freshEcPublicKey() }, { issuer: "i", audience: "a", evaluationTime: 1, clockSkew: 0, bounds: b as never })],
  ];
}

const MALFORMED_BOUNDS: Array<[string, unknown]> = [
  ["empty object", {}],
  ["maximum only (overrides missing)", { maximum: {} }],
  ["overrides null", { maximum: {}, overrides: null }],
  ["overrides non-pair array", { maximum: {}, overrides: [1, 2] }],
  ["overrides string", { maximum: {}, overrides: "map" }],
  ["overrides number", { maximum: {}, overrides: 5 }],
  ["bounds as array", []],
  ["bounds as string", "bounds"],
  ["maximum missing, overrides a valid Map", { overrides: new Map() }],
];

test("malformed caller Bounds returns the closed error on every contract-major surface", () => {
  for (const [shapeName, shape] of MALFORMED_BOUNDS) {
    for (const [surfaceName, call] of boundsSurfaces()) {
      let result: unknown = undefined;
      assert.doesNotThrow(() => {
        result = call(shape);
      }, `${surfaceName} threw on malformed bounds (${shapeName}) — past the Result contract`);
      assert.ok(
        typeof result === "object" && result !== null && (result as { ok?: unknown }).ok === false,
        `${surfaceName} must fail closed on malformed bounds (${shapeName})`,
      );
    }
  }
});

test("legal caller Bounds still resolve on every contract-major surface", () => {
  const legal: Array<[string, unknown]> = [
    ["undefined (the default)", undefined],
    ["the immutable maximum", { maximum: MAXIMA, overrides: new Map() }],
    ["boundsNew tightened", boundsNew({ compact_bytes: 4096 })],
  ];
  for (const [shapeName, shape] of legal) {
    for (const [surfaceName, call] of boundsSurfaces()) {
      // What this leg checks: legal bounds must not fault the call. The producer surfaces
      // must SUCCEED; the GARBAGE_COMPACT decode/verify surfaces reject on content either
      // way (bounds-tightening effect is covered by the permissiveness suite, not here).
      let result: unknown = undefined;
      assert.doesNotThrow(() => {
        result = call(shape);
      }, `${surfaceName} threw on legal bounds (${shapeName})`);
      if (surfaceName.endsWith("grantSigningInput")) {
        assert.ok((result as { ok?: boolean }).ok === true, `${surfaceName} must accept legal bounds (${shapeName})`);
      }
    }
  }
});

test("anchor producers reject junk field types with the closed error (no coercion, no TypeError)", () => {
  const ANCHOR = {
    keyId: "issuer-1", anchorId: "urn:example:anchor:1", chainId: "urn:example:chain:1",
    anchoredAt: 1000, sequence: 1, chainHash: new Uint8Array(32), publicKey: new Uint8Array(32),
  };
  const producers: Array<[string, (a: unknown) => unknown]> = [
    ["v1.boundaryAnchorSigningInput", (a) => v1.boundaryAnchorSigningInput(a as never)],
    ["v2.boundaryAnchorSigningInput", (a) => v2.boundaryAnchorSigningInput(a as never)],
    ["v3.boundaryAnchorSigningInput", (a) => v3.boundaryAnchorSigningInput(a as never)],
  ];
  const junk: Array<[string, unknown]> = [
    ["keyId null (would coerce to kid \"null\")", { ...ANCHOR, keyId: null }],
    ["keyId number (would coerce to kid \"123\")", { ...ANCHOR, keyId: 123 }],
    ["anchorId number", { ...ANCHOR, anchorId: 123 }],
    ["chainId null", { ...ANCHOR, chainId: null }],
    ["chainHash null", { ...ANCHOR, chainHash: null }],
  ];
  for (const [producerName, produce] of producers) {
    // v3's suite-specific public-key width (65-byte EC) would mask the shape gate, so v3's
    // junk inputs carry the EC point — the field-type gate is what must fire.
    const adapt = producerName.startsWith("v3")
      ? (input: Record<string, unknown>) => ({ ...input, publicKey: freshEcPublicKey() })
      : (input: Record<string, unknown>) => input;
    for (const [junkName, input] of junk) {
      let result: unknown = undefined;
      assert.doesNotThrow(() => {
        result = produce(adapt(input as Record<string, unknown>));
      }, `${producerName} threw on ${junkName} — past the Result contract`);
      assert.ok(
        typeof result === "object" && result !== null && (result as { ok?: unknown }).ok === false,
        `${producerName} must fail closed on ${junkName}`,
      );
    }
  }
});

test("grant producers reject junk field types with the closed error (no coercion, no TypeError)", () => {
  const producers: Array<[string, (g: unknown) => unknown]> = [
    ["v1.grantSigningInput", (g) => v1.grantSigningInput(g as never)],
    ["v2.grantSigningInput", (g) => v2.grantSigningInput(g as never)],
    ["v3.grantSigningInput", (g) => v3.grantSigningInput(g as never)],
  ];
  const junk: Array<[string, unknown]> = [
    ["keyId null (would coerce to kid \"null\")", { ...GRANT, keyId: null }],
    ["keyId number (would coerce to kid \"123\")", { ...GRANT, keyId: 123 }],
    ["grantId number", { ...GRANT, grantId: 123 }],
    ["issuer null", { ...GRANT, issuer: null }],
    ["audiences null", { ...GRANT, audiences: null }],
    ["audiences with a number member", { ...GRANT, audiences: [1] }],
    ["operations null", { ...GRANT, operations: null }],
    ["operations with a null member", { ...GRANT, operations: [null] }],
    ["operation name null", { ...GRANT, operations: [{ name: null, selectors: ["all"] }] }],
    ["selectors null", { ...GRANT, operations: [{ name: "read", selectors: null }] }],
    ["selectors number", { ...GRANT, operations: [{ name: "read", selectors: 5 }] }],
    ["selector item null", { ...GRANT, operations: [{ name: "read", selectors: [null] }] }],
    ["equals path as string (would mint [a,b,c])", { ...GRANT, operations: [{ name: "read", selectors: [{ kind: "equals", path: "abc" as never, value: { t: "int", v: 1 } }] }] }],
    ["equals path of numbers (would mint [1,2])", { ...GRANT, operations: [{ name: "read", selectors: [{ kind: "equals", path: [1, 2] as never, value: { t: "int", v: 1 } }] }] }],
    ["equals path null", { ...GRANT, operations: [{ name: "read", selectors: [{ kind: "equals", path: null, value: { t: "int", v: 1 } }] }] }],
    ["equals value null", { ...GRANT, operations: [{ name: "read", selectors: [{ kind: "equals", path: ["amount"], value: null }] }] }],
    ["one_of values null", { ...GRANT, operations: [{ name: "read", selectors: [{ kind: "one_of", path: ["region"], values: null }] }] }],
    ["one_of values number", { ...GRANT, operations: [{ name: "read", selectors: [{ kind: "one_of", path: ["region"], values: 3 }] }] }],
    ["one_of values with null member", { ...GRANT, operations: [{ name: "read", selectors: [{ kind: "one_of", path: ["region"], values: [{ t: "string", v: strUtf8("x") }, null] }] }] }],
  ];
  // v2/v3-only: the lte/gte numeric-bound arms (v1 has no range selectors). The null-value
  // leg pins isNumericTag's null guard — without it the whole suite stays green (review gap).
  const junkV2V3: Array<[string, unknown]> = [
    ["lte value null", { ...GRANT, operations: [{ name: "read", selectors: [{ kind: "lte", path: ["amount"], value: null }] }] }],
    ["gte value null", { ...GRANT, operations: [{ name: "read", selectors: [{ kind: "gte", path: ["amount"], value: null }] }] }],
    ["lte value untagged number", { ...GRANT, operations: [{ name: "read", selectors: [{ kind: "lte", path: ["amount"], value: 5 }] }] }],
  ];
  const v2v3Producers: Array<[string, (g: unknown) => unknown]> = [
    ["v2.grantSigningInput", (g) => v2.grantSigningInput(g as never)],
    ["v3.grantSigningInput", (g) => v3.grantSigningInput(g as never)],
  ];
  for (const [producerName, produce] of [...producers, ...v2v3Producers]) {
    const matrix = producerName.startsWith("v1") ? junk : [...junk, ...junkV2V3];
    for (const [junkName, input] of matrix) {
      let result: unknown = undefined;
      assert.doesNotThrow(() => {
        result = produce(input);
      }, `${producerName} threw on ${junkName} — past the Result contract`);
      assert.ok(
        typeof result === "object" && result !== null && (result as { ok?: unknown }).ok === false,
        `${producerName} must fail closed on ${junkName}`,
      );
    }
  }
});
