// es256VerifyStrict: the synchronous, never-throwing ES256 sibling of verifyStrict. It accepts only a
// 65-byte uncompressed on-curve P-256 key, a 64-byte r || s signature with 0 < r < n and
// 0 < s <= (n - 1) / 2, and then the backend's ECDSA verification. These cases run under the node
// backend (pnpm test) and the portable backend (pnpm test:portable); the last test removes the low-S
// line from the real source and proves the high-S deny case goes red under BOTH backends.
import { test } from "node:test";
import assert from "node:assert/strict";
import { generateKeyPairSync, sign as nodeSign } from "node:crypto";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { build, type Plugin } from "esbuild";
import { es256VerifyStrict } from "../src/index.js";

const N = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n;
const P = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffffn;
const hex = (h: string) => Uint8Array.from(h.match(/../g) ?? [], (b) => parseInt(b, 16));
const big = (b: Uint8Array) => b.reduce((v, x) => (v << 8n) | BigInt(x), 0n);
const be32 = (v: bigint) => hex(v.toString(16).padStart(64, "0"));
const cat = (...parts: Uint8Array[]) => { const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0)); let o = 0; for (const p of parts) { out.set(p, o); o += p.length; } return out; };
const enc = (s: string) => new TextEncoder().encode(s);

// A fresh key and a low-S signature over a message (test-local signing, node:crypto).
function fixture(message: Uint8Array) {
  const { publicKey, privateKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
  const jwk = publicKey.export({ format: "jwk" }) as { x: string; y: string };
  const raw = cat(Uint8Array.of(4), new Uint8Array(Buffer.from(jwk.x, "base64url")), new Uint8Array(Buffer.from(jwk.y, "base64url")));
  const sig = new Uint8Array(nodeSign("sha256", message, { key: privateKey, dsaEncoding: "ieee-p1363" }));
  const r = sig.subarray(0, 32);
  const s = big(sig.subarray(32));
  const low = s > (N - 1n) / 2n ? N - s : s;
  return { raw, low: cat(r, be32(low)), high: cat(r, be32(N - low)), r: big(r), lowS: low };
}

const MESSAGE = enc("es256VerifyStrict");
const F = fixture(MESSAGE);

// RFC 6979 appendix A.2.5 (P-256, SHA-256, message "test"): an independent published low-S vector.
const RFC6979_PUBLIC = hex("04" + "60fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb6" + "7903fe1008b8bc99a41ae9e95628bc64f2f1b20c2d7e9f5177a3c294d4462299");
const RFC6979_TEST = hex("f1abb023518351cd71d881567b1ea663ed3efcf6c5132b354f28d3b0b7d38367" + "019f4113742a2b14bd25926b49c649155f267e60d3814b4c0cc84250e46f0083");

test("allow: a valid low-S signature verifies (generated key, and the RFC 6979 vector)", () => {
  assert.equal(es256VerifyStrict(MESSAGE, F.low, F.raw), true);
  assert.equal(es256VerifyStrict(enc("test"), RFC6979_TEST, RFC6979_PUBLIC), true);
});

test("deny: the high-S twin of a valid signature", () => {
  assert.equal(es256VerifyStrict(MESSAGE, F.high, F.raw), false);
});

test("deny: r = 0, r = n, s = 0, s = n, s = n + 1", () => {
  for (const [r, s] of [[0n, F.lowS], [N, F.lowS], [F.r, 0n], [F.r, N], [F.r, N + 1n]] as const) {
    assert.equal(es256VerifyStrict(MESSAGE, cat(be32(r), be32(s)), F.raw), false, `r=${r} s=${s}`);
  }
});

test("deny: a wrong key and a wrong message", () => {
  assert.equal(es256VerifyStrict(MESSAGE, F.low, fixture(MESSAGE).raw), false);
  assert.equal(es256VerifyStrict(enc("es256VerifyStrict!"), F.low, F.raw), false);
});

test("malformed: 63- and 65-byte signatures, compressed, hybrid-prefix and off-curve keys", () => {
  assert.equal(es256VerifyStrict(MESSAGE, F.low.subarray(0, 63), F.raw), false);
  assert.equal(es256VerifyStrict(MESSAGE, cat(F.low, Uint8Array.of(0)), F.raw), false);
  const x = F.raw.subarray(1, 33);
  const yOdd = (F.raw[64]! & 1) === 1;
  assert.equal(es256VerifyStrict(MESSAGE, F.low, cat(Uint8Array.of(yOdd ? 3 : 2), x)), false, "compressed");
  assert.equal(es256VerifyStrict(MESSAGE, F.low, cat(Uint8Array.of(yOdd ? 7 : 6), F.raw.subarray(1))), false, "hybrid prefix");
  const offCurve = new Uint8Array(F.raw);
  offCurve[64] = offCurve[64]! ^ 1;
  assert.equal(es256VerifyStrict(MESSAGE, F.low, offCurve), false, "off-curve");
  assert.equal(es256VerifyStrict(MESSAGE, F.low, cat(Uint8Array.of(4), be32(P), F.raw.subarray(33))), false, "x = p");
});

test("malformed: non-Uint8Array inputs return false and never throw", () => {
  const values: unknown[] = [undefined, null, "", 0, [], {}, Array.from(F.low), new ArrayBuffer(64)];
  for (const v of values) {
    assert.equal(es256VerifyStrict(v as Uint8Array, F.low, F.raw), false);
    assert.equal(es256VerifyStrict(MESSAGE, v as Uint8Array, F.raw), false);
    assert.equal(es256VerifyStrict(MESSAGE, F.low, v as Uint8Array), false);
  }
});

// ---- mutation: the low-S clause is load-bearing under both backends ----

// The clause is the canonical-signature rule's single spelling in es256VerifyStrict (erratum 3
// made canonicalSignature the one owner; see src/es256.ts). Removing the call must let the
// high-S twin verify, which proves the clause still gates this surface.
const REPO = fileURLToPath(new URL("..", import.meta.url));
const LOW_S_LINE = "    if (!canonicalSignature(signature)) return false; // the rule's single spelling (see above)\n";

async function mutatedVerifyStrict(backend: "node" | "portable"): Promise<typeof es256VerifyStrict> {
  const plugin: Plugin = {
    name: "remove-low-s",
    setup(b) {
      b.onResolve({ filter: /^#crypto$/ }, () => ({ path: `${REPO}src/crypto/${backend}.ts` }));
      b.onLoad({ filter: /src[\\/]es256\.ts$/ }, (args) => {
        const source = readFileSync(args.path, "utf8");
        assert.ok(source.includes(LOW_S_LINE), "the low-S line exists to be removed");
        return { contents: source.replace(LOW_S_LINE, ""), loader: "ts" };
      });
    },
  };
  const result = await build({
    stdin: { contents: 'export { es256VerifyStrict } from "./src/es256.ts";', resolveDir: REPO, sourcefile: "m.ts", loader: "ts" },
    bundle: true, write: false, format: "esm", platform: "node", plugins: [plugin], logLevel: "silent",
  });
  const mod = (await import(`data:text/javascript;base64,${Buffer.from(result.outputFiles[0]!.text).toString("base64")}`)) as { es256VerifyStrict: typeof es256VerifyStrict };
  return mod.es256VerifyStrict;
}

for (const backend of ["node", "portable"] as const) {
  test(`mutation: without the low-S line the high-S twin verifies under the ${backend} backend (the deny case goes red)`, async () => {
    const mutated = await mutatedVerifyStrict(backend);
    assert.equal(mutated(MESSAGE, F.low, F.raw), true, "control");
    assert.equal(mutated(MESSAGE, F.high, F.raw), true, "the deny case fails once the line is gone");
  });
}
