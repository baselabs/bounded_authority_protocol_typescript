// The vendored strict-Ed25519 corpus snapshot (conformance/corpus-strict-ed25519), the way this
// repository vendors every other corpus: byte-identical to the certified source, the index SHA-256
// asserted at load, every listed file's SHA-256 recomputed, and the exact file set required. Every
// verdict is then recomputed by the SDK in conformance/run_strict_ed25519.ts (pnpm
// conformance:strict-ed25519); this suite pins the snapshot itself and the no-flip property: the
// index of every EXISTING corpus is byte-identical to its certified pin, so adding this corpus rotated
// none of them (the strict corpus is additive).
import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readdirSync, readFileSync, statSync } from "node:fs";
import { join, relative } from "node:path";

const ROOT = new URL("../conformance/", import.meta.url).pathname;
const sha = (b: Uint8Array) => createHash("sha256").update(b).digest("hex");
const read = (path: string) => new Uint8Array(readFileSync(path));

const STRICT = join(ROOT, "corpus-strict-ed25519");
const STRICT_INDEX_SHA256 = "0cfae60706387c8436735fd0282c3b7bed270105f6ec57e654cf1ccf3c80180c";

function files(dir: string): string[] {
  const out: string[] = [];
  for (const name of readdirSync(dir)) {
    const full = join(dir, name);
    if (statSync(full).isDirectory()) out.push(...files(full));
    else out.push(relative(STRICT, full).split("\\").join("/"));
  }
  return out;
}

test("the strict corpus index matches its certified SHA-256 pin", () => {
  assert.equal(sha(read(join(STRICT, "index.json"))), STRICT_INDEX_SHA256);
});

test("the strict corpus snapshot is exactly the files its index lists, each at its recorded SHA-256", () => {
  const index = JSON.parse(readFileSync(join(STRICT, "index.json"), "utf8")) as {
    profile: string; revision: number; total_cases: number; private_material_tracked: boolean;
    families: Record<string, number>; files: Array<{ path: string; cases?: number; sha256: string }>;
  };
  assert.equal(index.profile, "bap-strict-ed25519/1");
  assert.equal(index.revision, 1);
  assert.equal(index.total_cases, 2391);
  assert.equal(index.private_material_tracked, false);
  const listed = index.files.map((f) => f.path).sort();
  assert.deepEqual(listed, files(STRICT).filter((p) => p !== "index.json").sort(), "no unlisted or missing file");
  let cases = 0;
  const perFamily: Record<string, number> = {};
  for (const entry of index.files) {
    const bytes = read(join(STRICT, entry.path));
    assert.equal(sha(bytes), entry.sha256, entry.path);
    if (!entry.path.startsWith("cases/")) continue;
    const parsed = JSON.parse(Buffer.from(bytes).toString("utf8")) as { family: string; cases: unknown[] };
    assert.equal(parsed.cases.length, entry.cases, entry.path);
    cases += parsed.cases.length;
    perFamily[parsed.family] = (perFamily[parsed.family] ?? 0) + parsed.cases.length;
  }
  assert.equal(cases, index.total_cases);
  assert.deepEqual(perFamily, index.families);
});

test("the strict corpus profile names the rule requirement ids, the torsion note and the core families", () => {
  const profile = JSON.parse(readFileSync(join(STRICT, "profile.json"), "utf8")) as { requirement_ids: string[]; families: string[]; torsion_note: string };
  assert.ok(profile.requirement_ids.includes("REQ1-SIGNING-ed25519-small-order-reject"));
  assert.ok(profile.requirement_ids.includes("REQ1-HOST-ed25519-torsion-free"));
  assert.equal(profile.torsion_note, "accepted at verify; rejected by torsion_free?");
  for (const family of ["primitive", "key-acceptance", "grant-verify", "envelope", "differential", "taming", "jcs-utf8"]) {
    assert.ok(profile.families.includes(family), family);
  }
});

// The existing corpora are certified artifacts. Their index SHA-256 pins are asserted here independently
// of their runners; a byte change to any of them goes red.
const EXISTING_INDEX_PINS: Array<[string, string]> = [
  ["corpus", "4cb5072ab40ffd4b111659e6d4ab20209202380505f1f8424b96d22e533cb91b"],
  ["corpus-v2", "6de6289b7f47b0e0a78ea4610e7844a0f1d5247d8eace02ec9cf9841308f13d0"],
  ["corpus-v3", "a5c8075e7534345c3bb6611d0b40292904bcfa3af0702e07ae014fa66926433c"],
  ["corpus-role-attestation", "be5275c69539a0f31734242ff00a484c2f855f39181c55689d8b0f671195d62a"],
  ["corpus-content-assertion", "14b7436ccf7cc91fece52a1578c3760df6720a93494d147ee5ab523e2ce21876"],
  ["corpus-local-loopback-http", "10fc4cf05affcddc9e6340ff392c247e25ab038cd938f2557829a7ce63b1a5e4"],
];
for (const [dir, pin] of EXISTING_INDEX_PINS) {
  test(`existing corpus ${dir} keeps its certified index SHA-256 (the strict corpus is additive)`, () => {
    assert.equal(sha(read(join(ROOT, dir, "index.json"))), pin);
  });
}
