// The vendored strict-Ed25519 corpus snapshot (conformance/priv/conformance/strict-ed25519), the way this
// repository vendors every other corpus: byte-identical to the certified source, the index SHA-256
// asserted at load, every listed file's SHA-256 recomputed, and the exact file set required. Every
// verdict is then recomputed by the SDK in conformance/core/strict_ed25519.ts (pnpm
// conformance:strict-ed25519). SOURCE binds all nine indexes, independently checked in
// conformance-core.test.ts; this suite checks the strict profile's families and requirements.
import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readdirSync, readFileSync, statSync } from "node:fs";
import { join, relative } from "node:path";

const ROOT = new URL("../conformance/", import.meta.url).pathname;
const sha = (b: Uint8Array) => createHash("sha256").update(b).digest("hex");
const read = (path: string) => new Uint8Array(readFileSync(path));

const STRICT = join(ROOT, "priv/conformance/strict-ed25519");

function files(dir: string): string[] {
  const out: string[] = [];
  for (const name of readdirSync(dir)) {
    const full = join(dir, name);
    if (statSync(full).isDirectory()) out.push(...files(full));
    else out.push(relative(STRICT, full).split("\\").join("/"));
  }
  return out;
}

test("the strict corpus snapshot is exactly the files its index lists, each at its recorded SHA-256", () => {
  const index = JSON.parse(readFileSync(join(STRICT, "index.json"), "utf8")) as {
    profile: string; revision: number; total_cases: number; private_material_tracked: boolean;
    families: Record<string, number>; files: Array<{ path: string; cases?: number; sha256: string }>;
  };
  assert.equal(index.profile, "bap-strict-ed25519/1");
  assert.equal(index.revision, 1);
  assert.equal(index.total_cases, 2410);
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
