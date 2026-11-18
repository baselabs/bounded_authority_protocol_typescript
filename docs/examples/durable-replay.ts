// A host-owned SQLite reservation example. SQLite is the real store, on persistent disk.
import assert from "node:assert/strict";
import { generateKeyPairSync, randomUUID, sign } from "node:crypto";
import { spawn } from "node:child_process";
import { mkdtempSync, rmSync, existsSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { DatabaseSync } from "node:sqlite";

import { assembleCompact, checkEnvelope, grantSigningInput, jwkFromPublicKey, proofSigningInput,
  strUtf8, thumbprint, utf8Str, type ExpectedRequest, type SigningInput } from "@bounded-authority-protocol/verifier";
interface RequestData { grant: string; proof: string; publicKey: number[]; invocation: string }

export function openReplayStore(path: string) {
  const db = new DatabaseSync(path);
  db.exec(`PRAGMA busy_timeout=10000;
    CREATE TABLE IF NOT EXISTS reservations (
      issuer TEXT NOT NULL, grant_id TEXT NOT NULL, invocation_id TEXT NOT NULL,
      retain_until INTEGER NOT NULL,
      PRIMARY KEY (issuer, grant_id, invocation_id)
    ) STRICT;`);
  const insert = db.prepare(`INSERT INTO reservations SELECT ?, ?, ?, ? WHERE ? >= unixepoch('now')
    ON CONFLICT (issuer, grant_id, invocation_id) DO UPDATE
    SET retain_until=excluded.retain_until
    WHERE reservations.retain_until < unixepoch('now')
      AND excluded.retain_until >= unixepoch('now')`);
  return {
    now: () => Number(db.prepare("SELECT unixepoch('now') AS now").get()!.now),
    reserve(issuer: string, grant: string, invocation: string, until: number): boolean {
      assert.ok(Number.isSafeInteger(until));
      // Admission and expiry share one atomic statement and the store's clock.
      return insert.run(issuer, grant, invocation, until, until).changes === 1;
    },
    close: () => db.close(),
  };
}

const worker = process.argv[2] === "--reserve";
if (worker) {
  const store = openReplayStore(process.argv[3]!);
  try {
    const request = JSON.parse(readFileSync(process.argv[4]!, "utf8")) as RequestData;
    const expected: ExpectedRequest = {
      trustedIssuer: { keyId: "issuer-1", publicKey: new Uint8Array(request.publicKey) },
      issuer: "https://issuer.example", audience: "https://records.example", method: "POST",
      targetUri: "https://records.example/records", invocationId: request.invocation,
      operation: "records.create", castArguments: { t: "object", v: new Map() },
      evaluationTime: store.now(), clockSkew: 60, proofMaxAge: 300, nonce: { kind: "not_required" },
    };
    const checked = checkEnvelope(strUtf8(request.grant), strUtf8(request.proof), expected);
    const accepted = checked.ok && store.reserve(checked.value.issuer, checked.value.grantId,
      checked.value.invocationId, checked.value.grantExpiresAt + 60);
    // This demonstration's host policy permits records.create. Live revocation and actual effects
    // are host responsibilities and must also succeed before any production operation.

    process.stdout.write(accepted ? "accepted" : "replayed");
  } finally { store.close(); }
} else {
  const dir = mkdtempSync(join(tmpdir(), "bap-replay-"));
  const path = join(dir, "reservations.sqlite");
  try {
    let store = openReplayStore(path);
    const now = store.now(); const until = now + 3600 + 60;
    store.close();
    const issuer = generateKeyPairSync("ed25519"); const holder = generateKeyPairSync("ed25519");
    const raw = (key: typeof issuer.publicKey): Uint8Array => Buffer.from(key.export({ format: "jwk" }).x!, "base64url");
    const signInput = (input: SigningInput, key: typeof issuer.privateKey): Uint8Array => {
      const result = assembleCompact(input, sign(null, Buffer.concat([input.protectedSegment, Buffer.from("."), input.payloadSegment]), key));
      assert.ok(result.ok); return result.value;
    };
    const g = grantSigningInput({ keyId: "issuer-1", issuer: "https://issuer.example", grantId: "grant-1",
      audiences: ["https://records.example"], issuedAt: now, notBefore: now, expiresAt: now + 3600,
      holderThumbprint: thumbprint(jwkFromPublicKey(raw(holder.publicKey))),
      operations: [{ name: "records.create", selectors: ["all"] }] });
    assert.ok(g.ok); const grant = signInput(g.value, issuer.privateKey); const invocation = randomUUID();
    const p = proofSigningInput({ holderPublicKey: raw(holder.publicKey), proofId: randomUUID(), method: "POST",
      targetUri: "https://records.example/records", issuedAt: now, invocationId: invocation,
      operation: "records.create", grantCompact: grant, castArguments: { t: "object", v: new Map() } });
    assert.ok(p.ok);
    const request: RequestData = { grant: utf8Str(grant), proof: utf8Str(signInput(p.value, holder.privateKey)), publicKey: [...raw(issuer.publicKey)], invocation };
    const fixture = join(dir, "request.json"); writeFileSync(fixture, JSON.stringify(request));
    const contend = (): Promise<string> => new Promise((resolve, reject) => {
      const child = spawn(process.execPath, [fileURLToPath(import.meta.url), "--reserve", path, fixture],
        { stdio: ["ignore", "pipe", "pipe"] });
      let out = ""; let error = "";
      child.stdout.on("data", (chunk: Buffer) => { out += chunk.toString(); });
      child.stderr.on("data", (chunk: Buffer) => { error += chunk.toString(); });
      child.on("error", reject);
      child.on("close", (code) => code === 0 ? resolve(out) : reject(new Error(error)));
    });
    const completed = await Promise.allSettled(Array.from({ length: 12 }, contend));
    const results = completed.map((result) => { assert.equal(result.status, "fulfilled"); return (result as PromiseFulfilledResult<string>).value; });
    assert.equal(results.filter((x) => x === "accepted").length, 1);
    assert.equal(results.filter((x) => x === "replayed").length, 11);
    assert.equal(await contend(), "replayed", "a fresh verifier process still refuses after restart");
    // Every child has exited. Reopen the same file in a new connection after process restart.
    store = openReplayStore(path);
    try {
      assert.equal(store.reserve("https://issuer.example", "grant-1", invocation, until), false);
      assert.equal(store.reserve("https://issuer.example", "grant-2", "invocation-1", until), true);
      assert.equal(store.reserve("https://another.example", "grant-1", "invocation-1", until), true);
      assert.equal(store.reserve("https://issuer.example", "grant-1", "expired", store.now() - 1), false);
    } finally { store.close(); }
    console.log("durable replay: one winner, restart refused, distinct tuples accepted");
  } finally {
    rmSync(dir, { recursive: true, force: true });
    assert.equal(existsSync(dir), false);
  }
}
