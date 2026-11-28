// Run with Node.js after installing the verifier. The two SQLite files are real local stores.
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { generateKeyPairSync, sign } from "node:crypto";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { DatabaseSync } from "node:sqlite";
import { fileURLToPath } from "node:url";
import { actionApproval as approval, boundsMaximum, contentAssertion, sha256, strUtf8, type Result } from "@bounded-authority-protocol/verifier";

function take<T>(result: Result<T>): T {
  assert.ok(result.ok);
  return result.value;
}

function transaction<T>(db: DatabaseSync, work: () => T): T {
  db.exec("BEGIN IMMEDIATE");
  try {
    const result = work();
    db.exec("COMMIT");
    return result;
  } catch (error) {
    db.exec("ROLLBACK");
    throw error;
  }
}

type DeliveryStep = "stop-before-commit" | "stop-after-commit" | "reconcile";
const interruptedExit = 75;

function deliver(hostPath: string, destinationPath: string, intentId: string, step: DeliveryStep): void {
  const host = new DatabaseSync(hostPath);
  const destination = new DatabaseSync(destinationPath);
  try {
    const intent = host.prepare("SELECT effect FROM intents WHERE id = ? AND delivered = 0").get(intentId);
    assert.ok(typeof intent?.effect === "string");
    const effect = intent.effect;
    const lookup = destination.prepare("SELECT effect FROM applied WHERE id = ?");
    // An absent effect can be delivered under the same idempotency identity. A present effect
    // must match the committed intent before the host records delivery.
    if (lookup.get(intentId) === undefined) {
      transaction(destination, () => {
        destination.prepare("INSERT INTO applied VALUES (?, ?) ON CONFLICT DO NOTHING").run(intentId, effect);
        if (step === "stop-before-commit") process.exit(interruptedExit);
      });
    }
    assert.equal(lookup.get(intentId)?.effect, effect);
    if (step === "stop-after-commit") process.exit(interruptedExit);
    host.prepare("UPDATE intents SET delivered = 1 WHERE id = ?").run(intentId);
  } finally {
    destination.close();
    host.close();
  }
}

if (process.argv[2] === "--deliver") {
  const step = process.argv[6];
  assert.ok(step === "stop-before-commit" || step === "stop-after-commit" || step === "reconcile");
  deliver(process.argv[3]!, process.argv[4]!, process.argv[5]!, step);
} else {
  const directory = mkdtempSync(join(tmpdir(), "bap-approval-"));
  try {
    const hostPath = join(directory, "host.sqlite");
    const destinationPath = join(directory, "destination.sqlite");
    const host = new DatabaseSync(hostPath);
    const destination = new DatabaseSync(destinationPath);
    const revisions = new DatabaseSync(hostPath);
    try {
      host.exec(`
        CREATE TABLE requests (id TEXT PRIMARY KEY, revision TEXT NOT NULL) STRICT;
        CREATE TABLE artifacts (domain TEXT, issuer TEXT, artifact TEXT, PRIMARY KEY (domain, issuer, artifact)) STRICT;
        CREATE TABLE claims (request TEXT, revision TEXT, PRIMARY KEY (request, revision)) STRICT;
        CREATE TABLE effects (id TEXT PRIMARY KEY, effect TEXT NOT NULL) STRICT;
        CREATE TABLE intents (id TEXT PRIMARY KEY, effect TEXT NOT NULL, delivered INTEGER NOT NULL) STRICT;`);
      destination.exec("CREATE TABLE applied (id TEXT PRIMARY KEY, effect TEXT NOT NULL) STRICT");

      // The host freezes its own request, configures its trust source and chooses the suite.
      const revisionDigest = sha256(strUtf8("release-plan revision 7"));
      const version = Buffer.from(revisionDigest).toString("hex");
      const nextVersion = Buffer.from(sha256(strUtf8("release-plan revision 8"))).toString("hex");
      const subject = "routing-baseline", action = "activate";
      const resources = ["cluster/east", "cluster/west"];
      const {publicKey, privateKey} = generateKeyPairSync("ed25519");
      const now = 20; // Fixed trusted time for this offline example.
      const trustDomain = "configuration-review";
      const issuer = "network-operations", audience = "configuration-executor";
      const context: approval.ApprovalContext = {
        trustDomain, audience, requestId: "activate-7", revisionDigest, subject, action, resources, roles: ["release reviewer"],
        now, maxStaleness: 10, maxLifetime: 30, bounds: boundsMaximum(), recordBounds: {},
        snapshot: {trustDomain, suite: "eddsa", provenance: "enrolled-operations-keys", asOf: now,
          entries: [{issuer, roles: ["release reviewer"], key: {keyId: "review-key",
            publicKey: Buffer.from(publicKey.export({format: "jwk"}).x!, "base64url"), validFrom: 0, validBefore: null}}]},
      };
      for (const id of ["activate-7", "activate-copy", "activate-rollback", "activate-before", "activate-after", "activate-compare", "activate-mismatch"]) {
        host.prepare("INSERT INTO requests VALUES (?, ?)").run(id, version);
      }

      // In a deployment the record and compact arrive from a separately enrolled signer.
      const issue = (requestId: string, artifactId: string, scope = resources) => {
        const record = take(approval.encodeRecord({subject, action, requestId, revisionDigest, resources: scope, approverRole: "release reviewer"}));
        const input = take(contentAssertion.assertionSigningInput({
          attestorKeyId: "review-key", jti: artifactId, iss: issuer, aud: audience, sub: requestId,
          profile: approval.PROFILE, profileDigest: approval.profileDigest(), contentDigest: take(contentAssertion.contentDigest(record)),
          gen: 1, prev: new Uint8Array(32), iat: 15, nbf: 15, exp: 35,
        }));
        const signingInput = Buffer.concat([input.protectedSegment, Buffer.of(46), input.payloadSegment]);
        return {record, compact: take(contentAssertion.assembleCompact(input, sign(null, signingInput, privateKey)))};
      };
      const verified = (requestId: string, artifactId: string) => {
        const {record, compact} = issue(requestId, artifactId);
        return take(approval.verifyEddsa(record, compact, {...context, requestId}));
      };
      const subset = issue(context.requestId, "subset", [resources[0]!]);
      assert.deepEqual(approval.verifyEddsa(subset.record, subset.compact, context), {ok: false, code: "scope_mismatch"});

      type Effect = Pick<approval.ApprovalRecord, "subject" | "action" | "resources">;

      function claim(facts: approval.VerifiedApprovalFacts, prepared: Effect, mode: "local" | "external"): string {
        return transaction(host, () => {
          const {requestId, revisionDigest: revision, subject, action, resources} = facts.record;
          const approvedEffect = {subject, action, resources};
          assert.deepEqual(prepared, approvedEffect, "effect mismatch");
          const effect = JSON.stringify(approvedEffect);
          const revisionHex = Buffer.from(revision).toString("hex");
          assert.equal(host.prepare("SELECT revision FROM requests WHERE id = ?").get(requestId)?.revision, revisionHex, "revision changed");
          const insertArtifact = host.prepare("INSERT INTO artifacts VALUES (?, ?, ?) ON CONFLICT DO NOTHING");
          const insertRequest = host.prepare("INSERT INTO claims VALUES (?, ?) ON CONFLICT DO NOTHING");
          assert.equal(insertArtifact.run(facts.trustDomain, facts.assertion.iss, facts.assertion.jti).changes, 1, "artifact collision");
          assert.equal(insertRequest.run(requestId, revisionHex).changes, 1, "request revision collision");
          const id = JSON.stringify([requestId, revisionHex]);
          if (mode === "local") host.prepare("INSERT INTO effects VALUES (?, ?)").run(id, effect);
          else host.prepare("INSERT INTO intents VALUES (?, ?, 0)").run(id, effect);
          return id;
        });
      }

      // The effect comes from the same host request used to form the expected context.
      const effect = {subject, action, resources};
      const mismatch = verified("activate-mismatch", "artifact-mismatch");
      const mismatchedEffects = [{...effect, subject: "other"}, {...effect, action: "inspect"},
        {...effect, resources: [resources[0]!]}];
      for (const prepared of mismatchedEffects) {
        for (const mode of ["local", "external"] as const) {
          assert.throws(() => claim(mismatch, prepared, mode), /effect mismatch/);
        }
      }
      for (const table of ["artifacts", "claims", "effects", "intents"]) {
        assert.equal(host.prepare(`SELECT count(*) AS total FROM ${table}`).get()?.total, 0);
      }
      claim(verified("activate-7", "artifact-1"), effect, "local");
      assert.throws(() => claim(verified("activate-copy", "artifact-1"), effect, "local"), /artifact collision/);
      assert.throws(() => claim(verified("activate-7", "artifact-2"), effect, "local"), /request revision collision/);
      assert.equal(host.prepare("SELECT artifact FROM artifacts WHERE artifact = ?").get("artifact-2"), undefined);

      host.exec("CREATE TRIGGER refuse_effect BEFORE INSERT ON effects BEGIN SELECT RAISE(ABORT, 'effect failed'); END");
      assert.throws(() => claim(verified("activate-rollback", "artifact-3"), effect, "local"), /effect failed/);
      assert.equal(host.prepare("SELECT artifact FROM artifacts WHERE artifact = ?").get("artifact-3"), undefined);
      assert.equal(host.prepare("SELECT request FROM claims WHERE request = ?").get("activate-rollback"), undefined);

      const comparison = verified("activate-compare", "artifact-4");
      revisions.exec("BEGIN IMMEDIATE");
      try {
        revisions.prepare("UPDATE requests SET revision = ? WHERE id = ?").run(nextVersion, "activate-compare");
        assert.throws(() => claim(comparison, effect, "external"), /database is locked/);
        revisions.exec("COMMIT");
      } catch (error) {
        revisions.exec("ROLLBACK");
        throw error;
      }
      assert.throws(() => claim(comparison, effect, "external"), /revision changed/);

      const worker = (id: string, step: DeliveryStep) => {
        const child = spawnSync(process.execPath, [fileURLToPath(import.meta.url), "--deliver", hostPath, destinationPath, id, step], {encoding: "utf8"});
        assert.equal(child.status, step === "reconcile" ? 0 : interruptedExit, child.stderr);
      };
      for (const [request, step, destinationCommitted] of [
        ["activate-before", "stop-before-commit", false],
        ["activate-after", "stop-after-commit", true],
      ] as const) {
        const id = claim(verified(request, `artifact-${request}`), effect, "external");
        worker(id, step);
        const delivered = host.prepare("SELECT delivered FROM intents WHERE id = ?");
        const applied = destination.prepare("SELECT effect FROM applied WHERE id = ?");
        assert.equal(delivered.get(id)?.delivered, 0);
        assert.equal(applied.get(id) !== undefined, destinationCommitted);
        worker(id, "reconcile");
        assert.equal(applied.get(id)?.effect, JSON.stringify(effect));
        assert.equal(delivered.get(id)?.delivered, 1);
      }
      assert.equal(destination.prepare("SELECT count(*) AS total FROM applied").get()?.total, 2);
      console.log("approval: exact effect, atomic claims, and recovered deliveries");
    } finally {
      revisions.close();
      destination.close();
      host.close();
    }
  } finally {
    rmSync(directory, {recursive: true, force: true});
  }
}
