// The browser lanes (pnpm test:browser, which builds first): real engines through Playwright, the real
// bundle (esbuild for the browser over browser/main.ts, so "#crypto" resolves the way a browser bundler
// resolves it), the real corpus bytes, served by a node:http server on 127.0.0.1:0 that sends the
// strict CSP on every response. No jsdom, no mocks.
//
// BAP_BROWSERS selects engines (default "chromium"); CI runs chromium, firefox and webkit on Linux.
// BAP_CHROMIUM_EXECUTABLE points Playwright at a locally installed Chromium build when the bundled
// revision is not installed. Linux WebKit is evidence for this pure-JS verifier only, never for Safari.
import { test } from "node:test";
import assert from "node:assert/strict";
import { createServer, type Server } from "node:http";
import { execFileSync } from "node:child_process";
import { readFileSync, readdirSync, statSync } from "node:fs";
import { join, normalize, sep } from "node:path";
import { fileURLToPath } from "node:url";
import { build } from "esbuild";
import { chromium, firefox, webkit, type BrowserType } from "playwright";
import { assertLaneAgrees, summarize, type LaneCorpus } from "./support/lanes.js";

const REPO = fileURLToPath(new URL("..", import.meta.url));
const CONFORMANCE = join(REPO, "conformance");
export const CSP = "default-src 'none'; script-src 'self'; connect-src 'self'; base-uri 'none'; form-action 'none'";
const ENGINES: Record<string, BrowserType> = { chromium, firefox, webkit };
const SELECTED = (process.env.BAP_BROWSERS ?? "chromium").split(",").filter(Boolean);

async function bundle(entry: string): Promise<string> {
  const result = await build({
    entryPoints: [join(REPO, entry)], absWorkingDir: REPO, bundle: true, write: false, format: "esm",
    platform: "browser", target: "es2022", logLevel: "silent",
  });
  return result.outputFiles[0]!.text;
}

function corpusManifest(): string[] {
  const out: string[] = [];
  const walk = (dir: string, prefix: string) => {
    for (const name of readdirSync(dir).sort()) {
      const full = join(dir, name);
      if (statSync(full).isDirectory()) walk(full, `${prefix}${name}/`);
      else out.push(`${prefix}${name}`);
    }
  };
  for (const name of readdirSync(CONFORMANCE).sort()) {
    if (name.startsWith("corpus") && statSync(join(CONFORMANCE, name)).isDirectory()) walk(join(CONFORMANCE, name), `${name}/`);
    else if (/^curated-inputs-.*\.json$/.test(name)) out.push(name);
  }
  return out;
}

interface Served { server: Server; origin: string; requests: string[] }

async function serve(): Promise<Served> {
  const app = await bundle("browser/main.ts");
  const probe = await bundle("browser/eval-probe.ts");
  const manifest = JSON.stringify(corpusManifest());
  const index = readFileSync(join(REPO, "browser/index.html"), "utf8");
  const probeHtml = '<!doctype html><html><head><meta charset="utf-8"><title>CSP probe</title><script type="module" src="/eval-probe.js"></script></head><body data-state="running"></body></html>';
  const requests: string[] = [];
  const server = createServer((req, res) => {
    const url = new URL(req.url ?? "/", "http://127.0.0.1");
    requests.push(url.pathname);
    const send = (status: number, type: string, body: string | Uint8Array) => {
      res.writeHead(status, { "content-type": type, "content-security-policy": CSP, "cache-control": "no-store" });
      res.end(body);
    };
    if (url.pathname === "/") return send(200, "text/html; charset=utf-8", index);
    if (url.pathname === "/app.js") return send(200, "text/javascript; charset=utf-8", app);
    if (url.pathname === "/eval-probe.html") return send(200, "text/html; charset=utf-8", probeHtml);
    if (url.pathname === "/eval-probe.js") return send(200, "text/javascript; charset=utf-8", probe);
    if (url.pathname === "/conformance/manifest.json") return send(200, "application/json", manifest);
    if (url.pathname.startsWith("/conformance/")) {
      const rel = decodeURIComponent(url.pathname.slice("/conformance/".length));
      const full = normalize(join(CONFORMANCE, rel));
      if (!full.startsWith(CONFORMANCE + sep)) return send(403, "text/plain", "forbidden");
      try {
        return send(200, "application/octet-stream", readFileSync(full));
      } catch {
        return send(404, "text/plain", "not found");
      }
    }
    return send(404, "text/plain", "not found");
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address();
  assert.ok(address && typeof address === "object");
  return { server, origin: `http://127.0.0.1:${address.port}`, requests };
}

// Page functions are passed as functions, never as strings: Playwright evaluates a string predicate
// with eval inside the page, which the strict CSP blocks (and reports as a violation).
const pageDone = () => (globalThis as unknown as { document: { body: { dataset: Record<string, string> } } }).document.body.dataset.state === "done";

interface LaneResult { backend: string; secure: boolean; userAgent: string; violations: string[]; error: string | null; corpora: Record<string, LaneCorpus>; totalMs: number }

// The bench page (web/, the Pages site), built as the Pages workflow builds it and served as static
// files: a real click-through of its demo (an agent deploying a build to staging).
async function serveBench(): Promise<{ server: Server; origin: string }> {
  execFileSync(process.execPath, [join(REPO, "web/build.mjs")], { cwd: REPO, stdio: "ignore" });
  const dir = join(REPO, "site-dist");
  const types: Record<string, string> = { html: "text/html; charset=utf-8", js: "text/javascript; charset=utf-8", css: "text/css" };
  const server = createServer((req, res) => {
    const path = new URL(req.url ?? "/", "http://127.0.0.1").pathname;
    const file = path === "/" ? "index.html" : path.slice(1);
    try {
      const body = readFileSync(join(dir, normalize(file)));
      res.writeHead(200, { "content-type": types[file.split(".").pop() ?? ""] ?? "application/octet-stream" });
      res.end(body);
    } catch {
      res.writeHead(404);
      res.end();
    }
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address();
  assert.ok(address && typeof address === "object");
  return { server, origin: `http://127.0.0.1:${address.port}` };
}

// Page functions are serialized into the page, so each one reaches the document through globalThis.
type Doc = { getElementById(id: string): { dataset: Record<string, string>; textContent: string | null; disabled?: boolean } | null };

for (const name of SELECTED) {
  const engine = ENGINES[name];
  assert.ok(engine, `known engine ${name}`);

  test(`${name}: the bench demo (a deploy to staging) mints, verifies, and every tamper is refused`, async () => {
    const bench = await serveBench();
    const executablePath = name === "chromium" ? process.env.BAP_CHROMIUM_EXECUTABLE : undefined;
    const browser = await engine.launch(executablePath ? { executablePath } : {});
    try {
      const page = await browser.newPage();
      const errors: string[] = [];
      page.on("pageerror", (e) => errors.push(String(e)));
      await page.goto(`${bench.origin}/`);
      await page.click("#btn-mint");
      await page.waitForFunction(() => (globalThis as unknown as { document: Doc }).document.getElementById("btn-verify")?.disabled === false, undefined, { timeout: 30_000 });
      const text = async (id: string): Promise<string> =>
        page.evaluate((el) => (globalThis as unknown as { document: Doc }).document.getElementById(el)?.textContent ?? "", id);
      const verdict = async (): Promise<string> => page.evaluate(() => (globalThis as unknown as { document: Doc }).document.getElementById("verdict")?.dataset.state ?? "");
      await page.click("#btn-verify");
      assert.equal(await verdict(), "ok");
      // The verified facts name the demo's operation and target; the demo is not a payment.
      const facts = await text("facts-body");
      assert.match(facts, /deployments\.create/);
      assert.match(facts, /environments\/staging\/deployments/);
      assert.doesNotMatch(`${facts} ${await text("lane-mint")}`, /transfer|amount|withdraw/);
      for (const kind of ["payload", "operation", "expiry", "impostor", "issuer"]) {
        await page.click(`button[data-tamper="${kind}"]`);
        await page.waitForFunction(() => (globalThis as unknown as { document: Doc }).document.getElementById("verdict")?.dataset.state === "fail", undefined, { timeout: 30_000 });
        assert.equal(await verdict(), "fail", kind);
      }
      assert.deepEqual(errors, []);
    } finally {
      await browser.close();
      bench.server.close();
    }
  });

  test(`${name}: BACKEND_ID portable in a secure context under the strict CSP, and every corpus agrees with its pin and with Node`, async (t) => {
    const served = await serve();
    const executablePath = name === "chromium" ? process.env.BAP_CHROMIUM_EXECUTABLE : undefined;
    const browser = await engine.launch(executablePath ? { executablePath } : {});
    try {
      const page = await browser.newPage();
      const response = await page.goto(`${served.origin}/`);
      assert.equal(response?.headers()["content-security-policy"], CSP, "the page is served under the strict CSP");
      await page.waitForFunction(pageDone, undefined, { timeout: 300_000 });
      const result = await page.evaluate(() => (globalThis as unknown as { __BAP_RESULT__: unknown }).__BAP_RESULT__) as LaneResult;
      assert.equal(result.backend, "portable");
      assert.equal(result.secure, true);
      assert.equal(result.error, null);
      assert.deepEqual(result.violations, [], "no CSP violation while verifying");
      assertLaneAgrees(name, result.corpora);
      t.diagnostic(`${name} ${browser.version()} (${result.userAgent}): ${summarize(result.corpora)}; total ${result.totalMs} ms`);
    } finally {
      await browser.close();
      served.server.close();
    }
  });

  test(`${name}: red-proof: a page expecting the wrong backend runs no corpus`, async () => {
    const served = await serve();
    const executablePath = name === "chromium" ? process.env.BAP_CHROMIUM_EXECUTABLE : undefined;
    const browser = await engine.launch(executablePath ? { executablePath } : {});
    try {
      const page = await browser.newPage();
      await page.goto(`${served.origin}/?expect=node`);
      await page.waitForFunction(pageDone, undefined, { timeout: 60_000 });
      const result = await page.evaluate(() => (globalThis as unknown as { __BAP_RESULT__: unknown }).__BAP_RESULT__) as LaneResult;
      assert.match(result.error ?? "", /BACKEND_ID is "portable", this lane expects "node"; no corpus was run/);
      assert.deepEqual(result.corpora, {});
      assert.ok(!served.requests.some((p) => p.startsWith("/conformance/")), "no corpus file was fetched");
    } finally {
      await browser.close();
      served.server.close();
    }
  });

  test(`${name}: red-proof: eval is blocked by the served CSP and the securitypolicyviolation listener records it`, async () => {
    const served = await serve();
    const executablePath = name === "chromium" ? process.env.BAP_CHROMIUM_EXECUTABLE : undefined;
    const browser = await engine.launch(executablePath ? { executablePath } : {});
    try {
      const page = await browser.newPage();
      await page.goto(`${served.origin}/eval-probe.html`);
      await page.waitForFunction(pageDone, undefined, { timeout: 60_000 });
      const probe = await page.evaluate(() => (globalThis as unknown as { __BAP_PROBE__: unknown }).__BAP_PROBE__) as { evalBlocked: boolean; violations: string[] };
      assert.equal(probe.evalBlocked, true);
      assert.ok(probe.violations.some((v) => v.startsWith("script-src")), JSON.stringify(probe.violations));
    } finally {
      await browser.close();
      served.server.close();
    }
  });
}
