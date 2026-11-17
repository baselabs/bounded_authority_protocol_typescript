import assert from "node:assert/strict";
import { readFile, readdir } from "node:fs/promises";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { test } from "node:test";

const root = fileURLToPath(new URL("..", import.meta.url));

async function files(path: string): Promise<string[]> {
  const entries = await readdir(path, { withFileTypes: true });
  return (await Promise.all(entries.map((entry) => entry.isDirectory()
    ? files(join(path, entry.name)) : [join(path, entry.name)]))).flat();
}

function anchors(markdown: string): Set<string> {
  const result = new Set<string>();
  const counts = new Map<string, number>();
  for (const match of markdown.matchAll(/^#{1,6}\s+(.+?)(?:\s+#+)?$/gm)) {
    const slug = match[1]!.toLowerCase().replace(/<[^>]+>/g, "")
      .replace(/[^\p{L}\p{M}\p{N}_\-\s]/gu, "").replace(/ /g, "-");
    const count = counts.get(slug) ?? 0;
    result.add(count ? `${slug}-${count}` : slug);
    counts.set(slug, count + 1);
  }
  for (const match of markdown.matchAll(/<a\s+(?:id|name)=["']([^"']+)["']/g)) result.add(match[1]!);
  return result;
}

test("every spec citation resolves to a real protocol heading or explicit anchor", async () => {
  const paths = [join(root, "README.md"), join(root, "CHANGELOG.md"),
    ...(await Promise.all(["src", "conformance", "docs"].map((name) => files(join(root, name))))).flat()];
  const citations: { path: string; spec: string; anchor: string }[] = [];
  for (const path of paths) {
    // Comments can wrap a filename across lines, including immediately after a hyphen.
    const text = (await readFile(path, "utf8")).replace(/\r?\n\s*(?:\/\/|\*)\s*/g, "");
    for (const match of text.matchAll(/spec\/([\w.-]+\.md)#([\w%.-]+)/g)) {
      citations.push({ path, spec: match[1]!, anchor: decodeURIComponent(match[2]!.replace(/[.,;:]+$/, "")) });
    }
  }
  assert.ok(citations.length > 0, "the gate must discover actual citations");
  const headings = new Map(await Promise.all([...new Set(citations.map((c) => c.spec))].map(async (spec) => {
    let markdown: string;
    if (process.env.BAP_SPEC_DIR) markdown = await readFile(join(process.env.BAP_SPEC_DIR, spec), "utf8");
    else {
      const response = await fetch(`https://raw.githubusercontent.com/baselabs/bounded_authority_protocol/main/spec/${spec}`, {
        signal: AbortSignal.timeout(30_000),
      });
      assert.equal(response.status, 200, `load real normative spec ${spec}`);
      markdown = await response.text();
    }
    return [spec, anchors(markdown)] as const;
  })));
  const broken = citations.filter((c) => !headings.get(c.spec)!.has(c.anchor));
  assert.deepEqual(broken, [], "every cited fragment must exist in the actual normative text");
  console.log(`Resolved ${citations.length} spec citations in ${headings.size} normative documents.`);
});
