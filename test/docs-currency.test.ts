import assert from "node:assert/strict";
import { existsSync, readFileSync } from "node:fs";
import { dirname, extname, join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { test } from "node:test";
import ts from "typescript";
import { authoredSamples, docFiles, filesUnder, markdown, publicDeclarations, samplesIn, type Token } from "./support/documents.js";

const root = fileURLToPath(new URL("..", import.meta.url));
const pkg = JSON.parse(readFileSync(join(root, "package.json"), "utf8")) as { name: string; version: string; files: string[] };
const manifest = JSON.parse(readFileSync(join(root, "docs/manifest.json"), "utf8")) as {
  package: string; version: string; pages: { path: string; title: string }[]; extras: string[];
  runnableSources: string[]; previousReleaseLines: string[];
};
const notebookRegistry = JSON.parse(readFileSync(join(root, "docs/notebooks/registry.json"), "utf8")) as {
  schema: number; package: string; version: string; packages: Record<string, string>; notebooks: { file: string; title: string }[];
};
const notebooks = notebookRegistry.notebooks.map((item) => ({ ...item, path: `docs/notebooks/${item.file}` }));
function tokens(source: string): Token[] {
  const flatten = (items: Token[]): Token[] => items.flatMap((item) => [item, ...flatten(item.children ?? [])]);
  return flatten(markdown.parse(source, {}));
}
function anchors(source: string): Set<string> {
  const result = new Set<string>(); const counts = new Map<string, number>();
  const parsed = markdown.parse(source, {});
  for (const [index, token] of parsed.entries()) {
    if (token.type !== "heading_open") continue;
    const title = parsed[index + 1]!.content;
    const slug = title.toLowerCase().replace(/<[^>]*>|[\p{P}\p{S}]/gu, (s) => s === "-" || s === "_" ? s : "").replace(/\s/g, "-");
    const count = counts.get(slug) ?? 0; counts.set(slug, count + 1);
    result.add(slug + (count ? `-${count}` : ""));
  }
  for (const match of source.matchAll(/\b(?:id|name)=["']([^"']+)["']/g)) result.add(match[1]!);
  return result;
}
function checkLinks(source: string, file: string): void {
  const parsed = tokens(source);
  const links = parsed.flatMap((token) => (token.attrs ?? [])
    .filter(([key]) => key === "href" || key === "src").map(([, value]) => value));
  // HTML links are also authored documentation surfaces, including the bench.
  // Fenced HTML programs are executed by the browser lane, not resolved as prose links.
  for (const token of parsed.filter((item) => item.type === "html_block" || item.type === "html_inline")) {
    links.push(...[...token.content.matchAll(/\b(?:href|src)=["']([^"']+)["']/g)].map((match) => match[1]!));
  }
  for (const href of links) {
    if (/^(?:[a-z][a-z\d+.-]*:|\/\/)/i.test(href)) continue;
    const [target, fragment] = href.split("#");
    // Build output references on the bench are checked by its real browser lane.
    if (file.endsWith("web/index.html") && /^(?:\.\/)?(?:api\/|app\.|styles\.)/.test(target ?? "")) continue;
    const path = target ? resolve(dirname(file), decodeURIComponent(target.split("?")[0]!)) : file;
    assert.ok(existsSync(path), `${relative(root, file)}: missing ${href}`);
    if (!fragment) continue;
    const suffix = extname(path);
    if (suffix === ".md" || suffix === ".html") assert.ok(anchors(readFileSync(path, "utf8")).has(decodeURIComponent(fragment)), `${relative(root, file)}: missing anchor ${href}`);
    else if (suffix === ".ts") assert.match(fragment, /^L\d+(?:-L\d+)?$/);
  }
}

test("ordered manifest covers every guide, notebook and runnable source", () => {
  assert.equal(manifest.package, pkg.name); assert.equal(manifest.version, pkg.version);
  assert.equal(notebookRegistry.schema, 1); assert.equal(notebookRegistry.package, pkg.name);
  assert.equal(notebookRegistry.packages[pkg.name], pkg.version);
  const registered = manifest.pages.map((page) => page.path);
  const typedoc = JSON.parse(readFileSync(join(root, "typedoc.json"), "utf8")) as { projectDocuments: string[]; requiredToBeDocumented: string[] };
  assert.deepEqual(typedoc.projectDocuments, [...registered, ...manifest.extras]);
  assert.ok(typedoc.requiredToBeDocumented.includes("Constructor"));
  assert.equal(new Set(registered).size, registered.length);
  assert.deepEqual([...registered].sort(), filesUnder(join(root, "docs/guides")).filter((p) => p.endsWith(".md")).map((p) => relative(root, p)).sort());
  assert.deepEqual(notebooks.map((n) => n.path).sort(), filesUnder(join(root, "docs/notebooks")).filter((p) => p.endsWith(".ipynb")).map((p) => relative(root, p)).sort());
  assert.deepEqual(manifest.runnableSources, filesUnder(join(root, "docs/examples")).filter((p) => p.endsWith(".ts")).map((p) => relative(root, p)).sort());
  const overview = readFileSync(join(root, "README.md"), "utf8");
  assert.ok(Buffer.byteLength(overview) < 60_000, "registry README must stay below npm truncation");
  const indexText = overview.slice(overview.indexOf("## Documentation"));
  let previous = -1;
  for (const [index, page] of manifest.pages.entries()) {
    const position = indexText.indexOf(`](${page.path})`);
    assert.ok(position > previous, `${page.path}: ordered README index`); previous = position;
    const text = readFileSync(join(root, page.path), "utf8");
    assert.ok(text.includes("Documentation navigation: [Previous:") && text.includes("[Next:"), page.path);
    if (index) assert.ok(text.includes(`](${manifest.pages[index - 1]!.path.split("/").at(-1)})`));
    if (index + 1 < manifest.pages.length) assert.ok(text.includes(`](${manifest.pages[index + 1]!.path.split("/").at(-1)})`));
  }
  const start = readFileSync(join(root, "docs/guides/getting-started.md"), "utf8");
  for (const item of notebooks) {
    assert.equal(notebookRegistry.version, pkg.version);
    assert.ok(overview.includes(`](${item.path})`));
    assert.ok(start.includes(`](../notebooks/${item.path.split("/").at(-1)})`));
    const notebook = JSON.parse(readFileSync(join(root, item.path), "utf8")) as {
      metadata: { kernelspec: { name: string } }; cells: { cell_type: string; source: string[] | string; outputs?: unknown[] }[];
    };
    assert.equal(notebook.metadata.kernelspec.name, "deno");
    const cells = notebook.cells.filter((cell) => cell.cell_type === "code"); assert.ok(cells.length >= 2);
    for (const cell of cells) {
      const code = Array.isArray(cell.source) ? cell.source.join("") : cell.source;
      assert.ok(cell.outputs?.length, `${item.path}: missing persisted output`);
      for (const match of code.matchAll(/npm:@bounded-authority-protocol\/verifier@([^"/\s]+)/g)) assert.equal(match[1], pkg.version);
    }
  }
  for (const name of ["docs", "CONTRIBUTING.md", "usage-rules.md", "SECURITY.md", "CHANGELOG.md"]) assert.ok(pkg.files.includes(name));
});

test("all authored relative links and anchors resolve", () => {
  for (const file of docFiles(root)) checkLinks(readFileSync(file, "utf8"), file);
  checkLinks(readFileSync(join(root, "web/index.html"), "utf8"), join(root, "web/index.html"));
  for (const item of notebooks) {
    const notebook = JSON.parse(readFileSync(join(root, item.path), "utf8")) as { cells: { cell_type: string; source: string[] | string }[] };
    for (const cell of notebook.cells.filter((c) => c.cell_type === "markdown")) checkLinks(Array.isArray(cell.source) ? cell.source.join("") : cell.source, join(root, item.path));
  }
});

test("link discovery resolves actual HTML and ignores paths inside fenced HTML programs", () => {
  const file = join(root, "README.md");
  checkLinks('```html\n<script src="a-file-created-by-the-browser-harness.js"></script>\n```\n', file);
  assert.throws(() => checkLinks('<a href="missing-documentation-page.md">Missing</a>\n', file), /missing/);
});

test("every public callable has a categorized, executable TSDoc example, including constructors", () => {
  let functions = 0; let constructors = 0;
  for (const declaration of publicDeclarations(root)) {
    const list: ts.Node[] = ts.isClassDeclaration(declaration) ? declaration.members.filter(ts.isConstructorDeclaration) : [declaration];
    for (const node of list) {
      if (!ts.isConstructorDeclaration(node) && !ts.isFunctionDeclaration(node) &&
        !(ts.isVariableDeclaration(node) && node.initializer && (ts.isArrowFunction(node.initializer) || ts.isFunctionExpression(node.initializer)))) continue;
      if (ts.isConstructorDeclaration(node)) constructors++; else functions++;
      const owner = ts.isVariableDeclaration(node) ? node.parent.parent : node;
      const tags = ts.getJSDocTags(owner);
      assert.ok(tags.some((tag) => tag.tagName.text === "category" || tag.tagName.text === "group"), `${owner.getSourceFile().fileName}: missing task category`);
      assert.ok(tags.some((tag) => tag.tagName.text === "example"), `${owner.getSourceFile().fileName}: missing executable example`);
    }
  }
  assert.ok(functions >= 90, `export walk found only ${functions} callables`); assert.equal(constructors, 1);
  assert.ok(authoredSamples(root).some((sample) => sample.doc === "src/error.ts" && sample.code.includes("new InvalidError")));
});

test("CommonMark discovery includes nested, longer and tilde fences and refuses untagged code", () => {
  assert.equal(samplesIn('> ~~~~ts\n> import assert from "node:assert/strict";\n> assert.ok(true);\n> ~~~~\n', "probe.md").length, 1);
  assert.equal(samplesIn('````ts\nconst text = "```";\n````\n', "probe.md").length, 1);
  assert.throws(() => samplesIn("    const hidden = 1;\n", "probe.md"));
  assert.throws(() => samplesIn("```\nconst hidden = 1;\n```\n", "probe.md"));
});

test("install snippets, historical upgrade routes and closed errors stay current", () => {
  for (const file of [...docFiles(root), join(root, "web/index.html")]) {
    const text = readFileSync(file, "utf8");
    for (const match of text.matchAll(/(?:npm (?:i|install)|pnpm add|bun add|deno add)\s+[^\n<]*?(?:npm:)?@bounded-authority-protocol\/verifier(?:@([^\s<`")]+))?/g)) {
      assert.equal(match[1], pkg.version, `${relative(root, file)}: pin install examples to the documented release`);
    }
  }
  const errors = readFileSync(join(root, "docs/guides/handle-errors.md"), "utf8");
  const errorSource = readFileSync(join(root, "src/error.ts"), "utf8");
  const names = [...errorSource.matchAll(/export class (\w+) extends Error/g)].map((match) => match[1]!);
  assert.deepEqual(names, ["InvalidError"]);
  for (const name of names) assert.ok(errors.includes(`\`${name}\``));
  assert.ok(errors.includes("{ ok: false }") && errors.includes("no error code") && errors.includes("not part of the API"));
  assert.ok(!/readonly\s+(?:error|reason|code)\s*:/.test(errorSource), "a new result error needs a documented meaning, cause and remedy");
  const upgrades = readFileSync(join(root, "docs/guides/upgrading.md"), "utf8");
  for (const line of manifest.previousReleaseLines) assert.ok(upgrades.includes(`${line}.x`), `missing upgrade route ${line}`);
  // Bench code is executed in the existing real-browser matrix, with no unregistered inline code.
  // The existing browser harness consumes the runtimes guide's page and module together.
  // Refuse another authored HTML program until its browser execution path is registered too.
  for (const file of docFiles(root)) {
    const programs = markdown.parse(readFileSync(file, "utf8"), {}).filter((token) => token.type === "fence" && token.info === "html");
    if (programs.length) {
      assert.equal(relative(root, file), "docs/guides/runtimes.md"); assert.equal(programs.length, 1);
      assert.ok(programs[0]!.content.includes('src="./verify-anywhere.js"') || programs[0]!.content.includes('src="verify-anywhere.js"'));
    }
  }
  const html = readFileSync(join(root, "web/index.html"), "utf8");
  assert.ok(!/<script\b(?![^>]*\bsrc=)[^>]*>\s*[^<\s]/.test(html));
  assert.ok(!/<(?:pre|code)\b[^>]*class=["'][^"']*language-(?:ts|js)/.test(html), "register future inline authored programs with the sample harness");
});
