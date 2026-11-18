// CommonMark parsing shared by execution and currency checks. The parser, not a fence regex,
// handles nested lists, blockquotes, tilde fences, longer closers and indented code blocks.
import assert from "node:assert/strict";
import { readFileSync, readdirSync } from "node:fs";
import { join, relative } from "node:path";
import MarkdownIt from "markdown-it";
import ts from "typescript";
import { sourceComments } from "../comments.js";

export type { Token } from "markdown-it";
export const markdown = new MarkdownIt("commonmark", { html: true });
const excluded = new Set([".git", "node_modules", "dist", "site-dist", ".kimosabe", ".venv"]);
export function filesUnder(dir: string): string[] {
  return readdirSync(dir, { withFileTypes: true }).sort((a, b) => a.name.localeCompare(b.name)).flatMap((entry) => {
    if (excluded.has(entry.name) || entry.name.startsWith("build-")) return [];
    const path = join(dir, entry.name);
    return entry.isDirectory() ? filesUnder(path) : [path];
  });
}
export function docFiles(root: string): string[] {
  return filesUnder(root).filter((path) => path.endsWith(".md") && !["AGENTS.md", "CLAUDE.md"].includes(path.split("/").at(-1)!));
}
export interface Sample { doc: string; line: number; code: string; since?: string }
export function samplesIn(source: string, doc: string, offset = 0): Sample[] {
  return markdown.parse(source, {}).flatMap((token): Sample[] => {
    if (token.type !== "fence" && token.type !== "code_block") return [];
    const [tag = "", ...attributes] = token.info.trim().split(/\s+/);
    assert.ok(!["typescript", "js", "javascript", "mjs", "mts", "tsx"].includes(tag), `${doc}: tag runnable samples ts`);
    // Untagged fences and indented code must not hide executable JS/TS examples.
    if (token.type === "code_block" || tag === "") assert.ok(!/\b(?:import|export|const|let|function)\b/.test(token.content), `${doc}: tag executable code ts`);
    if (tag !== "ts") return [];
    const since = attributes.find((attribute) => attribute.startsWith("since="))?.slice(6);
    assert.ok(attributes.every((attribute) => /^since=\d+\.\d+\.\d+$/.test(attribute)), `${doc}: unsupported sample attribute`);
    return [{ doc, line: (token.map?.[0] ?? 0) + 1 + offset, code: token.content, ...(since === undefined ? {} : { since }) }];
  });
}
export function authoredSamples(root: string): Sample[] {
  const docs = docFiles(root).flatMap((file) => samplesIn(readFileSync(file, "utf8"), relative(root, file)));
  const examples = filesUnder(join(root, "docs")).filter((file) => file.endsWith(".ts"))
    .map((file): Sample => ({ doc: relative(root, file), line: 1, code: readFileSync(file, "utf8") }));
  const comments = filesUnder(join(root, "src")).filter((file) => file.endsWith(".ts")).flatMap((file) => {
    const source = readFileSync(file, "utf8");
    return sourceComments(source, file).flatMap(({ pos, end }) => {
      const comment = source.slice(pos, end);
      if (!comment.startsWith("/**") || !comment.includes("@example")) return [];
      const prose = comment.replace(/^\/\*\*|\*\/$/g, "").split("\n").map((line) => line.replace(/^\s*\* ?/, "")).join("\n");
      const samples = samplesIn(prose, relative(root, file), source.slice(0, pos).split("\n").length - 1);
      assert.equal(samples.length, [...prose.matchAll(/@example\b/g)].length, `${file}: each @example must contain one runnable ts fence`);
      return samples;
    });
  });
  return [...docs, ...examples, ...comments];
}

// Compiler-visible exports include namespace members and callable variables, not only function syntax.
export function publicDeclarations(root: string): ts.Declaration[] {
  const path = join(root, "src/index.ts");
  const program = ts.createProgram([path], { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.NodeNext,
    moduleResolution: ts.ModuleResolutionKind.NodeNext, customConditions: ["bap-source"], noEmit: true, skipLibCheck: true });
  const checker = program.getTypeChecker();
  const seen = new Set<ts.Symbol>(); const out: ts.Declaration[] = [];
  function walk(symbol: ts.Symbol): void {
    const target = symbol.flags & ts.SymbolFlags.Alias ? checker.getAliasedSymbol(symbol) : symbol;
    if (seen.has(target)) return;
    seen.add(target);
    out.push(...(target.declarations ?? []));
    if (target.flags & ts.SymbolFlags.ValueModule) for (const member of checker.getExportsOfModule(target)) walk(member);
  }
  const source = program.getSourceFile(path)!;
  for (const symbol of checker.getExportsOfModule(checker.getSymbolAtLocation(source)!)) walk(symbol);
  return out;
}
