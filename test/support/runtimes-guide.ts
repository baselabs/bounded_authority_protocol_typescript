// The Deno, Bun and browsers guide (docs/guides/runtimes.md), read from the guide itself so the
// tarball and browser lanes run exactly what a reader copies: its one TypeScript module, its page,
// and the commands it tells the reader to run. test/docs-samples.test.ts runs the same module on Node.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

const GUIDE = readFileSync(new URL("../../docs/guides/runtimes.md", import.meta.url), "utf8");

// The content of every top-level fence tagged exactly `tag`, in order.
function fences(tag: string): string[] {
  return [...GUIDE.matchAll(new RegExp("^```" + tag + "\\n([\\s\\S]*?)^```$", "gm"))].map((m) => m[1]!);
}

const modules = fences("ts");
const pages = fences("html");
assert.equal(modules.length, 1, "the runtimes guide has exactly one ts module");
assert.equal(pages.length, 1, "the runtimes guide has exactly one html page");

/** The module the guide tells the reader to save as `verify-anywhere.ts`. */
export const MODULE = modules[0]!;
/** The page that loads its bundle. */
export const PAGE = pages[0]!;
/** The line the module prints on each backend. */
export const verifiedLine = (backend: "node" | "portable"): string => `verified grant-gallery with the ${backend} backend`;

/** Fails unless the guide tells the reader to run exactly this command. */
export function documentedCommand(command: string): string {
  const commands = fences("bash").flatMap((block) => block.split("\n")).map((line) => line.trim());
  assert.ok(commands.includes(command), `the runtimes guide documents \`${command}\``);
  return command;
}
