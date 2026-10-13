// The node:fs corpus loader, used by the Node runners and by the Deno and Bun lanes (both provide
// node:fs). Paths are relative to the conformance/ directory.
import { readdirSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import type { CorpusSource } from "./core/types.js";

export const CONFORMANCE_DIR = fileURLToPath(new URL(".", import.meta.url));

export function fsSource(root: string = CONFORMANCE_DIR): CorpusSource {
  const walk = (dir: string, prefix: string): string[] => {
    const out: string[] = [];
    for (const name of readdirSync(dir).sort()) {
      const full = join(dir, name);
      if (statSync(full).isDirectory()) out.push(...walk(full, `${prefix}${name}/`));
      else out.push(`${prefix}${name}`);
    }
    return out;
  };
  return {
    read: (path) => new Uint8Array(readFileSync(join(root, ...path.split("/")))),
    list: (dir) => walk(join(root, ...dir.split("/")), ""),
  };
}
