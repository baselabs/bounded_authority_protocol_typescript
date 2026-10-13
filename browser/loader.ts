// The browser corpus loader: fetch the manifest of conformance files the test server exposes, fetch
// every corpus file, and serve them synchronously to the runtime-neutral cores. Same bytes as the
// node:fs loader; the cores' own index pins check them.
import type { CorpusSource } from "../conformance/core/types.js";

export async function loadCorpus(base: string): Promise<CorpusSource> {
  const manifest = (await (await fetch(`${base}manifest.json`)).json()) as string[];
  const files = new Map<string, Uint8Array>();
  await Promise.all(manifest.map(async (path) => {
    const response = await fetch(`${base}${path}`);
    if (!response.ok) throw new Error(`corpus fetch ${path}: HTTP ${response.status}`);
    files.set(path, new Uint8Array(await response.arrayBuffer()));
  }));
  return {
    read(path) {
      const bytes = files.get(path);
      if (bytes === undefined) throw new Error(`corpus file not served: ${path}`);
      return bytes;
    },
    list(dir) {
      const prefix = `${dir}/`;
      return manifest.filter((p) => p.startsWith(prefix)).map((p) => p.slice(prefix.length)).sort();
    },
  };
}
