#!/usr/bin/env node
import { fileURLToPath } from "node:url";
import { vendor } from "./corpus-artifact.mjs";

const args = process.argv.slice(2);
if (!(args.length === 1 && args[0] !== "--candidate") && !(args.length === 2 && args[0] === "--candidate")) {
  console.error("usage: node scripts/vendor.mjs <Hex-version> | --candidate <monorepo-commit>"); process.exit(2);
}
try {
  const source = await vendor(fileURLToPath(new URL("..", import.meta.url)), args[0], args[0] === "--candidate" ? args[1] : undefined);
  console.log(JSON.stringify(source, null, 2));
} catch (error) { console.error(error.message); process.exitCode = 1; }
