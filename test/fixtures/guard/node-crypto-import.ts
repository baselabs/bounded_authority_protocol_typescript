// Browser-typecheck red-proof fixture: node:crypto has no types under tsconfig.browser.json.
import { createHash } from "node:crypto";
export const probe = createHash;
