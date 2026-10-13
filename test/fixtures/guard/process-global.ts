// Browser-typecheck red-proof fixture: process is a Node global, absent under tsconfig.browser.json.
export const probe = process.version;
