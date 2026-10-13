// Browser-typecheck red-proof fixture: Buffer is a Node global, absent under tsconfig.browser.json.
export const probe = Buffer.from("probe");
