import assert from "node:assert/strict";
import { test } from "node:test";
import { citationText, commentProse } from "./comments.js";

test("comment citations join continuations without joining Markdown bullets or literals", () => {
  const wrapped = "/* spec/bap-\n * v1.md#verification */";
  assert.ok(citationText(wrapped, "source.ts").includes("spec/bap-v1.md#verification"));
  const lines = "// spec/bap-\n// v1.md#verification";
  assert.ok(citationText(lines, "source.ts").includes("spec/bap-v1.md#verification"));
  const sentences = "// spec/bap-v1.md#verification\n// Browser rule\n/** spec/bap-v1.md#verification.\n * Describe behavior. */";
  const citations = citationText(sentences, "source.ts");
  assert.ok(!citations.includes("verificationBrowser"));
  assert.ok(!citations.includes("verification.Describe"));
  const markdown = "First item\n* second item\n  * nested item";
  assert.equal(citationText(markdown, "doc.md"), markdown);
  const literal = 'const text = "spec/bap-v1.md#verification";';
  assert.equal(citationText(literal, "source.ts"), literal);
  const template = 'const value = `head ${1} tail`; // kept\nconst regex = /[/*]/; /* kept too */';
  const prose = commentProse(template, "source.ts");
  assert.equal(prose.indexOf("// kept"), template.indexOf("// kept"));
  assert.equal(prose.indexOf("/* kept too */"), template.indexOf("/* kept too */"));
});
