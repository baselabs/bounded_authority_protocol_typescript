// Keep the package's documented constructor while hiding inherited platform Error machinery, and
// give headings that contain code the same anchors on the API site as on GitHub.
import { Application, Converter } from "typedoc";

// TypeDoc slugs a heading from its text tokens only, so "### `TrustedIssuer`" would get no
// usable anchor. Exposing each heading code span's text as a child text token lets TypeDoc's
// slugger see it, while rendering still uses the code span's own content.
function headingCodeAnchors(parser) {
  parser.core.ruler.push("heading_code_anchors", (state) => {
    state.tokens.forEach((token, index) => {
      if (token.type !== "inline" || state.tokens[index - 1]?.type !== "heading_open") return;
      for (const child of token.children ?? []) {
        if (child.type !== "code_inline" || child.children) continue;
        const text = new state.Token("text", "", 0);
        text.content = child.content;
        child.children = [text];
      }
    });
  });
}

export function load(app) {
  app.on(Application.EVENT_BOOTSTRAP_END, () => {
    const configured = app.options.getValue("markdownItLoader");
    app.options.setValue("markdownItLoader", (parser) => {
      configured(parser);
      headingCodeAnchors(parser);
    });
  });
  app.converter.on(Converter.EVENT_RESOLVE_END, ({ project }) => {
    for (const reflection of Object.values(project.reflections)) {
      if (reflection.parent?.name === "InvalidError" && reflection.inheritedFrom) {
        project.removeReflection(reflection);
      }
    }
  });
}
