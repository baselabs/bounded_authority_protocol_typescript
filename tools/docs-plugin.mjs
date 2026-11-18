// Keep the package's documented constructor while hiding inherited platform Error machinery.
import { Converter } from "typedoc";
export function load(app) {
  app.converter.on(Converter.EVENT_RESOLVE_END, ({ project }) => {
    for (const reflection of Object.values(project.reflections)) {
      if (reflection.parent?.name === "InvalidError" && reflection.inheritedFrom) {
        project.removeReflection(reflection);
      }
    }
  });
}
