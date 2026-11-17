import ts from "typescript";

/** Comment ranges in original source coordinates, including trivia after templates and regexes. */
export function sourceComments(source: string, fileName: string): ts.CommentRange[] {
  const file = ts.createSourceFile(fileName, source, ts.ScriptTarget.Latest, true);
  const ranges = new Map<number, ts.CommentRange>();
  const collect = (pos: number, end: number, kind: ts.CommentKind, hasTrailingNewLine: boolean) => {
    ranges.set(pos, { pos, end, kind, hasTrailingNewLine });
  };
  const visit = (node: ts.Node): void => {
    ts.forEachLeadingCommentRange(source, node.pos, collect);
    ts.forEachTrailingCommentRange(source, node.end, collect);
    for (const child of node.getChildren(file)) visit(child);
  };
  visit(file);
  return [...ranges.values()].sort((a, b) => a.pos - b.pos);
}

/** Mask non-comment text while retaining every original newline and offset. */
export function commentProse(source: string, fileName: string): string {
  const out: string[] = [];
  let at = 0;
  for (const { pos, end } of sourceComments(source, fileName)) {
    out.push(source.slice(at, pos).replace(/[^\r\n]/g, " "), source.slice(pos, end));
    at = end;
  }
  out.push(source.slice(at).replace(/[^\r\n]/g, " "));
  return out.join("");
}

/** Join wrapped spec filenames only inside comments, retaining Markdown and code literals. */
export function citationText(source: string, fileName: string): string {
  if (!/\.(?:[cm]?[jt]s)$/.test(fileName)) return source;
  const ranges = sourceComments(source, fileName);
  const out: string[] = [];
  let at = 0;
  for (let i = 0; i < ranges.length; i++) {
    const start = ranges[i]!.pos;
    let end = ranges[i]!.end;
    while (i + 1 < ranges.length && /^\s*$/.test(source.slice(end, ranges[i + 1]!.pos))) {
      end = ranges[++i]!.end;
    }
    const comment = source.slice(start, end).replace(/\r?\n[ \t]*(?:\/\/|\*(?!\/))[ \t]*/g, "\n")
      .replace(/(spec\/[\w.-]*)\r?\n[ \t]*(?=[\w.-]+\.md\b)/g, "$1");
    out.push(source.slice(at, start), comment);
    at = end;
  }
  out.push(source.slice(at));
  return out.join("");
}
