import { parseSecLangSyntax } from "./syntax.js";

export interface SecLangSourceOptions {
  fileName?: string;
  files?: Record<string, string>;
}

/**
 * Strip comments from bundled SecLang rule and phrase files without altering
 * `.conf` line numbers, reducing Worker bundle size and cold-start parse cost.
 */
export function compactSecLangFiles(files: Record<string, string> = {}): Record<string, string> {
  const out: Record<string, string> = {};
  for (const [name, text] of Object.entries(files)) {
    if (name.endsWith(".conf")) {
      out[name] = text
        .split(/\r?\n/)
        .map((line) => (/^\s*#/.test(line) ? "" : line.trimEnd()))
        .join("\n");
    } else if (/\.(data|txt|ipset|list)$/.test(name)) {
      out[name] = text
        .split(/\r?\n/)
        .filter((line) => line.trim() && !line.trimStart().startsWith("#"))
        .join("\n");
    } else {
      out[name] = text;
    }
  }
  return out;
}

export function sourcePath(base: string, relative: string): string {
  if (/^[A-Za-z]:|^[\\/]/.test(relative)) throw new Error("SecLang bundle paths must be relative");
  const parts = base.split("/").slice(0, -1);
  for (const part of relative.replace(/\\/g, "/").split("/")) {
    if (!part || part === ".") continue;
    if (part === "..") {
      if (!parts.length) throw new Error("SecLang include escapes bundle");
      parts.pop();
    } else parts.push(part);
  }
  return parts.join("/");
}

export function expandSecLangSources(
  source: string,
  { fileName = "main.conf", files = {} }: SecLangSourceOptions = {},
) {
  const stack = new Set<string>();
  let bytes = 0;
  const expand = (
    name: string,
    text: string,
    depth: number,
  ): ReturnType<typeof parseSecLangSyntax> => {
    if (stack.has(name)) throw new Error(`Cyclic SecLang Include: ${name}`);
    bytes += new TextEncoder().encode(text).length;
    if (depth > 32 || bytes > 16 * 1024 * 1024) throw new Error("SecLang include resource limit");
    stack.add(name);
    const result: ReturnType<typeof parseSecLangSyntax> = [];
    for (const statement of parseSecLangSyntax(text)) {
      if (!["Include", "IncludeOptional"].includes(statement.directive)) {
        result.push({ ...statement, file: name });
        continue;
      }
      if (statement.args.length !== 1)
        throw new Error(`Malformed Include at ${name}:${statement.line}`);
      const path = sourcePath(name, statement.args[0]!);
      const pattern = new RegExp(
        `^${path
          .split(/([*?])/)
          .map((part) =>
            part === "*"
              ? "[^/]*"
              : part === "?"
                ? "[^/]"
                : part.replace(/[\\^$+.[\]{}()|]/g, "\\$&"),
          )
          .join("")}$`,
      );
      const names = Object.keys(files)
        .filter((key) => pattern.test(key))
        .sort();
      if (!names.length && statement.directive === "Include")
        throw new Error(`Missing SecLang Include: ${path}`);
      for (const file of names) result.push(...expand(file, files[file]!, depth + 1));
    }
    stack.delete(name);
    return result;
  };
  return expand(fileName, source, 0);
}
