/** First-party SecLang lexer: preserves multiline statements, directives and actions. */
export interface SecLangStatement {
  line: number;
  directive: string;
  args: string[];
  raw: string;
  file?: string;
}

function isSpace(code: number): boolean {
  return code === 32 || code === 9 || code === 13 || code === 10 || code === 12 || code === 11;
}

export function parseSecLangSyntax(input: string): SecLangStatement[] {
  if (typeof input !== "string") throw new TypeError("SecLang input must be text");
  const statements: SecLangStatement[] = [];
  let pending = "",
    start = 1;
  const lines = input.split(/\r?\n/);
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i]!.trim();
    if (!pending && (!line || line.charCodeAt(0) === 35)) continue;
    if (!pending) start = i + 1;
    let backslashes = 0;
    for (let j = line.length - 1; j >= 0 && line.charCodeAt(j) === 92; j--) backslashes++;
    const continued = (backslashes & 1) === 1;
    if (continued) {
      pending += `${line.slice(0, -1)} `;
      continue;
    }
    const raw = pending ? pending + line : line;
    pending = "";
    const parts: string[] = [];
    let part = "",
      quote = 0,
      escaped = false,
      started = false,
      chunkStart = 0;
    for (let j = 0; j < raw.length; j++) {
      const code = raw.charCodeAt(j);
      if (escaped) {
        if (code === quote) {
          if (j - 1 > chunkStart) part += raw.slice(chunkStart, j - 1);
          chunkStart = j;
        }
        escaped = false;
        continue;
      }
      if (code === 92 && quote) {
        escaped = true;
        continue;
      }
      if ((code === 39 || code === 34) && !quote) {
        if (j > chunkStart) part += raw.slice(chunkStart, j);
        quote = code;
        started = true;
        chunkStart = j + 1;
        continue;
      }
      if (code === quote) {
        if (j > chunkStart) part += raw.slice(chunkStart, j);
        quote = 0;
        chunkStart = j + 1;
        continue;
      }
      if (!quote && isSpace(code)) {
        if (started) {
          if (j > chunkStart) part += raw.slice(chunkStart, j);
          parts.push(part);
          part = "";
          started = false;
        }
        chunkStart = j + 1;
      } else {
        started = true;
      }
    }
    if (quote) throw new Error(`Unterminated quote at line ${start}`);
    if (started) {
      if (raw.length > chunkStart) part += raw.slice(chunkStart);
      parts.push(part);
    }
    const [directive, ...args] = parts;
    if (!directive) throw new Error(`Empty SecLang directive at line ${start}`);
    if (directive === "SecRule" && (args.length < 2 || args.length > 3))
      throw new Error(`Malformed SecRule at line ${start}`);
    if (directive === "SecAction" && args.length !== 1)
      throw new Error(`Malformed SecAction at line ${start}`);
    statements.push({ line: start, directive, args, raw });
  }
  if (pending) throw new Error(`Incomplete continuation at line ${start}`);
  return statements;
}
