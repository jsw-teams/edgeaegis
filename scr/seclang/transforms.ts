import { sha1 } from "@noble/hashes/legacy.js";
import { octets } from "./bytes.js";
import { defaultUnicodeMap } from "./unicode.js";

const whitespace = /[\t\n\v\f\r ]/g;
const fatalUtf8Decoder = new TextDecoder("utf-8", { fatal: true });
const byte = (n: number) => String.fromCharCode(n & 255);
const unicodeByte = (n: number) => byte(n >= 0xff01 && n <= 0xff5e ? n - 0xfee0 : n);
const escapes: Record<string, string> = {
  a: "\x07",
  b: "\b",
  f: "\f",
  n: "\n",
  r: "\r",
  t: "\t",
  v: "\v",
};

export function urlDecode(value: string, unicode = false, mapping = defaultUnicodeMap): string {
  if (!value.includes("%") && !value.includes("+")) return value;
  const pattern = unicode ? /%u([\da-f]{4})|%([\da-f]{2})|\+/gi : /%([\da-f]{2})|\+/gi;
  return value.replace(pattern, (...args: unknown[]) => {
    const text = args[0] as string;
    if (text === "+") return " ";
    if (unicode)
      return args[1]
        ? byte(
            mapping.get(Number.parseInt(args[1] as string, 16)) ??
              unicodeByte(Number.parseInt(args[1] as string, 16)).charCodeAt(0),
          )
        : byte(Number.parseInt(args[2] as string, 16));
    return byte(Number.parseInt(args[1] as string, 16));
  });
}

function normalizePath(value: string): string {
  const leading = value.startsWith("/");
  const trailing = value.endsWith("/") || value.endsWith("/.") || value.endsWith("/..");
  const parts: string[] = [];
  for (const part of value.split("/")) {
    if (!part || part === ".") continue;
    if (part === ".." && parts.length && parts.at(-1) !== "..") parts.pop();
    else if (part === ".." && leading) continue;
    else parts.push(part);
  }
  const path = `${leading ? "/" : ""}${parts.join("/")}`;
  return trailing && path && !path.endsWith("/") ? `${path}/` : path;
}

export const transformations: Record<string, (value: string) => string> = {
  none: (s) => s,
  lowercase: (s) => {
    for (let i = 0; i < s.length; i++) {
      const c = s.charCodeAt(i);
      if (c >= 65 && c <= 90) return s.replace(/[A-Z]+/g, (part) => part.toLowerCase());
    }
    return s;
  },
  uppercase: (s) => {
    for (let i = 0; i < s.length; i++) {
      const c = s.charCodeAt(i);
      if (c >= 97 && c <= 122) return s.replace(/[a-z]+/g, (part) => part.toUpperCase());
    }
    return s;
  },
  trim: (s) => s.replace(/^[\t\n\v\f\r ]+|[\t\n\v\f\r ]+$/g, ""),
  trimleft: (s) => s.replace(/^[\t\n\v\f\r ]+/, ""),
  trimright: (s) => s.replace(/[\t\n\v\f\r ]+$/, ""),
  compresswhitespace: (s) => s.replace(/[\t\n\v\f\r ]+/g, " "),
  removewhitespace: (s) => s.replace(whitespace, ""),
  removenulls: (s) => (s.includes("\0") ? s.replace(/\0/g, "") : s),
  replacenulls: (s) => (s.includes("\0") ? s.replace(/\0/g, " ") : s),
  urldecode: (s) => urlDecode(s),
  urldecodeuni: (s) => urlDecode(s, true),
  urlencode: (s) =>
    [...octets(s)]
      .map((n) =>
        /[\w.*-]/.test(byte(n)) ? byte(n) : n === 32 ? "+" : `%${n.toString(16).padStart(2, "0")}`,
      )
      .join(""),
  length: (s) => String(s.length),
  hexencode: (s) => [...s].map((c) => c.charCodeAt(0).toString(16).padStart(2, "0")).join(""),
  hexdecode: (s) => s.replace(/[\da-f]{2}/gi, (n) => byte(Number.parseInt(n, 16))),
  base64encode: (s) => btoa(s),
  base64decode: (s) => {
    try {
      return atob(s);
    } catch {
      return s;
    }
  },
  base64decodeext: (s) => {
    try {
      return atob(s.replace(/[^\da-z+/=]/gi, ""));
    } catch {
      return s;
    }
  },
  htmlentitydecode: (s) =>
    s.includes("&")
      ? s.replace(
          /&#x([\da-f]+);?|&#(\d+);?|&(quot|amp|lt|gt|nbsp|apos);?/gi,
          (original, hex, decimal, name) => {
            if (hex || decimal) return byte(Number.parseInt(hex ?? decimal, hex ? 16 : 10));
            return (
              (
                { quot: '"', amp: "&", lt: "<", gt: ">", nbsp: "\xa0", apos: "'" } as Record<
                  string,
                  string
                >
              )[name.toLowerCase()] ?? original
            );
          },
        )
      : s,
  jsdecode: (s) =>
    s.includes("\\")
      ? s.replace(
          /\\u([\da-f]{4})|\\x([\da-f]{2})|\\([0-3]?[0-7]{1,2})|\\([\s\S])/gi,
          (_all, uni, hex, octal, other) =>
            uni
              ? unicodeByte(Number.parseInt(uni, 16))
              : hex
                ? byte(Number.parseInt(hex, 16))
                : octal
                  ? byte(Number.parseInt(octal, 8))
                  : (escapes[other] ?? other),
        )
      : s,
  cssdecode: (s) =>
    s.includes("\\")
      ? s.replace(
          /\\([\da-f]{1,6})(?:\r\n|[\t\n\f\r ])?|\\(?:\r\n|[\n\r\f])|\\([\s\S])/gi,
          (_all, hex, other) => (hex ? unicodeByte(Number.parseInt(hex, 16)) : (other ?? "")),
        )
      : s,
  escapeseqdecode: (s) =>
    s.includes("\\")
      ? s.replace(/\\x([\da-f]{2})|\\([0-3]?[0-7]{1,2})|\\([\s\S])/gi, (_all, hex, octal, other) =>
          hex
            ? byte(Number.parseInt(hex, 16))
            : octal
              ? byte(Number.parseInt(octal, 8))
              : (escapes[other] ?? other),
        )
      : s,
  normalizepath: normalizePath,
  normalisepath: normalizePath,
  normalizepathwin: (s) => normalizePath(s.includes("\\") ? s.replace(/\\/g, "/") : s),
  normalisepathwin: (s) => normalizePath(s.includes("\\") ? s.replace(/\\/g, "/") : s),
  cmdline: (s) =>
    s
      .replace(/[\\"'^]/g, "")
      .replace(/[,;]/g, " ")
      .replace(/[\t\n\v\f\r ]+/g, " ")
      .replace(/ *([/(])/g, "$1")
      .replace(/[A-Z]+/g, (part) => part.toLowerCase()),
  removecommentschar: (s) =>
    s.includes("/*") || s.includes("*/") || s.includes("--") || s.includes("#")
      ? s.replace(/\/\*|\*\/|--|#/g, "")
      : s,
  replacecomments: (s) => (s.includes("/*") ? s.replace(/\/\*[\s\S]*?(?:\*\/|$)/g, " ") : s),
  removecomments: (s) =>
    s.includes("/*") || s.includes("<!--") || s.includes("--") || s.includes("#")
      ? s.replace(/\/\*[\s\S]*?(?:\*\/|$)|<!--[\s\S]*?(?:-->|$)|--[^\r\n]*|#[^\r\n]*/g, "")
      : s,
  utf8tounicode: (s) => {
    let hasHigh = false;
    for (let i = 0; i < s.length; i++) {
      if (s.charCodeAt(i) >= 128) {
        hasHigh = true;
        break;
      }
    }
    if (!hasHigh) return s;
    const bytes = octets(s);
    let result = "";
    for (let i = 0; i < bytes.length; i++) {
      const lead = bytes[i]!;
      if (lead < 128) {
        result += s[i];
        continue;
      }
      const size =
        lead >= 0xc2 && lead <= 0xdf
          ? 2
          : lead >= 0xe0 && lead <= 0xef
            ? 3
            : lead >= 0xf0 && lead <= 0xf4
              ? 4
              : 0;
      try {
        if (!size || i + size > bytes.length) throw new Error("Invalid UTF-8");
        const text = fatalUtf8Decoder.decode(bytes.subarray(i, i + size));
        result += `%u${text.codePointAt(0)!.toString(16).padStart(4, "0")}`;
        i += size - 1;
      } catch {
        result += s[i];
      }
    }
    return result;
  },
  sha1: (s) => String.fromCharCode(...sha1(octets(s))),
};

export function transform(
  value: string,
  pipeline: string[],
  unicodeMap = defaultUnicodeMap,
): string {
  let result = value;
  for (const name of pipeline) {
    const fn = transformations[name];
    if (!fn) throw new Error(`Unsupported SecLang transformation: ${name}`);
    result = name === "urldecodeuni" ? urlDecode(result, true, unicodeMap) : fn(result);
    if (result.length > 2 * 1024 * 1024)
      throw new Error("Transformed input exceeds policy size limit");
  }
  return result;
}
