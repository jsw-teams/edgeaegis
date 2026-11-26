/** Internal SecLang strings represent octets, including NUL and invalid UTF-8. */
const encoder = new TextEncoder();
export function utf8Bytes(value: string): string {
  // ASCII already has exactly the required octets, including embedded NUL.
  if (!/[^\x00-\x7f]/.test(value)) return value;
  return fromOctets(encoder.encode(value));
}
export function fromOctets(bytes: Uint8Array): string {
  let result = "";
  for (let i = 0; i < bytes.length; i += 8192)
    result += String.fromCharCode(...bytes.subarray(i, i + 8192));
  return result;
}

export function octets(value: string): Uint8Array {
  const result = new Uint8Array(value.length);
  for (let i = 0; i < value.length; i++) {
    const code = value.charCodeAt(i);
    if (code > 255) throw new Error("SecLang byte string contains a non-byte character");
    result[i] = code;
  }
  return result;
}

export function asciiLower(value: string): string {
  for (let i = 0; i < value.length; i++) {
    const code = value.charCodeAt(i);
    if (code >= 65 && code <= 90) return value.replace(/[A-Z]+/g, (part) => part.toLowerCase());
  }
  return value;
}

export function formEntries(value: string, binary = false): [string, string][] {
  if (!value) return [];
  return (binary ? value : utf8Bytes(value))
    .split("&")
    .filter(Boolean)
    .map((part) => {
      const at = part.indexOf("=");
      const decode = (v: string) =>
        v.replace(/%([\da-f]{2})|\+/gi, (all, hex) =>
          hex ? String.fromCharCode(Number.parseInt(hex, 16)) : all === "+" ? " " : all,
        );
      return [decode(at < 0 ? part : part.slice(0, at)), decode(at < 0 ? "" : part.slice(at + 1))];
    });
}
