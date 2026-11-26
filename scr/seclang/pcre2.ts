/** PCRE2 primitive backend. SecLang parsing, matching policy and state remain in EdgeAegis. */
export interface SecLangRegex {
  matcher(value: string): { find(): boolean; group(index: number): string | null };
  groupCount(): number;
  destroy?(): void;
}

export interface SecLangRegexBackend {
  compile(pattern: string, options?: { binary?: boolean }): SecLangRegex;
}

type Exports = {
  memory: WebAssembly.Memory;
  malloc(size: number): number;
  free(pointer: number): void;
  __wasm_call_ctors(): void;
  pcre2_wasm_compile(...args: number[]): number;
  pcre2_wasm_match(...args: number[]): number;
  pcre2_wasm_free(pointer: number): void;
  pcre2_wasm_pattern_info(...args: number[]): number;
  pcre2_wasm_error_message(...args: number[]): number;
};

export class PCRE2Error extends Error {
  constructor(
    message: string,
    public readonly code?: number,
  ) {
    super(message);
    this.name = "PCRE2Error";
  }
}

const SCRATCH_INPUT_SIZE = 4096;
const SCRATCH_OUTPUT_SIZE = 16384;

/** Pass a statically imported WebAssembly.Module in Workers; bytes also work in Node.js. */
export async function createPCRE2Backend(
  module: WebAssembly.Module | BufferSource,
  { matchLimit = 100_000, depthLimit = 1_000, memoryLimit = 64 * 1024 * 1024 } = {},
): Promise<SecLangRegexBackend> {
  if (![matchLimit, depthLimit, memoryLimit].every((n) => Number.isSafeInteger(n) && n > 0))
    throw new Error("Invalid PCRE2 resource limits");
  let exports: Exports;
  let cachedBuffer: ArrayBuffer | null = null;
  let cachedMem = new Uint8Array(0);
  const imports = {
    env: {
      emscripten_resize_heap(size: number) {
        if (!exports || size > memoryLimit) return 0;
        const memory = exports.memory;
        try {
          memory.grow(Math.max(0, Math.ceil((size - memory.buffer.byteLength) / 65536)));
          return 1;
        } catch {
          return 0;
        }
      },
    },
  };
  const loaded = await WebAssembly.instantiate(module as WebAssembly.Module, imports);
  const instance =
    loaded instanceof WebAssembly.Instance
      ? loaded
      : (loaded as WebAssembly.WebAssemblyInstantiatedSource).instance;
  exports = instance.exports as unknown as Exports;
  if (exports.memory.buffer.byteLength > memoryLimit)
    throw new Error("PCRE2 memory limit too small");
  exports.__wasm_call_ctors();
  const encoder = new TextEncoder();
  const decoder = new TextDecoder();

  function mem(): Uint8Array {
    const buffer = exports.memory.buffer;
    if (buffer !== cachedBuffer) {
      cachedBuffer = buffer;
      cachedMem = new Uint8Array(buffer);
    }
    return cachedMem;
  }

  function allocate(size: number) {
    const ptr = exports.malloc(size);
    if (!ptr) throw new PCRE2Error("PCRE2 allocation failed");
    return ptr;
  }

  // Reusable scratch buffers eliminate 2x malloc/free per regex evaluation on Cloudflare Workers.
  const scratchInputPtr = allocate(SCRATCH_INPUT_SIZE + 1);
  const scratchOutputPtr = allocate(SCRATCH_OUTPUT_SIZE);
  const scratchInfoPtr = allocate(256);
  const scratchOffsetPtr = allocate(4);

  function textAt(ptr: number, capacity: number) {
    const bytes = mem().subarray(ptr, ptr + capacity);
    const nul = bytes.indexOf(0);
    if (nul < 0) throw new PCRE2Error("Unterminated PCRE2 output");
    return decoder.decode(bytes.subarray(0, nul));
  }

  function writeBinary(value: string): { ptr: number; length: number; owned: boolean } {
    const length = value.length;
    const owned = length > SCRATCH_INPUT_SIZE;
    const ptr = owned ? allocate(length + 1) : scratchInputPtr;
    const view = mem();
    for (let i = 0; i < length; i++) {
      const code = value.charCodeAt(i);
      if (code > 255) {
        if (owned) exports.free(ptr);
        throw new Error("SecLang byte string contains a non-byte character");
      }
      view[ptr + i] = code;
    }
    view[ptr + length] = 0;
    return { ptr, length, owned };
  }

  function writePattern(value: string, binary = false) {
    if (binary) return writeBinary(value);
    const bytes = encoder.encode(value);
    const owned = bytes.length > SCRATCH_INPUT_SIZE;
    const ptr = owned ? allocate(bytes.length + 1) : scratchInputPtr;
    const view = mem();
    view.set(bytes, ptr);
    view[ptr + bytes.length] = 0;
    return { ptr, length: bytes.length, owned };
  }

  return {
    compile(pattern: string, { binary = false } = {}): SecLangRegex {
      const encoded = writePattern(pattern, binary);
      let ptr = 0;
      try {
        // SecLang uses DOTALL and DOLLAR_ENDONLY by default; inline flags may override them.
        ptr = exports.pcre2_wasm_compile(
          encoded.ptr,
          encoded.length,
          0x30,
          scratchInfoPtr,
          scratchOffsetPtr,
          0,
        );
        if (!ptr) throw new PCRE2Error(`PCRE2 compile: ${textAt(scratchInfoPtr, 256)}`);
      } finally {
        if (encoded.owned) exports.free(encoded.ptr);
      }
      let count: number;
      try {
        if (exports.pcre2_wasm_pattern_info(ptr, scratchInfoPtr, 256) < 0)
          throw new PCRE2Error("PCRE2 pattern info failed");
        count = JSON.parse(textAt(scratchInfoPtr, 256)).captureCount;
      } catch (error) {
        exports.pcre2_wasm_free(ptr);
        throw error;
      }
      return {
        groupCount: () => count,
        destroy() {
          if (ptr) exports.pcre2_wasm_free(ptr);
          ptr = 0;
        },
        matcher(value: string) {
          let result: { match: string; groups: (string | null)[] } | null = null;
          return {
            find() {
              if (!ptr) throw new PCRE2Error("PCRE2 pattern was destroyed");
              const input = writeBinary(value);
              try {
                for (let size = SCRATCH_OUTPUT_SIZE; size <= 8 * 1024 * 1024; size *= 2) {
                  const ownedOutput = size > SCRATCH_OUTPUT_SIZE;
                  const output = ownedOutput ? allocate(size) : scratchOutputPtr;
                  try {
                    const rc = exports.pcre2_wasm_match(
                      ptr,
                      input.ptr,
                      input.length,
                      output,
                      size,
                      matchLimit,
                      depthLimit,
                      0,
                      0,
                      0,
                      0,
                    );
                    if (rc === -999) continue;
                    if (rc < -2) {
                      exports.pcre2_wasm_error_message(rc, output, size);
                      throw new PCRE2Error(`PCRE2 match: ${textAt(output, size)}`, rc);
                    }
                    if (rc > 0) {
                      const bytes = mem().subarray(output, output + size);
                      const end = bytes.indexOf(0);
                      if (end < 0) throw new PCRE2Error("Unterminated PCRE2 match output");
                      let binary = "";
                      for (let i = 0; i < end; i += 8192)
                        binary += String.fromCharCode(
                          ...bytes.subarray(i, Math.min(end, i + 8192)),
                        );
                      result = JSON.parse(binary);
                    } else result = null;
                    return result !== null;
                  } finally {
                    if (ownedOutput) exports.free(output);
                  }
                }
                throw new PCRE2Error("PCRE2 capture output exceeds limit");
              } finally {
                if (input.owned) exports.free(input.ptr);
              }
            },
            group(index: number) {
              if (!result) throw new PCRE2Error("No successful PCRE2 match");
              return index === 0 ? result.match : (result.groups[index - 1] ?? null);
            },
          };
        },
      };
    },
  };
}
