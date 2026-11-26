export interface InjectionDetectors {
  sqli(value: string): { matched: boolean; fingerprint: string };
  xss(value: string): boolean;
}

const SCRATCH_INPUT_SIZE = 4096;

/** Only tokenizer/detector primitives are imported; SecLang execution stays first-party. */
export async function createInjectionDetectors(
  module: WebAssembly.Module | BufferSource,
): Promise<InjectionDetectors> {
  const loaded = await WebAssembly.instantiate(module as WebAssembly.Module, {});
  const instance =
    loaded instanceof WebAssembly.Instance
      ? loaded
      : (loaded as WebAssembly.WebAssemblyInstantiatedSource).instance;
  const api = instance.exports as unknown as {
    memory: WebAssembly.Memory;
    malloc(size: number): number;
    free(ptr: number): void;
    libinjection_sqli(ptr: number, length: number, fingerprint: number): number;
    libinjection_xss(ptr: number, length: number): number;
    _initialize?(): void;
  };
  api._initialize?.();
  const decoder = new TextDecoder();
  let cachedBuffer: ArrayBuffer | null = null;
  let cachedMem = new Uint8Array(0);
  function mem(): Uint8Array {
    const buffer = api.memory.buffer;
    if (buffer !== cachedBuffer) {
      cachedBuffer = buffer;
      cachedMem = new Uint8Array(buffer);
    }
    return cachedMem;
  }
  const scratchPtr = api.malloc(SCRATCH_INPUT_SIZE + 1);
  const fpPtr = api.malloc(8);
  if (!scratchPtr || !fpPtr) throw new Error("Libinjection allocation failed");

  function inspect<T>(value: string, fn: (ptr: number, length: number) => T): T {
    const length = value.length;
    if (length > 2 * 1024 * 1024) throw new Error("Libinjection input exceeds limit");
    const owned = length > SCRATCH_INPUT_SIZE;
    const ptr = owned ? api.malloc(length + 1) : scratchPtr;
    if (!ptr) throw new Error("Libinjection allocation failed");
    try {
      const view = mem();
      for (let i = 0; i < length; i++) {
        const code = value.charCodeAt(i);
        if (code > 255) throw new Error("SecLang byte string contains a non-byte character");
        view[ptr + i] = code;
      }
      return fn(ptr, length);
    } finally {
      if (owned) api.free(ptr);
    }
  }
  return {
    sqli(value) {
      return inspect(value, (ptr, length) => {
        const rc = api.libinjection_sqli(ptr, length, fpPtr);
        if (rc < 0) throw new Error("Libinjection SQLi error");
        if (rc !== 1) return { matched: false, fingerprint: "" };
        const buffer = mem().subarray(fpPtr, fpPtr + 8);
        const end = buffer.indexOf(0);
        if (end < 0) throw new Error("Libinjection fingerprint is unterminated");
        return {
          matched: true,
          fingerprint: decoder.decode(buffer.subarray(0, end)),
        };
      });
    },
    xss(value) {
      return inspect(value, (ptr, length) => {
        const rc = api.libinjection_xss(ptr, length);
        if (rc < 0) throw new Error("Libinjection XSS error");
        return rc === 1;
      });
    },
  };
}
