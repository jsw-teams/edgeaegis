import { requireInteger } from "../core/types.js";

/** No fixed total deadline: continuously progressing transfers can last longer than headerTimeoutMs. */
export function protectStream(
  input: ReadableStream<Uint8Array>,
  options: {
    maxBytes: number;
    idleTimeoutMs: number;
    signal: AbortSignal;
    abort: () => void;
    complete: () => void;
  },
): ReadableStream<Uint8Array> {
  requireInteger(options.maxBytes, 1, Number.MAX_SAFE_INTEGER, "stream bytes");
  requireInteger(options.idleTimeoutMs, 1, 300000, "stream idle deadline");
  const reader = input.getReader();
  let controller: ReadableStreamDefaultController<Uint8Array>;
  let timer: ReturnType<typeof setTimeout> | undefined;
  let ended = false;
  let total = 0;
  const cleanup = () => {
    if (ended) return;
    ended = true;
    if (timer) clearTimeout(timer);
    options.signal.removeEventListener("abort", interrupted);
    options.complete();
  };
  const fail = (error: Error) => {
    if (ended) return;
    cleanup();
    options.abort();
    void reader.cancel(error).catch(() => {});
    controller.error(error);
  };
  const interrupted = () => fail(new Error("origin-stream-aborted"));
  const reset = () => {
    if (timer) clearTimeout(timer);
    timer = setTimeout(() => fail(new Error("origin-stream-idle-timeout")), options.idleTimeoutMs);
  };
  return new ReadableStream<Uint8Array>({
    start(c) {
      controller = c;
      options.signal.addEventListener("abort", interrupted, { once: true });
      if (options.signal.aborted) interrupted();
      else reset();
    },
    async pull(c) {
      if (ended) return;
      try {
        const item = await reader.read();
        if (ended) return;
        if (item.done) {
          cleanup();
          c.close();
          return;
        }
        total += item.value.byteLength;
        if (total > options.maxBytes) throw new Error("origin-response-too-large");
        reset();
        c.enqueue(item.value);
      } catch (error) {
        fail(error instanceof Error ? error : new Error("stream-failure"));
      }
    },
    cancel(reason) {
      cleanup();
      options.abort();
      return reader.cancel(reason);
    },
  });
}
