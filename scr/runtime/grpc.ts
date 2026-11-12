import { ShieldError } from "../core/types.js";

export const isGrpcContentType = (value: string | null): boolean =>
  value !== null && /^application\/grpc(?:\+[a-z0-9._-]+)?(?:\s*;.*)?$/i.test(value);

/** Validates the gRPC 5-byte message envelope while forwarding without whole-stream buffering. */
export function validateGrpcStream(
  body: ReadableStream<Uint8Array>,
  maxMessageBytes: number,
  grpcEncoding: string | null,
): ReadableStream<Uint8Array> {
  const encoding = (grpcEncoding ?? "identity").trim().toLowerCase();
  if (!/^(identity|gzip)$/.test(encoding)) throw new ShieldError("unsupported-grpc-encoding", 415);
  let header = new Uint8Array(5);
  let headerBytes = 0;
  let remaining: number | undefined;
  const validator = new TransformStream<Uint8Array, Uint8Array>({
    transform(chunk, controller) {
      let offset = 0;
      while (offset < chunk.length) {
        if (remaining === undefined) {
          const take = Math.min(5 - headerBytes, chunk.length - offset);
          header.set(chunk.subarray(offset, offset + take), headerBytes);
          headerBytes += take;
          offset += take;
          if (headerBytes < 5) break;
          if (header[0]! > 1) throw new ShieldError("invalid-grpc-compression-flag", 400);
          remaining = ((header[1]! * 0x1000000 +
            (header[2]! << 16) +
            (header[3]! << 8) +
            header[4]!) >>>
            0) as number;
          if (remaining > maxMessageBytes) throw new ShieldError("grpc-message-too-large", 413);
          if (header[0] === 1 && encoding === "identity")
            throw new ShieldError("grpc-compression-header-mismatch", 400);
          header = new Uint8Array(5);
          headerBytes = 0;
          if (remaining === 0) remaining = undefined;
          continue;
        }
        const take = Math.min(remaining, chunk.length - offset);
        offset += take;
        remaining -= take;
        if (remaining === 0) remaining = undefined;
      }
      controller.enqueue(chunk);
    },
    flush() {
      if (headerBytes !== 0 || remaining !== undefined)
        throw new ShieldError("truncated-grpc-message", 400);
    },
  });
  return body.pipeThrough(validator);
}
