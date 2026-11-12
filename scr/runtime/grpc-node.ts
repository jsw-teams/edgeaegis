import { type ClientHttp2Session, connect, constants, type IncomingHttpHeaders } from "node:http2";
import { Readable } from "node:stream";
import type { Fetch } from "../core/types.js";
import { setGrpcTrailers } from "./grpc-metadata.js";

const forbidden = new Set([
  "connection",
  "keep-alive",
  "proxy-connection",
  "transfer-encoding",
  "upgrade",
  "host",
  "content-length",
]);

function headerMap(input: IncomingHttpHeaders, skipPseudo = true) {
  const result = new Headers();
  for (const [name, value] of Object.entries(input)) {
    if ((skipPseudo && name.startsWith(":")) || forbidden.has(name) || value === undefined)
      continue;
    if (Array.isArray(value)) for (const part of value) result.append(name, part);
    else if (typeof value === "string") result.append(name, value);
  }
  return result;
}

/** Native HTTP/2 upstream for gRPC routes; one bounded multiplexed session per origin. */
export function createGrpcFetch(): { fetch: Fetch; close: () => void } {
  const sessions = new Map<string, ClientHttp2Session>();
  const getSession = (target: URL) => {
    let session = sessions.get(target.origin);
    if (!session || session.closed || session.destroyed) {
      session = connect(target.origin);
      session.on("error", () => {});
      session.on("close", () => {
        if (sessions.get(target.origin) === session) sessions.delete(target.origin);
      });
      sessions.set(target.origin, session);
    }
    return session;
  };
  const fetch: Fetch = async (input, init = {}) => {
    const target = new URL(input instanceof Request ? input.url : input.toString());
    if (
      (target.protocol !== "https:" && target.protocol !== "http:") ||
      (target.protocol === "http:" && !["127.0.0.1", "[::1]"].includes(target.hostname))
    )
      throw new Error("gRPC upstream must use TLS or an explicit loopback h2c origin");
    const method = init.method ?? (input instanceof Request ? input.method : "POST");
    const sourceHeaders = new Headers(
      init.headers ?? (input instanceof Request ? input.headers : undefined),
    );
    const headers: Record<string, string> = {
      ":method": method,
      ":path": `${target.pathname}${target.search}`,
      ":scheme": target.protocol.slice(0, -1),
      ":authority": target.host,
    };
    for (const [name, value] of sourceHeaders)
      if (!forbidden.has(name) && /^[a-z0-9!#$%&'*+.^_`|~-]+$/.test(name)) headers[name] = value;
    headers.te = "trailers";

    const session = getSession(target);
    const stream = session.request(headers, {
      endStream: init.body === undefined || init.body === null,
      waitForTrailers: false,
    });
    const signal = init.signal;
    const abort = () => stream.close(constants.NGHTTP2_CANCEL);
    signal?.addEventListener("abort", abort, { once: true });
    if (signal?.aborted) abort();
    if (init.body !== undefined && init.body !== null) {
      const requestBody = init.body;
      const body =
        requestBody instanceof ReadableStream
          ? Readable.from(
              (async function* () {
                const reader = requestBody.getReader();
                try {
                  while (true) {
                    const item = await reader.read();
                    if (item.done) break;
                    yield Buffer.from(item.value);
                  }
                } finally {
                  reader.releaseLock();
                }
              })(),
            )
          : Readable.from([requestBody as string | Uint8Array]);
      body.once("error", () => stream.close(constants.NGHTTP2_CANCEL));
      body.pipe(stream);
    }

    try {
      const responseHeaders = await new Promise<IncomingHttpHeaders>((resolve, reject) => {
        stream.once("response", resolve);
        stream.once("error", reject);
      });
      const status = Number(responseHeaders[":status"] ?? 502);
      const headersOut = headerMap(responseHeaders);
      const trailers = new Promise<Headers>((resolve) => {
        stream.once("trailers", (value: IncomingHttpHeaders) => resolve(headerMap(value)));
        stream.once("close", () => resolve(new Headers()));
      });
      const response = new Response(Readable.toWeb(stream) as ReadableStream<Uint8Array>, {
        status,
        headers: headersOut,
      });
      setGrpcTrailers(response, trailers);
      stream.once("close", () => signal?.removeEventListener("abort", abort));
      return response;
    } catch (error) {
      signal?.removeEventListener("abort", abort);
      stream.close(constants.NGHTTP2_CANCEL);
      throw error;
    }
  };
  return {
    fetch,
    close() {
      for (const session of sessions.values()) session.close();
      sessions.clear();
    },
  };
}
