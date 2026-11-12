import { type Fetch, requireInteger, ShieldError } from "../core/types.js";
import { applyBrowserCache, type BrowserCachePolicy } from "./browser-cache.js";
import { copyGrpcTrailers } from "./grpc-metadata.js";
import { protectStream } from "./stream.js";

export interface ProxyOptions {
  origin: string;
  allowedOrigins: readonly string[];
  originToken: string;
  timeoutMs?: number;
  maxResponseBytes?: number;
  allowLoopbackHttp?: boolean;
  fetch?: Fetch;
  grpcFetch?: Fetch;
}
const hop = [
  "connection",
  "keep-alive",
  "proxy-authenticate",
  "proxy-authorization",
  "te",
  "trailer",
  "transfer-encoding",
  "upgrade",
  "host",
  "content-length",
];

export function createProxy(options: ProxyOptions) {
  const origin = new URL(options.origin);
  const loopback = ["127.0.0.1", "[::1]"].includes(origin.hostname);
  if (
    origin.username ||
    origin.password ||
    origin.pathname !== "/" ||
    origin.search ||
    origin.hash ||
    !options.allowedOrigins.includes(origin.origin)
  )
    throw new Error("Origin must be an exact allowlisted origin without credentials/path/query");
  if (
    origin.protocol !== "https:" &&
    !(options.allowLoopbackHttp && loopback && origin.protocol === "http:")
  )
    throw new Error("Upstream TLS required (only explicit loopback development HTTP allowed)");
  const originToken = options.originToken;
  if (!/^[\x21-\x7e]{32,2048}$/.test(originToken))
    throw new Error("Origin authentication token must contain 32..2048 visible ASCII characters");
  const timeout = requireInteger(options.timeoutMs ?? 10000, 1, 120000, "proxy timeout");
  const maxResponse = requireInteger(
    options.maxResponseBytes ?? 16777216,
    1,
    1073741824,
    "response bytes",
  );
  const transport = options.fetch ?? fetch;
  let consecutiveFailures = 0;
  let openUntil = 0;
  return async (
    incoming: Request,
    url: URL,
    path: string,
    body: Uint8Array,
    onComplete: () => void = () => {},
    websocket = false,
    browserCache?: BrowserCachePolicy,
    requestTransport?: Fetch,
    grpcBody?: ReadableStream<Uint8Array>,
    grpc = false,
  ): Promise<Response> => {
    if (Date.now() < openUntil) throw new ShieldError("origin-circuit-open", 503);
    const target = new URL(origin);
    target.pathname = path;
    target.search = url.search;
    if (target.origin !== origin.origin) throw new ShieldError("origin-allowlist", 502);
    const headers = new Headers(incoming.headers);
    for (const name of [...headers.keys()]) {
      if (
        hop.includes(name) ||
        name === "forwarded" ||
        name === "x-real-ip" ||
        name.startsWith("x-forwarded-") ||
        name.startsWith("cf-") ||
        name.startsWith("x-vercel-") ||
        name.startsWith("x-nf-") ||
        name.startsWith("x-shield-") ||
        name.startsWith("x-edgeshield-")
      )
        headers.delete(name);
    }
    headers.set("x-shield-origin-auth", originToken);
    headers.set("accept-encoding", "identity");
    if (grpc) headers.set("te", "trailers");
    if (websocket) headers.set("upgrade", "websocket");
    const abort = new AbortController();
    let completed = false;
    const timer = setTimeout(() => {
      abort.abort();
      cleanup();
    }, timeout);
    const abortFromClient = () => abort.abort();
    incoming.signal.addEventListener("abort", abortFromClient, { once: true });
    const cleanup = () => {
      if (completed) return;
      completed = true;
      clearTimeout(timer);
      incoming.signal.removeEventListener("abort", abortFromClient);
      onComplete();
    };
    try {
      const init: RequestInit = {
        method: incoming.method,
        headers,
        redirect: "manual",
        signal: abort.signal,
      };
      if (grpc) {
        if (!grpcBody) throw new ShieldError("grpc-body-required", 400);
        init.body = grpcBody;
        (init as RequestInit & { duplex?: "half" }).duplex = "half";
      } else if (!["GET", "HEAD"].includes(incoming.method) && body.length)
        init.body = body as BodyInit;
      if (incoming.signal.aborted) throw new ShieldError("client-aborted", 408);
      const upstream = await (
        requestTransport ??
        (grpc ? options.grpcFetch : undefined) ??
        transport
      )(target, init);
      if (grpc) clearTimeout(timer);
      if (abort.signal.aborted) {
        void upstream.body?.cancel().catch(() => {});
        throw new ShieldError("origin-timeout-or-abort", 504);
      }
      if (upstream.status >= 500) {
        consecutiveFailures++;
        if (consecutiveFailures >= 5) openUntil = Date.now() + 5000;
      } else consecutiveFailures = 0;
      if (upstream.status === 101) {
        const socket = (upstream as Response & { webSocket?: { close(code: number): void } })
          .webSocket;
        cleanup();
        if (!websocket || !socket) {
          try {
            socket?.close(1008);
          } catch {
            /* Already closed. */
          }
          throw new ShieldError("unexpected-origin-upgrade", 502);
        }
        const output = new Headers(upstream.headers);
        for (const name of [...output.keys()])
          if (
            ["server", "x-powered-by"].includes(name) ||
            name.startsWith("x-shield-") ||
            name.startsWith("x-edgeshield-")
          )
            output.delete(name);
        output.set("cache-control", "no-store");
        // Preserve the native socket. SecLang inspects this response before ownership is transferred.
        return new Response(null, {
          status: 101,
          headers: output,
          webSocket: socket,
        } as ResponseInit);
      }
      // Avoid fetch implementations disagreeing about automatic decompression.
      if (
        upstream.headers.has("content-encoding") &&
        upstream.headers.get("content-encoding") !== "identity"
      ) {
        void upstream.body?.cancel().catch(() => {});
        throw new ShieldError("unexpected-origin-encoding", 502);
      }
      const responseHeaders = new Headers(upstream.headers);
      for (const token of (responseHeaders.get("connection") ?? "").split(","))
        if (token.trim()) responseHeaders.delete(token.trim());
      for (const name of [...responseHeaders.keys()])
        if (
          hop.includes(name) ||
          ["server", "x-powered-by"].includes(name) ||
          name.startsWith("x-shield-")
        )
          responseHeaders.delete(name);
      applyBrowserCache(incoming, upstream, responseHeaders, browserCache);
      if (
        !upstream.body ||
        incoming.method === "HEAD" ||
        [204, 205, 304].includes(upstream.status)
      ) {
        cleanup();
        void upstream.body?.cancel().catch(() => {});
        return copyGrpcTrailers(
          upstream,
          new Response(null, { status: upstream.status, headers: responseHeaders }),
        );
      }
      const stream = protectStream(upstream.body, {
        maxBytes: grpc ? Number.MAX_SAFE_INTEGER : maxResponse,
        idleTimeoutMs: grpc ? 300000 : timeout,
        signal: abort.signal,
        abort: () => abort.abort(),
        complete: cleanup,
      });
      const response = new Response(stream, {
        status: upstream.status,
        statusText: upstream.statusText,
        headers: responseHeaders,
      });
      if (grpc) copyGrpcTrailers(upstream, response);
      return response;
    } catch (error) {
      const wasAborted = abort.signal.aborted;
      cleanup();
      abort.abort();
      consecutiveFailures++;
      if (consecutiveFailures >= 5) openUntil = Date.now() + 5000;
      if (error instanceof ShieldError) throw error;
      throw new ShieldError(
        wasAborted ? "origin-timeout-or-abort" : "origin-unavailable",
        wasAborted ? 504 : 502,
      );
    }
  };
}
