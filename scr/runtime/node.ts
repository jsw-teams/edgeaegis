import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import {
  createServer as createHttp2Server,
  type IncomingHttpHeaders,
  type ServerHttp2Stream,
} from "node:http2";
import { Readable } from "node:stream";
import { canonicalPath, checkRawHeaders } from "../http-boundary/index.js";
import { getGrpcTrailers } from "./grpc-metadata.js";

/** Node-only transport; the engine itself imports no Node API. Never trusts X-Forwarded-For. */
export function createNodeServer(
  handler: (request: Request, incoming: IncomingMessage) => Promise<Response>,
  publicHost: string | readonly string[] | (() => string | readonly string[]),
) {
  const server = createServer(
    {
      maxHeaderSize: 16384,
      insecureHTTPParser: false,
      requestTimeout: 15000,
      headersTimeout: 10000,
      keepAliveTimeout: 5000,
    },
    async (incoming: IncomingMessage, outgoing: ServerResponse) => {
      const abort = new AbortController();
      incoming.on("aborted", () => abort.abort());
      outgoing.on("close", () => {
        if (!outgoing.writableFinished) abort.abort();
      });
      try {
        const hosts = typeof publicHost === "function" ? publicHost() : publicHost;
        const allowed = typeof hosts === "string" ? [hosts] : hosts;
        const expectedHost = incoming.headers.host ?? "";
        checkRawHeaders(incoming.rawHeaders);
        canonicalPath(incoming.url ?? "");
        if (
          !allowed.includes(expectedHost) ||
          !incoming.url?.startsWith("/") ||
          incoming.url.startsWith("//")
        )
          throw new Error("Invalid authority/target");
        const headers = new Headers();
        for (let i = 0; i < incoming.rawHeaders.length; i += 2)
          headers.append(incoming.rawHeaders[i] ?? "", incoming.rawHeaders[i + 1] ?? "");
        const init: RequestInit & { duplex?: "half" } = {
          method: incoming.method ?? "GET",
          headers,
          signal: abort.signal,
        };
        if (!["GET", "HEAD"].includes(init.method ?? "GET")) {
          init.body = Readable.toWeb(incoming) as ReadableStream<Uint8Array>;
          init.duplex = "half";
        }
        const request = new Request(`http://${expectedHost}${incoming.url}`, init);
        const response = await handler(request, incoming);
        if (!incoming.complete) {
          outgoing.setHeader("connection", "close");
          outgoing.once("finish", () => incoming.destroy());
        }
        outgoing.statusCode = response.status;
        for (const [name, value] of response.headers)
          if (name !== "set-cookie") outgoing.setHeader(name, value);
        const cookies = response.headers.getSetCookie();
        if (cookies.length) outgoing.setHeader("set-cookie", cookies);
        if (!response.body) {
          outgoing.end();
          return;
        }
        const reader = response.body.getReader();
        try {
          while (true) {
            const item = await reader.read();
            if (item.done) break;
            if (!outgoing.write(item.value))
              await new Promise<void>((resolve, reject) => {
                const done = () => {
                  outgoing.off("error", failed);
                  outgoing.off("close", failed);
                  resolve();
                };
                const failed = () => {
                  outgoing.off("drain", done);
                  reject(new Error("client-closed"));
                };
                outgoing.once("drain", done);
                outgoing.once("error", failed);
                outgoing.once("close", failed);
              });
          }
          outgoing.end();
        } catch {
          void reader.cancel().catch(() => {});
          outgoing.destroy();
        }
      } catch {
        if (!outgoing.headersSent) {
          outgoing.writeHead(400, { "content-type": "application/json", connection: "close" });
          outgoing.end('{"error":"invalid_http_request"}');
        } else outgoing.destroy();
      }
    },
  );
  server.maxConnections = 256;
  return server;
}

/** Dedicated h2c listener for trusted local ingress (for example Caddy); never bind it publicly. */
export function createGrpcNodeServer(
  handler: (
    request: Request,
    incoming: { socket: { remoteAddress: string | undefined }; url: string },
  ) => Promise<Response>,
  publicHost: string | readonly string[] | (() => string | readonly string[]),
) {
  const server = createHttp2Server({
    maxHeaderListPairs: 100,
    maxSessionMemory: 32,
    settings: { maxConcurrentStreams: 128, maxHeaderListSize: 16384 },
  });
  server.on("stream", async (stream: ServerHttp2Stream, rawHeaders: IncomingHttpHeaders) => {
    const incoming = {
      socket: { remoteAddress: stream.session?.socket.remoteAddress },
      url: String(rawHeaders[":path"] ?? "/"),
    };
    const abort = new AbortController();
    stream.on("aborted", () => abort.abort());
    stream.on("close", () => {
      if (!stream.writableFinished) abort.abort();
    });
    try {
      const hosts = typeof publicHost === "function" ? publicHost() : publicHost;
      const allowed = typeof hosts === "string" ? [hosts] : hosts;
      const authority = String(rawHeaders[":authority"] ?? "");
      const target = String(rawHeaders[":path"] ?? "");
      if (
        !allowed.includes(authority) ||
        !target.startsWith("/") ||
        target.startsWith("//") ||
        Object.keys(rawHeaders).length > 100
      )
        throw new Error("Invalid HTTP/2 authority/target");
      canonicalPath(target);
      const headers = new Headers();
      for (const [name, value] of Object.entries(rawHeaders)) {
        if (name.startsWith(":")) continue;
        if (Array.isArray(value)) for (const item of value) headers.append(name, item);
        else if (value !== undefined) headers.append(name, value);
      }
      const method = String(rawHeaders[":method"] ?? "POST");
      const init: RequestInit & { duplex?: "half" } = {
        method,
        headers,
        signal: abort.signal,
      };
      if (!["GET", "HEAD"].includes(method)) {
        init.body = Readable.toWeb(Readable.from(stream)) as ReadableStream<Uint8Array>;
        init.duplex = "half";
      }
      const request = new Request(`http://${authority}${target}`, init);
      const response = await handler(request, incoming);
      const trailers = getGrpcTrailers(response);
      const responseHeaders: Record<string, string | string[]> = {
        ":status": String(response.status),
      };
      for (const [name, value] of response.headers)
        if (
          ![
            "connection",
            "keep-alive",
            "proxy-connection",
            "transfer-encoding",
            "upgrade",
            "set-cookie",
          ].includes(name)
        )
          responseHeaders[name] = value;
      const cookies = response.headers.getSetCookie();
      if (cookies.length) responseHeaders["set-cookie"] = cookies;
      let trailerFields: Headers | undefined;
      stream.respond(responseHeaders, trailers ? { waitForTrailers: true } : undefined);
      if (trailers)
        stream.once("wantTrailers", () => {
          if (!trailerFields) return stream.close();
          const output: Record<string, string> = {};
          for (const [name, value] of trailerFields)
            if (/^[a-z0-9-]+$/.test(name) && !name.startsWith(":")) output[name] = value;
          stream.sendTrailers(output);
        });
      if (!response.body) {
        if (trailers) trailerFields = await trailers;
        stream.end();
        return;
      }
      const reader = response.body.getReader();
      try {
        while (true) {
          const item = await reader.read();
          if (item.done) break;
          if (!stream.write(item.value))
            await new Promise<void>((resolve, reject) => {
              const drain = () => {
                stream.off("error", failed);
                stream.off("close", failed);
                resolve();
              };
              const failed = () => {
                stream.off("drain", drain);
                reject(new Error("client-closed"));
              };
              stream.once("drain", drain);
              stream.once("error", failed);
              stream.once("close", failed);
            });
        }
        if (trailers) trailerFields = await trailers;
        stream.end();
      } catch {
        void reader.cancel().catch(() => {});
        stream.close();
      }
    } catch {
      if (!stream.headersSent) {
        stream.respond({ ":status": 400, "content-type": "application/json" });
        stream.end('{"error":"invalid_http2_request"}');
      } else stream.destroy();
    }
  });
  return server;
}
