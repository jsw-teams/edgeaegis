import assert from "node:assert/strict";
import { once } from "node:events";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import {
  connect,
  createServer,
  type IncomingHttpHeaders,
  type ServerHttp2Stream,
} from "node:http2";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { readDeployment } from "../../scr/cli/deployment.js";
import { validateGrpcStream } from "../../scr/runtime/grpc.js";
import { getGrpcTrailers, setGrpcTrailers } from "../../scr/runtime/grpc-metadata.js";
import { createGrpcFetch } from "../../scr/runtime/grpc-node.js";
import { createGrpcNodeServer } from "../../scr/runtime/node.js";

const framed = Uint8Array.of(0, 0, 0, 0, 3, 1, 2, 3);
const streamOf = (bytes: Uint8Array) =>
  new ReadableStream<Uint8Array>({
    start(controller) {
      controller.enqueue(bytes);
      controller.close();
    },
  });

test("deployment permits loopback h2c only on explicitly enabled gRPC routes", async () => {
  const directory = await mkdtemp(join(tmpdir(), "edgeaegis-grpc-config-"));
  try {
    await mkdir(join(directory, "rules"));
    await mkdir(join(directory, "origin/cloudflare"), { recursive: true });
    await mkdir(join(directory, "secret"));
    await writeFile(join(directory, "rules/config.yml"), "source: source.conf\n");
    await writeFile(join(directory, "rules/source.conf"), "");
    await writeFile(join(directory, "secret/credentials.yml"), "{}");
    const config = join(directory, "config.yml");
    await writeFile(
      config,
      JSON.stringify({
        tenant: "test",
        service: "grpc",
        platform: "cloudflare",
        secretFile: "secret/credentials.yml",
        listen: { host: "127.0.0.1", port: 8787 },
        grpcListen: { host: "127.0.0.1", port: 8788 },
        allowLoopbackHttp: true,
      }),
    );
    const originFile = join(directory, "origin/config.yml");
    await writeFile(
      originFile,
      JSON.stringify({
        routes: [
          {
            pattern: "api.js.gripe/tunnel/*",
            origin: "http://127.0.0.1:10000",
            grpc: true,
            methods: ["POST"],
            key: "xray-local",
          },
        ],
      }),
    );
    const valid = await readDeployment(config);
    assert.equal(valid.config.routes[0]?.grpc, true);
    await writeFile(
      originFile,
      JSON.stringify({
        routes: [
          {
            pattern: "api.js.gripe/tunnel/*",
            origin: "http://127.0.0.1:10000",
            methods: ["POST"],
            key: "xray-local",
          },
        ],
      }),
    );
    await assert.rejects(readDeployment(config), /HTTPS/);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("gRPC frame validator streams complete envelopes and rejects malformed frames", async () => {
  const valid = validateGrpcStream(streamOf(framed), 16, null);
  const parts: Uint8Array[] = [];
  for await (const part of valid) parts.push(part);
  assert.deepEqual([...parts[0]!], [...framed]);
  await assert.rejects(async () => {
    for await (const _part of validateGrpcStream(
      streamOf(Uint8Array.of(2, 0, 0, 0, 0)),
      16,
      null,
    )) {
    }
  }, /invalid-grpc-compression-flag/);
  await assert.rejects(async () => {
    for await (const _part of validateGrpcStream(
      streamOf(Uint8Array.of(0, 0, 0, 0, 4, 1)),
      16,
      null,
    )) {
    }
  }, /truncated-grpc-message/);
  await assert.rejects(async () => {
    for await (const _part of validateGrpcStream(
      streamOf(Uint8Array.of(0, 0, 0, 1, 0)),
      16,
      null,
    )) {
    }
  }, /grpc-message-too-large/);
});

test("native gRPC transport multiplexing path preserves HTTP/2 trailers and binary frames", async (t) => {
  const server = createServer();
  server.on("stream", (stream: ServerHttp2Stream, headers) => {
    assert.equal(headers[":path"], "/svc/method?x=1");
    const chunks: Buffer[] = [];
    stream.on("data", (chunk: Buffer) => chunks.push(chunk));
    stream.on("end", () => {
      assert.deepEqual(Buffer.concat(chunks), Buffer.from(framed));
      stream.respond(
        { ":status": 200, "content-type": "application/grpc" },
        { waitForTrailers: true },
      );
      stream.on("wantTrailers", () =>
        stream.sendTrailers({ "grpc-status": "0", "grpc-message": "ok" }),
      );
      stream.end(framed);
    });
  });
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  t.after(() => server.close());
  const address = server.address();
  assert(address && typeof address !== "string");
  const transport = createGrpcFetch();
  t.after(() => transport.close());
  const response = await transport.fetch(`http://127.0.0.1:${address.port}/svc/method?x=1`, {
    method: "POST",
    headers: { "content-type": "application/grpc", te: "trailers" },
    body: streamOf(framed),
    duplex: "half",
  } as RequestInit);
  assert.equal(response.status, 200);
  assert.deepEqual(new Uint8Array(await response.arrayBuffer()), framed);
  assert.deepEqual(Object.fromEntries(await getGrpcTrailers(response)!), {
    "grpc-message": "ok",
    "grpc-status": "0",
  });
});

test("dedicated loopback gRPC listener enforces authority and streams trailers", async (t) => {
  const server = createGrpcNodeServer(
    async (request) => {
      assert.equal(request.headers.get("content-type"), "application/grpc");
      const received = new Uint8Array(await request.arrayBuffer());
      assert.deepEqual(received, framed);
      const response = new Response(streamOf(framed), {
        headers: { "content-type": "application/grpc" },
      });
      setGrpcTrailers(response, Promise.resolve(new Headers({ "grpc-status": "0" })));
      return response;
    },
    ["xray.example"],
  );
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  t.after(() => server.close());
  const address = server.address();
  assert(address && typeof address !== "string");
  const client = connect(`http://127.0.0.1:${address.port}`);
  t.after(() => client.close());
  const response = await new Promise<{
    status: number;
    bytes: Buffer;
    trailers: Record<string, string>;
  }>((resolve, reject) => {
    const stream = client.request({
      ":method": "POST",
      ":path": "/svc/Tun",
      ":authority": "xray.example",
      "content-type": "application/grpc",
      te: "trailers",
    });
    const chunks: Buffer[] = [];
    let status = 0;
    const timeout = setTimeout(
      () =>
        reject(
          new Error(
            `gRPC listener timed out at HTTP ${status}; bytes=${Buffer.concat(chunks).length}`,
          ),
        ),
      2000,
    );
    stream.on("response", (headers: IncomingHttpHeaders) => {
      status = Number(headers[":status"]);
    });
    stream.on("data", (chunk: Buffer) => chunks.push(chunk));
    stream.on("trailers", (trailers: IncomingHttpHeaders) => {
      clearTimeout(timeout);
      resolve({
        status,
        bytes: Buffer.concat(chunks),
        trailers: trailers as Record<string, string>,
      });
    });
    stream.on("end", () => {
      clearTimeout(timeout);
      reject(
        new Error(
          `gRPC response ended without trailers at HTTP ${status}; bytes=${Buffer.concat(chunks).length}`,
        ),
      );
    });
    stream.on("error", reject);
    stream.end(framed);
  });
  assert.equal(response.status, 200);
  assert.deepEqual(response.bytes, Buffer.from(framed));
  assert.equal(response.trailers["grpc-status"], "0");
});
