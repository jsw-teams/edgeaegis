import { timingSafeEqual } from "node:crypto";
import { once } from "node:events";
import { originCredential } from "../config.js";
import { digest, stableJson } from "../core/types.js";
import { createRelayTransport } from "../origin/relay.js";
import { createGrpcFetch } from "../runtime/grpc-node.js";
import { type AllowlistEntry, createShield } from "../runtime/index.js";
import { startL4Forwarders } from "../runtime/l4.js";
import { createGrpcNodeServer, createNodeServer } from "../runtime/node.js";
import { loadSecLangDeployment } from "../seclang/node.js";
import { readCredentials, readData } from "./config.js";
import { readBusinessFunction, readDeployment } from "./deployment.js";
import { readResponsePages } from "./responses.js";

function authorized(header: string | null, secret: string) {
  const given = Buffer.from(header?.startsWith("Bearer ") ? header.slice(7) : "");
  const expected = Buffer.from(secret);
  return given.length === expected.length && timingSafeEqual(given, expected);
}
export async function serve(path: string): Promise<void> {
  const grpcTransport = createGrpcFetch();
  let fingerprint = "";
  async function candidate() {
    const { config, businesses } = await readDeployment(path);
    const credentials = await readCredentials(config.secretFile),
      native = await loadSecLangDeployment(
        config.secLangFile,
        config.localRulesFile,
        config.setupRulesFile,
      );
    const allowlist = config.allowlistFile
      ? ((await readData(config.allowlistFile)) as AllowlistEntry[])
      : [];
    const errorPages = config.responses
      ? await readResponsePages(config.responses.directory, config.responses.contentSecurityPolicy)
      : {};
    const origins: Record<string, import("../runtime/proxy.js").ProxyOptions> = Object.create(null);
    const contexts: Record<string, unknown> = Object.create(null);
    for (const [name, { settings, businessFile }] of Object.entries(businesses)) {
      const business =
        settings.mode === "function" ? await readBusinessFunction(businessFile) : undefined;
      const upstreams =
        settings.mode === "function"
          ? Object.fromEntries(
              (settings.upstreams ?? []).map((key) => [key, config.upstreams![key]!]),
            )
          : {};
      const context = {
        secrets:
          settings.mode === "function" && settings.secretsFile
            ? ((await readData(settings.secretsFile, 65536)) as Record<string, unknown>)
            : {},
        upstreams,
        originKeys: Object.fromEntries(
          [
            ...new Set([
              config.origins[name]!.key,
              ...Object.values(upstreams).map((value) => value.key),
            ]),
          ].map((key) => [key, originCredential(credentials, key)]),
        ),
      };
      contexts[name] = context;
      const originFetch = business
        ? (input: RequestInfo | URL, init?: RequestInit) =>
            Promise.resolve(business.fetch(new Request(input, init), {}, context))
        : settings.mode === "relay"
          ? await createRelayTransport({
              endpoint: settings.endpoint,
              serverPublicKey: (await readData(settings.publicKeyFile, 16384)) as JsonWebKey,
              authenticationKey: (await readData(settings.authenticationKeyFile, 4096)) as string,
              maxBytes: config.limits?.maxBodyBytes ?? 8388608,
            })
          : undefined;
      origins[name] = {
        ...config.origins[name]!,
        originToken: originCredential(credentials, config.origins[name]!.key),
        allowLoopbackHttp: config.allowLoopbackHttp ?? false,
        grpcFetch: grpcTransport.fetch,
        ...(originFetch ? { fetch: originFetch } : {}),
      };
    }
    const hash = await digest(
      stableJson({
        config,
        businesses,
        errorPages,
        credentials,
        contexts,
        source: native.secLang,
        files: native.secLangOptions.files,
        allowlist,
      }),
    );
    if (hash === fingerprint) return undefined;
    const engine = await createShield({
      tenant: config.tenant,
      service: config.service,
      publicHosts: config.publicHosts,
      routes: config.routes,
      ...native,
      allowlist,
      errorPages,
      ...(config.limits ? { limits: config.limits } : {}),
      ...(config.maxConcurrentRequests
        ? { maxConcurrentRequests: config.maxConcurrentRequests }
        : {}),
      origins,
      event: (event) => process.stdout.write(`${JSON.stringify(event)}\n`),
    });
    return { config, credentials, engine, hash };
  }
  let current = (await candidate())!;
  fingerprint = current.hash;
  const l4 = await startL4Forwarders(current.config.l4Forwarders ?? [], current.config.l4Limits);
  let nextReload = Date.now() + 1000,
    reloading: Promise<void> | undefined;
  const server = createNodeServer(
    async (request, incoming) => {
      if (Date.now() >= nextReload && !reloading) {
        nextReload = Date.now() + 1000;
        reloading = candidate()
          .then((next) => {
            if (!next) return;
            if (
              stableJson(next.config.listen) !== stableJson(current.config.listen) ||
              stableJson(next.config.grpcListen ?? null) !==
                stableJson(current.config.grpcListen ?? null) ||
              stableJson(next.config.l4Forwarders ?? []) !==
                stableJson(current.config.l4Forwarders ?? []) ||
              stableJson(next.config.l4Limits ?? {}) !== stableJson(current.config.l4Limits ?? {})
            ) {
              next.engine.dispose();
              throw new Error("Listener changes require restart");
            }
            const previous = current;
            current = next;
            fingerprint = next.hash;
            previous.engine.dispose();
            process.stderr.write('{"event":"rules-reloaded"}\n');
          })
          .catch(() => process.stderr.write('{"event":"reload-rejected"}\n'))
          .then(() => {})
          .finally(() => {
            reloading = undefined;
          });
      }
      await reloading;
      return current.engine.handle(
        request,
        {
          tenant: current.config.tenant,
          verifiedClientIp: incoming.socket.remoteAddress ?? "127.0.0.1",
          httpProtocol: `HTTP/${incoming.httpVersion}`,
          ...(current.credentials.clientToken &&
          authorized(request.headers.get("authorization"), current.credentials.clientToken)
            ? { identity: "configured-api-client" }
            : {}),
        },
        incoming.url,
      );
    },
    () => current.config.publicHosts,
  );
  const grpcServer = current.config.grpcListen
    ? createGrpcNodeServer(
        (request, incoming) =>
          current.engine.handle(
            request,
            {
              tenant: current.config.tenant,
              verifiedClientIp: incoming.socket.remoteAddress ?? "127.0.0.1",
              httpProtocol: "HTTP/2.0",
              ...(current.credentials.clientToken &&
              authorized(request.headers.get("authorization"), current.credentials.clientToken)
                ? { identity: "configured-api-client" }
                : {}),
            },
            incoming.url,
          ),
        () => current.config.publicHosts,
      )
    : undefined;
  server.listen(current.config.listen.port, current.config.listen.host);
  await once(server, "listening");
  if (grpcServer && current.config.grpcListen) {
    grpcServer.listen(current.config.grpcListen.port, current.config.grpcListen.host);
    await once(grpcServer, "listening");
  }
  const address = server.address();
  if (!address || typeof address === "string") throw new Error("Missing TCP listener");
  process.stderr.write(
    `listening at http://${current.config.listen.host}:${address.port}; native SecLang\n`,
  );
  if (grpcServer && current.config.grpcListen)
    process.stderr.write(
      `gRPC h2c at ${current.config.grpcListen.host}:${current.config.grpcListen.port}\n`,
    );
  let stopping = false;
  const stop = () => {
    if (stopping) return;
    stopping = true;
    server.close(() => {
      current.engine.dispose();
    });
    grpcServer?.close();
    grpcTransport.close();
    void l4.close();
    server.closeIdleConnections();
    setTimeout(() => server.closeAllConnections(), 5000).unref();
  };
  process.once("SIGINT", stop);
  process.once("SIGTERM", stop);
}
