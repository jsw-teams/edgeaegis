import { realpath } from "node:fs/promises";
import { dirname, isAbsolute, relative, resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { type DeploymentConfig, validateDeploymentConfig } from "../config.js";
import { canonicalPath } from "../http-boundary/index.js";
import type { BusinessFunction, OriginSettings, PlatformName } from "../origin/types.js";
import type { Route } from "../runtime/index.js";
import { resolveL4ResourceLimits, validateL4ForwardRules } from "../runtime/l4.js";
import { readData } from "./config.js";

function record(value: unknown, label: string): Record<string, any> {
  if (!value || typeof value !== "object" || Array.isArray(value))
    throw new Error(`Invalid ${label}`);
  return value as Record<string, any>;
}
export async function readDeployment(path: string, platform?: PlatformName) {
  const directory = dirname(resolve(path)),
    input = record(await readData(path), "deployment configuration");
  platform ??= input.platform as PlatformName;
  if (!["cloudflare", "vercel", "netlify", "esa", "edgeone"].includes(platform))
    throw new Error("Select a cloud platform for the business functions");
  for (const key of [
    "routes",
    "upstreams",
    "originDirectory",
    "origins",
    "publicHosts",
    "secLangFile",
    "setupRulesFile",
    "localRulesFile",
    "allowlistFile",
  ])
    if (Object.hasOwn(input, key))
      throw new Error(
        "Configure rules in rules/config.yml and routes/origins in origin/config.yml",
      );
  const rulesFile = resolve(directory, input.rulesFile ?? "rules/config.yml");
  const originsFile = await realpath(resolve(directory, input.originsFile ?? "origin/config.yml"));
  const ruleInput = record(await readData(rulesFile, 65536), "rules configuration");
  if (
    Object.keys(ruleInput).some(
      (key) => !["source", "setup", "local", "allowlist"].includes(key),
    ) ||
    typeof ruleInput.source !== "string" ||
    !ruleInput.source ||
    Object.values(ruleInput).some((value) => typeof value !== "string" || !value)
  )
    throw new Error(
      "Rules configuration requires a source and valid optional setup/local/allowlist files",
    );
  const originInput = record(await readData(originsFile, 65536), "origin configuration");
  if (
    Object.keys(originInput).some((key) => !["routes", "upstreams"].includes(key)) ||
    !Array.isArray(originInput.routes) ||
    !originInput.routes.length ||
    originInput.routes.length > 256
  )
    throw new Error("Origin configuration requires 1 to 256 routes");
  const upstreams: NonNullable<DeploymentConfig["upstreams"]> = Object.create(null);
  for (const [name, value] of Object.entries(
    originInput.upstreams === undefined ? {} : record(originInput.upstreams, "upstreams"),
  )) {
    const upstream = record(value, "named upstream");
    if (
      !/^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$/.test(name) ||
      Object.keys(upstream).some((key) => !["url", "binding", "key"].includes(key)) ||
      typeof upstream.url !== "string" ||
      typeof upstream.key !== "string" ||
      !/^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$/.test(upstream.key) ||
      (upstream.binding !== undefined && !/^[A-Z][A-Z0-9_]{0,63}$/.test(upstream.binding))
    )
      throw new Error("Invalid named upstream");
    const url = new URL(upstream.url);
    if (
      (url.protocol !== "https:" &&
        !(platform === "cloudflare" && upstream.binding && url.protocol === "http:")) ||
      url.username ||
      url.password ||
      url.pathname !== "/" ||
      url.search ||
      url.hash
    )
      throw new Error("Invalid upstream address");
    upstreams[name] = {
      url: url.origin,
      key: upstream.key,
      ...(upstream.binding ? { binding: upstream.binding } : {}),
    };
  }
  const originRoot = dirname(originsFile),
    platformRoot = resolve(originRoot, platform);
  const businesses: Record<
    string,
    { settings: OriginSettings; originFile: string; businessFile: string }
  > = Object.create(null);
  const origins: DeploymentConfig["origins"] = Object.create(null);
  const routes: Route[] = [],
    hosts = new Set<string>(),
    targets = new Map<string, string>(),
    patterns = new Set<string>();
  for (let index = 0; index < originInput.routes.length; index++) {
    const entry = record(originInput.routes[index], "origin route");
    if (
      Object.keys(entry).some(
        (key) =>
          ![
            "pattern",
            "origin",
            "key",
            "secrets",
            "upstreams",
            "methods",
            "authenticated",
            "body",
            "websocket",
            "browserCache",
            "grpc",
            "relay",
          ].includes(key),
      ) ||
      typeof entry.pattern !== "string" ||
      typeof entry.origin !== "string" ||
      (entry.grpc !== undefined && typeof entry.grpc !== "boolean")
    )
      throw new Error("An origin route requires pattern and origin");
    const slash = entry.pattern.indexOf("/");
    if (slash < 1 || patterns.has(entry.pattern))
      throw new Error("Invalid or duplicate origin route pattern");
    patterns.add(entry.pattern);
    const hostname = entry.pattern.slice(0, slash),
      host = new URL(`https://${hostname}`);
    if (
      host.host !== hostname ||
      host.pathname !== "/" ||
      host.username ||
      host.password ||
      host.search ||
      host.hash ||
      hostname.includes("*")
    )
      throw new Error("Route patterns require an exact public hostname followed by a path");
    const prefix = entry.pattern.endsWith("*"),
      routePath = entry.pattern.slice(slash, prefix ? -1 : undefined);
    if (!routePath || routePath.includes("*") || canonicalPath(routePath) !== routePath)
      throw new Error("Only a trailing route wildcard is supported");
    hosts.add(hostname);
    const key =
      entry.key ?? (entry.origin.startsWith("function:") ? entry.origin.slice(9) : undefined);
    if (typeof key !== "string" || !/^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$/.test(key))
      throw new Error("Select a private key identifier for each origin");
    const targetKey = JSON.stringify([
      entry.origin,
      key,
      entry.relay,
      entry.secrets,
      entry.upstreams,
    ]);
    let name = targets.get(targetKey);
    if (!name) {
      let settings: OriginSettings,
        origin = "",
        businessFile = "";
      if (entry.origin.startsWith("function:")) {
        name = entry.origin.slice("function:".length);
        if (!/^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$/.test(name))
          throw new Error("A valid business name is required after function:");
        if (Object.hasOwn(businesses, name) || entry.relay !== undefined)
          throw new Error("Duplicate or conflicting business origin");
        const actualPlatform = await realpath(platformRoot);
        if (relative(originRoot, actualPlatform) !== platform)
          throw new Error("Cross-platform origin path is forbidden");
        const businessRoot = await realpath(resolve(actualPlatform, name));
        if (relative(actualPlatform, businessRoot) !== name)
          throw new Error("Business directory must remain within its platform");
        businessFile = await realpath(resolve(businessRoot, "index.js"));
        if (dirname(businessFile) !== businessRoot)
          throw new Error("Business entry must remain in its business directory");
        origin = `https://${name.toLowerCase()}.origin.internal`;
        settings = { platform, mode: "function" };
        if (entry.secrets !== undefined) {
          if (typeof entry.secrets !== "string")
            throw new Error("Select a private business secrets file");
          const secretRoot = await realpath(resolve(directory, "secret"));
          const file = await realpath(resolve(directory, entry.secrets)),
            rel = relative(secretRoot, file);
          if (rel.startsWith("..") || isAbsolute(rel))
            throw new Error("Business secrets must remain inside secret/");
          settings.secretsFile = file;
        }
        if (entry.upstreams !== undefined) {
          if (
            !Array.isArray(entry.upstreams) ||
            entry.upstreams.some(
              (name: unknown) => typeof name !== "string" || !Object.hasOwn(upstreams, name),
            )
          )
            throw new Error("Select configured upstream names for a business function");
          settings.upstreams = [...new Set<string>(entry.upstreams)];
        }
      } else {
        if (entry.secrets !== undefined || entry.upstreams !== undefined)
          throw new Error("Business secrets and upstream lists apply only to function origins");
        const address = new URL(entry.origin);
        const grpcLoopback =
          entry.grpc === true &&
          address.protocol === "http:" &&
          ["127.0.0.1", "[::1]"].includes(address.hostname);
        if (
          (address.protocol !== "https:" && !grpcLoopback) ||
          address.username ||
          address.password ||
          address.hash
        )
          throw new Error("Origin address must use HTTPS; gRPC may use explicit loopback h2c");
        if (grpcLoopback && input.allowLoopbackHttp !== true)
          throw new Error("Loopback gRPC h2c requires allowLoopbackHttp: true");
        name = `origin${index}`;
        while (
          Object.hasOwn(businesses, name) ||
          originInput.routes.some((item: any) => item?.origin === `function:${name}`)
        )
          name += "_";
        if (entry.relay !== undefined) {
          const relay = record(entry.relay, "relay keys");
          if (
            Object.keys(relay).some(
              (key) => !["publicKeyFile", "authenticationKeyFile"].includes(key),
            )
          )
            throw new Error("Unknown relay key option");
          const secretRoot = await realpath(resolve(directory, "secret")),
            keys: Record<string, string> = {};
          for (const field of ["publicKeyFile", "authenticationKeyFile"]) {
            if (typeof relay[field] !== "string") throw new Error("Relay key file is required");
            const file = await realpath(resolve(directory, relay[field])),
              rel = relative(secretRoot, file);
            if (rel.startsWith("..") || isAbsolute(rel))
              throw new Error("Relay keys must reside in the project secret directory");
            keys[field] = file;
          }
          origin = `https://${name}.origin.internal`;
          settings = {
            platform,
            mode: "relay",
            endpoint: address.href,
            publicKeyFile: keys.publicKeyFile!,
            authenticationKeyFile: keys.authenticationKeyFile!,
          };
        } else {
          if (address.pathname !== "/" || address.search)
            throw new Error("Proxy origin must be an exact HTTPS origin (IP, hostname or CNAME)");
          origin = address.origin;
          settings = { platform, mode: "proxy", url: origin };
        }
      }
      businesses[name] = { settings, originFile: originsFile, businessFile };
      origins[name] = { origin, allowedOrigins: [origin], key };
      targets.set(targetKey, name);
    }
    routes.push({
      host: hostname,
      path: routePath,
      prefix,
      business: name,
      methods: entry.methods ?? ["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
      authenticated: entry.authenticated ?? false,
      body: entry.body ?? "text",
      ...(entry.websocket === undefined ? {} : { websocket: entry.websocket }),
      ...(entry.grpc === undefined ? {} : { grpc: entry.grpc }),
      ...(entry.browserCache === undefined ? {} : { browserCache: entry.browserCache }),
    });
  }
  const rulePath = (key: string) =>
    ruleInput[key] === undefined ? undefined : resolve(dirname(rulesFile), ruleInput[key]);
  const config = validateDeploymentConfig({
    ...input,
    platform,
    rulesFile,
    originsFile,
    origins,
    upstreams,
    publicHosts: [...hosts],
    routes,
    secLangFile: rulePath("source"),
    setupRulesFile: rulePath("setup"),
    localRulesFile: rulePath("local"),
    allowlistFile: rulePath("allowlist"),
  });
  if (config.l4Forwarders) validateL4ForwardRules(config.l4Forwarders);
  if (config.l4Limits) resolveL4ResourceLimits(config.l4Limits);
  config.secretFile = resolve(directory, config.secretFile);
  if (config.responses) config.responses.directory = resolve(directory, config.responses.directory);
  return { config, businesses, originRoot, platformRoot };
}
export async function readBusinessFunction(path: string): Promise<BusinessFunction> {
  const module = await import(pathToFileURL(path).href),
    business = module.default;
  if (!business || typeof business.fetch !== "function")
    throw new Error("Business origin must export a fetch function");
  return business;
}
export { readCredentials, readData } from "./config.js";
export { readResponsePages } from "./responses.js";
