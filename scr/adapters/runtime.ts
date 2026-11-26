import type { DeploymentConfig, ProjectCredentials } from "../config.js";
import { originCredential } from "../config.js";
import { digest, type Fetch, type TrustedContext } from "../core/types.js";
import type { ErrorPages } from "../runtime/error-pages.js";
import { type AllowlistEntry, createShield } from "../runtime/index.js";
import { createInjectionDetectors, createPCRE2Backend } from "../seclang/index.js";

export interface PortableOptions {
  config: DeploymentConfig;
  credentials: ProjectCredentials;
  source: string;
  files: Record<string, string>;
  pcre2: WebAssembly.Module | BufferSource;
  libinjection: WebAssembly.Module | BufferSource;
  allowlist: AllowlistEntry[];
  errorPages?: ErrorPages;
  policyVersion?: string;
  lazyRegex?: boolean;
  originFetches: Record<string, Fetch>;
}
/** Every deployment uses this compiler, byte parser, transaction and response inspector. */
export async function createPortableRuntime(options: PortableOptions) {
  const engine = await createShield({
    tenant: options.config.tenant,
    service: options.config.service,
    publicHosts: options.config.publicHosts,
    routes: options.config.routes,
    secLang: options.source,
    secLangOptions: {
      files: options.files,
      ...(options.lazyRegex ? { lazyRegex: true } : {}),
      regexBackend: await createPCRE2Backend(options.pcre2),
      detectors: await createInjectionDetectors(options.libinjection),
    },
    allowlist: options.allowlist,
    ...(options.policyVersion ? { policyVersion: options.policyVersion } : {}),
    ...(options.errorPages ? { errorPages: options.errorPages } : {}),
    ...(options.config.limits ? { limits: options.config.limits } : {}),
    ...(options.config.maxConcurrentRequests
      ? { maxConcurrentRequests: options.config.maxConcurrentRequests }
      : {}),
    origins: Object.fromEntries(
      Object.entries(options.config.origins).map(([name, origin]) => {
        const fetch = options.originFetches[name];
        if (!fetch) throw new Error("Missing business transport");
        return [
          name,
          { ...origin, originToken: originCredential(options.credentials, origin.key), fetch },
        ];
      }),
    ),
  });
  const clientHash = options.credentials.clientToken
    ? await digest(options.credentials.clientToken)
    : undefined;
  return {
    engine,
    async handle(
      request: Request,
      transport: Omit<TrustedContext, "tenant">,
      rawTarget?: string,
      originFetches?: Record<string, Fetch>,
    ) {
      // Headers are never promoted to identity by the shared engine.
      const token = request.headers.get("authorization");
      const identity =
        clientHash && token?.startsWith("Bearer ") && (await digest(token.slice(7))) === clientHash
          ? "configured-api-client"
          : undefined;
      const context = {
        ...transport,
        tenant: options.config.tenant,
        ...(identity ? { identity } : {}),
      };
      return engine.handle(request, context, rawTarget, originFetches ? { originFetches } : {});
    },
  };
}
