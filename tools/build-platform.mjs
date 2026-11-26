import { mkdir, readFile, writeFile } from "node:fs/promises";
import { dirname, isAbsolute, join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { build } from "esbuild";
import { readCredentials, readData } from "./.build/scr/cli/config.js";
import { readDeployment } from "./.build/scr/cli/deployment.js";
import { readResponsePages } from "./.build/scr/cli/responses.js";
import { originCredential } from "./.build/scr/config.js";
import { digest, stableJson } from "./.build/scr/core/types.js";
import { compactSecLangFiles, compileSecLang } from "./.build/scr/seclang/index.js";
import { loadSecLangDeployment } from "./.build/scr/seclang/node.js";

export { compactSecLangFiles };

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
export async function originTransportsModule(businesses, config, credentials, contexts = {}) {
  const rel = (path) => JSON.stringify(path.replaceAll("\\", "/"));
  const imports = [],
    transports = [];
  for (const [name, { settings, businessFile }] of Object.entries(businesses)) {
    const id = imports.length;
    if (settings.mode === "function") {
      imports.push(`import business${id} from ${rel(businessFile)};`);
      const upstreams = Object.fromEntries(
        (settings.upstreams ?? []).map((name) => [name, config.upstreams[name]]),
      );
      const keys = new Set([
        config.origins[name].key,
        ...Object.values(upstreams).map((upstream) => upstream.key),
      ]);
      const context = contexts[name] ?? {
        secrets: settings.secretsFile ? await readData(settings.secretsFile, 65536) : {},
        upstreams,
        originKeys: Object.fromEntries(
          [...keys].map((key) => [key, originCredential(credentials, key)]),
        ),
      };
      imports.push(`const context${id}=${JSON.stringify(context)};`);
      transports.push(
        `${JSON.stringify(name)}:(input,init)=>Promise.resolve(business${id}.fetch(new Request(input,init),env,context${id}))`,
      );
    } else if (settings.mode === "proxy")
      transports.push(`${JSON.stringify(name)}:(input,init)=>fetch(input,init)`);
    else {
      imports.push(
        `import {createRelayTransport as createRelay${id}}from ${rel(resolve(root, "tools/.build/scr/origin/relay.js"))};const transport${id}=createRelay${id}(${JSON.stringify({ endpoint: settings.endpoint, serverPublicKey: await readData(settings.publicKeyFile, 16384), authenticationKey: await readData(settings.authenticationKeyFile, 4096), maxBytes: config.limits?.maxBodyBytes ?? 8388608 })});`,
      );
      transports.push(
        `${JSON.stringify(name)}:async(input,init)=>(await transport${id})(input,init)`,
      );
    }
  }
  return `${imports.join("\n")}\nexport default function createOriginFetches(env={}){return {${transports.join(",")}};}`;
}
export async function buildPlatform(
  platform,
  configFile = resolve("config.yml"),
  outputDirectory = resolve(dirname(configFile), "tools/.build", platform),
) {
  if (!["cloudflare", "vercel", "netlify", "esa", "edgeone"].includes(platform))
    throw new Error("Unknown deployment platform");
  const { config, businesses, originRoot, platformRoot } = await readDeployment(
    configFile,
    platform,
  );
  const credentials = await readCredentials(config.secretFile),
    native = await loadSecLangDeployment(
      config.secLangFile,
      config.localRulesFile,
      config.setupRulesFile,
    );
  const program = compileSecLang(native.secLang, { ...native.secLangOptions, strict: true });
  program.dispose();
  const compactFiles = compactSecLangFiles(native.secLangOptions.files);
  const allowlist = config.allowlistFile ? await readData(config.allowlistFile) : [];
  const policyVersion = await digest(
    stableJson({
      source: native.secLang,
      files: compactFiles,
      phraseFiles: {},
      fileName: "main.conf",
      allowlist,
    }),
  );
  const data = {
    config,
    credentials,
    source: native.secLang,
    files: compactFiles,
    allowlist,
    policyVersion,
    errorPages: config.responses
      ? await readResponsePages(config.responses.directory, config.responses.contentSecurityPolicy)
      : {},
  };
  for (const origin of [...Object.values(config.origins), ...Object.values(config.upstreams ?? {})])
    originCredential(credentials, origin.key);
  // Only the selected platform's configured businesses are bundled.
  const directory = resolve(outputDirectory);
  await mkdir(directory, { recursive: true });
  const origin = await originTransportsModule(businesses, config, credentials);
  const wasm = [];
  for (const name of ["pcre2", "libinjection"])
    wasm.push(await readFile(resolve(root, "tools/.build/scr/seclang/vendor", `${name}.wasm`)));
  const wasmSource =
    platform === "cloudflare"
      ? `import PCRE2 from './pcre2.wasm';import INJECTION from './libinjection.wasm';export{PCRE2,INJECTION};`
      : `const decode=s=>Uint8Array.from(atob(s),c=>c.charCodeAt(0));export const PCRE2=decode('${wasm[0].toString("base64")}'),INJECTION=decode('${wasm[1].toString("base64")}');`;
  const allowed = platformRoot;
  const result = await build({
    entryPoints: [resolve(root, `tools/.build/scr/adapters/${platform}/worker.js`)],
    bundle: true,
    minifyWhitespace: true,
    minifySyntax: true,
    minifyIdentifiers: platform !== "edgeone",
    write: false,
    metafile: true,
    format: "esm",
    platform: "browser",
    target: "es2022",
    outdir: directory,
    sourcemap: false,
    logLevel: "silent",
    external: ["*.wasm"],
    plugins: [
      {
        name: "private-project-assets",
        setup(api) {
          api.onResolve({ filter: /^edgeaegis:/ }, (args) => ({
            path: args.path,
            namespace: "project",
          }));
          api.onLoad({ filter: /.*/, namespace: "project" }, (args) => ({
            contents:
              args.path === "edgeaegis:deployment"
                ? `export default JSON.parse(${JSON.stringify(JSON.stringify(data))});`
                : args.path === "edgeaegis:origin"
                  ? origin
                  : wasmSource,
            loader: "js",
            resolveDir: directory,
          }));
          // Reject even transitive imports of another platform's business files.
          api.onLoad({ filter: /.*/ }, (args) => {
            const inside = relative(originRoot, args.path);
            if (!inside.startsWith("..") && !isAbsolute(inside)) {
              const own = relative(allowed, args.path);
              if (own.startsWith("..") || isAbsolute(own))
                throw new Error("Cross-platform origin import is forbidden");
            }
            return undefined;
          });
        },
      },
    ],
  });
  for (const output of result.outputFiles)
    await writeFile(output.path, output.contents, { mode: 0o600 });
  if (platform === "cloudflare")
    for (let i = 0; i < wasm.length; i++)
      await writeFile(join(directory, `${i ? "libinjection" : "pcre2"}.wasm`), wasm[i]);
  if (Object.keys(result.metafile.inputs).some((path) => /secret\/relay\/private/.test(path)))
    throw new Error("Relay private key must not enter a cloud build");
  const deployDirectory = join(directory, "deploy");
  await mkdir(deployDirectory, { recursive: true });
  const code = result.outputFiles.find((file) => file.path.endsWith("worker.js")).contents;
  const name = `edgeaegis-${config.tenant}-${config.service}`
    .toLowerCase()
    .replace(/[^a-z0-9-]/g, "-")
    .slice(0, 63);
  const put = async (path, content) => {
    const file = join(deployDirectory, path);
    await mkdir(dirname(file), { recursive: true });
    await writeFile(file, content, { mode: 0o600 });
  };
  await put(
    "package.json",
    JSON.stringify({ private: true, type: "module", engines: { node: "24.x" } }),
  );
  if (platform === "cloudflare") {
    await put("worker.js", code);
    await put(
      "wrangler.json",
      JSON.stringify(
        {
          name,
          main: "worker.js",
          compatibility_date: "2026-10-01",
          workers_dev: false,
          preview_urls: false,
          routes: [],
          send_metrics: false,
          no_bundle: true,
          rules: [{ type: "CompiledWasm", globs: ["**/*.wasm"], fallthrough: false }],
        },
        null,
        2,
      ),
    );
    for (let i = 0; i < wasm.length; i++)
      await put(`${i ? "libinjection" : "pcre2"}.wasm`, wasm[i]);
  } else if (platform === "vercel") {
    await put("api/index.mjs", code);
    await put(
      "vercel.json",
      JSON.stringify(
        { version: 2, rewrites: [{ source: "/:path*", destination: "/api/index" }] },
        null,
        2,
      ),
    );
  } else if (platform === "netlify") {
    await put("edge-functions/edgeaegis.js", code);
    await mkdir(join(deployDirectory, "public"), { recursive: true });
    await put("netlify.toml", '[build]\npublish = "public"\nedge_functions = "edge-functions"\n');
  } else if (platform === "esa") {
    await put("worker.js", code);
    await put("esa.jsonc", JSON.stringify({ name, entry: "./worker.js" }, null, 2));
  } else
    await put(
      "edge-functions/[[default]].js",
      `${new TextDecoder().decode(code)}\nexport default onRequest;\n`,
    );
  return {
    directory,
    deployDirectory,
    entry: join(directory, "worker.js"),
    inputs: Object.keys(result.metafile.inputs),
    bytes: result.outputFiles.reduce((n, file) => n + file.contents.length, 0),
  };
}
if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const result = await buildPlatform(
    process.argv[2],
    process.argv[3] ? resolve(process.argv[3]) : undefined,
  );
  console.log(JSON.stringify({ directory: result.directory, bytes: result.bytes }));
}
