# EdgeAegis

A portable, first-party SecLang firewall. Load and execute OWASP CRS source directly on Cloudflare Workers, Vercel, Netlify, Alibaba Cloud ESA, Tencent EdgeOne, or Node.js/VPS. The parser, transaction state and execution engine are shared across all adapters. No ModSecurity dependency, rule converter or legacy IR.

[![npm](https://img.shields.io/npm/v/edgeaegis)](https://www.npmjs.com/package/edgeaegis)
[![CI](https://github.com/jsw-teams/edgeaegis/actions/workflows/ci.yml/badge.svg)](https://github.com/jsw-teams/edgeaegis/actions/workflows/ci.yml)

[中文说明](#中文说明) · [Agent contributions and security reports](#agent-contributions-and-security-reports)

![Real VM terminal: configure multiple origins and keys, run curl, block SQL injection before the origin, recover after the temporary ban](https://raw.githubusercontent.com/jsw-teams/edgeaegis/main/tools/demo/edgeaegis-routing.3d240e2bb6009766.gif)

The GIF records an actual isolated Linux desktop and terminal. It shows two business functions, three authenticated HTTPS origins, real `curl -i` responses, an unchanged origin access log after a CRS block, and native temporary protection. All addresses, certificates and keys belong to the disposable lab. The recording shortens the ban TTL to five seconds; the default is 300 seconds. Reproduction sources are in `tools/demo/`.

## Install

Node.js 22.13 or newer is required. Initialize a deployment project, edit its routing and private credentials, then start it:

```sh
npm exec --package=edgeaegis -- edgeaegis init my-firewall
cd my-firewall
npm install
npm run deploy:local
```

From a source checkout, use `npm install` followed by the same platform commands. Dependencies and compiled output live under `tools/`. Installation generates random credentials only when the credentials file does not exist; initialization preserves existing operator files. Ordinary settings and secrets are files, without runtime Secret environment bindings or `SKIP_DEPENDENCY_INSTALL`.

| Location | Purpose |
| --- | --- |
| `config.yml` | Runtime, platform, listener and resource limits |
| `rules/config.yml` | Rule source, setup policy, local rules and allowlist |
| `origin/config.yml` | All hostname/path routing, origins and optional named upstreams |
| `origin/<platform>/<business>/index.js` | Same-runtime business functions |
| `secret/credentials.yml` | Independent origin keys and optional client/ingress credentials |
| `secret/<business>.yml` | Optional private business settings |
| `respond/` | Operator-controlled HTML/JSON rejection responses |
| `scr/`, `tools/` | Engine source, build tools, tests and recordings |

The Node listener defaults to loopback. Put your TLS ingress in front of it and use a hostname configured in `origin/config.yml`.

For production over SSH, install a supervised **background service**, so the firewall survives a closed terminal:

```sh
npx edgeaegis service install config.yml --system
npx edgeaegis service status config.yml --system
```

Run the system-service installation with the required administrative account on Linux/systemd. It installs and enables a uniquely named unit with automatic restart and journal logging; no service is started during npm installation. Omit `--system` for a systemd user service; persistent operation after logout then requires that account's existing linger policy. `service start` and `service stop` manage the same unit. `start:local` and `deploy:local` stay foreground development commands.

## Configure routes and origins

Keep **all origins in one file**, `origin/config.yml`. A route combines a public hostname/path pattern with a destination. Paths are preserved. Exact routes take precedence, followed by the longest matching prefix. A single trailing `*` is supported; host wildcards and ambiguous paths fail validation.

```yaml
routes:
  - pattern: api.example/orders/*
    origin: https://192.0.2.10
    key: orders-vps
    methods: [GET, POST]
  - pattern: api.example/search/*
    origin: https://lb.search.example
    key: search-lb
  - pattern: api.example/external/*
    origin: https://other-account-function.example
    key: external-service
  - pattern: api.example/shop/*
    origin: function:shop
  - pattern: status.example/*
    origin: function:status
```

IP addresses, IPv6 addresses such as `https://[2001:db8::1]:8443`, load-balancer CNAMEs and external cloud functions use the same HTTPS origin form. TLS certificate verification stays enabled. An IP origin needs a certificate valid for that IP; use a hostname when its certificate identifies a hostname. Proxy destinations must be exact HTTPS origins without credentials, query strings or paths. The engine never chooses an origin from request parameters or follows origin redirects.

Each proxy route names a key in **private** `secret/credentials.yml`:

```yaml
originKeys:
  orders-vps: REPLACE_WITH_AN_INDEPENDENT_RANDOM_SECRET
  search-lb: REPLACE_WITH_ANOTHER_INDEPENDENT_RANDOM_SECRET
  external-service: REPLACE_WITH_A_THIRD_INDEPENDENT_RANDOM_SECRET
  shop: REPLACE_WITH_A_FOURTH_INDEPENDENT_RANDOM_SECRET
  status: REPLACE_WITH_A_FIFTH_INDEPENDENT_RANDOM_SECRET
```

Generate separate random values of at least 32 characters, for example with `node -e "console.log(require('node:crypto').randomBytes(32).toString('base64url'))"`. The placeholders above are not usable deployment credentials. Missing references and duplicate key values fail validation. To intentionally share a trust group, explicitly reference the same key identifier. There is no global origin-token fallback.

Incoming authentication/forwarding headers are sanitized. The engine adds the selected `x-shield-origin-auth` credential. **Every external origin must verify its own key before serving traffic**, and should restrict direct access where possible. A stolen key for one independently keyed service does not authenticate to another. Credentials and compiled private bundles belong in a private deployment repository; never publish them as static files or npm package contents.

`function:shop` is configuration, not a built-in service name. Add any number of configured businesses, for example `origin/cloudflare/shop/index.js` and `origin/cloudflare/status/index.js`:

```js
export default {
  async fetch(request, env, context) {
    return Response.json({ business: "shop" });
  }
};
```

Only the selected platform's referenced businesses enter the build. Cross-platform imports are rejected. Functions are internal modules with no independently exposed URL: full request inspection runs before their `fetch`, and response inspection runs afterward. The generated deployment exports only the firewall entry point. Never copy business modules into a public assets directory or add a separate unprotected platform route.

For a function that delegates to several upstreams, add `upstreams: [primary, secondary]` and `secrets: secret/shop.yml` to each of its routes. Define those named upstreams in the same origin file:

```yaml
upstreams:
  primary: { url: https://primary.example, key: primary-key }
  secondary: { url: https://secondary.example, key: secondary-key }
```

The function receives `context.upstreams`, the selected `context.originKeys` and its parsed `context.secrets`. It must authenticate its delegated calls with each upstream's key. Cloudflare functions may additionally select an explicitly configured platform binding. Different businesses may use different private files; no business name is hardcoded in the engine.

For encrypted relay transport, set a proxy route's `origin` to its HTTPS relay endpoint and add `relay: { publicKeyFile: secret/relay/public.jwk, authenticationKeyFile: secret/relay/authentication.key }`. In a source checkout, `npm run relay:init` creates the key files; `edgeaegis serve-relay secret/relay-server.yml` starts the loopback Node endpoint. Set its `key` to the matching origin key identifier. The server private key stays on the origin. The relay uses ECDH/HKDF, AES-GCM, HMAC, request/time binding and persistent SQLite replay rejection. It preserves binary bodies and multiple cookies. This is an application transport protocol over HTTPS.

## Deploy

[![Deploy to Cloudflare](https://deploy.workers.cloudflare.com/button)](https://deploy.workers.cloudflare.com/?url=https://github.com/jsw-teams/edgeaegis)
[![Deploy to Vercel](https://vercel.com/button)](https://vercel.com/new/clone?repository-url=https%3A%2F%2Fgithub.com%2Fjsw-teams%2Fedgeaegis)
[![Deploy to Netlify](https://www.netlify.com/img/deploy/button.svg)](https://app.netlify.com/start/deploy?repository=https://github.com/jsw-teams/edgeaegis)
[![Deploy to EdgeOne](https://cdnstatic.tencentcs.com/edgeone/pages/deploy.svg)](https://edgeone.ai/pages/new?repository-url=https%3A%2F%2Fgithub.com%2Fjsw-teams%2Fedgeaegis&install-command=npm%20install&build-command=npm%20run%20build%20%26%26%20node%20tools%2Fhosting-build.mjs%20edgeone&output-directory=tools%2F.build%2Fedgeone%2Fdeploy%2Fpublic)
[![Import into ESA](https://img.shields.io/badge/ESA-Import_repository-ff6a00)](https://esa.console.aliyun.com/edge/pages/creation)

Buttons open new-project setup. Configure your hostname, origin keys and platform account before directing traffic there. Cloudflare, Vercel, Netlify and EdgeOne support repository imports; ESA opens its official import screen and requires choosing the repository. Existing deployments should update through their existing repository integration. These buttons do not modify an existing Worker or provision a trusted ingress automatically.

```sh
npm run build:cloudflare
npm run start:cloudflare
npm run deploy:cloudflare
# Also: vercel, netlify, esa, edgeone, local
```

Install and authenticate the selected provider CLI in the deployment project: `wrangler`, `vercel`, `netlify-cli`, `esa-cli` or `edgeone`. Local start/deploy runs the Node server. Cloud commands build the selected platform and invoke its CLI from the private deployment output. To inspect the command without deploying: `edgeaegis deploy vercel config.yml --plan`.

Private bundles live under `tools/.build/<platform>/deploy/`. Repository imports additionally generate provider-owned function output; static publish directories stay empty. Cloudflare uses only a Worker, with static WASM modules, workers.dev and previews disabled by default. The other adapters use the same engine and WASM primitives; provider payload/CPU/memory limits still apply.

**Trusted transport metadata is required.** Cloudflare reads platform metadata; Node reads its connection. Fetch-only adapters require original protocol/IP information signed by a trusted ingress using the optional `ingressKey` in `secret/credentials.yml`. Missing or forged metadata returns 503. Use `createIngressForwarder` from `edgeaegis/ingress` in an existing trusted Node/Worker ingress, passing the actual protocol/IP and available raw target. Signatures bind the method, destination, original URL, metadata and timestamp. Client-supplied forwarding headers are not trusted. A platform setup screen alone does not establish this trust.

## Native rules and updates

`rules/config.yml` selects rule files, separately from origin configuration:

```yaml
source: seclang-bundle.json
setup: setup.conf
local: local.conf
allowlist: allowlist.yml
```

Setup runs before the complete upstream corpus; local rules run afterward. The engine supports CRS collections/selectors/exclusions/counting, PCRE2, transformation chains, multiMatch, macros, TX, capture, chain, phases 1–5, default actions, setvar/initcol, skip/skipAfter, ctl, anomaly scoring and matched-rule events. It parses URL-encoded, JSON, XML/XPath and multipart bodies, and inspects actual response headers/bodies. Phase 5 runs after disruption. Phase indexes preserve source order and do not cache security decisions.

PCRE2 and libinjection are matching primitives, not third-party WAF engines. Their sources, hashes and licenses are recorded under `scr/seclang/vendor/`. Unknown semantics, missing data/Includes, duplicate IDs and incomplete compilation fail loading. Compatibility is verified against the entire CRS corpus and executable regressions; Apache server configuration and external-script execution are outside the verified directive scope.

**CRS tracks the latest stable release**, rather than a fixed tag or commit. `rules/seclang-upstreams.json` uses `ref: "latest"`. Multiple native SecLang sources can be added there. The bundled snapshot records its resolved source commit, Git blob hashes and SHA-256 provenance; these are verification records, not update pins. GitHub Actions checks every six hours and replaces the snapshot only after complete compilation, execution, regression tests, audit and Worker build checks pass. User rules, allowlists and credentials are preserved. New unsupported upstream semantics cause a visible failure requiring an engine fix, never rule removal.

```sh
edgeaegis sync --registry rules/seclang-upstreams.json --output rules/seclang-bundle.json
npm run test:crs
```

Native data-file rules execute directly, for example `@ipMatchFromFile threat-networks.txt` or `@pmFromFile threat-phrases.txt` in an operator rule. Files resolve relative to their rule source; missing files or malformed networks fail compilation. Downloading intelligence alone does not enable blocking: an enabled native rule must actually reference and match it. No conversion layer is needed. Third-party sources require their own licenses and full compatibility checks.

The default setup enforces a per-IP burst limit of 120 requests, refilling 20 per second, and a 300-second temporary ban after three confirmed attacks in 60 seconds. Bans expire without being prolonged by innocent blocked requests. Unknown payloads are also subject to burst/anomaly behavior protection. `rules/emergency.conf` contains a tested native virtual patch for CVE-2025-29927. Operators control thresholds, rules, TTLs and exemptions. Collection state is bounded and belongs to the engine instance; a Worker-only deployment does not pretend to maintain global cross-region counters.

## Exemptions, responses and caching

`rules/allowlist.yml` is entirely operator-controlled. It supports global, rule-ID, path/prefix, method, identity and IP/CIDR exemptions with optional expiry. Defaults contain no exemptions. Example: `skip: [rules]`, `ruleIds: ['942100']`, `path: /search`, `cidrs: [192.0.2.0/24]`. Omitting rule IDs or using `['*']` exempts all rules. Route/identity boundaries and byte limits still apply.

Customize `respond/403.html` and `respond/403.json`; other status files use the same convention. Full EdgePress-built HTML is supported. Responses retain their HTTP status and HEAD behavior and never insert untrusted request content. Configure the response CSP in `config.yml`.

For public GET/HEAD content, add `browserCache: { maxAgeSeconds: 120 }` to a route. The origin must also explicitly return `Cache-Control: public, max-age=N`; the shorter lifetime wins. The engine emits private browser freshness, varies on credentials, and declines caching for authentication, cookies, private/error responses or WebSockets. Browser reuse can avoid a network request and function invocation. Every request that reaches the engine still executes the complete rules. Origin-side/Worker-side caches can reduce origin work but do not remove an already-arrived function invocation. Serve genuinely public static assets through platform static hosting; do not put protected business data or private bundles there.

## Limits and verification

The 8 MB configuration-file read limit is separate from uploads. `limits.maxBodyBytes` checks actual streamed bytes, defaults to 8 MiB and is configurable up to 16 MiB. Complete CRS tests cover multipart uploads above 2 MiB and malicious neighboring fields. Individual transformed values, PCRE2 steps/depth/memory, concurrency and collections have enforced resource bounds; exhaustion rejects rather than becoming a non-match. Compressed request bodies and raw gRPC frames are not supported ingress forms. Explicit WebSocket routes inspect the real handshake and 101 headers while preserving native binary frames; opaque upgraded messages are outside SecLang inspection.

```sh
npm run check
npm run cloudflare:dry-run
npm run audit
```

CI covers Windows/Linux and Node 22/24, full CRS PL1–4, five built adapters, real workerd, PCRE2/capture/chain/TX/ctl, normal traffic, SQLi/XSS/LFI/RCE, response WebShell signatures, uploads, origin isolation, replay rejection, TTL and isolated npm installation. The current verified snapshot contains 693 SecRule and 8 SecAction instructions, with zero unsupported rules. Local adapter verification is not a claim of deployment to five live accounts.

Releases use `YYYY.M.monthly-release-number`, starting at `2026.10.1`, with tags such as `v2026.10.1`, matching EdgePress. Earlier naming experiments are test history. GitHub Actions `publish.yml` verifies and publishes the same hashed npm archive through Trusted Publishing/OIDC, checks public installation and the `latest` tag, and requires no stored npm token.


## MPTCP transport security boundary

EdgeAegis inspects HTTP requests and responses **after** a trusted network/HTTP ingress has received the connection. MPTCP is negotiated in the Linux TCP stack before SecLang can inspect a request. **EdgeAegis is not a mitigation for Linux MPTCP kernel CVEs**, including malformed DSS options, MP_JOIN state defects, or denial-of-service in the kernel's receive path. Patch the affected kernel or disable MPTCP at the system/network boundary where required.

The regression test `tools/tests/mptcp-transport.test.ts` uses an isolated loopback MPTCP listener/client, forwards their HTTP bytes to the Node adapter, and confirms that a harmless request passes while a rule-matching request receives HTTP 403 **without reaching the origin**. It probes `MPTCP_INFO` on both endpoints; unsupported MPTCP is explicitly reported as **skipped**, not passed. No exploit packets or public targets are involved. This verifies *application-layer enforcement over negotiated MPTCP transport*, **not** protection against MPTCP kernel vulnerabilities.

## Agent contributions and security reports

Vibe Coding and AI-assisted contributions are welcome. Humans remain responsible for the submitted code and evidence. Read [AGENTS.md](AGENTS.md), explain the change, and run the relevant regression tests **before uploading a branch or PR**. Engine, parser, rule or adapter changes require `npm run check`, `npm run test:crs`, `npm run cloudflare:dry-run` and `npm run audit`. Include commands, runtime, results and any unrun checks; never substitute generated output for an actual run or remove rules to improve results. Documentation-only changes require checking the documented commands, links and examples; identify checks that do not apply.

Agents may submit security reports, subject to the same evidence standard. Use [GitHub private vulnerability reporting](https://github.com/jsw-teams/edgeaegis/security/advisories/new) for sensitive findings. If private reporting is unavailable, request a private contact through an issue without exploit details. Do not publish live tokens, private origin addresses, customer payloads or a working exploit against an unfixed live deployment. Test only a local/disposable environment or an explicitly authorized target.

Each report must state the affected version/commit and configuration, prerequisites and trust boundary, a minimal sanitized reproducer, expected versus actual behavior, concrete impact, and exact verification commands/results. Distinguish reproduced findings from hypotheses and include a regression test or explain why one cannot be supplied. Disclose AI assistance and any uncertainty; consolidate duplicates. Maintainers validate reports before assigning severity or publishing an advisory. A report does not authorize production changes or release publication.

## 中文说明

EdgeAegis 是自研 SecLang 防火墙，直接加载并执行 OWASP CRS；Cloudflare Workers、Vercel、Netlify、ESA、EdgeOne 与 Node.js/VPS 共用引擎。规则配置位于 `rules/config.yml`，所有主机名、路径、VPS IP、负载均衡 CNAME、外部云函数和同一运行时业务函数统一配置在 `origin/config.yml`。每个外部服务引用自己的 `secret/credentials.yml` 密钥；实际凭据只放私有部署库，不上传公共仓库或 npm。

```sh
npm exec --package=edgeaegis -- edgeaegis init my-firewall
cd my-firewall
npm install
# 编辑 config.yml、rules/config.yml、origin/config.yml 和 secret/credentials.yml
npm run deploy:cloudflare
# 其他目标：deploy:vercel、deploy:netlify、deploy:esa、deploy:edgeone、deploy:local
```

通过 SSH 在 Linux/VPS 长期运行时，使用 `npx edgeaegis service install config.yml --system` 安装 systemd 后台服务，使用 `npx edgeaegis service status config.yml --system` 查看状态。需要相应管理权限；`deploy:local` 是前台开发命令。安装 npm 包不会自动开启后台服务。

上方 GIF 来自真实隔离虚拟机终端，演示多个业务、独立回源密钥、真实 curl 响应、完整 CRS 拦截与临时封禁到期恢复。全部示例地址和密钥属于一次性实验环境。CRS 定时跟踪最新稳定版，完整验证后才更新；来源提交与哈希用于核验，不作为永久锁定。白名单和自定义拒绝页面始终由部署者控制。

欢迎 Vibe Coding、AI 辅助开发及 Agent 安全报告。提交者须先阅读 [AGENTS.md](AGENTS.md)，**测试后再上传代码**，注明实际执行的命令、结果和未验证项。安全报告须提供受影响版本、前提、脱敏复现、预期与实际行为、影响及验证证据，区分已复现问题和推测；敏感漏洞使用上述 GitHub 私密报告入口。不得在公共报告中包含真实凭据、私有源站或用户数据，也不得把提交报告当作攻击生产环境的授权。

Licensed under [Apache-2.0](LICENSE); third-party notices are in [NOTICE](NOTICE).
