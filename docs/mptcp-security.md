# MPTCP threat-model boundary and validation guide

EdgeAegis is an HTTP/SecLang application-layer firewall, **not an MPTCP packet filter or a Linux-kernel vulnerability patch**. Do not claim that a successful EdgeAegis CI run, CRS block, or ordinary HTTP request demonstrates that the Linux kernel is protected from malformed Multipath TCP (MPTCP) options.

## What is and is not inspected

- EdgeAegis inspects the HTTP request after the ingress/OS has handled the transport and delivered an HTTP message. Its Node adapter uses `node:http`; the hosted platform adapters likewise receive an HTTP request rather than raw TCP segments.
- A malicious **HTTP payload** arriving over a working TCP or MPTCP transport can be inspected by the existing HTTP rules, subject to the deployment's routing and inspection configuration.
- Malformed MPTCP options, DSS mappings, MP_JOIN packets, subflow state races, kernel resource exhaustion and similar transport-layer inputs reach the kernel/network stack **before** EdgeAegis. SecLang rules cannot safely parse or block those packets.
- Relevant Linux issues include CVE-2026-80586 (unexpected DSS option sizes), CVE-2026-97523 (scheduler/socket race), and CVE-2026-97524 (subflow/receive-path deadlock). Apply relevant vendor kernel fixes; do not substitute WAF rules for those fixes.

## Verification checklist for the actual ingress host

Run these commands **on each Linux host that terminates or handles MPTCP** (including an upstream load balancer), not just inside a container or a CI runner:

```sh
uname -r
if [ -r /proc/sys/net/mptcp/enabled ]; then
  cat /proc/sys/net/mptcp/enabled
else
  echo "MPTCP setting unavailable in this host / network namespace"
fi
sysctl net.mptcp.enabled 2>/dev/null || true
```

Record the kernel build, vendor security advisory/patch status, kernel configuration, and whether MPTCP is enabled or used. A zero sysctl value may prevent new MPTCP connections in that network namespace, but it does **not** by itself prove that the kernel is fixed, or that every host/namespace has the same setting. A missing sysctl does not prove the production ingress is safe.

If MPTCP is not required, consider disabling it under the OS/vendor's supported configuration while arranging a kernel update. Verify the change in every relevant namespace and after reboot. Never disable a production transport feature without understanding its impact.

## Separate transport testing from HTTP-WAF testing

1. Run `npm run test:security` and `npm run test:crs` from a source checkout to exercise EdgeAegis's HTTP boundary and CRS logic. These tests **do not** test the Linux kernel's MPTCP option parser.
2. In an **authorized isolated staging environment**, verify that the ingress is actually negotiating MPTCP, not falling back to TCP. Confirm this with Linux MPTCP counters/socket diagnostics and a packet capture of the handshake where permitted. A client tool's `--mptcp` option alone is not proof of negotiation.
3. Send benign and known blocked *HTTP-layer* test cases through that staging ingress; compare HTTP response status and origin logs. This can demonstrate that HTTP inspection still applies when traffic uses MPTCP. It cannot demonstrate mitigation of a kernel CVE.
4. Confirm kernel remediation against the applicable vendor advisory and kernel package; use vendor tests or vetted kernel regression tests in an isolated, disposable test VM. **Do not send malformed or crash-triggering MPTCP packets at production hosts.**

A correct security report must state two separate outcomes:

| Claim | Required evidence |
| --- | --- |
| EdgeAegis blocks a specified HTTP attack over an MPTCP transport | Confirmed MPTCP negotiation, test request, WAF block response, and no protected-origin request |
| The kernel is not vulnerable to a specified MPTCP CVE | Vendor fixed-kernel build/patch status and appropriate isolated kernel regression evidence |

**Never describe an EdgeAegis HTTP block as proof that an MPTCP kernel vulnerability is blocked.**
