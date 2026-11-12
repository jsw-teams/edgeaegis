import { createSocket, type Socket as DatagramSocket, type RemoteInfo } from "node:dgram";
import { createConnection, createServer, isIP, type Server, type Socket } from "node:net";
import { totalmem } from "node:os";
import ipaddr from "ipaddr.js";

/** Explicit, fixed-target L4 forwarding. This layer cannot inspect HTTP or SecLang payloads. */
export interface L4ForwardRule {
  protocol: "tcp" | "udp";
  listen: { host: string; port: number };
  target: { host: string; port: number };
  /** Required source CIDRs; an empty allowlist is rejected. */
  allowSources: readonly string[];
  maxConnections?: number;
  idleTimeoutMs?: number;
}

export interface L4ResourceLimits {
  maxTcpConnections?: number;
  maxUdpSessions?: number;
  udpPendingBytes?: number;
}

export function resolveL4ResourceLimits(input: L4ResourceLimits = {}) {
  const keys = ["maxTcpConnections", "maxUdpSessions", "udpPendingBytes"];
  if (!input || typeof input !== "object" || Object.keys(input).some((key) => !keys.includes(key)))
    throw new Error("Invalid L4 resource limits");
  const memory = totalmem();
  const limits = {
    maxTcpConnections:
      input.maxTcpConnections ?? Math.min(32768, Math.max(2048, Math.floor(memory / 524288))),
    maxUdpSessions:
      input.maxUdpSessions ?? Math.min(65536, Math.max(4096, Math.floor(memory / 131072))),
    udpPendingBytes:
      input.udpPendingBytes ??
      Math.min(128 * 1024 * 1024, Math.max(8 * 1024 * 1024, Math.floor(memory / 64))),
  };
  if (
    !Number.isInteger(limits.maxTcpConnections) ||
    limits.maxTcpConnections < 1 ||
    limits.maxTcpConnections > 65536 ||
    !Number.isInteger(limits.maxUdpSessions) ||
    limits.maxUdpSessions < 1 ||
    limits.maxUdpSessions > 65536 ||
    !Number.isInteger(limits.udpPendingBytes) ||
    limits.udpPendingBytes < 1024 * 1024 ||
    limits.udpPendingBytes > 256 * 1024 * 1024
  )
    throw new Error("L4 resource limits exceed supported bounds");
  return limits;
}

function validPort(value: number): boolean {
  return Number.isInteger(value) && value >= 1 && value <= 65535;
}

function normalizeIp(value: string): string {
  const zoneFree = value.split("%")[0] ?? "";
  if (!isIP(zoneFree)) throw new Error("L4 listen/target addresses must be literal IPs");
  return ipaddr.process(zoneFree).toString();
}

function compileRule(input: L4ForwardRule) {
  if (!input || !["tcp", "udp"].includes(input.protocol))
    throw new Error("L4 protocol must be tcp or udp");
  if (
    Object.keys(input).some(
      (key) =>
        ![
          "protocol",
          "listen",
          "target",
          "allowSources",
          "maxConnections",
          "idleTimeoutMs",
        ].includes(key),
    ) ||
    !input.listen ||
    !input.target ||
    Object.keys(input.listen).some((key) => !["host", "port"].includes(key)) ||
    Object.keys(input.target).some((key) => !["host", "port"].includes(key))
  )
    throw new Error("Invalid L4 forwarding rule fields");
  const listenHost = normalizeIp(input.listen.host);
  const targetHost = normalizeIp(input.target.host);
  if (!validPort(input.listen.port) || !validPort(input.target.port))
    throw new Error("L4 ports must be between 1 and 65535");
  if (listenHost === targetHost && input.listen.port === input.target.port)
    throw new Error("L4 listener cannot forward to itself");
  if (!Array.isArray(input.allowSources) || input.allowSources.length === 0)
    throw new Error("L4 forwarding requires at least one source CIDR");
  const sources = input.allowSources.map((source) => {
    try {
      return ipaddr.parseCIDR(source);
    } catch {
      throw new Error("Invalid L4 source CIDR");
    }
  });
  const maxConnections =
    input.maxConnections ?? Math.min(16384, Math.max(1024, Math.floor(totalmem() / (1024 * 1024))));
  const idleTimeoutMs = input.idleTimeoutMs ?? 120000;
  if (!Number.isInteger(maxConnections) || maxConnections < 1 || maxConnections > 65536)
    throw new Error("L4 maxConnections must be between 1 and 65536");
  if (!Number.isInteger(idleTimeoutMs) || idleTimeoutMs < 1000 || idleTimeoutMs > 3600000)
    throw new Error("L4 idleTimeoutMs must be between 1000 and 3600000");
  return { ...input, listenHost, targetHost, sources, maxConnections, idleTimeoutMs };
}

export function validateL4ForwardRules(rules: readonly L4ForwardRule[]): void {
  if (!Array.isArray(rules) || rules.length > 64) throw new Error("Invalid L4 forwarding rules");
  const listeners = new Set<string>();
  for (const rule of rules) {
    const checked = compileRule(rule);
    const key = `${rule.protocol}/${checked.listenHost}/${rule.listen.port}`;
    if (listeners.has(key)) throw new Error("Duplicate L4 listener");
    listeners.add(key);
  }
}

function sourceAllowed(
  address: string | undefined,
  sources: ReturnType<typeof ipaddr.parseCIDR>[],
) {
  if (!address) return false;
  try {
    const parsed = ipaddr.process(address);
    return sources.some(([network, prefix]) => {
      const candidate =
        parsed.kind() === network.kind() ? parsed : ipaddr.process(parsed.toString());
      return candidate.kind() === network.kind() && candidate.match(network, prefix);
    });
  } catch {
    return false;
  }
}

function closeSocket(socket: Socket) {
  socket.destroy();
}

/** Starts bounded TCP/UDP forwarders and returns an idempotent shutdown hook. */
export async function startL4Forwarders(
  rules: readonly L4ForwardRule[],
  resourceLimits?: L4ResourceLimits,
) {
  const limits = resolveL4ResourceLimits(resourceLimits);
  const servers: Server[] = [];
  const datagrams: DatagramSocket[] = [];
  const tcpClients = new Set<Socket>();
  const udpRelays = new Set<DatagramSocket>();
  const udpTimers = new Set<NodeJS.Timeout>();
  const udpSessions = new Set<{
    socket: DatagramSocket;
    timer?: NodeJS.Timeout;
    ready: boolean;
    queuedBytes: number;
    pending?: Buffer[];
  }>();
  let stopped = false;
  let udpQueuedBytes = 0;
  const UDP_PENDING_LIMIT = limits.udpPendingBytes;
  try {
    validateL4ForwardRules(rules);
    for (const raw of rules) {
      const rule = compileRule(raw);
      const family = isIP(rule.listenHost) === 6 ? "udp6" : "udp4";
      if (isIP(rule.targetHost) !== isIP(rule.listenHost))
        throw new Error("L4 listener and target address families must match");
      if (rule.protocol === "tcp") {
        const server = createServer({ pauseOnConnect: true }, (client) => {
          if (
            stopped ||
            tcpClients.size / 2 >= Math.min(rule.maxConnections, limits.maxTcpConnections) ||
            !sourceAllowed(client.remoteAddress, rule.sources)
          ) {
            client.destroy();
            return;
          }
          tcpClients.add(client);
          client.setTimeout(rule.idleTimeoutMs, () => closeSocket(client));
          const upstream = createServerConnection(rule.targetHost, rule.target.port);
          tcpClients.add(upstream);
          upstream.setTimeout(rule.idleTimeoutMs, () => closeSocket(upstream));
          const done = () => {
            tcpClients.delete(client);
            tcpClients.delete(upstream);
            closeSocket(client);
            closeSocket(upstream);
          };
          client.once("error", done);
          upstream.once("error", done);
          client.once("close", done);
          upstream.once("close", done);
          upstream.once("connect", () => {
            if (stopped || client.destroyed) return done();
            client.pipe(upstream);
            upstream.pipe(client);
            client.resume();
          });
        });
        servers.push(server);
        await new Promise<void>((resolve, reject) => {
          server.once("error", reject);
          server.listen(rule.listen.port, rule.listenHost, () => {
            server.off("error", reject);
            resolve();
          });
        });
        continue;
      }

      const listener = createSocket(family);
      datagrams.push(listener);
      const clients = new Map<
        string,
        {
          socket: DatagramSocket;
          timer?: NodeJS.Timeout;
          ready: boolean;
          queuedBytes: number;
          pending?: Buffer[];
        }
      >();
      listener.on("message", (packet, peer: RemoteInfo) => {
        if (stopped || !sourceAllowed(peer.address, rule.sources)) return;
        const key = `${peer.family}/${peer.address}/${peer.port}`;
        let session = clients.get(key);
        if (!session) {
          if (clients.size >= rule.maxConnections || udpRelays.size >= limits.maxUdpSessions)
            return;
          const relay = createSocket(family);
          session = { socket: relay, ready: false, queuedBytes: 0 };
          clients.set(key, session);
          udpSessions.add(session);
          udpRelays.add(relay);
          let timer: NodeJS.Timeout;
          const refresh = () => {
            clearTimeout(timer);
            udpTimers.delete(timer);
            timer = setTimeout(() => {
              clients.delete(key);
              udpRelays.delete(relay!);
              udpSessions.delete(session!);
              udpQueuedBytes -= session!.queuedBytes;
              session!.queuedBytes = 0;
              udpTimers.delete(timer);
              relay!.removeAllListeners();
              relay!.close();
            }, rule.idleTimeoutMs);
            timer.unref();
            udpTimers.add(timer);
            session!.timer = timer;
          };
          relay.on("message", (response) => {
            refresh();
            listener.send(response, peer.port, peer.address);
          });
          relay.on("error", () => {
            clients.delete(key);
            udpRelays.delete(relay!);
            udpSessions.delete(session!);
            udpQueuedBytes -= session!.queuedBytes;
            session!.queuedBytes = 0;
            udpTimers.delete(session!.timer!);
            clearTimeout(session!.timer);
            try {
              relay!.close();
            } catch {
              /* already closed */
            }
          });
          relay.connect(rule.target.port, rule.targetHost, () => {
            session!.ready = true;
            refresh();
            session!.queuedBytes -= packet.length;
            udpQueuedBytes -= packet.length;
            relay!.send(packet);
            for (const queued of pending.splice(0)) {
              session!.queuedBytes -= queued.length;
              udpQueuedBytes -= queued.length;
              relay!.send(queued);
            }
          });
          const pending: Buffer[] = [];
          session!.pending = pending;
          if (packet.length > 65536) {
            clients.delete(key);
            udpRelays.delete(relay);
            udpSessions.delete(session);
            clearTimeout(session.timer);
            udpTimers.delete(session.timer!);
            session.queuedBytes = 0;
            relay.close();
            return;
          }
          if (udpQueuedBytes + packet.length > UDP_PENDING_LIMIT) {
            clients.delete(key);
            udpRelays.delete(relay);
            udpSessions.delete(session);
            clearTimeout(session.timer);
            udpTimers.delete(session.timer!);
            relay.close();
            return;
          }
          pending.push(packet);
          session!.queuedBytes = packet.length;
          udpQueuedBytes += packet.length;
          refresh();
          return;
        }
        if (session.ready) {
          clearTimeout(session.timer);
          udpTimers.delete(session.timer!);
          session.timer = setTimeout(() => {
            clients.delete(key);
            udpRelays.delete(session!.socket);
            udpSessions.delete(session!);
            udpQueuedBytes -= session!.queuedBytes;
            session!.queuedBytes = 0;
            udpTimers.delete(session!.timer!);
            try {
              session!.socket.close();
            } catch {
              /* already closed */
            }
          }, rule.idleTimeoutMs);
          session.timer.unref();
          udpTimers.add(session.timer);
          session.socket.send(packet);
        } else if (
          session.queuedBytes + packet.length <= 65536 &&
          udpQueuedBytes + packet.length <= UDP_PENDING_LIMIT
        ) {
          session.pending!.push(packet);
          session.queuedBytes += packet.length;
          udpQueuedBytes += packet.length;
        }
      });
      await new Promise<void>((resolve, reject) => {
        listener.once("error", reject);
        listener.bind(rule.listen.port, rule.listenHost, () => {
          listener.off("error", reject);
          resolve();
        });
      });
    }
  } catch (error) {
    await closeAll();
    throw error;
  }
  async function closeAll() {
    if (stopped) return;
    stopped = true;
    for (const timer of udpTimers) clearTimeout(timer);
    udpTimers.clear();
    udpSessions.clear();
    for (const client of tcpClients) client.destroy();
    for (const relay of udpRelays)
      try {
        relay.close();
      } catch {
        /* already closed */
      }
    await Promise.all([
      ...servers.map(
        (server) =>
          new Promise<void>((resolve) => {
            try {
              server.close(() => resolve());
            } catch {
              resolve();
            }
          }),
      ),
      ...datagrams.map(
        (socket) =>
          new Promise<void>((resolve) => {
            try {
              socket.close(() => resolve());
            } catch {
              resolve();
            }
          }),
      ),
    ]);
  }
  return { close: closeAll };
}

function createServerConnection(host: string, port: number): Socket {
  return createConnection({ host, port });
}
