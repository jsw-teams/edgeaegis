import assert from "node:assert/strict";
import { createSocket } from "node:dgram";
import { once } from "node:events";
import { createServer, type Server } from "node:net";
import { test } from "node:test";
import {
  resolveL4ResourceLimits,
  startL4Forwarders,
  validateL4ForwardRules,
} from "../../scr/runtime/l4.js";

async function freeTcpPort() {
  const server = createServer();
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  const port = (server.address() as { port: number }).port;
  await new Promise<void>((resolve) => server.close(() => resolve()));
  return port;
}

async function freeUdpPort() {
  const socket = createSocket("udp4");
  socket.bind(0, "127.0.0.1");
  await once(socket, "listening");
  const port = socket.address().port;
  socket.close();
  await once(socket, "close");
  return port;
}

test("L4 rules require fixed IP targets and an explicit source allowlist", () => {
  const base = {
    protocol: "tcp" as const,
    listen: { host: "127.0.0.1", port: 18081 },
    target: { host: "127.0.0.1", port: 18082 },
    allowSources: ["127.0.0.1/32"],
  };
  assert.throws(() => validateL4ForwardRules([{ ...base, allowSources: [] }]), /source CIDR/);
  assert.throws(
    () => validateL4ForwardRules([{ ...base, target: { host: "backend.internal", port: 80 } }]),
    /literal IP/,
  );
  assert.throws(
    () => validateL4ForwardRules([{ ...base, listen: { ...base.listen, port: base.target.port } }]),
    /itself/,
  );
});

test("L4 session and queue budgets can be raised for a larger VPS", () => {
  assert.deepEqual(
    resolveL4ResourceLimits({
      maxTcpConnections: 16384,
      maxUdpSessions: 32768,
      udpPendingBytes: 64 * 1024 * 1024,
    }),
    {
      maxTcpConnections: 16384,
      maxUdpSessions: 32768,
      udpPendingBytes: 64 * 1024 * 1024,
    },
  );
});

test("TCP forwarding applies source ACL and streams bytes to the fixed target", {
  timeout: 5000,
}, async () => {
  const target = createServer((socket) => socket.pipe(socket));
  target.listen(0, "127.0.0.1");
  await once(target, "listening");
  const targetPort = (target.address() as { port: number }).port;
  const listenPort = await freeTcpPort();
  const forwarding = await startL4Forwarders([
    {
      protocol: "tcp",
      listen: { host: "127.0.0.1", port: listenPort },
      target: { host: "127.0.0.1", port: targetPort },
      allowSources: ["127.0.0.1/32"],
      maxConnections: 4,
      idleTimeoutMs: 5000,
    },
  ]);
  try {
    const net = await import("node:net");
    const client = net.createConnection({ host: "127.0.0.1", port: listenPort });
    await once(client, "connect");
    const received = once(client, "data");
    client.write("streamed");
    assert.equal((await received)[0]?.toString(), "streamed");
    client.destroy();
  } finally {
    await forwarding.close();
    await new Promise<void>((resolve) => (target as Server).close(() => resolve()));
  }
});

test("TCP source rejected by the ACL never opens a target connection", {
  timeout: 5000,
}, async () => {
  let targetConnections = 0;
  const target = createServer(() => targetConnections++);
  target.listen(0, "127.0.0.1");
  await once(target, "listening");
  const listenPort = await freeTcpPort();
  const forwarding = await startL4Forwarders([
    {
      protocol: "tcp",
      listen: { host: "127.0.0.1", port: listenPort },
      target: { host: "127.0.0.1", port: (target.address() as { port: number }).port },
      allowSources: ["192.0.2.0/24"],
      idleTimeoutMs: 5000,
    },
  ]);
  try {
    const net = await import("node:net");
    const client = net.createConnection({ host: "127.0.0.1", port: listenPort });
    client.on("error", () => {});
    const closed = new Promise<void>((resolve) => client.once("close", () => resolve()));
    await once(client, "connect");
    client.write("must-not-forward");
    await closed;
    assert.equal(targetConnections, 0);
  } finally {
    await forwarding.close();
    await new Promise<void>((resolve) => target.close(() => resolve()));
  }
});

test("UDP forwarding keeps bounded per-client reply paths", { timeout: 5000 }, async () => {
  const target = createSocket("udp4");
  target.on("message", (message, peer) => target.send(message, peer.port, peer.address));
  target.bind(0, "127.0.0.1");
  await once(target, "listening");
  const targetPort = target.address().port;
  const listenPort = await freeUdpPort();
  const forwarding = await startL4Forwarders([
    {
      protocol: "udp",
      listen: { host: "127.0.0.1", port: listenPort },
      target: { host: "127.0.0.1", port: targetPort },
      allowSources: ["127.0.0.1/32"],
      maxConnections: 4,
      idleTimeoutMs: 5000,
    },
  ]);
  const client = createSocket("udp4");
  try {
    client.bind(0, "127.0.0.1");
    await once(client, "listening");
    const received = once(client, "message");
    client.send("dns", listenPort, "127.0.0.1");
    assert.equal((await received)[0].toString(), "dns");
  } finally {
    client.close();
    await once(client, "close");
    await forwarding.close();
    target.close();
    await once(target, "close");
  }
});
