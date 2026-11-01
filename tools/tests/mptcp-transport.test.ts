import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { once } from "node:events";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { createNodeServer } from "../../scr/runtime/node.js";
import { context, fixture } from "./helpers.js";

test("negotiated loopback MPTCP ingress preserves SecLang rejection before origin", async (t) => {
  if (process.platform !== "linux") {
    t.skip("MPTCP transport integration requires Linux");
    return;
  }
  const f = await fixture();
  const server = createNodeServer(
    (req, incoming) => f.handle(req, context, incoming.url),
    "api.test",
  );
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  try {
    const address = server.address();
    assert.ok(address && typeof address === "object");
    const helper = fileURLToPath(new URL("./fixtures/mptcp-loopback.py", import.meta.url));
    const result = await new Promise<{ code: number | null; stdout: string; stderr: string }>(
      (resolve, reject) => {
        const child = spawn("python3", [helper, String(address.port)], { timeout: 20000 });
        let stdout = "";
        let stderr = "";
        child.stdout.setEncoding("utf8");
        child.stderr.setEncoding("utf8");
        child.stdout.on("data", (value: string) => {
          stdout += value;
        });
        child.stderr.on("data", (value: string) => {
          stderr += value;
        });
        child.on("error", reject);
        child.on("close", (code) => resolve({ code, stdout, stderr }));
      },
    );
    if (result.code === 77) {
      t.skip(result.stderr.trim() || "Kernel MPTCP support is unavailable");
      return;
    }
    assert.equal(result.code, 0, result.stderr);
    const outcome = JSON.parse(result.stdout);
    assert.equal(outcome.transport, "negotiated-mptcp");
    assert.deepEqual(outcome.statuses, [200, 403]);
    assert.equal(f.forwarded.length, 1, "malicious request must never reach the origin");
    assert.ok(f.events.some((event) => event.kind === "block" && event.source === "rule"));
  } finally {
    server.closeAllConnections();
    await new Promise<void>((resolve) => server.close(() => resolve()));
  }
});
