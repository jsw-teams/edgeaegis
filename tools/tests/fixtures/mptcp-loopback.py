from __future__ import annotations

import json
import socket
import sys

# Linux IPPROTO_MPTCP, SOL_MPTCP and MPTCP_INFO. This is a normal,
# non-exploit loopback transport test, not a kernel CVE reproduction.
MPTCP_PROTOCOL = getattr(socket, "IPPROTO_MPTCP", 262)
SOL_MPTCP = 284
MPTCP_INFO = 1


def exchange(node_port: int, query: str) -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM, MPTCP_PROTOCOL) as listener:
        listener.settimeout(6)
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM, MPTCP_PROTOCOL) as client:
            client.settimeout(6)
            client.connect(listener.getsockname())
            with listener.accept()[0] as inbound:
                inbound.settimeout(6)
                # Never count plain TCP fallback as an MPTCP pass.
                for endpoint in (client, inbound):
                    info = endpoint.getsockopt(SOL_MPTCP, MPTCP_INFO, 128)
                    if not info:
                        raise RuntimeError("MPTCP_INFO returned no negotiated transport data")

                request = (
                    f"GET /api{query} HTTP/1.1\r\n"
                    "Host: api.test\r\n"
                    "Connection: close\r\n\r\n"
                ).encode("ascii")
                client.sendall(request)

                incoming = b""
                while b"\r\n\r\n" not in incoming:
                    part = inbound.recv(4096)
                    if not part:
                        raise RuntimeError("MPTCP gateway received incomplete HTTP headers")
                    incoming += part
                    if len(incoming) > 8192:
                        raise RuntimeError("HTTP request exceeded test header limit")
                with socket.create_connection(("127.0.0.1", node_port), timeout=6) as origin:
                    origin.settimeout(6)
                    origin.sendall(incoming)
                    while True:
                        part = origin.recv(65536)
                        if not part:
                            break
                        inbound.sendall(part)
                inbound.shutdown(socket.SHUT_WR)

                response = b""
                while True:
                    part = client.recv(65536)
                    if not part:
                        break
                    response += part
                    if len(response) > 1048576:
                        raise RuntimeError("HTTP response exceeded test limit")
                line = response.split(b"\r\n", 1)[0].decode("ascii")
                if not line.startswith("HTTP/1.1 "):
                    raise RuntimeError(f"Unexpected HTTP response: {line!r}")
                return int(line.split(" ")[1])


if __name__ == "__main__":
    if sys.platform != "linux":
        sys.exit(77)
    try:
        port = int(sys.argv[1])
        statuses = [exchange(port, "?q=ok"), exchange(port, "?q=attack")]
        print(json.dumps({"transport": "negotiated-mptcp", "statuses": statuses}))
    except OSError as exc:
        # Unsupported or disabled MPTCP is reported as SKIP, never PASS.
        if exc.errno in {22, 92, 93, 95}:
            print(f"SKIP: kernel MPTCP unavailable: {exc}", file=sys.stderr)
            sys.exit(77)
        raise
