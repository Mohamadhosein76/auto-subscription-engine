#!/usr/bin/env python3
"""Fake sing-box replacement for offline tests.

Reads the per-node config (same CLI shape: ``<core> run -c <path>``),
binds the configured mixed inbound port and implements just enough of
HTTP CONNECT to relay real requests to local test servers. It never
touches the network beyond 127.0.0.1.

If ASE_ARGV_FILE is set in the environment, the raw argv is dumped there
so tests can assert that no credentials appear in process arguments.
"""
import json
import os
import socket
import sys
import threading


def relay(src: socket.socket, dst: socket.socket) -> None:
    try:
        while True:
            data = src.recv(65536)
            if not data:
                break
            dst.sendall(data)
    except OSError:
        pass
    finally:
        try:
            dst.shutdown(socket.SHUT_WR)
        except OSError:
            pass


def handle(conn: socket.socket) -> None:
    conn.settimeout(10)
    try:
        data = b""
        while b"\r\n\r\n" not in data:
            chunk = conn.recv(4096)
            if not chunk:
                conn.close()
                return
            data += chunk
        head = data.split(b"\r\n\r\n", 1)[0].decode("latin1")
        parts = head.split("\r\n", 1)[0].split()
        method, target = parts[0].upper(), parts[1]
        if method == "CONNECT":
            host, port_text = target.rsplit(":", 1)
            port = int(port_text)
            # Only loopback targets in tests: refuse everything else loudly.
            if host not in ("127.0.0.1", "localhost"):
                conn.sendall(b"HTTP/1.1 403 Forbidden\r\n\r\n")
                conn.close()
                return
            conn.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")
            upstream = socket.create_connection((host, port), timeout=8)
            threads = [
                threading.Thread(target=relay, args=(conn, upstream), daemon=True),
                threading.Thread(target=relay, args=(upstream, conn), daemon=True),
            ]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join()
            conn.close()
            upstream.close()
        else:
            conn.sendall(b"HTTP/1.1 405 Method Not Allowed\r\n\r\n")
            conn.close()
    except OSError:
        pass


def main() -> None:
    if os.environ.get("ASE_ARGV_FILE"):
        with open(os.environ["ASE_ARGV_FILE"], "w", encoding="utf-8") as argv_dump:
            argv_dump.write("\x1f".join(sys.argv))
    if "-c" in sys.argv:
        config_path = sys.argv[sys.argv.index("-c") + 1]
        with open(config_path, encoding="utf-8") as config_file:
            config = json.load(config_file)
        port = int(config["inbounds"][0]["listen_port"])
    else:
        port = int(os.environ.get("FAKE_CORE_PORT", "18080"))
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("127.0.0.1", port))
    server.listen(64)
    while True:
        conn, _ = server.accept()
        threading.Thread(target=handle, args=(conn,), daemon=True).start()


if __name__ == "__main__":
    main()
