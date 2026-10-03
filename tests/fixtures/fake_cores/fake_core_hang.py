#!/usr/bin/env python3
"""A hanging core: binds the inbound port but never answers requests.

Exercises the per-probe HTTP timeout path (startup succeeds, tunnel
never completes).
"""
import json
import socket
import sys
import time

if "-c" in sys.argv:
    config_path = sys.argv[sys.argv.index("-c") + 1]
    with open(config_path, encoding="utf-8") as handle:
        config = json.load(handle)
    port = int(config["inbounds"][0]["listen_port"])
else:
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 18081

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server.bind(("127.0.0.1", port))
server.listen(16)
while True:
    conn, _ = server.accept()  # accept but never speak
    time.sleep(3600)
