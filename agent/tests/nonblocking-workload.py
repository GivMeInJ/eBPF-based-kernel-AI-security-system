#!/usr/bin/env python3
"""Produce a nonblocking TCP connect, normally returning EINPROGRESS."""

import select
import socket
import time


listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
listener.bind(("127.0.0.1", 0))
listener.listen(1)
time.sleep(1.5)

client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.setblocking(False)
result = client.connect_ex(listener.getsockname())
if result not in (0, 115):
    raise SystemExit(f"unexpected connect_ex result: {result}")
select.select([], [client], [], 2)
connection, _ = listener.accept()
connection.close()
client.close()
listener.close()
