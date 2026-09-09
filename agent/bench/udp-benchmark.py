#!/usr/bin/env python3
"""Generate a measured UDP syscall burst after an optional startup delay."""

import argparse
import json
import socket
import time


parser = argparse.ArgumentParser()
parser.add_argument("--count", type=int, default=50000)
parser.add_argument("--delay", type=float, default=1.5)
arguments = parser.parse_args()

time.sleep(arguments.delay)
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
started = time.perf_counter_ns()
for _ in range(arguments.count):
    sock.sendto(b"benchmark", ("127.0.0.1", 9))
elapsed_ns = time.perf_counter_ns() - started
sock.close()

print(
    json.dumps(
        {
            "sent": arguments.count,
            "elapsed_ns": elapsed_ns,
            "events_per_second": arguments.count * 1_000_000_000 / elapsed_ns,
        },
        separators=(",", ":"),
    )
)
