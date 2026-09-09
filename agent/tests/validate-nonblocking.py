#!/usr/bin/env python3
"""Verify preservation of the kernel's -EINPROGRESS return value."""

import json
import sys


with open(sys.argv[1], encoding="utf-8") as stream:
    events = [json.loads(line) for line in stream if line.strip()]

connects = [
    event
    for event in events
    if event.get("event_type") == "NETWORK_CONNECT"
    and event.get("comm") == "python3"
]
if not any(event.get("retval") == -115 for event in connects):
    raise SystemExit(f"missing -EINPROGRESS event: {connects}")
print("nonblocking connect validation passed")
